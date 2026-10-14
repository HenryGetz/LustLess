//! `lustless-agent` — the per-session tray (CONTRACTS §13).
//!
//! Single-instance via `GApplication` id `org.lustless.agent`; a background
//! worker polls `POLICY_GET` (0x60) every ~5 s and drains `NOTIFICATION`
//! frames (§5); menu actions send their §5 codes (see `menu.rs`); the
//! dashboard opens with `xdg-open` (§13); the session token from the 0x65
//! reply goes to the keyring/0600-file store (`secrets.rs`); when the
//! desktop has no StatusNotifier host the agent keeps running headless with
//! libnotify-style desktop notifications (§13 graceful degradation).

mod indicator;
mod ipc;
mod menu;
mod notify;
mod secrets;
mod status;
mod worker;

use gtk::glib::ExitCode;
use std::cell::RefCell;
use std::path::PathBuf;
use std::process::Command as Proc;
use std::rc::Rc;
use std::time::Duration;

use gtk::glib;
use gtk::prelude::*;

use lustless_core::config::LustlessConfig;
use lustless_core::policy::PolicySnapshot;
use lustless_core::wire::Code;

/// The §13 single-instance application id.
const APP_ID: &str = "org.lustless.agent";

/// How often the main loop drains worker updates.
const UI_PUMP: Duration = Duration::from_millis(250);

fn main() -> ExitCode {
    // stderr → journald through the user unit (CONTRACTS §14 shape).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let config_path = std::env::var_os("LUSTLESS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/lustless/lustless.toml"));
    let config = Rc::new(LustlessConfig::load(&config_path));

    // `--show` (alias `--signin`) is what the application-menu launcher
    // runs: instead of starting silently in the tray, present the sign-in
    // dialog (signed out) or the dashboard (signed in). The flags are
    // consumed here so GApplication never sees them; a second launch of the
    // same command line reaches the running primary instance as a remote
    // activation and presents the same surface (§13).
    let mut args: Vec<String> = std::env::args().collect();
    let show = args.iter().any(|arg| arg == "--show" || arg == "--signin");
    args.retain(|arg| arg != "--show" && arg != "--signin");

    let app = gtk::Application::builder().application_id(APP_ID).build();
    let activated = Rc::new(std::cell::Cell::new(false));
    let live_ctx: Rc<RefCell<Option<Rc<Ctx>>>> = Rc::new(RefCell::new(None));
    let activate_ctx = Rc::clone(&live_ctx);
    app.connect_activate(move |app| {
        // GApplication: the first launch runs the UI; later launches only
        // forward the activation to the primary instance — and that
        // forwarded activation is the user asking to see the agent.
        if activated.get() {
            if let Some(ctx) = activate_ctx.borrow().as_ref() {
                present(ctx);
            }
            return;
        }
        activated.set(true);
        let ctx = activate(app, &config);
        // `activate` stores gio's hold guard in `Ctx` — a windowless
        // GtkApplication otherwise returns from `run()` right here, before
        // any timer, menu click or dialog can ever be dispatched.
        if show {
            present(&ctx);
        } else {
            // Started by the installer or the autostart entry: prompt for
            // sign-in once the first snapshot has had a moment to arrive.
            schedule_sign_in_prompt(&ctx);
        }
        *activate_ctx.borrow_mut() = Some(ctx);
    });
    // The program name MUST stay in the argument list: passing an empty
    // slice leaves GApplication with argc 0, whose main loop returns
    // immediately — the agent then only survives on its worker thread and
    // never dispatches a timer, a menu click or a dialog.
    app.run_with_args(&args)
}

/// Shared main-thread context for menu actions.
struct Ctx {
    app: gtk::Application,
    /// Keeps the application held for the process lifetime. gio's `hold()`
    /// returns an RAII guard that *releases on drop* (`#[must_use]`), and a
    /// windowless `GtkApplication` whose use count reaches zero returns from
    /// `run()` immediately — which is exactly what this agent is. Dropping
    /// this guard silently kills the main loop: no timers, no tray menu
    /// clicks, no dialogs.
    _hold: gtk::gio::ApplicationHoldGuard,
    state: Rc<RefCell<UiState>>,
    tray: Rc<RefCell<Option<indicator::Tray>>>,
    socket: PathBuf,
    /// Set once the sign-in window (or dashboard) has been presented, so the
    /// startup prompt and a menu click cannot stack two dialogs.
    presented: std::cell::Cell<bool>,
}

/// UI-side state, painted on the GTK main thread only.
struct UiState {
    /// Last parsed §9 snapshot (`None` = daemon unreachable).
    snapshot: Option<PolicySnapshot>,
    /// Last painted colour (transition detection for notifications).
    color: status::StatusColor,
    /// Last known daemon reachability.
    daemon_up: bool,
    /// Username of the last successful sign-in (token-store bookkeeping).
    username: Option<String>,
}

fn activate(app: &gtk::Application, config: &LustlessConfig) -> Rc<Ctx> {
    let socket = PathBuf::from(&config.daemon.socket_path);

    // The CE logo tray icon in the user runtime dir (see indicator.rs).
    let icon_dir = match indicator::write_icon_files(&glib::user_runtime_dir()) {
        Ok(dir) => dir,
        Err(err) => {
            tracing::warn!(target: "agent", "cannot write tray icons: {err}");
            glib::user_runtime_dir()
        }
    };

    // SNI tray when the desktop hosts one; headless otherwise (§13).
    let tray = indicator::Tray::new(&icon_dir);

    // Every window the agent opens (the sign-in dialog) wears the CE shield,
    // like the original client: the installed theme icon when the desktop has
    // it, else the copy written into the runtime dir above. Without this the
    // login window shows a generic GTK icon.
    gtk::Window::set_default_icon_name("lustless");
    let icon_file = icon_dir.join("lustless.png");
    if icon_file.exists() {
        let _ = gtk::Window::set_default_icon_from_file(&icon_file);
    }

    let ctx = Rc::new(Ctx {
        app: app.clone(),
        _hold: app.hold(),
        state: Rc::new(RefCell::new(UiState {
            snapshot: None,
            color: status::StatusColor::Gray,
            daemon_up: false,
            username: None,
        })),
        tray: Rc::new(RefCell::new(tray)),
        socket,
        presented: std::cell::Cell::new(false),
    });

    // Build the CE-vocabulary menu (§13) and attach it to the indicator.
    let mut gtk_menu = gtk::Menu::new();
    build_menu(&gtk_menu, &menu::menu(), &ctx);
    gtk_menu.show_all();
    if let Some(tray) = ctx.tray.borrow_mut().as_mut() {
        tray.set_menu(&mut gtk_menu);
    } else {
        // No SNI host: the one-shot startup notification tells the user how
        // to reach LustLess anyway (§13 graceful degradation).
        eprintln!(
            "lustless-agent: tray unavailable — running headless (open \u{201c}LustLess\u{201d} from the application menu, or see `lustlessctl status`)"
        );
        notify::startup_tray_unavailable();
    }
    // Keep the menu alive for the process lifetime (the indicator holds a C
    // reference; the Rust handle must outlive nothing else, but leaking one
    // tray menu is cheaper than reasoning about every host's ref discipline).
    std::mem::forget(gtk_menu);

    // Background poller → main-thread pump.
    let (tx, rx) = std::sync::mpsc::channel::<worker::Update>();
    let worker_handle = worker::spawn(ctx.socket.clone(), tx);
    let pump_ctx = Rc::clone(&ctx);
    glib::timeout_add_local(UI_PUMP, move || {
        while let Ok(update) = rx.try_recv() {
            apply_update(&pump_ctx, update);
        }
        glib::ControlFlow::Continue
    });
    ctx.app.connect_shutdown(move |_| worker_handle.stop());
    ctx
}

/// Presents the agent to the user — the sign-in dialog when signed out, the
/// dashboard when signed in. Reached from the application-menu launcher
/// (`lustless-agent --show`) and from re-activation of a running agent, so
/// the agent is reachable even on desktops with no StatusNotifier host.
fn present(ctx: &Rc<Ctx>) {
    if ctx.presented.replace(true) {
        return; // a window is already open — never stack two dialogs
    }
    let signed_in = ctx
        .state
        .borrow()
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.signed_in)
        .unwrap_or(false);
    let action = if signed_in {
        menu::Action::OpenDashboard
    } else {
        menu::Action::SignIn
    };
    tracing::info!(target: "agent", "presenting the {action:?} window");
    handle_action(ctx, &action);
    // `handle_action` blocks while the dialog is up, so the guard clears when
    // the window closes and a later menu click can open it again.
    ctx.presented.set(false);
}

/// Signed out? Show the sign-in window, like the original client: a fresh
/// install starts this agent from the installer (and at every login from the
/// autostart entry), so the user lands on a login prompt instead of having to
/// find a tray icon or a menu entry.
fn schedule_sign_in_prompt(ctx: &Rc<Ctx>) {
    let ctx = Rc::clone(ctx);
    glib::timeout_add_local_once(Duration::from_secs(2), move || {
        // Two seconds in, the first policy snapshot has usually arrived;
        // without one (daemon down) still prompt — that is the honest thing
        // to show.
        let signed_in = ctx
            .state
            .borrow()
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.signed_in)
            .unwrap_or(false);
        if !signed_in {
            present(&ctx);
        }
    });
}

fn build_menu(parent: &gtk::Menu, entries: &[menu::MenuEntry], ctx: &Rc<Ctx>) {
    for entry in entries {
        match entry {
            menu::MenuEntry::Item { label, action } => {
                let item = gtk::MenuItem::with_label(label);
                let ctx = Rc::clone(ctx);
                let action = action.clone();
                item.connect_activate(move |_| handle_action(&ctx, &action));
                parent.append(&item);
            }
            menu::MenuEntry::Submenu { label, children } => {
                let item = gtk::MenuItem::with_label(label);
                let submenu = gtk::Menu::new();
                build_menu(&submenu, children, ctx);
                submenu.show_all();
                item.set_submenu(Some(&submenu));
                std::mem::forget(submenu);
                parent.append(&item);
            }
            menu::MenuEntry::Separator => {
                parent.append(&gtk::SeparatorMenuItem::new());
            }
        }
    }
}

/// Applies one worker update on the main thread.
fn apply_update(ctx: &Rc<Ctx>, update: worker::Update) {
    match update {
        worker::Update::Reachable(up) => {
            let mut state = ctx.state.borrow_mut();
            if state.daemon_up != up {
                state.daemon_up = up;
                if !up {
                    paint(ctx, &mut state, status::StatusColor::Gray);
                }
            }
            if up && state.snapshot.is_some() {
                let color = status::color_for(state.snapshot.as_ref());
                paint(ctx, &mut state, color);
            }
        }
        worker::Update::Policy(result) => match result {
            Ok(snapshot) => {
                let mut state = ctx.state.borrow_mut();
                let previous = state.snapshot.replace(snapshot);
                let snapshot = state.snapshot.clone().expect("just replaced");
                let color = status::color_for(Some(&snapshot));
                paint(ctx, &mut state, color);
                state.daemon_up = true;
                announce_transitions(ctx, &state, previous.as_ref(), &snapshot);
            }
            Err(err) => {
                tracing::warn!(target: "agent", "policy update failed: {err}");
            }
        },
        worker::Update::Notification { level, message } => {
            let color = match level.as_str() {
                "error" => status::StatusColor::Red,
                "warning" => status::StatusColor::Amber,
                _ => status::StatusColor::Green,
            };
            notify::state_change("LustLess", &message, color);
        }
    }
}

fn paint(ctx: &Ctx, state: &mut UiState, color: status::StatusColor) {
    if state.color != color {
        state.color = color;
        if let Some(tray) = ctx.tray.borrow_mut().as_mut() {
            tray.set_status(color);
        }
    }
}

/// Desktop notifications on the §13 state transitions: sign-out (web is
/// cut), sign-in, filter outage, and panic.
fn announce_transitions(
    ctx: &Ctx,
    _state: &UiState,
    previous: Option<&PolicySnapshot>,
    current: &PolicySnapshot,
) {
    let _ = ctx;
    let Some(previous) = previous else {
        return; // first snapshot after startup — no transition to announce
    };
    if previous.signed_in && !current.signed_in {
        notify::state_change(
            "Signed out",
            "Web access is now blocked until sign-in.",
            status::StatusColor::Red,
        );
    } else if !previous.signed_in && current.signed_in {
        notify::state_change(
            "Signed in",
            &format!("{} is signed in — filtering is active.", current.username),
            status::StatusColor::Green,
        );
    }
    if previous.filter.health != "outage" && current.filter.health == "outage" {
        notify::state_change(
            "Web filter degraded",
            "The filter service hit an outage — browsing may be limited.",
            status::StatusColor::Amber,
        );
    }
    if !previous.is_panicked && current.is_panicked {
        notify::state_change(
            "Account alert",
            "This account is in alert (panic) state.",
            status::StatusColor::Red,
        );
    }
}

/// Menu action dispatch — every action sends its §5 frame (`menu.rs` table).
fn handle_action(ctx: &Rc<Ctx>, action: &menu::Action) {
    match action {
        menu::Action::SignIn | menu::Action::SwitchUser => {
            if let Some((username, password)) = credentials_dialog() {
                let payload = serde_json::json!({ "username": username, "password": password });
                match ipc::request(&ctx.socket, Code::SignIn, payload, ipc::READ_TIMEOUT) {
                    Ok((reply, _)) => {
                        let token = reply
                            .get("token")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("");
                        if !token.is_empty() {
                            let backend = secrets::store(&username, token);
                            tracing::info!(
                                target: "agent",
                                "session token stored ({backend:?}); token value not logged"
                            );
                        }
                        ctx.state.borrow_mut().username = Some(username.clone());
                        notify::state_change(
                            "Signed in",
                            &format!("{username} is signed in — filtering is active."),
                            status::StatusColor::Green,
                        );
                    }
                    Err(err) => notify::state_change(
                        "Sign in failed",
                        &err.to_string(),
                        status::StatusColor::Red,
                    ),
                }
            }
        }
        menu::Action::SignOut => match ipc::request(
            &ctx.socket,
            Code::SignOut,
            serde_json::json!({}),
            ipc::READ_TIMEOUT,
        ) {
            Ok(_) => {
                if let Some(username) = ctx.state.borrow_mut().username.take() {
                    secrets::clear(&username);
                }
                notify::state_change(
                    "Signed out",
                    "Web access is now blocked until sign-in.",
                    status::StatusColor::Red,
                );
            }
            Err(err) => notify::state_change(
                "Sign out failed",
                &err.to_string(),
                status::StatusColor::Amber,
            ),
        },
        menu::Action::OpenDashboard | menu::Action::ViewActivity => {
            match ipc::request(
                &ctx.socket,
                Code::StatusGet,
                serde_json::json!({}),
                ipc::READ_TIMEOUT,
            ) {
                Ok((reply, _)) => {
                    let url = reply
                        .get("dashboard_url")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if url.is_empty() {
                        notify::state_change(
                            "Dashboard disabled",
                            "The dashboard is disabled in the system configuration.",
                            status::StatusColor::Amber,
                        );
                    } else {
                        // §13: the agent appends the session token when the
                        // daemon URL did not carry one.
                        let token = ctx
                            .state
                            .borrow()
                            .username
                            .as_deref()
                            .and_then(secrets::load);
                        let url = with_stored_token(&url, token);
                        let url = match action {
                            menu::Action::ViewActivity => activity_url(&url),
                            _ => url,
                        };
                        open_url(&url);
                    }
                }
                Err(err) => notify::state_change(
                    "Dashboard unavailable",
                    &err.to_string(),
                    status::StatusColor::Amber,
                ),
            }
        }
        menu::Action::SetFilterLevel(level) => {
            match ipc::request(
                &ctx.socket,
                Code::FilterSetLevel,
                serde_json::json!({ "level": level }),
                ipc::READ_TIMEOUT,
            ) {
                Ok(_) => notify::state_change(
                    "Filter level changed",
                    &format!("Blocking level set to {level}."),
                    status::StatusColor::Green,
                ),
                Err(err) => notify::state_change(
                    "Filter level unchanged",
                    &err.to_string(),
                    status::StatusColor::Amber,
                ),
            }
        }
        menu::Action::RefreshSettings => {
            // 0x53 re-pushes the user settings (§5), then repaint from 0x60.
            let pushed = ipc::request(
                &ctx.socket,
                Code::UserSettingsChange,
                serde_json::json!({}),
                ipc::READ_TIMEOUT,
            );
            match ipc::request(
                &ctx.socket,
                Code::PolicyGet,
                serde_json::json!({}),
                ipc::READ_TIMEOUT,
            ) {
                Ok((reply, _)) => {
                    if let Ok(snapshot) =
                        serde_json::from_value::<PolicySnapshot>(reply["policy"].clone())
                    {
                        let mut state = ctx.state.borrow_mut();
                        state.snapshot = Some(snapshot);
                        let color = status::color_for(state.snapshot.as_ref());
                        paint(ctx, &mut state, color);
                    }
                    let _ = pushed;
                    notify::state_change(
                        "Settings refreshed",
                        "Settings and policy reloaded.",
                        status::StatusColor::Green,
                    );
                }
                Err(err) => notify::state_change(
                    "Refresh failed",
                    &err.to_string(),
                    status::StatusColor::Amber,
                ),
            }
        }
        menu::Action::CollectDiagnostics => {
            match ipc::request(
                &ctx.socket,
                Code::CollectDebugLogs,
                serde_json::json!({}),
                ipc::READ_TIMEOUT,
            ) {
                Ok(_) => notify::state_change(
                    "Collecting diagnostics",
                    "Diagnostics are being collected…",
                    status::StatusColor::Green,
                ),
                Err(err) => notify::state_change(
                    "Diagnostics failed",
                    &err.to_string(),
                    status::StatusColor::Amber,
                ),
            }
        }
        menu::Action::CheckForUpdates => {
            match ipc::request(
                &ctx.socket,
                Code::UpdateCheck,
                serde_json::json!({}),
                ipc::READ_TIMEOUT,
            ) {
                Ok((reply, _)) => {
                    let recommendation = reply.get("recommendation");
                    let label = recommendation
                        .and_then(|r| r.get("recommendation"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("none");
                    let body = match label {
                        "now" => "An update is recommended now — see the dashboard.",
                        "later" => "An update is available; apply it at your convenience.",
                        _ => "LustLess is up to date.",
                    };
                    notify::state_change("Update check", body, status::StatusColor::Green);
                }
                Err(err) => notify::state_change(
                    "Update check failed",
                    &err.to_string(),
                    status::StatusColor::Amber,
                ),
            }
        }
        menu::Action::Quit => {
            ctx.app.quit();
        }
    }
}

/// The dashboard's activity page (the CE `ViewDnsActivityHandler` log): the
/// daemon serves it at `/activity` (verified in `lustless-net`'s router), so
/// the path is spliced before the `?t=<token>` query of the §13 URL.
fn activity_url(dashboard_url: &str) -> String {
    match dashboard_url.split_once('?') {
        Some((base, query)) => format!("{}/activity?{}", base.trim_end_matches('/'), query),
        None => format!("{}/activity", dashboard_url.trim_end_matches('/')),
    }
}

/// §13: "token … appended by the agent when opening the browser" — used when
/// the daemon's URL carries no query (the daemon normally issues its own
/// short-lived token in the URL; this is the agent-side fallback onto the
/// stored session token).
fn with_stored_token(url: &str, token: Option<String>) -> String {
    if url.contains('?') {
        return url.to_string();
    }
    let Some(token) = token else {
        return url.to_string();
    };
    format!("{url}?t={token}")
}

/// Opens a URL with `xdg-open` (§13: the agent embeds no browser). The log
/// line strips any `?t=<token>` query — tokens are never logged.
fn open_url(url: &str) {
    let sanitized = match url.split_once('?') {
        Some((base, _)) => format!("{base}?…"),
        None => url.to_string(),
    };
    match Proc::new("xdg-open").arg(url).spawn() {
        Ok(_) => tracing::info!(target: "agent", "opened {sanitized}"),
        Err(err) => {
            tracing::warn!(target: "agent", "xdg-open failed: {err}");
            notify::state_change(
                "Cannot open browser",
                &format!("xdg-open failed: {err}"),
                status::StatusColor::Amber,
            );
        }
    }
}

/// The sign-in dialog (CE sign-in vocabulary): username + password with
/// echo off. The password never touches argv or a log.
fn credentials_dialog() -> Option<(String, String)> {
    let dialog = gtk::Dialog::new();
    dialog.set_title("Sign in to LustLess");
    dialog.set_modal(true);
    dialog.add_button("Cancel", gtk::ResponseType::Cancel);
    dialog.add_button("Sign in", gtk::ResponseType::Ok);

    let content = dialog.content_area();
    content.set_spacing(8);

    // Header: the CE shield plus the product name, so the login window looks
    // like the client it reimplements rather than a bare GTK form. The mark is
    // shipped by the package (`/usr/share/lustless/lustless-mark.png`, the
    // real artwork extracted from the Windows build); if it is missing the
    // dialog simply renders without it.
    let header = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    header.set_margin_top(6);
    header.set_margin_start(6);
    header.set_margin_end(6);
    let mark_path = std::path::Path::new("/usr/share/lustless/lustless-mark.png");
    if mark_path.exists() {
        let mark = gtk::Image::from_file(mark_path);
        // Native artwork is 88x94; 56 keeps the header tidy beside the text.
        mark.set_pixel_size(56);
        mark.set_valign(gtk::Align::Center);
        header.pack_start(&mark, false, false, 0);
    }
    let titles = gtk::Box::new(gtk::Orientation::Vertical, 2);
    let name = gtk::Label::new(None);
    name.set_markup("<span size=\"large\" weight=\"bold\">LustLess</span>");
    name.set_xalign(0.0);
    let subtitle = gtk::Label::new(Some("Accountability — sign in to continue"));
    subtitle.set_xalign(0.0);
    titles.pack_start(&name, false, false, 0);
    titles.pack_start(&subtitle, false, false, 0);
    header.pack_start(&titles, true, true, 0);
    content.pack_start(&header, false, false, 0);

    let grid = gtk::Grid::new();
    grid.set_row_spacing(4);
    grid.set_column_spacing(8);
    grid.set_margin_top(8);
    grid.set_margin_bottom(8);
    grid.set_margin_start(8);
    grid.set_margin_end(8);

    let username = gtk::Entry::new();
    username.set_placeholder_text(Some("Username"));
    let password = gtk::Entry::new();
    password.set_placeholder_text(Some("Password"));
    password.set_visibility(false);
    password.set_activates_default(true);

    grid.attach(&gtk::Label::new(Some("Username")), 0, 0, 1, 1);
    grid.attach(&username, 1, 0, 1, 1);
    grid.attach(&gtk::Label::new(Some("Password")), 0, 1, 1, 1);
    grid.attach(&password, 1, 1, 1, 1);
    content.pack_start(&grid, true, true, 0);

    // The default button is the dialog's own "Sign in" action button:
    // `set_default` with a freshly built button pointed at a temporary widget
    // that was dropped immediately (GTK critical, no default response).
    dialog.set_default_response(gtk::ResponseType::Ok);
    dialog.show_all();
    let response = dialog.run();
    let credentials = (response == gtk::ResponseType::Ok)
        .then(|| (username.text().to_string(), password.text().to_string()));
    dialog.close();
    credentials.filter(|(user, pass)| !user.trim().is_empty() && !pass.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{activity_url, with_stored_token};

    #[test]
    fn activity_url_splices_the_path_before_the_token_query() {
        assert_eq!(
            activity_url("http://127.0.0.1:8760/?t=abc"),
            "http://127.0.0.1:8760/activity?t=abc"
        );
        assert_eq!(
            activity_url("http://127.0.0.1:8760"),
            "http://127.0.0.1:8760/activity"
        );
    }

    #[test]
    fn stored_token_is_appended_only_when_the_url_has_none() {
        assert_eq!(
            with_stored_token("http://127.0.0.1:8760", Some("tok".into())),
            "http://127.0.0.1:8760?t=tok"
        );
        // A daemon-issued token wins — never overridden.
        assert_eq!(
            with_stored_token("http://127.0.0.1:8760/?t=daemon", Some("tok".into())),
            "http://127.0.0.1:8760/?t=daemon"
        );
        // No stored token → unchanged.
        assert_eq!(
            with_stored_token("http://127.0.0.1:8760", None),
            "http://127.0.0.1:8760"
        );
    }
}
