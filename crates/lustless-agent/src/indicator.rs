//! The SNI tray indicator (CONTRACTS §13: "GTK3 + libayatana-appindicator
//! tray") and its graceful degradation on desktops without a
//! StatusNotifier host (LXQt/Lubuntu, §1).
//!
//! Availability is decided in two steps, both required by §13:
//!
//! 1. **SNI host probe** — the session bus must have a
//!    `org.kde.StatusNotifierWatcher` owner (GNOME's AppIndicator extension,
//!    Xfce's `xfce4-indicator-plugin`, and LXQt-with-plugin all provide one;
//!    plain LXQt does not). No watcher ⇒ headless mode, no indicator object
//!    is created at all.
//! 2. **Library probe** — the `libappindicator` crate dlopens
//!    `libayatana-appindicator3.so.1` on first use and panics when the
//!    library is missing; construction is wrapped in `catch_unwind` so a
//!    distro without the §15 runtime library also lands in headless mode
//!    instead of crashing the agent.

use std::fs;
use std::path::{Path, PathBuf};

use libappindicator::{AppIndicator, AppIndicatorStatus};

use crate::status::StatusColor;

/// Indicator title shown in SNI hosts.
const INDICATOR_TITLE: &str = "LustLess";

/// True when a StatusNotifier host is present on the session bus.
pub fn snw_available() -> bool {
    let result: Result<bool, _> = (|| {
        let conn = zbus::blocking::Connection::session()?;
        let proxy = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )?;
        proxy.call("NameHasOwner", &"org.kde.StatusNotifierWatcher".to_string())
    })();
    result.unwrap_or(false)
}

/// The CE shield logo, 32 px PNG (`packaging/assets/lustless-32.png` —
/// provenance and authorization in `packaging/assets/README.md` and the
/// repo-root `AUTHORIZATION.md`). The tray icon is the real logo in every
/// state; a status-coloured overlay would obscure the mark, so status
/// reaches the user through the adjacent label ([`StatusColor::label`])
/// and desktop notifications instead.
const TRAY_ICON_PNG: &[u8] = include_bytes!("../../../packaging/assets/lustless-32.png");

/// Icon name the SNI host resolves to `lustless.png` in the theme path.
const TRAY_ICON_NAME: &str = "lustless";

/// Writes the logo PNG into `<base>/lustless-agent-icons/` and returns that
/// directory (used as the indicator's icon theme path).
pub fn write_icon_files(base: &Path) -> std::io::Result<PathBuf> {
    let dir = base.join("lustless-agent-icons");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("lustless.png"), TRAY_ICON_PNG)?;
    Ok(dir)
}

/// The live indicator (main-thread only — `AppIndicator` is not `Send`).
pub struct Tray {
    indicator: AppIndicator,
}

impl Tray {
    /// Creates the indicator for `icon_dir`, or returns `None` when this
    /// desktop cannot host it (§13 graceful degradation — the caller keeps
    /// running headless).
    pub fn new(icon_dir: &Path) -> Option<Tray> {
        if !snw_available() {
            tracing::info!(target: "agent", "no StatusNotifierWatcher on the session bus — running headless");
            return None;
        }
        let theme_path = icon_dir.to_string_lossy().into_owned();
        let created = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut indicator = AppIndicator::new(INDICATOR_TITLE, TRAY_ICON_NAME);
            indicator.set_icon_theme_path(&theme_path);
            indicator.set_title(INDICATOR_TITLE);
            indicator.set_status(AppIndicatorStatus::Active);
            indicator
        }));
        match created {
            Ok(indicator) => Some(Tray { indicator }),
            Err(_) => {
                tracing::warn!(target: "agent", "appindicator library unavailable — running headless");
                None
            }
        }
    }

    /// Attaches the (already built, already shown) menu.
    pub fn set_menu(&mut self, menu: &mut gtk::Menu) {
        self.indicator.set_menu(menu);
    }

    /// Updates the status label next to the (fixed) logo icon.
    pub fn set_status(&mut self, color: StatusColor) {
        self.indicator
            .set_label(color.label(), "AAAAAAAAAAAAAAAAAAAA");
    }
}
