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

/// The tray icon: a status-coloured circle SVG per state, written into a
/// runtime directory and picked up through the indicator's icon theme path
/// (SNI hosts render it via the desktop's SVG icon loader).
fn svg_for(color: StatusColor) -> String {
    let fill = match color {
        StatusColor::Green => "#2e7d32",
        StatusColor::Amber => "#ed6c02",
        StatusColor::Red => "#c62828",
        StatusColor::Gray => "#9e9e9e",
    };
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"22\" height=\"22\" \
         viewBox=\"0 0 22 22\"><circle cx=\"11\" cy=\"11\" r=\"9\" fill=\"{fill}\" \
         stroke=\"#ffffff\" stroke-width=\"1.5\"/></svg>"
    )
}

/// Writes one SVG per status colour into `<base>/lustless-agent-icons/` and
/// returns that directory (used as the indicator's icon theme path).
pub fn write_icon_files(base: &Path) -> std::io::Result<PathBuf> {
    let dir = base.join("lustless-agent-icons");
    fs::create_dir_all(&dir)?;
    for color in [
        StatusColor::Green,
        StatusColor::Amber,
        StatusColor::Red,
        StatusColor::Gray,
    ] {
        fs::write(dir.join(format!("{}.svg", color.icon_name())), svg_for(color))?;
    }
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
            let mut indicator =
                AppIndicator::new(INDICATOR_TITLE, StatusColor::Gray.icon_name());
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

    /// repaints the status colour and the adjacent label.
    pub fn set_status(&mut self, color: StatusColor) {
        self.indicator.set_icon(color.icon_name());
        self.indicator
            .set_label(color.label(), "AAAAAAAAAAAAAAAAAAAA");
    }
}
