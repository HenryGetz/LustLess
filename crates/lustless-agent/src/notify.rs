//! Desktop notifications over D-Bus `org.freedesktop.Notifications` (the
//! freedesktop standard libnotify clients post to) — used for the §13 no-SNI
//! startup announcement and for state-change announcements (sign-out, filter
//! outage, break-glass progress). No libnotify build dependency: zbus only.

use std::collections::HashMap;

use zbus::zvariant::Value;

/// Posts one notification with a standard freedesktop icon name (rendered by
/// any notification daemon — GNOME/Xfce/LXQt alike). Never panics; returns
/// whether the server accepted it (a desktop without a notification daemon
/// is not an error condition for the agent — everything stays in the
/// tray/menu).
pub fn send(summary: &str, body: &str, icon: &str) -> bool {
    let conn = match zbus::blocking::Connection::session() {
        Ok(conn) => conn,
        Err(err) => {
            tracing::debug!(target: "agent", "no session bus for notification: {err}");
            return false;
        }
    };
    let proxy = match zbus::blocking::Proxy::new(
        &conn,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
    ) {
        Ok(proxy) => proxy,
        Err(err) => {
            tracing::debug!(target: "agent", "notification proxy failed: {err}");
            return false;
        }
    };
    let hints: HashMap<String, Value<'static>> = HashMap::new();
    let result: zbus::Result<u32> = proxy.call(
        "Notify",
        &(
            "lustless-agent",
            0u32,
            icon,
            summary,
            body,
            Vec::<String>::new(),
            hints,
            -1i32,
        ),
    );
    match result {
        Ok(_) => true,
        Err(err) => {
            tracing::debug!(target: "agent", "notification rejected: {err}");
            false
        }
    }
}

/// State-change announcement (sign-out, filter outage, break-glass progress
/// forwarded from §5 `NOTIFICATION` frames, panic) with the icon matching
/// the tray colour's urgency.
pub fn state_change(summary: &str, body: &str, color: crate::status::StatusColor) {
    use crate::status::StatusColor;
    let icon = match color {
        StatusColor::Green => "security-high",
        StatusColor::Amber => "dialog-warning",
        StatusColor::Red => "dialog-error",
        StatusColor::Gray => "dialog-information",
    };
    send(summary, body, icon);
}

/// The §13/A5 no-SNI-host startup sentence, pinned by test.
pub const STARTUP_TRAY_UNAVAILABLE_BODY: &str =
    "LustLess is running — open “LustLess” from the application menu to sign in";

/// The §13/A5 no-SNI-host startup announcement, sent once when the agent
/// comes up without a tray.
pub fn startup_tray_unavailable() {
    send(
        "LustLess running",
        STARTUP_TRAY_UNAVAILABLE_BODY,
        "dialog-information",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_message_matches_the_degradation_contract() {
        // The exact sentence required by the graceful-degradation contract
        // (assignment A5): with no tray, the application-menu launcher is
        // the sign-in surface — the message must name it, not just the CLI.
        assert_eq!(
            STARTUP_TRAY_UNAVAILABLE_BODY,
            "LustLess is running — open “LustLess” from the application menu to sign in"
        );
    }
}
