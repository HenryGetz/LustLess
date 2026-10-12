//! Tray status colour derived from the §9 `PolicySnapshot` (CONTRACTS §13:
//! "status icon color"). The tray icon itself is the fixed CE logo
//! (`indicator.rs`); the colour drives the adjacent label text and the
//! desktop notifications.
//!
//! Colour contract (product semantics):
//! * **green** — signed in, filtering active and healthy;
//! * **red** — signed out (fail-closed: "sign-out cuts web access", §8) or
//!   the account is panicked (`is_panicked`, static — no blinking);
//! * **amber** — degraded: filter health `outage`/`recovering`, or a sign-in
//!   / user-switch transition in flight;
//! * **gray** — no daemon reachable (unknown state).

use lustless_core::policy::{PolicySnapshot, UserState};

/// The four tray icon states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusColor {
    /// Signed in, filtering, healthy.
    Green,
    /// Degraded: filter outage/recovery, or transition in flight.
    Amber,
    /// Signed out (web blocked, fail-closed) or panicked.
    Red,
    /// Daemon unreachable — state unknown.
    Gray,
}

impl StatusColor {
    /// Menu/label text shown next to the icon.
    pub const fn label(self) -> &'static str {
        match self {
            StatusColor::Green => "Protected",
            StatusColor::Amber => "Degraded",
            StatusColor::Red => "Blocked",
            StatusColor::Gray => "Daemon unreachable",
        }
    }
}

/// Maps the latest snapshot (`None` = daemon unreachable) onto the colour.
pub fn color_for(snapshot: Option<&PolicySnapshot>) -> StatusColor {
    let Some(snapshot) = snapshot else {
        return StatusColor::Gray;
    };
    // Panic outranks everything: the account is in alert state (§9) — red,
    // static (the icon never blinks).
    if snapshot.is_panicked {
        return StatusColor::Red;
    }
    // Sign-out cuts web access (fail-closed, §8 `fail_closed_when_signed_out`).
    if !snapshot.signed_in || snapshot.state == UserState::LoggedOut {
        return StatusColor::Red;
    }
    // Degraded filter path.
    if matches!(snapshot.filter.health.as_str(), "outage" | "recovering") {
        return StatusColor::Amber;
    }
    // Sign-in / user-switch transitions in flight.
    if matches!(
        snapshot.state,
        UserState::LoggingIn | UserState::SwitchingUser
    ) {
        return StatusColor::Amber;
    }
    StatusColor::Green
}

#[cfg(test)]
mod tests {
    use super::*;
    use lustless_core::policy::{CapturePolicy, FilterPolicy};

    fn snapshot() -> PolicySnapshot {
        PolicySnapshot {
            username: "alice".into(),
            signed_in: true,
            state: UserState::LoggedIn,
            has_accountability: true,
            has_filtering: true,
            has_screen_accountability: true,
            has_url_accountability: false,
            has_dns_filtering: true,
            has_url_filtering: false,
            can_override: true,
            is_panicked: false,
            filter: FilterPolicy {
                level: "Standard Blocking".into(),
                fail_closed: true,
                health: "healthy".into(),
            },
            capture: CapturePolicy {
                active: true,
                backend: "x11".into(),
                last_screenstate_at: None,
            },
        }
    }

    #[test]
    fn colour_mapping_table() {
        let cases: &[(Option<PolicySnapshot>, StatusColor)] = &[
            // Daemon unreachable.
            (None, StatusColor::Gray),
            // Signed in + filtering + healthy → green.
            (Some(snapshot()), StatusColor::Green),
            // Signed out → red (sign-out cuts web access).
            (
                {
                    let mut s = snapshot();
                    s.signed_in = false;
                    s.state = UserState::LoggedOut;
                    Some(s)
                },
                StatusColor::Red,
            ),
            // LOGGED_OUT state without the flag still counts as signed out.
            (
                {
                    let mut s = snapshot();
                    s.state = UserState::LoggedOut;
                    Some(s)
                },
                StatusColor::Red,
            ),
            // Panic → red (static, never blinking).
            (
                {
                    let mut s = snapshot();
                    s.is_panicked = true;
                    Some(s)
                },
                StatusColor::Red,
            ),
            // Panic while signed out stays red.
            (
                {
                    let mut s = snapshot();
                    s.is_panicked = true;
                    s.signed_in = false;
                    Some(s)
                },
                StatusColor::Red,
            ),
            // Filter outage → amber.
            (
                {
                    let mut s = snapshot();
                    s.filter.health = "outage".into();
                    Some(s)
                },
                StatusColor::Amber,
            ),
            // Filter recovering → amber (degraded).
            (
                {
                    let mut s = snapshot();
                    s.filter.health = "recovering".into();
                    Some(s)
                },
                StatusColor::Amber,
            ),
            // Logging in → amber.
            (
                {
                    let mut s = snapshot();
                    s.state = UserState::LoggingIn;
                    Some(s)
                },
                StatusColor::Amber,
            ),
            // Switching user → amber.
            (
                {
                    let mut s = snapshot();
                    s.state = UserState::SwitchingUser;
                    Some(s)
                },
                StatusColor::Amber,
            ),
            // Panic outranks outage: red wins.
            (
                {
                    let mut s = snapshot();
                    s.is_panicked = true;
                    s.filter.health = "outage".into();
                    Some(s)
                },
                StatusColor::Red,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(color_for(input.as_ref()), *expected, "{input:?}");
        }
    }
}
