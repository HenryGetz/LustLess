//! Read-only policy snapshot served over IPC 0x60 (`POLICY_GET`) and to the
//! dashboard — CONTRACTS §9 (replaces CE's `CE_SPYMapObj` shared-memory block,
//! `ui-architecture.md` §4b).
//!
//! The wire form is the §9 struct verbatim: one JSON object whose field names
//! are `username`, `signed_in`, `state`, `has_accountability`, … , `filter`,
//! `capture`.

use serde::{Deserialize, Serialize};

/// Session state of the (single) filtering user — the
/// `LOGGED_OUT|LOGGING_IN|LOGGED_IN|SWITCHING_USER` vocabulary of §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserState {
    /// No account is signed in (§9).
    LoggedOut,
    /// A sign-in (IPC 0x65) is in flight (§9).
    LoggingIn,
    /// An account is signed in (§9).
    LoggedIn,
    /// A user switch (CE `switchUserActivityRecord` flow, §10) is in flight
    /// (§9).
    SwitchingUser,
}

/// The `filter` half of the §9 snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterPolicy {
    /// The user's blocking level. CE's client-side vocabulary is
    /// `"Standard Blocking"` (default), `"Strong Blocking"`, and
    /// `"Blocking Enabled"` (`filter-surface.md` §1b); the daemon passes the
    /// account's value through verbatim.
    pub level: String,
    /// Fail-closed flag of the forwarder: "signed out ⇒ web blocked" (§8,
    /// config `dns.fail_closed_when_signed_out` §9.1).
    pub fail_closed: bool,
    /// The DNS forwarder's health state (`error-recovery` machine of §8),
    /// forwarder-owned vocabulary rendered as a plain string.
    pub health: String,
}

/// The `capture` half of the §9 snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturePolicy {
    /// Whether screen-state capture is currently running (§7 gates: session
    /// active, not locked).
    pub active: bool,
    /// Capture backend: `"auto" | "x11" | "wayland"` (§7, config
    /// `capture.backend` §9.1).
    pub backend: String,
    /// ISO-8601 UTC stamp of the last written screenstate transaction (§6.3),
    /// `None` before the first capture.
    pub last_screenstate_at: Option<String>,
}

/// The policy snapshot of §9 — served read-only over IPC 0x60 and to the
/// dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    /// CE account username of the filtering user (§9).
    pub username: String,
    /// Whether an account is signed in (§9).
    pub signed_in: bool,
    /// Session state (§9).
    pub state: UserState,
    /// `has_accountability` service flag (`filter-surface.md` §1a; §9).
    pub has_accountability: bool,
    /// `has_filtering` service flag (§9).
    pub has_filtering: bool,
    /// `has_screen_accountability` service flag (§9).
    pub has_screen_accountability: bool,
    /// `has_url_accountability` service flag (§9).
    pub has_url_accountability: bool,
    /// `has_dns_filtering` service flag (§9).
    pub has_dns_filtering: bool,
    /// `has_url_filtering` service flag (§9).
    pub has_url_filtering: bool,
    /// Whether the user may override blocks (self-override, §9).
    pub can_override: bool,
    /// Panic flag (§9).
    pub is_panicked: bool,
    /// Filter policy block (§9).
    pub filter: FilterPolicy,
    /// Capture policy block (§9).
    pub capture: CapturePolicy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot() -> PolicySnapshot {
        PolicySnapshot {
            username: "kckt0717".into(),
            signed_in: true,
            state: UserState::LoggedIn,
            has_accountability: true,
            has_filtering: true,
            has_screen_accountability: false,
            has_url_accountability: true,
            has_dns_filtering: true,
            has_url_filtering: false,
            can_override: false,
            is_panicked: false,
            filter: FilterPolicy {
                level: "Standard Blocking".into(),
                fail_closed: true,
                health: "healthy".into(),
            },
            capture: CapturePolicy {
                active: true,
                backend: "auto".into(),
                last_screenstate_at: Some("2026-10-11T12:00:00Z".into()),
            },
        }
    }

    #[test]
    fn json_field_names_match_contract_section_9() {
        let value = serde_json::to_value(snapshot()).expect("serialize");
        let object = value.as_object().expect("snapshot is an object");
        let expected = [
            "username",
            "signed_in",
            "state",
            "has_accountability",
            "has_filtering",
            "has_screen_accountability",
            "has_url_accountability",
            "has_dns_filtering",
            "has_url_filtering",
            "can_override",
            "is_panicked",
            "filter",
            "capture",
        ];
        assert_eq!(object.len(), expected.len());
        for key in expected {
            assert!(object.contains_key(key), "missing §9 field {key}");
        }
        let filter = object["filter"].as_object().expect("filter object");
        assert_eq!(filter.len(), 3);
        for key in ["level", "fail_closed", "health"] {
            assert!(filter.contains_key(key), "missing §9 filter.{key}");
        }
        let capture = object["capture"].as_object().expect("capture object");
        assert_eq!(capture.len(), 3);
        for key in ["active", "backend", "last_screenstate_at"] {
            assert!(capture.contains_key(key), "missing §9 capture.{key}");
        }
    }

    #[test]
    fn user_state_serializes_in_contract_vocabulary() {
        assert_eq!(
            serde_json::to_value(UserState::LoggedOut).unwrap(),
            json!("LOGGED_OUT")
        );
        assert_eq!(
            serde_json::to_value(UserState::LoggingIn).unwrap(),
            json!("LOGGING_IN")
        );
        assert_eq!(
            serde_json::to_value(UserState::LoggedIn).unwrap(),
            json!("LOGGED_IN")
        );
        assert_eq!(
            serde_json::to_value(UserState::SwitchingUser).unwrap(),
            json!("SWITCHING_USER")
        );
    }

    #[test]
    fn snapshot_round_trips() {
        let original = snapshot();
        let text = serde_json::to_string(&original).expect("serialize");
        let back: PolicySnapshot = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(original, back);
    }
}
