//! The tray menu as a declarative table (CONTRACTS §13: CE's menu vocabulary
//! — "Sign in/out, Switch user, Open dashboard, View activity, Refresh
//! settings, Collect diagnostics, Check for updates" — plus Quit) and the
//! action → §5 wire-code mapping the unit tests pin.

use serde_json::{json, Value};

use lustless_core::wire::Code;

/// The CE blocking-level vocabulary of §9 `filter.level` (the same strings
/// the daemon accepts on IPC 0x63).
pub const FILTER_LEVELS: [&str; 3] = [
    "Standard Blocking",
    "Strong Blocking",
    "Blocking Enabled",
];

/// One menu action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// "Sign in…" — collect credentials in a GTK dialog, then IPC 0x65.
    SignIn,
    /// "Sign out" — IPC 0x66.
    SignOut,
    /// "Switch user…" — CE's switch-user flow is a fresh sign-in dialog
    /// (IPC 0x65 with the other account).
    SwitchUser,
    /// "Open dashboard" — IPC 0x61 for the token-authenticated URL (§13),
    /// opened with `xdg-open`.
    OpenDashboard,
    /// "View activity" — same dashboard URL, `/activity` page (the CE
    /// `ViewDnsActivityHandler` log, §8).
    ViewActivity,
    /// "Set filter level" — IPC 0x63 with one of [`FILTER_LEVELS`].
    SetFilterLevel(&'static str),
    /// "Refresh settings" — IPC 0x53 (re-pushes the user's settings, §5),
    /// followed by a fresh POLICY_GET to repaint the tray.
    RefreshSettings,
    /// "Collect diagnostics" — IPC 0x43 (progress arrives as §5 0x02
    /// NOTIFICATION frames).
    CollectDiagnostics,
    /// "Check for updates" — IPC 0x67 (§12 recommendation).
    CheckForUpdates,
    /// "Quit" — clean agent shutdown (exit code 0).
    Quit,
}

impl Action {
    /// The §5 wire request this menu action performs; `Quit` has none.
    /// `SignIn`/`SwitchUser` return an empty placeholder payload — the
    /// caller fills `{"username","password"}` from the GTK dialog at click
    /// time (§5 0x65).
    pub fn wire_request(&self) -> Option<(Code, Value)> {
        match self {
            Action::SignIn | Action::SwitchUser => Some((Code::SignIn, json!({}))),
            Action::SignOut => Some((Code::SignOut, json!({}))),
            Action::OpenDashboard | Action::ViewActivity => Some((Code::StatusGet, json!({}))),
            Action::SetFilterLevel(level) => {
                Some((Code::FilterSetLevel, json!({ "level": level })))
            }
            Action::RefreshSettings => Some((Code::UserSettingsChange, json!({}))),
            Action::CollectDiagnostics => Some((Code::CollectDebugLogs, json!({}))),
            Action::CheckForUpdates => Some((Code::UpdateCheck, json!({}))),
            Action::Quit => None,
        }
    }
}

/// A declarative menu entry, rendered to GTK by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuEntry {
    /// A clickable item.
    Item {
        /// Menu label (CE vocabulary).
        label: &'static str,
        /// Click action.
        action: Action,
    },
    /// A submenu: "Set filter level ▸ …".
    Submenu {
        /// Parent label.
        label: &'static str,
        /// Child items.
        children: Vec<MenuEntry>,
    },
    /// A visual separator.
    Separator,
}

/// The tray menu, in order.
pub fn menu() -> Vec<MenuEntry> {
    use MenuEntry::{Item, Separator, Submenu};
    vec![
        Item {
            label: "Sign in…",
            action: Action::SignIn,
        },
        Item {
            label: "Sign out",
            action: Action::SignOut,
        },
        Item {
            label: "Switch user…",
            action: Action::SwitchUser,
        },
        Separator,
        Item {
            label: "Open dashboard",
            action: Action::OpenDashboard,
        },
        Item {
            label: "View activity",
            action: Action::ViewActivity,
        },
        Separator,
        Submenu {
            label: "Set filter level",
            children: FILTER_LEVELS
                .iter()
                .map(|level| Item {
                    label: level,
                    action: Action::SetFilterLevel(level),
                })
                .collect(),
        },
        Item {
            label: "Refresh settings",
            action: Action::RefreshSettings,
        },
        Item {
            label: "Collect diagnostics",
            action: Action::CollectDiagnostics,
        },
        Item {
            label: "Check for updates",
            action: Action::CheckForUpdates,
        },
        Separator,
        Item {
            label: "Quit",
            action: Action::Quit,
        },
    ]
}

/// Collects every action in the rendered menu (flattening submenus), paired
/// with its label — used by the mapping-table test.
#[cfg(test)]
fn flatten(entries: &[MenuEntry]) -> Vec<(&'static str, Action)> {
    let mut out = Vec::new();
    for entry in entries {
        match entry {
            MenuEntry::Item { label, action } => out.push((*label, action.clone())),
            MenuEntry::Submenu { children, .. } => out.extend(flatten(children)),
            MenuEntry::Separator => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_action_to_wire_code_table() {
        let table: &[(&Action, Option<Code>)] = &[
            (&Action::SignIn, Some(Code::SignIn)),
            (&Action::SwitchUser, Some(Code::SignIn)),
            (&Action::SignOut, Some(Code::SignOut)),
            (&Action::OpenDashboard, Some(Code::StatusGet)),
            (&Action::ViewActivity, Some(Code::StatusGet)),
            (&Action::SetFilterLevel("Standard Blocking"), Some(Code::FilterSetLevel)),
            (&Action::SetFilterLevel("Strong Blocking"), Some(Code::FilterSetLevel)),
            (&Action::SetFilterLevel("Blocking Enabled"), Some(Code::FilterSetLevel)),
            (&Action::RefreshSettings, Some(Code::UserSettingsChange)),
            (&Action::CollectDiagnostics, Some(Code::CollectDebugLogs)),
            (&Action::CheckForUpdates, Some(Code::UpdateCheck)),
            (&Action::Quit, None),
        ];
        for (action, expected) in table {
            assert_eq!(
                action.wire_request().map(|(code, _)| code),
                *expected,
                "{action:?}"
            );
        }
    }

    #[test]
    fn wire_code_bytes_match_the_contract_section_5_table() {
        let byte = |action: &Action| action.wire_request().unwrap().0.as_u8();
        assert_eq!(byte(&Action::SignIn), 0x65);
        assert_eq!(byte(&Action::SignOut), 0x66);
        assert_eq!(byte(&Action::SetFilterLevel("Standard Blocking")), 0x63);
        assert_eq!(byte(&Action::RefreshSettings), 0x53);
        assert_eq!(byte(&Action::CollectDiagnostics), 0x43);
        assert_eq!(byte(&Action::CheckForUpdates), 0x67);
        assert_eq!(byte(&Action::OpenDashboard), 0x61);
        assert_eq!(byte(&Action::ViewActivity), 0x61);
    }

    #[test]
    fn switch_user_reuses_the_sign_in_frame() {
        // CE's switch-user is a fresh sign-in with the other account; the
        // frame is SIGN_IN either way (§5 0x65).
        let (code, _) = Action::SwitchUser.wire_request().expect("wire request");
        assert_eq!(code, Code::SignIn);
    }

    #[test]
    fn menu_labels_keep_ce_vocabulary() {
        let entries = menu();
        // The submenu parent is not an action; check it on the tree directly.
        assert!(
            entries.iter().any(|entry| matches!(
                entry,
                MenuEntry::Submenu { label: "Set filter level", .. }
            )),
            "missing the filter-level submenu"
        );
        let flat = flatten(&entries);
        let labels: Vec<&str> = flat.iter().map(|(label, _)| *label).collect();
        for expected in [
            "Sign in…",
            "Sign out",
            "Switch user…",
            "Open dashboard",
            "View activity",
            "Standard Blocking",
            "Strong Blocking",
            "Blocking Enabled",
            "Refresh settings",
            "Collect diagnostics",
            "Check for updates",
            "Quit",
        ] {
            assert!(labels.contains(&expected), "missing menu label {expected}");
        }
        assert_eq!(flat.len(), 12, "menu must stay exactly the §13 vocabulary");
    }

    #[test]
    fn set_filter_level_payload_carries_the_level() {
        let (_, payload) = Action::SetFilterLevel("Strong Blocking")
            .wire_request()
            .expect("wire request");
        assert_eq!(payload, json!({"level": "Strong Blocking"}));
    }
}
