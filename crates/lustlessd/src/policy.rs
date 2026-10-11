//! Policy state machine — CONTRACTS §9 (`PolicySnapshot` vocabulary and the
//! `LOGGED_OUT|LOGGING_IN|LOGGED_IN|SWITCHING_USER` session lifecycle).
//!
//! Pure state: the machine, the `user_info` service flags mirrored into the
//! snapshot, and the mutable per-session policy fields. `state.rs` owns the
//! storage (`Mutex<`[`PolicyState`]`>` inside [`crate::state::DaemonState`])
//! and builds the §9 [`lustless_core::policy::PolicySnapshot`] from it; IPC
//! `0x60`, the dashboard and `lustless-net` all read that snapshot.
//!
//! Transition evidence (`re/findings/15-ui/signin-and-settings.md` §3): the
//! session-state strings at `0x1408e1650`; a failed switch logs "Reverting
//! back to current user" (`0x1408e4f60`); a failed fresh attempt returns to
//! `LOGGED_OUT`.

use lustless_core::policy::UserState;
use lustless_core::settings::{UserInfo, DEFAULT_FILTER_LEVEL};

/// CE's blocking-level vocabulary (`filter-surface.md` §1b; §9 `filter.level`)
/// — the only values IPC `0x63 FILTER_SET_LEVEL` and the `filter_level` field
/// of `0x53 USER_SETTINGS_CHANGE` accept.
pub const FILTER_LEVELS: [&str; 3] = [
    "Standard Blocking",
    "Strong Blocking",
    "Blocking Enabled",
];

/// The §9 `LOGGED_OUT|LOGGING_IN|LOGGED_IN|SWITCHING_USER` state machine.
///
/// Deterministic and lock-free; callers (`state.rs`) wrap it in the shared
/// policy mutex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMachine {
    state: UserState,
    username: String,
    /// Username the daemon reverts to when a `SWITCHING_USER` attempt fails.
    previous_username: String,
}

/// How [`PolicyMachine::begin_sign_in`] transitioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInBegin {
    /// From `LOGGED_OUT`: a fresh session.
    NewSession,
    /// From `LOGGED_IN`: a user switch (§9 `SWITCHING_USER`).
    SwitchingUser,
}

impl Default for PolicyMachine {
    fn default() -> Self {
        Self {
            state: UserState::LoggedOut,
            username: String::new(),
            previous_username: String::new(),
        }
    }
}

impl PolicyMachine {
    /// Starts in `LOGGED_OUT` with no username (§9).
    pub fn new() -> Self {
        Self::default()
    }

    /// Current session state (§9).
    pub fn state(&self) -> UserState {
        self.state
    }

    /// Signed-in CE account username; empty while logged out (§9).
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Username held while a switch is in flight (for diagnostics and the
    /// `switch_users` row written by `state.rs`).
    pub fn previous_username(&self) -> &str {
        &self.previous_username
    }

    /// `LOGGED_OUT → LOGGING_IN` or `LOGGED_IN → SWITCHING_USER`. A sign-in
    /// that is already in flight is rejected.
    pub fn begin_sign_in(&mut self) -> Result<SignInBegin, String> {
        match self.state {
            UserState::LoggedOut => {
                self.state = UserState::LoggingIn;
                Ok(SignInBegin::NewSession)
            }
            UserState::LoggedIn => {
                self.previous_username = self.username.clone();
                self.state = UserState::SwitchingUser;
                Ok(SignInBegin::SwitchingUser)
            }
            UserState::LoggingIn | UserState::SwitchingUser => {
                Err("a sign-in is already in progress".to_string())
            }
        }
    }

    /// `LOGGING_IN|SWITCHING_USER → LOGGED_IN`.
    pub fn complete_sign_in(&mut self, username: &str) {
        self.username = username.to_string();
        self.previous_username.clear();
        self.state = UserState::LoggedIn;
    }

    /// A failed attempt: `LOGGING_IN → LOGGED_OUT`, and a failed switch
    /// reverts to the previous user (CE "Reverting back to current user").
    pub fn fail_sign_in(&mut self) {
        match self.state {
            UserState::LoggingIn => {
                self.state = UserState::LoggedOut;
                self.username.clear();
            }
            UserState::SwitchingUser => {
                self.state = UserState::LoggedIn;
                self.username = std::mem::take(&mut self.previous_username);
            }
            UserState::LoggedIn | UserState::LoggedOut => {}
        }
    }

    /// `LOGGED_IN → LOGGED_OUT`, clearing the session identity (§9).
    pub fn sign_out(&mut self) {
        self.state = UserState::LoggedOut;
        self.username.clear();
        self.previous_username.clear();
    }
}

/// The §9 service flags mirrored from the `user_info` row (§6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserFlags {
    /// `user_info.is_active`.
    pub is_active: bool,
    /// §9 `can_override` (self-override).
    pub can_override: bool,
    /// §9 `is_panicked` — the *server-delivered* flag (§6.2); the local
    /// break-glass override (§5 `0x68`) does NOT set it: the snapshot reports
    /// that override through `filter.fail_closed = false` instead.
    pub is_panicked: bool,
    /// §9 `has_accountability`.
    pub has_accountability: bool,
    /// §9 `has_filtering`.
    pub has_filtering: bool,
    /// §9 `has_screen_accountability`.
    pub has_screen_accountability: bool,
    /// §9 `has_url_accountability`.
    pub has_url_accountability: bool,
    /// §9 `has_dns_filtering`.
    pub has_dns_filtering: bool,
    /// §9 `has_url_filtering`.
    pub has_url_filtering: bool,
}

impl Default for UserFlags {
    fn default() -> Self {
        UserFlags {
            is_active: false,
            can_override: false,
            is_panicked: false,
            has_accountability: false,
            has_filtering: false,
            has_screen_accountability: false,
            has_url_accountability: false,
            has_dns_filtering: false,
            has_url_filtering: false,
        }
    }
}

impl From<&UserInfo> for UserFlags {
    fn from(info: &UserInfo) -> Self {
        UserFlags {
            is_active: info.is_active,
            can_override: info.can_override,
            is_panicked: info.is_panicked,
            has_accountability: info.has_accountability,
            has_filtering: info.has_filtering,
            has_screen_accountability: info.has_screen_accountability,
            has_url_accountability: info.has_url_accountability,
            has_dns_filtering: info.has_dns_filtering,
            has_url_filtering: info.has_url_filtering,
        }
    }
}

/// First-run `user_info` for an offline account: the local services the
/// product ships with are on (there is no server to deliver §6.2 flags),
/// `is_panicked` stays `false`, self-override stays off until an admin or the
/// server enables it (§9 `can_override`).
pub fn fresh_user_info(username: &str) -> UserInfo {
    UserInfo {
        username: username.to_string(),
        first_name: None,
        last_name: None,
        is_active: true,
        can_override: false,
        timezone: None,
        has_filtering: true,
        has_screen_accountability: true,
        is_panicked: false,
        has_accountability: true,
        has_url_filtering: false,
        has_url_accountability: false,
        has_dns_filtering: true,
    }
}

/// Mutable §9 policy state guarded by one mutex inside
/// [`crate::state::DaemonState`].
#[derive(Debug, Clone)]
pub struct PolicyState {
    /// Sign-in state machine.
    pub machine: PolicyMachine,
    /// uid of the signed-in session (`None` while logged out).
    pub session_uid: Option<u32>,
    /// `logins.login_at` of the open session row (§6.1), closed on sign-out.
    pub session_login_at: Option<String>,
    /// Local session token handed back by `SIGN_IN` (§5 `0x65` reply
    /// `{"token",…}`); offline mode issues a random 128-bit token, online
    /// mode holds the server's `device_token`.
    pub session_token: Option<String>,
    /// Flags mirrored from `user_info`.
    pub flags: UserFlags,
    /// §9 `filter.level`.
    pub filter_level: String,
    /// Break-glass fail-open override (§5 `0x68`). While set,
    /// `PolicySnapshot.filter.fail_closed` is `false` — the fail-open
    /// override is what the snapshot reports, alongside `filter.health`.
    pub fail_open_override: bool,
    /// §9 `capture.active`.
    pub capture_active: bool,
    /// §9 `capture.last_screenstate_at`.
    pub last_screenstate_at: Option<String>,
    /// UI counter: real analyses from classifier `result.analyzed_count`
    /// (§7 documented improvement over CE's capture counting).
    pub analyzed_count: u64,
    /// When `analyzed_count` last moved (ISO-8601 UTC).
    pub analyzed_updated_at: Option<String>,
}

impl Default for PolicyState {
    fn default() -> Self {
        PolicyState {
            machine: PolicyMachine::new(),
            session_uid: None,
            session_login_at: None,
            session_token: None,
            flags: UserFlags::default(),
            filter_level: DEFAULT_FILTER_LEVEL.to_string(),
            fail_open_override: false,
            capture_active: false,
            last_screenstate_at: None,
            analyzed_count: 0,
            analyzed_updated_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §9 transition table: fresh sign-in, failed fresh attempt, user
    /// switch (success + revert), sign-out.
    #[test]
    fn policy_machine_transitions() {
        let mut machine = PolicyMachine::new();
        assert_eq!(machine.state(), UserState::LoggedOut);

        assert_eq!(
            machine.begin_sign_in().expect("begin"),
            SignInBegin::NewSession
        );
        assert_eq!(machine.state(), UserState::LoggingIn);
        assert!(machine.begin_sign_in().is_err(), "double begin rejected");

        machine.fail_sign_in();
        assert_eq!(machine.state(), UserState::LoggedOut);
        assert_eq!(machine.username(), "");

        // LOGGED_OUT -> LOGGING_IN -> LOGGED_IN.
        machine.begin_sign_in().expect("begin");
        machine.complete_sign_in("alice");
        assert_eq!(machine.state(), UserState::LoggedIn);
        assert_eq!(machine.username(), "alice");

        // LOGGED_IN -> SWITCHING_USER -> LOGGED_IN(new user).
        assert_eq!(
            machine.begin_sign_in().expect("switch"),
            SignInBegin::SwitchingUser
        );
        assert_eq!(machine.state(), UserState::SwitchingUser);
        assert_eq!(machine.previous_username(), "alice");
        machine.complete_sign_in("bob");
        assert_eq!(machine.state(), UserState::LoggedIn);
        assert_eq!(machine.username(), "bob");
        assert_eq!(machine.previous_username(), "");

        // A failed switch reverts to the current user (CE behavior).
        machine.begin_sign_in().expect("switch again");
        machine.fail_sign_in();
        assert_eq!(machine.state(), UserState::LoggedIn);
        assert_eq!(machine.username(), "bob");

        // LOGGED_IN -> LOGGED_OUT.
        machine.sign_out();
        assert_eq!(machine.state(), UserState::LoggedOut);
        assert_eq!(machine.username(), "");
    }

    /// Offline first-run flag defaults keep `is_panicked=false` (§9/§6.2).
    #[test]
    fn fresh_flags_match_the_offline_defaults() {
        let flags = UserFlags::from(&fresh_user_info("alice"));
        assert!(flags.is_active);
        assert!(flags.has_filtering);
        assert!(flags.has_screen_accountability);
        assert!(flags.has_dns_filtering);
        assert!(!flags.is_panicked, "§3/§9: offline sessions are not panicked");
        assert!(!flags.can_override, "self-override stays server/admin-gated");
        assert_eq!(
            FILTER_LEVELS,
            [
                "Standard Blocking",
                "Strong Blocking",
                "Blocking Enabled"
            ],
            "CE level vocabulary (filter-surface.md §1b)"
        );
    }
}
