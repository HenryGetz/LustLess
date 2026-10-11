//! `tokens.rs` — dashboard session tokens (CONTRACTS §13).
//!
//! The dashboard on `127.0.0.1:<daemon.dashboard_port>` is token-authenticated:
//! the daemon issues a token over IPC (sign-in 0x65 / the agent appending
//! `?t=` when opening the browser) via
//! [`NetServices::issue_dashboard_token`](crate::NetServices::issue_dashboard_token).
//!
//! Rules (§13 + task):
//!
//! * a token is 32 random bytes rendered as lowercase hex (64 chars);
//! * TTL 600 s, bound to the issuing uid;
//! * validated on **every** request (single-use is NOT required);
//! * expired or unknown tokens are rejected (HTTP 401 by the dashboard).
//!
//! There is deliberately no route that hands credentials to local consumers —
//! CE's `/local/user/:username:/keys.:doctype:` served the per-user API key
//! pair to anyone who could reach `127.0.0.1:48867`
//! (`re/findings/13-service-ipc/service-ipc.md` §1). That anti-pattern is not
//! reproduced: this store is the only credential surface of the dashboard.

use std::collections::HashMap;

use lustless_core::ids::to_hex;
use parking_lot::Mutex;
use rand::RngCore;

/// Dashboard-token TTL in seconds (§13; CE's local-dashboard exposure made
/// long-lived local credentials unavoidable — ours expire in 10 minutes).
pub(crate) const DASHBOARD_TOKEN_TTL_SECS: i64 = 600;

/// Entropy of one token in bytes (32 → 64 hex chars).
const TOKEN_BYTES: usize = 32;

/// One issued token: the uid it was bound to and its expiry (unix seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenEntry {
    /// uid of the peer the token was issued for (IPC `SOPEERCRED` uid, §5).
    pub(crate) uid: u32,
    /// Expiry instant, unix seconds.
    pub(crate) expires_at: i64,
}

/// The in-memory token registry behind the dashboard auth middleware.
#[derive(Debug, Default)]
pub(crate) struct TokenStore {
    inner: Mutex<HashMap<String, TokenEntry>>,
}

impl TokenStore {
    /// Issues a fresh token for `uid` with the standard §13 TTL.
    pub(crate) fn issue(&self, uid: u32, now: i64) -> String {
        self.issue_with_ttl(uid, now, DASHBOARD_TOKEN_TTL_SECS)
    }

    /// Issues a token with an explicit TTL (used by the unit tests to model
    /// expiry without sleeping 600 s).
    pub(crate) fn issue_with_ttl(&self, uid: u32, now: i64, ttl_secs: i64) -> String {
        let mut bytes = [0u8; TOKEN_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = to_hex(&bytes);
        let mut map = self.inner.lock();
        purge_expired(&mut map, now);
        map.insert(
            token.clone(),
            TokenEntry {
                uid,
                expires_at: now + ttl_secs,
            },
        );
        token
    }

    /// Validates `token` at `now`: returns the bound uid when the token is
    /// known and unexpired; expired entries are purged as they are seen.
    pub(crate) fn validate(&self, token: &str, now: i64) -> Option<u32> {
        let mut map = self.inner.lock();
        purge_expired(&mut map, now);
        map.get(token).map(|entry| entry.uid)
    }

    /// Live-token count (tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

/// Drops every expired entry (validation and issuance both run this, so the
/// map cannot grow past the live-token set).
fn purge_expired(map: &mut HashMap<String, TokenEntry>, now: i64) {
    map.retain(|_, entry| entry.expires_at > now);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_validate_binds_uid() {
        let store = TokenStore::default();
        let token = store.issue(1000, 1_000_000);
        assert_eq!(token.len(), TOKEN_BYTES * 2);
        assert!(token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(store.validate(&token, 1_000_000), Some(1000));
        // Still valid just before the TTL edge.
        assert_eq!(
            store.validate(&token, 1_000_000 + DASHBOARD_TOKEN_TTL_SECS - 1),
            Some(1000)
        );
    }

    #[test]
    fn tokens_are_unique_per_issue() {
        let store = TokenStore::default();
        let a = store.issue(1000, 1_000_000);
        let b = store.issue(1000, 1_000_000);
        assert_ne!(a, b);
    }

    #[test]
    fn expired_token_is_rejected_and_purged() {
        let store = TokenStore::default();
        let token = store.issue_with_ttl(1000, 1_000_000, 600);
        let later = 1_000_000 + 600; // exactly at expiry ⇒ expired
        assert_eq!(store.validate(&token, later), None);
        // Purged: the map no longer holds it.
        assert_eq!(store.len(), 0);
        assert_eq!(store.validate(&token, later + 1), None);
    }

    #[test]
    fn unknown_token_is_rejected() {
        let store = TokenStore::default();
        let _ = store.issue(1000, 1_000_000);
        assert_eq!(store.validate("deadbeef", 1_000_000), None);
        assert_eq!(store.validate("", 1_000_000), None);
    }

    #[test]
    fn tokens_are_uid_bound() {
        let store = TokenStore::default();
        let token = store.issue(1000, 1_000_000);
        assert_eq!(store.validate(&token, 1_000_000), Some(1000));
        assert_ne!(store.validate(&token, 1_000_000), Some(1001));
    }
}
