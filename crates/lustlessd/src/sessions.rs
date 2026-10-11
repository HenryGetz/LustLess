//! logind session tracking — CONTRACTS §13 ("logind D-Bus
//! `Lock`/`Unlock`/`SessionNew`/`SessionRemoved` drives capture policy") and
//! §7 gates (logind `LockedHint`/`Active`).
//!
//! One task subscribes to the `org.freedesktop.login1.Manager` signals
//! (`SessionNew`/`SessionRemoved`); every session gets a watcher task that
//! reacts to the session's `Lock`/`Unlock` signals and `Active`/`LockedHint`
//! property changes (plus a 5 s re-read as a missed-signal safety net). The
//! resulting per-uid active/unlocked state is the pure, unit-tested
//! [`SessionRegistry`] consumed by `capture_loop.rs`.
//!
//! If the system bus is unreachable the registry fails **open** with an error
//! log — the same "fail-open, never a silent no-op" policy as
//! `lustless_capture::scheduler::GateError` (§7).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::watch;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Proxy};

use lustless_capture::scheduler::GateReason;

use crate::state::{rguard, wguard, DaemonState};

const LOGIN1_DEST: &str = "org.freedesktop.login1";
const LOGIN1_PATH: &str = "/org/freedesktop/login1";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";

/// Re-read cadence for `Active`/`LockedHint` (safety net beside the signals).
const REFRESH_TICK: Duration = Duration::from_secs(5);

/// Gating state of one logind session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEntry {
    /// Owning uid.
    pub uid: u32,
    /// logind `Active` (session on the active seat/VT).
    pub active: bool,
    /// `!LockedHint` — the screen is unlocked.
    pub unlocked: bool,
}

/// Per-uid session registry (§13). Pure data structure: the capture gating
/// truth table lives here and is unit-tested without a bus.
pub struct SessionRegistry {
    /// Keyed by session object path.
    sessions: RwLock<HashMap<String, SessionEntry>>,
    /// `false` once the system bus was proven unreachable (fail-open gates).
    bus_ok: AtomicBool,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        SessionRegistry {
            sessions: RwLock::new(HashMap::new()),
            bus_ok: AtomicBool::new(true),
        }
    }
}

impl SessionRegistry {
    /// Creates an empty registry that will gate normally once logind answers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records (or refreshes) one session.
    pub fn upsert(&self, path: &str, uid: u32, active: bool, unlocked: bool) {
        wguard(&self.sessions).insert(
            path.to_string(),
            SessionEntry {
                uid,
                active,
                unlocked,
            },
        );
    }

    /// Updates the flags of a known session; unknown paths are ignored (the
    /// watcher may have been torn down already).
    pub fn set_flags(&self, path: &str, active: bool, unlocked: bool) {
        if let Some(entry) = wguard(&self.sessions).get_mut(path) {
            entry.active = active;
            entry.unlocked = unlocked;
        }
    }

    /// Removes a session; returns its entry when it existed.
    pub fn remove(&self, path: &str) -> Option<SessionEntry> {
        wguard(&self.sessions).remove(path)
    }

    /// Marks the system bus unreachable (gates then fail open, §7).
    pub fn mark_bus_unavailable(&self) {
        self.bus_ok.store(false, Ordering::Relaxed);
    }

    /// Whether logind tracking is operational.
    pub fn bus_ok(&self) -> bool {
        self.bus_ok.load(Ordering::Relaxed)
    }

    /// Number of tracked sessions (test helper).
    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        rguard(&self.sessions).len()
    }

    /// Lowest active-session uid, for the sign-in uid fallback (`Control`
    /// carries no uid; `sessions.rs` feeds the hint). Deterministic: uids are
    /// visited in ascending order.
    pub fn active_uid(&self) -> Option<u32> {
        let sessions = rguard(&self.sessions);
        let mut uids: Vec<u32> = sessions.values().map(|entry| entry.uid).collect();
        uids.sort_unstable();
        uids.dedup();
        uids.into_iter()
            .find(|uid| sessions.values().any(|e| e.uid == *uid && e.active))
    }

    /// Capture gate for `uid` (§7): `None` allows the tick, `Some(reason)`
    /// skips it.
    ///
    /// | sessions for uid | state | result |
    /// |---|---|---|
    /// | none | — | [`GateReason::SessionInactive`] |
    /// | any active + unlocked | unlocked | allow |
    /// | active but all locked | locked | [`GateReason::SessionLocked`] |
    /// | none active (locked or not) | switched away | [`GateReason::SessionInactive`] |
    pub fn gate(&self, uid: u32) -> Option<GateReason> {
        if !self.bus_ok() {
            return None;
        }
        let sessions = rguard(&self.sessions);
        let mut any_session = false;
        let mut any_active = false;
        for entry in sessions.values().filter(|entry| entry.uid == uid) {
            any_session = true;
            if entry.active {
                any_active = true;
                if entry.unlocked {
                    return None;
                }
            }
        }
        if !any_session {
            Some(GateReason::SessionInactive)
        } else if any_active {
            Some(GateReason::SessionLocked)
        } else {
            Some(GateReason::SessionInactive)
        }
    }
}

/// Extracts `(session id, object path)` from a `SessionNew`/`SessionRemoved`
/// body, tolerating either argument order (systemd has shipped both shapes
/// across interfaces; we only need the path).
fn parse_session_signal(msg: &zbus::Message) -> Option<(String, OwnedObjectPath)> {
    let body = msg.body();
    if let Ok(pair) = body.deserialize::<(String, OwnedObjectPath)>() {
        return Some(pair);
    }
    let (path, id) = body.deserialize::<(OwnedObjectPath, String)>().ok()?;
    Some((id, path))
}

/// Lists `(id, uid, path)` of the current sessions (§13).
async fn list_sessions(conn: &Connection) -> Result<Vec<(String, u32, String)>, String> {
    let manager = Proxy::new(conn, LOGIN1_DEST, LOGIN1_PATH, MANAGER_IFACE)
        .await
        .map_err(|err| err.to_string())?;
    let reply = manager
        .call_method("ListSessions", &())
        .await
        .map_err(|err| err.to_string())?;
    let sessions: Vec<(String, u32, String, String, OwnedObjectPath)> = reply
        .body()
        .deserialize()
        .map_err(|err| format!("ListSessions decode: {err}"))?;
    Ok(sessions
        .into_iter()
        .map(|(id, uid, _name, _seat, path)| (id, uid, path.to_string()))
        .collect())
}

/// Recomputes the sticky active-session uid hint (sign-in fallback).
fn update_active_hint(registry: &SessionRegistry, state: &DaemonState) {
    if let Some(uid) = registry.active_uid() {
        state.set_active_session_uid(uid);
    }
}

/// Drives the registry from logind until shutdown: initial enumeration plus
/// `SessionNew`/`SessionRemoved` signals; every session gets its own watcher.
pub async fn run(
    registry: Arc<SessionRegistry>,
    state: Arc<DaemonState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let conn = match Connection::system().await {
        Ok(conn) => conn,
        Err(err) => {
            registry.mark_bus_unavailable();
            tracing::error!("logind: system bus unavailable; session gates fail open: {err}");
            return;
        }
    };

    match list_sessions(&conn).await {
        Ok(sessions) => {
            tracing::info!("logind: tracking {} existing session(s)", sessions.len());
            for (_id, uid, path) in sessions {
                spawn_session_watcher(
                    &conn,
                    path,
                    Some(uid),
                    Arc::clone(&registry),
                    Arc::clone(&state),
                    shutdown.clone(),
                );
            }
        }
        Err(err) => {
            registry.mark_bus_unavailable();
            tracing::error!("logind: ListSessions failed; session gates fail open: {err}");
            return;
        }
    }

    let manager = match Proxy::new(&conn, LOGIN1_DEST, LOGIN1_PATH, MANAGER_IFACE).await {
        Ok(proxy) => proxy,
        Err(err) => {
            registry.mark_bus_unavailable();
            tracing::error!("logind: manager proxy failed; session gates fail open: {err}");
            return;
        }
    };
    let mut signals = match manager.receive_all_signals().await {
        Ok(stream) => stream,
        Err(err) => {
            registry.mark_bus_unavailable();
            tracing::error!("logind: signal subscription failed; gates fail open: {err}");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            msg = signals.next() => {
                let Some(msg) = msg else { break };
                let member = msg.header().member().map(|m| m.as_str().to_string());
                match member.as_deref() {
                    Some("SessionNew") => {
                        if let Some((id, path)) = parse_session_signal(&msg) {
                            tracing::info!("logind: session new {id} ({path})");
                            spawn_session_watcher(
                                &conn,
                                path.to_string(),
                                None,
                                Arc::clone(&registry),
                                Arc::clone(&state),
                                shutdown.clone(),
                            );
                        }
                    }
                    Some("SessionRemoved") => {
                        if let Some((id, path)) = parse_session_signal(&msg) {
                            tracing::info!("logind: session removed {id} ({path})");
                            registry.remove(path.as_str());
                            update_active_hint(&registry, &state);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn spawn_session_watcher(
    conn: &Connection,
    path: String,
    uid: Option<u32>,
    registry: Arc<SessionRegistry>,
    state: Arc<DaemonState>,
    shutdown: watch::Receiver<bool>,
) {
    let conn = conn.clone();
    tokio::spawn(async move {
        watch_session(conn, path, uid, registry, state, shutdown).await;
    });
}

/// Per-session watcher: initial state, `Lock`/`Unlock` signals,
/// `Active`/`LockedHint` property changes and a 5 s refresh.
async fn watch_session(
    conn: Connection,
    path: String,
    uid: Option<u32>,
    registry: Arc<SessionRegistry>,
    state: Arc<DaemonState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let proxy = match Proxy::new(&conn, LOGIN1_DEST, path.as_str(), SESSION_IFACE).await {
        Ok(proxy) => proxy,
        Err(err) => {
            tracing::warn!("logind: session proxy {path} failed: {err}");
            return;
        }
    };
    let uid = match uid {
        Some(uid) => uid,
        None => match proxy.get_property::<u32>("User").await {
            Ok(uid) => uid,
            Err(err) => {
                tracing::warn!("logind: session {path} has no User property: {err}");
                return;
            }
        },
    };

    // Initial reads; with `CacheProperties::Lazily` (zbus default) they also
    // prime the cache the property-change streams below consume.
    let mut active = proxy.get_property::<bool>("Active").await.unwrap_or(false);
    let mut unlocked = !proxy.get_property::<bool>("LockedHint").await.unwrap_or(true);
    registry.upsert(&path, uid, active, unlocked);
    update_active_hint(&registry, &state);
    tracing::debug!("logind: watching session {path} (uid {uid}, active {active}, unlocked {unlocked})");

    let mut lock_stream = match proxy.receive_signal("Lock").await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!("logind: Lock subscription for {path} failed: {err}");
            return;
        }
    };
    let mut unlock_stream = match proxy.receive_signal("Unlock").await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!("logind: Unlock subscription for {path} failed: {err}");
            return;
        }
    };
    let mut active_stream = proxy.receive_property_changed::<bool>("Active").await;
    let mut locked_stream = proxy.receive_property_changed::<bool>("LockedHint").await;

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            msg = lock_stream.next() => {
                if msg.is_none() {
                    break;
                }
                unlocked = false;
                registry.set_flags(&path, active, unlocked);
                tracing::info!("logind: session {path} locked");
            }
            msg = unlock_stream.next() => {
                if msg.is_none() {
                    break;
                }
                unlocked = true;
                registry.set_flags(&path, active, unlocked);
                tracing::info!("logind: session {path} unlocked");
            }
            changed = active_stream.next() => {
                let Some(changed) = changed else { break };
                match changed.get().await {
                    Ok(value) => {
                        active = value;
                        registry.set_flags(&path, active, unlocked);
                        update_active_hint(&registry, &state);
                    }
                    Err(err) => tracing::warn!("logind: Active read for {path} failed: {err}"),
                }
            }
            changed = locked_stream.next() => {
                let Some(changed) = changed else { break };
                match changed.get().await {
                    Ok(locked) => {
                        unlocked = !locked;
                        registry.set_flags(&path, active, unlocked);
                    }
                    Err(err) => tracing::warn!("logind: LockedHint read for {path} failed: {err}"),
                }
            }
            _ = tokio::time::sleep(REFRESH_TICK) => {
                // Safety net for missed signals (CE polled once per second;
                // §13 chose signals + a slow refresh).
                let next_active = proxy.get_property::<bool>("Active").await;
                let next_locked = proxy.get_property::<bool>("LockedHint").await;
                match (next_active, next_locked) {
                    (Ok(new_active), Ok(new_locked)) => {
                        active = new_active;
                        unlocked = !new_locked;
                        registry.set_flags(&path, active, unlocked);
                    }
                    (Err(err), _) | (_, Err(err)) => {
                        tracing::warn!("logind: session {path} vanished: {err}");
                        registry.remove(&path);
                        update_active_hint(&registry, &state);
                        break;
                    }
                }
            }
        }
    }
    registry.remove(&path);
    update_active_hint(&registry, &state);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_with(entries: &[(&str, u32, bool, bool)]) -> SessionRegistry {
        let registry = SessionRegistry::new();
        for (path, uid, active, unlocked) in entries {
            registry.upsert(path, *uid, *active, *unlocked);
        }
        registry
    }

    /// The §7/§13 session-gating truth table.
    #[test]
    fn gating_truth_table() {
        // No session at all for the uid → inactive.
        let registry = registry_with(&[("s1", 1000, true, true)]);
        assert_eq!(registry.gate(2000), Some(GateReason::SessionInactive));

        // Active + unlocked → capture allowed.
        let registry = registry_with(&[("s1", 1000, true, true)]);
        assert_eq!(registry.gate(1000), None);

        // Active but locked → session locked.
        let registry = registry_with(&[("s1", 1000, true, false)]);
        assert_eq!(registry.gate(1000), Some(GateReason::SessionLocked));

        // Inactive (switched away), unlocked → session inactive.
        let registry = registry_with(&[("s1", 1000, false, true)]);
        assert_eq!(registry.gate(1000), Some(GateReason::SessionInactive));

        // Inactive AND locked → inactive dominates (nothing to capture).
        let registry = registry_with(&[("s1", 1000, false, false)]);
        assert_eq!(registry.gate(1000), Some(GateReason::SessionInactive));

        // Multi-session: a second session can unblock the gate.
        let registry = registry_with(&[("s1", 1000, false, false), ("s2", 1000, true, true)]);
        assert_eq!(registry.gate(1000), None, "any active+unlocked session wins");

        // Multi-session: all active ones locked → locked, not inactive.
        let registry = registry_with(&[("s1", 1000, true, false), ("s2", 1000, false, true)]);
        assert_eq!(registry.gate(1000), Some(GateReason::SessionLocked));

        // Removal empties the gate.
        let registry = registry_with(&[("s1", 1000, true, true)]);
        assert!(registry.remove("s1").is_some());
        assert_eq!(registry.gate(1000), Some(GateReason::SessionInactive));
        assert!(registry.remove("s1").is_none());
    }

    #[test]
    fn bus_failure_fails_open() {
        let registry = registry_with(&[("s1", 1000, true, false)]);
        assert_eq!(registry.gate(1000), Some(GateReason::SessionLocked));
        registry.mark_bus_unavailable();
        assert_eq!(
            registry.gate(1000),
            None,
            "no bus ⇒ fail open with an error log (§7 policy)"
        );
    }

    #[test]
    fn active_uid_prefers_lowest_active_session() {
        let registry = registry_with(&[
            ("s2", 2000, true, true),
            ("s1", 1000, true, true),
            ("s0", 500, false, true),
        ]);
        assert_eq!(registry.active_uid(), Some(1000));
        let registry = registry_with(&[("s0", 500, false, true)]);
        assert_eq!(registry.active_uid(), None);
        let registry = SessionRegistry::new();
        assert_eq!(registry.active_uid(), None);
        assert_eq!(registry.session_count(), 0);
    }

    #[test]
    fn session_signal_body_tolerates_either_argument_order() {
        let path: OwnedObjectPath = "/org/freedesktop/login1/session/c2".try_into().expect("path");
        // (id, path) — the documented systemd shape.
        let msg_a = zbus::Message::method_call("/org/freedesktop/login1", "SessionNew")
            .expect("builder")
            .build(&("c2", path.clone()))
            .expect("msg a");
        let parsed = parse_session_signal(&msg_a).expect("parse a");
        assert_eq!(parsed.0, "c2");
        // (path, id) — reversed order still parses.
        let msg_b = zbus::Message::method_call("/org/freedesktop/login1", "SessionNew")
            .expect("builder")
            .build(&(path, "c3"))
            .expect("msg b");
        let parsed = parse_session_signal(&msg_b).expect("parse b");
        assert_eq!(parsed.0, "c3");
        // Wrong shapes fail cleanly (no panic).
        let msg_c = zbus::Message::method_call("/org/freedesktop/login1", "SessionNew")
            .expect("builder")
            .build(&(42u32, "x"))
            .expect("msg c");
        assert!(parse_session_signal(&msg_c).is_none());
    }
}
