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
use std::path::{Path, PathBuf};
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

/// Kind of logind session, from the `Type` property (CONTRACTS §7/§13). Only
/// `X11`/`Wayland` have a screen worth capturing; `Tty` (text console) and
/// everything else (including logind's `mir`/`unspecified`) cannot be captured
/// through either backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// X11 graphical session.
    X11,
    /// Wayland graphical session.
    Wayland,
    /// Text/VT session (no display server).
    Tty,
    /// Any other/unknown `Type` (`mir`, `unspecified`, missing property, …).
    Unknown,
}

impl SessionKind {
    /// Parses a logind `Type` value. Strict: only the exact strings `x11`,
    /// `wayland` and `tty` are recognized.
    pub fn parse(raw: &str) -> SessionKind {
        match raw {
            "x11" => SessionKind::X11,
            "wayland" => SessionKind::Wayland,
            "tty" => SessionKind::Tty,
            _ => SessionKind::Unknown,
        }
    }

    /// The value the capture backends expect as `XDG_SESSION_TYPE`
    /// ([`lustless_capture::resolve_backend`]): `Some("x11")`/`Some("wayland")`
    /// for graphical sessions, `None` for `Tty`/`Unknown` so the caller's
    /// existing fallback applies.
    pub fn as_session_type(self) -> Option<&'static str> {
        match self {
            SessionKind::X11 => Some("x11"),
            SessionKind::Wayland => Some("wayland"),
            SessionKind::Tty | SessionKind::Unknown => None,
        }
    }
}

/// Gating state of one logind session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEntry {
    /// Owning uid.
    pub uid: u32,
    /// logind `Active` (session on the active seat/VT).
    pub active: bool,
    /// `!LockedHint` — the screen is unlocked.
    pub unlocked: bool,
    /// logind `Type` — which display server the session runs.
    pub kind: SessionKind,
    /// logind `Display` (e.g. `:0`), empty for text sessions.
    ///
    /// Empty on plenty of desktops (`loginctl show-session … -p Display`
    /// prints `Display=` under XFCE/Zorin Lite), so [`SessionEnv::resolve`]
    /// treats this as a *hint* and recovers the real value from the session
    /// leader's environment when it is missing.
    pub display: Option<String>,
    /// logind `Remote` — a remote/SSH session must never be captured (§13).
    pub remote: bool,
    /// logind `Leader` — the session leader's PID (`u`), or `None` when the
    /// property is absent/zero (old logind, or the leader already exited).
    /// The leader's `/proc/<pid>/environ` is the only place the real `DISPLAY`
    /// and `XAUTHORITY` live when logind's `Display` is empty.
    pub leader: Option<u32>,
}

impl SessionEntry {
    /// Whether this session may be captured at all: graphical and not remote
    /// (§13 — a remote or text session has no local screen worth capturing,
    /// and capturing one would be a privacy leak).
    pub fn capturable(&self) -> bool {
        !self.remote && self.kind != SessionKind::Tty
    }

    /// Why capture must be skipped, for the info log; `None` = capturable.
    pub fn skip_reason(&self) -> Option<&'static str> {
        if self.remote {
            Some("remote session")
        } else if self.kind == SessionKind::Tty {
            Some("text session")
        } else {
            None
        }
    }
}

/// Everything a capture backend needs to reach a session that a root daemon
/// does not itself run in. Derived from a [`SessionEntry`] plus the uid; see
/// [`SessionEnv::apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnv {
    /// Session bus/runtime owner.
    pub uid: u32,
    /// `/run/user/<uid>`.
    pub runtime_dir: PathBuf,
    /// `unix:path=/run/user/<uid>/bus` — the session D-Bus (xdg-desktop-portal).
    pub bus_address: String,
    /// logind `Display` (e.g. `:0`).
    pub display: Option<String>,
    /// First existing `XAUTHORITY` candidate, if any.
    pub xauthority: Option<PathBuf>,
    /// Session kind (drives backend selection).
    pub kind: SessionKind,
}

impl SessionEnv {
    /// Pure derivation from `(uid, entry, home)`. `home` is the session user's
    /// home directory, or `None` when unknown; it is injected so tests can use
    /// a fake root without a real `/etc/passwd` lookup.
    pub fn derive(uid: u32, entry: &SessionEntry, home: Option<&Path>) -> SessionEnv {
        let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
        let bus_address = format!("unix:path={}/bus", runtime_dir.display());
        let xauthority = probe_xauthority(&xauthority_candidates(uid, home));
        SessionEnv {
            uid,
            runtime_dir,
            bus_address,
            display: entry.display.clone(),
            xauthority,
            kind: entry.kind,
        }
    }

    /// Derives the environment using the real home directory of `uid`
    /// ([`home_for`]).
    ///
    /// Unlike [`derive`](Self::derive) this also *recovers* `DISPLAY` and
    /// `XAUTHORITY` from the session's processes: logind's `Display` is empty
    /// on many desktops, and without a real `DISPLAY` the X11 backend cannot
    /// even connect (`$DISPLAY variable not set`). The leader — and, when its
    /// own environment lacks the value, its descendants — carry the values the
    /// session's display server was actually exported to.
    pub fn resolve(uid: u32, entry: &SessionEntry) -> SessionEnv {
        let mut env = SessionEnv::derive(uid, entry, home_for(uid).as_deref());
        env.display = select_display(
            entry.kind,
            entry.display.clone(),
            environ_from_session(entry.leader, "DISPLAY").as_deref(),
        );
        // logind exposes no `XAUTHORITY` at all, so the leader's environment is
        // the only *authoritative* source; the ordered file probe (already in
        // `env.xauthority`) remains the fallback when no process carries it.
        env.xauthority = select_xauthority(
            environ_from_session(entry.leader, "XAUTHORITY").as_deref(),
            env.xauthority,
        );
        env
    }

    /// Writes the session values into the process environment so the backends'
    /// own libraries pick them up.
    ///
    /// (a) This is called once when a session is first resolved, and again only
    /// when the resolved session changes (uid or kind); the caller tracks that.
    /// (b) It is called from the capture task, not from arbitrary threads.
    /// (c) The alternative — threading these values through every backend API —
    /// is deliberately not taken because the X11 (`x11rb`) and portal
    /// (xdg-desktop-portal over the session bus) libraries read `DISPLAY`,
    /// `XAUTHORITY`, `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` from the
    /// environment themselves.
    ///
    /// Caveat, honestly: `std::env::set_var` mutates process-global state and
    /// is not thread-safe against concurrent `getenv` (which is why Rust 2024
    /// marks it `unsafe`). It is acceptable here only because the daemon's
    /// other threads do not read these variables and the capture task owns the
    /// backend; it is a known sharp edge, not a clean design.
    pub fn apply(&self) {
        std::env::set_var("XDG_RUNTIME_DIR", &self.runtime_dir);
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &self.bus_address);
        match &self.display {
            Some(display) => std::env::set_var("DISPLAY", display),
            None => std::env::remove_var("DISPLAY"),
        }
        match &self.xauthority {
            Some(path) => std::env::set_var("XAUTHORITY", path),
            None => std::env::remove_var("XAUTHORITY"),
        }
        match self.kind {
            SessionKind::X11 => std::env::set_var("XDG_SESSION_TYPE", "x11"),
            SessionKind::Wayland => std::env::set_var("XDG_SESSION_TYPE", "wayland"),
            SessionKind::Tty => std::env::set_var("XDG_SESSION_TYPE", "tty"),
            SessionKind::Unknown => std::env::remove_var("XDG_SESSION_TYPE"),
        }
    }
}

/// Ordered `XAUTHORITY` candidates for a session; the first that exists wins.
pub fn xauthority_candidates(uid: u32, home: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(3);
    candidates.push(PathBuf::from(format!("/run/user/{uid}/gdm/Xauthority")));
    candidates.push(PathBuf::from(format!("/run/user/{uid}/Xauthority")));
    if let Some(home) = home {
        candidates.push(home.join(".Xauthority"));
    }
    candidates
}

/// First candidate that exists on disk; `None` when none do.
fn probe_xauthority(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|path| path.exists()).cloned()
}

/// Extracts `key` from a NUL-separated `/proc/<pid>/environ` blob.
///
/// Pure and bounds-safe by construction: the blob is *not* guaranteed UTF-8
/// (paths, translated variables), so it is scanned as bytes and only the
/// matching value is decoded. An entry with no `=` is skipped; only the first
/// `=` separates name from value, so a value containing `=` (`A=b=c`) survives
/// intact. A matching key whose value is not UTF-8 yields `None` rather than a
/// lossy replacement or a panic.
fn parse_environ(bytes: &[u8], key: &str) -> Option<String> {
    for entry in bytes.split(|&byte| byte == 0) {
        let Some(eq) = entry.iter().position(|&byte| byte == b'=') else {
            continue;
        };
        if entry[..eq] == *key.as_bytes() {
            return std::str::from_utf8(&entry[eq + 1..])
                .ok()
                .map(str::to_string);
        }
    }
    None
}

/// [`parse_environ`] treating an empty value (`DISPLAY=`) as absent — an empty
/// `DISPLAY` is as unusable as no `DISPLAY` and must trigger recovery.
fn environ_value(bytes: &[u8], key: &str) -> Option<String> {
    parse_environ(bytes, key).filter(|value| !value.is_empty())
}

/// Reads `/proc/<pid>/environ`; `None` when unreadable (process gone, or
/// hidepid). Logind's leader/descendants belong to the user, but the daemon
/// runs as root, so these reads normally succeed.
fn read_environ(pid: u32) -> Option<Vec<u8>> {
    std::fs::read(format!("/proc/{pid}/environ")).ok()
}

/// Bound on how many descendants are visited while hunting for a variable.
/// Enumerating `/proc` once is unavoidable for a PPID search (there is no
/// children index), but this caps the work so an enormous process tree cannot
/// stall the capture task.
const MAX_DESCENDANTS: usize = 512;

/// `/proc/<pid>/stat` field 4 is the PPID. Field 2 (`comm`) may itself contain
/// spaces and parentheses, so the line is split after its *last* `)`.
fn ppid_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Breadth-first list of `root`'s descendants, capped at [`MAX_DESCENDANTS`].
fn descendants(root: u32) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(ppid) = ppid_of(pid) {
            children.entry(ppid).or_default().push(pid);
        }
    }
    let mut found = Vec::new();
    let mut queue = vec![root];
    while let Some(pid) = queue.pop() {
        let Some(kids) = children.get(&pid) else {
            continue;
        };
        for &kid in kids {
            if found.len() >= MAX_DESCENDANTS {
                return found;
            }
            found.push(kid);
            queue.push(kid);
        }
    }
    found
}

/// The first `/proc/<pid>/environ` blob (session leader first, then its
/// descendants) that defines `key`. Returns the whole blob so a caller can ask
/// for a second variable from the same process without another `/proc` sweep.
/// Descendants are only walked when the leader's own environment lacks `key`.
fn environ_from_session(leader: Option<u32>, key: &str) -> Option<Vec<u8>> {
    let leader = leader?;
    if let Some(bytes) = read_environ(leader) {
        if environ_value(&bytes, key).is_some() {
            return Some(bytes);
        }
    }
    descendants(leader)
        .into_iter()
        .filter_map(read_environ)
        .find(|bytes| environ_value(bytes, key).is_some())
}

/// Pure `DISPLAY` selection, in preference order: logind's `Display` → the
/// session process environment → `:0` for an `X11` session.
///
/// The `:0` guess is deliberate: an X11 session almost always has a local
/// display, and a *wrong* guess merely makes the backend report a connection
/// error (visible, retried), whereas returning `None` guarantees
/// `$DISPLAY variable not set` and capture never runs at all. A guess beats a
/// guaranteed failure. Wayland sessions are never guessed — they need
/// `XDG_RUNTIME_DIR` and the session bus, not `DISPLAY`.
fn select_display(
    kind: SessionKind,
    logind: Option<String>,
    session_environ: Option<&[u8]>,
) -> Option<String> {
    if let Some(logind) = logind {
        return Some(logind);
    }
    if let Some(display) = session_environ.and_then(|bytes| environ_value(bytes, "DISPLAY")) {
        return Some(display);
    }
    if kind == SessionKind::X11 {
        return Some(":0".to_string());
    }
    None
}

/// `XAUTHORITY` selection: the session process environment (the only
/// authoritative source — logind has no such property) wins over `probed`,
/// which is the ordered [`xauthority_candidates`] probe result.
fn select_xauthority(session_environ: Option<&[u8]>, probed: Option<PathBuf>) -> Option<PathBuf> {
    session_environ
        .and_then(|bytes| environ_value(bytes, "XAUTHORITY"))
        .map(PathBuf::from)
        .or(probed)
}

/// Home directory of `uid` from `/etc/passwd`. Deliberately dependency-free:
/// local desktop sessions are in `/etc/passwd`; NSS/LDAP-provided homes are
/// not resolved (they would need `getpwuid`/a new dependency).
fn home_for(uid: u32) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 && fields[2].parse::<u32>().ok() == Some(uid) && !fields[5].is_empty()
        {
            return Some(PathBuf::from(fields[5]));
        }
    }
    None
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

    /// Records (or refreshes) one session. Keeps the legacy flag-only shape:
    /// `Type`/`Display`/`Remote`/`Leader` default to
    /// `Unknown`/`None`/`false`/`None`.
    ///
    /// Test-only: production code always has the logind `Type`/`Display`/`Remote`
    /// properties in hand and goes through [`Self::upsert_entry`].
    #[cfg(test)]
    pub fn upsert(&self, path: &str, uid: u32, active: bool, unlocked: bool) {
        self.upsert_entry(
            path,
            SessionEntry {
                uid,
                active,
                unlocked,
                kind: SessionKind::Unknown,
                display: None,
                remote: false,
                leader: None,
            },
        );
    }

    /// Records (or refreshes) one complete session entry.
    pub fn upsert_entry(&self, path: &str, entry: SessionEntry) {
        wguard(&self.sessions).insert(path.to_string(), entry);
    }

    /// The session logind reports for `uid`, preferring an active+unlocked one.
    /// Deterministic: ties are broken by session object path, since the
    /// registry is a map. `None` when the uid has no tracked session.
    pub fn session_for_uid(&self, uid: u32) -> Option<SessionEntry> {
        fn rank(entry: &SessionEntry) -> u8 {
            if entry.active && entry.unlocked {
                0
            } else if entry.active {
                1
            } else {
                2
            }
        }
        let sessions = rguard(&self.sessions);
        let mut best: Option<(&str, &SessionEntry)> = None;
        for (path, entry) in sessions.iter().filter(|(_, entry)| entry.uid == uid) {
            let better = match best {
                None => true,
                Some((best_path, best_entry)) => {
                    (rank(entry), path.as_str()) < (rank(best_entry), best_path)
                }
            };
            if better {
                best = Some((path.as_str(), entry));
            }
        }
        best.map(|(_, entry)| entry.clone())
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

/// logind `Type` → [`SessionKind`]; a missing property is `Unknown`.
async fn read_kind(proxy: &Proxy<'_>) -> SessionKind {
    match proxy.get_property::<String>("Type").await {
        Ok(raw) => SessionKind::parse(&raw),
        Err(err) => {
            tracing::debug!("logind: session Type read failed: {err}");
            SessionKind::Unknown
        }
    }
}

/// logind `Display` (`:0`, …); empty means "no display" → `None`.
async fn read_display(proxy: &Proxy<'_>) -> Option<String> {
    proxy
        .get_property::<String>("Display")
        .await
        .ok()
        .filter(|display| !display.is_empty())
}

/// logind `Remote`; a missing property is treated as local (`false`).
async fn read_remote(proxy: &Proxy<'_>) -> bool {
    proxy.get_property::<bool>("Remote").await.unwrap_or(false)
}

/// logind `Leader` — the session leader's PID. Absent on very old logind (and
/// `0` when the leader has exited); both mean "no PID to inspect", not an
/// error worth logging.
async fn read_leader(proxy: &Proxy<'_>) -> Option<u32> {
    match proxy.get_property::<u32>("Leader").await {
        Ok(pid) if pid > 0 => Some(pid),
        _ => None,
    }
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
    let mut unlocked = !proxy
        .get_property::<bool>("LockedHint")
        .await
        .unwrap_or(true);
    let mut kind = read_kind(&proxy).await;
    let mut session_display = read_display(&proxy).await;
    let mut remote = read_remote(&proxy).await;
    let mut leader = read_leader(&proxy).await;
    registry.upsert_entry(
        &path,
        SessionEntry {
            uid,
            active,
            unlocked,
            kind,
            display: session_display.clone(),
            remote,
            leader,
        },
    );
    update_active_hint(&registry, &state);
    tracing::debug!(
        "logind: watching session {path} (uid {uid}, active {active}, unlocked {unlocked}, \
         type {kind:?}, session_display {session_display:?}, remote {remote}, leader {leader:?})"
    );

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
                        // `Type`/`Display`/`Remote` rarely change mid-session,
                        // but re-read them on the same cadence so a session
                        // that turns graphical (or remote) is picked up.
                        kind = read_kind(&proxy).await;
                        session_display = read_display(&proxy).await;
                        remote = read_remote(&proxy).await;
                        leader = read_leader(&proxy).await;
                        registry.upsert_entry(
                            &path,
                            SessionEntry {
                                uid,
                                active,
                                unlocked,
                                kind,
                                display: session_display.clone(),
                                remote,
                                leader,
                            },
                        );
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
        assert_eq!(
            registry.gate(1000),
            None,
            "any active+unlocked session wins"
        );

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
        let path: OwnedObjectPath = "/org/freedesktop/login1/session/c2"
            .try_into()
            .expect("path");
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

    fn entry(uid: u32, active: bool, unlocked: bool, kind: SessionKind) -> SessionEntry {
        SessionEntry {
            uid,
            active,
            unlocked,
            kind,
            display: None,
            remote: false,
            leader: None,
        }
    }

    #[test]
    fn session_kind_parsing() {
        assert_eq!(SessionKind::parse("x11"), SessionKind::X11);
        assert_eq!(SessionKind::parse("wayland"), SessionKind::Wayland);
        assert_eq!(SessionKind::parse("tty"), SessionKind::Tty);
        assert_eq!(SessionKind::parse("mir"), SessionKind::Unknown);
        assert_eq!(SessionKind::parse("unspecified"), SessionKind::Unknown);
        assert_eq!(SessionKind::parse(""), SessionKind::Unknown);
        assert_eq!(
            SessionKind::parse("X11"),
            SessionKind::Unknown,
            "logind reports lowercase; anything else is Unknown"
        );
        assert_eq!(SessionKind::X11.as_session_type(), Some("x11"));
        assert_eq!(SessionKind::Wayland.as_session_type(), Some("wayland"));
        assert_eq!(SessionKind::Tty.as_session_type(), None);
        assert_eq!(SessionKind::Unknown.as_session_type(), None);
    }

    #[test]
    fn session_env_derivation() {
        // A uid that has no `/run/user` entry and no `/etc/passwd` home.
        let uid = 59_999;
        let home = std::env::temp_dir().join(format!("lustless-sessionenv-{}", std::process::id()));
        let mut session = entry(uid, true, true, SessionKind::X11);
        session.display = Some(":0".to_string());

        let env = SessionEnv::derive(uid, &session, Some(&home));
        assert_eq!(env.uid, uid);
        assert_eq!(env.runtime_dir, PathBuf::from("/run/user/59999"));
        assert_eq!(env.bus_address, "unix:path=/run/user/59999/bus");
        assert_eq!(env.display.as_deref(), Some(":0"));
        assert_eq!(env.kind, SessionKind::X11);
        assert_eq!(
            env.xauthority, None,
            "no candidate exists for this fake uid"
        );
    }

    #[test]
    fn parse_environ_separates_entries_on_nul() {
        let blob = b"PATH=/usr/bin:/bin\0DISPLAY=:1\0XAUTHORITY=/run/user/1000/xauth\0";
        assert_eq!(parse_environ(blob, "DISPLAY").as_deref(), Some(":1"));
        assert_eq!(
            parse_environ(blob, "XAUTHORITY").as_deref(),
            Some("/run/user/1000/xauth")
        );
        assert_eq!(
            parse_environ(blob, "PATH").as_deref(),
            Some("/usr/bin:/bin")
        );
        // A trailing NUL is the normal shape and must not create an entry.
        assert_eq!(
            parse_environ(b"DISPLAY=:2\0", "DISPLAY").as_deref(),
            Some(":2")
        );
    }

    #[test]
    fn parse_environ_missing_key_is_none() {
        let blob = b"PATH=/usr/bin\0DISPLAY=:1\0";
        assert_eq!(parse_environ(blob, "XAUTHORITY"), None);
        assert_eq!(parse_environ(blob, "DISPLAYS"), None, "keys match exactly");
        assert_eq!(parse_environ(b"", "DISPLAY"), None);
        assert_eq!(parse_environ(b"\0\0", "DISPLAY"), None, "no `=` anywhere");
    }

    #[test]
    fn parse_environ_empty_value_is_present_but_empty() {
        // The parser reports an empty value; `environ_value` treats it as
        // absent so recovery still runs.
        let blob = b"DISPLAY=\0DISPLAYED=1\0";
        assert_eq!(parse_environ(blob, "DISPLAY").as_deref(), Some(""));
        assert_eq!(environ_value(blob, "DISPLAY"), None);
    }

    #[test]
    fn parse_environ_value_may_contain_equals() {
        // Only the first `=` separates name from value.
        let blob = b"QT_PLUGIN_PATH=/a=b:/c=d\0";
        assert_eq!(
            parse_environ(blob, "QT_PLUGIN_PATH").as_deref(),
            Some("/a=b:/c=d")
        );
    }

    #[test]
    fn parse_environ_non_utf8_never_panics() {
        // A value with an invalid UTF-8 byte: the matching key must return
        // `None` rather than panic or lossily decode.
        let blob = b"DISPLAY=\xff\xfe\0PATH=/bin\0";
        assert_eq!(parse_environ(blob, "DISPLAY"), None);
        // A non-UTF-8 entry we do not ask for must not break later lookups.
        assert_eq!(parse_environ(blob, "PATH").as_deref(), Some("/bin"));
        // A non-UTF-8 *name* is skipped without panicking.
        let blob = b"\xff\xfe=x\0DISPLAY=:3\0";
        assert_eq!(parse_environ(blob, "DISPLAY").as_deref(), Some(":3"));
    }

    #[test]
    fn resolve_recovers_display_from_leader_environ() {
        // The live defect: logind's `Display` is empty, so the only source of
        // the session's real display is the leader's `/proc/<pid>/environ`.
        // The selection is exercised through the pure parser with the environ
        // bytes injected — no `/proc`, no bus, no root.
        let leader_environ = b"PATH=/usr/bin\0DISPLAY=:1\0XAUTHORITY=/run/user/1000/xauth\0";
        assert_eq!(
            select_display(SessionKind::X11, None, Some(leader_environ)).as_deref(),
            Some(":1"),
            "empty logind Display must fall back to the leader's DISPLAY"
        );
        // logind's value still wins when it is present.
        assert_eq!(
            select_display(SessionKind::X11, Some(":0".into()), Some(leader_environ)).as_deref(),
            Some(":0")
        );
        // An empty DISPLAY in the environment is ignored, like a missing one.
        assert_eq!(
            select_display(SessionKind::X11, None, Some(b"DISPLAY=\0")).as_deref(),
            Some(":0"),
            "empty DISPLAY falls through to the X11 guess"
        );
        // Wayland never guesses a DISPLAY.
        assert_eq!(select_display(SessionKind::Wayland, None, None), None);
        assert_eq!(select_display(SessionKind::Tty, None, None), None);
    }

    #[test]
    fn resolve_guesses_x11_display_when_nothing_is_known() {
        // `SessionEnv::resolve` with no logind Display and no leader (so no
        // `/proc` read at all) still yields a usable display for an X11
        // session: a guess that the backend can refute beats the guaranteed
        // `$DISPLAY variable not set` failure.
        let uid = 59_999;
        let env = SessionEnv::resolve(uid, &entry(uid, true, true, SessionKind::X11));
        assert_eq!(env.display.as_deref(), Some(":0"));
        // A Wayland session gets no guess (it needs the runtime dir + bus).
        let env = SessionEnv::resolve(uid, &entry(uid, true, true, SessionKind::Wayland));
        assert_eq!(env.display, None);
    }

    #[test]
    fn xauthority_environ_wins_over_the_file_probe() {
        let probed = PathBuf::from("/run/user/1000/gdm/Xauthority");
        let environ = b"XAUTHORITY=/home/alice/.Xauthority\0";
        assert_eq!(
            select_xauthority(Some(environ), Some(probed.clone())),
            Some(PathBuf::from("/home/alice/.Xauthority")),
            "the session's own XAUTHORITY is authoritative"
        );
        // No environment value → the probe result stands.
        assert_eq!(
            select_xauthority(Some(b"DISPLAY=:0\0"), Some(probed.clone())),
            Some(probed.clone())
        );
        assert_eq!(select_xauthority(None, Some(probed.clone())), Some(probed));
        assert_eq!(select_xauthority(None, None), None);
    }

    #[test]
    fn xauthority_candidates_are_ordered() {
        let home = PathBuf::from("/home/alice");
        assert_eq!(
            xauthority_candidates(1000, Some(&home)),
            vec![
                PathBuf::from("/run/user/1000/gdm/Xauthority"),
                PathBuf::from("/run/user/1000/Xauthority"),
                PathBuf::from("/home/alice/.Xauthority"),
            ]
        );
        // Without a home the home candidate is omitted.
        assert_eq!(
            xauthority_candidates(1000, None),
            vec![
                PathBuf::from("/run/user/1000/gdm/Xauthority"),
                PathBuf::from("/run/user/1000/Xauthority"),
            ]
        );
    }

    #[test]
    fn xauthority_probe_picks_first_existing_candidate() {
        let dir = std::env::temp_dir().join(format!("lustless-xauth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let missing = dir.join("gdm/Xauthority"); // first candidate, absent
        let existing = dir.join("Xauthority"); // second candidate, present
        std::fs::write(&existing, b"cookie").expect("write xauthority");
        let candidates = vec![missing, existing.clone(), dir.join("home/.Xauthority")];

        assert_eq!(
            probe_xauthority(&candidates),
            Some(existing),
            "the missing first candidate is skipped"
        );
        assert_eq!(
            probe_xauthority(&[dir.join("nope/Xauthority")]),
            None,
            "nonexistent candidates are never returned"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tty_and_remote_sessions_are_not_capturable() {
        let x11 = entry(1000, true, true, SessionKind::X11);
        assert!(x11.capturable());
        assert_eq!(x11.skip_reason(), None);

        assert!(entry(1000, true, true, SessionKind::Wayland).capturable());

        let tty = entry(1000, true, true, SessionKind::Tty);
        assert!(!tty.capturable());
        assert_eq!(tty.skip_reason(), Some("text session"));

        // A remote session is never captured, even when graphical.
        let mut remote = entry(1000, true, true, SessionKind::Wayland);
        remote.remote = true;
        assert!(!remote.capturable());
        assert_eq!(remote.skip_reason(), Some("remote session"));

        // Unknown falls through to the backend's own fallback.
        assert!(entry(1000, true, true, SessionKind::Unknown).capturable());
    }

    #[test]
    fn session_for_uid_prefers_active_unlocked() {
        let registry = SessionRegistry::new();
        registry.upsert_entry("s2", entry(1000, false, true, SessionKind::Tty));
        let mut wayland = entry(1000, true, true, SessionKind::Wayland);
        wayland.display = Some("wayland-0".to_string());
        registry.upsert_entry("s1", wayland);

        let picked = registry.session_for_uid(1000).expect("session");
        assert_eq!(picked.kind, SessionKind::Wayland);
        assert_eq!(picked.display.as_deref(), Some("wayland-0"));
        assert_eq!(registry.session_for_uid(4242), None);
    }
}
