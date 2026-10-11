//! Shared daemon state — CONTRACTS §5 (IPC surface), §6 (stores), §9 (policy
//! snapshot), §9.1 (system config), §10/§12 (sign-in + update `Control`
//! semantics).
//!
//! [`DaemonState`] owns every piece of state the daemon shares across its
//! tasks:
//!
//! * the §6.1 outbox behind `Arc<Mutex<`[`Outbox`]`>>` (pinned API of
//!   `lustless-net`),
//! * per-uid §6.2 [`SettingsDb`] handles (lazily opened at `<state_dir>/<uid>/…`),
//! * the §10 [`ClockAnchor`] behind `Arc<RwLock<…>>`,
//! * the §9 sign-in state machine ([`crate::policy::PolicyMachine`]) and the
//!   flags mirrored from `user_info`,
//! * the per-connection NOTIFICATION queues drained by IPC `POLL` (§5,
//!   delivery with the CE `2×6×100 ms` bounded-retry budget implemented in
//!   `ipc.rs`),
//! * the §8 `FilterState`/health handles handed over by `dns_glue.rs`.
//!
//! It implements all three `lustless-net` traits — [`PolicyProvider`],
//! [`Notifier`] and [`Control`] — so `NetServices` is driven from the one
//! authoritative state object (CONTRACTS §3).
//!
//! Sign-in (§5 `0x65`, evidence `re/findings/15-ui/signin-and-settings.md` §3):
//! with `upload.base_url` set the daemon authenticates against the
//! deployment's auth endpoint and stores only `device_token`/`refresh_token`
//! in `api_credentials` (§6.2 — a password is never stored, §10). With
//! `upload.base_url` empty the daemon runs in the documented **offline mode**:
//! a local session only — `PolicySnapshot.username` is set, no credentials are
//! persisted, and every failure text is CE's `translateLoginFailure`
//! vocabulary from `signin-and-settings.md` §3 (see the `ERR_*` constants).

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::watch;

use lustless_core::clock::{local_timezone_offset, ClockAnchor};
use lustless_core::config::LustlessConfig;
use lustless_core::db::{CircumventionRow, LoginRow, Outbox, SwitchUserRow};
use lustless_core::ids;
use lustless_core::metrics::{
    AggTag, Aggregation, BucketTag, MetricField, MetricName, MetricSink, OPERATION_AGGREGATE,
};
use lustless_core::policy::{CapturePolicy, FilterPolicy, PolicySnapshot, UserState};
use lustless_core::settings::{
    ApiCredentials, SettingsDb, UserDnsFilter, Verdict, DEFAULT_FILTER_LEVEL,
};
use lustless_core::wire::ROOT_UID;
use lustless_core::{CoreError, LUSTLESS_VERSION};
use lustless_net::{Control, Notifier, PolicyProvider};

use crate::classifier::{txn_key, CrashStore};
use crate::policy::{fresh_user_info, PolicyState, UserFlags, FILTER_LEVELS};

/// `translateLoginFailure` text for bad credentials
/// (`re/findings/15-ui/signin-and-settings.md` §3: `0x1408dc900`).
pub const ERR_INVALID_CREDENTIALS: &str = "Invalid username or password. Please try again.";
/// §3: "This user has no Victory Shield services." (`0x1408dc930`).
pub const ERR_NO_SERVICES: &str = "This user has no Victory Shield services.";
/// §3: "This user is disabled." (`0x1408dc9a0`).
pub const ERR_ACCOUNT_DISABLED: &str = "This user is disabled.";
/// §3: "Sign in failed to connect to our servers." (`0x1408dca00`).
pub const ERR_NO_CONNECTION: &str = "Sign in failed to connect to our servers.";

/// The dotted keys of §9.1 accepted by IPC `0x52 SET_CLIENT_CONFIG` (root
/// only, §5). Every key MUST match its effect (§9.1).
pub const CLIENT_CONFIG_KEYS: &[&str] = &[
    "daemon.socket_path",
    "daemon.dashboard_enabled",
    "daemon.dashboard_port",
    "daemon.state_dir",
    "dns.enabled",
    "dns.listen",
    "dns.doh_url",
    "dns.user_resolvers",
    "dns.block_page",
    "dns.block_page_host",
    "dns.fail_closed_when_signed_out",
    "dns.pool_size",
    "capture.enabled",
    "capture.backend",
    "capture.interval_sec",
    "capture.variance_pct",
    "capture.spool_dir",
    "classifier.enabled",
    "classifier.bin",
    "classifier.model_dir",
    "upload.base_url",
    "upload.batch_size",
    "upload.heartbeat_sec",
    "upload.retry_sec",
    "upload.circumvention_records",
    "upload.logs_store",
    "update.feed_url",
    "update.pubkey",
    "update.check_sec",
    "update.disable_silent_upgrade",
    "update.host_allowlist",
];

/// Cap of the per-connection NOTIFICATION queue (§5 keeps CE's bounded queue
/// semantics: `ce_service_event_message_queue` was 10 slots; ours drops the
/// oldest message on overflow).
const MAX_QUEUED_NOTIFICATIONS: usize = 32;

/// Poison-tolerant `Mutex` guard (the workspace avoids `unwrap` boilerplate).
pub(crate) fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Poison-tolerant read guard.
pub(crate) fn rguard<T>(m: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|e| e.into_inner())
}

/// Poison-tolerant write guard.
pub(crate) fn wguard<T>(m: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|e| e.into_inner())
}

fn db_err(e: CoreError) -> String {
    e.to_string()
}

/// `<state_dir>/outbox.db` (§4/§6.1).
pub fn outbox_path(cfg: &LustlessConfig) -> PathBuf {
    Path::new(&cfg.daemon.state_dir).join("outbox.db")
}

/// One queued daemon→client `NOTIFICATION` frame payload (§5 code `0x02`:
/// `{"level","message","progress"?,…}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyMsg {
    /// Notification level (`"info"` / `"warning"` / `"error"`).
    pub level: String,
    /// Human-readable message (CE vocabulary, §5).
    pub message: String,
    /// Optional 0–100 progress value.
    pub progress: Option<u8>,
}

impl NotifyMsg {
    /// The wire payload of a `0x02 NOTIFICATION` frame (§5).
    pub fn to_payload(&self) -> Value {
        let mut payload = json!({ "level": self.level, "message": self.message });
        if let Some(progress) = self.progress {
            payload["progress"] = json!(progress);
        }
        payload
    }
}

/// Cached §6.2 domain-override lists consulted by the §8 forwarder on every
/// query (`lustless_dns::server::PolicyProvider`); refreshed on sign-in/out
/// and on IPC `0x64`.
#[derive(Debug, Clone, Default)]
pub struct DomainLists {
    /// Username whose custom overrides are cached.
    pub username: String,
    /// `custom_domain_overrides` for `username`.
    pub custom: HashMap<String, lustless_dns::OverrideVerdict>,
    /// `global_domain_overrides` (all users).
    pub global: HashMap<String, lustless_dns::OverrideVerdict>,
    /// Safe-search domain list (§8 code 8). The deployment has no
    /// server-delivered list yet (§9.1 carries no key for it), so this starts
    /// empty — `SafeSearchEnforced` therefore never fires until a sync path
    /// populates it.
    pub safe_search: HashSetLite,
    /// Always-allowable predicate list (§8 code 3), same provenance note as
    /// [`Self::safe_search`].
    pub always_allowable: HashSetLite,
}

/// Minimal ordered set of domains for the §8 list predicates.
pub type HashSetLite = std::collections::HashSet<String>;

/// A published §6.3 screenstate transaction the daemon is tracking. The
/// capture loop registers it on finalize; a classifier `result` for the same
/// batch moves it to the consumed queue, so the watcher no longer treats its
/// later deletion as tamper (`capture_loop.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedTxn {
    /// `<spool>/<uid>/pdl/<folder>` path.
    pub folder: PathBuf,
    /// Folder name (the §6.3 transaction timestamp).
    pub folder_name: String,
    /// `manifest.datetime_created` of the transaction.
    pub manifest_ts: String,
}

/// The single shared daemon state object (CONTRACTS §3: `lustlessd` drives
/// every subsystem from it).
pub struct DaemonState {
    /// Startup snapshot handed to `NetServices::new` (pinned API).
    cfg_static: Arc<LustlessConfig>,
    /// Live mirror updated by IPC `0x52 SET_CLIENT_CONFIG` (§9.1); the daemon
    /// loops re-read it so accepted keys take effect without a restart.
    cfg_live: RwLock<LustlessConfig>,
    /// Path of the system config file (§9.1 `/etc/lustless/lustless.toml`).
    config_path: PathBuf,
    /// §6.1 outbox (pinned `Arc<Mutex<Outbox>>`).
    pub outbox: Arc<Mutex<Outbox>>,
    /// Path of `outbox.db` (§4).
    outbox_path: PathBuf,
    /// §10 clock anchor (pinned `Arc<RwLock<ClockAnchor>>`).
    pub clock: Arc<RwLock<ClockAnchor>>,
    /// Per-uid §6.2 settings DBs, opened lazily.
    settings: Mutex<HashMap<u32, Arc<Mutex<SettingsDb>>>>,
    /// §9 policy state.
    policy: Mutex<PolicyState>,
    /// Per-connection NOTIFICATION queues (§5 `0x02`/`0x55`).
    notifications: Mutex<HashMap<u64, Arc<Mutex<VecDeque<NotifyMsg>>>>>,
    /// Connection id sequence.
    conn_seq: AtomicU64,
    /// Best-effort uid of the currently active logind session — the sign-in
    /// uid fallback when a `Control::sign_in` call (dashboard) carries no
    /// peer credential.
    active_session_uid: AtomicU32,
    /// Cached §8 domain lists.
    domain_lists: RwLock<DomainLists>,
    /// §8 `FilterState` handle attached by `dns_glue::spawn`.
    dns_filter: Mutex<Option<Arc<lustless_dns::EngineMutex<lustless_dns::FilterState>>>>,
    /// §8 health machine handle attached by `dns_glue::spawn`.
    dns_health: Mutex<Option<Arc<lustless_dns::EngineMutex<lustless_dns::DnsHealth>>>>,
    /// §5 `0x43` collection-in-progress flag.
    diagnostics_in_progress: AtomicBool,
    /// Classifier alive flag (§7 gates; written by the supervisor).
    classifier_alive: AtomicBool,
    /// Handle on the running `NetServices` (Clone keeps a handle beside
    /// `run(self)`) for `flush_now`/`issue_dashboard_token` (pinned API).
    net: OnceLock<lustless_net::NetServices>,
    /// Shutdown broadcast (SIGTERM / IPC `0x51 QUIT`).
    shutdown: watch::Sender<bool>,
    /// Weak self for spawning `&'static` work from sync `Control` methods.
    self_weak: OnceLock<Weak<DaemonState>>,
    /// uid hint set by IPC `0x65` right before `Control::sign_in` (the pinned
    /// trait carries no uid; the hint binds the session to the caller).
    sign_in_uid: Mutex<Option<u32>>,
    /// §11 classifier crash budget (per uid, persisted in `install_metadata`).
    pub crash: CrashStore,
    /// §6.3 transactions published and not yet scored.
    created: Mutex<Vec<CreatedTxn>>,
    /// Transactions whose batch was scored — the capture loop marks them
    /// consumed on its next tick (dropping their tamper watch).
    consumed: Mutex<Vec<PathBuf>>,
}

impl DaemonState {
    /// Builds the shared state. `shutdown` is the broadcast every long-running
    /// task selects on.
    pub fn new(
        cfg: Arc<LustlessConfig>,
        config_path: PathBuf,
        outbox: Arc<Mutex<Outbox>>,
        clock: Arc<RwLock<ClockAnchor>>,
        shutdown: watch::Sender<bool>,
    ) -> Self {
        let outbox_path = outbox_path(&cfg);
        let crash = CrashStore::new(Arc::clone(&outbox));
        DaemonState {
            cfg_static: cfg.clone(),
            cfg_live: RwLock::new((*cfg).clone()),
            config_path,
            outbox,
            outbox_path,
            clock,
            settings: Mutex::new(HashMap::new()),
            policy: Mutex::new(PolicyState::default()),
            notifications: Mutex::new(HashMap::new()),
            conn_seq: AtomicU64::new(1),
            active_session_uid: AtomicU32::new(u32::MAX),
            domain_lists: RwLock::new(DomainLists::default()),
            dns_filter: Mutex::new(None),
            dns_health: Mutex::new(None),
            diagnostics_in_progress: AtomicBool::new(false),
            classifier_alive: AtomicBool::new(false),
            net: OnceLock::new(),
            shutdown,
            self_weak: OnceLock::new(),
            sign_in_uid: Mutex::new(None),
            crash,
            created: Mutex::new(Vec::new()),
            consumed: Mutex::new(Vec::new()),
        }
    }

    /// Binds the weak self-handle (called once from `main` and from tests);
    /// required by [`Control::collect_debug`], which spawns the §5 `0x43`
    /// collection from a plain `&self`.
    pub fn bind_weak(self: &Arc<Self>) {
        let _ = self.self_weak.set(Arc::downgrade(self));
    }

    /// The live config (§9.1), reflecting IPC `0x52` writes.
    pub fn config(&self) -> LustlessConfig {
        rguard(&self.cfg_live).clone()
    }

    /// Path of the system config file (§9.1).
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Path of the outbox DB (§4).
    pub fn outbox_path(&self) -> &Path {
        &self.outbox_path
    }

    /// Registers a new IPC connection and returns its queue handle (§5
    /// `0x02`/`0x55`).
    pub fn register_connection(&self) -> (u64, Arc<Mutex<VecDeque<NotifyMsg>>>) {
        let id = self.conn_seq.fetch_add(1, Ordering::Relaxed);
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        guard(&self.notifications).insert(id, Arc::clone(&queue));
        (id, queue)
    }

    /// Drops a disconnected connection's queue.
    pub fn unregister_connection(&self, id: u64) {
        guard(&self.notifications).remove(&id);
    }

    /// Current policy state snapshot (cheap clone of the guarded fields).
    pub fn policy_state(&self) -> PolicyState {
        guard(&self.policy).clone()
    }

    /// uid of the signed-in session, if any.
    pub fn session_uid(&self) -> Option<u32> {
        guard(&self.policy).session_uid
    }

    /// `(uid, username)` of the signed-in session.
    pub fn session(&self) -> Result<(u32, String), String> {
        let pol = guard(&self.policy);
        if pol.machine.state() != UserState::LoggedIn {
            return Err("no user is currently signed in".to_string());
        }
        let uid = pol
            .session_uid
            .ok_or_else(|| "no user is currently signed in".to_string())?;
        Ok((uid, pol.machine.username().to_string()))
    }

    /// Like [`Self::session`], additionally requiring `peer_uid` to BE that
    /// session's uid (or root, §5 self-scope rule: root owns the machine).
    pub fn session_for(&self, peer_uid: u32) -> Result<(u32, String), String> {
        let (uid, username) = self.session()?;
        if peer_uid != ROOT_UID && peer_uid != uid {
            return Err("the signed-in session belongs to another user".to_string());
        }
        Ok((uid, username))
    }

    /// Username of the signed-in session; empty when logged out.
    pub fn username(&self) -> String {
        guard(&self.policy).machine.username().to_string()
    }

    /// Records the active logind session uid (driven by `sessions.rs`); the
    /// value is sticky so a locked screen does not lose the sign-in target.
    pub fn set_active_session_uid(&self, uid: u32) {
        self.active_session_uid.store(uid, Ordering::Relaxed);
    }

    /// Last known active logind session uid.
    pub fn active_session_uid(&self) -> Option<u32> {
        match self.active_session_uid.load(Ordering::Relaxed) {
            u32::MAX => None,
            uid => Some(uid),
        }
    }

    /// Stores the IPC-provided uid hint consumed by [`Control::sign_in`].
    pub fn set_sign_in_uid_hint(&self, uid: u32) {
        *guard(&self.sign_in_uid) = Some(uid);
    }

    fn signin_uid(&self) -> u32 {
        if let Some(uid) = *guard(&self.sign_in_uid) {
            return uid;
        }
        self.active_session_uid().unwrap_or(ROOT_UID)
    }

    /// Opens (and, on first use, creates with §4 modes) the uid's §6.2
    /// settings DB: `<state_dir>/<uid>/settings.db` + `settings.key`.
    pub fn settings_for(&self, uid: u32) -> Result<Arc<Mutex<SettingsDb>>, String> {
        if let Some(existing) = guard(&self.settings).get(&uid) {
            return Ok(Arc::clone(existing));
        }
        let dir = Path::new(&self.cfg_static.daemon.state_dir).join(uid.to_string());
        std::fs::create_dir_all(&dir).map_err(|e| format!("settings dir {}: {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let db_path = dir.join("settings.db");
        let key_path = dir.join("settings.key");
        let db = SettingsDb::open(&db_path, &key_path).map_err(|e| e.to_string())?;
        let handle = Arc::new(Mutex::new(db));
        guard(&self.settings).insert(uid, Arc::clone(&handle));
        Ok(handle)
    }

    /// Per-install device id (`install_metadata`, §6.1), generated on first
    /// use via [`ids::new_device_id`].
    pub fn device_id(&self) -> String {
        let mut outbox = guard(&self.outbox);
        if let Ok(Some(existing)) = outbox.install_metadata("device_id") {
            if !existing.is_empty() {
                return existing;
            }
        }
        let generated = ids::new_device_id();
        if let Err(e) = outbox.set_install_metadata("device_id", &generated) {
            tracing::error!("device_id persist failed: {e}");
        }
        generated
    }

    /// Writes a §6.1 `circumventions` row (born `status='queued'`), used by
    /// the capture tamper signal (§6.3), restricted windows (§7) and flagged
    /// classifier windows (§7).
    pub fn record_circumvention(
        &self,
        username: &str,
        interruption_type: &str,
        app_name: &str,
        app_window_title: Option<&str>,
    ) -> Result<i64, CoreError> {
        let (timestamp, timezone_offset) = self.event_stamp();
        let row = CircumventionRow {
            username: username.to_string(),
            interruption_type: interruption_type.to_string(),
            app_name: app_name.to_string(),
            app_window_title: app_window_title.map(String::from),
            device_id: self.device_id(),
            timestamp,
            timezone_offset,
        };
        guard(&self.outbox).insert_circumvention(&row)
    }

    /// ISO-8601 UTC stamp + separate local offset for one event row (§6.1).
    pub fn event_stamp(&self) -> (String, String) {
        let stamp = rguard(&self.clock).now_iso8601();
        (stamp, local_timezone_offset())
    }

    /// Records one §14 metric (`client_startup`, `client_screenshot`, …) into
    /// the §6.1 `metrics` table with the daemon's standard bucket tags.
    pub fn record_metric(
        &self,
        username: &str,
        metric: MetricName,
        fields: &[MetricField],
    ) -> Result<(), CoreError> {
        self.record_metric_tagged(username, metric, &[], fields)
    }

    /// Like [`Self::record_metric`] plus extra CE tags (§14 taxonomy — e.g.
    /// the §8 `cleanbrowsing_datacenter`/`doh_url`/`doh_request_reason`
    /// dimensions of the health metrics).
    pub fn record_metric_tagged(
        &self,
        username: &str,
        metric: MetricName,
        extra_tags: &[AggTag],
        fields: &[MetricField],
    ) -> Result<(), CoreError> {
        let bucket = [
            BucketTag {
                indexed: true,
                name: "client_component".to_string(),
                value: "daemon".to_string(),
            },
            BucketTag {
                indexed: true,
                name: "client_version".to_string(),
                value: LUSTLESS_VERSION.to_string(),
            },
        ];
        let mut tags = vec![
            AggTag {
                aggregation: Aggregation::Indexed,
                name: "client_component".to_string(),
                value: "daemon".to_string(),
            },
            AggTag {
                aggregation: Aggregation::Cardinal,
                name: "client_version".to_string(),
                value: LUSTLESS_VERSION.to_string(),
            },
        ];
        tags.extend_from_slice(extra_tags);
        let mut outbox = guard(&self.outbox);
        MetricSink::new(&mut outbox).record(username, metric, &bucket, &tags, fields)
    }

    /// A metric field with CE's observed `operation: 4` counter shape
    /// (`local-db.md` sample rows: `{"name":"startup_count","operation":4,…}`).
    pub fn counter_field(name: &str, value: u64) -> MetricField {
        MetricField {
            name: name.to_string(),
            operation: OPERATION_AGGREGATE,
            value: json!(value),
        }
    }

    /// Queues a NOTIFICATION for every connected IPC client (§5 `0x02`;
    /// fan-out keeps the per-connection queues independent).
    pub fn notify(&self, level: &str, message: &str, progress: Option<u8>) {
        let msg = NotifyMsg {
            level: level.to_string(),
            message: message.to_string(),
            progress,
        };
        let mut conns = guard(&self.notifications);
        if conns.is_empty() {
            tracing::debug!(target: "notification", "{message} (no connected clients)");
            return;
        }
        for queue in conns.values() {
            let mut q = guard(queue);
            if q.len() >= MAX_QUEUED_NOTIFICATIONS {
                q.pop_front();
                tracing::warn!("notification queue full; dropped the oldest message");
            }
            q.push_back(msg.clone());
        }
    }

    /// The §8 health string for §9 `filter.health` (`healthy` until the
    /// forwarder attaches).
    pub fn filter_health(&self) -> String {
        let handle = guard(&self.dns_filter);
        match handle.as_ref() {
            Some(filter_state) => filter_state.lock().health().as_str().to_string(),
            None => "healthy".to_string(),
        }
    }

    /// Attaches the §8 forwarder handles (`dns_glue::spawn`).
    pub fn attach_dns(
        &self,
        filter_state: Arc<lustless_dns::EngineMutex<lustless_dns::FilterState>>,
        health: Arc<lustless_dns::EngineMutex<lustless_dns::DnsHealth>>,
    ) {
        // A break-glass taken before the forwarder started must apply to it.
        let fail_open = guard(&self.policy).fail_open_override;
        if fail_open {
            filter_state
                .lock()
                .set_fail_closed_when_signed_out(false);
        }
        *guard(&self.dns_filter) = Some(filter_state);
        *guard(&self.dns_health) = Some(health);
    }

    /// Ref-counts the user in the §8 forwarder (sign-in/out, §8 lifecycle).
    pub fn sync_membership(&self, username: &str, want_filtering: bool) {
        let handle = guard(&self.dns_filter).clone();
        let Some(filter_state) = handle else {
            return;
        };
        let mut state = filter_state.lock();
        let active = if want_filtering {
            state.activate_user(username)
        } else {
            state.deactivate_user(username)
        };
        tracing::info!(
            "dns filter ref-count: {active} user(s) after {} for {username}",
            if want_filtering { "activation" } else { "deactivation" }
        );
    }

    /// Rebuilds the cached §8 domain lists from the §6.2 settings of the
    /// signed-in user.
    pub fn refresh_domain_lists(&self) {
        let next = match self.session() {
            Ok((uid, username)) => {
                let lists = self.settings_for(uid).and_then(|settings| {
                    let s = guard(&settings);
                    let customs = s.list_custom_overrides(&username).map_err(db_err)?;
                    let globals = s.list_global_overrides().map_err(db_err)?;
                    Ok::<DomainLists, String>(DomainLists {
                        username,
                        custom: customs
                            .into_iter()
                            .map(|o| (o.domain.to_ascii_lowercase(), override_verdict(o.verdict)))
                            .collect(),
                        global: globals
                            .into_iter()
                            .map(|o| (o.domain.to_ascii_lowercase(), override_verdict(o.verdict)))
                            .collect(),
                        safe_search: HashSetLite::new(),
                        always_allowable: HashSetLite::new(),
                    })
                });
                match lists {
                    Ok(lists) => lists,
                    Err(e) => {
                        tracing::warn!("domain override refresh failed: {e}");
                        return;
                    }
                }
            }
            Err(_) => DomainLists::default(),
        };
        *wguard(&self.domain_lists) = next;
    }

    /// Cached domain lists for the §8 `PolicyProvider`.
    pub fn domain_lists(&self) -> DomainLists {
        rguard(&self.domain_lists).clone()
    }

    /// Applies IPC `0x53 USER_SETTINGS_CHANGE` (§5): a non-empty set of
    /// `filter_level` plus the §9 boolean flags, validated before any write
    /// (all-or-nothing).
    pub fn apply_user_settings(&self, peer_uid: u32, fields: &Value) -> Result<(), String> {
        let obj = fields
            .as_object()
            .ok_or_else(|| "settings payload must be a JSON object".to_string())?;
        if obj.is_empty() {
            return Err("settings payload has no fields".to_string());
        }
        let (uid, username) = self.session_for(peer_uid)?;

        let mut bool_updates: Vec<(&str, bool)> = Vec::new();
        let mut new_level: Option<&str> = None;
        for (key, value) in obj {
            match key.as_str() {
                "filter_level" => {
                    let level = value
                        .as_str()
                        .ok_or_else(|| "filter_level must be a string".to_string())?;
                    if !FILTER_LEVELS.contains(&level) {
                        return Err(format!("invalid filter level: {level}"));
                    }
                    new_level = Some(level);
                }
                "has_accountability"
                | "has_filtering"
                | "has_screen_accountability"
                | "has_url_accountability"
                | "has_dns_filtering"
                | "has_url_filtering"
                | "can_override"
                | "is_active" => {
                    let flag = value
                        .as_bool()
                        .ok_or_else(|| format!("{key} must be a boolean"))?;
                    bool_updates.push((key.as_str(), flag));
                }
                other => return Err(format!("unknown settings field: {other}")),
            }
        }

        let settings = self.settings_for(uid)?;
        let (old_filtering, flags_after, level_after) = {
            let mut s = guard(&settings);
            let mut info = s
                .get_user_info(&username)
                .map_err(db_err)?
                .unwrap_or_else(|| fresh_user_info(&username));
            let mut filter = s
                .get_dns_filter(&username)
                .map_err(db_err)?
                .unwrap_or_else(|| UserDnsFilter::default_for(&username));
            let old_filtering = info.has_filtering;
            for (key, flag) in bool_updates {
                match key {
                    "has_accountability" => info.has_accountability = flag,
                    "has_filtering" => info.has_filtering = flag,
                    "has_screen_accountability" => info.has_screen_accountability = flag,
                    "has_url_accountability" => info.has_url_accountability = flag,
                    "has_dns_filtering" => info.has_dns_filtering = flag,
                    "has_url_filtering" => info.has_url_filtering = flag,
                    "can_override" => info.can_override = flag,
                    "is_active" => info.is_active = flag,
                    _ => unreachable!("validated above"),
                }
            }
            if let Some(level) = new_level {
                filter.level = level.to_string();
            }
            s.set_user_info(&info).map_err(db_err)?;
            s.set_dns_filter(&filter).map_err(db_err)?;
            (old_filtering, UserFlags::from(&info), filter.level)
        };

        {
            let mut pol = guard(&self.policy);
            pol.flags = flags_after.clone();
            pol.filter_level = level_after;
        }
        if flags_after.has_filtering != old_filtering {
            self.sync_membership(&username, flags_after.has_filtering);
        }
        tracing::info!("user settings changed for {username} (fields: {})", obj.len());
        Ok(())
    }

    /// IPC `0x63` core: stores the §6.2 `user_dns_filter.level` and mirrors it
    /// into §9.
    pub fn set_filter_level(&self, level: &str) -> Result<(), String> {
        if !FILTER_LEVELS.contains(&level) {
            return Err(format!("invalid filter level: {level}"));
        }
        let (uid, username) = self.session()?;
        let settings = self.settings_for(uid)?;
        {
            let mut s = guard(&settings);
            let mut filter = s
                .get_dns_filter(&username)
                .map_err(db_err)?
                .unwrap_or_else(|| UserDnsFilter::default_for(&username));
            filter.level = level.to_string();
            s.set_dns_filter(&filter).map_err(db_err)?;
        }
        guard(&self.policy).filter_level = level.to_string();
        tracing::info!("filter level for {username} set to {level}");
        Ok(())
    }

    /// IPC `0x64` core: stores a §6.2 tri-state domain override for the
    /// signed-in user and refreshes the §8 cache.
    pub fn set_override(&self, domain: &str, verdict: &str) -> Result<(), String> {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return Err("domain is required".to_string());
        }
        let verdict: Verdict = serde_json::from_value(Value::String(verdict.to_string()))
            .map_err(|_| format!("invalid verdict: {verdict} (expected allow|block|na)"))?;
        let (uid, username) = self.session()?;
        let settings = self.settings_for(uid)?;
        {
            let mut s = guard(&settings);
            s.set_custom_override(&username, &domain, verdict)
                .map_err(db_err)?;
        }
        self.refresh_domain_lists();
        tracing::info!("domain override for {username}: {domain} -> {}", verdict.as_str());
        Ok(())
    }

    /// IPC `0x68 BREAK_GLASS` (§5, root only; polkit + audit happen in
    /// `ipc.rs` before this call): sets the fail-open override flag. The
    /// snapshot reports it through `filter.fail_closed = false` alongside
    /// `filter.health` (`is_panicked` remains the §6.2 server flag and stays
    /// `false`). The forwarder's §8 `fail_closed_when_signed_out` is cleared so
    /// the override is real, not just reported.
    pub fn break_glass(&self, uid: u32, reason: &str) -> Result<(), String> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err("break-glass requires a reason".to_string());
        }
        // Journald audit line required by §5 (`break-glass uid=N reason=…`).
        tracing::info!("break-glass uid={uid} reason={reason}");
        guard(&self.policy).fail_open_override = true;
        if let Some(filter_state) = guard(&self.dns_filter).clone() {
            filter_state.lock().set_fail_closed_when_signed_out(false);
        }
        tracing::warn!("fail-open override active (filter fail-closed disabled)");
        Ok(())
    }

    /// Records the UI analysis counter bump from a classifier `result`
    /// (§7: real `analyzed_count`, not capture rows).
    pub fn bump_analyzed(&self, count: u64) {
        if count == 0 {
            return;
        }
        let stamp = rguard(&self.clock).now_iso8601();
        let mut pol = guard(&self.policy);
        pol.analyzed_count = pol.analyzed_count.saturating_add(count);
        pol.analyzed_updated_at = Some(stamp);
    }

    /// Records the §9 `capture.last_screenstate_at` stamp (§6.3).
    pub fn mark_screenstate(&self) {
        let stamp = rguard(&self.clock).now_iso8601();
        let mut pol = guard(&self.policy);
        pol.capture_active = true;
        pol.last_screenstate_at = Some(stamp);
    }

    /// Updates §9 `capture.active` (gates in `capture_loop.rs`).
    pub fn set_capture_active(&self, active: bool) {
        guard(&self.policy).capture_active = active;
    }

    /// Registers a finalized §6.3 transaction for tamper bookkeeping.
    pub fn remember_transaction(&self, txn: CreatedTxn) {
        guard(&self.created).push(txn);
    }

    /// A classifier `result` for `batch_ts` arrived: move the matching §6.3
    /// transaction to the consumed queue (its folder may now disappear
    /// without being tamper). Matching normalizes the timestamp form via
    /// [`txn_key`] (folder name or manifest `datetime_created`).
    pub fn note_result_batch(&self, batch_ts: &str) {
        let wanted = txn_key(batch_ts);
        let mut created = guard(&self.created);
        let Some(index) = created.iter().position(|txn| {
            txn_key(&txn.folder_name) == wanted || txn_key(&txn.manifest_ts) == wanted
        }) else {
            return;
        };
        let txn = created.remove(index);
        drop(created);
        guard(&self.consumed).push(txn.folder);
    }

    /// Drains the consumed transactions; the capture loop passes each to
    /// `SpoolWatcher::mark_consumed` (§6.3).
    pub fn drain_consumed_transactions(&self) -> Vec<PathBuf> {
        std::mem::take(&mut *guard(&self.consumed))
    }

    /// Whether the supervised classifier is alive (§7 capture gate).
    pub fn classifier_alive(&self) -> bool {
        self.classifier_alive.load(Ordering::Relaxed)
    }

    /// Written by the classifier supervisor on spawn/exit.
    pub fn set_classifier_alive(&self, alive: bool) {
        self.classifier_alive.store(alive, Ordering::Relaxed);
    }

    /// §5 `0x43` collection-in-progress flag (also the §14
    /// `collect_diagnostics_in_progress` companion).
    pub fn diagnostics_in_progress(&self) -> bool {
        self.diagnostics_in_progress.load(Ordering::Relaxed)
    }

    /// Atomically claims the §5 `0x43` slot: returns `true` when *this* caller
    /// started a collection (a racing or running collection yields `false`).
    pub(crate) fn begin_diagnostics(&self) -> bool {
        !self.diagnostics_in_progress.swap(true, Ordering::SeqCst)
    }

    /// Marks/reads the §5 `0x43` in-progress flag.
    pub fn set_diagnostics_in_progress(&self, running: bool) {
        self.diagnostics_in_progress.store(running, Ordering::Relaxed);
    }

    /// Installs the running `NetServices` handle (Clone keeps it usable beside
    /// `run(self)`; pinned API).
    pub fn set_net(&self, net: lustless_net::NetServices) {
        let _ = self.net.set(net);
    }

    /// Drains the outbox through `NetServices::flush_now` (pinned API).
    /// **Blocks up to `deadline`** — call from a blocking context.
    pub fn flush_outbox(&self, deadline: Duration) -> Result<usize, String> {
        self.net
            .get()
            .map(|net| net.flush_now(deadline))
            .ok_or_else(|| "network services unavailable".to_string())
    }

    /// `http://127.0.0.1:<port>/?t=<token>` (§13 dashboard token issued over
    /// IPC, uid-bound, TTL 10 min — pinned `issue_dashboard_token`).
    pub fn dashboard_url(&self, uid: u32) -> Option<String> {
        let port = rguard(&self.cfg_live).daemon.dashboard_port;
        self.net
            .get()
            .map(|net| format!("http://127.0.0.1:{port}/?t={}", net.issue_dashboard_token(uid)))
    }

    /// Requests daemon shutdown (IPC `0x51 QUIT` or SIGTERM path).
    pub fn request_shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    /// Resolves when shutdown is requested (SIGTERM / `QUIT`). The receiver
    /// is subscribed *before* the check so a racing request cannot be missed.
    pub async fn wait_shutdown(&self) {
        let mut rx = self.shutdown.subscribe();
        if *rx.borrow() {
            return;
        }
        let _ = rx.changed().await;
    }

    /// Daemon status object for IPC `0x61 STATUS_GET` (§5).
    pub fn status_json(&self) -> Value {
        let pol = guard(&self.policy);
        let cfg = rguard(&self.cfg_live);
        json!({
            "version": LUSTLESS_VERSION,
            "username": pol.machine.username(),
            "signed_in": pol.machine.state() == UserState::LoggedIn,
            "state": pol.machine.state(),
            "capture_active": pol.capture_active,
            "last_screenstate_at": pol.last_screenstate_at,
            "classifier_alive": self.classifier_alive(),
            "diagnostics_in_progress": self.diagnostics_in_progress(),
            "filter_level": pol.filter_level,
            "filter_health": self.filter_health(),
            "fail_closed": cfg.dns.fail_closed_when_signed_out && !pol.fail_open_override,
            "fail_open_override": pol.fail_open_override,
            "dashboard_enabled": cfg.daemon.dashboard_enabled,
            "analyzed_count": pol.analyzed_count,
            "analyzed_updated_at": pol.analyzed_updated_at,
            "outbox_path": self.outbox_path.display().to_string(),
        })
    }

    /// The §9 signed-in snapshot.
    fn signed_in_snapshot(&self, pol: &PolicyState, cfg: &LustlessConfig) -> PolicySnapshot {
        PolicySnapshot {
            username: pol.machine.username().to_string(),
            signed_in: true,
            state: pol.machine.state(),
            has_accountability: pol.flags.has_accountability,
            has_filtering: pol.flags.has_filtering,
            has_screen_accountability: pol.flags.has_screen_accountability,
            has_url_accountability: pol.flags.has_url_accountability,
            has_dns_filtering: pol.flags.has_dns_filtering,
            has_url_filtering: pol.flags.has_url_filtering,
            can_override: pol.flags.can_override,
            is_panicked: pol.flags.is_panicked,
            filter: FilterPolicy {
                level: pol.filter_level.clone(),
                fail_closed: cfg.dns.fail_closed_when_signed_out && !pol.fail_open_override,
                health: self.filter_health(),
            },
            capture: CapturePolicy {
                active: pol.capture_active,
                backend: cfg.capture.backend.clone(),
                last_screenstate_at: pol.last_screenstate_at.clone(),
            },
        }
    }

    /// The §9 snapshot a connection whose uid owns no session sees (§5:
    /// "user-scope connections see only their own uid's state").
    fn foreign_uid_snapshot(&self, cfg: &LustlessConfig) -> PolicySnapshot {
        PolicySnapshot {
            username: String::new(),
            signed_in: false,
            state: UserState::LoggedOut,
            has_accountability: false,
            has_filtering: false,
            has_screen_accountability: false,
            has_url_accountability: false,
            has_dns_filtering: false,
            has_url_filtering: false,
            can_override: false,
            is_panicked: false,
            filter: FilterPolicy {
                level: DEFAULT_FILTER_LEVEL.to_string(),
                fail_closed: cfg.dns.fail_closed_when_signed_out,
                health: self.filter_health(),
            },
            capture: CapturePolicy {
                active: false,
                backend: cfg.capture.backend.clone(),
                last_screenstate_at: None,
            },
        }
    }

    /// §9 snapshot as seen by the peer uid (self-scope rule of §5: a peer
    /// that is not root and does not own the signed-in session sees logged-out
    /// state).
    pub fn snapshot_for(&self, peer_uid: u32) -> PolicySnapshot {
        let cfg = rguard(&self.cfg_live).clone();
        let pol = guard(&self.policy).clone();
        let owns_session = pol.session_uid == Some(peer_uid) || peer_uid == ROOT_UID;
        if pol.machine.state() == UserState::LoggedIn && owns_session {
            self.signed_in_snapshot(&pol, &cfg)
        } else {
            self.foreign_uid_snapshot(&cfg)
        }
    }

    /// IPC `0x52 SET_CLIENT_CONFIG` (§5 root-only, §9.1): validates `key`
    /// against the §9.1 table, type-checks the whole document after the edit,
    /// persists atomically (0644) and updates the live mirror.
    pub fn set_client_config(&self, key: &str, value: &Value) -> Result<(), String> {
        if !CLIENT_CONFIG_KEYS.contains(&key) {
            return Err(format!("unknown config key: {key}"));
        }
        let toml_value = json_to_toml(value.clone())?;
        let text = std::fs::read_to_string(&self.config_path)
            .map_err(|e| format!("config read failed: {e}"))?;
        let mut table: toml::Table = toml::from_str(&text)
            .map_err(|e| format!("config parse failed: {e}"))?;
        let (section, field) = key
            .split_once('.')
            .ok_or_else(|| format!("unknown config key: {key}"))?;
        {
            let entry = table
                .entry(section.to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            let tbl = entry
                .as_table_mut()
                .ok_or_else(|| format!("config section {section} is not a table"))?;
            tbl.insert(field.to_string(), toml_value);
        }
        // Type-check the edited document before anything touches disk (§9.1
        // parse-failure fallback semantics).
        let rendered = toml::to_string(&table)
            .map_err(|e| format!("config parse failed: {e}"))?;
        let updated = toml::from_str::<LustlessConfig>(&rendered)
            .map_err(|e| format!("config parse failed: {e}"))?;
        write_config_atomic(&self.config_path, &rendered)?;
        // Keep the engine's §8 fail-closed flag in sync when its key changed.
        if key == "dns.fail_closed_when_signed_out" {
            if let Some(filter_state) = guard(&self.dns_filter).clone() {
                let effective = updated.dns.fail_closed_when_signed_out
                    && !guard(&self.policy).fail_open_override;
                filter_state.lock().set_fail_closed_when_signed_out(effective);
            }
        }
        *wguard(&self.cfg_live) = updated;
        tracing::info!("client config updated: {key}");
        Ok(())
    }
}

/// Waits up to `dur`; returns `true` when shutdown arrived first (or the
/// broadcast sender was dropped). Shared by the long-running daemon loops so
/// SIGTERM/`QUIT` stops them promptly.
pub async fn wait_or_shutdown(rx: &mut watch::Receiver<bool>, dur: Duration) -> bool {
    if *rx.borrow() {
        return true;
    }
    tokio::select! {
        changed = rx.changed() => changed.is_err() || *rx.borrow(),
        _ = tokio::time::sleep(dur) => false,
    }
}

/// Maps the §6.2 tri-state verdict into the forwarder's vocabulary (§8).
fn override_verdict(verdict: Verdict) -> lustless_dns::OverrideVerdict {
    match verdict {
        Verdict::Allow => lustless_dns::OverrideVerdict::Allow,
        Verdict::Block => lustless_dns::OverrideVerdict::Block,
        Verdict::Na => lustless_dns::OverrideVerdict::NotApplicable,
    }
}

/// Converts a JSON value into the `toml::Value` accepted by IPC `0x52`.
fn json_to_toml(value: Value) -> Result<toml::Value, String> {
    match value {
        Value::Null => Err("config values may not be null".to_string()),
        Value::Bool(b) => Ok(toml::Value::Boolean(b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(toml::Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(toml::Value::Float(f))
            } else {
                Err(format!("unsupported number: {n}"))
            }
        }
        Value::String(s) => Ok(toml::Value::String(s)),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_toml(item)?);
            }
            Ok(toml::Value::Array(out))
        }
        Value::Object(map) => {
            let mut out = toml::Table::new();
            for (key, item) in map {
                out.insert(key, json_to_toml(item)?);
            }
            Ok(toml::Value::Table(out))
        }
    }
}

/// Atomically persists the config file at §4 mode 0644.
fn write_config_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, contents).map_err(|e| format!("config write failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("config rename failed: {e}"))
}

// ---------------------------------------------------------------------------
// lustless-net trait implementations (pinned API, CONTRACTS §3)
// ---------------------------------------------------------------------------

impl PolicyProvider for DaemonState {
    /// §9 snapshot served to `NetServices`/the dashboard.
    fn snapshot(&self) -> PolicySnapshot {
        self.snapshot_for(ROOT_UID)
    }
}

impl Notifier for DaemonState {
    /// Fan-out of one notification to every connected IPC client (§5).
    fn notify(&self, level: &str, message: &str, progress: Option<u8>) {
        DaemonState::notify(self, level, message, progress);
    }
}

impl Control for DaemonState {
    /// IPC `0x65 SIGN_IN` semantics (§5, evidence `signin-and-settings.md`
    /// §3):
    ///
    /// * `upload.base_url` set → authenticate against the deployment's auth
    ///   endpoint (`POST <base_url>/v1/auth/signin`, §10 family) and store
    ///   `device_token`/`refresh_token` in §6.2 `api_credentials`. The
    ///   password is used for the request and dropped — it is never stored.
    /// * `upload.base_url` empty → documented **offline mode**: local session
    ///   only. `PolicySnapshot.username` is set, no credential is persisted,
    ///   and the caller gets a random 128-bit local session token.
    ///
    /// Failures map 1:1 onto CE's `translateLoginFailure` texts
    /// (`signin-and-settings.md` §3): 400/401 → [`ERR_INVALID_CREDENTIALS`],
    /// 403 → [`ERR_ACCOUNT_DISABLED`], 404 → [`ERR_NO_SERVICES`], transport
    /// or malformed responses → [`ERR_NO_CONNECTION`].
    fn sign_in(&self, username: &str, password: &str) -> Result<String, String> {
        let username = username.trim();
        if username.is_empty() || password.is_empty() {
            return Err(ERR_INVALID_CREDENTIALS.to_string());
        }
        let uid = self.signin_uid();
        {
            let mut pol = guard(&self.policy);
            pol.machine.begin_sign_in()?;
        }
        let cfg = self.config();
        let auth = if cfg.upload.base_url.trim().is_empty() {
            tracing::warn!(
                "sign-in: upload.base_url is empty — offline mode, local session only"
            );
            Ok(AuthOutcome::Offline)
        } else {
            authenticate_remote(&cfg.upload.base_url, username, password)
        };
        let auth = match auth {
            Ok(auth) => auth,
            Err(err) => {
                guard(&self.policy).machine.fail_sign_in();
                return Err(err);
            }
        };
        match self.persist_sign_in(uid, username, &auth) {
            Ok(token) => Ok(token),
            Err(err) => {
                guard(&self.policy).machine.fail_sign_in();
                Err(err)
            }
        }
    }

    /// IPC `0x66 SIGN_OUT` (§5): closes the §6.1 login row, clears the §6.2
    /// tokens (passwords were never there), deactivates §8 filtering for the
    /// user and returns the machine to `LOGGED_OUT`.
    fn sign_out(&self) -> Result<(), String> {
        let (uid, username, login_at) = {
            let pol = guard(&self.policy);
            if pol.machine.state() != UserState::LoggedIn {
                return Err("no user is currently signed in".to_string());
            }
            (
                pol.session_uid
                    .ok_or_else(|| "no user is currently signed in".to_string())?,
                pol.machine.username().to_string(),
                pol.session_login_at.clone(),
            )
        };
        let (timestamp, _) = self.event_stamp();
        let login_at = login_at.unwrap_or_else(|| timestamp.clone());
        {
            let mut outbox = guard(&self.outbox);
            outbox
                .insert_login(&LoginRow {
                    username: username.clone(),
                    system_user_id: Some(uid.to_string()),
                    system_user_name: os_username(uid),
                    timestamp,
                    login_at,
                    logout_at: Some(rguard(&self.clock).now_iso8601()),
                })
                .map_err(db_err)?;
        }
        // Credential hygiene (§10: revocable tokens, no password ever).
        match self.settings_for(uid) {
            Ok(settings) => {
                if let Err(e) = guard(&settings).clear_api_credentials(&username) {
                    tracing::warn!("clearing api_credentials failed: {e}");
                }
            }
            Err(e) => tracing::warn!("settings unavailable at sign-out: {e}"),
        }
        self.sync_membership(&username, false);
        let mut pol = guard(&self.policy);
        pol.machine.sign_out();
        pol.session_uid = None;
        pol.session_login_at = None;
        pol.session_token = None;
        pol.flags = UserFlags::default();
        pol.filter_level = DEFAULT_FILTER_LEVEL.to_string();
        drop(pol);
        // After the machine is LOGGED_OUT this clears the §8 domain cache.
        self.refresh_domain_lists();
        tracing::info!("signed out: {username}");
        Ok(())
    }

    /// IPC `0x63 FILTER_SET_LEVEL` (§5): validates CE's three-level
    /// vocabulary and persists it into §6.2 `user_dns_filter`.
    fn set_filter_level(&self, level: &str) -> Result<(), String> {
        DaemonState::set_filter_level(self, level)
    }

    /// IPC `0x64 FILTER_SET_OVERRIDES` (§5): persists the tri-state override
    /// for the signed-in user and refreshes the §8 cache.
    fn set_override(&self, domain: &str, verdict: &str) -> Result<(), String> {
        DaemonState::set_override(self, domain, verdict)
    }

    /// IPC `0x43 COLLECT_DEBUG_LOGS` (§5): spawns the support-bundle
    /// collection with the two CE progress notifications.
    fn collect_debug(&self) -> Result<(), String> {
        let state = self
            .self_weak
            .upgrade()
            .ok_or_else(|| "daemon not initialized".to_string())?;
        if state.start_diagnostics() {
            Ok(())
        } else {
            Err("diagnostics collection already in progress".to_string())
        }
    }

    /// IPC `0x67 UPDATE_CHECK` (§12): fetches the §12 feed
    /// (`POST <update.feed_url>`, the §10 `/v1/desktop_client_update` shape)
    /// and returns the recommendation verbatim — `now|later|none` is the whole
    /// policy; an empty `feed_url` disables the updater (§12).
    fn update_check(&self) -> Result<String, String> {
        let cfg = self.config();
        let feed = cfg.update.feed_url.trim();
        if feed.is_empty() {
            return Ok("none".to_string());
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("update check failed: {e}"))?;
        let response = client
            .post(feed)
            .json(&json!({}))
            .send()
            .map_err(|e| format!("update check failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("update check failed: HTTP {}", response.status()));
        }
        let body: Value = response
            .json()
            .map_err(|e| format!("update check failed: {e}"))?;
        let recommendation = body
            .get("recommendation")
            .and_then(Value::as_str)
            .ok_or_else(|| "update check failed: feed has no recommendation".to_string())?;
        match recommendation {
            "now" | "later" | "none" => Ok(recommendation.to_string()),
            other => Err(format!("update check failed: invalid recommendation {other}")),
        }
    }
}

/// Successful/failed remote authentication outcome of [`authenticate_remote`].
enum AuthOutcome {
    /// Server issued tokens (stored in §6.2 `api_credentials`).
    Remote {
        device_token: String,
        refresh_token: Option<String>,
    },
    /// `upload.base_url` empty — documented offline mode (local session).
    Offline,
}

/// `POST <base_url>/v1/auth/signin` with `{username,password}`; maps HTTP
/// outcomes onto CE's `translateLoginFailure` texts
/// (`signin-and-settings.md` §3).
fn authenticate_remote(base_url: &str, username: &str, password: &str) -> Result<AuthOutcome, String> {
    let url = format!("{}/v1/auth/signin", base_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| ERR_NO_CONNECTION.to_string())?;
    let response = client
        .post(&url)
        .json(&json!({ "username": username, "password": password }))
        .send();
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            tracing::warn!("sign-in transport failure: {err}");
            return Err(ERR_NO_CONNECTION.to_string());
        }
    };
    match response.status().as_u16() {
        200..=299 => {
            let body: Value = response.json().map_err(|e| {
                tracing::warn!("sign-in response malformed: {e}");
                ERR_NO_CONNECTION.to_string()
            })?;
            let device_token = body
                .get("device_token")
                .and_then(Value::as_str)
                .filter(|token| !token.is_empty())
                .ok_or_else(|| ERR_NO_CONNECTION.to_string())?
                .to_string();
            let refresh_token = body
                .get("refresh_token")
                .and_then(Value::as_str)
                .filter(|token| !token.is_empty())
                .map(String::from);
            Ok(AuthOutcome::Remote {
                device_token,
                refresh_token,
            })
        }
        400 | 401 => Err(ERR_INVALID_CREDENTIALS.to_string()),
        403 => Err(ERR_ACCOUNT_DISABLED.to_string()),
        404 => Err(ERR_NO_SERVICES.to_string()),
        status => {
            tracing::warn!("sign-in failed with status {status}");
            Err(ERR_NO_CONNECTION.to_string())
        }
    }
}

impl DaemonState {
    /// Persists a successful sign-in: §6.2 settings rows, §6.1 `logins`
    /// (plus `switch_users` on a switch), §8 membership and the §9 machine
    /// completion. On any failure the caller rolls the machine back.
    fn persist_sign_in(
        &self,
        uid: u32,
        username: &str,
        auth: &AuthOutcome,
    ) -> Result<String, String> {
        let (switching, previous, previous_login_at) = {
            let pol = guard(&self.policy);
            (
                pol.machine.state() == UserState::SwitchingUser,
                pol.machine.previous_username().to_string(),
                pol.session_login_at.clone(),
            )
        };
        let settings = self.settings_for(uid)?;
        let flags = {
            let mut s = guard(&settings);
            if s.get_user_info(username).map_err(db_err)?.is_none() {
                s.set_user_info(&fresh_user_info(username)).map_err(db_err)?;
            }
            if s.get_dns_filter(username).map_err(db_err)?.is_none() {
                s.set_dns_filter(&UserDnsFilter::default_for(username))
                    .map_err(db_err)?;
            }
            if let AuthOutcome::Remote {
                device_token,
                refresh_token,
            } = auth
            {
                s.set_api_credentials(&ApiCredentials {
                    username: username.to_string(),
                    device_token: device_token.clone(),
                    refresh_token: refresh_token.clone(),
                })
                .map_err(db_err)?;
            }
            let info = s
                .get_user_info(username)
                .map_err(db_err)?
                .unwrap_or_else(|| fresh_user_info(username));
            let level = s
                .get_dns_filter(username)
                .map_err(db_err)?
                .map(|f| f.level)
                .unwrap_or_else(|| DEFAULT_FILTER_LEVEL.to_string());
            (UserFlags::from(&info), level)
        };
        let (flags, level) = flags;

        let device_id = self.device_id();
        let (timestamp, _) = self.event_stamp();
        let switching = switching && !previous.is_empty() && previous != username;
        if switching {
            let login_at = previous_login_at.unwrap_or_else(|| timestamp.clone());
            {
                let mut outbox = guard(&self.outbox);
                outbox
                    .insert_login(&LoginRow {
                        username: previous.clone(),
                        system_user_id: Some(uid.to_string()),
                        system_user_name: os_username(uid),
                        timestamp: login_at.clone(),
                        login_at,
                        logout_at: Some(timestamp.clone()),
                    })
                    .map_err(db_err)?;
                outbox
                    .insert_switch_user(&SwitchUserRow {
                        username: username.to_string(),
                        switch_user_from: previous.clone(),
                        switch_user_to: username.to_string(),
                        timestamp: timestamp.clone(),
                        timezone_offset: local_timezone_offset(),
                        device_name: None,
                        device_id: device_id.clone(),
                    })
                    .map_err(db_err)?;
            }
            // Credentials and §8 membership of the previous user are cleaned
            // up outside the outbox guard (lock hygiene: never nest the
            // settings/forwarder locks under the outbox).
            if let Ok(previous_settings) = self.settings_for(uid) {
                if let Err(e) = guard(&previous_settings).clear_api_credentials(&previous) {
                    tracing::warn!("clearing previous api_credentials failed: {e}");
                }
            }
            self.sync_membership(&previous, false);
        }
        {
            let mut outbox = guard(&self.outbox);
            outbox
                .insert_login(&LoginRow {
                    username: username.to_string(),
                    system_user_id: Some(uid.to_string()),
                    system_user_name: os_username(uid),
                    timestamp: timestamp.clone(),
                    login_at: timestamp.clone(),
                    logout_at: None,
                })
                .map_err(db_err)?;
        }

        let token = match auth {
            AuthOutcome::Remote { device_token, .. } => device_token.clone(),
            AuthOutcome::Offline => {
                let token = local_session_token();
                guard(&self.policy).session_token = Some(token.clone());
                token
            }
        };

        if flags.has_filtering {
            self.sync_membership(username, true);
        }

        {
            let mut pol = guard(&self.policy);
            pol.machine.complete_sign_in(username);
            pol.session_uid = Some(uid);
            pol.session_login_at = Some(rguard(&self.clock).now_iso8601());
            pol.flags = flags;
            pol.filter_level = level;
        }
        // Only now that the machine is LOGGED_IN does the §8 domain cache
        // pick up this user's §6.2 override lists.
        self.refresh_domain_lists();
        tracing::info!(
            "signed in: {username} (uid {uid}, {})",
            match auth {
                AuthOutcome::Offline => "offline mode",
                AuthOutcome::Remote { .. } => "authenticated",
            }
        );
        Ok(token)
    }
}

/// A random 128-bit hex local session token for offline sign-in (§5 `0x65`
/// reply `{"token",…}`); never persisted — `SO_PEERCRED` remains the frame
/// authorization (§5).
fn local_session_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    ids::to_hex(&bytes)
}

/// OS account name for a uid (`logins.system_user_name`, §6.1), best effort.
fn os_username(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.name)
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;

    /// A `DaemonState` bound to a temp state dir with a fresh outbox; the
    /// config runs in **offline mode** (`upload.base_url` empty) so sign-in
    /// tests never touch the network (testing contract §16).
    pub struct TestState {
        pub state: Arc<DaemonState>,
        pub dir: tempfile::TempDir,
    }

    impl TestState {
        /// Opens the uid's settings DB handle for assertions.
        pub fn settings(&self, uid: u32) -> Arc<Mutex<SettingsDb>> {
            self.state.settings_for(uid).expect("settings open")
        }
    }

    pub fn test_state() -> TestState {
        test_state_with(|cfg| {
            cfg.upload.base_url = String::new();
        })
    }

    /// Like [`test_state`] but lets the test adjust the config first.
    pub fn test_state_with(f: impl FnOnce(&mut LustlessConfig)) -> TestState {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = LustlessConfig::default();
        cfg.daemon.state_dir = dir.path().join("state").display().to_string();
        cfg.daemon.socket_path = dir
            .path()
            .join("run")
            .join("lustlessd.sock")
            .display()
            .to_string();
        cfg.capture.spool_dir = dir.path().join("spool").display().to_string();
        f(&mut cfg);
        let state_dir = PathBuf::from(&cfg.daemon.state_dir);
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let cfg = Arc::new(cfg);
        let outbox = Outbox::open(&outbox_path(&cfg)).expect("outbox");
        let clock = Arc::new(RwLock::new(ClockAnchor::system()));
        let (shutdown, _rx) = watch::channel(false);
        let state = Arc::new(DaemonState::new(
            cfg,
            dir.path().join("lustless.toml"),
            Arc::new(Mutex::new(outbox)),
            clock,
            shutdown,
        ));
        state.bind_weak();
        TestState { state, dir }
    }

    #[test]
    fn offline_sign_in_sets_session_without_storing_a_password() {
        let ts = test_state();
        let state = &ts.state;
        state.set_sign_in_uid_hint(1000);
        let token = state.sign_in("alice", "hunter2").expect("offline sign-in");
        assert!(!token.is_empty());
        assert_eq!(state.username(), "alice");
        assert!(state.snapshot().signed_in);

        let snapshot = state.snapshot();
        assert_eq!(snapshot.username, "alice");
        assert!(snapshot.signed_in);
        assert_eq!(snapshot.state, UserState::LoggedIn);
        // §3 / assignment: offline mode keeps `is_panicked=false`.
        assert!(!snapshot.is_panicked);
        assert!(snapshot.has_filtering);
        assert!(snapshot.has_screen_accountability);

        // No password anywhere: `api_credentials` is untouched in offline mode.
        let settings = ts.settings(1000);
        assert!(guard(&settings)
            .get_api_credentials("alice")
            .expect("read")
            .is_none());
        // The session is bound to the caller's uid (SO_PEERCRED, §5).
        assert_eq!(state.session_uid(), Some(1000));
        assert!(state.policy_state().session_login_at.is_some());

        // Sign out returns to LOGGED_OUT with a closed login row.
        state.sign_out().expect("sign-out");
        assert!(!state.snapshot().signed_in);
        assert_eq!(state.snapshot().state, UserState::LoggedOut);
        assert!(state.sign_out().is_err(), "second sign-out is rejected");
    }

    #[test]
    fn remote_sign_in_failures_use_the_ui3_texts() {
        // Port 9 (discard) on loopback: connection refused, no network needed.
        let ts = test_state_with(|cfg| {
            cfg.upload.base_url = "http://127.0.0.1:9".to_string();
        });
        let state = &ts.state;
        state.set_sign_in_uid_hint(1000);
        let err = state.sign_in("alice", "hunter2").expect_err("offline host");
        assert_eq!(err, ERR_NO_CONNECTION);

        // Empty credentials fail before any request, with the §3 text.
        let err = state.sign_in("", "").expect_err("empty");
        assert_eq!(err, ERR_INVALID_CREDENTIALS);
        assert_eq!(state.snapshot().state, UserState::LoggedOut, "rolled back");
    }

    #[test]
    fn notifier_fans_out_per_connection() {
        let ts = test_state();
        let state = &ts.state;
        let (id_a, queue_a) = state.register_connection();
        let (id_b, queue_b) = state.register_connection();

        state.notify("info", "Diagnostics are being collected…", Some(0));
        assert_eq!(guard(&queue_a).len(), 1, "client A queued");
        assert_eq!(guard(&queue_b).len(), 1, "client B queued");
        assert_eq!(
            guard(&queue_a).front().expect("msg").message,
            "Diagnostics are being collected…"
        );

        state.unregister_connection(id_b);
        state.notify("info", "We've finished collecting diagnostics", Some(100));
        assert_eq!(guard(&queue_a).len(), 2, "A still receives");
        assert_eq!(guard(&queue_b).len(), 1, "B is gone");
        state.unregister_connection(id_a);

        let payload = guard(&queue_a).front().expect("msg").to_payload();
        assert_eq!(payload["level"], "info");
        assert_eq!(payload["progress"], 100);
    }

    #[test]
    fn filter_level_and_override_validation() {
        let ts = test_state();
        let state = &ts.state;
        assert!(state.set_filter_level("Strong Blocking").is_err(), "no session");
        state.set_sign_in_uid_hint(1000);
        state.sign_in("alice", "pw").expect("sign-in");

        state
            .set_filter_level("Blocking Enabled")
            .expect("valid level");
        assert_eq!(state.policy_state().filter_level, "Blocking Enabled");
        let err = state.set_filter_level("Everything").expect_err("invalid");
        assert!(err.contains("invalid filter level"), "{err}");

        state.set_override("Example.COM", "block").expect("override");
        state.set_override("example.org", "na").expect("override 2");
        let err = state.set_override("example.net", "sideways").expect_err("invalid verdict");
        assert!(err.contains("invalid verdict"), "{err}");
        let err = state.set_override("", "allow").expect_err("empty domain");
        assert!(err.contains("domain"), "{err}");

        // The §8 cache picked the overrides up (suffix keys lowercased).
        let lists = state.domain_lists();
        assert_eq!(
            lists.custom.get("example.com"),
            Some(&lustless_dns::OverrideVerdict::Block)
        );
        assert_eq!(
            lists.custom.get("example.org"),
            Some(&lustless_dns::OverrideVerdict::NotApplicable)
        );
    }

    #[test]
    fn user_settings_change_rejects_unknown_fields_before_writing() {
        let ts = test_state();
        let state = &ts.state;
        let before = state.policy_state().filter_level.clone();

        let err = state
            .apply_user_settings(1000, &json!({"nonsense": 1}))
            .expect_err("no session");
        assert!(err.contains("no user is currently signed in"), "{err}");

        state.set_sign_in_uid_hint(1000);
        state.sign_in("alice", "pw").expect("sign-in");

        let err = state
            .apply_user_settings(1000, &json!({"bogus_flag": true}))
            .expect_err("unknown field");
        assert!(err.contains("unknown settings field"), "{err}");
        assert_eq!(state.policy_state().filter_level, before, "nothing written");

        // A valid mix: flag + level land in the policy mirror and settings.
        state
            .apply_user_settings(
                1000,
                &json!({"can_override": true, "filter_level": "Strong Blocking"}),
            )
            .expect("valid settings");
        let pol = state.policy_state();
        assert!(pol.flags.can_override);
        assert_eq!(pol.filter_level, "Strong Blocking");

        // A foreign uid may not mutate this session (§5 self scope).
        let err = state
            .apply_user_settings(2000, &json!({"can_override": false}))
            .expect_err("foreign uid");
        assert!(err.contains("another user"), "{err}");
    }

    #[test]
    fn break_glass_sets_fail_open_reported_in_snapshot() {
        let ts = test_state();
        let state = &ts.state;
        state.set_sign_in_uid_hint(1000);
        state.sign_in("alice", "pw").expect("sign-in");

        let before = state.snapshot();
        assert!(before.filter.fail_closed, "§9.1 default is fail-closed");
        assert!(!before.is_panicked);

        assert!(state.break_glass(0, "").is_err(), "reason required");
        state.break_glass(0, "filter outage").expect("break-glass");

        let after = state.snapshot();
        assert!(!after.filter.fail_closed, "fail-open override reported");
        assert!(!after.is_panicked, "is_panicked stays the server flag (false)");
        assert!(after.filter.health == "healthy", "filter health still reported");
        assert!(state.policy_state().fail_open_override);
    }

    #[test]
    fn set_client_config_validates_and_persists() {
        let ts = test_state();
        let state = &ts.state;

        let err = state
            .set_client_config("capture.interval_sec", &json!(45))
            .expect_err("config file missing");
        assert!(err.contains("config read failed"), "{err}");

        std::fs::write(state.config_path(), "# lustless\n").expect("config file");
        let err = state
            .set_client_config("capture.spellbook", &json!(1))
            .expect_err("unknown key");
        assert!(err.contains("unknown config key"), "{err}");

        state
            .set_client_config("capture.interval_sec", &json!(45))
            .expect("valid key");
        assert_eq!(state.config().capture.interval_sec, 45);
        let text = std::fs::read_to_string(state.config_path()).expect("read back");
        let parsed: LustlessConfig = toml::from_str(&text).expect("round trip");
        assert_eq!(parsed.capture.interval_sec, 45);

        // Type mismatch is rejected before disk (§9.1 parse-failure rule).
        let err = state
            .set_client_config("capture.interval_sec", &json!("soon"))
            .expect_err("type mismatch");
        assert!(err.contains("config parse failed"), "{err}");
        assert_eq!(state.config().capture.interval_sec, 45, "unchanged");
    }

    #[test]
    fn status_and_foreign_uid_snapshot_scoping() {
        let ts = test_state();
        let state = &ts.state;
        state.set_sign_in_uid_hint(1000);
        state.sign_in("alice", "pw").expect("sign-in");

        let own = state.snapshot_for(1000);
        assert!(own.signed_in);
        assert_eq!(own.username, "alice");
        let root = state.snapshot_for(0);
        assert!(root.signed_in, "root sees the session (§5 root-or-self)");
        let foreign = state.snapshot_for(2000);
        assert!(!foreign.signed_in, "another uid sees only its own (empty) state");
        assert_eq!(foreign.state, UserState::LoggedOut);

        let status = state.status_json();
        assert_eq!(status["username"], "alice");
        assert_eq!(status["signed_in"], true);
        assert!(status.get("analyzed_count").is_some());
    }

    #[test]
    fn analyzed_counter_bumps() {
        let ts = test_state();
        let state = &ts.state;
        assert_eq!(state.policy_state().analyzed_count, 0);
        state.bump_analyzed(7);
        state.bump_analyzed(0); // no-op, no timestamp churn
        let pol = state.policy_state();
        assert_eq!(pol.analyzed_count, 7);
        assert!(pol.analyzed_updated_at.is_some());
    }
}
