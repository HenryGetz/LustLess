//! `uploader.rs` — the §10 REST uploader: one uploader, one outbox, CE's
//! claim/reaper state machine, per-user batching, server-requested throttling
//! and the hourly `(server_time, local_ticks)` clock anchor.
//!
//! Topology verbatim from CE (`re/findings/16-updater/upload-protocol.md`
//! §3–§5; CONTRACTS §10): batch **100** rows/request
//! ([`Outbox::claim_batch`] with the §6.1 min-age gate of 30 s), per-user
//! batching for the activity log, `mark_sent` on server ack, stale-`sending`
//! reaping (5 min) for crash recovery, invalid records dropped via
//! [`Outbox::drop_invalid`] (never failing a batch), and self-metrics
//! `client_api_success`/`client_api_problem` with host/route/status tags
//! around **every** HTTP call (§14).
//!
//! The loop has two distinct timers (§10):
//!
//! * the **flush poll** — a cheap local claim every `upload.retry_sec`
//!   (network only when rows are actually claimable; a LustLess choice, CE's
//!   `ApiActivityLoggingThread` flush cadence was not recoverable);
//! * the purely local **bookkeeping heartbeat** — `upload.heartbeat_sec`
//!   steady (600 s), `upload.retry_sec` on failure, zero packets by
//!   construction: it rolls aged metrics buckets, reaps stale claims and
//!   stamps `last_heartbeat_at` — distinct from any upload stamp.
//!
//! The HTTP layer is the [`Http`] trait: production uses [`ReqwestHttp`]
//! (one `reqwest::Client` with `pool_max_idle_per_host(0)` — §10 "fresh TCP
//! connect per exchange"); the unit tests drive the full state machine
//! through a mock (CONTRACTS §16: deterministic, no network).
//!
//! Locks: the outbox/clock locks are `std::sync` because their types are
//! pinned by the daemon-facing API (`NetServices::new`); the crate-owned
//! locks (audit ring, token store) use `parking_lot`.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use std::time::Duration;

use lustless_core::clock::{system_unix, ClockAnchor};
use lustless_core::config::LustlessConfig;
use lustless_core::db::{
    ClaimedRow, EventTable, Outbox, DEFAULT_MIN_AGE_SECS, STALE_SENDING_SECS,
};
use lustless_core::ids;
use lustless_core::metrics::{
    AggTag, Aggregation, BucketTag, MetricField, MetricName, MetricRow, MetricSink,
    OPERATION_AGGREGATE,
};
use lustless_core::records::{
    circumvention_record, install_activity_record, login_activity_record,
    switch_user_activity_record, web_activity_record, CircumventionFields, ClientBlock,
    InstallFields, LoginActivityFields, RecordContext, SwitchUserFields, WebActivityFields,
    local_architecture,
};
use lustless_core::settings::SettingsDb;
use lustless_core::LUSTLESS_VERSION;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, error, warn};

use crate::PolicyProvider;

/// File name of the persisted throttle state inside `daemon.state_dir`
/// (§10: server-requested throttling survives restarts as
/// `upload.resume_not_before`).
pub(crate) const UPLOADER_STATE_FILE: &str = "uploader-state.json";

/// `install_metadata` key stamped by the local bookkeeping heartbeat (§10:
/// "purely local bookkeeping tick … stamps last_update_at for health
/// monitoring, separate from upload completion stamps").
pub(crate) const HEARTBEAT_STAMP_KEY: &str = "last_heartbeat_at";

/// `install_metadata` key holding the install/device uuid shared by the
/// install activity record (§10) and the updater request (§12).
pub(crate) const DEVICE_UUID_KEY: &str = "device_uuid";

/// `install_metadata` key marking that the one-shot `installActivityRecord`
/// (§15 postinst report) has been delivered.
const INSTALL_REPORTED_KEY: &str = "install_activity_reported";

/// Default backoff when the server throttles without saying for how long.
const DEFAULT_THROTTLE_FALLBACK_SECS: i64 = 300;

/// Clock-anchor refresh period (§10: hourly `ServerTimeManager::sync`).
const ANCHOR_REFRESH_SECS: i64 = 3600;

/// Capacity of the in-memory API audit ring behind `upload.logs_store`
/// (`/v1/logs/store`, §10 — the support event log, debug toggle).
const AUDIT_RING_CAP: usize = 256;

/// Length cap for request/response snippets in audit records.
const AUDIT_SNIPPET_CHARS: usize = 256;

/// The four activity tables of §10, in flush order.
const ACTIVITY_TABLES: [EventTable; 4] = [
    EventTable::DnsActivity,
    EventTable::Logins,
    EventTable::Circumventions,
    EventTable::SwitchUsers,
];

// ---------------------------------------------------------------------------
// HTTP abstraction
// ---------------------------------------------------------------------------

/// HTTP verb of one API exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiMethod {
    /// `GET` (`/v1/status/time`, `/v1/status/ping`, update download).
    Get,
    /// `POST` (every upload route of §10).
    Post,
}

/// One outbound API exchange.
#[derive(Debug, Clone)]
pub(crate) struct ApiRequest {
    /// Verb.
    pub(crate) method: ApiMethod,
    /// Absolute URL.
    pub(crate) url: String,
    /// `Authorization: Bearer <device_token>` value (§10: Bearer only — no
    /// Basic, no stored password); `None` for unauthenticated calls.
    pub(crate) bearer: Option<String>,
    /// JSON request body.
    pub(crate) body: Option<String>,
}

/// One API response: status + raw bytes (payload downloads are binary — the
/// update package of §12 must be verified over the *exact* bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiResponse {
    /// HTTP status code.
    pub(crate) status: u16,
    /// Raw response body.
    pub(crate) body: Vec<u8>,
    /// `Retry-After` header, delta-seconds form.
    pub(crate) retry_after: Option<u64>,
}

/// The object-safe async HTTP seam shared by the uploader, the updater and
/// the unit tests (a `dyn`-safe wrapper over an `async fn`).
pub(crate) trait Http: Send + Sync + 'static {
    /// Executes one exchange to completion.
    fn execute(
        &self,
        request: ApiRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ApiResponse, String>> + Send + 'static>>;
}

/// Production HTTP layer: `reqwest` + rustls (CONTRACTS §2).
///
/// One client is built per uploader with `pool_max_idle_per_host(0)` so
/// **every exchange opens a fresh TCP connection** (§10: CE rotates ~301 s
/// connections); no connection pool, no keep-alive reuse.
pub(crate) struct ReqwestHttp {
    client: reqwest::Client,
}

impl ReqwestHttp {
    /// Builds the client. The builder configuration is static, so `build()`
    /// cannot fail.
    pub(crate) fn new() -> Self {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .expect("static reqwest client configuration");
        ReqwestHttp { client }
    }
}

impl Http for ReqwestHttp {
    fn execute(
        &self,
        request: ApiRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ApiResponse, String>> + Send + 'static>> {
        let client = self.client.clone();
        Box::pin(async move {
            let mut builder = match request.method {
                ApiMethod::Get => client.get(&request.url),
                ApiMethod::Post => client.post(&request.url),
            };
            if let Some(token) = &request.bearer {
                builder = builder.header("Authorization", format!("Bearer {token}"));
            }
            if let Some(body) = request.body {
                builder = builder.header("Content-Type", "application/json").body(body);
            }
            let response = builder.send().await.map_err(|err| err.to_string())?;
            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok());
            let body = response.bytes().await.map_err(|err| err.to_string())?;
            Ok(ApiResponse {
                status,
                body: body.to_vec(),
                retry_after,
            })
        })
    }
}

/// Result of one raw exchange.
pub(crate) enum ApiResult {
    /// An HTTP response (any status).
    Response {
        /// Status code.
        status: u16,
        /// Raw body.
        body: Vec<u8>,
        /// `Retry-After` header.
        retry_after: Option<u64>,
    },
    /// Transport failure (connect/TLS/read).
    Transport(String),
}

/// Executes one exchange with self-metrics + an audit row around it (§14:
/// `client_api_success`/`client_api_problem` with host/route/status tags
/// around **every** HTTP call). Shared by the uploader and the updater.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn tracked_exchange(
    http: &dyn Http,
    outbox: &Mutex<Outbox>,
    clock: &RwLock<ClockAnchor>,
    policy: &dyn PolicyProvider,
    audit: &AuditLog,
    component: &str,
    route: &str,
    method: ApiMethod,
    url: &str,
    body: Option<String>,
    bearer: Option<String>,
) -> ApiResult {
    let request = ApiRequest {
        method,
        url: url.to_string(),
        bearer,
        body: body.clone(),
    };
    let host = url_host(url);
    let result = http.execute(request).await;
    let username = policy.snapshot().username;
    match &result {
        Ok(response) => {
            track_api_call(outbox, policy, component, &host, route, Ok(response.status));
            audit_push(
                audit,
                clock,
                &username,
                component,
                &format!("{method:?} {url} {}", snippet(&body.unwrap_or_default())),
                &format!(
                    "{} {}",
                    response.status,
                    snippet(&String::from_utf8_lossy(&response.body))
                ),
            );
            if !(200..300).contains(&response.status) {
                warn!("{route} answered HTTP {}", response.status);
            }
            ApiResult::Response {
                status: response.status,
                body: response.body.clone(),
                retry_after: response.retry_after,
            }
        }
        Err(err) => {
            track_api_call(outbox, policy, component, &host, route, Err(()));
            audit_push(
                audit,
                clock,
                &username,
                component,
                &format!("{method:?} {url}"),
                &format!("transport error: {err}"),
            );
            warn!("{route} transport error: {err}");
            ApiResult::Transport(err.clone())
        }
    }
}

// ---------------------------------------------------------------------------
// Self-metrics + audit ring (§14)
// ---------------------------------------------------------------------------

/// Records one `client_api_success`/`client_api_problem` sample (§14) with
/// `host_name` / `route` / `http_response_code` tags. Never fails the
/// calling path.
pub(crate) fn track_api_call(
    outbox: &Mutex<Outbox>,
    policy: &dyn PolicyProvider,
    component: &str,
    host: &str,
    route: &str,
    status: Result<u16, ()>,
) {
    let metric = match status {
        Ok(code) if (200..300).contains(&code) => MetricName::ClientApiSuccess,
        _ => MetricName::ClientApiProblem,
    };
    let code = match status {
        Ok(code) => code.to_string(),
        Err(()) => "transport".to_string(),
    };
    let username = policy.snapshot().username;
    let bucket = [BucketTag {
        indexed: true,
        name: "client_component".to_string(),
        value: component.to_string(),
    }];
    let tags = [
        AggTag {
            aggregation: Aggregation::Indexed,
            name: "host_name".to_string(),
            value: host.to_string(),
        },
        AggTag {
            aggregation: Aggregation::Cardinal,
            name: "route".to_string(),
            value: route.to_string(),
        },
        AggTag {
            aggregation: Aggregation::Cardinal,
            name: "http_response_code".to_string(),
            value: code,
        },
    ];
    let fields = [MetricField {
        name: "api_count".to_string(),
        operation: OPERATION_AGGREGATE,
        value: json!(1),
    }];
    let mut outbox = lock_outbox(outbox);
    if let Err(err) = MetricSink::new(&mut outbox).record(&username, metric, &bucket, &tags, &fields)
    {
        warn!("failed to record api self-metric: {err}");
    }
}

/// The in-memory API audit ring behind `upload.logs_store` (§10
/// `/v1/logs/store`: per-call rows `(username, request, response, process,
/// component, timestamp)`; evidence `upload-protocol.md` §5). Shared by the
/// uploader and the updater; drained to the server on each flush cycle.
#[derive(Debug, Default)]
pub(crate) struct AuditLog {
    records: parking_lot::Mutex<VecDeque<Value>>,
}

impl AuditLog {
    /// Appends one audit record, evicting the oldest beyond the ring cap.
    pub(crate) fn push(&self, record: Value) {
        let mut records = self.records.lock();
        if records.len() >= AUDIT_RING_CAP {
            records.pop_front();
        }
        records.push_back(record);
    }

    /// Drains every record (they are restored if the send fails, never
    /// silently lost).
    pub(crate) fn drain(&self) -> Vec<Value> {
        std::mem::take(&mut *self.records.lock()).into()
    }

    /// Re-queues drained records at the front of the ring (failed send).
    pub(crate) fn restore_front(&self, records: Vec<Value>) {
        if records.is_empty() {
            return;
        }
        let mut ring = self.records.lock();
        for record in records.into_iter().rev() {
            ring.push_front(record);
        }
    }
}

/// Appends one audit row (CE's per-call event-log record) with a bounded
/// request/response snippet.
pub(crate) fn audit_push(
    audit: &AuditLog,
    clock: &RwLock<ClockAnchor>,
    username: &str,
    component: &str,
    request: &str,
    response: &str,
) {
    audit.push(json!({
        "username": username,
        "request": snippet(request),
        "response": snippet(response),
        "process": "lustlessd",
        "component": component,
        "timestamp": read_clock(clock).now_iso8601(),
    }));
}

fn snippet(text: &str) -> String {
    if text.len() <= AUDIT_SNIPPET_CHARS {
        return text.to_string();
    }
    let mut cut = AUDIT_SNIPPET_CHARS;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_string()
}

// ---------------------------------------------------------------------------
// Shared small helpers
// ---------------------------------------------------------------------------

/// Locks the outbox. The type is pinned by the daemon-facing API
/// (`std::sync::Mutex`), so poisoning is recovered instead of panicking:
/// DB work never mutates rows while holding the lock through a panic path.
pub(crate) fn lock_outbox(outbox: &Mutex<Outbox>) -> MutexGuard<'_, Outbox> {
    outbox
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Reads the clock anchor (pinned `std::sync::RwLock` type; poison
/// recovered).
pub(crate) fn read_clock(clock: &RwLock<ClockAnchor>) -> RwLockReadGuard<'_, ClockAnchor> {
    clock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Writes the clock anchor (pinned `std::sync::RwLock` type; poison
/// recovered).
pub(crate) fn write_clock(
    clock: &RwLock<ClockAnchor>,
) -> std::sync::RwLockWriteGuard<'_, ClockAnchor> {
    clock
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Percent-encodes one URL path segment (usernames are account e-mail-ish;
/// only RFC 3986 unreserved characters plus `@`/`+` pass through).
pub(crate) fn path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let safe =
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'@' | b'+');
        if safe {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Trims trailing `/` off the configured base URL.
pub(crate) fn base_url(cfg: &LustlessConfig) -> String {
    cfg.upload.base_url.trim_end_matches('/').to_string()
}

/// Host tag for self-metrics (§14 `host_name`): the URL's host.
pub(crate) fn url_host(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Reads (or lazily creates+persists) the install/device uuid shared by the
/// §10 install record and the §12 update-check request.
pub(crate) fn device_uuid(outbox: &Mutex<Outbox>) -> String {
    let mut outbox = lock_outbox(outbox);
    match outbox.install_metadata(DEVICE_UUID_KEY) {
        Ok(Some(uuid)) if !uuid.is_empty() => uuid,
        _ => {
            let uuid = ids::new_device_id();
            if let Err(err) = outbox.set_install_metadata(DEVICE_UUID_KEY, &uuid) {
                warn!("failed to persist device uuid: {err}");
            }
            uuid
        }
    }
}

/// Converts a SQLite `DATETIME('now')` stamp (`YYYY-MM-DD HH:MM:SS`, §6.1)
/// into the ISO-8601 UTC form the §10 record envelope carries; ISO inputs
/// pass through unchanged.
fn sqlite_dt_to_iso(value: &str) -> String {
    let mut out = value.replace(' ', "T");
    if !out.ends_with('Z') {
        out.push('Z');
    }
    out
}

/// Non-empty string column accessor: strings pass, numbers stringify.
fn col_req(cols: &Value, key: &str) -> Option<String> {
    match cols.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// Optional string column accessor: `null`/missing/empty become `None`.
fn col_opt(cols: &Value, key: &str) -> Option<String> {
    match cols.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// Builds the §10 typed activity record for one claimed row, or `None` when
/// the row is an invalid record (dropped, never failing the batch).
pub(crate) fn build_activity_record(
    row: &ClaimedRow,
    client: &ClientBlock,
    timestamp: &str,
) -> Option<Value> {
    let cols = &row.columns;
    let created = sqlite_dt_to_iso(&row.created_at);
    let ctx = RecordContext::new(client, timestamp, &created);
    match row.table {
        EventTable::DnsActivity => Some(web_activity_record(
            &ctx,
            WebActivityFields {
                domain: col_req(cols, "domain")?,
                process_id: col_opt(cols, "process_id"),
                process_name: col_opt(cols, "process_name").unwrap_or_else(|| "unknown".into()),
                ip: col_opt(cols, "ip"),
                resolution_type: col_req(cols, "resolution_type")?,
                connection_type: col_opt(cols, "connection_type"),
                resolution_datacenter: col_opt(cols, "resolution_datacenter"),
                resolution_time_ms: col_opt(cols, "resolution_time_ms"),
            },
        )),
        EventTable::Logins => Some(login_activity_record(
            &ctx,
            LoginActivityFields {
                login_at: col_req(cols, "login_at").or_else(|| col_req(cols, "timestamp"))?,
                logout_at: col_opt(cols, "logout_at"),
                system_user_id: col_opt(cols, "system_user_id"),
                system_user_name: col_opt(cols, "system_user_name"),
            },
        )),
        EventTable::Circumventions => Some(circumvention_record(
            &ctx,
            CircumventionFields {
                interruption_type: col_req(cols, "interruption_type")?,
                app_name: col_req(cols, "app_name")?,
                app_window_title: col_opt(cols, "app_window_title"),
                device_id: col_req(cols, "device_id")?,
                timezone_offset: col_opt(cols, "timezone_offset").unwrap_or_default(),
            },
        )),
        EventTable::SwitchUsers => Some(switch_user_activity_record(
            &ctx,
            SwitchUserFields {
                switch_from_username: col_req(cols, "switch_user_from")?,
                switch_to_username: col_req(cols, "switch_user_to")?,
                device_name: col_opt(cols, "device_name"),
                device_id: col_req(cols, "device_id")?,
            },
        )),
        EventTable::Telemetry => None, // telemetry has its own route
    }
}

/// Builds the one-shot `installActivityRecord` (§10/§15).
pub(crate) fn build_install_record(
    device_uuid: &str,
    platform_version: &str,
    client: &ClientBlock,
    timestamp: &str,
    created_iso: &str,
) -> Value {
    let ctx = RecordContext::new(client, timestamp, created_iso);
    install_activity_record(
        &ctx,
        InstallFields {
            device_uuid: device_uuid.to_string(),
            platform_version: platform_version.to_string(),
            architecture: local_architecture().to_string(),
        },
    )
}

/// Serializes one queued metrics bucket into the `POST /v1/metrics` array
/// (evidence `upload-protocol.md` §5: `username`, `metric_name`, `bucket_id`,
/// `tags`, `fields`, `utc_timestamp`, `bucket_size`, `bucket_current`).
pub(crate) fn metric_row_value(row: &MetricRow) -> Value {
    json!({
        "username": row.username,
        "metric_name": row.metric_name,
        "bucket_id": serde_json::to_value(&row.bucket_id).unwrap_or(Value::Array(Vec::new())),
        "tags": serde_json::to_value(&row.tags).unwrap_or(Value::Array(Vec::new())),
        "fields": serde_json::to_value(&row.fields).unwrap_or(Value::Array(Vec::new())),
        "utc_timestamp": row.utc_timestamp,
        "bucket_size": row.bucket_size,
        "bucket_current": row.bucket_current,
    })
}

/// Reads the signed-in user's Bearer device token (§10) from the per-uid
/// settings DBs under `state_dir` (`api_credentials`, §6.2 — tokens only).
///
/// The uploader knows the CE account username (from the policy snapshot) but
/// not the uid; the daemon stores credentials in `<state_dir>/<uid>/settings.db`
/// keyed by username, so every numeric uid directory that actually holds a
/// settings DB is probed (existing files only — nothing is created).
pub(crate) fn read_device_token(state_dir: &Path, username: &str) -> Option<String> {
    let entries = std::fs::read_dir(state_dir).ok()?;
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let db_path = dir.join("settings.db");
        if !db_path.exists() {
            continue;
        }
        let key_path = dir.join("settings.key");
        let Ok(db) = SettingsDb::open(&db_path, &key_path) else {
            continue;
        };
        match db.get_api_credentials(username) {
            Ok(Some(credentials)) if !credentials.device_token.is_empty() => {
                return Some(credentials.device_token);
            }
            _ => continue,
        }
    }
    None
}

/// Reads `/etc/os-release` `VERSION_ID` for the §10 `client.platformVersion`
/// block (`"unknown"` fallback — never fails the upload path).
pub(crate) fn platform_version() -> String {
    const FALLBACK: &str = "unknown";
    let Ok(text) = std::fs::read_to_string("/etc/os-release") else {
        return FALLBACK.to_string();
    };
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("VERSION_ID=") {
            let value = value.trim().trim_matches('"');
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    FALLBACK.to_string()
}

/// Parses the `/v1/status/time` response (§10 clock anchor): accepts a bare
/// JSON number, an ISO-8601 UTC string, or an object carrying `server_time`
/// / `time` in either form.
pub(crate) fn parse_server_time(body: &[u8]) -> Option<i64> {
    fn from_value(value: &Value) -> Option<i64> {
        match value {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => parse_iso8601(text),
            _ => None,
        }
    }
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        return match &value {
            Value::Object(map) => map
                .get("server_time")
                .or_else(|| map.get("time"))
                .and_then(from_value),
            _ => from_value(&value),
        };
    }
    // A bare ISO-8601 timestamp is not valid JSON on its own; parse it
    // directly (the doc'd third response shape).
    parse_iso8601(std::str::from_utf8(body).ok()?.trim())
}

/// RFC 3339 / ISO-8601 UTC → unix seconds.
fn parse_iso8601(text: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(|dt| dt.unix_timestamp())
}

// ---------------------------------------------------------------------------
// Throttle state (§10: persisted `upload.resume_not_before`)
// ---------------------------------------------------------------------------

/// Persisted uploader state (§10: `ApiTelemetryResumeTime` analog — a resume
/// timestamp that survives restarts).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct UploaderState {
    /// No network exchange before this unix time (server-requested throttle).
    #[serde(default)]
    pub(crate) resume_not_before: i64,
}

/// How long the server asked us to back off (Retry-After header, response
/// body fields, or the default).
pub(crate) fn throttle_seconds(body: &[u8], retry_after: Option<u64>) -> i64 {
    if let Some(seconds) = retry_after {
        return seconds as i64;
    }
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        if let Some(seconds) = value.get("retry_after_sec").and_then(Value::as_i64) {
            return seconds.max(0);
        }
        if let Some(resume) = value.get("resume_not_before").and_then(Value::as_i64) {
            return (resume - system_unix()).max(0);
        }
    }
    DEFAULT_THROTTLE_FALLBACK_SECS
}

/// Persists the throttle state atomically (temp file + rename) to
/// `<state_dir>/uploader-state.json` (§10).
fn persist_state(state: &UploaderState, state_path: &Path) {
    if let Some(parent) = state_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(text) = serde_json::to_string(state) else {
        return;
    };
    let tmp = state_path.with_extension("json.tmp");
    if std::fs::write(&tmp, text).is_ok() {
        if let Err(err) = std::fs::rename(&tmp, state_path) {
            error!("persisting uploader state failed: {err}");
        }
    }
}

// ---------------------------------------------------------------------------
// The uploader engine
// ---------------------------------------------------------------------------

/// Outcome of one flush cycle.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CycleOutcome {
    /// Rows acked as `sent` this cycle.
    pub(crate) rows: usize,
    /// Whether any rows were claimed (drives the `flush_now` drain loop even
    /// when every claimed row turned out invalid and was dropped).
    pub(crate) had_work: bool,
    /// A transport error or 5xx stopped the cycle (rows stay claimable).
    pub(crate) network_error: bool,
    /// A local DB error stopped the cycle.
    pub(crate) local_error: bool,
    /// The server requested throttling; the state file was updated.
    pub(crate) throttled: bool,
}

impl CycleOutcome {
    /// Whether the cycle stopped early (nothing more can move right now).
    fn stop(&self) -> bool {
        self.network_error || self.local_error || self.throttled
    }
}

/// Send classification of one API exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    /// 2xx — the batch was accepted.
    Accepted,
    /// 4xx other than 429/503 — the payload was rejected; the batch is
    /// dropped (invalid records never fail a batch, §6.1).
    Rejected,
    /// 429/503 — the server asked us to back off; persisted to the state
    /// file and the cycle stops immediately.
    Throttled,
    /// Transport failure or 5xx — retry later; claimed rows stay `sending`
    /// and are reaped back to `queued` after 5 minutes (§6.1).
    Failed,
}

/// A command from [`NetServices::flush_now`](crate::NetServices::flush_now):
/// drain everything pending, reporting progress row by row. The reply
/// channel is a plain `std::sync::mpsc` sender so the (synchronous)
/// `flush_now` caller can block on it with a deadline.
pub(crate) struct FlushCmd {
    /// Progress channel back to the `flush_now` caller.
    pub(crate) reply: std::sync::mpsc::Sender<FlushEvent>,
}

/// Progress events streamed to a `flush_now` caller.
pub(crate) enum FlushEvent {
    /// A batch of `n` rows was acked as sent.
    Rows(usize),
    /// The drain finished (fully flushed, throttled, or stuck — partial
    /// flushes still return ok, §5 0x69 semantics).
    Done,
}

/// The §10 uploader engine. One instance lives inside
/// [`crate::NetServices::run`]; `flush_now` reaches it through the command
/// channel.
pub(crate) struct Uploader {
    cfg: Arc<LustlessConfig>,
    outbox: Arc<Mutex<Outbox>>,
    clock: Arc<RwLock<ClockAnchor>>,
    policy: Arc<dyn PolicyProvider>,
    http: Arc<dyn Http>,
    audit: Arc<AuditLog>,
    state_dir: PathBuf,
    state_path: PathBuf,
    state: UploaderState,
    /// Min-age gate of the claim (§6.1: 30 s).
    min_age_secs: i64,
    /// Stale-`sending` threshold of the reaper (§6.1: 5 min).
    stale_secs: i64,
    /// Latched liveness: `GET /v1/status/ping` succeeded at least once since
    /// the last transport failure (pre-flight for the send queues).
    pinged: bool,
    /// Hourly clock-anchor bookkeeping.
    last_anchor_sync: Option<tokio::time::Instant>,
    /// Cached `(username, device_token)`; re-read whenever the signed-in
    /// username changes or the server answers 401.
    token_cache: Option<(String, String)>,
    /// Cached `/etc/os-release` `VERSION_ID`.
    platform_version: String,
    /// The one-shot install report has been delivered.
    install_reported: bool,
}

impl Uploader {
    /// Builds the engine over the shared daemon state.
    pub(crate) fn new(
        cfg: Arc<LustlessConfig>,
        outbox: Arc<Mutex<Outbox>>,
        clock: Arc<RwLock<ClockAnchor>>,
        policy: Arc<dyn PolicyProvider>,
        http: Arc<dyn Http>,
        audit: Arc<AuditLog>,
    ) -> Self {
        let state_dir = PathBuf::from(cfg.daemon.state_dir.as_str());
        let state_path = state_dir.join(UPLOADER_STATE_FILE);
        let state = std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|text| serde_json::from_slice::<UploaderState>(text.as_bytes()).ok())
            .unwrap_or_default();
        let install_reported = lock_outbox(&outbox)
            .install_metadata(INSTALL_REPORTED_KEY)
            .map(|value| value.is_some())
            .unwrap_or(false);
        Uploader {
            platform_version: platform_version(),
            state_dir,
            state_path,
            state,
            min_age_secs: DEFAULT_MIN_AGE_SECS,
            stale_secs: STALE_SENDING_SECS,
            pinged: false,
            last_anchor_sync: None,
            token_cache: None,
            install_reported,
            cfg,
            outbox,
            clock,
            policy,
            http,
            audit,
        }
    }

    /// Tuning hook for the §6.1 timing gates (defaults 30 s min-age / 5 min
    /// stale); used by the unit tests to avoid real-time waits.
    pub(crate) fn with_tuning(mut self, min_age_secs: i64, stale_secs: i64) -> Self {
        self.min_age_secs = min_age_secs;
        self.stale_secs = stale_secs;
        self
    }

    // -- loop ---------------------------------------------------------------

    /// The uploader loop: flush poll every `retry_sec`, local bookkeeping
    /// heartbeat on `heartbeat_sec`/`retry_sec`, `flush_now` commands served
    /// with priority. Runs until the command channel closes (all
    /// `NetServices` handles dropped) or the future is cancelled.
    pub(crate) async fn run_loop(mut self, mut commands: Option<UnboundedReceiver<FlushCmd>>) {
        let retry = Duration::from_secs(self.cfg.upload.retry_sec.max(1));
        let heartbeat = Duration::from_secs(self.cfg.upload.heartbeat_sec.max(1));
        let mut next_flush = tokio::time::Instant::now();
        let mut next_heartbeat = tokio::time::Instant::now() + heartbeat;
        loop {
            let wake = next_flush.min(next_heartbeat);
            if let Some(commands) = commands.as_mut() {
                tokio::select! {
                    command = commands.recv() => {
                        match command {
                            Some(command) => {
                                self.run_flush_report(Some(&command.reply)).await;
                            }
                            None => return,
                        }
                        continue;
                    }
                    _ = tokio::time::sleep_until(wake) => {}
                }
            } else {
                tokio::time::sleep_until(wake).await;
            }
            let now = tokio::time::Instant::now();
            if now >= next_heartbeat {
                // Local bookkeeping only — zero packets at tick time (§10).
                if self.heartbeat() {
                    next_heartbeat = now + heartbeat;
                } else {
                    next_heartbeat = now + retry;
                }
            }
            if now >= next_flush {
                let outcome = self.flush_cycle().await;
                debug!(
                    rows = outcome.rows,
                    throttled = outcome.throttled,
                    network_error = outcome.network_error,
                    "uploader flush cycle finished"
                );
                // The flush poll cadence is independent of the heartbeat:
                // an empty claim is one indexed SELECT per table, so a 60 s
                // poll stays cheap and keeps uploads responsive.
                next_flush = now + retry;
            }
        }
    }

    /// Serves one `flush_now` command: claims + sends until nothing is left,
    /// the server throttles, or the network fails — streaming row counts.
    pub(crate) async fn run_flush_report(
        &mut self,
        reply: Option<&std::sync::mpsc::Sender<FlushEvent>>,
    ) {
        loop {
            let outcome = self.flush_cycle().await;
            if outcome.rows > 0 {
                if let Some(reply) = reply {
                    let _ = reply.send(FlushEvent::Rows(outcome.rows));
                }
            }
            if outcome.stop() || (outcome.rows == 0 && !outcome.had_work) {
                break;
            }
        }
        if let Some(reply) = reply {
            let _ = reply.send(FlushEvent::Done);
        }
    }

    /// One §10 flush cycle: reap → throttle gate → clock anchor → activity
    /// (per-user batches) → metrics → telemetry → logs → install report.
    pub(crate) async fn flush_cycle(&mut self) -> CycleOutcome {
        let mut outcome = CycleOutcome::default();

        // Crash/retry recovery: stale `sending` claims go back to `queued`
        // (§6.1; 5 min). Purely local.
        if let Err(err) = lock_outbox(&self.outbox).reap_stale_sending(self.stale_secs) {
            warn!("outbox reap of stale sending rows failed: {err}");
        }

        // Server-requested throttling gate (§10): no exchange at all while
        // the persisted `resume_not_before` is in the future.
        if self.state.resume_not_before > read_clock(&self.clock).now_unix() {
            outcome.throttled = true;
            return outcome;
        }

        // Hourly clock anchor (§10): all event timestamps are rendered
        // through the `(server_time, local_ticks)` anchor; a failed sync
        // falls back to the system clock.
        self.maybe_refresh_anchor().await;

        let batch = self.cfg.upload.batch_size.max(1);

        // -- activity log, per-user batches ---------------------------------
        for table in ACTIVITY_TABLES {
            let claimed =
                match lock_outbox(&self.outbox).claim_batch(table, batch, self.min_age_secs) {
                    Ok(rows) => rows,
                    Err(err) => {
                        warn!("claim from {} failed: {err}", table.as_str());
                        outcome.local_error = true;
                        return outcome;
                    }
                };
            if claimed.is_empty() {
                continue;
            }
            outcome.had_work = true;

            // `upload.circumvention_records = false` (§7): the only
            // screen-adjacent record type is dropped locally, not uploaded.
            if table == EventTable::Circumventions && !self.cfg.upload.circumvention_records {
                let ids: Vec<i64> = claimed.iter().map(|row| row.id).collect();
                if let Err(err) = lock_outbox(&self.outbox).drop_invalid(table, &ids) {
                    warn!("dropping circumvention rows failed: {err}");
                }
                continue;
            }

            // Per-user batching (§10).
            let mut groups: BTreeMap<String, Vec<ClaimedRow>> = BTreeMap::new();
            let mut orphan_ids = Vec::new();
            for row in claimed {
                match row.username.clone() {
                    Some(username) if !username.trim().is_empty() => {
                        groups.entry(username).or_default().push(row);
                    }
                    _ => orphan_ids.push(row.id),
                }
            }
            if !orphan_ids.is_empty() {
                let _ = lock_outbox(&self.outbox).drop_invalid(table, &orphan_ids);
            }

            for (username, rows) in groups {
                for chunk in rows.chunks(batch as usize) {
                    let timestamp = read_clock(&self.clock).now_iso8601();
                    let client = ClientBlock::local(&self.platform_version, LUSTLESS_VERSION);
                    let mut records = Vec::new();
                    let mut ok_ids = Vec::new();
                    let mut bad_ids = Vec::new();
                    for row in chunk {
                        match build_activity_record(row, &client, &timestamp) {
                            Some(record) => {
                                records.push(record);
                                ok_ids.push(row.id);
                            }
                            None => bad_ids.push(row.id),
                        }
                    }
                    // Invalid records are dropped, never failing the batch
                    // (§6.1; evidence `removeInvalidRecords`).
                    if !bad_ids.is_empty() {
                        if let Err(err) = lock_outbox(&self.outbox).drop_invalid(table, &bad_ids) {
                            warn!("dropping invalid rows failed: {err}");
                        }
                    }
                    if records.is_empty() {
                        continue;
                    }
                    let url = format!(
                        "{}/v2/user/{}/report/activity_log.json",
                        base_url(&self.cfg),
                        path_segment(&username)
                    );
                    let body = json!({ "records": records }).to_string();
                    match self.send("activity_log", ApiMethod::Post, &url, Some(body)).await {
                        SendOutcome::Accepted => {
                            match lock_outbox(&self.outbox).mark_sent(table, &ok_ids) {
                                Ok(count) => outcome.rows += count,
                                Err(err) => {
                                    warn!("mark_sent failed: {err}");
                                    outcome.local_error = true;
                                    return outcome;
                                }
                            }
                        }
                        SendOutcome::Rejected => {
                            let _ = lock_outbox(&self.outbox).drop_invalid(table, &ok_ids);
                        }
                        SendOutcome::Throttled => {
                            outcome.throttled = true;
                            return outcome;
                        }
                        SendOutcome::Failed => {
                            outcome.network_error = true;
                            return outcome;
                        }
                    }
                }
            }
        }

        // -- metrics (POST /v1/metrics: JSON array of buckets) --------------
        let queued_metrics = {
            let mut outbox = lock_outbox(&self.outbox);
            MetricSink::new(&mut outbox).queued(batch)
        };
        let queued_metrics = match queued_metrics {
            Ok(rows) => rows,
            Err(err) => {
                warn!("reading queued metrics failed: {err}");
                outcome.local_error = true;
                return outcome;
            }
        };
        if !queued_metrics.is_empty() {
            outcome.had_work = true;
            let ids: Vec<i64> = queued_metrics.iter().map(|row| row.id).collect();
            let body =
                Value::Array(queued_metrics.iter().map(metric_row_value).collect()).to_string();
            let url = format!("{}/v1/metrics", base_url(&self.cfg));
            match self.send("metrics", ApiMethod::Post, &url, Some(body)).await {
                SendOutcome::Accepted | SendOutcome::Rejected => {
                    // A deterministic 4xx rejection acks the buckets out of
                    // the queue as well: `metrics` has no delete path (§6.1)
                    // and a permanently-rejected bucket would otherwise retry
                    // forever. Transport/5xx failures never reach this arm.
                    let marked = {
                        let mut outbox = lock_outbox(&self.outbox);
                        MetricSink::new(&mut outbox).mark_sent(&ids)
                    };
                    match marked {
                        Ok(count) => outcome.rows += count,
                        Err(err) => {
                            warn!("metrics mark_sent failed: {err}");
                            outcome.local_error = true;
                            return outcome;
                        }
                    }
                }
                SendOutcome::Throttled => {
                    outcome.throttled = true;
                    return outcome;
                }
                SendOutcome::Failed => {
                    outcome.network_error = true;
                    return outcome;
                }
            }
        }

        // -- telemetry (POST /v1/telemetry/store) ---------------------------
        let claimed = match lock_outbox(&self.outbox).claim_batch(
            EventTable::Telemetry,
            batch,
            self.min_age_secs,
        ) {
            Ok(rows) => rows,
            Err(err) => {
                warn!("claim from telemetry failed: {err}");
                outcome.local_error = true;
                return outcome;
            }
        };
        if !claimed.is_empty() {
            outcome.had_work = true;
            let mut records = Vec::new();
            let mut ok_ids = Vec::new();
            let mut bad_ids = Vec::new();
            for row in &claimed {
                if col_req(&row.columns, "name").is_some() {
                    records.push(json!({
                        "client_type": row.columns.get("client_type").cloned().unwrap_or(Value::Null),
                        "device_name": row.columns.get("device_name").cloned().unwrap_or(Value::Null),
                        "name": row.columns.get("name").cloned().unwrap_or(Value::Null),
                        "value": row.columns.get("value").cloned().unwrap_or(Value::Null),
                        "utc_timestamp": row.columns.get("utc_timestamp").cloned().unwrap_or(Value::Null),
                    }));
                    ok_ids.push(row.id);
                } else {
                    bad_ids.push(row.id);
                }
            }
            if !bad_ids.is_empty() {
                let _ = lock_outbox(&self.outbox).drop_invalid(EventTable::Telemetry, &bad_ids);
            }
            if !records.is_empty() {
                let url = format!("{}/v1/telemetry/store", base_url(&self.cfg));
                let body = Value::Array(records).to_string();
                match self.send("telemetry", ApiMethod::Post, &url, Some(body)).await {
                    SendOutcome::Accepted => {
                        match lock_outbox(&self.outbox).mark_sent(EventTable::Telemetry, &ok_ids) {
                            Ok(count) => outcome.rows += count,
                            Err(err) => {
                                warn!("telemetry mark_sent failed: {err}");
                                outcome.local_error = true;
                                return outcome;
                            }
                        }
                    }
                    SendOutcome::Rejected => {
                        let _ =
                            lock_outbox(&self.outbox).drop_invalid(EventTable::Telemetry, &ok_ids);
                    }
                    SendOutcome::Throttled => {
                        outcome.throttled = true;
                        return outcome;
                    }
                    SendOutcome::Failed => {
                        outcome.network_error = true;
                        return outcome;
                    }
                }
            }
        }

        // -- support event log (POST /v1/logs/store, debug toggle) ----------
        if self.cfg.upload.logs_store {
            let drained = self.audit.drain();
            if !drained.is_empty() {
                outcome.had_work = true;
                let url = format!("{}/v1/logs/store", base_url(&self.cfg));
                let body = Value::Array(drained.clone()).to_string();
                match self.send("logs", ApiMethod::Post, &url, Some(body)).await {
                    SendOutcome::Accepted | SendOutcome::Rejected => {}
                    SendOutcome::Throttled => {
                        self.audit.restore_front(drained);
                        outcome.throttled = true;
                        return outcome;
                    }
                    SendOutcome::Failed => {
                        self.audit.restore_front(drained);
                        outcome.network_error = true;
                        return outcome;
                    }
                }
            }
        }

        // -- one-shot install report (§10/§15) ------------------------------
        if !self.install_reported {
            let username = self.policy.snapshot().username;
            if !username.trim().is_empty() {
                outcome.had_work = true;
                let timestamp = read_clock(&self.clock).now_iso8601();
                let client = ClientBlock::local(&self.platform_version, LUSTLESS_VERSION);
                let uuid = device_uuid(&self.outbox);
                let record = build_install_record(
                    &uuid,
                    &self.platform_version,
                    &client,
                    &timestamp,
                    &timestamp,
                );
                let url = format!(
                    "{}/v2/user/{}/report/activity_log.json",
                    base_url(&self.cfg),
                    path_segment(&username)
                );
                let body = json!({ "records": [record] }).to_string();
                match self.send("activity_log", ApiMethod::Post, &url, Some(body)).await {
                    SendOutcome::Accepted | SendOutcome::Rejected => {
                        self.install_reported = true;
                        let _ = lock_outbox(&self.outbox)
                            .set_install_metadata(INSTALL_REPORTED_KEY, &timestamp);
                    }
                    SendOutcome::Throttled => {
                        outcome.throttled = true;
                        return outcome;
                    }
                    SendOutcome::Failed => {
                        outcome.network_error = true;
                        return outcome;
                    }
                }
            }
        }

        outcome
    }

    /// The purely local bookkeeping heartbeat (§10: 600 s steady / 60 s
    /// retry, zero packets): rolls aged metrics buckets, reaps stale claims
    /// and stamps `last_heartbeat_at`. Returns whether every step worked.
    pub(crate) fn heartbeat(&mut self) -> bool {
        let mut ok = true;
        let stamp = read_clock(&self.clock).now_iso8601();
        let mut outbox = lock_outbox(&self.outbox);
        if let Err(err) = MetricSink::new(&mut outbox).roll_ready() {
            warn!("heartbeat: rolling metric buckets failed: {err}");
            ok = false;
        }
        if let Err(err) = outbox.reap_stale_sending(self.stale_secs) {
            warn!("heartbeat: reap failed: {err}");
            ok = false;
        }
        if let Err(err) = outbox.set_install_metadata(HEARTBEAT_STAMP_KEY, &stamp) {
            warn!("heartbeat: stamping {HEARTBEAT_STAMP_KEY} failed: {err}");
            ok = false;
        }
        ok
    }

    // -- HTTP plumbing ------------------------------------------------------

    /// Sends one data exchange, honoring the liveness pre-flight and the
    /// §10 throttle/`resume_not_before` rules.
    async fn send(
        &mut self,
        route: &str,
        method: ApiMethod,
        url: &str,
        body: Option<String>,
    ) -> SendOutcome {
        // §10 Bearer auth from `api_credentials` (§6.2). Without a stored
        // token no request is sent at all — and rows are never dropped.
        let Some(bearer) = self.device_token() else {
            debug!("no device token for the signed-in user; skipping upload network call");
            return SendOutcome::Failed;
        };
        if !self.ensure_liveness().await {
            return SendOutcome::Failed;
        }
        let result = tracked_exchange(
            self.http.as_ref(),
            &self.outbox,
            &self.clock,
            self.policy.as_ref(),
            &self.audit,
            "uploader",
            route,
            method,
            url,
            body,
            Some(bearer),
        )
        .await;
        match result {
            ApiResult::Response {
                status,
                body,
                retry_after,
            } => {
                if status == 401 {
                    // The device token was revoked/rotated server-side —
                    // drop the cache so the next attempt re-reads
                    // `api_credentials`.
                    self.token_cache = None;
                }
                match status {
                    200..=299 => SendOutcome::Accepted,
                    429 | 503 => {
                        self.apply_throttle(throttle_seconds(&body, retry_after));
                        SendOutcome::Throttled
                    }
                    400..=499 => SendOutcome::Rejected,
                    _ => SendOutcome::Failed,
                }
            }
            ApiResult::Transport(_) => SendOutcome::Failed,
        }
    }

    /// `GET /v1/status/ping` liveness pre-flight for the send queues
    /// (evidence `upload-protocol.md` §3: ping registered as the liveness
    /// callback). Latches until the next transport failure.
    async fn ensure_liveness(&mut self) -> bool {
        if self.pinged {
            return true;
        }
        let Some(bearer) = self.device_token() else {
            return false;
        };
        let url = format!("{}/v1/status/ping", base_url(&self.cfg));
        let result = tracked_exchange(
            self.http.as_ref(),
            &self.outbox,
            &self.clock,
            self.policy.as_ref(),
            &self.audit,
            "uploader",
            "status/ping",
            ApiMethod::Get,
            &url,
            None,
            Some(bearer),
        )
        .await;
        match result {
            ApiResult::Response { status, .. } => {
                self.pinged = (200..300).contains(&status);
                self.pinged
            }
            ApiResult::Transport(_) => false,
        }
    }

    /// Hourly `(server_time, local_ticks)` anchor refresh (§10).
    async fn maybe_refresh_anchor(&mut self) {
        let due = match self.last_anchor_sync {
            None => true,
            Some(at) => at.elapsed() >= Duration::from_secs(ANCHOR_REFRESH_SECS as u64),
        };
        if !due {
            return;
        }
        // Without credentials there is nothing to sync against; keep the
        // current anchor (and retry next cycle rather than burning the
        // hourly slot on a signed-out machine).
        let Some(bearer) = self.device_token() else {
            return;
        };
        self.last_anchor_sync = Some(tokio::time::Instant::now());
        if !self.ensure_liveness().await {
            write_clock(&self.clock).fall_back_to_system_time();
            return;
        }
        let url = format!("{}/v1/status/time", base_url(&self.cfg));
        let result = tracked_exchange(
            self.http.as_ref(),
            &self.outbox,
            &self.clock,
            self.policy.as_ref(),
            &self.audit,
            "uploader",
            "status/time",
            ApiMethod::Get,
            &url,
            None,
            Some(bearer),
        )
        .await;
        match result {
            ApiResult::Response { status, body, .. } if (200..300).contains(&status) => {
                match parse_server_time(&body) {
                    Some(server_time) => {
                        debug!(server_time, "clock anchor refreshed from server time");
                        write_clock(&self.clock).refresh_from_server_time(server_time);
                    }
                    None => {
                        warn!("unparseable /v1/status/time response; falling back to system time");
                        write_clock(&self.clock).fall_back_to_system_time();
                    }
                }
            }
            _ => {
                warn!("server time sync failed; falling back to system time");
                write_clock(&self.clock).fall_back_to_system_time();
            }
        }
    }

    /// Applies a server-requested backoff: updates the in-memory state and
    /// persists `resume_not_before` to `<state_dir>/uploader-state.json`
    /// (§10).
    fn apply_throttle(&mut self, seconds: i64) {
        let resume = read_clock(&self.clock).now_unix() + seconds.max(0);
        if resume > self.state.resume_not_before {
            self.state.resume_not_before = resume;
            persist_state(&self.state, &self.state_path);
        }
    }

    /// Reads the §6.2 Bearer device token for the signed-in user, cached per
    /// username (re-read after sign-out/rotation).
    fn device_token(&mut self) -> Option<String> {
        let username = self.policy.snapshot().username;
        if username.trim().is_empty() {
            return None;
        }
        if let Some((cached_user, token)) = &self.token_cache {
            if *cached_user == username {
                return Some(token.clone());
            }
        }
        match read_device_token(&self.state_dir, &username) {
            Some(token) => {
                self.token_cache = Some((username, token.clone()));
                Some(token)
            }
            None => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (CONTRACTS §16: deterministic, isolated, local mock HTTP only)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_http {
    use super::*;
    use parking_lot::Mutex as ParkingMutex;

    /// Scripted HTTP layer for the state-machine tests.
    pub(crate) struct MockHttp {
        handler: Arc<dyn Fn(ApiRequest) -> ApiResponse + Send + Sync>,
        pub(crate) calls: ParkingMutex<Vec<ApiRequest>>,
    }

    impl MockHttp {
        pub(crate) fn new<F>(handler: F) -> Self
        where
            F: Fn(ApiRequest) -> ApiResponse + Send + Sync + 'static,
        {
            MockHttp {
                handler: Arc::new(handler),
                calls: ParkingMutex::new(Vec::new()),
            }
        }

        pub(crate) fn ok_json(body: &str) -> ApiResponse {
            ApiResponse {
                status: 200,
                body: body.as_bytes().to_vec(),
                retry_after: None,
            }
        }

        /// URLs called so far.
        pub(crate) fn urls(&self) -> Vec<String> {
            self.calls
                .lock()
                .iter()
                .map(|request| request.url.clone())
                .collect()
        }
    }

    impl Http for MockHttp {
        fn execute(
            &self,
            request: ApiRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ApiResponse, String>> + Send + 'static>> {
            self.calls.lock().push(request.clone());
            let handler = Arc::clone(&self.handler);
            Box::pin(async move { Ok(handler(request)) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_http::MockHttp;
    use super::*;
    use crate::test_mocks::{temp_dir, MockPolicy};
    use lustless_core::db::{CircumventionRow, DnsActivityRow, LoginRow, TelemetryRow};
    use lustless_core::settings::ApiCredentials;

    struct Harness {
        dir: PathBuf,
        cfg: Arc<LustlessConfig>,
        outbox: Arc<Mutex<Outbox>>,
        clock: Arc<RwLock<ClockAnchor>>,
        policy: Arc<dyn PolicyProvider>,
        audit: Arc<AuditLog>,
        http: Arc<MockHttp>,
    }

    impl Harness {
        fn new(name: &str) -> Self {
            let dir = temp_dir(name);
            let outbox = Arc::new(Mutex::new(Outbox::open(&dir.join("outbox.db")).unwrap()));
            // §6.2: the signed-in user's Bearer token lives in the per-uid
            // settings DB, exactly as the daemon writes it.
            let uid_dir = dir.join("1000");
            std::fs::create_dir_all(&uid_dir).unwrap();
            let mut settings =
                SettingsDb::open(&uid_dir.join("settings.db"), &uid_dir.join("settings.key"))
                    .unwrap();
            settings
                .set_api_credentials(&ApiCredentials {
                    username: "alice".to_string(),
                    device_token: "device-token-alice".to_string(),
                    refresh_token: None,
                })
                .unwrap();
            let cfg = Arc::new(LustlessConfig {
                daemon: lustless_core::config::DaemonConfig {
                    state_dir: dir.to_string_lossy().to_string(),
                    dashboard_enabled: false,
                    ..Default::default()
                },
                upload: lustless_core::config::UploadConfig {
                    base_url: "https://api.test".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            });
            let http = Arc::new(MockHttp::new(|_| MockHttp::ok_json("{}")));
            Harness {
                audit: Arc::new(AuditLog::default()),
                dir,
                cfg,
                outbox,
                clock: Arc::new(RwLock::new(ClockAnchor::system())),
                policy: Arc::new(MockPolicy::with_username("alice")),
                http,
            }
        }

        fn uploader(&self) -> Uploader {
            Uploader::new(
                self.cfg.clone(),
                self.outbox.clone(),
                self.clock.clone(),
                self.policy.clone(),
                self.http.clone(),
                self.audit.clone(),
            )
            .with_tuning(0, STALE_SENDING_SECS)
        }

        fn set_cfg(&self, f: impl FnOnce(&mut LustlessConfig)) -> Arc<LustlessConfig> {
            let mut cfg = (*self.cfg).clone();
            f(&mut cfg);
            Arc::new(cfg)
        }

        fn insert_dns(&self, domain: &str) -> i64 {
            let mut outbox = lock_outbox(&self.outbox);
            outbox
                .insert_dns_activity(&DnsActivityRow {
                    username: "alice".to_string(),
                    domain: domain.to_string(),
                    process_id: Some("4321".to_string()),
                    process_name: "browser".to_string(),
                    datetime_created: "2026-10-11T10:00:00Z".to_string(),
                    ip: Some("192.0.2.10".to_string()),
                    resolution_type: "UnrestrictedFiltered".to_string(),
                    connection_type: Some("DoH".to_string()),
                    resolution_datacenter: Some("dc1".to_string()),
                    resolution_time_ms: Some("12".to_string()),
                })
                .unwrap()
        }

        fn insert_login(&self) -> i64 {
            let mut outbox = lock_outbox(&self.outbox);
            outbox
                .insert_login(&LoginRow {
                    username: "alice".to_string(),
                    system_user_id: Some("1000".to_string()),
                    system_user_name: Some("alice-os".to_string()),
                    timestamp: "2026-10-11T10:00:00Z".to_string(),
                    login_at: "2026-10-11T09:59:00Z".to_string(),
                    logout_at: None,
                })
                .unwrap()
        }

        fn insert_circumvention(&self) -> i64 {
            let mut outbox = lock_outbox(&self.outbox);
            outbox
                .insert_circumvention(&CircumventionRow {
                    username: "alice".to_string(),
                    interruption_type: "restricted_window".to_string(),
                    app_name: "secret-app".to_string(),
                    app_window_title: Some("title".to_string()),
                    device_id: ids::new_device_id(),
                    timestamp: "2026-10-11T10:00:00Z".to_string(),
                    timezone_offset: "+00:00".to_string(),
                })
                .unwrap()
        }

        fn insert_telemetry(&self, name: &str) -> i64 {
            let mut outbox = lock_outbox(&self.outbox);
            outbox
                .insert_telemetry(&TelemetryRow {
                    client_type: "daemon".to_string(),
                    device_name: "host".to_string(),
                    name: name.to_string(),
                    value: "1".to_string(),
                    utc_timestamp: "2026-10-11T10:00:00Z".to_string(),
                })
                .unwrap()
        }

        fn dns_rows_left(&self) -> usize {
            lock_outbox(&self.outbox)
                .dns_activity_readback(500)
                .unwrap()
                .len()
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn activity_posts(http: &MockHttp) -> Vec<ApiRequest> {
        http.calls
            .lock()
            .iter()
            .filter(|request| request.url.contains("activity_log.json"))
            .cloned()
            .collect()
    }

    fn posts_with(http: &MockHttp, needle: &str) -> Vec<ApiRequest> {
        activity_posts(http)
            .into_iter()
            .filter(|request| {
                request
                    .body
                    .as_ref()
                    .map(|body| body.contains(needle))
                    .unwrap_or(false)
            })
            .collect()
    }

    #[test]
    fn flush_cycle_claims_sends_and_acks() {
        let harness = Harness::new("flush-claims");
        harness.insert_dns("example.org");
        harness.insert_dns("example.com");
        harness.insert_login();
        let mut uploader = harness.uploader();
        let runtime = runtime();

        let outcome = runtime.block_on(uploader.flush_cycle());
        // 2 web + 1 login row acked (the install report does not count).
        assert_eq!(outcome.rows, 3);
        assert!(outcome.had_work);
        assert!(!outcome.stop());

        // Per-user batching: the two dns rows travel in ONE request; the
        // login row in another; plus the one-shot install report.
        let posts = activity_posts(harness.http.as_ref());
        assert_eq!(posts.len(), 3);
        for post in &posts {
            assert_eq!(
                post.url,
                "https://api.test/v2/user/alice/report/activity_log.json"
            );
            assert_eq!(post.bearer.as_deref(), Some("device-token-alice"));
            let body: Value =
                serde_json::from_slice(post.body.as_ref().map(|b| b.as_bytes()).unwrap_or(b""))
                    .unwrap();
            let records = body.get("records").unwrap().as_array().unwrap();
            assert!(!records.is_empty());
            for record in records {
                let key = record.as_object().unwrap().keys().next().unwrap();
                assert!(key.ends_with("Record"), "unexpected record key {key}");
                let inner = record.get(key).unwrap();
                assert!(inner.get("client").is_some());
                assert!(inner.get("timestamp").is_some());
                assert!(inner.get("utc_datetime_created").is_some());
            }
        }
        let web_batch = &posts_with(harness.http.as_ref(), "webActivityRecord")[0];
        let body: Value = serde_json::from_slice(web_batch.body.as_ref().unwrap().as_bytes()).unwrap();
        assert_eq!(body["records"].as_array().unwrap().len(), 2);

        // Everything acked ⇒ a second cycle claims nothing new.
        let outcome = runtime.block_on(uploader.flush_cycle());
        assert_eq!(outcome.rows, 0);
        assert!(!outcome.had_work);
    }

    #[test]
    fn flush_cycle_sends_nothing_without_token() {
        let mut harness = Harness::new("flush-no-token");
        harness.policy = Arc::new(MockPolicy::with_username(""));
        harness.insert_dns("example.org");
        let mut uploader = harness.uploader();
        let runtime = runtime();
        let outcome = runtime.block_on(uploader.flush_cycle());
        // No token ⇒ no unauthenticated request, rows stay queued.
        assert!(outcome.network_error);
        assert!(harness
            .http
            .urls()
            .iter()
            .all(|url| !url.contains("activity_log")));
    }

    #[test]
    fn invalid_records_dropped_never_fail_the_batch() {
        let harness = Harness::new("invalid-drop");
        harness.insert_dns("good.example");
        // A row with an empty domain is an invalid record (§6.1).
        {
            let mut outbox = lock_outbox(&harness.outbox);
            outbox
                .insert_dns_activity(&DnsActivityRow {
                    username: "alice".to_string(),
                    domain: String::new(),
                    process_id: None,
                    process_name: "browser".to_string(),
                    datetime_created: "2026-10-11T10:00:00Z".to_string(),
                    ip: None,
                    resolution_type: "UnrestrictedFiltered".to_string(),
                    connection_type: None,
                    resolution_datacenter: None,
                    resolution_time_ms: None,
                })
                .unwrap();
        }
        let mut uploader = harness.uploader();
        let runtime = runtime();
        let outcome = runtime.block_on(uploader.flush_cycle());
        // The valid row went out; the invalid row was deleted, not retried.
        assert_eq!(outcome.rows, 1);
        let posts = posts_with(harness.http.as_ref(), "webActivityRecord");
        assert_eq!(posts.len(), 1);
        let body: Value = serde_json::from_slice(posts[0].body.as_ref().unwrap().as_bytes()).unwrap();
        assert_eq!(body["records"].as_array().unwrap().len(), 1);
        assert_eq!(
            harness.dns_rows_left(),
            1,
            "invalid row dropped from the outbox"
        );
    }

    #[test]
    fn server_throttle_is_persisted_and_respected() {
        let mut harness = Harness::new("throttle");
        // The server throttles the upload routes; status routes still answer.
        harness.http = Arc::new(MockHttp::new(|request| {
            if request.url.ends_with("/v1/status/ping") || request.url.ends_with("/v1/status/time") {
                MockHttp::ok_json("{}")
            } else {
                ApiResponse {
                    status: 429,
                    body: b"{\"retry_after_sec\": 120}".to_vec(),
                    retry_after: None,
                }
            }
        }));
        harness.insert_dns("example.org");
        let mut uploader = harness.uploader();
        let runtime = runtime();
        let outcome = runtime.block_on(uploader.flush_cycle());
        assert!(outcome.throttled);
        assert_eq!(outcome.rows, 0);

        // The state file carries the resume timestamp (§10).
        let state_path = harness.dir.join(UPLOADER_STATE_FILE);
        let text = std::fs::read_to_string(&state_path).unwrap();
        let state: UploaderState = serde_json::from_str(&text).unwrap();
        let now = system_unix();
        assert!(state.resume_not_before > now);
        assert!(state.resume_not_before <= now + 120);

        // A fresh engine (simulating a daemon restart) honors the persisted
        // throttle without any network call.
        let calls_before = harness.http.calls.lock().len();
        let mut restarted = harness.uploader();
        let outcome = runtime.block_on(restarted.flush_cycle());
        assert!(outcome.throttled);
        assert_eq!(harness.http.calls.lock().len(), calls_before);
    }

    #[test]
    fn stale_sending_rows_are_reaped_and_retried() {
        let harness = Harness::new("reaper");
        harness.insert_dns("example.org");
        // Claim the row directly so it sits in `sending` like a crashed
        // uploader left it.
        {
            let mut outbox = lock_outbox(&harness.outbox);
            let claimed = outbox.claim_batch(EventTable::DnsActivity, 10, 0).unwrap();
            assert_eq!(claimed.len(), 1);
        }
        // Age the claim past the 1 s threshold; SQLite's DATETIME('now') has
        // one-second granularity, so cross at least two whole boundaries.
        std::thread::sleep(Duration::from_millis(2100));
        let mut uploader = harness.uploader().with_tuning(0, 1);
        let runtime = runtime();
        let outcome = runtime.block_on(uploader.flush_cycle());
        assert_eq!(outcome.rows, 1, "stale claim requeued and delivered");
        // Exactly the requeued web batch — the one-shot install report shares
        // the activity route but is not this row's delivery.
        assert_eq!(posts_with(harness.http.as_ref(), "webActivityRecord").len(), 1);
    }

    #[test]
    fn circumvention_records_respect_admin_toggle() {
        let mut harness = Harness::new("circumvention-toggle");
        harness.cfg = harness.set_cfg(|cfg| cfg.upload.circumvention_records = false);
        harness.insert_circumvention();
        let mut uploader = harness.uploader();
        let runtime = runtime();
        let outcome = runtime.block_on(uploader.flush_cycle());
        // Dropped locally, never uploaded (§7 toggle): no post carries a
        // circumventionRecord (the one-shot install report may share the
        // activity route).
        assert_eq!(outcome.rows, 0);
        assert!(posts_with(harness.http.as_ref(), "circumventionRecord").is_empty());
        assert!(lock_outbox(&harness.outbox)
            .claim_batch(EventTable::Circumventions, 10, 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn telemetry_and_logs_routes_are_used() {
        let mut harness = Harness::new("telemetry-logs");
        harness.cfg = harness.set_cfg(|cfg| cfg.upload.logs_store = true);
        harness.insert_telemetry("boot_count");
        let mut uploader = harness.uploader();
        let runtime = runtime();
        runtime.block_on(uploader.flush_cycle());
        runtime.block_on(uploader.flush_cycle());
        let urls = harness.http.urls();
        assert!(urls
            .iter()
            .any(|url| url == "https://api.test/v1/telemetry/store"));
        assert!(urls.iter().any(|url| url == "https://api.test/v1/logs/store"));
        let logs_body = harness
            .http
            .calls
            .lock()
            .iter()
            .find(|request| request.url.ends_with("/v1/logs/store"))
            .and_then(|request| request.body.clone())
            .expect("logs body");
        let records: Value = serde_json::from_str(&logs_body).unwrap();
        let records = records.as_array().unwrap();
        assert!(!records.is_empty());
        for record in records {
            for key in [
                "username", "request", "response", "process", "component", "timestamp",
            ] {
                assert!(record.get(key).is_some(), "audit record missing {key}");
            }
        }
    }

    #[test]
    fn metrics_route_serializes_queued_buckets() {
        // The metrics route cannot be aged into `queued` without a 1 h wait,
        // so the wire shape is asserted directly on the serializer.
        let row = MetricRow {
            id: 7,
            username: "alice".to_string(),
            metric_name: "client_api_success".to_string(),
            bucket_id: vec![BucketTag {
                indexed: true,
                name: "client_component".to_string(),
                value: "uploader".to_string(),
            }],
            tags: vec![AggTag {
                aggregation: Aggregation::Cardinal,
                name: "route".to_string(),
                value: "metrics".to_string(),
            }],
            fields: vec![MetricField {
                name: "api_count".to_string(),
                operation: OPERATION_AGGREGATE,
                value: json!(3),
            }],
            utc_timestamp: "2026-10-11T10:00:00Z".to_string(),
            bucket_size: 3600,
            bucket_current: 3600,
            status: "queued".to_string(),
            status_changed_at: "2026-10-11 11:00:00".to_string(),
            created_at: "2026-10-11 10:00:00".to_string(),
        };
        let value = metric_row_value(&row);
        assert_eq!(value["username"], "alice");
        assert_eq!(value["metric_name"], "client_api_success");
        assert_eq!(value["bucket_id"][0]["name"], "client_component");
        assert_eq!(value["tags"][0]["aggregation"], "CARDINAL");
        assert_eq!(value["fields"][0]["name"], "api_count");
        assert_eq!(value["bucket_size"], 3600);
        assert_eq!(value["bucket_current"], 3600);
    }

    #[test]
    fn install_report_is_sent_once() {
        let harness = Harness::new("install-report");
        harness.insert_dns("example.org");
        let mut uploader = harness.uploader();
        let runtime = runtime();
        runtime.block_on(uploader.flush_cycle());
        assert_eq!(posts_with(harness.http.as_ref(), "installActivityRecord").len(), 1);
        // Second cycle: no repeat.
        runtime.block_on(uploader.flush_cycle());
        assert_eq!(posts_with(harness.http.as_ref(), "installActivityRecord").len(), 1);
    }

    #[test]
    fn record_envelope_shapes_for_all_five_types() {
        let client = ClientBlock::new("64", "22.04", "0.1.0");
        let timestamp = "2026-10-11T12:00:00Z";

        let web = build_activity_record(
            &ClaimedRow {
                table: EventTable::DnsActivity,
                id: 1,
                username: Some("alice".to_string()),
                created_at: "2026-10-11 11:00:00".to_string(),
                columns: json!({
                    "username": "alice", "domain": "example.org", "process_id": "4321",
                    "process_name": "browser", "ip": "192.0.2.10",
                    "resolution_type": "BlockedCustom", "connection_type": "DoH",
                    "resolution_datacenter": "dc1", "resolution_time_ms": "12"
                }),
            },
            &client,
            timestamp,
        )
        .unwrap();
        assert_eq!(web["webActivityRecord"]["client"]["platform"], "Linux");
        assert_eq!(web["webActivityRecord"]["client"]["architecture"], "64");
        assert_eq!(web["webActivityRecord"]["client"]["version"], "0.1.0");
        assert_eq!(web["webActivityRecord"]["timestamp"], timestamp);
        assert_eq!(
            web["webActivityRecord"]["utc_datetime_created"],
            "2026-10-11T11:00:00Z"
        );
        assert_eq!(web["webActivityRecord"]["domain"], "example.org");
        assert_eq!(web["webActivityRecord"]["resolution_type"], "BlockedCustom");

        let login = build_activity_record(
            &ClaimedRow {
                table: EventTable::Logins,
                id: 2,
                username: Some("alice".to_string()),
                created_at: "2026-10-11 11:01:00".to_string(),
                columns: json!({
                    "username": "alice", "login_at": "2026-10-11T09:00:00Z",
                    "logout_at": null, "system_user_id": "1000", "system_user_name": "alice-os"
                }),
            },
            &client,
            timestamp,
        )
        .unwrap();
        assert_eq!(
            login["loginActivityRecord"]["login_at"],
            "2026-10-11T09:00:00Z"
        );
        assert!(login["loginActivityRecord"]["logout_at"].is_null());

        let circ = build_activity_record(
            &ClaimedRow {
                table: EventTable::Circumventions,
                id: 3,
                username: Some("alice".to_string()),
                created_at: "2026-10-11 11:02:00".to_string(),
                columns: json!({
                    "username": "alice", "interruption_type": "restricted_window",
                    "app_name": "app", "app_window_title": "t",
                    "device_id": "abc", "timezone_offset": "+02:00"
                }),
            },
            &client,
            timestamp,
        )
        .unwrap();
        assert_eq!(circ["circumventionRecord"]["device_id"], "abc");
        assert_eq!(circ["circumventionRecord"]["timezone_offset"], "+02:00");

        let switch = build_activity_record(
            &ClaimedRow {
                table: EventTable::SwitchUsers,
                id: 4,
                username: Some("alice".to_string()),
                created_at: "2026-10-11 11:03:00".to_string(),
                columns: json!({
                    "username": "alice", "switch_user_from": "alice",
                    "switch_user_to": "bob", "device_name": "host", "device_id": "def"
                }),
            },
            &client,
            timestamp,
        )
        .unwrap();
        assert_eq!(
            switch["switchUserActivityRecord"]["switch_from_username"],
            "alice"
        );
        assert_eq!(
            switch["switchUserActivityRecord"]["switch_to_username"],
            "bob"
        );

        let install = build_install_record("uuid-1", "22.04", &client, timestamp, timestamp);
        assert_eq!(install["installActivityRecord"]["device_uuid"], "uuid-1");
        assert_eq!(install["installActivityRecord"]["platform"], "Linux");
        assert_eq!(install["installActivityRecord"]["platformVersion"], "22.04");
        assert!(install["installActivityRecord"].get("architecture").is_some());

        // Invalid rows produce no record (⇒ dropped, §6.1).
        assert!(build_activity_record(
            &ClaimedRow {
                table: EventTable::DnsActivity,
                id: 5,
                username: Some("alice".to_string()),
                created_at: "2026-10-11 11:04:00".to_string(),
                columns: json!({"username": "alice", "domain": ""}),
            },
            &client,
            timestamp,
        )
        .is_none());
        assert!(build_activity_record(
            &ClaimedRow {
                table: EventTable::Logins,
                id: 6,
                username: Some("alice".to_string()),
                created_at: "2026-10-11 11:05:00".to_string(),
                columns: json!({"username": "alice"}),
            },
            &client,
            timestamp,
        )
        .is_none());
    }

    #[test]
    fn server_time_response_parsing() {
        assert_eq!(parse_server_time(b"1790000000"), Some(1_790_000_000));
        assert_eq!(
            parse_server_time(b"{\"server_time\": 1790000000}"),
            Some(1_790_000_000)
        );
        // ISO round-trip through the `time` crate.
        let iso = time::OffsetDateTime::from_unix_timestamp(1_790_000_000)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        assert_eq!(parse_server_time(iso.as_bytes()), Some(1_790_000_000));
        assert_eq!(
            parse_server_time(format!("{{\"time\": \"{iso}\"}}").as_bytes()),
            Some(1_790_000_000)
        );
        assert_eq!(parse_server_time(b"not json"), None);
        assert_eq!(parse_server_time(b"{}"), None);
    }

    #[test]
    fn throttle_seconds_prefers_retry_after_header() {
        assert_eq!(throttle_seconds(b"{}", Some(42)), 42);
        assert_eq!(throttle_seconds(b"{\"retry_after_sec\": 17}", None), 17);
        assert_eq!(
            throttle_seconds(b"garbage", None),
            DEFAULT_THROTTLE_FALLBACK_SECS
        );
    }

    #[test]
    fn heartbeat_is_local_only_and_stamps() {
        let harness = Harness::new("heartbeat");
        let mut uploader = harness.uploader();
        assert!(uploader.heartbeat());
        let stamp = lock_outbox(&harness.outbox)
            .install_metadata(HEARTBEAT_STAMP_KEY)
            .unwrap();
        assert!(stamp.is_some());
        // Zero packets at tick time (§10): the heartbeat made no HTTP call.
        assert!(harness.http.urls().is_empty());
    }

    #[test]
    fn path_segment_encodes_special_characters() {
        assert_eq!(path_segment("alice"), "alice");
        assert_eq!(path_segment("alice@example.com"), "alice@example.com");
        assert_eq!(path_segment("a b/c"), "a%20b%2Fc");
    }
}
