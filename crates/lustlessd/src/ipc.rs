//! IPC server — CONTRACTS §5 (framing, `SO_PEERCRED` authorization, the full
//! CE code table + the `0x60+` LustLess extensions).
//!
//! Transport: one Unix stream socket (§4: parent dir created 0755, socket
//! chmod **0666** so user sessions can connect). Every accepted connection is
//! `SO_PEERCRED`-authenticated (`nix::sys::socket::sockopt::PeerCredentials`)
//! before any frame is served; authorization then runs through
//! `lustless_core::wire::authorize` with the peer as the target uid (§5
//! self-scope: root may act for any uid, root-only codes require uid 0).
//!
//! Framing: `u8 code | u32 LE length | UTF-8 JSON payload`, 64 KiB max (§5).
//! Unknown codes are logged and ignored (CE behavior); a malformed frame or a
//! frame over the cap closes the connection (the stream can no longer be
//! framed).
//!
//! Replies reuse the request code with `{"ok":true,…}` /
//! `{"ok":false,"error":{…}}`. `0x02 NOTIFICATION` frames carry async
//! progress with CE's bounded `2×6×100 ms` delivery budget (§5); `0x55 POLL`
//! drains the per-connection queue (or replies with an empty frame).
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use lustless_core::db::DASHBOARD_READ_LIMIT;
use lustless_core::metrics::MetricSink;
use lustless_core::wire::{
    self as wire, Code, DecodeOutcome, Frame, FRAME_HEADER_LEN, MAX_FRAME_LEN, ROOT_UID,
};
use lustless_net::Control;

use crate::state::{guard, DaemonState, NotifyMsg};

/// §5: BREAK_GLASS "MUST be preceded by polkit auth
/// `org.lustless.break-glass`".
pub const POLKIT_BREAK_GLASS_ACTION: &str = "org.lustless.break-glass";

/// How often a connected client's queue is proactively drained (§5
/// `0x02 NOTIFICATION`; `0x55 POLL` drains on demand as well).
const NOTIFY_TICK: Duration = Duration::from_millis(100);

/// CE's bounded notification delivery budget (§5: `2×6×100 ms`): two rounds
/// of six retries, one every 100 ms.
const NOTIFY_ATTEMPTS: u32 = 12;
const NOTIFY_RETRY_SLEEP: Duration = Duration::from_millis(100);

/// Default `deadline_sec` of `0x69 FLUSH_OUTBOX` (§5: bounded flush,
/// partial results still return ok).
const DEFAULT_FLUSH_DEADLINE_SECS: u64 = 30;
/// Flush deadline for `0x4d SEND_METRICS` / `0x54 SEND_TELEMETRY`.
const EVENT_FLUSH_DEADLINE_SECS: u64 = 10;

/// Peer credentials read by `SO_PEERCRED` on accept (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Peer uid — the §5 authorization principal.
    pub uid: u32,
    /// Peer gid.
    pub gid: u32,
    /// Peer pid — polkit subject for BREAK_GLASS (§5).
    pub pid: i32,
}

/// Result of [`read_frame`].
#[derive(Debug)]
enum ReadFrame {
    /// A known §5 code with payload.
    Known(Frame),
    /// An unrecognized code byte — log and ignore (§5).
    Unknown(u8),
}

/// Result of [`dispatch`].
#[derive(Debug, Default)]
pub(crate) struct DispatchOutcome {
    /// `0x02 NOTIFICATION` frames to write before the reply (POLL drain).
    pub notifications: Vec<Value>,
    /// Reply payload for the request code (`None` = ignore, no reply).
    pub reply: Option<Value>,
    /// Set for `0x51 QUIT`: reply, then request daemon shutdown.
    pub quit: bool,
}

impl DispatchOutcome {
    fn reply(payload: Value) -> Self {
        DispatchOutcome {
            notifications: Vec::new(),
            reply: Some(payload),
            quit: false,
        }
    }

    fn ignored() -> Self {
        DispatchOutcome::default()
    }
}

fn error_reply(code: &str, message: impl Into<String>) -> Value {
    json!({ "ok": false, "error": { "code": code, "message": message.into() } })
}

/// Creates the socket directory (§4 layout) and clears stale sockets; a live
/// listener is NOT clobbered (another daemon owns the machine).
async fn prepare_socket(path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
        }
    }
    if path.exists() {
        match UnixStream::connect(path).await {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("another daemon is listening on {}", path.display()),
                ));
            }
            Err(_) => {
                let _ = std::fs::remove_file(path);
                tracing::warn!("ipc: removed stale socket {}", path.display());
            }
        }
    }
    Ok(())
}

/// Serves the §5 Unix socket until shutdown: accept → `SO_PEERCRED` →
/// per-connection frame loop.
pub async fn serve(
    socket_path: PathBuf,
    state: Arc<DaemonState>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    if *shutdown.borrow() {
        return Ok(());
    }
    prepare_socket(&socket_path).await?;
    let listener = UnixListener::bind(&socket_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666));
    }
    tracing::info!(
        "ipc: listening on {} (mode 0666, §5)",
        socket_path.display()
    );

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let conn_state = Arc::clone(&state);
                        let conn_shutdown = shutdown.clone();
                        tokio::spawn(async move {
                            if let Err(err) = serve_conn(stream, conn_state, conn_shutdown).await {
                                tracing::debug!("ipc: connection closed: {err}");
                            }
                        });
                    }
                    Err(err) => tracing::warn!("ipc: accept failed: {err}"),
                }
            }
        }
    }
    let _ = std::fs::remove_file(&socket_path);
    tracing::info!("ipc: listener closed");
    Ok(())
}

/// `SO_PEERCRED` for the accepted stream (§5).
fn peer_cred(stream: &UnixStream) -> std::io::Result<PeerCred> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::fd::{AsRawFd, BorrowedFd};

    // SAFETY: the fd belongs to `stream`, which outlives the borrow.
    let borrowed = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    let ucred = getsockopt(&borrowed, PeerCredentials).map_err(std::io::Error::other)?;
    Ok(PeerCred {
        uid: ucred.uid(),
        gid: ucred.gid(),
        pid: ucred.pid(),
    })
}

async fn serve_conn(
    mut stream: UnixStream,
    state: Arc<DaemonState>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let cred = peer_cred(&stream)?;
    tracing::debug!(
        "ipc: connection from uid {} gid {} pid {}",
        cred.uid,
        cred.gid,
        cred.pid
    );
    let (conn_id, queue) = state.register_connection();
    let result = conn_loop(&mut stream, &state, cred, &queue, &mut shutdown).await;
    state.unregister_connection(conn_id);
    result
}

async fn conn_loop(
    stream: &mut UnixStream,
    state: &Arc<DaemonState>,
    cred: PeerCred,
    queue: &Arc<Mutex<VecDeque<NotifyMsg>>>,
    shutdown: &mut watch::Receiver<bool>,
) -> std::io::Result<()> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let pending = !guard(queue).is_empty();
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            _ = tokio::time::sleep(NOTIFY_TICK), if pending => {
                drain_notifications(stream, queue).await?;
            }
            read = read_frame(stream) => {
                match read? {
                    None => return Ok(()),
                    Some(ReadFrame::Unknown(code)) => {
                        tracing::warn!("ipc: ignoring unknown frame code 0x{code:02x} (§5 log-and-ignore)");
                    }
                    Some(ReadFrame::Known(frame)) => {
                        let code = frame.code;
                        let outcome = dispatch(state, cred, cred.uid, frame, queue).await;
                        for notification in outcome.notifications {
                            write_notification(stream, &Frame::new(Code::Notification, notification)).await?;
                        }
                        if let Some(payload) = outcome.reply {
                            write_frame(stream, &Frame::new(code, payload)).await?;
                        }
                        if outcome.quit {
                            state.request_shutdown();
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

/// Reads exactly one frame; `Ok(None)` = clean EOF (§5 framing).
async fn read_frame(stream: &mut UnixStream) -> std::io::Result<Option<ReadFrame>> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let payload_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if FRAME_HEADER_LEN + payload_len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds the 64 KiB maximum (§5)",
        ));
    }
    let mut buffer = vec![0u8; FRAME_HEADER_LEN + payload_len];
    buffer[..FRAME_HEADER_LEN].copy_from_slice(&header);
    match stream.read_exact(&mut buffer[FRAME_HEADER_LEN..]).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    match Frame::decode(&buffer) {
        Ok(DecodeOutcome::Frame(frame)) => Ok(Some(ReadFrame::Known(frame))),
        Ok(DecodeOutcome::UnknownCode(code)) => Ok(Some(ReadFrame::Unknown(code))),
        Err(err) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            err.to_string(),
        )),
    }
}

/// Writes a reply frame once (the peer asked for it, so it is reading).
async fn write_frame(stream: &mut UnixStream, frame: &Frame) -> std::io::Result<()> {
    let bytes = frame
        .encode()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    stream.write_all(&bytes).await
}

/// Writes a `0x02 NOTIFICATION` with CE's bounded `2×6×100 ms` retry budget
/// (§5): transient backpressure gets twelve 100 ms retries before the
/// delivery is given up (the message stays queued for `0x55 POLL` when the
/// write never started).
async fn write_notification(stream: &mut UnixStream, frame: &Frame) -> std::io::Result<()> {
    let bytes = frame
        .encode()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let mut offset = 0;
    let mut attempts = 0;
    while offset < bytes.len() {
        if attempts >= NOTIFY_ATTEMPTS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "notification delivery budget exhausted (2×6×100 ms)",
            ));
        }
        match stream.write(&bytes[offset..]).await {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "peer closed during notification write",
                ))
            }
            Ok(written) => offset += written,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                attempts += 1;
                tokio::time::sleep(NOTIFY_RETRY_SLEEP).await;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Pops and delivers every queued notification of this connection.
async fn drain_notifications(
    stream: &mut UnixStream,
    queue: &Arc<Mutex<VecDeque<NotifyMsg>>>,
) -> std::io::Result<()> {
    loop {
        let next = guard(queue).pop_front();
        let Some(message) = next else {
            return Ok(());
        };
        let frame = Frame::new(Code::Notification, message.to_payload());
        write_notification(stream, &frame).await?;
    }
}

/// `NetServices::flush_now` blocks up to the deadline (pinned API) — always
/// called from the blocking pool.
async fn flush_outbox_now(state: &Arc<DaemonState>, deadline_secs: u64) -> Result<usize, String> {
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || state.flush_outbox(Duration::from_secs(deadline_secs)))
        .await
        .map_err(|err| err.to_string())?
}

/// §5 `0x62` self scope: the §8 `ViewDnsActivityHandler` query plus a
/// `username = ?` predicate over a read-only connection. Core's
/// `Outbox::dns_activity_readback` has no username filter (and does not
/// return the column), so root uses it verbatim and "self" uses this
/// equivalent query.
fn readback_for_username(
    outbox_path: &Path,
    username: &str,
    limit: u32,
) -> Result<Vec<Value>, String> {
    const QUERY: &str = "SELECT domain,process_id,process_name,ip,resolution_type,connection_type,resolution_datacenter,resolution_time_ms,datetime_created \
                         FROM dns_activity WHERE username = ?1 ORDER BY datetime_created DESC LIMIT ?2";
    let conn = rusqlite::Connection::open_with_flags(
        outbox_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|err| err.to_string())?;
    let mut stmt = conn.prepare(QUERY).map_err(|err| err.to_string())?;
    let names: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
    let rows = stmt
        .query_map(rusqlite::params![username, limit], |row| {
            let mut map = Map::new();
            for (index, name) in names.iter().enumerate() {
                let value: Option<String> = row.get(index)?;
                map.insert(
                    name.clone(),
                    match value {
                        Some(text) => Value::String(text),
                        None => Value::Null,
                    },
                );
            }
            Ok(Value::Object(map))
        })
        .map_err(|err| err.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())
}

/// Keeps a rows reply inside §5's 64 KiB frame by dropping the oldest rows
/// (the tail of the `DESC` order) until it encodes.
fn fit_rows_reply(mut rows: Vec<Value>) -> Value {
    loop {
        let reply = json!({ "ok": true, "rows": rows });
        match Frame::new(Code::DnsActivityQuery, reply.clone()).encode() {
            Ok(_) => return reply,
            Err(_) => {
                if rows.pop().is_none() {
                    return error_reply("query", "result does not fit in one 64 KiB frame (§5)");
                }
            }
        }
    }
}

/// §5 BREAK_GLASS gate: `CheckAuthorization` for
/// `org.lustless.break-glass` on the peer's process subject. Fails closed —
/// any D-Bus/policy error denies the request.
pub async fn polkit_authorized(pid: i32) -> bool {
    use std::collections::HashMap;
    use zbus::zvariant::{OwnedValue, Value as ZValue};

    let conn = match zbus::Connection::system().await {
        Ok(conn) => conn,
        Err(err) => {
            tracing::warn!("polkit: system bus unavailable: {err}");
            return false;
        }
    };
    let proxy = match zbus::Proxy::new(
        &conn,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await
    {
        Ok(proxy) => proxy,
        Err(err) => {
            tracing::warn!("polkit: authority proxy failed: {err}");
            return false;
        }
    };
    let subject: (String, HashMap<String, ZValue>) = (
        "process".to_string(),
        HashMap::from([("pid".to_string(), ZValue::U32(pid as u32))]),
    );
    let details = HashMap::<String, ZValue>::new();
    let response = proxy
        .call_method(
            "CheckAuthorization",
            &(
                subject,
                POLKIT_BREAK_GLASS_ACTION,
                details,
                0u32, // no user interaction (§5 polkit gate is a check)
            ),
        )
        .await;
    match response {
        Err(err) => {
            tracing::warn!("polkit: CheckAuthorization failed: {err}");
            false
        }
        Ok(message) => match message
            .body()
            .deserialize::<(bool, bool, HashMap<String, OwnedValue>)>()
        {
            Ok((authorized, _challenge, _details)) => {
                tracing::info!("polkit: {POLKIT_BREAK_GLASS_ACTION} authorized={authorized}");
                authorized
            }
            Err(err) => {
                tracing::warn!("polkit: reply decode failed: {err}");
                false
            }
        },
    }
}

/// The §5 dispatch table: authorization first, then one handler per code.
/// Every handler is real code; unknown *bytes* never reach here (they are
/// log-and-ignored by [`read_frame`]).
pub(crate) async fn dispatch(
    state: &Arc<DaemonState>,
    cred: PeerCred,
    target_uid: u32,
    frame: Frame,
    queue: &Arc<Mutex<VecDeque<NotifyMsg>>>,
) -> DispatchOutcome {
    let code = frame.code;
    // A client has no business sending daemon→client notifications (§5 dir).
    if code == Code::Notification {
        tracing::warn!("ipc: peer sent a NOTIFICATION frame; ignoring");
        return DispatchOutcome::ignored();
    }
    if !wire::authorize(code, cred.uid, target_uid) {
        return DispatchOutcome::reply(error_reply(
            "forbidden",
            "authorization denied for this request",
        ));
    }
    let payload = frame.payload;

    match code {
        // 0x43 — spawn the §5/§10 support bundle (CE texts via Notifier).
        Code::CollectDebugLogs => {
            let started = state.start_diagnostics();
            DispatchOutcome::reply(json!({ "ok": true, "started": started }))
        }

        // 0x4c — CE schedules the filter re-evaluation after logout; here it
        // IS the sign-out (closes the §6.1 login row, clears §6.2 tokens,
        // drops §8 membership).
        Code::UserLogout => {
            let state = Arc::clone(state);
            let result = tokio::task::spawn_blocking(move || Control::sign_out(state.as_ref()))
                .await
                .unwrap_or_else(|err| Err(err.to_string()));
            match result {
                Ok(()) => DispatchOutcome::reply(json!({ "ok": true })),
                Err(err) => DispatchOutcome::reply(error_reply("sign_out", err)),
            }
        }

        // 0x4d — flush the metrics outbox now (roll open buckets first).
        Code::SendMetrics => {
            let rolled = {
                let mut outbox = guard(&state.outbox);
                MetricSink::new(&mut outbox).roll_ready()
            };
            if let Err(err) = rolled {
                return DispatchOutcome::reply(error_reply("metrics", err.to_string()));
            }
            match flush_outbox_now(state, EVENT_FLUSH_DEADLINE_SECS).await {
                Ok(flushed) => DispatchOutcome::reply(json!({ "ok": true, "flushed": flushed })),
                Err(err) => DispatchOutcome::reply(error_reply("flush", err)),
            }
        }

        // 0x51 — root-only daemon shutdown (session-guarded QUIT in CE).
        Code::Quit => DispatchOutcome {
            notifications: Vec::new(),
            reply: Some(json!({ "ok": true })),
            quit: true,
        },

        // 0x52 — root-only §9.1 system-config mutation.
        Code::SetClientConfig => {
            let Some(object) = payload.as_object() else {
                return DispatchOutcome::reply(error_reply(
                    "invalid_payload",
                    "expected {\"key\",\"value\"}",
                ));
            };
            let (Some(key), Some(value)) = (
                object.get("key").and_then(Value::as_str),
                object.get("value"),
            ) else {
                return DispatchOutcome::reply(error_reply(
                    "invalid_payload",
                    "expected {\"key\",\"value\"}",
                ));
            };
            if value.is_null() {
                return DispatchOutcome::reply(error_reply(
                    "invalid_payload",
                    "value may not be null",
                ));
            }
            match state.set_client_config(key, value) {
                Ok(()) => DispatchOutcome::reply(json!({ "ok": true, "key": key })),
                Err(err) => DispatchOutcome::reply(error_reply("config", err)),
            }
        }

        // 0x53 — self-scope settings publication (§5 `{fields}`).
        Code::UserSettingsChange => match state.apply_user_settings(cred.uid, &payload) {
            Ok(()) => DispatchOutcome::reply(json!({ "ok": true })),
            Err(err) => DispatchOutcome::reply(error_reply("settings", err)),
        },

        // 0x54 — flush telemetry now (rows are born `queued`, §6.1).
        Code::SendTelemetry => match flush_outbox_now(state, EVENT_FLUSH_DEADLINE_SECS).await {
            Ok(flushed) => DispatchOutcome::reply(json!({ "ok": true, "flushed": flushed })),
            Err(err) => DispatchOutcome::reply(error_reply("flush", err)),
        },

        // 0x55 — drain this connection's queued notifications; empty queue →
        // an empty 0x55 frame (Value::Null ⇒ zero-length payload, §5).
        Code::Poll => {
            let mut notifications = Vec::new();
            let mut drained = 0usize;
            while let Some(message) = guard(queue).pop_front() {
                notifications.push(message.to_payload());
                drained += 1;
            }
            let reply = if drained == 0 {
                Value::Null
            } else {
                json!({ "ok": true, "drained": drained })
            };
            DispatchOutcome {
                notifications,
                reply: Some(reply),
                quit: false,
            }
        }

        // 0x60 — §9 snapshot scoped to the peer (§5: own uid only).
        Code::PolicyGet => {
            let snapshot =
                serde_json::to_value(state.snapshot_for(cred.uid)).unwrap_or_else(|_| json!({}));
            DispatchOutcome::reply(json!({ "ok": true, "policy": snapshot }))
        }

        // 0x61 — daemon status + uid-bound dashboard URL (§13 token pin).
        Code::StatusGet => {
            let dashboard_url = state.dashboard_url(cred.uid).unwrap_or_default();
            DispatchOutcome::reply(json!({
                "ok": true,
                "status": state.status_json(),
                "dashboard_url": dashboard_url,
            }))
        }

        // 0x62 — root sees all rows, self sees only its own (§5/§8).
        Code::DnsActivityQuery => {
            let limit = payload
                .get("limit")
                .and_then(Value::as_u64)
                .map(|limit| limit.clamp(1, u64::from(DASHBOARD_READ_LIMIT)) as u32)
                .unwrap_or(DASHBOARD_READ_LIMIT);
            if cred.uid == ROOT_UID {
                let rows = match guard(&state.outbox).dns_activity_readback(limit) {
                    Ok(rows) => rows,
                    Err(err) => {
                        return DispatchOutcome::reply(error_reply("query", err.to_string()))
                    }
                };
                return DispatchOutcome::reply(json!({ "ok": true, "rows": rows, "scope": "all" }));
            }
            match state.session_for(cred.uid) {
                Err(_) => DispatchOutcome::reply(
                    json!({ "ok": true, "rows": Vec::<Value>::new(), "scope": "self" }),
                ),
                Ok((_uid, username)) => {
                    match readback_for_username(state.outbox_path(), &username, limit) {
                        Ok(rows) => {
                            let mut reply = fit_rows_reply(rows);
                            reply["scope"] = json!("self");
                            DispatchOutcome::reply(reply)
                        }
                        Err(err) => DispatchOutcome::reply(error_reply("query", err)),
                    }
                }
            }
        }

        // 0x63 — filter level via Control (§5).
        Code::FilterSetLevel => {
            if let Err(err) = state.session_for(cred.uid) {
                return DispatchOutcome::reply(error_reply("filter_level", err));
            }
            let Some(level) = payload.get("level").and_then(Value::as_str) else {
                return DispatchOutcome::reply(error_reply(
                    "invalid_payload",
                    "expected {\"level\"}",
                ));
            };
            let state = Arc::clone(state);
            let level = level.to_string();
            let reply_level = level.clone();
            let result = tokio::task::spawn_blocking(move || {
                Control::set_filter_level(state.as_ref(), &level)
            })
            .await
            .unwrap_or_else(|err| Err(err.to_string()));
            match result {
                Ok(()) => DispatchOutcome::reply(json!({ "ok": true, "level": reply_level })),
                Err(err) => DispatchOutcome::reply(error_reply("filter_level", err)),
            }
        }

        // 0x64 — tri-state domain override via Control (§5).
        Code::FilterSetOverrides => {
            if let Err(err) = state.session_for(cred.uid) {
                return DispatchOutcome::reply(error_reply("filter_override", err));
            }
            let (Some(domain), Some(verdict)) = (
                payload.get("domain").and_then(Value::as_str),
                payload.get("verdict").and_then(Value::as_str),
            ) else {
                return DispatchOutcome::reply(error_reply(
                    "invalid_payload",
                    "expected {\"domain\",\"verdict\":\"allow\"|\"block\"|\"na\"}",
                ));
            };
            let state = Arc::clone(state);
            let (domain, verdict) = (domain.to_string(), verdict.to_string());
            let result = tokio::task::spawn_blocking(move || {
                Control::set_override(state.as_ref(), &domain, &verdict)
            })
            .await
            .unwrap_or_else(|err| Err(err.to_string()));
            match result {
                Ok(()) => DispatchOutcome::reply(json!({ "ok": true })),
                Err(err) => DispatchOutcome::reply(error_reply("filter_override", err)),
            }
        }

        // 0x65 — connection-scope sign-in (§5; password never stored, §10).
        Code::SignIn => {
            let (Some(username), Some(password)) = (
                payload.get("username").and_then(Value::as_str),
                payload.get("password").and_then(Value::as_str),
            ) else {
                return DispatchOutcome::reply(error_reply(
                    "invalid_payload",
                    "expected {\"username\",\"password\"}",
                ));
            };
            if cred.uid != ROOT_UID {
                // Bind the session to the caller's uid (pinned Control carries
                // no uid; the hint is read inside sign_in).
                state.set_sign_in_uid_hint(cred.uid);
            }
            let sign_state = Arc::clone(state);
            let (username, password) = (username.to_string(), password.to_string());
            let result = tokio::task::spawn_blocking(move || {
                Control::sign_in(sign_state.as_ref(), &username, &password)
            })
            .await
            .unwrap_or_else(|err| Err(err.to_string()));
            match result {
                Ok(token) => {
                    let dashboard_url = state.dashboard_url(cred.uid).unwrap_or_default();
                    DispatchOutcome::reply(json!({
                        "ok": true,
                        "token": token,
                        "dashboard_url": dashboard_url,
                    }))
                }
                Err(err) => DispatchOutcome::reply(error_reply("sign_in", err)),
            }
        }

        // 0x66 — sign-out (self scope; peer must own the session, §5).
        Code::SignOut => {
            if let Err(err) = state.session_for(cred.uid) {
                return DispatchOutcome::reply(error_reply("sign_out", err));
            }
            let state = Arc::clone(state);
            let result = tokio::task::spawn_blocking(move || Control::sign_out(state.as_ref()))
                .await
                .unwrap_or_else(|err| Err(err.to_string()));
            match result {
                Ok(()) => DispatchOutcome::reply(json!({ "ok": true })),
                Err(err) => DispatchOutcome::reply(error_reply("sign_out", err)),
            }
        }

        // 0x67 — §12 feed recommendation via Control.
        Code::UpdateCheck => {
            let state = Arc::clone(state);
            let result = tokio::task::spawn_blocking(move || Control::update_check(state.as_ref()))
                .await
                .unwrap_or_else(|err| Err(err.to_string()));
            match result {
                Ok(recommendation) => {
                    DispatchOutcome::reply(json!({ "ok": true, "recommendation": recommendation }))
                }
                Err(err) => DispatchOutcome::reply(error_reply("update_check", err)),
            }
        }

        // 0x68 — root-only + polkit (§5) + journald audit + fail-open flag.
        Code::BreakGlass => {
            let Some(reason) = payload.get("reason").and_then(Value::as_str) else {
                return DispatchOutcome::reply(error_reply(
                    "invalid_payload",
                    "expected {\"reason\"}",
                ));
            };
            if reason.trim().is_empty() {
                return DispatchOutcome::reply(error_reply(
                    "invalid_payload",
                    "reason may not be empty",
                ));
            }
            if !polkit_authorized(cred.pid).await {
                return DispatchOutcome::reply(error_reply(
                    "forbidden",
                    format!("polkit authorization failed for {POLKIT_BREAK_GLASS_ACTION}"),
                ));
            }
            match state.break_glass(cred.uid, reason) {
                Ok(()) => DispatchOutcome::reply(json!({ "ok": true, "fail_open": true })),
                Err(err) => DispatchOutcome::reply(error_reply("break_glass", err)),
            }
        }

        // 0x69 — root-only bounded outbox drain (§5/§11 `prerm`).
        Code::FlushOutbox => {
            let deadline = payload
                .get("deadline_sec")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_FLUSH_DEADLINE_SECS)
                .clamp(1, 300);
            match flush_outbox_now(state, deadline).await {
                Ok(flushed) => DispatchOutcome::reply(json!({ "ok": true, "flushed": flushed })),
                Err(err) => DispatchOutcome::reply(error_reply("flush", err)),
            }
        }

        // Client-sent NOTIFICATION is handled above; keep the match total.
        Code::Notification => DispatchOutcome::ignored(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_util::test_state;

    fn queue_of(state: &Arc<DaemonState>) -> (u64, Arc<Mutex<VecDeque<NotifyMsg>>>) {
        state.register_connection()
    }

    fn frame(code: Code, payload: Value) -> Frame {
        Frame::new(code, payload)
    }

    fn cred(uid: u32) -> PeerCred {
        PeerCred {
            uid,
            gid: uid,
            pid: 4242,
        }
    }

    /// Every §5 code reaches its handler (the dispatch-table test).
    ///
    /// Root runs all of them so no code bounces off the root-only gate;
    /// `BreakGlass` is excluded because its polkit check needs a live
    /// PolicyKit (environment-dependent) — its authorization paths are
    /// covered by [`root_only_codes_are_rejected_for_non_root`] and the
    /// fail-closed logic of [`polkit_authorized`].
    #[tokio::test]
    async fn every_code_reaches_its_handler() {
        let ts = test_state();
        let state = &ts.state;
        let (id, queue) = queue_of(state);
        for code in Code::ALL {
            if code == Code::Notification {
                // Client→daemon NOTIFICATION is log-and-ignored by design.
                let outcome = dispatch(state, cred(0), 0, frame(code, json!({})), &queue).await;
                assert!(outcome.reply.is_none(), "{code} must be ignored");
                continue;
            }
            if code == Code::BreakGlass {
                continue; // needs a live PolicyKit; see the doc above
            }
            let outcome = dispatch(state, cred(0), 0, frame(code, json!({})), &queue).await;
            let reply = outcome
                .reply
                .unwrap_or_else(|| panic!("{code} produced no reply"));
            if reply.is_null() {
                assert_eq!(code, Code::Poll, "only POLL answers with an empty frame");
            } else {
                assert!(
                    reply.get("ok").is_some(),
                    "{code} reply must be ok-shaped: {reply}"
                );
                if let Some(error) = reply.get("error") {
                    assert_ne!(
                        error["code"], "forbidden",
                        "{code} must not be an authorization failure for its own peer"
                    );
                }
            }
            if code == Code::Quit {
                assert!(outcome.quit, "QUIT requests shutdown");
            }
        }
        state.unregister_connection(id);
    }

    /// Root-only codes reject a non-root peer before any handler runs (§5).
    #[tokio::test]
    async fn root_only_codes_are_rejected_for_non_root() {
        let ts = test_state();
        let state = &ts.state;
        let (id, queue) = queue_of(state);
        for code in [
            Code::Quit,
            Code::SetClientConfig,
            Code::BreakGlass,
            Code::FlushOutbox,
        ] {
            let outcome = dispatch(state, cred(1000), 1000, frame(code, json!({})), &queue).await;
            let reply = outcome.reply.expect("reply");
            assert_eq!(reply["ok"], false, "{code}");
            assert_eq!(reply["error"]["code"], "forbidden", "{code}");
            assert!(!outcome.quit, "{code} must not quit the daemon");
        }
        // Root passes authorization for the same codes (handlers may still
        // fail on their own merits — e.g. no net services in a test).
        let outcome = dispatch(state, cred(0), 0, frame(Code::Quit, json!({})), &queue).await;
        let reply = outcome.reply.expect("reply");
        assert_eq!(reply["ok"], true, "QUIT for root");
        assert!(outcome.quit);

        let outcome = dispatch(
            state,
            cred(0),
            0,
            frame(Code::FlushOutbox, json!({})),
            &queue,
        )
        .await;
        let reply = outcome.reply.expect("reply");
        // Authorized, but the test has no running NetServices: an ordinary
        // handler error, not an authorization failure.
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"]["code"], "flush");
        state.unregister_connection(id);
    }

    /// Self-scope codes reject a peer that is not the target uid (§5);
    /// connection-scope codes do not care.
    #[tokio::test]
    async fn self_scope_rejects_foreign_target() {
        let ts = test_state();
        let state = &ts.state;
        let (id, queue) = queue_of(state);

        let outcome = dispatch(
            state,
            cred(1000),
            2000,
            frame(Code::PolicyGet, json!({})),
            &queue,
        )
        .await;
        assert_eq!(outcome.reply.expect("reply")["error"]["code"], "forbidden");

        // POLL is connection-scope: served regardless of target.
        let outcome = dispatch(
            state,
            cred(1000),
            2000,
            frame(Code::Poll, Value::Null),
            &queue,
        )
        .await;
        assert_eq!(outcome.reply, Some(Value::Null), "connection scope allowed");

        // Root acts for any uid (§5 root-or-self).
        let outcome = dispatch(
            state,
            cred(0),
            2000,
            frame(Code::PolicyGet, json!({})),
            &queue,
        )
        .await;
        assert_eq!(outcome.reply.expect("reply")["ok"], true);
        state.unregister_connection(id);
    }

    /// `0x55 POLL` drains queued notifications, then answers empty (§5).
    #[tokio::test]
    async fn poll_drains_queued_notifications() {
        let ts = test_state();
        let state = &ts.state;
        let (id, queue) = queue_of(state);
        state.notify("info", "Diagnostics are being collected…", Some(0));
        state.notify("info", "We've finished collecting diagnostics", Some(100));

        let outcome = dispatch(
            state,
            cred(1000),
            1000,
            frame(Code::Poll, Value::Null),
            &queue,
        )
        .await;
        assert_eq!(outcome.notifications.len(), 2, "both notifications");
        assert_eq!(
            outcome.notifications[0]["message"],
            "Diagnostics are being collected…"
        );
        assert_eq!(outcome.reply, Some(json!({ "ok": true, "drained": 2 })));

        // Queue empty → empty 0x55 frame (zero-length payload, §5).
        let outcome = dispatch(
            state,
            cred(1000),
            1000,
            frame(Code::Poll, Value::Null),
            &queue,
        )
        .await;
        assert!(outcome.notifications.is_empty());
        assert_eq!(outcome.reply, Some(Value::Null));
        state.unregister_connection(id);
    }

    /// `0x65` over an offline config returns a token (§5 `{"token",…}`) and
    /// a dashboard URL slot (§13).
    #[tokio::test]
    async fn sign_in_dispatch_returns_token_and_dashboard_url() {
        let ts = test_state();
        let state = &ts.state;
        let (id, queue) = queue_of(state);
        let outcome = dispatch(
            state,
            cred(1000),
            1000,
            frame(Code::SignIn, json!({"username": "alice", "password": "pw"})),
            &queue,
        )
        .await;
        let reply = outcome.reply.expect("reply");
        assert_eq!(reply["ok"], true, "{reply}");
        assert!(!reply["token"].as_str().expect("token").is_empty());
        assert!(reply.get("dashboard_url").is_some());
        assert_eq!(state.session_uid(), Some(1000));
        state.unregister_connection(id);
    }

    /// Framing: known frame, unknown code byte (log-and-ignore), oversized
    /// frame rejection and clean EOF (§5).
    #[tokio::test]
    async fn frame_reader_handles_known_unknown_oversized_and_eof() {
        let (mut client, mut server) = UnixStream::pair().expect("pair");

        // Unknown code byte → Unknown (log-and-ignore path).
        client.write_all(&[0x99, 0, 0, 0, 0]).await.expect("write");
        match read_frame(&mut server).await.expect("read") {
            Some(ReadFrame::Unknown(0x99)) => {}
            other => panic!("expected unknown 0x99, got {other:?}"),
        }

        // Known code (POLICY_GET, empty payload).
        client.write_all(&[0x60, 0, 0, 0, 0]).await.expect("write");
        match read_frame(&mut server).await.expect("read") {
            Some(ReadFrame::Known(frame)) => assert_eq!(frame.code, Code::PolicyGet),
            other => panic!("expected known frame, got {other:?}"),
        }

        // Declared length over the 64 KiB cap → error (§5).
        let over = MAX_FRAME_LEN as u32;
        client
            .write_all(&[
                0x60,
                over.to_le_bytes()[0],
                over.to_le_bytes()[1],
                over.to_le_bytes()[2],
                over.to_le_bytes()[3],
            ])
            .await
            .expect("write");
        assert!(
            read_frame(&mut server).await.is_err(),
            "oversized frame rejected"
        );

        // Clean EOF → None.
        drop(client);
        assert!(matches!(read_frame(&mut server).await, Ok(None)));
    }

    /// The `2×6×100 ms` notification budget is what a dead peer gets (§5):
    /// the write fails once the peer is gone, without hanging the loop.
    #[tokio::test]
    async fn notification_write_to_dead_peer_fails_fast() {
        let (client, mut server) = UnixStream::pair().expect("pair");
        drop(client);
        let frame = Frame::new(Code::Notification, json!({"level":"info","message":"x"}));
        // The peer is gone: the kernel reports the error immediately (no
        // budget sleep is exercised — the budget exists for backpressure).
        let result = write_notification(&mut server, &frame).await;
        assert!(result.is_err(), "dead peer must fail the delivery");
    }

    /// The self-scope readback query returns only the caller's rows (§5).
    #[tokio::test]
    async fn self_readback_filters_by_username() {
        let ts = test_state();
        let state = &ts.state;
        {
            let mut outbox = guard(&state.outbox);
            for (user, domain) in [("alice", "a.example"), ("bob", "b.example")] {
                outbox
                    .insert_dns_activity(&lustless_core::db::DnsActivityRow {
                        username: user.to_string(),
                        domain: domain.to_string(),
                        process_id: Some("1".into()),
                        process_name: "test".into(),
                        datetime_created: "2026-10-11T10:00:00Z".into(),
                        ip: None,
                        resolution_type: "UnrestrictedFiltered".into(),
                        connection_type: None,
                        resolution_datacenter: None,
                        resolution_time_ms: Some("5".into()),
                    })
                    .expect("insert");
            }
        }
        let rows = readback_for_username(state.outbox_path(), "alice", 10).expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["domain"], "a.example");

        let reply = fit_rows_reply(rows);
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["rows"].as_array().expect("array").len(), 1);
    }
}
