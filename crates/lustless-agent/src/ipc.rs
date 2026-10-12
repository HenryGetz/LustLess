//! UDS client for the `lustlessd` IPC socket (CONTRACTS §5) — one request
//! per connection, framed with `lustless_core::wire`.
//!
//! The daemon may interleave `NOTIFICATION` frames (0x02) ahead of the reply
//! on the same connection; they are collected and handed back so the agent
//! can surface CE-progress vocabulary (§5).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use lustless_core::wire::{Code, DecodeOutcome, Frame, FRAME_HEADER_LEN, MAX_FRAME_LEN};

/// Read budget for an ordinary request against the local daemon.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Write budget for any request.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// IPC failure classes (the agent reconnects on both unreachable and
/// protocol/time-out failures).
#[derive(Debug)]
pub enum IpcError {
    /// The socket could not be connected (daemon down or restarting).
    Unreachable(String),
    /// Framing violation, or a reply that never came in time.
    Protocol(String),
    /// The daemon answered `{"ok":false,"error":{…}}`.
    Denied(String),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcError::Unreachable(msg) => write!(f, "cannot reach lustlessd: {msg}"),
            IpcError::Protocol(msg) => write!(f, "IPC protocol error: {msg}"),
            IpcError::Denied(msg) => write!(f, "daemon refused the request: {msg}"),
        }
    }
}

/// Sends `code`/`payload` on a fresh one-shot connection, returning the
/// `{"ok":true,…}` reply and any `NOTIFICATION` payload that preceded it
/// (§5 0x02). One-shot use is fine for menu actions; the poll loop uses
/// [`Connection`] so the daemon's per-connection notification queue survives
/// between requests (§5).
pub fn request(
    path: &Path,
    code: Code,
    payload: Value,
    read_timeout: Duration,
) -> Result<(Value, Vec<Value>), IpcError> {
    let mut stream = connect(path)?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|err| IpcError::Protocol(format!("set_read_timeout: {err}")))?;
    exchange(&mut stream, code, payload)
}

/// A persistent connection: the daemon queues `NOTIFICATION` frames per
/// accepted connection, so the ~2.5 s poll cadence must reuse one socket or
/// async progress would be lost between reconnects (§5).
pub struct Connection {
    stream: UnixStream,
}

impl Connection {
    /// Connects to the daemon socket.
    pub fn connect(path: &Path) -> Result<Connection, IpcError> {
        let stream = connect(path)?;
        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|err| IpcError::Protocol(format!("set_read_timeout: {err}")))?;
        Ok(Connection { stream })
    }

    /// One request/reply exchange on this connection; NOTIFICATION frames
    /// ahead of the reply are collected (§5 0x02).
    pub fn request(
        &mut self,
        code: Code,
        payload: Value,
        read_timeout: Duration,
    ) -> Result<(Value, Vec<Value>), IpcError> {
        self.stream
            .set_read_timeout(Some(read_timeout))
            .map_err(|err| IpcError::Protocol(format!("set_read_timeout: {err}")))?;
        exchange(&mut self.stream, code, payload)
    }
}

fn connect(path: &Path) -> Result<UnixStream, IpcError> {
    let stream = UnixStream::connect(path)
        .map_err(|err| IpcError::Unreachable(format!("{}: {err}", path.display())))?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|err| IpcError::Protocol(format!("set_write_timeout: {err}")))?;
    Ok(stream)
}

fn exchange(
    stream: &mut UnixStream,
    code: Code,
    payload: Value,
) -> Result<(Value, Vec<Value>), IpcError> {
    let bytes = Frame::new(code, payload)
        .encode()
        .map_err(|err| IpcError::Protocol(err.to_string()))?;
    stream
        .write_all(&bytes)
        .map_err(|err| IpcError::Protocol(format!("write: {err}")))?;

    let mut notifications = Vec::new();
    loop {
        let Some(frame) = read_frame(stream)? else {
            // Unknown code byte — log-and-ignore per §5, keep reading.
            continue;
        };
        match frame.code {
            Code::Notification => notifications.push(frame.payload),
            reply_code if reply_code == code => {
                return Ok((check_reply(frame.payload)?, notifications));
            }
            other => {
                return Err(IpcError::Protocol(format!(
                    "unexpected reply frame {other} while waiting for {code}"
                )))
            }
        }
    }
}

/// Reads exactly one frame; `Ok(None)` = unknown code byte, skipped (§5).
fn read_frame(stream: &mut UnixStream) -> Result<Option<Frame>, IpcError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).map_err(map_read_error)?;
    let payload_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if FRAME_HEADER_LEN + payload_len > MAX_FRAME_LEN {
        return Err(IpcError::Protocol(format!(
            "declared payload length {payload_len} exceeds the 64 KiB frame cap"
        )));
    }
    let mut body = vec![0u8; payload_len];
    stream.read_exact(&mut body).map_err(map_read_error)?;
    let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + payload_len);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&body);
    match Frame::decode(&bytes) {
        Ok(DecodeOutcome::Frame(frame)) => Ok(Some(frame)),
        Ok(DecodeOutcome::UnknownCode(byte)) => {
            tracing::warn!(target: "agent", "ignoring unknown frame code 0x{byte:02x}");
            Ok(None)
        }
        Err(err) => Err(IpcError::Protocol(err.to_string())),
    }
}

fn map_read_error(err: std::io::Error) -> IpcError {
    match err.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            IpcError::Protocol("timed out waiting for the daemon reply".into())
        }
        _ => IpcError::Unreachable(format!("socket read failed: {err}")),
    }
}

fn check_reply(payload: Value) -> Result<Value, IpcError> {
    match payload.get("ok") {
        Some(Value::Bool(true)) => Ok(payload),
        Some(Value::Bool(false)) => {
            let message = payload
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("unknown daemon error");
            Err(IpcError::Denied(message.to_string()))
        }
        _ => Err(IpcError::Protocol(
            "reply is missing the ok envelope".to_string(),
        )),
    }
}
