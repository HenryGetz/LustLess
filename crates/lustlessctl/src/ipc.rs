//! UDS client for the `lustlessd` IPC socket (CONTRACTS §5) — one request
//! per connection, framed with `lustless_core::wire`.
//!
//! Reply shape: the daemon reuses the request code and answers with
//! `{"ok":true,…}` / `{"ok":false,"error":{…}}` (§5). `NOTIFICATION` frames
//! (0x02) may be queued on the same connection ahead of the reply; they are
//! collected and handed back so callers can surface progress (the agent does;
//! the CLI prints them to stderr).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use lustless_core::wire::{Code, DecodeOutcome, Frame, FRAME_HEADER_LEN, MAX_FRAME_LEN};

/// Default read budget for an ordinary request (§5 local daemon; generous).
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Write budget for any request — the frame is small, a healthy daemon
/// accepts immediately.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// IPC failure classes, mapped onto the CLI exit codes of CONTRACTS §5
/// (0 ok / 1 error / 2 daemon-unreachable).
#[derive(Debug)]
pub enum IpcError {
    /// The socket could not be connected (daemon down, socket missing).
    Unreachable(String),
    /// A framing/protocol violation, or a reply that never came in time.
    Protocol(String),
    /// The daemon answered `{"ok":false,"error":{…}}` (authorization,
    /// validation, or handler failure).
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

/// Sends `code`/`payload` and returns the `{"ok":true,…}` reply payload,
/// dropping any interleaved `NOTIFICATION` frames (the CLI shows diagnostics
/// progress only through the daemon's own later notifications).
pub fn request(path: &Path, code: Code, payload: Value) -> Result<Value, IpcError> {
    request_collect(path, code, payload, DEFAULT_READ_TIMEOUT).map(|(reply, _)| reply)
}

/// Like [`request`], additionally returning every `NOTIFICATION` payload that
/// preceded the reply on this connection (§5 0x02).
pub fn request_collect(
    path: &Path,
    code: Code,
    payload: Value,
    read_timeout: Duration,
) -> Result<(Value, Vec<Value>), IpcError> {
    let mut stream = UnixStream::connect(path)
        .map_err(|err| IpcError::Unreachable(format!("{}: {err}", path.display())))?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|err| IpcError::Protocol(format!("set_write_timeout: {err}")))?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|err| IpcError::Protocol(format!("set_read_timeout: {err}")))?;

    let bytes = Frame::new(code, payload)
        .encode()
        .map_err(|err| IpcError::Protocol(err.to_string()))?;
    stream
        .write_all(&bytes)
        .map_err(|err| IpcError::Protocol(format!("write: {err}")))?;

    let mut notifications = Vec::new();
    loop {
        let Some(frame) = read_frame(&mut stream)? else {
            // Unknown code byte — log-and-ignore per §5, keep reading.
            continue;
        };
        match frame.code {
            Code::Notification => notifications.push(frame.payload),
            reply_code if reply_code == code => {
                let reply = check_reply(frame.payload)?;
                return Ok((reply, notifications));
            }
            other => {
                return Err(IpcError::Protocol(format!(
                    "unexpected reply frame {other} while waiting for {code}"
                )))
            }
        }
    }
}

/// Reads exactly one frame; `Ok(None)` means the code byte was unknown and
/// the frame was skipped (§5: log-and-ignore).
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
            eprintln!("lustlessctl: ignoring unknown frame code 0x{byte:02x}");
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

/// Enforces the §5 reply envelope: `{"ok":true,…}` passes through,
/// `{"ok":false,"error":{…}}` becomes [`IpcError::Denied`].
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// Serves one connection: reads one frame, replies `reply_frame`, after
    /// optionally pushing `prelude` (NOTIFICATION) frames first.
    fn serve_once(
        listener: std::os::unix::net::UnixListener,
        prelude: Vec<Frame>,
        reply_frame: Frame,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            for frame in prelude {
                sock.write_all(&frame.encode().expect("encode prelude"))
                    .unwrap();
            }
            let mut header = [0u8; FRAME_HEADER_LEN];
            sock.read_exact(&mut header).expect("read header");
            let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let mut body = vec![0u8; len];
            sock.read_exact(&mut body).expect("read body");
            sock.write_all(&reply_frame.encode().expect("encode reply"))
                .unwrap();
        })
    }

    fn temp_socket(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        (dir, path)
    }

    #[test]
    fn request_round_trips_a_filter_level_change() {
        use serde_json::json;
        let (_dir, path) = temp_socket("a.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let handle = serve_once(
            listener,
            vec![],
            Frame::new(
                Code::FilterSetLevel,
                json!({"ok": true, "level": "Strong Blocking"}),
            ),
        );
        let reply = request(
            &path,
            Code::FilterSetLevel,
            json!({"level": "Strong Blocking"}),
        )
        .expect("request");
        assert_eq!(reply["level"], "Strong Blocking");
        handle.join().unwrap();
    }

    #[test]
    fn interleaved_notifications_are_collected_and_reply_still_wins() {
        use serde_json::json;
        let (_dir, path) = temp_socket("b.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let handle = serve_once(
            listener,
            vec![
                Frame::new(
                    Code::Notification,
                    json!({"level": "info", "message": "Diagnostics are being collected…"}),
                ),
                Frame::new(
                    Code::Notification,
                    json!({"level": "info", "message": "We've finished collecting diagnostics"}),
                ),
            ],
            Frame::new(Code::CollectDebugLogs, json!({"ok": true, "started": true})),
        );
        let (reply, notifications) = request_collect(
            &path,
            Code::CollectDebugLogs,
            json!({}),
            Duration::from_secs(5),
        )
        .expect("request");
        assert_eq!(reply["started"], true);
        assert_eq!(notifications.len(), 2);
        assert!(notifications[0]["message"]
            .as_str()
            .unwrap()
            .starts_with("Diagnostics"));
        handle.join().unwrap();
    }

    #[test]
    fn denied_reply_maps_to_denied_error() {
        use serde_json::json;
        let (_dir, path) = temp_socket("c.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let handle = serve_once(
            listener,
            vec![],
            Frame::new(
                Code::FlushOutbox,
                json!({"ok": false, "error": {"code": "forbidden", "message": "root only"}}),
            ),
        );
        let err = request(&path, Code::FlushOutbox, json!({"deadline_sec": 10}))
            .expect_err("must be denied");
        assert!(matches!(&err, IpcError::Denied(m) if m == "root only"));
        handle.join().unwrap();
    }

    #[test]
    fn unknown_frame_codes_are_skipped() {
        use serde_json::json;
        let (_dir, path) = temp_socket("d.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        // Encode a genuinely unknown code byte (0xfe) by hand.
        let unknown_bytes = vec![0xfeu8, 1, 0, 0, 0, b'x'];
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut header = [0u8; FRAME_HEADER_LEN];
            sock.read_exact(&mut header).expect("read header");
            let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let mut body = vec![0u8; len];
            sock.read_exact(&mut body).expect("read body");
            sock.write_all(&unknown_bytes).unwrap();
            sock.write_all(
                &Frame::new(Code::StatusGet, json!({"ok": true}))
                    .encode()
                    .unwrap(),
            )
            .unwrap();
        });
        let reply = request(&path, Code::StatusGet, json!({})).expect("request");
        assert_eq!(reply["ok"], true);
        handle.join().unwrap();
    }

    #[test]
    fn unreachable_socket_is_unreachable_error() {
        let (_dir, path) = temp_socket("missing.sock");
        let err = request(&path, Code::StatusGet, serde_json::json!({})).expect_err("no daemon");
        assert!(matches!(err, IpcError::Unreachable(_)));
    }

    #[test]
    fn read_timeout_is_a_protocol_error() {
        let (_dir, path) = temp_socket("slow.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let handle = thread::spawn(move || {
            // Accept, then hold the connection open without replying until
            // the client's read timeout fires.
            let (_sock, _) = listener.accept().expect("accept");
            thread::sleep(Duration::from_millis(600));
        });
        let err = request_collect(
            &path,
            Code::StatusGet,
            serde_json::json!({}),
            Duration::from_millis(200),
        )
        .expect_err("timeout");
        assert!(matches!(err, IpcError::Protocol(_)));
        handle.join().unwrap();
    }
}
