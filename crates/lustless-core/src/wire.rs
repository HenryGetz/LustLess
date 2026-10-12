//! IPC frame codec and authorization scopes — CONTRACTS §5
//! ("agent/CLI ↔ daemon", Unix stream socket `/run/lustless/lustlessd.sock`).
//!
//! Framing: `u8 code | u32 LE length | payload`, payload is UTF-8 JSON, max
//! frame 64 KiB. Unknown codes are surfaced as [`DecodeOutcome::UnknownCode`]
//! so the reader can log-and-ignore them (CE behavior, §5; `service-ipc.md` §2).

use serde_json::Value;

use crate::CoreError;

/// Maximum frame size in bytes, header included (§5: "Max frame 64 KiB").
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Size of the fixed frame header: `u8 code` + `u32 LE length` (§5).
pub const FRAME_HEADER_LEN: usize = 5;

/// Wire vocabulary of §5. CE codes are kept verbatim (`91-linux-mapping.md` §4;
/// `service-ipc.md` §2), LustLess extensions live in the `0x60+` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Code {
    /// 0x02 `NOTIFICATION` — daemon→client progress/notification frame (§5).
    Notification = 0x02,
    /// 0x43 `COLLECT_DEBUG_LOGS` — collect diagnostics (§5).
    CollectDebugLogs = 0x43,
    /// 0x4c `USER_LOGOUT` — (§5).
    UserLogout = 0x4c,
    /// 0x4d `SEND_METRICS` — flush the metrics outbox now (§5).
    SendMetrics = 0x4d,
    /// 0x51 `QUIT` — root only (§5).
    Quit = 0x51,
    /// 0x52 `SET_CLIENT_CONFIG` — was `SET_WINDOWS_REGISTRY`; the registry
    /// semantics die with Windows, the code is kept (§5).
    SetClientConfig = 0x52,
    /// 0x53 `USER_SETTINGS_CHANGE` — (§5).
    UserSettingsChange = 0x53,
    /// 0x54 `SEND_TELEMETRY` — flush telemetry now (§5).
    SendTelemetry = 0x54,
    /// 0x55 `POLL` — empty-poll sentinel; drains notifications or returns an
    /// empty frame (§5).
    Poll = 0x55,
    /// 0x60 `POLICY_GET` — replies with a `PolicySnapshot` (§9).
    PolicyGet = 0x60,
    /// 0x61 `STATUS_GET` — daemon status (§5).
    StatusGet = 0x61,
    /// 0x62 `DNS_ACTIVITY_QUERY` — dashboard query; self sees own rows, root
    /// sees all (§5, §8).
    DnsActivityQuery = 0x62,
    /// 0x63 `FILTER_SET_LEVEL` — (§5).
    FilterSetLevel = 0x63,
    /// 0x64 `FILTER_SET_OVERRIDES` — payload `{"domain","verdict"}` (§5).
    FilterSetOverrides = 0x64,
    /// 0x65 `SIGN_IN` — password never stored (§5, §10).
    SignIn = 0x65,
    /// 0x66 `SIGN_OUT` — (§5).
    SignOut = 0x66,
    /// 0x67 `UPDATE_CHECK` — replies with a recommendation (§12).
    UpdateCheck = 0x67,
    /// 0x68 `BREAK_GLASS` — root only; polkit `org.lustless.break-glass`
    /// precedes it in the daemon (§5).
    BreakGlass = 0x68,
    /// 0x69 `FLUSH_OUTBOX` — root only; `lustlessctl flush` in `prerm` (§5/§11).
    FlushOutbox = 0x69,
}

impl Code {
    /// Every code of the §5 wire-vocabulary table, in numeric order.
    pub const ALL: [Code; 19] = [
        Code::Notification,
        Code::CollectDebugLogs,
        Code::UserLogout,
        Code::SendMetrics,
        Code::Quit,
        Code::SetClientConfig,
        Code::UserSettingsChange,
        Code::SendTelemetry,
        Code::Poll,
        Code::PolicyGet,
        Code::StatusGet,
        Code::DnsActivityQuery,
        Code::FilterSetLevel,
        Code::FilterSetOverrides,
        Code::SignIn,
        Code::SignOut,
        Code::UpdateCheck,
        Code::BreakGlass,
        Code::FlushOutbox,
    ];

    /// Maps a raw byte to a known §5 code; `None` = unknown code (the reader
    /// logs and ignores the frame, §5).
    pub const fn from_u8(byte: u8) -> Option<Code> {
        match byte {
            0x02 => Some(Code::Notification),
            0x43 => Some(Code::CollectDebugLogs),
            0x4c => Some(Code::UserLogout),
            0x4d => Some(Code::SendMetrics),
            0x51 => Some(Code::Quit),
            0x52 => Some(Code::SetClientConfig),
            0x53 => Some(Code::UserSettingsChange),
            0x54 => Some(Code::SendTelemetry),
            0x55 => Some(Code::Poll),
            0x60 => Some(Code::PolicyGet),
            0x61 => Some(Code::StatusGet),
            0x62 => Some(Code::DnsActivityQuery),
            0x63 => Some(Code::FilterSetLevel),
            0x64 => Some(Code::FilterSetOverrides),
            0x65 => Some(Code::SignIn),
            0x66 => Some(Code::SignOut),
            0x67 => Some(Code::UpdateCheck),
            0x68 => Some(Code::BreakGlass),
            0x69 => Some(Code::FlushOutbox),
            _ => None,
        }
    }

    /// The raw wire byte of the code (§5 table).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The CE/LustLess vocabulary name of the code (§5 table).
    pub const fn name(self) -> &'static str {
        match self {
            Code::Notification => "NOTIFICATION",
            Code::CollectDebugLogs => "COLLECT_DEBUG_LOGS",
            Code::UserLogout => "USER_LOGOUT",
            Code::SendMetrics => "SEND_METRICS",
            Code::Quit => "QUIT",
            Code::SetClientConfig => "SET_CLIENT_CONFIG",
            Code::UserSettingsChange => "USER_SETTINGS_CHANGE",
            Code::SendTelemetry => "SEND_TELEMETRY",
            Code::Poll => "POLL",
            Code::PolicyGet => "POLICY_GET",
            Code::StatusGet => "STATUS_GET",
            Code::DnsActivityQuery => "DNS_ACTIVITY_QUERY",
            Code::FilterSetLevel => "FILTER_SET_LEVEL",
            Code::FilterSetOverrides => "FILTER_SET_OVERRIDES",
            Code::SignIn => "SIGN_IN",
            Code::SignOut => "SIGN_OUT",
            Code::UpdateCheck => "UPDATE_CHECK",
            Code::BreakGlass => "BREAK_GLASS",
            Code::FlushOutbox => "FLUSH_OUTBOX",
        }
    }

    /// The authorization scope of the code, straight from the auth column of
    /// the §5 table (see [`AuthScope`] for how the column's three phrasings map
    /// onto the three variants).
    pub const fn auth_scope(self) -> AuthScope {
        match self {
            // "connection" (accept any peer that completed SO_PEERCRED, §5).
            Code::Notification | Code::Poll | Code::SignIn => AuthScope::Connection,
            // "self" and "root or self" both collapse into `SelfScope` — a
            // root peer may act for any uid (see `authorize`).
            Code::CollectDebugLogs
            | Code::UserLogout
            | Code::SendMetrics
            | Code::UserSettingsChange
            | Code::SendTelemetry
            | Code::PolicyGet
            | Code::StatusGet
            | Code::DnsActivityQuery
            | Code::FilterSetLevel
            | Code::FilterSetOverrides
            | Code::SignOut
            | Code::UpdateCheck => AuthScope::SelfScope,
            // "root only" (§5).
            Code::Quit | Code::SetClientConfig | Code::BreakGlass | Code::FlushOutbox => {
                AuthScope::RootOnly
            }
        }
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Authorization scope derived from the auth column of the §5 wire table.
///
/// The column has three phrasings — *connection*, *self* / *root or self*, and
/// *root only* — which map onto these three variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScope {
    /// Serve any peer whose `SO_PEERCRED` was read (§5 "connection").
    Connection,
    /// Serve the target user itself (§5 "self") or root acting on its behalf
    /// (§5 "root or self"; root owns the machine and runs the daemon, so the
    /// extra uid-0 allowance is not a privilege escalation).
    SelfScope,
    /// Serve only uid 0 (§5 "root only").
    RootOnly,
}

/// uid 0 — the daemon's own uid, the only "root" principal (§5).
pub const ROOT_UID: u32 = 0;

/// Decides whether a connection may be served a frame with `code`.
///
/// `peer_uid` is the uid from `SO_PEERCRED` (§5) and `target_uid` is the uid
/// of the user the frame concerns (0 for connection-scope frames).
pub fn authorize(code: Code, peer_uid: u32, target_uid: u32) -> bool {
    match code.auth_scope() {
        AuthScope::Connection => true,
        AuthScope::SelfScope => peer_uid == ROOT_UID || peer_uid == target_uid,
        AuthScope::RootOnly => peer_uid == ROOT_UID,
    }
}

/// One decoded frame: `u8 code` (already resolved to a known [`Code`]) plus
/// the parsed JSON payload (§5).
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// The known wire code of the frame.
    pub code: Code,
    /// The UTF-8 JSON payload. A zero-length payload decodes to
    /// [`Value::Null`] (CE's empty `POLL` frame, §5); `Null` encodes back to
    /// a zero-length payload, so byte round-trips are exact.
    pub payload: Value,
}

/// Result of [`Frame::decode`].
#[derive(Debug, Clone, PartialEq)]
pub enum DecodeOutcome {
    /// A known §5 code with its parsed payload.
    Frame(Frame),
    /// An unrecognized code byte: the reader MUST log it and ignore the frame
    /// (§5, `service-ipc.md` §2) and carry on.
    UnknownCode(u8),
}

impl Frame {
    /// Builds a frame for a known code.
    pub fn new(code: Code, payload: Value) -> Frame {
        Frame { code, payload }
    }

    /// Encodes the frame as `u8 code | u32 LE length | UTF-8 JSON payload`
    /// (§5). [`Value::Null`] is written as a zero-length payload.
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        let body = if self.payload.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&self.payload)?
        };
        if FRAME_HEADER_LEN + body.len() > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge);
        }
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
        out.push(self.code.as_u8());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decodes exactly one frame from `bytes` (header + payload, nothing
    /// else).
    ///
    /// Errors: [`CoreError::InvalidFrame`] for a truncated header, a length
    /// that does not match the buffer, or non-UTF-8/non-JSON payload;
    /// [`CoreError::FrameTooLarge`] for a declared length over the 64 KiB cap
    /// (rejected before the payload is even looked at). An unknown code is not
    /// an error — it decodes to [`DecodeOutcome::UnknownCode`] so the caller
    /// can log-and-ignore it (§5).
    pub fn decode(bytes: &[u8]) -> Result<DecodeOutcome, CoreError> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(CoreError::InvalidFrame(format!(
                "truncated header: {} of {} bytes",
                bytes.len(),
                FRAME_HEADER_LEN
            )));
        }
        let code_byte = bytes[0];
        let payload_len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        if FRAME_HEADER_LEN + payload_len > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge);
        }
        if bytes.len() != FRAME_HEADER_LEN + payload_len {
            return Err(CoreError::InvalidFrame(format!(
                "declared payload length {payload_len} does not match {} total bytes",
                bytes.len()
            )));
        }
        // §5: unknown codes are log-and-ignore — classify the code byte before
        // touching the payload so a garbage payload can't fail the frame.
        let code = match Code::from_u8(code_byte) {
            Some(code) => code,
            None => return Ok(DecodeOutcome::UnknownCode(code_byte)),
        };
        let payload = if payload_len == 0 {
            Value::Null
        } else {
            let text = std::str::from_utf8(&bytes[FRAME_HEADER_LEN..])
                .map_err(|e| CoreError::InvalidFrame(format!("payload is not valid UTF-8: {e}")))?;
            serde_json::from_str(text)?
        };
        Ok(DecodeOutcome::Frame(Frame { code, payload }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_every_known_code() {
        let payload = json!({"level": 2, "domain": "example.test", "nested": {"a": [1, 2]}});
        for code in Code::ALL {
            let frame = Frame::new(code, payload.clone());
            let bytes = frame.encode().expect("encode");
            let body_len = serde_json::to_vec(&payload).expect("payload length").len();
            assert_eq!(
                bytes.len(),
                FRAME_HEADER_LEN + body_len,
                "framing for {code}"
            );
            assert_eq!(bytes[0], code.as_u8());
            let outcome = Frame::decode(&bytes).expect("decode");
            match outcome {
                DecodeOutcome::Frame(got) => assert_eq!(got, frame),
                DecodeOutcome::UnknownCode(b) => panic!("known code {code} decoded as {b:#04x}"),
            }
        }
    }

    #[test]
    fn code_bytes_match_contract_section_5() {
        assert_eq!(Code::Notification.as_u8(), 0x02);
        assert_eq!(Code::CollectDebugLogs.as_u8(), 0x43);
        assert_eq!(Code::UserLogout.as_u8(), 0x4c);
        assert_eq!(Code::SendMetrics.as_u8(), 0x4d);
        assert_eq!(Code::Quit.as_u8(), 0x51);
        assert_eq!(Code::SetClientConfig.as_u8(), 0x52);
        assert_eq!(Code::UserSettingsChange.as_u8(), 0x53);
        assert_eq!(Code::SendTelemetry.as_u8(), 0x54);
        assert_eq!(Code::Poll.as_u8(), 0x55);
        assert_eq!(Code::PolicyGet.as_u8(), 0x60);
        assert_eq!(Code::StatusGet.as_u8(), 0x61);
        assert_eq!(Code::DnsActivityQuery.as_u8(), 0x62);
        assert_eq!(Code::FilterSetLevel.as_u8(), 0x63);
        assert_eq!(Code::FilterSetOverrides.as_u8(), 0x64);
        assert_eq!(Code::SignIn.as_u8(), 0x65);
        assert_eq!(Code::SignOut.as_u8(), 0x66);
        assert_eq!(Code::UpdateCheck.as_u8(), 0x67);
        assert_eq!(Code::BreakGlass.as_u8(), 0x68);
        assert_eq!(Code::FlushOutbox.as_u8(), 0x69);
        // Every code of §5 round-trips through from_u8.
        for code in Code::ALL {
            assert_eq!(Code::from_u8(code.as_u8()), Some(code));
        }
        assert_eq!(Code::from_u8(0x03), None);
        assert_eq!(Code::from_u8(0x6a), None);
    }

    #[test]
    fn unknown_code_is_surfaced_for_log_and_ignore() {
        // 0x01 is not in the §5 vocabulary: decode must yield UnknownCode.
        let bytes = [0x01, 0x02, 0x00, 0x00, 0x00, b'{', b'}'];
        match Frame::decode(&bytes).expect("unknown code is not an error") {
            DecodeOutcome::UnknownCode(byte) => assert_eq!(byte, 0x01),
            DecodeOutcome::Frame(f) => panic!("unexpectedly known: {f:?}"),
        }
    }

    #[test]
    fn oversize_frames_are_rejected_on_encode_and_decode() {
        let big = json!("x".repeat(MAX_FRAME_LEN));
        let err = Frame::new(Code::Notification, big).encode().unwrap_err();
        assert!(matches!(err, CoreError::FrameTooLarge), "{err:?}");

        // Header declaring a 64 KiB payload (total would be 65541 bytes).
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = Code::Poll.as_u8();
        header[1..].copy_from_slice(&(MAX_FRAME_LEN as u32).to_le_bytes());
        let err = Frame::decode(&header).unwrap_err();
        assert!(matches!(err, CoreError::FrameTooLarge), "{err:?}");
    }

    #[test]
    fn truncated_and_mismatched_frames_error() {
        assert!(matches!(
            Frame::decode(&[0x55]).unwrap_err(),
            CoreError::InvalidFrame(_)
        ));
        assert!(matches!(
            Frame::decode(&[0x55, 0x05, 0x00, 0x00, 0x00, b'{']).unwrap_err(),
            CoreError::InvalidFrame(_)
        ));
        // Declared length 0 but extra trailing bytes after the header.
        assert!(matches!(
            Frame::decode(&[0x55, 0x00, 0x00, 0x00, 0x00, b'x']).unwrap_err(),
            CoreError::InvalidFrame(_)
        ));
        // Payload is not JSON.
        assert!(matches!(
            Frame::decode(&[0x43, 0x03, 0x00, 0x00, 0x00, b'n', b'o', b'!']).unwrap_err(),
            CoreError::Json(_)
        ));
    }

    #[test]
    fn empty_poll_frame_round_trips_byte_exact() {
        let frame = Frame::new(Code::Poll, Value::Null);
        let bytes = frame.encode().expect("encode empty");
        assert_eq!(bytes, vec![0x55, 0x00, 0x00, 0x00, 0x00]);
        let decoded = Frame::decode(&bytes).expect("decode empty");
        assert_eq!(decoded, DecodeOutcome::Frame(frame.clone()));
        assert_eq!(frame.encode().expect("re-encode"), bytes);
    }

    #[test]
    fn auth_scopes_follow_the_section_5_table() {
        use AuthScope::*;
        for code in Code::ALL {
            let expected = match code {
                Code::Notification | Code::Poll | Code::SignIn => Connection,
                Code::Quit | Code::SetClientConfig | Code::BreakGlass | Code::FlushOutbox => {
                    RootOnly
                }
                _ => SelfScope,
            };
            assert_eq!(code.auth_scope(), expected, "scope of {code}");
        }
    }

    #[test]
    fn authorize_matrix() {
        let peer_user = 1000;
        let target_user = 1000;
        let other_user = 1001;

        // Connection scope: anyone.
        assert!(authorize(Code::Poll, peer_user, target_user));
        assert!(authorize(Code::SignIn, other_user, target_user));

        // Self scope: the target user, or root ("root or self", §5).
        assert!(authorize(Code::UserLogout, target_user, target_user));
        assert!(authorize(Code::UserLogout, ROOT_UID, target_user));
        assert!(!authorize(Code::UserLogout, other_user, target_user));

        // Root only: nobody but uid 0.
        assert!(authorize(Code::Quit, ROOT_UID, target_user));
        assert!(!authorize(Code::Quit, peer_user, target_user));
        assert!(!authorize(Code::BreakGlass, peer_user, target_user));
        assert!(!authorize(Code::FlushOutbox, peer_user, target_user));
        assert!(!authorize(Code::SetClientConfig, peer_user, target_user));
    }
}
