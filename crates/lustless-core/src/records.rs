//! Typed activity records and their envelope — CONTRACTS §10 ("Activity record
//! vocabulary (five keys, exhaustive in CE)"; evidence:
//! `upload-protocol.md` §5).
//!
//! Every record is wrapped as:
//!
//! ```json
//! { "<recordType>": {
//!     "client": { "architecture": …, "platform": "Linux",
//!                 "platformVersion": …, "version": … },
//!     "timestamp": "<ISO-8601 UTC>",
//!     "utc_datetime_created": "<ISO-8601 UTC>",
//!     …record fields…
//! } }
//! ```
//!
//! The `client` block and `timestamp` come from the envelope builder
//! (`FUN_14038b110` in CE), the shared key `utc_datetime_created` carries the
//! source row's creation time (`upload-protocol.md` §5).

use serde_json::{json, Map, Value};

/// The `platform` value of the client block (§10: `"platform":"Linux"`).
pub const PLATFORM: &str = "Linux";

/// The five exhaustive record keys of §10 (`upload-protocol.md` §5 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    /// `webActivityRecord` — from `dns_activity`.
    WebActivity,
    /// `loginActivityRecord` — from `logins`.
    Login,
    /// `circumventionRecord` — from `circumventions`.
    Circumvention,
    /// `switchUserActivityRecord` — from `switch_users`.
    SwitchUser,
    /// `installActivityRecord` — install report.
    Install,
}

impl RecordType {
    /// All five record keys, in §10 order.
    pub const ALL: [RecordType; 5] = [
        RecordType::WebActivity,
        RecordType::Login,
        RecordType::Circumvention,
        RecordType::SwitchUser,
        RecordType::Install,
    ];

    /// The verbatim record key (§10).
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordType::WebActivity => "webActivityRecord",
            RecordType::Login => "loginActivityRecord",
            RecordType::Circumvention => "circumventionRecord",
            RecordType::SwitchUser => "switchUserActivityRecord",
            RecordType::Install => "installActivityRecord",
        }
    }
}

/// The `client` block of the envelope (§10):
/// `{"architecture","platform":"Linux","platformVersion","version"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientBlock {
    /// CE renders `"32"`/`"64"` (evidence: `upload-protocol.md` §5);
    /// [`local_architecture`] provides the host value.
    pub architecture: String,
    /// OS release string (e.g. `/etc/os-release` `VERSION_ID`).
    pub platform_version: String,
    /// Client version (§1: `0.1.9` — see
    /// [`LUSTLESS_VERSION`](crate::LUSTLESS_VERSION)).
    pub version: String,
}

impl ClientBlock {
    /// Builds a client block with explicit components.
    pub fn new(
        architecture: impl Into<String>,
        platform_version: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        ClientBlock {
            architecture: architecture.into(),
            platform_version: platform_version.into(),
            version: version.into(),
        }
    }

    /// Client block for this machine: architecture from
    /// [`local_architecture`], the rest supplied by the caller.
    pub fn local(platform_version: impl Into<String>, version: impl Into<String>) -> Self {
        ClientBlock::new(local_architecture(), platform_version, version)
    }

    fn to_json(&self) -> Value {
        json!({
            "architecture": self.architecture,
            "platform": PLATFORM,
            "platformVersion": self.platform_version,
            "version": self.version,
        })
    }
}

/// CE's client-block architecture strings: `"64"` on 64-bit targets, `"32"`
/// elsewhere (evidence: `upload-protocol.md` §5, `"architecture": "32"|"64"`).
pub fn local_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" | "aarch64" => "64",
        _ => "32",
    }
}

/// Per-record envelope inputs shared by all five builders (§10):
/// the `client` block, the record `timestamp`, and the shared
/// `utc_datetime_created` key (the source row's creation time).
#[derive(Debug, Clone, Copy)]
pub struct RecordContext<'a> {
    /// Client block (§10).
    pub client: &'a ClientBlock,
    /// Envelope `timestamp` — render through
    /// [`ClockAnchor::now_iso8601`](crate::clock::ClockAnchor::now_iso8601)
    /// at submission time (§10 clock anchor).
    pub timestamp: &'a str,
    /// Shared key `utc_datetime_created` — the row's `datetime_created` /
    /// `timestamp` column in ISO-8601 UTC (§6.1).
    pub utc_datetime_created: &'a str,
}

impl<'a> RecordContext<'a> {
    /// Builds a record context.
    pub fn new(client: &'a ClientBlock, timestamp: &'a str, utc_datetime_created: &'a str) -> Self {
        RecordContext {
            client,
            timestamp,
            utc_datetime_created,
        }
    }
}

/// Wraps record fields as `{"<recordType>": {client, timestamp,
/// utc_datetime_created, …fields}}` (§10).
fn wrap(record_type: RecordType, ctx: &RecordContext<'_>, fields: Map<String, Value>) -> Value {
    let mut inner = Map::new();
    inner.insert("client".into(), ctx.client.to_json());
    inner.insert("timestamp".into(), json!(ctx.timestamp));
    inner.insert(
        "utc_datetime_created".into(),
        json!(ctx.utc_datetime_created),
    );
    inner.extend(fields);
    let mut outer = Map::new();
    outer.insert(record_type.as_str().into(), Value::Object(inner));
    Value::Object(outer)
}

/// Turns a `json!` object literal into the field map (builders always pass an
/// object by construction).
fn fields_of(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => unreachable!("record fields are an object, got {other}"),
    }
}

/// `webActivityRecord` fields — the `dns_activity` row vocabulary (§10;
/// `upload-protocol.md` §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebActivityFields {
    /// Queried domain.
    pub domain: String,
    /// Attributing process id (`"unknown"` tolerated default, §8).
    pub process_id: Option<String>,
    /// Attributing process name (`"unknown"` tolerated default, §8).
    pub process_name: String,
    /// Answer address.
    pub ip: Option<String>,
    /// `resolution_type` verdict vocabulary (§8 table).
    pub resolution_type: String,
    /// Connection type of the query.
    pub connection_type: Option<String>,
    /// `X-CB-Location`-style response-header tag (§8).
    pub resolution_datacenter: Option<String>,
    /// Resolution time in milliseconds.
    pub resolution_time_ms: Option<String>,
}

/// Builds a `webActivityRecord` (§10) from a `dns_activity` row.
pub fn web_activity_record(ctx: &RecordContext<'_>, fields: WebActivityFields) -> Value {
    wrap(
        RecordType::WebActivity,
        ctx,
        fields_of(json!({
            "domain": fields.domain,
            "process_id": fields.process_id,
            "process_name": fields.process_name,
            "ip": fields.ip,
            "resolution_type": fields.resolution_type,
            "connection_type": fields.connection_type,
            "resolution_datacenter": fields.resolution_datacenter,
            "resolution_time_ms": fields.resolution_time_ms,
        })),
    )
}

/// `loginActivityRecord` fields — the `logins` row vocabulary (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginActivityFields {
    /// Login timestamp of the session.
    pub login_at: String,
    /// Logout timestamp, `None` while the session is open.
    pub logout_at: Option<String>,
    /// OS account id mapped to the CE account.
    pub system_user_id: Option<String>,
    /// OS account name mapped to the CE account.
    pub system_user_name: Option<String>,
}

/// Builds a `loginActivityRecord` (§10) from a `logins` row.
pub fn login_activity_record(ctx: &RecordContext<'_>, fields: LoginActivityFields) -> Value {
    wrap(
        RecordType::Login,
        ctx,
        fields_of(json!({
            "login_at": fields.login_at,
            "logout_at": fields.logout_at,
            "system_user_id": fields.system_user_id,
            "system_user_name": fields.system_user_name,
        })),
    )
}

/// `circumventionRecord` fields — the `circumventions` row vocabulary (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircumventionFields {
    /// Kind of interruption (§6.3 tamper signal, §7 restricted windows).
    pub interruption_type: String,
    /// Application name.
    pub app_name: String,
    /// Window title at the time of the event.
    pub app_window_title: Option<String>,
    /// Device id (see [`new_device_id`](crate::ids::new_device_id)).
    pub device_id: String,
    /// Local `timezone_offset` beside the UTC timestamp (§6.1).
    pub timezone_offset: String,
}

/// Builds a `circumventionRecord` (§10) from a `circumventions` row. This is
/// the only screen-adjacent record that may be uploaded (§7: app + window
/// title of flagged/restricted windows; gated by
/// `upload.circumvention_records`).
pub fn circumvention_record(ctx: &RecordContext<'_>, fields: CircumventionFields) -> Value {
    wrap(
        RecordType::Circumvention,
        ctx,
        fields_of(json!({
            "interruption_type": fields.interruption_type,
            "app_name": fields.app_name,
            "app_window_title": fields.app_window_title,
            "device_id": fields.device_id,
            "timezone_offset": fields.timezone_offset,
        })),
    )
}

/// `switchUserActivityRecord` fields — the `switch_users` row vocabulary.
/// Record keys are CE's `switch_from_username` / `switch_to_username`
/// (`upload-protocol.md` §5), not the table's `switch_user_from` /
/// `switch_user_to` columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchUserFields {
    /// Username the session switched away from.
    pub switch_from_username: String,
    /// Username the session switched to.
    pub switch_to_username: String,
    /// Device name.
    pub device_name: Option<String>,
    /// Device id.
    pub device_id: String,
}

/// Builds a `switchUserActivityRecord` (§10) from a `switch_users` row.
pub fn switch_user_activity_record(ctx: &RecordContext<'_>, fields: SwitchUserFields) -> Value {
    wrap(
        RecordType::SwitchUser,
        ctx,
        fields_of(json!({
            "switch_from_username": fields.switch_from_username,
            "switch_to_username": fields.switch_to_username,
            "device_name": fields.device_name,
            "device_id": fields.device_id,
        })),
    )
}

/// `installActivityRecord` fields (§10; `upload-protocol.md` §5 —
/// `device_uuid`, `platform`, `platformVersion`, `architecture`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallFields {
    /// Install/device uuid.
    pub device_uuid: String,
    /// OS release string for the record's `platformVersion` key.
    pub platform_version: String,
    /// `"32"`/`"64"` for the record's `architecture` key.
    pub architecture: String,
}

/// Builds an `installActivityRecord` (§10) — the postinst install report
/// (§15). The record's `platform` key is fixed to `"Linux"`.
pub fn install_activity_record(ctx: &RecordContext<'_>, fields: InstallFields) -> Value {
    wrap(
        RecordType::Install,
        ctx,
        fields_of(json!({
            "device_uuid": fields.device_uuid,
            "platform": PLATFORM,
            "platformVersion": fields.platform_version,
            "architecture": fields.architecture,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_keys_match_contract_section_10() {
        let keys: Vec<&str> = RecordType::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "webActivityRecord",
                "loginActivityRecord",
                "circumventionRecord",
                "switchUserActivityRecord",
                "installActivityRecord",
            ]
        );
    }

    #[test]
    fn client_block_shape() {
        let block = ClientBlock::new("64", "22.04", "0.1.0");
        assert_eq!(
            block.to_json(),
            json!({
                "architecture": "64",
                "platform": "Linux",
                "platformVersion": "22.04",
                "version": "0.1.0",
            })
        );
        let arch = local_architecture();
        assert!(arch == "64" || arch == "32");
        let expected = if matches!(std::env::consts::ARCH, "x86_64" | "aarch64") {
            "64"
        } else {
            "32"
        };
        assert_eq!(arch, expected);
    }

    #[test]
    fn web_activity_envelope_shape() {
        let client = ClientBlock::new("64", "22.04", "0.1.0");
        let ctx = RecordContext::new(&client, "2026-10-11T12:00:00Z", "2026-10-11T11:59:58Z");
        let record = web_activity_record(
            &ctx,
            WebActivityFields {
                domain: "example.test".into(),
                process_id: Some("4321".into()),
                process_name: "firefox".into(),
                ip: None,
                resolution_type: "BlockedCustom".into(),
                connection_type: Some("dns".into()),
                resolution_datacenter: None,
                resolution_time_ms: Some("12".into()),
            },
        );

        // Exactly one top-level key: the record type (§10).
        let object = record.as_object().expect("object");
        assert_eq!(object.len(), 1);
        let inner = &object["webActivityRecord"];
        let inner = inner.as_object().expect("inner object");

        assert_eq!(
            inner["client"],
            json!({
                "architecture": "64",
                "platform": "Linux",
                "platformVersion": "22.04",
                "version": "0.1.0",
            })
        );
        assert_eq!(inner["timestamp"], json!("2026-10-11T12:00:00Z"));
        assert_eq!(inner["utc_datetime_created"], json!("2026-10-11T11:59:58Z"));
        assert_eq!(inner["domain"], json!("example.test"));
        assert_eq!(inner["resolution_type"], json!("BlockedCustom"));
        assert_eq!(inner["ip"], Value::Null);
        for key in [
            "process_id",
            "process_name",
            "connection_type",
            "resolution_datacenter",
            "resolution_time_ms",
        ] {
            assert!(inner.contains_key(key), "missing webActivity field {key}");
        }
    }

    #[test]
    fn login_record_envelope_shape() {
        let client = ClientBlock::new("64", "22.04", "0.1.0");
        let ctx = RecordContext::new(&client, "ts", "created");
        let record = login_activity_record(
            &ctx,
            LoginActivityFields {
                login_at: "2026-10-11T10:00:00Z".into(),
                logout_at: None,
                system_user_id: Some("1000".into()),
                system_user_name: Some("alice".into()),
            },
        );
        let inner = &record["loginActivityRecord"];
        assert_eq!(inner["login_at"], json!("2026-10-11T10:00:00Z"));
        assert_eq!(inner["logout_at"], Value::Null);
        assert_eq!(inner["system_user_name"], json!("alice"));
        assert_eq!(inner["client"]["platform"], json!("Linux"));
        assert_eq!(inner["timestamp"], json!("ts"));
        assert_eq!(inner["utc_datetime_created"], json!("created"));
    }

    #[test]
    fn circumvention_record_envelope_shape() {
        let client = ClientBlock::new("64", "22.04", "0.1.0");
        let ctx = RecordContext::new(&client, "ts", "created");
        let record = circumvention_record(
            &ctx,
            CircumventionFields {
                interruption_type: "pdl_transaction_removed".into(),
                app_name: "evilapp".into(),
                app_window_title: Some("Secret".into()),
                device_id: "0123456789abcdef0123456789abcdef".into(),
                timezone_offset: "-05:00".into(),
            },
        );
        let inner = &record["circumventionRecord"];
        assert_eq!(inner["interruption_type"], json!("pdl_transaction_removed"));
        assert_eq!(inner["app_name"], json!("evilapp"));
        assert_eq!(inner["app_window_title"], json!("Secret"));
        assert_eq!(
            inner["device_id"],
            json!("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(inner["timezone_offset"], json!("-05:00"));
    }

    #[test]
    fn switch_user_record_uses_ce_record_keys() {
        let client = ClientBlock::new("64", "22.04", "0.1.0");
        let ctx = RecordContext::new(&client, "ts", "created");
        let record = switch_user_activity_record(
            &ctx,
            SwitchUserFields {
                switch_from_username: "alice".into(),
                switch_to_username: "bob".into(),
                device_name: Some("workstation".into()),
                device_id: "0123456789abcdef0123456789abcdef".into(),
            },
        );
        let inner = record["switchUserActivityRecord"]
            .as_object()
            .expect("inner object");
        // CE's record keys (upload-protocol.md §5) — NOT the table columns.
        assert_eq!(inner["switch_from_username"], json!("alice"));
        assert_eq!(inner["switch_to_username"], json!("bob"));
        assert!(!inner.contains_key("switch_user_from"));
        assert!(!inner.contains_key("switch_user_to"));
        assert_eq!(inner["device_name"], json!("workstation"));
        assert_eq!(inner["client"]["platform"], json!("Linux"));
    }

    #[test]
    fn install_record_shape() {
        // Sentinel version, deliberately not `LUSTLESS_VERSION`: this pins that
        // the emitted record carries the client block through verbatim, and it
        // must not start failing every time the product version is bumped.
        let client = ClientBlock::new("64", "22.04", "9.9.9-sentinel");
        let ctx = RecordContext::new(&client, "ts", "created");
        let record = install_activity_record(
            &ctx,
            InstallFields {
                device_uuid: "7c9e6679-7425-40de-944b-e07fc1f90ae7".into(),
                platform_version: "22.04".into(),
                architecture: "64".into(),
            },
        );
        let inner = record["installActivityRecord"].as_object().expect("object");
        assert_eq!(
            inner["device_uuid"],
            json!("7c9e6679-7425-40de-944b-e07fc1f90ae7")
        );
        assert_eq!(inner["platform"], json!("Linux"));
        assert_eq!(inner["platformVersion"], json!("22.04"));
        assert_eq!(inner["architecture"], json!("64"));
        assert_eq!(inner["client"]["version"], json!("9.9.9-sentinel"));
    }
}
