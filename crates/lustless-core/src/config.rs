//! System configuration `/etc/lustless/lustless.toml` — CONTRACTS §9.1.
//!
//! Behavior required by §9.1:
//! * every key has a documented default matching the shipped sample below;
//! * unknown keys are ignored **with a warning**;
//! * a parse failure falls back to the defaults and logs
//!   `config parse failed: <err>` (that exact wording is the display form of
//!   [`CoreError::ConfigParse`](crate::CoreError::ConfigParse)).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::CoreError;

/// System configuration (§9.1, top-level TOML tables).
///
/// Missing tables/keys fall back to the section defaults; unknown keys are
/// ignored with a warning (§9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LustlessConfig {
    /// `[daemon]` — socket, dashboard, state dir.
    pub daemon: DaemonConfig,
    /// `[dns]` — forwarder, DoH, block page.
    pub dns: DnsConfig,
    /// `[capture]` — capture backend and cadence.
    pub capture: CaptureConfig,
    /// `[classifier]` — spawned scoring process.
    pub classifier: ClassifierConfig,
    /// `[upload]` — outbox uploader.
    pub upload: UploadConfig,
    /// `[update]` — signed update feed.
    pub update: UpdateConfig,
}

/// `[daemon]` section (§9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    /// IPC Unix stream socket path (§5).
    pub socket_path: String,
    /// Whether the embedded dashboard (§13) is served.
    pub dashboard_enabled: bool,
    /// Dashboard listen port (§13: `127.0.0.1:8760`).
    pub dashboard_port: u16,
    /// Daemon state root (§4: `/var/lib/lustless`).
    pub state_dir: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            socket_path: "/run/lustless/lustlessd.sock".into(),
            dashboard_enabled: true,
            dashboard_port: 8760,
            state_dir: "/var/lib/lustless".into(),
        }
    }
}

/// `[dns]` section (§9.1). Names match their effect — no inverted flags (the
/// CE `DnsProxyDisable` lesson, §9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Whether the forwarder listens at all.
    pub enabled: bool,
    /// Listener address (§8: `127.0.0.2:53`).
    pub listen: String,
    /// RFC 8484 DoH endpoint of the filter path (§8).
    pub doh_url: String,
    /// User-path resolvers; `"system"` reads the current upstream resolvers
    /// (§8 dual resolution).
    pub user_resolvers: Vec<String>,
    /// Serve the loopback block page on blocked answers (§8).
    pub block_page: bool,
    /// Block-page vhost (§8: `blocked.lustless.local`).
    pub block_page_host: String,
    /// "signed out ⇒ web blocked" product semantic (§8 fail-closed flag).
    pub fail_closed_when_signed_out: bool,
    /// DoH connections per endpoint (§8: pool ≤5).
    pub pool_size: u8,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            enabled: true,
            listen: "127.0.0.2:53".into(),
            doh_url: "https://dns.cleanbrowsing.org/doh/adult-filter".into(),
            user_resolvers: vec!["system".into()],
            block_page: true,
            block_page_host: "blocked.lustless.local".into(),
            fail_closed_when_signed_out: true,
            pool_size: 5,
        }
    }
}

/// `[capture]` section (§9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    /// Whether screen-state capture runs (§7).
    pub enabled: bool,
    /// Backend: `auto | x11 | wayland` (§7).
    pub backend: String,
    /// Base capture interval in seconds before jitter (§7 cadence).
    pub interval_sec: u64,
    /// Jitter `±%` around `interval_sec` (§7: `sleep ~ U[(1−v)·I, (1+v)·I]`).
    pub variance_pct: u8,
    /// Screenstate spool root (§6.3/§4).
    pub spool_dir: String,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            enabled: true,
            backend: "auto".into(),
            interval_sec: 30,
            variance_pct: 20,
            spool_dir: "/var/lib/lustless/spool".into(),
        }
    }
}

/// `[classifier]` section (§9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClassifierConfig {
    /// Whether the daemon spawns the classifier (§7 launch contract).
    pub enabled: bool,
    /// Classifier binary path (§7 CLI contract).
    pub bin: String,
    /// Model bundle directory (§4/§7).
    pub model_dir: String,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        ClassifierConfig {
            enabled: true,
            bin: "/usr/bin/lustless-classifier".into(),
            model_dir: "/usr/share/lustless/models".into(),
        }
    }
}

/// `[upload]` section (§9.1) — the §10 uploader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UploadConfig {
    /// REST base URL (deployment-specific, §10 routes).
    pub base_url: String,
    /// Rows per upload request (§10: batch **100**).
    pub batch_size: u32,
    /// Local bookkeeping heartbeat tick in seconds (§10: 600 s steady).
    pub heartbeat_sec: u64,
    /// Retry tick in seconds (§10: 60 s retry).
    pub retry_sec: u64,
    /// Upload CE's `circumventionRecord` vocabulary (§7 toggle, default true).
    pub circumvention_records: bool,
    /// Support event log (`/v1/logs/store`, §10) behind a debug toggle.
    pub logs_store: bool,
}

impl Default for UploadConfig {
    fn default() -> Self {
        UploadConfig {
            base_url: "https://api.lustless.invalid".into(),
            batch_size: 100,
            heartbeat_sec: 600,
            retry_sec: 60,
            circumvention_records: true,
            logs_store: false,
        }
    }
}

/// `[update]` section (§9.1) — the §12 updater.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateConfig {
    /// Update feed URL; empty disables the updater (§12).
    pub feed_url: String,
    /// ed25519 public key (base64); REQUIRED when `feed_url` is set (§12).
    pub pubkey: String,
    /// Check cadence in seconds (§12: 86 400 s).
    pub check_sec: u64,
    /// Unattended apply is `critical`-only behind this flag (§12).
    pub disable_silent_upgrade: bool,
    /// Download-URL host allowlist (§12 second layer).
    pub host_allowlist: Vec<String>,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        UpdateConfig {
            feed_url: String::new(),
            pubkey: String::new(),
            check_sec: 86400,
            disable_silent_upgrade: false,
            host_allowlist: vec!["packages.lustless.invalid".into()],
        }
    }
}

/// Top-level section names of the §9.1 sample.
const KNOWN_SECTIONS: &[(&str, &[&str])] = &[
    (
        "daemon",
        &[
            "socket_path",
            "dashboard_enabled",
            "dashboard_port",
            "state_dir",
        ],
    ),
    (
        "dns",
        &[
            "enabled",
            "listen",
            "doh_url",
            "user_resolvers",
            "block_page",
            "block_page_host",
            "fail_closed_when_signed_out",
            "pool_size",
        ],
    ),
    (
        "capture",
        &[
            "enabled",
            "backend",
            "interval_sec",
            "variance_pct",
            "spool_dir",
        ],
    ),
    ("classifier", &["enabled", "bin", "model_dir"]),
    (
        "upload",
        &[
            "base_url",
            "batch_size",
            "heartbeat_sec",
            "retry_sec",
            "circumvention_records",
            "logs_store",
        ],
    ),
    (
        "update",
        &[
            "feed_url",
            "pubkey",
            "check_sec",
            "disable_silent_upgrade",
            "host_allowlist",
        ],
    ),
];

impl LustlessConfig {
    /// Loads `/etc/lustless/lustless.toml` (§9.1) — never fails:
    ///
    /// * missing file → the documented defaults (fresh install);
    /// * unreadable file → warning + defaults;
    /// * parse failure → warning `config parse failed: <err>` + defaults;
    /// * unknown keys → one warning per key, then the parsed known keys.
    pub fn load(path: &Path) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(err) => {
                tracing::warn!("config read failed: {err}");
                return Self::default();
            }
        };
        let (config, warnings) = Self::parse_document(&text);
        for warning in warnings {
            tracing::warn!("{warning}");
        }
        config
    }

    /// Parses a TOML document, returning the configuration plus the warnings
    /// [`load`](Self::load) would log. Never fails: structurally invalid or
    /// type-invalid documents yield `(defaults, ["config parse failed: …"])`.
    pub fn parse_document(text: &str) -> (Self, Vec<String>) {
        let table: toml::Table = match toml::from_str(text) {
            Ok(table) => table,
            Err(err) => {
                return (
                    Self::default(),
                    vec![CoreError::ConfigParse(err.to_string()).to_string()],
                )
            }
        };
        let mut warnings = Vec::new();
        warn_unknown_keys(&table, &mut warnings);
        match toml::from_str::<Self>(text) {
            Ok(config) => (config, warnings),
            Err(err) => {
                warnings.push(CoreError::ConfigParse(err.to_string()).to_string());
                (Self::default(), warnings)
            }
        }
    }
}

/// Collects §9.1's "unknown keys are ignored with a warning" messages.
fn warn_unknown_keys(table: &toml::Table, warnings: &mut Vec<String>) {
    for key in table.keys() {
        if !KNOWN_SECTIONS.iter().any(|(name, _)| name == key) {
            warnings.push(format!("unknown config key ignored: {key}"));
        }
    }
    for (section, known) in KNOWN_SECTIONS {
        if let Some(toml::Value::Table(entries)) = table.get(*section) {
            for key in entries.keys() {
                if !known.contains(&key.as_str()) {
                    warnings.push(format!("unknown config key ignored: {section}.{key}"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    /// The sample config of CONTRACTS §9.1, verbatim.
    const SAMPLE: &str = r#"[daemon]
socket_path = "/run/lustless/lustlessd.sock"
dashboard_enabled = true
dashboard_port = 8760
state_dir = "/var/lib/lustless"

[dns]
enabled = true
listen = "127.0.0.2:53"
doh_url = "https://dns.cleanbrowsing.org/doh/adult-filter"   # filter path (RFC 8484)
user_resolvers = ["system"]        # "system" = read current upstream resolvers
block_page = true
block_page_host = "blocked.lustless.local"
fail_closed_when_signed_out = true # "signed out ⇒ web blocked" product semantic
pool_size = 5                      # DoH connections per endpoint

[capture]
enabled = true
backend = "auto"                   # auto | x11 | wayland
interval_sec = 30
variance_pct = 20                  # jitter ±%
spool_dir = "/var/lib/lustless/spool"

[classifier]
enabled = true
bin = "/usr/bin/lustless-classifier"
model_dir = "/usr/share/lustless/models"

[upload]
base_url = "https://api.lustless.invalid"   # deployment-specific
batch_size = 100
heartbeat_sec = 600                # local bookkeeping tick (CE 600 s)
retry_sec = 60
circumvention_records = true       # upload CE's circumventionRecord vocabulary
logs_store = false                 # support event log behind debug toggle

[update]
feed_url = ""                      # empty = updater disabled
pubkey = ""                        # ed25519 (base64) — REQUIRED when feed_url set
check_sec = 86400
disable_silent_upgrade = false
host_allowlist = ["packages.lustless.invalid"]
"#;

    #[test]
    fn defaults_are_the_section_9_1_sample_values() {
        let default = LustlessConfig::default();
        assert_eq!(default.daemon.socket_path, "/run/lustless/lustlessd.sock");
        assert!(default.daemon.dashboard_enabled);
        assert_eq!(default.daemon.dashboard_port, 8760);
        assert_eq!(default.daemon.state_dir, "/var/lib/lustless");

        assert!(default.dns.enabled);
        assert_eq!(default.dns.listen, "127.0.0.2:53");
        assert_eq!(
            default.dns.doh_url,
            "https://dns.cleanbrowsing.org/doh/adult-filter"
        );
        assert_eq!(default.dns.user_resolvers, vec!["system"]);
        assert!(default.dns.block_page);
        assert_eq!(default.dns.block_page_host, "blocked.lustless.local");
        assert!(default.dns.fail_closed_when_signed_out);
        assert_eq!(default.dns.pool_size, 5);

        assert!(default.capture.enabled);
        assert_eq!(default.capture.backend, "auto");
        assert_eq!(default.capture.interval_sec, 30);
        assert_eq!(default.capture.variance_pct, 20);
        assert_eq!(default.capture.spool_dir, "/var/lib/lustless/spool");

        assert!(default.classifier.enabled);
        assert_eq!(default.classifier.bin, "/usr/bin/lustless-classifier");
        assert_eq!(default.classifier.model_dir, "/usr/share/lustless/models");

        assert_eq!(default.upload.base_url, "https://api.lustless.invalid");
        assert_eq!(default.upload.batch_size, 100);
        assert_eq!(default.upload.heartbeat_sec, 600);
        assert_eq!(default.upload.retry_sec, 60);
        assert!(default.upload.circumvention_records);
        assert!(!default.upload.logs_store);

        assert_eq!(default.update.feed_url, "");
        assert_eq!(default.update.pubkey, "");
        assert_eq!(default.update.check_sec, 86400);
        assert!(!default.update.disable_silent_upgrade);
        assert_eq!(default.update.host_allowlist, vec!["packages.lustless.invalid"]);
    }

    #[test]
    fn sample_config_parses_to_the_defaults() {
        let (config, warnings) = LustlessConfig::parse_document(SAMPLE);
        assert_eq!(config, LustlessConfig::default());
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn defaults_round_trip_through_toml() {
        let original = LustlessConfig::default();
        let text = toml::to_string(&original).expect("serialize");
        let (parsed, warnings) = LustlessConfig::parse_document(&text);
        assert_eq!(parsed, original);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn unknown_keys_are_ignored_with_a_warning() {
        let text = "[dns]\nenabled = false\nresolv = 1\n\n[totally_unknown]\nflag = true\n";
        let (config, warnings) = LustlessConfig::parse_document(text);
        // The known key still applies…
        assert!(!config.dns.enabled);
        // …the rest of the config stays at defaults…
        assert_eq!(config.daemon.dashboard_port, 8760);
        // …and every unknown key produced a warning (§9.1).
        assert_eq!(
            warnings,
            vec![
                "unknown config key ignored: totally_unknown".to_string(),
                "unknown config key ignored: dns.resolv".to_string(),
            ]
        );
    }

    #[test]
    fn partial_sections_keep_defaults_for_missing_keys() {
        let (config, warnings) = LustlessConfig::parse_document("[upload]\nbatch_size = 50\n");
        assert_eq!(config.upload.batch_size, 50);
        assert_eq!(config.upload.heartbeat_sec, 600);
        assert_eq!(config.dns.pool_size, 5);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn parse_failure_falls_back_to_defaults_with_warning() {
        let (config, warnings) = LustlessConfig::parse_document("dns = [");
        assert_eq!(config, LustlessConfig::default());
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].starts_with("config parse failed:"),
            "§9.1 log wording, got {:?}",
            warnings[0]
        );
    }

    #[test]
    fn type_error_falls_back_to_defaults_with_warning() {
        let (config, warnings) = LustlessConfig::parse_document(
            "[daemon]\ndashboard_port = \"not-a-port\"\n",
        );
        assert_eq!(config, LustlessConfig::default());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("config parse failed:"));
    }

    #[test]
    fn load_reads_files_and_tolerates_bad_content() {
        let dir = TempDir::new("config");

        // Missing file → defaults.
        assert_eq!(
            LustlessConfig::load(&dir.path().join("absent.toml")),
            LustlessConfig::default()
        );

        // Good file → parsed.
        let good = dir.path().join("lustless.toml");
        std::fs::write(&good, SAMPLE).expect("write sample");
        assert_eq!(LustlessConfig::load(&good), LustlessConfig::default());

        // Broken file → defaults (§9.1 parse-failure fallback).
        let broken = dir.path().join("broken.toml");
        std::fs::write(&broken, "dns = [").expect("write broken");
        assert_eq!(LustlessConfig::load(&broken), LustlessConfig::default());
    }
}
