//! `updater.rs` — the §12 updater: signed feed check, ed25519 payload
//! verification, host allowlist, unattended critical apply via `apt-get`.
//!
//! Feed JSON decision shape (CONTRACTS §12, from CE's `getClientUpdate`,
//! `re/findings/16-updater/updater.md` §2):
//! `{"recommendation":"now"|"later"|"none","critical":bool,"version","url","sig"}`
//! — **the recommendation IS the policy**: no client-side version comparison
//! ever happens.
//!
//! Trust chain (the lesson CE failed: it shipped DSA verification but never
//! configured a key — `updater.md` §5):
//!
//! 1. the feed URL is pinned in root-owned `/etc/lustless/lustless.toml`
//!    (`update.feed_url`; empty ⇒ updater disabled);
//! 2. the download URL must be `https` on an `update.host_allowlist` host
//!    (exact or dot-suffix match — CE's `FUN_140201cd0` semantics);
//! 3. the downloaded payload **MUST** verify against the pinned ed25519
//!    pubkey (`update.pubkey`, base64) **before any package tooling runs**.
//!
//! Unattended apply is `critical`-only and suppressed while
//! `update.disable_silent_upgrade` is honored (24 h grace file, CE's
//! `DisableSilentUpgrade` window semantics). `later` is a notifier message
//! only; `none` does nothing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use lustless_core::clock::ClockAnchor;
use lustless_core::config::{LustlessConfig, UpdateConfig};
use lustless_core::db::Outbox;
use lustless_core::records::local_architecture;
use lustless_core::LUSTLESS_VERSION;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, error, info, warn};

use crate::uploader::{
    device_uuid, platform_version, tracked_exchange, AuditLog, ApiMethod, ApiResult, Http,
};
use crate::{Notifier, PolicyProvider};

/// Subdirectory of `daemon.state_dir` where downloaded packages land.
pub(crate) const UPDATE_DIR: &str = "update";

/// Grace file for the `disable_silent_upgrade` window (CE's
/// `SilentUpgradeDisabledAt` analog): while the file is younger than 24 h it
/// suppresses unattended applies; older disables are logged and then ignored
/// (`updater.md` §4 — "remind me later" grace window of 1 day).
pub(crate) const SILENT_UPGRADE_GRACE_FILE: &str = "silent-upgrade-disabled-at";

/// The 24 h grace window itself.
const GRACE_SECS: u64 = 86_400;

/// The feed decision shape of §12 (missing keys default, then get rejected
/// by the decision logic where they matter).
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct FeedResponse {
    /// `now` | `later` | `none` — the whole policy (§12).
    #[serde(default)]
    pub(crate) recommendation: String,
    /// Whether the update gates the unattended (silent) apply path.
    #[serde(default)]
    pub(crate) critical: bool,
    /// Offered version (informational only — never compared client-side).
    #[serde(default)]
    pub(crate) version: String,
    /// Download URL of the `.deb` payload.
    #[serde(default)]
    pub(crate) url: String,
    /// Base64 ed25519 signature over the payload bytes.
    #[serde(default)]
    pub(crate) sig: String,
}

/// Installs a verified package (injected so the tests never run `apt-get`).
pub(crate) trait PackageInstaller: Send + Sync + 'static {
    /// Installs the local `.deb` at `deb_path`.
    fn install(&self, deb_path: &Path) -> Result<(), String>;
}

/// Production installer: `apt-get install -y <verified-deb>` (§12; the
/// daemon runs as root). No forced reboots (§12).
pub(crate) struct AptInstaller;

impl PackageInstaller for AptInstaller {
    fn install(&self, deb_path: &Path) -> Result<(), String> {
        let output = std::process::Command::new("apt-get")
            .arg("install")
            .arg("-y")
            .arg("--")
            .arg(deb_path)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|err| format!("apt-get failed to start: {err}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "apt-get exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

/// Decodes the pinned base64 ed25519 pubkey (§12).
pub(crate) fn decode_pubkey(base64_key: &str) -> Result<VerifyingKey, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(base64_key.trim())
        .map_err(|err| format!("pubkey base64: {err}"))?;
    let len = bytes.len();
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("pubkey must be 32 bytes, got {len}"))?;
    VerifyingKey::from_bytes(&raw).map_err(|err| format!("invalid pubkey: {err}"))
}

/// Verifies the base64 `sig` over the exact downloaded payload bytes (§12).
/// Strict verification rejects small-order keys/non-canonical encodings.
pub(crate) fn verify_payload(
    key: &VerifyingKey,
    sig_base64: &str,
    payload: &[u8],
) -> Result<(), String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_base64.trim())
        .map_err(|err| format!("signature base64: {err}"))?;
    let len = bytes.len();
    let raw: [u8; 64] = bytes
        .try_into()
        .map_err(|_| format!("signature must be 64 bytes, got {len}"))?;
    let signature = Signature::from_bytes(&raw);
    key.verify_strict(payload, &signature)
        .map_err(|err| format!("verification failed: {err}"))
}

/// Exact-or-dot-suffix host match against the allowlist (CE `FUN_140201cd0`
/// semantics: `files.packages.example` matches `packages.example`,
/// `evilexample` does not).
pub(crate) fn host_allowed(host: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|entry| {
        let entry = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        !entry.is_empty()
            && (host.eq_ignore_ascii_case(&entry)
                || host.to_ascii_lowercase().ends_with(&format!(".{entry}")))
    })
}

/// Download-URL trust check (§12 layer 2): `https` scheme + allowlisted
/// host. Checked BEFORE the download, like CE's
/// "Untrusted download domain detected, ignoring".
pub(crate) fn trusted_url(url: &str, allowlist: &[String]) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    match parsed.host_str() {
        Some(host) => host_allowed(host, allowlist),
        None => false,
    }
}

/// Sanitized package file name from the download URL (no separators — the
/// payload lands in `<state_dir>/update/`).
fn package_name(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.path_segments().and_then(|mut s| s.next_back()).map(str::to_string))
        .filter(|name| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        })
        .unwrap_or_else(|| "lustless-update.deb".to_string())
}

/// The §12 updater engine.
pub(crate) struct Updater {
    cfg: UpdateConfig,
    state_dir: PathBuf,
    outbox: Arc<Mutex<Outbox>>,
    clock: Arc<RwLock<ClockAnchor>>,
    policy: Arc<dyn PolicyProvider>,
    notifier: Arc<dyn Notifier>,
    http: Arc<dyn Http>,
    audit: Arc<AuditLog>,
    installer: Arc<dyn PackageInstaller>,
    /// Cached `/etc/os-release` `VERSION_ID` for the feed request.
    platform_version: String,
}

impl Updater {
    /// Builds the updater over the shared daemon state.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        cfg: Arc<LustlessConfig>,
        outbox: Arc<Mutex<Outbox>>,
        clock: Arc<RwLock<ClockAnchor>>,
        policy: Arc<dyn PolicyProvider>,
        notifier: Arc<dyn Notifier>,
        http: Arc<dyn Http>,
        audit: Arc<AuditLog>,
        installer: Arc<dyn PackageInstaller>,
    ) -> Self {
        Updater {
            platform_version: platform_version(),
            state_dir: PathBuf::from(cfg.daemon.state_dir.as_str()),
            cfg: cfg.update.clone(),
            outbox,
            clock,
            policy,
            notifier,
            http,
            audit,
            installer,
        }
    }

    /// The updater ticker: check every `update.check_sec` (§12: 86 400 s).
    /// An empty `feed_url` or an unusable pinned pubkey parks the updater
    /// forever (fail-closed: unsigned updates are never run) without taking
    /// the rest of `NetServices::run` down with it.
    pub(crate) async fn run_loop(mut self) {
        if self.cfg.feed_url.is_empty() {
            info!("updater disabled: update.feed_url is empty");
            std::future::pending::<()>().await;
            return;
        }
        let key = match decode_pubkey(&self.cfg.pubkey) {
            Ok(key) => key,
            Err(err) => {
                error!("update pubkey unusable ({err}); updater stays idle — refusing unsigned updates");
                std::future::pending::<()>().await;
                return;
            }
        };
        let interval = Duration::from_secs(self.cfg.check_sec.max(60));
        info!(
            interval_secs = interval.as_secs(),
            "updater started; checking the signed feed"
        );
        loop {
            self.check(&key).await;
            tokio::time::sleep(interval).await;
        }
    }

    /// One update check: feed decision → trust → verify → (maybe) apply.
    pub(crate) async fn check(&mut self, key: &VerifyingKey) {
        let snapshot = self.policy.snapshot();
        let mut ce_user_names = Vec::new();
        if !snapshot.username.trim().is_empty() {
            ce_user_names.push(snapshot.username.clone());
        }
        // `getClientUpdate` request vocabulary (updater.md §2) posted to the
        // pinned feed URL (§10: `POST /v1/desktop_client_update`).
        let request = json!({
            "app_name": "lustless",
            "current_app_version": LUSTLESS_VERSION,
            "device_platform": "Linux",
            "device_os_version": self.platform_version,
            "branch_name": "master",
            "change_set": "",
            "unique_device_id": device_uuid(&self.outbox),
            "device_cpu_architecture": local_architecture(),
            "ce_user_names": ce_user_names,
        });
        let feed_url = self.cfg.feed_url.clone();
        let result = tracked_exchange(
            self.http.as_ref(),
            &self.outbox,
            &self.clock,
            self.policy.as_ref(),
            &self.audit,
            "updater",
            "desktop_client_update",
            ApiMethod::Post,
            &feed_url,
            Some(request.to_string()),
            None,
        )
        .await;
        let (status, body) = match result {
            ApiResult::Response { status, body, .. } => (status, body),
            ApiResult::Transport(err) => {
                warn!("update check failed: {err}");
                return;
            }
        };
        if !(200..300).contains(&status) {
            warn!("update check answered HTTP {status}");
            return;
        }
        let feed: FeedResponse = match serde_json::from_slice(&body) {
            Ok(feed) => feed,
            Err(err) => {
                warn!("unparseable update feed: {err}");
                return;
            }
        };
        match feed.recommendation.as_str() {
            "none" => debug!(version = %feed.version, "update recommendation: none"),
            "later" => {
                // `later` = Notifier message only (§12).
                self.notifier.notify(
                    "info",
                    &format!("LustLess {} is available", feed.version),
                    None,
                );
            }
            "now" => self.handle_now(key, &feed).await,
            other => warn!("unknown update recommendation {other:?}"),
        }
    }

    /// The `now` path: trust the URL, download, verify, then apply only when
    /// the unattended gates pass.
    async fn handle_now(&mut self, key: &VerifyingKey, feed: &FeedResponse) {
        // §12 layer 2: download-URL host allowlist, checked BEFORE download.
        if !trusted_url(&feed.url, &self.cfg.host_allowlist) {
            warn!("untrusted update download host, ignoring: {}", feed.url);
            self.notifier.notify(
                "warn",
                "an update download was rejected: untrusted host",
                None,
            );
            return;
        }
        let Some(payload) = self.download(&feed.url).await else {
            return;
        };
        // §12 requirement (CE never met it): ed25519 over the payload bytes
        // BEFORE any package tooling runs.
        if let Err(err) = verify_payload(key, &feed.sig, &payload) {
            warn!("update signature rejected: {err}; download discarded");
            self.notifier
                .notify("error", "update signature verification failed; download discarded", None);
            return;
        }
        debug!(url = %feed.url, "update payload signature verified");
        if feed.critical && self.unattended_allowed() {
            self.apply(&feed.url, &feed.version, &payload).await;
        } else if feed.critical {
            self.notifier.notify(
                "info",
                &format!(
                    "critical update {} was downloaded and verified; silent upgrade is disabled",
                    feed.version
                ),
                None,
            );
        } else {
            self.notifier.notify(
                "info",
                &format!("update {} was downloaded and verified", feed.version),
                None,
            );
        }
    }

    /// Downloads the payload bytes (tracked + audited like every call).
    async fn download(&mut self, url: &str) -> Option<Vec<u8>> {
        let result = tracked_exchange(
            self.http.as_ref(),
            &self.outbox,
            &self.clock,
            self.policy.as_ref(),
            &self.audit,
            "updater",
            "update_download",
            ApiMethod::Get,
            url,
            None,
            None,
        )
        .await;
        match result {
            ApiResult::Response { status, body, .. } if (200..300).contains(&status) => Some(body),
            ApiResult::Response { status, .. } => {
                warn!("update download answered HTTP {status}");
                None
            }
            ApiResult::Transport(err) => {
                warn!("update download failed: {err}");
                None
            }
        }
    }

    /// Whether the unattended (silent) apply path is open: allowed unless
    /// `disable_silent_upgrade` is honored by a grace file younger than 24 h
    /// (§12; CE `updater.md` §4 semantics).
    fn unattended_allowed(&self) -> bool {
        if !self.cfg.disable_silent_upgrade {
            return true;
        }
        let grace = self.state_dir.join(SILENT_UPGRADE_GRACE_FILE);
        match std::fs::metadata(&grace).and_then(|meta| meta.modified()) {
            Ok(modified) => match modified.elapsed() {
                Ok(elapsed) => elapsed > Duration::from_secs(GRACE_SECS),
                Err(_) => false,
            },
            // Disabled with no timestamp: conservatively stay disabled.
            Err(_) => false,
        }
    }

    /// Applies a verified critical update: stage the payload under
    /// `<state_dir>/update/`, then `apt-get install -y <deb>` (§12).
    async fn apply(&mut self, url: &str, version: &str, payload: &[u8]) {
        let dir = self.state_dir.join(UPDATE_DIR);
        if let Err(err) = std::fs::create_dir_all(&dir) {
            let message = format!("update staging failed: {err}");
            warn!("{message}");
            self.notifier.notify("error", &message, None);
            return;
        }
        let path = dir.join(package_name(url));
        if let Err(err) = std::fs::write(&path, payload) {
            let message = format!("update staging failed: {err}");
            warn!("{message}");
            self.notifier.notify("error", &message, None);
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        info!(version, path = %path.display(), "applying verified update");
        self.notifier
            .notify("info", &format!("applying verified update {version}"), Some(50));
        let installer = Arc::clone(&self.installer);
        let target = path.clone();
        let outcome = tokio::task::spawn_blocking(move || installer.install(&target)).await;
        match outcome {
            Ok(Ok(())) => {
                self.notifier.notify(
                    "info",
                    &format!("update {version} installed; it takes effect after the daemon restarts"),
                    None,
                );
            }
            Ok(Err(err)) => {
                warn!("update install failed: {err}");
                self.notifier
                    .notify("error", &format!("update install failed: {err}"), None);
            }
            Err(err) => {
                warn!("update install task failed: {err}");
                self.notifier
                    .notify("error", "update install task failed", None);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (CONTRACTS §16: signature matrix over a deterministic keypair; no
// network — the feed and download are served by the mock HTTP layer)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_mocks::{temp_dir, MockNotifier, MockPolicy};
    use crate::uploader::test_http::MockHttp;
    use crate::uploader::{ApiRequest, ApiResponse};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ed25519_dalek::Signer;
    use parking_lot::Mutex as ParkingMutex;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Records installs instead of running apt-get.
    struct MockInstaller {
        calls: ParkingMutex<Vec<PathBuf>>,
    }

    impl MockInstaller {
        fn new() -> Self {
            MockInstaller {
                calls: ParkingMutex::new(Vec::new()),
            }
        }

        fn paths(&self) -> Vec<PathBuf> {
            self.calls.lock().clone()
        }
    }

    impl PackageInstaller for MockInstaller {
        fn install(&self, deb_path: &Path) -> Result<(), String> {
            self.calls.lock().push(deb_path.to_path_buf());
            Ok(())
        }
    }

    struct Harness {
        cfg: Arc<LustlessConfig>,
        outbox: Arc<Mutex<Outbox>>,
        clock: Arc<RwLock<ClockAnchor>>,
        policy: Arc<dyn PolicyProvider>,
        notifier: Arc<MockNotifier>,
        audit: Arc<AuditLog>,
        http: Arc<MockHttp>,
        installer: Arc<MockInstaller>,
        pubkey_b64: String,
    }

    const SEED: [u8; 32] = [7u8; 32];

    fn harness(name: &str, handler: impl Fn(ApiRequest) -> ApiResponse + Send + Sync + 'static) -> Harness {
        let dir = temp_dir(name);
        let signing = ed25519_dalek::SigningKey::from_bytes(&SEED);
        let pubkey_b64 = STANDARD.encode(signing.verifying_key().to_bytes());
        let cfg = Arc::new(LustlessConfig {
            daemon: lustless_core::config::DaemonConfig {
                state_dir: dir.to_string_lossy().to_string(),
                dashboard_enabled: false,
                ..Default::default()
            },
            update: UpdateConfig {
                feed_url: "https://api.test/v1/desktop_client_update".to_string(),
                pubkey: pubkey_b64.clone(),
                check_sec: 86_400,
                disable_silent_upgrade: false,
                host_allowlist: vec!["packages.lustless.invalid".to_string()],
            },
            ..Default::default()
        });
        Harness {
            notifier: Arc::new(MockNotifier::default()),
            installer: Arc::new(MockInstaller::new()),
            audit: Arc::new(AuditLog::default()),
            http: Arc::new(MockHttp::new(handler)),
            policy: Arc::new(MockPolicy::with_username("alice")),
            clock: Arc::new(RwLock::new(ClockAnchor::system())),
            outbox: Arc::new(Mutex::new(Outbox::open(&dir.join("outbox.db")).unwrap())),
            pubkey_b64,
            cfg,
        }
    }

    impl Harness {
        fn updater(&self) -> Updater {
            Updater::new(
                self.cfg.clone(),
                self.outbox.clone(),
                self.clock.clone(),
                self.policy.clone(),
                self.notifier.clone(),
                self.http.clone(),
                self.audit.clone(),
                self.installer.clone(),
            )
        }

        fn pubkey(&self) -> VerifyingKey {
            decode_pubkey(&self.pubkey_b64).unwrap()
        }
    }

    /// A feed + payload server for one `(recommendation, critical, url)`
    /// triple.
    fn feed_server(
        recommendation: &str,
        critical: bool,
        url: &str,
        payload: &[u8],
        sig: String,
    ) -> impl Fn(ApiRequest) -> ApiResponse + Send + Sync + 'static {
        let feed = json!({
            "recommendation": recommendation,
            "critical": critical,
            "version": "0.2.0",
            "url": url,
            "sig": sig,
        })
        .to_string();
        let payload = payload.to_vec();
        move |request: ApiRequest| {
            if request.url.ends_with("/v1/desktop_client_update") {
                ApiResponse {
                    status: 200,
                    body: feed.as_bytes().to_vec(),
                    retry_after: None,
                }
            } else {
                ApiResponse {
                    status: 200,
                    body: payload.clone(),
                    retry_after: None,
                }
            }
        }
    }

    const DEB_URL: &str = "https://packages.lustless.invalid/lustless_0.2.0_amd64.deb";
    const PAYLOAD: &[u8] = b"fake deb payload \x00\xFF\xFE bytes";

    #[test]
    fn now_critical_with_valid_signature_applies() {
        let sig = {
            let signing = ed25519_dalek::SigningKey::from_bytes(&SEED);
            STANDARD.encode(signing.sign(PAYLOAD).to_bytes())
        };
        let harness = harness("update-apply", feed_server("now", true, DEB_URL, PAYLOAD, sig));
        let key = harness.pubkey();
        let mut updater = harness.updater();
        runtime().block_on(updater.check(&key));
        let paths = harness.installer.paths();
        assert_eq!(paths.len(), 1, "verified critical update applied");
        // The staged file carries the exact payload bytes.
        let staged = std::fs::read(&paths[0]).unwrap();
        assert_eq!(staged, PAYLOAD);
        assert!(paths[0]
            .to_string_lossy()
            .ends_with("lustless_0.2.0_amd64.deb"));
    }

    #[test]
    fn bad_signature_is_rejected_before_tooling() {
        let sig = {
            let signing = ed25519_dalek::SigningKey::from_bytes(&SEED);
            let mut raw = signing.sign(PAYLOAD).to_bytes();
            raw[0] ^= 0xFF; // corrupt one byte
            STANDARD.encode(raw)
        };
        let harness = harness("update-badsig", feed_server("now", true, DEB_URL, PAYLOAD, sig));
        let key = harness.pubkey();
        let mut updater = harness.updater();
        runtime().block_on(updater.check(&key));
        assert!(harness.installer.paths().is_empty());
        assert!(harness
            .notifier
            .messages()
            .iter()
            .any(|message| message.contains("signature")));
    }

    #[test]
    fn signature_over_other_bytes_is_rejected() {
        // Valid signature, but over DIFFERENT bytes than the payload served.
        let sig = {
            let signing = ed25519_dalek::SigningKey::from_bytes(&SEED);
            STANDARD.encode(signing.sign(b"other bytes").to_bytes())
        };
        let harness = harness("update-sigswap", feed_server("now", true, DEB_URL, PAYLOAD, sig));
        let key = harness.pubkey();
        let mut updater = harness.updater();
        runtime().block_on(updater.check(&key));
        assert!(harness.installer.paths().is_empty());
    }

    #[test]
    fn wrong_host_is_rejected_before_download() {
        let sig = {
            let signing = ed25519_dalek::SigningKey::from_bytes(&SEED);
            STANDARD.encode(signing.sign(PAYLOAD).to_bytes())
        };
        let harness = harness(
            "update-badhost",
            feed_server("now", true, "https://evil.example/lustless.deb", PAYLOAD, sig),
        );
        let key = harness.pubkey();
        let mut updater = harness.updater();
        runtime().block_on(updater.check(&key));
        // Only the feed was called; the payload was never fetched.
        let urls = harness.http.urls();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].ends_with("/v1/desktop_client_update"));
        assert!(harness.installer.paths().is_empty());
        assert!(harness
            .notifier
            .messages()
            .iter()
            .any(|message| message.contains("untrusted host")));
    }

    #[test]
    fn http_scheme_is_rejected() {
        assert!(!trusted_url(
            "http://packages.lustless.invalid/x.deb",
            &["packages.lustless.invalid".to_string()]
        ));
        // Dot-suffix hosts pass; lookalikes do not.
        assert!(trusted_url(
            "https://files.packages.lustless.invalid/x.deb",
            &["packages.lustless.invalid".to_string()]
        ));
        assert!(!trusted_url(
            "https://packages.lustless.invalid.evil.example/x.deb",
            &["packages.lustless.invalid".to_string()]
        ));
        assert!(!trusted_url("https://evil.example/x.deb", &[]));
    }

    #[test]
    fn none_recommends_nothing() {
        let harness = harness("update-none", feed_server("none", false, DEB_URL, PAYLOAD, String::new()));
        let key = harness.pubkey();
        let mut updater = harness.updater();
        runtime().block_on(updater.check(&key));
        assert_eq!(harness.http.urls().len(), 1, "only the feed was called");
        assert!(harness.notifier.messages().is_empty());
        assert!(harness.installer.paths().is_empty());
    }

    #[test]
    fn later_notifies_only() {
        let harness = harness(
            "update-later",
            feed_server("later", false, DEB_URL, PAYLOAD, String::new()),
        );
        let key = harness.pubkey();
        let mut updater = harness.updater();
        runtime().block_on(updater.check(&key));
        assert_eq!(harness.http.urls().len(), 1, "no download for `later`");
        assert!(harness
            .notifier
            .messages()
            .iter()
            .any(|message| message.contains("0.2.0")));
        assert!(harness.installer.paths().is_empty());
    }

    #[test]
    fn now_non_critical_verifies_but_does_not_apply() {
        let sig = {
            let signing = ed25519_dalek::SigningKey::from_bytes(&SEED);
            STANDARD.encode(signing.sign(PAYLOAD).to_bytes())
        };
        let harness = harness("update-noncritical", feed_server("now", false, DEB_URL, PAYLOAD, sig));
        let key = harness.pubkey();
        let mut updater = harness.updater();
        runtime().block_on(updater.check(&key));
        // Downloaded + verified + notified — but no unattended apply.
        assert!(harness
            .notifier
            .messages()
            .iter()
            .any(|message| message.contains("verified")));
        assert!(harness.installer.paths().is_empty());
    }

    #[test]
    fn silent_upgrade_disabled_suppresses_critical_apply() {
        let sig = {
            let signing = ed25519_dalek::SigningKey::from_bytes(&SEED);
            STANDARD.encode(signing.sign(PAYLOAD).to_bytes())
        };
        let mut harness = harness(
            "update-silent-off",
            feed_server("now", true, DEB_URL, PAYLOAD, sig),
        );
        {
            let mut cfg = (*harness.cfg).clone();
            cfg.update.disable_silent_upgrade = true;
            harness.cfg = Arc::new(cfg); // no grace file ⇒ conservatively disabled
        }
        let key = harness.pubkey();
        let mut updater = harness.updater();
        runtime().block_on(updater.check(&key));
        assert!(harness.installer.paths().is_empty());
        assert!(harness
            .notifier
            .messages()
            .iter()
            .any(|message| message.contains("silent upgrade is disabled")));
    }

    #[test]
    fn disabled_updater_parks_without_calls() {
        let mut harness = harness("update-disabled", |_| ApiResponse {
            status: 200,
            body: b"{}".to_vec(),
            retry_after: None,
        });
        {
            let mut cfg = (*harness.cfg).clone();
            cfg.update.feed_url = String::new();
            harness.cfg = Arc::new(cfg);
        }
        let updater = harness.updater();
        let runtime = runtime();
        let _ = runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(100), updater.run_loop()).await
        });
        assert!(harness.http.urls().is_empty());
    }

    #[test]
    fn unusable_pubkey_parks_updater() {
        let mut harness = harness("update-badkey", |_| ApiResponse {
            status: 200,
            body: b"{}".to_vec(),
            retry_after: None,
        });
        {
            let mut cfg = (*harness.cfg).clone();
            cfg.update.pubkey = "not base64!".to_string();
            harness.cfg = Arc::new(cfg);
        }
        let updater = harness.updater();
        let runtime = runtime();
        let _ = runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(100), updater.run_loop()).await
        });
        assert!(harness.http.urls().is_empty());
    }

    #[test]
    fn package_name_is_sanitized() {
        assert_eq!(
            package_name("https://packages.lustless.invalid/lustless_1.0.0_amd64.deb"),
            "lustless_1.0.0_amd64.deb"
        );
        // Traversal-ish or empty names fall back to a fixed safe name.
        assert_eq!(package_name("https://packages.lustless.invalid/"), "lustless-update.deb");
        assert_eq!(
            package_name("https://packages.lustless.invalid/a%2Fb.deb"),
            "lustless-update.deb"
        );
    }
}
