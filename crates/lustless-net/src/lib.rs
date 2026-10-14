//! `lustless-net` — the network services of the LustLess daemon
//! (CONTRACTS §3): the §10 REST uploader (outbox state machine), the §12
//! updater (signed feed + ed25519 verification) and the §13 dashboard
//! (axum, token-authenticated), driven by the daemon through the
//! [`PolicyProvider`] / [`Notifier`] / [`Control`] traits below.
//!
//! | module | contract section |
//! |---|---|
//! | [`uploader`] | §10 REST uploader: one uploader, one outbox, claim/reaper state machine, per-user batching, throttling, clock anchor |
//! | [`updater`] | §12 updater: feed decision shape, ed25519 payload verification, host allowlist, unattended critical apply |
//! | [`dashboard`] | §13 dashboard: axum on `127.0.0.1:<port>`, token auth, embedded templates, **no keys route** |
//! | [`tokens`] | §13 dashboard tokens: 32 random bytes hex, TTL 600 s, uid-bound |
//!
//! # Execution model
//!
//! [`NetServices::run`] drives the three services as futures of ONE
//! `tokio::select!`; dropping/cancelling the `run` future cancels all three
//! (the dashboard stops accepting, the loops stop at their next await).
//! None of the three branches ever completes on its own — a disabled
//! dashboard or disabled updater parks its branch instead — so `run`
//! returns only through cancellation.
//!
//! # Integrator notes (assumptions the daemon must satisfy)
//!
//! * `NetServices` is `Clone` (cheap, shares inner state): clone a handle
//!   for [`NetServices::flush_now`] / [`NetServices::issue_dashboard_token`]
//!   before moving the original into [`NetServices::run`].
//! * [`NetServices::flush_now`] **blocks the calling thread** until the
//!   drain finishes or the deadline expires; call it from a blocking
//!   context (`spawn_blocking` / a dedicated thread), never from the async
//!   task that drives `run`.
//! * Upload auth reads the signed-in user's `device_token` from
//!   `<daemon.state_dir>/<uid>/settings.db` (`api_credentials`, §6.2),
//!   matching `PolicySnapshot.username`; the daemon must have written those
//!   credentials on sign-in (they are re-read on username change and after
//!   any 401).

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use lustless_core::clock::{system_unix, ClockAnchor};
use lustless_core::config::LustlessConfig;
use lustless_core::db::{Outbox, STALE_SENDING_SECS};
use lustless_core::policy::PolicySnapshot;
use lustless_core::CoreError;

mod dashboard;
mod tokens;
mod updater;
mod uploader;

/// The policy source the daemon implements (CONTRACTS §9: the live
/// `PolicySnapshot` behind IPC 0x60).
pub trait PolicyProvider: Send + Sync + 'static {
    /// Returns the current policy snapshot.
    fn snapshot(&self) -> PolicySnapshot;
}

/// The user-facing notification channel the daemon implements (IPC
/// `NOTIFICATION` 0x02): `level` is a daemon vocabulary string (`"info"`,
/// `"warn"`, `"error"`), `progress` is an optional percentage.
pub trait Notifier: Send + Sync + 'static {
    /// Emits one notification.
    fn notify(&self, level: &str, message: &str, progress: Option<u8>);
}

/// The daemon control surface the dashboard drives (IPC 0x63–0x67): the
/// password is processed and never stored (§5/§6.2); `update_check` returns
/// the update recommendation string.
pub trait Control: Send + Sync + 'static {
    /// uid of the currently signed-in session, `None` when signed out. The
    /// dashboard uses it to reject mutations from a token minted for a
    /// different user (the token's uid was previously validated and then
    /// discarded, so any local uid could drive the session).
    fn session_uid(&self) -> Option<u32>;
    /// Signs in (IPC 0x65) and returns the session token.
    fn sign_in(&self, username: &str, password: &str) -> Result<String, String>;
    /// Signs out (IPC 0x66), clearing stored credentials (§6.2).
    fn sign_out(&self) -> Result<(), String>;
    /// Sets the blocking level (IPC 0x63).
    fn set_filter_level(&self, level: &str) -> Result<(), String>;
    /// Sets or clears (`"na"`) a tri-state domain override (IPC 0x64).
    fn set_override(&self, domain: &str, verdict: &str) -> Result<(), String>;
    /// Triggers a diagnostics collection (IPC 0x43).
    fn collect_debug(&self) -> Result<(), String>;
    /// Triggers an update check (IPC 0x67), returning the recommendation.
    fn update_check(&self) -> Result<String, String>;
}

/// The network-services handle: uploader + updater + dashboard (§10/§12/§13).
///
/// Clone it freely — clones share one uploader engine, one token store and
/// one flush channel.
#[derive(Clone)]
pub struct NetServices {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: Arc<LustlessConfig>,
    outbox: Arc<Mutex<Outbox>>,
    clock: Arc<RwLock<ClockAnchor>>,
    policy: Arc<dyn PolicyProvider>,
    notifier: Arc<dyn Notifier>,
    control: Arc<dyn Control>,
    http: Arc<dyn uploader::Http>,
    installer: Arc<dyn updater::PackageInstaller>,
    audit: Arc<uploader::AuditLog>,
    tokens: Arc<tokens::TokenStore>,
    flush_tx: tokio::sync::mpsc::UnboundedSender<uploader::FlushCmd>,
    flush_rx: tokio::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<uploader::FlushCmd>>>,
    /// Test-only claim min-age override (production: §6.1's 30 s gate).
    min_age_override: Option<i64>,
}

impl Inner {
    /// Applies the test tuning hook, if any.
    fn tune(&self, engine: uploader::Uploader) -> uploader::Uploader {
        match self.min_age_override {
            Some(min_age) => engine.with_tuning(min_age, STALE_SENDING_SECS),
            None => engine,
        }
    }
}

impl NetServices {
    /// Builds the network services over the daemon's shared state (CONTRACTS
    /// §3: driven through [`PolicyProvider`]/[`Notifier`]/[`Control`]).
    pub fn new(
        cfg: Arc<LustlessConfig>,
        outbox: Arc<Mutex<Outbox>>,
        clock: Arc<RwLock<ClockAnchor>>,
        policy: Arc<dyn PolicyProvider>,
        notifier: Arc<dyn Notifier>,
        control: Arc<dyn Control>,
    ) -> Self {
        Self::build(
            cfg,
            outbox,
            clock,
            policy,
            notifier,
            control,
            Arc::new(uploader::ReqwestHttp::new()),
            Arc::new(updater::AptInstaller),
            None,
        )
    }

    /// Assembles the services; also the test seam (injected HTTP layer and
    /// claim-tuning). The argument count mirrors the pinned `new` plus the
    /// two seams.
    #[allow(clippy::too_many_arguments)]
    fn build(
        cfg: Arc<LustlessConfig>,
        outbox: Arc<Mutex<Outbox>>,
        clock: Arc<RwLock<ClockAnchor>>,
        policy: Arc<dyn PolicyProvider>,
        notifier: Arc<dyn Notifier>,
        control: Arc<dyn Control>,
        http: Arc<dyn uploader::Http>,
        installer: Arc<dyn updater::PackageInstaller>,
        min_age_override: Option<i64>,
    ) -> Self {
        let (flush_tx, flush_rx) = tokio::sync::mpsc::unbounded_channel();
        NetServices {
            inner: Arc::new(Inner {
                flush_tx,
                flush_rx: tokio::sync::Mutex::new(Some(flush_rx)),
                installer,
                min_age_override,
                cfg,
                outbox,
                clock,
                policy,
                notifier,
                control,
                http,
                audit: Arc::new(uploader::AuditLog::default()),
                tokens: Arc::new(tokens::TokenStore::default()),
            }),
        }
    }

    /// Drives the uploader loop, the updater ticker and the dashboard
    /// concurrently until the returned future is dropped or cancelled
    /// (graceful shutdown: every service is a future of this `select!`, so
    /// cancellation stops all three at their next await point).
    pub async fn run(self) -> Result<(), CoreError> {
        let inner = Arc::clone(&self.inner);
        let commands = inner.flush_rx.lock().await.take();
        let uploader_engine = inner.tune(uploader::Uploader::new(
            Arc::clone(&inner.cfg),
            Arc::clone(&inner.outbox),
            Arc::clone(&inner.clock),
            Arc::clone(&inner.policy),
            Arc::clone(&inner.http),
            Arc::clone(&inner.audit),
        ));
        let uploader_loop = uploader_engine.run_loop(commands);
        let updater_engine = updater::Updater::new(
            Arc::clone(&inner.cfg),
            Arc::clone(&inner.outbox),
            Arc::clone(&inner.clock),
            Arc::clone(&inner.policy),
            Arc::clone(&inner.notifier),
            Arc::clone(&inner.http),
            Arc::clone(&inner.audit),
            Arc::clone(&inner.installer),
        );
        let updater_loop = updater_engine.run_loop();
        let dashboard_state = dashboard::DashboardState {
            policy: Arc::clone(&inner.policy),
            control: Arc::clone(&inner.control),
            outbox: Arc::clone(&inner.outbox),
            tokens: Arc::clone(&inner.tokens),
            clock: Arc::clone(&inner.clock),
        };
        let dashboard_server = dashboard::serve(Arc::clone(&inner.cfg), dashboard_state);
        tokio::select! {
            _ = uploader_loop => tracing::warn!("uploader loop exited"),
            _ = updater_loop => tracing::warn!("updater loop exited"),
            _ = dashboard_server => {}
        }
        Ok(())
    }

    /// Synchronously claims + sends everything pending until `deadline`
    /// (§5 IPC 0x69 / §11 prerm flush semantics): partial flushes are OK;
    /// the return value counts the outbox rows acked as `sent`.
    ///
    /// Blocks the calling thread up to `deadline` — call it from
    /// `spawn_blocking` (or another blocking thread), never from the task
    /// driving [`NetServices::run`].
    pub fn flush_now(&self, deadline: Duration) -> usize {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self
            .inner
            .flush_tx
            .send(uploader::FlushCmd { reply: reply_tx })
            .is_err()
        {
            return 0;
        }
        let mut total = 0usize;
        let deadline_at = std::time::Instant::now() + deadline;
        loop {
            let remaining = deadline_at.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match reply_rx.recv_timeout(remaining) {
                Ok(uploader::FlushEvent::Rows(count)) => total += count,
                Ok(uploader::FlushEvent::Done) => break,
                Err(_) => break,
            }
        }
        total
    }

    /// Issues a uid-bound dashboard token (§13: 32 random bytes hex, TTL
    /// 600 s) for the IPC peer that just authenticated; the agent appends it
    /// as `?t=` when opening the browser.
    pub fn issue_dashboard_token(&self, uid: u32) -> String {
        self.inner.tokens.issue(uid, system_unix())
    }
}

// ---------------------------------------------------------------------------
// Shared test mocks (CONTRACTS §16)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_mocks {
    use super::*;
    use lustless_core::policy::{CapturePolicy, FilterPolicy, UserState};
    use parking_lot::Mutex;

    /// A fresh, isolated temp directory per test.
    pub(crate) fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lustless-net-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Policy provider with a fixed username.
    pub(crate) struct MockPolicy {
        /// Signed-in account username (`""` = signed out).
        pub(crate) username: String,
    }

    impl MockPolicy {
        pub(crate) fn with_username(username: &str) -> Self {
            MockPolicy {
                username: username.to_string(),
            }
        }
    }

    impl PolicyProvider for MockPolicy {
        fn snapshot(&self) -> PolicySnapshot {
            let signed_in = !self.username.trim().is_empty();
            PolicySnapshot {
                username: self.username.clone(),
                signed_in,
                state: if signed_in {
                    UserState::LoggedIn
                } else {
                    UserState::LoggedOut
                },
                has_accountability: true,
                has_filtering: true,
                has_screen_accountability: false,
                has_url_accountability: false,
                has_dns_filtering: true,
                has_url_filtering: false,
                can_override: true,
                is_panicked: false,
                filter: FilterPolicy {
                    level: "Standard Blocking".to_string(),
                    fail_closed: true,
                    health: "ok".to_string(),
                },
                capture: CapturePolicy {
                    active: false,
                    backend: "auto".to_string(),
                    last_screenstate_at: None,
                },
            }
        }
    }

    /// Notifier that records every message.
    #[derive(Default)]
    pub(crate) struct MockNotifier {
        messages: Mutex<Vec<(String, String, Option<u8>)>>,
    }

    impl MockNotifier {
        /// Recorded message texts.
        pub(crate) fn messages(&self) -> Vec<String> {
            self.messages
                .lock()
                .iter()
                .map(|(_, message, _)| message.clone())
                .collect()
        }
    }

    impl Notifier for MockNotifier {
        fn notify(&self, level: &str, message: &str, progress: Option<u8>) {
            self.messages
                .lock()
                .push((level.to_string(), message.to_string(), progress));
        }
    }

    /// Control surface that records calls and always succeeds.
    #[derive(Default)]
    pub(crate) struct MockControl {
        calls: Mutex<Vec<String>>,
        /// uid the mock reports as the signed-in session (dashboard tests set
        /// it to exercise the token-ownership check).
        pub(crate) session_uid: Mutex<Option<u32>>,
    }

    impl MockControl {
        /// Recorded calls (`"sign_in:alice"`, …).
        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.lock().clone()
        }
    }

    impl Control for MockControl {
        fn session_uid(&self) -> Option<u32> {
            *self.session_uid.lock()
        }

        fn sign_in(&self, username: &str, _password: &str) -> Result<String, String> {
            self.calls.lock().push(format!("sign_in:{username}"));
            Ok("session-token".to_string())
        }

        fn sign_out(&self) -> Result<(), String> {
            self.calls.lock().push("sign_out".to_string());
            Ok(())
        }

        fn set_filter_level(&self, level: &str) -> Result<(), String> {
            self.calls.lock().push(format!("set_filter_level:{level}"));
            Ok(())
        }

        fn set_override(&self, domain: &str, verdict: &str) -> Result<(), String> {
            self.calls
                .lock()
                .push(format!("set_override:{domain}:{verdict}"));
            Ok(())
        }

        fn collect_debug(&self) -> Result<(), String> {
            self.calls.lock().push("collect_debug".to_string());
            Ok(())
        }

        fn update_check(&self) -> Result<String, String> {
            self.calls.lock().push("update_check".to_string());
            Ok("none".to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (CONTRACTS §16: the pinned API end to end over local mocks)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::test_mocks::{temp_dir, MockControl, MockNotifier, MockPolicy};
    use super::*;
    use crate::uploader::test_http::MockHttp;
    use crate::uploader::ApiResponse;
    use lustless_core::config::{DaemonConfig, UploadConfig};
    use lustless_core::db::{DnsActivityRow, EventTable, LoginRow};
    use lustless_core::settings::{ApiCredentials, SettingsDb};

    /// End-to-end: `run()` on a background thread, `flush_now` from the
    /// test thread, mock HTTP on the uploader's `https://api.test`.
    #[test]
    fn flush_now_drains_pending_rows_through_run() {
        let dir = temp_dir("flush-now");
        let outbox = Arc::new(Mutex::new(Outbox::open(&dir.join("outbox.db")).unwrap()));
        // §6.2: the daemon wrote the signed-in user's Bearer token.
        {
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
        }
        {
            let mut outbox = outbox.lock().unwrap();
            outbox
                .insert_dns_activity(&DnsActivityRow {
                    username: "alice".to_string(),
                    domain: "example.org".to_string(),
                    process_id: Some("4321".to_string()),
                    process_name: "browser".to_string(),
                    datetime_created: "2026-10-11T10:00:00Z".to_string(),
                    ip: Some("192.0.2.10".to_string()),
                    resolution_type: "BlockedCustom".to_string(),
                    connection_type: Some("DoH".to_string()),
                    resolution_datacenter: None,
                    resolution_time_ms: Some("3".to_string()),
                })
                .unwrap();
            outbox
                .insert_login(&LoginRow {
                    username: "alice".to_string(),
                    system_user_id: Some("1000".to_string()),
                    system_user_name: Some("alice-os".to_string()),
                    timestamp: "2026-10-11T10:00:00Z".to_string(),
                    login_at: "2026-10-11T09:00:00Z".to_string(),
                    logout_at: None,
                })
                .unwrap();
        }
        let cfg = Arc::new(LustlessConfig {
            daemon: DaemonConfig {
                state_dir: dir.to_string_lossy().to_string(),
                dashboard_enabled: false,
                ..Default::default()
            },
            upload: UploadConfig {
                base_url: "https://api.test".to_string(),
                ..Default::default()
            },
            ..Default::default()
        });
        let http = Arc::new(MockHttp::new(|_| ApiResponse {
            status: 200,
            body: b"{}".to_vec(),
            retry_after: None,
        }));
        let net = NetServices::build(
            cfg,
            outbox.clone(),
            Arc::new(RwLock::new(ClockAnchor::system())),
            Arc::new(MockPolicy::with_username("alice")),
            Arc::new(MockNotifier::default()),
            Arc::new(MockControl::default()),
            http.clone(),
            Arc::new(updater::AptInstaller),
            Some(0), // skip the §6.1 30 s min-age gate in this test
        );

        // Drive `run()` on a dedicated thread with its own runtime; the
        // test thread calls the blocking `flush_now` (integrator contract).
        let runner = net.clone();
        let _thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _ = runtime.block_on(runner.run());
        });

        let flushed = net.flush_now(Duration::from_secs(10));
        // 1 dns + 1 login row acked (the install report is not an outbox
        // row and is not counted).
        assert_eq!(flushed, 2);
        // Nothing claimable remains.
        assert!(outbox
            .lock()
            .unwrap()
            .claim_batch(EventTable::DnsActivity, 10, 0)
            .unwrap()
            .is_empty());
        assert!(outbox
            .lock()
            .unwrap()
            .claim_batch(EventTable::Logins, 10, 0)
            .unwrap()
            .is_empty());
        // The activity batches went out over the mock with Bearer auth.
        let calls = http.calls.lock().clone();
        assert!(calls.iter().any(|call| {
            call.url
                .ends_with("/v2/user/alice/report/activity_log.json")
                && call.bearer.as_deref() == Some("device-token-alice")
        }));
        assert!(calls
            .iter()
            .any(|call| call.url.ends_with("/v1/status/ping")));
        assert!(calls
            .iter()
            .any(|call| call.url.ends_with("/v1/status/time")));

        // Dashboard tokens come from the same handle (§13).
        let token = net.issue_dashboard_token(1000);
        assert_eq!(token.len(), 64);
        assert!(token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(net.inner.tokens.validate(&token, system_unix()), Some(1000));
    }

    /// A second `flush_now` after everything was drained returns 0 (nothing
    /// pending, partial = ok).
    #[test]
    fn flush_now_is_zero_when_drained() {
        let dir = temp_dir("flush-now-empty");
        let outbox = Arc::new(Mutex::new(Outbox::open(&dir.join("outbox.db")).unwrap()));
        let cfg = Arc::new(LustlessConfig {
            daemon: DaemonConfig {
                state_dir: dir.to_string_lossy().to_string(),
                dashboard_enabled: false,
                ..Default::default()
            },
            upload: UploadConfig {
                base_url: "https://api.test".to_string(),
                ..Default::default()
            },
            ..Default::default()
        });
        // Signed out ⇒ no token ⇒ the uploader never sends.
        let net = NetServices::build(
            cfg,
            outbox,
            Arc::new(RwLock::new(ClockAnchor::system())),
            Arc::new(MockPolicy::with_username("")),
            Arc::new(MockNotifier::default()),
            Arc::new(MockControl::default()),
            Arc::new(MockHttp::new(|_| ApiResponse {
                status: 200,
                body: b"{}".to_vec(),
                retry_after: None,
            })),
            Arc::new(updater::AptInstaller),
            Some(0),
        );
        let runner = net.clone();
        let _thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _ = runtime.block_on(runner.run());
        });
        assert_eq!(net.flush_now(Duration::from_secs(5)), 0);
    }
}
