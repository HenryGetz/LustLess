//! Classifier supervision — CONTRACTS §7 (CLI contract, CE's 5 s relaunch
//! poll, stdout JSON Lines), §11 (crash budget) and §6.3/§7 (circumvention
//! rows for flagged windows).
//!
//! The daemon spawns one `lustless-classifier` per filtering session with
//! CE's exact launch shape (§7, evidence `classifier-data.md` "Launch
//! contract"):
//!
//! ```text
//! lustless-classifier --model=<model_dir> --data=<spool/<uid>> \
//!     --cache=<state_dir>/<uid>/cache --version=<ver> --verbose
//! ```
//!
//! Its stdout is the §7 JSON Lines channel: `hello`/`result`/`log`/`bye`
//! messages, every one `{"type":…, "ts":…, …}`. On `result` the supervisor
//! bumps the §7 analysis counter, resolves the consumed §6.3 transaction
//! (so its later deletion is not tamper) and writes `circumventions` rows for
//! flagged windows when `upload.circumvention_records` is true (§7).
//!
//! Crash budget (§11, evidence `watchdog.md` §5/§7 + `crash-reporting.md`):
//! per-uid `last_crash_at` with a 10-minute no-relaunch window, a persisted
//! total counter, and `>3` restarts ⇒ stop auto-restart plus a human-visible
//! [`Notifier`](lustless_net::Notifier) escalation ("Too many restarts…"
//! in CE, `watchdog.md` §7).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;

use lustless_core::db::Outbox;
use lustless_core::ids;
use lustless_core::metrics::MetricName;
use lustless_core::LUSTLESS_VERSION;

use crate::state::{guard, wait_or_shutdown, DaemonState};

/// CE's relaunch poll between a classifier death and the next spawn attempt
/// (§7 `LaunchAndMonitorScreenMonitoring`, `capture-pipeline.md` §4: 5 s).
pub const RELAUNCH_POLL: Duration = Duration::from_secs(5);

/// §11 no-relaunch suppress window after a recorded crash (CE:
/// `AddMinutes(10)`, `watchdog.md` §5).
pub const CRASH_SUPPRESS_SECS: i64 = 600;

/// §11 restart limit: `>3` restarts ⇒ stop auto-restart + escalation
/// (CE `CMP R12D, 0x3; JLE`, `watchdog.md` §7).
pub const CRASH_LIMIT: u32 = 3;

/// A run that survives this long clears the §11 budget (CE clears
/// `ClientCrashesAt/Since` around a stable client start,
/// `logs.md` §272–273).
const HEALTHY_RUN_SECS: i64 = 600;

/// Supervisor session/uid re-check cadence.
const SESSION_TICK: Duration = Duration::from_secs(1);

/// §7 escalation message when the budget trips (CE: "Too many restarts…"
/// with Member Care contacts — `watchdog.md` §7; we name no CE contacts).
pub const ESCALATION_MSG: &str =
    "We've detected several unexpected restarts of the screen classifier. Automatic restarts are now disabled.";

/// `circumventions.interruption_type` for a classifier-flagged window (§7).
/// CE's only recovered value is `windows-screen-recording-not-allowed`
/// (`filter-surface.md` §7), which covers *restricted* windows — captured by
/// `capture_loop.rs`. Flagged (scored) windows are the sibling case and get
/// this distinct, documented value.
pub const INTERRUPTION_WINDOW_FLAGGED: &str = "window-flagged";

/// Normalized transaction key: `2026-10-11T05:00:00.123Z`,
/// `2026-10-11T05-00-00.123` and `2026-10-11T05:00:00Z` all collapse to
/// `2026-10-11T05-00-00` so a `result.batch_ts` can resolve its §6.3
/// transaction folder regardless of which timestamp form it echoes.
pub fn txn_key(stamp: &str) -> String {
    let base = stamp.split('.').next().unwrap_or(stamp);
    let base = base.strip_suffix('Z').unwrap_or(base);
    base.chars()
        .map(|c| if c == ':' { '-' } else { c })
        .collect()
}

// ---------------------------------------------------------------------------
// stdout JSON Lines protocol (§7)
// ---------------------------------------------------------------------------

/// One scored window inside a `result` message (§7).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ScoredWindow {
    /// Application name.
    pub app: String,
    /// Window title (may be empty on Wayland, §7).
    pub title: String,
    /// `[x, y, width, height]` in virtual-screen coordinates.
    pub rect: [i32; 4],
    /// Model score.
    pub score: f64,
    /// Flagged windows become `circumventions` rows (§7).
    pub flagged: bool,
}

/// The `summary` object of a `result` message (§7).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResultSummary {
    /// Number of flagged windows.
    pub flagged: u64,
    /// Highest score of the batch.
    pub top_score: f64,
    /// Number of scored windows.
    pub scored_windows: u64,
}

/// One parsed stdout line. Every message carries `{"type", "ts", …}` (§7);
/// `ts` is required and opaque (the channel pins its presence, not its
/// encoding).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClassifierMessage {
    /// `hello {version, model_ids}` — the child is ready.
    Hello {
        /// Message timestamp (opaque).
        ts: Value,
        /// Classifier version string.
        version: String,
        /// Loaded model artifact ids.
        model_ids: Vec<String>,
    },
    /// `result {batch_ts, windows[…], summary{…}, analyzed_count}`.
    Result {
        /// Message timestamp (opaque).
        ts: Value,
        /// Batch/transaction identifier of the consumed §6.3 folder.
        batch_ts: String,
        /// Scored windows of this batch.
        windows: Vec<ScoredWindow>,
        /// Batch summary.
        summary: ResultSummary,
        /// Real analysis count for the §7 UI counter.
        analyzed_count: u64,
    },
    /// `log {level, message}` — child log line.
    Log {
        /// Message timestamp (opaque).
        ts: Value,
        /// Severity (CE logging taxonomy, §14).
        level: String,
        /// Log text.
        message: String,
    },
    /// `bye {reason}` — graceful child exit.
    Bye {
        /// Message timestamp (opaque).
        ts: Value,
        /// Exit reason.
        reason: String,
    },
}

/// Parses one stdout line; malformed lines are an `Err` (never a panic) so
/// the supervisor can log and keep reading.
pub fn parse_line(line: &str) -> Result<ClassifierMessage, String> {
    serde_json::from_str(line.trim()).map_err(|err| err.to_string())
}

// ---------------------------------------------------------------------------
// §11 crash budget
// ---------------------------------------------------------------------------

/// Persisted per-uid crash budget (§11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CrashBudget {
    /// Unix stamp of the last recorded crash.
    pub last_crash_at: Option<i64>,
    /// Total crashes counted (§11 "total counter").
    pub total: u32,
    /// Whether the `>3` stop has been reached.
    pub stopped: bool,
}

/// Decision taken before a (re)launch attempt (§11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relaunch {
    /// Spawn allowed.
    Allow,
    /// Spawn suppressed until this unix stamp (10-minute window).
    SuppressUntil(i64),
    /// Budget exceeded (`>3`): no more auto-restarts.
    Stop,
}

/// Pure §11 decision — the unit-test surface for the budget edges.
pub fn relaunch_decision(budget: &CrashBudget, now: i64) -> Relaunch {
    if budget.total > CRASH_LIMIT {
        return Relaunch::Stop;
    }
    match budget.last_crash_at {
        None => Relaunch::Allow,
        Some(last) if now >= last + CRASH_SUPPRESS_SECS => Relaunch::Allow,
        Some(last) => Relaunch::SuppressUntil(last + CRASH_SUPPRESS_SECS),
    }
}

/// What [`CrashStore::record_crash`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashSummary {
    /// Total after this crash.
    pub total: u32,
    /// This crash crossed the `>3` line (escalate exactly once).
    pub stopped_now: bool,
}

/// Per-uid crash budget backed by `install_metadata` (§6.1) so it survives
/// daemon restarts (§11 Linux note: "persist both per user").
#[derive(Clone)]
pub struct CrashStore {
    outbox: Arc<Mutex<Outbox>>,
    budgets: Arc<Mutex<HashMap<u32, CrashBudget>>>,
}

fn meta_key(kind: &str, uid: u32) -> String {
    format!("classifier_crash_{kind}_{uid}")
}

impl CrashStore {
    /// Builds the store over the shared outbox.
    pub fn new(outbox: Arc<Mutex<Outbox>>) -> Self {
        CrashStore {
            outbox,
            budgets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Current budget for `uid` (loads from `install_metadata` on first use).
    pub fn budget(&self, uid: u32) -> CrashBudget {
        if let Some(budget) = guard(&self.budgets).get(&uid) {
            return *budget;
        }
        let outbox = guard(&self.outbox);
        let read = |kind: &str| -> Option<String> {
            outbox.install_metadata(&meta_key(kind, uid)).ok().flatten()
        };
        let budget = CrashBudget {
            last_crash_at: read("last")
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|stamp| *stamp > 0),
            total: read("total")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(0),
            stopped: read("stopped").as_deref() == Some("1"),
        };
        drop(outbox);
        guard(&self.budgets).insert(uid, budget);
        budget
    }

    fn persist(&self, uid: u32, budget: CrashBudget) {
        let mut outbox = guard(&self.outbox);
        let total = budget.total.to_string();
        let last = budget
            .last_crash_at
            .map(|stamp| stamp.to_string())
            .unwrap_or_default();
        let stopped = if budget.stopped { "1" } else { "0" };
        for (kind, value) in [
            ("total", total),
            ("last", last),
            ("stopped", stopped.to_string()),
        ] {
            if let Err(err) = outbox.set_install_metadata(&meta_key(kind, uid), &value) {
                tracing::error!("crash budget persist failed (uid {uid}, {kind}): {err}");
            }
        }
    }

    /// Records a crash: bumps the total, stamps `last_crash_at`, persists and
    /// reports whether the `>3` line was crossed (§11).
    pub fn record_crash(&self, uid: u32, now: i64) -> CrashSummary {
        let mut budget = self.budget(uid);
        let was_stopped = budget.total > CRASH_LIMIT;
        budget.total = budget.total.saturating_add(1);
        budget.last_crash_at = Some(now);
        let stopped_now = budget.total > CRASH_LIMIT && !was_stopped;
        budget.stopped = budget.stopped || stopped_now;
        self.persist(uid, budget);
        guard(&self.budgets).insert(uid, budget);
        CrashSummary {
            total: budget.total,
            stopped_now,
        }
    }

    /// Clears the budget after a healthy run (§11 — otherwise one bad day
    /// would disable screen accountability forever).
    pub fn reset_healthy(&self, uid: u32) {
        let previous = self.budget(uid);
        if previous.total == 0 && previous.last_crash_at.is_none() {
            return;
        }
        self.persist(uid, CrashBudget::default());
        guard(&self.budgets).insert(uid, CrashBudget::default());
        tracing::info!("classifier crash budget cleared for uid {uid} (healthy run)");
    }

    /// §11 decision for the next launch attempt.
    pub fn relaunch(&self, uid: u32, now: i64) -> Relaunch {
        relaunch_decision(&self.budget(uid), now)
    }

    /// Crash counters for the diagnostics bundle (§5 `0x43`), keyed by uid
    /// string.
    pub fn snapshot(&self, uids: &[u32]) -> Value {
        let mut map = serde_json::Map::new();
        for uid in uids {
            let budget = self.budget(*uid);
            map.insert(
                uid.to_string(),
                serde_json::json!({
                    "last_crash_at": budget.last_crash_at,
                    "total": budget.total,
                    "stopped": budget.stopped,
                }),
            );
        }
        Value::Object(map)
    }
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// How one supervised run ended.
enum RunOutcome {
    /// Daemon shutdown — no accounting.
    Shutdown,
    /// The session uid changed — the child was killed deliberately.
    SessionChanged,
    /// The child exited on its own.
    Died {
        /// `None` when waiting failed (treated as a crash).
        status: Option<ExitStatus>,
        /// Whether the child sent `bye` (§7).
        saw_bye: bool,
        /// Uptime in seconds.
        uptime: i64,
    },
}

/// Spawns and supervises `lustless-classifier` for the signed-in uid (§7).
pub struct ClassifierSupervisor {
    state: Arc<DaemonState>,
    /// Uids already escalated, so the §11 notification fires once per process.
    escalated: Mutex<HashSet<u32>>,
}

impl ClassifierSupervisor {
    /// Builds the supervisor around the shared state.
    pub fn new(state: Arc<DaemonState>) -> Self {
        ClassifierSupervisor {
            state,
            escalated: Mutex::new(HashSet::new()),
        }
    }

    /// Supervision loop: wait for a session → §11 gate → spawn (§7 CLI
    /// contract) → read JSON Lines until death → account for the crash →
    /// CE's 5 s relaunch poll.
    pub async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut after_death = false;
        loop {
            if *shutdown.borrow() {
                break;
            }
            // Only spawn for a signed-in session with the feature enabled.
            let Some(uid) = self.state.session_uid() else {
                if wait_or_shutdown(&mut shutdown, Duration::from_secs(1)).await {
                    break;
                }
                continue;
            };
            if !self.state.config().classifier.enabled {
                if wait_or_shutdown(&mut shutdown, Duration::from_secs(1)).await {
                    break;
                }
                continue;
            }
            if after_death {
                // CE: 5 s relaunch poll (§7).
                if wait_or_shutdown(&mut shutdown, RELAUNCH_POLL).await {
                    break;
                }
                after_death = false;
            }

            // §11 crash-budget gate.
            let now = self.now_unix();
            match self.state.crash.relaunch(uid, now) {
                Relaunch::Stop => {
                    tracing::error!(
                        "Too many restarts, classifier is not restarted automatically! (uid {uid})"
                    );
                    self.escalate(uid);
                    if wait_or_shutdown(&mut shutdown, Duration::from_secs(60)).await {
                        break;
                    }
                    continue;
                }
                Relaunch::SuppressUntil(until) => {
                    let secs = (until - now).max(1) as u64;
                    tracing::warn!(
                        "classifier relaunch suppressed for {secs}s (§11 10-minute crash window)"
                    );
                    if wait_or_shutdown(&mut shutdown, Duration::from_secs(secs)).await {
                        break;
                    }
                    continue;
                }
                Relaunch::Allow => {}
            }

            let mut child = match self.spawn(uid) {
                Ok(child) => child,
                Err(err) => {
                    tracing::error!(
                        "classifier spawn failed (uid {uid}): {err}; retrying in {}s",
                        RELAUNCH_POLL.as_secs()
                    );
                    if wait_or_shutdown(&mut shutdown, RELAUNCH_POLL).await {
                        break;
                    }
                    continue;
                }
            };
            tracing::info!(
                "classifier spawned (uid {uid}, pid {})",
                child.id().unwrap_or(0)
            );
            self.state.set_classifier_alive(true);

            let outcome = self.supervise(uid, &mut child, &mut shutdown).await;
            self.state.set_classifier_alive(false);

            match outcome {
                RunOutcome::Shutdown => break,
                RunOutcome::SessionChanged => {
                    // Deliberate kill for a uid switch: no crash accounting.
                }
                RunOutcome::Died {
                    status,
                    saw_bye,
                    uptime,
                } => {
                    after_death = true;
                    if *shutdown.borrow() {
                        break;
                    }
                    if uptime >= HEALTHY_RUN_SECS {
                        self.state.crash.reset_healthy(uid);
                    }
                    let clean = saw_bye || status.as_ref().is_some_and(ExitStatus::success);
                    if clean {
                        tracing::info!(
                            "classifier exited cleanly (uid {uid}, bye: {saw_bye}, uptime {uptime}s)"
                        );
                        continue;
                    }
                    let summary = self.state.crash.record_crash(uid, self.now_unix());
                    self.record_crash_metric(uid);
                    tracing::warn!(
                        "classifier crashed (uid {uid}, status: {}, total {})",
                        status
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        summary.total
                    );
                    if summary.stopped_now {
                        self.escalate(uid);
                    }
                }
            }
        }
        self.state.set_classifier_alive(false);
    }

    /// Spawns the child with §7's exact flag names.
    fn spawn(&self, uid: u32) -> std::io::Result<Child> {
        let cfg = self.state.config();
        let username = self.state.username();
        // `--data` is the §7 message root: `<data>/pdl` is the §6.3 spool.
        let data_dir =
            PathBuf::from(&cfg.capture.spool_dir).join(ids::url_safe_username(&username));
        // `--cache` holds the bundle/batch state (§7; `classifier-data.md`).
        let cache_dir = PathBuf::from(&cfg.daemon.state_dir)
            .join(uid.to_string())
            .join("cache");
        // `<data>/pdl` is the §6.3 exchange the classifier inotify-wakes on —
        // create it up front so the child never starts against a missing dir.
        let _ = std::fs::create_dir_all(data_dir.join("pdl"));
        let _ = std::fs::create_dir_all(&cache_dir);
        Command::new(&cfg.classifier.bin)
            .arg(format!("--model={}", cfg.classifier.model_dir))
            .arg(format!("--data={}", data_dir.display()))
            .arg(format!("--cache={}", cache_dir.display()))
            .arg(format!("--version={LUSTLESS_VERSION}"))
            .arg("--verbose")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
    }

    /// Reads stdout JSON Lines until the child dies, the session changes or
    /// shutdown arrives.
    async fn supervise(
        &self,
        uid: u32,
        child: &mut Child,
        shutdown: &mut watch::Receiver<bool>,
    ) -> RunOutcome {
        let started = std::time::Instant::now();
        let mut saw_bye = false;
        let uptime = || started.elapsed().as_secs() as i64;

        let Some(stdout) = child.stdout.take() else {
            let status = child.wait().await.ok();
            return RunOutcome::Died {
                status,
                saw_bye,
                uptime: uptime(),
            };
        };
        let mut lines = BufReader::new(stdout).lines();
        loop {
            if *shutdown.borrow() {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return RunOutcome::Shutdown;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        let _ = child.start_kill();
                        let _ = child.wait().await;
                        return RunOutcome::Shutdown;
                    }
                }
                line = lines.next_line() => {
                    match line {
                        Ok(Some(line)) => self.handle_line(uid, &line, &mut saw_bye),
                        Ok(None) => {
                            let status = child.wait().await.ok();
                            return RunOutcome::Died { status, saw_bye, uptime: uptime() };
                        }
                        Err(err) => {
                            tracing::warn!("classifier stdout read failed (uid {uid}): {err}");
                            let status = child.wait().await.ok();
                            return RunOutcome::Died { status, saw_bye, uptime: uptime() };
                        }
                    }
                }
                _ = tokio::time::sleep(SESSION_TICK) => {
                    if self.state.session_uid() != Some(uid) {
                        tracing::info!("session changed; stopping classifier for uid {uid}");
                        let _ = child.start_kill();
                        let _ = child.wait().await;
                        return RunOutcome::SessionChanged;
                    }
                }
            }
        }
    }

    /// Dispatches one stdout line (§7 message vocabulary).
    fn handle_line(&self, uid: u32, line: &str, saw_bye: &mut bool) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }
        match parse_line(trimmed) {
            Err(err) => tracing::warn!("classifier: unparseable stdout line ({err}): {trimmed}"),
            Ok(ClassifierMessage::Hello {
                version, model_ids, ..
            }) => tracing::info!(
                "classifier v{version} ready (uid {uid}, models: {})",
                model_ids.join(",")
            ),
            Ok(ClassifierMessage::Log { level, message, .. }) => {
                match level.to_ascii_lowercase().as_str() {
                    "error" | "err" | "fatal" => {
                        tracing::error!(target: "classifier", "{message}")
                    }
                    "warn" | "warning" => tracing::warn!(target: "classifier", "{message}"),
                    "debug" | "trace" => tracing::debug!(target: "classifier", "{message}"),
                    _ => tracing::info!(target: "classifier", "{message}"),
                }
            }
            Ok(ClassifierMessage::Result {
                batch_ts,
                windows,
                analyzed_count,
                ..
            }) => self.handle_result(&batch_ts, &windows, analyzed_count),
            Ok(ClassifierMessage::Bye { reason, .. }) => {
                *saw_bye = true;
                tracing::info!("classifier bye (uid {uid}): {reason}");
            }
        }
    }

    /// `result` handling (§7): analysis counter, transaction consumption and
    /// flagged-window circumvention rows.
    fn handle_result(&self, batch_ts: &str, windows: &[ScoredWindow], analyzed_count: u64) {
        self.state.bump_analyzed(analyzed_count);
        // §6.3: the batch was scored — its folder is consumed, not tampered.
        self.state.note_result_batch(batch_ts);

        let flagged: Vec<&ScoredWindow> = windows.iter().filter(|w| w.flagged).collect();
        if flagged.is_empty() {
            return;
        }
        if !self.state.config().upload.circumvention_records {
            tracing::debug!(
                "upload.circumvention_records=false; skipping {} flagged row(s)",
                flagged.len()
            );
            return;
        }
        let username = self.state.username();
        for window in flagged {
            let title = if window.title.is_empty() {
                None
            } else {
                Some(window.title.as_str())
            };
            if let Err(err) = self.state.record_circumvention(
                &username,
                INTERRUPTION_WINDOW_FLAGGED,
                &window.app,
                title,
            ) {
                tracing::warn!("circumvention row failed: {err}");
            }
        }
    }

    /// §14 `client_crash` counter on every recorded crash.
    fn record_crash_metric(&self, uid: u32) {
        let username = self.state.username();
        if let Err(err) = self.state.record_metric(
            &username,
            MetricName::ClientCrash,
            &[DaemonState::counter_field("crash_count", 1)],
        ) {
            tracing::warn!("client_crash metric failed (uid {uid}): {err}");
        }
    }

    /// §11 escalation: one human-visible notification per process.
    fn escalate(&self, uid: u32) {
        if guard(&self.escalated).insert(uid) {
            self.state.notify("error", ESCALATION_MSG, None);
        }
    }

    fn now_unix(&self) -> i64 {
        let clock = crate::state::rguard(&self.state.clock);
        clock.now_unix()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_util::test_state;
    use lustless_net::Control;

    #[test]
    fn parses_good_lines_of_every_message_type() {
        let hello = parse_line(
            r#"{"type":"hello","ts":1789880113,"version":"0.1.0","model_ids":["scorer-abc"]}"#,
        )
        .expect("hello");
        assert!(matches!(hello, ClassifierMessage::Hello { .. }));

        let result = parse_line(
            r#"{"type":"result","ts":"2026-10-11T05:00:00Z","batch_ts":"2026-10-11T05-00-00.123456",
                "windows":[{"app":"Firefox","title":"Video","rect":[0,0,800,600],"score":0.97,"flagged":true}],
                "summary":{"flagged":1,"top_score":0.97,"scored_windows":3},
                "analyzed_count":3}"#,
        )
        .expect("result");
        match result {
            ClassifierMessage::Result {
                batch_ts,
                windows,
                summary,
                analyzed_count,
                ..
            } => {
                assert_eq!(batch_ts, "2026-10-11T05-00-00.123456");
                assert_eq!(windows.len(), 1);
                assert!(windows[0].flagged);
                assert_eq!(windows[0].rect, [0, 0, 800, 600]);
                assert_eq!(summary.flagged, 1);
                assert!((summary.top_score - 0.97).abs() < f64::EPSILON);
                assert_eq!(analyzed_count, 3);
            }
            other => panic!("unexpected message: {other:?}"),
        }

        let log = parse_line(r#"{"type":"log","ts":1,"level":"warn","message":"slow batch"}"#)
            .expect("log");
        assert!(matches!(log, ClassifierMessage::Log { .. }));

        let bye = parse_line(r#"{"type":"bye","ts":1,"reason":"sigterm"}"#).expect("bye");
        assert!(matches!(bye, ClassifierMessage::Bye { .. }));
    }

    #[test]
    fn malformed_lines_are_errors_not_panics() {
        for line in [
            "",                                           // empty
            "not json at all",                            // invalid JSON
            r#"{"type":"mystery","ts":1}"#,               // unknown type
            r#"{"type":"hello","version":"1"}"#,          // missing ts
            r#"{"type":"log","ts":1,"level":"info"}"#,    // missing message
            r#"{"type":"result","ts":1,"batch_ts":"b"}"#, // missing windows/summary/analyzed_count
            r#"{"type":"result","ts":1,"batch_ts":"b","windows":[{"app":"a","title":"t","rect":[0,0,1],"score":1,"flagged":false}],"summary":{"flagged":0,"top_score":0,"scored_windows":1},"analyzed_count":1}"#, // rect too short
            r#"{"type":"hello","ts":1,"version":1,"model_ids":[]}"#, // wrong field type
        ] {
            assert!(parse_line(line).is_err(), "expected error for: {line}");
        }
    }

    #[test]
    fn crash_budget_edges() {
        // Fresh budget: allowed.
        let fresh = CrashBudget::default();
        assert_eq!(relaunch_decision(&fresh, 1_000), Relaunch::Allow);

        // One crash: suppressed for 10 minutes, allowed at the boundary.
        let budget = CrashBudget {
            last_crash_at: Some(1_000),
            total: 1,
            stopped: false,
        };
        assert_eq!(
            relaunch_decision(&budget, 1_000 + CRASH_SUPPRESS_SECS - 1),
            Relaunch::SuppressUntil(1_000 + CRASH_SUPPRESS_SECS)
        );
        assert_eq!(
            relaunch_decision(&budget, 1_000 + CRASH_SUPPRESS_SECS),
            Relaunch::Allow,
            "boundary is inclusive"
        );

        // >3 total: stop regardless of the window.
        let over = CrashBudget {
            last_crash_at: Some(1_000),
            total: CRASH_LIMIT + 1,
            stopped: true,
        };
        assert_eq!(
            relaunch_decision(&over, 10_000_000),
            Relaunch::Stop,
            "total > 3 stops even outside the window"
        );
        // Exactly 3 is still restartable (CE: `count <= 3 ⇒ restart`).
        let three = CrashBudget {
            total: CRASH_LIMIT,
            ..CrashBudget::default()
        };
        assert_eq!(relaunch_decision(&three, 1_000), Relaunch::Allow);
    }

    #[test]
    fn crash_store_counts_windows_and_crosses_the_limit_once() {
        let ts = test_state();
        let store = &ts.state.crash;
        store.record_crash(7, 10_000);
        assert_eq!(
            store.relaunch(7, 10_001),
            Relaunch::SuppressUntil(10_000 + CRASH_SUPPRESS_SECS)
        );
        assert_eq!(
            store.relaunch(7, 10_000 + CRASH_SUPPRESS_SECS),
            Relaunch::Allow
        );

        // Crashes 2..=4: only the 4th crosses the line.
        assert!(!store.record_crash(7, 20_000).stopped_now);
        assert!(!store.record_crash(7, 30_000).stopped_now);
        let summary = store.record_crash(7, 40_000);
        assert!(summary.stopped_now, "3 -> 4 crosses >3");
        assert_eq!(summary.total, 4);
        assert!(
            !store.record_crash(7, 50_000).stopped_now,
            "already stopped"
        );
        assert_eq!(store.relaunch(7, 60_000), Relaunch::Stop);

        // A healthy run clears the budget (§11).
        store.reset_healthy(7);
        assert_eq!(store.relaunch(7, 60_001), Relaunch::Allow);

        // Persistence: a fresh store over the same outbox reads it back.
        let fresh = CrashStore::new(Arc::clone(&ts.state.outbox));
        assert_eq!(fresh.budget(7).total, 0);
        fresh.record_crash(9, 1);
        let again = CrashStore::new(Arc::clone(&ts.state.outbox));
        assert_eq!(again.budget(9).total, 1);
        assert_eq!(again.budget(9).last_crash_at, Some(1));
    }

    /// §11 escalation: exactly one human-visible notification per uid, even
    /// when the stop condition is observed repeatedly.
    #[test]
    fn escalation_notification_fires_once_per_uid() {
        let ts = test_state();
        let state = &ts.state;
        let (id, queue) = state.register_connection();
        let supervisor = ClassifierSupervisor::new(Arc::clone(state));

        supervisor.escalate(1000);
        supervisor.escalate(1000);
        supervisor.escalate(2000);

        let queued = guard(&queue);
        assert_eq!(
            queued.len(),
            2,
            "one notification per uid, not per observation"
        );
        assert_eq!(queued[0].message, ESCALATION_MSG);
        assert_eq!(queued[0].level, "error");
        drop(queued);
        state.unregister_connection(id);
    }

    #[test]
    fn transaction_keys_match_across_timestamp_forms() {
        assert_eq!(txn_key("2026-10-11T05-00-00.123456"), "2026-10-11T05-00-00");
        assert_eq!(
            txn_key("2026-10-11T05:00:00.123456Z"),
            "2026-10-11T05-00-00"
        );
        assert_eq!(txn_key("2026-10-11T05:00:00Z"), "2026-10-11T05-00-00");
        assert_eq!(txn_key("2026-10-11T05-00-00"), "2026-10-11T05-00-00");
        assert_ne!(
            txn_key("2026-10-11T05:00:00Z"),
            txn_key("2026-10-11T05:00:01Z"),
            "distinct seconds stay distinct"
        );
    }

    #[test]
    fn result_batch_resolves_and_is_marked_consumed() {
        let ts = test_state();
        let state = &ts.state;
        state.remember_transaction(crate::state::CreatedTxn {
            folder: PathBuf::from("/spool/alice/pdl/2026-10-11T05-00-00.123456"),
            folder_name: "2026-10-11T05-00-00.123456".to_string(),
            manifest_ts: "2026-10-11T05:00:00.123456Z".to_string(),
        });
        // Unknown batch: nothing consumed.
        state.note_result_batch("2026-10-11T06-00-00");
        assert!(state.drain_consumed_transactions().is_empty());

        // The manifest timestamp form resolves the same folder.
        state.note_result_batch("2026-10-11T05:00:00Z");
        let consumed = state.drain_consumed_transactions();
        assert_eq!(consumed.len(), 1);
        assert_eq!(
            consumed[0].file_name().unwrap().to_string_lossy(),
            "2026-10-11T05-00-00.123456"
        );
        // Idempotent: the entry moved out.
        assert!(state.drain_consumed_transactions().is_empty());
    }

    #[test]
    fn flagged_windows_write_circumvention_rows_when_toggle_allows() {
        let ts = test_state();
        let state = &ts.state;
        state.set_sign_in_uid_hint(1000);
        state.sign_in("alice", "pw").expect("sign-in");

        let supervisor = ClassifierSupervisor::new(Arc::clone(state));
        let windows = vec![
            ScoredWindow {
                app: "Firefox".into(),
                title: "Video".into(),
                rect: [0, 0, 800, 600],
                score: 0.97,
                flagged: true,
            },
            ScoredWindow {
                app: "Terminal".into(),
                title: String::new(),
                rect: [0, 0, 100, 100],
                score: 0.01,
                flagged: false,
            },
        ];
        supervisor.handle_result("2026-10-11T05:00:00Z", &windows, 4);

        assert_eq!(state.policy_state().analyzed_count, 4, "§7 UI counter");
        // Exactly one row: the flagged window only.
        let rows = circumvention_rows(&ts);
        assert_eq!(rows, 1, "flagged window wrote one row");
    }

    /// Counts `circumventions` rows via a read-only connection (tests only).
    fn circumvention_rows(ts: &crate::state::test_util::TestState) -> i64 {
        let conn = rusqlite::Connection::open_with_flags(
            ts.state.outbox_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open outbox");
        conn.query_row("SELECT COUNT(*) FROM circumventions", [], |row| row.get(0))
            .expect("count")
    }

    #[test]
    fn toggle_off_suppresses_flagged_rows() {
        let ts = crate::state::test_util::test_state_with(|cfg| {
            cfg.upload.base_url = String::new();
            cfg.upload.circumvention_records = false;
        });
        let state = &ts.state;
        state.set_sign_in_uid_hint(1000);
        state.sign_in("alice", "pw").expect("sign-in");
        let supervisor = ClassifierSupervisor::new(Arc::clone(state));
        supervisor.handle_result(
            "batch",
            &[ScoredWindow {
                app: "Firefox".into(),
                title: "t".into(),
                rect: [0, 0, 1, 1],
                score: 1.0,
                flagged: true,
            }],
            1,
        );
        assert_eq!(circumvention_rows(&ts), 0, "§7 toggle respected");
        assert_eq!(
            state.policy_state().analyzed_count,
            1,
            "counter still bumps"
        );
    }
}
