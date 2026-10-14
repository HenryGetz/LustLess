//! `lustlessd` — the LustLess system daemon (CONTRACTS §3 crate graph, §4
//! filesystem/process layout, §14 logging).
//!
//! Wiring order:
//!
//! 1. journald logging (§14, stderr fallback) + the `log` → `tracing` bridge,
//! 2. §9.1 config load (`LUSTLESS_CONFIG` override for tests/smoke) and the
//!    §4 layout (0700 state dir, socket dir, spool root),
//! 3. shared [`state::DaemonState`] (§6.1 outbox + §10 clock anchor),
//! 4. subsystems on one shutdown broadcast: logind sessions (§13), DNS
//!    forwarder (§8), classifier supervisor (§7/§11), capture loop (§7),
//!    `NetServices` (pinned API — a `Clone` handle stays behind for
//!    `flush_now`/`issue_dashboard_token` while `run()` drives the loop),
//! 5. the §5 IPC server,
//! 6. graceful shutdown on SIGTERM/SIGINT or IPC `0x51 QUIT`: broadcast
//!    shutdown (stops capture + supervisor + DNS, closes the listener), one
//!    bounded outbox flush (§11 `prerm` shape) and a WAL checkpoint (§6.1).
mod capture_loop;
mod classifier;
mod crash;
mod diagnostics;
mod dns_glue;
mod ipc;
mod policy;
mod sessions;
mod state;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::watch;

use lustless_core::clock::ClockAnchor;
use lustless_core::config::LustlessConfig;
use lustless_core::db::Outbox;
use lustless_core::metrics::MetricName;
use lustless_net::{Control, NetServices, Notifier, PolicyProvider};

use crate::classifier::ClassifierSupervisor;
use crate::sessions::SessionRegistry;
use crate::state::{outbox_path, DaemonState};

#[tokio::main]
async fn main() {
    init_logging();
    if let Err(err) = run().await {
        tracing::error!("lustlessd: {err}");
        std::process::exit(1);
    }
}

/// §14 logging: journald via `tracing-journald` (stderr fallback when the
/// journal socket is unavailable) at INFO, plus the `log` facade bridge so
/// `lustless-capture`'s `log::` records reach the same subscriber.
fn init_logging() {
    use tracing_subscriber::prelude::*;

    let info = tracing_subscriber::filter::LevelFilter::INFO;
    match tracing_journald::layer() {
        Ok(journald) => tracing_subscriber::registry()
            .with(journald)
            .with(info)
            .init(),
        Err(err) => {
            eprintln!("lustlessd: journald unavailable ({err}); logging to stderr");
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                .with(info)
                .init();
        }
    }
    if let Err(err) = tracing_log::LogTracer::init() {
        tracing::warn!("log facade bridge already initialized: {err}");
    }
}

/// Resolves until SIGTERM or SIGINT.
async fn terminate_signal() {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(err) => {
            tracing::warn!("SIGTERM handler unavailable: {err}");
            std::future::pending::<()>().await;
            return;
        }
    };
    let mut interrupt =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
            Ok(signal) => signal,
            Err(err) => {
                tracing::warn!("SIGINT handler unavailable: {err}");
                let _ = term.recv().await;
                return;
            }
        };
    tokio::select! {
        _ = term.recv() => {}
        _ = interrupt.recv() => {}
    }
}

/// Exclusive `flock` on `<state_dir>/lustlessd.pid` (held for the process
/// lifetime). Refuses a second daemon instead of letting two of them share the
/// outbox/spool/crash ledger.
fn acquire_singleton(state_dir: &Path) -> std::io::Result<std::fs::File> {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join("lustlessd.pid");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    // SAFETY: plain `flock(2)` on an fd we own.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "another lustlessd already holds {} (state dir {})",
                path.display(),
                state_dir.display()
            ),
        ));
    }
    let mut file = file;
    let _ = file.set_len(0);
    let _ = writeln!(file, "{}", std::process::id());
    Ok(file)
}

/// Creates the §4 layout: `<state_dir>` 0700, socket dir 0755 (the socket
/// itself is chmod 0666 by `ipc::serve`), spool root 0700. The classifier log
/// dir is best-effort (§4 paths, created root-owned when possible).
fn ensure_layout(cfg: &LustlessConfig) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let state_dir = PathBuf::from(&cfg.daemon.state_dir);
    std::fs::create_dir_all(&state_dir)?;
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;

    if let Some(socket_dir) = Path::new(&cfg.daemon.socket_path)
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
    {
        std::fs::create_dir_all(socket_dir)?;
        std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o755))?;
    }

    let spool_dir = PathBuf::from(&cfg.capture.spool_dir);
    std::fs::create_dir_all(&spool_dir)?;
    std::fs::set_permissions(&spool_dir, std::fs::Permissions::from_mode(0o700))?;

    if let Err(err) = std::fs::create_dir_all("/var/log/lustless/classifier") {
        tracing::warn!("classifier log dir not created (continuing): {err}");
    }
    Ok(())
}

/// Best-effort `PRAGMA wal_checkpoint(TRUNCATE)` on the §6.1 outbox at
/// shutdown (a second connection checkpoints the WAL while the daemon's own
/// handle is idle).
fn checkpoint_outbox(path: &Path) {
    if !path.exists() {
        return;
    }
    let conn = match rusqlite::Connection::open(path) {
        Ok(conn) => conn,
        Err(err) => {
            tracing::warn!("outbox checkpoint open failed: {err}");
            return;
        }
    };
    match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(0) => tracing::info!("outbox WAL checkpointed (§6.1)"),
        Ok(busy) => tracing::warn!("outbox WAL checkpoint busy ({busy})"),
        Err(err) => tracing::warn!("outbox WAL checkpoint failed: {err}"),
    }
}

/// Config path precedence: `--config <path>`, then `LUSTLESS_CONFIG`, then the
/// system default (§9.1).
fn config_path() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(value) = args.next() {
                return PathBuf::from(value);
            }
        }
    }
    std::env::var_os("LUSTLESS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/lustless/lustless.toml"))
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = config_path();
    let cfg = Arc::new(LustlessConfig::load(&config_path));
    cfg.validate().map_err(|err| format!("config: {err}"))?;

    // Singleton guard: a second daemon would share the outbox, the spool and
    // the crash ledger with the first (duplicate uploads, capture writes) and
    // would report a false crash because the first has not rewritten its clean
    // marker. The lock is held for the process lifetime.
    let _singleton = acquire_singleton(Path::new(&cfg.daemon.state_dir))
        .map_err(|err| format!("stage singleton: {err}"))?;

    ensure_layout(&cfg).map_err(|err| format!("stage ensure_layout: {err}"))?;

    let outbox = Arc::new(Mutex::new(
        Outbox::open(&outbox_path(&cfg)).map_err(|err| format!("stage outbox_open: {err}"))?,
    ));
    let clock = Arc::new(RwLock::new(ClockAnchor::system()));
    // §10 crash pipeline: the ledger decides whether the *previous* run died
    // (a clean-shutdown marker is missing) before anything else is written.
    // systemd's `Restart=always` is CE's restart helper, so the report is made
    // by this start — CE's timing exactly.
    let ledger = crash::CrashLedger::new(Path::new(&cfg.daemon.state_dir));
    ledger.install_hooks();
    std::env::set_var("LUSTLESS_CRASH_REASON", ledger.reason_path());
    let previous_crash = ledger.begin();
    // CE's `crashatonce=true` command-line switch / `ForceCrashClient` setting.
    if crash::forced_crash_requested(&std::env::args().collect::<Vec<_>>(), &cfg.daemon.crash_test_hook)
    {
        crash::force_crash();
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = Arc::new(DaemonState::new(
        Arc::clone(&cfg),
        config_path,
        outbox,
        Arc::clone(&clock),
        shutdown_tx,
    ));
    state.bind_weak();
    tracing::info!("config: {}", state.config_path().display());

    // §14 `client_startup` (mirrors the captured sample row shape).
    if let Err(err) = state.record_metric(
        "",
        MetricName::ClientStartup,
        &[DaemonState::counter_field("startup_count", 1)],
    ) {
        tracing::warn!("client_startup metric failed: {err}");
    }
    // §10: report the crash the previous run left behind (metric with
    // `crash_type`, telemetry row, sanitized attachments) and clear CE's
    // counter pair afterwards.
    if let Some(crash_type) = previous_crash {
        report_previous_crash(&state, &ledger, crash_type);
    }
    tracing::info!(
        "lustlessd {} starting (state {})",
        lustless_core::LUSTLESS_VERSION,
        cfg.daemon.state_dir
    );

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // §13 logind tracking.
    let registry = Arc::new(SessionRegistry::new());
    tasks.push(tokio::spawn(sessions::run(
        Arc::clone(&registry),
        Arc::clone(&state),
        shutdown_rx.clone(),
    )));

    // §8 forwarder + block page.
    tasks.push(tokio::spawn(dns_glue::spawn(
        Arc::clone(&state),
        shutdown_rx.clone(),
    )));

    // §7/§11 classifier supervision.
    let supervisor = Arc::new(ClassifierSupervisor::new(Arc::clone(&state)));
    tasks.push(tokio::spawn(supervisor.run(shutdown_rx.clone())));

    // §7 capture loop.
    tasks.push(tokio::spawn(capture_loop::run(
        Arc::clone(&state),
        Arc::clone(&registry),
        shutdown_rx.clone(),
    )));

    // §10/§12/§13 network services (pinned API): keep a Clone handle for
    // flush_now()/issue_dashboard_token() while run() consumes its own copy.
    let policy: Arc<dyn PolicyProvider> = state.clone();
    let notifier: Arc<dyn Notifier> = state.clone();
    let control: Arc<dyn Control> = state.clone();
    let net = NetServices::new(
        Arc::clone(&cfg),
        Arc::clone(&state.outbox),
        Arc::clone(&state.clock),
        policy,
        notifier,
        control,
    );
    state.set_net(net.clone());
    let net_task = tokio::spawn(async move {
        if let Err(err) = net.run().await {
            tracing::error!("network services terminated: {err}");
        }
    });

    // §5 IPC server.
    let socket_path = PathBuf::from(&cfg.daemon.socket_path);
    let ipc_state = Arc::clone(&state);
    let ipc_shutdown = shutdown_rx.clone();
    let ipc = tokio::spawn(async move {
        if let Err(err) = ipc::serve(socket_path, ipc_state, ipc_shutdown).await {
            tracing::error!("ipc server failed: {err}");
        }
    });

    // Wait for SIGTERM/SIGINT or an authorized IPC QUIT.
    tokio::select! {
        () = terminate_signal() => tracing::info!("signal received; shutting down"),
        () = state.wait_shutdown() => tracing::info!("quit requested; shutting down"),
    }
    state.request_shutdown();

    // Bounded wind-down: every task observes the shutdown broadcast. The
    // net task only stops through cancellation (its documented stop —
    // dropping the `run` future cancels uploader/updater/dashboard), so it
    // is cancelled AFTER the final flush below (while its receiver lives).
    for task in tasks {
        let mut task = task;
        if tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .is_err()
        {
            // A task that ignores the shutdown broadcast is aborted: a detached
            // capture task could otherwise keep writing the spool while the
            // final flush and WAL checkpoint run.
            task.abort();
            tracing::warn!("a task exceeded its shutdown deadline and was aborted");
        }
    }
    let mut ipc = ipc;
    if tokio::time::timeout(Duration::from_secs(5), &mut ipc)
        .await
        .is_err()
    {
        ipc.abort();
        tracing::warn!("the ipc server exceeded its shutdown deadline and was aborted");
    }

    // §11 `prerm` shape: bounded flush first (partial results still count),
    // then the §6.1 WAL checkpoint.
    let flush_state = Arc::clone(&state);
    match tokio::task::spawn_blocking(move || flush_state.flush_outbox(Duration::from_secs(5)))
        .await
    {
        Ok(Ok(flushed)) => tracing::info!("final flush: {flushed} row(s)"),
        Ok(Err(err)) => tracing::warn!("final flush skipped: {err}"),
        Err(err) => tracing::warn!("final flush task failed: {err}"),
    }
    net_task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(5), net_task).await;
    checkpoint_outbox(&outbox_path(&cfg));

    // §10: a clean shutdown must not look like a crash on the next start.
    ledger.mark_clean();

    tracing::info!("lustlessd stopped");
    Ok(())
}

/// §10 crash report for the previous run: CE reports accumulated crash counts
/// as a `client_crash{crash_type,count}` metrics event at the next successful
/// start, bumps the telemetry counter, attaches the log groups and clears the
/// counter. The attachments never include the activity databases
/// (`91-linux-mapping.md` §10).
fn report_previous_crash(state: &DaemonState, ledger: &crash::CrashLedger, crash_type: crash::CrashType) {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let (count, crashes_at) = state.with_outbox(|outbox| ledger.bump(outbox, now));

    // Sanitized state summary (replaces CE's `debugDB.zip`).
    let summary = serde_json::json!({
        "version": lustless_core::LUSTLESS_VERSION,
        "crashes_at": crashes_at,
        "crashes_since": count,
        "crash_type": crash_type.as_str(),
        "note": "LustLess never attaches the activity databases (CONTRACTS §10)",
    })
    .to_string();

    let log_dir = std::path::PathBuf::from("/var/log/lustless");
    let mut sources = Vec::new();
    if log_dir.exists() {
        sources.push(("debugLogs".to_string(), log_dir.clone()));
    }
    let classifier_logs = log_dir.join("classifier");
    if classifier_logs.exists() {
        sources.push(("debugClassLogs".to_string(), classifier_logs));
    }
    match ledger.collect_attachments(&sources, &summary) {
        Ok(dir) => tracing::warn!(
            "previous run crashed ({}, {} in window) — attachments in {}",
            crash_type.as_str(),
            count,
            dir.display()
        ),
        Err(err) => tracing::warn!("crash attachments failed: {err}"),
    }

    // CE's `client_crash{crash_type=…, count=…}` metrics event.
    let tag = lustless_core::metrics::AggTag {
        aggregation: lustless_core::metrics::Aggregation::Cardinal,
        name: "crash_type".to_string(),
        value: crash_type.as_str().to_string(),
    };
    if let Err(err) = state.record_metric_tagged(
        "",
        lustless_core::metrics::MetricName::ClientCrash,
        &[tag],
        &[DaemonState::counter_field("crash_count", count as u64)],
    ) {
        tracing::warn!("client_crash metric failed: {err}");
    }

    // CE's telemetry crash counter (`updateProcessCrashes("client", +1)`).
    let device = state.device_name();
    let row = crash::telemetry_row(crash_type, count, &device);
    if let Err(err) = state.insert_telemetry(row) {
        tracing::warn!("client_crashes telemetry failed: {err}");
    }

    state.notify(
        "error",
        &format!(
            "LustLess recovered from a crash ({}); diagnostics were collected",
            crash_type.as_str()
        ),
        None,
    );
    state.with_outbox(|outbox| ledger.clear(outbox));
}
