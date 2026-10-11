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
        Ok(journald) => tracing_subscriber::registry().with(journald).with(info).init(),
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
    match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get::<_, i64>(0)) {
        Ok(busy) if busy == 0 => tracing::info!("outbox WAL checkpointed (§6.1)"),
        Ok(busy) => tracing::warn!("outbox WAL checkpoint busy ({busy})"),
        Err(err) => tracing::warn!("outbox WAL checkpoint failed: {err}"),
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::var_os("LUSTLESS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/lustless/lustless.toml"));
    let cfg = Arc::new(LustlessConfig::load(&config_path));
    ensure_layout(&cfg)?;

    let outbox = Arc::new(Mutex::new(Outbox::open(&outbox_path(&cfg))?));
    let clock = Arc::new(RwLock::new(ClockAnchor::system()));
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
    let policy: Arc<dyn PolicyProvider> = Arc::clone(&state);
    let notifier: Arc<dyn Notifier> = Arc::clone(&state);
    let control: Arc<dyn Control> = Arc::clone(&state);
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
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), ipc).await;

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

    tracing::info!("lustlessd stopped");
    Ok(())
}
