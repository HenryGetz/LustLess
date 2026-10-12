//! Background poll loop (CONTRACTS §13/§5): one thread keeps a connection
//! cadence against the daemon socket — `POLL` (0x55) every ~2.5 s to drain
//! queued `NOTIFICATION` frames, `POLICY_GET` (0x60) every ~5 s to repaint
//! the tray — and pushes [`Update`]s to the GTK main thread through a
//! channel (the main loop drains it on a short timeout, so no `Send` GTK
//! objects ever cross threads).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use lustless_core::policy::PolicySnapshot;
use lustless_core::wire::Code;

use crate::ipc;

/// Poll cadence for `POLL` (0x55).
const TICK: Duration = Duration::from_millis(2500);
/// `POLICY_GET` every n-th tick → ~5 s.
const POLICY_EVERY_TICKS: usize = 2;
/// Read budget per poll request (local daemon; short so the loop stays live).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Backoff when the daemon is unreachable.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// One update from the daemon toward the UI.
#[derive(Debug, Clone)]
pub enum Update {
    /// Fresh §9 snapshot (`Err` = the reply did not parse).
    Policy(Result<PolicySnapshot, String>),
    /// Daemon reachability flipped (icon greys out / recovers).
    Reachable(bool),
    /// A §5 0x02 `NOTIFICATION` frame (CE progress vocabulary).
    Notification { level: String, message: String },
}

/// Handle to stop the worker on Quit.
pub struct Worker {
    stop: Arc<AtomicBool>,
}

impl Worker {
    /// Signals the loop to exit after the current tick.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Spawns the poll thread.
pub fn spawn(socket_path: PathBuf, tx: Sender<Update>) -> Worker {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let spawned = thread::Builder::new()
        .name("lustless-agent-poll".into())
        .spawn(move || run(&flag, &socket_path, &tx));
    match spawned {
        Ok(_) => Worker { stop },
        Err(err) => {
            tracing::error!(target: "agent", "cannot spawn the poll thread: {err}");
            Worker { stop }
        }
    }
}

fn run(stop: &AtomicBool, socket_path: &Path, tx: &Sender<Update>) {
    // One persistent connection: the daemon queues §5 0x02 NOTIFICATION
    // frames per accepted connection, so churning sockets each tick would
    // drop async progress. A transport error tears the connection down and
    // the loop reconnects after a backoff.
    let mut conn: Option<ipc::Connection> = None;
    let mut reachable = false;
    let mut ticks: usize = 0;

    while !stop.load(Ordering::Relaxed) {
        // Establish / keep a live connection.
        if conn.is_none() {
            match ipc::Connection::connect(socket_path) {
                Ok(established) => {
                    conn = Some(established);
                    tracing::info!(target: "agent", "connected to lustlessd at {}", socket_path.display());
                }
                Err(err) => {
                    tracing::debug!(target: "agent", "daemon unreachable: {err}");
                    if reachable {
                        reachable = false;
                        let _ = tx.send(Update::Reachable(false));
                    }
                    thread::sleep(RECONNECT_DELAY);
                    continue;
                }
            }
        }

        // Scoped so the `conn` borrow ends before any reconnect assignment.
        let poll_failed = {
            let live = conn.as_mut().expect("connected above");
            // 1. Drain queued notifications (§5 0x55 POLL).
            match live.request(Code::Poll, Value::Null, REQUEST_TIMEOUT) {
                Ok((_, notifications)) => {
                    if !reachable {
                        reachable = true;
                        let _ = tx.send(Update::Reachable(true));
                    }
                    emit_notifications(tx, &notifications);
                    false
                }
                Err(err) => {
                    tracing::debug!(target: "agent", "POLL failed ({err}); reconnecting");
                    true
                }
            }
        };
        if poll_failed {
            conn = None;
            if reachable {
                reachable = false;
                let _ = tx.send(Update::Reachable(false));
            }
            thread::sleep(RECONNECT_DELAY);
            continue;
        }

        // 2. Refresh the policy snapshot every ~5 s.
        if ticks.is_multiple_of(POLICY_EVERY_TICKS) {
            let live = conn.as_mut().expect("connected above");
            match live.request(Code::PolicyGet, json!({}), REQUEST_TIMEOUT) {
                Ok((reply, notifications)) => {
                    emit_notifications(tx, &notifications);
                    let update = match reply.get("policy") {
                        Some(policy) => {
                            match serde_json::from_value::<PolicySnapshot>(policy.clone()) {
                                Ok(snapshot) => Update::Policy(Ok(snapshot)),
                                Err(err) => Update::Policy(Err(format!(
                                    "policy snapshot does not match the core type: {err}"
                                ))),
                            }
                        }
                        None => Update::Policy(Err("reply has no policy field".to_string())),
                    };
                    let _ = tx.send(update);
                }
                Err(err) => {
                    // Leave the connection up; the next POLL decides liveness.
                    tracing::warn!(target: "agent", "POLICY_GET failed: {err}");
                }
            }
        }

        ticks = ticks.wrapping_add(1);
        thread::sleep(TICK);
    }
}

fn emit_notifications(tx: &Sender<Update>, payloads: &[Value]) {
    for payload in payloads {
        let level = payload
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_string();
        let message = payload
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !message.is_empty() {
            let _ = tx.send(Update::Notification { level, message });
        }
    }
}
