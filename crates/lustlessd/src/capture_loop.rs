//! Capture loop — CONTRACTS §7 (jittered cadence, gate ladder, backend
//! select), §6.3 (spool transactions + tamper signal) and §14
//! (`client_screenshot` metric).
//!
//! One tick per cadence:
//!
//! 1. gates — capture enabled + signed-in screen-accountability session,
//!    classifier alive (CE's `isClassifierRunning`), logind unlocked+active
//!    (`sessions.rs` registry), screensaver inactive (§7; skip entirely),
//! 2. backend select ([`lustless_capture::resolve_backend`]: `auto` = X11 when
//!    the *session's* logind `Type` is x11, else Wayland — the daemon's own
//!    environment says nothing about the user's session),
//! 3. capture → §6.3 transaction (`im<N>.png` + `manifest.json` + atomic
//!    `ready`),
//! 4. bookkeeping — `client_screenshot` metric, `circumventions` rows for
//!    restricted windows (§7: flagged, never aborted), tamper drain
//!    (`Circumvention: PDL transaction file removed|renamed`, §6.3).
//!
//! Retry ladder (CE, `capture-pipeline.md` §1): 5 s while a gate/classifier
//! is down, jittered `U[(1−v)I,(1+v)I]` after a capture, 60 s when capture
//! failed.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use lustless_capture::manifest::ScreenstateManifest;
use lustless_capture::scheduler::{BackendChoice, Scheduler};
use lustless_capture::spool::READY_MARKER;
use lustless_capture::x11;
use lustless_capture::{Capture, CaptureBackend, SpoolWatcher, TransactionWriter};
use lustless_core::clock::local_timezone_offset;
use lustless_core::ids;
use lustless_core::metrics::MetricName;

use crate::sessions::{SessionEnv, SessionRegistry};
use crate::state::{wait_or_shutdown, CreatedTxn, DaemonState};

/// How often the daemon sweeps the spool for orphans.
const CLEANUP_EVERY: Duration = Duration::from_secs(300);
/// CE's spool ages (`capture-pipeline.md` §"clean PDL send folders"): the
/// classifier uses the same pair at its startup.
const INCOMPLETE_MAX_AGE: Duration = Duration::from_secs(3600);
const STALE_MAX_AGE: Duration = Duration::from_secs(1800);
/// Last sweep (process-wide; the loop is single-instance).
static CLEANUP_LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// CE's gate/classifier-down retry (§7: `5000 ms`).
const GATE_RETRY: Duration = Scheduler::RETRY_CLASSIFIER_DOWN;

/// `circumventions.interruption_type` for capture-restricted windows (§7,
/// evidence `filter-surface.md` §7: CE's literal at `0x1408e1050`).
const INTERRUPTION_RESTRICTED: &str = "windows-screen-recording-not-allowed";

/// `circumventions.interruption_type` for §6.3 tamper (LustLess spelling of
/// CE's log vocabulary `removed|renamed`).
const INTERRUPTION_TAMPER_REMOVED: &str = "pdl-transaction-file-removed";
const INTERRUPTION_TAMPER_RENAMED: &str = "pdl-transaction-file-renamed";

/// Drives capture for the signed-in session until shutdown.
pub async fn run(
    state: Arc<DaemonState>,
    registry: Arc<SessionRegistry>,
    mut shutdown: watch::Receiver<bool>,
) {
    // The screensaver gate lives on the user's session bus; a system daemon
    // usually has none (§7/capture-crate policy: disable the gate with a
    // warning, logind still gates).
    let session_bus = match zbus::Connection::session().await {
        Ok(conn) => Some(conn),
        Err(err) => {
            tracing::warn!("capture: session bus unavailable, screensaver gate disabled: {err}");
            None
        }
    };

    let mut backend: Option<Box<dyn CaptureBackend>> = None;
    let mut watcher: Option<SpoolWatcher> = None;
    let mut watcher_key: Option<String> = None;
    // Last session environment applied to this process (see `SessionEnv::apply`).
    let mut session_env: Option<SessionEnv> = None;

    loop {
        if *shutdown.borrow() {
            break;
        }
        let delay = tick(
            &state,
            &registry,
            session_bus.as_ref(),
            &mut backend,
            &mut watcher,
            &mut watcher_key,
            &mut session_env,
        )
        .await;
        if wait_or_shutdown(&mut shutdown, delay).await {
            break;
        }
    }
    state.set_capture_active(false);
    tracing::info!("capture: loop stopped");
}

async fn tick(
    state: &Arc<DaemonState>,
    registry: &Arc<SessionRegistry>,
    session_bus: Option<&zbus::Connection>,
    backend: &mut Option<Box<dyn CaptureBackend>>,
    watcher: &mut Option<SpoolWatcher>,
    watcher_key: &mut Option<String>,
    session_env: &mut Option<SessionEnv>,
) -> Duration {
    let cfg = state.config();

    // §7: capture enabled?
    if !cfg.capture.enabled {
        state.set_capture_active(false);
        return GATE_RETRY;
    }
    // Signed-in screen-accountability session?
    let Some((uid, username)) = state.session().ok() else {
        state.set_capture_active(false);
        return GATE_RETRY;
    };
    if !state.policy_state().flags.has_screen_accountability {
        state.set_capture_active(false);
        return GATE_RETRY;
    }
    // §6.3 spool hygiene: the classifier only cleans orphans at *its* startup,
    // so a daemon killed mid-transaction (or a classifier that is alive but
    // not consuming) would leak folders — and disk — forever. The daemon runs
    // the same cleanup on a slow cadence.
    {
        let now = std::time::Instant::now();
        let mut last = CLEANUP_LAST.lock().unwrap_or_else(|err| err.into_inner());
        if last
            .map(|at| now.duration_since(at) > CLEANUP_EVERY)
            .unwrap_or(true)
        {
            *last = Some(now);
            let spool = PathBuf::from(&cfg.capture.spool_dir);
            let uid_name = lustless_core::ids::url_safe_username(&username);
            match lustless_capture::spool::cleanup_orphaned(
                &spool,
                &uid_name,
                INCOMPLETE_MAX_AGE,
                STALE_MAX_AGE,
            ) {
                Ok(report)
                    if !report.removed_incomplete.is_empty()
                        || !report.removed_stale.is_empty() =>
                {
                    tracing::info!(
                        "capture: spool cleanup removed {} incomplete and {} stale transaction(s)",
                        report.removed_incomplete.len(),
                        report.removed_stale.len()
                    );
                }
                Ok(_) => {}
                Err(err) => tracing::debug!("capture: spool cleanup skipped: {err}"),
            }
        }
    }

    // §7 classifier-alive gate (CE: 5 s while it is down).
    if !state.classifier_alive() {
        state.set_capture_active(false);
        tracing::info!("Skip capturing Screenstate (classifier not running)");
        return GATE_RETRY;
    }
    // §13/§7 logind gates.
    if let Some(reason) = registry.gate(uid) {
        state.set_capture_active(false);
        tracing::info!("Skip capturing Screenstate ({reason})");
        return GATE_RETRY;
    }
    // §7 screensaver gate.
    match screensaver_active(session_bus).await {
        Some(true) => {
            state.set_capture_active(false);
            tracing::info!("Skip capturing Screenstate (screensaver active)");
            return GATE_RETRY;
        }
        Some(false) => {}
        None => {} // cannot tell → fail open with the warning logged at start
    }

    // The §6.3 tamper watcher follows this session's spool tree.
    let spool_key = ids::url_safe_username(&username);
    if watcher_key.as_deref() != Some(spool_key.as_str()) {
        match SpoolWatcher::open(Path::new(&cfg.capture.spool_dir), &spool_key) {
            Ok(fresh) => {
                adopt_ready_transactions(state, fresh.root());
                *watcher = Some(fresh);
                *watcher_key = Some(spool_key.clone());
            }
            Err(err) => {
                tracing::error!("capture: spool watcher open failed: {err}");
                return GATE_RETRY;
            }
        }
    }

    // §13: never capture a remote/SSH or text session — there is no local
    // screen worth capturing and capturing one would be a privacy leak.
    let session = registry.session_for_uid(uid);
    if let Some(session) = session.as_ref() {
        if !session.capturable() {
            state.set_capture_active(false);
            let reason = session.skip_reason().unwrap_or("non-capturable session");
            tracing::info!("Skip capturing Screenstate ({reason})");
            return GATE_RETRY;
        }

        // Point the daemon's process at the *session's* environment (DISPLAY,
        // XAUTHORITY, XDG_RUNTIME_DIR, session bus) before any backend reads
        // it. Applied once when a session is first resolved and again only when
        // the resolved session changes; a changed session invalidates the
        // cached backend, which was opened against the old environment.
        let env = SessionEnv::resolve(uid, session);
        if session_env.as_ref() != Some(&env) {
            env.apply();
            if session_env.is_some() {
                *backend = None;
            }
            tracing::info!(
                "capture: session env applied (uid {}, type {:?}, display {:?})",
                env.uid,
                env.kind,
                env.display
            );
            *session_env = Some(env);
        }
    } else if registry.bus_ok() {
        // The gate above allowed this tick, so logind knows an active+unlocked
        // session exists; a missing entry means it vanished mid-tick.
        state.set_capture_active(false);
        tracing::info!("Skip capturing Screenstate (session vanished)");
        return GATE_RETRY;
    } else {
        // logind is unreachable: fail open (§7) with the daemon's own
        // environment, exactly as before session discovery existed.
        tracing::debug!("capture: logind unavailable; session environment unknown");
    }

    // Backend select (§7: `auto` = X11 when the session's display server is
    // X11, else Wayland — the daemon's own environment says nothing about the
    // user's session).
    if backend.is_none() {
        let choice = match BackendChoice::parse(&cfg.capture.backend) {
            Ok(choice) => choice,
            Err(err) => {
                tracing::error!("capture: bad capture.backend value: {err}");
                return GATE_RETRY;
            }
        };
        let session_type = session.as_ref().and_then(|s| s.kind.as_session_type());
        // The portal grant is per user: keep the ScreenCast restore token beside
        // that user's other state so the compositor does not re-prompt on every
        // login (the dialog is the difference between a quiet background agent
        // and one that nags the person it is accountable to).
        let portal_token = state
            .uid_dir(uid)
            .ok()
            .map(|dir| dir.join("portal-restore-token"));
        match x11::open(choice, session_type, portal_token) {
            Ok(opened) => {
                tracing::info!(
                    "capture: backend selected ({:?})",
                    lustless_capture::resolve_backend(choice, session_type)
                );
                *backend = Some(opened);
            }
            Err(err) => {
                tracing::error!("capture: backend open failed: {err}");
                return Scheduler::RETRY_WORST;
            }
        }
    }

    // Drain batches the classifier scored BEFORE pumping inotify events: the
    // consumed folders' watches are retired first, so their later deletion is
    // not reported as tamper (§6.3).
    if let Some(watcher) = watcher.as_mut() {
        for folder in state.drain_consumed_transactions() {
            watcher.mark_consumed(&folder);
        }
    }

    // Capture.
    let capture = match backend
        .as_mut()
        .expect("backend checked above")
        .capture()
        .await
    {
        Ok(capture) if capture.is_empty() => {
            tracing::warn!("capture: no monitor captured");
            return Scheduler::RETRY_WORST;
        }
        Ok(capture) => capture,
        Err(err) => {
            tracing::warn!("capture: backend capture failed: {err}");
            return Scheduler::RETRY_WORST;
        }
    };

    // Restricted windows (§7): flagged rows, never an abort.
    let restricted: Vec<(String, String)> = capture
        .apps
        .iter()
        .filter(|app| app.do_not_score)
        .map(|app| (app.name.clone(), app.window_title.clone()))
        .collect();

    match write_transaction(state, &spool_key, capture).await {
        Ok((folder, folder_name, manifest_ts)) => {
            state.mark_screenstate();
            if let Err(err) = state.record_metric(
                &username,
                MetricName::ClientScreenshot,
                &[DaemonState::counter_field("screenshot_count", 1)],
            ) {
                tracing::warn!("client_screenshot metric failed: {err}");
            }
            state.remember_transaction(CreatedTxn {
                folder,
                folder_name,
                manifest_ts,
            });
            // §7: restricted windows produce a `circumventions` row (flagged,
            // never aborted). The row is recorded locally regardless of the
            // §10 `upload.circumvention_records` toggle — the toggle governs
            // *uploading* circumvention records (owned by lustless-net); the
            // flagged classifier rows follow the assignment's explicit gate.
            for (app, title) in restricted {
                tracing::info!(
                    "Possible circumvention: Screen capture is restricted for App: `{app}` with Window Title: `{title}`"
                );
                let title = if title.is_empty() {
                    None
                } else {
                    Some(title.as_str())
                };
                if let Err(err) =
                    state.record_circumvention(&username, INTERRUPTION_RESTRICTED, &app, title)
                {
                    tracing::warn!("restricted-window row failed: {err}");
                }
            }
            // Pump inotify (absorbing our own `ready` event) then drain the
            // tamper signal (§6.3).
            if let Some(watcher) = watcher.as_mut() {
                if let Err(err) = watcher.wait_ready(Duration::ZERO) {
                    tracing::warn!("capture: spool pump failed: {err}");
                }
                drain_tamper(state, &username, watcher);
            }
            scheduler(&cfg).steady_delay()
        }
        Err(err) => {
            tracing::error!("capture: transaction failed: {err}");
            Scheduler::RETRY_WORST
        }
    }
}

/// Jittered §7 scheduler from the (live) config.
fn scheduler(cfg: &lustless_core::config::LustlessConfig) -> Scheduler {
    Scheduler::new(cfg.capture.interval_sec, cfg.capture.variance_pct as f64)
}

/// Records the §6.3 tamper signal: the exact CE journal line plus a
/// `circumventions` row.
fn drain_tamper(state: &DaemonState, username: &str, watcher: &mut SpoolWatcher) {
    for event in watcher.drain_tamper() {
        tracing::warn!("{}", event.log_line());
        let interruption = match event.kind {
            lustless_capture::spool::TamperKind::Removed => INTERRUPTION_TAMPER_REMOVED,
            lustless_capture::spool::TamperKind::Renamed => INTERRUPTION_TAMPER_RENAMED,
        };
        let app_name = event
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "pdl-transaction".to_string());
        let path = event.path.display().to_string();
        if let Err(err) = state.record_circumvention(username, interruption, &app_name, Some(&path))
        {
            tracing::warn!("tamper circumvention row failed: {err}");
        }
    }
}

/// Registers §6.3 transactions that were ready before this daemon (or this
/// spool key) started, so their consumption is recognized (matched by a
/// classifier `result`) instead of looking like tamper.
fn adopt_ready_transactions(state: &DaemonState, pdl_root: &Path) {
    let entries = match std::fs::read_dir(pdl_root) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!("capture: cannot scan {pdl_root:?} for ready transactions: {err}");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() || !path.join(READY_MARKER).exists() {
            continue;
        }
        let folder_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let manifest_path = path.join("manifest.json");
        let manifest_ts = std::fs::read_to_string(&manifest_path)
            .ok()
            .and_then(|text| ScreenstateManifest::from_json(&text).ok())
            .map(|manifest| manifest.datetime_created)
            .unwrap_or_else(|| folder_name.clone());
        state.remember_transaction(CreatedTxn {
            folder: path,
            folder_name,
            manifest_ts,
        });
    }
}

/// `org.freedesktop.ScreenSaver.GetActive` on the user's session bus;
/// `None` = cannot tell (fail open).
async fn screensaver_active(session_bus: Option<&zbus::Connection>) -> Option<bool> {
    let conn = session_bus?;
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.ScreenSaver",
        "/org/freedesktop/ScreenSaver",
        "org.freedesktop.ScreenSaver",
    )
    .await
    .ok()?;
    proxy
        .call_method("GetActive", &())
        .await
        .ok()?
        .body()
        .deserialize::<bool>()
        .ok()
}

/// One §6.3 file transaction: `im<N>.png` per monitor + `manifest.json` +
/// atomic `ready` marker (§6.3). Returns `(folder, folder_name,
/// manifest_ts)`.
async fn write_transaction(
    state: &DaemonState,
    spool_key: &str,
    capture: Capture,
) -> Result<(PathBuf, String, String), String> {
    let spool_dir = PathBuf::from(&state.config().capture.spool_dir);
    let key = spool_key.to_string();
    let datetime_created = manifest_datetime_now();
    let local_offset = local_timezone_offset();
    let device_uuid = state.device_id();

    tokio::task::spawn_blocking(move || {
        let mut writer =
            TransactionWriter::begin(&spool_dir, &key).map_err(|err| err.to_string())?;
        let folder_name = writer
            .folder()
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut images = Vec::with_capacity(capture.monitors.len());
        let mut monitors = Vec::with_capacity(capture.monitors.len());
        for monitor in &capture.monitors {
            let index = writer
                .write_monitor_png(&monitor.image)
                .map_err(|err| err.to_string())?;
            images.push(lustless_capture::manifest::ImageEntry {
                filename: format!("im{index}.png"),
                screen_rect: monitor.rect,
            });
            monitors.push(monitor.rect);
        }
        let apps = capture
            .apps
            .iter()
            .map(|app| lustless_capture::manifest::AppEntry {
                name: app.name.clone(),
                window_title: app.window_title.clone(),
                app_rect: app.app_rect,
                // Written only when true, like CE (§7).
                do_not_score: if app.do_not_score { Some(true) } else { None },
            })
            .collect();
        let manifest = ScreenstateManifest::new(
            key,
            datetime_created.clone(),
            local_offset,
            images,
            monitors,
            apps,
            device_uuid,
        );
        writer
            .write_manifest(&manifest)
            .map_err(|err| err.to_string())?;
        let folder = writer.finalize().map_err(|err| err.to_string())?;
        Ok::<(PathBuf, String, String), String>((folder, folder_name, datetime_created))
    })
    .await
    .map_err(|err| err.to_string())?
}

/// `manifest.datetime_created` in the §6.3 schema form
/// (`2026-10-11T12:00:00.000000Z`).
fn manifest_datetime_now() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.microsecond()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_datetime_matches_the_schema_shape() {
        let stamp = manifest_datetime_now();
        // 2026-10-11T05:00:00.123456Z
        assert_eq!(stamp.len(), 27, "{stamp}");
        assert_eq!(&stamp[4..5], "-", "{stamp}");
        assert_eq!(&stamp[10..11], "T", "{stamp}");
        assert_eq!(&stamp[19..20], ".", "{stamp}");
        assert!(stamp.ends_with('Z'), "{stamp}");
        assert!(
            stamp[..19]
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b':' || b == b'-' || b == b'T'),
            "{stamp}"
        );
    }

    #[test]
    fn gate_retry_matches_ce_ladder() {
        assert_eq!(GATE_RETRY, Duration::from_secs(5));
        assert_eq!(Scheduler::RETRY_WORST, Duration::from_secs(60));
        assert_eq!(Scheduler::RETRY_DEFAULT, Duration::from_secs(40));
    }

    /// The §7/§6.3 interruption vocabulary stays stable (upload consumers
    /// depend on it).
    #[test]
    fn interruption_vocabulary_is_stable() {
        assert_eq!(
            INTERRUPTION_RESTRICTED,
            "windows-screen-recording-not-allowed"
        );
        assert_eq!(INTERRUPTION_TAMPER_REMOVED, "pdl-transaction-file-removed");
        assert_eq!(INTERRUPTION_TAMPER_RENAMED, "pdl-transaction-file-renamed");
        assert_eq!(
            crate::classifier::INTERRUPTION_WINDOW_FLAGGED,
            "window-flagged"
        );
    }

    #[test]
    fn adopt_ready_transactions_registers_manifest_timestamps() {
        let ts = crate::state::test_util::test_state();
        let root = ts.dir.path().join("pdl");
        let folder = root.join("2026-10-11T05-00-00.123456");
        std::fs::create_dir_all(&folder).expect("folder");
        std::fs::write(folder.join(READY_MARKER), b"").expect("ready");
        let manifest = ScreenstateManifest::new(
            "alice".into(),
            "2026-10-11T05:00:00.123456Z".into(),
            "+00:00".into(),
            vec![],
            vec![],
            vec![],
            "device".into(),
        );
        std::fs::write(
            folder.join("manifest.json"),
            manifest.to_json().expect("json"),
        )
        .expect("manifest");

        adopt_ready_transactions(&ts.state, &root);
        // The manifest timestamp is what a `result.batch_ts` will echo.
        ts.state.note_result_batch("2026-10-11T05:00:00.123456Z");
        let consumed = ts.state.drain_consumed_transactions();
        assert_eq!(consumed, vec![folder]);
    }
}
