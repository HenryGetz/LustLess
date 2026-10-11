//! Support-bundle diagnostics — CONTRACTS §5 (IPC `0x43
//! `COLLECT_DEBUG_LOGS``), §14 (metric `collect_diagnostics_in_progress`) and
//! the §10 payload rule: a bundle carries logs, versions, the sanitized
//! config, a DB integrity report and crash counters — **never** the activity
//! databases (`outbox.db`, the per-user `settings.db`s or the screenstate
//! spool; evidence `re/findings/16-updater/crash-reporting.md` §3–§5,
//! `re/findings/91-linux-mapping.md` item 10: "sanitized state summary (never
//! the activity DBs)").
//!
//! Progress reaches clients through the §5 back-channel: CE's two texts
//! ("Diagnostics are being collected…" / "We've finished collecting
//! diagnostics", `service-ipc.md` §2) queued as `0x02 NOTIFICATION` frames.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lustless_core::clock::{iso8601_utc, system_unix};
use lustless_core::config::LustlessConfig;
use lustless_core::metrics::MetricName;
use lustless_core::LUSTLESS_VERSION;

use crate::classifier::CrashStore;
use crate::state::DaemonState;

/// CE's start text (§5 `service-ipc.md` §2).
pub const DIAG_START_MSG: &str = "Diagnostics are being collected…";
/// CE's finish text (§5).
pub const DIAG_DONE_MSG: &str = "We've finished collecting diagnostics";

/// Where the classifier's per-PID lifetime logs live (§4
/// `/var/log/lustless/classifier/<pid>.log`).
pub const CLASSIFIER_LOG_DIR: &str = "/var/log/lustless/classifier";

/// Newest log files bundled.
const LOG_FILE_CAP: usize = 5;
/// Bytes kept from the tail of each log file.
const LOG_TAIL_CAP: u64 = 256 * 1024;
/// Bytes kept of the model manifest inside `versions.txt`.
const MANIFEST_CAP: usize = 8 * 1024;

impl DaemonState {
    /// Starts one §5 `0x43` collection (idempotent): records the §14
    /// `collect_diagnostics_in_progress` metric, queues the CE start
    /// notification and spawns the worker thread. Returns `false` when a
    /// collection is already running.
    pub fn start_diagnostics(self: &Arc<Self>) -> bool {
        if !self.begin_diagnostics() {
            return false;
        }
        let state = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("lustless-diagnostics".into())
            .spawn(move || state.run_diagnostics());
        match spawned {
            Ok(_) => true,
            Err(err) => {
                self.set_diagnostics_in_progress(false);
                tracing::error!("diagnostics worker spawn failed: {err}");
                self.notify("error", &format!("Diagnostics collection failed: {err}"), None);
                false
            }
        }
    }

    /// Worker body: metric → start text → bundle → finish/failure text.
    fn run_diagnostics(self: Arc<Self>) {
        let username = self.username();
        if let Err(err) = self.record_metric(
            &username,
            MetricName::CollectDiagnosticsInProgress,
            &[DaemonState::counter_field("collect_diagnostics_count", 1)],
        ) {
            tracing::warn!("collect_diagnostics_in_progress metric failed: {err}");
        }
        self.notify("info", DIAG_START_MSG, Some(0));

        let cfg = self.config();
        let crash = self.crash.clone();
        let result = collect_bundle(
            &cfg,
            self.outbox_path(),
            &crash,
            Path::new(CLASSIFIER_LOG_DIR),
        );
        match result {
            Ok(path) => {
                tracing::info!("diagnostics bundle written: {}", path.display());
                self.notify("info", DIAG_DONE_MSG, Some(100));
            }
            Err(err) => {
                tracing::error!("diagnostics collection failed: {err}");
                self.notify("error", &format!("Diagnostics collection failed: {err}"), None);
            }
        }
        self.set_diagnostics_in_progress(false);
    }
}

/// Builds `<state_dir>/diagnostics-<ts>.tar.gz` (mode 0600) from metadata
/// entries. Never reads activity-database *content* (§10): the outbox only
/// contributes an integrity verdict and row counts, settings DBs only file
/// sizes.
pub fn collect_bundle(
    cfg: &LustlessConfig,
    outbox_path: &Path,
    crash: &CrashStore,
    log_dir: &Path,
) -> Result<PathBuf, String> {
    let ts = bundle_stamp();
    let entries = build_entries(cfg, outbox_path, crash, log_dir, &ts);
    let out_path = Path::new(&cfg.daemon.state_dir).join(format!("diagnostics-{ts}.tar.gz"));
    write_tar_gz(&entries, &out_path)?;
    Ok(out_path)
}

/// `YYYYmmddTHHMMSSZ` from the system clock — filesystem-safe (§4 naming).
fn bundle_stamp() -> String {
    let base = iso8601_utc(system_unix()).replace(['-', ':'], "");
    format!("{}Z", base.trim_end_matches('Z'))
}

/// All bundle entries, best effort: an unreadable source degrades to a note
/// inside its entry instead of failing the bundle.
fn build_entries(
    cfg: &LustlessConfig,
    outbox_path: &Path,
    crash: &CrashStore,
    log_dir: &Path,
    ts: &str,
) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    entries.push((
        "README.txt".to_string(),
        format!(
            "LustLess support bundle\n\
             collected_at={ts}\n\
             version={LUSTLESS_VERSION}\n\
             \n\
             Contents: versions, sanitized system config, outbox integrity report\n\
             (verdict + row counts only), settings-DB inventory (file sizes only),\n\
             classifier crash counters and the newest classifier logs.\n\
             \n\
             This bundle never contains activity databases or screenstate data\n\
             (CONTRACTS §10 payload rule).\n"
        )
        .into_bytes(),
    ));

    entries.push((
        "versions.txt".to_string(),
        versions_report(cfg).into_bytes(),
    ));

    match toml::to_string_pretty(cfg) {
        Ok(text) => entries.push((
            "config/lustless.toml".to_string(),
            // §9.1: the system config carries no secrets (0644, root-owned);
            // it is included verbatim as the sanitized state summary.
            text.into_bytes(),
        )),
        Err(err) => entries.push((
            "config/lustless.toml".to_string(),
            format!("config serialization failed: {err}\n").into_bytes(),
        )),
    }

    entries.push((
        "integrity/outbox.txt".to_string(),
        outbox_integrity(outbox_path).into_bytes(),
    ));
    entries.push((
        "integrity/settings-dbs.txt".to_string(),
        settings_db_inventory(Path::new(&cfg.daemon.state_dir)).into_bytes(),
    ));
    entries.push((
        "crash-counters.json".to_string(),
        serde_json::to_vec_pretty(&crash.snapshot(&state_dir_uids(&cfg.daemon.state_dir)))
            .unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}").into_bytes()),
    ));

    for (name, bytes) in classifier_log_tails(log_dir) {
        entries.push((format!("logs/classifier/{name}"), bytes));
    }
    entries
}

/// Daemon/classifier/model version inventory.
fn versions_report(cfg: &LustlessConfig) -> String {
    let mut out = format!("lustlessd {LUSTLESS_VERSION}\n");
    out.push_str(&format!("state_dir: {}\n", cfg.daemon.state_dir));
    out.push_str(&format!("upload.base_url: {}\n", cfg.upload.base_url));
    for (label, path) in [
        ("classifier.bin", cfg.classifier.bin.as_str()),
        ("classifier.model_dir", cfg.classifier.model_dir.as_str()),
    ] {
        let present = Path::new(path).exists();
        out.push_str(&format!("{label}: {path} (present: {present})\n"));
    }
    let manifest_path = Path::new(&cfg.classifier.model_dir).join("manifest.json");
    match std::fs::read(&manifest_path) {
        Ok(bytes) => {
            let head: String = bytes
                .iter()
                .take(MANIFEST_CAP)
                .map(|b| char::from(*b))
                .collect();
            out.push_str(&format!("\nmodel manifest ({} bytes):\n{head}\n", bytes.len()));
        }
        Err(err) => out.push_str(&format!("\nmodel manifest unreadable: {err}\n")),
    }
    out
}

/// `PRAGMA integrity_check` + per-table row counts (counts only — §10).
fn outbox_integrity(outbox_path: &Path) -> String {
    if !outbox_path.exists() {
        return format!("outbox: {} not present\n", outbox_path.display());
    }
    let conn = match rusqlite::Connection::open_with_flags(
        outbox_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(conn) => conn,
        Err(err) => return format!("outbox: open failed: {err}\n"),
    };
    let verdict: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap_or_else(|err| format!("error: {err}"));
    let mut out = format!("integrity_check: {verdict}\n");
    for table in [
        "install_metadata",
        "logins",
        "metrics",
        "circumventions",
        "switch_users",
        "dns_activity",
        "telemetry",
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .unwrap_or(-1);
        out.push_str(&format!("{table}: {count}\n"));
    }
    out
}

/// Numeric uid directories under `<state_dir>` (§4) — the uids whose §11
/// crash counters exist.
fn state_dir_uids(state_dir: &str) -> Vec<u32> {
    let mut uids = Vec::new();
    if let Ok(entries) = std::fs::read_dir(state_dir) {
        for entry in entries.flatten() {
            if let Some(uid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            {
                uids.push(uid);
            }
        }
    }
    uids.sort_unstable();
    uids
}

/// Per-user settings DB inventory: existence + sizes only (§10).
fn settings_db_inventory(state_dir: &Path) -> String {
    let mut out = String::new();
    let entries = match std::fs::read_dir(state_dir) {
        Ok(entries) => entries,
        Err(err) => return format!("state dir unreadable: {err}\n"),
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let db = dir.join("settings.db");
        let key = dir.join("settings.key");
        let size = std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0);
        out.push_str(&format!(
            "uid {name}: settings.db={size} bytes (present: {}), settings.key (present: {})\n",
            db.exists(),
            key.exists()
        ));
    }
    if out.is_empty() {
        out.push_str("no per-user settings directories\n");
    }
    out
}

/// Tails of the newest classifier lifetime logs (§4/§14).
fn classifier_log_tails(log_dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(std::time::SystemTime, String, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("log") {
                continue;
            }
            let modified = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let name = entry.file_name().to_string_lossy().into_owned();
            files.push((modified, name, path));
        }
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    files.truncate(LOG_FILE_CAP);

    files
        .into_iter()
        .map(|(_, name, path)| (name, tail_bytes(&path, LOG_TAIL_CAP).unwrap_or_default()))
        .collect()
}

/// Last `cap` bytes of a file (support logs can be large).
fn tail_bytes(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > cap {
        file.seek(SeekFrom::End(-(cap as i64)))?;
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Writes the entries as a `.tar.gz` at mode 0600 (§4).
fn write_tar_gz(entries: &[(String, Vec<u8>)], out_path: &Path) -> Result<(), String> {
    let file = std::fs::File::create(out_path)
        .map_err(|e| format!("create {}: {e}", out_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let now = system_unix().max(0) as u64;
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_mtime(now);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append_data(&mut header, name, bytes.as_slice())
            .map_err(|e| format!("tar append {name}: {e}"))?;
    }
    let encoder = builder.into_inner().map_err(|e| format!("tar finish: {e}"))?;
    let file = encoder.finish().map_err(|e| format!("gzip finish: {e}"))?;
    file.sync_all().map_err(|e| format!("sync: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_util::test_state;

    fn read_gz_names(path: &Path) -> Vec<String> {
        let file = std::fs::File::open(path).expect("open bundle");
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        let mut names = Vec::new();
        for entry in archive.entries().expect("tar entries") {
            let entry = entry.expect("entry");
            names.push(entry.path().expect("path").to_string_lossy().into_owned());
        }
        names
    }

    #[test]
    fn bundle_contains_metadata_but_never_activity_databases() {
        let ts = test_state();
        let state = &ts.state;
        let log_dir = ts.dir.path().join("classifier-logs");
        std::fs::create_dir_all(&log_dir).expect("log dir");
        std::fs::write(log_dir.join("1234.log"), b"Classifier: starting\n").expect("log file");

        // Pretend a classifier crash was recorded (counters land in the bundle).
        state.crash.record_crash(1000, 1_700_000_000);

        let cfg = state.config();
        let crash = state.crash.clone();
        let bundle = collect_bundle(&cfg, state.outbox_path(), &crash, &log_dir)
            .expect("bundle created");
        let name = bundle.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("diagnostics-") && name.ends_with(".tar.gz"), "{name}");

        // gzip magic.
        let mut magic = [0u8; 2];
        let mut file = std::fs::File::open(&bundle).expect("open");
        file.read_exact(&mut magic).expect("magic");
        assert_eq!(magic, [0x1f, 0x8b]);

        let names = read_gz_names(&bundle);
        for expected in [
            "README.txt",
            "versions.txt",
            "config/lustless.toml",
            "integrity/outbox.txt",
            "integrity/settings-dbs.txt",
            "crash-counters.json",
            "logs/classifier/1234.log",
        ] {
            assert!(names.iter().any(|n| n == expected), "missing {expected}: {names:?}");
        }
        // §10 payload rule: no activity DB ever enters the bundle.
        for forbidden in ["outbox.db", "settings.db", "settings.key", ".png"] {
            assert!(
                !names.iter().any(|n| n.contains(forbidden)),
                "activity data leaked: {forbidden} in {names:?}"
            );
        }
        std::fs::remove_file(&bundle).expect("cleanup");
    }

    #[test]
    fn bundle_degrades_gracefully_for_missing_sources() {
        let ts = test_state();
        let state = &ts.state;
        let cfg = state.config();
        let missing = ts.dir.path().join("no-such-outbox.db");
        let bundle = collect_bundle(
            &cfg,
            &missing,
            &state.crash,
            &ts.dir.path().join("no-such-log-dir"),
        )
        .expect("bundle still created");
        let names = read_gz_names(&bundle);
        assert!(names.iter().any(|n| n == "integrity/outbox.txt"));
        std::fs::remove_file(&bundle).expect("cleanup");
    }
}
