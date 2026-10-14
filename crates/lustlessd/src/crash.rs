//! Crash reporting pipeline (CONTRACTS §10/§12; `crash-reporting.md` §1–§5).
//!
//! CE registers a BugSplat reporter that, on a fatal error, zips the client
//! logs plus the SQLite databases (5 MB per file, 19 MB total), uploads the
//! report to the BugSplat SaaS, bumps a telemetry crash counter and launches
//! `RestartVSClientOnly.exe --RestartRequestFrom=<ver> --PID=<pid>`. On the
//! next successful start it reports the accumulated count as a
//! `client_crash{crash_type=GENERIC,count=N}` metrics event and clears it.
//!
//! The Linux equivalents keep the observable semantics:
//!
//! * **Detection** — a clean-shutdown marker. A missing marker at startup means
//!   the previous run died; systemd's `Restart=always` is CE's restart helper,
//!   so the crash is reported by the *next* start (exactly CE's timing).
//! * **Type** — a panic hook and fatal-signal handlers write the reason, so the
//!   metric's `crash_type` is `PANIC`/`SIGNAL` where CE hardcodes `GENERIC`.
//! * **Attachments** — the same bundle groups (`debugLogs`,
//!   `debugClassLogs`) with CE's byte caps, **minus the databases**: LustLess
//!   never ships `debugDB.zip`-style content, only a sanitized
//!   `state-summary.json` (`91-linux-mapping.md` §10 — deliberately stricter
//!   than CE, which uploads `ce-file`/`ce-user-file`).
//! * **Counters** — CE's `ClientCrashesAt`/`ClientCrashesSince` pair in
//!   `install_metadata` (the watchdog contract) plus the telemetry
//!   `client_crashes` row CE's BugSplat callback bumps.
//! * **Test hooks** — `--crashatonce=true` (CE's command-line switch) and
//!   `crash_test_hook = "force"` (CE's `ForceCrashClient` setting).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use lustless_core::db::{Outbox, TelemetryRow};

/// CE's per-attachment cap (`crash-reporting.md` §3: `< 0x500000`).
pub const ATTACH_FILE_CAP: u64 = 0x500000;
/// CE's total-attachment cap (`< 0x1300000`).
pub const ATTACH_TOTAL_CAP: u64 = 0x1300000;

/// Marker written on a clean shutdown and removed at startup: absent at
/// startup ⇒ the previous run died.
pub const CLEAN_MARKER: &str = "clean";
/// Best-effort reason written by the panic/signal hooks.
pub const REASON_FILE: &str = "last-reason";

/// `install_metadata` key for CE's `ClientCrashesAt` (last crash stamp).
const KEY_CRASHES_AT: &str = "client_crashes_at";
/// `install_metadata` key for CE's `ClientCrashesSince` (window counter).
const KEY_CRASHES_SINCE: &str = "client_crashes_since";

/// CE's reset window for `ClientCrashesSince` (`0x165a0bc00` ms ≈ 69 days).
pub const CRASH_WINDOW_SECS: i64 = 0x165a0bc00 / 1000;

/// The crash classes CE's `crash_type` tag carries (`GENERIC` is CE's only
/// observed value; PANIC/SIGNAL are the Linux-native refinements).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashType {
    /// Unknown/unspecified — CE's value, and the fallback here.
    Generic,
    /// Rust panic (the panic hook wrote the reason).
    Panic,
    /// Fatal signal (SIGSEGV/SIGABRT/SIGBUS/SIGILL).
    Signal,
}

impl CrashType {
    pub fn as_str(self) -> &'static str {
        match self {
            CrashType::Generic => "GENERIC",
            CrashType::Panic => "PANIC",
            CrashType::Signal => "SIGNAL",
        }
    }

    fn parse(value: &str) -> Self {
        match value.trim() {
            "PANIC" => CrashType::Panic,
            "SIGNAL" => CrashType::Signal,
            _ => CrashType::Generic,
        }
    }
}

/// One crash the previous run left behind, ready to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashRecord {
    pub crash_type: CrashType,
    /// Crash stamp (CE's `ClientCrashesAt` value), `%Y-%m-%dT%H:%M:%SZ`.
    pub crashes_at: String,
    /// Accumulated count for the reported metric (CE clears it after reporting).
    pub count: i64,
    /// Directory holding the attachments (CE's zip groups).
    pub bundle_dir: PathBuf,
}

/// Crash state under `<state_dir>/crash/`.
pub struct CrashLedger {
    dir: PathBuf,
    /// Set once the ledger has reported for this process (hooks stay armed).
    armed: AtomicBool,
}

impl CrashLedger {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            dir: state_dir.join("crash"),
            armed: AtomicBool::new(false),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn clean_marker(&self) -> PathBuf {
        self.dir.join(CLEAN_MARKER)
    }

    fn reason_file(&self) -> PathBuf {
        self.dir.join(REASON_FILE)
    }

    /// Path the fatal-signal handler writes (`LUSTLESS_CRASH_REASON`): the
    /// handler cannot touch Rust state, so the path is passed through the
    /// environment.
    pub fn reason_path(&self) -> std::ffi::OsString {
        self.reason_file().into_os_string()
    }

    /// Installs the panic hook and fatal-signal handlers (idempotent). The
    /// handlers only write the reason and re-raise, so systemd still sees the
    /// signal and applies its restart policy — CE's restart helper equivalent.
    pub fn install_hooks(&self) {
        if self.armed.swap(true, Ordering::SeqCst) {
            return;
        }
        let reason = self.reason_file();
        let panic_reason = reason.clone();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = fs::write(&panic_reason, CrashType::Panic.as_str());
            previous(info);
        }));
        for signal in [
            libc::SIGSEGV,
            libc::SIGABRT,
            libc::SIGBUS,
            libc::SIGILL,
            libc::SIGFPE,
        ] {
            // SAFETY: the handler only writes a small file and re-raises.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = fatal_signal_handler as usize;
                action.sa_flags = libc::SA_RESETHAND | libc::SA_NODEFER;
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, std::ptr::null_mut());
            }
        }
    }

    /// Startup: returns the previous run's crash (if it died) and re-arms the
    /// clean marker for this run. The marker is removed *before* the daemon
    /// does any work, so a crash during startup is still detected next time.
    pub fn begin(&self) -> Option<CrashType> {
        if !self.dir.exists() {
            // First ever start: nothing to report (CE's counters start clean
            // and only the restart helpers ever increment them).
            let _ = fs::create_dir_all(&self.dir);
            let _ = fs::write(self.clean_marker(), b"");
            let _ = fs::remove_file(self.clean_marker());
            return None;
        }
        let crashed = !self.clean_marker().exists();
        let _ = fs::remove_file(self.clean_marker());
        if !crashed {
            let _ = fs::remove_file(self.reason_file());
            return None;
        }
        let crash_type = fs::read_to_string(self.reason_file())
            .map(|value| CrashType::parse(&value))
            .unwrap_or(CrashType::Generic);
        let _ = fs::remove_file(self.reason_file());
        Some(crash_type)
    }

    /// Graceful shutdown: the next start must not report a crash.
    pub fn mark_clean(&self) {
        let _ = fs::create_dir_all(&self.dir);
        let _ = fs::write(self.clean_marker(), b"");
    }

    /// Records this crash in CE's counter pair and returns the accumulated
    /// count plus the stamp (the reported metric's `count`).
    pub fn bump(&self, outbox: &mut Outbox, now_unix: i64) -> (i64, String) {
        let since = self
            .crashes_since(outbox)
            .map(|(count, at)| {
                let expired = now_unix.saturating_sub(at) > CRASH_WINDOW_SECS;
                if expired {
                    0
                } else {
                    count
                }
            })
            .unwrap_or(0);
        let next = since + 1;
        let stamp = stamp_from_unix(now_unix);
        let _ = outbox.set_install_metadata(KEY_CRASHES_AT, &stamp);
        let _ = outbox.set_install_metadata(KEY_CRASHES_SINCE, &next.to_string());
        (next, stamp)
    }

    /// CE's `ClientCrashesSince` (count, stamp) pair.
    pub fn crashes_since(&self, outbox: &mut Outbox) -> Option<(i64, i64)> {
        let count = outbox
            .install_metadata(KEY_CRASHES_SINCE)
            .ok()
            .flatten()
            .and_then(|value| value.parse::<i64>().ok())?;
        let at = outbox
            .install_metadata(KEY_CRASHES_AT)
            .ok()
            .flatten()
            .and_then(|stamp| unix_from_stamp(&stamp))
            .unwrap_or(0);
        Some((count, at))
    }

    /// CE clears the counter once the report has been produced.
    pub fn clear(&self, outbox: &mut Outbox) {
        let _ = outbox.set_install_metadata(KEY_CRASHES_SINCE, "0");
    }

    /// Builds the attachment directory for one crash: CE's log groups under
    /// CE's caps, plus the sanitized state summary that replaces CE's
    /// `debugDB.zip` (never the activity databases).
    pub fn collect_attachments(
        &self,
        log_sources: &[(String, PathBuf)],
        state_summary: &str,
    ) -> Result<PathBuf, String> {
        fs::create_dir_all(&self.dir).map_err(|err| format!("crash dir: {err}"))?;
        let dir = self.dir.join(format!("report-{}", unix_now()));
        fs::create_dir_all(&dir).map_err(|err| format!("crash dir: {err}"))?;
        let mut total: u64 = 0;
        for (name, source) in log_sources {
            let mut bytes = Vec::new();
            collect_files(source, &mut bytes, ATTACH_FILE_CAP, &mut total)?;
            let path = dir.join(format!("{name}.tar"));
            write_capped(&path, &bytes)?;
        }
        write_capped(
            &dir.join("state-summary.json"),
            state_summary.as_bytes(),
        )?;
        Ok(dir)
    }
}

/// SAFETY: async-signal-safe work only (open/write a tiny file, re-raise).
extern "C" fn fatal_signal_handler(signal: libc::c_int) {
    let reason = match signal {
        libc::SIGABRT => CrashType::Signal,
        _ => CrashType::Signal,
    };
    let path = std::env::var_os("LUSTLESS_CRASH_REASON").map(PathBuf::from);
    if let Some(path) = path {
        if let Ok(mut file) = fs::File::create(&path) {
            let _ = file.write_all(reason.as_str().as_bytes());
        }
    }
    // Restore the default action and re-raise so the exit status stays a signal
    // (systemd's restart policy and `coredumpctl` both depend on that).
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

/// Appends every file under `dir` (depth 2, CE's log groups) up to `cap`,
/// honouring the running total cap.
fn collect_files(
    dir: &Path,
    out: &mut Vec<u8>,
    cap: u64,
    total: &mut u64,
) -> Result<(), String> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let child = entry.path();
            if child.is_dir() {
                stack.push(child);
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() > ATTACH_FILE_CAP {
                continue; // CE: attach only files < 5 MB
            }
            if *total + meta.len() > ATTACH_TOTAL_CAP {
                return Ok(()); // CE: stop at the 19 MB running total
            }
            let Ok(bytes) = fs::read(&child) else { continue };
            let name = child
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.extend_from_slice(format!("== {name} ==\n").as_bytes());
            let keep = bytes.len().min(cap as usize);
            out.extend_from_slice(&bytes[..keep]);
            out.push(b'\n');
            *total += keep as u64;
        }
    }
    Ok(())
}

fn write_capped(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let keep = bytes.len().min(ATTACH_FILE_CAP as usize);
    fs::write(path, &bytes[..keep]).map_err(|err| format!("{}: {err}", path.display()))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_secs() as i64)
        .unwrap_or(0)
}

/// `%Y-%m-%dT%H:%M:%SZ` (CE's `CrashesAt` stamp shape).
fn stamp_from_unix(unix: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(unix) {
        Ok(stamp) => {
            let stamp = stamp.to_offset(time::UtcOffset::UTC);
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                stamp.year(),
                stamp.month() as u8,
                stamp.day(),
                stamp.hour(),
                stamp.minute(),
                stamp.second()
            )
        }
        Err(_) => String::new(),
    }
}

fn unix_from_stamp(stamp: &str) -> Option<i64> {
    let parsed = time::OffsetDateTime::parse(
        stamp,
        &time::format_description::well_known::Rfc3339,
    )
    .ok()?;
    Some(parsed.unix_timestamp())
}

/// CE's `crashatonce=true` switch (an integer self-divide of zero on Windows;
/// here a fatal abort, which the signal hook records as SIGNAL).
pub fn forced_crash_requested(args: &[String], hook: &str) -> bool {
    args.iter()
        .any(|arg| arg == "--crashatonce=true" || arg == "--crashatonce")
        || hook.trim().eq_ignore_ascii_case("force")
}

/// The deliberate crash (support/QA parity with CE's `ForceCrashClient`).
pub fn force_crash() -> ! {
    eprintln!("lustlessd: Forced crash (test hook, CE `ForceCrashClient` parity)");
    std::process::abort()
}

/// One telemetry row per crash — CE's `updateProcessCrashes("client", +1)`.
pub fn telemetry_row(crash_type: CrashType, count: i64, device_name: &str) -> TelemetryRow {
    TelemetryRow {
        client_type: "daemon".to_string(),
        device_name: device_name.to_string(),
        name: "client_crashes".to_string(),
        value: format!("{}:{}", crash_type.as_str(), count),
        utc_timestamp: stamp_from_unix(unix_now()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lustless_core::db::Outbox;

    fn temp_ledger() -> (tempfile::TempDir, CrashLedger) {
        let dir = tempfile::tempdir().unwrap();
        let ledger = CrashLedger::new(dir.path());
        (dir, ledger)
    }

    fn temp_outbox(dir: &Path) -> Outbox {
        Outbox::open(&dir.join("outbox.db")).unwrap()
    }

    #[test]
    fn a_clean_shutdown_is_not_a_crash_and_a_missing_marker_is() {
        let (dir, ledger) = temp_ledger();

        // First ever start: nothing to report (the state dir did not exist).
        assert_eq!(ledger.begin(), None);

        // A start that never reached `mark_clean` (crash/kill) is reported.
        assert_eq!(ledger.begin(), Some(CrashType::Generic));

        // Clean shutdown then start: no crash.
        ledger.mark_clean();
        assert_eq!(ledger.begin(), None);
        let _ = dir;
    }

    #[test]
    fn the_reason_file_selects_the_crash_type() {
        let (_dir, ledger) = temp_ledger();
        assert_eq!(ledger.begin(), None); // first run
        assert_eq!(ledger.begin(), Some(CrashType::Generic)); // died

        fs::write(ledger.reason_file(), b"PANIC").unwrap();
        assert_eq!(ledger.begin(), Some(CrashType::Panic));

        fs::write(ledger.reason_file(), b"SIGNAL").unwrap();
        assert_eq!(ledger.begin(), Some(CrashType::Signal));

        // A reason without a crash (clean marker present) is discarded.
        ledger.mark_clean();
        assert_eq!(ledger.begin(), None);
    }

    #[test]
    fn counters_accumulate_inside_ces_window_and_reset_outside_it() {
        let (dir, ledger) = temp_ledger();
        let mut outbox = temp_outbox(dir.path());
        let now = 1_700_000_000;

        assert_eq!(ledger.crashes_since(&mut outbox), None);
        assert_eq!(ledger.bump(&mut outbox, now), (1, stamp_from_unix(now)));
        assert_eq!(ledger.bump(&mut outbox, now + 60), (2, stamp_from_unix(now + 60)));
        assert_eq!(ledger.crashes_since(&mut outbox).unwrap().0, 2);

        // CE resets `ClientCrashesSince` once the window has passed (measured
        // from the *last* crash stamp, which the second bump moved).
        let later = now + 60 + CRASH_WINDOW_SECS + 1;
        assert_eq!(ledger.bump(&mut outbox, later).0, 1);

        // Reporting clears it (CE's client-side clear).
        ledger.clear(&mut outbox);
        assert_eq!(ledger.crashes_since(&mut outbox).unwrap().0, 0);
    }

    #[test]
    fn attachment_caps_are_ces_and_the_summary_replaces_the_database_zip() {
        assert_eq!(ATTACH_FILE_CAP, 5 * 1024 * 1024);
        assert_eq!(ATTACH_TOTAL_CAP, 19 * 1024 * 1024);

        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("lustlessd.log"), b"line one\nline two\n").unwrap();
        // Over the per-file cap: must be skipped entirely (CE's `< 5 MB` rule).
        fs::write(
            logs.join("huge.log"),
            vec![b'x'; (ATTACH_FILE_CAP + 1) as usize],
        )
        .unwrap();

        let ledger = CrashLedger::new(dir.path());
        let bundle = ledger
            .collect_attachments(
                &[("debugLogs".to_string(), logs.clone())],
                "{\"crashes\":1}",
            )
            .unwrap();

        let logs_tar = fs::read_to_string(bundle.join("debugLogs.tar")).unwrap();
        assert!(logs_tar.contains("line one"));
        assert!(!logs_tar.contains("xxxx"), "5 MB file must not be attached");
        assert!(bundle.join("state-summary.json").exists());
        assert!(
            !bundle.join("debugDB.zip").exists(),
            "LustLess never attaches the activity databases"
        );
    }

    #[test]
    fn forced_crash_hooks_match_ces_switch_and_setting() {
        let args = vec!["--config".to_string(), "/tmp/x.toml".to_string()];
        assert!(!forced_crash_requested(&args, ""));
        assert!(!forced_crash_requested(&args, "off"));

        let on = vec!["--crashatonce=true".to_string()];
        assert!(forced_crash_requested(&on, ""));
        assert!(forced_crash_requested(&args, "force"));
        assert!(forced_crash_requested(&args, " FORCE "));
    }

    #[test]
    fn telemetry_row_carries_the_crash_type_and_count() {
        let row = telemetry_row(CrashType::Signal, 3, "workstation");
        assert_eq!(row.name, "client_crashes");
        assert_eq!(row.value, "SIGNAL:3");
        assert_eq!(row.client_type, "daemon");
        assert_eq!(row.device_name, "workstation");
        assert!(row.utc_timestamp.ends_with('Z'));
    }

    #[test]
    fn stamps_round_trip_through_ces_format() {
        let stamp = stamp_from_unix(1_700_000_000);
        assert_eq!(stamp, "2023-11-14T22:13:20Z");
        assert_eq!(unix_from_stamp(&stamp), Some(1_700_000_000));
        assert_eq!(unix_from_stamp("not a stamp"), None);
    }
}
