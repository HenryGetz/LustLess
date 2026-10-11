//! Classifier logging (CONTRACTS §14; CE shape from
//! `re/findings/02-artifacts/classifier-data.md` "Classifier log format and taxonomy").
//!
//! Two sinks, one call:
//! * `<log_dir>/<pid>.log` — plain text lines `YYYY-MM-DD HH:MM:SS.mmm <SEV> <tag>: <message>`
//!   (CE's time/severity/tag/message record shape; CE used 3-letter codes `MAR/WAR/ERR`, we
//!   use the full severity word per the shipped log contract). The taxonomy tag
//!   (`classifier`/`capture`/`bundles`, CONTRACTS §14) lives here.
//! * stdout — JSON Lines `log` messages
//!   (`{"type":"log","ts":…,"level":…,"message":…}`) consumed by `lustlessd` over the
//!   classifier pipe — the §7 `log {level, message}` pin exactly; the stdout channel
//!   carries no `tag` field.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;

use crate::Message;

/// Log severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    /// The severity token written into the file log (CE taxonomy: full word).
    fn file_token(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }

    /// The lowercase severity on the stdout `log` message (§7).
    fn protocol_token(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

/// Per-process logger writing the `<pid>.log` file plus stdout JSONL.
pub struct Logger {
    file: Mutex<File>,
    log_path: PathBuf,
    verbose: bool,
    stdout: Mutex<io::Stdout>,
}

impl Logger {
    /// Open `<log_dir>/<pid>.log` (0600, per CONTRACTS §4). On failure the caller should
    /// fall back to [`Logger::open_or_fallback`].
    pub fn open(log_dir: &Path, verbose: bool) -> io::Result<Self> {
        fs::create_dir_all(log_dir)?;
        let log_path = log_dir.join(format!("{}.log", std::process::id()));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)?;
        Ok(Self {
            file: Mutex::new(file),
            log_path,
            verbose,
            stdout: Mutex::new(io::stdout()),
        })
    }

    /// Open the primary log dir, falling back to `<fallback_dir>` (the per-user cache dir)
    /// when `/var/log/lustless/classifier` is not writable (e.g. non-root test runs). Both
    /// attempts are reported on stdout as `log` messages.
    pub fn open_or_fallback(primary: &Path, fallback: &Path, verbose: bool) -> Self {
        match Self::open(primary, verbose) {
            Ok(logger) => logger,
            Err(primary_err) => {
                let (logger, fallback_note) = match Self::open(fallback, verbose) {
                    Ok(logger) => (logger, String::new()),
                    Err(fallback_err) => (Self::null(verbose), format!("; fallback {fallback} also failed: {fallback_err}")),
                };
                logger.log(
                    Level::Warn,
                    "classifier",
                    &format!(
                        "log dir {} not writable ({primary_err}){fallback_note}, using {}",
                        primary.display(),
                        logger.log_path().display()
                    ),
                );
                logger
            }
        }
    }

    /// A logger with no file sink (both log dirs unusable): stdout only.
    fn null(verbose: bool) -> Self {
        Self {
            file: Mutex::new(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/dev/null")
                    .expect("/dev/null is always openable"),
            ),
            log_path: PathBuf::from("/dev/null"),
            verbose,
            stdout: Mutex::new(io::stdout()),
        }
    }

    /// The log file path in use.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Whether debug-level records are emitted.
    pub fn verbose(&self) -> bool {
        self.verbose
    }

    /// Emit one record to both sinks.
    pub fn log(&self, level: Level, tag: &str, message: &str) {
        if level == Level::Debug && !self.verbose {
            return;
        }
        let ts = chrono::Local::now();
        let stamp = ts.format("%Y-%m-%d %H:%M:%S%.3f");
        let token = level.file_token();
        let file_line = format!("{stamp} {token} {tag}: {message}\n");
        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(file_line.as_bytes());
            let _ = file.flush();
        }
        // §7 `log {level, message}` pin: exact field set, raw message text
        // (the taxonomy tag belongs to the `<pid>.log` record above).
        let stdout_msg = Message::Log {
            ts: ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level: level.protocol_token().to_string(),
            message: message.to_string(),
        };
        if let Ok(mut stdout) = self.stdout.lock() {
            if let Ok(mut line) = serde_json::to_string(&stdout_msg) {
                line.push('\n');
                let _ = stdout.write_all(line.as_bytes());
                let _ = stdout.flush();
            }
        }
    }

    pub fn debug(&self, tag: &str, message: &str) {
        self.log(Level::Debug, tag, message);
    }

    pub fn info(&self, tag: &str, message: &str) {
        self.log(Level::Info, tag, message);
    }

    pub fn warn(&self, tag: &str, message: &str) {
        self.log(Level::Warn, tag, message);
    }

    pub fn error(&self, tag: &str, message: &str) {
        self.log(Level::Error, tag, message);
    }

    /// Write one already-serialized JSON Lines message to stdout (for `hello`/`result`/
    /// `bye`, which the daemon reads off the same pipe).
    pub fn stdout_json(&self, value: &impl Serialize) {
        if let Ok(mut stdout) = self.stdout.lock() {
            if let Ok(mut line) = serde_json::to_string(value) {
                line.push('\n');
                let _ = stdout.write_all(line.as_bytes());
                let _ = stdout.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_log_uses_ce_record_shape() {
        let dir = tempfile::tempdir().unwrap();
        let logger = Logger::open(dir.path(), true).unwrap();
        logger.info("pdl-edi", "hello world");
        let text = std::fs::read_to_string(logger.log_path()).unwrap();
        let line = text.lines().last().unwrap();
        // `2026-10-11 12:00:00.123 INFO pdl-edi: hello world`
        let mut parts = line.splitn(5, ' ');
        assert!(parts.next().unwrap().contains('-'), "date part: {line}");
        assert!(parts.next().unwrap().contains(':'), "time part: {line}");
        assert_eq!(parts.next().unwrap(), "INFO");
        assert_eq!(parts.next().unwrap(), "pdl-edi:");
        assert_eq!(parts.next().unwrap(), "hello world");
    }

    #[test]
    fn debug_records_respect_verbosity() {
        let dir = tempfile::tempdir().unwrap();
        let quiet = Logger::open(dir.path(), false).unwrap();
        quiet.debug("classifier", "invisible");
        let text = std::fs::read_to_string(quiet.log_path()).unwrap();
        assert!(!text.contains("invisible"));

        let verbose = Logger::open(dir.path(), true).unwrap();
        verbose.debug("classifier", "visible");
        let text = std::fs::read_to_string(verbose.log_path()).unwrap();
        assert!(text.contains("visible"));
    }

    #[test]
    fn fallback_open_reports_both_attempts() {
        let dir = tempfile::tempdir().unwrap();
        // Primary does not exist and cannot be created under a file path.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let fallback_dir = dir.path().join("fallback-logs");
        let logger = Logger::open_or_fallback(&blocker, &fallback_dir, false);
        assert!(logger.log_path().starts_with(&fallback_dir));
        // The fallback was reported on stdout; the file sink itself works.
        logger.error("bundleManager", "test");
        let text = std::fs::read_to_string(logger.log_path()).unwrap();
        assert!(text.contains("bundleManager: test"));
    }
}
