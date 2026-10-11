//! `lustless-classifier` — the supervised screenstate scoring process
//! (CONTRACTS §3, §6.3, §7, §14).
//!
//! Lifecycle, mirroring CE's launch/terminate shape from
//! `re/findings/02-artifacts/classifier-data.md` ("Launch contract"):
//!
//! 1. parse the pinned CLI (`--model=<dir> --data=<dir> --cache=<dir>
//!    --version=<ver> [--verbose] [--threshold=<0..1>]`, §7),
//! 2. install SIGTERM/SIGINT handlers (supervision-friendly `bye`, §7),
//! 3. open the `<pid>.log` file sink (§14) and log the CE-style command line
//!    + `Classifier v<ver> is starting`,
//! 4. validate the model bundle fail-closed (every artifact hash checked,
//!    `bundles::load`) and log the loaded artifact ids (§7 — CE never does),
//! 5. emit `hello` on the stdout JSON Lines channel,
//! 6. consume spool transactions until signalled (`consumer::Consumer`),
//! 7. emit `bye {reason}` and exit — `0` on SIGTERM/SIGINT, non-zero on any
//!    fail-closed startup or runtime failure.

mod bundles;
mod consumer;
mod logging;
mod scoring;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use serde::{Deserialize, Serialize};

use logging::Logger;
use scoring::ImageScorer;

/// Primary `<pid>.log` directory (CONTRACTS §4). Falls back to the per-user
/// `<cache>/logs` via [`Logger::open_or_fallback`] when not writable (tests,
/// non-root runs).
const DEFAULT_LOG_DIR: &str = "/var/log/lustless/classifier";

// ---------------------------------------------------------------------------
// stdout JSON Lines protocol (CONTRACTS §7)
// ---------------------------------------------------------------------------

/// Current wall-clock stamp for protocol `ts` fields (opaque to the daemon).
pub(crate) fn now_ts() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// One scored window inside a `result` message (§7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoredWindow {
    /// Application name from `apps[].name`.
    pub app: String,
    /// Window title from `apps[].window_title` (may be empty on Wayland).
    pub title: String,
    /// `[x, y, width, height]` of `apps[].appRect` in virtual-screen coords.
    pub rect: [i32; 4],
    /// Model score in `0..=1` (P(nsfw), see MODEL.md).
    pub score: f64,
    /// `score >= threshold`; flagged windows become `circumventions` rows (§7).
    pub flagged: bool,
}

/// The `summary` object of a `result` message (§7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultSummary {
    /// Number of flagged windows.
    pub flagged: u64,
    /// Highest score of the batch (`0.0` when nothing was scored).
    pub top_score: f64,
    /// Number of scored windows.
    pub scored_windows: u64,
}

/// One message on the classifier → daemon stdout pipe. Every message carries
/// `{"type": …, "ts": …, …}`; field sets are pinned by §7:
/// `hello {version, model_ids}`, `result {batch_ts, windows, summary,
/// analyzed_count}`, `log {level, message}`, `bye {reason}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// The child is ready: bundle validated, scorer session built.
    Hello {
        /// Message timestamp (opaque to the daemon).
        ts: String,
        /// `--version` value echoed back.
        version: String,
        /// Content-addressed ids of the loaded bundle artifacts (§7).
        model_ids: Vec<String>,
    },
    /// One consumed §6.3 spool transaction.
    Result {
        /// Message timestamp (opaque to the daemon).
        ts: String,
        /// Manifest `datetime_created` of the consumed transaction; the
        /// folder name is used when the manifest is unreadable (the daemon's
        /// `txn_key` normalizes either form).
        batch_ts: String,
        /// Scored windows (doNotScore entries are never included, §7).
        windows: Vec<ScoredWindow>,
        /// Batch summary.
        summary: ResultSummary,
        /// Real analysis count for the §7 UI counter (= scored windows).
        analyzed_count: u64,
    },
    /// Child log line (§7; the taxonomy tag lives in the `<pid>.log` record).
    Log {
        /// Message timestamp (opaque to the daemon).
        ts: String,
        /// Severity, lowercase (`debug`/`info`/`warn`/`error`).
        level: String,
        /// Log text.
        message: String,
    },
    /// Graceful child exit.
    Bye {
        /// Message timestamp (opaque to the daemon).
        ts: String,
        /// Exit reason (`sigterm`, `sigint`, or a fail-closed error summary).
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// CLI contract (CONTRACTS §7, evidence `classifier-data.md` "Launch contract")
// ---------------------------------------------------------------------------

/// Parsed command line.
#[derive(Debug, Clone, PartialEq)]
pub struct Args {
    /// `--model=<dir>` — the model bundle directory (§4
    /// `/usr/share/lustless/models`).
    pub model: PathBuf,
    /// `--data=<dir>` — the per-user message root: `<data>/pdl` is the §6.3
    /// spool the daemon writes.
    pub data: PathBuf,
    /// `--cache=<dir>` — per-user control-file tree (§7, `classifier-data.md`).
    pub cache: PathBuf,
    /// `--version=<ver>` — classifier/model version string.
    pub version: String,
    /// `--verbose` — emit debug-level records.
    pub verbose: bool,
    /// `--threshold=<0..1>` — override the calibration-artifact threshold.
    pub threshold: Option<f64>,
}

/// CLI parse failures (exit code 2; no logger exists yet, so they go to stderr).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ArgError {
    #[error("missing required argument --{0}")]
    MissingRequired(&'static str),
    #[error("unknown argument {0}")]
    Unknown(String),
    #[error("argument {0} must use --name=value form")]
    MissingValue(String),
    #[error("argument --{0} needs a non-empty value")]
    EmptyValue(&'static str),
    #[error("invalid --threshold value {0:?} (want a number in 0.0..=1.0)")]
    BadThreshold(String),
    #[error("unexpected positional argument {0}")]
    UnexpectedPositional(String),
}

impl Args {
    /// The pinned usage line (§7).
    pub fn usage() -> &'static str {
        "usage: lustless-classifier --model=<dir> --data=<dir> --cache=<dir> \
         --version=<ver> [--verbose] [--threshold=<0..1>]"
    }

    /// Parse `--name=value` flags (the CE launch contract is `=`-only).
    pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Result<Self, ArgError> {
        let mut model: Option<PathBuf> = None;
        let mut data: Option<PathBuf> = None;
        let mut cache: Option<PathBuf> = None;
        let mut version: Option<String> = None;
        let mut verbose = false;
        let mut threshold: Option<f64> = None;

        for arg in argv {
            if arg == "--verbose" {
                verbose = true;
                continue;
            }
            let Some(flag) = arg.strip_prefix("--") else {
                return Err(ArgError::UnexpectedPositional(arg));
            };
            let Some((key, value)) = flag.split_once('=') else {
                return Err(ArgError::MissingValue(arg));
            };
            if value.is_empty() {
                return Err(ArgError::EmptyValue(match key {
                    "model" => "model",
                    "data" => "data",
                    "cache" => "cache",
                    "version" => "version",
                    "threshold" => "threshold",
                    _ => return Err(ArgError::Unknown(format!("--{flag}"))),
                }));
            }
            match key {
                "model" => model = Some(PathBuf::from(value)),
                "data" => data = Some(PathBuf::from(value)),
                "cache" => cache = Some(PathBuf::from(value)),
                "version" => version = Some(value.to_string()),
                "threshold" => {
                    let parsed: f64 = value
                        .parse()
                        .map_err(|_| ArgError::BadThreshold(value.to_string()))?;
                    if !parsed.is_finite() || !(0.0..=1.0).contains(&parsed) {
                        return Err(ArgError::BadThreshold(value.to_string()));
                    }
                    threshold = Some(parsed);
                }
                _ => return Err(ArgError::Unknown(format!("--{flag}"))),
            }
        }

        Ok(Self {
            model: model.ok_or(ArgError::MissingRequired("model=<dir>"))?,
            data: data.ok_or(ArgError::MissingRequired("data=<dir>"))?,
            cache: cache.ok_or(ArgError::MissingRequired("cache=<dir>"))?,
            version: version.ok_or(ArgError::MissingRequired("version=<ver>"))?,
            verbose,
            threshold,
        })
    }

    /// CE's startup command-line dump, reconstructed in CE argument order.
    pub fn command_line(&self) -> String {
        let mut line = format!(
            "lustless-classifier --version={} --model={} --data={} --cache={}",
            self.version,
            self.model.display(),
            self.data.display(),
            self.cache.display()
        );
        if self.verbose {
            line.push_str(" --verbose");
        }
        if let Some(threshold) = self.threshold {
            line.push_str(&format!(" --threshold={threshold}"));
        }
        line
    }
}

// ---------------------------------------------------------------------------
// Supervision lifecycle
// ---------------------------------------------------------------------------

/// Set by the SIGTERM/SIGINT handler; polled by the consumer loop.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// The signal number that requested shutdown (0 = none), for the `bye` reason.
static SIGNALLED: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    SIGNALLED.store(sig, Ordering::SeqCst);
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
    }
}

/// The `bye {reason}` string for a signal-initiated shutdown.
fn shutdown_reason() -> String {
    match SIGNALLED.load(Ordering::SeqCst) {
        libc::SIGTERM => "sigterm".to_string(),
        libc::SIGINT => "sigint".to_string(),
        0 => "shutdown".to_string(),
        other => format!("signal {other}"),
    }
}

fn main() {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("lustless-classifier: {err}");
            eprintln!("{}", Args::usage());
            std::process::exit(2);
        }
    };
    install_signal_handlers();
    let logger = Logger::open_or_fallback(
        Path::new(DEFAULT_LOG_DIR),
        &args.cache.join("logs"),
        args.verbose,
    );
    std::process::exit(run(&args, &logger));
}

/// Startup, supervise, shutdown. Returns the process exit code: `0` only for
/// a signal-initiated graceful stop; every fail-closed path returns `1`
/// *after* emitting `bye {reason}` so the daemon logs why.
fn run(args: &Args, logger: &Logger) -> i32 {
    logger.info("classifier", &format!("Command line: {}", args.command_line()));
    logger.info(
        "classifier",
        &format!("Classifier v{} is starting", args.version),
    );

    // Per-user `--data`/`--cache` trees (§7, evidence `classifier-data.md`).
    if let Err(err) = bundles::ensure_user_tree(&args.data, &args.cache) {
        return fail_closed(logger, format!("user state tree setup failed: {err}"));
    }
    match bundles::read_last_result(&args.cache) {
        Ok(Some(prev)) => logger.info(
            "classifier",
            &format!(
                "previous run consumed batch {} ({} analyzed, {} flagged) at {}",
                prev.batch_ts, prev.analyzed_count, prev.flagged, prev.finished_at
            ),
        ),
        Ok(None) => {}
        Err(err) => logger.warn("classifier", &format!("last-result control file unreadable: {err}")),
    }

    // Fail closed on any missing/corrupt artifact (§7 bundle contract).
    let bundle = match bundles::load(&args.model) {
        Ok(bundle) => bundle,
        Err(err) => return fail_closed(logger, format!("model bundle validation failed: {err}")),
    };
    logger.info(
        "bundles",
        &format!(
            "model bundle v{}: {} ({}, {})",
            bundle.bundle_version,
            bundle.model.name,
            bundle.model.license,
            bundle.model.source
        ),
    );
    for artifact in bundle.artifacts() {
        logger.info(
            "bundles",
            &format!(
                "loaded artifact {} ({} v{})",
                artifact.id,
                artifact.role.as_str(),
                artifact.version
            ),
        );
    }

    let mut scorer = match scoring::Scorer::open(&bundle, args.threshold) {
        Ok(scorer) => scorer,
        Err(err) => return fail_closed(logger, format!("scorer init failed: {err}")),
    };
    logger.info(
        "scoring",
        &format!(
            "threshold {:.3} ({}), input {}x{}",
            scorer.threshold(),
            scorer.threshold_source(),
            scoring::INPUT_WIDTH,
            scoring::INPUT_HEIGHT
        ),
    );

    logger.stdout_json(&Message::Hello {
        ts: now_ts(),
        version: args.version.clone(),
        model_ids: bundle.ids(),
    });

    let mut consumer =
        match consumer::Consumer::new(&args.data, &args.cache, &mut scorer, logger, &SHUTDOWN) {
            Ok(consumer) => consumer,
            Err(err) => return fail_closed(logger, format!("spool consumer init failed: {err}")),
        };
    if let Err(err) = consumer.run() {
        return fail_closed(logger, format!("spool consumer stopped: {err}"));
    }

    let reason = shutdown_reason();
    logger.info(
        "classifier",
        &format!("Classifier v{} is terminating ({reason})", args.version),
    );
    logger.stdout_json(&Message::Bye {
        ts: now_ts(),
        reason,
    });
    0
}

/// Log + `bye` + exit code 1 for a fail-closed path.
fn fail_closed(logger: &Logger, message: String) -> i32 {
    logger.error("classifier", &message);
    logger.stdout_json(&Message::Bye {
        ts: now_ts(),
        reason: message,
    });
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &[&str]) -> Result<Args, ArgError> {
        let mut argv = vec![
            "--model=/models".to_string(),
            "--data=/spool/u".to_string(),
            "--cache=/var/lib/1/cache".to_string(),
            "--version=0.1.0".to_string(),
        ];
        argv.extend(extra.iter().map(|s| s.to_string()));
        Args::parse(argv)
    }

    #[test]
    fn cli_arg_table() {
        // The four pinned required arguments, `=`-form only (§7).
        let args = parse(&[]).expect("base command line");
        assert_eq!(args.model, PathBuf::from("/models"));
        assert_eq!(args.data, PathBuf::from("/spool/u"));
        assert_eq!(args.cache, PathBuf::from("/var/lib/1/cache"));
        assert_eq!(args.version, "0.1.0");
        assert!(!args.verbose);
        assert_eq!(args.threshold, None);

        // Optional flags.
        assert!(parse(&["--verbose"]).unwrap().verbose);
        assert_eq!(parse(&["--threshold=0.9"]).unwrap().threshold, Some(0.9));
        assert_eq!(parse(&["--threshold=0"]).unwrap().threshold, Some(0.0));
        assert_eq!(
            parse(&["--verbose", "--threshold=0.42"]).unwrap().threshold,
            Some(0.42)
        );

        // Each required argument is mandatory.
        for (missing, want) in [
            ("--model", "model=<dir>"),
            ("--data", "data=<dir>"),
            ("--cache", "cache=<dir>"),
            ("--version", "version=<ver>"),
        ] {
            let argv: Vec<String> = [
                "--model=/models",
                "--data=/spool/u",
                "--cache=/var/lib/1/cache",
                "--version=0.1.0",
            ]
            .iter()
            .filter(|arg| !arg.starts_with(missing))
            .map(|s| s.to_string())
            .collect();
            let err = Args::parse(argv).expect_err("one required flag dropped");
            assert_eq!(err, ArgError::MissingRequired(want), "without {missing}");
        }

        // Threshold validation.
        assert!(matches!(
            parse(&["--threshold=1.5"]),
            Err(ArgError::BadThreshold(_))
        ));
        assert!(matches!(
            parse(&["--threshold=-0.1"]),
            Err(ArgError::BadThreshold(_))
        ));
        assert!(matches!(
            parse(&["--threshold=abc"]),
            Err(ArgError::BadThreshold(_))
        ));

        // Shape errors: unknown flags, space form, positional, empty value.
        assert!(matches!(parse(&["--bogus=1"]), Err(ArgError::Unknown(_))));
        assert!(matches!(
            parse(&["--models=/x"]),
            Err(ArgError::Unknown(_))
        ));
        assert!(matches!(
            Args::parse(["--model", "/m"]),
            Err(ArgError::MissingValue(_))
        ));
        assert!(matches!(
            Args::parse(["/positional"]),
            Err(ArgError::UnexpectedPositional(_))
        ));
        assert!(matches!(
            parse(&["--model="]),
            Err(ArgError::EmptyValue(_))
        ));
        assert!(matches!(
            parse(&["--verbose=1"]),
            Err(ArgError::Unknown(_))
        ));
    }

    #[test]
    fn command_line_dump_matches_ce_argument_order() {
        let args = parse(&["--verbose", "--threshold=0.75"]).unwrap();
        assert_eq!(
            args.command_line(),
            "lustless-classifier --version=0.1.0 --model=/models --data=/spool/u \
             --cache=/var/lib/1/cache --verbose --threshold=0.75"
        );
    }

    // -- protocol byte pins + round-trips (§7) --------------------------------

    fn hello() -> Message {
        Message::Hello {
            ts: "2026-10-11T12:00:00.000Z".to_string(),
            version: "0.1.0".to_string(),
            model_ids: vec!["dce8f5af8509fee39c-scorer".to_string()],
        }
    }

    fn result() -> Message {
        Message::Result {
            ts: "2026-10-11T12:00:01.123Z".to_string(),
            batch_ts: "2026-10-11T11:59:00.000000Z".to_string(),
            windows: vec![ScoredWindow {
                app: "Firefox".to_string(),
                title: "Video".to_string(),
                rect: [0, 0, 800, 600],
                score: 0.97,
                flagged: true,
            }],
            summary: ResultSummary {
                flagged: 1,
                top_score: 0.97,
                scored_windows: 3,
            },
            analyzed_count: 3,
        }
    }

    fn log() -> Message {
        Message::Log {
            ts: "2026-10-11T12:00:02.004Z".to_string(),
            level: "info".to_string(),
            message: "loaded artifact".to_string(),
        }
    }

    fn bye() -> Message {
        Message::Bye {
            ts: "2026-10-11T12:00:03.000Z".to_string(),
            reason: "sigterm".to_string(),
        }
    }

    #[test]
    fn protocol_bytes_match_the_contract_pins() {
        assert_eq!(
            serde_json::to_string(&hello()).unwrap(),
            r#"{"type":"hello","ts":"2026-10-11T12:00:00.000Z","version":"0.1.0","model_ids":["dce8f5af8509fee39c-scorer"]}"#
        );
        assert_eq!(
            serde_json::to_string(&result()).unwrap(),
            r#"{"type":"result","ts":"2026-10-11T12:00:01.123Z","batch_ts":"2026-10-11T11:59:00.000000Z","windows":[{"app":"Firefox","title":"Video","rect":[0,0,800,600],"score":0.97,"flagged":true}],"summary":{"flagged":1,"top_score":0.97,"scored_windows":3},"analyzed_count":3}"#
        );
        assert_eq!(
            serde_json::to_string(&log()).unwrap(),
            r#"{"type":"log","ts":"2026-10-11T12:00:02.004Z","level":"info","message":"loaded artifact"}"#
        );
        assert_eq!(
            serde_json::to_string(&bye()).unwrap(),
            r#"{"type":"bye","ts":"2026-10-11T12:00:03.000Z","reason":"sigterm"}"#
        );
    }

    #[test]
    fn protocol_messages_round_trip() {
        for message in [hello(), result(), log(), bye()] {
            let json = serde_json::to_string(&message).unwrap();
            let back: Message = serde_json::from_str(&json).unwrap();
            assert_eq!(back, message, "round trip of {json}");
        }
    }

    #[test]
    fn shutdown_reason_maps_signals() {
        SIGNALLED.store(libc::SIGTERM, Ordering::SeqCst);
        assert_eq!(shutdown_reason(), "sigterm");
        SIGNALLED.store(libc::SIGINT, Ordering::SeqCst);
        assert_eq!(shutdown_reason(), "sigint");
        SIGNALLED.store(0, Ordering::SeqCst);
        assert_eq!(shutdown_reason(), "shutdown");
    }
}
