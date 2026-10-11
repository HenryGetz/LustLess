//! Spool consumer — inotify-wakes on §6.3 `ready` markers, scores the
//! transaction, emits §7 `result` messages, then consumes/cleans the folder.
//!
//! Integration contract with `lustlessd`'s capture loop (pinned with
//! `DaemonRuntime`):
//! * startup cleanup removes **incomplete** (no `ready`) folders older than
//!   [`INCOMPLETE_MAX_AGE`] — a crashed producer's leftovers, tamper-safe by
//!   construction; **ready** folders are never age-discarded (deleting one
//!   without a preceding `result` is indistinguishable from tamper on the
//!   daemon's watcher — staleness is a scoring policy, not a discard trigger);
//! * per folder: score → emit `result` → `SpoolWatcher::mark_consumed` →
//!   delete, so the daemon resolves the batch before the DELETE event lands;
//! * `batch_ts` echoes the manifest `datetime_created`; unreadable manifests
//!   fall back to the transaction folder name (the daemon's `txn_key`
//!   normalizes both forms).
//!
//! Window scoring (§7): `apps[]` entries with `doNotScore: true` are skipped
//! (the daemon records their `circumventions` row from the capture side);
//! every other window is cropped from the monitor image covering its
//! `appRect`, with a full-frame fallback when no image covers the rect.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use image::imageops;
use image::RgbImage;
use lustless_capture::manifest::{Rect, ScreenstateManifest};
use lustless_capture::spool::{self, SpoolWatcher, SpoolError, READY_MARKER};

use crate::bundles::{self, LastResult};
use crate::logging::Logger;
use crate::scoring::{ImageScorer, ScoreError};
use crate::{now_ts, Message, ResultSummary, ScoredWindow};

/// inotify poll cadence — bounds the SIGTERM reaction time while idle.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Startup cleanup cutoff for **incomplete** transactions: a capture interval
/// is ≤ 60 s worst case (§7 cadence), so anything without a `ready` marker
/// after 5 minutes is a crashed producer's orphan (§6.3 startup cleanup /
/// CE `PdlEdi::cleanFolders`).
pub const INCOMPLETE_MAX_AGE: Duration = Duration::from_secs(300);
/// Ready transactions are consumed regardless of age — never age-removed
/// (see module docs; passed to `cleanup_orphaned` as "no stale cutoff").
const READY_MAX_AGE: Duration = Duration::MAX;

/// Consumer failures (all fatal: the process exits non-zero, §7).
#[derive(Debug, thiserror::Error)]
pub enum ConsumerError {
    #[error("--data {0} must be the absolute <spool>/<uid> message root")]
    BadDataDir(PathBuf),
    #[error("spool watcher: {0}")]
    Spool(#[from] SpoolError),
    #[error("scoring failed: {0}")]
    Score(#[from] ScoreError),
}

// ---------------------------------------------------------------------------
// One transaction → one result message
// ---------------------------------------------------------------------------

/// Score a ready transaction folder into a §7 `result` message.
///
/// Folder-shape problems (missing/unreadable manifest, unreadable images)
/// degrade to a logged, empty or partial batch — they are consumed either
/// way so the daemon can resolve them. Only ONNX inference errors propagate
/// (fatal).
pub fn score_transaction(
    folder: &Path,
    scorer: &mut dyn ImageScorer,
    logger: &Logger,
) -> Result<Message, ScoreError> {
    let folder_name = folder
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());

    let manifest = match read_manifest(folder) {
        Ok(manifest) => manifest,
        Err(err) => {
            logger.error(
                "classifier",
                &format!(
                    "transaction {folder_name}: manifest unreadable ({err}) — consuming as empty batch"
                ),
            );
            return Ok(Message::Result {
                ts: now_ts(),
                batch_ts: folder_name,
                windows: Vec::new(),
                summary: ResultSummary {
                    flagged: 0,
                    top_score: 0.0,
                    scored_windows: 0,
                },
                analyzed_count: 0,
            });
        }
    };

    // Load every monitor image once; a missing/corrupt image only costs the
    // windows it would have covered (full-frame fallback still applies).
    let mut images: Vec<(Rect, RgbImage)> = Vec::new();
    for entry in &manifest.images {
        let path = folder.join(&entry.filename);
        match image::open(&path) {
            Ok(image) => images.push((entry.screen_rect, image.to_rgb8())),
            Err(err) => logger.warn(
                "capture",
                &format!(
                    "transaction {folder_name}: image {} unreadable: {err}",
                    entry.filename
                ),
            ),
        }
    }

    let mut windows = Vec::new();
    for app in &manifest.apps {
        if app.is_do_not_score() {
            logger.debug(
                "classifier",
                &format!("skipping doNotScore window {:?}", app.name),
            );
            continue;
        }
        let Some(crop) = select_crop(app.app_rect, &images) else {
            logger.warn(
                "classifier",
                &format!(
                    "no loaded image covers window {:?} at {:?} — skipped",
                    app.name, app.app_rect
                ),
            );
            continue;
        };
        let score = scorer.score_image(&crop)?;
        windows.push(ScoredWindow {
            app: app.name.clone(),
            title: app.window_title.clone(),
            rect: app.app_rect,
            score,
            flagged: score >= scorer.threshold(),
        });
    }

    let flagged = windows.iter().filter(|window| window.flagged).count() as u64;
    let top_score = windows
        .iter()
        .map(|window| window.score)
        .fold(0.0f64, f64::max);
    let scored_windows = windows.len() as u64;
    Ok(Message::Result {
        ts: now_ts(),
        batch_ts: manifest.datetime_created.clone(),
        windows,
        summary: ResultSummary {
            flagged,
            top_score,
            scored_windows,
        },
        analyzed_count: scored_windows,
    })
}

/// Parse + validate `manifest.json` inside a transaction.
fn read_manifest(folder: &Path) -> Result<ScreenstateManifest, String> {
    let path = folder.join(spool::MANIFEST_FILE);
    let text = fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    let manifest =
        ScreenstateManifest::from_json(&text).map_err(|err| format!("manifest.json: {err}"))?;
    manifest.validate().map_err(|err| err.to_string())?;
    Ok(manifest)
}

/// Choose the pixels for one window: the crop of the monitor image with the
/// largest intersection with `app_rect`, or the full frame of the first
/// loaded image when nothing covers the rect (§7 full-frame fallback).
fn select_crop(app_rect: Rect, images: &[(Rect, RgbImage)]) -> Option<RgbImage> {
    let [ax, ay, aw, ah] = app_rect;
    let (app_x2, app_y2) = (ax.saturating_add(aw), ay.saturating_add(ah));

    let mut best: Option<(i64, usize, i32, i32, i32, i32)> = None;
    if aw > 0 && ah > 0 {
        for (index, (rect, _image)) in images.iter().enumerate() {
            let [rx, ry, rw, rh] = *rect;
            if rw <= 0 || rh <= 0 {
                continue;
            }
            let ix = ax.max(rx);
            let iy = ay.max(ry);
            let ix2 = app_x2.min(rx.saturating_add(rw));
            let iy2 = app_y2.min(ry.saturating_add(rh));
            let (cw, ch) = (ix2 - ix, iy2 - iy);
            if cw <= 0 || ch <= 0 {
                continue;
            }
            let area = i64::from(cw) * i64::from(ch);
            let better = match best {
                Some((best_area, ..)) => area > best_area,
                None => true,
            };
            if better {
                best = Some((area, index, ix - rx, iy - ry, cw, ch));
            }
        }
    }

    match best {
        Some((_, index, cx, cy, cw, ch)) => {
            let image = &images[index].1;
            Some(imageops::crop_imm(image, cx as u32, cy as u32, cw as u32, ch as u32).to_image())
        }
        None => images.first().map(|(_, image)| image.clone()),
    }
}

// ---------------------------------------------------------------------------
// The consumer loop
// ---------------------------------------------------------------------------

/// Owns the inotify watcher, the scorer handle and the per-user cache tree.
pub struct Consumer<'a> {
    cache_dir: PathBuf,
    watcher: SpoolWatcher,
    scorer: &'a mut dyn ImageScorer,
    logger: &'a Logger,
    shutdown: &'a AtomicBool,
}

impl<'a> Consumer<'a> {
    /// Run the §6.3 startup cleanup (incomplete only), then open the
    /// inotify watcher on `<data>/pdl`.
    pub fn new(
        data_dir: &Path,
        cache_dir: &Path,
        scorer: &'a mut dyn ImageScorer,
        logger: &'a Logger,
        shutdown: &'a AtomicBool,
    ) -> Result<Self, ConsumerError> {
        let (spool_dir, uid) = split_data_dir(data_dir)?;
        // Cleanup BEFORE watching: ready folders must never be removed (see
        // module docs), and incomplete ones are invisible to the daemon's
        // tamper branches.
        let report = spool::cleanup_orphaned(spool_dir, &uid, INCOMPLETE_MAX_AGE, READY_MAX_AGE)?;
        if !report.removed_incomplete.is_empty() || !report.removed_stale.is_empty() {
            logger.info(
                "classifier",
                &format!(
                    "startup cleanup removed {} incomplete and {} stale spool transactions",
                    report.removed_incomplete.len(),
                    report.removed_stale.len()
                ),
            );
        }
        let watcher = SpoolWatcher::open(spool_dir, &uid)?;
        Ok(Self {
            cache_dir: cache_dir.to_path_buf(),
            watcher,
            scorer,
            logger,
            shutdown,
        })
    }

    /// Consume ready transactions until `shutdown` is signalled. Returns
    /// `Ok` on SIGTERM/SIGINT; watcher/inference errors are fatal.
    pub fn run(&mut self) -> Result<(), ConsumerError> {
        let mut initial = true;
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }
            // First pass adopts folders that were already ready (classifier
            // restart); afterwards block on inotify with a bounded poll.
            let ready = if initial {
                initial = false;
                self.watcher.scan_ready()
            } else {
                self.watcher.wait_ready(POLL_INTERVAL)?
            };
            for folder in &ready {
                self.process_ready(folder)?;
            }
            self.log_tamper();
        }
    }

    /// Score + emit + consume one folder: `result` on stdout **before** the
    /// folder disappears (daemon contract above), then the control file,
    /// watcher retirement and deletion.
    fn process_ready(&mut self, folder: &Path) -> Result<(), ConsumerError> {
        if !folder.exists() {
            return Ok(());
        }
        if !folder.join(READY_MARKER).exists() {
            self.logger.warn(
                "capture",
                &format!(
                    "transaction {} lost its ready marker — skipped",
                    folder.display()
                ),
            );
            return Ok(());
        }

        let message = score_transaction(folder, self.scorer, self.logger)?;
        self.logger.stdout_json(&message);
        self.record_last_result(&message);

        self.watcher.mark_consumed(folder);
        if let Err(err) = fs::remove_dir_all(folder) {
            self.logger.warn(
                "classifier",
                &format!(
                    "consumed transaction {} could not be removed: {err}",
                    folder.display()
                ),
            );
        }
        Ok(())
    }

    /// Persist the `bmdat/last-result.json` control file (best effort — the
    /// batch itself is already reported on stdout).
    fn record_last_result(&self, message: &Message) {
        let Message::Result {
            batch_ts,
            summary,
            analyzed_count,
            ..
        } = message
        else {
            return;
        };
        let result = LastResult {
            batch_ts: batch_ts.clone(),
            analyzed_count: *analyzed_count,
            flagged: summary.flagged,
            top_score: summary.top_score,
            finished_at: now_ts(),
        };
        if let Err(err) = bundles::write_last_result(&self.cache_dir, &result) {
            self.logger.warn(
                "classifier",
                &format!("last-result control file not written: {err}"),
            );
        }
    }

    /// Surface watcher tamper events (§6.3 `Circumvention:` lines) in the
    /// `<pid>.log` + stdout `log` stream.
    fn log_tamper(&mut self) {
        for event in self.watcher.drain_tamper() {
            self.logger.warn("capture", event.log_line());
        }
    }
}

/// `--data` is the §7 message root `<spool>/<uid>`; the watched pdl root is
/// `<data>/pdl`, i.e. split the path back into (spool root, uid key).
fn split_data_dir(data_dir: &Path) -> Result<(&Path, String), ConsumerError> {
    let uid = data_dir
        .file_name()
        .ok_or_else(|| ConsumerError::BadDataDir(data_dir.to_path_buf()))?;
    let parent = data_dir
        .parent()
        .ok_or_else(|| ConsumerError::BadDataDir(data_dir.to_path_buf()))?;
    Ok((parent, uid.to_string_lossy().into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use image::{Rgb, RgbImage};
    use lustless_capture::manifest::{AppEntry, ImageEntry};
    use lustless_capture::spool::TransactionWriter;
    use std::collections::VecDeque;

    /// Deterministic scorer: returns queued scores and records the crops it
    /// was handed (no ONNX session in tests).
    struct FakeScorer {
        scores: VecDeque<f64>,
        seen_dims: Vec<(u32, u32)>,
        threshold: f64,
    }

    impl FakeScorer {
        fn new(scores: &[f64]) -> Self {
            Self {
                scores: scores.iter().copied().collect(),
                seen_dims: Vec::new(),
                threshold: 0.8,
            }
        }
    }

    impl ImageScorer for FakeScorer {
        fn score_image(&mut self, image: &RgbImage) -> Result<f64, ScoreError> {
            self.seen_dims.push((image.width(), image.height()));
            Ok(self.scores.pop_front().unwrap_or(0.0))
        }

        fn threshold(&self) -> f64 {
            self.threshold
        }
    }

    /// One 8×8 monitor with three windows: scorable crop, `doNotScore`,
    /// off-screen (needs the full-frame fallback).
    fn write_transaction(spool: &Path) -> PathBuf {
        let mut writer = TransactionWriter::begin(spool, "tester").unwrap();
        writer
            .write_monitor_png(&RgbImage::from_pixel(8, 8, Rgb([10, 20, 30])))
            .unwrap();
        let manifest = ScreenstateManifest::new(
            "tester".to_string(),
            "2026-10-11T11:59:00.000000Z".to_string(),
            "+00:00".to_string(),
            vec![ImageEntry {
                filename: "im0.png".to_string(),
                screen_rect: [0, 0, 8, 8],
            }],
            vec![[0, 0, 8, 8]],
            vec![
                AppEntry {
                    name: "Browser".to_string(),
                    window_title: "Clip".to_string(),
                    app_rect: [1, 1, 3, 3],
                    do_not_score: None,
                },
                AppEntry {
                    name: "Secret".to_string(),
                    window_title: "Bank".to_string(),
                    app_rect: [2, 2, 4, 4],
                    do_not_score: Some(true),
                },
                AppEntry {
                    name: "Ghost".to_string(),
                    window_title: "Offscreen".to_string(),
                    app_rect: [100, 100, 5, 5],
                    do_not_score: None,
                },
            ],
            "device".to_string(),
        );
        writer.write_manifest(&manifest).unwrap();
        writer.finalize().unwrap()
    }

    fn test_logger(dir: &Path) -> Logger {
        Logger::open(&dir.join("logs"), true).expect("logger")
    }

    #[test]
    fn scores_a_synthetic_transaction_skipping_do_not_score_and_falling_back() {
        let dir = tempfile::tempdir().unwrap();
        let folder = write_transaction(&dir.path().join("spool"));
        let logger = test_logger(dir.path());
        let mut scorer = FakeScorer::new(&[0.9, 0.3]);

        let message = score_transaction(&folder, &mut scorer, &logger).expect("scored");
        let Message::Result {
            batch_ts,
            windows,
            summary,
            analyzed_count,
            ..
        } = message
        else {
            panic!("expected a result message");
        };

        // `batch_ts` echoes the manifest timestamp (daemon contract).
        assert_eq!(batch_ts, "2026-10-11T11:59:00.000000Z");

        // doNotScore window never appears; remaining two keep manifest order.
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].app, "Browser");
        assert_eq!(windows[0].title, "Clip");
        assert_eq!(windows[0].rect, [1, 1, 3, 3]);
        assert_eq!(windows[0].score, 0.9);
        assert!(windows[0].flagged, "0.9 >= default threshold 0.8");
        assert_eq!(windows[1].app, "Ghost");
        assert!(!windows[1].flagged, "0.3 < 0.8");

        // Crop geometry: 3×3 intersection for Browser, full-frame 8×8
        // fallback for the off-screen Ghost.
        assert_eq!(scorer.seen_dims, vec![(3, 3), (8, 8)]);

        assert_eq!(
            summary,
            ResultSummary {
                flagged: 1,
                top_score: 0.9,
                scored_windows: 2
            }
        );
        assert_eq!(analyzed_count, 2);
        // Scoring never mutates the spool — consumption happens afterwards.
        assert!(folder.exists());
    }

    #[test]
    fn unreadable_manifest_degrades_to_an_empty_result_named_after_the_folder() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("spool").join("tester").join("pdl").join(
            "2026-10-11T11-59-00.000000",
        );
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join(spool::MANIFEST_FILE), b"{broken").unwrap();
        fs::write(folder.join(READY_MARKER), b"").unwrap();

        let logger = test_logger(dir.path());
        let mut scorer = FakeScorer::new(&[]);
        let message = score_transaction(&folder, &mut scorer, &logger).expect("degraded");
        let Message::Result {
            batch_ts,
            windows,
            summary,
            analyzed_count,
            ..
        } = message
        else {
            panic!("expected a result message");
        };
        assert_eq!(batch_ts, "2026-10-11T11-59-00.000000");
        assert!(windows.is_empty());
        assert_eq!(analyzed_count, 0);
        assert_eq!(summary.flagged, 0);
        assert_eq!(summary.top_score, 0.0);
        assert!(scorer.seen_dims.is_empty(), "nothing was scored");
    }

    #[test]
    fn processing_a_ready_folder_consumes_it_and_writes_the_control_file() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool");
        let folder = write_transaction(&spool);
        let data_dir = spool.join("tester");
        let cache_dir = dir.path().join("cache");
        // Mirror main()'s wiring: the per-user trees exist before consumption.
        bundles::ensure_user_tree(&data_dir, &cache_dir).expect("tree");
        let logger = test_logger(dir.path());
        let shutdown = AtomicBool::new(false);
        let mut scorer = FakeScorer::new(&[0.9, 0.3]);

        let mut consumer =
            Consumer::new(&data_dir, &cache_dir, &mut scorer, &logger, &shutdown)
                .expect("consumer");
        consumer.process_ready(&folder).expect("processed");

        // Consumed: folder gone, control file written.
        assert!(!folder.exists(), "consumed transaction must be removed");
        let last = bundles::read_last_result(&cache_dir)
            .expect("control readable")
            .expect("control present");
        assert_eq!(last.batch_ts, "2026-10-11T11:59:00.000000Z");
        assert_eq!(last.analyzed_count, 2);
        assert_eq!(last.flagged, 1);
        assert_eq!(last.top_score, 0.9);

        // A pre-signalled run exits gracefully without blocking.
        shutdown.store(true, Ordering::SeqCst);
        consumer.run().expect("graceful stop");
    }

    #[test]
    fn select_crop_prefers_the_largest_intersection_then_falls_back() {
        let left = RgbImage::from_pixel(8, 8, Rgb([1, 2, 3]));
        let right = RgbImage::from_pixel(8, 8, Rgb([4, 5, 6]));
        let images = vec![([0, 0, 8, 8], left), ([8, 0, 8, 8], right)];

        // Inside the right monitor only.
        let crop = select_crop([10, 2, 4, 4], &images).expect("crop");
        assert_eq!((crop.width(), crop.height()), (4, 4));
        assert_eq!(crop.get_pixel(0, 0).0, [4, 5, 6], "cut from the right image");

        // Straddling both monitors with equal area: first best wins.
        let crop = select_crop([6, 0, 4, 4], &images).expect("crop");
        assert_eq!((crop.width(), crop.height()), (2, 4));
        assert_eq!(crop.get_pixel(0, 0).0, [1, 2, 3], "cut from the left image");

        // Covered by no image: full-frame fallback of the first image.
        let crop = select_crop([20, 20, 4, 4], &images).expect("fallback");
        assert_eq!((crop.width(), crop.height()), (8, 8));
        assert_eq!(crop.get_pixel(0, 0).0, [1, 2, 3]);

        // Degenerate rect: also the full-frame fallback, never a panic.
        let crop = select_crop([0, 0, 0, 0], &images).expect("fallback");
        assert_eq!((crop.width(), crop.height()), (8, 8));

        // No images at all: nothing to score.
        assert!(select_crop([0, 0, 4, 4], &[]).is_none());
    }

    #[test]
    fn data_dir_must_be_a_spool_uid_path() {
        assert!(matches!(
            split_data_dir(Path::new("/")),
            Err(ConsumerError::BadDataDir(_))
        ));
        let (spool, uid) = split_data_dir(Path::new("/var/lib/lustless/spool/alice")).unwrap();
        assert_eq!(spool, Path::new("/var/lib/lustless/spool"));
        assert_eq!(uid, "alice");
    }
}
