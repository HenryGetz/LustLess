//! Screenstate spool file transactions (CONTRACTS §6.3; CE behavior:
//! `re/findings/10-classifier/capture-pipeline.md` §2/§3 and
//! `re/findings/10-classifier/classifier-internals-classifier.md` §a).
//!
//! Layout: `spool_dir/<uid>/pdl/<ts>/` containing `im<N>.png` per monitor, `manifest.json`,
//! and an atomic `ready` marker (write-temp-then-rename). The consumer (classifier)
//! inotify-wakes on the marker, consumes the folder and deletes it; startup orphan cleanup
//! removes transactions a crashed producer left behind; removal/rename of a not-yet-consumed
//! ready folder is tamper (`Circumvention: PDL transaction file removed|renamed`).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use image::RgbImage;
use inotify::{Event, EventMask, Inotify, WatchDescriptor, WatchMask};

use crate::manifest::{self, ScreenstateManifest};

/// Marker file that turns a transaction folder into a consumable unit (CE's `rr.dat`).
pub const READY_MARKER: &str = "ready";
/// Temp name used for the atomic ready-marker write.
const READY_TMP: &str = ".ready.tmp";
/// Manifest file name inside a transaction folder.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Errors from spool transactions.
#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("spool io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("manifest serialization failed: {0}")]
    Manifest(#[from] serde_json::Error),
    #[error("manifest validation failed: {0}")]
    InvalidManifest(#[from] manifest::ManifestError),
    #[error("transaction not finalized yet")]
    NotFinalized,
}

fn io_err(path: &Path, source: io::Error) -> SpoolError {
    SpoolError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// `spool_dir/<uid>/pdl` for a user key (`<uid>` = `url_safe_username(username)`).
pub fn pdl_root(spool_dir: &Path, uid: &str) -> PathBuf {
    spool_dir.join(uid).join("pdl")
}

/// Producer-side transaction writer.
///
/// Lifecycle: [`TransactionWriter::begin`] → [`TransactionWriter::write_monitor_png`] per
/// monitor → [`TransactionWriter::write_manifest`] → [`TransactionWriter::finalize`] (atomic
/// `ready` marker). Dropping an unfinalized writer aborts (removes) the folder — CE deletes
/// the transaction on capture failure (`capture-pipeline.md` §2).
pub struct TransactionWriter {
    folder: PathBuf,
    monitor_count: u32,
    finalized: bool,
    keep_on_drop: bool,
}

impl TransactionWriter {
    /// Create `pdl/<ts>/` under the user's spool root. On a name collision CE appends
    /// `-0`…`-9` (`createTransactionFolder`, `capture-pipeline.md` §2 step 1); we take the
    /// first free name the same way.
    pub fn begin(spool_dir: &Path, uid: &str) -> Result<Self, SpoolError> {
        let root = pdl_root(spool_dir, uid);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .map_err(|e| io_err(&root, e))?;

        let ts = manifest::transaction_timestamp(chrono::Utc::now());
        let mut folder = root.join(&ts);
        if folder.exists() {
            folder = (0..10)
                .map(|suffix| root.join(format!("{ts}-{suffix}")))
                .find(|candidate| !candidate.exists())
                .unwrap_or_else(|| root.join(format!("{ts}-9")));
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&folder)
            .map_err(|e| io_err(&folder, e))?;
        log::debug!(
            "pdl-edi: created spool transaction folder {}",
            folder.display()
        );
        Ok(Self {
            folder,
            monitor_count: 0,
            finalized: false,
            keep_on_drop: false,
        })
    }

    /// Create a writer over an existing (empty) transaction folder. Used by tests and by the
    /// daemon when it pre-allocates the folder name.
    pub fn at(folder: PathBuf) -> Self {
        Self {
            folder,
            monitor_count: 0,
            finalized: false,
            keep_on_drop: false,
        }
    }

    /// The transaction folder path (`…/pdl/<ts>`).
    pub fn folder(&self) -> &Path {
        &self.folder
    }

    /// Number of monitor images written so far.
    pub fn monitor_count(&self) -> u32 {
        self.monitor_count
    }

    /// Write `im<N>.png` (0-based monitor index).
    pub fn write_monitor_png(&mut self, image: &RgbImage) -> Result<u32, SpoolError> {
        let index = self.monitor_count;
        let filename = format!("im{index}.png");
        let path = self.folder.join(&filename);
        image
            .save_with_format(&path, image::ImageFormat::Png)
            .map_err(|e| io_err(&path, io::Error::other(e)))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| io_err(&path, e))?;
        self.monitor_count += 1;
        Ok(index)
    }

    /// Write `manifest.json` (after the monitor images, before finalize).
    pub fn write_manifest(&mut self, manifest: &ScreenstateManifest) -> Result<(), SpoolError> {
        manifest.validate()?;
        let path = self.folder.join(MANIFEST_FILE);
        let json = manifest.to_json()?;
        // Write-temp-then-rename so a crash mid-write cannot leave a parseable-but-partial
        // manifest next to a ready marker.
        let tmp = self.folder.join(".manifest.tmp");
        write_private(&tmp, json.as_bytes())?;
        fs::rename(&tmp, &path).map_err(|e| io_err(&path, e))
    }

    /// Publish the transaction: atomic `ready` marker via temp-file + rename. This is the only
    /// step that makes the folder visible to the consumer.
    pub fn finalize(mut self) -> Result<PathBuf, SpoolError> {
        if self.monitor_count == 0 {
            // CE aborts when zero monitors captured ("only zero successful monitors aborts",
            // capture-pipeline.md §3).
            let folder = self.folder.clone();
            self.keep_on_drop = true;
            let _ = fs::remove_dir_all(&folder);
            return Err(SpoolError::Io {
                path: folder,
                source: io::Error::other("no monitor images captured"),
            });
        }
        let tmp = self.folder.join(READY_TMP);
        write_private(&tmp, b"")?;
        let ready = self.folder.join(READY_MARKER);
        fs::rename(&tmp, &ready).map_err(|e| io_err(&ready, e))?;
        // Persist directory metadata so the rename survives a host crash.
        if let Ok(dir) = fs::File::open(&self.folder) {
            let _ = dir.sync_all();
        }
        self.finalized = true;
        self.keep_on_drop = true;
        log::debug!(
            "pdl-edi: marked spool transaction ready: {}",
            self.folder.display()
        );
        Ok(std::mem::take(&mut self.folder))
    }
}

impl Drop for TransactionWriter {
    fn drop(&mut self) {
        if !self.finalized && !self.keep_on_drop {
            // CE: capture failure deletes the transaction folder (`FUN_1401acbe0`).
            let _ = fs::remove_dir_all(&self.folder);
            log::warn!(
                "pdl-edi: aborted unfinalized transaction {}",
                self.folder.display()
            );
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SpoolError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| io_err(path, e))?;
    file.write_all(bytes).map_err(|e| io_err(path, e))?;
    file.sync_all().map_err(|e| io_err(path, e))
}

/// Outcome of the startup orphan cleanup.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CleanupReport {
    /// Incomplete folders (no `ready` marker — producer died mid-transaction) removed.
    pub removed_incomplete: Vec<PathBuf>,
    /// Ready-but-unconsumed folders older than the stale cutoff removed (consumer was down).
    pub removed_stale: Vec<PathBuf>,
}

/// Parseable prefix of a transaction folder name: `26` bytes of
/// `<YYYY-MM-DDTHH-MM-SS.mmmmmm>` (see [`manifest::transaction_timestamp`]). Anything after
/// that prefix — the `-0`…`-9` collision suffix, CE's extra micros digits — is ignored.
const FOLDER_NAME_LEN: usize = 26;
const FOLDER_NAME_FORMAT: &str = "%Y-%m-%dT%H-%M-%S%.6f";

/// The transaction timestamp encoded in a folder name (`None` for a non-conforming name or
/// a pre-epoch one).
fn folder_name_timestamp(name: &str) -> Option<SystemTime> {
    let stamp = name.get(..FOLDER_NAME_LEN)?;
    let micros = u64::try_from(
        chrono::NaiveDateTime::parse_from_str(stamp, FOLDER_NAME_FORMAT)
            .ok()?
            .and_utc()
            .timestamp_micros(),
    )
    .ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_micros(micros))
}

/// Age of a transaction folder: the timestamp in its name (the transaction's creation time),
/// falling back to the directory mtime for a name that doesn't parse.
fn folder_age(path: &Path, now: SystemTime) -> Duration {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(folder_name_timestamp)
        .or_else(|| fs::metadata(path).and_then(|m| m.modified()).ok())
        .and_then(|since| now.duration_since(since).ok())
        .unwrap_or(Duration::ZERO)
}

/// Remove orphaned transactions at startup (CE `PdlEdi::cleanFolders`,
/// `capture-pipeline.md` §"clean PDL send folders").
///
/// * incomplete (no `ready`) folders older than `incomplete_max_age` — crashed producer;
/// * `ready` folders older than `stale_max_age` — the consumer never came back for them and
///   the pixels are worthless (screenstate freshness is seconds, not hours). The classifier
///   passes `Duration::MAX` here: ready transactions are consumed regardless of age.
///
/// A folder's age is the timestamp in its name (its transaction creation time), not its
/// mtime: finalize bumps the directory mtime, and an mtime is trivially reset by anyone
/// trying to keep (or hasten) a folder around.
pub fn cleanup_orphaned(
    spool_dir: &Path,
    uid: &str,
    incomplete_max_age: Duration,
    stale_max_age: Duration,
) -> Result<CleanupReport, SpoolError> {
    let root = pdl_root(spool_dir, uid);
    let mut report = CleanupReport::default();
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(report),
        Err(e) => return Err(io_err(&root, e)),
    };
    let now = SystemTime::now();
    for entry in entries {
        let entry = entry.map_err(|e| io_err(&root, e))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let has_ready = path.join(READY_MARKER).exists();
        let age = folder_age(&path, now);
        if !has_ready && age >= incomplete_max_age {
            fs::remove_dir_all(&path).map_err(|e| io_err(&path, e))?;
            report.removed_incomplete.push(path);
        } else if has_ready && age >= stale_max_age {
            fs::remove_dir_all(&path).map_err(|e| io_err(&path, e))?;
            report.removed_stale.push(path);
        }
    }
    if !report.removed_incomplete.is_empty() || !report.removed_stale.is_empty() {
        log::info!(
            "pdl-edi: startup cleanup removed {} incomplete and {} stale spool transactions",
            report.removed_incomplete.len(),
            report.removed_stale.len()
        );
    }
    Ok(report)
}

/// A tamper event on the spool tree: a ready transaction (or its payload) disappeared without
/// being consumed by this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TamperEvent {
    /// What happened, spelled the way CE logs it.
    pub kind: TamperKind,
    /// The transaction folder that vanished or was renamed.
    pub path: PathBuf,
}

/// Tamper classification (CE vocabulary: `removed|renamed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperKind {
    Removed,
    Renamed,
}

impl TamperEvent {
    /// The CE log line, verbatim (`Circumvention: PDL transaction file removed|renamed`,
    /// `capture-pipeline.md` §"handlePdlFileNotifications").
    pub fn log_line(&self) -> &'static str {
        match self.kind {
            TamperKind::Removed => "Circumvention: PDL transaction file removed",
            TamperKind::Renamed => "Circumvention: PDL transaction file renamed",
        }
    }
}

enum Watched {
    Root,
    Transaction(PathBuf),
}

/// Consumer-side spool watcher: inotify-wakes on `ready` markers, tracks not-yet-consumed
/// transactions and records tamper on their removal/rename.
pub struct SpoolWatcher {
    root: PathBuf,
    /// `None` = polling mode: no inotify instance was available (the per-user
    /// instance limit is exhausted, or the kernel refuses one). The pipeline
    /// must keep working — a capture product that stops consuming because a
    /// watch could not be registered is worse than a 1 s wake-up.
    inode: Option<Inotify>,
    watches: HashMap<WatchDescriptor, Watched>,
    /// Ready folders not (yet) consumed by this process.
    pending: HashSet<PathBuf>,
    /// Inode per pending folder, recorded when it is adopted. The polling
    /// fallback uses it to tell a rename (same inode, new name) from a removal
    /// — after the fact the original path no longer exists to stat.
    pending_inos: HashMap<PathBuf, u64>,
    tamper: Vec<TamperEvent>,
}

impl SpoolWatcher {
    /// Watch `spool_dir/<uid>/pdl`. Folders already carrying `ready` (from a previous
    /// classifier run) are reported by [`SpoolWatcher::scan_ready`] so nothing is lost across
    /// restarts.
    pub fn open(spool_dir: &Path, uid: &str) -> Result<Self, SpoolError> {
        let root = pdl_root(spool_dir, uid);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .map_err(|e| io_err(&root, e))?;
        let inode = match Inotify::init() {
            Ok(inode) => {
                let mask = WatchMask::CREATE
                    | WatchMask::DELETE
                    | WatchMask::MOVED_FROM
                    | WatchMask::MOVED_TO
                    | WatchMask::DELETE_SELF
                    | WatchMask::MOVE_SELF;
                let root_wd = inode
                    .watches()
                    .add(&root, mask)
                    .map_err(|e| io_err(&root, e))?;
                Some((inode, root_wd))
            }
            Err(err) => {
                log::warn!(
                    "spool: inotify unavailable at {} ({err}); polling for ready \
                     transactions instead",
                    root.display()
                );
                None
            }
        };
        let mut watches = HashMap::new();
        let (inode, _) = match inode {
            Some((inode, root_wd)) => {
                watches.insert(root_wd, Watched::Root);
                (Some(inode), ())
            }
            None => (None, ()),
        };
        let mut watcher = Self {
            root,
            inode,
            watches,
            pending: HashSet::new(),
            pending_inos: HashMap::new(),
            tamper: Vec::new(),
        };
        // Adopt transaction folders created before this watcher existed.
        let entries = fs::read_dir(watcher.root.clone()).map_err(|e| io_err(&watcher.root, e))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                watcher.watch_transaction(path);
            }
        }
        Ok(watcher)
    }

    /// The watched pdl root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Ready folders that predate this watcher (classifier restart): consume these first.
    pub fn scan_ready(&mut self) -> Vec<PathBuf> {
        let mut ready = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(_) => return ready,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join(READY_MARKER).exists() {
                self.pending.insert(path.clone());
                if let Some(ino) = folder_inode(&path) {
                    self.pending_inos.insert(path.clone(), ino);
                }
                ready.push(path);
            }
        }
        ready.sort();
        ready
    }

    /// Take the tamper events recorded since the last call. The caller (daemon) logs
    /// [`TamperEvent::log_line`] and records a `circumventions` row (CONTRACTS §6.3/§7).
    pub fn drain_tamper(&mut self) -> Vec<TamperEvent> {
        std::mem::take(&mut self.tamper)
    }

    /// Forget a folder the consumer is about to delete itself, so its disappearance is not
    /// reported as tamper.
    pub fn mark_consumed(&mut self, path: &Path) {
        self.pending.remove(path);
        self.pending_inos.remove(path);
        self.retire_watch(path);
    }

    /// Block until at least one transaction folder gains a `ready` marker, or `timeout`
    /// elapses. Returns the folders observed ready during this call (plus, on the first call,
    /// any adopted via [`SpoolWatcher::scan_ready`]).
    pub fn wait_ready(&mut self, timeout: Duration) -> Result<Vec<PathBuf>, SpoolError> {
        if self.inode.is_none() {
            // Polling fallback: same semantics with a coarser wake-up. Only
            // folders that became ready during this wait are returned (so a
            // consumer never sees the same transaction twice), and a pending
            // folder that vanished is the same tamper the inotify path reports
            // from its delete/rename events.
            // The inode identifies a transaction folder across a rename, so
            // "disappeared" can still be classified as CE's Renamed vs Removed.
            let before: HashSet<PathBuf> = self.pending.clone();
            std::thread::sleep(timeout);
            let mut ready = self.scan_ready();
            ready.retain(|path| !before.contains(path));
            let gone: Vec<PathBuf> = before.iter().filter(|path| !path.exists()).cloned().collect();
            if !gone.is_empty() {
                let live: HashMap<u64, PathBuf> = fs::read_dir(&self.root)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter_map(|entry| {
                        let path = entry.path();
                        (path.is_dir())
                            .then(|| folder_inode(&path).map(|ino| (ino, path.clone())))
                            .flatten()
                    })
                    .collect();
                for path in gone {
                    self.pending.remove(&path);
                    let kind = self
                        .pending_inos
                        .remove(&path)
                        .and_then(|ino| live.get(&ino))
                        .map(|_| TamperKind::Renamed)
                        .unwrap_or(TamperKind::Removed);
                    self.record_tamper(kind, path);
                }
            }
            return Ok(ready);
        }
        let mut ready = Vec::new();
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Some(inode) = self.inode.as_mut() else {
                break;
            };
            if !poll_readable(inode.as_raw_fd(), remaining) {
                break;
            }
            let mut buf = [0u8; 8192];
            match inode.read_events(&mut buf) {
                Ok(events) => {
                    for event in events {
                        self.handle_event(&event, &mut ready);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(io_err(&self.root, e)),
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        ready.sort();
        ready.dedup();
        Ok(ready)
    }

    fn handle_event(&mut self, event: &Event<&std::ffi::OsStr>, ready: &mut Vec<PathBuf>) {
        let Some(name) = event.name.map(|n| n.to_string_lossy().into_owned()) else {
            return;
        };
        // Resolve the concrete path from the watch target: the pdl root reports per-<ts>
        // directory events, transaction dirs report per-file events.
        let watched_path = match self.watches.get(&event.wd) {
            Some(Watched::Root) => self.root.join(&name),
            Some(Watched::Transaction(path)) => path.clone(),
            None => return,
        };
        let is_root_child = matches!(self.watches.get(&event.wd), Some(Watched::Root));

        if is_root_child {
            if event.mask.contains(EventMask::CREATE) || event.mask.contains(EventMask::MOVED_TO) {
                self.watch_transaction(watched_path);
            } else {
                // A transaction directory was removed or renamed. If it was an unconsumed
                // ready transaction, that is circumvention
                // (CE `PdlEdi::handlePdlFileNotifications`).
                let was_pending = self.pending.remove(&watched_path);
                if was_pending || watched_path.join(READY_MARKER).exists() {
                    let kind = if event.mask.contains(EventMask::MOVED_FROM) {
                        TamperKind::Renamed
                    } else {
                        TamperKind::Removed
                    };
                    self.record_tamper(kind, watched_path.clone());
                }
                self.retire_watch(&watched_path);
            }
            return;
        }

        // Event inside a transaction folder.
        if name == READY_MARKER
            && (event.mask.contains(EventMask::CREATE) || event.mask.contains(EventMask::MOVED_TO))
        {
            self.pending.insert(watched_path.clone());
            ready.push(watched_path);
        } else if (event.mask.contains(EventMask::DELETE)
            || event.mask.contains(EventMask::MOVED_FROM))
            && name != READY_TMP
            && watched_path.join(READY_MARKER).exists()
        {
            // A payload file vanished from a ready transaction: same tamper class, "removed".
            self.record_tamper(TamperKind::Removed, watched_path);
        }
    }

    fn record_tamper(&mut self, kind: TamperKind, path: PathBuf) {
        let event = TamperEvent { kind, path };
        log::warn!("classifier: {}", event.log_line());
        self.tamper.push(event);
    }

    fn watch_transaction(&mut self, path: PathBuf) {
        if !path.starts_with(&self.root) || path == self.root {
            return;
        }
        if self
            .watches
            .values()
            .any(|w| matches!(w, Watched::Transaction(p) if *p == path))
        {
            return;
        }
        let mask =
            WatchMask::CREATE | WatchMask::DELETE | WatchMask::MOVED_FROM | WatchMask::MOVED_TO;
        let Some(inode) = self.inode.as_ref() else {
            // Polling mode: no per-folder watches to register.
            if path.join(READY_MARKER).exists() {
                self.pending.insert(path.clone());
            }
            return;
        };
        let Ok(wd) = inode.watches().add(&path, mask) else {
            return;
        };
        if path.join(READY_MARKER).exists() {
            self.pending.insert(path.clone());
        }
        self.watches.insert(wd, Watched::Transaction(path));
    }

    fn retire_watch(&mut self, path: &Path) {
        let stale: Vec<WatchDescriptor> = self
            .watches
            .iter()
            .filter_map(|(wd, w)| match w {
                Watched::Transaction(p) if p == path => Some(wd.clone()),
                _ => None,
            })
            .collect();
        for wd in stale {
            if let Some(inode) = self.inode.as_ref() {
                let _ = inode.watches().remove(wd.clone());
            }
            self.watches.remove(&wd);
        }
    }
}

/// Inode of a transaction folder (used by the polling fallback to tell a
/// rename from a removal).
fn folder_inode(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    fs::metadata(path).ok().map(|meta| meta.ino())
}

/// Wait until `fd` is readable or `timeout` elapses. `timeout == 0` polls once.
fn poll_readable(fd: i32, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let n = unsafe { libc::poll(&mut pfd, 1, ms) };
    n > 0 && (pfd.revents & libc::POLLIN) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AppEntry, ImageEntry};

    fn test_manifest(filename: &str) -> ScreenstateManifest {
        ScreenstateManifest::new(
            "tester".into(),
            "2026-10-11T12:00:00.000000Z".into(),
            "+00:00".into(),
            vec![ImageEntry {
                filename: filename.into(),
                screen_rect: [0, 0, 4, 4],
            }],
            vec![[0, 0, 4, 4]],
            vec![AppEntry {
                name: "app".into(),
                window_title: "title".into(),
                app_rect: [0, 0, 4, 4],
                do_not_score: None,
            }],
            "device".into(),
        )
    }

    fn tiny_image() -> RgbImage {
        RgbImage::from_pixel(4, 4, image::Rgb([10u8, 20, 30]))
    }

    fn finalize_one(spool: &Path, uid: &str) -> PathBuf {
        let mut writer = TransactionWriter::begin(spool, uid).unwrap();
        writer.write_monitor_png(&tiny_image()).unwrap();
        writer.write_manifest(&test_manifest("im0.png")).unwrap();
        writer.finalize().unwrap()
    }

    #[test]
    fn ready_marker_appears_atomically_after_all_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path();

        let mut writer = TransactionWriter::begin(spool, "tester").unwrap();
        let folder = writer.folder().to_path_buf();
        assert!(!folder.join(READY_MARKER).exists());

        writer.write_monitor_png(&tiny_image()).unwrap();
        writer.write_manifest(&test_manifest("im0.png")).unwrap();
        // Still invisible: ready only lands on finalize, via temp+rename.
        assert!(!folder.join(READY_MARKER).exists());
        assert!(!folder.join(READY_TMP).exists());

        let published = writer.finalize().unwrap();
        assert_eq!(published, folder);
        assert!(folder.join(READY_MARKER).exists());
        assert!(folder.join(MANIFEST_FILE).exists());
        assert!(folder.join("im0.png").exists());
        // No temp residue.
        assert!(!folder.join(READY_TMP).exists());
        assert!(!folder.join(".manifest.tmp").exists());

        let manifest = ScreenstateManifest::from_json(
            &fs::read_to_string(folder.join(MANIFEST_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.images[0].filename, "im0.png");
    }

    #[test]
    fn unfinalized_transaction_is_aborted_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let folder;
        {
            let mut writer = TransactionWriter::begin(dir.path(), "tester").unwrap();
            writer.write_monitor_png(&tiny_image()).unwrap();
            folder = writer.folder().to_path_buf();
        }
        assert!(!folder.exists(), "drop must delete the aborted transaction");
    }

    #[test]
    fn finalize_without_monitors_fails_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let writer = TransactionWriter::begin(dir.path(), "tester").unwrap();
        let folder = writer.folder().to_path_buf();
        let err = writer.finalize().unwrap_err();
        assert!(matches!(err, SpoolError::Io { .. }));
        assert!(!folder.exists());
    }

    /// A transaction folder name in the on-disk format, `ago` before now.
    /// Fixtures MUST be relative to the clock: `cleanup_orphaned` reads the
    /// transaction time out of the *name*, so hardcoded dates turn into
    /// "everything is stale" the day after they were written.
    fn folder_name_ago(ago: Duration) -> String {
        let when = SystemTime::now() - ago;
        let stamp: chrono::DateTime<chrono::Utc> = when.into();
        stamp.format(FOLDER_NAME_FORMAT).to_string()
    }

    #[test]
    fn startup_cleanup_removes_incomplete_and_stale_folders_keeps_fresh_ready() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path();
        let root = pdl_root(spool, "tester");
        fs::DirBuilder::new().recursive(true).create(&root).unwrap();

        let incomplete = root.join(folder_name_ago(Duration::from_secs(600)));
        fs::create_dir(&incomplete).unwrap();
        fs::write(incomplete.join("im0.png"), b"partial").unwrap();

        let stale = root.join(folder_name_ago(Duration::from_secs(300)));
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join(READY_MARKER), b"").unwrap();

        let fresh = root.join(folder_name_ago(Duration::from_secs(0)));
        fs::create_dir(&fresh).unwrap();
        fs::write(fresh.join(READY_MARKER), b"").unwrap();

        let report = cleanup_orphaned(
            spool,
            "tester",
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(report.removed_incomplete, vec![incomplete.clone()]);
        assert_eq!(report.removed_stale, vec![stale.clone()]);
        assert!(!incomplete.exists());
        assert!(!stale.exists());
        assert!(
            fresh.exists(),
            "a fresh ready transaction must survive startup cleanup"
        );
    }

    #[test]
    fn watcher_sees_ready_marker_and_adopts_preexisting_folders() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path();

        // A transaction finalized BEFORE the watcher starts (classifier restart case).
        let preexisting = finalize_one(spool, "tester");

        let mut watcher = SpoolWatcher::open(spool, "tester").unwrap();
        let adopted = watcher.scan_ready();
        assert_eq!(adopted, vec![preexisting.clone()]);

        // A new transaction finalized while the watcher is live.
        let root = pdl_root(spool, "tester");
        let producer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let folder = root.join("2099-01-01T00-00-00.000000");
            fs::DirBuilder::new().mode(0o700).create(&folder).unwrap();
            let mut writer = TransactionWriter::at(folder.clone());
            writer.write_monitor_png(&tiny_image()).unwrap();
            writer.write_manifest(&test_manifest("im0.png")).unwrap();
            writer.finalize().unwrap();
        });
        let mut woken = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline
            && !woken
                .iter()
                .any(|p: &PathBuf| p.ends_with("2099-01-01T00-00-00.000000"))
        {
            woken.extend(watcher.wait_ready(Duration::from_millis(200)).unwrap());
        }
        producer.join().unwrap();
        assert!(
            woken
                .iter()
                .any(|p| p.ends_with("2099-01-01T00-00-00.000000")),
            "watcher must wake on the new ready marker, got {woken:?}"
        );
    }

    #[test]
    fn wait_ready_times_out_quietly_when_idle() {
        let dir = tempfile::tempdir().unwrap();
        let mut watcher = SpoolWatcher::open(dir.path(), "tester").unwrap();
        let started = Instant::now();
        let ready = watcher.wait_ready(Duration::from_millis(200)).unwrap();
        assert!(ready.is_empty());
        assert!(started.elapsed() >= Duration::from_millis(150));
    }

    #[test]
    fn removing_an_unconsumed_ready_transaction_is_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path();
        let folder = finalize_one(spool, "tester");

        let mut watcher = SpoolWatcher::open(spool, "tester").unwrap();
        watcher.scan_ready();

        // External actor deletes the ready folder (not via mark_consumed).
        fs::remove_dir_all(&folder).unwrap();
        let tamper = wait_for_tamper(&mut watcher, Duration::from_secs(5));
        assert_eq!(
            tamper,
            vec![TamperEvent {
                kind: TamperKind::Removed,
                path: folder.clone(),
            }]
        );
        assert_eq!(
            tamper[0].log_line(),
            "Circumvention: PDL transaction file removed"
        );
    }

    #[test]
    fn renaming_an_unconsumed_ready_transaction_is_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path();
        let folder = finalize_one(spool, "tester");

        let mut watcher = SpoolWatcher::open(spool, "tester").unwrap();
        watcher.scan_ready();

        let renamed = folder.with_file_name("hijacked");
        fs::rename(&folder, &renamed).unwrap();
        let tamper = wait_for_tamper(&mut watcher, Duration::from_secs(5));
        assert_eq!(
            tamper,
            vec![TamperEvent {
                kind: TamperKind::Renamed,
                path: folder.clone(),
            }]
        );
        assert_eq!(
            tamper[0].log_line(),
            "Circumvention: PDL transaction file renamed"
        );
    }

    #[test]
    fn consuming_via_mark_suppresses_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path();
        let folder = finalize_one(spool, "tester");

        let mut watcher = SpoolWatcher::open(spool, "tester").unwrap();
        watcher.scan_ready();
        watcher.mark_consumed(&folder);
        fs::remove_dir_all(&folder).unwrap();

        let _ = watcher.wait_ready(Duration::from_millis(300)).unwrap();
        assert!(
            watcher.drain_tamper().is_empty(),
            "consumer-initiated deletion must not be tamper"
        );
    }

    fn wait_for_tamper(watcher: &mut SpoolWatcher, timeout: Duration) -> Vec<TamperEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            let drained = watcher.drain_tamper();
            if !drained.is_empty() {
                return drained;
            }
            assert!(
                Instant::now() < deadline,
                "no tamper event within {timeout:?}"
            );
            let _ = watcher.wait_ready(Duration::from_millis(50)).unwrap();
        }
    }
}
