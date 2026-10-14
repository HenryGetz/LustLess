//! `lustless-core` — the shared contract surface of the LustLess workspace
//! (clean-room Linux reimplementation of the Covenant Eyes "Victory Shield"
//! 10.1.44 behavior surface).
//!
//! Per `docs/impl/CONTRACTS.md` §3 this crate owns:
//!
//! | module | contract section |
//! |---|---|
//! | [`config`] | §9.1 system configuration (`/etc/lustless/lustless.toml`) |
//! | [`wire`] | §5 IPC frame codec + authorization scopes |
//! | [`records`] | §10 activity record vocabulary + envelope |
//! | [`db`] | §6.1 outbox DB (verbatim `ce-file` schema + lifecycle) |
//! | [`settings`] | §6.2 per-user SQLCipher settings DB |
//! | [`metrics`] | §14 metric taxonomy + §6.1 metrics bucket lifecycle |
//! | [`clock`] | §10 `(server_time, local_ticks)` clock anchor |
//! | [`policy`] | §9 `PolicySnapshot` |
//! | [`ids`] | §6.3 `urlSafeUsername` + device-id helpers |
//!
//! The public API (types and function signatures) of these modules is fixed by
//! CONTRACTS §5–§9 and MUST NOT drift without updating that document.

use thiserror::Error;

/// Version of the `lustless` product this crate was built from (CONTRACTS §1:
/// `0.1.9`); used for the `client.version` field of upload records (§10).
pub const LUSTLESS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The single error type of this crate (one `thiserror` enum for all modules).
#[derive(Debug, Error)]
pub enum CoreError {
    /// A frame failed to encode/decode (§5 framing rules).
    #[error("invalid frame: {0}")]
    InvalidFrame(String),

    /// A frame exceeded the 64 KiB maximum of §5 (header + payload).
    #[error("frame exceeds the 64 KiB maximum")]
    FrameTooLarge,

    /// SQL statement/connection failure in the outbox (§6.1) or settings (§6.2) DB.
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    /// Filesystem failure (DB/key/config files, §4 permission/layout rules).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization failure (frames §5, records §10, metrics §6.1).
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// `/etc/lustless/lustless.toml` could not be parsed; the display form is
    /// exactly the `config parse failed: <err>` log line required by §9.1.
    /// Callers fall back to the documented defaults (§9.1).
    #[error("config parse failed: {0}")]
    ConfigParse(String),

    /// The per-install `settings.key` file (§6.2) is unusable (wrong length,
    /// unreadable, or could not be created with mode 0600).
    #[error("settings key file: {0}")]
    KeyFile(String),

    /// A caller-supplied SQL table/column name for the lazy `ALTER TABLE`
    /// migration helper (§6.2) contains characters outside `[A-Za-z0-9_]`.
    #[error("invalid SQL identifier: {0}")]
    InvalidIdentifier(String),

    /// The database did not switch to WAL journal mode (required by §6.1).
    #[error("unexpected journal mode: {0}")]
    JournalMode(String),
}

pub mod clock;
pub mod config;
pub mod db;
pub mod ids;
pub mod metrics;
pub mod policy;
pub mod records;
pub mod settings;
pub mod wire;

/// Shared helpers for this crate's unit tests (temp dirs for the SQLite files
/// required by the testing contract, CONTRACTS §16).
#[cfg(test)]
pub(crate) mod test_util {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// A unique directory under the system temp dir, removed on drop.
    pub(crate) struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "lustless-core-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
