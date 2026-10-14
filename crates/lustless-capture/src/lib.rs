//! LustLess capture library (CONTRACTS §3, §6.3, §7).
//!
//! Provides:
//! - [`manifest`] — screenstate manifest schema 3.0.0 serde types (key set verbatim per §6.3),
//! - [`spool`] — the file-transaction writer (`spool/<uid>/pdl/<ts>/` + atomic `ready` marker),
//!   the consumer-side inotify watcher, startup orphan cleanup and tamper detection,
//! - [`x11`] — X11 capture backend (RandR outputs, MIT-SHM `ShmGetImage` with layered fallbacks),
//! - [`wayland`] — Wayland capture backend (xdg-desktop-portal ScreenCast via `ashpd`,
//!   PipeWire stream consumption, DMA-BUF/memfd frame extraction),
//! - [`scheduler`] — jittered capture cadence `U[(1-v)*I, (1+v)*I]`, the CE retry ladder and the
//!   lock/screensaver/classifier-alive gates (logind `LockedHint`/`Active` via `zbus`).

pub mod manifest;
pub mod pipewire_pod;
pub mod pipewire_sys;
pub mod scheduler;
pub mod spool;
#[cfg(feature = "wayland-portal")]
pub mod wayland;
pub mod x11;

use std::future::Future;
use std::pin::Pin;

use image::RgbImage;

pub use manifest::ScreenstateManifest;
pub use scheduler::{BackendChoice, GateError, Gates, Scheduler};
pub use spool::{SpoolWatcher, TamperEvent, TransactionWriter};

/// One captured monitor image together with its rectangle in virtual-screen coordinates.
#[derive(Debug, Clone)]
pub struct CapturedMonitor {
    /// Monitor index; the PNG written for it is `im<N>.png` (CONTRACTS §6.3).
    pub index: u32,
    /// `[x, y, width, height]` in the backend's virtual-screen coordinate space.
    pub rect: [i32; 4],
    /// The captured pixels (RGB, one image per monitor, rotation already normalized by the
    /// backend: RandR reports post-rotation geometry, PipeWire delivers scanout-oriented
    /// buffers).
    pub image: RgbImage,
    /// True when the compositor/security state marks this output's content as protected or
    /// excluded from scoring (Wayland restricted PipeWire nodes, X11 excluded-capture
    /// surfaces). Captured and flagged, never skipped — CONTRACTS §7.
    pub restricted: bool,
}

/// One scorable application window enumerated during the capture.
#[derive(Debug, Clone)]
pub struct CapturedApp {
    /// Application name (X11: executable/WM_CLASS identity; Wayland: synthetic output entry).
    pub name: String,
    /// Window title (X11 `_NET_WM_NAME`; Wayland: empty — compositor exposes no titles).
    pub window_title: String,
    /// `[x, y, width, height]` in virtual-screen coordinates, over a monitor rect.
    pub app_rect: [i32; 4],
    /// Protected/restricted surface: include in the manifest with `doNotScore: true`
    /// (CONTRACTS §7 — flagged, never aborted).
    pub do_not_score: bool,
}

/// The result of one backend capture pass.
#[derive(Debug, Clone, Default)]
pub struct Capture {
    pub monitors: Vec<CapturedMonitor>,
    pub apps: Vec<CapturedApp>,
}

impl Capture {
    /// True when no monitor was captured successfully.
    pub fn is_empty(&self) -> bool {
        self.monitors.is_empty()
    }
}

/// Errors surfaced by a capture backend.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("display connection failed: {0}")]
    Connect(String),
    #[error("no capture source available: {0}")]
    NoSource(String),
    #[error("capture of {what} failed: {reason}")]
    CaptureFailed { what: String, reason: String },
    #[error("portal request failed: {0}")]
    Portal(String),
    #[error("pipewire error: {0}")]
    PipeWire(String),
}

/// Common behavior of the X11 and Wayland backends.
///
/// Both implementations are async so the daemon can drive them from one tokio runtime next to
/// the `zbus`-based gates; the X11 backend simply performs blocking X round trips inside its
/// future. The boxed future keeps the trait object-safe for [`open`]-style dispatch.
pub trait CaptureBackend: Send {
    /// Capture every available output plus the window list (or its Wayland approximation).
    fn capture(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Capture, CaptureError>> + Send + '_>>;
}

/// Backend selector per CONTRACTS §7: `auto` = X11 when `XDG_SESSION_TYPE=x11`, else Wayland.
pub fn resolve_backend(choice: BackendChoice, session_type: Option<&str>) -> BackendChoice {
    match choice {
        BackendChoice::Auto => match session_type {
            Some("x11") => BackendChoice::X11,
            _ => BackendChoice::Wayland,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_selects_x11_only_for_x11_session_type() {
        assert!(matches!(
            resolve_backend(BackendChoice::Auto, Some("x11")),
            BackendChoice::X11
        ));
        assert!(matches!(
            resolve_backend(BackendChoice::Auto, Some("wayland")),
            BackendChoice::Wayland
        ));
        assert!(matches!(
            resolve_backend(BackendChoice::Auto, None),
            BackendChoice::Wayland
        ));
        assert!(matches!(
            resolve_backend(BackendChoice::X11, Some("wayland")),
            BackendChoice::X11
        ));
    }
}
