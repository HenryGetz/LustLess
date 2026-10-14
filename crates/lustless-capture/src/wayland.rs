//! Wayland capture backend (CONTRACTS §7): xdg-desktop-portal ScreenCast via `ashpd` plus
//! PipeWire stream consumption through our own runtime bindings
//! ([`crate::pipewire_sys`] + [`crate::pipewire_pod`]).
//!
//! ## Why our own bindings instead of the `pipewire` crate
//!
//! The maintained `pipewire` crate cannot even be *built* against the Zorin 17 / Ubuntu 22.04
//! baseline (libpipewire 0.3.48 / libspa 0.2): its bindgen output needs symbols and fields that
//! do not exist there, and `struct spa_video_info_raw` genuinely changed layout between 0.3.48
//! and 1.0.x, so no single linked build can be correct on both. We therefore link nothing at
//! build time and `dlopen` `libpipewire-0.3.so.0` by its stable soname (identical in both) from
//! [`crate::pipewire_sys`]. The three consequences this file leans on:
//!
//! * **version tolerance** — one artifact serves 0.3.48 and 1.0.x,
//! * **no link dependency** — a machine without PipeWire installed fails the *session*, not the
//!   build or the process,
//! * **graceful degradation** — a missing library or a dead compositor surfaces as
//!   [`CaptureError::PipeWire`], which the daemon treats like any other capture failure (§7, §13).
//!
//! SPA data crosses that boundary **only as bytes**: a stream negotiates with the EnumFormat pod
//! built by [`pipewire_pod::enum_format_pod`] and reads the negotiated format back out of the
//! `param_changed` pod with [`pipewire_pod::parse_video_info`]. This module never constructs or
//! passes an SPA negotiation struct.
//!
//! ## Architecture
//!
//! One long-lived ScreenCast session per backend (a cadence that recreated the session would
//! re-prompt the user; a held session keeps the compositor's consent). The portal reports every
//! node id *before* the PipeWire thread starts, so the thread creates the main loop, context,
//! core, registry and one capture stream per node itself and then simply runs — there is no
//! command channel between the threads. Teardown is [`MainLoop::quit`] from the capture thread
//! followed by a join ([`SessionState::shutdown`]). Each `capture()` takes the freshest frame
//! per stream.
//!
//! ## The portal lives on the user's session bus
//!
//! The daemon is a root *system* service, but xdg-desktop-portal runs in the logged-in user's
//! session, so we connect that session bus explicitly (address from `$DBUS_SESSION_BUS_ADDRESS`,
//! else `unix:path=$XDG_RUNTIME_DIR/bus`) and hand the connection to `ashpd` rather than letting
//! it pick up whatever the daemon happened to inherit. The daemon prepares the user's session
//! environment before opening the backend (§7).
//!
//! ## Permission persistence
//!
//! [`WaylandBackend::new`] takes an optional restore-token path. When it is given we ask the
//! portal to persist the selection (`PersistMode::ExplicitlyRevoked`, the
//! `XDP_PERSIST_MODE_PERSISTENT` mode), present any token we already stored so the user is not
//! asked again, and write the token the portal returns back to that path (0600). An
//! accountability agent that re-presented the ScreenCast permission dialog on every login would
//! be worse than useless: the user would learn to dismiss it, or turn the agent off. A failed
//! token read or write is never fatal — it only costs one more dialog.
//!
//! ## Frame extraction
//!
//! Only CPU-readable memory is consumed (`MemPtr`/`MemFd`/`MemId`); a `DmaBuf` plane is logged
//! once per stream and skipped, never fatal — we negotiate packed raw formats precisely so the
//! compositor hands us memory we can read. The chunk's real geometry is honoured: rows are
//! addressed by the *signed* `chunk.stride` (a negative stride means the rows are stored
//! bottom-up and [`wire_to_rgb`] flips them), every access is bounds-checked against the chunk
//! window and the mapping size, and a short or inconsistent buffer is dropped with a log rather
//! than a panic.
//!
//! Wayland exposes no global window enumeration, so `apps[]` gets one synthetic entry per
//! monitor — the classifier's full-frame fallback covers per-window semantics. Protected
//! surfaces (PipeWire nodes flagged `restricted`/`securityContext` by the compositor) mark the
//! entry `doNotScore: true` (flag, don't abort — §7).

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::future::Future;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::ptr;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use ashpd::desktop::screencast::{
    CursorMode, OpenPipeWireRemoteOptions, Screencast, SelectSourcesOptions, SourceType,
};
use ashpd::desktop::{PersistMode, Session};
use image::{Rgb, RgbImage};

use crate::manifest::Rect;
use crate::pipewire_pod::{
    self, enum_format_pod, parse_video_info, SPA_VIDEO_FORMAT_BGR, SPA_VIDEO_FORMAT_BGRA,
    SPA_VIDEO_FORMAT_BGRX, SPA_VIDEO_FORMAT_RGB, SPA_VIDEO_FORMAT_RGBA, SPA_VIDEO_FORMAT_RGBX,
};
use crate::pipewire_sys::{
    dict_get, pod_as_bytes, Context, Core, MainLoop, Properties, PwBuffer, PwLibrary, Registry,
    RegistryEvents, SPA_DATA_MemFd, SPA_DATA_MemId, SPA_DATA_MemPtr, SpaDirection, Stream,
    StreamEvents, PW_STREAM_FLAG_AUTOCONNECT, PW_STREAM_FLAG_MAP_BUFFERS, SPA_DATA_FLAG_READABLE,
};
use crate::{Capture, CaptureBackend, CaptureError, CapturedApp, CapturedMonitor};

/// How long a capture waits for every stream to deliver a fresh frame.
const FRAME_WAIT: Duration = Duration::from_secs(3);

/// Geometry assumed for a portal stream that reported no size. Only the *default* of the
/// EnumFormat offer; the real size comes back from `param_changed`.
const DEFAULT_STREAM_SIZE: (u32, u32) = (1920, 1080);

/// `PW_STREAM_STATE_ERROR` — `enum pw_stream_state` in `pipewire/stream.h` is `-1..=3` in both
/// 0.3.48 and 1.0.5, with `ERROR = -1`.
const PW_STREAM_STATE_ERROR: c_int = -1;

/// PipeWire's object type string for nodes, as `pw_registry_events.global` reports it: the
/// qualified name (the same string `pipewire`'s own `ObjectType` maps to `Node`).
const NODE_TYPE: &[u8] = b"PipeWire:Interface:Node";
/// The bare object type name, accepted alongside [`NODE_TYPE`].
const NODE_TYPE_SHORT: &[u8] = b"Node";

/// The Wayland capture backend (portal session + PipeWire thread are created lazily on the
/// first capture).
pub struct WaylandBackend {
    state: Option<SessionState>,
    /// Where to keep the portal's ScreenCast restore token; `None` disables persistence.
    token_path: Option<PathBuf>,
}

/// One portal-reported stream: (node_id, optional size, optional position).
type PortalStream = (u32, Option<(u32, u32)>, Option<(i32, i32)>);

/// Everything owned by one live ScreenCast session.
struct SessionState {
    /// Held, not read: dropping `Screencast` closes the portal session and
    /// dropping `Session` releases the D-Bus ScreenCast connection; the
    /// capture loop only needs the PipeWire side after setup.
    #[allow(dead_code)]
    portal: Screencast,
    /// See `portal`: session lifetime is the point of this field.
    #[allow(dead_code)]
    session: Session<Screencast>,
    /// Streams reported by the portal (see [`PortalStream`]).
    streams: Vec<PortalStream>,
    /// Handle into the PipeWire thread's loop: `quit()` stops it, the join finishes it.
    main_loop: Arc<MainLoop>,
    thread: JoinHandle<()>,
    shared: Arc<Shared>,
    /// Last frame sequence consumed per node, for freshness.
    last_seq: HashMap<u32, u64>,
}

/// Cross-thread state between the PipeWire loop thread and the capture thread.
#[derive(Default)]
struct Shared {
    /// Freshest decoded frame per PipeWire node id.
    frames: Mutex<HashMap<u32, FrameSlot>>,
    /// Wakeup for new frames.
    cv: Condvar,
    /// Per-node `restricted`/`securityContext` flags collected from the registry.
    restricted: Mutex<HashMap<u32, bool>>,
    /// Fatal PipeWire-side error, if any.
    error: Mutex<Option<String>>,
}

struct FrameSlot {
    seq: u64,
    frame: WireFrame,
}

/// A decoded frame as it crossed the thread boundary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WireFormat {
    Bgrx,
    Rgbx,
    Bgra,
    Rgba,
    Bgr,
    Rgb,
}

impl WireFormat {
    /// Bytes per pixel.
    fn channels(self) -> usize {
        match self {
            WireFormat::Bgrx | WireFormat::Rgbx | WireFormat::Bgra | WireFormat::Rgba => 4,
            WireFormat::Bgr | WireFormat::Rgb => 3,
        }
    }

    /// True when the first byte in memory is the blue channel.
    fn is_bgr(self) -> bool {
        match self {
            WireFormat::Bgrx | WireFormat::Bgra | WireFormat::Bgr => true,
            WireFormat::Rgbx | WireFormat::Rgba | WireFormat::Rgb => false,
        }
    }

    /// Map an `SPA_VIDEO_FORMAT_*` id onto the formats this backend understands.
    fn from_spa(id: u32) -> Option<Self> {
        match id {
            SPA_VIDEO_FORMAT_BGRX => Some(WireFormat::Bgrx),
            SPA_VIDEO_FORMAT_RGBX => Some(WireFormat::Rgbx),
            SPA_VIDEO_FORMAT_BGRA => Some(WireFormat::Bgra),
            SPA_VIDEO_FORMAT_RGBA => Some(WireFormat::Rgba),
            SPA_VIDEO_FORMAT_BGR => Some(WireFormat::Bgr),
            SPA_VIDEO_FORMAT_RGB => Some(WireFormat::Rgb),
            _ => None,
        }
    }
}

/// A copy of one PipeWire buffer, as it crossed the thread boundary.
///
/// `data` starts at the first byte of the chunk's row span and `stride` is the chunk's signed
/// row pitch: with a positive stride, image row `row` starts at byte `row * stride`; with a
/// negative one the rows are stored bottom-up, so image row `row` starts at byte
/// `(height - 1 - row) * |stride|`. Either way a padded stride is carried through unchanged and
/// honoured by [`wire_to_rgb`].
#[derive(Clone)]
struct WireFrame {
    data: Vec<u8>,
    width: u32,
    height: u32,
    /// Signed byte distance between successive image rows in `data`, matching
    /// `struct spa_chunk::stride`. Negative means the rows are stored bottom-up (the first row
    /// in memory is the *last* image row).
    stride: i32,
    format: WireFormat,
}

impl WireFrame {
    /// Index, *within `data`*, of the row slot holding image row `row`; multiply it by the
    /// stride's magnitude to get a byte offset. A negative stride means the rows are stored
    /// bottom-up, so the image is read back to front.
    fn memory_row(&self, row: usize) -> Option<usize> {
        let rows = self.height as usize;
        if row >= rows {
            return None;
        }
        Some(if self.stride < 0 { rows - 1 - row } else { row })
    }
}

/// The geometry and pixel format the compositor negotiated for one stream.
#[derive(Clone, Copy)]
struct Negotiated {
    width: u32,
    height: u32,
    format: WireFormat,
}

/// Per-stream state owned by the PipeWire thread and reached only through that stream's
/// listener callbacks (which the library invokes on that same thread).
struct StreamUser {
    node_id: u32,
    /// Stream name, for log lines only.
    name: String,
    /// Negotiated geometry and pixel format, learned from `param_changed`.
    negotiated: Option<Negotiated>,
    /// The stream these callbacks belong to; filled in right after the stream is boxed.
    stream: *const Stream,
    shared: Arc<Shared>,
    /// One-shot log gates: a compositor that hands us unusable buffers every frame must not
    /// flood the log with a line per frame.
    warned_memory: bool,
    warned_geometry: bool,
}

impl StreamUser {
    /// Log an unusable memory type once per stream.
    fn warn_memory(&mut self, data_type: u32) {
        if self.warned_memory {
            return;
        }
        self.warned_memory = true;
        log::warn!(
            "capture: stream {} (node {}) delivers spa_data type {data_type}, which we cannot \
             read (only MemPtr/MemFd/MemId are consumed — we negotiate packed raw formats, \
             never DMA-BUF); its frames are skipped",
            self.name,
            self.node_id
        );
    }

    /// Log an unusable buffer once per stream. The frame is always skipped; only the log is
    /// throttled.
    fn warn_geometry(&mut self, detail: &str) {
        if self.warned_geometry {
            return;
        }
        self.warned_geometry = true;
        log::warn!(
            "capture: stream {} (node {}) produced an unusable buffer ({detail}); skipping its \
             frames",
            self.name,
            self.node_id
        );
    }

    /// Record a fatal stream failure. It is stored in the shared slot that the capture thread
    /// checks on every tick, so the session is torn down and rebuilt instead of waiting forever
    /// for frames that cannot arrive.
    fn fail(&self, detail: &str) {
        let message = format!("stream {} (node {}): {detail}", self.name, self.node_id);
        log::error!("capture: {message}");
        *self.shared.error.lock() = Some(message);
    }
}

/// One capture stream plus the listener state whose addresses the PipeWire library keeps.
///
/// Both fields are held, never read: the point is that the listener goes away with the stream,
/// and that the addresses the library stored stay valid for exactly that long.
#[allow(dead_code)]
struct StreamHandle {
    /// Boxed so the address the process callback reads stays valid: moving `Stream` into the
    /// `Vec` would move it in memory.
    stream: Box<Stream>,
    /// Boxed for the same reason — the library stores this address as the callbacks' `data`.
    user: Box<StreamUser>,
}

/// The live PipeWire object graph of one capture session, owned by the loop thread.
///
/// Field order *is* drop order and matters: streams and the registry are proxies on the core
/// and must go before it, and the core must go before the context whose loop drives it (see the
/// `Drop` notes on `pipewire_sys::Context`/`Core`). The fields are held rather than read, hence
/// the `dead_code` allowance.
#[allow(dead_code)]
struct PipeWireGraph {
    streams: Vec<StreamHandle>,
    /// Registry listener that flags protected nodes `doNotScore`.
    registry: Registry,
    /// The `Arc<Shared>` the registry callback dereferences; must outlive `registry`.
    ///
    /// Deliberately `Box`ed: the callback receives a pointer to the `Arc` *slot* and casts it
    /// to `*const Arc<Shared>` (see `on_registry_global`), so that slot must keep a stable
    /// address — a plain field would be moved into this struct after the pointer was taken.
    // clippy sees a redundant allocation; it cannot see that the inner value is address-taken
    // and that its address is part of the ABI between us and the callback.
    #[allow(clippy::redundant_allocation)]
    registry_data: Box<Arc<Shared>>,
    /// Connection to the compositor's PipeWire instance.
    core: Core,
    /// Kept alive only so `core`, `registry` and `streams` have a loop to run in; declared last
    /// so it is dropped after them.
    _context: Context,
}

impl PipeWireGraph {
    /// Connect to the portal's PipeWire remote and create one capture stream per node the
    /// portal reported. Takes ownership of `remote_fd` (PipeWire closes it).
    fn connect(
        lib: &Arc<PwLibrary>,
        main_loop: &MainLoop,
        remote_fd: OwnedFd,
        portal_streams: &[PortalStream],
        shared: Arc<Shared>,
    ) -> Result<Self, String> {
        let context = Context::new(lib, main_loop).map_err(|e| format!("context: {e}"))?;
        let core = context
            .connect_fd(remote_fd)
            .map_err(|e| format!("connect: {e}"))?;
        let registry_data = Box::new(Arc::clone(&shared));
        let registry = core
            .registry(
                RegistryEvents {
                    global: Some(on_registry_global),
                    ..Default::default()
                },
                &*registry_data as *const Arc<Shared> as *mut c_void,
            )
            .map_err(|e| format!("registry: {e}"))?;
        let mut streams = Vec::with_capacity(portal_streams.len());
        for (node_id, size, _) in portal_streams {
            let (width, height) = size.unwrap_or(DEFAULT_STREAM_SIZE);
            streams.push(connect_stream(
                lib,
                &core,
                *node_id,
                &format!("lustless-capture-{node_id}"),
                (width, height),
                Arc::clone(&shared),
            )?);
        }
        Ok(Self {
            streams,
            registry,
            registry_data,
            core,
            _context: context,
        })
    }
}

impl WaylandBackend {
    /// Prepare a backend. `token_path`, when given, is where the portal's ScreenCast *restore
    /// token* is persisted so later logins do not re-present the permission dialog (see the
    /// module docs).
    ///
    /// No portal or PipeWire object is created here: that happens on the first capture, so that
    /// a failure can be reported per capture and retried on the next one.
    pub fn new(token_path: Option<PathBuf>) -> Result<Self, CaptureError> {
        Ok(Self {
            state: None,
            token_path,
        })
    }

    /// Establish the portal session and the PipeWire loop thread (idempotent).
    async fn ensure_session(&mut self) -> Result<&mut SessionState, CaptureError> {
        if self.state.is_none() {
            let token_path = self.token_path.clone();
            let state = open_session(token_path.as_deref()).await?;
            log::info!(
                "capture: wayland ScreenCast session established with {} stream(s)",
                state.streams.len()
            );
            self.state = Some(state);
        }
        self.state
            .as_mut()
            .ok_or_else(|| CaptureError::Portal("capture session vanished after opening".into()))
    }
}

impl CaptureBackend for WaylandBackend {
    fn capture(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Capture, CaptureError>> + Send + '_>> {
        Box::pin(async move {
            let state = self.ensure_session().await?;
            let loop_error = state.shared.error.lock().clone();
            if let Some(err) = loop_error {
                // Compositor/PipeWire died: tear the session down so the next tick
                // re-establishes it (never a silent no-op).
                log::error!("capture: pipewire loop failed ({err}), resetting session");
                if let Some(dead) = self.state.take() {
                    dead.shutdown();
                }
                return Err(CaptureError::PipeWire(err));
            }

            let mut capture = Capture::default();
            let mut successes = 0usize;
            for (index, (node_id, size, position)) in state.streams.clone().into_iter().enumerate()
            {
                let last = *state.last_seq.get(&node_id).unwrap_or(&0);
                let (seq, frame) = match wait_for_frame(&state.shared, node_id, last, FRAME_WAIT) {
                    Some(entry) => entry,
                    None => {
                        log::error!(
                            "capture: stream {node_id} delivered no frame within {FRAME_WAIT:?}"
                        );
                        continue;
                    }
                };
                state.last_seq.insert(node_id, seq);
                let image = match wire_to_rgb(&frame) {
                    Ok(image) => image,
                    Err(e) => {
                        log::error!("capture: stream {node_id} frame conversion failed: {e}");
                        continue;
                    }
                };
                let (width, height) = size.unwrap_or((frame.width, frame.height));
                let [px, py] = match position {
                    Some((x, y)) => [x, y],
                    None => [0, index as i32 * height as i32],
                };
                let rect: Rect = [px, py, width as i32, height as i32];
                let restricted = state
                    .shared
                    .restricted
                    .lock()
                    .get(&node_id)
                    .copied()
                    .unwrap_or(false);
                capture.monitors.push(CapturedMonitor {
                    index: index as u32,
                    rect,
                    image,
                    restricted,
                });
                // Synthetic per-monitor app entry: Wayland compositors expose no window
                // list to non-sandboxed clients; full-frame scoring covers this.
                capture.apps.push(CapturedApp {
                    name: format!("wayland-output-{index}"),
                    window_title: String::new(),
                    app_rect: rect,
                    do_not_score: restricted,
                });
                successes += 1;
            }
            if successes == 0 {
                if let Some(dead) = self.state.take() {
                    dead.shutdown();
                }
                return Err(CaptureError::NoSource(
                    "no Wayland stream produced a usable frame".into(),
                ));
            }
            Ok(capture)
        })
    }
}

impl SessionState {
    /// Stop the PipeWire thread. The main loop quits from *this* thread (that is exactly what
    /// `pw_main_loop_quit` is for), then the join reaps the thread and drops its graph. The
    /// portal session object is dropped with the backend; the portal closes it when our D-Bus
    /// name disappears.
    fn shutdown(self) {
        if let Err(e) = self.main_loop.quit() {
            log::warn!("capture: stopping the PipeWire main loop failed: {e}");
        }
        if self.thread.join().is_err() {
            log::warn!("capture: the PipeWire loop thread panicked");
        }
    }
}

impl Drop for WaylandBackend {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.shutdown();
        }
    }
}

/// Connect the user's *session* bus (see the module docs).
///
/// The address comes from `$DBUS_SESSION_BUS_ADDRESS`, falling back to the well-known socket
/// under `$XDG_RUNTIME_DIR`; without either we cannot reach the portal at all.
async fn connect_session_bus() -> Result<zbus::Connection, CaptureError> {
    let address = match std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        Ok(address) if !address.trim().is_empty() => address,
        _ => match std::env::var("XDG_RUNTIME_DIR") {
            Ok(runtime_dir) if !runtime_dir.is_empty() => {
                format!("unix:path={runtime_dir}/bus")
            }
            _ => {
                return Err(CaptureError::Portal(
                    "no session bus address: neither DBUS_SESSION_BUS_ADDRESS nor \
                     XDG_RUNTIME_DIR is set for the captured session"
                        .into(),
                ))
            }
        },
    };
    zbus::connection::Builder::address(address.as_str())
        .map_err(|e| CaptureError::Portal(format!("session bus address {address:?}: {e}")))?
        .build()
        .await
        .map_err(|e| CaptureError::Portal(format!("session bus {address:?}: {e}")))
}

/// Establish the portal session, the PipeWire loop thread and its streams.
async fn open_session(token_path: Option<&Path>) -> Result<SessionState, CaptureError> {
    let connection = connect_session_bus().await?;
    let portal = Screencast::with_connection(connection)
        .await
        .map_err(|e| CaptureError::Portal(format!("ScreenCast portal: {e}")))?;
    let session = portal
        .create_session(Default::default())
        .await
        .map_err(|e| CaptureError::Portal(format!("create_session: {e}")))?;

    let mut options = SelectSourcesOptions::default()
        .set_sources(Some(SourceType::Monitor.into()))
        .set_cursor_mode(CursorMode::Embedded)
        .set_multiple(true);
    if let Some(path) = token_path {
        // `PersistMode` is what makes the portal *return* a restore token, so it must be set on
        // the very first run too — even though we have nothing to restore yet.
        options = options.set_persist_mode(PersistMode::ExplicitlyRevoked);
        if let Some(token) = read_restore_token(path) {
            options = options.set_restore_token(Some(token.as_str()));
        }
    }
    portal
        .select_sources(&session, options)
        .await
        .map_err(|e| CaptureError::Portal(format!("select_sources: {e}")))?;

    let response = portal
        .start(&session, None, Default::default())
        .await
        .map_err(|e| CaptureError::Portal(format!("start: {e}")))?
        .response()
        .map_err(|e| CaptureError::Portal(format!("start response: {e}")))?;
    if let Some(path) = token_path {
        match response.restore_token() {
            Some(token) => persist_restore_token(path, token),
            None => log::warn!(
                "capture: the portal returned no ScreenCast restore token, so the permission \
                 dialog will reappear in a later session"
            ),
        }
    }
    let streams = response
        .streams()
        .iter()
        .map(|stream| {
            let size = stream.size().map(|(w, h)| (w as u32, h as u32));
            (stream.pipe_wire_node_id(), size, stream.position())
        })
        .collect::<Vec<_>>();
    if streams.is_empty() {
        return Err(CaptureError::NoSource(
            "ScreenCast returned no streams (selection denied or no outputs)".into(),
        ));
    }

    let remote_fd = portal
        .open_pipe_wire_remote(&session, OpenPipeWireRemoteOptions::default())
        .await
        .map_err(|e| CaptureError::Portal(format!("open_pipe_wire_remote: {e}")))?;
    let shared = Arc::new(Shared::default());
    let (main_loop, thread) = spawn_pipewire_loop(remote_fd, streams.clone(), Arc::clone(&shared))?;

    Ok(SessionState {
        portal,
        session,
        streams,
        main_loop,
        thread,
        shared,
        last_seq: HashMap::new(),
    })
}

/// Read a previously persisted portal restore token.
///
/// Returns `None` (after logging) when the file is absent, empty or unreadable: the portal then
/// simply asks the user again, which is exactly what must happen if the user revoked the grant.
fn read_restore_token(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let token = raw.trim();
            if token.is_empty() {
                log::warn!(
                    "capture: portal restore token {} is empty; asking the portal afresh",
                    path.display()
                );
                return None;
            }
            log::info!(
                "capture: offering the saved ScreenCast permission token from {}",
                path.display()
            );
            Some(token.to_owned())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log::info!(
                "capture: no saved ScreenCast permission token yet ({})",
                path.display()
            );
            None
        }
        Err(e) => {
            log::warn!(
                "capture: cannot read the portal restore token {}: {e}",
                path.display()
            );
            None
        }
    }
}

/// Persist the portal's restore token so a later login skips the permission dialog.
///
/// Never fails the capture: an unwritable token costs the user one more dialog, which is far
/// better than losing the capture.
fn persist_restore_token(path: &Path, token: &str) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                log::warn!(
                    "capture: cannot create {} for the portal restore token: {e}",
                    parent.display()
                );
                return;
            }
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) => {
            log::warn!(
                "capture: cannot open {} for the portal restore token: {e}",
                path.display()
            );
            return;
        }
    };
    // `create` only applies the mode to a *new* file, so make 0600 authoritative either way —
    // and do it before writing, so the token is never briefly readable by others.
    if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        log::warn!(
            "capture: cannot set 0600 on the portal restore token {}: {e}",
            path.display()
        );
    }
    if let Err(e) = file.write_all(token.as_bytes()) {
        log::warn!(
            "capture: cannot write the portal restore token {}: {e}",
            path.display()
        );
    }
}

/// Spawn the PipeWire thread that builds the object graph for `remote_fd` and then runs the
/// main loop.
///
/// Blocks until the thread reports setup success or failure, so a broken PipeWire shows up as a
/// capture error instead of a silent [`FRAME_WAIT`] timeout. The thread owns everything except
/// the returned [`MainLoop`] handle, which the capture thread uses to stop it.
fn spawn_pipewire_loop(
    remote_fd: OwnedFd,
    portal_streams: Vec<PortalStream>,
    shared: Arc<Shared>,
) -> Result<(Arc<MainLoop>, JoinHandle<()>), CaptureError> {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<Arc<MainLoop>, String>>(1);
    let thread_shared = Arc::clone(&shared);
    let thread = std::thread::Builder::new()
        .name("lustless-pipewire".into())
        .spawn(move || {
            // All of the graph is built here, on the thread that will run the loop; the
            // capture thread never touches a PipeWire object (there is no channel to send one
            // over).
            let lib = match crate::pipewire_sys::load() {
                Ok(lib) => lib,
                Err(e) => {
                    setup_failed(&ready_tx, "loading libpipewire", e);
                    return;
                }
            };
            let main_loop = match MainLoop::new(&lib) {
                Ok(main_loop) => Arc::new(main_loop),
                Err(e) => {
                    setup_failed(&ready_tx, "creating the PipeWire main loop", e);
                    return;
                }
            };
            // Held (never read) for the whole loop: the binding owns the connected streams,
            // registry and core, so it must outlive `main_loop.run()` below.
            let _graph = match PipeWireGraph::connect(
                &lib,
                &main_loop,
                remote_fd,
                &portal_streams,
                Arc::clone(&thread_shared),
            ) {
                Ok(graph) => graph,
                Err(detail) => {
                    setup_failed(&ready_tx, "connecting to PipeWire", detail);
                    return;
                }
            };
            if ready_tx.send(Ok(Arc::clone(&main_loop))).is_err() {
                // The backend was dropped while we were still setting up; run nothing.
                log::info!("capture: PipeWire loop thread stopping before running (backend gone)");
                return;
            }
            if let Err(e) = main_loop.run() {
                let detail = format!("main loop: {e}");
                log::error!("capture: {detail}");
                *thread_shared.error.lock() = Some(detail);
            }
            // Locals drop in reverse declaration order here: `_graph` (streams, registry,
            // core), then the context it owns, then the main loop.
        })
        .map_err(|e| CaptureError::PipeWire(format!("spawn loop thread: {e}")))?;
    let main_loop = ready_rx
        .recv()
        .map_err(|_| CaptureError::PipeWire("pipewire loop thread exited early".into()))?
        .map_err(CaptureError::PipeWire)?;
    Ok((main_loop, thread))
}

/// Report a fatal loop-thread setup failure to the capture thread.
fn setup_failed(
    ready: &SyncSender<Result<Arc<MainLoop>, String>>,
    what: &str,
    error: impl std::fmt::Display,
) {
    let detail = format!("{what}: {error}");
    log::error!("capture: PipeWire loop setup failed ({detail})");
    // Fails only when the whole backend was dropped while we were setting up.
    let _ = ready.send(Err(detail));
}

/// Create, configure and connect one capture stream inside the loop thread.
fn connect_stream(
    lib: &Arc<PwLibrary>,
    core: &Core,
    node_id: u32,
    name: &str,
    size: (u32, u32),
    shared: Arc<Shared>,
) -> Result<StreamHandle, String> {
    let mut props = Properties::new().map_err(|e| format!("stream {node_id} properties: {e}"))?;
    props.set("media.type", "Video");
    props.set("media.category", "Capture");
    props.set("media.role", "Screen");
    let stream = Box::new(
        Stream::new(lib, core, name, &props).map_err(|e| format!("stream {node_id}: {e}"))?,
    );
    let user = Box::new(StreamUser {
        node_id,
        name: name.to_owned(),
        negotiated: None,
        stream: &*stream as *const Stream,
        shared,
        warned_memory: false,
        warned_geometry: false,
    });
    let events = StreamEvents {
        state_changed: Some(on_stream_state_changed),
        param_changed: Some(on_stream_param_changed),
        process: Some(on_stream_process),
        ..Default::default()
    };
    stream
        .add_listener(&events, &*user as *const StreamUser as *mut c_void)
        .map_err(|e| format!("stream {node_id} listener: {e}"))?;

    // Negotiate packed raw formats only: the whole frame-extraction path below depends on the
    // compositor handing us CPU-readable memory. `AUTOCONNECT` binds the stream to the
    // portal-provided node; `MAP_BUFFERS` gives us the mapped pointer in `process`.
    //
    // Deliberately *not* `PW_STREAM_FLAG_DRIVER`: a capture stream is not the graph's driver
    // (the compositor's stream is), and asking for it can leave the stream without frames.
    let pod = enum_format_pod(size);
    stream
        .connect(
            SpaDirection::Input,
            Some(node_id),
            PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
            &[pod.as_slice()],
        )
        .map_err(|e| format!("stream {node_id} connect: {e}"))?;
    Ok(StreamHandle { stream, user })
}

/// Registry `global`: remember which nodes the compositor flags as protected so their monitor
/// entry can be captured but marked `doNotScore` (§7).
unsafe extern "C" fn on_registry_global(
    data: *mut c_void,
    id: u32,
    _permissions: u32,
    type_: *const c_char,
    _version: u32,
    props: *const c_void,
) {
    if data.is_null() || type_.is_null() {
        return;
    }
    // SAFETY: `data` is the `Box<Arc<Shared>>` installed by `Core::registry`, kept alive by the
    // graph for as long as this listener exists — and boxed precisely so this cast lands on a
    // stable `Arc<Shared>` slot rather than one that moved when the graph was assembled.
    let shared = unsafe { &*(data as *const Arc<Shared>) };
    // SAFETY: the global's type is a NUL-terminated C string owned by pipewire for the duration
    // of this callback.
    let type_ = unsafe { CStr::from_ptr(type_) };
    if !is_node_type(type_) {
        return;
    }
    // SAFETY: for a node global, `props` is the node's `spa_dict` (or null, which
    // `node_is_restricted` handles).
    let restricted = unsafe { node_is_restricted(props) };
    if restricted {
        shared.restricted.lock().insert(id, true);
    }
}

/// True when a registry global's `type` string names a node.
///
/// PipeWire reports the fully qualified `PipeWire:Interface:Node` (the very string the
/// `pipewire` crate's `ObjectType` maps to `Node`); the bare `Node` form is accepted as well so
/// the check cannot silently stop matching if a producer reports the short name.
fn is_node_type(type_: &CStr) -> bool {
    let type_ = type_.to_bytes();
    type_ == NODE_TYPE || type_ == NODE_TYPE_SHORT
}

/// True when the node's properties mark it protected (`restricted`/`securityContext`), matching
/// the flags the `pipewire` crate's `Properties` used to expose.
///
/// # Safety
///
/// `props` must be null or the `const struct spa_dict *` handed to a registry `global`
/// callback, valid for the duration of the call.
unsafe fn node_is_restricted(props: *const c_void) -> bool {
    if props.is_null() {
        return false;
    }
    for key in ["restricted", "securityContext"] {
        // SAFETY: forwarded from this function's contract — `props` is a live dict and
        // `dict_get` only reads it.
        if let Some(value) = unsafe { dict_get(props, key) } {
            if value == "1" || value.eq_ignore_ascii_case("yes") {
                return true;
            }
        }
    }
    false
}

/// Stream `state_changed`: a stream that reached `PW_STREAM_STATE_ERROR` is fatal for the whole
/// session (the capture thread tears it down and rebuilds it, rather than waiting for frames
/// that can never come).
unsafe extern "C" fn on_stream_state_changed(
    data: *mut c_void,
    _old: c_int,
    state: c_int,
    error: *const c_char,
) {
    if data.is_null() || state != PW_STREAM_STATE_ERROR {
        return;
    }
    // SAFETY: `data` is the `Box<StreamUser>` installed by `Stream::add_listener`; the library
    // calls every callback for one stream on the thread that owns that box.
    let user = unsafe { &mut *(data as *mut StreamUser) };
    let detail = if error.is_null() {
        "no detail".to_owned()
    } else {
        // SAFETY: the state error string is a NUL-terminated C string owned by pipewire for the
        // duration of this callback.
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    };
    user.fail(&format!("PipeWire stream error: {detail}"));
}

/// Stream `param_changed`: the compositor is telling us the negotiated format. We only read the
/// SPA pod bytes (`pipewire_pod`); no SPA struct is parsed or built here.
unsafe extern "C" fn on_stream_param_changed(data: *mut c_void, id: u32, param: *const c_void) {
    if data.is_null() || param.is_null() {
        return;
    }
    // SAFETY: as in `on_stream_state_changed` — listener data, called from the stream's thread.
    let user = unsafe { &mut *(data as *mut StreamUser) };
    if id != pipewire_pod::SPA_PARAM_FORMAT {
        return;
    }
    // SAFETY: `param` is a live `spa_pod` owned by pipewire; it stays valid for the duration of
    // this callback, which is exactly the lifetime `pod_as_bytes` asks to be guaranteed.
    let Some(bytes) = (unsafe { pod_as_bytes(param) }) else {
        log::warn!(
            "capture: stream {} (node {}) sent an unreadable format pod",
            user.name,
            user.node_id
        );
        return;
    };
    let Some(info) = parse_video_info(bytes) else {
        log::warn!(
            "capture: stream {} (node {}) sent a format pod we cannot parse",
            user.name,
            user.node_id
        );
        return;
    };
    let Some(format) = WireFormat::from_spa(info.format) else {
        // Fatal: the session is torn down and rebuilt, exactly like any other PipeWire failure.
        // Analysing a format we cannot decode would be worse than no capture at all.
        user.fail(&format!(
            "negotiated unsupported video format 0x{:x}",
            info.format
        ));
        return;
    };
    if info.width == 0 || info.height == 0 {
        user.warn_geometry("negotiated a zero-sized frame");
        return;
    }
    user.negotiated = Some(Negotiated {
        width: info.width,
        height: info.height,
        format,
    });
}

/// Stream `process`: copy the dequeued buffer's pixels into the shared slot.
///
/// Every buffer is queued back, even when it is skipped — a consumer that keeps a buffer stalls
/// the stream forever.
unsafe extern "C" fn on_stream_process(data: *mut c_void) {
    if data.is_null() {
        return;
    }
    // SAFETY: `data` is the `Box<StreamUser>` installed by `Stream::add_listener`; this
    // callback runs on the thread that owns that box.
    let user = unsafe { &mut *(data as *mut StreamUser) };
    let Some(negotiated) = user.negotiated else {
        return;
    };
    let stream = user.stream;
    if stream.is_null() {
        return;
    }
    // SAFETY: the boxed `Stream` outlives this listener (both live in the same `StreamHandle`)
    // and is only ever used from this thread.
    let stream = unsafe { &*stream };
    let Some(buffer) = stream.dequeue_buffer() else {
        return;
    };
    // SAFETY: `buffer` was just dequeued from this stream and stays valid until it is queued
    // back below; `user` belongs to that same stream.
    let frame = unsafe { extract_frame(user, buffer, negotiated) };
    stream.queue_buffer(buffer);
    let Some(frame) = frame else {
        return;
    };
    let mut frames = user.shared.frames.lock();
    match frames.entry(user.node_id) {
        Entry::Occupied(mut slot) => {
            let slot = slot.get_mut();
            slot.seq = slot.seq.wrapping_add(1);
            slot.frame = frame;
        }
        Entry::Vacant(slot) => {
            slot.insert(FrameSlot { seq: 1, frame });
        }
    }
    drop(frames);
    user.shared.cv.notify_all();
}

/// Copy the winning plane of a dequeued PipeWire buffer into a [`WireFrame`].
///
/// Returns `None`, after logging at most once per stream, when the buffer cannot be used: a
/// memory type we cannot map (`SPA_DATA_DmaBuf` in particular), a plane that is not readable or
/// has a null `data` pointer, or chunk geometry that does not fit the mapping. A skipped frame
/// is just a skipped frame — this never panics and never tears the session down.
///
/// # Safety
///
/// `buffer` must be a buffer currently dequeued from `user`'s stream (valid until it is queued
/// back), and `user` must be the listener data pointer of that stream.
// Matched below in their verbatim C enum spellings (`pipewire_sys`), so the names stay
// greppable against `spa/buffer/buffer.h`; hence the allowance here only.
#[allow(non_upper_case_globals)]
unsafe fn extract_frame(
    user: &mut StreamUser,
    buffer: *mut PwBuffer,
    negotiated: Negotiated,
) -> Option<WireFrame> {
    // SAFETY: per this function's contract `buffer` is a live pw_buffer.
    let buffer = unsafe { &*buffer };
    let spa_buffer = buffer.buffer;
    if spa_buffer.is_null() {
        user.warn_geometry("pw_buffer carries no spa_buffer");
        return None;
    }
    // SAFETY: `buffer.buffer` points at the live spa_buffer of a dequeued buffer.
    let spa_buffer = unsafe { &*spa_buffer };
    if spa_buffer.n_datas == 0 || spa_buffer.datas.is_null() {
        user.warn_geometry("buffer has no data planes");
        return None;
    }
    // SAFETY: the first of at least one plane; we negotiate single-plane packed formats.
    let plane = unsafe { &*spa_buffer.datas };
    if !matches!(
        plane.type_,
        SPA_DATA_MemPtr | SPA_DATA_MemFd | SPA_DATA_MemId
    ) {
        user.warn_memory(plane.type_);
        return None;
    }
    // `SPA_DATA_FLAG_MAPPABLE` (`1 << 3`) only exists in 1.0.x and is deliberately not part of
    // `pipewire_sys`, so the baseline-independent readable check is what we can ask for —
    // `PW_STREAM_FLAG_MAP_BUFFERS` means PipeWire has already mapped the memory for us.
    if (plane.flags & SPA_DATA_FLAG_READABLE) == 0 {
        user.warn_geometry("data plane is not marked readable");
        return None;
    }
    if plane.data.is_null() {
        user.warn_geometry("data plane has a null pointer");
        return None;
    }
    // SAFETY: non-null chunk pointer of a dequeued buffer.
    let Some(chunk) = (unsafe { plane.chunk.as_ref() }) else {
        user.warn_geometry("data plane has no chunk");
        return None;
    };

    let channels = negotiated.format.channels();
    let Some(row_bytes) = (negotiated.width as usize).checked_mul(channels) else {
        user.warn_geometry("row length overflows");
        return None;
    };
    if row_bytes == 0 {
        user.warn_geometry("negotiated width is zero");
        return None;
    }
    if negotiated.height == 0 {
        user.warn_geometry("negotiated height is zero");
        return None;
    }
    // The bytes we may read are the chunk's window inside the mapping.
    let offset = u64::from(chunk.offset);
    let Some(window_end) = offset.checked_add(u64::from(chunk.size)) else {
        user.warn_geometry("chunk offset/size overflow");
        return None;
    };
    if window_end > u64::from(plane.maxsize) {
        user.warn_geometry("chunk window runs past the mapped region");
        return None;
    }
    // Row pitch: the chunk's stride when the compositor provides one, else the packed layout.
    // We only require that rows cannot overlap; a *padded* stride is normal, and a negative one
    // means the rows are stored bottom-up (flipped in `wire_to_rgb`).
    let stride = if chunk.stride == 0 {
        match i32::try_from(row_bytes) {
            Ok(stride) => stride,
            Err(_) => {
                user.warn_geometry("row length does not fit a stride");
                return None;
            }
        }
    } else {
        chunk.stride
    };
    let pitch = i64::from(stride).unsigned_abs();
    if pitch < row_bytes as u64 {
        user.warn_geometry("stride is shorter than one row");
        return None;
    }
    let rows = u64::from(negotiated.height);
    let Some(span_end) = rows
        .checked_sub(1)
        .and_then(|last| last.checked_mul(pitch))
        .and_then(|span| span.checked_add(row_bytes as u64))
        .and_then(|span| offset.checked_add(span))
    else {
        user.warn_geometry("row span overflows");
        return None;
    };
    if span_end > window_end {
        user.warn_geometry("rows extend past the chunk window");
        return None;
    }
    let Some(span_len) = usize::try_from(span_end - offset).ok() else {
        user.warn_geometry("row span is not addressable");
        return None;
    };

    // One contiguous copy of the whole row span, padding bytes included: `wire_to_rgb` walks it
    // with the same signed stride, so the copy keeps the buffer's exact row geometry.
    let mut data: Vec<u8> = Vec::with_capacity(span_len);
    // SAFETY: the source span starts at `plane.data + offset` and is `span_len` bytes long, and
    // we just proved `offset + span_len <= window_end <= plane.maxsize`, i.e. that the whole
    // span lies inside the mapped region. The destination is freshly reserved, so it holds
    // exactly `span_len` writable bytes; `copy_nonoverlapping` initialises all of them before
    // `set_len` makes them part of the `Vec`. `u8` needs no drop.
    unsafe {
        ptr::copy_nonoverlapping(
            (plane.data as *const u8).add(offset as usize),
            data.as_mut_ptr(),
            span_len,
        );
        data.set_len(span_len);
    }
    Some(WireFrame {
        data,
        width: negotiated.width,
        height: negotiated.height,
        stride,
        format: negotiated.format,
    })
}

/// Decode a wire frame into an RGB image.
///
/// Rows are addressed with the frame's signed stride: a padded stride is honoured (the bytes
/// between rows are ignored) and a negative stride flips the image (bottom-up rows). The
/// existing rejection of short or inconsistent buffers is kept — a frame that does not describe
/// a complete image is an error, not a panic.
fn wire_to_rgb(frame: &WireFrame) -> Result<RgbImage, String> {
    let (width, height) = (frame.width, frame.height);
    let rows = height as usize;
    let cols = width as usize;
    if rows == 0 || cols == 0 {
        return Ok(RgbImage::new(width, height));
    }
    let channels = frame.format.channels();
    let row_bytes = cols
        .checked_mul(channels)
        .ok_or_else(|| format!("row length overflows for width {width}"))?;
    let stride = if frame.stride == 0 {
        row_bytes
    } else {
        // `unsigned_abs` so that `i32::MIN` cannot overflow.
        frame.stride.unsigned_abs() as usize
    };
    if stride < row_bytes {
        return Err(format!(
            "stride {} is shorter than one row ({row_bytes} bytes for {width} px)",
            frame.stride
        ));
    }
    // The last row we touch starts at `(rows - 1) * stride` and needs `row_bytes` more.
    let needed = (rows - 1)
        .checked_mul(stride)
        .and_then(|start| start.checked_add(row_bytes))
        .ok_or_else(|| format!("frame geometry overflows ({width}x{height}, stride {stride})"))?;
    if needed > frame.data.len() {
        return Err(format!(
            "short frame (need {needed}, got {})",
            frame.data.len()
        ));
    }

    let mut image = RgbImage::new(width, height);
    for row in 0..rows {
        let mem_row = frame
            .memory_row(row)
            .ok_or_else(|| format!("row {row} out of range for height {height}"))?;
        let start = mem_row * stride;
        let end = start
            .checked_add(row_bytes)
            .ok_or_else(|| format!("row {row} end overflows"))?;
        let line = frame
            .data
            .get(start..end)
            .ok_or_else(|| format!("short frame at row {row} (need bytes {start}..{end})"))?;
        for (col, px) in line.chunks_exact(channels).enumerate() {
            let rgb = match (frame.format.is_bgr(), px) {
                (true, [b, g, r, ..]) => Rgb([*r, *g, *b]),
                (false, [r, g, b, ..]) => Rgb([*r, *g, *b]),
                // Unreachable: `chunks_exact` yields exactly `channels` bytes, which is the
                // pixel size of the format we asked for.
                _ => continue,
            };
            image.put_pixel(col as u32, row as u32, rgb);
        }
    }
    Ok(image)
}

/// Wait until `node_id` has a frame newer than `last_seq` (or any frame), or time out.
fn wait_for_frame(
    shared: &Shared,
    node_id: u32,
    last_seq: u64,
    timeout: Duration,
) -> Option<(u64, WireFrame)> {
    let mut frames = shared.frames.lock();
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(slot) = frames.get(&node_id) {
            if slot.seq > last_seq {
                return Some((slot.seq, slot.frame.clone()));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let _timed_out = shared.cv.wait_for(&mut frames, remaining);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame with a packed (unpadded, top-down) stride.
    fn packed(data: Vec<u8>, width: u32, height: u32, format: WireFormat) -> WireFrame {
        let stride = (width as usize * format.channels()) as i32;
        WireFrame {
            data,
            width,
            height,
            stride,
            format,
        }
    }

    #[test]
    fn wire_to_rgb_decodes_bgrx_and_rgb() {
        // 2x1 BGRx: [B,G,R,x] per pixel.
        let frame = packed(vec![1, 2, 3, 0, 40, 50, 60, 0], 2, 1, WireFormat::Bgrx);
        let img = wire_to_rgb(&frame).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [3, 2, 1]);
        assert_eq!(img.get_pixel(1, 0).0, [60, 50, 40]);

        let frame = packed(vec![9, 8, 7], 1, 1, WireFormat::Rgb);
        let img = wire_to_rgb(&frame).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [9, 8, 7]);
    }

    #[test]
    fn wire_to_rgb_honours_a_padded_stride() {
        // 2x2 BGRx with a 12-byte pitch: 8 bytes of pixels, 4 bytes of padding per row.
        let frame = WireFrame {
            data: vec![
                1, 2, 3, 0, 4, 5, 6, 0, 9, 9, 9, 9, // row 0
                7, 8, 9, 0, 10, 11, 12, 0, 9, 9, 9, 9, // row 1
            ],
            width: 2,
            height: 2,
            stride: 12,
            format: WireFormat::Bgrx,
        };
        let img = wire_to_rgb(&frame).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [3, 2, 1]);
        assert_eq!(img.get_pixel(1, 0).0, [6, 5, 4]);
        assert_eq!(img.get_pixel(0, 1).0, [9, 8, 7]);
        assert_eq!(img.get_pixel(1, 1).0, [12, 11, 10]);

        // A padded stride is also accepted when the trailing padding is absent.
        let frame = WireFrame {
            data: vec![1, 2, 3, 0, 9, 9, 9, 9, 4, 5, 6, 0],
            width: 1,
            height: 2,
            stride: 8,
            format: WireFormat::Bgrx,
        };
        let img = wire_to_rgb(&frame).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [3, 2, 1]);
        assert_eq!(img.get_pixel(0, 1).0, [6, 5, 4]);
    }

    #[test]
    fn wire_to_rgb_flips_rows_for_a_negative_stride() {
        // 1x2 BGR stored bottom-up: the first row in memory is the *last* image row.
        let frame = WireFrame {
            data: vec![10, 20, 30, 40, 50, 60],
            width: 1,
            height: 2,
            stride: -3,
            format: WireFormat::Bgr,
        };
        let img = wire_to_rgb(&frame).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [60, 50, 40]);
        assert_eq!(img.get_pixel(0, 1).0, [30, 20, 10]);
    }

    #[test]
    fn wire_to_rgb_rejects_short_buffers() {
        let frame = packed(vec![0u8; 7], 2, 1, WireFormat::Bgrx);
        assert!(wire_to_rgb(&frame).is_err());

        // Enough for one row but not for the second.
        let frame = packed(vec![0u8; 8], 2, 2, WireFormat::Bgrx);
        assert!(wire_to_rgb(&frame).is_err());

        // A stride that would make the rows overlap is inconsistent, not short.
        let mut overlapping = packed(vec![0u8; 16], 2, 2, WireFormat::Bgrx);
        overlapping.stride = 4;
        assert!(wire_to_rgb(&overlapping).is_err());
    }

    #[test]
    fn wire_format_maps_spa_ids() {
        assert_eq!(
            WireFormat::from_spa(SPA_VIDEO_FORMAT_BGRX),
            Some(WireFormat::Bgrx)
        );
        assert_eq!(
            WireFormat::from_spa(SPA_VIDEO_FORMAT_RGBX),
            Some(WireFormat::Rgbx)
        );
        assert_eq!(
            WireFormat::from_spa(SPA_VIDEO_FORMAT_BGRA),
            Some(WireFormat::Bgra)
        );
        assert_eq!(
            WireFormat::from_spa(SPA_VIDEO_FORMAT_RGBA),
            Some(WireFormat::Rgba)
        );
        assert_eq!(
            WireFormat::from_spa(SPA_VIDEO_FORMAT_BGR),
            Some(WireFormat::Bgr)
        );
        assert_eq!(
            WireFormat::from_spa(SPA_VIDEO_FORMAT_RGB),
            Some(WireFormat::Rgb)
        );
        // `SPA_VIDEO_FORMAT_YUY2` (0x1f) and friends are not ours.
        assert_eq!(WireFormat::from_spa(0x1f), None);
    }

    #[test]
    fn only_node_globals_are_examined() {
        let qualified = std::ffi::CString::new("PipeWire:Interface:Node").unwrap();
        let short = std::ffi::CString::new("Node").unwrap();
        let other = std::ffi::CString::new("PipeWire:Interface:Client").unwrap();
        assert!(is_node_type(&qualified));
        assert!(is_node_type(&short));
        assert!(!is_node_type(&other));

        // A null props pointer (a global without properties) must not be treated as protected.
        // SAFETY: `node_is_restricted` accepts null and reads nothing then.
        let restricted = unsafe { node_is_restricted(ptr::null()) };
        assert!(!restricted);
    }

    #[test]
    fn wait_for_frame_times_out_without_frames() {
        let shared = Shared::default();
        let started = Instant::now();
        assert!(wait_for_frame(&shared, 1, 0, Duration::from_millis(100)).is_none());
        assert!(started.elapsed() >= Duration::from_millis(90));
    }

    #[test]
    fn wait_for_frame_returns_newer_frames_only() {
        let shared = Shared::default();
        {
            let mut slots = shared.frames.lock();
            let frame = packed(vec![0u8; 4], 1, 1, WireFormat::Bgrx);
            slots.insert(7, FrameSlot { seq: 3, frame });
        }
        // seq 3 > last_seq 2 => delivered.
        assert!(wait_for_frame(&shared, 7, 2, Duration::ZERO).is_some());
        // seq 3 > last_seq 3 is false => nothing fresh.
        assert!(wait_for_frame(&shared, 7, 3, Duration::ZERO).is_none());
    }
}
