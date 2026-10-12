//! X11 capture backend (CONTRACTS §7): one PNG per RandR output via MIT-SHM
//! `ShmGetImage` (`x11rb` protocol bindings + SysV/fd shared segments), plus EWMH window
//! enumeration for the manifest `apps[]` list.
//!
//! Capture layers, tried in order (each fallback logged once):
//! 1. MIT-SHM `ShmCreateSegment` (X server ≥ 21, fd-passing segments — no permission games),
//! 2. MIT-SHM over SysV segments (`shmget`/`shmat`; permissions widened for the server's
//!    attach, the classic XShmGetImage setup — the daemon runs as root, the X server as the
//!    session user),
//! 3. plain `xproto::GetImage` over the socket (works everywhere, slower).
//!
//! Restricted-window semantics (CONTRACTS §7): X11 has no per-window "exclude from capture"
//! API, so shell/compositor surfaces (`_NET_WM_WINDOW_TYPE` dock/desktop/notification/menu
//! family) are captured but flagged `doNotScore: true` — never skipped, never aborted.

use std::fs;
use std::future::Future;
use std::os::fd::AsRawFd;
use std::pin::Pin;

use image::{Rgb, RgbImage};
use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm;
use x11rb::protocol::shm::{Seg, SegWrapper};
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ConnectionExt as _, Depth, ImageFormat, MapState, VisualClass, Visualid,
    Visualtype, Window,
};
use x11rb::rust_connection::RustConnection;

use crate::manifest::Rect;
use crate::scheduler::BackendChoice;
use crate::{Capture, CaptureBackend, CaptureError, CapturedApp, CapturedMonitor};

/// `_NET_WM_WINDOW_TYPE` values that denote shell/compositor surfaces rather than
/// scoreable application content (X11's practical analog of a restricted surface).
const DO_NOT_SCORE_WINDOW_TYPES: &[&[u8]] = &[
    b"_NET_WM_WINDOW_TYPE_DESKTOP",
    b"_NET_WM_WINDOW_TYPE_DOCK",
    b"_NET_WM_WINDOW_TYPE_NOTIFICATION",
    b"_NET_WM_WINDOW_TYPE_TOOLBAR",
    b"_NET_WM_WINDOW_TYPE_MENU",
    b"_NET_WM_WINDOW_TYPE_UTILITY",
    b"_NET_WM_WINDOW_TYPE_COMBO",
    b"_NET_WM_WINDOW_TYPE_DROPDOWN_MENU",
    b"_NET_WM_WINDOW_TYPE_POPUP_MENU",
    b"_NET_WM_WINDOW_TYPE_TOOLTIP",
];

/// How the pixels of a root-depth pixmap are laid out.
#[derive(Debug, Clone, Copy)]
struct PixelFormat {
    bits_per_pixel: u8,
    red_mask: u32,
    green_mask: u32,
    blue_mask: u32,
}

impl PixelFormat {
    /// Bytes between the starts of two scanlines (32-bit padded, per the pixmap format).
    fn stride(&self, width: u32) -> usize {
        let bits = width as usize * self.bits_per_pixel as usize;
        bits.div_ceil(32) * 4
    }

    fn bytes_per_pixel(&self) -> usize {
        (self.bits_per_pixel as usize).div_ceil(8)
    }
}

/// The X11 capture backend.
pub struct X11Backend {
    conn: RustConnection,
    screen_num: usize,
    root: Window,
    pixel_format: PixelFormat,
    /// MIT-SHM present (probed once via `ShmQueryVersion`).
    shm_ok: bool,
    /// Which shared-segment strategy works on this server.
    shm_strategy: Option<ShmStrategy>,
    fallback_logged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShmStrategy {
    /// MIT-SHM ≥ 1.2 fd segments (`ShmCreateSegment`).
    ServerSegment,
    /// Classic SysV segments (`shmget`/`shmat`).
    SysV,
}

/// A shared-memory backing for one capture: the X server writes the image straight into it.
enum ShmBacking<'a> {
    /// Server-allocated fd segment, mmapped locally.
    ServerFd {
        seg: SegWrapper<&'a RustConnection>,
        map: MappedRegion,
    },
    /// SysV segment attached both locally and server-side.
    SysV {
        seg: SegWrapper<&'a RustConnection>,
        ptr: *mut u8,
        shmid: libc::c_int,
        len: usize,
    },
}

impl<'a> ShmBacking<'a> {
    fn segment_id(&self) -> Seg {
        match self {
            ShmBacking::ServerFd { seg, .. } | ShmBacking::SysV { seg, .. } => seg.seg(),
        }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        match self {
            ShmBacking::ServerFd { map, .. } => map.as_mut_slice(),
            ShmBacking::SysV { ptr, len, .. } => unsafe {
                std::slice::from_raw_parts_mut(*ptr, *len)
            },
        }
    }
}

impl Drop for ShmBacking<'_> {
    fn drop(&mut self) {
        // `seg` (dropped first, field order) detaches the server-side X resource; then the
        // local mapping goes away and SysV segments are marked for removal.
        match self {
            ShmBacking::ServerFd { .. } => {}
            ShmBacking::SysV { ptr, shmid, .. } => unsafe {
                libc::shmdt(*ptr as *const libc::c_void);
                libc::shmctl(*shmid, libc::IPC_RMID, std::ptr::null_mut());
            },
        }
    }
}

/// A local `mmap` of the segment the X server writes into.
struct MappedRegion {
    ptr: *mut u8,
    len: usize,
}

impl MappedRegion {
    /// Map `len` bytes of `fd`. The mapping survives any later close of the fd.
    ///
    /// # Safety
    /// `fd` must be a readable/writable descriptor covering at least `len` bytes.
    unsafe fn map(fd: libc::c_int, len: usize) -> Result<Self, CaptureError> {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err(CaptureError::CaptureFailed {
                what: "MIT-SHM mmap".into(),
                reason: std::io::Error::last_os_error().to_string(),
            });
        }
        Ok(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.cast(), self.len);
        }
    }
}

// SAFETY: the mapped pointers only ever live on the capture thread that owns the backend;
// they are not shared between threads.
unsafe impl Send for MappedRegion {}
unsafe impl Send for ShmBacking<'_> {}

/// A grabbed (not yet converted) frame.
struct RawFrame {
    data: Vec<u8>,
    width: u32,
    height: u32,
}

impl X11Backend {
    /// Connect to `$DISPLAY` and probe the screen format + MIT-SHM availability.
    pub fn connect() -> Result<Self, CaptureError> {
        let (conn, screen_num) =
            x11rb::connect(None).map_err(|e| CaptureError::Connect(e.to_string()))?;
        let root = conn.setup().roots[screen_num].root;
        let pixel_format = screen_pixel_format(&conn, screen_num)
            .ok_or_else(|| CaptureError::Connect("no pixmap format for root depth".into()))?;
        let shm_ok = shm::query_version(&conn)
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .is_some();
        if !shm_ok {
            log::warn!("capture: MIT-SHM unavailable on this X server, using socket GetImage");
        }
        Ok(Self {
            conn,
            screen_num,
            root,
            pixel_format,
            shm_ok,
            shm_strategy: None,
            fallback_logged: false,
        })
    }

    /// Enumerate active outputs. RandR ≥ 1.5 `GetMonitors` first (post-rotation geometry in
    /// screen space); fall back to outputs/crtcs, then to the whole root window.
    fn list_monitors(&self) -> Result<Vec<Rect>, CaptureError> {
        if let Ok(reply) = self.conn.randr_get_monitors(self.root, true) {
            if let Ok(monitors) = reply.reply() {
                let rects: Vec<Rect> = monitors
                    .monitors
                    .iter()
                    .filter(|m| m.width > 0 && m.height > 0)
                    .map(|m| [m.x as i32, m.y as i32, m.width as i32, m.height as i32])
                    .collect();
                if !rects.is_empty() {
                    return Ok(rects);
                }
            }
        }
        // RandR 1.2–1.4: outputs with an active crtc.
        if let Ok(reply) = self.conn.randr_get_screen_resources_current(self.root) {
            if let Ok(res) = reply.reply() {
                let mut rects = Vec::new();
                for output in &res.outputs {
                    let info = match self
                        .conn
                        .randr_get_output_info(*output, res.config_timestamp)
                        .ok()
                        .and_then(|c| c.reply().ok())
                    {
                        Some(info) if info.crtc != 0 => info,
                        _ => continue,
                    };
                    let crtc = match self
                        .conn
                        .randr_get_crtc_info(info.crtc, res.config_timestamp)
                        .ok()
                        .and_then(|c| c.reply().ok())
                    {
                        Some(crtc) => crtc,
                        None => continue,
                    };
                    if crtc.width > 0 && crtc.height > 0 {
                        rects.push([
                            crtc.x as i32,
                            crtc.y as i32,
                            crtc.width as i32,
                            crtc.height as i32,
                        ]);
                    }
                }
                if !rects.is_empty() {
                    return Ok(rects);
                }
            }
        }
        // Last resort: the whole root window is one monitor.
        let screen = &self.conn.setup().roots[self.screen_num];
        Ok(vec![[
            0,
            0,
            screen.width_in_pixels as i32,
            screen.height_in_pixels as i32,
        ]])
    }

    /// Grab one rectangle of the root window, preferring MIT-SHM.
    fn grab_rect(&mut self, rect: Rect) -> Result<RawFrame, CaptureError> {
        let [x, y, width, height] = rect;
        if width <= 0 || height <= 0 {
            return Err(CaptureError::CaptureFailed {
                what: format!("rect {rect:?}"),
                reason: "non-positive size".into(),
            });
        }
        if self.shm_ok {
            match self.grab_shm(rect) {
                Ok(frame) => return Ok(frame),
                Err(e) => {
                    let first_failure = self.shm_strategy.is_none();
                    log::warn!(
                        "capture: MIT-SHM capture failed ({e}), falling back to {}",
                        if first_failure {
                            "SysV segments"
                        } else {
                            "socket GetImage"
                        }
                    );
                    self.shm_strategy = None;
                }
            }
        }
        let _ = (x, y);
        self.grab_socket(rect)
    }

    /// MIT-SHM capture: create/attach a segment, `ShmGetImage`, read out of the segment.
    fn grab_shm(&mut self, rect: Rect) -> Result<RawFrame, CaptureError> {
        let [x, y, width, height] = rect;
        let stride = self.pixel_format.stride(width as u32);
        let len = stride * height as usize;
        if len == 0 || len > (1usize << 31) {
            return Err(CaptureError::CaptureFailed {
                what: "MIT-SHM segment".into(),
                reason: format!("unreasonable segment size {len}"),
            });
        }

        let strategy = self.shm_strategy.unwrap_or(ShmStrategy::ServerSegment);
        let mut backing = match strategy {
            ShmStrategy::ServerSegment => match Self::attach_server_segment(&self.conn, len) {
                Ok(backing) => backing,
                Err(e) => {
                    log::warn!("capture: ShmCreateSegment unsupported ({e}), trying SysV segments");
                    Self::attach_sysv_segment(&self.conn, len)?
                }
            },
            ShmStrategy::SysV => Self::attach_sysv_segment(&self.conn, len)?,
        };
        self.shm_strategy = Some(match backing {
            ShmBacking::ServerFd { .. } => ShmStrategy::ServerSegment,
            ShmBacking::SysV { .. } => ShmStrategy::SysV,
        });

        let reply = shm::get_image(
            &self.conn,
            self.root,
            x as i16,
            y as i16,
            width as u16,
            height as u16,
            u32::MAX,
            ImageFormat::Z_PIXMAP.into(),
            backing.segment_id(),
            0,
        )
        .map_err(|e| shm_fail("ShmGetImage request", e))?
        .reply()
        .map_err(|e| shm_fail("ShmGetImage reply", e))?;

        if reply.depth == 0 {
            return Err(CaptureError::CaptureFailed {
                what: "ShmGetImage".into(),
                reason: "depth-0 reply".into(),
            });
        }
        let pixels = backing.bytes_mut();
        if pixels.len() < len {
            return Err(CaptureError::CaptureFailed {
                what: "ShmGetImage".into(),
                reason: format!("short segment ({} < {len})", pixels.len()),
            });
        }
        Ok(RawFrame {
            data: pixels[..len].to_vec(),
            width: width as u32,
            height: height as u32,
        })
    }

    /// Server-allocated segment (MIT-SHM 1.2 `ShmCreateSegment`): no SysV permission issues.
    fn attach_server_segment(
        conn: &RustConnection,
        len: usize,
    ) -> Result<ShmBacking<'_>, CaptureError> {
        let shmseg = conn.generate_id().map_err(|e| shm_fail("generate_id", e))?;
        let reply = shm::create_segment(conn, shmseg, len as u32, false)
            .map_err(|e| shm_fail("ShmCreateSegment request", e))?
            .reply()
            .map_err(|e| shm_fail("ShmCreateSegment reply", e))?;
        let map = unsafe { MappedRegion::map(reply.shm_fd.as_raw_fd(), len)? };
        let (seg, cookie) = SegWrapper::attach_fd_and_get_cookie(conn, reply.shm_fd, false)
            .map_err(|e| shm_fail("ShmAttach(fd)", e))?;
        cookie
            .check()
            .map_err(|e| shm_fail("ShmAttach(fd) check", e))?;
        Ok(ShmBacking::ServerFd { seg, map })
    }

    /// Classic SysV segment. The X server attaches as the session user, so the segment is
    /// briefly 0666 around the attach window and 0600 otherwise (root-owned daemon).
    fn attach_sysv_segment(
        conn: &RustConnection,
        len: usize,
    ) -> Result<ShmBacking<'_>, CaptureError> {
        let shmid = unsafe {
            libc::shmget(
                libc::IPC_PRIVATE,
                len,
                libc::IPC_CREAT | libc::IPC_EXCL | 0o600,
            )
        };
        if shmid < 0 {
            return Err(CaptureError::CaptureFailed {
                what: "shmget".into(),
                reason: std::io::Error::last_os_error().to_string(),
            });
        }
        let ptr = unsafe { libc::shmat(shmid, std::ptr::null(), 0) };
        if ptr == libc::MAP_FAILED.cast() {
            unsafe {
                libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut());
            }
            return Err(CaptureError::CaptureFailed {
                what: "shmat".into(),
                reason: std::io::Error::last_os_error().to_string(),
            });
        }
        // Widen for the server's attach, then narrow again once it succeeded.
        set_shm_mode(shmid, 0o666);
        let attached = (|| {
            let (seg, cookie) = SegWrapper::attach_and_get_cookie(conn, shmid as u32, false)
                .map_err(|e| shm_fail("ShmAttach", e))?;
            cookie.check().map_err(|e| shm_fail("ShmAttach check", e))?;
            Ok::<ShmBacking<'_>, CaptureError>(ShmBacking::SysV {
                seg,
                ptr: ptr.cast(),
                shmid,
                len,
            })
        })();
        set_shm_mode(shmid, 0o600);
        match attached {
            Ok(backing) => Ok(backing),
            Err(e) => {
                unsafe {
                    libc::shmdt(ptr as *const libc::c_void);
                    libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut());
                }
                Err(e)
            }
        }
    }

    /// Plain socket `GetImage` fallback.
    fn grab_socket(&self, rect: Rect) -> Result<RawFrame, CaptureError> {
        let [x, y, width, height] = rect;
        let reply = x11rb::protocol::xproto::get_image(
            &self.conn,
            ImageFormat::Z_PIXMAP,
            self.root,
            x as i16,
            y as i16,
            width as u16,
            height as u16,
            u32::MAX,
        )
        .map_err(|e| CaptureError::CaptureFailed {
            what: "GetImage".into(),
            reason: e.to_string(),
        })?
        .reply()
        .map_err(|e| CaptureError::CaptureFailed {
            what: "GetImage reply".into(),
            reason: e.to_string(),
        })?;
        if reply.depth == 0 {
            return Err(CaptureError::CaptureFailed {
                what: "GetImage".into(),
                reason: "depth-0 reply".into(),
            });
        }
        Ok(RawFrame {
            data: reply.data,
            width: width as u32,
            height: height as u32,
        })
    }

    /// EWMH window list → manifest `apps[]` entries (geometry in root coordinates).
    fn list_windows(&self) -> Vec<CapturedApp> {
        let mut apps = Vec::new();
        let Ok(list_atom) = self.conn.intern_atom(false, b"_NET_CLIENT_LIST") else {
            return apps;
        };
        let Ok(list_atom) = list_atom.reply() else {
            return apps;
        };
        let Ok(prop) = self.conn.get_property(
            false,
            self.root,
            list_atom.atom,
            AtomEnum::WINDOW,
            0,
            u32::MAX,
        ) else {
            return apps;
        };
        let Ok(prop) = prop.reply() else {
            return apps;
        };
        let Some(windows) = prop.value32() else {
            return apps;
        };
        for window in windows {
            if let Some(app) = self.window_entry(window) {
                apps.push(app);
            }
        }
        apps
    }

    fn window_entry(&self, window: Window) -> Option<CapturedApp> {
        let attrs = self.conn.get_window_attributes(window).ok()?.reply().ok()?;
        if attrs.map_state != MapState::VIEWABLE {
            return None;
        }
        let (x, y, width, height) = self.window_geometry(window)?;
        if width == 0 || height == 0 {
            return None;
        }
        let types = self.window_property_atoms(window, b"_NET_WM_WINDOW_TYPE");
        let do_not_score = types
            .iter()
            .any(|atom| self.atom_in_set(*atom, DO_NOT_SCORE_WINDOW_TYPES));
        Some(CapturedApp {
            name: self.window_app_name(window),
            window_title: self.window_title(window),
            app_rect: [x, y, width, height],
            do_not_score,
        })
    }

    /// Window position translated into root coordinates plus its size.
    fn window_geometry(&self, window: Window) -> Option<(i32, i32, i32, i32)> {
        let geom = self.conn.get_geometry(window).ok()?.reply().ok()?;
        // XTranslateCoordinates into the root window yields root-space coordinates directly.
        let translated = self
            .conn
            .translate_coordinates(window, self.root, 0, 0)
            .ok()?
            .reply()
            .ok()?;
        Some((
            translated.dst_x as i32,
            translated.dst_y as i32,
            geom.width as i32,
            geom.height as i32,
        ))
    }

    fn window_title(&self, window: Window) -> String {
        if let Ok(utf8) = self.conn.intern_atom(false, b"UTF8_STRING") {
            if let Ok(atom) = utf8.reply() {
                if let Ok(prop) = self.conn.get_property(
                    false,
                    window,
                    self.intern(b"_NET_WM_NAME"),
                    atom.atom,
                    0,
                    1024,
                ) {
                    if let Ok(reply) = prop.reply() {
                        if !reply.value.is_empty() {
                            return String::from_utf8_lossy(&reply.value).into_owned();
                        }
                    }
                }
            }
        }
        if let Ok(prop) = self.conn.get_property(
            false,
            window,
            self.intern(b"WM_NAME"),
            AtomEnum::STRING,
            0,
            1024,
        ) {
            if let Ok(reply) = prop.reply() {
                if !reply.value.is_empty() {
                    return String::from_utf8_lossy(&reply.value).into_owned();
                }
            }
        }
        String::new()
    }

    fn window_app_name(&self, window: Window) -> String {
        // WM_CLASS instance/name: the most stable app identity on X11 (NUL-separated,
        // last component is the class name).
        if let Ok(prop) = self.conn.get_property(
            false,
            window,
            self.intern(b"WM_CLASS"),
            AtomEnum::STRING,
            0,
            1024,
        ) {
            if let Ok(reply) = prop.reply() {
                if let Some(class) = reply.value.split(|b| *b == 0).rfind(|s| !s.is_empty()) {
                    if !class.is_empty() {
                        return String::from_utf8_lossy(class).into_owned();
                    }
                }
            }
        }
        if let Some(pid) = self.window_pid(window) {
            if let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) {
                let trimmed = comm.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
        "unknown".to_string()
    }

    fn window_pid(&self, window: Window) -> Option<u32> {
        let prop = self
            .conn
            .get_property(
                false,
                window,
                self.intern(b"_NET_WM_PID"),
                AtomEnum::CARDINAL,
                0,
                1,
            )
            .ok()?
            .reply()
            .ok()?;
        let next = prop.value32()?.next();
        next
    }

    fn window_property_atoms(&self, window: Window, name: &[u8]) -> Vec<Atom> {
        let prop = match self
            .conn
            .get_property(false, window, self.intern(name), AtomEnum::ATOM, 0, 64)
            .ok()
            .and_then(|c| c.reply().ok())
        {
            Some(prop) => prop,
            None => return Vec::new(),
        };
        prop.value32().map(|v| v.collect()).unwrap_or_default()
    }

    fn atom_in_set(&self, atom: Atom, names: &[&[u8]]) -> bool {
        names.iter().any(|name| self.intern(name) == atom)
    }

    fn intern(&self, name: &[u8]) -> Atom {
        self.conn
            .intern_atom(false, name)
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .map(|reply| reply.atom)
            .unwrap_or(0)
    }
}

impl CaptureBackend for X11Backend {
    fn capture(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Capture, CaptureError>> + Send + '_>> {
        Box::pin(async move {
            let rects = self.list_monitors()?;
            let mut capture = Capture::default();
            let mut successes = 0usize;
            for (index, rect) in rects.into_iter().enumerate() {
                match self.grab_rect(rect) {
                    Ok(frame) => {
                        match convert_to_rgb(
                            &frame.data,
                            frame.width,
                            frame.height,
                            self.pixel_format,
                        ) {
                            Ok(image) => {
                                capture.monitors.push(CapturedMonitor {
                                    index: index as u32,
                                    rect,
                                    image,
                                    restricted: false,
                                });
                                successes += 1;
                            }
                            Err(e) => log::error!(
                                "capture: pixel conversion failed for monitor {index}: {e}"
                            ),
                        }
                    }
                    Err(e) => log::error!("capture: monitor {index} capture failed: {e}"),
                }
            }
            if successes == 0 {
                return Err(CaptureError::NoSource(
                    "no monitor could be captured".into(),
                ));
            }
            capture.apps = self.list_windows();
            if capture.apps.is_empty() && !self.fallback_logged {
                self.fallback_logged = true;
                log::warn!(
                    "capture: no EWMH client list on this display; manifest apps[] is empty \
                     (classifier falls back to full-frame scoring)"
                );
            }
            Ok(capture)
        })
    }
}

fn shm_fail(step: &str, e: impl std::fmt::Display) -> CaptureError {
    CaptureError::CaptureFailed {
        what: format!("MIT-SHM {step}"),
        reason: e.to_string(),
    }
}

fn set_shm_mode(shmid: libc::c_int, mode: libc::mode_t) {
    let mut ds: libc::shmid_ds = unsafe { std::mem::zeroed() };
    if unsafe { libc::shmctl(shmid, libc::IPC_STAT, &mut ds) } == 0 {
        // `shm_perm.mode` is c_ushort on glibc and c_uint on musl — widen to
        // u32 for the arithmetic, then narrow back to the field's per-libc
        // type (PACKAGING-MATRIX §1).
        let cur = u32::from(ds.shm_perm.mode);
        if let Ok(mode) = ((cur & !0o777) | u32::from(mode)).try_into() {
            ds.shm_perm.mode = mode;
        }
        unsafe {
            libc::shmctl(shmid, libc::IPC_SET, &mut ds);
        }
    }
}

/// The screen's pixmap format + root visual channel masks.
fn screen_pixel_format(conn: &RustConnection, screen_num: usize) -> Option<PixelFormat> {
    let screen = conn.setup().roots.get(screen_num)?;
    let format = conn
        .setup()
        .pixmap_formats
        .iter()
        .find(|f| f.depth == screen.root_depth)?;
    let visual = find_visual(&screen.allowed_depths, screen.root_visual)?;
    Some(PixelFormat {
        bits_per_pixel: format.bits_per_pixel,
        red_mask: visual.red_mask,
        green_mask: visual.green_mask,
        blue_mask: visual.blue_mask,
    })
}

fn find_visual(depths: &[Depth], visual_id: Visualid) -> Option<&Visualtype> {
    depths
        .iter()
        .flat_map(|depth| depth.visuals.iter())
        .find(|visual| {
            visual.visual_id == visual_id
                && (visual.class == VisualClass::TRUE_COLOR
                    || visual.class == VisualClass::DIRECT_COLOR)
        })
}

/// Convert raw X11 scanlines (ZPixmap, 32-bit padded) into an RGB image using the visual's
/// channel masks — correct for both RGBA- and BGRA-ordered servers.
fn convert_to_rgb(
    data: &[u8],
    width: u32,
    height: u32,
    format: PixelFormat,
) -> Result<RgbImage, CaptureError> {
    let stride = format.stride(width);
    let bpp = format.bytes_per_pixel();
    let total = stride
        .checked_mul(height as usize)
        .filter(|total| *total <= data.len())
        .ok_or_else(|| CaptureError::CaptureFailed {
            what: "pixel conversion".into(),
            reason: format!("need {stride}x{height} bytes, got {}", data.len()),
        })?;
    let _ = total;
    let mut image = RgbImage::new(width, height);
    for row in 0..height as usize {
        let line = &data[row * stride..];
        for col in 0..width as usize {
            let mut px = 0u32;
            for byte in 0..bpp {
                px |= (line[col * bpp + byte] as u32) << (8 * byte);
            }
            image.put_pixel(
                col as u32,
                row as u32,
                Rgb([
                    apply_mask(px, format.red_mask),
                    apply_mask(px, format.green_mask),
                    apply_mask(px, format.blue_mask),
                ]),
            );
        }
    }
    Ok(image)
}

fn apply_mask(px: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let max = (mask >> shift) as u64;
    let value = ((px & mask) >> shift) as u64;
    ((value * 255 + max / 2) / max) as u8
}

/// Open the backend selected by the config value and the session type
/// (`XDG_SESSION_TYPE`), per CONTRACTS §7.
pub fn open(
    choice: BackendChoice,
    session_type: Option<&str>,
) -> Result<Box<dyn CaptureBackend>, CaptureError> {
    match crate::resolve_backend(choice, session_type) {
        BackendChoice::X11 => Ok(Box::new(X11Backend::connect()?)),
        BackendChoice::Wayland => {
            #[cfg(feature = "wayland-portal")]
            {
                Ok(Box::new(crate::wayland::WaylandBackend::new()?))
            }
            #[cfg(not(feature = "wayland-portal"))]
            {
                log::warn!(
                    "capture: this build has no Wayland portal backend (built against \
                     the pipewire-0.3 base); falling back to X11/XWayland root capture \
                     — reduced coverage on Wayland-native windows"
                );
                Ok(Box::new(X11Backend::connect()?))
            }
        }
        BackendChoice::Auto => unreachable!("resolve_backend never returns Auto"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_mask_scales_channels_to_full_range() {
        // Classic 0x00RRGGBB layout.
        let px = 0x00AABBCCu32;
        assert_eq!(apply_mask(px, 0x00FF0000), 0xAA);
        assert_eq!(apply_mask(px, 0x0000FF00), 0xBB);
        assert_eq!(apply_mask(px, 0x000000FF), 0xCC);
        // 5-6-5 style masks: the channel max must reach 255, and small values round.
        assert_eq!(apply_mask(0b1111_1000_0001_0000, 0xF800), 255);
        assert_eq!(apply_mask(0b0000_1000_0000_0001, 0x001F), 8);
    }

    #[test]
    fn convert_handles_bgra_and_rgba_orders() {
        let bgra = [10u8, 20, 30, 255, 40, 50, 60, 255];
        let fmt = PixelFormat {
            bits_per_pixel: 32,
            red_mask: 0x00FF_0000,
            green_mask: 0x0000_FF00,
            blue_mask: 0x0000_00FF,
        };
        let img = convert_to_rgb(&bgra, 2, 1, fmt).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [30, 20, 10]);
        assert_eq!(img.get_pixel(1, 0).0, [60, 50, 40]);

        let rgba = [10u8, 20, 30, 255, 40, 50, 60, 255];
        let fmt = PixelFormat {
            bits_per_pixel: 32,
            red_mask: 0x0000_00FF,
            green_mask: 0x0000_FF00,
            blue_mask: 0x00FF_0000,
        };
        let img = convert_to_rgb(&rgba, 2, 1, fmt).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [10, 20, 30]);
        assert_eq!(img.get_pixel(1, 0).0, [40, 50, 60]);
    }

    #[test]
    fn convert_pads_24bpp_scanlines() {
        // One pixel of 24bpp (blue,green,red byte order under these masks — same layout as
        // the BGRA case above), scanline padded to 4 bytes.
        let data = [7u8, 8, 9, 0];
        let fmt = PixelFormat {
            bits_per_pixel: 24,
            red_mask: 0xFF0000,
            green_mask: 0x00FF00,
            blue_mask: 0x0000FF,
        };
        let img = convert_to_rgb(&data, 1, 1, fmt).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [9, 8, 7]);
    }

    #[test]
    fn convert_rejects_truncated_buffers() {
        let fmt = PixelFormat {
            bits_per_pixel: 32,
            red_mask: 0xFF0000,
            green_mask: 0xFF00,
            blue_mask: 0xFF,
        };
        assert!(convert_to_rgb(&[0u8; 4], 2, 1, fmt).is_err());
    }
}
