//! Integration test: prove `pipewire_sys` (and its companion `pipewire_pod`) is a faithful
//! transcription of the real libpipewire ABI — **without** a compositor, a portal or a live
//! PipeWire.
//!
//! The trick is [`tests/fixtures/fake_pipewire.c`]: a self-contained stand-in for
//! `libpipewire-0.3.so.0` whose structs, vtables and function signatures are transcribed from
//! the real 0.3.48 headers. This test compiles it at runtime into a temporary directory under
//! the runtime soname `libpipewire-0.3.so.0` and loads *that* file with
//! [`pipewire_sys::load_named`], so the whole FFI layer is exercised against a library we can
//! observe from both sides.
//!
//! This drives the **RAII wrappers end to end**, exactly as the production backend does:
//! `MainLoop`/`Context`/`Core` create and connect; `Core::registry` dispatches
//! `pw_core_methods::get_registry` (byte offset 48) and `pw_registry_methods::add_listener`
//! (byte offset 8) through the real `spa_interface` vtable; `Properties::new_with` +
//! `Stream::new` hand the property object over with correct ownership; `Stream::add_listener`
//! keeps the `spa_hook` and a *copy* of the events table alive for the listener's lifetime;
//! `Stream::connect` marshals the direction/target/flags and the pod pointer array; and the
//! `process` callback dequeues and re-queues the buffer through the wrapper. So the test covers
//! hook lifetime, events-table copying, flag/param marshalling and buffer queueing — not just
//! the raw symbols.
//!
//! What else it pins down:
//!
//! * `PwLibrary::load_named` resolves every symbol and `PwLibrary::version()` reads the C
//!   `pw_get_library_version` sentinel.
//! * `Stream::connect`'s `enum_format_pod` bytes survive the C boundary intact (the stub
//!   parses the pod header/object type itself and copies the bytes back out).
//! * The `param_changed` callback receives a real format pod built by hand in C; the bytes are
//!   read with `pipewire_sys::pod_as_bytes` and parsed by `pipewire_pod::parse_video_info`.
//! * The `process` callback reads a real `pw_buffer` → `spa_buffer` → `spa_data` → `spa_chunk`
//!   chain, including the deliberately **non-packed** stride, and reconstructs the frame.
//! * The registry `global` callback fires for the fake Node and its `restricted` property is
//!   read through `pipewire_sys::dict_get`, proving the real `spa_dict` layout (with its
//!   leading `flags` word).
//!
//! Determinism: one unique `TempDir`, no network, no shared state. If no C compiler is found
//! the test prints `skipping: no cc` and returns without failing the suite.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use lustless_capture::pipewire_pod::{self, VideoFormatInfo, SPA_VIDEO_FORMAT_BGRX};
use lustless_capture::pipewire_sys::{
    self, Context, MainLoop, Properties, PwBuffer, PwLibrary, RegistryEvents, SPA_DATA_MemPtr,
    SpaDirection, Stream, StreamEvents, PW_STREAM_FLAG_AUTOCONNECT, PW_STREAM_FLAG_MAP_BUFFERS,
    SPA_DATA_FLAG_READABLE,
};

/// Facts the fake library published that the callbacks below record for the test thread.
struct Shared {
    /// The wrapper-owned stream, used by `on_process` to dequeue/queue through the RAII layer.
    /// `Mutex` because the loop-thread callback touches it while the test thread waits.
    stream: Mutex<Stream>,
    /// Format parsed from the `param_changed` pod.
    param: Mutex<Option<VideoFormatInfo>>,
    /// Frame reconstructed from the `process` buffer.
    frame: Mutex<Option<CapturedFrame>>,
    /// Registry `global` observation.
    restricted: Mutex<Option<Restricted>>,
    /// Signalled once `process` has finished reading the buffer.
    process_tx: mpsc::Sender<()>,
}

/// A frame reconstructed row-by-row honouring `spa_chunk::stride`.
struct CapturedFrame {
    width: u32,
    height: u32,
    stride: usize,
    /// `height * width * 4` tightly packed bytes (no row padding).
    pixels: Vec<u8>,
    /// First byte of row 0's padding — distinct from the image, so it proves `stride` was used.
    pad_byte: u8,
}

/// One registry `global` observation.
struct Restricted {
    id: u32,
    iface_type: String,
    restricted: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// C callbacks (invoked from the fake library's loop thread).
// ---------------------------------------------------------------------------------------------

/// `pw_stream_events::param_changed`.
///
/// # Safety
///
/// Called by the fake library with `data` = the leaked `*mut Shared` and `param` = a live
/// `spa_pod` owned by the library for the duration of the call.
unsafe extern "C" fn on_param_changed(data: *mut c_void, _id: u32, param: *const c_void) {
    // SAFETY: `data` is the `*const Shared` the test leaked into the listener.
    let shared = unsafe { &*(data as *const Shared) };
    // SAFETY: `param` is a `spa_pod` valid for this call; we only borrow it here.
    let bytes = unsafe { pipewire_sys::pod_as_bytes(param) }.unwrap_or_default();
    *shared.param.lock().unwrap_or_else(|e| e.into_inner()) = pipewire_pod::parse_video_info(bytes);
}

/// `pw_stream_events::process`.
///
/// # Safety
///
/// `data` is the same `*mut Shared` passed to `Stream::add_listener`.
unsafe extern "C" fn on_process(data: *mut c_void) {
    // SAFETY: `data` is the `*const Shared` the test leaked into the listener.
    let shared = unsafe { &*(data as *const Shared) };
    let dims = {
        let guard = shared.param.lock().unwrap_or_else(|e| e.into_inner());
        (*guard).map(|info| (info.width, info.height))
    };
    if let Some((width, height)) = dims {
        // `Stream` is only `Send`, so the shared stream is behind a `Mutex`; the loop thread is
        // the only one inside this callback, and the test thread is blocked on the channel.
        let stream = shared.stream.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(buffer) = stream.dequeue_buffer() {
            // SAFETY: `buffer` was just dequeued from the live stream.
            if let Some(frame) = unsafe { read_frame(buffer, width, height) } {
                *shared.frame.lock().unwrap_or_else(|e| e.into_inner()) = Some(frame);
            }
            stream.queue_buffer(buffer);
        }
    }
    let _ = shared.process_tx.send(());
}

/// `pw_registry_events::global`.
///
/// # Safety
///
/// `data` is the `*mut Shared` passed to `Core::registry`; `iface_type`/`props` are valid for
/// the duration of the call.
unsafe extern "C" fn on_global(
    data: *mut c_void,
    id: u32,
    _permissions: u32,
    iface_type: *const c_char,
    _version: u32,
    props: *const c_void,
) {
    // SAFETY: `data` is the `*const Shared` the test handed to the registry.
    let shared = unsafe { &*(data as *const Shared) };
    let iface_type = if iface_type.is_null() {
        String::new()
    } else {
        // SAFETY: the library passes a NUL-terminated interface name.
        unsafe { CStr::from_ptr(iface_type) }
            .to_string_lossy()
            .into_owned()
    };
    // SAFETY: `props` is a valid `spa_dict` for the duration of the call; `dict_get` proves
    // the real layout (leading `flags` word) rather than a test-local mirror.
    let restricted = unsafe { pipewire_sys::dict_get(props, "restricted") }.map(str::to_owned);
    *shared.restricted.lock().unwrap_or_else(|e| e.into_inner()) = Some(Restricted {
        id,
        iface_type,
        restricted,
    });
}

/// Read one dequeued `pw_buffer` into a tightly packed image, using `spa_chunk::stride`.
///
/// # Safety
///
/// `buffer` must be non-null and point at a live `pw_buffer` whose `buffer` field is a live
/// `spa_buffer` with at least one data plane (the fake guarantees exactly one `MemPtr` plane).
unsafe fn read_frame(buffer: *mut PwBuffer, width: u32, height: u32) -> Option<CapturedFrame> {
    // SAFETY: caller guarantees `buffer` is live; we only read its first field.
    let pw_buffer = unsafe { &*buffer };
    if pw_buffer.buffer.is_null() {
        return None;
    }
    // SAFETY: `buffer` field points at the stream's live spa_buffer.
    let spa = unsafe { &*pw_buffer.buffer };
    if spa.n_datas == 0 || spa.datas.is_null() {
        return None;
    }
    // SAFETY: `n_datas >= 1`, so the first plane is valid.
    let plane = unsafe { &*spa.datas };
    if plane.type_ != SPA_DATA_MemPtr || plane.flags & SPA_DATA_FLAG_READABLE == 0 {
        return None;
    }
    if plane.data.is_null() || plane.chunk.is_null() {
        return None;
    }
    // SAFETY: the plane carries a valid chunk pointer.
    let chunk = unsafe { &*plane.chunk };

    let stride = chunk.stride;
    if stride <= 0 {
        return None;
    }
    let stride = stride as usize;
    let row_bytes = width as usize * 4;
    if stride < row_bytes || height == 0 {
        return None;
    }
    let maxsize = plane.maxsize as usize;
    let offset = chunk.offset as usize;
    // Reject a plane we cannot fully read (defensive: never index past the mapping).
    if offset
        .checked_add((height as usize - 1) * stride)?
        .checked_add(row_bytes)?
        > maxsize
    {
        return None;
    }

    // SAFETY: `data` points at `maxsize` readable bytes; every row is inside that range.
    let base = unsafe { (plane.data as *const u8).add(offset) };
    let mut pixels = vec![0u8; height as usize * row_bytes];
    for y in 0..height as usize {
        // SAFETY: bounds checked above; `pixels` is a distinct allocation.
        unsafe {
            let src = base.add(y * stride);
            ptr::copy_nonoverlapping(src, pixels.as_mut_ptr().add(y * row_bytes), row_bytes);
        }
    }
    // SAFETY: stride > row_bytes (the fake never packs rows), and the row is in range.
    let pad_byte = unsafe { *base.add(row_bytes) };
    Some(CapturedFrame {
        width,
        height,
        stride,
        pixels,
        pad_byte,
    })
}

// ---------------------------------------------------------------------------------------------
// Fixture build + symbol lookup.
// ---------------------------------------------------------------------------------------------

/// Compile `fixtures/fake_pipewire.c` into a temp dir under the runtime soname.
///
/// Returns `None` (printing a greppable skip line) when no C compiler is available, so the
/// suite stays green on machines without one. Any *found* compiler that fails to build is a
/// hard test failure.
fn build_fake_library() -> Option<(tempfile::TempDir, PathBuf)> {
    let compiler = ["cc", "gcc", "clang"].into_iter().find(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    });
    let Some(cc) = compiler else {
        eprintln!("skipping: no cc");
        return None;
    };

    let dir = tempfile::Builder::new()
        .prefix("lustless-fake-pipewire-")
        .tempdir()
        .expect("create temp dir");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fake_pipewire.c");
    let out = dir.path().join("libpipewire-0.3.so.0");

    let output = Command::new(cc)
        .arg("-shared")
        .arg("-fPIC")
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&source)
        .output()
        .expect("spawn C compiler");
    assert!(
        output.status.success(),
        "compiling fake_pipewire.c with {cc} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some((dir, out))
}

/// Resolve a symbol exported by the fake library through the [`PwLibrary`] handle.
///
/// # Safety
///
/// `T` must be the exact function-pointer type of the C symbol `name`.
unsafe fn export<T: Copy>(lib: &PwLibrary, name: &str) -> T {
    let cname = CString::new(name).expect("symbol name must not contain NUL");
    // SAFETY: `lib.handle` is the live dlopen handle kept for the process lifetime and `cname`
    // is NUL-terminated.
    let ptr = unsafe { libc::dlsym(lib.handle, cname.as_ptr()) };
    assert!(
        !ptr.is_null(),
        "fake library is missing the symbol {name:?}"
    );
    // SAFETY: the caller guarantees `T` is the symbol's exact function-pointer type, and every
    // function pointer has the same size as `*mut c_void`.
    unsafe { std::mem::transmute_copy::<*mut c_void, T>(&ptr) }
}

// ---------------------------------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------------------------------

#[test]
fn ffi_boundary_is_faithful_to_libpipewire_abi() {
    let Some((_fixture_dir, library_path)) = build_fake_library() else {
        return;
    };
    let soname = library_path
        .to_str()
        .expect("temp path must be valid UTF-8");

    let lib = pipewire_sys::load_named(soname).expect("load the fake libpipewire");

    // (1) The happy path resolves and reads the C-side version sentinel.
    assert_eq!(lib.version(), "fake-0.3.48");

    // (2) MainLoop / Context / Core wrappers drive the fake objects.
    let mainloop = Arc::new(MainLoop::new(&lib).expect("pw_main_loop_new"));
    let context = Context::new(&lib, &mainloop).expect("pw_context_new");
    let (sock, _peer) = UnixStream::pair().expect("socketpair for connect_fd");
    let fd: OwnedFd = sock.into();
    let core = context.connect_fd(fd).expect("pw_context_connect_fd");

    // (3) The RAII stream layer: `Properties::new_with` against the stub library, then
    // `Stream::new` which takes ownership of the property object.
    let props = Properties::new_with(&lib).expect("pw_properties_new_string");
    let stream = Stream::new(&lib, &core, "lustless-capture-fake", &props).expect("pw_stream_new");

    let (process_tx, process_rx) = mpsc::channel();
    let shared = Box::new(Shared {
        stream: Mutex::new(stream),
        param: Mutex::new(None),
        frame: Mutex::new(None),
        restricted: Mutex::new(None),
        process_tx,
    });
    let shared_ptr = (&*shared) as *const Shared as *mut c_void;

    // (4) Registry: `Core::registry` dispatches get_registry (vtable offset 48) and
    // add_listener (offset 8). The fake emits one Node global with `restricted=1`.
    let registry_events = RegistryEvents {
        global: Some(on_global),
        ..Default::default()
    };
    let registry = core
        .registry(registry_events, shared_ptr)
        .expect("pw_core_get_registry + pw_registry_add_listener");

    // (5) `Stream::add_listener` owns the hook + a copy of the events table; `Stream::connect`
    // marshals direction/target/flags and the pod pointer array.
    let events = StreamEvents {
        param_changed: Some(on_param_changed),
        process: Some(on_process),
        ..Default::default()
    };
    let pod = pipewire_pod::enum_format_pod((64, 48));
    {
        let stream = shared.stream.lock().unwrap_or_else(|e| e.into_inner());
        stream
            .add_listener(&events, shared_ptr)
            .expect("pw_stream_add_listener");
        stream
            .connect(
                SpaDirection::Input,
                Some(42),
                PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
                &[pod.as_slice()],
            )
            .expect("pw_stream_connect");
    }

    // The C stub validates the pod itself and copies the bytes out, closing the loop on
    // `enum_format_pod`.
    let params_ok: unsafe extern "C" fn() -> c_int = unsafe { export(&lib, "fake_pw_params_ok") };
    let params_size: unsafe extern "C" fn() -> c_int =
        unsafe { export(&lib, "fake_pw_params_size") };
    let params_data: unsafe extern "C" fn() -> *const u8 =
        unsafe { export(&lib, "fake_pw_params_data") };
    // SAFETY: plain C getters with no preconditions.
    assert_eq!(
        unsafe { params_ok() },
        1,
        "the C stub rejected the EnumFormat pod"
    );
    let copied_size = unsafe { params_size() } as usize;
    assert_eq!(
        copied_size,
        pod.len(),
        "pod length changed across the boundary"
    );
    // SAFETY: `params_data()` points at `params_size()` bytes copied by the stub.
    let copied = unsafe { std::slice::from_raw_parts(params_data(), copied_size) };
    assert_eq!(
        copied,
        pod.as_slice(),
        "pod bytes differ across the boundary"
    );

    // (6) Run the loop on a worker thread; `run` fires param_changed then process, then blocks
    // until quit.
    let runner = {
        let mainloop = Arc::clone(&mainloop);
        thread::spawn(move || mainloop.run())
    };
    process_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("process callback never fired");
    mainloop.quit().expect("pw_main_loop_quit");
    let run_result = runner
        .join()
        .unwrap_or_else(|_| panic!("pipewire loop thread panicked"));
    run_result.expect("pw_main_loop_run failed");

    // (7) param_changed delivered a pod the sibling codec parses exactly.
    let info = {
        let guard = shared.param.lock().unwrap_or_else(|e| e.into_inner());
        (*guard).expect("param_changed pod did not parse")
    };
    assert_eq!(
        info,
        VideoFormatInfo {
            format: SPA_VIDEO_FORMAT_BGRX,
            width: 64,
            height: 48,
        }
    );

    // (8) process read the buffer with the padded stride and reconstructed the frame.
    let frame = shared
        .frame
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .expect("process callback captured no frame");
    assert_eq!((frame.width, frame.height), (64, 48));
    assert_eq!(frame.stride, 320, "expected the fake's non-packed stride");
    assert_eq!(frame.pad_byte, 0xee, "reader ignored chunk.stride");
    // Spot-check the pattern the stub published: pixel (x, y) = (x, y, 0x80, 0).
    for &(x, y) in &[(0usize, 0usize), (5, 7), (63, 47)] {
        let i = (y * 64 + x) * 4;
        assert_eq!(
            &frame.pixels[i..i + 4],
            &[x as u8, y as u8, 0x80, 0x00],
            "pixel ({x}, {y})"
        );
    }
    assert_eq!(frame.pixels.len(), 64 * 48 * 4);

    // (9) The registry global fired for the fake Node with its `restricted` property, read
    // through `pipewire_sys::dict_get` against the stub's real `spa_dict`.
    let restricted = shared
        .restricted
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .expect("registry global callback did not fire");
    assert_eq!(restricted.id, 42);
    assert!(
        restricted.iface_type.contains("Node"),
        "unexpected interface type: {}",
        restricted.iface_type
    );
    assert_eq!(
        restricted.restricted.as_deref(),
        Some("1"),
        "restricted property missing from the global's spa_dict"
    );

    // Teardown (declaration order drops registry before core and core before context; the
    // stream's listener boxes are freed by `Stream`'s own `Drop`).
    let stream = shared.stream.lock().unwrap_or_else(|e| e.into_inner());
    stream.disconnect();
    drop(stream);
    drop(registry);
    core.disconnect();
}
