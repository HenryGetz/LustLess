//! Version-tolerant FFI shim over PipeWire (`libpipewire-0.3.so.0`) for the Wayland capture
//! backend (docs/impl/CONTRACTS.md §7).
//!
//! ## Why this module exists
//!
//! The maintained `pipewire` Rust crate (pipewire 0.10.1 + `libspa-sys` bindgen) is generated
//! against pipewire **1.x** headers and cannot even be *compiled* against the 0.3.48 headers
//! shipped by Zorin OS 17 / Ubuntu 22.04: `libspa` needs `spa_meta_first`/
//! `spa_meta_region_is_valid` and `spa_video_info_raw.flags`, none of which exist in 0.3.48.
//! Worse, `struct spa_video_info_raw` genuinely **changed layout** between 0.3.48 and 1.0.x
//! (1.x inserted a `uint32_t flags` after `format` and widened `modifier` to `uint64`), so no
//! single linked build can be correct on both baselines.
//!
//! So we link nothing at build time: we `dlopen` the runtime library by its **stable soname**
//! `libpipewire-0.3.so.0` (identical in 0.3.48 and 1.0.x) and resolve the handful of exported
//! functions we need with `dlsym`. This works on the whole supported matrix
//! (Zorin 17 / Ubuntu 22.04 = pipewire 0.3.48; Ubuntu 24.04 / Fedora 44 = pipewire 1.0.x).
//!
//! ## The one rule that makes this safe
//!
//! **No SPA struct is ever passed across the FFI boundary by pointer, except raw spa *pod*
//! byte buffers.** Pods are self-describing byte streams (built/parsed by the sibling
//! `pipewire_pod` module, applied only with `pw_stream_connect`/`pw_stream_update_params`),
//! so their layout is a wire format we own; every other SPA type stays on the far side of the
//! call. We never embed an SPA struct we could get wrong.
//!
//! The `#[repr(C)]` structs defined below are *not* SPA negotiation types — they are the
//! pipewire-owned objects whose layout is byte-for-byte identical across the whole matrix,
//! verified against both `ubuntu:22.04` (0.3.48) and `ubuntu:24.04` (1.0.5) headers:
//!
//! * `struct spa_interface`  — `spa/utils/hook.h` (type, version, cb{funcs,data}) — 32 B both.
//! * `struct spa_hook`       — `spa/utils/hook.h` (link, cb, removed, priv) — 48 B both.
//! * `struct spa_chunk`      — `spa/buffer/buffer.h` — 16 B both.
//! * `struct spa_data`       — `spa/buffer/buffer.h` — 40 B both.
//! * `struct spa_buffer`     — `spa/buffer/buffer.h` — 24 B both.
//! * `struct pw_buffer`      — `pipewire/stream.h` — 0.3.48 has 3 fields (24 B), 1.0.x has 5
//!   (40 B). We model the 1.0.x superset and only ever read the first field `buffer`, which
//!   sits at offset 0 in **both** versions.
//! * `struct pw_stream_events` / `struct pw_registry_events` — callback tables; identical
//!   member order in both. We add generous trailing padding so the library can never read past
//!   our allocation. `PW_VERSION_STREAM_EVENTS == 2` and `PW_VERSION_REGISTRY_EVENTS == 0` in
//!   0.3.48 and unchanged in 1.0.5.
//! * `struct pw_core_methods` / `struct pw_registry_methods` — vtables; member order is
//!   identical in 0.3.48, 1.0.5 and master.
//!
//! Header paths referenced throughout are under `/usr/include/pipewire-0.3/pipewire/` and
//! `/usr/include/spa-0.2/spa/` as installed by `libpipewire-0.3-dev` + `libspa-0.2-dev`.
//!
//! ## Reaching methods that are header macros
//!
//! `pw_core_get_registry`, `pw_registry_add_listener` and `pw_registry_destroy` are `static
//! inline`/macro wrappers in the headers — not exported symbols — that dispatch through the
//! object's `struct spa_interface` vtable. We reproduce the header dispatch ourselves:
//! `iface.cb.funcs` is the `pw_*_methods` table and `iface.cb.data` is the first argument the
//! macro passes (`spa_callbacks_call_res` calls `_f->method((callbacks)->data, ...)`). Every
//! pointer is null-checked before use.
//!
//! ## Threading
//!
//! The library handle is process-global and immutable after load, so [`PwLibrary`] is
//! `Send + Sync`. [`MainLoop`] is `Send + Sync` because `pw_main_loop_quit` is explicitly
//! designed to be called from another thread to stop `pw_main_loop_run`. The remaining
//! wrappers are `Send` so they can be moved into the dedicated PipeWire loop thread.
//!
//! ## Ownership footguns the wrappers absorb
//!
//! * `pw_stream_new` and `pw_context_connect_fd` take **ownership** of their properties/fd;
//!   [`Properties`] marks its raw pointer consumed and [`Context::connect_fd`] hands the fd
//!   over with `IntoRawFd`, so neither is double-freed on the failure path.
//! * `pw_stream_add_listener`/`pw_registry_add_listener` store *pointers* to the `spa_hook`
//!   and to the events table; both are heap-allocated and owned by the RAII wrapper so their
//!   address is stable for the listener's whole lifetime.

#![allow(clippy::missing_safety_doc)]

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::mem;
use std::os::fd::{IntoRawFd, OwnedFd};
use std::ptr;
use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;

/// The runtime soname present (and unchanged) on every supported baseline.
pub const DEFAULT_SONAME: &str = "libpipewire-0.3.so.0";

/// `PW_VERSION_STREAM_EVENTS` — `pipewire/stream.h`: `2` in 0.3.48, unchanged in 1.0.5.
pub const PW_VERSION_STREAM_EVENTS: u32 = 2;
/// `PW_VERSION_REGISTRY_EVENTS` — `pipewire/core.h`: `0` in 0.3.48, unchanged in 1.0.5.
pub const PW_VERSION_REGISTRY_EVENTS: u32 = 0;
/// `PW_VERSION_REGISTRY` — `pipewire/core.h`: `3` in 0.3.48, unchanged in 1.0.5.
pub const PW_VERSION_REGISTRY: u32 = 3;
/// `PW_ID_ANY` — `pipewire/core.h`: `(uint32_t)(0xffffffff)`; "let the manager pick".
pub const PW_ID_ANY: u32 = 0xffff_ffff;

/// Stream direction — `enum spa_direction` in `spa/utils/defs.h` (`pipewire`'s
/// `enum pw_direction` is that same enum): `INPUT = 0`, `OUTPUT = 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SpaDirection {
    /// Input (a capture stream consumes frames).
    Input = 0,
    /// Output (a playback stream produces frames).
    Output = 1,
}

impl SpaDirection {
    #[inline]
    fn as_sys(self) -> c_int {
        self as c_int
    }
}

/// `enum spa_direction` values — `spa/utils/defs.h`: `SPA_DIRECTION_INPUT = 0`,
/// `SPA_DIRECTION_OUTPUT = 1`. Identical in 0.3.48 and 1.0.5. (`pw_direction` is the same
/// enum.)
pub const SPA_DIRECTION_INPUT: u32 = 0;
/// `SPA_DIRECTION_OUTPUT`.
pub const SPA_DIRECTION_OUTPUT: u32 = 1;

/// `PW_STREAM_FLAG_*` — `pipewire/stream.h`. Values verified byte-identical in 0.3.48 and
/// 1.0.5.
pub const PW_STREAM_FLAG_NONE: u32 = 0;
/// `PW_STREAM_FLAG_AUTOCONNECT`.
pub const PW_STREAM_FLAG_AUTOCONNECT: u32 = 1 << 0;
/// `PW_STREAM_FLAG_INACTIVE`.
pub const PW_STREAM_FLAG_INACTIVE: u32 = 1 << 1;
/// `PW_STREAM_FLAG_MAP_BUFFERS`.
pub const PW_STREAM_FLAG_MAP_BUFFERS: u32 = 1 << 2;
/// `PW_STREAM_FLAG_DRIVER`.
pub const PW_STREAM_FLAG_DRIVER: u32 = 1 << 3;
/// `PW_STREAM_FLAG_RT_PROCESS`.
pub const PW_STREAM_FLAG_RT_PROCESS: u32 = 1 << 4;
/// `PW_STREAM_FLAG_NO_CONVERT`.
pub const PW_STREAM_FLAG_NO_CONVERT: u32 = 1 << 5;
/// `PW_STREAM_FLAG_EXCLUSIVE`.
pub const PW_STREAM_FLAG_EXCLUSIVE: u32 = 1 << 6;
/// `PW_STREAM_FLAG_DONT_RECONNECT`.
pub const PW_STREAM_FLAG_DONT_RECONNECT: u32 = 1 << 7;
/// `PW_STREAM_FLAG_ALLOC_BUFFERS`.
pub const PW_STREAM_FLAG_ALLOC_BUFFERS: u32 = 1 << 8;
/// `PW_STREAM_FLAG_TRIGGER`.
pub const PW_STREAM_FLAG_TRIGGER: u32 = 1 << 9;

// `enum spa_data_type` — `spa/buffer/buffer.h`; identical in 0.3.48 and 1.0.5. Names kept
// verbatim from the C enum (hence the `non_upper_case_globals` allow). These are the
// `SpaData::type_` values the consumer accepts (MemPtr/MemFd) or rejects (DmaBuf/MemId).
#[allow(non_upper_case_globals)]
/// `SPA_DATA_Invalid` = 0.
pub const SPA_DATA_Invalid: u32 = 0;
#[allow(non_upper_case_globals)]
/// `SPA_DATA_MemPtr` = 1 — `SpaData::data` is a plain pointer.
pub const SPA_DATA_MemPtr: u32 = 1;
#[allow(non_upper_case_globals)]
/// `SPA_DATA_MemFd` = 2 — generic fd; mmap to reach the memory.
pub const SPA_DATA_MemFd: u32 = 2;
#[allow(non_upper_case_globals)]
/// `SPA_DATA_DmaBuf` = 3 — DMA-BUF fd.
pub const SPA_DATA_DmaBuf: u32 = 3;
#[allow(non_upper_case_globals)]
/// `SPA_DATA_MemId` = 4 — memory identified by id.
pub const SPA_DATA_MemId: u32 = 4;

// `SPA_DATA_FLAG_*` — `spa/buffer/buffer.h`; identical in 0.3.48 and 1.0.5. (`MAPPABLE`,
// `1 << 3`, exists only in 1.0.x and is deliberately not exposed so the constant set is
// baseline-independent.)
/// `SPA_DATA_FLAG_NONE`.
pub const SPA_DATA_FLAG_NONE: u32 = 0;
/// `SPA_DATA_FLAG_READABLE` — data is readable.
pub const SPA_DATA_FLAG_READABLE: u32 = 1 << 0;
/// `SPA_DATA_FLAG_WRITABLE` — data is writable.
pub const SPA_DATA_FLAG_WRITABLE: u32 = 1 << 1;
/// `SPA_DATA_FLAG_DYNAMIC` — the `data` pointer can change.
pub const SPA_DATA_FLAG_DYNAMIC: u32 = 1 << 2;
/// `SPA_DATA_FLAG_READWRITE` — `READABLE | WRITABLE`.
pub const SPA_DATA_FLAG_READWRITE: u32 = SPA_DATA_FLAG_READABLE | SPA_DATA_FLAG_WRITABLE;

/// View the `spa_pod` a param callback handed us as a byte slice.
///
/// `param` is a `*const spa_pod`; its first two `u32`s are `size` and `type`, with `size`
/// counting the **body only**, so the total serialized length is `align_up8(8 + size)`
/// (`spa/utils/pod.h` `SPA_ROUND_UP_N(8 + size, 8)`). Returns `None` when the pointer is null
/// or the length arithmetic overflows.
///
/// # Safety
///
/// The caller must ensure `param` points at a valid `spa_pod` owned by pipewire for at least
/// the returned borrow. The `'a` lifetime is **the caller's obligation** — this function
/// cannot check how long pipewire keeps the pod alive (in practice: the duration of the
/// `param_changed`/`process` callback, or until the buffer is queued back).
pub unsafe fn pod_as_bytes<'a>(param: *const c_void) -> Option<&'a [u8]> {
    if param.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `param` points at a `spa_pod`; the first `u32` is its
    // body size. `read_unaligned` is used so a pod that is not 4-aligned is still handled.
    let size = unsafe { (param as *const u32).read_unaligned() } as usize;
    let total = (8usize.checked_add(size)?).checked_add(7)? & !7usize;
    // SAFETY: per the caller contract the pod occupies at least `total` initialized bytes
    // starting at `param`.
    Some(unsafe { std::slice::from_raw_parts(param as *const u8, total) })
}

// ---------------------------------------------------------------------------------------------
// Opaque pipewire objects. We only ever hold `*mut` to them.
// ---------------------------------------------------------------------------------------------

/// Opaque `struct pw_main_loop`.
#[repr(C)]
pub struct PwMainLoop {
    _private: [u8; 0],
}
/// Opaque `struct pw_loop`.
#[repr(C)]
pub struct PwLoop {
    _private: [u8; 0],
}
/// Opaque `struct pw_context`.
#[repr(C)]
pub struct PwContext {
    _private: [u8; 0],
}
/// Opaque `struct pw_core`.
#[repr(C)]
pub struct PwCore {
    _private: [u8; 0],
}
/// Opaque `struct pw_registry` (a proxy).
#[repr(C)]
pub struct PwRegistry {
    _private: [u8; 0],
}
/// Opaque `struct pw_stream`.
#[repr(C)]
pub struct PwStream {
    _private: [u8; 0],
}
/// Opaque `struct pw_properties`.
#[repr(C)]
pub struct PwProperties {
    _private: [u8; 0],
}

// ---------------------------------------------------------------------------------------------
// SPA layout types we must interpret. Layouts cited from the headers above; identical across
// the supported matrix.
// ---------------------------------------------------------------------------------------------

/// `struct spa_list` — `spa/utils/list.h`: `{ spa_list *next; spa_list *prev; }` (16 B).
#[repr(C)]
pub struct SpaList {
    /// Next node.
    pub next: *mut SpaList,
    /// Previous node.
    pub prev: *mut SpaList,
}

/// `struct spa_dict_item` — `spa/utils/dict.h`: `{ const char *key; const char *value; }`.
#[repr(C)]
pub struct SpaDictItem {
    /// Property key (NUL-terminated).
    pub key: *const c_char,
    /// Property value (NUL-terminated, may be null).
    pub value: *const c_char,
}

/// `struct spa_dict` — `spa/utils/dict.h`:
/// `{ uint32_t flags; uint32_t n_items; const struct spa_dict_item *items; }` (**16 B**;
/// note the leading `flags`, so `items` is at offset 8). Layout verified byte-identical in
/// the 0.3.48 (`ubuntu:22.04`) and 1.0.5 (`ubuntu:24.04`) headers.
#[repr(C)]
pub struct SpaDict {
    /// `SPA_DICT_FLAG_*` bitfield.
    pub flags: u32,
    /// Number of items in `items`.
    pub n_items: u32,
    /// Item array.
    pub items: *const SpaDictItem,
}

/// Look up `key` in a `struct spa_dict` (as handed to the registry `global` callback),
/// comparing raw bytes (never locale-collated).
///
/// Returns the value borrowed from the dict, or `None` when the dict/item pointers are null,
/// the key is absent, or the value is not valid UTF-8 (the signature returns `&str`, so a
/// lossily-decoded `String` cannot be returned).
///
/// # Safety
///
/// The caller must ensure `dict` points at a valid `spa_dict` whose `items`/string storage is
/// library-owned memory kept alive for at least the returned borrow (`'a` is the caller's
/// obligation).
pub unsafe fn dict_get<'a>(dict: *const c_void, key: &str) -> Option<&'a str> {
    if dict.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `dict` points at a `spa_dict`.
    let d = unsafe { &*(dict as *const SpaDict) };
    if d.items.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `items` holds `n_items` valid entries.
    let items = unsafe { std::slice::from_raw_parts(d.items, d.n_items as usize) };
    let want = key.as_bytes();
    for item in items {
        if item.key.is_null() {
            continue;
        }
        // SAFETY: `item.key` is a NUL-terminated library-owned string.
        let k: &'a CStr = unsafe { CStr::from_ptr(item.key) };
        if k.to_bytes() == want {
            if item.value.is_null() {
                return None;
            }
            // SAFETY: `item.value` is a NUL-terminated library-owned string; the borrow is
            // valid for `'a` per the caller contract.
            let v: &'a CStr = unsafe { CStr::from_ptr(item.value) };
            return v.to_str().ok();
        }
    }
    None
}

/// `struct spa_callbacks` — `spa/utils/hook.h`: `{ const void *funcs; void *data; }` (16 B).
#[repr(C)]
pub struct SpaCallbacks {
    /// The method/event table pointer.
    pub funcs: *const c_void,
    /// The object's `data` argument (first argument of every vtable call).
    pub data: *mut c_void,
}

/// `struct spa_interface` — `spa/utils/hook.h`:
/// `{ const char *type; uint32_t version; struct spa_callbacks cb; }` (32 B; `funcs` at
/// offset 16, `data` at offset 24). Identical in 0.3.48 and 1.0.5.
#[repr(C)]
pub struct SpaInterface {
    /// Interface type name.
    pub type_: *const c_char,
    /// Interface version.
    pub version: u32,
    /// Callbacks (object `funcs` + `data`).
    pub cb: SpaCallbacks,
}

/// `struct spa_hook` — `spa/utils/hook.h`:
/// `{ struct spa_list link; struct spa_callbacks cb; void (*removed)(hook); void *priv; }`
/// (48 B). The library writes this in place and links it into its listener list, so it must
/// live at a stable heap address for the listener's lifetime.
#[repr(C)]
pub struct SpaHook {
    /// Hook list linkage.
    pub link: SpaList,
    /// Event table + data for this listener.
    pub cb: SpaCallbacks,
    /// Removed callback (invoked when the hook is removed).
    pub removed: Option<unsafe extern "C" fn(*mut SpaHook)>,
    /// Private to the hook-list implementor.
    pub priv_: *mut c_void,
}

/// `struct spa_chunk` — `spa/buffer/buffer.h`:
/// `{ uint32_t offset; uint32_t size; int32_t stride; int32_t flags; }` — **16 B** in 0.3.48
/// and 1.0.5.
#[repr(C)]
pub struct SpaChunk {
    /// Offset of valid data (modulo `SpaData::maxsize`).
    pub offset: u32,
    /// Size of valid data.
    pub size: u32,
    /// Row stride of valid data.
    pub stride: i32,
    /// `SPA_CHUNK_FLAG_*` bitfield.
    pub flags: i32,
}

/// `struct spa_data` — `spa/buffer/buffer.h`: `uint32_t type; uint32_t flags; int64_t fd;
/// uint32_t mapoffset; uint32_t maxsize; void *data; struct spa_chunk *chunk;` — **40 B** in
/// 0.3.48 and 1.0.5 (note `fd` is `int64_t`, not `int`, and the `data`/`chunk` pointers are
/// the fields the consumer reads).
#[repr(C)]
pub struct SpaData {
    /// Memory type (`SPA_DATA_*`).
    pub type_: u32,
    /// Data flags (`SPA_DATA_FLAG_*`).
    pub flags: u32,
    /// Optional fd for the mapping.
    pub fd: i64,
    /// Offset to map the fd at.
    pub mapoffset: u32,
    /// Max size of the mapping.
    pub maxsize: u32,
    /// Optional CPU-mapped pointer.
    pub data: *mut c_void,
    /// Valid region within the mapping.
    pub chunk: *mut SpaChunk,
}

/// `struct spa_meta` — `spa/buffer/buffer.h`: `{ uint32_t type; uint32_t size; void *data; }`.
#[repr(C)]
pub struct SpaMeta {
    /// Metadata type.
    pub type_: u32,
    /// Size of the metadata.
    pub size: u32,
    /// Pointer to the metadata.
    pub data: *mut c_void,
}

/// `struct spa_buffer` — `spa/buffer/buffer.h`: `{ uint32_t n_metas; uint32_t n_datas;
/// struct spa_meta *metas; struct spa_data *datas; }` — **24 B** in 0.3.48 and 1.0.5.
#[repr(C)]
pub struct SpaBuffer {
    /// Number of metadata entries.
    pub n_metas: u32,
    /// Number of data planes.
    pub n_datas: u32,
    /// Metadata array.
    pub metas: *mut SpaMeta,
    /// Data plane array.
    pub datas: *mut SpaData,
}

/// `struct pw_buffer` — `pipewire/stream.h`. 0.3.48 declares `{ spa_buffer *buffer; void
/// *user_data; uint64_t size; }` (24 B); 1.0.5 adds `uint64_t requested; uint64_t time;`
/// (40 B). We model the 1.0.5 superset — only `buffer` (offset 0, identical in both) is read.
#[repr(C)]
pub struct PwBuffer {
    /// The underlying spa buffer (offset 0 in every version).
    pub buffer: *mut SpaBuffer,
    /// Opaque per-buffer user data.
    pub user_data: *mut c_void,
    /// Application-set size.
    pub size: u64,
    /// 1.0.x only: requested size for playback.
    pub requested: u64,
    /// 1.0.x only: capture timestamp.
    pub time: u64,
}

// ---------------------------------------------------------------------------------------------
// Event tables.
// ---------------------------------------------------------------------------------------------

/// `destroy` member of [`StreamEvents`].
pub type StreamDestroyFn = unsafe extern "C" fn(*mut c_void);
/// `state_changed` member of [`StreamEvents`] (`enum pw_stream_state`, `-1..=3`).
pub type StreamStateChangedFn = unsafe extern "C" fn(*mut c_void, c_int, c_int, *const c_char);
/// `control_info` member of [`StreamEvents`].
pub type StreamControlInfoFn = unsafe extern "C" fn(*mut c_void, u32, *const c_void);
/// `io_changed` member of [`StreamEvents`].
pub type StreamIoChangedFn = unsafe extern "C" fn(*mut c_void, u32, *mut c_void, u32);
/// `param_changed` member of [`StreamEvents`] (`const struct spa_pod *`).
pub type StreamParamChangedFn = unsafe extern "C" fn(*mut c_void, u32, *const c_void);
/// `add_buffer`/`remove_buffer` member of [`StreamEvents`].
pub type StreamBufferFn = unsafe extern "C" fn(*mut c_void, *mut PwBuffer);
/// `process`/`drained`/`trigger_done` member of [`StreamEvents`].
pub type StreamProcessFn = unsafe extern "C" fn(*mut c_void);
/// `command` member of [`StreamEvents`] (`const struct spa_command *`).
pub type StreamCommandFn = unsafe extern "C" fn(*mut c_void, *const c_void);

/// `struct pw_stream_events` — `pipewire/stream.h`. Members are in exact header order:
/// `version, destroy, state_changed, control_info, io_changed, param_changed, add_buffer,
/// remove_buffer, process, drained, command, trigger_done` (verified identical in the 0.3.48
/// and 1.0.5 headers). The trailing `_padding` guarantees that if the library reads/copies a
/// *larger* events struct of its own it still stays inside our allocation. `version` is first,
/// as the header requires.
///
/// `Copy` because the RAII wrappers store their own copy of the table: the library keeps a
/// pointer to our struct, so it has to outlive the call and never move (see `Stream`).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct StreamEvents {
    /// `PW_VERSION_STREAM_EVENTS` (2).
    pub version: u32,
    /// Stream destroyed.
    pub destroy: Option<StreamDestroyFn>,
    /// Stream state changed.
    pub state_changed: Option<StreamStateChangedFn>,
    /// Control value info changed.
    pub control_info: Option<StreamControlInfoFn>,
    /// IO area changed.
    pub io_changed: Option<StreamIoChangedFn>,
    /// A parameter changed.
    pub param_changed: Option<StreamParamChangedFn>,
    /// A buffer was created.
    pub add_buffer: Option<StreamBufferFn>,
    /// A buffer was destroyed.
    pub remove_buffer: Option<StreamBufferFn>,
    /// A buffer is ready (capture) / can be filled (playback).
    pub process: Option<StreamProcessFn>,
    /// The stream drained.
    pub drained: Option<StreamProcessFn>,
    /// A command was received.
    pub command: Option<StreamCommandFn>,
    /// `trigger_process` completed (since 0.3.40).
    pub trigger_done: Option<StreamProcessFn>,
    /// Generous slack for library-side struct growth.
    pub _padding: [usize; 16],
}

impl Default for StreamEvents {
    fn default() -> Self {
        Self {
            version: PW_VERSION_STREAM_EVENTS,
            destroy: None,
            state_changed: None,
            control_info: None,
            io_changed: None,
            param_changed: None,
            add_buffer: None,
            remove_buffer: None,
            process: None,
            drained: None,
            command: None,
            trigger_done: None,
            _padding: [0; 16],
        }
    }
}

/// `global` member of [`RegistryEvents`].
pub type RegistryGlobalFn =
    unsafe extern "C" fn(*mut c_void, u32, u32, *const c_char, u32, *const c_void);
/// `global_remove` member of [`RegistryEvents`].
pub type RegistryGlobalRemoveFn = unsafe extern "C" fn(*mut c_void, u32);

/// `struct pw_registry_events` — `pipewire/core.h` (0.3.48) / `pipewire/registry.h` (some 1.x
/// trees): `version, global, global_remove`, verified identical in 0.3.48 and 1.0.5. Trailing
/// padding as for [`StreamEvents`]. `PW_VERSION_REGISTRY_EVENTS == 0`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RegistryEvents {
    /// `PW_VERSION_REGISTRY_EVENTS` (0).
    pub version: u32,
    /// A new global object appeared.
    pub global: Option<RegistryGlobalFn>,
    /// A global object disappeared.
    pub global_remove: Option<RegistryGlobalRemoveFn>,
    /// Generous slack for library-side struct growth.
    pub _padding: [usize; 16],
}

impl Default for RegistryEvents {
    fn default() -> Self {
        Self {
            version: PW_VERSION_REGISTRY_EVENTS,
            global: None,
            global_remove: None,
            _padding: [0; 16],
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Method tables (vtables), mirroring the header field order exactly.
// ---------------------------------------------------------------------------------------------

/// `struct pw_core_methods` — `pipewire/core.h`. Member order (verified identical in 0.3.48,
/// 1.0.5 and master): `version, add_listener, hello, sync, pong, error, get_registry,
/// `create_object, destroy`. Only `get_registry` is ever called; the rest are opaque slots that
/// preserve the offset. `size_of == 72` (8 B header + eight pointers); `get_registry` sits at
/// byte offset **48** (`version` 4 B + 4 B pad, then five pointers).
#[repr(C)]
pub struct PwCoreMethods {
    /// `PW_VERSION_CORE_METHODS`.
    pub version: u32,
    /// `add_listener` slot (unused).
    pub add_listener: *const c_void,
    /// `hello` slot (unused).
    pub hello: *const c_void,
    /// `sync` slot (unused).
    pub sync: *const c_void,
    /// `pong` slot (unused).
    pub pong: *const c_void,
    /// `error` slot (unused).
    pub error: *const c_void,
    /// `get_registry(object, version, user_data_size)`.
    pub get_registry: Option<unsafe extern "C" fn(*mut c_void, u32, usize) -> *mut PwRegistry>,
    /// `create_object` slot (unused).
    pub create_object: *const c_void,
    /// `destroy` slot (unused).
    pub destroy: *const c_void,
}

/// `struct pw_registry_methods` — `pipewire/core.h`. Member order (verified identical in
/// 0.3.48 and 1.0.5): `version, add_listener, bind, destroy`. `add_listener` is at offset 8.
#[repr(C)]
pub struct PwRegistryMethods {
    /// `PW_VERSION_REGISTRY_METHODS`.
    pub version: u32,
    /// `add_listener(object, listener, events, data)`.
    pub add_listener: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *mut SpaHook,
            *const RegistryEvents,
            *mut c_void,
        ) -> c_int,
    >,
    /// `bind(object, id, type, version, user_data_size)` (unused).
    pub bind: *const c_void,
    /// `destroy(object, id)` — destroys a *global*, not the registry (unused).
    pub destroy: *const c_void,
}

// ---------------------------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------------------------

/// Failures surfaced by this shim. Every failure path is one of these — the FFI code never
/// panics, unwraps or expects.
#[derive(Debug, thiserror::Error)]
pub enum PwError {
    /// `dlopen` of the soname failed (library not installed / not loadable).
    #[error("libpipewire unavailable: {0}")]
    Unavailable(String),
    /// `dlsym` failed for the named symbol.
    #[error("libpipewire symbol missing: {0}")]
    Symbol(String),
    /// A resolved call rejected the request (null return or negative result code).
    #[error("pipewire call failed: {0}")]
    Call(String),
    /// A caller-supplied argument was invalid (e.g. an interior NUL byte).
    #[error("invalid argument: {0}")]
    Invalid(String),
}

/// Result alias for this module.
pub type PwResult<T> = Result<T, PwError>;

// ---------------------------------------------------------------------------------------------
// Library handle.
// ---------------------------------------------------------------------------------------------

/// Resolve one symbol into a function pointer of type `T` (always one of the `unsafe extern
/// "C" fn` types on [`PwLibrary`]).
///
/// # Safety
///
/// `handle` must be a live handle returned by `dlopen`, and `T` must be the exact
/// `unsafe extern "C" fn` type of the C symbol named by `name`.
unsafe fn resolve<T: Copy>(handle: *mut c_void, name: &str) -> PwResult<T> {
    let cname = CString::new(name).map_err(|_| PwError::Symbol(name.to_owned()))?;
    // SAFETY: `handle` is a live dlopen handle and `cname` is NUL-terminated.
    let sym = libc::dlsym(handle, cname.as_ptr());
    if sym.is_null() {
        return Err(PwError::Symbol(name.to_owned()));
    }
    debug_assert_eq!(mem::size_of::<T>(), mem::size_of::<*mut c_void>());
    // SAFETY: `T` is a function-pointer type with the same size as `*mut c_void`, and `sym` is
    // the address of the C function `name` whose signature `T` encodes.
    Ok(mem::transmute_copy::<*mut c_void, T>(&sym))
}

/// The loaded PipeWire library: the `dlopen` handle plus every resolved function pointer.
///
/// The handle is kept open for the whole process lifetime: `pw_init` installs process-global
/// state and PipeWire is not designed to be unloaded, and our wrappers only ever drop after
/// they have destroyed their own objects, so there is nothing to gain from `dlclose`.
///
/// All pointer fields are `pub` so they can be inspected/tested without accessors.
pub struct PwLibrary {
    /// The `dlopen` handle (kept for the process lifetime).
    pub handle: *mut c_void,
    /// `void pw_init(int *argc, char **argv[])` — called once per instance in [`load_named`].
    pub pw_init: unsafe extern "C" fn(*mut c_int, *mut *mut *mut c_char),
    /// `void pw_deinit(void)` — intentionally never called (see struct docs).
    pub pw_deinit: unsafe extern "C" fn(),
    /// `const char *pw_get_library_version(void)`.
    pub pw_get_library_version: unsafe extern "C" fn() -> *const c_char,
    /// `struct pw_main_loop *pw_main_loop_new(const struct spa_dict *props)`.
    pub pw_main_loop_new: unsafe extern "C" fn(*const c_void) -> *mut PwMainLoop,
    /// `void pw_main_loop_destroy(struct pw_main_loop *loop)`.
    pub pw_main_loop_destroy: unsafe extern "C" fn(*mut PwMainLoop),
    /// `int pw_main_loop_run(struct pw_main_loop *loop)`.
    pub pw_main_loop_run: unsafe extern "C" fn(*mut PwMainLoop) -> c_int,
    /// `int pw_main_loop_quit(struct pw_main_loop *loop)`.
    pub pw_main_loop_quit: unsafe extern "C" fn(*mut PwMainLoop) -> c_int,
    /// `struct pw_loop *pw_main_loop_get_loop(struct pw_main_loop *loop)`.
    pub pw_main_loop_get_loop: unsafe extern "C" fn(*mut PwMainLoop) -> *mut PwLoop,
    /// `struct pw_context *pw_context_new(struct pw_loop *main_loop, struct pw_properties
    /// *props, size_t user_data_size)`.
    pub pw_context_new: unsafe extern "C" fn(*mut PwLoop, *mut c_void, usize) -> *mut PwContext,
    /// `void pw_context_destroy(struct pw_context *context)`.
    pub pw_context_destroy: unsafe extern "C" fn(*mut PwContext),
    /// `struct pw_core *pw_context_connect_fd(struct pw_context *context, int fd, struct
    /// pw_properties *properties, size_t user_data_size)`.
    pub pw_context_connect_fd:
        unsafe extern "C" fn(*mut PwContext, c_int, *mut c_void, usize) -> *mut PwCore,
    /// `const struct pw_properties *pw_context_get_properties(struct pw_context *context)`.
    pub pw_context_get_properties: unsafe extern "C" fn(*mut PwContext) -> *const c_void,
    /// `int pw_core_disconnect(struct pw_core *core)`.
    pub pw_core_disconnect: unsafe extern "C" fn(*mut PwCore) -> c_int,
    /// `void pw_proxy_destroy(struct pw_proxy *proxy)` — how the `pw_registry_destroy` header
    /// macro ultimately frees a registry proxy.
    pub pw_proxy_destroy: unsafe extern "C" fn(*mut c_void),
    /// `struct pw_stream *pw_stream_new(struct pw_core *core, const char *name, struct
    /// pw_properties *props)` (props ownership taken).
    pub pw_stream_new:
        unsafe extern "C" fn(*mut PwCore, *const c_char, *mut c_void) -> *mut PwStream,
    /// `void pw_stream_destroy(struct pw_stream *stream)`.
    pub pw_stream_destroy: unsafe extern "C" fn(*mut PwStream),
    /// `void pw_stream_add_listener(struct pw_stream *stream, struct spa_hook *listener, const
    /// struct pw_stream_events *events, void *data)`.
    pub pw_stream_add_listener:
        unsafe extern "C" fn(*mut PwStream, *mut SpaHook, *const StreamEvents, *mut c_void),
    /// `int pw_stream_connect(struct pw_stream *stream, enum pw_direction direction, uint32_t
    /// target_id, enum pw_stream_flags flags, const struct spa_pod **params, uint32_t
    /// n_params)`.
    pub pw_stream_connect:
        unsafe extern "C" fn(*mut PwStream, c_int, u32, c_int, *const *const c_void, u32) -> c_int,
    /// `int pw_stream_disconnect(struct pw_stream *stream)`.
    pub pw_stream_disconnect: unsafe extern "C" fn(*mut PwStream) -> c_int,
    /// `struct pw_buffer *pw_stream_dequeue_buffer(struct pw_stream *stream)`.
    pub pw_stream_dequeue_buffer: unsafe extern "C" fn(*mut PwStream) -> *mut PwBuffer,
    /// `int pw_stream_queue_buffer(struct pw_stream *stream, struct pw_buffer *buffer)`.
    pub pw_stream_queue_buffer: unsafe extern "C" fn(*mut PwStream, *mut PwBuffer) -> c_int,
    /// `struct pw_properties *pw_properties_new_string(const char *args)`.
    pub pw_properties_new_string: unsafe extern "C" fn(*const c_char) -> *mut PwProperties,
    /// `int pw_properties_set(struct pw_properties *properties, const char *key, const char
    /// *value)`.
    pub pw_properties_set:
        unsafe extern "C" fn(*mut PwProperties, *const c_char, *const c_char) -> c_int,
    /// `void pw_properties_free(struct pw_properties *properties)`.
    pub pw_properties_free: unsafe extern "C" fn(*mut PwProperties),
    /// `void pw_loop_destroy(struct pw_loop *loop)`.
    pub pw_loop_destroy: unsafe extern "C" fn(*mut PwLoop),
}

// SAFETY: after construction a `PwLibrary` is immutable; all fields are plain function
// pointers and an opaque process-global `dlopen` handle, and PipeWire's API is callable from
// any thread. `Arc<PwLibrary>` is therefore safely shared across threads.
unsafe impl Send for PwLibrary {}
// SAFETY: see the `Send` impl — sharing `&PwLibrary` across threads only reads these fields.
unsafe impl Sync for PwLibrary {}

impl PwLibrary {
    /// Resolve every symbol we need. Does **not** call `pw_init` (the caller does, once).
    ///
    /// # Safety
    ///
    /// `handle` must be a live `dlopen` handle to `libpipewire-0.3.so.0`.
    unsafe fn resolve(handle: *mut c_void) -> PwResult<Self> {
        Ok(PwLibrary {
            handle,
            pw_init: resolve(handle, "pw_init")?,
            pw_deinit: resolve(handle, "pw_deinit")?,
            pw_get_library_version: resolve(handle, "pw_get_library_version")?,
            pw_main_loop_new: resolve(handle, "pw_main_loop_new")?,
            pw_main_loop_destroy: resolve(handle, "pw_main_loop_destroy")?,
            pw_main_loop_run: resolve(handle, "pw_main_loop_run")?,
            pw_main_loop_quit: resolve(handle, "pw_main_loop_quit")?,
            pw_main_loop_get_loop: resolve(handle, "pw_main_loop_get_loop")?,
            pw_context_new: resolve(handle, "pw_context_new")?,
            pw_context_destroy: resolve(handle, "pw_context_destroy")?,
            pw_context_connect_fd: resolve(handle, "pw_context_connect_fd")?,
            pw_context_get_properties: resolve(handle, "pw_context_get_properties")?,
            pw_core_disconnect: resolve(handle, "pw_core_disconnect")?,
            pw_proxy_destroy: resolve(handle, "pw_proxy_destroy")?,
            pw_stream_new: resolve(handle, "pw_stream_new")?,
            pw_stream_destroy: resolve(handle, "pw_stream_destroy")?,
            pw_stream_add_listener: resolve(handle, "pw_stream_add_listener")?,
            pw_stream_connect: resolve(handle, "pw_stream_connect")?,
            pw_stream_disconnect: resolve(handle, "pw_stream_disconnect")?,
            pw_stream_dequeue_buffer: resolve(handle, "pw_stream_dequeue_buffer")?,
            pw_stream_queue_buffer: resolve(handle, "pw_stream_queue_buffer")?,
            pw_properties_new_string: resolve(handle, "pw_properties_new_string")?,
            pw_properties_set: resolve(handle, "pw_properties_set")?,
            pw_properties_free: resolve(handle, "pw_properties_free")?,
            pw_loop_destroy: resolve(handle, "pw_loop_destroy")?,
        })
    }

    /// The runtime PipeWire version string (`pw_get_library_version`), or an empty string if
    /// the library reports none.
    pub fn version(&self) -> String {
        // SAFETY: `pw_get_library_version` returns a static NUL-terminated string (or null);
        // the returned pointer is valid for the process lifetime.
        let p = unsafe { (self.pw_get_library_version)() };
        if p.is_null() {
            return String::new();
        }
        // SAFETY: non-null, NUL-terminated per the API contract.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

/// Read the dynamic loader's last error string.
fn dl_error() -> String {
    // SAFETY: `dlerror` returns a NUL-terminated string valid until the next dl* call, or null.
    unsafe {
        let p = libc::dlerror();
        if p.is_null() {
            "unknown loader error".to_owned()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

/// Load (or return the cached handle for) the default soname [`DEFAULT_SONAME`].
///
/// Cheap on repeat calls: the first success is cached and subsequent calls return the same
/// `Arc` without touching the loader again.
pub fn load() -> PwResult<Arc<PwLibrary>> {
    static DEFAULT: LazyLock<Mutex<Option<Arc<PwLibrary>>>> = LazyLock::new(|| Mutex::new(None));
    let mut guard = DEFAULT.lock();
    if let Some(lib) = guard.as_ref() {
        return Ok(Arc::clone(lib));
    }
    let lib = load_named(DEFAULT_SONAME)?;
    *guard = Some(Arc::clone(&lib));
    Ok(lib)
}

/// Load an arbitrary soname. Exists primarily so tests can exercise the failure path; also
/// useful for pinning a specific library file.
///
/// Calls `pw_init(null, null)` exactly once per successful load, before returning.
pub fn load_named(soname: &str) -> PwResult<Arc<PwLibrary>> {
    let cname = CString::new(soname)
        .map_err(|_| PwError::Unavailable(format!("soname contains NUL: {soname:?}")))?;
    // SAFETY: `cname` is NUL-terminated; RTLD_NOW|RTLD_LOCAL is a valid mode.
    let handle = unsafe { libc::dlopen(cname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return Err(PwError::Unavailable(dl_error()));
    }
    // SAFETY: `handle` is a live dlopen handle (checked above).
    let lib = match unsafe { PwLibrary::resolve(handle) } {
        Ok(lib) => lib,
        Err(err) => {
            // SAFETY: the handle was never handed to a `PwLibrary`, so it is ours to close.
            unsafe { libc::dlclose(handle) };
            return Err(err);
        }
    };
    // SAFETY: `pw_init` was resolved into `lib`; passing null argc/argv is documented.
    unsafe { (lib.pw_init)(ptr::null_mut(), ptr::null_mut()) };
    Ok(Arc::new(lib))
}

// ---------------------------------------------------------------------------------------------
// MainLoop.
// ---------------------------------------------------------------------------------------------

/// Owns a `struct pw_main_loop`. `run` blocks on the calling thread until `quit` is invoked
/// (typically from another thread), at which point `Drop` destroys the loop.
pub struct MainLoop {
    lib: Arc<PwLibrary>,
    ptr: *mut PwMainLoop,
}

// SAFETY: `pw_main_loop_quit` is designed to be called from another thread to unblock
// `pw_main_loop_run`; the handle is opaque and only read.
unsafe impl Send for MainLoop {}
// SAFETY: as for `Send` — `quit(&self)` is the intended cross-thread entry point.
unsafe impl Sync for MainLoop {}

impl MainLoop {
    /// Create a main loop (no properties).
    pub fn new(lib: &Arc<PwLibrary>) -> PwResult<Self> {
        // SAFETY: `pw_main_loop_new` accepts a null properties pointer.
        let ptr = unsafe { (lib.pw_main_loop_new)(ptr::null()) };
        if ptr.is_null() {
            return Err(PwError::Call("pw_main_loop_new returned null".into()));
        }
        Ok(Self {
            lib: Arc::clone(lib),
            ptr,
        })
    }

    /// Run the loop; blocks the calling thread until [`MainLoop::quit`].
    pub fn run(&self) -> PwResult<()> {
        // SAFETY: `self.ptr` is a live main loop for the lifetime of `self`.
        let res = unsafe { (self.lib.pw_main_loop_run)(self.ptr) };
        if res < 0 {
            return Err(PwError::Call(format!("pw_main_loop_run failed: {res}")));
        }
        Ok(())
    }

    /// Ask the loop to stop. Safe to call from another thread.
    pub fn quit(&self) -> PwResult<()> {
        // SAFETY: `self.ptr` is a live main loop for the lifetime of `self`.
        let res = unsafe { (self.lib.pw_main_loop_quit)(self.ptr) };
        if res < 0 {
            return Err(PwError::Call(format!("pw_main_loop_quit failed: {res}")));
        }
        Ok(())
    }
}

impl Drop for MainLoop {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was created by `pw_main_loop_new` and is destroyed exactly once,
        // here; all methods borrowed it only through `&self`.
        unsafe { (self.lib.pw_main_loop_destroy)(self.ptr) };
    }
}

// ---------------------------------------------------------------------------------------------
// Context.
// ---------------------------------------------------------------------------------------------

/// Owns a `struct pw_context`. The [`MainLoop`] it was created from must outlive it (the
/// context runs in that loop; we do not retain a reference, matching the C API).
pub struct Context {
    lib: Arc<PwLibrary>,
    ptr: *mut PwContext,
}

// SAFETY: the context handle is only read after construction; PipeWire objects are used from
// whichever thread runs the loop.
unsafe impl Send for Context {}

impl Context {
    /// Create a context on `main_loop`.
    pub fn new(lib: &Arc<PwLibrary>, main_loop: &MainLoop) -> PwResult<Self> {
        // SAFETY: `main_loop.ptr` is a live main loop.
        let loop_ptr = unsafe { (lib.pw_main_loop_get_loop)(main_loop.ptr) };
        if loop_ptr.is_null() {
            return Err(PwError::Call("pw_main_loop_get_loop returned null".into()));
        }
        // SAFETY: `loop_ptr` is a live pw_loop; null properties is accepted.
        let ptr = unsafe { (lib.pw_context_new)(loop_ptr, ptr::null_mut(), 0) };
        if ptr.is_null() {
            return Err(PwError::Call("pw_context_new returned null".into()));
        }
        Ok(Self {
            lib: Arc::clone(lib),
            ptr,
        })
    }

    /// Connect to a PipeWire instance over `fd`.
    ///
    /// **Takes ownership of `fd`**: per `pipewire/context.h` the socket "will be closed
    /// automatically on disconnect or error", so we hand it over with `IntoRawFd` and never
    /// close it ourselves (including on the failure path).
    pub fn connect_fd(&self, fd: OwnedFd) -> PwResult<Core> {
        let raw_fd = fd.into_raw_fd();
        // SAFETY: `self.ptr` is a live context; `raw_fd` is a valid owned fd we transfer to
        // pipewire; null properties is accepted.
        let ptr = unsafe { (self.lib.pw_context_connect_fd)(self.ptr, raw_fd, ptr::null_mut(), 0) };
        if ptr.is_null() {
            return Err(PwError::Call("pw_context_connect_fd returned null".into()));
        }
        Ok(Core {
            lib: Arc::clone(&self.lib),
            ptr: Cell::new(ptr),
        })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: created by `pw_context_new`, destroyed exactly once here.
        unsafe { (self.lib.pw_context_destroy)(self.ptr) };
    }
}

// ---------------------------------------------------------------------------------------------
// Core.
// ---------------------------------------------------------------------------------------------

/// Owns a `struct pw_core` (the connection). Dropping or [`Core::disconnect`]-ing it tears the
/// connection down. Any [`Registry`]/[`Stream`] created from it must be dropped first, as they
/// are child proxies freed by the core.
pub struct Core {
    lib: Arc<PwLibrary>,
    /// `Cell` so [`Core::disconnect`] (which consumes `self`) and `Drop` can atomically mark
    /// the handle consumed without moving out of a `Drop` type.
    ptr: Cell<*mut PwCore>,
}

// SAFETY: moved into the PipeWire loop thread; the handle is only read after construction.
unsafe impl Send for Core {}

impl Core {
    /// Create the registry and install `events` as its listener.
    ///
    /// Both the `spa_hook` and a copy of `events` are heap-allocated and owned by the returned
    /// [`Registry`] — the library stores their addresses, so they must not move and must
    /// outlive the listener. `data` is passed through to every callback.
    // `data` is an *opaque* pointer that we hand to the library untouched and never
    // dereference ourselves; the invariant that matters (the pointee outliving the listener)
    // belongs to the caller and is documented above, so this is deliberately a safe method
    // taking a raw pointer rather than an `unsafe fn` — there is nothing the compiler could
    // check here, and making it `unsafe` would push noise into the backend's call sites.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn registry(&self, events: RegistryEvents, data: *mut c_void) -> PwResult<Registry> {
        let core_ptr = self.ptr.get();
        if core_ptr.is_null() {
            return Err(PwError::Call("core is disconnected".into()));
        }
        // Dispatch `pw_core_get_registry` through the core's vtable, reproducing the header's
        // `spa_interface_call_res(... get_registry, 0, version, user_data_size)`: the first
        // argument is the interface `data`, not the object pointer.
        // SAFETY: a live `pw_core`'s first member is a `struct spa_interface`.
        let iface = unsafe { &*(core_ptr as *const SpaInterface) };
        if iface.cb.funcs.is_null() {
            return Err(PwError::Call("core vtable is null".into()));
        }
        // SAFETY: `cb.funcs` points at a `struct pw_core_methods` (verified member order).
        let methods = unsafe { &*(iface.cb.funcs as *const PwCoreMethods) };
        let get_registry = methods
            .get_registry
            .ok_or_else(|| PwError::Call("pw_core_methods::get_registry is null".into()))?;
        // SAFETY: `get_registry` is non-null and `iface.cb.data` is the core's object data.
        let reg = unsafe { get_registry(iface.cb.data, PW_VERSION_REGISTRY, 0) };
        if reg.is_null() {
            return Err(PwError::Call("pw_core_get_registry returned null".into()));
        }

        let mut hook = Box::new(unsafe {
            // SAFETY: an all-zero `spa_hook` is a valid empty hook (null pointers).
            mem::zeroed::<SpaHook>()
        });
        let ev = Box::new(events);

        // Install the listener through the registry's vtable (the `pw_registry_add_listener`
        // header macro).
        // SAFETY: a live `pw_registry`'s first member is a `struct spa_interface`.
        let riface = unsafe { &*(reg as *const SpaInterface) };
        if riface.cb.funcs.is_null() {
            // SAFETY: `reg` was just created by `get_registry` and is not otherwise owned.
            unsafe { (self.lib.pw_proxy_destroy)(reg as *mut c_void) };
            return Err(PwError::Call("registry vtable is null".into()));
        }
        // SAFETY: `cb.funcs` points at a `struct pw_registry_methods`.
        let rmethods = unsafe { &*(riface.cb.funcs as *const PwRegistryMethods) };
        let add_listener = match rmethods.add_listener {
            Some(f) => f,
            None => {
                // SAFETY: as above — clean up the freshly created registry.
                unsafe { (self.lib.pw_proxy_destroy)(reg as *mut c_void) };
                return Err(PwError::Call(
                    "pw_registry_methods::add_listener is null".into(),
                ));
            }
        };
        // SAFETY: `add_listener` is non-null; `hook`/`ev` live on the heap and are moved into
        // the returned `Registry`, so their addresses stay valid for the listener's lifetime.
        let res = unsafe {
            add_listener(
                riface.cb.data,
                &mut *hook as *mut SpaHook,
                &*ev as *const RegistryEvents,
                data,
            )
        };
        if res < 0 {
            // SAFETY: `add_listener` failed, so no listener was linked; free the registry.
            unsafe { (self.lib.pw_proxy_destroy)(reg as *mut c_void) };
            return Err(PwError::Call(format!(
                "pw_registry_add_listener failed: {res}"
            )));
        }

        Ok(Registry {
            lib: Arc::clone(&self.lib),
            ptr: reg,
            _hook: hook,
            _events: ev,
        })
    }

    /// Disconnect and destroy the core. Idempotent: the handle is marked consumed so the
    /// subsequent `Drop` is a no-op.
    pub fn disconnect(self) {
        let ptr = self.ptr.replace(ptr::null_mut());
        if !ptr.is_null() {
            // SAFETY: `ptr` is a live core, not yet disconnected.
            unsafe { (self.lib.pw_core_disconnect)(ptr) };
        }
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        let ptr = self.ptr.replace(ptr::null_mut());
        if !ptr.is_null() {
            // SAFETY: `ptr` is a live core (unless `disconnect` already consumed it).
            unsafe { (self.lib.pw_core_disconnect)(ptr) };
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Registry.
// ---------------------------------------------------------------------------------------------

/// RAII owner of a `struct pw_registry` plus its listener `spa_hook` and event table copy.
///
/// The listener is installed by [`Core::registry`]; there are no public methods. Dropping the
/// registry frees the proxy (the `pw_registry_destroy` header macro expands to
/// `pw_proxy_method(... destroy ...)`, which destroys a *global* by id — freeing the proxy
/// itself is `pw_proxy_destroy((struct pw_proxy *)registry)`, an exported symbol).
pub struct Registry {
    lib: Arc<PwLibrary>,
    ptr: *mut PwRegistry,
    /// Owned so the library's stored pointer stays valid; never read directly.
    _hook: Box<SpaHook>,
    /// Owned copy of the caller's event table; never read directly.
    _events: Box<RegistryEvents>,
}

// SAFETY: moved into the PipeWire loop thread; the handle is only read after construction.
unsafe impl Send for Registry {}

impl Drop for Registry {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is a live registry proxy; `pw_proxy_destroy` frees it exactly
        // once. The boxes are dropped after this body, once the library has unlinked the hook.
        unsafe { (self.lib.pw_proxy_destroy)(self.ptr as *mut c_void) };
    }
}

// ---------------------------------------------------------------------------------------------
// Properties.
// ---------------------------------------------------------------------------------------------

/// Owns a `struct pw_properties`. [`Stream::new`] takes ownership of the raw object, after
/// which this wrapper (and its `Drop`) is a no-op.
///
/// Bound to whichever [`PwLibrary`] created it ([`Properties::new`] uses the process-wide
/// cached [`load`], [`Properties::new_with`] takes an explicit instance); it must be paired
/// with streams created from that same library instance.
pub struct Properties {
    lib: Arc<PwLibrary>,
    /// `Cell` so ownership can be handed to `pw_stream_new` exactly once.
    raw: Cell<*mut PwProperties>,
}

// SAFETY: moved into the PipeWire loop thread; the handle is only read after construction.
unsafe impl Send for Properties {}

impl Properties {
    /// Create an empty property set against the process-wide cached library from [`load`].
    pub fn new() -> PwResult<Self> {
        Self::new_with(&load()?)
    }

    /// Same as [`Properties::new`], but against a specific library instance — used by tests
    /// that load a stub `libpipewire-0.3.so.0`, and by any caller that already holds one. The
    /// properties must be used with streams created from this same library.
    pub fn new_with(lib: &Arc<PwLibrary>) -> PwResult<Self> {
        // A static, NUL-terminated empty C string: `pw_properties_new_string("")` yields empty
        // properties without going through the variadic `pw_properties_new`.
        // SAFETY: `c""` is a `&'static CStr`, so the pointer is valid, NUL-terminated and
        // lives for the whole program.
        let raw = unsafe { (lib.pw_properties_new_string)(c"".as_ptr()) };
        if raw.is_null() {
            return Err(PwError::Call(
                "pw_properties_new_string returned null".into(),
            ));
        }
        Ok(Self {
            lib: Arc::clone(lib),
            raw: Cell::new(raw),
        })
    }

    /// Set `key` to `value`. Errors (interior NUL, or a rejected key/value) are logged, not
    /// returned: the signature is the fixed consumer-facing one.
    pub fn set(&mut self, key: &str, value: &str) {
        let raw = self.raw.get();
        if raw.is_null() {
            log::warn!("pipewire_sys: set() on consumed properties");
            return;
        }
        let ckey = match CString::new(key) {
            Ok(k) => k,
            Err(_) => {
                log::warn!("pipewire_sys: property key contains NUL");
                return;
            }
        };
        let cvalue = match CString::new(value) {
            Ok(v) => v,
            Err(_) => {
                log::warn!("pipewire_sys: property value contains NUL");
                return;
            }
        };
        // SAFETY: `raw` is a live properties object (non-null checked) and both strings are
        // NUL-terminated.
        let res = unsafe { (self.lib.pw_properties_set)(raw, ckey.as_ptr(), cvalue.as_ptr()) };
        if res < 0 {
            log::warn!("pipewire_sys: pw_properties_set failed for key {key:?}: {res}");
        }
    }

    /// Relinquish ownership of the raw object (used when handing it to `pw_stream_new`).
    fn take_raw(&self) -> *mut PwProperties {
        self.raw.replace(ptr::null_mut())
    }
}

impl Drop for Properties {
    fn drop(&mut self) {
        let raw = self.raw.replace(ptr::null_mut());
        if !raw.is_null() {
            // SAFETY: `raw` is a live properties object we own.
            unsafe { (self.lib.pw_properties_free)(raw) };
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Stream.
// ---------------------------------------------------------------------------------------------

/// Owns a `struct pw_stream` plus its listener `spa_hook` and a copy of the caller's event
/// table.
pub struct Stream {
    lib: Arc<PwLibrary>,
    ptr: *mut PwStream,
    /// Installed listener (hook + events copy), kept alive for the stream's lifetime.
    listener: Mutex<Option<Listener>>,
}

/// Heap-owned listener state whose addresses are stored by the library.
struct Listener {
    /// The `spa_hook` the library links into its list; its address must not move.
    _hook: Box<SpaHook>,
    /// A copy of the caller's `StreamEvents`; the library keeps a pointer to it.
    _events: Box<StreamEvents>,
}

// SAFETY: moved into the PipeWire loop thread. `dequeue_buffer`/`queue_buffer` are PipeWire's
// dedicated cross-thread (realtime-callback) operations.
unsafe impl Send for Stream {}

impl Stream {
    /// Create a stream on `core`.
    ///
    /// **Takes ownership of `props`** (the C API does): the properties object is consumed and
    /// its `Drop` becomes a no-op.
    pub fn new(
        lib: &Arc<PwLibrary>,
        core: &Core,
        name: &str,
        props: &Properties,
    ) -> PwResult<Self> {
        let core_ptr = core.ptr.get();
        if core_ptr.is_null() {
            return Err(PwError::Call("core is disconnected".into()));
        }
        let cname =
            CString::new(name).map_err(|_| PwError::Invalid("stream name contains NUL".into()))?;
        let props_ptr = props.take_raw();
        // SAFETY: `core_ptr` is a live core; `cname` is NUL-terminated; `props_ptr` is null or
        // a live properties object whose ownership we transfer per the header contract.
        let ptr =
            unsafe { (lib.pw_stream_new)(core_ptr, cname.as_ptr(), props_ptr as *mut c_void) };
        if ptr.is_null() {
            return Err(PwError::Call("pw_stream_new returned null".into()));
        }
        Ok(Self {
            lib: Arc::clone(lib),
            ptr,
            listener: Mutex::new(None),
        })
    }

    /// Install `events` as this stream's listener. A copy of `events` is stored, so the
    /// caller's value need not outlive the call. `data` is passed through to every callback.
    // See `Core::registry`: `data` is opaque to us and never dereferenced here; the caller
    // owns the pointee's lifetime (the backend keeps `StreamUser` and `Stream` alive together
    // in `StreamHandle`).
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn add_listener(&self, events: &StreamEvents, data: *mut c_void) -> PwResult<()> {
        if self.ptr.is_null() {
            return Err(PwError::Call("stream is disconnected".into()));
        }
        let mut hook = Box::new(unsafe {
            // SAFETY: an all-zero `spa_hook` is a valid empty hook.
            mem::zeroed::<SpaHook>()
        });
        let ev = Box::new(*events);
        // SAFETY: `self.ptr` is a live stream; `hook`/`ev` are heap allocations whose addresses
        // are stable and which we keep alive in `self.listener`.
        unsafe {
            (self.lib.pw_stream_add_listener)(
                self.ptr,
                &mut *hook as *mut SpaHook,
                &*ev as *const StreamEvents,
                data,
            );
        }
        *self.listener.lock() = Some(Listener {
            _hook: hook,
            _events: ev,
        });
        Ok(())
    }

    /// Connect the stream. `params` are raw spa pod **byte buffers** (built by the sibling
    /// `pipewire_pod` module) — the only place SPA data crosses the boundary, and only as
    /// opaque bytes. `target_id` `None` means `PW_ID_ANY`.
    pub fn connect(
        &self,
        direction: SpaDirection,
        target_id: Option<u32>,
        flags: u32,
        params: &[&[u8]],
    ) -> PwResult<()> {
        if self.ptr.is_null() {
            return Err(PwError::Call("stream is disconnected".into()));
        }
        let pod_ptrs: Vec<*const c_void> =
            params.iter().map(|p| p.as_ptr() as *const c_void).collect();
        // SAFETY: `self.ptr` is a live stream; `pod_ptrs` is a valid array of `n_params`
        // pointers that outlives the call; each entry points at caller-owned pod bytes.
        let res = unsafe {
            (self.lib.pw_stream_connect)(
                self.ptr,
                direction.as_sys(),
                target_id.unwrap_or(PW_ID_ANY),
                flags as c_int,
                pod_ptrs.as_ptr(),
                pod_ptrs.len() as u32,
            )
        };
        if res < 0 {
            return Err(PwError::Call(format!("pw_stream_connect failed: {res}")));
        }
        Ok(())
    }

    /// Dequeue the next buffer, or `None` if none is ready.
    pub fn dequeue_buffer(&self) -> Option<*mut PwBuffer> {
        if self.ptr.is_null() {
            return None;
        }
        // SAFETY: `self.ptr` is a live stream; the returned pointer is owned by the stream and
        // valid until the matching `queue_buffer`.
        let buf = unsafe { (self.lib.pw_stream_dequeue_buffer)(self.ptr) };
        if buf.is_null() {
            None
        } else {
            Some(buf)
        }
    }

    /// Return a buffer to the stream after consuming it.
    // `buffer` must come from `dequeue_buffer` on this stream and is only ever forwarded to
    // the library; the obligation is the caller's and is documented here rather than encoded
    // in the signature (same reasoning as `Core::registry`).
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn queue_buffer(&self, buffer: *mut PwBuffer) {
        if self.ptr.is_null() || buffer.is_null() {
            return;
        }
        // SAFETY: `self.ptr` is a live stream and `buffer` is a buffer previously dequeued
        // from this stream.
        let res = unsafe { (self.lib.pw_stream_queue_buffer)(self.ptr, buffer) };
        if res < 0 {
            log::warn!("pipewire_sys: pw_stream_queue_buffer failed: {res}");
        }
    }

    /// Disconnect the stream (its buffers/nodes are torn down; the object itself survives
    /// until `Drop`).
    pub fn disconnect(&self) {
        if self.ptr.is_null() {
            return;
        }
        // SAFETY: `self.ptr` is a live stream.
        let res = unsafe { (self.lib.pw_stream_disconnect)(self.ptr) };
        if res < 0 {
            log::warn!("pipewire_sys: pw_stream_disconnect failed: {res}");
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `self.ptr` is a live stream, destroyed exactly once here; the listener
            // boxes are dropped afterwards, once the library has removed the hook.
            unsafe { (self.lib.pw_stream_destroy)(self.ptr) };
            self.ptr = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn load_named_missing_library_returns_err() {
        let res = load_named("/nonexistent/libpipewire-0.3.so.0");
        assert!(matches!(res, Err(PwError::Unavailable(_))));
    }

    #[test]
    fn stream_events_version_is_first_and_has_trailing_padding() {
        // `struct pw_stream_events` (pipewire-0.3/pipewire/stream.h) starts with
        // `uint32_t version`, so the first callback pointer cannot begin before offset 8; the
        // size must exceed the version word plus the first four pointer members (8 + 4*8).
        assert!(core::mem::size_of::<StreamEvents>() >= 8 + 4 * 8);

        let uninit = MaybeUninit::<StreamEvents>::uninit();
        let base = uninit.as_ptr() as usize;
        // SAFETY: `addr_of!` computes the address of a place without reading it.
        let version_off =
            unsafe { core::ptr::addr_of!((*uninit.as_ptr()).version) as usize - base };
        assert_eq!(version_off, 0);
        assert_eq!(StreamEvents::default().version, PW_VERSION_STREAM_EVENTS);
    }

    #[test]
    fn registry_events_default_version_matches_header() {
        assert_eq!(
            RegistryEvents::default().version,
            PW_VERSION_REGISTRY_EVENTS
        );
        assert!(core::mem::size_of::<RegistryEvents>() >= 8);
    }

    #[test]
    fn core_methods_get_registry_offset_matches_header() {
        // pipewire-0.3/pipewire/core.h `struct pw_core_methods`: `uint32_t version` at 0 (4 B)
        // plus 4 B padding, then `add_listener, hello, sync, pong, error` (five pointers)
        // before `get_registry` -> offset 8 + 5*8 = 48. Member order verified identical in
        // 0.3.48, 1.0.5 and master.
        let uninit = MaybeUninit::<PwCoreMethods>::uninit();
        let base = uninit.as_ptr() as usize;
        // SAFETY: `addr_of!` computes the address of a place without reading it.
        let off = unsafe { core::ptr::addr_of!((*uninit.as_ptr()).get_registry) as usize - base };
        assert_eq!(off, 48);
    }

    #[test]
    fn spa_layouts_match_0_3_48_headers() {
        // spa-0.2/spa/buffer/buffer.h in pipewire 0.3.48 (ubuntu:22.04):
        //   struct spa_chunk { u32 offset; u32 size; i32 stride; i32 flags; }        = 16
        //   struct spa_data  { u32 type; u32 flags; i64 fd; u32 mapoffset; u32
        //                      maxsize; void *data; struct spa_chunk *chunk; }      = 40
        //   struct spa_buffer{ u32 n_metas; u32 n_datas; spa_meta *metas;
        //                      spa_data *datas; }                                   = 24
        // Verified byte-identical in the ubuntu:24.04 (pipewire 1.0.5) headers.
        assert_eq!(core::mem::size_of::<SpaChunk>(), 16);
        assert_eq!(core::mem::size_of::<SpaData>(), 40);
        assert_eq!(core::mem::size_of::<SpaBuffer>(), 24);
    }

    #[test]
    fn hook_and_interface_layouts_match_headers() {
        // spa-0.2/spa/utils/hook.h (identical in 0.3.48 and 1.0.5):
        //   struct spa_hook      { spa_list link; spa_callbacks cb;
        //                          void (*removed)(spa_hook *); void *priv; }      = 48
        //   struct spa_interface { const char *type; u32 version;
        //                          struct spa_callbacks cb; }                     = 32
        assert_eq!(core::mem::size_of::<SpaHook>(), 48);
        assert_eq!(core::mem::size_of::<SpaInterface>(), 32);
    }

    #[test]
    fn pw_buffer_is_at_least_the_0_3_48_layout() {
        // `struct pw_buffer` is 24 B in 0.3.48 and 40 B in 1.0.x; we model the superset and
        // only read the `buffer` field at offset 0.
        assert!(core::mem::size_of::<PwBuffer>() >= 24);
    }

    #[test]
    fn spa_dict_layout_and_lookup() {
        // spa-0.2/spa/utils/dict.h (identical in 0.3.48 and 1.0.5):
        //   struct spa_dict_item { const char *key; const char *value; }        = 16
        //   struct spa_dict { u32 flags; u32 n_items; const spa_dict_item
        //                     *items; }                                         = 16
        assert_eq!(core::mem::size_of::<SpaDictItem>(), 16);
        assert_eq!(core::mem::size_of::<SpaDict>(), 16);

        let k1 = b"node.name\0";
        let v1 = b"v4l2-input\0";
        let k2 = b"media.class\0";
        let v2 = b"Video/Source\0";
        let items = [
            SpaDictItem {
                key: k1.as_ptr() as *const c_char,
                value: v1.as_ptr() as *const c_char,
            },
            SpaDictItem {
                key: k2.as_ptr() as *const c_char,
                value: v2.as_ptr() as *const c_char,
            },
        ];
        let dict = SpaDict {
            flags: 0,
            n_items: items.len() as u32,
            items: items.as_ptr(),
        };
        let dict_ptr = &dict as *const SpaDict as *const c_void;

        // SAFETY: `dict` and all its strings outlive the borrow for this whole test.
        assert_eq!(
            unsafe { dict_get(dict_ptr, "media.class") },
            Some("Video/Source")
        );
        // SAFETY: as above.
        assert_eq!(
            unsafe { dict_get(dict_ptr, "node.name") },
            Some("v4l2-input")
        );
        // SAFETY: as above — a key that is not present.
        assert_eq!(unsafe { dict_get(dict_ptr, "absent") }, None);

        // SAFETY: a null dict pointer is explicitly handled.
        assert_eq!(unsafe { dict_get(std::ptr::null(), "node.name") }, None);
        // SAFETY: `n_items > 0` with a null `items` pointer must not be dereferenced.
        let no_items = SpaDict {
            flags: 0,
            n_items: 4,
            items: std::ptr::null(),
        };
        // SAFETY: the null `items` pointer is explicitly handled.
        assert_eq!(
            unsafe { dict_get(&no_items as *const SpaDict as *const c_void, "node.name") },
            None
        );
    }

    #[test]
    fn pod_as_bytes_uses_rounded_body_size() {
        // A `spa_pod` header is `{ uint32_t size; uint32_t type; }`; the total is
        // `align_up8(8 + size)`. size = 0 -> 8 bytes, size = 1 -> 16 bytes.
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&0u32.to_ne_bytes());
        // SAFETY: `buf` holds a 16-byte pod whose reported body size is 0.
        let len0 = unsafe { pod_as_bytes(buf.as_ptr() as *const c_void) }.map(<[u8]>::len);
        assert_eq!(len0, Some(8));

        buf[0..4].copy_from_slice(&1u32.to_ne_bytes());
        // SAFETY: as above — body size 1, so the rounded total is 16 within `buf`.
        let len1 = unsafe { pod_as_bytes(buf.as_ptr() as *const c_void) }.map(<[u8]>::len);
        assert_eq!(len1, Some(16));

        // SAFETY: a null pointer is explicitly handled and returns `None`.
        assert_eq!(
            unsafe { pod_as_bytes(std::ptr::null()) }.map(<[u8]>::len),
            None
        );
    }
}
