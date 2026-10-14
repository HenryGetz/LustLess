//! Minimal, self-contained SPA pod reader/writer for the Wayland capture backend
//! (CONTRACTS §7).
//!
//! The upstream `pipewire`/`libspa` crates carry a bindgen build of the SPA ABI that cannot
//! build against the Zorin OS 17 / Ubuntu 22.04 baseline (`libpipewire` 0.3.48, `libspa` 0.2):
//! `libspa-0.10.1` needs `spa_meta_first`/`spa_meta_region_is_valid` and
//! `spa_video_info_raw.flags`, and the layout of `struct spa_video_info_raw` itself changed
//! between 0.3.48 and master. This module therefore replaces only the tiny piece of `libspa`
//! we actually needed — pod serialization/parsing of the video EnumFormat/Format object — with
//! a dependency-free implementation that works on every baseline.
//!
//! Design rules:
//! * Spa data crosses the C boundary **only as bytes**: we build the EnumFormat pod here,
//!   hand the byte buffer to `pw_stream_connect`, and parse the format pod the compositor
//!   returns with [`parse_video_info`]. No `#[repr(C)]` spa struct is ever shared with the
//!   linked library, so ABI drift in struct layouts is irrelevant.
//! * Pure safe Rust: no `unsafe`, and every read goes through `get`/`checked_*`, so malformed
//!   or hostile pod bytes yield `None` instead of a panic.
//!
//! The numeric constants below were read from the real headers (and compiled out) in both
//! `ubuntu:22.04` (`libspa-0.2-dev`, spa 0.2 / pipewire 0.3.48) and `ubuntu:24.04`
//! (pipewire 1.0.x); **the values are identical on both**, which is the version-tolerance
//! claim this module relies on. Header files consulted:
//! `/usr/include/spa-0.2/spa/utils/type.h`,
//! `/usr/include/spa-0.2/spa/param/param.h`,
//! `/usr/include/spa-0.2/spa/param/format.h`,
//! `/usr/include/spa-0.2/spa/param/video/raw.h`,
//! `/usr/include/spa-0.2/spa/pod/pod.h`.
//!
//! Wire format notes. A pod is `{ u32 size; u32 type; body[size] }` where `size` counts only
//! the body; pods are padded with zero bytes to an 8-byte boundary and the padding is *not*
//! included in `size`. The padding is written zeroed by the builder
//! (`spa_pod_builder_pad` in `spa/pod/builder.h` copies a zeroed `uint64_t`), so the bytes in
//! `[8 + size, align_up8(8 + size))` are part of the encoding and are required to be zero;
//! bytes *at or past* `align_up8(8 + size)` are outside this pod and are ignored, because the
//! pod usually arrives inside a larger, library-owned buffer. An object body is
//! `{ u32 type; u32 id; properties... }` and each property is `{ u32 key; u32 flags;
//! <value pod> }`. A choice body is `{ u32 choice_type; u32 flags; u32 child_size;
//! u32 child_type; child values... }` — the child values are packed back-to-back with **no**
//! per-value padding and **no** trailing alternative-count field (verified against
//! `spa_pod_builder_push_choice` in `spa/pod/builder.h` and against `libspa`'s Rust
//! serializer).

// ---------------------------------------------------------------------------------------------
// Pod type ids — from `spa/utils/type.h` (`enum spa_type`). Same values in 0.3.48 and 1.0.x.
// ---------------------------------------------------------------------------------------------

/// `SPA_TYPE_None` = 0x1 — `spa/utils/type.h`.
pub const SPA_TYPE_NONE: u32 = 0x1;
/// `SPA_TYPE_Bool` = 0x2 — `spa/utils/type.h`.
pub const SPA_TYPE_BOOL: u32 = 0x2;
/// `SPA_TYPE_Id` = 0x3 — `spa/utils/type.h`.
pub const SPA_TYPE_ID: u32 = 0x3;
/// `SPA_TYPE_Int` = 0x4 — `spa/utils/type.h`.
pub const SPA_TYPE_INT: u32 = 0x4;
/// `SPA_TYPE_Long` = 0x5 — `spa/utils/type.h`.
pub const SPA_TYPE_LONG: u32 = 0x5;
/// `SPA_TYPE_Float` = 0x6 — `spa/utils/type.h`.
pub const SPA_TYPE_FLOAT: u32 = 0x6;
/// `SPA_TYPE_Double` = 0x7 — `spa/utils/type.h`.
pub const SPA_TYPE_DOUBLE: u32 = 0x7;
/// `SPA_TYPE_String` = 0x8 — `spa/utils/type.h`.
pub const SPA_TYPE_STRING: u32 = 0x8;
/// `SPA_TYPE_Bytes` = 0x9 — `spa/utils/type.h`.
pub const SPA_TYPE_BYTES: u32 = 0x9;
/// `SPA_TYPE_Rectangle` = 0xa — `spa/utils/type.h`.
pub const SPA_TYPE_RECTANGLE: u32 = 0xa;
/// `SPA_TYPE_Fraction` = 0xb — `spa/utils/type.h`.
pub const SPA_TYPE_FRACTION: u32 = 0xb;
/// `SPA_TYPE_Bitmap` = 0xc — `spa/utils/type.h`.
pub const SPA_TYPE_BITMAP: u32 = 0xc;
/// `SPA_TYPE_Array` = 0xd — `spa/utils/type.h`.
pub const SPA_TYPE_ARRAY: u32 = 0xd;
/// `SPA_TYPE_Struct` = 0xe — `spa/utils/type.h`.
pub const SPA_TYPE_STRUCT: u32 = 0xe;
/// `SPA_TYPE_Object` = 0xf — `spa/utils/type.h`.
pub const SPA_TYPE_OBJECT: u32 = 0xf;
/// `SPA_TYPE_Sequence` = 0x10 — `spa/utils/type.h`.
pub const SPA_TYPE_SEQUENCE: u32 = 0x10;
/// `SPA_TYPE_Pointer` = 0x11 — `spa/utils/type.h`.
pub const SPA_TYPE_POINTER: u32 = 0x11;
/// `SPA_TYPE_Fd` = 0x12 — `spa/utils/type.h`.
pub const SPA_TYPE_FD: u32 = 0x12;
/// `SPA_TYPE_Choice` = 0x13 — `spa/utils/type.h`.
pub const SPA_TYPE_CHOICE: u32 = 0x13;
/// `SPA_TYPE_Pod` = 0x14 — `spa/utils/type.h`.
pub const SPA_TYPE_POD: u32 = 0x14;

/// `SPA_TYPE_OBJECT_Format` = 0x40003 — object type carried by format params, from
/// `spa/utils/type.h` (`SPA_TYPE_OBJECT_START = 0x40000`, then `PropInfo`, `Props`, `Format`).
pub const SPA_TYPE_OBJECT_FORMAT: u32 = 0x40003;

// ---------------------------------------------------------------------------------------------
// Param ids — from `spa/param/param.h` (`enum spa_param_type`).
// ---------------------------------------------------------------------------------------------

/// `SPA_PARAM_EnumFormat` = 0x3 — `spa/param/param.h` (`enum spa_param_type`).
pub const SPA_PARAM_ENUM_FORMAT: u32 = 0x3;
/// `SPA_PARAM_Format` = 0x4 — `spa/param/param.h`.
pub const SPA_PARAM_FORMAT: u32 = 0x4;

// ---------------------------------------------------------------------------------------------
// Format property keys — from `spa/param/format.h` (`enum spa_format`).
// ---------------------------------------------------------------------------------------------

/// `SPA_FORMAT_mediaType` = 0x1 — `spa/param/format.h`.
pub const SPA_FORMAT_MEDIA_TYPE: u32 = 0x1;
/// `SPA_FORMAT_mediaSubtype` = 0x2 — `spa/param/format.h`.
pub const SPA_FORMAT_MEDIA_SUBTYPE: u32 = 0x2;
/// `SPA_FORMAT_VIDEO_format` = 0x20001 (`SPA_FORMAT_START_Video = 0x20000` + 1) —
/// `spa/param/format.h`.
pub const SPA_FORMAT_VIDEO_FORMAT: u32 = 0x20001;
/// `SPA_FORMAT_VIDEO_size` = 0x20003 (`SPA_FORMAT_START_Video` + 3) — `spa/param/format.h`.
pub const SPA_FORMAT_VIDEO_SIZE: u32 = 0x20003;
/// `SPA_FORMAT_VIDEO_framerate` = 0x20004 (`SPA_FORMAT_START_Video` + 4) — `spa/param/format.h`.
pub const SPA_FORMAT_VIDEO_FRAMERATE: u32 = 0x20004;

// ---------------------------------------------------------------------------------------------
// Media type/subtype — from `spa/param/format.h`.
// ---------------------------------------------------------------------------------------------

/// `SPA_MEDIA_TYPE_video` = 0x2 — `spa/param/format.h` (`enum spa_media_type`).
pub const SPA_MEDIA_TYPE_VIDEO: u32 = 0x2;
/// `SPA_MEDIA_SUBTYPE_raw` = 0x1 — `spa/param/format.h` (`enum spa_media_subtype`).
pub const SPA_MEDIA_SUBTYPE_RAW: u32 = 0x1;

// ---------------------------------------------------------------------------------------------
// Video format ids — from `spa/param/video/raw.h` (`enum spa_video_format`).
// ---------------------------------------------------------------------------------------------

/// `SPA_VIDEO_FORMAT_RGBx` = 0x7 — `spa/param/video/raw.h`.
pub const SPA_VIDEO_FORMAT_RGBX: u32 = 0x7;
/// `SPA_VIDEO_FORMAT_BGRx` = 0x8 — `spa/param/video/raw.h`.
pub const SPA_VIDEO_FORMAT_BGRX: u32 = 0x8;
/// `SPA_VIDEO_FORMAT_RGBA` = 0xb — `spa/param/video/raw.h`.
pub const SPA_VIDEO_FORMAT_RGBA: u32 = 0xb;
/// `SPA_VIDEO_FORMAT_BGRA` = 0xc — `spa/param/video/raw.h`.
pub const SPA_VIDEO_FORMAT_BGRA: u32 = 0xc;
/// `SPA_VIDEO_FORMAT_RGB` = 0xf — `spa/param/video/raw.h`.
pub const SPA_VIDEO_FORMAT_RGB: u32 = 0xf;
/// `SPA_VIDEO_FORMAT_BGR` = 0x10 — `spa/param/video/raw.h`.
pub const SPA_VIDEO_FORMAT_BGR: u32 = 0x10;

// ---------------------------------------------------------------------------------------------
// Choice types — from `spa/pod/pod.h` (`enum spa_choice_type`).
// ---------------------------------------------------------------------------------------------

/// `SPA_CHOICE_None` = 0x0 — `spa/pod/pod.h`.
pub const SPA_CHOICE_NONE: u32 = 0x0;
/// `SPA_CHOICE_Range` = 0x1 — `spa/pod/pod.h`.
pub const SPA_CHOICE_RANGE: u32 = 0x1;
/// `SPA_CHOICE_Step` = 0x2 — `spa/pod/pod.h`.
pub const SPA_CHOICE_STEP: u32 = 0x2;
/// `SPA_CHOICE_Enum` = 0x3 — `spa/pod/pod.h`.
pub const SPA_CHOICE_ENUM: u32 = 0x3;
/// `SPA_CHOICE_Flags` = 0x4 — `spa/pod/pod.h`.
pub const SPA_CHOICE_FLAGS: u32 = 0x4;

/// The 6 linear raw formats we accept, in negotiation-preference order.
///
/// Every one is a plain packed/linear layout, so the compositor hands us CPU-mappable memory
/// we can read directly; DRM-modifier (`DMA-BUF`) planes are deliberately not offered. Order
/// matters: PipeWire uses the first entry as the preferred default when the compositor has no
/// better reason to pick another (CONTRACTS §7 — BGRx first, matching the X11 backend's
/// byte-order contract).
pub const SUPPORTED_VIDEO_FORMATS: [u32; 6] = [
    SPA_VIDEO_FORMAT_BGRX,
    SPA_VIDEO_FORMAT_RGBX,
    SPA_VIDEO_FORMAT_BGRA,
    SPA_VIDEO_FORMAT_RGBA,
    SPA_VIDEO_FORMAT_BGR,
    SPA_VIDEO_FORMAT_RGB,
];

/// One video format as negotiated by the compositor, parsed out of a format pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoFormatInfo {
    /// `SPA_FORMAT_VIDEO_format` id (one of [`SUPPORTED_VIDEO_FORMATS`] in practice).
    pub format: u32,
    /// `SPA_FORMAT_VIDEO_size` width.
    pub width: u32,
    /// `SPA_FORMAT_VIDEO_size` height.
    pub height: u32,
}

// ---------------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------------

/// A borrowed view of one pod: its type, its body (exactly `size` bytes, padding excluded), and
/// how far the *next* pod starts (8-byte aligned total).
struct PodRef<'a> {
    ty: u32,
    body: &'a [u8],
    /// `align_up8(8 + size)`: distance from this pod's start to the next pod.
    advance: usize,
}

/// Round `n` up to the next multiple of 8, or `None` on overflow.
fn align_up8(n: usize) -> Option<usize> {
    Some(n.checked_add(7)? & !7usize)
}

/// Read a little-endian `u32` at `off`, or `None` if it is out of bounds.
fn le_u32(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let bytes: [u8; 4] = buf.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Read a pod header + body at `off` in `buf`.
///
/// Returns `None` for a truncated pod (declared size past the end) or any arithmetic overflow.
fn read_pod(buf: &[u8], off: usize) -> Option<PodRef<'_>> {
    let size = le_u32(buf, off)? as usize;
    let ty = le_u32(buf, off.checked_add(4)?)?;
    let body_start = off.checked_add(8)?;
    let body_end = body_start.checked_add(size)?;
    let body = buf.get(body_start..body_end)?;
    let total = body_end.checked_sub(off)?; // 8 + size
    let advance = align_up8(total)?;
    Some(PodRef { ty, body, advance })
}

/// Extract an `Id` value from a pod that is either a plain `Id` or a `Choice` whose *first*
/// (default) alternative is an `Id`. Integer choice types (None/Range/Enum/…) all place the
/// default first, so this is correct for every variant a compositor may send.
fn value_as_id(pod: &PodRef<'_>) -> Option<u32> {
    match pod.ty {
        SPA_TYPE_ID => le_u32(pod.body, 0),
        SPA_TYPE_CHOICE => {
            let choice_type = le_u32(pod.body, 0)?;
            match choice_type {
                SPA_CHOICE_NONE | SPA_CHOICE_RANGE | SPA_CHOICE_STEP | SPA_CHOICE_ENUM
                | SPA_CHOICE_FLAGS => {}
                _ => return None,
            }
            let child_size = le_u32(pod.body, 8)?;
            let child_type = le_u32(pod.body, 12)?;
            if child_type != SPA_TYPE_ID || child_size != 4 {
                return None;
            }
            le_u32(pod.body, 16)
        }
        _ => None,
    }
}

/// Extract a `(width, height)` from a pod that is either a plain `Rectangle` or a `Choice`
/// whose first alternative is a `Rectangle`.
fn value_as_size(pod: &PodRef<'_>) -> Option<(u32, u32)> {
    match pod.ty {
        SPA_TYPE_RECTANGLE => {
            let width = le_u32(pod.body, 0)?;
            let height = le_u32(pod.body, 4)?;
            Some((width, height))
        }
        SPA_TYPE_CHOICE => {
            let choice_type = le_u32(pod.body, 0)?;
            match choice_type {
                SPA_CHOICE_NONE | SPA_CHOICE_RANGE | SPA_CHOICE_STEP | SPA_CHOICE_ENUM
                | SPA_CHOICE_FLAGS => {}
                _ => return None,
            }
            let child_size = le_u32(pod.body, 8)?;
            let child_type = le_u32(pod.body, 12)?;
            if child_type != SPA_TYPE_RECTANGLE || child_size != 8 {
                return None;
            }
            let width = le_u32(pod.body, 16)?;
            let height = le_u32(pod.body, 20)?;
            Some((width, height))
        }
        _ => None,
    }
}

/// Parse the video format out of a `SPA_PARAM_Format`/`EnumFormat` result pod.
///
/// Tolerates: unknown properties (skipped), properties in any order, and choice-wrapped values
/// (the first/default alternative is taken). Returns `None` for anything unexpected — wrong pod
/// or object type, missing `VIDEO_format`/`VIDEO_size`, wrong value types, truncation, or
/// non-zero bytes in its alignment padding — and never panics on malformed input. Bytes after
/// the pod's aligned end are ignored.
pub fn parse_video_info(pod_bytes: &[u8]) -> Option<VideoFormatInfo> {
    let pod = read_pod(pod_bytes, 0)?;
    if pod.ty != SPA_TYPE_OBJECT {
        return None;
    }
    // The pod's authored bytes run to `total`; the builder zeroes the internal alignment
    // padding out to the 8-byte aligned end (`spa_pod_builder_pad` in `spa/pod/builder.h`
    // writes a zeroed `uint64_t`). Anything *past* that aligned end belongs to whatever else
    // the caller's buffer holds (`param_changed` hands us a library-owned buffer, not a
    // single-pod allocation) and must be ignored, not rejected.
    let total = pod.body.len().checked_add(8)?;
    let aligned = align_up8(total)?;
    let gap_end = aligned.min(pod_bytes.len());
    match pod_bytes.get(total..gap_end) {
        Some(gap) if gap.iter().all(|&b| b == 0) => {}
        _ => return None,
    }

    let obj_type = le_u32(pod.body, 0)?;
    if obj_type != SPA_TYPE_OBJECT_FORMAT {
        return None;
    }
    let _obj_id = le_u32(pod.body, 4)?;

    let mut format = None;
    let mut size = None;
    let mut off = 8usize;
    while off < pod.body.len() {
        let key = le_u32(pod.body, off)?;
        // Property flags are not interesting here, but must exist.
        let _flags = le_u32(pod.body, off.checked_add(4)?)?;
        let value_off = off.checked_add(8)?;
        let value = read_pod(pod.body, value_off)?;
        match key {
            SPA_FORMAT_VIDEO_FORMAT => format = Some(value_as_id(&value)?),
            SPA_FORMAT_VIDEO_SIZE => size = Some(value_as_size(&value)?),
            _ => {}
        }
        off = value_off.checked_add(value.advance)?;
    }

    let (width, height) = size?;
    Some(VideoFormatInfo {
        format: format?,
        width,
        height,
    })
}

// ---------------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------------

/// Append a little-endian `u32`.
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Serialize one pod (header + body + zero padding to an 8-byte boundary). The `size` field
/// counts only `body`, matching `spa_pod_builder`.
fn pod_of(ty: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len().saturating_add(16));
    // Bodies constructed here are tiny fixed sizes, far below u32::MAX.
    push_u32(&mut out, body.len() as u32);
    push_u32(&mut out, ty);
    out.extend_from_slice(body);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out
}

/// A plain `Id` value pod.
fn id_pod(id: u32) -> Vec<u8> {
    pod_of(SPA_TYPE_ID, &id.to_le_bytes())
}

/// A `Choice` value pod. `children` is the already-packed sequence of child values (each exactly
/// `child_size` bytes, back-to-back, no padding) as produced by `spa_pod_builder`.
fn choice_pod(choice_type: u32, child_type: u32, child_size: u32, children: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(children.len().saturating_add(16));
    push_u32(&mut body, choice_type);
    push_u32(&mut body, 0); // choice flags
    push_u32(&mut body, child_size);
    push_u32(&mut body, child_type);
    body.extend_from_slice(children);
    pod_of(SPA_TYPE_CHOICE, &body)
}

/// Append a property (`{ key; flags; value pod }`) to an object body. `value_pod` must already
/// be 8-byte padded so the object body stays aligned.
fn push_prop(out: &mut Vec<u8>, key: u32, value_pod: &[u8]) {
    push_u32(out, key);
    push_u32(out, 0); // property flags
    out.extend_from_slice(value_pod);
}

/// Build the EnumFormat object pod we hand to `pw_stream_connect`.
///
/// Shape (matching what the previous `pipewire`-crate backend negotiated):
/// `mediaType = video`, `mediaSubtype = raw`, `VIDEO_format` = an `Enum` choice defaulting to
/// [`SPA_VIDEO_FORMAT_BGRX`] with all of [`SUPPORTED_VIDEO_FORMATS`] as alternatives,
/// `VIDEO_size` = a `Range` choice from `1x1` to `u32::MAX x u32::MAX` with `size` as the
/// default, and `VIDEO_framerate` = a `None` choice of `0/1` (let the compositor choose).
pub fn enum_format_pod(size: (u32, u32)) -> Vec<u8> {
    let mut props = Vec::new();

    push_prop(
        &mut props,
        SPA_FORMAT_MEDIA_TYPE,
        &id_pod(SPA_MEDIA_TYPE_VIDEO),
    );
    push_prop(
        &mut props,
        SPA_FORMAT_MEDIA_SUBTYPE,
        &id_pod(SPA_MEDIA_SUBTYPE_RAW),
    );

    let mut format_children = Vec::with_capacity(SUPPORTED_VIDEO_FORMATS.len() * 4);
    for format in SUPPORTED_VIDEO_FORMATS {
        format_children.extend_from_slice(&format.to_le_bytes());
    }
    push_prop(
        &mut props,
        SPA_FORMAT_VIDEO_FORMAT,
        &choice_pod(SPA_CHOICE_ENUM, SPA_TYPE_ID, 4, &format_children),
    );

    let mut size_children = Vec::with_capacity(3 * 8);
    for (w, h) in [(size.0, size.1), (1, 1), (u32::MAX, u32::MAX)] {
        size_children.extend_from_slice(&w.to_le_bytes());
        size_children.extend_from_slice(&h.to_le_bytes());
    }
    push_prop(
        &mut props,
        SPA_FORMAT_VIDEO_SIZE,
        &choice_pod(SPA_CHOICE_RANGE, SPA_TYPE_RECTANGLE, 8, &size_children),
    );

    let mut framerate_children = Vec::with_capacity(8);
    framerate_children.extend_from_slice(&0u32.to_le_bytes()); // num
    framerate_children.extend_from_slice(&1u32.to_le_bytes()); // denom
    push_prop(
        &mut props,
        SPA_FORMAT_VIDEO_FRAMERATE,
        &choice_pod(SPA_CHOICE_NONE, SPA_TYPE_FRACTION, 8, &framerate_children),
    );

    let mut obj_body = Vec::with_capacity(props.len().saturating_add(8));
    push_u32(&mut obj_body, SPA_TYPE_OBJECT_FORMAT);
    push_u32(&mut obj_body, SPA_PARAM_ENUM_FORMAT);
    obj_body.extend_from_slice(&props);
    pod_of(SPA_TYPE_OBJECT, &obj_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_requested_size_and_default_format() {
        for size in [(1920, 1080), (1, 1), (640, 480), (u32::MAX, u32::MAX)] {
            let pod = enum_format_pod(size);
            assert_eq!(
                parse_video_info(&pod),
                Some(VideoFormatInfo {
                    format: SPA_VIDEO_FORMAT_BGRX,
                    width: size.0,
                    height: size.1,
                }),
                "size {size:?}"
            );
        }
    }

    /// Start from a valid EnumFormat pod and rewrite it as an object carrying an extra unknown
    /// property first, `VIDEO_format` as a plain (non-choice) `Id`, `VIDEO_size` as a plain
    /// `Rectangle`, and the keys in an unusual order — proving the parser tolerates all of it.
    #[test]
    fn parses_tolerant_fixture_with_unknown_property_and_shuffled_order() {
        let mut props = Vec::new();

        // Unknown property with an Int value the parser must skip.
        push_prop(
            &mut props,
            0x9999,
            &pod_of(SPA_TYPE_INT, &7i32.to_le_bytes()),
        );

        // VIDEO_size as a plain Rectangle (64x48).
        let mut rect = Vec::with_capacity(8);
        rect.extend_from_slice(&64u32.to_le_bytes());
        rect.extend_from_slice(&48u32.to_le_bytes());
        push_prop(
            &mut props,
            SPA_FORMAT_VIDEO_SIZE,
            &pod_of(SPA_TYPE_RECTANGLE, &rect),
        );

        // Another unknown property with a String-ish shape after the key we care about.
        push_prop(
            &mut props,
            0xabcd,
            &pod_of(SPA_TYPE_ID, &123u32.to_le_bytes()),
        );

        // VIDEO_format as a plain Id (RGBA, id 0xb).
        push_prop(
            &mut props,
            SPA_FORMAT_VIDEO_FORMAT,
            &id_pod(SPA_VIDEO_FORMAT_RGBA),
        );

        let mut obj_body = Vec::new();
        push_u32(&mut obj_body, SPA_TYPE_OBJECT_FORMAT);
        push_u32(&mut obj_body, SPA_PARAM_FORMAT);
        obj_body.extend_from_slice(&props);
        let pod = pod_of(SPA_TYPE_OBJECT, &obj_body);

        assert_eq!(
            parse_video_info(&pod),
            Some(VideoFormatInfo {
                format: SPA_VIDEO_FORMAT_RGBA,
                width: 64,
                height: 48,
            })
        );
    }

    #[test]
    fn every_truncated_prefix_returns_none() {
        let pod = enum_format_pod((800, 600));
        assert!(parse_video_info(&pod).is_some());
        for len in 0..pod.len() {
            assert!(
                parse_video_info(&pod[..len]).is_none(),
                "prefix of length {len} must not parse"
            );
        }
    }

    #[test]
    fn declared_size_past_buffer_returns_none() {
        let mut pod = enum_format_pod((800, 600));
        // Inflate the top-level body size far past the buffer.
        pod[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_video_info(&pod).is_none());
    }

    #[test]
    fn empty_slice_returns_none() {
        assert!(parse_video_info(&[]).is_none());
    }

    /// A valid object pod whose declared body length is `4 mod 8`, so the top-level pod has a
    /// 4-byte alignment gap: the last property is an `Int` value pod whose own trailing padding
    /// is the top-level pod's padding (this is how `spa_pod_builder_pop` lays pods out — the
    /// pad bytes are charged to the parent). `pod_of` zeroes that gap.
    fn pod_with_padding_gap() -> Vec<u8> {
        let mut props = Vec::new();

        push_prop(
            &mut props,
            SPA_FORMAT_VIDEO_FORMAT,
            &id_pod(SPA_VIDEO_FORMAT_BGRX),
        );

        let mut rect = Vec::with_capacity(8);
        rect.extend_from_slice(&64u32.to_le_bytes());
        rect.extend_from_slice(&48u32.to_le_bytes());
        push_prop(
            &mut props,
            SPA_FORMAT_VIDEO_SIZE,
            &pod_of(SPA_TYPE_RECTANGLE, &rect),
        );

        // Unsupported `Int` property, last, with its 4-byte value body and no per-pod padding.
        let mut int_pod = Vec::new();
        push_u32(&mut int_pod, 4);
        push_u32(&mut int_pod, SPA_TYPE_INT);
        int_pod.extend_from_slice(&7i32.to_le_bytes());
        push_prop(&mut props, 0x1234, &int_pod);

        let mut obj_body = Vec::new();
        push_u32(&mut obj_body, SPA_TYPE_OBJECT_FORMAT);
        push_u32(&mut obj_body, SPA_PARAM_FORMAT);
        obj_body.extend_from_slice(&props);
        pod_of(SPA_TYPE_OBJECT, &obj_body)
    }

    #[test]
    fn bytes_after_the_aligned_end_are_ignored() {
        // A library-owned buffer can hold other data right after the pod; those bytes must not
        // make a valid negotiated format fail to parse.
        let mut pod = enum_format_pod((800, 600));
        let aligned = align_up8(pod.len()).unwrap_or(pod.len());
        assert_eq!(aligned, pod.len(), "self-produced pod is already 8-aligned");
        pod.extend_from_slice(&[0xff, 0xee, 0xdd, 0xcc]);
        assert_eq!(
            parse_video_info(&pod),
            Some(VideoFormatInfo {
                format: SPA_VIDEO_FORMAT_BGRX,
                width: 800,
                height: 600,
            })
        );
    }

    #[test]
    fn non_zero_byte_inside_the_padding_gap_returns_none() {
        let pod = pod_with_padding_gap();
        let total = le_u32(&pod, 0).unwrap_or(0) as usize + 8;
        let aligned = align_up8(total).unwrap_or(total);
        assert!(aligned > total, "fixture must have an internal padding gap");

        // Zeroed gap: valid.
        assert_eq!(
            parse_video_info(&pod),
            Some(VideoFormatInfo {
                format: SPA_VIDEO_FORMAT_BGRX,
                width: 64,
                height: 48,
            })
        );

        // Non-zero byte inside the gap: rejected.
        let mut bad = pod.clone();
        bad[total] = 0xff;
        assert!(parse_video_info(&bad).is_none());
    }

    #[test]
    fn wrong_object_type_returns_none() {
        let mut pod = enum_format_pod((800, 600));
        // Object body type lives at offset 8 in the buffer.
        pod[8..12].copy_from_slice(&SPA_TYPE_OBJECT.to_le_bytes());
        assert!(parse_video_info(&pod).is_none());
    }
}
