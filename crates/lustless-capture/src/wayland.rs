//! Wayland capture backend (CONTRACTS §7): xdg-desktop-portal ScreenCast via `ashpd` plus
//! PipeWire stream consumption via `pipewire` — real frame extraction from the negotiated
//! CPU-mapped buffers (we negotiate only linear raw formats, so the compositor always hands
//! us memory we can read; DRM modifier planes are rejected by our format list).
//!
//! Architecture: one long-lived ScreenCast session per backend (a 30 s cadence that recreated
//! the session would re-prompt the user; a held session keeps the compositor's consent),
//! with a dedicated PipeWire mainloop thread. Each `capture()` takes the freshest frame per
//! stream.
//!
//! Wayland exposes no global window enumeration, so `apps[]` gets one synthetic entry per
//! monitor — the classifier's full-frame fallback covers per-window semantics. Protected
//! surfaces (PipeWire nodes flagged `restricted`/`securityContext` by the compositor) mark
//! the entry `doNotScore: true` (flag, don't abort — §7).

use std::collections::HashMap;
use std::future::Future;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use ashpd::desktop::screencast::{
    CursorMode, OpenPipeWireRemoteOptions, Screencast, SelectSourcesOptions, SourceType,
};
use image::{Rgb, RgbImage};
use pipewire::channel::Sender as PwSender;
use pipewire::context::ContextRc;
use pipewire::main_loop::MainLoopRc;
use pipewire::properties::properties;
use pipewire::spa::param::format::{FormatProperties, MediaSubtype, MediaType};
use pipewire::spa::param::video::{VideoFormat, VideoInfoRaw};
use pipewire::spa::param::ParamType;
use pipewire::spa::pod::serialize::PodSerializer;
use pipewire::spa::pod::{object, property, ChoiceValue, Object as PodObject, Pod, Value};
use pipewire::spa::utils::{
    Choice, ChoiceEnum, ChoiceFlags, Direction, Fraction, Id, Rectangle, SpaTypes,
};
use pipewire::stream::{StreamFlags, StreamListener, StreamRc};

use crate::manifest::Rect;
use crate::{Capture, CaptureBackend, CaptureError, CapturedApp, CapturedMonitor};

/// How long a capture waits for every stream to deliver a fresh frame.
const FRAME_WAIT: Duration = Duration::from_secs(3);

/// The Wayland capture backend (portal session + PipeWire thread are created lazily on the
/// first capture).
pub struct WaylandBackend {
    state: Option<SessionState>,
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
    session: ashpd::desktop::Session<Screencast>,
    /// Streams reported by the portal (see [`PortalStream`]).
    streams: Vec<PortalStream>,
    thread: JoinHandle<()>,
    commands: PwSender<LoopCommand>,
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
#[derive(Clone, Copy, PartialEq, Eq)]
enum WireFormat {
    Bgrx,
    Rgbx,
    Bgra,
    Rgba,
    Bgr,
    Rgb,
}

#[derive(Clone)]
struct WireFrame {
    data: Vec<u8>,
    width: u32,
    height: u32,
    format: WireFormat,
}

/// Commands sent to the PipeWire mainloop thread.
enum LoopCommand {
    /// Connect a capture stream to a portal-provided node.
    Connect {
        node_id: u32,
        name: String,
        size: (u32, u32),
    },
    /// Stop the loop and exit the thread.
    Quit,
}

/// Per-stream state owned by the PipeWire thread.
struct StreamUser {
    node_id: u32,
    negotiated: Option<(u32, u32, WireFormat)>,
    shared: Arc<Shared>,
}

impl WaylandBackend {
    /// Prepare a backend; the portal session is created on the first capture.
    pub fn new() -> Result<Self, CaptureError> {
        pipewire::init();
        Ok(Self { state: None })
    }

    /// Establish the portal session and the PipeWire loop thread (idempotent).
    async fn ensure_session(&mut self) -> Result<&mut SessionState, CaptureError> {
        if self.state.is_none() {
            let portal = Screencast::new()
                .await
                .map_err(|e| CaptureError::Portal(format!("Screencast::new: {e}")))?;
            let session = portal
                .create_session(Default::default())
                .await
                .map_err(|e| CaptureError::Portal(format!("create_session: {e}")))?;
            portal
                .select_sources(
                    &session,
                    SelectSourcesOptions::default()
                        .set_sources(Some(SourceType::Monitor.into()))
                        .set_cursor_mode(CursorMode::Embedded)
                        .set_multiple(true),
                )
                .await
                .map_err(|e| CaptureError::Portal(format!("select_sources: {e}")))?;
            let streams = portal
                .start(&session, None, Default::default())
                .await
                .map_err(|e| CaptureError::Portal(format!("start: {e}")))?
                .response()
                .map_err(|e| CaptureError::Portal(format!("start response: {e}")))?
                .streams()
                .iter()
                .map(|stream| {
                    (
                        stream.pipe_wire_node_id(),
                        stream
                            .size()
                            .map(|(width, height)| (width as u32, height as u32)),
                        stream.position(),
                    )
                })
                .collect::<Vec<_>>();
            if streams.is_empty() {
                return Err(CaptureError::NoSource(
                    "ScreenCast returned no streams (selection denied or no outputs)".into(),
                ));
            }
            let pw_fd = portal
                .open_pipe_wire_remote(&session, OpenPipeWireRemoteOptions::default())
                .await
                .map_err(|e| CaptureError::Portal(format!("open_pipe_wire_remote: {e}")))?;
            // Transfer the raw fd into a std OwnedFd without an extra dup.
            let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(pw_fd.into_raw_fd()) };

            let shared = Arc::new(Shared::default());
            let (commands, thread) = spawn_pipewire_loop(owned, Arc::clone(&shared))?;

            let state = SessionState {
                portal,
                session,
                streams,
                thread,
                commands,
                shared,
                last_seq: HashMap::new(),
            };
            // Ask the loop thread to connect one stream per portal stream.
            for (node_id, size, _) in &state.streams {
                let (width, height) = size.unwrap_or((1920, 1080));
                let _ = state.commands.send(LoopCommand::Connect {
                    node_id: *node_id,
                    name: format!("lustless-capture-{node_id}"),
                    size: (width, height),
                });
            }
            log::info!(
                "capture: wayland ScreenCast session established with {} stream(s)",
                state.streams.len()
            );
            self.state = Some(state);
        }
        Ok(self.state.as_mut().expect("just inserted"))
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
                let dead = self.state.take().expect("state present");
                dead.shutdown();
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
                let dead = self.state.take().expect("state present");
                dead.shutdown();
                return Err(CaptureError::NoSource(
                    "no Wayland stream produced a usable frame".into(),
                ));
            }
            Ok(capture)
        })
    }
}

impl SessionState {
    /// Stop the PipeWire thread (the portal session object is dropped with the backend; the
    /// portal closes it when our D-Bus name disappears).
    fn shutdown(self) {
        let _ = self.commands.send(LoopCommand::Quit);
        let _ = self.thread.join();
    }
}

impl Drop for WaylandBackend {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.shutdown();
        }
    }
}

/// Decode a wire frame into an RGB image.
fn wire_to_rgb(frame: &WireFrame) -> Result<RgbImage, String> {
    let (width, height) = (frame.width, frame.height);
    let channels = match frame.format {
        WireFormat::Bgrx | WireFormat::Rgbx | WireFormat::Bgra | WireFormat::Rgba => 4,
        WireFormat::Bgr | WireFormat::Rgb => 3,
    };
    let stride = width as usize * channels;
    stride
        .checked_mul(height as usize)
        .filter(|total| *total <= frame.data.len())
        .ok_or_else(|| {
            format!(
                "short frame (need {stride}x{height}, got {})",
                frame.data.len()
            )
        })?;
    let mut image = RgbImage::new(width, height);
    for row in 0..height as usize {
        let line = &frame.data[row * stride..];
        for col in 0..width as usize {
            let px = &line[col * channels..];
            let rgb = match frame.format {
                WireFormat::Bgrx | WireFormat::Bgra | WireFormat::Bgr => Rgb([px[2], px[1], px[0]]),
                WireFormat::Rgbx | WireFormat::Rgba | WireFormat::Rgb => Rgb([px[0], px[1], px[2]]),
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

/// Build the EnumFormat pod: raw video, BGRx/RGBx/RGBA/BGRA/RGB/BGR, any size, any framerate.
fn format_pod(size: (u32, u32)) -> PodObject {
    let formats = [
        VideoFormat::BGRx,
        VideoFormat::RGBx,
        VideoFormat::BGRA,
        VideoFormat::RGBA,
        VideoFormat::BGR,
        VideoFormat::RGB,
    ];
    object! {
        SpaTypes::ObjectParamFormat,
        ParamType::EnumFormat,
        property!(FormatProperties::MediaType, Id, MediaType::Video),
        property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        property!(
            FormatProperties::VideoFormat,
            Choice,
            ChoiceValue::Id(Choice(
                ChoiceFlags::empty(),
                ChoiceEnum::Enum {
                    default: Id(formats[0].as_raw()),
                    alternatives: formats.iter().map(|f| Id(f.as_raw())).collect(),
                },
            ))
        ),
        property!(
            FormatProperties::VideoSize,
            Choice,
            ChoiceValue::Rectangle(Choice(
                ChoiceFlags::empty(),
                ChoiceEnum::Range {
                    default: Rectangle { width: size.0, height: size.1 },
                    min: Rectangle { width: 1, height: 1 },
                    max: Rectangle { width: u32::MAX, height: u32::MAX },
                },
            ))
        ),
        property!(
            FormatProperties::VideoFramerate,
            Choice,
            ChoiceValue::Fraction(Choice(
                ChoiceFlags::empty(),
                ChoiceEnum::None(Fraction { num: 0, denom: 1 }),
            ))
        ),
    }
}

/// Spawn the PipeWire mainloop thread bound to the portal-provided remote fd. Returns the
/// command sender (created inside the loop thread and ferried out) plus the join handle.
fn spawn_pipewire_loop(
    remote_fd: std::os::fd::OwnedFd,
    shared: Arc<Shared>,
) -> Result<(PwSender<LoopCommand>, JoinHandle<()>), CaptureError> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<PwSender<LoopCommand>>();
    let thread_shared = Arc::clone(&shared);
    let thread = std::thread::Builder::new()
        .name("lustless-pipewire".into())
        .spawn(move || {
            let mainloop = match MainLoopRc::new(None) {
                Ok(mainloop) => mainloop,
                Err(e) => {
                    *thread_shared.error.lock() = Some(format!("MainLoop::new: {e}"));
                    return;
                }
            };
            let context = match ContextRc::new(&mainloop, None) {
                Ok(context) => context,
                Err(e) => {
                    *thread_shared.error.lock() = Some(format!("Context::new: {e}"));
                    return;
                }
            };
            let core = match context.connect_fd_rc(remote_fd, None) {
                Ok(core) => core,
                Err(e) => {
                    *thread_shared.error.lock() = Some(format!("connect_fd: {e}"));
                    return;
                }
            };

            let (sender, receiver) = pipewire::channel::channel::<LoopCommand>();
            if ready_tx.send(sender).is_err() {
                // The capturing thread went away; nothing to serve.
                return;
            }

            // Registry listener: record `restricted`/`securityContext` node properties so
            // protected surfaces can be flagged doNotScore.
            let registry_shared = Arc::clone(&thread_shared);
            let registry = match core.get_registry_rc() {
                Ok(registry) => registry,
                Err(e) => {
                    *thread_shared.error.lock() = Some(format!("get_registry: {e}"));
                    return;
                }
            };
            let _registry_listener = registry
                .add_listener_local()
                .global(move |global| {
                    if global.type_ != pipewire::types::ObjectType::Node {
                        return;
                    }
                    let Some(props) = global.props else { return };
                    let restricted = props
                        .get("restricted")
                        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("yes"))
                        || props
                            .get("securityContext")
                            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("yes"));
                    if restricted {
                        registry_shared.restricted.lock().insert(global.id, true);
                    }
                })
                .register();

            let streams: std::cell::RefCell<Vec<(StreamRc, StreamListener<StreamUser>)>> =
                std::cell::RefCell::new(Vec::new());
            let loop_shared = Arc::clone(&thread_shared);
            let loop_mainloop = mainloop.clone();
            let loop_core = core.clone();
            let _receiver = receiver.attach(mainloop.loop_(), move |command| match command {
                LoopCommand::Connect {
                    node_id,
                    name,
                    size,
                } => {
                    let result = connect_stream(
                        loop_core.clone(),
                        &mut streams.borrow_mut(),
                        node_id,
                        &name,
                        size,
                        Arc::clone(&loop_shared),
                    );
                    if let Err(e) = result {
                        *loop_shared.error.lock() = Some(format!("stream connect {node_id}: {e}"));
                        loop_mainloop.quit();
                    }
                }
                LoopCommand::Quit => loop_mainloop.quit(),
            });

            mainloop.run();
        })
        .map_err(|e| CaptureError::PipeWire(format!("spawn loop thread: {e}")))?;
    let sender = ready_rx
        .recv()
        .map_err(|_| CaptureError::PipeWire("pipewire loop thread exited early".into()))?;
    Ok((sender, thread))
}

/// Create, configure and connect one capture stream inside the loop thread.
fn connect_stream(
    core: pipewire::core::CoreRc,
    streams: &mut Vec<(StreamRc, StreamListener<StreamUser>)>,
    node_id: u32,
    name: &str,
    size: (u32, u32),
    shared: Arc<Shared>,
) -> Result<(), String> {
    let props = properties! {
        "media.type" => "Video",
        "media.category" => "Capture",
        "media.role" => "Screen",
    };
    let stream = StreamRc::new(core, name, props).map_err(|e| e.to_string())?;
    let user = StreamUser {
        node_id,
        negotiated: None,
        shared,
    };
    let listener = stream
        .add_local_listener_with_user_data(user)
        .state_changed(|_stream, user, _old, new| {
            if let pipewire::stream::StreamState::Error(err) = &new {
                *user.shared.error.lock() = Some(format!("stream {} error: {err}", user.node_id));
            }
        })
        .param_changed(|stream, user, _id, param| {
            let Some(param) = param else { return };
            let mut info = VideoInfoRaw::new();
            if info.parse(param).is_ok() {
                let format = match info.format() {
                    VideoFormat::BGRx => WireFormat::Bgrx,
                    VideoFormat::RGBx => WireFormat::Rgbx,
                    VideoFormat::BGRA => WireFormat::Bgra,
                    VideoFormat::RGBA => WireFormat::Rgba,
                    VideoFormat::BGR => WireFormat::Bgr,
                    VideoFormat::RGB => WireFormat::Rgb,
                    other => {
                        log::error!(
                            "capture: negotiated unsupported video format {:?} on stream {}",
                            other,
                            stream.name()
                        );
                        return;
                    }
                };
                let size = info.size();
                user.negotiated = Some((size.width, size.height, format));
            }
        })
        .process(|stream, user| {
            let Some((width, height, format)) = user.negotiated else {
                return;
            };
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let Some(data) = buffer.datas_mut().first_mut().and_then(|d| d.data()) else {
                return;
            };
            let channels = match format {
                WireFormat::Bgrx | WireFormat::Rgbx | WireFormat::Bgra | WireFormat::Rgba => 4,
                WireFormat::Bgr | WireFormat::Rgb => 3,
            };
            let wanted = width as usize * height as usize * channels;
            let take = data.len().min(wanted);
            let frame = WireFrame {
                data: data[..take].to_vec(),
                width,
                height,
                format,
            };
            let mut slots = user.shared.frames.lock();
            let slot = slots.entry(user.node_id).or_insert(FrameSlot {
                seq: 0,
                frame: frame.clone(),
            });
            slot.seq += 1;
            slot.frame = frame;
            drop(slots);
            user.shared.cv.notify_all();
        })
        .register()
        .map_err(|e| e.to_string())?;

    let pod_bytes: Vec<u8> = PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &Value::Object(format_pod(size)),
    )
    .map_err(|e| format!("format pod serialization: {e:?}"))?
    .0
    .into_inner();
    let pod = Pod::from_bytes(&pod_bytes).ok_or_else(|| "format pod reparse failed".to_string())?;
    let mut params = [pod];
    stream
        .connect(
            Direction::Input,
            Some(node_id),
            StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS | StreamFlags::DRIVER,
            &mut params,
        )
        .map_err(|e| e.to_string())?;
    streams.push((stream, listener));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_to_rgb_decodes_bgrx_and_rgb() {
        // 2x1 BGRx: [B,G,R,x] per pixel.
        let frame = WireFrame {
            data: vec![1, 2, 3, 0, 40, 50, 60, 0],
            width: 2,
            height: 1,
            format: WireFormat::Bgrx,
        };
        let img = wire_to_rgb(&frame).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [3, 2, 1]);
        assert_eq!(img.get_pixel(1, 0).0, [60, 50, 40]);

        let frame = WireFrame {
            data: vec![9, 8, 7],
            width: 1,
            height: 1,
            format: WireFormat::Rgb,
        };
        let img = wire_to_rgb(&frame).unwrap();
        assert_eq!(img.get_pixel(0, 0).0, [9, 8, 7]);
    }

    #[test]
    fn wire_to_rgb_rejects_short_buffers() {
        let frame = WireFrame {
            data: vec![0u8; 7],
            width: 2,
            height: 1,
            format: WireFormat::Bgrx,
        };
        assert!(wire_to_rgb(&frame).is_err());
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
            slots.insert(
                7,
                FrameSlot {
                    seq: 3,
                    frame: WireFrame {
                        data: vec![0u8; 4],
                        width: 1,
                        height: 1,
                        format: WireFormat::Bgrx,
                    },
                },
            );
        }
        // seq 3 > last_seq 2 => delivered.
        assert!(wait_for_frame(&shared, 7, 2, Duration::ZERO).is_some());
        // seq 3 > last_seq 3 is false => nothing fresh.
        assert!(wait_for_frame(&shared, 7, 3, Duration::ZERO).is_none());
    }
}
