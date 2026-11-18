//! Small GDI canvas and deterministic journal projection.
//!
//! Input collection never runs from the redraw path. The only rendered source
//! in this milestone is an explicitly provisional direct WM_POINTER stream;
//! public Winit and Wintab records are not blended into it.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};
use tiny_skia::{
    Color, ColorSpace, FillRule, IntSize, LineCap, LineJoin, Paint, PathBuilder, Pixmap, Stroke,
    Transform as RasterTransform,
};

use crate::journal::{
    EditCommand, JournalError, JournalMetadata, JournalReplayState, MetadataScope, NativeTimestamp,
    PhysicalSample, RawPosition, RawPressure, StrokeRef, StrokeViewFrame,
};
use crate::win32_pointer::{
    DirectPenHistoryBatch, LifecycleEventKind, OwnedPointerSample, PointerMessageKind,
};

pub(crate) const PROVISIONAL_DIRECT_SOURCE_API: &str = "direct-wm-pointer-pen-history";
const SCREEN_POSITION_SPACE: &str = "windows-screen-coordinates";
const SCREEN_POSITION_UNITS: &str = "screen-pixel";
const ORIGIN_X_KEY: &str = "canvas-origin-x-screen-px";
const ORIGIN_Y_KEY: &str = "canvas-origin-y-screen-px";
const MAX_CANVAS_STROKES: usize = 16_384;
const MAX_POINTS_PER_STROKE: usize = 131_072;
const MAX_VISIBLE_POINTS: usize = 131_072;
const MAX_ACTIVE_DIRECT_STROKES: usize = 256;
// Keep the projection plan within the current bounded provider-view limits.
const MAX_CANONICAL_RASTER_STROKES: usize = 512;
const MAX_CANONICAL_RASTER_SAMPLES: usize = 4096;
const MAX_CANONICAL_RASTER_RAW_SAMPLE_BYTES: usize = 1024 * 1024;
const MAX_CANONICAL_RASTER_SINGLE_SAMPLE_BYTES: usize = 8192;
const MAX_CANONICAL_RASTER_OUTPUT_DIMENSION: u32 = 2048;
const MAX_CANONICAL_RASTER_OUTPUT_PIXELS: u64 = 262_144;
const MAX_CANONICAL_RASTER_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_CANONICAL_RASTER_PNG_BYTES: usize = 2 * 1024 * 1024;
const MAX_CANONICAL_RASTER_CROP_DIMENSION: u64 = 1_048_576;
const MAX_CANONICAL_RASTER_CROP_AREA: u64 = 67_108_864;
const CANONICAL_RASTER_FIXED_ONE: i128 = 1 << 16;
const CANONICAL_RASTER_BYTES_PER_PIXEL: u32 = 4;
const CANONICAL_RASTER_BACKGROUND_RGBA: [u8; 4] = [255, 255, 255, 255];
const CANONICAL_RASTER_INK_RGBA: [u8; 4] = [32, 32, 32, 255];
const CANONICAL_RASTER_INK_WIDTH_16_16: u32 = 2 << 16;
const CANONICAL_RASTER_RENDERER_VERSION: &str = "tiny-skia/0.12.0;canonical-raster-v1";
const TOOLBAR_HEIGHT: i32 = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanvasTool {
    Pen,
    Eraser,
    Select,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CanvasOrigin {
    pub x_screen_px: i64,
    pub y_screen_px: i64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct CanvasViewport {
    zoom: f64,
    pan_x: f64,
    pan_y: f64,
}

impl Default for CanvasViewport {
    fn default() -> Self {
        Self {
            zoom: 1.0,
            pan_x: 0.0,
            pan_y: 0.0,
        }
    }
}

impl CanvasViewport {
    pub(crate) fn zoom(&self) -> f64 {
        self.zoom
    }

    pub(crate) fn pan(&self) -> (f64, f64) {
        (self.pan_x, self.pan_y)
    }

    pub(crate) fn stroke_view_frame(
        self,
        origin: CanvasOrigin,
        dpi_scale_factor: f64,
    ) -> Result<StrokeViewFrame, CanvasError> {
        let frame = StrokeViewFrame {
            screen_origin_x_px: origin.x_screen_px,
            screen_origin_y_px: origin.y_screen_px,
            dpi_scale_factor_bits: dpi_scale_factor.to_bits(),
            canvas_zoom_bits: self.zoom.to_bits(),
            canvas_pan_x_bits: self.pan_x.to_bits(),
            canvas_pan_y_bits: self.pan_y.to_bits(),
            toolbar_height_px: TOOLBAR_HEIGHT as u32,
        };
        if !frame.is_valid() {
            return Err(CanvasError::InvalidTransform);
        }
        Ok(frame)
    }

    pub(crate) fn pan_by(&mut self, delta_x: f64, delta_y: f64) -> Result<(), CanvasError> {
        if !delta_x.is_finite() || !delta_y.is_finite() {
            return Err(CanvasError::InvalidTransform);
        }
        let pan_x = self.pan_x + delta_x;
        let pan_y = self.pan_y + delta_y;
        if !pan_x.is_finite() || !pan_y.is_finite() {
            return Err(CanvasError::InvalidTransform);
        }
        self.pan_x = pan_x;
        self.pan_y = pan_y;
        Ok(())
    }

    /// Zooms around a client-space anchor so the world point under the anchor
    /// stays fixed. Zoom is bounded to keep numeric projection well behaved.
    pub(crate) fn zoom_about(
        &mut self,
        anchor_x: f64,
        anchor_y: f64,
        factor: f64,
    ) -> Result<(), CanvasError> {
        if !anchor_x.is_finite() || !anchor_y.is_finite() || !factor.is_finite() || factor <= 0.0 {
            return Err(CanvasError::InvalidTransform);
        }
        let world_x = (anchor_x - self.pan_x) / self.zoom;
        let world_y = (anchor_y - self.pan_y - f64::from(TOOLBAR_HEIGHT)) / self.zoom;
        let zoom = (self.zoom * factor).clamp(0.2, 8.0);
        let pan_x = anchor_x - world_x * zoom;
        let pan_y = anchor_y - f64::from(TOOLBAR_HEIGHT) - world_y * zoom;
        if !zoom.is_finite() || !pan_x.is_finite() || !pan_y.is_finite() {
            return Err(CanvasError::InvalidTransform);
        }
        self.zoom = zoom;
        self.pan_x = pan_x;
        self.pan_y = pan_y;
        Ok(())
    }

    fn map_raw_point(
        &self,
        position: &RawPosition,
        origin: CanvasOrigin,
    ) -> Result<CanvasPointPx, CanvasError> {
        if position.coordinate_space != SCREEN_POSITION_SPACE
            || position.units != SCREEN_POSITION_UNITS
        {
            return Err(CanvasError::UnsupportedCoordinateSpace {
                coordinate_space: position.coordinate_space.clone(),
                units: position.units.clone(),
            });
        }
        let document_x = position
            .x_raw
            .checked_sub(origin.x_screen_px)
            .ok_or(CanvasError::InvalidTransform)? as f64;
        let document_y = position
            .y_raw
            .checked_sub(origin.y_screen_px)
            .ok_or(CanvasError::InvalidTransform)? as f64;
        self.map_document_point(document_x, document_y)
    }

    fn map_raw_point_in_stroke_frame(
        &self,
        position: &RawPosition,
        frame: StrokeViewFrame,
    ) -> Result<CanvasPointPx, CanvasError> {
        if position.coordinate_space != SCREEN_POSITION_SPACE
            || position.units != SCREEN_POSITION_UNITS
            || !frame.is_valid()
        {
            return Err(CanvasError::InvalidTransform);
        }
        let relative_x = position
            .x_raw
            .checked_sub(frame.screen_origin_x_px)
            .ok_or(CanvasError::InvalidTransform)? as f64;
        let relative_y = position
            .y_raw
            .checked_sub(frame.screen_origin_y_px)
            .ok_or(CanvasError::InvalidTransform)? as f64;
        let start_zoom = f64::from_bits(frame.canvas_zoom_bits);
        let start_pan_x = f64::from_bits(frame.canvas_pan_x_bits);
        let start_pan_y = f64::from_bits(frame.canvas_pan_y_bits);
        // Raw pointer and ClientToScreen values are physical pixels; the DPI
        // scale is retained in the frame but is not applied a second time.
        let document_x = (relative_x - start_pan_x) / start_zoom;
        let document_y =
            (relative_y - start_pan_y - f64::from(frame.toolbar_height_px)) / start_zoom;
        self.map_document_point(document_x, document_y)
    }

    fn map_document_point(
        &self,
        document_x: f64,
        document_y: f64,
    ) -> Result<CanvasPointPx, CanvasError> {
        let x = document_x * self.zoom + self.pan_x;
        let y = document_y * self.zoom + self.pan_y + f64::from(TOOLBAR_HEIGHT);
        if !x.is_finite() || !y.is_finite() {
            return Err(CanvasError::InvalidTransform);
        }
        let x = x.round();
        let y = y.round();
        if x < f64::from(i32::MIN)
            || x > f64::from(i32::MAX)
            || y < f64::from(i32::MIN)
            || y > f64::from(i32::MAX)
        {
            return Err(CanvasError::InvalidTransform);
        }
        Ok(CanvasPointPx {
            x: x as i32,
            y: y as i32,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanvasPointPx {
    pub x: i32,
    pub y: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanvasPoint {
    pub source_sequence_raw: u64,
    pub position: RawPosition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanvasStroke {
    pub identity: StrokeRef,
    pub view_frame: Option<StrokeViewFrame>,
    pub points: Vec<CanvasPoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RenderedStroke {
    pub identity: StrokeRef,
    pub points: Vec<CanvasPointPx>,
    pub selected: bool,
    /// Pending samples are visible as a preview until the journal worker
    /// acknowledges their durable append.
    pub preview: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct CanvasRect {
    pub left: f64,
    pub top: f64,
    pub right: f64,
    pub bottom: f64,
}

impl CanvasRect {
    pub(crate) fn normalized(a: (f64, f64), b: (f64, f64)) -> Result<Self, CanvasError> {
        if !a.0.is_finite() || !a.1.is_finite() || !b.0.is_finite() || !b.1.is_finite() {
            return Err(CanvasError::InvalidTransform);
        }
        Ok(Self {
            left: a.0.min(b.0),
            top: a.1.min(b.1),
            right: a.0.max(b.0),
            bottom: a.1.max(b.1),
        })
    }

    fn contains(&self, point: (f64, f64)) -> bool {
        point.0 >= self.left
            && point.0 <= self.right
            && point.1 >= self.top
            && point.1 <= self.bottom
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CanvasError {
    InvalidTransform,
    UnsupportedCoordinateSpace {
        coordinate_space: String,
        units: String,
    },
    StrokeCapacityReached,
    PointCapacityReached,
    SelectionCapacityReached,
    ActiveStrokeCapacityReached,
    StrokeSequenceExhausted,
    MissingStrokeViewFrame,
    StrokeViewFrameMismatch,
    InvalidCanonicalRasterProjection(&'static str),
    RasterAllocationFailed,
    RasterEncodingFailed,
    Journal(JournalErrorKindForCanvas),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CanvasInputTracker {
    active_direct_strokes: HashMap<(isize, u32), DirectActiveStroke>,
    next_stroke_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectActiveStroke {
    target: StrokeRef,
    has_contact_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DirectCaptureEvent {
    StrokeStarted {
        target: StrokeRef,
        view_frame: StrokeViewFrame,
        app_arrival_elapsed_ns: u128,
    },
    PhysicalSample(Box<PhysicalSample>),
    StrokeCommitRequested {
        target: StrokeRef,
        app_arrival_elapsed_ns: u128,
    },
    StrokeInterrupted {
        target: StrokeRef,
        reason: crate::journal::StrokeInterruptionReason,
        app_arrival_elapsed_ns: u128,
    },
    UnmatchedNativeUp {
        pointer_id_requested: u32,
        source_device_handle_raw_session_scoped: Option<isize>,
        reason: DirectUpIssue,
        app_arrival_elapsed_ns: u128,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectUpIssue {
    EmptyHistory,
    MissingNativeUpFlag,
    CanceledNativeUp,
    DeviceOrPointerMismatch,
    MixedDeviceHistory,
    NoActiveStroke,
    AmbiguousActiveStrokes,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CanvasToolIntent {
    SelectTarget(Option<StrokeRef>),
    SelectRegion(CanvasRect),
    Edit(EditCommand),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CanvasToolGestureTracker {
    active: HashMap<(isize, u32), CanvasToolGesture>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanvasToolGesture {
    tool: CanvasTool,
    view_frame: StrokeViewFrame,
    start_client: (i32, i32),
    last_client: (i32, i32),
    start_target: Option<StrokeRef>,
    erase_targets: Vec<StrokeRef>,
}

pub(crate) struct CanvasToolCaptureContext<'a> {
    pub session_id: &'a str,
    pub config_id: Option<&'a str>,
    pub view_frame: StrokeViewFrame,
    pub scene: &'a CanvasScene,
    pub viewport: CanvasViewport,
}

impl CanvasToolGestureTracker {
    pub(crate) fn cancel_all(&mut self) {
        self.active.clear();
    }

    pub(crate) fn cancel_pointer_id(&mut self, pointer_id: Option<u32>) {
        self.active.retain(|(_, active_pointer_id), _| {
            pointer_id.is_some_and(|id| id != *active_pointer_id)
        });
    }

    pub(crate) fn direct_batch_to_tool_events(
        &mut self,
        tool: CanvasTool,
        batch: &DirectPenHistoryBatch,
        context: CanvasToolCaptureContext<'_>,
    ) -> Result<(Vec<DirectCaptureEvent>, Option<CanvasToolIntent>), CanvasError> {
        let mut raw_events = Vec::new();
        raw_events
            .try_reserve_exact(batch.samples.len())
            .map_err(|_| CanvasError::PointCapacityReached)?;
        for native in &batch.samples {
            let physical = owned_direct_sample_to_physical(
                batch,
                native,
                context.session_id,
                context.config_id,
                None,
            )?;
            raw_events.push(DirectCaptureEvent::PhysicalSample(Box::new(physical)));
        }
        let Some(first) = batch.samples.first() else {
            if batch.message_kind == PointerMessageKind::Up {
                self.cancel_pointer_id(Some(batch.pointer_id_requested));
            }
            return Ok((raw_events, None));
        };
        let device_handle = first.source_device_handle_raw_session_scoped;
        let pointer_key = (device_handle, batch.pointer_id_requested);
        if batch
            .samples
            .iter()
            .any(|sample| sample.source_device_handle_raw_session_scoped != device_handle)
        {
            self.cancel_pointer_id(Some(batch.pointer_id_requested));
            return Ok((raw_events, None));
        }

        let contacts = batch.samples.iter().filter(|sample| {
            has_matching_direct_pen_contact(device_handle, batch.pointer_id_requested, sample)
        });

        if batch.message_kind == PointerMessageKind::Down {
            self.active.remove(&pointer_key);
            let mut first_point = None;
            let mut start_target = None;
            let mut erase_targets = Vec::new();
            for native in contacts {
                let point = context.viewport.map_raw_point_in_stroke_frame(
                    &RawPosition {
                        coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
                        units: SCREEN_POSITION_UNITS.to_owned(),
                        x_raw: i64::from(native.position.pt_pixel_location_raw.x),
                        y_raw: i64::from(native.position.pt_pixel_location_raw.y),
                    },
                    context.view_frame,
                )?;
                if first_point.is_none() {
                    first_point = Some((point.x, point.y));
                    if tool == CanvasTool::Select {
                        start_target = context.scene.hit_test(
                            context.viewport,
                            f64::from(point.x),
                            f64::from(point.y),
                            10.0,
                        )?;
                    }
                }
                if tool == CanvasTool::Eraser {
                    collect_erase_hit(
                        context.scene,
                        context.viewport,
                        (point.x, point.y),
                        &mut erase_targets,
                    )?;
                }
            }
            if let Some(start_client) = first_point {
                if !self.active.contains_key(&pointer_key)
                    && self.active.len() >= MAX_ACTIVE_DIRECT_STROKES
                {
                    return Err(CanvasError::ActiveStrokeCapacityReached);
                }
                self.active
                    .try_reserve(1)
                    .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
                self.active.insert(
                    pointer_key,
                    CanvasToolGesture {
                        tool,
                        view_frame: context.view_frame,
                        start_client,
                        last_client: start_client,
                        start_target,
                        erase_targets,
                    },
                );
            }
            return Ok((raw_events, None));
        }

        if batch.message_kind == PointerMessageKind::Update {
            let Some(gesture) = self.active.get_mut(&pointer_key) else {
                return Ok((raw_events, None));
            };
            let mut found_contact = false;
            for native in contacts {
                found_contact = true;
                let point = context.viewport.map_raw_point_in_stroke_frame(
                    &RawPosition {
                        coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
                        units: SCREEN_POSITION_UNITS.to_owned(),
                        x_raw: i64::from(native.position.pt_pixel_location_raw.x),
                        y_raw: i64::from(native.position.pt_pixel_location_raw.y),
                    },
                    gesture.view_frame,
                )?;
                gesture.last_client = (point.x, point.y);
                if gesture.tool == CanvasTool::Eraser {
                    collect_erase_hit(
                        context.scene,
                        context.viewport,
                        gesture.last_client,
                        &mut gesture.erase_targets,
                    )?;
                }
            }
            if !found_contact {
                self.active.remove(&pointer_key);
            }
            return Ok((raw_events, None));
        }

        if batch.message_kind != PointerMessageKind::Up {
            return Ok((raw_events, None));
        }
        let has_canceled_native_up = batch.samples.iter().any(|sample| {
            matches_direct_pen_identity(device_handle, batch.pointer_id_requested, sample)
                && sample.pointer_flags_raw
                    & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_UP
                    != 0
                && sample.pointer_flags_raw
                    & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_CANCELED
                    != 0
        });
        let has_native_up = batch.samples.iter().any(|sample| {
            matches_direct_pen_identity(device_handle, batch.pointer_id_requested, sample)
                && sample.pointer_flags_raw
                    & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_UP
                    != 0
                && sample.pointer_flags_raw
                    & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_CANCELED
                    == 0
        });
        let Some(mut gesture) = self.active.remove(&pointer_key) else {
            self.cancel_pointer_id(Some(batch.pointer_id_requested));
            return Ok((raw_events, None));
        };
        if !has_native_up || has_canceled_native_up {
            return Ok((raw_events, None));
        }
        for native in batch.samples.iter().filter(|sample| {
            matches_direct_pen_identity(device_handle, batch.pointer_id_requested, sample)
        }) {
            let point = context.viewport.map_raw_point_in_stroke_frame(
                &RawPosition {
                    coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
                    units: SCREEN_POSITION_UNITS.to_owned(),
                    x_raw: i64::from(native.position.pt_pixel_location_raw.x),
                    y_raw: i64::from(native.position.pt_pixel_location_raw.y),
                },
                gesture.view_frame,
            )?;
            gesture.last_client = (point.x, point.y);
            if gesture.tool == CanvasTool::Eraser {
                collect_erase_hit(
                    context.scene,
                    context.viewport,
                    gesture.last_client,
                    &mut gesture.erase_targets,
                )?;
            }
        }

        // Convert before subtracting: both endpoints are valid i32 client
        // coordinates, but their mathematical difference can exceed i32.
        let delta_x = f64::from(gesture.last_client.0) - f64::from(gesture.start_client.0);
        let delta_y = f64::from(gesture.last_client.1) - f64::from(gesture.start_client.1);
        let dragged = delta_x.abs() >= 3.0 || delta_y.abs() >= 3.0;
        let intent = match gesture.tool {
            CanvasTool::Pen => None,
            CanvasTool::Eraser => {
                if gesture.erase_targets.is_empty() {
                    None
                } else {
                    gesture.erase_targets.sort();
                    Some(CanvasToolIntent::Edit(EditCommand::Tombstone {
                        targets: gesture.erase_targets,
                    }))
                }
            }
            CanvasTool::Select => match (gesture.start_target, dragged) {
                (Some(target), true) => {
                    let (delta_x_raw, delta_y_raw) = context.scene.raw_move_delta_from_view_drag(
                        &target,
                        context.viewport,
                        delta_x,
                        delta_y,
                    )?;
                    if delta_x_raw == 0 && delta_y_raw == 0 {
                        Some(CanvasToolIntent::SelectTarget(Some(target)))
                    } else {
                        Some(CanvasToolIntent::Edit(EditCommand::Move {
                            target,
                            delta_x_raw,
                            delta_y_raw,
                            coordinate_space: "windows-screen-coordinates".to_owned(),
                            units: "screen-pixel".to_owned(),
                        }))
                    }
                }
                (Some(target), false) => Some(CanvasToolIntent::SelectTarget(Some(target))),
                (None, true) => Some(CanvasToolIntent::SelectRegion(CanvasRect::normalized(
                    (
                        f64::from(gesture.start_client.0),
                        f64::from(gesture.start_client.1),
                    ),
                    (
                        f64::from(gesture.last_client.0),
                        f64::from(gesture.last_client.1),
                    ),
                )?)),
                (None, false) => Some(CanvasToolIntent::SelectTarget(None)),
            },
        };
        Ok((raw_events, intent))
    }
}

fn collect_erase_hit(
    scene: &CanvasScene,
    viewport: CanvasViewport,
    point: (i32, i32),
    targets: &mut Vec<StrokeRef>,
) -> Result<(), CanvasError> {
    if let Some(target) = scene.hit_test(viewport, f64::from(point.0), f64::from(point.1), 10.0)?
        && !targets.contains(&target)
    {
        if targets.len() >= crate::journal::MAX_EDIT_TARGETS {
            return Err(CanvasError::SelectionCapacityReached);
        }
        targets
            .try_reserve(1)
            .map_err(|_| CanvasError::SelectionCapacityReached)?;
        targets.push(target);
    }
    Ok(())
}

impl CanvasInputTracker {
    pub(crate) fn active_stroke_count(&self) -> usize {
        self.active_direct_strokes.len()
    }

    pub(crate) fn interrupt_active_strokes(
        &mut self,
        reason: crate::journal::StrokeInterruptionReason,
        app_arrival_elapsed_ns: u128,
    ) -> Result<Vec<DirectCaptureEvent>, CanvasError> {
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(self.active_direct_strokes.len())
            .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
        targets.extend(self.active_direct_strokes.keys().copied());
        let mut events = Vec::new();
        events
            .try_reserve_exact(targets.len())
            .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
        for key in targets {
            if let Some(active) = self.active_direct_strokes.remove(&key) {
                events.push(DirectCaptureEvent::StrokeInterrupted {
                    target: active.target,
                    reason,
                    app_arrival_elapsed_ns,
                });
            }
        }
        Ok(events)
    }

    fn interrupt_pointer_id(
        &mut self,
        pointer_id_requested: u32,
        reason: crate::journal::StrokeInterruptionReason,
        app_arrival_elapsed_ns: u128,
    ) -> Result<Vec<DirectCaptureEvent>, CanvasError> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(self.active_direct_strokes.len())
            .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
        keys.extend(
            self.active_direct_strokes
                .keys()
                .filter(|(_, pointer_id)| *pointer_id == pointer_id_requested)
                .copied(),
        );
        let mut events = Vec::new();
        events
            .try_reserve_exact(keys.len())
            .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
        for key in keys {
            if let Some(active) = self.active_direct_strokes.remove(&key) {
                events.push(DirectCaptureEvent::StrokeInterrupted {
                    target: active.target,
                    reason,
                    app_arrival_elapsed_ns,
                });
            }
        }
        Ok(events)
    }

    fn unmatched_up_events(
        &mut self,
        pointer_id_requested: u32,
        source_device_handle_raw_session_scoped: Option<isize>,
        issue: DirectUpIssue,
        unique_interruption_reason: crate::journal::StrokeInterruptionReason,
        app_arrival_elapsed_ns: u128,
    ) -> Result<Vec<DirectCaptureEvent>, CanvasError> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(self.active_direct_strokes.len())
            .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
        keys.extend(
            self.active_direct_strokes
                .keys()
                .filter(|(_, pointer_id)| *pointer_id == pointer_id_requested)
                .copied(),
        );
        let interruption_reason = if keys.len() > 1 {
            crate::journal::StrokeInterruptionReason::AmbiguousNativeUp
        } else {
            unique_interruption_reason
        };
        let mut events = Vec::new();
        events
            .try_reserve_exact(keys.len().saturating_add(1))
            .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
        for key in keys {
            if let Some(active) = self.active_direct_strokes.remove(&key) {
                events.push(DirectCaptureEvent::StrokeInterrupted {
                    target: active.target,
                    reason: interruption_reason,
                    app_arrival_elapsed_ns,
                });
            }
        }
        events.push(DirectCaptureEvent::UnmatchedNativeUp {
            pointer_id_requested,
            source_device_handle_raw_session_scoped,
            reason: if interruption_reason
                == crate::journal::StrokeInterruptionReason::AmbiguousNativeUp
            {
                DirectUpIssue::AmbiguousActiveStrokes
            } else {
                issue
            },
            app_arrival_elapsed_ns,
        });
        Ok(events)
    }

    /// Copies validated contact samples from the already-owned direct history
    /// batch. Native clocks/flags/units remain raw; no public Winit or mouse
    /// event is accepted as a pen fallback.
    #[cfg(test)]
    pub(crate) fn direct_batch_to_samples(
        &mut self,
        batch: &DirectPenHistoryBatch,
        journal_id: &str,
        session_id: &str,
        config_id: Option<&str>,
    ) -> Result<Vec<PhysicalSample>, CanvasError> {
        let events = self.direct_batch_to_events(
            batch,
            journal_id,
            session_id,
            config_id,
            StrokeViewFrame::default(),
        )?;
        let mut samples = Vec::new();
        samples
            .try_reserve(events.len())
            .map_err(|_| CanvasError::PointCapacityReached)?;
        for event in events {
            if let DirectCaptureEvent::PhysicalSample(sample) = event {
                samples.push(*sample);
            }
        }
        Ok(samples)
    }

    pub(crate) fn direct_batch_to_events(
        &mut self,
        batch: &DirectPenHistoryBatch,
        journal_id: &str,
        session_id: &str,
        config_id: Option<&str>,
        view_frame: StrokeViewFrame,
    ) -> Result<Vec<DirectCaptureEvent>, CanvasError> {
        let Some(first_sample) = batch.samples.first() else {
            return if batch.message_kind == PointerMessageKind::Up {
                self.unmatched_up_events(
                    batch.pointer_id_requested,
                    None,
                    DirectUpIssue::EmptyHistory,
                    crate::journal::StrokeInterruptionReason::UnattributedNativeUp,
                    batch.hook_observed_elapsed_ns,
                )
            } else {
                Ok(Vec::new())
            };
        };
        let device_handle = first_sample.source_device_handle_raw_session_scoped;
        let pointer_key = (device_handle, batch.pointer_id_requested);
        let mut events = Vec::new();
        events
            .try_reserve(batch.samples.len().saturating_add(3))
            .map_err(|_| CanvasError::PointCapacityReached)?;
        let mixed_device_history = batch
            .samples
            .iter()
            .any(|sample| sample.source_device_handle_raw_session_scoped != device_handle);
        if mixed_device_history {
            if batch.message_kind == PointerMessageKind::Up {
                let mut interruptions = self.unmatched_up_events(
                    batch.pointer_id_requested,
                    Some(device_handle),
                    DirectUpIssue::MixedDeviceHistory,
                    crate::journal::StrokeInterruptionReason::MixedDeviceBatch,
                    batch.hook_observed_elapsed_ns,
                )?;
                events
                    .try_reserve(interruptions.len())
                    .map_err(|_| CanvasError::PointCapacityReached)?;
                events.append(&mut interruptions);
            } else {
                let mut interruptions = self.interrupt_pointer_id(
                    batch.pointer_id_requested,
                    crate::journal::StrokeInterruptionReason::MixedDeviceBatch,
                    batch.hook_observed_elapsed_ns,
                )?;
                events
                    .try_reserve(interruptions.len())
                    .map_err(|_| CanvasError::PointCapacityReached)?;
                events.append(&mut interruptions);
            }
            for native in &batch.samples {
                let physical =
                    owned_direct_sample_to_physical(batch, native, session_id, config_id, None)?;
                events.push(DirectCaptureEvent::PhysicalSample(Box::new(physical)));
            }
            return Ok(events);
        }
        if batch.message_kind == PointerMessageKind::Down {
            if let Some(previous) = self.active_direct_strokes.remove(&pointer_key) {
                events.push(DirectCaptureEvent::StrokeInterrupted {
                    target: previous.target,
                    reason: crate::journal::StrokeInterruptionReason::PointerDownBeforePenUp,
                    app_arrival_elapsed_ns: batch.hook_observed_elapsed_ns,
                });
            }
            if batch.samples.iter().any(|sample| {
                has_matching_direct_pen_contact(device_handle, batch.pointer_id_requested, sample)
            }) {
                if self.active_direct_strokes.len() >= MAX_ACTIVE_DIRECT_STROKES {
                    return Err(CanvasError::ActiveStrokeCapacityReached);
                }
                self.active_direct_strokes
                    .try_reserve(1)
                    .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
                self.next_stroke_sequence = self
                    .next_stroke_sequence
                    .checked_add(1)
                    .ok_or(CanvasError::StrokeSequenceExhausted)?;
                let target = StrokeRef {
                    journal_id: journal_id.to_owned(),
                    session_id: session_id.to_owned(),
                    source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
                    device_id: Some(format!("session-scoped-handle-{device_handle:X}")),
                    pointer_id: Some(u64::from(batch.pointer_id_requested)),
                    stroke_id: format!("direct-stroke-{}", self.next_stroke_sequence),
                };
                events.push(DirectCaptureEvent::StrokeStarted {
                    target: target.clone(),
                    view_frame,
                    app_arrival_elapsed_ns: batch.hook_observed_elapsed_ns,
                });
                self.active_direct_strokes.insert(
                    pointer_key,
                    DirectActiveStroke {
                        target,
                        has_contact_evidence: true,
                    },
                );
            }
        }
        let active = self.active_direct_strokes.get(&pointer_key).cloned();
        for native in &batch.samples {
            let sample_stroke = active
                .as_ref()
                .filter(|_| {
                    native.source_device_handle_raw_session_scoped == device_handle
                        && native.pointer_id_raw == batch.pointer_id_requested
                        && is_stroke_attributable(batch.message_kind, native)
                })
                .map(|active| active.target.stroke_id.as_str());
            let physical = owned_direct_sample_to_physical(
                batch,
                native,
                session_id,
                config_id,
                sample_stroke,
            )?;
            if let Some(active) = self.active_direct_strokes.get_mut(&pointer_key)
                && sample_stroke.is_some()
            {
                active.has_contact_evidence = true;
            }
            events.push(DirectCaptureEvent::PhysicalSample(Box::new(physical)));
        }

        if batch.message_kind == PointerMessageKind::Up {
            let matching_identity = batch.samples.iter().any(|sample| {
                matches_direct_pen_identity(device_handle, batch.pointer_id_requested, sample)
            });
            let canceled_up = batch.samples.iter().any(|sample| {
                matches_direct_pen_identity(device_handle, batch.pointer_id_requested, sample)
                    && sample.pointer_flags_raw
                        & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_UP
                        != 0
                    && sample.pointer_flags_raw
                        & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_CANCELED
                        != 0
            });
            let matching_native_up = batch.samples.iter().any(|sample| {
                matches_direct_pen_identity(device_handle, batch.pointer_id_requested, sample)
                    && sample.pointer_flags_raw
                        & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_UP
                        != 0
                    && sample.pointer_flags_raw
                        & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_CANCELED
                        == 0
            });
            if let Some(active) = self.active_direct_strokes.remove(&pointer_key) {
                if matching_native_up && !canceled_up && active.has_contact_evidence {
                    events.push(DirectCaptureEvent::StrokeCommitRequested {
                        target: active.target,
                        app_arrival_elapsed_ns: batch.hook_observed_elapsed_ns,
                    });
                } else {
                    let reason = if canceled_up {
                        crate::journal::StrokeInterruptionReason::CanceledNativeUp
                    } else {
                        crate::journal::StrokeInterruptionReason::UnattributedNativeUp
                    };
                    let issue = if canceled_up {
                        DirectUpIssue::CanceledNativeUp
                    } else if matching_identity && !matching_native_up {
                        DirectUpIssue::MissingNativeUpFlag
                    } else {
                        DirectUpIssue::DeviceOrPointerMismatch
                    };
                    events.push(DirectCaptureEvent::StrokeInterrupted {
                        target: active.target,
                        reason,
                        app_arrival_elapsed_ns: batch.hook_observed_elapsed_ns,
                    });
                    events.push(DirectCaptureEvent::UnmatchedNativeUp {
                        pointer_id_requested: batch.pointer_id_requested,
                        source_device_handle_raw_session_scoped: Some(device_handle),
                        reason: issue,
                        app_arrival_elapsed_ns: batch.hook_observed_elapsed_ns,
                    });
                }
            } else {
                let active_for_other_device = self
                    .active_direct_strokes
                    .keys()
                    .any(|(_, pointer_id)| *pointer_id == batch.pointer_id_requested);
                let (issue, reason) = if canceled_up {
                    (
                        DirectUpIssue::CanceledNativeUp,
                        crate::journal::StrokeInterruptionReason::CanceledNativeUp,
                    )
                } else if active_for_other_device {
                    (
                        DirectUpIssue::DeviceOrPointerMismatch,
                        crate::journal::StrokeInterruptionReason::UnattributedNativeUp,
                    )
                } else if matching_identity && !matching_native_up {
                    (
                        DirectUpIssue::MissingNativeUpFlag,
                        crate::journal::StrokeInterruptionReason::UnattributedNativeUp,
                    )
                } else if matching_native_up {
                    (
                        DirectUpIssue::NoActiveStroke,
                        crate::journal::StrokeInterruptionReason::UnattributedNativeUp,
                    )
                } else {
                    (
                        DirectUpIssue::DeviceOrPointerMismatch,
                        crate::journal::StrokeInterruptionReason::UnattributedNativeUp,
                    )
                };
                let mut unmatched = self.unmatched_up_events(
                    batch.pointer_id_requested,
                    Some(device_handle),
                    issue,
                    reason,
                    batch.hook_observed_elapsed_ns,
                )?;
                events
                    .try_reserve(unmatched.len())
                    .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
                events.append(&mut unmatched);
            }
        } else if batch.message_kind == PointerMessageKind::Update
            && !batch.samples.iter().any(|sample| {
                has_matching_direct_pen_contact(device_handle, batch.pointer_id_requested, sample)
            })
            && let Some(active) = self.active_direct_strokes.remove(&pointer_key)
        {
            events.push(DirectCaptureEvent::StrokeInterrupted {
                target: active.target,
                reason: crate::journal::StrokeInterruptionReason::ContactLostWithoutPenUp,
                app_arrival_elapsed_ns: batch.hook_observed_elapsed_ns,
            });
        }
        Ok(events)
    }

    pub(crate) fn on_direct_lifecycle(
        &mut self,
        kind: LifecycleEventKind,
        pointer_id: Option<u32>,
        app_arrival_elapsed_ns: u128,
    ) -> Result<Vec<DirectCaptureEvent>, CanvasError> {
        let reason = match kind {
            LifecycleEventKind::DirectPointerLeave => {
                Some(crate::journal::StrokeInterruptionReason::PointerLeave)
            }
            LifecycleEventKind::DirectPointerEnter => {
                Some(crate::journal::StrokeInterruptionReason::PointerReentryBoundary)
            }
            LifecycleEventKind::DirectPointerCaptureChanged => {
                Some(crate::journal::StrokeInterruptionReason::PointerCaptureChanged)
            }
            LifecycleEventKind::DirectPointerDeviceOutOfRange => {
                Some(crate::journal::StrokeInterruptionReason::DeviceOutOfRange)
            }
            LifecycleEventKind::DirectPointerDeviceInRange => {
                Some(crate::journal::StrokeInterruptionReason::DeviceReentryBoundary)
            }
            LifecycleEventKind::DirectPointerDeviceChanged => {
                Some(crate::journal::StrokeInterruptionReason::DeviceChanged)
            }
            LifecycleEventKind::WindowFocusLost => {
                Some(crate::journal::StrokeInterruptionReason::WindowFocusLost)
            }
            _ => None,
        };
        let Some(reason) = reason else {
            return Ok(Vec::new());
        };
        let mut events = Vec::new();
        let mut keys = Vec::new();
        keys.try_reserve(self.active_direct_strokes.len())
            .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
        keys.extend(
            self.active_direct_strokes
                .keys()
                .filter(|(_, active_pointer_id)| {
                    pointer_id.is_none_or(|id| id == *active_pointer_id)
                })
                .copied(),
        );
        events
            .try_reserve(keys.len())
            .map_err(|_| CanvasError::ActiveStrokeCapacityReached)?;
        for key in keys {
            if let Some(active) = self.active_direct_strokes.remove(&key) {
                events.push(DirectCaptureEvent::StrokeInterrupted {
                    target: active.target,
                    reason,
                    app_arrival_elapsed_ns,
                });
            }
        }
        Ok(events)
    }
}

fn has_matching_direct_pen_contact(
    expected_device_handle: isize,
    requested_pointer_id: u32,
    sample: &OwnedPointerSample,
) -> bool {
    matches_direct_pen_identity(expected_device_handle, requested_pointer_id, sample)
        && (sample.pointer_flags_raw
            & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT
            != 0)
}

fn matches_direct_pen_identity(
    expected_device_handle: isize,
    requested_pointer_id: u32,
    sample: &OwnedPointerSample,
) -> bool {
    sample.pointer_type_raw == windows_sys::Win32::UI::WindowsAndMessaging::PT_PEN
        && sample.attribution == crate::win32_pointer::PointerAttribution::MatchesRequestedPointer
        && sample.pointer_id_raw == requested_pointer_id
        && sample.source_device_handle_raw_session_scoped == expected_device_handle
}

fn is_stroke_attributable(kind: PointerMessageKind, sample: &OwnedPointerSample) -> bool {
    sample.pointer_type_raw == windows_sys::Win32::UI::WindowsAndMessaging::PT_PEN
        && sample.attribution == crate::win32_pointer::PointerAttribution::MatchesRequestedPointer
        && (sample.pointer_flags_raw
            & windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT
            != 0
            || kind == PointerMessageKind::Up)
}

fn owned_direct_sample_to_physical(
    batch: &DirectPenHistoryBatch,
    native: &OwnedPointerSample,
    session_id: &str,
    config_id: Option<&str>,
    stroke_id: Option<&str>,
) -> Result<PhysicalSample, CanvasError> {
    let raw_payload = encode_direct_raw_payload(batch, native)?;
    let pressure_mask = native.pen_mask_raw;
    let pressure = (pressure_mask & windows_sys::Win32::UI::WindowsAndMessaging::PEN_MASK_PRESSURE
        != 0)
        .then(|| RawPressure {
            representation: "POINTER_PEN_INFO.pressure".to_owned(),
            units: "Windows-normalized-raw-units".to_owned(),
            value_raw: u64::from(native.pressure_raw),
            mask_raw: Some(u64::from(pressure_mask)),
            minimum_raw: Some(0),
            maximum_raw: Some(1024),
        });
    let rotation_raw =
        (pressure_mask & windows_sys::Win32::UI::WindowsAndMessaging::PEN_MASK_ROTATION != 0)
            .then_some(u64::from(native.rotation_raw));
    Ok(PhysicalSample {
        session_id: session_id.to_owned(),
        source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
        source_device_id: Some(format!(
            "session-scoped-handle-{:X}",
            native.source_device_handle_raw_session_scoped
        )),
        pointer_id: Some(u64::from(native.pointer_id_raw)),
        stroke_id: stroke_id.map(str::to_owned),
        // `frameId` is retained as its raw pointer/device-qualified counter;
        // it is not a claim of strict sequencing or drop count.
        source_sequence: u64::from(native.frame_id_raw),
        config_id: config_id.map(str::to_owned),
        app_arrival_elapsed_ns: batch.hook_observed_elapsed_ns,
        position: Some(RawPosition {
            coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
            units: SCREEN_POSITION_UNITS.to_owned(),
            x_raw: i64::from(native.position.pt_pixel_location_raw.x),
            y_raw: i64::from(native.position.pt_pixel_location_raw.y),
        }),
        pressure,
        native_timestamp: Some(NativeTimestamp {
            clock_domain: "POINTER_INFO.PerformanceCount/QPC at OS message receipt".to_owned(),
            units: "QPC ticks".to_owned(),
            count_raw: native.performance_count_qpc_raw,
            frequency_hz: batch.qpc_frequency_hz,
        }),
        contact_range_state: Some(format!(
            "raw POINTER_INFO.pointerFlags=0x{:08X}",
            native.pointer_flags_raw
        )),
        // `dwKeyStates` carries keyboard modifier state, not tablet buttons.
        // PT_PEN barrel/eraser flags remain in the opaque raw payload until a
        // device/API contract justifies a structured button mapping.
        button_state_raw: None,
        tilt_x_raw: None,
        tilt_y_raw: None,
        rotation_raw,
        raw_payload,
    })
}

fn encode_direct_raw_payload(
    batch: &DirectPenHistoryBatch,
    sample: &OwnedPointerSample,
) -> Result<Vec<u8>, CanvasError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(160)
        .map_err(|_| CanvasError::PointCapacityReached)?;
    bytes.extend_from_slice(b"DWP3");
    push_u32(&mut bytes, sample.history_index_newest_first);
    push_u32(&mut bytes, sample.chronological_index);
    push_i32(&mut bytes, sample.pointer_type_raw);
    push_u32(&mut bytes, sample.pointer_id_raw);
    push_u32(&mut bytes, sample.frame_id_raw);
    push_i64(
        &mut bytes,
        sample.source_device_handle_raw_session_scoped as i64,
    );
    push_i64(&mut bytes, sample.target_hwnd_raw_session_scoped as i64);
    push_u32(&mut bytes, sample.pointer_flags_raw);
    push_i32(&mut bytes, sample.button_change_type_raw);
    push_i32(&mut bytes, sample.position.pt_pixel_location_raw.x);
    push_i32(&mut bytes, sample.position.pt_pixel_location_raw.y);
    push_i32(&mut bytes, sample.position.pt_himetric_location_raw.x);
    push_i32(&mut bytes, sample.position.pt_himetric_location_raw.y);
    push_u64(&mut bytes, sample.performance_count_qpc_raw);
    push_u32(&mut bytes, sample.dw_time_ms_wrapping_raw);
    push_u32(&mut bytes, sample.history_count_raw);
    push_i32(&mut bytes, sample.input_data_raw);
    push_u32(&mut bytes, sample.key_states_raw);
    push_u32(&mut bytes, sample.pen_flags_raw);
    push_u32(&mut bytes, sample.pen_mask_raw);
    push_u32(&mut bytes, sample.pressure_raw);
    push_u32(&mut bytes, sample.rotation_raw);
    push_i32(&mut bytes, sample.tilt_x_raw);
    push_i32(&mut bytes, sample.tilt_y_raw);
    push_u64(&mut bytes, batch.message_sequence);
    push_u32(&mut bytes, batch.message_id_raw);
    push_i64(&mut bytes, batch.message_hwnd_raw_session_scoped as i64);
    bytes.push(u8::from(batch.message_time_ms_raw.is_some()));
    push_u32(&mut bytes, batch.message_time_ms_raw.unwrap_or_default());
    bytes.push(u8::from(batch.hook_qpc_count_raw.is_some()));
    push_u64(&mut bytes, batch.hook_qpc_count_raw.unwrap_or_default());
    push_u32(&mut bytes, batch.native_history_count);
    bytes.push(u8::from(batch.qpc_frequency_hz.is_some()));
    push_u64(&mut bytes, batch.qpc_frequency_hz.unwrap_or_default());
    Ok(bytes)
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_i32(bytes: &mut Vec<u8>, value: i32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_i64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalErrorKindForCanvas {
    pub kind: String,
    pub message: String,
}

impl From<JournalError> for CanvasError {
    fn from(error: JournalError) -> Self {
        Self::Journal(JournalErrorKindForCanvas {
            kind: format!("{:?}", error.kind),
            message: error.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CanvasScene {
    source_api_provisional: String,
    strokes: HashMap<StrokeRef, CanvasStroke>,
    preview_strokes: HashMap<StrokeRef, CanvasStroke>,
    origins_by_session: HashMap<String, CanvasOrigin>,
    selected: HashSet<StrokeRef>,
    active_selection: Option<CanvasRect>,
    tool: CanvasTool,
    point_count: usize,
    preview_point_count: usize,
}

impl Default for CanvasScene {
    fn default() -> Self {
        Self {
            source_api_provisional: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
            strokes: HashMap::new(),
            preview_strokes: HashMap::new(),
            origins_by_session: HashMap::new(),
            selected: HashSet::new(),
            active_selection: None,
            tool: CanvasTool::Pen,
            point_count: 0,
            preview_point_count: 0,
        }
    }
}

impl CanvasScene {
    pub(crate) fn from_journal(
        state: &JournalReplayState,
        provisional_source_api: &str,
    ) -> Result<Self, CanvasError> {
        let mut scene = Self {
            source_api_provisional: provisional_source_api.to_owned(),
            ..Self::default()
        };
        scene.load_origins(state.metadata_history.iter().map(|stored| &stored.metadata))?;
        let mut view_frames = HashMap::new();
        view_frames
            .try_reserve(state.stroke_starts.len())
            .map_err(|_| CanvasError::StrokeCapacityReached)?;
        for stored in &state.stroke_starts {
            if stored.target.source_api == scene.source_api_provisional {
                view_frames.insert(stored.target.clone(), stored.view_frame);
            }
        }
        for projected in state.projected_samples()? {
            if projected.sample.source_api != scene.source_api_provisional {
                continue;
            }
            if let Some(stroke_ref) = projected.stroke_ref {
                let view_frame = view_frames.get(&stroke_ref).copied();
                scene.push_point(
                    stroke_ref,
                    projected.sample.source_sequence,
                    projected
                        .effective_position
                        .or_else(|| projected.sample.position.clone()),
                    view_frame,
                )?;
            }
        }
        Ok(scene)
    }

    pub(crate) fn refresh_from_journal(
        &mut self,
        state: &JournalReplayState,
    ) -> Result<(), CanvasError> {
        let tool = self.tool;
        let selected = self.selected.clone();
        let preview_strokes = std::mem::take(&mut self.preview_strokes);
        let preview_point_count = self.preview_point_count;
        let mut refreshed = Self::from_journal(state, &self.source_api_provisional)?;
        refreshed.tool = tool;
        refreshed.preview_strokes = preview_strokes;
        refreshed.preview_point_count = preview_point_count;
        refreshed
            .selected
            .try_reserve(selected.len())
            .map_err(|_| CanvasError::SelectionCapacityReached)?;
        for identity in selected {
            if refreshed.strokes.contains_key(&identity) {
                refreshed.selected.insert(identity);
            }
        }
        *self = refreshed;
        Ok(())
    }

    pub(crate) fn set_session_origin(&mut self, session_id: &str, origin: CanvasOrigin) {
        self.origins_by_session
            .insert(session_id.to_owned(), origin);
    }

    /// Adds only a caller-validated provisional direct pen sample. Mouse,
    /// public Winit, and Wintab events have no fallback into this path.
    #[cfg(test)]
    pub(crate) fn append_live_sample(
        &mut self,
        sample: &PhysicalSample,
        journal_id: &str,
        confirmed_direct_pen: bool,
    ) -> Result<(), CanvasError> {
        if !confirmed_direct_pen || sample.source_api != self.source_api_provisional {
            return Ok(());
        }
        let Some(stroke_id) = sample.stroke_id.as_deref() else {
            return Ok(());
        };
        let identity = StrokeRef {
            journal_id: journal_id.to_owned(),
            session_id: sample.session_id.clone(),
            source_api: sample.source_api.clone(),
            device_id: sample.source_device_id.clone(),
            pointer_id: sample.pointer_id,
            stroke_id: stroke_id.to_owned(),
        };
        self.push_point(
            identity,
            sample.source_sequence,
            sample.position.clone(),
            None,
        )
    }

    pub(crate) fn begin_preview_stroke(
        &mut self,
        identity: StrokeRef,
        view_frame: StrokeViewFrame,
    ) -> Result<(), CanvasError> {
        if !view_frame.is_valid() {
            return Err(CanvasError::InvalidTransform);
        }
        if let Some(existing) = self.preview_strokes.get(&identity) {
            return if existing.view_frame == Some(view_frame) {
                Ok(())
            } else {
                Err(CanvasError::StrokeViewFrameMismatch)
            };
        }
        if self
            .strokes
            .len()
            .saturating_add(self.preview_strokes.len())
            >= MAX_CANVAS_STROKES
        {
            return Err(CanvasError::StrokeCapacityReached);
        }
        self.preview_strokes
            .try_reserve(1)
            .map_err(|_| CanvasError::StrokeCapacityReached)?;
        self.preview_strokes.insert(
            identity.clone(),
            CanvasStroke {
                identity,
                view_frame: Some(view_frame),
                points: Vec::new(),
            },
        );
        Ok(())
    }

    pub(crate) fn append_preview_sample(
        &mut self,
        sample: &PhysicalSample,
        journal_id: &str,
        confirmed_direct_pen: bool,
    ) -> Result<Option<StrokeRef>, CanvasError> {
        if !confirmed_direct_pen || sample.source_api != self.source_api_provisional {
            return Ok(None);
        }
        let Some(stroke_id) = sample.stroke_id.as_deref() else {
            return Ok(None);
        };
        let identity = StrokeRef {
            journal_id: journal_id.to_owned(),
            session_id: sample.session_id.clone(),
            source_api: sample.source_api.clone(),
            device_id: sample.source_device_id.clone(),
            pointer_id: sample.pointer_id,
            stroke_id: stroke_id.to_owned(),
        };
        if !self.preview_strokes.contains_key(&identity) {
            return Err(CanvasError::MissingStrokeViewFrame);
        }
        self.push_preview_point(
            identity.clone(),
            sample.source_sequence,
            sample.position.clone(),
        )?;
        Ok(Some(identity))
    }

    pub(crate) fn promote_preview_stroke(
        &mut self,
        identity: &StrokeRef,
    ) -> Result<(), CanvasError> {
        let Some(preview) = self.preview_strokes.get(identity) else {
            return Ok(());
        };
        let preview_points = preview.points.len();
        if let Some(existing) = self.strokes.get_mut(identity) {
            if existing.points.len().saturating_add(preview_points) > MAX_POINTS_PER_STROKE {
                return Err(CanvasError::PointCapacityReached);
            }
            existing
                .points
                .try_reserve(preview_points)
                .map_err(|_| CanvasError::PointCapacityReached)?;
        } else {
            if self
                .strokes
                .len()
                .saturating_add(self.preview_strokes.len())
                > MAX_CANVAS_STROKES
            {
                return Err(CanvasError::StrokeCapacityReached);
            }
            self.strokes
                .try_reserve(1)
                .map_err(|_| CanvasError::StrokeCapacityReached)?;
        }
        let mut preview = self
            .preview_strokes
            .remove(identity)
            .expect("preview was checked above");
        self.preview_point_count = self.preview_point_count.saturating_sub(preview_points);
        if let Some(existing) = self.strokes.get_mut(identity) {
            existing.points.append(&mut preview.points);
        } else {
            self.strokes.insert(identity.clone(), preview);
        }
        self.point_count = self.point_count.saturating_add(preview_points);
        Ok(())
    }

    pub(crate) fn discard_preview_stroke(&mut self, identity: &StrokeRef) {
        if let Some(preview) = self.preview_strokes.remove(identity) {
            self.preview_point_count = self
                .preview_point_count
                .saturating_sub(preview.points.len());
        }
    }

    pub(crate) fn discard_all_preview_strokes(&mut self) {
        self.preview_strokes.clear();
        self.preview_point_count = 0;
    }

    fn load_origins<'a>(
        &mut self,
        metadata: impl Iterator<Item = &'a JournalMetadata>,
    ) -> Result<(), CanvasError> {
        let mut partial = HashMap::<String, (Option<i64>, Option<i64>)>::new();
        for entry in metadata {
            if entry.scope != MetadataScope::Session {
                continue;
            }
            let Ok(value) = entry.value.parse::<i64>() else {
                continue;
            };
            if !partial.contains_key(&entry.scope_id) {
                partial
                    .try_reserve(1)
                    .map_err(|_| CanvasError::StrokeCapacityReached)?;
                partial.insert(entry.scope_id.clone(), (None, None));
            }
            let origin = partial
                .get_mut(&entry.scope_id)
                .expect("origin was inserted");
            match entry.key.as_str() {
                ORIGIN_X_KEY => origin.0 = Some(value),
                ORIGIN_Y_KEY => origin.1 = Some(value),
                _ => {}
            }
        }
        self.origins_by_session.clear();
        self.origins_by_session
            .try_reserve(partial.len())
            .map_err(|_| CanvasError::StrokeCapacityReached)?;
        for (session, (x, y)) in partial {
            if let (Some(x_screen_px), Some(y_screen_px)) = (x, y) {
                self.origins_by_session.insert(
                    session,
                    CanvasOrigin {
                        x_screen_px,
                        y_screen_px,
                    },
                );
            }
        }
        Ok(())
    }

    fn push_point(
        &mut self,
        identity: StrokeRef,
        source_sequence_raw: u64,
        position: Option<RawPosition>,
        view_frame: Option<StrokeViewFrame>,
    ) -> Result<(), CanvasError> {
        let Some(position) = position else {
            return Ok(());
        };
        if position.coordinate_space != SCREEN_POSITION_SPACE
            || position.units != SCREEN_POSITION_UNITS
        {
            return Ok(());
        }
        if !self.strokes.contains_key(&identity) {
            if self
                .strokes
                .len()
                .saturating_add(self.preview_strokes.len())
                >= MAX_CANVAS_STROKES
            {
                return Err(CanvasError::StrokeCapacityReached);
            }
            self.strokes
                .try_reserve(1)
                .map_err(|_| CanvasError::StrokeCapacityReached)?;
            self.strokes.insert(
                identity.clone(),
                CanvasStroke {
                    identity: identity.clone(),
                    view_frame,
                    points: Vec::new(),
                },
            );
        }
        if let Some(frame) = view_frame
            && self
                .strokes
                .get(&identity)
                .is_some_and(|stroke| stroke.view_frame.is_some_and(|existing| existing != frame))
        {
            return Err(CanvasError::StrokeViewFrameMismatch);
        }
        if self.point_count.saturating_add(self.preview_point_count) >= MAX_VISIBLE_POINTS {
            return Err(CanvasError::PointCapacityReached);
        }
        let stroke = self
            .strokes
            .get_mut(&identity)
            .expect("stroke was inserted");
        if stroke.points.len() >= MAX_POINTS_PER_STROKE {
            return Err(CanvasError::PointCapacityReached);
        }
        stroke
            .points
            .try_reserve(1)
            .map_err(|_| CanvasError::PointCapacityReached)?;
        stroke.points.push(CanvasPoint {
            source_sequence_raw,
            position,
        });
        self.point_count += 1;
        Ok(())
    }

    fn push_preview_point(
        &mut self,
        identity: StrokeRef,
        source_sequence_raw: u64,
        position: Option<RawPosition>,
    ) -> Result<(), CanvasError> {
        let Some(position) = position else {
            return Ok(());
        };
        if position.coordinate_space != SCREEN_POSITION_SPACE
            || position.units != SCREEN_POSITION_UNITS
        {
            return Ok(());
        }
        if self.point_count.saturating_add(self.preview_point_count) >= MAX_VISIBLE_POINTS {
            return Err(CanvasError::PointCapacityReached);
        }
        if !self.preview_strokes.contains_key(&identity) {
            return Err(CanvasError::MissingStrokeViewFrame);
        }
        let stroke = self
            .preview_strokes
            .get_mut(&identity)
            .expect("preview stroke was inserted");
        if stroke.points.len() >= MAX_POINTS_PER_STROKE {
            return Err(CanvasError::PointCapacityReached);
        }
        stroke
            .points
            .try_reserve(1)
            .map_err(|_| CanvasError::PointCapacityReached)?;
        stroke.points.push(CanvasPoint {
            source_sequence_raw,
            position,
        });
        self.preview_point_count += 1;
        Ok(())
    }

    pub(crate) fn set_tool(&mut self, tool: CanvasTool) {
        self.tool = tool;
    }

    pub(crate) fn tool(&self) -> CanvasTool {
        self.tool
    }

    pub(crate) fn set_selection_rect(&mut self, rect: Option<CanvasRect>) {
        self.active_selection = rect;
    }

    pub(crate) fn select_region(
        &mut self,
        viewport: CanvasViewport,
        rect: CanvasRect,
    ) -> Result<(), CanvasError> {
        self.selected.clear();
        for (key, stroke) in &self.strokes {
            let origin = self.origin_for(&key.session_id);
            if stroke.points.iter().any(|point| {
                let mapped = match stroke.view_frame {
                    Some(frame) => viewport.map_raw_point_in_stroke_frame(&point.position, frame),
                    None => viewport.map_raw_point(&point.position, origin),
                };
                mapped.is_ok_and(|mapped| rect.contains((f64::from(mapped.x), f64::from(mapped.y))))
            }) {
                self.selected
                    .try_reserve(1)
                    .map_err(|_| CanvasError::SelectionCapacityReached)?;
                self.selected.insert(key.clone());
            }
        }
        self.active_selection = Some(rect);
        Ok(())
    }

    pub(crate) fn select_target(&mut self, target: Option<StrokeRef>) -> Result<(), CanvasError> {
        self.selected.clear();
        if let Some(target) = target {
            self.selected
                .try_reserve(1)
                .map_err(|_| CanvasError::SelectionCapacityReached)?;
            self.selected.insert(target);
        }
        self.active_selection = None;
        Ok(())
    }

    pub(crate) fn selected_targets(&self) -> Result<Vec<StrokeRef>, CanvasError> {
        if self.selected.len() > crate::journal::MAX_EDIT_TARGETS {
            return Err(CanvasError::SelectionCapacityReached);
        }
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(self.selected.len())
            .map_err(|_| CanvasError::SelectionCapacityReached)?;
        targets.extend(self.selected.iter().cloned());
        targets.sort();
        Ok(targets)
    }

    pub(crate) fn tombstone_selected_command(&self) -> Result<Option<EditCommand>, CanvasError> {
        let targets = self.selected_targets()?;
        if targets.is_empty() {
            Ok(None)
        } else {
            Ok(Some(EditCommand::Tombstone { targets }))
        }
    }

    pub(crate) fn render_plan(
        &self,
        viewport: CanvasViewport,
    ) -> Result<Vec<RenderedStroke>, CanvasError> {
        let mut output = Vec::new();
        output
            .try_reserve(
                self.strokes
                    .len()
                    .saturating_add(self.preview_strokes.len()),
            )
            .map_err(|_| CanvasError::StrokeCapacityReached)?;
        for (identity, stroke) in &self.strokes {
            let origin = self.origin_for(&identity.session_id);
            let mut points = Vec::new();
            points
                .try_reserve(stroke.points.len())
                .map_err(|_| CanvasError::PointCapacityReached)?;
            for point in &stroke.points {
                points.push(match stroke.view_frame {
                    Some(frame) => {
                        viewport.map_raw_point_in_stroke_frame(&point.position, frame)?
                    }
                    None => viewport.map_raw_point(&point.position, origin)?,
                });
            }
            output.push(RenderedStroke {
                identity: identity.clone(),
                points,
                selected: self.selected.contains(identity),
                preview: false,
            });
        }
        for (identity, stroke) in &self.preview_strokes {
            let origin = self.origin_for(&identity.session_id);
            let mut points = Vec::new();
            points
                .try_reserve(stroke.points.len())
                .map_err(|_| CanvasError::PointCapacityReached)?;
            for point in &stroke.points {
                points.push(match stroke.view_frame {
                    Some(frame) => {
                        viewport.map_raw_point_in_stroke_frame(&point.position, frame)?
                    }
                    None => viewport.map_raw_point(&point.position, origin)?,
                });
            }
            output.push(RenderedStroke {
                identity: identity.clone(),
                points,
                selected: self.selected.contains(identity),
                preview: true,
            });
        }
        output.sort_by(|left, right| left.identity.cmp(&right.identity));
        Ok(output)
    }

    pub(crate) fn hit_test(
        &self,
        viewport: CanvasViewport,
        client_x: f64,
        client_y: f64,
        tolerance_px: f64,
    ) -> Result<Option<StrokeRef>, CanvasError> {
        if !client_x.is_finite() || !client_y.is_finite() || !tolerance_px.is_finite() {
            return Err(CanvasError::InvalidTransform);
        }
        let tolerance_squared = tolerance_px.max(0.0).powi(2);
        let mut nearest: Option<(f64, StrokeRef)> = None;
        for rendered in self.render_plan(viewport)? {
            if rendered.preview {
                continue;
            }
            let distance = polyline_distance_squared(&rendered.points, client_x, client_y);
            if distance <= tolerance_squared
                && nearest.as_ref().is_none_or(|(best, _)| distance < *best)
            {
                nearest = Some((distance, rendered.identity));
            }
        }
        Ok(nearest.map(|(_, identity)| identity))
    }

    pub(crate) fn raw_move_delta_from_view_drag(
        &self,
        identity: &StrokeRef,
        viewport: CanvasViewport,
        delta_client_x: f64,
        delta_client_y: f64,
    ) -> Result<(i64, i64), CanvasError> {
        if !delta_client_x.is_finite() || !delta_client_y.is_finite() || viewport.zoom <= 0.0 {
            return Err(CanvasError::InvalidTransform);
        }
        let stroke = self
            .strokes
            .get(identity)
            .ok_or(CanvasError::InvalidTransform)?;
        let captured_zoom = stroke
            .view_frame
            .map(|frame| f64::from_bits(frame.canvas_zoom_bits))
            .unwrap_or(1.0);
        if !captured_zoom.is_finite() || captured_zoom <= 0.0 {
            return Err(CanvasError::InvalidTransform);
        }
        let raw_x = delta_client_x / viewport.zoom * captured_zoom;
        let raw_y = delta_client_y / viewport.zoom * captured_zoom;
        let rounded_x = raw_x.round();
        let rounded_y = raw_y.round();
        let minimum = i64::MIN as f64;
        let maximum_exclusive = -minimum;
        if !rounded_x.is_finite()
            || !rounded_y.is_finite()
            || rounded_x < minimum
            || rounded_x >= maximum_exclusive
            || rounded_y < minimum
            || rounded_y >= maximum_exclusive
        {
            return Err(CanvasError::InvalidTransform);
        }
        Ok((rounded_x as i64, rounded_y as i64))
    }

    #[cfg(test)]
    pub(crate) fn provisional_source_api(&self) -> &str {
        &self.source_api_provisional
    }

    #[cfg(test)]
    pub(crate) fn stroke_count(&self) -> usize {
        self.strokes.len()
    }

    fn origin_for(&self, session_id: &str) -> CanvasOrigin {
        self.origins_by_session
            .get(session_id)
            .copied()
            .unwrap_or_default()
    }
}

/// A validated geometry-only projection of the selected, committed Direct
/// samples. `samples_in_journal_order` is never sorted by source clock or
/// `StrokeRef`; `source_sample` preserves the exact immutable journal payload.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalRasterProjectionPlanV1 {
    journal_id: String,
    logical_revision: u64,
    last_sequence: u64,
    /// The caller's selection order is kept separately from physical sample order.
    selected_strokes: Vec<StrokeRef>,
    samples_in_journal_order: Vec<CanonicalRasterProjectionSampleV1>,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalRasterProjectionSampleV1 {
    journal_sequence: u64,
    source_sequence_raw: u64,
    stroke_ref: StrokeRef,
    view_frame: StrokeViewFrame,
    /// Exact source values are copied as evidence and are never rewritten by
    /// the derived mapping below.
    source_sample: PhysicalSample,
    effective_position: RawPosition,
    /// Position mapped through the captured stroke frame into the default
    /// canvas view. This is geometry only; no raster pixels are generated here.
    canonical_canvas_position_px: CanvasPointPx,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalRasterProjectionCropV1 {
    /// Inclusive bounds in the plan's default-canvas pixel coordinates.
    pub left_px: i32,
    pub top_px: i32,
    /// Exclusive bounds. A point on the right or bottom edge is rejected.
    pub right_px_exclusive: i32,
    pub bottom_px_exclusive: i32,
}

macro_rules! raster_spec_enum {
    ($name:ident, $variant:ident) => {
        #[cfg_attr(
            not(test),
            expect(
                dead_code,
                reason = "consumed by the later raster pixel-rendering slice"
            )
        )]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) enum $name {
            $variant,
        }
    };
}

raster_spec_enum!(CanonicalRasterAspectRatioPolicyV1, FitContainCentered);
raster_spec_enum!(CanonicalRasterPixelLayoutV1, Rgba8PremultipliedSrgbTopDown);
raster_spec_enum!(CanonicalRasterCoveragePolicyV1, Antialiased);
raster_spec_enum!(CanonicalRasterStrokeCapV1, Round);
raster_spec_enum!(CanonicalRasterStrokeJoinV1, Round);
raster_spec_enum!(CanonicalRasterRoundingPolicyV1, NearestTiesAwayQ16);
raster_spec_enum!(
    CanonicalRasterClippingPolicyV1,
    RejectPointsOutsideSourceCropClipCoverageAtOutputBounds
);
raster_spec_enum!(
    CanonicalRasterSinglePointPolicyV1,
    OpaqueDiscAtObservedPoint
);
raster_spec_enum!(CanonicalRasterStrokeOrderPolicyV1, JournalFirstOccurrence);

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalRasterProjectionSpecV1 {
    schema_version: u32,
    output_width_px: u32,
    output_height_px: u32,
    source_crop: CanonicalRasterProjectionCropV1,
    aspect_ratio_policy: CanonicalRasterAspectRatioPolicyV1,
    pixel_layout: CanonicalRasterPixelLayoutV1,
    coverage_policy: CanonicalRasterCoveragePolicyV1,
    background_rgba: [u8; 4],
    committed_ink_rgba: [u8; 4],
    stroke_width_16_16: u32,
    stroke_cap: CanonicalRasterStrokeCapV1,
    stroke_join: CanonicalRasterStrokeJoinV1,
    rounding_policy: CanonicalRasterRoundingPolicyV1,
    clipping_policy: CanonicalRasterClippingPolicyV1,
    single_point_policy: CanonicalRasterSinglePointPolicyV1,
    stroke_order_policy: CanonicalRasterStrokeOrderPolicyV1,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
impl CanonicalRasterProjectionSpecV1 {
    pub(crate) fn new(
        output_width_px: u32,
        output_height_px: u32,
        source_crop: CanonicalRasterProjectionCropV1,
    ) -> Self {
        Self {
            schema_version: 1,
            output_width_px,
            output_height_px,
            source_crop,
            aspect_ratio_policy: CanonicalRasterAspectRatioPolicyV1::FitContainCentered,
            pixel_layout: CanonicalRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown,
            coverage_policy: CanonicalRasterCoveragePolicyV1::Antialiased,
            background_rgba: CANONICAL_RASTER_BACKGROUND_RGBA,
            committed_ink_rgba: CANONICAL_RASTER_INK_RGBA,
            stroke_width_16_16: CANONICAL_RASTER_INK_WIDTH_16_16,
            stroke_cap: CanonicalRasterStrokeCapV1::Round,
            stroke_join: CanonicalRasterStrokeJoinV1::Round,
            rounding_policy: CanonicalRasterRoundingPolicyV1::NearestTiesAwayQ16,
            clipping_policy:
                CanonicalRasterClippingPolicyV1::RejectPointsOutsideSourceCropClipCoverageAtOutputBounds,
            single_point_policy: CanonicalRasterSinglePointPolicyV1::OpaqueDiscAtObservedPoint,
            stroke_order_policy: CanonicalRasterStrokeOrderPolicyV1::JournalFirstOccurrence,
        }
    }

    fn validate(&self) -> Result<(i128, i128, u32, u32), CanvasError> {
        if self.schema_version != 1
            || self.output_width_px == 0
            || self.output_height_px == 0
            || self.output_width_px > MAX_CANONICAL_RASTER_OUTPUT_DIMENSION
            || self.output_height_px > MAX_CANONICAL_RASTER_OUTPUT_DIMENSION
            || self.background_rgba != CANONICAL_RASTER_BACKGROUND_RGBA
            || self.committed_ink_rgba != CANONICAL_RASTER_INK_RGBA
            || self.stroke_width_16_16 != CANONICAL_RASTER_INK_WIDTH_16_16
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "raster projection spec has unsupported version, bounds, or ink style",
            ));
        }

        let output_pixels = u64::from(self.output_width_px)
            .checked_mul(u64::from(self.output_height_px))
            .ok_or(CanvasError::InvalidTransform)?;
        let row_stride_bytes = self
            .output_width_px
            .checked_mul(CANONICAL_RASTER_BYTES_PER_PIXEL)
            .ok_or(CanvasError::InvalidTransform)?;
        let output_buffer_bytes = row_stride_bytes
            .checked_mul(self.output_height_px)
            .ok_or(CanvasError::InvalidTransform)?;
        if output_pixels > MAX_CANONICAL_RASTER_OUTPUT_PIXELS
            || u64::from(output_buffer_bytes) > MAX_CANONICAL_RASTER_OUTPUT_BYTES
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "raster output pixel or byte cap exceeded",
            ));
        }

        let crop_width =
            i128::from(self.source_crop.right_px_exclusive) - i128::from(self.source_crop.left_px);
        let crop_height =
            i128::from(self.source_crop.bottom_px_exclusive) - i128::from(self.source_crop.top_px);
        if crop_width <= 0
            || crop_height <= 0
            || crop_width > i128::from(MAX_CANONICAL_RASTER_CROP_DIMENSION)
            || crop_height > i128::from(MAX_CANONICAL_RASTER_CROP_DIMENSION)
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "source crop is empty, reversed, or exceeds its dimension cap",
            ));
        }
        let crop_area = crop_width
            .checked_mul(crop_height)
            .ok_or(CanvasError::InvalidTransform)?;
        if crop_area > i128::from(MAX_CANONICAL_RASTER_CROP_AREA) {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "source crop area cap exceeded",
            ));
        }
        Ok((
            crop_width,
            crop_height,
            row_stride_bytes,
            output_buffer_bytes,
        ))
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalRasterOutputPointV1 {
    journal_sequence: u64,
    source_sequence_raw: u64,
    stroke_ref: StrokeRef,
    /// Fixed-point pixel coordinates with 16 fractional bits.
    x_subpixel_16_16: i64,
    y_subpixel_16_16: i64,
    /// A tap remains one source point; the later backend paints the declared disc.
    is_single_point_stroke: bool,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalRasterOutputGeometryV1 {
    schema_version: u32,
    source_journal_id: String,
    source_logical_revision: u64,
    source_last_sequence: u64,
    /// Fingerprints are computed from actual owned plan data and spec fields.
    source_content_sha256: [u8; 32],
    projection_spec_sha256: [u8; 32],
    geometry_sha256: [u8; 32],
    spec: CanonicalRasterProjectionSpecV1,
    output_width_px: u32,
    output_height_px: u32,
    row_stride_bytes: u32,
    output_buffer_bytes: u32,
    /// Canonical render order derives from first physical journal occurrence.
    stroke_draw_order: Vec<StrokeRef>,
    /// Original caller selection metadata is retained outside the render identity.
    caller_selection_order: Vec<StrokeRef>,
    points_in_journal_order: Vec<CanonicalRasterOutputPointV1>,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster export/provider slice"
    )
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalRasterImageV1 {
    schema_version: u32,
    renderer_version: &'static str,
    source_journal_id: String,
    source_logical_revision: u64,
    source_last_sequence: u64,
    source_content_sha256: [u8; 32],
    projection_spec_sha256: [u8; 32],
    geometry_sha256: [u8; 32],
    output_width_px: u32,
    output_height_px: u32,
    row_stride_bytes: u32,
    pixel_layout: CanonicalRasterPixelLayoutV1,
    /// Owned, top-down, premultiplied RGBA8 pixel bytes.
    rgba8_premultiplied_srgb_top_down: Vec<u8>,
    /// Encoded PNG bytes, retained separately from the canonical pixel buffer.
    png_bytes: Vec<u8>,
    pixel_bytes_sha256: [u8; 32],
    png_bytes_sha256: [u8; 32],
    /// Binds source/spec/geometry, renderer identity, layout and both byte hashes.
    raster_artifact_sha256: [u8; 32],
}

/// Build a strict, immutable geometry view from the current append-only
/// journal projection. No session-origin/default-frame fallback is used here:
/// every selected stroke must have exactly one valid captured start frame.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
pub(crate) fn build_canonical_raster_projection_plan(
    state: &JournalReplayState,
    selected_strokes: &[StrokeRef],
) -> Result<CanonicalRasterProjectionPlanV1, CanvasError> {
    if state.journal_id.is_empty()
        || selected_strokes.is_empty()
        || selected_strokes.len() > MAX_CANONICAL_RASTER_STROKES
    {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "journal ID or selected stroke count is invalid",
        ));
    }

    let mut stroke_frames = Vec::<(&StrokeRef, StrokeViewFrame)>::new();
    stroke_frames
        .try_reserve_exact(selected_strokes.len())
        .map_err(|_| CanvasError::StrokeCapacityReached)?;
    for (index, target) in selected_strokes.iter().enumerate() {
        if selected_strokes[..index].contains(target) {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected StrokeRefs must be unique",
            ));
        }
        if target.journal_id != state.journal_id
            || target.source_api != PROVISIONAL_DIRECT_SOURCE_API
            || target.stroke_id.is_empty()
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected stroke is outside this journal or unsupported Direct source",
            ));
        }

        let mut matching_starts = state
            .stroke_starts
            .iter()
            .filter(|start| &start.target == target);
        let start = matching_starts
            .next()
            .ok_or(CanvasError::MissingStrokeViewFrame)?;
        if matching_starts.next().is_some() {
            return Err(CanvasError::StrokeViewFrameMismatch);
        }
        if !start.view_frame.is_valid()
            || i32::try_from(start.view_frame.screen_origin_x_px).is_err()
            || i32::try_from(start.view_frame.screen_origin_y_px).is_err()
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected stroke has an invalid captured view frame or screen origin",
            ));
        }
        // The initial header epoch intentionally keeps marker-less legacy
        // strokes visible. A typed started stroke is stricter: it needs a
        // durable commit in history and an active visible logical state.
        let has_durable_commit = state.edit_actions.iter().any(|action| {
            matches!(
                &action.command,
                EditCommand::StrokeVisibility { targets, visible: true }
                    if targets.contains(target)
            )
        });
        if !has_durable_commit {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected started stroke has no durable commit history",
            ));
        }
        let mut explicit_visibility = None;
        for action in state.edit_actions.iter().filter(|action| action.active) {
            match &action.command {
                EditCommand::Tombstone { targets } if targets.contains(target) => {
                    explicit_visibility = Some(false);
                }
                EditCommand::Restore { targets } if targets.contains(target) => {
                    explicit_visibility = Some(true);
                }
                EditCommand::StrokeVisibility { targets, visible } if targets.contains(target) => {
                    explicit_visibility = Some(*visible);
                }
                _ => {}
            }
        }
        if explicit_visibility != Some(true) {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected started stroke is not currently visible",
            ));
        }
        stroke_frames.push((target, start.view_frame));
    }

    let projected = state.projected_samples()?;
    let mut samples_in_journal_order = Vec::new();
    let mut selected_sample_counts = Vec::new();
    selected_sample_counts
        .try_reserve_exact(selected_strokes.len())
        .map_err(|_| CanvasError::StrokeCapacityReached)?;
    selected_sample_counts.resize(selected_strokes.len(), 0usize);

    let mut previous_journal_sequence = None;
    let mut total_raw_sample_bytes = 0usize;
    for projected_sample in projected {
        if previous_journal_sequence.is_some_and(|previous| projected_sample.sequence <= previous) {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "projected samples are not in strict journal sequence order",
            ));
        }
        previous_journal_sequence = Some(projected_sample.sequence);
        if projected_sample.sequence > state.last_sequence {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "projected sample sequence exceeds the journal revision",
            ));
        }

        let Some(sample_stroke) = projected_sample.stroke_ref.as_ref() else {
            continue;
        };
        let Some(selected_index) = stroke_frames
            .iter()
            .position(|(target, _)| *target == sample_stroke)
        else {
            continue;
        };
        let Some(raw_position) = projected_sample.sample.position.as_ref() else {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected sample has no raw position",
            ));
        };
        let Some(effective_position) = projected_sample.effective_position.as_ref() else {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected sample has no derived position",
            ));
        };
        if raw_position.coordinate_space != SCREEN_POSITION_SPACE
            || raw_position.units != SCREEN_POSITION_UNITS
            || effective_position.coordinate_space != SCREEN_POSITION_SPACE
            || effective_position.units != SCREEN_POSITION_UNITS
        {
            return Err(CanvasError::UnsupportedCoordinateSpace {
                coordinate_space: effective_position.coordinate_space.clone(),
                units: effective_position.units.clone(),
            });
        }
        if i32::try_from(raw_position.x_raw).is_err() || i32::try_from(raw_position.y_raw).is_err()
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "raw Direct screen position is outside the native POINT range",
            ));
        }

        let (stroke_ref, view_frame) = stroke_frames[selected_index];
        if projected_sample.sample.source_api != PROVISIONAL_DIRECT_SOURCE_API
            || sample_stroke.source_api != PROVISIONAL_DIRECT_SOURCE_API
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected sample source does not match the supported Direct source",
            ));
        }
        let canonical_canvas_position_px = CanvasViewport::default()
            .map_raw_point_in_stroke_frame(effective_position, view_frame)?;
        if projected_sample.sample.raw_payload.len() > MAX_CANONICAL_RASTER_SINGLE_SAMPLE_BYTES {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected raw sample payload exceeds its fixed byte cap",
            ));
        }
        total_raw_sample_bytes = total_raw_sample_bytes
            .checked_add(projected_sample.sample.raw_payload.len())
            .ok_or(CanvasError::PointCapacityReached)?;
        if total_raw_sample_bytes > MAX_CANONICAL_RASTER_RAW_SAMPLE_BYTES {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "selected raw sample payload total exceeds its fixed byte cap",
            ));
        }
        if samples_in_journal_order.len() >= MAX_CANONICAL_RASTER_SAMPLES {
            return Err(CanvasError::PointCapacityReached);
        }
        samples_in_journal_order
            .try_reserve(1)
            .map_err(|_| CanvasError::PointCapacityReached)?;
        samples_in_journal_order.push(CanonicalRasterProjectionSampleV1 {
            journal_sequence: projected_sample.sequence,
            source_sequence_raw: projected_sample.sample.source_sequence,
            stroke_ref: stroke_ref.to_owned(),
            view_frame,
            source_sample: (*projected_sample.sample).clone(),
            effective_position: effective_position.to_owned(),
            canonical_canvas_position_px,
        });
        selected_sample_counts[selected_index] = selected_sample_counts[selected_index]
            .checked_add(1)
            .ok_or(CanvasError::PointCapacityReached)?;
    }

    if selected_sample_counts.contains(&0) {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "selected stroke has no visible committed sample in this journal revision",
        ));
    }

    let mut selected_stroke_snapshot = Vec::new();
    selected_stroke_snapshot
        .try_reserve_exact(selected_strokes.len())
        .map_err(|_| CanvasError::StrokeCapacityReached)?;
    selected_stroke_snapshot.extend(selected_strokes.iter().cloned());

    Ok(CanonicalRasterProjectionPlanV1 {
        journal_id: state.journal_id.to_owned(),
        logical_revision: state.logical_revision,
        last_sequence: state.last_sequence,
        selected_strokes: selected_stroke_snapshot,
        samples_in_journal_order,
    })
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
pub(crate) fn transform_canonical_raster_geometry(
    plan: &CanonicalRasterProjectionPlanV1,
    spec: &CanonicalRasterProjectionSpecV1,
) -> Result<CanonicalRasterOutputGeometryV1, CanvasError> {
    let (crop_width, crop_height, row_stride_bytes, output_buffer_bytes) = spec.validate()?;
    if plan.journal_id.is_empty()
        || plan.selected_strokes.is_empty()
        || plan.selected_strokes.len() > MAX_CANONICAL_RASTER_STROKES
        || plan.samples_in_journal_order.is_empty()
        || plan.samples_in_journal_order.len() > MAX_CANONICAL_RASTER_SAMPLES
    {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "owned source plan is empty or exceeds its fixed item caps",
        ));
    }

    let mut frame_by_selected_stroke = Vec::new();
    frame_by_selected_stroke
        .try_reserve_exact(plan.selected_strokes.len())
        .map_err(|_| CanvasError::StrokeCapacityReached)?;
    let mut sample_counts = Vec::new();
    sample_counts
        .try_reserve_exact(plan.selected_strokes.len())
        .map_err(|_| CanvasError::StrokeCapacityReached)?;
    sample_counts.resize(plan.selected_strokes.len(), 0usize);
    for (index, stroke) in plan.selected_strokes.iter().enumerate() {
        if plan.selected_strokes[..index].contains(stroke)
            || stroke.journal_id != plan.journal_id
            || stroke.source_api != PROVISIONAL_DIRECT_SOURCE_API
            || stroke.stroke_id.is_empty()
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "output stroke order contains a duplicate or unsupported StrokeRef",
            ));
        }
        frame_by_selected_stroke.push(None::<StrokeViewFrame>);
    }

    let mut previous_journal_sequence = None;
    let mut total_raw_sample_bytes = 0usize;
    for point in &plan.samples_in_journal_order {
        if previous_journal_sequence.is_some_and(|sequence| point.journal_sequence <= sequence)
            || point.journal_sequence > plan.last_sequence
            || point.source_sequence_raw != point.source_sample.source_sequence
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "output plan points are not a valid physical journal sequence",
            ));
        }
        previous_journal_sequence = Some(point.journal_sequence);

        let selected_index = plan
            .selected_strokes
            .iter()
            .position(|stroke| stroke == &point.stroke_ref)
            .ok_or(CanvasError::InvalidCanonicalRasterProjection(
                "output point refers to an unselected stroke",
            ))?;
        if point.stroke_ref.journal_id != plan.journal_id
            || point.stroke_ref.source_api != PROVISIONAL_DIRECT_SOURCE_API
            || point.source_sample.source_api != PROVISIONAL_DIRECT_SOURCE_API
            || point.source_sample.session_id != point.stroke_ref.session_id
            || point.source_sample.source_device_id != point.stroke_ref.device_id
            || point.source_sample.pointer_id != point.stroke_ref.pointer_id
            || point.source_sample.stroke_id.as_deref() != Some(point.stroke_ref.stroke_id.as_str())
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "output point raw provenance does not match its selected StrokeRef",
            ));
        }

        let raw_position = point.source_sample.position.as_ref().ok_or(
            CanvasError::InvalidCanonicalRasterProjection("output point has no raw position"),
        )?;
        if raw_position.coordinate_space != SCREEN_POSITION_SPACE
            || raw_position.units != SCREEN_POSITION_UNITS
            || i32::try_from(raw_position.x_raw).is_err()
            || i32::try_from(raw_position.y_raw).is_err()
            || point.effective_position.coordinate_space != SCREEN_POSITION_SPACE
            || point.effective_position.units != SCREEN_POSITION_UNITS
            || !point.view_frame.is_valid()
            || i32::try_from(point.view_frame.screen_origin_x_px).is_err()
            || i32::try_from(point.view_frame.screen_origin_y_px).is_err()
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "output point position or captured frame is unsupported",
            ));
        }
        if frame_by_selected_stroke[selected_index].is_some_and(|frame| frame != point.view_frame) {
            return Err(CanvasError::StrokeViewFrameMismatch);
        }
        frame_by_selected_stroke[selected_index] = Some(point.view_frame);
        let expected_canvas_position = CanvasViewport::default()
            .map_raw_point_in_stroke_frame(&point.effective_position, point.view_frame)?;
        if expected_canvas_position != point.canonical_canvas_position_px {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "stored canonical canvas position does not match its source frame",
            ));
        }
        if point.source_sample.raw_payload.len() > MAX_CANONICAL_RASTER_SINGLE_SAMPLE_BYTES {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "output point raw payload exceeds its fixed byte cap",
            ));
        }
        total_raw_sample_bytes = total_raw_sample_bytes
            .checked_add(point.source_sample.raw_payload.len())
            .ok_or(CanvasError::PointCapacityReached)?;
        if total_raw_sample_bytes > MAX_CANONICAL_RASTER_RAW_SAMPLE_BYTES {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "output point raw payload total exceeds its fixed byte cap",
            ));
        }
        sample_counts[selected_index] = sample_counts[selected_index]
            .checked_add(1)
            .ok_or(CanvasError::PointCapacityReached)?;
    }
    if frame_by_selected_stroke.iter().any(Option::is_none) || sample_counts.contains(&0) {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "output plan contains a selected stroke without visible committed geometry",
        ));
    }

    let stroke_draw_order = journal_first_occurrence_stroke_order(plan)?;
    let source_content_sha256 = hash_canonical_raster_source(plan, &stroke_draw_order);
    let projection_spec_sha256 =
        hash_canonical_raster_spec(spec, row_stride_bytes, output_buffer_bytes);
    let mut points_in_journal_order = Vec::new();
    points_in_journal_order
        .try_reserve_exact(plan.samples_in_journal_order.len())
        .map_err(|_| CanvasError::PointCapacityReached)?;
    for point in &plan.samples_in_journal_order {
        let selected_index = plan
            .selected_strokes
            .iter()
            .position(|stroke| stroke == &point.stroke_ref)
            .ok_or(CanvasError::InvalidCanonicalRasterProjection(
                "output point refers to an unselected stroke",
            ))?;
        let (x_subpixel_16_16, y_subpixel_16_16) = map_canonical_point_to_output(
            point.canonical_canvas_position_px,
            spec,
            crop_width,
            crop_height,
        )?;
        points_in_journal_order.push(CanonicalRasterOutputPointV1 {
            journal_sequence: point.journal_sequence,
            source_sequence_raw: point.source_sequence_raw,
            stroke_ref: point.stroke_ref.clone(),
            x_subpixel_16_16,
            y_subpixel_16_16,
            is_single_point_stroke: sample_counts[selected_index] == 1,
        });
    }

    let mut caller_selection_order = Vec::new();
    caller_selection_order
        .try_reserve_exact(plan.selected_strokes.len())
        .map_err(|_| CanvasError::StrokeCapacityReached)?;
    caller_selection_order.extend(plan.selected_strokes.iter().cloned());
    let mut geometry = CanonicalRasterOutputGeometryV1 {
        schema_version: 1,
        source_journal_id: plan.journal_id.clone(),
        source_logical_revision: plan.logical_revision,
        source_last_sequence: plan.last_sequence,
        source_content_sha256,
        projection_spec_sha256,
        geometry_sha256: [0; 32],
        spec: spec.clone(),
        output_width_px: spec.output_width_px,
        output_height_px: spec.output_height_px,
        row_stride_bytes,
        output_buffer_bytes,
        stroke_draw_order,
        caller_selection_order,
        points_in_journal_order,
    };
    geometry.geometry_sha256 = hash_canonical_raster_geometry(&geometry);
    Ok(geometry)
}

/// Render the already-validated canonical geometry with the pinned CPU
/// backend. This creates a projection artifact only; it does not claim parity
/// with an external rasterizer, UI frame, or recognition model preprocessing.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster export/provider slice"
    )
)]
pub(crate) fn render_canonical_raster(
    geometry: &CanonicalRasterOutputGeometryV1,
) -> Result<CanonicalRasterImageV1, CanvasError> {
    validate_canonical_raster_geometry_for_render(geometry)?;

    let pixel_byte_count = usize::try_from(geometry.output_buffer_bytes)
        .map_err(|_| CanvasError::RasterAllocationFailed)?;
    let mut pixels = Vec::new();
    pixels
        .try_reserve_exact(pixel_byte_count)
        .map_err(|_| CanvasError::RasterAllocationFailed)?;
    pixels.resize(pixel_byte_count, 0);
    let pixmap_size = IntSize::from_wh(geometry.output_width_px, geometry.output_height_px)
        .ok_or(CanvasError::RasterAllocationFailed)?;
    let mut pixmap =
        Pixmap::from_vec(pixels, pixmap_size).ok_or(CanvasError::RasterAllocationFailed)?;
    pixmap.fill(Color::from_rgba8(
        geometry.spec.background_rgba[0],
        geometry.spec.background_rgba[1],
        geometry.spec.background_rgba[2],
        geometry.spec.background_rgba[3],
    ));

    let mut paint = Paint::default();
    paint.set_color_rgba8(
        geometry.spec.committed_ink_rgba[0],
        geometry.spec.committed_ink_rgba[1],
        geometry.spec.committed_ink_rgba[2],
        geometry.spec.committed_ink_rgba[3],
    );
    paint.anti_alias = match geometry.spec.coverage_policy {
        CanonicalRasterCoveragePolicyV1::Antialiased => true,
    };
    // The projection's declared byte interpretation is sRGB. Pin the blend
    // behavior too; the output remains premultiplied RGBA8 as tiny-skia stores it.
    paint.colorspace = ColorSpace::FullSRGBGamma;
    paint.force_hq_pipeline = true;

    let stroke_width = checked_q16_to_renderer_f32(i64::from(geometry.spec.stroke_width_16_16))?;
    let mut stroke = Stroke::default();
    stroke.width = stroke_width;
    stroke.line_cap = match geometry.spec.stroke_cap {
        CanonicalRasterStrokeCapV1::Round => LineCap::Round,
    };
    stroke.line_join = match geometry.spec.stroke_join {
        CanonicalRasterStrokeJoinV1::Round => LineJoin::Round,
    };

    for stroke_ref in &geometry.stroke_draw_order {
        draw_canonical_raster_stroke(&mut pixmap, &paint, &stroke, geometry, stroke_ref)?;
    }

    if pixmap.data().len() != pixel_byte_count {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "renderer pixel buffer does not match the bounded RGBA8 layout",
        ));
    }
    let mut rgba8_premultiplied_srgb_top_down = Vec::new();
    rgba8_premultiplied_srgb_top_down
        .try_reserve_exact(pixel_byte_count)
        .map_err(|_| CanvasError::RasterAllocationFailed)?;
    rgba8_premultiplied_srgb_top_down.extend_from_slice(pixmap.data());
    if rgba8_premultiplied_srgb_top_down
        .chunks_exact(4)
        .any(|pixel| pixel[3] != 255)
    {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "opaque raster background or ink produced a non-opaque pixel",
        ));
    }

    let png_bytes = pixmap
        .encode_png()
        .map_err(|_| CanvasError::RasterEncodingFailed)?;
    if png_bytes.is_empty() || png_bytes.len() > MAX_CANONICAL_RASTER_PNG_BYTES {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "encoded PNG is empty or exceeds its fixed byte cap",
        ));
    }

    let pixel_bytes_sha256 = Sha256::digest(&rgba8_premultiplied_srgb_top_down).into();
    let png_bytes_sha256 = Sha256::digest(&png_bytes).into();
    let mut image = CanonicalRasterImageV1 {
        schema_version: 1,
        renderer_version: CANONICAL_RASTER_RENDERER_VERSION,
        source_journal_id: geometry.source_journal_id.clone(),
        source_logical_revision: geometry.source_logical_revision,
        source_last_sequence: geometry.source_last_sequence,
        source_content_sha256: geometry.source_content_sha256,
        projection_spec_sha256: geometry.projection_spec_sha256,
        geometry_sha256: geometry.geometry_sha256,
        output_width_px: geometry.output_width_px,
        output_height_px: geometry.output_height_px,
        row_stride_bytes: geometry.row_stride_bytes,
        pixel_layout: geometry.spec.pixel_layout,
        rgba8_premultiplied_srgb_top_down,
        png_bytes,
        pixel_bytes_sha256,
        png_bytes_sha256,
        raster_artifact_sha256: [0; 32],
    };
    image.raster_artifact_sha256 = hash_canonical_raster_artifact(&image);
    Ok(image)
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the canonical raster renderer")
)]
fn validate_canonical_raster_geometry_for_render(
    geometry: &CanonicalRasterOutputGeometryV1,
) -> Result<(), CanvasError> {
    let (_, _, expected_stride, expected_buffer_bytes) = geometry.spec.validate()?;
    let expected_spec_hash =
        hash_canonical_raster_spec(&geometry.spec, expected_stride, expected_buffer_bytes);
    if geometry.schema_version != 1
        || geometry.source_journal_id.is_empty()
        || geometry.output_width_px != geometry.spec.output_width_px
        || geometry.output_height_px != geometry.spec.output_height_px
        || geometry.row_stride_bytes != expected_stride
        || geometry.output_buffer_bytes != expected_buffer_bytes
        || geometry.projection_spec_sha256 != expected_spec_hash
        || geometry.geometry_sha256 != hash_canonical_raster_geometry(geometry)
        || geometry.stroke_draw_order.is_empty()
        || geometry.stroke_draw_order.len() > MAX_CANONICAL_RASTER_STROKES
        || geometry.points_in_journal_order.is_empty()
        || geometry.points_in_journal_order.len() > MAX_CANONICAL_RASTER_SAMPLES
        || geometry.caller_selection_order.len() != geometry.stroke_draw_order.len()
    {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "raster geometry identity, dimensions, order, or item bounds are invalid",
        ));
    }

    let q16_fixed_one = i64::from(1_u32 << 16);
    let max_x_q16 = i64::from(geometry.output_width_px)
        .checked_mul(q16_fixed_one)
        .ok_or(CanvasError::InvalidTransform)?;
    let max_y_q16 = i64::from(geometry.output_height_px)
        .checked_mul(q16_fixed_one)
        .ok_or(CanvasError::InvalidTransform)?;

    let mut derived_order = Vec::<StrokeRef>::new();
    derived_order
        .try_reserve_exact(geometry.stroke_draw_order.len())
        .map_err(|_| CanvasError::RasterAllocationFailed)?;
    let mut counts = Vec::<(StrokeRef, usize)>::new();
    counts
        .try_reserve_exact(geometry.stroke_draw_order.len())
        .map_err(|_| CanvasError::RasterAllocationFailed)?;
    let mut previous_sequence = None;
    for point in &geometry.points_in_journal_order {
        if point.journal_sequence == 0
            || point.journal_sequence > geometry.source_last_sequence
            || previous_sequence.is_some_and(|previous| point.journal_sequence <= previous)
            || point.stroke_ref.journal_id != geometry.source_journal_id
            || point.stroke_ref.source_api != PROVISIONAL_DIRECT_SOURCE_API
            || point.stroke_ref.stroke_id.is_empty()
            || point.x_subpixel_16_16 < 0
            || point.y_subpixel_16_16 < 0
            || point.x_subpixel_16_16 > max_x_q16
            || point.y_subpixel_16_16 > max_y_q16
        {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "raster points are not bounded physical-order Direct geometry",
            ));
        }
        previous_sequence = Some(point.journal_sequence);

        let point_xy = (point.x_subpixel_16_16, point.y_subpixel_16_16);
        if let Some(index) = counts
            .iter()
            .position(|(stroke_ref, _)| stroke_ref == &point.stroke_ref)
        {
            let entry = &mut counts[index];
            entry.1 = entry
                .1
                .checked_add(1)
                .ok_or(CanvasError::PointCapacityReached)?;
        } else {
            if derived_order.len() >= geometry.stroke_draw_order.len() {
                return Err(CanvasError::InvalidCanonicalRasterProjection(
                    "raster point references a stroke outside canonical draw order",
                ));
            }
            derived_order.push(point.stroke_ref.clone());
            counts.push((point.stroke_ref.clone(), 1));
        }
    }
    if derived_order != geometry.stroke_draw_order
        || counts.len() != geometry.stroke_draw_order.len()
        || geometry
            .caller_selection_order
            .iter()
            .enumerate()
            .any(|(index, stroke)| {
                geometry.caller_selection_order[..index].contains(stroke)
                    || !geometry.stroke_draw_order.contains(stroke)
            })
        || counts
            .iter()
            .any(|(stroke, count)| !geometry.stroke_draw_order.contains(stroke) || *count == 0)
    {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "raster stroke ordering or caller-selection provenance is inconsistent",
        ));
    }
    for point in &geometry.points_in_journal_order {
        let count = counts
            .iter()
            .find(|(stroke, _)| stroke == &point.stroke_ref)
            .map(|(_, count)| *count)
            .ok_or(CanvasError::InvalidCanonicalRasterProjection(
                "raster stroke count is missing",
            ))?;
        if point.is_single_point_stroke != (count == 1) {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "single-sample marker disagrees with physical stroke sample count",
            ));
        }
    }
    Ok(())
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the canonical raster renderer")
)]
fn draw_canonical_raster_stroke(
    pixmap: &mut Pixmap,
    paint: &Paint<'_>,
    stroke: &Stroke,
    geometry: &CanonicalRasterOutputGeometryV1,
    stroke_ref: &StrokeRef,
) -> Result<(), CanvasError> {
    let mut builder = PathBuilder::new();
    let mut first_renderer_point = None;
    let mut first_q16 = None;
    let mut all_points_repeat = true;
    let mut point_count = 0usize;
    for point in geometry
        .points_in_journal_order
        .iter()
        .filter(|point| &point.stroke_ref == stroke_ref)
    {
        let q16 = (point.x_subpixel_16_16, point.y_subpixel_16_16);
        let renderer_point = (
            checked_q16_to_renderer_f32(q16.0)?,
            checked_q16_to_renderer_f32(q16.1)?,
        );
        if let Some(first) = first_q16 {
            if q16 != first {
                all_points_repeat = false;
            }
            builder.line_to(renderer_point.0, renderer_point.1);
        } else {
            first_q16 = Some(q16);
            first_renderer_point = Some(renderer_point);
            builder.move_to(renderer_point.0, renderer_point.1);
        }
        point_count = point_count
            .checked_add(1)
            .ok_or(CanvasError::PointCapacityReached)?;
    }
    if point_count == 0 {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "canonical draw order contains a stroke with no points",
        ));
    }

    let path = if point_count == 1 || all_points_repeat {
        // A one-sample tap and a quantized/repeated-point stroke use only the
        // observed point. This draws the explicitly specified opaque disc and
        // never manufactures or stores another sample.
        let (x, y) = first_renderer_point.ok_or(CanvasError::InvalidCanonicalRasterProjection(
            "single-point center is missing",
        ))?;
        let radius = stroke.width / 2.0;
        if !radius.is_finite() || radius <= 0.0 {
            return Err(CanvasError::InvalidCanonicalRasterProjection(
                "canonical stroke radius is invalid",
            ));
        }
        let mut circle = PathBuilder::new();
        circle.push_circle(x, y, radius);
        circle
            .finish()
            .ok_or(CanvasError::InvalidCanonicalRasterProjection(
                "canonical tap disc could not be represented",
            ))?
    } else {
        builder
            .finish()
            .ok_or(CanvasError::InvalidCanonicalRasterProjection(
                "canonical stroke path could not be represented",
            ))?
    };

    if point_count == 1 || all_points_repeat {
        pixmap.fill_path(
            &path,
            paint,
            FillRule::Winding,
            RasterTransform::identity(),
            None,
        );
    } else {
        pixmap.stroke_path(&path, paint, stroke, RasterTransform::identity(), None);
    }
    Ok(())
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the canonical raster renderer")
)]
fn checked_q16_to_renderer_f32(value: i64) -> Result<f32, CanvasError> {
    let coordinate = value as f64 / CANONICAL_RASTER_FIXED_ONE as f64;
    if !coordinate.is_finite() || coordinate.abs() > f64::from(f32::MAX) {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "Q16 coordinate cannot be represented by the renderer",
        ));
    }
    let rendered = coordinate as f32;
    if !rendered.is_finite() {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "Q16 coordinate conversion overflowed renderer precision",
        ));
    }
    Ok(rendered)
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
fn journal_first_occurrence_stroke_order(
    plan: &CanonicalRasterProjectionPlanV1,
) -> Result<Vec<StrokeRef>, CanvasError> {
    let mut order = Vec::new();
    order
        .try_reserve_exact(plan.selected_strokes.len())
        .map_err(|_| CanvasError::StrokeCapacityReached)?;
    for point in &plan.samples_in_journal_order {
        if !order.contains(&point.stroke_ref) {
            if !plan.selected_strokes.contains(&point.stroke_ref) {
                return Err(CanvasError::InvalidCanonicalRasterProjection(
                    "journal point is outside the selected stroke set",
                ));
            }
            order.push(point.stroke_ref.clone());
        }
    }
    if order.len() != plan.selected_strokes.len() {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "journal first-occurrence order does not cover the selected stroke set",
        ));
    }
    Ok(order)
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
fn map_canonical_point_to_output(
    point: CanvasPointPx,
    spec: &CanonicalRasterProjectionSpecV1,
    crop_width: i128,
    crop_height: i128,
) -> Result<(i64, i64), CanvasError> {
    if point.x < spec.source_crop.left_px
        || point.x >= spec.source_crop.right_px_exclusive
        || point.y < spec.source_crop.top_px
        || point.y >= spec.source_crop.bottom_px_exclusive
    {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "projected point falls outside the declared source crop",
        ));
    }
    let relative_x = i128::from(point.x) - i128::from(spec.source_crop.left_px);
    let relative_y = i128::from(point.y) - i128::from(spec.source_crop.top_px);
    let output_width = i128::from(spec.output_width_px);
    let output_height = i128::from(spec.output_height_px);
    let width_scale_cross = output_width
        .checked_mul(crop_height)
        .ok_or(CanvasError::InvalidTransform)?;
    let height_scale_cross = output_height
        .checked_mul(crop_width)
        .ok_or(CanvasError::InvalidTransform)?;

    let (x_numerator, x_denominator, y_numerator, y_denominator) =
        if width_scale_cross <= height_scale_cross {
            let vertical_padding_numerator = height_scale_cross - width_scale_cross;
            let x_numerator = relative_x
                .checked_mul(output_width)
                .and_then(|value| value.checked_mul(CANONICAL_RASTER_FIXED_ONE))
                .ok_or(CanvasError::InvalidTransform)?;
            let y_numerator = relative_y
                .checked_mul(output_width)
                .and_then(|value| value.checked_mul(2))
                .and_then(|value| value.checked_add(vertical_padding_numerator))
                .and_then(|value| value.checked_mul(CANONICAL_RASTER_FIXED_ONE))
                .ok_or(CanvasError::InvalidTransform)?;
            (
                x_numerator,
                crop_width,
                y_numerator,
                crop_width
                    .checked_mul(2)
                    .ok_or(CanvasError::InvalidTransform)?,
            )
        } else {
            let horizontal_padding_numerator = width_scale_cross - height_scale_cross;
            let x_numerator = relative_x
                .checked_mul(output_height)
                .and_then(|value| value.checked_mul(2))
                .and_then(|value| value.checked_add(horizontal_padding_numerator))
                .and_then(|value| value.checked_mul(CANONICAL_RASTER_FIXED_ONE))
                .ok_or(CanvasError::InvalidTransform)?;
            let y_numerator = relative_y
                .checked_mul(output_height)
                .and_then(|value| value.checked_mul(CANONICAL_RASTER_FIXED_ONE))
                .ok_or(CanvasError::InvalidTransform)?;
            (
                x_numerator,
                crop_height
                    .checked_mul(2)
                    .ok_or(CanvasError::InvalidTransform)?,
                y_numerator,
                crop_height,
            )
        };
    let x_subpixel_16_16 = round_nonnegative_ratio_ties_away(x_numerator, x_denominator)?;
    let y_subpixel_16_16 = round_nonnegative_ratio_ties_away(y_numerator, y_denominator)?;
    let output_x_limit = output_width
        .checked_mul(CANONICAL_RASTER_FIXED_ONE)
        .ok_or(CanvasError::InvalidTransform)?;
    let output_y_limit = output_height
        .checked_mul(CANONICAL_RASTER_FIXED_ONE)
        .ok_or(CanvasError::InvalidTransform)?;
    if x_subpixel_16_16 < 0
        || y_subpixel_16_16 < 0
        || i128::from(x_subpixel_16_16) > output_x_limit
        || i128::from(y_subpixel_16_16) > output_y_limit
    {
        return Err(CanvasError::InvalidCanonicalRasterProjection(
            "transformed center falls outside bounded output geometry",
        ));
    }
    Ok((x_subpixel_16_16, y_subpixel_16_16))
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
fn round_nonnegative_ratio_ties_away(
    numerator: i128,
    denominator: i128,
) -> Result<i64, CanvasError> {
    if numerator < 0 || denominator <= 0 {
        return Err(CanvasError::InvalidTransform);
    }
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    let round_up = remainder
        .checked_mul(2)
        .ok_or(CanvasError::InvalidTransform)?
        >= denominator;
    let rounded = if round_up {
        quotient
            .checked_add(1)
            .ok_or(CanvasError::InvalidTransform)?
    } else {
        quotient
    };
    i64::try_from(rounded).map_err(|_| CanvasError::InvalidTransform)
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
struct CanonicalRasterHashWriter(Sha256);

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
impl CanonicalRasterHashWriter {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(domain);
        Self(hash)
    }

    fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn u32(&mut self, value: u32) {
        self.0.update(value.to_le_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.0.update(value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.0.update(value.to_le_bytes());
    }

    fn u128(&mut self, value: u128) {
        self.0.update(value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.0.update(value);
    }

    fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn optional_string(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.string(value);
            }
            None => self.u8(0),
        }
    }

    fn optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.u64(value);
            }
            None => self.u8(0),
        }
    }

    fn optional_i32(&mut self, value: Option<i32>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.i32(value);
            }
            None => self.u8(0),
        }
    }

    fn stroke_ref(&mut self, stroke: &StrokeRef) {
        self.string(&stroke.journal_id);
        self.string(&stroke.session_id);
        self.string(&stroke.source_api);
        self.optional_string(stroke.device_id.as_deref());
        self.optional_u64(stroke.pointer_id);
        self.string(&stroke.stroke_id);
    }

    fn frame(&mut self, frame: StrokeViewFrame) {
        self.i64(frame.screen_origin_x_px);
        self.i64(frame.screen_origin_y_px);
        self.u64(frame.dpi_scale_factor_bits);
        self.u64(frame.canvas_zoom_bits);
        self.u64(frame.canvas_pan_x_bits);
        self.u64(frame.canvas_pan_y_bits);
        self.u32(frame.toolbar_height_px);
    }

    fn position(&mut self, position: &RawPosition) {
        self.string(&position.coordinate_space);
        self.string(&position.units);
        self.i64(position.x_raw);
        self.i64(position.y_raw);
    }

    fn optional_position(&mut self, position: Option<&RawPosition>) {
        match position {
            Some(position) => {
                self.u8(1);
                self.position(position);
            }
            None => self.u8(0),
        }
    }

    fn optional_pressure(&mut self, pressure: Option<&RawPressure>) {
        match pressure {
            Some(pressure) => {
                self.u8(1);
                self.string(&pressure.representation);
                self.string(&pressure.units);
                self.u64(pressure.value_raw);
                self.optional_u64(pressure.mask_raw);
                self.optional_u64(pressure.minimum_raw);
                self.optional_u64(pressure.maximum_raw);
            }
            None => self.u8(0),
        }
    }

    fn optional_timestamp(&mut self, timestamp: Option<&NativeTimestamp>) {
        match timestamp {
            Some(timestamp) => {
                self.u8(1);
                self.string(&timestamp.clock_domain);
                self.string(&timestamp.units);
                self.u64(timestamp.count_raw);
                self.optional_u64(timestamp.frequency_hz);
            }
            None => self.u8(0),
        }
    }

    fn physical_sample(&mut self, sample: &PhysicalSample) {
        self.string(&sample.session_id);
        self.string(&sample.source_api);
        self.optional_string(sample.source_device_id.as_deref());
        self.optional_u64(sample.pointer_id);
        self.optional_string(sample.stroke_id.as_deref());
        self.u64(sample.source_sequence);
        self.optional_string(sample.config_id.as_deref());
        self.u128(sample.app_arrival_elapsed_ns);
        self.optional_position(sample.position.as_ref());
        self.optional_pressure(sample.pressure.as_ref());
        self.optional_timestamp(sample.native_timestamp.as_ref());
        self.optional_string(sample.contact_range_state.as_deref());
        self.optional_u64(sample.button_state_raw);
        self.optional_i32(sample.tilt_x_raw);
        self.optional_i32(sample.tilt_y_raw);
        self.optional_u64(sample.rotation_raw);
        self.bytes(&sample.raw_payload);
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
fn hash_canonical_raster_source(
    plan: &CanonicalRasterProjectionPlanV1,
    stroke_draw_order: &[StrokeRef],
) -> [u8; 32] {
    let mut hash = CanonicalRasterHashWriter::new(b"LassoInk/canonical-raster-source/v1\0");
    hash.string(&plan.journal_id);
    hash.u64(plan.logical_revision);
    hash.u64(plan.last_sequence);
    hash.u64(stroke_draw_order.len() as u64);
    for stroke in stroke_draw_order {
        hash.stroke_ref(stroke);
    }
    hash.u64(plan.samples_in_journal_order.len() as u64);
    for point in &plan.samples_in_journal_order {
        hash.u64(point.journal_sequence);
        hash.u64(point.source_sequence_raw);
        hash.stroke_ref(&point.stroke_ref);
        hash.frame(point.view_frame);
        hash.physical_sample(&point.source_sample);
        hash.position(&point.effective_position);
        hash.i32(point.canonical_canvas_position_px.x);
        hash.i32(point.canonical_canvas_position_px.y);
    }
    hash.finish()
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
fn hash_canonical_raster_spec(
    spec: &CanonicalRasterProjectionSpecV1,
    row_stride_bytes: u32,
    output_buffer_bytes: u32,
) -> [u8; 32] {
    let mut hash = CanonicalRasterHashWriter::new(b"LassoInk/canonical-raster-spec/v1\0");
    hash.u32(spec.schema_version);
    hash.u32(spec.output_width_px);
    hash.u32(spec.output_height_px);
    hash.i32(spec.source_crop.left_px);
    hash.i32(spec.source_crop.top_px);
    hash.i32(spec.source_crop.right_px_exclusive);
    hash.i32(spec.source_crop.bottom_px_exclusive);
    hash.u8(match spec.aspect_ratio_policy {
        CanonicalRasterAspectRatioPolicyV1::FitContainCentered => 1,
    });
    hash.u8(match spec.pixel_layout {
        CanonicalRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown => 1,
    });
    hash.u8(match spec.coverage_policy {
        CanonicalRasterCoveragePolicyV1::Antialiased => 1,
    });
    hash.bytes(&spec.background_rgba);
    hash.bytes(&spec.committed_ink_rgba);
    hash.u32(spec.stroke_width_16_16);
    hash.u8(match spec.stroke_cap {
        CanonicalRasterStrokeCapV1::Round => 1,
    });
    hash.u8(match spec.stroke_join {
        CanonicalRasterStrokeJoinV1::Round => 1,
    });
    hash.u8(match spec.rounding_policy {
        CanonicalRasterRoundingPolicyV1::NearestTiesAwayQ16 => 1,
    });
    hash.u8(match spec.clipping_policy {
        CanonicalRasterClippingPolicyV1::RejectPointsOutsideSourceCropClipCoverageAtOutputBounds =>
            1,
    });
    hash.u8(match spec.single_point_policy {
        CanonicalRasterSinglePointPolicyV1::OpaqueDiscAtObservedPoint => 1,
    });
    hash.u8(match spec.stroke_order_policy {
        CanonicalRasterStrokeOrderPolicyV1::JournalFirstOccurrence => 1,
    });
    hash.u32(row_stride_bytes);
    hash.u32(output_buffer_bytes);
    hash.finish()
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the later raster pixel-rendering slice"
    )
)]
fn hash_canonical_raster_geometry(geometry: &CanonicalRasterOutputGeometryV1) -> [u8; 32] {
    let mut hash = CanonicalRasterHashWriter::new(b"LassoInk/canonical-raster-geometry/v1\0");
    hash.bytes(&geometry.source_content_sha256);
    hash.bytes(&geometry.projection_spec_sha256);
    hash.u32(geometry.output_width_px);
    hash.u32(geometry.output_height_px);
    hash.u32(geometry.row_stride_bytes);
    hash.u32(geometry.output_buffer_bytes);
    hash.u64(geometry.stroke_draw_order.len() as u64);
    for stroke in &geometry.stroke_draw_order {
        hash.stroke_ref(stroke);
    }
    hash.u64(geometry.points_in_journal_order.len() as u64);
    for point in &geometry.points_in_journal_order {
        hash.u64(point.journal_sequence);
        hash.u64(point.source_sequence_raw);
        hash.stroke_ref(&point.stroke_ref);
        hash.i64(point.x_subpixel_16_16);
        hash.i64(point.y_subpixel_16_16);
        hash.u8(u8::from(point.is_single_point_stroke));
    }
    hash.finish()
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the canonical raster renderer")
)]
fn hash_canonical_raster_artifact(image: &CanonicalRasterImageV1) -> [u8; 32] {
    let mut hash = CanonicalRasterHashWriter::new(b"LassoInk/canonical-raster-artifact/v1\0");
    hash.u32(image.schema_version);
    hash.string(image.renderer_version);
    hash.string(&image.source_journal_id);
    hash.u64(image.source_logical_revision);
    hash.u64(image.source_last_sequence);
    hash.bytes(&image.source_content_sha256);
    hash.bytes(&image.projection_spec_sha256);
    hash.bytes(&image.geometry_sha256);
    hash.u32(image.output_width_px);
    hash.u32(image.output_height_px);
    hash.u32(image.row_stride_bytes);
    hash.u8(match image.pixel_layout {
        CanonicalRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown => 1,
    });
    hash.bytes(&image.pixel_bytes_sha256);
    hash.bytes(&image.png_bytes_sha256);
    hash.finish()
}

fn polyline_distance_squared(points: &[CanvasPointPx], x: f64, y: f64) -> f64 {
    match points {
        [] => f64::INFINITY,
        [point] => distance_squared(f64::from(point.x), f64::from(point.y), x, y),
        _ => points
            .windows(2)
            .map(|segment| {
                let (x1, y1) = (f64::from(segment[0].x), f64::from(segment[0].y));
                let (x2, y2) = (f64::from(segment[1].x), f64::from(segment[1].y));
                let dx = x2 - x1;
                let dy = y2 - y1;
                let length_squared = dx * dx + dy * dy;
                if length_squared == 0.0 {
                    distance_squared(x1, y1, x, y)
                } else {
                    let projection =
                        (((x - x1) * dx + (y - y1) * dy) / length_squared).clamp(0.0, 1.0);
                    distance_squared(x1 + projection * dx, y1 + projection * dy, x, y)
                }
            })
            .fold(f64::INFINITY, f64::min),
    }
}

fn distance_squared(x1: f64, y1: f64, x2: f64, y2: f64) -> f64 {
    (x1 - x2).powi(2) + (y1 - y2).powi(2)
}

/// Paints only the current scene. It never samples input or advances a journal.
/// Winit retains WM_PAINT/update-region ownership; a RedrawRequested callback
/// borrows the live client DC directly so internal redraws without an invalid
/// region still present the changed canvas.
pub(crate) fn paint_gdi(
    window: &winit::window::Window,
    scene: &CanvasScene,
    viewport: CanvasViewport,
    status: &str,
) -> std::io::Result<()> {
    use windows_sys::Win32::Graphics::Gdi::{GetDC, ReleaseDC};

    use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let handle = window
        .window_handle()
        .map_err(|error| std::io::Error::other(format!("could not obtain Winit HWND: {error}")))?;
    let hwnd = match handle.as_raw() {
        RawWindowHandle::Win32(handle) => handle.hwnd.get() as windows_sys::Win32::Foundation::HWND,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "canvas renderer requires the owned Winit Win32 window",
            ));
        }
    };
    if hwnd == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "canvas renderer rejects a null HWND",
        ));
    }
    // SAFETY: `window` is a live Winit-owned window borrowed from its event
    // callback, so hwnd is non-null and owned on this UI thread. GetDC is
    // scoped to this client HWND and is always paired with ReleaseDC below.
    let hdc = unsafe { GetDC(hwnd) };
    if hdc == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let draw_result = paint_scene_gdi(hwnd, hdc, scene, viewport, status);
    // SAFETY: hdc was acquired from this exact live hwnd above and this call
    // runs synchronously on the same Winit owner thread.
    let release_result = unsafe { ReleaseDC(hwnd, hdc) };
    let release_error = if release_result == 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    match (draw_result, release_error) {
        (Err(primary), _) => Err(primary),
        (Ok(()), Some(release_error)) => Err(release_error),
        (Ok(()), None) => Ok(()),
    }
}

fn paint_scene_gdi(
    hwnd: isize,
    hdc: isize,
    scene: &CanvasScene,
    viewport: CanvasViewport,
    status: &str,
) -> std::io::Result<()> {
    use windows_sys::Win32::{
        Foundation::RECT,
        Graphics::Gdi::{
            COLOR_WINDOW, CreatePen, DeleteObject, FillRect, GetSysColorBrush, HGDIOBJ, LineTo,
            MoveToEx, PS_DOT, PS_SOLID, SelectObject, TextOutW,
        },
        UI::WindowsAndMessaging::GetClientRect,
    };

    let mut bounds: RECT = unsafe { std::mem::zeroed() };
    // SAFETY: hwnd is the live Winit window and bounds is valid output storage.
    if unsafe { GetClientRect(hwnd, &mut bounds) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the HDC is borrowed from the live Winit HWND and bounds is
    // valid client storage for this redraw.
    let background = unsafe { GetSysColorBrush(COLOR_WINDOW) };
    if background == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the HDC/brush are valid and bounds is a valid client rectangle.
    if unsafe { FillRect(hdc, &bounds, background) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let title: Vec<u16> = status.encode_utf16().collect();
    // SAFETY: title points to `title.len()` initialized UTF-16 code units and
    // the borrowed HDC is valid for this synchronous draw call.
    if unsafe { TextOutW(hdc, 12, 12, title.as_ptr(), title.len() as i32) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    for stroke in scene
        .render_plan(viewport)
        .map_err(|error| std::io::Error::other(format!("canvas projection failed: {error:?}")))?
    {
        if stroke.points.is_empty() {
            continue;
        }
        let color = if stroke.preview {
            0x00808080
        } else if stroke.selected {
            0x00D07030
        } else {
            0x00202020
        };
        // PS_DOT is supported only with a one-pixel pen width. The preview
        // remains visibly dotted while committed strokes use a wider solid pen.
        let pen_style = if stroke.preview { PS_DOT } else { PS_SOLID };
        let pen_width = if stroke.preview { 1 } else { 2 };
        // SAFETY: CreatePen returns an owned GDI object when nonzero; it is
        // selected only for this draw and deleted after restoring the prior pen.
        let pen = unsafe { CreatePen(pen_style, pen_width, color) };
        if pen == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: hdc is borrowed and pen is an owned valid GDI object.
        let previous: HGDIOBJ = unsafe { SelectObject(hdc, pen) };
        if previous == 0 || previous == -1 {
            let selection_error = std::io::Error::last_os_error();
            // SAFETY: selection failed, so pen was not installed in hdc.
            let _ = unsafe { DeleteObject(pen) };
            return Err(selection_error);
        }
        let first = stroke.points[0];
        let draw_result = (|| {
            // SAFETY: coordinates are integer client positions and hdc is borrowed/live.
            if unsafe { MoveToEx(hdc, first.x, first.y, std::ptr::null_mut()) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            if stroke.points.len() == 1 {
                // A one-sample contact is a one-pixel mark, never a fabricated sample.
                // SAFETY: the second point is the adjacent bounded client pixel.
                if unsafe { LineTo(hdc, first.x.saturating_add(1), first.y) } == 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else {
                for point in stroke.points.iter().skip(1) {
                    // SAFETY: each point is derived from bounded raw coordinates.
                    if unsafe { LineTo(hdc, point.x, point.y) } == 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            Ok(())
        })();
        // Capture each cleanup error immediately; cleanup must still run when
        // drawing failed, but must not overwrite that primary draw error.
        // SAFETY: previous is the object returned by the successful selection above.
        let restored = unsafe { SelectObject(hdc, previous) };
        let restore_error = if restored == 0 || restored == -1 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        // SAFETY: pen was created above; after the restore attempt it is safe to
        // request deletion even when restoration itself reports failure.
        let deleted = unsafe { DeleteObject(pen) };
        let delete_error = if deleted == 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        draw_result?;
        if let Some(error) = restore_error {
            return Err(error);
        }
        if let Some(error) = delete_error {
            return Err(error);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{JournalHeader, JournalWriter, NativeTimestamp, RawPosition, RawPressure};
    use crate::win32_pointer::{
        CaptureSource, CoordinateSpace, CoordinateUnits, DirectPenHistoryBatch, LifecycleEventKind,
        OwnedPointerSample, PointerAttribution, PointerMessageKind, PressureValidity, RawPoint,
        RawScreenPosition,
    };
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let id = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lassoink-canvas-{}-{id}.ljnl", std::process::id()))
    }

    fn header() -> JournalHeader {
        JournalHeader {
            journal_id: "canvas-project".to_owned(),
            session_id: "session-canvas".to_owned(),
            config_id: Some("config-canvas".to_owned()),
            device_model_declared: Some("owner-declared device".to_owned()),
            tilt_supported_declared: Some(false),
        }
    }

    fn sample(source_sequence: u64, x: i64, y: i64) -> PhysicalSample {
        PhysicalSample {
            session_id: "session-canvas".to_owned(),
            source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
            source_device_id: Some("opaque-device-1".to_owned()),
            pointer_id: Some(12),
            stroke_id: Some("stroke-1".to_owned()),
            source_sequence,
            config_id: Some("config-canvas".to_owned()),
            app_arrival_elapsed_ns: source_sequence as u128 * 1_000_000,
            position: Some(RawPosition {
                coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
                units: SCREEN_POSITION_UNITS.to_owned(),
                x_raw: x,
                y_raw: y,
            }),
            pressure: Some(RawPressure {
                representation: "direct-pen-mask-pressure".to_owned(),
                units: "windows-normalized-pressure-0-1024".to_owned(),
                value_raw: 512,
                mask_raw: Some(1),
                minimum_raw: Some(0),
                maximum_raw: Some(1024),
            }),
            native_timestamp: Some(NativeTimestamp {
                clock_domain: "POINTER_INFO.PerformanceCount/QPC".to_owned(),
                units: "ticks".to_owned(),
                count_raw: source_sequence * 10_000,
                frequency_hz: Some(10_000_000),
            }),
            contact_range_state: Some("InRange+Contact".to_owned()),
            button_state_raw: Some(0),
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload: vec![source_sequence as u8, x as u8, y as u8],
        }
    }

    fn projection_target(stroke_id: &str, device_id: &str) -> StrokeRef {
        StrokeRef {
            journal_id: "canvas-project".to_owned(),
            session_id: "session-canvas".to_owned(),
            source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
            device_id: Some(device_id.to_owned()),
            pointer_id: Some(12),
            stroke_id: stroke_id.to_owned(),
        }
    }

    fn projection_sample(
        target: &StrokeRef,
        source_sequence: u64,
        x: i64,
        y: i64,
        app_arrival_elapsed_ns: u128,
    ) -> PhysicalSample {
        let mut physical = sample(source_sequence, x, y);
        physical.session_id.clone_from(&target.session_id);
        physical.source_api.clone_from(&target.source_api);
        physical.source_device_id.clone_from(&target.device_id);
        physical.pointer_id = target.pointer_id;
        physical.stroke_id = Some(target.stroke_id.clone());
        physical.app_arrival_elapsed_ns = app_arrival_elapsed_ns;
        physical
    }

    fn append_projection_stroke(
        writer: &mut JournalWriter,
        target: &StrokeRef,
        view_frame: StrokeViewFrame,
        points: &[(u64, i64, i64)],
        app_arrival_start: u128,
    ) {
        writer
            .start_stroke(target.clone(), view_frame, app_arrival_start)
            .unwrap();
        for (index, (source_sequence, x, y)) in points.iter().copied().enumerate() {
            writer
                .append_sample(projection_sample(
                    target,
                    source_sequence,
                    x,
                    y,
                    app_arrival_start + index as u128 + 1,
                ))
                .unwrap();
        }
        writer
            .commit_stroke(target.clone(), app_arrival_start + points.len() as u128 + 1)
            .unwrap();
    }

    fn committed_projection_fixture(
        target: &StrokeRef,
        view_frame: StrokeViewFrame,
        points: &[(u64, i64, i64)],
    ) -> (PathBuf, JournalWriter) {
        let path = temp_path();
        let mut writer = JournalWriter::create(path.clone(), header()).unwrap();
        append_projection_stroke(&mut writer, target, view_frame, points, 1);
        (path, writer)
    }

    fn committed_projection_state(
        target: &StrokeRef,
        view_frame: StrokeViewFrame,
        points: &[(u64, i64, i64)],
    ) -> JournalReplayState {
        let (path, mut writer) = committed_projection_fixture(target, view_frame, points);
        writer.flush().unwrap();
        let state = writer.replay_state().clone();
        drop(writer);
        let _ = fs::remove_file(path);
        state
    }

    #[test]
    fn canonical_raster_projection_preserves_physical_order_and_mixed_stroke_frames() {
        let first = projection_target("z-first-in-journal", "device-a");
        let second = projection_target("a-second-in-journal", "device-b");
        let first_frame = CanvasViewport::default()
            .stroke_view_frame(
                CanvasOrigin {
                    x_screen_px: 100,
                    y_screen_px: 200,
                },
                1.0,
            )
            .unwrap();
        let second_frame = StrokeViewFrame {
            screen_origin_x_px: 500,
            screen_origin_y_px: 600,
            dpi_scale_factor_bits: 1.5f64.to_bits(),
            canvas_zoom_bits: 2.0f64.to_bits(),
            canvas_pan_x_bits: 4.0f64.to_bits(),
            canvas_pan_y_bits: 6.0f64.to_bits(),
            toolbar_height_px: TOOLBAR_HEIGHT as u32,
        };
        let path = temp_path();
        let mut writer = JournalWriter::create(path.clone(), header()).unwrap();
        writer.start_stroke(first.clone(), first_frame, 1).unwrap();
        writer
            .append_sample(projection_sample(&first, 90, 110, 220, 2))
            .unwrap();
        writer
            .start_stroke(second.clone(), second_frame, 3)
            .unwrap();
        writer
            .append_sample(projection_sample(&second, 501, 540, 680, 4))
            .unwrap();
        writer
            .append_sample(projection_sample(&first, 7, 120, 230, 5))
            .unwrap();
        writer.commit_stroke(first.clone(), 6).unwrap();
        writer.commit_stroke(second.clone(), 7).unwrap();
        let state = writer.replay_state().clone();
        let selected = [second.clone(), first.clone()];

        let plan = build_canonical_raster_projection_plan(&state, &selected).unwrap();
        let journal_order = state
            .physical_samples
            .iter()
            .map(|stored| stored.sequence)
            .collect::<Vec<_>>();
        assert_eq!(
            plan.samples_in_journal_order
                .iter()
                .map(|point| point.journal_sequence)
                .collect::<Vec<_>>(),
            journal_order
        );
        assert_eq!(
            plan.samples_in_journal_order
                .iter()
                .map(|point| point.source_sequence_raw)
                .collect::<Vec<_>>(),
            vec![90, 501, 7]
        );
        assert_eq!(plan.selected_strokes.as_slice(), selected.as_slice());
        assert_eq!(
            plan.samples_in_journal_order
                .iter()
                .map(|point| point.stroke_ref.clone())
                .collect::<Vec<_>>(),
            vec![first.clone(), second.clone(), first.clone()]
        );
        assert_eq!(
            plan.samples_in_journal_order[0].canonical_canvas_position_px,
            CanvasPointPx { x: 10, y: 20 }
        );
        assert_eq!(
            plan.samples_in_journal_order[1].canonical_canvas_position_px,
            CanvasPointPx { x: 18, y: 57 }
        );
        assert_eq!(
            plan.samples_in_journal_order[2].canonical_canvas_position_px,
            CanvasPointPx { x: 20, y: 30 }
        );
        assert_eq!(plan.samples_in_journal_order[1].view_frame, second_frame);
        assert_eq!(
            plan.samples_in_journal_order[0]
                .source_sample
                .position
                .as_ref(),
            state.physical_samples[0].sample.position.as_ref()
        );
        let spec = CanonicalRasterProjectionSpecV1::new(
            200,
            100,
            CanonicalRasterProjectionCropV1 {
                left_px: 0,
                top_px: 0,
                right_px_exclusive: 40,
                bottom_px_exclusive: 80,
            },
        );
        let geometry = transform_canonical_raster_geometry(&plan, &spec).unwrap();
        let repeated_geometry = transform_canonical_raster_geometry(&plan, &spec).unwrap();
        assert_eq!(geometry, repeated_geometry);
        assert_eq!(geometry.output_width_px, 200);
        assert_eq!(geometry.output_height_px, 100);
        assert_eq!(geometry.row_stride_bytes, 800);
        assert_eq!(geometry.output_buffer_bytes, 80_000);
        assert_eq!(
            geometry.spec.pixel_layout,
            CanonicalRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown
        );
        assert_eq!(geometry.spec.background_rgba, [255, 255, 255, 255]);
        assert_eq!(geometry.spec.committed_ink_rgba, [32, 32, 32, 255]);
        assert_eq!(geometry.spec.stroke_width_16_16, 2 << 16);
        assert_eq!(
            geometry.spec.single_point_policy,
            CanonicalRasterSinglePointPolicyV1::OpaqueDiscAtObservedPoint
        );
        assert_eq!(
            geometry.stroke_draw_order,
            vec![first.clone(), second.clone()]
        );
        assert_eq!(geometry.caller_selection_order, selected);
        assert_eq!(
            geometry
                .points_in_journal_order
                .iter()
                .map(|point| point.journal_sequence)
                .collect::<Vec<_>>(),
            journal_order
        );
        assert_eq!(
            geometry
                .points_in_journal_order
                .iter()
                .map(|point| point.source_sequence_raw)
                .collect::<Vec<_>>(),
            vec![90, 501, 7]
        );
        assert_eq!(
            geometry.points_in_journal_order[0].x_subpixel_16_16,
            5_734_400
        );
        assert_eq!(
            geometry.points_in_journal_order[0].y_subpixel_16_16,
            1_638_400
        );
        assert_eq!(
            geometry.points_in_journal_order[1].x_subpixel_16_16,
            6_389_760
        );
        assert_eq!(
            geometry.points_in_journal_order[1].y_subpixel_16_16,
            4_669_440
        );
        assert_eq!(
            geometry.points_in_journal_order[2].x_subpixel_16_16,
            6_553_600
        );
        assert_eq!(
            geometry.points_in_journal_order[2].y_subpixel_16_16,
            2_457_600
        );
        assert_eq!(
            geometry
                .points_in_journal_order
                .iter()
                .map(|point| point.is_single_point_stroke)
                .collect::<Vec<_>>(),
            vec![false, true, false]
        );

        let forward_selection = [first.clone(), second.clone()];
        let forward_plan =
            build_canonical_raster_projection_plan(&state, &forward_selection).unwrap();
        let forward_geometry = transform_canonical_raster_geometry(&forward_plan, &spec).unwrap();
        assert_eq!(
            forward_plan
                .samples_in_journal_order
                .iter()
                .map(|point| point.journal_sequence)
                .collect::<Vec<_>>(),
            plan.samples_in_journal_order
                .iter()
                .map(|point| point.journal_sequence)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            forward_geometry.stroke_draw_order,
            geometry.stroke_draw_order
        );
        assert_eq!(
            forward_geometry.source_content_sha256,
            geometry.source_content_sha256
        );
        assert_eq!(
            forward_geometry.projection_spec_sha256,
            geometry.projection_spec_sha256
        );
        assert_eq!(forward_geometry.geometry_sha256, geometry.geometry_sha256);
        assert_ne!(
            forward_geometry.caller_selection_order,
            geometry.caller_selection_order
        );
        let selected_raster = render_canonical_raster(&geometry).unwrap();
        let forward_raster = render_canonical_raster(&forward_geometry).unwrap();
        assert_eq!(
            selected_raster.rgba8_premultiplied_srgb_top_down,
            forward_raster.rgba8_premultiplied_srgb_top_down
        );
        assert_eq!(selected_raster.png_bytes, forward_raster.png_bytes);
        assert_eq!(
            selected_raster.raster_artifact_sha256,
            forward_raster.raster_artifact_sha256
        );

        let mut changed_source = plan.clone();
        changed_source.samples_in_journal_order[0]
            .source_sample
            .raw_payload[0] ^= 0xff;
        let changed_source_geometry =
            transform_canonical_raster_geometry(&changed_source, &spec).unwrap();
        assert_eq!(changed_source.journal_id, plan.journal_id);
        assert_eq!(changed_source.logical_revision, plan.logical_revision);
        assert_eq!(changed_source.last_sequence, plan.last_sequence);
        assert_ne!(
            geometry.source_content_sha256,
            changed_source_geometry.source_content_sha256
        );
        assert_ne!(
            geometry.geometry_sha256,
            changed_source_geometry.geometry_sha256
        );

        let mut changed_spec = spec.clone();
        changed_spec.output_width_px = 180;
        let changed_spec_geometry =
            transform_canonical_raster_geometry(&plan, &changed_spec).unwrap();
        assert_ne!(
            geometry.projection_spec_sha256,
            changed_spec_geometry.projection_spec_sha256
        );
        assert_ne!(
            geometry.geometry_sha256,
            changed_spec_geometry.geometry_sha256
        );
        writer.flush().unwrap();
        drop(writer);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn canonical_raster_spec_checks_crop_output_caps_rounding_and_single_taps() {
        let target = projection_target("spec-bounds-proof", "device-a");
        let frame = CanvasViewport::default()
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let state = committed_projection_state(&target, frame, &[(1, 10, 60)]);
        let plan =
            build_canonical_raster_projection_plan(&state, std::slice::from_ref(&target)).unwrap();
        let valid_crop = CanonicalRasterProjectionCropV1 {
            left_px: 0,
            top_px: 0,
            right_px_exclusive: 100,
            bottom_px_exclusive: 100,
        };
        let valid_spec = CanonicalRasterProjectionSpecV1::new(80, 80, valid_crop);
        let output = transform_canonical_raster_geometry(&plan, &valid_spec).unwrap();
        assert_eq!(output.points_in_journal_order.len(), 1);
        assert!(output.points_in_journal_order[0].is_single_point_stroke);
        assert_eq!(output.row_stride_bytes, 320);
        assert_eq!(output.output_buffer_bytes, 25_600);
        assert_eq!(output.points_in_journal_order[0].x_subpixel_16_16, 8 << 16);
        assert_eq!(output.points_in_journal_order[0].y_subpixel_16_16, 48 << 16);
        let mut mismatched_buffer = output.clone();
        mismatched_buffer.output_buffer_bytes += 4;
        assert!(render_canonical_raster(&mismatched_buffer).is_err());
        assert_eq!(round_nonnegative_ratio_ties_away(1, 2).unwrap(), 1);
        assert_eq!(round_nonnegative_ratio_ties_away(5, 2).unwrap(), 3);
        assert!(round_nonnegative_ratio_ties_away(1, 0).is_err());
        assert!(round_nonnegative_ratio_ties_away(i128::MAX, 1).is_err());

        let mut zero_width = valid_spec.clone();
        zero_width.output_width_px = 0;
        assert!(transform_canonical_raster_geometry(&plan, &zero_width).is_err());
        let mut dimension_overflow = valid_spec.clone();
        dimension_overflow.output_width_px = u32::MAX;
        assert!(transform_canonical_raster_geometry(&plan, &dimension_overflow).is_err());
        let area_over_cap = CanonicalRasterProjectionSpecV1::new(1024, 512, valid_crop);
        assert!(transform_canonical_raster_geometry(&plan, &area_over_cap).is_err());

        let empty_crop = CanonicalRasterProjectionSpecV1::new(
            80,
            80,
            CanonicalRasterProjectionCropV1 {
                right_px_exclusive: 0,
                ..valid_crop
            },
        );
        assert!(transform_canonical_raster_geometry(&plan, &empty_crop).is_err());
        let crop_area_over_cap = CanonicalRasterProjectionSpecV1::new(
            80,
            80,
            CanonicalRasterProjectionCropV1 {
                left_px: -4096,
                top_px: -4096,
                right_px_exclusive: 4097,
                bottom_px_exclusive: 4096,
            },
        );
        assert!(transform_canonical_raster_geometry(&plan, &crop_area_over_cap).is_err());
        let crop_excludes_sample = CanonicalRasterProjectionSpecV1::new(
            80,
            80,
            CanonicalRasterProjectionCropV1 {
                left_px: 11,
                ..valid_crop
            },
        );
        assert!(transform_canonical_raster_geometry(&plan, &crop_excludes_sample).is_err());
    }

    #[test]
    fn canonical_raster_cpu_backend_emits_bounded_rgba_and_png_round_trip() {
        let target = projection_target("pixel-contract", "device-a");
        let frame = CanvasViewport::default()
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let state = committed_projection_state(&target, frame, &[(4, 20, 60), (5, 40, 60)]);
        let plan =
            build_canonical_raster_projection_plan(&state, std::slice::from_ref(&target)).unwrap();
        let spec = CanonicalRasterProjectionSpecV1::new(
            100,
            100,
            CanonicalRasterProjectionCropV1 {
                left_px: 0,
                top_px: 0,
                right_px_exclusive: 200,
                bottom_px_exclusive: 200,
            },
        );
        let geometry = transform_canonical_raster_geometry(&plan, &spec).unwrap();
        let rendered = render_canonical_raster(&geometry).unwrap();
        let repeated = render_canonical_raster(&geometry).unwrap();

        assert_eq!(rendered.output_width_px, 100);
        assert_eq!(rendered.output_height_px, 100);
        assert_eq!(rendered.row_stride_bytes, 400);
        assert_eq!(rendered.rgba8_premultiplied_srgb_top_down.len(), 40_000);
        assert!(
            rendered
                .rgba8_premultiplied_srgb_top_down
                .chunks_exact(4)
                .all(|pixel| pixel[3] == 255)
        );
        assert_eq!(
            rendered.pixel_layout,
            CanonicalRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown
        );
        assert_eq!(
            rendered.renderer_version,
            "tiny-skia/0.12.0;canonical-raster-v1"
        );
        assert_eq!(
            rendered.source_content_sha256,
            geometry.source_content_sha256
        );
        assert_eq!(
            rendered.projection_spec_sha256,
            geometry.projection_spec_sha256
        );
        assert_eq!(rendered.geometry_sha256, geometry.geometry_sha256);
        assert_eq!(
            rendered.rgba8_premultiplied_srgb_top_down,
            repeated.rgba8_premultiplied_srgb_top_down
        );
        assert_eq!(rendered.png_bytes, repeated.png_bytes);
        assert_eq!(rendered.pixel_bytes_sha256, repeated.pixel_bytes_sha256);
        assert_eq!(rendered.png_bytes_sha256, repeated.png_bytes_sha256);
        assert_eq!(
            rendered.raster_artifact_sha256,
            repeated.raster_artifact_sha256
        );
        let expected_pixel_hash: [u8; 32] =
            Sha256::digest(&rendered.rgba8_premultiplied_srgb_top_down).into();
        let expected_png_hash: [u8; 32] = Sha256::digest(&rendered.png_bytes).into();
        assert_eq!(rendered.pixel_bytes_sha256, expected_pixel_hash);
        assert_eq!(rendered.png_bytes_sha256, expected_png_hash);
        assert_eq!(
            rendered.raster_artifact_sha256,
            hash_canonical_raster_artifact(&rendered)
        );

        let pixel_index = (30 * rendered.row_stride_bytes + 15 * 4) as usize;
        assert_eq!(
            &rendered.rgba8_premultiplied_srgb_top_down[pixel_index..pixel_index + 4],
            &[32, 32, 32, 255]
        );
        assert_eq!(
            &rendered.rgba8_premultiplied_srgb_top_down[0..4],
            &[255, 255, 255, 255]
        );

        let decoded = Pixmap::decode_png(&rendered.png_bytes).unwrap();
        assert_eq!(decoded.width(), rendered.output_width_px);
        assert_eq!(decoded.height(), rendered.output_height_px);
        assert_eq!(
            decoded.data(),
            rendered.rgba8_premultiplied_srgb_top_down.as_slice()
        );
        assert!(rendered.png_bytes.len() <= MAX_CANONICAL_RASTER_PNG_BYTES);
    }

    #[test]
    fn canonical_raster_cpu_backend_treats_repeated_observations_as_an_observed_tap() {
        let target = projection_target("repeated-point-tap", "device-a");
        let frame = CanvasViewport::default()
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let tap_state = committed_projection_state(&target, frame, &[(7, 30, 50)]);
        let repeated_state =
            committed_projection_state(&target, frame, &[(7, 30, 50), (9, 30, 50)]);
        let spec = CanonicalRasterProjectionSpecV1::new(
            100,
            100,
            CanonicalRasterProjectionCropV1 {
                left_px: 0,
                top_px: 0,
                right_px_exclusive: 100,
                bottom_px_exclusive: 100,
            },
        );
        let tap_plan =
            build_canonical_raster_projection_plan(&tap_state, std::slice::from_ref(&target))
                .unwrap();
        let repeated_plan =
            build_canonical_raster_projection_plan(&repeated_state, std::slice::from_ref(&target))
                .unwrap();
        let tap_geometry = transform_canonical_raster_geometry(&tap_plan, &spec).unwrap();
        let repeated_geometry = transform_canonical_raster_geometry(&repeated_plan, &spec).unwrap();
        assert!(tap_geometry.points_in_journal_order[0].is_single_point_stroke);
        assert!(
            repeated_geometry
                .points_in_journal_order
                .iter()
                .all(|point| !point.is_single_point_stroke)
        );

        let tap_image = render_canonical_raster(&tap_geometry).unwrap();
        let repeated_image = render_canonical_raster(&repeated_geometry).unwrap();
        assert_eq!(
            tap_image.rgba8_premultiplied_srgb_top_down,
            repeated_image.rgba8_premultiplied_srgb_top_down
        );
        assert_eq!(tap_image.png_bytes, repeated_image.png_bytes);
        assert_ne!(
            tap_image.source_content_sha256,
            repeated_image.source_content_sha256
        );
        assert_ne!(
            tap_image.raster_artifact_sha256,
            repeated_image.raster_artifact_sha256
        );
    }

    #[test]
    fn canonical_raster_cpu_backend_rejects_invalid_geometry_before_allocation() {
        let target = projection_target("invalid-render-geometry", "device-a");
        let frame = CanvasViewport::default()
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let state = committed_projection_state(&target, frame, &[(1, 10, 60), (2, 12, 62)]);
        let plan =
            build_canonical_raster_projection_plan(&state, std::slice::from_ref(&target)).unwrap();
        let spec = CanonicalRasterProjectionSpecV1::new(
            80,
            80,
            CanonicalRasterProjectionCropV1 {
                left_px: 0,
                top_px: 0,
                right_px_exclusive: 100,
                bottom_px_exclusive: 100,
            },
        );
        let geometry = transform_canonical_raster_geometry(&plan, &spec).unwrap();

        let mut invalid_dimension = geometry.clone();
        invalid_dimension.output_width_px = MAX_CANONICAL_RASTER_OUTPUT_DIMENSION + 1;
        assert!(render_canonical_raster(&invalid_dimension).is_err());

        let mut invalid_point = geometry;
        invalid_point.points_in_journal_order[0].x_subpixel_16_16 = i64::MAX;
        assert!(render_canonical_raster(&invalid_point).is_err());
    }

    #[test]
    fn canonical_raster_projection_moves_only_derived_geometry() {
        let target = projection_target("move-proof", "device-a");
        let frame = CanvasViewport::default()
            .stroke_view_frame(
                CanvasOrigin {
                    x_screen_px: 100,
                    y_screen_px: 200,
                },
                1.0,
            )
            .unwrap();
        let (path, mut writer) = committed_projection_fixture(&target, frame, &[(73, 110, 220)]);
        let before_state = writer.replay_state().clone();
        let before =
            build_canonical_raster_projection_plan(&before_state, std::slice::from_ref(&target))
                .unwrap();
        let raw_before = before.samples_in_journal_order[0]
            .source_sample
            .position
            .clone()
            .unwrap();
        let journal_sequence = before.samples_in_journal_order[0].journal_sequence;
        let source_sequence = before.samples_in_journal_order[0].source_sequence_raw;
        let position_before = before.samples_in_journal_order[0].canonical_canvas_position_px;
        let render_spec = CanonicalRasterProjectionSpecV1::new(
            100,
            100,
            CanonicalRasterProjectionCropV1 {
                left_px: 0,
                top_px: 0,
                right_px_exclusive: 100,
                bottom_px_exclusive: 100,
            },
        );
        let before_geometry = transform_canonical_raster_geometry(&before, &render_spec).unwrap();
        let before_image = render_canonical_raster(&before_geometry).unwrap();
        drop(before);

        writer
            .apply_edit_action(
                20,
                EditCommand::Move {
                    target: target.clone(),
                    delta_x_raw: 5,
                    delta_y_raw: 7,
                    coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
                    units: SCREEN_POSITION_UNITS.to_owned(),
                },
            )
            .unwrap();
        let moved_state = writer.replay_state().clone();
        let after =
            build_canonical_raster_projection_plan(&moved_state, std::slice::from_ref(&target))
                .unwrap();
        let after_geometry = transform_canonical_raster_geometry(&after, &render_spec).unwrap();
        let after_image = render_canonical_raster(&after_geometry).unwrap();
        assert_eq!(
            after.samples_in_journal_order[0].journal_sequence,
            journal_sequence
        );
        assert_eq!(
            after.samples_in_journal_order[0].source_sequence_raw,
            source_sequence
        );
        assert_eq!(
            after.samples_in_journal_order[0]
                .source_sample
                .position
                .as_ref(),
            Some(&raw_before)
        );
        assert_eq!(
            moved_state.physical_samples[0].sample.position.as_ref(),
            Some(&raw_before)
        );
        assert_eq!(
            moved_state.physical_samples[0].sample,
            before_state.physical_samples[0].sample
        );
        assert_eq!(
            after.samples_in_journal_order[0].canonical_canvas_position_px,
            CanvasPointPx {
                x: position_before.x + 5,
                y: position_before.y + 7,
            }
        );
        assert_ne!(
            before_image.rgba8_premultiplied_srgb_top_down,
            after_image.rgba8_premultiplied_srgb_top_down
        );
        assert_ne!(before_image.png_bytes, after_image.png_bytes);
        assert_ne!(
            before_image.source_content_sha256,
            after_image.source_content_sha256
        );
        assert_ne!(before_image.geometry_sha256, after_image.geometry_sha256);
        writer.flush().unwrap();
        drop(writer);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn canonical_raster_projection_respects_commit_undo_tombstone_restore_visibility() {
        let target = projection_target("visibility-proof", "device-a");
        let frame = CanvasViewport::default()
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let (path, mut writer) =
            committed_projection_fixture(&target, frame, &[(1, 10, 60), (2, 20, 70)]);
        assert!(
            build_canonical_raster_projection_plan(
                writer.replay_state(),
                std::slice::from_ref(&target)
            )
            .is_ok()
        );

        writer.undo_last_edit(10).unwrap();
        assert!(
            build_canonical_raster_projection_plan(
                writer.replay_state(),
                std::slice::from_ref(&target)
            )
            .is_err()
        );
        writer.redo_last_edit(11).unwrap();
        assert!(
            build_canonical_raster_projection_plan(
                writer.replay_state(),
                std::slice::from_ref(&target)
            )
            .is_ok()
        );

        writer
            .apply_edit_action(
                12,
                EditCommand::Tombstone {
                    targets: vec![target.clone()],
                },
            )
            .unwrap();
        assert!(
            build_canonical_raster_projection_plan(
                writer.replay_state(),
                std::slice::from_ref(&target)
            )
            .is_err()
        );
        writer
            .apply_edit_action(
                13,
                EditCommand::Restore {
                    targets: vec![target.clone()],
                },
            )
            .unwrap();
        assert!(
            build_canonical_raster_projection_plan(
                writer.replay_state(),
                std::slice::from_ref(&target)
            )
            .is_ok()
        );
        writer.flush().unwrap();
        drop(writer);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn canonical_raster_projection_rejects_uncommitted_and_unsupported_inputs() {
        let target = projection_target("uncommitted-proof", "device-a");
        let frame = CanvasViewport::default()
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let path = temp_path();
        let mut writer = JournalWriter::create(path.clone(), header()).unwrap();
        writer.start_stroke(target.clone(), frame, 1).unwrap();
        writer
            .append_sample(projection_sample(&target, 1, 10, 60, 2))
            .unwrap();
        assert!(
            build_canonical_raster_projection_plan(
                writer.replay_state(),
                std::slice::from_ref(&target)
            )
            .is_err()
        );
        writer.flush().unwrap();
        drop(writer);
        let _ = fs::remove_file(path);

        let target = projection_target("missing-frame-proof", "device-a");
        let mut state = committed_projection_state(&target, frame, &[(1, 10, 60)]);
        state.stroke_starts.clear();
        assert!(
            build_canonical_raster_projection_plan(&state, std::slice::from_ref(&target)).is_err()
        );

        let target = projection_target("invalid-frame-proof", "device-a");
        let mut state = committed_projection_state(&target, frame, &[(1, 10, 60)]);
        state.stroke_starts[0].view_frame.canvas_zoom_bits = f64::NAN.to_bits();
        assert!(
            build_canonical_raster_projection_plan(&state, std::slice::from_ref(&target)).is_err()
        );

        let target = projection_target("unsupported-units-proof", "device-a");
        let mut state = committed_projection_state(&target, frame, &[(1, 10, 60)]);
        state.physical_samples[0]
            .sample
            .position
            .as_mut()
            .unwrap()
            .units = "himetric".to_owned();
        assert!(
            build_canonical_raster_projection_plan(&state, std::slice::from_ref(&target)).is_err()
        );

        let target = projection_target("missing-position-proof", "device-a");
        let mut state = committed_projection_state(&target, frame, &[(1, 10, 60), (2, 20, 70)]);
        state.physical_samples[0].sample.position = None;
        assert!(
            build_canonical_raster_projection_plan(&state, std::slice::from_ref(&target)).is_err()
        );

        let target = projection_target("unsupported-space-proof", "device-a");
        let mut state = committed_projection_state(&target, frame, &[(1, 10, 60)]);
        state.physical_samples[0]
            .sample
            .position
            .as_mut()
            .unwrap()
            .coordinate_space = "windows-client-coordinates".to_owned();
        assert!(
            build_canonical_raster_projection_plan(&state, std::slice::from_ref(&target)).is_err()
        );

        let target = projection_target("unrepresentable-transform-proof", "device-a");
        let mut state = committed_projection_state(&target, frame, &[(1, 10, 60)]);
        state.stroke_starts[0].view_frame.screen_origin_x_px = i64::from(i32::MIN);
        state.stroke_starts[0].view_frame.canvas_zoom_bits = 0.2f64.to_bits();
        state.physical_samples[0]
            .sample
            .position
            .as_mut()
            .unwrap()
            .x_raw = i64::from(i32::MAX);
        assert!(
            build_canonical_raster_projection_plan(&state, std::slice::from_ref(&target)).is_err()
        );

        let target = projection_target("unsupported-source-proof", "device-a");
        let state = committed_projection_state(&target, frame, &[(1, 10, 60)]);
        let unsupported_target = StrokeRef {
            source_api: "wintab".to_owned(),
            ..target
        };
        assert!(
            build_canonical_raster_projection_plan(
                &state,
                std::slice::from_ref(&unsupported_target)
            )
            .is_err()
        );
    }

    #[test]
    fn live_and_replayed_direct_fixture_render_the_same_geometry() {
        let path = temp_path();
        let mut writer = JournalWriter::create(path.clone(), header()).unwrap();
        let inputs = [
            sample(4, 100, 200),
            sample(5, 110, 210),
            sample(6, 125, 230),
        ];
        let mut live = CanvasScene::default();
        for input in &inputs {
            live.append_live_sample(input, "canvas-project", true)
                .unwrap();
            writer.append_sample(input.clone()).unwrap();
        }
        writer.flush().unwrap();
        drop(writer);

        let replay = crate::journal::read_journal(&path).unwrap();
        let replay_scene =
            CanvasScene::from_journal(&replay.state, PROVISIONAL_DIRECT_SOURCE_API).unwrap();
        let viewport = CanvasViewport::default();
        assert_eq!(
            live.render_plan(viewport).unwrap(),
            replay_scene.render_plan(viewport).unwrap()
        );
        assert_eq!(replay_scene.stroke_count(), 1);
        assert_eq!(
            replay_scene.render_plan(viewport).unwrap()[0].points,
            [
                CanvasPointPx { x: 100, y: 240 },
                CanvasPointPx { x: 110, y: 250 },
                CanvasPointPx { x: 125, y: 270 },
            ]
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn viewport_zoom_anchor_pan_and_selection_geometry_are_deterministic() {
        let mut viewport = CanvasViewport::default();
        let anchor = (120.0, 160.0);
        let before = viewport
            .map_raw_point(
                &RawPosition {
                    coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
                    units: SCREEN_POSITION_UNITS.to_owned(),
                    x_raw: 120,
                    y_raw: 120,
                },
                CanvasOrigin::default(),
            )
            .unwrap();
        viewport.zoom_about(anchor.0, anchor.1, 2.0).unwrap();
        let after = viewport
            .map_raw_point(
                &RawPosition {
                    coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
                    units: SCREEN_POSITION_UNITS.to_owned(),
                    x_raw: 120,
                    y_raw: 120,
                },
                CanvasOrigin::default(),
            )
            .unwrap();
        assert_eq!(before.x, 120);
        assert_eq!(before.y, 160);
        assert_eq!(after, before);
        viewport.pan_by(25.0, -5.0).unwrap();

        let mut scene = CanvasScene::default();
        for point in [sample(1, 10, 20), sample(2, 20, 30)] {
            scene
                .append_live_sample(&point, "canvas-project", true)
                .unwrap();
        }
        scene
            .select_region(
                CanvasViewport::default(),
                CanvasRect::normalized((0.0, 40.0), (15.0, 65.0)).unwrap(),
            )
            .unwrap();
        assert_eq!(scene.selected_targets().unwrap().len(), 1);
        assert_eq!(
            scene.tombstone_selected_command().unwrap().unwrap(),
            EditCommand::Tombstone {
                targets: vec![StrokeRef {
                    journal_id: "canvas-project".to_owned(),
                    session_id: "session-canvas".to_owned(),
                    source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
                    device_id: Some("opaque-device-1".to_owned()),
                    pointer_id: Some(12),
                    stroke_id: "stroke-1".to_owned(),
                }],
            }
        );
    }

    #[test]
    fn selection_uses_the_same_zoom_pan_and_session_origin_as_rendering() {
        let mut scene = CanvasScene::default();
        scene.set_session_origin(
            "session-canvas",
            CanvasOrigin {
                x_screen_px: 100,
                y_screen_px: 200,
            },
        );
        scene
            .append_live_sample(&sample(1, 110, 220), "canvas-project", true)
            .unwrap();
        let mut viewport = CanvasViewport::default();
        viewport.pan_by(5.0, 3.0).unwrap();
        viewport.zoom_about(0.0, 0.0, 2.0).unwrap();
        let rendered = scene.render_plan(viewport).unwrap();
        let point = rendered[0].points[0];
        let selection = CanvasRect::normalized(
            (f64::from(point.x) - 1.0, f64::from(point.y) - 1.0),
            (f64::from(point.x) + 1.0, f64::from(point.y) + 1.0),
        )
        .unwrap();
        scene.select_region(viewport, selection).unwrap();
        assert_eq!(scene.selected_targets().unwrap().len(), 1);
    }

    #[test]
    fn move_drag_is_converted_through_the_stroke_start_view_frame() {
        let point = sample(1, 10, 60);
        let target = StrokeRef {
            journal_id: "canvas-project".to_owned(),
            session_id: point.session_id.clone(),
            source_api: point.source_api.clone(),
            device_id: point.source_device_id.clone(),
            pointer_id: point.pointer_id,
            stroke_id: point.stroke_id.clone().unwrap(),
        };
        let mut started_view = CanvasViewport::default();
        started_view.zoom_about(0.0, 0.0, 2.0).unwrap();
        let frame = started_view
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let mut scene = CanvasScene::default();
        scene.begin_preview_stroke(target.clone(), frame).unwrap();
        scene
            .append_preview_sample(&point, "canvas-project", true)
            .unwrap();
        scene.promote_preview_stroke(&target).unwrap();
        assert_eq!(
            scene
                .raw_move_delta_from_view_drag(&target, CanvasViewport::default(), 10.0, -5.0)
                .unwrap(),
            (20, -10)
        );
    }

    #[test]
    fn per_stroke_view_frames_survive_window_move_and_project_reopen() {
        let path = temp_path();
        let snapshot_path = crate::journal::default_snapshot_path(&path);
        let mut writer = JournalWriter::create(path.clone(), header()).unwrap();
        writer
            .begin_session_epoch(
                "session-view-frames".to_owned(),
                1_800_000_111_000_000_000,
                Some("config-view".to_owned()),
                "software view-frame fixture".to_owned(),
            )
            .unwrap();
        let first_frame = CanvasViewport::default()
            .stroke_view_frame(
                CanvasOrigin {
                    x_screen_px: 100,
                    y_screen_px: 200,
                },
                1.0,
            )
            .unwrap();
        let mut second_view = CanvasViewport::default();
        second_view.zoom_about(0.0, 0.0, 2.0).unwrap();
        let second_frame = second_view
            .stroke_view_frame(
                CanvasOrigin {
                    x_screen_px: 200,
                    y_screen_px: 300,
                },
                1.5,
            )
            .unwrap();
        for (stroke_id, frame, position) in [
            (
                "before-window-move",
                first_frame,
                RawPosition {
                    coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
                    units: SCREEN_POSITION_UNITS.to_owned(),
                    x_raw: 110,
                    y_raw: 260,
                },
            ),
            (
                "after-window-move",
                second_frame,
                RawPosition {
                    coordinate_space: SCREEN_POSITION_SPACE.to_owned(),
                    units: SCREEN_POSITION_UNITS.to_owned(),
                    x_raw: 220,
                    y_raw: 420,
                },
            ),
        ] {
            let mut physical = sample(1, position.x_raw, position.y_raw);
            physical.session_id = "session-view-frames".to_owned();
            physical.config_id = Some("config-view".to_owned());
            physical.stroke_id = Some(stroke_id.to_owned());
            physical.position = Some(position);
            let identity = StrokeRef {
                journal_id: "canvas-project".to_owned(),
                session_id: physical.session_id.clone(),
                source_api: physical.source_api.clone(),
                device_id: physical.source_device_id.clone(),
                pointer_id: physical.pointer_id,
                stroke_id: stroke_id.to_owned(),
            };
            writer
                .start_stroke(identity.clone(), frame, physical.app_arrival_elapsed_ns)
                .unwrap();
            writer.append_sample(physical.clone()).unwrap();
            writer
                .commit_stroke(identity, physical.app_arrival_elapsed_ns + 1)
                .unwrap();
        }
        let live_state = writer.replay_state().clone();
        writer.write_snapshot(&snapshot_path).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let live_scene =
            CanvasScene::from_journal(&live_state, PROVISIONAL_DIRECT_SOURCE_API).unwrap();
        let with_snapshot = crate::journal::load_with_snapshot(&path, &snapshot_path).unwrap();
        assert_eq!(
            with_snapshot.disposition,
            crate::journal::SnapshotDisposition::Used
        );
        assert_eq!(with_snapshot.state, live_state);
        let parsed = crate::journal::read_journal(&path).unwrap();
        let reopened_scene =
            CanvasScene::from_journal(&parsed.state, PROVISIONAL_DIRECT_SOURCE_API).unwrap();
        let live_plan = live_scene.render_plan(CanvasViewport::default()).unwrap();
        let reopened_plan = reopened_scene
            .render_plan(CanvasViewport::default())
            .unwrap();
        assert_eq!(live_plan, reopened_plan);
        assert_eq!(live_plan.len(), 2);
        assert_eq!(live_plan[0].points, live_plan[1].points);
        assert_eq!(parsed.state.stroke_starts[0].view_frame, first_frame);
        assert_eq!(parsed.state.stroke_starts[1].view_frame, second_frame);
        assert_ne!(
            first_frame.screen_origin_x_px,
            second_frame.screen_origin_x_px
        );
        fs::remove_file(path).unwrap();
        fs::remove_file(snapshot_path).unwrap();
    }

    #[test]
    #[ignore = "requires the guarded isolated Windows UI test job"]
    fn committed_reopen_undo_redo_canvas_matches_gdi_pixels() {
        use windows_sys::Win32::{
            Foundation::COLORREF,
            Graphics::Gdi::{
                CreateCompatibleBitmap, CreateCompatibleDC, DeleteObject, GetDC, HGDIOBJ,
                ReleaseDC, SelectObject,
            },
            System::LibraryLoader::GetModuleHandleW,
            UI::WindowsAndMessaging::{CreateWindowExW, DestroyWindow, WS_POPUP},
        };
        crate::require_native_ui_test_opt_in();

        let width = 80;
        let height = 120;
        let class_name: Vec<u16> = "STATIC\0".encode_utf16().collect();
        let window_name: Vec<u16> = "\0".encode_utf16().collect();
        // SAFETY: null requests the current process module, and both string
        // pointers below are NUL-terminated for the duration of window creation.
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        // SAFETY: STATIC is a built-in window class; parent/menu are null,
        // and the requested dimensions are small bounded test values.
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class_name.as_ptr(),
                window_name.as_ptr(),
                WS_POPUP,
                0,
                0,
                width,
                height,
                0,
                0,
                instance,
                std::ptr::null(),
            )
        };
        assert_ne!(hwnd, 0);

        let path = temp_path();
        let mut writer = JournalWriter::create(path.clone(), header()).unwrap();
        writer
            .begin_session_epoch(
                "session-gdi-replay".to_owned(),
                1_800_000_222_000_000_000,
                Some("config-gdi".to_owned()),
                "software GDI fixture".to_owned(),
            )
            .unwrap();
        let mut screen_origin = windows_sys::Win32::Foundation::POINT { x: 0, y: 0 };
        // SAFETY: hwnd is a live hidden HWND and screen_origin is valid output storage.
        assert_ne!(
            unsafe { windows_sys::Win32::Graphics::Gdi::ClientToScreen(hwnd, &mut screen_origin) },
            0
        );
        let frame = CanvasViewport::default()
            .stroke_view_frame(
                CanvasOrigin {
                    x_screen_px: i64::from(screen_origin.x),
                    y_screen_px: i64::from(screen_origin.y),
                },
                1.0,
            )
            .unwrap();
        let mut physical = sample(
            1,
            i64::from(screen_origin.x) + 15,
            i64::from(screen_origin.y) + 60,
        );
        physical.session_id = "session-gdi-replay".to_owned();
        physical.config_id = Some("config-gdi".to_owned());
        physical.stroke_id = Some("gdi-stroke".to_owned());
        let target = StrokeRef {
            journal_id: "canvas-project".to_owned(),
            session_id: physical.session_id.clone(),
            source_api: physical.source_api.clone(),
            device_id: physical.source_device_id.clone(),
            pointer_id: physical.pointer_id,
            stroke_id: "gdi-stroke".to_owned(),
        };
        writer.start_stroke(target.clone(), frame, 1).unwrap();
        writer.append_sample(physical).unwrap();
        let commit_action = writer.commit_stroke(target, 2).unwrap();
        assert_eq!(writer.replay_state().projected_samples().unwrap().len(), 1);
        writer.flush().unwrap();
        drop(writer);

        // Reopen the persisted project and exercise append-only undo/redo before
        // comparing the final replayed scene to the pre-reopen committed state.
        let mut reopened = JournalWriter::open_append(path.clone()).unwrap();
        assert_eq!(reopened.undo_last_edit(3).unwrap(), commit_action);
        assert!(
            reopened
                .replay_state()
                .projected_samples()
                .unwrap()
                .is_empty()
        );
        assert_eq!(reopened.redo_last_edit(4).unwrap(), commit_action);
        let live_after_ack = reopened.replay_state().clone();
        reopened.flush().unwrap();
        drop(reopened);
        let parsed = crate::journal::read_journal(&path).unwrap();
        let live_scene =
            CanvasScene::from_journal(&live_after_ack, PROVISIONAL_DIRECT_SOURCE_API).unwrap();
        let replayed_scene =
            CanvasScene::from_journal(&parsed.state, PROVISIONAL_DIRECT_SOURCE_API).unwrap();

        // SAFETY: hwnd is live; GetDC returns a temporary window DC and all
        // created GDI resources are paired with restoration/deletion below.
        let screen_dc = unsafe { GetDC(hwnd) };
        assert_ne!(screen_dc, 0);
        // SAFETY: compatible DC/bitmap are created from the valid screen DC.
        let memory_dc = unsafe { CreateCompatibleDC(screen_dc) };
        let bitmap = unsafe { CreateCompatibleBitmap(screen_dc, width, height) };
        assert_ne!(memory_dc, 0);
        assert_ne!(bitmap, 0);
        // SAFETY: bitmap is a compatible owned GDI bitmap and memory_dc is valid.
        let previous: HGDIOBJ = unsafe { SelectObject(memory_dc, bitmap as HGDIOBJ) };
        assert_ne!(previous, 0);

        paint_scene_gdi(
            hwnd as isize,
            memory_dc as isize,
            &live_scene,
            CanvasViewport::default(),
            "software scene fixture",
        )
        .unwrap();
        let live_pixels = read_gdi_pixels(memory_dc, width, height);
        paint_scene_gdi(
            hwnd as isize,
            memory_dc as isize,
            &replayed_scene,
            CanvasViewport::default(),
            "software scene fixture",
        )
        .unwrap();
        let replayed_pixels = read_gdi_pixels(memory_dc, width, height);
        assert_eq!(live_pixels, replayed_pixels);
        let background_pixel = live_pixels[0];
        let stroke_pixel = live_pixels[60 * width as usize + 15];
        assert_ne!(background_pixel, u32::MAX as COLORREF);
        assert_ne!(stroke_pixel, u32::MAX as COLORREF);
        assert_ne!(
            stroke_pixel, background_pixel,
            "the GDI output contains the expected visible stroke"
        );
        assert!(
            paint_scene_gdi(
                hwnd as isize,
                0,
                &live_scene,
                CanvasViewport::default(),
                "invalid HDC fixture",
            )
            .is_err()
        );

        // SAFETY: restore the prior bitmap before deleting the selected bitmap,
        // then release each DC and destroy the hidden HWND created above.
        unsafe {
            SelectObject(memory_dc, previous);
            DeleteObject(bitmap as HGDIOBJ);
            windows_sys::Win32::Graphics::Gdi::DeleteDC(memory_dc);
            ReleaseDC(hwnd, screen_dc);
            DestroyWindow(hwnd);
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "requires the guarded isolated Windows UI test job"]
    fn winit_request_redraw_updates_pixels_and_undo_redo_without_invalidation() {
        use std::time::{Duration, Instant};
        use winit::{
            application::ApplicationHandler,
            dpi::PhysicalSize,
            event::WindowEvent,
            event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
            platform::windows::EventLoopBuilderExtWindows,
            raw_window_handle::{HasWindowHandle, RawWindowHandle},
            window::{Window, WindowId},
        };
        crate::require_native_ui_test_opt_in();

        struct RedrawApp {
            window: Option<Window>,
            scenes: Vec<CanvasScene>,
            pixels: Vec<(u32, u32)>,
            deadline: Instant,
            failure: Option<String>,
        }

        impl ApplicationHandler for RedrawApp {
            fn resumed(&mut self, event_loop: &ActiveEventLoop) {
                if self.window.is_some() {
                    return;
                }
                let attributes = Window::default_attributes()
                    .with_title("LassoInk Winit redraw fixture")
                    .with_visible(true)
                    .with_inner_size(PhysicalSize::new(80, 120));
                match event_loop.create_window(attributes) {
                    Ok(window) => {
                        window.request_redraw();
                        self.window = Some(window);
                    }
                    Err(error) => {
                        self.failure =
                            Some(format!("could not create Winit fixture window: {error}"));
                        event_loop.exit();
                    }
                }
            }

            fn window_event(
                &mut self,
                event_loop: &ActiveEventLoop,
                window_id: WindowId,
                event: WindowEvent,
            ) {
                let Some(window) = self.window.as_ref() else {
                    return;
                };
                if window.id() != window_id || event != WindowEvent::RedrawRequested {
                    return;
                }
                let scene_index = self.pixels.len();
                let Some(scene) = self.scenes.get(scene_index) else {
                    self.failure = Some("unexpected extra Winit redraw".to_owned());
                    event_loop.exit();
                    return;
                };
                let hwnd = match window.window_handle().ok().map(|handle| handle.as_raw()) {
                    Some(RawWindowHandle::Win32(handle)) => handle.hwnd.get(),
                    _ => {
                        self.failure = Some("Winit fixture did not expose a Win32 HWND".to_owned());
                        event_loop.exit();
                        return;
                    }
                };
                if let Err(error) = paint_gdi(
                    window,
                    scene,
                    CanvasViewport::default(),
                    "Winit redraw fixture",
                ) {
                    self.failure = Some(format!("paint_gdi failed in Winit callback: {error}"));
                    event_loop.exit();
                    return;
                }
                let stroke_pixel = match read_window_pixel(hwnd, 15, 60) {
                    Ok(pixel) => pixel,
                    Err(error) => {
                        self.failure = Some(format!("stroke pixel read failed: {error}"));
                        event_loop.exit();
                        return;
                    }
                };
                let background_pixel = match read_window_pixel(hwnd, 70, 100) {
                    Ok(pixel) => pixel,
                    Err(error) => {
                        self.failure = Some(format!("background pixel read failed: {error}"));
                        event_loop.exit();
                        return;
                    }
                };
                self.pixels.push((stroke_pixel, background_pixel));
                if self.pixels.len() < self.scenes.len() {
                    window.request_redraw();
                } else {
                    event_loop.exit();
                }
            }

            fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
                if self.pixels.len() < self.scenes.len() && Instant::now() >= self.deadline {
                    self.failure = Some("Winit request_redraw timed out".to_owned());
                    event_loop.exit();
                } else if self.pixels.len() < self.scenes.len() {
                    event_loop.set_control_flow(ControlFlow::WaitUntil(self.deadline));
                }
            }
        }

        let path = temp_path();
        let mut writer = JournalWriter::create(path.clone(), header()).unwrap();
        writer
            .begin_session_epoch(
                "session-winit-redraw".to_owned(),
                1_800_000_333_000_000_000,
                Some("config-winit-redraw".to_owned()),
                "software Winit redraw fixture".to_owned(),
            )
            .unwrap();
        let frame = CanvasViewport::default()
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let mut physical = sample(1, 15, 60);
        physical.session_id = "session-winit-redraw".to_owned();
        physical.config_id = Some("config-winit-redraw".to_owned());
        physical.stroke_id = Some("winit-redraw-stroke".to_owned());
        let target = StrokeRef {
            journal_id: "canvas-project".to_owned(),
            session_id: physical.session_id.clone(),
            source_api: physical.source_api.clone(),
            device_id: physical.source_device_id.clone(),
            pointer_id: physical.pointer_id,
            stroke_id: "winit-redraw-stroke".to_owned(),
        };
        writer.start_stroke(target, frame, 1).unwrap();
        writer.append_sample(physical).unwrap();
        let commit_action = writer
            .commit_stroke(
                StrokeRef {
                    journal_id: "canvas-project".to_owned(),
                    session_id: "session-winit-redraw".to_owned(),
                    source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
                    device_id: Some("opaque-device-1".to_owned()),
                    pointer_id: Some(12),
                    stroke_id: "winit-redraw-stroke".to_owned(),
                },
                2,
            )
            .unwrap();
        let committed_state = writer.replay_state().clone();
        writer.flush().unwrap();
        drop(writer);

        let mut reopened = JournalWriter::open_append(path.clone()).unwrap();
        assert_eq!(reopened.undo_last_edit(3).unwrap(), commit_action);
        let undone_state = reopened.replay_state().clone();
        assert!(undone_state.projected_samples().unwrap().is_empty());
        assert_eq!(reopened.redo_last_edit(4).unwrap(), commit_action);
        reopened.flush().unwrap();
        drop(reopened);
        let final_journal = crate::journal::read_journal(&path).unwrap();
        let scenes = vec![
            CanvasScene::from_journal(&undone_state, PROVISIONAL_DIRECT_SOURCE_API).unwrap(),
            CanvasScene::from_journal(&committed_state, PROVISIONAL_DIRECT_SOURCE_API).unwrap(),
            CanvasScene::from_journal(&undone_state, PROVISIONAL_DIRECT_SOURCE_API).unwrap(),
            CanvasScene::from_journal(&final_journal.state, PROVISIONAL_DIRECT_SOURCE_API).unwrap(),
        ];

        let mut event_loop_builder = EventLoop::builder();
        event_loop_builder.with_any_thread(true);
        let event_loop = event_loop_builder.build().unwrap();
        let mut app = RedrawApp {
            window: None,
            scenes,
            pixels: Vec::new(),
            deadline: Instant::now() + Duration::from_secs(5),
            failure: None,
        };
        event_loop.run_app(&mut app).unwrap();
        assert!(app.failure.is_none(), "{:?}", app.failure);
        assert_eq!(app.pixels.len(), 4);
        let [
            (empty_before, background_before),
            (committed, committed_background),
            (undone, undone_background),
            (redone, redone_background),
        ] = app.pixels.as_slice()
        else {
            panic!("four Winit redraw states were observed");
        };
        assert_eq!(empty_before, background_before);
        assert_ne!(committed, committed_background);
        assert_eq!(undone, undone_background);
        assert_ne!(redone, redone_background);
        assert_eq!(committed, redone);
        assert_eq!(committed_background, redone_background);
        fs::remove_file(path).unwrap();
    }

    fn read_window_pixel(hwnd: isize, x: i32, y: i32) -> std::io::Result<u32> {
        use windows_sys::Win32::{
            Foundation::RECT,
            Graphics::Gdi::{GetDC, GetPixel, ReleaseDC},
            UI::WindowsAndMessaging::{GetClientRect, IsWindow},
        };
        // SAFETY: hwnd was extracted from the live Winit-owned window in its
        // callback, and IsWindow checks it before client/DC operations.
        if unsafe { IsWindow(hwnd as _) } == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Winit window handle is no longer live",
            ));
        }
        let mut client: RECT = unsafe { std::mem::zeroed() };
        // SAFETY: hwnd is a live window and client is valid writable storage.
        if unsafe { GetClientRect(hwnd as _, &mut client) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if x < 0 || y < 0 || x >= client.right || y >= client.bottom {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pixel coordinates are outside the Winit client area",
            ));
        }
        // SAFETY: GetDC is scoped to this live Winit client HWND and the DC is
        // released synchronously on the same event-loop thread below.
        let dc = unsafe { GetDC(hwnd as _) };
        if dc == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: x/y are within the checked client area and dc is live.
        let pixel = unsafe { GetPixel(dc, x, y) };
        // SAFETY: dc was acquired from hwnd immediately above.
        let release = unsafe { ReleaseDC(hwnd as _, dc) };
        if release == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if pixel == u32::MAX {
            return Err(std::io::Error::last_os_error());
        }
        Ok(pixel)
    }

    fn read_gdi_pixels(
        hdc: windows_sys::Win32::Graphics::Gdi::HDC,
        width: i32,
        height: i32,
    ) -> Vec<windows_sys::Win32::Foundation::COLORREF> {
        let mut pixels = Vec::new();
        pixels.try_reserve_exact((width * height) as usize).unwrap();
        for y in 0..height {
            for x in 0..width {
                // SAFETY: hdc is a live memory DC with a selected bitmap, and
                // coordinates are inside its allocated dimensions.
                pixels.push(unsafe { windows_sys::Win32::Graphics::Gdi::GetPixel(hdc, x, y) });
            }
        }
        pixels
    }

    #[test]
    fn other_source_and_mouse_like_rows_never_enter_provisional_canvas() {
        let mut scene = CanvasScene::default();
        let mut other = sample(1, 1, 2);
        other.source_api = "public-winit".to_owned();
        scene
            .append_live_sample(&other, "canvas-project", true)
            .unwrap();
        let candidate = sample(2, 3, 4);
        scene
            .append_live_sample(&candidate, "canvas-project", false)
            .unwrap();
        assert_eq!(scene.stroke_count(), 0);
        assert_eq!(
            scene.provisional_source_api(),
            PROVISIONAL_DIRECT_SOURCE_API
        );
    }

    fn direct_sample(flags: u32, frame_id_raw: u32) -> OwnedPointerSample {
        OwnedPointerSample {
            history_index_newest_first: 0,
            chronological_index: 0,
            attribution: PointerAttribution::MatchesRequestedPointer,
            pointer_type_raw: windows_sys::Win32::UI::WindowsAndMessaging::PT_PEN,
            pointer_id_raw: 12,
            frame_id_raw,
            source_device_handle_raw_session_scoped: 0x1111,
            target_hwnd_raw_session_scoped: 0x2222,
            pointer_flags_raw: flags,
            button_change_type_raw: 0,
            position: RawScreenPosition {
                coordinate_space: CoordinateSpace::WindowsScreenCoordinates,
                pixel_units: CoordinateUnits::ScreenPixel,
                pt_pixel_location_raw: RawPoint { x: 110, y: 220 },
                himetric_units: CoordinateUnits::HimetricHundredthMillimeter,
                pt_himetric_location_raw: RawPoint { x: 100, y: 200 },
            },
            performance_count_qpc_raw: u64::from(frame_id_raw) * 10_000,
            dw_time_ms_wrapping_raw: frame_id_raw,
            history_count_raw: 1,
            input_data_raw: 0,
            key_states_raw: 0,
            pen_flags_raw: 0,
            pen_mask_raw: windows_sys::Win32::UI::WindowsAndMessaging::PEN_MASK_PRESSURE,
            pressure_raw: 512,
            pressure_validity: PressureValidity::Valid,
            rotation_raw: 0,
            tilt_x_raw: 0,
            tilt_y_raw: 0,
            tilt: None,
            validation_issues: Vec::new(),
        }
    }

    fn direct_batch(
        kind: PointerMessageKind,
        mut sample: OwnedPointerSample,
    ) -> DirectPenHistoryBatch {
        if kind == PointerMessageKind::Up {
            sample.pointer_flags_raw |= windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_UP;
        }
        DirectPenHistoryBatch {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence: u64::from(sample.frame_id_raw),
            message_id_raw: 0x0246,
            message_hwnd_raw_session_scoped: 0x2222,
            message_time_ms_raw: Some(sample.dw_time_ms_wrapping_raw),
            message_kind: kind,
            pointer_id_requested: 12,
            hook_observed_elapsed_ns: u128::from(sample.frame_id_raw) * 100,
            hook_qpc_count_raw: Some(sample.performance_count_qpc_raw + 100),
            hook_qpc_issue: None,
            qpc_frequency_hz: Some(10_000_000),
            native_history_count: 1,
            samples: vec![sample],
        }
    }

    fn tool_sample(flags: u32, frame_id: u32, x: i32, y: i32) -> OwnedPointerSample {
        let mut native = direct_sample(flags, frame_id);
        native.position.pt_pixel_location_raw = RawPoint { x, y };
        native
    }

    fn append_tool_samples(writer: &mut JournalWriter, events: Vec<DirectCaptureEvent>) {
        for event in events {
            let DirectCaptureEvent::PhysicalSample(sample) = event else {
                panic!("non-Pen tool observation must not create a stroke lifecycle event");
            };
            assert_eq!(sample.stroke_id, None);
            writer.append_sample(*sample).unwrap();
        }
    }

    fn payload_u32(payload: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn direct_input_preserves_native_domains_and_requires_contact_down_boundary() {
        let in_contact = windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT;
        let mut tracker = CanvasInputTracker::default();
        let down = direct_batch(PointerMessageKind::Down, direct_sample(in_contact, 11));
        let down_sample = tracker
            .direct_batch_to_samples(&down, "canvas-project", "session-a", Some("config-a"))
            .unwrap()
            .pop()
            .unwrap();
        assert!(down_sample.stroke_id.is_some());
        assert_eq!(down_sample.source_sequence, 11);
        assert_eq!(down_sample.app_arrival_elapsed_ns, 1_100);
        assert_eq!(
            down_sample.native_timestamp.as_ref().unwrap().count_raw,
            110_000
        );
        assert_eq!(
            down_sample.native_timestamp.as_ref().unwrap().frequency_hz,
            Some(10_000_000)
        );
        assert_eq!(down_sample.position.as_ref().unwrap().x_raw, 110);
        assert_eq!(down_sample.pressure.as_ref().unwrap().mask_raw, Some(1));
        assert!(down_sample.raw_payload.starts_with(b"DWP3"));

        let update = direct_batch(PointerMessageKind::Update, direct_sample(in_contact, 12));
        let update_sample = tracker
            .direct_batch_to_samples(&update, "canvas-project", "session-a", Some("config-a"))
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(update_sample.stroke_id, down_sample.stroke_id);

        let up = direct_batch(PointerMessageKind::Up, direct_sample(0, 13));
        let up_sample = tracker
            .direct_batch_to_samples(&up, "canvas-project", "session-a", Some("config-a"))
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(up_sample.stroke_id, down_sample.stroke_id);

        let update_without_down =
            direct_batch(PointerMessageKind::Update, direct_sample(in_contact, 14));
        let unclassified = tracker
            .direct_batch_to_samples(
                &update_without_down,
                "canvas-project",
                "session-a",
                Some("config-a"),
            )
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(unclassified.stroke_id, None);
    }

    #[test]
    fn optional_pressure_and_rotation_require_their_masks_but_raw_slots_survive() {
        for (frame_id, pressure_raw, rotation_raw) in [(40, 0, 0), (41, 1700, 73)] {
            let mut native = direct_sample(0, frame_id);
            native.pen_mask_raw = 0;
            native.pressure_raw = pressure_raw;
            native.pressure_validity = PressureValidity::NotReported;
            native.rotation_raw = rotation_raw;
            let physical = CanvasInputTracker::default()
                .direct_batch_to_samples(
                    &direct_batch(PointerMessageKind::Update, native),
                    "canvas-project",
                    "session-a",
                    None,
                )
                .unwrap()
                .remove(0);
            assert_eq!(physical.pressure, None);
            assert_eq!(physical.rotation_raw, None);
            assert_eq!(payload_u32(&physical.raw_payload, 92), 0);
            assert_eq!(payload_u32(&physical.raw_payload, 96), pressure_raw);
            assert_eq!(payload_u32(&physical.raw_payload, 100), rotation_raw);
        }

        let mut anomalous_masked_pressure = direct_sample(0, 42);
        anomalous_masked_pressure.pen_mask_raw =
            windows_sys::Win32::UI::WindowsAndMessaging::PEN_MASK_PRESSURE;
        anomalous_masked_pressure.pressure_raw = 1700;
        anomalous_masked_pressure.pressure_validity = PressureValidity::OutOfRange;
        let physical = CanvasInputTracker::default()
            .direct_batch_to_samples(
                &direct_batch(PointerMessageKind::Update, anomalous_masked_pressure),
                "canvas-project",
                "session-a",
                None,
            )
            .unwrap()
            .remove(0);
        assert_eq!(physical.pressure.as_ref().unwrap().value_raw, 1700);
        assert_eq!(payload_u32(&physical.raw_payload, 96), 1700);

        let mut reported_rotation = direct_sample(0, 45);
        reported_rotation.pen_mask_raw =
            windows_sys::Win32::UI::WindowsAndMessaging::PEN_MASK_ROTATION;
        reported_rotation.pressure_validity = PressureValidity::NotReported;
        reported_rotation.rotation_raw = 73;
        let physical = CanvasInputTracker::default()
            .direct_batch_to_samples(
                &direct_batch(PointerMessageKind::Update, reported_rotation),
                "canvas-project",
                "session-a",
                None,
            )
            .unwrap()
            .remove(0);
        assert_eq!(physical.pressure, None);
        assert_eq!(physical.rotation_raw, Some(73));
        assert_eq!(payload_u32(&physical.raw_payload, 100), 73);
    }

    #[test]
    fn keyboard_modifiers_are_not_structured_as_pen_buttons() {
        let mut keyboard_modifiers = direct_sample(0, 43);
        keyboard_modifiers.key_states_raw = 0x0008;
        keyboard_modifiers.pen_flags_raw = 0;
        let keyboard_sample = CanvasInputTracker::default()
            .direct_batch_to_samples(
                &direct_batch(PointerMessageKind::Update, keyboard_modifiers),
                "canvas-project",
                "session-a",
                None,
            )
            .unwrap()
            .remove(0);
        assert_eq!(keyboard_sample.button_state_raw, None);
        assert_eq!(payload_u32(&keyboard_sample.raw_payload, 84), 0x0008);
        assert_eq!(payload_u32(&keyboard_sample.raw_payload, 88), 0);

        let mut pen_flags = direct_sample(0, 44);
        pen_flags.key_states_raw = 0;
        pen_flags.pen_flags_raw = windows_sys::Win32::UI::WindowsAndMessaging::PEN_FLAG_BARREL
            | windows_sys::Win32::UI::WindowsAndMessaging::PEN_FLAG_ERASER;
        let pen_flag_sample = CanvasInputTracker::default()
            .direct_batch_to_samples(
                &direct_batch(PointerMessageKind::Update, pen_flags),
                "canvas-project",
                "session-a",
                None,
            )
            .unwrap()
            .remove(0);
        assert_eq!(pen_flag_sample.button_state_raw, None);
        assert_eq!(payload_u32(&pen_flag_sample.raw_payload, 84), 0);
        assert_eq!(
            payload_u32(&pen_flag_sample.raw_payload, 88),
            windows_sys::Win32::UI::WindowsAndMessaging::PEN_FLAG_BARREL
                | windows_sys::Win32::UI::WindowsAndMessaging::PEN_FLAG_ERASER
        );
    }

    #[test]
    fn direct_reentry_invalidates_active_stroke_until_fresh_down() {
        let in_contact = windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT;
        let mut tracker = CanvasInputTracker::default();
        let down = direct_batch(PointerMessageKind::Down, direct_sample(in_contact, 1));
        assert!(
            tracker
                .direct_batch_to_samples(&down, "canvas-project", "session-a", None)
                .unwrap()[0]
                .stroke_id
                .is_some()
        );
        tracker
            .on_direct_lifecycle(LifecycleEventKind::DirectPointerEnter, Some(12), 2)
            .unwrap();
        let update = direct_batch(PointerMessageKind::Update, direct_sample(in_contact, 2));
        assert_eq!(
            tracker
                .direct_batch_to_samples(&update, "canvas-project", "session-a", None)
                .unwrap()[0]
                .stroke_id,
            None
        );
    }

    #[test]
    fn view_change_interrupts_contact_without_fake_up_or_new_stroke() {
        let in_contact = windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT;
        let mut tracker = CanvasInputTracker::default();
        let first_frame = StrokeViewFrame::default();
        let down = direct_batch(PointerMessageKind::Down, direct_sample(in_contact, 31));
        let started = tracker
            .direct_batch_to_events(&down, "canvas-project", "session-a", None, first_frame)
            .unwrap();
        let target = match &started[0] {
            DirectCaptureEvent::StrokeStarted {
                target, view_frame, ..
            } => {
                assert_eq!(*view_frame, first_frame);
                target.clone()
            }
            other => panic!("expected a typed start before samples, got {other:?}"),
        };
        let interrupted = tracker
            .interrupt_active_strokes(
                crate::journal::StrokeInterruptionReason::CanvasViewTransformChanged,
                3_200,
            )
            .unwrap();
        assert!(matches!(
            interrupted.as_slice(),
            [DirectCaptureEvent::StrokeInterrupted {
                target: interrupted_target,
                reason: crate::journal::StrokeInterruptionReason::CanvasViewTransformChanged,
                ..
            }] if interrupted_target == &target
        ));

        let still_contact = direct_batch(PointerMessageKind::Update, direct_sample(in_contact, 32));
        let unclassified = tracker
            .direct_batch_to_events(
                &still_contact,
                "canvas-project",
                "session-a",
                None,
                first_frame,
            )
            .unwrap();
        assert!(matches!(
            &unclassified[0],
            DirectCaptureEvent::PhysicalSample(sample) if sample.stroke_id.is_none()
        ));
        assert!(!unclassified.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::StrokeStarted { .. }
                | DirectCaptureEvent::StrokeCommitRequested { .. }
        )));

        let up = direct_batch(PointerMessageKind::Up, direct_sample(0, 33));
        let up_events = tracker
            .direct_batch_to_events(&up, "canvas-project", "session-a", None, first_frame)
            .unwrap();
        assert!(
            !up_events
                .iter()
                .any(|event| matches!(event, DirectCaptureEvent::StrokeCommitRequested { .. }))
        );
        let fresh_down = direct_batch(PointerMessageKind::Down, direct_sample(in_contact, 34));
        let fresh = tracker
            .direct_batch_to_events(
                &fresh_down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame {
                    screen_origin_x_px: 500,
                    ..first_frame
                },
            )
            .unwrap();
        assert!(
            matches!(fresh.first(), Some(DirectCaptureEvent::StrokeStarted { target: next, .. }) if next != &target)
        );
    }

    #[test]
    fn tool_switch_interrupts_pen_contact_until_a_fresh_native_down() {
        use windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT;

        let mut tracker = CanvasInputTracker::default();
        let down = direct_batch(
            PointerMessageKind::Down,
            direct_sample(POINTER_FLAG_INCONTACT, 91),
        );
        let started = tracker
            .direct_batch_to_events(
                &down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        let original = match &started[0] {
            DirectCaptureEvent::StrokeStarted { target, .. } => target.clone(),
            other => panic!("expected an ink start before tool switch, got {other:?}"),
        };
        let interrupted = tracker
            .interrupt_active_strokes(
                crate::journal::StrokeInterruptionReason::CanvasToolChanged,
                9_200,
            )
            .unwrap();
        assert!(matches!(
            interrupted.as_slice(),
            [DirectCaptureEvent::StrokeInterrupted {
                target,
                reason: crate::journal::StrokeInterruptionReason::CanvasToolChanged,
                ..
            }] if target == &original
        ));
        let held_contact = direct_batch(
            PointerMessageKind::Update,
            direct_sample(POINTER_FLAG_INCONTACT, 92),
        );
        let unclassified = tracker
            .direct_batch_to_events(
                &held_contact,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(matches!(
            &unclassified[0],
            DirectCaptureEvent::PhysicalSample(sample) if sample.stroke_id.is_none()
        ));
        assert_eq!(tracker.active_stroke_count(), 0);

        let late_up = direct_batch(PointerMessageKind::Up, direct_sample(0, 93));
        let late_up_events = tracker
            .direct_batch_to_events(
                &late_up,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(
            !late_up_events
                .iter()
                .any(|event| matches!(event, DirectCaptureEvent::StrokeCommitRequested { .. }))
        );

        let fresh_down = direct_batch(
            PointerMessageKind::Down,
            direct_sample(POINTER_FLAG_INCONTACT, 94),
        );
        let fresh = tracker
            .direct_batch_to_events(
                &fresh_down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(matches!(
            fresh.first(),
            Some(DirectCaptureEvent::StrokeStarted { target, .. }) if target != &original
        ));
    }

    #[test]
    fn only_native_up_commits_and_capture_loss_records_interruption() {
        let in_contact = windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT;
        let mut tracker = CanvasInputTracker::default();
        let down = direct_batch(PointerMessageKind::Down, direct_sample(in_contact, 20));
        let started = tracker
            .direct_batch_to_events(
                &down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        let target = match &started[0] {
            DirectCaptureEvent::StrokeStarted { target, .. } => target.clone(),
            other => panic!("expected explicit StrokeStarted before samples, got {other:?}"),
        };
        assert!(matches!(started[1], DirectCaptureEvent::PhysicalSample(_)));

        let update = direct_batch(PointerMessageKind::Update, direct_sample(in_contact, 21));
        let update_events = tracker
            .direct_batch_to_events(
                &update,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(matches!(
            update_events[0],
            DirectCaptureEvent::PhysicalSample(_)
        ));

        let mut pressure_missing = direct_sample(in_contact, 22);
        pressure_missing.pen_mask_raw = 0;
        pressure_missing.pressure_validity = PressureValidity::NotReported;
        pressure_missing.validation_issues =
            vec![crate::win32_pointer::SampleValidationIssue::PressureMaskMissing];
        let invalid_pressure_update = direct_batch(PointerMessageKind::Update, pressure_missing);
        let invalid_pressure_events = tracker
            .direct_batch_to_events(
                &invalid_pressure_update,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert_eq!(tracker.active_stroke_count(), 1);
        assert_eq!(invalid_pressure_events.len(), 1);
        let DirectCaptureEvent::PhysicalSample(raw_invalid) = &invalid_pressure_events[0] else {
            panic!("invalid pressure update remains raw contact data");
        };
        assert_eq!(
            raw_invalid.stroke_id.as_deref(),
            Some(target.stroke_id.as_str())
        );
        assert_eq!(raw_invalid.pressure, None);
        assert_eq!(payload_u32(&raw_invalid.raw_payload, 92), 0);
        assert_eq!(payload_u32(&raw_invalid.raw_payload, 96), 512);

        let up = direct_batch(PointerMessageKind::Up, direct_sample(0, 23));
        let up_events = tracker
            .direct_batch_to_events(
                &up,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(matches!(
            up_events[0],
            DirectCaptureEvent::PhysicalSample(_)
        ));
        assert!(matches!(
            up_events.last().unwrap(),
            DirectCaptureEvent::StrokeCommitRequested { target: committed, .. }
                if committed == &target
        ));
        assert_eq!(tracker.active_stroke_count(), 0);

        let mut interrupted_tracker = CanvasInputTracker::default();
        interrupted_tracker
            .direct_batch_to_events(
                &down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        let loss = interrupted_tracker
            .on_direct_lifecycle(
                LifecycleEventKind::DirectPointerCaptureChanged,
                Some(12),
                25,
            )
            .unwrap();
        assert!(matches!(
            loss.as_slice(),
            [DirectCaptureEvent::StrokeInterrupted {
                reason: crate::journal::StrokeInterruptionReason::PointerCaptureChanged,
                ..
            }]
        ));
        let late_up = interrupted_tracker
            .direct_batch_to_events(
                &up,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(
            !late_up
                .iter()
                .any(|event| matches!(event, DirectCaptureEvent::StrokeCommitRequested { .. }))
        );
    }

    #[test]
    fn native_up_requires_matching_device_pointer_up_flag_and_not_canceled() {
        use windows_sys::Win32::UI::Input::Pointer::{
            POINTER_FLAG_CANCELED, POINTER_FLAG_INCONTACT, POINTER_FLAG_UP,
        };

        let mut tracker = CanvasInputTracker::default();
        let down = direct_batch(
            PointerMessageKind::Down,
            direct_sample(POINTER_FLAG_INCONTACT, 51),
        );
        let started = tracker
            .direct_batch_to_events(
                &down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        let target = match &started[0] {
            DirectCaptureEvent::StrokeStarted { target, .. } => target.clone(),
            other => panic!("expected explicit stroke start, got {other:?}"),
        };

        let canceled_native_up = direct_sample(POINTER_FLAG_UP | POINTER_FLAG_CANCELED, 52);
        let canceled = direct_batch(PointerMessageKind::Up, canceled_native_up);
        let canceled_events = tracker
            .direct_batch_to_events(
                &canceled,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(canceled_events.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::StrokeInterrupted {
                target: interrupted,
                reason: crate::journal::StrokeInterruptionReason::CanceledNativeUp,
                ..
            } if interrupted == &target
        )));
        assert!(
            !canceled_events
                .iter()
                .any(|event| matches!(event, DirectCaptureEvent::StrokeCommitRequested { .. }))
        );
        assert!(canceled_events.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::PhysicalSample(sample) if sample.stroke_id.as_deref() == Some(target.stroke_id.as_str())
        )));
        assert_eq!(tracker.active_stroke_count(), 0);

        let chronological_down = direct_batch(
            PointerMessageKind::Down,
            direct_sample(POINTER_FLAG_INCONTACT, 53),
        );
        let chronological_started = tracker
            .direct_batch_to_events(
                &chronological_down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        let chronological_target = match &chronological_started[0] {
            DirectCaptureEvent::StrokeStarted { target, .. } => target.clone(),
            other => panic!("expected fresh stroke before chronological up, got {other:?}"),
        };
        let mut older_up = direct_sample(POINTER_FLAG_UP, 54);
        older_up.history_index_newest_first = 1;
        older_up.chronological_index = 0;
        let mut newer_canceled_up = direct_sample(POINTER_FLAG_UP | POINTER_FLAG_CANCELED, 55);
        newer_canceled_up.history_index_newest_first = 0;
        newer_canceled_up.chronological_index = 1;
        let mut contradictory_up = direct_batch(PointerMessageKind::Up, older_up);
        contradictory_up.samples.push(newer_canceled_up);
        contradictory_up.native_history_count = 2;
        let contradictory_events = tracker
            .direct_batch_to_events(
                &contradictory_up,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert_eq!(
            contradictory_up
                .samples
                .iter()
                .map(|sample| sample.frame_id_raw)
                .collect::<Vec<_>>(),
            vec![54, 55]
        );
        assert_eq!(
            contradictory_events
                .iter()
                .filter(|event| matches!(event, DirectCaptureEvent::PhysicalSample(_)))
                .count(),
            2
        );
        let preserved_native_up_flags = contradictory_events
            .iter()
            .filter_map(|event| match event {
                DirectCaptureEvent::PhysicalSample(sample) => {
                    Some(payload_u32(&sample.raw_payload, 40))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            preserved_native_up_flags,
            vec![POINTER_FLAG_UP, POINTER_FLAG_UP | POINTER_FLAG_CANCELED]
        );
        assert!(contradictory_events.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::StrokeInterrupted {
                target,
                reason: crate::journal::StrokeInterruptionReason::CanceledNativeUp,
                ..
            } if target == &chronological_target
        )));
        assert!(contradictory_events.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::UnmatchedNativeUp {
                reason: DirectUpIssue::CanceledNativeUp,
                ..
            }
        )));
        assert!(
            contradictory_events
                .iter()
                .all(|event| !matches!(event, DirectCaptureEvent::StrokeCommitRequested { .. }))
        );
        assert_eq!(tracker.active_stroke_count(), 0);

        let fresh_down = direct_batch(
            PointerMessageKind::Down,
            direct_sample(POINTER_FLAG_INCONTACT, 56),
        );
        tracker
            .direct_batch_to_events(
                &fresh_down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        let mut missing = direct_batch(PointerMessageKind::Up, direct_sample(0, 57));
        missing.samples[0].pointer_flags_raw &= !POINTER_FLAG_UP;
        let missing_events = tracker
            .direct_batch_to_events(
                &missing,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(
            !missing_events
                .iter()
                .any(|event| matches!(event, DirectCaptureEvent::StrokeCommitRequested { .. }))
        );
        assert!(missing_events.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::UnmatchedNativeUp {
                reason: DirectUpIssue::MissingNativeUpFlag,
                ..
            }
        )));

        let final_down = direct_batch(
            PointerMessageKind::Down,
            direct_sample(POINTER_FLAG_INCONTACT, 58),
        );
        tracker
            .direct_batch_to_events(
                &final_down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        let mut mismatched_device_up = direct_sample(POINTER_FLAG_UP, 59);
        mismatched_device_up.source_device_handle_raw_session_scoped = 0x3333;
        let mismatched = direct_batch(PointerMessageKind::Up, mismatched_device_up);
        let mismatch_events = tracker
            .direct_batch_to_events(
                &mismatched,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(
            !mismatch_events
                .iter()
                .any(|event| matches!(event, DirectCaptureEvent::StrokeCommitRequested { .. }))
        );
        assert!(mismatch_events.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::StrokeInterrupted {
                reason: crate::journal::StrokeInterruptionReason::UnattributedNativeUp,
                ..
            }
        )));
        assert_eq!(tracker.active_stroke_count(), 0);

        let no_history_down = direct_batch(
            PointerMessageKind::Down,
            direct_sample(POINTER_FLAG_INCONTACT, 60),
        );
        tracker
            .direct_batch_to_events(
                &no_history_down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        let mut empty_up = direct_batch(PointerMessageKind::Up, direct_sample(POINTER_FLAG_UP, 61));
        empty_up.samples.clear();
        empty_up.native_history_count = 0;
        let empty_events = tracker
            .direct_batch_to_events(
                &empty_up,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert!(empty_events.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::StrokeInterrupted {
                reason: crate::journal::StrokeInterruptionReason::UnattributedNativeUp,
                ..
            }
        )));
        assert!(empty_events.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::UnmatchedNativeUp {
                reason: DirectUpIssue::EmptyHistory,
                ..
            }
        )));
        assert_eq!(tracker.active_stroke_count(), 0);
    }

    #[test]
    fn mixed_device_history_never_starts_or_keeps_a_device_scoped_stroke() {
        use windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT;

        let mut tracker = CanvasInputTracker::default();
        let mut mixed_down = direct_batch(
            PointerMessageKind::Down,
            direct_sample(POINTER_FLAG_INCONTACT, 61),
        );
        let mut other_device = direct_sample(POINTER_FLAG_INCONTACT, 62);
        other_device.source_device_handle_raw_session_scoped = 0x3333;
        mixed_down.samples.push(other_device);
        mixed_down.native_history_count = 2;
        let down_events = tracker
            .direct_batch_to_events(
                &mixed_down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert_eq!(tracker.active_stroke_count(), 0);
        assert!(
            !down_events
                .iter()
                .any(|event| matches!(event, DirectCaptureEvent::StrokeStarted { .. }))
        );
        assert_eq!(
            down_events
                .iter()
                .filter(|event| matches!(
                    event,
                    DirectCaptureEvent::PhysicalSample(sample) if sample.stroke_id.is_none()
                ))
                .count(),
            2
        );

        let mut valid_down = direct_batch(
            PointerMessageKind::Down,
            direct_sample(POINTER_FLAG_INCONTACT, 63),
        );
        valid_down.samples[0].source_device_handle_raw_session_scoped = 0x1111;
        tracker
            .direct_batch_to_events(
                &valid_down,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert_eq!(tracker.active_stroke_count(), 1);

        let mut mixed_update = direct_batch(
            PointerMessageKind::Update,
            direct_sample(POINTER_FLAG_INCONTACT, 64),
        );
        let mut other_update = direct_sample(POINTER_FLAG_INCONTACT, 65);
        other_update.source_device_handle_raw_session_scoped = 0x3333;
        mixed_update.samples.push(other_update);
        mixed_update.native_history_count = 2;
        let update_events = tracker
            .direct_batch_to_events(
                &mixed_update,
                "canvas-project",
                "session-a",
                None,
                StrokeViewFrame::default(),
            )
            .unwrap();
        assert_eq!(tracker.active_stroke_count(), 0);
        assert!(update_events.iter().any(|event| matches!(
            event,
            DirectCaptureEvent::StrokeInterrupted {
                reason: crate::journal::StrokeInterruptionReason::MixedDeviceBatch,
                ..
            }
        )));
        assert_eq!(
            update_events
                .iter()
                .filter(|event| matches!(
                    event,
                    DirectCaptureEvent::PhysicalSample(sample) if sample.stroke_id.is_none()
                ))
                .count(),
            2
        );
    }

    #[test]
    fn select_region_handles_opposite_i32_native_coordinates_without_mutating_raw_rows() {
        use windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT;

        let mut tracker = CanvasToolGestureTracker::default();
        let scene = CanvasScene::default();
        let viewport = CanvasViewport::default();
        let view_frame = viewport
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let down = direct_batch(
            PointerMessageKind::Down,
            tool_sample(POINTER_FLAG_INCONTACT, 90, i32::MIN, 100),
        );
        let (down_raw, down_intent) = tracker
            .direct_batch_to_tool_events(
                CanvasTool::Select,
                &down,
                CanvasToolCaptureContext {
                    session_id: "session-extreme-select",
                    config_id: None,
                    view_frame,
                    scene: &scene,
                    viewport,
                },
            )
            .unwrap();
        assert!(down_intent.is_none());
        let [DirectCaptureEvent::PhysicalSample(down_sample)] = down_raw.as_slice() else {
            panic!("select down preserves one raw physical row");
        };
        assert_eq!(
            i32::from_le_bytes(down_sample.raw_payload[48..52].try_into().unwrap()),
            i32::MIN
        );

        let up = direct_batch(PointerMessageKind::Up, tool_sample(0, 91, i32::MAX, 100));
        let (up_raw, up_intent) = tracker
            .direct_batch_to_tool_events(
                CanvasTool::Select,
                &up,
                CanvasToolCaptureContext {
                    session_id: "session-extreme-select",
                    config_id: None,
                    view_frame,
                    scene: &scene,
                    viewport,
                },
            )
            .unwrap();
        let [DirectCaptureEvent::PhysicalSample(up_sample)] = up_raw.as_slice() else {
            panic!("select up preserves one raw physical row");
        };
        assert_eq!(
            i32::from_le_bytes(up_sample.raw_payload[48..52].try_into().unwrap()),
            i32::MAX
        );
        let Some(CanvasToolIntent::SelectRegion(region)) = up_intent else {
            panic!("opposite i32 endpoints form a select-region drag");
        };
        assert_eq!(region.left, f64::from(i32::MIN));
        assert_eq!(region.right, f64::from(i32::MAX));
        assert_eq!(region.top, 100.0);
        assert_eq!(region.bottom, 100.0);
        assert!(tracker.active.is_empty());
    }

    #[test]
    fn canceled_up_overrides_older_uncanceled_up_for_eraser_and_select() {
        use windows_sys::Win32::UI::Input::Pointer::{
            POINTER_FLAG_CANCELED, POINTER_FLAG_INCONTACT, POINTER_FLAG_UP,
        };

        let mut scene = CanvasScene::default();
        scene
            .append_live_sample(&sample(1, 110, 180), "canvas-project", true)
            .unwrap();
        let viewport = CanvasViewport::default();
        let view_frame = viewport
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();

        for (tool, up_x, up_y) in [
            (CanvasTool::Eraser, 110, 220),
            (CanvasTool::Select, 120, 230),
        ] {
            let mut tracker = CanvasToolGestureTracker::default();
            let down = direct_batch(
                PointerMessageKind::Down,
                tool_sample(POINTER_FLAG_INCONTACT, 100, 110, 220),
            );
            let (down_raw, down_intent) = tracker
                .direct_batch_to_tool_events(
                    tool,
                    &down,
                    CanvasToolCaptureContext {
                        session_id: "session-canceled-tool",
                        config_id: None,
                        view_frame,
                        scene: &scene,
                        viewport,
                    },
                )
                .unwrap();
            assert!(down_intent.is_none());
            assert_eq!(down_raw.len(), 1);

            let mut older_up = tool_sample(POINTER_FLAG_UP, 101, up_x, up_y);
            older_up.history_index_newest_first = 1;
            older_up.chronological_index = 0;
            let mut newer_canceled_up =
                tool_sample(POINTER_FLAG_UP | POINTER_FLAG_CANCELED, 102, up_x, up_y);
            newer_canceled_up.history_index_newest_first = 0;
            newer_canceled_up.chronological_index = 1;
            let mut up = direct_batch(PointerMessageKind::Up, older_up);
            up.samples.push(newer_canceled_up);
            up.native_history_count = 2;

            let (up_raw, up_intent) = tracker
                .direct_batch_to_tool_events(
                    tool,
                    &up,
                    CanvasToolCaptureContext {
                        session_id: "session-canceled-tool",
                        config_id: None,
                        view_frame,
                        scene: &scene,
                        viewport,
                    },
                )
                .unwrap();
            assert_eq!(up_raw.len(), 2, "both native rows remain observable");
            let preserved_native_up_flags = up_raw
                .iter()
                .filter_map(|event| match event {
                    DirectCaptureEvent::PhysicalSample(sample) => {
                        Some(payload_u32(&sample.raw_payload, 40))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(
                preserved_native_up_flags,
                vec![POINTER_FLAG_UP, POINTER_FLAG_UP | POINTER_FLAG_CANCELED]
            );
            assert_eq!(
                up.samples
                    .iter()
                    .map(|sample| sample.frame_id_raw)
                    .collect::<Vec<_>>(),
                vec![101, 102]
            );
            assert!(
                up_intent.is_none(),
                "canceled history cannot edit the scene"
            );
            assert!(tracker.active.is_empty());
            assert_eq!(scene.stroke_count(), 1);
        }
    }

    #[test]
    fn eraser_and_select_tools_keep_raw_samples_unstroked_and_persist_intents() {
        use windows_sys::Win32::UI::Input::Pointer::POINTER_FLAG_INCONTACT;

        fn writer_with_existing_stroke(
            path: &std::path::Path,
        ) -> (JournalWriter, CanvasScene, StrokeRef) {
            let mut writer = JournalWriter::create(path.to_path_buf(), header()).unwrap();
            let existing = sample(1, 110, 180);
            let target = StrokeRef {
                journal_id: "canvas-project".to_owned(),
                session_id: existing.session_id.clone(),
                source_api: existing.source_api.clone(),
                device_id: existing.source_device_id.clone(),
                pointer_id: existing.pointer_id,
                stroke_id: existing.stroke_id.clone().unwrap(),
            };
            writer.append_sample(existing).unwrap();
            let scene =
                CanvasScene::from_journal(writer.replay_state(), PROVISIONAL_DIRECT_SOURCE_API)
                    .unwrap();
            (writer, scene, target)
        }

        let viewport = CanvasViewport::default();
        let view_frame = viewport
            .stroke_view_frame(CanvasOrigin::default(), 1.0)
            .unwrap();
        let eraser_path = temp_path();
        let (mut eraser_writer, eraser_scene, erased_target) =
            writer_with_existing_stroke(&eraser_path);
        let mut eraser = CanvasToolGestureTracker::default();
        let down = direct_batch(
            PointerMessageKind::Down,
            tool_sample(POINTER_FLAG_INCONTACT, 70, 110, 220),
        );
        let (down_raw, down_intent) = eraser
            .direct_batch_to_tool_events(
                CanvasTool::Eraser,
                &down,
                CanvasToolCaptureContext {
                    session_id: "session-canvas",
                    config_id: Some("config-canvas"),
                    view_frame,
                    scene: &eraser_scene,
                    viewport,
                },
            )
            .unwrap();
        assert!(down_intent.is_none());
        append_tool_samples(&mut eraser_writer, down_raw);
        let update = direct_batch(
            PointerMessageKind::Update,
            tool_sample(POINTER_FLAG_INCONTACT, 71, 110, 220),
        );
        let (update_raw, update_intent) = eraser
            .direct_batch_to_tool_events(
                CanvasTool::Eraser,
                &update,
                CanvasToolCaptureContext {
                    session_id: "session-canvas",
                    config_id: Some("config-canvas"),
                    view_frame,
                    scene: &eraser_scene,
                    viewport,
                },
            )
            .unwrap();
        assert!(update_intent.is_none());
        append_tool_samples(&mut eraser_writer, update_raw);
        let up = direct_batch(PointerMessageKind::Up, tool_sample(0, 72, 110, 220));
        let (up_raw, up_intent) = eraser
            .direct_batch_to_tool_events(
                CanvasTool::Eraser,
                &up,
                CanvasToolCaptureContext {
                    session_id: "session-canvas",
                    config_id: Some("config-canvas"),
                    view_frame,
                    scene: &eraser_scene,
                    viewport,
                },
            )
            .unwrap();
        append_tool_samples(&mut eraser_writer, up_raw);
        let Some(CanvasToolIntent::Edit(EditCommand::Tombstone { targets })) = up_intent else {
            panic!("Eraser pen-up must produce a journal tombstone intent");
        };
        assert_eq!(targets, vec![erased_target.clone()]);
        let erase_command = EditCommand::Tombstone { targets };
        eraser_writer.apply_edit_action(73, erase_command).unwrap();
        eraser_writer.flush().unwrap();
        drop(eraser_writer);
        let erased = crate::journal::read_journal(&eraser_path).unwrap();
        assert_eq!(erased.state.physical_samples.len(), 4);
        assert!(
            erased
                .state
                .physical_samples
                .iter()
                .skip(1)
                .all(|stored| stored.sample.stroke_id.is_none())
        );
        assert!(
            erased
                .state
                .projected_samples()
                .unwrap()
                .iter()
                .all(|projected| projected.stroke_ref.as_ref() != Some(&erased_target))
        );
        assert_eq!(
            CanvasScene::from_journal(&erased.state, PROVISIONAL_DIRECT_SOURCE_API)
                .unwrap()
                .stroke_count(),
            0
        );
        fs::remove_file(eraser_path).unwrap();

        let select_path = temp_path();
        let (mut select_writer, select_scene, moved_target) =
            writer_with_existing_stroke(&select_path);
        let mut selector = CanvasToolGestureTracker::default();
        let down = direct_batch(
            PointerMessageKind::Down,
            tool_sample(POINTER_FLAG_INCONTACT, 80, 110, 220),
        );
        let (down_raw, down_intent) = selector
            .direct_batch_to_tool_events(
                CanvasTool::Select,
                &down,
                CanvasToolCaptureContext {
                    session_id: "session-canvas",
                    config_id: Some("config-canvas"),
                    view_frame,
                    scene: &select_scene,
                    viewport,
                },
            )
            .unwrap();
        assert!(down_intent.is_none());
        append_tool_samples(&mut select_writer, down_raw);
        let update = direct_batch(
            PointerMessageKind::Update,
            tool_sample(POINTER_FLAG_INCONTACT, 81, 120, 230),
        );
        let (update_raw, update_intent) = selector
            .direct_batch_to_tool_events(
                CanvasTool::Select,
                &update,
                CanvasToolCaptureContext {
                    session_id: "session-canvas",
                    config_id: Some("config-canvas"),
                    view_frame,
                    scene: &select_scene,
                    viewport,
                },
            )
            .unwrap();
        assert!(update_intent.is_none());
        append_tool_samples(&mut select_writer, update_raw);
        let up = direct_batch(PointerMessageKind::Up, tool_sample(0, 82, 120, 230));
        let (up_raw, up_intent) = selector
            .direct_batch_to_tool_events(
                CanvasTool::Select,
                &up,
                CanvasToolCaptureContext {
                    session_id: "session-canvas",
                    config_id: Some("config-canvas"),
                    view_frame,
                    scene: &select_scene,
                    viewport,
                },
            )
            .unwrap();
        append_tool_samples(&mut select_writer, up_raw);
        let Some(CanvasToolIntent::Edit(EditCommand::Move {
            target,
            delta_x_raw,
            delta_y_raw,
            ..
        })) = up_intent
        else {
            panic!("Select pen drag must produce a logical move intent");
        };
        assert_eq!(target, moved_target);
        assert_eq!((delta_x_raw, delta_y_raw), (10, 10));
        select_writer
            .apply_edit_action(
                83,
                EditCommand::Move {
                    target: target.clone(),
                    delta_x_raw,
                    delta_y_raw,
                    coordinate_space: "windows-screen-coordinates".to_owned(),
                    units: "screen-pixel".to_owned(),
                },
            )
            .unwrap();
        select_writer.flush().unwrap();
        drop(select_writer);
        let selected = crate::journal::read_journal(&select_path).unwrap();
        assert_eq!(selected.state.physical_samples.len(), 4);
        assert!(
            selected
                .state
                .physical_samples
                .iter()
                .skip(1)
                .all(|stored| stored.sample.stroke_id.is_none())
        );
        let selected_scene =
            CanvasScene::from_journal(&selected.state, PROVISIONAL_DIRECT_SOURCE_API).unwrap();
        assert_eq!(selected_scene.stroke_count(), 1);
        let rendered = selected_scene.render_plan(viewport).unwrap();
        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0].points[0], CanvasPointPx { x: 120, y: 230 });
        fs::remove_file(select_path).unwrap();
    }
}
