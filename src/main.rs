#[cfg(not(target_os = "windows"))]
compile_error!("The LassoInk Gate 0 probe is Windows-only.");

mod benchmark;
mod canvas;
#[allow(dead_code)]
mod journal;
mod process_cpu;
mod project_runtime;
#[allow(dead_code)]
mod provider_protocol;
mod session;
mod win32_pointer;
mod wintab;

use canvas::{
    CanvasInputTracker, CanvasOrigin, CanvasRect, CanvasScene, CanvasTool,
    CanvasToolCaptureContext, CanvasToolGestureTracker, CanvasToolIntent, CanvasViewport,
    DirectCaptureEvent, paint_gdi,
};
use journal::{
    EditCommand, JournalEvent, JournalHeader, JournalMetadata, JournalRecord, JournalWriter,
    MetadataScope, StrokeInterruptionReason, StrokeViewFrame, migrate_schema_one_to_three,
    migrate_schema_two_to_three, read_journal,
};
use process_cpu::{
    PROCESS_CPU_SCOPE, measure as measure_process_cpu, snapshot as process_cpu_snapshot,
};
use project_runtime::{ProjectQueueError, ProjectWriterAck, ProjectWriterHandle};
use session::{SessionWriter, default_session_path, read_report};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    error::Error,
    io,
    ops::Range,
    path::{Path, PathBuf},
    process,
    rc::Rc,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use win32_pointer::{
    CaptureMode, CaptureSource, LifecycleEventKind, LifecycleEventRecord, ProbeRecord, ProbeState,
    ProbeSummary, PublicEventCapability, PublicWinitEventData, PublicWinitEventRecord,
    StorageLimit, WintabPacketTimeMode, WintabStatus,
};
use winit::event::ElementState;
use winit::keyboard::{KeyCode, ModifiersState, PhysicalKey};
use winit::{
    application::ApplicationHandler,
    event::{DeviceEvent, MouseButton, MouseScrollDelta, StartCause, WindowEvent},
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    raw_window_handle::{HasWindowHandle, RawWindowHandle},
    window::{Window, WindowId},
};
use wintab::{WT_DEFBASE, WintabCapture, WintabControlObserver};

const STATUS: &str = "LassoInk M3 minimal canvas: Direct WM_POINTER is provisional; no mouse fallback or capture winner is selected";
const NOT_IMPLEMENTED: &str =
    "Convert provider unavailable; Gate 0 hardware status is DEFERRED / NOT PASSED.";
const STORAGE_POLICY: &str = "Bounded local session output under the selected session directory; 4,096 retained events, 131,072 native samples, 65,536 direct samples per history, 4,096 Wintab packets per message, and bounded parser/metrics partitions.";
const TITLE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const EVENT_LOOP_WAKE_MARKER_THRESHOLD_NS: u128 = 50_000_000;

#[cfg(test)]
pub(crate) fn require_native_ui_test_opt_in() {
    fn env_is(key: &str, expected: &str) -> bool {
        std::env::var(key).is_ok_and(|actual| actual == expected)
    }

    let hosted_event =
        env_is("GITHUB_EVENT_NAME", "push") || env_is("GITHUB_EVENT_NAME", "pull_request");
    assert!(
        cfg!(target_os = "windows")
            && env_is("LASSOINK_RUN_NATIVE_UI_TESTS", "1")
            && env_is("CI", "true")
            && env_is("GITHUB_ACTIONS", "true")
            && env_is("RUNNER_ENVIRONMENT", "github-hosted")
            && env_is("RUNNER_OS", "Windows")
            && env_is("GITHUB_REPOSITORY", "Herzchens/LassoInk")
            && hosted_event,
        "native Win32/Winit tests require the explicit isolated GitHub Actions Windows job opt-in"
    );
}

struct ProbeApp {
    window: Option<Window>,
    focused: Option<bool>,
    client_size: Option<(u32, u32)>,
    last_title: Option<String>,
    last_title_update: Option<Instant>,
    startup_error: Option<String>,
    capture_mode: CaptureMode,
    app_clock_origin: Instant,
    probe_state: Rc<RefCell<ProbeState>>,
    wintab: Rc<RefCell<WintabCapture>>,
    wintab_control_observer: Option<WintabControlObserver>,
    wintab_control_pending: Arc<AtomicBool>,
    session_writer: Option<SessionWriter>,
    session_path: PathBuf,
    session_writer_failed: bool,
    project_writer: Option<ProjectWriterHandle>,
    project_path: PathBuf,
    project_journal_id: String,
    active_session_id: String,
    active_config_id: String,
    direct_input_tracker: CanvasInputTracker,
    canvas_tool_gesture_tracker: CanvasToolGestureTracker,
    deferred_canvas_intents: Vec<CanvasToolIntent>,
    last_project_message_sequence: u64,
    pending_record_cursor: PendingRecordCursor,
    next_project_batch_id: u64,
    deferred_capture_batch: Option<(u64, u64, Vec<DirectCaptureEvent>)>,
    project_incomplete_reason: Option<String>,
    project_recovery_note: Option<String>,
    historical_interrupted_strokes_at_start: usize,
    controlled_stall: ControlledStallTrigger,
    canvas_scene: CanvasScene,
    canvas_viewport: CanvasViewport,
    canvas_origin: Option<CanvasOrigin>,
    canvas_dpi_scale_factor: f64,
    canvas_cursor_client: Option<(f64, f64)>,
    canvas_modifiers: ModifiersState,
    canvas_selection_drag_start: Option<(f64, f64)>,
    canvas_move_drag_start: Option<(f64, f64)>,
    canvas_pan_drag_last: Option<(f64, f64)>,
    canvas_status: String,
}

struct RunOptions {
    capture_mode: CaptureMode,
    session_path: PathBuf,
    project_path: PathBuf,
    open_project: bool,
    metadata: BTreeMap<String, String>,
    controlled_stall_ms: Option<u64>,
}

#[derive(Debug, Default)]
struct ControlledStallTrigger {
    duration_ms: Option<u64>,
    armed: bool,
    triggered: bool,
}

#[derive(Debug, Default)]
struct PendingRecordCursor {
    next_index: usize,
}

fn cancel_mouse_canvas_gestures(
    cursor: &mut Option<(f64, f64)>,
    selection_drag_start: &mut Option<(f64, f64)>,
    move_drag_start: &mut Option<(f64, f64)>,
    pan_drag_last: &mut Option<(f64, f64)>,
) -> bool {
    let had_active_drag =
        selection_drag_start.is_some() || move_drag_start.is_some() || pan_drag_last.is_some();
    *cursor = None;
    *selection_drag_start = None;
    *move_drag_start = None;
    *pan_drag_last = None;
    had_active_drag
}

impl PendingRecordCursor {
    fn take_new_range(&mut self, pending_len: usize) -> Range<usize> {
        if pending_len < self.next_index {
            self.next_index = 0;
        }
        let start = self.next_index;
        self.next_index = pending_len;
        start..pending_len
    }

    fn reset_after_buffer_clear(&mut self) {
        self.next_index = 0;
    }
}

impl ControlledStallTrigger {
    fn new(duration_ms: Option<u64>) -> Self {
        Self {
            duration_ms,
            armed: false,
            triggered: false,
        }
    }

    fn observe_operator_key(
        &mut self,
        physical_key: &PhysicalKey,
        state: ElementState,
        repeat: bool,
    ) -> bool {
        if self.duration_ms.is_some()
            && !self.triggered
            && !repeat
            && state == ElementState::Pressed
            && *physical_key == PhysicalKey::Code(KeyCode::F9)
        {
            self.armed = true;
            true
        } else {
            false
        }
    }

    fn take_armed_once(&mut self) -> Option<u64> {
        if self.armed && !self.triggered {
            self.armed = false;
            self.triggered = true;
            self.duration_ms
        } else {
            None
        }
    }
}

impl ProbeApp {
    fn title(&self) -> String {
        let summary: ProbeSummary = self.probe_state.borrow().summary();
        let capture_state = capture_state(summary);
        let timing_state = timing_state(summary);
        let mode_label = match self.capture_mode {
            CaptureMode::DirectWmPointer => "mode direct WM_POINTER".to_owned(),
            CaptureMode::Wintab => format!("mode Wintab ({:?})", self.wintab.borrow().status()),
        };
        let latest_issue = summary
            .latest_incomplete_issue
            .map(|issue| format!("{issue:?}"))
            .unwrap_or_else(|| "none".to_owned());
        let latest_wintab_issue = self
            .wintab
            .borrow()
            .latest_issue()
            .or(summary.latest_wintab_issue);
        let latest_startup_issue = latest_startup_issue_label(summary);
        let validation_state = if summary.validation_anomaly_samples > 0 {
            "VALIDATION WARNING"
        } else {
            "validation clear"
        };
        let focus = match self.focused {
            Some(true) => "focused",
            Some(false) => "unfocused",
            None => "focus unknown",
        };
        let size = self
            .client_size
            .map(|(width, height)| format!("{width}x{height}"))
            .unwrap_or_else(|| "size unknown".to_owned());

        format!(
            "{STATUS} | {mode_label} | {capture_state} | {timing_state} | {validation_state} | startup issue {latest_startup_issue} | records {} raw direct samples {} valid direct rows {} invalid candidates {} validation anomalies {} public events {} Wintab packets {} uncertain Wintab {} control notifications {} lifecycle {} issues {} | incomplete batches {} latest issue {} latest Wintab issue {:?} | omitted records {} batches {} samples {} | {focus} | client {size}",
            summary.records_retained,
            summary.samples,
            summary.valid_direct_pen_samples,
            summary.invalid_direct_pen_samples,
            summary.validation_anomaly_samples,
            summary.public_events,
            summary.wintab_packets,
            summary.uncertain_wintab_packets,
            summary.wintab_control_messages,
            summary.lifecycle_events,
            summary.issues,
            summary.incomplete_batches,
            latest_issue,
            latest_wintab_issue,
            summary.records_not_retained,
            summary.batches_not_retained,
            summary.samples_not_retained
        )
    }

    fn refresh_title(&mut self) {
        let now = Instant::now();
        if self
            .last_title_update
            .is_some_and(|last| now.duration_since(last) < TITLE_REFRESH_INTERVAL)
        {
            return;
        }
        let Some(window) = &self.window else {
            return;
        };
        self.last_title_update = Some(now);
        let title = self.title();
        if self.last_title.as_deref() == Some(title.as_str()) {
            return;
        }
        window.set_title(&title);
        self.last_title = Some(title);
    }

    fn set_canvas_tool(&mut self, tool: CanvasTool) {
        if self.canvas_scene.tool() != tool {
            self.interrupt_active_canvas_strokes(StrokeInterruptionReason::CanvasToolChanged);
            self.canvas_tool_gesture_tracker.cancel_all();
        }
        self.canvas_scene.set_tool(tool);
        self.canvas_selection_drag_start = None;
        self.canvas_move_drag_start = None;
        self.canvas_scene.set_selection_rect(None);
        self.canvas_status = match tool {
            CanvasTool::Pen => {
                "Direct WM_POINTER pen input only; mouse drawing disabled".to_owned()
            }
            CanvasTool::Eraser => {
                "Eraser: pen contact erases on native up; mouse click then Delete also works"
                    .to_owned()
            }
            CanvasTool::Select => {
                "Select: pen or mouse selects; drag a selected stroke to move".to_owned()
            }
        };
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }

    fn allocate_project_batch_id(&mut self) -> Option<u64> {
        let batch_id = self.next_project_batch_id;
        self.next_project_batch_id = batch_id.checked_add(1)?;
        Some(batch_id)
    }

    fn submit_project_edit(&mut self, command: EditCommand, label: &str) {
        let Some(batch_id) = self.allocate_project_batch_id() else {
            self.mark_project_incomplete("project command identifier exhausted".to_owned());
            return;
        };
        let Some(writer) = self.project_writer.as_mut() else {
            self.canvas_status = format!("{label} was not queued: project writer is unavailable");
            return;
        };
        match writer.try_edit_action(
            batch_id,
            self.app_clock_origin.elapsed().as_nanos(),
            command,
        ) {
            Ok(()) => self.canvas_status = format!("{label} queued for durable project save"),
            Err(ProjectQueueError::QueueFull) => {
                self.canvas_status = format!("{label} not queued: project writer is busy; retry")
            }
            Err(ProjectQueueError::WorkerStopped | ProjectQueueError::Stopped { .. }) => {
                self.mark_project_incomplete(format!("{label} not queued: project writer stopped"))
            }
            Err(ProjectQueueError::Backpressure { .. }) => {
                self.canvas_status = format!("{label} not queued: project writer is busy; retry")
            }
        }
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }

    fn submit_project_undo_redo(&mut self, redo: bool, label: &str) {
        let Some(batch_id) = self.allocate_project_batch_id() else {
            self.mark_project_incomplete("project command identifier exhausted".to_owned());
            return;
        };
        let Some(writer) = self.project_writer.as_mut() else {
            self.canvas_status = format!("{label} was not queued: project writer is unavailable");
            return;
        };
        let app_arrival_elapsed_ns = self.app_clock_origin.elapsed().as_nanos();
        let result = if redo {
            writer.try_redo(batch_id, app_arrival_elapsed_ns)
        } else {
            writer.try_undo(batch_id, app_arrival_elapsed_ns)
        };
        match result {
            Ok(()) => self.canvas_status = format!("{label} queued for durable project save"),
            Err(ProjectQueueError::QueueFull) => {
                self.canvas_status = format!("{label} not queued: project writer is busy; retry")
            }
            Err(ProjectQueueError::WorkerStopped | ProjectQueueError::Stopped { .. }) => {
                self.mark_project_incomplete(format!("{label} not queued: project writer stopped"))
            }
            Err(ProjectQueueError::Backpressure { .. }) => {
                self.canvas_status = format!("{label} not queued: project writer is busy; retry")
            }
        }
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }

    fn apply_canvas_tool_intents(&mut self, intents: Vec<CanvasToolIntent>) {
        for intent in intents {
            match intent {
                CanvasToolIntent::SelectTarget(target) => {
                    if let Err(error) = self.canvas_scene.select_target(target) {
                        self.canvas_status = format!("Pen selection failed: {error:?}");
                    } else {
                        self.canvas_status = format!(
                            "Selected {} stroke(s)",
                            self.canvas_scene
                                .selected_targets()
                                .map_or(0, |targets| targets.len())
                        );
                    }
                }
                CanvasToolIntent::SelectRegion(rect) => {
                    if let Err(error) = self.canvas_scene.select_region(self.canvas_viewport, rect)
                    {
                        self.canvas_status = format!("Pen region selection failed: {error:?}");
                    } else {
                        self.canvas_status = format!(
                            "Selected {} stroke(s)",
                            self.canvas_scene
                                .selected_targets()
                                .map_or(0, |targets| targets.len())
                        );
                    }
                }
                CanvasToolIntent::Edit(command) => {
                    let label = match &command {
                        EditCommand::Tombstone { .. } => "Pen eraser",
                        EditCommand::Move { .. } => "Pen move",
                        _ => "Pen canvas edit",
                    };
                    self.submit_project_edit(command, label);
                }
            }
        }
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }

    fn queue_selected_move_from_view(&mut self, delta_client_x: f64, delta_client_y: f64) {
        let targets = match self.canvas_scene.selected_targets() {
            Ok(targets) => targets,
            Err(error) => {
                self.canvas_status = format!("Move selection failed: {error:?}");
                return;
            }
        };
        let [target] = targets.as_slice() else {
            self.canvas_status = if targets.is_empty() {
                "Select one stroke before moving it".to_owned()
            } else {
                "Move currently supports one selected stroke at a time".to_owned()
            };
            return;
        };
        let (delta_x_raw, delta_y_raw) = match self.canvas_scene.raw_move_delta_from_view_drag(
            target,
            self.canvas_viewport,
            delta_client_x,
            delta_client_y,
        ) {
            Ok(delta) => delta,
            Err(error) => {
                self.canvas_status = format!("Move rejected: {error:?}");
                return;
            }
        };
        self.submit_project_edit(
            EditCommand::Move {
                target: target.clone(),
                delta_x_raw,
                delta_y_raw,
                coordinate_space: "windows-screen-coordinates".to_owned(),
                units: "screen-pixel".to_owned(),
            },
            "Move",
        );
    }

    fn handle_canvas_key(&mut self, event: &winit::event::KeyEvent) {
        if event.state != ElementState::Pressed || event.repeat {
            return;
        }
        match event.physical_key {
            PhysicalKey::Code(KeyCode::F1) => self.set_canvas_tool(CanvasTool::Pen),
            PhysicalKey::Code(KeyCode::F2) => self.set_canvas_tool(CanvasTool::Eraser),
            PhysicalKey::Code(KeyCode::F3) => self.set_canvas_tool(CanvasTool::Select),
            PhysicalKey::Code(KeyCode::KeyZ) if self.canvas_modifiers.control_key() => {
                self.submit_project_undo_redo(false, "Undo")
            }
            PhysicalKey::Code(KeyCode::KeyY) if self.canvas_modifiers.control_key() => {
                self.submit_project_undo_redo(true, "Redo")
            }
            PhysicalKey::Code(KeyCode::F5) => self.submit_project_undo_redo(false, "Undo"),
            PhysicalKey::Code(KeyCode::F6) => self.submit_project_undo_redo(true, "Redo"),
            PhysicalKey::Code(KeyCode::ArrowLeft) => self.queue_selected_move_from_view(-10.0, 0.0),
            PhysicalKey::Code(KeyCode::ArrowRight) => self.queue_selected_move_from_view(10.0, 0.0),
            PhysicalKey::Code(KeyCode::ArrowUp) => self.queue_selected_move_from_view(0.0, -10.0),
            PhysicalKey::Code(KeyCode::ArrowDown) => self.queue_selected_move_from_view(0.0, 10.0),
            PhysicalKey::Code(KeyCode::F4) | PhysicalKey::Code(KeyCode::Enter) => {
                self.canvas_status =
                    "Convert unavailable: no recognition provider is configured".to_owned();
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
            }
            PhysicalKey::Code(KeyCode::Delete | KeyCode::Backspace) => {
                match self.canvas_scene.tombstone_selected_command() {
                    Ok(Some(command)) => {
                        self.submit_project_edit(command, "Erase");
                    }
                    Ok(None) => self.canvas_status = "No strokes are selected".to_owned(),
                    Err(error) => self.canvas_status = format!("Erase selection failed: {error:?}"),
                }
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
            }
            _ => {}
        }
    }

    fn handle_canvas_mouse_button(&mut self, button: MouseButton, state: ElementState) {
        if matches!(button, MouseButton::Middle | MouseButton::Right) {
            if state == ElementState::Pressed {
                self.canvas_pan_drag_last = self.canvas_cursor_client;
            } else {
                self.canvas_pan_drag_last = None;
            }
            return;
        }
        if button != MouseButton::Left {
            return;
        }
        let Some(cursor) = self.canvas_cursor_client else {
            return;
        };
        match (self.canvas_scene.tool(), state) {
            (CanvasTool::Select, ElementState::Pressed) => {
                match self
                    .canvas_scene
                    .hit_test(self.canvas_viewport, cursor.0, cursor.1, 10.0)
                {
                    Ok(Some(target)) => {
                        let was_selected = self
                            .canvas_scene
                            .selected_targets()
                            .is_ok_and(|targets| targets.len() == 1 && targets[0] == target);
                        if !was_selected {
                            let _ = self.canvas_scene.select_target(Some(target));
                        }
                        self.canvas_move_drag_start = Some(cursor);
                        self.canvas_selection_drag_start = None;
                        self.canvas_scene.set_selection_rect(None);
                    }
                    Ok(None) => {
                        let _ = self.canvas_scene.select_target(None);
                        self.canvas_move_drag_start = None;
                        self.canvas_selection_drag_start = Some(cursor);
                        self.canvas_scene
                            .set_selection_rect(CanvasRect::normalized(cursor, cursor).ok());
                    }
                    Err(error) => {
                        self.canvas_status = format!("Selection hit test failed: {error:?}")
                    }
                }
            }
            (CanvasTool::Select, ElementState::Released) => {
                if let Some(start) = self.canvas_move_drag_start.take() {
                    let delta_x = cursor.0 - start.0;
                    let delta_y = cursor.1 - start.1;
                    if delta_x != 0.0 || delta_y != 0.0 {
                        self.queue_selected_move_from_view(delta_x, delta_y);
                    }
                } else if let Some(start) = self.canvas_selection_drag_start.take() {
                    match CanvasRect::normalized(start, cursor).and_then(|rect| {
                        self.canvas_scene
                            .select_region(self.canvas_viewport, rect)
                            .map(|()| rect)
                    }) {
                        Ok(_) => {
                            self.canvas_status = format!(
                                "Selected {} stroke(s)",
                                self.canvas_scene
                                    .selected_targets()
                                    .map_or(0, |targets| targets.len())
                            )
                        }
                        Err(error) => self.canvas_status = format!("Selection failed: {error:?}"),
                    }
                }
                self.canvas_scene.set_selection_rect(None);
            }
            (CanvasTool::Eraser, ElementState::Pressed) => {
                match self
                    .canvas_scene
                    .hit_test(self.canvas_viewport, cursor.0, cursor.1, 10.0)
                {
                    Ok(target) => {
                        let count = usize::from(target.is_some());
                        if let Err(error) = self.canvas_scene.select_target(target) {
                            self.canvas_status = format!("Eraser selection failed: {error:?}");
                        } else {
                            self.canvas_status = if count == 1 {
                                "Stroke selected; press Delete to append an erase action".to_owned()
                            } else {
                                "No stroke found under eraser".to_owned()
                            };
                        }
                    }
                    Err(error) => self.canvas_status = format!("Eraser hit test failed: {error:?}"),
                }
            }
            (CanvasTool::Pen, ElementState::Pressed) => {
                self.canvas_status =
                    "Mouse drawing disabled; no pen-to-mouse fallback is used".to_owned();
            }
            _ => {}
        }
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }

    fn record_application_lifecycle(
        &self,
        kind: LifecycleEventKind,
        device_id_debug: Option<String>,
        wait_start_elapsed_ns: Option<u128>,
        requested_resume_elapsed_ns: Option<u128>,
        wake_lateness_ns: Option<u128>,
    ) {
        self.probe_state
            .borrow_mut()
            .record(ProbeRecord::Lifecycle(LifecycleEventRecord {
                source: CaptureSource::ApplicationLifecycle,
                kind,
                app_observed_elapsed_ns: self.app_clock_origin.elapsed().as_nanos(),
                message_id_raw: None,
                message_hwnd_raw_session_scoped: self.window.as_ref().and_then(raw_window_hwnd),
                wparam_raw: None,
                lparam_raw: None,
                native_message_time_ms_raw: None,
                pointer_id_raw: None,
                winit_device_id_debug: device_id_debug,
                event_loop_wait_start_elapsed_ns: wait_start_elapsed_ns,
                event_loop_requested_resume_elapsed_ns: requested_resume_elapsed_ns,
                event_loop_wake_lateness_ns: wake_lateness_ns,
                controlled_stall_duration_ns: None,
                issue_debug: None,
            }));
    }

    fn record_controlled_stall(&self, kind: LifecycleEventKind, duration_ns: u128) {
        self.probe_state
            .borrow_mut()
            .record(ProbeRecord::Lifecycle(LifecycleEventRecord {
                source: CaptureSource::ApplicationLifecycle,
                kind,
                app_observed_elapsed_ns: self.app_clock_origin.elapsed().as_nanos(),
                message_id_raw: None,
                message_hwnd_raw_session_scoped: self.window.as_ref().and_then(raw_window_hwnd),
                wparam_raw: None,
                lparam_raw: None,
                native_message_time_ms_raw: None,
                pointer_id_raw: None,
                winit_device_id_debug: None,
                event_loop_wait_start_elapsed_ns: None,
                event_loop_requested_resume_elapsed_ns: None,
                event_loop_wake_lateness_ns: None,
                controlled_stall_duration_ns: Some(duration_ns),
                issue_debug: None,
            }));
    }

    fn record_lifecycle_issue(&self, kind: LifecycleEventKind, issue_debug: String) {
        self.probe_state
            .borrow_mut()
            .record(ProbeRecord::Lifecycle(LifecycleEventRecord {
                source: CaptureSource::ApplicationLifecycle,
                kind,
                app_observed_elapsed_ns: self.app_clock_origin.elapsed().as_nanos(),
                message_id_raw: None,
                message_hwnd_raw_session_scoped: self.window.as_ref().and_then(raw_window_hwnd),
                wparam_raw: None,
                lparam_raw: None,
                native_message_time_ms_raw: None,
                pointer_id_raw: None,
                winit_device_id_debug: None,
                event_loop_wait_start_elapsed_ns: None,
                event_loop_requested_resume_elapsed_ns: None,
                event_loop_wake_lateness_ns: None,
                controlled_stall_duration_ns: None,
                issue_debug: Some(issue_debug),
            }));
    }

    fn run_controlled_stall_if_requested(&mut self, event_loop: &ActiveEventLoop) -> bool {
        let Some(requested_ms) = self.controlled_stall.take_armed_once() else {
            return true;
        };
        let requested_ns = u128::from(requested_ms).saturating_mul(1_000_000);
        self.record_controlled_stall(LifecycleEventKind::ControlledStallStart, requested_ns);
        if !self.flush_pending_records() {
            self.stop_wintab_after_output_failure();
            event_loop.exit();
            return false;
        }
        let stall_start = Instant::now();
        std::thread::sleep(Duration::from_millis(requested_ms));
        let actual_ns = stall_start.elapsed().as_nanos();
        self.record_controlled_stall(LifecycleEventKind::ControlledStallEnd, actual_ns);
        true
    }

    fn flush_pending_records(&mut self) -> bool {
        if self.session_writer_failed {
            return false;
        }
        let result = {
            let state = self.probe_state.borrow();
            match self.session_writer.as_mut() {
                Some(writer) => writer.write_records(state.pending_records()),
                None => return false,
            }
        };
        match result {
            Ok(()) => {
                self.probe_state
                    .borrow_mut()
                    .clear_pending_records_after_write();
                self.pending_record_cursor.reset_after_buffer_clear();
                true
            }
            Err(error) => {
                self.session_writer_failed = true;
                self.probe_state
                    .borrow_mut()
                    .mark_session_output_failed(error.stage);
                self.startup_error = Some(format!("local session output failed: {error}"));
                eprintln!("{}", self.startup_error.as_deref().unwrap_or_default());
                false
            }
        }
    }

    fn write_runtime_metadata(&mut self) -> bool {
        let summary = self.probe_state.borrow().summary();
        let wintab = self.wintab.borrow();
        let wintab_status = wintab.status();
        let context_config = wintab.context_config_snapshot();
        let entries = [
            ("qpc_frequency_hz", opt_text(summary.qpc_frequency_hz)),
            (
                "qpc_frequency_issue",
                debug_opt_text(summary.qpc_frequency_issue),
            ),
            ("wintab_status_latest", format!("{wintab_status:?}")),
            (
                "wintab_packet_time_mode",
                debug_opt_text(summary.wintab_packet_time_mode),
            ),
            (
                "wintab_packet_data_mask_raw",
                opt_text(summary.wintab_configured_packet_data_raw),
            ),
            (
                "wintab_packet_mode_raw",
                opt_text(summary.wintab_configured_packet_mode_raw),
            ),
            (
                "wintab_queue_capacity_raw",
                opt_text(summary.wintab_queue_capacity_raw),
            ),
            (
                "wintab_context_config_latest_raw",
                debug_opt_text(context_config),
            ),
            (
                "retained_valid_direct_pen_samples",
                summary.valid_direct_pen_samples.to_string(),
            ),
            (
                "retained_validation_anomaly_samples",
                summary.validation_anomaly_samples.to_string(),
            ),
        ];
        let result = match self.session_writer.as_mut() {
            Some(writer) => entries
                .iter()
                .try_for_each(|(key, value)| writer.write_metadata(key, value)),
            None => return false,
        };
        match result {
            Ok(()) => true,
            Err(error) => {
                self.session_writer_failed = true;
                self.probe_state
                    .borrow_mut()
                    .mark_session_output_failed(error.stage);
                self.startup_error = Some(format!("local session metadata write failed: {error}"));
                false
            }
        }
    }

    fn record_public_window_event(&self, event: &WindowEvent) {
        let Some(window) = &self.window else {
            return;
        };
        let window_hwnd_raw_session_scoped = raw_window_hwnd(window);
        let app_observed_elapsed_ns = self.app_clock_origin.elapsed().as_nanos();
        let mut state = self.probe_state.borrow_mut();

        let event_fields = match event {
            WindowEvent::Touch(touch) => {
                let native =
                    state.public_touch_native_metadata(window_hwnd_raw_session_scoped, touch.id);
                Some((
                    PublicEventCapability::TouchPhasePositionForce,
                    native.message_association,
                    PublicWinitEventData::Touch {
                        winit_device_id: touch.device_id,
                        public_touch_id: touch.id,
                        phase: touch.phase,
                        x_physical_px: touch.location.x,
                        y_physical_px: touch.location.y,
                        public_winit_force: touch.force,
                        native_pointer_type_raw: native.native_pointer_type_raw,
                        pointer_type_error_raw: native.pointer_type_error_raw,
                        pen_classification: native.pen_classification,
                        native_timestamp_raw: None,
                        tilt: None,
                    },
                ))
            }
            WindowEvent::CursorMoved {
                device_id,
                position,
            } => Some((
                PublicEventCapability::CursorPosition,
                None,
                PublicWinitEventData::CursorMoved {
                    winit_device_id: *device_id,
                    x_physical_px: position.x,
                    y_physical_px: position.y,
                    native_timestamp_raw: None,
                },
            )),
            WindowEvent::MouseInput {
                device_id,
                state: button_state,
                button,
            } => Some((
                PublicEventCapability::MouseButton,
                None,
                PublicWinitEventData::MouseInput {
                    winit_device_id: *device_id,
                    state: *button_state,
                    button: *button,
                    native_timestamp_raw: None,
                },
            )),
            _ => None,
        };

        if let Some((capability, message_association, data)) = event_fields {
            let public_event_sequence = state.next_public_event_sequence();
            state.record(ProbeRecord::PublicWinitEvent(PublicWinitEventRecord {
                source: CaptureSource::PublicWinitWindowEvent,
                capability,
                public_event_sequence,
                app_observed_elapsed_ns,
                window_hwnd_raw_session_scoped,
                message_association,
                data,
            }));
            if self.capture_mode == CaptureMode::Wintab && !state.can_capture() {
                self.wintab
                    .borrow_mut()
                    .request_close_after_storage_limit(&mut state);
            }
        }
    }

    fn drain_wintab_control_notifications(&mut self) {
        loop {
            let notification = self
                .wintab_control_observer
                .as_ref()
                .and_then(WintabControlObserver::pop_pending);
            let Some(notification) = notification else {
                break;
            };
            let mut state = self.probe_state.borrow_mut();
            self.wintab
                .borrow_mut()
                .handle_control_notification(notification, &mut state);
        }

        let Some(observer) = self.wintab_control_observer.as_ref() else {
            return;
        };
        let hwnd = observer.hwnd_raw();
        let diagnostics = observer.take_diagnostics();
        if diagnostics.dropped_messages > 0 || diagnostics.callback_panics > 0 {
            let mut state = self.probe_state.borrow_mut();
            self.wintab
                .borrow_mut()
                .report_control_observer_diagnostics(hwnd, diagnostics, &mut state);
        }
        if let Some(observer) = self.wintab_control_observer.as_ref() {
            observer.clear_pending_if_idle(self.wintab.borrow().control_state_valid());
        }
    }

    fn process_durable_capture_records(&mut self, records: &[JournalRecord]) {
        for record in records {
            match &record.event {
                JournalEvent::StrokeInterrupted { target, reason, .. } => {
                    self.canvas_scene.discard_preview_stroke(target);
                    self.canvas_status =
                        format!("Stroke interrupted: {reason:?}; raw samples retained");
                }
                JournalEvent::EditAction {
                    command:
                        EditCommand::StrokeVisibility {
                            targets,
                            visible: true,
                        },
                    ..
                } => self.promote_committed_previews(targets),
                _ => {}
            }
        }
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }

    fn promote_committed_previews(&mut self, targets: &[journal::StrokeRef]) {
        for target in targets {
            if let Err(error) = self.canvas_scene.promote_preview_stroke(target) {
                self.project_incomplete_reason =
                    Some(format!("canvas commit projection error: {error:?}"));
                self.canvas_status = format!("CAPTURE INCOMPLETE: {error:?}");
            }
        }
    }

    fn drain_project_writer_acks(&mut self) {
        let Some(project_writer) = self.project_writer.as_mut() else {
            return;
        };
        let acknowledgements = project_writer.drain_acks();
        for acknowledgement in acknowledgements {
            match acknowledgement {
                ProjectWriterAck::CaptureCommitted { records, .. } => {
                    self.process_durable_capture_records(&records);
                }
                ProjectWriterAck::CaptureFailed { records, error, .. } => {
                    self.process_durable_capture_records(&records);
                    self.mark_project_incomplete(format!("project capture write failed: {error}"));
                }
                ProjectWriterAck::EditCommitted {
                    record, projection, ..
                } => {
                    if let JournalEvent::EditAction {
                        command:
                            EditCommand::StrokeVisibility {
                                targets,
                                visible: true,
                            },
                        ..
                    } = &record.event
                    {
                        self.promote_committed_previews(targets);
                    }
                    if let Err(error) = self.canvas_scene.refresh_from_journal(&projection) {
                        self.mark_project_incomplete(format!(
                            "canvas projection refresh failed: {error:?}"
                        ));
                    }
                    if let Some(window) = self.window.as_ref() {
                        window.request_redraw();
                    }
                }
                ProjectWriterAck::EditFailed { error, .. } => {
                    self.canvas_status = format!("Edit was not committed: {error}");
                    if let Some(window) = self.window.as_ref() {
                        window.request_redraw();
                    }
                }
                ProjectWriterAck::MetadataCommitted(_) => {}
                ProjectWriterAck::MetadataFailed(error) => {
                    self.mark_project_incomplete(format!("project metadata write failed: {error}"));
                }
                ProjectWriterAck::Finished(result) => {
                    if let Err(error) = result {
                        self.startup_error = Some(format!("project finalization failed: {error}"));
                    }
                }
            }
        }
    }

    fn mark_project_incomplete(&mut self, reason: String) {
        self.project_incomplete_reason
            .get_or_insert_with(|| reason.clone());
        self.canvas_status = format!("CAPTURE INCOMPLETE: {reason}");
        self.canvas_scene.discard_all_preview_strokes();
        self.canvas_tool_gesture_tracker.cancel_all();
        self.deferred_canvas_intents.clear();
        self.probe_state.borrow_mut().mark_project_incomplete();
        if self.capture_mode == CaptureMode::Wintab {
            let mut state = self.probe_state.borrow_mut();
            self.wintab
                .borrow_mut()
                .request_close_after_storage_limit(&mut state);
        }
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }

    fn apply_capture_preview_events(
        &mut self,
        events: &[DirectCaptureEvent],
    ) -> Result<(), canvas::CanvasError> {
        for event in events {
            match event {
                DirectCaptureEvent::StrokeStarted {
                    target, view_frame, ..
                } => self
                    .canvas_scene
                    .begin_preview_stroke(target.clone(), *view_frame)?,
                DirectCaptureEvent::PhysicalSample(sample) => {
                    self.canvas_scene.append_preview_sample(
                        sample,
                        &self.project_journal_id,
                        true,
                    )?;
                }
                DirectCaptureEvent::StrokeCommitRequested { .. } => {}
                DirectCaptureEvent::UnmatchedNativeUp { .. } => {}
                DirectCaptureEvent::StrokeInterrupted { target, reason, .. } => {
                    self.canvas_scene.discard_preview_stroke(target);
                    self.canvas_status =
                        format!("Stroke interrupted: {reason:?}; raw samples retained");
                }
            }
        }
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
        Ok(())
    }

    fn discard_preview_capture_events(&mut self, events: &[DirectCaptureEvent]) {
        for event in events {
            match event {
                DirectCaptureEvent::StrokeStarted { target, .. }
                | DirectCaptureEvent::StrokeInterrupted { target, .. }
                | DirectCaptureEvent::StrokeCommitRequested { target, .. } => {
                    self.canvas_scene.discard_preview_stroke(target);
                }
                DirectCaptureEvent::UnmatchedNativeUp { .. } => {}
                DirectCaptureEvent::PhysicalSample(sample) => {
                    if let Some(stroke_id) = sample.stroke_id.as_deref() {
                        let target = journal::StrokeRef {
                            journal_id: self.project_journal_id.clone(),
                            session_id: sample.session_id.clone(),
                            source_api: sample.source_api.clone(),
                            device_id: sample.source_device_id.clone(),
                            pointer_id: sample.pointer_id,
                            stroke_id: stroke_id.to_owned(),
                        };
                        self.canvas_scene.discard_preview_stroke(&target);
                    }
                }
            }
        }
    }

    fn enqueue_control_capture_events(
        &mut self,
        events: Vec<DirectCaptureEvent>,
    ) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        self.apply_capture_preview_events(&events)
            .map_err(|error| format!("could not update interruption preview: {error:?}"))?;
        if let Some((_, _, pending_events)) = self.deferred_capture_batch.as_mut() {
            pending_events
                .try_reserve(events.len())
                .map_err(|_| "could not retain a bounded pending interruption".to_owned())?;
            pending_events.extend(events);
            return Ok(());
        }
        if self.project_incomplete_reason.is_some() {
            return Err("project already stopped accepting capture".to_owned());
        }
        let batch_id = self
            .allocate_project_batch_id()
            .ok_or_else(|| "project command identifier exhausted".to_owned())?;
        let last_message_sequence = self.last_project_message_sequence;
        let result = self
            .project_writer
            .as_mut()
            .ok_or_else(|| "project writer is unavailable".to_owned())?
            .try_capture_batch(batch_id, events);
        match result {
            Ok(()) => Ok(()),
            Err(ProjectQueueError::Backpressure {
                batch_id,
                events,
                queued_samples,
            }) => {
                self.deferred_capture_batch = Some((batch_id, last_message_sequence, events));
                self.probe_state
                    .borrow_mut()
                    .mark_project_writer_backpressure(queued_samples, 8);
                self.project_incomplete_reason = Some(
                    "project writer backpressure: a view-change interruption is retained pending queue space"
                        .to_owned(),
                );
                self.canvas_status = self.project_incomplete_reason.clone().unwrap_or_default();
                Ok(())
            }
            Err(ProjectQueueError::Stopped { batch_id, events }) => {
                let omitted_samples = direct_capture_sample_count(&events);
                self.discard_preview_capture_events(&events);
                Err(format!(
                    "project writer stopped before interruption batch {batch_id} was accepted ({} events, {omitted_samples} samples)",
                    events.len()
                ))
            }
            Err(ProjectQueueError::QueueFull | ProjectQueueError::WorkerStopped) => {
                Err("project writer command queue is unavailable".to_owned())
            }
        }
    }

    fn interrupt_active_canvas_strokes(&mut self, reason: StrokeInterruptionReason) {
        let events = match self
            .direct_input_tracker
            .interrupt_active_strokes(reason, self.app_clock_origin.elapsed().as_nanos())
        {
            Ok(events) => events,
            Err(error) => {
                self.mark_project_incomplete(format!(
                    "could not represent view-change interruption: {error:?}"
                ));
                return;
            }
        };
        self.canvas_tool_gesture_tracker.cancel_all();
        if let Err(error) = self.enqueue_control_capture_events(events) {
            self.mark_project_incomplete(error);
        }
    }

    fn observe_canvas_window_frame(&mut self, scale_override: Option<f64>) {
        let Some(window) = self.window.as_ref() else {
            return;
        };
        let Some(origin) = raw_client_screen_origin(window) else {
            self.mark_project_incomplete(
                "could not map the live client origin to screen pixels".to_owned(),
            );
            return;
        };
        let scale = scale_override.unwrap_or_else(|| window.scale_factor());
        if !scale.is_finite() || scale <= 0.0 {
            self.mark_project_incomplete("window reported an invalid DPI scale factor".to_owned());
            return;
        }
        let changed = self
            .canvas_origin
            .is_some_and(|previous| previous != origin)
            || self.canvas_dpi_scale_factor.to_bits() != scale.to_bits();
        if changed {
            self.interrupt_active_canvas_strokes(
                StrokeInterruptionReason::CanvasViewTransformChanged,
            );
        }
        self.canvas_origin = Some(origin);
        self.canvas_dpi_scale_factor = scale;
    }

    fn try_send_deferred_capture_batch(&mut self) {
        let Some((batch_id, last_message_sequence, events)) = self.deferred_capture_batch.take()
        else {
            return;
        };
        let Some(project_writer) = self.project_writer.as_mut() else {
            let omitted_samples = direct_capture_sample_count(&events);
            self.mark_project_incomplete(format!(
                "project writer unavailable; deferred batch {batch_id} had {} events and {omitted_samples} samples not accepted",
                events.len()
            ));
            return;
        };
        let result = project_writer.try_capture_batch(batch_id, events);
        match result {
            Ok(()) => {
                self.last_project_message_sequence = last_message_sequence;
                let intents = std::mem::take(&mut self.deferred_canvas_intents);
                self.apply_canvas_tool_intents(intents);
            }
            Err(ProjectQueueError::Backpressure {
                batch_id,
                events,
                queued_samples,
            }) => {
                self.deferred_capture_batch = Some((batch_id, last_message_sequence, events));
                self.probe_state
                    .borrow_mut()
                    .mark_project_writer_backpressure(queued_samples, 8);
                self.project_incomplete_reason.get_or_insert_with(|| {
                    "project writer queue saturated; capture stopped with a bounded pending batch"
                        .to_owned()
                });
                self.canvas_status = self.project_incomplete_reason.clone().unwrap_or_default();
            }
            Err(ProjectQueueError::Stopped {
                batch_id: stopped_batch_id,
                events,
            }) => {
                let omitted_samples = direct_capture_sample_count(&events);
                self.mark_project_incomplete(format!(
                    "project writer stopped before queued batch {stopped_batch_id} committed; {} events and {omitted_samples} samples remain unwritten",
                    events.len()
                ));
            }
            Err(ProjectQueueError::QueueFull | ProjectQueueError::WorkerStopped) => {
                self.mark_project_incomplete(
                    "project writer command queue is unavailable".to_owned(),
                );
            }
        }
    }

    fn process_pending_project_capture(&mut self) {
        self.drain_project_writer_acks();
        if self.deferred_capture_batch.is_some() {
            self.try_send_deferred_capture_batch();
            return;
        }
        if self.project_incomplete_reason.is_some() {
            return;
        }

        if self.project_writer.is_none() {
            self.mark_project_incomplete("project writer is unavailable for capture".to_owned());
            return;
        }

        let pending_len = self.probe_state.borrow().pending_records().len();
        let new_range = self.pending_record_cursor.take_new_range(pending_len);
        if new_range.is_empty() {
            return;
        }

        let mut events = Vec::new();
        let mut tool_intents = Vec::new();
        let mut last_message_sequence = self.last_project_message_sequence;
        let mut conversion_error = None;
        {
            let state = self.probe_state.borrow();
            for record in &state.pending_records()[new_range] {
                match record {
                    ProbeRecord::DirectPenHistory(batch)
                        if self.capture_mode == CaptureMode::DirectWmPointer
                            && batch.message_sequence > self.last_project_message_sequence =>
                    {
                        let view_frame = match self.current_stroke_view_frame() {
                            Ok(frame) => frame,
                            Err(error) => {
                                conversion_error = Some(error);
                                break;
                            }
                        };
                        let converted = if self.canvas_scene.tool() == CanvasTool::Pen {
                            self.direct_input_tracker
                                .direct_batch_to_events(
                                    batch,
                                    &self.project_journal_id,
                                    &self.active_session_id,
                                    Some(&self.active_config_id),
                                    view_frame,
                                )
                                .map(|events| (events, None))
                        } else {
                            self.canvas_tool_gesture_tracker
                                .direct_batch_to_tool_events(
                                    self.canvas_scene.tool(),
                                    batch,
                                    CanvasToolCaptureContext {
                                        session_id: &self.active_session_id,
                                        config_id: Some(&self.active_config_id),
                                        view_frame,
                                        scene: &self.canvas_scene,
                                        viewport: self.canvas_viewport,
                                    },
                                )
                        };
                        match converted {
                            Ok(converted) => {
                                let (mut converted_events, intent) = converted;
                                if events.try_reserve(converted_events.len()).is_err() {
                                    conversion_error =
                                        Some("capture event allocation failed".to_owned());
                                    break;
                                }
                                events.append(&mut converted_events);
                                if let Some(intent) = intent {
                                    if tool_intents.try_reserve(1).is_err() {
                                        conversion_error =
                                            Some("canvas tool intent allocation failed".to_owned());
                                        break;
                                    }
                                    tool_intents.push(intent);
                                }
                                last_message_sequence = batch.message_sequence;
                            }
                            Err(error) => {
                                conversion_error =
                                    Some(format!("capture conversion failed: {error:?}"));
                                break;
                            }
                        }
                    }
                    ProbeRecord::Lifecycle(record)
                        if record.source == CaptureSource::DirectWin32Lifecycle
                            || record.kind == LifecycleEventKind::WindowFocusLost =>
                    {
                        self.canvas_tool_gesture_tracker
                            .cancel_pointer_id(record.pointer_id_raw);
                        match self.direct_input_tracker.on_direct_lifecycle(
                            record.kind,
                            record.pointer_id_raw,
                            record.app_observed_elapsed_ns,
                        ) {
                            Ok(mut converted) => {
                                if events.try_reserve(converted.len()).is_err() {
                                    conversion_error =
                                        Some("lifecycle event allocation failed".to_owned());
                                    break;
                                }
                                events.append(&mut converted);
                            }
                            Err(error) => {
                                conversion_error = Some(format!(
                                    "stroke interruption allocation failed: {error:?}"
                                ));
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(error) = conversion_error {
            self.mark_project_incomplete(error);
            return;
        }
        if events.is_empty() {
            self.last_project_message_sequence = last_message_sequence;
            self.apply_canvas_tool_intents(tool_intents);
            return;
        }
        if let Err(error) = self.apply_capture_preview_events(&events) {
            self.mark_project_incomplete(format!("canvas preview update failed: {error:?}"));
            return;
        }
        let batch_id = self.next_project_batch_id;
        let Some(next_batch_id) = self.next_project_batch_id.checked_add(1) else {
            self.mark_project_incomplete("project capture batch identifier exhausted".to_owned());
            return;
        };
        self.next_project_batch_id = next_batch_id;
        let result = self
            .project_writer
            .as_mut()
            .expect("project writer presence checked")
            .try_capture_batch(batch_id, events);
        match result {
            Ok(()) => {
                self.last_project_message_sequence = last_message_sequence;
                self.apply_canvas_tool_intents(tool_intents);
            }
            Err(ProjectQueueError::Backpressure {
                batch_id,
                events,
                queued_samples,
            }) => {
                self.deferred_capture_batch = Some((batch_id, last_message_sequence, events));
                self.deferred_canvas_intents = tool_intents;
                self.probe_state
                    .borrow_mut()
                    .mark_project_writer_backpressure(queued_samples, 8);
                self.project_incomplete_reason = Some(
                    "project writer backpressure: input capture stopped and pending batch retained"
                        .to_owned(),
                );
                self.canvas_status = self.project_incomplete_reason.clone().unwrap_or_default();
            }
            Err(ProjectQueueError::Stopped {
                batch_id: stopped_batch_id,
                events,
            }) => {
                let omitted_samples = direct_capture_sample_count(&events);
                self.discard_preview_capture_events(&events);
                self.deferred_canvas_intents.clear();
                self.mark_project_incomplete(format!(
                    "project writer stopped during capture; batch {stopped_batch_id} had {} events and {omitted_samples} samples not accepted",
                    events.len()
                ));
            }
            Err(ProjectQueueError::QueueFull | ProjectQueueError::WorkerStopped) => {
                self.mark_project_incomplete(
                    "project writer command queue is unavailable".to_owned(),
                );
            }
        }
    }

    fn finish_project_writer(&mut self) -> Result<(), String> {
        self.process_pending_project_capture();
        let unfinished_direct_strokes = self.direct_input_tracker.active_stroke_count();
        if unfinished_direct_strokes > 0 {
            self.mark_project_incomplete(format!(
                "process shutdown with {unfinished_direct_strokes} direct stroke(s) lacking an observed native up; raw rows will be retained without a commit"
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.deferred_capture_batch.is_some() && Instant::now() < deadline {
            self.drain_project_writer_acks();
            self.try_send_deferred_capture_batch();
            if self.deferred_capture_batch.is_some() {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        if let Some((batch_id, _, events)) = self.deferred_capture_batch.take() {
            let omitted_samples = direct_capture_sample_count(&events);
            let reason = format!(
                "shutdown timeout left capture batch {batch_id} unwritten ({} events, {omitted_samples} samples)",
                events.len()
            );
            self.mark_project_incomplete(reason);
        }
        let writer = self
            .project_writer
            .take()
            .ok_or_else(|| "project writer was already stopped".to_owned())?;
        let finalization_reason = match (
            self.project_incomplete_reason.clone(),
            self.project_recovery_note.clone(),
        ) {
            (Some(incomplete), Some(recovery)) => {
                Some(format!("{incomplete}; recovery: {recovery}"))
            }
            (Some(incomplete), None) => Some(incomplete),
            (None, Some(recovery)) => Some(recovery),
            (None, None) => None,
        };
        writer.finish(
            self.app_clock_origin.elapsed().as_nanos(),
            finalization_reason,
        )
    }

    fn stop_wintab_after_output_failure(&mut self) {
        if self.capture_mode != CaptureMode::Wintab || self.wintab.borrow().close_requested() {
            return;
        }
        let mut state = self.probe_state.borrow_mut();
        self.wintab
            .borrow_mut()
            .request_close_after_storage_limit(&mut state);
        self.wintab
            .borrow_mut()
            .close_after_stop_request(&mut state);
        drop(state);
        self.drain_wintab_control_notifications();
    }

    fn current_stroke_view_frame(&self) -> Result<StrokeViewFrame, String> {
        let origin = self
            .canvas_origin
            .ok_or_else(|| "client screen origin has not been established".to_owned())?;
        self.canvas_viewport
            .stroke_view_frame(origin, self.canvas_dpi_scale_factor)
            .map_err(|error| format!("invalid current canvas transform: {error:?}"))
    }
}

fn raw_window_hwnd(window: &Window) -> Option<isize> {
    let handle = window.window_handle().ok()?;
    match handle.as_raw() {
        RawWindowHandle::Win32(handle) => Some(handle.hwnd.get()),
        _ => None,
    }
}

fn raw_client_screen_origin(window: &Window) -> Option<CanvasOrigin> {
    let hwnd = raw_window_hwnd(window)? as windows_sys::Win32::Foundation::HWND;
    let mut origin = windows_sys::Win32::Foundation::POINT { x: 0, y: 0 };
    // SAFETY: hwnd is the live Winit Win32 window, and origin is valid
    // writable POINT storage. The result is an exact client-to-screen offset.
    if unsafe { windows_sys::Win32::Graphics::Gdi::ClientToScreen(hwnd, &mut origin) } == 0 {
        return None;
    }
    Some(CanvasOrigin {
        x_screen_px: i64::from(origin.x),
        y_screen_px: i64::from(origin.y),
    })
}

fn direct_capture_sample_count(events: &[DirectCaptureEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, DirectCaptureEvent::PhysicalSample(_)))
        .count()
}

fn capture_state(summary: ProbeSummary) -> String {
    if summary.storage_limit.is_some() {
        return match summary.storage_limit {
            Some(StorageLimit::Records) => "CAPTURE INCOMPLETE: record cap reached".to_owned(),
            Some(StorageLimit::Samples) => "CAPTURE INCOMPLETE: sample cap reached".to_owned(),
            Some(StorageLimit::NativeHistory) => {
                "CAPTURE INCOMPLETE: per-history native cap exceeded".to_owned()
            }
            Some(StorageLimit::Allocation) => {
                "CAPTURE INCOMPLETE: record allocation failed".to_owned()
            }
            Some(StorageLimit::SessionOutput) => {
                "CAPTURE INCOMPLETE: local session output failed".to_owned()
            }
            Some(StorageLimit::ProjectWriter) => {
                "CAPTURE INCOMPLETE: project writer backpressure".to_owned()
            }
            Some(StorageLimit::ProjectIncomplete) => {
                "CAPTURE INCOMPLETE: project or canvas failure".to_owned()
            }
            Some(StorageLimit::Multiple) => "CAPTURE INCOMPLETE: multiple caps reached".to_owned(),
            None => unreachable!(),
        };
    }

    if summary.capture_mode == CaptureMode::Wintab {
        return match summary.wintab_status {
            WintabStatus::NotSelected => "CAPTURE UNAVAILABLE: Wintab mode not selected".to_owned(),
            WintabStatus::Loading => "Wintab context initializing; no fallback selected".to_owned(),
            WintabStatus::Available => {
                "Wintab context open; CT430 compatibility unverified".to_owned()
            }
            WintabStatus::Partial => {
                "WINTAB PARTIAL: inspect issue/queue; CT430 compatibility unverified".to_owned()
            }
            WintabStatus::Unavailable => {
                format!(
                    "CAPTURE UNAVAILABLE: Wintab ({:?})",
                    summary.latest_wintab_issue
                )
            }
        };
    }

    if !summary.pointer_api_available {
        return match summary.pointer_api_issue {
            Some(issue) => format!("CAPTURE UNAVAILABLE: {issue:?}"),
            None => "CAPTURE UNAVAILABLE: pointer API status not established".to_owned(),
        };
    }

    match summary.storage_limit {
        Some(StorageLimit::Records) => "CAPTURE INCOMPLETE: record cap reached".to_owned(),
        Some(StorageLimit::Samples) => "CAPTURE INCOMPLETE: sample cap reached".to_owned(),
        Some(StorageLimit::NativeHistory) => {
            "CAPTURE INCOMPLETE: per-history native cap exceeded".to_owned()
        }
        Some(StorageLimit::Allocation) => "CAPTURE INCOMPLETE: record allocation failed".to_owned(),
        Some(StorageLimit::SessionOutput) => {
            "CAPTURE INCOMPLETE: local session output failed".to_owned()
        }
        Some(StorageLimit::ProjectWriter) => {
            "CAPTURE INCOMPLETE: project writer backpressure".to_owned()
        }
        Some(StorageLimit::ProjectIncomplete) => {
            "CAPTURE INCOMPLETE: project or canvas failure".to_owned()
        }
        Some(StorageLimit::Multiple) => "CAPTURE INCOMPLETE: multiple caps reached".to_owned(),
        None if summary.incomplete_batches > 0 => {
            format!(
                "CAPTURE INCOMPLETE: {} message batches",
                summary.incomplete_batches
            )
        }
        None => "in-memory capture active".to_owned(),
    }
}

fn timing_state(summary: ProbeSummary) -> String {
    if summary.capture_mode == CaptureMode::Wintab {
        return match summary.wintab_packet_time_mode {
            Some(WintabPacketTimeMode::AbsoluteSystemTime) => {
                "Wintab pkTime preserved as raw absolute system-time; app clock separate".to_owned()
            }
            Some(WintabPacketTimeMode::RelativeMilliseconds) => {
                "Wintab pkTime preserved as raw relative milliseconds; app clock separate"
                    .to_owned()
            }
            None => "Wintab packet time mode not established; app clock separate".to_owned(),
        };
    }

    match (summary.qpc_frequency_hz, summary.qpc_frequency_issue) {
        (Some(frequency), _) if summary.qpc_counter_failures > 0 => format!(
            "TIMING WARNING: QPC frequency {frequency} Hz; hook counter failed for {} batch(es)",
            summary.qpc_counter_failures
        ),
        (Some(frequency), _) => format!("QPC frequency {frequency} Hz"),
        (None, Some(issue)) => format!("TIMING WARNING: QPC frequency unavailable ({issue:?})"),
        (None, None) => "TIMING WARNING: QPC frequency not established".to_owned(),
    }
}

fn latest_startup_issue_label(summary: ProbeSummary) -> String {
    summary
        .latest_startup_issue
        .map(|issue| format!("{issue:?}"))
        .unwrap_or_else(|| "none".to_owned())
}

impl ApplicationHandler for ProbeApp {
    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        let now = Instant::now();
        let (wait_start, requested_resume) = match cause {
            StartCause::ResumeTimeReached {
                start,
                requested_resume,
            } => (Some(start), Some(requested_resume)),
            StartCause::WaitCancelled {
                start,
                requested_resume,
            } => (Some(start), requested_resume),
            StartCause::Init | StartCause::Poll => return,
        };
        let elapsed = |instant: Instant| {
            instant
                .checked_duration_since(self.app_clock_origin)
                .map(|duration| duration.as_nanos())
        };
        let wake_lateness_ns = requested_resume
            .and_then(|requested| now.checked_duration_since(requested))
            .map(|duration| duration.as_nanos());
        if !wake_lateness_ns.is_some_and(|lateness| lateness >= EVENT_LOOP_WAKE_MARKER_THRESHOLD_NS)
        {
            return;
        }
        self.record_application_lifecycle(
            LifecycleEventKind::EventLoopWake,
            None,
            wait_start.and_then(elapsed),
            requested_resume.and_then(elapsed),
            wake_lateness_ns,
        );
    }

    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        {
            let mut state = self.probe_state.borrow_mut();
            state.expire_public_dispatch_candidate();
            state.enter_winit_callback();
        }
        if self.window.is_some() {
            self.probe_state.borrow_mut().leave_winit_callback();
            return;
        }

        let attributes = Window::default_attributes().with_title(STATUS);
        match event_loop.create_window(attributes) {
            Ok(window) => {
                let size = window.inner_size();
                self.client_size = Some((size.width, size.height));
                let hwnd = raw_window_hwnd(&window).unwrap_or(0);
                let dpi_scale_factor = window.scale_factor();
                self.window = Some(window);
                if let Some(origin) = self.window.as_ref().and_then(raw_client_screen_origin) {
                    self.canvas_origin = Some(origin);
                    self.canvas_dpi_scale_factor = dpi_scale_factor;
                    self.canvas_scene
                        .set_session_origin(&self.active_session_id, origin);
                    for (key, value) in [
                        ("canvas-origin-x-screen-px", origin.x_screen_px.to_string()),
                        ("canvas-origin-y-screen-px", origin.y_screen_px.to_string()),
                    ] {
                        let metadata = JournalMetadata {
                            scope: MetadataScope::Session,
                            scope_id: self.active_session_id.clone(),
                            source_api: None,
                            device_id: None,
                            key: key.to_owned(),
                            value,
                            provenance:
                                "Winit client origin mapped to screen pixels at session start"
                                    .to_owned(),
                            app_arrival_elapsed_ns: self.app_clock_origin.elapsed().as_nanos(),
                        };
                        let result = self
                            .project_writer
                            .as_mut()
                            .map(|writer| writer.try_metadata(metadata))
                            .unwrap_or(Err(ProjectQueueError::WorkerStopped));
                        if let Err(error) = result {
                            self.mark_project_incomplete(format!(
                                "could not queue canvas-origin metadata: {error:?}"
                            ));
                            break;
                        }
                    }
                }
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
                self.last_title = Some(STATUS.to_owned());
                self.last_title_update = Some(Instant::now());
                if self.capture_mode == CaptureMode::Wintab {
                    match WintabControlObserver::install(
                        hwnd,
                        WT_DEFBASE,
                        self.app_clock_origin,
                        Arc::clone(&self.wintab_control_pending),
                    ) {
                        Ok(observer) => {
                            self.wintab_control_observer = Some(observer);
                            self.wintab
                                .borrow_mut()
                                .open_context(hwnd, &mut self.probe_state.borrow_mut());
                            if let Some(message_base) = self.wintab.borrow().message_base_raw()
                                && let Some(observer) = self.wintab_control_observer.as_ref()
                            {
                                observer.set_message_base(message_base);
                            }
                            // WTOpen can synchronously send WT_CTXOPEN and the
                            // initial overlap notification. Drain those before
                            // returning to the queued message loop, so a valid
                            // first packet is not held behind the safety signal.
                            self.drain_wintab_control_notifications();
                            if self.wintab.borrow().close_requested() {
                                let mut state = self.probe_state.borrow_mut();
                                self.wintab
                                    .borrow_mut()
                                    .close_after_stop_request(&mut state);
                                drop(state);
                                self.drain_wintab_control_notifications();
                            }
                        }
                        Err(win32_error) => {
                            self.wintab
                                .borrow_mut()
                                .report_control_observer_install_failure(
                                    hwnd,
                                    win32_error,
                                    &mut self.probe_state.borrow_mut(),
                                );
                        }
                    }
                }
                println!("{STATUS}");
                println!("{NOT_IMPLEMENTED}");
                println!("{STORAGE_POLICY}");
                if !self.write_runtime_metadata() || !self.flush_pending_records() {
                    self.stop_wintab_after_output_failure();
                    event_loop.exit();
                }
            }
            Err(error) => {
                let message = format!("could not create the M1 diagnostic window: {error}");
                eprintln!("{message}");
                self.record_lifecycle_issue(
                    LifecycleEventKind::WindowInitializationFailed,
                    message.clone(),
                );
                self.startup_error = Some(message);
                event_loop.exit();
            }
        }
        self.probe_state.borrow_mut().leave_winit_callback();
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        self.probe_state.borrow_mut().enter_winit_callback();
        if self.window.as_ref().map(Window::id) != Some(window_id) {
            self.probe_state.borrow_mut().leave_winit_callback();
            return;
        }

        self.drain_wintab_control_notifications();
        self.process_pending_project_capture();

        self.record_public_window_event(&event);

        match event {
            WindowEvent::CloseRequested => {
                self.record_application_lifecycle(
                    LifecycleEventKind::WindowCloseRequested,
                    None,
                    None,
                    None,
                    None,
                );
                println!(
                    "M3 canvas closed; the local project journal will be flushed on shutdown."
                );
                event_loop.exit();
            }
            WindowEvent::Focused(focused) => {
                self.focused = Some(focused);
                if !focused {
                    self.canvas_tool_gesture_tracker.cancel_all();
                    let canceled = cancel_mouse_canvas_gestures(
                        &mut self.canvas_cursor_client,
                        &mut self.canvas_selection_drag_start,
                        &mut self.canvas_move_drag_start,
                        &mut self.canvas_pan_drag_last,
                    );
                    self.canvas_scene.set_selection_rect(None);
                    if canceled {
                        self.canvas_status =
                            "Mouse canvas drag canceled on focus loss; no edit was written"
                                .to_owned();
                    }
                }
                self.record_application_lifecycle(
                    if focused {
                        LifecycleEventKind::WindowFocusGained
                    } else {
                        LifecycleEventKind::WindowFocusLost
                    },
                    None,
                    None,
                    None,
                    None,
                );
                self.refresh_title();
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
                println!("window focus changed: {focused}");
            }
            WindowEvent::Resized(size) => {
                self.client_size = Some((size.width, size.height));
                self.observe_canvas_window_frame(None);
                self.refresh_title();
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
                println!("window resized: {}x{}", size.width, size.height);
            }
            WindowEvent::Moved(_) => {
                self.observe_canvas_window_frame(None);
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
            }
            WindowEvent::ScaleFactorChanged { scale_factor, .. } => {
                self.observe_canvas_window_frame(Some(scale_factor));
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
            }
            WindowEvent::RedrawRequested => {
                if let Some(window) = self.window.as_ref()
                    && let Err(error) = paint_gdi(
                        window,
                        &self.canvas_scene,
                        self.canvas_viewport,
                        &format!(
                            "{} | source {} (provisional; no fallback) | zoom {:.0}% pan {:.0},{:.0} | Ctrl+Z/Y undo/redo | arrows move selected",
                            self.canvas_status,
                            match self.capture_mode {
                                CaptureMode::DirectWmPointer => "Direct WM_POINTER",
                                CaptureMode::Wintab =>
                                    "explicit Wintab; canvas adapter unavailable",
                            },
                            self.canvas_viewport.zoom() * 100.0,
                            self.canvas_viewport.pan().0,
                            self.canvas_viewport.pan().1,
                        ),
                    )
                {
                    self.startup_error = Some(format!("canvas repaint failed: {error}"));
                    self.record_lifecycle_issue(
                        LifecycleEventKind::WindowInitializationFailed,
                        format!("canvas repaint failed: {error}"),
                    );
                }
            }
            WindowEvent::KeyboardInput { event, .. }
                if self.controlled_stall.observe_operator_key(
                    &event.physical_key,
                    event.state,
                    event.repeat,
                ) =>
            {
                println!(
                    "F9 accepted: starting the requested {} ms controlled UI stall during capture.",
                    self.controlled_stall.duration_ms.unwrap_or_default()
                );
                if !self.run_controlled_stall_if_requested(event_loop) {
                    self.probe_state.borrow_mut().leave_winit_callback();
                    return;
                }
            }
            WindowEvent::KeyboardInput { event, .. } => self.handle_canvas_key(&event),
            WindowEvent::ModifiersChanged(modifiers) => {
                self.canvas_modifiers = modifiers.state();
            }
            WindowEvent::CursorMoved { position, .. } => {
                let cursor = (position.x, position.y);
                self.canvas_cursor_client = Some(cursor);
                if let Some(last) = self.canvas_pan_drag_last {
                    if cursor != last {
                        self.interrupt_active_canvas_strokes(
                            StrokeInterruptionReason::CanvasViewTransformChanged,
                        );
                    }
                    if let Err(error) = self
                        .canvas_viewport
                        .pan_by(cursor.0 - last.0, cursor.1 - last.1)
                    {
                        self.canvas_status = format!("Pan failed: {error:?}");
                    }
                    self.canvas_pan_drag_last = Some(cursor);
                    if let Some(window) = self.window.as_ref() {
                        window.request_redraw();
                    }
                } else if self.canvas_move_drag_start.is_some() {
                    if let Some(window) = self.window.as_ref() {
                        window.request_redraw();
                    }
                } else if let Some(start) = self.canvas_selection_drag_start {
                    self.canvas_scene
                        .set_selection_rect(CanvasRect::normalized(start, cursor).ok());
                    if let Some(window) = self.window.as_ref() {
                        window.request_redraw();
                    }
                }
            }
            WindowEvent::CursorLeft { .. } => {
                self.canvas_cursor_client = None;
                self.canvas_pan_drag_last = None;
                self.canvas_selection_drag_start = None;
                if self.canvas_move_drag_start.take().is_some() {
                    self.canvas_status =
                        "Move cancelled when the cursor left the canvas; no edit was written"
                            .to_owned();
                }
                self.canvas_scene.set_selection_rect(None);
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                self.handle_canvas_mouse_button(button, state);
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let steps = match delta {
                    MouseScrollDelta::LineDelta(_, vertical) => f64::from(vertical),
                    MouseScrollDelta::PixelDelta(position) => position.y / 120.0,
                };
                if let Some((anchor_x, anchor_y)) = self.canvas_cursor_client {
                    self.interrupt_active_canvas_strokes(
                        StrokeInterruptionReason::CanvasViewTransformChanged,
                    );
                    if let Err(error) =
                        self.canvas_viewport
                            .zoom_about(anchor_x, anchor_y, 1.1_f64.powf(steps))
                    {
                        self.canvas_status = format!("Zoom failed: {error:?}");
                    }
                    if let Some(window) = self.window.as_ref() {
                        window.request_redraw();
                    }
                }
            }
            _ => {}
        }
        self.probe_state.borrow_mut().leave_winit_callback();
    }

    fn device_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        device_id: winit::event::DeviceId,
        event: DeviceEvent,
    ) {
        self.probe_state.borrow_mut().enter_winit_callback();
        match event {
            DeviceEvent::Added => self.record_application_lifecycle(
                LifecycleEventKind::InputDeviceAdded,
                Some(format!("{device_id:?}")),
                None,
                None,
                None,
            ),
            DeviceEvent::Removed => self.record_application_lifecycle(
                LifecycleEventKind::InputDeviceRemoved,
                Some(format!("{device_id:?}")),
                None,
                None,
                None,
            ),
            _ => {}
        }
        self.probe_state.borrow_mut().leave_winit_callback();
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        self.process_pending_project_capture();
        {
            let mut state = self.probe_state.borrow_mut();
            state.expire_public_dispatch_candidate();
            state.enter_winit_callback();
            if self.capture_mode == CaptureMode::Wintab && !state.can_capture() {
                self.wintab
                    .borrow_mut()
                    .request_close_after_storage_limit(&mut state);
            }
        }
        self.drain_wintab_control_notifications();
        if self.capture_mode == CaptureMode::Wintab && self.wintab.borrow().close_requested() {
            let mut state = self.probe_state.borrow_mut();
            self.wintab
                .borrow_mut()
                .close_after_stop_request(&mut state);
        }
        self.drain_wintab_control_notifications();
        self.refresh_title();
        if let Some(last_update) = self.last_title_update {
            event_loop
                .set_control_flow(ControlFlow::WaitUntil(last_update + TITLE_REFRESH_INTERVAL));
        }
        if !self.flush_pending_records() {
            self.stop_wintab_after_output_failure();
            event_loop.exit();
        }
        self.probe_state.borrow_mut().leave_winit_callback();
    }
}

fn run_window(options: RunOptions) -> Result<(), Box<dyn Error>> {
    let capture_mode = options.capture_mode;
    let app_clock_origin = Instant::now();
    let session_started_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let active_session_id = format!("session-{session_started_unix_ns}-{}", process::id());
    let active_config_id = format!("config-{active_session_id}");
    let mut project_path = options.project_path.clone();
    let mut metadata = options.metadata;
    metadata.insert("session_id".to_owned(), active_session_id.clone());
    metadata.insert("schema_version".to_owned(), "3".to_owned());
    metadata.insert(
        "project_path".to_owned(),
        project_path.display().to_string(),
    );
    metadata.insert("app_name".to_owned(), "LassoInk minimal canvas".to_owned());
    metadata.insert(
        "app_version".to_owned(),
        env!("CARGO_PKG_VERSION").to_owned(),
    );
    metadata.insert(
        "capture_mode".to_owned(),
        capture_mode_label(capture_mode).to_owned(),
    );
    metadata.insert(
        "capture_mode_declared".to_owned(),
        match capture_mode {
            CaptureMode::DirectWmPointer => "direct",
            CaptureMode::Wintab => "wintab",
        }
        .to_owned(),
    );
    metadata.insert(
        "canvas_capture_source_status".to_owned(),
        match capture_mode {
            CaptureMode::DirectWmPointer => {
                "direct WM_POINTER provisionally selected; not a canonical source decision"
            }
            CaptureMode::Wintab => {
                "Wintab explicitly selected; canvas adapter unavailable and no fallback is used"
            }
        }
        .to_owned(),
    );
    metadata.insert(
        "device_model_declared".to_owned(),
        "XP-Pen Deco Fun XS / CT430 (owner-declared target)".to_owned(),
    );
    metadata.insert(
        "windows_ink_state_source".to_owned(),
        "owner declaration".to_owned(),
    );
    metadata.insert(
        "tablet_profile_source".to_owned(),
        "owner declaration".to_owned(),
    );
    metadata.insert(
        "runtime_os_family".to_owned(),
        std::env::consts::OS.to_owned(),
    );
    metadata.insert(
        "runtime_architecture".to_owned(),
        std::env::consts::ARCH.to_owned(),
    );
    metadata.insert("winit_version".to_owned(), "0.30.13".to_owned());
    metadata.insert("windows_sys_version".to_owned(), "0.52.0".to_owned());
    metadata.insert(
        "build_git_sha".to_owned(),
        env!("LASSOINK_BUILD_GIT_SHA").to_owned(),
    );
    metadata.insert(
        "build_tree_dirty".to_owned(),
        env!("LASSOINK_BUILD_TREE_DIRTY").to_owned(),
    );
    metadata.insert("build_id".to_owned(), env!("LASSOINK_BUILD_ID").to_owned());
    metadata.insert(
        "build_target".to_owned(),
        env!("LASSOINK_BUILD_TARGET").to_owned(),
    );
    metadata.insert(
        "build_profile".to_owned(),
        env!("LASSOINK_BUILD_PROFILE").to_owned(),
    );
    metadata.insert(
        "build_rustc".to_owned(),
        env!("LASSOINK_BUILD_RUSTC").to_owned(),
    );
    metadata.insert(
        "binary_sha256".to_owned(),
        std::env::var("LASSOINK_BINARY_SHA256")
            .unwrap_or_else(|_| "unknown;run through the owner runner for SHA256".to_owned()),
    );
    metadata.insert(
        "session_started_unix_ns".to_owned(),
        session_started_unix_ns.to_string(),
    );
    metadata.insert(
        "clock_contract".to_owned(),
        "PerformanceCount and hook QueryPerformanceCounter are same-QPC counts; age is message-receipt-to-hook only; dwTime, Wintab pkTime, and app Instant remain separate".to_owned(),
    );
    metadata.insert(
        "sample_validation_policy".to_owned(),
        "invalid type, pointer-ID attribution, missing pressure mask, or out-of-range pressure are excluded from valid direct pen metrics; raw rows remain".to_owned(),
    );
    metadata.insert(
        "dedup_policy".to_owned(),
        "raw rows are never removed; exact repeated history fingerprints are counted and skipped in derived direct QPC interval and pressure distribution metrics"
            .to_owned(),
    );
    metadata.insert("process_cpu_scope".to_owned(), PROCESS_CPU_SCOPE.to_owned());
    metadata.insert(
        "controlled_stall_trigger".to_owned(),
        "operator presses non-repeating F9 after the capture window is running; no startup pause"
            .to_owned(),
    );
    metadata.insert(
        "controlled_stall_requested_ms".to_owned(),
        options
            .controlled_stall_ms
            .map_or_else(|| "not-requested".to_owned(), |value| value.to_string()),
    );
    metadata.insert(
        "event_loop_wake_marker_threshold_ns".to_owned(),
        EVENT_LOOP_WAKE_MARKER_THRESHOLD_NS.to_string(),
    );
    metadata.insert(
        "hardware_gate_status".to_owned(),
        "DEFERRED / NOT PASSED; this software run does not establish CT430 fidelity".to_owned(),
    );
    let process_cpu_start = process_cpu_snapshot(app_clock_origin);

    let mut recovery_notes = Vec::new();
    let mut project = if options.open_project {
        let source = read_journal(&project_path)?;
        if source.schema_version != journal::JOURNAL_SCHEMA_VERSION {
            let source_path = project_path.clone();
            let source_schema_version = source.schema_version;
            project_path = schema_three_project_path(&source_path);
            let migration = match source_schema_version {
                1 => migrate_schema_one_to_three(&source_path, project_path.clone())?,
                2 => migrate_schema_two_to_three(&source_path, project_path.clone())?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "project journal schema is unsupported",
                    )
                    .into());
                }
            };
            if migration.source_truncated_final_record {
                recovery_notes.push(legacy_migration_recovery_note(
                    &source_path,
                    &project_path,
                    source_schema_version,
                ));
            }
        }
        JournalWriter::open_append(project_path.clone())?
    } else {
        let project_id = format!("project-{session_started_unix_ns}-{}", process::id());
        let initial_session_id = format!("project-initial-{project_id}");
        let header = JournalHeader {
            journal_id: project_id,
            session_id: initial_session_id,
            config_id: None,
            device_model_declared: metadata.get("device_model_declared").cloned(),
            tilt_supported_declared: Some(false),
        };
        JournalWriter::create(project_path.clone(), header)?
    };
    if project.recovered_truncated_final_record() {
        recovery_notes.push(active_project_recovery_note(&project_path));
    }
    let project_recovery_note = (!recovery_notes.is_empty()).then(|| recovery_notes.join("; "));
    metadata.insert(
        "project_path".to_owned(),
        project_path.display().to_string(),
    );
    metadata.insert(
        "project_recovery_note".to_owned(),
        project_recovery_note
            .clone()
            .unwrap_or_else(|| "none".to_owned()),
    );
    project.begin_session_epoch(
        active_session_id.clone(),
        session_started_unix_ns,
        Some(active_config_id.clone()),
        if options.open_project {
            "new process resumed an existing project; fresh Instant arrival epoch".to_owned()
        } else {
            "new process created a project; fresh Instant arrival epoch".to_owned()
        },
    )?;
    for (key, value) in &metadata {
        project.append_metadata(JournalMetadata {
            scope: MetadataScope::Session,
            scope_id: active_session_id.clone(),
            source_api: None,
            device_id: None,
            key: key.clone(),
            value: value.clone(),
            provenance: if key == "project_recovery_note" {
                "project parser/append recovery observation".to_owned()
            } else {
                "owner declaration or runtime build fact".to_owned()
            },
            app_arrival_elapsed_ns: 0,
        })?;
    }
    let incomplete_stroke_count = project.replay_state().incomplete_stroke_count();
    let historical_interrupted_strokes_at_start = project.replay_state().stroke_interruptions.len();
    let session_writer = SessionWriter::create(options.session_path.clone(), &metadata)?;
    let session_path = session_writer.path().to_path_buf();
    let project_journal_id = project.header().journal_id.clone();
    let canvas_scene = CanvasScene::from_journal(
        project.replay_state(),
        canvas::PROVISIONAL_DIRECT_SOURCE_API,
    )
    .map_err(|error| io::Error::other(format!("could not build project canvas: {error:?}")))?;
    let project_writer = ProjectWriterHandle::spawn(project)?;
    let probe_state = Rc::new(RefCell::new(ProbeState::default()));
    probe_state.borrow_mut().set_capture_mode(capture_mode);
    let wintab_capture = {
        let mut state = probe_state.borrow_mut();
        WintabCapture::new(capture_mode, app_clock_origin, &mut state)
    };
    let wintab = Rc::new(RefCell::new(wintab_capture));
    let wintab_control_pending = Arc::new(AtomicBool::new(false));
    let mut builder = EventLoop::builder();
    win32_pointer::install_message_hook(
        &mut builder,
        Rc::clone(&probe_state),
        capture_mode,
        Rc::clone(&wintab),
        app_clock_origin,
        Arc::clone(&wintab_control_pending),
    );
    let event_loop = builder.build()?;
    let mut app = ProbeApp {
        window: None,
        focused: None,
        client_size: None,
        last_title: None,
        last_title_update: None,
        startup_error: None,
        capture_mode,
        app_clock_origin,
        probe_state: Rc::clone(&probe_state),
        wintab: Rc::clone(&wintab),
        wintab_control_observer: None,
        wintab_control_pending,
        session_writer: Some(session_writer),
        session_path: session_path.clone(),
        session_writer_failed: false,
        project_writer: Some(project_writer),
        project_path: project_path.clone(),
        project_journal_id,
        active_session_id,
        active_config_id,
        direct_input_tracker: CanvasInputTracker::default(),
        canvas_tool_gesture_tracker: CanvasToolGestureTracker::default(),
        deferred_canvas_intents: Vec::new(),
        last_project_message_sequence: 0,
        pending_record_cursor: PendingRecordCursor::default(),
        next_project_batch_id: 1,
        deferred_capture_batch: None,
        project_incomplete_reason: None,
        project_recovery_note: project_recovery_note.clone(),
        historical_interrupted_strokes_at_start,
        controlled_stall: ControlledStallTrigger::new(options.controlled_stall_ms),
        canvas_scene,
        canvas_viewport: CanvasViewport::default(),
        canvas_origin: None,
        canvas_dpi_scale_factor: 1.0,
        canvas_cursor_client: None,
        canvas_modifiers: ModifiersState::empty(),
        canvas_selection_drag_start: None,
        canvas_move_drag_start: None,
        canvas_pan_drag_last: None,
        canvas_status: startup_canvas_status(
            project_recovery_note.as_deref(),
            incomplete_stroke_count,
        ),
    };
    let run_result = event_loop.run_app(&mut app);
    if let Err(error) = &run_result {
        let message = format!("Winit event loop failed: {error}");
        app.record_lifecycle_issue(LifecycleEventKind::EventLoopFailed, message.clone());
        app.startup_error.get_or_insert(message);
    }
    if capture_mode == CaptureMode::Wintab {
        app.drain_wintab_control_notifications();
    }
    wintab.borrow_mut().close(&mut probe_state.borrow_mut());
    if capture_mode == CaptureMode::Wintab {
        app.drain_wintab_control_notifications();
        if let Some(observer) = app.wintab_control_observer.as_mut() {
            let hwnd = observer.hwnd_raw();
            if let Err(win32_error) = observer.remove() {
                wintab.borrow_mut().report_control_observer_removal_failure(
                    hwnd,
                    win32_error,
                    &mut probe_state.borrow_mut(),
                );
                if let Err(retry_error) = observer.remove() {
                    wintab.borrow_mut().report_control_observer_removal_failure(
                        hwnd,
                        retry_error,
                        &mut probe_state.borrow_mut(),
                    );
                }
            }
        }
        app.drain_wintab_control_notifications();
    }
    if let Err(error) = app.finish_project_writer() {
        app.startup_error = Some(format!("project journal remains partial: {error}"));
    } else {
        println!("Local project journal: {}", app.project_path.display());
        if let Some(reason) = app.project_incomplete_reason.as_deref() {
            println!("Project finalization status: INCOMPLETE — {reason}");
        } else if app.historical_interrupted_strokes_at_start > 0 {
            println!(
                "Project finalization status: clean close with no active stroke; {} previously interrupted stroke(s) remain as raw history and are not rendered complete",
                app.historical_interrupted_strokes_at_start
            );
        }
        if let Some(note) = app.project_recovery_note.as_deref() {
            println!("Project recovery note: {note}");
        }
    }
    let mut output_ok = !app.session_writer_failed && app.flush_pending_records();
    if output_ok {
        output_ok = app.write_runtime_metadata() && app.flush_pending_records();
    }

    let mut finalized_path = None;
    if output_ok
        && probe_state.borrow().summary().storage_limit != Some(StorageLimit::SessionOutput)
        && let Some(writer) = app.session_writer.take()
    {
        let process_cpu_end = process_cpu_snapshot(app.app_clock_origin);
        let process_cpu_measurement = measure_process_cpu(process_cpu_start, process_cpu_end);
        match writer.finish(
            probe_state.borrow().summary(),
            app.app_clock_origin.elapsed().as_nanos(),
            process_cpu_measurement,
        ) {
            Ok(path) => finalized_path = Some(path),
            Err(error) => {
                probe_state
                    .borrow_mut()
                    .mark_session_output_failed(error.stage);
                app.startup_error = Some(format!("could not finalize local session: {error}"));
            }
        }
    }

    if let Some(path) = finalized_path {
        println!("Local session file: {}", path.display());
        match read_report(&path) {
            Ok(mut report) => print!("{}", report.format_text()),
            Err(error) => {
                let message =
                    format!("session was saved but its report could not be parsed: {error}");
                eprintln!("{message}");
                app.startup_error.get_or_insert(message);
            }
        }
    } else {
        eprintln!(
            "Session output remains partial at {}",
            app.session_path.display()
        );
    }

    run_result?;
    if capture_mode == CaptureMode::Wintab {
        let session = wintab.borrow();
        println!(
            "Wintab session ended: {:?}; latest issue {:?}",
            session.status(),
            session.latest_issue()
        );
    }

    if let Some(message) = app.startup_error {
        return Err(io::Error::other(message).into());
    }

    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if (arguments.len() == 3 || arguments.len() == 4) && arguments[0] == "--benchmark-batch" {
        return benchmark::run_batch_cli(
            Path::new(&arguments[1]),
            Path::new(&arguments[2]),
            arguments.get(3).map(Path::new),
        );
    }
    if arguments.len() == 1 && arguments[0] == "--help" {
        println!("LassoInk M3 minimal canvas with explicitly provisional capture diagnostics");
        println!("Usage: lassoink-capture-probe [options]");
        println!("  --capture-mode direct|wintab");
        println!("  --session-dir PATH | --session-path PATH");
        println!("  --project-path PATH | --open-project PATH");
        println!("  --trial-id ID --windows-ink on|off|unknown");
        println!("  --tablet-profile default|osu|unknown");
        println!("  --driver-version TEXT --active-area TEXT --mapped-display TEXT");
        println!("  --pressure-curve TEXT --windows-build TEXT");
        println!("  --controlled-stall-ms 1..30000 (press F9 once while capture is running)");
        println!("  --report PATH --help --version --status");
        println!("  --benchmark-batch CASES.json PROVIDERS.json [CORPUS-ANNOTATIONS.json]");
        println!(
            "Benchmark artifacts are local-only; never include credentials or private corpus data in Git."
        );
        println!("{STATUS}");
        println!("{NOT_IMPLEMENTED}");
        println!("{STORAGE_POLICY}");
        return Ok(());
    }
    if arguments.len() == 1 && arguments[0] == "--version" {
        println!(
            "lassoink-capture-probe {} (M3 minimal canvas; source {} dirty {}; build {} profile {} target {} rustc {})",
            env!("CARGO_PKG_VERSION"),
            env!("LASSOINK_BUILD_GIT_SHA"),
            env!("LASSOINK_BUILD_TREE_DIRTY"),
            env!("LASSOINK_BUILD_ID"),
            env!("LASSOINK_BUILD_PROFILE"),
            env!("LASSOINK_BUILD_TARGET"),
            env!("LASSOINK_BUILD_RUSTC")
        );
        return Ok(());
    }
    if arguments.len() == 1 && arguments[0] == "--status" {
        println!("{STATUS}");
        println!("{NOT_IMPLEMENTED}");
        println!("{STORAGE_POLICY}");
        println!("Default session directory: local_capture (ignored local data)");
        println!("Gate 0 hardware status: DEFERRED / NOT PASSED pending owner CT430 evidence.");
        return Ok(());
    }
    if arguments.len() == 2 && arguments[0] == "--report" {
        let mut report = read_report(Path::new(&arguments[1]))?;
        print!("{}", report.format_text());
        return Ok(());
    }
    run_window(parse_run_options(&arguments)?)
}

fn parse_run_options(arguments: &[String]) -> Result<RunOptions, io::Error> {
    let mut capture_mode = CaptureMode::DirectWmPointer;
    let mut session_directory = PathBuf::from("local_capture");
    let mut explicit_session_path = None;
    let mut explicit_project_path = None;
    let mut open_project = false;
    let mut metadata = BTreeMap::new();
    let mut controlled_stall_ms = None;
    let mut index = 0usize;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        index += 1;
        let value = |index: &mut usize| -> Result<String, io::Error> {
            let Some(value) = arguments.get(*index) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{flag} requires a value"),
                ));
            };
            *index += 1;
            Ok(value.clone())
        };
        match flag {
            "--capture-mode" => {
                capture_mode = match value(&mut index)?.as_str() {
                    "direct" => CaptureMode::DirectWmPointer,
                    "wintab" => CaptureMode::Wintab,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--capture-mode must be direct or wintab",
                        ));
                    }
                };
            }
            "--session-dir" => session_directory = PathBuf::from(value(&mut index)?),
            "--session-path" => explicit_session_path = Some(PathBuf::from(value(&mut index)?)),
            "--project-path" => {
                explicit_project_path = Some(PathBuf::from(value(&mut index)?));
                open_project = false;
            }
            "--open-project" => {
                explicit_project_path = Some(PathBuf::from(value(&mut index)?));
                open_project = true;
            }
            "--trial-id" => {
                metadata.insert("trial_id".to_owned(), value(&mut index)?);
            }
            "--windows-ink" => {
                let setting = value(&mut index)?;
                if !matches!(setting.as_str(), "on" | "off" | "unknown") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--windows-ink must be on, off, or unknown",
                    ));
                }
                metadata.insert("windows_ink_state_declared".to_owned(), setting);
            }
            "--tablet-profile" => {
                let profile = value(&mut index)?;
                if !matches!(profile.as_str(), "default" | "osu" | "unknown") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--tablet-profile must be default, osu, or unknown",
                    ));
                }
                metadata.insert("tablet_profile_declared".to_owned(), profile);
            }
            "--driver-version" => {
                metadata.insert(
                    "tablet_driver_version_declared".to_owned(),
                    value(&mut index)?,
                );
            }
            "--active-area" => {
                metadata.insert("active_area_declared".to_owned(), value(&mut index)?);
            }
            "--mapped-display" => {
                metadata.insert("mapped_display_declared".to_owned(), value(&mut index)?);
            }
            "--pressure-curve" => {
                metadata.insert("pressure_curve_declared".to_owned(), value(&mut index)?);
            }
            "--windows-build" => {
                metadata.insert("windows_build_reported".to_owned(), value(&mut index)?);
                metadata.insert(
                    "windows_build_source".to_owned(),
                    "runner registry or explicit CLI input".to_owned(),
                );
            }
            "--controlled-stall-ms" => {
                let stall = value(&mut index)?.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid stall duration")
                })?;
                if !(1..=30_000).contains(&stall) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "controlled stall must be between 1 and 30000 ms",
                    ));
                }
                controlled_stall_ms = Some(stall);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument {flag:?}; run with --help"),
                ));
            }
        }
    }

    let session_path =
        explicit_session_path.unwrap_or_else(|| default_session_path(&session_directory));
    let project_path =
        explicit_project_path.unwrap_or_else(|| default_project_path(&session_directory));
    Ok(RunOptions {
        capture_mode,
        session_path,
        project_path,
        open_project,
        metadata,
        controlled_stall_ms,
    })
}

fn default_project_path(directory: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    directory.join(format!("project-{timestamp}-{}.inkj", process::id()))
}

fn schema_three_project_path(source: &Path) -> PathBuf {
    let stem = source
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("project");
    source
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.schema3.inkj"))
}

fn legacy_migration_recovery_note(
    source_path: &Path,
    destination_path: &Path,
    source_schema_version: u32,
) -> String {
    format!(
        "legacy schema {source_schema_version} source {} ended in a torn final record; only its validated prefix was migrated to {}; selected source file remains unchanged",
        source_path.display(),
        destination_path.display()
    )
}

fn active_project_recovery_note(project_path: &Path) -> String {
    format!(
        "active schema-3 project {} ended in a torn final record; only the validated prefix was retained and the torn tail was truncated before append",
        project_path.display()
    )
}

fn project_recovery_status(note: &str) -> String {
    let legacy_source = note.contains("legacy schema");
    let active_project = note.contains("active schema-3 project");
    let summary = match (legacy_source, active_project) {
        (true, true) => {
            "PROJECT RECOVERY: truncated tails omitted; validated prefixes retained; legacy source unchanged."
        }
        (true, false) => {
            "PROJECT RECOVERY: only validated legacy prefix migrated; selected source unchanged."
        }
        (false, true) => {
            "PROJECT RECOVERY: only validated active-project prefix retained; torn tail removed."
        }
        (false, false) => "PROJECT RECOVERY: validated prefix used; see project metadata.",
    };
    format!("{summary} Details are recorded in project metadata.")
}

fn startup_canvas_status(recovery_note: Option<&str>, incomplete_strokes: usize) -> String {
    match (recovery_note, incomplete_strokes) {
        (Some(note), count) if count > 0 => format!(
            "{} | {count} interrupted/in-progress stroke(s) remain raw; lift before restarting",
            project_recovery_status(note)
        ),
        (Some(note), _) => project_recovery_status(note),
        (None, count) if count > 0 => format!(
            "{count} interrupted/in-progress stroke(s) remain as raw history and are not rendered complete; lift before restarting"
        ),
        (None, _) => "F1 pen | F2 eraser | F3 select | F4 Convert (unavailable)".to_owned(),
    }
}

fn capture_mode_label(mode: CaptureMode) -> &'static str {
    match mode {
        CaptureMode::DirectWmPointer => "direct-wm-pointer",
        CaptureMode::Wintab => "wintab",
    }
}

fn opt_text<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
}

fn debug_opt_text<T: std::fmt::Debug>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |value| format!("{value:?}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("lassoink-capture-probe: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod status_tests {
    use super::{capture_state, latest_startup_issue_label, timing_state};
    use crate::win32_pointer::{
        CaptureIssue, CaptureMode, NativeApi, ProbeSummary, StorageLimit, WintabPacketTimeMode,
        WintabStatus,
    };

    #[test]
    fn missing_pointer_apis_are_reported_as_capture_unavailable() {
        let summary = ProbeSummary {
            pointer_api_available: false,
            pointer_api_issue: Some(CaptureIssue::ApiUnavailable {
                api: NativeApi::GetPointerType,
                win32_error: 126,
            }),
            ..ProbeSummary::default()
        };

        assert!(capture_state(summary).starts_with("CAPTURE UNAVAILABLE:"));
        assert!(capture_state(summary).contains("GetPointerType"));
    }

    #[test]
    fn missing_qpc_frequency_is_a_timing_warning_without_blocking_capture() {
        let summary = ProbeSummary {
            pointer_api_available: true,
            qpc_frequency_issue: Some(CaptureIssue::QpcFrequencyUnavailable { win32_error: 5 }),
            latest_startup_issue: Some(CaptureIssue::QpcFrequencyUnavailable { win32_error: 5 }),
            ..ProbeSummary::default()
        };

        assert_eq!(capture_state(summary), "in-memory capture active");
        assert!(timing_state(summary).starts_with("TIMING WARNING:"));
        assert!(timing_state(summary).contains("QpcFrequencyUnavailable"));
        assert!(latest_startup_issue_label(summary).contains("QpcFrequencyUnavailable"));
    }

    #[test]
    fn unavailable_wintab_mode_does_not_report_direct_capture_as_fallback() {
        let summary = ProbeSummary {
            capture_mode: CaptureMode::Wintab,
            pointer_api_available: true,
            wintab_status: WintabStatus::Unavailable,
            ..ProbeSummary::default()
        };

        assert!(capture_state(summary).starts_with("CAPTURE UNAVAILABLE: Wintab"));
    }

    #[test]
    fn wintab_time_status_reports_configured_raw_domain() {
        let summary = ProbeSummary {
            capture_mode: CaptureMode::Wintab,
            wintab_status: WintabStatus::Available,
            wintab_packet_time_mode: Some(WintabPacketTimeMode::RelativeMilliseconds),
            ..ProbeSummary::default()
        };

        assert!(timing_state(summary).contains("raw relative milliseconds"));
        assert!(timing_state(summary).contains("app clock separate"));
    }

    #[test]
    fn project_incomplete_status_does_not_mislabel_non_backpressure_as_backpressure() {
        let incomplete = ProbeSummary {
            storage_limit: Some(StorageLimit::ProjectIncomplete),
            ..ProbeSummary::default()
        };
        assert_eq!(
            capture_state(incomplete),
            "CAPTURE INCOMPLETE: project or canvas failure"
        );
        let backpressure = ProbeSummary {
            storage_limit: Some(StorageLimit::ProjectWriter),
            ..ProbeSummary::default()
        };
        assert_eq!(
            capture_state(backpressure),
            "CAPTURE INCOMPLETE: project writer backpressure"
        );
    }
}

#[cfg(test)]
mod project_recovery_note_tests {
    use super::{
        active_project_recovery_note, legacy_migration_recovery_note, startup_canvas_status,
    };
    use std::path::Path;

    #[test]
    fn legacy_truncated_migration_note_names_validated_prefix_and_unchanged_source() {
        let note = legacy_migration_recovery_note(
            Path::new("selected-legacy.inkj"),
            Path::new("selected-legacy.schema3.inkj"),
            2,
        );
        assert!(note.contains("schema 2"));
        assert!(note.contains("only its validated prefix was migrated"));
        assert!(note.contains("selected source file remains unchanged"));
        assert!(note.contains("selected-legacy.inkj"));
        assert!(note.contains("selected-legacy.schema3.inkj"));
        let status = super::project_recovery_status(&note);
        assert!(status.contains("validated legacy prefix migrated"));
        assert!(status.contains("source unchanged"));
        let combined = startup_canvas_status(Some(&note), 2);
        assert!(combined.contains("validated legacy prefix migrated"));
        assert!(combined.contains("2 interrupted/in-progress stroke(s) remain raw"));
    }

    #[test]
    fn torn_schema_three_append_note_names_recovered_prefix_and_truncated_tail() {
        let note = active_project_recovery_note(Path::new("active-project.inkj"));
        assert!(note.contains("schema-3"));
        assert!(note.contains("only the validated prefix was retained"));
        assert!(note.contains("torn tail was truncated before append"));
        assert!(note.contains("active-project.inkj"));
        let status = super::project_recovery_status(&note);
        assert!(status.contains("validated active-project prefix retained"));
        assert!(status.contains("torn tail removed"));
    }
}

#[cfg(test)]
mod controlled_stall_tests {
    use super::ControlledStallTrigger;
    use winit::{
        event::ElementState,
        keyboard::{KeyCode, PhysicalKey},
    };

    #[test]
    fn startup_wait_does_not_arm_stall_and_operator_f9_triggers_once() {
        let mut trigger = ControlledStallTrigger::new(Some(2_000));

        // Startup/about-to-wait has no automatic path to arm or consume a stall.
        assert_eq!(trigger.take_armed_once(), None);
        assert!(!trigger.observe_operator_key(
            &PhysicalKey::Code(KeyCode::F8),
            ElementState::Pressed,
            false,
        ));
        assert!(!trigger.observe_operator_key(
            &PhysicalKey::Code(KeyCode::F9),
            ElementState::Pressed,
            true,
        ));
        assert_eq!(trigger.take_armed_once(), None);

        assert!(trigger.observe_operator_key(
            &PhysicalKey::Code(KeyCode::F9),
            ElementState::Pressed,
            false,
        ));
        assert_eq!(trigger.take_armed_once(), Some(2_000));
        assert_eq!(trigger.take_armed_once(), None);
        assert!(!trigger.observe_operator_key(
            &PhysicalKey::Code(KeyCode::F9),
            ElementState::Pressed,
            false,
        ));
    }
}

#[cfg(test)]
mod pending_record_cursor_tests {
    use super::PendingRecordCursor;

    #[test]
    fn repeated_pending_buffer_scan_does_not_replay_lifecycle_after_new_start() {
        let mut cursor = PendingRecordCursor::default();
        let pending_records = ["leave", "new-down"];
        let mut active = false;
        for index in cursor.take_new_range(pending_records.len()) {
            match pending_records[index] {
                "leave" => active = false,
                "new-down" => active = true,
                _ => unreachable!(),
            }
        }
        assert!(active);
        assert!(cursor.take_new_range(pending_records.len()).is_empty());
        assert!(active, "the old leave must not interrupt the later start");
        cursor.reset_after_buffer_clear();
        assert_eq!(cursor.take_new_range(1), 0..1);
    }
}

#[cfg(test)]
mod canvas_focus_cancel_tests {
    use super::cancel_mouse_canvas_gestures;

    #[test]
    fn focus_loss_clears_drag_and_cursor_anchors_before_a_later_release() {
        let mut cursor = Some((40.0, 50.0));
        let mut selection_drag_start = Some((20.0, 25.0));
        let mut move_drag_start = Some((30.0, 35.0));
        let mut pan_drag_last = Some((40.0, 50.0));

        assert!(cancel_mouse_canvas_gestures(
            &mut cursor,
            &mut selection_drag_start,
            &mut move_drag_start,
            &mut pan_drag_last,
        ));
        assert_eq!(cursor, None);
        assert_eq!(selection_drag_start, None);
        assert_eq!(move_drag_start, None);
        assert_eq!(pan_drag_last, None);

        // A later mouse release has no remembered move origin and therefore
        // cannot enqueue a stale Move action or jump after focus returns.
        assert!(move_drag_start.take().is_none());
    }
}
