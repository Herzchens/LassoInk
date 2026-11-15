#[cfg(not(target_os = "windows"))]
compile_error!("The LassoInk Gate 0 probe is Windows-only.");

mod session;
mod win32_pointer;
mod wintab;

use session::{SessionWriter, default_session_path, read_report};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    error::Error,
    io,
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
use winit::{
    application::ApplicationHandler,
    event::{DeviceEvent, StartCause, WindowEvent},
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    raw_window_handle::{HasWindowHandle, RawWindowHandle},
    window::{Window, WindowId},
};
use wintab::{WT_DEFBASE, WintabCapture, WintabControlObserver};

const STATUS: &str = "LassoInk Gate 0 M1 stage 3 diagnostic: independent direct, public Winit, and explicit Wintab streams; no canonical adapter selected";
const NOT_IMPLEMENTED: &str = "Canonical journal, canvas, providers, network, and telemetry remain gated; CT430 hardware review is pending.";
const STORAGE_POLICY: &str = "Bounded local session output under the selected session directory; 4,096 retained events, 131,072 native samples, 65,536 direct samples per history, 4,096 Wintab packets per message, and bounded parser/metrics partitions.";
const TITLE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const EVENT_LOOP_WAKE_MARKER_THRESHOLD_NS: u128 = 50_000_000;

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
    controlled_stall_ms: Option<u64>,
    controlled_stall_triggered: bool,
}

struct RunOptions {
    capture_mode: CaptureMode,
    session_path: PathBuf,
    metadata: BTreeMap<String, String>,
    controlled_stall_ms: Option<u64>,
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
        if self.controlled_stall_triggered {
            return true;
        }
        let Some(requested_ms) = self.controlled_stall_ms else {
            return true;
        };
        self.controlled_stall_triggered = true;
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
}

fn raw_window_hwnd(window: &Window) -> Option<isize> {
    let handle = window.window_handle().ok()?;
    match handle.as_raw() {
        RawWindowHandle::Win32(handle) => Some(handle.hwnd.get()),
        _ => None,
    }
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
                self.window = Some(window);
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
                println!("M1 diagnostic window closed; session output will finalize locally.");
                event_loop.exit();
            }
            WindowEvent::Focused(focused) => {
                self.focused = Some(focused);
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
                println!("window focus changed: {focused}");
            }
            WindowEvent::Resized(size) => {
                self.client_size = Some((size.width, size.height));
                self.refresh_title();
                println!("window resized: {}x{}", size.width, size.height);
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
        if !self.run_controlled_stall_if_requested(event_loop) {
            self.probe_state.borrow_mut().leave_winit_callback();
            return;
        }
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
    let mut metadata = options.metadata;
    metadata.insert(
        "session_id".to_owned(),
        options
            .session_path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("session-id-unavailable")
            .to_owned(),
    );
    metadata.insert("schema_version".to_owned(), "1".to_owned());
    metadata.insert("app_name".to_owned(), "LassoInk capture probe".to_owned());
    metadata.insert(
        "app_version".to_owned(),
        env!("CARGO_PKG_VERSION").to_owned(),
    );
    metadata.insert(
        "capture_mode".to_owned(),
        capture_mode_label(capture_mode).to_owned(),
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
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_string(),
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
        "raw rows are never deduplicated; report exact raw fingerprints as diagnostic counts only"
            .to_owned(),
    );
    metadata.insert(
        "event_loop_wake_marker_threshold_ns".to_owned(),
        EVENT_LOOP_WAKE_MARKER_THRESHOLD_NS.to_string(),
    );
    metadata.insert(
        "hardware_gate_status".to_owned(),
        "pending owner CT430 evidence; software run does not pass Gate 0".to_owned(),
    );
    let session_writer = SessionWriter::create(options.session_path.clone(), &metadata)?;
    let session_path = session_writer.path().to_path_buf();
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
        controlled_stall_ms: options.controlled_stall_ms,
        controlled_stall_triggered: false,
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
    let mut output_ok = !app.session_writer_failed && app.flush_pending_records();
    if output_ok {
        output_ok = app.write_runtime_metadata() && app.flush_pending_records();
    }

    let mut finalized_path = None;
    if output_ok
        && probe_state.borrow().summary().storage_limit != Some(StorageLimit::SessionOutput)
        && let Some(writer) = app.session_writer.take()
    {
        match writer.finish(
            probe_state.borrow().summary(),
            app.app_clock_origin.elapsed().as_nanos(),
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
    if arguments.len() == 1 && arguments[0] == "--help" {
        println!("LassoInk Gate 0 M1 stage 3 capture diagnostics");
        println!("Usage: lassoink-capture-probe [options]");
        println!("  --capture-mode direct|wintab");
        println!("  --session-dir PATH | --session-path PATH");
        println!("  --trial-id ID --windows-ink on|off|unknown");
        println!("  --tablet-profile default|osu|unknown");
        println!("  --driver-version TEXT --active-area TEXT --mapped-display TEXT");
        println!("  --pressure-curve TEXT --windows-build TEXT");
        println!("  --controlled-stall-ms 1..30000");
        println!("  --report PATH --help --version --status");
        println!("{STATUS}");
        println!("{NOT_IMPLEMENTED}");
        println!("{STORAGE_POLICY}");
        return Ok(());
    }
    if arguments.len() == 1 && arguments[0] == "--version" {
        println!(
            "lassoink-capture-probe {} (M1 stage 3 diagnostic; source {} dirty {}; build {} profile {} target {} rustc {})",
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
        println!("Gate 0 hardware status: pending owner CT430 evidence.");
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
    Ok(RunOptions {
        capture_mode,
        session_path,
        metadata,
        controlled_stall_ms,
    })
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
        CaptureIssue, CaptureMode, NativeApi, ProbeSummary, WintabPacketTimeMode, WintabStatus,
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
}
