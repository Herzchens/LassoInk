#[cfg(not(target_os = "windows"))]
compile_error!("The LassoInk Gate 0 probe is Windows-only.");

mod win32_pointer;
mod wintab;

use std::{
    cell::RefCell,
    error::Error,
    io, process,
    rc::Rc,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use win32_pointer::{
    CaptureMode, CaptureSource, ProbeRecord, ProbeState, ProbeSummary, PublicEventCapability,
    PublicWinitEventData, PublicWinitEventRecord, StorageLimit, WintabPacketTimeMode, WintabStatus,
};
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    raw_window_handle::{HasWindowHandle, RawWindowHandle},
    window::{Window, WindowId},
};
use wintab::{WT_DEFBASE, WintabCapture, WintabControlObserver};

const STATUS: &str = "LassoInk Gate 0 M1 stage 2 diagnostic: independent direct, public Winit, and explicit Wintab streams; no canonical adapter selected";
const NOT_IMPLEMENTED: &str = "Metrics/reporting, session files, consolidated hardware procedure, and canonical adapter selection are not implemented.";
const STORAGE_POLICY: &str = "In-memory caps: 4,096 records, 131,072 native samples total, 65,536 direct samples per history, 4,096 Wintab packets per message, and 128 pending Wintab control notifications; any reached cap/observer overflow stops capture and marks it incomplete.";
const TITLE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

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
            "{STATUS} | {mode_label} | {capture_state} | {timing_state} | startup issue {latest_startup_issue} | records {} direct samples {} public events {} Wintab packets {} control notifications {} issues {} | incomplete batches {} latest issue {} latest Wintab issue {:?} | omitted records {} batches {} samples {} | {focus} | client {size}",
            summary.records_retained,
            summary.samples,
            summary.public_events,
            summary.wintab_packets,
            summary.wintab_control_messages,
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
            }
            Err(error) => {
                let message = format!("could not create the M1 diagnostic window: {error}");
                eprintln!("{message}");
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
                println!("M1 diagnostic window closed; no session file was written.");
                event_loop.exit();
            }
            WindowEvent::Focused(focused) => {
                self.focused = Some(focused);
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
        self.refresh_title();
        if let Some(last_update) = self.last_title_update {
            event_loop
                .set_control_flow(ControlFlow::WaitUntil(last_update + TITLE_REFRESH_INTERVAL));
        }
        self.probe_state.borrow_mut().leave_winit_callback();
    }
}

fn run_window(capture_mode: CaptureMode) -> Result<(), Box<dyn Error>> {
    let probe_state = Rc::new(RefCell::new(ProbeState::default()));
    probe_state.borrow_mut().set_capture_mode(capture_mode);
    let wintab_capture = {
        let mut state = probe_state.borrow_mut();
        WintabCapture::new(capture_mode, &mut state)
    };
    let wintab = Rc::new(RefCell::new(wintab_capture));
    let app_clock_origin = Instant::now();
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
    };
    let run_result = event_loop.run_app(&mut app);
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
    match arguments.as_slice() {
        [] => run_window(CaptureMode::DirectWmPointer),
        [mode_flag, mode] if mode_flag == "--capture-mode" && mode == "direct" => {
            run_window(CaptureMode::DirectWmPointer)
        }
        [mode_flag, mode] if mode_flag == "--capture-mode" && mode == "wintab" => {
            run_window(CaptureMode::Wintab)
        }
        [argument] if argument == "--help" => {
            println!("LassoInk Gate 0 M1 stage 2 capture comparison diagnostic");
            println!(
                "Usage: lassoink-capture-probe [--help|--version|--status|--capture-mode direct|wintab]"
            );
            println!("{STATUS}");
            println!("{NOT_IMPLEMENTED}");
            println!("{STORAGE_POLICY}");
            Ok(())
        }
        [argument] if argument == "--version" => {
            println!(
                "lassoink-capture-probe {} (M1 stage 2; diagnostic only)",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        [argument] if argument == "--status" => {
            println!("{STATUS}");
            println!("{NOT_IMPLEMENTED}");
            println!("{STORAGE_POLICY}");
            println!(
                "Default capture mode: direct; choose --capture-mode wintab to request the separate Wintab path."
            );
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown arguments; run with --help",
        )
        .into()),
    }
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
