#[cfg(not(target_os = "windows"))]
compile_error!("The LassoInk Gate 0 probe is Windows-only.");

mod win32_pointer;

use std::{
    cell::RefCell,
    error::Error,
    io, process,
    rc::Rc,
    time::{Duration, Instant},
};
use win32_pointer::{ProbeState, ProbeSummary, StorageLimit};
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    window::{Window, WindowId},
};

const STATUS: &str = "LassoInk Gate 0 M1 stage 1: direct WM_POINTER pen-history diagnostic only; no canonical adapter selected";
const NOT_IMPLEMENTED: &str = "Public Winit comparison, Wintab, metrics/reporting, session files, and canonical adapter selection are not implemented.";
const STORAGE_POLICY: &str = "In-memory caps: 4,096 records, 131,072 samples total, and 65,536 samples per native history; reaching a cap stops capture and marks it incomplete. Message errors also mark their batch incomplete.";
const TITLE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

struct ProbeApp {
    window: Option<Window>,
    focused: Option<bool>,
    client_size: Option<(u32, u32)>,
    last_title: Option<String>,
    last_title_update: Option<Instant>,
    startup_error: Option<String>,
    probe_state: Rc<RefCell<ProbeState>>,
}

impl ProbeApp {
    fn title(&self) -> String {
        let summary: ProbeSummary = self.probe_state.borrow().summary();
        let capture_state = capture_state(summary);
        let timing_state = timing_state(summary);
        let latest_issue = summary
            .latest_incomplete_issue
            .map(|issue| format!("{issue:?}"))
            .unwrap_or_else(|| "none".to_owned());
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
            "{STATUS} | {capture_state} | {timing_state} | startup issue {latest_startup_issue} | records {} samples {} issues {} | incomplete batches {} latest issue {} | omitted records {} batches {} samples {} | {focus} | client {size}",
            summary.records_retained,
            summary.samples,
            summary.issues,
            summary.incomplete_batches,
            latest_issue,
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
}

fn capture_state(summary: ProbeSummary) -> String {
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
        if self.window.is_some() {
            return;
        }

        let attributes = Window::default_attributes().with_title(STATUS);
        match event_loop.create_window(attributes) {
            Ok(window) => {
                let size = window.inner_size();
                self.client_size = Some((size.width, size.height));
                self.window = Some(window);
                self.last_title = Some(STATUS.to_owned());
                self.last_title_update = Some(Instant::now());
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
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        if self.window.as_ref().map(Window::id) != Some(window_id) {
            return;
        }

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
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        self.refresh_title();
        if let Some(last_update) = self.last_title_update {
            event_loop
                .set_control_flow(ControlFlow::WaitUntil(last_update + TITLE_REFRESH_INTERVAL));
        }
    }
}

fn run_window() -> Result<(), Box<dyn Error>> {
    let probe_state = Rc::new(RefCell::new(ProbeState::default()));
    let mut builder = EventLoop::builder();
    win32_pointer::install_message_hook(&mut builder, Rc::clone(&probe_state));
    let event_loop = builder.build()?;
    let mut app = ProbeApp {
        window: None,
        focused: None,
        client_size: None,
        last_title: None,
        last_title_update: None,
        startup_error: None,
        probe_state,
    };
    event_loop.run_app(&mut app)?;

    if let Some(message) = app.startup_error {
        return Err(io::Error::other(message).into());
    }

    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => run_window(),
        [argument] if argument == "--help" => {
            println!("LassoInk Gate 0 M1 stage 1 diagnostic shell");
            println!("Usage: lassoink-capture-probe [--help|--version|--status]");
            println!("{STATUS}");
            println!("{NOT_IMPLEMENTED}");
            println!("{STORAGE_POLICY}");
            Ok(())
        }
        [argument] if argument == "--version" => {
            println!(
                "lassoink-capture-probe {} (M1 stage 1; diagnostic only)",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        [argument] if argument == "--status" => {
            println!("{STATUS}");
            println!("{NOT_IMPLEMENTED}");
            println!("{STORAGE_POLICY}");
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
    use crate::win32_pointer::{CaptureIssue, NativeApi, ProbeSummary};

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
}
