#[cfg(not(target_os = "windows"))]
compile_error!("The LassoInk Gate 0 probe shell is Windows-only.");

use std::{error::Error, io, process};
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, EventLoop},
    window::{Window, WindowId},
};

const STATUS: &str = "LassoInk Gate 0 M0 shell: capture paths are not implemented";

#[derive(Default)]
struct ProbeApp {
    window: Option<Window>,
    focused: Option<bool>,
    client_size: Option<(u32, u32)>,
    startup_error: Option<String>,
}

impl ProbeApp {
    fn title(&self) -> String {
        let focus = match self.focused {
            Some(true) => "focused",
            Some(false) => "unfocused",
            None => "focus unknown",
        };
        let size = self
            .client_size
            .map(|(width, height)| format!("{width}x{height}"))
            .unwrap_or_else(|| "size unknown".to_owned());

        format!("{STATUS} | {focus} | client {size}")
    }

    fn refresh_title(&self) {
        if let Some(window) = &self.window {
            window.set_title(&self.title());
        }
    }
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
                self.refresh_title();
                println!("{STATUS}");
            }
            Err(error) => {
                let message = format!("could not create the M0 diagnostic window: {error}");
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
                println!("M0 diagnostic window closed; no capture data was collected.");
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
}

fn run_window() -> Result<(), Box<dyn Error>> {
    let event_loop = EventLoop::new()?;
    let mut app = ProbeApp::default();
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
            println!("LassoInk Gate 0 M0 diagnostic shell");
            println!("Usage: lassoink-capture-probe [--help|--version|--status]");
            println!("M0 does not implement pen capture.");
            Ok(())
        }
        [argument] if argument == "--version" => {
            println!(
                "lassoink-capture-probe {} (M0 shell; capture not implemented)",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        [argument] if argument == "--status" => {
            println!("{STATUS}");
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
