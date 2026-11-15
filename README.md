# LassoInk Gate 0 Probe

## Implemented scope

This M1 stage 2 package is a standalone Windows Winit capture diagnostic. The default `direct` mode copies direct `GetPointerPenInfoHistory` records inside Winit's `WM_POINTER` message hook, then returns `false` so Winit continues dispatch. It also records Winit `Touch`, cursor, and mouse-button events as a separately tagged public stream. Use `--capture-mode wintab` to explicitly select the Wintab driver path. Wintab failure is reported; it does not switch to direct WM_POINTER. Public Winit events continue as their own comparison stream and are never treated as a Wintab fallback.

Public Winit events retain Winit's device ID and force representation as public event data, separate from native `sourceDevice`, pointer ID, and HWND values. They have no native timestamp or CT430 tilt. At most one Touch event per dispatch receives a message association, and only when the current hooked message, Winit window HWND, and `Touch.id` match. Pen classification is separate: only `GetPointerType == PT_PEN` yields `ConfirmedPen`; a known non-pen type is `ConfirmedNonPen`, while an unavailable or failed type query stays unclassified even if the message association is known. Additional frame events, unmatched events, and reentrant/ambiguous events have no association and remain unclassified. The association identifies the dispatch message only; it does not join individual Winit frame events to direct history samples.

Wintab is loaded only from an absolute path under the Windows System32 directory using restricted loader flags. The DLL and SDK binaries are not bundled. The probe requests a fixed packet mask and absolute context mode; it records the actual packet mask, mode, queue size, `lcDevice`, cursor and context values. `pkTime` remains raw in the configured absolute-system-time or relative-milliseconds domain, separate from QPC and app arrival time. Queued packets are drained on both `WT_PACKET` and `WT_PROXIMITY`. A per-window subclass is installed before `WTOpen` so sent and posted Wintab context controls are recorded once with raw HWND/message parameters and app-arrival time; sent controls have no Winit MSG timestamp. The queued hook ignores those control IDs and checks a nonblocking pending-control signal before reading Wintab packets. It rechecks that signal after each native queue query and packet read; a control observed during a packet read stops the drain and marks any rows returned by that call as uncertain raw diagnostics. The safe Winit callback drains WTOpen's initial control messages before packet processing and clears the signal only when the queue is empty and context state remains valid. The subclass forwards messages to Winit; its 128-entry pending queue reports overflow or callback failure. State changes and driver calls run at a later Winit callback boundary. If a requested queue size fails, the probe retries smaller sizes down through one packet; it records the actual capacity and reports a reduced accepted capacity as partial status without inferring sample loss. Context/device changes, overlap changes, overflow flags, serial discontinuities, and bounded-drain issues are also reported as partial status. Capture stops and requests context close at the next Winit loop boundary after a shared storage cap or context/order change; there is no same-session reopen. A first self-context overlap notification before any packet is treated as WTOpen's initial top-of-order setup only when raw status has `CXS_ONTOP` and neither `CXS_DISABLED` nor `CXS_OBSCURED`; adverse status, later overlap changes, or foreign-context overlap stop the Wintab stream. If `WTClose` fails at a stop boundary, the probe tries `WTEnable(FALSE)` to stop packet processing and records the pre-disable queue count when available. If both operations fail, the failure remains visible and the DLL stays loaded while the HCTX may remain live.

In-memory retention is bounded at 4,096 event/error records and 131,072 native samples total. A direct native history is capped at 65,536 samples; one Wintab message drain is capped at 4,096 packets. When a limit is reached, capture stops and the window reports an incomplete state with retained and known omitted counts. Message-level capture errors also mark their batch incomplete and show the latest issue. Records are not overwritten. Live title refreshes are limited to once per second.

In direct mode, the window reports `CAPTURE UNAVAILABLE` if the required Win32 pointer APIs cannot be loaded. A missing QPC frequency appears as a timing warning and does not prevent position capture.

Gate 0 still requires real CT430 measurements. Stage 2 does not pass that gate or select a canonical capture source. Metrics/reporting, persisted session artifacts, the consolidated hardware procedure, and canonical adapter selection remain unimplemented; M2+ remains gated on owner review of actual hardware results.

## Requirements and build

The project pins Rust 1.100.0 for `x86_64-pc-windows-msvc`. Install the pinned toolchain and target if they are not already present:

```powershell
rustup toolchain install 1.100.0 --profile minimal --component clippy --component rustfmt --target x86_64-pc-windows-msvc
```

Run the diagnostic shell or use its CLI status commands:

```powershell
cargo run
cargo run -- --capture-mode direct
cargo run -- --capture-mode wintab
cargo run -- --status
cargo run -- --version
cargo run -- --help
```

The quality checks used by Windows CI are:

```powershell
cargo +1.100.0 fmt --all -- --check
cargo +1.100.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.100.0 test --locked --workspace
cargo +1.100.0 build --locked --workspace
```

## Data handling

M1 stage 2 keeps bounded direct, public Winit, and optional Wintab records in process memory and writes no capture files. Later local session dumps must stay under an ignored `local_*` path such as `local_capture/`; do not add private handwriting or device dumps to Git.

## Dependencies

The diagnostic directly depends on Winit 0.30.13 with default features disabled and the `rwh_06` interoperability feature, plus Windows-target `windows-sys` 0.52.0. `Cargo.lock` records the resolved `raw-window-handle` version.
