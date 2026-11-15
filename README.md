# LassoInk Gate 0 Probe

## Implemented scope

This M1 stage 1 package is a minimal Windows Winit window and CLI shell with a localized `WM_POINTER` message hook. For `PT_PEN` messages it copies `GetPointerPenInfoHistory` records while the message is current, then returns `false` so Winit continues public dispatch. The window title and `--status` output label this as a diagnostic-only direct path with no canonical adapter selected. The hook stores owned records in process memory only; it does not write session files or transmit data.

In-memory retention is bounded at 4,096 event/error records and 131,072 samples total; one native history is capped at 65,536 samples. When a limit is reached, capture stops and the window reports an incomplete state with retained and known omitted counts. Message-level capture errors also mark their batch incomplete and show the latest issue. Records are not overwritten. Live title refreshes are limited to once per second.

The window reports `CAPTURE UNAVAILABLE` when the required Win32 pointer APIs cannot be loaded. A missing QPC frequency is shown as a timing warning; it does not prevent position capture.

Gate 0 still requires real CT430 measurements. Stage 1 does not pass that gate or select a capture source. Public-Winit comparison, Wintab, metrics/reporting, full session artifacts, and canonical adapter selection remain for later eligible M1 stages; M2+ remains gated on owner review of actual hardware results.

## Requirements and build

The project pins Rust 1.100.0 for `x86_64-pc-windows-msvc`. Install the pinned toolchain and target if they are not already present:

```powershell
rustup toolchain install 1.100.0 --profile minimal --component clippy --component rustfmt --target x86_64-pc-windows-msvc
```

Run the diagnostic shell or use its CLI status commands:

```powershell
cargo run
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

M1 stage 1 keeps bounded owned pointer-history records in process memory and writes no capture files. Later local session dumps must stay under an ignored `local_*` path such as `local_capture/`; do not add private handwriting or device dumps to Git.

## Dependencies

The M1 diagnostic directly depends on Winit 0.30.13 (default features disabled) and Windows-target `windows-sys` 0.52.0. `Cargo.toml` declares direct dependencies; `Cargo.lock` records their resolved versions.
