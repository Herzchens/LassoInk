# LassoInk Gate 0 Probe

## Implemented scope

This M0 package is a minimal Windows Winit window and CLI shell. Its window title and `--status` output say that **capture paths are not implemented**. It reports only basic window focus and size changes. It does not read pen samples, call pointer-history or Wintab APIs, persist diagnostic dumps, transmit data, or select a canonical capture adapter.

Gate 0 still requires real CT430 measurements. M0 does not pass that gate; M1 will add the diagnostic paths, and later milestones remain gated on owner review of the physical results.

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

M0 writes no capture data. When later M1 diagnostics produce local raw session dumps, keep them under an ignored `local_*` path such as `local_capture/`; do not add private handwriting or device dumps to Git.

## Dependencies

The M0 binary directly depends on Winit 0.30.13 with default features disabled. `Cargo.toml` declares direct dependencies; `Cargo.lock` records their resolved versions.