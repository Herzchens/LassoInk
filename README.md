# LassoInk Gate 0 Probe

## Implemented scope

This M1 stage 3 package is a standalone Windows Winit capture diagnostic. The default `direct` mode copies direct `GetPointerPenInfoHistory` records inside Winit's `WM_POINTER` message hook, then returns `false` so Winit continues dispatch. It also records Winit `Touch`, cursor, mouse-button, focus, and device add/remove events as separately tagged public/application streams. Use `--capture-mode wintab` to explicitly select the Wintab driver path. Wintab failure is reported; it does not switch to direct WM_POINTER. Public Winit events continue as their own comparison stream and are never treated as a Wintab fallback.

Public Winit events retain Winit's device ID and force representation as public event data, separate from native `sourceDevice`, pointer ID, and HWND values. They have no native timestamp or CT430 tilt. At most one Touch event per dispatch receives a message association, and only when the current hooked message, Winit window HWND, and `Touch.id` match. Pen classification is separate: only `GetPointerType == PT_PEN` yields `ConfirmedPen`; a known non-pen type is `ConfirmedNonPen`, while an unavailable or failed type query stays unclassified even if the message association is known. Additional frame events, unmatched events, and reentrant/ambiguous events have no association and remain unclassified. The association identifies the dispatch message only; it does not join individual Winit frame events to direct history samples.

Wintab is loaded only from an absolute path under the Windows System32 directory using restricted loader flags. The DLL and SDK binaries are not bundled. The probe requests a fixed packet mask and absolute context mode; it records the actual packet mask, mode, queue size, `lcDevice`, cursor and context values. `pkTime` remains raw in the configured absolute-system-time or relative-milliseconds domain, separate from QPC and app arrival time. Queued packets are drained on both `WT_PACKET` and `WT_PROXIMITY`; every proximity enter/leave is logged with raw `MSG` fields, raw `lParam` flags, `MSG.time`, and app arrival even when the queue is empty. A per-window subclass is installed before `WTOpen` so sent and posted Wintab context controls are recorded once with raw HWND/message parameters and app-arrival time; sent controls have no Winit MSG timestamp. The queued hook ignores those control IDs and checks a nonblocking pending-control signal before reading Wintab packets. It rechecks that signal after each native queue query and packet read; a control observed during a packet read stops the drain and marks any rows returned by that call as uncertain raw diagnostics, excluded from uninterrupted Wintab metrics. The safe Winit callback drains WTOpen's initial control messages before packet processing and clears the signal only when the queue is empty and context state remains valid. The subclass forwards messages to Winit; its 128-entry pending queue reports overflow or callback failure. State changes and driver calls run at a later Winit callback boundary. If a requested queue size fails, the probe retries smaller sizes down through one packet; it records the actual capacity and reports a reduced accepted capacity as partial status without inferring sample loss. Context/device changes, overlap changes, overflow flags, serial discontinuities, and bounded-drain issues are also reported as partial status. Capture stops and requests context close at the next Winit loop boundary after a shared storage cap or context/order change; there is no same-session reopen. A first self-context overlap notification before any packet is treated as WTOpen's initial top-of-order setup only when raw status has `CXS_ONTOP` and neither `CXS_DISABLED` nor `CXS_OBSCURED`; adverse status, later overlap changes, or foreign-context overlap stop the Wintab stream. If `WTClose` fails at a stop boundary, the probe tries `WTEnable(FALSE)` to stop packet processing and records the pre-disable queue count when available. If both operations fail, the failure remains visible and the DLL stays loaded while the HCTX may remain live.

Raw input records are streamed to a versioned local TSV session (`LASSOINK-SESSION`, schema 1) at Winit callback boundaries. Output defaults to the ignored `local_capture/` directory; use `--session-dir` or `--session-path` to select another local path. A session remains `.partial` if a write, flush, sync, or final rename fails. The parser applies fixed file, line, sample, record, metadata, partition, and duplicate-fingerprint limits. It rejects malformed schemas and oversized rows instead of reading them into unbounded buffers.

In-memory pending records are bounded by the existing 4,096-record and 131,072-native-sample caps. A direct native history is capped at 65,536 samples; one Wintab message drain is capped at 4,096 packets. When any capture or session-output limit is reached, capture stops and the window reports incomplete state. Invalid direct rows remain in the raw session, while valid-direct-pen row counts require `PT_PEN`, matching requested pointer ID, a reported pressure mask, and pressure in the inclusive 0 through 1024 range. Validation anomaly counts are separate from raw row counts. Wintab rows interrupted by a control notification stay raw and are excluded from uninterrupted Wintab metrics. Raw overlaps and duplicate fingerprints are retained; no sample rows are removed. Direct inter-sample QPC intervals skip repeated raw fingerprints and report that exclusion reason.

`POINTER_INFO.PerformanceCount` and a QPC observation sampled at the Win32 hook boundary use the same QPC count domain, so the report may compute a message-receipt-to-hook-observation age and raw QPC intervals when frequency and values are available. These are not physical sensing-to-display latency measures. `dwTime`, Wintab `pkTime` (with mode), Winit public timestamps, and app `Instant` arrival remain separate. Missing/negative QPC values are reported as null with a reason. Derived metrics are partitioned by API, device, pointer, observed stroke, and native clock. Direct stroke buckets use only observed WM_POINTER down/up boundaries; public touch buckets use observed Winit phases. Focus loss, device lifecycle, pointer enter/re-entry/leave/capture loss, and device-range changes invalidate affected active stroke buckets; missing boundaries stay unclassified. The report never bridges clocks or strokes, joins public events to individual direct samples, interprets `frameId` gaps as proven loss, or claims hardware fidelity.

The timeline includes direct pointer enter/leave/capture/device messages; Wintab packet/proximity and control/error messages; Winit focus and input-device add/remove; and event-loop wake delays over the declared diagnostic threshold. `--controlled-stall-ms N` records an explicit start/end marker around one deliberate UI-thread pause (1..30000 ms). Windows Ink, tablet profile, driver version, active area, display mapping, and pressure curve are owner declarations; the runner reads the Windows build from the current-version registry and records its source. The tool does not change system or driver settings. Live title refreshes remain limited to once per second.

In direct mode, the window reports `CAPTURE UNAVAILABLE` if the required Win32 pointer APIs cannot be loaded. A missing QPC frequency appears as a timing warning and does not prevent position capture.

Gate 0 still requires real CT430 measurements. This software stage does not pass that gate or select a canonical capture source. The capture source comparison and derived report are diagnostic only; canonical journal, canvas, provider, network, and telemetry work remain gated on owner review of actual hardware results.

## Requirements and build

The project pins Rust 1.100.0 for `x86_64-pc-windows-msvc`. Install the pinned toolchain and target if they are not already present:

```powershell
rustup toolchain install 1.100.0 --profile minimal --component clippy --component rustfmt --target x86_64-pc-windows-msvc
```

Run the diagnostic or parse a finalized/partial session:

```powershell
cargo run
cargo run -- --capture-mode direct
cargo run -- --capture-mode wintab
cargo run -- --session-dir local_capture --trial-id ink-on-default --windows-ink on --tablet-profile default
cargo run -- --capture-mode wintab --session-path local_capture\ink-off-osu.tsv --windows-ink off --tablet-profile osu
cargo run -- --controlled-stall-ms 2000 --trial-id controlled-stall
cargo run -- --report local_capture\session-file.tsv
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

M1 session files may contain sensitive handwriting, timing, pressure, and device data. Keep them in an ignored local path or the owner-selected local session directory. They are not uploaded. Do not put them in the owner package, Git, or a public issue. The owner runner defaults session files to `%LOCALAPPDATA%\LassoInk\capture-sessions`, outside the package directory.

## Dependencies

The diagnostic directly depends on Winit 0.30.13 with default features disabled and the `rwh_06` interoperability feature, plus Windows-target `windows-sys` 0.52.0. `Cargo.lock` records the resolved `raw-window-handle` version.
