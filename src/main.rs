#[cfg(not(target_os = "windows"))]
compile_error!("The LassoInk Gate 0 probe is Windows-only.");

mod benchmark;
mod canvas;
mod convert;
#[allow(dead_code)]
mod correction;
#[allow(dead_code)]
mod journal;
mod process_cpu;
mod project_runtime;
#[allow(dead_code)]
mod provider_protocol;
mod session;
mod win32_pointer;
mod windows_clipboard;
mod wintab;

use canvas::{
    CORRECTION_PANE_PADDING_PX, CORRECTION_PANE_ROW_HEIGHT_PX, CORRECTION_PANE_WIDTH_PX,
    CanvasInputTracker, CanvasOrigin, CanvasRect, CanvasScene, CanvasTool,
    CanvasToolCaptureContext, CanvasToolGestureTracker, CanvasToolIntent, CanvasViewport,
    DirectCaptureEvent, GdiTextAdvanceCache, paint_gdi_with_side_pane,
};
use convert::{
    ConvertPreparationError, ConvertPreparationTask, LocalConvertProviderV1, PreparedConversionV1,
    projection_from_execution, same_generated_raster_output,
};
use correction::{CorrectionSession, CorrectionTextEditor};
use journal::{
    EditCommand, JournalEvent, JournalHeader, JournalMetadata, JournalRecord, JournalReplayState,
    JournalWriter, MetadataScope, RegionCorrectionActionV1, StoredRecognitionProjection,
    StrokeInterruptionReason, StrokeViewFrame, migrate_schema_one_to_four,
    migrate_schema_three_to_four, migrate_schema_two_to_four, read_journal,
};
use process_cpu::{
    PROCESS_CPU_SCOPE, measure as measure_process_cpu, snapshot as process_cpu_snapshot,
};
use project_runtime::{
    CorrectionQueueError, ProjectQueueError, ProjectWriterAck, ProjectWriterHandle,
    ProjectionQueueError,
};
use provider_protocol::{
    ProviderErrorKind, ProviderExecution, ProviderSubmitError, ProviderWorkerHandle,
    ProviderWorkerPoll, RecognitionRequestV1, validate_result_for_current_view,
};
use session::{SessionWriter, default_session_path, read_report};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    io,
    ops::Range,
    path::{Path, PathBuf},
    process,
    rc::Rc,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use unicode_segmentation::UnicodeSegmentation;
use win32_pointer::{
    CaptureMode, CaptureSource, LifecycleEventKind, LifecycleEventRecord, MouseMessageOrigin,
    PointerMessageKind, ProbeRecord, ProbeState, ProbeSummary, PublicEventCapability,
    PublicWinitEventData, PublicWinitEventRecord, StorageLimit, WintabPacketTimeMode, WintabStatus,
};
use winit::dpi::{PhysicalPosition, PhysicalSize};
use winit::event::{ElementState, Ime};
use winit::keyboard::{Key, KeyCode, ModifiersState, NamedKey, PhysicalKey};
use winit::{
    application::ApplicationHandler,
    event::{DeviceEvent, MouseButton, MouseScrollDelta, StartCause, WindowEvent},
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    raw_window_handle::{HasWindowHandle, RawWindowHandle},
    window::{Window, WindowId},
};
use wintab::{WT_DEFBASE, WintabCapture, WintabControlObserver};

const STATUS: &str = "LassoInk M3: canonical capture lock is Direct WM_POINTER/GetPointerPenInfoHistory + Windows Ink ON; diagnostics elsewhere do not requalify it";
const CONVERT_POLICY: &str = "F4 Convert requires an explicit local --provider-config; no provider is selected by default. Gate 0 remains PROVISIONAL PASS with criterion-8 capture CPU and physical pen-to-display latency debt partial and nonblocking.";
const STORAGE_POLICY: &str = "Bounded local session output under the selected session directory; 4,096 retained events, 131,072 native samples, 65,536 direct samples per history, 4,096 Wintab packets per message, and bounded parser/metrics partitions.";
const TITLE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const EVENT_LOOP_WAKE_MARKER_THRESHOLD_NS: u128 = 50_000_000;
const MAX_UI_POINTER_OWNERS: usize = 32;
const MAX_DIRECT_CANVAS_POINTER_OWNERS: usize = 256;
const CORRECTION_PANE_MAX_EDITOR_ROWS: usize = 4;
const MAX_DEFERRED_PANE_ACTIONS: usize = 32;

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
    local_convert_provider: Option<LocalConvertProviderV1>,
    provider_worker: Option<ProviderWorkerHandle>,
    pending_convert: Option<PendingConvert>,
    correction_session: Option<CorrectionSession>,
    pending_correction: Option<PendingCorrectionWrite>,
    next_correction_id: u64,
    correction_focus: CorrectionPaneFocus,
    correction_panel_status: String,
    provider_config_path_editor: CorrectionTextEditor,
    provider_id_editor: CorrectionTextEditor,
    export_path_editor: CorrectionTextEditor,
    direct_ui_pointer_owners: DirectUiPointerOwnerTracker,
    deferred_pane_actions: Vec<CorrectionPaneAction>,
    correction_pane_scroll: CorrectionPaneScrollOffsets,
    pane_text_measurements: GdiTextAdvanceCache,
    correction_editor_browse_mode: bool,
    correction_mouse_selection_anchor: Option<usize>,
    correction_mouse_selecting: bool,
    alt_graph_active: bool,
    next_convert_generation: u64,
    project_generation: u64,
    convert_view_generation: u64,
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
    provider_config_path: Option<PathBuf>,
    provider_selection_id: Option<String>,
}

struct PendingConvert {
    generation: u64,
    project_generation: u64,
    view_generation: u64,
    cancelled: bool,
    selected_strokes_in_ui_order: Vec<journal::StrokeRef>,
    line_id: String,
    request: Option<RecognitionRequestV1>,
    ink_binding: Option<journal::ProjectionInkBindingV1>,
    generated_raster: Option<journal::GeneratedRasterProvenanceV1>,
    phase: PendingConvertPhase,
}

enum PendingConvertPhase {
    Transitioning,
    QueueSnapshotForPreparation {
        batch_id: u64,
    },
    SnapshotForPreparation {
        batch_id: u64,
    },
    Preparing {
        task: Box<ConvertPreparationTask>,
        revalidate: Option<Box<ProviderExecution>>,
    },
    ProviderRunning,
    SnapshotForValidation {
        batch_id: u64,
        execution: Box<ProviderExecution>,
    },
    QueueSnapshotForValidation {
        batch_id: u64,
        execution: Box<ProviderExecution>,
    },
    QueueProjectionCommit {
        batch_id: u64,
        app_arrival_elapsed_ns: u128,
        projection: Box<journal::RecognitionProjectionV1>,
    },
    Persisting {
        batch_id: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CorrectionPaneFocus {
    None,
    CorrectionEditor,
    ProviderConfigPath,
    ProviderId,
    ExportPath,
}

impl CorrectionPaneFocus {
    fn is_text_field(self) -> bool {
        self != Self::None
    }
}

struct PendingCorrectionWrite {
    batch_id: u64,
    correction: Box<journal::RegionCorrectionV1>,
    enqueued: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectUiPointerRoute {
    Canvas,
    Unowned,
    CapacityExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CorrectionPaneAction {
    Convert,
    Save,
    Reset,
    Cancel,
    Copy,
    LoadProviderConfig,
}

#[derive(Default)]
struct DirectUiPointerOwnerTracker {
    ui_owned: HashMap<(isize, u32), Option<CorrectionPaneAction>>,
    canvas_owned: HashSet<(isize, u32)>,
    // One separately bounded overflow slot preserves the next UI contact;
    // further simultaneous pane contacts fail capture instead of changing owner.
    overflow_ui_owned: Option<((isize, u32), Option<CorrectionPaneAction>)>,
}

impl DirectUiPointerOwnerTracker {
    fn route_down(
        &mut self,
        key: (isize, u32),
        starts_in_ui: bool,
        action: Option<CorrectionPaneAction>,
    ) -> DirectUiPointerRoute {
        if self.ui_owned.contains_key(&key)
            || self
                .overflow_ui_owned
                .is_some_and(|(overflow_key, _)| overflow_key == key)
        {
            return DirectUiPointerRoute::Unowned;
        }
        if self.canvas_owned.contains(&key) {
            return DirectUiPointerRoute::Canvas;
        }
        if !starts_in_ui {
            if self.canvas_owned.len() >= MAX_DIRECT_CANVAS_POINTER_OWNERS {
                return DirectUiPointerRoute::CapacityExceeded;
            }
            self.canvas_owned.insert(key);
            return DirectUiPointerRoute::Canvas;
        }
        if self.ui_owned.len() < MAX_UI_POINTER_OWNERS {
            self.ui_owned.insert(key, action);
            DirectUiPointerRoute::Unowned
        } else if self.overflow_ui_owned.is_none() {
            self.overflow_ui_owned = Some((key, action));
            DirectUiPointerRoute::Unowned
        } else {
            DirectUiPointerRoute::CapacityExceeded
        }
    }

    fn route_continuation(
        &mut self,
        key: (isize, u32),
        kind: PointerMessageKind,
        action_at_release: Option<CorrectionPaneAction>,
    ) -> (DirectUiPointerRoute, Option<CorrectionPaneAction>) {
        let saved_action = self.ui_owned.get(&key).copied().or_else(|| {
            self.overflow_ui_owned
                .filter(|(overflow_key, _)| *overflow_key == key)
                .map(|(_, action)| action)
        });
        let ui_owned = self.ui_owned.contains_key(&key)
            || self
                .overflow_ui_owned
                .is_some_and(|(overflow_key, _)| overflow_key == key);
        let completed_action = if kind == PointerMessageKind::Up {
            saved_action
                .filter(|saved| saved.is_some() && *saved == action_at_release)
                .flatten()
        } else {
            None
        };
        if kind == PointerMessageKind::Up {
            self.ui_owned.remove(&key);
            self.canvas_owned.remove(&key);
            if self
                .overflow_ui_owned
                .is_some_and(|(overflow_key, _)| overflow_key == key)
            {
                self.overflow_ui_owned = None;
            }
        }
        let route = if ui_owned {
            DirectUiPointerRoute::Unowned
        } else {
            DirectUiPointerRoute::Canvas
        };
        (route, completed_action)
    }

    fn release_pointer_id(&mut self, pointer_id: u32) -> DirectUiPointerRoute {
        let was_canvas_owned = self
            .canvas_owned
            .iter()
            .any(|(_, tracked_pointer_id)| *tracked_pointer_id == pointer_id);
        let was_ui_owned = self
            .ui_owned
            .keys()
            .any(|(_, tracked_pointer_id)| *tracked_pointer_id == pointer_id)
            || self
                .overflow_ui_owned
                .is_some_and(|((_, tracked_pointer_id), _)| tracked_pointer_id == pointer_id);
        self.ui_owned
            .retain(|(_, tracked_pointer_id), _| *tracked_pointer_id != pointer_id);
        self.canvas_owned
            .retain(|(_, tracked_pointer_id)| *tracked_pointer_id != pointer_id);
        if self
            .overflow_ui_owned
            .is_some_and(|((_, tracked_pointer_id), _)| tracked_pointer_id == pointer_id)
        {
            self.overflow_ui_owned = None;
        }
        self.canvas_owned
            .retain(|(_, tracked_pointer_id)| *tracked_pointer_id != pointer_id);
        if was_canvas_owned {
            DirectUiPointerRoute::Canvas
        } else if was_ui_owned {
            DirectUiPointerRoute::Unowned
        } else {
            DirectUiPointerRoute::Canvas
        }
    }

    fn clear(&mut self) {
        self.ui_owned.clear();
        self.canvas_owned.clear();
        self.overflow_ui_owned = None;
    }

    #[cfg(test)]
    fn has_pending_action(&self, action: CorrectionPaneAction) -> bool {
        self.ui_owned
            .values()
            .any(|pending| *pending == Some(action))
            || self
                .overflow_ui_owned
                .is_some_and(|(_, pending)| pending == Some(action))
    }

    fn has_pending_direct_action(&self) -> bool {
        self.ui_owned.values().any(|pending| pending.is_some())
            || self
                .overflow_ui_owned
                .is_some_and(|(_, pending)| pending.is_some())
    }

    fn has_active_canvas_pointer(&self) -> bool {
        !self.canvas_owned.is_empty()
    }

    fn observe_lifecycle(&mut self, kind: LifecycleEventKind, pointer_id: Option<u32>) {
        if kind == LifecycleEventKind::WindowFocusLost {
            self.clear();
        } else if matches!(
            kind,
            LifecycleEventKind::DirectPointerLeave
                | LifecycleEventKind::DirectPointerEnter
                | LifecycleEventKind::DirectPointerCaptureChanged
                | LifecycleEventKind::DirectPointerDeviceChanged
                | LifecycleEventKind::DirectPointerDeviceInRange
                | LifecycleEventKind::DirectPointerDeviceOutOfRange
        ) {
            if let Some(pointer_id) = pointer_id {
                self.release_pointer_id(pointer_id);
            } else {
                self.clear();
            }
        }
    }
}

#[derive(Default)]
struct CorrectionPaneLayout {
    lines: Vec<String>,
    editor_rows: Option<Range<usize>>,
    editor_grapheme_ranges: Vec<Range<usize>>,
    editor_row_hit_offsets: Vec<Vec<i32>>,
    action_row: Option<usize>,
    action_hit_targets: Vec<(Range<i32>, CorrectionPaneAction)>,
    scroll_regions: Vec<CorrectionPaneScrollRegion>,
    inline_editor_rows: Vec<InlineEditorRowLayout>,
    provider_path_row: Option<usize>,
    provider_id_row: Option<usize>,
    load_config_row: Option<usize>,
    export_path_row: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InlineEditorField {
    ProviderConfigPath,
    ProviderId,
    ExportPath,
}

#[derive(Clone, Debug)]
struct InlineEditorRowLayout {
    field: InlineEditorField,
    row_index: usize,
    visible_graphemes: Range<usize>,
    boundary_x: Vec<i32>,
}

#[derive(Clone, Debug)]
struct MeasuredPaneTextRow {
    text: String,
    grapheme_range: Range<usize>,
}

type MeasuredEditorDisplayRow = (String, Range<usize>, Vec<i32>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CorrectionPaneTextSection {
    Status,
    ProviderDetails,
    ProviderOutput,
    SavedText,
    EffectiveText,
    Draft,
    ImePreview,
}

#[derive(Clone, Debug)]
struct CorrectionPaneScrollRegion {
    section: CorrectionPaneTextSection,
    row_range: Range<usize>,
    total_rows: usize,
    visible_rows: usize,
}

#[derive(Default)]
struct CorrectionPaneScrollOffsets {
    status: usize,
    provider_details: usize,
    provider_output: usize,
    saved_text: usize,
    effective_text: usize,
    draft: usize,
    ime_preview: usize,
}

impl CorrectionPaneScrollOffsets {
    fn get(&self, section: CorrectionPaneTextSection) -> usize {
        match section {
            CorrectionPaneTextSection::Status => self.status,
            CorrectionPaneTextSection::ProviderDetails => self.provider_details,
            CorrectionPaneTextSection::ProviderOutput => self.provider_output,
            CorrectionPaneTextSection::SavedText => self.saved_text,
            CorrectionPaneTextSection::EffectiveText => self.effective_text,
            CorrectionPaneTextSection::Draft => self.draft,
            CorrectionPaneTextSection::ImePreview => self.ime_preview,
        }
    }

    fn set(&mut self, section: CorrectionPaneTextSection, offset: usize) {
        match section {
            CorrectionPaneTextSection::Status => self.status = offset,
            CorrectionPaneTextSection::ProviderDetails => self.provider_details = offset,
            CorrectionPaneTextSection::ProviderOutput => self.provider_output = offset,
            CorrectionPaneTextSection::SavedText => self.saved_text = offset,
            CorrectionPaneTextSection::EffectiveText => self.effective_text = offset,
            CorrectionPaneTextSection::Draft => self.draft = offset,
            CorrectionPaneTextSection::ImePreview => self.ime_preview = offset,
        }
    }
}

fn append_pane_line(layout: &mut CorrectionPaneLayout, line: String) -> usize {
    let row = layout.lines.len();
    layout.lines.push(line);
    row
}

fn safe_pane_display_grapheme(grapheme: &str) -> String {
    if matches!(grapheme, "\n" | "\r\n" | "\r") {
        String::new()
    } else if grapheme.chars().any(char::is_control) {
        "�".to_owned()
    } else {
        grapheme.to_owned()
    }
}

fn grapheme_pixel_boundaries(text: &str, utf16_extents: &[i32]) -> Vec<i32> {
    let mut boundaries = Vec::with_capacity(text.graphemes(true).count().saturating_add(1));
    boundaries.push(0);
    let mut utf16_units = 0usize;
    for grapheme in text.graphemes(true) {
        utf16_units = utf16_units.saturating_add(grapheme.encode_utf16().count());
        let fallback = boundaries.last().copied().unwrap_or_default();
        let extent = utf16_extents
            .get(utf16_units.saturating_sub(1))
            .copied()
            .unwrap_or(fallback);
        boundaries.push(extent);
    }
    boundaries
}

fn measured_pane_text_rows(
    text: &str,
    maximum_width_px: i32,
    measurements: &mut GdiTextAdvanceCache,
) -> io::Result<Vec<MeasuredPaneTextRow>> {
    let graphemes = text
        .graphemes(true)
        .map(safe_pane_display_grapheme)
        .collect::<Vec<_>>();
    let maximum_width_px = maximum_width_px.max(1);
    let mut rows = Vec::new();
    let mut logical_start = 0usize;

    loop {
        let logical_end = graphemes[logical_start..]
            .iter()
            .position(String::is_empty)
            .map_or(graphemes.len(), |relative| logical_start + relative);
        let logical_text = graphemes[logical_start..logical_end].concat();
        let logical_extents = measurements.advances(&logical_text)?;
        let logical_boundaries = grapheme_pixel_boundaries(&logical_text, &logical_extents);
        let logical_len = logical_end.saturating_sub(logical_start);

        if logical_len == 0 {
            rows.push(MeasuredPaneTextRow {
                text: String::new(),
                grapheme_range: logical_start..logical_start,
            });
        } else {
            let mut row_start = 0usize;
            while row_start < logical_len {
                let mut row_end = row_start;
                while row_end < logical_len {
                    let next = row_end + 1;
                    let width =
                        logical_boundaries[next].saturating_sub(logical_boundaries[row_start]);
                    if width > maximum_width_px && row_end > row_start {
                        break;
                    }
                    row_end = next;
                    if width > maximum_width_px {
                        break;
                    }
                }
                if row_end == row_start {
                    row_end = row_start + 1;
                }

                let mut row_text = logical_text_for_range(
                    &graphemes,
                    logical_start + row_start..logical_start + row_end,
                );
                let mut row_extents = measurements.advances(&row_text)?;
                let mut boundary_x = grapheme_pixel_boundaries(&row_text, &row_extents);
                while row_end > row_start + 1
                    && boundary_x.last().copied().unwrap_or_default() > maximum_width_px
                {
                    row_end -= 1;
                    row_text = logical_text_for_range(
                        &graphemes,
                        logical_start + row_start..logical_start + row_end,
                    );
                    row_extents = measurements.advances(&row_text)?;
                    boundary_x = grapheme_pixel_boundaries(&row_text, &row_extents);
                }
                rows.push(MeasuredPaneTextRow {
                    text: row_text,
                    grapheme_range: logical_start + row_start..logical_start + row_end,
                });
                row_start = row_end;
            }
        }

        if logical_end == graphemes.len() {
            break;
        }
        logical_start = logical_end + 1;
        if logical_start > graphemes.len() {
            break;
        }
    }
    Ok(rows)
}

fn logical_text_for_range(graphemes: &[String], range: Range<usize>) -> String {
    graphemes[range].concat()
}

fn scroll_view_range(total_rows: usize, visible_rows: usize, offset: usize) -> Range<usize> {
    let start = offset.min(total_rows.saturating_sub(visible_rows));
    start..start.saturating_add(visible_rows).min(total_rows)
}

fn append_scrolled_measured_rows(
    layout: &mut CorrectionPaneLayout,
    section: CorrectionPaneTextSection,
    rows: &[MeasuredPaneTextRow],
    visible_rows: usize,
    offset: usize,
) -> Range<usize> {
    let visible_range = scroll_view_range(rows.len(), visible_rows, offset);
    let row_start = layout.lines.len();
    for row in visible_range.clone() {
        append_pane_line(layout, rows[row].text.clone());
    }
    while layout.lines.len().saturating_sub(row_start) < visible_rows {
        append_pane_line(layout, String::new());
    }
    let row_range = row_start..layout.lines.len();
    layout.scroll_regions.push(CorrectionPaneScrollRegion {
        section,
        row_range: row_range.clone(),
        total_rows: rows.len(),
        visible_rows,
    });
    row_range
}

fn extent_at_utf16_boundary(extents: &[i32], utf16_boundary: usize) -> i32 {
    if utf16_boundary == 0 {
        0
    } else {
        extents
            .get(utf16_boundary - 1)
            .copied()
            .unwrap_or_else(|| extents.last().copied().unwrap_or_default())
    }
}

fn measured_editor_display_rows(
    editor: &CorrectionTextEditor,
    maximum_width_px: i32,
    measurements: &mut GdiTextAdvanceCache,
) -> io::Result<Vec<MeasuredEditorDisplayRow>> {
    let marker_extents = measurements.advances("[]|")?;
    let marker_reserve = marker_extents.last().copied().unwrap_or(0).max(1);
    let text_rows = measured_pane_text_rows(
        editor.text(),
        maximum_width_px.saturating_sub(marker_reserve).max(1),
        measurements,
    )?;
    let graphemes = editor.text().graphemes(true).collect::<Vec<_>>();
    let selection = editor.selection_graphemes();
    let cursor = editor.cursor_grapheme();
    let mut output = Vec::with_capacity(text_rows.len());
    for (row_index, row) in text_rows.iter().enumerate() {
        let mut line = String::new();
        let mut boundary_units = Vec::with_capacity(row.grapheme_range.len().saturating_add(1));
        for (index, grapheme) in graphemes
            .iter()
            .enumerate()
            .take(row.grapheme_range.end)
            .skip(row.grapheme_range.start)
        {
            let is_wrapped_start = row_index > 0
                && text_rows[row_index - 1].grapheme_range.end == row.grapheme_range.start
                && index == row.grapheme_range.start;
            boundary_units.push(line.encode_utf16().count());
            if !is_wrapped_start {
                append_editor_caret_marker(&mut line, selection.as_ref(), cursor, index);
            }
            line.push_str(&safe_pane_display_grapheme(grapheme));
        }
        boundary_units.push(line.encode_utf16().count());
        append_editor_caret_marker(
            &mut line,
            selection.as_ref(),
            cursor,
            row.grapheme_range.end,
        );
        let line_extents = measurements.advances(&line)?;
        let boundary_x = boundary_units
            .into_iter()
            .map(|boundary| extent_at_utf16_boundary(&line_extents, boundary))
            .collect();
        output.push((line, row.grapheme_range.clone(), boundary_x));
    }
    Ok(output)
}

fn append_scrolled_editor_rows(
    layout: &mut CorrectionPaneLayout,
    rows: &[MeasuredEditorDisplayRow],
    visible_rows: usize,
    offset: usize,
) -> Range<usize> {
    let visible_range = scroll_view_range(rows.len(), visible_rows, offset);
    let row_start = layout.lines.len();
    for row_index in visible_range {
        let (line, grapheme_range, boundary_x) = &rows[row_index];
        append_pane_line(layout, line.clone());
        layout.editor_grapheme_ranges.push(grapheme_range.clone());
        layout.editor_row_hit_offsets.push(boundary_x.clone());
    }
    while layout.lines.len().saturating_sub(row_start) < visible_rows {
        append_pane_line(layout, String::new());
        layout.editor_grapheme_ranges.push(0..0);
        layout.editor_row_hit_offsets.push(vec![0]);
    }
    let row_range = row_start..layout.lines.len();
    layout.editor_rows = Some(row_range.clone());
    layout.scroll_regions.push(CorrectionPaneScrollRegion {
        section: CorrectionPaneTextSection::Draft,
        row_range: row_range.clone(),
        total_rows: rows.len(),
        visible_rows,
    });
    row_range
}

fn inline_editor_cursor_at(
    layout: &CorrectionPaneLayout,
    field: InlineEditorField,
    row: usize,
    x_px: i32,
) -> Option<usize> {
    let inline = layout
        .inline_editor_rows
        .iter()
        .find(|inline| inline.field == field && inline.row_index == row)?;
    Some(
        inline
            .visible_graphemes
            .start
            .saturating_add(nearest_grapheme_boundary(&inline.boundary_x, x_px)),
    )
}

fn pane_text_width(text: &str, measurements: &mut GdiTextAdvanceCache) -> io::Result<i32> {
    measurements
        .advances(text)
        .map(|advances| advances.last().copied().unwrap_or_default())
}

fn correction_action_hit_targets(
    label: &str,
    measurements: &mut GdiTextAdvanceCache,
) -> io::Result<Vec<(Range<i32>, CorrectionPaneAction)>> {
    let advances = measurements.advances(label)?;
    let boundaries = grapheme_pixel_boundaries(label, &advances);
    let graphemes = label.graphemes(true).collect::<Vec<_>>();
    let labels = [
        ("[Convert]", CorrectionPaneAction::Convert),
        ("[Save]", CorrectionPaneAction::Save),
        ("[Reset]", CorrectionPaneAction::Reset),
        ("[Cancel]", CorrectionPaneAction::Cancel),
        ("[Copy]", CorrectionPaneAction::Copy),
    ];
    let mut cursor = 0usize;
    let mut targets = Vec::with_capacity(labels.len());
    for (index, (button, action)) in labels.iter().enumerate() {
        let start = cursor;
        let end = start.saturating_add(button.graphemes(true).count());
        if end > graphemes.len() || end >= boundaries.len() {
            return Ok(Vec::new());
        }
        let hit_end = if index + 1 < labels.len() && graphemes.get(end) == Some(&" ") {
            end + 1
        } else {
            end
        };
        targets.push((boundaries[start]..boundaries[hit_end], *action));
        cursor = hit_end;
    }
    Ok(targets)
}

fn should_process_winit_mouse_input(
    capture_mode: CaptureMode,
    origin: MouseMessageOrigin,
    has_active_canvas_pointer: bool,
    has_pending_direct_action: bool,
    targets_pane_action: bool,
) -> bool {
    // Unknown origin must remain a usable mouse event; only a confirmed pen
    // promotion that overlaps Direct-owned input or a pane action is filtered.
    capture_mode != CaptureMode::DirectWmPointer
        || (match origin {
            MouseMessageOrigin::PenPromoted { .. } => {
                !has_active_canvas_pointer && !has_pending_direct_action && !targets_pane_action
            }
            MouseMessageOrigin::TouchPromoted { .. } | MouseMessageOrigin::Unknown => true,
        })
}

fn move_text_editor_cursor(editor: &mut CorrectionTextEditor, right: bool, extend: bool) {
    match (right, extend) {
        (true, true) => editor.move_cursor_right_extending_selection(),
        (false, true) => editor.move_cursor_left_extending_selection(),
        (true, false) => editor.move_cursor_right(),
        (false, false) => editor.move_cursor_left(),
    }
}

fn append_editor_caret_marker(
    line: &mut String,
    selection: Option<&Range<usize>>,
    cursor: usize,
    index: usize,
) {
    if let Some(selection) = selection {
        if selection.start == index {
            line.push('[');
        }
        if selection.end == index {
            line.push(']');
        }
    } else if cursor == index {
        line.push('|');
    }
}

fn inline_text_editor_line(
    prefix: &str,
    editor: &CorrectionTextEditor,
    field: InlineEditorField,
    maximum_width_px: i32,
    measurements: &mut GdiTextAdvanceCache,
) -> io::Result<(String, InlineEditorRowLayout)> {
    let text = editor
        .preview_text()
        .unwrap_or_else(|_| "invalid draft".to_owned());
    let graphemes = text
        .graphemes(true)
        .map(|grapheme| match grapheme {
            "\n" | "\r\n" | "\r" => "↵".to_owned(),
            _ if grapheme.chars().any(char::is_control) => "�".to_owned(),
            _ => grapheme.to_owned(),
        })
        .collect::<Vec<_>>();
    let selection = editor.selection_graphemes();
    let cursor = editor.cursor_grapheme().min(graphemes.len());
    let prefix_width = pane_text_width(prefix, measurements)?;
    let marker_reserve = pane_text_width("[]|", measurements)?.max(1);
    let ellipsis_width = pane_text_width("…", measurements)?;
    let capacity = maximum_width_px
        .saturating_sub(prefix_width)
        .saturating_sub(marker_reserve)
        .saturating_sub(ellipsis_width.saturating_mul(2))
        .max(1);
    let display_text = graphemes.concat();
    let display_extents = measurements.advances(&display_text)?;
    let display_boundaries = grapheme_pixel_boundaries(&display_text, &display_extents);
    let mut start = cursor;
    let before_capacity = capacity / 2;
    while start > 0
        && display_boundaries[cursor].saturating_sub(display_boundaries[start - 1])
            <= before_capacity
    {
        start -= 1;
    }
    let mut end = cursor;
    while end < graphemes.len()
        && display_boundaries[end + 1].saturating_sub(display_boundaries[start]) <= capacity
    {
        end += 1;
    }
    if end == start && end < graphemes.len() {
        end += 1;
    }

    let mut line = String::with_capacity(prefix.len().saturating_add(text.len()).saturating_add(8));
    let mut boundary_units = Vec::with_capacity(end.saturating_sub(start).saturating_add(1));
    line.push_str(prefix);
    if start > 0 {
        line.push('…');
    }
    for (index, grapheme) in graphemes.iter().enumerate().take(end).skip(start) {
        boundary_units.push(line.encode_utf16().count());
        if let Some(selection) = &selection {
            if selection.start == index {
                line.push('[');
            }
            if selection.end == index {
                line.push(']');
            }
        } else if cursor == index {
            line.push('|');
        }
        line.push_str(grapheme);
    }
    boundary_units.push(line.encode_utf16().count());
    if let Some(selection) = &selection {
        if selection.start == end {
            line.push('[');
        }
        if selection.end == end {
            line.push(']');
        }
    } else if cursor == end {
        line.push('|');
    }
    if end < graphemes.len() {
        line.push('…');
    }
    let line_extents = measurements.advances(&line)?;
    let boundary_x = boundary_units
        .into_iter()
        .map(|boundary| extent_at_utf16_boundary(&line_extents, boundary))
        .collect();
    Ok((
        line,
        InlineEditorRowLayout {
            field,
            row_index: 0,
            visible_graphemes: start..end,
            boundary_x,
        },
    ))
}

fn direct_screen_point_in_correction_pane(
    screen_point: (i32, i32),
    client_origin: CanvasOrigin,
    client_size: (u32, u32),
) -> bool {
    let client_x = i64::from(screen_point.0) - client_origin.x_screen_px;
    let client_y = i64::from(screen_point.1) - client_origin.y_screen_px;
    let width = i64::from(client_size.0);
    let height = i64::from(client_size.1);
    correction_pane_contains_client_point(client_x, client_y, width, height)
}

fn correction_pane_left_edge(client_width: i64) -> i64 {
    client_width
        .saturating_sub(i64::from(CORRECTION_PANE_WIDTH_PX))
        .max(0)
}

fn correction_pane_left_edge_i32(client_width: i32) -> i32 {
    i32::try_from(correction_pane_left_edge(i64::from(client_width))).unwrap_or(0)
}

fn correction_pane_contains_client_point(
    client_x: i64,
    client_y: i64,
    client_width: i64,
    client_height: i64,
) -> bool {
    client_width > 0
        && client_height > 0
        && client_x >= correction_pane_left_edge(client_width)
        && client_x < client_width
        && client_y >= 0
        && client_y < client_height
}

fn direct_pen_screen_point(batch: &win32_pointer::DirectPenHistoryBatch) -> Option<(i32, i32)> {
    let first = batch.samples.first()?;
    let device_handle = first.source_device_handle_raw_session_scoped;
    if batch
        .samples
        .iter()
        .any(|sample| sample.source_device_handle_raw_session_scoped != device_handle)
    {
        return None;
    }
    let mut pen_samples = batch.samples.iter().filter(|sample| {
        sample.pointer_type_raw == windows_sys::Win32::UI::WindowsAndMessaging::PT_PEN
            && sample.attribution == win32_pointer::PointerAttribution::MatchesRequestedPointer
            && sample.pointer_id_raw == batch.pointer_id_requested
            && sample.source_device_handle_raw_session_scoped == device_handle
    });
    let sample = if batch.message_kind == PointerMessageKind::Up {
        pen_samples.next_back()?
    } else {
        pen_samples.next()?
    };
    Some((
        sample.position.pt_pixel_location_raw.x,
        sample.position.pt_pixel_location_raw.y,
    ))
}

fn direct_pen_ui_screen_point(batch: &win32_pointer::DirectPenHistoryBatch) -> Option<(i32, i32)> {
    let first = batch.samples.first()?;
    let device_handle = first.source_device_handle_raw_session_scoped;
    if batch
        .samples
        .iter()
        .any(|sample| sample.source_device_handle_raw_session_scoped != device_handle)
    {
        return None;
    }
    let sample = batch.samples.iter().find(|sample| {
        sample.pointer_type_raw == windows_sys::Win32::UI::WindowsAndMessaging::PT_PEN
            && sample.source_device_handle_raw_session_scoped == device_handle
    })?;
    Some((
        sample.position.pt_pixel_location_raw.x,
        sample.position.pt_pixel_location_raw.y,
    ))
}

fn direct_pen_down_starts_in_correction_pane(
    batch: &win32_pointer::DirectPenHistoryBatch,
    client_origin: Option<CanvasOrigin>,
    client_size: Option<(u32, u32)>,
) -> bool {
    if batch.message_kind != PointerMessageKind::Down {
        return false;
    }
    let (Some(origin), Some(size), Some(screen_point)) = (
        client_origin,
        client_size,
        direct_pen_ui_screen_point(batch),
    ) else {
        return false;
    };
    direct_screen_point_in_correction_pane(screen_point, origin, size)
}

fn correction_pane_action_at_client_layout(
    x: i32,
    y: i32,
    client_size: (u32, u32),
    layout: &CorrectionPaneLayout,
) -> Option<CorrectionPaneAction> {
    let width = i32::try_from(client_size.0).unwrap_or(i32::MAX);
    let height = i32::try_from(client_size.1).unwrap_or(i32::MAX);
    if !correction_pane_contains_client_point(
        i64::from(x),
        i64::from(y),
        i64::from(width),
        i64::from(height),
    ) {
        return None;
    }
    let pane_left = correction_pane_left_edge_i32(width);
    let row = usize::try_from(
        y.saturating_sub(CORRECTION_PANE_PADDING_PX) / CORRECTION_PANE_ROW_HEIGHT_PX,
    )
    .ok()?;
    if layout.action_row == Some(row) {
        let action_offset = x
            .saturating_sub(pane_left)
            .saturating_sub(CORRECTION_PANE_PADDING_PX);
        return layout
            .action_hit_targets
            .iter()
            .find(|(target, _)| target.contains(&action_offset))
            .map(|(_, action)| *action);
    }
    if layout.load_config_row == Some(row) {
        return Some(CorrectionPaneAction::LoadProviderConfig);
    }
    None
}

fn correction_pane_action_at_screen_layout(
    screen_point: (i32, i32),
    client_origin: Option<CanvasOrigin>,
    client_size: Option<(u32, u32)>,
    layout: Option<&CorrectionPaneLayout>,
) -> Option<CorrectionPaneAction> {
    let (origin, client_size, layout) = (client_origin?, client_size?, layout?);
    let x = i64::from(screen_point.0).checked_sub(origin.x_screen_px)?;
    let y = i64::from(screen_point.1).checked_sub(origin.y_screen_px)?;
    correction_pane_action_at_client_layout(
        i32::try_from(x).ok()?,
        i32::try_from(y).ok()?,
        client_size,
        layout,
    )
}

fn route_direct_batch_to_correction_ui(
    owners: &mut DirectUiPointerOwnerTracker,
    batch: &win32_pointer::DirectPenHistoryBatch,
    client_origin: Option<CanvasOrigin>,
    client_size: Option<(u32, u32)>,
    pane_layout: Option<&CorrectionPaneLayout>,
) -> (DirectUiPointerRoute, Option<CorrectionPaneAction>) {
    match batch.message_kind {
        PointerMessageKind::Down => {
            let Some(first) = batch.samples.first() else {
                return (DirectUiPointerRoute::Canvas, None);
            };
            let starts_in_ui =
                direct_pen_down_starts_in_correction_pane(batch, client_origin, client_size);
            let action = direct_pen_screen_point(batch).and_then(|point| {
                correction_pane_action_at_screen_layout(
                    point,
                    client_origin,
                    client_size,
                    pane_layout,
                )
            });
            (
                owners.route_down(
                    (
                        first.source_device_handle_raw_session_scoped,
                        batch.pointer_id_requested,
                    ),
                    starts_in_ui,
                    action,
                ),
                None,
            )
        }
        PointerMessageKind::Update | PointerMessageKind::Up => {
            let Some(first) = batch.samples.first() else {
                if batch.message_kind == PointerMessageKind::Up {
                    return (owners.release_pointer_id(batch.pointer_id_requested), None);
                }
                return (DirectUiPointerRoute::Canvas, None);
            };
            let action_at_release = if batch.message_kind == PointerMessageKind::Up {
                direct_pen_screen_point(batch).and_then(|point| {
                    correction_pane_action_at_screen_layout(
                        point,
                        client_origin,
                        client_size,
                        pane_layout,
                    )
                })
            } else {
                None
            };
            owners.route_continuation(
                (
                    first.source_device_handle_raw_session_scoped,
                    batch.pointer_id_requested,
                ),
                batch.message_kind,
                action_at_release,
            )
        }
    }
}

fn nearest_grapheme_boundary(boundary_x: &[i32], x_px: i32) -> usize {
    if boundary_x.len() <= 1 {
        return 0;
    }
    boundary_x
        .windows(2)
        .position(|pair| x_px < pair[0].saturating_add(pair[1].saturating_sub(pair[0]) / 2))
        .unwrap_or(boundary_x.len() - 1)
}

fn correction_pane_scroll_offset(current: usize, wheel_rows: f64, maximum: usize) -> usize {
    let current = current.min(maximum);
    if !wheel_rows.is_finite() || wheel_rows == 0.0 {
        return current;
    }
    let rows = wheel_rows.abs().ceil().max(1.0) as usize;
    if wheel_rows > 0.0 {
        current.saturating_sub(rows)
    } else {
        current.saturating_add(rows).min(maximum)
    }
}

fn correction_editor_scroll_offset_for_caret(
    current: usize,
    caret_row: usize,
    total_rows: usize,
    visible_rows: usize,
) -> usize {
    let maximum = total_rows.saturating_sub(visible_rows);
    let current = current.min(maximum);
    if caret_row < current {
        caret_row.min(maximum)
    } else if caret_row >= current.saturating_add(visible_rows) {
        caret_row
            .saturating_add(1)
            .saturating_sub(visible_rows)
            .min(maximum)
    } else {
        current
    }
}

#[cfg(test)]
fn correction_pane_visible_row_count(client_height: u32) -> usize {
    let height = i32::try_from(client_height).unwrap_or(i32::MAX);
    usize::try_from(
        (height - 2 * CORRECTION_PANE_PADDING_PX).max(0) / CORRECTION_PANE_ROW_HEIGHT_PX,
    )
    .unwrap_or_default()
}

fn is_control_alt_shortcut(control: bool, alt: bool, alt_graph: bool) -> bool {
    control && alt && !alt_graph
}

fn allows_keyboard_text(control: bool, alt: bool, alt_graph: bool) -> bool {
    alt_graph || (!control && !alt)
}

fn should_insert_keyboard_text(
    control: bool,
    alt: bool,
    alt_graph: bool,
    ime_preedit_active: bool,
    has_text: bool,
) -> bool {
    allows_keyboard_text(control, alt, alt_graph) && !ime_preedit_active && has_text
}

fn should_process_focused_text_key(state: ElementState, _repeat: bool) -> bool {
    // Repeated Windows KeyEvents can carry printable text and editing keys should repeat.
    state == ElementState::Pressed
}

fn focused_text_measurement_allows_input(
    focus: CorrectionPaneFocus,
    measurement_available: bool,
) -> bool {
    !focus.is_text_field() || measurement_available
}

fn convert_context_matches(
    pending: &PendingConvert,
    project_generation: u64,
    view_generation: u64,
    selected_strokes: Option<&[journal::StrokeRef]>,
    capture_pending_or_preview: bool,
) -> bool {
    pending.project_generation == project_generation
        && pending.view_generation == view_generation
        && !capture_pending_or_preview
        && selected_strokes == Some(pending.selected_strokes_in_ui_order.as_slice())
}

fn convert_phase_is_persisting(phase: &PendingConvertPhase) -> bool {
    matches!(phase, PendingConvertPhase::Persisting { .. })
}

fn convert_provider_failure_message(error: &ProviderErrorKind) -> &'static str {
    if matches!(error, ProviderErrorKind::TimedOut(_)) {
        "Convert provider timed out; no fallback was attempted"
    } else {
        "Convert provider failed; no fallback was attempted"
    }
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
                "Direct WM_POINTER pen input only (Windows Ink ON); public mouse events are not ink"
                    .to_owned()
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

    fn start_or_cancel_convert(&mut self) {
        if self.pending_convert.is_some() {
            self.cancel_convert("Convert canceled by the user".to_owned());
            return;
        }
        if self.local_convert_provider.is_none() {
            self.canvas_status =
                "Convert unavailable: supply an explicit --provider-config PATH; no provider is selected by default"
                    .to_owned();
            self.request_redraw();
            return;
        }
        if self.pending_correction.is_some()
            || self
                .correction_session
                .as_ref()
                .is_some_and(CorrectionSession::is_dirty)
        {
            self.canvas_status =
                "Save or cancel the open correction draft before starting another Convert"
                    .to_owned();
            self.request_redraw();
            return;
        }
        if self.project_incomplete_reason.is_some()
            || self.deferred_capture_batch.is_some()
            || self.canvas_scene.has_preview_strokes()
            || self.canvas_selection_drag_start.is_some()
            || self.canvas_move_drag_start.is_some()
            || self.canvas_pan_drag_last.is_some()
        {
            self.canvas_status =
                "Convert unavailable while the project has pending or incomplete ink changes"
                    .to_owned();
            self.request_redraw();
            return;
        }
        let selected_strokes = match self.canvas_scene.selected_targets() {
            Ok(selected) if !selected.is_empty() => selected,
            Ok(_) => {
                self.canvas_status = "Select one region before Convert".to_owned();
                self.request_redraw();
                return;
            }
            Err(_) => {
                self.canvas_status = "Convert selection exceeds its fixed limits".to_owned();
                self.request_redraw();
                return;
            }
        };
        let generation = self.next_convert_generation;
        let Some(next_generation) = generation.checked_add(1) else {
            self.canvas_status = "Convert request identifier exhausted".to_owned();
            self.request_redraw();
            return;
        };
        self.next_convert_generation = next_generation;
        let Some(batch_id) = self.allocate_project_batch_id() else {
            self.canvas_status = "Convert queue identifier exhausted".to_owned();
            self.request_redraw();
            return;
        };
        let line_id = "line-1".to_owned();
        let mut pending = PendingConvert {
            generation,
            project_generation: self.project_generation,
            view_generation: self.convert_view_generation,
            cancelled: false,
            selected_strokes_in_ui_order: selected_strokes,
            line_id,
            request: None,
            ink_binding: None,
            generated_raster: None,
            phase: PendingConvertPhase::Transitioning,
        };
        let result = self
            .project_writer
            .as_mut()
            .map(|writer| writer.try_snapshot_for_convert(batch_id));
        match result {
            Some(Ok(())) => {
                pending.phase = PendingConvertPhase::SnapshotForPreparation { batch_id };
                self.pending_convert = Some(pending);
                self.canvas_status =
                    "Convert queued after accepted project writes; freezing the durable region"
                        .to_owned();
            }
            Some(Err(ProjectQueueError::QueueFull | ProjectQueueError::Backpressure { .. })) => {
                pending.phase = PendingConvertPhase::QueueSnapshotForPreparation { batch_id };
                self.pending_convert = Some(pending);
                self.canvas_status =
                    "Convert intent retained; waiting for project writer capacity".to_owned();
            }
            Some(Err(ProjectQueueError::WorkerStopped | ProjectQueueError::Stopped { .. }))
            | None => {
                self.canvas_status = "Convert unavailable: project writer stopped".to_owned();
            }
        }
        self.request_redraw();
    }

    fn cancel_convert(&mut self, message: String) {
        let Some(mut pending) = self.pending_convert.take() else {
            return;
        };
        if convert_phase_is_persisting(&pending.phase) {
            self.pending_convert = Some(pending);
            self.canvas_status =
                "Convert save is already queued; waiting for its durable result".to_owned();
            self.request_redraw();
            return;
        }
        if let PendingConvertPhase::Preparing { task, .. } = &mut pending.phase {
            task.cancel();
            pending.cancelled = true;
            self.pending_convert = Some(pending);
        } else {
            if let Some(worker) = self.provider_worker.take() {
                worker.cancel();
            }
        }
        self.canvas_status = message;
        self.request_redraw();
    }

    fn note_convert_view_change(&mut self) {
        self.convert_view_generation = self.convert_view_generation.saturating_add(1);
        if self.pending_convert.as_ref().is_some_and(|pending| {
            !matches!(&pending.phase, PendingConvertPhase::Persisting { .. })
        }) {
            self.cancel_convert(
                "Convert canceled because the selection or view changed".to_owned(),
            );
        }
    }

    fn convert_context_is_current(&self, pending: &PendingConvert) -> bool {
        let capture_pending_or_preview =
            self.deferred_capture_batch.is_some() || self.canvas_scene.has_preview_strokes();
        if capture_pending_or_preview {
            return convert_context_matches(
                pending,
                self.project_generation,
                self.convert_view_generation,
                None,
                true,
            );
        }
        let selected_strokes = self.canvas_scene.selected_targets().ok();
        convert_context_matches(
            pending,
            self.project_generation,
            self.convert_view_generation,
            selected_strokes.as_deref(),
            false,
        )
    }

    fn request_redraw(&self) {
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }

    fn correction_pane_text_width_px(&self) -> i32 {
        let client_width = self
            .client_size
            .map_or(i64::from(CORRECTION_PANE_WIDTH_PX), |(width, _)| {
                i64::from(width)
            });
        let pane_width = client_width.min(i64::from(CORRECTION_PANE_WIDTH_PX)).max(0);
        i32::try_from(
            pane_width.saturating_sub(i64::from(CORRECTION_PANE_PADDING_PX.saturating_mul(2))),
        )
        .unwrap_or(1)
        .max(1)
    }

    fn refresh_pane_text_measurement_target(&mut self) -> io::Result<()> {
        let hwnd = match self.window.as_ref() {
            None => None,
            Some(window) => {
                let hwnd = raw_window_hwnd(window).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "pane text measurement could not resolve the live window HWND",
                    )
                })?;
                if hwnd == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "pane text measurement rejects a null live window HWND",
                    ));
                }
                Some(hwnd)
            }
        };
        self.pane_text_measurements.set_hwnd(hwnd);
        Ok(())
    }

    fn correction_pane_layout(&mut self) -> io::Result<CorrectionPaneLayout> {
        self.refresh_pane_text_measurement_target()?;
        let text_width = self.correction_pane_text_width_px();
        let mut layout = CorrectionPaneLayout {
            lines: Vec::new(),
            editor_rows: None,
            editor_grapheme_ranges: Vec::new(),
            editor_row_hit_offsets: Vec::new(),
            action_row: None,
            action_hit_targets: Vec::new(),
            scroll_regions: Vec::new(),
            inline_editor_rows: Vec::new(),
            provider_path_row: None,
            provider_id_row: None,
            load_config_row: None,
            export_path_row: None,
        };
        append_pane_line(&mut layout, "RESULT / CORRECTION".to_owned());
        append_pane_line(&mut layout, "Wheel over text to scroll.".to_owned());
        let status_rows = measured_pane_text_rows(
            &self.correction_panel_status,
            text_width,
            &mut self.pane_text_measurements,
        )?;
        append_scrolled_measured_rows(
            &mut layout,
            CorrectionPaneTextSection::Status,
            &status_rows,
            2,
            self.correction_pane_scroll.status,
        );
        if let Some(session) = self.correction_session.as_ref() {
            let projection = session.projection();
            let candidate = session
                .candidates()
                .iter()
                .find(|candidate| candidate.rank == 0);
            let native_score = candidate
                .and_then(|candidate| candidate.native_score_raw.as_deref())
                .unwrap_or("unavailable");
            append_pane_line(&mut layout, "Provider details:".to_owned());
            let provider_details = format!(
                "Provider: {}\nProvider version: {}\nModel version: {}\nResource version: {}\nNative score: {} (uncalibrated)",
                projection.provider.provider_id,
                projection.provider.provider_version,
                projection
                    .provider
                    .model_version
                    .as_deref()
                    .unwrap_or("unavailable"),
                projection
                    .provider
                    .resource_version
                    .as_deref()
                    .unwrap_or("unavailable"),
                native_score,
            );
            let provider_detail_rows = measured_pane_text_rows(
                &provider_details,
                text_width,
                &mut self.pane_text_measurements,
            )?;
            append_scrolled_measured_rows(
                &mut layout,
                CorrectionPaneTextSection::ProviderDetails,
                &provider_detail_rows,
                4,
                self.correction_pane_scroll.provider_details,
            );
            append_pane_line(&mut layout, "Provider output (immutable):".to_owned());
            append_pane_line(&mut layout, "rank 0:".to_owned());
            let recognized_text = candidate.map_or("unavailable", |candidate| {
                candidate.recognized_text.as_str()
            });
            let wrapped = measured_pane_text_rows(
                recognized_text,
                text_width,
                &mut self.pane_text_measurements,
            )?;
            append_scrolled_measured_rows(
                &mut layout,
                CorrectionPaneTextSection::ProviderOutput,
                &wrapped,
                3,
                self.correction_pane_scroll.provider_output,
            );

            append_pane_line(
                &mut layout,
                format!(
                    "Corrections: {}; latest saved:",
                    session.correction_history().len()
                ),
            );
            let saved_text = match session.latest_saved_action() {
                Some(RegionCorrectionActionV1::SetText(text)) if text.is_empty() => {
                    "<empty>".to_owned()
                }
                Some(RegionCorrectionActionV1::SetText(text)) => text.clone(),
                Some(RegionCorrectionActionV1::Reset) => "Reset to provider output".to_owned(),
                None => "none".to_owned(),
            };
            let saved_rows =
                measured_pane_text_rows(&saved_text, text_width, &mut self.pane_text_measurements)?;
            append_scrolled_measured_rows(
                &mut layout,
                CorrectionPaneTextSection::SavedText,
                &saved_rows,
                2,
                self.correction_pane_scroll.saved_text,
            );
            append_pane_line(&mut layout, "Effective text:".to_owned());
            let effective = session.effective_text().unwrap_or("unavailable");
            let effective_rows =
                measured_pane_text_rows(effective, text_width, &mut self.pane_text_measurements)?;
            append_scrolled_measured_rows(
                &mut layout,
                CorrectionPaneTextSection::EffectiveText,
                &effective_rows,
                2,
                self.correction_pane_scroll.effective_text,
            );
            append_pane_line(
                &mut layout,
                if self.pending_correction.is_some() {
                    "Draft (save pending; editing paused):".to_owned()
                } else {
                    "Draft (click to edit):".to_owned()
                },
            );
            let editor_rows = measured_editor_display_rows(
                session.editor(),
                text_width,
                &mut self.pane_text_measurements,
            )?;
            append_scrolled_editor_rows(
                &mut layout,
                &editor_rows,
                CORRECTION_PANE_MAX_EDITOR_ROWS,
                self.correction_pane_scroll.draft,
            );
            if session.editor().has_preedit()
                && let Ok(preview) = session.ime_preview_text()
            {
                append_pane_line(
                    &mut layout,
                    "IME composition preview (not saved):".to_owned(),
                );
                let preview_rows = measured_pane_text_rows(
                    &preview,
                    text_width,
                    &mut self.pane_text_measurements,
                )?;
                append_scrolled_measured_rows(
                    &mut layout,
                    CorrectionPaneTextSection::ImePreview,
                    &preview_rows,
                    2,
                    self.correction_pane_scroll.ime_preview,
                );
            }
        } else {
            append_pane_line(&mut layout, "No stored projection is open.".to_owned());
            append_pane_line(
                &mut layout,
                "Select committed ink and press F4 to convert.".to_owned(),
            );
            append_pane_line(
                &mut layout,
                "Provider output and corrections appear here.".to_owned(),
            );
        }
        let action_label = "[Convert] [Save] [Reset] [Cancel] [Copy]";
        let action_row = append_pane_line(&mut layout, action_label.to_owned());
        layout.action_row = Some(action_row);
        layout.action_hit_targets =
            correction_action_hit_targets(action_label, &mut self.pane_text_measurements)?;

        append_pane_line(
            &mut layout,
            "Local provider setup (in memory only):".to_owned(),
        );
        let (provider_path_line, mut provider_path_layout) = inline_text_editor_line(
            "Config path: ",
            &self.provider_config_path_editor,
            InlineEditorField::ProviderConfigPath,
            text_width,
            &mut self.pane_text_measurements,
        )?;
        let provider_path_row = append_pane_line(&mut layout, provider_path_line);
        provider_path_layout.row_index = provider_path_row;
        layout.provider_path_row = Some(provider_path_row);
        layout.inline_editor_rows.push(provider_path_layout);
        let (provider_id_line, mut provider_id_layout) = inline_text_editor_line(
            "Provider ID: ",
            &self.provider_id_editor,
            InlineEditorField::ProviderId,
            text_width,
            &mut self.pane_text_measurements,
        )?;
        let provider_id_row = append_pane_line(&mut layout, provider_id_line);
        provider_id_layout.row_index = provider_id_row;
        layout.provider_id_row = Some(provider_id_row);
        layout.inline_editor_rows.push(provider_id_layout);
        layout.load_config_row = Some(append_pane_line(
            &mut layout,
            if self.local_convert_provider.is_some() {
                "[Load config] loaded".to_owned()
            } else {
                "[Load config] click to load".to_owned()
            },
        ));
        let (export_path_line, mut export_path_layout) = inline_text_editor_line(
            "Export path: ",
            &self.export_path_editor,
            InlineEditorField::ExportPath,
            text_width,
            &mut self.pane_text_measurements,
        )?;
        let export_path_row = append_pane_line(&mut layout, export_path_line);
        export_path_layout.row_index = export_path_row;
        layout.export_path_row = Some(export_path_row);
        layout.inline_editor_rows.push(export_path_layout);
        append_pane_line(&mut layout, "Export is not implemented.".to_owned());
        Ok(layout)
    }

    fn winit_mouse_input_targets_pane_action(
        &mut self,
        button: MouseButton,
        state: ElementState,
    ) -> bool {
        if button != MouseButton::Left || state != ElementState::Pressed {
            return false;
        }
        let (Some(cursor), Some((width, height))) = (self.canvas_cursor_client, self.client_size)
        else {
            return false;
        };
        let client_width = i32::try_from(width).unwrap_or(i32::MAX);
        let client_height = i32::try_from(height).unwrap_or(i32::MAX);
        let x = cursor.0.floor() as i32;
        let y = cursor.1.floor() as i32;
        if !correction_pane_contains_client_point(
            i64::from(x),
            i64::from(y),
            i64::from(client_width),
            i64::from(client_height),
        ) {
            return false;
        }
        let row = usize::try_from(
            y.saturating_sub(CORRECTION_PANE_PADDING_PX) / CORRECTION_PANE_ROW_HEIGHT_PX,
        )
        .unwrap_or(usize::MAX);
        match self.correction_pane_layout() {
            Ok(layout) => layout.action_row == Some(row) || layout.load_config_row == Some(row),
            Err(_) => true,
        }
    }

    fn handle_correction_pane_wheel(&mut self, delta: &MouseScrollDelta) -> bool {
        let (Some(cursor), Some((width, height))) = (self.canvas_cursor_client, self.client_size)
        else {
            return false;
        };
        let client_width = i32::try_from(width).unwrap_or(i32::MAX);
        let client_height = i32::try_from(height).unwrap_or(i32::MAX);
        let x = cursor.0.floor() as i32;
        let y = cursor.1.floor() as i32;
        if !correction_pane_contains_client_point(
            i64::from(x),
            i64::from(y),
            i64::from(client_width),
            i64::from(client_height),
        ) {
            return false;
        }

        let row = usize::try_from(
            y.saturating_sub(CORRECTION_PANE_PADDING_PX) / CORRECTION_PANE_ROW_HEIGHT_PX,
        )
        .unwrap_or(usize::MAX);
        let layout = match self.correction_pane_layout() {
            Ok(layout) => layout,
            Err(_) => {
                self.correction_panel_status =
                    "Text measurement is unavailable; pane scrolling is paused.".to_owned();
                self.request_redraw();
                return true;
            }
        };
        let Some(region) = layout
            .scroll_regions
            .iter()
            .find(|region| region.row_range.contains(&row))
        else {
            return true;
        };
        let section = region.section;
        let total_rows = region.total_rows;
        let visible_rows = region.visible_rows;
        let wheel_rows = match delta {
            MouseScrollDelta::LineDelta(_, vertical) => f64::from(*vertical),
            MouseScrollDelta::PixelDelta(position) => {
                position.y / f64::from(CORRECTION_PANE_ROW_HEIGHT_PX)
            }
        };
        let maximum = total_rows.saturating_sub(visible_rows);
        let current = self.correction_pane_scroll.get(section);
        let mut next = correction_pane_scroll_offset(current, wheel_rows, maximum);
        if section == CorrectionPaneTextSection::Draft
            && self.correction_focus == CorrectionPaneFocus::CorrectionEditor
        {
            let Some(session) = self.correction_session.as_ref() else {
                return true;
            };
            let cursor = session.editor().cursor_grapheme();
            let rows = match measured_editor_display_rows(
                session.editor(),
                self.correction_pane_text_width_px(),
                &mut self.pane_text_measurements,
            ) {
                Ok(rows) => rows,
                Err(_) => {
                    self.correction_panel_status =
                        "Text measurement is unavailable; pane scrolling is paused.".to_owned();
                    self.request_redraw();
                    return true;
                }
            };
            let caret_row = rows
                .iter()
                .position(|(_, range, _)| cursor >= range.start && cursor <= range.end)
                .unwrap_or_else(|| rows.len().saturating_sub(1));
            if self.focused_ime_preedit_active() {
                let first_offset = caret_row.saturating_sub(visible_rows.saturating_sub(1));
                next = next.clamp(first_offset, caret_row.min(maximum));
            } else {
                let caret_visible =
                    caret_row >= next && caret_row < next.saturating_add(visible_rows);
                if !caret_visible {
                    self.correction_editor_browse_mode = true;
                    if let Some(window) = self.window.as_ref() {
                        window.set_ime_allowed(false);
                    }
                } else if self.correction_editor_browse_mode {
                    self.correction_editor_browse_mode = false;
                    if let Some(window) = self.window.as_ref() {
                        window.set_ime_allowed(true);
                    }
                }
            }
        }
        if next != current {
            self.correction_pane_scroll.set(section, next);
            self.request_redraw();
        }
        if section == CorrectionPaneTextSection::Draft
            && self.correction_focus == CorrectionPaneFocus::CorrectionEditor
            && !self.correction_editor_browse_mode
        {
            self.update_ime_cursor_area();
        }
        true
    }

    fn focused_text(&self) -> Option<&str> {
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor => self
                .correction_session
                .as_ref()
                .map(|session| session.editor().text()),
            CorrectionPaneFocus::ProviderConfigPath => {
                Some(self.provider_config_path_editor.text())
            }
            CorrectionPaneFocus::ProviderId => Some(self.provider_id_editor.text()),
            CorrectionPaneFocus::ExportPath => Some(self.export_path_editor.text()),
            CorrectionPaneFocus::None => None,
        }
    }

    fn focused_selected_text(&self) -> Option<&str> {
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor => self
                .correction_session
                .as_ref()
                .and_then(CorrectionSession::selected_text),
            CorrectionPaneFocus::ProviderConfigPath => {
                self.provider_config_path_editor.selected_text()
            }
            CorrectionPaneFocus::ProviderId => self.provider_id_editor.selected_text(),
            CorrectionPaneFocus::ExportPath => self.export_path_editor.selected_text(),
            CorrectionPaneFocus::None => None,
        }
    }

    fn focused_ime_preedit_active(&self) -> bool {
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor => self
                .correction_session
                .as_ref()
                .is_some_and(|session| session.editor().has_preedit()),
            CorrectionPaneFocus::ProviderConfigPath => {
                self.provider_config_path_editor.has_preedit()
            }
            CorrectionPaneFocus::ProviderId => self.provider_id_editor.has_preedit(),
            CorrectionPaneFocus::ExportPath => self.export_path_editor.has_preedit(),
            CorrectionPaneFocus::None => false,
        }
    }

    fn provider_setup_fields_locked(&self) -> bool {
        self.pending_convert.is_some() || self.provider_worker.is_some()
    }

    fn set_correction_focus(&mut self, focus: CorrectionPaneFocus) {
        if focus != CorrectionPaneFocus::CorrectionEditor {
            self.correction_editor_browse_mode = false;
        }
        if self.correction_focus != focus {
            match self.correction_focus {
                CorrectionPaneFocus::CorrectionEditor => {
                    if let Some(session) = self.correction_session.as_mut() {
                        session.cancel_ime_preedit();
                    }
                }
                CorrectionPaneFocus::ProviderConfigPath => {
                    self.provider_config_path_editor.cancel_preedit();
                }
                CorrectionPaneFocus::ProviderId => {
                    self.provider_id_editor.cancel_preedit();
                }
                CorrectionPaneFocus::ExportPath => {
                    self.export_path_editor.cancel_preedit();
                }
                CorrectionPaneFocus::None => {}
            }
        }
        if focus == CorrectionPaneFocus::CorrectionEditor {
            if self.correction_session.is_none() {
                self.correction_panel_status = "There is no stored projection to edit.".to_owned();
                self.request_redraw();
                return;
            }
            if self.pending_correction.is_some() {
                self.correction_panel_status =
                    "Editing is paused until the pending save is acknowledged.".to_owned();
                self.request_redraw();
                return;
            }
            if let Some(session) = self.correction_session.as_mut()
                && session.prepare_editor_for_edit().is_err()
            {
                self.correction_panel_status =
                    "The stored correction text could not be opened for editing.".to_owned();
                self.request_redraw();
                return;
            }
        }
        self.correction_focus = focus;
        let has_window = self.window.is_some();
        if let Some(window) = self.window.as_ref() {
            window.set_ime_allowed(focus.is_text_field());
        }
        if has_window && focus.is_text_field() {
            self.update_ime_cursor_area();
        }
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }

    fn ensure_correction_editor_caret_visible(&mut self) -> io::Result<()> {
        if self.correction_focus != CorrectionPaneFocus::CorrectionEditor {
            return Ok(());
        }
        self.refresh_pane_text_measurement_target()?;
        let Some(session) = self.correction_session.as_ref() else {
            return Ok(());
        };
        let rows = measured_editor_display_rows(
            session.editor(),
            self.correction_pane_text_width_px(),
            &mut self.pane_text_measurements,
        )?;
        let cursor = session.editor().cursor_grapheme();
        let caret_row = rows
            .iter()
            .position(|(_, range, _)| cursor >= range.start && cursor <= range.end)
            .unwrap_or_else(|| rows.len().saturating_sub(1));
        self.correction_pane_scroll.draft = correction_editor_scroll_offset_for_caret(
            self.correction_pane_scroll.draft,
            caret_row,
            rows.len(),
            CORRECTION_PANE_MAX_EDITOR_ROWS,
        );
        if self.correction_editor_browse_mode {
            self.correction_editor_browse_mode = false;
            if let Some(window) = self.window.as_ref() {
                window.set_ime_allowed(true);
            }
        }
        Ok(())
    }

    fn ensure_focused_text_layout(&mut self) -> io::Result<()> {
        let focus = self.correction_focus;
        self.correction_pane_layout()?;
        if focus == CorrectionPaneFocus::CorrectionEditor {
            self.ensure_correction_editor_caret_visible()?;
        }
        Ok(())
    }

    fn prepare_focused_text_input(&mut self) -> bool {
        let measurement_available = self.ensure_focused_text_layout().is_ok();
        if focused_text_measurement_allows_input(self.correction_focus, measurement_available) {
            return true;
        }
        self.correction_panel_status =
            "Text measurement is unavailable; focused text input is paused.".to_owned();
        if let Some(window) = self.window.as_ref() {
            window.set_ime_allowed(false);
        }
        self.request_redraw();
        false
    }

    fn update_ime_cursor_area(&mut self) {
        if self.correction_focus == CorrectionPaneFocus::CorrectionEditor
            && self.correction_editor_browse_mode
        {
            return;
        }
        if self.correction_focus == CorrectionPaneFocus::CorrectionEditor
            && self.ensure_correction_editor_caret_visible().is_err()
        {
            if let Some(window) = self.window.as_ref() {
                window.set_ime_allowed(false);
            }
            return;
        }
        if let Some(window) = self.window.as_ref() {
            window.set_ime_allowed(false);
        }
        let Some((width, _)) = self.client_size else {
            return;
        };
        let Ok(layout) = self.correction_pane_layout() else {
            return;
        };
        let (row, x_offset) = match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor => {
                let cursor = self
                    .correction_session
                    .as_ref()
                    .map_or(0, |session| session.editor().cursor_grapheme());
                let Some(editor_rows) = layout.editor_rows.as_ref() else {
                    return;
                };
                let row_index = layout
                    .editor_grapheme_ranges
                    .iter()
                    .position(|range| cursor >= range.start && cursor <= range.end);
                let Some(row_index) = row_index else {
                    return;
                };
                let range = &layout.editor_grapheme_ranges[row_index];
                let boundary = cursor
                    .saturating_sub(range.start)
                    .min(range.end.saturating_sub(range.start));
                let Some(x) = layout.editor_row_hit_offsets[row_index]
                    .get(boundary)
                    .copied()
                else {
                    return;
                };
                (editor_rows.start.saturating_add(row_index), x)
            }
            focus @ (CorrectionPaneFocus::ProviderConfigPath
            | CorrectionPaneFocus::ProviderId
            | CorrectionPaneFocus::ExportPath) => {
                let (field, cursor) = match focus {
                    CorrectionPaneFocus::ProviderConfigPath => (
                        InlineEditorField::ProviderConfigPath,
                        self.provider_config_path_editor.cursor_grapheme(),
                    ),
                    CorrectionPaneFocus::ProviderId => (
                        InlineEditorField::ProviderId,
                        self.provider_id_editor.cursor_grapheme(),
                    ),
                    CorrectionPaneFocus::ExportPath => (
                        InlineEditorField::ExportPath,
                        self.export_path_editor.cursor_grapheme(),
                    ),
                    _ => return,
                };
                let Some(inline) = layout
                    .inline_editor_rows
                    .iter()
                    .find(|inline| inline.field == field)
                else {
                    return;
                };
                let boundary = cursor.saturating_sub(inline.visible_graphemes.start).min(
                    inline
                        .visible_graphemes
                        .end
                        .saturating_sub(inline.visible_graphemes.start),
                );
                let Some(x) = inline.boundary_x.get(boundary).copied() else {
                    return;
                };
                (inline.row_index, x)
            }
            CorrectionPaneFocus::None => return,
        };
        let Some(window) = self.window.as_ref() else {
            return;
        };
        let client_width = i32::try_from(width).unwrap_or(i32::MAX);
        let pane_left = correction_pane_left_edge_i32(client_width);
        let x = pane_left
            .saturating_add(CORRECTION_PANE_PADDING_PX)
            .saturating_add(x_offset)
            .clamp(0, client_width.saturating_sub(1).max(0));
        let y = CORRECTION_PANE_PADDING_PX.saturating_add(
            i32::try_from(row)
                .unwrap_or(i32::MAX)
                .saturating_mul(CORRECTION_PANE_ROW_HEIGHT_PX),
        );
        window.set_ime_allowed(true);
        window.set_ime_cursor_area(
            PhysicalPosition::new(x, y),
            PhysicalSize::new(1, u32::try_from(CORRECTION_PANE_ROW_HEIGHT_PX).unwrap_or(1)),
        );
    }

    fn focused_insert_text(&mut self, text: &str) {
        if self.correction_focus.is_text_field() && !self.prepare_focused_text_input() {
            return;
        }
        if matches!(
            self.correction_focus,
            CorrectionPaneFocus::ProviderConfigPath | CorrectionPaneFocus::ProviderId
        ) && self.provider_setup_fields_locked()
        {
            self.correction_panel_status =
                "Provider configuration is locked while Convert is active.".to_owned();
            self.request_redraw();
            return;
        }
        let result = match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor => {
                if self.pending_correction.is_some() {
                    return;
                }
                self.correction_session
                    .as_mut()
                    .map(|session| session.insert_text(text))
            }
            CorrectionPaneFocus::ProviderConfigPath => {
                Some(self.provider_config_path_editor.insert_text(text))
            }
            CorrectionPaneFocus::ProviderId => Some(self.provider_id_editor.insert_text(text)),
            CorrectionPaneFocus::ExportPath => Some(self.export_path_editor.insert_text(text)),
            CorrectionPaneFocus::None => None,
        };
        self.note_editor_result(result);
    }

    fn focused_insert_newline(&mut self) {
        if matches!(
            self.correction_focus,
            CorrectionPaneFocus::ProviderConfigPath | CorrectionPaneFocus::ProviderId
        ) && self.provider_setup_fields_locked()
        {
            self.correction_panel_status =
                "Provider configuration is locked while Convert is active.".to_owned();
            self.request_redraw();
            return;
        }
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor if self.pending_correction.is_none() => {
                let result = self
                    .correction_session
                    .as_mut()
                    .map(|session| session.insert_newline());
                self.note_editor_result(result);
            }
            CorrectionPaneFocus::ProviderConfigPath => {
                let result = self.provider_config_path_editor.insert_newline();
                self.note_editor_result(Some(result));
            }
            CorrectionPaneFocus::ProviderId => {
                let result = self.provider_id_editor.insert_newline();
                self.note_editor_result(Some(result));
            }
            CorrectionPaneFocus::ExportPath => {
                let result = self.export_path_editor.insert_newline();
                self.note_editor_result(Some(result));
            }
            _ => {}
        }
    }

    fn focused_delete(&mut self, backward: bool) {
        if matches!(
            self.correction_focus,
            CorrectionPaneFocus::ProviderConfigPath | CorrectionPaneFocus::ProviderId
        ) && self.provider_setup_fields_locked()
        {
            self.correction_panel_status =
                "Provider configuration is locked while Convert is active.".to_owned();
            self.request_redraw();
            return;
        }
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor if self.pending_correction.is_none() => {
                let result = self.correction_session.as_mut().map(|session| {
                    if backward {
                        session.delete_backward()
                    } else {
                        session.delete_forward()
                    }
                });
                self.note_editor_result(result);
            }
            CorrectionPaneFocus::ProviderConfigPath => {
                let result = if backward {
                    self.provider_config_path_editor.delete_backward()
                } else {
                    self.provider_config_path_editor.delete_forward()
                };
                self.note_editor_result(Some(result));
            }
            CorrectionPaneFocus::ProviderId => {
                let result = if backward {
                    self.provider_id_editor.delete_backward()
                } else {
                    self.provider_id_editor.delete_forward()
                };
                self.note_editor_result(Some(result));
            }
            CorrectionPaneFocus::ExportPath => {
                let result = if backward {
                    self.export_path_editor.delete_backward()
                } else {
                    self.export_path_editor.delete_forward()
                };
                self.note_editor_result(Some(result));
            }
            _ => {}
        }
    }

    fn focused_move_cursor(&mut self, right: bool, extend: bool) {
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor if self.pending_correction.is_none() => {
                if let Some(session) = self.correction_session.as_mut() {
                    match (right, extend) {
                        (true, true) => session.move_cursor_right_extending_selection(),
                        (false, true) => session.move_cursor_left_extending_selection(),
                        (true, false) => session.move_cursor_right(),
                        (false, false) => session.move_cursor_left(),
                    }
                }
            }
            CorrectionPaneFocus::ProviderConfigPath => {
                move_text_editor_cursor(&mut self.provider_config_path_editor, right, extend)
            }
            CorrectionPaneFocus::ProviderId => {
                move_text_editor_cursor(&mut self.provider_id_editor, right, extend)
            }
            CorrectionPaneFocus::ExportPath => {
                move_text_editor_cursor(&mut self.export_path_editor, right, extend)
            }
            _ => {}
        }
        self.request_redraw();
        self.update_ime_cursor_area();
    }

    fn focused_move_vertical(&mut self, down: bool, extend: bool) {
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor if self.pending_correction.is_none() => {
                let visual_rows = self.refresh_pane_text_measurement_target().and_then(|()| {
                    if let Some(session) = self.correction_session.as_ref() {
                        measured_editor_display_rows(
                            session.editor(),
                            self.correction_pane_text_width_px(),
                            &mut self.pane_text_measurements,
                        )
                        .map(|rows| {
                            rows.into_iter()
                                .map(|(_, range, _)| range)
                                .collect::<Vec<_>>()
                        })
                    } else {
                        Ok(Vec::new())
                    }
                });
                match visual_rows {
                    Ok(visual_rows) => {
                        if let Some(session) = self.correction_session.as_mut() {
                            session.move_cursor_on_visual_rows(
                                &visual_rows,
                                if down { 1 } else { -1 },
                                extend,
                            );
                        }
                    }
                    Err(_) => {
                        self.correction_panel_status =
                            "Text measurement is unavailable; correction editing is paused."
                                .to_owned();
                    }
                }
            }
            CorrectionPaneFocus::ProviderConfigPath => {
                if down {
                    self.provider_config_path_editor.move_cursor_down(extend);
                } else {
                    self.provider_config_path_editor.move_cursor_up(extend);
                }
            }
            CorrectionPaneFocus::ProviderId => {
                if down {
                    self.provider_id_editor.move_cursor_down(extend);
                } else {
                    self.provider_id_editor.move_cursor_up(extend);
                }
            }
            CorrectionPaneFocus::ExportPath => {
                if down {
                    self.export_path_editor.move_cursor_down(extend);
                } else {
                    self.export_path_editor.move_cursor_up(extend);
                }
            }
            _ => {}
        }
        self.request_redraw();
        self.update_ime_cursor_area();
    }

    fn focused_move_line_edge(&mut self, end: bool, extend: bool) {
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor if self.pending_correction.is_none() => {
                if let Some(session) = self.correction_session.as_mut() {
                    if end {
                        session.move_to_line_end(extend);
                    } else {
                        session.move_to_line_start(extend);
                    }
                }
            }
            CorrectionPaneFocus::ProviderConfigPath => {
                if end {
                    self.provider_config_path_editor.move_to_line_end(extend);
                } else {
                    self.provider_config_path_editor.move_to_line_start(extend);
                }
            }
            CorrectionPaneFocus::ProviderId => {
                if end {
                    self.provider_id_editor.move_to_line_end(extend);
                } else {
                    self.provider_id_editor.move_to_line_start(extend);
                }
            }
            CorrectionPaneFocus::ExportPath => {
                if end {
                    self.export_path_editor.move_to_line_end(extend);
                } else {
                    self.export_path_editor.move_to_line_start(extend);
                }
            }
            _ => {}
        }
        self.request_redraw();
        self.update_ime_cursor_area();
    }

    fn focused_set_cursor(&mut self, cursor: usize) {
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor if self.pending_correction.is_none() => {
                if let Some(session) = self.correction_session.as_mut() {
                    session.set_cursor_grapheme(cursor);
                }
            }
            CorrectionPaneFocus::ProviderConfigPath => {
                self.provider_config_path_editor.set_cursor_grapheme(cursor)
            }
            CorrectionPaneFocus::ProviderId => self.provider_id_editor.set_cursor_grapheme(cursor),
            CorrectionPaneFocus::ExportPath => self.export_path_editor.set_cursor_grapheme(cursor),
            _ => {}
        }
        self.request_redraw();
        self.update_ime_cursor_area();
    }

    fn focused_select_graphemes(&mut self, start: usize, end: usize) {
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor if self.pending_correction.is_none() => {
                if let Some(session) = self.correction_session.as_mut() {
                    session.select_graphemes(start, end);
                }
            }
            CorrectionPaneFocus::ProviderConfigPath => self
                .provider_config_path_editor
                .select_graphemes(start, end),
            CorrectionPaneFocus::ProviderId => self.provider_id_editor.select_graphemes(start, end),
            CorrectionPaneFocus::ExportPath => self.export_path_editor.select_graphemes(start, end),
            _ => {}
        }
        self.request_redraw();
    }

    fn correction_text_caret_at(&mut self, cursor: (f64, f64)) -> Option<usize> {
        let (width, height) = self.client_size?;
        let client_width = i32::try_from(width).unwrap_or(i32::MAX);
        let client_height = i32::try_from(height).unwrap_or(i32::MAX);
        let pane_left = correction_pane_left_edge_i32(client_width);
        let x = cursor.0.floor() as i32;
        let y = cursor.1.floor() as i32;
        let local_y = y.saturating_sub(CORRECTION_PANE_PADDING_PX);
        if !correction_pane_contains_client_point(
            i64::from(x),
            i64::from(y),
            i64::from(client_width),
            i64::from(client_height),
        ) {
            return None;
        }
        let row = usize::try_from(local_y / CORRECTION_PANE_ROW_HEIGHT_PX).ok()?;
        let layout = self.correction_pane_layout().ok()?;
        let rows = layout.editor_rows?;
        if !rows.contains(&row) {
            return None;
        }
        let relative_row = row.saturating_sub(rows.start);
        let range = layout.editor_grapheme_ranges.get(relative_row)?;
        let boundary_x = layout.editor_row_hit_offsets.get(relative_row)?;
        let content_x = x
            .saturating_sub(pane_left)
            .saturating_sub(CORRECTION_PANE_PADDING_PX)
            .max(0);
        let column = nearest_grapheme_boundary(boundary_x, content_x);
        Some(
            range
                .start
                .saturating_add(column.min(range.end.saturating_sub(range.start))),
        )
    }

    fn handle_correction_mouse_button(&mut self, button: MouseButton, state: ElementState) -> bool {
        if button == MouseButton::Left
            && state == ElementState::Released
            && self.correction_mouse_selecting
        {
            if let (Some(cursor), Some(anchor)) = (
                self.canvas_cursor_client,
                self.correction_mouse_selection_anchor,
            ) && let Some(caret) = self.correction_text_caret_at(cursor)
            {
                self.focused_select_graphemes(anchor, caret);
            }
            self.correction_mouse_selecting = false;
            return true;
        }
        if state == ElementState::Released
            && ((button == MouseButton::Left
                && (self.canvas_selection_drag_start.is_some()
                    || self.canvas_move_drag_start.is_some()))
                || (matches!(button, MouseButton::Middle | MouseButton::Right)
                    && self.canvas_pan_drag_last.is_some()))
        {
            // A gesture that began on the canvas keeps its original owner even
            // when its release lands over the overlay pane.
            return false;
        }
        let Some(cursor) = self.canvas_cursor_client else {
            return false;
        };
        let Some((width, height)) = self.client_size else {
            return false;
        };
        let client_width = i32::try_from(width).unwrap_or(i32::MAX);
        let client_height = i32::try_from(height).unwrap_or(i32::MAX);
        let pane_left = correction_pane_left_edge_i32(client_width);
        let x = cursor.0.floor() as i32;
        let y = cursor.1.floor() as i32;
        if !correction_pane_contains_client_point(
            i64::from(x),
            i64::from(y),
            i64::from(client_width),
            i64::from(client_height),
        ) {
            return false;
        }
        if button != MouseButton::Left {
            return true;
        }
        if state == ElementState::Released {
            return true;
        }

        self.canvas_pan_drag_last = None;
        self.canvas_selection_drag_start = None;
        self.canvas_move_drag_start = None;
        self.canvas_scene.set_selection_rect(None);
        self.correction_mouse_selecting = false;
        let row = usize::try_from(
            y.saturating_sub(CORRECTION_PANE_PADDING_PX) / CORRECTION_PANE_ROW_HEIGHT_PX,
        )
        .unwrap_or(usize::MAX);
        let Ok(layout) = self.correction_pane_layout() else {
            return true;
        };
        if layout.action_row == Some(row) {
            let action_offset = x
                .saturating_sub(pane_left)
                .saturating_sub(CORRECTION_PANE_PADDING_PX);
            if let Some((_, action)) = layout
                .action_hit_targets
                .iter()
                .find(|(target, _)| target.contains(&action_offset))
            {
                self.dispatch_pane_action(*action);
            }
            return true;
        }
        if layout.load_config_row == Some(row) {
            self.dispatch_pane_action(CorrectionPaneAction::LoadProviderConfig);
            return true;
        }
        if layout.provider_path_row == Some(row) {
            let cursor = inline_editor_cursor_at(
                &layout,
                InlineEditorField::ProviderConfigPath,
                row,
                x.saturating_sub(pane_left)
                    .saturating_sub(CORRECTION_PANE_PADDING_PX),
            )
            .unwrap_or_default();
            self.set_correction_focus(CorrectionPaneFocus::ProviderConfigPath);
            self.provider_config_path_editor
                .set_cursor_grapheme(cursor.min(self.provider_config_path_editor.grapheme_count()));
            self.update_ime_cursor_area();
            return true;
        }
        if layout.provider_id_row == Some(row) {
            let cursor = inline_editor_cursor_at(
                &layout,
                InlineEditorField::ProviderId,
                row,
                x.saturating_sub(pane_left)
                    .saturating_sub(CORRECTION_PANE_PADDING_PX),
            )
            .unwrap_or_default();
            self.set_correction_focus(CorrectionPaneFocus::ProviderId);
            self.provider_id_editor
                .set_cursor_grapheme(cursor.min(self.provider_id_editor.grapheme_count()));
            self.update_ime_cursor_area();
            return true;
        }
        if layout.export_path_row == Some(row) {
            let cursor = inline_editor_cursor_at(
                &layout,
                InlineEditorField::ExportPath,
                row,
                x.saturating_sub(pane_left)
                    .saturating_sub(CORRECTION_PANE_PADDING_PX),
            )
            .unwrap_or_default();
            self.set_correction_focus(CorrectionPaneFocus::ExportPath);
            self.export_path_editor
                .set_cursor_grapheme(cursor.min(self.export_path_editor.grapheme_count()));
            self.update_ime_cursor_area();
            return true;
        }
        if layout
            .editor_rows
            .as_ref()
            .is_some_and(|rows| rows.contains(&row))
        {
            self.correction_editor_browse_mode = false;
            self.set_correction_focus(CorrectionPaneFocus::CorrectionEditor);
            if self.correction_focus == CorrectionPaneFocus::CorrectionEditor {
                let Some(caret) = self.correction_text_caret_at(cursor) else {
                    return true;
                };
                self.focused_set_cursor(caret);
                self.correction_mouse_selection_anchor = Some(caret);
                self.correction_mouse_selecting = true;
            }
            return true;
        }
        self.set_correction_focus(CorrectionPaneFocus::None);
        true
    }

    fn handle_focused_text_key(&mut self, event: &winit::event::KeyEvent) -> bool {
        if !self.correction_focus.is_text_field() {
            return false;
        }
        if event.logical_key == Key::Named(NamedKey::AltGraph) {
            self.alt_graph_active = event.state == ElementState::Pressed;
            return true;
        }
        if !self.prepare_focused_text_input() {
            return true;
        }
        if !should_process_focused_text_key(event.state, event.repeat) {
            return true;
        }
        if self.correction_focus == CorrectionPaneFocus::CorrectionEditor
            && self.pending_correction.is_some()
        {
            self.correction_panel_status =
                "Editing is paused until the pending save is acknowledged.".to_owned();
            self.request_redraw();
            return true;
        }
        if matches!(
            self.correction_focus,
            CorrectionPaneFocus::ProviderConfigPath | CorrectionPaneFocus::ProviderId
        ) && self.provider_setup_fields_locked()
        {
            self.correction_panel_status =
                "Provider configuration is locked while Convert is active.".to_owned();
            self.request_redraw();
            return true;
        }
        if self.focused_ime_preedit_active() {
            if event.physical_key == PhysicalKey::Code(KeyCode::Escape) {
                match self.correction_focus {
                    CorrectionPaneFocus::CorrectionEditor => {
                        if let Some(session) = self.correction_session.as_mut() {
                            session.cancel_ime_preedit();
                        }
                    }
                    CorrectionPaneFocus::ProviderConfigPath => {
                        self.provider_config_path_editor.cancel_preedit();
                    }
                    CorrectionPaneFocus::ProviderId => {
                        self.provider_id_editor.cancel_preedit();
                    }
                    CorrectionPaneFocus::ExportPath => {
                        self.export_path_editor.cancel_preedit();
                    }
                    CorrectionPaneFocus::None => {}
                }
                self.request_redraw();
            }
            // During composition the IME owns navigation/edit keys. In particular,
            // do not commit ordinary KeyEvent text alongside Ime::Commit.
            return true;
        }
        let control = self.canvas_modifiers.control_key();
        let shift = self.canvas_modifiers.shift_key();
        let alt_gr = self.alt_graph_active;
        let control_alt_shortcut =
            is_control_alt_shortcut(control, self.canvas_modifiers.alt_key(), alt_gr);
        if control_alt_shortcut {
            return true;
        }
        match event.physical_key {
            PhysicalKey::Code(KeyCode::Escape) => {
                if self.correction_focus == CorrectionPaneFocus::CorrectionEditor {
                    self.cancel_correction_draft();
                } else {
                    self.set_correction_focus(CorrectionPaneFocus::None);
                }
            }
            PhysicalKey::Code(KeyCode::Enter)
                if control && self.correction_focus == CorrectionPaneFocus::CorrectionEditor =>
            {
                self.save_correction()
            }
            PhysicalKey::Code(KeyCode::Enter) if control => {}
            PhysicalKey::Code(KeyCode::Enter) => self.focused_insert_newline(),
            PhysicalKey::Code(KeyCode::Backspace) => self.focused_delete(true),
            PhysicalKey::Code(KeyCode::Delete) => self.focused_delete(false),
            PhysicalKey::Code(KeyCode::ArrowLeft) => self.focused_move_cursor(false, shift),
            PhysicalKey::Code(KeyCode::ArrowRight) => self.focused_move_cursor(true, shift),
            PhysicalKey::Code(KeyCode::ArrowUp) => self.focused_move_vertical(false, shift),
            PhysicalKey::Code(KeyCode::ArrowDown) => self.focused_move_vertical(true, shift),
            PhysicalKey::Code(KeyCode::Home) => self.focused_move_line_edge(false, shift),
            PhysicalKey::Code(KeyCode::End) => self.focused_move_line_edge(true, shift),
            PhysicalKey::Code(KeyCode::KeyA) if control => self.focused_select_all(),
            PhysicalKey::Code(KeyCode::KeyC) if control => self.copy_focused_text(),
            PhysicalKey::Code(KeyCode::KeyV) if control => self.paste_focused_text(),
            PhysicalKey::Code(KeyCode::KeyZ) if control => self.focused_undo_redo(false),
            PhysicalKey::Code(KeyCode::KeyY) if control => self.focused_undo_redo(true),
            PhysicalKey::Code(KeyCode::KeyS)
                if control && self.correction_focus == CorrectionPaneFocus::CorrectionEditor =>
            {
                self.save_correction()
            }
            _ => {
                // With the pinned Winit Windows backend, IME WM_CHAR messages
                // without a pending key event are dropped by its keyboard
                // builder and delivered through Ime::Commit instead. During
                // visible preedit the guard above also suppresses KeyEvent text.
                if should_insert_keyboard_text(
                    control,
                    self.canvas_modifiers.alt_key(),
                    alt_gr,
                    self.focused_ime_preedit_active(),
                    event.text.is_some(),
                ) && let Some(text) = event.text.as_ref()
                    && !text.chars().all(char::is_control)
                {
                    self.focused_insert_text(text.as_str());
                }
            }
        }
        self.request_redraw();
        true
    }

    fn handle_ime_event(&mut self, event: Ime) {
        if !self.correction_focus.is_text_field() {
            return;
        }
        if !self.prepare_focused_text_input() {
            return;
        }
        if matches!(
            self.correction_focus,
            CorrectionPaneFocus::ProviderConfigPath | CorrectionPaneFocus::ProviderId
        ) && self.provider_setup_fields_locked()
        {
            self.correction_panel_status =
                "Provider configuration is locked while Convert is active.".to_owned();
            self.request_redraw();
            return;
        }
        match event {
            Ime::Enabled => self.update_ime_cursor_area(),
            Ime::Preedit(text, _) => {
                if self.correction_focus == CorrectionPaneFocus::CorrectionEditor
                    && self.pending_correction.is_some()
                {
                    return;
                }
                let result = match self.correction_focus {
                    CorrectionPaneFocus::CorrectionEditor => self
                        .correction_session
                        .as_mut()
                        .map(|session| session.update_ime_preedit(&text).map(|()| true)),
                    CorrectionPaneFocus::ProviderConfigPath => {
                        let has_composition = !text.is_empty();
                        Some(
                            self.provider_config_path_editor
                                .update_preedit(&text)
                                .map(|()| has_composition),
                        )
                    }
                    CorrectionPaneFocus::ProviderId => {
                        let has_composition = !text.is_empty();
                        Some(
                            self.provider_id_editor
                                .update_preedit(&text)
                                .map(|()| has_composition),
                        )
                    }
                    CorrectionPaneFocus::ExportPath => Some(
                        self.export_path_editor
                            .update_preedit(&text)
                            .map(|()| false),
                    ),
                    CorrectionPaneFocus::None => None,
                };
                self.note_editor_result(result);
            }
            Ime::Commit(text) => {
                if self.correction_focus == CorrectionPaneFocus::CorrectionEditor
                    && self.pending_correction.is_some()
                {
                    return;
                }
                let result = match self.correction_focus {
                    CorrectionPaneFocus::CorrectionEditor => self
                        .correction_session
                        .as_mut()
                        .map(|session| session.commit_ime_text(&text)),
                    CorrectionPaneFocus::ProviderConfigPath => {
                        Some(self.provider_config_path_editor.commit_ime_text(&text))
                    }
                    CorrectionPaneFocus::ProviderId => {
                        Some(self.provider_id_editor.commit_ime_text(&text))
                    }
                    CorrectionPaneFocus::ExportPath => {
                        Some(self.export_path_editor.commit_ime_text(&text))
                    }
                    CorrectionPaneFocus::None => None,
                };
                self.note_editor_result(result);
            }
            Ime::Disabled => {
                match self.correction_focus {
                    CorrectionPaneFocus::CorrectionEditor => {
                        if let Some(session) = self.correction_session.as_mut() {
                            session.cancel_ime_preedit();
                        }
                    }
                    CorrectionPaneFocus::ProviderConfigPath => {
                        self.provider_config_path_editor.cancel_preedit();
                    }
                    CorrectionPaneFocus::ProviderId => {
                        self.provider_id_editor.cancel_preedit();
                    }
                    CorrectionPaneFocus::ExportPath => {
                        self.export_path_editor.cancel_preedit();
                    }
                    CorrectionPaneFocus::None => {}
                }
                self.request_redraw();
            }
        }
    }

    fn focused_select_all(&mut self) {
        match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor if self.pending_correction.is_none() => {
                if let Some(session) = self.correction_session.as_mut() {
                    session.select_all();
                }
            }
            CorrectionPaneFocus::ProviderConfigPath => {
                self.provider_config_path_editor.select_all()
            }
            CorrectionPaneFocus::ProviderId => self.provider_id_editor.select_all(),
            CorrectionPaneFocus::ExportPath => self.export_path_editor.select_all(),
            _ => {}
        }
        self.request_redraw();
    }

    fn focused_undo_redo(&mut self, redo: bool) {
        let changed = match self.correction_focus {
            CorrectionPaneFocus::CorrectionEditor if self.pending_correction.is_none() => self
                .correction_session
                .as_mut()
                .is_some_and(|session| if redo { session.redo() } else { session.undo() }),
            CorrectionPaneFocus::ProviderConfigPath => {
                if redo {
                    self.provider_config_path_editor.redo()
                } else {
                    self.provider_config_path_editor.undo()
                }
            }
            CorrectionPaneFocus::ProviderId => {
                if redo {
                    self.provider_id_editor.redo()
                } else {
                    self.provider_id_editor.undo()
                }
            }
            CorrectionPaneFocus::ExportPath => {
                if redo {
                    self.export_path_editor.redo()
                } else {
                    self.export_path_editor.undo()
                }
            }
            _ => false,
        };
        if changed {
            if matches!(
                self.correction_focus,
                CorrectionPaneFocus::ProviderConfigPath | CorrectionPaneFocus::ProviderId
            ) {
                self.mark_provider_setup_changed();
            } else {
                self.correction_panel_status = if redo {
                    "Draft redone; Save is still required.".to_owned()
                } else {
                    "Draft undo applied; Save is still required.".to_owned()
                };
            }
        }
        self.request_redraw();
    }

    fn note_editor_result(&mut self, result: Option<Result<bool, journal::JournalError>>) {
        match result {
            Some(Err(_)) => {
                self.correction_panel_status =
                    "Text edit exceeds the correction or setup field limits.".to_owned();
            }
            Some(Ok(true))
                if matches!(
                    self.correction_focus,
                    CorrectionPaneFocus::ProviderConfigPath | CorrectionPaneFocus::ProviderId
                ) =>
            {
                self.mark_provider_setup_changed();
            }
            Some(Ok(_)) => self.correction_panel_status.clear(),
            None => {}
        }
        self.request_redraw();
        self.update_ime_cursor_area();
    }

    fn mark_provider_setup_changed(&mut self) {
        self.local_convert_provider = None;
        self.correction_panel_status =
            "Provider settings changed; click Load config before Convert.".to_owned();
    }

    fn load_local_provider_from_pane(&mut self) {
        if self.pending_convert.is_some() || self.provider_worker.is_some() {
            self.correction_panel_status =
                "Load a provider configuration only after the current Convert has ended."
                    .to_owned();
            self.request_redraw();
            return;
        }
        if self.provider_config_path_editor.has_preedit() || self.provider_id_editor.has_preedit() {
            self.correction_panel_status =
                "Finish or cancel the active IME composition before loading config.".to_owned();
            self.request_redraw();
            return;
        }
        let path_text = self.provider_config_path_editor.text().trim();
        let provider_id = self.provider_id_editor.text().trim();
        if path_text.is_empty() {
            self.correction_panel_status =
                "Enter a local provider configuration path first.".to_owned();
            self.request_redraw();
            return;
        }
        let selection = (!provider_id.is_empty()).then_some(provider_id);
        match LocalConvertProviderV1::load(Path::new(path_text), selection) {
            Ok(provider) => {
                self.local_convert_provider = Some(provider);
                self.correction_panel_status =
                    "Provider configuration loaded; no worker was launched.".to_owned();
            }
            Err(_) => {
                self.local_convert_provider = None;
                self.provider_worker = None;
                self.correction_panel_status =
                    "Provider configuration could not be loaded; check the local file and ID."
                        .to_owned();
            }
        }
        self.request_redraw();
    }

    fn dispatch_pane_action(&mut self, action: CorrectionPaneAction) {
        if self.deferred_capture_batch.is_some() {
            if self.deferred_pane_actions.len() >= MAX_DEFERRED_PANE_ACTIONS
                || self.deferred_pane_actions.try_reserve(1).is_err()
            {
                self.correction_panel_status =
                    "Pane action queue is full while capture waits for storage.".to_owned();
                self.request_redraw();
                return;
            }
            self.deferred_pane_actions.push(action);
            self.correction_panel_status =
                "Pane action queued behind pending pen capture.".to_owned();
            self.request_redraw();
            return;
        }
        match action {
            CorrectionPaneAction::Convert => self.start_or_cancel_convert(),
            CorrectionPaneAction::Save => self.save_correction(),
            CorrectionPaneAction::Reset => self.reset_correction_draft(),
            CorrectionPaneAction::Cancel => self.cancel_correction_draft(),
            CorrectionPaneAction::Copy => self.copy_correction_text(),
            CorrectionPaneAction::LoadProviderConfig => self.load_local_provider_from_pane(),
        }
    }

    fn save_correction(&mut self) {
        if self.pending_correction.is_some() {
            self.correction_panel_status = "A correction save is already pending.".to_owned();
            self.request_redraw();
            return;
        }
        let Some(session) = self.correction_session.as_ref() else {
            self.correction_panel_status = "There is no stored projection to correct.".to_owned();
            self.request_redraw();
            return;
        };
        if session.editor().has_preedit() {
            self.correction_panel_status =
                "Finish or cancel the active IME composition before saving.".to_owned();
            self.request_redraw();
            return;
        }
        if !session.is_dirty() {
            self.correction_panel_status = "No correction draft to save.".to_owned();
            self.request_redraw();
            return;
        }
        let counter = self.next_correction_id;
        let Some(next_counter) = counter.checked_add(1) else {
            self.correction_panel_status =
                "Correction identifier capacity was exhausted.".to_owned();
            self.request_redraw();
            return;
        };
        let correction_id = format!("correction-{}-{counter}", self.active_session_id);
        let correction = match session.build_correction(&correction_id) {
            Ok(Some(correction)) => correction,
            Ok(None) => {
                self.correction_panel_status = "No correction draft to save.".to_owned();
                self.request_redraw();
                return;
            }
            Err(_) => {
                self.correction_panel_status =
                    "Correction draft is invalid or exceeds its limit.".to_owned();
                self.request_redraw();
                return;
            }
        };
        let Some(batch_id) = self.allocate_project_batch_id() else {
            self.correction_panel_status =
                "Project command identifier capacity was exhausted.".to_owned();
            self.request_redraw();
            return;
        };
        self.next_correction_id = next_counter;
        self.pending_correction = Some(PendingCorrectionWrite {
            batch_id,
            correction: Box::new(correction),
            enqueued: false,
        });
        self.retry_pending_correction();
    }

    fn retry_pending_correction(&mut self) {
        let Some(pending) = self.pending_correction.as_ref() else {
            return;
        };
        if pending.enqueued {
            return;
        }
        let Some(writer) = self.project_writer.as_mut() else {
            self.correction_panel_status =
                "Project writer is unavailable; draft remains editable.".to_owned();
            self.request_redraw();
            return;
        };
        let batch_id = pending.batch_id;
        let correction = (*pending.correction).clone();
        match writer.try_append_region_correction(
            batch_id,
            correction,
            self.app_clock_origin.elapsed().as_nanos(),
        ) {
            Ok(()) => {
                if let Some(pending) = self.pending_correction.as_mut() {
                    pending.enqueued = true;
                }
                self.correction_panel_status =
                    "Correction queued; waiting for durable journal acknowledgement.".to_owned();
            }
            Err(CorrectionQueueError::QueueFull(returned)) => {
                if let Some(pending) = self.pending_correction.as_mut() {
                    pending.correction = returned;
                    pending.enqueued = false;
                }
                self.correction_panel_status =
                    "Project writer busy; the correction is retained and will retry.".to_owned();
            }
            Err(CorrectionQueueError::WorkerStopped) => {
                self.pending_correction = None;
                self.correction_panel_status =
                    "Project writer stopped; the correction draft remains unsaved.".to_owned();
            }
        }
        self.request_redraw();
    }

    fn reset_correction_draft(&mut self) {
        if self.pending_correction.is_some() {
            self.correction_panel_status =
                "Reset is unavailable while a save is pending.".to_owned();
        } else if let Some(session) = self.correction_session.as_mut() {
            match session.reset() {
                Ok(()) => {
                    self.correction_panel_status =
                        "Reset staged; Save records it as a distinct history action.".to_owned();
                }
                Err(_) => self.correction_panel_status = "Reset could not be staged.".to_owned(),
            }
        } else {
            self.correction_panel_status = "There is no stored projection to reset.".to_owned();
        }
        self.request_redraw();
    }

    fn cancel_correction_draft(&mut self) {
        if self.pending_correction.is_some() {
            self.correction_panel_status =
                "Cancel is unavailable while a save is pending.".to_owned();
        } else if let Some(session) = self.correction_session.as_mut() {
            session.cancel_ime_preedit();
            session.cancel();
            self.correction_panel_status =
                "Draft canceled; the saved correction or provider output is displayed.".to_owned();
        } else {
            self.correction_panel_status = "There is no correction draft to cancel.".to_owned();
        }
        self.request_redraw();
    }

    fn copy_focused_text(&mut self) {
        let Some(hwnd) = self.window.as_ref().and_then(raw_window_hwnd) else {
            self.correction_panel_status = "Clipboard is unavailable for this window.".to_owned();
            return;
        };
        let text = self
            .focused_selected_text()
            .or_else(|| self.focused_text())
            .map(str::to_owned)
            .or_else(|| {
                self.correction_session.as_ref().and_then(|session| {
                    if session.is_cancelled() {
                        Some(session.text().to_owned())
                    } else {
                        session.effective_text().map(str::to_owned)
                    }
                })
            });
        let Some(text) = text else {
            self.correction_panel_status = "There is no text to copy.".to_owned();
            self.request_redraw();
            return;
        };
        self.correction_panel_status = match windows_clipboard::copy_unicode_text(hwnd, &text) {
            Ok(()) => "Text copied to the Windows clipboard.".to_owned(),
            Err(_) => "Clipboard copy failed; the draft remains local.".to_owned(),
        };
        self.request_redraw();
    }

    fn copy_correction_text(&mut self) {
        let Some(hwnd) = self.window.as_ref().and_then(raw_window_hwnd) else {
            self.correction_panel_status = "Clipboard is unavailable for this window.".to_owned();
            self.request_redraw();
            return;
        };
        let text = self.correction_session.as_ref().and_then(|session| {
            if let Some(selected) = session.selected_text() {
                Some(selected.to_owned())
            } else if session.is_dirty() || session.is_cancelled() {
                Some(session.text().to_owned())
            } else {
                session.effective_text().map(str::to_owned)
            }
        });
        let Some(text) = text else {
            self.correction_panel_status = "There is no correction text to copy.".to_owned();
            self.request_redraw();
            return;
        };
        self.correction_panel_status = match windows_clipboard::copy_unicode_text(hwnd, &text) {
            Ok(()) => "Correction text copied to the Windows clipboard.".to_owned(),
            Err(_) => "Clipboard copy failed; the draft remains local.".to_owned(),
        };
        self.request_redraw();
    }

    fn paste_focused_text(&mut self) {
        let Some(hwnd) = self.window.as_ref().and_then(raw_window_hwnd) else {
            self.correction_panel_status = "Clipboard is unavailable for this window.".to_owned();
            self.request_redraw();
            return;
        };
        match windows_clipboard::read_unicode_text(hwnd) {
            Ok(Some(text)) => self.focused_insert_text(&text),
            Ok(None) => self.correction_panel_status = "Clipboard has no Unicode text.".to_owned(),
            Err(_) => {
                self.correction_panel_status =
                    "Clipboard paste failed; no text was inserted.".to_owned()
            }
        }
        self.request_redraw();
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
                        self.note_convert_view_change();
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
                        self.note_convert_view_change();
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
                self.start_or_cancel_convert();
            }
            PhysicalKey::Code(KeyCode::Escape) => {
                self.cancel_convert("Convert canceled by the user".to_owned());
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
                        if !was_selected && self.canvas_scene.select_target(Some(target)).is_ok() {
                            self.note_convert_view_change();
                        }
                        self.canvas_move_drag_start = Some(cursor);
                        self.canvas_selection_drag_start = None;
                        self.canvas_scene.set_selection_rect(None);
                    }
                    Ok(None) => {
                        if self.canvas_scene.select_target(None).is_ok() {
                            self.note_convert_view_change();
                        }
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
                            self.note_convert_view_change();
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
                            self.note_convert_view_change();
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
                    } else {
                        self.note_convert_view_change();
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
                ProjectWriterAck::ConvertSnapshot { batch_id, state } => {
                    self.handle_convert_snapshot(batch_id, *state);
                }
                ProjectWriterAck::RecognitionProjectionCommitted { batch_id, record } => {
                    let matches_pending = self.pending_convert.as_ref().is_some_and(|pending| {
                        matches!(
                            &pending.phase,
                            PendingConvertPhase::Persisting { batch_id: expected }
                                if *expected == batch_id
                        )
                    });
                    let is_current = matches_pending
                        && self.pending_convert.as_ref().is_some_and(|pending| {
                            pending.project_generation == self.project_generation
                        });
                    if matches_pending {
                        self.pending_convert = None;
                        if is_current {
                            if let JournalEvent::RecognitionProjection {
                                app_arrival_elapsed_ns,
                                projection,
                            } = record.event
                            {
                                let stored_projection = StoredRecognitionProjection {
                                    sequence: record.sequence,
                                    app_epoch_id: record.app_epoch_id,
                                    app_arrival_elapsed_ns,
                                    projection: *projection,
                                };
                                match CorrectionSession::from_durable_projection(stored_projection)
                                {
                                    Ok(session) => {
                                        self.correction_session = Some(session);
                                        self.correction_panel_status =
                                            "New durable provider output opened; raw result is immutable.".to_owned();
                                    }
                                    Err(_) => {
                                        self.correction_panel_status =
                                            "Saved projection could not be opened for correction."
                                                .to_owned();
                                    }
                                }
                            }
                            self.canvas_status =
                                "Convert result was durably saved as a projection".to_owned();
                            self.request_redraw();
                        }
                    }
                }
                ProjectWriterAck::RecognitionProjectionFailed {
                    batch_id,
                    error: _,
                    writer_poisoned,
                } => {
                    let matches_pending = self.pending_convert.as_ref().is_some_and(|pending| {
                        matches!(
                            &pending.phase,
                            PendingConvertPhase::Persisting { batch_id: expected }
                                if *expected == batch_id
                        )
                    });
                    let is_current = matches_pending
                        && self.pending_convert.as_ref().is_some_and(|pending| {
                            pending.project_generation == self.project_generation
                        });
                    if matches_pending {
                        self.pending_convert = None;
                        if writer_poisoned {
                            self.mark_project_incomplete(
                                "project journal synchronization failed while saving the Convert result".to_owned(),
                            );
                        } else if is_current {
                            self.canvas_status =
                                "Convert result was rejected as stale or invalid; no projection was saved".to_owned();
                            self.request_redraw();
                        }
                    } else if writer_poisoned {
                        self.mark_project_incomplete(
                            "project journal synchronization failed while saving a Convert result"
                                .to_owned(),
                        );
                    }
                }
                ProjectWriterAck::RegionCorrectionCommitted { batch_id, record } => {
                    let matches_pending = self
                        .pending_correction
                        .as_ref()
                        .is_some_and(|pending| pending.batch_id == batch_id && pending.enqueued);
                    if matches_pending {
                        let saved_correction = match record.event {
                            JournalEvent::RegionCorrection { correction, .. } => Some(*correction),
                            _ => None,
                        };
                        let exact = saved_correction.as_ref().is_some_and(|saved| {
                            self.pending_correction
                                .as_ref()
                                .is_some_and(|pending| *saved == *pending.correction)
                        });
                        if exact {
                            let acknowledged = saved_correction.as_ref().is_some_and(|saved| {
                                self.correction_session.as_mut().is_some_and(|session| {
                                    session.acknowledge_committed(saved).is_ok()
                                })
                            });
                            if acknowledged {
                                self.pending_correction = None;
                                self.correction_panel_status =
                                    "Correction durably saved for this projection.".to_owned();
                            } else {
                                self.mark_project_incomplete(
                                    "durable correction acknowledgement did not match the frozen draft"
                                        .to_owned(),
                                );
                            }
                        } else {
                            self.pending_correction = None;
                            self.correction_panel_status =
                                "Correction acknowledgement did not match; the draft remains unsaved."
                                    .to_owned();
                        }
                        self.request_redraw();
                    }
                }
                ProjectWriterAck::RegionCorrectionFailed {
                    batch_id,
                    error: _,
                    writer_poisoned,
                } => {
                    let matches_pending = self
                        .pending_correction
                        .as_ref()
                        .is_some_and(|pending| pending.batch_id == batch_id);
                    if matches_pending {
                        self.pending_correction = None;
                    }
                    if writer_poisoned {
                        self.mark_project_incomplete(
                            "project journal synchronization failed while saving a correction"
                                .to_owned(),
                        );
                    } else if matches_pending {
                        self.correction_panel_status =
                            "Correction was stale or invalid; the draft is retained and can be copied or edited.".to_owned();
                    }
                    self.request_redraw();
                }
                ProjectWriterAck::Finished(result) => {
                    if let Err(error) = result {
                        self.startup_error = Some(format!("project finalization failed: {error}"));
                    }
                }
            }
        }
    }

    fn handle_convert_snapshot(&mut self, batch_id: u64, state: JournalReplayState) {
        let Some(mut pending) = self.pending_convert.take() else {
            return;
        };
        let phase = std::mem::replace(&mut pending.phase, PendingConvertPhase::Transitioning);
        match phase {
            PendingConvertPhase::SnapshotForPreparation {
                batch_id: expected_batch,
            } if expected_batch == batch_id => {
                if !self.convert_context_is_current(&pending) {
                    self.canvas_status =
                        "Convert canceled because the selected view changed before snapshot"
                            .to_owned();
                    self.request_redraw();
                    return;
                }
                if state.journal_id != self.project_journal_id {
                    self.canvas_status =
                        "Convert snapshot belongs to a different project".to_owned();
                    self.request_redraw();
                    return;
                }
                let Some(provider) = self.local_convert_provider.clone() else {
                    self.canvas_status =
                        "Convert unavailable: no explicit local provider configuration is loaded"
                            .to_owned();
                    self.request_redraw();
                    return;
                };
                let request_id =
                    format!("convert-{}-{}", self.active_session_id, pending.generation);
                match ConvertPreparationTask::start(
                    state,
                    pending.selected_strokes_in_ui_order.clone(),
                    request_id,
                    pending.line_id.clone(),
                    provider,
                ) {
                    Ok(task) => {
                        pending.phase = PendingConvertPhase::Preparing {
                            task: Box::new(task),
                            revalidate: None,
                        };
                        self.pending_convert = Some(pending);
                        self.canvas_status =
                            "Convert is preparing a bounded canonical request".to_owned();
                    }
                    Err(_) => {
                        self.canvas_status =
                            "Convert could not start its bounded preparation worker".to_owned();
                    }
                }
                self.request_redraw();
            }
            PendingConvertPhase::SnapshotForValidation {
                batch_id: expected_batch,
                execution,
            } if expected_batch == batch_id => {
                if !self.convert_context_is_current(&pending) {
                    self.canvas_status =
                        "Convert result was discarded because its selected view changed".to_owned();
                    self.request_redraw();
                    return;
                }
                if state.journal_id != self.project_journal_id {
                    self.canvas_status = "Convert result belongs to a different project".to_owned();
                    self.request_redraw();
                    return;
                }
                let (Some(request), Some(provider)) = (
                    pending.request.as_ref(),
                    self.local_convert_provider.clone(),
                ) else {
                    self.canvas_status =
                        "Convert lost its explicit provider or frozen request".to_owned();
                    self.request_redraw();
                    return;
                };
                match ConvertPreparationTask::start(
                    state,
                    pending.selected_strokes_in_ui_order.clone(),
                    request.request_id.clone(),
                    pending.line_id.clone(),
                    provider,
                ) {
                    Ok(task) => {
                        pending.phase = PendingConvertPhase::Preparing {
                            task: Box::new(task),
                            revalidate: Some(execution),
                        };
                        self.pending_convert = Some(pending);
                        self.canvas_status =
                            "Convert is recomputing the current input identity before saving"
                                .to_owned();
                    }
                    Err(_) => {
                        self.canvas_status =
                            "Convert could not start its bounded revalidation worker".to_owned();
                    }
                }
                self.request_redraw();
            }
            other => {
                pending.phase = other;
                self.pending_convert = Some(pending);
            }
        }
    }

    fn poll_convert(&mut self) {
        if self.pending_convert.as_ref().is_some_and(|pending| {
            !matches!(&pending.phase, PendingConvertPhase::Persisting { .. })
                && !self.convert_context_is_current(pending)
        }) {
            self.cancel_convert(
                "Convert canceled because the project or selected view changed".to_owned(),
            );
            if self.pending_convert.is_none() {
                return;
            }
        }

        if self.retry_pending_convert_writer_command() {
            return;
        }

        let preparation_result =
            self.pending_convert
                .as_mut()
                .and_then(|pending| match &mut pending.phase {
                    PendingConvertPhase::Preparing { task, .. } => task.try_receive(),
                    _ => None,
                });
        if let Some(result) = preparation_result {
            self.handle_prepared_conversion(result);
        }

        let provider_poll =
            if self.pending_convert.as_ref().is_some_and(|pending| {
                matches!(&pending.phase, PendingConvertPhase::ProviderRunning)
            }) {
                self.provider_worker
                    .as_ref()
                    .map(ProviderWorkerHandle::try_receive)
            } else {
                None
            };
        if let Some(provider_poll) = provider_poll {
            self.handle_provider_poll(provider_poll);
        }
    }

    fn retry_pending_convert_writer_command(&mut self) -> bool {
        let Some(mut pending) = self.pending_convert.take() else {
            return false;
        };
        let phase = std::mem::replace(&mut pending.phase, PendingConvertPhase::Transitioning);
        match phase {
            PendingConvertPhase::QueueSnapshotForPreparation { batch_id } => {
                if pending.cancelled || !self.convert_context_is_current(&pending) {
                    self.canvas_status =
                        "Convert intent was discarded because its selected view changed".to_owned();
                    self.request_redraw();
                    return true;
                }
                let result = self
                    .project_writer
                    .as_mut()
                    .map(|writer| writer.try_snapshot_for_convert(batch_id));
                match result {
                    Some(Ok(())) => {
                        pending.phase = PendingConvertPhase::SnapshotForPreparation { batch_id };
                        self.canvas_status =
                            "Convert snapshot queued after earlier accepted writes".to_owned();
                    }
                    Some(Err(
                        ProjectQueueError::QueueFull | ProjectQueueError::Backpressure { .. },
                    )) => {
                        pending.phase =
                            PendingConvertPhase::QueueSnapshotForPreparation { batch_id };
                        self.canvas_status =
                            "Convert intent retained; waiting for project writer capacity"
                                .to_owned();
                    }
                    Some(Err(
                        ProjectQueueError::WorkerStopped | ProjectQueueError::Stopped { .. },
                    ))
                    | None => {
                        self.canvas_status =
                            "Convert intent was not submitted because the project writer stopped"
                                .to_owned();
                        self.request_redraw();
                        return true;
                    }
                }
                self.pending_convert = Some(pending);
                self.request_redraw();
                true
            }
            PendingConvertPhase::QueueSnapshotForValidation {
                batch_id,
                execution,
            } => {
                if pending.cancelled || !self.convert_context_is_current(&pending) {
                    self.canvas_status =
                        "Convert result was discarded because its selected view changed".to_owned();
                    self.request_redraw();
                    return true;
                }
                let result = self
                    .project_writer
                    .as_mut()
                    .map(|writer| writer.try_snapshot_for_convert(batch_id));
                match result {
                    Some(Ok(())) => {
                        pending.phase = PendingConvertPhase::SnapshotForValidation {
                            batch_id,
                            execution,
                        };
                        self.canvas_status =
                            "Convert is revalidating its result against the latest durable view"
                                .to_owned();
                    }
                    Some(Err(
                        ProjectQueueError::QueueFull | ProjectQueueError::Backpressure { .. },
                    )) => {
                        pending.phase = PendingConvertPhase::QueueSnapshotForValidation {
                            batch_id,
                            execution,
                        };
                        self.canvas_status =
                            "Convert is waiting for project writer capacity before revalidation"
                                .to_owned();
                    }
                    Some(Err(
                        ProjectQueueError::WorkerStopped | ProjectQueueError::Stopped { .. },
                    ))
                    | None => {
                        self.canvas_status =
                            "Convert result was discarded: project writer stopped".to_owned();
                        self.request_redraw();
                        return true;
                    }
                }
                self.pending_convert = Some(pending);
                self.request_redraw();
                true
            }
            PendingConvertPhase::QueueProjectionCommit {
                batch_id,
                app_arrival_elapsed_ns,
                projection,
            } => {
                if pending.cancelled || !self.convert_context_is_current(&pending) {
                    self.canvas_status =
                        "Convert result was discarded because its selected view changed".to_owned();
                    self.request_redraw();
                    return true;
                }
                let result = self.project_writer.as_mut().map(|writer| {
                    writer.try_append_recognition_projection(
                        batch_id,
                        *projection,
                        app_arrival_elapsed_ns,
                    )
                });
                match result {
                    Some(Ok(())) => {
                        pending.phase = PendingConvertPhase::Persisting { batch_id };
                        self.canvas_status =
                            "Convert projection queued for atomic journal validation and save"
                                .to_owned();
                    }
                    Some(Err(ProjectionQueueError::QueueFull(projection))) => {
                        pending.phase = PendingConvertPhase::QueueProjectionCommit {
                            batch_id,
                            app_arrival_elapsed_ns,
                            projection,
                        };
                        self.canvas_status =
                            "Convert is waiting for project writer capacity before saving"
                                .to_owned();
                    }
                    Some(Err(ProjectionQueueError::WorkerStopped)) | None => {
                        self.canvas_status =
                            "Convert result was not saved: project writer stopped".to_owned();
                        self.request_redraw();
                        return true;
                    }
                }
                self.pending_convert = Some(pending);
                self.request_redraw();
                true
            }
            other => {
                pending.phase = other;
                self.pending_convert = Some(pending);
                false
            }
        }
    }

    fn handle_prepared_conversion(
        &mut self,
        result: Result<PreparedConversionV1, ConvertPreparationError>,
    ) {
        let Some(mut pending) = self.pending_convert.take() else {
            return;
        };
        let phase = std::mem::replace(&mut pending.phase, PendingConvertPhase::Transitioning);
        let revalidate = match phase {
            PendingConvertPhase::Preparing { revalidate, .. } => revalidate,
            other => {
                pending.phase = other;
                self.pending_convert = Some(pending);
                return;
            }
        };
        if pending.cancelled {
            self.request_redraw();
            return;
        }
        if !self.convert_context_is_current(&pending) {
            return;
        }
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(error) => {
                self.canvas_status = convert_preparation_message(error).to_owned();
                self.request_redraw();
                return;
            }
        };
        if let Some(execution) = revalidate {
            self.finish_convert_revalidation(pending, prepared, *execution);
            return;
        }

        let Some(provider) = self.local_convert_provider.as_ref() else {
            self.canvas_status =
                "Convert unavailable: explicit provider configuration is no longer available"
                    .to_owned();
            self.request_redraw();
            return;
        };
        let worker = match provider.start_worker() {
            Ok(worker) => worker,
            Err(_) => {
                self.canvas_status = "Convert provider worker could not be started".to_owned();
                self.request_redraw();
                return;
            }
        };
        match worker.try_submit(prepared.request.clone()) {
            Ok(()) => {
                pending.request = Some(prepared.request);
                pending.ink_binding = Some(prepared.ink_binding);
                pending.generated_raster = prepared.generated_raster;
                pending.phase = PendingConvertPhase::ProviderRunning;
                self.provider_worker = Some(worker);
                self.pending_convert = Some(pending);
                self.canvas_status =
                    "Convert is waiting for the explicit local provider".to_owned();
            }
            Err(ProviderSubmitError::Backpressure(_)) => {
                self.canvas_status =
                    "Convert provider is busy; no fallback was attempted".to_owned();
            }
            Err(ProviderSubmitError::Stopped(_)) => {
                self.canvas_status =
                    "Convert provider stopped before accepting the request".to_owned();
            }
            Err(ProviderSubmitError::Invalid(_)) => {
                self.canvas_status = "Convert request was rejected by M4 validation".to_owned();
            }
        }
        self.request_redraw();
    }

    fn finish_convert_revalidation(
        &mut self,
        mut pending: PendingConvert,
        prepared: PreparedConversionV1,
        execution: ProviderExecution,
    ) {
        if !self.convert_context_is_current(&pending) {
            self.canvas_status = "Convert result was discarded because its view changed".to_owned();
            self.request_redraw();
            return;
        }
        let (Some(request), Some(binding)) = (pending.request.as_ref(), pending.ink_binding.take())
        else {
            self.canvas_status = "Convert result lost its frozen source binding".to_owned();
            self.request_redraw();
            return;
        };
        if prepared.request.input_view_id != request.input_view_id
            || prepared.request.region_id != request.region_id
            || prepared.request.line_id != request.line_id
            || prepared.request.requested_input_modalities != request.requested_input_modalities
            || prepared.request.provider_configuration != request.provider_configuration
            || prepared.request.provider_configuration_fingerprint
                != request.provider_configuration_fingerprint
            || prepared.ink_binding.ink_binding_sha256 != binding.ink_binding_sha256
            || prepared.ink_binding.selected_strokes != binding.selected_strokes
            || prepared.ink_binding.source_sample_sequences != binding.source_sample_sequences
            || prepared.ink_binding.stroke_views != binding.stroke_views
            || !same_generated_raster_output(
                pending.generated_raster.as_ref(),
                prepared.generated_raster.as_ref(),
            )
        {
            self.canvas_status =
                "Convert result is stale: current selected ink/view differs from its request"
                    .to_owned();
            self.request_redraw();
            return;
        }
        if validate_result_for_current_view(
            request,
            &execution.result,
            &prepared.request.source_revision,
            &prepared.request.input_view_id,
        )
        .is_err()
        {
            self.canvas_status =
                "Convert result is stale or does not match its exact M4 request".to_owned();
            self.request_redraw();
            return;
        }
        let projection = match projection_from_execution(
            request,
            binding,
            pending.generated_raster.take(),
            &execution,
        ) {
            Ok(projection) => projection,
            Err(_) => {
                self.canvas_status =
                    "Convert result exceeded the bounded projection format".to_owned();
                self.request_redraw();
                return;
            }
        };
        let Some(batch_id) = self.allocate_project_batch_id() else {
            self.canvas_status = "Convert save identifier exhausted".to_owned();
            self.request_redraw();
            return;
        };
        let Some(writer) = self.project_writer.as_mut() else {
            self.canvas_status = "Convert could not save: project writer is unavailable".to_owned();
            self.request_redraw();
            return;
        };
        let app_arrival_elapsed_ns = self.app_clock_origin.elapsed().as_nanos();
        match writer.try_append_recognition_projection(batch_id, projection, app_arrival_elapsed_ns)
        {
            Ok(()) => {
                pending.phase = PendingConvertPhase::Persisting { batch_id };
                self.pending_convert = Some(pending);
                self.canvas_status =
                    "Convert projection queued for atomic journal validation and save".to_owned();
            }
            Err(ProjectionQueueError::QueueFull(projection)) => {
                pending.phase = PendingConvertPhase::QueueProjectionCommit {
                    batch_id,
                    app_arrival_elapsed_ns,
                    projection,
                };
                self.pending_convert = Some(pending);
                self.canvas_status =
                    "Convert is waiting for project writer capacity before saving".to_owned();
            }
            Err(ProjectionQueueError::WorkerStopped) => {
                self.canvas_status =
                    "Convert result was not saved: project writer stopped".to_owned();
            }
        }
        self.request_redraw();
    }

    fn handle_provider_poll(&mut self, poll: ProviderWorkerPoll) {
        match poll {
            ProviderWorkerPoll::Pending => {}
            ProviderWorkerPoll::Stopped => {
                self.provider_worker = None;
                self.pending_convert = None;
                self.canvas_status = "Convert provider worker stopped".to_owned();
                self.request_redraw();
            }
            ProviderWorkerPoll::Outcome(outcome) => {
                let Some(mut pending) = self.pending_convert.take() else {
                    self.provider_worker = None;
                    return;
                };
                let Some(request) = pending.request.as_ref() else {
                    self.provider_worker = None;
                    self.canvas_status = "Convert result had no matching frozen request".to_owned();
                    self.request_redraw();
                    return;
                };
                if !matches!(&pending.phase, PendingConvertPhase::ProviderRunning)
                    || outcome.request_id != request.request_id
                    || !self.convert_context_is_current(&pending)
                {
                    self.provider_worker = None;
                    self.canvas_status = "Convert result was discarded as stale".to_owned();
                    self.request_redraw();
                    return;
                }
                let execution = match outcome.outcome {
                    Ok(execution) => execution,
                    Err(error) => {
                        self.provider_worker = None;
                        self.canvas_status =
                            convert_provider_failure_message(&error.kind).to_owned();
                        self.request_redraw();
                        return;
                    }
                };
                if self
                    .local_convert_provider
                    .as_ref()
                    .is_none_or(|provider| execution.provider.provider_id != provider.provider_id)
                {
                    self.provider_worker = None;
                    self.canvas_status =
                        "Convert provider identity differs from the explicit local selection"
                            .to_owned();
                    self.request_redraw();
                    return;
                }
                if validate_result_for_current_view(
                    request,
                    &execution.result,
                    &request.source_revision,
                    &request.input_view_id,
                )
                .is_err()
                {
                    self.provider_worker = None;
                    self.canvas_status =
                        "Convert result did not match its exact frozen M4 request".to_owned();
                    self.request_redraw();
                    return;
                }
                self.provider_worker = None;
                let Some(batch_id) = self.allocate_project_batch_id() else {
                    self.canvas_status = "Convert validation identifier exhausted".to_owned();
                    self.request_redraw();
                    return;
                };
                let Some(writer) = self.project_writer.as_mut() else {
                    self.canvas_status =
                        "Convert could not revalidate: project writer is unavailable".to_owned();
                    self.request_redraw();
                    return;
                };
                let execution = Box::new(execution);
                match writer.try_snapshot_for_convert(batch_id) {
                    Ok(()) => {
                        pending.phase = PendingConvertPhase::SnapshotForValidation {
                            batch_id,
                            execution,
                        };
                        self.pending_convert = Some(pending);
                        self.canvas_status =
                            "Convert is revalidating its result against the latest durable view"
                                .to_owned();
                    }
                    Err(ProjectQueueError::QueueFull | ProjectQueueError::Backpressure { .. }) => {
                        pending.phase = PendingConvertPhase::QueueSnapshotForValidation {
                            batch_id,
                            execution,
                        };
                        self.pending_convert = Some(pending);
                        self.canvas_status =
                            "Convert is waiting for project writer capacity before revalidation"
                                .to_owned();
                    }
                    Err(ProjectQueueError::WorkerStopped | ProjectQueueError::Stopped { .. }) => {
                        self.canvas_status =
                            "Convert result was discarded: project writer stopped".to_owned();
                    }
                }
                self.request_redraw();
            }
        }
    }

    fn mark_project_incomplete(&mut self, reason: String) {
        self.project_generation = self.project_generation.saturating_add(1);
        if self.pending_convert.as_ref().is_some_and(|pending| {
            !matches!(&pending.phase, PendingConvertPhase::Persisting { .. })
        }) {
            self.cancel_convert(
                "Convert canceled because the project stopped accepting writes".to_owned(),
            );
        }
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
            self.deferred_pane_actions.clear();
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
                let pane_actions = std::mem::take(&mut self.deferred_pane_actions);
                for action in pane_actions {
                    self.dispatch_pane_action(action);
                }
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
                self.deferred_pane_actions.clear();
                let omitted_samples = direct_capture_sample_count(&events);
                self.mark_project_incomplete(format!(
                    "project writer stopped before queued batch {stopped_batch_id} committed; {} events and {omitted_samples} samples remain unwritten",
                    events.len()
                ));
            }
            Err(ProjectQueueError::QueueFull | ProjectQueueError::WorkerStopped) => {
                self.deferred_pane_actions.clear();
                self.mark_project_incomplete(
                    "project writer command queue is unavailable".to_owned(),
                );
            }
        }
    }

    fn process_pending_project_capture(&mut self) {
        self.drain_project_writer_acks();
        self.retry_pending_correction();
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

        let capture_mode = self.capture_mode;
        let prior_message_sequence = self.last_project_message_sequence;
        let client_origin = self.canvas_origin;
        let client_size = self.client_size;
        let direct_pane_layout = if capture_mode == CaptureMode::DirectWmPointer {
            match self.correction_pane_layout() {
                Ok(layout) => Some(layout),
                Err(_) => {
                    self.correction_panel_status =
                        "Pane measurement is unavailable; Direct pane actions are paused."
                            .to_owned();
                    self.request_redraw();
                    None
                }
            }
        } else {
            None
        };
        let current_stroke_view_frame = (capture_mode == CaptureMode::DirectWmPointer)
            .then(|| self.current_stroke_view_frame());

        let mut events = Vec::new();
        let mut tool_intents = Vec::new();
        let mut pane_actions = Vec::new();
        let mut last_message_sequence = self.last_project_message_sequence;
        let mut conversion_error = None;
        {
            let state = self.probe_state.borrow();
            for record in &state.pending_records()[new_range] {
                match record {
                    ProbeRecord::DirectPenHistory(batch)
                        if capture_mode == CaptureMode::DirectWmPointer
                            && batch.message_sequence > prior_message_sequence =>
                    {
                        let (ui_route, completed_action) = route_direct_batch_to_correction_ui(
                            &mut self.direct_ui_pointer_owners,
                            batch,
                            client_origin,
                            client_size,
                            direct_pane_layout.as_ref(),
                        );
                        if ui_route == DirectUiPointerRoute::CapacityExceeded {
                            conversion_error = Some(
                                "Direct pointer ownership capacity reached; capture stopped rather than reassigning a live gesture"
                                    .to_owned(),
                            );
                            break;
                        }
                        if let Some(action) = completed_action {
                            if pane_actions.len() >= MAX_DEFERRED_PANE_ACTIONS
                                || pane_actions.try_reserve(1).is_err()
                            {
                                conversion_error = Some(
                                    "correction-pane action batch exceeded its fixed capacity"
                                        .to_owned(),
                                );
                                break;
                            }
                            pane_actions.push(action);
                        }
                        let converted = if ui_route == DirectUiPointerRoute::Unowned {
                            (|| {
                                let mut raw_events =
                                    if batch.message_kind == PointerMessageKind::Down {
                                        self.canvas_tool_gesture_tracker
                                            .cancel_pointer_id(Some(batch.pointer_id_requested));
                                        self.direct_input_tracker.interrupt_pointer_id(
                                            batch.pointer_id_requested,
                                            StrokeInterruptionReason::PointerDownBeforePenUp,
                                            batch.hook_observed_elapsed_ns,
                                        )?
                                    } else {
                                        Vec::new()
                                    };
                                let mut unowned =
                                    canvas::CanvasInputTracker::direct_batch_to_unowned_events(
                                        batch,
                                        &self.active_session_id,
                                        Some(&self.active_config_id),
                                    )?;
                                raw_events
                                    .try_reserve(unowned.len())
                                    .map_err(|_| canvas::CanvasError::PointCapacityReached)?;
                                raw_events.append(&mut unowned);
                                Ok((raw_events, None))
                            })()
                        } else {
                            let view_frame = match current_stroke_view_frame.as_ref() {
                                Some(Ok(frame)) => *frame,
                                Some(Err(error)) => {
                                    conversion_error = Some(error.clone());
                                    break;
                                }
                                None => {
                                    conversion_error = Some(
                                        "current stroke view frame was not prepared".to_owned(),
                                    );
                                    break;
                                }
                            };
                            if self.canvas_scene.tool() == CanvasTool::Pen {
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
                            }
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
                        self.direct_ui_pointer_owners
                            .observe_lifecycle(record.kind, record.pointer_id_raw);
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
            for action in pane_actions {
                self.dispatch_pane_action(action);
            }
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
                for action in pane_actions {
                    self.dispatch_pane_action(action);
                }
            }
            Err(ProjectQueueError::Backpressure {
                batch_id,
                events,
                queued_samples,
            }) => {
                self.deferred_capture_batch = Some((batch_id, last_message_sequence, events));
                self.deferred_canvas_intents = tool_intents;
                self.deferred_pane_actions = pane_actions;
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
                self.deferred_pane_actions.clear();
                let omitted_samples = direct_capture_sample_count(&events);
                self.discard_preview_capture_events(&events);
                self.deferred_canvas_intents.clear();
                self.mark_project_incomplete(format!(
                    "project writer stopped during capture; batch {stopped_batch_id} had {} events and {omitted_samples} samples not accepted",
                    events.len()
                ));
            }
            Err(ProjectQueueError::QueueFull | ProjectQueueError::WorkerStopped) => {
                self.deferred_pane_actions.clear();
                self.mark_project_incomplete(
                    "project writer command queue is unavailable".to_owned(),
                );
            }
        }
    }

    fn finish_project_writer(&mut self) -> Result<(), String> {
        self.project_generation = self.project_generation.saturating_add(1);
        self.cancel_convert("Convert canceled when the project closed".to_owned());
        self.cancel_and_join_preparation_for_shutdown();
        self.process_pending_project_capture();
        let unfinished_direct_strokes = self.direct_input_tracker.active_stroke_count();
        if unfinished_direct_strokes > 0 {
            self.mark_project_incomplete(format!(
                "process shutdown with {unfinished_direct_strokes} direct stroke(s) lacking an observed native up; raw rows will be retained without a commit"
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while (self.deferred_capture_batch.is_some() || self.pending_correction.is_some())
            && Instant::now() < deadline
        {
            self.drain_project_writer_acks();
            self.retry_pending_correction();
            self.try_send_deferred_capture_batch();
            if self.deferred_capture_batch.is_some() || self.pending_correction.is_some() {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        if self.pending_correction.take().is_some() {
            self.mark_project_incomplete(
                "shutdown ended before the requested correction received a durable acknowledgement"
                    .to_owned(),
            );
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

    fn cancel_and_join_preparation_for_shutdown(&mut self) {
        let Some(mut pending) = self.pending_convert.take() else {
            return;
        };
        if let PendingConvertPhase::Preparing { task, .. } = &mut pending.phase {
            // Shutdown runs after Winit has exited; retain and join the single
            // bounded CPU-preparation worker rather than detaching its handle.
            task.cancel_and_join();
        } else if convert_phase_is_persisting(&pending.phase) {
            self.pending_convert = Some(pending);
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

fn convert_preparation_message(error: ConvertPreparationError) -> &'static str {
    match error {
        ConvertPreparationError::Cancelled => "Convert preparation was canceled",
        ConvertPreparationError::InvalidSelection => "Select one valid region before Convert",
        ConvertPreparationError::UnsupportedSource => {
            "Convert requires committed Direct strokes with valid captured frames"
        }
        ConvertPreparationError::OversizedInput => {
            "Convert input exceeds the fixed raster or provider request cap"
        }
        ConvertPreparationError::RequestRejected => "Convert request was rejected by M4 validation",
        ConvertPreparationError::RasterRejected => {
            "Convert could not produce a valid canonical raster for this region"
        }
        ConvertPreparationError::AllocationFailed => {
            "Convert could not allocate its bounded preparation buffers"
        }
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

        let attributes = Window::default_attributes()
            .with_title(STATUS)
            .with_min_inner_size(PhysicalSize::new(960, 720));
        match event_loop.create_window(attributes) {
            Ok(window) => {
                let size = window.inner_size();
                self.client_size = Some((size.width, size.height));
                let hwnd = raw_window_hwnd(&window).unwrap_or(0);
                let dpi_scale_factor = window.scale_factor();
                self.window = Some(window);
                self.pane_text_measurements.clear();
                self.pane_text_measurements
                    .set_hwnd((hwnd != 0).then_some(hwnd));
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
                println!("{CONVERT_POLICY}");
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
                if let Some(window) = self.window.as_ref() {
                    window.set_ime_allowed(false);
                }
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
                    self.correction_mouse_selecting = false;
                    self.alt_graph_active = false;
                    if let Some(session) = self.correction_session.as_mut() {
                        session.cancel_ime_preedit();
                        session.on_focus_lost();
                    }
                    self.provider_config_path_editor.cancel_preedit();
                    self.provider_id_editor.cancel_preedit();
                    self.export_path_editor.cancel_preedit();
                    if let Some(window) = self.window.as_ref() {
                        window.set_ime_allowed(false);
                    }
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
                } else if self.correction_focus.is_text_field()
                    && let Some(window) = self.window.as_ref()
                {
                    window.set_ime_allowed(true);
                    self.update_ime_cursor_area();
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
                self.pane_text_measurements.clear();
                self.observe_canvas_window_frame(Some(scale_factor));
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
            }
            WindowEvent::RedrawRequested => match self.correction_pane_layout() {
                Ok(side_pane) => {
                    if let Some(window) = self.window.as_ref()
                        && let Err(error) = paint_gdi_with_side_pane(
                            window,
                            &self.canvas_scene,
                            self.canvas_viewport,
                            &format!(
                                "{} | source {} (no fallback) | zoom {:.0}% pan {:.0},{:.0} | Ctrl+Z/Y undo/redo | arrows move selected",
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
                            &side_pane.lines,
                        )
                    {
                        self.startup_error = Some(format!("canvas repaint failed: {error}"));
                        self.record_lifecycle_issue(
                            LifecycleEventKind::WindowInitializationFailed,
                            format!("canvas repaint failed: {error}"),
                        );
                    }
                }
                Err(error) => {
                    let message = format!("correction pane text measurement failed: {error}");
                    self.startup_error = Some(message.clone());
                    self.correction_panel_status =
                        "Pane measurement is unavailable; correction controls are paused."
                            .to_owned();
                    self.record_lifecycle_issue(
                        LifecycleEventKind::WindowInitializationFailed,
                        message,
                    );
                    if let Some(window) = self.window.as_ref() {
                        let _ = paint_gdi_with_side_pane(
                            window,
                            &self.canvas_scene,
                            self.canvas_viewport,
                            &self.correction_panel_status,
                            &[],
                        );
                    }
                }
            },
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
            WindowEvent::KeyboardInput { event, .. } => {
                if event.logical_key == Key::Named(NamedKey::AltGraph) {
                    self.alt_graph_active = event.state == ElementState::Pressed;
                }
                if !self.handle_focused_text_key(&event) {
                    self.handle_canvas_key(&event);
                }
            }
            WindowEvent::Ime(ime) => self.handle_ime_event(ime),
            WindowEvent::ModifiersChanged(modifiers) => {
                self.canvas_modifiers = modifiers.state();
            }
            WindowEvent::CursorMoved { position, .. } => {
                let cursor = (position.x, position.y);
                self.canvas_cursor_client = Some(cursor);
                if self.correction_mouse_selecting {
                    if let (Some(anchor), Some(caret)) = (
                        self.correction_mouse_selection_anchor,
                        self.correction_text_caret_at(cursor),
                    ) {
                        self.focused_select_graphemes(anchor, caret);
                    }
                } else if let Some(last) = self.canvas_pan_drag_last {
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
                    } else if cursor != last {
                        self.note_convert_view_change();
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
                self.correction_mouse_selecting = false;
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
                let window_hwnd = self.window.as_ref().and_then(raw_window_hwnd);
                let origin =
                    self.probe_state
                        .borrow()
                        .public_mouse_input_origin(window_hwnd, state, button);
                let (has_active_canvas_pointer, has_pending_direct_action, targets_pane_action) =
                    if self.capture_mode == CaptureMode::DirectWmPointer
                        && matches!(origin, MouseMessageOrigin::PenPromoted { .. })
                    {
                        let active_canvas_pointer =
                            self.direct_ui_pointer_owners.has_active_canvas_pointer();
                        let pending_direct_action =
                            self.direct_ui_pointer_owners.has_pending_direct_action();
                        let targets_pane_action =
                            self.winit_mouse_input_targets_pane_action(button, state);
                        (
                            active_canvas_pointer,
                            pending_direct_action,
                            targets_pane_action,
                        )
                    } else {
                        (false, false, false)
                    };
                if should_process_winit_mouse_input(
                    self.capture_mode,
                    origin,
                    has_active_canvas_pointer,
                    has_pending_direct_action,
                    targets_pane_action,
                ) && !self.handle_correction_mouse_button(button, state)
                {
                    self.handle_canvas_mouse_button(button, state);
                }
            }
            WindowEvent::MouseWheel { delta, .. } if !self.handle_correction_pane_wheel(&delta) => {
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
                    } else {
                        self.note_convert_view_change();
                    }
                    if let Some(window) = self.window.as_ref() {
                        window.request_redraw();
                    }
                }
            }
            WindowEvent::MouseWheel { .. } => {}
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
        self.poll_convert();
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
    let local_convert_provider = options
        .provider_config_path
        .as_deref()
        .map(|path| LocalConvertProviderV1::load(path, options.provider_selection_id.as_deref()))
        .transpose()?;
    let provider_config_path_text = options
        .provider_config_path
        .as_deref()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let provider_id_text = options.provider_selection_id.clone().unwrap_or_default();
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
    metadata.insert(
        "schema_version".to_owned(),
        journal::JOURNAL_SCHEMA_VERSION.to_string(),
    );
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
                "Direct WM_POINTER/GetPointerPenInfoHistory selected for this session; owner-tested supported setup requires Windows Ink ON; this session is not hardware qualification"
            }
            CaptureMode::Wintab => {
                "Wintab explicitly selected for diagnostics; canvas adapter unavailable and no fallback is used"
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
        "Owner-reported Gate 0 PROVISIONAL PASS for Direct WM_POINTER with Windows Ink ON; criterion-8 callback/query CPU cost and physical pen-to-display latency remain partial and nonblocking; this session is not hardware qualification".to_owned(),
    );
    let process_cpu_start = process_cpu_snapshot(app_clock_origin);

    let mut recovery_notes = Vec::new();
    let mut project = if options.open_project {
        let source = read_journal(&project_path)?;
        if source.schema_version != journal::JOURNAL_SCHEMA_VERSION {
            let source_path = project_path.clone();
            let source_schema_version = source.schema_version;
            project_path = schema_four_project_path(&source_path);
            let migration = match source_schema_version {
                1 => migrate_schema_one_to_four(&source_path, project_path.clone())?,
                2 => migrate_schema_two_to_four(&source_path, project_path.clone())?,
                3 => migrate_schema_three_to_four(&source_path, project_path.clone())?,
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
    let initial_correction_session = project
        .replay_state()
        .recognition_projections
        .last()
        .map(|stored| {
            CorrectionSession::open(project.replay_state(), &stored.projection.projection_id)
        })
        .transpose()
        .map_err(|_| io::Error::other("could not open the latest stored correction projection"))?;
    let initial_correction_status = if initial_correction_session.is_some() {
        "Stored projection opened; no correction draft is pending.".to_owned()
    } else {
        String::new()
    };
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
        local_convert_provider,
        provider_worker: None,
        pending_convert: None,
        correction_session: initial_correction_session,
        pending_correction: None,
        next_correction_id: 1,
        correction_focus: CorrectionPaneFocus::None,
        correction_panel_status: initial_correction_status,
        provider_config_path_editor: CorrectionTextEditor::new(&provider_config_path_text)?,
        provider_id_editor: CorrectionTextEditor::new(&provider_id_text)?,
        export_path_editor: CorrectionTextEditor::new("")?,
        direct_ui_pointer_owners: DirectUiPointerOwnerTracker::default(),
        deferred_pane_actions: Vec::new(),
        correction_pane_scroll: CorrectionPaneScrollOffsets::default(),
        pane_text_measurements: GdiTextAdvanceCache::default(),
        correction_editor_browse_mode: false,
        correction_mouse_selection_anchor: None,
        correction_mouse_selecting: false,
        alt_graph_active: false,
        next_convert_generation: 1,
        project_generation: 1,
        convert_view_generation: 0,
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
        println!(
            "LassoInk M3 minimal canvas; Direct WM_POINTER with Windows Ink ON is the owner-tested capture lock"
        );
        println!("Usage: lassoink-capture-probe [options]");
        println!("  --capture-mode direct|wintab");
        println!(
            "  Supported tested capture setup: Direct WM_POINTER/GetPointerPenInfoHistory with Windows Ink ON"
        );
        println!(
            "  Ink OFF may suppress Direct PT_PEN; public mouse/Winit events remain diagnostic and never become ink"
        );
        println!("  Wintab is an explicit diagnostic mode, not a fallback for Direct capture");
        println!("  --session-dir PATH | --session-path PATH");
        println!("  --project-path PATH | --open-project PATH");
        println!("  --provider-config PATH [--provider-id ID] (explicit local Convert provider)");
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
        println!("{CONVERT_POLICY}");
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
        println!("{CONVERT_POLICY}");
        println!("{STORAGE_POLICY}");
        println!("Default session directory: local_capture (ignored local data)");
        println!(
            "Gate 0 hardware status: PROVISIONAL PASS for the owner-tested Direct WM_POINTER + Windows Ink ON setup; criterion-8 CPU/physical latency debt is partial and nonblocking."
        );
        println!("This software session is not hardware qualification or a Gate 1 selection.");
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
    let mut provider_config_path = None;
    let mut provider_selection_id = None;
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
            "--provider-config" => {
                provider_config_path = Some(PathBuf::from(value(&mut index)?));
            }
            "--provider-id" => {
                provider_selection_id = Some(value(&mut index)?);
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

    if provider_selection_id.is_some() && provider_config_path.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--provider-id requires --provider-config",
        ));
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
        provider_config_path,
        provider_selection_id,
    })
}

fn default_project_path(directory: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    directory.join(format!("project-{timestamp}-{}.inkj", process::id()))
}

fn schema_four_project_path(source: &Path) -> PathBuf {
    let stem = source
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("project");
    source
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.schema4.inkj"))
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
        "active schema-4 project {} ended in a torn final record; only the validated prefix was retained and the torn tail was truncated before append",
        project_path.display()
    )
}

fn project_recovery_status(note: &str) -> String {
    let legacy_source = note.contains("legacy schema");
    let active_project = note.contains("active schema-4 project");
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
        (None, _) => {
            "F1 pen | F2 eraser | F3 select | F4 Convert (explicit local provider)".to_owned()
        }
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
            Path::new("selected-legacy.schema4.inkj"),
            2,
        );
        assert!(note.contains("schema 2"));
        assert!(note.contains("only its validated prefix was migrated"));
        assert!(note.contains("selected source file remains unchanged"));
        assert!(note.contains("selected-legacy.inkj"));
        assert!(note.contains("selected-legacy.schema4.inkj"));
        let status = super::project_recovery_status(&note);
        assert!(status.contains("validated legacy prefix migrated"));
        assert!(status.contains("source unchanged"));
        let combined = startup_canvas_status(Some(&note), 2);
        assert!(combined.contains("validated legacy prefix migrated"));
        assert!(combined.contains("2 interrupted/in-progress stroke(s) remain raw"));
    }

    #[test]
    fn torn_schema_four_append_note_names_recovered_prefix_and_truncated_tail() {
        let note = active_project_recovery_note(Path::new("active-project.inkj"));
        assert!(note.contains("schema-4"));
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
mod correction_pane_pointer_owner_tests {
    use super::{
        CORRECTION_PANE_PADDING_PX, CanvasOrigin, CorrectionPaneAction,
        DirectUiPointerOwnerTracker, DirectUiPointerRoute, GdiTextAdvanceCache,
        MAX_UI_POINTER_OWNERS, correction_action_hit_targets,
        correction_pane_contains_client_point, correction_pane_left_edge,
        direct_screen_point_in_correction_pane, should_process_winit_mouse_input,
    };
    use crate::win32_pointer::{CaptureMode, MouseMessageOrigin, PointerMessageKind};

    #[test]
    fn direct_pointer_owner_is_frozen_at_down_when_gesture_crosses_pane() {
        let mut owners = DirectUiPointerOwnerTracker::default();
        let canvas_key = (0x1111, 7);
        let pane_key = (0x2222, 8);

        assert_eq!(
            owners.route_down(canvas_key, false, None),
            DirectUiPointerRoute::Canvas
        );
        assert!(owners.has_active_canvas_pointer());
        // A canvas-owned gesture stays with CanvasInputTracker when later
        // updates cross the side-pane area.
        assert_eq!(
            owners.route_continuation(canvas_key, PointerMessageKind::Update, None),
            (DirectUiPointerRoute::Canvas, None)
        );
        assert_eq!(
            owners.route_continuation(
                canvas_key,
                PointerMessageKind::Up,
                Some(CorrectionPaneAction::Convert)
            ),
            (DirectUiPointerRoute::Canvas, None)
        );
        assert!(!should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::PenPromoted { cursor_id: 7 },
            false,
            false,
            true,
        ));
        assert!(!should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::PenPromoted { cursor_id: 7 },
            true,
            false,
            false,
        ));
        assert!(!owners.has_active_canvas_pointer());

        assert_eq!(
            owners.route_down(pane_key, true, Some(CorrectionPaneAction::Save)),
            DirectUiPointerRoute::Unowned
        );
        assert!(owners.has_pending_action(CorrectionPaneAction::Save));
        // A UI-owned down remains raw/non-stroke even after moving over canvas.
        assert_eq!(
            owners.route_continuation(pane_key, PointerMessageKind::Update, None),
            (DirectUiPointerRoute::Unowned, None)
        );
        assert_eq!(
            owners.route_continuation(
                pane_key,
                PointerMessageKind::Up,
                Some(CorrectionPaneAction::Save)
            ),
            (
                DirectUiPointerRoute::Unowned,
                Some(CorrectionPaneAction::Save)
            )
        );
        assert_eq!(
            owners.route_continuation(pane_key, PointerMessageKind::Update, None),
            (DirectUiPointerRoute::Canvas, None)
        );
        assert!(!owners.has_pending_action(CorrectionPaneAction::Save));
    }

    #[test]
    fn pointer_owner_capacity_fails_closed_instead_of_reassigning_a_ui_gesture() {
        let mut owners = DirectUiPointerOwnerTracker::default();
        for pointer_id in 0..u32::try_from(MAX_UI_POINTER_OWNERS).unwrap() {
            assert_eq!(
                owners.route_down(
                    (isize::try_from(pointer_id).unwrap(), pointer_id),
                    true,
                    None,
                ),
                DirectUiPointerRoute::Unowned
            );
        }
        let overflow = (isize::MAX, u32::MAX);
        assert_eq!(
            owners.route_down(overflow, true, None),
            DirectUiPointerRoute::Unowned
        );
        assert_eq!(
            owners.route_continuation(overflow, PointerMessageKind::Update, None),
            (DirectUiPointerRoute::Unowned, None)
        );
        assert_eq!(
            owners.route_down((isize::MAX - 1, u32::MAX - 1), true, None),
            DirectUiPointerRoute::CapacityExceeded
        );
        assert_eq!(
            owners.route_continuation(overflow, PointerMessageKind::Up, None),
            (DirectUiPointerRoute::Unowned, None)
        );
    }

    #[test]
    fn correction_pane_hit_test_uses_the_captured_physical_client_frame() {
        let origin = CanvasOrigin {
            x_screen_px: 1_000,
            y_screen_px: 2_000,
        };
        let size = (1_200, 700);
        assert!(direct_screen_point_in_correction_pane(
            (1_840, 2_000),
            origin,
            size
        ));
        assert!(!direct_screen_point_in_correction_pane(
            (1_839, 2_000),
            origin,
            size
        ));
        assert!(!direct_screen_point_in_correction_pane(
            (2_200, 2_000),
            origin,
            size
        ));
        assert!(!direct_screen_point_in_correction_pane(
            (1_840, 2_700),
            origin,
            size
        ));
    }

    #[test]
    fn same_action_real_mouse_after_pen_is_honored_and_confirmed_promotion_is_filtered() {
        let mut actions = vec![CorrectionPaneAction::Convert];
        if should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::Unknown,
            false,
            false,
            false,
        ) {
            actions.push(CorrectionPaneAction::Convert);
        }
        assert_eq!(
            actions,
            vec![CorrectionPaneAction::Convert, CorrectionPaneAction::Convert]
        );
        assert!(!should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::PenPromoted { cursor_id: 7 },
            false,
            false,
            true,
        ));
        assert!(should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::TouchPromoted { cursor_id: 9 },
            false,
            false,
            true,
        ));
        assert!(should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::Unknown,
            true,
            false,
            true,
        ));
        assert!(should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::PenPromoted { cursor_id: 7 },
            false,
            false,
            false,
        ));
        let mut owners = DirectUiPointerOwnerTracker::default();
        assert_eq!(
            owners.route_down((0x4444, 10), true, Some(CorrectionPaneAction::Convert)),
            DirectUiPointerRoute::Unowned,
        );
        assert!(owners.has_pending_direct_action());
        assert!(!should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::PenPromoted { cursor_id: 7 },
            false,
            owners.has_pending_direct_action(),
            false,
        ));
    }

    #[test]
    fn action_hit_targets_follow_measured_labels_and_spacing() {
        let mut measurements = GdiTextAdvanceCache::default();
        let targets = correction_action_hit_targets(
            "[Convert] [Save] [Reset] [Cancel] [Copy]",
            &mut measurements,
        )
        .unwrap();
        assert_eq!(targets.len(), 5);
        assert_eq!(targets[0].1, CorrectionPaneAction::Convert);
        assert_eq!(targets[1].1, CorrectionPaneAction::Save);
        assert_eq!(targets[2].1, CorrectionPaneAction::Reset);
        assert_eq!(targets[3].1, CorrectionPaneAction::Cancel);
        assert_eq!(targets[4].1, CorrectionPaneAction::Copy);
        assert_eq!(targets[0].0, 0..80);
        assert_eq!(targets[4].0, 272..320);
    }

    #[test]
    fn pane_hit_bounds_match_render_width_and_reject_off_client_releases() {
        for (width, expected_left) in [(0, 0), (1, 0), (359, 0), (360, 0), (960, 600)] {
            assert_eq!(correction_pane_left_edge(width), expected_left);
            assert!(!correction_pane_contains_client_point(-1, 20, width, 80));
            assert!(!correction_pane_contains_client_point(width, 20, width, 80));
            assert_eq!(
                correction_pane_contains_client_point(expected_left, 20, width, 80),
                width > 0,
            );
        }

        let width = 1_i64;
        let off_client_x = -200_i64;
        let naive_left = width - 360;
        let naive_offset =
            i32::try_from(off_client_x - naive_left - i64::from(CORRECTION_PANE_PADDING_PX))
                .unwrap();
        assert_eq!(naive_offset, 147);
        let measured_actions = correction_action_hit_targets(
            "[Convert] [Save] [Reset] [Cancel] [Copy]",
            &mut GdiTextAdvanceCache::default(),
        )
        .unwrap();
        assert_eq!(measured_actions[2].1, CorrectionPaneAction::Reset);
        assert!(measured_actions[2].0.contains(&naive_offset));

        let origin = CanvasOrigin {
            x_screen_px: 100,
            y_screen_px: 200,
        };
        let release_point = ((origin.x_screen_px - 200) as i32, 220);
        assert!(!direct_screen_point_in_correction_pane(
            release_point,
            origin,
            (1, 80),
        ));
        let action_at_release = correction_pane_contains_client_point(off_client_x, 20, width, 80)
            .then_some(CorrectionPaneAction::Reset);
        let mut owners = DirectUiPointerOwnerTracker::default();
        let key = (0x3333, 9);
        assert_eq!(
            owners.route_down(key, true, Some(CorrectionPaneAction::Reset)),
            DirectUiPointerRoute::Unowned,
        );
        assert_eq!(
            owners.route_continuation(key, PointerMessageKind::Up, action_at_release),
            (DirectUiPointerRoute::Unowned, None),
        );
    }
}

#[cfg(test)]
mod correction_pane_scroll_tests {
    use super::{
        CORRECTION_PANE_ROW_HEIGHT_PX, CanvasViewport, CorrectionPaneLayout,
        CorrectionPaneScrollOffsets, CorrectionPaneTextSection, GdiTextAdvanceCache,
        InlineEditorField, append_pane_line, append_scrolled_measured_rows,
        correction_editor_scroll_offset_for_caret, correction_pane_scroll_offset,
        correction_pane_visible_row_count, inline_editor_cursor_at, inline_text_editor_line,
        measured_editor_display_rows, measured_pane_text_rows, scroll_view_range,
    };
    use crate::correction::CorrectionTextEditor;

    #[test]
    fn section_scroll_reaches_provider_effective_and_draft_ends_without_editing() {
        let provider = format!(
            "PROVIDER-HEAD-{}-MIDDLE-{}-PROVIDER-TAIL",
            "p".repeat(48),
            "q".repeat(48)
        );
        let effective = format!(
            "ORIGINAL-HEAD-{}-MIDDLE-{}-EFFECTIVE-TAIL",
            "e".repeat(48),
            "f".repeat(50)
        );
        let draft_text = format!(
            "DRAFT-HEAD-{}-MIDDLE-{}-DRAFT-TAIL",
            "d".repeat(72),
            "x".repeat(72)
        );
        let editor = CorrectionTextEditor::new(&draft_text).unwrap();
        let draft_before = editor.text().to_owned();
        let viewport = CanvasViewport::default();
        let zoom_before = viewport.zoom();
        let pan_before = viewport.pan();
        let mut measurements = GdiTextAdvanceCache::default();

        let provider_rows = measured_pane_text_rows(&provider, 64, &mut measurements).unwrap();
        let effective_rows = measured_pane_text_rows(&effective, 64, &mut measurements).unwrap();
        let draft_rows = measured_editor_display_rows(&editor, 64, &mut measurements).unwrap();
        let provider_first = scroll_view_range(provider_rows.len(), 3, 0);
        let provider_last = scroll_view_range(provider_rows.len(), 3, usize::MAX);
        assert!(
            provider_rows[provider_first]
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>()
                .contains("PROVIDER-HEAD")
        );
        assert!(
            provider_rows[provider_last]
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>()
                .contains("PROVIDER-TAIL")
        );
        assert!(
            provider_rows
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>()
                .contains("MIDDLE")
        );

        let effective_first = scroll_view_range(effective_rows.len(), 2, 0);
        let effective_last = scroll_view_range(effective_rows.len(), 2, usize::MAX);
        assert!(
            effective_rows[effective_first]
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>()
                .contains("ORIGINAL-HEAD")
        );
        assert_eq!(
            effective_rows
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>(),
            effective
        );
        assert!(
            effective_rows[effective_last]
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>()
                .contains("EFFECTIVE-TAIL")
        );

        let draft_first = scroll_view_range(draft_rows.len(), 4, 0);
        let draft_last = scroll_view_range(draft_rows.len(), 4, usize::MAX);
        assert!(
            draft_rows[draft_first]
                .iter()
                .map(|row| row.0.as_str())
                .collect::<String>()
                .contains("DRAFT-HEAD")
        );
        assert!(
            draft_rows[draft_last]
                .iter()
                .map(|row| row.0.as_str())
                .collect::<String>()
                .contains("DRAFT-TAIL")
        );

        let mut offsets = CorrectionPaneScrollOffsets::default();
        let max_provider_offset = provider_rows.len().saturating_sub(3);
        offsets.set(
            CorrectionPaneTextSection::ProviderOutput,
            correction_pane_scroll_offset(0, -1.0, max_provider_offset),
        );
        assert_eq!(offsets.get(CorrectionPaneTextSection::ProviderOutput), 1);
        assert_eq!(viewport.zoom(), zoom_before);
        assert_eq!(viewport.pan(), pan_before);
        assert_eq!(editor.text(), draft_before);

        let mut top_layout = CorrectionPaneLayout::default();
        append_scrolled_measured_rows(
            &mut top_layout,
            CorrectionPaneTextSection::ProviderOutput,
            &provider_rows,
            3,
            0,
        );
        let top_actions = append_pane_line(
            &mut top_layout,
            "[Convert] [Save] [Reset] [Cancel] [Copy]".to_owned(),
        );
        let top_config = append_pane_line(&mut top_layout, "[Load config]".to_owned());

        let mut bottom_layout = CorrectionPaneLayout::default();
        append_scrolled_measured_rows(
            &mut bottom_layout,
            CorrectionPaneTextSection::ProviderOutput,
            &provider_rows,
            3,
            usize::MAX,
        );
        let bottom_actions = append_pane_line(
            &mut bottom_layout,
            "[Convert] [Save] [Reset] [Cancel] [Copy]".to_owned(),
        );
        let bottom_config = append_pane_line(&mut bottom_layout, "[Load config]".to_owned());
        assert_eq!(top_actions, bottom_actions);
        assert_eq!(top_config, bottom_config);
        assert!(correction_pane_visible_row_count(720) >= bottom_layout.lines.len());
    }

    #[test]
    fn wheel_scroll_offsets_are_bounded_in_both_directions() {
        assert_eq!(correction_pane_scroll_offset(0, 1.0, 9), 0);
        assert_eq!(correction_pane_scroll_offset(4, 2.0, 9), 2);
        assert_eq!(correction_pane_scroll_offset(8, -4.0, 9), 9);
        assert_eq!(correction_pane_scroll_offset(9, -4.0, 9), 9);
    }

    #[test]
    fn draft_caret_recenters_after_read_only_browsing() {
        assert_eq!(correction_editor_scroll_offset_for_caret(0, 9, 10, 4), 6);
        assert_eq!(correction_editor_scroll_offset_for_caret(6, 4, 10, 4), 4);
        assert_eq!(correction_editor_scroll_offset_for_caret(6, 7, 10, 4), 6);
    }

    #[test]
    fn measured_editor_rows_drive_up_down_shift_selection_and_caret_view() {
        let text = format!("a👩‍💻{}", "b".repeat(20));
        let mut editor = CorrectionTextEditor::new(&text).unwrap();
        let mut measurements = GdiTextAdvanceCache::default();
        let rows = measured_editor_display_rows(&editor, 64, &mut measurements).unwrap();
        let ranges = rows
            .iter()
            .map(|(_, range, _)| range.clone())
            .collect::<Vec<_>>();
        assert_eq!(ranges, vec![0..5, 5..10, 10..15, 15..20, 20..22]);

        editor.set_cursor_grapheme(6);
        editor.move_cursor_on_visual_rows(&ranges, -1, false);
        assert_eq!(editor.cursor_grapheme(), 1);
        editor.move_cursor_on_visual_rows(&ranges, 1, false);
        assert_eq!(editor.cursor_grapheme(), 6);

        editor.set_cursor_grapheme(1);
        editor.move_cursor_on_visual_rows(&ranges, 1, true);
        assert_eq!(editor.cursor_grapheme(), 6);
        assert_eq!(editor.selection_graphemes(), Some(1..6));
        assert!(editor.selection_graphemes().is_some_and(|range| {
            range.start <= editor.grapheme_count() && range.end <= editor.grapheme_count()
        }));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "guarded hosted Windows GDI pane measurement and scroll fixture"]
    fn gdi_measurement_keeps_wide_vietnamese_nfd_text_reachable_at_minimum_pane_width() {
        super::require_native_ui_test_opt_in();
        let class_name: Vec<u16> = "STATIC".encode_utf16().chain(Some(0)).collect();
        let title: Vec<u16> = "LassoInk pane measurement fixture"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // SAFETY: a null module handle requests the current module; no pointer is retained.
        let instance = unsafe {
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null())
        };
        assert_ne!(instance, 0);
        // SAFETY: STATIC is a built-in window class and the test owns the resulting HWND.
        let hwnd = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::CreateWindowExW(
                0,
                class_name.as_ptr(),
                title.as_ptr(),
                0,
                0,
                0,
                960,
                720,
                0,
                0,
                instance,
                std::ptr::null(),
            )
        };
        assert_ne!(hwnd, 0);

        let mut measurements = GdiTextAdvanceCache::default();
        measurements.set_hwnd(Some(hwnd as isize));
        // SAFETY: hwnd is the live fixture window; GetDC is paired with ReleaseDC below.
        let hdc = unsafe { windows_sys::Win32::Graphics::Gdi::GetDC(hwnd) };
        assert_ne!(hdc, 0);
        // SAFETY: TEXTMETRICW is integer output storage and hdc is live.
        let mut font_metrics: windows_sys::Win32::Graphics::Gdi::TEXTMETRICW =
            unsafe { std::mem::zeroed() };
        assert_ne!(
            unsafe { windows_sys::Win32::Graphics::Gdi::GetTextMetricsW(hdc, &mut font_metrics) },
            0
        );
        assert!(font_metrics.tmHeight <= CORRECTION_PANE_ROW_HEIGHT_PX);
        // SAFETY: hdc was acquired from this exact hwnd above.
        assert_ne!(
            unsafe { windows_sys::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc) },
            0
        );
        let wide = measurements.advances("WWWW").unwrap();
        let narrow = measurements.advances("iiii").unwrap();
        assert!(
            wide.last().copied().unwrap_or_default() > narrow.last().copied().unwrap_or_default()
        );
        let action_label = "[Convert] [Save] [Reset] [Cancel] [Copy]";
        assert!(
            measurements
                .advances(action_label)
                .unwrap()
                .last()
                .copied()
                .unwrap_or_default()
                <= 336,
            "measured action buttons must fit the 960-pixel minimum pane"
        );

        let path_text = format!("C:\\Users\\{}", "W".repeat(100));
        let mut path_editor = CorrectionTextEditor::new(&path_text).unwrap();
        path_editor.set_cursor_grapheme(path_editor.grapheme_count());
        let (path_line, path_layout) = inline_text_editor_line(
            "Config path: ",
            &path_editor,
            InlineEditorField::ProviderConfigPath,
            336,
            &mut measurements,
        )
        .unwrap();
        assert!(path_layout.visible_graphemes.start > 0);
        assert_eq!(
            path_layout.visible_graphemes.end,
            path_editor.grapheme_count()
        );
        assert!(
            path_layout.boundary_x[0] > 0,
            "measured prefix width must be included"
        );
        assert!(
            path_layout
                .boundary_x
                .get(path_layout.visible_graphemes.end - path_layout.visible_graphemes.start)
                .is_some()
        );
        let mut inline_layout = CorrectionPaneLayout::default();
        inline_layout.inline_editor_rows.push(path_layout.clone());
        assert_eq!(
            inline_editor_cursor_at(
                &inline_layout,
                path_layout.field,
                path_layout.row_index,
                *path_layout.boundary_x.last().unwrap(),
            ),
            Some(path_editor.grapheme_count()),
        );
        assert!(
            measurements
                .advances(&path_line)
                .unwrap()
                .last()
                .copied()
                .unwrap_or_default()
                <= 336
        );

        let text = format!(
            "VIETNAMESE-NFD-HEAD {} MIDDLE {} TAIL-NFD-END",
            "W".repeat(70),
            "e\u{301}".repeat(70),
        );
        let rows = measured_pane_text_rows(&text, 336, &mut measurements).unwrap();
        assert!(rows.len() > 3);
        assert_eq!(
            rows.iter().map(|row| row.text.as_str()).collect::<String>(),
            text
        );
        let head = scroll_view_range(rows.len(), 3, 0);
        let tail = scroll_view_range(rows.len(), 3, usize::MAX);
        assert!(
            rows[head]
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>()
                .contains("VIETNAMESE-NFD-HEAD")
        );
        assert!(
            rows[tail]
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>()
                .contains("TAIL-NFD-END")
        );

        // SAFETY: hwnd is the owned fixture window created immediately above.
        let destroyed = unsafe { windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd) };
        assert_ne!(destroyed, 0);
    }
}

#[cfg(test)]
mod correction_text_routing_tests {
    use super::{
        CorrectionPaneFocus, ElementState, allows_keyboard_text,
        focused_text_measurement_allows_input, is_control_alt_shortcut,
        should_insert_keyboard_text, should_process_focused_text_key,
    };

    #[test]
    fn altgr_character_input_is_not_mistaken_for_a_control_shortcut() {
        assert!(is_control_alt_shortcut(true, true, false));
        assert!(!is_control_alt_shortcut(true, true, true));
        assert!(allows_keyboard_text(true, true, true));
        assert!(!allows_keyboard_text(true, true, false));
        assert!(allows_keyboard_text(false, false, false));
        assert!(should_insert_keyboard_text(
            false, false, false, false, true
        ));
        assert!(!should_insert_keyboard_text(
            false, false, false, true, true
        ));
        assert!(should_insert_keyboard_text(true, true, true, false, true));
    }

    #[test]
    fn focused_text_fields_process_repeated_pressed_key_events() {
        assert!(should_process_focused_text_key(ElementState::Pressed, true));
        assert!(should_process_focused_text_key(
            ElementState::Pressed,
            false
        ));
        assert!(!should_process_focused_text_key(
            ElementState::Released,
            true
        ));
        assert!(should_insert_keyboard_text(
            false, false, false, false, true
        ));
    }

    #[test]
    fn focused_text_input_waits_for_live_measurement() {
        assert!(!focused_text_measurement_allows_input(
            CorrectionPaneFocus::CorrectionEditor,
            false,
        ));
        assert!(!focused_text_measurement_allows_input(
            CorrectionPaneFocus::ProviderConfigPath,
            false,
        ));
        assert!(!focused_text_measurement_allows_input(
            CorrectionPaneFocus::ProviderId,
            false,
        ));
        assert!(!focused_text_measurement_allows_input(
            CorrectionPaneFocus::ExportPath,
            false,
        ));
        assert!(focused_text_measurement_allows_input(
            CorrectionPaneFocus::ProviderConfigPath,
            true,
        ));
    }

    #[test]
    fn only_explicit_editor_fields_receive_text_focus() {
        assert!(!CorrectionPaneFocus::None.is_text_field());
        assert!(CorrectionPaneFocus::CorrectionEditor.is_text_field());
        assert!(CorrectionPaneFocus::ProviderConfigPath.is_text_field());
        assert!(CorrectionPaneFocus::ProviderId.is_text_field());
        assert!(CorrectionPaneFocus::ExportPath.is_text_field());
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

#[cfg(test)]
mod convert_controller_tests {
    use super::{
        CaptureMode, ControlledStallTrigger, CorrectionPaneFocus, CorrectionPaneScrollOffsets,
        CorrectionTextEditor, DirectUiPointerOwnerTracker, GdiTextAdvanceCache, ModifiersState,
        PendingConvert, PendingConvertPhase, PendingRecordCursor, ProbeApp, ProbeState,
        WintabCapture, convert_context_matches, convert_phase_is_persisting,
        convert_provider_failure_message,
    };
    use crate::{
        canvas::{
            CanvasInputTracker, CanvasScene, CanvasToolGestureTracker, CanvasViewport,
            DirectCaptureEvent, PROVISIONAL_DIRECT_SOURCE_API,
        },
        journal::{
            JournalHeader, JournalWriter, PhysicalSample, ProjectionInkBindingV1,
            ProjectionProviderProvenanceV1, ProjectionStrokeRangeV1, ProjectionStrokeViewV1,
            RawPosition, RecognitionCandidateV1, RecognitionProjectionV1, StrokeRef,
            StrokeViewFrame, read_journal,
        },
        project_runtime::ProjectWriterHandle,
        provider_protocol::{ProviderErrorKind, ProviderPhase},
    };
    use std::{
        cell::RefCell,
        fs, process,
        rc::Rc,
        sync::{Arc, atomic::AtomicBool},
        time::{Duration, Instant},
    };

    fn selected_stroke(stroke_id: &str) -> StrokeRef {
        StrokeRef {
            journal_id: "convert-controller-project".to_owned(),
            session_id: "convert-controller-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-device-1".to_owned()),
            pointer_id: Some(1),
            stroke_id: stroke_id.to_owned(),
        }
    }

    fn pending(stroke: StrokeRef, phase: PendingConvertPhase) -> PendingConvert {
        PendingConvert {
            generation: 3,
            project_generation: 7,
            view_generation: 11,
            cancelled: false,
            selected_strokes_in_ui_order: vec![stroke],
            line_id: "line-1".to_owned(),
            request: None,
            ink_binding: None,
            generated_raster: None,
            phase,
        }
    }

    #[test]
    fn convert_context_requires_same_project_view_selection_and_committed_capture() {
        let stroke = selected_stroke("selected");
        let ticket = pending(stroke.clone(), PendingConvertPhase::Transitioning);
        assert!(convert_context_matches(
            &ticket,
            7,
            11,
            Some(std::slice::from_ref(&stroke)),
            false,
        ));

        // Project close/reopen advances the project generation and invalidates
        // a result even when the same StrokeRef still appears selected.
        assert!(!convert_context_matches(
            &ticket,
            8,
            11,
            Some(std::slice::from_ref(&stroke)),
            false,
        ));
        assert!(!convert_context_matches(
            &ticket,
            7,
            12,
            Some(std::slice::from_ref(&stroke)),
            false,
        ));

        let changed_selection = selected_stroke("other");
        assert!(!convert_context_matches(
            &ticket,
            7,
            11,
            Some(std::slice::from_ref(&changed_selection)),
            false,
        ));
        assert!(!convert_context_matches(&ticket, 7, 11, None, false));
        assert!(!convert_context_matches(
            &ticket,
            7,
            11,
            Some(std::slice::from_ref(&stroke)),
            true,
        ));
    }

    #[test]
    fn queued_durable_projection_is_not_cancelled_with_provider_work() {
        assert!(!convert_phase_is_persisting(
            &PendingConvertPhase::Transitioning
        ));
        assert!(!convert_phase_is_persisting(
            &PendingConvertPhase::SnapshotForPreparation { batch_id: 1 }
        ));
        assert!(convert_phase_is_persisting(
            &PendingConvertPhase::Persisting { batch_id: 2 }
        ));
    }

    #[test]
    fn provider_timeout_remains_visible_without_a_fallback() {
        assert_eq!(
            convert_provider_failure_message(&ProviderErrorKind::TimedOut(
                ProviderPhase::Recognition
            )),
            "Convert provider timed out; no fallback was attempted"
        );
    }

    #[test]
    fn saturated_convert_projection_retries_once_after_drain_then_capture_continues() {
        let path = std::env::temp_dir().join(format!(
            "lassoink-controller-queue-retry-{}.inkj",
            process::id()
        ));
        let journal_id = "convert-controller-project";
        let session_id = "convert-controller-session";
        let mut journal_writer = JournalWriter::create(
            path.clone(),
            JournalHeader {
                journal_id: journal_id.to_owned(),
                session_id: session_id.to_owned(),
                config_id: Some("config-a".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        let target = selected_stroke("queue-selected");
        let frame = StrokeViewFrame::default();
        let source_sample = PhysicalSample {
            session_id: target.session_id.clone(),
            source_api: target.source_api.clone(),
            source_device_id: target.device_id.clone(),
            pointer_id: target.pointer_id,
            stroke_id: Some(target.stroke_id.clone()),
            source_sequence: 1,
            config_id: Some("config-a".to_owned()),
            app_arrival_elapsed_ns: 2,
            position: Some(RawPosition {
                coordinate_space: "windows-screen-coordinates".to_owned(),
                units: "screen-pixel".to_owned(),
                x_raw: 50,
                y_raw: 60,
            }),
            pressure: None,
            native_timestamp: None,
            contact_range_state: Some("contact".to_owned()),
            button_state_raw: None,
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload: vec![0xC1],
        };
        journal_writer
            .start_stroke(target.clone(), frame, 1)
            .unwrap();
        let sample_sequence = journal_writer.append_sample(source_sample.clone()).unwrap();
        journal_writer.commit_stroke(target.clone(), 3).unwrap();
        let state = journal_writer.replay_state().clone();
        let mut scene = CanvasScene::from_journal(&state, PROVISIONAL_DIRECT_SOURCE_API).unwrap();
        scene.select_target(Some(target.clone())).unwrap();
        let project_writer = ProjectWriterHandle::spawn(journal_writer).unwrap();

        let probe = Rc::new(RefCell::new(ProbeState::default()));
        let wintab_capture = {
            let mut probe_state = probe.borrow_mut();
            WintabCapture::new(
                CaptureMode::DirectWmPointer,
                Instant::now(),
                &mut probe_state,
            )
        };
        let mut app = ProbeApp {
            window: None,
            focused: None,
            client_size: None,
            last_title: None,
            last_title_update: None,
            startup_error: None,
            capture_mode: CaptureMode::DirectWmPointer,
            app_clock_origin: Instant::now(),
            probe_state: probe,
            wintab: Rc::new(RefCell::new(wintab_capture)),
            wintab_control_observer: None,
            wintab_control_pending: Arc::new(AtomicBool::new(false)),
            session_writer: None,
            session_path: path.with_extension("session.tsv"),
            session_writer_failed: false,
            project_writer: Some(project_writer),
            project_path: path.clone(),
            project_journal_id: journal_id.to_owned(),
            local_convert_provider: None,
            provider_worker: None,
            pending_convert: None,
            correction_session: None,
            pending_correction: None,
            next_correction_id: 1,
            correction_focus: CorrectionPaneFocus::None,
            correction_panel_status: String::new(),
            provider_config_path_editor: CorrectionTextEditor::new("").unwrap(),
            provider_id_editor: CorrectionTextEditor::new("").unwrap(),
            export_path_editor: CorrectionTextEditor::new("").unwrap(),
            direct_ui_pointer_owners: DirectUiPointerOwnerTracker::default(),
            deferred_pane_actions: Vec::new(),
            correction_pane_scroll: CorrectionPaneScrollOffsets::default(),
            pane_text_measurements: GdiTextAdvanceCache::default(),
            correction_editor_browse_mode: false,
            correction_mouse_selection_anchor: None,
            correction_mouse_selecting: false,
            alt_graph_active: false,
            next_convert_generation: 1,
            project_generation: 1,
            convert_view_generation: 0,
            active_session_id: session_id.to_owned(),
            active_config_id: "config-a".to_owned(),
            direct_input_tracker: CanvasInputTracker::default(),
            canvas_tool_gesture_tracker: CanvasToolGestureTracker::default(),
            deferred_canvas_intents: Vec::new(),
            last_project_message_sequence: 0,
            pending_record_cursor: PendingRecordCursor::default(),
            next_project_batch_id: 10,
            deferred_capture_batch: None,
            project_incomplete_reason: None,
            project_recovery_note: None,
            historical_interrupted_strokes_at_start: 0,
            controlled_stall: ControlledStallTrigger::default(),
            canvas_scene: scene,
            canvas_viewport: CanvasViewport::default(),
            canvas_origin: None,
            canvas_dpi_scale_factor: 1.0,
            canvas_cursor_client: None,
            canvas_modifiers: ModifiersState::empty(),
            canvas_selection_drag_start: None,
            canvas_move_drag_start: None,
            canvas_pan_drag_last: None,
            canvas_status: "queue retry fixture".to_owned(),
        };
        let binding = ProjectionInkBindingV1 {
            journal_id: state.journal_id.clone(),
            logical_revision: state.logical_revision,
            last_sequence: state.last_sequence,
            region_id: "stable-queue-region".to_owned(),
            line_id: Some("line-1".to_owned()),
            input_view_id: "input-view-v1-0000000000000001".to_owned(),
            ink_binding_sha256: "a".repeat(64),
            selected_strokes: vec![target.clone()],
            source_sample_sequences: vec![sample_sequence],
            stroke_views: vec![ProjectionStrokeViewV1 {
                stroke: target.clone(),
                frame,
            }],
        };
        let projection = RecognitionProjectionV1 {
            projection_id: "completed-queue-projection".to_owned(),
            ink: binding,
            provider: ProjectionProviderProvenanceV1 {
                provider_id: "external-raster-provider".to_owned(),
                provider_version: "synthetic-test".to_owned(),
                model_version: None,
                resource_version: None,
                configuration_id: "operator-test-config".to_owned(),
                configuration_fingerprint: "provider-config-v1-fnv64-0000000000000001".to_owned(),
            },
            candidates: vec![RecognitionCandidateV1 {
                rank: 0,
                recognized_text: "synthetic completed result".to_owned(),
                native_score_raw: None,
                stroke_ranges: vec![ProjectionStrokeRangeV1 {
                    stroke: target.clone(),
                    first_journal_sequence: sample_sequence,
                    last_journal_sequence: sample_sequence,
                }],
            }],
            input_modalities: None,
            generated_raster: None,
        };
        for batch_id in 1..=8 {
            app.project_writer
                .as_mut()
                .unwrap()
                .try_snapshot_for_convert(batch_id)
                .unwrap();
        }
        app.pending_convert = Some(PendingConvert {
            generation: 1,
            project_generation: app.project_generation,
            view_generation: app.convert_view_generation,
            cancelled: false,
            selected_strokes_in_ui_order: vec![target.clone()],
            line_id: "line-1".to_owned(),
            request: None,
            ink_binding: None,
            generated_raster: None,
            phase: PendingConvertPhase::QueueProjectionCommit {
                batch_id: 9,
                app_arrival_elapsed_ns: 20,
                projection: Box::new(projection),
            },
        });

        app.poll_convert();
        assert!(matches!(
            app.pending_convert.as_ref().map(|pending| &pending.phase),
            Some(PendingConvertPhase::QueueProjectionCommit {
                projection,
                batch_id: 9,
                ..
            }) if projection.projection_id == "completed-queue-projection"
        ));

        let drain_deadline = Instant::now() + Duration::from_secs(10);
        while !app.project_writer.as_ref().unwrap().is_idle() {
            app.drain_project_writer_acks();
            assert!(
                Instant::now() < drain_deadline,
                "writer queue did not drain"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        app.poll_convert();
        assert!(matches!(
            app.pending_convert.as_ref().map(|pending| &pending.phase),
            Some(PendingConvertPhase::Persisting { batch_id: 9 })
        ));

        let continued_target = selected_stroke("queue-capture-continues");
        let continued_sample = PhysicalSample {
            session_id: continued_target.session_id.clone(),
            source_api: continued_target.source_api.clone(),
            source_device_id: continued_target.device_id.clone(),
            pointer_id: continued_target.pointer_id,
            stroke_id: Some(continued_target.stroke_id.clone()),
            source_sequence: 1,
            config_id: Some("config-a".to_owned()),
            app_arrival_elapsed_ns: 21,
            position: Some(RawPosition {
                coordinate_space: "windows-screen-coordinates".to_owned(),
                units: "screen-pixel".to_owned(),
                x_raw: 70,
                y_raw: 80,
            }),
            pressure: None,
            native_timestamp: None,
            contact_range_state: Some("contact".to_owned()),
            button_state_raw: None,
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload: vec![0xC2],
        };
        let capture_events = vec![
            DirectCaptureEvent::StrokeStarted {
                target: continued_target.clone(),
                view_frame: frame,
                app_arrival_elapsed_ns: 20,
            },
            DirectCaptureEvent::PhysicalSample(Box::new(continued_sample.clone())),
            DirectCaptureEvent::StrokeCommitRequested {
                target: continued_target,
                app_arrival_elapsed_ns: 22,
            },
        ];
        app.apply_capture_preview_events(&capture_events).unwrap();
        app.project_writer
            .as_mut()
            .unwrap()
            .try_capture_batch(10, capture_events)
            .unwrap();

        let finish_deadline = Instant::now() + Duration::from_secs(10);
        while app.pending_convert.is_some() || !app.project_writer.as_ref().unwrap().is_idle() {
            app.drain_project_writer_acks();
            assert!(
                Instant::now() < finish_deadline,
                "retry/capture ACKs did not finish"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        app.drain_project_writer_acks();
        assert!(app.canvas_status.contains("durably saved as a projection"));
        app.finish_project_writer().unwrap();
        let persisted = read_journal(&path).unwrap();
        assert_eq!(persisted.state.recognition_projections.len(), 1);
        assert_eq!(
            persisted.state.recognition_projections[0]
                .projection
                .projection_id,
            "completed-queue-projection"
        );
        assert_eq!(persisted.state.physical_samples.len(), 2);
        assert_eq!(persisted.state.physical_samples[0].sample, source_sample);
        assert_eq!(persisted.state.physical_samples[1].sample, continued_sample);
        let _ = fs::remove_file(path);
    }
}

#[cfg(all(test, windows))]
mod f4_convert_mock_pipeline_tests {
    use super::*;
    use crate::{
        canvas::PROVISIONAL_DIRECT_SOURCE_API,
        convert::{LocalConvertProviderV1, prepare_conversion},
        journal::{
            PhysicalSample, ProjectionInkBindingV1, ProjectionInputModalityV1,
            ProjectionProviderProvenanceV1, RawPosition, RecognitionCandidateV1,
            RecognitionProjectionV1, RegionCorrectionV1, StoredRegionCorrection, StrokeRef,
        },
        project_runtime::ProjectWriterAck,
        provider_protocol::{
            PROVIDER_PROTOCOL_VERSION, ProviderCandidateV1, ProviderCapabilitiesV1,
            ProviderIdentityV1, ProviderInputCapabilityV1, ProviderOutputCapabilityV1,
            RecognitionRequestV1, RecognitionResultV1, WorkerResponseFrameV1,
        },
        win32_pointer::{
            CaptureSource, CoordinateSpace, CoordinateUnits, DirectPenHistoryBatch,
            OwnedPointerSample, PointerAttribution, PointerMessageKind, PressureValidity, RawPoint,
            RawScreenPosition,
        },
    };
    use std::{fs, path::PathBuf, time::Duration};

    struct ReleaseWorkerOnDrop(PathBuf);

    impl Drop for ReleaseWorkerOnDrop {
        fn drop(&mut self) {
            let _ = fs::write(&self.0, b"release");
        }
    }

    fn provider_config_path(
        directory: &std::path::Path,
        executable: &std::path::Path,
        arguments: &[String],
    ) -> PathBuf {
        let path = directory.join("f4-convert-provider.json");
        let contents = serde_json::json!({
            "schema_version": 1,
            "providers": [{
                "provider_id": "senocr-v1-fp32-local",
                "executable_path": executable.to_string_lossy(),
                "arguments": arguments,
                "protocol_configuration": {
                    "configuration_id": "f4-convert-synthetic-config",
                    "values": { "fixture": "owned-synthetic-input" }
                },
                "requested_input_modalities": ["raster"],
                "language_hints": ["vi-VN"]
            }]
        });
        fs::write(&path, serde_json::to_vec(&contents).unwrap()).unwrap();
        path
    }

    fn response_frames(request: &RecognitionRequestV1) -> (String, String) {
        let provider = ProviderIdentityV1 {
            provider_id: "senocr-v1-fp32-local".to_owned(),
            provider_version: "synthetic-hosted-mock-v1".to_owned(),
            model_version: None,
            resource_version: None,
        };
        let capabilities = ProviderCapabilitiesV1 {
            inputs: vec![ProviderInputCapabilityV1::Raster],
            outputs: vec![ProviderOutputCapabilityV1::Text],
            languages: request.language_hints.clone(),
        };
        let handshake = WorkerResponseFrameV1::Handshake {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            provider: provider.clone(),
            configuration_id: request.provider_configuration.configuration_id.clone(),
            configuration_fingerprint: request.provider_configuration_fingerprint.clone(),
            capabilities,
        };
        let recognition = WorkerResponseFrameV1::Recognition {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            result: RecognitionResultV1 {
                request_id: request.request_id.clone(),
                input_view_id: request.input_view_id.clone(),
                source_revision: request.source_revision.clone(),
                region_id: request.region_id.clone(),
                line_id: request.line_id.clone(),
                provider_configuration_id: request.provider_configuration.configuration_id.clone(),
                provider_configuration_fingerprint: request
                    .provider_configuration_fingerprint
                    .clone(),
                provider,
                provider_provenance: "guarded synthetic Convert fixture; no recognition evidence"
                    .to_owned(),
                consumed_input_modalities: request.requested_input_modalities.clone(),
                candidates: vec![ProviderCandidateV1 {
                    recognized_text: "F4 synthetic conversion result".to_owned(),
                    native_score_raw: None,
                    stroke_ranges: Vec::new(),
                    raw_candidate: serde_json::json!({"fixture":"synthetic-only"}),
                }],
            },
        };
        (
            serde_json::to_string(&handshake).unwrap(),
            serde_json::to_string(&recognition).unwrap(),
        )
    }

    fn execution_for_request(request: &RecognitionRequestV1) -> ProviderExecution {
        let (_, response) = response_frames(request);
        let frame: WorkerResponseFrameV1 = serde_json::from_str(&response).unwrap();
        let WorkerResponseFrameV1::Recognition { result, .. } = frame else {
            panic!("synthetic response fixture must be a recognition frame");
        };
        ProviderExecution {
            provider: result.provider.clone(),
            capabilities: ProviderCapabilitiesV1 {
                inputs: vec![ProviderInputCapabilityV1::Raster],
                outputs: vec![ProviderOutputCapabilityV1::Text],
                languages: request.language_hints.clone(),
            },
            result,
            stderr_bytes: Vec::new(),
            stderr_truncated: false,
            raw_response_transcript: Default::default(),
            process_resources: None,
            timing: crate::provider_protocol::ProviderExecutionTimingV1 {
                process_create_call_to_handshake_ns: 0,
                process_create_call_to_recognition_ns: 0,
                process_create_call_to_parent_exit_ns: 0,
                process_create_call_to_tree_drain_ns: 0,
                model_cold_start_ns: None,
                model_cold_start_unavailable_reason: None,
            },
        }
    }

    fn direct_target(journal_id: &str, session_id: &str, stroke_id: &str) -> StrokeRef {
        StrokeRef {
            journal_id: journal_id.to_owned(),
            session_id: session_id.to_owned(),
            source_api: canvas::PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
            device_id: Some("session-scoped-device-f4".to_owned()),
            pointer_id: Some(17),
            stroke_id: stroke_id.to_owned(),
        }
    }

    fn direct_sample(target: &StrokeRef, source_sequence: u64, x_raw: i64) -> PhysicalSample {
        PhysicalSample {
            session_id: target.session_id.clone(),
            source_api: target.source_api.clone(),
            source_device_id: target.device_id.clone(),
            pointer_id: target.pointer_id,
            stroke_id: Some(target.stroke_id.clone()),
            source_sequence,
            config_id: Some("f4-synthetic-config".to_owned()),
            app_arrival_elapsed_ns: u128::from(source_sequence),
            position: Some(RawPosition {
                coordinate_space: "windows-screen-coordinates".to_owned(),
                units: "screen-pixel".to_owned(),
                x_raw,
                y_raw: 160,
            }),
            pressure: None,
            native_timestamp: None,
            contact_range_state: Some("contact".to_owned()),
            button_state_raw: None,
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload: vec![0xFA, u8::try_from(source_sequence).unwrap_or_default()],
        }
    }

    fn direct_ui_batch(
        message_sequence: u64,
        message_kind: PointerMessageKind,
        x_screen_px: i32,
        y_screen_px: i32,
    ) -> DirectPenHistoryBatch {
        let pointer_id = 29;
        let device_handle = 0xD129;
        DirectPenHistoryBatch {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence,
            message_id_raw: 0,
            message_hwnd_raw_session_scoped: 0xBEEF,
            message_time_ms_raw: Some(u32::try_from(message_sequence).unwrap_or_default()),
            message_kind,
            pointer_id_requested: pointer_id,
            hook_observed_elapsed_ns: u128::from(message_sequence),
            hook_qpc_count_raw: Some(message_sequence),
            hook_qpc_issue: None,
            qpc_frequency_hz: Some(10_000_000),
            native_history_count: 1,
            samples: vec![OwnedPointerSample {
                history_index_newest_first: 0,
                chronological_index: 0,
                attribution: PointerAttribution::MatchesRequestedPointer,
                pointer_type_raw: windows_sys::Win32::UI::WindowsAndMessaging::PT_PEN,
                pointer_id_raw: pointer_id,
                frame_id_raw: u32::try_from(message_sequence).unwrap_or_default(),
                source_device_handle_raw_session_scoped: device_handle,
                target_hwnd_raw_session_scoped: 0xBEEF,
                pointer_flags_raw: 0,
                button_change_type_raw: 0,
                position: RawScreenPosition {
                    coordinate_space: CoordinateSpace::WindowsScreenCoordinates,
                    pixel_units: CoordinateUnits::ScreenPixel,
                    pt_pixel_location_raw: RawPoint {
                        x: x_screen_px,
                        y: y_screen_px,
                    },
                    himetric_units: CoordinateUnits::HimetricHundredthMillimeter,
                    pt_himetric_location_raw: RawPoint { x: 0, y: 0 },
                },
                performance_count_qpc_raw: message_sequence,
                dw_time_ms_wrapping_raw: u32::try_from(message_sequence).unwrap_or_default(),
                history_count_raw: 1,
                input_data_raw: 0,
                key_states_raw: 0,
                pen_flags_raw: 0,
                pen_mask_raw: 0,
                pressure_raw: 0,
                pressure_validity: PressureValidity::NotReported,
                rotation_raw: 0,
                tilt_x_raw: 0,
                tilt_y_raw: 0,
                tilt: None,
                validation_issues: Vec::new(),
            }],
        }
    }

    fn provider_for_expected_request(
        directory: &std::path::Path,
        executable: &std::path::Path,
        state: &journal::JournalReplayState,
        target: &StrokeRef,
        active_session_id: &str,
        generation: u64,
    ) -> (
        PathBuf,
        LocalConvertProviderV1,
        convert::PreparedConversionV1,
    ) {
        let config_path = provider_config_path(directory, executable, &[]);
        let provider = LocalConvertProviderV1::load(&config_path, None).unwrap();
        let request_id = format!("convert-{active_session_id}-{generation}");
        let cancellation = AtomicBool::new(false);
        let prepared = prepare_conversion(
            state,
            std::slice::from_ref(target),
            &request_id,
            "line-1",
            &provider,
            &cancellation,
        )
        .unwrap();
        (config_path, provider, prepared)
    }

    fn make_test_app(
        project_path: PathBuf,
        project_journal_id: String,
        active_session_id: String,
        writer: ProjectWriterHandle,
        provider: LocalConvertProviderV1,
        scene: CanvasScene,
        app_clock_origin: Instant,
    ) -> ProbeApp {
        let mut probe = ProbeState::default();
        probe.set_capture_mode(CaptureMode::DirectWmPointer);
        let probe_state = Rc::new(RefCell::new(probe));
        let wintab_capture = {
            let mut state = probe_state.borrow_mut();
            WintabCapture::new(CaptureMode::DirectWmPointer, app_clock_origin, &mut state)
        };
        ProbeApp {
            window: None,
            focused: None,
            client_size: None,
            last_title: None,
            last_title_update: None,
            startup_error: None,
            capture_mode: CaptureMode::DirectWmPointer,
            app_clock_origin,
            probe_state,
            wintab: Rc::new(RefCell::new(wintab_capture)),
            wintab_control_observer: None,
            wintab_control_pending: Arc::new(AtomicBool::new(false)),
            session_writer: None,
            session_path: project_path.with_extension("session.tsv"),
            session_writer_failed: false,
            project_writer: Some(writer),
            project_path,
            project_journal_id,
            local_convert_provider: Some(provider),
            provider_worker: None,
            pending_convert: None,
            correction_session: None,
            pending_correction: None,
            next_correction_id: 1,
            correction_focus: CorrectionPaneFocus::None,
            correction_panel_status: String::new(),
            provider_config_path_editor: CorrectionTextEditor::new("").unwrap(),
            provider_id_editor: CorrectionTextEditor::new("").unwrap(),
            export_path_editor: CorrectionTextEditor::new("").unwrap(),
            direct_ui_pointer_owners: DirectUiPointerOwnerTracker::default(),
            deferred_pane_actions: Vec::new(),
            correction_pane_scroll: CorrectionPaneScrollOffsets::default(),
            pane_text_measurements: GdiTextAdvanceCache::default(),
            correction_editor_browse_mode: false,
            correction_mouse_selection_anchor: None,
            correction_mouse_selecting: false,
            alt_graph_active: false,
            next_convert_generation: 1,
            project_generation: 1,
            convert_view_generation: 0,
            active_session_id,
            active_config_id: "f4-synthetic-config".to_owned(),
            direct_input_tracker: CanvasInputTracker::default(),
            canvas_tool_gesture_tracker: CanvasToolGestureTracker::default(),
            deferred_canvas_intents: Vec::new(),
            last_project_message_sequence: 0,
            pending_record_cursor: PendingRecordCursor::default(),
            next_project_batch_id: 1,
            deferred_capture_batch: None,
            project_incomplete_reason: None,
            project_recovery_note: None,
            historical_interrupted_strokes_at_start: 0,
            controlled_stall: ControlledStallTrigger::default(),
            canvas_scene: scene,
            canvas_viewport: CanvasViewport::default(),
            canvas_origin: None,
            canvas_dpi_scale_factor: 1.0,
            canvas_cursor_client: None,
            canvas_modifiers: ModifiersState::empty(),
            canvas_selection_drag_start: None,
            canvas_move_drag_start: None,
            canvas_pan_drag_last: None,
            canvas_status: "synthetic F4 controller test".to_owned(),
        }
    }

    fn scroll_state_correction_session(
        journal_id: &str,
    ) -> (CorrectionSession, String, String, String) {
        let projection_id = "pane-scroll-projection";
        let provider_text = format!("PROVIDER-HEAD-{}-PROVIDER-TAIL", "p".repeat(220));
        let saved_text = format!("SAVED-ORIGINAL-HEAD-{}-SAVED-TAIL", "s".repeat(64));
        let draft_text = format!("DIRTY-DRAFT-HEAD-{}-DIRTY-DRAFT-TAIL", "d".repeat(260));
        let ink = ProjectionInkBindingV1 {
            journal_id: journal_id.to_owned(),
            logical_revision: 1,
            last_sequence: 1,
            region_id: "pane-scroll-region".to_owned(),
            line_id: Some("pane-scroll-line".to_owned()),
            input_view_id: "input-view-v1-0000000000000001".to_owned(),
            ink_binding_sha256: "a".repeat(64),
            selected_strokes: Vec::new(),
            source_sample_sequences: Vec::new(),
            stroke_views: Vec::new(),
        };
        let projection = RecognitionProjectionV1 {
            projection_id: projection_id.to_owned(),
            ink: ink.clone(),
            provider: ProjectionProviderProvenanceV1 {
                provider_id: "pane-scroll-provider".to_owned(),
                provider_version: "synthetic-v1".to_owned(),
                model_version: Some("model-scroll-v1".to_owned()),
                resource_version: Some("resource-scroll-v1".to_owned()),
                configuration_id: "pane-scroll-config".to_owned(),
                configuration_fingerprint: "provider-config-v1-fnv64-0000000000000001".to_owned(),
            },
            candidates: vec![RecognitionCandidateV1 {
                rank: 0,
                recognized_text: provider_text.clone(),
                native_score_raw: Some("0.875".to_owned()),
                stroke_ranges: Vec::new(),
            }],
            input_modalities: None,
            generated_raster: None,
        };
        let saved_correction = RegionCorrectionV1 {
            correction_id: "pane-scroll-saved-correction".to_owned(),
            projection_id: projection_id.to_owned(),
            ink,
            action: RegionCorrectionActionV1::SetText(saved_text.clone()),
        };
        let mut state = JournalReplayState::default();
        state.journal_id = journal_id.to_owned();
        state
            .recognition_projections
            .push(StoredRecognitionProjection {
                sequence: 1,
                app_epoch_id: "pane-scroll-session".to_owned(),
                app_arrival_elapsed_ns: 1,
                projection,
            });
        state.region_corrections.push(StoredRegionCorrection {
            sequence: 2,
            app_epoch_id: "pane-scroll-session".to_owned(),
            app_arrival_elapsed_ns: 2,
            correction: saved_correction,
        });
        let mut session = CorrectionSession::open(&state, projection_id).unwrap();
        session.set_text(&draft_text).unwrap();
        session.select_graphemes(5, 21);
        (session, provider_text, saved_text, draft_text)
    }

    #[test]
    fn pane_wheel_preserves_dirty_session_candidates_and_convert_intent() {
        let directory = std::env::temp_dir().join(format!(
            "lassoink-pane-scroll-state-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let project_path = directory.join("pane-scroll-state.inkj");
        let journal_id = "pane-scroll-state-project";
        let session_id = "pane-scroll-state-session";
        let journal_writer = JournalWriter::create(
            project_path.clone(),
            JournalHeader {
                journal_id: journal_id.to_owned(),
                session_id: session_id.to_owned(),
                config_id: Some("pane-scroll-config".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        let writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        let config_path = provider_config_path(&directory, &std::env::current_exe().unwrap(), &[]);
        let provider = LocalConvertProviderV1::load(&config_path, None).unwrap();
        let mut app = make_test_app(
            project_path,
            journal_id.to_owned(),
            session_id.to_owned(),
            writer,
            provider,
            CanvasScene::default(),
            Instant::now(),
        );
        app.client_size = Some((960, 720));
        app.correction_focus = CorrectionPaneFocus::CorrectionEditor;
        let (session, provider_text, saved_text, draft_text) =
            scroll_state_correction_session(journal_id);
        app.correction_session = Some(session);
        app.convert_view_generation = 41;
        app.pending_convert = Some(PendingConvert {
            generation: 7,
            project_generation: app.project_generation,
            view_generation: app.convert_view_generation,
            cancelled: false,
            selected_strokes_in_ui_order: Vec::new(),
            line_id: "pane-scroll-line".to_owned(),
            request: None,
            ink_binding: None,
            generated_raster: None,
            phase: PendingConvertPhase::SnapshotForPreparation { batch_id: 77 },
        });

        let viewport_before = app.canvas_viewport;
        let view_generation_before = app.convert_view_generation;
        let session = app.correction_session.as_ref().unwrap();
        let candidate_before = session.projection().candidates[0].recognized_text.clone();
        let effective_before = session.effective_text().map(str::to_owned);
        let history_before = session.correction_history().to_vec();
        let latest_saved_before = session.latest_saved_action().cloned();
        let draft_action_before = session.draft_action();
        let selected_text_before = session.selected_text().map(str::to_owned);
        let selection_before = session.editor().selection_graphemes();
        let cursor_before = session.editor().cursor_grapheme();
        let undo_depth_before = session.editor().undo_depth();
        assert!(session.is_dirty());
        assert_eq!(candidate_before, provider_text);
        assert_eq!(
            latest_saved_before,
            Some(RegionCorrectionActionV1::SetText(saved_text))
        );
        assert_eq!(session.text(), draft_text);
        let pending_batch_before = 77_u64;

        for section in [
            CorrectionPaneTextSection::ProviderOutput,
            CorrectionPaneTextSection::EffectiveText,
            CorrectionPaneTextSection::Draft,
        ] {
            let layout = app.correction_pane_layout().unwrap();
            let region = layout
                .scroll_regions
                .iter()
                .find(|region| region.section == section)
                .unwrap();
            assert!(region.total_rows > region.visible_rows);
            let row = region.row_range.start;
            let offset_before = app.correction_pane_scroll.get(section);
            app.canvas_cursor_client = Some((
                f64::from(960 - CORRECTION_PANE_WIDTH_PX + CORRECTION_PANE_PADDING_PX + 1),
                f64::from(
                    CORRECTION_PANE_PADDING_PX
                        + i32::try_from(row).unwrap() * CORRECTION_PANE_ROW_HEIGHT_PX
                        + 1,
                ),
            ));
            assert!(app.handle_correction_pane_wheel(&MouseScrollDelta::LineDelta(0.0, -1.0)));
            assert_eq!(app.correction_pane_scroll.get(section), offset_before + 1);

            let session = app.correction_session.as_ref().unwrap();
            assert_eq!(
                session.projection().candidates[0].recognized_text,
                candidate_before
            );
            assert_eq!(
                session.effective_text().map(str::to_owned),
                effective_before
            );
            assert_eq!(session.text(), draft_text);
            assert_eq!(session.draft_action(), draft_action_before);
            assert_eq!(session.correction_history(), history_before.as_slice());
            assert_eq!(session.latest_saved_action(), latest_saved_before.as_ref());
            assert_eq!(
                session.selected_text().map(str::to_owned),
                selected_text_before
            );
            assert_eq!(session.editor().selection_graphemes(), selection_before);
            assert_eq!(session.editor().cursor_grapheme(), cursor_before);
            assert_eq!(session.editor().undo_depth(), undo_depth_before);
            assert!(matches!(
                app.pending_convert.as_ref(),
                Some(PendingConvert {
                    generation: 7,
                    cancelled: false,
                    phase: PendingConvertPhase::SnapshotForPreparation { batch_id },
                    ..
                }) if *batch_id == pending_batch_before
            ));
            assert_eq!(app.canvas_viewport.zoom(), viewport_before.zoom());
            assert_eq!(app.canvas_viewport.pan(), viewport_before.pan());
            assert_eq!(app.convert_view_generation, view_generation_before);
        }

        app.finish_project_writer().unwrap();
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    #[ignore = "guarded hosted Windows Convert intent retry and writer ordering fixture"]
    fn queued_convert_intent_retries_snapshot_after_accepted_raw_rows() {
        require_native_ui_test_opt_in();
        let directory = std::env::temp_dir().join(format!(
            "lassoink-convert-intent-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let project_path = directory.join("convert-intent.inkj");
        let journal_id = "convert-intent-project";
        let active_session_id = "convert-intent-session";
        let target = direct_target(journal_id, active_session_id, "selected-stroke");
        let frame = StrokeViewFrame::default();
        let mut journal_writer = JournalWriter::create(
            project_path.clone(),
            JournalHeader {
                journal_id: journal_id.to_owned(),
                session_id: active_session_id.to_owned(),
                config_id: Some("f4-synthetic-config".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        journal_writer
            .start_stroke(target.clone(), frame, 1)
            .unwrap();
        journal_writer
            .append_sample(direct_sample(&target, 1, 120))
            .unwrap();
        journal_writer.commit_stroke(target.clone(), 2).unwrap();
        let initial_state = journal_writer.replay_state().clone();
        let mut scene =
            CanvasScene::from_journal(&initial_state, PROVISIONAL_DIRECT_SOURCE_API).unwrap();
        scene.select_target(Some(target.clone())).unwrap();
        let project_writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        let config_path = provider_config_path(&directory, &std::env::current_exe().unwrap(), &[]);
        let provider = LocalConvertProviderV1::load(&config_path, None).unwrap();
        let mut app = make_test_app(
            project_path.clone(),
            journal_id.to_owned(),
            active_session_id.to_owned(),
            project_writer,
            provider,
            scene,
            Instant::now(),
        );

        let mut unowned_sample = direct_sample(&target, 2, 240);
        unowned_sample.stroke_id = None;
        app.project_writer
            .as_mut()
            .unwrap()
            .try_capture_batch(
                1,
                vec![DirectCaptureEvent::PhysicalSample(Box::new(
                    unowned_sample.clone(),
                ))],
            )
            .unwrap();
        for batch_id in 2..=8 {
            app.project_writer
                .as_mut()
                .unwrap()
                .try_snapshot_for_convert(batch_id)
                .unwrap();
        }
        app.next_project_batch_id = 9;
        app.start_or_cancel_convert();
        assert!(matches!(
            app.pending_convert.as_ref(),
            Some(PendingConvert {
                phase: PendingConvertPhase::QueueSnapshotForPreparation { batch_id: 9 },
                ..
            })
        ));
        assert!(app.canvas_status.contains("intent retained"));

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut initial_acks = Vec::new();
        while !app.project_writer.as_ref().unwrap().is_idle() {
            initial_acks.extend(app.project_writer.as_mut().unwrap().drain_acks());
            assert!(
                Instant::now() < deadline,
                "writer queue did not drain for Convert retry"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        initial_acks.extend(app.project_writer.as_mut().unwrap().drain_acks());
        assert!(matches!(
            initial_acks.first(),
            Some(ProjectWriterAck::CaptureCommitted { records, .. })
                if records.len() == 1
                    && matches!(&records[0].event,
                        JournalEvent::PhysicalSample(sample) if sample.stroke_id.is_none())
        ));

        app.poll_convert();
        assert!(matches!(
            app.pending_convert.as_ref(),
            Some(PendingConvert {
                phase: PendingConvertPhase::SnapshotForPreparation { batch_id: 9 },
                ..
            })
        ));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut retried_snapshot = None;
        while retried_snapshot.is_none() {
            for ack in app.project_writer.as_mut().unwrap().drain_acks() {
                if let ProjectWriterAck::ConvertSnapshot { batch_id: 9, state } = ack {
                    retried_snapshot = Some(*state);
                }
            }
            assert!(
                Instant::now() < deadline,
                "retained Convert snapshot did not ACK"
            );
            if retried_snapshot.is_none() {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let frozen_state = retried_snapshot.unwrap();
        assert_eq!(frozen_state.physical_samples.len(), 2);
        assert_eq!(frozen_state.physical_samples[1].sample, unowned_sample);
        assert!(frozen_state.physical_samples[1].sample.stroke_id.is_none());
        assert_eq!(frozen_state.stroke_starts.len(), 1);

        app.cancel_convert("test cleanup".to_owned());
        app.finish_project_writer().unwrap();
        let persisted = read_journal(&project_path).unwrap();
        assert_eq!(persisted.state.physical_samples.len(), 2);
        assert_eq!(persisted.state.physical_samples[1].sample, unowned_sample);
        assert_eq!(persisted.state.stroke_starts.len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "guarded hosted Windows Direct-pointer pane action and writer ordering fixture"]
    fn direct_pen_convert_click_queues_raw_rows_before_one_snapshot_and_suppresses_mouse_promotion()
    {
        require_native_ui_test_opt_in();
        let directory = std::env::temp_dir().join(format!(
            "lassoink-direct-pane-action-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let project_path = directory.join("direct-pane-action.inkj");
        let journal_id = "direct-pane-action-project";
        let session_id = "direct-pane-action-session";
        let target = direct_target(journal_id, session_id, "committed-selection");
        let frame = StrokeViewFrame::default();
        let initial_sample = direct_sample(&target, 1, 40);
        let mut journal_writer = JournalWriter::create(
            project_path.clone(),
            JournalHeader {
                journal_id: journal_id.to_owned(),
                session_id: session_id.to_owned(),
                config_id: Some("f4-synthetic-config".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        journal_writer
            .start_stroke(target.clone(), frame, 1)
            .unwrap();
        journal_writer.append_sample(initial_sample).unwrap();
        journal_writer.commit_stroke(target.clone(), 2).unwrap();
        let initial_state = journal_writer.replay_state().clone();
        let mut scene =
            CanvasScene::from_journal(&initial_state, PROVISIONAL_DIRECT_SOURCE_API).unwrap();
        scene.select_target(Some(target)).unwrap();
        let writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        let config_path = provider_config_path(&directory, &std::env::current_exe().unwrap(), &[]);
        let provider = LocalConvertProviderV1::load(&config_path, None).unwrap();
        let mut app = make_test_app(
            project_path.clone(),
            journal_id.to_owned(),
            session_id.to_owned(),
            writer,
            provider,
            scene,
            Instant::now(),
        );
        // Setup/config parsing is explicit and does not start the worker.
        assert!(config_path.is_file());
        app.canvas_origin = Some(CanvasOrigin::default());
        app.client_size = Some((960, 720));

        let layout = app.correction_pane_layout().unwrap();
        let action_row = layout.action_row.unwrap();
        let click_x = 600 + CORRECTION_PANE_PADDING_PX + 16;
        let click_y = CORRECTION_PANE_PADDING_PX
            + i32::try_from(action_row).unwrap() * CORRECTION_PANE_ROW_HEIGHT_PX
            + 2;
        let down = direct_ui_batch(1, PointerMessageKind::Down, click_x, click_y);
        let up = direct_ui_batch(2, PointerMessageKind::Up, click_x, click_y);
        app.probe_state
            .borrow_mut()
            .record(ProbeRecord::DirectPenHistory(down));
        app.probe_state
            .borrow_mut()
            .record(ProbeRecord::DirectPenHistory(up));

        let before_visible_strokes = app
            .canvas_scene
            .render_plan(app.canvas_viewport)
            .unwrap()
            .len();
        app.process_pending_project_capture();
        assert_eq!(before_visible_strokes, 1);
        assert_eq!(
            app.canvas_scene
                .render_plan(app.canvas_viewport)
                .unwrap()
                .len(),
            before_visible_strokes,
            "pane-started Direct gesture must not add visible ink"
        );
        assert!(matches!(
            app.pending_convert.as_ref(),
            Some(PendingConvert {
                generation: 1,
                phase: PendingConvertPhase::SnapshotForPreparation { batch_id: 2 },
                ..
            })
        ));
        assert!(
            !app.project_writer.as_ref().unwrap().is_idle(),
            "capture and snapshot ACKs should still be pending"
        );

        app.correction_panel_status = format!(
            "SCROLL-HEAD-{}-SCROLL-MIDDLE-{}-SCROLL-TAIL",
            "s".repeat(60),
            "t".repeat(60),
        );
        let pane_before_scroll = app.correction_pane_layout().unwrap();
        assert!(correction_pane_visible_row_count(720) >= pane_before_scroll.lines.len());
        let action_row_before_scroll = pane_before_scroll.action_row;
        let provider_path_row_before_scroll = pane_before_scroll.provider_path_row;
        let provider_id_row_before_scroll = pane_before_scroll.provider_id_row;
        let load_row_before_scroll = pane_before_scroll.load_config_row;
        let export_row_before_scroll = pane_before_scroll.export_path_row;
        let status_region = pane_before_scroll
            .scroll_regions
            .iter()
            .find(|region| region.section == CorrectionPaneTextSection::Status)
            .unwrap();
        assert!(status_region.total_rows > status_region.visible_rows);
        let scroll_offset_before = app
            .correction_pane_scroll
            .get(CorrectionPaneTextSection::Status);
        let viewport_before_scroll = app.canvas_viewport;
        let generation_before_scroll = app.convert_view_generation;
        app.canvas_cursor_client = Some((
            f64::from(960 - CORRECTION_PANE_WIDTH_PX + CORRECTION_PANE_PADDING_PX + 1),
            f64::from(
                CORRECTION_PANE_PADDING_PX
                    + i32::try_from(status_region.row_range.start).unwrap()
                        * CORRECTION_PANE_ROW_HEIGHT_PX
                    + 1,
            ),
        ));
        assert!(app.handle_correction_pane_wheel(&MouseScrollDelta::LineDelta(0.0, -1.0)));
        assert!(
            app.correction_pane_scroll
                .get(CorrectionPaneTextSection::Status)
                > scroll_offset_before
        );
        assert_eq!(app.canvas_viewport.zoom(), viewport_before_scroll.zoom());
        assert_eq!(app.canvas_viewport.pan(), viewport_before_scroll.pan());
        assert_eq!(app.convert_view_generation, generation_before_scroll);
        let pane_after_scroll = app.correction_pane_layout().unwrap();
        assert_eq!(pane_after_scroll.action_row, action_row_before_scroll);
        assert_eq!(
            pane_after_scroll.provider_path_row,
            provider_path_row_before_scroll
        );
        assert_eq!(
            pane_after_scroll.provider_id_row,
            provider_id_row_before_scroll
        );
        assert_eq!(pane_after_scroll.load_config_row, load_row_before_scroll);
        assert_eq!(pane_after_scroll.export_path_row, export_row_before_scroll);
        assert!(matches!(
            app.pending_convert.as_ref().map(|pending| &pending.phase),
            Some(PendingConvertPhase::SnapshotForPreparation { batch_id: 2 })
        ));

        app.canvas_cursor_client = Some((f64::from(click_x), f64::from(click_y)));
        let promoted_mouse_hits_pane_action =
            app.winit_mouse_input_targets_pane_action(MouseButton::Left, ElementState::Pressed);
        if super::should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::PenPromoted { cursor_id: 7 },
            app.direct_ui_pointer_owners.has_active_canvas_pointer(),
            app.direct_ui_pointer_owners.has_pending_direct_action(),
            promoted_mouse_hits_pane_action,
        ) {
            assert!(app.handle_correction_mouse_button(MouseButton::Left, ElementState::Pressed));
        }
        assert_eq!(
            app.next_project_batch_id, 3,
            "promoted mouse click must not queue a second snapshot"
        );
        assert!(matches!(
            app.pending_convert.as_ref().map(|pending| &pending.phase),
            Some(PendingConvertPhase::SnapshotForPreparation { batch_id: 2 })
        ));

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut acknowledgements = Vec::new();
        while !app.project_writer.as_ref().unwrap().is_idle() {
            acknowledgements.extend(app.project_writer.as_mut().unwrap().drain_acks());
            assert!(
                Instant::now() < deadline,
                "capture/snapshot ACK sequence timed out"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        acknowledgements.extend(app.project_writer.as_mut().unwrap().drain_acks());
        let [
            ProjectWriterAck::CaptureCommitted { records, .. },
            ProjectWriterAck::ConvertSnapshot { batch_id: 2, state },
        ] = acknowledgements.as_slice()
        else {
            panic!("expected ordered raw capture then Convert snapshot acknowledgements");
        };
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| matches!(
            &record.event,
            JournalEvent::PhysicalSample(sample) if sample.stroke_id.is_none()
        )));
        assert_eq!(state.physical_samples.len(), 3);
        assert!(
            state.physical_samples[1..]
                .iter()
                .all(|sample| sample.sample.stroke_id.is_none())
        );
        assert_eq!(state.stroke_starts.len(), 1);

        app.cancel_convert("test cleanup".to_owned());
        app.finish_project_writer().unwrap();
        let persisted = read_journal(&project_path).unwrap();
        assert_eq!(persisted.state.physical_samples.len(), 3);
        assert_eq!(persisted.state.stroke_starts.len(), 1);
        assert!(
            persisted.state.physical_samples[1..]
                .iter()
                .all(|sample| sample.sample.stroke_id.is_none())
        );
        fs::remove_dir_all(directory).unwrap();
    }

    fn wait_for_app(app: &mut ProbeApp, timeout: Duration, finished: impl Fn(&ProbeApp) -> bool) {
        let deadline = Instant::now() + timeout;
        while !finished(app) {
            app.drain_project_writer_acks();
            app.poll_convert();
            assert!(
                Instant::now() < deadline,
                "F4 mock pipeline did not reach its checkpoint"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    #[ignore = "guarded hosted Windows production Convert/M4 mock path; synthetic only"]
    // This exercises the F4 controller and durable path, not the real pinned SenOCR model.
    fn f4_convert_mock_pipeline_persists_then_rejects_stale_view_and_capture_continues() {
        require_native_ui_test_opt_in();
        crate::provider_protocol::tests::require_provider_mock_test_opt_in();
        let mock = crate::provider_protocol::tests::compile_mock_worker();
        let project_path = mock.directory.join("f4-convert-project.inkj");
        let journal_id = "f4-convert-mock-project";
        let active_session_id = "f4-convert-mock-session";
        let target = direct_target(journal_id, active_session_id, "f4-selected-stroke");
        let initial_sample = direct_sample(&target, 1, 120);
        let frame = StrokeViewFrame::default();
        let mut journal_writer = JournalWriter::create(
            project_path.clone(),
            JournalHeader {
                journal_id: journal_id.to_owned(),
                session_id: active_session_id.to_owned(),
                config_id: Some("f4-synthetic-config".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        journal_writer
            .start_stroke(target.clone(), frame, 1)
            .unwrap();
        journal_writer
            .append_sample(initial_sample.clone())
            .unwrap();
        journal_writer.commit_stroke(target.clone(), 2).unwrap();
        let initial_state = journal_writer.replay_state().clone();
        let mut scene =
            CanvasScene::from_journal(&initial_state, canvas::PROVISIONAL_DIRECT_SOURCE_API)
                .unwrap();
        scene.select_target(Some(target.clone())).unwrap();
        let writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        let (provider_path, _provider_before_first, expected_first) = provider_for_expected_request(
            &mock.directory,
            &mock.executable,
            &initial_state,
            &target,
            active_session_id,
            1,
        );
        let (first_handshake, first_response) = response_frames(&expected_first.request);
        let first_arguments = vec!["ok".to_owned(), first_handshake, first_response];
        provider_config_path(&mock.directory, &mock.executable, &first_arguments);
        let first_provider = LocalConvertProviderV1::load(&provider_path, None).unwrap();
        let app_clock_origin = Instant::now();
        let mut app = make_test_app(
            project_path.clone(),
            journal_id.to_owned(),
            active_session_id.to_owned(),
            writer,
            first_provider,
            scene,
            app_clock_origin,
        );

        // This is the same controller method reached by F4 in the real window.
        app.start_or_cancel_convert();
        wait_for_app(&mut app, Duration::from_secs(25), |app| {
            app.pending_convert.is_none()
                && app.canvas_status == "Convert result was durably saved as a projection"
        });
        assert!(app.project_writer.as_ref().unwrap().is_idle());
        let initial_pane = app.correction_pane_layout().unwrap();
        assert!(
            initial_pane
                .lines
                .iter()
                .any(|line| line == "Provider output (immutable):")
        );
        assert!(
            initial_pane
                .lines
                .iter()
                .any(|line| line.contains("F4 synthetic conversion result"))
        );
        assert!(
            initial_pane
                .lines
                .iter()
                .any(|line| line == "Model version: unavailable")
        );
        assert!(
            initial_pane
                .lines
                .iter()
                .any(|line| line == "Resource version: unavailable")
        );
        let provider_details_bottom_offset = initial_pane
            .scroll_regions
            .iter()
            .find(|region| region.section == CorrectionPaneTextSection::ProviderDetails)
            .map(|region| region.total_rows.saturating_sub(region.visible_rows))
            .unwrap();
        app.correction_pane_scroll.set(
            CorrectionPaneTextSection::ProviderDetails,
            provider_details_bottom_offset,
        );
        let pane = app.correction_pane_layout().unwrap();
        let provider_details_region = pane
            .scroll_regions
            .iter()
            .find(|region| region.section == CorrectionPaneTextSection::ProviderDetails)
            .unwrap();
        let provider_details = pane.lines[provider_details_region.row_range.clone()]
            .iter()
            .map(String::as_str)
            .collect::<String>();
        assert!(
            provider_details.contains("Native score")
                && provider_details.contains("unavailable (uncalibrated)")
        );
        assert!(pane.provider_path_row.is_some());
        assert!(pane.provider_id_row.is_some());
        assert!(pane.load_config_row.is_some());
        assert!(pane.export_path_row.is_some());
        assert!(
            pane.lines
                .iter()
                .any(|line| line.contains("Export is not implemented"))
        );
        assert!(
            app.correction_session
                .as_ref()
                .is_some_and(|session| !session.is_dirty())
        );
        app.set_correction_focus(CorrectionPaneFocus::CorrectionEditor);
        assert!(
            app.correction_session
                .as_ref()
                .is_some_and(|session| session.text() == "F4 synthetic conversion result"
                    && !session.is_dirty())
        );
        app.canvas_origin = Some(CanvasOrigin::default());
        app.client_size = Some((960, 720));
        app.correction_session
            .as_mut()
            .unwrap()
            .insert_text(" corrected by user")
            .unwrap();
        let save_row = app.correction_pane_layout().unwrap().action_row.unwrap();
        let save_x = 600 + CORRECTION_PANE_PADDING_PX + 88;
        let save_y = CORRECTION_PANE_PADDING_PX
            + i32::try_from(save_row).unwrap() * CORRECTION_PANE_ROW_HEIGHT_PX
            + 2;
        app.probe_state
            .borrow_mut()
            .record(ProbeRecord::DirectPenHistory(direct_ui_batch(
                1,
                PointerMessageKind::Down,
                save_x,
                save_y,
            )));
        app.probe_state
            .borrow_mut()
            .record(ProbeRecord::DirectPenHistory(direct_ui_batch(
                2,
                PointerMessageKind::Up,
                save_x,
                save_y,
            )));
        app.process_pending_project_capture();
        assert!(
            app.pending_correction
                .as_ref()
                .is_some_and(|pending| pending.enqueued)
        );
        assert!(
            !app.project_writer.as_ref().unwrap().is_idle(),
            "raw pen and correction ACKs should still be pending"
        );
        app.canvas_cursor_client = Some((f64::from(save_x), f64::from(save_y)));
        let next_batch_after_direct_save = app.next_project_batch_id;
        let promoted_mouse_hits_pane_action =
            app.winit_mouse_input_targets_pane_action(MouseButton::Left, ElementState::Pressed);
        if super::should_process_winit_mouse_input(
            CaptureMode::DirectWmPointer,
            MouseMessageOrigin::PenPromoted { cursor_id: 7 },
            app.direct_ui_pointer_owners.has_active_canvas_pointer(),
            app.direct_ui_pointer_owners.has_pending_direct_action(),
            promoted_mouse_hits_pane_action,
        ) {
            assert!(app.handle_correction_mouse_button(MouseButton::Left, ElementState::Pressed));
        }
        assert_eq!(
            app.next_project_batch_id, next_batch_after_direct_save,
            "promoted Winit mouse click must not enqueue a second correction"
        );
        wait_for_app(&mut app, Duration::from_secs(10), |app| {
            app.pending_correction.is_none()
                && app.correction_panel_status.contains("durably saved")
        });
        assert!(
            app.correction_session.as_ref().is_some_and(
                |session| !session.is_dirty() && session.correction_history().len() == 1
            )
        );

        let snapshot_batch_id = app.allocate_project_batch_id().unwrap();
        app.project_writer
            .as_mut()
            .unwrap()
            .try_snapshot_for_convert(snapshot_batch_id)
            .unwrap();
        let current_state = loop {
            let mut found = None;
            for ack in app.project_writer.as_mut().unwrap().drain_acks() {
                match ack {
                    ProjectWriterAck::ConvertSnapshot { batch_id, state }
                        if batch_id == snapshot_batch_id =>
                    {
                        found = Some(*state)
                    }
                    other => {
                        panic!("unexpected snapshot ACK in guarded Convert fixture: {other:?}")
                    }
                }
            }
            if let Some(state) = found {
                break state;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(current_state.recognition_projections.len(), 1);
        assert_eq!(current_state.region_corrections.len(), 1);
        assert_eq!(current_state.physical_samples.len(), 3);
        assert!(
            current_state.physical_samples[1..]
                .iter()
                .all(|sample| sample.sample.stroke_id.is_none())
        );
        assert!(
            current_state.region_corrections[0].sequence
                > current_state.physical_samples[2].sequence
        );

        let (second_config_path, _provider_before_second, expected_second) =
            provider_for_expected_request(
                &mock.directory,
                &mock.executable,
                &current_state,
                &target,
                active_session_id,
                2,
            );
        assert_eq!(
            expected_first.request.region_id,
            expected_second.request.region_id
        );
        assert_ne!(
            expected_first.request.request_id,
            expected_second.request.request_id
        );
        assert_eq!(
            expected_first.request.input_view_id,
            expected_second.request.input_view_id
        );
        let (second_handshake, second_response) = response_frames(&expected_second.request);
        let ready_marker = mock.directory.join("f4-worker-ready.marker");
        let release_marker = mock.directory.join("f4-worker-release.marker");
        let _release_on_drop = ReleaseWorkerOnDrop(release_marker.clone());
        let second_arguments = vec![
            "ok-wait-release".to_owned(),
            second_handshake,
            second_response,
            ready_marker.to_string_lossy().into_owned(),
            release_marker.to_string_lossy().into_owned(),
        ];
        provider_config_path(&mock.directory, &mock.executable, &second_arguments);
        let second_provider = LocalConvertProviderV1::load(&second_config_path, None).unwrap();
        app.local_convert_provider = Some(second_provider);
        app.start_or_cancel_convert();
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            app.drain_project_writer_acks();
            app.poll_convert();
            let provider_running = app.pending_convert.as_ref().is_some_and(|pending| {
                matches!(&pending.phase, PendingConvertPhase::ProviderRunning)
            });
            if provider_running && ready_marker.exists() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "mock did not consume the second M4 request"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        // Inject a durable logical edit after M4 submission but before the
        // ordered revalidation snapshot. Hold its ACK so the production
        // controller exercises its source/view revalidation rather than the
        // earlier UI gesture-cancellation branch.
        let move_batch_id = app.allocate_project_batch_id().unwrap();
        app.project_writer
            .as_mut()
            .unwrap()
            .try_edit_action(
                move_batch_id,
                app.app_clock_origin.elapsed().as_nanos(),
                EditCommand::Move {
                    target: target.clone(),
                    delta_x_raw: 9,
                    delta_y_raw: 0,
                    coordinate_space: "windows-screen-coordinates".to_owned(),
                    units: "screen-pixel".to_owned(),
                },
            )
            .unwrap();
        let mut moved_projection = None;
        let deadline = Instant::now() + Duration::from_secs(10);
        while moved_projection.is_none() {
            for ack in app.project_writer.as_mut().unwrap().drain_acks() {
                match ack {
                    ProjectWriterAck::EditCommitted {
                        batch_id,
                        projection,
                        ..
                    } if batch_id == move_batch_id => moved_projection = Some(*projection),
                    other => panic!("unexpected ACK before releasing mock: {other:?}"),
                }
            }
            assert!(
                Instant::now() < deadline,
                "logical edit did not durably acknowledge"
            );
            if moved_projection.is_none() {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        release_marker_guarded_write(&release_marker);

        wait_for_app(&mut app, Duration::from_secs(25), |app| {
            app.pending_convert.is_none()
                && app.canvas_status
                    == "Convert result is stale: current selected ink/view differs from its request"
        });
        app.canvas_scene
            .refresh_from_journal(moved_projection.as_ref().unwrap())
            .unwrap();
        app.note_convert_view_change();

        app.set_correction_focus(CorrectionPaneFocus::CorrectionEditor);
        app.correction_session
            .as_mut()
            .unwrap()
            .insert_text(" stale draft")
            .unwrap();
        app.save_correction();
        let correction_deadline = Instant::now() + Duration::from_secs(10);
        while app.pending_correction.is_some() {
            app.drain_project_writer_acks();
            assert!(
                Instant::now() < correction_deadline,
                "stale correction did not receive a recoverable writer response"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(app.correction_panel_status.contains("draft is retained"));
        assert!(
            app.correction_session
                .as_ref()
                .is_some_and(CorrectionSession::is_dirty)
        );

        let continued_target = direct_target(journal_id, active_session_id, "after-stale-capture");
        let continued_sample = direct_sample(&continued_target, 1, 240);
        let capture_events = vec![
            DirectCaptureEvent::StrokeStarted {
                target: continued_target.clone(),
                view_frame: frame,
                app_arrival_elapsed_ns: 40,
            },
            DirectCaptureEvent::PhysicalSample(Box::new(continued_sample.clone())),
            DirectCaptureEvent::StrokeCommitRequested {
                target: continued_target,
                app_arrival_elapsed_ns: 41,
            },
        ];
        app.apply_capture_preview_events(&capture_events).unwrap();
        let capture_batch_id = app.allocate_project_batch_id().unwrap();
        app.project_writer
            .as_mut()
            .unwrap()
            .try_capture_batch(capture_batch_id, capture_events)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !app.project_writer.as_ref().unwrap().is_idle() {
            app.drain_project_writer_acks();
            assert!(
                Instant::now() < deadline,
                "physical capture did not ACK after stale Convert"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        app.drain_project_writer_acks();
        app.finish_project_writer().unwrap();

        let persisted = read_journal(&project_path).unwrap();
        assert_eq!(persisted.state.recognition_projections.len(), 1);
        let projection = &persisted.state.recognition_projections[0].projection;
        assert_eq!(
            projection.candidates[0].recognized_text,
            "F4 synthetic conversion result"
        );
        assert_eq!(
            projection.input_modalities,
            Some(vec![ProjectionInputModalityV1::Raster])
        );
        assert!(projection.generated_raster.is_some());
        assert_eq!(persisted.state.physical_samples.len(), 4);
        assert_eq!(persisted.state.physical_samples[0].sample, initial_sample);
        assert!(
            persisted.state.physical_samples[1..3]
                .iter()
                .all(|sample| sample.sample.stroke_id.is_none())
        );
        assert_eq!(persisted.state.physical_samples[3].sample, continued_sample);
        assert!(persisted.state.edit_actions.iter().any(|action| {
            matches!(
                &action.command,
                EditCommand::Move { target: moved, .. } if moved == &target
            )
        }));
        assert_eq!(persisted.state.region_corrections.len(), 1);
        assert_eq!(
            persisted.state.region_corrections[0].correction.action,
            RegionCorrectionActionV1::SetText(
                "F4 synthetic conversion result corrected by user".to_owned()
            )
        );
    }

    #[test]
    fn full_writer_queue_retains_completed_execution_until_snapshot_retry() {
        let test_directory = std::env::temp_dir().join(format!(
            "lassoink-f4-queue-validation-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&test_directory).unwrap();
        let project_path = test_directory.join("queue-validation.inkj");
        let journal_id = "f4-queue-validation-project";
        let session_id = "f4-queue-validation-session";
        let target = direct_target(journal_id, session_id, "queue-validation-stroke");
        let frame = StrokeViewFrame::default();
        let mut journal_writer = JournalWriter::create(
            project_path.clone(),
            JournalHeader {
                journal_id: journal_id.to_owned(),
                session_id: session_id.to_owned(),
                config_id: Some("f4-synthetic-config".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        journal_writer
            .start_stroke(target.clone(), frame, 1)
            .unwrap();
        journal_writer
            .append_sample(direct_sample(&target, 1, 120))
            .unwrap();
        journal_writer.commit_stroke(target.clone(), 2).unwrap();
        let state = journal_writer.replay_state().clone();
        let config_path =
            provider_config_path(&test_directory, &std::env::current_exe().unwrap(), &[]);
        let provider = LocalConvertProviderV1::load(&config_path, None).unwrap();
        let request_id = "convert-f4-queue-validation-session-1";
        let cancellation = AtomicBool::new(false);
        let prepared = prepare_conversion(
            &state,
            std::slice::from_ref(&target),
            request_id,
            "line-1",
            &provider,
            &cancellation,
        )
        .unwrap();
        let execution = execution_for_request(&prepared.request);
        let mut scene = CanvasScene::from_journal(&state, PROVISIONAL_DIRECT_SOURCE_API).unwrap();
        scene.select_target(Some(target.clone())).unwrap();
        let mut writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        for batch_id in 1..=8 {
            writer.try_snapshot_for_convert(batch_id).unwrap();
        }
        let mut app = make_test_app(
            project_path.clone(),
            journal_id.to_owned(),
            session_id.to_owned(),
            writer,
            provider,
            scene,
            Instant::now(),
        );
        app.next_project_batch_id = 9;
        app.pending_convert = Some(PendingConvert {
            generation: 1,
            project_generation: app.project_generation,
            view_generation: app.convert_view_generation,
            cancelled: false,
            selected_strokes_in_ui_order: vec![target.clone()],
            line_id: "line-1".to_owned(),
            request: Some(prepared.request.clone()),
            ink_binding: Some(prepared.ink_binding.clone()),
            generated_raster: prepared.generated_raster.clone(),
            phase: PendingConvertPhase::ProviderRunning,
        });
        app.handle_provider_poll(ProviderWorkerPoll::Outcome(Box::new(
            crate::provider_protocol::ProviderJobOutcome {
                request_id: request_id.to_owned(),
                outcome: Ok(execution),
            },
        )));
        assert!(matches!(
            app.pending_convert.as_ref().map(|pending| &pending.phase),
            Some(PendingConvertPhase::QueueSnapshotForValidation {
                batch_id: 9,
                execution,
            }) if execution.result.request_id == request_id
                && execution.result.candidates[0].recognized_text == "F4 synthetic conversion result"
        ));

        let drain_deadline = Instant::now() + Duration::from_secs(10);
        while !app.project_writer.as_ref().unwrap().is_idle() {
            app.drain_project_writer_acks();
            assert!(
                Instant::now() < drain_deadline,
                "snapshot ACK capacity did not drain"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(matches!(
            app.pending_convert.as_ref().map(|pending| &pending.phase),
            Some(PendingConvertPhase::QueueSnapshotForValidation {
                batch_id: 9,
                execution,
            }) if execution.result.request_id == request_id
                && execution.result.candidates[0].recognized_text == "F4 synthetic conversion result"
        ));
        app.poll_convert();
        assert!(matches!(
            app.pending_convert.as_ref().map(|pending| &pending.phase),
            Some(PendingConvertPhase::SnapshotForValidation {
                batch_id: 9,
                execution,
            }) if execution.result.request_id == request_id
                && execution.result.candidates[0].recognized_text == "F4 synthetic conversion result"
        ));

        wait_for_app(&mut app, Duration::from_secs(10), |app| {
            app.pending_convert.is_none()
                && app.canvas_status == "Convert result was durably saved as a projection"
        });
        assert!(app.project_writer.as_ref().unwrap().is_idle());
        app.finish_project_writer().unwrap();
        let persisted = read_journal(&project_path).unwrap();
        assert_eq!(persisted.state.recognition_projections.len(), 1);
        assert_eq!(
            persisted.state.recognition_projections[0]
                .projection
                .projection_id,
            request_id
        );
        assert!(
            persisted.state.recognition_projections[0]
                .projection
                .generated_raster
                .is_some()
        );
        let _ = fs::remove_dir_all(test_directory);
    }

    fn release_marker_guarded_write(path: &std::path::Path) {
        fs::write(path, b"release").unwrap();
    }
}
