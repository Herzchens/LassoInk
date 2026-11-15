//! Localized, Windows-only direct WM_POINTER pen-history boundary.
//!
//! The Winit hook runs after a message is retrieved and before Winit dispatches
//! it. This module copies every native value needed by the diagnostic into
//! owned records while that message/history is still valid. It keeps no native
//! pointers; device/window handles survive only as opaque session-scoped integer
//! values and are never dereferenced, owned, or closed.

use std::{
    cell::RefCell,
    ffi::c_void,
    mem::{self, MaybeUninit},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use windows_sys::Win32::{
    Foundation::{BOOL, GetLastError, HMODULE},
    System::{
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
    },
    UI::{
        Input::Pointer::POINTER_PEN_INFO,
        WindowsAndMessaging::{
            MSG, PEN_MASK_PRESSURE, PEN_MASK_TILT_X, PEN_MASK_TILT_Y, POINTER_INPUT_TYPE, PT_PEN,
            WM_POINTERCAPTURECHANGED, WM_POINTERDEVICECHANGE, WM_POINTERDEVICEINRANGE,
            WM_POINTERDEVICEOUTOFRANGE, WM_POINTERDOWN, WM_POINTERENTER, WM_POINTERLEAVE,
            WM_POINTERUP, WM_POINTERUPDATE,
        },
    },
};
use winit::{
    event::{ElementState, Force, MouseButton, TouchPhase},
    event_loop::EventLoopBuilder,
    platform::windows::EventLoopBuilderExtWindows,
};

const USER32_DLL: [u16; 11] = [
    b'u' as u16,
    b's' as u16,
    b'e' as u16,
    b'r' as u16,
    b'3' as u16,
    b'2' as u16,
    b'.' as u16,
    b'd' as u16,
    b'l' as u16,
    b'l' as u16,
    0,
];
const GET_POINTER_TYPE_NAME: &[u8] = b"GetPointerType\0";
const GET_POINTER_PEN_INFO_HISTORY_NAME: &[u8] = b"GetPointerPenInfoHistory\0";
const MAX_HISTORY_ENTRIES: u32 = 65_536;
const MAX_HISTORY_FETCH_ATTEMPTS: u8 = 4;
const MAX_NATIVE_PRESSURE: u32 = 1024;
// Interim in-memory retention is capped at 4,096 records and 131,072 samples.
// A single native history is separately capped at MAX_HISTORY_ENTRIES rows.
const MAX_RETAINED_RECORDS: usize = 4_096;
const MAX_RETAINED_SAMPLES: u64 = 131_072;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureSource {
    DirectWmPointerPenHistory,
    DirectWin32Lifecycle,
    PublicWinitWindowEvent,
    ApplicationLifecycle,
    WintabPacket,
    WintabControlNotification,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum CaptureMode {
    #[default]
    DirectWmPointer,
    Wintab,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum WintabStatus {
    #[default]
    NotSelected,
    Loading,
    Available,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WintabFunction {
    WTInfoA,
    WTOpenA,
    WTClose,
    WTQueueSizeSet,
    WTQueueSizeGet,
    WTQueuePacketsEx,
    WTPacketsGet,
    WTEnable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WintabPacketOperation {
    QueueQuery,
    PacketRead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WintabIssue {
    SystemPathUnavailable {
        win32_error: u32,
    },
    SystemPathTooLong {
        required: u32,
        capacity: u32,
    },
    LibraryLoadFailed {
        win32_error: u32,
    },
    MissingFunction {
        function: WintabFunction,
    },
    InvalidWindowHandle,
    ContextInfoUnavailable {
        returned_bytes: u32,
    },
    ContextConfigurationMismatch {
        expected_packet_data: u32,
        actual_packet_data: u32,
    },
    ContextOpenFailed,
    ContextClosed,
    ContextConfigurationChanged,
    ContextInformationChanged,
    ContextOverlapChanged {
        related_context_raw_session_scoped: isize,
        context_status_raw: u32,
    },
    ContextDisabledAfterCloseFailure {
        queue_count_before_disable: Option<u32>,
    },
    ContextDisableFailed,
    CaptureStoppedByStorageLimit,
    ControlTransitionObservedDuringDrain {
        operation: WintabPacketOperation,
        returned_packets: Option<u32>,
    },
    ControlObserverInstallFailed {
        win32_error: u32,
    },
    ControlObserverRemovalFailed {
        win32_error: u32,
    },
    ControlObserverQueueOverflow {
        dropped_messages: u64,
    },
    ControlObserverCallbackPanicked {
        count: u64,
    },
    MessageBaseChanged {
        requested: u32,
        actual: u32,
    },
    QueueSizeSetFailed {
        requested: i32,
    },
    QueueCapacityReduced {
        requested: i32,
        actual: i32,
    },
    QueueSizeUnavailable {
        reported: i32,
    },
    PacketReadFailed {
        reported: i32,
    },
    PacketCountInvalid {
        reported: i32,
        capacity: u32,
    },
    PacketContextMismatch {
        expected_raw: isize,
        reported_raw: isize,
    },
    PacketAllocationFailed {
        capacity: u32,
    },
    QueueQueryFailed,
    QueueCountExceedsCapacity {
        reported: u32,
        capacity: i32,
    },
    QueueSerialRangeInvalid {
        oldest_raw: u32,
        newest_raw: u32,
    },
    DrainLimitReached {
        pending_packets_reported: Option<u32>,
        drain_rounds: u8,
    },
    QueueOverflow {
        status_raw: u32,
    },
    SerialDiscontinuity {
        previous_raw: u32,
        current_raw: u32,
    },
    RetainedDataLimitExceeded {
        reported_packets: u32,
        remaining_records: u64,
        remaining_samples: u64,
    },
    RetainedSampleCapacityExceeded {
        reported_packets: u32,
        remaining: u64,
    },
    ContextCloseFailed,
    RecordAllocationFailed {
        requested_records: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WintabPacketTimeMode {
    AbsoluteSystemTime,
    RelativeMilliseconds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WintabCoordinateSpace {
    DigitizerContextOutputCoordinates,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WintabContextConfig {
    pub context_name_raw: [u8; 40],
    pub options_raw: u32,
    pub status_raw: u32,
    pub locks_raw: u32,
    pub message_base_raw: u32,
    /// Wintab's numeric context device selector; its interpretation is driver-specific.
    pub device_raw: u32,
    pub packet_rate_raw: u32,
    pub packet_data_raw: u32,
    pub packet_mode_raw: u32,
    pub move_mask_raw: u32,
    pub button_down_mask_raw: u32,
    pub button_up_mask_raw: u32,
    pub input_origin_raw: [i32; 3],
    pub input_extent_raw: [i32; 3],
    pub output_origin_raw: [i32; 3],
    pub output_extent_raw: [i32; 3],
    pub sensitivity_fixed32_raw: [u32; 3],
    pub system_mode_raw: i32,
    pub system_origin_raw: [i32; 2],
    pub system_extent_raw: [i32; 2],
    pub system_sensitivity_fixed32_raw: [u32; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicEventCapability {
    TouchPhasePositionForce,
    CursorPosition,
    MouseButton,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicUnclassifiedReason {
    NoMatchedNativeMessage,
    AmbiguousOrReentrantDispatch,
    AdditionalFrameEventUnjoined,
    PointerTypeApiUnavailable,
    PointerTypeQueryFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicPenClassification {
    ConfirmedPen,
    ConfirmedNonPen { pointer_type_raw: i32 },
    Unclassified(PublicUnclassifiedReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicMessageAssociation {
    /// Hook observation sequence for the matching dispatch; never a sample join ID.
    pub message_sequence: u64,
    pub message_id_raw: u32,
    /// Opaque dispatch HWND raw value; not stable across process sessions.
    pub message_hwnd_raw_session_scoped: isize,
    /// Pointer ID from the exact dispatch message.
    pub pointer_id_raw: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicTouchNativeMetadata {
    pub message_association: Option<PublicMessageAssociation>,
    pub native_pointer_type_raw: Option<i32>,
    pub pen_classification: PublicPenClassification,
    pub pointer_type_error_raw: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum PublicWinitEventData {
    Touch {
        /// Winit's own device identity, distinct from native sourceDevice and
        /// pointer ID; do not treat it as stable across sessions.
        winit_device_id: winit::event::DeviceId,
        /// Winit's public `Touch.id`, not a cross-source sample join key.
        public_touch_id: u64,
        phase: TouchPhase,
        x_physical_px: f64,
        y_physical_px: f64,
        /// Exact Winit `Touch.force` representation, not physical ground truth.
        public_winit_force: Option<Force>,
        native_pointer_type_raw: Option<i32>,
        pointer_type_error_raw: Option<u32>,
        pen_classification: PublicPenClassification,
        /// Winit exposes no native timestamp or CT430 tilt in this event.
        native_timestamp_raw: Option<u64>,
        tilt: Option<(f64, f64)>,
    },
    CursorMoved {
        /// Winit's public device identity, separate from Win32 sourceDevice.
        winit_device_id: winit::event::DeviceId,
        x_physical_px: f64,
        y_physical_px: f64,
        native_timestamp_raw: Option<u64>,
    },
    MouseInput {
        /// Winit's public device identity, separate from native device handles.
        winit_device_id: winit::event::DeviceId,
        state: ElementState,
        button: MouseButton,
        native_timestamp_raw: Option<u64>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PublicWinitEventRecord {
    pub source: CaptureSource,
    pub capability: PublicEventCapability,
    pub public_event_sequence: u64,
    /// Application monotonic-arrival elapsed time, separate from native clocks.
    pub app_observed_elapsed_ns: u128,
    /// Opaque process/session-scoped HWND; it is not stable across runs.
    pub window_hwnd_raw_session_scoped: Option<isize>,
    /// Present only for a same-dispatch, HWND and pointer-ID association.
    pub message_association: Option<PublicMessageAssociation>,
    pub data: PublicWinitEventData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WintabPacketSample {
    /// Opaque pointer-sized HCTX value scoped to this context/session.
    pub context_handle_raw_session_scoped: isize,
    pub status_raw: u32,
    pub packet_time_raw: u32,
    pub serial_number_raw: u32,
    pub cursor_raw: u32,
    pub buttons_raw: u32,
    pub x_raw: i32,
    pub y_raw: i32,
    pub normal_pressure_raw: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WintabPacketBatch {
    pub source: CaptureSource,
    pub message_sequence: u64,
    pub message_id_raw: u32,
    /// Opaque Wintab-message owner HWND value scoped to this process/session.
    pub message_hwnd_raw_session_scoped: isize,
    pub message_time_ms_raw: Option<u32>,
    pub message_wparam_raw: usize,
    pub message_lparam_raw: isize,
    /// Opaque pointer-sized HCTX value scoped to this context/session.
    pub context_handle_raw_session_scoped: isize,
    /// WT_PACKET supplies a serial in wParam; WT_PROXIMITY has no serial.
    pub notification_serial_raw: Option<u32>,
    pub context_config: WintabContextConfig,
    pub queue_capacity_raw: i32,
    pub coordinate_space: WintabCoordinateSpace,
    pub packet_time_mode: WintabPacketTimeMode,
    pub app_observed_elapsed_ns: u128,
    /// True when a sent Wintab control callback was observed while a packet
    /// retrieval was in flight. Retained packets are raw diagnostics and must
    /// not be counted as confidently attributed pen samples.
    pub control_transition_observed_during_read: bool,
    pub packets: Vec<WintabPacketSample>,
}

/// Owned scalar provenance copied from a Wintab control-message window
/// subclass. It carries app arrival only; sent messages have no `MSG` hook
/// timestamp or durable hook sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WintabControlNotification {
    pub source: CaptureSource,
    pub observer_sequence: u64,
    pub message_id_raw: u32,
    /// Opaque process/session-scoped HWND passed to the subclass.
    pub message_hwnd_raw_session_scoped: isize,
    pub wparam_raw: usize,
    pub lparam_raw: isize,
    pub app_observed_elapsed_ns: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActivePublicDispatch {
    message_sequence: u64,
    metadata: HookMessageMetadata,
    association_used: bool,
    pointer_type_query_attempted: bool,
    pointer_type_query_result: Option<Result<i32, u32>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PointerMessageKind {
    Down,
    Update,
    Up,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeApi {
    User32Module,
    GetPointerType,
    GetPointerPenInfoHistoryExport,
    GetPointerPenInfoHistorySizing,
    GetPointerPenInfoHistoryFetch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureIssue {
    ApiUnavailable {
        api: NativeApi,
        win32_error: u32,
    },
    ApiCallFailed {
        api: NativeApi,
        win32_error: u32,
    },
    QpcFrequencyUnavailable {
        win32_error: u32,
    },
    QpcCounterUnavailable {
        win32_error: u32,
    },
    SessionOutputFailed {
        stage: SessionOutputStage,
    },
    NullMessagePointer,
    InvalidPointerId,
    EmptyHistory,
    HistoryTooLarge {
        reported: u32,
        maximum: u32,
    },
    HistoryCountChanged {
        expected: u32,
        returned: u32,
    },
    HistoryStillGrowing {
        capacity: u32,
        returned: u32,
        attempts: u8,
    },
    RetainedSampleCapacityExceeded {
        reported: u32,
        remaining: u64,
    },
    RetainedRecordCapacityExceeded {
        reported_samples: u32,
        remaining_records: u64,
    },
    RetentionCapacitiesExceeded {
        reported_samples: u32,
        remaining_records: u64,
        remaining_samples: u64,
    },
    RecordAllocationFailed {
        requested_records: u64,
    },
    AllocationFailed {
        capacity: u32,
    },
    MessageSequenceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionOutputStage {
    CreateDirectory,
    CreateFile,
    Write,
    Flush,
    Sync,
    Finalize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PressureValidity {
    NotReported,
    Valid,
    OutOfRange,
}

fn pressure_validity(pen_mask: u32, pressure_raw: u32) -> PressureValidity {
    if pen_mask & PEN_MASK_PRESSURE == 0 {
        PressureValidity::NotReported
    } else if pressure_raw > MAX_NATIVE_PRESSURE {
        PressureValidity::OutOfRange
    } else {
        PressureValidity::Valid
    }
}

pub(crate) fn is_valid_direct_pen_sample(sample: &OwnedPointerSample) -> bool {
    sample.pointer_type_raw == PT_PEN
        && sample.attribution == PointerAttribution::MatchesRequestedPointer
        && sample.pen_mask_raw & PEN_MASK_PRESSURE != 0
        && sample.pressure_validity == PressureValidity::Valid
        && sample.pressure_raw <= MAX_NATIVE_PRESSURE
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawPoint {
    pub x: i32,
    pub y: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoordinateSpace {
    WindowsScreenCoordinates,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoordinateUnits {
    ScreenPixel,
    HimetricHundredthMillimeter,
}

/// Raw `POINTER_INFO` positions with explicit coordinate space and units.
/// Neither position is converted to client coordinates or DPI units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawScreenPosition {
    pub coordinate_space: CoordinateSpace,
    pub pixel_units: CoordinateUnits,
    /// Exact native `ptPixelLocationRaw` value.
    pub pt_pixel_location_raw: RawPoint,
    pub himetric_units: CoordinateUnits,
    /// Exact native `ptHimetricLocationRaw` value, 0.01 mm per unit.
    pub pt_himetric_location_raw: RawPoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PointerAttribution {
    MatchesRequestedPointer,
    UnclassifiedIdMismatch { requested: u32, reported: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SampleValidationIssue {
    PointerIdMismatch { requested: u32, reported: u32 },
    UnexpectedPointerType { reported: POINTER_INPUT_TYPE },
    PressureMaskMissing,
    PressureOutOfRange { raw: u32 },
    UnexpectedTiltMask { raw_mask: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifecycleEventKind {
    DirectPointerEnter,
    DirectPointerLeave,
    DirectPointerCaptureChanged,
    DirectPointerDeviceChanged,
    DirectPointerDeviceInRange,
    DirectPointerDeviceOutOfRange,
    WintabPacketNotification,
    WintabProximityEnter,
    WintabProximityLeave,
    WindowFocusGained,
    WindowFocusLost,
    WindowCloseRequested,
    InputDeviceAdded,
    InputDeviceRemoved,
    EventLoopWake,
    ControlledStallStart,
    ControlledStallEnd,
    StartupIssue,
    WindowInitializationFailed,
    EventLoopFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleEventRecord {
    pub source: CaptureSource,
    pub kind: LifecycleEventKind,
    /// Application monotonic-arrival time only; never a native sample clock.
    pub app_observed_elapsed_ns: u128,
    pub message_id_raw: Option<u32>,
    /// Opaque process/session-scoped HWND; never dereferenced or owned.
    pub message_hwnd_raw_session_scoped: Option<isize>,
    pub wparam_raw: Option<usize>,
    pub lparam_raw: Option<isize>,
    /// Raw wrapping `MSG.time` for queued messages only. Sent subclass events
    /// leave this null because no hook `MSG` timestamp exists.
    pub native_message_time_ms_raw: Option<u32>,
    pub pointer_id_raw: Option<u32>,
    /// Winit device ID's diagnostic representation; not stable across runs.
    pub winit_device_id_debug: Option<String>,
    pub event_loop_wait_start_elapsed_ns: Option<u128>,
    pub event_loop_requested_resume_elapsed_ns: Option<u128>,
    pub event_loop_wake_lateness_ns: Option<u128>,
    pub controlled_stall_duration_ns: Option<u128>,
    pub issue_debug: Option<String>,
}

/// One owned `POINTER_PEN_INFO` record. `frame_id_raw` is the uninterpreted,
/// qualified native frame counter allocated across pointers/devices. It is not
/// strictly sequential within a stream, so a gap is not evidence of dropped ink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnedPointerSample {
    /// Original native-array index: zero is newest.
    pub history_index_newest_first: u32,
    /// Position after the single explicit reverse into chronological order.
    pub chronological_index: u32,
    pub attribution: PointerAttribution,
    pub pointer_type_raw: POINTER_INPUT_TYPE,
    pub pointer_id_raw: u32,
    pub frame_id_raw: u32,
    /// Opaque source-device handle value scoped to this process/session only.
    /// Do not dereference, own, close, or treat as stable across sessions.
    pub source_device_handle_raw_session_scoped: isize,
    /// Opaque target HWND value scoped to this process/session only.
    /// Do not dereference, own, close, or treat as stable across sessions.
    pub target_hwnd_raw_session_scoped: isize,
    pub pointer_flags_raw: u32,
    pub button_change_type_raw: i32,
    pub position: RawScreenPosition,
    /// OS high-resolution counter value for when Windows received the pointer
    /// message, from `PerformanceCount`. Windows may hardware-calibrate it for
    /// supported digitizers; it is not a universal sensing or display timestamp.
    pub performance_count_qpc_raw: u64,
    /// Raw wrapping DWORD system-time field; kept separate from QPC and app time.
    pub dw_time_ms_wrapping_raw: u32,
    pub history_count_raw: u32,
    pub input_data_raw: i32,
    pub key_states_raw: u32,
    pub pen_flags_raw: u32,
    pub pen_mask_raw: u32,
    /// Preserve the raw Windows-normalized pressure value even if its mask is absent.
    pub pressure_raw: u32,
    pub pressure_validity: PressureValidity,
    pub rotation_raw: u32,
    /// Raw values and masks remain for diagnostics; CT430 semantic tilt stays null.
    pub tilt_x_raw: i32,
    pub tilt_y_raw: i32,
    pub tilt: Option<(i32, i32)>,
    pub validation_issues: Vec<SampleValidationIssue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectPenHistoryBatch {
    pub source: CaptureSource,
    pub message_sequence: u64,
    pub message_id_raw: u32,
    /// Opaque `MSG.hwnd` value scoped to this process/session only. Do not
    /// dereference, own, close, or treat it as stable across sessions.
    pub message_hwnd_raw_session_scoped: isize,
    pub message_time_ms_raw: Option<u32>,
    pub message_kind: PointerMessageKind,
    pub pointer_id_requested: u32,
    /// App `Instant` elapsed time observed at hook entry; not mixed with native time.
    pub hook_observed_elapsed_ns: u128,
    /// Host QPC sampled in the hook for message-receipt-to-hook queue age only.
    pub hook_qpc_count_raw: Option<u64>,
    pub hook_qpc_issue: Option<CaptureIssue>,
    /// QPC counts per second sampled once at probe startup.
    pub qpc_frequency_hz: Option<u64>,
    pub native_history_count: u32,
    /// Chronological order after one explicit reverse of the newest-first API array.
    pub samples: Vec<OwnedPointerSample>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ProbeRecord {
    StartupIssue(CaptureIssue),
    DirectPenHistory(DirectPenHistoryBatch),
    PublicWinitEvent(PublicWinitEventRecord),
    Lifecycle(LifecycleEventRecord),
    WintabPackets(WintabPacketBatch),
    WintabControlNotification(WintabControlNotification),
    WintabIssue {
        source: CaptureSource,
        message_sequence: u64,
        message_id_raw: u32,
        message_hwnd_raw_session_scoped: Option<isize>,
        message_wparam_raw: Option<usize>,
        message_lparam_raw: Option<isize>,
        message_time_ms_raw: Option<u32>,
        app_observed_elapsed_ns: Option<u128>,
        issue: WintabIssue,
    },
    IgnoredNonPenPointer {
        source: CaptureSource,
        message_sequence: u64,
        message_id_raw: u32,
        /// Opaque `MSG.hwnd` value scoped to this process/session only.
        message_hwnd_raw_session_scoped: isize,
        message_wparam_raw: usize,
        message_lparam_raw: isize,
        message_time_ms_raw: Option<u32>,
        message_kind: PointerMessageKind,
        pointer_id: u32,
        pointer_type_raw: POINTER_INPUT_TYPE,
        hook_observed_elapsed_ns: u128,
    },
    MessageIssue {
        source: CaptureSource,
        message_sequence: u64,
        message_id_raw: u32,
        /// `None` means no readable `MSG` pointer was supplied by Winit.
        /// Otherwise this is an opaque process/session-scoped HWND value.
        message_hwnd_raw_session_scoped: Option<isize>,
        message_wparam_raw: Option<usize>,
        message_lparam_raw: Option<isize>,
        message_time_ms_raw: Option<u32>,
        message_kind: Option<PointerMessageKind>,
        pointer_id: Option<u32>,
        hook_observed_elapsed_ns: u128,
        issue: CaptureIssue,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProbeSummary {
    pub capture_mode: CaptureMode,
    pub pointer_api_available: bool,
    pub qpc_frequency_hz: Option<u64>,
    pub history_batches: u64,
    pub samples: u64,
    pub valid_direct_pen_samples: u64,
    pub invalid_direct_pen_samples: u64,
    pub validation_anomaly_samples: u64,
    pub validation_issue_count: u64,
    pub pressure_mask_missing_samples: u64,
    pub pressure_out_of_range_samples: u64,
    pub pointer_id_mismatch_samples: u64,
    pub unexpected_pointer_type_samples: u64,
    pub unexpected_tilt_mask_samples: u64,
    pub uncertain_wintab_packets: u64,
    pub qpc_counter_failures: u64,
    pub lifecycle_events: u64,
    pub issues: u64,
    pub ignored_non_pen_pointers: u64,
    pub public_events: u64,
    pub public_touch_events: u64,
    pub wintab_packets: u64,
    pub wintab_control_messages: u64,
    pub wintab_issues: u64,
    pub wintab_status: WintabStatus,
    pub wintab_packet_time_mode: Option<WintabPacketTimeMode>,
    pub wintab_configured_packet_data_raw: Option<u32>,
    pub wintab_configured_packet_mode_raw: Option<u32>,
    pub wintab_queue_capacity_raw: Option<i32>,
    pub latest_wintab_issue: Option<WintabIssue>,
    pub records_retained: u64,
    pub records_not_retained: u64,
    pub batches_not_retained: u64,
    pub samples_not_retained: u64,
    pub incomplete_batches: u64,
    pub latest_incomplete_issue: Option<CaptureIssue>,
    pub latest_startup_issue: Option<CaptureIssue>,
    pub pointer_api_issue: Option<CaptureIssue>,
    pub qpc_frequency_issue: Option<CaptureIssue>,
    pub storage_limit: Option<StorageLimit>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageLimit {
    Records,
    Samples,
    NativeHistory,
    Allocation,
    SessionOutput,
    Multiple,
}

#[derive(Debug, Default)]
pub(crate) struct ProbeState {
    records: Vec<ProbeRecord>,
    summary: ProbeSummary,
    public_pointer_type_api: Option<GetPointerTypeFn>,
    active_public_dispatch: Option<ActivePublicDispatch>,
    public_callback_depth: u32,
    public_association_ambiguous: bool,
    next_public_event_sequence: u64,
}

impl ProbeState {
    pub(crate) fn summary(&self) -> ProbeSummary {
        self.summary
    }

    fn set_api_state(&mut self, available: bool, issue: Option<CaptureIssue>) {
        self.summary.pointer_api_available = available;
        self.summary.pointer_api_issue = issue;
    }

    fn set_qpc_frequency(&mut self, frequency: Option<u64>, issue: Option<CaptureIssue>) {
        self.summary.qpc_frequency_hz = frequency;
        self.summary.qpc_frequency_issue = issue;
    }

    pub(crate) fn set_capture_mode(&mut self, mode: CaptureMode) {
        self.summary.capture_mode = mode;
    }

    pub(crate) fn set_wintab_configuration(
        &mut self,
        status: WintabStatus,
        time_mode: Option<WintabPacketTimeMode>,
        packet_data_raw: Option<u32>,
        packet_mode_raw: Option<u32>,
        queue_capacity_raw: Option<i32>,
    ) {
        self.summary.wintab_status = status;
        self.summary.wintab_packet_time_mode = time_mode;
        self.summary.wintab_configured_packet_data_raw = packet_data_raw;
        self.summary.wintab_configured_packet_mode_raw = packet_mode_raw;
        self.summary.wintab_queue_capacity_raw = queue_capacity_raw;
    }

    fn set_public_pointer_type_api(&mut self, api: Option<GetPointerTypeFn>) {
        self.public_pointer_type_api = api;
    }

    fn begin_native_dispatch(
        &mut self,
        message_sequence: u64,
        metadata: Option<HookMessageMetadata>,
    ) {
        if self.public_callback_depth > 0 {
            self.active_public_dispatch = None;
            self.public_association_ambiguous = true;
            return;
        }

        self.public_association_ambiguous = false;
        self.active_public_dispatch = metadata
            .filter(|message| {
                message.pointer_id != 0 && pointer_message_kind(message.message_id_raw).is_some()
            })
            .map(|metadata| ActivePublicDispatch {
                message_sequence,
                metadata,
                association_used: false,
                pointer_type_query_attempted: false,
                pointer_type_query_result: None,
            });
    }

    pub(crate) fn expire_public_dispatch_candidate(&mut self) {
        self.active_public_dispatch = None;
    }

    pub(crate) fn enter_winit_callback(&mut self) {
        if self.public_callback_depth > 0 {
            self.public_association_ambiguous = true;
            self.active_public_dispatch = None;
        }
        self.public_callback_depth = self.public_callback_depth.saturating_add(1);
    }

    pub(crate) fn leave_winit_callback(&mut self) {
        self.public_callback_depth = self.public_callback_depth.saturating_sub(1);
        if self.public_callback_depth == 0 {
            // The message hook runs before Winit dispatch and has no matching
            // post-dispatch callback. Expire the candidate after this public
            // callback so a buffered or later event cannot reuse stale MSG data.
            self.active_public_dispatch = None;
        }
    }

    pub(crate) fn public_touch_native_metadata(
        &mut self,
        window_hwnd_raw_session_scoped: Option<isize>,
        public_touch_id: u64,
    ) -> PublicTouchNativeMetadata {
        if self.public_association_ambiguous {
            return PublicTouchNativeMetadata {
                message_association: None,
                native_pointer_type_raw: None,
                pen_classification: PublicPenClassification::Unclassified(
                    PublicUnclassifiedReason::AmbiguousOrReentrantDispatch,
                ),
                pointer_type_error_raw: None,
            };
        }

        let Some(active) = self.active_public_dispatch else {
            return PublicTouchNativeMetadata {
                message_association: None,
                native_pointer_type_raw: None,
                pen_classification: PublicPenClassification::Unclassified(
                    PublicUnclassifiedReason::NoMatchedNativeMessage,
                ),
                pointer_type_error_raw: None,
            };
        };
        let metadata = active.metadata;
        if window_hwnd_raw_session_scoped != Some(metadata.message_hwnd_raw_session_scoped)
            || u64::from(metadata.pointer_id) != public_touch_id
            || pointer_message_kind(metadata.message_id_raw).is_none()
        {
            return PublicTouchNativeMetadata {
                message_association: None,
                native_pointer_type_raw: None,
                pen_classification: PublicPenClassification::Unclassified(
                    PublicUnclassifiedReason::NoMatchedNativeMessage,
                ),
                pointer_type_error_raw: None,
            };
        }

        if active.association_used {
            return PublicTouchNativeMetadata {
                message_association: None,
                native_pointer_type_raw: None,
                pen_classification: PublicPenClassification::Unclassified(
                    PublicUnclassifiedReason::AdditionalFrameEventUnjoined,
                ),
                pointer_type_error_raw: None,
            };
        }

        let association = Some(PublicMessageAssociation {
            message_sequence: active.message_sequence,
            message_id_raw: metadata.message_id_raw,
            message_hwnd_raw_session_scoped: metadata.message_hwnd_raw_session_scoped,
            pointer_id_raw: metadata.pointer_id,
        });
        let mut active = active;
        active.association_used = true;
        self.active_public_dispatch = Some(active);
        if !active.pointer_type_query_attempted {
            let query_result = if let Some(get_pointer_type) = self.public_pointer_type_api {
                let mut pointer_type: POINTER_INPUT_TYPE = 0;
                // SAFETY: This runs synchronously from Winit's window callback inside
                // the WndProc for the associated live WM_POINTER dispatch. The ID,
                // HWND and message sequence have already been matched; output is valid.
                if unsafe { get_pointer_type(metadata.pointer_id, &mut pointer_type) } == 0 {
                    Err(win32_last_error())
                } else {
                    Ok(pointer_type)
                }
            } else {
                // `None` is cached as an attempted query without a result.
                let mut active = active;
                active.pointer_type_query_attempted = true;
                self.active_public_dispatch = Some(active);
                return PublicTouchNativeMetadata {
                    message_association: association,
                    native_pointer_type_raw: None,
                    pen_classification: PublicPenClassification::Unclassified(
                        PublicUnclassifiedReason::PointerTypeApiUnavailable,
                    ),
                    pointer_type_error_raw: None,
                };
            };

            let mut active = active;
            active.pointer_type_query_attempted = true;
            active.pointer_type_query_result = Some(query_result);
            self.active_public_dispatch = Some(active);
        }

        match self
            .active_public_dispatch
            .and_then(|active| active.pointer_type_query_result)
        {
            Some(Ok(pointer_type)) => PublicTouchNativeMetadata {
                message_association: association,
                native_pointer_type_raw: Some(pointer_type),
                pen_classification: if pointer_type == PT_PEN {
                    PublicPenClassification::ConfirmedPen
                } else {
                    PublicPenClassification::ConfirmedNonPen {
                        pointer_type_raw: pointer_type,
                    }
                },
                pointer_type_error_raw: None,
            },
            Some(Err(error)) => PublicTouchNativeMetadata {
                message_association: association,
                native_pointer_type_raw: None,
                pen_classification: PublicPenClassification::Unclassified(
                    PublicUnclassifiedReason::PointerTypeQueryFailed,
                ),
                pointer_type_error_raw: Some(error),
            },
            None => PublicTouchNativeMetadata {
                message_association: association,
                native_pointer_type_raw: None,
                pen_classification: PublicPenClassification::Unclassified(
                    PublicUnclassifiedReason::PointerTypeApiUnavailable,
                ),
                pointer_type_error_raw: None,
            },
        }
    }

    pub(crate) fn next_public_event_sequence(&mut self) -> u64 {
        let sequence = self.next_public_event_sequence;
        self.next_public_event_sequence = self.next_public_event_sequence.saturating_add(1);
        sequence
    }

    pub(crate) fn can_capture(&self) -> bool {
        self.summary.storage_limit.is_none()
    }

    #[cfg(test)]
    pub(crate) fn retained_records(&self) -> &[ProbeRecord] {
        &self.records
    }

    pub(crate) fn pending_records(&self) -> &[ProbeRecord] {
        &self.records
    }

    pub(crate) fn clear_pending_records_after_write(&mut self) {
        self.records.clear();
    }

    pub(crate) fn mark_session_output_failed(&mut self, stage: SessionOutputStage) {
        let issue = CaptureIssue::SessionOutputFailed { stage };
        self.summary.issues = self.summary.issues.saturating_add(1);
        self.summary.latest_startup_issue = Some(issue);
        self.summary.latest_incomplete_issue = Some(issue);
        self.summary.storage_limit = Some(if self.summary.storage_limit.is_some() {
            StorageLimit::Multiple
        } else {
            StorageLimit::SessionOutput
        });
    }

    pub(crate) fn remaining_sample_capacity(&self) -> u64 {
        MAX_RETAINED_SAMPLES.saturating_sub(
            self.summary
                .samples
                .saturating_add(self.summary.wintab_packets),
        )
    }

    pub(crate) fn record(&mut self, record: ProbeRecord) {
        self.record_with_limits(record, MAX_RETAINED_RECORDS, MAX_RETAINED_SAMPLES);
    }

    fn record_with_limits(&mut self, record: ProbeRecord, max_records: usize, max_samples: u64) {
        if !self.can_capture() {
            return;
        }

        let incoming_samples = match &record {
            ProbeRecord::DirectPenHistory(batch) => batch.samples.len() as u64,
            ProbeRecord::WintabPackets(batch) => batch.packets.len() as u64,
            _ => 0,
        };
        let record_limit_reached = self.summary.records_retained >= max_records as u64;
        let retained_sample_count = self
            .summary
            .samples
            .saturating_add(self.summary.wintab_packets);
        let sample_limit_exceeded =
            incoming_samples > max_samples.saturating_sub(retained_sample_count);
        let message_issue = match &record {
            ProbeRecord::MessageIssue { issue, .. } => Some(*issue),
            _ => None,
        };
        let native_history_limit =
            matches!(message_issue, Some(CaptureIssue::HistoryTooLarge { .. }));
        let retained_sample_limit = matches!(
            message_issue,
            Some(
                CaptureIssue::RetainedSampleCapacityExceeded { .. }
                    | CaptureIssue::RetentionCapacitiesExceeded { .. }
            )
        );
        let wintab_retention_limit = match &record {
            ProbeRecord::WintabIssue {
                message_id_raw,
                issue,
                ..
            } if *message_id_raw != 0 => Some(*issue),
            _ => None,
        };
        if record_limit_reached || sample_limit_exceeded {
            self.summary.records_not_retained = self.summary.records_not_retained.saturating_add(1);
            if incoming_samples > 0 {
                let remaining_records =
                    (max_records as u64).saturating_sub(self.summary.records_retained);
                let remaining_samples = max_samples.saturating_sub(retained_sample_count);
                if let ProbeRecord::WintabPackets(_) = &record {
                    let issue = WintabIssue::RetainedDataLimitExceeded {
                        reported_packets: incoming_samples as u32,
                        remaining_records,
                        remaining_samples,
                    };
                    self.summary.issues = self.summary.issues.saturating_add(1);
                    self.summary.wintab_issues = self.summary.wintab_issues.saturating_add(1);
                    self.summary.latest_wintab_issue = Some(issue);
                    self.summary.incomplete_batches =
                        self.summary.incomplete_batches.saturating_add(1);
                    self.summary.batches_not_retained =
                        self.summary.batches_not_retained.saturating_add(1);
                    self.summary.samples_not_retained = self
                        .summary
                        .samples_not_retained
                        .saturating_add(incoming_samples);
                    self.summary.wintab_status = WintabStatus::Partial;
                } else {
                    let issue = match (record_limit_reached, sample_limit_exceeded) {
                        (true, true) => CaptureIssue::RetentionCapacitiesExceeded {
                            reported_samples: incoming_samples as u32,
                            remaining_records,
                            remaining_samples,
                        },
                        (true, false) => CaptureIssue::RetainedRecordCapacityExceeded {
                            reported_samples: incoming_samples as u32,
                            remaining_records,
                        },
                        (false, true) => CaptureIssue::RetainedSampleCapacityExceeded {
                            reported: incoming_samples as u32,
                            remaining: remaining_samples,
                        },
                        (false, false) => unreachable!("a record or sample cap was reached"),
                    };
                    self.note_incomplete_issue(issue, Some(incoming_samples));
                }
            } else if let Some(issue) = message_issue {
                self.note_incomplete_issue(issue, known_unretained_samples(issue));
            }
            self.mark_storage_limit(
                record_limit_reached,
                sample_limit_exceeded || retained_sample_limit,
                native_history_limit,
                false,
            );
            return;
        }

        if self.records.try_reserve(1).is_err() {
            let requested_records = self.summary.records_retained.saturating_add(1);
            self.account_record_allocation_failure(
                &record,
                CaptureIssue::RecordAllocationFailed { requested_records },
            );
            return;
        }

        match &record {
            ProbeRecord::StartupIssue(issue) => {
                self.summary.latest_startup_issue = Some(*issue);
                self.summary.issues = self.summary.issues.saturating_add(1);
            }
            ProbeRecord::MessageIssue { issue, .. } => {
                self.note_incomplete_issue(*issue, known_unretained_samples(*issue));
            }
            ProbeRecord::WintabIssue {
                message_id_raw,
                issue,
                ..
            } => {
                self.summary.issues = self.summary.issues.saturating_add(1);
                self.summary.wintab_issues = self.summary.wintab_issues.saturating_add(1);
                self.summary.latest_wintab_issue = Some(*issue);
                if *message_id_raw != 0 {
                    self.summary.incomplete_batches =
                        self.summary.incomplete_batches.saturating_add(1);
                    self.summary.batches_not_retained =
                        self.summary.batches_not_retained.saturating_add(1);
                    if let Some(packets) = known_unretained_wintab_packets(*issue) {
                        self.summary.samples_not_retained =
                            self.summary.samples_not_retained.saturating_add(packets);
                    }
                    self.summary.wintab_status = WintabStatus::Partial;
                }
            }
            ProbeRecord::DirectPenHistory(batch) => {
                self.summary.history_batches = self.summary.history_batches.saturating_add(1);
                self.summary.samples = self
                    .summary
                    .samples
                    .saturating_add(batch.samples.len() as u64);
                if batch.hook_qpc_issue.is_some() {
                    self.summary.qpc_counter_failures =
                        self.summary.qpc_counter_failures.saturating_add(1);
                }
                for sample in &batch.samples {
                    let issues = &sample.validation_issues;
                    if !issues.is_empty() {
                        self.summary.validation_anomaly_samples =
                            self.summary.validation_anomaly_samples.saturating_add(1);
                        self.summary.validation_issue_count = self
                            .summary
                            .validation_issue_count
                            .saturating_add(issues.len() as u64);
                    }
                    if issues.contains(&SampleValidationIssue::PressureMaskMissing) {
                        self.summary.pressure_mask_missing_samples =
                            self.summary.pressure_mask_missing_samples.saturating_add(1);
                    }
                    if issues.iter().any(|issue| {
                        matches!(issue, SampleValidationIssue::PressureOutOfRange { .. })
                    }) {
                        self.summary.pressure_out_of_range_samples =
                            self.summary.pressure_out_of_range_samples.saturating_add(1);
                    }
                    if issues.iter().any(|issue| {
                        matches!(issue, SampleValidationIssue::PointerIdMismatch { .. })
                    }) {
                        self.summary.pointer_id_mismatch_samples =
                            self.summary.pointer_id_mismatch_samples.saturating_add(1);
                    }
                    if issues.iter().any(|issue| {
                        matches!(issue, SampleValidationIssue::UnexpectedPointerType { .. })
                    }) {
                        self.summary.unexpected_pointer_type_samples = self
                            .summary
                            .unexpected_pointer_type_samples
                            .saturating_add(1);
                    }
                    if issues.iter().any(|issue| {
                        matches!(issue, SampleValidationIssue::UnexpectedTiltMask { .. })
                    }) {
                        self.summary.unexpected_tilt_mask_samples =
                            self.summary.unexpected_tilt_mask_samples.saturating_add(1);
                    }
                    if is_valid_direct_pen_sample(sample) {
                        self.summary.valid_direct_pen_samples =
                            self.summary.valid_direct_pen_samples.saturating_add(1);
                    } else {
                        self.summary.invalid_direct_pen_samples =
                            self.summary.invalid_direct_pen_samples.saturating_add(1);
                    }
                }
            }
            ProbeRecord::WintabPackets(batch) => {
                self.summary.wintab_packets = self
                    .summary
                    .wintab_packets
                    .saturating_add(batch.packets.len() as u64);
                if batch.control_transition_observed_during_read {
                    self.summary.uncertain_wintab_packets = self
                        .summary
                        .uncertain_wintab_packets
                        .saturating_add(batch.packets.len() as u64);
                }
            }
            ProbeRecord::WintabControlNotification(_) => {
                self.summary.wintab_control_messages =
                    self.summary.wintab_control_messages.saturating_add(1);
            }
            ProbeRecord::PublicWinitEvent(event) => {
                self.summary.public_events = self.summary.public_events.saturating_add(1);
                if matches!(event.data, PublicWinitEventData::Touch { .. }) {
                    self.summary.public_touch_events =
                        self.summary.public_touch_events.saturating_add(1);
                }
            }
            ProbeRecord::Lifecycle(_) => {
                self.summary.lifecycle_events = self.summary.lifecycle_events.saturating_add(1);
            }
            ProbeRecord::IgnoredNonPenPointer { .. } => {
                self.summary.ignored_non_pen_pointers =
                    self.summary.ignored_non_pen_pointers.saturating_add(1);
            }
        }
        self.records.push(record);
        self.summary.records_retained = self.summary.records_retained.saturating_add(1);

        let wintab_record_limit = wintab_retention_limit.is_some_and(|issue| {
            matches!(
                issue,
                WintabIssue::RetainedDataLimitExceeded {
                    remaining_records: 0,
                    ..
                }
            )
        });
        let wintab_sample_limit = wintab_retention_limit.is_some_and(|issue| match issue {
            WintabIssue::RetainedSampleCapacityExceeded { .. } => true,
            WintabIssue::RetainedDataLimitExceeded {
                reported_packets,
                remaining_samples,
                ..
            } => u64::from(reported_packets) > remaining_samples,
            _ => false,
        });
        self.mark_storage_limit(
            self.summary.records_retained >= max_records as u64 || wintab_record_limit,
            self.summary
                .samples
                .saturating_add(self.summary.wintab_packets)
                >= max_samples
                || matches!(
                    message_issue,
                    Some(
                        CaptureIssue::RetainedSampleCapacityExceeded { .. }
                            | CaptureIssue::RetentionCapacitiesExceeded { .. }
                    )
                )
                || wintab_sample_limit,
            native_history_limit,
            false,
        );
    }

    fn account_record_allocation_failure(&mut self, record: &ProbeRecord, issue: CaptureIssue) {
        self.summary.records_not_retained = self.summary.records_not_retained.saturating_add(1);
        match record {
            ProbeRecord::StartupIssue(startup_issue) => {
                self.summary.issues = self.summary.issues.saturating_add(2);
                self.summary.latest_startup_issue = Some(*startup_issue);
                self.summary.latest_incomplete_issue = Some(issue);
            }
            ProbeRecord::MessageIssue {
                issue: message_issue,
                ..
            } => {
                self.note_incomplete_issue(
                    *message_issue,
                    known_unretained_samples(*message_issue),
                );
                self.summary.issues = self.summary.issues.saturating_add(1);
                self.summary.latest_incomplete_issue = Some(issue);
            }
            ProbeRecord::DirectPenHistory(batch) => {
                self.note_incomplete_issue(issue, Some(batch.samples.len() as u64));
            }
            ProbeRecord::WintabPackets(batch) => {
                self.summary.issues = self.summary.issues.saturating_add(1);
                self.summary.wintab_issues = self.summary.wintab_issues.saturating_add(1);
                self.summary.latest_wintab_issue = Some(WintabIssue::RecordAllocationFailed {
                    requested_records: match issue {
                        CaptureIssue::RecordAllocationFailed { requested_records } => {
                            requested_records
                        }
                        _ => 0,
                    },
                });
                self.summary.incomplete_batches = self.summary.incomplete_batches.saturating_add(1);
                self.summary.batches_not_retained =
                    self.summary.batches_not_retained.saturating_add(1);
                self.summary.samples_not_retained = self
                    .summary
                    .samples_not_retained
                    .saturating_add(batch.packets.len() as u64);
            }
            ProbeRecord::WintabControlNotification(_) => {
                self.summary.issues = self.summary.issues.saturating_add(1);
                self.summary.incomplete_batches = self.summary.incomplete_batches.saturating_add(1);
                self.summary.batches_not_retained =
                    self.summary.batches_not_retained.saturating_add(1);
                self.summary.wintab_control_messages =
                    self.summary.wintab_control_messages.saturating_add(1);
                self.summary.latest_incomplete_issue = Some(issue);
                self.summary.wintab_status = WintabStatus::Partial;
            }
            ProbeRecord::PublicWinitEvent(event) => {
                self.summary.issues = self.summary.issues.saturating_add(1);
                self.summary.incomplete_batches = self.summary.incomplete_batches.saturating_add(1);
                self.summary.batches_not_retained =
                    self.summary.batches_not_retained.saturating_add(1);
                self.summary.public_events = self.summary.public_events.saturating_add(1);
                if matches!(event.data, PublicWinitEventData::Touch { .. }) {
                    self.summary.public_touch_events =
                        self.summary.public_touch_events.saturating_add(1);
                }
                self.summary.latest_incomplete_issue = Some(issue);
            }
            ProbeRecord::Lifecycle(_) => {
                self.summary.issues = self.summary.issues.saturating_add(1);
                self.summary.lifecycle_events = self.summary.lifecycle_events.saturating_add(1);
                self.summary.latest_incomplete_issue = Some(issue);
            }
            ProbeRecord::WintabIssue {
                message_id_raw,
                issue: wintab_issue,
                ..
            } => {
                self.summary.issues = self.summary.issues.saturating_add(2);
                self.summary.wintab_issues = self.summary.wintab_issues.saturating_add(2);
                self.summary.latest_wintab_issue = Some(WintabIssue::RecordAllocationFailed {
                    requested_records: match issue {
                        CaptureIssue::RecordAllocationFailed { requested_records } => {
                            requested_records
                        }
                        _ => 0,
                    },
                });
                if *message_id_raw != 0 {
                    self.summary.incomplete_batches =
                        self.summary.incomplete_batches.saturating_add(1);
                    self.summary.batches_not_retained =
                        self.summary.batches_not_retained.saturating_add(1);
                    if let Some(packets) = known_unretained_wintab_packets(*wintab_issue) {
                        self.summary.samples_not_retained =
                            self.summary.samples_not_retained.saturating_add(packets);
                    }
                    self.summary.wintab_status = WintabStatus::Partial;
                }
            }
            ProbeRecord::IgnoredNonPenPointer { .. } => {
                self.summary.issues = self.summary.issues.saturating_add(1);
                self.summary.ignored_non_pen_pointers =
                    self.summary.ignored_non_pen_pointers.saturating_add(1);
                self.summary.latest_incomplete_issue = Some(issue);
            }
        }
        self.mark_storage_limit(false, false, false, true);
    }

    fn note_incomplete_issue(&mut self, issue: CaptureIssue, samples_not_retained: Option<u64>) {
        self.summary.issues = self.summary.issues.saturating_add(1);
        self.summary.incomplete_batches = self.summary.incomplete_batches.saturating_add(1);
        self.summary.batches_not_retained = self.summary.batches_not_retained.saturating_add(1);
        self.summary.latest_incomplete_issue = Some(issue);
        if let Some(samples) = samples_not_retained {
            self.summary.samples_not_retained =
                self.summary.samples_not_retained.saturating_add(samples);
        }
    }

    fn mark_storage_limit(
        &mut self,
        record_limit: bool,
        sample_limit: bool,
        native_limit: bool,
        allocation_limit: bool,
    ) {
        if !record_limit && !sample_limit && !native_limit && !allocation_limit {
            return;
        }
        let reached_count = u8::from(record_limit)
            + u8::from(sample_limit)
            + u8::from(native_limit)
            + u8::from(allocation_limit);
        self.summary.storage_limit = Some(if reached_count > 1 {
            StorageLimit::Multiple
        } else if record_limit {
            StorageLimit::Records
        } else if sample_limit {
            StorageLimit::Samples
        } else if native_limit {
            StorageLimit::NativeHistory
        } else {
            StorageLimit::Allocation
        });
    }
}

fn known_unretained_samples(issue: CaptureIssue) -> Option<u64> {
    match issue {
        CaptureIssue::HistoryTooLarge { reported, .. }
        | CaptureIssue::RetainedSampleCapacityExceeded { reported, .. } => {
            Some(u64::from(reported))
        }
        CaptureIssue::RetainedRecordCapacityExceeded {
            reported_samples, ..
        }
        | CaptureIssue::RetentionCapacitiesExceeded {
            reported_samples, ..
        } => Some(u64::from(reported_samples)),
        CaptureIssue::HistoryStillGrowing { returned, .. } => Some(u64::from(returned)),
        CaptureIssue::AllocationFailed { capacity } => Some(u64::from(capacity)),
        _ => None,
    }
}

fn known_unretained_wintab_packets(issue: WintabIssue) -> Option<u64> {
    match issue {
        WintabIssue::RetainedDataLimitExceeded {
            reported_packets, ..
        }
        | WintabIssue::RetainedSampleCapacityExceeded {
            reported_packets, ..
        } => Some(u64::from(reported_packets)),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HistoryBufferDecision {
    Complete { initialized_len: usize },
    Retry { required_capacity: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HistoryCountError {
    Empty,
    TooLarge { reported: u32, maximum: u32 },
    CountChanged { expected: u32, returned: u32 },
}

/// An API-success buffer may still be incomplete: if returned total exceeds the
/// supplied capacity, Win32 wrote only the newest rows and the caller must retry.
fn history_buffer_decision(
    supplied_capacity: u32,
    expected_total: u32,
    returned_total: u32,
    maximum: u32,
) -> Result<HistoryBufferDecision, HistoryCountError> {
    if supplied_capacity == 0 || expected_total == 0 || returned_total == 0 {
        return Err(HistoryCountError::Empty);
    }
    for count in [supplied_capacity, expected_total, returned_total] {
        if count > maximum {
            return Err(HistoryCountError::TooLarge {
                reported: count,
                maximum,
            });
        }
    }
    if returned_total > supplied_capacity {
        return Ok(HistoryBufferDecision::Retry {
            required_capacity: returned_total,
        });
    }
    if returned_total < expected_total {
        return Err(HistoryCountError::CountChanged {
            expected: expected_total,
            returned: returned_total,
        });
    }
    Ok(HistoryBufferDecision::Complete {
        initialized_len: returned_total as usize,
    })
}

/// Win32 returns the history newest-first. Reverse the copied array exactly once;
/// do not sort by timestamp or frame ID.
fn normalize_newest_first<T>(mut records: Vec<T>) -> Vec<T> {
    records.reverse();
    records
}

#[derive(Clone, Copy)]
struct PointerApi {
    get_pointer_type: GetPointerTypeFn,
    get_pen_history: GetPointerPenInfoHistoryFn,
}

#[derive(Clone, Copy)]
struct HookQpcObservation {
    count_raw: Option<u64>,
    issue: Option<CaptureIssue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HookMessageMetadata {
    pub message_id_raw: u32,
    pub message_hwnd_raw_session_scoped: isize,
    pub wparam_raw: usize,
    pub lparam_raw: isize,
    pub message_time_ms_raw: Option<u32>,
    pub pointer_id: u32,
}

fn hook_message_metadata(message: &MSG) -> HookMessageMetadata {
    HookMessageMetadata {
        message_id_raw: message.message,
        message_hwnd_raw_session_scoped: message.hwnd,
        wparam_raw: message.wParam,
        lparam_raw: message.lParam,
        message_time_ms_raw: Some(message.time),
        pointer_id: (message.wParam & 0xffff) as u32,
    }
}

type GetPointerTypeFn = unsafe extern "system" fn(u32, *mut POINTER_INPUT_TYPE) -> BOOL;
type GetPointerPenInfoHistoryFn =
    unsafe extern "system" fn(u32, *mut u32, *mut POINTER_PEN_INFO) -> BOOL;

fn win32_last_error() -> u32 {
    // SAFETY: GetLastError has no pointer parameters and is valid on this Windows thread.
    unsafe { GetLastError() }
}

fn load_pointer_api() -> Result<PointerApi, CaptureIssue> {
    // SAFETY: USER32_DLL is a static, NUL-terminated UTF-16 module name.
    let module: HMODULE = unsafe { GetModuleHandleW(USER32_DLL.as_ptr()) };
    if module == 0 {
        return Err(CaptureIssue::ApiUnavailable {
            api: NativeApi::User32Module,
            win32_error: win32_last_error(),
        });
    }

    // SAFETY: The symbol name is static, ASCII, and NUL-terminated; GetProcAddress
    // only returns the address and does not call the function.
    let get_pointer_type_raw = unsafe { GetProcAddress(module, GET_POINTER_TYPE_NAME.as_ptr()) };
    let Some(get_pointer_type_raw) = get_pointer_type_raw else {
        return Err(CaptureIssue::ApiUnavailable {
            api: NativeApi::GetPointerType,
            win32_error: win32_last_error(),
        });
    };
    // SAFETY: USER32's GetPointerType export has the documented system ABI and
    // signature BOOL (UINT32, POINTER_INPUT_TYPE*). The function pointer widths match.
    let get_pointer_type = unsafe {
        mem::transmute::<unsafe extern "system" fn() -> isize, GetPointerTypeFn>(
            get_pointer_type_raw,
        )
    };

    // SAFETY: The symbol name is static, ASCII, and NUL-terminated; GetProcAddress
    // only returns the address and does not call the function.
    let get_pen_history_raw =
        unsafe { GetProcAddress(module, GET_POINTER_PEN_INFO_HISTORY_NAME.as_ptr()) };
    let Some(get_pen_history_raw) = get_pen_history_raw else {
        return Err(CaptureIssue::ApiUnavailable {
            api: NativeApi::GetPointerPenInfoHistoryExport,
            win32_error: win32_last_error(),
        });
    };
    // SAFETY: USER32's GetPointerPenInfoHistory export has the documented system
    // ABI and signature BOOL (UINT32, UINT32*, POINTER_PEN_INFO*). The function pointer widths match.
    let get_pen_history = unsafe {
        mem::transmute::<unsafe extern "system" fn() -> isize, GetPointerPenInfoHistoryFn>(
            get_pen_history_raw,
        )
    };

    Ok(PointerApi {
        get_pointer_type,
        get_pen_history,
    })
}

fn query_qpc_frequency() -> Result<u64, CaptureIssue> {
    let mut frequency = 0i64;
    // SAFETY: `frequency` is a valid writable LARGE_INTEGER-compatible output buffer.
    let succeeded = unsafe { QueryPerformanceFrequency(&mut frequency) };
    if succeeded == 0 || frequency <= 0 {
        return Err(CaptureIssue::QpcFrequencyUnavailable {
            win32_error: win32_last_error(),
        });
    }
    Ok(frequency as u64)
}

fn query_qpc_counter() -> Result<u64, CaptureIssue> {
    let mut count = 0i64;
    // SAFETY: `count` is a valid writable LARGE_INTEGER-compatible output buffer.
    let succeeded = unsafe { QueryPerformanceCounter(&mut count) };
    if succeeded == 0 || count < 0 {
        return Err(CaptureIssue::QpcCounterUnavailable {
            win32_error: win32_last_error(),
        });
    }
    Ok(count as u64)
}

fn direct_lifecycle_message(message_id_raw: u32) -> Option<(LifecycleEventKind, bool)> {
    let event = match message_id_raw {
        WM_POINTERENTER => (LifecycleEventKind::DirectPointerEnter, true),
        WM_POINTERLEAVE => (LifecycleEventKind::DirectPointerLeave, true),
        WM_POINTERCAPTURECHANGED => (LifecycleEventKind::DirectPointerCaptureChanged, true),
        WM_POINTERDEVICECHANGE => (LifecycleEventKind::DirectPointerDeviceChanged, false),
        WM_POINTERDEVICEINRANGE => (LifecycleEventKind::DirectPointerDeviceInRange, false),
        WM_POINTERDEVICEOUTOFRANGE => (LifecycleEventKind::DirectPointerDeviceOutOfRange, false),
        _ => return None,
    };
    Some(event)
}

fn startup_issue_event(issue: CaptureIssue, app_observed_elapsed_ns: u128) -> LifecycleEventRecord {
    LifecycleEventRecord {
        source: CaptureSource::ApplicationLifecycle,
        kind: LifecycleEventKind::StartupIssue,
        app_observed_elapsed_ns,
        message_id_raw: None,
        message_hwnd_raw_session_scoped: None,
        wparam_raw: None,
        lparam_raw: None,
        native_message_time_ms_raw: None,
        pointer_id_raw: None,
        winit_device_id_debug: None,
        event_loop_wait_start_elapsed_ns: None,
        event_loop_requested_resume_elapsed_ns: None,
        event_loop_wake_lateness_ns: None,
        controlled_stall_duration_ns: None,
        issue_debug: Some(format!("{issue:?}")),
    }
}

/// Install a synchronous Winit hook. Copy pointer history before returning
/// `false`, which allows Winit to dispatch the public window event normally.
pub(crate) fn install_message_hook(
    builder: &mut EventLoopBuilder<()>,
    state: Rc<RefCell<ProbeState>>,
    mode: CaptureMode,
    wintab: Rc<RefCell<crate::wintab::WintabCapture>>,
    app_clock_origin: Instant,
    wintab_control_pending: Arc<AtomicBool>,
) {
    state.borrow_mut().set_capture_mode(mode);
    let pointer_api = load_pointer_api();
    let pointer_api_issue = pointer_api.as_ref().err().copied();
    state
        .borrow_mut()
        .set_api_state(pointer_api.is_ok(), pointer_api_issue);
    let public_pointer_type_api = pointer_api.as_ref().ok().map(|api| api.get_pointer_type);
    state
        .borrow_mut()
        .set_public_pointer_type_api(public_pointer_type_api);
    if let Some(issue) = pointer_api_issue {
        state.borrow_mut().record(ProbeRecord::StartupIssue(issue));
        state
            .borrow_mut()
            .record(ProbeRecord::Lifecycle(startup_issue_event(
                issue,
                app_clock_origin.elapsed().as_nanos(),
            )));
    }
    let (qpc_frequency, qpc_frequency_issue) = if mode == CaptureMode::DirectWmPointer {
        match query_qpc_frequency() {
            Ok(frequency) => (Some(frequency), None),
            Err(issue) => (None, Some(issue)),
        }
    } else {
        (None, None)
    };
    state
        .borrow_mut()
        .set_qpc_frequency(qpc_frequency, qpc_frequency_issue);
    if let Some(issue) = qpc_frequency_issue {
        state.borrow_mut().record(ProbeRecord::StartupIssue(issue));
        state
            .borrow_mut()
            .record(ProbeRecord::Lifecycle(startup_issue_event(
                issue,
                app_clock_origin.elapsed().as_nanos(),
            )));
    }

    let mut message_sequence = 0u64;
    builder.with_msg_hook(move |message_pointer| {
        if !state.borrow().can_capture() {
            if mode == CaptureMode::Wintab {
                let mut probe_state = state.borrow_mut();
                wintab
                    .borrow_mut()
                    .request_close_after_storage_limit(&mut probe_state);
            }
            return false;
        }
        let remaining_samples = state.borrow().remaining_sample_capacity();
        let current_sequence = message_sequence;
        let Some(next_sequence) = message_sequence.checked_add(1) else {
            let issue = CaptureIssue::MessageSequenceExhausted;
            state.borrow_mut().record(ProbeRecord::StartupIssue(issue));
            state
                .borrow_mut()
                .record(ProbeRecord::Lifecycle(startup_issue_event(
                    issue,
                    app_clock_origin.elapsed().as_nanos(),
                )));
            return false;
        };
        message_sequence = next_sequence;
        let hook_observed_elapsed_ns = app_clock_origin.elapsed().as_nanos();
        // SAFETY: Winit's pointer is the current live MSG for this hook call.
        // Copy only its numeric fields; no pointer or handle ownership is kept.
        let message_metadata = unsafe { copy_message_metadata(message_pointer) };
        let hook_qpc_observation = if mode == CaptureMode::DirectWmPointer
            && message_metadata
                .is_some_and(|metadata| pointer_message_kind(metadata.message_id_raw).is_some())
        {
            match query_qpc_counter() {
                Ok(count) => HookQpcObservation {
                    count_raw: Some(count),
                    issue: None,
                },
                Err(issue) => HookQpcObservation {
                    count_raw: None,
                    issue: Some(issue),
                },
            }
        } else {
            HookQpcObservation {
                count_raw: None,
                issue: None,
            }
        };
        let mut probe_state = state.borrow_mut();
        probe_state.begin_native_dispatch(current_sequence, message_metadata);
        if let Some(metadata) = message_metadata
            && let Some((kind, has_pointer_id)) = direct_lifecycle_message(metadata.message_id_raw)
        {
            probe_state.record(ProbeRecord::Lifecycle(LifecycleEventRecord {
                source: CaptureSource::DirectWin32Lifecycle,
                kind,
                app_observed_elapsed_ns: hook_observed_elapsed_ns,
                message_id_raw: Some(metadata.message_id_raw),
                message_hwnd_raw_session_scoped: Some(metadata.message_hwnd_raw_session_scoped),
                wparam_raw: Some(metadata.wparam_raw),
                lparam_raw: Some(metadata.lparam_raw),
                native_message_time_ms_raw: metadata.message_time_ms_raw,
                pointer_id_raw: has_pointer_id.then_some(metadata.pointer_id),
                winit_device_id_debug: None,
                event_loop_wait_start_elapsed_ns: None,
                event_loop_requested_resume_elapsed_ns: None,
                event_loop_wake_lateness_ns: None,
                controlled_stall_duration_ns: None,
                issue_debug: None,
            }));
        }
        if !probe_state.can_capture() {
            if mode == CaptureMode::Wintab {
                wintab
                    .borrow_mut()
                    .request_close_after_storage_limit(&mut probe_state);
            }
            return false;
        }
        // SAFETY: Winit's Windows hook receives a pointer to its current, live MSG
        // after PeekMessageW and before DispatchMessageW/another message retrieval.
        // capture_message borrows it only for this callback and copies all fields.
        match mode {
            CaptureMode::DirectWmPointer => {
                let record = unsafe {
                    capture_message(
                        message_pointer,
                        current_sequence,
                        hook_observed_elapsed_ns,
                        pointer_api,
                        qpc_frequency,
                        remaining_samples,
                        hook_qpc_observation,
                    )
                };
                if let Some(record) = record {
                    probe_state.record(record);
                }
            }
            CaptureMode::Wintab => {
                if let Some(metadata) = message_metadata {
                    wintab.borrow_mut().handle_message(
                        metadata,
                        current_sequence,
                        hook_observed_elapsed_ns,
                        &wintab_control_pending,
                        &mut probe_state,
                    );
                }
            }
        }
        false
    });
}

pub(crate) fn wintab_packet_hook_may_drain(control_pending: &AtomicBool) -> bool {
    !control_pending.load(Ordering::Acquire)
}

/// # Safety
/// `message_pointer` must be the live MSG pointer supplied by Winit's
/// `with_msg_hook`; this helper only copies scalar fields and returns no pointer.
unsafe fn copy_message_metadata(message_pointer: *const c_void) -> Option<HookMessageMetadata> {
    if message_pointer.is_null() {
        return None;
    }
    // SAFETY: The caller guarantees the MSG remains live throughout the hook.
    let message = unsafe { &*message_pointer.cast::<MSG>() };
    Some(hook_message_metadata(message))
}

/// # Safety
/// `message_pointer` must be the live MSG pointer supplied by Winit's
/// `with_msg_hook`, and this function must complete before the hook returns.
unsafe fn capture_message(
    message_pointer: *const c_void,
    message_sequence: u64,
    hook_observed_elapsed_ns: u128,
    pointer_api_result: Result<PointerApi, CaptureIssue>,
    qpc_frequency_hz: Option<u64>,
    remaining_sample_capacity: u64,
    hook_qpc_observation: HookQpcObservation,
) -> Option<ProbeRecord> {
    if message_pointer.is_null() {
        return Some(ProbeRecord::MessageIssue {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence,
            message_id_raw: 0,
            message_hwnd_raw_session_scoped: None,
            message_wparam_raw: None,
            message_lparam_raw: None,
            message_time_ms_raw: None,
            message_kind: None,
            pointer_id: None,
            hook_observed_elapsed_ns,
            issue: CaptureIssue::NullMessagePointer,
        });
    }

    // SAFETY: The caller guarantees Winit's live MSG pointer and this borrow does
    // not outlive the callback. We copy the fields used below immediately.
    let message = unsafe { &*message_pointer.cast::<MSG>() };
    let metadata = hook_message_metadata(message);
    let message_id_raw = metadata.message_id_raw;
    let message_kind = pointer_message_kind(message_id_raw)?;
    let pointer_id = metadata.pointer_id;
    if pointer_id == 0 {
        return Some(message_issue(
            message_sequence,
            metadata,
            message_kind,
            None,
            hook_observed_elapsed_ns,
            CaptureIssue::InvalidPointerId,
        ));
    }
    let pointer_api = match pointer_api_result {
        Ok(api) => api,
        Err(issue) => {
            return Some(message_issue(
                message_sequence,
                metadata,
                message_kind,
                Some(pointer_id),
                hook_observed_elapsed_ns,
                issue,
            ));
        }
    };

    let mut pointer_type: POINTER_INPUT_TYPE = 0;
    // SAFETY: `pointer_type` is a valid output pointer; the ID came from this
    // thread's current WM_POINTER message.
    if unsafe { (pointer_api.get_pointer_type)(pointer_id, &mut pointer_type) } == 0 {
        let error = win32_last_error();
        return Some(message_issue(
            message_sequence,
            metadata,
            message_kind,
            Some(pointer_id),
            hook_observed_elapsed_ns,
            CaptureIssue::ApiCallFailed {
                api: NativeApi::GetPointerType,
                win32_error: error,
            },
        ));
    }
    if pointer_type != PT_PEN {
        return Some(ProbeRecord::IgnoredNonPenPointer {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence,
            message_id_raw,
            message_hwnd_raw_session_scoped: metadata.message_hwnd_raw_session_scoped,
            message_wparam_raw: metadata.wparam_raw,
            message_lparam_raw: metadata.lparam_raw,
            message_time_ms_raw: metadata.message_time_ms_raw,
            message_kind,
            pointer_id,
            pointer_type_raw: pointer_type,
            hook_observed_elapsed_ns,
        });
    }

    let raw_history =
        match read_complete_history(pointer_api, pointer_id, remaining_sample_capacity) {
            Ok(history) => history,
            Err(issue) => {
                return Some(message_issue(
                    message_sequence,
                    metadata,
                    message_kind,
                    Some(pointer_id),
                    hook_observed_elapsed_ns,
                    issue,
                ));
            }
        };
    let native_history_count = match u32::try_from(raw_history.len()) {
        Ok(count) => count,
        Err(_) => {
            return Some(message_issue(
                message_sequence,
                metadata,
                message_kind,
                Some(pointer_id),
                hook_observed_elapsed_ns,
                CaptureIssue::HistoryTooLarge {
                    reported: u32::MAX,
                    maximum: MAX_HISTORY_ENTRIES,
                },
            ));
        }
    };
    let chronological_records = normalize_newest_first(raw_history);
    let mut samples = Vec::new();
    if samples
        .try_reserve_exact(native_history_count as usize)
        .is_err()
    {
        return Some(message_issue(
            message_sequence,
            metadata,
            message_kind,
            Some(pointer_id),
            hook_observed_elapsed_ns,
            CaptureIssue::AllocationFailed {
                capacity: native_history_count,
            },
        ));
    }
    for (chronological_index, native) in chronological_records.into_iter().enumerate() {
        let sample = match own_sample(
            native,
            pointer_id,
            native_history_count - 1 - chronological_index as u32,
            chronological_index as u32,
        ) {
            Ok(sample) => sample,
            Err(()) => {
                return Some(message_issue(
                    message_sequence,
                    metadata,
                    message_kind,
                    Some(pointer_id),
                    hook_observed_elapsed_ns,
                    CaptureIssue::AllocationFailed {
                        capacity: native_history_count,
                    },
                ));
            }
        };
        samples.push(sample);
    }

    Some(ProbeRecord::DirectPenHistory(DirectPenHistoryBatch {
        source: CaptureSource::DirectWmPointerPenHistory,
        message_sequence,
        message_id_raw,
        message_hwnd_raw_session_scoped: metadata.message_hwnd_raw_session_scoped,
        message_time_ms_raw: metadata.message_time_ms_raw,
        message_kind,
        pointer_id_requested: pointer_id,
        hook_observed_elapsed_ns,
        hook_qpc_count_raw: hook_qpc_observation.count_raw,
        hook_qpc_issue: hook_qpc_observation.issue,
        qpc_frequency_hz,
        native_history_count,
        samples,
    }))
}

fn message_issue(
    message_sequence: u64,
    metadata: HookMessageMetadata,
    message_kind: PointerMessageKind,
    pointer_id: Option<u32>,
    hook_observed_elapsed_ns: u128,
    issue: CaptureIssue,
) -> ProbeRecord {
    ProbeRecord::MessageIssue {
        source: CaptureSource::DirectWmPointerPenHistory,
        message_sequence,
        message_id_raw: metadata.message_id_raw,
        message_hwnd_raw_session_scoped: Some(metadata.message_hwnd_raw_session_scoped),
        message_wparam_raw: Some(metadata.wparam_raw),
        message_lparam_raw: Some(metadata.lparam_raw),
        message_time_ms_raw: metadata.message_time_ms_raw,
        message_kind: Some(message_kind),
        pointer_id,
        hook_observed_elapsed_ns,
        issue,
    }
}

fn read_complete_history(
    api: PointerApi,
    pointer_id: u32,
    remaining_sample_capacity: u64,
) -> Result<Vec<POINTER_PEN_INFO>, CaptureIssue> {
    let mut available_count = 0u32;
    // SAFETY: Microsoft permits a null penInfo buffer when the input count is
    // zero. This call runs on the thread that retrieved the current MSG.
    if unsafe { (api.get_pen_history)(pointer_id, &mut available_count, std::ptr::null_mut()) } == 0
    {
        return Err(CaptureIssue::ApiCallFailed {
            api: NativeApi::GetPointerPenInfoHistorySizing,
            win32_error: win32_last_error(),
        });
    }
    if available_count == 0 {
        return Err(CaptureIssue::EmptyHistory);
    }
    ensure_native_history_fits(available_count, remaining_sample_capacity)?;

    let mut expected_total = available_count;
    let mut capacity = available_count;
    let mut last_returned_total = available_count;
    for attempt in 1..=MAX_HISTORY_FETCH_ATTEMPTS {
        let capacity_usize =
            usize::try_from(capacity).map_err(|_| CaptureIssue::HistoryTooLarge {
                reported: capacity,
                maximum: MAX_HISTORY_ENTRIES,
            })?;
        let mut buffer = Vec::<MaybeUninit<POINTER_PEN_INFO>>::new();
        buffer
            .try_reserve_exact(capacity_usize)
            .map_err(|_| CaptureIssue::AllocationFailed { capacity })?;
        buffer.resize_with(capacity_usize, MaybeUninit::uninit);

        let mut returned_total = capacity;
        // SAFETY: `buffer` holds `capacity` correctly aligned MaybeUninit slots;
        // the typed Win32 API writes up to that capacity. No next MSG is retrieved
        // between sizing, fetching, and a bounded retry in this hook.
        if unsafe {
            (api.get_pen_history)(
                pointer_id,
                &mut returned_total,
                buffer.as_mut_ptr().cast::<POINTER_PEN_INFO>(),
            )
        } == 0
        {
            return Err(CaptureIssue::ApiCallFailed {
                api: NativeApi::GetPointerPenInfoHistoryFetch,
                win32_error: win32_last_error(),
            });
        }
        last_returned_total = returned_total;
        ensure_native_history_fits(returned_total, remaining_sample_capacity)?;

        match history_buffer_decision(
            capacity,
            expected_total,
            returned_total,
            MAX_HISTORY_ENTRIES,
        ) {
            Ok(HistoryBufferDecision::Retry { required_capacity }) => {
                if attempt == MAX_HISTORY_FETCH_ATTEMPTS {
                    return Err(CaptureIssue::HistoryStillGrowing {
                        capacity,
                        returned: returned_total,
                        attempts: attempt,
                    });
                }
                capacity = required_capacity;
                expected_total = required_capacity;
            }
            Ok(HistoryBufferDecision::Complete { initialized_len }) => {
                let mut initialized = Vec::new();
                initialized
                    .try_reserve_exact(initialized_len)
                    .map_err(|_| CaptureIssue::AllocationFailed {
                        capacity: returned_total,
                    })?;
                for slot in buffer.into_iter().take(initialized_len) {
                    // SAFETY: The API returned success and a total within the
                    // supplied capacity, so the first `initialized_len` rows were written.
                    initialized.push(unsafe { slot.assume_init() });
                }
                return Ok(initialized);
            }
            Err(HistoryCountError::Empty) => return Err(CaptureIssue::EmptyHistory),
            Err(HistoryCountError::TooLarge { reported, maximum }) => {
                return Err(CaptureIssue::HistoryTooLarge { reported, maximum });
            }
            Err(HistoryCountError::CountChanged { expected, returned }) => {
                return Err(CaptureIssue::HistoryCountChanged { expected, returned });
            }
        }
    }

    Err(CaptureIssue::HistoryStillGrowing {
        capacity,
        returned: last_returned_total,
        attempts: MAX_HISTORY_FETCH_ATTEMPTS,
    })
}

fn ensure_native_history_fits(
    reported: u32,
    remaining_sample_capacity: u64,
) -> Result<(), CaptureIssue> {
    if reported > MAX_HISTORY_ENTRIES {
        return Err(CaptureIssue::HistoryTooLarge {
            reported,
            maximum: MAX_HISTORY_ENTRIES,
        });
    }
    if u64::from(reported) > remaining_sample_capacity {
        return Err(CaptureIssue::RetainedSampleCapacityExceeded {
            reported,
            remaining: remaining_sample_capacity,
        });
    }
    Ok(())
}

fn own_sample(
    native: POINTER_PEN_INFO,
    requested_pointer_id: u32,
    history_index_newest_first: u32,
    chronological_index: u32,
) -> Result<OwnedPointerSample, ()> {
    let pointer_info = native.pointerInfo;
    let mut validation_issues = Vec::new();
    let attribution = if pointer_info.pointerId == requested_pointer_id {
        PointerAttribution::MatchesRequestedPointer
    } else {
        push_validation_issue(
            &mut validation_issues,
            SampleValidationIssue::PointerIdMismatch {
                requested: requested_pointer_id,
                reported: pointer_info.pointerId,
            },
        )?;
        PointerAttribution::UnclassifiedIdMismatch {
            requested: requested_pointer_id,
            reported: pointer_info.pointerId,
        }
    };
    if pointer_info.pointerType != PT_PEN {
        push_validation_issue(
            &mut validation_issues,
            SampleValidationIssue::UnexpectedPointerType {
                reported: pointer_info.pointerType,
            },
        )?;
    }

    let pressure_validity = pressure_validity(native.penMask, native.pressure);
    match pressure_validity {
        PressureValidity::NotReported => {
            push_validation_issue(
                &mut validation_issues,
                SampleValidationIssue::PressureMaskMissing,
            )?;
        }
        PressureValidity::OutOfRange => {
            push_validation_issue(
                &mut validation_issues,
                SampleValidationIssue::PressureOutOfRange {
                    raw: native.pressure,
                },
            )?;
        }
        PressureValidity::Valid => {}
    }
    let tilt_mask = PEN_MASK_TILT_X | PEN_MASK_TILT_Y;
    if native.penMask & tilt_mask != 0 {
        push_validation_issue(
            &mut validation_issues,
            SampleValidationIssue::UnexpectedTiltMask {
                raw_mask: native.penMask,
            },
        )?;
    }

    Ok(OwnedPointerSample {
        history_index_newest_first,
        chronological_index,
        attribution,
        pointer_type_raw: pointer_info.pointerType,
        pointer_id_raw: pointer_info.pointerId,
        frame_id_raw: pointer_info.frameId,
        source_device_handle_raw_session_scoped: pointer_info.sourceDevice,
        target_hwnd_raw_session_scoped: pointer_info.hwndTarget,
        pointer_flags_raw: pointer_info.pointerFlags,
        button_change_type_raw: pointer_info.ButtonChangeType,
        position: RawScreenPosition {
            coordinate_space: CoordinateSpace::WindowsScreenCoordinates,
            pixel_units: CoordinateUnits::ScreenPixel,
            pt_pixel_location_raw: RawPoint {
                x: pointer_info.ptPixelLocationRaw.x,
                y: pointer_info.ptPixelLocationRaw.y,
            },
            himetric_units: CoordinateUnits::HimetricHundredthMillimeter,
            pt_himetric_location_raw: RawPoint {
                x: pointer_info.ptHimetricLocationRaw.x,
                y: pointer_info.ptHimetricLocationRaw.y,
            },
        },
        performance_count_qpc_raw: pointer_info.PerformanceCount,
        dw_time_ms_wrapping_raw: pointer_info.dwTime,
        history_count_raw: pointer_info.historyCount,
        input_data_raw: pointer_info.InputData,
        key_states_raw: pointer_info.dwKeyStates,
        pen_flags_raw: native.penFlags,
        pen_mask_raw: native.penMask,
        pressure_raw: native.pressure,
        pressure_validity,
        rotation_raw: native.rotation,
        tilt_x_raw: native.tiltX,
        tilt_y_raw: native.tiltY,
        // CT430 does not support tilt; retain the native mask and raw values above,
        // but never derive or synthesize semantic tilt for this device.
        tilt: None,
        validation_issues,
    })
}

fn push_validation_issue(
    issues: &mut Vec<SampleValidationIssue>,
    issue: SampleValidationIssue,
) -> Result<(), ()> {
    issues.try_reserve(1).map_err(|_| ())?;
    issues.push(issue);
    Ok(())
}

fn pointer_message_kind(message_id: u32) -> Option<PointerMessageKind> {
    match message_id {
        WM_POINTERDOWN => Some(PointerMessageKind::Down),
        WM_POINTERUPDATE => Some(PointerMessageKind::Update),
        WM_POINTERUP => Some(PointerMessageKind::Up),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CaptureIssue, CaptureSource, CoordinateSpace, CoordinateUnits, DirectPenHistoryBatch,
        HistoryBufferDecision, HistoryCountError, HookMessageMetadata, MAX_HISTORY_ENTRIES,
        NativeApi, PointerAttribution, PointerMessageKind, PressureValidity, ProbeRecord,
        ProbeState, PublicEventCapability, PublicMessageAssociation, PublicPenClassification,
        PublicUnclassifiedReason, PublicWinitEventData, PublicWinitEventRecord, RawPoint,
        RawScreenPosition, SampleValidationIssue, SessionOutputStage, StorageLimit, TouchPhase,
        WintabContextConfig, WintabCoordinateSpace, WintabIssue, WintabPacketBatch,
        WintabPacketSample, WintabPacketTimeMode, WintabStatus, ensure_native_history_fits,
        history_buffer_decision, hook_message_metadata, normalize_newest_first, own_sample,
        pressure_validity,
    };
    use windows_sys::Win32::{
        Foundation::BOOL,
        UI::Input::Pointer::POINTER_PEN_INFO,
        UI::WindowsAndMessaging::{
            MSG, PEN_MASK_PRESSURE, POINTER_INPUT_TYPE, PT_PEN, PT_TOUCH, WM_POINTERUPDATE,
        },
    };

    unsafe extern "system" fn fake_get_pointer_type(
        pointer_id: u32,
        pointer_type: *mut POINTER_INPUT_TYPE,
    ) -> BOOL {
        if pointer_type.is_null() {
            return 0;
        }
        // SAFETY: The test caller supplies a valid output slot through the safe
        // ProbeState association method.
        unsafe {
            *pointer_type = if pointer_id == 7 { PT_PEN } else { PT_TOUCH };
        }
        1
    }

    fn api_error_record(sequence: u64) -> ProbeRecord {
        ProbeRecord::MessageIssue {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence: sequence,
            message_id_raw: WM_POINTERUPDATE,
            message_hwnd_raw_session_scoped: Some(0x2222),
            message_wparam_raw: Some(7),
            message_lparam_raw: Some(0),
            message_time_ms_raw: Some(1),
            message_kind: Some(PointerMessageKind::Update),
            pointer_id: Some(7),
            hook_observed_elapsed_ns: sequence as u128,
            issue: CaptureIssue::ApiCallFailed {
                api: NativeApi::GetPointerType,
                win32_error: 5,
            },
        }
    }

    fn public_touch_record(sequence: u64) -> ProbeRecord {
        ProbeRecord::PublicWinitEvent(PublicWinitEventRecord {
            source: CaptureSource::PublicWinitWindowEvent,
            capability: PublicEventCapability::TouchPhasePositionForce,
            public_event_sequence: sequence,
            app_observed_elapsed_ns: sequence as u128,
            window_hwnd_raw_session_scoped: Some(0x2222),
            message_association: None,
            data: PublicWinitEventData::Touch {
                winit_device_id: winit::event::DeviceId::dummy(),
                public_touch_id: 7,
                phase: TouchPhase::Moved,
                x_physical_px: 1.0,
                y_physical_px: 2.0,
                public_winit_force: Some(winit::event::Force::Normalized(0.5)),
                native_pointer_type_raw: None,
                pointer_type_error_raw: None,
                pen_classification: PublicPenClassification::Unclassified(
                    PublicUnclassifiedReason::NoMatchedNativeMessage,
                ),
                native_timestamp_raw: None,
                tilt: None,
            },
        })
    }

    fn direct_batch(sample_count: usize, sequence: u64) -> ProbeRecord {
        let sample = super::OwnedPointerSample {
            history_index_newest_first: 0,
            chronological_index: 0,
            attribution: PointerAttribution::MatchesRequestedPointer,
            pointer_type_raw: PT_PEN,
            pointer_id_raw: 7,
            frame_id_raw: 1,
            source_device_handle_raw_session_scoped: 0x1234,
            target_hwnd_raw_session_scoped: 0x5678,
            pointer_flags_raw: 0,
            button_change_type_raw: 0,
            position: RawScreenPosition {
                coordinate_space: CoordinateSpace::WindowsScreenCoordinates,
                pixel_units: CoordinateUnits::ScreenPixel,
                pt_pixel_location_raw: RawPoint { x: 1, y: 2 },
                himetric_units: CoordinateUnits::HimetricHundredthMillimeter,
                pt_himetric_location_raw: RawPoint { x: 3, y: 4 },
            },
            performance_count_qpc_raw: 5,
            dw_time_ms_wrapping_raw: 6,
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
        };
        ProbeRecord::DirectPenHistory(DirectPenHistoryBatch {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence: sequence,
            message_id_raw: WM_POINTERUPDATE,
            message_hwnd_raw_session_scoped: 0x2222,
            message_time_ms_raw: Some(sequence as u32),
            message_kind: PointerMessageKind::Update,
            pointer_id_requested: 7,
            hook_observed_elapsed_ns: sequence as u128,
            hook_qpc_count_raw: Some(sequence),
            hook_qpc_issue: None,
            qpc_frequency_hz: Some(10_000_000),
            native_history_count: sample_count as u32,
            samples: vec![sample; sample_count],
        })
    }

    fn wintab_batch(packet_count: usize, sequence: u64) -> ProbeRecord {
        let packet = WintabPacketSample {
            context_handle_raw_session_scoped: 0x7777,
            status_raw: 0,
            packet_time_raw: sequence as u32,
            serial_number_raw: sequence as u32,
            cursor_raw: 0,
            buttons_raw: 0,
            x_raw: 1,
            y_raw: 2,
            normal_pressure_raw: 0,
        };
        ProbeRecord::WintabPackets(WintabPacketBatch {
            source: CaptureSource::WintabPacket,
            message_sequence: sequence,
            message_id_raw: 0x7ff0,
            message_hwnd_raw_session_scoped: 0x2222,
            message_time_ms_raw: Some(sequence as u32),
            message_wparam_raw: sequence as usize,
            message_lparam_raw: 0x7777,
            context_handle_raw_session_scoped: 0x7777,
            notification_serial_raw: Some(sequence as u32),
            context_config: WintabContextConfig {
                context_name_raw: [0; 40],
                options_raw: 0x0004,
                status_raw: 0,
                locks_raw: 0,
                message_base_raw: 0x7ff0,
                device_raw: 1,
                packet_rate_raw: 220,
                packet_data_raw: 0x5f7,
                packet_mode_raw: 0,
                move_mask_raw: 0x580,
                button_down_mask_raw: 0,
                button_up_mask_raw: 0,
                input_origin_raw: [0; 3],
                input_extent_raw: [10_000; 3],
                output_origin_raw: [0; 3],
                output_extent_raw: [10_000; 3],
                sensitivity_fixed32_raw: [0; 3],
                system_mode_raw: 0,
                system_origin_raw: [0; 2],
                system_extent_raw: [0; 2],
                system_sensitivity_fixed32_raw: [0; 2],
            },
            queue_capacity_raw: 1024,
            coordinate_space: WintabCoordinateSpace::DigitizerContextOutputCoordinates,
            packet_time_mode: WintabPacketTimeMode::AbsoluteSystemTime,
            app_observed_elapsed_ns: sequence as u128,
            control_transition_observed_during_read: false,
            packets: vec![packet; packet_count],
        })
    }

    #[test]
    fn successful_undersized_history_buffer_retries_before_reading_rows() {
        // If the API succeeds but reports more total rows than the supplied
        // capacity, it only wrote the newest rows. It is not a complete history.
        assert_eq!(
            history_buffer_decision(2, 2, 5, MAX_HISTORY_ENTRIES),
            Ok(HistoryBufferDecision::Retry {
                required_capacity: 5,
            })
        );
    }

    #[test]
    fn adequate_history_buffer_uses_the_reported_initialized_count() {
        assert_eq!(
            history_buffer_decision(8, 5, 5, MAX_HISTORY_ENTRIES),
            Ok(HistoryBufferDecision::Complete { initialized_len: 5 })
        );
    }

    #[test]
    fn shrinking_history_count_is_incomplete() {
        assert_eq!(
            history_buffer_decision(5, 5, 4, MAX_HISTORY_ENTRIES),
            Err(HistoryCountError::CountChanged {
                expected: 5,
                returned: 4,
            })
        );
    }

    #[test]
    fn chronological_normalization_reverses_once_without_timestamp_sorting() {
        let newest_first = vec![(0_u32, 30_u64), (1, 10), (2, 20)];
        assert_eq!(
            normalize_newest_first(newest_first),
            vec![(2, 20), (1, 10), (0, 30)]
        );
    }

    #[test]
    fn pressure_mask_distinguishes_missing_zero_and_out_of_range() {
        assert_eq!(pressure_validity(0, 0), PressureValidity::NotReported);
        assert_eq!(
            pressure_validity(PEN_MASK_PRESSURE, 0),
            PressureValidity::Valid
        );
        assert_eq!(
            pressure_validity(PEN_MASK_PRESSURE, 1025),
            PressureValidity::OutOfRange
        );
    }

    #[test]
    fn missing_pressure_mask_is_visible_and_excluded_from_valid_pen_counts() {
        // SAFETY: POINTER_PEN_INFO is a scalar-only native value; zeroed input
        // is a valid synthetic fixture for the pure ownership/validation mapper.
        let mut native: POINTER_PEN_INFO = unsafe { std::mem::zeroed() };
        native.pointerInfo.pointerType = PT_PEN;
        native.pointerInfo.pointerId = 7;
        native.pressure = 777;
        let sample = own_sample(native, 7, 0, 0).unwrap();
        assert_eq!(sample.pressure_validity, PressureValidity::NotReported);
        assert!(
            sample
                .validation_issues
                .contains(&SampleValidationIssue::PressureMaskMissing)
        );

        let mut state = ProbeState::default();
        state.record(ProbeRecord::DirectPenHistory(DirectPenHistoryBatch {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence: 1,
            message_id_raw: WM_POINTERUPDATE,
            message_hwnd_raw_session_scoped: 0x2222,
            message_time_ms_raw: Some(10),
            message_kind: PointerMessageKind::Update,
            pointer_id_requested: 7,
            hook_observed_elapsed_ns: 1,
            hook_qpc_count_raw: Some(100),
            hook_qpc_issue: None,
            qpc_frequency_hz: Some(10_000_000),
            native_history_count: 1,
            samples: vec![sample],
        }));
        let summary = state.summary();
        assert_eq!(summary.valid_direct_pen_samples, 0);
        assert_eq!(summary.invalid_direct_pen_samples, 1);
        assert_eq!(summary.validation_anomaly_samples, 1);
        assert_eq!(summary.pressure_mask_missing_samples, 1);
    }

    #[test]
    fn per_batch_native_history_limit_is_enforced() {
        let issue = ensure_native_history_fits(MAX_HISTORY_ENTRIES + 1, 131_072).unwrap_err();
        assert_eq!(
            issue,
            CaptureIssue::HistoryTooLarge {
                reported: MAX_HISTORY_ENTRIES + 1,
                maximum: MAX_HISTORY_ENTRIES,
            }
        );

        let mut state = ProbeState::default();
        state.record_with_limits(
            ProbeRecord::MessageIssue {
                source: CaptureSource::DirectWmPointerPenHistory,
                message_sequence: 1,
                message_id_raw: WM_POINTERUPDATE,
                message_hwnd_raw_session_scoped: Some(0x2222),
                message_wparam_raw: Some(7),
                message_lparam_raw: Some(0),
                message_time_ms_raw: Some(1),
                message_kind: Some(PointerMessageKind::Update),
                pointer_id: Some(7),
                hook_observed_elapsed_ns: 1,
                issue,
            },
            8,
            131_072,
        );
        let summary = state.summary();
        assert_eq!(summary.storage_limit, Some(StorageLimit::NativeHistory));
        assert_eq!(summary.incomplete_batches, 1);
        assert_eq!(
            summary.samples_not_retained,
            u64::from(MAX_HISTORY_ENTRIES + 1)
        );
        assert_eq!(summary.latest_incomplete_issue, Some(issue));
        assert!(!state.can_capture());
    }

    #[test]
    fn record_cap_stops_accepting_records_and_keeps_incomplete_state() {
        let mut state = ProbeState::default();
        state.record_with_limits(api_error_record(1), 2, 8);
        state.record_with_limits(api_error_record(2), 2, 8);

        let full_summary = state.summary();
        assert_eq!(state.records.len(), 2);
        assert_eq!(full_summary.records_retained, 2);
        assert_eq!(full_summary.storage_limit, Some(StorageLimit::Records));
        assert!(!state.can_capture());

        state.record_with_limits(api_error_record(3), 2, 8);
        assert_eq!(state.records.len(), 2);
        assert_eq!(state.summary(), full_summary);
    }

    #[test]
    fn public_event_records_obey_the_shared_record_cap() {
        let mut state = ProbeState::default();
        state.record_with_limits(public_touch_record(1), 1, 8);
        state.record_with_limits(public_touch_record(2), 1, 8);

        let summary = state.summary();
        assert_eq!(state.records.len(), 1);
        assert_eq!(summary.public_events, 1);
        assert_eq!(summary.public_touch_events, 1);
        assert_eq!(summary.records_not_retained, 0);
        assert_eq!(summary.storage_limit, Some(StorageLimit::Records));
        assert!(!state.can_capture());
    }

    #[test]
    fn session_output_failure_marks_capture_incomplete_and_stops_input() {
        let mut state = ProbeState::default();
        state.mark_session_output_failed(SessionOutputStage::Write);
        assert!(!state.can_capture());
        assert_eq!(
            state.summary().storage_limit,
            Some(StorageLimit::SessionOutput)
        );
        assert_eq!(
            state.summary().latest_startup_issue,
            Some(CaptureIssue::SessionOutputFailed {
                stage: SessionOutputStage::Write,
            })
        );
    }

    #[test]
    fn record_cap_rejection_does_not_claim_sample_capacity_was_exhausted() {
        let mut state = ProbeState::default();
        state.record_with_limits(
            ProbeRecord::StartupIssue(CaptureIssue::QpcFrequencyUnavailable { win32_error: 0 }),
            2,
            8,
        );
        state.record_with_limits(direct_batch(2, 2), 1, 8);

        let summary = state.summary();
        assert_eq!(state.records.len(), 1);
        assert_eq!(summary.samples, 0);
        assert_eq!(summary.records_not_retained, 1);
        assert_eq!(summary.batches_not_retained, 1);
        assert_eq!(summary.samples_not_retained, 2);
        assert_eq!(summary.storage_limit, Some(StorageLimit::Records));
        assert_eq!(
            summary.latest_incomplete_issue,
            Some(CaptureIssue::RetainedRecordCapacityExceeded {
                reported_samples: 2,
                remaining_records: 0,
            })
        );
    }

    #[test]
    fn record_reservation_failure_marks_session_incomplete_and_counts_dropped_batch() {
        let mut state = ProbeState::default();
        let record = direct_batch(3, 1);
        let issue = CaptureIssue::RecordAllocationFailed {
            requested_records: 1,
        };
        state.account_record_allocation_failure(&record, issue);

        let summary = state.summary();
        assert!(state.records.is_empty());
        assert_eq!(summary.records_not_retained, 1);
        assert_eq!(summary.batches_not_retained, 1);
        assert_eq!(summary.samples_not_retained, 3);
        assert_eq!(summary.incomplete_batches, 1);
        assert_eq!(summary.storage_limit, Some(StorageLimit::Allocation));
        assert_eq!(summary.latest_incomplete_issue, Some(issue));
        assert!(!state.can_capture());
    }

    #[test]
    fn sample_vector_allocation_issue_preserves_native_count() {
        let mut state = ProbeState::default();
        state.record_with_limits(
            ProbeRecord::MessageIssue {
                source: CaptureSource::DirectWmPointerPenHistory,
                message_sequence: 9,
                message_id_raw: WM_POINTERUPDATE,
                message_hwnd_raw_session_scoped: Some(0x2222),
                message_wparam_raw: Some(7),
                message_lparam_raw: Some(0),
                message_time_ms_raw: Some(1),
                message_kind: Some(PointerMessageKind::Update),
                pointer_id: Some(7),
                hook_observed_elapsed_ns: 9,
                issue: CaptureIssue::AllocationFailed { capacity: 3 },
            },
            8,
            8,
        );

        let summary = state.summary();
        assert_eq!(summary.incomplete_batches, 1);
        assert_eq!(summary.batches_not_retained, 1);
        assert_eq!(summary.samples_not_retained, 3);
        assert_eq!(
            summary.latest_incomplete_issue,
            Some(CaptureIssue::AllocationFailed { capacity: 3 })
        );
        assert_eq!(summary.storage_limit, None);
    }

    #[test]
    fn sample_cap_rejects_a_whole_batch_and_counts_omitted_samples() {
        let mut state = ProbeState::default();
        state.record_with_limits(direct_batch(2, 1), 4, 3);
        state.record_with_limits(direct_batch(2, 2), 4, 3);

        let summary = state.summary();
        assert_eq!(state.records.len(), 1);
        assert_eq!(summary.samples, 2);
        assert_eq!(summary.records_not_retained, 1);
        assert_eq!(summary.batches_not_retained, 1);
        assert_eq!(summary.samples_not_retained, 2);
        assert_eq!(summary.incomplete_batches, 1);
        assert_eq!(
            summary.latest_incomplete_issue,
            Some(CaptureIssue::RetainedSampleCapacityExceeded {
                reported: 2,
                remaining: 1,
            })
        );
        assert_eq!(summary.storage_limit, Some(StorageLimit::Samples));
        assert!(!state.can_capture());
    }

    #[test]
    fn wintab_packets_share_the_native_sample_cap_without_becoming_direct_samples() {
        let mut state = ProbeState::default();
        state.record_with_limits(wintab_batch(2, 1), 4, 3);
        state.record_with_limits(wintab_batch(2, 2), 4, 3);

        let summary = state.summary();
        assert_eq!(summary.samples, 0);
        assert_eq!(summary.wintab_packets, 2);
        assert_eq!(summary.samples_not_retained, 2);
        assert_eq!(summary.batches_not_retained, 1);
        assert_eq!(summary.storage_limit, Some(StorageLimit::Samples));
        assert_eq!(state.records.len(), 1);
        assert!(!state.can_capture());
    }

    #[test]
    fn wintab_capacity_issue_keeps_source_and_unretained_packet_count() {
        let mut state = ProbeState::default();
        state.set_capture_mode(super::CaptureMode::Wintab);
        state.record_with_limits(
            ProbeRecord::WintabIssue {
                source: CaptureSource::WintabPacket,
                message_sequence: 12,
                message_id_raw: 0x7ff0,
                message_hwnd_raw_session_scoped: Some(0x2222),
                message_wparam_raw: None,
                message_lparam_raw: None,
                message_time_ms_raw: None,
                app_observed_elapsed_ns: None,
                issue: WintabIssue::RetainedSampleCapacityExceeded {
                    reported_packets: 5,
                    remaining: 3,
                },
            },
            4,
            3,
        );

        let summary = state.summary();
        assert_eq!(summary.wintab_issues, 1);
        assert_eq!(summary.samples_not_retained, 5);
        assert_eq!(summary.incomplete_batches, 1);
        assert_eq!(summary.storage_limit, Some(StorageLimit::Samples));
        assert_eq!(summary.wintab_status, WintabStatus::Partial);
        assert_eq!(
            summary.latest_wintab_issue,
            Some(WintabIssue::RetainedSampleCapacityExceeded {
                reported_packets: 5,
                remaining: 3,
            })
        );
        assert!(!state.can_capture());
    }

    #[test]
    fn wintab_overlap_issue_preserves_opaque_context_and_status_flags() {
        let mut state = ProbeState::default();
        state.set_capture_mode(super::CaptureMode::Wintab);
        let issue = WintabIssue::ContextOverlapChanged {
            related_context_raw_session_scoped: 0x7788,
            context_status_raw: 0x0002,
        };
        state.record(ProbeRecord::WintabIssue {
            source: CaptureSource::WintabPacket,
            message_sequence: 14,
            message_id_raw: 0x7ff4,
            message_hwnd_raw_session_scoped: Some(0x2222),
            message_wparam_raw: None,
            message_lparam_raw: None,
            message_time_ms_raw: None,
            app_observed_elapsed_ns: None,
            issue,
        });

        let summary = state.summary();
        assert_eq!(summary.wintab_issues, 1);
        assert_eq!(summary.incomplete_batches, 1);
        assert_eq!(summary.wintab_status, WintabStatus::Partial);
        assert_eq!(summary.latest_wintab_issue, Some(issue));
    }

    #[test]
    fn reduced_wintab_queue_capacity_is_not_reported_as_sample_loss() {
        let mut state = ProbeState::default();
        state.set_capture_mode(super::CaptureMode::Wintab);
        let issue = WintabIssue::QueueCapacityReduced {
            requested: 4096,
            actual: 128,
        };
        state.set_wintab_configuration(
            WintabStatus::Partial,
            Some(WintabPacketTimeMode::AbsoluteSystemTime),
            Some(0x5f7),
            Some(0),
            Some(128),
        );
        state.record(ProbeRecord::WintabIssue {
            source: CaptureSource::WintabPacket,
            message_sequence: 0,
            message_id_raw: 0,
            message_hwnd_raw_session_scoped: None,
            message_wparam_raw: None,
            message_lparam_raw: None,
            message_time_ms_raw: None,
            app_observed_elapsed_ns: None,
            issue,
        });

        let summary = state.summary();
        assert_eq!(summary.wintab_status, WintabStatus::Partial);
        assert_eq!(summary.wintab_queue_capacity_raw, Some(128));
        assert_eq!(summary.samples_not_retained, 0);
        assert_eq!(summary.latest_wintab_issue, Some(issue));
    }

    #[test]
    fn native_history_larger_than_remaining_capacity_marks_incomplete() {
        let mut state = ProbeState::default();
        state.record_with_limits(
            ProbeRecord::MessageIssue {
                source: CaptureSource::DirectWmPointerPenHistory,
                message_sequence: 3,
                message_id_raw: WM_POINTERUPDATE,
                message_hwnd_raw_session_scoped: Some(0x2222),
                message_wparam_raw: Some(7),
                message_lparam_raw: Some(0),
                message_time_ms_raw: Some(3),
                message_kind: Some(PointerMessageKind::Update),
                pointer_id: Some(7),
                hook_observed_elapsed_ns: 3,
                issue: CaptureIssue::RetainedSampleCapacityExceeded {
                    reported: 5,
                    remaining: 3,
                },
            },
            4,
            3,
        );

        let summary = state.summary();
        assert_eq!(summary.records_retained, 1);
        assert_eq!(summary.batches_not_retained, 1);
        assert_eq!(summary.samples_not_retained, 5);
        assert_eq!(summary.storage_limit, Some(StorageLimit::Samples));
        assert_eq!(summary.incomplete_batches, 1);
        assert_eq!(
            summary.latest_incomplete_issue,
            Some(CaptureIssue::RetainedSampleCapacityExceeded {
                reported: 5,
                remaining: 3,
            })
        );
        assert!(!state.can_capture());
    }

    #[test]
    fn message_and_sample_mapping_preserves_opaque_session_handles() {
        // SAFETY: MSG and POINTER_PEN_INFO contain only integer, point, and handle
        // fields here; their zeroed representation is valid and no pointer is followed.
        let mut message: MSG = unsafe { std::mem::zeroed() };
        message.message = WM_POINTERUPDATE;
        message.hwnd = 0x2222;
        message.wParam = 7;
        let metadata = hook_message_metadata(&message);
        assert_eq!(metadata.message_id_raw, WM_POINTERUPDATE);
        assert_eq!(metadata.message_hwnd_raw_session_scoped, 0x2222);
        assert_eq!(metadata.pointer_id, 7);

        let mut native: POINTER_PEN_INFO = unsafe { std::mem::zeroed() };
        native.pointerInfo.pointerType = PT_PEN;
        native.pointerInfo.pointerId = 7;
        native.pointerInfo.sourceDevice = 0x1234;
        native.pointerInfo.hwndTarget = 0x5678;
        let sample = own_sample(native, 7, 0, 0).unwrap();
        assert_eq!(sample.source_device_handle_raw_session_scoped, 0x1234);
        assert_eq!(sample.target_hwnd_raw_session_scoped, 0x5678);
    }

    #[test]
    fn public_event_association_requires_same_dispatch_window_and_pointer() {
        let mut state = ProbeState::default();
        state.set_public_pointer_type_api(Some(fake_get_pointer_type));
        let metadata = HookMessageMetadata {
            message_id_raw: WM_POINTERUPDATE,
            message_hwnd_raw_session_scoped: 0x2222,
            wparam_raw: 7,
            lparam_raw: 0,
            message_time_ms_raw: None,
            pointer_id: 7,
        };
        state.begin_native_dispatch(41, Some(metadata));

        let matching = state.public_touch_native_metadata(Some(0x2222), 7);
        assert_eq!(
            matching.message_association,
            Some(PublicMessageAssociation {
                message_sequence: 41,
                message_id_raw: WM_POINTERUPDATE,
                message_hwnd_raw_session_scoped: 0x2222,
                pointer_id_raw: 7,
            })
        );
        assert_eq!(matching.native_pointer_type_raw, Some(PT_PEN));
        assert_eq!(
            matching.pen_classification,
            PublicPenClassification::ConfirmedPen
        );

        let additional_frame_event = state.public_touch_native_metadata(Some(0x2222), 7);
        assert_eq!(additional_frame_event.message_association, None);
        assert_eq!(
            additional_frame_event.pen_classification,
            PublicPenClassification::Unclassified(
                PublicUnclassifiedReason::AdditionalFrameEventUnjoined
            )
        );

        let wrong_window = state.public_touch_native_metadata(Some(0x3333), 7);
        assert_eq!(wrong_window.message_association, None);
        assert_eq!(
            wrong_window.pen_classification,
            PublicPenClassification::Unclassified(PublicUnclassifiedReason::NoMatchedNativeMessage)
        );
        let wrong_pointer = state.public_touch_native_metadata(Some(0x2222), 8);
        assert_eq!(wrong_pointer.message_association, None);
    }

    #[test]
    fn public_touch_is_not_classified_as_pen_without_native_pt_pen() {
        let mut state = ProbeState::default();
        state.set_public_pointer_type_api(Some(fake_get_pointer_type));
        let metadata = HookMessageMetadata {
            message_id_raw: WM_POINTERUPDATE,
            message_hwnd_raw_session_scoped: 0x2222,
            wparam_raw: 8,
            lparam_raw: 0,
            message_time_ms_raw: None,
            pointer_id: 8,
        };
        state.begin_native_dispatch(50, Some(metadata));

        let native = state.public_touch_native_metadata(Some(0x2222), 8);
        assert!(native.message_association.is_some());
        assert_eq!(native.native_pointer_type_raw, Some(PT_TOUCH));
        assert_eq!(
            native.pen_classification,
            PublicPenClassification::ConfirmedNonPen {
                pointer_type_raw: PT_TOUCH,
            }
        );
    }

    #[test]
    fn reentrant_public_event_association_stays_null_and_unclassified() {
        let mut state = ProbeState::default();
        state.set_public_pointer_type_api(Some(fake_get_pointer_type));
        let metadata = HookMessageMetadata {
            message_id_raw: WM_POINTERUPDATE,
            message_hwnd_raw_session_scoped: 0x2222,
            wparam_raw: 7,
            lparam_raw: 0,
            message_time_ms_raw: None,
            pointer_id: 7,
        };
        state.begin_native_dispatch(41, Some(metadata));
        state.enter_winit_callback();
        state.begin_native_dispatch(42, Some(metadata));

        let ambiguous = state.public_touch_native_metadata(Some(0x2222), 7);
        assert_eq!(ambiguous.message_association, None);
        assert_eq!(
            ambiguous.pen_classification,
            PublicPenClassification::Unclassified(
                PublicUnclassifiedReason::AmbiguousOrReentrantDispatch
            )
        );
        state.leave_winit_callback();

        let after_callback = state.public_touch_native_metadata(Some(0x2222), 7);
        assert_eq!(after_callback.message_association, None);
    }

    #[test]
    fn stale_dispatch_metadata_is_expired_after_public_callback() {
        let mut state = ProbeState::default();
        state.set_public_pointer_type_api(Some(fake_get_pointer_type));
        let metadata = HookMessageMetadata {
            message_id_raw: WM_POINTERUPDATE,
            message_hwnd_raw_session_scoped: 0x2222,
            wparam_raw: 7,
            lparam_raw: 0,
            message_time_ms_raw: None,
            pointer_id: 7,
        };
        state.begin_native_dispatch(60, Some(metadata));

        state.enter_winit_callback();
        let current_dispatch = state.public_touch_native_metadata(Some(0x2222), 7);
        assert!(current_dispatch.message_association.is_some());
        state.leave_winit_callback();

        // A later or buffered callback cannot reuse the last hook message even
        // when its HWND and touch ID happen to match exactly.
        state.enter_winit_callback();
        let stale = state.public_touch_native_metadata(Some(0x2222), 7);
        assert_eq!(stale.message_association, None);
        assert_eq!(
            stale.pen_classification,
            PublicPenClassification::Unclassified(PublicUnclassifiedReason::NoMatchedNativeMessage)
        );
        state.leave_winit_callback();
    }

    #[test]
    fn public_winit_touch_record_keeps_force_as_source_data_and_native_time_tilt_null() {
        let mut state = ProbeState::default();
        state.record(ProbeRecord::PublicWinitEvent(PublicWinitEventRecord {
            source: CaptureSource::PublicWinitWindowEvent,
            capability: PublicEventCapability::TouchPhasePositionForce,
            public_event_sequence: 1,
            app_observed_elapsed_ns: 2,
            window_hwnd_raw_session_scoped: Some(0x2222),
            message_association: None,
            data: PublicWinitEventData::Touch {
                winit_device_id: winit::event::DeviceId::dummy(),
                public_touch_id: 7,
                phase: winit::event::TouchPhase::Moved,
                x_physical_px: 1.0,
                y_physical_px: 2.0,
                public_winit_force: Some(winit::event::Force::Normalized(0.25)),
                native_pointer_type_raw: None,
                pointer_type_error_raw: None,
                pen_classification: PublicPenClassification::Unclassified(
                    PublicUnclassifiedReason::NoMatchedNativeMessage,
                ),
                native_timestamp_raw: None,
                tilt: None,
            },
        }));

        assert_eq!(state.summary().public_events, 1);
        assert_eq!(state.summary().public_touch_events, 1);
        match &state.records[0] {
            ProbeRecord::PublicWinitEvent(record) => {
                assert_eq!(record.message_association, None);
                assert!(matches!(
                    record.data,
                    PublicWinitEventData::Touch {
                        public_winit_force: Some(winit::event::Force::Normalized(0.25)),
                        native_timestamp_raw: None,
                        tilt: None,
                        ..
                    }
                ));
            }
            _ => panic!("public event source tag changed"),
        }
    }
}
