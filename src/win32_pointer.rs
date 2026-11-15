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
    time::Instant,
};

use windows_sys::Win32::{
    Foundation::{BOOL, GetLastError, HMODULE},
    System::{
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Performance::QueryPerformanceFrequency,
    },
    UI::{
        Input::Pointer::POINTER_PEN_INFO,
        WindowsAndMessaging::{
            MSG, PEN_MASK_PRESSURE, PEN_MASK_TILT_X, PEN_MASK_TILT_Y, POINTER_INPUT_TYPE, PT_PEN,
            WM_POINTERDOWN, WM_POINTERUP, WM_POINTERUPDATE,
        },
    },
};
use winit::{event_loop::EventLoopBuilder, platform::windows::EventLoopBuilderExtWindows};

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
    PressureOutOfRange { raw: u32 },
    UnexpectedTiltMask { raw_mask: u32 },
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
    pub message_kind: PointerMessageKind,
    pub pointer_id_requested: u32,
    /// App `Instant` elapsed time observed at hook entry; not mixed with native time.
    pub hook_observed_elapsed_ns: u128,
    /// QPC counts per second sampled once at probe startup.
    pub qpc_frequency_hz: Option<u64>,
    pub native_history_count: u32,
    /// Chronological order after one explicit reverse of the newest-first API array.
    pub samples: Vec<OwnedPointerSample>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProbeRecord {
    StartupIssue(CaptureIssue),
    DirectPenHistory(DirectPenHistoryBatch),
    IgnoredNonPenPointer {
        source: CaptureSource,
        message_sequence: u64,
        message_id_raw: u32,
        /// Opaque `MSG.hwnd` value scoped to this process/session only.
        message_hwnd_raw_session_scoped: isize,
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
        message_kind: Option<PointerMessageKind>,
        pointer_id: Option<u32>,
        hook_observed_elapsed_ns: u128,
        issue: CaptureIssue,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProbeSummary {
    pub pointer_api_available: bool,
    pub qpc_frequency_hz: Option<u64>,
    pub history_batches: u64,
    pub samples: u64,
    pub issues: u64,
    pub ignored_non_pen_pointers: u64,
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
    Multiple,
}

#[derive(Debug, Default)]
pub(crate) struct ProbeState {
    records: Vec<ProbeRecord>,
    summary: ProbeSummary,
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

    fn can_capture(&self) -> bool {
        self.summary.storage_limit.is_none()
    }

    fn remaining_sample_capacity(&self) -> u64 {
        MAX_RETAINED_SAMPLES.saturating_sub(self.summary.samples)
    }

    fn record(&mut self, record: ProbeRecord) {
        self.record_with_limits(record, MAX_RETAINED_RECORDS, MAX_RETAINED_SAMPLES);
    }

    fn record_with_limits(&mut self, record: ProbeRecord, max_records: usize, max_samples: u64) {
        if !self.can_capture() {
            return;
        }

        let incoming_samples = match &record {
            ProbeRecord::DirectPenHistory(batch) => batch.samples.len() as u64,
            _ => 0,
        };
        let record_limit_reached = self.records.len() >= max_records;
        let sample_limit_exceeded =
            incoming_samples > max_samples.saturating_sub(self.summary.samples);
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
        if record_limit_reached || sample_limit_exceeded {
            self.summary.records_not_retained = self.summary.records_not_retained.saturating_add(1);
            if incoming_samples > 0 {
                let remaining_records = max_records.saturating_sub(self.records.len()) as u64;
                let remaining_samples = max_samples.saturating_sub(self.summary.samples);
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
            let requested_records = u64::try_from(self.records.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
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
            ProbeRecord::DirectPenHistory(batch) => {
                self.summary.history_batches = self.summary.history_batches.saturating_add(1);
                self.summary.samples = self
                    .summary
                    .samples
                    .saturating_add(batch.samples.len() as u64);
            }
            ProbeRecord::IgnoredNonPenPointer { .. } => {
                self.summary.ignored_non_pen_pointers =
                    self.summary.ignored_non_pen_pointers.saturating_add(1);
            }
        }
        self.records.push(record);
        self.summary.records_retained = self.summary.records_retained.saturating_add(1);

        self.mark_storage_limit(
            self.records.len() >= max_records,
            self.summary.samples >= max_samples
                || matches!(
                    message_issue,
                    Some(
                        CaptureIssue::RetainedSampleCapacityExceeded { .. }
                            | CaptureIssue::RetentionCapacitiesExceeded { .. }
                    )
                ),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HookMessageMetadata {
    message_id_raw: u32,
    message_hwnd_raw_session_scoped: isize,
    pointer_id: u32,
}

fn hook_message_metadata(message: &MSG) -> HookMessageMetadata {
    HookMessageMetadata {
        message_id_raw: message.message,
        message_hwnd_raw_session_scoped: message.hwnd,
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

/// Install a synchronous Winit hook. Copy pointer history before returning
/// `false`, which allows Winit to dispatch the public window event normally.
pub(crate) fn install_message_hook(
    builder: &mut EventLoopBuilder<()>,
    state: Rc<RefCell<ProbeState>>,
) {
    let pointer_api = load_pointer_api();
    let pointer_api_issue = pointer_api.as_ref().err().copied();
    state
        .borrow_mut()
        .set_api_state(pointer_api.is_ok(), pointer_api_issue);
    if let Some(issue) = pointer_api_issue {
        state.borrow_mut().record(ProbeRecord::StartupIssue(issue));
    }
    let (qpc_frequency, qpc_frequency_issue) = match query_qpc_frequency() {
        Ok(frequency) => (Some(frequency), None),
        Err(issue) => (None, Some(issue)),
    };
    state
        .borrow_mut()
        .set_qpc_frequency(qpc_frequency, qpc_frequency_issue);
    if let Some(issue) = qpc_frequency_issue {
        state.borrow_mut().record(ProbeRecord::StartupIssue(issue));
    }

    let hook_origin = Instant::now();
    let mut message_sequence = 0u64;
    builder.with_msg_hook(move |message_pointer| {
        if !state.borrow().can_capture() {
            return false;
        }
        let remaining_samples = state.borrow().remaining_sample_capacity();
        let current_sequence = message_sequence;
        let Some(next_sequence) = message_sequence.checked_add(1) else {
            state.borrow_mut().record(ProbeRecord::StartupIssue(
                CaptureIssue::MessageSequenceExhausted,
            ));
            return false;
        };
        message_sequence = next_sequence;
        let hook_observed_elapsed_ns = hook_origin.elapsed().as_nanos();
        // SAFETY: Winit's Windows hook receives a pointer to its current, live MSG
        // after PeekMessageW and before DispatchMessageW/another message retrieval.
        // capture_message borrows it only for this callback and copies all fields.
        let record = unsafe {
            capture_message(
                message_pointer,
                current_sequence,
                hook_observed_elapsed_ns,
                pointer_api,
                qpc_frequency,
                remaining_samples,
            )
        };
        if let Some(record) = record {
            state.borrow_mut().record(record);
        }
        false
    });
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
) -> Option<ProbeRecord> {
    if message_pointer.is_null() {
        return Some(ProbeRecord::MessageIssue {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence,
            message_id_raw: 0,
            message_hwnd_raw_session_scoped: None,
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
        message_kind,
        pointer_id_requested: pointer_id,
        hook_observed_elapsed_ns,
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
    if pressure_validity == PressureValidity::OutOfRange {
        push_validation_issue(
            &mut validation_issues,
            SampleValidationIssue::PressureOutOfRange {
                raw: native.pressure,
            },
        )?;
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
        HistoryBufferDecision, HistoryCountError, MAX_HISTORY_ENTRIES, NativeApi,
        PointerAttribution, PointerMessageKind, PressureValidity, ProbeRecord, ProbeState,
        RawPoint, RawScreenPosition, StorageLimit, ensure_native_history_fits,
        history_buffer_decision, hook_message_metadata, normalize_newest_first, own_sample,
        pressure_validity,
    };
    use windows_sys::Win32::{
        UI::Input::Pointer::POINTER_PEN_INFO,
        UI::WindowsAndMessaging::{MSG, PEN_MASK_PRESSURE, PT_PEN, WM_POINTERUPDATE},
    };

    fn api_error_record(sequence: u64) -> ProbeRecord {
        ProbeRecord::MessageIssue {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence: sequence,
            message_id_raw: WM_POINTERUPDATE,
            message_hwnd_raw_session_scoped: Some(0x2222),
            message_kind: Some(PointerMessageKind::Update),
            pointer_id: Some(7),
            hook_observed_elapsed_ns: sequence as u128,
            issue: CaptureIssue::ApiCallFailed {
                api: NativeApi::GetPointerType,
                win32_error: 5,
            },
        }
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
            message_kind: PointerMessageKind::Update,
            pointer_id_requested: 7,
            hook_observed_elapsed_ns: sequence as u128,
            qpc_frequency_hz: Some(10_000_000),
            native_history_count: sample_count as u32,
            samples: vec![sample; sample_count],
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
    fn native_history_larger_than_remaining_capacity_marks_incomplete() {
        let mut state = ProbeState::default();
        state.record_with_limits(
            ProbeRecord::MessageIssue {
                source: CaptureSource::DirectWmPointerPenHistory,
                message_sequence: 3,
                message_id_raw: WM_POINTERUPDATE,
                message_hwnd_raw_session_scoped: Some(0x2222),
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
}
