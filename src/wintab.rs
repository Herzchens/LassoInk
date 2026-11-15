//! Explicit Wintab diagnostic mode. All Wintab ABI calls and native handles
//! remain localized here; no driver DLL or SDK binary is bundled.

use std::{
    ffi::{c_char, c_void},
    marker::PhantomData,
    mem::{self, MaybeUninit},
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Instant,
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_INVALID_WINDOW_HANDLE, FreeLibrary, GetLastError, HMODULE, HWND, LPARAM, LRESULT,
        WPARAM,
    },
    System::{
        LibraryLoader::{
            GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
            LoadLibraryExW,
        },
        SystemInformation::GetSystemDirectoryW,
    },
    UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass},
};

use crate::win32_pointer::{
    CaptureMode, CaptureSource, HookMessageMetadata, LifecycleEventKind, LifecycleEventRecord,
    ProbeRecord, ProbeState, WintabContextConfig, WintabControlNotification, WintabCoordinateSpace,
    WintabFunction, WintabIssue, WintabPacketBatch, WintabPacketOperation, WintabPacketSample,
    WintabPacketTimeMode, WintabStatus, wintab_packet_hook_may_drain,
};

const SYSTEM_DIRECTORY_CAPACITY: usize = 260;
const WINTAB_PATH_CAPACITY: usize = 280;
const WINTAB_DLL_NAME: &[u8] = b"Wintab32.dll";

const WTI_DEFCONTEXT: u32 = 3;
const CXO_SYSTEM: u32 = 0x0001;
const CXO_MESSAGES: u32 = 0x0004;
pub(crate) const WT_DEFBASE: u32 = 0x7ff0;
const CXS_DISABLED: u32 = 0x0001;
const CXS_OBSCURED: u32 = 0x0002;
const CXS_ONTOP: u32 = 0x0004;
const WINTAB_SUBCLASS_ID: usize = 0x4c49_4e4b;
const MAX_PENDING_CONTROL_MESSAGES: usize = 128;

const PK_CONTEXT: u32 = 0x0001;
const PK_STATUS: u32 = 0x0002;
const PK_TIME: u32 = 0x0004;
const PK_SERIAL_NUMBER: u32 = 0x0010;
const PK_CURSOR: u32 = 0x0020;
const PK_BUTTONS: u32 = 0x0040;
const PK_X: u32 = 0x0080;
const PK_Y: u32 = 0x0100;
const PK_NORMAL_PRESSURE: u32 = 0x0400;
const PK_PACKET_DATA: u32 = PK_CONTEXT
    | PK_STATUS
    | PK_TIME
    | PK_SERIAL_NUMBER
    | PK_CURSOR
    | PK_BUTTONS
    | PK_X
    | PK_Y
    | PK_NORMAL_PRESSURE;
const PK_MOVE_MASK: u32 = PK_X | PK_Y | PK_NORMAL_PRESSURE;

const TPS_QUEUE_ERR: u32 = 0x0002;
const DESIRED_QUEUE_CAPACITY: i32 = 4096;
const QUEUE_SIZE_ATTEMPTS: [i32; 13] = [4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1];
const PACKET_READ_CHUNK: u32 = 256;
const MAX_DRAIN_ROUNDS: u8 = 16;
const MAX_PACKETS_PER_MESSAGE: u32 = PACKET_READ_CHUNK * MAX_DRAIN_ROUNDS as u32;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct LogContextA {
    name: [c_char; 40],
    options: u32,
    status: u32,
    locks: u32,
    message_base: u32,
    device: u32,
    packet_rate: u32,
    packet_data: u32,
    packet_mode: u32,
    move_mask: u32,
    button_down_mask: u32,
    button_up_mask: u32,
    input_origin_x: i32,
    input_origin_y: i32,
    input_origin_z: i32,
    input_extent_x: i32,
    input_extent_y: i32,
    input_extent_z: i32,
    output_origin_x: i32,
    output_origin_y: i32,
    output_origin_z: i32,
    output_extent_x: i32,
    output_extent_y: i32,
    output_extent_z: i32,
    sensitivity_x: u32,
    sensitivity_y: u32,
    sensitivity_z: u32,
    system_mode: i32,
    system_origin_x: i32,
    system_origin_y: i32,
    system_extent_x: i32,
    system_extent_y: i32,
    system_sensitivity_x: u32,
    system_sensitivity_y: u32,
}

/// `PKTDEF.H` generates this C structure from the exact packet-data mask above.
/// Wintab HCTX is a DECLARE_HANDLE, so this field is pointer-sized in the ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct WintabPacketLayout {
    context: isize,
    status: u32,
    time: u32,
    serial_number: u32,
    cursor: u32,
    buttons: u32,
    x: i32,
    y: i32,
    normal_pressure: u32,
}

type WtInfoA = unsafe extern "system" fn(u32, u32, *mut c_void) -> u32;
type WtOpenA = unsafe extern "system" fn(isize, *mut LogContextA, i32) -> isize;
type WtClose = unsafe extern "system" fn(isize) -> i32;
type WtQueueSizeSet = unsafe extern "system" fn(isize, i32) -> i32;
type WtQueueSizeGet = unsafe extern "system" fn(isize) -> i32;
type WtQueuePacketsEx = unsafe extern "system" fn(isize, *mut u32, *mut u32) -> i32;
type WtPacketsGet = unsafe extern "system" fn(isize, i32, *mut WintabPacketLayout) -> i32;
type WtEnable = unsafe extern "system" fn(isize, i32) -> i32;

#[derive(Clone, Copy)]
struct WintabApi {
    info_a: WtInfoA,
    open_a: WtOpenA,
    close: WtClose,
    queue_size_set: WtQueueSizeSet,
    queue_size_get: WtQueueSizeGet,
    queue_packets_ex: WtQueuePacketsEx,
    packets_get: WtPacketsGet,
    enable: WtEnable,
}

#[derive(Clone, Copy)]
struct QueueRange {
    available: u32,
    issue: Option<WintabIssue>,
    zero_range_ambiguous: bool,
}

#[derive(Clone, Copy)]
struct WintabIssueProvenance {
    message_sequence: u64,
    message_id_raw: u32,
    message_hwnd_raw_session_scoped: Option<isize>,
    message_wparam_raw: Option<usize>,
    message_lparam_raw: Option<isize>,
    message_time_ms_raw: Option<u32>,
    app_observed_elapsed_ns: Option<u128>,
    status: WintabStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WintabQueueTrigger {
    Packet { notification_serial_raw: u32 },
    Proximity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextOverlapDisposition {
    ExpectedInitialOpen,
    Changed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ControlObserverDiagnostics {
    pub dropped_messages: u64,
    pub callback_panics: u64,
}

struct PendingControlQueue {
    entries: [Option<WintabControlNotification>; MAX_PENDING_CONTROL_MESSAGES],
    head: usize,
    len: usize,
    next_sequence: u64,
    overflow_total: u64,
    reported_overflow: u64,
    panic_total: u64,
    reported_panics: u64,
}

impl Default for PendingControlQueue {
    fn default() -> Self {
        Self {
            entries: [None; MAX_PENDING_CONTROL_MESSAGES],
            head: 0,
            len: 0,
            next_sequence: 0,
            overflow_total: 0,
            reported_overflow: 0,
            panic_total: 0,
            reported_panics: 0,
        }
    }
}

struct ControlObserverState {
    message_base: AtomicU32,
    control_pending: Arc<AtomicBool>,
    app_clock_origin: Instant,
    pending: Mutex<PendingControlQueue>,
}

impl ControlObserverState {
    fn observe(&self, hwnd: HWND, message_id_raw: u32, wparam_raw: WPARAM, lparam_raw: LPARAM) {
        if !is_wintab_control_message(self.message_base.load(Ordering::Acquire), message_id_raw) {
            return;
        }
        // Stop the queued hook before this native callback returns; state
        // changes and any driver operation are deferred to a Winit callback.
        self.control_pending.store(true, Ordering::Release);

        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let observer_sequence = pending.next_sequence;
        pending.next_sequence = pending.next_sequence.saturating_add(1);
        if pending.len == MAX_PENDING_CONTROL_MESSAGES {
            pending.overflow_total = pending.overflow_total.saturating_add(1);
            return;
        }

        let index = (pending.head + pending.len) % MAX_PENDING_CONTROL_MESSAGES;
        pending.entries[index] = Some(WintabControlNotification {
            source: CaptureSource::WintabControlNotification,
            observer_sequence,
            message_id_raw,
            message_hwnd_raw_session_scoped: hwnd,
            wparam_raw,
            lparam_raw,
            app_observed_elapsed_ns: self.app_clock_origin.elapsed().as_nanos(),
        });
        pending.len += 1;
    }

    fn pop(&self) -> Option<WintabControlNotification> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending.len == 0 {
            return None;
        }
        let index = pending.head;
        pending.head = (pending.head + 1) % MAX_PENDING_CONTROL_MESSAGES;
        pending.len -= 1;
        pending.entries[index].take()
    }

    fn note_callback_panic(&self) {
        self.control_pending.store(true, Ordering::Release);
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.panic_total = pending.panic_total.saturating_add(1);
    }

    fn take_diagnostics(&self) -> ControlObserverDiagnostics {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let diagnostics = ControlObserverDiagnostics {
            dropped_messages: pending
                .overflow_total
                .saturating_sub(pending.reported_overflow),
            callback_panics: pending.panic_total.saturating_sub(pending.reported_panics),
        };
        pending.reported_overflow = pending.overflow_total;
        pending.reported_panics = pending.panic_total;
        diagnostics
    }

    fn clear_pending_if_idle(&self, allowed: bool) {
        if !allowed {
            return;
        }
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending.len == 0
            && pending.overflow_total == pending.reported_overflow
            && pending.panic_total == pending.reported_panics
        {
            self.control_pending.store(false, Ordering::Release);
        }
    }
}

/// Per-window route for Wintab lifecycle messages. The queued Winit hook never
/// records these control IDs; the subclass owns them for both sent and posted
/// delivery, preventing hook/subclass double-counting.
pub(crate) struct WintabControlObserver {
    hwnd: HWND,
    state: Option<Box<ControlObserverState>>,
    installed: bool,
    // SetWindowSubclass install/remove and reference-data ownership are bound
    // to the HWND's creating UI thread. Keep the safe wrapper !Send + !Sync.
    _ui_thread_only: PhantomData<Rc<()>>,
}

impl WintabControlObserver {
    pub(crate) fn install(
        hwnd: HWND,
        requested_message_base: u32,
        app_clock_origin: Instant,
        control_pending: Arc<AtomicBool>,
    ) -> Result<Self, u32> {
        if hwnd == 0 {
            return Err(ERROR_INVALID_WINDOW_HANDLE);
        }

        let mut state = Box::new(ControlObserverState {
            message_base: AtomicU32::new(requested_message_base),
            control_pending,
            app_clock_origin,
            pending: Mutex::new(PendingControlQueue::default()),
        });
        let reference_data = (&mut *state as *mut ControlObserverState) as usize;
        // SAFETY: HWND is the live Winit window on this UI thread; the boxed
        // reference data remains stable until RemoveWindowSubclass succeeds.
        if unsafe {
            SetWindowSubclass(
                hwnd,
                Some(wintab_control_subclass_proc),
                WINTAB_SUBCLASS_ID,
                reference_data,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }

        Ok(Self {
            hwnd,
            state: Some(state),
            installed: true,
            _ui_thread_only: PhantomData,
        })
    }

    pub(crate) fn set_message_base(&self, message_base: u32) {
        if let Some(state) = self.state.as_ref() {
            state.message_base.store(message_base, Ordering::Release);
        }
    }

    pub(crate) fn hwnd_raw(&self) -> isize {
        self.hwnd
    }

    pub(crate) fn pop_pending(&self) -> Option<WintabControlNotification> {
        self.state.as_ref()?.pop()
    }

    pub(crate) fn take_diagnostics(&self) -> ControlObserverDiagnostics {
        self.state
            .as_ref()
            .map(|state| state.take_diagnostics())
            .unwrap_or_default()
    }

    pub(crate) fn clear_pending_if_idle(&self, allowed: bool) {
        if let Some(state) = self.state.as_ref() {
            state.clear_pending_if_idle(allowed);
        }
    }

    pub(crate) fn remove(&mut self) -> Result<(), u32> {
        if !self.installed {
            return Ok(());
        }
        // SAFETY: this is the same HWND/procedure/ID tuple used for installation.
        if unsafe {
            RemoveWindowSubclass(
                self.hwnd,
                Some(wintab_control_subclass_proc),
                WINTAB_SUBCLASS_ID,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        self.installed = false;
        Ok(())
    }
}

impl Drop for WintabControlObserver {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // SAFETY: the observer owns a stable box until the subclass is removed.
        let removed = unsafe {
            RemoveWindowSubclass(
                self.hwnd,
                Some(wintab_control_subclass_proc),
                WINTAB_SUBCLASS_ID,
            )
        } != 0;
        if removed {
            self.installed = false;
        } else if let Some(state) = self.state.take() {
            // Keep callback data alive if the window still has the subclass.
            let _ = Box::leak(state);
        }
    }
}

fn is_wintab_control_message(message_base: u32, message_id_raw: u32) -> bool {
    matches!(
        message_id_raw,
        id if id == message_base + 1
            || id == message_base + 2
            || id == message_base + 3
            || id == message_base + 4
            || id == message_base + 6
    )
}

/// # Safety
/// `reference_data` must point to the observer box installed for this HWND and
/// remain live until the subclass has been removed.
unsafe extern "system" fn wintab_control_subclass_proc(
    hwnd: HWND,
    message_id_raw: u32,
    wparam_raw: WPARAM,
    lparam_raw: LPARAM,
    _subclass_id: usize,
    reference_data: usize,
) -> LRESULT {
    if reference_data != 0 {
        let state_pointer = reference_data as *const ControlObserverState;
        let callback_result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: SetWindowSubclass receives the stable boxed observer pointer;
            // WintabControlObserver keeps it alive until subclass removal.
            let state = unsafe { &*state_pointer };
            state.observe(hwnd, message_id_raw, wparam_raw, lparam_raw);
        }));
        if callback_result.is_err() {
            // SAFETY: the same lifetime guarantee applies while the callback runs.
            unsafe { &*state_pointer }.note_callback_panic();
        }
    }

    // SAFETY: DefSubclassProc continues the original Winit window procedure.
    unsafe { DefSubclassProc(hwnd, message_id_raw, wparam_raw, lparam_raw) }
}

pub(crate) struct WintabCapture {
    module: HMODULE,
    api: Option<WintabApi>,
    context: Option<isize>,
    owner_hwnd_raw_session_scoped: Option<isize>,
    context_config: Option<WintabContextConfig>,
    context_configuration_stale: bool,
    initial_context_overlap_pending: bool,
    packet_notification_seen: bool,
    stop_requested: bool,
    stop_close_attempted: bool,
    status: WintabStatus,
    latest_issue: Option<WintabIssue>,
    configured_device_raw: Option<u32>,
    configured_packet_data_raw: Option<u32>,
    configured_packet_mode_raw: Option<u32>,
    packet_time_mode: Option<WintabPacketTimeMode>,
    queue_capacity_raw: Option<i32>,
    message_base_raw: Option<u32>,
    last_packet_serial_raw: Option<u32>,
    app_clock_origin: Option<Instant>,
}

impl WintabCapture {
    pub(crate) fn new(
        mode: CaptureMode,
        app_clock_origin: Instant,
        state: &mut ProbeState,
    ) -> Self {
        if mode != CaptureMode::Wintab {
            let capture = Self::empty(WintabStatus::NotSelected);
            capture.update_probe_configuration(state);
            return capture;
        }

        match load_wintab_api() {
            Ok((module, api)) => {
                let capture = Self {
                    module,
                    api: Some(api),
                    context: None,
                    owner_hwnd_raw_session_scoped: None,
                    context_config: None,
                    context_configuration_stale: false,
                    initial_context_overlap_pending: false,
                    packet_notification_seen: false,
                    stop_requested: false,
                    stop_close_attempted: false,
                    status: WintabStatus::Loading,
                    latest_issue: None,
                    configured_device_raw: None,
                    configured_packet_data_raw: None,
                    configured_packet_mode_raw: None,
                    packet_time_mode: None,
                    queue_capacity_raw: None,
                    message_base_raw: None,
                    last_packet_serial_raw: None,
                    app_clock_origin: Some(app_clock_origin),
                };
                capture.update_probe_configuration(state);
                capture
            }
            Err(issue) => Self::unavailable_from_load_error(issue, app_clock_origin, state),
        }
    }

    fn unavailable_from_load_error(
        issue: WintabIssue,
        app_clock_origin: Instant,
        state: &mut ProbeState,
    ) -> Self {
        let mut capture = Self::empty(WintabStatus::Unavailable);
        capture.app_clock_origin = Some(app_clock_origin);
        capture.latest_issue = Some(issue);
        capture.update_probe_configuration(state);
        capture.record_issue(state, issue, 0, 0, None, WintabStatus::Unavailable);
        capture
    }

    fn empty(status: WintabStatus) -> Self {
        Self {
            module: 0,
            api: None,
            context: None,
            owner_hwnd_raw_session_scoped: None,
            context_config: None,
            context_configuration_stale: false,
            initial_context_overlap_pending: false,
            packet_notification_seen: false,
            stop_requested: false,
            stop_close_attempted: false,
            status,
            latest_issue: None,
            configured_device_raw: None,
            configured_packet_data_raw: None,
            configured_packet_mode_raw: None,
            packet_time_mode: None,
            queue_capacity_raw: None,
            message_base_raw: None,
            last_packet_serial_raw: None,
            app_clock_origin: None,
        }
    }

    pub(crate) fn open_context(&mut self, hwnd: isize, state: &mut ProbeState) {
        if !state.can_capture() {
            self.request_close_after_storage_limit(state);
            return;
        }
        if self.status == WintabStatus::NotSelected || self.api.is_none() {
            return;
        }
        if hwnd == 0 {
            self.record_issue(
                state,
                WintabIssue::InvalidWindowHandle,
                0,
                0,
                None,
                WintabStatus::Unavailable,
            );
            return;
        }

        let api = self.api.expect("checked above");
        // SAFETY: Wintab is loaded and WTInfoA accepts a null output pointer to
        // report the exact size required for the requested default context.
        let required_bytes = unsafe { (api.info_a)(WTI_DEFCONTEXT, 0, std::ptr::null_mut()) };
        let expected_bytes = std::mem::size_of::<LogContextA>() as u32;
        if required_bytes != expected_bytes {
            self.record_issue(
                state,
                WintabIssue::ContextInfoUnavailable {
                    returned_bytes: required_bytes,
                },
                0,
                0,
                Some(hwnd),
                WintabStatus::Unavailable,
            );
            return;
        }

        // SAFETY: LOGCONTEXTA contains only fixed-width scalar and character
        // fields; every field's all-zero representation is valid before WTInfoA.
        let mut context = unsafe { mem::zeroed::<LogContextA>() };
        // SAFETY: `context` is a writable buffer exactly the size WTInfoA reported.
        let returned_bytes = unsafe {
            (api.info_a)(
                WTI_DEFCONTEXT,
                0,
                (&mut context as *mut LogContextA).cast::<c_void>(),
            )
        };
        if returned_bytes != expected_bytes {
            self.record_issue(
                state,
                WintabIssue::ContextInfoUnavailable { returned_bytes },
                0,
                0,
                Some(hwnd),
                WintabStatus::Unavailable,
            );
            return;
        }

        context.name = wintab_context_name();
        context.options = (context.options | CXO_MESSAGES) & !CXO_SYSTEM;
        context.message_base = WT_DEFBASE;
        context.packet_data = PK_PACKET_DATA;
        context.packet_mode = 0;
        context.move_mask = PK_MOVE_MASK;

        // SAFETY: hwnd is the live HWND owned by Winit and `context` has the exact
        // LOGCONTEXTA layout/size verified above. The context is enabled explicitly.
        let context_handle = unsafe { (api.open_a)(hwnd, &mut context, 1) };
        if context_handle == 0 {
            self.record_issue(
                state,
                WintabIssue::ContextOpenFailed,
                0,
                0,
                Some(hwnd),
                WintabStatus::Unavailable,
            );
            return;
        }

        self.context = Some(context_handle);
        self.owner_hwnd_raw_session_scoped = Some(hwnd);
        self.message_base_raw = Some(context.message_base);
        // WTOpen places the new context at the top of the overlap order. Treat
        // one self-context WT_CTXOVERLAP before the first packet as that setup
        // notification; all later or foreign-context overlap changes stop capture.
        self.initial_context_overlap_pending = true;
        self.packet_notification_seen = false;
        self.stop_requested = false;
        self.stop_close_attempted = false;
        self.configured_device_raw = Some(context.device);
        self.configured_packet_data_raw = Some(context.packet_data);
        self.configured_packet_mode_raw = Some(context.packet_mode);
        self.context_config = Some(wintab_context_config(&context));
        self.context_configuration_stale = false;
        self.packet_time_mode = Some(packet_time_mode(context.packet_mode));

        if context.packet_data != PK_PACKET_DATA {
            self.record_issue(
                state,
                WintabIssue::ContextConfigurationMismatch {
                    expected_packet_data: PK_PACKET_DATA,
                    actual_packet_data: context.packet_data,
                },
                0,
                0,
                Some(hwnd),
                WintabStatus::Unavailable,
            );
            self.close_context_raw();
            return;
        }

        let mut failed_queue_size = DESIRED_QUEUE_CAPACITY;
        let selected_queue_size =
            first_supported_queue_size(&QUEUE_SIZE_ATTEMPTS, |requested_size| {
                failed_queue_size = requested_size;
                // SAFETY: context_handle is live and each requested queue size is a
                // positive bounded integer. Wintab requires a smaller retry after failure.
                (unsafe { (api.queue_size_set)(context_handle, requested_size) }) != 0
            });
        let Some(_selected_queue_size) = selected_queue_size else {
            self.record_issue(
                state,
                WintabIssue::QueueSizeSetFailed {
                    requested: failed_queue_size,
                },
                0,
                0,
                Some(hwnd),
                WintabStatus::Unavailable,
            );
            self.close_context_raw();
            return;
        };

        // SAFETY: context_handle is live after a successful WTQueueSizeSet.
        let actual_queue_size = unsafe { (api.queue_size_get)(context_handle) };
        if actual_queue_size <= 0 {
            self.record_issue(
                state,
                WintabIssue::QueueSizeUnavailable {
                    reported: actual_queue_size,
                },
                0,
                0,
                Some(hwnd),
                WintabStatus::Unavailable,
            );
            self.close_context_raw();
            return;
        }

        self.queue_capacity_raw = Some(actual_queue_size);
        if context.message_base != WT_DEFBASE {
            self.record_issue(
                state,
                WintabIssue::MessageBaseChanged {
                    requested: WT_DEFBASE,
                    actual: context.message_base,
                },
                0,
                0,
                Some(hwnd),
                WintabStatus::Partial,
            );
        }

        if actual_queue_size < DESIRED_QUEUE_CAPACITY {
            self.record_issue(
                state,
                WintabIssue::QueueCapacityReduced {
                    requested: DESIRED_QUEUE_CAPACITY,
                    actual: actual_queue_size,
                },
                0,
                0,
                Some(hwnd),
                WintabStatus::Partial,
            );
        } else if self.status == WintabStatus::Loading {
            self.status = WintabStatus::Available;
            self.update_probe_configuration(state);
        } else {
            self.update_probe_configuration(state);
        }
    }

    /// Apply a scalar control event drained from the per-window subclass at a
    /// Winit callback boundary. This code never runs inside the native proc.
    pub(crate) fn handle_control_notification(
        &mut self,
        notification: WintabControlNotification,
        state: &mut ProbeState,
    ) {
        state.record(ProbeRecord::WintabControlNotification(notification));
        let metadata = HookMessageMetadata {
            message_id_raw: notification.message_id_raw,
            message_hwnd_raw_session_scoped: notification.message_hwnd_raw_session_scoped,
            wparam_raw: notification.wparam_raw,
            lparam_raw: notification.lparam_raw,
            message_time_ms_raw: None,
            pointer_id: 0,
        };

        if Some(notification.message_hwnd_raw_session_scoped) == self.owner_hwnd_raw_session_scoped
            && let Some(message_base) = self.message_base_raw
        {
            let context_matches = self
                .context
                .is_some_and(|context| notification.wparam_raw as isize == context);
            if notification.message_id_raw == message_base + 2 && context_matches {
                self.context = None;
                self.context_configuration_stale = true;
                self.stop_requested = true;
                self.record_issue_with_raw(
                    state,
                    WintabIssue::ContextClosed,
                    WintabIssueProvenance {
                        message_sequence: 0,
                        message_id_raw: notification.message_id_raw,
                        message_hwnd_raw_session_scoped: Some(
                            notification.message_hwnd_raw_session_scoped,
                        ),
                        message_wparam_raw: Some(notification.wparam_raw),
                        message_lparam_raw: Some(notification.lparam_raw),
                        message_time_ms_raw: None,
                        app_observed_elapsed_ns: Some(notification.app_observed_elapsed_ns),
                        status: WintabStatus::Unavailable,
                    },
                );
            } else if notification.message_id_raw == message_base + 3 && context_matches {
                self.context_configuration_stale = true;
                self.stop_requested = true;
                self.set_partial_at(
                    WintabIssue::ContextConfigurationChanged,
                    0,
                    metadata,
                    Some(notification.app_observed_elapsed_ns),
                    state,
                );
            } else if notification.message_id_raw == message_base + 4 {
                if let Some(context) = self.context {
                    let related_context = notification.wparam_raw as isize;
                    let disposition = context_overlap_disposition(
                        self.initial_context_overlap_pending,
                        self.packet_notification_seen,
                        related_context,
                        context,
                        notification.lparam_raw as u32,
                    );
                    self.initial_context_overlap_pending = false;
                    if disposition == ContextOverlapDisposition::Changed {
                        self.context_configuration_stale = true;
                        self.stop_requested = true;
                        self.set_partial_at(
                            WintabIssue::ContextOverlapChanged {
                                related_context_raw_session_scoped: related_context,
                                context_status_raw: notification.lparam_raw as u32,
                            },
                            0,
                            metadata,
                            Some(notification.app_observed_elapsed_ns),
                            state,
                        );
                    }
                }
            } else if notification.message_id_raw == message_base + 6 {
                self.context_configuration_stale = true;
                self.stop_requested = true;
                self.record_issue_with_raw(
                    state,
                    WintabIssue::ContextInformationChanged,
                    WintabIssueProvenance {
                        message_sequence: 0,
                        message_id_raw: notification.message_id_raw,
                        message_hwnd_raw_session_scoped: Some(
                            notification.message_hwnd_raw_session_scoped,
                        ),
                        message_wparam_raw: Some(notification.wparam_raw),
                        message_lparam_raw: Some(notification.lparam_raw),
                        message_time_ms_raw: None,
                        app_observed_elapsed_ns: Some(notification.app_observed_elapsed_ns),
                        status: WintabStatus::Partial,
                    },
                );
            }
        }

        if !state.can_capture() {
            self.request_close_after_storage_limit(state);
        }
    }

    pub(crate) fn handle_message(
        &mut self,
        metadata: HookMessageMetadata,
        message_sequence: u64,
        app_observed_elapsed_ns: u128,
        control_pending: &AtomicBool,
        state: &mut ProbeState,
    ) {
        if !state.can_capture() {
            self.request_close_after_storage_limit(state);
            return;
        }
        if self.message_base_raw.is_some_and(|message_base| {
            is_wintab_control_message(message_base, metadata.message_id_raw)
        }) {
            // All Wintab lifecycle/control IDs belong to the subclass route so
            // sent and posted deliveries are observed exactly once.
            return;
        }
        let (Some(context), Some(message_base), Some(api)) =
            (self.context, self.message_base_raw, self.api)
        else {
            return;
        };
        if Some(metadata.message_hwnd_raw_session_scoped) != self.owner_hwnd_raw_session_scoped {
            return;
        }
        if !self.packet_capture_enabled() {
            return;
        }
        let Some(queue_trigger) = queue_trigger(metadata, message_base, context) else {
            return;
        };
        let notification_serial_raw = match queue_trigger {
            WintabQueueTrigger::Packet {
                notification_serial_raw,
            } => {
                self.packet_notification_seen = true;
                self.initial_context_overlap_pending = false;
                Some(notification_serial_raw)
            }
            WintabQueueTrigger::Proximity => None,
        };
        let lifecycle_kind = match queue_trigger {
            WintabQueueTrigger::Packet { .. } => LifecycleEventKind::WintabPacketNotification,
            WintabQueueTrigger::Proximity => {
                if (metadata.lparam_raw as u32 & 0xffff) != 0 {
                    LifecycleEventKind::WintabProximityEnter
                } else {
                    LifecycleEventKind::WintabProximityLeave
                }
            }
        };
        state.record(ProbeRecord::Lifecycle(LifecycleEventRecord {
            source: CaptureSource::WintabPacket,
            kind: lifecycle_kind,
            app_observed_elapsed_ns,
            message_id_raw: Some(metadata.message_id_raw),
            message_hwnd_raw_session_scoped: Some(metadata.message_hwnd_raw_session_scoped),
            wparam_raw: Some(metadata.wparam_raw),
            lparam_raw: Some(metadata.lparam_raw),
            native_message_time_ms_raw: metadata.message_time_ms_raw,
            pointer_id_raw: None,
            winit_device_id_debug: None,
            event_loop_wait_start_elapsed_ns: None,
            event_loop_requested_resume_elapsed_ns: None,
            event_loop_wake_lateness_ns: None,
            controlled_stall_duration_ns: None,
            issue_debug: None,
        }));
        if !state.can_capture() {
            self.request_close_after_storage_limit(state);
            return;
        }
        if !wintab_packet_hook_may_drain(control_pending) {
            return;
        }
        let initial_range_result = self.queue_range(context, api, notification_serial_raw);
        if !wintab_packet_hook_may_drain(control_pending) {
            self.note_control_transition_during_drain(
                WintabPacketOperation::QueueQuery,
                None,
                message_sequence,
                metadata,
                state,
            );
            if let Err(issue) = initial_range_result {
                self.set_partial(issue, message_sequence, metadata, state);
            }
            return;
        }
        let initial_range = match initial_range_result {
            Ok(Some(range)) => range,
            Ok(None) => return,
            Err(issue) => {
                self.set_partial(issue, message_sequence, metadata, state);
                return;
            }
        };
        if !state.can_capture() {
            self.request_close_after_storage_limit(state);
            return;
        }
        if initial_range.available == 0 {
            return;
        }

        let mut packet_issue = initial_range.issue;
        let mut secondary_issue = None;

        let remaining_samples = state.remaining_sample_capacity();
        let initially_queued = initial_range.available;
        if u64::from(initially_queued) > remaining_samples {
            self.set_partial(
                WintabIssue::RetainedSampleCapacityExceeded {
                    reported_packets: initially_queued,
                    remaining: remaining_samples,
                },
                message_sequence,
                metadata,
                state,
            );
            return;
        }

        let output_capacity = bounded_message_output_capacity(remaining_samples);
        let mut packets = Vec::new();
        if packets.try_reserve_exact(output_capacity as usize).is_err() {
            self.set_partial(
                WintabIssue::PacketAllocationFailed {
                    capacity: output_capacity,
                },
                message_sequence,
                metadata,
                state,
            );
            return;
        }

        let mut packet_buffer = Vec::<MaybeUninit<WintabPacketLayout>>::new();
        if packet_buffer
            .try_reserve_exact(PACKET_READ_CHUNK as usize)
            .is_err()
        {
            self.set_partial(
                WintabIssue::PacketAllocationFailed {
                    capacity: PACKET_READ_CHUNK,
                },
                message_sequence,
                metadata,
                state,
            );
            return;
        }
        packet_buffer.resize_with(PACKET_READ_CHUNK as usize, MaybeUninit::uninit);

        let mut drained_packets = 0u32;
        let mut drain_rounds = 0u8;
        let mut batch_control_transition_observed = false;
        let mut interrupted_by_control: Option<(WintabPacketOperation, Option<u32>)> = None;
        while drain_rounds < MAX_DRAIN_ROUNDS && drained_packets < output_capacity {
            if !wintab_packet_hook_may_drain(control_pending) {
                interrupted_by_control = Some((WintabPacketOperation::QueueQuery, None));
                break;
            }
            drain_rounds = drain_rounds.saturating_add(1);
            let current_range_result = self.queue_range(context, api, notification_serial_raw);
            if !wintab_packet_hook_may_drain(control_pending) {
                if let Err(issue) = current_range_result {
                    retain_issue(&mut packet_issue, &mut secondary_issue, issue);
                }
                interrupted_by_control = Some((WintabPacketOperation::QueueQuery, None));
                break;
            }
            let current_range = match current_range_result {
                Ok(Some(range)) => range,
                Ok(None) => break,
                Err(issue) => {
                    retain_issue(&mut packet_issue, &mut secondary_issue, issue);
                    break;
                }
            };
            if !state.can_capture() {
                self.request_close_after_storage_limit(state);
                return;
            }
            if current_range.available == 0 {
                break;
            }
            if let Some(issue) = current_range.issue {
                retain_issue(&mut packet_issue, &mut secondary_issue, issue);
            }

            let remaining_budget = output_capacity.saturating_sub(drained_packets);
            let request_count = current_range
                .available
                .min(remaining_budget)
                .min(PACKET_READ_CHUNK);
            if request_count == 0 {
                break;
            }
            if !wintab_packet_hook_may_drain(control_pending) {
                interrupted_by_control = Some((WintabPacketOperation::PacketRead, None));
                break;
            }

            // SAFETY: packet_buffer contains PACKET_READ_CHUNK aligned uninitialized
            // PACKET slots, and cMaxPkts does not exceed that allocated capacity.
            let returned = unsafe {
                (api.packets_get)(
                    context,
                    request_count as i32,
                    packet_buffer.as_mut_ptr().cast::<WintabPacketLayout>(),
                )
            };
            if !wintab_packet_hook_may_drain(control_pending) {
                let reported_packets = if returned >= 0 && returned as u32 <= request_count {
                    let count = returned as u32;
                    if count > 0 {
                        // The data is copied before returning from the hook, but
                        // the sent control ran reentrantly during this Wintab
                        // call. Preserve the raw rows and mark the whole batch
                        // uncertain; do not update the cross-call serial chain.
                        for slot in packet_buffer.iter().take(count as usize) {
                            // SAFETY: the successful bounded return count says
                            // these packet slots were initialized by WTPacketsGet.
                            let packet = unsafe { slot.assume_init() };
                            packets.push(wintab_packet_sample(packet));
                        }
                        drained_packets = drained_packets.saturating_add(count);
                        batch_control_transition_observed = true;
                    }
                    Some(count)
                } else {
                    if returned < 0 || returned as u32 > request_count {
                        retain_issue(
                            &mut packet_issue,
                            &mut secondary_issue,
                            WintabIssue::PacketCountInvalid {
                                reported: returned,
                                capacity: request_count,
                            },
                        );
                    }
                    None
                };
                interrupted_by_control =
                    Some((WintabPacketOperation::PacketRead, reported_packets));
                break;
            }
            if returned < 0 || returned as u32 > request_count {
                retain_issue(
                    &mut packet_issue,
                    &mut secondary_issue,
                    WintabIssue::PacketCountInvalid {
                        reported: returned,
                        capacity: request_count,
                    },
                );
                break;
            }
            if returned == 0 {
                if zero_range_probe_is_empty(current_range, returned) {
                    break;
                }
                retain_issue(
                    &mut packet_issue,
                    &mut secondary_issue,
                    WintabIssue::PacketReadFailed { reported: returned },
                );
                break;
            }

            for slot in packet_buffer.iter().take(returned as usize) {
                // SAFETY: WTPacketsGet reported this count and writes complete
                // fixed-layout packets for the configured PK_PACKET_DATA mask.
                let packet = unsafe { slot.assume_init() };
                let sample = wintab_packet_sample(packet);
                if packet.context != context {
                    retain_issue(
                        &mut packet_issue,
                        &mut secondary_issue,
                        WintabIssue::PacketContextMismatch {
                            expected_raw: context,
                            reported_raw: packet.context,
                        },
                    );
                }
                if packet.status & TPS_QUEUE_ERR != 0 {
                    retain_issue(
                        &mut packet_issue,
                        &mut secondary_issue,
                        WintabIssue::QueueOverflow {
                            status_raw: packet.status,
                        },
                    );
                }
                if let Some(previous) = self.last_packet_serial_raw {
                    let expected = previous.wrapping_add(1);
                    if packet.serial_number != expected {
                        retain_issue(
                            &mut packet_issue,
                            &mut secondary_issue,
                            WintabIssue::SerialDiscontinuity {
                                previous_raw: previous,
                                current_raw: packet.serial_number,
                            },
                        );
                    }
                }
                self.last_packet_serial_raw = Some(packet.serial_number);
                packets.push(sample);
            }
            drained_packets = drained_packets.saturating_add(returned as u32);
        }

        if !packets.is_empty() {
            state.record(ProbeRecord::WintabPackets(WintabPacketBatch {
                source: CaptureSource::WintabPacket,
                message_sequence,
                message_id_raw: metadata.message_id_raw,
                message_hwnd_raw_session_scoped: metadata.message_hwnd_raw_session_scoped,
                message_time_ms_raw: metadata.message_time_ms_raw,
                message_wparam_raw: metadata.wparam_raw,
                message_lparam_raw: metadata.lparam_raw,
                context_handle_raw_session_scoped: context,
                notification_serial_raw,
                context_config: self
                    .context_config
                    .expect("an open Wintab context has saved LOGCONTEXT metadata"),
                queue_capacity_raw: self.queue_capacity_raw.unwrap_or(0),
                coordinate_space: WintabCoordinateSpace::DigitizerContextOutputCoordinates,
                packet_time_mode: self
                    .packet_time_mode
                    .unwrap_or(WintabPacketTimeMode::AbsoluteSystemTime),
                app_observed_elapsed_ns,
                control_transition_observed_during_read: batch_control_transition_observed,
                packets,
            }));
        }
        if let Some((operation, returned_packets)) = interrupted_by_control {
            if let Some(issue) = packet_issue {
                self.set_partial(issue, message_sequence, metadata, state);
            }
            if let Some(issue) = secondary_issue {
                self.set_partial(issue, message_sequence, metadata, state);
            }
            self.note_control_transition_during_drain(
                operation,
                returned_packets,
                message_sequence,
                metadata,
                state,
            );
            return;
        }
        if !state.can_capture() {
            self.request_close_after_storage_limit(state);
            return;
        }
        if drained_packets == output_capacity || drain_rounds == MAX_DRAIN_ROUNDS {
            if !wintab_packet_hook_may_drain(control_pending) {
                self.note_control_transition_during_drain(
                    WintabPacketOperation::QueueQuery,
                    None,
                    message_sequence,
                    metadata,
                    state,
                );
                return;
            }
            let after_drain_result = self.queue_range(context, api, notification_serial_raw);
            if !wintab_packet_hook_may_drain(control_pending) {
                if let Some(issue) = packet_issue {
                    self.set_partial(issue, message_sequence, metadata, state);
                }
                if let Some(issue) = secondary_issue {
                    self.set_partial(issue, message_sequence, metadata, state);
                }
                self.note_control_transition_during_drain(
                    WintabPacketOperation::QueueQuery,
                    None,
                    message_sequence,
                    metadata,
                    state,
                );
                if let Err(issue) = after_drain_result {
                    self.set_partial(issue, message_sequence, metadata, state);
                }
                return;
            }
            match after_drain_result {
                Ok(after_drain) => {
                    if let Some(issue) = drain_limit_issue(
                        drained_packets,
                        output_capacity,
                        drain_rounds,
                        MAX_DRAIN_ROUNDS,
                        after_drain,
                    ) {
                        retain_issue(&mut packet_issue, &mut secondary_issue, issue);
                    }
                }
                Err(issue) => retain_issue(&mut packet_issue, &mut secondary_issue, issue),
            }
        }
        if let Some(issue) = packet_issue {
            self.set_partial(issue, message_sequence, metadata, state);
        }
        if let Some(issue) = secondary_issue {
            self.set_partial(issue, message_sequence, metadata, state);
        }
    }

    pub(crate) fn close(&mut self, state: &mut ProbeState) {
        let Some(context) = self.context else {
            return;
        };
        let Some(api) = self.api else {
            return;
        };
        // SAFETY: context is the live HCTX returned by WTOpenA. This runs before
        // the owning Winit Window is dropped, preserving the context lifetime.
        if unsafe { (api.close)(context) } == 0 {
            self.set_partial(
                WintabIssue::ContextCloseFailed,
                0,
                HookMessageMetadata {
                    message_id_raw: 0,
                    message_hwnd_raw_session_scoped: self
                        .owner_hwnd_raw_session_scoped
                        .unwrap_or(0),
                    wparam_raw: 0,
                    lparam_raw: 0,
                    message_time_ms_raw: None,
                    pointer_id: 0,
                },
                state,
            );
            return;
        }
        self.context = None;
    }

    pub(crate) fn request_close_after_storage_limit(&mut self, state: &mut ProbeState) {
        self.stop_requested = true;
        if self.status == WintabStatus::NotSelected || self.status == WintabStatus::Unavailable {
            return;
        }
        self.status = WintabStatus::Partial;
        if self.latest_issue.is_none() && state.summary().latest_wintab_issue.is_none() {
            self.latest_issue = Some(WintabIssue::CaptureStoppedByStorageLimit);
        }
        self.update_probe_configuration(state);
    }

    pub(crate) fn close_requested(&self) -> bool {
        self.stop_requested
    }

    pub(crate) fn control_state_valid(&self) -> bool {
        !self.context_configuration_stale && !self.stop_requested
    }

    /// Run at a Winit callback boundary, after the message hook has returned, so
    /// a driver call cannot re-enter code while its RefCell borrow is active.
    pub(crate) fn close_after_stop_request(&mut self, state: &mut ProbeState) {
        if !self.stop_requested || self.stop_close_attempted {
            return;
        }
        self.stop_close_attempted = true;
        if self.context.is_none()
            && matches!(
                self.status,
                WintabStatus::NotSelected | WintabStatus::Unavailable
            )
        {
            return;
        }
        self.status = WintabStatus::Partial;
        self.update_probe_configuration(state);

        if self.context.is_none() || self.close_context_raw() {
            self.update_probe_configuration(state);
            return;
        }

        let context = self.context.expect("failed WTClose leaves the HCTX live");
        let api = self.api.expect("an open HCTX has a loaded Wintab API");
        let queue_count_before_disable = match self.queue_range(context, api, None) {
            Ok(Some(range)) => exact_queue_count(range),
            Ok(None) => Some(0),
            Err(_) => None,
        };
        // SAFETY: `context` remains the live HCTX after WTClose returned false;
        // Wintab specifies WTEnable(FALSE) as stopping packet processing and
        // flushing its queue.
        if unsafe { (api.enable)(context, 0) } != 0 {
            eprintln!(
                "Wintab context close failed at the capture stop boundary; WTEnable(FALSE) deactivated it and flushed the queue; the DLL remains loaded until the context closes"
            );
            self.record_issue(
                state,
                close_failure_fallback_issue(true, queue_count_before_disable),
                0,
                0,
                self.owner_hwnd_raw_session_scoped,
                WintabStatus::Partial,
            );
        } else {
            eprintln!(
                "Wintab context close and WTEnable(FALSE) both failed at the capture stop boundary; the DLL remains loaded while the HCTX may still be live"
            );
            self.record_issue(
                state,
                close_failure_fallback_issue(false, queue_count_before_disable),
                0,
                0,
                self.owner_hwnd_raw_session_scoped,
                WintabStatus::Partial,
            );
        }
    }

    pub(crate) fn status(&self) -> WintabStatus {
        self.status
    }

    pub(crate) fn message_base_raw(&self) -> Option<u32> {
        self.message_base_raw
    }

    pub(crate) fn report_control_observer_install_failure(
        &mut self,
        hwnd: isize,
        win32_error: u32,
        state: &mut ProbeState,
    ) {
        self.record_issue(
            state,
            WintabIssue::ControlObserverInstallFailed { win32_error },
            0,
            0,
            Some(hwnd),
            WintabStatus::Unavailable,
        );
    }

    pub(crate) fn report_control_observer_removal_failure(
        &mut self,
        hwnd: isize,
        win32_error: u32,
        state: &mut ProbeState,
    ) {
        self.record_issue(
            state,
            WintabIssue::ControlObserverRemovalFailed { win32_error },
            0,
            0,
            Some(hwnd),
            WintabStatus::Partial,
        );
    }

    pub(crate) fn report_control_observer_diagnostics(
        &mut self,
        hwnd: isize,
        diagnostics: ControlObserverDiagnostics,
        state: &mut ProbeState,
    ) {
        if diagnostics.dropped_messages > 0 {
            self.context_configuration_stale = true;
            self.stop_requested = true;
            self.record_issue(
                state,
                WintabIssue::ControlObserverQueueOverflow {
                    dropped_messages: diagnostics.dropped_messages,
                },
                0,
                0,
                Some(hwnd),
                WintabStatus::Partial,
            );
        }
        if diagnostics.callback_panics > 0 {
            self.context_configuration_stale = true;
            self.stop_requested = true;
            self.record_issue(
                state,
                WintabIssue::ControlObserverCallbackPanicked {
                    count: diagnostics.callback_panics,
                },
                0,
                0,
                Some(hwnd),
                WintabStatus::Partial,
            );
        }
    }

    pub(crate) fn latest_issue(&self) -> Option<WintabIssue> {
        self.latest_issue
    }

    pub(crate) fn context_config_snapshot(&self) -> Option<WintabContextConfig> {
        self.context_config
    }

    fn packet_capture_enabled(&self) -> bool {
        self.context.is_some() && !self.context_configuration_stale && !self.stop_requested
    }

    fn queue_range(
        &mut self,
        context: isize,
        api: WintabApi,
        notification_serial_raw: Option<u32>,
    ) -> Result<Option<QueueRange>, WintabIssue> {
        let mut oldest = 0u32;
        let mut newest = 0u32;
        // SAFETY: both serial pointers are valid outputs and context is live.
        let succeeded = unsafe { (api.queue_packets_ex)(context, &mut oldest, &mut newest) };
        interpret_queue_query(
            succeeded != 0,
            oldest,
            newest,
            notification_serial_raw,
            self.last_packet_serial_raw,
            self.queue_capacity_raw.unwrap_or(0),
        )
    }

    fn set_partial(
        &mut self,
        issue: WintabIssue,
        message_sequence: u64,
        metadata: HookMessageMetadata,
        state: &mut ProbeState,
    ) {
        self.set_partial_at(
            issue,
            message_sequence,
            metadata,
            self.app_elapsed_now(),
            state,
        );
    }

    fn set_partial_at(
        &mut self,
        issue: WintabIssue,
        message_sequence: u64,
        metadata: HookMessageMetadata,
        app_observed_elapsed_ns: Option<u128>,
        state: &mut ProbeState,
    ) {
        self.status = WintabStatus::Partial;
        self.latest_issue = Some(issue);
        self.update_probe_configuration(state);
        state.record(ProbeRecord::WintabIssue {
            source: CaptureSource::WintabPacket,
            message_sequence,
            message_id_raw: metadata.message_id_raw,
            message_hwnd_raw_session_scoped: Some(metadata.message_hwnd_raw_session_scoped),
            message_wparam_raw: Some(metadata.wparam_raw),
            message_lparam_raw: Some(metadata.lparam_raw),
            message_time_ms_raw: metadata.message_time_ms_raw,
            app_observed_elapsed_ns,
            issue,
        });
        if !state.can_capture() {
            self.request_close_after_storage_limit(state);
        }
    }

    fn note_control_transition_during_drain(
        &mut self,
        operation: WintabPacketOperation,
        returned_packets: Option<u32>,
        message_sequence: u64,
        metadata: HookMessageMetadata,
        state: &mut ProbeState,
    ) {
        self.context_configuration_stale = true;
        self.stop_requested = true;
        self.set_partial(
            WintabIssue::ControlTransitionObservedDuringDrain {
                operation,
                returned_packets,
            },
            message_sequence,
            metadata,
            state,
        );
    }

    fn record_issue(
        &mut self,
        state: &mut ProbeState,
        issue: WintabIssue,
        message_sequence: u64,
        message_id_raw: u32,
        message_hwnd_raw_session_scoped: Option<isize>,
        status: WintabStatus,
    ) {
        self.record_issue_with_raw(
            state,
            issue,
            WintabIssueProvenance {
                message_sequence,
                message_id_raw,
                message_hwnd_raw_session_scoped,
                message_wparam_raw: None,
                message_lparam_raw: None,
                message_time_ms_raw: None,
                app_observed_elapsed_ns: self.app_elapsed_now(),
                status,
            },
        );
    }

    fn record_issue_with_raw(
        &mut self,
        state: &mut ProbeState,
        issue: WintabIssue,
        provenance: WintabIssueProvenance,
    ) {
        self.status = provenance.status;
        self.latest_issue = Some(issue);
        self.update_probe_configuration(state);
        state.record(ProbeRecord::WintabIssue {
            source: CaptureSource::WintabPacket,
            message_sequence: provenance.message_sequence,
            message_id_raw: provenance.message_id_raw,
            message_hwnd_raw_session_scoped: provenance.message_hwnd_raw_session_scoped,
            message_wparam_raw: provenance.message_wparam_raw,
            message_lparam_raw: provenance.message_lparam_raw,
            message_time_ms_raw: provenance.message_time_ms_raw,
            app_observed_elapsed_ns: provenance.app_observed_elapsed_ns,
            issue,
        });
        if !state.can_capture() {
            self.request_close_after_storage_limit(state);
        }
    }

    fn app_elapsed_now(&self) -> Option<u128> {
        self.app_clock_origin
            .map(|origin| origin.elapsed().as_nanos())
    }

    fn update_probe_configuration(&self, state: &mut ProbeState) {
        state.set_wintab_configuration(
            self.status,
            self.packet_time_mode,
            self.configured_packet_data_raw,
            self.configured_packet_mode_raw,
            self.queue_capacity_raw,
        );
    }

    fn close_context_raw(&mut self) -> bool {
        let Some(context) = self.context else {
            return true;
        };
        let Some(api) = self.api else {
            return false;
        };
        // SAFETY: context is owned by this object and the module is still loaded.
        if unsafe { (api.close)(context) } == 0 {
            return false;
        }
        self.context = None;
        true
    }
}

fn interpret_queue_query(
    succeeded: bool,
    oldest: u32,
    newest: u32,
    _notification_serial_raw: Option<u32>,
    _last_packet_serial_raw: Option<u32>,
    queue_capacity: i32,
) -> Result<Option<QueueRange>, WintabIssue> {
    if !succeeded {
        return Err(WintabIssue::QueueQueryFailed);
    }

    // Wintab's reference does not reserve serial zero as an empty sentinel.
    // Always treat TRUE + 0/0 as ambiguous and probe with WTPacketsGet, even
    // after a prior serial or a packet notification.
    if oldest == 0 && newest == 0 {
        return Ok(Some(QueueRange {
            available: 1,
            issue: None,
            zero_range_ambiguous: true,
        }));
    }

    let available = serial_range_count(oldest, newest);
    if available == 0 {
        return Err(WintabIssue::QueueSerialRangeInvalid {
            oldest_raw: oldest,
            newest_raw: newest,
        });
    }
    let issue = if available > queue_capacity as u32 {
        Some(WintabIssue::QueueCountExceedsCapacity {
            reported: available,
            capacity: queue_capacity,
        })
    } else {
        None
    };
    Ok(Some(QueueRange {
        available,
        issue,
        zero_range_ambiguous: false,
    }))
}

fn zero_range_probe_is_empty(range: QueueRange, returned_packet_count: i32) -> bool {
    range.zero_range_ambiguous && returned_packet_count == 0
}

fn exact_queue_count(range: QueueRange) -> Option<u32> {
    (!range.zero_range_ambiguous).then_some(range.available)
}

fn retain_issue(
    primary: &mut Option<WintabIssue>,
    secondary: &mut Option<WintabIssue>,
    issue: WintabIssue,
) {
    if primary.is_none() {
        *primary = Some(issue);
    } else if *primary != Some(issue) && secondary.is_none() {
        *secondary = Some(issue);
    }
}

impl Drop for WintabCapture {
    fn drop(&mut self) {
        if self.context.is_some() && !self.close_context_raw() {
            // Keep the module loaded until process teardown if a driver refuses
            // to close its context; unloading could leave driver callbacks dangling.
            return;
        }
        if self.module != 0 {
            // SAFETY: module was acquired by LoadLibraryExW and the context is closed.
            unsafe { FreeLibrary(self.module) };
            self.module = 0;
        }
    }
}

fn load_wintab_api() -> Result<(HMODULE, WintabApi), WintabIssue> {
    let path = system_wintab_path()?;
    // SAFETY: path is absolute under GetSystemDirectoryW. The flags restrict
    // dependency resolution to this DLL directory and System32, never CWD/PATH.
    let module = unsafe {
        LoadLibraryExW(
            path.as_ptr(),
            0,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module == 0 {
        // SAFETY: GetLastError has no pointer parameters and is valid on this thread.
        return Err(WintabIssue::LibraryLoadFailed {
            win32_error: unsafe { GetLastError() },
        });
    }

    // SAFETY: module is the loaded absolute-path Wintab DLL.
    let api_result = unsafe { resolve_wintab_api(module) };
    match api_result {
        Ok(api) => Ok((module, api)),
        Err(issue) => {
            // SAFETY: module was loaded and no context/functions escape on failure.
            unsafe { FreeLibrary(module) };
            Err(issue)
        }
    }
}

/// # Safety
/// `module` must be the Wintab32.dll module loaded by `load_wintab_api`.
unsafe fn resolve_wintab_api(module: HMODULE) -> Result<WintabApi, WintabIssue> {
    // SAFETY: symbol names are static NUL-terminated ASCII strings. Each pointer
    // is cast to the exact WINAPI prototype corresponding to WINTAB.H 1.4.
    let info_raw = unsafe { get_export(module, b"WTInfoA\0")? };
    let open_raw = unsafe { get_export(module, b"WTOpenA\0")? };
    let close_raw = unsafe { get_export(module, b"WTClose\0")? };
    let queue_size_set_raw = unsafe { get_export(module, b"WTQueueSizeSet\0")? };
    let queue_size_get_raw = unsafe { get_export(module, b"WTQueueSizeGet\0")? };
    let queue_packets_ex_raw = unsafe { get_export(module, b"WTQueuePacketsEx\0")? };
    let packets_get_raw = unsafe { get_export(module, b"WTPacketsGet\0")? };
    let enable_raw = unsafe { get_export(module, b"WTEnable\0")? };

    Ok(WintabApi {
        info_a: unsafe {
            mem::transmute::<unsafe extern "system" fn() -> isize, WtInfoA>(info_raw)
        },
        open_a: unsafe {
            mem::transmute::<unsafe extern "system" fn() -> isize, WtOpenA>(open_raw)
        },
        close: unsafe {
            mem::transmute::<unsafe extern "system" fn() -> isize, WtClose>(close_raw)
        },
        queue_size_set: unsafe {
            mem::transmute::<unsafe extern "system" fn() -> isize, WtQueueSizeSet>(
                queue_size_set_raw,
            )
        },
        queue_size_get: unsafe {
            mem::transmute::<unsafe extern "system" fn() -> isize, WtQueueSizeGet>(
                queue_size_get_raw,
            )
        },
        queue_packets_ex: unsafe {
            mem::transmute::<unsafe extern "system" fn() -> isize, WtQueuePacketsEx>(
                queue_packets_ex_raw,
            )
        },
        packets_get: unsafe {
            mem::transmute::<unsafe extern "system" fn() -> isize, WtPacketsGet>(packets_get_raw)
        },
        enable: unsafe {
            mem::transmute::<unsafe extern "system" fn() -> isize, WtEnable>(enable_raw)
        },
    })
}

/// # Safety
/// `module` must be a valid loaded module and `symbol` must be NUL-terminated.
unsafe fn get_export(
    module: HMODULE,
    symbol: &'static [u8],
) -> Result<unsafe extern "system" fn() -> isize, WintabIssue> {
    // SAFETY: `symbol` is a static NUL-terminated byte string.
    unsafe { GetProcAddress(module, symbol.as_ptr()) }.ok_or_else(|| {
        let function = match symbol {
            b"WTInfoA\0" => WintabFunction::WTInfoA,
            b"WTOpenA\0" => WintabFunction::WTOpenA,
            b"WTClose\0" => WintabFunction::WTClose,
            b"WTQueueSizeSet\0" => WintabFunction::WTQueueSizeSet,
            b"WTQueueSizeGet\0" => WintabFunction::WTQueueSizeGet,
            b"WTQueuePacketsEx\0" => WintabFunction::WTQueuePacketsEx,
            b"WTPacketsGet\0" => WintabFunction::WTPacketsGet,
            _ => WintabFunction::WTEnable,
        };
        WintabIssue::MissingFunction { function }
    })
}

fn system_wintab_path() -> Result<[u16; WINTAB_PATH_CAPACITY], WintabIssue> {
    let mut system_directory = [0u16; SYSTEM_DIRECTORY_CAPACITY];
    // SAFETY: system_directory is writable and the supplied capacity matches.
    let system_len = unsafe {
        GetSystemDirectoryW(system_directory.as_mut_ptr(), system_directory.len() as u32)
    };
    if system_len == 0 {
        // SAFETY: GetLastError has no pointer parameters and is valid on this thread.
        return Err(WintabIssue::SystemPathUnavailable {
            win32_error: unsafe { GetLastError() },
        });
    }
    if system_len as usize >= system_directory.len() {
        return Err(WintabIssue::SystemPathTooLong {
            required: system_len,
            capacity: system_directory.len() as u32,
        });
    }

    build_system_wintab_path(&system_directory[..system_len as usize])
}

fn build_system_wintab_path(
    system_directory: &[u16],
) -> Result<[u16; WINTAB_PATH_CAPACITY], WintabIssue> {
    let mut path = [0u16; WINTAB_PATH_CAPACITY];
    let mut cursor = system_directory.len();
    let separator_len = if system_directory.last().copied() == Some(b'\\' as u16) {
        0
    } else {
        1
    };
    let required = cursor
        .saturating_add(separator_len)
        .saturating_add(WINTAB_DLL_NAME.len())
        .saturating_add(1);
    if system_directory.is_empty() {
        return Err(WintabIssue::SystemPathUnavailable { win32_error: 0 });
    }
    if required > WINTAB_PATH_CAPACITY {
        return Err(WintabIssue::SystemPathTooLong {
            required: u32::try_from(required).unwrap_or(u32::MAX),
            capacity: WINTAB_PATH_CAPACITY as u32,
        });
    }
    path[..cursor].copy_from_slice(system_directory);
    if cursor == 0 || path[cursor - 1] != b'\\' as u16 {
        path[cursor] = b'\\' as u16;
        cursor += 1;
    }
    for byte in WINTAB_DLL_NAME {
        path[cursor] = u16::from(*byte);
        cursor += 1;
    }
    path[cursor] = 0;
    Ok(path)
}

fn packet_time_mode(packet_mode_raw: u32) -> WintabPacketTimeMode {
    if packet_mode_raw & PK_TIME == 0 {
        WintabPacketTimeMode::AbsoluteSystemTime
    } else {
        WintabPacketTimeMode::RelativeMilliseconds
    }
}

fn queue_trigger(
    metadata: HookMessageMetadata,
    message_base: u32,
    context: isize,
) -> Option<WintabQueueTrigger> {
    if metadata.message_id_raw == message_base && metadata.lparam_raw == context {
        Some(WintabQueueTrigger::Packet {
            notification_serial_raw: metadata.wparam_raw as u32,
        })
    } else if metadata.message_id_raw == message_base + 5 && metadata.wparam_raw as isize == context
    {
        Some(WintabQueueTrigger::Proximity)
    } else {
        None
    }
}

fn context_overlap_disposition(
    initial_overlap_pending: bool,
    packet_notification_seen: bool,
    related_context: isize,
    own_context: isize,
    context_status_raw: u32,
) -> ContextOverlapDisposition {
    let positively_open_and_topmost = context_status_raw & CXS_ONTOP != 0
        && context_status_raw & (CXS_DISABLED | CXS_OBSCURED) == 0;
    if initial_overlap_pending
        && !packet_notification_seen
        && related_context == own_context
        && positively_open_and_topmost
    {
        ContextOverlapDisposition::ExpectedInitialOpen
    } else {
        ContextOverlapDisposition::Changed
    }
}

fn first_supported_queue_size<F>(attempts: &[i32], mut try_set: F) -> Option<i32>
where
    F: FnMut(i32) -> bool,
{
    attempts.iter().copied().find(|size| try_set(*size))
}

fn bounded_message_output_capacity(remaining_samples: u64) -> u32 {
    u64::from(MAX_PACKETS_PER_MESSAGE)
        .min(remaining_samples)
        .min(u64::from(u32::MAX)) as u32
}

fn drain_limit_issue(
    drained_packets: u32,
    output_capacity: u32,
    drain_rounds: u8,
    max_drain_rounds: u8,
    after_drain: Option<QueueRange>,
) -> Option<WintabIssue> {
    if drained_packets < output_capacity && drain_rounds < max_drain_rounds {
        return None;
    }
    let range = after_drain?;
    Some(WintabIssue::DrainLimitReached {
        pending_packets_reported: (!range.zero_range_ambiguous).then_some(range.available),
        drain_rounds,
    })
}

fn close_failure_fallback_issue(
    disable_succeeded: bool,
    queue_count_before_disable: Option<u32>,
) -> WintabIssue {
    if disable_succeeded {
        WintabIssue::ContextDisabledAfterCloseFailure {
            queue_count_before_disable,
        }
    } else {
        WintabIssue::ContextDisableFailed
    }
}

fn wintab_context_config(context: &LogContextA) -> WintabContextConfig {
    let mut context_name_raw = [0u8; 40];
    for (destination, source) in context_name_raw.iter_mut().zip(context.name) {
        *destination = source as u8;
    }
    WintabContextConfig {
        context_name_raw,
        options_raw: context.options,
        status_raw: context.status,
        locks_raw: context.locks,
        message_base_raw: context.message_base,
        device_raw: context.device,
        packet_rate_raw: context.packet_rate,
        packet_data_raw: context.packet_data,
        packet_mode_raw: context.packet_mode,
        move_mask_raw: context.move_mask,
        button_down_mask_raw: context.button_down_mask,
        button_up_mask_raw: context.button_up_mask,
        input_origin_raw: [
            context.input_origin_x,
            context.input_origin_y,
            context.input_origin_z,
        ],
        input_extent_raw: [
            context.input_extent_x,
            context.input_extent_y,
            context.input_extent_z,
        ],
        output_origin_raw: [
            context.output_origin_x,
            context.output_origin_y,
            context.output_origin_z,
        ],
        output_extent_raw: [
            context.output_extent_x,
            context.output_extent_y,
            context.output_extent_z,
        ],
        sensitivity_fixed32_raw: [
            context.sensitivity_x,
            context.sensitivity_y,
            context.sensitivity_z,
        ],
        system_mode_raw: context.system_mode,
        system_origin_raw: [context.system_origin_x, context.system_origin_y],
        system_extent_raw: [context.system_extent_x, context.system_extent_y],
        system_sensitivity_fixed32_raw: [
            context.system_sensitivity_x,
            context.system_sensitivity_y,
        ],
    }
}

fn wintab_packet_sample(packet: WintabPacketLayout) -> WintabPacketSample {
    WintabPacketSample {
        context_handle_raw_session_scoped: packet.context,
        status_raw: packet.status,
        packet_time_raw: packet.time,
        serial_number_raw: packet.serial_number,
        cursor_raw: packet.cursor,
        buttons_raw: packet.buttons,
        x_raw: packet.x,
        y_raw: packet.y,
        normal_pressure_raw: packet.normal_pressure,
    }
}

fn serial_range_count(oldest: u32, newest: u32) -> u32 {
    newest.wrapping_sub(oldest).wrapping_add(1)
}

fn wintab_context_name() -> [c_char; 40] {
    let mut name = [0 as c_char; 40];
    for (destination, source) in name.iter_mut().zip(b"LassoInk Wintab") {
        *destination = *source as c_char;
    }
    name
}

#[cfg(test)]
mod tests {
    use super::{
        Arc, AtomicBool, AtomicU32, CXO_MESSAGES, CXS_DISABLED, CXS_OBSCURED, CXS_ONTOP,
        ContextOverlapDisposition, ControlObserverDiagnostics, ControlObserverState, LogContextA,
        MAX_DRAIN_ROUNDS, MAX_PACKETS_PER_MESSAGE, MAX_PENDING_CONTROL_MESSAGES, Mutex, Ordering,
        PK_PACKET_DATA, PK_TIME, PendingControlQueue, QUEUE_SIZE_ATTEMPTS, QueueRange, WT_DEFBASE,
        WintabApi, WintabCapture, WintabControlObserver, WintabIssue, WintabPacketLayout,
        WintabQueueTrigger, WintabStatus, bounded_message_output_capacity,
        build_system_wintab_path, close_failure_fallback_issue, context_overlap_disposition,
        drain_limit_issue, exact_queue_count, first_supported_queue_size, interpret_queue_query,
        packet_time_mode, queue_trigger, wintab_context_config, wintab_packet_sample,
        zero_range_probe_is_empty,
    };
    use crate::win32_pointer::{
        CaptureMode, CaptureSource, HookMessageMetadata, ProbeRecord, ProbeState,
        WintabContextConfig, WintabControlNotification, WintabPacketOperation,
        WintabPacketTimeMode, wintab_packet_hook_may_drain,
    };
    use std::ffi::c_void;
    use std::mem::{self, offset_of, size_of};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::{
        Foundation::{HWND, LPARAM, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW,
            PostMessageW, SendMessageW, WS_POPUP,
        },
    };

    static QUEUE_QUERY_CALLS: AtomicU32 = AtomicU32::new(0);
    static REENTRANT_CONTROL_TEST_LOCK: Mutex<()> = Mutex::new(());
    static REENTRANT_CONTROL_HWND: std::sync::atomic::AtomicIsize =
        std::sync::atomic::AtomicIsize::new(0);
    static REENTRANT_QUEUE_QUERY_CALLS: AtomicU32 = AtomicU32::new(0);
    static REENTRANT_PACKET_READ_CALLS: AtomicU32 = AtomicU32::new(0);

    struct TestWindow(HWND);

    impl TestWindow {
        fn new() -> Self {
            let class_name = "STATIC\0".encode_utf16().collect::<Vec<_>>();
            let window_name = "LassoInk Wintab subclass test\0"
                .encode_utf16()
                .collect::<Vec<_>>();
            // SAFETY: null requests the current process module handle.
            let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
            // SAFETY: the built-in STATIC class and NUL-terminated strings are valid;
            // this creates a real top-level HWND on the current test thread.
            let hwnd = unsafe {
                CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    window_name.as_ptr(),
                    WS_POPUP,
                    0,
                    0,
                    1,
                    1,
                    0,
                    0,
                    instance,
                    std::ptr::null(),
                )
            };
            assert_ne!(hwnd, 0);
            Self(hwnd)
        }
    }

    impl Drop for TestWindow {
        fn drop(&mut self) {
            // SAFETY: the test owns this HWND and destroys it on its creating thread.
            unsafe { DestroyWindow(self.0) };
        }
    }

    fn fake_capture(hwnd: HWND, context: isize) -> WintabCapture {
        let mut capture = WintabCapture::empty(WintabStatus::Available);
        capture.context = Some(context);
        capture.owner_hwnd_raw_session_scoped = Some(hwnd);
        capture.message_base_raw = Some(WT_DEFBASE);
        capture.packet_notification_seen = true;
        capture
    }

    unsafe extern "system" fn stub_info(_: u32, _: u32, _: *mut c_void) -> u32 {
        0
    }

    unsafe extern "system" fn stub_open(_: isize, _: *mut LogContextA, _: i32) -> isize {
        0
    }

    unsafe extern "system" fn stub_close(_: isize) -> i32 {
        1
    }

    unsafe extern "system" fn stub_queue_size_set(_: isize, _: i32) -> i32 {
        0
    }

    unsafe extern "system" fn stub_queue_size_get(_: isize) -> i32 {
        0
    }

    unsafe extern "system" fn stub_queue_packets_ex(_: isize, _: *mut u32, _: *mut u32) -> i32 {
        0
    }

    unsafe extern "system" fn stub_packets_get(
        _: isize,
        _: i32,
        _: *mut WintabPacketLayout,
    ) -> i32 {
        0
    }

    unsafe extern "system" fn stub_enable(_: isize, _: i32) -> i32 {
        0
    }

    fn fake_close_api() -> WintabApi {
        WintabApi {
            info_a: stub_info,
            open_a: stub_open,
            close: stub_close,
            queue_size_set: stub_queue_size_set,
            queue_size_get: stub_queue_size_get,
            queue_packets_ex: stub_queue_packets_ex,
            packets_get: stub_packets_get,
            enable: stub_enable,
        }
    }

    unsafe extern "system" fn counting_queue_packets_ex(_: isize, _: *mut u32, _: *mut u32) -> i32 {
        QUEUE_QUERY_CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }

    unsafe extern "system" fn control_during_queue_query(
        context: isize,
        oldest: *mut u32,
        newest: *mut u32,
    ) -> i32 {
        REENTRANT_QUEUE_QUERY_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the probe passes writable output pointers for WTQueuePacketsEx.
        unsafe {
            oldest.write(1);
            newest.write(1);
        }
        let hwnd = REENTRANT_CONTROL_HWND.load(Ordering::Relaxed) as HWND;
        // SAFETY: the test stores its live HWND and sends scalar Wintab fields.
        unsafe { SendMessageW(hwnd, WT_DEFBASE + 3, context as usize, CXS_ONTOP as isize) };
        1
    }

    unsafe extern "system" fn one_packet_queue_query(
        _: isize,
        oldest: *mut u32,
        newest: *mut u32,
    ) -> i32 {
        REENTRANT_QUEUE_QUERY_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the probe passes writable output pointers for WTQueuePacketsEx.
        unsafe {
            oldest.write(1);
            newest.write(1);
        }
        1
    }

    unsafe extern "system" fn control_during_packet_read(
        context: isize,
        max_packets: i32,
        packets: *mut WintabPacketLayout,
    ) -> i32 {
        REENTRANT_PACKET_READ_CALLS.fetch_add(1, Ordering::Relaxed);
        if max_packets < 1 {
            return 0;
        }
        // SAFETY: the probe provides at least one writable packet slot here.
        unsafe {
            packets.write(WintabPacketLayout {
                context,
                status: 0,
                time: 123,
                serial_number: 1,
                cursor: 0,
                buttons: 0,
                x: 10,
                y: 20,
                normal_pressure: 512,
            });
        }
        let hwnd = REENTRANT_CONTROL_HWND.load(Ordering::Relaxed) as HWND;
        // SAFETY: the test stores its live HWND and sends scalar Wintab fields.
        unsafe { SendMessageW(hwnd, WT_DEFBASE + 3, context as usize, CXS_ONTOP as isize) };
        1
    }

    unsafe extern "system" fn counting_packets_get(
        _: isize,
        _: i32,
        _: *mut WintabPacketLayout,
    ) -> i32 {
        REENTRANT_PACKET_READ_CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }

    fn set_reentrant_test_context(hwnd: HWND) {
        REENTRANT_CONTROL_HWND.store(hwnd, Ordering::Relaxed);
        REENTRANT_QUEUE_QUERY_CALLS.store(0, Ordering::Relaxed);
        REENTRANT_PACKET_READ_CALLS.store(0, Ordering::Relaxed);
    }

    fn test_context_config() -> WintabContextConfig {
        // SAFETY: LogContextA contains only integer and byte-array fields, so
        // its all-zero representation is valid diagnostic test input.
        let context = unsafe { mem::zeroed::<LogContextA>() };
        wintab_context_config(&context)
    }

    fn send_and_pop_control(
        observer: &WintabControlObserver,
        hwnd: HWND,
        message_id: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> WintabControlNotification {
        // SAFETY: hwnd is the live test window and this synchronous send is
        // intentionally delivered through its installed subclass procedure.
        unsafe { SendMessageW(hwnd, message_id, wparam, lparam) };
        observer
            .pop_pending()
            .expect("subclass should queue the sent Wintab control message")
    }

    #[test]
    fn wintab_header_layout_matches_x64_abi() {
        assert_eq!(size_of::<LogContextA>(), 172);
        assert_eq!(offset_of!(LogContextA, options), 40);
        assert_eq!(offset_of!(LogContextA, packet_data), 64);
        assert_eq!(offset_of!(LogContextA, system_sensitivity_y), 168);
        assert_eq!(size_of::<WintabPacketLayout>(), 40);
        assert_eq!(offset_of!(WintabPacketLayout, status), 8);
        assert_eq!(offset_of!(WintabPacketLayout, time), 12);
        assert_eq!(offset_of!(WintabPacketLayout, x), 28);
        assert_eq!(offset_of!(WintabPacketLayout, normal_pressure), 36);
    }

    #[test]
    fn configured_packet_mask_has_exact_selected_fields() {
        assert_eq!(
            PK_PACKET_DATA,
            0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020 | 0x0040 | 0x0080 | 0x0100 | 0x0400
        );
    }

    #[test]
    fn packet_time_mode_preserves_the_configured_domain() {
        assert_eq!(
            packet_time_mode(0),
            WintabPacketTimeMode::AbsoluteSystemTime
        );
        assert_eq!(
            packet_time_mode(PK_TIME),
            WintabPacketTimeMode::RelativeMilliseconds
        );
    }

    #[test]
    fn proximity_message_uses_context_in_wparam_and_has_no_packet_serial() {
        let context = 0x1122_isize;
        let metadata = HookMessageMetadata {
            message_id_raw: WT_DEFBASE + 5,
            message_hwnd_raw_session_scoped: 0x3344,
            wparam_raw: context as usize,
            lparam_raw: 0x0001_0001,
            message_time_ms_raw: None,
            pointer_id: 0,
        };
        assert_eq!(
            queue_trigger(metadata, WT_DEFBASE, context),
            Some(WintabQueueTrigger::Proximity)
        );
    }

    #[test]
    fn packet_message_keeps_its_raw_serial_and_requires_matching_context() {
        let context = 0x1122_isize;
        let metadata = HookMessageMetadata {
            message_id_raw: WT_DEFBASE,
            message_hwnd_raw_session_scoped: 0x3344,
            wparam_raw: 0xffff,
            lparam_raw: context,
            message_time_ms_raw: None,
            pointer_id: 0,
        };
        assert_eq!(
            queue_trigger(metadata, WT_DEFBASE, context),
            Some(WintabQueueTrigger::Packet {
                notification_serial_raw: 0xffff,
            })
        );
        assert_eq!(queue_trigger(metadata, WT_DEFBASE, context + 1), None);
    }

    #[test]
    fn context_changes_stop_packet_reads_until_the_context_is_recreated() {
        let mut capture = WintabCapture::empty(WintabStatus::Partial);
        capture.context = Some(0x1122);
        assert!(capture.packet_capture_enabled());

        capture.context_configuration_stale = true;
        capture.stop_requested = true;
        assert!(!capture.packet_capture_enabled());
        assert!(capture.close_requested());

        capture.context = None;
        capture.context_configuration_stale = false;
        assert!(!capture.packet_capture_enabled());
    }

    #[test]
    fn a_shared_storage_limit_requests_deferred_partial_close() {
        let mut state = crate::win32_pointer::ProbeState::default();
        let mut capture = WintabCapture::empty(WintabStatus::Available);
        capture.context = Some(0x1122);

        capture.request_close_after_storage_limit(&mut state);

        assert!(capture.close_requested());
        assert_eq!(capture.status(), WintabStatus::Partial);
        assert_eq!(
            capture.latest_issue(),
            Some(WintabIssue::CaptureStoppedByStorageLimit)
        );
        assert!(!capture.packet_capture_enabled());
        assert!(!capture.stop_close_attempted);
    }

    #[test]
    fn deferred_close_request_is_consumed_at_loop_boundary() {
        let mut state = crate::win32_pointer::ProbeState::default();
        let mut capture = WintabCapture::empty(WintabStatus::Available);

        capture.request_close_after_storage_limit(&mut state);
        capture.close_after_stop_request(&mut state);

        assert!(capture.stop_close_attempted);
        assert_eq!(capture.status(), WintabStatus::Partial);
    }

    #[test]
    fn unavailable_wintab_startup_issue_has_app_arrival_and_null_message_fields() {
        let mut state = ProbeState::default();
        state.set_capture_mode(CaptureMode::Wintab);
        let issue = WintabIssue::SystemPathUnavailable { win32_error: 2 };
        let origin = Instant::now() - Duration::from_secs(1);
        let capture = WintabCapture::unavailable_from_load_error(issue, origin, &mut state);

        assert_eq!(capture.status(), WintabStatus::Unavailable);
        let issue_record = state
            .retained_records()
            .iter()
            .find_map(|record| match record {
                ProbeRecord::WintabIssue {
                    issue: recorded_issue,
                    app_observed_elapsed_ns,
                    message_id_raw,
                    message_hwnd_raw_session_scoped,
                    message_wparam_raw,
                    message_lparam_raw,
                    message_time_ms_raw,
                    ..
                } => Some((
                    *recorded_issue,
                    *app_observed_elapsed_ns,
                    *message_id_raw,
                    *message_hwnd_raw_session_scoped,
                    *message_wparam_raw,
                    *message_lparam_raw,
                    *message_time_ms_raw,
                )),
                _ => None,
            })
            .expect("Wintab load failure should be retained as a startup issue");
        assert_eq!(issue_record.0, issue);
        assert!(issue_record.1.is_some_and(|elapsed| elapsed > 0));
        assert_eq!(issue_record.2, 0);
        assert_eq!(issue_record.3, None);
        assert_eq!(issue_record.4, None);
        assert_eq!(issue_record.5, None);
        assert_eq!(issue_record.6, None);
    }

    #[test]
    fn overlap_notification_is_initial_only_for_our_context_before_packets() {
        assert_eq!(
            context_overlap_disposition(true, false, 0x1122, 0x1122, CXS_ONTOP),
            ContextOverlapDisposition::ExpectedInitialOpen
        );
        assert_eq!(
            context_overlap_disposition(true, false, 0x3344, 0x1122, CXS_ONTOP),
            ContextOverlapDisposition::Changed
        );
        assert_eq!(
            context_overlap_disposition(true, true, 0x1122, 0x1122, CXS_ONTOP),
            ContextOverlapDisposition::Changed
        );
        assert_eq!(
            context_overlap_disposition(false, false, 0x1122, 0x1122, CXS_ONTOP),
            ContextOverlapDisposition::Changed
        );
    }

    #[test]
    fn initial_self_overlap_with_disabled_obscured_or_not_ontop_status_stops_capture() {
        for adverse_status in [CXS_DISABLED, CXS_OBSCURED, 0] {
            assert_eq!(
                context_overlap_disposition(true, false, 0x1122, 0x1122, adverse_status),
                ContextOverlapDisposition::Changed
            );
        }
        assert_eq!(
            context_overlap_disposition(true, false, 0x1122, 0x1122, CXS_ONTOP | CXS_DISABLED),
            ContextOverlapDisposition::Changed
        );
        assert_eq!(
            context_overlap_disposition(true, false, 0x1122, 0x1122, CXS_ONTOP | CXS_OBSCURED),
            ContextOverlapDisposition::Changed
        );
    }

    #[test]
    fn initial_self_overlap_with_adverse_status_is_recorded_and_stops_capture() {
        let own_context = 0x1122_isize;
        let owner_hwnd = 0x3344_isize;
        for status in [CXS_ONTOP | CXS_OBSCURED, CXS_ONTOP | CXS_DISABLED, 0] {
            let mut state = ProbeState::default();
            state.set_capture_mode(CaptureMode::Wintab);
            let mut capture = fake_capture(owner_hwnd, own_context);
            capture.initial_context_overlap_pending = true;
            capture.packet_notification_seen = false;
            let notification = WintabControlNotification {
                source: CaptureSource::WintabControlNotification,
                observer_sequence: 9,
                message_id_raw: WT_DEFBASE + 4,
                message_hwnd_raw_session_scoped: owner_hwnd,
                wparam_raw: own_context as usize,
                lparam_raw: status as isize,
                app_observed_elapsed_ns: 10,
            };

            capture.handle_control_notification(notification, &mut state);

            assert_eq!(
                capture.latest_issue(),
                Some(WintabIssue::ContextOverlapChanged {
                    related_context_raw_session_scoped: own_context,
                    context_status_raw: status,
                })
            );
            assert!(capture.context_configuration_stale);
            assert!(capture.close_requested());
            assert_eq!(state.summary().wintab_status, WintabStatus::Partial);
        }
    }

    #[test]
    fn close_failure_fallback_reports_disabled_queue_snapshot_or_failure() {
        assert_eq!(
            close_failure_fallback_issue(true, Some(7)),
            WintabIssue::ContextDisabledAfterCloseFailure {
                queue_count_before_disable: Some(7),
            }
        );
        assert_eq!(
            close_failure_fallback_issue(true, None),
            WintabIssue::ContextDisabledAfterCloseFailure {
                queue_count_before_disable: None,
            }
        );
        assert_eq!(
            close_failure_fallback_issue(false, Some(7)),
            WintabIssue::ContextDisableFailed
        );

        let ambiguous_snapshot = QueueRange {
            available: 1,
            issue: None,
            zero_range_ambiguous: true,
        };
        assert_eq!(
            close_failure_fallback_issue(true, exact_queue_count(ambiguous_snapshot)),
            WintabIssue::ContextDisabledAfterCloseFailure {
                queue_count_before_disable: None,
            }
        );
    }

    #[test]
    fn real_window_subclass_observes_sent_wintab_lifecycle_controls() {
        let window = TestWindow::new();
        let context = 0x1122_isize;
        let origin = Instant::now() - Duration::from_secs(1);
        let control_pending = Arc::new(AtomicBool::new(false));
        let mut observer =
            WintabControlObserver::install(window.0, WT_DEFBASE, origin, control_pending).unwrap();

        let update = send_and_pop_control(
            &observer,
            window.0,
            WT_DEFBASE + 3,
            context as usize,
            0x0004,
        );
        assert_eq!(update.message_id_raw, WT_DEFBASE + 3);
        assert_eq!(update.source, CaptureSource::WintabControlNotification);
        assert_eq!(update.observer_sequence, 0);
        assert_eq!(update.message_hwnd_raw_session_scoped, window.0);
        assert_eq!(update.wparam_raw, context as usize);
        assert_eq!(update.lparam_raw, 0x0004);
        assert!(update.app_observed_elapsed_ns > 0);

        let mut update_state = ProbeState::default();
        update_state.set_capture_mode(CaptureMode::Wintab);
        let mut update_capture = fake_capture(window.0, context);
        update_capture.handle_control_notification(update, &mut update_state);
        assert!(update_capture.context_configuration_stale);
        assert!(update_capture.close_requested());
        assert_eq!(update_state.summary().wintab_control_messages, 1);

        let overlap = send_and_pop_control(&observer, window.0, WT_DEFBASE + 4, 0x3344, 0x0002);
        assert_eq!(overlap.observer_sequence, 1);
        let mut overlap_state = ProbeState::default();
        overlap_state.set_capture_mode(CaptureMode::Wintab);
        let mut overlap_capture = fake_capture(window.0, context);
        overlap_capture.handle_control_notification(overlap, &mut overlap_state);
        assert_eq!(
            overlap_capture.latest_issue(),
            Some(WintabIssue::ContextOverlapChanged {
                related_context_raw_session_scoped: 0x3344,
                context_status_raw: 0x0002,
            })
        );
        assert!(overlap_capture.close_requested());

        let close = send_and_pop_control(
            &observer,
            window.0,
            WT_DEFBASE + 2,
            context as usize,
            0x0004,
        );
        assert_eq!(close.observer_sequence, 2);
        let mut close_state = ProbeState::default();
        close_state.set_capture_mode(CaptureMode::Wintab);
        let mut close_capture = fake_capture(window.0, context);
        close_capture.handle_control_notification(close, &mut close_state);
        assert_eq!(close_capture.context, None);
        assert_eq!(close_capture.status(), WintabStatus::Unavailable);

        observer.remove().unwrap();
    }

    #[test]
    fn initial_open_and_positive_self_top_overlap_clear_packet_block_after_safe_drain() {
        let window = TestWindow::new();
        let context = 0x1122_isize;
        let control_pending = Arc::new(AtomicBool::new(false));
        let mut observer = WintabControlObserver::install(
            window.0,
            WT_DEFBASE,
            Instant::now() - Duration::from_secs(1),
            Arc::clone(&control_pending),
        )
        .unwrap();
        let mut capture = fake_capture(window.0, context);
        capture.initial_context_overlap_pending = true;
        capture.packet_notification_seen = false;
        let mut state = ProbeState::default();
        state.set_capture_mode(CaptureMode::Wintab);

        let open = send_and_pop_control(
            &observer,
            window.0,
            WT_DEFBASE + 1,
            context as usize,
            CXS_ONTOP as isize,
        );
        let overlap = send_and_pop_control(
            &observer,
            window.0,
            WT_DEFBASE + 4,
            context as usize,
            CXS_ONTOP as isize,
        );
        assert!(control_pending.load(Ordering::Acquire));

        capture.handle_control_notification(open, &mut state);
        capture.handle_control_notification(overlap, &mut state);
        observer.clear_pending_if_idle(capture.control_state_valid());

        assert!(capture.packet_capture_enabled());
        assert!(!control_pending.load(Ordering::Acquire));
        assert_eq!(state.summary().wintab_control_messages, 2);

        observer.remove().unwrap();
    }

    #[test]
    fn posted_control_passes_hook_without_double_recording_then_reaches_subclass() {
        let window = TestWindow::new();
        let context = 0x1122_isize;
        let mut observer = WintabControlObserver::install(
            window.0,
            WT_DEFBASE,
            Instant::now() - Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let mut capture = fake_capture(window.0, context);
        let mut state = ProbeState::default();
        state.set_capture_mode(CaptureMode::Wintab);

        // SAFETY: the test HWND is live and this user message carries scalars.
        assert_ne!(
            unsafe { PostMessageW(window.0, WT_DEFBASE + 3, context as usize, 0x0004) },
            0
        );
        // SAFETY: `message` is zero-initialized writable MSG storage and the
        // queue filter targets this live window and posted control message.
        let mut message: MSG = unsafe { std::mem::zeroed() };
        assert_ne!(
            unsafe {
                PeekMessageW(
                    &mut message,
                    window.0,
                    WT_DEFBASE + 3,
                    WT_DEFBASE + 3,
                    PM_REMOVE,
                )
            },
            0
        );

        capture.handle_message(
            HookMessageMetadata {
                message_id_raw: message.message,
                message_hwnd_raw_session_scoped: message.hwnd,
                wparam_raw: message.wParam,
                lparam_raw: message.lParam,
                message_time_ms_raw: Some(message.time),
                pointer_id: 0,
            },
            10,
            20,
            &AtomicBool::new(false),
            &mut state,
        );
        assert_eq!(state.summary().wintab_control_messages, 0);

        // SAFETY: dispatches the MSG retrieved above to the test HWND; the
        // subclass forwards it to the original STATIC procedure.
        unsafe { DispatchMessageW(&message) };
        let control = observer.pop_pending().unwrap();
        capture.handle_control_notification(control, &mut state);
        assert_eq!(state.summary().wintab_control_messages, 1);
        assert_eq!(state.summary().wintab_issues, 1);
        assert!(observer.pop_pending().is_none());

        observer.remove().unwrap();
    }

    #[test]
    fn sent_context_change_blocks_next_queued_packet_until_safe_close() {
        let window = TestWindow::new();
        let context = 0x1122_isize;
        let control_pending = Arc::new(AtomicBool::new(false));
        let mut observer = WintabControlObserver::install(
            window.0,
            WT_DEFBASE,
            Instant::now() - Duration::from_secs(1),
            Arc::clone(&control_pending),
        )
        .unwrap();
        let mut capture = fake_capture(window.0, context);
        capture.api = Some(fake_close_api());
        let mut state = ProbeState::default();
        state.set_capture_mode(CaptureMode::Wintab);

        let update = send_and_pop_control(
            &observer,
            window.0,
            WT_DEFBASE + 3,
            context as usize,
            0x0004,
        );
        assert!(control_pending.load(Ordering::Acquire));

        let mut hook_api = fake_close_api();
        hook_api.queue_packets_ex = counting_queue_packets_ex;
        capture.api = Some(hook_api);
        capture.queue_capacity_raw = Some(128);
        QUEUE_QUERY_CALLS.store(0, Ordering::Relaxed);

        // Post a queued packet before the safe Winit callback consumes the
        // sent control notification.
        assert_ne!(unsafe { PostMessageW(window.0, WT_DEFBASE, 1, context) }, 0);
        let mut packet_message: MSG = unsafe { std::mem::zeroed() };
        assert_ne!(
            unsafe {
                PeekMessageW(
                    &mut packet_message,
                    window.0,
                    WT_DEFBASE,
                    WT_DEFBASE,
                    PM_REMOVE,
                )
            },
            0
        );
        assert_eq!(packet_message.message, WT_DEFBASE);
        assert!(!wintab_packet_hook_may_drain(&control_pending));
        if wintab_packet_hook_may_drain(&control_pending) {
            capture.handle_message(
                HookMessageMetadata {
                    message_id_raw: packet_message.message,
                    message_hwnd_raw_session_scoped: packet_message.hwnd,
                    wparam_raw: packet_message.wParam,
                    lparam_raw: packet_message.lParam,
                    message_time_ms_raw: Some(packet_message.time),
                    pointer_id: 0,
                },
                20,
                30,
                &control_pending,
                &mut state,
            );
        }
        assert_eq!(QUEUE_QUERY_CALLS.load(Ordering::Relaxed), 0);
        unsafe { DispatchMessageW(&packet_message) };
        assert_eq!(state.summary().wintab_packets, 0);

        capture.handle_control_notification(update, &mut state);
        assert!(capture.context_configuration_stale);
        assert!(capture.close_requested());
        observer.clear_pending_if_idle(capture.control_state_valid());
        assert!(control_pending.load(Ordering::Acquire));

        capture.close_after_stop_request(&mut state);
        assert_eq!(capture.context, None);
        assert_eq!(state.summary().wintab_packets, 0);
        assert_eq!(state.summary().samples, 0);

        observer.remove().unwrap();
    }

    #[test]
    fn reentrant_control_during_queue_query_prevents_any_packet_read() {
        let _serial = REENTRANT_CONTROL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let window = TestWindow::new();
        let context = 0x1122_isize;
        set_reentrant_test_context(window.0);
        let control_pending = Arc::new(AtomicBool::new(false));
        let mut observer = WintabControlObserver::install(
            window.0,
            WT_DEFBASE,
            Instant::now(),
            Arc::clone(&control_pending),
        )
        .unwrap();
        let mut capture = fake_capture(window.0, context);
        let mut api = fake_close_api();
        api.queue_packets_ex = control_during_queue_query;
        api.packets_get = counting_packets_get;
        capture.api = Some(api);
        capture.queue_capacity_raw = Some(128);
        let mut state = ProbeState::default();
        state.set_capture_mode(CaptureMode::Wintab);

        capture.handle_message(
            HookMessageMetadata {
                message_id_raw: WT_DEFBASE,
                message_hwnd_raw_session_scoped: window.0,
                wparam_raw: 1,
                lparam_raw: context,
                message_time_ms_raw: None,
                pointer_id: 0,
            },
            41,
            99,
            &control_pending,
            &mut state,
        );

        assert_eq!(REENTRANT_QUEUE_QUERY_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(REENTRANT_PACKET_READ_CALLS.load(Ordering::Relaxed), 0);
        assert!(control_pending.load(Ordering::Acquire));
        assert_eq!(state.summary().wintab_packets, 0);
        assert_eq!(
            state.summary().latest_wintab_issue,
            Some(WintabIssue::ControlTransitionObservedDuringDrain {
                operation: WintabPacketOperation::QueueQuery,
                returned_packets: None,
            })
        );
        assert!(capture.close_requested());
        let notification = observer.pop_pending().unwrap();
        assert_eq!(notification.message_id_raw, WT_DEFBASE + 3);
        assert_eq!(notification.wparam_raw, context as usize);
        assert_eq!(notification.message_hwnd_raw_session_scoped, window.0);
        observer.remove().unwrap();
    }

    #[test]
    fn reentrant_control_during_packet_read_stops_next_read_and_marks_batch_uncertain() {
        let _serial = REENTRANT_CONTROL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let window = TestWindow::new();
        let context = 0x1122_isize;
        set_reentrant_test_context(window.0);
        let control_pending = Arc::new(AtomicBool::new(false));
        let mut observer = WintabControlObserver::install(
            window.0,
            WT_DEFBASE,
            Instant::now(),
            Arc::clone(&control_pending),
        )
        .unwrap();
        let mut capture = fake_capture(window.0, context);
        capture.context_config = Some(test_context_config());
        let mut api = fake_close_api();
        api.queue_packets_ex = one_packet_queue_query;
        api.packets_get = control_during_packet_read;
        capture.api = Some(api);
        capture.queue_capacity_raw = Some(128);
        let mut state = ProbeState::default();
        state.set_capture_mode(CaptureMode::Wintab);

        capture.handle_message(
            HookMessageMetadata {
                message_id_raw: WT_DEFBASE,
                message_hwnd_raw_session_scoped: window.0,
                wparam_raw: 1,
                lparam_raw: context,
                message_time_ms_raw: None,
                pointer_id: 0,
            },
            42,
            100,
            &control_pending,
            &mut state,
        );

        assert_eq!(REENTRANT_QUEUE_QUERY_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(REENTRANT_PACKET_READ_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(state.summary().wintab_packets, 1);
        assert_eq!(
            state.summary().latest_wintab_issue,
            Some(WintabIssue::ControlTransitionObservedDuringDrain {
                operation: WintabPacketOperation::PacketRead,
                returned_packets: Some(1),
            })
        );
        let batch = state
            .retained_records()
            .iter()
            .find_map(|record| match record {
                ProbeRecord::WintabPackets(batch) => Some(batch),
                _ => None,
            })
            .expect("the packet returned during the control callback is retained raw");
        assert!(batch.control_transition_observed_during_read);
        assert_eq!(batch.packets.len(), 1);
        assert_eq!(batch.packets[0].serial_number_raw, 1);
        assert_eq!(capture.last_packet_serial_raw, None);
        assert!(capture.close_requested());

        let notification = observer.pop_pending().unwrap();
        capture.handle_control_notification(notification, &mut state);
        assert!(capture.context_configuration_stale);
        assert!(capture.close_requested());
        // Simulate the later safe Winit callback boundary: driver operations
        // happen only after the message hook has returned and released its
        // active capture borrow.
        capture.close_after_stop_request(&mut state);
        assert_eq!(capture.context, None);
        assert_eq!(REENTRANT_QUEUE_QUERY_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(REENTRANT_PACKET_READ_CALLS.load(Ordering::Relaxed), 1);
        observer.remove().unwrap();
    }

    #[test]
    fn subclass_pending_queue_is_bounded_and_reports_overflow() {
        let observer = ControlObserverState {
            message_base: AtomicU32::new(WT_DEFBASE),
            control_pending: Arc::new(AtomicBool::new(false)),
            app_clock_origin: Instant::now(),
            pending: Mutex::new(PendingControlQueue::default()),
        };
        for sequence in 0..=MAX_PENDING_CONTROL_MESSAGES {
            observer.observe(0x1111, WT_DEFBASE + 6, sequence, sequence as isize);
        }
        observer.note_callback_panic();

        let mut retained = 0usize;
        while observer.pop().is_some() {
            retained += 1;
        }
        assert_eq!(retained, MAX_PENDING_CONTROL_MESSAGES);
        assert_eq!(
            observer.take_diagnostics(),
            ControlObserverDiagnostics {
                dropped_messages: 1,
                callback_panics: 1,
            }
        );
    }

    #[test]
    fn queue_size_retries_smaller_until_a_128_capacity_is_accepted() {
        let mut tried = Vec::new();
        let selected = first_supported_queue_size(&QUEUE_SIZE_ATTEMPTS, |requested| {
            tried.push(requested);
            requested <= 128
        });

        assert_eq!(selected, Some(128));
        assert_eq!(tried, vec![4096, 2048, 1024, 512, 256, 128]);
        assert_eq!(QUEUE_SIZE_ATTEMPTS.last(), Some(&1));
        assert_eq!(
            first_supported_queue_size(&QUEUE_SIZE_ATTEMPTS, |requested| requested == 1),
            Some(1)
        );
    }

    #[test]
    fn one_initial_packet_and_a_normal_arrival_do_not_hit_the_drain_limit() {
        let initial_queue = QueueRange {
            available: 1,
            issue: None,
            zero_range_ambiguous: false,
        };
        let output_capacity = bounded_message_output_capacity(10_000);
        assert_eq!(initial_queue.available, 1);
        assert_eq!(output_capacity, MAX_PACKETS_PER_MESSAGE);

        // Initial queue=1: the initial packet was read, then one ordinary
        // packet arrived before the final queue query. A pending row under both
        // budgets is not a drain-limit signal.
        let normal_arrival = QueueRange {
            available: 1,
            issue: None,
            zero_range_ambiguous: false,
        };
        assert_eq!(
            drain_limit_issue(
                1,
                output_capacity,
                1,
                MAX_DRAIN_ROUNDS,
                Some(normal_arrival)
            ),
            None
        );

        // A second query after that arrival has drained confirms the empty
        // queue without reporting loss.
        assert_eq!(
            drain_limit_issue(2, output_capacity, 3, MAX_DRAIN_ROUNDS, None),
            None
        );
    }

    #[test]
    fn drain_limit_reports_only_a_bounded_pending_range() {
        let pending = QueueRange {
            available: 3,
            issue: None,
            zero_range_ambiguous: false,
        };
        assert_eq!(exact_queue_count(pending), Some(3));
        assert_eq!(
            drain_limit_issue(4096, 4096, 16, 16, Some(pending)),
            Some(WintabIssue::DrainLimitReached {
                pending_packets_reported: Some(3),
                drain_rounds: 16,
            })
        );
        let ambiguous = QueueRange {
            available: 1,
            issue: None,
            zero_range_ambiguous: true,
        };
        assert_eq!(
            drain_limit_issue(4096, 4096, 16, 16, Some(ambiguous)),
            Some(WintabIssue::DrainLimitReached {
                pending_packets_reported: None,
                drain_rounds: 16,
            })
        );
    }

    #[test]
    fn true_zero_zero_queue_range_is_probed_and_can_preserve_serial_zero() {
        let context = 0x1122_isize;
        let proximity_metadata = HookMessageMetadata {
            message_id_raw: WT_DEFBASE + 5,
            message_hwnd_raw_session_scoped: 0x3344,
            wparam_raw: context as usize,
            lparam_raw: 1,
            message_time_ms_raw: None,
            pointer_id: 0,
        };
        assert_eq!(
            queue_trigger(proximity_metadata, WT_DEFBASE, context),
            Some(WintabQueueTrigger::Proximity)
        );

        let range = interpret_queue_query(true, 0, 0, None, None, 256)
            .unwrap()
            .unwrap();
        assert!(range.zero_range_ambiguous);
        assert_eq!(range.available, 1);
        assert!(zero_range_probe_is_empty(range, 0));
        assert!(!zero_range_probe_is_empty(range, 1));
        assert_eq!(exact_queue_count(range), None);

        let sample = wintab_packet_sample(WintabPacketLayout {
            serial_number: 0,
            ..WintabPacketLayout::default()
        });
        assert_eq!(sample.serial_number_raw, 0);

        let after_prior_serial = interpret_queue_query(true, 0, 0, None, Some(5), 256)
            .unwrap()
            .unwrap();
        assert!(after_prior_serial.zero_range_ambiguous);
        assert!(!zero_range_probe_is_empty(after_prior_serial, 1));

        let after_packet_notification = interpret_queue_query(true, 0, 0, Some(7), Some(5), 256)
            .unwrap()
            .unwrap();
        assert!(after_packet_notification.zero_range_ambiguous);
        assert!(zero_range_probe_is_empty(after_packet_notification, 0));
        assert!(!zero_range_probe_is_empty(after_packet_notification, 1));

        let wrapped = interpret_queue_query(true, 0, 0, None, Some(u32::MAX), 256)
            .unwrap()
            .unwrap();
        assert!(wrapped.zero_range_ambiguous);
    }

    #[test]
    fn false_queue_query_is_not_swallowed_as_an_empty_duplicate() {
        assert!(matches!(
            interpret_queue_query(false, 0, 0, Some(7), Some(7), 256),
            Err(WintabIssue::QueueQueryFailed)
        ));
    }

    #[test]
    fn reported_queue_range_counts_across_the_serial_wrap() {
        let range = interpret_queue_query(true, u32::MAX - 1, 1, None, None, 256)
            .unwrap()
            .unwrap();
        assert_eq!(range.available, 4);
        assert!(!range.zero_range_ambiguous);
    }

    #[test]
    fn secure_library_path_appends_only_the_system_dll_name() {
        let system_directory = "C:\\Windows\\System32".encode_utf16().collect::<Vec<_>>();
        let path = build_system_wintab_path(&system_directory).unwrap();
        let nul = path.iter().position(|unit| *unit == 0).unwrap();
        assert_eq!(
            String::from_utf16(&path[..nul]).unwrap(),
            "C:\\Windows\\System32\\Wintab32.dll"
        );

        let system_directory = "C:\\Windows\\System32\\".encode_utf16().collect::<Vec<_>>();
        let path = build_system_wintab_path(&system_directory).unwrap();
        let nul = path.iter().position(|unit| *unit == 0).unwrap();
        assert_eq!(
            String::from_utf16(&path[..nul]).unwrap(),
            "C:\\Windows\\System32\\Wintab32.dll"
        );
    }

    #[test]
    fn wintab_packet_mapping_keeps_each_native_field_raw() {
        let packet = WintabPacketLayout {
            context: 0x1122,
            status: 0x33,
            time: u32::MAX,
            serial_number: 0x4455,
            cursor: 6,
            buttons: 0x77,
            x: -8,
            y: 9,
            normal_pressure: 1025,
        };
        let sample = wintab_packet_sample(packet);
        assert_eq!(sample.context_handle_raw_session_scoped, 0x1122);
        assert_eq!(sample.status_raw, 0x33);
        assert_eq!(sample.packet_time_raw, u32::MAX);
        assert_eq!(sample.serial_number_raw, 0x4455);
        assert_eq!(sample.cursor_raw, 6);
        assert_eq!(sample.buttons_raw, 0x77);
        assert_eq!(sample.x_raw, -8);
        assert_eq!(sample.y_raw, 9);
        assert_eq!(sample.normal_pressure_raw, 1025);
    }

    #[test]
    fn wintab_context_snapshot_preserves_mapping_and_modes_raw() {
        // SAFETY: LOGCONTEXTA contains fixed-width scalar fields and a character
        // array; its all-zero representation is valid for this pure mapping test.
        let mut context: LogContextA = unsafe { std::mem::zeroed() };
        context.name[0] = b'L' as _;
        context.options = CXO_MESSAGES;
        context.message_base = WT_DEFBASE;
        context.device = 3;
        context.packet_data = PK_PACKET_DATA;
        context.packet_mode = PK_TIME;
        context.input_origin_x = 10;
        context.input_extent_y = 20;
        context.output_origin_x = -30;
        context.output_extent_y = 40;
        context.system_mode = 1;
        context.system_extent_x = 1920;

        let snapshot = wintab_context_config(&context);
        assert_eq!(snapshot.context_name_raw[0], b'L');
        assert_eq!(snapshot.options_raw, CXO_MESSAGES);
        assert_eq!(snapshot.device_raw, 3);
        assert_eq!(snapshot.packet_data_raw, PK_PACKET_DATA);
        assert_eq!(snapshot.packet_mode_raw, PK_TIME);
        assert_eq!(snapshot.input_origin_raw, [10, 0, 0]);
        assert_eq!(snapshot.input_extent_raw, [0, 20, 0]);
        assert_eq!(snapshot.output_origin_raw, [-30, 0, 0]);
        assert_eq!(snapshot.output_extent_raw, [0, 40, 0]);
        assert_eq!(snapshot.system_mode_raw, 1);
        assert_eq!(snapshot.system_extent_raw, [1920, 0]);
    }
}
