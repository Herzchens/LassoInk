//! Versioned, source-agnostic recognition worker protocol for M4.
//!
//! This module defines a bounded local JSON/stdio boundary only. It does not
//! register or ship a recognition provider, write results into the project
//! journal, or select a capture source. Callers must supply an explicit
//! operator-approved absolute executable path; project metadata is never a
//! launch configuration source.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    fmt,
    io::{self, Read, Write},
    marker::PhantomData,
    panic::AssertUnwindSafe,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use serde::{
    Deserialize, Deserializer, Serialize, de::Error as DeError, de::SeqAccess, de::Visitor,
};
use serde_json::Value;

#[cfg(windows)]
#[path = "provider_windows.rs"]
mod windows_process;

use crate::journal::{
    JournalReplayState, NativeTimestamp, PhysicalSample, RawPosition, RawPressure, StrokeRef,
    StrokeViewFrame,
};

pub(crate) const PROVIDER_PROTOCOL_VERSION: u32 = 1;
const MAX_HANDSHAKE_FRAME_BYTES: usize = 64 * 1024;
const MAX_REQUEST_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_FRAME_BYTES: usize = 2 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_STROKES: usize = 512;
const MAX_PROVIDER_SAMPLES: usize = 4096;
const MAX_PROVIDER_CANDIDATES: usize = 128;
const MAX_PROVIDER_STROKE_RANGES: usize = 256;
const MAX_RAW_SAMPLE_BYTES: usize = 8192;
const MAX_TOTAL_RAW_SAMPLE_BYTES: usize = 1024 * 1024;
const MAX_RAW_PROVIDER_RESPONSE_FRAMES: usize = 3;
const MAX_RAW_PROVIDER_RESPONSE_BYTES: usize =
    MAX_HANDSHAKE_FRAME_BYTES + MAX_RESPONSE_FRAME_BYTES * 2;
const MAX_ID_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_LANGUAGE_HINTS: usize = 16;
const MAX_LANGUAGE_TAG_BYTES: usize = 32;
const MAX_SETTINGS: usize = 128;
const MAX_SETTING_KEY_BYTES: usize = 128;
const MAX_SETTING_VALUE_BYTES: usize = 2048;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 2048;
const IO_POLL_INTERVAL: Duration = Duration::from_millis(10);
const CHILD_CLEANUP_GRACE: Duration = Duration::from_millis(500);
const MAX_PROVIDER_WORKER_THREADS: usize = 8;

#[derive(Default)]
struct ProviderWorkerThreadRegistry {
    handles: Vec<thread::JoinHandle<()>>,
    reserved: usize,
}

static PROVIDER_WORKER_THREADS: OnceLock<Mutex<ProviderWorkerThreadRegistry>> = OnceLock::new();

struct ProviderWorkerThreadPermit {
    active: bool,
}

fn provider_worker_thread_registry() -> &'static Mutex<ProviderWorkerThreadRegistry> {
    PROVIDER_WORKER_THREADS.get_or_init(|| Mutex::new(ProviderWorkerThreadRegistry::default()))
}

fn reserve_provider_worker_thread() -> Result<ProviderWorkerThreadPermit, ProviderErrorKind> {
    let registry = provider_worker_thread_registry();
    let mut registry = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reap_provider_worker_threads_locked(&mut registry);
    if registry.handles.len().saturating_add(registry.reserved) >= MAX_PROVIDER_WORKER_THREADS {
        return Err(ProviderErrorKind::WorkerCapacityReached);
    }
    let required_reservations = registry.reserved.saturating_add(1);
    registry
        .handles
        .try_reserve(required_reservations)
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    registry.reserved += 1;
    Ok(ProviderWorkerThreadPermit { active: true })
}

impl ProviderWorkerThreadPermit {
    fn register(mut self, handle: thread::JoinHandle<()>) {
        let registry = provider_worker_thread_registry();
        let mut registry = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.reserved = registry.reserved.saturating_sub(1);
        registry.handles.push(handle);
        self.active = false;
    }
}

impl Drop for ProviderWorkerThreadPermit {
    fn drop(&mut self) {
        if self.active {
            let registry = provider_worker_thread_registry();
            let mut registry = registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.reserved = registry.reserved.saturating_sub(1);
        }
    }
}

fn reap_provider_worker_threads() {
    let registry = provider_worker_thread_registry();
    let mut registry = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reap_provider_worker_threads_locked(&mut registry);
}

fn reap_provider_worker_threads_locked(registry: &mut ProviderWorkerThreadRegistry) {
    let mut index = 0;
    while index < registry.handles.len() {
        if registry.handles[index].is_finished() {
            let handle = registry.handles.swap_remove(index);
            let _ = handle.join();
        } else {
            index += 1;
        }
    }
}

#[cfg(any(windows, test))]
fn cleanup_failure_or_original(
    original: ProviderErrorKind,
    cleanup: Result<(), String>,
) -> ProviderErrorKind {
    match cleanup {
        Ok(()) => original,
        Err(cleanup_error) => ProviderErrorKind::ProcessCleanupFailed(format!(
            "original request failure: {original}; {cleanup_error}"
        )),
    }
}

#[cfg(windows)]
const MAX_QUARANTINED_PROVIDER_SESSIONS: usize = 4;

#[cfg(windows)]
struct QuarantinedProviderSession {
    child: Option<windows_process::NativeChild>,
    helpers: Vec<thread::JoinHandle<()>>,
}

#[cfg(windows)]
const MAX_PROVIDER_HELPER_THREADS: usize = 3;

#[cfg(windows)]
#[derive(Default)]
struct ProcessCleanupRegistry {
    sessions: Vec<QuarantinedProviderSession>,
    reserved: usize,
}

#[cfg(windows)]
static PROCESS_CLEANUP_REGISTRY: OnceLock<Mutex<ProcessCleanupRegistry>> = OnceLock::new();

#[cfg(windows)]
struct ProcessCleanupPermit {
    active: bool,
}

#[cfg(windows)]
fn process_cleanup_registry() -> &'static Mutex<ProcessCleanupRegistry> {
    PROCESS_CLEANUP_REGISTRY.get_or_init(|| Mutex::new(ProcessCleanupRegistry::default()))
}

#[cfg(windows)]
fn reserve_process_cleanup_slot() -> Result<ProcessCleanupPermit, ProviderErrorKind> {
    let registry = process_cleanup_registry();
    let mut registry = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reap_process_cleanup_registry_locked(&mut registry);
    ensure_no_quarantined_provider_sessions(registry.sessions.len())?;
    if registry.sessions.len().saturating_add(registry.reserved)
        >= MAX_QUARANTINED_PROVIDER_SESSIONS
    {
        return Err(ProviderErrorKind::WorkerCapacityReached);
    }
    let required_reservations = registry.reserved.saturating_add(1);
    registry
        .sessions
        .try_reserve(required_reservations)
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    registry.reserved += 1;
    Ok(ProcessCleanupPermit { active: true })
}

#[cfg(any(windows, test))]
fn ensure_no_quarantined_provider_sessions(count: usize) -> Result<(), ProviderErrorKind> {
    if count == 0 {
        Ok(())
    } else {
        Err(ProviderErrorKind::WorkerSubsystemPoisoned)
    }
}

#[cfg(any(windows, test))]
fn quarantine_can_release(
    tree_reaped: bool,
    helpers_finished: bool,
    child_handles_closed: bool,
) -> bool {
    tree_reaped && helpers_finished && child_handles_closed
}

#[cfg(windows)]
impl ProcessCleanupPermit {
    fn release(&mut self) {
        if self.active {
            let registry = process_cleanup_registry();
            let mut registry = registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.reserved = registry.reserved.saturating_sub(1);
            self.active = false;
        }
    }

    fn quarantine(
        &mut self,
        child: Option<windows_process::NativeChild>,
        helpers: Vec<thread::JoinHandle<()>>,
    ) {
        let registry = process_cleanup_registry();
        let mut registry = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.reserved = registry.reserved.saturating_sub(1);
        registry
            .sessions
            .push(QuarantinedProviderSession { child, helpers });
        self.active = false;
    }
}

#[cfg(windows)]
impl Drop for ProcessCleanupPermit {
    fn drop(&mut self) {
        if self.active {
            let registry = process_cleanup_registry();
            let mut registry = registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.reserved = registry.reserved.saturating_sub(1);
        }
    }
}

#[cfg(windows)]
fn reap_process_cleanup_registry_locked(registry: &mut ProcessCleanupRegistry) {
    let mut session_index = 0;
    while session_index < registry.sessions.len() {
        let session = &mut registry.sessions[session_index];
        let tree_reaped = session
            .child
            .as_mut()
            .is_none_or(|child| child.terminate_and_reap(Duration::ZERO));
        if tree_reaped {
            for helper in &session.helpers {
                if !helper.is_finished() {
                    windows_process::cancel_synchronous_io(helper);
                }
            }
            let mut helper_index = 0;
            while helper_index < session.helpers.len() {
                if session.helpers[helper_index].is_finished() {
                    let helper = session.helpers.swap_remove(helper_index);
                    let _ = helper.join();
                    continue;
                }
                helper_index += 1;
            }
            if session.helpers.is_empty()
                && session
                    .child
                    .as_mut()
                    .is_none_or(|child| child.close_job().is_ok())
                && let Some(child) = session.child.as_mut()
            {
                child.clear_quarantined_fault_after_reap();
            }
        }
        if quarantine_can_release(
            tree_reaped,
            session.helpers.is_empty(),
            session
                .child
                .as_ref()
                .is_none_or(windows_process::NativeChild::is_closed),
        ) {
            registry.sessions.swap_remove(session_index);
        } else {
            session_index += 1;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderSourceRevisionV1 {
    pub journal_id: String,
    pub logical_revision: u64,
    /// Exact submitted journal prefix; results must echo this value, but it is
    /// not by itself a current-view freshness test.
    pub last_sequence: u64,
}

impl ProviderSourceRevisionV1 {
    pub(crate) fn from_journal(state: &JournalReplayState) -> Self {
        Self {
            journal_id: state.journal_id.clone(),
            logical_revision: state.logical_revision,
            last_sequence: state.last_sequence,
        }
    }

    fn validate(&self) -> Result<(), ProviderErrorKind> {
        validate_text(&self.journal_id, MAX_ID_BYTES, "journal ID")?;
        if self.journal_id.is_empty() {
            return Err(ProviderErrorKind::InvalidRequest(
                "source journal ID must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderConfigurationV1 {
    pub configuration_id: String,
    pub values: BTreeMap<String, String>,
}

impl ProviderConfigurationV1 {
    fn validate(&self) -> Result<(), ProviderErrorKind> {
        validate_text(&self.configuration_id, MAX_ID_BYTES, "provider config ID")?;
        if self.configuration_id.is_empty() || self.values.len() > MAX_SETTINGS {
            return Err(ProviderErrorKind::InvalidRequest(
                "provider configuration is empty or exceeds its entry cap".to_owned(),
            ));
        }
        let mut total_bytes = self.configuration_id.len();
        for (key, value) in &self.values {
            validate_text(key, MAX_SETTING_KEY_BYTES, "provider setting key")?;
            validate_text(value, MAX_SETTING_VALUE_BYTES, "provider setting value")?;
            if key.is_empty() {
                return Err(ProviderErrorKind::InvalidRequest(
                    "provider setting keys must not be empty".to_owned(),
                ));
            }
            total_bytes = total_bytes
                .checked_add(key.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or_else(|| {
                    ProviderErrorKind::InvalidRequest(
                        "provider configuration size overflow".to_owned(),
                    )
                })?;
        }
        if total_bytes > MAX_REQUEST_FRAME_BYTES / 4 {
            return Err(ProviderErrorKind::InvalidRequest(
                "provider configuration exceeds its byte cap".to_owned(),
            ));
        }
        Ok(())
    }

    fn fingerprint(&self) -> Result<String, ProviderErrorKind> {
        self.validate()?;
        let bytes = bounded_json_bytes(self, MAX_REQUEST_FRAME_BYTES / 4)?;
        let hash = bytes.into_iter().fold(0xcbf29ce484222325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        });
        // This binds a result to the exact operator-supplied settings; it is
        // an identifier, not an authentication or integrity signature.
        Ok(format!("provider-config-v1-fnv64-{hash:016x}"))
    }
}

/// This type can only be created from explicit caller-supplied configuration.
/// There is deliberately no conversion from journal metadata or provider
/// results, so opening a project cannot launch a metadata-selected program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperatorApprovedProviderConfig {
    provider_id: String,
    executable: PathBuf,
    arguments: Vec<String>,
    protocol_configuration: ProviderConfigurationV1,
}

impl OperatorApprovedProviderConfig {
    pub(crate) fn from_explicit_selection(
        provider_id: String,
        executable: PathBuf,
        arguments: Vec<String>,
        protocol_configuration: ProviderConfigurationV1,
    ) -> Result<Self, ProviderErrorKind> {
        validate_text(&provider_id, MAX_ID_BYTES, "provider ID")?;
        if provider_id.is_empty()
            || !executable.is_absolute()
            || executable.to_string_lossy().len() > MAX_ARGUMENT_BYTES
        {
            return Err(ProviderErrorKind::InvalidConfiguration(
                "provider ID must be nonempty and executable path must be absolute and bounded"
                    .to_owned(),
            ));
        }
        if arguments.len() > MAX_ARGUMENTS
            || arguments
                .iter()
                .any(|argument| argument.len() > MAX_ARGUMENT_BYTES)
            || arguments.iter().map(String::len).sum::<usize>() > 16 * 1024
        {
            return Err(ProviderErrorKind::InvalidConfiguration(
                "provider command arguments exceed configured bounds".to_owned(),
            ));
        }
        protocol_configuration.validate()?;
        Ok(Self {
            provider_id,
            executable,
            arguments,
            protocol_configuration,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderStrokeRefV1 {
    pub journal_id: String,
    pub session_id: String,
    pub source_api: String,
    pub device_id: Option<String>,
    pub pointer_id: Option<u64>,
    pub stroke_id: String,
}

impl From<&StrokeRef> for ProviderStrokeRefV1 {
    fn from(stroke: &StrokeRef) -> Self {
        Self {
            journal_id: stroke.journal_id.clone(),
            session_id: stroke.session_id.clone(),
            source_api: stroke.source_api.clone(),
            device_id: stroke.device_id.clone(),
            pointer_id: stroke.pointer_id,
            stroke_id: stroke.stroke_id.clone(),
        }
    }
}

impl ProviderStrokeRefV1 {
    fn validate(&self) -> Result<(), ProviderErrorKind> {
        for (value, label) in [
            (self.journal_id.as_str(), "stroke journal ID"),
            (self.session_id.as_str(), "stroke session ID"),
            (self.source_api.as_str(), "stroke source API"),
            (self.stroke_id.as_str(), "stroke ID"),
        ] {
            validate_text(value, MAX_ID_BYTES, label)?;
            if value.is_empty() {
                return Err(ProviderErrorKind::InvalidRequest(format!(
                    "{label} must not be empty"
                )));
            }
        }
        if let Some(device_id) = &self.device_id {
            validate_text(device_id, MAX_ID_BYTES, "stroke device ID")?;
            if device_id.is_empty() {
                return Err(ProviderErrorKind::InvalidRequest(
                    "stroke device ID must not be empty when present".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderViewFrameV1 {
    pub screen_origin_x_px: i64,
    pub screen_origin_y_px: i64,
    pub dpi_scale_factor_bits: u64,
    pub canvas_zoom_bits: u64,
    pub canvas_pan_x_bits: u64,
    pub canvas_pan_y_bits: u64,
    pub toolbar_height_px: u32,
}

impl From<StrokeViewFrame> for ProviderViewFrameV1 {
    fn from(frame: StrokeViewFrame) -> Self {
        Self {
            screen_origin_x_px: frame.screen_origin_x_px,
            screen_origin_y_px: frame.screen_origin_y_px,
            dpi_scale_factor_bits: frame.dpi_scale_factor_bits,
            canvas_zoom_bits: frame.canvas_zoom_bits,
            canvas_pan_x_bits: frame.canvas_pan_x_bits,
            canvas_pan_y_bits: frame.canvas_pan_y_bits,
            toolbar_height_px: frame.toolbar_height_px,
        }
    }
}

impl ProviderViewFrameV1 {
    fn validate(self) -> Result<(), ProviderErrorKind> {
        let dpi = f64::from_bits(self.dpi_scale_factor_bits);
        let zoom = f64::from_bits(self.canvas_zoom_bits);
        let pan_x = f64::from_bits(self.canvas_pan_x_bits);
        let pan_y = f64::from_bits(self.canvas_pan_y_bits);
        if !dpi.is_finite()
            || dpi <= 0.0
            || !zoom.is_finite()
            || !(0.2..=8.0).contains(&zoom)
            || !pan_x.is_finite()
            || !pan_y.is_finite()
            || self.toolbar_height_px > 4096
        {
            return Err(ProviderErrorKind::InvalidRequest(
                "stroke view frame is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderStrokeViewV1 {
    pub stroke: ProviderStrokeRefV1,
    /// Absent for legacy rows that have no persisted per-stroke view frame.
    pub view_frame: Option<ProviderViewFrameV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderPositionV1 {
    pub coordinate_space: String,
    pub units: String,
    pub x_raw: i64,
    pub y_raw: i64,
}

impl From<&RawPosition> for ProviderPositionV1 {
    fn from(position: &RawPosition) -> Self {
        Self {
            coordinate_space: position.coordinate_space.clone(),
            units: position.units.clone(),
            x_raw: position.x_raw,
            y_raw: position.y_raw,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderPressureV1 {
    pub representation: String,
    pub units: String,
    pub value_raw: u64,
    pub mask_raw: Option<u64>,
    pub minimum_raw: Option<u64>,
    pub maximum_raw: Option<u64>,
}

impl From<&RawPressure> for ProviderPressureV1 {
    fn from(pressure: &RawPressure) -> Self {
        Self {
            representation: pressure.representation.clone(),
            units: pressure.units.clone(),
            value_raw: pressure.value_raw,
            mask_raw: pressure.mask_raw,
            minimum_raw: pressure.minimum_raw,
            maximum_raw: pressure.maximum_raw,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderNativeTimestampV1 {
    pub clock_domain: String,
    pub units: String,
    pub count_raw: u64,
    pub frequency_hz: Option<u64>,
}

impl From<&NativeTimestamp> for ProviderNativeTimestampV1 {
    fn from(timestamp: &NativeTimestamp) -> Self {
        Self {
            clock_domain: timestamp.clock_domain.clone(),
            units: timestamp.units.clone(),
            count_raw: timestamp.count_raw,
            frequency_hz: timestamp.frequency_hz,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderSampleV1 {
    /// Canonical order in the append-only journal. Never timestamp-sorted.
    pub journal_sequence: u64,
    /// Original source sequence, retained separately from journal order.
    pub source_sequence_raw: u64,
    pub stroke: ProviderStrokeRefV1,
    pub app_arrival_elapsed_ns_decimal: String,
    pub config_id: Option<String>,
    pub position: Option<ProviderPositionV1>,
    /// Logical/document position after append-only edits. The raw sample
    /// position above remains unchanged and separately preserved.
    pub effective_position: Option<ProviderPositionV1>,
    pub pressure: Option<ProviderPressureV1>,
    pub native_timestamp: Option<ProviderNativeTimestampV1>,
    pub contact_range_state: Option<String>,
    pub button_state_raw: Option<u64>,
    pub tilt_x_raw: Option<i32>,
    pub tilt_y_raw: Option<i32>,
    pub rotation_raw: Option<u64>,
    /// Exact sample bytes represented as lowercase hex so JSON does not
    /// coerce a byte array or normalize source-specific fields.
    pub raw_payload_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderRasterInputV1 {
    pub width: u32,
    pub height: u32,
    /// The protocol preserves this as opaque bytes and does not decode a pixel layout.
    pub payload_contract: ProviderRasterPayloadContractV1,
    pub coordinate_space: String,
    pub units: String,
    pub raw_payload_hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProviderRasterPayloadContractV1 {
    OpaqueBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecognitionRequestV1 {
    pub protocol_version: u32,
    pub request_id: String,
    pub input_view_id: String,
    pub source_revision: ProviderSourceRevisionV1,
    pub region_id: String,
    pub line_id: String,
    pub coordinate_space: String,
    pub coordinate_units: String,
    pub language_hints: Vec<String>,
    /// Required provider inputs. Online samples remain canonical provenance for raster-only calls.
    pub requested_input_modalities: Vec<ProviderInputCapabilityV1>,
    pub provider_configuration: ProviderConfigurationV1,
    pub provider_configuration_fingerprint: String,
    pub stroke_views: Vec<ProviderStrokeViewV1>,
    /// Flat canonical sequence across selected strokes, not a render-plan sort.
    pub samples: Vec<ProviderSampleV1>,
    pub raster: Option<ProviderRasterInputV1>,
}

#[derive(Serialize)]
struct RequestFingerprintV1<'a> {
    protocol_version: u32,
    source_journal_id: &'a str,
    logical_revision: u64,
    region_id: &'a str,
    line_id: &'a str,
    coordinate_space: &'a str,
    coordinate_units: &'a str,
    language_hints: &'a [String],
    requested_input_modalities: &'a [ProviderInputCapabilityV1],
    stroke_views: &'a [ProviderStrokeViewV1],
    samples: &'a [ProviderSampleV1],
    raster: &'a Option<ProviderRasterInputV1>,
}

/// Explicit inputs for building a bounded recognition request from one journal view.
pub(crate) struct RecognitionRequestBuildInput<'a> {
    pub(crate) state: &'a JournalReplayState,
    pub(crate) request_id: String,
    pub(crate) region_id: String,
    pub(crate) line_id: String,
    pub(crate) coordinate_space: String,
    pub(crate) coordinate_units: String,
    pub(crate) language_hints: Vec<String>,
    pub(crate) requested_input_modalities: Vec<ProviderInputCapabilityV1>,
    pub(crate) provider_configuration: ProviderConfigurationV1,
    pub(crate) selected_strokes: &'a [StrokeRef],
    pub(crate) raster: Option<ProviderRasterInputV1>,
}

/// Snapshot and hash the journal-selected view for provider work. This bounded
/// projection is O(selected samples); callers should schedule it on the
/// provider preparation worker rather than the redraw/event loop.
pub(crate) fn build_recognition_request(
    input: RecognitionRequestBuildInput<'_>,
) -> Result<RecognitionRequestV1, ProviderErrorKind> {
    let RecognitionRequestBuildInput {
        state,
        request_id,
        region_id,
        line_id,
        coordinate_space,
        coordinate_units,
        language_hints,
        requested_input_modalities,
        provider_configuration,
        selected_strokes,
        raster,
    } = input;
    validate_text(&state.journal_id, MAX_ID_BYTES, "journal ID")?;
    if state.journal_id.is_empty() {
        return Err(ProviderErrorKind::InvalidRequest(
            "source journal ID must not be empty".to_owned(),
        ));
    }
    let source_revision = ProviderSourceRevisionV1::from_journal(state);
    source_revision.validate()?;
    validate_text(&request_id, MAX_ID_BYTES, "request ID")?;
    validate_text(&region_id, MAX_ID_BYTES, "region ID")?;
    validate_text(&line_id, MAX_ID_BYTES, "line ID")?;
    validate_text(&coordinate_space, MAX_ID_BYTES, "request coordinate space")?;
    validate_text(&coordinate_units, MAX_ID_BYTES, "request coordinate units")?;
    if request_id.is_empty()
        || region_id.is_empty()
        || line_id.is_empty()
        || coordinate_space.is_empty()
        || coordinate_units.is_empty()
    {
        return Err(ProviderErrorKind::InvalidRequest(
            "request and region/line/coordinate identifiers must be nonempty".to_owned(),
        ));
    }
    validate_language_hints(&language_hints)?;
    provider_configuration.validate()?;
    let provider_configuration_fingerprint = provider_configuration.fingerprint()?;
    if selected_strokes.is_empty() || selected_strokes.len() > MAX_PROVIDER_STROKES {
        return Err(ProviderErrorKind::InvalidRequest(
            "selected stroke count is empty or exceeds the protocol cap".to_owned(),
        ));
    }
    let mut selected = HashSet::new();
    selected
        .try_reserve(selected_strokes.len())
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    for stroke in selected_strokes {
        if stroke.journal_id != state.journal_id {
            return Err(ProviderErrorKind::InvalidRequest(
                "selected StrokeRef belongs to another project journal".to_owned(),
            ));
        }
        validate_core_stroke_ref(stroke)?;
        selected.insert(stroke.clone());
    }

    let projected = state
        .projected_samples()
        .map_err(|error| ProviderErrorKind::InvalidRequest(error.to_string()))?;
    let mut stroke_views = Vec::new();
    stroke_views
        .try_reserve(selected_strokes.len())
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    let mut seen_strokes = HashSet::new();
    seen_strokes
        .try_reserve(selected_strokes.len())
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    let mut samples = Vec::new();
    let sample_capacity = projected
        .iter()
        .filter(|sample| {
            sample
                .stroke_ref
                .as_ref()
                .is_some_and(|stroke| selected.contains(stroke))
        })
        .count();
    if sample_capacity == 0 || sample_capacity > MAX_PROVIDER_SAMPLES {
        return Err(ProviderErrorKind::InvalidRequest(
            "selected strokes have no visible samples or exceed the sample cap".to_owned(),
        ));
    }
    samples
        .try_reserve_exact(sample_capacity)
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    let mut total_raw_payload_bytes = 0usize;
    for projected_sample in projected {
        let Some(stroke) = projected_sample.stroke_ref.as_ref() else {
            continue;
        };
        if !selected.contains(stroke) {
            continue;
        }
        if seen_strokes.insert(stroke.clone()) {
            validate_core_stroke_ref(stroke)?;
            let view_frame = state
                .stroke_starts
                .iter()
                .find(|start| start.target == *stroke)
                .map(|start| ProviderViewFrameV1::from(start.view_frame));
            stroke_views.push(ProviderStrokeViewV1 {
                stroke: ProviderStrokeRefV1::from(stroke),
                view_frame,
            });
        }
        total_raw_payload_bytes = total_raw_payload_bytes
            .checked_add(projected_sample.sample.raw_payload.len())
            .ok_or_else(|| {
                ProviderErrorKind::InvalidRequest("raw sample byte count overflow".to_owned())
            })?;
        if projected_sample.sample.raw_payload.len() > MAX_RAW_SAMPLE_BYTES
            || total_raw_payload_bytes > MAX_TOTAL_RAW_SAMPLE_BYTES
        {
            return Err(ProviderErrorKind::InvalidRequest(
                "selected raw sample payload exceeds the protocol byte cap".to_owned(),
            ));
        }
        validate_source_sample(projected_sample.sample)?;
        samples.push(provider_sample(
            projected_sample.sequence,
            projected_sample.sample,
            projected_sample.effective_position.as_ref(),
            stroke,
        )?);
    }
    if seen_strokes != selected {
        return Err(ProviderErrorKind::InvalidRequest(
            "every requested StrokeRef must have visible committed samples in the source revision"
                .to_owned(),
        ));
    }
    let mut request = RecognitionRequestV1 {
        protocol_version: PROVIDER_PROTOCOL_VERSION,
        request_id,
        input_view_id: String::new(),
        source_revision,
        region_id,
        line_id,
        coordinate_space,
        coordinate_units,
        language_hints,
        requested_input_modalities: canonicalize_input_modalities(&requested_input_modalities)?,
        provider_configuration,
        provider_configuration_fingerprint,
        stroke_views,
        samples,
        raster,
    };
    request.input_view_id = input_view_id(&request)?;
    validate_request(&request)?;
    Ok(request)
}

fn provider_sample(
    journal_sequence: u64,
    sample: &PhysicalSample,
    effective_position: Option<&RawPosition>,
    stroke: &StrokeRef,
) -> Result<ProviderSampleV1, ProviderErrorKind> {
    let mut raw_payload_hex = String::new();
    let encoded_capacity = sample
        .raw_payload
        .len()
        .checked_mul(2)
        .ok_or(ProviderErrorKind::AllocationFailed)?;
    raw_payload_hex
        .try_reserve_exact(encoded_capacity)
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in &sample.raw_payload {
        raw_payload_hex.push(HEX[(*byte >> 4) as usize] as char);
        raw_payload_hex.push(HEX[(*byte & 0x0f) as usize] as char);
    }
    Ok(ProviderSampleV1 {
        journal_sequence,
        source_sequence_raw: sample.source_sequence,
        stroke: ProviderStrokeRefV1::from(stroke),
        app_arrival_elapsed_ns_decimal: sample.app_arrival_elapsed_ns.to_string(),
        config_id: sample.config_id.clone(),
        position: sample.position.as_ref().map(ProviderPositionV1::from),
        effective_position: effective_position.map(ProviderPositionV1::from),
        pressure: sample.pressure.as_ref().map(ProviderPressureV1::from),
        native_timestamp: sample
            .native_timestamp
            .as_ref()
            .map(ProviderNativeTimestampV1::from),
        contact_range_state: sample.contact_range_state.clone(),
        button_state_raw: sample.button_state_raw,
        tilt_x_raw: sample.tilt_x_raw,
        tilt_y_raw: sample.tilt_y_raw,
        rotation_raw: sample.rotation_raw,
        raw_payload_hex,
    })
}

fn validate_core_stroke_ref(stroke: &StrokeRef) -> Result<(), ProviderErrorKind> {
    for (value, label) in [
        (stroke.journal_id.as_str(), "stroke journal ID"),
        (stroke.session_id.as_str(), "stroke session ID"),
        (stroke.source_api.as_str(), "stroke source API"),
        (stroke.stroke_id.as_str(), "stroke ID"),
    ] {
        validate_text(value, MAX_ID_BYTES, label)?;
        if value.is_empty() {
            return Err(ProviderErrorKind::InvalidRequest(format!(
                "{label} must not be empty"
            )));
        }
    }
    if let Some(device_id) = &stroke.device_id {
        validate_text(device_id, MAX_ID_BYTES, "stroke device ID")?;
        if device_id.is_empty() {
            return Err(ProviderErrorKind::InvalidRequest(
                "stroke device ID must not be empty when present".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_source_sample(sample: &PhysicalSample) -> Result<(), ProviderErrorKind> {
    for (value, label) in [
        (sample.session_id.as_str(), "sample session ID"),
        (sample.source_api.as_str(), "sample source API"),
    ] {
        validate_text(value, MAX_ID_BYTES, label)?;
        if value.is_empty() {
            return Err(ProviderErrorKind::InvalidRequest(format!(
                "{label} must not be empty"
            )));
        }
    }
    for (value, label) in [
        (sample.source_device_id.as_deref(), "sample device ID"),
        (sample.stroke_id.as_deref(), "sample stroke ID"),
        (sample.config_id.as_deref(), "sample config ID"),
    ] {
        if let Some(value) = value {
            validate_text(value, MAX_ID_BYTES, label)?;
            if value.is_empty() {
                return Err(ProviderErrorKind::InvalidRequest(format!(
                    "{label} must not be empty when present"
                )));
            }
        }
    }
    if let Some(position) = &sample.position {
        validate_text(
            &position.coordinate_space,
            MAX_ID_BYTES,
            "position coordinate space",
        )?;
        validate_text(&position.units, MAX_ID_BYTES, "position units")?;
    }
    if let Some(pressure) = &sample.pressure {
        validate_text(
            &pressure.representation,
            MAX_ID_BYTES,
            "pressure representation",
        )?;
        validate_text(&pressure.units, MAX_ID_BYTES, "pressure units")?;
    }
    if let Some(timestamp) = &sample.native_timestamp {
        validate_text(&timestamp.clock_domain, MAX_ID_BYTES, "native clock domain")?;
        validate_text(&timestamp.units, MAX_ID_BYTES, "native clock units")?;
    }
    if let Some(contact_range) = &sample.contact_range_state {
        validate_text(contact_range, MAX_TEXT_BYTES, "contact/range state")?;
    }
    if sample.raw_payload.len() > MAX_RAW_SAMPLE_BYTES {
        return Err(ProviderErrorKind::InvalidRequest(
            "source sample raw payload exceeds the per-sample cap".to_owned(),
        ));
    }
    Ok(())
}

/// Hash selected, shared input and logical view state. The exact submitted
/// `last_sequence` stays in the request/result provenance echo, but unrelated
/// metadata or hover-only appends do not change this selected-view identity.
fn input_view_id(request: &RecognitionRequestV1) -> Result<String, ProviderErrorKind> {
    validate_requested_input_modalities(request)?;
    let requested_input_modalities =
        canonicalize_input_modalities(&request.requested_input_modalities)?;
    if let Some(raster) = &request.raster {
        validate_raster_input(raster)?;
    }
    let fingerprint = RequestFingerprintV1 {
        protocol_version: request.protocol_version,
        source_journal_id: &request.source_revision.journal_id,
        logical_revision: request.source_revision.logical_revision,
        region_id: &request.region_id,
        line_id: &request.line_id,
        coordinate_space: &request.coordinate_space,
        coordinate_units: &request.coordinate_units,
        language_hints: &request.language_hints,
        requested_input_modalities: &requested_input_modalities,
        stroke_views: &request.stroke_views,
        samples: &request.samples,
        raster: &request.raster,
    };
    let bytes = bounded_json_bytes(&fingerprint, MAX_REQUEST_FRAME_BYTES)?;
    // This ID is a deterministic view identifier, not an integrity signature.
    let hash = bytes.into_iter().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    });
    Ok(format!("input-view-v1-{hash:016x}"))
}

fn add_wire_estimate(estimate: &mut usize, amount: usize) -> Result<(), ProviderErrorKind> {
    let next = estimate
        .checked_add(amount)
        .ok_or(ProviderErrorKind::AllocationFailed)?;
    if next > MAX_REQUEST_FRAME_BYTES {
        return Err(ProviderErrorKind::OversizedFrame {
            actual: next,
            maximum: MAX_REQUEST_FRAME_BYTES,
        });
    }
    *estimate = next;
    Ok(())
}

fn add_string_estimate(estimate: &mut usize, value: &str) -> Result<(), ProviderErrorKind> {
    // A constant-time upper bound: one UTF-8 byte can expand to at most six
    // JSON bytes when escaped. Exact serialization and content validation run
    // on the dedicated provider worker before any child is created.
    let bytes = value
        .len()
        .checked_mul(6)
        .and_then(|length| length.checked_add(2))
        .ok_or(ProviderErrorKind::AllocationFailed)?;
    add_wire_estimate(estimate, bytes)
}

/// Cheap, allocation-free admission check for the UI-facing `try_submit`.
/// Full hashing, canonical-order validation, and JSON encoding happen in the
/// dedicated provider worker before it spawns any executable.
fn validate_request_admission(request: &RecognitionRequestV1) -> Result<(), ProviderErrorKind> {
    if request.protocol_version != PROVIDER_PROTOCOL_VERSION {
        return Err(ProviderErrorKind::ProtocolVersion {
            expected: PROVIDER_PROTOCOL_VERSION,
            actual: request.protocol_version,
        });
    }
    if request.stroke_views.is_empty()
        || request.stroke_views.len() > MAX_PROVIDER_STROKES
        || request.samples.is_empty()
        || request.samples.len() > MAX_PROVIDER_SAMPLES
    {
        return Err(ProviderErrorKind::InvalidRequest(
            "request stroke/sample count is empty or exceeds its fixed cap".to_owned(),
        ));
    }
    request.source_revision.validate()?;
    request.provider_configuration.validate()?;
    validate_text(
        &request.provider_configuration_fingerprint,
        MAX_ID_BYTES,
        "provider configuration fingerprint",
    )?;
    if request.provider_configuration_fingerprint.is_empty() {
        return Err(ProviderErrorKind::InvalidRequest(
            "provider configuration fingerprint must not be empty".to_owned(),
        ));
    }
    validate_language_hints(&request.language_hints)?;
    validate_requested_input_modalities(request)?;
    if let Some(raster) = &request.raster {
        validate_raster_bounds(raster)?;
    }
    for (value, label) in [
        (request.request_id.as_str(), "request ID"),
        (request.input_view_id.as_str(), "input-view ID"),
        (request.region_id.as_str(), "region ID"),
        (request.line_id.as_str(), "line ID"),
        (request.coordinate_space.as_str(), "coordinate space"),
        (request.coordinate_units.as_str(), "coordinate units"),
    ] {
        validate_text(value, MAX_ID_BYTES, label)?;
        if value.is_empty() {
            return Err(ProviderErrorKind::InvalidRequest(format!(
                "{label} must not be empty"
            )));
        }
    }

    let mut estimate = 2048usize;
    let mut raw_bytes = 0usize;
    add_string_estimate(&mut estimate, &request.source_revision.journal_id)?;
    add_string_estimate(&mut estimate, &request.request_id)?;
    add_string_estimate(&mut estimate, &request.input_view_id)?;
    add_string_estimate(&mut estimate, &request.region_id)?;
    add_string_estimate(&mut estimate, &request.line_id)?;
    add_string_estimate(&mut estimate, &request.coordinate_space)?;
    add_string_estimate(&mut estimate, &request.coordinate_units)?;
    add_string_estimate(
        &mut estimate,
        &request.provider_configuration.configuration_id,
    )?;
    add_string_estimate(&mut estimate, &request.provider_configuration_fingerprint)?;
    for hint in &request.language_hints {
        add_wire_estimate(&mut estimate, 32)?;
        add_string_estimate(&mut estimate, hint)?;
    }
    for _modality in &request.requested_input_modalities {
        add_wire_estimate(&mut estimate, 32)?;
    }
    for (key, value) in &request.provider_configuration.values {
        add_wire_estimate(&mut estimate, 48)?;
        add_string_estimate(&mut estimate, key)?;
        add_string_estimate(&mut estimate, value)?;
    }
    for view in &request.stroke_views {
        view.stroke.validate()?;
        if view.stroke.journal_id != request.source_revision.journal_id {
            return Err(ProviderErrorKind::InvalidRequest(
                "StrokeRef journal ID does not match source revision".to_owned(),
            ));
        }
        add_wire_estimate(&mut estimate, 512)?;
        add_string_estimate(&mut estimate, &view.stroke.journal_id)?;
        add_string_estimate(&mut estimate, &view.stroke.session_id)?;
        add_string_estimate(&mut estimate, &view.stroke.source_api)?;
        add_string_estimate(&mut estimate, &view.stroke.stroke_id)?;
        if let Some(device_id) = &view.stroke.device_id {
            add_string_estimate(&mut estimate, device_id)?;
        }
        if let Some(frame) = view.view_frame {
            frame.validate()?;
        }
    }
    let mut previous_sequence = 0u64;
    for sample in &request.samples {
        sample.stroke.validate()?;
        if sample.stroke.journal_id != request.source_revision.journal_id
            || sample.journal_sequence <= previous_sequence
            || sample.journal_sequence > request.source_revision.last_sequence
        {
            return Err(ProviderErrorKind::InvalidRequest(
                "sample journal sequence or StrokeRef does not match source revision".to_owned(),
            ));
        }
        previous_sequence = sample.journal_sequence;
        if sample.app_arrival_elapsed_ns_decimal.len() > 39
            || sample
                .app_arrival_elapsed_ns_decimal
                .parse::<u128>()
                .is_err()
        {
            return Err(ProviderErrorKind::InvalidRequest(
                "app-arrival time must be a bounded unsigned decimal string".to_owned(),
            ));
        }
        if sample.raw_payload_hex.len() % 2 != 0
            || sample.raw_payload_hex.len() / 2 > MAX_RAW_SAMPLE_BYTES
        {
            return Err(ProviderErrorKind::InvalidRequest(
                "raw sample payload must be bounded hex".to_owned(),
            ));
        }
        raw_bytes = raw_bytes
            .checked_add(sample.raw_payload_hex.len() / 2)
            .ok_or(ProviderErrorKind::AllocationFailed)?;
        if raw_bytes > MAX_TOTAL_RAW_SAMPLE_BYTES {
            return Err(ProviderErrorKind::InvalidRequest(
                "total raw sample payload exceeds the protocol cap".to_owned(),
            ));
        }
        add_wire_estimate(&mut estimate, 1024)?;
        add_string_estimate(&mut estimate, &sample.stroke.journal_id)?;
        add_string_estimate(&mut estimate, &sample.stroke.session_id)?;
        add_string_estimate(&mut estimate, &sample.stroke.source_api)?;
        add_string_estimate(&mut estimate, &sample.stroke.stroke_id)?;
        add_string_estimate(&mut estimate, &sample.app_arrival_elapsed_ns_decimal)?;
        add_wire_estimate(
            &mut estimate,
            sample.raw_payload_hex.len().saturating_add(2),
        )?;
        if let Some(device_id) = &sample.stroke.device_id {
            add_string_estimate(&mut estimate, device_id)?;
        }
        if let Some(config_id) = &sample.config_id {
            validate_text(config_id, MAX_ID_BYTES, "sample config ID")?;
            add_string_estimate(&mut estimate, config_id)?;
        }
        if let Some(position) = &sample.position {
            validate_text(
                &position.coordinate_space,
                MAX_ID_BYTES,
                "position coordinate space",
            )?;
            validate_text(&position.units, MAX_ID_BYTES, "position units")?;
            add_string_estimate(&mut estimate, &position.coordinate_space)?;
            add_string_estimate(&mut estimate, &position.units)?;
        }
        if let Some(position) = &sample.effective_position {
            validate_text(
                &position.coordinate_space,
                MAX_ID_BYTES,
                "effective position coordinate space",
            )?;
            validate_text(&position.units, MAX_ID_BYTES, "effective position units")?;
            add_string_estimate(&mut estimate, &position.coordinate_space)?;
            add_string_estimate(&mut estimate, &position.units)?;
        }
        if let Some(pressure) = &sample.pressure {
            validate_text(
                &pressure.representation,
                MAX_ID_BYTES,
                "pressure representation",
            )?;
            validate_text(&pressure.units, MAX_ID_BYTES, "pressure units")?;
            add_string_estimate(&mut estimate, &pressure.representation)?;
            add_string_estimate(&mut estimate, &pressure.units)?;
        }
        if let Some(timestamp) = &sample.native_timestamp {
            validate_text(&timestamp.clock_domain, MAX_ID_BYTES, "native clock domain")?;
            validate_text(&timestamp.units, MAX_ID_BYTES, "native clock units")?;
            add_string_estimate(&mut estimate, &timestamp.clock_domain)?;
            add_string_estimate(&mut estimate, &timestamp.units)?;
        }
        if let Some(contact_state) = &sample.contact_range_state {
            validate_text(contact_state, MAX_TEXT_BYTES, "contact/range state")?;
            add_string_estimate(&mut estimate, contact_state)?;
        }
    }
    if let Some(raster) = &request.raster {
        add_wire_estimate(&mut estimate, 512)?;
        add_string_estimate(&mut estimate, &raster.coordinate_space)?;
        add_string_estimate(&mut estimate, &raster.units)?;
        add_wire_estimate(&mut estimate, raster.raw_payload_hex.len())?;
    }
    Ok(())
}

fn validate_request(request: &RecognitionRequestV1) -> Result<(), ProviderErrorKind> {
    if request.protocol_version != PROVIDER_PROTOCOL_VERSION {
        return Err(ProviderErrorKind::ProtocolVersion {
            expected: PROVIDER_PROTOCOL_VERSION,
            actual: request.protocol_version,
        });
    }
    validate_text(&request.request_id, MAX_ID_BYTES, "request ID")?;
    validate_text(&request.input_view_id, MAX_ID_BYTES, "input-view ID")?;
    validate_text(&request.region_id, MAX_ID_BYTES, "region ID")?;
    validate_text(&request.line_id, MAX_ID_BYTES, "line ID")?;
    validate_text(&request.coordinate_space, MAX_ID_BYTES, "coordinate space")?;
    validate_text(&request.coordinate_units, MAX_ID_BYTES, "coordinate units")?;
    request.source_revision.validate()?;
    request.provider_configuration.validate()?;
    if request.provider_configuration_fingerprint != request.provider_configuration.fingerprint()? {
        return Err(ProviderErrorKind::ProviderConfigurationMismatch);
    }
    validate_language_hints(&request.language_hints)?;
    validate_requested_input_modalities(request)?;
    if request.request_id.is_empty()
        || request.input_view_id.is_empty()
        || request.region_id.is_empty()
        || request.line_id.is_empty()
    {
        return Err(ProviderErrorKind::InvalidRequest(
            "request, input-view, region, and line IDs must not be empty".to_owned(),
        ));
    }
    if request.stroke_views.is_empty() || request.stroke_views.len() > MAX_PROVIDER_STROKES {
        return Err(ProviderErrorKind::InvalidRequest(
            "stroke view count is empty or exceeds the protocol cap".to_owned(),
        ));
    }
    if request.input_view_id != input_view_id(request)? {
        return Err(ProviderErrorKind::InvalidRequest(
            "input-view ID does not match the exact request payload".to_owned(),
        ));
    }
    if request.samples.is_empty() || request.samples.len() > MAX_PROVIDER_SAMPLES {
        return Err(ProviderErrorKind::InvalidRequest(
            "sample count is empty or exceeds the protocol cap".to_owned(),
        ));
    }
    let mut view_refs = HashSet::new();
    view_refs
        .try_reserve(request.stroke_views.len())
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    for view in &request.stroke_views {
        view.stroke.validate()?;
        if view.stroke.journal_id != request.source_revision.journal_id {
            return Err(ProviderErrorKind::InvalidRequest(
                "StrokeRef journal ID does not match request source revision".to_owned(),
            ));
        }
        if !view_refs.insert(view.stroke.clone()) {
            return Err(ProviderErrorKind::InvalidRequest(
                "stroke view list contains duplicate StrokeRefs".to_owned(),
            ));
        }
        if let Some(frame) = view.view_frame {
            frame.validate()?;
        }
    }
    let mut previous_sequence = 0u64;
    let mut total_raw_bytes = 0usize;
    let mut first_occurrence_order = Vec::new();
    first_occurrence_order
        .try_reserve(request.stroke_views.len())
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    let mut seen_sample_strokes = HashSet::new();
    seen_sample_strokes
        .try_reserve(request.stroke_views.len())
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    for sample in &request.samples {
        sample.stroke.validate()?;
        if !view_refs.contains(&sample.stroke)
            || sample.stroke.journal_id != request.source_revision.journal_id
            || sample.journal_sequence <= previous_sequence
            || sample.journal_sequence > request.source_revision.last_sequence
        {
            return Err(ProviderErrorKind::InvalidRequest(
                "samples must reference request StrokeRefs in increasing journal sequence"
                    .to_owned(),
            ));
        }
        previous_sequence = sample.journal_sequence;
        if seen_sample_strokes.insert(sample.stroke.clone()) {
            first_occurrence_order.push(sample.stroke.clone());
        }
        if sample.app_arrival_elapsed_ns_decimal.is_empty()
            || sample.app_arrival_elapsed_ns_decimal.len() > 39
            || sample
                .app_arrival_elapsed_ns_decimal
                .parse::<u128>()
                .is_err()
        {
            return Err(ProviderErrorKind::InvalidRequest(
                "app-arrival time must be an unsigned decimal string".to_owned(),
            ));
        }
        if sample.raw_payload_hex.len() % 2 != 0
            || sample.raw_payload_hex.len() / 2 > MAX_RAW_SAMPLE_BYTES
            || !sample
                .raw_payload_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ProviderErrorKind::InvalidRequest(
                "raw sample payload must be bounded hex".to_owned(),
            ));
        }
        total_raw_bytes = total_raw_bytes
            .checked_add(sample.raw_payload_hex.len() / 2)
            .ok_or_else(|| {
                ProviderErrorKind::InvalidRequest("raw sample byte count overflow".to_owned())
            })?;
        if total_raw_bytes > MAX_TOTAL_RAW_SAMPLE_BYTES {
            return Err(ProviderErrorKind::InvalidRequest(
                "total raw sample payload exceeds the protocol cap".to_owned(),
            ));
        }
        if let Some(position) = &sample.position {
            validate_text(
                &position.coordinate_space,
                MAX_ID_BYTES,
                "position coordinate space",
            )?;
            validate_text(&position.units, MAX_ID_BYTES, "position units")?;
            if position.coordinate_space.is_empty() || position.units.is_empty() {
                return Err(ProviderErrorKind::InvalidRequest(
                    "raw position must retain nonempty coordinate space and units".to_owned(),
                ));
            }
        }
        if let Some(position) = &sample.effective_position {
            validate_text(
                &position.coordinate_space,
                MAX_ID_BYTES,
                "effective position coordinate space",
            )?;
            validate_text(&position.units, MAX_ID_BYTES, "effective position units")?;
            if position.coordinate_space.is_empty() || position.units.is_empty() {
                return Err(ProviderErrorKind::InvalidRequest(
                    "effective position must retain nonempty coordinate space and units".to_owned(),
                ));
            }
        }
        if let Some(pressure) = &sample.pressure {
            validate_text(
                &pressure.representation,
                MAX_ID_BYTES,
                "pressure representation",
            )?;
            validate_text(&pressure.units, MAX_ID_BYTES, "pressure units")?;
            if pressure.representation.is_empty() || pressure.units.is_empty() {
                return Err(ProviderErrorKind::InvalidRequest(
                    "raw pressure must retain nonempty representation and units".to_owned(),
                ));
            }
        }
        if let Some(timestamp) = &sample.native_timestamp {
            validate_text(&timestamp.clock_domain, MAX_ID_BYTES, "native clock domain")?;
            validate_text(&timestamp.units, MAX_ID_BYTES, "native clock units")?;
            if timestamp.clock_domain.is_empty() || timestamp.units.is_empty() {
                return Err(ProviderErrorKind::InvalidRequest(
                    "native timestamp must retain nonempty clock domain and units".to_owned(),
                ));
            }
        }
        if let Some(config_id) = &sample.config_id {
            validate_text(config_id, MAX_ID_BYTES, "sample config ID")?;
        }
        if let Some(contact_state) = &sample.contact_range_state {
            validate_text(contact_state, MAX_TEXT_BYTES, "contact/range state")?;
        }
    }
    if first_occurrence_order
        != request
            .stroke_views
            .iter()
            .map(|view| view.stroke.clone())
            .collect::<Vec<_>>()
    {
        return Err(ProviderErrorKind::InvalidRequest(
            "StrokeRefs must follow first occurrence in canonical journal sample order".to_owned(),
        ));
    }
    if let Some(raster) = &request.raster {
        validate_raster_input(raster)?;
    }
    Ok(())
}

fn validate_language_hints(hints: &[String]) -> Result<(), ProviderErrorKind> {
    if hints.len() > MAX_LANGUAGE_HINTS {
        return Err(ProviderErrorKind::InvalidRequest(
            "language hint count exceeds the protocol cap".to_owned(),
        ));
    }
    for hint in hints {
        validate_text(hint, MAX_LANGUAGE_TAG_BYTES, "language hint")?;
        if hint.is_empty() {
            return Err(ProviderErrorKind::InvalidRequest(
                "language hints must not be empty".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), ProviderErrorKind> {
    if value.len() > maximum {
        return Err(ProviderErrorKind::InvalidRequest(format!(
            "{label} exceeds its {maximum}-byte cap"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderIdentityV1 {
    pub provider_id: String,
    pub provider_version: String,
    pub model_version: Option<String>,
    pub resource_version: Option<String>,
}

impl ProviderIdentityV1 {
    fn validate(&self) -> Result<(), ProviderErrorKind> {
        validate_text(&self.provider_id, MAX_ID_BYTES, "provider ID")?;
        validate_text(&self.provider_version, MAX_ID_BYTES, "provider version")?;
        if self.provider_id.is_empty() || self.provider_version.is_empty() {
            return Err(ProviderErrorKind::InvalidResponse(
                "provider ID and version must not be empty".to_owned(),
            ));
        }
        if let Some(model) = &self.model_version {
            validate_text(model, MAX_ID_BYTES, "provider model version")?;
        }
        if let Some(resource) = &self.resource_version {
            validate_text(resource, MAX_ID_BYTES, "provider resource version")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProviderInputCapabilityV1 {
    OnlineStrokes,
    Raster,
}

fn validate_requested_input_modalities(
    request: &RecognitionRequestV1,
) -> Result<(), ProviderErrorKind> {
    let requested = &request.requested_input_modalities;
    if requested.is_empty() || requested.len() > 2 {
        return Err(ProviderErrorKind::InvalidRequest(
            "requested input modality set is empty or exceeds its fixed cap".to_owned(),
        ));
    }
    for (index, modality) in requested.iter().enumerate() {
        if requested[..index].contains(modality) {
            return Err(ProviderErrorKind::InvalidRequest(
                "requested input modalities must be unique".to_owned(),
            ));
        }
        match modality {
            ProviderInputCapabilityV1::OnlineStrokes
                if request.stroke_views.is_empty() || request.samples.is_empty() =>
            {
                return Err(ProviderErrorKind::InvalidRequest(
                    "online-stroke modality requires canonical stroke and sample provenance"
                        .to_owned(),
                ));
            }
            ProviderInputCapabilityV1::Raster => {
                let raster = request.raster.as_ref().ok_or_else(|| {
                    ProviderErrorKind::InvalidRequest(
                        "requested raster modality has no raster payload".to_owned(),
                    )
                })?;
                validate_raster_bounds(raster)?;
            }
            _ => {}
        }
    }
    if request.raster.is_some() != requested.contains(&ProviderInputCapabilityV1::Raster) {
        return Err(ProviderErrorKind::InvalidRequest(
            "raster payload presence must match the requested raster modality".to_owned(),
        ));
    }
    Ok(())
}

fn canonicalize_input_modalities(
    modalities: &[ProviderInputCapabilityV1],
) -> Result<Vec<ProviderInputCapabilityV1>, ProviderErrorKind> {
    if modalities.is_empty() || modalities.len() > 2 {
        return Err(ProviderErrorKind::InvalidRequest(
            "requested input modality set is empty or exceeds its fixed cap".to_owned(),
        ));
    }
    let mut canonical = Vec::new();
    canonical
        .try_reserve_exact(modalities.len())
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    canonical.extend_from_slice(modalities);
    canonical.sort_by_key(|modality| match modality {
        ProviderInputCapabilityV1::OnlineStrokes => 0u8,
        ProviderInputCapabilityV1::Raster => 1u8,
    });
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProviderErrorKind::InvalidRequest(
            "requested input modalities must be unique".to_owned(),
        ));
    }
    Ok(canonical)
}

fn validate_raster_input(raster: &ProviderRasterInputV1) -> Result<(), ProviderErrorKind> {
    validate_raster_bounds(raster)?;
    if !raster
        .raw_payload_hex
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProviderErrorKind::InvalidRequest(
            "opaque raster payload must use bounded hexadecimal bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_raster_bounds(raster: &ProviderRasterInputV1) -> Result<(), ProviderErrorKind> {
    let raw_bytes = raster.raw_payload_hex.len() / 2;
    let declared_area = u64::from(raster.width).checked_mul(u64::from(raster.height));
    if raster.width == 0
        || raster.height == 0
        || declared_area.is_none_or(|area| area > MAX_TOTAL_RAW_SAMPLE_BYTES as u64)
        || raster.raw_payload_hex.is_empty()
        || !raster.raw_payload_hex.len().is_multiple_of(2)
        || raw_bytes == 0
        || raw_bytes > MAX_TOTAL_RAW_SAMPLE_BYTES
    {
        return Err(ProviderErrorKind::InvalidRequest(
            "opaque raster bytes are empty or exceed their geometry/byte limits".to_owned(),
        ));
    }
    for (value, label) in [
        (raster.coordinate_space.as_str(), "raster coordinate space"),
        (raster.units.as_str(), "raster units"),
    ] {
        validate_text(value, MAX_ID_BYTES, label)?;
        if value.is_empty() {
            return Err(ProviderErrorKind::InvalidRequest(format!(
                "{label} must not be empty"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProviderOutputCapabilityV1 {
    Text,
    Math,
    Multiline,
    Layout,
    NBest,
    NativeScore,
    WordCandidates,
    CharacterCandidates,
    StrokeRanges,
    OfflineOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderCapabilitiesV1 {
    pub inputs: Vec<ProviderInputCapabilityV1>,
    pub outputs: Vec<ProviderOutputCapabilityV1>,
    pub languages: Vec<String>,
}

impl ProviderCapabilitiesV1 {
    fn validate(&self) -> Result<(), ProviderErrorKind> {
        if self.inputs.len() > 8 || self.outputs.len() > 32 || self.languages.len() > 128 {
            return Err(ProviderErrorKind::InvalidResponse(
                "provider capability list exceeds a fixed item cap".to_owned(),
            ));
        }
        for language in &self.languages {
            validate_text(language, MAX_LANGUAGE_TAG_BYTES, "provider language")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderStrokeRangeV1 {
    pub stroke: ProviderStrokeRefV1,
    pub first_journal_sequence: u64,
    pub last_journal_sequence: u64,
}

fn deserialize_bounded_stroke_ranges<'de, D>(
    deserializer: D,
) -> Result<Vec<ProviderStrokeRangeV1>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RangesVisitor;
    impl<'de> Visitor<'de> for RangesVisitor {
        type Value = Vec<ProviderStrokeRangeV1>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded list of provider stroke ranges")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut ranges = Vec::new();
            while let Some(range) = sequence.next_element::<ProviderStrokeRangeV1>()? {
                if ranges.len() >= MAX_PROVIDER_STROKE_RANGES {
                    return Err(<A::Error as DeError>::custom(
                        "provider stroke-range cap exceeded",
                    ));
                }
                ranges
                    .try_reserve(1)
                    .map_err(|_| <A::Error as DeError>::custom("stroke-range allocation failed"))?;
                ranges.push(range);
            }
            Ok(ranges)
        }
    }
    deserializer.deserialize_seq(RangesVisitor)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderCandidateV1 {
    pub recognized_text: String,
    /// The provider's native numeric score. It is never interpreted as a
    /// calibrated probability by this protocol.
    pub native_score_raw: Option<serde_json::Number>,
    #[serde(deserialize_with = "deserialize_bounded_stroke_ranges")]
    pub stroke_ranges: Vec<ProviderStrokeRangeV1>,
    /// Preserve the provider-specific candidate object, including unknown
    /// fields, without turning it into a normalized core representation.
    pub raw_candidate: Value,
}

fn deserialize_bounded_candidates<'de, D>(
    deserializer: D,
) -> Result<Vec<ProviderCandidateV1>, D::Error>
where
    D: Deserializer<'de>,
{
    struct CandidatesVisitor;
    impl<'de> Visitor<'de> for CandidatesVisitor {
        type Value = Vec<ProviderCandidateV1>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded list of provider candidates")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut candidates = Vec::new();
            while let Some(candidate) = sequence.next_element::<ProviderCandidateV1>()? {
                if candidates.len() >= MAX_PROVIDER_CANDIDATES {
                    return Err(<A::Error as DeError>::custom(
                        "provider candidate cap exceeded",
                    ));
                }
                candidates
                    .try_reserve(1)
                    .map_err(|_| <A::Error as DeError>::custom("candidate allocation failed"))?;
                candidates.push(candidate);
            }
            Ok(candidates)
        }
    }
    deserializer.deserialize_seq(CandidatesVisitor)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecognitionResultV1 {
    pub request_id: String,
    pub input_view_id: String,
    pub source_revision: ProviderSourceRevisionV1,
    pub region_id: String,
    pub line_id: String,
    pub provider_configuration_id: String,
    pub provider_configuration_fingerprint: String,
    pub provider: ProviderIdentityV1,
    pub provider_provenance: String,
    /// Exact acknowledgement of the modalities requested for this response.
    pub consumed_input_modalities: Vec<ProviderInputCapabilityV1>,
    #[serde(deserialize_with = "deserialize_bounded_candidates")]
    pub candidates: Vec<ProviderCandidateV1>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WorkerRequestFrameV1 {
    Handshake {
        protocol_version: u32,
        provider_id: String,
        configuration_id: String,
        configuration_fingerprint: String,
    },
    Recognize {
        protocol_version: u32,
        request: Box<RecognitionRequestV1>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WorkerResponseFrameV1 {
    Handshake {
        protocol_version: u32,
        provider: ProviderIdentityV1,
        configuration_id: String,
        configuration_fingerprint: String,
        capabilities: ProviderCapabilitiesV1,
    },
    Recognition {
        protocol_version: u32,
        result: RecognitionResultV1,
    },
    Failure {
        protocol_version: u32,
        code: String,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderPhase {
    Handshake,
    Recognition,
    Shutdown,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ProviderErrorKind {
    InvalidConfiguration(String),
    InvalidRequest(String),
    InvalidResponse(String),
    ProtocolVersion {
        expected: u32,
        actual: u32,
    },
    OversizedFrame {
        actual: usize,
        maximum: usize,
    },
    TimedOut(ProviderPhase),
    Cancelled,
    SpawnFailed(String),
    IoFailed {
        phase: ProviderPhase,
        message: String,
    },
    WorkerExited {
        exit_code: Option<i32>,
    },
    UnexpectedFrame(String),
    UnsupportedCapability(String),
    ProviderFailure {
        code: String,
        message: String,
    },
    StaleSourceRevision,
    ProviderRequestMismatch,
    ProviderConfigurationMismatch,
    WorkerThreadPanicked,
    UnsupportedPlatform,
    WorkerCapacityReached,
    WorkerSubsystemPoisoned,
    ProcessCleanupFailed(String),
    AllocationFailed,
}

impl fmt::Display for ProviderErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ProviderErrorKind {}

#[derive(Debug)]
pub(crate) struct ProviderExecutionError {
    pub kind: ProviderErrorKind,
    pub stderr_bytes: Vec<u8>,
    pub stderr_truncated: bool,
    pub raw_response_transcript: ProviderRawResponseTranscriptV1,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProviderExecution {
    pub provider: ProviderIdentityV1,
    pub capabilities: ProviderCapabilitiesV1,
    pub result: RecognitionResultV1,
    pub stderr_bytes: Vec<u8>,
    pub stderr_truncated: bool,
    pub raw_response_transcript: ProviderRawResponseTranscriptV1,
    pub process_resources: Option<ProviderProcessResourcesV1>,
    pub timing: ProviderExecutionTimingV1,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderRawResponseFrameV1 {
    pub ordinal: u8,
    pub payload_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderRawResponseTranscriptV1 {
    pub frames: Vec<ProviderRawResponseFrameV1>,
    pub capture_complete: bool,
    pub omitted_frame_count: u32,
    pub omitted_payload_bytes: u64,
}

impl ProviderRawResponseTranscriptV1 {
    fn capture_frame(&mut self, ordinal: u8, payload_bytes: Vec<u8>) {
        let frame_size = payload_bytes.len();
        let accumulated = self
            .frames
            .iter()
            .map(|frame| frame.payload_bytes.len())
            .sum::<usize>();
        if self.frames.len() >= MAX_RAW_PROVIDER_RESPONSE_FRAMES
            || accumulated.saturating_add(frame_size) > MAX_RAW_PROVIDER_RESPONSE_BYTES
            || self.frames.try_reserve(1).is_err()
        {
            self.capture_complete = false;
            self.omitted_frame_count = self.omitted_frame_count.saturating_add(1);
            self.omitted_payload_bytes =
                self.omitted_payload_bytes.saturating_add(frame_size as u64);
            return;
        }
        self.frames.push(ProviderRawResponseFrameV1 {
            ordinal,
            payload_bytes,
        });
    }

    fn mark_clean_eof(&mut self) {
        self.capture_complete = self.frames.len() == 2 && self.omitted_frame_count == 0;
    }

    fn mark_incomplete(&mut self) {
        self.capture_complete = false;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProviderResourceScopeV1 {
    JobProcessTree,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderProcessResourcesV1 {
    pub scope: ProviderResourceScopeV1,
    /// Raw Job Object accumulated user CPU counter in 100-nanosecond units,
    /// observed after the job reached ActiveProcesses == 0.
    pub total_user_time_100ns_raw: i64,
    /// Raw Job Object accumulated kernel CPU counter in 100-nanosecond units.
    pub total_kernel_time_100ns_raw: i64,
    pub total_page_fault_count_raw: u32,
    pub total_process_count_raw: u32,
    /// Raw `JOBOBJECT_EXTENDED_LIMIT_INFORMATION.PeakJobMemoryUsed` bytes:
    /// peak memory usage of processes associated with the job as documented
    /// by Windows. This is not a claim about RSS, VRAM, or a separate memory
    /// accounting model.
    pub peak_job_memory_bytes_raw: Option<u64>,
    /// Raw `PeakProcessMemoryUsed` bytes: peak memory used by any process ever
    /// associated with the job, per the Windows structure documentation.
    pub peak_process_memory_bytes_raw: Option<u64>,
    pub memory_unavailable_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderExecutionTimingV1 {
    /// All durations use `Instant` sampled immediately before the CreateProcessW
    /// call. Job CPU starts after the job-list assignment inside that call; this
    /// wall denominator is conservatively a little wider and may understate the
    /// core-equivalent ratio. It is not physical latency.
    pub process_create_call_to_handshake_ns: u64,
    pub process_create_call_to_recognition_ns: u64,
    pub process_create_call_to_parent_exit_ns: u64,
    pub process_create_call_to_tree_drain_ns: u64,
    /// No provider protocol frame separately measures model initialization.
    pub model_cold_start_ns: Option<u64>,
    pub model_cold_start_unavailable_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderCallTimeouts {
    pub handshake: Duration,
    pub recognition: Duration,
    pub shutdown: Duration,
}

impl Default for ProviderCallTimeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(5),
            recognition: Duration::from_secs(30),
            shutdown: Duration::from_secs(2),
        }
    }
}

impl ProviderCallTimeouts {
    fn validate(self) -> Result<Self, ProviderErrorKind> {
        let minimum = Duration::from_millis(1);
        let maximum = Duration::from_secs(120);
        if self.handshake < minimum
            || self.recognition < minimum
            || self.shutdown < minimum
            || self.handshake > maximum
            || self.recognition > maximum
            || self.shutdown > maximum
        {
            return Err(ProviderErrorKind::InvalidConfiguration(
                "provider deadlines must be between 1 ms and 120 s".to_owned(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug)]
pub(crate) struct ProviderJobOutcome {
    pub request_id: String,
    pub outcome: Result<ProviderExecution, ProviderExecutionError>,
}

#[derive(Debug)]
pub(crate) enum ProviderSubmitError {
    Backpressure(Box<RecognitionRequestV1>),
    Stopped(Box<RecognitionRequestV1>),
    Invalid(ProviderErrorKind),
}

#[derive(Debug)]
pub(crate) enum ProviderWorkerPoll {
    Pending,
    Outcome(Box<ProviderJobOutcome>),
    Stopped,
}

enum ProviderWorkerCommand {
    Recognize(RecognitionRequestV1),
}

/// Asynchronous, single-worker interface for the UI/core. Submitting and
/// polling are nonblocking. Its command and result queues each hold one item;
/// provider work and child I/O deadlines run only on the dedicated worker.
/// The handle is intentionally UI-thread-bound so submit/cancel state changes
/// cannot race across callers.
pub(crate) struct ProviderWorkerHandle {
    commands: SyncSender<ProviderWorkerCommand>,
    results: Receiver<Box<ProviderJobOutcome>>,
    cancelled: Arc<AtomicBool>,
    pending: AtomicBool,
    _owner_thread: PhantomData<Rc<()>>,
}

impl ProviderWorkerHandle {
    pub(crate) fn start(
        approved: OperatorApprovedProviderConfig,
        timeouts: ProviderCallTimeouts,
    ) -> Result<Self, ProviderErrorKind> {
        let timeouts = timeouts.validate()?;
        let worker_slot = reserve_provider_worker_thread()?;
        let (command_sender, command_receiver) = mpsc::sync_channel(1);
        let (result_sender, results) = mpsc::sync_channel::<Box<ProviderJobOutcome>>(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let provider_thread = thread::Builder::new()
            .name("lassoink-provider-worker".to_owned())
            .spawn(move || {
                loop {
                    if worker_cancelled.load(Ordering::Acquire) {
                        match command_receiver.try_recv() {
                            Ok(ProviderWorkerCommand::Recognize(request)) => {
                                let cancelled_result = Box::new(ProviderJobOutcome {
                                    request_id: request.request_id,
                                    outcome: Err(ProviderExecutionError {
                                        kind: ProviderErrorKind::Cancelled,
                                        stderr_bytes: Vec::new(),
                                        stderr_truncated: false,
                                        raw_response_transcript:
                                            ProviderRawResponseTranscriptV1::default(),
                                    }),
                                });
                                let _ = result_sender.send(cancelled_result);
                            }
                            Err(_) => {}
                        }
                        break;
                    }
                    let command = match command_receiver.recv_timeout(IO_POLL_INTERVAL) {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    match command {
                        ProviderWorkerCommand::Recognize(request) => {
                            let request_id = request.request_id.clone();
                            let runner = ProviderProcessRunner {
                                approved: &approved,
                                timeouts,
                            };
                            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                                runner.run(request, &worker_cancelled)
                            }))
                            .unwrap_or_else(|_| {
                                Err(ProviderExecutionError {
                                    kind: ProviderErrorKind::WorkerThreadPanicked,
                                    stderr_bytes: Vec::new(),
                                    stderr_truncated: false,
                                    raw_response_transcript:
                                        ProviderRawResponseTranscriptV1::default(),
                                })
                            });
                            if result_sender
                                .send(Box::new(ProviderJobOutcome {
                                    request_id,
                                    outcome,
                                }))
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            })
            .map_err(|error| ProviderErrorKind::SpawnFailed(error.to_string()))?;
        worker_slot.register(provider_thread);
        Ok(Self {
            commands: command_sender,
            results,
            cancelled,
            pending: AtomicBool::new(false),
            _owner_thread: PhantomData,
        })
    }

    pub(crate) fn try_submit(
        &self,
        request: RecognitionRequestV1,
    ) -> Result<(), ProviderSubmitError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ProviderSubmitError::Stopped(Box::new(request)));
        }
        validate_request_admission(&request).map_err(ProviderSubmitError::Invalid)?;
        if self
            .pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ProviderSubmitError::Backpressure(Box::new(request)));
        }
        match self
            .commands
            .try_send(ProviderWorkerCommand::Recognize(request))
        {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(ProviderWorkerCommand::Recognize(request))) => {
                self.pending.store(false, Ordering::Release);
                Err(ProviderSubmitError::Backpressure(Box::new(request)))
            }
            Err(TrySendError::Disconnected(ProviderWorkerCommand::Recognize(request))) => {
                self.pending.store(false, Ordering::Release);
                Err(ProviderSubmitError::Stopped(Box::new(request)))
            }
        }
    }

    pub(crate) fn try_receive(&self) -> ProviderWorkerPoll {
        reap_provider_worker_threads();
        match self.results.try_recv() {
            Ok(outcome) => {
                self.pending.store(false, Ordering::Release);
                ProviderWorkerPoll::Outcome(outcome)
            }
            Err(TryRecvError::Empty) => ProviderWorkerPoll::Pending,
            Err(TryRecvError::Disconnected) => {
                self.pending.store(false, Ordering::Release);
                ProviderWorkerPoll::Stopped
            }
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl Drop for ProviderWorkerHandle {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

struct ProviderProcessRunner<'a> {
    approved: &'a OperatorApprovedProviderConfig,
    timeouts: ProviderCallTimeouts,
}

impl ProviderProcessRunner<'_> {
    fn run(
        &self,
        request: RecognitionRequestV1,
        cancelled: &AtomicBool,
    ) -> Result<ProviderExecution, ProviderExecutionError> {
        let stderr_capture = Arc::new(Mutex::new(BoundedStderr::default()));
        let raw_response_capture = Arc::new(Mutex::new(ProviderRawResponseTranscriptV1::default()));
        let result = self.run_inner(
            request,
            cancelled,
            Arc::clone(&stderr_capture),
            Arc::clone(&raw_response_capture),
        );
        let (stderr_bytes, stderr_truncated) = stderr_snapshot(&stderr_capture);
        let raw_response_transcript = raw_response_snapshot(&raw_response_capture);
        match result {
            Ok(mut execution) => {
                execution.raw_response_transcript = raw_response_transcript;
                Ok(execution)
            }
            Err(kind) => Err(ProviderExecutionError {
                kind,
                stderr_bytes,
                stderr_truncated,
                raw_response_transcript,
            }),
        }
    }

    #[cfg(windows)]
    fn run_inner(
        &self,
        mut request: RecognitionRequestV1,
        cancelled: &AtomicBool,
        stderr_capture: Arc<Mutex<BoundedStderr>>,
        raw_response_capture: Arc<Mutex<ProviderRawResponseTranscriptV1>>,
    ) -> Result<ProviderExecution, ProviderErrorKind> {
        request.requested_input_modalities =
            canonicalize_input_modalities(&request.requested_input_modalities)?;
        validate_request(&request)?;
        if request.provider_configuration != self.approved.protocol_configuration
            || request.provider_configuration_fingerprint
                != self.approved.protocol_configuration.fingerprint()?
        {
            return Err(ProviderErrorKind::ProviderConfigurationMismatch);
        }
        if request
            .samples
            .iter()
            .any(|sample| sample.stroke.journal_id != request.source_revision.journal_id)
        {
            return Err(ProviderErrorKind::InvalidRequest(
                "request contains a StrokeRef from another journal".to_owned(),
            ));
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(ProviderErrorKind::Cancelled);
        }

        let handshake_request = WorkerRequestFrameV1::Handshake {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            provider_id: self.approved.provider_id.clone(),
            configuration_id: self
                .approved
                .protocol_configuration
                .configuration_id
                .clone(),
            configuration_fingerprint: self.approved.protocol_configuration.fingerprint()?,
        };
        let recognition_request = WorkerRequestFrameV1::Recognize {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            request: Box::new(request.clone()),
        };
        let handshake_frame = encode_frame(&handshake_request, MAX_HANDSHAKE_FRAME_BYTES)?;
        let recognition_frame = encode_frame(&recognition_request, MAX_REQUEST_FRAME_BYTES)?;

        let cleanup_permit = reserve_process_cleanup_slot()?;
        let mut child = ChildGuard::new(cleanup_permit);
        let attempt = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let windows_process::SpawnedProvider {
                stdin,
                stdout,
                stderr,
                create_process_call_started,
            } = windows_process::spawn_provider(
                &self.approved.executable,
                &self.approved.arguments,
                &mut child,
            )
            .map_err(|error| {
                ProviderErrorKind::SpawnFailed(format!(
                    "contained Windows provider launch failed (Windows 10+ Job List required; \
                     no uncontained fallback): {error}"
                ))
            })?;
            child.reserve_helper_slot()?;
            let stderr_thread_capture = Arc::clone(&stderr_capture);
            let stderr_thread = thread::Builder::new()
                .name("lassoink-provider-stderr".to_owned())
                .spawn(move || drain_stderr(stderr, stderr_thread_capture))
                .map_err(|error| ProviderErrorKind::SpawnFailed(error.to_string()))?;
            child.add_helper(stderr_thread);

            let (response_sender, response_receiver) = mpsc::sync_channel(2);
            let (reader_done_sender, reader_done_receiver) = mpsc::sync_channel(1);
            child.reserve_helper_slot()?;
            let stdout_thread = thread::Builder::new()
                .name("lassoink-provider-stdout".to_owned())
                .spawn(move || {
                    read_worker_responses(
                        stdout,
                        response_sender,
                        reader_done_sender,
                        raw_response_capture,
                    )
                })
                .map_err(|error| ProviderErrorKind::SpawnFailed(error.to_string()))?;
            child.add_helper(stdout_thread);

            let (write_sender, write_receiver) = mpsc::sync_channel(1);
            child.reserve_helper_slot()?;
            let stdin_thread = thread::Builder::new()
                .name("lassoink-provider-stdin".to_owned())
                .spawn(move || write_worker_frames(stdin, write_receiver))
                .map_err(|error| ProviderErrorKind::SpawnFailed(error.to_string()))?;
            child.add_helper(stdin_thread);

            let handshake_deadline = Instant::now() + self.timeouts.handshake;
            send_frame_to_worker(
                &write_sender,
                handshake_frame,
                handshake_deadline,
                cancelled,
                ProviderPhase::Handshake,
            )?;
            let handshake = receive_worker_response(
                &response_receiver,
                handshake_deadline,
                cancelled,
                ProviderPhase::Handshake,
            )?;
            let (provider, capabilities) = match handshake {
                WorkerResponseFrameV1::Handshake {
                    protocol_version,
                    provider,
                    configuration_id,
                    configuration_fingerprint,
                    capabilities,
                } => {
                    verify_protocol_version(protocol_version)?;
                    provider.validate()?;
                    capabilities.validate()?;
                    if provider.provider_id != self.approved.provider_id {
                        return Err(ProviderErrorKind::InvalidResponse(
                            "provider handshake ID does not match the approved configuration"
                                .to_owned(),
                        ));
                    }
                    if configuration_id != self.approved.protocol_configuration.configuration_id
                        || configuration_fingerprint
                            != self.approved.protocol_configuration.fingerprint()?
                    {
                        return Err(ProviderErrorKind::ProviderConfigurationMismatch);
                    }
                    validate_capabilities_for_request(&capabilities, &request)?;
                    (provider, capabilities)
                }
                WorkerResponseFrameV1::Failure {
                    protocol_version,
                    code,
                    message,
                } => {
                    verify_protocol_version(protocol_version)?;
                    validate_text(&code, MAX_ID_BYTES, "provider failure code")?;
                    validate_text(&message, MAX_TEXT_BYTES, "provider failure message")?;
                    return Err(ProviderErrorKind::ProviderFailure { code, message });
                }
                other => {
                    return Err(ProviderErrorKind::UnexpectedFrame(format!(
                        "expected handshake response, received {other:?}"
                    )));
                }
            };
            let process_create_call_to_handshake_ns = elapsed_ns(create_process_call_started);

            let recognition_deadline = Instant::now() + self.timeouts.recognition;
            send_frame_to_worker(
                &write_sender,
                recognition_frame,
                recognition_deadline,
                cancelled,
                ProviderPhase::Recognition,
            )?;
            drop(write_sender);
            let response = receive_worker_response(
                &response_receiver,
                recognition_deadline,
                cancelled,
                ProviderPhase::Recognition,
            )?;
            let result = match response {
                WorkerResponseFrameV1::Recognition {
                    protocol_version,
                    result,
                } => {
                    verify_protocol_version(protocol_version)?;
                    validate_recognition_result(&result, &request, &provider, &capabilities)?;
                    result
                }
                WorkerResponseFrameV1::Failure {
                    protocol_version,
                    code,
                    message,
                } => {
                    verify_protocol_version(protocol_version)?;
                    validate_text(&code, MAX_ID_BYTES, "provider failure code")?;
                    validate_text(&message, MAX_TEXT_BYTES, "provider failure message")?;
                    return Err(ProviderErrorKind::ProviderFailure { code, message });
                }
                other => {
                    return Err(ProviderErrorKind::UnexpectedFrame(format!(
                        "expected recognition response, received {other:?}"
                    )));
                }
            };
            let process_create_call_to_recognition_ns = elapsed_ns(create_process_call_started);
            let shutdown_deadline = Instant::now() + self.timeouts.shutdown;
            // Observe and release the direct process handle first. A descendant
            // may outlive its parent even when it closes all three stdio handles,
            // so keep the job open and repeatedly terminate/query its accounting
            // state until ActiveProcesses reaches zero before waiting for EOF.
            // The reader still rejects any third frame before success is accepted.
            let exit_code = child.wait_until(shutdown_deadline, cancelled)?;
            let process_create_call_to_parent_exit_ns = elapsed_ns(create_process_call_started);
            child.wait_for_job_tree_until(shutdown_deadline, cancelled)?;
            let process_create_call_to_tree_drain_ns = elapsed_ns(create_process_call_started);
            let process_resources = child.process_resources();
            receive_reader_completion(&reader_done_receiver, shutdown_deadline, cancelled)?;
            drop(response_receiver);
            drop(reader_done_receiver);
            child.finish_success(shutdown_deadline)?;

            if exit_code != 0 {
                return Err(ProviderErrorKind::WorkerExited {
                    exit_code: Some(exit_code as i32),
                });
            }
            let (stderr_bytes, stderr_truncated) = stderr_snapshot(&stderr_capture);
            Ok(ProviderExecution {
                provider,
                capabilities,
                result,
                stderr_bytes,
                stderr_truncated,
                raw_response_transcript: ProviderRawResponseTranscriptV1::default(),
                process_resources,
                timing: ProviderExecutionTimingV1 {
                    process_create_call_to_handshake_ns,
                    process_create_call_to_recognition_ns,
                    process_create_call_to_parent_exit_ns,
                    process_create_call_to_tree_drain_ns,
                    model_cold_start_ns: None,
                    model_cold_start_unavailable_reason: Some(
                        "the generic process protocol reports no separate model-load phase"
                            .to_owned(),
                    ),
                },
            })
        }));
        let attempt = match attempt {
            Ok(attempt) => attempt,
            Err(_) => Err(ProviderErrorKind::WorkerThreadPanicked),
        };

        match attempt {
            Ok(execution) => Ok(execution),
            Err(original_error) => Err(cleanup_failure_or_original(
                original_error,
                child.cleanup_after_failure(),
            )),
        }
    }

    #[cfg(not(windows))]
    fn run_inner(
        &self,
        request: RecognitionRequestV1,
        cancelled: &AtomicBool,
        _stderr_capture: Arc<Mutex<BoundedStderr>>,
        _raw_response_capture: Arc<Mutex<ProviderRawResponseTranscriptV1>>,
    ) -> Result<ProviderExecution, ProviderErrorKind> {
        let _ = (request, cancelled);
        Err(ProviderErrorKind::UnsupportedPlatform)
    }
}

fn verify_protocol_version(actual: u32) -> Result<(), ProviderErrorKind> {
    if actual == PROVIDER_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProviderErrorKind::ProtocolVersion {
            expected: PROVIDER_PROTOCOL_VERSION,
            actual,
        })
    }
}

fn validate_recognition_result(
    result: &RecognitionResultV1,
    request: &RecognitionRequestV1,
    provider: &ProviderIdentityV1,
    capabilities: &ProviderCapabilitiesV1,
) -> Result<(), ProviderErrorKind> {
    result.source_revision.validate()?;
    result.provider.validate()?;
    if result.source_revision != request.source_revision {
        return Err(ProviderErrorKind::StaleSourceRevision);
    }
    if result.request_id != request.request_id
        || result.input_view_id != request.input_view_id
        || result.region_id != request.region_id
        || result.line_id != request.line_id
    {
        return Err(ProviderErrorKind::ProviderRequestMismatch);
    }
    if result.provider_configuration_id != request.provider_configuration.configuration_id
        || result.provider_configuration_fingerprint != request.provider_configuration_fingerprint
    {
        return Err(ProviderErrorKind::ProviderConfigurationMismatch);
    }
    if result.consumed_input_modalities != request.requested_input_modalities {
        return Err(ProviderErrorKind::InvalidResponse(
            "provider did not acknowledge the exact requested input modalities".to_owned(),
        ));
    }
    if result.provider != *provider {
        return Err(ProviderErrorKind::InvalidResponse(
            "result provider provenance differs from handshake".to_owned(),
        ));
    }
    validate_text(
        &result.provider_provenance,
        MAX_TEXT_BYTES,
        "provider provenance",
    )?;
    if result.provider_provenance.is_empty() {
        return Err(ProviderErrorKind::InvalidResponse(
            "provider provenance must not be empty".to_owned(),
        ));
    }
    let mut valid_strokes = HashSet::new();
    valid_strokes
        .try_reserve(request.stroke_views.len())
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    for view in &request.stroke_views {
        valid_strokes.insert(view.stroke.clone());
    }
    let mut sequences_by_stroke = HashMap::<ProviderStrokeRefV1, HashSet<u64>>::new();
    sequences_by_stroke
        .try_reserve(request.stroke_views.len())
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    for sample in &request.samples {
        let sequences = sequences_by_stroke
            .entry(sample.stroke.clone())
            .or_default();
        sequences
            .try_reserve(1)
            .map_err(|_| ProviderErrorKind::AllocationFailed)?;
        sequences.insert(sample.journal_sequence);
    }
    if result.candidates.len() > 1
        && !capabilities
            .outputs
            .contains(&ProviderOutputCapabilityV1::NBest)
    {
        return Err(ProviderErrorKind::InvalidResponse(
            "provider returned multiple candidates without advertising N-best output".to_owned(),
        ));
    }
    for candidate in &result.candidates {
        validate_text(&candidate.recognized_text, MAX_TEXT_BYTES, "candidate text")?;
        if candidate.native_score_raw.is_some()
            && !capabilities
                .outputs
                .contains(&ProviderOutputCapabilityV1::NativeScore)
        {
            return Err(ProviderErrorKind::InvalidResponse(
                "provider returned a native score it did not advertise".to_owned(),
            ));
        }
        if candidate
            .native_score_raw
            .as_ref()
            .is_some_and(|number| number.as_f64().is_none_or(|score| !score.is_finite()))
        {
            return Err(ProviderErrorKind::InvalidResponse(
                "provider native score is not finite".to_owned(),
            ));
        }
        if !candidate.stroke_ranges.is_empty()
            && !capabilities
                .outputs
                .contains(&ProviderOutputCapabilityV1::StrokeRanges)
        {
            return Err(ProviderErrorKind::InvalidResponse(
                "provider returned stroke ranges it did not advertise".to_owned(),
            ));
        }
        for range in &candidate.stroke_ranges {
            range.stroke.validate()?;
            let sample_sequences = sequences_by_stroke.get(&range.stroke);
            if range.first_journal_sequence > range.last_journal_sequence
                || !valid_strokes.contains(&range.stroke)
                || sample_sequences.is_none_or(|sequences| {
                    !sequences.contains(&range.first_journal_sequence)
                        || !sequences.contains(&range.last_journal_sequence)
                })
            {
                return Err(ProviderErrorKind::InvalidResponse(
                    "candidate stroke range is reversed or references an unknown StrokeRef"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_capabilities_for_request(
    capabilities: &ProviderCapabilitiesV1,
    request: &RecognitionRequestV1,
) -> Result<(), ProviderErrorKind> {
    for modality in &request.requested_input_modalities {
        if !capabilities.inputs.contains(modality) {
            return Err(ProviderErrorKind::UnsupportedCapability(format!(
                "provider did not advertise requested {modality:?} input"
            )));
        }
    }
    if !capabilities
        .outputs
        .contains(&ProviderOutputCapabilityV1::Text)
    {
        return Err(ProviderErrorKind::UnsupportedCapability(
            "provider did not advertise text output".to_owned(),
        ));
    }
    if request
        .language_hints
        .iter()
        .any(|hint| !capabilities.languages.contains(hint))
    {
        return Err(ProviderErrorKind::UnsupportedCapability(
            "provider did not advertise every requested language hint".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_result_for_current_view(
    request: &RecognitionRequestV1,
    result: &RecognitionResultV1,
    current_source_revision: &ProviderSourceRevisionV1,
    current_input_view_id: &str,
) -> Result<(), ProviderErrorKind> {
    if result.source_revision != request.source_revision
        || request.source_revision.journal_id != current_source_revision.journal_id
        || request.source_revision.logical_revision != current_source_revision.logical_revision
    {
        return Err(ProviderErrorKind::StaleSourceRevision);
    }
    if request.input_view_id != current_input_view_id
        || result.input_view_id != current_input_view_id
        || result.request_id != request.request_id
        || result.region_id != request.region_id
        || result.line_id != request.line_id
    {
        return Err(ProviderErrorKind::ProviderRequestMismatch);
    }
    if result.consumed_input_modalities != request.requested_input_modalities {
        return Err(ProviderErrorKind::InvalidResponse(
            "provider did not acknowledge the exact requested input modalities".to_owned(),
        ));
    }
    if result.provider_configuration_id != request.provider_configuration.configuration_id
        || result.provider_configuration_fingerprint != request.provider_configuration_fingerprint
    {
        return Err(ProviderErrorKind::ProviderConfigurationMismatch);
    }
    Ok(())
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    maximum: usize,
    overflowed: bool,
}

impl BoundedBuffer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            overflowed: false,
        }
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(new_length) = self.bytes.len().checked_add(buffer.len()) else {
            self.overflowed = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "bounded JSON buffer length overflow",
            ));
        };
        if new_length > self.maximum {
            self.overflowed = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "bounded JSON buffer limit reached",
            ));
        }
        self.bytes
            .try_reserve(buffer.len())
            .map_err(|_| io::Error::other("bounded JSON buffer allocation failed"))?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json_bytes<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ProviderErrorKind> {
    let mut buffer = BoundedBuffer::new(maximum);
    if let Err(error) = serde_json::to_writer(&mut buffer, value) {
        if buffer.overflowed {
            return Err(ProviderErrorKind::OversizedFrame {
                actual: buffer.bytes.len().saturating_add(1),
                maximum,
            });
        }
        return Err(ProviderErrorKind::InvalidRequest(format!(
            "JSON serialization failed: {error}"
        )));
    }
    Ok(buffer.bytes)
}

fn encode_frame<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, ProviderErrorKind> {
    let payload = bounded_json_bytes(value, maximum)?;
    let length = u32::try_from(payload.len()).map_err(|_| ProviderErrorKind::OversizedFrame {
        actual: payload.len(),
        maximum,
    })?;
    let frame_length = payload
        .len()
        .checked_add(4)
        .ok_or(ProviderErrorKind::AllocationFailed)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(frame_length)
        .map_err(|_| ProviderErrorKind::AllocationFailed)?;
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn read_frame<R: Read>(reader: &mut R, maximum: usize) -> Result<Option<Vec<u8>>, String> {
    let mut prefix = [0u8; 4];
    loop {
        match reader.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => unreachable!("one-byte read cannot return more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("could not read frame prefix: {error}")),
        }
    }
    reader
        .read_exact(&mut prefix[1..])
        .map_err(|error| format!("truncated frame prefix: {error}"))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > maximum {
        return Err(format!(
            "worker frame length {length} is outside 1..={maximum} bytes"
        ));
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| "worker frame allocation failed".to_owned())?;
    payload.resize(length, 0);
    reader
        .read_exact(&mut payload)
        .map_err(|error| format!("truncated worker frame: {error}"))?;
    Ok(Some(payload))
}

fn read_worker_responses(
    mut stdout: impl Read,
    sender: SyncSender<Result<WorkerResponseFrameV1, String>>,
    completion: SyncSender<Result<(), String>>,
    raw_response_capture: Arc<Mutex<ProviderRawResponseTranscriptV1>>,
) {
    for (ordinal, maximum) in [MAX_HANDSHAKE_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES]
        .into_iter()
        .enumerate()
    {
        let frame = match read_frame(&mut stdout, maximum) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                let message = "worker closed stdout before protocol response".to_owned();
                mark_raw_response_capture_incomplete(&raw_response_capture);
                let _ = sender.send(Err(message.clone()));
                let _ = completion.send(Err(message));
                return;
            }
            Err(message) => {
                mark_raw_response_capture_incomplete(&raw_response_capture);
                let _ = sender.send(Err(message.clone()));
                let _ = completion.send(Err(message));
                return;
            }
        };
        let parsed = serde_json::from_slice::<WorkerResponseFrameV1>(&frame)
            .map_err(|error| format!("invalid worker response JSON: {error}"));
        match parsed {
            Ok(response) => {
                capture_raw_response_frame(&raw_response_capture, ordinal as u8, frame);
                if sender.send(Ok(response)).is_err() {
                    mark_raw_response_capture_incomplete(&raw_response_capture);
                    let _ = completion.send(Err("protocol response receiver closed".to_owned()));
                    return;
                }
            }
            Err(message) => {
                capture_raw_response_frame(&raw_response_capture, ordinal as u8, frame);
                mark_raw_response_capture_incomplete(&raw_response_capture);
                let _ = sender.send(Err(message.clone()));
                let _ = completion.send(Err(message));
                return;
            }
        }
    }

    let completion_status = match read_frame(&mut stdout, MAX_RESPONSE_FRAME_BYTES) {
        Ok(None) => {
            mark_raw_response_capture_clean_eof(&raw_response_capture);
            Ok(())
        }
        Ok(Some(frame)) => {
            capture_raw_response_frame(&raw_response_capture, 2, frame);
            mark_raw_response_capture_incomplete(&raw_response_capture);
            Err("worker emitted an unexpected third protocol frame".to_owned())
        }
        Err(message) => {
            mark_raw_response_capture_incomplete(&raw_response_capture);
            Err(message)
        }
    };
    let _ = completion.send(completion_status);
}

struct WorkerWriteCommand {
    frame: Vec<u8>,
    acknowledgement: SyncSender<Result<(), String>>,
}

fn write_worker_frames(mut stdin: impl Write, receiver: Receiver<WorkerWriteCommand>) {
    while let Ok(command) = receiver.recv() {
        let result = stdin
            .write_all(&command.frame)
            .and_then(|()| stdin.flush())
            .map_err(|error| error.to_string());
        let should_stop = result.is_err();
        let _ = command.acknowledgement.send(result);
        if should_stop {
            return;
        }
    }
}

fn send_frame_to_worker(
    sender: &SyncSender<WorkerWriteCommand>,
    frame: Vec<u8>,
    deadline: Instant,
    cancelled: &AtomicBool,
    phase: ProviderPhase,
) -> Result<(), ProviderErrorKind> {
    if cancelled.load(Ordering::Acquire) {
        return Err(ProviderErrorKind::Cancelled);
    }
    let (acknowledgement_sender, acknowledgement_receiver) = mpsc::sync_channel(1);
    let command = WorkerWriteCommand {
        frame,
        acknowledgement: acknowledgement_sender,
    };
    match sender.try_send(command) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            return Err(ProviderErrorKind::IoFailed {
                phase,
                message: "bounded provider stdin queue is full".to_owned(),
            });
        }
        Err(TrySendError::Disconnected(_)) => {
            return Err(ProviderErrorKind::IoFailed {
                phase,
                message: "provider stdin writer stopped".to_owned(),
            });
        }
    }
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(ProviderErrorKind::Cancelled);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ProviderErrorKind::TimedOut(phase));
        }
        match acknowledgement_receiver.recv_timeout(remaining.min(IO_POLL_INTERVAL)) {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(message)) => {
                return Err(ProviderErrorKind::IoFailed { phase, message });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(ProviderErrorKind::IoFailed {
                    phase,
                    message: "provider stdin writer acknowledgement was lost".to_owned(),
                });
            }
        }
    }
}

fn receive_worker_response(
    receiver: &Receiver<Result<WorkerResponseFrameV1, String>>,
    deadline: Instant,
    cancelled: &AtomicBool,
    phase: ProviderPhase,
) -> Result<WorkerResponseFrameV1, ProviderErrorKind> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(ProviderErrorKind::Cancelled);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ProviderErrorKind::TimedOut(phase));
        }
        match receiver.recv_timeout(remaining.min(IO_POLL_INTERVAL)) {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(message)) => {
                return Err(ProviderErrorKind::InvalidResponse(message));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(ProviderErrorKind::UnexpectedFrame(
                    "provider response channel closed before a frame arrived".to_owned(),
                ));
            }
        }
    }
}

fn receive_reader_completion(
    receiver: &Receiver<Result<(), String>>,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(), ProviderErrorKind> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(ProviderErrorKind::Cancelled);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ProviderErrorKind::TimedOut(ProviderPhase::Shutdown));
        }
        match receiver.recv_timeout(remaining.min(IO_POLL_INTERVAL)) {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(message)) => return Err(ProviderErrorKind::InvalidResponse(message)),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(ProviderErrorKind::InvalidResponse(
                    "provider stdout reader closed without clean EOF".to_owned(),
                ));
            }
        }
    }
}

#[derive(Default)]
struct BoundedStderr {
    bytes: Vec<u8>,
    truncated: bool,
}

fn drain_stderr(mut stderr: impl Read, capture: Arc<Mutex<BoundedStderr>>) {
    let mut buffer = [0u8; 4096];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => {
                let Ok(mut stored) = capture.lock() else {
                    return;
                };
                let remaining = MAX_STDERR_BYTES.saturating_sub(stored.bytes.len());
                let keep = remaining.min(read);
                if keep > 0 {
                    if stored.bytes.try_reserve(keep).is_ok() {
                        stored.bytes.extend_from_slice(&buffer[..keep]);
                    } else {
                        stored.truncated = true;
                    }
                }
                if keep < read || stored.bytes.len() >= MAX_STDERR_BYTES {
                    stored.truncated = true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

fn stderr_snapshot(capture: &Arc<Mutex<BoundedStderr>>) -> (Vec<u8>, bool) {
    match capture.lock() {
        Ok(stored) => (stored.bytes.clone(), stored.truncated),
        Err(_) => (Vec::new(), true),
    }
}

fn raw_response_snapshot(
    capture: &Arc<Mutex<ProviderRawResponseTranscriptV1>>,
) -> ProviderRawResponseTranscriptV1 {
    capture.lock().map_or_else(
        |_| ProviderRawResponseTranscriptV1 {
            frames: Vec::new(),
            capture_complete: false,
            omitted_frame_count: 1,
            omitted_payload_bytes: 0,
        },
        |stored| stored.clone(),
    )
}

fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

fn capture_raw_response_frame(
    capture: &Arc<Mutex<ProviderRawResponseTranscriptV1>>,
    ordinal: u8,
    payload_bytes: Vec<u8>,
) {
    if let Ok(mut stored) = capture.lock() {
        stored.capture_frame(ordinal, payload_bytes);
    }
}

fn mark_raw_response_capture_incomplete(capture: &Arc<Mutex<ProviderRawResponseTranscriptV1>>) {
    if let Ok(mut stored) = capture.lock() {
        stored.mark_incomplete();
    }
}

fn mark_raw_response_capture_clean_eof(capture: &Arc<Mutex<ProviderRawResponseTranscriptV1>>) {
    if let Ok(mut stored) = capture.lock() {
        stored.mark_clean_eof();
    }
}

#[cfg(windows)]
struct ChildGuard {
    child: Option<windows_process::NativeChild>,
    helpers: Vec<thread::JoinHandle<()>>,
    cleanup_permit: ProcessCleanupPermit,
    completed: bool,
}

#[cfg(windows)]
impl ChildGuard {
    fn new(cleanup_permit: ProcessCleanupPermit) -> Self {
        Self {
            child: None,
            helpers: Vec::new(),
            cleanup_permit,
            completed: false,
        }
    }

    fn attach_child(&mut self, child: windows_process::NativeChild) {
        self.child = Some(child);
    }

    fn reserve_helper_slot(&mut self) -> Result<(), ProviderErrorKind> {
        if self.helpers.len() >= MAX_PROVIDER_HELPER_THREADS {
            return Err(ProviderErrorKind::ProcessCleanupFailed(
                "provider helper-thread cap exceeded".to_owned(),
            ));
        }
        self.helpers
            .try_reserve(1)
            .map_err(|_| ProviderErrorKind::AllocationFailed)?;
        Ok(())
    }

    fn add_helper(&mut self, helper: thread::JoinHandle<()>) {
        self.helpers.push(helper);
    }

    fn child_mut(&mut self) -> &mut windows_process::NativeChild {
        self.child.as_mut().expect("child is owned until cleanup")
    }

    fn process_resources(&self) -> Option<ProviderProcessResourcesV1> {
        self.child
            .as_ref()
            .and_then(windows_process::NativeChild::process_resources)
    }

    fn wait_until(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<u32, ProviderErrorKind> {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(ProviderErrorKind::Cancelled);
            }
            if let Some(exit_code) =
                self.child_mut()
                    .try_wait()
                    .map_err(|error| ProviderErrorKind::IoFailed {
                        phase: ProviderPhase::Shutdown,
                        message: error.to_string(),
                    })?
            {
                return Ok(exit_code);
            }
            if Instant::now() >= deadline {
                return Err(ProviderErrorKind::TimedOut(ProviderPhase::Shutdown));
            }
            thread::sleep(IO_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    fn wait_for_job_tree_until(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<(), ProviderErrorKind> {
        self.child_mut()
            .wait_for_job_tree_until(deadline, cancelled)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::Interrupted => ProviderErrorKind::Cancelled,
                std::io::ErrorKind::TimedOut => ProviderErrorKind::ProcessCleanupFailed(format!(
                    "provider process tree did not drain: {error}"
                )),
                _ => ProviderErrorKind::ProcessCleanupFailed(format!(
                    "provider process-tree accounting/termination failed: {error}"
                )),
            })
    }

    fn finish_success(&mut self, deadline: Instant) -> Result<(), ProviderErrorKind> {
        if !self.wait_for_helpers(deadline) {
            self.cancel_helpers();
            let retry_deadline = Instant::now() + CHILD_CLEANUP_GRACE;
            if !self.wait_for_helpers(retry_deadline) {
                return Err(ProviderErrorKind::ProcessCleanupFailed(
                    concat!(
                        "provider stdio helpers did not stop after EOF and verified ",
                        "tree drain"
                    )
                    .to_owned(),
                ));
            }
        }
        self.join_finished_helpers()?;
        self.child_mut().close_job().map_err(|error| {
            ProviderErrorKind::ProcessCleanupFailed(format!(
                "provider Job Object could not be released after helpers joined: {error}"
            ))
        })?;
        if !self
            .child
            .as_ref()
            .is_some_and(windows_process::NativeChild::is_closed)
        {
            return Err(ProviderErrorKind::ProcessCleanupFailed(
                concat!(
                    "provider process tree, Job Object, or setup handle remained open ",
                    "after verified drain"
                )
                .to_owned(),
            ));
        }
        self.cleanup_permit.release();
        self.completed = true;
        Ok(())
    }

    fn wait_for_helpers(&self, deadline: Instant) -> bool {
        loop {
            if self.helpers.iter().all(|helper| helper.is_finished()) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(IO_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    fn cancel_helpers(&self) {
        for helper in &self.helpers {
            if !helper.is_finished() {
                windows_process::cancel_synchronous_io(helper);
            }
        }
    }

    fn join_finished_helpers(&mut self) -> Result<(), ProviderErrorKind> {
        let mut helper_panicked = false;
        for helper in self.helpers.drain(..) {
            if helper.join().is_err() {
                helper_panicked = true;
            }
        }
        if helper_panicked {
            Err(ProviderErrorKind::ProcessCleanupFailed(
                "provider stdio helper panicked".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    fn cleanup_after_failure(&mut self) -> Result<(), String> {
        if self.completed {
            return Ok(());
        }
        let had_prior_cleanup_fault = self
            .child
            .as_ref()
            .is_some_and(windows_process::NativeChild::cleanup_faulted);
        let process_tree_reaped = self
            .child
            .as_mut()
            .is_none_or(|child| child.terminate_and_reap(CHILD_CLEANUP_GRACE));
        self.cancel_helpers();
        let helper_deadline = Instant::now() + CHILD_CLEANUP_GRACE;
        let _ = self.wait_for_helpers(helper_deadline);
        let helpers_closed = self.helpers.iter().all(|helper| helper.is_finished());
        if process_tree_reaped && helpers_closed {
            let _ = self.join_finished_helpers();
        }
        let job_closed = if process_tree_reaped && helpers_closed && !had_prior_cleanup_fault {
            self.child
                .as_mut()
                .is_none_or(|child| child.close_job().is_ok())
        } else {
            false
        };
        let child_closed = self
            .child
            .as_ref()
            .is_none_or(windows_process::NativeChild::is_closed);
        if process_tree_reaped
            && helpers_closed
            && job_closed
            && child_closed
            && !had_prior_cleanup_fault
        {
            self.child.take();
            self.cleanup_permit.release();
            self.completed = true;
            return Ok(());
        }

        let failure = format!(
            "bounded cleanup did not confirm parent exit, Job Object ActiveProcesses == 0, \
             helper completion, and Job Object release \
             (process_tree_reaped={process_tree_reaped}, helpers_finished={helpers_closed}, \
             job_closed={job_closed}, prior_cleanup_fault={had_prior_cleanup_fault}); \
             owned handles retained in quarantine"
        );
        self.cleanup_permit
            .quarantine(self.child.take(), std::mem::take(&mut self.helpers));
        self.completed = true;
        Err(failure)
    }
}

#[cfg(windows)]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.cleanup_after_failure();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::{
        self, ApprovedBenchmarkProviderV1, BenchmarkAnnotationCaseV1, BenchmarkCaseManifestV1,
        BenchmarkCaseProvenanceV1, BenchmarkCaseSpecV1, BenchmarkClusterKeyV1,
        BenchmarkCorpusManifestV1, BenchmarkGeneratedRasterCropV1, BenchmarkGeneratedRasterSpecV1,
        BenchmarkProviderManifestV1, BenchmarkRasterInputSpecV1, BenchmarkSplitKeyV1,
        BenchmarkSplitV1, BenchmarkStrokeRefV1, BenchmarkTimeoutsV1, BenchmarkTokenizationPolicyV1,
        ProviderArtifactPathV1, ProviderArtifactRoleV1,
    };
    use crate::journal::{
        EditCommand, JournalHeader, JournalMetadata, JournalWriter, MetadataScope,
        StoredEditAction, StoredMetadata, StoredPhysicalSample, StoredStrokeStart,
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs,
        process::{self, Command},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    #[cfg(windows)]
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, WaitForSingleObject},
    };

    static NEXT_MOCK_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn json_value_contains_string(value: &serde_json::Value, needle: &str) -> bool {
        match value {
            serde_json::Value::String(value) => value.contains(needle),
            serde_json::Value::Array(values) => values
                .iter()
                .any(|value| json_value_contains_string(value, needle)),
            serde_json::Value::Object(values) => values
                .values()
                .any(|value| json_value_contains_string(value, needle)),
            _ => false,
        }
    }

    fn stroke_ref(stroke_id: &str, device_id: &str) -> StrokeRef {
        StrokeRef {
            journal_id: "provider-test-journal".to_owned(),
            session_id: "provider-test-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some(device_id.to_owned()),
            pointer_id: Some(17),
            stroke_id: stroke_id.to_owned(),
        }
    }

    fn physical_sample(target: &StrokeRef, source_sequence: u64, x: i64) -> PhysicalSample {
        PhysicalSample {
            session_id: target.session_id.clone(),
            source_api: target.source_api.clone(),
            source_device_id: target.device_id.clone(),
            pointer_id: target.pointer_id,
            stroke_id: Some(target.stroke_id.clone()),
            source_sequence,
            config_id: Some("provider-test-config".to_owned()),
            app_arrival_elapsed_ns: 18_446_744_073_709_551_617,
            position: Some(RawPosition {
                coordinate_space: "windows-screen-coordinates".to_owned(),
                units: "screen-pixel".to_owned(),
                x_raw: x,
                y_raw: 220,
            }),
            pressure: Some(RawPressure {
                representation: "raw-pen-mask-pressure".to_owned(),
                units: "device-range-unknown".to_owned(),
                value_raw: 513,
                mask_raw: Some(1),
                minimum_raw: Some(0),
                maximum_raw: Some(1024),
            }),
            native_timestamp: Some(NativeTimestamp {
                clock_domain: "POINTER_INFO.PerformanceCount/QPC".to_owned(),
                units: "ticks".to_owned(),
                count_raw: source_sequence * 10_000,
                frequency_hz: Some(10_000_000),
            }),
            contact_range_state: Some("InRange+Contact".to_owned()),
            button_state_raw: None,
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload: vec![0xd0, (source_sequence & 0xff) as u8, 1],
        }
    }

    fn fixture_state_and_selection() -> (JournalReplayState, Vec<StrokeRef>) {
        // The first sample has a lexically later StrokeRef, deliberately
        // differing from both selection order and CanvasScene's identity sort.
        let z_stroke = stroke_ref("z-stroke", "opaque-device-z");
        let a_stroke = stroke_ref("a-stroke", "opaque-device-a");
        let mut state = JournalReplayState::default();
        state.journal_id = "provider-test-journal".to_owned();
        state.current_session_id = "provider-test-session".to_owned();
        state.last_sequence = 30;
        state.logical_revision = 4;
        state.physical_samples.push(StoredPhysicalSample {
            sequence: 20,
            sample: physical_sample(&z_stroke, 501, 110),
        });
        state.physical_samples.push(StoredPhysicalSample {
            sequence: 22,
            sample: physical_sample(&z_stroke, 502, 114),
        });
        state.physical_samples.push(StoredPhysicalSample {
            sequence: 25,
            sample: physical_sample(&a_stroke, 301, 310),
        });
        state.stroke_starts.push(StoredStrokeStart {
            sequence: 12,
            app_epoch_id: z_stroke.session_id.clone(),
            app_arrival_elapsed_ns: 4,
            target: z_stroke.clone(),
            view_frame: StrokeViewFrame::default(),
        });
        state.stroke_starts.push(StoredStrokeStart {
            sequence: 15,
            app_epoch_id: a_stroke.session_id.clone(),
            app_arrival_elapsed_ns: 5,
            target: a_stroke.clone(),
            view_frame: StrokeViewFrame {
                screen_origin_x_px: 1234,
                screen_origin_y_px: 5678,
                dpi_scale_factor_bits: 1.5_f64.to_bits(),
                canvas_zoom_bits: 2.0_f64.to_bits(),
                canvas_pan_x_bits: 7.0_f64.to_bits(),
                canvas_pan_y_bits: 9.0_f64.to_bits(),
                toolbar_height_px: 42,
            },
        });
        state.edit_actions.push(StoredEditAction {
            sequence: 27,
            action_id: 27,
            revision_id: 4,
            app_epoch_id: z_stroke.session_id.clone(),
            app_arrival_elapsed_ns: 8,
            command: EditCommand::Move {
                target: z_stroke.clone(),
                delta_x_raw: 11,
                delta_y_raw: -7,
                coordinate_space: "windows-screen-coordinates".to_owned(),
                units: "screen-pixel".to_owned(),
            },
            active: true,
        });
        (state, vec![a_stroke, z_stroke])
    }

    fn fixture_configuration() -> ProviderConfigurationV1 {
        ProviderConfigurationV1 {
            configuration_id: "operator-approved-config".to_owned(),
            values: BTreeMap::from([("language-mode".to_owned(), "recognize".to_owned())]),
        }
    }

    #[test]
    fn provider_configuration_fingerprint_shared_golden_vector() {
        let configuration = fixture_configuration();
        assert_eq!(
            bounded_json_bytes(&configuration, MAX_REQUEST_FRAME_BYTES / 4).unwrap(),
            br#"{"configuration_id":"operator-approved-config","values":{"language-mode":"recognize"}}"#,
        );
        assert_eq!(
            configuration.fingerprint().unwrap(),
            "provider-config-v1-fnv64-5d449396c33394f8",
        );
    }

    #[test]
    fn provider_configuration_unicode_windows_path_shared_json_vector() {
        #[derive(serde::Deserialize)]
        struct SharedConfigFixture {
            schema_version: u32,
            configuration: ProviderConfigurationV1,
            canonical_json_utf8: String,
        }

        let fixture: SharedConfigFixture = serde_json::from_str(include_str!(
            "../tests/fixtures/provider_configuration_unicode_path_v1.json"
        ))
        .unwrap();
        assert_eq!(fixture.schema_version, 1);
        let maximum = MAX_REQUEST_FRAME_BYTES / 4;
        let actual = bounded_json_bytes(&fixture.configuration, maximum).unwrap();
        assert_eq!(actual.as_slice(), fixture.canonical_json_utf8.as_bytes());
    }

    #[test]
    fn input_view_fingerprint_matches_shared_fixture_payload_and_fnv() {
        #[derive(serde::Deserialize)]
        struct SharedInputViewFixture {
            request: RecognitionRequestV1,
            fingerprint_payload_hex: String,
            input_view_id: String,
        }

        let fixture: SharedInputViewFixture = serde_json::from_str(include_str!(
            "../tests/fixtures/provider_input_view_v1.json"
        ))
        .unwrap();
        let (_, request) = fixture_request();
        assert_eq!(request, fixture.request);

        let requested_input_modalities =
            canonicalize_input_modalities(&request.requested_input_modalities).unwrap();
        let fingerprint = RequestFingerprintV1 {
            protocol_version: request.protocol_version,
            source_journal_id: &request.source_revision.journal_id,
            logical_revision: request.source_revision.logical_revision,
            region_id: &request.region_id,
            line_id: &request.line_id,
            coordinate_space: &request.coordinate_space,
            coordinate_units: &request.coordinate_units,
            language_hints: &request.language_hints,
            requested_input_modalities: &requested_input_modalities,
            stroke_views: &request.stroke_views,
            samples: &request.samples,
            raster: &request.raster,
        };
        let payload = bounded_json_bytes(&fingerprint, MAX_REQUEST_FRAME_BYTES).unwrap();
        let mut payload_hex = String::new();
        use std::fmt::Write as _;
        for byte in &payload {
            write!(&mut payload_hex, "{byte:02x}").unwrap();
        }
        assert_eq!(payload_hex, fixture.fingerprint_payload_hex);
        assert_eq!(input_view_id(&request).unwrap(), fixture.input_view_id);
    }

    #[test]
    fn raster_input_view_fingerprint_matches_shared_fixture_payload_and_fnv() {
        #[derive(serde::Deserialize)]
        struct SharedRasterInputViewFixture {
            request: RecognitionRequestV1,
            fingerprint_payload_hex: String,
            input_view_id: String,
        }

        let fixture: SharedRasterInputViewFixture = serde_json::from_str(include_str!(
            "../tests/fixtures/provider_raster_input_view_v1.json"
        ))
        .unwrap();
        let (state, selected) = fixture_state_and_selection();
        let raster = ProviderRasterInputV1 {
            width: 1,
            height: 1,
            payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
            coordinate_space: "windows-screen-coordinates".to_owned(),
            units: "screen-pixel".to_owned(),
            raw_payload_hex: "00".to_owned(),
        };
        let request = fixture_request_with_inputs(
            &state,
            &selected,
            fixture_configuration(),
            vec![ProviderInputCapabilityV1::Raster],
            Some(raster),
        );
        assert_eq!(request, fixture.request);

        let requested_input_modalities =
            canonicalize_input_modalities(&request.requested_input_modalities).unwrap();
        let fingerprint = RequestFingerprintV1 {
            protocol_version: request.protocol_version,
            source_journal_id: &request.source_revision.journal_id,
            logical_revision: request.source_revision.logical_revision,
            region_id: &request.region_id,
            line_id: &request.line_id,
            coordinate_space: &request.coordinate_space,
            coordinate_units: &request.coordinate_units,
            language_hints: &request.language_hints,
            requested_input_modalities: &requested_input_modalities,
            stroke_views: &request.stroke_views,
            samples: &request.samples,
            raster: &request.raster,
        };
        let payload = bounded_json_bytes(&fingerprint, MAX_REQUEST_FRAME_BYTES).unwrap();
        let mut payload_hex = String::new();
        use std::fmt::Write as _;
        for byte in &payload {
            write!(&mut payload_hex, "{byte:02x}").unwrap();
        }
        assert_eq!(payload_hex, fixture.fingerprint_payload_hex);
        assert_eq!(input_view_id(&request).unwrap(), fixture.input_view_id);
    }

    fn fixture_request_for_state(
        state: &JournalReplayState,
        selected: &[StrokeRef],
        provider_configuration: ProviderConfigurationV1,
    ) -> RecognitionRequestV1 {
        fixture_request_with_inputs(
            state,
            selected,
            provider_configuration,
            vec![ProviderInputCapabilityV1::OnlineStrokes],
            None,
        )
    }

    fn fixture_request_with_inputs(
        state: &JournalReplayState,
        selected: &[StrokeRef],
        provider_configuration: ProviderConfigurationV1,
        requested_input_modalities: Vec<ProviderInputCapabilityV1>,
        raster: Option<ProviderRasterInputV1>,
    ) -> RecognitionRequestV1 {
        build_recognition_request(RecognitionRequestBuildInput {
            state,
            request_id: "request-1".to_owned(),
            region_id: "region-1".to_owned(),
            line_id: "line-2".to_owned(),
            coordinate_space: "windows-screen-coordinates".to_owned(),
            coordinate_units: "screen-pixel".to_owned(),
            language_hints: vec!["vi-VN".to_owned(), "en-US".to_owned()],
            requested_input_modalities,
            provider_configuration,
            selected_strokes: selected,
            raster,
        })
        .unwrap()
    }

    fn fixture_request() -> (JournalReplayState, RecognitionRequestV1) {
        let (state, selected) = fixture_state_and_selection();
        let request = fixture_request_for_state(&state, &selected, fixture_configuration());
        (state, request)
    }

    fn fixture_provider() -> ProviderIdentityV1 {
        ProviderIdentityV1 {
            provider_id: "mock-provider".to_owned(),
            provider_version: "0.0.0-ci-fixture".to_owned(),
            model_version: Some("fixture-model".to_owned()),
            resource_version: Some("fixture-resource".to_owned()),
        }
    }

    fn fixture_capabilities() -> ProviderCapabilitiesV1 {
        fixture_capabilities_with_inputs(vec![ProviderInputCapabilityV1::OnlineStrokes])
    }

    fn fixture_capabilities_with_inputs(
        inputs: Vec<ProviderInputCapabilityV1>,
    ) -> ProviderCapabilitiesV1 {
        ProviderCapabilitiesV1 {
            inputs,
            outputs: vec![
                ProviderOutputCapabilityV1::Text,
                ProviderOutputCapabilityV1::NativeScore,
                ProviderOutputCapabilityV1::StrokeRanges,
            ],
            languages: vec!["vi-VN".to_owned(), "en-US".to_owned()],
        }
    }

    fn fixture_result(
        request: &RecognitionRequestV1,
        source_revision: ProviderSourceRevisionV1,
    ) -> RecognitionResultV1 {
        let score = serde_json::Number::from_f64(0.75).unwrap();
        RecognitionResultV1 {
            request_id: request.request_id.clone(),
            input_view_id: request.input_view_id.clone(),
            source_revision,
            region_id: request.region_id.clone(),
            line_id: request.line_id.clone(),
            provider_configuration_id: request.provider_configuration.configuration_id.clone(),
            provider_configuration_fingerprint: request.provider_configuration_fingerprint.clone(),
            provider: fixture_provider(),
            provider_provenance: "CI-only mock fixture; not recognition evidence".to_owned(),
            consumed_input_modalities: request.requested_input_modalities.clone(),
            candidates: vec![ProviderCandidateV1 {
                recognized_text: "fixture text".to_owned(),
                native_score_raw: Some(score),
                stroke_ranges: vec![ProviderStrokeRangeV1 {
                    stroke: request.stroke_views[0].stroke.clone(),
                    first_journal_sequence: request.samples[0].journal_sequence,
                    last_journal_sequence: request.samples[0].journal_sequence,
                }],
                raw_candidate: serde_json::json!({
                    "text": "fixture text",
                    "native_score": 0.75,
                    "source": "test-only"
                }),
            }],
        }
    }

    #[test]
    fn request_keeps_journal_order_raw_provenance_and_per_stroke_view() {
        let (state, request) = fixture_request();
        assert_eq!(request.protocol_version, PROVIDER_PROTOCOL_VERSION);
        assert_eq!(request.source_revision.journal_id, state.journal_id);
        assert_eq!(request.source_revision.logical_revision, 4);
        assert_eq!(request.source_revision.last_sequence, 30);
        assert_eq!(request.region_id, "region-1");
        assert_eq!(request.line_id, "line-2");
        assert_eq!(
            request.language_hints,
            vec!["vi-VN".to_owned(), "en-US".to_owned()]
        );
        assert_eq!(
            request.provider_configuration.configuration_id,
            "operator-approved-config"
        );
        assert_eq!(
            request
                .samples
                .iter()
                .map(|sample| sample.journal_sequence)
                .collect::<Vec<_>>(),
            vec![20, 22, 25]
        );
        assert_eq!(request.samples[0].source_sequence_raw, 501);
        assert_eq!(request.samples[1].source_sequence_raw, 502);
        assert_eq!(request.samples[2].source_sequence_raw, 301);
        assert_eq!(request.samples[0].stroke.stroke_id, "z-stroke");
        assert_eq!(request.samples[1].stroke.stroke_id, "z-stroke");
        assert_eq!(request.samples[2].stroke.stroke_id, "a-stroke");
        assert_eq!(request.samples[0].position.as_ref().unwrap().x_raw, 110);
        let moved = request.samples[0].effective_position.as_ref().unwrap();
        assert_eq!((moved.x_raw, moved.y_raw), (121, 213));
        assert_eq!(
            state.physical_samples[0]
                .sample
                .position
                .as_ref()
                .unwrap()
                .x_raw,
            110,
            "provider effective geometry never rewrites journal raw coordinates"
        );
        assert_eq!(request.samples[0].raw_payload_hex, "d0f501");
        assert_eq!(
            request.samples[0].position.as_ref().unwrap().units,
            "screen-pixel"
        );
        assert_eq!(
            request.samples[0].app_arrival_elapsed_ns_decimal,
            "18446744073709551617"
        );
        assert_eq!(request.stroke_views[0].stroke.stroke_id, "z-stroke");
        assert_eq!(request.stroke_views[1].stroke.stroke_id, "a-stroke");
        assert_eq!(
            request.stroke_views[1]
                .view_frame
                .unwrap()
                .screen_origin_x_px,
            1234
        );
        let (_, repeated) = fixture_request();
        assert_eq!(request.input_view_id, repeated.input_view_id);

        let (_, selected) = fixture_state_and_selection();
        let mut no_move_state = state.clone();
        no_move_state.edit_actions.clear();
        let no_move_request =
            fixture_request_for_state(&no_move_state, &selected, fixture_configuration());
        assert_eq!(request.source_revision, no_move_request.source_revision);
        assert_ne!(request.input_view_id, no_move_request.input_view_id);

        let mut later_revision = state.clone();
        later_revision.logical_revision += 1;
        later_revision.last_sequence += 1;
        let later_request =
            fixture_request_for_state(&later_revision, &selected, fixture_configuration());
        assert_ne!(request.source_revision, later_request.source_revision);
        assert_ne!(request.input_view_id, later_request.input_view_id);
    }

    #[test]
    fn approval_requires_an_absolute_executable_and_nonempty_provider_identity() {
        let relative = OperatorApprovedProviderConfig::from_explicit_selection(
            "mock-provider".to_owned(),
            PathBuf::from("relative-provider.exe"),
            Vec::new(),
            fixture_configuration(),
        );
        assert!(matches!(
            relative,
            Err(ProviderErrorKind::InvalidConfiguration(_))
        ));
        let empty_id = OperatorApprovedProviderConfig::from_explicit_selection(
            String::new(),
            std::env::current_exe().unwrap(),
            Vec::new(),
            fixture_configuration(),
        );
        assert!(matches!(
            empty_id,
            Err(ProviderErrorKind::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn unrelated_appends_preserve_freshness_but_logical_edits_stale_results() {
        let (mut state, selected) = fixture_state_and_selection();
        let request = fixture_request_for_state(&state, &selected, fixture_configuration());
        let result = fixture_result(&request, request.source_revision.clone());
        let mut wrong_boundary_echo = result.clone();
        wrong_boundary_echo.source_revision.last_sequence += 1;
        assert_eq!(
            validate_recognition_result(
                &wrong_boundary_echo,
                &request,
                &fixture_provider(),
                &fixture_capabilities()
            ),
            Err(ProviderErrorKind::StaleSourceRevision)
        );

        let mut hover = physical_sample(&selected[0], 901, 999);
        hover.stroke_id = None;
        state.physical_samples.push(StoredPhysicalSample {
            sequence: 31,
            sample: hover,
        });
        state.metadata_history.push(StoredMetadata {
            sequence: 32,
            app_epoch_id: state.current_session_id.clone(),
            metadata: JournalMetadata {
                scope: MetadataScope::Session,
                scope_id: state.current_session_id.clone(),
                source_api: None,
                device_id: None,
                key: "provider-test-note".to_owned(),
                value: "unrelated metadata append".to_owned(),
                provenance: "test fixture".to_owned(),
                app_arrival_elapsed_ns: 99,
            },
        });
        state.last_sequence = 32;
        let latest_unrelated =
            fixture_request_for_state(&state, &selected, fixture_configuration());
        assert_ne!(
            request.source_revision.last_sequence,
            latest_unrelated.source_revision.last_sequence
        );
        assert_eq!(request.input_view_id, latest_unrelated.input_view_id);
        assert!(
            validate_result_for_current_view(
                &request,
                &result,
                &latest_unrelated.source_revision,
                &latest_unrelated.input_view_id
            )
            .is_ok()
        );

        let mut edited = state.clone();
        edited.logical_revision += 1;
        if let EditCommand::Move { delta_x_raw, .. } = &mut edited.edit_actions[0].command {
            *delta_x_raw += 1;
        }
        let edited_request = fixture_request_for_state(&edited, &selected, fixture_configuration());
        assert_ne!(request.input_view_id, edited_request.input_view_id);
        assert_eq!(
            validate_result_for_current_view(
                &request,
                &result,
                &edited_request.source_revision,
                &edited_request.input_view_id
            ),
            Err(ProviderErrorKind::StaleSourceRevision)
        );

        assert_eq!(
            validate_result_for_current_view(
                &request,
                &result,
                &latest_unrelated.source_revision,
                "another-input-view"
            ),
            Err(ProviderErrorKind::ProviderRequestMismatch)
        );
    }

    #[test]
    fn input_view_is_provider_independent_but_result_binding_is_not() {
        let (state, selected) = fixture_state_and_selection();
        let provider_a = fixture_configuration();
        let provider_b = ProviderConfigurationV1 {
            configuration_id: "operator-approved-config-b".to_owned(),
            values: BTreeMap::from([("language-mode".to_owned(), "dictation".to_owned())]),
        };
        let request_a = fixture_request_for_state(&state, &selected, provider_a);
        let request_b = fixture_request_for_state(&state, &selected, provider_b);
        assert_eq!(request_a.source_revision, request_b.source_revision);
        assert_eq!(request_a.input_view_id, request_b.input_view_id);
        assert_ne!(
            request_a.provider_configuration_fingerprint,
            request_b.provider_configuration_fingerprint
        );

        let result_a = fixture_result(&request_a, request_a.source_revision.clone());
        assert_eq!(result_a.input_view_id, request_b.input_view_id);
        assert_eq!(
            validate_recognition_result(
                &result_a,
                &request_b,
                &fixture_provider(),
                &fixture_capabilities()
            ),
            Err(ProviderErrorKind::ProviderConfigurationMismatch)
        );
        assert_eq!(
            validate_result_for_current_view(
                &request_b,
                &result_a,
                &request_b.source_revision,
                &request_b.input_view_id
            ),
            Err(ProviderErrorKind::ProviderConfigurationMismatch)
        );

        let mut wrong_request_result =
            fixture_result(&request_b, request_b.source_revision.clone());
        wrong_request_result.request_id = "another-request".to_owned();
        assert_eq!(
            validate_recognition_result(
                &wrong_request_result,
                &request_b,
                &fixture_provider(),
                &fixture_capabilities()
            ),
            Err(ProviderErrorKind::ProviderRequestMismatch)
        );

        let mut wrong_provider_result =
            fixture_result(&request_b, request_b.source_revision.clone());
        wrong_provider_result.provider.provider_id = "another-provider".to_owned();
        assert!(matches!(
            validate_recognition_result(
                &wrong_provider_result,
                &request_b,
                &fixture_provider(),
                &fixture_capabilities()
            ),
            Err(ProviderErrorKind::InvalidResponse(_))
        ));
    }

    #[test]
    fn provider_stroke_ranges_must_end_on_submitted_samples() {
        let (_, request) = fixture_request();
        let provider = fixture_provider();
        let capabilities = fixture_capabilities();
        let mut valid = fixture_result(&request, request.source_revision.clone());
        valid.candidates[0].stroke_ranges[0].last_journal_sequence = 22;
        assert!(validate_recognition_result(&valid, &request, &provider, &capabilities).is_ok());

        let mut missing_end = valid.clone();
        missing_end.candidates[0].stroke_ranges[0].last_journal_sequence = 21;
        assert!(matches!(
            validate_recognition_result(&missing_end, &request, &provider, &capabilities),
            Err(ProviderErrorKind::InvalidResponse(_))
        ));
        let mut missing_start = valid;
        missing_start.candidates[0].stroke_ranges[0].first_journal_sequence = 21;
        assert!(matches!(
            validate_recognition_result(&missing_start, &request, &provider, &capabilities),
            Err(ProviderErrorKind::InvalidResponse(_))
        ));
    }

    #[test]
    fn multiple_candidates_require_negotiated_nbest_capability() {
        let (_, request) = fixture_request();
        let provider = fixture_provider();
        let mut result = fixture_result(&request, request.source_revision.clone());
        result.candidates.push(result.candidates[0].clone());
        let mut capabilities = fixture_capabilities();
        assert!(matches!(
            validate_recognition_result(&result, &request, &provider, &capabilities),
            Err(ProviderErrorKind::InvalidResponse(_))
        ));
        capabilities.outputs.push(ProviderOutputCapabilityV1::NBest);
        assert!(validate_recognition_result(&result, &request, &provider, &capabilities).is_ok());
    }

    #[test]
    fn requested_modalities_require_available_and_advertised_inputs() {
        let (state, selected) = fixture_state_and_selection();
        let online_request = fixture_request_for_state(&state, &selected, fixture_configuration());
        let online_capabilities = ProviderCapabilitiesV1 {
            inputs: vec![ProviderInputCapabilityV1::OnlineStrokes],
            outputs: vec![ProviderOutputCapabilityV1::Text],
            languages: vec!["vi-VN".to_owned(), "en-US".to_owned()],
        };
        assert!(validate_capabilities_for_request(&online_capabilities, &online_request).is_ok());

        let raster = ProviderRasterInputV1 {
            width: 1,
            height: 1,
            payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
            coordinate_space: "windows-screen-coordinates".to_owned(),
            units: "screen-pixel".to_owned(),
            raw_payload_hex: "00".to_owned(),
        };
        let raster_request = fixture_request_with_inputs(
            &state,
            &selected,
            fixture_configuration(),
            vec![ProviderInputCapabilityV1::Raster],
            Some(raster.clone()),
        );
        assert_ne!(online_request.input_view_id, raster_request.input_view_id);
        assert!(!raster_request.stroke_views.is_empty());
        assert!(!raster_request.samples.is_empty());
        let raster_capabilities = ProviderCapabilitiesV1 {
            inputs: vec![ProviderInputCapabilityV1::Raster],
            outputs: vec![
                ProviderOutputCapabilityV1::Text,
                ProviderOutputCapabilityV1::NativeScore,
                ProviderOutputCapabilityV1::StrokeRanges,
            ],
            languages: vec!["vi-VN".to_owned(), "en-US".to_owned()],
        };
        assert!(validate_capabilities_for_request(&raster_capabilities, &raster_request).is_ok());
        let raster_result = fixture_result(&raster_request, raster_request.source_revision.clone());
        assert!(
            validate_recognition_result(
                &raster_result,
                &raster_request,
                &fixture_provider(),
                &raster_capabilities
            )
            .is_ok()
        );

        let both_request = fixture_request_with_inputs(
            &state,
            &selected,
            fixture_configuration(),
            vec![
                ProviderInputCapabilityV1::OnlineStrokes,
                ProviderInputCapabilityV1::Raster,
            ],
            Some(raster.clone()),
        );
        let reversed_both_request = fixture_request_with_inputs(
            &state,
            &selected,
            fixture_configuration(),
            vec![
                ProviderInputCapabilityV1::Raster,
                ProviderInputCapabilityV1::OnlineStrokes,
            ],
            Some(raster.clone()),
        );
        let both_capabilities = ProviderCapabilitiesV1 {
            inputs: vec![
                ProviderInputCapabilityV1::OnlineStrokes,
                ProviderInputCapabilityV1::Raster,
            ],
            outputs: vec![ProviderOutputCapabilityV1::Text],
            languages: vec!["vi-VN".to_owned(), "en-US".to_owned()],
        };
        assert!(validate_capabilities_for_request(&both_capabilities, &both_request).is_ok());
        assert_eq!(
            both_request.requested_input_modalities,
            reversed_both_request.requested_input_modalities
        );
        assert_eq!(
            both_request.input_view_id,
            reversed_both_request.input_view_id
        );
        let mut reversed_wire_request = both_request.clone();
        reversed_wire_request.requested_input_modalities = vec![
            ProviderInputCapabilityV1::Raster,
            ProviderInputCapabilityV1::OnlineStrokes,
        ];
        assert!(validate_request_admission(&reversed_wire_request).is_ok());
        assert_eq!(
            input_view_id(&reversed_wire_request).unwrap(),
            both_request.input_view_id
        );
        assert_ne!(raster_request.input_view_id, both_request.input_view_id);
        assert!(matches!(
            validate_capabilities_for_request(&raster_capabilities, &both_request),
            Err(ProviderErrorKind::UnsupportedCapability(_))
        ));
        let mut unacknowledged =
            fixture_result(&both_request, both_request.source_revision.clone());
        unacknowledged.consumed_input_modalities = vec![ProviderInputCapabilityV1::OnlineStrokes];
        assert!(matches!(
            validate_recognition_result(
                &unacknowledged,
                &both_request,
                &fixture_provider(),
                &both_capabilities
            ),
            Err(ProviderErrorKind::InvalidResponse(_))
        ));

        let mut missing_required = raster_request.clone();
        missing_required.raster = None;
        assert!(matches!(
            validate_request_admission(&missing_required),
            Err(ProviderErrorKind::InvalidRequest(_))
        ));
        assert!(matches!(
            validate_capabilities_for_request(&online_capabilities, &raster_request),
            Err(ProviderErrorKind::UnsupportedCapability(_))
        ));

        let mut empty_payload = raster_request;
        empty_payload
            .raster
            .as_mut()
            .unwrap()
            .raw_payload_hex
            .clear();
        assert!(matches!(
            input_view_id(&empty_payload),
            Err(ProviderErrorKind::InvalidRequest(_))
        ));
        assert!(matches!(
            validate_request_admission(&empty_payload),
            Err(ProviderErrorKind::InvalidRequest(_))
        ));
    }

    #[test]
    fn bounded_json_writer_and_candidate_parser_reject_caps() {
        assert!(matches!(
            bounded_json_bytes(&"large string", 4),
            Err(ProviderErrorKind::OversizedFrame { .. })
        ));

        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct CandidateList {
            #[serde(deserialize_with = "deserialize_bounded_candidates")]
            candidates: Vec<ProviderCandidateV1>,
        }
        let candidate = r#"{"recognized_text":"x","native_score_raw":null,"stroke_ranges":[],"raw_candidate":{}}"#;
        let mut json = String::from("{\"candidates\":[");
        for index in 0..=MAX_PROVIDER_CANDIDATES {
            if index > 0 {
                json.push(',');
            }
            json.push_str(candidate);
        }
        json.push_str("]}");
        assert!(serde_json::from_str::<CandidateList>(&json).is_err());
    }

    #[test]
    fn incomplete_process_cleanup_is_reported_and_quarantine_blocks_launches() {
        assert_eq!(
            cleanup_failure_or_original(ProviderErrorKind::Cancelled, Ok(())),
            ProviderErrorKind::Cancelled
        );
        assert!(matches!(
            cleanup_failure_or_original(
                ProviderErrorKind::TimedOut(ProviderPhase::Recognition),
                Err("helper and process remain owned in quarantine".to_owned())
            ),
            ProviderErrorKind::ProcessCleanupFailed(message)
                if message.contains("TimedOut(Recognition)")
                    && message.contains("owned in quarantine")
        ));
        assert_eq!(ensure_no_quarantined_provider_sessions(0), Ok(()));
        assert_eq!(
            ensure_no_quarantined_provider_sessions(1),
            Err(ProviderErrorKind::WorkerSubsystemPoisoned)
        );
        assert!(!quarantine_can_release(false, true, true));
        assert!(!quarantine_can_release(true, true, false));
        assert!(quarantine_can_release(true, true, true));
    }

    #[test]
    fn versioned_json_frames_round_trip_typed_handshake_and_request() {
        let (_, request) = fixture_request();
        let frames = [
            WorkerRequestFrameV1::Handshake {
                protocol_version: PROVIDER_PROTOCOL_VERSION,
                provider_id: "mock-provider".to_owned(),
                configuration_id: request.provider_configuration.configuration_id.clone(),
                configuration_fingerprint: request.provider_configuration_fingerprint.clone(),
            },
            WorkerRequestFrameV1::Recognize {
                protocol_version: PROVIDER_PROTOCOL_VERSION,
                request: Box::new(request),
            },
        ];
        for frame in frames {
            let encoded = encode_frame(&frame, MAX_REQUEST_FRAME_BYTES).unwrap();
            let length = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
            assert_eq!(length, encoded.len() - 4);
            let decoded = serde_json::from_slice::<WorkerRequestFrameV1>(&encoded[4..]).unwrap();
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn response_frame_length_is_checked_before_body_allocation() {
        let oversized_length = (MAX_RESPONSE_FRAME_BYTES as u32 + 1).to_be_bytes();
        let mut input = io::Cursor::new(oversized_length);
        assert!(read_frame(&mut input, MAX_RESPONSE_FRAME_BYTES).is_err());
    }

    #[test]
    fn raw_response_transcript_preserves_two_frames_clean_eof_and_incomplete_cases() {
        let (_, request) = fixture_request();
        let handshake = WorkerResponseFrameV1::Handshake {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            provider: fixture_provider(),
            configuration_id: request.provider_configuration.configuration_id.clone(),
            configuration_fingerprint: request.provider_configuration_fingerprint.clone(),
            capabilities: fixture_capabilities(),
        };
        let recognition = WorkerResponseFrameV1::Recognition {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            result: fixture_result(&request, request.source_revision.clone()),
        };
        let handshake_frame = encode_frame(&handshake, MAX_HANDSHAKE_FRAME_BYTES).unwrap();
        let recognition_frame = encode_frame(&recognition, MAX_RESPONSE_FRAME_BYTES).unwrap();
        let mut clean_stream = handshake_frame.clone();
        clean_stream.extend_from_slice(&recognition_frame);
        let (response_sender, responses) = mpsc::sync_channel(2);
        let (completion_sender, completion) = mpsc::sync_channel(1);
        let capture = Arc::new(Mutex::new(ProviderRawResponseTranscriptV1::default()));
        read_worker_responses(
            io::Cursor::new(clean_stream),
            response_sender,
            completion_sender,
            Arc::clone(&capture),
        );
        assert!(completion.recv().unwrap().is_ok());
        assert!(matches!(
            responses.recv().unwrap(),
            Ok(WorkerResponseFrameV1::Handshake { .. })
        ));
        assert!(matches!(
            responses.recv().unwrap(),
            Ok(WorkerResponseFrameV1::Recognition { .. })
        ));
        let transcript = capture.lock().unwrap().clone();
        assert!(transcript.capture_complete);
        assert_eq!(transcript.frames.len(), 2);
        assert_eq!(transcript.frames[0].ordinal, 0);
        assert_eq!(&transcript.frames[0].payload_bytes, &handshake_frame[4..]);
        assert_eq!(transcript.frames[1].ordinal, 1);
        assert_eq!(&transcript.frames[1].payload_bytes, &recognition_frame[4..]);

        let third_frame = encode_frame(
            &WorkerResponseFrameV1::Failure {
                protocol_version: PROVIDER_PROTOCOL_VERSION,
                code: "unexpected".to_owned(),
                message: "third frame fixture".to_owned(),
            },
            MAX_RESPONSE_FRAME_BYTES,
        )
        .unwrap();
        let mut extra_stream = handshake_frame.clone();
        extra_stream.extend_from_slice(&recognition_frame);
        extra_stream.extend_from_slice(&third_frame);
        let (response_sender, responses) = mpsc::sync_channel(2);
        let (completion_sender, completion) = mpsc::sync_channel(1);
        let extra_capture = Arc::new(Mutex::new(ProviderRawResponseTranscriptV1::default()));
        read_worker_responses(
            io::Cursor::new(extra_stream),
            response_sender,
            completion_sender,
            Arc::clone(&extra_capture),
        );
        assert!(responses.recv().unwrap().is_ok());
        assert!(responses.recv().unwrap().is_ok());
        let completion_error = completion.recv().unwrap().unwrap_err();
        assert!(completion_error.contains("unexpected third"));
        let transcript = extra_capture.lock().unwrap().clone();
        assert!(!transcript.capture_complete);
        assert_eq!(transcript.frames.len(), 3);
        assert_eq!(&transcript.frames[2].payload_bytes, &third_frame[4..]);

        let (response_sender, responses) = mpsc::sync_channel(2);
        let (completion_sender, completion) = mpsc::sync_channel(1);
        let partial_capture = Arc::new(Mutex::new(ProviderRawResponseTranscriptV1::default()));
        read_worker_responses(
            io::Cursor::new(handshake_frame),
            response_sender,
            completion_sender,
            Arc::clone(&partial_capture),
        );
        assert!(responses.recv().unwrap().is_ok());
        assert!(completion.recv().unwrap().is_err());
        let transcript = partial_capture.lock().unwrap().clone();
        assert!(!transcript.capture_complete);
        assert_eq!(transcript.frames.len(), 1);
    }

    #[test]
    fn stderr_is_drained_while_retention_stays_byte_capped() {
        let capture = Arc::new(Mutex::new(BoundedStderr::default()));
        let bytes = vec![b'x'; MAX_STDERR_BYTES + 32];
        drain_stderr(io::Cursor::new(bytes), Arc::clone(&capture));
        let (retained, truncated) = stderr_snapshot(&capture);
        assert_eq!(retained.len(), MAX_STDERR_BYTES);
        assert!(truncated);
    }

    fn require_provider_mock_test_opt_in() {
        fn env_is(key: &str, expected: &str) -> bool {
            std::env::var(key).is_ok_and(|actual| actual == expected)
        }
        let github_event =
            env_is("GITHUB_EVENT_NAME", "push") || env_is("GITHUB_EVENT_NAME", "pull_request");
        assert!(
            cfg!(target_os = "windows")
                && env_is("LASSOINK_RUN_PROVIDER_MOCK_TESTS", "1")
                && env_is("CI", "true")
                && env_is("GITHUB_ACTIONS", "true")
                && env_is("RUNNER_ENVIRONMENT", "github-hosted")
                && env_is("RUNNER_OS", "Windows")
                && env_is("GITHUB_REPOSITORY", "Herzchens/LassoInk")
                && github_event,
            "provider subprocess tests require the guarded GitHub-hosted Windows CI job"
        );
    }

    #[cfg(windows)]
    fn require_senocr_m4_worker_test_opt_in() {
        assert!(
            std::env::var("LASSOINK_RUN_SENOCR_M4_E2E").is_ok_and(|value| value == "1"),
            "the model-backed M4 worker test requires its dedicated hosted opt-in"
        );
        require_provider_mock_test_opt_in();
        let expected_head = std::env::var("LASSOINK_EXPECTED_HEAD_SHA")
            .expect("the guarded worker job provides its exact PR head");
        assert_eq!(expected_head.len(), 40, "expected a full PR head SHA");
        assert!(
            expected_head
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(
            std::env::var("LASSOINK_CHECKED_OUT_HEAD_SHA")
                .is_ok_and(|actual| actual == expected_head)
        );
        assert!(
            std::env::var("LASSOINK_EXPECTED_HEAD_REPOSITORY")
                .is_ok_and(|actual| actual == "Herzchens/LassoInk")
        );
        assert!(
            std::env::var("LASSOINK_EXPECTED_HEAD_REF")
                .is_ok_and(|actual| actual == "feat/benchmark-fidelity")
        );
        assert!(std::env::var("GITHUB_EVENT_NAME").is_ok_and(|actual| actual == "pull_request"));
        assert!(
            std::env::var("GITHUB_HEAD_REF")
                .is_ok_and(|actual| actual == "feat/benchmark-fidelity")
        );
        assert!(std::env::var("RUNNER_ARCH").is_ok_and(|actual| actual == "X64"));
    }

    struct MockWorkerBinary {
        directory: PathBuf,
        executable: PathBuf,
    }

    impl Drop for MockWorkerBinary {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn compile_mock_worker() -> MockWorkerBinary {
        require_provider_mock_test_opt_in();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = NEXT_MOCK_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "lassoink-provider-mock-{}-{nonce}-{sequence}",
            process::id()
        ));
        fs::create_dir(&directory).expect("create unique provider mock temp directory");
        let source_path = directory.join("provider_mock_worker.rs");
        let executable = directory.join("provider_mock_worker.exe");
        fs::write(
            &source_path,
            include_str!("../tests/fixtures/provider_mock_worker.rs"),
        )
        .expect("write test-only provider mock source");
        let mock = MockWorkerBinary {
            directory,
            executable,
        };
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let output = Command::new(rustc)
            .arg("--edition=2024")
            .arg(&source_path)
            .arg("-o")
            .arg(&mock.executable)
            .output()
            .expect("compile the test-only provider mock in the CI temp directory");
        assert!(
            output.status.success(),
            "test-only mock compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        mock
    }

    fn run_mock_worker(
        executable: &std::path::Path,
        mode: &str,
        response: String,
        request: RecognitionRequestV1,
        recognition_timeout: Duration,
    ) -> Result<ProviderExecution, ProviderExecutionError> {
        run_mock_worker_with_arguments(
            executable,
            mode,
            response,
            request,
            recognition_timeout,
            &[],
        )
    }

    fn run_mock_worker_with_arguments(
        executable: &std::path::Path,
        mode: &str,
        response: String,
        request: RecognitionRequestV1,
        recognition_timeout: Duration,
        trailing_arguments: &[String],
    ) -> Result<ProviderExecution, ProviderExecutionError> {
        let configuration = request.provider_configuration.clone();
        let handshake_response = serde_json::to_string(&WorkerResponseFrameV1::Handshake {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            provider: fixture_provider(),
            configuration_id: configuration.configuration_id.clone(),
            configuration_fingerprint: request.provider_configuration_fingerprint.clone(),
            capabilities: fixture_capabilities(),
        })
        .unwrap();
        let mut arguments = vec![mode.to_owned(), handshake_response, response];
        arguments.extend_from_slice(trailing_arguments);
        let approved = OperatorApprovedProviderConfig::from_explicit_selection(
            "mock-provider".to_owned(),
            executable.to_path_buf(),
            arguments,
            configuration,
        )
        .unwrap();
        let worker = ProviderWorkerHandle::start(
            approved,
            ProviderCallTimeouts {
                handshake: Duration::from_secs(5),
                recognition: recognition_timeout,
                shutdown: Duration::from_secs(1),
            },
        )
        .unwrap();
        worker.try_submit(request).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match worker.try_receive() {
                ProviderWorkerPoll::Outcome(outcome) => return outcome.outcome,
                ProviderWorkerPoll::Stopped => {
                    panic!("provider worker exited before returning a result")
                }
                ProviderWorkerPoll::Pending => {}
            }
            assert!(
                Instant::now() < deadline,
                "provider worker result timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(windows)]
    fn run_senocr_worker_request(
        python_executable: &std::path::Path,
        worker_script: &std::path::Path,
        request: RecognitionRequestV1,
    ) -> Result<ProviderExecution, ProviderExecutionError> {
        assert!(python_executable.is_absolute());
        assert!(worker_script.is_absolute());
        let approved = OperatorApprovedProviderConfig::from_explicit_selection(
            "senocr-v1-fp32-local".to_owned(),
            python_executable.to_path_buf(),
            vec![
                "-u".to_owned(),
                worker_script.to_string_lossy().into_owned(),
            ],
            request.provider_configuration.clone(),
        )
        .unwrap_or_else(|_| panic!("construct the explicit local Python worker configuration"));
        let worker = ProviderWorkerHandle::start(
            approved,
            ProviderCallTimeouts {
                handshake: Duration::from_secs(5),
                recognition: Duration::from_secs(120),
                shutdown: Duration::from_secs(2),
            },
        )
        .unwrap_or_else(|_| panic!("start the isolated one-shot worker"));
        worker
            .try_submit(request)
            .unwrap_or_else(|_| panic!("submit the frozen synthetic Raster request"));
        let deadline = Instant::now() + Duration::from_secs(135);
        loop {
            match worker.try_receive() {
                ProviderWorkerPoll::Outcome(outcome) => return outcome.outcome,
                ProviderWorkerPoll::Stopped => {
                    panic!("SenOCR worker stopped before returning a protocol outcome")
                }
                ProviderWorkerPoll::Pending => {}
            }
            assert!(
                Instant::now() < deadline,
                "SenOCR worker exceeded its test observation deadline"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    #[cfg(windows)]
    fn process_is_signaled(pid: u32) -> bool {
        // SYNCHRONIZE is the only access right needed to wait on this same-user
        // CI fixture process; avoid query/termination rights in the assertion.
        const SYNCHRONIZE: u32 = 0x0010_0000;
        // SAFETY: OpenProcess returns an owned synchronization-only process
        // handle for the fixture's recorded PID, or an invalid integer sentinel.
        let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
        if handle == 0 || handle == -1 {
            // A process object may already be gone after the Job Object reached
            // ActiveProcesses == 0. ERROR_INVALID_PARAMETER means no such PID.
            return unsafe { GetLastError() } == ERROR_INVALID_PARAMETER;
        }
        // SAFETY: `handle` is the owned process handle returned above.
        let signaled = unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0;
        // SAFETY: the test owns exactly this OpenProcess handle.
        let close_succeeded = unsafe { CloseHandle(handle) } != 0;
        signaled && close_succeeded
    }

    #[cfg(not(windows))]
    fn process_is_signaled(_pid: u32) -> bool {
        false
    }

    fn run_mock_worker_cancelled_after_descendant_start(
        mock: &MockWorkerBinary,
        request: RecognitionRequestV1,
    ) -> Result<ProviderExecution, ProviderExecutionError> {
        require_provider_mock_test_opt_in();
        let marker = mock.directory.join("cancel-holder-ready.txt");
        let configuration = request.provider_configuration.clone();
        let handshake_response = serde_json::to_string(&WorkerResponseFrameV1::Handshake {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            provider: fixture_provider(),
            configuration_id: configuration.configuration_id.clone(),
            configuration_fingerprint: request.provider_configuration_fingerprint.clone(),
            capabilities: fixture_capabilities(),
        })
        .unwrap();
        let approved = OperatorApprovedProviderConfig::from_explicit_selection(
            "mock-provider".to_owned(),
            mock.executable.clone(),
            vec![
                "cancel-holder".to_owned(),
                handshake_response,
                String::new(),
                marker.to_string_lossy().into_owned(),
            ],
            configuration,
        )
        .unwrap();
        let worker = ProviderWorkerHandle::start(
            approved,
            ProviderCallTimeouts {
                handshake: Duration::from_secs(5),
                recognition: Duration::from_secs(30),
                shutdown: Duration::from_secs(1),
            },
        )
        .unwrap();
        worker.try_submit(request).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while !marker.exists() {
            assert!(
                Instant::now() < deadline,
                "pipe-holder descendant did not signal startup"
            );
            assert!(matches!(worker.try_receive(), ProviderWorkerPoll::Pending));
            thread::sleep(Duration::from_millis(10));
        }
        worker.cancel();
        loop {
            match worker.try_receive() {
                ProviderWorkerPoll::Outcome(outcome) => return outcome.outcome,
                ProviderWorkerPoll::Stopped => {
                    panic!("provider worker stopped without returning cancellation result")
                }
                ProviderWorkerPoll::Pending => {}
            }
            assert!(
                Instant::now() < deadline,
                "cancelled worker did not finish cleanup"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn run_mock_worker_timed_out_after_descendant_start(
        mock: &MockWorkerBinary,
        request: RecognitionRequestV1,
    ) -> Result<ProviderExecution, ProviderExecutionError> {
        require_provider_mock_test_opt_in();
        let marker = mock.directory.join("timeout-holder-ready.txt");
        let configuration = request.provider_configuration.clone();
        let handshake_response = serde_json::to_string(&WorkerResponseFrameV1::Handshake {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            provider: fixture_provider(),
            configuration_id: configuration.configuration_id.clone(),
            configuration_fingerprint: request.provider_configuration_fingerprint.clone(),
            capabilities: fixture_capabilities(),
        })
        .unwrap();
        let approved = OperatorApprovedProviderConfig::from_explicit_selection(
            "mock-provider".to_owned(),
            mock.executable.clone(),
            vec![
                "hang-holder".to_owned(),
                handshake_response,
                String::new(),
                marker.to_string_lossy().into_owned(),
            ],
            configuration,
        )
        .unwrap();
        let worker = ProviderWorkerHandle::start(
            approved,
            ProviderCallTimeouts {
                handshake: Duration::from_secs(5),
                recognition: Duration::from_secs(2),
                shutdown: Duration::from_secs(1),
            },
        )
        .unwrap();
        worker.try_submit(request).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while !marker.exists() {
            assert!(
                Instant::now() < deadline,
                "pipe-holder descendant did not signal startup before timeout"
            );
            assert!(matches!(worker.try_receive(), ProviderWorkerPoll::Pending));
            thread::sleep(Duration::from_millis(10));
        }
        loop {
            match worker.try_receive() {
                ProviderWorkerPoll::Outcome(outcome) => return outcome.outcome,
                ProviderWorkerPoll::Stopped => {
                    panic!("provider worker stopped without returning timeout result")
                }
                ProviderWorkerPoll::Pending => {}
            }
            assert!(
                Instant::now() < deadline,
                "timed-out worker did not finish cleanup"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "CI-only end-to-end benchmark/provider test; see guarded hosted provider test job"]
    fn benchmark_cli_cross_modal_mock_provider_pipeline_writes_private_complete_artifact() {
        require_provider_mock_test_opt_in();
        let mock = compile_mock_worker();
        let target = stroke_ref("cli-e2e-stroke", "cli-e2e-device");
        let journal_path = mock.directory.join("frozen-cli-e2e.journal");
        let mut journal_writer = JournalWriter::create(
            journal_path.clone(),
            JournalHeader {
                journal_id: target.journal_id.clone(),
                session_id: target.session_id.clone(),
                config_id: Some("provider-test-config".to_owned()),
                device_model_declared: Some("synthetic fixture device".to_owned()),
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        journal_writer
            .start_stroke(target.clone(), StrokeViewFrame::default(), 10)
            .unwrap();
        let mut first_sample = physical_sample(&target, 501, 110);
        first_sample.app_arrival_elapsed_ns = 11;
        let first_sample_sequence = journal_writer.append_sample(first_sample).unwrap();
        let mut second_sample = physical_sample(&target, 502, 114);
        second_sample.app_arrival_elapsed_ns = 12;
        let second_sample_sequence = journal_writer.append_sample(second_sample).unwrap();
        journal_writer.commit_stroke(target.clone(), 13).unwrap();
        journal_writer.flush().unwrap();
        drop(journal_writer);

        let journal = crate::journal::read_journal(&journal_path).unwrap();
        assert!(!journal.recovery.truncated_final_record);
        assert_eq!(journal.state.physical_samples.len(), 2);
        assert_eq!(first_sample_sequence, 2);
        assert_eq!(second_sample_sequence, 3);
        let source_revision = ProviderSourceRevisionV1::from_journal(&journal.state);
        let selected_strokes = vec![target.clone()];
        let selected_stroke_refs = vec![BenchmarkStrokeRefV1::from(&target)];
        let batch_id = format!(
            "provider-cli-e2e-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let case_id = "cli-e2e-case".to_owned();
        let corpus_id = "cli-e2e-corpus".to_owned();
        let annotation_id = "cli-e2e-annotation".to_owned();
        let raster_bytes = b"synthetic cross-modal raster fixture";
        let raster_path = mock.directory.join("synthetic-page.bin");
        fs::write(&raster_path, raster_bytes).unwrap();
        let bytes_hex = |bytes: &[u8]| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
            for byte in bytes {
                encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
                encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
            }
            encoded
        };
        let raster_request_input = ProviderRasterInputV1 {
            width: 2,
            height: 2,
            payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
            coordinate_space: "synthetic-page".to_owned(),
            units: "opaque-bytes".to_owned(),
            raw_payload_hex: bytes_hex(raster_bytes),
        };
        let raster_payload_hex = bytes_hex(raster_bytes);
        let raster_sha256_hex = bytes_hex(&Sha256::digest(raster_bytes));
        let case = BenchmarkCaseSpecV1 {
            case_id: case_id.clone(),
            journal_path: journal_path.clone(),
            expected_source_revision: source_revision.clone(),
            region_id: "region-e2e".to_owned(),
            line_id: "line-e2e".to_owned(),
            coordinate_space: "windows-screen-coordinates".to_owned(),
            coordinate_units: "screen-pixel".to_owned(),
            language_hints: vec!["vi-VN".to_owned(), "en-US".to_owned()],
            requested_input_modalities: vec![
                ProviderInputCapabilityV1::OnlineStrokes,
                ProviderInputCapabilityV1::Raster,
            ],
            selected_strokes: selected_stroke_refs,
            provenance: BenchmarkCaseProvenanceV1 {
                corpus_id: Some(corpus_id.clone()),
                annotation_id: Some(annotation_id.clone()),
                writer_key: "synthetic-writer-e2e".to_owned(),
                session_key: target.session_id.clone(),
                session_start_unix_ns: Some(1_700_000_000_000_000_000),
                configuration_key: "provider-test-config".to_owned(),
                split: Some(BenchmarkSplitV1::Evaluation),
                capture_api: Some("synthetic-fixture".to_owned()),
                capture_api_version: Some("fixture-api-v1".to_owned()),
                tablet_model: None,
                driver_version: None,
                windows_build: None,
                windows_ink_state: None,
                active_area: None,
                display_mapping: None,
                pressure_curve: None,
            },
            raster: Some(BenchmarkRasterInputSpecV1 {
                path: raster_path.clone(),
                width: 2,
                height: 2,
                coordinate_space: "synthetic-page".to_owned(),
                units: "opaque-bytes".to_owned(),
            }),
            generated_raster: None,
        };
        let case_manifest = BenchmarkCaseManifestV1 {
            schema_version: 1,
            batch_id: batch_id.clone(),
            cases: vec![case.clone()],
        };
        let corpus_manifest = BenchmarkCorpusManifestV1 {
            schema_version: 1,
            corpus_id: corpus_id.clone(),
            split_key: BenchmarkSplitKeyV1::Session,
            bootstrap_cluster: BenchmarkClusterKeyV1::Session,
            bootstrap_seed: 17,
            bootstrap_replicates: 10,
            tokenization_policy: BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            cases: vec![BenchmarkAnnotationCaseV1 {
                case_id: case_id.clone(),
                annotation_id: annotation_id.clone(),
                reference_text: "PRIVATE_REFERENCE_TEXT_SENTINEL".to_owned(),
                reference_language_scope:
                    crate::benchmark::BenchmarkReferenceLanguageScopeV1::MixedOrUnknown,
                reference_lexical_tokens: None,
                delayed_marks: Vec::new(),
            }],
        };

        let provider_configurations = [
            (
                "cfg-success-a",
                "online-success",
                "ok",
                vec![ProviderInputCapabilityV1::OnlineStrokes],
                vec![ProviderInputCapabilityV1::OnlineStrokes],
            ),
            (
                "cfg-success-b",
                "raster-success",
                "ok",
                vec![ProviderInputCapabilityV1::Raster],
                vec![ProviderInputCapabilityV1::Raster],
            ),
            (
                "cfg-visible-failure",
                "raster-failure",
                "crash",
                vec![ProviderInputCapabilityV1::Raster],
                vec![ProviderInputCapabilityV1::Raster],
            ),
        ];
        let mut expected_frames = BTreeMap::<String, (Vec<u8>, Vec<u8>)>::new();
        let mut providers = Vec::new();
        for (
            provider_index,
            (configuration_id, mode_label, behavior, requested_modalities, advertised_inputs),
        ) in provider_configurations.iter().enumerate()
        {
            let configuration = ProviderConfigurationV1 {
                configuration_id: (*configuration_id).to_owned(),
                values: BTreeMap::from([
                    (
                        "credential".to_owned(),
                        "PRIVATE_PROVIDER_SETTING_SENTINEL".to_owned(),
                    ),
                    ("mode".to_owned(), (*mode_label).to_owned()),
                ]),
            };
            let request = build_recognition_request(RecognitionRequestBuildInput {
                state: &journal.state,
                request_id: format!("bench-{batch_id}-0-{provider_index}"),
                region_id: case.region_id.clone(),
                line_id: case.line_id.clone(),
                coordinate_space: case.coordinate_space.clone(),
                coordinate_units: case.coordinate_units.clone(),
                language_hints: case.language_hints.clone(),
                requested_input_modalities: requested_modalities.to_vec(),
                provider_configuration: configuration.clone(),
                selected_strokes: &selected_strokes,
                raster: requested_modalities
                    .contains(&ProviderInputCapabilityV1::Raster)
                    .then(|| raster_request_input.clone()),
            })
            .unwrap();
            assert_eq!(request.source_revision, source_revision);
            let handshake = serde_json::to_string(&WorkerResponseFrameV1::Handshake {
                protocol_version: PROVIDER_PROTOCOL_VERSION,
                provider: fixture_provider(),
                configuration_id: configuration.configuration_id.clone(),
                configuration_fingerprint: request.provider_configuration_fingerprint.clone(),
                capabilities: fixture_capabilities_with_inputs(advertised_inputs.to_vec()),
            })
            .unwrap();
            let mut mock_result = fixture_result(&request, source_revision.clone());
            if !request
                .requested_input_modalities
                .contains(&ProviderInputCapabilityV1::OnlineStrokes)
            {
                for candidate in &mut mock_result.candidates {
                    candidate.stroke_ranges.clear();
                }
            }
            let recognition = serde_json::to_string(&WorkerResponseFrameV1::Recognition {
                protocol_version: PROVIDER_PROTOCOL_VERSION,
                result: mock_result,
            })
            .unwrap();
            expected_frames.insert(
                configuration.configuration_id.clone(),
                (
                    handshake.as_bytes().to_vec(),
                    recognition.as_bytes().to_vec(),
                ),
            );
            providers.push(ApprovedBenchmarkProviderV1 {
                provider_id: "mock-provider".to_owned(),
                executable_path: mock.executable.clone(),
                arguments: vec![(*behavior).to_owned(), handshake, recognition],
                requested_input_modalities: Some(requested_modalities.to_vec()),
                protocol_configuration: configuration,
                artifacts: vec![ProviderArtifactPathV1 {
                    artifact_id: "mock-executable".to_owned(),
                    role: ProviderArtifactRoleV1::Executable,
                    path: mock.executable.clone(),
                }],
                timeouts: Some(BenchmarkTimeoutsV1 {
                    handshake_ms: 10_000,
                    recognition_ms: 10_000,
                    shutdown_ms: 1_000,
                }),
            });
        }
        let provider_manifest = BenchmarkProviderManifestV1 {
            schema_version: 1,
            providers,
        };

        let case_manifest_path = mock.directory.join("cases.json");
        let provider_manifest_path = mock.directory.join("providers.json");
        let corpus_manifest_path = mock.directory.join("corpus.json");
        fs::write(
            &case_manifest_path,
            serde_json::to_vec(&case_manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            &provider_manifest_path,
            serde_json::to_vec(&provider_manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            &corpus_manifest_path,
            serde_json::to_vec(&corpus_manifest).unwrap(),
        )
        .unwrap();
        let output_directory = mock.directory.join("benchmark-output");
        assert!(!output_directory.exists());
        let completion = benchmark::run_batch_cli_to_directory(
            &case_manifest_path,
            &provider_manifest_path,
            Some(&corpus_manifest_path),
            &output_directory,
        )
        .unwrap();
        assert_eq!(completion.run_count, 3);
        assert_eq!(completion.failure_count, 1);
        assert!(completion.artifact_path.starts_with(&output_directory));
        let artifact_bytes = fs::read(&completion.artifact_path).unwrap();
        let artifact_text = String::from_utf8(artifact_bytes).unwrap();
        assert!(!artifact_text.contains("PRIVATE_PROVIDER_SETTING_SENTINEL"));
        assert!(!artifact_text.contains("PRIVATE_REFERENCE_TEXT_SENTINEL"));
        assert!(!artifact_text.contains(&raster_payload_hex));

        let rows = artifact_text
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let path_sentinel = mock.executable.to_string_lossy().into_owned();
        let injected_path_json = serde_json::to_string(&serde_json::json!({
            "nested": {"path": path_sentinel.clone()}
        }))
        .unwrap();
        let injected_path_row: serde_json::Value =
            serde_json::from_str(&injected_path_json).unwrap();
        assert!(json_value_contains_string(
            &injected_path_row,
            &path_sentinel
        ));
        for private_path in [
            &mock.executable,
            &journal_path,
            &case_manifest_path,
            &provider_manifest_path,
            &corpus_manifest_path,
            &raster_path,
        ] {
            let path_text = private_path.to_string_lossy();
            assert!(
                !rows
                    .iter()
                    .any(|row| json_value_contains_string(row, path_text.as_ref()))
            );
        }
        assert_eq!(rows.len(), 5);
        let header = &rows
            .iter()
            .find(|row| row["record_type"] == "header")
            .unwrap()["record"];
        assert_eq!(header["batch_id"], batch_id);
        assert!(
            header["case_manifest_sha256"]
                .as_str()
                .is_some_and(|value| {
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        );
        assert!(
            header["corpus_manifest_sha256"]
                .as_str()
                .is_some_and(|value| {
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        );
        let run_rows = rows
            .iter()
            .filter(|row| row["record_type"] == "run")
            .map(|row| &row["record"])
            .collect::<Vec<_>>();
        assert_eq!(run_rows.len(), 3);
        let find_run = |configuration_id: &str| {
            run_rows
                .iter()
                .find(|row| row["provider_configuration_id"] == configuration_id)
                .copied()
                .unwrap()
        };
        let success_a = find_run("cfg-success-a");
        let success_b = find_run("cfg-success-b");
        assert_eq!(success_a["status"], "completed");
        assert_eq!(success_b["status"], "completed");
        assert_eq!(success_a["case_id"], case_id);
        assert_eq!(success_a["provider_id"], "mock-provider");
        assert_eq!(
            success_a["requested_input_modalities"],
            serde_json::json!(["online_strokes"])
        );
        assert_eq!(
            success_b["requested_input_modalities"],
            serde_json::json!(["raster"])
        );
        assert_eq!(
            success_a["result"]["consumed_input_modalities"],
            serde_json::json!(["online_strokes"])
        );
        assert_eq!(
            success_b["result"]["consumed_input_modalities"],
            serde_json::json!(["raster"])
        );
        assert_eq!(
            success_a["provider_capabilities"]["inputs"],
            serde_json::json!(["online_strokes"])
        );
        assert_eq!(
            success_b["provider_capabilities"]["inputs"],
            serde_json::json!(["raster"])
        );
        assert_eq!(success_a["source_revision"], success_b["source_revision"]);
        assert_eq!(
            success_a["source_revision"],
            serde_json::to_value(&source_revision).unwrap()
        );
        assert_eq!(
            success_a["source_revision"]["journal_id"],
            target.journal_id
        );
        let input_view_id = success_a["input_view_id"].as_str().unwrap();
        let input_view_hash = input_view_id.strip_prefix("input-view-v1-").unwrap();
        assert_eq!(input_view_hash.len(), 16);
        assert!(
            input_view_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let raster_input_view_id = success_b["input_view_id"].as_str().unwrap();
        let raster_input_view_hash = raster_input_view_id.strip_prefix("input-view-v1-").unwrap();
        assert_eq!(raster_input_view_hash.len(), 16);
        assert!(
            raster_input_view_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_ne!(success_a["input_view_id"], success_b["input_view_id"]);
        let canonical_binding = &success_a["canonical_ink_comparison_binding"];
        assert_eq!(
            canonical_binding,
            &success_b["canonical_ink_comparison_binding"]
        );
        assert_eq!(canonical_binding["schema_version"].as_u64(), Some(1));
        assert_eq!(canonical_binding["raster_pixel_parity"], "unverified");
        assert!(
            canonical_binding["sha256_hex"]
                .as_str()
                .is_some_and(|value| value.len() == 64)
        );
        assert!(success_a["raster_input_byte_count"].is_null());
        assert!(success_a["raster_input_sha256"].is_null());
        assert_eq!(
            success_b["raster_input_byte_count"].as_u64(),
            Some(raster_bytes.len() as u64)
        );
        assert_eq!(
            success_b["raster_input_sha256"].as_str(),
            Some(raster_sha256_hex.as_str())
        );
        assert_eq!(
            success_a["source_sample_sequences"],
            serde_json::json!([first_sample_sequence, second_sample_sequence])
        );
        assert_eq!(
            success_a["source_sample_sequences"],
            success_b["source_sample_sequences"]
        );
        assert_eq!(success_a["selected_strokes"], success_b["selected_strokes"]);
        assert_eq!(
            success_a["selected_strokes"],
            serde_json::to_value(vec![BenchmarkStrokeRefV1::from(&target)]).unwrap()
        );
        assert_eq!(
            success_b["result"]["candidates"][0]["stroke_ranges"],
            serde_json::json!([])
        );

        for configuration_id in ["cfg-success-a", "cfg-success-b"] {
            let run = find_run(configuration_id);
            assert!(run["raw_response_capture_complete"].as_bool().unwrap());
            assert!(run["result"].is_object());
            let frames = run["raw_response_frames"].as_array().unwrap();
            let expected = expected_frames.get(configuration_id).unwrap();
            assert_eq!(frames.len(), 2);
            for (ordinal, bytes) in [&expected.0, &expected.1].into_iter().enumerate() {
                let prefix = u32::try_from(bytes.len()).unwrap().to_be_bytes();
                assert_eq!(frames[ordinal]["ordinal"].as_u64(), Some(ordinal as u64));
                assert_eq!(frames[ordinal]["payload_hex"], bytes_hex(bytes));
                assert_eq!(frames[ordinal]["length_prefix_be_hex"], bytes_hex(&prefix));
            }
            let executable_digest = run["artifact_digests"][0]["sha256_hex"].as_str().unwrap();
            assert_eq!(executable_digest.len(), 64);
            assert!(artifact_text.contains(executable_digest));
        }

        let failed = find_run("cfg-visible-failure");
        assert_eq!(failed["status"], "failed");
        assert!(failed["result"].is_null());
        assert!(failed["provider_identity"].is_null());
        assert_eq!(
            failed["requested_input_modalities"],
            serde_json::json!(["raster"])
        );
        assert_eq!(failed["source_revision"], success_a["source_revision"]);
        assert_eq!(failed["input_view_id"], success_b["input_view_id"]);
        assert_eq!(
            failed["canonical_ink_comparison_binding"],
            success_b["canonical_ink_comparison_binding"]
        );
        assert_eq!(
            failed["raster_input_byte_count"].as_u64(),
            Some(raster_bytes.len() as u64)
        );
        assert_eq!(
            failed["raster_input_sha256"].as_str(),
            Some(raster_sha256_hex.as_str())
        );
        assert_eq!(
            failed["source_sample_sequences"],
            success_a["source_sample_sequences"]
        );
        assert!(!failed["raw_response_capture_complete"].as_bool().unwrap());
        let failed_frames = failed["raw_response_frames"].as_array().unwrap();
        let expected_failure_handshake = &expected_frames.get("cfg-visible-failure").unwrap().0;
        assert_eq!(failed_frames.len(), 1);
        assert_eq!(failed_frames[0]["ordinal"].as_u64(), Some(0));
        assert_eq!(
            failed_frames[0]["payload_hex"],
            bytes_hex(expected_failure_handshake)
        );

        let footer = &rows
            .iter()
            .find(|row| row["record_type"] == "footer")
            .unwrap()["record"];
        assert_eq!(footer["planned_case_count"].as_u64(), Some(1));
        assert_eq!(footer["planned_provider_count"].as_u64(), Some(3));
        assert_eq!(footer["recorded_run_count"].as_u64(), Some(3));
        assert_eq!(footer["failed_run_count"].as_u64(), Some(1));
        assert_eq!(footer["complete"].as_bool(), Some(true));
        let summaries = footer["provider_summaries"].as_array().unwrap();
        assert_eq!(summaries.len(), 3);
        for (configuration_id, completed, failed_count) in [
            ("cfg-success-a", 1u64, 0u64),
            ("cfg-success-b", 1u64, 0u64),
            ("cfg-visible-failure", 0u64, 1u64),
        ] {
            let summary = summaries
                .iter()
                .find(|summary| summary["configuration_id"] == configuration_id)
                .unwrap();
            assert_eq!(summary["attempted_run_count"].as_u64(), Some(1));
            assert_eq!(summary["completed_run_count"].as_u64(), Some(completed));
            assert_eq!(summary["failed_run_count"].as_u64(), Some(failed_count));
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "CI-only generated-raster E2E; guarded hosted provider job"]
    fn benchmark_cli_generated_raster_mock_pipeline_records_exact_origin_and_no_fallback() {
        require_provider_mock_test_opt_in();
        let mock = compile_mock_worker();
        let bytes_hex = |bytes: &[u8]| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
            for byte in bytes {
                encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
                encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
            }
            encoded
        };
        let target = stroke_ref("generated-cli-e2e-stroke", "generated-cli-e2e-device");
        let journal_path = mock.directory.join("frozen-generated-cli-e2e.journal");
        let mut journal_writer = JournalWriter::create(
            journal_path.clone(),
            JournalHeader {
                journal_id: target.journal_id.clone(),
                session_id: target.session_id.clone(),
                config_id: Some("generated-raster-fixture-config".to_owned()),
                device_model_declared: Some("synthetic fixture device".to_owned()),
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        journal_writer
            .start_stroke(target.clone(), StrokeViewFrame::default(), 10)
            .unwrap();
        let mut first_sample = physical_sample(&target, 501, 110);
        first_sample.app_arrival_elapsed_ns = 11;
        first_sample.raw_payload = b"GENERATED_E2E_RAW_SAMPLE_A_PRIVATE_SENTINEL".to_vec();
        let first_sample_sequence = journal_writer.append_sample(first_sample.clone()).unwrap();
        let mut second_sample = physical_sample(&target, 502, 250);
        second_sample.app_arrival_elapsed_ns = 12;
        second_sample.raw_payload = b"GENERATED_E2E_RAW_SAMPLE_B_PRIVATE_SENTINEL".to_vec();
        let second_sample_sequence = journal_writer.append_sample(second_sample.clone()).unwrap();
        journal_writer.commit_stroke(target.clone(), 13).unwrap();
        journal_writer.flush().unwrap();
        drop(journal_writer);

        let journal = crate::journal::read_journal(&journal_path).unwrap();
        assert!(!journal.recovery.truncated_final_record);
        assert_eq!(journal.state.physical_samples.len(), 2);
        assert_eq!(first_sample_sequence, 2);
        assert_eq!(second_sample_sequence, 3);
        let source_revision = ProviderSourceRevisionV1::from_journal(&journal.state);
        let selected_strokes = vec![target.clone()];
        let selected_stroke_refs = vec![BenchmarkStrokeRefV1::from(&target)];
        let generated_raster_spec = BenchmarkGeneratedRasterSpecV1 {
            projection_schema_version: 1,
            output_width_px: 128,
            output_height_px: 128,
            source_crop: BenchmarkGeneratedRasterCropV1 {
                left_px: 0,
                top_px: 0,
                right_px_exclusive: 512,
                bottom_px_exclusive: 512,
            },
        };
        let projection_spec = crate::canvas::CanonicalRasterProjectionSpecV1::new(
            generated_raster_spec.output_width_px,
            generated_raster_spec.output_height_px,
            crate::canvas::CanonicalRasterProjectionCropV1 {
                left_px: generated_raster_spec.source_crop.left_px,
                top_px: generated_raster_spec.source_crop.top_px,
                right_px_exclusive: generated_raster_spec.source_crop.right_px_exclusive,
                bottom_px_exclusive: generated_raster_spec.source_crop.bottom_px_exclusive,
            },
        );
        let raster_plan = crate::canvas::build_canonical_raster_projection_plan(
            &journal.state,
            &selected_strokes,
        )
        .unwrap();
        let raster_geometry =
            crate::canvas::transform_canonical_raster_geometry(&raster_plan, &projection_spec)
                .unwrap();
        let raster_image = crate::canvas::render_canonical_raster(&raster_geometry).unwrap();
        let png_bytes = raster_image.png_bytes();
        assert!(!png_bytes.is_empty());
        assert!(png_bytes.len() <= 1024 * 1024);
        let decoded_png = tiny_skia::Pixmap::decode_png(png_bytes).unwrap();
        assert_eq!(decoded_png.width(), 128);
        assert_eq!(decoded_png.height(), 128);
        let (decoded_pixels, decoded_remainder) = decoded_png.data().as_chunks::<4>();
        assert!(decoded_remainder.is_empty());
        assert!(decoded_pixels.contains(&[32, 32, 32, 255]));
        assert!(decoded_pixels.contains(&[255, 255, 255, 255]));
        assert_eq!(
            bytes_hex(&Sha256::digest(decoded_png.data())),
            bytes_hex(&raster_image.pixel_bytes_sha256())
        );

        let raster_payload_hex = bytes_hex(png_bytes);
        let raster_pixel_hex = bytes_hex(decoded_png.data());
        let raster_sha256_hex = bytes_hex(&Sha256::digest(png_bytes));
        let raster_source_sha256 = bytes_hex(&raster_image.source_content_sha256());
        let raster_projection_spec_sha256 = bytes_hex(&raster_image.projection_spec_sha256());
        let raster_geometry_sha256 = bytes_hex(&raster_image.geometry_sha256());
        let raster_pixel_sha256 = bytes_hex(&raster_image.pixel_bytes_sha256());
        let raster_artifact_sha256 = bytes_hex(&raster_image.raster_artifact_sha256());
        let (raster_width_px, raster_height_px, raster_row_stride_bytes) =
            raster_image.output_dimensions_and_stride();
        let raster_request_input = ProviderRasterInputV1 {
            width: raster_width_px,
            height: raster_height_px,
            payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
            coordinate_space: "canonical-raster-output-v1".to_owned(),
            units: "pixel".to_owned(),
            raw_payload_hex: raster_payload_hex.clone(),
        };

        let batch_id = format!(
            "provider-generated-raster-e2e-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let case_id = "generated-raster-e2e-case".to_owned();
        let case = BenchmarkCaseSpecV1 {
            case_id: case_id.clone(),
            journal_path: journal_path.clone(),
            expected_source_revision: source_revision.clone(),
            region_id: "generated-region-e2e".to_owned(),
            line_id: "generated-line-e2e".to_owned(),
            coordinate_space: "document".to_owned(),
            coordinate_units: "px".to_owned(),
            language_hints: vec!["vi-VN".to_owned()],
            requested_input_modalities: vec![ProviderInputCapabilityV1::OnlineStrokes],
            selected_strokes: selected_stroke_refs.clone(),
            provenance: BenchmarkCaseProvenanceV1 {
                corpus_id: None,
                annotation_id: None,
                writer_key: "synthetic-generated-raster-writer".to_owned(),
                session_key: target.session_id.clone(),
                session_start_unix_ns: None,
                configuration_key: "synthetic-generated-raster-config".to_owned(),
                split: None,
                capture_api: Some(target.source_api.clone()),
                capture_api_version: Some("synthetic-direct-fixture-v1".to_owned()),
                tablet_model: None,
                driver_version: None,
                windows_build: None,
                windows_ink_state: None,
                active_area: None,
                display_mapping: None,
                pressure_curve: None,
            },
            raster: None,
            generated_raster: Some(generated_raster_spec),
        };

        let provider_modes = [
            (
                "cfg-generated-online",
                "generated-online-success",
                "ok",
                vec![ProviderInputCapabilityV1::OnlineStrokes],
            ),
            (
                "cfg-generated-raster",
                "generated-raster-success",
                "ok",
                vec![ProviderInputCapabilityV1::Raster],
            ),
            (
                "cfg-generated-raster-failure",
                "generated-raster-runtime-failure",
                "crash",
                vec![ProviderInputCapabilityV1::Raster],
            ),
        ];
        let mut expected_frames = BTreeMap::<String, (Vec<u8>, Vec<u8>)>::new();
        let mut expected_input_view_ids = BTreeMap::<String, String>::new();
        let mut providers = Vec::new();
        for (provider_index, (configuration_id, mode_label, behavior, requested_modalities)) in
            provider_modes.iter().enumerate()
        {
            let configuration = ProviderConfigurationV1 {
                configuration_id: (*configuration_id).to_owned(),
                values: BTreeMap::from([
                    (
                        "credential".to_owned(),
                        "GENERATED_E2E_PROVIDER_SETTING_PRIVATE_SENTINEL".to_owned(),
                    ),
                    ("mode".to_owned(), (*mode_label).to_owned()),
                ]),
            };
            let expected_request = build_recognition_request(RecognitionRequestBuildInput {
                state: &journal.state,
                request_id: format!("bench-{batch_id}-0-{provider_index}"),
                region_id: case.region_id.clone(),
                line_id: case.line_id.clone(),
                coordinate_space: case.coordinate_space.clone(),
                coordinate_units: case.coordinate_units.clone(),
                language_hints: case.language_hints.clone(),
                requested_input_modalities: requested_modalities.to_vec(),
                provider_configuration: configuration.clone(),
                selected_strokes: &selected_strokes,
                raster: requested_modalities
                    .contains(&ProviderInputCapabilityV1::Raster)
                    .then(|| raster_request_input.clone()),
            })
            .unwrap();
            assert_eq!(expected_request.source_revision, source_revision);
            expected_input_view_ids.insert(
                configuration.configuration_id.clone(),
                expected_request.input_view_id.clone(),
            );
            let handshake = serde_json::to_string(&WorkerResponseFrameV1::Handshake {
                protocol_version: PROVIDER_PROTOCOL_VERSION,
                provider: fixture_provider(),
                configuration_id: configuration.configuration_id.clone(),
                configuration_fingerprint: expected_request
                    .provider_configuration_fingerprint
                    .clone(),
                capabilities: fixture_capabilities_with_inputs(requested_modalities.to_vec()),
            })
            .unwrap();
            let mut mock_result = fixture_result(&expected_request, source_revision.clone());
            if !requested_modalities.contains(&ProviderInputCapabilityV1::OnlineStrokes) {
                for candidate in &mut mock_result.candidates {
                    candidate.stroke_ranges.clear();
                }
            }
            let recognition = serde_json::to_string(&WorkerResponseFrameV1::Recognition {
                protocol_version: PROVIDER_PROTOCOL_VERSION,
                result: mock_result,
            })
            .unwrap();
            expected_frames.insert(
                configuration.configuration_id.clone(),
                (
                    handshake.as_bytes().to_vec(),
                    recognition.as_bytes().to_vec(),
                ),
            );
            providers.push(ApprovedBenchmarkProviderV1 {
                provider_id: "mock-provider".to_owned(),
                executable_path: mock.executable.clone(),
                arguments: vec![(*behavior).to_owned(), handshake, recognition],
                requested_input_modalities: Some(requested_modalities.to_vec()),
                protocol_configuration: configuration,
                artifacts: vec![ProviderArtifactPathV1 {
                    artifact_id: "mock-executable".to_owned(),
                    role: ProviderArtifactRoleV1::Executable,
                    path: mock.executable.clone(),
                }],
                timeouts: Some(BenchmarkTimeoutsV1 {
                    handshake_ms: 10_000,
                    recognition_ms: 10_000,
                    shutdown_ms: 1_000,
                }),
            });
        }

        let case_manifest = BenchmarkCaseManifestV1 {
            schema_version: 1,
            batch_id: batch_id.clone(),
            cases: vec![case],
        };
        let provider_manifest = BenchmarkProviderManifestV1 {
            schema_version: 1,
            providers,
        };
        let case_manifest_path = mock.directory.join("generated-cases.json");
        let provider_manifest_path = mock.directory.join("generated-providers.json");
        fs::write(
            &case_manifest_path,
            serde_json::to_vec(&case_manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            &provider_manifest_path,
            serde_json::to_vec(&provider_manifest).unwrap(),
        )
        .unwrap();
        let output_directory = mock.directory.join("generated-benchmark-output");
        assert!(!output_directory.exists());
        let completion = benchmark::run_batch_cli_to_directory(
            &case_manifest_path,
            &provider_manifest_path,
            None,
            &output_directory,
        )
        .unwrap();
        assert_eq!(completion.run_count, 3);
        assert_eq!(completion.failure_count, 1);

        let artifact_bytes = fs::read(&completion.artifact_path).unwrap();
        let artifact_text = String::from_utf8(artifact_bytes).unwrap();
        assert!(!artifact_text.contains("GENERATED_E2E_PROVIDER_SETTING_PRIVATE_SENTINEL"));
        assert!(!artifact_text.contains(&raster_payload_hex));
        assert!(!artifact_text.contains(&raster_pixel_hex));
        assert!(!artifact_text.contains(&bytes_hex(&first_sample.raw_payload)));
        assert!(!artifact_text.contains(&bytes_hex(&second_sample.raw_payload)));

        let rows = artifact_text
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let private_paths = [
            &mock.executable,
            &journal_path,
            &case_manifest_path,
            &provider_manifest_path,
            &output_directory,
        ];
        for private_path in private_paths {
            let path_sentinel = private_path.to_string_lossy();
            assert!(
                !rows
                    .iter()
                    .any(|row| { json_value_contains_string(row, path_sentinel.as_ref()) })
            );
        }
        assert_eq!(rows.len(), 5);
        let run_rows = rows
            .iter()
            .filter(|row| row["record_type"] == "run")
            .map(|row| &row["record"])
            .collect::<Vec<_>>();
        assert_eq!(run_rows.len(), 3);
        let find_run = |configuration_id: &str| {
            run_rows
                .iter()
                .find(|row| row["provider_configuration_id"] == configuration_id)
                .copied()
                .unwrap()
        };

        let online = find_run("cfg-generated-online");
        let raster = find_run("cfg-generated-raster");
        let failed_raster = find_run("cfg-generated-raster-failure");
        assert_eq!(online["status"], "completed");
        assert_eq!(raster["status"], "completed");
        assert_eq!(failed_raster["status"], "failed");
        assert!(failed_raster["result"].is_null());
        assert_eq!(
            online["requested_input_modalities"],
            serde_json::json!(["online_strokes"])
        );
        assert_eq!(
            raster["requested_input_modalities"],
            serde_json::json!(["raster"])
        );
        for (configuration_id, run) in [
            ("cfg-generated-online", online),
            ("cfg-generated-raster", raster),
            ("cfg-generated-raster-failure", failed_raster),
        ] {
            assert_eq!(
                run["input_view_id"],
                expected_input_view_ids[configuration_id]
            );
        }
        assert_eq!(
            online["result"]["consumed_input_modalities"],
            serde_json::json!(["online_strokes"])
        );
        assert_eq!(
            raster["result"]["consumed_input_modalities"],
            serde_json::json!(["raster"])
        );
        assert_eq!(online["raster_input_byte_count"], serde_json::Value::Null);
        assert_eq!(online["raster_input_sha256"], serde_json::Value::Null);
        assert_eq!(online["generated_raster_origin"], serde_json::Value::Null);
        assert_ne!(online["input_view_id"], raster["input_view_id"]);
        assert_eq!(
            online["canonical_ink_comparison_binding"],
            raster["canonical_ink_comparison_binding"]
        );
        assert_eq!(
            failed_raster["canonical_ink_comparison_binding"],
            raster["canonical_ink_comparison_binding"]
        );
        assert_eq!(
            raster["canonical_ink_comparison_binding"]["raster_pixel_parity"],
            "unverified"
        );
        assert_eq!(online["source_revision"], raster["source_revision"]);
        assert_eq!(
            online["source_sample_sequences"],
            raster["source_sample_sequences"]
        );
        assert_eq!(
            online["source_sample_sequences"],
            serde_json::json!([first_sample_sequence, second_sample_sequence])
        );
        assert_eq!(online["selected_strokes"], raster["selected_strokes"]);
        assert_eq!(
            raster["raster_input_byte_count"].as_u64(),
            Some(png_bytes.len() as u64)
        );
        assert_eq!(
            raster["raster_input_sha256"].as_str(),
            Some(raster_sha256_hex.as_str())
        );

        let origin = &raster["generated_raster_origin"];
        assert_eq!(origin["schema_version"].as_u64(), Some(1));
        assert_eq!(
            origin["canonical_ink_comparison_binding_sha256"],
            raster["canonical_ink_comparison_binding"]["sha256_hex"]
        );
        let producer = &origin["producer"];
        assert_eq!(producer["source_revision"], raster["source_revision"]);
        assert_eq!(
            producer["source_content_sha256"].as_str(),
            Some(raster_source_sha256.as_str())
        );
        assert_eq!(
            producer["projection_spec_sha256"].as_str(),
            Some(raster_projection_spec_sha256.as_str())
        );
        assert_eq!(
            producer["geometry_sha256"].as_str(),
            Some(raster_geometry_sha256.as_str())
        );
        assert_eq!(
            producer["renderer_version"],
            raster_image.renderer_version()
        );
        assert_eq!(
            producer["pixel_bytes_sha256"].as_str(),
            Some(raster_pixel_sha256.as_str())
        );
        assert_eq!(
            producer["png_bytes_sha256"].as_str(),
            Some(raster_sha256_hex.as_str())
        );
        assert_eq!(
            producer["raster_artifact_sha256"].as_str(),
            Some(raster_artifact_sha256.as_str())
        );
        assert_eq!(producer["output_width_px"].as_u64(), Some(128));
        assert_eq!(producer["output_height_px"].as_u64(), Some(128));
        assert_eq!(raster_row_stride_bytes, 512);
        assert_eq!(
            producer["row_stride_bytes"].as_u64(),
            Some(u64::from(raster_row_stride_bytes))
        );
        assert_eq!(producer["projection_schema_version"].as_u64(), Some(1));
        assert_eq!(
            producer["pixel_layout"],
            "rgba8_premultiplied_srgb_top_down"
        );
        assert_eq!(producer["selected_strokes"], raster["selected_strokes"]);
        assert_eq!(producer["stroke_draw_order"], raster["selected_strokes"]);
        assert_eq!(
            producer["physical_sample_provenance"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            producer["physical_sample_provenance"][0]["journal_sequence"],
            first_sample_sequence
        );
        assert_eq!(
            producer["physical_sample_provenance"][1]["journal_sequence"],
            second_sample_sequence
        );
        assert_eq!(
            producer["physical_sample_provenance"][0]["source_sequence_raw"],
            501
        );
        assert_eq!(
            producer["physical_sample_provenance"][1]["source_sequence_raw"],
            502
        );
        assert_eq!(
            failed_raster["generated_raster_origin"],
            raster["generated_raster_origin"]
        );
        assert_eq!(
            failed_raster["requested_input_modalities"],
            serde_json::json!(["raster"])
        );

        for configuration_id in ["cfg-generated-online", "cfg-generated-raster"] {
            let run = find_run(configuration_id);
            assert!(run["raw_response_capture_complete"].as_bool().unwrap());
            let frames = run["raw_response_frames"].as_array().unwrap();
            let expected = expected_frames.get(configuration_id).unwrap();
            assert_eq!(frames.len(), 2);
            for (ordinal, bytes) in [&expected.0, &expected.1].into_iter().enumerate() {
                let prefix = u32::try_from(bytes.len()).unwrap().to_be_bytes();
                assert_eq!(frames[ordinal]["ordinal"].as_u64(), Some(ordinal as u64));
                assert_eq!(frames[ordinal]["payload_hex"], bytes_hex(bytes));
                assert_eq!(frames[ordinal]["length_prefix_be_hex"], bytes_hex(&prefix));
            }
        }
        assert!(
            !failed_raster["raw_response_capture_complete"]
                .as_bool()
                .unwrap()
        );
        let failed_frames = failed_raster["raw_response_frames"].as_array().unwrap();
        assert_eq!(failed_frames.len(), 1);
        assert_eq!(failed_frames[0]["ordinal"].as_u64(), Some(0));
        assert_eq!(
            failed_frames[0]["payload_hex"],
            bytes_hex(
                &expected_frames
                    .get("cfg-generated-raster-failure")
                    .unwrap()
                    .0
            )
        );
        assert_eq!(failed_raster["source_revision"], raster["source_revision"]);
        assert_eq!(failed_raster["input_view_id"], raster["input_view_id"]);
        assert_eq!(
            failed_raster["raster_input_sha256"],
            raster["raster_input_sha256"]
        );

        let footer = &rows
            .iter()
            .find(|row| row["record_type"] == "footer")
            .unwrap()["record"];
        assert_eq!(footer["planned_case_count"].as_u64(), Some(1));
        assert_eq!(footer["planned_provider_count"].as_u64(), Some(3));
        assert_eq!(footer["recorded_run_count"].as_u64(), Some(3));
        assert_eq!(footer["failed_run_count"].as_u64(), Some(1));
        assert_eq!(footer["complete"].as_bool(), Some(true));
        let summaries = footer["provider_summaries"].as_array().unwrap();
        assert_eq!(summaries.len(), 3);
        let failed_summary = summaries
            .iter()
            .find(|summary| summary["configuration_id"] == "cfg-generated-raster-failure")
            .unwrap();
        assert_eq!(failed_summary["attempted_run_count"].as_u64(), Some(1));
        assert_eq!(failed_summary["completed_run_count"].as_u64(), Some(0));
        assert_eq!(failed_summary["failed_run_count"].as_u64(), Some(1));
    }

    #[test]
    #[ignore = "CI-only subprocess integration test; see guarded hosted provider test job"]
    fn provider_mock_process_tree_cleanup_and_protocol_failures_are_isolated() {
        require_provider_mock_test_opt_in();
        let mock = compile_mock_worker();
        let (_state, request) = fixture_request();

        let crash = run_mock_worker(
            &mock.executable,
            "crash-holder",
            String::new(),
            request.clone(),
            Duration::from_secs(2),
        );
        assert!(
            crash.is_err(),
            "worker process crash returns an error to core"
        );

        let timeout = run_mock_worker_timed_out_after_descendant_start(&mock, request.clone());
        assert!(matches!(
            timeout,
            Err(ProviderExecutionError {
                kind: ProviderErrorKind::TimedOut(ProviderPhase::Recognition),
                ..
            })
        ));

        let cancelled = run_mock_worker_cancelled_after_descendant_start(&mock, request.clone());
        assert!(matches!(
            cancelled,
            Err(ProviderExecutionError {
                kind: ProviderErrorKind::Cancelled,
                ..
            })
        ));

        let stale_result = fixture_result(
            &request,
            ProviderSourceRevisionV1 {
                logical_revision: request.source_revision.logical_revision + 1,
                ..request.source_revision.clone()
            },
        );
        let stale_response = serde_json::to_string(&WorkerResponseFrameV1::Recognition {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            result: stale_result,
        })
        .unwrap();
        let stale = run_mock_worker(
            &mock.executable,
            "stale",
            stale_response,
            request.clone(),
            Duration::from_secs(2),
        );
        assert!(matches!(
            stale,
            Err(ProviderExecutionError {
                kind: ProviderErrorKind::StaleSourceRevision,
                ..
            })
        ));

        let valid_result = fixture_result(&request, request.source_revision.clone());
        let valid_response = serde_json::to_string(&WorkerResponseFrameV1::Recognition {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            result: valid_result.clone(),
        })
        .unwrap();
        let extra_response = run_mock_worker(
            &mock.executable,
            "extra-holder",
            serde_json::to_string(&WorkerResponseFrameV1::Recognition {
                protocol_version: PROVIDER_PROTOCOL_VERSION,
                result: valid_result.clone(),
            })
            .unwrap(),
            request.clone(),
            Duration::from_secs(2),
        );
        assert!(matches!(
            extra_response,
            Err(ProviderExecutionError {
                kind: ProviderErrorKind::InvalidResponse(message),
                ..
            }) if message.contains("third protocol frame")
        ));

        let valid = run_mock_worker(
            &mock.executable,
            "ok-holder",
            valid_response.clone(),
            request.clone(),
            Duration::from_secs(2),
        )
        .expect("a successful one-shot result closes descendants holding its stdout pipe");
        assert_eq!(valid.provider.provider_id, "mock-provider");
        assert!(
            valid
                .capabilities
                .inputs
                .contains(&ProviderInputCapabilityV1::OnlineStrokes)
        );
        assert_eq!(valid.result.candidates[0].recognized_text, "fixture text");
        assert!(!valid.stderr_truncated);

        let silent_holder_marker = mock.directory.join("silent-holder-ready.txt");
        let silent_holder = run_mock_worker_with_arguments(
            &mock.executable,
            "ok-silent-holder",
            valid_response.clone(),
            request.clone(),
            Duration::from_secs(2),
            &[silent_holder_marker.to_string_lossy().into_owned()],
        )
        .expect("success waits for the silent descendant to leave its Job Object");
        assert_eq!(
            silent_holder.result.candidates[0].recognized_text,
            "fixture text"
        );
        let silent_holder_pid = fs::read_to_string(&silent_holder_marker)
            .expect("silent descendant startup marker")
            .parse::<u32>()
            .expect("silent descendant process ID");
        assert!(
            process_is_signaled(silent_holder_pid),
            "the descendant is signaled before the provider slot is reusable"
        );

        let after_silent_cleanup = run_mock_worker(
            &mock.executable,
            "ok",
            valid_response.clone(),
            request.clone(),
            Duration::from_secs(2),
        )
        .expect("the next request is admitted only after ActiveProcesses reached zero");
        assert_eq!(
            after_silent_cleanup.result.candidates[0].recognized_text,
            "fixture text"
        );

        let mut argv_request = request.clone();
        argv_request.provider_configuration.configuration_id =
            "cfg with spaces \"embedded\" slash\\\"quote trailing\\\\".to_owned();
        argv_request.provider_configuration_fingerprint =
            argv_request.provider_configuration.fingerprint().unwrap();
        let argv_response = serde_json::to_string(&WorkerResponseFrameV1::Recognition {
            protocol_version: PROVIDER_PROTOCOL_VERSION,
            result: fixture_result(&argv_request, argv_request.source_revision.clone()),
        })
        .unwrap();
        let argv_roundtrip = run_mock_worker(
            &mock.executable,
            "ok",
            argv_response,
            argv_request.clone(),
            Duration::from_secs(2),
        )
        .expect("Windows argv quoting preserves whitespace, quotes, and backslashes");
        assert_eq!(
            argv_roundtrip.result.provider_configuration_id,
            argv_request.provider_configuration.configuration_id
        );

        let after_cleanup = run_mock_worker(
            &mock.executable,
            "ok",
            valid_response,
            request,
            Duration::from_secs(2),
        )
        .expect("another provider call is admitted after verified tree and helper cleanup");
        assert_eq!(
            after_cleanup.result.candidates[0].recognized_text,
            "fixture text"
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "model-backed M4 integration; guarded hosted Windows x64 job only"]
    fn senocr_full_precision_raster_worker_integrates_with_m4_parent() {
        require_senocr_m4_worker_test_opt_in();
        let runner_temp = PathBuf::from(
            std::env::var_os("RUNNER_TEMP").expect("guarded hosted runner temp directory"),
        );
        let shared_dir = PathBuf::from(
            std::env::var_os("LASSOINK_SENOCR_E2E_SHARED_DIR")
                .expect("guarded test-only sidecar directory"),
        );
        assert!(runner_temp.is_absolute() && shared_dir.is_absolute());
        assert_eq!(
            shared_dir.file_name().and_then(|name| name.to_str()),
            Some("lasso-senocr-worker-e2e")
        );
        assert!(
            shared_dir
                .parent()
                .and_then(|parent| parent.canonicalize().ok())
                .is_some_and(|parent| runner_temp.canonicalize().is_ok_and(|root| parent == root)),
            "test sidecar directory must remain directly under RUNNER_TEMP"
        );
        fs::create_dir(&shared_dir).expect("create unique bounded test-only sidecar directory");

        let target = stroke_ref("senocr-e2e-stroke", "synthetic-device");
        let journal_path = shared_dir.join("synthetic-source.journal");
        let mut writer = JournalWriter::create(
            journal_path.clone(),
            JournalHeader {
                journal_id: target.journal_id.clone(),
                session_id: target.session_id.clone(),
                config_id: Some("synthetic-senocr-e2e-config".to_owned()),
                device_model_declared: Some("synthetic fixture device".to_owned()),
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        writer
            .start_stroke(target.clone(), StrokeViewFrame::default(), 10)
            .unwrap();
        let mut first = physical_sample(&target, 701, 128);
        first.position.as_mut().unwrap().y_raw = 160;
        first.app_arrival_elapsed_ns = 11;
        let first_sequence = writer.append_sample(first).unwrap();
        let mut second = physical_sample(&target, 702, 320);
        second.position.as_mut().unwrap().y_raw = 340;
        second.app_arrival_elapsed_ns = 12;
        let second_sequence = writer.append_sample(second).unwrap();
        writer.commit_stroke(target.clone(), 13).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let journal = crate::journal::read_journal(&journal_path).unwrap();
        assert!(!journal.recovery.truncated_final_record);
        assert_eq!(journal.state.physical_samples.len(), 2);
        let source_revision = ProviderSourceRevisionV1::from_journal(&journal.state);
        let selected = vec![target.clone()];
        let generated_spec = crate::canvas::CanonicalRasterProjectionSpecV1::new(
            128,
            128,
            crate::canvas::CanonicalRasterProjectionCropV1 {
                left_px: 0,
                top_px: 0,
                right_px_exclusive: 512,
                bottom_px_exclusive: 512,
            },
        );
        let plan = crate::canvas::build_canonical_raster_projection_plan(&journal.state, &selected)
            .unwrap();
        let geometry =
            crate::canvas::transform_canonical_raster_geometry(&plan, &generated_spec).unwrap();
        let raster_image = crate::canvas::render_canonical_raster(&geometry).unwrap();
        let (width, height, stride) = raster_image.output_dimensions_and_stride();
        assert_eq!((width, height, stride), (128, 128, 512));
        let rgba = raster_image.rgba8_premultiplied_srgb_top_down();
        assert_eq!(rgba.len(), (stride * height) as usize);
        let mut canonical_rgb = Vec::with_capacity(width as usize * height as usize * 3);
        let (rgba_pixels, rgba_remainder) = rgba.as_chunks::<4>();
        assert!(rgba_remainder.is_empty());
        for pixel in rgba_pixels {
            assert_eq!(pixel[3], 255);
            canonical_rgb.extend_from_slice(&pixel[..3]);
        }

        let pixel_path = shared_dir.join("canonical-rgba.bin");
        let mut pixel_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pixel_path)
            .expect("create the bounded test-only canonical pixel baseline");
        pixel_file.write_all(rgba).unwrap();
        pixel_file.flush().unwrap();
        drop(pixel_file);

        let hex = |bytes: &[u8]| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut output = String::with_capacity(bytes.len().saturating_mul(2));
            for byte in bytes {
                output.push(char::from(HEX[usize::from(*byte >> 4)]));
                output.push(char::from(HEX[usize::from(*byte & 0x0f)]));
            }
            output
        };
        let png = raster_image.png_bytes();
        assert!(!png.is_empty() && png.len() <= 1024 * 1024);
        let png_hex = hex(png);
        let raster = ProviderRasterInputV1 {
            width,
            height,
            payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
            coordinate_space: "canonical-raster-output-v1".to_owned(),
            units: "pixel".to_owned(),
            raw_payload_hex: png_hex.clone(),
        };

        let python_executable = PathBuf::from(
            std::env::var_os("LASSOINK_SENOCR_PYTHON")
                .expect("setup-python provides its absolute executable path"),
        );
        let worker_script =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/senocr_fp32_worker.py");
        let asset_root = PathBuf::from(
            std::env::var_os("LASSOINK_SENOCR_ASSET_ROOT")
                .expect("the prior guarded probe retained the verified local asset directory"),
        );
        assert!(python_executable.is_absolute() && worker_script.is_absolute());
        assert!(asset_root.is_absolute() && asset_root.is_dir());
        let make_request =
            |request_id: &str,
             asset_root: &std::path::Path,
             requested_input_modalities: Vec<ProviderInputCapabilityV1>,
             raster_input: Option<ProviderRasterInputV1>| {
                let configuration = ProviderConfigurationV1 {
                    configuration_id: "senocr-v1-fp32-local".to_owned(),
                    values: BTreeMap::from([
                        (
                            "asset_root".to_owned(),
                            asset_root.to_string_lossy().into_owned(),
                        ),
                        ("model_id".to_owned(), "VietAlphaLabs/SenOCR-Vi".to_owned()),
                        (
                            "model_revision".to_owned(),
                            "1e70dff4ef0429b0d88a2b873fb5d03300af1a41".to_owned(),
                        ),
                    ]),
                };
                build_recognition_request(RecognitionRequestBuildInput {
                    state: &journal.state,
                    request_id: request_id.to_owned(),
                    region_id: "synthetic-senocr-region".to_owned(),
                    line_id: "synthetic-senocr-line".to_owned(),
                    coordinate_space: "canonical-raster-output-v1".to_owned(),
                    coordinate_units: "pixel".to_owned(),
                    language_hints: vec!["vi-VN".to_owned()],
                    requested_input_modalities,
                    provider_configuration: configuration,
                    selected_strokes: &selected,
                    raster: raster_input,
                })
                .unwrap()
            };
        let request = make_request(
            "senocr-m4-raster-e2e",
            &asset_root,
            vec![ProviderInputCapabilityV1::Raster],
            Some(raster.clone()),
        );
        assert_eq!(request.source_revision, source_revision);
        assert_eq!(
            request.requested_input_modalities,
            vec![ProviderInputCapabilityV1::Raster]
        );
        assert_eq!(
            request
                .samples
                .iter()
                .map(|sample| sample.journal_sequence)
                .collect::<Vec<_>>(),
            vec![first_sequence, second_sequence]
        );
        assert_eq!(request.samples.len(), 2);

        let execution =
            run_senocr_worker_request(&python_executable, &worker_script, request.clone())
                .unwrap_or_else(|_error| {
                    panic!("the guarded local Raster worker returned a failure")
                });
        let result = &execution.result;
        assert_eq!(result.request_id, request.request_id);
        assert_eq!(result.input_view_id, request.input_view_id);
        assert_eq!(result.source_revision, request.source_revision);
        assert_eq!(result.region_id, request.region_id);
        assert_eq!(result.line_id, request.line_id);
        assert_eq!(
            result.provider_configuration_id,
            request.provider_configuration.configuration_id
        );
        assert_eq!(
            result.provider_configuration_fingerprint,
            request.provider_configuration_fingerprint
        );
        assert_eq!(
            result.consumed_input_modalities,
            vec![ProviderInputCapabilityV1::Raster]
        );
        assert_eq!(result.provider.provider_id, "senocr-v1-fp32-local");
        assert_eq!(
            result.provider.model_version.as_deref(),
            Some("1e70dff4ef0429b0d88a2b873fb5d03300af1a41")
        );
        assert_eq!(result.candidates.len(), 1);
        assert!(result.candidates[0].recognized_text.len() <= MAX_TEXT_BYTES);
        assert!(result.candidates[0].native_score_raw.is_none());
        assert!(result.candidates[0].stroke_ranges.is_empty());
        assert!(execution.raw_response_transcript.capture_complete);
        assert_eq!(execution.raw_response_transcript.frames.len(), 2);
        assert!(execution.timing.process_create_call_to_recognition_ns > 0);
        assert!(execution.timing.model_cold_start_ns.is_none());

        let sidecar_path = shared_dir.join("processor-parity.json");
        let sidecar_bytes = fs::read(&sidecar_path).unwrap();
        assert!(sidecar_bytes.len() <= 16 * 1024);
        let sidecar_text = std::str::from_utf8(&sidecar_bytes).unwrap();
        assert!(!sidecar_text.contains(&asset_root.to_string_lossy().into_owned()));
        assert!(!sidecar_text.contains(&worker_script.to_string_lossy().into_owned()));
        assert!(!sidecar_text.contains(&png_hex));
        assert!(!sidecar_text.contains("recognized_text"));
        let sidecar: serde_json::Value = serde_json::from_slice(&sidecar_bytes).unwrap();
        assert_eq!(sidecar["schema"], "senocr-processor-parity-v1");
        assert_eq!(sidecar["width"].as_u64(), Some(u64::from(width)));
        assert_eq!(sidecar["height"].as_u64(), Some(u64::from(height)));
        assert_eq!(sidecar["canonical_rgba_sha256"], hex(&Sha256::digest(rgba)));
        let canonical_rgb_sha256 = hex(&Sha256::digest(&canonical_rgb));
        assert_eq!(sidecar["canonical_rgb_sha256"], canonical_rgb_sha256);
        assert_eq!(sidecar["decoded_png_rgb_sha256"], canonical_rgb_sha256);
        assert_eq!(
            sidecar["decoded_processor_inputs"],
            sidecar["direct_processor_inputs"]
        );
        assert!(sidecar["decoded_processor_inputs"]["input_ids"].is_object());
        assert!(
            sidecar["decoded_processor_inputs"]
                .as_object()
                .is_some_and(|inputs| inputs.len() >= 2)
        );
        fs::remove_file(&sidecar_path).unwrap();

        // Exercise the same production benchmark path with the real guarded
        // local worker. The temporary artifact must bind the full frozen
        // runtime profile and every required asset observation without
        // copying the operator paths or raster bytes.
        let benchmark_case_path = shared_dir.join("benchmark-case.json");
        let benchmark_provider_path = shared_dir.join("benchmark-provider.json");
        let benchmark_case = BenchmarkCaseManifestV1 {
            schema_version: 1,
            batch_id: "senocr-benchmark-e2e".to_owned(),
            cases: vec![BenchmarkCaseSpecV1 {
                case_id: "synthetic-case".to_owned(),
                journal_path: journal_path.clone(),
                expected_source_revision: source_revision.clone(),
                region_id: "synthetic-senocr-region".to_owned(),
                line_id: "synthetic-senocr-line".to_owned(),
                coordinate_space: "canonical-raster-output-v1".to_owned(),
                coordinate_units: "pixel".to_owned(),
                language_hints: vec!["vi-VN".to_owned()],
                requested_input_modalities: vec![ProviderInputCapabilityV1::Raster],
                selected_strokes: vec![BenchmarkStrokeRefV1::from(&target)],
                provenance: BenchmarkCaseProvenanceV1 {
                    corpus_id: None,
                    annotation_id: None,
                    writer_key: "synthetic-writer".to_owned(),
                    session_key: target.session_id.clone(),
                    session_start_unix_ns: None,
                    configuration_key: "synthetic-senocr-e2e-config".to_owned(),
                    split: None,
                    capture_api: None,
                    capture_api_version: None,
                    tablet_model: None,
                    driver_version: None,
                    windows_build: None,
                    windows_ink_state: None,
                    active_area: None,
                    display_mapping: None,
                    pressure_curve: None,
                },
                raster: None,
                generated_raster: Some(BenchmarkGeneratedRasterSpecV1 {
                    projection_schema_version: 1,
                    output_width_px: width,
                    output_height_px: height,
                    source_crop: BenchmarkGeneratedRasterCropV1 {
                        left_px: 0,
                        top_px: 0,
                        right_px_exclusive: 512,
                        bottom_px_exclusive: 512,
                    },
                }),
            }],
        };
        let benchmark_configuration = ProviderConfigurationV1 {
            configuration_id: "senocr-v1-fp32-local".to_owned(),
            values: BTreeMap::from([
                (
                    "asset_root".to_owned(),
                    asset_root.to_string_lossy().into_owned(),
                ),
                ("model_id".to_owned(), "VietAlphaLabs/SenOCR-Vi".to_owned()),
                (
                    "model_revision".to_owned(),
                    "1e70dff4ef0429b0d88a2b873fb5d03300af1a41".to_owned(),
                ),
            ]),
        };
        let mut benchmark_artifacts = vec![ProviderArtifactPathV1 {
            artifact_id: "python-executable".to_owned(),
            role: ProviderArtifactRoleV1::Executable,
            path: python_executable.clone(),
        }];
        for (index, (asset_name, _expected_bytes)) in
            benchmark::SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES
                .iter()
                .enumerate()
        {
            let role = match *asset_name {
                "model-00001-of-00001.safetensors" => ProviderArtifactRoleV1::Model,
                "added_tokens.json"
                | "chat_template.jinja"
                | "special_tokens_map.json"
                | "tokenizer.json"
                | "tokenizer.model"
                | "tokenizer_config.json" => ProviderArtifactRoleV1::Tokenizer,
                _ => ProviderArtifactRoleV1::Resource,
            };
            benchmark_artifacts.push(ProviderArtifactPathV1 {
                artifact_id: format!("senocr-asset-{index:02}"),
                role,
                path: asset_root.join(*asset_name),
            });
        }
        let benchmark_provider = BenchmarkProviderManifestV1 {
            schema_version: 1,
            providers: vec![ApprovedBenchmarkProviderV1 {
                provider_id: "senocr-v1-fp32-local".to_owned(),
                executable_path: python_executable,
                arguments: vec![worker_script.to_string_lossy().into_owned()],
                requested_input_modalities: Some(vec![ProviderInputCapabilityV1::Raster]),
                protocol_configuration: benchmark_configuration,
                artifacts: benchmark_artifacts,
                timeouts: Some(BenchmarkTimeoutsV1 {
                    handshake_ms: 30_000,
                    recognition_ms: 120_000,
                    shutdown_ms: 30_000,
                }),
            }],
        };
        fs::write(
            &benchmark_case_path,
            serde_json::to_vec(&benchmark_case).unwrap(),
        )
        .unwrap();
        fs::write(
            &benchmark_provider_path,
            serde_json::to_vec(&benchmark_provider).unwrap(),
        )
        .unwrap();
        let benchmark_completion = benchmark::run_batch_cli_to_directory(
            &benchmark_case_path,
            &benchmark_provider_path,
            None,
            &shared_dir,
        )
        .unwrap_or_else(|_error| panic!("the guarded M5 benchmark run returned a failure"));
        let benchmark_text = fs::read_to_string(&benchmark_completion.artifact_path).unwrap();
        let benchmark_rows = benchmark_text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        let run_row = benchmark_rows
            .iter()
            .find(|row| row["record_type"] == "run")
            .expect("the benchmark artifact contains its run record");
        let record = &run_row["record"];
        let quality_evidence = &record["quality_evidence"];
        assert_eq!(
            quality_evidence["status"],
            "eligible_by_declared_senocr_evidence"
        );
        assert_eq!(
            quality_evidence["runtime_profile"]["profile_manifest_sha256"],
            "3d6150df16fc91bf032638d88a02d30be6877f5b4e62da5682fa601d0fe1ac1c"
        );
        assert_eq!(
            quality_evidence["runtime_profile"]["installed_distribution_closure"]
                .as_array()
                .unwrap()
                .len(),
            41
        );
        assert_eq!(
            quality_evidence["model_asset_coverage"]["required_asset_count"],
            12
        );
        assert_eq!(
            quality_evidence["model_asset_coverage"]["observed_asset_count"],
            12
        );
        assert_eq!(
            quality_evidence["model_asset_coverage"]["status"],
            "complete_prelaunch_observations"
        );
        assert_eq!(
            quality_evidence["model_asset_coverage"]["observed_assets"]
                .as_array()
                .unwrap()
                .len(),
            12
        );
        assert!(record["candidate_metrics"].as_array().unwrap().is_empty());
        assert_eq!(record["requested_input_modalities"][0], "raster");
        assert_eq!(
            record["provider_identity"]["provider_id"],
            "senocr-v1-fp32-local"
        );
        let private_paths = vec![
            asset_root.to_string_lossy().into_owned(),
            python_executable.to_string_lossy().into_owned(),
            worker_script.to_string_lossy().into_owned(),
        ];
        let injected_path_json = serde_json::to_string(&serde_json::json!({
            "nested": {"paths": private_paths.clone()}
        }))
        .unwrap();
        let injected_path_values: serde_json::Value =
            serde_json::from_str(&injected_path_json).unwrap();
        for private_path in &private_paths {
            assert!(json_value_contains_string(
                &injected_path_values,
                private_path
            ));
            assert!(
                !benchmark_rows
                    .iter()
                    .any(|row| json_value_contains_string(row, private_path))
            );
        }
        assert!(!benchmark_text.contains(&png_hex));

        let expect_worker_failure = |request: RecognitionRequestV1, expected_code: &str| {
            let error = match run_senocr_worker_request(&python_executable, &worker_script, request)
            {
                Ok(_execution) => panic!("invalid Raster request unexpectedly succeeded"),
                Err(error) => error,
            };
            assert!(matches!(
                &error.kind,
                ProviderErrorKind::ProviderFailure { code, .. } if code == expected_code
            ));
            assert!(error.raw_response_transcript.capture_complete);
            assert_eq!(error.raw_response_transcript.frames.len(), 2);
            let failure_payload = &error.raw_response_transcript.frames[1].payload_bytes;
            let failure: serde_json::Value = serde_json::from_slice(failure_payload).unwrap();
            assert_eq!(failure["kind"], "failure");
            assert_eq!(failure["code"], expected_code);
        };
        let raster_for_png = |payload: &[u8]| ProviderRasterInputV1 {
            raw_payload_hex: hex(payload),
            ..raster.clone()
        };

        let truncated_png = &png[..png.len().saturating_sub(16)];
        assert!(truncated_png.len() > 33);
        expect_worker_failure(
            make_request(
                "senocr-m4-truncated-png",
                &asset_root,
                vec![ProviderInputCapabilityV1::Raster],
                Some(raster_for_png(truncated_png)),
            ),
            "raster_decode_failed",
        );

        let apng_fixture = PathBuf::from(
            std::env::var_os("LASSOINK_SENOCR_APNG_FIXTURE")
                .expect("the guarded Pillow test produced a bounded APNG fixture"),
        );
        assert!(apng_fixture.is_absolute() && !apng_fixture.is_symlink());
        assert_eq!(
            apng_fixture.file_name().and_then(|name| name.to_str()),
            Some("senocr-apng-negative.png")
        );
        assert!(
            apng_fixture
                .parent()
                .and_then(|parent| parent.canonicalize().ok())
                .is_some_and(|parent| runner_temp.canonicalize().is_ok_and(|root| parent == root)),
            "APNG fixture must remain directly under RUNNER_TEMP"
        );
        let apng_bytes = fs::read(&apng_fixture).unwrap();
        assert!(!apng_bytes.is_empty() && apng_bytes.len() <= 64 * 1024);
        expect_worker_failure(
            make_request(
                "senocr-m4-apng",
                &asset_root,
                vec![ProviderInputCapabilityV1::Raster],
                Some(raster_for_png(&apng_bytes)),
            ),
            "raster_decode_failed",
        );

        let mut transparent_pixmap = tiny_skia::Pixmap::new(128, 128).unwrap();
        transparent_pixmap.fill(tiny_skia::Color::from_rgba8(10, 20, 30, 254));
        let transparent_png = transparent_pixmap.encode_png().unwrap();
        assert!(!transparent_png.is_empty() && transparent_png.len() <= 64 * 1024);
        expect_worker_failure(
            make_request(
                "senocr-m4-transparent-alpha",
                &asset_root,
                vec![ProviderInputCapabilityV1::Raster],
                Some(raster_for_png(&transparent_png)),
            ),
            "raster_decode_failed",
        );

        let unsupported_mode = make_request(
            "senocr-m4-unsupported-online-mode",
            &asset_root,
            vec![ProviderInputCapabilityV1::OnlineStrokes],
            None,
        );
        let unsupported_mode_error =
            match run_senocr_worker_request(&python_executable, &worker_script, unsupported_mode) {
                Ok(_execution) => panic!("unsupported mode unexpectedly received a result"),
                Err(error) => error,
            };
        assert!(matches!(
            unsupported_mode_error.kind,
            ProviderErrorKind::UnsupportedCapability(_)
        ));
        assert_eq!(
            unsupported_mode_error.raw_response_transcript.frames.len(),
            1
        );
        assert!(
            !unsupported_mode_error
                .raw_response_transcript
                .capture_complete
        );

        let missing_asset_root = shared_dir.join("missing-asset-root");
        assert!(!missing_asset_root.exists());
        let missing_request = make_request(
            "senocr-m4-missing-assets",
            &missing_asset_root,
            vec![ProviderInputCapabilityV1::Raster],
            Some(raster.clone()),
        );
        let missing =
            match run_senocr_worker_request(&python_executable, &worker_script, missing_request) {
                Ok(_execution) => {
                    panic!("missing local model files must fail without an alternate provider")
                }
                Err(error) => error,
            };
        assert!(matches!(
            missing.kind,
            ProviderErrorKind::ProviderFailure { code, .. } if code == "asset_directory_invalid"
        ));
        assert!(missing.raw_response_transcript.capture_complete);
        let failure_payload = &missing.raw_response_transcript.frames[1].payload_bytes;
        let failure: serde_json::Value = serde_json::from_slice(failure_payload).unwrap();
        assert_eq!(failure["kind"], "failure");
        assert_eq!(failure["code"], "asset_directory_invalid");
        assert!(failure["message"].as_str().is_some());

        fs::remove_dir_all(&shared_dir).unwrap();
    }
}
