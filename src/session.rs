//! Bounded local session output and deterministic report parsing.
//!
//! The versioned TSV stream is intentionally local-only. It keeps native clock
//! domains separate, preserves raw records, and never deduplicates input rows.

use crate::process_cpu::{
    FileTimeWords, PROCESS_CPU_SCOPE, ProcessCpuMeasurement, ProcessCpuSnapshot,
    ProcessCpuUnavailableReason,
};
use crate::win32_pointer::{
    DirectPenHistoryBatch, LifecycleEventRecord, PointerAttribution, PointerMessageKind,
    ProbeRecord, ProbeSummary, PublicWinitEventData, SessionOutputStage, WintabPacketBatch,
    WintabPacketTimeMode,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{self, Debug, Display, Formatter},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    PEN_MASK_PRESSURE, PEN_MASK_TILT_X, PEN_MASK_TILT_Y, PT_PEN,
};
use windows_sys::Win32::{
    Foundation::GetLastError,
    Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW},
};

pub(crate) const SESSION_SCHEMA_VERSION: u32 = 2;
pub(crate) const MAX_SESSION_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_SESSION_LINE_BYTES: usize = 16 * 1024;
const MAX_SESSION_LINES: u64 = 140_000;
const MAX_REPORT_PARTITIONS: usize = 4096;
const MAX_REPORT_FINGERPRINTS: usize = 131_072;
const MAX_TRACKED_STROKES: usize = 4096;
const MAX_PRESSURE_VALUES_PER_PARTITION: usize = 4096;
const MAX_PRESSURE_DISTRIBUTION_ENTRIES: usize = 32_768;
const MAX_SESSION_METADATA_ENTRIES: usize = 128;
const MAX_SESSION_METADATA_TEXT_BYTES: usize = 4096;
const WINTAB_TPS_QUEUE_ERR: u32 = 0x0002;
static SESSION_FILENAME_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn default_session_path(directory: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = SESSION_FILENAME_COUNTER.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        "session-{timestamp}-{}-{sequence}.tsv",
        std::process::id()
    ))
}

#[derive(Debug)]
pub(crate) struct SessionIoError {
    pub stage: SessionOutputStage,
    message: String,
}

impl Display for SessionIoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.stage, self.message)
    }
}

impl std::error::Error for SessionIoError {}

impl SessionIoError {
    fn new(stage: SessionOutputStage, error: impl Display) -> Self {
        Self {
            stage,
            message: error.to_string(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SessionWriter {
    final_path: PathBuf,
    partial_path: PathBuf,
    file: Option<BufWriter<File>>,
    bytes_written: u64,
    rows_written: u64,
    max_session_lines: u64,
    metadata_keys: HashSet<String>,
}

impl SessionWriter {
    pub(crate) fn create(
        final_path: PathBuf,
        metadata: &BTreeMap<String, String>,
    ) -> Result<Self, SessionIoError> {
        Self::create_with_line_limit(final_path, metadata, MAX_SESSION_LINES)
    }

    fn create_with_line_limit(
        final_path: PathBuf,
        metadata: &BTreeMap<String, String>,
        max_session_lines: u64,
    ) -> Result<Self, SessionIoError> {
        if max_session_lines < 3 {
            return Err(SessionIoError::new(
                SessionOutputStage::Write,
                "session line limit must fit a header, CPU row, and END footer",
            ));
        }
        let parent = final_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent)
                .map_err(|error| SessionIoError::new(SessionOutputStage::CreateDirectory, error))?;
        }
        let partial_path = partial_session_path(&final_path);
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&partial_path)
            .map_err(|error| SessionIoError::new(SessionOutputStage::CreateFile, error))?;
        let mut writer = Self {
            final_path,
            partial_path,
            file: Some(BufWriter::new(file)),
            bytes_written: 0,
            rows_written: 0,
            max_session_lines,
            metadata_keys: HashSet::new(),
        };
        writer.write_row(&[
            "LASSOINK-SESSION".to_owned(),
            SESSION_SCHEMA_VERSION.to_string(),
        ])?;
        for (key, value) in metadata {
            writer.write_metadata(key, value)?;
        }
        writer.flush()?;
        Ok(writer)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.final_path
    }

    pub(crate) fn write_metadata(&mut self, key: &str, value: &str) -> Result<(), SessionIoError> {
        if key.len() > 256 || value.len() > MAX_SESSION_METADATA_TEXT_BYTES {
            return Err(SessionIoError::new(
                SessionOutputStage::Write,
                "session metadata field exceeds its bounded byte size",
            ));
        }
        if !self.metadata_keys.contains(key)
            && self.metadata_keys.len() >= MAX_SESSION_METADATA_ENTRIES
        {
            return Err(SessionIoError::new(
                SessionOutputStage::Write,
                "session metadata key limit reached",
            ));
        }
        self.write_row(&["META".to_owned(), key.to_owned(), value.to_owned()])
            .map(|()| {
                self.metadata_keys.insert(key.to_owned());
            })
    }

    pub(crate) fn write_records(&mut self, records: &[ProbeRecord]) -> Result<(), SessionIoError> {
        for record in records {
            self.write_record(record)?;
        }
        self.flush()
    }

    pub(crate) fn finish(
        mut self,
        summary: ProbeSummary,
        ended_elapsed_ns: u128,
        process_cpu: ProcessCpuMeasurement,
    ) -> Result<PathBuf, SessionIoError> {
        self.write_cpu_measurement(&process_cpu)?;
        self.write_footer_row(&[
            "END".to_owned(),
            "finalized".to_owned(),
            ended_elapsed_ns.to_string(),
            summary.records_retained.to_string(),
            summary
                .samples
                .saturating_add(summary.wintab_packets)
                .to_string(),
            summary.valid_direct_pen_samples.to_string(),
            summary.invalid_direct_pen_samples.to_string(),
            summary.validation_anomaly_samples.to_string(),
            summary.uncertain_wintab_packets.to_string(),
            summary.lifecycle_events.to_string(),
            debug_opt(summary.storage_limit),
            summary.incomplete_batches.to_string(),
            format!("{:?}", summary.wintab_status),
            summary.pointer_api_available.to_string(),
            format!("{:?}", summary.capture_mode),
            debug_opt(summary.latest_startup_issue),
            debug_opt(summary.latest_wintab_issue),
            debug_opt(summary.latest_incomplete_issue),
            summary.records_not_retained.to_string(),
            summary.batches_not_retained.to_string(),
            summary.samples_not_retained.to_string(),
        ])?;
        self.flush()?;
        let file = self.file.take().expect("session writer owns an open file");
        file.get_ref()
            .sync_all()
            .map_err(|error| SessionIoError::new(SessionOutputStage::Sync, error))?;
        drop(file);
        publish_no_clobber(&self.partial_path, &self.final_path)
            .map_err(|error| SessionIoError::new(SessionOutputStage::Finalize, error))?;
        Ok(self.final_path.clone())
    }

    fn write_cpu_measurement(
        &mut self,
        measurement: &ProcessCpuMeasurement,
    ) -> Result<(), SessionIoError> {
        let mut fields = vec![
            "CPU".to_owned(),
            measurement.start.app_elapsed_ns.to_string(),
            measurement.end.app_elapsed_ns.to_string(),
            opt_display(measurement.app_interval_ns),
        ];
        for time in [
            measurement.start.user,
            measurement.start.kernel,
            measurement.end.user,
            measurement.end.kernel,
        ] {
            fields.push(opt_display(time.map(|value| value.low)));
            fields.push(opt_display(time.map(|value| value.high)));
        }
        fields.extend([
            opt_display(measurement.user_delta_100ns),
            opt_display(measurement.kernel_delta_100ns),
            measurement
                .core_equivalent_percent
                .map_or_else(String::new, |value| format!("{:016X}", value.to_bits())),
            measurement
                .unavailable_reason
                .as_ref()
                .map_or_else(String::new, cpu_unavailable_reason_label),
            opt_display(measurement.start.win32_error),
            opt_display(measurement.end.win32_error),
        ]);
        self.write_cpu_row(&fields)
    }

    fn flush(&mut self) -> Result<(), SessionIoError> {
        self.file
            .as_mut()
            .expect("session writer owns an open file")
            .flush()
            .map_err(|error| SessionIoError::new(SessionOutputStage::Flush, error))
    }

    fn write_record(&mut self, record: &ProbeRecord) -> Result<(), SessionIoError> {
        match record {
            ProbeRecord::StartupIssue(issue) => {
                self.write_row(&["STARTUP".to_owned(), format!("{issue:?}")])?;
            }
            ProbeRecord::DirectPenHistory(batch) => self.write_direct_batch(batch)?,
            ProbeRecord::PublicWinitEvent(event) => self.write_public_event(event)?,
            ProbeRecord::Lifecycle(event) => self.write_lifecycle(event)?,
            ProbeRecord::WintabPackets(batch) => self.write_wintab_batch(batch)?,
            ProbeRecord::WintabControlNotification(event) => {
                self.write_row(&[
                    "CONTROL".to_owned(),
                    format!("{:?}", event.source),
                    event.observer_sequence.to_string(),
                    event.message_id_raw.to_string(),
                    event.message_hwnd_raw_session_scoped.to_string(),
                    event.wparam_raw.to_string(),
                    event.lparam_raw.to_string(),
                    event.app_observed_elapsed_ns.to_string(),
                ])?;
            }
            ProbeRecord::WintabIssue {
                source,
                message_sequence,
                message_id_raw,
                message_hwnd_raw_session_scoped,
                message_wparam_raw,
                message_lparam_raw,
                message_time_ms_raw,
                app_observed_elapsed_ns,
                issue,
            } => {
                self.write_row(&[
                    "W_ISSUE".to_owned(),
                    format!("{source:?}"),
                    message_sequence.to_string(),
                    message_id_raw.to_string(),
                    opt_display(*message_hwnd_raw_session_scoped),
                    opt_display(*message_wparam_raw),
                    opt_display(*message_lparam_raw),
                    opt_display(*message_time_ms_raw),
                    opt_display(*app_observed_elapsed_ns),
                    format!("{issue:?}"),
                ])?;
            }
            ProbeRecord::IgnoredNonPenPointer {
                source,
                message_sequence,
                message_id_raw,
                message_hwnd_raw_session_scoped,
                message_wparam_raw,
                message_lparam_raw,
                message_time_ms_raw,
                message_kind,
                pointer_id,
                pointer_type_raw,
                hook_observed_elapsed_ns,
            } => {
                self.write_row(&[
                    "IGNORED".to_owned(),
                    format!("{source:?}"),
                    message_sequence.to_string(),
                    message_id_raw.to_string(),
                    message_hwnd_raw_session_scoped.to_string(),
                    message_wparam_raw.to_string(),
                    message_lparam_raw.to_string(),
                    opt_display(*message_time_ms_raw),
                    format!("{message_kind:?}"),
                    pointer_id.to_string(),
                    pointer_type_raw.to_string(),
                    hook_observed_elapsed_ns.to_string(),
                ])?;
            }
            ProbeRecord::MessageIssue {
                source,
                message_sequence,
                message_id_raw,
                message_hwnd_raw_session_scoped,
                message_wparam_raw,
                message_lparam_raw,
                message_time_ms_raw,
                message_kind,
                pointer_id,
                hook_observed_elapsed_ns,
                issue,
            } => {
                self.write_row(&[
                    "M_ISSUE".to_owned(),
                    format!("{source:?}"),
                    message_sequence.to_string(),
                    message_id_raw.to_string(),
                    opt_display(*message_hwnd_raw_session_scoped),
                    opt_display(*message_wparam_raw),
                    opt_display(*message_lparam_raw),
                    opt_display(*message_time_ms_raw),
                    debug_opt(*message_kind),
                    opt_display(*pointer_id),
                    hook_observed_elapsed_ns.to_string(),
                    format!("{issue:?}"),
                ])?;
            }
        }
        Ok(())
    }

    fn write_direct_batch(&mut self, batch: &DirectPenHistoryBatch) -> Result<(), SessionIoError> {
        self.write_row(&[
            "D_BATCH".to_owned(),
            batch.message_sequence.to_string(),
            batch.message_id_raw.to_string(),
            batch.message_hwnd_raw_session_scoped.to_string(),
            opt_display(batch.message_time_ms_raw),
            format!("{:?}", batch.message_kind),
            batch.pointer_id_requested.to_string(),
            batch.hook_observed_elapsed_ns.to_string(),
            opt_display(batch.hook_qpc_count_raw),
            debug_opt(batch.hook_qpc_issue),
            opt_display(batch.qpc_frequency_hz),
            batch.native_history_count.to_string(),
            batch.samples.len().to_string(),
        ])?;
        for sample in &batch.samples {
            self.write_row(&[
                "D_SAMPLE".to_owned(),
                batch.message_sequence.to_string(),
                sample.history_index_newest_first.to_string(),
                sample.chronological_index.to_string(),
                (sample.attribution == PointerAttribution::MatchesRequestedPointer).to_string(),
                sample.pointer_type_raw.to_string(),
                sample.pointer_id_raw.to_string(),
                sample.frame_id_raw.to_string(),
                sample.source_device_handle_raw_session_scoped.to_string(),
                sample.target_hwnd_raw_session_scoped.to_string(),
                sample.pointer_flags_raw.to_string(),
                sample.button_change_type_raw.to_string(),
                format!("{:?}", sample.position.coordinate_space),
                format!("{:?}", sample.position.pixel_units),
                sample.position.pt_pixel_location_raw.x.to_string(),
                sample.position.pt_pixel_location_raw.y.to_string(),
                format!("{:?}", sample.position.himetric_units),
                sample.position.pt_himetric_location_raw.x.to_string(),
                sample.position.pt_himetric_location_raw.y.to_string(),
                sample.performance_count_qpc_raw.to_string(),
                sample.dw_time_ms_wrapping_raw.to_string(),
                sample.history_count_raw.to_string(),
                sample.input_data_raw.to_string(),
                sample.key_states_raw.to_string(),
                sample.pen_flags_raw.to_string(),
                sample.pen_mask_raw.to_string(),
                sample.pressure_raw.to_string(),
                format!("{:?}", sample.pressure_validity),
                sample.rotation_raw.to_string(),
                sample.tilt_x_raw.to_string(),
                sample.tilt_y_raw.to_string(),
                debug_opt(sample.tilt),
                sample.validation_issues.len().to_string(),
                format!("{:?}", sample.validation_issues),
            ])?;
        }
        Ok(())
    }

    fn write_public_event(
        &mut self,
        event: &crate::win32_pointer::PublicWinitEventRecord,
    ) -> Result<(), SessionIoError> {
        let association = event.message_association;
        let mut fields = vec![
            "PUBLIC".to_owned(),
            format!("{:?}", event.source),
            event.public_event_sequence.to_string(),
            event.app_observed_elapsed_ns.to_string(),
            opt_display(event.window_hwnd_raw_session_scoped),
            format!("{:?}", event.capability),
            opt_display(association.map(|value| value.message_sequence)),
            opt_display(association.map(|value| value.message_id_raw)),
            opt_display(association.map(|value| value.message_hwnd_raw_session_scoped)),
            opt_display(association.map(|value| value.pointer_id_raw)),
        ];
        match event.data {
            PublicWinitEventData::Touch {
                winit_device_id,
                public_touch_id,
                phase,
                x_physical_px,
                y_physical_px,
                public_winit_force,
                native_pointer_type_raw,
                pointer_type_error_raw,
                pen_classification,
                native_timestamp_raw,
                tilt,
            } => {
                fields.extend([
                    "Touch".to_owned(),
                    format!("{winit_device_id:?}"),
                    public_touch_id.to_string(),
                    format!("{phase:?}"),
                    format!("{:016X}", x_physical_px.to_bits()),
                    format!("{:016X}", y_physical_px.to_bits()),
                    force_parts(public_winit_force).0,
                    force_parts(public_winit_force).1,
                    force_parts(public_winit_force).2,
                    force_parts(public_winit_force).3,
                    opt_display(native_pointer_type_raw),
                    opt_display(pointer_type_error_raw),
                    format!("{pen_classification:?}"),
                    opt_display(native_timestamp_raw),
                    debug_opt(tilt),
                ]);
            }
            PublicWinitEventData::CursorMoved {
                winit_device_id,
                x_physical_px,
                y_physical_px,
                native_timestamp_raw,
            } => fields.extend([
                "CursorMoved".to_owned(),
                format!("{winit_device_id:?}"),
                String::new(),
                String::new(),
                format!("{:016X}", x_physical_px.to_bits()),
                format!("{:016X}", y_physical_px.to_bits()),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                opt_display(native_timestamp_raw),
                String::new(),
            ]),
            PublicWinitEventData::MouseInput {
                winit_device_id,
                state,
                button,
                native_timestamp_raw,
            } => fields.extend([
                "MouseInput".to_owned(),
                format!("{winit_device_id:?}"),
                String::new(),
                format!("{state:?}:{button:?}"),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                opt_display(native_timestamp_raw),
                String::new(),
            ]),
        }
        self.write_row(&fields)
    }

    fn write_lifecycle(&mut self, event: &LifecycleEventRecord) -> Result<(), SessionIoError> {
        self.write_row(&[
            "EVENT".to_owned(),
            format!("{:?}", event.source),
            format!("{:?}", event.kind),
            event.app_observed_elapsed_ns.to_string(),
            opt_display(event.message_id_raw),
            opt_display(event.message_hwnd_raw_session_scoped),
            opt_display(event.wparam_raw),
            opt_display(event.lparam_raw),
            opt_display(event.native_message_time_ms_raw),
            opt_display(event.pointer_id_raw),
            event.winit_device_id_debug.clone().unwrap_or_default(),
            opt_display(event.event_loop_wait_start_elapsed_ns),
            opt_display(event.event_loop_requested_resume_elapsed_ns),
            opt_display(event.event_loop_wake_lateness_ns),
            opt_display(event.controlled_stall_duration_ns),
            opt_display(event.issue_debug.clone()),
        ])
    }

    fn write_wintab_batch(&mut self, batch: &WintabPacketBatch) -> Result<(), SessionIoError> {
        self.write_row(&[
            "W_BATCH".to_owned(),
            batch.message_sequence.to_string(),
            batch.message_id_raw.to_string(),
            batch.message_hwnd_raw_session_scoped.to_string(),
            opt_display(batch.message_time_ms_raw),
            batch.message_wparam_raw.to_string(),
            batch.message_lparam_raw.to_string(),
            batch.context_handle_raw_session_scoped.to_string(),
            opt_display(batch.notification_serial_raw),
            format!("{:?}", batch.context_config),
            batch.context_config.device_raw.to_string(),
            batch.queue_capacity_raw.to_string(),
            format!("{:?}", batch.coordinate_space),
            format!("{:?}", batch.packet_time_mode),
            batch.app_observed_elapsed_ns.to_string(),
            batch.control_transition_observed_during_read.to_string(),
            batch.packet_quality_issue_observed.to_string(),
            batch.packets.len().to_string(),
        ])?;
        for packet in &batch.packets {
            self.write_row(&[
                "W_PACKET".to_owned(),
                batch.message_sequence.to_string(),
                packet.context_handle_raw_session_scoped.to_string(),
                packet.status_raw.to_string(),
                packet.packet_time_raw.to_string(),
                packet.serial_number_raw.to_string(),
                packet.cursor_raw.to_string(),
                packet.buttons_raw.to_string(),
                packet.x_raw.to_string(),
                packet.y_raw.to_string(),
                packet.normal_pressure_raw.to_string(),
            ])?;
        }
        Ok(())
    }

    fn write_row(&mut self, fields: &[String]) -> Result<(), SessionIoError> {
        self.write_row_with_reservation(fields, 2)
    }

    fn write_cpu_row(&mut self, fields: &[String]) -> Result<(), SessionIoError> {
        self.write_row_with_reservation(fields, 1)
    }

    fn write_footer_row(&mut self, fields: &[String]) -> Result<(), SessionIoError> {
        self.write_row_with_reservation(fields, 0)
    }

    fn write_row_with_reservation(
        &mut self,
        fields: &[String],
        reserved_following_lines: u64,
    ) -> Result<(), SessionIoError> {
        let row = encode_row(fields);
        if row.len() > MAX_SESSION_LINE_BYTES {
            return Err(SessionIoError::new(
                SessionOutputStage::Write,
                "session row exceeds the bounded line size",
            ));
        }
        let row_len = row.len() as u64;
        if self.bytes_written.saturating_add(row_len) > MAX_SESSION_BYTES {
            return Err(SessionIoError::new(
                SessionOutputStage::Write,
                "session byte cap reached; partial file retained",
            ));
        }
        let rows_after_write = self.rows_written.saturating_add(1);
        let required_lines = rows_after_write.saturating_add(reserved_following_lines);
        if required_lines > self.max_session_lines {
            return Err(SessionIoError::new(
                SessionOutputStage::Write,
                format!(
                    "session line cap reached at {}; {reserved_following_lines} required line(s) are reserved",
                    self.max_session_lines,
                ),
            ));
        }
        self.file
            .as_mut()
            .expect("session writer owns an open file")
            .write_all(&row)
            .map_err(|error| SessionIoError::new(SessionOutputStage::Write, error))?;
        self.bytes_written = self.bytes_written.saturating_add(row_len);
        self.rows_written = rows_after_write;
        Ok(())
    }
}

fn publish_no_clobber(partial_path: &Path, final_path: &Path) -> io::Result<()> {
    let partial_wide = partial_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let final_wide = final_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are NUL-terminated UTF-16 buffers alive for the call.
    // Only MOVEFILE_WRITE_THROUGH is set; omitting REPLACE_EXISTING makes an
    // existing destination a hard failure while preserving its bytes.
    let succeeded = unsafe {
        MoveFileExW(
            partial_wide.as_ptr(),
            final_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if succeeded == 0 {
        // SAFETY: GetLastError has no preconditions and is called immediately
        // after the failed Win32 operation on this thread.
        let error = unsafe { GetLastError() };
        Err(io::Error::from_raw_os_error(error as i32))
    } else {
        Ok(())
    }
}

fn partial_session_path(final_path: &Path) -> PathBuf {
    let mut name = final_path.as_os_str().to_owned();
    name.push(".partial");
    PathBuf::from(name)
}

fn encode_row(fields: &[String]) -> Vec<u8> {
    let mut row = Vec::with_capacity(fields.iter().map(String::len).sum::<usize>() + fields.len());
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            row.push(b'\t');
        }
        for byte in field.as_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-' | b':') {
                row.push(*byte);
            } else {
                row.extend_from_slice(format!("%{byte:02X}").as_bytes());
            }
        }
    }
    row.push(b'\n');
    row
}

fn opt_display<T: Display>(value: Option<T>) -> String {
    value.map_or_else(String::new, |value| value.to_string())
}

fn debug_opt<T: Debug>(value: Option<T>) -> String {
    value.map_or_else(String::new, |value| format!("{value:?}"))
}

fn cpu_unavailable_reason_label(reason: &ProcessCpuUnavailableReason) -> String {
    match reason {
        ProcessCpuUnavailableReason::StartSnapshotFailed { .. } => "StartSnapshotFailed",
        ProcessCpuUnavailableReason::EndSnapshotFailed { .. } => "EndSnapshotFailed",
        ProcessCpuUnavailableReason::SnapshotValuesUnavailable => "SnapshotValuesUnavailable",
        ProcessCpuUnavailableReason::AppClockRegressed => "AppClockRegressed",
        ProcessCpuUnavailableReason::ZeroMeasurementInterval => "ZeroMeasurementInterval",
        ProcessCpuUnavailableReason::ProcessTimeRegressed => "ProcessTimeRegressed",
    }
    .to_owned()
}

fn force_parts(force: Option<winit::event::Force>) -> (String, String, String, String) {
    match force {
        None => (
            "None".to_owned(),
            String::new(),
            String::new(),
            String::new(),
        ),
        Some(winit::event::Force::Normalized(value)) => (
            "Normalized".to_owned(),
            format!("{:016X}", value.to_bits()),
            String::new(),
            String::new(),
        ),
        Some(winit::event::Force::Calibrated {
            force,
            max_possible_force,
            altitude_angle,
        }) => (
            "Calibrated".to_owned(),
            format!("{:016X}", force.to_bits()),
            format!("{:016X}", max_possible_force.to_bits()),
            altitude_angle.map_or_else(String::new, |value| format!("{:016X}", value.to_bits())),
        ),
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SessionReport {
    pub complete: bool,
    pub capture_incomplete: bool,
    pub capture_mode: Option<String>,
    pub pointer_api_available: Option<bool>,
    pub wintab_status: Option<String>,
    pub latest_startup_issue: Option<String>,
    pub latest_wintab_issue: Option<String>,
    pub latest_incomplete_issue: Option<String>,
    pub records_not_retained: u64,
    pub batches_not_retained: u64,
    pub samples_not_retained: u64,
    pub schema_version: Option<u32>,
    pub process_cpu: Option<ProcessCpuMeasurement>,
    pub metadata: BTreeMap<String, String>,
    pub parsed_rows: u64,
    pub direct_batches: u64,
    pub raw_direct_samples: u64,
    pub valid_direct_pen_samples: u64,
    pub invalid_direct_pen_samples: u64,
    pub validation_anomaly_samples: u64,
    pub validation_issue_count: u64,
    pub pressure_mask_missing_samples: u64,
    pub pressure_out_of_range_samples: u64,
    pub pointer_id_mismatch_samples: u64,
    pub unexpected_pointer_type_samples: u64,
    pub unexpected_tilt_mask_samples: u64,
    pub public_events: u64,
    pub public_touch_events: u64,
    pub confirmed_public_pen_events: u64,
    pub direct_public_dispatch_overlaps: u64,
    pub wintab_control_notifications: u64,
    pub ignored_non_pen_events: u64,
    pub raw_wintab_packets: u64,
    pub uninterrupted_wintab_packets: u64,
    pub uncertain_wintab_packets: u64,
    pub wintab_context_mismatch_packets: u64,
    pub lifecycle_events: u64,
    pub issue_records: u64,
    pub exact_raw_duplicate_fingerprints: u64,
    pub pressure_distribution_value_entries: u64,
    pub pressure_distribution_cap_reached: bool,
    pub pressure_run_tracker_cap_reached: bool,
    pub unqualified_wintab_pressure_rows: u64,
    pub pressure_null_reasons: BTreeMap<String, u64>,
    pub native_clock_regressions: u64,
    pub qpc_message_to_hook_age_samples: u64,
    pub qpc_age_null_reasons: BTreeMap<String, u64>,
    pub qpc_native_interval_samples: u64,
    pub qpc_interval_null_reasons: BTreeMap<String, u64>,
    pub metric_partition_overflow: u64,
    pub duplicate_fingerprint_cap_reached: bool,
    pub partitions: BTreeMap<MetricKey, MetricBucket>,
    pub warnings: Vec<String>,
    overflowed_metric_partitions: HashSet<MetricKey>,
    overflow_partition_count_truncated: bool,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct MetricKey {
    pub api: String,
    pub device: String,
    pub pointer: String,
    pub stroke: String,
    pub native_clock: String,
    pub pressure_representation: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MetricBucket {
    pub raw_rows: u64,
    pub valid_direct_pen_samples: u64,
    pub invalid_direct_pen_samples: u64,
    pub anomaly_samples: u64,
    pub public_events: u64,
    pub confirmed_public_pen_events: u64,
    pub uninterrupted_wintab_packets: u64,
    pub uncertain_wintab_packets: u64,
    pub exact_raw_duplicate_fingerprints: u64,
    pub native_clock_regressions: u64,
    pub pressure_metric_samples: u64,
    pub pressure_value_counts: BTreeMap<u64, u64>,
    pub pressure_distribution_truncated: bool,
    pub pressure_repeated_values: u64,
    pub pressure_plateau_runs: u64,
    pub pressure_transitions: u64,
    pub pressure_max_run_length: u64,
    qpc_age_ns: Vec<u128>,
    qpc_age_null_reasons: BTreeMap<String, u64>,
    qpc_sample_interval_ns: Vec<u128>,
    qpc_interval_null_reasons: BTreeMap<String, u64>,
    valid_pressure_min: Option<u32>,
    valid_pressure_max: Option<u32>,
}

impl MetricBucket {
    fn add_qpc_age(&mut self, age_ns: Option<u128>, reason: Option<&str>) {
        if let Some(age_ns) = age_ns {
            self.qpc_age_ns.push(age_ns);
        } else if let Some(reason) = reason {
            *self
                .qpc_age_null_reasons
                .entry(reason.to_owned())
                .or_default() += 1;
        }
    }

    fn add_qpc_interval(&mut self, interval_ns: Option<u128>, reason: Option<&str>) {
        if let Some(interval_ns) = interval_ns {
            self.qpc_sample_interval_ns.push(interval_ns);
        } else if let Some(reason) = reason {
            *self
                .qpc_interval_null_reasons
                .entry(reason.to_owned())
                .or_default() += 1;
        }
    }

    fn note_valid_pressure(&mut self, pressure: u32) {
        self.valid_pressure_min = Some(
            self.valid_pressure_min
                .map_or(pressure, |v| v.min(pressure)),
        );
        self.valid_pressure_max = Some(
            self.valid_pressure_max
                .map_or(pressure, |v| v.max(pressure)),
        );
    }

    fn pressure_entropy_bits(&self) -> Option<f64> {
        if self.pressure_distribution_truncated {
            return None;
        }
        let sample_count = self.pressure_value_counts.values().copied().sum::<u64>();
        if sample_count == 0 {
            return None;
        }
        let entropy = self
            .pressure_value_counts
            .values()
            .map(|count| {
                let probability = *count as f64 / sample_count as f64;
                -probability * probability.log2()
            })
            .sum();
        Some(entropy)
    }

    fn qpc_age_percentile_ms(&mut self, percentile: usize) -> Option<f64> {
        if self.qpc_age_ns.is_empty() {
            return None;
        }
        self.qpc_age_ns.sort_unstable();
        let index = nearest_rank_index(self.qpc_age_ns.len(), percentile)?;
        Some(self.qpc_age_ns[index] as f64 / 1_000_000.0)
    }

    fn qpc_interval_percentile_ms(&mut self, percentile: usize) -> Option<f64> {
        if self.qpc_sample_interval_ns.is_empty() {
            return None;
        }
        self.qpc_sample_interval_ns.sort_unstable();
        let index = nearest_rank_index(self.qpc_sample_interval_ns.len(), percentile)?;
        Some(self.qpc_sample_interval_ns[index] as f64 / 1_000_000.0)
    }
}

/// Selects the discrete nearest-rank sample at ceil(n*p/100), with rank 1
/// returned for p=0 and the rank capped to the available sample count.
fn nearest_rank_index(sample_count: usize, percentile: usize) -> Option<usize> {
    if sample_count == 0 {
        return None;
    }
    let percentile = percentile.min(100);
    let rank = sample_count
        .saturating_mul(percentile)
        .div_ceil(100)
        .clamp(1, sample_count);
    Some(rank - 1)
}

#[derive(Clone, Copy, Debug)]
struct PressureRunState {
    value: u64,
    length: u64,
}

#[derive(Debug)]
pub(crate) struct SessionReadError {
    message: String,
}

impl Display for SessionReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SessionReadError {}

impl SessionReadError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy)]
struct DirectBatchMeta {
    sequence: u64,
    requested_pointer_id: u32,
    hook_qpc: Option<u64>,
    qpc_frequency_hz: Option<u64>,
}

struct DirectMetricTrackers<'a> {
    fingerprints: &'a mut HashSet<String>,
    last_qpc: &'a mut HashMap<MetricKey, u64>,
    pressure_runs: &'a mut HashMap<MetricKey, PressureRunState>,
}

#[derive(Clone, Copy)]
struct WintabBatchMeta {
    sequence: u64,
    context_raw: i64,
    device_raw: u32,
    packet_time_mode: WintabPacketTimeMode,
    uncertain: bool,
    quality_issue_observed: bool,
}

#[derive(Default)]
struct StrokeTracker {
    next_id: u64,
    active: HashMap<(String, u32), u64>,
    direct_batch_strokes: HashMap<(String, u32), u64>,
    direct_batch_close_keys: Vec<(String, u32)>,
    current_direct_kind: Option<PointerMessageKind>,
    public_active: HashMap<(String, u64), u64>,
}

impl StrokeTracker {
    fn invalidate_direct_pointer(&mut self, pointer_id: Option<u32>) {
        if let Some(pointer_id) = pointer_id {
            self.active.retain(|(_, id), _| *id != pointer_id);
            self.direct_batch_strokes
                .retain(|(_, id), _| *id != pointer_id);
            self.direct_batch_close_keys
                .retain(|(_, id)| *id != pointer_id);
        } else {
            self.active.clear();
            self.direct_batch_strokes.clear();
            self.direct_batch_close_keys.clear();
        }
        self.current_direct_kind = None;
    }

    fn invalidate_all(&mut self) {
        self.active.clear();
        self.direct_batch_strokes.clear();
        self.direct_batch_close_keys.clear();
        self.current_direct_kind = None;
        self.public_active.clear();
    }

    fn on_lifecycle(&mut self, kind: &str, pointer_id: Option<u32>) {
        match kind {
            "DirectPointerEnter" | "DirectPointerLeave" | "DirectPointerCaptureChanged" => {
                self.invalidate_direct_pointer(pointer_id);
            }
            "DirectPointerDeviceChanged"
            | "DirectPointerDeviceInRange"
            | "DirectPointerDeviceOutOfRange" => {
                self.invalidate_direct_pointer(None);
            }
            "WindowFocusGained"
            | "WindowFocusLost"
            | "WindowCloseRequested"
            | "InputDeviceAdded"
            | "InputDeviceRemoved" => self.invalidate_all(),
            _ => {}
        }
    }

    fn finish_direct_batch(&mut self) {
        if self.current_direct_kind == Some(PointerMessageKind::Up) {
            for key in self.direct_batch_close_keys.drain(..) {
                self.active.remove(&key);
            }
        } else {
            self.direct_batch_close_keys.clear();
        }
        self.direct_batch_strokes.clear();
        self.current_direct_kind = None;
    }

    fn begin_direct_batch(&mut self, kind: PointerMessageKind) {
        self.finish_direct_batch();
        self.current_direct_kind = Some(kind);
    }

    fn direct_stroke(&mut self, device: &str, pointer_id: u32, matches_requested: bool) -> String {
        if !matches_requested {
            return "unclassified-id-mismatch".to_owned();
        }
        let key = (device.to_owned(), pointer_id);
        if let Some(id) = self.direct_batch_strokes.get(&key) {
            return format!("observed-direct-stroke-{id}");
        }
        match self.current_direct_kind {
            Some(PointerMessageKind::Down) => {
                if self.active.len() >= MAX_TRACKED_STROKES
                    || self.direct_batch_strokes.len() >= MAX_TRACKED_STROKES
                {
                    return "unclassified-stroke-tracker-cap".to_owned();
                }
                self.next_id = self.next_id.saturating_add(1);
                self.active.insert(key.clone(), self.next_id);
                self.direct_batch_strokes.insert(key, self.next_id);
                format!("observed-direct-stroke-{}", self.next_id)
            }
            Some(PointerMessageKind::Up) => {
                if let Some(id) = self.active.get(&key).copied() {
                    if self.direct_batch_strokes.len() >= MAX_TRACKED_STROKES {
                        return "unclassified-stroke-tracker-cap".to_owned();
                    }
                    self.direct_batch_strokes.insert(key.clone(), id);
                    if self.direct_batch_close_keys.len() < MAX_TRACKED_STROKES {
                        self.direct_batch_close_keys.push(key);
                    }
                    format!("observed-direct-stroke-{id}")
                } else {
                    "unclassified-no-observed-down".to_owned()
                }
            }
            Some(PointerMessageKind::Update) => self.active.get(&key).copied().map_or_else(
                || "unclassified-no-observed-down".to_owned(),
                |id| format!("observed-direct-stroke-{id}"),
            ),
            None => "unclassified-no-batch".to_owned(),
        }
    }

    fn public_touch_stroke(&mut self, device: &str, touch_id: u64, phase: &str) -> String {
        let key = (device.to_owned(), touch_id);
        match phase {
            "Started" => {
                if self.public_active.len() >= MAX_TRACKED_STROKES {
                    return "unclassified-stroke-tracker-cap".to_owned();
                }
                self.next_id = self.next_id.saturating_add(1);
                self.public_active.insert(key, self.next_id);
                format!("observed-public-touch-stroke-{}", self.next_id)
            }
            "Moved" => self.public_active.get(&key).copied().map_or_else(
                || "unclassified-no-observed-start".to_owned(),
                |id| format!("observed-public-touch-stroke-{id}"),
            ),
            "Ended" | "Cancelled" => self.public_active.remove(&key).map_or_else(
                || "unclassified-no-observed-start".to_owned(),
                |id| format!("observed-public-touch-stroke-{id}"),
            ),
            _ => "unclassified-phase".to_owned(),
        }
    }
}

pub(crate) fn read_report(path: &Path) -> Result<SessionReport, SessionReadError> {
    let metadata = fs::metadata(path)
        .map_err(|error| SessionReadError::invalid(format!("cannot stat session file: {error}")))?;
    if metadata.len() > MAX_SESSION_BYTES {
        return Err(SessionReadError::invalid(format!(
            "session file exceeds the {MAX_SESSION_BYTES}-byte parser limit"
        )));
    }
    let file = File::open(path)
        .map_err(|error| SessionReadError::invalid(format!("cannot open session file: {error}")))?;
    let mut report = parse_session(file)?;
    if path.as_os_str().to_string_lossy().ends_with(".partial") {
        report.complete = false;
        report.capture_incomplete = true;
        report
            .warnings
            .push("file has a .partial suffix; session output did not finalize".to_owned());
    }
    if !report.complete && report.warnings.is_empty() {
        report
            .warnings
            .push("session footer is missing or marks capture incomplete".to_owned());
    }
    Ok(report)
}

pub(crate) fn parse_session(reader: impl Read) -> Result<SessionReport, SessionReadError> {
    parse_session_with_line_limit(reader, MAX_SESSION_LINES)
}

fn parse_session_with_line_limit(
    reader: impl Read,
    max_session_lines: u64,
) -> Result<SessionReport, SessionReadError> {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    let mut report = SessionReport::default();
    let mut line_number = 0u64;
    let mut event_record_count = 0u64;
    let mut total_session_bytes = 0u64;
    let mut saw_header = false;
    let mut saw_end = false;
    let mut saw_cpu = false;
    let mut direct_batch: Option<DirectBatchMeta> = None;
    let mut wintab_batch: Option<WintabBatchMeta> = None;
    let mut strokes = StrokeTracker::default();
    let mut direct_dispatches = HashSet::new();
    let mut fingerprints = HashSet::new();
    let mut last_direct_qpc: HashMap<MetricKey, u64> = HashMap::new();
    let mut direct_pressure_runs: HashMap<MetricKey, PressureRunState> = HashMap::new();

    loop {
        line.clear();
        let Some(line_complete) = read_bounded_line(&mut reader, &mut line)
            .map_err(|error| SessionReadError::invalid(format!("line read failed: {error}")))?
        else {
            break;
        };
        total_session_bytes = total_session_bytes.saturating_add(line.len() as u64);
        if total_session_bytes > MAX_SESSION_BYTES {
            return Err(SessionReadError::invalid(format!(
                "session exceeds the {MAX_SESSION_BYTES}-byte parser limit"
            )));
        }
        if !line_complete {
            if saw_end {
                return Err(SessionReadError::invalid(
                    "trailing data appears after the END footer",
                ));
            }
            report.complete = false;
            report.capture_incomplete = true;
            report
                .warnings
                .push("truncated final line discarded; session is partial".to_owned());
            break;
        }
        line_number = line_number.saturating_add(1);
        if line_number > max_session_lines {
            return Err(SessionReadError::invalid(format!(
                "session exceeds the {max_session_lines}-line parser limit"
            )));
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| SessionReadError::invalid(format!("line {line_number} is not UTF-8")))?;
        let fields = text.split('\t').collect::<Vec<_>>();
        let tag = *fields
            .first()
            .ok_or_else(|| SessionReadError::invalid(format!("line {line_number} is empty")))?;
        if saw_end {
            return Err(SessionReadError::invalid(format!(
                "record appears after the END footer on line {line_number}"
            )));
        }

        if tag != "D_SAMPLE" && direct_batch.is_some() {
            strokes.finish_direct_batch();
            direct_batch = None;
        }
        if tag != "W_PACKET" && wintab_batch.is_some() {
            wintab_batch = None;
        }

        if !saw_header {
            if tag != "LASSOINK-SESSION" || fields.len() != 2 {
                return Err(SessionReadError::invalid(
                    "first line is not a LASSOINK-SESSION header",
                ));
            }
            let version = parse_u32(fields[1], line_number, "schema version")?;
            if !matches!(version, 1 | SESSION_SCHEMA_VERSION) {
                return Err(SessionReadError::invalid(format!(
                    "unsupported session schema version {version}"
                )));
            }
            report.schema_version = Some(version);
            saw_header = true;
            continue;
        }
        report.parsed_rows = report.parsed_rows.saturating_add(1);
        if matches!(
            tag,
            "STARTUP"
                | "D_BATCH"
                | "PUBLIC"
                | "EVENT"
                | "W_BATCH"
                | "CONTROL"
                | "W_ISSUE"
                | "IGNORED"
                | "M_ISSUE"
        ) {
            event_record_count = event_record_count.saturating_add(1);
            if event_record_count > 4096 {
                return Err(SessionReadError::invalid(
                    "event/error record rows exceed the session retention cap",
                ));
            }
        }

        match tag {
            "META" => {
                require_fields(&fields, 3, line_number)?;
                let key = decode_field(fields[1], line_number)?;
                let value = decode_field(fields[2], line_number)?;
                if key.len() > 256 || value.len() > MAX_SESSION_METADATA_TEXT_BYTES {
                    return Err(SessionReadError::invalid(format!(
                        "metadata field on line {line_number} exceeds the bounded text size"
                    )));
                }
                if !report.metadata.contains_key(&key)
                    && report.metadata.len() >= MAX_SESSION_METADATA_ENTRIES
                {
                    return Err(SessionReadError::invalid(
                        "session metadata exceeds the bounded entry count",
                    ));
                }
                report.metadata.insert(key, value);
            }
            "D_BATCH" => {
                require_fields(&fields, 13, line_number)?;
                strokes.begin_direct_batch(parse_pointer_kind(fields[5], line_number)?);
                direct_batch = Some(DirectBatchMeta {
                    sequence: parse_u64(fields[1], line_number, "direct batch sequence")?,
                    requested_pointer_id: parse_u32(
                        fields[6],
                        line_number,
                        "requested pointer ID",
                    )?,
                    hook_qpc: parse_option_u64(fields[8], line_number, "hook QPC")?,
                    qpc_frequency_hz: parse_option_u64(fields[10], line_number, "QPC frequency")?,
                });
                report.direct_batches = report.direct_batches.saturating_add(1);
                direct_dispatches.insert(parse_u64(fields[1], line_number, "direct sequence")?);
            }
            "D_SAMPLE" => {
                require_fields(&fields, 34, line_number)?;
                report.raw_direct_samples = report.raw_direct_samples.saturating_add(1);
                if report.raw_direct_samples > 131_072 {
                    return Err(SessionReadError::invalid(
                        "direct sample rows exceed the session retention cap",
                    ));
                }
                let batch = direct_batch.ok_or_else(|| {
                    SessionReadError::invalid(format!(
                        "direct sample on line {line_number} has no preceding batch"
                    ))
                })?;
                let batch_sequence = parse_u64(fields[1], line_number, "batch sequence")?;
                if batch.sequence != batch_sequence {
                    return Err(SessionReadError::invalid(format!(
                        "direct sample on line {line_number} references a different batch"
                    )));
                }
                update_direct_metrics(
                    &mut report,
                    &mut strokes,
                    &mut DirectMetricTrackers {
                        fingerprints: &mut fingerprints,
                        last_qpc: &mut last_direct_qpc,
                        pressure_runs: &mut direct_pressure_runs,
                    },
                    batch,
                    &fields,
                    line_number,
                )?;
            }
            "W_BATCH" => {
                let schema_version = report.schema_version.unwrap_or(1);
                let quality_issue_observed = if schema_version >= 2 {
                    require_fields(&fields, 18, line_number)?;
                    parse_bool(fields[16], line_number, "Wintab batch quality issue")?
                } else {
                    require_fields(&fields, 17, line_number)?;
                    false
                };
                wintab_batch = Some(WintabBatchMeta {
                    sequence: parse_u64(fields[1], line_number, "Wintab batch sequence")?,
                    context_raw: parse_i64(fields[7], line_number, "Wintab context")?,
                    device_raw: parse_u32(fields[10], line_number, "Wintab device selector")?,
                    packet_time_mode: parse_wintab_time_mode(fields[13], line_number)?,
                    uncertain: parse_bool(fields[15], line_number, "Wintab uncertainty")?,
                    quality_issue_observed,
                });
            }
            "W_PACKET" => {
                require_fields(&fields, 11, line_number)?;
                report.raw_wintab_packets = report.raw_wintab_packets.saturating_add(1);
                if report.raw_direct_samples + report.raw_wintab_packets > 131_072 {
                    return Err(SessionReadError::invalid(
                        "sample rows exceed the session retention cap",
                    ));
                }
                let batch = wintab_batch.ok_or_else(|| {
                    SessionReadError::invalid(format!(
                        "Wintab packet on line {line_number} has no preceding batch"
                    ))
                })?;
                if parse_u64(fields[1], line_number, "Wintab packet batch")? != batch.sequence {
                    return Err(SessionReadError::invalid(format!(
                        "Wintab packet on line {line_number} references a different batch"
                    )));
                }
                update_wintab_metrics(&mut report, &mut fingerprints, batch, &fields, line_number)?;
            }
            "PUBLIC" => update_public_metrics(
                &mut report,
                &mut strokes,
                &direct_dispatches,
                &fields,
                line_number,
            )?,
            "EVENT" => {
                require_fields(&fields, 16, line_number)?;
                report.lifecycle_events = report.lifecycle_events.saturating_add(1);
                let event_pointer_id =
                    parse_option_u64(fields[9], line_number, "lifecycle pointer ID")?
                        .and_then(|value| u32::try_from(value).ok());
                strokes.on_lifecycle(fields[2], event_pointer_id);
                if matches!(fields[2], "WindowInitializationFailed" | "EventLoopFailed") {
                    report.capture_incomplete = true;
                }
                if !fields[15].is_empty() {
                    report.issue_records = report.issue_records.saturating_add(1);
                }
            }
            "STARTUP" => {
                require_fields(&fields, 2, line_number)?;
                report.issue_records = report.issue_records.saturating_add(1);
            }
            "W_ISSUE" => {
                require_fields(&fields, 10, line_number)?;
                report.issue_records = report.issue_records.saturating_add(1);
            }
            "M_ISSUE" => {
                require_fields(&fields, 12, line_number)?;
                report.issue_records = report.issue_records.saturating_add(1);
            }
            "CONTROL" => {
                require_fields(&fields, 8, line_number)?;
                report.wintab_control_notifications =
                    report.wintab_control_notifications.saturating_add(1);
            }
            "CPU" => {
                if report.schema_version.unwrap_or(1) < 2 {
                    return Err(SessionReadError::invalid(
                        "CPU rows require schema version 2",
                    ));
                }
                require_fields(&fields, 18, line_number)?;
                if saw_cpu {
                    return Err(SessionReadError::invalid(
                        "session contains more than one CPU measurement row",
                    ));
                }
                let parse_words =
                    |low: &str,
                     high: &str,
                     label: &str|
                     -> Result<Option<FileTimeWords>, SessionReadError> {
                        match (low.is_empty(), high.is_empty()) {
                            (true, true) => Ok(None),
                            (false, false) => Ok(Some(FileTimeWords {
                                low: parse_u32(low, line_number, &format!("{label} FILETIME low"))?,
                                high: parse_u32(
                                    high,
                                    line_number,
                                    &format!("{label} FILETIME high"),
                                )?,
                            })),
                            _ => Err(SessionReadError::invalid(format!(
                                "line {line_number} has a partial {label} FILETIME"
                            ))),
                        }
                    };
                let start = ProcessCpuSnapshot {
                    app_elapsed_ns: parse_u128(fields[1], line_number, "CPU start app arrival")?,
                    user: parse_words(fields[4], fields[5], "start user")?,
                    kernel: parse_words(fields[6], fields[7], "start kernel")?,
                    win32_error: parse_option_u32(fields[16], line_number, "start CPU error")?,
                };
                let end = ProcessCpuSnapshot {
                    app_elapsed_ns: parse_u128(fields[2], line_number, "CPU end app arrival")?,
                    user: parse_words(fields[8], fields[9], "end user")?,
                    kernel: parse_words(fields[10], fields[11], "end kernel")?,
                    win32_error: parse_option_u32(fields[17], line_number, "end CPU error")?,
                };
                if start.win32_error.is_some() && (start.user.is_some() || start.kernel.is_some())
                    || end.win32_error.is_some() && (end.user.is_some() || end.kernel.is_some())
                {
                    return Err(SessionReadError::invalid(format!(
                        "line {line_number} has FILETIME values attached to a failed CPU snapshot"
                    )));
                }
                let cached_app_interval_ns =
                    parse_option_u128(fields[3], line_number, "CPU app interval")?;
                let cached_user_delta_100ns =
                    parse_option_u128(fields[12], line_number, "CPU user delta")?;
                let cached_kernel_delta_100ns =
                    parse_option_u128(fields[13], line_number, "CPU kernel delta")?;
                let cached_core_equivalent_percent = if fields[14].is_empty() {
                    None
                } else {
                    let bits = u64::from_str_radix(fields[14], 16).map_err(|_| {
                        SessionReadError::invalid(format!(
                            "line {line_number} has an invalid CPU ratio bit pattern"
                        ))
                    })?;
                    let value = f64::from_bits(bits);
                    if !value.is_finite() || value < 0.0 {
                        return Err(SessionReadError::invalid(format!(
                            "line {line_number} has a non-finite or negative CPU ratio"
                        )));
                    }
                    Some(value)
                };
                let measured = crate::process_cpu::measure(start, end);
                let expected_reason = measured
                    .unavailable_reason
                    .as_ref()
                    .map(cpu_unavailable_reason_label)
                    .unwrap_or_default();
                if cached_app_interval_ns != measured.app_interval_ns
                    || cached_user_delta_100ns != measured.user_delta_100ns
                    || cached_kernel_delta_100ns != measured.kernel_delta_100ns
                    || cached_core_equivalent_percent.map(f64::to_bits)
                        != measured.core_equivalent_percent.map(f64::to_bits)
                    || fields[15] != expected_reason
                {
                    return Err(SessionReadError::invalid(format!(
                        "line {line_number} cached CPU metrics disagree with raw FILETIME snapshots and app-arrival times"
                    )));
                }
                report.process_cpu = Some(measured);
                saw_cpu = true;
            }
            "IGNORED" => {
                require_fields(&fields, 12, line_number)?;
                report.ignored_non_pen_events = report.ignored_non_pen_events.saturating_add(1);
            }
            "END" => {
                require_fields(&fields, 21, line_number)?;
                report.complete = fields[1] == "finalized";
                if report.complete && report.schema_version.unwrap_or(1) >= 2 && !saw_cpu {
                    report.complete = false;
                    report.capture_incomplete = true;
                    report.warnings.push(
                        "schema 2 finalized session is missing its CPU measurement row".to_owned(),
                    );
                }
                report.wintab_status = Some(fields[12].to_owned());
                report.pointer_api_available = Some(parse_bool(
                    fields[13],
                    line_number,
                    "pointer API availability",
                )?);
                report.capture_mode = Some(fields[14].to_owned());
                report.latest_startup_issue = nonempty_decoded(fields[15], line_number)?;
                report.latest_wintab_issue = nonempty_decoded(fields[16], line_number)?;
                report.latest_incomplete_issue = nonempty_decoded(fields[17], line_number)?;
                report.records_not_retained =
                    parse_u64(fields[18], line_number, "omitted record count")?;
                report.batches_not_retained =
                    parse_u64(fields[19], line_number, "omitted batch count")?;
                report.samples_not_retained =
                    parse_u64(fields[20], line_number, "omitted sample count")?;
                let footer_records = parse_u64(fields[3], line_number, "retained record count")?;
                let footer_samples = parse_u64(fields[4], line_number, "retained sample count")?;
                if footer_records != event_record_count {
                    report.capture_incomplete = true;
                    report.warnings.push(format!(
                        "footer says {footer_records} event records but the file contains {event_record_count}"
                    ));
                }
                let parsed_samples = report.raw_direct_samples + report.raw_wintab_packets;
                if footer_samples != parsed_samples {
                    report.capture_incomplete = true;
                    report.warnings.push(format!(
                        "footer says {footer_samples} native samples but the file contains {parsed_samples}"
                    ));
                }
                let incomplete_batches = parse_u64(fields[11], line_number, "incomplete batches")?;
                report.capture_incomplete |= !fields[10].is_empty()
                    || incomplete_batches > 0
                    || matches!(fields[12], "Unavailable" | "Partial")
                    || (fields[14] == "DirectWmPointer" && fields[13] == "false")
                    || report.latest_incomplete_issue.is_some();
                saw_end = true;
            }
            _ => {
                return Err(SessionReadError::invalid(format!(
                    "unknown record tag {tag:?} on line {line_number}"
                )));
            }
        }
    }

    if !saw_header {
        return Err(SessionReadError::invalid("session file is empty"));
    }
    if !saw_end {
        report.complete = false;
        report.capture_incomplete = true;
        report
            .warnings
            .push("session footer is missing; the file may be partial".to_owned());
    }
    if report.metric_partition_overflow > 0 {
        report.warnings.push(format!(
            "metric partition cap reached; {} additional partition key(s) were counted and not retained{}",
            report.metric_partition_overflow,
            if report.overflow_partition_count_truncated {
                " (additional-key count itself was capped)"
            } else {
                ""
            }
        ));
    }
    if report.duplicate_fingerprint_cap_reached {
        report.warnings.push(
            "exact-duplicate fingerprint cap reached; later duplicate counts are incomplete"
                .to_owned(),
        );
    }
    if report.pressure_distribution_cap_reached {
        report.warnings.push(
            "pressure value distribution cap reached; raw rows remain intact and retained histograms are partial".to_owned(),
        );
    }
    if report.pressure_run_tracker_cap_reached {
        report.warnings.push(
            "pressure repeat-run tracker cap reached; later run statistics are incomplete"
                .to_owned(),
        );
    }
    Ok(report)
}

fn update_direct_metrics(
    report: &mut SessionReport,
    strokes: &mut StrokeTracker,
    trackers: &mut DirectMetricTrackers<'_>,
    batch: DirectBatchMeta,
    fields: &[&str],
    line_number: u64,
) -> Result<(), SessionReadError> {
    let matches_requested = parse_bool(fields[4], line_number, "pointer attribution")?;
    let pointer_type = parse_i32(fields[5], line_number, "pointer type")?;
    let pointer_id = parse_u32(fields[6], line_number, "pointer ID")?;
    let _frame_id = parse_u32(fields[7], line_number, "frame ID")?;
    let device_raw = parse_i64(fields[8], line_number, "sourceDevice")?;
    let device = device_raw.to_string();
    let _pixel_x = parse_i32(fields[14], line_number, "pixel x")?;
    let _pixel_y = parse_i32(fields[15], line_number, "pixel y")?;
    let qpc = parse_u64(fields[19], line_number, "PerformanceCount")?;
    let _dw_time = parse_u32(fields[20], line_number, "dwTime")?;
    let pen_mask = parse_u32(fields[25], line_number, "pen mask")?;
    let pressure = parse_u32(fields[26], line_number, "pressure")?;
    let validation_count = parse_u64(fields[32], line_number, "validation issue count")?;
    let id_matches = matches_requested && pointer_id == batch.requested_pointer_id;
    let valid = pointer_type == PT_PEN
        && id_matches
        && pen_mask & PEN_MASK_PRESSURE != 0
        && pressure <= 1024;
    let anomaly = validation_count > 0
        || pointer_type != PT_PEN
        || !id_matches
        || pen_mask & PEN_MASK_PRESSURE == 0
        || pressure > 1024
        || pen_mask & (PEN_MASK_TILT_X | PEN_MASK_TILT_Y) != 0;
    let pressure_validity = fields[27];
    if anomaly {
        report.validation_anomaly_samples = report.validation_anomaly_samples.saturating_add(1);
    }
    report.validation_issue_count = report
        .validation_issue_count
        .saturating_add(validation_count);
    if pressure_validity == "NotReported" || pen_mask & PEN_MASK_PRESSURE == 0 {
        report.pressure_mask_missing_samples =
            report.pressure_mask_missing_samples.saturating_add(1);
    }
    if pressure_validity == "OutOfRange" || pressure > 1024 {
        report.pressure_out_of_range_samples =
            report.pressure_out_of_range_samples.saturating_add(1);
    }
    if !id_matches {
        report.pointer_id_mismatch_samples = report.pointer_id_mismatch_samples.saturating_add(1);
    }
    if pointer_type != PT_PEN {
        report.unexpected_pointer_type_samples =
            report.unexpected_pointer_type_samples.saturating_add(1);
    }
    if pen_mask & (PEN_MASK_TILT_X | PEN_MASK_TILT_Y) != 0
        || fields[33].contains("UnexpectedTiltMask")
    {
        report.unexpected_tilt_mask_samples = report.unexpected_tilt_mask_samples.saturating_add(1);
    }
    if valid {
        report.valid_direct_pen_samples = report.valid_direct_pen_samples.saturating_add(1);
    } else {
        report.invalid_direct_pen_samples = report.invalid_direct_pen_samples.saturating_add(1);
    }

    let stroke = strokes.direct_stroke(&device, pointer_id, id_matches);
    let clock = batch.qpc_frequency_hz.map_or_else(
        || "POINTER_INFO.PerformanceCount/QPC;frequency=unknown".to_owned(),
        |frequency| format!("POINTER_INFO.PerformanceCount/QPC;frequency={frequency}Hz"),
    );
    let key = MetricKey {
        api: "direct-wm-pointer".to_owned(),
        device: format!("sourceDevice:{device}"),
        pointer: format!("pointerId:{pointer_id}"),
        stroke,
        native_clock: clock,
        pressure_representation: "POINTER_INFO.pressure raw u32; valid mask range 0..1024"
            .to_owned(),
    };
    let fingerprint = format!("D|{}", fields[5..32].join("|"));
    let duplicate = note_fingerprint(report, trackers.fingerprints, fingerprint);
    let stroke_is_classified = key.stroke.starts_with("observed-direct-stroke-");
    let partition_tracking_available =
        report.partitions.contains_key(&key) || report.partitions.len() < MAX_REPORT_PARTITIONS;
    let qpc_tracking_available =
        trackers.last_qpc.contains_key(&key) || trackers.last_qpc.len() < MAX_REPORT_PARTITIONS;
    let qpc_tracking_enabled = valid
        && stroke_is_classified
        && !duplicate
        && partition_tracking_available
        && qpc_tracking_available;
    let previous_qpc = if qpc_tracking_enabled {
        trackers.last_qpc.insert(key.clone(), qpc)
    } else {
        if !valid {
            trackers.last_qpc.remove(&key);
            trackers.pressure_runs.remove(&key);
        }
        None
    };
    let (qpc_interval_ns, interval_null_reason, clock_regressed) = if duplicate {
        (None, Some("duplicate_raw_fingerprint"), false)
    } else if !valid {
        (None, Some("invalid_direct_pen_candidate"), false)
    } else if !stroke_is_classified {
        (None, Some("stroke_unclassified"), false)
    } else if !partition_tracking_available || !qpc_tracking_available {
        (None, Some("metric_partition_cap"), false)
    } else {
        match (previous_qpc, batch.qpc_frequency_hz) {
            (_, None | Some(0)) => (None, Some("qpc_frequency_unavailable"), false),
            (None, Some(_)) => (None, Some("first_sample_in_stroke"), false),
            (Some(previous), Some(frequency)) if qpc >= previous => {
                let delta = u128::from(qpc - previous);
                (
                    Some(delta.saturating_mul(1_000_000_000) / u128::from(frequency)),
                    None,
                    false,
                )
            }
            (Some(_), Some(_)) => (None, Some("native_qpc_regressed"), true),
        }
    };
    if clock_regressed {
        report.native_clock_regressions = report.native_clock_regressions.saturating_add(1);
    }
    if qpc_interval_ns.is_some() {
        report.qpc_native_interval_samples = report.qpc_native_interval_samples.saturating_add(1);
    } else if let Some(reason) = interval_null_reason {
        *report
            .qpc_interval_null_reasons
            .entry(reason.to_owned())
            .or_default() += 1;
    }
    let (age, null_reason) = if !valid {
        (None, Some("invalid_direct_pen_candidate"))
    } else {
        match (batch.hook_qpc, batch.qpc_frequency_hz) {
            (None, _) => (None, Some("hook_qpc_unavailable")),
            (_, None | Some(0)) => (None, Some("qpc_frequency_unavailable")),
            (Some(hook), Some(frequency)) if hook >= qpc => {
                let delta = u128::from(hook - qpc);
                (
                    Some(delta.saturating_mul(1_000_000_000) / u128::from(frequency)),
                    None,
                )
            }
            (Some(_), Some(_)) => (None, Some("hook_qpc_precedes_performance_count")),
        }
    };
    if age.is_some() {
        report.qpc_message_to_hook_age_samples =
            report.qpc_message_to_hook_age_samples.saturating_add(1);
    } else if let Some(reason) = null_reason {
        *report
            .qpc_age_null_reasons
            .entry(reason.to_owned())
            .or_default() += 1;
    }
    if let Some(bucket) = bucket_mut(report, key.clone()) {
        bucket.raw_rows = bucket.raw_rows.saturating_add(1);
        if valid {
            bucket.valid_direct_pen_samples = bucket.valid_direct_pen_samples.saturating_add(1);
            if !duplicate {
                bucket.note_valid_pressure(pressure);
            }
        } else {
            bucket.invalid_direct_pen_samples = bucket.invalid_direct_pen_samples.saturating_add(1);
        }
        if anomaly {
            bucket.anomaly_samples = bucket.anomaly_samples.saturating_add(1);
        }
        if duplicate {
            bucket.exact_raw_duplicate_fingerprints =
                bucket.exact_raw_duplicate_fingerprints.saturating_add(1);
        }
        if clock_regressed {
            bucket.native_clock_regressions = bucket.native_clock_regressions.saturating_add(1);
        }
        bucket.add_qpc_interval(qpc_interval_ns, interval_null_reason);
        bucket.add_qpc_age(age, null_reason);
    }
    if valid && !duplicate {
        record_pressure_value(
            report,
            &key,
            u64::from(pressure),
            Some(trackers.pressure_runs),
            stroke_is_classified,
        );
    } else if duplicate || !valid {
        let reason = if duplicate {
            "duplicate_raw_fingerprint"
        } else {
            "invalid_direct_pen_candidate"
        };
        *report
            .pressure_null_reasons
            .entry(reason.to_owned())
            .or_default() += 1;
    }
    Ok(())
}

fn update_wintab_metrics(
    report: &mut SessionReport,
    fingerprints: &mut HashSet<String>,
    batch: WintabBatchMeta,
    fields: &[&str],
    line_number: u64,
) -> Result<(), SessionReadError> {
    let context = parse_i64(fields[2], line_number, "packet context")?;
    let context_mismatch = context != batch.context_raw;
    if context_mismatch {
        report.wintab_context_mismatch_packets =
            report.wintab_context_mismatch_packets.saturating_add(1);
    }
    let status = parse_u32(fields[3], line_number, "packet status")?;
    let packet_time = parse_u32(fields[4], line_number, "pkTime")?;
    let serial = parse_u32(fields[5], line_number, "packet serial")?;
    let cursor = parse_u32(fields[6], line_number, "Wintab cursor")?;
    let x = parse_i32(fields[8], line_number, "Wintab x")?;
    let y = parse_i32(fields[9], line_number, "Wintab y")?;
    let pressure = parse_u32(fields[10], line_number, "Wintab pressure")?;
    let key = MetricKey {
        api: "wintab".to_owned(),
        device: format!("Wintab lcDevice:{}", batch.device_raw),
        pointer: format!("cursor:{cursor}"),
        stroke: "unclassified-wintab-stroke".to_owned(),
        native_clock: format!("Wintab pkTime {:?};raw-u32", batch.packet_time_mode),
        pressure_representation:
            "Wintab NORMAL_PRESSURE raw u32; uncalibrated; driver range unknown".to_owned(),
    };
    let fingerprint =
        format!("W|{context}|{status}|{packet_time}|{serial}|{cursor}|{x}|{y}|{pressure}");
    let duplicate = note_fingerprint(report, fingerprints, fingerprint);
    let pressure_valid = !batch.uncertain
        && !batch.quality_issue_observed
        && !context_mismatch
        && status & WINTAB_TPS_QUEUE_ERR == 0
        && !duplicate;
    if !pressure_valid {
        report.unqualified_wintab_pressure_rows =
            report.unqualified_wintab_pressure_rows.saturating_add(1);
        let reason = if duplicate {
            "duplicate_raw_fingerprint"
        } else if batch.uncertain {
            "wintab_control_transition_during_read"
        } else if batch.quality_issue_observed {
            "wintab_packet_quality_issue"
        } else if context_mismatch {
            "wintab_context_mismatch"
        } else if status & WINTAB_TPS_QUEUE_ERR != 0 {
            "wintab_queue_error_status"
        } else {
            "wintab_pressure_unqualified"
        };
        *report
            .pressure_null_reasons
            .entry(reason.to_owned())
            .or_default() += 1;
    }
    if batch.uncertain {
        report.uncertain_wintab_packets = report.uncertain_wintab_packets.saturating_add(1);
    } else {
        report.uninterrupted_wintab_packets = report.uninterrupted_wintab_packets.saturating_add(1);
    }
    *report
        .qpc_age_null_reasons
        .entry("wintab_clock_not_compared_to_qpc".to_owned())
        .or_default() += 1;
    if let Some(bucket) = bucket_mut(report, key.clone()) {
        bucket.raw_rows = bucket.raw_rows.saturating_add(1);
        if batch.uncertain {
            bucket.uncertain_wintab_packets = bucket.uncertain_wintab_packets.saturating_add(1);
        } else {
            bucket.uninterrupted_wintab_packets =
                bucket.uninterrupted_wintab_packets.saturating_add(1);
        }
        if duplicate {
            bucket.exact_raw_duplicate_fingerprints =
                bucket.exact_raw_duplicate_fingerprints.saturating_add(1);
        }
        bucket.add_qpc_age(None, Some("wintab_clock_not_compared_to_qpc"));
    }
    if pressure_valid {
        record_pressure_value(report, &key, u64::from(pressure), None, false);
    }
    Ok(())
}

fn record_pressure_value(
    report: &mut SessionReport,
    key: &MetricKey,
    value: u64,
    run_states: Option<&mut HashMap<MetricKey, PressureRunState>>,
    track_runs: bool,
) {
    let global_value_capacity =
        report.pressure_distribution_value_entries < MAX_PRESSURE_DISTRIBUTION_ENTRIES as u64;
    let mut inserted_new_value = false;
    let mut skipped_new_value = false;
    let mut run_cap_reached = false;
    if let Some(bucket) = bucket_mut(report, key.clone()) {
        bucket.pressure_metric_samples = bucket.pressure_metric_samples.saturating_add(1);
        if let Some(count) = bucket.pressure_value_counts.get_mut(&value) {
            *count = count.saturating_add(1);
        } else if bucket.pressure_value_counts.len() < MAX_PRESSURE_VALUES_PER_PARTITION
            && global_value_capacity
        {
            bucket.pressure_value_counts.insert(value, 1);
            inserted_new_value = true;
        } else {
            bucket.pressure_distribution_truncated = true;
            skipped_new_value = true;
        }

        if track_runs && let Some(states) = run_states {
            if let Some(previous) = states.get_mut(key) {
                if previous.value == value {
                    previous.length = previous.length.saturating_add(1);
                    bucket.pressure_repeated_values =
                        bucket.pressure_repeated_values.saturating_add(1);
                    if previous.length == 2 {
                        bucket.pressure_plateau_runs =
                            bucket.pressure_plateau_runs.saturating_add(1);
                    }
                    bucket.pressure_max_run_length =
                        bucket.pressure_max_run_length.max(previous.length);
                } else {
                    previous.value = value;
                    previous.length = 1;
                    bucket.pressure_transitions = bucket.pressure_transitions.saturating_add(1);
                }
            } else if states.len() < MAX_REPORT_PARTITIONS {
                states.insert(key.clone(), PressureRunState { value, length: 1 });
                bucket.pressure_max_run_length = bucket.pressure_max_run_length.max(1);
            } else {
                run_cap_reached = true;
            }
        }
    }
    if inserted_new_value {
        report.pressure_distribution_value_entries =
            report.pressure_distribution_value_entries.saturating_add(1);
    }
    if skipped_new_value {
        report.pressure_distribution_cap_reached = true;
    }
    if run_cap_reached {
        report.pressure_run_tracker_cap_reached = true;
    }
}

fn update_public_metrics(
    report: &mut SessionReport,
    strokes: &mut StrokeTracker,
    direct_dispatches: &HashSet<u64>,
    fields: &[&str],
    line_number: u64,
) -> Result<(), SessionReadError> {
    require_fields(fields, 25, line_number)?;
    report.public_events = report.public_events.saturating_add(1);
    let event_kind = fields[10];
    let device = decode_field(fields[11], line_number)?;
    if device.len() > 512 {
        return Err(SessionReadError::invalid(format!(
            "public Winit device ID on line {line_number} exceeds the metric-key limit"
        )));
    }
    let mut pointer = "none".to_owned();
    let mut stroke = "unclassified-no-public-stroke".to_owned();
    let mut confirmed_pen = false;
    let mut pressure_representation = "Winit Force absent or not applicable".to_owned();
    let mut public_force_value = None;
    if event_kind == "Touch" {
        report.public_touch_events = report.public_touch_events.saturating_add(1);
        let touch_id = parse_u64(fields[12], line_number, "public Touch ID")?;
        let phase = decode_field(fields[13], line_number)?;
        let public_pen_classification = decode_field(fields[22], line_number)?;
        pointer = format!("public-touch-id:{touch_id}");
        stroke = strokes.public_touch_stroke(&device, touch_id, &phase);
        confirmed_pen = public_pen_classification == "ConfirmedPen";
        if confirmed_pen {
            report.confirmed_public_pen_events =
                report.confirmed_public_pen_events.saturating_add(1);
        }
        pressure_representation =
            format!("Winit Touch Force classification={public_pen_classification}; force absent");
        match fields[16] {
            "Normalized" => {
                let bits = parse_hex_u64(fields[17], line_number, "normalized public force")?;
                let value = f64::from_bits(bits);
                pressure_representation = format!(
                    "Winit Force::Normalized raw f64 bits; classification={public_pen_classification}"
                );
                if value.is_finite() {
                    public_force_value = Some(bits);
                } else {
                    *report
                        .pressure_null_reasons
                        .entry("public_force_nonfinite".to_owned())
                        .or_default() += 1;
                }
            }
            "Calibrated" => {
                let bits = parse_hex_u64(fields[17], line_number, "calibrated public force")?;
                let max_bits =
                    parse_hex_u64(fields[18], line_number, "calibrated public force maximum")?;
                let value = f64::from_bits(bits);
                let maximum = f64::from_bits(max_bits);
                pressure_representation = format!(
                    "Winit Force::Calibrated raw f64 bits; maximum bits {max_bits:016X}; classification={public_pen_classification}"
                );
                if value.is_finite() && maximum.is_finite() && maximum > 0.0 {
                    public_force_value = Some(bits);
                } else {
                    *report
                        .pressure_null_reasons
                        .entry("public_force_calibration_unusable".to_owned())
                        .or_default() += 1;
                }
            }
            "None" | "" => {
                *report
                    .pressure_null_reasons
                    .entry("public_force_absent".to_owned())
                    .or_default() += 1;
            }
            other => {
                return Err(SessionReadError::invalid(format!(
                    "line {line_number} has an unknown public force representation {other:?}"
                )));
            }
        }
    }
    if let Some(associated_sequence) =
        parse_option_u64(fields[6], line_number, "association sequence")?
        && direct_dispatches.contains(&associated_sequence)
    {
        report.direct_public_dispatch_overlaps =
            report.direct_public_dispatch_overlaps.saturating_add(1);
    }
    let key = MetricKey {
        api: "public-winit".to_owned(),
        device: format!("Winit DeviceId:{device}"),
        pointer,
        stroke,
        native_clock: "none;Winit native timestamp null".to_owned(),
        pressure_representation,
    };
    *report
        .qpc_age_null_reasons
        .entry("public_native_timestamp_absent".to_owned())
        .or_default() += 1;
    if let Some(bucket) = bucket_mut(report, key.clone()) {
        bucket.raw_rows = bucket.raw_rows.saturating_add(1);
        bucket.public_events = bucket.public_events.saturating_add(1);
        if confirmed_pen {
            bucket.confirmed_public_pen_events =
                bucket.confirmed_public_pen_events.saturating_add(1);
        }
        bucket.add_qpc_age(None, Some("public_native_timestamp_absent"));
    }
    if let Some(value) = public_force_value {
        record_pressure_value(report, &key, value, None, false);
    }
    Ok(())
}

fn bucket_mut(report: &mut SessionReport, key: MetricKey) -> Option<&mut MetricBucket> {
    if !report.partitions.contains_key(&key) {
        if report.partitions.len() >= MAX_REPORT_PARTITIONS {
            if report.overflowed_metric_partitions.contains(&key) {
                return None;
            }
            if report.overflowed_metric_partitions.len() < MAX_REPORT_PARTITIONS {
                report.overflowed_metric_partitions.insert(key);
                report.metric_partition_overflow =
                    report.metric_partition_overflow.saturating_add(1);
            } else {
                report.overflow_partition_count_truncated = true;
            }
            return None;
        }
        report
            .partitions
            .insert(key.clone(), MetricBucket::default());
    }
    report.partitions.get_mut(&key)
}

fn note_fingerprint(
    report: &mut SessionReport,
    fingerprints: &mut HashSet<String>,
    fingerprint: String,
) -> bool {
    if fingerprints.contains(&fingerprint) {
        report.exact_raw_duplicate_fingerprints =
            report.exact_raw_duplicate_fingerprints.saturating_add(1);
        return true;
    }
    if fingerprints.len() >= MAX_REPORT_FINGERPRINTS {
        report.duplicate_fingerprint_cap_reached = true;
        return false;
    }
    fingerprints.insert(fingerprint);
    false
}

impl SessionReport {
    pub(crate) fn format_text(&mut self) -> String {
        let mut output = String::new();
        use fmt::Write as _;
        writeln!(
            output,
            "LassoInk capture session report (schema {})",
            self.schema_version.unwrap_or(0)
        )
        .ok();
        writeln!(output, "Session file finalized: {}", self.complete).ok();
        writeln!(output, "Capture incomplete: {}", self.capture_incomplete).ok();
        writeln!(output, "Capture mode: {:?}", self.capture_mode).ok();
        writeln!(
            output,
            "Pointer APIs available: {:?}",
            self.pointer_api_available
        )
        .ok();
        writeln!(output, "Wintab status: {:?}", self.wintab_status).ok();
        writeln!(
            output,
            "Latest startup issue: {:?}",
            self.latest_startup_issue
        )
        .ok();
        writeln!(
            output,
            "Latest Wintab issue: {:?}",
            self.latest_wintab_issue
        )
        .ok();
        writeln!(
            output,
            "Latest incomplete issue: {:?}",
            self.latest_incomplete_issue
        )
        .ok();
        for key in [
            "session_id",
            "capture_mode",
            "trial_id",
            "windows_ink_state_declared",
            "tablet_profile_declared",
            "device_model_declared",
            "tablet_driver_version_declared",
            "active_area_declared",
            "mapped_display_declared",
            "pressure_curve_declared",
            "windows_build_reported",
            "windows_build_source",
            "windows_ink_state_source",
            "tablet_profile_source",
            "runtime_os_family",
            "runtime_architecture",
            "qpc_frequency_hz",
            "wintab_packet_time_mode",
            "wintab_context_config_latest_raw",
            "event_loop_wake_marker_threshold_ns",
            "build_git_sha",
            "build_tree_dirty",
            "build_id",
            "build_profile",
            "binary_sha256",
        ] {
            if let Some(value) = self.metadata.get(key) {
                writeln!(output, "{key}: {value}").ok();
            }
        }
        writeln!(output, "Parsed rows: {}", self.parsed_rows).ok();
        writeln!(
            output,
            "Known omitted records/batches/samples: {}/{}/{}",
            self.records_not_retained, self.batches_not_retained, self.samples_not_retained
        )
        .ok();
        writeln!(output, "Direct history batches: {}", self.direct_batches).ok();
        writeln!(output, "Raw direct samples: {}", self.raw_direct_samples).ok();
        writeln!(
            output,
            "Valid direct pen metric rows: {} (raw rows, may include exact repeats; PT_PEN, matching requested pointer ID, pressure mask present, pressure 0 through 1024 inclusive)",
            self.valid_direct_pen_samples
        )
        .ok();
        writeln!(
            output,
            "Invalid direct pen candidates: {}",
            self.invalid_direct_pen_samples
        )
        .ok();
        writeln!(
            output,
            "Samples with validation anomalies: {}",
            self.validation_anomaly_samples
        )
        .ok();
        writeln!(
            output,
            "Total sample validation issues: {}",
            self.validation_issue_count
        )
        .ok();
        writeln!(
            output,
            "Pressure-mask-missing samples: {}; pressure-out-of-range samples: {}; pointer-ID mismatch samples: {}; unexpected type samples: {}; unexpected tilt-mask samples: {}",
            self.pressure_mask_missing_samples,
            self.pressure_out_of_range_samples,
            self.pointer_id_mismatch_samples,
            self.unexpected_pointer_type_samples,
            self.unexpected_tilt_mask_samples
        )
        .ok();
        writeln!(
            output,
            "Public Winit events: {}; Touch events: {}; event-level PT_PEN confirmations: {}; proven direct/public dispatch overlaps: {}",
            self.public_events,
            self.public_touch_events,
            self.confirmed_public_pen_events,
            self.direct_public_dispatch_overlaps
        )
        .ok();
        writeln!(
            output,
            "Wintab control notifications: {}; ignored non-pen pointer messages: {}; issue records: {}",
            self.wintab_control_notifications,
            self.ignored_non_pen_events,
            self.issue_records
        )
        .ok();
        writeln!(
            output,
            "Wintab raw packets: {}; not-interrupted (unverified) packets: {}; uncertain packets: {}; context-mismatch packets: {}",
            self.raw_wintab_packets,
            self.uninterrupted_wintab_packets,
            self.uncertain_wintab_packets,
            self.wintab_context_mismatch_packets
        )
        .ok();
        writeln!(
            output,
            "Lifecycle/control events: {}; issue records: {}; exact raw duplicate fingerprints: {}; native-clock regressions: {}",
            self.lifecycle_events,
            self.issue_records,
            self.exact_raw_duplicate_fingerprints,
            self.native_clock_regressions
        )
        .ok();
        writeln!(
            output,
            "QPC message-receipt-to-hook observation ages: {} (not physical sensing or display latency)",
            self.qpc_message_to_hook_age_samples
        )
        .ok();
        writeln!(
            output,
            "QPC age null reasons: {:?}",
            self.qpc_age_null_reasons
        )
        .ok();
        writeln!(
            output,
            "Direct raw QPC intervals inside observed strokes: {}; null reasons: {:?}",
            self.qpc_native_interval_samples, self.qpc_interval_null_reasons
        )
        .ok();
        writeln!(
            output,
            "Pressure metric null/exclusion reasons: {:?}; Wintab unqualified raw pressure rows: {}",
            self.pressure_null_reasons,
            self.unqualified_wintab_pressure_rows
        )
        .ok();
        writeln!(output, "Process CPU scope: {PROCESS_CPU_SCOPE}").ok();
        match &self.process_cpu {
            Some(cpu) => {
                writeln!(
                    output,
                    "Process CPU measurement app-arrival ns: {}..{}; interval ns: {:?}; raw FILETIME user start/end: {:?}/{:?}; kernel start/end: {:?}/{:?}; deltas user/kernel: {:?}/{:?} 100ns; whole-process core-equivalent percent: {}; unavailable reason: {:?}",
                    cpu.start.app_elapsed_ns,
                    cpu.end.app_elapsed_ns,
                    cpu.app_interval_ns,
                    cpu.start.user,
                    cpu.end.user,
                    cpu.start.kernel,
                    cpu.end.kernel,
                    cpu.user_delta_100ns,
                    cpu.kernel_delta_100ns,
                    cpu.core_equivalent_percent.map_or_else(|| "null".to_owned(), |value| format!("{value:.3}%")),
                    cpu.unavailable_reason
                )
                .ok();
            }
            None => {
                writeln!(
                    output,
                    "Process CPU measurement: unavailable (CPU row absent)"
                )
                .ok();
            }
        }
        writeln!(
            output,
            "QPC age and direct interval percentiles use discrete nearest-rank (ceil(n*p/100), rank at least 1)."
        )
        .ok();
        writeln!(
            output,
            "Metric partitions (API | device | pointer | stroke | native clock | pressure representation):"
        )
        .ok();
        for (key, bucket) in &mut self.partitions {
            let p50 = bucket
                .qpc_age_percentile_ms(50)
                .map_or_else(|| "null".to_owned(), |value| format!("{value:.3}ms"));
            let p95 = bucket
                .qpc_age_percentile_ms(95)
                .map_or_else(|| "null".to_owned(), |value| format!("{value:.3}ms"));
            let p99 = bucket
                .qpc_age_percentile_ms(99)
                .map_or_else(|| "null".to_owned(), |value| format!("{value:.3}ms"));
            let interval_p50 = bucket
                .qpc_interval_percentile_ms(50)
                .map_or_else(|| "null".to_owned(), |value| format!("{value:.3}ms"));
            let interval_p95 = bucket
                .qpc_interval_percentile_ms(95)
                .map_or_else(|| "null".to_owned(), |value| format!("{value:.3}ms"));
            let interval_p99 = bucket
                .qpc_interval_percentile_ms(99)
                .map_or_else(|| "null".to_owned(), |value| format!("{value:.3}ms"));
            writeln!(
                output,
                "  {} | {} | {} | {} | {} | {}: raw={}, validDirect={}, invalidDirect={}, publicEvents={}, wintabUninterrupted={}, wintabUncertain={}, duplicateFingerprints={}, clockRegressions={}, qpcAgeP50={}, qpcAgeP95={}, qpcAgeP99={}, qpcAgeNull={:?}, qpcIntervalP50={}, qpcIntervalP95={}, qpcIntervalP99={}, qpcIntervalNull={:?}, pressureSamples={}, pressureDistinct={}, pressureEntropyBits={}, pressureRepeats={}, pressurePlateauRuns={}, pressureTransitions={}, pressureMaxRun={}, pressureDistribution={:?}, pressureDistributionTruncated={}, pressureRange={:?}..{:?}",
                key.api,
                key.device,
                key.pointer,
                key.stroke,
                key.native_clock,
                key.pressure_representation,
                bucket.raw_rows,
                bucket.valid_direct_pen_samples,
                bucket.invalid_direct_pen_samples,
                bucket.public_events,
                bucket.uninterrupted_wintab_packets,
                bucket.uncertain_wintab_packets,
                bucket.exact_raw_duplicate_fingerprints,
                bucket.native_clock_regressions,
                p50,
                p95,
                p99,
                bucket.qpc_age_null_reasons,
                interval_p50,
                interval_p95,
                interval_p99,
                bucket.qpc_interval_null_reasons,
                bucket.pressure_metric_samples,
                bucket.pressure_value_counts.len(),
                bucket.pressure_entropy_bits().map_or_else(|| "null".to_owned(), |value| format!("{value:.6}")),
                bucket.pressure_repeated_values,
                bucket.pressure_plateau_runs,
                bucket.pressure_transitions,
                bucket.pressure_max_run_length,
                bucket.pressure_value_counts,
                bucket.pressure_distribution_truncated,
                bucket.valid_pressure_min,
                bucket.valid_pressure_max
            )
            .ok();
        }
        writeln!(
            output,
            "Raw rows are preserved. Exact repeated direct-history fingerprints remain counted but are skipped in derived direct QPC intervals and pressure distributions. Direct pressure metrics require a valid PT_PEN type/ID/pressure mask/range. Wintab NORMAL_PRESSURE remains uncalibrated raw data with unknown driver range and is never normalized or compared with direct pressure. Repeat-run statistics cover valid unique direct rows inside an observed stroke only. Jitter is unresolved because no calibrated position-noise procedure is measured here. Physical end-to-end latency is unresolved because there is no trusted pen-sensing/display clock bridge or instrumented display endpoint. No 220 Hz threshold, frame-lock conclusion, cross-source per-sample join, or CT430 hardware conclusion is produced."
        )
        .ok();
        for warning in &self.warnings {
            writeln!(output, "WARNING: {warning}").ok();
        }
        output
    }
}

fn require_fields(
    fields: &[&str],
    expected: usize,
    line_number: u64,
) -> Result<(), SessionReadError> {
    if fields.len() != expected {
        return Err(SessionReadError::invalid(format!(
            "line {line_number} has {} columns; expected {expected}",
            fields.len()
        )));
    }
    Ok(())
}

fn parse_u64(value: &str, line: u64, name: &str) -> Result<u64, SessionReadError> {
    value.parse().map_err(|_| {
        SessionReadError::invalid(format!("line {line} has an invalid {name}: {value:?}"))
    })
}

fn parse_hex_u64(value: &str, line: u64, name: &str) -> Result<u64, SessionReadError> {
    u64::from_str_radix(value, 16).map_err(|_| {
        SessionReadError::invalid(format!(
            "line {line} has an invalid {name} bit pattern: {value:?}"
        ))
    })
}

fn parse_u128(value: &str, line: u64, name: &str) -> Result<u128, SessionReadError> {
    value.parse().map_err(|_| {
        SessionReadError::invalid(format!("line {line} has an invalid {name}: {value:?}"))
    })
}

fn parse_option_u128(value: &str, line: u64, name: &str) -> Result<Option<u128>, SessionReadError> {
    if value.is_empty() || value == "~" {
        Ok(None)
    } else {
        parse_u128(value, line, name).map(Some)
    }
}

fn parse_u32(value: &str, line: u64, name: &str) -> Result<u32, SessionReadError> {
    value.parse().map_err(|_| {
        SessionReadError::invalid(format!("line {line} has an invalid {name}: {value:?}"))
    })
}

fn parse_option_u32(value: &str, line: u64, name: &str) -> Result<Option<u32>, SessionReadError> {
    if value.is_empty() || value == "~" {
        Ok(None)
    } else {
        parse_u32(value, line, name).map(Some)
    }
}

fn parse_i64(value: &str, line: u64, name: &str) -> Result<i64, SessionReadError> {
    value.parse().map_err(|_| {
        SessionReadError::invalid(format!("line {line} has an invalid {name}: {value:?}"))
    })
}

fn parse_i32(value: &str, line: u64, name: &str) -> Result<i32, SessionReadError> {
    value.parse().map_err(|_| {
        SessionReadError::invalid(format!("line {line} has an invalid {name}: {value:?}"))
    })
}

fn parse_option_u64(value: &str, line: u64, name: &str) -> Result<Option<u64>, SessionReadError> {
    if value == "~" || value.is_empty() {
        Ok(None)
    } else {
        parse_u64(value, line, name).map(Some)
    }
}

fn nonempty_decoded(value: &str, line: u64) -> Result<Option<String>, SessionReadError> {
    if value.is_empty() {
        Ok(None)
    } else {
        decode_field(value, line).map(Some)
    }
}

fn parse_bool(value: &str, line: u64, name: &str) -> Result<bool, SessionReadError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(SessionReadError::invalid(format!(
            "line {line} has an invalid {name}: {value:?}"
        ))),
    }
}

fn parse_pointer_kind(value: &str, line: u64) -> Result<PointerMessageKind, SessionReadError> {
    match value {
        "Down" => Ok(PointerMessageKind::Down),
        "Update" => Ok(PointerMessageKind::Update),
        "Up" => Ok(PointerMessageKind::Up),
        _ => Err(SessionReadError::invalid(format!(
            "line {line} has an unknown pointer message kind {value:?}"
        ))),
    }
}

fn parse_wintab_time_mode(
    value: &str,
    line: u64,
) -> Result<WintabPacketTimeMode, SessionReadError> {
    match value {
        "AbsoluteSystemTime" => Ok(WintabPacketTimeMode::AbsoluteSystemTime),
        "RelativeMilliseconds" => Ok(WintabPacketTimeMode::RelativeMilliseconds),
        _ => Err(SessionReadError::invalid(format!(
            "line {line} has an unknown Wintab time mode {value:?}"
        ))),
    }
}

fn decode_field(value: &str, line: u64) -> Result<String, SessionReadError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(SessionReadError::invalid(format!(
                "line {line} contains a truncated percent escape"
            )));
        }
        let high = hex_value(bytes[index + 1]).ok_or_else(|| {
            SessionReadError::invalid(format!("line {line} contains an invalid percent escape"))
        })?;
        let low = hex_value(bytes[index + 2]).ok_or_else(|| {
            SessionReadError::invalid(format!("line {line} contains an invalid percent escape"))
        })?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| SessionReadError::invalid(format!("line {line} has invalid UTF-8 text")))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn read_bounded_line<R: BufRead>(reader: &mut R, output: &mut Vec<u8>) -> io::Result<Option<bool>> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((!output.is_empty()).then_some(false));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if output.len().saturating_add(take) > MAX_SESSION_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session line exceeds bounded parser capacity",
            ));
        }
        let terminated = available.get(take.saturating_sub(1)) == Some(&b'\n');
        output.extend_from_slice(&available[..take]);
        reader.consume(take);
        if terminated {
            return Ok(Some(true));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32_pointer::{
        CaptureSource, CoordinateSpace, CoordinateUnits, DirectPenHistoryBatch, LifecycleEventKind,
        LifecycleEventRecord, OwnedPointerSample, PointerMessageKind, PressureValidity,
        ProbeRecord, ProbeSummary, PublicEventCapability, PublicMessageAssociation,
        PublicPenClassification, PublicUnclassifiedReason, PublicWinitEventData,
        PublicWinitEventRecord, RawPoint, RawScreenPosition, SampleValidationIssue, StorageLimit,
        WintabContextConfig, WintabCoordinateSpace, WintabIssue, WintabPacketBatch,
        WintabPacketSample,
    };
    use std::io::Cursor;

    fn sample(
        pointer_type: u32,
        pointer_id: u32,
        pen_mask: u32,
        pressure: u32,
    ) -> OwnedPointerSample {
        let mut issues = Vec::new();
        if pointer_type != 3 {
            issues.push(SampleValidationIssue::UnexpectedPointerType {
                reported: pointer_type as i32,
            });
        }
        if pointer_id != 7 {
            issues.push(SampleValidationIssue::PointerIdMismatch {
                requested: 7,
                reported: pointer_id,
            });
        }
        let pressure_validity = if pen_mask & PEN_MASK_PRESSURE == 0 {
            issues.push(SampleValidationIssue::PressureMaskMissing);
            PressureValidity::NotReported
        } else if pressure > 1024 {
            issues.push(SampleValidationIssue::PressureOutOfRange { raw: pressure });
            PressureValidity::OutOfRange
        } else {
            PressureValidity::Valid
        };
        OwnedPointerSample {
            history_index_newest_first: 0,
            chronological_index: 0,
            attribution: if pointer_id == 7 {
                PointerAttribution::MatchesRequestedPointer
            } else {
                PointerAttribution::UnclassifiedIdMismatch {
                    requested: 7,
                    reported: pointer_id,
                }
            },
            pointer_type_raw: pointer_type as i32,
            pointer_id_raw: pointer_id,
            frame_id_raw: 44,
            source_device_handle_raw_session_scoped: 0x1234,
            target_hwnd_raw_session_scoped: 0x5678,
            pointer_flags_raw: 0,
            button_change_type_raw: 0,
            position: RawScreenPosition {
                coordinate_space: CoordinateSpace::WindowsScreenCoordinates,
                pixel_units: CoordinateUnits::ScreenPixel,
                pt_pixel_location_raw: RawPoint { x: 10, y: 20 },
                himetric_units: CoordinateUnits::HimetricHundredthMillimeter,
                pt_himetric_location_raw: RawPoint { x: 30, y: 40 },
            },
            performance_count_qpc_raw: 900,
            dw_time_ms_wrapping_raw: 0xffff_fffe,
            history_count_raw: 1,
            input_data_raw: pressure as i32,
            key_states_raw: 0,
            pen_flags_raw: 0,
            pen_mask_raw: pen_mask,
            pressure_raw: pressure,
            pressure_validity,
            rotation_raw: 0,
            tilt_x_raw: 0,
            tilt_y_raw: 0,
            tilt: None,
            validation_issues: issues,
        }
    }

    fn direct_batch(samples: Vec<OwnedPointerSample>, sequence: u64) -> ProbeRecord {
        direct_batch_with_kind(samples, sequence, PointerMessageKind::Update)
    }

    fn direct_batch_with_kind(
        samples: Vec<OwnedPointerSample>,
        sequence: u64,
        message_kind: PointerMessageKind,
    ) -> ProbeRecord {
        ProbeRecord::DirectPenHistory(DirectPenHistoryBatch {
            source: CaptureSource::DirectWmPointerPenHistory,
            message_sequence: sequence,
            message_id_raw: 0x0245,
            message_hwnd_raw_session_scoped: 0x5678,
            message_time_ms_raw: Some(1234),
            message_kind,
            pointer_id_requested: 7,
            hook_observed_elapsed_ns: 20_000,
            hook_qpc_count_raw: Some(1000),
            hook_qpc_issue: None,
            qpc_frequency_hz: Some(10_000_000),
            native_history_count: samples.len() as u32,
            samples,
        })
    }

    fn public_touch_event(
        sequence: u64,
        touch_id: u64,
        phase: winit::event::TouchPhase,
    ) -> ProbeRecord {
        ProbeRecord::PublicWinitEvent(PublicWinitEventRecord {
            source: CaptureSource::PublicWinitWindowEvent,
            capability: PublicEventCapability::TouchPhasePositionForce,
            public_event_sequence: sequence,
            app_observed_elapsed_ns: sequence as u128,
            window_hwnd_raw_session_scoped: Some(0x5678),
            message_association: None::<PublicMessageAssociation>,
            data: PublicWinitEventData::Touch {
                winit_device_id: winit::event::DeviceId::dummy(),
                public_touch_id: touch_id,
                phase,
                x_physical_px: 10.0,
                y_physical_px: 20.0,
                public_winit_force: None,
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

    fn public_touch_with_force(
        sequence: u64,
        touch_id: u64,
        phase: winit::event::TouchPhase,
        force: winit::event::Force,
    ) -> ProbeRecord {
        public_touch_with_force_classification(
            sequence,
            touch_id,
            phase,
            force,
            PublicPenClassification::Unclassified(PublicUnclassifiedReason::NoMatchedNativeMessage),
        )
    }

    fn public_touch_with_force_classification(
        sequence: u64,
        touch_id: u64,
        phase: winit::event::TouchPhase,
        force: winit::event::Force,
        classification: PublicPenClassification,
    ) -> ProbeRecord {
        let mut record = public_touch_event(sequence, touch_id, phase);
        if let ProbeRecord::PublicWinitEvent(event) = &mut record
            && let PublicWinitEventData::Touch {
                public_winit_force,
                pen_classification,
                ..
            } = &mut event.data
        {
            *public_winit_force = Some(force);
            *pen_classification = classification;
        }
        record
    }

    fn temporary_session_path() -> PathBuf {
        default_session_path(&std::env::temp_dir())
    }

    fn cpu_measurement_for_tests() -> ProcessCpuMeasurement {
        crate::process_cpu::measure(
            ProcessCpuSnapshot {
                app_elapsed_ns: 10,
                user: None,
                kernel: None,
                win32_error: Some(5),
            },
            ProcessCpuSnapshot {
                app_elapsed_ns: 20,
                user: Some(FileTimeWords { low: 2, high: 3 }),
                kernel: Some(FileTimeWords { low: 4, high: 5 }),
                win32_error: None,
            },
        )
    }

    fn available_cpu_measurement_for_tests() -> ProcessCpuMeasurement {
        crate::process_cpu::measure(
            ProcessCpuSnapshot {
                app_elapsed_ns: 0,
                user: Some(FileTimeWords {
                    low: 10_000_000,
                    high: 0,
                }),
                kernel: Some(FileTimeWords {
                    low: 10_000_000,
                    high: 0,
                }),
                win32_error: None,
            },
            ProcessCpuSnapshot {
                app_elapsed_ns: 1_000_000_000,
                user: Some(FileTimeWords {
                    low: 20_000_000,
                    high: 0,
                }),
                kernel: Some(FileTimeWords {
                    low: 20_000_000,
                    high: 0,
                }),
                win32_error: None,
            },
        )
    }

    fn save_cpu_only_session(cpu: ProcessCpuMeasurement) -> PathBuf {
        let path = temporary_session_path();
        let writer = SessionWriter::create(path.clone(), &BTreeMap::new()).unwrap();
        writer
            .finish(ProbeSummary::default(), 1_000_000_000, cpu)
            .unwrap();
        path
    }

    fn replace_cpu_row_field(path: &Path, field_index: usize, value: &str) {
        let text = fs::read_to_string(path).unwrap();
        let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
        let cpu_line = lines
            .iter_mut()
            .find(|line| line.starts_with("CPU\t"))
            .unwrap();
        let mut fields = cpu_line.split('\t').map(str::to_owned).collect::<Vec<_>>();
        fields[field_index] = value.to_owned();
        *cpu_line = fields.join("\t");
        fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    fn save_records(records: &[ProbeRecord]) -> PathBuf {
        let path = temporary_session_path();
        let mut writer = SessionWriter::create(path.clone(), &BTreeMap::new()).unwrap();
        writer.write_records(records).unwrap();
        let mut summary = ProbeSummary {
            records_retained: records.len() as u64,
            pointer_api_available: true,
            ..ProbeSummary::default()
        };
        for record in records {
            match record {
                ProbeRecord::DirectPenHistory(batch) => {
                    summary.samples += batch.samples.len() as u64;
                    summary.valid_direct_pen_samples += batch
                        .samples
                        .iter()
                        .filter(|sample| crate::win32_pointer::is_valid_direct_pen_sample(sample))
                        .count() as u64;
                    summary.invalid_direct_pen_samples += batch.samples.len() as u64
                        - batch
                            .samples
                            .iter()
                            .filter(|sample| {
                                crate::win32_pointer::is_valid_direct_pen_sample(sample)
                            })
                            .count() as u64;
                }
                ProbeRecord::WintabPackets(batch) => {
                    summary.wintab_packets += batch.packets.len() as u64;
                    if batch.control_transition_observed_during_read {
                        summary.uncertain_wintab_packets += batch.packets.len() as u64;
                    }
                }
                _ => {}
            }
        }
        writer
            .finish(summary, 30_000, cpu_measurement_for_tests())
            .unwrap()
    }

    #[test]
    fn malformed_tagged_sample_round_trips_raw_and_is_excluded_from_valid_pen_metrics() {
        let malformed = sample(3, 8, 0, 777);
        let path = save_records(&[direct_batch(vec![malformed], 1)]);
        let mut report = read_report(&path).unwrap();
        let text = report.format_text();
        let raw = fs::read_to_string(&path).unwrap();

        assert_eq!(report.raw_direct_samples, 1);
        assert_eq!(report.validation_anomaly_samples, 1);
        assert_eq!(report.validation_issue_count, 2);
        assert_eq!(report.pressure_mask_missing_samples, 1);
        assert_eq!(report.pointer_id_mismatch_samples, 1);
        assert_eq!(report.valid_direct_pen_samples, 0);
        assert_eq!(report.invalid_direct_pen_samples, 1);
        assert_eq!(report.qpc_message_to_hook_age_samples, 0);
        assert_eq!(
            report
                .qpc_age_null_reasons
                .get("invalid_direct_pen_candidate"),
            Some(&1)
        );
        assert_eq!(report.qpc_native_interval_samples, 0);
        assert_eq!(
            report
                .partitions
                .values()
                .map(|bucket| bucket.pressure_metric_samples)
                .sum::<u64>(),
            0
        );
        assert!(raw.contains("D_SAMPLE\t"));
        assert!(raw.contains("\t777\tNotReported\t"));
        assert!(text.contains("Raw direct samples: 1"));
        assert!(text.contains("Valid direct pen metric rows: 0"));
        assert!(text.contains("message-receipt-to-hook"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn invalid_signed_pointer_type_is_preserved_and_reported_without_parser_loss() {
        let malformed = sample(u32::MAX, 7, PEN_MASK_PRESSURE, 512);
        let path = save_records(&[direct_batch(vec![malformed], 1)]);
        let report = read_report(&path).unwrap();
        let raw = fs::read_to_string(&path).unwrap();

        assert_eq!(report.raw_direct_samples, 1);
        assert_eq!(report.valid_direct_pen_samples, 0);
        assert_eq!(report.invalid_direct_pen_samples, 1);
        assert_eq!(report.unexpected_pointer_type_samples, 1);
        assert!(raw.contains("\t-1\t7\t"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn exact_duplicate_fingerprints_are_reported_without_removing_raw_rows() {
        let valid = sample(3, 7, PEN_MASK_PRESSURE, 512);
        let path = save_records(&[direct_batch(vec![valid.clone(), valid], 2)]);
        let report = read_report(&path).unwrap();

        assert_eq!(report.raw_direct_samples, 2);
        assert_eq!(report.valid_direct_pen_samples, 2);
        assert_eq!(report.exact_raw_duplicate_fingerprints, 1);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn direct_qpc_intervals_are_partitioned_by_observed_stroke() {
        let first = sample(3, 7, PEN_MASK_PRESSURE, 512);
        let mut second = first.clone();
        second.performance_count_qpc_raw = 910;
        second.frame_id_raw = 45;
        let path = save_records(&[direct_batch_with_kind(
            vec![first, second],
            7,
            PointerMessageKind::Down,
        )]);
        let mut report = read_report(&path).unwrap();
        let text = report.format_text();

        assert_eq!(report.qpc_native_interval_samples, 1);
        assert!(text.contains("observed-direct-stroke-1"));
        assert!(text.contains("qpcIntervalP50=0.001ms"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn overlapping_direct_history_fingerprints_stay_raw_but_do_not_add_intervals() {
        let first = sample(3, 7, PEN_MASK_PRESSURE, 512);
        let mut second = first.clone();
        second.performance_count_qpc_raw = 910;
        second.frame_id_raw = 45;
        let duplicate = first.clone();
        let mut third = second.clone();
        third.performance_count_qpc_raw = 920;
        third.frame_id_raw = 46;
        let path = save_records(&[
            direct_batch_with_kind(vec![first, second], 8, PointerMessageKind::Down),
            direct_batch_with_kind(vec![duplicate, third], 9, PointerMessageKind::Update),
        ]);
        let mut report = read_report(&path).unwrap();
        let text = report.format_text();

        assert_eq!(report.raw_direct_samples, 4);
        assert_eq!(report.valid_direct_pen_samples, 4);
        assert_eq!(report.exact_raw_duplicate_fingerprints, 1);
        assert_eq!(report.qpc_native_interval_samples, 2);
        let direct_bucket = report
            .partitions
            .iter()
            .find(|(key, _)| key.api == "direct-wm-pointer")
            .map(|(_, bucket)| bucket)
            .unwrap();
        assert_eq!(direct_bucket.pressure_metric_samples, 3);
        assert_eq!(direct_bucket.pressure_value_counts.values().sum::<u64>(), 3);
        assert_eq!(direct_bucket.pressure_repeated_values, 2);
        assert_eq!(
            report
                .qpc_interval_null_reasons
                .get("duplicate_raw_fingerprint"),
            Some(&1)
        );
        assert_eq!(report.native_clock_regressions, 0);
        assert!(text.contains("duplicate_raw_fingerprint"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn pressure_distribution_entropy_and_repeat_runs_use_valid_unique_direct_rows() {
        let pressures = [100, 100, 200, 200];
        let samples = pressures
            .into_iter()
            .enumerate()
            .map(|(index, pressure)| {
                let mut sample = sample(3, 7, PEN_MASK_PRESSURE, pressure);
                sample.performance_count_qpc_raw = 900 + index as u64;
                sample.frame_id_raw = 40 + index as u32;
                sample
            })
            .collect();
        let path = save_records(&[direct_batch_with_kind(
            samples,
            11,
            PointerMessageKind::Down,
        )]);
        let mut report = read_report(&path).unwrap();
        let text = report.format_text();
        let (key, bucket) = report
            .partitions
            .iter()
            .find(|(key, _)| key.api == "direct-wm-pointer")
            .unwrap();

        assert!(
            key.pressure_representation
                .contains("valid mask range 0..1024")
        );
        assert_eq!(bucket.pressure_metric_samples, 4);
        assert_eq!(bucket.pressure_value_counts.len(), 2);
        assert_eq!(bucket.pressure_value_counts.get(&100), Some(&2));
        assert_eq!(bucket.pressure_value_counts.get(&200), Some(&2));
        assert!((bucket.pressure_entropy_bits().unwrap() - 1.0).abs() < f64::EPSILON);
        assert_eq!(bucket.pressure_repeated_values, 2);
        assert_eq!(bucket.pressure_plateau_runs, 2);
        assert_eq!(bucket.pressure_transitions, 1);
        assert_eq!(bucket.pressure_max_run_length, 2);
        assert!(text.contains("pressureEntropyBits=1.000000"));
        assert!(text.contains("pressurePlateauRuns=2"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn truncated_pressure_histogram_reports_null_entropy_and_explicit_cap_state() {
        let mut report = SessionReport::default();
        let key = MetricKey {
            api: "direct-wm-pointer".to_owned(),
            device: "device:test".to_owned(),
            pointer: "pointer:7".to_owned(),
            stroke: "observed-direct-stroke-1".to_owned(),
            native_clock: "QPC:test".to_owned(),
            pressure_representation: "test raw integer".to_owned(),
        };
        for value in 0..=MAX_PRESSURE_VALUES_PER_PARTITION as u64 {
            record_pressure_value(&mut report, &key, value, None, false);
        }
        let bucket = report.partitions.get(&key).unwrap();

        assert!(bucket.pressure_distribution_truncated);
        assert!(report.pressure_distribution_cap_reached);
        assert_eq!(bucket.pressure_entropy_bits(), None);
        let text = report.format_text();
        assert!(text.contains("pressureEntropyBits=null"));
        assert!(text.contains("pressureDistributionTruncated=true"));
    }

    #[test]
    fn public_winit_force_distribution_keeps_its_separate_representation() {
        let path = save_records(&[
            public_touch_with_force(
                1,
                7,
                winit::event::TouchPhase::Started,
                winit::event::Force::Normalized(0.25),
            ),
            public_touch_with_force(
                2,
                7,
                winit::event::TouchPhase::Moved,
                winit::event::Force::Normalized(0.75),
            ),
        ]);
        let report = read_report(&path).unwrap();
        let (key, bucket) = report
            .partitions
            .iter()
            .find(|(key, _)| key.api == "public-winit")
            .unwrap();

        assert!(key.pressure_representation.contains("Force::Normalized"));
        assert_eq!(bucket.pressure_metric_samples, 2);
        assert_eq!(bucket.pressure_value_counts.len(), 2);
        assert!((bucket.pressure_entropy_bits().unwrap() - 1.0).abs() < f64::EPSILON);
        assert_eq!(
            report
                .partitions
                .keys()
                .filter(|key| key.api == "direct-wm-pointer")
                .count(),
            0
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn public_force_distribution_partitions_by_pen_classification() {
        let force = winit::event::Force::Normalized(0.5);
        let path = save_records(&[
            public_touch_with_force_classification(
                1,
                7,
                winit::event::TouchPhase::Moved,
                force,
                PublicPenClassification::ConfirmedPen,
            ),
            public_touch_with_force_classification(
                2,
                7,
                winit::event::TouchPhase::Moved,
                force,
                PublicPenClassification::ConfirmedNonPen {
                    pointer_type_raw: 2,
                },
            ),
            public_touch_with_force_classification(
                3,
                7,
                winit::event::TouchPhase::Moved,
                force,
                PublicPenClassification::Unclassified(
                    PublicUnclassifiedReason::PointerTypeApiUnavailable,
                ),
            ),
        ]);
        let report = read_report(&path).unwrap();
        let public_keys = report
            .partitions
            .keys()
            .filter(|key| key.api == "public-winit")
            .collect::<Vec<_>>();

        assert_eq!(public_keys.len(), 3);
        assert!(public_keys.iter().any(|key| {
            key.pressure_representation
                .contains("classification=ConfirmedPen")
        }));
        assert!(
            public_keys
                .iter()
                .any(|key| key.pressure_representation.contains("ConfirmedNonPen"))
        );
        assert!(public_keys.iter().any(|key| {
            key.pressure_representation
                .contains("PointerTypeApiUnavailable")
        }));
        assert_eq!(
            report
                .partitions
                .iter()
                .filter(|(key, _)| key.api == "public-winit")
                .map(|(_, bucket)| bucket.pressure_metric_samples)
                .collect::<Vec<_>>(),
            vec![1, 1, 1]
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn qpc_report_includes_p99_for_age_and_unique_observed_stroke_intervals() {
        let samples = (1..=100)
            .map(|qpc| {
                let mut sample = sample(3, 7, PEN_MASK_PRESSURE, 512);
                sample.performance_count_qpc_raw = qpc;
                sample.frame_id_raw = qpc as u32;
                sample
            })
            .collect();
        let mut batch = match direct_batch_with_kind(samples, 12, PointerMessageKind::Down) {
            ProbeRecord::DirectPenHistory(batch) => batch,
            _ => unreachable!(),
        };
        batch.hook_qpc_count_raw = Some(100);
        batch.native_history_count = 100;
        let path = save_records(&[ProbeRecord::DirectPenHistory(batch)]);
        let mut report = read_report(&path).unwrap();
        let text = report.format_text();
        let bucket = report
            .partitions
            .values_mut()
            .find(|bucket| bucket.valid_direct_pen_samples == 100)
            .unwrap();

        assert_eq!(bucket.qpc_age_ns.len(), 100);
        assert_eq!(bucket.qpc_sample_interval_ns.len(), 99);
        assert!((bucket.qpc_age_percentile_ms(99).unwrap() - 0.0098).abs() < 1e-12);
        assert!((bucket.qpc_interval_percentile_ms(99).unwrap() - 0.0001).abs() < 1e-12);
        assert!(text.contains("qpcAgeP99="));
        assert!(text.contains("qpcIntervalP99="));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn qpc_nearest_rank_percentiles_use_upper_rank_for_small_p95_p99_samples() {
        let mut bucket = MetricBucket::default();
        bucket.add_qpc_age(Some(1_000_000), None);
        bucket.add_qpc_age(Some(9_000_000), None);
        bucket.add_qpc_interval(Some(1_000_000), None);
        bucket.add_qpc_interval(Some(9_000_000), None);

        assert_eq!(bucket.qpc_age_percentile_ms(50), Some(1.0));
        assert_eq!(bucket.qpc_age_percentile_ms(95), Some(9.0));
        assert_eq!(bucket.qpc_age_percentile_ms(99), Some(9.0));
        assert_eq!(bucket.qpc_interval_percentile_ms(50), Some(1.0));
        assert_eq!(bucket.qpc_interval_percentile_ms(95), Some(9.0));
        assert_eq!(bucket.qpc_interval_percentile_ms(99), Some(9.0));
        assert_eq!(nearest_rank_index(1, 99), Some(0));
    }

    #[test]
    fn direct_pointer_leave_breaks_stroke_and_qpc_interval_tracking() {
        let first = sample(3, 7, PEN_MASK_PRESSURE, 512);
        let mut second = first.clone();
        second.performance_count_qpc_raw = 910;
        second.frame_id_raw = 45;
        let mut after_leave = second.clone();
        after_leave.performance_count_qpc_raw = 920;
        after_leave.frame_id_raw = 46;
        let mut next_stroke = after_leave.clone();
        next_stroke.performance_count_qpc_raw = 930;
        next_stroke.frame_id_raw = 47;
        let leave = LifecycleEventRecord {
            source: CaptureSource::DirectWin32Lifecycle,
            kind: LifecycleEventKind::DirectPointerLeave,
            app_observed_elapsed_ns: 15_000,
            message_id_raw: Some(0x024a),
            message_hwnd_raw_session_scoped: Some(0x5678),
            wparam_raw: Some(7),
            lparam_raw: Some(0),
            native_message_time_ms_raw: Some(10),
            pointer_id_raw: Some(7),
            winit_device_id_debug: None,
            event_loop_wait_start_elapsed_ns: None,
            event_loop_requested_resume_elapsed_ns: None,
            event_loop_wake_lateness_ns: None,
            controlled_stall_duration_ns: None,
            issue_debug: None,
        };
        let path = save_records(&[
            direct_batch_with_kind(vec![first], 30, PointerMessageKind::Down),
            direct_batch_with_kind(vec![second], 31, PointerMessageKind::Update),
            ProbeRecord::Lifecycle(leave),
            direct_batch_with_kind(vec![after_leave], 32, PointerMessageKind::Update),
            direct_batch_with_kind(vec![next_stroke], 33, PointerMessageKind::Down),
        ]);
        let report = read_report(&path).unwrap();
        let direct_strokes = report
            .partitions
            .keys()
            .filter(|key| key.api == "direct-wm-pointer")
            .map(|key| key.stroke.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(report.raw_direct_samples, 4);
        assert_eq!(report.qpc_native_interval_samples, 1);
        assert!(direct_strokes.contains("observed-direct-stroke-1"));
        assert!(direct_strokes.contains("unclassified-no-observed-down"));
        assert!(direct_strokes.contains("observed-direct-stroke-2"));
        assert!(
            report
                .qpc_interval_null_reasons
                .contains_key("stroke_unclassified")
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn direct_pointer_reentry_without_leave_requires_a_new_down_boundary() {
        let first = sample(3, 7, PEN_MASK_PRESSURE, 512);
        let mut second = first.clone();
        second.performance_count_qpc_raw = 910;
        second.frame_id_raw = 45;
        let mut after_reentry = second.clone();
        after_reentry.performance_count_qpc_raw = 920;
        after_reentry.frame_id_raw = 46;
        let mut next_down = after_reentry.clone();
        next_down.performance_count_qpc_raw = 940;
        next_down.frame_id_raw = 48;
        let mut next_update = next_down.clone();
        next_update.performance_count_qpc_raw = 950;
        next_update.frame_id_raw = 49;
        let mut after_range = after_reentry.clone();
        after_range.performance_count_qpc_raw = 930;
        after_range.frame_id_raw = 47;
        let reentry = LifecycleEventRecord {
            source: CaptureSource::DirectWin32Lifecycle,
            kind: LifecycleEventKind::DirectPointerEnter,
            app_observed_elapsed_ns: 15_000,
            message_id_raw: Some(0x0249),
            message_hwnd_raw_session_scoped: Some(0x5678),
            wparam_raw: Some(7),
            lparam_raw: Some(0),
            native_message_time_ms_raw: Some(10),
            pointer_id_raw: Some(7),
            winit_device_id_debug: None,
            event_loop_wait_start_elapsed_ns: None,
            event_loop_requested_resume_elapsed_ns: None,
            event_loop_wake_lateness_ns: None,
            controlled_stall_duration_ns: None,
            issue_debug: None,
        };
        let device_in_range = LifecycleEventRecord {
            source: CaptureSource::DirectWin32Lifecycle,
            kind: LifecycleEventKind::DirectPointerDeviceInRange,
            app_observed_elapsed_ns: 18_000,
            message_id_raw: Some(0x0239),
            message_hwnd_raw_session_scoped: Some(0x5678),
            wparam_raw: Some(0),
            lparam_raw: Some(0),
            native_message_time_ms_raw: Some(11),
            pointer_id_raw: None,
            winit_device_id_debug: None,
            event_loop_wait_start_elapsed_ns: None,
            event_loop_requested_resume_elapsed_ns: None,
            event_loop_wake_lateness_ns: None,
            controlled_stall_duration_ns: None,
            issue_debug: None,
        };
        let path = save_records(&[
            direct_batch_with_kind(vec![first], 40, PointerMessageKind::Down),
            direct_batch_with_kind(vec![second], 41, PointerMessageKind::Update),
            ProbeRecord::Lifecycle(reentry),
            direct_batch_with_kind(vec![after_reentry], 42, PointerMessageKind::Update),
            ProbeRecord::Lifecycle(device_in_range),
            direct_batch_with_kind(vec![after_range], 43, PointerMessageKind::Update),
            direct_batch_with_kind(vec![next_down], 44, PointerMessageKind::Down),
            direct_batch_with_kind(vec![next_update], 45, PointerMessageKind::Update),
        ]);
        let report = read_report(&path).unwrap();
        let direct_strokes = report
            .partitions
            .keys()
            .filter(|key| key.api == "direct-wm-pointer")
            .map(|key| key.stroke.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(report.raw_direct_samples, 6);
        assert_eq!(report.qpc_native_interval_samples, 2);
        assert!(direct_strokes.contains("observed-direct-stroke-1"));
        assert!(direct_strokes.contains("unclassified-no-observed-down"));
        assert!(direct_strokes.contains("observed-direct-stroke-2"));
        assert!(
            report
                .qpc_interval_null_reasons
                .contains_key("stroke_unclassified")
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn focus_and_device_lifecycle_break_public_touch_strokes() {
        let focus_lost = LifecycleEventRecord {
            source: CaptureSource::ApplicationLifecycle,
            kind: LifecycleEventKind::WindowFocusLost,
            app_observed_elapsed_ns: 20,
            message_id_raw: None,
            message_hwnd_raw_session_scoped: Some(0x5678),
            wparam_raw: None,
            lparam_raw: None,
            native_message_time_ms_raw: None,
            pointer_id_raw: None,
            winit_device_id_debug: None,
            event_loop_wait_start_elapsed_ns: None,
            event_loop_requested_resume_elapsed_ns: None,
            event_loop_wake_lateness_ns: None,
            controlled_stall_duration_ns: None,
            issue_debug: None,
        };
        let device_removed = LifecycleEventRecord {
            source: CaptureSource::ApplicationLifecycle,
            kind: LifecycleEventKind::InputDeviceRemoved,
            app_observed_elapsed_ns: 40,
            message_id_raw: None,
            message_hwnd_raw_session_scoped: Some(0x5678),
            wparam_raw: None,
            lparam_raw: None,
            native_message_time_ms_raw: None,
            pointer_id_raw: None,
            winit_device_id_debug: Some("DeviceId(test)".to_owned()),
            event_loop_wait_start_elapsed_ns: None,
            event_loop_requested_resume_elapsed_ns: None,
            event_loop_wake_lateness_ns: None,
            controlled_stall_duration_ns: None,
            issue_debug: None,
        };
        let path = save_records(&[
            public_touch_event(1, 7, winit::event::TouchPhase::Started),
            public_touch_event(2, 7, winit::event::TouchPhase::Moved),
            ProbeRecord::Lifecycle(focus_lost),
            public_touch_event(3, 7, winit::event::TouchPhase::Moved),
            public_touch_event(4, 8, winit::event::TouchPhase::Started),
            ProbeRecord::Lifecycle(device_removed),
            public_touch_event(5, 8, winit::event::TouchPhase::Moved),
        ]);
        let report = read_report(&path).unwrap();
        let strokes = report
            .partitions
            .keys()
            .filter(|key| key.api == "public-winit")
            .map(|key| key.stroke.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(report.public_touch_events, 5);
        assert!(strokes.contains("observed-public-touch-stroke-1"));
        assert!(strokes.contains("observed-public-touch-stroke-2"));
        assert!(strokes.contains("unclassified-no-observed-start"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn interrupted_wintab_packets_are_counted_separately_from_uninterrupted_rows() {
        let batch = WintabPacketBatch {
            source: CaptureSource::WintabPacket,
            message_sequence: 3,
            message_id_raw: 0x7ff0,
            message_hwnd_raw_session_scoped: 0x5678,
            message_time_ms_raw: Some(42),
            message_wparam_raw: 1,
            message_lparam_raw: 7,
            context_handle_raw_session_scoped: 7,
            notification_serial_raw: Some(1),
            context_config: WintabContextConfig {
                context_name_raw: [0; 40],
                options_raw: 0,
                status_raw: 0,
                locks_raw: 0,
                message_base_raw: 0x7ff0,
                device_raw: 2,
                packet_rate_raw: 0,
                packet_data_raw: 0,
                packet_mode_raw: 0,
                move_mask_raw: 0,
                button_down_mask_raw: 0,
                button_up_mask_raw: 0,
                input_origin_raw: [0; 3],
                input_extent_raw: [0; 3],
                output_origin_raw: [0; 3],
                output_extent_raw: [0; 3],
                sensitivity_fixed32_raw: [0; 3],
                system_mode_raw: 0,
                system_origin_raw: [0; 2],
                system_extent_raw: [0; 2],
                system_sensitivity_fixed32_raw: [0; 2],
            },
            queue_capacity_raw: 128,
            coordinate_space: WintabCoordinateSpace::DigitizerContextOutputCoordinates,
            packet_time_mode: WintabPacketTimeMode::AbsoluteSystemTime,
            app_observed_elapsed_ns: 22,
            control_transition_observed_during_read: true,
            packet_quality_issue_observed: false,
            packets: vec![WintabPacketSample {
                context_handle_raw_session_scoped: 7,
                status_raw: 0,
                packet_time_raw: 111,
                serial_number_raw: 1,
                cursor_raw: 0,
                buttons_raw: 0,
                x_raw: 1,
                y_raw: 2,
                normal_pressure_raw: 512,
            }],
        };
        let mut quality_issue = batch.clone();
        quality_issue.message_sequence = 4;
        quality_issue.control_transition_observed_during_read = false;
        quality_issue.packet_quality_issue_observed = true;
        quality_issue.packets[0].status_raw = WINTAB_TPS_QUEUE_ERR;
        quality_issue.packets[0].serial_number_raw = 2;
        let mut valid = batch.clone();
        valid.message_sequence = 5;
        valid.control_transition_observed_during_read = false;
        valid.packets[0].serial_number_raw = 3;
        valid.packets[0].normal_pressure_raw = 513;
        let path = save_records(&[
            ProbeRecord::WintabPackets(batch),
            ProbeRecord::WintabPackets(quality_issue),
            ProbeRecord::WintabPackets(valid),
        ]);
        let report = read_report(&path).unwrap();

        assert_eq!(report.raw_wintab_packets, 3);
        assert_eq!(report.uncertain_wintab_packets, 1);
        assert_eq!(report.uninterrupted_wintab_packets, 2);
        assert_eq!(report.unqualified_wintab_pressure_rows, 2);
        let (key, bucket) = report
            .partitions
            .iter()
            .find(|(key, _)| key.api == "wintab")
            .unwrap();
        assert!(key.pressure_representation.contains("uncalibrated"));
        assert!(key.pressure_representation.contains("driver range unknown"));
        assert_eq!(bucket.pressure_metric_samples, 1);
        assert_eq!(bucket.pressure_value_counts.get(&513), Some(&1));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn zero_sample_lifecycle_event_keeps_raw_flags_and_arrival_timeline() {
        let event = LifecycleEventRecord {
            source: CaptureSource::WintabPacket,
            kind: LifecycleEventKind::WintabProximityEnter,
            app_observed_elapsed_ns: 900,
            message_id_raw: Some(0x7ff5),
            message_hwnd_raw_session_scoped: Some(0x5678),
            wparam_raw: Some(7),
            lparam_raw: Some(0x0001_0001),
            native_message_time_ms_raw: Some(123),
            pointer_id_raw: None,
            winit_device_id_debug: None,
            event_loop_wait_start_elapsed_ns: None,
            event_loop_requested_resume_elapsed_ns: None,
            event_loop_wake_lateness_ns: None,
            controlled_stall_duration_ns: None,
            issue_debug: None,
        };
        let path = save_records(&[ProbeRecord::Lifecycle(event)]);
        let report = read_report(&path).unwrap();
        let raw = fs::read_to_string(&path).unwrap();

        assert_eq!(report.lifecycle_events, 1);
        assert!(raw.contains("WintabProximityEnter"));
        assert!(raw.contains("\t900\t"));
        assert!(raw.contains("\t65537\t123\t"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn wintab_control_and_error_rows_keep_raw_provenance_and_app_arrival() {
        let control = crate::win32_pointer::WintabControlNotification {
            source: CaptureSource::WintabControlNotification,
            observer_sequence: 4,
            message_id_raw: 0x7ff3,
            message_hwnd_raw_session_scoped: 0x5678,
            wparam_raw: 7,
            lparam_raw: 0x0004,
            app_observed_elapsed_ns: 778,
        };
        let issue = ProbeRecord::WintabIssue {
            source: CaptureSource::WintabPacket,
            message_sequence: 11,
            message_id_raw: 0x7ff0,
            message_hwnd_raw_session_scoped: Some(0x5678),
            message_wparam_raw: Some(7),
            message_lparam_raw: Some(0x1122),
            message_time_ms_raw: Some(321),
            app_observed_elapsed_ns: Some(777),
            issue: WintabIssue::QueueQueryFailed,
        };
        let path = save_records(&[ProbeRecord::WintabControlNotification(control), issue]);
        let report = read_report(&path).unwrap();
        let raw = fs::read_to_string(&path).unwrap();

        assert_eq!(report.wintab_control_notifications, 1);
        assert_eq!(report.issue_records, 1);
        assert!(raw.contains("CONTROL"));
        assert!(raw.contains("W_ISSUE"));
        assert!(raw.contains("\t4386\t321\t777\tQueueQueryFailed"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn parser_rejects_oversized_lines_before_unbounded_allocation() {
        let mut input = b"LASSOINK-SESSION\t1\nMETA\tkey\t".to_vec();
        input.extend(std::iter::repeat_n(b'x', MAX_SESSION_LINE_BYTES));
        input.push(b'\n');
        assert!(parse_session(Cursor::new(input)).is_err());
    }

    #[test]
    fn parser_keeps_complete_rows_and_marks_truncated_tail_incomplete() {
        let input = b"LASSOINK-SESSION\t1\nMETA\tkey\tvalue\nSTARTUP\tApiFailure";
        let report = parse_session(Cursor::new(input)).unwrap();
        assert!(!report.complete);
        assert!(report.capture_incomplete);
        assert_eq!(
            report.metadata.get("key").map(String::as_str),
            Some("value")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("truncated final line"))
        );
    }

    #[test]
    fn parser_keeps_legacy_schema_one_session_without_cpu_row() {
        let input = b"LASSOINK-SESSION\t1\nEND\tfinalized\t20\t0\t0\t0\t0\t0\t0\t0\t\t0\tNotSelected\ttrue\tDirectWmPointer\t\t\t\t0\t0\t0\n";
        let report = parse_session(Cursor::new(input)).unwrap();
        assert!(report.complete);
        assert_eq!(report.schema_version, Some(1));
        assert!(report.process_cpu.is_none());
    }

    #[test]
    fn writer_rejects_metadata_values_over_parser_limit_and_keeps_partial_path() {
        let path = temporary_session_path();
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "oversized".to_owned(),
            "x".repeat(MAX_SESSION_METADATA_TEXT_BYTES + 1),
        );
        let error = SessionWriter::create(path.clone(), &metadata).unwrap_err();
        assert_eq!(error.stage, SessionOutputStage::Write);
        let partial = partial_session_path(&path);
        assert!(partial.exists());
        fs::remove_file(partial).unwrap();
    }

    #[test]
    fn writer_rejects_metadata_key_overflow_and_keeps_partial_path() {
        let path = temporary_session_path();
        let metadata = (0..=MAX_SESSION_METADATA_ENTRIES)
            .map(|index| (format!("key-{index}"), "value".to_owned()))
            .collect::<BTreeMap<_, _>>();
        let error = SessionWriter::create(path.clone(), &metadata).unwrap_err();
        assert_eq!(error.stage, SessionOutputStage::Write);
        let partial = partial_session_path(&path);
        assert!(partial.exists());
        fs::remove_file(partial).unwrap();
    }

    #[test]
    fn writer_and_parser_share_total_line_cap_and_reserve_end_footer() {
        let path = temporary_session_path();
        let mut writer =
            SessionWriter::create_with_line_limit(path.clone(), &BTreeMap::new(), 6).unwrap();
        writer.write_metadata("repeat", "one").unwrap();
        writer.write_metadata("repeat", "two").unwrap();
        writer.write_metadata("repeat", "three").unwrap();
        writer
            .finish(ProbeSummary::default(), 20, cpu_measurement_for_tests())
            .unwrap();

        let complete_bytes = fs::read(&path).unwrap();
        assert_eq!(
            complete_bytes.iter().filter(|byte| **byte == b'\n').count(),
            6
        );
        let parsed = parse_session_with_line_limit(Cursor::new(complete_bytes), 6).unwrap();
        assert!(parsed.complete);
        fs::remove_file(&path).unwrap();

        let over_path = temporary_session_path();
        let mut writer =
            SessionWriter::create_with_line_limit(over_path.clone(), &BTreeMap::new(), 6).unwrap();
        writer.write_metadata("repeat", "one").unwrap();
        writer.write_metadata("repeat", "two").unwrap();
        writer.write_metadata("repeat", "three").unwrap();
        let error = writer.write_metadata("repeat", "four").unwrap_err();
        assert_eq!(error.stage, SessionOutputStage::Write);
        writer.flush().unwrap();
        let partial_path = partial_session_path(&over_path);
        let partial = fs::read(&partial_path).unwrap();
        assert_eq!(partial.iter().filter(|byte| **byte == b'\n').count(), 4);
        let parsed_partial = parse_session_with_line_limit(Cursor::new(partial), 6).unwrap();
        assert!(!parsed_partial.complete);
        assert!(parsed_partial.capture_incomplete);
        assert!(!over_path.exists());
        fs::remove_file(partial_path).unwrap();
    }

    #[test]
    fn no_clobber_finalize_preserves_preexisting_destination_and_partial() {
        let path = temporary_session_path();
        fs::write(&path, b"owner destination bytes\n").unwrap();
        let mut writer = SessionWriter::create(path.clone(), &BTreeMap::new()).unwrap();
        writer.write_metadata("session", "new data").unwrap();
        let error = writer
            .finish(ProbeSummary::default(), 20, cpu_measurement_for_tests())
            .unwrap_err();
        assert_eq!(error.stage, SessionOutputStage::Finalize);
        assert_eq!(fs::read(&path).unwrap(), b"owner destination bytes\n");
        let partial_path = partial_session_path(&path);
        let parsed = read_report(&partial_path).unwrap();
        assert!(!parsed.complete);
        assert_eq!(
            parsed.metadata.get("session").map(String::as_str),
            Some("new data")
        );
        fs::remove_file(path).unwrap();
        fs::remove_file(partial_path).unwrap();
    }

    #[test]
    fn no_clobber_finalize_publishes_normal_session() {
        let path = temporary_session_path();
        let writer = SessionWriter::create(path.clone(), &BTreeMap::new()).unwrap();
        let finalized = writer
            .finish(ProbeSummary::default(), 20, cpu_measurement_for_tests())
            .unwrap();
        assert_eq!(finalized, path);
        assert!(path.exists());
        assert!(!partial_session_path(&path).exists());
        assert!(read_report(&path).unwrap().complete);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn no_clobber_finalize_preserves_destination_created_after_writer_open() {
        let path = temporary_session_path();
        let mut writer = SessionWriter::create(path.clone(), &BTreeMap::new()).unwrap();
        writer.write_metadata("session", "new data").unwrap();
        fs::write(&path, b"late destination bytes\n").unwrap();
        let error = writer
            .finish(ProbeSummary::default(), 20, cpu_measurement_for_tests())
            .unwrap_err();
        assert_eq!(error.stage, SessionOutputStage::Finalize);
        assert_eq!(fs::read(&path).unwrap(), b"late destination bytes\n");
        let partial_path = partial_session_path(&path);
        let parsed = read_report(&partial_path).unwrap();
        assert!(!parsed.complete);
        assert_eq!(
            parsed.metadata.get("session").map(String::as_str),
            Some("new data")
        );
        fs::remove_file(path).unwrap();
        fs::remove_file(partial_path).unwrap();
    }

    #[test]
    fn cpu_row_round_trips_raw_filetimes_and_explicit_unavailable_reason() {
        let path = save_records(&[]);
        let mut report = read_report(&path).unwrap();
        let text = report.format_text();
        let cpu = report.process_cpu.expect("CPU row should be persisted");
        assert_eq!(cpu.start.app_elapsed_ns, 10);
        assert_eq!(cpu.end.app_elapsed_ns, 20);
        assert_eq!(cpu.start.win32_error, Some(5));
        assert_eq!(cpu.start.user, None);
        assert_eq!(cpu.end.user, Some(FileTimeWords { low: 2, high: 3 }));
        assert_eq!(cpu.core_equivalent_percent, None);
        assert_eq!(
            cpu.unavailable_reason,
            Some(ProcessCpuUnavailableReason::StartSnapshotFailed { win32_error: 5 })
        );
        assert!(text.contains("whole process/all threads"));
        assert!(text.contains("core-equivalent percent: null"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn cpu_row_round_trips_available_ratio_and_all_thread_scope() {
        let path = save_cpu_only_session(available_cpu_measurement_for_tests());
        let mut report = read_report(&path).unwrap();
        let text = report.format_text();
        let parsed_cpu = report.process_cpu.unwrap();

        assert_eq!(parsed_cpu.user_delta_100ns, Some(10_000_000));
        assert_eq!(parsed_cpu.kernel_delta_100ns, Some(10_000_000));
        assert_eq!(parsed_cpu.core_equivalent_percent, Some(200.0));
        assert!(text.contains("whole process/all threads"));
        assert!(text.contains("whole-process core-equivalent percent: 200.000%"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn parser_rejects_nonfinite_and_contradictory_cached_cpu_metrics() {
        for (field_index, cached_value) in [
            (14, "7FF8000000000000"), // NaN
            (14, "7FF0000000000000"), // positive infinity
            (14, "3FF0000000000000"), // finite but not the computed ratio
            (3, "999"),               // contradictory app interval
            (12, "1"),                // contradictory user delta
            (13, "2"),                // contradictory kernel delta
        ] {
            let path = save_cpu_only_session(available_cpu_measurement_for_tests());
            replace_cpu_row_field(&path, field_index, cached_value);
            assert!(
                parse_session(File::open(&path).unwrap()).is_err(),
                "CPU row field {field_index} accepted contradictory value {cached_value}"
            );
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn parser_rejects_available_cpu_metrics_when_raw_start_snapshot_failed() {
        let path = save_cpu_only_session(available_cpu_measurement_for_tests());
        for field_index in 4..=7 {
            replace_cpu_row_field(&path, field_index, "");
        }
        replace_cpu_row_field(&path, 16, "5");

        assert!(parse_session(File::open(&path).unwrap()).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn finalized_capture_cap_footer_preserves_known_omitted_counts() {
        let event = LifecycleEventRecord {
            source: CaptureSource::ApplicationLifecycle,
            kind: LifecycleEventKind::WindowFocusGained,
            app_observed_elapsed_ns: 10,
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
            issue_debug: None,
        };
        let path = temporary_session_path();
        let mut writer = SessionWriter::create(path.clone(), &BTreeMap::new()).unwrap();
        writer
            .write_records(&[ProbeRecord::Lifecycle(event)])
            .unwrap();
        let summary = ProbeSummary {
            records_retained: 1,
            records_not_retained: 1,
            batches_not_retained: 1,
            samples_not_retained: 5,
            incomplete_batches: 1,
            storage_limit: Some(StorageLimit::Samples),
            ..ProbeSummary::default()
        };
        writer
            .finish(summary, 20, cpu_measurement_for_tests())
            .unwrap();
        let report = read_report(&path).unwrap();

        assert!(report.capture_incomplete);
        assert_eq!(report.records_not_retained, 1);
        assert_eq!(report.batches_not_retained, 1);
        assert_eq!(report.samples_not_retained, 5);
        fs::remove_file(path).unwrap();
    }
}
