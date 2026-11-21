//! Bounded asynchronous project-journal writer for M3.
//!
//! The Winit/UI thread owns capture callbacks and canvas state. This worker
//! owns the journal's exclusive file lease and performs durable writes away
//! from redraw. Queue saturation is returned to the caller so capture can be
//! stopped visibly instead of silently dropping canonical rows.

use std::{
    sync::mpsc::{self, Receiver, SyncSender, TrySendError},
    thread::{self, JoinHandle},
};

use crate::{
    canvas::DirectCaptureEvent,
    journal::{
        EditCommand, JournalEvent, JournalMetadata, JournalRecord, JournalReplayState,
        JournalWriter, MetadataScope, RecognitionProjectionV1, RegionCorrectionV1,
        StrokeInterruptionReason,
    },
};

const COMMAND_CAPACITY: usize = 8;
const ACK_CAPACITY: usize = 32;
const QUEUED_SAMPLE_CAPACITY: u64 = 131_072;

enum Command {
    Capture {
        batch_id: u64,
        events: Vec<DirectCaptureEvent>,
    },
    Edit {
        batch_id: u64,
        app_arrival_elapsed_ns: u128,
        command: EditCommand,
    },
    Undo {
        batch_id: u64,
        app_arrival_elapsed_ns: u128,
    },
    Redo {
        batch_id: u64,
        app_arrival_elapsed_ns: u128,
    },
    Metadata(JournalMetadata),
    SnapshotForConvert {
        batch_id: u64,
    },
    RecognitionProjection {
        batch_id: u64,
        projection: Box<RecognitionProjectionV1>,
        app_arrival_elapsed_ns: u128,
    },
    /// Staged writer plumbing for the next correction-editor UI unit.
    #[allow(dead_code)]
    RegionCorrection {
        batch_id: u64,
        correction: Box<RegionCorrectionV1>,
        app_arrival_elapsed_ns: u128,
    },
    Finish {
        app_arrival_elapsed_ns: u128,
        incomplete_reason: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProjectWriterAck {
    CaptureCommitted {
        batch_id: u64,
        records: Vec<JournalRecord>,
    },
    CaptureFailed {
        batch_id: u64,
        records: Vec<JournalRecord>,
        error: String,
    },
    EditCommitted {
        batch_id: u64,
        record: JournalRecord,
        projection: Box<JournalReplayState>,
    },
    EditFailed {
        batch_id: u64,
        error: String,
    },
    MetadataCommitted(JournalRecord),
    MetadataFailed(String),
    ConvertSnapshot {
        batch_id: u64,
        state: Box<JournalReplayState>,
    },
    RecognitionProjectionCommitted {
        batch_id: u64,
        record: JournalRecord,
    },
    RecognitionProjectionFailed {
        batch_id: u64,
        error: String,
        writer_poisoned: bool,
    },
    RegionCorrectionCommitted {
        batch_id: u64,
        record: JournalRecord,
    },
    RegionCorrectionFailed {
        batch_id: u64,
        error: String,
        writer_poisoned: bool,
    },
    Finished(Result<(), String>),
}

#[derive(Debug)]
pub(crate) enum ProjectQueueError {
    Backpressure {
        batch_id: u64,
        events: Vec<DirectCaptureEvent>,
        queued_samples: u64,
    },
    Stopped {
        batch_id: u64,
        events: Vec<DirectCaptureEvent>,
    },
    QueueFull,
    WorkerStopped,
}

#[derive(Debug)]
pub(crate) enum ProjectionQueueError {
    QueueFull(Box<RecognitionProjectionV1>),
    WorkerStopped,
}

/// Queue result for the staged correction-editor writer API. The current
/// source unit exercises the API in tests before the UI caller is added.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum CorrectionQueueError {
    QueueFull(Box<RegionCorrectionV1>),
    WorkerStopped,
}

pub(crate) struct ProjectWriterHandle {
    sender: SyncSender<Command>,
    acknowledgements: Receiver<ProjectWriterAck>,
    worker: Option<JoinHandle<()>>,
    pending_commands: usize,
    pending_samples: u64,
    worker_stopped: bool,
}

impl ProjectWriterHandle {
    pub(crate) fn spawn(mut writer: JournalWriter) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(COMMAND_CAPACITY);
        let (ack_sender, acknowledgements) = mpsc::sync_channel(ACK_CAPACITY);
        let worker = thread::Builder::new()
            .name("lassoink-project-writer".to_owned())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    match command {
                        Command::Capture { batch_id, events } => {
                            let total_events = events.len();
                            let total_samples = events
                                .iter()
                                .filter(|event| {
                                    matches!(event, DirectCaptureEvent::PhysicalSample(_))
                                })
                                .count();
                            let mut records = Vec::new();
                            if records.try_reserve(events.len()).is_err() {
                                let _ = ack_sender.send(ProjectWriterAck::CaptureFailed {
                                    batch_id,
                                    records,
                                    error: format!(
                                        "capture acknowledgement allocation failed before any of {total_events} events ({total_samples} samples) were written"
                                    ),
                                });
                                break;
                            }
                            let mut failure = None;
                            for event in events {
                                let result = match event {
                                    DirectCaptureEvent::StrokeStarted {
                                        target,
                                        view_frame,
                                        app_arrival_elapsed_ns,
                                    } => writer.start_stroke_record(
                                        target,
                                        view_frame,
                                        app_arrival_elapsed_ns,
                                    ),
                                    DirectCaptureEvent::PhysicalSample(sample) => {
                                        writer.append_sample_record(*sample)
                                    }
                                    DirectCaptureEvent::StrokeCommitRequested {
                                        target,
                                        app_arrival_elapsed_ns,
                                    } => {
                                        writer.commit_stroke_record(target, app_arrival_elapsed_ns)
                                    }
                                    DirectCaptureEvent::StrokeInterrupted {
                                        target,
                                        reason,
                                        app_arrival_elapsed_ns,
                                    } => writer.interrupt_stroke_record(
                                        target,
                                        reason,
                                        app_arrival_elapsed_ns,
                                    ),
                                    DirectCaptureEvent::UnmatchedNativeUp {
                                        pointer_id_requested,
                                        source_device_handle_raw_session_scoped,
                                        reason,
                                        app_arrival_elapsed_ns,
                                    } => {
                                        let session_id = writer.active_session_id().to_owned();
                                        let source_api = "direct-wm-pointer-pen-history";
                                        let device_id = source_device_handle_raw_session_scoped
                                            .map(|handle| format!("session-scoped-handle-{handle:X}"));
                                        writer.append_event_record(JournalEvent::Metadata(
                                            JournalMetadata {
                                                scope: MetadataScope::Session,
                                                scope_id: session_id,
                                                // Session-scope metadata must not carry device
                                                // identifiers. Preserve the opaque source/device
                                                // values in the bounded value text instead.
                                                source_api: None,
                                                device_id: None,
                                                key: "unmatched-native-pointer-up".to_owned(),
                                                value: format!(
                                                    "requested_pointer_id={pointer_id_requested}; source_api={source_api}; source_device_handle_raw_session_scoped={source_device_handle_raw_session_scoped:?}; device_id={device_id:?}; reason={reason:?}"
                                                ),
                                                provenance: "native WM_POINTERUP did not prove a stroke commit; source API and opaque session-scoped device handle are recorded in the value; source raw message/history remains in the M1 diagnostic session".to_owned(),
                                                app_arrival_elapsed_ns,
                                            },
                                        ))
                                    }
                                };
                                match result {
                                    Ok(record) => records.push(record),
                                    Err(error) => {
                                        let written_samples = records
                                            .iter()
                                            .filter(|record: &&JournalRecord| {
                                                matches!(
                                                    &record.event,
                                                    JournalEvent::PhysicalSample(_)
                                                )
                                            })
                                            .count();
                                        failure = Some(format!(
                                            "{error}; {} of {total_events} capture events and {written_samples} of {total_samples} samples were durably written before failure",
                                            records.len()
                                        ));
                                        break;
                                    }
                                }
                            }
                            let had_failure = failure.is_some();
                            let acknowledgement = match failure {
                                Some(error) => ProjectWriterAck::CaptureFailed {
                                    batch_id,
                                    records,
                                    error,
                                },
                                None => ProjectWriterAck::CaptureCommitted { batch_id, records },
                            };
                            if ack_sender.send(acknowledgement).is_err() || had_failure {
                                break;
                            }
                        }
                        Command::Edit {
                            batch_id,
                            app_arrival_elapsed_ns,
                            command,
                        } => {
                            let result =
                                writer.apply_edit_action_record(app_arrival_elapsed_ns, command);
                            let acknowledgement = match result {
                                Ok(record) => ProjectWriterAck::EditCommitted {
                                    batch_id,
                                    record,
                                    projection: Box::new(writer.replay_state().clone()),
                                },
                                Err(error) => ProjectWriterAck::EditFailed {
                                    batch_id,
                                    error: error.to_string(),
                                },
                            };
                            if ack_sender.send(acknowledgement).is_err() || writer.is_poisoned() {
                                break;
                            }
                        }
                        Command::Undo {
                            batch_id,
                            app_arrival_elapsed_ns,
                        } => {
                            let result = writer.undo_last_edit_record(app_arrival_elapsed_ns);
                            let acknowledgement = match result {
                                Ok(record) => ProjectWriterAck::EditCommitted {
                                    batch_id,
                                    record,
                                    projection: Box::new(writer.replay_state().clone()),
                                },
                                Err(error) => ProjectWriterAck::EditFailed {
                                    batch_id,
                                    error: error.to_string(),
                                },
                            };
                            if ack_sender.send(acknowledgement).is_err() || writer.is_poisoned() {
                                break;
                            }
                        }
                        Command::Redo {
                            batch_id,
                            app_arrival_elapsed_ns,
                        } => {
                            let result = writer.redo_last_edit_record(app_arrival_elapsed_ns);
                            let acknowledgement = match result {
                                Ok(record) => ProjectWriterAck::EditCommitted {
                                    batch_id,
                                    record,
                                    projection: Box::new(writer.replay_state().clone()),
                                },
                                Err(error) => ProjectWriterAck::EditFailed {
                                    batch_id,
                                    error: error.to_string(),
                                },
                            };
                            if ack_sender.send(acknowledgement).is_err() || writer.is_poisoned() {
                                break;
                            }
                        }
                        Command::Metadata(metadata) => {
                            let result =
                                writer.append_event_record(JournalEvent::Metadata(metadata));
                            let acknowledgement = match result {
                                Ok(record) => ProjectWriterAck::MetadataCommitted(record),
                                Err(error) => ProjectWriterAck::MetadataFailed(error.to_string()),
                            };
                            if ack_sender.send(acknowledgement).is_err() || writer.is_poisoned() {
                                break;
                            }
                        }
                        Command::SnapshotForConvert { batch_id } => {
                            if ack_sender
                                .send(ProjectWriterAck::ConvertSnapshot {
                                    batch_id,
                                    state: Box::new(writer.replay_state().clone()),
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Command::RecognitionProjection {
                            batch_id,
                            projection,
                            app_arrival_elapsed_ns,
                        } => {
                            let result = writer.append_recognition_projection_record(
                                *projection,
                                app_arrival_elapsed_ns,
                            );
                            match result {
                                Ok(record) => {
                                    if ack_sender
                                        .send(ProjectWriterAck::RecognitionProjectionCommitted {
                                            batch_id,
                                            record,
                                        })
                                        .is_err()
                                        || writer.is_poisoned()
                                    {
                                        break;
                                    }
                                }
                                Err(error) => {
                                    let writer_poisoned = writer.is_poisoned();
                                    if ack_sender
                                        .send(ProjectWriterAck::RecognitionProjectionFailed {
                                            batch_id,
                                            error: error.to_string(),
                                            writer_poisoned,
                                        })
                                        .is_err()
                                        || writer_poisoned
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                        Command::RegionCorrection {
                            batch_id,
                            correction,
                            app_arrival_elapsed_ns,
                        } => {
                            let result = writer.append_region_correction_record(
                                *correction,
                                app_arrival_elapsed_ns,
                            );
                            match result {
                                Ok(record) => {
                                    if ack_sender
                                        .send(ProjectWriterAck::RegionCorrectionCommitted {
                                            batch_id,
                                            record,
                                        })
                                        .is_err()
                                        || writer.is_poisoned()
                                    {
                                        break;
                                    }
                                }
                                Err(error) => {
                                    let writer_poisoned = writer.is_poisoned();
                                    if ack_sender
                                        .send(ProjectWriterAck::RegionCorrectionFailed {
                                            batch_id,
                                            error: error.to_string(),
                                            writer_poisoned,
                                        })
                                        .is_err()
                                        || writer_poisoned
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                        Command::Finish {
                            app_arrival_elapsed_ns,
                            incomplete_reason,
                        } => {
                            let result = finish_writer(
                                &mut writer,
                                app_arrival_elapsed_ns,
                                incomplete_reason,
                            )
                            .map_err(|error| error.to_string());
                            let _ = ack_sender.send(ProjectWriterAck::Finished(result));
                            break;
                        }
                    }
                }
            })?;
        Ok(Self {
            sender,
            acknowledgements,
            worker: Some(worker),
            pending_commands: 0,
            pending_samples: 0,
            worker_stopped: false,
        })
    }

    pub(crate) fn try_capture_batch(
        &mut self,
        batch_id: u64,
        events: Vec<DirectCaptureEvent>,
    ) -> Result<(), ProjectQueueError> {
        if self.worker_stopped {
            return Err(ProjectQueueError::Stopped { batch_id, events });
        }
        let sample_count = events
            .iter()
            .filter(|event| matches!(event, DirectCaptureEvent::PhysicalSample(_)))
            .count() as u64;
        if self.pending_commands >= COMMAND_CAPACITY
            || self.pending_samples.saturating_add(sample_count) > QUEUED_SAMPLE_CAPACITY
        {
            return Err(ProjectQueueError::Backpressure {
                batch_id,
                events,
                queued_samples: self.pending_samples,
            });
        }
        match self.sender.try_send(Command::Capture { batch_id, events }) {
            Ok(()) => {
                self.pending_commands += 1;
                self.pending_samples = self.pending_samples.saturating_add(sample_count);
                Ok(())
            }
            Err(TrySendError::Full(Command::Capture { batch_id, events })) => {
                Err(ProjectQueueError::Backpressure {
                    batch_id,
                    events,
                    queued_samples: self.pending_samples,
                })
            }
            Err(TrySendError::Disconnected(Command::Capture { batch_id, events })) => {
                self.worker_stopped = true;
                Err(ProjectQueueError::Stopped { batch_id, events })
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                unreachable!("capture command is preserved by try_send")
            }
        }
    }

    pub(crate) fn try_edit_action(
        &mut self,
        batch_id: u64,
        app_arrival_elapsed_ns: u128,
        command: EditCommand,
    ) -> Result<(), ProjectQueueError> {
        self.try_send(Command::Edit {
            batch_id,
            app_arrival_elapsed_ns,
            command,
        })
    }

    pub(crate) fn try_undo(
        &mut self,
        batch_id: u64,
        app_arrival_elapsed_ns: u128,
    ) -> Result<(), ProjectQueueError> {
        self.try_send(Command::Undo {
            batch_id,
            app_arrival_elapsed_ns,
        })
    }

    pub(crate) fn try_redo(
        &mut self,
        batch_id: u64,
        app_arrival_elapsed_ns: u128,
    ) -> Result<(), ProjectQueueError> {
        self.try_send(Command::Redo {
            batch_id,
            app_arrival_elapsed_ns,
        })
    }

    pub(crate) fn try_metadata(
        &mut self,
        metadata: JournalMetadata,
    ) -> Result<(), ProjectQueueError> {
        self.try_send(Command::Metadata(metadata))
    }

    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        !self.worker_stopped && self.pending_commands == 0 && self.pending_samples == 0
    }

    /// Enqueues an ordered view snapshot. Its acknowledgement observes all
    /// commands accepted before this one after their journal syncs completed.
    pub(crate) fn try_snapshot_for_convert(
        &mut self,
        batch_id: u64,
    ) -> Result<(), ProjectQueueError> {
        self.try_send(Command::SnapshotForConvert { batch_id })
    }

    /// Enqueues a derived projection after the exact frozen journal snapshot.
    /// Journal validation runs atomically in the writer immediately before
    /// append, so stale conversion failure does not poison a healthy writer.
    pub(crate) fn try_append_recognition_projection(
        &mut self,
        batch_id: u64,
        projection: RecognitionProjectionV1,
        app_arrival_elapsed_ns: u128,
    ) -> Result<(), ProjectionQueueError> {
        if self.worker_stopped {
            return Err(ProjectionQueueError::WorkerStopped);
        }
        if self.pending_commands >= COMMAND_CAPACITY {
            return Err(ProjectionQueueError::QueueFull(Box::new(projection)));
        }
        match self.sender.try_send(Command::RecognitionProjection {
            batch_id,
            projection: Box::new(projection),
            app_arrival_elapsed_ns,
        }) {
            Ok(()) => {
                self.pending_commands += 1;
                Ok(())
            }
            Err(TrySendError::Full(Command::RecognitionProjection { projection, .. })) => {
                Err(ProjectionQueueError::QueueFull(projection))
            }
            Err(TrySendError::Disconnected(Command::RecognitionProjection { .. })) => {
                self.worker_stopped = true;
                Err(ProjectionQueueError::WorkerStopped)
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                unreachable!("projection command is preserved by try_append_recognition_projection")
            }
        }
    }

    /// Enqueues one immutable region correction. Queue saturation returns the
    /// owned correction so the caller can retry exactly once after capacity
    /// returns; journal validation and sync still happen in sequence on the
    /// writer thread before the committed acknowledgement.
    #[allow(dead_code)]
    pub(crate) fn try_append_region_correction(
        &mut self,
        batch_id: u64,
        correction: RegionCorrectionV1,
        app_arrival_elapsed_ns: u128,
    ) -> Result<(), CorrectionQueueError> {
        if self.worker_stopped {
            return Err(CorrectionQueueError::WorkerStopped);
        }
        if self.pending_commands >= COMMAND_CAPACITY {
            return Err(CorrectionQueueError::QueueFull(Box::new(correction)));
        }
        match self.sender.try_send(Command::RegionCorrection {
            batch_id,
            correction: Box::new(correction),
            app_arrival_elapsed_ns,
        }) {
            Ok(()) => {
                self.pending_commands += 1;
                Ok(())
            }
            Err(TrySendError::Full(Command::RegionCorrection { correction, .. })) => {
                Err(CorrectionQueueError::QueueFull(correction))
            }
            Err(TrySendError::Disconnected(Command::RegionCorrection { .. })) => {
                self.worker_stopped = true;
                Err(CorrectionQueueError::WorkerStopped)
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                unreachable!("correction command is preserved by try_append_region_correction")
            }
        }
    }

    fn try_send(&mut self, command: Command) -> Result<(), ProjectQueueError> {
        if self.worker_stopped {
            return Err(ProjectQueueError::WorkerStopped);
        }
        if self.pending_commands >= COMMAND_CAPACITY {
            return Err(ProjectQueueError::QueueFull);
        }
        match self.sender.try_send(command) {
            Ok(()) => {
                self.pending_commands += 1;
                Ok(())
            }
            Err(TrySendError::Full(_)) => Err(ProjectQueueError::QueueFull),
            Err(TrySendError::Disconnected(_)) => {
                self.worker_stopped = true;
                Err(ProjectQueueError::WorkerStopped)
            }
        }
    }

    pub(crate) fn drain_acks(&mut self) -> Vec<ProjectWriterAck> {
        let mut output = Vec::new();
        while let Ok(acknowledgement) = self.acknowledgements.try_recv() {
            self.pending_commands = self.pending_commands.saturating_sub(1);
            if let ProjectWriterAck::CaptureCommitted { records, .. }
            | ProjectWriterAck::CaptureFailed { records, .. } = &acknowledgement
            {
                let samples = records
                    .iter()
                    .filter(|record| matches!(&record.event, JournalEvent::PhysicalSample(_)))
                    .count() as u64;
                self.pending_samples = self.pending_samples.saturating_sub(samples);
            }
            if matches!(&acknowledgement, ProjectWriterAck::Finished(_)) {
                self.worker_stopped = true;
            }
            output.push(acknowledgement);
        }
        output
    }

    pub(crate) fn finish(
        mut self,
        app_arrival_elapsed_ns: u128,
        incomplete_reason: Option<String>,
    ) -> Result<(), String> {
        self.sender
            .send(Command::Finish {
                app_arrival_elapsed_ns,
                incomplete_reason,
            })
            .map_err(|_| "project writer stopped before finish".to_owned())?;
        let mut result = Err("project writer did not acknowledge finish".to_owned());
        while let Ok(acknowledgement) = self.acknowledgements.recv() {
            if let ProjectWriterAck::Finished(finished) = acknowledgement {
                result = finished;
                break;
            }
        }
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| "project writer thread panicked".to_owned())?;
        }
        result
    }
}

fn finish_writer(
    writer: &mut JournalWriter,
    app_arrival_elapsed_ns: u128,
    incomplete_reason: Option<String>,
) -> Result<(), crate::journal::JournalError> {
    let active_at_close = writer.replay_state().active_strokes.len();
    let historical_interrupted = writer.replay_state().stroke_interruptions.len();
    let finalization_note =
        project_finalization_note(incomplete_reason, active_at_close, historical_interrupted);
    writer.interrupt_active_strokes(
        StrokeInterruptionReason::ProcessEndedWithoutPenUp,
        app_arrival_elapsed_ns,
    )?;
    let current_session_id = writer.active_session_id().to_owned();
    writer.append_event_record(JournalEvent::Metadata(JournalMetadata {
        scope: MetadataScope::Session,
        scope_id: current_session_id,
        source_api: None,
        device_id: None,
        key: "project-finalization".to_owned(),
        value: finalization_note.unwrap_or_else(|| "complete-local-save".to_owned()),
        provenance: "M3 local project writer shutdown".to_owned(),
        app_arrival_elapsed_ns,
    }))?;
    writer.flush()
}

fn project_finalization_note(
    reason: Option<String>,
    active_at_close: usize,
    historical_interrupted: usize,
) -> Option<String> {
    let stroke_status = match (active_at_close, historical_interrupted) {
        (0, 0) => None,
        (0, historical) => Some(format!(
            "clean close with no active stroke; {historical} previously interrupted stroke(s) remain as raw history and are not rendered complete"
        )),
        (active, 0) => Some(format!(
            "process closed with {active} active unfinished stroke(s); raw rows retained, no pen-up or commit synthesized"
        )),
        (active, historical) => Some(format!(
            "process closed with {active} active unfinished stroke(s); raw rows retained, no pen-up or commit synthesized; {historical} previously interrupted stroke(s) also remain as raw history"
        )),
    };
    match (reason, stroke_status) {
        (Some(reason), Some(status)) => Some(format!("{reason}; {status}")),
        (Some(reason), None) => Some(reason),
        (None, status) => status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correction::CorrectionSession;
    use crate::journal::{
        JournalHeader, NativeTimestamp, PhysicalSample, ProjectionInkBindingV1,
        ProjectionInputModalityV1, ProjectionProviderProvenanceV1, ProjectionStrokeRangeV1,
        ProjectionStrokeViewV1, RawPosition, RawPressure, RecognitionCandidateV1,
        RecognitionProjectionV1, RegionCorrectionActionV1, StrokeRef, StrokeViewFrame,
        read_journal,
    };
    use std::{
        fs,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_project(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "lassoink-project-runtime-{label}-{}-{nonce}.inkj",
            process::id()
        ))
    }

    fn new_writer(path: &std::path::Path) -> JournalWriter {
        let mut writer = JournalWriter::create(
            path.to_path_buf(),
            JournalHeader {
                journal_id: "project-runtime-test".to_owned(),
                session_id: "initial-session".to_owned(),
                config_id: None,
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        writer
            .begin_session_epoch(
                "capture-session".to_owned(),
                1_800_000_000_000_000_000,
                Some("config-a".to_owned()),
                "software fixture".to_owned(),
            )
            .unwrap();
        writer
    }

    fn started_sample(target: &StrokeRef) -> PhysicalSample {
        PhysicalSample {
            session_id: target.session_id.clone(),
            source_api: target.source_api.clone(),
            source_device_id: target.device_id.clone(),
            pointer_id: target.pointer_id,
            stroke_id: Some(target.stroke_id.clone()),
            source_sequence: 1,
            config_id: Some("config-a".to_owned()),
            app_arrival_elapsed_ns: 10,
            position: Some(RawPosition {
                coordinate_space: "windows-screen-coordinates".to_owned(),
                units: "screen-pixel".to_owned(),
                x_raw: 100,
                y_raw: 200,
            }),
            pressure: Some(RawPressure {
                representation: "PT_PEN-raw-u32".to_owned(),
                units: "0..1024".to_owned(),
                value_raw: 512,
                mask_raw: Some(1),
                minimum_raw: Some(0),
                maximum_raw: Some(1024),
            }),
            native_timestamp: Some(NativeTimestamp {
                clock_domain: "QPC".to_owned(),
                units: "ticks".to_owned(),
                count_raw: 1000,
                frequency_hz: Some(10_000_000),
            }),
            contact_range_state: Some("in-contact".to_owned()),
            button_state_raw: Some(0),
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload: b"fixture-native-fields".to_vec(),
        }
    }

    fn correction_test_target(stroke_id: &str) -> StrokeRef {
        StrokeRef {
            journal_id: "project-runtime-test".to_owned(),
            session_id: "capture-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-device-17".to_owned()),
            pointer_id: Some(17),
            stroke_id: stroke_id.to_owned(),
        }
    }

    fn append_correction_test_projection(
        writer: &mut JournalWriter,
        target: &StrokeRef,
        projection_id: &str,
    ) -> RecognitionProjectionV1 {
        let frame = StrokeViewFrame::default();
        writer
            .start_stroke_record(target.clone(), frame, 9)
            .unwrap();
        writer.append_sample_record(started_sample(target)).unwrap();
        writer.commit_stroke_record(target.clone(), 11).unwrap();

        let state = writer.replay_state().clone();
        let sample_sequence = state
            .physical_samples
            .iter()
            .find(|sample| sample.sample.stroke_ref(&state.journal_id).as_ref() == Some(target))
            .unwrap()
            .sequence;
        let projection = RecognitionProjectionV1 {
            projection_id: projection_id.to_owned(),
            ink: ProjectionInkBindingV1 {
                journal_id: state.journal_id.clone(),
                logical_revision: state.logical_revision,
                last_sequence: state.last_sequence,
                region_id: "region-correction-test".to_owned(),
                line_id: Some("line-correction-test".to_owned()),
                input_view_id: "input-view-v1-0000000000000001".to_owned(),
                ink_binding_sha256: "a".repeat(64),
                selected_strokes: vec![target.clone()],
                source_sample_sequences: vec![sample_sequence],
                stroke_views: vec![ProjectionStrokeViewV1 {
                    stroke: target.clone(),
                    frame,
                }],
            },
            provider: ProjectionProviderProvenanceV1 {
                provider_id: "external-online-provider".to_owned(),
                provider_version: "synthetic-test-version".to_owned(),
                model_version: None,
                resource_version: None,
                configuration_id: "operator-test-config".to_owned(),
                configuration_fingerprint: "provider-config-v1-fnv64-0000000000000001".to_owned(),
            },
            candidates: vec![RecognitionCandidateV1 {
                rank: 0,
                recognized_text: "immutable provider candidate".to_owned(),
                native_score_raw: None,
                stroke_ranges: vec![ProjectionStrokeRangeV1 {
                    stroke: target.clone(),
                    first_journal_sequence: sample_sequence,
                    last_journal_sequence: sample_sequence,
                }],
            }],
            input_modalities: Some(vec![ProjectionInputModalityV1::OnlineStrokes]),
            generated_raster: None,
        };
        writer
            .append_recognition_projection_record(projection.clone(), 12)
            .unwrap();
        projection
    }

    #[test]
    fn region_correction_queue_full_retries_once_and_acknowledges_after_durable_append() {
        let path = temp_project("region-correction-queue-retry");
        let mut journal_writer = new_writer(&path);
        let target = correction_test_target("correction-queue-stroke");
        let projection = append_correction_test_projection(
            &mut journal_writer,
            &target,
            "correction-queue-projection",
        );
        let projection_snapshot = journal_writer.replay_state().clone();
        let mut session =
            CorrectionSession::open(&projection_snapshot, &projection.projection_id).unwrap();
        session.set_text("durable human correction").unwrap();
        let expected_correction = session
            .build_correction("correction-queue-row")
            .unwrap()
            .unwrap();

        let mut project_writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        for batch_id in 1..=8 {
            project_writer.try_snapshot_for_convert(batch_id).unwrap();
        }
        let correction =
            match project_writer.try_append_region_correction(9, expected_correction.clone(), 13) {
                Err(CorrectionQueueError::QueueFull(correction)) => *correction,
                other => panic!("expected an owned correction on queue saturation, got {other:?}"),
            };

        let mut snapshots_acknowledged = 0;
        for _ in 0..2_000 {
            snapshots_acknowledged += project_writer
                .drain_acks()
                .iter()
                .filter(|ack| matches!(ack, ProjectWriterAck::ConvertSnapshot { .. }))
                .count();
            if snapshots_acknowledged == 8 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(snapshots_acknowledged, 8);
        assert!(project_writer.is_idle());
        project_writer
            .try_append_region_correction(9, correction, 13)
            .unwrap();

        let mut hover = started_sample(&target);
        hover.source_sequence = 2;
        hover.app_arrival_elapsed_ns = 14;
        hover.stroke_id = None;
        hover.source_device_id = None;
        hover.pointer_id = None;
        project_writer
            .try_capture_batch(
                10,
                vec![DirectCaptureEvent::PhysicalSample(Box::new(hover.clone()))],
            )
            .unwrap();

        let mut correction_committed = false;
        let mut capture_committed = false;
        for _ in 0..2_000 {
            for acknowledgement in project_writer.drain_acks() {
                match acknowledgement {
                    ProjectWriterAck::RegionCorrectionCommitted {
                        batch_id: 9,
                        record,
                    } => match record.event {
                        JournalEvent::RegionCorrection { correction, .. } => {
                            assert_eq!(*correction, expected_correction);
                            correction_committed = true;
                        }
                        other => panic!("unexpected correction record event: {other:?}"),
                    },
                    ProjectWriterAck::CaptureCommitted {
                        batch_id: 10,
                        records,
                    } => {
                        assert_eq!(records.len(), 1);
                        assert!(matches!(
                            &records[0].event,
                            JournalEvent::PhysicalSample(sample) if **sample == hover
                        ));
                        capture_committed = true;
                    }
                    ProjectWriterAck::RegionCorrectionFailed {
                        batch_id, error, ..
                    } => {
                        panic!("correction batch {batch_id} failed unexpectedly: {error}");
                    }
                    ProjectWriterAck::CaptureFailed {
                        batch_id, error, ..
                    } => {
                        panic!("capture batch {batch_id} failed after correction commit: {error}");
                    }
                    _ => {}
                }
            }
            if correction_committed && capture_committed {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(correction_committed);
        assert!(capture_committed);
        assert!(project_writer.is_idle());
        session.acknowledge_committed(&expected_correction).unwrap();
        assert!(!session.is_dirty());
        project_writer.finish(20, None).unwrap();

        let persisted = read_journal(&path).unwrap();
        assert_eq!(persisted.state.recognition_projections.len(), 1);
        assert_eq!(persisted.state.region_corrections.len(), 1);
        assert_eq!(
            persisted.state.region_corrections[0].correction.action,
            RegionCorrectionActionV1::SetText("durable human correction".to_owned())
        );
        assert_eq!(persisted.state.physical_samples.len(), 2);
        assert_eq!(
            persisted.state.physical_samples[0].sample,
            started_sample(&target)
        );
        assert_eq!(persisted.state.physical_samples[1].sample, hover);
        assert_eq!(
            persisted.state.recognition_projections[0]
                .projection
                .candidates[0]
                .recognized_text,
            "immutable provider candidate"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stale_region_correction_is_recoverable_and_retains_draft_while_capture_continues() {
        let path = temp_project("region-correction-stale-recoverable");
        let mut journal_writer = new_writer(&path);
        let target = correction_test_target("correction-stale-stroke");
        let projection = append_correction_test_projection(
            &mut journal_writer,
            &target,
            "correction-stale-projection",
        );
        let projection_snapshot = journal_writer.replay_state().clone();
        let mut session =
            CorrectionSession::open(&projection_snapshot, &projection.projection_id).unwrap();
        session.set_text("copyable stale draft").unwrap();
        let stale_correction = session
            .build_correction("correction-stale-row")
            .unwrap()
            .unwrap();
        journal_writer
            .apply_edit_action_record(
                13,
                EditCommand::Tombstone {
                    targets: vec![target.clone()],
                },
            )
            .unwrap();
        assert_ne!(
            journal_writer.replay_state().logical_revision,
            stale_correction.ink.logical_revision
        );

        let mut project_writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        project_writer
            .try_append_region_correction(20, stale_correction, 14)
            .unwrap();
        let mut hover = started_sample(&target);
        hover.source_sequence = 2;
        hover.app_arrival_elapsed_ns = 15;
        hover.stroke_id = None;
        hover.source_device_id = None;
        hover.pointer_id = None;
        project_writer
            .try_capture_batch(
                21,
                vec![DirectCaptureEvent::PhysicalSample(Box::new(hover.clone()))],
            )
            .unwrap();

        let mut stale_failure = false;
        let mut capture_committed = false;
        for _ in 0..2_000 {
            for acknowledgement in project_writer.drain_acks() {
                match acknowledgement {
                    ProjectWriterAck::RegionCorrectionFailed {
                        batch_id: 20,
                        writer_poisoned,
                        ..
                    } => {
                        assert!(!writer_poisoned);
                        stale_failure = true;
                    }
                    ProjectWriterAck::CaptureCommitted {
                        batch_id: 21,
                        records,
                    } => {
                        assert_eq!(records.len(), 1);
                        capture_committed = true;
                    }
                    ProjectWriterAck::RegionCorrectionCommitted { .. } => {
                        panic!("stale correction must not commit");
                    }
                    ProjectWriterAck::CaptureFailed {
                        batch_id, error, ..
                    } => {
                        panic!("capture batch {batch_id} failed after stale correction: {error}");
                    }
                    _ => {}
                }
            }
            if stale_failure && capture_committed {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(stale_failure);
        assert!(capture_committed);
        assert!(project_writer.is_idle());
        assert_eq!(session.text(), "copyable stale draft");
        assert!(session.is_dirty());
        assert_eq!(
            session
                .build_correction("correction-stale-row-retry")
                .unwrap()
                .unwrap()
                .action,
            RegionCorrectionActionV1::SetText("copyable stale draft".to_owned())
        );
        project_writer.finish(16, None).unwrap();

        let persisted = read_journal(&path).unwrap();
        assert_eq!(persisted.state.recognition_projections.len(), 1);
        assert!(persisted.state.region_corrections.is_empty());
        assert_eq!(persisted.state.physical_samples.len(), 2);
        assert_eq!(
            persisted.state.physical_samples[0].sample,
            started_sample(&target)
        );
        assert_eq!(persisted.state.physical_samples[1].sample, hover);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn project_writer_commits_native_up_then_durable_move_projection() {
        let path = temp_project("commit-move");
        let writer = new_writer(&path);
        let target = StrokeRef {
            journal_id: "project-runtime-test".to_owned(),
            session_id: "capture-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-device-1".to_owned()),
            pointer_id: Some(12),
            stroke_id: "stroke-1".to_owned(),
        };
        let sample = started_sample(&target);
        let project_writer = ProjectWriterHandle::spawn(writer).unwrap();
        let events = vec![
            DirectCaptureEvent::StrokeStarted {
                target: target.clone(),
                view_frame: StrokeViewFrame::default(),
                app_arrival_elapsed_ns: 9,
            },
            DirectCaptureEvent::PhysicalSample(Box::new(sample)),
            DirectCaptureEvent::StrokeCommitRequested {
                target: target.clone(),
                app_arrival_elapsed_ns: 11,
            },
        ];
        let mut project_writer = project_writer;
        project_writer.try_capture_batch(1, events).unwrap();
        project_writer
            .try_edit_action(
                2,
                12,
                EditCommand::Move {
                    target: target.clone(),
                    delta_x_raw: 5,
                    delta_y_raw: -2,
                    coordinate_space: "windows-screen-coordinates".to_owned(),
                    units: "screen-pixel".to_owned(),
                },
            )
            .unwrap();
        project_writer.finish(13, None).unwrap();

        let parsed = read_journal(&path).unwrap();
        let projected = parsed.state.projected_samples().unwrap();
        assert_eq!(parsed.state.physical_samples.len(), 1);
        assert_eq!(parsed.state.active_strokes.len(), 0);
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].stroke_ref.as_ref(), Some(&target));
        assert_eq!(projected[0].effective_position.as_ref().unwrap().x_raw, 105);
        assert_eq!(projected[0].effective_position.as_ref().unwrap().y_raw, 198);
        assert!(matches!(
            &parsed.records[2].event,
            JournalEvent::PhysicalSample(_)
        ));
        assert!(parsed.records.iter().any(|record| matches!(
            &record.event,
            JournalEvent::EditAction {
                command: EditCommand::StrokeVisibility {
                    targets,
                    visible: true
                },
                ..
            } if targets == std::slice::from_ref(&target)
        )));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn convert_snapshot_commands_obey_the_existing_bounded_writer_queue() {
        let path = temp_project("convert-snapshot-bounded-queue");
        let writer = new_writer(&path);
        let mut project_writer = ProjectWriterHandle::spawn(writer).unwrap();
        for batch_id in 1..=8 {
            project_writer.try_snapshot_for_convert(batch_id).unwrap();
        }
        assert!(matches!(
            project_writer.try_snapshot_for_convert(9),
            Err(ProjectQueueError::QueueFull)
        ));

        let mut snapshot_acknowledgements = 0;
        for _ in 0..2_000 {
            snapshot_acknowledgements += project_writer
                .drain_acks()
                .iter()
                .filter(|ack| matches!(ack, ProjectWriterAck::ConvertSnapshot { .. }))
                .count();
            if snapshot_acknowledgements == 8 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(snapshot_acknowledgements, 8);
        assert!(project_writer.is_idle());
        project_writer.finish(1, None).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn saturated_projection_queue_can_retry_once_then_capture_continues() {
        let path = temp_project("convert-projection-queue-retry");
        let mut journal_writer = JournalWriter::create(
            path.clone(),
            JournalHeader {
                journal_id: "project-runtime-queue-retry".to_owned(),
                session_id: "capture-session".to_owned(),
                config_id: Some("config-a".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        let target = StrokeRef {
            journal_id: "project-runtime-queue-retry".to_owned(),
            session_id: "capture-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-device-4".to_owned()),
            pointer_id: Some(24),
            stroke_id: "queue-retry-stroke".to_owned(),
        };
        let frame = StrokeViewFrame::default();
        journal_writer
            .start_stroke(target.clone(), frame, 9)
            .unwrap();
        journal_writer
            .append_sample(started_sample(&target))
            .unwrap();
        journal_writer.commit_stroke(target.clone(), 11).unwrap();
        let snapshot = journal_writer.replay_state().clone();
        let source_sequence = snapshot
            .physical_samples
            .iter()
            .find(|sample| sample.sample.stroke_ref(&snapshot.journal_id).as_ref() == Some(&target))
            .unwrap()
            .sequence;
        let binding = ProjectionInkBindingV1 {
            journal_id: snapshot.journal_id.clone(),
            logical_revision: snapshot.logical_revision,
            last_sequence: snapshot.last_sequence,
            region_id: "region-queue-retry".to_owned(),
            line_id: Some("line-1".to_owned()),
            input_view_id: "input-view-v1-0000000000000001".to_owned(),
            ink_binding_sha256: "a".repeat(64),
            selected_strokes: vec![target.clone()],
            source_sample_sequences: vec![source_sequence],
            stroke_views: vec![ProjectionStrokeViewV1 {
                stroke: target.clone(),
                frame,
            }],
        };
        let projection = RecognitionProjectionV1 {
            projection_id: "queue-retry-projection".to_owned(),
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
                recognized_text: "synthetic queued projection".to_owned(),
                native_score_raw: None,
                stroke_ranges: vec![ProjectionStrokeRangeV1 {
                    stroke: target.clone(),
                    first_journal_sequence: source_sequence,
                    last_journal_sequence: source_sequence,
                }],
            }],
            generated_raster: None,
            input_modalities: Some(vec![crate::journal::ProjectionInputModalityV1::Raster]),
        };
        let mut project_writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        for batch_id in 1..=8 {
            project_writer.try_snapshot_for_convert(batch_id).unwrap();
        }
        let projection = match project_writer.try_append_recognition_projection(9, projection, 12) {
            Err(ProjectionQueueError::QueueFull(projection)) => projection,
            other => panic!("expected a recoverable full queue, got {other:?}"),
        };

        let mut snapshot_ack_count = 0;
        for _ in 0..2_000 {
            snapshot_ack_count += project_writer
                .drain_acks()
                .iter()
                .filter(|ack| matches!(ack, ProjectWriterAck::ConvertSnapshot { .. }))
                .count();
            if snapshot_ack_count == 8 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(snapshot_ack_count, 8);
        assert!(project_writer.is_idle());
        project_writer
            .try_append_recognition_projection(9, *projection, 12)
            .unwrap();

        let mut hover = started_sample(&target);
        hover.source_sequence = 2;
        hover.app_arrival_elapsed_ns = 13;
        hover.stroke_id = None;
        hover.source_device_id = None;
        hover.pointer_id = None;
        project_writer
            .try_capture_batch(
                10,
                vec![DirectCaptureEvent::PhysicalSample(Box::new(hover.clone()))],
            )
            .unwrap();

        let mut projection_ack_count = 0;
        let mut capture_ack_seen = false;
        for _ in 0..2_000 {
            for acknowledgement in project_writer.drain_acks() {
                match acknowledgement {
                    ProjectWriterAck::RecognitionProjectionCommitted { batch_id: 9, .. } => {
                        projection_ack_count += 1;
                    }
                    ProjectWriterAck::CaptureCommitted {
                        batch_id: 10,
                        records,
                    } => {
                        assert_eq!(records.len(), 1);
                        assert!(matches!(
                            &records[0].event,
                            JournalEvent::PhysicalSample(sample) if **sample == hover
                        ));
                        capture_ack_seen = true;
                    }
                    other => panic!("unexpected ACK after projection retry: {other:?}"),
                }
            }
            if projection_ack_count == 1 && capture_ack_seen {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(projection_ack_count, 1);
        assert!(capture_ack_seen);
        project_writer.finish(14, None).unwrap();
        let persisted = read_journal(&path).unwrap();
        assert_eq!(persisted.state.recognition_projections.len(), 1);
        assert_eq!(
            persisted.state.recognition_projections[0]
                .projection
                .projection_id,
            "queue-retry-projection"
        );
        assert_eq!(persisted.state.physical_samples.len(), 2);
        assert_eq!(persisted.state.physical_samples[1].sample, hover);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ordered_convert_snapshot_and_stale_projection_rejection_do_not_poison_capture_writer() {
        fn next_ack(
            writer: &mut ProjectWriterHandle,
            predicate: impl Fn(&ProjectWriterAck) -> bool,
        ) -> ProjectWriterAck {
            for _ in 0..2_000 {
                for ack in writer.drain_acks() {
                    if predicate(&ack) {
                        return ack;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            panic!("project writer did not produce the expected ACK");
        }

        let path = temp_project("convert-snapshot-stale-append");
        let journal_writer = JournalWriter::create(
            path.clone(),
            JournalHeader {
                journal_id: "project-runtime-convert-test".to_owned(),
                session_id: "capture-session".to_owned(),
                config_id: Some("config-a".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        let target = StrokeRef {
            journal_id: "project-runtime-convert-test".to_owned(),
            session_id: "capture-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-device-2".to_owned()),
            pointer_id: Some(22),
            stroke_id: "convert-stroke".to_owned(),
        };
        let frame = StrokeViewFrame::default();
        let first_sample = started_sample(&target);
        let mut project_writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        project_writer
            .try_capture_batch(
                1,
                vec![
                    DirectCaptureEvent::StrokeStarted {
                        target: target.clone(),
                        view_frame: frame,
                        app_arrival_elapsed_ns: 9,
                    },
                    DirectCaptureEvent::PhysicalSample(Box::new(first_sample.clone())),
                ],
            )
            .unwrap();
        project_writer.try_snapshot_for_convert(2).unwrap();

        let mut capture_ack_seen = false;
        let mut snapshot_state = None;
        for _ in 0..2_000 {
            for ack in project_writer.drain_acks() {
                match ack {
                    ProjectWriterAck::CaptureCommitted {
                        batch_id: 1,
                        records,
                    } => {
                        assert_eq!(records.len(), 2);
                        capture_ack_seen = true;
                    }
                    ProjectWriterAck::ConvertSnapshot { batch_id: 2, state } => {
                        snapshot_state = Some(*state);
                    }
                    _ => {}
                }
            }
            if capture_ack_seen && snapshot_state.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let snapshot_state = snapshot_state.expect("ordered snapshot must receive an ACK");
        assert!(capture_ack_seen);
        assert_eq!(snapshot_state.last_sequence, 2);
        assert_eq!(snapshot_state.physical_samples.len(), 1);
        assert_eq!(snapshot_state.stroke_starts.len(), 1);

        let binding = ProjectionInkBindingV1 {
            journal_id: snapshot_state.journal_id.clone(),
            logical_revision: snapshot_state.logical_revision,
            last_sequence: snapshot_state.last_sequence,
            region_id: "region-queue-test".to_owned(),
            line_id: Some("line-1".to_owned()),
            input_view_id: "input-view-v1-0000000000000001".to_owned(),
            ink_binding_sha256: "a".repeat(64),
            selected_strokes: vec![target.clone()],
            source_sample_sequences: vec![2],
            stroke_views: vec![ProjectionStrokeViewV1 {
                stroke: target.clone(),
                frame,
            }],
        };
        let stale_projection = RecognitionProjectionV1 {
            projection_id: "convert-queue-projection".to_owned(),
            ink: binding,
            provider: ProjectionProviderProvenanceV1 {
                provider_id: "local-test-provider".to_owned(),
                provider_version: "test-version".to_owned(),
                model_version: None,
                resource_version: None,
                configuration_id: "operator-test-config".to_owned(),
                configuration_fingerprint: "provider-config-v1-fnv64-0000000000000001".to_owned(),
            },
            generated_raster: None,
            input_modalities: None,
            candidates: vec![RecognitionCandidateV1 {
                rank: 0,
                recognized_text: "test candidate".to_owned(),
                native_score_raw: None,
                stroke_ranges: vec![ProjectionStrokeRangeV1 {
                    stroke: target.clone(),
                    first_journal_sequence: 2,
                    last_journal_sequence: 2,
                }],
            }],
        };

        let mut later_selected_sample = started_sample(&target);
        later_selected_sample.source_sequence = 2;
        later_selected_sample.app_arrival_elapsed_ns = 20;
        later_selected_sample.position.as_mut().unwrap().x_raw = 101;
        let second_sample = later_selected_sample.clone();
        project_writer
            .try_capture_batch(
                3,
                vec![DirectCaptureEvent::PhysicalSample(Box::new(
                    later_selected_sample,
                ))],
            )
            .unwrap();
        project_writer
            .try_append_recognition_projection(4, stale_projection, 21)
            .unwrap();
        let mut hover = started_sample(&target);
        hover.stroke_id = None;
        hover.source_device_id = None;
        hover.pointer_id = None;
        hover.source_sequence = 3;
        hover.app_arrival_elapsed_ns = 22;
        project_writer
            .try_capture_batch(
                5,
                vec![DirectCaptureEvent::PhysicalSample(Box::new(hover.clone()))],
            )
            .unwrap();

        let mut stale_failure_seen = false;
        let mut later_capture_seen = false;
        for _ in 0..2_000 {
            for ack in project_writer.drain_acks() {
                match ack {
                    ProjectWriterAck::RecognitionProjectionFailed {
                        batch_id: 4,
                        writer_poisoned,
                        ..
                    } => {
                        assert!(!writer_poisoned);
                        stale_failure_seen = true;
                    }
                    ProjectWriterAck::CaptureCommitted {
                        batch_id: 5,
                        records,
                    } => {
                        assert_eq!(records.len(), 1);
                        later_capture_seen = true;
                    }
                    ProjectWriterAck::CaptureFailed {
                        batch_id, error, ..
                    } => {
                        panic!(
                            "capture batch {batch_id} failed after a recoverable stale conversion: {error}"
                        );
                    }
                    _ => {}
                }
            }
            if stale_failure_seen && later_capture_seen {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(stale_failure_seen);
        assert!(later_capture_seen);
        assert!(project_writer.is_idle());

        project_writer.try_snapshot_for_convert(6).unwrap();
        let fresh_snapshot = match next_ack(&mut project_writer, |ack| {
            matches!(ack, ProjectWriterAck::ConvertSnapshot { batch_id: 6, .. })
        }) {
            ProjectWriterAck::ConvertSnapshot { state, .. } => *state,
            _ => unreachable!("predicate accepts only the requested snapshot acknowledgement"),
        };
        assert_eq!(fresh_snapshot.last_sequence, 4);
        assert_eq!(fresh_snapshot.physical_samples.len(), 3);
        let fresh_sample_sequences = fresh_snapshot
            .physical_samples
            .iter()
            .filter(|stored| {
                stored
                    .sample
                    .stroke_ref(&fresh_snapshot.journal_id)
                    .as_ref()
                    == Some(&target)
            })
            .map(|stored| stored.sequence)
            .collect::<Vec<_>>();
        let fresh_binding = ProjectionInkBindingV1 {
            journal_id: fresh_snapshot.journal_id.clone(),
            logical_revision: fresh_snapshot.logical_revision,
            last_sequence: fresh_snapshot.last_sequence,
            region_id: "region-queue-test-fresh".to_owned(),
            line_id: Some("line-1".to_owned()),
            input_view_id: "input-view-v1-0000000000000002".to_owned(),
            ink_binding_sha256: "b".repeat(64),
            selected_strokes: vec![target.clone()],
            source_sample_sequences: fresh_sample_sequences.clone(),
            stroke_views: vec![ProjectionStrokeViewV1 {
                stroke: target.clone(),
                frame,
            }],
        };
        let recovered_projection = RecognitionProjectionV1 {
            projection_id: "convert-queue-recovered-projection".to_owned(),
            ink: fresh_binding,
            provider: ProjectionProviderProvenanceV1 {
                provider_id: "local-test-provider".to_owned(),
                provider_version: "test-version".to_owned(),
                model_version: None,
                resource_version: None,
                configuration_id: "operator-test-config".to_owned(),
                configuration_fingerprint: "provider-config-v1-fnv64-0000000000000001".to_owned(),
            },
            generated_raster: None,
            input_modalities: None,
            candidates: vec![RecognitionCandidateV1 {
                rank: 0,
                recognized_text: "recovered candidate".to_owned(),
                native_score_raw: None,
                stroke_ranges: vec![ProjectionStrokeRangeV1 {
                    stroke: target.clone(),
                    first_journal_sequence: fresh_sample_sequences[0],
                    last_journal_sequence: *fresh_sample_sequences.last().unwrap(),
                }],
            }],
        };
        project_writer
            .try_append_recognition_projection(7, recovered_projection, 25)
            .unwrap();
        let recovered_ack = next_ack(&mut project_writer, |ack| {
            matches!(
                ack,
                ProjectWriterAck::RecognitionProjectionCommitted { batch_id: 7, .. }
            )
        });
        assert!(matches!(
            recovered_ack,
            ProjectWriterAck::RecognitionProjectionCommitted { .. }
        ));
        assert!(project_writer.is_idle());
        project_writer.finish(30, None).unwrap();

        let persisted = read_journal(&path).unwrap();
        assert_eq!(persisted.state.recognition_projections.len(), 1);
        assert_eq!(persisted.state.physical_samples.len(), 3);
        assert_eq!(persisted.state.physical_samples[0].sample, first_sample);
        assert_eq!(persisted.state.physical_samples[1].sample, second_sample);
        assert_eq!(persisted.state.physical_samples[2].sample, hover);
        let stored_projection = &persisted.state.recognition_projections[0].projection;
        assert_eq!(
            stored_projection.projection_id,
            "convert-queue-recovered-projection"
        );
        assert_eq!(
            stored_projection.ink.journal_id,
            "project-runtime-convert-test"
        );
        assert_eq!(stored_projection.ink.selected_strokes.as_slice(), &[target]);
        assert_eq!(
            stored_projection.ink.source_sample_sequences.as_slice(),
            &[2, 3]
        );
        assert_eq!(stored_projection.ink.last_sequence, 4);
        assert_eq!(
            stored_projection.provider.provider_id,
            "local-test-provider"
        );
        assert_eq!(
            stored_projection.candidates[0].recognized_text,
            "recovered candidate"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn oversized_projection_rejection_keeps_later_physical_capture_writable() {
        let path = temp_project("convert-oversized-projection-recoverable");
        let mut journal_writer = JournalWriter::create(
            path.clone(),
            JournalHeader {
                journal_id: "project-runtime-oversized-convert-test".to_owned(),
                session_id: "capture-session".to_owned(),
                config_id: Some("config-a".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        let target = StrokeRef {
            journal_id: "project-runtime-oversized-convert-test".to_owned(),
            session_id: "capture-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-device-3".to_owned()),
            pointer_id: Some(23),
            stroke_id: "oversized-convert-stroke".to_owned(),
        };
        let frame = StrokeViewFrame::default();
        let source_sample = started_sample(&target);
        journal_writer
            .start_stroke_record(target.clone(), frame, 9)
            .unwrap();
        journal_writer.append_sample_record(source_sample).unwrap();
        journal_writer
            .commit_stroke_record(target.clone(), 11)
            .unwrap();
        let state = journal_writer.replay_state();
        let source_sequences = state
            .physical_samples
            .iter()
            .filter(|stored| stored.sample.stroke_ref(&state.journal_id).as_ref() == Some(&target))
            .map(|stored| stored.sequence)
            .collect::<Vec<_>>();
        assert_eq!(source_sequences.len(), 1);
        let binding = ProjectionInkBindingV1 {
            journal_id: state.journal_id.clone(),
            logical_revision: state.logical_revision,
            last_sequence: state.last_sequence,
            region_id: "region-oversized-row".to_owned(),
            line_id: Some("line-1".to_owned()),
            input_view_id: "input-view-v1-0000000000000001".to_owned(),
            ink_binding_sha256: "a".repeat(64),
            selected_strokes: vec![target.clone()],
            source_sample_sequences: source_sequences.clone(),
            stroke_views: vec![ProjectionStrokeViewV1 {
                stroke: target.clone(),
                frame,
            }],
        };
        let oversized_projection = RecognitionProjectionV1 {
            projection_id: "oversized-convert-projection".to_owned(),
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
                recognized_text: "x".repeat(4097),
                native_score_raw: None,
                stroke_ranges: vec![ProjectionStrokeRangeV1 {
                    stroke: target.clone(),
                    first_journal_sequence: source_sequences[0],
                    last_journal_sequence: source_sequences[0],
                }],
            }],
            generated_raster: None,
            input_modalities: Some(vec![crate::journal::ProjectionInputModalityV1::Raster]),
        };
        let mut project_writer = ProjectWriterHandle::spawn(journal_writer).unwrap();
        project_writer
            .try_append_recognition_projection(2, oversized_projection, 12)
            .unwrap();
        let mut hover = started_sample(&target);
        hover.source_sequence = 2;
        hover.app_arrival_elapsed_ns = 13;
        hover.stroke_id = None;
        hover.source_device_id = None;
        hover.pointer_id = None;
        project_writer
            .try_capture_batch(
                3,
                vec![DirectCaptureEvent::PhysicalSample(Box::new(hover.clone()))],
            )
            .unwrap();

        let mut recoverable_failure_seen = false;
        let mut capture_ack_seen = false;
        for _ in 0..2_000 {
            for acknowledgement in project_writer.drain_acks() {
                match acknowledgement {
                    ProjectWriterAck::RecognitionProjectionFailed {
                        batch_id: 2,
                        writer_poisoned,
                        ..
                    } => {
                        assert!(!writer_poisoned);
                        recoverable_failure_seen = true;
                    }
                    ProjectWriterAck::CaptureCommitted {
                        batch_id: 3,
                        records,
                    } => {
                        assert_eq!(records.len(), 1);
                        assert!(matches!(
                            &records[0].event,
                            JournalEvent::PhysicalSample(sample) if **sample == hover
                        ));
                        capture_ack_seen = true;
                    }
                    ProjectWriterAck::CaptureFailed {
                        batch_id, error, ..
                    } => {
                        panic!(
                            "physical capture batch {batch_id} failed after a recoverable Convert rejection: {error}"
                        );
                    }
                    _ => {}
                }
            }
            if recoverable_failure_seen && capture_ack_seen {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(recoverable_failure_seen);
        assert!(capture_ack_seen);
        assert!(project_writer.is_idle());
        project_writer.finish(14, None).unwrap();

        let persisted = read_journal(&path).unwrap();
        assert!(persisted.state.recognition_projections.is_empty());
        assert_eq!(persisted.state.physical_samples.len(), 2);
        assert_eq!(persisted.state.physical_samples[1].sample, hover);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn unmatched_canceled_up_metadata_does_not_stop_later_project_capture() {
        fn wait_for_capture_commit(
            project_writer: &mut ProjectWriterHandle,
            expected_batch_id: u64,
        ) -> Vec<JournalRecord> {
            for _ in 0..2_000 {
                for acknowledgement in project_writer.drain_acks() {
                    match acknowledgement {
                        ProjectWriterAck::CaptureCommitted { batch_id, records }
                            if batch_id == expected_batch_id =>
                        {
                            return records;
                        }
                        ProjectWriterAck::CaptureFailed {
                            batch_id, error, ..
                        } if batch_id == expected_batch_id => {
                            panic!("capture batch {batch_id} failed: {error}");
                        }
                        _ => {}
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            panic!("capture batch {expected_batch_id} did not receive an ACK");
        }

        let path = temp_project("canceled-up-writer-continues");
        let writer = new_writer(&path);
        let interrupted_target = StrokeRef {
            journal_id: "project-runtime-test".to_owned(),
            session_id: "capture-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-handle-1111".to_owned()),
            pointer_id: Some(12),
            stroke_id: "canceled-up-stroke".to_owned(),
        };
        let valid_target = StrokeRef {
            stroke_id: "following-valid-stroke".to_owned(),
            ..interrupted_target.clone()
        };
        let interrupted_sample = started_sample(&interrupted_target);
        let mut valid_sample = started_sample(&valid_target);
        valid_sample.source_sequence = 2;
        valid_sample.app_arrival_elapsed_ns = 20;

        let mut project_writer = ProjectWriterHandle::spawn(writer).unwrap();
        project_writer
            .try_capture_batch(
                1,
                vec![
                    DirectCaptureEvent::StrokeStarted {
                        target: interrupted_target.clone(),
                        view_frame: StrokeViewFrame::default(),
                        app_arrival_elapsed_ns: 9,
                    },
                    DirectCaptureEvent::PhysicalSample(Box::new(interrupted_sample.clone())),
                    DirectCaptureEvent::StrokeInterrupted {
                        target: interrupted_target.clone(),
                        reason: StrokeInterruptionReason::CanceledNativeUp,
                        app_arrival_elapsed_ns: 11,
                    },
                    DirectCaptureEvent::UnmatchedNativeUp {
                        pointer_id_requested: 12,
                        source_device_handle_raw_session_scoped: Some(0x1111),
                        reason: crate::canvas::DirectUpIssue::CanceledNativeUp,
                        app_arrival_elapsed_ns: 11,
                    },
                ],
            )
            .unwrap();
        let interrupted_records = wait_for_capture_commit(&mut project_writer, 1);
        assert!(interrupted_records.iter().any(|record| matches!(
            &record.event,
            JournalEvent::Metadata(metadata)
                if metadata.key == "unmatched-native-pointer-up"
                    && metadata.scope == MetadataScope::Session
                    && metadata.source_api.is_none()
                    && metadata.device_id.is_none()
                    && metadata.value.contains("source_api=direct-wm-pointer-pen-history")
                    && metadata.value.contains("source_device_handle_raw_session_scoped=Some(4369)")
        )));

        project_writer
            .try_capture_batch(
                2,
                vec![
                    DirectCaptureEvent::StrokeStarted {
                        target: valid_target.clone(),
                        view_frame: StrokeViewFrame::default(),
                        app_arrival_elapsed_ns: 19,
                    },
                    DirectCaptureEvent::PhysicalSample(Box::new(valid_sample.clone())),
                    DirectCaptureEvent::StrokeCommitRequested {
                        target: valid_target.clone(),
                        app_arrival_elapsed_ns: 21,
                    },
                ],
            )
            .unwrap();
        let valid_records = wait_for_capture_commit(&mut project_writer, 2);
        assert!(valid_records.iter().any(|record| matches!(
            &record.event,
            JournalEvent::EditAction {
                command: EditCommand::StrokeVisibility { targets, visible: true },
                ..
            } if targets == std::slice::from_ref(&valid_target)
        )));
        project_writer.finish(30, None).unwrap();

        let parsed = read_journal(&path).unwrap();
        assert_eq!(parsed.state.physical_samples.len(), 2);
        assert_eq!(
            parsed.state.physical_samples[0].sample.raw_payload,
            interrupted_sample.raw_payload
        );
        assert_eq!(
            parsed.state.physical_samples[1].sample.raw_payload,
            valid_sample.raw_payload
        );
        assert!(parsed.records.iter().any(|record| matches!(
            &record.event,
            JournalEvent::StrokeInterrupted {
                target,
                reason: StrokeInterruptionReason::CanceledNativeUp,
                ..
            } if target == &interrupted_target
        )));
        assert!(!parsed.records.iter().any(|record| matches!(
            &record.event,
            JournalEvent::EditAction {
                command: EditCommand::StrokeVisibility { targets, visible: true },
                ..
            } if targets == std::slice::from_ref(&interrupted_target)
        )));
        assert!(parsed.records.iter().any(|record| matches!(
            &record.event,
            JournalEvent::EditAction {
                command: EditCommand::StrokeVisibility { targets, visible: true },
                ..
            } if targets == std::slice::from_ref(&valid_target)
        )));
        let projected = parsed.state.projected_samples().unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].stroke_ref.as_ref(), Some(&valid_target));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn pending_capture_preview_precedes_ack_then_matches_replayed_stroke() {
        let path = temp_project("pending-preview");
        let writer = new_writer(&path);
        let target = StrokeRef {
            journal_id: "project-runtime-test".to_owned(),
            session_id: "capture-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-device-1".to_owned()),
            pointer_id: Some(12),
            stroke_id: "preview-stroke".to_owned(),
        };
        let sample = started_sample(&target);
        let frame = StrokeViewFrame::default();
        let mut scene = crate::canvas::CanvasScene::default();
        scene.begin_preview_stroke(target.clone(), frame).unwrap();
        scene
            .append_preview_sample(&sample, &target.journal_id, true)
            .unwrap();
        let pending = scene
            .render_plan(crate::canvas::CanvasViewport::default())
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].preview, "sample is visible before writer ACK");

        let mut project_writer = ProjectWriterHandle::spawn(writer).unwrap();
        project_writer
            .try_capture_batch(
                1,
                vec![
                    DirectCaptureEvent::StrokeStarted {
                        target: target.clone(),
                        view_frame: frame,
                        app_arrival_elapsed_ns: 9,
                    },
                    DirectCaptureEvent::PhysicalSample(Box::new(sample)),
                    DirectCaptureEvent::StrokeCommitRequested {
                        target: target.clone(),
                        app_arrival_elapsed_ns: 11,
                    },
                ],
            )
            .unwrap();

        let mut capture_ack_received = false;
        for _ in 0..2_000 {
            for acknowledgement in project_writer.drain_acks() {
                if let ProjectWriterAck::CaptureCommitted { records, .. } = acknowledgement {
                    capture_ack_received = true;
                    for record in records {
                        if let JournalEvent::EditAction {
                            command:
                                EditCommand::StrokeVisibility {
                                    targets,
                                    visible: true,
                                },
                            ..
                        } = record.event
                        {
                            for target in targets {
                                scene.promote_preview_stroke(&target).unwrap();
                            }
                        }
                    }
                }
            }
            if capture_ack_received {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(capture_ack_received, "writer returns durable capture ACK");
        let acknowledged = scene
            .render_plan(crate::canvas::CanvasViewport::default())
            .unwrap();
        assert_eq!(acknowledged.len(), 1);
        assert!(!acknowledged[0].preview);
        project_writer.finish(12, None).unwrap();

        let parsed = read_journal(&path).unwrap();
        let replayed = crate::canvas::CanvasScene::from_journal(
            &parsed.state,
            crate::canvas::PROVISIONAL_DIRECT_SOURCE_API,
        )
        .unwrap();
        assert_eq!(
            acknowledged,
            replayed
                .render_plan(crate::canvas::CanvasViewport::default())
                .unwrap()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn project_shutdown_interrupts_unfinished_stroke_without_claiming_complete_save() {
        let path = temp_project("incomplete-shutdown");
        let mut writer = new_writer(&path);
        let target = StrokeRef {
            journal_id: "project-runtime-test".to_owned(),
            session_id: "capture-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-device-1".to_owned()),
            pointer_id: Some(12),
            stroke_id: "stroke-incomplete".to_owned(),
        };
        writer
            .start_stroke(target.clone(), StrokeViewFrame::default(), 9)
            .unwrap();
        writer.append_sample(started_sample(&target)).unwrap();
        let project_writer = ProjectWriterHandle::spawn(writer).unwrap();
        project_writer.finish(20, None).unwrap();

        let parsed = read_journal(&path).unwrap();
        assert_eq!(parsed.state.physical_samples.len(), 1);
        assert!(parsed.state.projected_samples().unwrap().is_empty());
        assert!(parsed.records.iter().any(|record| matches!(
            &record.event,
            JournalEvent::StrokeInterrupted {
                reason: StrokeInterruptionReason::ProcessEndedWithoutPenUp,
                ..
            }
        )));
        let finalization = parsed
            .state
            .metadata_history
            .iter()
            .find(|stored| stored.metadata.key == "project-finalization");
        assert!(finalization.is_some_and(|stored| {
            stored.metadata.value.contains("unfinished stroke")
                && stored
                    .metadata
                    .value
                    .contains("no pen-up or commit synthesized")
        }));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn resumed_clean_close_distinguishes_historical_interruption_from_active_strokes() {
        let path = temp_project("resumed-historical-interruption");
        let mut writer = new_writer(&path);
        let target = StrokeRef {
            journal_id: "project-runtime-test".to_owned(),
            session_id: "capture-session".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-scoped-device-1".to_owned()),
            pointer_id: Some(12),
            stroke_id: "interrupted-before-resume".to_owned(),
        };
        writer
            .start_stroke(target.clone(), StrokeViewFrame::default(), 9)
            .unwrap();
        writer.append_sample(started_sample(&target)).unwrap();
        writer
            .interrupt_stroke(target, StrokeInterruptionReason::PointerCaptureChanged, 10)
            .unwrap();
        writer
            .begin_session_epoch(
                "resumed-session".to_owned(),
                1_800_000_001_000_000_000,
                Some("config-b".to_owned()),
                "clean resumed session".to_owned(),
            )
            .unwrap();
        assert!(writer.replay_state().active_strokes.is_empty());
        assert_eq!(writer.replay_state().stroke_interruptions.len(), 1);
        let project_writer = ProjectWriterHandle::spawn(writer).unwrap();
        project_writer.finish(20, None).unwrap();

        let parsed = read_journal(&path).unwrap();
        let finalization = parsed
            .state
            .metadata_history
            .iter()
            .find(|stored| stored.metadata.key == "project-finalization")
            .unwrap();
        assert!(
            finalization
                .metadata
                .value
                .contains("clean close with no active stroke")
        );
        assert!(
            finalization
                .metadata
                .value
                .contains("1 previously interrupted stroke(s)")
        );
        assert!(
            !finalization
                .metadata
                .value
                .contains("process closed with 1 active unfinished stroke")
        );
        fs::remove_file(path).unwrap();
    }
}
