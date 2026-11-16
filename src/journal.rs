//! Source-agnostic canonical physical-history journal.
//!
//! This module is intentionally independent of the M1 diagnostic TSV and its
//! candidate capture adapters. Native fields remain raw with explicit units
//! and clock domains; application arrival time is a separate monotonic field.
//! Snapshot FNV-1a fingerprints are deterministic corruption/staleness checks,
//! not cryptographic authentication.
//! A write or sync error poisons the writer. The caller must discard live
//! derived state and reload the journal before accepting more edits, because a
//! failed final write may have reached disk completely or as a truncated tail.

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

pub(crate) const JOURNAL_SCHEMA_VERSION: u32 = 2;
const LEGACY_JOURNAL_SCHEMA_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_JOURNAL_LINE_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_RECORDS: usize = 131_072;
const MAX_JOURNAL_TEXT_BYTES: usize = 4096;
const MAX_RAW_PAYLOAD_BYTES: usize = 8192;
const MAX_METADATA_TEXT_BYTES: usize = 4096;
const FNV_OFFSET_BASIS: u64 = 14_695_981_039_346_656_037;
const FNV_PRIME: u64 = 1_099_511_628_211;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalHeader {
    /// Unique identity for this journal file, distinct from capture source IDs.
    pub journal_id: String,
    pub session_id: String,
    pub config_id: Option<String>,
    pub device_model_declared: Option<String>,
    /// Owner/device capability declaration; this is not inferred from null
    /// sample fields or nominal model specifications.
    pub tilt_supported_declared: Option<bool>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct StrokeRef {
    pub source_api: String,
    pub device_id: Option<String>,
    pub pointer_id: Option<u64>,
    pub stroke_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawPosition {
    pub coordinate_space: String,
    pub units: String,
    pub x_raw: i64,
    pub y_raw: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawPressure {
    pub representation: String,
    pub units: String,
    pub value_raw: u64,
    pub mask_raw: Option<u64>,
    pub minimum_raw: Option<u64>,
    pub maximum_raw: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeTimestamp {
    pub clock_domain: String,
    pub units: String,
    pub count_raw: u64,
    pub frequency_hz: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalSample {
    /// Repeated in each sample so session provenance is explicit at the row.
    pub session_id: String,
    /// Source API name only. It does not imply a preferred/canonical adapter.
    pub source_api: String,
    pub source_device_id: Option<String>,
    pub pointer_id: Option<u64>,
    pub stroke_id: Option<String>,
    /// Exact source sequence/sample index; never sorted by timestamp.
    pub source_sequence: u64,
    pub config_id: Option<String>,
    /// Application monotonic arrival elapsed time, separate from native time.
    pub app_arrival_elapsed_ns: u128,
    pub position: Option<RawPosition>,
    /// Missing pressure remains null; no guessed/default pressure is stored.
    pub pressure: Option<RawPressure>,
    pub native_timestamp: Option<NativeTimestamp>,
    /// Source-defined contact/range label, retained without normalization.
    pub contact_range_state: Option<String>,
    pub button_state_raw: Option<u64>,
    /// Nullable when the source/device does not provide the field.
    pub tilt_x_raw: Option<i32>,
    pub tilt_y_raw: Option<i32>,
    pub rotation_raw: Option<u64>,
    /// Opaque exact source payload bytes. Structured fields above do not
    /// replace or rewrite this source-specific evidence.
    pub raw_payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetadataScope {
    Session,
    Device,
    Configuration,
}

/// Append-only owner declarations or source observations associated with a
/// session, device, or immutable configuration identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalMetadata {
    pub scope: MetadataScope,
    /// Session ID, device ID, or configuration ID, according to `scope`.
    pub scope_id: String,
    /// Required for device scope; optional for configuration scope.
    pub source_api: Option<String>,
    /// Required for device scope; optional for configuration scope.
    pub device_id: Option<String>,
    pub key: String,
    /// Empty values are retained so callers can record an explicit clear.
    pub value: String,
    /// E.g. owner-declared, driver-reported, or imported with source details.
    pub provenance: String,
    pub app_arrival_elapsed_ns: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredMetadata {
    pub sequence: u64,
    pub metadata: JournalMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JournalEvent {
    PhysicalSample(Box<PhysicalSample>),
    Metadata(JournalMetadata),
    /// Starts a new logical edit revision while preserving prior physical rows.
    Revision {
        revision_id: u64,
        parent_revision: u64,
        app_arrival_elapsed_ns: u128,
        note: String,
    },
    Tombstone {
        logical_revision: u64,
        app_arrival_elapsed_ns: u128,
        target: StrokeRef,
    },
    StrokeMove {
        logical_revision: u64,
        app_arrival_elapsed_ns: u128,
        target: StrokeRef,
        delta_x_raw: i64,
        delta_y_raw: i64,
        coordinate_space: String,
        units: String,
    },
    UserCorrection {
        logical_revision: u64,
        app_arrival_elapsed_ns: u128,
        target: StrokeRef,
        corrected_text: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalRecord {
    pub sequence: u64,
    pub event: JournalEvent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredPhysicalSample {
    pub sequence: u64,
    pub sample: PhysicalSample,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredMove {
    pub sequence: u64,
    pub logical_revision: u64,
    pub target: StrokeRef,
    pub delta_x_raw: i64,
    pub delta_y_raw: i64,
    pub coordinate_space: String,
    pub units: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredCorrection {
    pub sequence: u64,
    pub logical_revision: u64,
    pub target: StrokeRef,
    pub corrected_text: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct JournalReplayState {
    pub last_sequence: u64,
    pub logical_revision: u64,
    pub physical_samples: Vec<StoredPhysicalSample>,
    /// Full append-only metadata history; later values never overwrite prior
    /// declarations or observations.
    pub metadata_history: Vec<StoredMetadata>,
    pub tombstones: Vec<StrokeRef>,
    pub moves: Vec<StoredMove>,
    pub corrections: Vec<StoredCorrection>,
    stroke_domains: HashMap<StrokeRef, HashSet<(String, String)>>,
    tombstone_set: HashSet<StrokeRef>,
    move_totals: HashMap<StrokeRef, ProjectedTransform>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectedTransform {
    coordinate_space: String,
    units: String,
    delta_x_raw: i64,
    delta_y_raw: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectedSample<'a> {
    pub sequence: u64,
    pub sample: &'a PhysicalSample,
    /// A derived coordinate view. The stored raw sample is never modified.
    pub effective_position: Option<RawPosition>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JournalErrorKind {
    Io,
    InvalidData,
    LimitReached,
    AllocationFailed,
    Poisoned,
}

#[derive(Debug)]
pub(crate) struct JournalError {
    pub kind: JournalErrorKind,
    message: String,
}

impl JournalError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: JournalErrorKind::InvalidData,
            message: message.into(),
        }
    }

    fn limit(message: impl Into<String>) -> Self {
        Self {
            kind: JournalErrorKind::LimitReached,
            message: message.into(),
        }
    }

    fn allocation(message: impl Display) -> Self {
        Self {
            kind: JournalErrorKind::AllocationFailed,
            message: message.to_string(),
        }
    }

    fn io(error: impl Display) -> Self {
        Self {
            kind: JournalErrorKind::Io,
            message: error.to_string(),
        }
    }

    fn poisoned() -> Self {
        Self {
            kind: JournalErrorKind::Poisoned,
            message:
                "journal writer is poisoned; discard derived in-memory state and reopen the file"
                    .to_owned(),
        }
    }
}

impl Display for JournalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for JournalError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalRecovery {
    pub truncated_final_record: bool,
    pub valid_prefix_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PrefixCheckpoint {
    sequence: u64,
    logical_revision: u64,
    byte_len: u64,
    fingerprint: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalReadResult {
    pub schema_version: u32,
    pub header: JournalHeader,
    pub records: Vec<JournalRecord>,
    pub state: JournalReplayState,
    pub recovery: JournalRecovery,
    checkpoints: Vec<PrefixCheckpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SnapshotDisposition {
    Used,
    Missing,
    Rejected(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SnapshotReplayResult {
    pub state: JournalReplayState,
    pub recovery: JournalRecovery,
    pub disposition: SnapshotDisposition,
    pub replayed_tail_records: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalMigrationResult {
    pub destination_path: PathBuf,
    pub source_truncated_final_record: bool,
    pub migrated_records: u64,
}

#[derive(Debug)]
pub(crate) struct JournalWriter {
    path: PathBuf,
    file: File,
    header: JournalHeader,
    state: JournalReplayState,
    bytes_written: u64,
    prefix_fingerprint: u64,
    poisoned: bool,
    recovered_truncated_final_record: bool,
    #[cfg(test)]
    fail_next_sync_after_write: bool,
    #[cfg(test)]
    fail_next_flush: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MaterializedState {
    journal_id: String,
    prefix_bytes: u64,
    prefix_sequence: u64,
    logical_revision: u64,
    prefix_fingerprint: u64,
    state: JournalReplayState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedSnapshot {
    journal_id: String,
    prefix_bytes: u64,
    prefix_sequence: u64,
    logical_revision: u64,
    prefix_fingerprint: u64,
    state: JournalReplayState,
}

impl JournalHeader {
    fn validate(&self) -> Result<(), JournalError> {
        validate_text(&self.journal_id, "journal ID", 128)?;
        validate_text(&self.session_id, "session ID", 256)?;
        if self.journal_id.is_empty() || self.session_id.is_empty() {
            return Err(JournalError::invalid(
                "journal ID and session ID must be nonempty",
            ));
        }
        validate_optional_text(self.config_id.as_deref(), "header configuration ID")?;
        validate_optional_text(
            self.device_model_declared.as_deref(),
            "declared device model",
        )?;
        Ok(())
    }
}

impl PhysicalSample {
    fn stroke_ref(&self) -> Option<StrokeRef> {
        self.stroke_id.as_ref().map(|stroke_id| StrokeRef {
            source_api: self.source_api.clone(),
            device_id: self.source_device_id.clone(),
            pointer_id: self.pointer_id,
            stroke_id: stroke_id.clone(),
        })
    }

    fn validate(&self, header: &JournalHeader) -> Result<(), JournalError> {
        if self.session_id != header.session_id {
            return Err(JournalError::invalid(
                "sample session ID differs from journal header",
            ));
        }
        validate_text(&self.session_id, "sample session ID", 256)?;
        validate_text(&self.source_api, "source API", MAX_JOURNAL_TEXT_BYTES)?;
        if self.source_api.is_empty() {
            return Err(JournalError::invalid("source API must be nonempty"));
        }
        validate_optional_text(self.source_device_id.as_deref(), "source device ID")?;
        validate_optional_text(self.stroke_id.as_deref(), "stroke ID")?;
        validate_optional_text(self.config_id.as_deref(), "sample configuration ID")?;
        if self.stroke_id.as_deref() == Some("") {
            return Err(JournalError::invalid("present stroke ID must be nonempty"));
        }
        if let Some(position) = &self.position {
            validate_text(
                &position.coordinate_space,
                "coordinate space",
                MAX_JOURNAL_TEXT_BYTES,
            )?;
            validate_text(&position.units, "position units", MAX_JOURNAL_TEXT_BYTES)?;
            if position.coordinate_space.is_empty() || position.units.is_empty() {
                return Err(JournalError::invalid(
                    "position coordinate space and units must be nonempty",
                ));
            }
        }
        if let Some(pressure) = &self.pressure {
            validate_text(
                &pressure.representation,
                "pressure representation",
                MAX_JOURNAL_TEXT_BYTES,
            )?;
            validate_text(&pressure.units, "pressure units", MAX_JOURNAL_TEXT_BYTES)?;
            if pressure.representation.is_empty() || pressure.units.is_empty() {
                return Err(JournalError::invalid(
                    "pressure representation and units must be nonempty",
                ));
            }
            if let (Some(minimum), Some(maximum)) = (pressure.minimum_raw, pressure.maximum_raw)
                && minimum > maximum
            {
                return Err(JournalError::invalid(
                    "pressure minimum exceeds maximum in the declared raw range",
                ));
            }
        }
        if let Some(timestamp) = &self.native_timestamp {
            validate_text(
                &timestamp.clock_domain,
                "native clock domain",
                MAX_JOURNAL_TEXT_BYTES,
            )?;
            validate_text(
                &timestamp.units,
                "native timestamp units",
                MAX_JOURNAL_TEXT_BYTES,
            )?;
            if timestamp.clock_domain.is_empty() || timestamp.units.is_empty() {
                return Err(JournalError::invalid(
                    "native clock domain and units must be nonempty",
                ));
            }
            if timestamp.frequency_hz == Some(0) {
                return Err(JournalError::invalid(
                    "native clock frequency must be positive when present",
                ));
            }
        }
        validate_optional_text(self.contact_range_state.as_deref(), "contact/range state")?;
        if self.raw_payload.len() > MAX_RAW_PAYLOAD_BYTES {
            return Err(JournalError::limit(format!(
                "raw source payload exceeds {MAX_RAW_PAYLOAD_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

impl JournalMetadata {
    fn validate_shape(&self) -> Result<(), JournalError> {
        validate_text(&self.scope_id, "metadata scope ID", MAX_JOURNAL_TEXT_BYTES)?;
        validate_text(&self.key, "metadata key", MAX_METADATA_TEXT_BYTES)?;
        validate_text(&self.value, "metadata value", MAX_METADATA_TEXT_BYTES)?;
        validate_text(
            &self.provenance,
            "metadata provenance",
            MAX_METADATA_TEXT_BYTES,
        )?;
        if self.scope_id.is_empty() || self.key.is_empty() || self.provenance.is_empty() {
            return Err(JournalError::invalid(
                "metadata scope ID, key, and provenance must be nonempty",
            ));
        }
        validate_optional_text(self.source_api.as_deref(), "metadata source API")?;
        validate_optional_text(self.device_id.as_deref(), "metadata device ID")?;
        match self.scope {
            MetadataScope::Session => {
                if self.source_api.is_some() || self.device_id.is_some() {
                    return Err(JournalError::invalid(
                        "session metadata cannot carry device scope identifiers",
                    ));
                }
            }
            MetadataScope::Device => {
                let source_api = self.source_api.as_deref().unwrap_or_default();
                let device_id = self.device_id.as_deref().unwrap_or_default();
                if source_api.is_empty() || device_id.is_empty() || self.scope_id != device_id {
                    return Err(JournalError::invalid(
                        "device metadata requires matching nonempty API and device identifiers",
                    ));
                }
            }
            MetadataScope::Configuration => {
                if self.device_id.is_some() && self.source_api.is_none() {
                    return Err(JournalError::invalid(
                        "device-specific configuration metadata requires a source API",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate(&self, header: &JournalHeader) -> Result<(), JournalError> {
        self.validate_shape()?;
        if self.scope == MetadataScope::Session && self.scope_id != header.session_id {
            return Err(JournalError::invalid(
                "session metadata ID differs from journal header",
            ));
        }
        Ok(())
    }
}

impl JournalReplayState {
    fn contains_stroke(&self, target: &StrokeRef) -> bool {
        self.stroke_domains.contains_key(target)
    }

    fn index_sample(&mut self, sample: &PhysicalSample) -> Result<(), JournalError> {
        let Some(stroke) = sample.stroke_ref() else {
            return Ok(());
        };
        let Some(position) = &sample.position else {
            if !self.stroke_domains.contains_key(&stroke) {
                self.stroke_domains
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.stroke_domains.insert(stroke, HashSet::new());
            }
            return Ok(());
        };
        if let Some(transform) = self.move_totals.get(&stroke)
            && (transform.coordinate_space != position.coordinate_space
                || transform.units != position.units)
        {
            return Err(JournalError::invalid(
                "a moved stroke cannot add physical samples from a different position domain",
            ));
        }
        if let Some(domains) = self.stroke_domains.get_mut(&stroke) {
            let domain = (position.coordinate_space.clone(), position.units.clone());
            if !domains.contains(&domain) {
                domains.try_reserve(1).map_err(JournalError::allocation)?;
                domains.insert(domain);
            }
        } else {
            self.stroke_domains
                .try_reserve(1)
                .map_err(JournalError::allocation)?;
            let mut domains = HashSet::new();
            domains.try_reserve(1).map_err(JournalError::allocation)?;
            domains.insert((position.coordinate_space.clone(), position.units.clone()));
            self.stroke_domains.insert(stroke, domains);
        }
        Ok(())
    }

    fn prepare_move(
        &mut self,
        target: &StrokeRef,
        delta_x_raw: i64,
        delta_y_raw: i64,
        coordinate_space: &str,
        units: &str,
    ) -> Result<(), JournalError> {
        let domains = self.stroke_domains.get(target).ok_or_else(|| {
            JournalError::invalid("move target has no observed physical position")
        })?;
        if domains.len() != 1 || !domains.contains(&(coordinate_space.to_owned(), units.to_owned()))
        {
            return Err(JournalError::invalid(
                "move must match the stroke's single observed raw position domain",
            ));
        }
        if let Some(transform) = self.move_totals.get_mut(target) {
            if transform.coordinate_space != coordinate_space || transform.units != units {
                return Err(JournalError::invalid(
                    "moves for one stroke use inconsistent position domains",
                ));
            }
            transform
                .delta_x_raw
                .checked_add(delta_x_raw)
                .ok_or_else(|| JournalError::invalid("combined move x delta overflow"))?;
            transform
                .delta_y_raw
                .checked_add(delta_y_raw)
                .ok_or_else(|| JournalError::invalid("combined move y delta overflow"))?;
        } else {
            self.move_totals
                .try_reserve(1)
                .map_err(JournalError::allocation)?;
            self.move_totals.insert(
                target.clone(),
                ProjectedTransform {
                    coordinate_space: coordinate_space.to_owned(),
                    units: units.to_owned(),
                    delta_x_raw: 0,
                    delta_y_raw: 0,
                },
            );
        }
        Ok(())
    }

    fn apply_move_total(&mut self, target: &StrokeRef, delta_x_raw: i64, delta_y_raw: i64) {
        let transform = self
            .move_totals
            .get_mut(target)
            .expect("move transform was reserved during record validation");
        transform.delta_x_raw = transform
            .delta_x_raw
            .checked_add(delta_x_raw)
            .expect("move delta was checked during record validation");
        transform.delta_y_raw = transform
            .delta_y_raw
            .checked_add(delta_y_raw)
            .expect("move delta was checked during record validation");
    }

    fn prepare_record(
        &mut self,
        header: &JournalHeader,
        record: &JournalRecord,
    ) -> Result<(), JournalError> {
        let expected = self.last_sequence.saturating_add(1);
        if record.sequence != expected {
            return Err(JournalError::invalid(format!(
                "journal sequence {} is not the next ordered value {expected}",
                record.sequence
            )));
        }
        match &record.event {
            JournalEvent::PhysicalSample(sample) => {
                sample.validate(header)?;
                if self.physical_samples.len() >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::limit("physical sample record cap reached"));
                }
                self.physical_samples
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.index_sample(sample)?;
            }
            JournalEvent::Metadata(metadata) => {
                metadata.validate(header)?;
                if self.metadata_history.len() >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::limit("journal metadata history cap reached"));
                }
                self.metadata_history
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
            JournalEvent::Revision {
                revision_id,
                parent_revision,
                note,
                ..
            } => {
                if *parent_revision != self.logical_revision
                    || *revision_id != self.logical_revision.saturating_add(1)
                {
                    return Err(JournalError::invalid(
                        "logical revision does not extend the current parent revision",
                    ));
                }
                validate_optional_text(Some(note), "revision note")?;
            }
            JournalEvent::Tombstone {
                logical_revision,
                target,
                ..
            } => {
                self.validate_logical_target(*logical_revision, target)?;
                if self.tombstone_set.contains(target) {
                    return Err(JournalError::invalid(
                        "stroke already has a tombstone in this journal history",
                    ));
                }
                self.tombstones
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.tombstone_set
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.tombstone_set.insert(target.clone());
            }
            JournalEvent::StrokeMove {
                logical_revision,
                target,
                delta_x_raw,
                delta_y_raw,
                coordinate_space,
                units,
                ..
            } => {
                self.validate_logical_target(*logical_revision, target)?;
                validate_text(
                    coordinate_space,
                    "move coordinate space",
                    MAX_JOURNAL_TEXT_BYTES,
                )?;
                validate_text(units, "move units", MAX_JOURNAL_TEXT_BYTES)?;
                if coordinate_space.is_empty() || units.is_empty() {
                    return Err(JournalError::invalid(
                        "move coordinate space and units must be nonempty",
                    ));
                }
                self.moves
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.prepare_move(target, *delta_x_raw, *delta_y_raw, coordinate_space, units)?;
            }
            JournalEvent::UserCorrection {
                logical_revision,
                target,
                corrected_text,
                ..
            } => {
                self.validate_logical_target(*logical_revision, target)?;
                validate_optional_text(Some(corrected_text), "corrected text")?;
                self.corrections
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
        }
        Ok(())
    }

    fn validate_logical_target(
        &self,
        logical_revision: u64,
        target: &StrokeRef,
    ) -> Result<(), JournalError> {
        if logical_revision == 0 || logical_revision != self.logical_revision {
            return Err(JournalError::invalid(
                "logical operation does not target the current nonzero revision",
            ));
        }
        validate_stroke_ref(target)?;
        if !self.contains_stroke(target) {
            return Err(JournalError::invalid(
                "logical target does not identify an observed source/device/pointer/stroke",
            ));
        }
        Ok(())
    }

    fn apply_prepared(&mut self, record: JournalRecord) {
        let JournalRecord { sequence, event } = record;
        match event {
            JournalEvent::PhysicalSample(sample) => {
                self.physical_samples.push(StoredPhysicalSample {
                    sequence,
                    sample: *sample,
                });
            }
            JournalEvent::Metadata(metadata) => {
                self.metadata_history
                    .push(StoredMetadata { sequence, metadata });
            }
            JournalEvent::Revision { revision_id, .. } => {
                self.logical_revision = revision_id;
            }
            JournalEvent::Tombstone { target, .. } => self.tombstones.push(target),
            JournalEvent::StrokeMove {
                logical_revision,
                target,
                delta_x_raw,
                delta_y_raw,
                coordinate_space,
                units,
                ..
            } => {
                self.apply_move_total(&target, delta_x_raw, delta_y_raw);
                self.moves.push(StoredMove {
                    sequence,
                    logical_revision,
                    target,
                    delta_x_raw,
                    delta_y_raw,
                    coordinate_space,
                    units,
                });
            }
            JournalEvent::UserCorrection {
                logical_revision,
                target,
                corrected_text,
                ..
            } => self.corrections.push(StoredCorrection {
                sequence,
                logical_revision,
                target,
                corrected_text,
            }),
        }
        self.last_sequence = sequence;
    }

    pub(crate) fn projected_samples(&self) -> Result<Vec<ProjectedSample<'_>>, JournalError> {
        let mut projected = Vec::new();
        projected
            .try_reserve(self.physical_samples.len())
            .map_err(JournalError::allocation)?;
        for stored in &self.physical_samples {
            let stroke = stored.sample.stroke_ref();
            if stroke
                .as_ref()
                .is_some_and(|stroke| self.tombstone_set.contains(stroke))
            {
                continue;
            }
            let mut effective_position = stored.sample.position.clone();
            if let Some(stroke) = &stroke
                && let Some(transform) = self.move_totals.get(stroke)
                && let Some(position) = effective_position.as_mut()
            {
                if position.coordinate_space != transform.coordinate_space
                    || position.units != transform.units
                {
                    return Err(JournalError::invalid(
                        "stored move cannot be projected onto this position domain",
                    ));
                }
                position.x_raw = position
                    .x_raw
                    .checked_add(transform.delta_x_raw)
                    .ok_or_else(|| JournalError::invalid("projected x coordinate overflow"))?;
                position.y_raw = position
                    .y_raw
                    .checked_add(transform.delta_y_raw)
                    .ok_or_else(|| JournalError::invalid("projected y coordinate overflow"))?;
            }
            projected.push(ProjectedSample {
                sequence: stored.sequence,
                sample: &stored.sample,
                effective_position,
            });
        }
        Ok(projected)
    }
}

impl JournalWriter {
    pub(crate) fn create(path: PathBuf, header: JournalHeader) -> Result<Self, JournalError> {
        header.validate()?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(JournalError::io)?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)
            .map_err(JournalError::io)?;
        let header_line = encode_row(&encode_header_fields(&header, JOURNAL_SCHEMA_VERSION))?;
        if header_line.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalError::limit(
                "journal header exceeds the file byte cap",
            ));
        }
        let mut writer = Self {
            path,
            file,
            header,
            state: JournalReplayState::default(),
            bytes_written: 0,
            prefix_fingerprint: FNV_OFFSET_BASIS,
            poisoned: false,
            recovered_truncated_final_record: false,
            #[cfg(test)]
            fail_next_sync_after_write: false,
            #[cfg(test)]
            fail_next_flush: false,
        };
        writer
            .file
            .write_all(&header_line)
            .map_err(JournalError::io)?;
        writer.file.sync_all().map_err(JournalError::io)?;
        writer.bytes_written = header_line.len() as u64;
        writer.prefix_fingerprint = fnv_update(writer.prefix_fingerprint, &header_line);
        Ok(writer)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Opens an existing valid journal for append. A torn final line is
    /// explicitly truncated to the last validated record boundary; malformed
    /// complete records and interior corruption are rejected by the parser.
    pub(crate) fn open_append(path: PathBuf) -> Result<Self, JournalError> {
        let parsed = read_journal(&path)?;
        if parsed.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalError::invalid(
                "legacy journal is read-only; migrate into a new schema 2 journal before append",
            ));
        }
        let recovered_truncated_final_record = parsed.recovery.truncated_final_record;
        let valid_prefix_bytes = parsed.recovery.valid_prefix_bytes;
        let prefix_fingerprint = parsed
            .checkpoints
            .last()
            .map(|checkpoint| checkpoint.fingerprint)
            .ok_or_else(|| JournalError::invalid("journal has no validated header prefix"))?;
        if recovered_truncated_final_record {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(JournalError::io)?;
            file.set_len(valid_prefix_bytes).map_err(JournalError::io)?;
            file.sync_all().map_err(JournalError::io)?;
        }
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(JournalError::io)?;
        Ok(Self {
            path,
            file,
            header: parsed.header,
            state: parsed.state,
            bytes_written: valid_prefix_bytes,
            prefix_fingerprint,
            poisoned: false,
            recovered_truncated_final_record,
            #[cfg(test)]
            fail_next_sync_after_write: false,
            #[cfg(test)]
            fail_next_flush: false,
        })
    }

    pub(crate) fn recovered_truncated_final_record(&self) -> bool {
        self.recovered_truncated_final_record
    }

    pub(crate) fn logical_revision(&self) -> u64 {
        self.state.logical_revision
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn append_sample(&mut self, sample: PhysicalSample) -> Result<u64, JournalError> {
        self.append_event(JournalEvent::PhysicalSample(Box::new(sample)))
    }

    pub(crate) fn append_metadata(
        &mut self,
        metadata: JournalMetadata,
    ) -> Result<u64, JournalError> {
        self.append_event(JournalEvent::Metadata(metadata))
    }

    pub(crate) fn begin_revision(
        &mut self,
        app_arrival_elapsed_ns: u128,
        note: String,
    ) -> Result<u64, JournalError> {
        let parent_revision = self.state.logical_revision;
        let revision_id = parent_revision
            .checked_add(1)
            .ok_or_else(|| JournalError::limit("logical revision counter overflow"))?;
        self.append_event(JournalEvent::Revision {
            revision_id,
            parent_revision,
            app_arrival_elapsed_ns,
            note,
        })?;
        Ok(revision_id)
    }

    pub(crate) fn tombstone(
        &mut self,
        app_arrival_elapsed_ns: u128,
        target: StrokeRef,
    ) -> Result<u64, JournalError> {
        self.append_event(JournalEvent::Tombstone {
            logical_revision: self.state.logical_revision,
            app_arrival_elapsed_ns,
            target,
        })
    }

    pub(crate) fn move_stroke(
        &mut self,
        app_arrival_elapsed_ns: u128,
        target: StrokeRef,
        delta_x_raw: i64,
        delta_y_raw: i64,
        coordinate_space: String,
        units: String,
    ) -> Result<u64, JournalError> {
        self.append_event(JournalEvent::StrokeMove {
            logical_revision: self.state.logical_revision,
            app_arrival_elapsed_ns,
            target,
            delta_x_raw,
            delta_y_raw,
            coordinate_space,
            units,
        })
    }

    pub(crate) fn correct_stroke(
        &mut self,
        app_arrival_elapsed_ns: u128,
        target: StrokeRef,
        corrected_text: String,
    ) -> Result<u64, JournalError> {
        self.append_event(JournalEvent::UserCorrection {
            logical_revision: self.state.logical_revision,
            app_arrival_elapsed_ns,
            target,
            corrected_text,
        })
    }

    /// Writes a single materialized checkpoint beside the journal. The
    /// checkpoint is no-clobber and is never a substitute for journal rows.
    pub(crate) fn write_snapshot(&mut self, snapshot_path: &Path) -> Result<(), JournalError> {
        self.flush()?;
        let materialized = MaterializedState {
            journal_id: self.header.journal_id.clone(),
            prefix_bytes: self.bytes_written,
            prefix_sequence: self.state.last_sequence,
            logical_revision: self.state.logical_revision,
            prefix_fingerprint: self.prefix_fingerprint,
            state: self.state.clone(),
        };
        let bytes = encode_snapshot(&materialized)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(snapshot_path)
            .map_err(JournalError::io)?;
        if let Err(error) = file.write_all(&bytes) {
            return Err(JournalError::io(error));
        }
        file.sync_all().map_err(JournalError::io)
    }

    fn append_event(&mut self, event: JournalEvent) -> Result<u64, JournalError> {
        if self.poisoned {
            return Err(JournalError::poisoned());
        }
        if self.state.last_sequence as usize >= MAX_JOURNAL_RECORDS {
            return Err(JournalError::limit("journal record cap reached"));
        }
        let sequence = self
            .state
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| JournalError::limit("journal sequence counter overflow"))?;
        let record = JournalRecord { sequence, event };
        validate_record_before_encoding(&self.header, &record)?;
        let line = encode_row(&encode_record_fields(&record)?)?;
        if line.len() > MAX_JOURNAL_LINE_BYTES {
            return Err(JournalError::limit("journal record exceeds line cap"));
        }
        if self.bytes_written.saturating_add(line.len() as u64) > MAX_JOURNAL_BYTES {
            return Err(JournalError::limit("journal byte cap reached"));
        }
        self.state.prepare_record(&self.header, &record)?;

        if let Err(error) = self.file.write_all(&line) {
            self.poisoned = true;
            return Err(JournalError::io(error));
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_sync_after_write) {
            self.poisoned = true;
            return Err(JournalError::io(
                "simulated sync failure after complete record write",
            ));
        }
        if let Err(error) = self.file.sync_data() {
            self.poisoned = true;
            return Err(JournalError::io(error));
        }

        self.state.apply_prepared(record);
        self.bytes_written = self.bytes_written.saturating_add(line.len() as u64);
        self.prefix_fingerprint = fnv_update(self.prefix_fingerprint, &line);
        Ok(sequence)
    }

    pub(crate) fn flush(&mut self) -> Result<(), JournalError> {
        if self.poisoned {
            return Err(JournalError::poisoned());
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_flush) {
            self.poisoned = true;
            return Err(JournalError::io("simulated flush failure"));
        }
        if let Err(error) = self.file.sync_all() {
            self.poisoned = true;
            return Err(JournalError::io(error));
        }
        Ok(())
    }
}

pub(crate) fn read_journal(path: &Path) -> Result<JournalReadResult, JournalError> {
    let metadata = fs::metadata(path).map_err(JournalError::io)?;
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::limit("journal file exceeds the byte cap"));
    }
    let file = File::open(path).map_err(JournalError::io)?;
    parse_journal(file)
}

/// Migrates a readable schema-1 journal into a new schema-2 journal with a
/// caller-supplied new identity. Source bytes remain untouched. If the source
/// had a torn final line, only its validated prefix is migrated and the result
/// reports that recovery status to the caller.
pub(crate) fn migrate_schema_one_to_two(
    source_path: &Path,
    destination_path: PathBuf,
    new_journal_id: String,
) -> Result<JournalMigrationResult, JournalError> {
    let source = read_journal(source_path)?;
    if source.schema_version != LEGACY_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::invalid(
            "only schema 1 journals can be migrated by this migration function",
        ));
    }
    if new_journal_id == source.header.journal_id {
        return Err(JournalError::invalid(
            "migration requires a new journal identity",
        ));
    }
    let mut header = source.header.clone();
    header.journal_id = new_journal_id;
    let mut writer = JournalWriter::create(destination_path.clone(), header)?;
    let mut migrated_records = 0u64;
    for source_record in source.records {
        let sequence = writer.append_event(source_record.event)?;
        migrated_records = migrated_records.saturating_add(1);
        if sequence != migrated_records {
            return Err(JournalError::invalid(
                "schema migration did not preserve validated source ordering",
            ));
        }
    }
    writer.flush()?;
    Ok(JournalMigrationResult {
        destination_path,
        source_truncated_final_record: source.recovery.truncated_final_record,
        migrated_records,
    })
}

pub(crate) fn parse_journal(reader: impl Read) -> Result<JournalReadResult, JournalError> {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    let mut total_bytes = 0u64;
    let mut valid_prefix_bytes = 0u64;
    let mut truncated_final_record = false;
    let mut header: Option<JournalHeader> = None;
    let mut schema_version = 0u32;
    let mut state = JournalReplayState::default();
    let mut records = Vec::new();
    let mut checkpoints = Vec::new();
    let mut fingerprint = FNV_OFFSET_BASIS;

    loop {
        line.clear();
        let Some(line_complete) = read_bounded_line(&mut reader, &mut line)? else {
            break;
        };
        total_bytes = total_bytes.saturating_add(line.len() as u64);
        if total_bytes > MAX_JOURNAL_BYTES {
            return Err(JournalError::limit("journal file exceeds the byte cap"));
        }
        if !line_complete {
            if header.is_none() {
                return Err(JournalError::invalid(
                    "journal ends before a complete header record",
                ));
            }
            truncated_final_record = true;
            break;
        }
        let complete_line_len = line.len() as u64;
        fingerprint = fnv_update(fingerprint, &line);
        valid_prefix_bytes = valid_prefix_bytes.saturating_add(complete_line_len);
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| JournalError::invalid("journal record is not UTF-8"))?;
        let fields = text.split('\t').collect::<Vec<_>>();
        if header.is_none() {
            let (version, parsed_header) = parse_header_fields(&fields)?;
            schema_version = version;
            header = Some(parsed_header);
            checkpoints.push(PrefixCheckpoint {
                sequence: 0,
                logical_revision: 0,
                byte_len: valid_prefix_bytes,
                fingerprint,
            });
            continue;
        }
        if records.len() >= MAX_JOURNAL_RECORDS {
            return Err(JournalError::limit("journal record cap reached"));
        }
        let record = parse_record_fields(schema_version, &fields)?;
        state.prepare_record(header.as_ref().expect("header was parsed"), &record)?;
        records.try_reserve(1).map_err(JournalError::allocation)?;
        let sequence = record.sequence;
        state.apply_prepared(record.clone());
        records.push(record);
        checkpoints.push(PrefixCheckpoint {
            sequence,
            logical_revision: state.logical_revision,
            byte_len: valid_prefix_bytes,
            fingerprint,
        });
    }

    let header = header.ok_or_else(|| JournalError::invalid("journal file is empty"))?;
    Ok(JournalReadResult {
        schema_version,
        header,
        records,
        state,
        recovery: JournalRecovery {
            truncated_final_record,
            valid_prefix_bytes,
        },
        checkpoints,
    })
}

pub(crate) fn default_snapshot_path(journal_path: &Path) -> PathBuf {
    let mut name = journal_path.as_os_str().to_owned();
    name.push(".snapshot");
    PathBuf::from(name)
}

pub(crate) fn load_with_snapshot(
    journal_path: &Path,
    snapshot_path: &Path,
) -> Result<SnapshotReplayResult, JournalError> {
    let journal = read_journal(journal_path)?;
    let full_state = journal.state.clone();
    let snapshot_file = match File::open(snapshot_path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SnapshotReplayResult {
                state: full_state,
                recovery: journal.recovery,
                disposition: SnapshotDisposition::Missing,
                replayed_tail_records: 0,
            });
        }
        Err(error) => {
            return Ok(SnapshotReplayResult {
                state: full_state,
                recovery: journal.recovery,
                disposition: SnapshotDisposition::Rejected(format!(
                    "snapshot open failed: {error}"
                )),
                replayed_tail_records: 0,
            });
        }
    };
    let snapshot = match parse_snapshot(snapshot_file) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Ok(SnapshotReplayResult {
                state: full_state,
                recovery: journal.recovery,
                disposition: SnapshotDisposition::Rejected(error.to_string()),
                replayed_tail_records: 0,
            });
        }
    };
    if snapshot.journal_id != journal.header.journal_id {
        return Ok(SnapshotReplayResult {
            state: full_state,
            recovery: journal.recovery,
            disposition: SnapshotDisposition::Rejected(
                "snapshot journal identity does not match".to_owned(),
            ),
            replayed_tail_records: 0,
        });
    }
    let checkpoint = journal.checkpoints.iter().find(|checkpoint| {
        checkpoint.sequence == snapshot.prefix_sequence
            && checkpoint.logical_revision == snapshot.logical_revision
            && checkpoint.byte_len == snapshot.prefix_bytes
            && checkpoint.fingerprint == snapshot.prefix_fingerprint
    });
    if checkpoint.is_none() {
        return Ok(SnapshotReplayResult {
            state: full_state,
            recovery: journal.recovery,
            disposition: SnapshotDisposition::Rejected(
                "snapshot does not identify a validated journal prefix/revision".to_owned(),
            ),
            replayed_tail_records: 0,
        });
    }

    let mut prefix_state = JournalReplayState::default();
    for record in journal
        .records
        .iter()
        .take_while(|record| record.sequence <= snapshot.prefix_sequence)
    {
        prefix_state.prepare_record(&journal.header, record)?;
        prefix_state.apply_prepared(record.clone());
    }
    if prefix_state != snapshot.state {
        return Ok(SnapshotReplayResult {
            state: full_state,
            recovery: journal.recovery,
            disposition: SnapshotDisposition::Rejected(
                "snapshot materialized state differs from replayed journal prefix".to_owned(),
            ),
            replayed_tail_records: 0,
        });
    }

    let mut state = snapshot.state;
    let mut replayed_tail_records = 0usize;
    for record in journal
        .records
        .iter()
        .filter(|record| record.sequence > checkpoint.expect("checked above").sequence)
    {
        state.prepare_record(&journal.header, record)?;
        state.apply_prepared(record.clone());
        replayed_tail_records = replayed_tail_records.saturating_add(1);
    }
    Ok(SnapshotReplayResult {
        state,
        recovery: journal.recovery,
        disposition: SnapshotDisposition::Used,
        replayed_tail_records,
    })
}

fn parse_snapshot(reader: impl Read) -> Result<ParsedSnapshot, JournalError> {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    let mut total_bytes = 0u64;
    let mut saw_header = false;
    let mut saw_end = false;
    let mut total_state_entries = 0usize;
    let mut parsed: Option<ParsedSnapshot> = None;
    let mut expected_state_fingerprint: Option<u64> = None;
    let mut state_fingerprint = FNV_OFFSET_BASIS;

    loop {
        line.clear();
        let Some(line_complete) = read_bounded_line(&mut reader, &mut line)? else {
            break;
        };
        total_bytes = total_bytes.saturating_add(line.len() as u64);
        if total_bytes > MAX_JOURNAL_BYTES {
            return Err(JournalError::limit("snapshot file exceeds the byte cap"));
        }
        if !line_complete {
            return Err(JournalError::invalid("snapshot ends in a truncated record"));
        }
        if saw_end {
            return Err(JournalError::invalid(
                "snapshot contains data after ENDSNAP",
            ));
        }
        let is_header = !saw_header;
        if !is_header {
            state_fingerprint = fnv_update(state_fingerprint, &line);
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| JournalError::invalid("snapshot record is not UTF-8"))?;
        let fields = text.split('\t').collect::<Vec<_>>();
        if is_header {
            require_fields(&fields, 8, "LASSOINK-SNAPSHOT")?;
            if fields[0] != "LASSOINK-SNAPSHOT" || fields[1] != "1" {
                return Err(JournalError::invalid("unsupported snapshot header"));
            }
            let prefix_fingerprint = parse_hex_u64(fields[6], "snapshot prefix fingerprint")?;
            let state_fingerprint_expected =
                parse_hex_u64(fields[7], "snapshot state fingerprint")?;
            parsed = Some(ParsedSnapshot {
                journal_id: decode_field(fields[2])?,
                prefix_bytes: parse_u64(fields[3], "snapshot prefix byte length")?,
                prefix_sequence: parse_u64(fields[4], "snapshot prefix sequence")?,
                logical_revision: parse_u64(fields[5], "snapshot logical revision")?,
                prefix_fingerprint,
                state: JournalReplayState::default(),
            });
            expected_state_fingerprint = Some(state_fingerprint_expected);
            saw_header = true;
            continue;
        }

        let snapshot = parsed.as_mut().expect("snapshot header has been parsed");
        match fields.first().copied().unwrap_or_default() {
            "SP" => {
                if total_state_entries >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sample = parse_sample_fields(&fields, JOURNAL_SCHEMA_VERSION)?;
                let sequence = parse_u64(fields[1], "snapshot sample sequence")?;
                if sequence > snapshot.prefix_sequence {
                    return Err(JournalError::invalid(
                        "snapshot sample is past its declared prefix",
                    ));
                }
                snapshot
                    .state
                    .physical_samples
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot.state.index_sample(&sample)?;
                snapshot
                    .state
                    .physical_samples
                    .push(StoredPhysicalSample { sequence, sample });
            }
            "SMD" => {
                if total_state_entries >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot metadata sequence")?;
                if sequence > snapshot.prefix_sequence {
                    return Err(JournalError::invalid(
                        "snapshot metadata is past its declared prefix",
                    ));
                }
                let metadata = parse_metadata_fields(&fields)?;
                snapshot
                    .state
                    .metadata_history
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .metadata_history
                    .push(StoredMetadata { sequence, metadata });
            }
            "ST" => {
                require_fields(&fields, 5, "ST")?;
                if total_state_entries >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let target = parse_stroke_ref_fields(&fields, 1)?;
                snapshot
                    .state
                    .tombstones
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .tombstone_set
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                if !snapshot.state.tombstone_set.insert(target.clone()) {
                    return Err(JournalError::invalid(
                        "duplicate stroke tombstone in snapshot",
                    ));
                }
                snapshot.state.tombstones.push(target);
            }
            "SM" => {
                require_fields(&fields, 11, "SM")?;
                if total_state_entries >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot move sequence")?;
                let logical_revision = parse_u64(fields[2], "snapshot move revision")?;
                if sequence > snapshot.prefix_sequence
                    || logical_revision > snapshot.logical_revision
                {
                    return Err(JournalError::invalid(
                        "snapshot move is past its declared prefix/revision",
                    ));
                }
                snapshot
                    .state
                    .moves
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                let target = parse_stroke_ref_fields(&fields, 3)?;
                let delta_x_raw = parse_i64(fields[7], "snapshot move delta x")?;
                let delta_y_raw = parse_i64(fields[8], "snapshot move delta y")?;
                let coordinate_space = decode_field(fields[9])?;
                let units = decode_field(fields[10])?;
                snapshot.state.prepare_move(
                    &target,
                    delta_x_raw,
                    delta_y_raw,
                    &coordinate_space,
                    &units,
                )?;
                snapshot
                    .state
                    .apply_move_total(&target, delta_x_raw, delta_y_raw);
                snapshot.state.moves.push(StoredMove {
                    sequence,
                    logical_revision,
                    target,
                    delta_x_raw,
                    delta_y_raw,
                    coordinate_space,
                    units,
                });
            }
            "SC" => {
                require_fields(&fields, 8, "SC")?;
                if total_state_entries >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot correction sequence")?;
                let logical_revision = parse_u64(fields[2], "snapshot correction revision")?;
                if sequence > snapshot.prefix_sequence
                    || logical_revision > snapshot.logical_revision
                {
                    return Err(JournalError::invalid(
                        "snapshot correction is past its declared prefix/revision",
                    ));
                }
                snapshot
                    .state
                    .corrections
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot.state.corrections.push(StoredCorrection {
                    sequence,
                    logical_revision,
                    target: parse_stroke_ref_fields(&fields, 3)?,
                    corrected_text: decode_field(fields[7])?,
                });
            }
            "ENDSNAP" => {
                require_fields(&fields, 1, "ENDSNAP")?;
                saw_end = true;
            }
            other => {
                return Err(JournalError::invalid(format!(
                    "unknown snapshot record tag {other:?}"
                )));
            }
        }
        if !saw_end {
            total_state_entries = total_state_entries.saturating_add(1);
        }
    }
    if !saw_header || !saw_end {
        return Err(JournalError::invalid(
            "snapshot is missing its header or ENDSNAP",
        ));
    }
    let snapshot = parsed.as_mut().expect("snapshot header has been parsed");
    snapshot.state.last_sequence = snapshot.prefix_sequence;
    snapshot.state.logical_revision = snapshot.logical_revision;
    let expected = expected_state_fingerprint
        .take()
        .ok_or_else(|| JournalError::invalid("snapshot fingerprint header is missing"))?;
    if state_fingerprint != expected {
        return Err(JournalError::invalid("snapshot state fingerprint mismatch"));
    }
    Ok(parsed.expect("snapshot header has been parsed"))
}

fn encode_snapshot(materialized: &MaterializedState) -> Result<Vec<u8>, JournalError> {
    if materialized.state.last_sequence != materialized.prefix_sequence
        || materialized.state.logical_revision != materialized.logical_revision
    {
        return Err(JournalError::invalid(
            "snapshot prefix metadata differs from materialized state",
        ));
    }
    let mut body = Vec::new();
    for stored in &materialized.state.physical_samples {
        let fields = encode_sample_fields(
            "SP",
            stored.sequence,
            &stored.sample,
            JOURNAL_SCHEMA_VERSION,
        )?;
        append_encoded_row(&mut body, &fields)?;
    }
    for stored in &materialized.state.metadata_history {
        let fields = encode_metadata_fields("SMD", stored.sequence, &stored.metadata);
        append_encoded_row(&mut body, &fields)?;
    }
    for target in &materialized.state.tombstones {
        let mut fields = vec!["ST".to_owned()];
        fields.extend(encode_stroke_ref_fields(target));
        append_encoded_row(&mut body, &fields)?;
    }
    for movement in &materialized.state.moves {
        let mut fields = vec![
            "SM".to_owned(),
            movement.sequence.to_string(),
            movement.logical_revision.to_string(),
        ];
        fields.extend(encode_stroke_ref_fields(&movement.target));
        fields.extend([
            movement.delta_x_raw.to_string(),
            movement.delta_y_raw.to_string(),
            encode_field(&movement.coordinate_space),
            encode_field(&movement.units),
        ]);
        append_encoded_row(&mut body, &fields)?;
    }
    for correction in &materialized.state.corrections {
        let mut fields = vec![
            "SC".to_owned(),
            correction.sequence.to_string(),
            correction.logical_revision.to_string(),
        ];
        fields.extend(encode_stroke_ref_fields(&correction.target));
        fields.push(encode_field(&correction.corrected_text));
        append_encoded_row(&mut body, &fields)?;
    }
    append_encoded_row(&mut body, &["ENDSNAP".to_owned()])?;
    let state_fingerprint = fnv_update(FNV_OFFSET_BASIS, &body);
    let header = vec![
        "LASSOINK-SNAPSHOT".to_owned(),
        "1".to_owned(),
        encode_field(&materialized.journal_id),
        materialized.prefix_bytes.to_string(),
        materialized.prefix_sequence.to_string(),
        materialized.logical_revision.to_string(),
        format!("{:016X}", materialized.prefix_fingerprint),
        format!("{state_fingerprint:016X}"),
    ];
    let mut bytes = encode_row(&header)?;
    bytes
        .try_reserve(body.len())
        .map_err(JournalError::allocation)?;
    bytes.extend_from_slice(&body);
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(JournalError::limit("snapshot exceeds the byte cap"));
    }
    Ok(bytes)
}

fn append_encoded_row(output: &mut Vec<u8>, fields: &[String]) -> Result<(), JournalError> {
    let row = encode_row(fields)?;
    if output.len().saturating_add(row.len()) as u64 > MAX_JOURNAL_BYTES {
        return Err(JournalError::limit("snapshot state exceeds the byte cap"));
    }
    output
        .try_reserve(row.len())
        .map_err(JournalError::allocation)?;
    output.extend_from_slice(&row);
    Ok(())
}

impl From<io::Error> for JournalError {
    fn from(error: io::Error) -> Self {
        Self::io(error)
    }
}

fn encode_header_fields(header: &JournalHeader, version: u32) -> Vec<String> {
    let mut fields = vec![
        "LASSOINK-JOURNAL".to_owned(),
        version.to_string(),
        encode_field(&header.journal_id),
        encode_field(&header.session_id),
        encode_option_text(header.config_id.as_deref()),
        encode_option_text(header.device_model_declared.as_deref()),
    ];
    if version >= 2 {
        fields.push(opt_bool(header.tilt_supported_declared));
    }
    fields
}

fn parse_header_fields(fields: &[&str]) -> Result<(u32, JournalHeader), JournalError> {
    if fields.first() != Some(&"LASSOINK-JOURNAL") {
        return Err(JournalError::invalid(
            "first journal record is not a LASSOINK-JOURNAL header",
        ));
    }
    let version = parse_u32(fields[1], "journal schema version")?;
    if !matches!(
        version,
        LEGACY_JOURNAL_SCHEMA_VERSION | JOURNAL_SCHEMA_VERSION
    ) {
        return Err(JournalError::invalid(format!(
            "unsupported journal schema version {version}"
        )));
    }
    let expected_fields = if version >= 2 { 7 } else { 6 };
    require_fields(fields, expected_fields, "LASSOINK-JOURNAL")?;
    let header = JournalHeader {
        journal_id: decode_field(fields[2])?,
        session_id: decode_field(fields[3])?,
        config_id: decode_option_text(fields[4])?,
        device_model_declared: decode_option_text(fields[5])?,
        tilt_supported_declared: if version >= 2 {
            parse_option_bool(fields[6], "declared tilt support")?
        } else {
            None
        },
    };
    header.validate()?;
    Ok((version, header))
}

/// Validates every caller-controlled string/blob before any percent/hex
/// encoder allocates. The encoded row is then bounded by fixed field counts
/// and the per-field caps; `encode_row` applies the final line cap before the
/// replay state is prepared or changed.
fn validate_record_before_encoding(
    header: &JournalHeader,
    record: &JournalRecord,
) -> Result<(), JournalError> {
    match &record.event {
        JournalEvent::PhysicalSample(sample) => sample.validate(header),
        JournalEvent::Metadata(metadata) => metadata.validate(header),
        JournalEvent::Revision { note, .. } => validate_optional_text(Some(note), "revision note"),
        JournalEvent::Tombstone { target, .. } => validate_stroke_ref(target),
        JournalEvent::StrokeMove {
            target,
            coordinate_space,
            units,
            ..
        } => {
            validate_stroke_ref(target)?;
            validate_text(
                coordinate_space,
                "move coordinate space",
                MAX_JOURNAL_TEXT_BYTES,
            )?;
            validate_text(units, "move units", MAX_JOURNAL_TEXT_BYTES)?;
            if coordinate_space.is_empty() || units.is_empty() {
                return Err(JournalError::invalid(
                    "move coordinate space and units must be nonempty",
                ));
            }
            Ok(())
        }
        JournalEvent::UserCorrection {
            target,
            corrected_text,
            ..
        } => {
            validate_stroke_ref(target)?;
            validate_optional_text(Some(corrected_text), "corrected text")
        }
    }
}

fn validate_stroke_ref(target: &StrokeRef) -> Result<(), JournalError> {
    validate_text(
        &target.source_api,
        "logical target source API",
        MAX_JOURNAL_TEXT_BYTES,
    )?;
    validate_optional_text(target.device_id.as_deref(), "logical target device ID")?;
    validate_text(
        &target.stroke_id,
        "logical target stroke ID",
        MAX_JOURNAL_TEXT_BYTES,
    )?;
    if target.source_api.is_empty() || target.stroke_id.is_empty() {
        return Err(JournalError::invalid(
            "logical target source API and stroke ID must be nonempty",
        ));
    }
    Ok(())
}

fn encode_record_fields(record: &JournalRecord) -> Result<Vec<String>, JournalError> {
    let fields = match &record.event {
        JournalEvent::PhysicalSample(sample) => {
            encode_sample_fields("P", record.sequence, sample, JOURNAL_SCHEMA_VERSION)?
        }
        JournalEvent::Metadata(metadata) => {
            encode_metadata_fields("META", record.sequence, metadata)
        }
        JournalEvent::Revision {
            revision_id,
            parent_revision,
            app_arrival_elapsed_ns,
            note,
        } => vec![
            "REV".to_owned(),
            record.sequence.to_string(),
            app_arrival_elapsed_ns.to_string(),
            revision_id.to_string(),
            parent_revision.to_string(),
            encode_field(note),
        ],
        JournalEvent::Tombstone {
            logical_revision,
            app_arrival_elapsed_ns,
            target,
        } => {
            let mut fields = vec![
                "TOMB".to_owned(),
                record.sequence.to_string(),
                app_arrival_elapsed_ns.to_string(),
                logical_revision.to_string(),
            ];
            fields.extend(encode_stroke_ref_fields(target));
            fields
        }
        JournalEvent::StrokeMove {
            logical_revision,
            app_arrival_elapsed_ns,
            target,
            delta_x_raw,
            delta_y_raw,
            coordinate_space,
            units,
        } => {
            let mut fields = vec![
                "MOVE".to_owned(),
                record.sequence.to_string(),
                app_arrival_elapsed_ns.to_string(),
                logical_revision.to_string(),
            ];
            fields.extend(encode_stroke_ref_fields(target));
            fields.extend([
                delta_x_raw.to_string(),
                delta_y_raw.to_string(),
                encode_field(coordinate_space),
                encode_field(units),
            ]);
            fields
        }
        JournalEvent::UserCorrection {
            logical_revision,
            app_arrival_elapsed_ns,
            target,
            corrected_text,
        } => {
            let mut fields = vec![
                "CORR".to_owned(),
                record.sequence.to_string(),
                app_arrival_elapsed_ns.to_string(),
                logical_revision.to_string(),
            ];
            fields.extend(encode_stroke_ref_fields(target));
            fields.push(encode_field(corrected_text));
            fields
        }
    };
    Ok(fields)
}

fn encode_sample_fields(
    tag: &str,
    sequence: u64,
    sample: &PhysicalSample,
    version: u32,
) -> Result<Vec<String>, JournalError> {
    let (position_space, position_units, position_x, position_y) =
        sample.position.as_ref().map_or_else(
            || {
                (
                    "~".to_owned(),
                    "~".to_owned(),
                    "~".to_owned(),
                    "~".to_owned(),
                )
            },
            |position| {
                (
                    encode_field(&position.coordinate_space),
                    encode_field(&position.units),
                    position.x_raw.to_string(),
                    position.y_raw.to_string(),
                )
            },
        );
    let (
        pressure_representation,
        pressure_units,
        pressure_value,
        pressure_mask,
        pressure_min,
        pressure_max,
    ) = sample.pressure.as_ref().map_or_else(
        || {
            (
                "~".to_owned(),
                "~".to_owned(),
                "~".to_owned(),
                "~".to_owned(),
                "~".to_owned(),
                "~".to_owned(),
            )
        },
        |pressure| {
            (
                encode_field(&pressure.representation),
                encode_field(&pressure.units),
                pressure.value_raw.to_string(),
                opt_u64(pressure.mask_raw),
                opt_u64(pressure.minimum_raw),
                opt_u64(pressure.maximum_raw),
            )
        },
    );
    let (clock_domain, clock_units, clock_count, clock_frequency) =
        sample.native_timestamp.as_ref().map_or_else(
            || {
                (
                    "~".to_owned(),
                    "~".to_owned(),
                    "~".to_owned(),
                    "~".to_owned(),
                )
            },
            |timestamp| {
                (
                    encode_field(&timestamp.clock_domain),
                    encode_field(&timestamp.units),
                    timestamp.count_raw.to_string(),
                    opt_u64(timestamp.frequency_hz),
                )
            },
        );

    let mut fields = vec![
        tag.to_owned(),
        sequence.to_string(),
        encode_field(&sample.session_id),
        encode_field(&sample.source_api),
        encode_option_text(sample.source_device_id.as_deref()),
        opt_u64(sample.pointer_id),
        encode_option_text(sample.stroke_id.as_deref()),
        sample.source_sequence.to_string(),
        encode_option_text(sample.config_id.as_deref()),
        sample.app_arrival_elapsed_ns.to_string(),
        position_space,
        position_units,
        position_x,
        position_y,
        pressure_representation,
        pressure_units,
        pressure_value,
    ];
    if version >= 2 {
        fields.extend([pressure_mask, pressure_min, pressure_max]);
    }
    fields.extend([
        clock_domain,
        clock_units,
        clock_count,
        clock_frequency,
        encode_option_text(sample.contact_range_state.as_deref()),
        opt_u64(sample.button_state_raw),
    ]);
    if version >= 2 {
        fields.extend([
            opt_i32(sample.tilt_x_raw),
            opt_i32(sample.tilt_y_raw),
            opt_u64(sample.rotation_raw),
        ]);
    }
    fields.push(encode_hex(&sample.raw_payload));
    Ok(fields)
}

fn encode_stroke_ref_fields(target: &StrokeRef) -> Vec<String> {
    vec![
        encode_field(&target.source_api),
        encode_option_text(target.device_id.as_deref()),
        opt_u64(target.pointer_id),
        encode_field(&target.stroke_id),
    ]
}

fn encode_metadata_fields(tag: &str, sequence: u64, metadata: &JournalMetadata) -> Vec<String> {
    vec![
        tag.to_owned(),
        sequence.to_string(),
        metadata.app_arrival_elapsed_ns.to_string(),
        encode_metadata_scope(metadata.scope).to_owned(),
        encode_field(&metadata.scope_id),
        encode_option_text(metadata.source_api.as_deref()),
        encode_option_text(metadata.device_id.as_deref()),
        encode_field(&metadata.key),
        encode_field(&metadata.value),
        encode_field(&metadata.provenance),
    ]
}

fn encode_metadata_scope(scope: MetadataScope) -> &'static str {
    match scope {
        MetadataScope::Session => "session",
        MetadataScope::Device => "device",
        MetadataScope::Configuration => "configuration",
    }
}

fn parse_metadata_fields(fields: &[&str]) -> Result<JournalMetadata, JournalError> {
    require_fields(fields, 10, "metadata")?;
    let scope = match fields[3] {
        "session" => MetadataScope::Session,
        "device" => MetadataScope::Device,
        "configuration" => MetadataScope::Configuration,
        other => {
            return Err(JournalError::invalid(format!(
                "unknown metadata scope {other:?}"
            )));
        }
    };
    let metadata = JournalMetadata {
        scope,
        scope_id: decode_field(fields[4])?,
        source_api: decode_option_text(fields[5])?,
        device_id: decode_option_text(fields[6])?,
        key: decode_field(fields[7])?,
        value: decode_field(fields[8])?,
        provenance: decode_field(fields[9])?,
        app_arrival_elapsed_ns: parse_u128(fields[2], "metadata app arrival")?,
    };
    metadata.validate_shape()?;
    Ok(metadata)
}

fn parse_record_fields(version: u32, fields: &[&str]) -> Result<JournalRecord, JournalError> {
    let tag = fields
        .first()
        .ok_or_else(|| JournalError::invalid("empty journal record"))?;
    match *tag {
        "P" => {
            let sample = parse_sample_fields(fields, version)?;
            let sequence = parse_u64(fields[1], "sample event sequence")?;
            Ok(JournalRecord {
                sequence,
                event: JournalEvent::PhysicalSample(Box::new(sample)),
            })
        }
        "META" => {
            let metadata = parse_metadata_fields(fields)?;
            Ok(JournalRecord {
                sequence: parse_u64(fields[1], "metadata event sequence")?,
                event: JournalEvent::Metadata(metadata),
            })
        }
        "REV" => {
            require_fields(fields, 6, "REV")?;
            Ok(JournalRecord {
                sequence: parse_u64(fields[1], "revision event sequence")?,
                event: JournalEvent::Revision {
                    app_arrival_elapsed_ns: parse_u128(fields[2], "revision app arrival")?,
                    revision_id: parse_u64(fields[3], "logical revision ID")?,
                    parent_revision: parse_u64(fields[4], "parent logical revision")?,
                    note: decode_field(fields[5])?,
                },
            })
        }
        "TOMB" => {
            require_fields(fields, 8, "TOMB")?;
            Ok(JournalRecord {
                sequence: parse_u64(fields[1], "tombstone sequence")?,
                event: JournalEvent::Tombstone {
                    app_arrival_elapsed_ns: parse_u128(fields[2], "tombstone app arrival")?,
                    logical_revision: parse_u64(fields[3], "tombstone revision")?,
                    target: parse_stroke_ref_fields(fields, 4)?,
                },
            })
        }
        "MOVE" => {
            require_fields(fields, 12, "MOVE")?;
            Ok(JournalRecord {
                sequence: parse_u64(fields[1], "move sequence")?,
                event: JournalEvent::StrokeMove {
                    app_arrival_elapsed_ns: parse_u128(fields[2], "move app arrival")?,
                    logical_revision: parse_u64(fields[3], "move revision")?,
                    target: parse_stroke_ref_fields(fields, 4)?,
                    delta_x_raw: parse_i64(fields[8], "move delta x")?,
                    delta_y_raw: parse_i64(fields[9], "move delta y")?,
                    coordinate_space: decode_field(fields[10])?,
                    units: decode_field(fields[11])?,
                },
            })
        }
        "CORR" => {
            require_fields(fields, 9, "CORR")?;
            Ok(JournalRecord {
                sequence: parse_u64(fields[1], "correction sequence")?,
                event: JournalEvent::UserCorrection {
                    app_arrival_elapsed_ns: parse_u128(fields[2], "correction app arrival")?,
                    logical_revision: parse_u64(fields[3], "correction revision")?,
                    target: parse_stroke_ref_fields(fields, 4)?,
                    corrected_text: decode_field(fields[8])?,
                },
            })
        }
        other => Err(JournalError::invalid(format!(
            "unknown journal record tag {other:?}"
        ))),
    }
}

fn parse_sample_fields(fields: &[&str], version: u32) -> Result<PhysicalSample, JournalError> {
    let expected_fields = if version >= 2 { 30 } else { 24 };
    require_fields(fields, expected_fields, "P")?;
    let source_api = decode_field(fields[3])?;
    let source_device_id = decode_option_text(fields[4])?;
    let pointer_id = parse_option_u64(fields[5], "sample pointer ID")?;
    let stroke_id = decode_option_text(fields[6])?;
    let source_sequence = parse_u64(fields[7], "source sample sequence")?;
    let config_id = decode_option_text(fields[8])?;
    let app_arrival_elapsed_ns = parse_u128(fields[9], "sample app arrival")?;
    let position = parse_optional_position(fields[10], fields[11], fields[12], fields[13])?;
    let pressure = parse_optional_pressure(fields, version)?;
    let (
        clock_domain,
        clock_units,
        clock_count,
        clock_frequency,
        contact,
        buttons,
        tilt_x,
        tilt_y,
        rotation,
    ) = if version >= 2 {
        (
            fields[20], fields[21], fields[22], fields[23], fields[24], fields[25], fields[26],
            fields[27], fields[28],
        )
    } else {
        (
            fields[17], fields[18], fields[19], fields[20], fields[21], fields[22], "~", "~", "~",
        )
    };
    let native_timestamp =
        parse_optional_native_timestamp(clock_domain, clock_units, clock_count, clock_frequency)?;
    let sample = PhysicalSample {
        session_id: decode_field(fields[2])?,
        source_api,
        source_device_id,
        pointer_id,
        stroke_id,
        source_sequence,
        config_id,
        app_arrival_elapsed_ns,
        position,
        pressure,
        native_timestamp,
        contact_range_state: decode_option_text(contact)?,
        button_state_raw: parse_option_u64(buttons, "sample button state")?,
        tilt_x_raw: parse_option_i32(tilt_x, "sample tilt X")?,
        tilt_y_raw: parse_option_i32(tilt_y, "sample tilt Y")?,
        rotation_raw: parse_option_u64(rotation, "sample rotation")?,
        raw_payload: decode_hex(fields[payload_index(version)])?,
    };
    Ok(sample)
}

fn payload_index(version: u32) -> usize {
    if version >= 2 { 29 } else { 23 }
}

fn parse_optional_position(
    coordinate_space: &str,
    units: &str,
    x: &str,
    y: &str,
) -> Result<Option<RawPosition>, JournalError> {
    let position_fields = [coordinate_space, units, x, y];
    if position_fields.contains(&"~") {
        if position_fields.iter().all(|value| *value == "~") {
            return Ok(None);
        }
        return Err(JournalError::invalid("partial raw position is not allowed"));
    }
    Ok(Some(RawPosition {
        coordinate_space: decode_field(coordinate_space)?,
        units: decode_field(units)?,
        x_raw: parse_i64(x, "raw position x")?,
        y_raw: parse_i64(y, "raw position y")?,
    }))
}

fn parse_optional_pressure(
    fields: &[&str],
    version: u32,
) -> Result<Option<RawPressure>, JournalError> {
    let (representation, units, value, mask, minimum, maximum) = if version >= 2 {
        (
            fields[14], fields[15], fields[16], fields[17], fields[18], fields[19],
        )
    } else {
        (fields[14], fields[15], fields[16], "~", "~", "~")
    };
    if representation == "~" && units == "~" && value == "~" {
        if mask != "~" || minimum != "~" || maximum != "~" {
            return Err(JournalError::invalid(
                "pressure metadata is present without a raw pressure value",
            ));
        }
        return Ok(None);
    }
    if representation == "~" || units == "~" || value == "~" {
        return Err(JournalError::invalid(
            "partial raw pressure group is not allowed",
        ));
    }
    Ok(Some(RawPressure {
        representation: decode_field(representation)?,
        units: decode_field(units)?,
        value_raw: parse_u64(value, "raw pressure")?,
        mask_raw: parse_option_u64(mask, "raw pressure mask")?,
        minimum_raw: parse_option_u64(minimum, "raw pressure minimum")?,
        maximum_raw: parse_option_u64(maximum, "raw pressure maximum")?,
    }))
}

fn parse_optional_native_timestamp(
    domain: &str,
    units: &str,
    count: &str,
    frequency: &str,
) -> Result<Option<NativeTimestamp>, JournalError> {
    if domain == "~" && units == "~" && count == "~" {
        if frequency != "~" {
            return Err(JournalError::invalid(
                "native clock frequency is present without a native count",
            ));
        }
        return Ok(None);
    }
    if domain == "~" || units == "~" || count == "~" {
        return Err(JournalError::invalid(
            "partial native timestamp group is not allowed",
        ));
    }
    Ok(Some(NativeTimestamp {
        clock_domain: decode_field(domain)?,
        units: decode_field(units)?,
        count_raw: parse_u64(count, "native clock count")?,
        frequency_hz: parse_option_u64(frequency, "native clock frequency")?,
    }))
}

fn parse_stroke_ref_fields(fields: &[&str], start: usize) -> Result<StrokeRef, JournalError> {
    let target = StrokeRef {
        source_api: decode_field(fields[start])?,
        device_id: decode_option_text(fields[start + 1])?,
        pointer_id: parse_option_u64(fields[start + 2], "logical target pointer ID")?,
        stroke_id: decode_field(fields[start + 3])?,
    };
    if target.source_api.is_empty() || target.stroke_id.is_empty() {
        return Err(JournalError::invalid(
            "logical target source API and stroke ID must be nonempty",
        ));
    }
    Ok(target)
}

fn encode_row(fields: &[String]) -> Result<Vec<u8>, JournalError> {
    let mut row = Vec::new();
    row.try_reserve(fields.iter().map(String::len).sum::<usize>() + fields.len())
        .map_err(JournalError::allocation)?;
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            row.push(b'\t');
        }
        row.extend_from_slice(field.as_bytes());
    }
    row.push(b'\n');
    if row.len() > MAX_JOURNAL_LINE_BYTES {
        return Err(JournalError::limit(
            "journal line exceeds bounded line capacity",
        ));
    }
    Ok(row)
}

fn encode_field(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-' | b':') {
            encoded.push(char::from(*byte));
        } else {
            use fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn decode_field(value: &str) -> Result<String, JournalError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::new();
    decoded
        .try_reserve(bytes.len())
        .map_err(JournalError::allocation)?;
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(high) = bytes.get(index + 1).and_then(|b| hex_value(*b)) else {
                return Err(JournalError::invalid(
                    "malformed percent escape in journal field",
                ));
            };
            let Some(low) = bytes.get(index + 2).and_then(|b| hex_value(*b)) else {
                return Err(JournalError::invalid(
                    "malformed percent escape in journal field",
                ));
            };
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| JournalError::invalid("journal text is not UTF-8"))
}

fn encode_option_text(value: Option<&str>) -> String {
    value.map_or_else(|| "~".to_owned(), encode_field)
}

fn decode_option_text(value: &str) -> Result<Option<String>, JournalError> {
    if value == "~" {
        Ok(None)
    } else {
        decode_field(value).map(Some)
    }
}

fn opt_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "~".to_owned(), |value| value.to_string())
}

fn opt_i32(value: Option<i32>) -> String {
    value.map_or_else(|| "~".to_owned(), |value| value.to_string())
}

fn opt_bool(value: Option<bool>) -> String {
    value.map_or_else(|| "~".to_owned(), |value| value.to_string())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(result, "{byte:02X}");
    }
    result
}

fn decode_hex(value: &str) -> Result<Vec<u8>, JournalError> {
    if !value.len().is_multiple_of(2) || value.len() / 2 > MAX_RAW_PAYLOAD_BYTES {
        return Err(JournalError::limit(
            "raw payload hex length is invalid or over limit",
        ));
    }
    let mut output = Vec::new();
    output
        .try_reserve(value.len() / 2)
        .map_err(JournalError::allocation)?;
    let bytes = value.as_bytes();
    let (pairs, remainder) = bytes.as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for pair in pairs {
        let high =
            hex_value(pair[0]).ok_or_else(|| JournalError::invalid("invalid raw payload hex"))?;
        let low =
            hex_value(pair[1]).ok_or_else(|| JournalError::invalid("invalid raw payload hex"))?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_text(value: &str, name: &str, maximum: usize) -> Result<(), JournalError> {
    if value.len() > maximum {
        Err(JournalError::limit(format!(
            "{name} exceeds {maximum} bytes"
        )))
    } else {
        Ok(())
    }
}

fn validate_optional_text(value: Option<&str>, name: &str) -> Result<(), JournalError> {
    if let Some(value) = value {
        validate_text(value, name, MAX_JOURNAL_TEXT_BYTES)?;
    }
    Ok(())
}

fn parse_u32(value: &str, name: &str) -> Result<u32, JournalError> {
    value
        .parse()
        .map_err(|_| JournalError::invalid(format!("invalid {name}: {value:?}")))
}

fn parse_hex_u64(value: &str, name: &str) -> Result<u64, JournalError> {
    u64::from_str_radix(value, 16)
        .map_err(|_| JournalError::invalid(format!("invalid {name}: {value:?}")))
}

fn parse_i64(value: &str, name: &str) -> Result<i64, JournalError> {
    value
        .parse()
        .map_err(|_| JournalError::invalid(format!("invalid {name}: {value:?}")))
}

fn parse_i32(value: &str, name: &str) -> Result<i32, JournalError> {
    value
        .parse()
        .map_err(|_| JournalError::invalid(format!("invalid {name}: {value:?}")))
}

fn parse_u64(value: &str, name: &str) -> Result<u64, JournalError> {
    value
        .parse()
        .map_err(|_| JournalError::invalid(format!("invalid {name}: {value:?}")))
}

fn parse_u128(value: &str, name: &str) -> Result<u128, JournalError> {
    value
        .parse()
        .map_err(|_| JournalError::invalid(format!("invalid {name}: {value:?}")))
}

fn parse_option_u64(value: &str, name: &str) -> Result<Option<u64>, JournalError> {
    if value == "~" {
        Ok(None)
    } else {
        parse_u64(value, name).map(Some)
    }
}

fn parse_option_i32(value: &str, name: &str) -> Result<Option<i32>, JournalError> {
    if value == "~" {
        Ok(None)
    } else {
        parse_i32(value, name).map(Some)
    }
}

fn parse_option_bool(value: &str, name: &str) -> Result<Option<bool>, JournalError> {
    match value {
        "~" => Ok(None),
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        _ => Err(JournalError::invalid(format!(
            "invalid {name} declaration: {value:?}"
        ))),
    }
}

fn require_fields(fields: &[&str], expected: usize, tag: &str) -> Result<(), JournalError> {
    if fields.len() != expected {
        Err(JournalError::invalid(format!(
            "{tag} record has {} fields; expected {expected}",
            fields.len()
        )))
    } else {
        Ok(())
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    output: &mut Vec<u8>,
) -> Result<Option<bool>, JournalError> {
    loop {
        let available = reader.fill_buf().map_err(JournalError::io)?;
        if available.is_empty() {
            return Ok((!output.is_empty()).then_some(false));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if output.len().saturating_add(take) > MAX_JOURNAL_LINE_BYTES {
            return Err(JournalError::limit(
                "journal line exceeds bounded line capacity",
            ));
        }
        let terminated = available.get(take.saturating_sub(1)) == Some(&b'\n');
        output.try_reserve(take).map_err(JournalError::allocation)?;
        output.extend_from_slice(&available[..take]);
        reader.consume(take);
        if terminated {
            return Ok(Some(true));
        }
    }
}

fn fnv_update(mut state: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn temp_path(label: &str) -> PathBuf {
        let id = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "lassoink-journal-{label}-{}-{id}.ljnl",
            std::process::id()
        ))
    }

    fn header(journal_id: &str) -> JournalHeader {
        JournalHeader {
            journal_id: journal_id.to_owned(),
            session_id: "session-1".to_owned(),
            config_id: Some("cfg-a".to_owned()),
            device_model_declared: Some("owner-declared device".to_owned()),
            tilt_supported_declared: Some(false),
        }
    }

    fn sample(
        source_api: &str,
        stroke_id: &str,
        source_sequence: u64,
        app_arrival_elapsed_ns: u128,
        native_count: Option<u64>,
        has_pressure: bool,
        x_raw: i64,
    ) -> PhysicalSample {
        PhysicalSample {
            session_id: "session-1".to_owned(),
            source_api: source_api.to_owned(),
            source_device_id: Some("device-a".to_owned()),
            pointer_id: Some(7),
            stroke_id: Some(stroke_id.to_owned()),
            source_sequence,
            config_id: Some("cfg-a".to_owned()),
            app_arrival_elapsed_ns,
            position: Some(RawPosition {
                coordinate_space: "device-output".to_owned(),
                units: "raw-units".to_owned(),
                x_raw,
                y_raw: 20,
            }),
            pressure: has_pressure.then(|| RawPressure {
                representation: format!("{source_api} native pressure"),
                units: "raw-u32".to_owned(),
                value_raw: 512,
                mask_raw: Some(1),
                minimum_raw: None,
                maximum_raw: None,
            }),
            native_timestamp: native_count.map(|count_raw| NativeTimestamp {
                clock_domain: format!("{source_api} native clock"),
                units: "ticks".to_owned(),
                count_raw,
                frequency_hz: Some(10_000_000),
            }),
            contact_range_state: Some("InRange+Contact".to_owned()),
            button_state_raw: Some(3),
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload: vec![0x00, 0x80, source_sequence as u8, 0xff],
        }
    }

    fn target_of(sample: &PhysicalSample) -> StrokeRef {
        sample.stroke_ref().unwrap()
    }

    fn cleanup_journal(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(default_snapshot_path(path));
    }

    fn rewrite_record_field(path: &Path, tag: &str, field_index: usize, replacement: &str) {
        let text = fs::read_to_string(path).unwrap();
        let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
        let line = lines
            .iter_mut()
            .find(|line| line.split('\t').next() == Some(tag))
            .unwrap();
        let mut fields = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
        fields[field_index] = replacement.to_owned();
        *line = fields.join("\t");
        fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn physical_journal_preserves_source_order_raw_domains_and_null_capabilities() {
        let path = temp_path("order");
        let mut writer = JournalWriter::create(path.clone(), header("journal-order")).unwrap();
        let first = sample(
            "direct-wm-pointer",
            "stroke-direct",
            1,
            100,
            Some(900),
            true,
            10,
        );
        let mut second = sample("public-winit", "stroke-public", 1, 200, None, false, 30);
        second.native_timestamp = None;
        second.tilt_x_raw = None;
        second.tilt_y_raw = None;
        second.rotation_raw = None;
        writer.append_sample(first).unwrap();
        writer.append_sample(second).unwrap();
        writer.flush().unwrap();

        let parsed = read_journal(&path).unwrap();
        assert_eq!(parsed.schema_version, JOURNAL_SCHEMA_VERSION);
        assert_eq!(parsed.header.tilt_supported_declared, Some(false));
        assert!(!parsed.recovery.truncated_final_record);
        assert_eq!(parsed.records.len(), 2);
        let JournalEvent::PhysicalSample(first) = &parsed.records[0].event else {
            panic!("first source event must remain first in journal order");
        };
        let JournalEvent::PhysicalSample(second) = &parsed.records[1].event else {
            panic!("second source event must remain second in journal order");
        };
        assert_eq!(first.source_api, "direct-wm-pointer");
        assert_eq!(first.native_timestamp.as_ref().unwrap().count_raw, 900);
        assert_eq!(first.raw_payload, [0x00, 0x80, 1, 0xff]);
        assert_eq!(second.source_api, "public-winit");
        assert_eq!(second.app_arrival_elapsed_ns, 200);
        assert_eq!(second.native_timestamp, None);
        assert_eq!(second.pressure, None);
        assert_eq!(second.tilt_x_raw, None);
        assert_eq!(second.tilt_y_raw, None);
        assert_eq!(second.rotation_raw, None);
        assert_eq!(parsed.state.physical_samples.len(), 2);
        let replayed_again = read_journal(&path).unwrap();
        assert_eq!(parsed.records, replayed_again.records);
        assert_eq!(parsed.state, replayed_again.state);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn metadata_history_persists_scope_and_config_drift_through_snapshot_replay() {
        let path = temp_path("metadata-drift");
        let snapshot_path = default_snapshot_path(&path);
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-metadata-drift")).unwrap();

        assert!(
            writer
                .append_metadata(JournalMetadata {
                    scope: MetadataScope::Session,
                    scope_id: "wrong-session".to_owned(),
                    source_api: None,
                    device_id: None,
                    key: "active-config-id".to_owned(),
                    value: "cfg-a".to_owned(),
                    provenance: "owner-declared".to_owned(),
                    app_arrival_elapsed_ns: 10,
                })
                .is_err()
        );
        assert_eq!(writer.state.last_sequence, 0);

        writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Session,
                scope_id: "session-1".to_owned(),
                source_api: None,
                device_id: None,
                key: "active-config-id".to_owned(),
                value: "cfg-a".to_owned(),
                provenance: "owner-declared".to_owned(),
                app_arrival_elapsed_ns: 10,
            })
            .unwrap();
        writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Device,
                scope_id: "device-a".to_owned(),
                source_api: Some("direct-wm-pointer".to_owned()),
                device_id: Some("device-a".to_owned()),
                key: "driver-version".to_owned(),
                value: "unknown".to_owned(),
                provenance: "owner-declared".to_owned(),
                app_arrival_elapsed_ns: 11,
            })
            .unwrap();
        writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Configuration,
                scope_id: "cfg-a".to_owned(),
                source_api: Some("direct-wm-pointer".to_owned()),
                device_id: Some("device-a".to_owned()),
                key: "pressure-curve".to_owned(),
                value: "linear-v1".to_owned(),
                provenance: "owner-declared".to_owned(),
                app_arrival_elapsed_ns: 12,
            })
            .unwrap();
        let mut first_sample = sample("direct-wm-pointer", "stroke-a", 1, 13, Some(100), true, 1);
        first_sample.config_id = Some("cfg-a".to_owned());
        writer.append_sample(first_sample).unwrap();
        writer.write_snapshot(&snapshot_path).unwrap();

        writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Session,
                scope_id: "session-1".to_owned(),
                source_api: None,
                device_id: None,
                key: "active-config-id".to_owned(),
                value: "cfg-b".to_owned(),
                provenance: "owner-declared-after-profile-change".to_owned(),
                app_arrival_elapsed_ns: 20,
            })
            .unwrap();
        writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Configuration,
                scope_id: "cfg-b".to_owned(),
                source_api: Some("direct-wm-pointer".to_owned()),
                device_id: Some("device-a".to_owned()),
                key: "pressure-curve".to_owned(),
                value: "custom-v2".to_owned(),
                provenance: "owner-declared-after-profile-change".to_owned(),
                app_arrival_elapsed_ns: 21,
            })
            .unwrap();
        let mut second_sample = sample("direct-wm-pointer", "stroke-b", 2, 22, Some(200), true, 2);
        second_sample.config_id = Some("cfg-b".to_owned());
        writer.append_sample(second_sample).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let full = read_journal(&path).unwrap();
        let restored = load_with_snapshot(&path, &snapshot_path).unwrap();
        assert_eq!(restored.disposition, SnapshotDisposition::Used);
        assert_eq!(restored.replayed_tail_records, 3);
        assert_eq!(restored.state, full.state);
        assert_eq!(full.state.metadata_history.len(), 5);
        assert_eq!(full.state.physical_samples.len(), 2);
        assert_eq!(
            full.state.physical_samples[0].sample.config_id.as_deref(),
            Some("cfg-a")
        );
        assert_eq!(
            full.state.physical_samples[1].sample.config_id.as_deref(),
            Some("cfg-b")
        );

        let active_config_history = full
            .state
            .metadata_history
            .iter()
            .filter(|stored| {
                stored.metadata.scope == MetadataScope::Session
                    && stored.metadata.key == "active-config-id"
            })
            .map(|stored| stored.metadata.value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(active_config_history, ["cfg-a", "cfg-b"]);
        let pressure_curves = full
            .state
            .metadata_history
            .iter()
            .filter(|stored| {
                stored.metadata.scope == MetadataScope::Configuration
                    && stored.metadata.key == "pressure-curve"
            })
            .map(|stored| {
                (
                    stored.metadata.scope_id.as_str(),
                    stored.metadata.value.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            pressure_curves,
            [("cfg-a", "linear-v1"), ("cfg-b", "custom-v2")]
        );
        cleanup_journal(&path);
    }

    #[test]
    fn logical_revisions_tombstones_moves_and_corrections_preserve_physical_rows() {
        let path = temp_path("logical");
        let mut writer = JournalWriter::create(path.clone(), header("journal-logical")).unwrap();
        let original = sample("wintab", "stroke-a", 1, 100, Some(50), true, 10);
        let target = target_of(&original);
        writer.append_sample(original).unwrap();
        let revision = writer
            .begin_revision(200, "move and annotate".to_owned())
            .unwrap();
        writer
            .move_stroke(
                210,
                target.clone(),
                3,
                -2,
                "device-output".to_owned(),
                "raw-units".to_owned(),
            )
            .unwrap();
        writer
            .correct_stroke(220, target.clone(), "corrected words".to_owned())
            .unwrap();
        assert_eq!(revision, 1);
        let projected = writer.state.projected_samples().unwrap();
        assert_eq!(
            writer.state.physical_samples[0]
                .sample
                .position
                .as_ref()
                .unwrap()
                .x_raw,
            10
        );
        assert_eq!(projected[0].effective_position.as_ref().unwrap().x_raw, 13);
        assert_eq!(projected[0].effective_position.as_ref().unwrap().y_raw, 18);
        let delete_revision = writer
            .begin_revision(300, "delete stroke".to_owned())
            .unwrap();
        writer.tombstone(310, target).unwrap();
        assert_eq!(delete_revision, 2);
        writer.flush().unwrap();

        let parsed = read_journal(&path).unwrap();
        assert_eq!(parsed.records.len(), 6);
        assert_eq!(parsed.state.logical_revision, 2);
        assert_eq!(parsed.state.physical_samples.len(), 1);
        assert_eq!(parsed.state.moves.len(), 1);
        assert_eq!(parsed.state.corrections.len(), 1);
        assert_eq!(parsed.state.tombstones.len(), 1);
        assert_eq!(parsed.state.projected_samples().unwrap().len(), 0);
        assert_eq!(
            parsed.state.physical_samples[0]
                .sample
                .position
                .as_ref()
                .unwrap()
                .x_raw,
            10
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn duplicate_source_stroke_labels_do_not_merge_without_api_device_provenance() {
        let path = temp_path("partition");
        let mut writer = JournalWriter::create(path.clone(), header("journal-partition")).unwrap();
        writer
            .append_sample(sample(
                "direct-wm-pointer",
                "shared-label",
                1,
                10,
                Some(5),
                true,
                1,
            ))
            .unwrap();
        writer
            .append_sample(sample("wintab", "shared-label", 1, 20, Some(5), true, 2))
            .unwrap();
        let rev = writer
            .begin_revision(30, "delete direct only".to_owned())
            .unwrap();
        writer
            .tombstone(
                31,
                StrokeRef {
                    source_api: "direct-wm-pointer".to_owned(),
                    device_id: Some("device-a".to_owned()),
                    pointer_id: Some(7),
                    stroke_id: "shared-label".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(rev, 1);
        let parsed = read_journal(&path).unwrap();
        let visible = parsed.state.projected_samples().unwrap();
        assert_eq!(parsed.state.physical_samples.len(), 2);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].sample.source_api, "wintab");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn truncated_final_record_recovers_but_complete_malformed_record_errors() {
        let path = temp_path("tail");
        let mut writer = JournalWriter::create(path.clone(), header("journal-tail")).unwrap();
        writer
            .append_sample(sample(
                "direct-wm-pointer",
                "stroke-a",
                1,
                10,
                Some(5),
                true,
                1,
            ))
            .unwrap();
        writer
            .append_sample(sample(
                "direct-wm-pointer",
                "stroke-a",
                2,
                20,
                Some(6),
                true,
                2,
            ))
            .unwrap();
        drop(writer);
        let original = fs::read(&path).unwrap();
        let mut partial = OpenOptions::new().append(true).open(&path).unwrap();
        partial.write_all(b"P\t3\tpartial-row").unwrap();
        drop(partial);
        let recovered = read_journal(&path).unwrap();
        assert!(recovered.recovery.truncated_final_record);
        assert_eq!(recovered.records.len(), 2);
        let mut resumed = JournalWriter::open_append(path.clone()).unwrap();
        assert!(resumed.recovered_truncated_final_record());
        resumed
            .append_sample(sample(
                "direct-wm-pointer",
                "stroke-a",
                3,
                30,
                Some(7),
                true,
                3,
            ))
            .unwrap();
        resumed.flush().unwrap();
        drop(resumed);
        let resumed_result = read_journal(&path).unwrap();
        assert!(!resumed_result.recovery.truncated_final_record);
        assert_eq!(resumed_result.records.len(), 3);
        assert_eq!(resumed_result.records[2].sequence, 3);

        let malformed_path = temp_path("malformed-open");
        fs::write(&malformed_path, &original).unwrap();
        rewrite_record_field(&malformed_path, "P", 0, "BROKEN");
        assert!(JournalWriter::open_append(malformed_path.clone()).is_err());
        fs::remove_file(malformed_path).unwrap();

        fs::write(&path, &original).unwrap();
        rewrite_record_field(&path, "P", 0, "BROKEN");
        assert!(read_journal(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn schema_one_sample_migrates_missing_capabilities_as_null() {
        let header = header("legacy-journal");
        let header_line = encode_row(&encode_header_fields(
            &header,
            LEGACY_JOURNAL_SCHEMA_VERSION,
        ))
        .unwrap();
        let legacy = sample(
            "direct-wm-pointer",
            "stroke-legacy",
            1,
            123,
            Some(77),
            true,
            9,
        );
        let sample_line = encode_row(
            &encode_sample_fields("P", 1, &legacy, LEGACY_JOURNAL_SCHEMA_VERSION).unwrap(),
        )
        .unwrap();
        let mut bytes = header_line;
        bytes.extend_from_slice(&sample_line);
        let path = temp_path("legacy-readonly");
        fs::write(&path, &bytes).unwrap();

        let parsed = parse_journal(std::io::Cursor::new(bytes)).unwrap();
        let JournalEvent::PhysicalSample(migrated) = &parsed.records[0].event else {
            panic!("legacy row must migrate to a physical sample");
        };
        assert_eq!(parsed.schema_version, LEGACY_JOURNAL_SCHEMA_VERSION);
        assert_eq!(parsed.header.tilt_supported_declared, None);
        assert_eq!(migrated.pressure.as_ref().unwrap().mask_raw, None);
        assert_eq!(migrated.pressure.as_ref().unwrap().minimum_raw, None);
        assert_eq!(migrated.tilt_x_raw, None);
        assert_eq!(migrated.tilt_y_raw, None);
        assert_eq!(migrated.rotation_raw, None);
        assert_eq!(migrated.raw_payload, legacy.raw_payload);
        assert!(JournalWriter::open_append(path.clone()).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn schema_one_migration_writes_new_identity_without_mutating_source() {
        let source_path = temp_path("legacy-migration-source");
        let destination_path = temp_path("legacy-migration-destination");
        let legacy_header = header("legacy-migration-id");
        let legacy_sample = sample(
            "direct-wm-pointer",
            "legacy-stroke",
            17,
            1234,
            Some(77),
            true,
            9,
        );
        let mut source_bytes = encode_row(&encode_header_fields(
            &legacy_header,
            LEGACY_JOURNAL_SCHEMA_VERSION,
        ))
        .unwrap();
        source_bytes.extend_from_slice(
            &encode_row(
                &encode_sample_fields("P", 1, &legacy_sample, LEGACY_JOURNAL_SCHEMA_VERSION)
                    .unwrap(),
            )
            .unwrap(),
        );
        fs::write(&source_path, &source_bytes).unwrap();

        let result = migrate_schema_one_to_two(
            &source_path,
            destination_path.clone(),
            "migrated-journal-id".to_owned(),
        )
        .unwrap();
        let mut migrated_writer = JournalWriter::open_append(destination_path.clone()).unwrap();
        migrated_writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Session,
                scope_id: "session-1".to_owned(),
                source_api: None,
                device_id: None,
                key: "migration-source-schema".to_owned(),
                value: "1".to_owned(),
                provenance: "software-migration".to_owned(),
                app_arrival_elapsed_ns: 1300,
            })
            .unwrap();
        migrated_writer.flush().unwrap();
        drop(migrated_writer);
        let migrated = read_journal(&destination_path).unwrap();
        let preserved_source = fs::read(&source_path).unwrap();
        let JournalEvent::PhysicalSample(sample) = &migrated.records[0].event else {
            panic!("migrated legacy row must stay a physical sample");
        };

        assert_eq!(result.migrated_records, 1);
        assert!(!result.source_truncated_final_record);
        assert_eq!(migrated.schema_version, JOURNAL_SCHEMA_VERSION);
        assert_eq!(migrated.header.journal_id, "migrated-journal-id");
        assert_eq!(migrated.header.config_id, Some("cfg-a".to_owned()));
        assert_eq!(
            migrated.header.device_model_declared,
            Some("owner-declared device".to_owned())
        );
        assert_eq!(migrated.header.tilt_supported_declared, None);
        assert_eq!(sample.source_sequence, legacy_sample.source_sequence);
        assert_eq!(sample.raw_payload, legacy_sample.raw_payload);
        assert_eq!(sample.pressure.as_ref().unwrap().mask_raw, None);
        assert_eq!(sample.tilt_x_raw, None);
        assert_eq!(sample.rotation_raw, None);
        assert_eq!(migrated.state.metadata_history.len(), 1);
        assert_eq!(
            migrated.state.metadata_history[0].metadata.key,
            "migration-source-schema"
        );
        assert_eq!(preserved_source, source_bytes);
        fs::remove_file(source_path).unwrap();
        fs::remove_file(destination_path).unwrap();
    }

    #[test]
    fn oversized_event_fields_fail_before_encoding_without_advancing_writer() {
        let path = temp_path("oversized-fields");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-oversized-fields")).unwrap();

        let mut oversized_sample = sample("direct-wm-pointer", "stroke-a", 1, 10, Some(5), true, 1);
        oversized_sample.raw_payload = vec![0xAB; MAX_RAW_PAYLOAD_BYTES + 1];
        let error = writer.append_sample(oversized_sample).unwrap_err();
        assert_eq!(error.kind, JournalErrorKind::LimitReached);
        assert_eq!(writer.state.last_sequence, 0);
        assert!(writer.state.physical_samples.is_empty());

        let valid_sample = sample("direct-wm-pointer", "stroke-a", 1, 20, Some(6), true, 2);
        assert_eq!(writer.append_sample(valid_sample.clone()).unwrap(), 1);
        let target = target_of(&valid_sample);
        assert_eq!(writer.begin_revision(21, "edit".to_owned()).unwrap(), 1);

        let oversized_metadata = JournalMetadata {
            scope: MetadataScope::Session,
            scope_id: "session-1".to_owned(),
            source_api: None,
            device_id: None,
            key: "owner-note".to_owned(),
            value: "v".repeat(MAX_METADATA_TEXT_BYTES + 1),
            provenance: "owner-declared".to_owned(),
            app_arrival_elapsed_ns: 22,
        };
        let error = writer.append_metadata(oversized_metadata).unwrap_err();
        assert_eq!(error.kind, JournalErrorKind::LimitReached);
        assert_eq!(writer.state.last_sequence, 2);

        let error = writer
            .correct_stroke(23, target.clone(), "c".repeat(MAX_JOURNAL_TEXT_BYTES + 1))
            .unwrap_err();
        assert_eq!(error.kind, JournalErrorKind::LimitReached);
        assert_eq!(writer.state.last_sequence, 2);
        assert!(writer.state.corrections.is_empty());

        assert_eq!(
            writer
                .append_metadata(JournalMetadata {
                    scope: MetadataScope::Session,
                    scope_id: "session-1".to_owned(),
                    source_api: None,
                    device_id: None,
                    key: "owner-note".to_owned(),
                    value: "accepted".to_owned(),
                    provenance: "owner-declared".to_owned(),
                    app_arrival_elapsed_ns: 24,
                })
                .unwrap(),
            3
        );
        assert_eq!(
            writer
                .correct_stroke(25, target, "valid correction".to_owned())
                .unwrap(),
            4
        );
        writer.flush().unwrap();
        drop(writer);

        let parsed = read_journal(&path).unwrap();
        assert_eq!(parsed.state.last_sequence, 4);
        assert_eq!(parsed.state.physical_samples.len(), 1);
        assert_eq!(parsed.state.metadata_history.len(), 1);
        assert_eq!(parsed.state.corrections.len(), 1);
        assert_eq!(
            parsed
                .records
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        cleanup_journal(&path);
    }

    #[test]
    fn writer_poisons_after_sync_failure_and_reopen_replays_recoverable_disk_truth() {
        let path = temp_path("poison");
        let mut writer = JournalWriter::create(path.clone(), header("journal-poison")).unwrap();
        writer.fail_next_sync_after_write = true;
        let result = writer.append_sample(sample(
            "direct-wm-pointer",
            "stroke-a",
            1,
            10,
            Some(5),
            true,
            1,
        ));
        assert!(result.is_err());
        assert!(writer.is_poisoned());
        assert_eq!(writer.state.last_sequence, 0);
        assert_eq!(writer.state.physical_samples.len(), 0);
        assert_eq!(
            writer
                .append_sample(sample(
                    "direct-wm-pointer",
                    "stroke-a",
                    2,
                    20,
                    Some(6),
                    true,
                    2
                ))
                .unwrap_err()
                .kind,
            JournalErrorKind::Poisoned
        );
        drop(writer);

        let recovered = read_journal(&path).unwrap();
        assert_eq!(recovered.records.len(), 1);
        assert_eq!(recovered.state.last_sequence, 1);
        assert_eq!(
            recovered.state.physical_samples[0].sample.source_sequence,
            1
        );
        let mut reopened = JournalWriter::open_append(path.clone()).unwrap();
        assert!(!reopened.recovered_truncated_final_record());
        reopened
            .append_sample(sample(
                "direct-wm-pointer",
                "stroke-a",
                2,
                20,
                Some(6),
                true,
                2,
            ))
            .unwrap();
        reopened.flush().unwrap();
        drop(reopened);
        assert_eq!(read_journal(&path).unwrap().records.len(), 2);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn flush_failure_keeps_durable_revision_and_poisoned_writer_rejects_more_events() {
        let path = temp_path("flush-poison");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-flush-poison")).unwrap();
        writer
            .append_sample(sample(
                "direct-wm-pointer",
                "stroke-a",
                1,
                10,
                Some(5),
                true,
                1,
            ))
            .unwrap();
        writer.fail_next_flush = true;

        assert!(writer.flush().is_err());
        assert!(writer.is_poisoned());
        assert_eq!(writer.state.last_sequence, 1);
        assert_eq!(
            writer
                .append_sample(sample(
                    "direct-wm-pointer",
                    "stroke-a",
                    2,
                    20,
                    Some(6),
                    true,
                    2
                ))
                .unwrap_err()
                .kind,
            JournalErrorKind::Poisoned
        );
        drop(writer);

        let recovered = read_journal(&path).unwrap();
        assert_eq!(recovered.records.len(), 1);
        assert_eq!(recovered.state.last_sequence, 1);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn snapshot_plus_tail_matches_full_replay_and_preserves_logical_state() {
        let path = temp_path("snapshot-tail");
        let snapshot_path = default_snapshot_path(&path);
        let mut writer = JournalWriter::create(path.clone(), header("journal-snapshot")).unwrap();
        let first = sample("direct-wm-pointer", "stroke-a", 1, 10, Some(5), true, 10);
        let target = target_of(&first);
        writer.append_sample(first).unwrap();
        let revision = writer
            .begin_revision(20, "logical edit".to_owned())
            .unwrap();
        writer
            .move_stroke(
                21,
                target.clone(),
                4,
                2,
                "device-output".to_owned(),
                "raw-units".to_owned(),
            )
            .unwrap();
        writer
            .correct_stroke(22, target, "recognized correction".to_owned())
            .unwrap();
        writer.write_snapshot(&snapshot_path).unwrap();
        writer
            .append_sample(sample("wintab", "stroke-b", 1, 30, Some(4), false, 7))
            .unwrap();
        assert_eq!(revision, 1);
        writer.flush().unwrap();
        drop(writer);

        let full = read_journal(&path).unwrap();
        let restored = load_with_snapshot(&path, &snapshot_path).unwrap();
        assert_eq!(restored.disposition, SnapshotDisposition::Used);
        assert_eq!(restored.replayed_tail_records, 1);
        assert_eq!(restored.state, full.state);
        assert_eq!(
            restored.state.projected_samples().unwrap()[0]
                .effective_position
                .as_ref()
                .unwrap()
                .x_raw,
            14
        );
        assert_eq!(
            restored.state.physical_samples[0]
                .sample
                .position
                .as_ref()
                .unwrap()
                .x_raw,
            10
        );
        cleanup_journal(&path);
    }

    #[test]
    fn missing_corrupt_stale_wrong_journal_and_wrong_revision_snapshots_fall_back() {
        let path = temp_path("snapshot-fallback");
        let snapshot_path = default_snapshot_path(&path);
        let mut writer = JournalWriter::create(path.clone(), header("journal-fallback")).unwrap();
        writer
            .append_sample(sample(
                "direct-wm-pointer",
                "stroke-a",
                1,
                10,
                Some(5),
                true,
                1,
            ))
            .unwrap();
        writer.write_snapshot(&snapshot_path).unwrap();
        writer
            .append_sample(sample(
                "direct-wm-pointer",
                "stroke-a",
                2,
                20,
                Some(6),
                true,
                2,
            ))
            .unwrap();
        writer.flush().unwrap();
        drop(writer);
        let full = read_journal(&path).unwrap();

        let missing_path = temp_path("snapshot-missing");
        fs::copy(&path, &missing_path).unwrap();
        let missing =
            load_with_snapshot(&missing_path, &default_snapshot_path(&missing_path)).unwrap();
        assert_eq!(missing.disposition, SnapshotDisposition::Missing);
        assert_eq!(missing.state, full.state);
        cleanup_journal(&missing_path);

        let corrupt_snapshot = temp_path("snapshot-corrupt");
        fs::copy(&snapshot_path, &corrupt_snapshot).unwrap();
        rewrite_record_field(&corrupt_snapshot, "SP", 9, "11");
        let corrupt = load_with_snapshot(&path, &corrupt_snapshot).unwrap();
        assert!(matches!(
            corrupt.disposition,
            SnapshotDisposition::Rejected(_)
        ));
        assert_eq!(corrupt.state, full.state);
        fs::remove_file(corrupt_snapshot).unwrap();

        let wrong_revision_snapshot = temp_path("snapshot-wrong-rev");
        fs::copy(&snapshot_path, &wrong_revision_snapshot).unwrap();
        rewrite_record_field(&wrong_revision_snapshot, "LASSOINK-SNAPSHOT", 5, "9");
        let wrong_revision = load_with_snapshot(&path, &wrong_revision_snapshot).unwrap();
        assert!(matches!(
            wrong_revision.disposition,
            SnapshotDisposition::Rejected(_)
        ));
        assert_eq!(wrong_revision.state, full.state);
        fs::remove_file(wrong_revision_snapshot).unwrap();

        let wrong_journal_path = temp_path("snapshot-other-journal");
        let mut other_writer =
            JournalWriter::create(wrong_journal_path.clone(), header("another-journal")).unwrap();
        other_writer
            .append_sample(sample(
                "direct-wm-pointer",
                "stroke-a",
                1,
                10,
                Some(5),
                true,
                1,
            ))
            .unwrap();
        other_writer.flush().unwrap();
        drop(other_writer);
        let wrong_journal_snapshot = default_snapshot_path(&wrong_journal_path);
        fs::copy(&snapshot_path, &wrong_journal_snapshot).unwrap();
        let wrong_journal =
            load_with_snapshot(&wrong_journal_path, &wrong_journal_snapshot).unwrap();
        assert!(matches!(
            wrong_journal.disposition,
            SnapshotDisposition::Rejected(_)
        ));
        assert_eq!(wrong_journal.state.physical_samples.len(), 1);
        cleanup_journal(&wrong_journal_path);

        let stale_path = temp_path("snapshot-stale");
        fs::copy(&path, &stale_path).unwrap();
        rewrite_record_field(&stale_path, "LASSOINK-JOURNAL", 4, "cfg-b");
        let stale_snapshot = default_snapshot_path(&stale_path);
        fs::copy(&snapshot_path, &stale_snapshot).unwrap();
        let stale = load_with_snapshot(&stale_path, &stale_snapshot).unwrap();
        assert!(matches!(
            stale.disposition,
            SnapshotDisposition::Rejected(_)
        ));
        assert_eq!(stale.state.physical_samples.len(), 2);
        cleanup_journal(&stale_path);

        cleanup_journal(&path);
    }
}
