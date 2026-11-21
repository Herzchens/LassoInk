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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub(crate) const JOURNAL_SCHEMA_VERSION: u32 = 4;
const LEGACY_JOURNAL_SCHEMA_VERSION: u32 = 1;
const PREVIOUS_JOURNAL_SCHEMA_VERSION: u32 = 2;
const THIRD_JOURNAL_SCHEMA_VERSION: u32 = 3;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_JOURNAL_LINE_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_RECORDS: usize = 131_072;
const MAX_SNAPSHOT_STATE_ENTRIES: usize = MAX_JOURNAL_RECORDS * 2 + 1;
pub(crate) const MAX_JOURNAL_TEXT_BYTES: usize = 4096;
const MAX_RAW_PAYLOAD_BYTES: usize = 8192;
const MAX_METADATA_TEXT_BYTES: usize = 4096;
const MAX_RECOGNITION_PROJECTIONS: usize = 16_384;
pub(crate) const MAX_REGION_CORRECTIONS: usize = 16_384;
const MAX_PROJECTION_CANDIDATES: usize = 128;
const MAX_PROJECTION_STROKES: usize = 512;
const MAX_PROJECTION_SAMPLES: usize = 4096;
const MAX_PROJECTION_INPUT_MODALITIES: usize = 2;
pub(crate) const LOCAL_SENOCR_RASTER_PROVIDER_ID: &str = "senocr-v1-fp32-local";
const MAX_PROJECTION_RANGES: usize = 4096;
const MAX_PROJECTION_ID_BYTES: usize = 128;
const MAX_PROJECTION_SOURCE_ID_BYTES: usize = 256;
const SHA256_HEX_BYTES: usize = 64;
const MAX_PROJECTION_RASTER_DIMENSION: u32 = 2048;
const MAX_PROJECTION_RASTER_PIXELS: u64 = 262_144;
const MAX_PROJECTION_RASTER_CROP_DIMENSION: i64 = 1_048_576;
const MAX_PROJECTION_RASTER_CROP_AREA: i64 = 67_108_864;
const MAX_PROJECTION_RASTER_PNG_BYTES: u32 = 1024 * 1024;
const PROJECTION_RASTER_BYTES_PER_PIXEL: u32 = 4;
const PROJECTION_RASTER_BACKGROUND_RGBA: [u8; 4] = [255, 255, 255, 255];
const PROJECTION_RASTER_INK_RGBA: [u8; 4] = [32, 32, 32, 255];
const PROJECTION_RASTER_INK_WIDTH_16_16: u32 = 2 << 16;
pub(crate) const CANONICAL_RASTER_RENDERER_VERSION_V1: &str =
    "tiny-skia/0.12.0;canonical-raster-v1";
pub(crate) const MAX_EDIT_TARGETS: usize = 256;
const STROKE_VIEW_FRAME_WIDTH: usize = 7;
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

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StrokeRef {
    /// Project journal identity; kept explicit so targets cannot cross projects.
    pub journal_id: String,
    /// Capture-session/arrival-clock epoch, distinct across resumed processes.
    pub session_id: String,
    pub source_api: String,
    pub device_id: Option<String>,
    pub pointer_id: Option<u64>,
    pub stroke_id: String,
}

/// Exact per-stroke coordinate frame observed at native pen-down. Screen
/// positions remain raw in `PhysicalSample`; this frame documents the client
/// origin and canvas view used to derive replay geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StrokeViewFrame {
    pub screen_origin_x_px: i64,
    pub screen_origin_y_px: i64,
    /// IEEE-754 bits for the Winit DPI scale factor observed at pen-down.
    /// Raw pointer and GDI coordinates are already physical screen pixels, so
    /// this value is provenance and is not multiplied into those coordinates.
    pub dpi_scale_factor_bits: u64,
    pub canvas_zoom_bits: u64,
    pub canvas_pan_x_bits: u64,
    pub canvas_pan_y_bits: u64,
    pub toolbar_height_px: u32,
}

/// The exact journal prefix and selected ink/view that an external recognizer
/// result describes. `input_view_id` remains the M4 per-request identity;
/// `ink_binding_sha256` is the shared canonical-ink fingerprint used across
/// modalities. Neither authenticates provider pixels or proves raster parity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectionInkBindingV1 {
    pub journal_id: String,
    pub logical_revision: u64,
    pub last_sequence: u64,
    pub region_id: String,
    pub line_id: Option<String>,
    pub input_view_id: String,
    pub ink_binding_sha256: String,
    pub selected_strokes: Vec<StrokeRef>,
    pub source_sample_sequences: Vec<u64>,
    pub stroke_views: Vec<ProjectionStrokeViewV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectionStrokeViewV1 {
    pub stroke: StrokeRef,
    pub frame: StrokeViewFrame,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectionProviderProvenanceV1 {
    pub provider_id: String,
    pub provider_version: String,
    /// M4's optional model version/revision, not a configured repository name.
    pub model_version: Option<String>,
    pub resource_version: Option<String>,
    pub configuration_id: String,
    /// The exact M4 provider-configuration fingerprint; it is an identifier,
    /// not an authentication or file-integrity guarantee.
    pub configuration_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectionStrokeRangeV1 {
    pub stroke: StrokeRef,
    pub first_journal_sequence: u64,
    pub last_journal_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecognitionCandidateV1 {
    pub rank: u16,
    pub recognized_text: String,
    /// Native, uncalibrated provider score serialized as a JSON number string.
    pub native_score_raw: Option<String>,
    pub stroke_ranges: Vec<ProjectionStrokeRangeV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionInputModalityV1 {
    OnlineStrokes,
    Raster,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecognitionProjectionV1 {
    pub projection_id: String,
    pub ink: ProjectionInkBindingV1,
    pub provider: ProjectionProviderProvenanceV1,
    pub candidates: Vec<RecognitionCandidateV1>,
    /// Exact M4 modalities acknowledged by the provider. Missing is retained
    /// for earlier v4 projections and is never inferred from the opaque view ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_modalities: Option<Vec<ProjectionInputModalityV1>>,
    /// Optional metadata-only origin for an app-generated canonical Raster
    /// request. Missing remains valid for older schema-v4 rows and online-only
    /// requests; this never stores the image bytes or authenticates a model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_raster: Option<GeneratedRasterProvenanceV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionRasterAspectRatioPolicyV1 {
    FitContainCentered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionRasterPixelLayoutV1 {
    Rgba8PremultipliedSrgbTopDown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionRasterCoveragePolicyV1 {
    Antialiased,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionRasterStrokeCapV1 {
    Round,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionRasterStrokeJoinV1 {
    Round,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionRasterRoundingPolicyV1 {
    NearestTiesAwayQ16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionRasterClippingPolicyV1 {
    RejectPointsOutsideSourceCropClipCoverageAtOutputBounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionRasterSinglePointPolicyV1 {
    OpaqueDiscAtObservedPoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionRasterStrokeOrderPolicyV1 {
    JournalFirstOccurrence,
}

/// The exact bounded transform/style parameters used by the canonical raster
/// producer. The persisted identity is enough to review the transform without
/// storing raw geometry points, pixel bytes, or PNG payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectionRasterSpecV1 {
    pub schema_version: u32,
    pub output_width_px: u32,
    pub output_height_px: u32,
    pub source_crop_left_px: i32,
    pub source_crop_top_px: i32,
    pub source_crop_right_px_exclusive: i32,
    pub source_crop_bottom_px_exclusive: i32,
    pub aspect_ratio_policy: ProjectionRasterAspectRatioPolicyV1,
    pub pixel_layout: ProjectionRasterPixelLayoutV1,
    pub coverage_policy: ProjectionRasterCoveragePolicyV1,
    pub background_rgba: [u8; 4],
    pub committed_ink_rgba: [u8; 4],
    pub stroke_width_16_16: u32,
    pub stroke_cap: ProjectionRasterStrokeCapV1,
    pub stroke_join: ProjectionRasterStrokeJoinV1,
    pub rounding_policy: ProjectionRasterRoundingPolicyV1,
    pub clipping_policy: ProjectionRasterClippingPolicyV1,
    pub single_point_policy: ProjectionRasterSinglePointPolicyV1,
    pub stroke_order_policy: ProjectionRasterStrokeOrderPolicyV1,
    pub row_stride_bytes: u32,
    pub output_buffer_bytes: u32,
}

impl ProjectionRasterSpecV1 {
    pub(crate) fn canonical_sha256(&self) -> [u8; 32] {
        let mut hash = RasterMetadataHashWriter::new(b"LassoInk/canonical-raster-spec/v1\0");
        hash.u32(self.schema_version);
        hash.u32(self.output_width_px);
        hash.u32(self.output_height_px);
        hash.i32(self.source_crop_left_px);
        hash.i32(self.source_crop_top_px);
        hash.i32(self.source_crop_right_px_exclusive);
        hash.i32(self.source_crop_bottom_px_exclusive);
        hash.u8(match self.aspect_ratio_policy {
            ProjectionRasterAspectRatioPolicyV1::FitContainCentered => 1,
        });
        hash.u8(match self.pixel_layout {
            ProjectionRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown => 1,
        });
        hash.u8(match self.coverage_policy {
            ProjectionRasterCoveragePolicyV1::Antialiased => 1,
        });
        hash.bytes(&self.background_rgba);
        hash.bytes(&self.committed_ink_rgba);
        hash.u32(self.stroke_width_16_16);
        hash.u8(match self.stroke_cap {
            ProjectionRasterStrokeCapV1::Round => 1,
        });
        hash.u8(match self.stroke_join {
            ProjectionRasterStrokeJoinV1::Round => 1,
        });
        hash.u8(match self.rounding_policy {
            ProjectionRasterRoundingPolicyV1::NearestTiesAwayQ16 => 1,
        });
        hash.u8(match self.clipping_policy {
            ProjectionRasterClippingPolicyV1::RejectPointsOutsideSourceCropClipCoverageAtOutputBounds => 1,
        });
        hash.u8(match self.single_point_policy {
            ProjectionRasterSinglePointPolicyV1::OpaqueDiscAtObservedPoint => 1,
        });
        hash.u8(match self.stroke_order_policy {
            ProjectionRasterStrokeOrderPolicyV1::JournalFirstOccurrence => 1,
        });
        hash.u32(self.row_stride_bytes);
        hash.u32(self.output_buffer_bytes);
        hash.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectionRasterSourceBindingV1 {
    pub journal_id: String,
    pub logical_revision: u64,
    pub last_sequence: u64,
    pub region_id: String,
    pub line_id: Option<String>,
    pub input_view_id: String,
    pub ink_binding_sha256: String,
}

/// Metadata-only provenance for the raster bytes generated for one M4 request.
/// Its checks bind these observations together, but do not authenticate files,
/// hash omitted image bytes during journal append, or prove external parity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedRasterProvenanceV1 {
    pub schema_version: u32,
    pub source: ProjectionRasterSourceBindingV1,
    pub source_content_sha256: String,
    pub projection_spec: ProjectionRasterSpecV1,
    pub projection_spec_sha256: String,
    pub geometry_schema_version: u32,
    pub geometry_sha256: String,
    pub raster_artifact_schema_version: u32,
    pub renderer_version: String,
    pub output_width_px: u32,
    pub output_height_px: u32,
    pub row_stride_bytes: u32,
    pub pixel_layout: ProjectionRasterPixelLayoutV1,
    pub pixel_bytes_sha256: String,
    pub png_bytes_len: u32,
    pub png_bytes_sha256: String,
    pub raster_artifact_sha256: String,
}

impl GeneratedRasterProvenanceV1 {
    fn expected_raster_artifact_sha256(&self) -> Result<[u8; 32], JournalError> {
        let source_content_sha256 = decode_sha256(&self.source_content_sha256)?;
        let projection_spec_sha256 = decode_sha256(&self.projection_spec_sha256)?;
        let geometry_sha256 = decode_sha256(&self.geometry_sha256)?;
        let pixel_bytes_sha256 = decode_sha256(&self.pixel_bytes_sha256)?;
        let png_bytes_sha256 = decode_sha256(&self.png_bytes_sha256)?;
        Ok(canonical_raster_artifact_sha256(
            CanonicalRasterArtifactHashInputV1 {
                schema_version: self.raster_artifact_schema_version,
                renderer_version: &self.renderer_version,
                source_journal_id: &self.source.journal_id,
                source_logical_revision: self.source.logical_revision,
                source_last_sequence: self.source.last_sequence,
                source_content_sha256: &source_content_sha256,
                projection_spec_sha256: &projection_spec_sha256,
                geometry_sha256: &geometry_sha256,
                output_width_px: self.output_width_px,
                output_height_px: self.output_height_px,
                row_stride_bytes: self.row_stride_bytes,
                pixel_layout: self.pixel_layout,
                pixel_bytes_sha256: &pixel_bytes_sha256,
                png_bytes_sha256: &png_bytes_sha256,
            },
        ))
    }
}

pub(crate) struct CanonicalRasterArtifactHashInputV1<'a> {
    pub schema_version: u32,
    pub renderer_version: &'a str,
    pub source_journal_id: &'a str,
    pub source_logical_revision: u64,
    pub source_last_sequence: u64,
    pub source_content_sha256: &'a [u8; 32],
    pub projection_spec_sha256: &'a [u8; 32],
    pub geometry_sha256: &'a [u8; 32],
    pub output_width_px: u32,
    pub output_height_px: u32,
    pub row_stride_bytes: u32,
    pub pixel_layout: ProjectionRasterPixelLayoutV1,
    pub pixel_bytes_sha256: &'a [u8; 32],
    pub png_bytes_sha256: &'a [u8; 32],
}

pub(crate) fn canonical_raster_artifact_sha256(
    input: CanonicalRasterArtifactHashInputV1<'_>,
) -> [u8; 32] {
    let mut hash = RasterMetadataHashWriter::new(b"LassoInk/canonical-raster-artifact/v1\0");
    hash.u32(input.schema_version);
    hash.string(input.renderer_version);
    hash.string(input.source_journal_id);
    hash.u64(input.source_logical_revision);
    hash.u64(input.source_last_sequence);
    hash.bytes(input.source_content_sha256);
    hash.bytes(input.projection_spec_sha256);
    hash.bytes(input.geometry_sha256);
    hash.u32(input.output_width_px);
    hash.u32(input.output_height_px);
    hash.u32(input.row_stride_bytes);
    hash.u8(match input.pixel_layout {
        ProjectionRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown => 1,
    });
    hash.bytes(input.pixel_bytes_sha256);
    hash.bytes(input.png_bytes_sha256);
    hash.finish()
}

struct RasterMetadataHashWriter(Sha256);

impl RasterMetadataHashWriter {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(domain);
        Self(hash)
    }

    fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn u32(&mut self, value: u32) {
        self.0.update(value.to_le_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.0.update(value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.0.update(value);
    }

    fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// A region-level user correction attached to one exact stored projection.
/// It is derived annotation history, not a canonical physical sample or a
/// replacement for the immutable provider result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    content = "text",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum RegionCorrectionActionV1 {
    SetText(String),
    Reset,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegionCorrectionV1 {
    pub correction_id: String,
    pub projection_id: String,
    pub ink: ProjectionInkBindingV1,
    pub action: RegionCorrectionActionV1,
}

impl Default for StrokeViewFrame {
    fn default() -> Self {
        Self {
            screen_origin_x_px: 0,
            screen_origin_y_px: 0,
            dpi_scale_factor_bits: 1.0_f64.to_bits(),
            canvas_zoom_bits: 1.0_f64.to_bits(),
            canvas_pan_x_bits: 0.0_f64.to_bits(),
            canvas_pan_y_bits: 0.0_f64.to_bits(),
            toolbar_height_px: 40,
        }
    }
}

impl StrokeViewFrame {
    pub(crate) fn is_valid(self) -> bool {
        let dpi_scale = f64::from_bits(self.dpi_scale_factor_bits);
        let zoom = f64::from_bits(self.canvas_zoom_bits);
        let pan_x = f64::from_bits(self.canvas_pan_x_bits);
        let pan_y = f64::from_bits(self.canvas_pan_y_bits);
        dpi_scale.is_finite()
            && dpi_scale > 0.0
            && zoom.is_finite()
            && (0.2..=8.0).contains(&zoom)
            && pan_x.is_finite()
            && pan_y.is_finite()
            && self.toolbar_height_px <= 4096
    }
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
    pub app_epoch_id: String,
    pub metadata: JournalMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JournalEvent {
    PhysicalSample(Box<PhysicalSample>),
    Metadata(JournalMetadata),
    SessionEpochStarted {
        epoch: SessionEpoch,
        app_arrival_elapsed_ns: u128,
    },
    StrokeStarted {
        target: StrokeRef,
        view_frame: StrokeViewFrame,
        app_arrival_elapsed_ns: u128,
    },
    StrokeInterrupted {
        target: StrokeRef,
        reason: StrokeInterruptionReason,
        app_arrival_elapsed_ns: u128,
    },
    /// One durable row is one complete logical action. Multi-stroke actions
    /// are bounded lists in this row, so a crash cannot expose a partial edit.
    EditAction {
        action_id: u64,
        revision_id: u64,
        app_arrival_elapsed_ns: u128,
        command: EditCommand,
    },
    Undo {
        action_id: u64,
        revision_id: u64,
        app_arrival_elapsed_ns: u128,
    },
    Redo {
        action_id: u64,
        revision_id: u64,
        app_arrival_elapsed_ns: u128,
    },
    MigrationProvenance {
        source_schema_version: u32,
        source_journal_id: String,
        source_prefix_fingerprint: u64,
        source_record_count: u64,
        app_arrival_elapsed_ns: Option<u128>,
    },
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
    RecognitionProjection {
        app_arrival_elapsed_ns: u128,
        projection: Box<RecognitionProjectionV1>,
    },
    RegionCorrection {
        app_arrival_elapsed_ns: u128,
        correction: Box<RegionCorrectionV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalRecord {
    pub sequence: u64,
    /// Monotonic application elapsed time is meaningful only within this epoch.
    pub app_epoch_id: String,
    pub event: JournalEvent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionEpoch {
    pub session_id: String,
    /// Wall-clock context only; never used to convert native clocks.
    pub started_at_unix_ns: Option<u128>,
    pub config_id: Option<String>,
    pub provenance: String,
    /// New capture sessions require explicit stroke start/commit rows.
    /// Legacy migrated sessions remain visible without synthesized markers.
    pub requires_stroke_commit: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredSessionEpoch {
    pub sequence: u64,
    pub epoch: SessionEpoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EditCommand {
    Tombstone {
        targets: Vec<StrokeRef>,
    },
    Restore {
        targets: Vec<StrokeRef>,
    },
    StrokeVisibility {
        targets: Vec<StrokeRef>,
        visible: bool,
    },
    Move {
        target: StrokeRef,
        delta_x_raw: i64,
        delta_y_raw: i64,
        coordinate_space: String,
        units: String,
    },
    Correction {
        target: StrokeRef,
        corrected_text: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredEditAction {
    pub sequence: u64,
    pub action_id: u64,
    pub revision_id: u64,
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: u128,
    pub command: EditCommand,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredEditControl {
    pub sequence: u64,
    pub action_id: u64,
    pub revision_id: u64,
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: u128,
    pub redo: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredMigrationProvenance {
    pub sequence: u64,
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: Option<u128>,
    pub source_schema_version: u32,
    pub source_journal_id: String,
    pub source_prefix_fingerprint: u64,
    pub source_record_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrokeInterruptionReason {
    PointerDownBeforePenUp,
    PointerCaptureChanged,
    PointerLeave,
    PointerReentryBoundary,
    DeviceOutOfRange,
    DeviceChanged,
    DeviceReentryBoundary,
    ContactLostWithoutPenUp,
    CanvasViewTransformChanged,
    CanvasToolChanged,
    CanceledNativeUp,
    UnattributedNativeUp,
    AmbiguousNativeUp,
    MixedDeviceBatch,
    WindowFocusLost,
    WriterBackpressure,
    ProcessEndedWithoutPenUp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredStrokeStart {
    pub sequence: u64,
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: u128,
    pub target: StrokeRef,
    pub view_frame: StrokeViewFrame,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredStrokeInterruption {
    pub sequence: u64,
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: u128,
    pub target: StrokeRef,
    pub reason: StrokeInterruptionReason,
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
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: u128,
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
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: u128,
    pub target: StrokeRef,
    pub corrected_text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredRecognitionProjection {
    pub sequence: u64,
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: u128,
    pub projection: RecognitionProjectionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredRegionCorrection {
    pub sequence: u64,
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: u128,
    pub correction: RegionCorrectionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredTombstone {
    pub sequence: u64,
    pub logical_revision: u64,
    pub app_epoch_id: String,
    pub app_arrival_elapsed_ns: u128,
    pub target: StrokeRef,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct JournalReplayState {
    pub journal_id: String,
    pub current_session_id: String,
    pub last_sequence: u64,
    pub logical_revision: u64,
    pub physical_samples: Vec<StoredPhysicalSample>,
    pub session_epochs: Vec<StoredSessionEpoch>,
    pub stroke_starts: Vec<StoredStrokeStart>,
    pub stroke_interruptions: Vec<StoredStrokeInterruption>,
    pub active_strokes: HashMap<StrokeRef, StoredStrokeStart>,
    pub edit_actions: Vec<StoredEditAction>,
    pub edit_controls: Vec<StoredEditControl>,
    pub migration_provenance: Vec<StoredMigrationProvenance>,
    /// Full append-only metadata history; later values never overwrite prior
    /// declarations or observations.
    pub metadata_history: Vec<StoredMetadata>,
    pub tombstones: Vec<StrokeRef>,
    pub tombstone_history: Vec<StoredTombstone>,
    pub moves: Vec<StoredMove>,
    pub corrections: Vec<StoredCorrection>,
    pub recognition_projections: Vec<StoredRecognitionProjection>,
    pub region_corrections: Vec<StoredRegionCorrection>,
    session_ids: HashSet<String>,
    stroke_start_set: HashSet<StrokeRef>,
    undo_stack: Vec<u64>,
    redo_stack: Vec<u64>,
    stroke_domains: HashMap<StrokeRef, HashSet<(String, String)>>,
    tombstone_set: HashSet<StrokeRef>,
    move_totals: HashMap<StrokeRef, ProjectedTransform>,
    recognition_projection_ids: HashSet<String>,
    region_correction_ids: HashSet<String>,
    derived_event_sequences: HashSet<u64>,
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
    pub stroke_ref: Option<StrokeRef>,
    /// A derived coordinate view. The stored raw sample is never modified.
    pub effective_position: Option<RawPosition>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JournalErrorKind {
    Io,
    InvalidData,
    LimitReached,
    AllocationFailed,
    WriterLeaseBusy,
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

    fn writer_lease_busy() -> Self {
        Self {
            kind: JournalErrorKind::WriterLeaseBusy,
            message: "another writer holds the journal's exclusive file lease".to_owned(),
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
    pub source_journal_id: String,
    pub destination_journal_id: String,
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
    schema_version: u32,
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

impl SessionEpoch {
    fn validate(&self) -> Result<(), JournalError> {
        validate_text(&self.session_id, "session epoch ID", 256)?;
        validate_optional_text(self.config_id.as_deref(), "session epoch configuration ID")?;
        validate_text(
            &self.provenance,
            "session epoch provenance",
            MAX_METADATA_TEXT_BYTES,
        )?;
        if self.session_id.is_empty() || self.provenance.is_empty() {
            return Err(JournalError::invalid(
                "session epoch ID and provenance must be nonempty",
            ));
        }
        Ok(())
    }
}

impl PhysicalSample {
    pub(crate) fn stroke_ref(&self, journal_id: &str) -> Option<StrokeRef> {
        self.stroke_id.as_ref().map(|stroke_id| StrokeRef {
            journal_id: journal_id.to_owned(),
            session_id: self.session_id.clone(),
            source_api: self.source_api.clone(),
            device_id: self.source_device_id.clone(),
            pointer_id: self.pointer_id,
            stroke_id: stroke_id.clone(),
        })
    }

    fn validate(&self) -> Result<(), JournalError> {
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

    fn validate(&self) -> Result<(), JournalError> {
        self.validate_shape()
    }
}

impl JournalReplayState {
    fn for_header(header: &JournalHeader) -> Result<Self, JournalError> {
        let initial_epoch = SessionEpoch {
            session_id: header.session_id.clone(),
            started_at_unix_ns: None,
            config_id: header.config_id.clone(),
            provenance: "initial journal header session; original app origin is implicit"
                .to_owned(),
            requires_stroke_commit: false,
        };
        initial_epoch.validate()?;
        let mut state = Self {
            journal_id: header.journal_id.clone(),
            current_session_id: header.session_id.clone(),
            ..Self::default()
        };
        state
            .session_ids
            .try_reserve(1)
            .map_err(JournalError::allocation)?;
        state.session_ids.insert(header.session_id.clone());
        state
            .session_epochs
            .try_reserve(1)
            .map_err(JournalError::allocation)?;
        state.session_epochs.push(StoredSessionEpoch {
            sequence: 0,
            epoch: initial_epoch,
        });
        Ok(state)
    }

    fn contains_stroke(&self, target: &StrokeRef) -> bool {
        self.stroke_domains.contains_key(target)
    }

    fn stroke_is_visible(&self, target: &StrokeRef) -> bool {
        let mut visible = !self.session_requires_stroke_commit(&target.session_id)
            && !self.tombstone_set.contains(target);
        for action in self.edit_actions.iter().filter(|action| action.active) {
            match &action.command {
                EditCommand::Tombstone { targets } if targets.contains(target) => {
                    visible = false;
                }
                EditCommand::Restore { targets } if targets.contains(target) => {
                    visible = true;
                }
                EditCommand::StrokeVisibility {
                    targets,
                    visible: value,
                } if targets.contains(target) => {
                    visible = *value;
                }
                _ => {}
            }
        }
        visible
    }

    fn session_requires_stroke_commit(&self, session_id: &str) -> bool {
        self.session_epochs
            .iter()
            .find(|epoch| epoch.epoch.session_id == session_id)
            .is_some_and(|epoch| epoch.epoch.requires_stroke_commit)
    }

    fn index_sample(&mut self, sample: &PhysicalSample) -> Result<(), JournalError> {
        let Some(stroke) = sample.stroke_ref(&self.journal_id) else {
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
        self.validate_move_domain(target, coordinate_space, units)?;
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

    fn validate_move_domain(
        &self,
        target: &StrokeRef,
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
        Ok(())
    }

    fn validate_edit_target(&self, target: &StrokeRef) -> Result<(), JournalError> {
        validate_stroke_ref(target)?;
        if target.journal_id != self.journal_id
            || !self.session_ids.contains(&target.session_id)
            || !self.contains_stroke(target)
        {
            return Err(JournalError::invalid(
                "edit target does not identify an observed project/session/source/device/pointer/stroke",
            ));
        }
        Ok(())
    }

    fn validate_restore_target(&self, target: &StrokeRef) -> Result<(), JournalError> {
        self.validate_edit_target(target)?;
        if self.session_requires_stroke_commit(&target.session_id)
            && !self.edit_actions.iter().any(|action| {
                matches!(
                    &action.command,
                    EditCommand::StrokeVisibility { targets, visible: true }
                        if targets.iter().any(|committed| committed == target)
                )
            })
        {
            return Err(JournalError::invalid(
                "Restore cannot expose a new-session stroke without a durable native-up commit",
            ));
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

    fn validate_selected_ink_suffix(
        &self,
        source_last_sequence: u64,
        selected_strokes: &[StrokeRef],
    ) -> Result<(), JournalError> {
        if source_last_sequence > self.last_sequence {
            return Err(JournalError::invalid(
                "derived result source prefix is ahead of the current journal",
            ));
        }
        let selected_contains = |target: &StrokeRef| selected_strokes.contains(target);
        if self
            .stroke_interruptions
            .iter()
            .any(|event| event.sequence > source_last_sequence && selected_contains(&event.target))
            || self.tombstone_history.iter().any(|event| {
                event.sequence > source_last_sequence && selected_contains(&event.target)
            })
            || self.moves.iter().any(|event| {
                event.sequence > source_last_sequence && selected_contains(&event.target)
            })
            || self.corrections.iter().any(|event| {
                event.sequence > source_last_sequence && selected_contains(&event.target)
            })
        {
            return Err(JournalError::invalid(
                "derived result is stale because a selected stroke changed after its source prefix",
            ));
        }
        Ok(())
    }

    fn validate_ink_binding(
        &self,
        binding: &ProjectionInkBindingV1,
    ) -> Result<HashMap<u64, StrokeRef>, JournalError> {
        validate_ink_binding_fields(binding)?;
        // Keep the exact M4 prefix as provenance. Later unrelated journal
        // rows may exist; freshness is based on the unchanged selected ink,
        // captured frames, and logical revision rather than rebinding it.
        if binding.journal_id != self.journal_id
            || binding.logical_revision != self.logical_revision
            || binding.last_sequence > self.last_sequence
        {
            return Err(JournalError::invalid(
                "projection source journal or logical revision is stale or mismatched",
            ));
        }
        self.validate_selected_ink_suffix(binding.last_sequence, &binding.selected_strokes)?;

        let mut selected = HashSet::new();
        selected
            .try_reserve(binding.selected_strokes.len())
            .map_err(JournalError::allocation)?;
        for stroke in &binding.selected_strokes {
            if stroke.journal_id != self.journal_id {
                return Err(JournalError::invalid(
                    "projection selected stroke belongs to a different project",
                ));
            }
            self.validate_edit_target(stroke)?;
            if !self.stroke_is_visible(stroke) {
                return Err(JournalError::invalid(
                    "projection selected stroke is not visible in the current logical view",
                ));
            }
            if !selected.insert(stroke.clone()) {
                return Err(JournalError::invalid(
                    "projection repeats a selected stroke identity",
                ));
            }
        }

        let mut observed_sequences = Vec::new();
        observed_sequences
            .try_reserve(self.physical_samples.len().min(MAX_PROJECTION_SAMPLES + 1))
            .map_err(JournalError::allocation)?;
        let mut observed_stroke_order = Vec::new();
        observed_stroke_order
            .try_reserve(binding.selected_strokes.len())
            .map_err(JournalError::allocation)?;
        let mut seen_strokes = HashSet::new();
        seen_strokes
            .try_reserve(binding.selected_strokes.len())
            .map_err(JournalError::allocation)?;
        let mut sample_strokes = HashMap::new();
        sample_strokes
            .try_reserve(binding.source_sample_sequences.len())
            .map_err(JournalError::allocation)?;
        for stored in &self.physical_samples {
            let Some(stroke) = stored.sample.stroke_ref(&self.journal_id) else {
                continue;
            };
            if !selected.contains(&stroke) {
                continue;
            }
            if stored.sequence > binding.last_sequence {
                return Err(JournalError::invalid(
                    "projection source is stale because a selected stroke gained samples",
                ));
            }
            if observed_sequences.len() >= MAX_PROJECTION_SAMPLES {
                return Err(JournalError::limit(
                    "projection selected sample count exceeds its fixed cap",
                ));
            }
            observed_sequences.push(stored.sequence);
            sample_strokes.insert(stored.sequence, stroke.clone());
            if seen_strokes.insert(stroke.clone()) {
                observed_stroke_order.push(stroke);
            }
        }
        if observed_sequences != binding.source_sample_sequences
            || observed_stroke_order != binding.selected_strokes
        {
            return Err(JournalError::invalid(
                "projection sample sequence or canonical stroke order differs from journal history",
            ));
        }

        for (index, stroke_view) in binding.stroke_views.iter().enumerate() {
            let selected_stroke = &binding.selected_strokes[index];
            if &stroke_view.stroke != selected_stroke || !stroke_view.frame.is_valid() {
                return Err(JournalError::invalid(
                    "projection stroke view order or frame is invalid",
                ));
            }
            let observed = self
                .stroke_starts
                .iter()
                .find(|start| &start.target == selected_stroke)
                .ok_or_else(|| {
                    JournalError::invalid(
                        "projection requires a durable captured view frame for every stroke",
                    )
                })?;
            if observed.sequence > binding.last_sequence || observed.view_frame != stroke_view.frame
            {
                return Err(JournalError::invalid(
                    "projection view frame differs from its captured journal frame",
                ));
            }
            if self
                .stroke_interruptions
                .iter()
                .any(|interruption| interruption.target == *selected_stroke)
            {
                return Err(JournalError::invalid(
                    "projection cannot bind a durably interrupted stroke",
                ));
            }
        }
        Ok(sample_strokes)
    }

    fn validate_recognition_projection(
        &self,
        projection: &RecognitionProjectionV1,
    ) -> Result<(), JournalError> {
        validate_recognition_projection_fields(projection)?;
        let sample_strokes = self.validate_ink_binding(&projection.ink)?;
        for candidate in &projection.candidates {
            for range in &candidate.stroke_ranges {
                if !projection.ink.selected_strokes.contains(&range.stroke)
                    || sample_strokes.get(&range.first_journal_sequence) != Some(&range.stroke)
                    || sample_strokes.get(&range.last_journal_sequence) != Some(&range.stroke)
                {
                    return Err(JournalError::invalid(
                        "provider range is not contained in the bound selected stroke samples",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_region_correction(
        &self,
        correction: &RegionCorrectionV1,
    ) -> Result<(), JournalError> {
        validate_region_correction_fields(correction)?;
        self.validate_ink_binding(&correction.ink)?;
        let projection = self
            .recognition_projections
            .iter()
            .find(|stored| stored.projection.projection_id == correction.projection_id)
            .ok_or_else(|| JournalError::invalid("correction target projection is unknown"))?;
        if projection.projection.ink != correction.ink {
            return Err(JournalError::invalid(
                "region correction does not match its exact projection ink binding",
            ));
        }
        Ok(())
    }

    fn prepare_record(
        &mut self,
        _header: &JournalHeader,
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
            JournalEvent::SessionEpochStarted { epoch, .. } => {
                epoch.validate()?;
                if record.app_epoch_id != epoch.session_id {
                    return Err(JournalError::invalid(
                        "session-start event app epoch must match its new session ID",
                    ));
                }
                if self.session_ids.contains(&epoch.session_id) {
                    return Err(JournalError::invalid(
                        "session epoch ID already exists in this project journal",
                    ));
                }
                self.session_ids
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.session_epochs
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
            _ => {
                if record.app_epoch_id != self.current_session_id {
                    return Err(JournalError::invalid(
                        "record app-arrival epoch is not the current session epoch",
                    ));
                }
            }
        }
        match &record.event {
            JournalEvent::PhysicalSample(sample) => {
                sample.validate()?;
                if sample.session_id != record.app_epoch_id {
                    return Err(JournalError::invalid(
                        "physical sample session ID differs from its app-arrival epoch",
                    ));
                }
                if self.physical_samples.len() >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::limit("physical sample record cap reached"));
                }
                if sample.stroke_id.is_some()
                    && self
                        .session_epochs
                        .iter()
                        .find(|epoch| epoch.epoch.session_id == sample.session_id)
                        .is_some_and(|epoch| epoch.epoch.requires_stroke_commit)
                {
                    let stroke = sample
                        .stroke_ref(&self.journal_id)
                        .expect("a present stroke ID creates a stroke target");
                    if !self.active_strokes.contains_key(&stroke) {
                        return Err(JournalError::invalid(
                            "new-session stroke sample has no explicit StrokeStarted event",
                        ));
                    }
                }
                self.physical_samples
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.index_sample(sample)?;
            }
            JournalEvent::Metadata(metadata) => {
                metadata.validate()?;
                if metadata.scope == MetadataScope::Session
                    && !self.session_ids.contains(&metadata.scope_id)
                {
                    return Err(JournalError::invalid(
                        "session metadata references an unknown session epoch",
                    ));
                }
                if self.metadata_history.len() >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::limit("journal metadata history cap reached"));
                }
                self.metadata_history
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
            JournalEvent::SessionEpochStarted { .. } => {}
            JournalEvent::StrokeStarted {
                target, view_frame, ..
            } => {
                validate_stroke_ref(target)?;
                if !view_frame.is_valid() {
                    return Err(JournalError::invalid(
                        "stroke start has an invalid captured view frame",
                    ));
                }
                if target.journal_id != self.journal_id
                    || target.session_id != record.app_epoch_id
                    || !self.session_ids.contains(&target.session_id)
                {
                    return Err(JournalError::invalid(
                        "StrokeStarted target must identify this project and current session",
                    ));
                }
                if self.stroke_start_set.contains(target) {
                    return Err(JournalError::invalid(
                        "stroke identity already has a start record",
                    ));
                }
                self.stroke_start_set
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.stroke_starts
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.active_strokes
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
            JournalEvent::StrokeInterrupted { target, .. } => {
                validate_stroke_ref(target)?;
                if !self.active_strokes.contains_key(target) {
                    return Err(JournalError::invalid(
                        "StrokeInterrupted target is not an active started stroke",
                    ));
                }
                self.stroke_interruptions
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
            JournalEvent::MigrationProvenance {
                source_schema_version,
                source_journal_id,
                ..
            } => {
                if !matches!(
                    *source_schema_version,
                    LEGACY_JOURNAL_SCHEMA_VERSION
                        | PREVIOUS_JOURNAL_SCHEMA_VERSION
                        | THIRD_JOURNAL_SCHEMA_VERSION
                ) {
                    return Err(JournalError::invalid(
                        "migration provenance has an unsupported source schema",
                    ));
                }
                validate_text(source_journal_id, "migration source journal ID", 128)?;
                self.migration_provenance
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
            JournalEvent::EditAction {
                action_id,
                revision_id,
                command,
                ..
            } => {
                if *action_id != record.sequence
                    || *revision_id != self.logical_revision.saturating_add(1)
                {
                    return Err(JournalError::invalid(
                        "edit action ID or revision does not extend the current history",
                    ));
                }
                validate_edit_command(self, command)?;
                self.edit_actions
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.undo_stack
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
            JournalEvent::Undo {
                action_id,
                revision_id,
                ..
            } => {
                if *revision_id != self.logical_revision.saturating_add(1)
                    || self.undo_stack.last() != Some(action_id)
                {
                    return Err(JournalError::invalid(
                        "undo must target the latest active edit action",
                    ));
                }
                self.edit_controls
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.redo_stack
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
            JournalEvent::Redo {
                action_id,
                revision_id,
                ..
            } => {
                if *revision_id != self.logical_revision.saturating_add(1)
                    || self.redo_stack.last() != Some(action_id)
                {
                    return Err(JournalError::invalid(
                        "redo must target the latest undone edit action",
                    ));
                }
                self.edit_controls
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.undo_stack
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
            JournalEvent::RecognitionProjection { projection, .. } => {
                if self.recognition_projections.len() >= MAX_RECOGNITION_PROJECTIONS {
                    return Err(JournalError::limit(
                        "recognition projection history cap reached",
                    ));
                }
                self.validate_recognition_projection(projection)?;
                if self
                    .recognition_projection_ids
                    .contains(&projection.projection_id)
                {
                    return Err(JournalError::invalid(
                        "recognition projection ID already exists",
                    ));
                }
                self.recognition_projections
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.recognition_projection_ids
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.derived_event_sequences
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
            }
            JournalEvent::RegionCorrection { correction, .. } => {
                if self.region_corrections.len() >= MAX_REGION_CORRECTIONS {
                    return Err(JournalError::limit("region correction history cap reached"));
                }
                self.validate_region_correction(correction)?;
                if self
                    .region_correction_ids
                    .contains(&correction.correction_id)
                {
                    return Err(JournalError::invalid("correction ID already exists"));
                }
                self.region_corrections
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.region_correction_ids
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                self.derived_event_sequences
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
        self.validate_edit_target(target)
    }

    fn apply_prepared(&mut self, record: JournalRecord) {
        let JournalRecord {
            sequence,
            app_epoch_id,
            event,
        } = record;
        match event {
            JournalEvent::PhysicalSample(sample) => {
                self.physical_samples.push(StoredPhysicalSample {
                    sequence,
                    sample: *sample,
                });
            }
            JournalEvent::Metadata(metadata) => {
                self.metadata_history.push(StoredMetadata {
                    sequence,
                    app_epoch_id: app_epoch_id.clone(),
                    metadata,
                });
            }
            JournalEvent::SessionEpochStarted { epoch, .. } => {
                self.session_ids.insert(epoch.session_id.clone());
                self.current_session_id = epoch.session_id.clone();
                self.session_epochs
                    .push(StoredSessionEpoch { sequence, epoch });
            }
            JournalEvent::StrokeStarted {
                target,
                view_frame,
                app_arrival_elapsed_ns,
            } => {
                let stored = StoredStrokeStart {
                    sequence,
                    app_epoch_id: app_epoch_id.clone(),
                    app_arrival_elapsed_ns,
                    target: target.clone(),
                    view_frame,
                };
                self.stroke_start_set.insert(target.clone());
                self.active_strokes.insert(target.clone(), stored.clone());
                self.stroke_starts.push(stored);
            }
            JournalEvent::StrokeInterrupted {
                target,
                reason,
                app_arrival_elapsed_ns,
            } => {
                self.active_strokes.remove(&target);
                self.stroke_interruptions.push(StoredStrokeInterruption {
                    sequence,
                    app_epoch_id: app_epoch_id.clone(),
                    app_arrival_elapsed_ns,
                    target,
                    reason,
                });
            }
            JournalEvent::MigrationProvenance {
                source_schema_version,
                source_journal_id,
                source_prefix_fingerprint,
                source_record_count,
                app_arrival_elapsed_ns,
            } => self.migration_provenance.push(StoredMigrationProvenance {
                sequence,
                app_epoch_id: app_epoch_id.clone(),
                app_arrival_elapsed_ns,
                source_schema_version,
                source_journal_id,
                source_prefix_fingerprint,
                source_record_count,
            }),
            JournalEvent::EditAction {
                action_id,
                revision_id,
                app_arrival_elapsed_ns,
                command,
            } => {
                if let EditCommand::StrokeVisibility {
                    targets,
                    visible: true,
                } = &command
                {
                    for target in targets {
                        self.active_strokes.remove(target);
                    }
                }
                self.edit_actions.push(StoredEditAction {
                    sequence,
                    action_id,
                    revision_id,
                    app_epoch_id: app_epoch_id.clone(),
                    app_arrival_elapsed_ns,
                    command,
                    active: true,
                });
                self.undo_stack.push(action_id);
                self.redo_stack.clear();
                self.logical_revision = revision_id;
            }
            JournalEvent::Undo {
                action_id,
                revision_id,
                app_arrival_elapsed_ns,
            } => {
                self.undo_stack.pop();
                self.redo_stack.push(action_id);
                self.edit_actions
                    .iter_mut()
                    .find(|action| action.action_id == action_id)
                    .expect("undo target was validated")
                    .active = false;
                self.edit_controls.push(StoredEditControl {
                    sequence,
                    action_id,
                    revision_id,
                    app_epoch_id: app_epoch_id.clone(),
                    app_arrival_elapsed_ns,
                    redo: false,
                });
                self.logical_revision = revision_id;
            }
            JournalEvent::Redo {
                action_id,
                revision_id,
                app_arrival_elapsed_ns,
            } => {
                self.redo_stack.pop();
                self.undo_stack.push(action_id);
                self.edit_actions
                    .iter_mut()
                    .find(|action| action.action_id == action_id)
                    .expect("redo target was validated")
                    .active = true;
                self.edit_controls.push(StoredEditControl {
                    sequence,
                    action_id,
                    revision_id,
                    app_epoch_id: app_epoch_id.clone(),
                    app_arrival_elapsed_ns,
                    redo: true,
                });
                self.logical_revision = revision_id;
            }
            JournalEvent::Revision { revision_id, .. } => {
                self.logical_revision = revision_id;
            }
            JournalEvent::Tombstone {
                logical_revision,
                app_arrival_elapsed_ns,
                target,
            } => {
                self.tombstones.push(target.clone());
                self.tombstone_history.push(StoredTombstone {
                    sequence,
                    logical_revision,
                    app_epoch_id: app_epoch_id.clone(),
                    app_arrival_elapsed_ns,
                    target,
                });
            }
            JournalEvent::StrokeMove {
                logical_revision,
                app_arrival_elapsed_ns,
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
                    app_epoch_id: app_epoch_id.clone(),
                    app_arrival_elapsed_ns,
                    target,
                    delta_x_raw,
                    delta_y_raw,
                    coordinate_space,
                    units,
                });
            }
            JournalEvent::UserCorrection {
                logical_revision,
                app_arrival_elapsed_ns,
                target,
                corrected_text,
                ..
            } => self.corrections.push(StoredCorrection {
                sequence,
                logical_revision,
                app_epoch_id: app_epoch_id.clone(),
                app_arrival_elapsed_ns,
                target,
                corrected_text,
            }),
            JournalEvent::RecognitionProjection {
                app_arrival_elapsed_ns,
                projection,
            } => {
                self.recognition_projection_ids
                    .insert(projection.projection_id.clone());
                self.derived_event_sequences.insert(sequence);
                self.recognition_projections
                    .push(StoredRecognitionProjection {
                        sequence,
                        app_epoch_id: app_epoch_id.clone(),
                        app_arrival_elapsed_ns,
                        projection: *projection,
                    });
            }
            JournalEvent::RegionCorrection {
                app_arrival_elapsed_ns,
                correction,
            } => {
                self.region_correction_ids
                    .insert(correction.correction_id.clone());
                self.derived_event_sequences.insert(sequence);
                self.region_corrections.push(StoredRegionCorrection {
                    sequence,
                    app_epoch_id: app_epoch_id.clone(),
                    app_arrival_elapsed_ns,
                    correction: *correction,
                });
            }
        }
        self.last_sequence = sequence;
    }

    pub(crate) fn projected_samples(&self) -> Result<Vec<ProjectedSample<'_>>, JournalError> {
        let mut visibility = HashMap::<StrokeRef, bool>::new();
        let mut edit_moves = HashMap::<StrokeRef, ProjectedTransform>::new();
        visibility
            .try_reserve(self.edit_actions.len())
            .map_err(JournalError::allocation)?;
        edit_moves
            .try_reserve(self.edit_actions.len())
            .map_err(JournalError::allocation)?;
        for action in self.edit_actions.iter().filter(|action| action.active) {
            match &action.command {
                EditCommand::Tombstone { targets } => {
                    for target in targets {
                        visibility.insert(target.clone(), false);
                    }
                }
                EditCommand::Restore { targets } => {
                    for target in targets {
                        visibility.insert(target.clone(), true);
                    }
                }
                EditCommand::StrokeVisibility { targets, visible } => {
                    for target in targets {
                        visibility.insert(target.clone(), *visible);
                    }
                }
                EditCommand::Move {
                    target,
                    delta_x_raw,
                    delta_y_raw,
                    coordinate_space,
                    units,
                } => {
                    if let Some(total) = edit_moves.get_mut(target) {
                        if total.coordinate_space != *coordinate_space || total.units != *units {
                            return Err(JournalError::invalid(
                                "active edit moves use inconsistent raw position domains",
                            ));
                        }
                        total.delta_x_raw = total
                            .delta_x_raw
                            .checked_add(*delta_x_raw)
                            .ok_or_else(|| JournalError::invalid("edit move x delta overflow"))?;
                        total.delta_y_raw = total
                            .delta_y_raw
                            .checked_add(*delta_y_raw)
                            .ok_or_else(|| JournalError::invalid("edit move y delta overflow"))?;
                    } else {
                        let legacy = self.move_totals.get(target);
                        if legacy.is_some_and(|legacy| {
                            legacy.coordinate_space != *coordinate_space || legacy.units != *units
                        }) {
                            return Err(JournalError::invalid(
                                "legacy and schema 3 moves use inconsistent raw position domains",
                            ));
                        }
                        edit_moves.insert(
                            target.clone(),
                            ProjectedTransform {
                                coordinate_space: coordinate_space.clone(),
                                units: units.clone(),
                                // Keep the accumulation order shared with
                                // validate_edit_command: legacy transform
                                // first, then active schema 3 actions in
                                // journal order. Separately summing actions
                                // could overflow even when the final combined
                                // raw coordinate is representable.
                                delta_x_raw: legacy.map_or(0, |legacy| legacy.delta_x_raw),
                                delta_y_raw: legacy.map_or(0, |legacy| legacy.delta_y_raw),
                            },
                        );
                        let total = edit_moves.get_mut(target).expect("move total was inserted");
                        total.delta_x_raw = total
                            .delta_x_raw
                            .checked_add(*delta_x_raw)
                            .ok_or_else(|| JournalError::invalid("edit move x delta overflow"))?;
                        total.delta_y_raw = total
                            .delta_y_raw
                            .checked_add(*delta_y_raw)
                            .ok_or_else(|| JournalError::invalid("edit move y delta overflow"))?;
                    }
                }
                EditCommand::Correction { .. } => {}
            }
        }

        let mut projected = Vec::new();
        projected
            .try_reserve(self.physical_samples.len())
            .map_err(JournalError::allocation)?;
        for stored in &self.physical_samples {
            let stroke = stored.sample.stroke_ref(&self.journal_id);
            if let Some(stroke) = &stroke {
                let default_visible = !self.session_requires_stroke_commit(&stroke.session_id)
                    && !self.tombstone_set.contains(stroke);
                let visible = visibility.get(stroke).copied().unwrap_or(default_visible);
                if !visible {
                    continue;
                }
            }
            let mut effective_position = stored.sample.position.clone();
            if let Some(stroke) = &stroke {
                let transform = edit_moves
                    .get(stroke)
                    .or_else(|| self.move_totals.get(stroke));
                if let Some(transform) = transform
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
            }
            projected.push(ProjectedSample {
                sequence: stored.sequence,
                sample: &stored.sample,
                stroke_ref: stroke,
                effective_position,
            });
        }
        Ok(projected)
    }

    pub(crate) fn incomplete_stroke_count(&self) -> usize {
        self.active_strokes
            .len()
            .saturating_add(self.stroke_interruptions.len())
    }
}

fn acquire_writer_lease(file: &File) -> Result<(), JournalError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(JournalError::writer_lease_busy()),
        Err(TryLockError::Error(error)) => Err(JournalError::io(error)),
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
            .read(true)
            .write(true)
            .open(&path)
            .map_err(JournalError::io)?;
        acquire_writer_lease(&file)?;
        let header_line = encode_row(&encode_header_fields(&header, JOURNAL_SCHEMA_VERSION))?;
        if header_line.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalError::limit(
                "journal header exceeds the file byte cap",
            ));
        }
        let state = JournalReplayState::for_header(&header)?;
        let mut writer = Self {
            path,
            file,
            header,
            state,
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

    pub(crate) fn header(&self) -> &JournalHeader {
        &self.header
    }

    pub(crate) fn replay_state(&self) -> &JournalReplayState {
        &self.state
    }

    pub(crate) fn active_session_id(&self) -> &str {
        &self.state.current_session_id
    }

    /// Opens an existing valid journal for append. A torn final line is
    /// explicitly truncated to the last validated record boundary. One
    /// exclusive OS file lease covers parsing, recovery, and future appends;
    /// malformed complete records and interior corruption are rejected.
    pub(crate) fn open_append(path: PathBuf) -> Result<Self, JournalError> {
        Self::open_append_with_validation_hook(path, || {})
    }

    fn open_append_with_validation_hook(
        path: PathBuf,
        after_validation: impl FnOnce(),
    ) -> Result<Self, JournalError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(JournalError::io)?;
        acquire_writer_lease(&file)?;
        file.seek(SeekFrom::Start(0)).map_err(JournalError::io)?;
        let parsed = parse_journal(&mut file)?;
        if parsed.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalError::invalid(
                "legacy journal is read-only; migrate into a schema 4 project journal before append",
            ));
        }
        let recovered_truncated_final_record = parsed.recovery.truncated_final_record;
        let valid_prefix_bytes = parsed.recovery.valid_prefix_bytes;
        let prefix_fingerprint = parsed
            .checkpoints
            .last()
            .map(|checkpoint| checkpoint.fingerprint)
            .ok_or_else(|| JournalError::invalid("journal has no validated header prefix"))?;
        after_validation();
        if recovered_truncated_final_record {
            file.set_len(valid_prefix_bytes).map_err(JournalError::io)?;
            file.sync_all().map_err(JournalError::io)?;
        }
        file.seek(SeekFrom::End(0)).map_err(JournalError::io)?;
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
        self.append_sample_record(sample)
            .map(|record| record.sequence)
    }

    pub(crate) fn append_sample_record(
        &mut self,
        sample: PhysicalSample,
    ) -> Result<JournalRecord, JournalError> {
        if sample.session_id != self.state.current_session_id {
            return Err(JournalError::invalid(
                "sample session ID must match the active app-arrival epoch",
            ));
        }
        self.append_event_record(JournalEvent::PhysicalSample(Box::new(sample)))
    }

    pub(crate) fn begin_session_epoch(
        &mut self,
        session_id: String,
        started_at_unix_ns: u128,
        config_id: Option<String>,
        provenance: String,
    ) -> Result<u64, JournalError> {
        let sequence = self.append_event(JournalEvent::SessionEpochStarted {
            epoch: SessionEpoch {
                session_id,
                started_at_unix_ns: Some(started_at_unix_ns),
                config_id,
                provenance,
                requires_stroke_commit: true,
            },
            app_arrival_elapsed_ns: 0,
        })?;
        // If a prior process ended with a pen down, record an explicit
        // interruption in the new arrival epoch. Never synthesize pen-up or
        // commit an in-progress stroke during resume.
        self.interrupt_active_strokes(StrokeInterruptionReason::ProcessEndedWithoutPenUp, 0)?;
        Ok(sequence)
    }

    pub(crate) fn start_stroke(
        &mut self,
        target: StrokeRef,
        view_frame: StrokeViewFrame,
        app_arrival_elapsed_ns: u128,
    ) -> Result<u64, JournalError> {
        self.start_stroke_record(target, view_frame, app_arrival_elapsed_ns)
            .map(|record| record.sequence)
    }

    pub(crate) fn start_stroke_record(
        &mut self,
        target: StrokeRef,
        view_frame: StrokeViewFrame,
        app_arrival_elapsed_ns: u128,
    ) -> Result<JournalRecord, JournalError> {
        self.append_event_record(JournalEvent::StrokeStarted {
            target,
            view_frame,
            app_arrival_elapsed_ns,
        })
    }

    pub(crate) fn interrupt_stroke(
        &mut self,
        target: StrokeRef,
        reason: StrokeInterruptionReason,
        app_arrival_elapsed_ns: u128,
    ) -> Result<u64, JournalError> {
        self.interrupt_stroke_record(target, reason, app_arrival_elapsed_ns)
            .map(|record| record.sequence)
    }

    pub(crate) fn interrupt_stroke_record(
        &mut self,
        target: StrokeRef,
        reason: StrokeInterruptionReason,
        app_arrival_elapsed_ns: u128,
    ) -> Result<JournalRecord, JournalError> {
        self.append_event_record(JournalEvent::StrokeInterrupted {
            target,
            reason,
            app_arrival_elapsed_ns,
        })
    }

    pub(crate) fn commit_stroke(
        &mut self,
        target: StrokeRef,
        app_arrival_elapsed_ns: u128,
    ) -> Result<u64, JournalError> {
        self.commit_stroke_record(target, app_arrival_elapsed_ns)
            .map(|record| record.sequence)
    }

    pub(crate) fn commit_stroke_record(
        &mut self,
        target: StrokeRef,
        app_arrival_elapsed_ns: u128,
    ) -> Result<JournalRecord, JournalError> {
        self.apply_edit_action_record(
            app_arrival_elapsed_ns,
            EditCommand::StrokeVisibility {
                targets: vec![target],
                visible: true,
            },
        )
    }

    pub(crate) fn interrupt_active_strokes(
        &mut self,
        reason: StrokeInterruptionReason,
        app_arrival_elapsed_ns: u128,
    ) -> Result<usize, JournalError> {
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(self.state.active_strokes.len())
            .map_err(JournalError::allocation)?;
        targets.extend(self.state.active_strokes.keys().cloned());
        let count = targets.len();
        for target in targets {
            self.interrupt_stroke(target, reason, app_arrival_elapsed_ns)?;
        }
        Ok(count)
    }

    pub(crate) fn append_metadata(
        &mut self,
        metadata: JournalMetadata,
    ) -> Result<u64, JournalError> {
        self.append_event(JournalEvent::Metadata(metadata))
    }

    pub(crate) fn append_recognition_projection(
        &mut self,
        projection: RecognitionProjectionV1,
        app_arrival_elapsed_ns: u128,
    ) -> Result<u64, JournalError> {
        self.append_recognition_projection_record(projection, app_arrival_elapsed_ns)
            .map(|record| record.sequence)
    }

    pub(crate) fn append_recognition_projection_record(
        &mut self,
        projection: RecognitionProjectionV1,
        app_arrival_elapsed_ns: u128,
    ) -> Result<JournalRecord, JournalError> {
        self.append_event_record(JournalEvent::RecognitionProjection {
            app_arrival_elapsed_ns,
            projection: Box::new(projection),
        })
    }

    pub(crate) fn append_region_correction(
        &mut self,
        correction: RegionCorrectionV1,
        app_arrival_elapsed_ns: u128,
    ) -> Result<u64, JournalError> {
        self.append_region_correction_record(correction, app_arrival_elapsed_ns)
            .map(|record| record.sequence)
    }

    pub(crate) fn append_region_correction_record(
        &mut self,
        correction: RegionCorrectionV1,
        app_arrival_elapsed_ns: u128,
    ) -> Result<JournalRecord, JournalError> {
        self.append_event_record(JournalEvent::RegionCorrection {
            app_arrival_elapsed_ns,
            correction: Box::new(correction),
        })
    }

    pub(crate) fn apply_edit_action(
        &mut self,
        app_arrival_elapsed_ns: u128,
        command: EditCommand,
    ) -> Result<u64, JournalError> {
        self.apply_edit_action_record(app_arrival_elapsed_ns, command)
            .map(|record| match record.event {
                JournalEvent::EditAction { action_id, .. } => action_id,
                _ => unreachable!("edit action append returns an edit action row"),
            })
    }

    pub(crate) fn apply_edit_action_record(
        &mut self,
        app_arrival_elapsed_ns: u128,
        command: EditCommand,
    ) -> Result<JournalRecord, JournalError> {
        let action_id = self
            .state
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| JournalError::limit("journal sequence counter overflow"))?;
        let revision_id = self
            .state
            .logical_revision
            .checked_add(1)
            .ok_or_else(|| JournalError::limit("logical revision counter overflow"))?;
        self.append_event_record(JournalEvent::EditAction {
            action_id,
            revision_id,
            app_arrival_elapsed_ns,
            command,
        })
    }

    pub(crate) fn undo_last_edit(
        &mut self,
        app_arrival_elapsed_ns: u128,
    ) -> Result<u64, JournalError> {
        self.undo_last_edit_record(app_arrival_elapsed_ns)
            .map(|record| match record.event {
                JournalEvent::Undo { action_id, .. } => action_id,
                _ => unreachable!("undo append returns an undo row"),
            })
    }

    pub(crate) fn undo_last_edit_record(
        &mut self,
        app_arrival_elapsed_ns: u128,
    ) -> Result<JournalRecord, JournalError> {
        let action_id = *self
            .state
            .undo_stack
            .last()
            .ok_or_else(|| JournalError::invalid("there is no active edit to undo"))?;
        let revision_id = self
            .state
            .logical_revision
            .checked_add(1)
            .ok_or_else(|| JournalError::limit("logical revision counter overflow"))?;
        self.append_event_record(JournalEvent::Undo {
            action_id,
            revision_id,
            app_arrival_elapsed_ns,
        })
    }

    pub(crate) fn redo_last_edit(
        &mut self,
        app_arrival_elapsed_ns: u128,
    ) -> Result<u64, JournalError> {
        self.redo_last_edit_record(app_arrival_elapsed_ns)
            .map(|record| match record.event {
                JournalEvent::Redo { action_id, .. } => action_id,
                _ => unreachable!("redo append returns a redo row"),
            })
    }

    pub(crate) fn redo_last_edit_record(
        &mut self,
        app_arrival_elapsed_ns: u128,
    ) -> Result<JournalRecord, JournalError> {
        let action_id = *self
            .state
            .redo_stack
            .last()
            .ok_or_else(|| JournalError::invalid("there is no undone edit to redo"))?;
        let revision_id = self
            .state
            .logical_revision
            .checked_add(1)
            .ok_or_else(|| JournalError::limit("logical revision counter overflow"))?;
        self.append_event_record(JournalEvent::Redo {
            action_id,
            revision_id,
            app_arrival_elapsed_ns,
        })
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
        self.append_event_record(event)
            .map(|record| record.sequence)
    }

    pub(crate) fn append_event_record(
        &mut self,
        event: JournalEvent,
    ) -> Result<JournalRecord, JournalError> {
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
        let app_epoch_id = match &event {
            JournalEvent::SessionEpochStarted { epoch, .. } => epoch.session_id.clone(),
            _ => self.state.current_session_id.clone(),
        };
        let record = JournalRecord {
            sequence,
            app_epoch_id,
            event,
        };
        validate_record_before_encoding(&self.header, &record)?;
        let line = encode_row(&encode_record_fields(&record, JOURNAL_SCHEMA_VERSION)?)?;
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

        self.state.apply_prepared(record.clone());
        self.bytes_written = self.bytes_written.saturating_add(line.len() as u64);
        self.prefix_fingerprint = fnv_update(self.prefix_fingerprint, &line);
        Ok(record)
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

/// Migrates a readable older journal into schema 4 while preserving its
/// logical project identity and every validated physical field. The source
/// file remains untouched; the migration row records the source prefix.
pub(crate) fn migrate_schema_one_to_four(
    source_path: &Path,
    destination_path: PathBuf,
) -> Result<JournalMigrationResult, JournalError> {
    let source = read_journal(source_path)?;
    if source.schema_version != LEGACY_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::invalid(
            "only schema 1 journals can be migrated by this function",
        ));
    }
    migrate_parsed_journal_to_four(source, destination_path)
}

pub(crate) fn migrate_schema_two_to_four(
    source_path: &Path,
    destination_path: PathBuf,
) -> Result<JournalMigrationResult, JournalError> {
    let source = read_journal(source_path)?;
    if source.schema_version != PREVIOUS_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::invalid(
            "only schema 2 journals can be migrated by this function",
        ));
    }
    migrate_parsed_journal_to_four(source, destination_path)
}

pub(crate) fn migrate_schema_three_to_four(
    source_path: &Path,
    destination_path: PathBuf,
) -> Result<JournalMigrationResult, JournalError> {
    let source = read_journal(source_path)?;
    if source.schema_version != THIRD_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::invalid(
            "only schema 3 journals can be migrated by this function",
        ));
    }
    migrate_parsed_journal_to_four(source, destination_path)
}

fn migrate_parsed_journal_to_four(
    source: JournalReadResult,
    destination_path: PathBuf,
) -> Result<JournalMigrationResult, JournalError> {
    let source_journal_id = source.header.journal_id.clone();
    let source_schema_version = source.schema_version;
    let source_prefix_fingerprint = source
        .checkpoints
        .last()
        .map(|checkpoint| checkpoint.fingerprint)
        .ok_or_else(|| JournalError::invalid("legacy journal has no validated prefix"))?;
    let mut writer = JournalWriter::create(destination_path.clone(), source.header.clone())?;
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
    writer.append_event(JournalEvent::MigrationProvenance {
        source_schema_version,
        source_journal_id: source_journal_id.clone(),
        source_prefix_fingerprint,
        source_record_count: migrated_records,
        // Migration is an offline file operation with no capture-session
        // monotonic timestamp. Preserve that absence rather than inventing 0.
        app_arrival_elapsed_ns: None,
    })?;
    writer.flush()?;
    Ok(JournalMigrationResult {
        destination_path,
        source_journal_id: source_journal_id.clone(),
        destination_journal_id: source_journal_id,
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
            state = JournalReplayState::for_header(&parsed_header)?;
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
        let record = parse_record_fields(
            schema_version,
            &fields,
            header.as_ref().expect("header was parsed"),
        )?;
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

    let mut prefix_state = JournalReplayState::for_header(&journal.header)?;
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
            let snapshot_schema_version = parse_u32(fields[1], "snapshot schema version")?;
            if fields[0] != "LASSOINK-SNAPSHOT"
                || !matches!(
                    snapshot_schema_version,
                    THIRD_JOURNAL_SCHEMA_VERSION | JOURNAL_SCHEMA_VERSION
                )
            {
                return Err(JournalError::invalid("unsupported snapshot header"));
            }
            let prefix_fingerprint = parse_hex_u64(fields[6], "snapshot prefix fingerprint")?;
            let state_fingerprint_expected =
                parse_hex_u64(fields[7], "snapshot state fingerprint")?;
            let journal_id = decode_field(fields[2])?;
            parsed = Some(ParsedSnapshot {
                schema_version: snapshot_schema_version,
                journal_id: journal_id.clone(),
                prefix_bytes: parse_u64(fields[3], "snapshot prefix byte length")?,
                prefix_sequence: parse_u64(fields[4], "snapshot prefix sequence")?,
                logical_revision: parse_u64(fields[5], "snapshot logical revision")?,
                prefix_fingerprint,
                state: JournalReplayState {
                    journal_id,
                    ..JournalReplayState::default()
                },
            });
            expected_state_fingerprint = Some(state_fingerprint_expected);
            saw_header = true;
            continue;
        }

        let snapshot = parsed.as_mut().expect("snapshot header has been parsed");
        match fields.first().copied().unwrap_or_default() {
            "EPO" => {
                require_fields(&fields, 7, "EPO")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot epoch sequence")?;
                let epoch = SessionEpoch {
                    session_id: decode_field(fields[2])?,
                    started_at_unix_ns: parse_option_u128(
                        fields[3],
                        "snapshot epoch wall-clock start",
                    )?,
                    config_id: decode_option_text(fields[4])?,
                    provenance: decode_field(fields[5])?,
                    requires_stroke_commit: parse_bool(
                        fields[6],
                        "snapshot epoch stroke-commit policy",
                    )?,
                };
                epoch.validate()?;
                if sequence > snapshot.prefix_sequence
                    || snapshot.state.session_ids.contains(&epoch.session_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot session epoch is duplicated or past its prefix",
                    ));
                }
                if snapshot.state.session_epochs.is_empty() && sequence != 0 {
                    return Err(JournalError::invalid(
                        "snapshot is missing the header's initial session epoch",
                    ));
                }
                snapshot
                    .state
                    .session_epochs
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .session_ids
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot.state.session_ids.insert(epoch.session_id.clone());
                snapshot.state.current_session_id = epoch.session_id.clone();
                snapshot
                    .state
                    .session_epochs
                    .push(StoredSessionEpoch { sequence, epoch });
            }
            "SBG" => {
                require_fields(&fields, 4 + STROKE_VIEW_FRAME_WIDTH + 6, "SBG")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot stroke start sequence")?;
                let app_epoch_id = decode_field(fields[2])?;
                let app_arrival_elapsed_ns =
                    parse_u128(fields[3], "snapshot stroke start app arrival")?;
                let view_frame = parse_stroke_view_frame_fields(&fields, 4)?;
                if sequence > snapshot.prefix_sequence
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot stroke start is past its prefix or has unknown epoch",
                    ));
                }
                let target = parse_stroke_ref_fields(
                    &fields,
                    4 + STROKE_VIEW_FRAME_WIDTH,
                    JOURNAL_SCHEMA_VERSION,
                    &snapshot.journal_id,
                    &snapshot.state.current_session_id,
                )?;
                if target.session_id != app_epoch_id
                    || !snapshot.state.stroke_start_set.insert(target.clone())
                {
                    return Err(JournalError::invalid(
                        "snapshot stroke start identity is inconsistent or repeated",
                    ));
                }
                snapshot.state.stroke_starts.push(StoredStrokeStart {
                    sequence,
                    app_epoch_id,
                    app_arrival_elapsed_ns,
                    target,
                    view_frame,
                });
            }
            "SIT" => {
                require_fields(&fields, 11, "SIT")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot stroke interruption sequence")?;
                let app_epoch_id = decode_field(fields[2])?;
                let app_arrival_elapsed_ns =
                    parse_u128(fields[3], "snapshot stroke interruption app arrival")?;
                let reason = parse_stroke_interruption_reason(fields[4])?;
                if sequence > snapshot.prefix_sequence
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot stroke interruption is past its prefix or has unknown epoch",
                    ));
                }
                let target = parse_stroke_ref_fields(
                    &fields,
                    5,
                    JOURNAL_SCHEMA_VERSION,
                    &snapshot.journal_id,
                    &snapshot.state.current_session_id,
                )?;
                if !snapshot.state.stroke_start_set.contains(&target) {
                    return Err(JournalError::invalid(
                        "snapshot interruption references an unknown stroke start",
                    ));
                }
                snapshot
                    .state
                    .stroke_interruptions
                    .push(StoredStrokeInterruption {
                        sequence,
                        app_epoch_id,
                        app_arrival_elapsed_ns,
                        target,
                        reason,
                    });
            }
            "SAC" => {
                require_fields(&fields, 7, "SAC")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let target = parse_stroke_ref_fields(
                    &fields,
                    1,
                    JOURNAL_SCHEMA_VERSION,
                    &snapshot.journal_id,
                    &snapshot.state.current_session_id,
                )?;
                let start = snapshot
                    .state
                    .stroke_starts
                    .iter()
                    .find(|start| start.target == target)
                    .cloned()
                    .ok_or_else(|| JournalError::invalid("active snapshot stroke has no start"))?;
                if snapshot
                    .state
                    .stroke_interruptions
                    .iter()
                    .any(|interruption| interruption.target == target)
                    || snapshot
                        .state
                        .active_strokes
                        .insert(target, start)
                        .is_some()
                {
                    return Err(JournalError::invalid(
                        "snapshot active stroke is interrupted or duplicated",
                    ));
                }
            }
            "SP" => {
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sample = parse_sample_fields(&fields, PREVIOUS_JOURNAL_SCHEMA_VERSION)?;
                let sequence = parse_u64(fields[1], "snapshot sample sequence")?;
                if sequence > snapshot.prefix_sequence
                    || !snapshot.state.session_ids.contains(&sample.session_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot sample is past its prefix or references an unknown session",
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
                require_fields(&fields, 11, "SMD")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot metadata sequence")?;
                if sequence > snapshot.prefix_sequence {
                    return Err(JournalError::invalid(
                        "snapshot metadata is past its declared prefix",
                    ));
                }
                let app_epoch_id = decode_field(fields[2])?;
                if !snapshot.state.session_ids.contains(&app_epoch_id) {
                    return Err(JournalError::invalid(
                        "snapshot metadata references an unknown app-arrival epoch",
                    ));
                }
                let mut metadata_fields = Vec::new();
                metadata_fields
                    .try_reserve_exact(fields.len() - 1)
                    .map_err(JournalError::allocation)?;
                metadata_fields.extend_from_slice(&fields[..2]);
                metadata_fields.extend_from_slice(&fields[3..]);
                let metadata = parse_metadata_fields(&metadata_fields)?;
                if metadata.scope == MetadataScope::Session
                    && !snapshot.state.session_ids.contains(&metadata.scope_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot session metadata references an unknown epoch",
                    ));
                }
                snapshot
                    .state
                    .metadata_history
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot.state.metadata_history.push(StoredMetadata {
                    sequence,
                    app_epoch_id,
                    metadata,
                });
            }
            "ST" => {
                require_fields(&fields, 11, "ST")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot tombstone sequence")?;
                let logical_revision = parse_u64(fields[2], "snapshot tombstone revision")?;
                let app_epoch_id = decode_field(fields[3])?;
                let app_arrival_elapsed_ns =
                    parse_u128(fields[4], "snapshot tombstone app arrival")?;
                if sequence > snapshot.prefix_sequence
                    || logical_revision > snapshot.logical_revision
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot tombstone is past its prefix/revision or has unknown epoch",
                    ));
                }
                let target = parse_stroke_ref_fields(
                    &fields,
                    5,
                    JOURNAL_SCHEMA_VERSION,
                    &snapshot.journal_id,
                    &snapshot.state.current_session_id,
                )?;
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
                snapshot.state.tombstones.push(target.clone());
                snapshot.state.tombstone_history.push(StoredTombstone {
                    sequence,
                    logical_revision,
                    app_epoch_id,
                    app_arrival_elapsed_ns,
                    target,
                });
            }
            "SM" => {
                require_fields(&fields, 15, "SM")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot move sequence")?;
                let logical_revision = parse_u64(fields[2], "snapshot move revision")?;
                let app_epoch_id = decode_field(fields[3])?;
                let app_arrival_elapsed_ns = parse_u128(fields[4], "snapshot move app arrival")?;
                if sequence > snapshot.prefix_sequence
                    || logical_revision > snapshot.logical_revision
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
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
                let target = parse_stroke_ref_fields(
                    &fields,
                    5,
                    JOURNAL_SCHEMA_VERSION,
                    &snapshot.journal_id,
                    &snapshot.state.current_session_id,
                )?;
                let delta_x_raw = parse_i64(fields[11], "snapshot move delta x")?;
                let delta_y_raw = parse_i64(fields[12], "snapshot move delta y")?;
                let coordinate_space = decode_field(fields[13])?;
                let units = decode_field(fields[14])?;
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
                    app_epoch_id,
                    app_arrival_elapsed_ns,
                    target,
                    delta_x_raw,
                    delta_y_raw,
                    coordinate_space,
                    units,
                });
            }
            "SC" => {
                require_fields(&fields, 12, "SC")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot correction sequence")?;
                let logical_revision = parse_u64(fields[2], "snapshot correction revision")?;
                let app_epoch_id = decode_field(fields[3])?;
                let app_arrival_elapsed_ns =
                    parse_u128(fields[4], "snapshot correction app arrival")?;
                if sequence > snapshot.prefix_sequence
                    || logical_revision > snapshot.logical_revision
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
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
                    app_epoch_id,
                    app_arrival_elapsed_ns,
                    target: parse_stroke_ref_fields(
                        &fields,
                        5,
                        JOURNAL_SCHEMA_VERSION,
                        &snapshot.journal_id,
                        &snapshot.state.current_session_id,
                    )?,
                    corrected_text: decode_field(fields[11])?,
                });
            }
            "EA" => {
                require_at_least_fields(&fields, 8, "EA")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot edit action sequence")?;
                let app_epoch_id = decode_field(fields[2])?;
                let revision_id = parse_u64(fields[3], "snapshot edit action revision")?;
                if sequence > snapshot.prefix_sequence
                    || revision_id > snapshot.logical_revision
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot edit action is past its prefix/revision or has unknown epoch",
                    ));
                }
                let active = parse_bool(fields[6], "snapshot action active state")?;
                let mut action_fields = Vec::new();
                action_fields
                    .try_reserve(fields.len() - 1)
                    .map_err(JournalError::allocation)?;
                action_fields.push("ACT");
                action_fields.extend_from_slice(&fields[1..6]);
                action_fields.extend_from_slice(&fields[7..]);
                let action_header = JournalHeader {
                    journal_id: snapshot.journal_id.clone(),
                    session_id: snapshot.state.current_session_id.clone(),
                    config_id: None,
                    device_model_declared: None,
                    tilt_supported_declared: None,
                };
                let parsed_action =
                    parse_record_fields(JOURNAL_SCHEMA_VERSION, &action_fields, &action_header)?;
                let JournalEvent::EditAction {
                    action_id,
                    revision_id: parsed_revision,
                    app_arrival_elapsed_ns,
                    command,
                } = parsed_action.event
                else {
                    return Err(JournalError::invalid(
                        "snapshot edit action row did not parse as an action",
                    ));
                };
                if action_id != sequence || parsed_revision != revision_id {
                    return Err(JournalError::invalid(
                        "snapshot action identity differs from its event sequence/revision",
                    ));
                }
                validate_edit_command_fields(&command)?;
                validate_snapshot_edit_targets(&snapshot.state, &command)?;
                snapshot
                    .state
                    .edit_actions
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot.state.edit_actions.push(StoredEditAction {
                    sequence,
                    action_id,
                    revision_id,
                    app_epoch_id,
                    app_arrival_elapsed_ns,
                    command,
                    active,
                });
            }
            "EC" => {
                require_fields(&fields, 7, "EC")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot edit control sequence")?;
                let app_epoch_id = decode_field(fields[2])?;
                let revision_id = parse_u64(fields[3], "snapshot edit control revision")?;
                if sequence > snapshot.prefix_sequence
                    || revision_id > snapshot.logical_revision
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot edit control is past its prefix/revision or has unknown epoch",
                    ));
                }
                snapshot
                    .state
                    .edit_controls
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot.state.edit_controls.push(StoredEditControl {
                    sequence,
                    app_epoch_id,
                    revision_id,
                    app_arrival_elapsed_ns: parse_u128(
                        fields[4],
                        "snapshot edit control app arrival",
                    )?,
                    action_id: parse_u64(fields[5], "snapshot edit control action ID")?,
                    redo: parse_bool(fields[6], "snapshot edit control redo")?,
                });
            }
            "US" | "RS" => {
                require_fields(&fields, 2, "undo/redo stack")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let action_id = parse_u64(fields[1], "snapshot stack action ID")?;
                let stack = if fields[0] == "US" {
                    &mut snapshot.state.undo_stack
                } else {
                    &mut snapshot.state.redo_stack
                };
                stack.try_reserve(1).map_err(JournalError::allocation)?;
                stack.push(action_id);
            }
            "MPR" => {
                require_fields(&fields, 8, "MPR")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot migration sequence")?;
                let app_epoch_id = decode_field(fields[2])?;
                if sequence > snapshot.prefix_sequence
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot migration provenance is past its prefix or has unknown epoch",
                    ));
                }
                snapshot
                    .state
                    .migration_provenance
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .migration_provenance
                    .push(StoredMigrationProvenance {
                        sequence,
                        app_epoch_id,
                        app_arrival_elapsed_ns: parse_option_u128(
                            fields[3],
                            "snapshot migration app arrival",
                        )?,
                        source_schema_version: parse_u32(fields[4], "snapshot migration schema")?,
                        source_journal_id: decode_field(fields[5])?,
                        source_prefix_fingerprint: parse_hex_u64(
                            fields[6],
                            "snapshot migration source prefix",
                        )?,
                        source_record_count: parse_u64(fields[7], "snapshot source record count")?,
                    });
            }
            "SPJ" if snapshot.schema_version >= JOURNAL_SCHEMA_VERSION => {
                require_fields(&fields, 5, "SPJ")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot projection sequence")?;
                let app_epoch_id = decode_field(fields[2])?;
                let app_arrival_elapsed_ns =
                    parse_u128(fields[3], "snapshot projection app arrival")?;
                if sequence == 0
                    || sequence > snapshot.prefix_sequence
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot projection is past its prefix or has unknown epoch",
                    ));
                }
                let projection: RecognitionProjectionV1 =
                    decode_json_payload(fields[4], "snapshot recognition projection")?;
                validate_recognition_projection_fields(&projection)?;
                if snapshot.state.recognition_projections.len() >= MAX_RECOGNITION_PROJECTIONS {
                    return Err(JournalError::limit(
                        "snapshot recognition projection count exceeds its cap",
                    ));
                }
                if snapshot
                    .state
                    .recognition_projection_ids
                    .contains(&projection.projection_id)
                    || snapshot.state.derived_event_sequences.contains(&sequence)
                {
                    return Err(JournalError::invalid(
                        "snapshot recognition projection is duplicated",
                    ));
                }
                snapshot
                    .state
                    .recognition_projections
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .recognition_projection_ids
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .derived_event_sequences
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .recognition_projection_ids
                    .insert(projection.projection_id.clone());
                snapshot.state.derived_event_sequences.insert(sequence);
                snapshot
                    .state
                    .recognition_projections
                    .push(StoredRecognitionProjection {
                        sequence,
                        app_epoch_id,
                        app_arrival_elapsed_ns,
                        projection,
                    });
            }
            "SRC" if snapshot.schema_version >= JOURNAL_SCHEMA_VERSION => {
                require_fields(&fields, 5, "SRC")?;
                if total_state_entries >= MAX_SNAPSHOT_STATE_ENTRIES {
                    return Err(JournalError::limit("snapshot state entry cap reached"));
                }
                let sequence = parse_u64(fields[1], "snapshot region correction sequence")?;
                let app_epoch_id = decode_field(fields[2])?;
                let app_arrival_elapsed_ns =
                    parse_u128(fields[3], "snapshot region correction app arrival")?;
                if sequence == 0
                    || sequence > snapshot.prefix_sequence
                    || !snapshot.state.session_ids.contains(&app_epoch_id)
                {
                    return Err(JournalError::invalid(
                        "snapshot region correction is past its prefix or has unknown epoch",
                    ));
                }
                let correction: RegionCorrectionV1 =
                    decode_json_payload(fields[4], "snapshot region correction")?;
                validate_region_correction_fields(&correction)?;
                if snapshot.state.region_corrections.len() >= MAX_REGION_CORRECTIONS {
                    return Err(JournalError::limit(
                        "snapshot region correction count exceeds its cap",
                    ));
                }
                if snapshot
                    .state
                    .region_correction_ids
                    .contains(&correction.correction_id)
                    || snapshot.state.derived_event_sequences.contains(&sequence)
                {
                    return Err(JournalError::invalid(
                        "snapshot region correction is duplicated",
                    ));
                }
                snapshot
                    .state
                    .region_corrections
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .region_correction_ids
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .derived_event_sequences
                    .try_reserve(1)
                    .map_err(JournalError::allocation)?;
                snapshot
                    .state
                    .region_correction_ids
                    .insert(correction.correction_id.clone());
                snapshot.state.derived_event_sequences.insert(sequence);
                snapshot
                    .state
                    .region_corrections
                    .push(StoredRegionCorrection {
                        sequence,
                        app_epoch_id,
                        app_arrival_elapsed_ns,
                        correction,
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
    if snapshot
        .state
        .session_epochs
        .first()
        .is_none_or(|first| first.sequence != 0 || first.epoch.session_id.is_empty())
    {
        return Err(JournalError::invalid(
            "snapshot is missing its initial session epoch",
        ));
    }
    if !snapshot
        .state
        .session_ids
        .contains(&snapshot.state.current_session_id)
    {
        return Err(JournalError::invalid(
            "snapshot current session epoch is not declared",
        ));
    }
    snapshot.state.last_sequence = snapshot.prefix_sequence;
    snapshot.state.logical_revision = snapshot.logical_revision;
    // Historical projections/corrections may be stale relative to later ink
    // edits in this snapshot prefix. Their validity is checked at their
    // original journal event during replay, and load_with_snapshot requires
    // exact equality with that replayed prefix before using this state.
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
    for stored in &materialized.state.session_epochs {
        let fields = vec![
            "EPO".to_owned(),
            stored.sequence.to_string(),
            encode_field(&stored.epoch.session_id),
            opt_u128(stored.epoch.started_at_unix_ns),
            encode_option_text(stored.epoch.config_id.as_deref()),
            encode_field(&stored.epoch.provenance),
            stored.epoch.requires_stroke_commit.to_string(),
        ];
        append_encoded_row(&mut body, &fields)?;
    }
    for start in &materialized.state.stroke_starts {
        let mut fields = vec![
            "SBG".to_owned(),
            start.sequence.to_string(),
            encode_field(&start.app_epoch_id),
            start.app_arrival_elapsed_ns.to_string(),
        ];
        fields.extend(encode_stroke_view_frame_fields(start.view_frame));
        fields.extend(encode_stroke_ref_fields(
            &start.target,
            JOURNAL_SCHEMA_VERSION,
        ));
        append_encoded_row(&mut body, &fields)?;
    }
    for interruption in &materialized.state.stroke_interruptions {
        let mut fields = vec![
            "SIT".to_owned(),
            interruption.sequence.to_string(),
            encode_field(&interruption.app_epoch_id),
            interruption.app_arrival_elapsed_ns.to_string(),
            encode_stroke_interruption_reason(interruption.reason).to_owned(),
        ];
        fields.extend(encode_stroke_ref_fields(
            &interruption.target,
            JOURNAL_SCHEMA_VERSION,
        ));
        append_encoded_row(&mut body, &fields)?;
    }
    let mut active_targets = materialized
        .state
        .active_strokes
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    active_targets.sort();
    for target in active_targets {
        let mut fields = vec!["SAC".to_owned()];
        fields.extend(encode_stroke_ref_fields(&target, JOURNAL_SCHEMA_VERSION));
        append_encoded_row(&mut body, &fields)?;
    }
    for stored in &materialized.state.physical_samples {
        let fields = encode_sample_fields(
            "SP",
            stored.sequence,
            &stored.sample,
            PREVIOUS_JOURNAL_SCHEMA_VERSION,
        )?;
        append_encoded_row(&mut body, &fields)?;
    }
    for stored in &materialized.state.metadata_history {
        let mut fields = encode_metadata_fields("SMD", stored.sequence, &stored.metadata);
        fields.insert(2, encode_field(&stored.app_epoch_id));
        append_encoded_row(&mut body, &fields)?;
    }
    for tombstone in &materialized.state.tombstone_history {
        let mut fields = vec![
            "ST".to_owned(),
            tombstone.sequence.to_string(),
            tombstone.logical_revision.to_string(),
            encode_field(&tombstone.app_epoch_id),
            tombstone.app_arrival_elapsed_ns.to_string(),
        ];
        fields.extend(encode_stroke_ref_fields(
            &tombstone.target,
            JOURNAL_SCHEMA_VERSION,
        ));
        append_encoded_row(&mut body, &fields)?;
    }
    for movement in &materialized.state.moves {
        let mut fields = vec![
            "SM".to_owned(),
            movement.sequence.to_string(),
            movement.logical_revision.to_string(),
            encode_field(&movement.app_epoch_id),
            movement.app_arrival_elapsed_ns.to_string(),
        ];
        fields.extend(encode_stroke_ref_fields(
            &movement.target,
            JOURNAL_SCHEMA_VERSION,
        ));
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
            encode_field(&correction.app_epoch_id),
            correction.app_arrival_elapsed_ns.to_string(),
        ];
        fields.extend(encode_stroke_ref_fields(
            &correction.target,
            JOURNAL_SCHEMA_VERSION,
        ));
        fields.push(encode_field(&correction.corrected_text));
        append_encoded_row(&mut body, &fields)?;
    }
    for action in &materialized.state.edit_actions {
        let mut fields = encode_edit_action_fields(
            action.sequence,
            action.revision_id,
            action.app_arrival_elapsed_ns,
            action.action_id,
            &action.command,
            JOURNAL_SCHEMA_VERSION,
        )?;
        fields[0] = "EA".to_owned();
        fields.insert(2, encode_field(&action.app_epoch_id));
        fields.insert(6, action.active.to_string());
        append_encoded_row(&mut body, &fields)?;
    }
    for control in &materialized.state.edit_controls {
        append_encoded_row(
            &mut body,
            &[
                "EC".to_owned(),
                control.sequence.to_string(),
                encode_field(&control.app_epoch_id),
                control.revision_id.to_string(),
                control.app_arrival_elapsed_ns.to_string(),
                control.action_id.to_string(),
                control.redo.to_string(),
            ],
        )?;
    }
    for action_id in &materialized.state.undo_stack {
        append_encoded_row(&mut body, &["US".to_owned(), action_id.to_string()])?;
    }
    for action_id in &materialized.state.redo_stack {
        append_encoded_row(&mut body, &["RS".to_owned(), action_id.to_string()])?;
    }
    for migration in &materialized.state.migration_provenance {
        append_encoded_row(
            &mut body,
            &[
                "MPR".to_owned(),
                migration.sequence.to_string(),
                encode_field(&migration.app_epoch_id),
                opt_u128(migration.app_arrival_elapsed_ns),
                migration.source_schema_version.to_string(),
                encode_field(&migration.source_journal_id),
                format!("{:016X}", migration.source_prefix_fingerprint),
                migration.source_record_count.to_string(),
            ],
        )?;
    }
    for stored in &materialized.state.recognition_projections {
        append_encoded_row(
            &mut body,
            &[
                "SPJ".to_owned(),
                stored.sequence.to_string(),
                encode_field(&stored.app_epoch_id),
                stored.app_arrival_elapsed_ns.to_string(),
                encode_json_payload(&stored.projection, "snapshot recognition projection")?,
            ],
        )?;
    }
    for stored in &materialized.state.region_corrections {
        append_encoded_row(
            &mut body,
            &[
                "SRC".to_owned(),
                stored.sequence.to_string(),
                encode_field(&stored.app_epoch_id),
                stored.app_arrival_elapsed_ns.to_string(),
                encode_json_payload(&stored.correction, "snapshot region correction")?,
            ],
        )?;
    }
    append_encoded_row(&mut body, &["ENDSNAP".to_owned()])?;
    let state_fingerprint = fnv_update(FNV_OFFSET_BASIS, &body);
    let header = vec![
        "LASSOINK-SNAPSHOT".to_owned(),
        JOURNAL_SCHEMA_VERSION.to_string(),
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
    require_at_least_fields(fields, 2, "LASSOINK-JOURNAL")?;
    let version = parse_u32(fields[1], "journal schema version")?;
    if !matches!(
        version,
        LEGACY_JOURNAL_SCHEMA_VERSION
            | PREVIOUS_JOURNAL_SCHEMA_VERSION
            | THIRD_JOURNAL_SCHEMA_VERSION
            | JOURNAL_SCHEMA_VERSION
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
    _header: &JournalHeader,
    record: &JournalRecord,
) -> Result<(), JournalError> {
    match &record.event {
        JournalEvent::PhysicalSample(sample) => {
            sample.validate()?;
            if sample.session_id != record.app_epoch_id {
                return Err(JournalError::invalid(
                    "physical sample session ID differs from its app-arrival epoch",
                ));
            }
            Ok(())
        }
        JournalEvent::Metadata(metadata) => metadata.validate(),
        JournalEvent::SessionEpochStarted { epoch, .. } => epoch.validate(),
        JournalEvent::StrokeStarted { target, .. }
        | JournalEvent::StrokeInterrupted { target, .. } => validate_stroke_ref(target),
        JournalEvent::EditAction { command, .. } => validate_edit_command_fields(command),
        JournalEvent::Undo { .. } | JournalEvent::Redo { .. } => Ok(()),
        JournalEvent::MigrationProvenance {
            source_journal_id, ..
        } => validate_text(source_journal_id, "migration source journal ID", 128),
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
        JournalEvent::RecognitionProjection { projection, .. } => {
            validate_recognition_projection_fields(projection)?;
            if projection.provider.provider_id == LOCAL_SENOCR_RASTER_PROVIDER_ID
                && projection.input_modalities.is_none()
            {
                return Err(JournalError::invalid(
                    "new local SenOCR projections require explicit Raster modality and generated origin",
                ));
            }
            Ok(())
        }
        JournalEvent::RegionCorrection { correction, .. } => {
            validate_region_correction_fields(correction)
        }
    }
}

fn validate_edit_command_fields(command: &EditCommand) -> Result<(), JournalError> {
    match command {
        EditCommand::Tombstone { targets }
        | EditCommand::Restore { targets }
        | EditCommand::StrokeVisibility { targets, .. } => validate_edit_target_list(targets),
        EditCommand::Move {
            target,
            coordinate_space,
            units,
            ..
        } => {
            validate_stroke_ref(target)?;
            validate_text(
                coordinate_space,
                "edit move coordinate space",
                MAX_JOURNAL_TEXT_BYTES,
            )?;
            validate_text(units, "edit move units", MAX_JOURNAL_TEXT_BYTES)?;
            if coordinate_space.is_empty() || units.is_empty() {
                return Err(JournalError::invalid(
                    "edit move coordinate space and units must be nonempty",
                ));
            }
            Ok(())
        }
        EditCommand::Correction {
            target,
            corrected_text,
        } => {
            validate_stroke_ref(target)?;
            validate_optional_text(corrected_text.as_deref(), "edit correction")
        }
    }
}

fn validate_snapshot_edit_targets(
    state: &JournalReplayState,
    command: &EditCommand,
) -> Result<(), JournalError> {
    match command {
        EditCommand::Tombstone { targets } | EditCommand::Restore { targets } => {
            for target in targets {
                if matches!(command, EditCommand::Restore { .. }) {
                    state.validate_restore_target(target)?;
                } else {
                    state.validate_edit_target(target)?;
                }
            }
            Ok(())
        }
        EditCommand::StrokeVisibility { targets, visible } => {
            for target in targets {
                state.validate_edit_target(target)?;
                if *visible
                    && (!state.stroke_start_set.contains(target)
                        || !state.stroke_domains.contains_key(target))
                {
                    return Err(JournalError::invalid(
                        "snapshot stroke visibility commit has no started stroke with samples",
                    ));
                }
            }
            Ok(())
        }
        EditCommand::Move {
            target,
            coordinate_space,
            units,
            ..
        } => {
            state.validate_edit_target(target)?;
            state.validate_move_domain(target, coordinate_space, units)
        }
        EditCommand::Correction { target, .. } => state.validate_edit_target(target),
    }
}

fn validate_edit_target_list(targets: &[StrokeRef]) -> Result<(), JournalError> {
    if targets.is_empty() || targets.len() > MAX_EDIT_TARGETS {
        return Err(JournalError::limit(format!(
            "logical action must target between 1 and {MAX_EDIT_TARGETS} strokes"
        )));
    }
    let mut unique = HashSet::new();
    unique
        .try_reserve(targets.len())
        .map_err(JournalError::allocation)?;
    for target in targets {
        validate_stroke_ref(target)?;
        if !unique.insert(target) {
            return Err(JournalError::invalid(
                "one logical action cannot repeat a stroke target",
            ));
        }
    }
    Ok(())
}

fn validate_edit_command(
    state: &JournalReplayState,
    command: &EditCommand,
) -> Result<(), JournalError> {
    match command {
        EditCommand::Tombstone { targets } | EditCommand::Restore { targets } => {
            validate_edit_target_list(targets)?;
            for target in targets {
                if matches!(command, EditCommand::Restore { .. }) {
                    state.validate_restore_target(target)?;
                } else {
                    state.validate_edit_target(target)?;
                }
            }
            Ok(())
        }
        EditCommand::StrokeVisibility { targets, visible } => {
            validate_edit_target_list(targets)?;
            for target in targets {
                state.validate_edit_target(target)?;
                if *visible
                    && (!state.active_strokes.contains_key(target)
                        || !state.stroke_domains.contains_key(target))
                {
                    return Err(JournalError::invalid(
                        "visible StrokeVisibility commit requires an active started stroke with samples",
                    ));
                }
            }
            Ok(())
        }
        EditCommand::Move {
            target,
            delta_x_raw,
            delta_y_raw,
            coordinate_space,
            units,
        } => {
            state.validate_edit_target(target)?;
            validate_text(
                coordinate_space,
                "edit move coordinate space",
                MAX_JOURNAL_TEXT_BYTES,
            )?;
            validate_text(units, "edit move units", MAX_JOURNAL_TEXT_BYTES)?;
            if coordinate_space.is_empty() || units.is_empty() {
                return Err(JournalError::invalid(
                    "edit move coordinate space and units must be nonempty",
                ));
            }
            state.validate_move_domain(target, coordinate_space, units)?;

            let existing = state.move_totals.get(target);
            let mut total_x = existing.map_or(0, |move_total| move_total.delta_x_raw);
            let mut total_y = existing.map_or(0, |move_total| move_total.delta_y_raw);
            for action in state.edit_actions.iter().filter(|action| action.active) {
                if let EditCommand::Move {
                    target: action_target,
                    delta_x_raw,
                    delta_y_raw,
                    coordinate_space: action_space,
                    units: action_units,
                } = &action.command
                    && action_target == target
                {
                    if action_space != coordinate_space || action_units != units {
                        return Err(JournalError::invalid(
                            "active moves on a stroke must use one raw position domain",
                        ));
                    }
                    total_x = total_x.checked_add(*delta_x_raw).ok_or_else(|| {
                        JournalError::invalid("combined active move x delta overflow")
                    })?;
                    total_y = total_y.checked_add(*delta_y_raw).ok_or_else(|| {
                        JournalError::invalid("combined active move y delta overflow")
                    })?;
                }
            }
            let final_delta_x = total_x
                .checked_add(*delta_x_raw)
                .ok_or_else(|| JournalError::invalid("combined edit move x delta overflow"))?;
            let final_delta_y = total_y
                .checked_add(*delta_y_raw)
                .ok_or_else(|| JournalError::invalid("combined edit move y delta overflow"))?;
            for stored in &state.physical_samples {
                if stored.sample.stroke_ref(&state.journal_id).as_ref() == Some(target)
                    && let Some(position) = &stored.sample.position
                {
                    position
                        .x_raw
                        .checked_add(final_delta_x)
                        .ok_or_else(|| JournalError::invalid("projected x coordinate overflow"))?;
                    position
                        .y_raw
                        .checked_add(final_delta_y)
                        .ok_or_else(|| JournalError::invalid("projected y coordinate overflow"))?;
                }
            }
            Ok(())
        }
        EditCommand::Correction {
            target,
            corrected_text,
        } => {
            state.validate_edit_target(target)?;
            validate_optional_text(corrected_text.as_deref(), "edit correction")
        }
    }
}

fn validate_stroke_ref(target: &StrokeRef) -> Result<(), JournalError> {
    validate_text(&target.journal_id, "logical target journal ID", 128)?;
    validate_text(&target.session_id, "logical target session ID", 256)?;
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
    if target.journal_id.is_empty()
        || target.session_id.is_empty()
        || target.source_api.is_empty()
        || target.stroke_id.is_empty()
    {
        return Err(JournalError::invalid(
            "logical target journal/session/API/stroke IDs must be nonempty",
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), JournalError> {
    if value.len() != SHA256_HEX_BYTES || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(JournalError::invalid(format!(
            "{label} must be a 64-character hexadecimal SHA-256 digest"
        )));
    }
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], JournalError> {
    if value.len() != SHA256_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(JournalError::invalid(
            "canonical raster digest must be lowercase SHA-256 hex",
        ));
    }
    let mut digest = [0_u8; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(JournalError::invalid(
            "canonical raster digest must contain complete byte pairs",
        ));
    }
    for (index, pair) in pairs.iter().enumerate() {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| JournalError::invalid("canonical raster digest contains invalid hex"))?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| JournalError::invalid("canonical raster digest contains invalid hex"))?;
        digest[index] = ((high << 4) | low) as u8;
    }
    Ok(digest)
}

fn encode_lower_sha256(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(SHA256_HEX_BYTES);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_input_view_id(value: &str) -> Result<(), JournalError> {
    const PREFIX: &str = "input-view-v1-";
    let Some(fingerprint) = value.strip_prefix(PREFIX) else {
        return Err(JournalError::invalid(
            "projection input-view ID is not an M4 input-view-v1 identity",
        ));
    };
    if fingerprint.len() != 16
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(JournalError::invalid(
            "projection input-view ID has an invalid M4 fingerprint",
        ));
    }
    Ok(())
}

fn validate_provider_configuration_fingerprint(value: &str) -> Result<(), JournalError> {
    const PREFIX: &str = "provider-config-v1-fnv64-";
    let Some(fingerprint) = value.strip_prefix(PREFIX) else {
        return Err(JournalError::invalid(
            "projection provider configuration fingerprint is not an M4 identifier",
        ));
    };
    if fingerprint.len() != 16
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(JournalError::invalid(
            "projection provider configuration fingerprint is malformed",
        ));
    }
    Ok(())
}

fn validate_ink_binding_fields(binding: &ProjectionInkBindingV1) -> Result<(), JournalError> {
    validate_text(&binding.journal_id, "projection journal ID", 128)?;
    validate_text(
        &binding.region_id,
        "projection region ID",
        MAX_PROJECTION_SOURCE_ID_BYTES,
    )?;
    validate_text(
        binding.line_id.as_deref().unwrap_or_default(),
        "projection line ID",
        MAX_PROJECTION_SOURCE_ID_BYTES,
    )?;
    validate_text(
        &binding.input_view_id,
        "projection input-view ID",
        MAX_PROJECTION_SOURCE_ID_BYTES,
    )?;
    validate_input_view_id(&binding.input_view_id)?;
    validate_sha256(&binding.ink_binding_sha256, "projection ink binding")?;
    if binding.journal_id.is_empty()
        || binding.region_id.is_empty()
        || binding.input_view_id.is_empty()
        || binding.line_id.as_deref() == Some("")
    {
        return Err(JournalError::invalid(
            "projection journal, region, view, and present line IDs must be nonempty",
        ));
    }
    if binding.selected_strokes.is_empty()
        || binding.selected_strokes.len() > MAX_PROJECTION_STROKES
        || binding.source_sample_sequences.is_empty()
        || binding.source_sample_sequences.len() > MAX_PROJECTION_SAMPLES
        || binding.stroke_views.len() != binding.selected_strokes.len()
    {
        return Err(JournalError::limit(
            "projection stroke, sample, or view-frame count is empty or exceeds its cap",
        ));
    }
    let mut unique_strokes = HashSet::new();
    unique_strokes
        .try_reserve(binding.selected_strokes.len())
        .map_err(JournalError::allocation)?;
    for stroke in &binding.selected_strokes {
        validate_stroke_ref(stroke)?;
        if stroke.journal_id != binding.journal_id || !unique_strokes.insert(stroke) {
            return Err(JournalError::invalid(
                "projection selected strokes contain a duplicate or cross-project identity",
            ));
        }
    }
    let mut previous_sequence = 0u64;
    for sequence in &binding.source_sample_sequences {
        if *sequence == 0 || *sequence <= previous_sequence {
            return Err(JournalError::invalid(
                "projection source sample sequences must be positive and strictly ordered",
            ));
        }
        previous_sequence = *sequence;
    }
    for (stroke, view) in binding.selected_strokes.iter().zip(&binding.stroke_views) {
        if &view.stroke != stroke || !view.frame.is_valid() {
            return Err(JournalError::invalid(
                "projection view frames must match selected stroke order and be valid",
            ));
        }
    }
    Ok(())
}

fn validate_recognition_projection_fields(
    projection: &RecognitionProjectionV1,
) -> Result<(), JournalError> {
    validate_text(
        &projection.projection_id,
        "recognition projection ID",
        MAX_PROJECTION_ID_BYTES,
    )?;
    if projection.projection_id.is_empty() {
        return Err(JournalError::invalid(
            "recognition projection ID must be nonempty",
        ));
    }
    validate_ink_binding_fields(&projection.ink)?;
    for (value, label, maximum) in [
        (&projection.provider.provider_id, "provider ID", 256usize),
        (
            &projection.provider.provider_version,
            "provider version",
            256usize,
        ),
        (
            &projection.provider.configuration_id,
            "provider configuration ID",
            256usize,
        ),
    ] {
        validate_text(value, label, maximum)?;
        if value.is_empty() {
            return Err(JournalError::invalid(format!("{label} must be nonempty")));
        }
    }
    for (value, label) in [
        (&projection.provider.model_version, "model version"),
        (&projection.provider.resource_version, "resource version"),
    ] {
        if let Some(value) = value {
            validate_text(value, label, 512)?;
            if value.is_empty() {
                return Err(JournalError::invalid(format!(
                    "{label} must be nonempty when present"
                )));
            }
        }
    }
    validate_text(
        &projection.provider.configuration_fingerprint,
        "provider configuration fingerprint",
        256,
    )?;
    validate_provider_configuration_fingerprint(&projection.provider.configuration_fingerprint)?;
    if projection.candidates.len() > MAX_PROJECTION_CANDIDATES {
        return Err(JournalError::limit(
            "recognition candidate count exceeds its fixed cap",
        ));
    }
    let mut range_count = 0usize;
    for (index, candidate) in projection.candidates.iter().enumerate() {
        if usize::from(candidate.rank) != index {
            return Err(JournalError::invalid(
                "recognition candidate ranks must be contiguous and ordered from zero",
            ));
        }
        validate_text(
            &candidate.recognized_text,
            "recognized candidate text",
            MAX_JOURNAL_TEXT_BYTES,
        )?;
        if let Some(score) = &candidate.native_score_raw {
            validate_text(score, "native recognition score", 256)?;
            if serde_json::from_str::<serde_json::Number>(score).is_err() {
                return Err(JournalError::invalid(
                    "native recognition score is not a JSON number",
                ));
            }
        }
        range_count = range_count
            .checked_add(candidate.stroke_ranges.len())
            .ok_or_else(|| JournalError::limit("recognition range count overflow"))?;
        if range_count > MAX_PROJECTION_RANGES {
            return Err(JournalError::limit(
                "recognition stroke-range count exceeds its fixed cap",
            ));
        }
        for range in &candidate.stroke_ranges {
            validate_stroke_ref(&range.stroke)?;
            if range.first_journal_sequence == 0
                || range.first_journal_sequence > range.last_journal_sequence
            {
                return Err(JournalError::invalid(
                    "recognition stroke range is empty or reversed",
                ));
            }
        }
    }
    if let Some(modalities) = &projection.input_modalities {
        if modalities.is_empty() || modalities.len() > MAX_PROJECTION_INPUT_MODALITIES {
            return Err(JournalError::limit(
                "projection input-modality list is empty or exceeds its fixed cap",
            ));
        }
        for (index, modality) in modalities.iter().enumerate() {
            if modalities[..index].contains(modality) {
                return Err(JournalError::invalid(
                    "projection input modalities must be unique",
                ));
            }
        }
        if projection.provider.provider_id == LOCAL_SENOCR_RASTER_PROVIDER_ID
            && (modalities.len() != 1
                || modalities.first() != Some(&ProjectionInputModalityV1::Raster)
                || projection.generated_raster.is_none())
        {
            return Err(JournalError::invalid(
                "local SenOCR projections require the exact Raster mode and generated origin",
            ));
        }
    }
    if let Some(generated_raster) = &projection.generated_raster {
        if projection
            .input_modalities
            .as_ref()
            .is_none_or(|modalities| !modalities.contains(&ProjectionInputModalityV1::Raster))
        {
            return Err(JournalError::invalid(
                "generated raster origin requires a persisted Raster input modality",
            ));
        }
        validate_generated_raster_provenance(generated_raster, &projection.ink)?;
    }
    Ok(())
}

fn validate_generated_raster_provenance(
    provenance: &GeneratedRasterProvenanceV1,
    ink: &ProjectionInkBindingV1,
) -> Result<(), JournalError> {
    let source = &provenance.source;
    for (value, label, maximum) in [
        (&source.journal_id, "generated raster journal ID", 128usize),
        (
            &source.region_id,
            "generated raster region ID",
            MAX_PROJECTION_SOURCE_ID_BYTES,
        ),
        (
            &source.input_view_id,
            "generated raster input-view ID",
            MAX_PROJECTION_SOURCE_ID_BYTES,
        ),
    ] {
        validate_text(value, label, maximum)?;
        if value.is_empty() {
            return Err(JournalError::invalid(format!("{label} must be nonempty")));
        }
    }
    if let Some(line_id) = &source.line_id {
        validate_text(
            line_id,
            "generated raster line ID",
            MAX_PROJECTION_SOURCE_ID_BYTES,
        )?;
        if line_id.is_empty() {
            return Err(JournalError::invalid(
                "generated raster line ID must be nonempty when present",
            ));
        }
    }
    validate_input_view_id(&source.input_view_id)?;
    validate_sha256(&source.ink_binding_sha256, "generated raster ink binding")?;
    if provenance.schema_version != 1
        || source.journal_id != ink.journal_id
        || source.logical_revision != ink.logical_revision
        || source.last_sequence != ink.last_sequence
        || source.region_id != ink.region_id
        || source.line_id != ink.line_id
        || source.input_view_id != ink.input_view_id
        || source.ink_binding_sha256 != ink.ink_binding_sha256
    {
        return Err(JournalError::invalid(
            "generated raster source does not match the exact projection input binding",
        ));
    }

    let spec = &provenance.projection_spec;
    let output_pixels = u64::from(spec.output_width_px)
        .checked_mul(u64::from(spec.output_height_px))
        .ok_or_else(|| JournalError::limit("generated raster pixel count overflow"))?;
    let expected_stride = spec
        .output_width_px
        .checked_mul(PROJECTION_RASTER_BYTES_PER_PIXEL)
        .ok_or_else(|| JournalError::limit("generated raster row stride overflow"))?;
    let expected_buffer_bytes = expected_stride
        .checked_mul(spec.output_height_px)
        .ok_or_else(|| JournalError::limit("generated raster buffer size overflow"))?;
    let crop_width =
        i64::from(spec.source_crop_right_px_exclusive) - i64::from(spec.source_crop_left_px);
    let crop_height =
        i64::from(spec.source_crop_bottom_px_exclusive) - i64::from(spec.source_crop_top_px);
    let crop_area = crop_width
        .checked_mul(crop_height)
        .ok_or_else(|| JournalError::limit("generated raster crop area overflow"))?;
    if spec.schema_version != 1
        || spec.output_width_px == 0
        || spec.output_height_px == 0
        || spec.output_width_px > MAX_PROJECTION_RASTER_DIMENSION
        || spec.output_height_px > MAX_PROJECTION_RASTER_DIMENSION
        || output_pixels > MAX_PROJECTION_RASTER_PIXELS
        || crop_width <= 0
        || crop_height <= 0
        || crop_width > MAX_PROJECTION_RASTER_CROP_DIMENSION
        || crop_height > MAX_PROJECTION_RASTER_CROP_DIMENSION
        || crop_area > MAX_PROJECTION_RASTER_CROP_AREA
        || spec.background_rgba != PROJECTION_RASTER_BACKGROUND_RGBA
        || spec.committed_ink_rgba != PROJECTION_RASTER_INK_RGBA
        || spec.stroke_width_16_16 != PROJECTION_RASTER_INK_WIDTH_16_16
        || spec.row_stride_bytes != expected_stride
        || spec.output_buffer_bytes != expected_buffer_bytes
        || provenance.output_width_px != spec.output_width_px
        || provenance.output_height_px != spec.output_height_px
        || provenance.row_stride_bytes != expected_stride
        || provenance.pixel_layout != spec.pixel_layout
        || provenance.geometry_schema_version != 1
        || provenance.raster_artifact_schema_version != 1
        || provenance.renderer_version != CANONICAL_RASTER_RENDERER_VERSION_V1
        || provenance.png_bytes_len == 0
        || provenance.png_bytes_len > MAX_PROJECTION_RASTER_PNG_BYTES
    {
        return Err(JournalError::invalid(
            "generated raster spec, dimensions, renderer, layout, or byte caps are inconsistent",
        ));
    }

    for (value, label) in [
        (
            &provenance.source_content_sha256,
            "generated raster source content",
        ),
        (&provenance.projection_spec_sha256, "generated raster spec"),
        (&provenance.geometry_sha256, "generated raster geometry"),
        (&provenance.pixel_bytes_sha256, "generated raster pixels"),
        (&provenance.png_bytes_sha256, "generated raster PNG"),
        (
            &provenance.raster_artifact_sha256,
            "generated raster artifact",
        ),
    ] {
        decode_sha256(value).map_err(|_| {
            JournalError::invalid(format!("{label} digest is not lowercase SHA-256 hex"))
        })?;
    }
    if provenance.projection_spec_sha256 != encode_lower_sha256(&spec.canonical_sha256()) {
        return Err(JournalError::invalid(
            "generated raster spec digest does not match its declared transform",
        ));
    }
    if provenance.raster_artifact_sha256
        != encode_lower_sha256(&provenance.expected_raster_artifact_sha256()?)
    {
        return Err(JournalError::invalid(
            "generated raster artifact digest does not match its metadata",
        ));
    }
    Ok(())
}

pub(crate) fn validate_region_correction_text(text: &str) -> Result<(), JournalError> {
    validate_region_correction_text_length(text.len())?;
    validate_text(text, "region correction text", MAX_JOURNAL_TEXT_BYTES)
}

pub(crate) fn validate_region_correction_text_length(length: usize) -> Result<(), JournalError> {
    if length > MAX_JOURNAL_TEXT_BYTES {
        return Err(JournalError::limit(format!(
            "region correction text exceeds {MAX_JOURNAL_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

pub(crate) fn validate_region_correction_fields(
    correction: &RegionCorrectionV1,
) -> Result<(), JournalError> {
    validate_text(
        &correction.correction_id,
        "region correction ID",
        MAX_PROJECTION_ID_BYTES,
    )?;
    validate_text(
        &correction.projection_id,
        "region correction projection ID",
        MAX_PROJECTION_ID_BYTES,
    )?;
    if correction.correction_id.is_empty() || correction.projection_id.is_empty() {
        return Err(JournalError::invalid(
            "region correction and projection IDs must be nonempty",
        ));
    }
    validate_ink_binding_fields(&correction.ink)?;
    if let RegionCorrectionActionV1::SetText(text) = &correction.action {
        // Empty text is a valid explicit SetText value; Reset remains a
        // separate enum variant and is never conflated with it.
        validate_region_correction_text(text)?;
    }
    Ok(())
}

fn encode_json_payload<T: Serialize>(payload: &T, label: &str) -> Result<String, JournalError> {
    let json = serde_json::to_string(payload)
        .map_err(|error| JournalError::invalid(format!("{label} JSON encoding failed: {error}")))?;
    if json.len() > MAX_JOURNAL_LINE_BYTES {
        return Err(JournalError::limit(format!(
            "{label} JSON exceeds the row cap"
        )));
    }
    Ok(encode_field(&json))
}

fn decode_json_payload<T: for<'de> Deserialize<'de>>(
    field: &str,
    label: &str,
) -> Result<T, JournalError> {
    let json = decode_field(field)?;
    if json.len() > MAX_JOURNAL_LINE_BYTES {
        return Err(JournalError::limit(format!(
            "{label} JSON exceeds the row cap"
        )));
    }
    serde_json::from_str(&json)
        .map_err(|error| JournalError::invalid(format!("{label} JSON is malformed: {error}")))
}

fn encode_record_fields(record: &JournalRecord, version: u32) -> Result<Vec<String>, JournalError> {
    let mut fields = match &record.event {
        JournalEvent::PhysicalSample(sample) => {
            encode_sample_fields("P", record.sequence, sample, version)?
        }
        JournalEvent::Metadata(metadata) => {
            encode_metadata_fields("META", record.sequence, metadata)
        }
        JournalEvent::SessionEpochStarted {
            epoch,
            app_arrival_elapsed_ns,
        } => vec![
            "EPOCH".to_owned(),
            record.sequence.to_string(),
            app_arrival_elapsed_ns.to_string(),
            opt_u128(epoch.started_at_unix_ns),
            encode_option_text(epoch.config_id.as_deref()),
            encode_field(&epoch.provenance),
            epoch.requires_stroke_commit.to_string(),
        ],
        JournalEvent::StrokeStarted {
            target,
            view_frame,
            app_arrival_elapsed_ns,
        } => {
            let mut fields = vec![
                "SBEG".to_owned(),
                record.sequence.to_string(),
                app_arrival_elapsed_ns.to_string(),
            ];
            fields.extend(encode_stroke_view_frame_fields(*view_frame));
            fields.extend(encode_stroke_ref_fields(target, version));
            fields
        }
        JournalEvent::StrokeInterrupted {
            target,
            reason,
            app_arrival_elapsed_ns,
        } => {
            let mut fields = vec![
                "SINT".to_owned(),
                record.sequence.to_string(),
                app_arrival_elapsed_ns.to_string(),
                encode_stroke_interruption_reason(*reason).to_owned(),
            ];
            fields.extend(encode_stroke_ref_fields(target, version));
            fields
        }
        JournalEvent::EditAction {
            action_id,
            revision_id,
            app_arrival_elapsed_ns,
            command,
        } => encode_edit_action_fields(
            record.sequence,
            *revision_id,
            *app_arrival_elapsed_ns,
            *action_id,
            command,
            version,
        )?,
        JournalEvent::Undo {
            action_id,
            revision_id,
            app_arrival_elapsed_ns,
        } => vec![
            "UNDO".to_owned(),
            record.sequence.to_string(),
            revision_id.to_string(),
            app_arrival_elapsed_ns.to_string(),
            action_id.to_string(),
        ],
        JournalEvent::Redo {
            action_id,
            revision_id,
            app_arrival_elapsed_ns,
        } => vec![
            "REDO".to_owned(),
            record.sequence.to_string(),
            revision_id.to_string(),
            app_arrival_elapsed_ns.to_string(),
            action_id.to_string(),
        ],
        JournalEvent::MigrationProvenance {
            source_schema_version,
            source_journal_id,
            source_prefix_fingerprint,
            source_record_count,
            app_arrival_elapsed_ns,
        } => vec![
            "MIGR".to_owned(),
            record.sequence.to_string(),
            opt_u128(*app_arrival_elapsed_ns),
            source_schema_version.to_string(),
            encode_field(source_journal_id),
            format!("{source_prefix_fingerprint:016X}"),
            source_record_count.to_string(),
        ],
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
            fields.extend(encode_stroke_ref_fields(target, version));
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
            fields.extend(encode_stroke_ref_fields(target, version));
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
            fields.extend(encode_stroke_ref_fields(target, version));
            fields.push(encode_field(corrected_text));
            fields
        }
        JournalEvent::RecognitionProjection {
            app_arrival_elapsed_ns,
            projection,
        } => {
            if version < JOURNAL_SCHEMA_VERSION {
                return Err(JournalError::invalid(
                    "recognition projections require journal schema 4",
                ));
            }
            vec![
                "RPROJ".to_owned(),
                record.sequence.to_string(),
                app_arrival_elapsed_ns.to_string(),
                encode_json_payload(projection, "recognition projection")?,
            ]
        }
        JournalEvent::RegionCorrection {
            app_arrival_elapsed_ns,
            correction,
        } => {
            if version < JOURNAL_SCHEMA_VERSION {
                return Err(JournalError::invalid(
                    "region corrections require journal schema 4",
                ));
            }
            vec![
                "RCOR".to_owned(),
                record.sequence.to_string(),
                app_arrival_elapsed_ns.to_string(),
                encode_json_payload(correction, "region correction")?,
            ]
        }
    };
    if version >= THIRD_JOURNAL_SCHEMA_VERSION {
        fields.insert(2, encode_field(&record.app_epoch_id));
    }
    Ok(fields)
}

fn encode_edit_action_fields(
    sequence: u64,
    revision_id: u64,
    app_arrival_elapsed_ns: u128,
    action_id: u64,
    command: &EditCommand,
    version: u32,
) -> Result<Vec<String>, JournalError> {
    let mut fields = vec![
        "ACT".to_owned(),
        sequence.to_string(),
        revision_id.to_string(),
        app_arrival_elapsed_ns.to_string(),
        action_id.to_string(),
    ];
    match command {
        EditCommand::Tombstone { targets } | EditCommand::Restore { targets } => {
            fields.push(if matches!(command, EditCommand::Tombstone { .. }) {
                "hide".to_owned()
            } else {
                "restore".to_owned()
            });
            fields.push(targets.len().to_string());
            for target in targets {
                fields.extend(encode_stroke_ref_fields(target, version));
            }
        }
        EditCommand::StrokeVisibility { targets, visible } => {
            fields.extend([
                "visibility".to_owned(),
                visible.to_string(),
                targets.len().to_string(),
            ]);
            for target in targets {
                fields.extend(encode_stroke_ref_fields(target, version));
            }
        }
        EditCommand::Move {
            target,
            delta_x_raw,
            delta_y_raw,
            coordinate_space,
            units,
        } => {
            fields.push("move".to_owned());
            fields.extend(encode_stroke_ref_fields(target, version));
            fields.extend([
                delta_x_raw.to_string(),
                delta_y_raw.to_string(),
                encode_field(coordinate_space),
                encode_field(units),
            ]);
        }
        EditCommand::Correction {
            target,
            corrected_text,
        } => {
            fields.push("correction".to_owned());
            fields.extend(encode_stroke_ref_fields(target, version));
            fields.push(encode_option_text(corrected_text.as_deref()));
        }
    }
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

fn encode_stroke_ref_fields(target: &StrokeRef, version: u32) -> Vec<String> {
    let mut fields = Vec::new();
    if version >= THIRD_JOURNAL_SCHEMA_VERSION {
        fields.extend([
            encode_field(&target.journal_id),
            encode_field(&target.session_id),
        ]);
    }
    fields.extend([
        encode_field(&target.source_api),
        encode_option_text(target.device_id.as_deref()),
        opt_u64(target.pointer_id),
        encode_field(&target.stroke_id),
    ]);
    fields
}

fn encode_stroke_view_frame_fields(frame: StrokeViewFrame) -> [String; STROKE_VIEW_FRAME_WIDTH] {
    [
        frame.screen_origin_x_px.to_string(),
        frame.screen_origin_y_px.to_string(),
        format!("{:016X}", frame.dpi_scale_factor_bits),
        format!("{:016X}", frame.canvas_zoom_bits),
        format!("{:016X}", frame.canvas_pan_x_bits),
        format!("{:016X}", frame.canvas_pan_y_bits),
        frame.toolbar_height_px.to_string(),
    ]
}

fn parse_stroke_view_frame_fields(
    fields: &[&str],
    start: usize,
) -> Result<StrokeViewFrame, JournalError> {
    let frame = StrokeViewFrame {
        screen_origin_x_px: parse_i64(fields[start], "stroke view origin x")?,
        screen_origin_y_px: parse_i64(fields[start + 1], "stroke view origin y")?,
        dpi_scale_factor_bits: parse_hex_u64(fields[start + 2], "stroke view DPI scale bits")?,
        canvas_zoom_bits: parse_hex_u64(fields[start + 3], "stroke view zoom bits")?,
        canvas_pan_x_bits: parse_hex_u64(fields[start + 4], "stroke view pan x bits")?,
        canvas_pan_y_bits: parse_hex_u64(fields[start + 5], "stroke view pan y bits")?,
        toolbar_height_px: parse_u32(fields[start + 6], "stroke view toolbar height")?,
    };
    if !frame.is_valid() {
        return Err(JournalError::invalid("stroke start view frame is invalid"));
    }
    Ok(frame)
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

fn encode_stroke_interruption_reason(reason: StrokeInterruptionReason) -> &'static str {
    match reason {
        StrokeInterruptionReason::PointerDownBeforePenUp => "pointer-down-before-pen-up",
        StrokeInterruptionReason::PointerCaptureChanged => "pointer-capture-changed",
        StrokeInterruptionReason::PointerLeave => "pointer-leave",
        StrokeInterruptionReason::PointerReentryBoundary => "pointer-reentry-boundary",
        StrokeInterruptionReason::DeviceOutOfRange => "device-out-of-range",
        StrokeInterruptionReason::DeviceChanged => "device-changed",
        StrokeInterruptionReason::DeviceReentryBoundary => "device-reentry-boundary",
        StrokeInterruptionReason::ContactLostWithoutPenUp => "contact-lost-without-pen-up",
        StrokeInterruptionReason::CanvasViewTransformChanged => "canvas-view-transform-changed",
        StrokeInterruptionReason::CanvasToolChanged => "canvas-tool-changed",
        StrokeInterruptionReason::CanceledNativeUp => "canceled-native-up",
        StrokeInterruptionReason::UnattributedNativeUp => "unattributed-native-up",
        StrokeInterruptionReason::AmbiguousNativeUp => "ambiguous-native-up",
        StrokeInterruptionReason::MixedDeviceBatch => "mixed-device-batch",
        StrokeInterruptionReason::WindowFocusLost => "window-focus-lost",
        StrokeInterruptionReason::WriterBackpressure => "writer-backpressure",
        StrokeInterruptionReason::ProcessEndedWithoutPenUp => "process-ended-without-pen-up",
    }
}

fn parse_stroke_interruption_reason(value: &str) -> Result<StrokeInterruptionReason, JournalError> {
    match value {
        "pointer-down-before-pen-up" => Ok(StrokeInterruptionReason::PointerDownBeforePenUp),
        "pointer-capture-changed" => Ok(StrokeInterruptionReason::PointerCaptureChanged),
        "pointer-leave" => Ok(StrokeInterruptionReason::PointerLeave),
        "pointer-reentry-boundary" => Ok(StrokeInterruptionReason::PointerReentryBoundary),
        "device-out-of-range" => Ok(StrokeInterruptionReason::DeviceOutOfRange),
        "device-changed" => Ok(StrokeInterruptionReason::DeviceChanged),
        "device-reentry-boundary" => Ok(StrokeInterruptionReason::DeviceReentryBoundary),
        "contact-lost-without-pen-up" => Ok(StrokeInterruptionReason::ContactLostWithoutPenUp),
        "canvas-view-transform-changed" => Ok(StrokeInterruptionReason::CanvasViewTransformChanged),
        "canvas-tool-changed" => Ok(StrokeInterruptionReason::CanvasToolChanged),
        "canceled-native-up" => Ok(StrokeInterruptionReason::CanceledNativeUp),
        "unattributed-native-up" => Ok(StrokeInterruptionReason::UnattributedNativeUp),
        "ambiguous-native-up" => Ok(StrokeInterruptionReason::AmbiguousNativeUp),
        "mixed-device-batch" => Ok(StrokeInterruptionReason::MixedDeviceBatch),
        "window-focus-lost" => Ok(StrokeInterruptionReason::WindowFocusLost),
        "writer-backpressure" => Ok(StrokeInterruptionReason::WriterBackpressure),
        "process-ended-without-pen-up" => Ok(StrokeInterruptionReason::ProcessEndedWithoutPenUp),
        other => Err(JournalError::invalid(format!(
            "unknown stroke interruption reason {other:?}"
        ))),
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

fn parse_record_fields(
    version: u32,
    fields: &[&str],
    header: &JournalHeader,
) -> Result<JournalRecord, JournalError> {
    let tag = fields
        .first()
        .copied()
        .ok_or_else(|| JournalError::invalid("empty journal record"))?;
    let (app_epoch_id, body_fields) = if version >= THIRD_JOURNAL_SCHEMA_VERSION {
        require_at_least_fields(fields, 3, tag)?;
        let app_epoch_id = decode_field(fields[2])?;
        let mut shifted = Vec::new();
        shifted
            .try_reserve(fields.len().saturating_sub(1))
            .map_err(JournalError::allocation)?;
        shifted.extend_from_slice(&fields[..2]);
        shifted.extend_from_slice(&fields[3..]);
        (app_epoch_id, shifted)
    } else {
        (header.session_id.clone(), fields.to_vec())
    };
    let fields = body_fields.as_slice();
    let sequence = || parse_u64(fields[1], "journal event sequence");
    let stroke_ref_width = if version >= THIRD_JOURNAL_SCHEMA_VERSION {
        6
    } else {
        4
    };

    let event = match fields
        .first()
        .copied()
        .ok_or_else(|| JournalError::invalid("empty journal record"))?
    {
        "P" => JournalEvent::PhysicalSample(Box::new(parse_sample_fields(
            fields,
            if version >= THIRD_JOURNAL_SCHEMA_VERSION {
                PREVIOUS_JOURNAL_SCHEMA_VERSION
            } else {
                version
            },
        )?)),
        "META" => JournalEvent::Metadata(parse_metadata_fields(fields)?),
        "EPOCH" if version >= THIRD_JOURNAL_SCHEMA_VERSION => {
            require_fields(fields, 7, "EPOCH")?;
            JournalEvent::SessionEpochStarted {
                epoch: SessionEpoch {
                    session_id: app_epoch_id.clone(),
                    started_at_unix_ns: parse_option_u128(
                        fields[3],
                        "session epoch wall-clock start",
                    )?,
                    config_id: decode_option_text(fields[4])?,
                    provenance: decode_field(fields[5])?,
                    requires_stroke_commit: parse_bool(
                        fields[6],
                        "session epoch stroke-commit policy",
                    )?,
                },
                app_arrival_elapsed_ns: parse_u128(fields[2], "session epoch app arrival")?,
            }
        }
        "SBEG" if version >= THIRD_JOURNAL_SCHEMA_VERSION => {
            require_fields(
                fields,
                3 + STROKE_VIEW_FRAME_WIDTH + stroke_ref_width,
                "SBEG",
            )?;
            let view_frame = parse_stroke_view_frame_fields(fields, 3)?;
            JournalEvent::StrokeStarted {
                app_arrival_elapsed_ns: parse_u128(fields[2], "stroke start app arrival")?,
                view_frame,
                target: parse_stroke_ref_fields(
                    fields,
                    3 + STROKE_VIEW_FRAME_WIDTH,
                    version,
                    &header.journal_id,
                    &header.session_id,
                )?,
            }
        }
        "SINT" if version >= THIRD_JOURNAL_SCHEMA_VERSION => {
            require_fields(fields, 4 + stroke_ref_width, "SINT")?;
            JournalEvent::StrokeInterrupted {
                app_arrival_elapsed_ns: parse_u128(fields[2], "stroke interruption app arrival")?,
                reason: parse_stroke_interruption_reason(fields[3])?,
                target: parse_stroke_ref_fields(
                    fields,
                    4,
                    version,
                    &header.journal_id,
                    &header.session_id,
                )?,
            }
        }
        "ACT" if version >= THIRD_JOURNAL_SCHEMA_VERSION => {
            require_at_least_fields(fields, 6, "ACT")?;
            let revision_id = parse_u64(fields[2], "edit action revision")?;
            let app_arrival_elapsed_ns = parse_u128(fields[3], "edit action app arrival")?;
            let action_id = parse_u64(fields[4], "edit action ID")?;
            let kind = fields[5];
            let command = match kind {
                "hide" | "restore" => {
                    require_at_least_fields(fields, 7, "ACT targets")?;
                    let target_count = parse_usize(fields[6], "edit target count")?;
                    if target_count == 0 || target_count > MAX_EDIT_TARGETS {
                        return Err(JournalError::limit(
                            "edit target count is empty or exceeds the configured cap",
                        ));
                    }
                    let expected_fields = 7usize
                        .checked_add(target_count.saturating_mul(stroke_ref_width))
                        .ok_or_else(|| JournalError::limit("edit target row width overflow"))?;
                    require_fields(fields, expected_fields, "ACT targets")?;
                    let mut targets = Vec::new();
                    targets
                        .try_reserve_exact(target_count)
                        .map_err(JournalError::allocation)?;
                    for index in 0..target_count {
                        let start = 7 + index * stroke_ref_width;
                        targets.push(parse_stroke_ref_fields(
                            fields,
                            start,
                            version,
                            &header.journal_id,
                            &header.session_id,
                        )?);
                    }
                    if kind == "hide" {
                        EditCommand::Tombstone { targets }
                    } else {
                        EditCommand::Restore { targets }
                    }
                }
                "move" => {
                    let expected_fields = 6 + stroke_ref_width + 4;
                    require_fields(fields, expected_fields, "ACT move")?;
                    let start = 6;
                    EditCommand::Move {
                        target: parse_stroke_ref_fields(
                            fields,
                            start,
                            version,
                            &header.journal_id,
                            &header.session_id,
                        )?,
                        delta_x_raw: parse_i64(
                            fields[start + stroke_ref_width],
                            "edit move delta x",
                        )?,
                        delta_y_raw: parse_i64(
                            fields[start + stroke_ref_width + 1],
                            "edit move delta y",
                        )?,
                        coordinate_space: decode_field(fields[start + stroke_ref_width + 2])?,
                        units: decode_field(fields[start + stroke_ref_width + 3])?,
                    }
                }
                "correction" => {
                    let expected_fields = 6 + stroke_ref_width + 1;
                    require_fields(fields, expected_fields, "ACT correction")?;
                    EditCommand::Correction {
                        target: parse_stroke_ref_fields(
                            fields,
                            6,
                            version,
                            &header.journal_id,
                            &header.session_id,
                        )?,
                        corrected_text: decode_option_text(fields[6 + stroke_ref_width])?,
                    }
                }
                "visibility" => {
                    require_at_least_fields(fields, 8, "ACT visibility")?;
                    let visible = parse_bool(fields[6], "stroke visibility")?;
                    let target_count = parse_usize(fields[7], "stroke visibility target count")?;
                    if target_count == 0 || target_count > MAX_EDIT_TARGETS {
                        return Err(JournalError::limit(
                            "visibility target count is empty or exceeds the configured cap",
                        ));
                    }
                    let expected_fields = 8usize
                        .checked_add(target_count.saturating_mul(stroke_ref_width))
                        .ok_or_else(|| JournalError::limit("visibility row width overflow"))?;
                    require_fields(fields, expected_fields, "ACT visibility")?;
                    let mut targets = Vec::new();
                    targets
                        .try_reserve_exact(target_count)
                        .map_err(JournalError::allocation)?;
                    for index in 0..target_count {
                        let start = 8 + index * stroke_ref_width;
                        targets.push(parse_stroke_ref_fields(
                            fields,
                            start,
                            version,
                            &header.journal_id,
                            &header.session_id,
                        )?);
                    }
                    EditCommand::StrokeVisibility { targets, visible }
                }
                other => {
                    return Err(JournalError::invalid(format!(
                        "unknown edit action kind {other:?}"
                    )));
                }
            };
            JournalEvent::EditAction {
                action_id,
                revision_id,
                app_arrival_elapsed_ns,
                command,
            }
        }
        "UNDO" | "REDO" if version >= THIRD_JOURNAL_SCHEMA_VERSION => {
            require_fields(fields, 5, "undo/redo")?;
            let action_id = parse_u64(fields[4], "undo/redo target action ID")?;
            let revision_id = parse_u64(fields[2], "undo/redo revision")?;
            let app_arrival_elapsed_ns = parse_u128(fields[3], "undo/redo app arrival")?;
            if fields[0] == "UNDO" {
                JournalEvent::Undo {
                    action_id,
                    revision_id,
                    app_arrival_elapsed_ns,
                }
            } else {
                JournalEvent::Redo {
                    action_id,
                    revision_id,
                    app_arrival_elapsed_ns,
                }
            }
        }
        "MIGR" if version >= THIRD_JOURNAL_SCHEMA_VERSION => {
            require_fields(fields, 7, "MIGR")?;
            JournalEvent::MigrationProvenance {
                app_arrival_elapsed_ns: parse_option_u128(fields[2], "migration app arrival")?,
                source_schema_version: parse_u32(fields[3], "migration source schema")?,
                source_journal_id: decode_field(fields[4])?,
                source_prefix_fingerprint: parse_hex_u64(fields[5], "migration source prefix")?,
                source_record_count: parse_u64(fields[6], "migration source record count")?,
            }
        }
        "RPROJ" if version >= JOURNAL_SCHEMA_VERSION => {
            require_fields(fields, 4, "RPROJ")?;
            JournalEvent::RecognitionProjection {
                app_arrival_elapsed_ns: parse_u128(
                    fields[2],
                    "recognition projection app arrival",
                )?,
                projection: Box::new(decode_json_payload(fields[3], "recognition projection")?),
            }
        }
        "RCOR" if version >= JOURNAL_SCHEMA_VERSION => {
            require_fields(fields, 4, "RCOR")?;
            JournalEvent::RegionCorrection {
                app_arrival_elapsed_ns: parse_u128(fields[2], "region correction app arrival")?,
                correction: Box::new(decode_json_payload(fields[3], "region correction")?),
            }
        }
        "REV" => {
            require_fields(fields, 6, "REV")?;
            JournalEvent::Revision {
                app_arrival_elapsed_ns: parse_u128(fields[2], "revision app arrival")?,
                revision_id: parse_u64(fields[3], "logical revision ID")?,
                parent_revision: parse_u64(fields[4], "parent logical revision")?,
                note: decode_field(fields[5])?,
            }
        }
        "TOMB" => {
            require_fields(fields, 4 + stroke_ref_width, "TOMB")?;
            JournalEvent::Tombstone {
                app_arrival_elapsed_ns: parse_u128(fields[2], "tombstone app arrival")?,
                logical_revision: parse_u64(fields[3], "tombstone revision")?,
                target: parse_stroke_ref_fields(
                    fields,
                    4,
                    version,
                    &header.journal_id,
                    &header.session_id,
                )?,
            }
        }
        "MOVE" => {
            let target_start = 4;
            let expected_fields = target_start + stroke_ref_width + 4;
            require_fields(fields, expected_fields, "MOVE")?;
            JournalEvent::StrokeMove {
                app_arrival_elapsed_ns: parse_u128(fields[2], "move app arrival")?,
                logical_revision: parse_u64(fields[3], "move revision")?,
                target: parse_stroke_ref_fields(
                    fields,
                    target_start,
                    version,
                    &header.journal_id,
                    &header.session_id,
                )?,
                delta_x_raw: parse_i64(fields[target_start + stroke_ref_width], "move delta x")?,
                delta_y_raw: parse_i64(
                    fields[target_start + stroke_ref_width + 1],
                    "move delta y",
                )?,
                coordinate_space: decode_field(fields[target_start + stroke_ref_width + 2])?,
                units: decode_field(fields[target_start + stroke_ref_width + 3])?,
            }
        }
        "CORR" => {
            let expected_fields = 4 + stroke_ref_width + 1;
            require_fields(fields, expected_fields, "CORR")?;
            JournalEvent::UserCorrection {
                app_arrival_elapsed_ns: parse_u128(fields[2], "correction app arrival")?,
                logical_revision: parse_u64(fields[3], "correction revision")?,
                target: parse_stroke_ref_fields(
                    fields,
                    4,
                    version,
                    &header.journal_id,
                    &header.session_id,
                )?,
                corrected_text: decode_field(fields[4 + stroke_ref_width])?,
            }
        }
        other => {
            return Err(JournalError::invalid(format!(
                "unknown journal record tag {other:?}"
            )));
        }
    };
    Ok(JournalRecord {
        sequence: sequence()?,
        app_epoch_id,
        event,
    })
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

fn parse_stroke_ref_fields(
    fields: &[&str],
    start: usize,
    version: u32,
    journal_id: &str,
    default_session_id: &str,
) -> Result<StrokeRef, JournalError> {
    let (target_journal_id, target_session_id, source_offset) =
        if version >= THIRD_JOURNAL_SCHEMA_VERSION {
            (
                decode_field(fields[start])?,
                decode_field(fields[start + 1])?,
                2,
            )
        } else {
            (journal_id.to_owned(), default_session_id.to_owned(), 0)
        };
    let target = StrokeRef {
        journal_id: target_journal_id,
        session_id: target_session_id,
        source_api: decode_field(fields[start + source_offset])?,
        device_id: decode_option_text(fields[start + source_offset + 1])?,
        pointer_id: parse_option_u64(
            fields[start + source_offset + 2],
            "logical target pointer ID",
        )?,
        stroke_id: decode_field(fields[start + source_offset + 3])?,
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

fn opt_u128(value: Option<u128>) -> String {
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

fn parse_usize(value: &str, name: &str) -> Result<usize, JournalError> {
    value
        .parse()
        .map_err(|_| JournalError::invalid(format!("invalid {name}: {value:?}")))
}

fn parse_u128(value: &str, name: &str) -> Result<u128, JournalError> {
    value
        .parse()
        .map_err(|_| JournalError::invalid(format!("invalid {name}: {value:?}")))
}

fn parse_option_u128(value: &str, name: &str) -> Result<Option<u128>, JournalError> {
    if value == "~" {
        Ok(None)
    } else {
        parse_u128(value, name).map(Some)
    }
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

fn parse_bool(value: &str, name: &str) -> Result<bool, JournalError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(JournalError::invalid(format!(
            "invalid {name} value: {value:?}"
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

fn require_at_least_fields(fields: &[&str], minimum: usize, tag: &str) -> Result<(), JournalError> {
    if fields.len() < minimum {
        Err(JournalError::invalid(format!(
            "{tag} record has {} fields; expected at least {minimum}",
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

    fn target_of(sample: &PhysicalSample, journal_id: &str) -> StrokeRef {
        sample.stroke_ref(journal_id).unwrap()
    }

    fn append_projection_test_stroke(
        writer: &mut JournalWriter,
        stroke_id: &str,
    ) -> (
        StrokeRef,
        Vec<u64>,
        StrokeViewFrame,
        PhysicalSample,
        PhysicalSample,
    ) {
        let first = sample("direct-wm-pointer", stroke_id, 1, 10, Some(100), true, 10);
        let target = target_of(&first, &writer.header.journal_id);
        let frame = StrokeViewFrame::default();
        writer.start_stroke(target.clone(), frame, 5).unwrap();
        let first_record = writer.append_sample_record(first.clone()).unwrap();
        let second = sample("direct-wm-pointer", stroke_id, 2, 20, Some(200), true, 20);
        let second_record = writer.append_sample_record(second.clone()).unwrap();
        (
            target,
            vec![first_record.sequence, second_record.sequence],
            frame,
            first,
            second,
        )
    }

    fn projection_test_binding(
        state: &JournalReplayState,
        target: &StrokeRef,
        source_sample_sequences: Vec<u64>,
    ) -> ProjectionInkBindingV1 {
        let start = state
            .stroke_starts
            .iter()
            .find(|start| &start.target == target)
            .unwrap();
        ProjectionInkBindingV1 {
            journal_id: state.journal_id.clone(),
            logical_revision: state.logical_revision,
            last_sequence: state.last_sequence,
            region_id: "region-1".to_owned(),
            line_id: Some("line-1".to_owned()),
            input_view_id: "input-view-v1-0000000000000001".to_owned(),
            ink_binding_sha256: "a".repeat(SHA256_HEX_BYTES),
            selected_strokes: vec![target.clone()],
            source_sample_sequences,
            stroke_views: vec![ProjectionStrokeViewV1 {
                stroke: target.clone(),
                frame: start.view_frame,
            }],
        }
    }

    fn projection_test_record(
        projection_id: &str,
        ink: ProjectionInkBindingV1,
        first_sample_sequence: u64,
        last_sample_sequence: u64,
    ) -> RecognitionProjectionV1 {
        RecognitionProjectionV1 {
            projection_id: projection_id.to_owned(),
            ink: ink.clone(),
            provider: ProjectionProviderProvenanceV1 {
                provider_id: "senocr-reference".to_owned(),
                provider_version: "1.0".to_owned(),
                model_version: Some("model-r1".to_owned()),
                resource_version: Some("assets-r1".to_owned()),
                configuration_id: "config-r1".to_owned(),
                configuration_fingerprint: "provider-config-v1-fnv64-5d449396c33394f8".to_owned(),
            },
            generated_raster: None,
            input_modalities: None,
            candidates: vec![RecognitionCandidateV1 {
                rank: 0,
                recognized_text: "recognized text".to_owned(),
                native_score_raw: Some("0.75".to_owned()),
                stroke_ranges: vec![ProjectionStrokeRangeV1 {
                    stroke: ink.selected_strokes[0].clone(),
                    first_journal_sequence: first_sample_sequence,
                    last_journal_sequence: last_sample_sequence,
                }],
            }],
        }
    }

    fn projection_test_generated_raster(
        binding: &ProjectionInkBindingV1,
    ) -> GeneratedRasterProvenanceV1 {
        let projection_spec = ProjectionRasterSpecV1 {
            schema_version: 1,
            output_width_px: 8,
            output_height_px: 8,
            source_crop_left_px: 0,
            source_crop_top_px: 0,
            source_crop_right_px_exclusive: 16,
            source_crop_bottom_px_exclusive: 16,
            aspect_ratio_policy: ProjectionRasterAspectRatioPolicyV1::FitContainCentered,
            pixel_layout: ProjectionRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown,
            coverage_policy: ProjectionRasterCoveragePolicyV1::Antialiased,
            background_rgba: PROJECTION_RASTER_BACKGROUND_RGBA,
            committed_ink_rgba: PROJECTION_RASTER_INK_RGBA,
            stroke_width_16_16: PROJECTION_RASTER_INK_WIDTH_16_16,
            stroke_cap: ProjectionRasterStrokeCapV1::Round,
            stroke_join: ProjectionRasterStrokeJoinV1::Round,
            rounding_policy: ProjectionRasterRoundingPolicyV1::NearestTiesAwayQ16,
            clipping_policy:
                ProjectionRasterClippingPolicyV1::RejectPointsOutsideSourceCropClipCoverageAtOutputBounds,
            single_point_policy: ProjectionRasterSinglePointPolicyV1::OpaqueDiscAtObservedPoint,
            stroke_order_policy: ProjectionRasterStrokeOrderPolicyV1::JournalFirstOccurrence,
            row_stride_bytes: 32,
            output_buffer_bytes: 256,
        };
        let source_content_sha256 = "c".repeat(64);
        let projection_spec_sha256 = encode_lower_sha256(&projection_spec.canonical_sha256());
        let geometry_sha256 = "d".repeat(64);
        let pixel_bytes_sha256 = "e".repeat(64);
        let png_bytes_sha256 = "f".repeat(64);
        let source_content_digest = decode_sha256(&source_content_sha256).unwrap();
        let projection_spec_digest = decode_sha256(&projection_spec_sha256).unwrap();
        let geometry_digest = decode_sha256(&geometry_sha256).unwrap();
        let pixel_bytes_digest = decode_sha256(&pixel_bytes_sha256).unwrap();
        let png_bytes_digest = decode_sha256(&png_bytes_sha256).unwrap();
        let raster_artifact_sha256 = encode_lower_sha256(&canonical_raster_artifact_sha256(
            CanonicalRasterArtifactHashInputV1 {
                schema_version: 1,
                renderer_version: CANONICAL_RASTER_RENDERER_VERSION_V1,
                source_journal_id: &binding.journal_id,
                source_logical_revision: binding.logical_revision,
                source_last_sequence: binding.last_sequence,
                source_content_sha256: &source_content_digest,
                projection_spec_sha256: &projection_spec_digest,
                geometry_sha256: &geometry_digest,
                output_width_px: 8,
                output_height_px: 8,
                row_stride_bytes: 32,
                pixel_layout: ProjectionRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown,
                pixel_bytes_sha256: &pixel_bytes_digest,
                png_bytes_sha256: &png_bytes_digest,
            },
        ));
        GeneratedRasterProvenanceV1 {
            schema_version: 1,
            source: ProjectionRasterSourceBindingV1 {
                journal_id: binding.journal_id.clone(),
                logical_revision: binding.logical_revision,
                last_sequence: binding.last_sequence,
                region_id: binding.region_id.clone(),
                line_id: binding.line_id.clone(),
                input_view_id: binding.input_view_id.clone(),
                ink_binding_sha256: binding.ink_binding_sha256.clone(),
            },
            source_content_sha256,
            projection_spec,
            projection_spec_sha256,
            geometry_schema_version: 1,
            geometry_sha256,
            raster_artifact_schema_version: 1,
            renderer_version: CANONICAL_RASTER_RENDERER_VERSION_V1.to_owned(),
            output_width_px: 8,
            output_height_px: 8,
            row_stride_bytes: 32,
            pixel_layout: ProjectionRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown,
            pixel_bytes_sha256,
            png_bytes_len: 64,
            png_bytes_sha256,
            raster_artifact_sha256,
        }
    }

    fn region_correction_test_record(
        correction_id: &str,
        projection_id: &str,
        ink: ProjectionInkBindingV1,
        action: RegionCorrectionActionV1,
    ) -> RegionCorrectionV1 {
        RegionCorrectionV1 {
            correction_id: correction_id.to_owned(),
            projection_id: projection_id.to_owned(),
            ink,
            action,
        }
    }

    fn cleanup_journal(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(default_snapshot_path(path));
    }

    #[test]
    fn schema_four_projection_correction_history_reopens_and_snapshot_replays_tail() {
        let path = temp_path("projection-correction-history");
        let snapshot_path = default_snapshot_path(&path);
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-derived-history")).unwrap();
        let (target, source_sequences, _frame, first, second) =
            append_projection_test_stroke(&mut writer, "stroke-derived");
        let source_raw = writer.state.physical_samples.clone();
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        let projection = projection_test_record(
            "projection-1",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        let projection_sequence = writer
            .append_recognition_projection(projection, 30)
            .unwrap();
        assert_eq!(projection_sequence, 4);
        assert_eq!(writer.logical_revision(), 0);
        assert_eq!(writer.state.physical_samples, source_raw);
        assert_eq!(
            writer.state.physical_samples[0].sample.raw_payload,
            first.raw_payload
        );
        assert_eq!(
            writer.state.physical_samples[1].sample.raw_payload,
            second.raw_payload
        );

        writer
            .append_region_correction(
                region_correction_test_record(
                    "correction-empty",
                    "projection-1",
                    binding.clone(),
                    RegionCorrectionActionV1::SetText(String::new()),
                ),
                31,
            )
            .unwrap();
        writer
            .append_region_correction(
                region_correction_test_record(
                    "correction-reset",
                    "projection-1",
                    binding.clone(),
                    RegionCorrectionActionV1::Reset,
                ),
                32,
            )
            .unwrap();
        assert_eq!(writer.logical_revision(), 0);
        assert!(matches!(
            writer.state.region_corrections[0].correction.action,
            RegionCorrectionActionV1::SetText(ref text) if text.is_empty()
        ));
        assert_eq!(
            writer.state.region_corrections[1].correction.action,
            RegionCorrectionActionV1::Reset
        );
        assert_eq!(writer.state.recognition_projections.len(), 1);
        assert_eq!(writer.state.region_corrections.len(), 2);
        assert_eq!(writer.state.physical_samples, source_raw);
        writer.write_snapshot(&snapshot_path).unwrap();

        writer
            .append_region_correction(
                region_correction_test_record(
                    "correction-after-snapshot",
                    "projection-1",
                    binding,
                    RegionCorrectionActionV1::SetText("corrected".to_owned()),
                ),
                33,
            )
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reopened = read_journal(&path).unwrap();
        assert_eq!(reopened.state.recognition_projections.len(), 1);
        assert_eq!(reopened.state.region_corrections.len(), 3);
        assert_eq!(reopened.state.logical_revision, 0);
        assert_eq!(reopened.state.physical_samples, source_raw);
        assert_eq!(
            reopened.state.region_corrections[0].correction.action,
            RegionCorrectionActionV1::SetText(String::new())
        );
        let replay = load_with_snapshot(&path, &snapshot_path).unwrap();
        assert_eq!(replay.disposition, SnapshotDisposition::Used);
        assert_eq!(replay.replayed_tail_records, 1);
        assert_eq!(replay.state, reopened.state);
        cleanup_journal(&path);
    }

    #[test]
    fn stable_region_membership_does_not_transfer_corrections_between_projections() {
        let path = temp_path("stable-region-no-correction-transfer");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-stable-region-correction"))
                .unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-stable-region");
        let first_binding =
            projection_test_binding(&writer.state, &target, source_sequences.clone());
        let first_region_id = first_binding.region_id.clone();
        writer
            .append_recognition_projection(
                projection_test_record(
                    "projection-first-attempt",
                    first_binding.clone(),
                    source_sequences[0],
                    source_sequences[1],
                ),
                30,
            )
            .unwrap();
        writer
            .append_region_correction(
                region_correction_test_record(
                    "correction-first-attempt",
                    "projection-first-attempt",
                    first_binding.clone(),
                    RegionCorrectionActionV1::SetText("first projection only".to_owned()),
                ),
                31,
            )
            .unwrap();

        writer
            .apply_edit_action_record(
                32,
                EditCommand::Move {
                    target: target.clone(),
                    delta_x_raw: 7,
                    delta_y_raw: -3,
                    coordinate_space: "device-output".to_owned(),
                    units: "raw-units".to_owned(),
                },
            )
            .unwrap();
        let mut moved_binding =
            projection_test_binding(&writer.state, &target, source_sequences.clone());
        moved_binding.input_view_id = "input-view-v1-0000000000000002".to_owned();
        moved_binding.ink_binding_sha256 = "b".repeat(SHA256_HEX_BYTES);
        assert_eq!(moved_binding.region_id, first_region_id);
        writer
            .append_recognition_projection(
                projection_test_record(
                    "projection-second-attempt",
                    moved_binding.clone(),
                    source_sequences[0],
                    source_sequences[1],
                ),
                33,
            )
            .unwrap();
        assert_eq!(writer.state.recognition_projections.len(), 2);
        assert_eq!(writer.state.region_corrections.len(), 1);
        assert_eq!(
            writer.state.region_corrections[0].correction.projection_id,
            "projection-first-attempt"
        );
        assert_eq!(
            writer.state.recognition_projections[0]
                .projection
                .ink
                .region_id,
            writer.state.recognition_projections[1]
                .projection
                .ink
                .region_id
        );
        assert_ne!(
            writer.state.recognition_projections[0]
                .projection
                .projection_id,
            writer.state.recognition_projections[1]
                .projection
                .projection_id
        );
        writer.flush().unwrap();
        drop(writer);

        let reopened = read_journal(&path).unwrap();
        assert_eq!(reopened.state.region_corrections.len(), 1);
        assert_eq!(
            reopened.state.region_corrections[0]
                .correction
                .projection_id,
            "projection-first-attempt"
        );
        assert_eq!(reopened.state.recognition_projections.len(), 2);
        cleanup_journal(&path);
    }

    #[test]
    fn projection_roundtrip_preserves_unavailable_optional_model_and_resource_versions() {
        let path = temp_path("projection-missing-version");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-missing-version")).unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-missing-version");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        let mut projection = projection_test_record(
            "projection-missing-version",
            binding,
            source_sequences[0],
            source_sequences[1],
        );
        projection.provider.model_version = None;
        projection.provider.resource_version = None;
        writer
            .append_recognition_projection(projection, 30)
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let mut reopened = JournalWriter::open_append(path.clone()).unwrap();
        let stored = &reopened.state.recognition_projections[0]
            .projection
            .provider;
        assert_eq!(stored.model_version.as_deref(), None);
        assert_eq!(stored.resource_version.as_deref(), None);
        reopened.flush().unwrap();
        drop(reopened);
        let read_back = read_journal(&path).unwrap();
        assert_eq!(
            read_back.state.recognition_projections[0]
                .projection
                .provider
                .model_version
                .as_deref(),
            None
        );
        assert_eq!(
            read_back.state.recognition_projections[0]
                .projection
                .provider
                .resource_version
                .as_deref(),
            None
        );
        cleanup_journal(&path);
    }

    #[test]
    fn projection_generated_raster_origin_roundtrips_without_image_payloads() {
        let path = temp_path("projection-generated-raster-origin");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-generated-raster-origin")).unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-generated-raster");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        let mut projection = projection_test_record(
            "projection-generated-raster",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        projection.input_modalities = Some(vec![ProjectionInputModalityV1::Raster]);

        let mut wrong_source = projection_test_generated_raster(&binding);
        wrong_source.source.input_view_id = "input-view-v1-0000000000000002".to_owned();
        projection.generated_raster = Some(wrong_source);
        assert!(
            writer
                .append_recognition_projection(projection.clone(), 30)
                .is_err()
        );

        let mut wrong_spec = projection_test_generated_raster(&binding);
        wrong_spec.projection_spec.output_width_px = 9;
        projection.generated_raster = Some(wrong_spec);
        assert!(
            writer
                .append_recognition_projection(projection.clone(), 31)
                .is_err()
        );

        let mut wrong_dimensions = projection_test_generated_raster(&binding);
        wrong_dimensions.output_width_px = 9;
        projection.generated_raster = Some(wrong_dimensions);
        assert!(
            writer
                .append_recognition_projection(projection.clone(), 32)
                .is_err()
        );

        let mut wrong_hash = projection_test_generated_raster(&binding);
        wrong_hash.pixel_bytes_sha256 = "0".repeat(64);
        projection.generated_raster = Some(wrong_hash);
        assert!(
            writer
                .append_recognition_projection(projection.clone(), 33)
                .is_err()
        );
        assert!(writer.state.recognition_projections.is_empty());
        assert_eq!(writer.state.last_sequence, 3);

        projection.projection_id = "projection-generated-raster-valid".to_owned();
        projection.generated_raster = Some(projection_test_generated_raster(&binding));
        writer
            .append_recognition_projection(projection, 34)
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let persisted = read_journal(&path).unwrap();
        let stored = persisted.state.recognition_projections[0]
            .projection
            .generated_raster
            .as_ref()
            .unwrap();
        assert_eq!(
            stored.source,
            ProjectionRasterSourceBindingV1 {
                journal_id: binding.journal_id.clone(),
                logical_revision: binding.logical_revision,
                last_sequence: binding.last_sequence,
                region_id: binding.region_id.clone(),
                line_id: binding.line_id.clone(),
                input_view_id: binding.input_view_id.clone(),
                ink_binding_sha256: binding.ink_binding_sha256.clone(),
            }
        );
        let serialized = serde_json::to_string(stored).unwrap();
        assert!(!serialized.contains("raw_payload_hex"));
        assert!(!serialized.contains("\"png_bytes\""));
        assert!(!serialized.contains("\"pixel_bytes\""));
        cleanup_journal(&path);
    }

    #[test]
    fn projection_modality_validation_keeps_legacy_and_external_raster_origins_distinct() {
        let path = temp_path("projection-input-modalities");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-input-modalities")).unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-input-modalities");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());

        let mut empty_modalities = projection_test_record(
            "projection-empty-modalities",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        empty_modalities.input_modalities = Some(Vec::new());
        assert!(
            writer
                .append_recognition_projection(empty_modalities, 30)
                .is_err()
        );

        let mut duplicate_modalities = projection_test_record(
            "projection-duplicate-modalities",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        duplicate_modalities.input_modalities = Some(vec![
            ProjectionInputModalityV1::Raster,
            ProjectionInputModalityV1::Raster,
        ]);
        assert!(
            writer
                .append_recognition_projection(duplicate_modalities, 31)
                .is_err()
        );

        let mut over_cap_modalities = projection_test_record(
            "projection-over-cap-modalities",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        over_cap_modalities.input_modalities = Some(vec![
            ProjectionInputModalityV1::Raster,
            ProjectionInputModalityV1::Raster,
            ProjectionInputModalityV1::Raster,
        ]);
        assert!(
            writer
                .append_recognition_projection(over_cap_modalities, 32)
                .is_err()
        );

        let unknown_modality = projection_test_record(
            "projection-unknown-modality",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        let mut unknown_json = serde_json::to_value(unknown_modality).unwrap();
        unknown_json["input_modalities"] = serde_json::json!(["unknown"]);
        assert!(serde_json::from_value::<RecognitionProjectionV1>(unknown_json).is_err());

        let mut senocr_with_legacy_none = projection_test_record(
            "projection-senocr-legacy-none-write",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        senocr_with_legacy_none.provider.provider_id = LOCAL_SENOCR_RASTER_PROVIDER_ID.to_owned();
        assert!(
            writer
                .append_recognition_projection(senocr_with_legacy_none, 32)
                .is_err()
        );

        let mut senocr_without_origin = projection_test_record(
            "projection-senocr-without-origin",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        senocr_without_origin.provider.provider_id = LOCAL_SENOCR_RASTER_PROVIDER_ID.to_owned();
        senocr_without_origin.input_modalities = Some(vec![ProjectionInputModalityV1::Raster]);
        assert!(
            writer
                .append_recognition_projection(senocr_without_origin, 33)
                .is_err()
        );

        let mut origin_without_raster_mode = projection_test_record(
            "projection-origin-without-raster-mode",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        origin_without_raster_mode.generated_raster =
            Some(projection_test_generated_raster(&binding));
        assert!(
            writer
                .append_recognition_projection(origin_without_raster_mode, 34)
                .is_err()
        );
        assert!(writer.state.recognition_projections.is_empty());

        let mut external_raster_without_origin = projection_test_record(
            "projection-external-raster-no-origin",
            binding,
            source_sequences[0],
            source_sequences[1],
        );
        external_raster_without_origin.provider.provider_id = "external-raster-provider".to_owned();
        external_raster_without_origin.input_modalities =
            Some(vec![ProjectionInputModalityV1::Raster]);
        writer
            .append_recognition_projection(external_raster_without_origin, 35)
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reopened = read_journal(&path).unwrap();
        let projection = &reopened.state.recognition_projections[0].projection;
        assert_eq!(
            projection.input_modalities,
            Some(vec![ProjectionInputModalityV1::Raster])
        );
        assert!(projection.generated_raster.is_none());
        assert_eq!(projection.provider.provider_id, "external-raster-provider");
        cleanup_journal(&path);
    }

    #[test]
    fn legacy_senocr_projection_without_modalities_remains_readable() {
        let path = temp_path("legacy-senocr-projection-no-modalities");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-legacy-senocr-projection"))
                .unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-legacy-senocr");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        let mut projection = projection_test_record(
            "projection-legacy-senocr-none",
            binding,
            source_sequences[0],
            source_sequences[1],
        );
        projection.provider.provider_id = LOCAL_SENOCR_RASTER_PROVIDER_ID.to_owned();
        projection.input_modalities = None;
        projection.generated_raster = None;
        let sequence = writer.state.last_sequence + 1;
        let app_epoch_id = writer.state.current_session_id.clone();
        writer.flush().unwrap();
        drop(writer);

        let record = JournalRecord {
            sequence,
            app_epoch_id,
            event: JournalEvent::RecognitionProjection {
                app_arrival_elapsed_ns: 30,
                projection: Box::new(projection),
            },
        };
        let encoded =
            encode_row(&encode_record_fields(&record, JOURNAL_SCHEMA_VERSION).unwrap()).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&encoded).unwrap();
        drop(file);

        let parsed = read_journal(&path).unwrap();
        let stored = &parsed.state.recognition_projections[0].projection;
        assert_eq!(stored.provider.provider_id, LOCAL_SENOCR_RASTER_PROVIDER_ID);
        assert!(stored.input_modalities.is_none());
        assert!(stored.generated_raster.is_none());
        cleanup_journal(&path);
    }

    #[test]
    fn older_projection_json_defaults_missing_optional_raster_fields() {
        let binding = ProjectionInkBindingV1 {
            journal_id: "legacy-raster-projection".to_owned(),
            logical_revision: 1,
            last_sequence: 3,
            region_id: "region-legacy".to_owned(),
            line_id: Some("line-1".to_owned()),
            input_view_id: "input-view-v1-0000000000000001".to_owned(),
            ink_binding_sha256: "a".repeat(64),
            selected_strokes: vec![StrokeRef {
                journal_id: "legacy-raster-projection".to_owned(),
                session_id: "session-1".to_owned(),
                source_api: "direct-wm-pointer".to_owned(),
                device_id: Some("device-1".to_owned()),
                pointer_id: Some(1),
                stroke_id: "stroke-1".to_owned(),
            }],
            source_sample_sequences: vec![2],
            stroke_views: vec![ProjectionStrokeViewV1 {
                stroke: StrokeRef {
                    journal_id: "legacy-raster-projection".to_owned(),
                    session_id: "session-1".to_owned(),
                    source_api: "direct-wm-pointer".to_owned(),
                    device_id: Some("device-1".to_owned()),
                    pointer_id: Some(1),
                    stroke_id: "stroke-1".to_owned(),
                },
                frame: StrokeViewFrame::default(),
            }],
        };
        let projection = projection_test_record("legacy-projection", binding, 2, 2);
        let mut value = serde_json::to_value(projection).unwrap();
        value.as_object_mut().unwrap().remove("generated_raster");
        value.as_object_mut().unwrap().remove("input_modalities");
        let parsed: RecognitionProjectionV1 = serde_json::from_value(value).unwrap();
        assert!(parsed.generated_raster.is_none());
        assert!(parsed.input_modalities.is_none());
    }

    #[test]
    fn legacy_senocr_projection_row_without_modalities_remains_readable() {
        let path = temp_path("legacy-senocr-projection-row");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-legacy-senocr-projection-row"))
                .unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-legacy-senocr-row");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        let mut projection = projection_test_record(
            "projection-legacy-senocr-row",
            binding,
            source_sequences[0],
            source_sequences[1],
        );
        projection.provider.provider_id = LOCAL_SENOCR_RASTER_PROVIDER_ID.to_owned();
        projection.input_modalities = None;
        projection.generated_raster = None;
        let sequence = writer.state.last_sequence + 1;
        let app_epoch_id = writer.state.current_session_id.clone();
        writer.flush().unwrap();
        drop(writer);

        let record = JournalRecord {
            sequence,
            app_epoch_id,
            event: JournalEvent::RecognitionProjection {
                app_arrival_elapsed_ns: 30,
                projection: Box::new(projection),
            },
        };
        let row =
            encode_row(&encode_record_fields(&record, JOURNAL_SCHEMA_VERSION).unwrap()).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&row).unwrap();
        drop(file);

        let parsed = read_journal(&path).unwrap();
        let projection = &parsed.state.recognition_projections[0].projection;
        assert_eq!(
            projection.provider.provider_id,
            LOCAL_SENOCR_RASTER_PROVIDER_ID
        );
        assert!(projection.input_modalities.is_none());
        assert!(projection.generated_raster.is_none());
        cleanup_journal(&path);
    }

    #[test]
    fn projection_and_correction_allow_unrelated_appends_without_rebinding_source() {
        let path = temp_path("projection-unrelated-appends");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-unrelated-appends")).unwrap();
        let (target, source_sequences, _frame, first, second) =
            append_projection_test_stroke(&mut writer, "stroke-frozen");
        let source_raw = writer.state.physical_samples.clone();
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());

        let mut hover = sample("direct-wm-pointer", "ignored-hover", 1, 25, None, false, 90);
        hover.stroke_id = None;
        hover.source_device_id = None;
        hover.pointer_id = None;
        writer.append_sample(hover.clone()).unwrap();
        writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Session,
                scope_id: "session-1".to_owned(),
                source_api: None,
                device_id: None,
                key: "unrelated-observation".to_owned(),
                value: "after-frozen-request".to_owned(),
                provenance: "test-observation".to_owned(),
                app_arrival_elapsed_ns: 26,
            })
            .unwrap();

        let projection = projection_test_record(
            "projection-with-unrelated-tail",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        writer
            .append_recognition_projection(projection, 30)
            .unwrap();
        assert_eq!(
            writer.state.recognition_projections[0]
                .projection
                .ink
                .last_sequence,
            3
        );

        let mut later_hover = sample(
            "direct-wm-pointer",
            "ignored-hover-2",
            2,
            35,
            None,
            false,
            91,
        );
        later_hover.stroke_id = None;
        later_hover.source_device_id = None;
        later_hover.pointer_id = None;
        writer.append_sample(later_hover.clone()).unwrap();
        writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Session,
                scope_id: "session-1".to_owned(),
                source_api: None,
                device_id: None,
                key: "another-unrelated-observation".to_owned(),
                value: "still-after-frozen-request".to_owned(),
                provenance: "test-observation".to_owned(),
                app_arrival_elapsed_ns: 36,
            })
            .unwrap();
        writer
            .append_region_correction(
                region_correction_test_record(
                    "correction-after-unrelated-tail",
                    "projection-with-unrelated-tail",
                    binding.clone(),
                    RegionCorrectionActionV1::SetText("user annotation".to_owned()),
                ),
                40,
            )
            .unwrap();

        assert_eq!(writer.logical_revision(), 0);
        assert_eq!(
            writer.state.recognition_projections[0].projection.ink,
            binding
        );
        assert_eq!(
            writer.state.region_corrections[0]
                .correction
                .ink
                .last_sequence,
            3
        );
        assert_eq!(writer.state.physical_samples[0].sample, first);
        assert_eq!(writer.state.physical_samples[1].sample, second);
        assert_eq!(writer.state.physical_samples[2].sample, hover);
        assert_eq!(writer.state.physical_samples[3].sample, later_hover);
        assert_eq!(writer.state.metadata_history.len(), 2);
        assert_eq!(&writer.state.physical_samples[..2], source_raw.as_slice());
        writer.flush().unwrap();
        drop(writer);

        let reopened = read_journal(&path).unwrap();
        assert_eq!(reopened.state.recognition_projections.len(), 1);
        assert_eq!(reopened.state.region_corrections.len(), 1);
        assert_eq!(reopened.state.logical_revision, 0);
        assert_eq!(
            reopened.state.recognition_projections[0]
                .projection
                .ink
                .last_sequence,
            3
        );
        cleanup_journal(&path);
    }

    #[test]
    fn projection_rejects_a_logical_edit_after_its_frozen_source_prefix() {
        let path = temp_path("projection-logical-edit-stale");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-logical-edit-stale")).unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-edited");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        writer
            .begin_revision(30, "a later logical edit".to_owned())
            .unwrap();
        let error = writer
            .append_recognition_projection(
                projection_test_record(
                    "projection-after-edit",
                    binding,
                    source_sequences[0],
                    source_sequences[1],
                ),
                31,
            )
            .unwrap_err();
        assert_eq!(error.kind, JournalErrorKind::InvalidData);
        assert_eq!(writer.state.logical_revision, 1);
        assert!(writer.state.recognition_projections.is_empty());
        writer.flush().unwrap();
        drop(writer);
        cleanup_journal(&path);
    }

    #[test]
    fn stale_projection_history_survives_snapshot_but_cannot_receive_new_correction() {
        let path = temp_path("stale-projection-history");
        let snapshot_path = default_snapshot_path(&path);
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-stale-projection-history"))
                .unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-later-edited");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        writer
            .append_recognition_projection(
                projection_test_record(
                    "projection-before-later-ink",
                    binding.clone(),
                    source_sequences[0],
                    source_sequences[1],
                ),
                30,
            )
            .unwrap();
        writer
            .append_region_correction(
                region_correction_test_record(
                    "correction-before-later-ink",
                    "projection-before-later-ink",
                    binding.clone(),
                    RegionCorrectionActionV1::SetText("historic annotation".to_owned()),
                ),
                31,
            )
            .unwrap();
        let later_sample = sample(
            "direct-wm-pointer",
            "stroke-later-edited",
            3,
            40,
            Some(300),
            true,
            30,
        );
        writer.append_sample(later_sample).unwrap();
        writer.write_snapshot(&snapshot_path).unwrap();
        writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Session,
                scope_id: "session-1".to_owned(),
                source_api: None,
                device_id: None,
                key: "post-stale-snapshot-tail".to_owned(),
                value: "retained".to_owned(),
                provenance: "stale-history-test".to_owned(),
                app_arrival_elapsed_ns: 45,
            })
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let full = read_journal(&path).unwrap();
        let snapshot_replay = load_with_snapshot(&path, &snapshot_path).unwrap();
        assert_eq!(snapshot_replay.disposition, SnapshotDisposition::Used);
        assert_eq!(snapshot_replay.replayed_tail_records, 1);
        assert_eq!(snapshot_replay.state, full.state);
        assert_eq!(snapshot_replay.state.recognition_projections.len(), 1);
        assert_eq!(snapshot_replay.state.region_corrections.len(), 1);
        assert_eq!(snapshot_replay.state.logical_revision, 0);

        let mut reopened = JournalWriter::open_append(path.clone()).unwrap();
        let stale_projection = reopened
            .append_recognition_projection(
                projection_test_record(
                    "auto-carried-stale-projection",
                    binding.clone(),
                    source_sequences[0],
                    source_sequences[1],
                ),
                40,
            )
            .unwrap_err();
        assert_eq!(stale_projection.kind, JournalErrorKind::InvalidData);
        assert_eq!(reopened.state.recognition_projections.len(), 1);
        let stale_correction = reopened
            .append_region_correction(
                region_correction_test_record(
                    "correction-after-later-ink",
                    "projection-before-later-ink",
                    binding,
                    RegionCorrectionActionV1::SetText("must not carry forward".to_owned()),
                ),
                41,
            )
            .unwrap_err();
        assert_eq!(stale_correction.kind, JournalErrorKind::InvalidData);
        assert_eq!(reopened.state.region_corrections.len(), 1);
        assert_eq!(reopened.state.recognition_projections.len(), 1);
        reopened.flush().unwrap();
        drop(reopened);
        cleanup_journal(&path);
    }

    #[test]
    fn derived_correction_rejects_project_mismatch_and_new_ink_without_self_staling() {
        let path = temp_path("projection-stale-binding");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-stale-binding")).unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-stale");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        writer
            .append_recognition_projection(
                projection_test_record(
                    "projection-stale",
                    binding.clone(),
                    source_sequences[0],
                    source_sequences[1],
                ),
                30,
            )
            .unwrap();

        let mut other_project = binding.clone();
        other_project.journal_id = "different-project".to_owned();
        assert!(
            writer
                .append_region_correction(
                    region_correction_test_record(
                        "wrong-project-correction",
                        "projection-stale",
                        other_project,
                        RegionCorrectionActionV1::Reset,
                    ),
                    31,
                )
                .is_err()
        );
        assert_eq!(writer.state.region_corrections.len(), 0);

        let mut changed_view = binding.clone();
        changed_view.input_view_id = "input-view-v1-0000000000000002".to_owned();
        assert!(
            writer
                .append_region_correction(
                    region_correction_test_record(
                        "wrong-view-correction",
                        "projection-stale",
                        changed_view,
                        RegionCorrectionActionV1::Reset,
                    ),
                    32,
                )
                .is_err()
        );
        assert_eq!(writer.state.region_corrections.len(), 0);

        let extra = sample(
            "direct-wm-pointer",
            "stroke-stale",
            3,
            40,
            Some(300),
            true,
            30,
        );
        writer.append_sample(extra).unwrap();
        let stale_error = writer
            .append_region_correction(
                region_correction_test_record(
                    "stale-correction",
                    "projection-stale",
                    binding,
                    RegionCorrectionActionV1::SetText("stale".to_owned()),
                ),
                41,
            )
            .unwrap_err();
        assert_eq!(stale_error.kind, JournalErrorKind::InvalidData);
        assert_eq!(writer.state.region_corrections.len(), 0);
        assert_eq!(writer.logical_revision(), 0);
        writer.flush().unwrap();
        drop(writer);
        let parsed = read_journal(&path).unwrap();
        assert_eq!(parsed.state.physical_samples.len(), 3);
        assert_eq!(parsed.state.recognition_projections.len(), 1);
        assert_eq!(parsed.state.region_corrections.len(), 0);
        cleanup_journal(&path);
    }

    #[test]
    fn projection_payload_limits_and_truncated_rows_do_not_create_fake_success() {
        let path = temp_path("projection-malformed-row");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-malformed-row")).unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-malformed");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        let mut oversized = projection_test_record(
            "projection-too-long",
            binding.clone(),
            source_sequences[0],
            source_sequences[1],
        );
        oversized.candidates[0].recognized_text = "x".repeat(MAX_JOURNAL_TEXT_BYTES + 1);
        let before_sequence = writer.state.last_sequence;
        assert!(writer.append_recognition_projection(oversized, 30).is_err());
        assert_eq!(writer.state.last_sequence, before_sequence);
        assert!(writer.state.recognition_projections.is_empty());

        let valid = projection_test_record(
            "projection-valid",
            binding,
            source_sequences[0],
            source_sequences[1],
        );
        writer.append_recognition_projection(valid, 31).unwrap();
        writer.flush().unwrap();
        drop(writer);

        rewrite_record_field(&path, "RPROJ", 4, &encode_field("not-json"));
        assert!(read_journal(&path).is_err());
        cleanup_journal(&path);

        let truncated_path = temp_path("projection-truncated-row");
        let mut writer =
            JournalWriter::create(truncated_path.clone(), header("journal-truncated-row")).unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-truncated");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        writer.flush().unwrap();
        drop(writer);
        let mut bytes = fs::read(&truncated_path).unwrap();
        let projection = projection_test_record(
            "projection-truncated",
            binding,
            source_sequences[0],
            source_sequences[1],
        );
        let record = JournalRecord {
            sequence: 4,
            app_epoch_id: "session-1".to_owned(),
            event: JournalEvent::RecognitionProjection {
                app_arrival_elapsed_ns: 50,
                projection: Box::new(projection),
            },
        };
        let line =
            encode_row(&encode_record_fields(&record, JOURNAL_SCHEMA_VERSION).unwrap()).unwrap();
        bytes.extend_from_slice(&line[..line.len() - 1]);
        fs::write(&truncated_path, bytes).unwrap();
        let recovered = read_journal(&truncated_path).unwrap();
        assert!(recovered.recovery.truncated_final_record);
        assert!(recovered.state.recognition_projections.is_empty());
        assert_eq!(recovered.state.last_sequence, 3);
        cleanup_journal(&truncated_path);
    }

    #[test]
    fn recognition_projection_sync_failure_poisons_writer_and_reopen_replays_disk_state() {
        let path = temp_path("projection-sync-failure");
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-projection-sync-failure")).unwrap();
        let (target, source_sequences, _frame, _first, _second) =
            append_projection_test_stroke(&mut writer, "stroke-sync-failure");
        let binding = projection_test_binding(&writer.state, &target, source_sequences.clone());
        let projection = projection_test_record(
            "projection-sync-failure",
            binding,
            source_sequences[0],
            source_sequences[1],
        );
        writer.fail_next_sync_after_write = true;
        let error = writer
            .append_recognition_projection(projection, 30)
            .unwrap_err();
        assert_eq!(error.kind, JournalErrorKind::Io);
        assert!(writer.is_poisoned());
        assert!(writer.state.recognition_projections.is_empty());
        assert_eq!(
            writer
                .append_metadata(JournalMetadata {
                    scope: MetadataScope::Session,
                    scope_id: "session-1".to_owned(),
                    source_api: None,
                    device_id: None,
                    key: "after-poison".to_owned(),
                    value: "must-reopen".to_owned(),
                    provenance: "test".to_owned(),
                    app_arrival_elapsed_ns: 31,
                })
                .unwrap_err()
                .kind,
            JournalErrorKind::Poisoned
        );
        drop(writer);

        let replayed = read_journal(&path).unwrap();
        assert_eq!(replayed.state.recognition_projections.len(), 1);
        assert_eq!(
            replayed.state.recognition_projections[0]
                .projection
                .projection_id,
            "projection-sync-failure"
        );
        let reopened = JournalWriter::open_append(path.clone()).unwrap();
        assert_eq!(reopened.state.recognition_projections.len(), 1);
        drop(reopened);
        cleanup_journal(&path);
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
        drop(writer);

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
        let target = target_of(&original, "journal-logical");
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
        drop(writer);

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
    fn resumed_epoch_and_identity_scoped_targets_do_not_merge_colliding_strokes() {
        let path = temp_path("resume-epoch");
        let journal_header = header("journal-resume-epoch");
        let mut writer = JournalWriter::create(path.clone(), journal_header.clone()).unwrap();
        let first = sample(
            "direct-wm-pointer",
            "same-label",
            1,
            100,
            Some(900),
            true,
            10,
        );
        let old_target = target_of(&first, &journal_header.journal_id);
        writer.append_sample(first.clone()).unwrap();

        writer
            .begin_session_epoch(
                "session-2".to_owned(),
                1_800_000_000_000_000_000,
                Some("cfg-b".to_owned()),
                "resumed-process-new-Instant-origin".to_owned(),
            )
            .unwrap();
        let mut second = sample("direct-wm-pointer", "same-label", 1, 5, Some(10), true, 20);
        second.session_id = "session-2".to_owned();
        second.config_id = Some("cfg-b".to_owned());
        let new_target = target_of(&second, &journal_header.journal_id);
        assert_ne!(old_target, new_target);
        writer
            .start_stroke(new_target.clone(), StrokeViewFrame::default(), 4)
            .unwrap();
        writer.append_sample(second.clone()).unwrap();
        writer.commit_stroke(new_target.clone(), 6).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let parsed = read_journal(&path).unwrap();
        assert_eq!(parsed.state.session_epochs.len(), 2);
        assert_eq!(parsed.state.current_session_id, "session-2");
        assert_eq!(parsed.state.physical_samples.len(), 2);
        assert_eq!(parsed.state.physical_samples[0].sample, first);
        assert_eq!(parsed.state.physical_samples[1].sample, second);
        assert_eq!(parsed.state.stroke_domains.len(), 2);
        let visible = parsed.state.projected_samples().unwrap();
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].stroke_ref.as_ref(), Some(&old_target));
        assert_eq!(visible[1].stroke_ref.as_ref(), Some(&new_target));
        cleanup_journal(&path);
    }

    #[test]
    fn committed_stroke_visibility_undo_redo_survives_project_reopen() {
        let path = temp_path("stroke-commit-undo-redo");
        let journal_header = header("journal-stroke-commit-undo-redo");
        let mut writer = JournalWriter::create(path.clone(), journal_header.clone()).unwrap();
        writer
            .append_sample(sample(
                "direct-wm-pointer",
                "legacy-visible",
                1,
                10,
                Some(10),
                true,
                10,
            ))
            .unwrap();
        writer
            .begin_session_epoch(
                "session-2".to_owned(),
                1_800_000_004_000_000_000,
                Some("cfg-b".to_owned()),
                "commit-undo-reopen".to_owned(),
            )
            .unwrap();
        let mut live_sample = sample("direct-wm-pointer", "new-stroke", 1, 1, Some(20), true, 30);
        live_sample.session_id = "session-2".to_owned();
        live_sample.config_id = Some("cfg-b".to_owned());
        let target = target_of(&live_sample, &journal_header.journal_id);
        writer
            .start_stroke(target.clone(), StrokeViewFrame::default(), 1)
            .unwrap();
        writer.append_sample(live_sample).unwrap();
        let commit_action_id = writer.commit_stroke(target.clone(), 2).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let mut reopened = JournalWriter::open_append(path.clone()).unwrap();
        assert_eq!(reopened.state.projected_samples().unwrap().len(), 2);
        assert_eq!(reopened.undo_last_edit(3).unwrap(), commit_action_id);
        assert_eq!(reopened.state.projected_samples().unwrap().len(), 1);
        assert_eq!(reopened.redo_last_edit(4).unwrap(), commit_action_id);
        assert_eq!(reopened.state.projected_samples().unwrap().len(), 2);
        reopened
            .apply_edit_action(
                5,
                EditCommand::Tombstone {
                    targets: vec![target.clone()],
                },
            )
            .unwrap();
        assert_eq!(reopened.state.projected_samples().unwrap().len(), 1);
        reopened
            .apply_edit_action(
                6,
                EditCommand::Restore {
                    targets: vec![target],
                },
            )
            .unwrap();
        assert_eq!(reopened.state.projected_samples().unwrap().len(), 2);
        reopened.flush().unwrap();
        drop(reopened);

        let replayed = read_journal(&path).unwrap();
        assert_eq!(replayed.state.projected_samples().unwrap().len(), 2);
        assert_eq!(replayed.state.physical_samples.len(), 2);
        assert_eq!(replayed.state.edit_actions.len(), 3);
        assert!(replayed.state.edit_actions[0].active);
        assert_eq!(replayed.state.edit_controls.len(), 2);
        cleanup_journal(&path);
    }

    #[test]
    fn new_epoch_stroke_without_commit_stays_incomplete_and_loss_never_commits() {
        let path = temp_path("stroke-lifecycle-incomplete");
        let journal_header = header("journal-stroke-lifecycle-incomplete");
        let mut writer = JournalWriter::create(path.clone(), journal_header.clone()).unwrap();
        writer
            .append_sample(sample(
                "direct-wm-pointer",
                "legacy-unmarked",
                1,
                10,
                Some(1),
                true,
                1,
            ))
            .unwrap();
        assert_eq!(writer.state.projected_samples().unwrap().len(), 1);

        writer
            .begin_session_epoch(
                "session-2".to_owned(),
                1_800_000_003_000_000_000,
                Some("cfg-b".to_owned()),
                "new capture epoch".to_owned(),
            )
            .unwrap();
        let mut in_progress = sample("direct-wm-pointer", "in-progress", 1, 1, Some(2), true, 2);
        in_progress.session_id = "session-2".to_owned();
        in_progress.config_id = Some("cfg-b".to_owned());
        let unstarted_error = writer.append_sample(in_progress.clone()).unwrap_err();
        assert_eq!(unstarted_error.kind, JournalErrorKind::InvalidData);
        assert_eq!(writer.state.physical_samples.len(), 1);

        let target = target_of(&in_progress, &journal_header.journal_id);
        writer
            .start_stroke(target.clone(), StrokeViewFrame::default(), 1)
            .unwrap();
        writer.append_sample(in_progress).unwrap();
        assert_eq!(writer.state.active_strokes.len(), 1);
        assert_eq!(writer.state.incomplete_stroke_count(), 1);
        assert_eq!(writer.state.projected_samples().unwrap().len(), 1);
        writer.flush().unwrap();
        drop(writer);

        let recovered = read_journal(&path).unwrap();
        assert_eq!(recovered.state.active_strokes.len(), 1);
        assert_eq!(recovered.state.physical_samples.len(), 2);
        assert_eq!(recovered.state.projected_samples().unwrap().len(), 1);

        let mut writer = JournalWriter::open_append(path.clone()).unwrap();
        writer
            .begin_session_epoch(
                "session-3".to_owned(),
                1_800_000_005_000_000_000,
                Some("cfg-c".to_owned()),
                "second-process-resume".to_owned(),
            )
            .unwrap();
        let mut capture_lost = sample("direct-wm-pointer", "capture-lost", 1, 1, Some(3), true, 3);
        capture_lost.session_id = "session-3".to_owned();
        capture_lost.config_id = Some("cfg-c".to_owned());
        let lost_target = target_of(&capture_lost, &journal_header.journal_id);
        writer
            .start_stroke(lost_target.clone(), StrokeViewFrame::default(), 1)
            .unwrap();
        writer.append_sample(capture_lost).unwrap();
        writer
            .interrupt_stroke(
                lost_target.clone(),
                StrokeInterruptionReason::PointerCaptureChanged,
                2,
            )
            .unwrap();
        let restore_error = writer
            .apply_edit_action(
                3,
                EditCommand::Restore {
                    targets: vec![lost_target],
                },
            )
            .unwrap_err();
        assert_eq!(restore_error.kind, JournalErrorKind::InvalidData);
        assert_eq!(writer.state.edit_actions.len(), 0);
        writer.flush().unwrap();
        drop(writer);
        let interrupted = read_journal(&path).unwrap();
        assert!(interrupted.state.active_strokes.is_empty());
        assert_eq!(interrupted.state.stroke_interruptions.len(), 2);
        assert_eq!(interrupted.state.edit_actions.len(), 0);
        assert_eq!(interrupted.state.physical_samples.len(), 3);
        assert_eq!(interrupted.state.projected_samples().unwrap().len(), 1);
        assert!(matches!(
            interrupted.records.last().unwrap().event,
            JournalEvent::StrokeInterrupted {
                reason: StrokeInterruptionReason::PointerCaptureChanged,
                ..
            }
        ));
        assert_eq!(
            interrupted.state.stroke_interruptions[0].reason,
            StrokeInterruptionReason::ProcessEndedWithoutPenUp
        );
        assert_eq!(
            interrupted.state.stroke_interruptions[1].reason,
            StrokeInterruptionReason::PointerCaptureChanged
        );
        cleanup_journal(&path);
    }

    #[test]
    fn erase_undo_redo_restore_is_append_only_and_targets_the_old_epoch() {
        let path = temp_path("undo-redo-epochs");
        let journal_header = header("journal-undo-redo-epochs");
        let snapshot_path = default_snapshot_path(&path);
        let mut writer = JournalWriter::create(path.clone(), journal_header.clone()).unwrap();
        let old_sample = sample(
            "direct-wm-pointer",
            "collision",
            1,
            100,
            Some(100),
            true,
            10,
        );
        let old_target = target_of(&old_sample, &journal_header.journal_id);
        writer.append_sample(old_sample.clone()).unwrap();
        writer
            .begin_session_epoch(
                "session-2".to_owned(),
                1_800_000_001_000_000_000,
                Some("cfg-b".to_owned()),
                "resumed-process".to_owned(),
            )
            .unwrap();
        let mut new_sample = sample("direct-wm-pointer", "collision", 1, 1, Some(1), true, 50);
        new_sample.session_id = "session-2".to_owned();
        new_sample.config_id = Some("cfg-b".to_owned());
        let new_target = target_of(&new_sample, &journal_header.journal_id);
        writer
            .start_stroke(new_target.clone(), StrokeViewFrame::default(), 1)
            .unwrap();
        writer.append_sample(new_sample.clone()).unwrap();
        writer.commit_stroke(new_target.clone(), 2).unwrap();
        assert_ne!(old_target, new_target);
        writer.write_snapshot(&snapshot_path).unwrap();

        let action_id = writer
            .apply_edit_action(
                2,
                EditCommand::Tombstone {
                    targets: vec![old_target.clone()],
                },
            )
            .unwrap();
        assert_eq!(writer.state.projected_samples().unwrap().len(), 1);
        assert_eq!(writer.undo_last_edit(3).unwrap(), action_id);
        assert_eq!(writer.state.projected_samples().unwrap().len(), 2);
        assert_eq!(writer.redo_last_edit(4).unwrap(), action_id);
        assert_eq!(writer.state.projected_samples().unwrap().len(), 1);

        let restore_id = writer
            .apply_edit_action(
                5,
                EditCommand::Restore {
                    targets: vec![old_target.clone()],
                },
            )
            .unwrap();
        assert_ne!(restore_id, action_id);
        assert_eq!(writer.state.projected_samples().unwrap().len(), 2);
        assert_eq!(writer.undo_last_edit(6).unwrap(), restore_id);
        assert_eq!(writer.state.projected_samples().unwrap().len(), 1);
        assert_eq!(writer.redo_last_edit(7).unwrap(), restore_id);
        assert_eq!(writer.state.projected_samples().unwrap().len(), 2);
        writer.flush().unwrap();
        drop(writer);

        let full = read_journal(&path).unwrap();
        let snapshot = load_with_snapshot(&path, &snapshot_path).unwrap();
        assert_eq!(snapshot.disposition, SnapshotDisposition::Used);
        assert_eq!(snapshot.state, full.state);
        assert_eq!(full.state.physical_samples.len(), 2);
        assert_eq!(full.state.edit_actions.len(), 3);
        assert_eq!(full.state.edit_controls.len(), 4);
        assert!(full.state.edit_actions.iter().all(|action| action.active));
        assert_eq!(full.state.logical_revision, 7);
        assert_eq!(
            full.state
                .physical_samples
                .iter()
                .map(|stored| stored.sample.session_id.as_str())
                .collect::<Vec<_>>(),
            ["session-1", "session-2"]
        );
        cleanup_journal(&path);
    }

    #[test]
    fn snapshot_round_trips_mixed_edit_actions_and_undo_redo_stacks_with_tail() {
        let path = temp_path("snapshot-edit-state");
        let snapshot_path = default_snapshot_path(&path);
        let journal_header = header("journal-snapshot-edit-state");
        let mut writer = JournalWriter::create(path.clone(), journal_header.clone()).unwrap();

        let old_sample = sample("direct-wm-pointer", "collision", 1, 100, Some(10), true, 10);
        let old_target = target_of(&old_sample, &journal_header.journal_id);
        writer.append_sample(old_sample).unwrap();
        writer
            .begin_session_epoch(
                "session-2".to_owned(),
                1_800_000_002_000_000_000,
                Some("cfg-b".to_owned()),
                "snapshot-test-resume".to_owned(),
            )
            .unwrap();
        let mut new_sample = sample("direct-wm-pointer", "collision", 1, 1, Some(1), true, 30);
        new_sample.session_id = "session-2".to_owned();
        new_sample.config_id = Some("cfg-b".to_owned());
        let new_target = target_of(&new_sample, &journal_header.journal_id);
        writer
            .start_stroke(new_target.clone(), StrokeViewFrame::default(), 1)
            .unwrap();
        writer.append_sample(new_sample).unwrap();
        let commit_new = writer.commit_stroke(new_target.clone(), 1).unwrap();
        assert_ne!(old_target, new_target);

        let hide_old = writer
            .apply_edit_action(
                2,
                EditCommand::Tombstone {
                    targets: vec![old_target.clone()],
                },
            )
            .unwrap();
        let hide_new = writer
            .apply_edit_action(
                3,
                EditCommand::Tombstone {
                    targets: vec![new_target],
                },
            )
            .unwrap();
        let restore_old = writer
            .apply_edit_action(
                4,
                EditCommand::Restore {
                    targets: vec![old_target.clone()],
                },
            )
            .unwrap();
        writer.undo_last_edit(5).unwrap();
        writer.undo_last_edit(6).unwrap();
        assert_eq!(writer.state.undo_stack, [commit_new, hide_old]);
        assert_eq!(writer.state.redo_stack, [restore_old, hide_new]);
        assert_eq!(
            writer
                .state
                .edit_actions
                .iter()
                .map(|action| action.active)
                .collect::<Vec<_>>(),
            [true, true, false, false]
        );
        writer.write_snapshot(&snapshot_path).unwrap();

        assert_eq!(writer.redo_last_edit(7).unwrap(), hide_new);
        let restore_after_snapshot = writer
            .apply_edit_action(
                8,
                EditCommand::Restore {
                    targets: vec![old_target],
                },
            )
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let full = read_journal(&path).unwrap();
        let restored = load_with_snapshot(&path, &snapshot_path).unwrap();
        assert_eq!(restored.disposition, SnapshotDisposition::Used);
        assert_eq!(restored.replayed_tail_records, 2);
        assert_eq!(restored.state, full.state);
        assert_eq!(full.state.session_epochs.len(), 2);
        assert_eq!(full.state.edit_actions.len(), 5);
        assert_eq!(full.state.edit_controls.len(), 3);
        assert_eq!(
            full.state.undo_stack,
            [commit_new, hide_old, hide_new, restore_after_snapshot]
        );
        assert!(full.state.redo_stack.is_empty());
        assert_eq!(
            full.state
                .edit_actions
                .iter()
                .map(|action| action.active)
                .collect::<Vec<_>>(),
            [true, true, true, false, true]
        );
        assert_eq!(full.state.projected_samples().unwrap().len(), 1);
        cleanup_journal(&path);
    }

    #[test]
    fn legacy_and_schema_three_moves_share_checked_projection_accumulation_order() {
        let path = temp_path("move-accumulation-order");
        let snapshot_path = default_snapshot_path(&path);
        let journal_header = header("journal-move-accumulation-order");
        let mut writer = JournalWriter::create(path.clone(), journal_header.clone()).unwrap();
        let original = sample("direct-wm-pointer", "stroke-a", 1, 10, Some(5), true, 0);
        let target = target_of(&original, &journal_header.journal_id);
        writer.append_sample(original.clone()).unwrap();
        writer
            .begin_revision(11, "legacy adjustment".to_owned())
            .unwrap();
        writer
            .move_stroke(
                12,
                target.clone(),
                -1,
                0,
                "device-output".to_owned(),
                "raw-units".to_owned(),
            )
            .unwrap();
        assert_eq!(
            writer.state.projected_samples().unwrap()[0]
                .effective_position
                .as_ref()
                .unwrap()
                .x_raw,
            -1
        );

        writer
            .apply_edit_action(
                13,
                EditCommand::Move {
                    target: target.clone(),
                    delta_x_raw: i64::MAX,
                    delta_y_raw: 0,
                    coordinate_space: "device-output".to_owned(),
                    units: "raw-units".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(
            writer.state.projected_samples().unwrap()[0]
                .effective_position
                .as_ref()
                .unwrap()
                .x_raw,
            i64::MAX - 1
        );
        writer.write_snapshot(&snapshot_path).unwrap();

        writer
            .apply_edit_action(
                14,
                EditCommand::Move {
                    target,
                    delta_x_raw: 1,
                    delta_y_raw: 0,
                    coordinate_space: "device-output".to_owned(),
                    units: "raw-units".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(
            writer.state.projected_samples().unwrap()[0]
                .effective_position
                .as_ref()
                .unwrap()
                .x_raw,
            i64::MAX
        );
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
            i64::MAX
        );
        assert_eq!(
            full.state.physical_samples[0]
                .sample
                .position
                .as_ref()
                .unwrap()
                .x_raw,
            0,
            "movement is a derived view and leaves raw physical coordinates unchanged"
        );
        cleanup_journal(&path);
    }

    #[test]
    fn interrupted_multi_stroke_action_is_not_partially_visible() {
        let path = temp_path("interrupted-edit");
        let journal_header = header("journal-interrupted-edit");
        let mut writer = JournalWriter::create(path.clone(), journal_header.clone()).unwrap();
        let first = sample("direct-wm-pointer", "first", 1, 10, Some(1), true, 1);
        let second = sample("direct-wm-pointer", "second", 2, 20, Some(2), true, 2);
        let first_target = target_of(&first, &journal_header.journal_id);
        let second_target = target_of(&second, &journal_header.journal_id);
        writer.append_sample(first).unwrap();
        writer.append_sample(second).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let mut torn = OpenOptions::new().append(true).open(&path).unwrap();
        torn.write_all(b"ACT\t3\tapp-epoch\t1\t30\t3\thide\t2\t")
            .unwrap();
        drop(torn);
        let before_recovery = read_journal(&path).unwrap();
        assert!(before_recovery.recovery.truncated_final_record);
        assert_eq!(before_recovery.state.physical_samples.len(), 2);
        assert_eq!(before_recovery.state.projected_samples().unwrap().len(), 2);
        assert!(before_recovery.state.edit_actions.is_empty());

        let mut recovered = JournalWriter::open_append(path.clone()).unwrap();
        assert!(recovered.recovered_truncated_final_record());
        assert_eq!(recovered.state.projected_samples().unwrap().len(), 2);
        recovered
            .apply_edit_action(
                30,
                EditCommand::Tombstone {
                    targets: vec![first_target, second_target],
                },
            )
            .unwrap();
        assert!(recovered.state.projected_samples().unwrap().is_empty());
        drop(recovered);

        let after = read_journal(&path).unwrap();
        assert_eq!(after.state.physical_samples.len(), 2);
        assert_eq!(after.state.edit_actions.len(), 1);
        assert_eq!(after.state.projected_samples().unwrap().len(), 0);
        cleanup_journal(&path);
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
                    journal_id: "journal-partition".to_owned(),
                    session_id: "session-1".to_owned(),
                    source_api: "direct-wm-pointer".to_owned(),
                    device_id: Some("device-a".to_owned()),
                    pointer_id: Some(7),
                    stroke_id: "shared-label".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(rev, 1);
        drop(writer);
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
    fn complete_short_header_and_event_rows_return_invalid_data() {
        let short_header_path = temp_path("short-header");
        fs::write(&short_header_path, b"LASSOINK-JOURNAL\n").unwrap();
        let error = read_journal(&short_header_path).unwrap_err();
        assert_eq!(error.kind, JournalErrorKind::InvalidData);
        let error = parse_journal(std::io::Cursor::new(b"LASSOINK-JOURNAL\n")).unwrap_err();
        assert_eq!(error.kind, JournalErrorKind::InvalidData);
        fs::remove_file(short_header_path).unwrap();

        let header_line = encode_row(&encode_header_fields(
            &header("short-event-header"),
            JOURNAL_SCHEMA_VERSION,
        ))
        .unwrap();
        for malformed_row in ["P", "META", "REV", "TOMB", "MOVE", "CORR"] {
            let mut input = header_line.clone();
            input.extend_from_slice(format!("{malformed_row}\n").as_bytes());
            let error = parse_journal(std::io::Cursor::new(input)).unwrap_err();
            assert_eq!(
                error.kind,
                JournalErrorKind::InvalidData,
                "row tag {malformed_row} must reject its short complete row"
            );
        }
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
    fn schema_one_migration_preserves_identity_raw_history_and_source_bytes() {
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

        let result = migrate_schema_one_to_four(&source_path, destination_path.clone()).unwrap();
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
        assert_eq!(migrated.header.journal_id, "legacy-migration-id");
        assert_eq!(result.source_journal_id, result.destination_journal_id);
        assert_eq!(migrated.records[0].app_epoch_id, "session-1");
        assert_eq!(migrated.header.config_id, Some("cfg-a".to_owned()));
        assert_eq!(
            migrated.header.device_model_declared,
            Some("owner-declared device".to_owned())
        );
        assert_eq!(migrated.header.tilt_supported_declared, None);
        assert_eq!(sample.source_sequence, legacy_sample.source_sequence);
        assert_eq!(sample.session_id, legacy_sample.session_id);
        assert_eq!(
            sample.app_arrival_elapsed_ns,
            legacy_sample.app_arrival_elapsed_ns
        );
        assert_eq!(sample.position, legacy_sample.position);
        assert_eq!(sample.native_timestamp, legacy_sample.native_timestamp);
        assert_eq!(sample.raw_payload, legacy_sample.raw_payload);
        assert_eq!(sample.pressure.as_ref().unwrap().mask_raw, None);
        assert_eq!(sample.tilt_x_raw, None);
        assert_eq!(sample.rotation_raw, None);
        assert_eq!(migrated.state.metadata_history.len(), 1);
        assert_eq!(
            migrated.state.metadata_history[0].metadata.key,
            "migration-source-schema"
        );
        assert_eq!(migrated.state.migration_provenance.len(), 1);
        assert_eq!(
            migrated.state.migration_provenance[0].source_journal_id,
            "legacy-migration-id"
        );
        assert_eq!(
            migrated.state.projected_samples().unwrap().len(),
            1,
            "migrated legacy stroke without lifecycle markers remains visible"
        );
        assert_eq!(preserved_source, source_bytes);
        fs::remove_file(source_path).unwrap();
        fs::remove_file(destination_path).unwrap();
    }

    #[test]
    fn schema_two_to_four_migration_preserves_raw_order_and_logical_view() {
        let source_path = temp_path("schema-two-source");
        let destination_path = temp_path("schema-two-migrated");
        let legacy_header = header("project-schema-two");
        let first = sample(
            "direct-wm-pointer",
            "legacy-stroke",
            1,
            100,
            Some(900),
            true,
            10,
        );
        let target = target_of(&first, &legacy_header.journal_id);

        let mut source_bytes = encode_row(&encode_header_fields(
            &legacy_header,
            PREVIOUS_JOURNAL_SCHEMA_VERSION,
        ))
        .unwrap();
        let first_row = encode_row(
            &encode_sample_fields("P", 1, &first, PREVIOUS_JOURNAL_SCHEMA_VERSION).unwrap(),
        )
        .unwrap();
        source_bytes.extend_from_slice(&first_row);
        for record in [
            JournalRecord {
                sequence: 2,
                app_epoch_id: legacy_header.session_id.clone(),
                event: JournalEvent::Revision {
                    revision_id: 1,
                    parent_revision: 0,
                    app_arrival_elapsed_ns: 110,
                    note: "legacy delete revision".to_owned(),
                },
            },
            JournalRecord {
                sequence: 3,
                app_epoch_id: legacy_header.session_id.clone(),
                event: JournalEvent::Tombstone {
                    logical_revision: 1,
                    app_arrival_elapsed_ns: 120,
                    target,
                },
            },
        ] {
            source_bytes.extend_from_slice(
                &encode_row(
                    &encode_record_fields(&record, PREVIOUS_JOURNAL_SCHEMA_VERSION).unwrap(),
                )
                .unwrap(),
            );
        }
        source_bytes.extend_from_slice(b"torn-final-record-without-newline");
        fs::write(&source_path, &source_bytes).unwrap();

        let before = read_journal(&source_path).unwrap();
        assert_eq!(before.schema_version, PREVIOUS_JOURNAL_SCHEMA_VERSION);
        assert!(before.recovery.truncated_final_record);
        assert!(before.state.projected_samples().unwrap().is_empty());
        let result = migrate_schema_two_to_four(&source_path, destination_path.clone()).unwrap();
        let after = read_journal(&destination_path).unwrap();
        let source_after = fs::read(&source_path).unwrap();

        assert_eq!(result.migrated_records, 3);
        assert_eq!(result.source_journal_id, "project-schema-two");
        assert_eq!(result.destination_journal_id, result.source_journal_id);
        assert!(result.source_truncated_final_record);
        assert_eq!(after.schema_version, JOURNAL_SCHEMA_VERSION);
        assert_eq!(after.header.journal_id, before.header.journal_id);
        assert_eq!(after.header.session_id, before.header.session_id);
        assert_eq!(after.records[0].sequence, 1);
        assert_eq!(after.records[0].app_epoch_id, before.header.session_id);
        let JournalEvent::PhysicalSample(migrated_sample) = &after.records[0].event else {
            panic!("first migrated source row remains physical history");
        };
        assert_eq!(migrated_sample.as_ref(), &first);
        assert_eq!(after.state.logical_revision, before.state.logical_revision);
        assert_eq!(
            after.state.projected_samples().unwrap(),
            before.state.projected_samples().unwrap()
        );
        assert_eq!(after.state.physical_samples.len(), 1);
        assert_eq!(after.state.migration_provenance.len(), 1);
        assert_eq!(after.state.migration_provenance[0].source_record_count, 3);
        assert_eq!(source_after, source_bytes);
        cleanup_journal(&source_path);
        cleanup_journal(&destination_path);
    }

    #[test]
    fn schema_three_golden_migration_preserves_multiepoch_history_and_snapshot_tail() {
        let source_path = temp_path("schema-three-source");
        let destination_path = temp_path("schema-three-migrated");
        // Literal v3 wire-format fixture from the pre-v4 schema: header,
        // session epochs, framed stroke starts, raw samples, edit actions,
        // legacy logical move/correction rows, and undo/redo controls. This
        // intentionally does not use the current schema encoders. V3 places
        // the app epoch after each sequence, stores journal/session IDs in
        // target references, and uses the v2 physical-sample field layout.
        const SCHEMA_THREE_BYTES: &[u8] = b"LASSOINK-JOURNAL\t3\tproject-v3-golden\tsession-1\tcfg-a\towner-device\tfalse\n\
P\t1\tsession-1\tsession-1\tdirect-wm-pointer\tdevice-a\t7\tlegacy-stroke\t1\tcfg-a\t100\tdevice-output\traw-units\t10\t20\traw-u32\traw-pressure\t512\t1\t~\t~\tqpc\tticks\t123\t10000000\tcontact\t3\t-2\t4\t5\t0102\n\
EPOCH\t2\tsession-2\t200\t1800000000000000000\tcfg-b\tresume\ttrue\n\
SBEG\t3\tsession-2\t210\t100\t200\t3FF0000000000000\t3FF0000000000000\t0000000000000000\t0000000000000000\t40\tproject-v3-golden\tsession-2\tdirect-wm-pointer\tdevice-b\t9\tnew-stroke\n\
P\t4\tsession-2\tsession-2\tdirect-wm-pointer\tdevice-b\t9\tnew-stroke\t1\tcfg-b\t220\tdevice-output\traw-units\t10\t20\traw-u32\traw-pressure\t600\t1\t~\t~\tqpc\tticks\t2000\t10000000\tcontact\t3\t~\t~\t~\tA0B0\n\
REV\t5\tsession-2\t230\t1\t0\tinitial-revision\n\
MOVE\t6\tsession-2\t240\t1\tproject-v3-golden\tsession-2\tdirect-wm-pointer\tdevice-b\t9\tnew-stroke\t5\t-2\tdevice-output\traw-units\n\
CORR\t7\tsession-2\t250\t1\tproject-v3-golden\tsession-2\tdirect-wm-pointer\tdevice-b\t9\tnew-stroke\tlegacy-correction\n\
ACT\t8\tsession-2\t2\t260\t8\tvisibility\ttrue\t1\tproject-v3-golden\tsession-2\tdirect-wm-pointer\tdevice-b\t9\tnew-stroke\n\
ACT\t9\tsession-2\t3\t270\t9\tmove\tproject-v3-golden\tsession-2\tdirect-wm-pointer\tdevice-b\t9\tnew-stroke\t2\t-1\tdevice-output\traw-units\n\
ACT\t10\tsession-2\t4\t280\t10\tcorrection\tproject-v3-golden\tsession-2\tdirect-wm-pointer\tdevice-b\t9\tnew-stroke\tedit-correction\n\
UNDO\t11\tsession-2\t5\t290\t10\n\
REDO\t12\tsession-2\t6\t300\t10\n";
        fs::write(&source_path, SCHEMA_THREE_BYTES).unwrap();

        let before = read_journal(&source_path).unwrap();
        assert_eq!(before.schema_version, THIRD_JOURNAL_SCHEMA_VERSION);
        assert_eq!(before.records.len(), 12);
        assert_eq!(before.state.session_epochs.len(), 2);
        assert_eq!(before.state.session_epochs[0].epoch.session_id, "session-1");
        assert_eq!(before.state.session_epochs[1].epoch.session_id, "session-2");
        assert_eq!(
            before.state.session_epochs[1].epoch.started_at_unix_ns,
            Some(1_800_000_000_000_000_000)
        );
        assert_eq!(before.state.stroke_starts.len(), 1);
        assert_eq!(before.state.stroke_starts[0].sequence, 3);
        assert_eq!(
            before.state.stroke_starts[0].view_frame.screen_origin_x_px,
            100
        );
        assert_eq!(
            before.state.stroke_starts[0].view_frame.screen_origin_y_px,
            200
        );
        assert_eq!(
            before.state.stroke_starts[0]
                .view_frame
                .dpi_scale_factor_bits,
            1.0_f64.to_bits()
        );
        assert_eq!(
            before.state.stroke_starts[0].view_frame.canvas_zoom_bits,
            1.0_f64.to_bits()
        );
        assert_eq!(
            before.state.stroke_starts[0].view_frame.canvas_pan_x_bits,
            0.0_f64.to_bits()
        );
        assert_eq!(
            before.state.stroke_starts[0].view_frame.canvas_pan_y_bits,
            0.0_f64.to_bits()
        );
        assert_eq!(
            before.state.stroke_starts[0].view_frame.toolbar_height_px,
            40
        );
        assert_eq!(before.state.physical_samples.len(), 2);
        assert_eq!(before.state.physical_samples[0].sequence, 1);
        assert_eq!(before.state.physical_samples[0].sample.source_sequence, 1);
        assert_eq!(
            before.state.physical_samples[0].sample.raw_payload,
            [0x01, 0x02]
        );
        assert_eq!(before.state.physical_samples[0].sample.tilt_x_raw, Some(-2));
        assert_eq!(
            before.state.physical_samples[0].sample.rotation_raw,
            Some(5)
        );
        assert_eq!(before.state.physical_samples[1].sequence, 4);
        assert_eq!(
            before.state.physical_samples[1].sample.raw_payload,
            [0xA0, 0xB0]
        );
        assert_eq!(before.state.moves.len(), 1);
        assert_eq!(before.state.corrections.len(), 1);
        assert_eq!(
            before.state.corrections[0].corrected_text,
            "legacy-correction"
        );
        assert_eq!(before.state.edit_actions.len(), 3);
        assert_eq!(before.state.edit_controls.len(), 2);
        assert!(!before.state.edit_controls[0].redo);
        assert!(before.state.edit_controls[1].redo);
        assert_eq!(before.state.logical_revision, 6);
        assert_eq!(before.state.undo_stack.as_slice(), &[8, 9, 10]);
        assert!(before.state.redo_stack.is_empty());
        let before_view = before.state.projected_samples().unwrap();
        assert_eq!(before_view.len(), 2);
        assert_eq!(before_view[0].sequence, 1);
        assert_eq!(
            before_view[0].effective_position.as_ref().unwrap().x_raw,
            10
        );
        assert_eq!(
            before_view[0].effective_position.as_ref().unwrap().y_raw,
            20
        );
        assert_eq!(before_view[1].sequence, 4);
        assert_eq!(
            before_view[1].effective_position.as_ref().unwrap().x_raw,
            17
        );
        assert_eq!(
            before_view[1].effective_position.as_ref().unwrap().y_raw,
            17
        );

        let migrated =
            migrate_schema_three_to_four(&source_path, destination_path.clone()).unwrap();
        let after = read_journal(&destination_path).unwrap();
        assert_eq!(after.schema_version, JOURNAL_SCHEMA_VERSION);
        assert_eq!(after.records.len(), before.records.len() + 1);
        assert_eq!(
            &after.records[..before.records.len()],
            before.records.as_slice()
        );
        assert_eq!(after.state.session_epochs, before.state.session_epochs);
        assert_eq!(after.state.stroke_starts, before.state.stroke_starts);
        assert_eq!(after.state.physical_samples, before.state.physical_samples);
        assert_eq!(after.state.moves, before.state.moves);
        assert_eq!(after.state.corrections, before.state.corrections);
        assert_eq!(after.state.edit_actions, before.state.edit_actions);
        assert_eq!(after.state.edit_controls, before.state.edit_controls);
        assert_eq!(after.state.undo_stack, before.state.undo_stack);
        assert_eq!(after.state.redo_stack, before.state.redo_stack);
        assert_eq!(after.state.logical_revision, before.state.logical_revision);
        assert_eq!(after.state.projected_samples().unwrap(), before_view);
        assert_eq!(migrated.migrated_records, 12);
        assert_eq!(after.state.migration_provenance.len(), 1);
        assert_eq!(
            after.state.migration_provenance[0].source_schema_version,
            THIRD_JOURNAL_SCHEMA_VERSION
        );
        assert_eq!(
            fs::read(&source_path).unwrap().as_slice(),
            SCHEMA_THREE_BYTES
        );

        let snapshot_path = default_snapshot_path(&destination_path);
        let mut reopened = JournalWriter::open_append(destination_path.clone()).unwrap();
        assert_eq!(reopened.state, after.state);
        reopened.write_snapshot(&snapshot_path).unwrap();
        reopened
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Session,
                scope_id: "session-2".to_owned(),
                source_api: None,
                device_id: None,
                key: "post-migration-tail".to_owned(),
                value: "retained".to_owned(),
                provenance: "golden-migration-test".to_owned(),
                app_arrival_elapsed_ns: 310,
            })
            .unwrap();
        reopened.flush().unwrap();
        drop(reopened);
        let full = read_journal(&destination_path).unwrap();
        let snapshot = load_with_snapshot(&destination_path, &snapshot_path).unwrap();
        assert_eq!(snapshot.disposition, SnapshotDisposition::Used);
        assert_eq!(snapshot.replayed_tail_records, 1);
        assert_eq!(snapshot.state, full.state);
        assert_eq!(snapshot.state.session_epochs.len(), 2);
        assert_eq!(snapshot.state.edit_controls.len(), 2);
        assert_eq!(snapshot.state.projected_samples().unwrap(), before_view);
        assert_eq!(
            fs::read(&source_path).unwrap().as_slice(),
            SCHEMA_THREE_BYTES
        );

        cleanup_journal(&source_path);
        cleanup_journal(&destination_path);
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
        let target = target_of(&valid_sample, "journal-oversized-fields");
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
    fn exclusive_writer_lease_refuses_second_writer_without_mutation() {
        let path = temp_path("writer-lease");
        let mut owner =
            JournalWriter::create(path.clone(), header("journal-writer-lease")).unwrap();
        owner
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
        drop(owner);
        let bytes_before_competitor = fs::read(&path).unwrap();

        let owner = JournalWriter::open_append(path.clone()).unwrap();
        let second_writer_error = JournalWriter::open_append(path.clone()).unwrap_err();
        assert_eq!(second_writer_error.kind, JournalErrorKind::WriterLeaseBusy);
        drop(owner);
        assert_eq!(fs::read(&path).unwrap(), bytes_before_competitor);

        let mut owner = JournalWriter::open_append(path.clone()).unwrap();
        assert_eq!(
            owner
                .append_sample(sample(
                    "direct-wm-pointer",
                    "stroke-a",
                    2,
                    20,
                    Some(6),
                    true,
                    2,
                ))
                .unwrap(),
            2
        );
        drop(owner);

        let reopened = JournalWriter::open_append(path.clone()).unwrap();
        assert_eq!(reopened.state.last_sequence, 2);
        drop(reopened);
        let parsed = read_journal(&path).unwrap();
        assert_eq!(parsed.state.last_sequence, 2);
        assert_eq!(parsed.state.physical_samples.len(), 2);
        cleanup_journal(&path);
    }

    #[test]
    fn recovery_holds_lease_across_parse_truncate_and_append_on_same_handle() {
        let path = temp_path("writer-lease-recovery");
        let mut initial =
            JournalWriter::create(path.clone(), header("journal-writer-lease-recovery")).unwrap();
        initial
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
        drop(initial);

        let mut torn_tail = OpenOptions::new().append(true).open(&path).unwrap();
        torn_tail.write_all(b"P\t2\tinterrupted-row").unwrap();
        drop(torn_tail);
        let valid_prefix_bytes = read_journal(&path).unwrap().recovery.valid_prefix_bytes;
        let path_during_recovery = path.clone();

        let mut recovery_owner =
            JournalWriter::open_append_with_validation_hook(path.clone(), || {
                // This callback runs after validation and before recovery
                // truncation while the one writer lease is still held.
                let competing_error =
                    JournalWriter::open_append(path_during_recovery.clone()).unwrap_err();
                assert_eq!(competing_error.kind, JournalErrorKind::WriterLeaseBusy);
            })
            .unwrap();
        assert!(recovery_owner.recovered_truncated_final_record());
        assert_eq!(recovery_owner.state.last_sequence, 1);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            valid_prefix_bytes,
            "recovery truncates only the torn tail after holding the lease"
        );
        assert_eq!(
            recovery_owner
                .append_sample(sample(
                    "direct-wm-pointer",
                    "stroke-a",
                    2,
                    20,
                    Some(6),
                    true,
                    2,
                ))
                .unwrap(),
            2
        );
        drop(recovery_owner);

        let parsed = read_journal(&path).unwrap();
        assert!(!parsed.recovery.truncated_final_record);
        assert_eq!(parsed.state.last_sequence, 2);
        assert_eq!(parsed.state.physical_samples.len(), 2);
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
        let target = target_of(&first, "journal-snapshot");
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

    #[test]
    fn short_snapshot_state_rows_reject_and_malformed_snapshot_falls_back() {
        let snapshot_header =
            b"LASSOINK-SNAPSHOT\t2\tjournal-short-smd\t0\t0\t0\t0000000000000000\t0000000000000000\n";
        for malformed_tag in ["SP", "SMD", "ST", "SM", "SC"] {
            let mut bytes = snapshot_header.to_vec();
            bytes.extend_from_slice(format!("{malformed_tag}\n").as_bytes());
            assert!(
                parse_snapshot(std::io::Cursor::new(bytes)).is_err(),
                "short snapshot row {malformed_tag} must be rejected"
            );
        }

        let path = temp_path("snapshot-short-smd-journal");
        let snapshot_path = default_snapshot_path(&path);
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-short-smd-source")).unwrap();
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
        drop(writer);
        let full = read_journal(&path).unwrap();

        let mut malformed_snapshot =
            b"LASSOINK-SNAPSHOT\t2\tjournal-short-smd-source\t0\t0\t0\t0000000000000000\t0000000000000000\n"
                .to_vec();
        malformed_snapshot.extend_from_slice(b"SMD\n");
        fs::write(&snapshot_path, malformed_snapshot).unwrap();

        let restored = load_with_snapshot(&path, &snapshot_path).unwrap();
        assert!(matches!(
            restored.disposition,
            SnapshotDisposition::Rejected(_)
        ));
        assert_eq!(restored.state, full.state);
        cleanup_journal(&path);
    }

    #[test]
    fn oversized_snapshot_undo_redo_stack_rows_reject_and_load_falls_back() {
        let path = temp_path("snapshot-stack-cap-journal");
        let snapshot_path = default_snapshot_path(&path);
        let mut writer =
            JournalWriter::create(path.clone(), header("journal-snapshot-stack-cap")).unwrap();
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
        writer.flush().unwrap();
        drop(writer);
        let full = read_journal(&path).unwrap();

        let snapshot_header =
            b"LASSOINK-SNAPSHOT\t2\tjournal-snapshot-stack-cap\t0\t0\t0\t0000000000000000\t0000000000000000\n";
        for stack_tag in ["US", "RS"] {
            let mut malformed_snapshot = Vec::new();
            malformed_snapshot
                .try_reserve(
                    snapshot_header
                        .len()
                        .saturating_add(MAX_SNAPSHOT_STATE_ENTRIES.saturating_mul(6)),
                )
                .unwrap();
            malformed_snapshot.extend_from_slice(snapshot_header);
            for _ in 0..=MAX_SNAPSHOT_STATE_ENTRIES {
                malformed_snapshot.extend_from_slice(stack_tag.as_bytes());
                malformed_snapshot.extend_from_slice(b"\t1\n");
            }
            fs::write(&snapshot_path, malformed_snapshot).unwrap();

            let restored = load_with_snapshot(&path, &snapshot_path).unwrap();
            assert!(matches!(
                restored.disposition,
                SnapshotDisposition::Rejected(_)
            ));
            assert_eq!(restored.state, full.state);
        }
        cleanup_journal(&path);
    }
}
