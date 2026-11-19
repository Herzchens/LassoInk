//! Local-only M5 batch harness and reproducibility artifact.
//!
//! Provider launch configuration is supplied separately from journal data. The
//! output records provenance and provider responses, but never serializes raw
//! request JSON, sample payloads, executable paths, or provider setting values.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{
    canvas::{
        CanonicalRasterProjectionCropV1, CanonicalRasterProjectionSpecV1,
        build_canonical_raster_projection_plan, render_canonical_raster,
        transform_canonical_raster_geometry,
    },
    journal::{JournalReplayState, StrokeRef, read_journal},
    provider_protocol::{
        OperatorApprovedProviderConfig, ProviderCallTimeouts, ProviderCapabilitiesV1,
        ProviderConfigurationV1, ProviderErrorKind, ProviderExecution, ProviderExecutionError,
        ProviderIdentityV1, ProviderInputCapabilityV1, ProviderProcessResourcesV1,
        ProviderRasterInputV1, ProviderRasterPayloadContractV1, ProviderRawResponseFrameV1,
        ProviderRawResponseTranscriptV1, ProviderSampleV1, ProviderSourceRevisionV1,
        ProviderStrokeViewV1, ProviderSubmitError, ProviderWorkerHandle, ProviderWorkerPoll,
        RecognitionRequestBuildInput, RecognitionRequestV1, RecognitionResultV1,
        build_recognition_request,
    },
    session::publish_no_clobber,
};
use unicode_normalization::UnicodeNormalization;

const BENCHMARK_SCHEMA_VERSION: u32 = 1;
const MAX_CASE_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PROVIDER_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_BENCHMARK_CASES: usize = 2048;
const MAX_BENCHMARK_PROVIDERS: usize = 8;
const MAX_BENCHMARK_INPUT_MODALITIES: usize = 2;
const CANONICAL_INK_COMPARISON_BINDING_SCHEMA_VERSION: u32 = 1;
const MAX_CANONICAL_INK_COMPARISON_BINDING_BYTES: usize = 8 * 1024 * 1024 + 1024;
const MAX_PROVIDER_ARTIFACTS: usize = 16;
const MAX_PROVIDER_ARTIFACT_HASH_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_TOTAL_PROVIDER_ARTIFACT_HASH_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_RASTER_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_GENERATED_RASTER_OUTPUT_DIMENSION: u32 = 2048;
const MAX_GENERATED_RASTER_OUTPUT_PIXELS: u64 = 262_144;
const MAX_GENERATED_RASTER_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_GENERATED_RASTER_CROP_DIMENSION: i128 = 1_048_576;
const MAX_GENERATED_RASTER_CROP_AREA: i128 = 67_108_864;
const MAX_GENERATED_RASTER_PROVENANCE_SAMPLES: usize = 4096;
const MAX_GENERATED_RASTER_PROVENANCE_STROKES: usize = 512;
const GENERATED_RASTER_COORDINATE_SPACE: &str = "canonical-raster-output-v1";
const GENERATED_RASTER_COORDINATE_UNITS: &str = "pixel";
const MAX_BENCHMARK_RECORD_BYTES: usize = 48 * 1024 * 1024;
const MAX_BENCHMARK_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BENCHMARK_RECORDS: u64 = 50_000;
const MAX_PROVIDER_RESULTS_WAIT: Duration = Duration::from_secs(365);
const IO_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_ANNOTATION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ANNOTATIONS: usize = MAX_BENCHMARK_CASES;
const MAX_REFERENCE_TEXT_BYTES: usize = 64 * 1024;
const MAX_NFD_MARK_SCALARS: usize = 4 * MAX_REFERENCE_TEXT_BYTES;
const MAX_METRIC_DP_CELLS: usize = 1024 * 1024;
const MAX_BOOTSTRAP_REPLICATES: u32 = 5_000;
const MAX_TOTAL_BOOTSTRAP_CLUSTER_DRAWS: u64 = 10_000_000;
const SENOCR_REFERENCE_PROVIDER_ID: &str = "senocr-v1-fp32-local";
const SENOCR_REFERENCE_PROVIDER_VERSION: &str = "stdlib-senocr-fp32-worker-v1";
const SENOCR_REFERENCE_CONFIGURATION_ID: &str = "senocr-v1-fp32-local";
const SENOCR_REFERENCE_MODEL_REVISION: &str = "1e70dff4ef0429b0d88a2b873fb5d03300af1a41";
const SENOCR_REFERENCE_RUNTIME_PROFILE_ID: &str = "senocr-runtime-profile-v1";
const SENOCR_REFERENCE_RUNTIME_PROFILE_SHA256: &str =
    "3d6150df16fc91bf032638d88a02d30be6877f5b4e62da5682fa601d0fe1ac1c";
const SENOCR_REFERENCE_RUNTIME_DISTRIBUTION_COUNT: u32 = 41;
const SENOCR_REFERENCE_PYTHON_VERSION: &str = "3.13.17";
const SENOCR_REFERENCE_PLATFORM: &str = "windows-x64";
const MAX_SENOCR_RUNTIME_PROFILE_BYTES: usize = 64 * 1024;
const SENOCR_REFERENCE_ROOT_PIN_COUNT: usize = 4;
const SENOCR_RUNTIME_PROFILE_DOCUMENT: &[u8] =
    include_bytes!("../tools/senocr_runtime_profile_v1.json");
pub(crate) const SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES: [(&str, u64); 12] = [
    ("added_tokens.json", 25_381),
    ("chat_template.jinja", 1_474),
    ("config.json", 2_059),
    ("generation_config.json", 133),
    ("model-00001-of-00001.safetensors", 3_834_433_136),
    ("model.safetensors.index.json", 58_809),
    ("preprocessor_config.json", 641),
    ("processor_config.json", 137),
    ("special_tokens_map.json", 1_151),
    ("tokenizer.json", 11_189_060),
    ("tokenizer.model", 1_614_363),
    ("tokenizer_config.json", 186_947),
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkCaseManifestV1 {
    pub schema_version: u32,
    pub batch_id: String,
    pub cases: Vec<BenchmarkCaseSpecV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkProviderManifestV1 {
    pub schema_version: u32,
    pub providers: Vec<ApprovedBenchmarkProviderV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkCorpusManifestV1 {
    pub schema_version: u32,
    pub corpus_id: String,
    pub split_key: BenchmarkSplitKeyV1,
    pub bootstrap_cluster: BenchmarkClusterKeyV1,
    pub bootstrap_seed: u64,
    pub bootstrap_replicates: u32,
    pub tokenization_policy: BenchmarkTokenizationPolicyV1,
    pub cases: Vec<BenchmarkAnnotationCaseV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkAnnotationCaseV1 {
    pub case_id: String,
    pub annotation_id: String,
    pub reference_text: String,
    pub reference_language_scope: BenchmarkReferenceLanguageScopeV1,
    /// Optional reference lexical segments are retained only in the local
    /// annotation input. Predicted lexical boundaries are unavailable unless
    /// an independently validated segmenter is supplied.
    pub reference_lexical_tokens: Option<Vec<String>>,
    pub delayed_marks: Vec<DelayedMarkAnnotationV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkReferenceLanguageScopeV1 {
    VietnameseOnly,
    MixedOrUnknown,
    OtherLanguage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DelayedMarkAnnotationV1 {
    pub reference_scalar_index: u32,
    pub expected_stroke: BenchmarkStrokeRefV1,
    pub expected_source_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkSplitKeyV1 {
    Writer,
    Session,
    Configuration,
    SessionStartTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkClusterKeyV1 {
    Writer,
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkTokenizationPolicyV1 {
    UnicodeWhitespaceSyllableV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkCaseSpecV1 {
    pub case_id: String,
    pub journal_path: PathBuf,
    pub expected_source_revision: ProviderSourceRevisionV1,
    pub region_id: String,
    pub line_id: String,
    pub coordinate_space: String,
    pub coordinate_units: String,
    pub language_hints: Vec<String>,
    pub requested_input_modalities: Vec<ProviderInputCapabilityV1>,
    pub selected_strokes: Vec<BenchmarkStrokeRefV1>,
    pub provenance: BenchmarkCaseProvenanceV1,
    pub raster: Option<BenchmarkRasterInputSpecV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_raster: Option<BenchmarkGeneratedRasterSpecV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkStrokeRefV1 {
    pub journal_id: String,
    pub session_id: String,
    pub source_api: String,
    pub device_id: Option<String>,
    pub pointer_id: Option<u64>,
    pub stroke_id: String,
}

impl From<&StrokeRef> for BenchmarkStrokeRefV1 {
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

impl From<&BenchmarkStrokeRefV1> for StrokeRef {
    fn from(stroke: &BenchmarkStrokeRefV1) -> Self {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkCaseProvenanceV1 {
    pub corpus_id: Option<String>,
    pub annotation_id: Option<String>,
    pub writer_key: String,
    pub session_key: String,
    /// Owner-declared UTC Unix nanoseconds for the actual capture session;
    /// never generated by the benchmark runner.
    pub session_start_unix_ns: Option<u64>,
    pub configuration_key: String,
    pub split: Option<BenchmarkSplitV1>,
    pub capture_api: Option<String>,
    /// Owner-declared capture adapter/API version, separate from the app build.
    pub capture_api_version: Option<String>,
    pub tablet_model: Option<String>,
    pub driver_version: Option<String>,
    pub windows_build: Option<String>,
    pub windows_ink_state: Option<String>,
    pub active_area: Option<String>,
    pub display_mapping: Option<String>,
    pub pressure_curve: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkSplitV1 {
    Adaptation,
    Calibration,
    Train,
    Validation,
    Evaluation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkRasterInputSpecV1 {
    pub path: PathBuf,
    pub width: u32,
    pub height: u32,
    pub coordinate_space: String,
    pub units: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkGeneratedRasterSpecV1 {
    /// Version of the supported canonical raster projection specification.
    pub projection_schema_version: u32,
    pub output_width_px: u32,
    pub output_height_px: u32,
    pub source_crop: BenchmarkGeneratedRasterCropV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkGeneratedRasterCropV1 {
    pub left_px: i32,
    pub top_px: i32,
    pub right_px_exclusive: i32,
    pub bottom_px_exclusive: i32,
}

/// This operator-supplied file is separate from the journal/corpus manifest.
/// Its executable, arguments, settings, and artifact paths never go into the
/// benchmark result artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovedBenchmarkProviderV1 {
    pub provider_id: String,
    pub executable_path: PathBuf,
    pub arguments: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_input_modalities: Option<Vec<ProviderInputCapabilityV1>>,
    pub protocol_configuration: ProviderConfigurationV1,
    pub artifacts: Vec<ProviderArtifactPathV1>,
    pub timeouts: Option<BenchmarkTimeoutsV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderArtifactPathV1 {
    pub artifact_id: String,
    pub role: ProviderArtifactRoleV1,
    pub path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProviderArtifactRoleV1 {
    Executable,
    Model,
    Tokenizer,
    Resource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkTimeoutsV1 {
    pub handshake_ms: u64,
    pub recognition_ms: u64,
    pub shutdown_ms: u64,
}

impl From<BenchmarkTimeoutsV1> for ProviderCallTimeouts {
    fn from(timeouts: BenchmarkTimeoutsV1) -> Self {
        Self {
            handshake: std::time::Duration::from_millis(timeouts.handshake_ms),
            recognition: std::time::Duration::from_millis(timeouts.recognition_ms),
            shutdown: std::time::Duration::from_millis(timeouts.shutdown_ms),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderArtifactDigestV1 {
    pub artifact_id: String,
    pub role: ProviderArtifactRoleV1,
    pub byte_count: u64,
    pub sha256_hex: String,
    pub observation: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkQualityEvidenceStatusV1 {
    /// A legacy row had no structured runtime/asset evidence. It is diagnostic
    /// only and is not eligible for quality comparison.
    LegacyUnassessed,
    /// No configured provider-specific evidence policy makes this row
    /// diagnostic only, not quality-eligible.
    ProviderPolicyNotApplicable,
    /// The declared runtime profile and all required prelaunch asset hashes match.
    EligibleByDeclaredSenocrEvidence,
    /// One or more required runtime or asset observations are absent.
    IncompleteSenocrEvidence,
    /// Supplied provider identity or asset mapping conflicts with the fixed policy.
    MismatchedSenocrEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkRuntimeDistributionV1 {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkRuntimeProfileBindingV1 {
    pub manifest_schema_version: u32,
    pub profile_id: String,
    pub profile_manifest_sha256: String,
    pub distribution_count: u32,
    pub python_version: String,
    pub platform: String,
    pub root_pins: Vec<BenchmarkRuntimeDistributionV1>,
    pub installed_distribution_closure: Vec<BenchmarkRuntimeDistributionV1>,
    pub observation_scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenocrRuntimeProfileManifestV1 {
    distribution_count: u32,
    installed_distribution_closure: Vec<BenchmarkRuntimeDistributionV1>,
    platform: String,
    python_version: String,
    root_pins: Vec<BenchmarkRuntimeDistributionV1>,
    schema_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkModelAssetObservationV1 {
    pub asset_name: String,
    pub expected_byte_count: u64,
    pub observed_byte_count: u64,
    pub observed_sha256_hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkModelAssetCoverageStatusV1 {
    CompletePrelaunchObservations,
    IncompletePrelaunchObservations,
    MismatchedPrelaunchManifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkModelAssetCoverageV1 {
    pub model_revision: String,
    pub required_asset_count: u32,
    pub observed_asset_count: u32,
    pub missing_asset_names: Vec<String>,
    pub observed_assets: Vec<BenchmarkModelAssetObservationV1>,
    pub status: BenchmarkModelAssetCoverageStatusV1,
    pub observation_scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkQualityEvidenceV1 {
    pub schema_version: u32,
    pub status: BenchmarkQualityEvidenceStatusV1,
    pub runtime_profile: Option<BenchmarkRuntimeProfileBindingV1>,
    pub model_asset_coverage: Option<BenchmarkModelAssetCoverageV1>,
    pub unavailable_reason: Option<String>,
}

impl Default for BenchmarkQualityEvidenceV1 {
    fn default() -> Self {
        Self {
            schema_version: 0,
            status: BenchmarkQualityEvidenceStatusV1::LegacyUnassessed,
            runtime_profile: None,
            model_asset_coverage: None,
            unavailable_reason: Some(
                "legacy benchmark row has no structured runtime/profile and complete model-asset evidence; not quality-eligible"
                    .to_owned(),
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkArtifactHeaderV1 {
    pub schema_version: u32,
    pub batch_id: String,
    pub case_manifest_sha256: String,
    pub corpus_manifest_sha256: Option<String>,
    pub app_version: String,
    pub source_git_sha: String,
    pub source_tree_dirty: String,
    pub build_id: String,
    pub build_profile: String,
    pub build_target: String,
    pub build_rustc: String,
    pub created_unix_ns: u128,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkRawResponseFrameHexV1 {
    pub ordinal: u8,
    pub length_prefix_be_hex: String,
    pub payload_hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkRasterPixelParityV1 {
    Unverified,
}

/// Shared digest of canonical source-ordered ink and its document/view context.
/// Equality excludes request modality/config/raster bytes and is not raster-pixel parity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkCanonicalInkComparisonBindingV1 {
    pub schema_version: u32,
    pub sha256_hex: String,
    pub raster_pixel_parity: BenchmarkRasterPixelParityV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkGeneratedRasterOriginV1 {
    pub schema_version: u32,
    /// Binds this producer record to this run's shared canonical-ink request view.
    pub canonical_ink_comparison_binding_sha256: String,
    pub producer: BenchmarkGeneratedRasterProducerV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkGeneratedRasterProducerV1 {
    pub schema_version: u32,
    pub geometry_schema_version: u32,
    pub projection_schema_version: u32,
    pub source_revision: ProviderSourceRevisionV1,
    pub selected_strokes: Vec<BenchmarkStrokeRefV1>,
    pub source_content_sha256: String,
    pub projection_spec_sha256: String,
    pub geometry_sha256: String,
    pub renderer_version: String,
    pub pixel_bytes_sha256: String,
    pub png_bytes_sha256: String,
    pub raster_artifact_sha256: String,
    pub output_width_px: u32,
    pub output_height_px: u32,
    pub row_stride_bytes: u32,
    pub pixel_layout: String,
    pub stroke_draw_order: Vec<BenchmarkStrokeRefV1>,
    pub physical_sample_provenance: Vec<BenchmarkGeneratedRasterSampleProvenanceV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkGeneratedRasterSampleProvenanceV1 {
    pub stroke: BenchmarkStrokeRefV1,
    pub journal_sequence: u64,
    pub source_sequence_raw: u64,
}

#[derive(Serialize)]
struct CanonicalInkComparisonFingerprintV1<'a> {
    schema_version: u32,
    protocol_version: u32,
    source_journal_id: &'a str,
    logical_revision: u64,
    region_id: &'a str,
    line_id: &'a str,
    coordinate_space: &'a str,
    coordinate_units: &'a str,
    language_hints: &'a [String],
    stroke_views: &'a [ProviderStrokeViewV1],
    samples: &'a [ProviderSampleV1],
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkRunRecordV1 {
    pub case_id: String,
    pub region_id: String,
    pub line_id: String,
    pub coordinate_space: String,
    pub coordinate_units: String,
    pub language_hints: Vec<String>,
    pub raster_input_byte_count: Option<u64>,
    pub raster_input_sha256: Option<String>,
    pub corpus_id: Option<String>,
    pub annotation_id: Option<String>,
    /// Copied from the validated corpus annotation, never from case provenance.
    pub reference_language_scope: Option<BenchmarkReferenceLanguageScopeV1>,
    pub writer_key: String,
    pub session_key: String,
    pub declared_session_start_unix_ns: Option<u64>,
    pub configuration_key: String,
    pub split: Option<BenchmarkSplitV1>,
    pub declared_capture_api: Option<String>,
    pub declared_capture_api_version: Option<String>,
    pub declared_tablet_model: Option<String>,
    pub declared_driver_version: Option<String>,
    pub declared_windows_build: Option<String>,
    pub declared_windows_ink_state: Option<String>,
    pub declared_active_area: Option<String>,
    pub declared_display_mapping: Option<String>,
    pub declared_pressure_curve: Option<String>,
    pub source_revision: ProviderSourceRevisionV1,
    pub input_view_id: String,
    /// Shared canonical-ink identity; the per-request M4 view ID remains separate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_ink_comparison_binding: Option<BenchmarkCanonicalInkComparisonBindingV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_raster_origin: Option<BenchmarkGeneratedRasterOriginV1>,
    pub requested_input_modalities: Vec<ProviderInputCapabilityV1>,
    pub selected_strokes: Vec<BenchmarkStrokeRefV1>,
    pub source_sample_sequences: Vec<u64>,
    pub provider_id: String,
    pub provider_identity: Option<ProviderIdentityV1>,
    pub provider_capabilities: Option<ProviderCapabilitiesV1>,
    pub provider_configuration_id: String,
    pub provider_configuration_fingerprint: String,
    pub artifact_digests: Vec<ProviderArtifactDigestV1>,
    pub model_artifact_digests: Vec<ProviderArtifactDigestV1>,
    pub model_artifact_hash_unavailable_reason: Option<String>,
    /// Optional for backward-compatible parsing; missing fields mean legacy
    /// evidence is unknown and cannot establish quality eligibility.
    #[serde(default)]
    pub quality_evidence: BenchmarkQualityEvidenceV1,
    pub elapsed_app_batch_call_wall_ns: u64,
    pub timing: Option<crate::provider_protocol::ProviderExecutionTimingV1>,
    pub timing_unavailable_reason: Option<String>,
    pub process_resources: Option<ProviderProcessResourcesV1>,
    pub process_resources_unavailable_reason: Option<String>,
    pub job_process_tree_cpu_core_equivalent_percent: Option<f64>,
    pub job_cpu_ratio_unavailable_reason: Option<String>,
    pub gpu_memory_bytes: Option<u64>,
    pub gpu_memory_unavailable_reason: Option<String>,
    pub result: Option<RecognitionResultV1>,
    pub candidate_metrics: Vec<BenchmarkCandidateMetricsV1>,
    pub metric_evaluation_unavailable_reason: Option<String>,
    pub raw_response_frames: Vec<BenchmarkRawResponseFrameHexV1>,
    pub raw_response_capture_complete: bool,
    pub raw_response_omitted_frame_count: u32,
    pub raw_response_omitted_payload_bytes: u64,
    pub stderr_byte_count: u64,
    pub stderr_truncated: bool,
    pub status: BenchmarkRunStatusV1,
    pub failure_category: Option<BenchmarkFailureCategoryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkCountMetricV1 {
    pub errors: u64,
    pub reference_units: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkCandidateMetricsV1 {
    pub candidate_rank: u16,
    pub nfc_unicode_scalar_cer: Option<BenchmarkCountMetricV1>,
    pub nfc_cer_unavailable_reason: Option<String>,
    pub whitespace_token_syllable_wer: Option<BenchmarkCountMetricV1>,
    pub whitespace_wer_unavailable_reason: Option<String>,
    pub lexical_wer_unavailable_reason: String,
    /// Global NFD inventory deltas are diagnostics only; they do not align
    /// marks to letters and are not error rates.
    pub tone_mark_inventory_difference_count: u64,
    pub vowel_modifier_inventory_difference_count: u64,
    pub vietnamese_tone_mark_alignment_edits: Option<BenchmarkCountMetricV1>,
    pub vietnamese_tone_mark_unavailable_reason: Option<String>,
    pub vietnamese_vowel_modifier_alignment_edits: Option<BenchmarkCountMetricV1>,
    pub vietnamese_vowel_modifier_unavailable_reason: Option<String>,
    pub vietnamese_mark_alignment_policy: Option<String>,
    pub syllable_boundary_offset_diagnostic: Option<BenchmarkCountMetricV1>,
    pub syllable_boundary_offset_diagnostic_unavailable_reason: Option<String>,
    pub syllable_boundary_diagnostic_policy: String,
    pub delayed_attachment_unavailable_reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkRunStatusV1 {
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkFailureCategoryV1 {
    InvalidConfig,
    InvalidRequest,
    UnsupportedPlatform,
    UnsupportedCapability,
    Timeout,
    Cancelled,
    ProviderFailure,
    InvalidResponse,
    WorkerFailure,
    CleanupFailure,
    WorkerCapacity,
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkArtifactFooterV1 {
    pub planned_case_count: u32,
    pub planned_provider_count: u32,
    pub recorded_run_count: u32,
    pub failed_run_count: u32,
    /// True means every planned case/provider attempt has a run row. Failed
    /// provider outcomes remain visible and do not make the artifact partial.
    pub complete: bool,
    pub corpus_id: Option<String>,
    pub split_key: Option<BenchmarkSplitKeyV1>,
    pub bootstrap_cluster: Option<BenchmarkClusterKeyV1>,
    pub bootstrap_seed: Option<u64>,
    pub bootstrap_replicates: Option<u32>,
    pub max_bootstrap_cluster_draws: Option<u64>,
    pub tokenization_policy: Option<BenchmarkTokenizationPolicyV1>,
    pub pairwise_interpretation: Option<BenchmarkPairwiseInterpretationV1>,
    pub provider_summaries: Vec<BenchmarkProviderSummaryV1>,
    pub paired_comparisons: Vec<BenchmarkPairedComparisonV1>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkProviderSummaryV1 {
    pub provider_id: String,
    pub configuration_id: String,
    pub attempted_run_count: u32,
    pub completed_run_count: u32,
    pub failed_run_count: u32,
    pub app_batch_call_wall_ns: BenchmarkU64PercentilesV1,
    pub process_create_call_to_handshake_ns: BenchmarkU64PercentilesV1,
    pub process_create_call_to_recognition_ns: BenchmarkU64PercentilesV1,
    pub process_create_call_to_tree_drain_ns: BenchmarkU64PercentilesV1,
    pub job_process_tree_cpu_core_equivalent_percent: BenchmarkF64PercentilesV1,
    pub peak_job_memory_bytes_raw: BenchmarkU64PercentilesV1,
    pub peak_process_memory_bytes_raw: BenchmarkU64PercentilesV1,
    pub model_cold_start_ns: BenchmarkU64PercentilesV1,
    pub gpu_memory_bytes_raw: BenchmarkU64PercentilesV1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkU64PercentilesV1 {
    pub unit: String,
    pub sample_count: u32,
    pub missing_observation_count: u32,
    pub p50: Option<u64>,
    pub p95: Option<u64>,
    pub p99: Option<u64>,
    pub unavailable_reason: Option<String>,
    pub missing_observation_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkF64PercentilesV1 {
    pub unit: String,
    pub sample_count: u32,
    pub missing_observation_count: u32,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
    pub unavailable_reason: Option<String>,
    pub missing_observation_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkPairedComparisonV1 {
    pub left_provider: String,
    pub left_configuration_id: String,
    pub right_provider: String,
    pub right_configuration_id: String,
    pub split: BenchmarkSplitV1,
    pub nfc_cer_paired_case_count: u32,
    pub nfc_cer_cluster_count: u32,
    pub nfc_cer_rate_difference: Option<BenchmarkBootstrapIntervalV1>,
    pub nfc_cer_unavailable_reason: Option<String>,
    pub whitespace_syllable_wer_paired_case_count: u32,
    pub whitespace_syllable_wer_cluster_count: u32,
    pub whitespace_syllable_wer_rate_difference: Option<BenchmarkBootstrapIntervalV1>,
    pub whitespace_syllable_wer_unavailable_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BenchmarkPairwiseInterpretationV1 {
    NominalUnadjustedExploratoryNotSelectionEvidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkBootstrapIntervalV1 {
    /// Nominal right-minus-left estimate and interval; no multiplicity correction.
    pub median_difference: f64,
    pub nominal_95_unadjusted_low: f64,
    pub nominal_95_unadjusted_high: f64,
    pub bootstrap_replicates: u32,
    pub seed: u64,
    pub interpretation: BenchmarkPairwiseInterpretationV1,
    pub selection_evidence_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record_type", content = "record", rename_all = "snake_case")]
enum BenchmarkArtifactRecordV1 {
    Header(BenchmarkArtifactHeaderV1),
    Run(Box<BenchmarkRunRecordV1>),
    Footer(BenchmarkArtifactFooterV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BenchmarkBatchCompletionV1 {
    pub artifact_path: PathBuf,
    pub run_count: u32,
    pub failure_count: u32,
}

struct BenchmarkArtifactWriter {
    file: Option<File>,
    partial_path: PathBuf,
    final_path: PathBuf,
    bytes_written: u64,
    rows_written: u64,
    run_count: u32,
    failure_count: u32,
}

impl BenchmarkArtifactWriter {
    fn create_at(
        output_directory: &Path,
        batch_id: &str,
        case_manifest_sha256: &str,
        corpus_manifest_sha256: Option<String>,
    ) -> io::Result<Self> {
        validate_local_id(batch_id, "batch ID")?;
        validate_sha256_hex(case_manifest_sha256, "case manifest digest")?;
        if let Some(sha256) = &corpus_manifest_sha256 {
            validate_sha256_hex(sha256, "corpus manifest digest")?;
        }
        fs::create_dir_all(output_directory)?;
        let unique_suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let stem = format!("{batch_id}-{}-{unique_suffix}", process::id());
        let final_path = output_directory.join(format!("benchmark-{stem}.jsonl"));
        let partial_path = output_directory.join(format!("benchmark-{stem}.jsonl.partial"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial_path)?;
        let mut writer = Self {
            file: Some(file),
            partial_path,
            final_path,
            bytes_written: 0,
            rows_written: 0,
            run_count: 0,
            failure_count: 0,
        };
        writer.write_record(&BenchmarkArtifactRecordV1::Header(
            BenchmarkArtifactHeaderV1 {
                schema_version: BENCHMARK_SCHEMA_VERSION,
                batch_id: batch_id.to_owned(),
                case_manifest_sha256: case_manifest_sha256.to_owned(),
                corpus_manifest_sha256,
                app_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_git_sha: env!("LASSOINK_BUILD_GIT_SHA").to_owned(),
                source_tree_dirty: env!("LASSOINK_BUILD_TREE_DIRTY").to_owned(),
                build_id: env!("LASSOINK_BUILD_ID").to_owned(),
                build_profile: env!("LASSOINK_BUILD_PROFILE").to_owned(),
                build_target: env!("LASSOINK_BUILD_TARGET").to_owned(),
                build_rustc: env!("LASSOINK_BUILD_RUSTC").to_owned(),
                created_unix_ns: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            },
        ))?;
        Ok(writer)
    }

    fn write_run(&mut self, run: BenchmarkRunRecordV1) -> io::Result<()> {
        let status = run.status;
        self.write_record(&BenchmarkArtifactRecordV1::Run(Box::new(run)))?;
        self.run_count = self.run_count.saturating_add(1);
        if status == BenchmarkRunStatusV1::Failed {
            self.failure_count = self.failure_count.saturating_add(1);
        }
        Ok(())
    }

    fn finish(
        mut self,
        planned_case_count: usize,
        planned_provider_count: usize,
        paired_comparisons: Vec<BenchmarkPairedComparisonV1>,
        provider_summaries: Vec<BenchmarkProviderSummaryV1>,
        corpus_manifest: Option<&BenchmarkCorpusManifestV1>,
    ) -> io::Result<BenchmarkBatchCompletionV1> {
        let planned_run_count = planned_case_count
            .checked_mul(planned_provider_count)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "planned run count exceeds u32")
            })?;
        self.write_record(&BenchmarkArtifactRecordV1::Footer(
            BenchmarkArtifactFooterV1 {
                planned_case_count: u32::try_from(planned_case_count).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "case count does not fit u32")
                })?,
                planned_provider_count: u32::try_from(planned_provider_count).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "provider count does not fit u32")
                })?,
                recorded_run_count: self.run_count,
                failed_run_count: self.failure_count,
                complete: self.run_count == planned_run_count,
                corpus_id: corpus_manifest.map(|manifest| manifest.corpus_id.clone()),
                split_key: corpus_manifest.map(|manifest| manifest.split_key),
                bootstrap_cluster: corpus_manifest.map(|manifest| manifest.bootstrap_cluster),
                bootstrap_seed: corpus_manifest.map(|manifest| manifest.bootstrap_seed),
                bootstrap_replicates: corpus_manifest
                    .map(|manifest| manifest.bootstrap_replicates),
                max_bootstrap_cluster_draws: corpus_manifest
                    .map(|_| MAX_TOTAL_BOOTSTRAP_CLUSTER_DRAWS),
                tokenization_policy: corpus_manifest.map(|manifest| manifest.tokenization_policy),
                pairwise_interpretation: corpus_manifest.map(|_| {
                    BenchmarkPairwiseInterpretationV1::NominalUnadjustedExploratoryNotSelectionEvidence
                }),
                provider_summaries,
                paired_comparisons,
            },
        ))?;
        self.file
            .as_mut()
            .expect("benchmark writer owns its partial file")
            .sync_all()?;
        self.file.take();
        publish_no_clobber(&self.partial_path, &self.final_path)?;
        Ok(BenchmarkBatchCompletionV1 {
            artifact_path: self.final_path.clone(),
            run_count: self.run_count,
            failure_count: self.failure_count,
        })
    }

    fn write_record(&mut self, record: &BenchmarkArtifactRecordV1) -> io::Result<()> {
        if self.rows_written >= MAX_BENCHMARK_RECORDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "benchmark artifact record cap reached; partial output retained",
            ));
        }
        let mut buffer = BoundedJsonBuffer::new(MAX_BENCHMARK_RECORD_BYTES);
        serde_json::to_writer(&mut buffer, record).map_err(|error| {
            io::Error::other(format!("benchmark JSON encoding failed: {error}"))
        })?;
        buffer.write_all(b"\n")?;
        let row_length = u64::try_from(buffer.bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "benchmark row size does not fit u64",
            )
        })?;
        let next_total = self.bytes_written.checked_add(row_length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "benchmark byte count overflow")
        })?;
        if next_total > MAX_BENCHMARK_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "benchmark artifact byte cap reached; partial output retained",
            ));
        }
        self.file
            .as_mut()
            .expect("benchmark writer owns its partial file")
            .write_all(&buffer.bytes)?;
        self.bytes_written = next_total;
        self.rows_written = self.rows_written.saturating_add(1);
        Ok(())
    }
}

struct BoundedJsonBuffer {
    bytes: Vec<u8>,
    maximum: usize,
}

impl BoundedJsonBuffer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }
}

impl Write for BoundedJsonBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next_length = self.bytes.len().checked_add(buffer.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "benchmark JSON row overflow")
        })?;
        if next_length > self.maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "benchmark JSON row exceeds its byte cap",
            ));
        }
        self.bytes.try_reserve(buffer.len()).map_err(|error| {
            io::Error::other(format!("benchmark JSON row allocation failed: {error}"))
        })?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn local_benchmark_directory() -> io::Result<PathBuf> {
    let root = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "LOCALAPPDATA is unavailable; benchmark output is local-only",
        )
    })?;
    let root = PathBuf::from(root);
    let root_text = root.to_string_lossy();
    if !root.is_absolute() || root_text.starts_with("\\\\") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "benchmark output requires a local absolute LOCALAPPDATA path",
        ));
    }
    Ok(root.join("LassoInk").join("benchmark"))
}

fn validate_local_id(value: &str, label: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be 1..=128 ASCII letters, digits, '-' or '_'"),
        ));
    }
    Ok(())
}

fn read_json_file<T: DeserializeOwned>(path: &Path, maximum: u64) -> Result<T, Box<dyn Error>> {
    let bytes = read_json_bytes(path, maximum)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_json_file_with_sha<T: DeserializeOwned>(
    path: &Path,
    maximum: u64,
) -> Result<(T, String), Box<dyn Error>> {
    let bytes = read_json_bytes(path, maximum)?;
    let digest = hex_encode(&Sha256::digest(&bytes))?;
    Ok((serde_json::from_slice(&bytes)?, digest))
}

fn read_json_bytes(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    require_local_absolute_path(path, "manifest path")?;
    let link_metadata = fs::symlink_metadata(path)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(invalid_data("manifest must be a regular non-symlink file").into());
    }
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() != link_metadata.len() || before.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a bounded regular JSON file", path.display()),
        )
        .into());
    }
    let reserve = usize::try_from(before.len())?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(reserve)?;
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum || file.metadata()?.len() != before.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "JSON manifest exceeded its cap or changed while being read",
        )
        .into());
    }
    Ok(bytes)
}

fn hex_encode(bytes: &[u8]) -> Result<String, io::Error> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes
        .len()
        .checked_mul(2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "hex output length overflow"))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|error| io::Error::other(format!("hex output allocation failed: {error}")))?;
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)]);
        encoded.push(HEX[usize::from(byte & 0x0f)]);
    }
    String::from_utf8(encoded).map_err(|error| io::Error::other(error.to_string()))
}

fn canonical_ink_comparison_binding(
    request: &RecognitionRequestV1,
) -> io::Result<BenchmarkCanonicalInkComparisonBindingV1> {
    let fingerprint = CanonicalInkComparisonFingerprintV1 {
        schema_version: CANONICAL_INK_COMPARISON_BINDING_SCHEMA_VERSION,
        protocol_version: request.protocol_version,
        source_journal_id: &request.source_revision.journal_id,
        logical_revision: request.source_revision.logical_revision,
        region_id: &request.region_id,
        line_id: &request.line_id,
        coordinate_space: &request.coordinate_space,
        coordinate_units: &request.coordinate_units,
        language_hints: &request.language_hints,
        stroke_views: &request.stroke_views,
        samples: &request.samples,
    };
    let fingerprint_bytes = serde_json::to_vec(&fingerprint).map_err(|error| {
        invalid_data(format!(
            "canonical-ink fingerprint serialization failed: {error}"
        ))
    })?;
    if fingerprint_bytes.len() > MAX_CANONICAL_INK_COMPARISON_BINDING_BYTES {
        return Err(invalid_data(
            "canonical-ink comparison binding exceeds its fixed byte cap",
        ));
    }
    Ok(BenchmarkCanonicalInkComparisonBindingV1 {
        schema_version: CANONICAL_INK_COMPARISON_BINDING_SCHEMA_VERSION,
        sha256_hex: hex_encode(&Sha256::digest(fingerprint_bytes))?,
        raster_pixel_parity: BenchmarkRasterPixelParityV1::Unverified,
    })
}

fn validate_sha256_hex(value: &str, label: &str) -> io::Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_data(format!(
            "{label} is not a 32-byte hexadecimal SHA-256"
        )));
    }
    Ok(())
}

struct PreparedBenchmarkProvider {
    provider_id: String,
    configuration: ProviderConfigurationV1,
    configuration_id: String,
    approved: OperatorApprovedProviderConfig,
    timeouts: ProviderCallTimeouts,
    artifact_digests: Vec<ProviderArtifactDigestV1>,
    senocr_asset_plan: Option<SenocrAssetPlan>,
}

#[derive(Clone, Debug)]
struct SenocrAssetPlan {
    artifact_id_by_asset_name: BTreeMap<String, String>,
    mismatch_reason: Option<String>,
}

#[derive(Clone, Debug)]
struct EvaluationObservation {
    case_id: String,
    provider_id: String,
    configuration_id: String,
    split: BenchmarkSplitV1,
    writer_key: String,
    session_key: String,
    cer: Option<BenchmarkCountMetricV1>,
    wer: Option<BenchmarkCountMetricV1>,
}

struct ProviderSummaryAccumulator {
    provider_id: String,
    configuration_id: String,
    attempted_run_count: u32,
    completed_run_count: u32,
    failed_run_count: u32,
    app_batch_call_wall_ns: Vec<u64>,
    process_create_call_to_handshake_ns: Vec<u64>,
    process_create_call_to_recognition_ns: Vec<u64>,
    process_create_call_to_tree_drain_ns: Vec<u64>,
    job_process_tree_cpu_percent: Vec<f64>,
    peak_job_memory_bytes: Vec<u64>,
    peak_process_memory_bytes: Vec<u64>,
    model_cold_start_ns: Vec<u64>,
    gpu_memory_bytes: Vec<u64>,
}

impl ProviderSummaryAccumulator {
    fn new(provider_id: String, configuration_id: String, maximum_runs: usize) -> io::Result<Self> {
        let mut summary = Self {
            provider_id,
            configuration_id,
            attempted_run_count: 0,
            completed_run_count: 0,
            failed_run_count: 0,
            app_batch_call_wall_ns: Vec::new(),
            process_create_call_to_handshake_ns: Vec::new(),
            process_create_call_to_recognition_ns: Vec::new(),
            process_create_call_to_tree_drain_ns: Vec::new(),
            job_process_tree_cpu_percent: Vec::new(),
            peak_job_memory_bytes: Vec::new(),
            peak_process_memory_bytes: Vec::new(),
            model_cold_start_ns: Vec::new(),
            gpu_memory_bytes: Vec::new(),
        };
        for values in [
            &mut summary.app_batch_call_wall_ns,
            &mut summary.process_create_call_to_handshake_ns,
            &mut summary.process_create_call_to_recognition_ns,
            &mut summary.process_create_call_to_tree_drain_ns,
            &mut summary.peak_job_memory_bytes,
            &mut summary.peak_process_memory_bytes,
            &mut summary.model_cold_start_ns,
            &mut summary.gpu_memory_bytes,
        ] {
            values.try_reserve_exact(maximum_runs)?;
        }
        summary
            .job_process_tree_cpu_percent
            .try_reserve_exact(maximum_runs)?;
        Ok(summary)
    }

    fn observe(&mut self, run: &BenchmarkRunRecordV1) -> io::Result<()> {
        self.attempted_run_count = self
            .attempted_run_count
            .checked_add(1)
            .ok_or_else(|| invalid_data("provider summary attempt count overflow"))?;
        match run.status {
            BenchmarkRunStatusV1::Completed => {
                self.completed_run_count = self
                    .completed_run_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("provider summary completion count overflow"))?;
            }
            BenchmarkRunStatusV1::Failed => {
                self.failed_run_count = self
                    .failed_run_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("provider summary failure count overflow"))?;
            }
        }
        self.app_batch_call_wall_ns
            .push(run.elapsed_app_batch_call_wall_ns);
        if let Some(timing) = &run.timing {
            self.process_create_call_to_handshake_ns
                .push(timing.process_create_call_to_handshake_ns);
            self.process_create_call_to_recognition_ns
                .push(timing.process_create_call_to_recognition_ns);
            self.process_create_call_to_tree_drain_ns
                .push(timing.process_create_call_to_tree_drain_ns);
            if let Some(cold_start) = timing.model_cold_start_ns {
                self.model_cold_start_ns.push(cold_start);
            }
        }
        if let Some(cpu_percent) = run.job_process_tree_cpu_core_equivalent_percent {
            self.job_process_tree_cpu_percent.push(cpu_percent);
        }
        if let Some(resources) = &run.process_resources {
            if let Some(peak) = resources.peak_job_memory_bytes_raw {
                self.peak_job_memory_bytes.push(peak);
            }
            if let Some(peak) = resources.peak_process_memory_bytes_raw {
                self.peak_process_memory_bytes.push(peak);
            }
        }
        if let Some(gpu_bytes) = run.gpu_memory_bytes {
            self.gpu_memory_bytes.push(gpu_bytes);
        }
        Ok(())
    }

    fn finish(mut self) -> io::Result<BenchmarkProviderSummaryV1> {
        let attempted_run_count = self.attempted_run_count;
        Ok(BenchmarkProviderSummaryV1 {
            provider_id: self.provider_id,
            configuration_id: self.configuration_id,
            attempted_run_count: self.attempted_run_count,
            completed_run_count: self.completed_run_count,
            failed_run_count: self.failed_run_count,
            app_batch_call_wall_ns: u64_percentiles(
                &mut self.app_batch_call_wall_ns,
                attempted_run_count,
                "nanoseconds",
                "no provider-call runs were recorded",
            )?,
            process_create_call_to_handshake_ns: u64_percentiles(
                &mut self.process_create_call_to_handshake_ns,
                attempted_run_count,
                "nanoseconds",
                "no completed process handshake phase was observed",
            )?,
            process_create_call_to_recognition_ns: u64_percentiles(
                &mut self.process_create_call_to_recognition_ns,
                attempted_run_count,
                "nanoseconds",
                "no completed process recognition phase was observed",
            )?,
            process_create_call_to_tree_drain_ns: u64_percentiles(
                &mut self.process_create_call_to_tree_drain_ns,
                attempted_run_count,
                "nanoseconds",
                "no completed Job Object tree-drain phase was observed",
            )?,
            job_process_tree_cpu_core_equivalent_percent: f64_percentiles(
                &mut self.job_process_tree_cpu_percent,
                attempted_run_count,
                "core_equivalent_percent",
                "no completed Job Object CPU counters and matching wall interval were available",
            )?,
            peak_job_memory_bytes_raw: u64_percentiles(
                &mut self.peak_job_memory_bytes,
                attempted_run_count,
                "PeakJobMemoryUsed_bytes_raw",
                "Windows did not return a usable PeakJobMemoryUsed value",
            )?,
            peak_process_memory_bytes_raw: u64_percentiles(
                &mut self.peak_process_memory_bytes,
                attempted_run_count,
                "PeakProcessMemoryUsed_bytes_raw",
                "Windows did not return a usable PeakProcessMemoryUsed value",
            )?,
            model_cold_start_ns: u64_percentiles(
                &mut self.model_cold_start_ns,
                attempted_run_count,
                "nanoseconds",
                "generic M4 protocol reports no measured model initialization phase",
            )?,
            gpu_memory_bytes_raw: u64_percentiles(
                &mut self.gpu_memory_bytes,
                attempted_run_count,
                "bytes_raw",
                "generic provider protocol and Windows Job Objects expose no GPU-memory counter",
            )?,
        })
    }
}

fn u64_percentiles(
    values: &mut [u64],
    attempted_run_count: u32,
    unit: &str,
    empty_reason: &str,
) -> io::Result<BenchmarkU64PercentilesV1> {
    let sample_count = u32::try_from(values.len())
        .map_err(|_| invalid_data("percentile sample count exceeds u32"))?;
    let missing_observation_count = attempted_run_count.saturating_sub(sample_count);
    values.sort_unstable();
    let unavailable_reason = values.is_empty().then(|| empty_reason.to_owned());
    let missing_observation_reason = (missing_observation_count > 0).then(|| {
        "some attempts have no sample; inspect each run row for its specific null reason".to_owned()
    });
    Ok(BenchmarkU64PercentilesV1 {
        unit: unit.to_owned(),
        sample_count,
        missing_observation_count,
        p50: nearest_rank_u64(values, 50),
        p95: nearest_rank_u64(values, 95),
        p99: nearest_rank_u64(values, 99),
        unavailable_reason,
        missing_observation_reason,
    })
}

fn f64_percentiles(
    values: &mut [f64],
    attempted_run_count: u32,
    unit: &str,
    empty_reason: &str,
) -> io::Result<BenchmarkF64PercentilesV1> {
    let sample_count = u32::try_from(values.len())
        .map_err(|_| invalid_data("percentile sample count exceeds u32"))?;
    let missing_observation_count = attempted_run_count.saturating_sub(sample_count);
    values.sort_by(f64::total_cmp);
    let unavailable_reason = values.is_empty().then(|| empty_reason.to_owned());
    let missing_observation_reason = (missing_observation_count > 0).then(|| {
        "some attempts have no sample; inspect each run row for its specific null reason".to_owned()
    });
    Ok(BenchmarkF64PercentilesV1 {
        unit: unit.to_owned(),
        sample_count,
        missing_observation_count,
        p50: nearest_rank_f64(values, 50),
        p95: nearest_rank_f64(values, 95),
        p99: nearest_rank_f64(values, 99),
        unavailable_reason,
        missing_observation_reason,
    })
}

fn nearest_rank_u64(values: &[u64], percentile: u32) -> Option<u64> {
    let rank = nearest_rank_index(values.len(), percentile)?;
    values.get(rank).copied()
}

fn nearest_rank_f64(values: &[f64], percentile: u32) -> Option<f64> {
    let rank = nearest_rank_index(values.len(), percentile)?;
    values.get(rank).copied()
}

fn nearest_rank_index(sample_count: usize, percentile: u32) -> Option<usize> {
    if sample_count == 0 || percentile == 0 || percentile > 100 {
        return None;
    }
    let rank_1_based = sample_count
        .checked_mul(percentile as usize)?
        .div_ceil(100)
        .max(1);
    Some(rank_1_based - 1)
}

pub(crate) fn run_batch_cli(
    case_manifest_path: &Path,
    provider_manifest_path: &Path,
    corpus_manifest_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let output_directory = local_benchmark_directory()?;
    let completion = run_batch_cli_inner(
        case_manifest_path,
        provider_manifest_path,
        corpus_manifest_path,
        &output_directory,
    )?;
    println!(
        "Benchmark artifact saved locally: {} ({} run(s), {} failed)",
        completion.artifact_path.display(),
        completion.run_count,
        completion.failure_count
    );
    Ok(())
}

/// Runs the same bounded manifest → journal → provider → artifact path as the
/// CLI while allowing the guarded integration test to own its output folder.
#[cfg(test)]
pub(crate) fn run_batch_cli_to_directory(
    case_manifest_path: &Path,
    provider_manifest_path: &Path,
    corpus_manifest_path: Option<&Path>,
    output_directory: &Path,
) -> Result<BenchmarkBatchCompletionV1, Box<dyn Error>> {
    run_batch_cli_inner(
        case_manifest_path,
        provider_manifest_path,
        corpus_manifest_path,
        output_directory,
    )
}

fn run_batch_cli_inner(
    case_manifest_path: &Path,
    provider_manifest_path: &Path,
    corpus_manifest_path: Option<&Path>,
    output_directory: &Path,
) -> Result<BenchmarkBatchCompletionV1, Box<dyn Error>> {
    let (case_manifest, case_manifest_sha256): (BenchmarkCaseManifestV1, String) =
        read_json_file_with_sha(case_manifest_path, MAX_CASE_MANIFEST_BYTES)?;
    let provider_manifest: BenchmarkProviderManifestV1 =
        read_json_file(provider_manifest_path, MAX_PROVIDER_CONFIG_BYTES)?;
    let corpus_with_sha: Option<(BenchmarkCorpusManifestV1, String)> = corpus_manifest_path
        .map(|path| read_json_file_with_sha(path, MAX_ANNOTATION_BYTES))
        .transpose()?;
    let (corpus_manifest, corpus_manifest_sha256) = match corpus_with_sha {
        Some((manifest, sha256)) => (Some(manifest), Some(sha256)),
        None => (None, None),
    };

    validate_case_manifest(&case_manifest)?;
    if provider_manifest.schema_version != BENCHMARK_SCHEMA_VERSION
        || provider_manifest.providers.is_empty()
        || provider_manifest.providers.len() > MAX_BENCHMARK_PROVIDERS
    {
        return Err(invalid_data("provider manifest version/count is invalid").into());
    }
    if case_manifest.cases.len()
        > MAX_BENCHMARK_RECORDS as usize / provider_manifest.providers.len()
    {
        return Err(invalid_data("case × provider run count exceeds artifact record cap").into());
    }
    let mut provider_input_modalities_by_case = Vec::new();
    provider_input_modalities_by_case.try_reserve_exact(case_manifest.cases.len())?;
    for case in &case_manifest.cases {
        let mut modalities_for_case = Vec::new();
        modalities_for_case.try_reserve_exact(provider_manifest.providers.len())?;
        for provider in &provider_manifest.providers {
            modalities_for_case.push(resolve_provider_input_modalities(
                case,
                provider.requested_input_modalities.as_deref(),
            )?);
        }
        provider_input_modalities_by_case.push(modalities_for_case);
    }
    let annotations = match corpus_manifest.as_ref() {
        Some(corpus) => {
            validate_corpus_manifest(corpus, &case_manifest)?;
            Some(
                corpus
                    .cases
                    .iter()
                    .map(|case| (case.case_id.as_str(), case))
                    .collect::<BTreeMap<_, _>>(),
            )
        }
        None => None,
    };

    let mut providers = Vec::new();
    providers.try_reserve_exact(provider_manifest.providers.len())?;
    let mut provider_keys = BTreeSet::new();
    for provider in provider_manifest.providers {
        validate_provider_spec(&provider)?;
        if !provider_keys.insert((
            provider.provider_id.clone(),
            provider.protocol_configuration.configuration_id.clone(),
        )) {
            return Err(invalid_data("provider/configuration pairs must be unique").into());
        }
        let approved = OperatorApprovedProviderConfig::from_explicit_selection(
            provider.provider_id.clone(),
            provider.executable_path.clone(),
            provider.arguments.clone(),
            provider.protocol_configuration.clone(),
        )
        .map_err(|error| {
            invalid_data(format!("invalid operator provider configuration: {error}"))
        })?;
        let senocr_asset_plan = senocr_asset_plan_from_manifest(&provider);
        let timeouts = provider
            .timeouts
            .map(ProviderCallTimeouts::from)
            .unwrap_or_default();
        let mut artifact_digests = Vec::new();
        artifact_digests.try_reserve_exact(provider.artifacts.len())?;
        let mut total_hashed_bytes = 0u64;
        for artifact in provider.artifacts {
            let remaining = MAX_TOTAL_PROVIDER_ARTIFACT_HASH_BYTES
                .checked_sub(total_hashed_bytes)
                .ok_or_else(|| invalid_data("provider artifact total hash cap exceeded"))?;
            let digest = hash_operator_artifact(artifact, remaining)?;
            total_hashed_bytes = total_hashed_bytes
                .checked_add(digest.byte_count)
                .ok_or_else(|| invalid_data("provider artifact total byte count overflow"))?;
            artifact_digests.push(digest);
        }
        providers.push(PreparedBenchmarkProvider {
            provider_id: provider.provider_id,
            configuration_id: provider.protocol_configuration.configuration_id.clone(),
            configuration: provider.protocol_configuration,
            approved,
            timeouts,
            artifact_digests,
            senocr_asset_plan,
        });
    }

    let mut provider_summary_accumulators =
        BTreeMap::<(String, String), ProviderSummaryAccumulator>::new();
    for provider in &providers {
        let summary = ProviderSummaryAccumulator::new(
            provider.provider_id.clone(),
            provider.configuration_id.clone(),
            case_manifest.cases.len(),
        )?;
        provider_summary_accumulators.insert(
            (
                provider.provider_id.clone(),
                provider.configuration_id.clone(),
            ),
            summary,
        );
    }

    let mut writer = BenchmarkArtifactWriter::create_at(
        output_directory,
        &case_manifest.batch_id,
        &case_manifest_sha256,
        corpus_manifest_sha256,
    )?;
    let partial_path = writer.partial_path.clone();
    let processing = (|| -> Result<BenchmarkBatchCompletionV1, Box<dyn Error>> {
        let mut evaluation_observations = Vec::new();
        if annotations.is_some() {
            evaluation_observations
                .try_reserve(case_manifest.cases.len().saturating_mul(providers.len()))?;
        }
        let mut canonical_case_bindings = BTreeMap::<
            String,
            (
                ProviderSourceRevisionV1,
                BenchmarkCanonicalInkComparisonBindingV1,
            ),
        >::new();
        for (case_index, case) in case_manifest.cases.iter().enumerate() {
            let journal = read_journal(&case.journal_path)?;
            if journal.recovery.truncated_final_record {
                return Err(invalid_data(format!(
                    "case {} journal has a truncated final record; correct/review it before benchmarking",
                    case.case_id
                ))
                .into());
            }
            let source_revision = ProviderSourceRevisionV1::from_journal(&journal.state);
            if source_revision != case.expected_source_revision {
                return Err(invalid_data(format!(
                    "case {} source revision does not match the current journal prefix",
                    case.case_id
                ))
                .into());
            }
            let mut selected_strokes = Vec::new();
            selected_strokes.try_reserve_exact(case.selected_strokes.len())?;
            selected_strokes.extend(case.selected_strokes.iter().map(StrokeRef::from));
            let modalities_for_case = &provider_input_modalities_by_case[case_index];
            let raster_is_selected = modalities_for_case
                .iter()
                .any(|modalities| modalities.contains(&ProviderInputCapabilityV1::Raster));
            let raster = if raster_is_selected {
                match (&case.raster, &case.generated_raster) {
                    (Some(file_spec), None) => Some(read_raster_input(file_spec)?),
                    (None, Some(generated_spec)) => Some(materialize_generated_raster(
                        &journal.state,
                        &source_revision,
                        &selected_strokes,
                        generated_spec,
                    )?),
                    (None, None) => {
                        return Err(invalid_data(
                            "a provider selected raster without a case raster source",
                        )
                        .into());
                    }
                    (Some(_), Some(_)) => {
                        return Err(invalid_data(
                            "file raster and generated raster sources are mutually exclusive",
                        )
                        .into());
                    }
                }
            } else {
                None
            };
            let annotation = annotations
                .as_ref()
                .and_then(|items| items.get(case.case_id.as_str()).copied());

            for (provider_index, provider) in providers.iter().enumerate() {
                let request_id = format!(
                    "bench-{}-{case_index}-{provider_index}",
                    case_manifest.batch_id
                );
                let requested_input_modalities = modalities_for_case[provider_index].clone();
                let requested_raster =
                    if requested_input_modalities.contains(&ProviderInputCapabilityV1::Raster) {
                        raster.as_ref().map(|value| value.request_input.clone())
                    } else {
                        None
                    };
                let request = build_recognition_request(RecognitionRequestBuildInput {
                    state: &journal.state,
                    request_id,
                    region_id: case.region_id.clone(),
                    line_id: case.line_id.clone(),
                    coordinate_space: case.coordinate_space.clone(),
                    coordinate_units: case.coordinate_units.clone(),
                    language_hints: case.language_hints.clone(),
                    requested_input_modalities,
                    provider_configuration: provider.configuration.clone(),
                    selected_strokes: &selected_strokes,
                    raster: requested_raster,
                })
                .map_err(|error| {
                    invalid_data(format!("case {} request invalid: {error}", case.case_id))
                })?;
                if request.source_revision != source_revision {
                    return Err(
                        invalid_data("built request changed the exact source revision").into(),
                    );
                }
                let canonical_ink_comparison_binding = canonical_ink_comparison_binding(&request)?;
                if let Some(annotation) = annotation {
                    validate_delayed_mark_links(annotation, &request)?;
                }
                match canonical_case_bindings.get(&case.case_id) {
                    Some((known_revision, known_binding))
                        if known_revision != &request.source_revision
                            || known_binding != &canonical_ink_comparison_binding =>
                    {
                        return Err(invalid_data(format!(
                            "provider requests for case {} do not share one canonical-ink binding",
                            case.case_id
                        ))
                        .into());
                    }
                    Some(_) => {}
                    None => {
                        canonical_case_bindings.insert(
                            case.case_id.clone(),
                            (
                                request.source_revision.clone(),
                                canonical_ink_comparison_binding.clone(),
                            ),
                        );
                    }
                }
                let mut source_sample_sequences = Vec::new();
                source_sample_sequences.try_reserve_exact(request.samples.len())?;
                source_sample_sequences
                    .extend(request.samples.iter().map(|sample| sample.journal_sequence));
                let selected_strokes = benchmark_selected_strokes_from_request(&request)?;
                let generated_raster_origin = generated_raster_origin_for_request(
                    &request,
                    raster.as_ref(),
                    &canonical_ink_comparison_binding,
                    &selected_strokes,
                )?;
                let (raster_input_byte_count, raster_input_sha256) = raster_provenance_for_request(
                    &request.requested_input_modalities,
                    raster.as_ref(),
                )?;
                let base = BenchmarkRunBase {
                    case,
                    region_id: case.region_id.clone(),
                    line_id: case.line_id.clone(),
                    coordinate_space: case.coordinate_space.clone(),
                    coordinate_units: case.coordinate_units.clone(),
                    language_hints: case.language_hints.clone(),
                    raster_input_byte_count,
                    raster_input_sha256,
                    source_revision: request.source_revision.clone(),
                    input_view_id: request.input_view_id.clone(),
                    canonical_ink_comparison_binding,
                    generated_raster_origin,
                    requested_input_modalities: request.requested_input_modalities.clone(),
                    selected_strokes,
                    source_sample_sequences,
                    provider,
                    provider_configuration_id: request
                        .provider_configuration
                        .configuration_id
                        .clone(),
                    provider_configuration_fingerprint: request
                        .provider_configuration_fingerprint
                        .clone(),
                };
                let run_started = Instant::now();
                let outcome = execute_provider(provider, request);
                let elapsed_app_batch_call_wall_ns = elapsed_app_ns(run_started);
                let record = match outcome {
                    Ok(execution) => successful_run_record(
                        base,
                        execution,
                        elapsed_app_batch_call_wall_ns,
                        annotation,
                        corpus_manifest
                            .as_ref()
                            .map(|corpus| corpus.tokenization_policy),
                    )?,
                    Err(error) => {
                        failed_run_record(base, error, elapsed_app_batch_call_wall_ns, annotation)?
                    }
                };
                if let (Some(_annotation), Some(split)) = (annotation, case.provenance.split) {
                    let first = record.candidate_metrics.first();
                    evaluation_observations.push(EvaluationObservation {
                        case_id: case.case_id.clone(),
                        provider_id: provider.provider_id.clone(),
                        configuration_id: provider.approved_configuration_id().to_owned(),
                        split,
                        writer_key: case.provenance.writer_key.clone(),
                        session_key: case.provenance.session_key.clone(),
                        cer: first.and_then(|metrics| metrics.nfc_unicode_scalar_cer.clone()),
                        wer: first
                            .and_then(|metrics| metrics.whitespace_token_syllable_wer.clone()),
                    });
                }
                let summary_key = (
                    provider.provider_id.clone(),
                    provider.configuration_id.clone(),
                );
                provider_summary_accumulators
                    .get_mut(&summary_key)
                    .ok_or_else(|| invalid_data("provider summary accumulator is missing"))?
                    .observe(&record)?;
                writer.write_run(record)?;
            }
        }

        let paired_comparisons = match corpus_manifest.as_ref() {
            Some(corpus) => build_paired_comparisons(&evaluation_observations, corpus)?,
            None => Vec::new(),
        };
        let mut provider_summaries = Vec::new();
        provider_summaries.try_reserve_exact(provider_summary_accumulators.len())?;
        for summary in provider_summary_accumulators.into_values() {
            provider_summaries.push(summary.finish()?);
        }
        Ok(writer.finish(
            case_manifest.cases.len(),
            providers.len(),
            paired_comparisons,
            provider_summaries,
            corpus_manifest.as_ref(),
        )?)
    })();
    let completion = match processing {
        Ok(completion) => completion,
        Err(error) => {
            eprintln!(
                "Benchmark artifact remains recoverable as partial output at {}",
                partial_path.display()
            );
            return Err(error);
        }
    };
    Ok(completion)
}

impl PreparedBenchmarkProvider {
    fn approved_configuration_id(&self) -> &str {
        &self.configuration_id
    }
}

struct BenchmarkRunBase<'a> {
    case: &'a BenchmarkCaseSpecV1,
    region_id: String,
    line_id: String,
    coordinate_space: String,
    coordinate_units: String,
    language_hints: Vec<String>,
    raster_input_byte_count: Option<u64>,
    raster_input_sha256: Option<String>,
    source_revision: ProviderSourceRevisionV1,
    input_view_id: String,
    canonical_ink_comparison_binding: BenchmarkCanonicalInkComparisonBindingV1,
    generated_raster_origin: Option<BenchmarkGeneratedRasterOriginV1>,
    requested_input_modalities: Vec<ProviderInputCapabilityV1>,
    selected_strokes: Vec<BenchmarkStrokeRefV1>,
    source_sample_sequences: Vec<u64>,
    provider: &'a PreparedBenchmarkProvider,
    provider_configuration_id: String,
    provider_configuration_fingerprint: String,
}

fn execute_provider(
    provider: &PreparedBenchmarkProvider,
    request: RecognitionRequestV1,
) -> Result<ProviderExecution, ProviderExecutionError> {
    let request_id = request.request_id.clone();
    let worker = ProviderWorkerHandle::start(provider.approved.clone(), provider.timeouts)
        .map_err(empty_execution_error)?;
    worker.try_submit(request).map_err(|error| {
        let kind = match error {
            ProviderSubmitError::Backpressure(_) => ProviderErrorKind::WorkerCapacityReached,
            ProviderSubmitError::Stopped(_) => ProviderErrorKind::WorkerSubsystemPoisoned,
            ProviderSubmitError::Invalid(kind) => kind,
        };
        empty_execution_error(kind)
    })?;
    let deadline = Instant::now() + MAX_PROVIDER_RESULTS_WAIT;
    loop {
        match worker.try_receive() {
            ProviderWorkerPoll::Outcome(outcome) => {
                if outcome.request_id != request_id {
                    let (stderr_bytes, stderr_truncated, raw_response_transcript) =
                        match outcome.outcome {
                            Ok(execution) => (
                                execution.stderr_bytes,
                                execution.stderr_truncated,
                                execution.raw_response_transcript,
                            ),
                            Err(error) => (
                                error.stderr_bytes,
                                error.stderr_truncated,
                                error.raw_response_transcript,
                            ),
                        };
                    return Err(ProviderExecutionError {
                        kind: ProviderErrorKind::ProviderRequestMismatch,
                        stderr_bytes,
                        stderr_truncated,
                        raw_response_transcript,
                    });
                }
                return outcome.outcome;
            }
            ProviderWorkerPoll::Stopped => {
                return Err(empty_execution_error(
                    ProviderErrorKind::WorkerSubsystemPoisoned,
                ));
            }
            ProviderWorkerPoll::Pending => {
                if Instant::now() >= deadline {
                    worker.cancel();
                    return Err(empty_execution_error(ProviderErrorKind::TimedOut(
                        crate::provider_protocol::ProviderPhase::Recognition,
                    )));
                }
                thread::sleep(IO_POLL_INTERVAL);
            }
        }
    }
}

fn empty_execution_error(kind: ProviderErrorKind) -> ProviderExecutionError {
    ProviderExecutionError {
        kind,
        stderr_bytes: Vec::new(),
        stderr_truncated: false,
        raw_response_transcript: ProviderRawResponseTranscriptV1::default(),
    }
}

fn successful_run_record(
    base: BenchmarkRunBase<'_>,
    execution: ProviderExecution,
    elapsed_app_batch_call_wall_ns: u64,
    annotation: Option<&BenchmarkAnnotationCaseV1>,
    tokenization_policy: Option<BenchmarkTokenizationPolicyV1>,
) -> Result<BenchmarkRunRecordV1, io::Error> {
    let quality_evidence = benchmark_quality_evidence(base.provider, Some(&execution.provider))?;
    let (candidate_metrics, metric_evaluation_unavailable_reason) =
        candidate_metrics_for_quality_evidence(
            &execution.result,
            annotation,
            tokenization_policy,
            &quality_evidence,
        );
    let transcript = execution.raw_response_transcript;
    let raw_response_frames = encode_response_frames(transcript.frames)?;
    let (model_artifact_digests, model_artifact_hash_unavailable_reason) =
        model_artifact_hash_status(&base.provider.artifact_digests)?;
    let (job_cpu_ratio, job_cpu_ratio_unavailable_reason) = job_cpu_core_equivalent_percent(
        execution.process_resources.as_ref(),
        Some(&execution.timing),
    );
    let run = BenchmarkRunRecordV1 {
        case_id: base.case.case_id.clone(),
        region_id: base.region_id,
        line_id: base.line_id,
        coordinate_space: base.coordinate_space,
        coordinate_units: base.coordinate_units,
        language_hints: base.language_hints,
        raster_input_byte_count: base.raster_input_byte_count,
        raster_input_sha256: base.raster_input_sha256,
        corpus_id: base.case.provenance.corpus_id.clone(),
        annotation_id: base.case.provenance.annotation_id.clone(),
        reference_language_scope: annotation.map(|value| value.reference_language_scope),
        writer_key: base.case.provenance.writer_key.clone(),
        session_key: base.case.provenance.session_key.clone(),
        declared_session_start_unix_ns: base.case.provenance.session_start_unix_ns,
        configuration_key: base.case.provenance.configuration_key.clone(),
        split: base.case.provenance.split,
        declared_capture_api: base.case.provenance.capture_api.clone(),
        declared_capture_api_version: base.case.provenance.capture_api_version.clone(),
        declared_tablet_model: base.case.provenance.tablet_model.clone(),
        declared_driver_version: base.case.provenance.driver_version.clone(),
        declared_windows_build: base.case.provenance.windows_build.clone(),
        declared_windows_ink_state: base.case.provenance.windows_ink_state.clone(),
        declared_active_area: base.case.provenance.active_area.clone(),
        declared_display_mapping: base.case.provenance.display_mapping.clone(),
        declared_pressure_curve: base.case.provenance.pressure_curve.clone(),
        source_revision: base.source_revision,
        input_view_id: base.input_view_id,
        canonical_ink_comparison_binding: Some(base.canonical_ink_comparison_binding),
        generated_raster_origin: base.generated_raster_origin,
        requested_input_modalities: base.requested_input_modalities,
        selected_strokes: base.selected_strokes,
        source_sample_sequences: base.source_sample_sequences,
        provider_id: base.provider.provider_id.clone(),
        provider_identity: Some(execution.provider),
        provider_capabilities: Some(execution.capabilities),
        provider_configuration_id: base.provider_configuration_id,
        provider_configuration_fingerprint: base.provider_configuration_fingerprint,
        artifact_digests: base.provider.artifact_digests.clone(),
        model_artifact_digests,
        model_artifact_hash_unavailable_reason,
        quality_evidence,
        elapsed_app_batch_call_wall_ns,
        timing: Some(execution.timing),
        timing_unavailable_reason: None,
        process_resources: execution.process_resources,
        process_resources_unavailable_reason: None,
        job_process_tree_cpu_core_equivalent_percent: job_cpu_ratio,
        job_cpu_ratio_unavailable_reason,
        gpu_memory_bytes: None,
        gpu_memory_unavailable_reason: Some(
            "the generic provider protocol and Windows Job Object counters expose no GPU-memory measurement"
                .to_owned(),
        ),
        result: Some(execution.result),
        candidate_metrics,
        metric_evaluation_unavailable_reason,
        raw_response_frames,
        raw_response_capture_complete: transcript.capture_complete,
        raw_response_omitted_frame_count: transcript.omitted_frame_count,
        raw_response_omitted_payload_bytes: transcript.omitted_payload_bytes,
        stderr_byte_count: execution.stderr_bytes.len() as u64,
        stderr_truncated: execution.stderr_truncated,
        status: BenchmarkRunStatusV1::Completed,
        failure_category: None,
    };
    let mut run = run;
    if run.process_resources.is_none() {
        run.process_resources_unavailable_reason = Some(
            "Job Object resource counters were not returned after observed tree completion"
                .to_owned(),
        );
    }
    Ok(run)
}

fn candidate_metrics_for_quality_evidence(
    result: &RecognitionResultV1,
    annotation: Option<&BenchmarkAnnotationCaseV1>,
    tokenization_policy: Option<BenchmarkTokenizationPolicyV1>,
    quality_evidence: &BenchmarkQualityEvidenceV1,
) -> (Vec<BenchmarkCandidateMetricsV1>, Option<String>) {
    if !quality_metrics_allowed(quality_evidence) {
        return (
            Vec::new(),
            quality_evidence.unavailable_reason.clone().or_else(|| {
                Some(
                    "text metrics withheld because runtime/model evidence is not quality-eligible"
                        .to_owned(),
                )
            }),
        );
    }
    match (annotation, tokenization_policy) {
        (Some(_), Some(_)) if result.candidates.is_empty() => (
            Vec::new(),
            Some("text metrics unavailable because provider returned no rank-0 candidate".to_owned()),
        ),
        (Some(annotation), Some(policy)) => match score_candidates(result, annotation, policy) {
            Ok(metrics) => (metrics, None),
            Err(error) => (
                Vec::new(),
                Some(format!(
                    "text metrics unavailable; provider result and raw response are preserved: {error}"
                )),
            ),
        },
        _ => (Vec::new(), None),
    }
}

fn failed_run_record(
    base: BenchmarkRunBase<'_>,
    error: ProviderExecutionError,
    elapsed_app_batch_call_wall_ns: u64,
    annotation: Option<&BenchmarkAnnotationCaseV1>,
) -> Result<BenchmarkRunRecordV1, io::Error> {
    let category = failure_category(&error.kind);
    let transcript = error.raw_response_transcript;
    let quality_evidence = benchmark_quality_evidence(base.provider, None)?;
    let (model_artifact_digests, model_artifact_hash_unavailable_reason) =
        model_artifact_hash_status(&base.provider.artifact_digests)?;
    Ok(BenchmarkRunRecordV1 {
        case_id: base.case.case_id.clone(),
        region_id: base.region_id,
        line_id: base.line_id,
        coordinate_space: base.coordinate_space,
        coordinate_units: base.coordinate_units,
        language_hints: base.language_hints,
        raster_input_byte_count: base.raster_input_byte_count,
        raster_input_sha256: base.raster_input_sha256,
        corpus_id: base.case.provenance.corpus_id.clone(),
        annotation_id: base.case.provenance.annotation_id.clone(),
        reference_language_scope: annotation.map(|value| value.reference_language_scope),
        writer_key: base.case.provenance.writer_key.clone(),
        session_key: base.case.provenance.session_key.clone(),
        declared_session_start_unix_ns: base.case.provenance.session_start_unix_ns,
        configuration_key: base.case.provenance.configuration_key.clone(),
        split: base.case.provenance.split,
        declared_capture_api: base.case.provenance.capture_api.clone(),
        declared_capture_api_version: base.case.provenance.capture_api_version.clone(),
        declared_tablet_model: base.case.provenance.tablet_model.clone(),
        declared_driver_version: base.case.provenance.driver_version.clone(),
        declared_windows_build: base.case.provenance.windows_build.clone(),
        declared_windows_ink_state: base.case.provenance.windows_ink_state.clone(),
        declared_active_area: base.case.provenance.active_area.clone(),
        declared_display_mapping: base.case.provenance.display_mapping.clone(),
        declared_pressure_curve: base.case.provenance.pressure_curve.clone(),
        source_revision: base.source_revision,
        input_view_id: base.input_view_id,
        canonical_ink_comparison_binding: Some(base.canonical_ink_comparison_binding),
        generated_raster_origin: base.generated_raster_origin,
        requested_input_modalities: base.requested_input_modalities,
        selected_strokes: base.selected_strokes,
        source_sample_sequences: base.source_sample_sequences,
        provider_id: base.provider.provider_id.clone(),
        provider_identity: None,
        provider_capabilities: None,
        provider_configuration_id: base.provider_configuration_id,
        provider_configuration_fingerprint: base.provider_configuration_fingerprint,
        artifact_digests: base.provider.artifact_digests.clone(),
        model_artifact_digests,
        model_artifact_hash_unavailable_reason,
        quality_evidence,
        elapsed_app_batch_call_wall_ns,
        timing: None,
        timing_unavailable_reason: Some(
            "complete process-phase checkpoints were not returned; app provider-call wall time remains available"
                .to_owned(),
        ),
        process_resources: None,
        process_resources_unavailable_reason: Some(
            "the worker did not return a completed Job Object tree measurement".to_owned(),
        ),
        job_process_tree_cpu_core_equivalent_percent: None,
        job_cpu_ratio_unavailable_reason: Some(
            "no completed Job Object CPU counters and matching runner interval were returned"
                .to_owned(),
        ),
        gpu_memory_bytes: None,
        gpu_memory_unavailable_reason: Some(
            "the generic provider protocol and Windows Job Object counters expose no GPU-memory measurement"
                .to_owned(),
        ),
        result: None,
        candidate_metrics: Vec::new(),
        metric_evaluation_unavailable_reason: Some(
            "provider did not return a valid recognition result".to_owned(),
        ),
        raw_response_frames: encode_response_frames(transcript.frames)?,
        raw_response_capture_complete: transcript.capture_complete,
        raw_response_omitted_frame_count: transcript.omitted_frame_count,
        raw_response_omitted_payload_bytes: transcript.omitted_payload_bytes,
        stderr_byte_count: error.stderr_bytes.len() as u64,
        stderr_truncated: error.stderr_truncated,
        status: BenchmarkRunStatusV1::Failed,
        failure_category: Some(category),
    })
}

fn job_cpu_core_equivalent_percent(
    resources: Option<&ProviderProcessResourcesV1>,
    timing: Option<&crate::provider_protocol::ProviderExecutionTimingV1>,
) -> (Option<f64>, Option<String>) {
    let (Some(resources), Some(timing)) = (resources, timing) else {
        return (
            None,
            Some("completed Job Object counters or wall interval are unavailable".to_owned()),
        );
    };
    if resources.scope != crate::provider_protocol::ProviderResourceScopeV1::JobProcessTree {
        return (
            None,
            Some("resource scope is not the provider Job Object process tree".to_owned()),
        );
    }
    if resources.total_user_time_100ns_raw < 0 || resources.total_kernel_time_100ns_raw < 0 {
        return (
            None,
            Some("raw Job Object CPU counter is negative".to_owned()),
        );
    }
    let Some(total_cpu_100ns) = u128::try_from(resources.total_user_time_100ns_raw)
        .ok()
        .and_then(|user| {
            u128::try_from(resources.total_kernel_time_100ns_raw)
                .ok()
                .and_then(|kernel| user.checked_add(kernel))
        })
    else {
        return (
            None,
            Some("raw Job Object CPU counter sum overflowed".to_owned()),
        );
    };
    let Some(cpu_ns) = total_cpu_100ns.checked_mul(100) else {
        return (
            None,
            Some("Job Object CPU nanosecond conversion overflowed".to_owned()),
        );
    };
    let wall_ns = timing.process_create_call_to_tree_drain_ns;
    if wall_ns == 0 {
        return (
            None,
            Some("observed provider wall interval is zero".to_owned()),
        );
    }
    let ratio = (cpu_ns as f64 / wall_ns as f64) * 100.0;
    if ratio.is_finite() {
        (Some(ratio), None)
    } else {
        (
            None,
            Some("derived Job Object core-equivalent ratio is non-finite".to_owned()),
        )
    }
}

fn model_artifact_hash_status(
    artifact_digests: &[ProviderArtifactDigestV1],
) -> io::Result<(Vec<ProviderArtifactDigestV1>, Option<String>)> {
    let model_artifact_count = artifact_digests
        .iter()
        .filter(|artifact| artifact.role == ProviderArtifactRoleV1::Model)
        .count();
    let mut model_artifacts = Vec::new();
    model_artifacts.try_reserve_exact(model_artifact_count)?;
    model_artifacts.extend(
        artifact_digests
            .iter()
            .filter(|artifact| artifact.role == ProviderArtifactRoleV1::Model)
            .cloned(),
    );
    let reason = model_artifacts.is_empty().then(|| {
        "no operator-enumerated Model artifact was hashed; executable, tokenizer, resource, and provider-reported model version are not model-content hashes"
            .to_owned()
    });
    Ok((model_artifacts, reason))
}

fn failure_category(kind: &ProviderErrorKind) -> BenchmarkFailureCategoryV1 {
    match kind {
        ProviderErrorKind::InvalidConfiguration(_) => BenchmarkFailureCategoryV1::InvalidConfig,
        ProviderErrorKind::InvalidRequest(_) => BenchmarkFailureCategoryV1::InvalidRequest,
        ProviderErrorKind::UnsupportedPlatform => BenchmarkFailureCategoryV1::UnsupportedPlatform,
        ProviderErrorKind::UnsupportedCapability(_) => {
            BenchmarkFailureCategoryV1::UnsupportedCapability
        }
        ProviderErrorKind::TimedOut(_) => BenchmarkFailureCategoryV1::Timeout,
        ProviderErrorKind::Cancelled => BenchmarkFailureCategoryV1::Cancelled,
        ProviderErrorKind::ProviderFailure { .. } => BenchmarkFailureCategoryV1::ProviderFailure,
        ProviderErrorKind::InvalidResponse(_)
        | ProviderErrorKind::ProtocolVersion { .. }
        | ProviderErrorKind::OversizedFrame { .. }
        | ProviderErrorKind::UnexpectedFrame(_) => BenchmarkFailureCategoryV1::InvalidResponse,
        ProviderErrorKind::WorkerCapacityReached | ProviderErrorKind::WorkerSubsystemPoisoned => {
            BenchmarkFailureCategoryV1::WorkerCapacity
        }
        ProviderErrorKind::ProcessCleanupFailed(_) => BenchmarkFailureCategoryV1::CleanupFailure,
        ProviderErrorKind::WorkerThreadPanicked => BenchmarkFailureCategoryV1::WorkerFailure,
        _ => BenchmarkFailureCategoryV1::Other,
    }
}

fn encode_response_frames(
    frames: Vec<ProviderRawResponseFrameV1>,
) -> Result<Vec<BenchmarkRawResponseFrameHexV1>, io::Error> {
    let mut encoded = Vec::new();
    encoded.try_reserve_exact(frames.len())?;
    for frame in frames {
        let length = u32::try_from(frame.payload_bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "provider response frame exceeds u32",
            )
        })?;
        encoded.push(BenchmarkRawResponseFrameHexV1 {
            ordinal: frame.ordinal,
            length_prefix_be_hex: hex_encode(&length.to_be_bytes())?,
            payload_hex: hex_encode(&frame.payload_bytes)?,
        });
    }
    Ok(encoded)
}

fn elapsed_app_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn validate_case_manifest(manifest: &BenchmarkCaseManifestV1) -> io::Result<()> {
    if manifest.schema_version != BENCHMARK_SCHEMA_VERSION
        || manifest.cases.is_empty()
        || manifest.cases.len() > MAX_BENCHMARK_CASES
    {
        return Err(invalid_data("case manifest version/count is invalid"));
    }
    validate_local_id(&manifest.batch_id, "batch ID")?;
    let mut case_ids = BTreeSet::new();
    for case in &manifest.cases {
        validate_local_id(&case.case_id, "case ID")?;
        if !case_ids.insert(case.case_id.as_str()) {
            return Err(invalid_data("case IDs must be unique"));
        }
        validate_raster_source_declaration(case.raster.as_ref(), case.generated_raster.as_ref())?;
        require_local_absolute_path(&case.journal_path, "journal path")?;
        let journal_metadata = fs::symlink_metadata(&case.journal_path)?;
        if journal_metadata.file_type().is_symlink() || !journal_metadata.is_file() {
            return Err(invalid_data(
                "journal input must be a regular non-symlink file",
            ));
        }
        for (value, label) in [
            (case.region_id.as_str(), "region ID"),
            (case.line_id.as_str(), "line ID"),
            (case.coordinate_space.as_str(), "coordinate space"),
            (case.coordinate_units.as_str(), "coordinate units"),
        ] {
            validate_bounded_text(value, label, 256)?;
        }
        if case.language_hints.is_empty() || case.language_hints.len() > 16 {
            return Err(invalid_data("language hint count is empty or exceeds 16"));
        }
        for language in &case.language_hints {
            validate_bounded_text(language, "language hint", 128)?;
        }
        if case.requested_input_modalities.is_empty() || case.requested_input_modalities.len() > 2 {
            return Err(invalid_data("requested input modality count is invalid"));
        }
        if case.requested_input_modalities.len() == 2
            && case.requested_input_modalities[0] == case.requested_input_modalities[1]
        {
            return Err(invalid_data("requested input modalities must be unique"));
        }
        if case.selected_strokes.is_empty() || case.selected_strokes.len() > 256 {
            return Err(invalid_data(
                "selected StrokeRef count is empty or exceeds 256",
            ));
        }
        for (index, stroke) in case.selected_strokes.iter().enumerate() {
            if case.selected_strokes[..index].contains(stroke) {
                return Err(invalid_data("selected StrokeRefs must be unique"));
            }
        }
        for stroke in &case.selected_strokes {
            for (value, label) in [
                (stroke.journal_id.as_str(), "stroke journal ID"),
                (stroke.session_id.as_str(), "stroke session ID"),
                (stroke.source_api.as_str(), "stroke source API"),
                (stroke.stroke_id.as_str(), "stroke ID"),
            ] {
                validate_bounded_text(value, label, 256)?;
            }
            if let Some(device_id) = &stroke.device_id {
                validate_bounded_text(device_id, "stroke device ID", 256)?;
            }
        }
        validate_bounded_text(&case.provenance.writer_key, "writer key", 256)?;
        validate_bounded_text(&case.provenance.session_key, "session key", 256)?;
        validate_bounded_text(&case.provenance.configuration_key, "configuration key", 256)?;
        for (value, label) in [
            (&case.provenance.corpus_id, "corpus ID"),
            (&case.provenance.annotation_id, "annotation ID"),
            (&case.provenance.capture_api, "capture API"),
            (&case.provenance.capture_api_version, "capture API version"),
            (&case.provenance.tablet_model, "tablet model"),
            (&case.provenance.driver_version, "driver version"),
            (&case.provenance.windows_build, "Windows build"),
            (&case.provenance.windows_ink_state, "Windows Ink state"),
            (&case.provenance.active_area, "active area"),
            (&case.provenance.display_mapping, "display mapping"),
            (&case.provenance.pressure_curve, "pressure curve"),
        ] {
            if let Some(value) = value {
                validate_bounded_text(value, label, 512)?;
            }
        }
        if let Some(raster) = &case.raster {
            require_local_absolute_path(&raster.path, "raster input path")?;
            validate_bounded_text(&raster.coordinate_space, "raster coordinate space", 256)?;
            validate_bounded_text(&raster.units, "raster units", 256)?;
        }
    }
    Ok(())
}

fn validate_raster_source_declaration(
    file_raster: Option<&BenchmarkRasterInputSpecV1>,
    generated_raster: Option<&BenchmarkGeneratedRasterSpecV1>,
) -> io::Result<()> {
    if file_raster.is_some() && generated_raster.is_some() {
        return Err(invalid_data(
            "file raster and generated raster sources are mutually exclusive",
        ));
    }
    if let Some(spec) = generated_raster {
        validate_generated_raster_spec(spec)?;
    }
    Ok(())
}

fn validate_generated_raster_spec(spec: &BenchmarkGeneratedRasterSpecV1) -> io::Result<()> {
    if spec.projection_schema_version != 1
        || spec.output_width_px == 0
        || spec.output_height_px == 0
        || spec.output_width_px > MAX_GENERATED_RASTER_OUTPUT_DIMENSION
        || spec.output_height_px > MAX_GENERATED_RASTER_OUTPUT_DIMENSION
    {
        return Err(invalid_data(
            "generated raster projection version or output dimensions are unsupported",
        ));
    }
    let output_pixels = u64::from(spec.output_width_px)
        .checked_mul(u64::from(spec.output_height_px))
        .ok_or_else(|| invalid_data("generated raster output pixel count overflowed"))?;
    let output_bytes = output_pixels
        .checked_mul(4)
        .ok_or_else(|| invalid_data("generated raster output byte count overflowed"))?;
    if output_pixels > MAX_GENERATED_RASTER_OUTPUT_PIXELS
        || output_bytes > MAX_GENERATED_RASTER_OUTPUT_BYTES
    {
        return Err(invalid_data(
            "generated raster output exceeds the canonical pixel or byte cap",
        ));
    }

    let crop_width =
        i128::from(spec.source_crop.right_px_exclusive) - i128::from(spec.source_crop.left_px);
    let crop_height =
        i128::from(spec.source_crop.bottom_px_exclusive) - i128::from(spec.source_crop.top_px);
    if crop_width <= 0
        || crop_height <= 0
        || crop_width > MAX_GENERATED_RASTER_CROP_DIMENSION
        || crop_height > MAX_GENERATED_RASTER_CROP_DIMENSION
    {
        return Err(invalid_data(
            "generated raster source crop is empty, reversed, or exceeds its dimension cap",
        ));
    }
    let crop_area = crop_width
        .checked_mul(crop_height)
        .ok_or_else(|| invalid_data("generated raster crop area overflowed"))?;
    if crop_area > MAX_GENERATED_RASTER_CROP_AREA {
        return Err(invalid_data(
            "generated raster source crop exceeds its area cap",
        ));
    }
    Ok(())
}

fn case_has_raster_source(case: &BenchmarkCaseSpecV1) -> bool {
    case.raster.is_some() || case.generated_raster.is_some()
}

fn validate_provider_input_modalities(modalities: &[ProviderInputCapabilityV1]) -> io::Result<()> {
    if modalities.is_empty() || modalities.len() > MAX_BENCHMARK_INPUT_MODALITIES {
        return Err(invalid_data(
            "provider input modality count is empty or exceeds 2",
        ));
    }
    for (index, modality) in modalities.iter().enumerate() {
        if modalities[..index].contains(modality) {
            return Err(invalid_data("provider input modalities must be unique"));
        }
    }
    Ok(())
}

/// Resolve the request modes solely from the case's available input data or
/// the provider's explicit override. Provider capabilities never imply a
/// fallback or change this selection.
fn resolve_provider_input_modalities(
    case: &BenchmarkCaseSpecV1,
    provider_modalities: Option<&[ProviderInputCapabilityV1]>,
) -> io::Result<Vec<ProviderInputCapabilityV1>> {
    validate_raster_source_declaration(case.raster.as_ref(), case.generated_raster.as_ref())?;
    let has_provider_override = provider_modalities.is_some();
    let resolved = provider_modalities.unwrap_or(&case.requested_input_modalities);
    validate_provider_input_modalities(resolved)?;

    if !has_provider_override {
        let legacy_requests_raster = case
            .requested_input_modalities
            .contains(&ProviderInputCapabilityV1::Raster);
        if case_has_raster_source(case) && !legacy_requests_raster {
            return Err(invalid_data(
                "raster source is present but raster modality was not requested",
            ));
        }
        if !case_has_raster_source(case) && legacy_requests_raster {
            return Err(invalid_data(
                "raster modality was requested without an explicit raster source",
            ));
        }
    }

    for modality in resolved {
        match *modality {
            ProviderInputCapabilityV1::OnlineStrokes if case.selected_strokes.is_empty() => {
                return Err(invalid_data(
                    "provider selected online strokes without case stroke data",
                ));
            }
            ProviderInputCapabilityV1::Raster if !case_has_raster_source(case) => {
                return Err(invalid_data(
                    "provider selected raster without case raster source",
                ));
            }
            _ => {}
        }
    }

    let mut modalities = Vec::new();
    modalities.try_reserve_exact(resolved.len())?;
    modalities.extend_from_slice(resolved);
    Ok(modalities)
}

fn senocr_evidence_candidate(
    provider_id: &str,
    configuration_id: &str,
    identity: Option<&ProviderIdentityV1>,
) -> bool {
    provider_id == SENOCR_REFERENCE_PROVIDER_ID
        || configuration_id == SENOCR_REFERENCE_CONFIGURATION_ID
        || identity.is_some_and(|value| value.provider_id == SENOCR_REFERENCE_PROVIDER_ID)
}

/// Retain only an in-memory basename→operator artifact-ID map. Paths are used
/// for strict association checks and are never copied into benchmark evidence.
fn senocr_asset_plan_from_manifest(
    provider: &ApprovedBenchmarkProviderV1,
) -> Option<SenocrAssetPlan> {
    if !senocr_evidence_candidate(
        &provider.provider_id,
        &provider.protocol_configuration.configuration_id,
        None,
    ) {
        return None;
    }

    let mut mismatch_reason = None;
    if provider.protocol_configuration.configuration_id != SENOCR_REFERENCE_CONFIGURATION_ID {
        mismatch_reason = Some(
            "SenOCR evidence requires the fixed operator configuration ID".to_owned(),
        );
    }
    let values = &provider.protocol_configuration.values;
    let model_root = values
        .get("asset_root")
        .map(|value| PathBuf::from(value.as_str()));
    if values.len() != 3
        || values.get("model_id").map(String::as_str) != Some("VietAlphaLabs/SenOCR-Vi")
        || values.get("model_revision").map(String::as_str)
            != Some(SENOCR_REFERENCE_MODEL_REVISION)
        || model_root
            .as_deref()
            .is_none_or(|path| require_local_absolute_path(path, "SenOCR model asset root").is_err())
    {
        mismatch_reason.get_or_insert_with(|| {
            "SenOCR model configuration does not match the fixed local reference model".to_owned()
        });
    }

    let mut artifact_id_by_asset_name = BTreeMap::new();
    for artifact in &provider.artifacts {
        if artifact.role == ProviderArtifactRoleV1::Executable {
            if artifact.path != provider.executable_path {
                mismatch_reason.get_or_insert_with(|| {
                    "SenOCR artifact manifest contains an unexpected executable entry".to_owned()
                });
            }
            continue;
        }

        let asset_name = artifact.path.file_name().and_then(|name| name.to_str());
        let Some((expected_name, _expected_bytes)) = asset_name.and_then(|name| {
            SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES
                .iter()
                .find(|(expected_name, _)| *expected_name == name)
        }) else {
            mismatch_reason.get_or_insert_with(|| {
                "SenOCR artifact manifest contains an unrecognized non-executable asset".to_owned()
            });
            continue;
        };
        let root_matches = model_root
            .as_deref()
            .is_some_and(|root| artifact.path.parent() == Some(root));
        if !root_matches {
            mismatch_reason.get_or_insert_with(|| {
                "SenOCR asset observations are not bound to the configured asset directory"
                    .to_owned()
            });
            continue;
        }
        if artifact_id_by_asset_name
            .insert((*expected_name).to_owned(), artifact.artifact_id.clone())
            .is_some()
        {
            mismatch_reason.get_or_insert_with(|| {
                "SenOCR artifact manifest maps multiple paths to one required asset".to_owned()
            });
        }
    }

    Some(SenocrAssetPlan {
        artifact_id_by_asset_name,
        mismatch_reason,
    })
}

fn senocr_model_asset_coverage(
    plan: Option<&SenocrAssetPlan>,
    artifact_digests: &[ProviderArtifactDigestV1],
) -> io::Result<BenchmarkModelAssetCoverageV1> {
    let mut observed_assets = Vec::new();
    let mut missing_asset_names = Vec::new();
    let mut size_mismatch = false;
    observed_assets.try_reserve_exact(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len())?;
    missing_asset_names.try_reserve_exact(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len())?;
    let Some(plan) = plan else {
        for (name, _) in SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES {
            missing_asset_names.push(name.to_owned());
        }
        return Ok(BenchmarkModelAssetCoverageV1 {
            model_revision: SENOCR_REFERENCE_MODEL_REVISION.to_owned(),
            required_asset_count: SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len() as u32,
            observed_asset_count: 0,
            missing_asset_names,
            observed_assets,
            status: BenchmarkModelAssetCoverageStatusV1::IncompletePrelaunchObservations,
            observation_scope: "bounded prelaunch SHA-256 observations of operator-enumerated required asset paths; not authenticity, loaded-file identity, or a TOCTOU guarantee".to_owned(),
        });
    };
    for (asset_name, expected_byte_count) in SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES {
        let digest = plan
            .artifact_id_by_asset_name
            .get(asset_name)
            .and_then(|artifact_id| {
                artifact_digests
                    .iter()
                    .find(|artifact| artifact.artifact_id == *artifact_id)
            });
        let Some(digest) = digest.filter(|digest| {
            digest.role != ProviderArtifactRoleV1::Executable
                && validate_sha256_hex(&digest.sha256_hex, "SenOCR asset observation").is_ok()
        }) else {
            missing_asset_names.push(asset_name.to_owned());
            continue;
        };
        size_mismatch |= digest.byte_count != expected_byte_count;
        observed_assets.push(BenchmarkModelAssetObservationV1 {
            asset_name: asset_name.to_owned(),
            expected_byte_count,
            observed_byte_count: digest.byte_count,
            observed_sha256_hex: digest.sha256_hex.clone(),
        });
    }
    let status = if plan.mismatch_reason.is_some() || size_mismatch {
        BenchmarkModelAssetCoverageStatusV1::MismatchedPrelaunchManifest
    } else if !missing_asset_names.is_empty() {
        BenchmarkModelAssetCoverageStatusV1::IncompletePrelaunchObservations
    } else {
        BenchmarkModelAssetCoverageStatusV1::CompletePrelaunchObservations
    };
    Ok(BenchmarkModelAssetCoverageV1 {
        model_revision: SENOCR_REFERENCE_MODEL_REVISION.to_owned(),
        required_asset_count: SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len() as u32,
        observed_asset_count: observed_assets.len() as u32,
        missing_asset_names,
        observed_assets,
        status,
        observation_scope: "complete means all fixed required files had matching configured basenames and expected byte counts and were hashed before launch; hashes do not authenticate the files or prove which bytes the provider loaded".to_owned(),
    })
}

fn senocr_runtime_profile_binding(
    identity: Option<&ProviderIdentityV1>,
) -> io::Result<Result<BenchmarkRuntimeProfileBindingV1, BenchmarkQualityEvidenceStatusV1>> {
    let Some(identity) = identity else {
        return Ok(Err(
            BenchmarkQualityEvidenceStatusV1::IncompleteSenocrEvidence,
        ));
    };
    let expected_resource_version = format!(
        "{SENOCR_REFERENCE_RUNTIME_PROFILE_ID}-sha256-{SENOCR_REFERENCE_RUNTIME_PROFILE_SHA256}"
    );
    if identity.provider_id != SENOCR_REFERENCE_PROVIDER_ID
        || identity.provider_version != SENOCR_REFERENCE_PROVIDER_VERSION
        || identity.model_version.as_deref() != Some(SENOCR_REFERENCE_MODEL_REVISION)
        || identity.resource_version.as_deref() != Some(expected_resource_version.as_str())
    {
        return Ok(Err(
            BenchmarkQualityEvidenceStatusV1::MismatchedSenocrEvidence,
        ));
    }
    let manifest = load_senocr_runtime_profile_manifest()?;
    Ok(Ok(BenchmarkRuntimeProfileBindingV1 {
        manifest_schema_version: manifest.schema_version,
        profile_id: SENOCR_REFERENCE_RUNTIME_PROFILE_ID.to_owned(),
        profile_manifest_sha256: SENOCR_REFERENCE_RUNTIME_PROFILE_SHA256.to_owned(),
        distribution_count: manifest.distribution_count,
        python_version: manifest.python_version,
        platform: manifest.platform,
        root_pins: manifest.root_pins,
        installed_distribution_closure: manifest.installed_distribution_closure,
        observation_scope: "provider-declared runtime profile matched the checked-in full installed-distribution snapshot by SHA-256; not wheel authenticity or a proof of isolated-process state"
            .to_owned(),
    }))
}

fn load_senocr_runtime_profile_manifest() -> io::Result<SenocrRuntimeProfileManifestV1> {
    let raw = SENOCR_RUNTIME_PROFILE_DOCUMENT;
    if raw.is_empty() || raw.len() > MAX_SENOCR_RUNTIME_PROFILE_BYTES {
        return Err(invalid_data(
            "checked-in SenOCR runtime profile exceeds its fixed byte bounds",
        ));
    }
    let payload = raw
        .strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw);
    if payload.is_empty() || payload.contains(&b'\r') || payload.contains(&b'\n') {
        return Err(invalid_data(
            "checked-in SenOCR runtime profile has invalid line endings",
        ));
    }
    let actual_sha256 = hex_encode(&Sha256::digest(payload))?;
    if actual_sha256 != SENOCR_REFERENCE_RUNTIME_PROFILE_SHA256 {
        return Err(invalid_data(
            "checked-in SenOCR runtime profile digest differs from the fixed reference",
        ));
    }
    let manifest: SenocrRuntimeProfileManifestV1 = serde_json::from_slice(payload)
        .map_err(|_| invalid_data("checked-in SenOCR runtime profile is malformed"))?;
    let canonical = serde_json::to_vec(&manifest)
        .map_err(|_| invalid_data("checked-in SenOCR runtime profile cannot be serialized"))?;
    if canonical.as_slice() != payload
        || manifest.schema_version != 1
        || manifest.distribution_count != SENOCR_REFERENCE_RUNTIME_DISTRIBUTION_COUNT
        || manifest.installed_distribution_closure.len()
            != SENOCR_REFERENCE_RUNTIME_DISTRIBUTION_COUNT as usize
        || manifest.root_pins.len() != SENOCR_REFERENCE_ROOT_PIN_COUNT
        || manifest.python_version != SENOCR_REFERENCE_PYTHON_VERSION
        || manifest.platform != SENOCR_REFERENCE_PLATFORM
    {
        return Err(invalid_data(
            "checked-in SenOCR runtime profile disagrees with its fixed schema or runtime identity",
        ));
    }

    let mut previous_name: Option<&str> = None;
    for distribution in &manifest.installed_distribution_closure {
        if distribution.name.is_empty()
            || distribution.name.len() > 128
            || !distribution
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || distribution.version.is_empty()
            || distribution.version.len() > 128
            || !distribution.version.is_ascii()
            || previous_name.is_some_and(|previous| previous >= distribution.name.as_str())
        {
            return Err(invalid_data(
                "checked-in SenOCR runtime package catalog is not canonical",
            ));
        }
        previous_name = Some(&distribution.name);
    }
    let mut previous_pin_name: Option<&str> = None;
    for pin in &manifest.root_pins {
        let matches_closure = manifest
            .installed_distribution_closure
            .iter()
            .any(|distribution| distribution.name == pin.name && distribution.version == pin.version);
        if !matches_closure
            || previous_pin_name.is_some_and(|previous| previous >= pin.name.as_str())
        {
            return Err(invalid_data(
                "checked-in SenOCR runtime root pins disagree with its package catalog",
            ));
        }
        previous_pin_name = Some(&pin.name);
    }
    Ok(manifest)
}

fn benchmark_quality_evidence(
    provider: &PreparedBenchmarkProvider,
    identity: Option<&ProviderIdentityV1>,
) -> io::Result<BenchmarkQualityEvidenceV1> {
    if !senocr_evidence_candidate(&provider.provider_id, &provider.configuration_id, identity) {
        return Ok(BenchmarkQualityEvidenceV1 {
            schema_version: 1,
            status: BenchmarkQualityEvidenceStatusV1::ProviderPolicyNotApplicable,
            runtime_profile: None,
            model_asset_coverage: None,
            unavailable_reason: Some(
                "no eligible provider-specific frozen runtime/profile and required-asset evidence policy is configured; raw output is diagnostic only and not quality-eligible"
                    .to_owned(),
            ),
        });
    }

    let coverage = senocr_model_asset_coverage(
        provider.senocr_asset_plan.as_ref(),
        &provider.artifact_digests,
    )?;
    let mut mismatch_reason = provider
        .senocr_asset_plan
        .as_ref()
        .and_then(|plan| plan.mismatch_reason.clone());
    if provider.configuration_id != SENOCR_REFERENCE_CONFIGURATION_ID {
        mismatch_reason.get_or_insert_with(|| {
            "SenOCR result is not bound to the fixed operator configuration ID".to_owned()
        });
    }
    let (runtime_profile, runtime_status) = match senocr_runtime_profile_binding(identity)? {
        Ok(binding) => (Some(binding), None),
        Err(status) => (None, Some(status)),
    };
    if coverage.status == BenchmarkModelAssetCoverageStatusV1::MismatchedPrelaunchManifest {
        mismatch_reason.get_or_insert_with(|| {
            "SenOCR required-asset manifest or observed byte counts do not match the fixed inventory"
                .to_owned()
        });
    }

    let (status, reason) = if mismatch_reason.is_some()
        || runtime_status == Some(BenchmarkQualityEvidenceStatusV1::MismatchedSenocrEvidence)
    {
        (
            BenchmarkQualityEvidenceStatusV1::MismatchedSenocrEvidence,
            mismatch_reason.or_else(|| {
                Some("SenOCR provider identity or declared runtime profile mismatched the fixed reference".to_owned())
            }),
        )
    } else if runtime_profile.is_none()
        || coverage.status != BenchmarkModelAssetCoverageStatusV1::CompletePrelaunchObservations
    {
        (
            BenchmarkQualityEvidenceStatusV1::IncompleteSenocrEvidence,
            Some(
                "SenOCR runtime profile or all 12 required prelaunch model-asset observations are unavailable; result is diagnostic only and excluded from quality comparisons"
                    .to_owned(),
            ),
        )
    } else {
        (
            BenchmarkQualityEvidenceStatusV1::EligibleByDeclaredSenocrEvidence,
            None,
        )
    };
    Ok(BenchmarkQualityEvidenceV1 {
        schema_version: 1,
        status,
        runtime_profile,
        model_asset_coverage: Some(coverage),
        unavailable_reason: reason,
    })
}

fn quality_metrics_allowed(evidence: &BenchmarkQualityEvidenceV1) -> bool {
    // Do not treat missing policy/evidence as an implicit approval.
    evidence.status == BenchmarkQualityEvidenceStatusV1::EligibleByDeclaredSenocrEvidence
}

fn validate_provider_spec(provider: &ApprovedBenchmarkProviderV1) -> io::Result<()> {
    validate_local_id(&provider.provider_id, "provider ID")?;
    if let Some(modalities) = &provider.requested_input_modalities {
        validate_provider_input_modalities(modalities)?;
    }
    require_local_absolute_path(&provider.executable_path, "provider executable path")?;
    if provider.arguments.len() > 64
        || provider
            .arguments
            .iter()
            .any(|argument| argument.len() > 4096)
        || provider.arguments.iter().map(String::len).sum::<usize>() > 16 * 1024
    {
        return Err(invalid_data(
            "provider argument count or bytes exceed fixed limits",
        ));
    }
    if provider.artifacts.len() > MAX_PROVIDER_ARTIFACTS {
        return Err(invalid_data(
            "explicit provider artifact list exceeds 16 entries",
        ));
    }
    let mut artifact_ids = BTreeSet::new();
    let executable_digests = provider
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.role == ProviderArtifactRoleV1::Executable
                && artifact.path.as_path() == provider.executable_path.as_path()
        })
        .count();
    if executable_digests != 1 {
        return Err(invalid_data(
            "provider must explicitly enumerate its exact executable path once for hashing",
        ));
    }
    for artifact in &provider.artifacts {
        validate_local_id(&artifact.artifact_id, "artifact ID")?;
        if !artifact_ids.insert(artifact.artifact_id.as_str()) {
            return Err(invalid_data("provider artifact IDs must be unique"));
        }
        require_local_absolute_path(&artifact.path, "explicit artifact path")?;
    }
    if let Some(timeouts) = provider.timeouts
        && [
            timeouts.handshake_ms,
            timeouts.recognition_ms,
            timeouts.shutdown_ms,
        ]
        .iter()
        .any(|milliseconds| !(1..=120_000).contains(milliseconds))
    {
        return Err(invalid_data(
            "provider deadlines must be between 1 and 120000 ms",
        ));
    }
    Ok(())
}

fn validate_corpus_manifest(
    corpus: &BenchmarkCorpusManifestV1,
    batch: &BenchmarkCaseManifestV1,
) -> io::Result<()> {
    if corpus.schema_version != BENCHMARK_SCHEMA_VERSION
        || corpus.cases.is_empty()
        || corpus.cases.len() > MAX_ANNOTATIONS
        || corpus.cases.len() != batch.cases.len()
        || !(1..=MAX_BOOTSTRAP_REPLICATES).contains(&corpus.bootstrap_replicates)
    {
        return Err(invalid_data(
            "corpus annotation version/count/bootstrap settings are invalid",
        ));
    }
    validate_local_id(&corpus.corpus_id, "corpus ID")?;
    let batch_by_id = batch
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut annotation_ids = BTreeSet::new();
    let mut split_assignments = BTreeMap::<String, BenchmarkSplitV1>::new();
    let mut session_assignments = BTreeMap::<String, (u64, BenchmarkSplitV1, String)>::new();
    for annotation in &corpus.cases {
        validate_local_id(&annotation.case_id, "annotation case ID")?;
        validate_local_id(&annotation.annotation_id, "annotation ID")?;
        if !annotation_ids.insert(annotation.case_id.as_str()) {
            return Err(invalid_data("annotation case IDs must be unique"));
        }
        if annotation.reference_text.len() > MAX_REFERENCE_TEXT_BYTES {
            return Err(invalid_data("reference text exceeds 64 KiB"));
        }
        let normalized_reference = annotation.reference_text.nfc().collect::<String>();
        if annotation.delayed_marks.iter().any(|mark| {
            usize::try_from(mark.reference_scalar_index)
                .is_ok_and(|index| index >= normalized_reference.chars().count())
        }) {
            return Err(invalid_data(
                "delayed-mark scalar index is outside reference text",
            ));
        }
        if let Some(tokens) = &annotation.reference_lexical_tokens
            && (tokens.len() > 4096 || tokens.iter().any(|token| token.len() > 256))
        {
            return Err(invalid_data(
                "optional reference lexical segmentation exceeds limits",
            ));
        }
        if annotation.delayed_marks.len() > 4096 {
            return Err(invalid_data("delayed-mark annotation count exceeds 4096"));
        }
        let case = batch_by_id
            .get(annotation.case_id.as_str())
            .ok_or_else(|| invalid_data("annotation references a case absent from the batch"))?;
        if case.provenance.corpus_id.as_deref() != Some(corpus.corpus_id.as_str())
            || case.provenance.annotation_id.as_deref() != Some(annotation.annotation_id.as_str())
        {
            return Err(invalid_data(
                "case corpus/annotation provenance does not match the annotation manifest",
            ));
        }
        let session_time = case.provenance.session_start_unix_ns.ok_or_else(|| {
            invalid_data("corpus cases require an owner-declared UTC session_start_unix_ns")
        })?;
        if case
            .provenance
            .capture_api_version
            .as_deref()
            .is_none_or(str::is_empty)
        {
            return Err(invalid_data(
                "corpus cases require a declared capture API/application version",
            ));
        }
        let split = case
            .provenance
            .split
            .ok_or_else(|| invalid_data("every annotated case requires an explicit split"))?;
        if let Some((previous_time, previous_split, previous_writer)) = session_assignments.insert(
            case.provenance.session_key.clone(),
            (session_time, split, case.provenance.writer_key.clone()),
        ) && (previous_time != session_time
            || previous_split != split
            || previous_writer.as_str() != case.provenance.writer_key.as_str())
        {
            return Err(invalid_data(format!(
                "session-disjoint split violation for session {}",
                case.provenance.session_key
            )));
        }
        let split_key = match corpus.split_key {
            BenchmarkSplitKeyV1::Writer => Some(case.provenance.writer_key.as_str()),
            BenchmarkSplitKeyV1::Session => Some(case.provenance.session_key.as_str()),
            BenchmarkSplitKeyV1::Configuration => Some(case.provenance.configuration_key.as_str()),
            BenchmarkSplitKeyV1::SessionStartTime => None,
        };
        if let Some(key) = split_key
            && let Some(previous) = split_assignments.insert(key.to_owned(), split)
            && previous != split
        {
            return Err(invalid_data(format!(
                "split leakage: {:?} key {key} appears in more than one split",
                corpus.split_key
            )));
        }
    }
    if corpus.split_key == BenchmarkSplitKeyV1::SessionStartTime {
        let mut latest_prior_session = None::<u64>;
        let mut has_adaptation_calibration = false;
        let mut earliest_evaluation = None::<u64>;
        for case in &batch.cases {
            let timestamp = case
                .provenance
                .session_start_unix_ns
                .ok_or_else(|| invalid_data("corpus case is missing a session timestamp"))?;
            match case.provenance.split {
                Some(BenchmarkSplitV1::Adaptation | BenchmarkSplitV1::Calibration) => {
                    has_adaptation_calibration = true;
                    latest_prior_session = Some(
                        latest_prior_session.map_or(timestamp, |latest| latest.max(timestamp)),
                    );
                }
                Some(BenchmarkSplitV1::Evaluation) => {
                    earliest_evaluation = Some(
                        earliest_evaluation.map_or(timestamp, |earliest| earliest.min(timestamp)),
                    );
                }
                Some(_) => {
                    latest_prior_session = Some(
                        latest_prior_session.map_or(timestamp, |latest| latest.max(timestamp)),
                    );
                }
                None => {}
            }
        }
        if !has_adaptation_calibration {
            return Err(invalid_data(
                "session-time split requires adaptation/calibration sessions",
            ));
        }
        let earlier = latest_prior_session.ok_or_else(|| {
            invalid_data("session-time split requires adaptation/calibration sessions")
        })?;
        let future = earliest_evaluation.ok_or_else(|| {
            invalid_data("session-time split requires future evaluation sessions")
        })?;
        if earlier >= future {
            return Err(invalid_data(
                "time-disjoint split requires every non-evaluation session to predate evaluation",
            ));
        }
    }
    Ok(())
}

fn validate_delayed_mark_links(
    annotation: &BenchmarkAnnotationCaseV1,
    request: &RecognitionRequestV1,
) -> io::Result<()> {
    for mark in &annotation.delayed_marks {
        let stroke = crate::provider_protocol::ProviderStrokeRefV1 {
            journal_id: mark.expected_stroke.journal_id.clone(),
            session_id: mark.expected_stroke.session_id.clone(),
            source_api: mark.expected_stroke.source_api.clone(),
            device_id: mark.expected_stroke.device_id.clone(),
            pointer_id: mark.expected_stroke.pointer_id,
            stroke_id: mark.expected_stroke.stroke_id.clone(),
        };
        if !request.samples.iter().any(|sample| {
            sample.stroke == stroke && sample.source_sequence_raw == mark.expected_source_sequence
        }) {
            return Err(invalid_data(
                "delayed-mark annotation references a sample outside the selected request view",
            ));
        }
    }
    Ok(())
}

fn validate_bounded_text(value: &str, label: &str, maximum: usize) -> io::Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(invalid_data(format!(
            "{label} is empty, oversized, or contains controls"
        )));
    }
    Ok(())
}

fn require_local_absolute_path(path: &Path, label: &str) -> io::Result<()> {
    let text = path.to_string_lossy();
    if !path.is_absolute() || text.starts_with("\\\\") || text.len() > 32 * 1024 {
        return Err(invalid_data(format!(
            "{label} must be an explicit, bounded local absolute path"
        )));
    }
    Ok(())
}

struct LoadedRasterInput {
    request_input: ProviderRasterInputV1,
    byte_count: u64,
    sha256_hex: String,
    generated_origin: Option<BenchmarkGeneratedRasterProducerV1>,
}

fn read_raster_input(spec: &BenchmarkRasterInputSpecV1) -> io::Result<LoadedRasterInput> {
    let bytes = read_bounded_regular_file(&spec.path, MAX_RASTER_INPUT_BYTES)?;
    Ok(LoadedRasterInput {
        request_input: ProviderRasterInputV1 {
            width: spec.width,
            height: spec.height,
            payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
            coordinate_space: spec.coordinate_space.clone(),
            units: spec.units.clone(),
            raw_payload_hex: hex_encode(&bytes)?,
        },
        byte_count: bytes.len() as u64,
        sha256_hex: hex_encode(&Sha256::digest(&bytes))?,
        generated_origin: None,
    })
}

fn validate_generated_raster_png_size(byte_count: usize) -> io::Result<u64> {
    let byte_count = u64::try_from(byte_count)
        .map_err(|_| invalid_data("generated raster PNG byte count exceeds u64"))?;
    if byte_count == 0 || byte_count > MAX_RASTER_INPUT_BYTES {
        return Err(invalid_data(
            "generated raster PNG is empty or exceeds the 1 MiB provider intake cap",
        ));
    }
    Ok(byte_count)
}

fn materialize_generated_raster(
    state: &JournalReplayState,
    expected_source_revision: &ProviderSourceRevisionV1,
    selected_strokes: &[StrokeRef],
    generated_spec: &BenchmarkGeneratedRasterSpecV1,
) -> io::Result<LoadedRasterInput> {
    validate_generated_raster_spec(generated_spec)?;
    if ProviderSourceRevisionV1::from_journal(state) != *expected_source_revision {
        return Err(invalid_data(
            "generated raster journal state does not match the verified source revision",
        ));
    }

    let plan =
        build_canonical_raster_projection_plan(state, selected_strokes).map_err(|error| {
            invalid_data(format!(
                "generated raster source projection failed: {error:?}"
            ))
        })?;
    let projection_spec = CanonicalRasterProjectionSpecV1::new(
        generated_spec.output_width_px,
        generated_spec.output_height_px,
        CanonicalRasterProjectionCropV1 {
            left_px: generated_spec.source_crop.left_px,
            top_px: generated_spec.source_crop.top_px,
            right_px_exclusive: generated_spec.source_crop.right_px_exclusive,
            bottom_px_exclusive: generated_spec.source_crop.bottom_px_exclusive,
        },
    );
    let geometry =
        transform_canonical_raster_geometry(&plan, &projection_spec).map_err(|error| {
            invalid_data(format!(
                "generated raster geometry transform failed: {error:?}"
            ))
        })?;
    let (geometry_journal_id, geometry_logical_revision, geometry_last_sequence) =
        geometry.source_revision_parts();
    if geometry_journal_id != expected_source_revision.journal_id
        || geometry_logical_revision != expected_source_revision.logical_revision
        || geometry_last_sequence != expected_source_revision.last_sequence
        || geometry.caller_selection_order() != selected_strokes
        || geometry.caller_selection_order().len() > MAX_GENERATED_RASTER_PROVENANCE_STROKES
    {
        return Err(invalid_data(
            "generated raster geometry provenance does not match the frozen case selection/revision",
        ));
    }

    let mut selected_stroke_refs = Vec::new();
    selected_stroke_refs.try_reserve_exact(geometry.canonical_stroke_draw_order().len())?;
    selected_stroke_refs.extend(
        geometry
            .canonical_stroke_draw_order()
            .iter()
            .map(BenchmarkStrokeRefV1::from),
    );
    let mut stroke_draw_order = Vec::new();
    stroke_draw_order.try_reserve_exact(geometry.canonical_stroke_draw_order().len())?;
    stroke_draw_order.extend(
        geometry
            .canonical_stroke_draw_order()
            .iter()
            .map(BenchmarkStrokeRefV1::from),
    );

    let sequence_count = geometry.physical_sample_sequence_provenance().count();
    if sequence_count == 0 || sequence_count > MAX_GENERATED_RASTER_PROVENANCE_SAMPLES {
        return Err(invalid_data(
            "generated raster physical sequence provenance is empty or exceeds its fixed cap",
        ));
    }
    let mut physical_sample_provenance = Vec::new();
    physical_sample_provenance.try_reserve_exact(sequence_count)?;
    let mut previous_journal_sequence = None;
    for (stroke_ref, journal_sequence, source_sequence_raw) in
        geometry.physical_sample_sequence_provenance()
    {
        if journal_sequence == 0
            || journal_sequence > expected_source_revision.last_sequence
            || previous_journal_sequence.is_some_and(|previous| journal_sequence <= previous)
        {
            return Err(invalid_data(
                "generated raster physical sequence provenance is not in the verified journal order",
            ));
        }
        previous_journal_sequence = Some(journal_sequence);
        physical_sample_provenance.push(BenchmarkGeneratedRasterSampleProvenanceV1 {
            stroke: BenchmarkStrokeRefV1::from(stroke_ref),
            journal_sequence,
            source_sequence_raw,
        });
    }

    let image = render_canonical_raster(&geometry)
        .map_err(|error| invalid_data(format!("generated raster rendering failed: {error:?}")))?;
    let (image_journal_id, image_logical_revision, image_last_sequence) =
        image.source_revision_parts();
    let (output_width_px, output_height_px, row_stride_bytes) =
        image.output_dimensions_and_stride();
    let expected_row_stride_bytes = output_width_px
        .checked_mul(4)
        .ok_or_else(|| invalid_data("generated raster row stride overflowed u32"))?;
    if image_journal_id != expected_source_revision.journal_id
        || image_logical_revision != expected_source_revision.logical_revision
        || image_last_sequence != expected_source_revision.last_sequence
        || image.source_content_sha256() != geometry.source_content_sha256()
        || image.projection_spec_sha256() != geometry.projection_spec_sha256()
        || image.geometry_sha256() != geometry.geometry_sha256()
        || output_width_px != generated_spec.output_width_px
        || output_height_px != generated_spec.output_height_px
        || row_stride_bytes != expected_row_stride_bytes
        || image.pixel_layout()
            != crate::canvas::CanonicalRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown
    {
        return Err(invalid_data(
            "generated raster image metadata does not match its verified geometry/spec",
        ));
    }

    let png_bytes = image.png_bytes();
    let byte_count = validate_generated_raster_png_size(png_bytes.len())?;
    let png_sha256: [u8; 32] = Sha256::digest(png_bytes).into();
    if png_sha256 != image.png_bytes_sha256() {
        return Err(invalid_data(
            "generated raster PNG digest does not match actual producer bytes",
        ));
    }
    let sha256_hex = hex_encode(&png_sha256)?;
    let producer_metadata = BenchmarkGeneratedRasterProducerV1 {
        schema_version: 1,
        geometry_schema_version: geometry.geometry_schema_version(),
        projection_schema_version: geometry.projection_schema_version(),
        source_revision: expected_source_revision.clone(),
        selected_strokes: selected_stroke_refs,
        source_content_sha256: hex_encode(&image.source_content_sha256())?,
        projection_spec_sha256: hex_encode(&image.projection_spec_sha256())?,
        geometry_sha256: hex_encode(&image.geometry_sha256())?,
        renderer_version: image.renderer_version().to_owned(),
        pixel_bytes_sha256: hex_encode(&image.pixel_bytes_sha256())?,
        png_bytes_sha256: sha256_hex.clone(),
        raster_artifact_sha256: hex_encode(&image.raster_artifact_sha256())?,
        output_width_px,
        output_height_px,
        row_stride_bytes,
        pixel_layout: image.pixel_layout_name().to_owned(),
        stroke_draw_order,
        physical_sample_provenance,
    };
    if producer_metadata.schema_version != 1
        || producer_metadata.geometry_schema_version != 1
        || producer_metadata.projection_schema_version != generated_spec.projection_schema_version
    {
        return Err(invalid_data(
            "generated raster producer schema version does not match the requested canonical spec",
        ));
    }
    let raw_payload_hex = hex_encode(png_bytes)?;
    // Only the PNG needed by the provider request survives this function;
    // raw pixels and the encoded PNG are not copied into run metadata.
    let request_input = ProviderRasterInputV1 {
        width: output_width_px,
        height: output_height_px,
        payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
        coordinate_space: GENERATED_RASTER_COORDINATE_SPACE.to_owned(),
        units: GENERATED_RASTER_COORDINATE_UNITS.to_owned(),
        raw_payload_hex,
    };
    Ok(LoadedRasterInput {
        request_input,
        byte_count,
        sha256_hex,
        generated_origin: Some(producer_metadata),
    })
}

fn raster_provenance_for_request(
    requested_input_modalities: &[ProviderInputCapabilityV1],
    raster: Option<&LoadedRasterInput>,
) -> io::Result<(Option<u64>, Option<String>)> {
    if requested_input_modalities.contains(&ProviderInputCapabilityV1::Raster) {
        let raster = raster.ok_or_else(|| {
            invalid_data("raster modality was requested without loaded raster input")
        })?;
        Ok((Some(raster.byte_count), Some(raster.sha256_hex.clone())))
    } else {
        Ok((None, None))
    }
}

fn generated_raster_origin_for_request(
    request: &RecognitionRequestV1,
    raster: Option<&LoadedRasterInput>,
    canonical_binding: &BenchmarkCanonicalInkComparisonBindingV1,
    request_selected_strokes: &[BenchmarkStrokeRefV1],
) -> io::Result<Option<BenchmarkGeneratedRasterOriginV1>> {
    if !request
        .requested_input_modalities
        .contains(&ProviderInputCapabilityV1::Raster)
    {
        return Ok(None);
    }
    let raster = raster
        .ok_or_else(|| invalid_data("raster request has no materialized case raster input"))?;
    let request_raster = request
        .raster
        .as_ref()
        .ok_or_else(|| invalid_data("raster request omitted its raster payload"))?;
    if request_raster != &raster.request_input {
        return Err(invalid_data(
            "request raster differs from the materialized case raster source",
        ));
    }
    let Some(producer) = &raster.generated_origin else {
        return Ok(None);
    };
    if !request_selected_strokes_match_request(request, request_selected_strokes) {
        return Err(invalid_data(
            "generated raster selection was not derived from the built request stroke views",
        ));
    }
    if producer.source_revision != request.source_revision
        || producer.selected_strokes != request_selected_strokes
        || producer.output_width_px != request_raster.width
        || producer.output_height_px != request_raster.height
        || producer.png_bytes_sha256 != raster.sha256_hex
        || canonical_binding.schema_version != CANONICAL_INK_COMPARISON_BINDING_SCHEMA_VERSION
        || canonical_binding.raster_pixel_parity != BenchmarkRasterPixelParityV1::Unverified
    {
        return Err(invalid_data(
            "generated raster provenance does not match the exact request revision, selection, or bytes",
        ));
    }
    validate_sha256_hex(
        &canonical_binding.sha256_hex,
        "generated raster canonical-ink binding SHA-256",
    )?;
    Ok(Some(BenchmarkGeneratedRasterOriginV1 {
        schema_version: 1,
        canonical_ink_comparison_binding_sha256: canonical_binding.sha256_hex.clone(),
        producer: producer.clone(),
    }))
}

fn benchmark_selected_strokes_from_request(
    request: &RecognitionRequestV1,
) -> io::Result<Vec<BenchmarkStrokeRefV1>> {
    let mut selected_strokes = Vec::new();
    selected_strokes.try_reserve_exact(request.stroke_views.len())?;
    selected_strokes.extend(
        request
            .stroke_views
            .iter()
            .map(|view| BenchmarkStrokeRefV1 {
                journal_id: view.stroke.journal_id.clone(),
                session_id: view.stroke.session_id.clone(),
                source_api: view.stroke.source_api.clone(),
                device_id: view.stroke.device_id.clone(),
                pointer_id: view.stroke.pointer_id,
                stroke_id: view.stroke.stroke_id.clone(),
            }),
    );
    Ok(selected_strokes)
}

fn request_selected_strokes_match_request(
    request: &RecognitionRequestV1,
    selected_strokes: &[BenchmarkStrokeRefV1],
) -> bool {
    request.stroke_views.len() == selected_strokes.len()
        && request
            .stroke_views
            .iter()
            .zip(selected_strokes)
            .all(|(view, selected)| {
                view.stroke.journal_id == selected.journal_id
                    && view.stroke.session_id == selected.session_id
                    && view.stroke.source_api == selected.source_api
                    && view.stroke.device_id == selected.device_id
                    && view.stroke.pointer_id == selected.pointer_id
                    && view.stroke.stroke_id == selected.stroke_id
            })
}

fn read_bounded_regular_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    require_local_absolute_path(path, "input path")?;
    let before_link = fs::symlink_metadata(path)?;
    if before_link.file_type().is_symlink() || !before_link.is_file() || before_link.len() > maximum
    {
        return Err(invalid_data(
            "input is not a bounded regular non-symlink file",
        ));
    }
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() != before_link.len() {
        return Err(invalid_data("input changed during bounded open"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(
        usize::try_from(before.len())
            .map_err(|_| invalid_data("input size does not fit addressable memory"))?,
    )?;
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum
        || bytes.len() as u64 != before.len()
        || file.metadata()?.len() != before.len()
    {
        return Err(invalid_data(
            "input exceeded its cap or changed while being read",
        ));
    }
    Ok(bytes)
}

fn hash_operator_artifact(
    artifact: ProviderArtifactPathV1,
    remaining_total_cap: u64,
) -> io::Result<ProviderArtifactDigestV1> {
    let (byte_count, sha256_hex) = hash_explicit_file(&artifact.path, remaining_total_cap)?;
    Ok(ProviderArtifactDigestV1 {
        artifact_id: artifact.artifact_id,
        role: artifact.role,
        byte_count,
        sha256_hex,
        observation: "bounded prelaunch SHA-256 observation of an operator-enumerated path; not authenticity or a TOCTOU guarantee"
            .to_owned(),
    })
}

fn hash_explicit_file(path: &Path, remaining_total_cap: u64) -> io::Result<(u64, String)> {
    require_local_absolute_path(path, "explicit artifact path")?;
    let link_metadata = fs::symlink_metadata(path)?;
    if link_metadata.file_type().is_symlink()
        || !link_metadata.is_file()
        || link_metadata.len() > MAX_PROVIDER_ARTIFACT_HASH_BYTES
        || link_metadata.len() > remaining_total_cap
    {
        return Err(invalid_data(
            "explicit artifact must be a bounded regular non-symlink file",
        ));
    }
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() != link_metadata.len() {
        return Err(invalid_data("artifact changed during bounded open"));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| invalid_data("artifact byte count overflow"))?;
        if total > MAX_PROVIDER_ARTIFACT_HASH_BYTES || total > remaining_total_cap {
            return Err(invalid_data(
                "artifact exceeded its per-file or total hash cap",
            ));
        }
        digest.update(&buffer[..read]);
    }
    if total != before.len() || file.metadata()?.len() != before.len() {
        return Err(invalid_data("artifact changed size while hashing"));
    }
    Ok((total, hex_encode(&digest.finalize())?))
}

fn score_candidates(
    result: &RecognitionResultV1,
    annotation: &BenchmarkAnnotationCaseV1,
    tokenization_policy: BenchmarkTokenizationPolicyV1,
) -> io::Result<Vec<BenchmarkCandidateMetricsV1>> {
    let mut metrics = Vec::new();
    let Some(candidate) = result.candidates.first() else {
        return Ok(metrics);
    };
    metrics.try_reserve_exact(1)?;
    metrics.push(score_candidate(
        &candidate.recognized_text,
        annotation,
        tokenization_policy,
        0,
    )?);
    Ok(metrics)
}

fn score_candidate(
    hypothesis: &str,
    annotation: &BenchmarkAnnotationCaseV1,
    tokenization_policy: BenchmarkTokenizationPolicyV1,
    candidate_rank: u16,
) -> io::Result<BenchmarkCandidateMetricsV1> {
    let reference = annotation.reference_text.nfc().collect::<String>();
    let hypothesis = hypothesis.nfc().collect::<String>();
    let reference_chars = reference.chars().collect::<Vec<_>>();
    let hypothesis_chars = hypothesis.chars().collect::<Vec<_>>();
    let (cer, wer, cer_unavailable_reason, wer_unavailable_reason) = match tokenization_policy {
        BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1 => {
            let cer_distance = bounded_levenshtein(&reference_chars, &hypothesis_chars)?;
            let reference_tokens = reference.split_whitespace().collect::<Vec<_>>();
            let hypothesis_tokens = hypothesis.split_whitespace().collect::<Vec<_>>();
            let wer_distance = bounded_levenshtein(&reference_tokens, &hypothesis_tokens)?;
            let cer = if reference_chars.is_empty() {
                None
            } else {
                cer_distance.map(|errors| BenchmarkCountMetricV1 {
                    errors,
                    reference_units: reference_chars.len() as u64,
                })
            };
            let wer = if reference_tokens.is_empty() {
                None
            } else {
                wer_distance.map(|errors| BenchmarkCountMetricV1 {
                    errors,
                    reference_units: reference_tokens.len() as u64,
                })
            };
            let cer_reason = if reference_chars.is_empty() {
                Some(
                    "NFC CER is unavailable because the reference has zero Unicode scalars"
                        .to_owned(),
                )
            } else if cer_distance.is_none() {
                Some(
                    "CER edit-distance work cap exceeded; raw texts are retained separately"
                        .to_owned(),
                )
            } else {
                None
            };
            let wer_reason = if reference_tokens.is_empty() {
                Some(
                    "whitespace-token/syllable WER is unavailable because the reference has zero tokens"
                        .to_owned(),
                )
            } else if wer_distance.is_none() {
                Some(
                    "WER edit-distance work cap exceeded; raw texts are retained separately"
                        .to_owned(),
                )
            } else {
                None
            };
            (cer, wer, cer_reason, wer_reason)
        }
    };
    let (tone_mark_inventory_difference_count, vowel_modifier_inventory_difference_count) =
        mark_inventory_difference(&reference, &hypothesis);
    let (
        vietnamese_tone_mark_alignment_edits,
        vietnamese_tone_mark_unavailable_reason,
        vietnamese_vowel_modifier_alignment_edits,
        vietnamese_vowel_modifier_unavailable_reason,
        vietnamese_mark_alignment_policy,
    ) = if annotation.reference_language_scope != BenchmarkReferenceLanguageScopeV1::VietnameseOnly
    {
        let reason = match annotation.reference_language_scope {
            BenchmarkReferenceLanguageScopeV1::MixedOrUnknown => {
                "reference is mixed/unknown and has no annotated Vietnamese spans; Vietnamese mark alignment is withheld"
            }
            BenchmarkReferenceLanguageScopeV1::OtherLanguage => {
                "reference is annotated as a non-Vietnamese language"
            }
            BenchmarkReferenceLanguageScopeV1::VietnameseOnly => unreachable!(),
        };
        (
            None,
            Some(reason.to_owned()),
            None,
            Some(reason.to_owned()),
            None,
        )
    } else {
        let reference_nfd = bounded_nfd_scalars(&reference)?;
        let hypothesis_nfd = bounded_nfd_scalars(&hypothesis)?;
        let reference_vowel_nuclei = reference_nfd
            .iter()
            .filter(|character| is_vietnamese_vowel_base(**character))
            .count() as u64;
        if reference_vowel_nuclei == 0 {
            (
                None,
                Some("reference has no Vietnamese vowel nuclei for tone scoring".to_owned()),
                None,
                Some("reference has no Vietnamese vowel nuclei for modifier scoring".to_owned()),
                None,
            )
        } else {
            match aligned_vietnamese_mark_edits(&reference_nfd, &hypothesis_nfd)? {
                Some((tone_errors, modifier_errors)) => (
                    Some(BenchmarkCountMetricV1 {
                        errors: tone_errors,
                        reference_units: reference_vowel_nuclei,
                    }),
                    None,
                    Some(BenchmarkCountMetricV1 {
                        errors: modifier_errors,
                        reference_units: reference_vowel_nuclei,
                    }),
                    None,
                    Some("nfd_scalar_levenshtein_v1: minimum edit cost; ties prefer diagonal, deletion, insertion; denominator is reference vowel nuclei".to_owned()),
                ),
                None => (
                    None,
                    Some("Vietnamese mark-alignment DP cell cap exceeded".to_owned()),
                    None,
                    Some("Vietnamese mark-alignment DP cell cap exceeded".to_owned()),
                    None,
                ),
            }
        }
    };
    let reference_boundaries = syllable_boundaries(&reference);
    let hypothesis_boundaries = syllable_boundaries(&hypothesis);
    let boundary_difference =
        symmetric_difference_count(&reference_boundaries, &hypothesis_boundaries);
    let boundary_metric = if reference_boundaries.is_empty() {
        None
    } else {
        Some(BenchmarkCountMetricV1 {
            errors: boundary_difference,
            reference_units: reference_boundaries.len() as u64,
        })
    };
    let boundary_unavailable_reason = reference_boundaries
        .is_empty()
        .then(|| "no reference whitespace syllable boundary exists".to_owned());
    let lexical_wer_unavailable_reason = if annotation.reference_lexical_tokens.is_some() {
        "predicted lexical token boundaries are unavailable; supplied references alone do not establish a word segmenter"
            .to_owned()
    } else {
        "Vietnamese whitespace tokens are syllables/orthographic units; no validated lexical segmenter or boundaries were supplied"
            .to_owned()
    };
    let delayed_attachment_unavailable_reason = if annotation.delayed_marks.is_empty() {
        "no delayed-mark alignment annotations were supplied".to_owned()
    } else {
        "the provider protocol has no validated token-to-stroke alignment for delayed-mark scoring"
            .to_owned()
    };
    Ok(BenchmarkCandidateMetricsV1 {
        candidate_rank,
        nfc_unicode_scalar_cer: cer,
        nfc_cer_unavailable_reason: cer_unavailable_reason,
        whitespace_token_syllable_wer: wer,
        whitespace_wer_unavailable_reason: wer_unavailable_reason,
        lexical_wer_unavailable_reason,
        tone_mark_inventory_difference_count,
        vowel_modifier_inventory_difference_count,
        vietnamese_tone_mark_alignment_edits,
        vietnamese_tone_mark_unavailable_reason,
        vietnamese_vowel_modifier_alignment_edits,
        vietnamese_vowel_modifier_unavailable_reason,
        vietnamese_mark_alignment_policy,
        syllable_boundary_offset_diagnostic: boundary_metric,
        syllable_boundary_offset_diagnostic_unavailable_reason: boundary_unavailable_reason,
        syllable_boundary_diagnostic_policy: "symmetric_difference_cumulative_non_whitespace_nfc_scalar_offsets_v1; not aligned boundary accuracy".to_owned(),
        delayed_attachment_unavailable_reason,
    })
}

fn bounded_levenshtein<T: Eq>(left: &[T], right: &[T]) -> io::Result<Option<u64>> {
    let columns = left
        .len()
        .min(right.len())
        .checked_add(1)
        .ok_or_else(|| invalid_data("edit-distance column count overflow"))?;
    let rows = left
        .len()
        .max(right.len())
        .checked_add(1)
        .ok_or_else(|| invalid_data("edit-distance row count overflow"))?;
    if rows
        .checked_mul(columns)
        .ok_or_else(|| invalid_data("edit-distance cell count overflow"))?
        > MAX_METRIC_DP_CELLS
    {
        return Ok(None);
    }
    let (shorter, longer) = if left.len() <= right.len() {
        (left, right)
    } else {
        (right, left)
    };
    let mut previous = Vec::new();
    previous
        .try_reserve_exact(shorter.len().saturating_add(1))
        .map_err(|error| io::Error::other(format!("edit-distance allocation failed: {error}")))?;
    previous.extend(0..=shorter.len());
    let mut current = Vec::new();
    current
        .try_reserve_exact(shorter.len().saturating_add(1))
        .map_err(|error| io::Error::other(format!("edit-distance allocation failed: {error}")))?;
    current.resize(shorter.len() + 1, 0usize);
    for (row_index, right_value) in longer.iter().enumerate() {
        current[0] = row_index + 1;
        for (column_index, left_value) in shorter.iter().enumerate() {
            let substitution_cost = if left_value == right_value { 0 } else { 1 };
            let substitution = previous[column_index]
                .checked_add(substitution_cost)
                .ok_or_else(|| invalid_data("edit-distance substitution count overflow"))?;
            current[column_index + 1] = substitution
                .min(
                    previous[column_index + 1]
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("edit-distance deletion count overflow"))?,
                )
                .min(
                    current[column_index]
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("edit-distance insertion count overflow"))?,
                );
        }
        std::mem::swap(&mut previous, &mut current);
    }
    let distance = *previous
        .last()
        .ok_or_else(|| invalid_data("edit-distance result row is empty"))?;
    Ok(Some(u64::try_from(distance).map_err(|_| {
        invalid_data("edit distance does not fit u64")
    })?))
}

fn mark_inventory_difference(reference: &str, hypothesis: &str) -> (u64, u64) {
    let mut reference_tone = BTreeMap::<char, u64>::new();
    let mut hypothesis_tone = BTreeMap::<char, u64>::new();
    let mut reference_modifiers = BTreeMap::<char, u64>::new();
    let mut hypothesis_modifiers = BTreeMap::<char, u64>::new();
    for character in reference.nfd() {
        if is_tone_mark(character) {
            *reference_tone.entry(character).or_default() += 1;
        } else if is_vowel_modifier(character) {
            *reference_modifiers.entry(character).or_default() += 1;
        }
    }
    for character in hypothesis.nfd() {
        if is_tone_mark(character) {
            *hypothesis_tone.entry(character).or_default() += 1;
        } else if is_vowel_modifier(character) {
            *hypothesis_modifiers.entry(character).or_default() += 1;
        }
    }
    (
        count_map_difference(&reference_tone, &hypothesis_tone),
        count_map_difference(&reference_modifiers, &hypothesis_modifiers),
    )
}

fn count_map_difference(left: &BTreeMap<char, u64>, right: &BTreeMap<char, u64>) -> u64 {
    left.keys()
        .chain(right.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|key| {
            left.get(&key)
                .copied()
                .unwrap_or_default()
                .abs_diff(right.get(&key).copied().unwrap_or_default())
        })
        .sum()
}

fn is_tone_mark(character: char) -> bool {
    matches!(
        character,
        '\u{0300}' | '\u{0301}' | '\u{0303}' | '\u{0309}' | '\u{0323}'
    )
}

fn is_vowel_modifier(character: char) -> bool {
    matches!(character, '\u{0302}' | '\u{0306}' | '\u{031b}')
}

fn is_vietnamese_vowel_base(character: char) -> bool {
    matches!(
        character.to_ascii_lowercase(),
        'a' | 'e' | 'i' | 'o' | 'u' | 'y'
    )
}

fn bounded_nfd_scalars(value: &str) -> io::Result<Vec<char>> {
    let mut scalars = Vec::new();
    scalars.try_reserve_exact(value.len().min(MAX_NFD_MARK_SCALARS))?;
    for scalar in value.nfd() {
        if scalars.len() >= MAX_NFD_MARK_SCALARS {
            return Err(invalid_data("NFD mark-alignment scalar cap exceeded"));
        }
        if scalars.len() == scalars.capacity() {
            scalars.try_reserve(1)?;
        }
        scalars.push(scalar);
    }
    Ok(scalars)
}

#[derive(Clone, Copy, Debug, Default)]
struct MarkEditCounts {
    tone_marks: u64,
    vowel_modifiers: u64,
}

const ALIGN_DIAGONAL: u8 = 0;
const ALIGN_DELETE: u8 = 1;
const ALIGN_INSERT: u8 = 2;

fn aligned_vietnamese_mark_edits(
    reference_nfd: &[char],
    hypothesis_nfd: &[char],
) -> io::Result<Option<(u64, u64)>> {
    let rows = reference_nfd
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid_data("NFD mark-alignment row count overflow"))?;
    let columns = hypothesis_nfd
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid_data("NFD mark-alignment column count overflow"))?;
    let cells = rows
        .checked_mul(columns)
        .ok_or_else(|| invalid_data("NFD mark-alignment cell count overflow"))?;
    if cells > MAX_METRIC_DP_CELLS {
        return Ok(None);
    }

    let mut backtrace = Vec::new();
    backtrace.try_reserve_exact(cells)?;
    backtrace.resize(cells, ALIGN_DIAGONAL);
    let mut previous = Vec::new();
    previous.try_reserve_exact(columns)?;
    previous.resize(columns, 0usize);
    let mut current = Vec::new();
    current.try_reserve_exact(columns)?;
    current.resize(columns, 0usize);

    for column in 1..columns {
        previous[column] = column;
        backtrace[column] = ALIGN_INSERT;
    }
    for row in 1..rows {
        current[0] = row;
        backtrace[row * columns] = ALIGN_DELETE;
        for column in 1..columns {
            let reference_scalar = reference_nfd[row - 1];
            let hypothesis_scalar = hypothesis_nfd[column - 1];
            let substitution_cost = if reference_scalar == hypothesis_scalar {
                0
            } else {
                1
            };
            let mut best_distance = previous[column - 1] + substitution_cost;
            let mut best_operation = ALIGN_DIAGONAL;
            let deletion = previous[column] + 1;
            if deletion < best_distance {
                best_distance = deletion;
                best_operation = ALIGN_DELETE;
            }
            let insertion = current[column - 1] + 1;
            if insertion < best_distance {
                best_distance = insertion;
                best_operation = ALIGN_INSERT;
            }
            current[column] = best_distance;
            backtrace[row * columns + column] = best_operation;
        }
        std::mem::swap(&mut previous, &mut current);
    }

    let mut counts = MarkEditCounts::default();
    let mut row = reference_nfd.len();
    let mut column = hypothesis_nfd.len();
    while row > 0 || column > 0 {
        match backtrace[row * columns + column] {
            ALIGN_DIAGONAL if row > 0 && column > 0 => {
                let reference_scalar = reference_nfd[row - 1];
                let hypothesis_scalar = hypothesis_nfd[column - 1];
                if reference_scalar != hypothesis_scalar {
                    count_mark_edit(&mut counts, Some(reference_scalar), Some(hypothesis_scalar));
                }
                row -= 1;
                column -= 1;
            }
            ALIGN_DELETE if row > 0 => {
                count_mark_edit(&mut counts, Some(reference_nfd[row - 1]), None);
                row -= 1;
            }
            ALIGN_INSERT if column > 0 => {
                count_mark_edit(&mut counts, None, Some(hypothesis_nfd[column - 1]));
                column -= 1;
            }
            _ => return Err(invalid_data("NFD mark-alignment backtrace is malformed")),
        }
    }
    Ok(Some((counts.tone_marks, counts.vowel_modifiers)))
}

fn count_mark_edit(
    counts: &mut MarkEditCounts,
    reference_scalar: Option<char>,
    hypothesis_scalar: Option<char>,
) {
    if reference_scalar.is_some_and(is_tone_mark) || hypothesis_scalar.is_some_and(is_tone_mark) {
        counts.tone_marks = counts.tone_marks.saturating_add(1);
    }
    if reference_scalar.is_some_and(is_vowel_modifier)
        || hypothesis_scalar.is_some_and(is_vowel_modifier)
    {
        counts.vowel_modifiers = counts.vowel_modifiers.saturating_add(1);
    }
}

fn syllable_boundaries(value: &str) -> BTreeSet<u64> {
    let mut boundaries = BTreeSet::new();
    let mut scalar_offset = 0u64;
    let tokens = value.split_whitespace().collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        scalar_offset = scalar_offset.saturating_add(token.chars().count() as u64);
        if index + 1 < tokens.len() {
            boundaries.insert(scalar_offset);
        }
    }
    boundaries
}

fn symmetric_difference_count<T: Ord>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> u64 {
    left.symmetric_difference(right).count() as u64
}

fn build_paired_comparisons(
    observations: &[EvaluationObservation],
    corpus: &BenchmarkCorpusManifestV1,
) -> io::Result<Vec<BenchmarkPairedComparisonV1>> {
    build_paired_comparisons_with_work_budget(
        observations,
        corpus,
        MAX_TOTAL_BOOTSTRAP_CLUSTER_DRAWS,
    )
}

fn build_paired_comparisons_with_work_budget(
    observations: &[EvaluationObservation],
    corpus: &BenchmarkCorpusManifestV1,
    work_budget: u64,
) -> io::Result<Vec<BenchmarkPairedComparisonV1>> {
    let mut provider_keys = BTreeSet::<(String, String)>::new();
    let mut indexed =
        BTreeMap::<(String, String, BenchmarkSplitV1, String), &EvaluationObservation>::new();
    for observation in observations {
        let provider_key = (
            observation.provider_id.clone(),
            observation.configuration_id.clone(),
        );
        provider_keys.insert(provider_key.clone());
        let key = (
            provider_key.0,
            provider_key.1,
            observation.split,
            observation.case_id.clone(),
        );
        if indexed.insert(key, observation).is_some() {
            return Err(invalid_data(
                "duplicate provider/case evaluation observation",
            ));
        }
    }
    let provider_keys = provider_keys.into_iter().collect::<Vec<_>>();
    let splits = [
        BenchmarkSplitV1::Adaptation,
        BenchmarkSplitV1::Calibration,
        BenchmarkSplitV1::Train,
        BenchmarkSplitV1::Validation,
        BenchmarkSplitV1::Evaluation,
    ];
    let mut planned_bootstrap_draws = 0u64;
    for left_index in 0..provider_keys.len() {
        for right_index in (left_index + 1)..provider_keys.len() {
            let left_key = &provider_keys[left_index];
            let right_key = &provider_keys[right_index];
            for split in splits {
                let cer_clusters = count_metric_pair_clusters(
                    &indexed,
                    left_key,
                    right_key,
                    split,
                    corpus.bootstrap_cluster,
                    true,
                );
                let wer_clusters = count_metric_pair_clusters(
                    &indexed,
                    left_key,
                    right_key,
                    split,
                    corpus.bootstrap_cluster,
                    false,
                );
                let pair_clusters = u64::try_from(cer_clusters)
                    .ok()
                    .and_then(|cer| {
                        u64::try_from(wer_clusters)
                            .ok()
                            .and_then(|wer| cer.checked_add(wer))
                    })
                    .ok_or_else(|| invalid_data("bootstrap cluster-draw estimate overflow"))?;
                let pair_draws = pair_clusters
                    .checked_mul(u64::from(corpus.bootstrap_replicates))
                    .ok_or_else(|| invalid_data("bootstrap draw estimate overflow"))?;
                planned_bootstrap_draws = planned_bootstrap_draws
                    .checked_add(pair_draws)
                    .ok_or_else(|| invalid_data("total bootstrap draw estimate overflow"))?;
            }
        }
    }
    let bootstrap_budget_exceeded = planned_bootstrap_draws > work_budget;
    let pair_capacity = provider_keys
        .len()
        .saturating_mul(provider_keys.len().saturating_sub(1))
        / 2;
    let mut comparisons = Vec::new();
    comparisons.try_reserve(pair_capacity.saturating_mul(splits.len()))?;
    for left_index in 0..provider_keys.len() {
        for right_index in (left_index + 1)..provider_keys.len() {
            let left_key = &provider_keys[left_index];
            let right_key = &provider_keys[right_index];
            for split in splits {
                let mut paired = Vec::new();
                for ((provider_id, configuration_id, row_split, case_id), left) in &indexed {
                    if provider_id != &left_key.0
                        || configuration_id != &left_key.1
                        || *row_split != split
                    {
                        continue;
                    }
                    let right = indexed.get(&(
                        right_key.0.clone(),
                        right_key.1.clone(),
                        split,
                        case_id.clone(),
                    ));
                    if let Some(right) = right {
                        let cluster = match corpus.bootstrap_cluster {
                            BenchmarkClusterKeyV1::Writer => left.writer_key.clone(),
                            BenchmarkClusterKeyV1::Session => left.session_key.clone(),
                        };
                        paired.push(PairedMetricCase {
                            cluster,
                            left_cer: left.cer.clone(),
                            right_cer: right.cer.clone(),
                            left_wer: left.wer.clone(),
                            right_wer: right.wer.clone(),
                        });
                    }
                }
                if paired.is_empty() {
                    continue;
                }
                let (cer_case_count, cer_cluster_count) = metric_pair_counts(&paired, true)?;
                let (wer_case_count, wer_cluster_count) = metric_pair_counts(&paired, false)?;
                let budget_reason = || {
                    format!(
                        "global bootstrap cluster-draw budget exceeded ({work_budget}); paired counts retained and no intervals calculated"
                    )
                };
                let (cer_interval, cer_reason) = if bootstrap_budget_exceeded {
                    (None, Some(budget_reason()))
                } else {
                    paired_bootstrap_for_metric(
                        &paired,
                        true,
                        corpus.bootstrap_replicates,
                        corpus.bootstrap_seed,
                    )?
                };
                let (wer_interval, wer_reason) = if bootstrap_budget_exceeded {
                    (None, Some(budget_reason()))
                } else {
                    paired_bootstrap_for_metric(
                        &paired,
                        false,
                        corpus.bootstrap_replicates,
                        corpus.bootstrap_seed,
                    )?
                };
                comparisons.push(BenchmarkPairedComparisonV1 {
                    left_provider: left_key.0.clone(),
                    left_configuration_id: left_key.1.clone(),
                    right_provider: right_key.0.clone(),
                    right_configuration_id: right_key.1.clone(),
                    split,
                    nfc_cer_paired_case_count: cer_case_count,
                    nfc_cer_cluster_count: cer_cluster_count,
                    nfc_cer_rate_difference: cer_interval,
                    nfc_cer_unavailable_reason: cer_reason,
                    whitespace_syllable_wer_paired_case_count: wer_case_count,
                    whitespace_syllable_wer_cluster_count: wer_cluster_count,
                    whitespace_syllable_wer_rate_difference: wer_interval,
                    whitespace_syllable_wer_unavailable_reason: wer_reason,
                });
            }
        }
    }
    Ok(comparisons)
}

#[derive(Clone, Debug)]
struct PairedMetricCase {
    cluster: String,
    left_cer: Option<BenchmarkCountMetricV1>,
    right_cer: Option<BenchmarkCountMetricV1>,
    left_wer: Option<BenchmarkCountMetricV1>,
    right_wer: Option<BenchmarkCountMetricV1>,
}

fn count_metric_pair_clusters(
    indexed: &BTreeMap<(String, String, BenchmarkSplitV1, String), &EvaluationObservation>,
    left_key: &(String, String),
    right_key: &(String, String),
    split: BenchmarkSplitV1,
    cluster_key: BenchmarkClusterKeyV1,
    cer: bool,
) -> usize {
    let mut clusters = BTreeSet::new();
    for ((provider_id, configuration_id, row_split, case_id), left) in indexed {
        if provider_id != &left_key.0 || configuration_id != &left_key.1 || *row_split != split {
            continue;
        }
        let right = indexed.get(&(
            right_key.0.clone(),
            right_key.1.clone(),
            split,
            case_id.clone(),
        ));
        let Some(right) = right else {
            continue;
        };
        let (left_metric, right_metric) = if cer {
            (&left.cer, &right.cer)
        } else {
            (&left.wer, &right.wer)
        };
        if let (Some(left_metric), Some(right_metric)) = (left_metric, right_metric)
            && left_metric.reference_units > 0
            && right_metric.reference_units > 0
        {
            let cluster = match cluster_key {
                BenchmarkClusterKeyV1::Writer => left.writer_key.as_str(),
                BenchmarkClusterKeyV1::Session => left.session_key.as_str(),
            };
            clusters.insert(cluster);
        }
    }
    clusters.len()
}

fn metric_pair_counts(cases: &[PairedMetricCase], cer: bool) -> io::Result<(u32, u32)> {
    let mut count = 0u32;
    let mut clusters = BTreeSet::new();
    for case in cases {
        let (left, right) = if cer {
            (&case.left_cer, &case.right_cer)
        } else {
            (&case.left_wer, &case.right_wer)
        };
        if let (Some(left), Some(right)) = (left, right)
            && left.reference_units > 0
            && right.reference_units > 0
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid_data("metric paired-case count exceeds u32"))?;
            clusters.insert(case.cluster.as_str());
        }
    }
    let cluster_count = u32::try_from(clusters.len())
        .map_err(|_| invalid_data("metric cluster count exceeds u32"))?;
    Ok((count, cluster_count))
}

fn paired_bootstrap_for_metric(
    cases: &[PairedMetricCase],
    cer: bool,
    replicates: u32,
    seed: u64,
) -> io::Result<(Option<BenchmarkBootstrapIntervalV1>, Option<String>)> {
    let mut clusters = BTreeMap::<String, ClusterMetricTotals>::new();
    for case in cases {
        let (left, right) = if cer {
            (&case.left_cer, &case.right_cer)
        } else {
            (&case.left_wer, &case.right_wer)
        };
        let (Some(left), Some(right)) = (left, right) else {
            continue;
        };
        if left.reference_units == 0 || right.reference_units == 0 {
            continue;
        }
        let totals = clusters.entry(case.cluster.clone()).or_default();
        totals.add(
            left.errors,
            left.reference_units,
            right.errors,
            right.reference_units,
        )?;
    }
    if clusters.is_empty() {
        return Ok((
            None,
            Some("no paired cases with nonzero reference denominator".to_owned()),
        ));
    }
    if clusters.len() < 2 {
        return Ok((
            None,
            Some(
                "paired clustered bootstrap unavailable with fewer than two independent clusters"
                    .to_owned(),
            ),
        ));
    }
    let mut totals = Vec::new();
    totals.try_reserve_exact(clusters.len())?;
    totals.extend(clusters.into_values());
    let cluster_count = totals.len();
    let mut rng = seed
        ^ if cer {
            0x4345_525f_5631
        } else {
            0x5745_525f_5631
        };
    if rng == 0 {
        rng = 0x9e37_79b9_7f4a_7c15;
    }
    let mut differences = Vec::new();
    differences.try_reserve_exact(replicates as usize)?;
    for _ in 0..replicates {
        let mut aggregate = ClusterMetricTotals::default();
        for _ in 0..cluster_count {
            let chosen = uniform_index(&mut rng, cluster_count);
            aggregate.merge(&totals[chosen])?;
        }
        if aggregate.left_units == 0 || aggregate.right_units == 0 {
            continue;
        }
        let left_rate = aggregate.left_errors as f64 / aggregate.left_units as f64;
        let right_rate = aggregate.right_errors as f64 / aggregate.right_units as f64;
        let difference = right_rate - left_rate;
        if difference.is_finite() {
            differences.push(difference);
        }
    }
    if differences.is_empty() {
        return Ok((
            None,
            Some("bootstrap produced no finite paired rate".to_owned()),
        ));
    }
    differences.sort_by(f64::total_cmp);
    let median = nearest_rank(&differences, 50.0);
    let low = nearest_rank(&differences, 2.5);
    let high = nearest_rank(&differences, 97.5);
    Ok((
        Some(BenchmarkBootstrapIntervalV1 {
            median_difference: median,
            nominal_95_unadjusted_low: low,
            nominal_95_unadjusted_high: high,
            bootstrap_replicates: u32::try_from(differences.len()).unwrap_or(u32::MAX),
            seed,
            interpretation:
                BenchmarkPairwiseInterpretationV1::NominalUnadjustedExploratoryNotSelectionEvidence,
            selection_evidence_allowed: false,
        }),
        None,
    ))
}

#[derive(Clone, Copy, Debug, Default)]
struct ClusterMetricTotals {
    left_errors: u64,
    left_units: u64,
    right_errors: u64,
    right_units: u64,
}

impl ClusterMetricTotals {
    fn add(
        &mut self,
        left_errors: u64,
        left_units: u64,
        right_errors: u64,
        right_units: u64,
    ) -> io::Result<()> {
        self.left_errors = self
            .left_errors
            .checked_add(left_errors)
            .ok_or_else(|| invalid_data("bootstrap left error total overflow"))?;
        self.left_units = self
            .left_units
            .checked_add(left_units)
            .ok_or_else(|| invalid_data("bootstrap left denominator overflow"))?;
        self.right_errors = self
            .right_errors
            .checked_add(right_errors)
            .ok_or_else(|| invalid_data("bootstrap right error total overflow"))?;
        self.right_units = self
            .right_units
            .checked_add(right_units)
            .ok_or_else(|| invalid_data("bootstrap right denominator overflow"))?;
        Ok(())
    }

    fn merge(&mut self, other: &Self) -> io::Result<()> {
        self.add(
            other.left_errors,
            other.left_units,
            other.right_errors,
            other.right_units,
        )
    }
}

fn uniform_index(state: &mut u64, upper_bound: usize) -> usize {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (((u128::from(*state)) * (upper_bound as u128)) >> 64) as usize
}

fn nearest_rank(values: &[f64], percentile: f64) -> f64 {
    let rank = ((percentile / 100.0) * values.len() as f64).ceil().max(1.0) as usize;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::PROVISIONAL_DIRECT_SOURCE_API;
    use crate::journal::{
        JournalHeader, JournalWriter, PhysicalSample, RawPosition, StrokeViewFrame,
    };
    use crate::provider_protocol::{
        ProviderNativeTimestampV1, ProviderPositionV1, ProviderStrokeRefV1, ProviderViewFrameV1,
    };

    fn annotation(reference_text: &str) -> BenchmarkAnnotationCaseV1 {
        annotation_for("case-1", "annotation-1", reference_text)
    }

    fn annotation_for(
        case_id: &str,
        annotation_id: &str,
        reference_text: &str,
    ) -> BenchmarkAnnotationCaseV1 {
        BenchmarkAnnotationCaseV1 {
            case_id: case_id.to_owned(),
            annotation_id: annotation_id.to_owned(),
            reference_text: reference_text.to_owned(),
            reference_language_scope: BenchmarkReferenceLanguageScopeV1::VietnameseOnly,
            reference_lexical_tokens: None,
            delayed_marks: Vec::new(),
        }
    }

    fn senocr_quality_test_provider(asset_count: usize) -> PreparedBenchmarkProvider {
        let executable_path = PathBuf::from(r"C:\python\python.exe");
        let asset_root = PathBuf::from(r"C:\runner\models\senocr");
        let configuration = ProviderConfigurationV1 {
            configuration_id: SENOCR_REFERENCE_CONFIGURATION_ID.to_owned(),
            values: BTreeMap::from([
                ("asset_root".to_owned(), asset_root.to_string_lossy().into_owned()),
                ("model_id".to_owned(), "VietAlphaLabs/SenOCR-Vi".to_owned()),
                (
                    "model_revision".to_owned(),
                    SENOCR_REFERENCE_MODEL_REVISION.to_owned(),
                ),
            ]),
        };
        let mut artifacts = vec![ProviderArtifactPathV1 {
            artifact_id: "python-executable".to_owned(),
            role: ProviderArtifactRoleV1::Executable,
            path: executable_path.clone(),
        }];
        let mut artifact_digests = vec![ProviderArtifactDigestV1 {
            artifact_id: "python-executable".to_owned(),
            role: ProviderArtifactRoleV1::Executable,
            byte_count: 1,
            sha256_hex: hex_encode(&Sha256::digest(b"python")).unwrap(),
            observation: "test-only".to_owned(),
        }];
        for (index, (asset_name, byte_count)) in SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES
            .iter()
            .take(asset_count)
            .enumerate()
        {
            let artifact_id = format!("required-asset-{index:02}");
            artifacts.push(ProviderArtifactPathV1 {
                artifact_id: artifact_id.clone(),
                role: ProviderArtifactRoleV1::Resource,
                path: asset_root.join(*asset_name),
            });
            artifact_digests.push(ProviderArtifactDigestV1 {
                artifact_id,
                role: ProviderArtifactRoleV1::Resource,
                byte_count: *byte_count,
                sha256_hex: hex_encode(&Sha256::digest(asset_name.as_bytes())).unwrap(),
                observation: "test-only prelaunch digest".to_owned(),
            });
        }
        let manifest = ApprovedBenchmarkProviderV1 {
            provider_id: SENOCR_REFERENCE_PROVIDER_ID.to_owned(),
            executable_path: executable_path.clone(),
            arguments: Vec::new(),
            requested_input_modalities: Some(vec![ProviderInputCapabilityV1::Raster]),
            protocol_configuration: configuration.clone(),
            artifacts,
            timeouts: None,
        };
        let senocr_asset_plan = senocr_asset_plan_from_manifest(&manifest);
        let approved = OperatorApprovedProviderConfig::from_explicit_selection(
            manifest.provider_id.clone(),
            executable_path,
            manifest.arguments.clone(),
            configuration.clone(),
        )
        .unwrap();
        PreparedBenchmarkProvider {
            provider_id: manifest.provider_id,
            configuration,
            configuration_id: SENOCR_REFERENCE_CONFIGURATION_ID.to_owned(),
            approved,
            timeouts: ProviderCallTimeouts::default(),
            artifact_digests,
            senocr_asset_plan,
        }
    }

    fn senocr_quality_test_identity() -> ProviderIdentityV1 {
        ProviderIdentityV1 {
            provider_id: SENOCR_REFERENCE_PROVIDER_ID.to_owned(),
            provider_version: SENOCR_REFERENCE_PROVIDER_VERSION.to_owned(),
            model_version: Some(SENOCR_REFERENCE_MODEL_REVISION.to_owned()),
            resource_version: Some(format!(
                "{SENOCR_REFERENCE_RUNTIME_PROFILE_ID}-sha256-{SENOCR_REFERENCE_RUNTIME_PROFILE_SHA256}"
            )),
        }
    }

    fn senocr_quality_test_result(text: &str) -> RecognitionResultV1 {
        RecognitionResultV1 {
            request_id: "quality-gate-test-request".to_owned(),
            input_view_id: "quality-gate-test-view".to_owned(),
            source_revision: ProviderSourceRevisionV1 {
                journal_id: "quality-gate-test-journal".to_owned(),
                logical_revision: 1,
                last_sequence: 12,
            },
            region_id: "quality-gate-test-region".to_owned(),
            line_id: "quality-gate-test-line".to_owned(),
            provider_configuration_id: SENOCR_REFERENCE_CONFIGURATION_ID.to_owned(),
            provider_configuration_fingerprint: "a".repeat(64),
            provider: senocr_quality_test_identity(),
            provider_provenance: "test-only quality evidence gate fixture".to_owned(),
            consumed_input_modalities: vec![ProviderInputCapabilityV1::Raster],
            candidates: vec![crate::provider_protocol::ProviderCandidateV1 {
                recognized_text: text.to_owned(),
                native_score_raw: None,
                stroke_ranges: Vec::new(),
                raw_candidate: serde_json::json!({"text": text}),
            }],
        }
    }

    fn case_with_split(
        case_id: &str,
        writer_key: &str,
        session_key: &str,
        configuration_key: &str,
        split: BenchmarkSplitV1,
        annotation_id: &str,
    ) -> BenchmarkCaseSpecV1 {
        BenchmarkCaseSpecV1 {
            case_id: case_id.to_owned(),
            journal_path: PathBuf::from(r"C:\fixture\project.lj"),
            expected_source_revision: ProviderSourceRevisionV1 {
                journal_id: "journal-1".to_owned(),
                logical_revision: 0,
                last_sequence: 0,
            },
            region_id: "region-1".to_owned(),
            line_id: "line-1".to_owned(),
            coordinate_space: "document".to_owned(),
            coordinate_units: "px".to_owned(),
            language_hints: vec!["vi-VN".to_owned()],
            requested_input_modalities: vec![ProviderInputCapabilityV1::OnlineStrokes],
            selected_strokes: vec![BenchmarkStrokeRefV1 {
                journal_id: "journal-1".to_owned(),
                session_id: "session-1".to_owned(),
                source_api: "direct".to_owned(),
                device_id: Some("device-1".to_owned()),
                pointer_id: Some(1),
                stroke_id: format!("stroke-{case_id}"),
            }],
            provenance: BenchmarkCaseProvenanceV1 {
                corpus_id: Some("corpus-1".to_owned()),
                annotation_id: Some(annotation_id.to_owned()),
                writer_key: writer_key.to_owned(),
                session_key: session_key.to_owned(),
                session_start_unix_ns: Some(match split {
                    BenchmarkSplitV1::Evaluation => 200,
                    BenchmarkSplitV1::Adaptation => 100,
                    BenchmarkSplitV1::Calibration => 150,
                    BenchmarkSplitV1::Train => 80,
                    BenchmarkSplitV1::Validation => 180,
                }),
                configuration_key: configuration_key.to_owned(),
                split: Some(split),
                capture_api: Some("direct".to_owned()),
                capture_api_version: Some("m1-direct-v1".to_owned()),
                tablet_model: None,
                driver_version: None,
                windows_build: None,
                windows_ink_state: None,
                active_area: None,
                display_mapping: None,
                pressure_curve: None,
            },
            raster: None,
            generated_raster: None,
        }
    }

    fn generated_raster_spec() -> BenchmarkGeneratedRasterSpecV1 {
        BenchmarkGeneratedRasterSpecV1 {
            projection_schema_version: 1,
            output_width_px: 100,
            output_height_px: 100,
            source_crop: BenchmarkGeneratedRasterCropV1 {
                left_px: 0,
                top_px: 0,
                right_px_exclusive: 100,
                bottom_px_exclusive: 100,
            },
        }
    }

    fn generated_raster_journal_fixture() -> (JournalReplayState, StrokeRef) {
        let directory = temp_dir("generated-raster-source");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("source.lj");
        let header = JournalHeader {
            journal_id: "generated-raster-journal".to_owned(),
            session_id: "generated-raster-session".to_owned(),
            config_id: Some("generated-raster-config".to_owned()),
            device_model_declared: None,
            tilt_supported_declared: None,
        };
        let target = StrokeRef {
            journal_id: header.journal_id.clone(),
            session_id: header.session_id.clone(),
            source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
            device_id: Some("generated-raster-device".to_owned()),
            pointer_id: Some(5),
            stroke_id: "generated-raster-stroke".to_owned(),
        };
        let mut writer = JournalWriter::create(path.clone(), header).unwrap();
        writer
            .start_stroke(target.clone(), StrokeViewFrame::default(), 1)
            .unwrap();
        writer
            .append_sample(PhysicalSample {
                session_id: target.session_id.clone(),
                source_api: target.source_api.clone(),
                source_device_id: target.device_id.clone(),
                pointer_id: target.pointer_id,
                stroke_id: Some(target.stroke_id.clone()),
                source_sequence: 91,
                config_id: Some("generated-raster-config".to_owned()),
                app_arrival_elapsed_ns: 2,
                position: Some(RawPosition {
                    coordinate_space: "windows-screen-coordinates".to_owned(),
                    units: "screen-pixel".to_owned(),
                    x_raw: 50,
                    y_raw: 80,
                }),
                pressure: None,
                native_timestamp: None,
                contact_range_state: Some("in_contact".to_owned()),
                button_state_raw: None,
                tilt_x_raw: None,
                tilt_y_raw: None,
                rotation_raw: None,
                raw_payload: vec![0xd3; 128],
            })
            .unwrap();
        writer.commit_stroke(target.clone(), 3).unwrap();
        writer.flush().unwrap();
        let state = writer.replay_state().clone();
        drop(writer);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
        (state, target)
    }

    fn interleaved_generated_raster_journal_fixture() -> (JournalReplayState, StrokeRef, StrokeRef)
    {
        let directory = temp_dir("generated-raster-interleaved");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("source.lj");
        let header = JournalHeader {
            journal_id: "generated-raster-interleaved-journal".to_owned(),
            session_id: "generated-raster-interleaved-session".to_owned(),
            config_id: Some("generated-raster-interleaved-config".to_owned()),
            device_model_declared: None,
            tilt_supported_declared: None,
        };
        let first = StrokeRef {
            journal_id: header.journal_id.clone(),
            session_id: header.session_id.clone(),
            source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
            device_id: Some("generated-raster-device-a".to_owned()),
            pointer_id: Some(5),
            stroke_id: "generated-raster-stroke-a".to_owned(),
        };
        let second = StrokeRef {
            journal_id: header.journal_id.clone(),
            session_id: header.session_id.clone(),
            source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
            device_id: Some("generated-raster-device-b".to_owned()),
            pointer_id: Some(6),
            stroke_id: "generated-raster-stroke-b".to_owned(),
        };
        let mut writer = JournalWriter::create(path.clone(), header).unwrap();
        let frame = StrokeViewFrame::default();
        writer.start_stroke(first.clone(), frame, 1).unwrap();
        writer.start_stroke(second.clone(), frame, 2).unwrap();
        let append_sample = |target: &StrokeRef,
                             source_sequence: u64,
                             x_raw: i64,
                             y_raw: i64,
                             app_arrival_elapsed_ns: u128,
                             raw_payload: Vec<u8>| {
            PhysicalSample {
                session_id: target.session_id.clone(),
                source_api: target.source_api.clone(),
                source_device_id: target.device_id.clone(),
                pointer_id: target.pointer_id,
                stroke_id: Some(target.stroke_id.clone()),
                source_sequence,
                config_id: Some("generated-raster-interleaved-config".to_owned()),
                app_arrival_elapsed_ns,
                position: Some(RawPosition {
                    coordinate_space: "windows-screen-coordinates".to_owned(),
                    units: "screen-pixel".to_owned(),
                    x_raw,
                    y_raw,
                }),
                pressure: None,
                native_timestamp: None,
                contact_range_state: Some("in_contact".to_owned()),
                button_state_raw: None,
                tilt_x_raw: None,
                tilt_y_raw: None,
                rotation_raw: None,
                raw_payload,
            }
        };
        writer
            .append_sample(append_sample(&first, 501, 20, 80, 3, vec![0xa1]))
            .unwrap();
        writer
            .append_sample(append_sample(&second, 601, 60, 80, 4, vec![0xb1]))
            .unwrap();
        writer
            .append_sample(append_sample(&first, 502, 40, 80, 5, vec![0xa2]))
            .unwrap();
        writer.commit_stroke(first.clone(), 6).unwrap();
        writer.commit_stroke(second.clone(), 7).unwrap();
        writer.flush().unwrap();
        let state = writer.replay_state().clone();
        drop(writer);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
        (state, first, second)
    }

    fn generated_raster_request(
        state: &JournalReplayState,
        target: &StrokeRef,
        configuration_id: &str,
        requested_input_modalities: Vec<ProviderInputCapabilityV1>,
        raster: Option<ProviderRasterInputV1>,
    ) -> RecognitionRequestV1 {
        generated_raster_request_for_strokes(
            state,
            std::slice::from_ref(target),
            configuration_id,
            requested_input_modalities,
            raster,
        )
    }

    fn generated_raster_request_for_strokes(
        state: &JournalReplayState,
        selected_strokes: &[StrokeRef],
        configuration_id: &str,
        requested_input_modalities: Vec<ProviderInputCapabilityV1>,
        raster: Option<ProviderRasterInputV1>,
    ) -> RecognitionRequestV1 {
        build_recognition_request(RecognitionRequestBuildInput {
            state,
            request_id: format!("generated-raster-{configuration_id}"),
            region_id: "generated-raster-region".to_owned(),
            line_id: "generated-raster-line".to_owned(),
            coordinate_space: "document".to_owned(),
            coordinate_units: "px".to_owned(),
            language_hints: vec!["vi-VN".to_owned()],
            requested_input_modalities,
            provider_configuration: ProviderConfigurationV1 {
                configuration_id: configuration_id.to_owned(),
                values: BTreeMap::new(),
            },
            selected_strokes,
            raster,
        })
        .unwrap()
    }

    fn canonical_comparison_request_fixture() -> RecognitionRequestV1 {
        let stroke = ProviderStrokeRefV1 {
            journal_id: "journal-1".to_owned(),
            session_id: "session-1".to_owned(),
            source_api: "direct".to_owned(),
            device_id: Some("device-1".to_owned()),
            pointer_id: Some(4),
            stroke_id: "stroke-1".to_owned(),
        };
        let view = ProviderStrokeViewV1 {
            stroke: stroke.clone(),
            view_frame: Some(ProviderViewFrameV1 {
                screen_origin_x_px: 10,
                screen_origin_y_px: 20,
                dpi_scale_factor_bits: 1.0f64.to_bits(),
                canvas_zoom_bits: 1.0f64.to_bits(),
                canvas_pan_x_bits: 0.0f64.to_bits(),
                canvas_pan_y_bits: 0.0f64.to_bits(),
                toolbar_height_px: 32,
            }),
        };
        let sample = |sequence: u64, x_raw: i64| ProviderSampleV1 {
            journal_sequence: sequence,
            source_sequence_raw: sequence + 100,
            stroke: stroke.clone(),
            app_arrival_elapsed_ns_decimal: (sequence * 1000).to_string(),
            config_id: Some("capture-config-1".to_owned()),
            position: Some(ProviderPositionV1 {
                coordinate_space: "screen_pixels".to_owned(),
                units: "px".to_owned(),
                x_raw,
                y_raw: 200,
            }),
            effective_position: Some(ProviderPositionV1 {
                coordinate_space: "document".to_owned(),
                units: "px".to_owned(),
                x_raw: x_raw + 5,
                y_raw: 205,
            }),
            pressure: None,
            native_timestamp: Some(ProviderNativeTimestampV1 {
                clock_domain: "qpc".to_owned(),
                units: "ticks".to_owned(),
                count_raw: sequence * 10,
                frequency_hz: Some(10_000_000),
            }),
            contact_range_state: Some("in_contact".to_owned()),
            button_state_raw: None,
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload_hex: format!("{sequence:04x}"),
        };
        RecognitionRequestV1 {
            protocol_version: 1,
            request_id: "request-a".to_owned(),
            input_view_id: "input-view-v1-0000000000000001".to_owned(),
            source_revision: ProviderSourceRevisionV1 {
                journal_id: "journal-1".to_owned(),
                logical_revision: 3,
                last_sequence: 42,
            },
            region_id: "region-1".to_owned(),
            line_id: "line-1".to_owned(),
            coordinate_space: "document".to_owned(),
            coordinate_units: "px".to_owned(),
            language_hints: vec!["vi-VN".to_owned()],
            requested_input_modalities: vec![ProviderInputCapabilityV1::OnlineStrokes],
            provider_configuration: ProviderConfigurationV1 {
                configuration_id: "provider-config-a".to_owned(),
                values: BTreeMap::new(),
            },
            provider_configuration_fingerprint: "a".repeat(64),
            stroke_views: vec![view],
            samples: vec![sample(41, 100), sample(42, 110)],
            raster: None,
        }
    }

    #[test]
    fn canonical_ink_binding_matches_across_modalities_and_provider_configs() {
        let online = canonical_comparison_request_fixture();
        let mut raster = online.clone();
        raster.request_id = "request-b".to_owned();
        raster.input_view_id = "input-view-v1-0000000000000002".to_owned();
        raster.requested_input_modalities = vec![ProviderInputCapabilityV1::Raster];
        raster.provider_configuration.configuration_id = "provider-config-b".to_owned();
        raster
            .provider_configuration
            .values
            .insert("setting".to_owned(), "different".to_owned());
        raster.provider_configuration_fingerprint = "b".repeat(64);
        raster.raster = Some(ProviderRasterInputV1 {
            width: 1,
            height: 1,
            payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
            coordinate_space: "page".to_owned(),
            units: "opaque".to_owned(),
            raw_payload_hex: "ff00".to_owned(),
        });

        assert_ne!(online.input_view_id, raster.input_view_id);
        assert_ne!(
            online.requested_input_modalities,
            raster.requested_input_modalities
        );
        let online_binding = canonical_ink_comparison_binding(&online).unwrap();
        let raster_binding = canonical_ink_comparison_binding(&raster).unwrap();
        assert_eq!(online_binding, raster_binding);
        assert_eq!(
            online_binding.schema_version,
            CANONICAL_INK_COMPARISON_BINDING_SCHEMA_VERSION
        );
        assert_eq!(
            online_binding.raster_pixel_parity,
            BenchmarkRasterPixelParityV1::Unverified
        );
    }

    #[test]
    fn canonical_ink_binding_changes_with_samples_order_frames_source_or_context() {
        let base = canonical_comparison_request_fixture();
        let binding = canonical_ink_comparison_binding(&base).unwrap();

        let mut changed_sample = base.clone();
        changed_sample.samples[0]
            .effective_position
            .as_mut()
            .unwrap()
            .x_raw += 1;
        assert_ne!(
            binding,
            canonical_ink_comparison_binding(&changed_sample).unwrap()
        );

        let mut changed_order = base.clone();
        changed_order.samples.swap(0, 1);
        assert_ne!(
            binding,
            canonical_ink_comparison_binding(&changed_order).unwrap()
        );

        let mut changed_frame = base.clone();
        changed_frame.stroke_views[0]
            .view_frame
            .as_mut()
            .unwrap()
            .canvas_pan_x_bits = 1.0f64.to_bits();
        assert_ne!(
            binding,
            canonical_ink_comparison_binding(&changed_frame).unwrap()
        );

        let mut changed_source = base.clone();
        changed_source.samples[0].stroke.source_api = "wintab".to_owned();
        assert_ne!(
            binding,
            canonical_ink_comparison_binding(&changed_source).unwrap()
        );

        let mut changed_context = base.clone();
        changed_context.language_hints.push("en".to_owned());
        assert_ne!(
            binding,
            canonical_ink_comparison_binding(&changed_context).unwrap()
        );

        let mut changed_revision = base;
        changed_revision.source_revision.logical_revision += 1;
        assert_ne!(
            binding,
            canonical_ink_comparison_binding(&changed_revision).unwrap()
        );
    }

    #[test]
    fn provider_input_modalities_inherit_legacy_case_vector_exactly() {
        let mut case = case_with_split(
            "case-1",
            "writer-1",
            "session-1",
            "configuration-1",
            BenchmarkSplitV1::Train,
            "annotation-1",
        );
        case.requested_input_modalities = vec![
            ProviderInputCapabilityV1::Raster,
            ProviderInputCapabilityV1::OnlineStrokes,
        ];
        case.raster = Some(BenchmarkRasterInputSpecV1 {
            path: PathBuf::from(r"C:\fixture\blank.png"),
            width: 1,
            height: 1,
            coordinate_space: "document".to_owned(),
            units: "px".to_owned(),
        });

        let resolved = resolve_provider_input_modalities(&case, None).unwrap();
        assert_eq!(resolved, case.requested_input_modalities);
    }

    #[test]
    fn provider_input_modalities_use_explicit_available_selection() {
        let mut case = case_with_split(
            "case-1",
            "writer-1",
            "session-1",
            "configuration-1",
            BenchmarkSplitV1::Train,
            "annotation-1",
        );
        case.requested_input_modalities = vec![ProviderInputCapabilityV1::OnlineStrokes];
        case.raster = Some(BenchmarkRasterInputSpecV1 {
            path: PathBuf::from(r"C:\fixture\blank.png"),
            width: 1,
            height: 1,
            coordinate_space: "document".to_owned(),
            units: "px".to_owned(),
        });
        let explicit = [ProviderInputCapabilityV1::Raster];

        assert_eq!(
            resolve_provider_input_modalities(&case, Some(&explicit)).unwrap(),
            explicit.to_vec()
        );
        assert!(resolve_provider_input_modalities(&case, None).is_err());
    }

    #[test]
    fn provider_input_modalities_reject_invalid_and_unavailable_declarations() {
        let case = case_with_split(
            "case-1",
            "writer-1",
            "session-1",
            "configuration-1",
            BenchmarkSplitV1::Train,
            "annotation-1",
        );
        let empty = [];
        assert!(resolve_provider_input_modalities(&case, Some(&empty)).is_err());

        let duplicate = [
            ProviderInputCapabilityV1::OnlineStrokes,
            ProviderInputCapabilityV1::OnlineStrokes,
        ];
        assert!(resolve_provider_input_modalities(&case, Some(&duplicate)).is_err());

        let over_cap = [
            ProviderInputCapabilityV1::OnlineStrokes,
            ProviderInputCapabilityV1::Raster,
            ProviderInputCapabilityV1::OnlineStrokes,
        ];
        assert!(resolve_provider_input_modalities(&case, Some(&over_cap)).is_err());

        let unavailable_raster = [ProviderInputCapabilityV1::Raster];
        assert!(resolve_provider_input_modalities(&case, Some(&unavailable_raster)).is_err());

        let mut no_selected_strokes = case;
        no_selected_strokes.selected_strokes.clear();
        let unavailable_online = [ProviderInputCapabilityV1::OnlineStrokes];
        assert!(
            resolve_provider_input_modalities(&no_selected_strokes, Some(&unavailable_online))
                .is_err()
        );
    }

    #[test]
    fn generated_raster_spec_is_versioned_and_bounded() {
        let valid = generated_raster_spec();
        assert!(validate_generated_raster_spec(&valid).is_ok());

        let mut unsupported_version = valid;
        unsupported_version.projection_schema_version = 2;
        assert!(validate_generated_raster_spec(&unsupported_version).is_err());

        let mut zero_width = valid;
        zero_width.output_width_px = 0;
        assert!(validate_generated_raster_spec(&zero_width).is_err());

        let mut output_area_over_cap = valid;
        output_area_over_cap.output_width_px = 513;
        output_area_over_cap.output_height_px = 512;
        assert!(validate_generated_raster_spec(&output_area_over_cap).is_err());

        let mut empty_crop = valid;
        empty_crop.source_crop.right_px_exclusive = empty_crop.source_crop.left_px;
        assert!(validate_generated_raster_spec(&empty_crop).is_err());

        let mut crop_dimension_over_cap = valid;
        crop_dimension_over_cap.source_crop.right_px_exclusive = i32::MAX;
        assert!(validate_generated_raster_spec(&crop_dimension_over_cap).is_err());

        let mut crop_area_over_cap = valid;
        crop_area_over_cap.source_crop = BenchmarkGeneratedRasterCropV1 {
            left_px: -4096,
            top_px: -4096,
            right_px_exclusive: 4097,
            bottom_px_exclusive: 4096,
        };
        assert!(validate_generated_raster_spec(&crop_area_over_cap).is_err());
    }

    #[test]
    fn legacy_file_raster_manifest_deserializes_without_generated_source_field() {
        let mut case = case_with_split(
            "case-1",
            "writer-1",
            "session-1",
            "configuration-1",
            BenchmarkSplitV1::Train,
            "annotation-1",
        );
        case.requested_input_modalities = vec![ProviderInputCapabilityV1::Raster];
        case.raster = Some(BenchmarkRasterInputSpecV1 {
            path: PathBuf::from(r"C:\fixture\blank.png"),
            width: 1,
            height: 1,
            coordinate_space: "document".to_owned(),
            units: "px".to_owned(),
        });

        let mut manifest_value = serde_json::to_value(&case).unwrap();
        let case_object = manifest_value.as_object_mut().unwrap();
        assert!(case_object.remove("generated_raster").is_none());
        let decoded: BenchmarkCaseSpecV1 = serde_json::from_value(manifest_value).unwrap();

        assert_eq!(decoded.raster, case.raster);
        assert_eq!(decoded.generated_raster, None);
        assert_eq!(
            resolve_provider_input_modalities(&decoded, None).unwrap(),
            vec![ProviderInputCapabilityV1::Raster]
        );
    }

    #[test]
    fn generated_raster_is_a_raster_source_without_capability_fallback() {
        let mut case = case_with_split(
            "case-1",
            "writer-1",
            "session-1",
            "configuration-1",
            BenchmarkSplitV1::Train,
            "annotation-1",
        );
        case.generated_raster = Some(generated_raster_spec());
        assert!(validate_raster_source_declaration(None, case.generated_raster.as_ref()).is_ok());

        // The legacy default stays OnlineStrokes and retains the old source /
        // modality consistency rule. An explicit OnlineStrokes override can
        // ignore a declared generated raster without switching modalities.
        assert!(resolve_provider_input_modalities(&case, None).is_err());
        let explicit_online = [ProviderInputCapabilityV1::OnlineStrokes];
        assert_eq!(
            resolve_provider_input_modalities(&case, Some(&explicit_online)).unwrap(),
            explicit_online.to_vec()
        );
        let explicit_raster = [ProviderInputCapabilityV1::Raster];
        assert_eq!(
            resolve_provider_input_modalities(&case, Some(&explicit_raster)).unwrap(),
            explicit_raster.to_vec()
        );

        let file_raster = BenchmarkRasterInputSpecV1 {
            path: PathBuf::from(r"C:\fixture\blank.png"),
            width: 1,
            height: 1,
            coordinate_space: "document".to_owned(),
            units: "px".to_owned(),
        };
        assert!(
            validate_raster_source_declaration(Some(&file_raster), case.generated_raster.as_ref())
                .is_err()
        );

        case.generated_raster = None;
        assert!(resolve_provider_input_modalities(&case, Some(&explicit_raster)).is_err());

        case.generated_raster = Some(generated_raster_spec());
        case.requested_input_modalities = vec![ProviderInputCapabilityV1::Raster];
        assert_eq!(
            resolve_provider_input_modalities(&case, None).unwrap(),
            explicit_raster.to_vec()
        );
    }

    #[test]
    fn generated_raster_materializes_once_and_links_origin_to_each_request() {
        let (state, target) = generated_raster_journal_fixture();
        let source_revision = ProviderSourceRevisionV1::from_journal(&state);
        let selected = [target.clone()];
        let materialized = materialize_generated_raster(
            &state,
            &source_revision,
            &selected,
            &generated_raster_spec(),
        )
        .unwrap();
        let raster_modes = vec![ProviderInputCapabilityV1::Raster];

        let request_a = generated_raster_request(
            &state,
            &target,
            "generated-raster-config-a",
            raster_modes.clone(),
            Some(materialized.request_input.clone()),
        );
        let binding_a = canonical_ink_comparison_binding(&request_a).unwrap();
        let selected_a = benchmark_selected_strokes_from_request(&request_a).unwrap();
        let origin_a = generated_raster_origin_for_request(
            &request_a,
            Some(&materialized),
            &binding_a,
            &selected_a,
        )
        .unwrap()
        .unwrap();

        let request_b = generated_raster_request(
            &state,
            &target,
            "generated-raster-config-b",
            raster_modes,
            Some(materialized.request_input.clone()),
        );
        let binding_b = canonical_ink_comparison_binding(&request_b).unwrap();
        let selected_b = benchmark_selected_strokes_from_request(&request_b).unwrap();
        let origin_b = generated_raster_origin_for_request(
            &request_b,
            Some(&materialized),
            &binding_b,
            &selected_b,
        )
        .unwrap()
        .unwrap();

        assert_eq!(request_a.input_view_id, request_b.input_view_id);
        assert_eq!(binding_a, binding_b);
        assert_eq!(origin_a, origin_b);
        assert_eq!(origin_a.schema_version, 1);
        assert_eq!(
            origin_a.canonical_ink_comparison_binding_sha256,
            binding_a.sha256_hex
        );
        assert_eq!(
            binding_a.raster_pixel_parity,
            BenchmarkRasterPixelParityV1::Unverified
        );
        assert_eq!(origin_a.producer.source_revision, request_a.source_revision);
        assert_eq!(origin_a.producer.selected_strokes, selected_a);
        assert_eq!(origin_a.producer.stroke_draw_order, selected_a);
        assert_eq!(origin_a.producer.physical_sample_provenance.len(), 1);
        assert_eq!(
            origin_a.producer.physical_sample_provenance[0].source_sequence_raw,
            91
        );
        assert_eq!(origin_a.producer.output_width_px, 100);
        assert_eq!(origin_a.producer.output_height_px, 100);
        assert_eq!(origin_a.producer.row_stride_bytes, 400);
        assert_eq!(
            origin_a.producer.pixel_layout,
            "rgba8_premultiplied_srgb_top_down"
        );
        assert_eq!(origin_a.producer.png_bytes_sha256, materialized.sha256_hex);
        let serialized_origin = serde_json::to_string(&origin_a).unwrap();
        let raw_sample_payload_hex = "d3".repeat(128);
        assert!(!serialized_origin.contains(&materialized.request_input.raw_payload_hex));
        assert!(!serialized_origin.contains(&raw_sample_payload_hex));
        assert!(!serialized_origin.contains("generated-raster-config"));
        assert!(!serialized_origin.contains("C:\\"));
        let raster_provenance = raster_provenance_for_request(
            &request_a.requested_input_modalities,
            Some(&materialized),
        )
        .unwrap();
        assert_eq!(
            raster_provenance,
            (
                Some(materialized.byte_count),
                Some(materialized.sha256_hex.clone())
            )
        );
        assert!(materialized.byte_count <= MAX_RASTER_INPUT_BYTES);
    }

    #[test]
    fn generated_raster_origin_uses_journal_order_for_interleaved_strokes() {
        let (state, first, second) = interleaved_generated_raster_journal_fixture();
        let source_revision = ProviderSourceRevisionV1::from_journal(&state);
        let caller_selection = [second.clone(), first.clone()];
        let raw_samples_before = state
            .physical_samples
            .iter()
            .map(|sample| sample.sample.clone())
            .collect::<Vec<_>>();
        let physical_journal_sequences = state
            .physical_samples
            .iter()
            .map(|sample| sample.sequence)
            .collect::<Vec<_>>();

        let materialized = materialize_generated_raster(
            &state,
            &source_revision,
            &caller_selection,
            &generated_raster_spec(),
        )
        .unwrap();
        let request = generated_raster_request_for_strokes(
            &state,
            &caller_selection,
            "generated-raster-interleaved-config-a",
            vec![ProviderInputCapabilityV1::Raster],
            Some(materialized.request_input.clone()),
        );
        let binding = canonical_ink_comparison_binding(&request).unwrap();
        let request_strokes = benchmark_selected_strokes_from_request(&request).unwrap();
        let origin = generated_raster_origin_for_request(
            &request,
            Some(&materialized),
            &binding,
            &request_strokes,
        )
        .unwrap()
        .unwrap();

        let canonical_strokes = vec![
            BenchmarkStrokeRefV1::from(&first),
            BenchmarkStrokeRefV1::from(&second),
        ];
        assert_eq!(request_strokes, canonical_strokes);
        assert_eq!(origin.producer.selected_strokes, canonical_strokes);
        assert_eq!(origin.producer.stroke_draw_order, canonical_strokes);
        assert_eq!(
            origin
                .producer
                .physical_sample_provenance
                .iter()
                .map(|sample| sample.source_sequence_raw)
                .collect::<Vec<_>>(),
            vec![501, 601, 502]
        );
        assert_eq!(
            origin
                .producer
                .physical_sample_provenance
                .iter()
                .map(|sample| sample.journal_sequence)
                .collect::<Vec<_>>(),
            physical_journal_sequences
        );
        assert_eq!(
            state
                .physical_samples
                .iter()
                .map(|sample| sample.sample.clone())
                .collect::<Vec<_>>(),
            raw_samples_before
        );
    }

    #[test]
    fn generated_raster_rejects_mismatched_revision_selection_and_oversized_png() {
        let (state, target) = generated_raster_journal_fixture();
        let source_revision = ProviderSourceRevisionV1::from_journal(&state);
        let selected = [target.clone()];
        let spec = generated_raster_spec();
        assert_eq!(
            validate_generated_raster_png_size(usize::try_from(MAX_RASTER_INPUT_BYTES).unwrap())
                .unwrap(),
            MAX_RASTER_INPUT_BYTES
        );
        assert!(
            validate_generated_raster_png_size(
                usize::try_from(MAX_RASTER_INPUT_BYTES).unwrap() + 1
            )
            .is_err()
        );

        let mut wrong_revision = source_revision.clone();
        wrong_revision.last_sequence += 1;
        assert!(materialize_generated_raster(&state, &wrong_revision, &selected, &spec).is_err());

        let mut wrong_target = target.clone();
        wrong_target.stroke_id.push_str("-other");
        assert!(
            materialize_generated_raster(&state, &source_revision, &[wrong_target], &spec).is_err()
        );

        let materialized =
            materialize_generated_raster(&state, &source_revision, &selected, &spec).unwrap();
        let request = generated_raster_request(
            &state,
            &target,
            "generated-raster-config-a",
            vec![ProviderInputCapabilityV1::Raster],
            Some(materialized.request_input.clone()),
        );
        let binding = canonical_ink_comparison_binding(&request).unwrap();
        let request_strokes = benchmark_selected_strokes_from_request(&request).unwrap();

        let mut stale_request = request.clone();
        stale_request.source_revision.logical_revision += 1;
        let stale_strokes = benchmark_selected_strokes_from_request(&stale_request).unwrap();
        assert!(
            generated_raster_origin_for_request(
                &stale_request,
                Some(&materialized),
                &binding,
                &stale_strokes,
            )
            .is_err()
        );

        let mut wrong_selection_request = request;
        wrong_selection_request.stroke_views[0]
            .stroke
            .stroke_id
            .push_str("-other");
        let wrong_request_strokes =
            benchmark_selected_strokes_from_request(&wrong_selection_request).unwrap();
        assert!(
            generated_raster_origin_for_request(
                &wrong_selection_request,
                Some(&materialized),
                &binding,
                &wrong_request_strokes,
            )
            .is_err()
        );
        let expected_request_strokes = selected
            .iter()
            .map(BenchmarkStrokeRefV1::from)
            .collect::<Vec<_>>();
        assert_eq!(request_strokes, expected_request_strokes);
    }

    #[test]
    fn file_raster_and_online_only_rows_have_no_generated_origin() {
        let (state, target) = generated_raster_journal_fixture();
        let source_revision = ProviderSourceRevisionV1::from_journal(&state);
        let target_refs = [target.clone()];
        let generated = materialize_generated_raster(
            &state,
            &source_revision,
            &target_refs,
            &generated_raster_spec(),
        )
        .unwrap();

        let directory = temp_dir("external-raster-input");
        fs::create_dir(&directory).unwrap();
        let raster_path = directory.join("external.bin");
        let file_bytes = [0x10, 0x20, 0x30, 0xff];
        fs::write(&raster_path, file_bytes).unwrap();
        let file_raster = read_raster_input(&BenchmarkRasterInputSpecV1 {
            path: raster_path.clone(),
            width: 1,
            height: 1,
            coordinate_space: "document".to_owned(),
            units: "px".to_owned(),
        })
        .unwrap();
        assert!(file_raster.generated_origin.is_none());
        let file_request = generated_raster_request(
            &state,
            &target,
            "external-file-config",
            vec![ProviderInputCapabilityV1::Raster],
            Some(file_raster.request_input.clone()),
        );
        let file_binding = canonical_ink_comparison_binding(&file_request).unwrap();
        let file_selected = benchmark_selected_strokes_from_request(&file_request).unwrap();
        assert_eq!(
            generated_raster_origin_for_request(
                &file_request,
                Some(&file_raster),
                &file_binding,
                &file_selected,
            )
            .unwrap(),
            None
        );

        let online_request = generated_raster_request(
            &state,
            &target,
            "online-only-config",
            vec![ProviderInputCapabilityV1::OnlineStrokes],
            None,
        );
        let online_binding = canonical_ink_comparison_binding(&online_request).unwrap();
        let online_selected = benchmark_selected_strokes_from_request(&online_request).unwrap();
        assert_eq!(
            generated_raster_origin_for_request(
                &online_request,
                Some(&generated),
                &online_binding,
                &online_selected,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            raster_provenance_for_request(
                &online_request.requested_input_modalities,
                Some(&generated)
            )
            .unwrap(),
            (None, None)
        );

        fs::remove_file(raster_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn raster_provenance_is_attributed_only_to_requests_selecting_raster() {
        let raster_hash = "a".repeat(64);
        let raster = LoadedRasterInput {
            request_input: ProviderRasterInputV1 {
                width: 1,
                height: 1,
                payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
                coordinate_space: "document".to_owned(),
                units: "px".to_owned(),
                raw_payload_hex: "00".to_owned(),
            },
            byte_count: 1,
            sha256_hex: raster_hash.clone(),
            generated_origin: None,
        };
        let online_only = [ProviderInputCapabilityV1::OnlineStrokes];
        let raster_only = [ProviderInputCapabilityV1::Raster];

        assert_eq!(
            raster_provenance_for_request(&online_only, Some(&raster)).unwrap(),
            (None, None)
        );
        assert_eq!(
            raster_provenance_for_request(&raster_only, Some(&raster)).unwrap(),
            (Some(1), Some(raster_hash))
        );
        assert!(raster_provenance_for_request(&raster_only, None).is_err());
    }

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("lassoink-{label}-{}-{unique}", process::id()))
    }

    #[test]
    fn sha256_known_vectors_and_streamed_artifact_match() {
        assert_eq!(
            hex_encode(&Sha256::digest(b"")).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_encode(&Sha256::digest(b"abc")).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let directory = temp_dir("hash-vector");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("explicit-model.bin");
        fs::write(&path, b"abc").unwrap();
        let (length, digest) = hash_explicit_file(&path, MAX_PROVIDER_ARTIFACT_HASH_BYTES).unwrap();
        assert_eq!(length, 3);
        assert_eq!(digest, hex_encode(&Sha256::digest(b"abc")).unwrap());
        assert!(hash_explicit_file(&path, 2).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn raw_response_frame_serialization_preserves_length_and_payload_bytes() {
        let frames = vec![ProviderRawResponseFrameV1 {
            ordinal: 1,
            payload_bytes: vec![0, 0x7f, 0xff],
        }];
        let encoded = encode_response_frames(frames).unwrap();
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0].ordinal, 1);
        assert_eq!(encoded[0].length_prefix_be_hex, "00000003");
        assert_eq!(encoded[0].payload_hex, "007fff");
    }

    #[test]
    fn executable_digest_is_not_presented_as_model_digest() {
        let executable = ProviderArtifactDigestV1 {
            artifact_id: "provider-exe".to_owned(),
            role: ProviderArtifactRoleV1::Executable,
            byte_count: 3,
            sha256_hex: hex_encode(&Sha256::digest(b"exe")).unwrap(),
            observation: "test".to_owned(),
        };
        let (model_artifacts, reason) =
            model_artifact_hash_status(std::slice::from_ref(&executable)).unwrap();
        assert!(model_artifacts.is_empty());
        assert!(
            reason
                .as_deref()
                .is_some_and(|value| value.contains("not model-content hashes"))
        );

        let tokenizer = ProviderArtifactDigestV1 {
            artifact_id: "tokenizer-1".to_owned(),
            role: ProviderArtifactRoleV1::Tokenizer,
            byte_count: 4,
            sha256_hex: hex_encode(&Sha256::digest(b"token")).unwrap(),
            observation: "test".to_owned(),
        };
        let (model_artifacts, reason) =
            model_artifact_hash_status(&[executable.clone(), tokenizer]).unwrap();
        assert!(model_artifacts.is_empty());
        assert!(reason.is_some());

        let model = ProviderArtifactDigestV1 {
            artifact_id: "model-1".to_owned(),
            role: ProviderArtifactRoleV1::Model,
            byte_count: 4,
            sha256_hex: hex_encode(&Sha256::digest(b"model")).unwrap(),
            observation: "test".to_owned(),
        };
        let (model_artifacts, reason) =
            model_artifact_hash_status(&[executable, model.clone()]).unwrap();
        assert_eq!(model_artifacts, vec![model]);
        assert!(reason.is_none());
    }

    #[test]
    fn senocr_quality_evidence_binds_profile_and_all_twelve_prelaunch_asset_hashes() {
        let provider = senocr_quality_test_provider(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len());
        let evidence = benchmark_quality_evidence(&provider, Some(&senocr_quality_test_identity()))
            .unwrap();
        assert_eq!(
            evidence.status,
            BenchmarkQualityEvidenceStatusV1::EligibleByDeclaredSenocrEvidence
        );
        let profile = evidence.runtime_profile.as_ref().unwrap();
        assert_eq!(profile.profile_id, SENOCR_REFERENCE_RUNTIME_PROFILE_ID);
        assert_eq!(
            profile.profile_manifest_sha256,
            SENOCR_REFERENCE_RUNTIME_PROFILE_SHA256
        );
        assert_eq!(profile.distribution_count, 41);
        assert_eq!(profile.python_version, "3.13.17");
        assert_eq!(profile.platform, "windows-x64");

        let coverage = evidence.model_asset_coverage.as_ref().unwrap();
        assert_eq!(coverage.model_revision, SENOCR_REFERENCE_MODEL_REVISION);
        assert_eq!(coverage.required_asset_count, 12);
        assert_eq!(coverage.observed_asset_count, 12);
        assert!(coverage.missing_asset_names.is_empty());
        assert_eq!(coverage.observed_assets.len(), 12);
        assert_eq!(
            coverage.status,
            BenchmarkModelAssetCoverageStatusV1::CompletePrelaunchObservations
        );
        assert!(quality_metrics_allowed(&evidence));

        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains(r"C:\runner\models\senocr"));
        assert!(!serialized.contains("asset_root"));
        assert!(serialized.contains(SENOCR_REFERENCE_RUNTIME_PROFILE_SHA256));
    }

    #[test]
    fn quality_scoring_requires_complete_runtime_and_model_asset_evidence() {
        let annotation = annotation_for("case-1", "annotation-1", "xin chào");
        let policy = BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1;
        let result = senocr_quality_test_result("xin chào");

        let complete_provider =
            senocr_quality_test_provider(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len());
        let complete_evidence =
            benchmark_quality_evidence(&complete_provider, Some(&senocr_quality_test_identity()))
                .unwrap();
        let (complete_metrics, complete_reason) = candidate_metrics_for_quality_evidence(
            &result,
            Some(&annotation),
            Some(policy),
            &complete_evidence,
        );
        assert_eq!(complete_metrics.len(), 1);
        assert_eq!(
            complete_metrics[0]
                .nfc_unicode_scalar_cer
                .as_ref()
                .unwrap()
                .errors,
            0
        );
        assert!(complete_reason.is_none());

        let partial_provider =
            senocr_quality_test_provider(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len() - 1);
        let partial_evidence =
            benchmark_quality_evidence(&partial_provider, Some(&senocr_quality_test_identity()))
                .unwrap();
        let (partial_metrics, partial_reason) = candidate_metrics_for_quality_evidence(
            &result,
            Some(&annotation),
            Some(policy),
            &partial_evidence,
        );
        assert!(partial_metrics.is_empty());
        assert!(partial_reason.is_some());

        let mut mismatched_identity = senocr_quality_test_identity();
        mismatched_identity.resource_version = Some("different-runtime-profile".to_owned());
        let mismatched_evidence =
            benchmark_quality_evidence(&complete_provider, Some(&mismatched_identity)).unwrap();
        let (mismatched_metrics, mismatched_reason) = candidate_metrics_for_quality_evidence(
            &result,
            Some(&annotation),
            Some(policy),
            &mismatched_evidence,
        );
        assert!(mismatched_metrics.is_empty());
        assert!(mismatched_reason.is_some());
        assert_eq!(result.candidates[0].recognized_text, "xin chào");
    }

    #[test]
    fn unbound_provider_ground_truth_metrics_do_not_enter_paired_comparisons() {
        let annotation = annotation_for("case-1", "annotation-1", "xin chào");
        let policy = BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1;
        let mut unbound_provider = senocr_quality_test_provider(0);
        unbound_provider.provider_id = "mock-provider".to_owned();
        unbound_provider.configuration_id = "mock-configuration".to_owned();
        unbound_provider.configuration.configuration_id = "mock-configuration".to_owned();
        let unbound_identity = ProviderIdentityV1 {
            provider_id: "mock-provider".to_owned(),
            provider_version: "test-only-mock".to_owned(),
            model_version: None,
            resource_version: None,
        };
        let unbound_evidence =
            benchmark_quality_evidence(&unbound_provider, Some(&unbound_identity)).unwrap();
        assert_eq!(
            unbound_evidence.status,
            BenchmarkQualityEvidenceStatusV1::ProviderPolicyNotApplicable
        );
        assert!(!quality_metrics_allowed(&unbound_evidence));

        let mut unbound_result = senocr_quality_test_result("xin chào");
        unbound_result.provider = unbound_identity;
        unbound_result.provider_configuration_id = "mock-configuration".to_owned();
        let (unbound_metrics, unbound_reason) = candidate_metrics_for_quality_evidence(
            &unbound_result,
            Some(&annotation),
            Some(policy),
            &unbound_evidence,
        );
        assert!(unbound_metrics.is_empty());
        assert!(unbound_reason.is_some());

        let senocr_provider =
            senocr_quality_test_provider(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len());
        let senocr_evidence =
            benchmark_quality_evidence(&senocr_provider, Some(&senocr_quality_test_identity()))
                .unwrap();
        let (senocr_metrics, senocr_reason) = candidate_metrics_for_quality_evidence(
            &senocr_quality_test_result("xin chào"),
            Some(&annotation),
            Some(policy),
            &senocr_evidence,
        );
        assert_eq!(senocr_metrics.len(), 1);
        assert!(senocr_reason.is_none());

        let observations = vec![
            EvaluationObservation {
                case_id: "case-1".to_owned(),
                provider_id: "mock-provider".to_owned(),
                configuration_id: "mock-configuration".to_owned(),
                split: BenchmarkSplitV1::Evaluation,
                writer_key: "writer-1".to_owned(),
                session_key: "session-1".to_owned(),
                cer: unbound_metrics
                    .first()
                    .and_then(|metrics| metrics.nfc_unicode_scalar_cer.clone()),
                wer: unbound_metrics
                    .first()
                    .and_then(|metrics| metrics.whitespace_token_syllable_wer.clone()),
            },
            EvaluationObservation {
                case_id: "case-1".to_owned(),
                provider_id: SENOCR_REFERENCE_PROVIDER_ID.to_owned(),
                configuration_id: SENOCR_REFERENCE_CONFIGURATION_ID.to_owned(),
                split: BenchmarkSplitV1::Evaluation,
                writer_key: "writer-1".to_owned(),
                session_key: "session-1".to_owned(),
                cer: senocr_metrics[0].nfc_unicode_scalar_cer.clone(),
                wer: senocr_metrics[0].whitespace_token_syllable_wer.clone(),
            },
        ];
        let corpus = BenchmarkCorpusManifestV1 {
            schema_version: BENCHMARK_SCHEMA_VERSION,
            corpus_id: "quality-gate-corpus".to_owned(),
            split_key: BenchmarkSplitKeyV1::Session,
            bootstrap_cluster: BenchmarkClusterKeyV1::Session,
            bootstrap_seed: 1,
            bootstrap_replicates: 100,
            tokenization_policy: policy,
            cases: vec![annotation],
        };
        let comparisons =
            build_paired_comparisons_with_work_budget(&observations, &corpus, 10_000).unwrap();
        assert_eq!(comparisons.len(), 1);
        assert_eq!(comparisons[0].nfc_cer_paired_case_count, 0);
        assert_eq!(comparisons[0].whitespace_syllable_wer_paired_case_count, 0);
        assert!(comparisons[0].nfc_cer_rate_difference.is_none());
        assert!(comparisons[0].whitespace_syllable_wer_rate_difference.is_none());
        assert!(comparisons[0]
            .nfc_cer_unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("no paired cases")));
    }

    #[test]
    fn senocr_quality_evidence_withholds_metrics_for_missing_asset_identity_and_size_mismatches() {
        let partial = senocr_quality_test_provider(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len() - 1);
        let partial_evidence =
            benchmark_quality_evidence(&partial, Some(&senocr_quality_test_identity())).unwrap();
        assert_eq!(
            partial_evidence.status,
            BenchmarkQualityEvidenceStatusV1::IncompleteSenocrEvidence
        );
        let partial_coverage = partial_evidence.model_asset_coverage.as_ref().unwrap();
        assert_eq!(partial_coverage.observed_asset_count, 11);
        assert_eq!(partial_coverage.missing_asset_names.len(), 1);
        assert_eq!(
            partial_coverage.missing_asset_names[0],
            SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES[11].0
        );
        assert!(!quality_metrics_allowed(&partial_evidence));

        let complete = senocr_quality_test_provider(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len());
        let mut wrong_identity = senocr_quality_test_identity();
        wrong_identity.resource_version = Some("different-runtime-profile".to_owned());
        let identity_evidence = benchmark_quality_evidence(&complete, Some(&wrong_identity)).unwrap();
        assert_eq!(
            identity_evidence.status,
            BenchmarkQualityEvidenceStatusV1::MismatchedSenocrEvidence
        );
        assert!(identity_evidence.runtime_profile.is_none());
        assert!(!quality_metrics_allowed(&identity_evidence));

        let mut wrong_size = complete;
        wrong_size.artifact_digests[1].byte_count += 1;
        let size_evidence = benchmark_quality_evidence(
            &wrong_size,
            Some(&senocr_quality_test_identity()),
        )
        .unwrap();
        assert_eq!(
            size_evidence.status,
            BenchmarkQualityEvidenceStatusV1::MismatchedSenocrEvidence
        );
        assert_eq!(
            size_evidence.model_asset_coverage.as_ref().unwrap().status,
            BenchmarkModelAssetCoverageStatusV1::MismatchedPrelaunchManifest
        );
        assert!(!quality_metrics_allowed(&size_evidence));
    }

    #[test]
    fn senocr_quality_evidence_rejects_artifact_paths_outside_configured_root() {
        let mut provider = senocr_quality_test_provider(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len());
        let mut manifest = ApprovedBenchmarkProviderV1 {
            provider_id: provider.provider_id.clone(),
            executable_path: PathBuf::from(r"C:\python\python.exe"),
            arguments: Vec::new(),
            requested_input_modalities: Some(vec![ProviderInputCapabilityV1::Raster]),
            protocol_configuration: provider.configuration.clone(),
            artifacts: Vec::new(),
            timeouts: None,
        };
        let root = PathBuf::from(r"C:\runner\models\senocr");
        for (index, (asset_name, _)) in SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.iter().enumerate() {
            manifest.artifacts.push(ProviderArtifactPathV1 {
                artifact_id: format!("required-asset-{index:02}"),
                role: ProviderArtifactRoleV1::Resource,
                path: if index == 0 {
                    PathBuf::from(r"C:\runner\different\added_tokens.json")
                } else {
                    root.join(*asset_name)
                },
            });
        }
        manifest.artifacts.insert(
            0,
            ProviderArtifactPathV1 {
                artifact_id: "python-executable".to_owned(),
                role: ProviderArtifactRoleV1::Executable,
                path: PathBuf::from(r"C:\python\python.exe"),
            },
        );
        provider.senocr_asset_plan = senocr_asset_plan_from_manifest(&manifest);
        let evidence = benchmark_quality_evidence(&provider, Some(&senocr_quality_test_identity()))
            .unwrap();
        assert_eq!(
            evidence.status,
            BenchmarkQualityEvidenceStatusV1::MismatchedSenocrEvidence
        );
        assert!(!quality_metrics_allowed(&evidence));
        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains(r"C:\runner\different"));
    }

    #[test]
    fn legacy_benchmark_rows_default_to_unassessed_quality_evidence() {
        #[derive(Deserialize)]
        struct LegacyEvidenceField {
            #[serde(default)]
            quality_evidence: BenchmarkQualityEvidenceV1,
        }

        let legacy: LegacyEvidenceField = serde_json::from_str("{}").unwrap();
        assert_eq!(
            legacy.quality_evidence.status,
            BenchmarkQualityEvidenceStatusV1::LegacyUnassessed
        );
        assert!(!quality_metrics_allowed(&legacy.quality_evidence));
        assert!(legacy.quality_evidence.unavailable_reason.is_some());
    }

    #[test]
    fn senocr_profile_binding_matches_the_checked_in_full_manifest() {
        let manifest = load_senocr_runtime_profile_manifest().unwrap();
        assert_eq!(
            manifest.distribution_count,
            SENOCR_REFERENCE_RUNTIME_DISTRIBUTION_COUNT
        );
        assert_eq!(
            manifest.python_version,
            SENOCR_REFERENCE_PYTHON_VERSION
        );
        assert_eq!(
            manifest.platform,
            SENOCR_REFERENCE_PLATFORM
        );
        assert_eq!(manifest.installed_distribution_closure.len(), 41);
        assert_eq!(manifest.root_pins.len(), SENOCR_REFERENCE_ROOT_PIN_COUNT);

        let provider = senocr_quality_test_provider(SENOCR_REFERENCE_ASSET_NAMES_AND_BYTES.len());
        let evidence = benchmark_quality_evidence(&provider, Some(&senocr_quality_test_identity()))
            .unwrap();
        let serialized_artifact_evidence = serde_json::to_vec(&evidence).unwrap();
        let restored: BenchmarkQualityEvidenceV1 =
            serde_json::from_slice(&serialized_artifact_evidence).unwrap();
        let restored_profile = restored.runtime_profile.unwrap();
        assert_eq!(restored_profile.manifest_schema_version, manifest.schema_version);
        assert_eq!(restored_profile.profile_manifest_sha256, SENOCR_REFERENCE_RUNTIME_PROFILE_SHA256);
        assert_eq!(restored_profile.distribution_count, 41);
        assert_eq!(
            restored_profile.installed_distribution_closure,
            manifest.installed_distribution_closure
        );
        assert_eq!(restored_profile.root_pins, manifest.root_pins);
    }

    #[test]
    fn nfc_cer_and_vietnamese_mark_inventory_are_separate() {
        let decomposed = annotation("a\u{0301}");
        let exact = score_candidate(
            "á",
            &decomposed,
            BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            0,
        )
        .unwrap();
        assert_eq!(exact.nfc_unicode_scalar_cer.unwrap().errors, 0);
        assert_eq!(exact.tone_mark_inventory_difference_count, 0);
        assert_eq!(
            exact.vietnamese_tone_mark_alignment_edits.unwrap().errors,
            0
        );

        let tone = score_candidate(
            "hòa",
            &annotation("hoa"),
            BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            0,
        )
        .unwrap();
        assert_eq!(tone.tone_mark_inventory_difference_count, 1);
        assert_eq!(tone.vowel_modifier_inventory_difference_count, 0);
        assert_eq!(tone.vietnamese_tone_mark_alignment_edits.unwrap().errors, 1);

        let modifier = score_candidate(
            "â",
            &annotation("a"),
            BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            0,
        )
        .unwrap();
        assert_eq!(modifier.tone_mark_inventory_difference_count, 0);
        assert_eq!(modifier.vowel_modifier_inventory_difference_count, 1);
        assert_eq!(
            modifier
                .vietnamese_vowel_modifier_alignment_edits
                .unwrap()
                .errors,
            1
        );
    }

    #[test]
    fn aligned_mark_metric_detects_tone_swaps_hidden_by_global_histogram() {
        let metrics = score_candidate(
            "aá",
            &annotation("áa"),
            BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            0,
        )
        .unwrap();
        assert_eq!(metrics.tone_mark_inventory_difference_count, 0);
        assert!(
            metrics
                .vietnamese_tone_mark_alignment_edits
                .is_some_and(|metric| metric.errors > 0)
        );
    }

    #[test]
    fn mixed_vi_english_reference_with_foreign_accent_withholds_vietnamese_mark_errors() {
        let mut reference = annotation("café viết");
        reference.reference_language_scope = BenchmarkReferenceLanguageScopeV1::MixedOrUnknown;
        let metrics = score_candidate(
            "cafe viết",
            &reference,
            BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            0,
        )
        .unwrap();
        assert!(metrics.nfc_unicode_scalar_cer.is_some());
        assert!(metrics.whitespace_token_syllable_wer.is_some());
        assert!(metrics.tone_mark_inventory_difference_count > 0);
        assert!(metrics.vietnamese_tone_mark_alignment_edits.is_none());
        assert!(metrics.vietnamese_vowel_modifier_alignment_edits.is_none());
        assert!(
            metrics
                .vietnamese_tone_mark_unavailable_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("mixed/unknown"))
        );
    }

    #[test]
    fn whitespace_syllable_wer_and_boundary_difference_are_distinct() {
        let metrics = score_candidate(
            "tôi-viết",
            &annotation("tôi viết"),
            BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            0,
        )
        .unwrap();
        assert_eq!(metrics.whitespace_token_syllable_wer.unwrap().errors, 2);
        assert_eq!(
            metrics.syllable_boundary_offset_diagnostic.unwrap().errors,
            1
        );
        assert!(
            metrics
                .syllable_boundary_diagnostic_policy
                .contains("not aligned boundary accuracy")
        );
        assert!(metrics.lexical_wer_unavailable_reason.contains("lexical"));
        assert!(
            metrics
                .delayed_attachment_unavailable_reason
                .contains("no delayed-mark")
        );
    }

    #[test]
    fn boundary_offset_diagnostic_is_not_read_as_alignment_accuracy() {
        let metrics = score_candidate(
            "xab cd",
            &annotation("ab cd"),
            BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            0,
        )
        .unwrap();
        let diagnostic = metrics.syllable_boundary_offset_diagnostic.unwrap();
        assert_eq!(diagnostic.errors, 2);
        assert_eq!(diagnostic.reference_units, 1);
        assert!(
            metrics
                .syllable_boundary_diagnostic_policy
                .contains("not aligned boundary accuracy")
        );
    }

    #[test]
    fn edit_distance_work_cap_is_visible_as_null() {
        let reference = "a".repeat(3000);
        let hypothesis = "b".repeat(3000);
        let metrics = score_candidate(
            &hypothesis,
            &annotation(&reference),
            BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            0,
        )
        .unwrap();
        assert!(metrics.nfc_unicode_scalar_cer.is_none());
        assert!(metrics.nfc_cer_unavailable_reason.is_some());
    }

    #[test]
    fn empty_reference_denominators_are_null_with_reasons() {
        let metrics = score_candidate(
            "ink",
            &annotation(""),
            BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            0,
        )
        .unwrap();
        assert!(metrics.nfc_unicode_scalar_cer.is_none());
        assert!(metrics.nfc_cer_unavailable_reason.is_some());
        assert!(metrics.whitespace_token_syllable_wer.is_none());
        assert!(metrics.whitespace_wer_unavailable_reason.is_some());
        assert!(metrics.syllable_boundary_offset_diagnostic.is_none());
        assert!(
            metrics
                .syllable_boundary_offset_diagnostic_unavailable_reason
                .is_some()
        );
    }

    #[test]
    fn paired_cluster_bootstrap_is_deterministic_and_reports_direction() {
        let cases = vec![
            PairedMetricCase {
                cluster: "writer-a".to_owned(),
                left_cer: Some(BenchmarkCountMetricV1 {
                    errors: 2,
                    reference_units: 10,
                }),
                right_cer: Some(BenchmarkCountMetricV1 {
                    errors: 1,
                    reference_units: 10,
                }),
                left_wer: Some(BenchmarkCountMetricV1 {
                    errors: 1,
                    reference_units: 5,
                }),
                right_wer: Some(BenchmarkCountMetricV1 {
                    errors: 0,
                    reference_units: 5,
                }),
            },
            PairedMetricCase {
                cluster: "writer-b".to_owned(),
                left_cer: Some(BenchmarkCountMetricV1 {
                    errors: 2,
                    reference_units: 10,
                }),
                right_cer: Some(BenchmarkCountMetricV1 {
                    errors: 1,
                    reference_units: 10,
                }),
                left_wer: Some(BenchmarkCountMetricV1 {
                    errors: 1,
                    reference_units: 5,
                }),
                right_wer: Some(BenchmarkCountMetricV1 {
                    errors: 0,
                    reference_units: 5,
                }),
            },
        ];
        let first = paired_bootstrap_for_metric(&cases, true, 100, 42)
            .unwrap()
            .0
            .unwrap();
        let second = paired_bootstrap_for_metric(&cases, true, 100, 42)
            .unwrap()
            .0
            .unwrap();
        assert_eq!(first, second);
        assert!((first.median_difference + 0.1).abs() < f64::EPSILON);
        assert_eq!(first.nominal_95_unadjusted_low, first.median_difference);
        assert_eq!(first.nominal_95_unadjusted_high, first.median_difference);
        assert_eq!(
            first.interpretation,
            BenchmarkPairwiseInterpretationV1::NominalUnadjustedExploratoryNotSelectionEvidence
        );
        assert!(!first.selection_evidence_allowed);
    }

    #[test]
    fn paired_metric_counts_are_metric_specific_and_single_cluster_is_unavailable() {
        let cases = vec![
            PairedMetricCase {
                cluster: "session-a".to_owned(),
                left_cer: Some(BenchmarkCountMetricV1 {
                    errors: 1,
                    reference_units: 10,
                }),
                right_cer: Some(BenchmarkCountMetricV1 {
                    errors: 0,
                    reference_units: 10,
                }),
                left_wer: Some(BenchmarkCountMetricV1 {
                    errors: 1,
                    reference_units: 2,
                }),
                right_wer: Some(BenchmarkCountMetricV1 {
                    errors: 0,
                    reference_units: 2,
                }),
            },
            PairedMetricCase {
                cluster: "session-b".to_owned(),
                left_cer: None,
                right_cer: None,
                left_wer: Some(BenchmarkCountMetricV1 {
                    errors: 0,
                    reference_units: 2,
                }),
                right_wer: Some(BenchmarkCountMetricV1 {
                    errors: 1,
                    reference_units: 2,
                }),
            },
        ];
        assert_eq!(metric_pair_counts(&cases, true).unwrap(), (1, 1));
        assert_eq!(metric_pair_counts(&cases, false).unwrap(), (2, 2));
        let (interval, reason) = paired_bootstrap_for_metric(&cases[..1], true, 100, 7).unwrap();
        assert!(interval.is_none());
        assert!(
            reason
                .unwrap()
                .contains("fewer than two independent clusters")
        );
    }

    #[test]
    fn bootstrap_work_budget_keeps_counts_and_marks_intervals_unavailable() {
        let mut observations = Vec::new();
        for (case_id, session_key, errors) in
            [("case-a", "session-a", 1), ("case-b", "session-b", 2)]
        {
            for (provider_id, metric_errors) in [("left", errors), ("right", errors - 1)] {
                observations.push(EvaluationObservation {
                    case_id: case_id.to_owned(),
                    provider_id: provider_id.to_owned(),
                    configuration_id: "config-1".to_owned(),
                    split: BenchmarkSplitV1::Evaluation,
                    writer_key: format!("writer-{session_key}"),
                    session_key: session_key.to_owned(),
                    cer: Some(BenchmarkCountMetricV1 {
                        errors: metric_errors,
                        reference_units: 10,
                    }),
                    wer: Some(BenchmarkCountMetricV1 {
                        errors: metric_errors,
                        reference_units: 5,
                    }),
                });
            }
        }
        let corpus = BenchmarkCorpusManifestV1 {
            schema_version: BENCHMARK_SCHEMA_VERSION,
            corpus_id: "corpus-1".to_owned(),
            split_key: BenchmarkSplitKeyV1::Session,
            bootstrap_cluster: BenchmarkClusterKeyV1::Session,
            bootstrap_seed: 13,
            bootstrap_replicates: 5_000,
            tokenization_policy: BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            cases: vec![annotation_for("case-a", "ann-a", "x")],
        };
        let comparisons =
            build_paired_comparisons_with_work_budget(&observations, &corpus, 0).unwrap();
        assert_eq!(comparisons.len(), 1);
        assert_eq!(comparisons[0].nfc_cer_paired_case_count, 2);
        assert_eq!(comparisons[0].nfc_cer_cluster_count, 2);
        assert!(comparisons[0].nfc_cer_rate_difference.is_none());
        assert!(
            comparisons[0]
                .nfc_cer_unavailable_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("cluster-draw budget exceeded"))
        );
    }

    #[test]
    fn nearest_rank_percentiles_do_not_understate_small_n_p99() {
        let values = [10u64, 20];
        assert_eq!(nearest_rank_u64(&values, 50), Some(10));
        assert_eq!(nearest_rank_u64(&values, 95), Some(20));
        assert_eq!(nearest_rank_u64(&values, 99), Some(20));
        let one = [7.0f64];
        assert_eq!(nearest_rank_f64(&one, 50), Some(7.0));
        assert_eq!(nearest_rank_f64(&one, 95), Some(7.0));
        assert_eq!(nearest_rank_f64(&one, 99), Some(7.0));
    }

    #[test]
    fn system_percentiles_include_missing_count_and_null_reason() {
        let mut values = vec![10u64, 20];
        let summary = u64_percentiles(&mut values, 3, "nanoseconds", "none available").unwrap();
        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.missing_observation_count, 1);
        assert_eq!(summary.p50, Some(10));
        assert_eq!(summary.p95, Some(20));
        assert_eq!(summary.p99, Some(20));
        assert!(summary.missing_observation_reason.is_some());
        let mut empty_values = Vec::new();
        let empty = u64_percentiles(&mut empty_values, 3, "bytes", "no memory counter").unwrap();
        assert_eq!(empty.sample_count, 0);
        assert_eq!(empty.p99, None);
        assert_eq!(
            empty.unavailable_reason.as_deref(),
            Some("no memory counter")
        );
    }

    #[test]
    fn selected_split_key_must_not_cross_partitions() {
        let batch = BenchmarkCaseManifestV1 {
            schema_version: BENCHMARK_SCHEMA_VERSION,
            batch_id: "batch-1".to_owned(),
            cases: vec![
                case_with_split(
                    "case-a",
                    "writer-1",
                    "session-a",
                    "config-a",
                    BenchmarkSplitV1::Train,
                    "annotation-a",
                ),
                case_with_split(
                    "case-b",
                    "writer-1",
                    "session-b",
                    "config-b",
                    BenchmarkSplitV1::Evaluation,
                    "annotation-b",
                ),
            ],
        };
        let corpus = BenchmarkCorpusManifestV1 {
            schema_version: BENCHMARK_SCHEMA_VERSION,
            corpus_id: "corpus-1".to_owned(),
            split_key: BenchmarkSplitKeyV1::Writer,
            bootstrap_cluster: BenchmarkClusterKeyV1::Writer,
            bootstrap_seed: 7,
            bootstrap_replicates: 100,
            tokenization_policy: BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            cases: vec![
                annotation_for("case-a", "annotation-a", "train"),
                annotation_for("case-b", "annotation-b", "evaluation"),
            ],
        };
        assert!(validate_corpus_manifest(&corpus, &batch).is_err());

        let mut session_split_corpus = corpus;
        session_split_corpus.split_key = BenchmarkSplitKeyV1::Session;
        assert!(validate_corpus_manifest(&session_split_corpus, &batch).is_ok());
    }

    #[test]
    fn session_time_split_requires_earlier_adaptation_and_future_evaluation() {
        let mut batch = BenchmarkCaseManifestV1 {
            schema_version: BENCHMARK_SCHEMA_VERSION,
            batch_id: "batch-time".to_owned(),
            cases: vec![
                case_with_split(
                    "adapt",
                    "writer-1",
                    "session-adapt",
                    "config-a",
                    BenchmarkSplitV1::Adaptation,
                    "annotation-adapt",
                ),
                case_with_split(
                    "calibrate",
                    "writer-1",
                    "session-calibrate",
                    "config-a",
                    BenchmarkSplitV1::Calibration,
                    "annotation-calibrate",
                ),
                case_with_split(
                    "future",
                    "writer-1",
                    "session-future",
                    "config-a",
                    BenchmarkSplitV1::Evaluation,
                    "annotation-future",
                ),
            ],
        };
        let corpus = BenchmarkCorpusManifestV1 {
            schema_version: BENCHMARK_SCHEMA_VERSION,
            corpus_id: "corpus-1".to_owned(),
            split_key: BenchmarkSplitKeyV1::SessionStartTime,
            bootstrap_cluster: BenchmarkClusterKeyV1::Session,
            bootstrap_seed: 9,
            bootstrap_replicates: 100,
            tokenization_policy: BenchmarkTokenizationPolicyV1::UnicodeWhitespaceSyllableV1,
            cases: vec![
                annotation_for("adapt", "annotation-adapt", "tôi"),
                annotation_for("calibrate", "annotation-calibrate", "viết"),
                annotation_for("future", "annotation-future", "ghi chú"),
            ],
        };
        assert!(validate_corpus_manifest(&corpus, &batch).is_ok());
        let mut missing_api_version = batch.clone();
        missing_api_version.cases[0].provenance.capture_api_version = None;
        assert!(validate_corpus_manifest(&corpus, &missing_api_version).is_err());
        batch.cases[2].provenance.session_start_unix_ns = Some(150);
        assert!(validate_corpus_manifest(&corpus, &batch).is_err());
    }

    #[test]
    fn job_cpu_ratio_keeps_whole_tree_scope_and_unavailable_reason() {
        let resources = ProviderProcessResourcesV1 {
            scope: crate::provider_protocol::ProviderResourceScopeV1::JobProcessTree,
            total_user_time_100ns_raw: 1_000_000,
            total_kernel_time_100ns_raw: 500_000,
            total_page_fault_count_raw: 0,
            total_process_count_raw: 2,
            peak_job_memory_bytes_raw: Some(1_000_000),
            peak_process_memory_bytes_raw: Some(900_000),
            memory_unavailable_reason: None,
        };
        let timing = crate::provider_protocol::ProviderExecutionTimingV1 {
            process_create_call_to_handshake_ns: 10,
            process_create_call_to_recognition_ns: 20,
            process_create_call_to_parent_exit_ns: 30,
            process_create_call_to_tree_drain_ns: 50_000_000,
            model_cold_start_ns: None,
            model_cold_start_unavailable_reason: Some("not exposed".to_owned()),
        };
        let (ratio, reason) = job_cpu_core_equivalent_percent(Some(&resources), Some(&timing));
        assert_eq!(ratio, Some(300.0));
        assert!(reason.is_none());
        let (missing, reason) = job_cpu_core_equivalent_percent(None, Some(&timing));
        assert!(missing.is_none());
        assert!(reason.is_some());
    }

    #[test]
    fn benchmark_publish_is_no_clobber_and_partial_remains_recoverable() {
        let directory = temp_dir("no-clobber");
        fs::create_dir_all(&directory).unwrap();
        let manifest_sha = hex_encode(&Sha256::digest(b"case manifest")).unwrap();
        let writer =
            BenchmarkArtifactWriter::create_at(&directory, "batch-1", &manifest_sha, None).unwrap();
        let final_path = writer.final_path.clone();
        let partial_path = writer.partial_path.clone();
        fs::write(&final_path, b"pre-existing-result").unwrap();
        assert!(writer.finish(0, 0, Vec::new(), Vec::new(), None).is_err());
        assert_eq!(fs::read(&final_path).unwrap(), b"pre-existing-result");
        assert!(partial_path.is_file());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn benchmark_publish_writes_header_footer_and_completes_normally() {
        let directory = temp_dir("publish");
        fs::create_dir_all(&directory).unwrap();
        let manifest_sha = hex_encode(&Sha256::digest(b"case manifest")).unwrap();
        let corpus_digest = hex_encode(&Sha256::digest(b"corpus manifest")).unwrap();
        let corpus_sha = Some(corpus_digest.clone());
        let writer =
            BenchmarkArtifactWriter::create_at(&directory, "batch-2", &manifest_sha, corpus_sha)
                .unwrap();
        let partial_path = writer.partial_path.clone();
        let completion = writer.finish(0, 0, Vec::new(), Vec::new(), None).unwrap();
        assert!(completion.artifact_path.is_file());
        assert!(!partial_path.exists());
        let contents = fs::read_to_string(&completion.artifact_path).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains("\"record_type\":\"header\""));
        assert!(contents.contains("\"record_type\":\"footer\""));
        assert!(contents.contains(&manifest_sha));
        assert!(contents.contains(&corpus_digest));
        assert!(!contents.contains("case manifest"));
        assert!(!contents.contains("corpus manifest"));
        fs::remove_dir_all(directory).unwrap();
    }
}
