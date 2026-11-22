//! Explicit local M7 conversion preparation and projection mapping.
//!
//! Launch authority is loaded only from an operator-supplied local config.
//! This module never persists executable paths, arguments, configuration
//! values, raw provider diagnostics, raster bytes, or canonical samples.

use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    canvas::{
        CanonicalRasterOutputGeometryV1, CanonicalRasterPixelLayoutV1,
        CanonicalRasterProjectionSpecV1, build_canonical_raster_projection_plan,
        render_canonical_raster, transform_canonical_raster_geometry,
    },
    journal::{
        GeneratedRasterProvenanceV1, JournalReplayState,
        LOCAL_SENOCR_RASTER_PROVIDER_ID as LOCAL_SENOCR_PROVIDER_ID, ProjectionInkBindingV1,
        ProjectionInputModalityV1, ProjectionProviderProvenanceV1, ProjectionRasterPixelLayoutV1,
        ProjectionRasterSourceBindingV1, ProjectionStrokeRangeV1, ProjectionStrokeViewV1,
        RecognitionCandidateV1, RecognitionProjectionV1, StrokeRef, StrokeViewFrame,
    },
    provider_protocol::{
        OperatorApprovedProviderConfig, ProviderCallTimeouts, ProviderConfigurationV1,
        ProviderErrorKind, ProviderExecution, ProviderInputCapabilityV1, ProviderRasterInputV1,
        ProviderRasterPayloadContractV1, ProviderStrokeRefV1, ProviderWorkerHandle,
        RecognitionRequestBuildInput, RecognitionRequestV1, build_recognition_request,
    },
};

const MAX_LOCAL_PROVIDER_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_LOCAL_PROVIDERS: usize = 8;
const MAX_LOCAL_LANGUAGE_HINTS: usize = 16;
pub(crate) const CONVERT_RASTER_WIDTH_PX: u32 = 384;
pub(crate) const CONVERT_RASTER_HEIGHT_PX: u32 = 384;
pub(crate) const CONVERT_RASTER_SOURCE_PADDING_PX: i32 = 4;
const MAX_PROVIDER_RASTER_BYTES: usize = 1024 * 1024;
const CONVERT_RASTER_COORDINATE_SPACE: &str = "canonical-raster-output-v1";
const CONVERT_RASTER_COORDINATE_UNITS: &str = "pixel";
const CANONICAL_REGION_ID_DOMAIN_V1: &[u8] = b"LassoInk/canonical-region-id/v1\0";
static CONVERT_PREPARATION_ACTIVE: AtomicBool = AtomicBool::new(false);

struct ConvertPreparationSlot;

impl Drop for ConvertPreparationSlot {
    fn drop(&mut self) {
        CONVERT_PREPARATION_ACTIVE.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
pub(crate) struct LocalConvertProviderV1 {
    pub provider_id: String,
    approved: OperatorApprovedProviderConfig,
    protocol_configuration: ProviderConfigurationV1,
    requested_input_modalities: Vec<ProviderInputCapabilityV1>,
    language_hints: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalProviderConfigFileV1 {
    schema_version: u32,
    providers: Vec<LocalProviderEntryV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalProviderEntryV1 {
    provider_id: String,
    executable_path: PathBuf,
    #[serde(default)]
    arguments: Vec<String>,
    protocol_configuration: ProviderConfigurationV1,
    requested_input_modalities: Vec<ProviderInputCapabilityV1>,
    #[serde(default)]
    language_hints: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConvertPreparationError {
    Cancelled,
    InvalidSelection,
    UnsupportedSource,
    OversizedInput,
    RequestRejected,
    RasterRejected,
    AllocationFailed,
}

#[derive(Debug)]
pub(crate) struct PreparedConversionV1 {
    pub request: RecognitionRequestV1,
    pub ink_binding: ProjectionInkBindingV1,
    pub generated_raster: Option<GeneratedRasterProvenanceV1>,
}

pub(crate) struct ConvertPreparationTask {
    receiver: Receiver<Result<PreparedConversionV1, ConvertPreparationError>>,
    cancelled: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    completed_result: Option<Result<PreparedConversionV1, ConvertPreparationError>>,
}

impl LocalConvertProviderV1 {
    pub(crate) fn load(config_path: &Path, selected_provider_id: Option<&str>) -> io::Result<Self> {
        let config_text = config_path.to_string_lossy();
        if !config_path.is_absolute()
            || config_text.starts_with("\\\\")
            || config_text.starts_with("//")
            || config_text.len() > 32 * 1024
        {
            return Err(invalid_configuration());
        }
        let metadata = fs::symlink_metadata(config_path).map_err(|_| invalid_configuration())?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_LOCAL_PROVIDER_CONFIG_BYTES {
            return Err(invalid_configuration());
        }
        let file = File::open(config_path).map_err(|_| invalid_configuration())?;
        let mut bytes = Vec::new();
        file.take(MAX_LOCAL_PROVIDER_CONFIG_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| invalid_configuration())?;
        if bytes.len() as u64 > MAX_LOCAL_PROVIDER_CONFIG_BYTES {
            return Err(invalid_configuration());
        }
        let config: LocalProviderConfigFileV1 =
            serde_json::from_slice(&bytes).map_err(|_| invalid_configuration())?;
        if config.schema_version != 1
            || config.providers.is_empty()
            || config.providers.len() > MAX_LOCAL_PROVIDERS
        {
            return Err(invalid_configuration());
        }
        for (index, provider) in config.providers.iter().enumerate() {
            if provider.provider_id.is_empty()
                || config.providers[..index]
                    .iter()
                    .any(|previous| previous.provider_id == provider.provider_id)
            {
                return Err(invalid_configuration());
            }
        }
        let selected = match selected_provider_id {
            Some(provider_id) => config
                .providers
                .iter()
                .find(|provider| provider.provider_id == provider_id),
            None if config.providers.len() == 1 => config.providers.first(),
            None => return Err(invalid_configuration()),
        }
        .ok_or_else(invalid_configuration)?;
        if selected.provider_id != LOCAL_SENOCR_PROVIDER_ID {
            return Err(invalid_configuration());
        }
        let executable_text = selected.executable_path.to_string_lossy();
        if !selected.executable_path.is_absolute()
            || executable_text.starts_with("\\\\")
            || executable_text.starts_with("//")
        {
            return Err(invalid_configuration());
        }
        let executable_metadata =
            fs::symlink_metadata(&selected.executable_path).map_err(|_| invalid_configuration())?;
        if !executable_metadata.file_type().is_file()
            || executable_metadata.file_type().is_symlink()
        {
            return Err(invalid_configuration());
        }
        validate_modalities(&selected.requested_input_modalities)?;
        if selected.language_hints.len() > MAX_LOCAL_LANGUAGE_HINTS {
            return Err(invalid_configuration());
        }
        let approved = OperatorApprovedProviderConfig::from_explicit_selection(
            selected.provider_id.clone(),
            selected.executable_path.clone(),
            selected.arguments.clone(),
            selected.protocol_configuration.clone(),
        )
        .map_err(|_| invalid_configuration())?;
        Ok(Self {
            provider_id: selected.provider_id.clone(),
            approved,
            protocol_configuration: selected.protocol_configuration.clone(),
            requested_input_modalities: selected.requested_input_modalities.clone(),
            language_hints: selected.language_hints.clone(),
        })
    }

    pub(crate) fn start_worker(&self) -> Result<ProviderWorkerHandle, ProviderErrorKind> {
        ProviderWorkerHandle::start(self.approved.clone(), senocr_call_timeouts())
    }
}

fn senocr_call_timeouts() -> ProviderCallTimeouts {
    ProviderCallTimeouts {
        recognition: Duration::from_secs(120),
        ..ProviderCallTimeouts::default()
    }
}

fn canonical_region_id(
    journal_id: &str,
    ordered_strokes: &[StrokeRef],
) -> Result<String, ConvertPreparationError> {
    if journal_id.is_empty() || ordered_strokes.is_empty() || ordered_strokes.len() > 512 {
        return Err(ConvertPreparationError::InvalidSelection);
    }
    let mut hash = Sha256::new();
    hash.update(CANONICAL_REGION_ID_DOMAIN_V1);
    update_region_hash_string(&mut hash, journal_id)?;
    hash.update(
        u64::try_from(ordered_strokes.len())
            .map_err(|_| ConvertPreparationError::OversizedInput)?
            .to_le_bytes(),
    );
    for stroke in ordered_strokes {
        if stroke.journal_id != journal_id {
            return Err(ConvertPreparationError::InvalidSelection);
        }
        update_region_hash_string(&mut hash, &stroke.journal_id)?;
        update_region_hash_string(&mut hash, &stroke.session_id)?;
        update_region_hash_string(&mut hash, &stroke.source_api)?;
        match stroke.device_id.as_deref() {
            Some(device_id) => {
                hash.update([1]);
                update_region_hash_string(&mut hash, device_id)?;
            }
            None => hash.update([0]),
        }
        match stroke.pointer_id {
            Some(pointer_id) => {
                hash.update([1]);
                hash.update(pointer_id.to_le_bytes());
            }
            None => hash.update([0]),
        }
        update_region_hash_string(&mut hash, &stroke.stroke_id)?;
    }
    let digest: [u8; 32] = hash.finalize().into();
    Ok(format!("region-v1-{}", hex_lower(&digest)?))
}

fn update_region_hash_string(
    hash: &mut Sha256,
    value: &str,
) -> Result<(), ConvertPreparationError> {
    hash.update(
        u64::try_from(value.len())
            .map_err(|_| ConvertPreparationError::OversizedInput)?
            .to_le_bytes(),
    );
    hash.update(value.as_bytes());
    Ok(())
}

impl ConvertPreparationTask {
    pub(crate) fn start(
        state: JournalReplayState,
        selected_strokes: Vec<StrokeRef>,
        request_id: String,
        line_id: String,
        provider: LocalConvertProviderV1,
    ) -> io::Result<Self> {
        Self::spawn_with(move |cancelled| {
            let result = prepare_conversion(
                &state,
                &selected_strokes,
                &request_id,
                &line_id,
                &provider,
                cancelled,
            );
            // Release the potentially large replay snapshot and its selection
            // before the global slot can admit another preparation.
            drop(state);
            drop(selected_strokes);
            drop(request_id);
            drop(line_id);
            drop(provider);
            result
        })
    }

    fn spawn_with<F>(prepare: F) -> io::Result<Self>
    where
        F: FnOnce(&AtomicBool) -> Result<PreparedConversionV1, ConvertPreparationError>
            + Send
            + 'static,
    {
        CONVERT_PREPARATION_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "bounded Convert preparation slot is busy",
                )
            })?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let slot = ConvertPreparationSlot;
        let join = match thread::Builder::new()
            .name("lassoink-convert-preparation".to_owned())
            .spawn(move || {
                let prepared = prepare(&worker_cancelled);
                let published = sender.send(prepared);
                // If the receiver disappeared, drop its unsent large result
                // before releasing the bounded preparation slot as well.
                drop(published);
                drop(slot);
            }) {
            Ok(join) => join,
            Err(error) => {
                CONVERT_PREPARATION_ACTIVE.store(false, Ordering::Release);
                return Err(error);
            }
        };
        Ok(Self {
            receiver,
            cancelled,
            join: Some(join),
            completed_result: None,
        })
    }

    pub(crate) fn try_receive(
        &mut self,
    ) -> Option<Result<PreparedConversionV1, ConvertPreparationError>> {
        if self.completed_result.is_none() {
            match self.receiver.try_recv() {
                Ok(result) => self.completed_result = Some(result),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => {
                    self.completed_result = Some(Err(ConvertPreparationError::AllocationFailed));
                }
            }
        }
        if self.join.as_ref().is_some_and(|join| !join.is_finished()) {
            return None;
        }
        if let Some(join) = self.join.take()
            && join.join().is_err()
        {
            self.completed_result = Some(Err(ConvertPreparationError::AllocationFailed));
        }
        self.completed_result.take()
    }

    pub(crate) fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn cancel_and_join(&mut self) {
        self.cancel();
        if let Some(join) = self.join.take()
            && join.join().is_err()
        {
            self.completed_result = Some(Err(ConvertPreparationError::AllocationFailed));
        }
        while let Ok(result) = self.receiver.try_recv() {
            drop(result);
        }
        self.completed_result.take();
    }
}

pub(crate) fn projection_from_execution(
    request: &RecognitionRequestV1,
    binding: ProjectionInkBindingV1,
    generated_raster: Option<GeneratedRasterProvenanceV1>,
    execution: &ProviderExecution,
) -> Result<RecognitionProjectionV1, ConvertPreparationError> {
    if execution.result.consumed_input_modalities != request.requested_input_modalities
        || execution.result.consumed_input_modalities.is_empty()
        || execution.result.consumed_input_modalities.len() > 2
    {
        return Err(ConvertPreparationError::RequestRejected);
    }
    if execution.provider.provider_id == LOCAL_SENOCR_PROVIDER_ID
        && (request.requested_input_modalities.len() != 1
            || request.requested_input_modalities.first()
                != Some(&ProviderInputCapabilityV1::Raster)
            || request.raster.is_none()
            || generated_raster.is_none())
    {
        return Err(ConvertPreparationError::RasterRejected);
    }
    let mut input_modalities = Vec::new();
    input_modalities
        .try_reserve_exact(execution.result.consumed_input_modalities.len())
        .map_err(|_| ConvertPreparationError::AllocationFailed)?;
    input_modalities.extend(
        execution
            .result
            .consumed_input_modalities
            .iter()
            .map(|modality| match modality {
                ProviderInputCapabilityV1::OnlineStrokes => {
                    ProjectionInputModalityV1::OnlineStrokes
                }
                ProviderInputCapabilityV1::Raster => ProjectionInputModalityV1::Raster,
            }),
    );
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(execution.result.candidates.len())
        .map_err(|_| ConvertPreparationError::AllocationFailed)?;
    for (index, candidate) in execution.result.candidates.iter().enumerate() {
        let rank = u16::try_from(index).map_err(|_| ConvertPreparationError::OversizedInput)?;
        let mut stroke_ranges = Vec::new();
        stroke_ranges
            .try_reserve_exact(candidate.stroke_ranges.len())
            .map_err(|_| ConvertPreparationError::AllocationFailed)?;
        stroke_ranges.extend(
            candidate
                .stroke_ranges
                .iter()
                .map(|range| ProjectionStrokeRangeV1 {
                    stroke: core_stroke_ref(&range.stroke),
                    first_journal_sequence: range.first_journal_sequence,
                    last_journal_sequence: range.last_journal_sequence,
                }),
        );
        candidates.push(RecognitionCandidateV1 {
            rank,
            recognized_text: candidate.recognized_text.clone(),
            native_score_raw: candidate.native_score_raw.as_ref().map(ToString::to_string),
            stroke_ranges,
        });
    }
    Ok(RecognitionProjectionV1 {
        projection_id: request.request_id.clone(),
        ink: binding,
        provider: ProjectionProviderProvenanceV1 {
            provider_id: execution.provider.provider_id.clone(),
            provider_version: execution.provider.provider_version.clone(),
            model_version: execution.provider.model_version.clone(),
            resource_version: execution.provider.resource_version.clone(),
            configuration_id: execution.result.provider_configuration_id.clone(),
            configuration_fingerprint: execution.result.provider_configuration_fingerprint.clone(),
        },
        generated_raster,
        input_modalities: Some(input_modalities),
        candidates,
    })
}

pub(crate) fn same_generated_raster_output(
    frozen: Option<&GeneratedRasterProvenanceV1>,
    current: Option<&GeneratedRasterProvenanceV1>,
) -> bool {
    match (frozen, current) {
        (None, None) => true,
        (Some(frozen), Some(current)) => {
            frozen.schema_version == current.schema_version
                && frozen.geometry_schema_version == current.geometry_schema_version
                && frozen.raster_artifact_schema_version == current.raster_artifact_schema_version
                && frozen.source.journal_id == current.source.journal_id
                && frozen.source.logical_revision == current.source.logical_revision
                && current.source.last_sequence >= frozen.source.last_sequence
                && frozen.source.region_id == current.source.region_id
                && frozen.source.line_id == current.source.line_id
                && frozen.source.input_view_id == current.source.input_view_id
                && frozen.source.ink_binding_sha256 == current.source.ink_binding_sha256
                && frozen.source_content_sha256 == current.source_content_sha256
                && frozen.projection_spec == current.projection_spec
                && frozen.projection_spec_sha256 == current.projection_spec_sha256
                && frozen.geometry_sha256 == current.geometry_sha256
                && frozen.renderer_version == current.renderer_version
                && frozen.output_width_px == current.output_width_px
                && frozen.output_height_px == current.output_height_px
                && frozen.row_stride_bytes == current.row_stride_bytes
                && frozen.pixel_layout == current.pixel_layout
                && frozen.pixel_bytes_sha256 == current.pixel_bytes_sha256
                && frozen.png_bytes_len == current.png_bytes_len
                && frozen.png_bytes_sha256 == current.png_bytes_sha256
                && (frozen.source.last_sequence != current.source.last_sequence
                    || frozen.raster_artifact_sha256 == current.raster_artifact_sha256)
        }
        _ => false,
    }
}

pub(crate) fn prepare_conversion(
    state: &JournalReplayState,
    selected_strokes: &[StrokeRef],
    request_id: &str,
    line_id: &str,
    provider: &LocalConvertProviderV1,
    cancelled: &AtomicBool,
) -> Result<PreparedConversionV1, ConvertPreparationError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(ConvertPreparationError::Cancelled);
    }
    if selected_strokes.is_empty() {
        return Err(ConvertPreparationError::InvalidSelection);
    }
    let initial_plan = build_canonical_raster_projection_plan(state, selected_strokes)
        .map_err(|_| ConvertPreparationError::UnsupportedSource)?;
    let ordered_strokes = initial_plan
        .journal_first_occurrence_stroke_order()
        .map_err(|_| ConvertPreparationError::UnsupportedSource)?;
    let region_id = canonical_region_id(&state.journal_id, &ordered_strokes)?;
    let plan = build_canonical_raster_projection_plan(state, &ordered_strokes)
        .map_err(|_| ConvertPreparationError::UnsupportedSource)?;
    let mut raster_output = None;
    let raster = if provider
        .requested_input_modalities
        .contains(&ProviderInputCapabilityV1::Raster)
    {
        if cancelled.load(Ordering::Acquire) {
            return Err(ConvertPreparationError::Cancelled);
        }
        let spec = CanonicalRasterProjectionSpecV1::new(
            CONVERT_RASTER_WIDTH_PX,
            CONVERT_RASTER_HEIGHT_PX,
            plan.source_crop_with_padding(CONVERT_RASTER_SOURCE_PADDING_PX)
                .map_err(|_| ConvertPreparationError::UnsupportedSource)?,
        );
        let geometry = transform_canonical_raster_geometry(&plan, &spec)
            .map_err(|_| ConvertPreparationError::RasterRejected)?;
        let (journal_id, logical_revision, last_sequence) = geometry.source_revision_parts();
        if journal_id != state.journal_id
            || logical_revision != state.logical_revision
            || last_sequence != state.last_sequence
            || geometry.caller_selection_order() != ordered_strokes.as_slice()
        {
            return Err(ConvertPreparationError::UnsupportedSource);
        }
        let image = render_canonical_raster(&geometry)
            .map_err(|_| ConvertPreparationError::RasterRejected)?;
        let png = image.png_bytes();
        if png.is_empty() || png.len() > MAX_PROVIDER_RASTER_BYTES {
            return Err(ConvertPreparationError::OversizedInput);
        }
        let raw_payload_hex = bounded_hex(png)?;
        let raster_input = ProviderRasterInputV1 {
            width: CONVERT_RASTER_WIDTH_PX,
            height: CONVERT_RASTER_HEIGHT_PX,
            payload_contract: ProviderRasterPayloadContractV1::OpaqueBytes,
            coordinate_space: CONVERT_RASTER_COORDINATE_SPACE.to_owned(),
            units: CONVERT_RASTER_COORDINATE_UNITS.to_owned(),
            raw_payload_hex,
        };
        raster_output = Some((geometry, image));
        Some(raster_input)
    } else {
        None
    };
    if cancelled.load(Ordering::Acquire) {
        return Err(ConvertPreparationError::Cancelled);
    }

    let request = build_recognition_request(RecognitionRequestBuildInput {
        state,
        request_id: request_id.to_owned(),
        region_id,
        line_id: line_id.to_owned(),
        coordinate_space: "windows-screen-coordinates".to_owned(),
        coordinate_units: "screen-pixel".to_owned(),
        language_hints: provider.language_hints.clone(),
        requested_input_modalities: provider.requested_input_modalities.clone(),
        provider_configuration: provider.protocol_configuration.clone(),
        selected_strokes: &ordered_strokes,
        raster,
    })
    .map_err(|_| ConvertPreparationError::RequestRejected)?;
    let request_source = request.source_revision.clone();
    // Reuse the benchmark's exact canonical-ink fingerprint. The M4 input-view
    // ID remains separate and binds this request's modality and Raster bytes.
    let ink_binding_sha256 = crate::benchmark::canonical_ink_comparison_binding_sha256(&request)
        .map_err(|_| ConvertPreparationError::RequestRejected)?;
    let mut source_sample_sequences = Vec::new();
    source_sample_sequences
        .try_reserve_exact(request.samples.len())
        .map_err(|_| ConvertPreparationError::AllocationFailed)?;
    source_sample_sequences.extend(request.samples.iter().map(|sample| sample.journal_sequence));
    let mut stroke_views = Vec::new();
    stroke_views
        .try_reserve_exact(request.stroke_views.len())
        .map_err(|_| ConvertPreparationError::AllocationFailed)?;
    for view in &request.stroke_views {
        let frame = view
            .view_frame
            .ok_or(ConvertPreparationError::UnsupportedSource)?;
        stroke_views.push(ProjectionStrokeViewV1 {
            stroke: core_stroke_ref(&view.stroke),
            frame: StrokeViewFrame {
                screen_origin_x_px: frame.screen_origin_x_px,
                screen_origin_y_px: frame.screen_origin_y_px,
                dpi_scale_factor_bits: frame.dpi_scale_factor_bits,
                canvas_zoom_bits: frame.canvas_zoom_bits,
                canvas_pan_x_bits: frame.canvas_pan_x_bits,
                canvas_pan_y_bits: frame.canvas_pan_y_bits,
                toolbar_height_px: frame.toolbar_height_px,
            },
        });
    }
    if request_source.journal_id != state.journal_id
        || request_source.logical_revision != state.logical_revision
        || request_source.last_sequence != state.last_sequence
        || request.input_view_id.is_empty()
    {
        return Err(ConvertPreparationError::UnsupportedSource);
    }
    let ink_binding = ProjectionInkBindingV1 {
        journal_id: request_source.journal_id,
        logical_revision: request_source.logical_revision,
        last_sequence: request_source.last_sequence,
        region_id: request.region_id.clone(),
        line_id: Some(request.line_id.clone()),
        input_view_id: request.input_view_id.clone(),
        ink_binding_sha256,
        selected_strokes: ordered_strokes,
        source_sample_sequences,
        stroke_views,
    };
    let generated_raster = raster_output
        .map(|(geometry, image)| generated_raster_provenance(&ink_binding, &geometry, &image))
        .transpose()?;
    Ok(PreparedConversionV1 {
        request,
        ink_binding,
        generated_raster,
    })
}

fn generated_raster_provenance(
    binding: &ProjectionInkBindingV1,
    geometry: &CanonicalRasterOutputGeometryV1,
    image: &crate::canvas::CanonicalRasterImageV1,
) -> Result<GeneratedRasterProvenanceV1, ConvertPreparationError> {
    let (journal_id, logical_revision, last_sequence) = image.source_revision_parts();
    if journal_id != binding.journal_id
        || logical_revision != binding.logical_revision
        || last_sequence != binding.last_sequence
        || geometry.source_revision_parts() != (journal_id, logical_revision, last_sequence)
    {
        return Err(ConvertPreparationError::UnsupportedSource);
    }
    let projection_spec = geometry.projection_spec_metadata();
    let projection_spec_sha256 = image.projection_spec_sha256();
    if projection_spec.canonical_sha256() != projection_spec_sha256
        || geometry.projection_spec_sha256() != projection_spec_sha256
    {
        return Err(ConvertPreparationError::RasterRejected);
    }
    let (output_width_px, output_height_px, row_stride_bytes) =
        image.output_dimensions_and_stride();
    let pixel_layout = match image.pixel_layout() {
        CanonicalRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown => {
            ProjectionRasterPixelLayoutV1::Rgba8PremultipliedSrgbTopDown
        }
    };
    let png_bytes_len = u32::try_from(image.png_bytes().len())
        .map_err(|_| ConvertPreparationError::OversizedInput)?;
    Ok(GeneratedRasterProvenanceV1 {
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
        source_content_sha256: hex_lower(&image.source_content_sha256())?,
        projection_spec_sha256: hex_lower(&projection_spec_sha256)?,
        projection_spec,
        geometry_schema_version: geometry.geometry_schema_version(),
        geometry_sha256: hex_lower(&image.geometry_sha256())?,
        raster_artifact_schema_version: image.schema_version(),
        renderer_version: image.renderer_version().to_owned(),
        output_width_px,
        output_height_px,
        row_stride_bytes,
        pixel_layout,
        pixel_bytes_sha256: hex_lower(&image.pixel_bytes_sha256())?,
        png_bytes_len,
        png_bytes_sha256: hex_lower(&image.png_bytes_sha256())?,
        raster_artifact_sha256: hex_lower(&image.raster_artifact_sha256())?,
    })
}

fn validate_modalities(modalities: &[ProviderInputCapabilityV1]) -> io::Result<()> {
    if modalities.len() != 1 || modalities.first() != Some(&ProviderInputCapabilityV1::Raster) {
        return Err(invalid_configuration());
    }
    Ok(())
}

fn core_stroke_ref(stroke: &ProviderStrokeRefV1) -> StrokeRef {
    StrokeRef {
        journal_id: stroke.journal_id.clone(),
        session_id: stroke.session_id.clone(),
        source_api: stroke.source_api.clone(),
        device_id: stroke.device_id.clone(),
        pointer_id: stroke.pointer_id,
        stroke_id: stroke.stroke_id.clone(),
    }
}

fn bounded_hex(bytes: &[u8]) -> Result<String, ConvertPreparationError> {
    let capacity = bytes
        .len()
        .checked_mul(2)
        .ok_or(ConvertPreparationError::OversizedInput)?;
    if bytes.len() > MAX_PROVIDER_RASTER_BYTES {
        return Err(ConvertPreparationError::OversizedInput);
    }
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| ConvertPreparationError::AllocationFailed)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(output)
}

fn hex_lower(bytes: &[u8]) -> Result<String, ConvertPreparationError> {
    bounded_hex(bytes)
}

fn invalid_configuration() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "operator provider configuration is invalid or exceeds its bounds",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{
        JournalHeader, JournalMetadata, JournalWriter, MetadataScope, PhysicalSample, RawPosition,
        StrokeViewFrame,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "lassoink-convert-{label}-{}-{nonce}.json",
            std::process::id()
        ))
    }

    fn write_provider_config(provider_ids: &[&str], modalities: &[&str]) -> PathBuf {
        let executable = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let providers = provider_ids
            .iter()
            .map(|provider_id| {
                serde_json::json!({
                    "provider_id": provider_id,
                    "executable_path": executable.clone(),
                    "arguments": [],
                    "protocol_configuration": {
                        "configuration_id": "operator-config",
                        "values": { "model_revision": "owner-selected-local" }
                    },
                    "requested_input_modalities": modalities,
                    "language_hints": ["vi-VN"]
                })
            })
            .collect::<Vec<_>>();
        let json = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "providers": providers
        }))
        .unwrap();
        let path = temp_path("provider-config");
        std::fs::write(&path, json).unwrap();
        path
    }

    // Data-only unit fixture. It never launches a provider or adds a production success path.
    fn synthetic_senocr_execution(request: &RecognitionRequestV1) -> ProviderExecution {
        let provider = crate::provider_protocol::ProviderIdentityV1 {
            provider_id: LOCAL_SENOCR_PROVIDER_ID.to_owned(),
            provider_version: "synthetic-contract-fixture".to_owned(),
            model_version: None,
            resource_version: None,
        };
        ProviderExecution {
            provider: provider.clone(),
            capabilities: crate::provider_protocol::ProviderCapabilitiesV1 {
                inputs: vec![ProviderInputCapabilityV1::Raster],
                outputs: Vec::new(),
                languages: Vec::new(),
            },
            result: crate::provider_protocol::RecognitionResultV1 {
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
                provider_provenance: "synthetic projection-mapping fixture".to_owned(),
                consumed_input_modalities: request.requested_input_modalities.clone(),
                candidates: Vec::new(),
            },
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

    #[test]
    fn repeated_cancel_keeps_preparation_slot_until_owned_snapshot_cleanup() {
        let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let owned_snapshot = vec![0_u8; 1024 * 1024];
        let mut canceled_task = ConvertPreparationTask::spawn_with(move |_| {
            let owned_snapshot = owned_snapshot;
            entered_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
            drop(owned_snapshot);
            Err(ConvertPreparationError::Cancelled)
        })
        .unwrap();
        entered_receiver.recv().unwrap();
        canceled_task.cancel();
        canceled_task.cancel();

        let blocked_successor =
            ConvertPreparationTask::spawn_with(|_| Err(ConvertPreparationError::Cancelled));
        assert!(matches!(
            blocked_successor,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));

        release_sender.send(()).unwrap();
        let completed = (0..2_000).find_map(|_| {
            let result = canceled_task.try_receive();
            if result.is_none() {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            result
        });
        assert!(matches!(
            completed,
            Some(Err(ConvertPreparationError::Cancelled))
        ));

        let mut successor =
            ConvertPreparationTask::spawn_with(|_| Err(ConvertPreparationError::Cancelled))
                .unwrap();
        let successor_result = (0..2_000).find_map(|_| {
            let result = successor.try_receive();
            if result.is_none() {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            result
        });
        assert!(matches!(
            successor_result,
            Some(Err(ConvertPreparationError::Cancelled))
        ));
    }

    fn assert_shared_canonical_ink_fingerprint_contract(request: &RecognitionRequestV1) {
        let fingerprint =
            crate::benchmark::canonical_ink_comparison_binding_sha256(request).unwrap();

        let mut changed_request_id = request.clone();
        changed_request_id.request_id.push_str("-different");
        assert_eq!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_request_id).unwrap(),
            fingerprint
        );

        let mut changed_provider_configuration = request.clone();
        changed_provider_configuration
            .provider_configuration
            .values
            .insert("synthetic-setting".to_owned(), "changed-value".to_owned());
        changed_provider_configuration.provider_configuration_fingerprint =
            "provider-config-v1-fnv64-0000000000000002".to_owned();
        assert_eq!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(
                &changed_provider_configuration
            )
            .unwrap(),
            fingerprint
        );

        let mut changed_modality = request.clone();
        changed_modality.requested_input_modalities =
            vec![ProviderInputCapabilityV1::OnlineStrokes];
        assert_eq!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_modality).unwrap(),
            fingerprint
        );

        let mut changed_raster = request.clone();
        changed_raster
            .raster
            .as_mut()
            .expect("the prepared test request has Raster input")
            .raw_payload_hex
            .push('0');
        assert_eq!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_raster).unwrap(),
            fingerprint
        );

        let mut changed_sample = request.clone();
        changed_sample.samples[0].source_sequence_raw += 1;
        assert_ne!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_sample).unwrap(),
            fingerprint
        );

        let mut changed_sample_order = request.clone();
        changed_sample_order.samples.reverse();
        assert_ne!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_sample_order)
                .unwrap(),
            fingerprint
        );

        let mut changed_frame = request.clone();
        changed_frame.stroke_views[0]
            .view_frame
            .as_mut()
            .expect("selected Direct stroke has a captured frame")
            .screen_origin_x_px += 1;
        assert_ne!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_frame).unwrap(),
            fingerprint
        );

        let mut changed_region = request.clone();
        changed_region.region_id.push_str("-different");
        assert_ne!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_region).unwrap(),
            fingerprint
        );

        let mut changed_line = request.clone();
        changed_line.line_id.push_str("-different");
        assert_ne!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_line).unwrap(),
            fingerprint
        );

        let mut changed_language = request.clone();
        changed_language.language_hints.push("en-US".to_owned());
        assert_ne!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_language).unwrap(),
            fingerprint
        );

        let mut changed_logical_revision = request.clone();
        changed_logical_revision.source_revision.logical_revision += 1;
        assert_ne!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_logical_revision)
                .unwrap(),
            fingerprint
        );

        let mut changed_journal = request.clone();
        changed_journal
            .source_revision
            .journal_id
            .push_str("-different");
        assert_ne!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_journal).unwrap(),
            fingerprint
        );

        // The exact submitted last_sequence is stored separately; this shared
        // content fingerprint intentionally remains stable across unrelated tails.
        let mut changed_prefix_boundary = request.clone();
        changed_prefix_boundary.source_revision.last_sequence += 1;
        assert_eq!(
            crate::benchmark::canonical_ink_comparison_binding_sha256(&changed_prefix_boundary)
                .unwrap(),
            fingerprint
        );
    }

    fn direct_target(journal_id: &str, stroke_id: &str) -> StrokeRef {
        StrokeRef {
            journal_id: journal_id.to_owned(),
            session_id: "session-1".to_owned(),
            source_api: crate::canvas::PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
            device_id: Some("device-1".to_owned()),
            pointer_id: Some(7),
            stroke_id: stroke_id.to_owned(),
        }
    }

    fn direct_sample(target: &StrokeRef, source_sequence: u64, x: i64, y: i64) -> PhysicalSample {
        PhysicalSample {
            session_id: target.session_id.clone(),
            source_api: target.source_api.clone(),
            source_device_id: target.device_id.clone(),
            pointer_id: target.pointer_id,
            stroke_id: Some(target.stroke_id.clone()),
            source_sequence,
            config_id: Some("config-1".to_owned()),
            app_arrival_elapsed_ns: u128::from(source_sequence),
            position: Some(RawPosition {
                coordinate_space: "windows-screen-coordinates".to_owned(),
                units: "screen-pixel".to_owned(),
                x_raw: x,
                y_raw: y,
            }),
            pressure: None,
            native_timestamp: None,
            contact_range_state: Some("contact".to_owned()),
            button_state_raw: None,
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload: vec![u8::try_from(source_sequence).unwrap_or_default(), 0xA5],
        }
    }

    #[test]
    fn convert_config_has_no_provider_default_and_selects_only_explicit_local_senocr() {
        let path = write_provider_config(
            &[LOCAL_SENOCR_PROVIDER_ID, "another-operator-provider"],
            &["raster"],
        );
        assert!(LocalConvertProviderV1::load(&path, None).is_err());
        let selected = LocalConvertProviderV1::load(&path, Some(LOCAL_SENOCR_PROVIDER_ID)).unwrap();
        assert_eq!(selected.provider_id, LOCAL_SENOCR_PROVIDER_ID);
        assert_eq!(
            selected.requested_input_modalities.as_slice(),
            &[ProviderInputCapabilityV1::Raster]
        );
        assert!(LocalConvertProviderV1::load(&path, Some("another-operator-provider")).is_err());
        let online_only_path =
            write_provider_config(&[LOCAL_SENOCR_PROVIDER_ID], &["online_strokes"]);
        assert!(LocalConvertProviderV1::load(&online_only_path, None).is_err());
        let mixed_modalities_path =
            write_provider_config(&[LOCAL_SENOCR_PROVIDER_ID], &["raster", "online_strokes"]);
        assert!(LocalConvertProviderV1::load(&mixed_modalities_path, None).is_err());
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(online_only_path);
        let _ = std::fs::remove_file(mixed_modalities_path);
    }

    #[test]
    fn local_senocr_recognition_timeout_uses_the_existing_bounded_ceiling() {
        let adapter_timeouts = senocr_call_timeouts();
        let m4_defaults = ProviderCallTimeouts::default();
        assert_eq!(adapter_timeouts.handshake, m4_defaults.handshake);
        assert_eq!(adapter_timeouts.recognition, Duration::from_secs(120));
        assert_eq!(adapter_timeouts.shutdown, m4_defaults.shutdown);
        assert_eq!(m4_defaults.recognition, Duration::from_secs(30));
    }

    #[test]
    fn convert_preparation_uses_first_journal_occurrence_and_ignores_unrelated_rows() {
        let journal_id = "convert-order-project";
        let path = std::env::temp_dir().join(format!(
            "lassoink-convert-order-{}-{}.inkj",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let mut writer = JournalWriter::create(
            path.clone(),
            JournalHeader {
                journal_id: journal_id.to_owned(),
                session_id: "session-1".to_owned(),
                config_id: Some("config-1".to_owned()),
                device_model_declared: None,
                tilt_supported_declared: Some(false),
            },
        )
        .unwrap();
        // Lexicographic and caller order are deliberately opposite to physical
        // first occurrence: `z-first` must precede `a-second` in the request.
        let first_target = direct_target(journal_id, "z-first");
        let second_target = direct_target(journal_id, "a-second");
        writer
            .start_stroke(first_target.clone(), StrokeViewFrame::default(), 1)
            .unwrap();
        writer
            .append_sample(direct_sample(&first_target, 1, 100, 100))
            .unwrap();
        writer.commit_stroke(first_target.clone(), 2).unwrap();
        writer
            .start_stroke(second_target.clone(), StrokeViewFrame::default(), 3)
            .unwrap();
        writer
            .append_sample(direct_sample(&second_target, 1, 200, 120))
            .unwrap();
        writer.commit_stroke(second_target.clone(), 4).unwrap();
        let before = writer.replay_state().clone();
        let config_path = write_provider_config(&[LOCAL_SENOCR_PROVIDER_ID], &["raster"]);
        let provider = LocalConvertProviderV1::load(&config_path, None).unwrap();
        let cancellation = AtomicBool::new(false);
        let prepared = prepare_conversion(
            &before,
            &[second_target.clone(), first_target.clone()],
            "convert-order-request",
            "line-1",
            &provider,
            &cancellation,
        )
        .unwrap();
        assert_shared_canonical_ink_fingerprint_contract(&prepared.request);
        assert_eq!(
            prepared.ink_binding.ink_binding_sha256,
            crate::benchmark::canonical_ink_comparison_binding_sha256(&prepared.request).unwrap()
        );
        assert_eq!(
            prepared.ink_binding.selected_strokes.as_slice(),
            &[first_target.clone(), second_target.clone()]
        );
        let stable_region_id =
            canonical_region_id(journal_id, &[first_target.clone(), second_target.clone()])
                .unwrap();
        assert_eq!(prepared.request.region_id, stable_region_id);
        let retry = prepare_conversion(
            &before,
            &[first_target.clone(), second_target.clone()],
            "convert-order-retry",
            "line-1",
            &provider,
            &cancellation,
        )
        .unwrap();
        assert_eq!(retry.request.region_id, prepared.request.region_id);
        assert_ne!(retry.request.request_id, prepared.request.request_id);

        // Preparation-only variation; this fixture never starts a worker.
        let mut changed_provider_configuration = provider.clone();
        changed_provider_configuration
            .protocol_configuration
            .values
            .insert(
                "model_revision".to_owned(),
                "operator-selected-r2".to_owned(),
            );
        let changed_configuration_retry = prepare_conversion(
            &before,
            &[first_target.clone(), second_target.clone()],
            "convert-order-config-retry",
            "line-1",
            &changed_provider_configuration,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            changed_configuration_retry.request.region_id,
            prepared.request.region_id
        );
        assert_ne!(
            changed_configuration_retry
                .request
                .provider_configuration_fingerprint,
            prepared.request.provider_configuration_fingerprint
        );
        assert_ne!(
            canonical_region_id(journal_id, std::slice::from_ref(&first_target)).unwrap(),
            prepared.request.region_id
        );
        let mut other_project_first = first_target.clone();
        let mut other_project_second = second_target.clone();
        other_project_first.journal_id = "another-project".to_owned();
        other_project_second.journal_id = "another-project".to_owned();
        assert_ne!(
            canonical_region_id(
                "another-project",
                &[other_project_first, other_project_second]
            )
            .unwrap(),
            prepared.request.region_id
        );
        assert_eq!(
            prepared
                .request
                .samples
                .iter()
                .map(|sample| sample.stroke.stroke_id.as_str())
                .collect::<Vec<_>>()
                .as_slice(),
            &["z-first", "a-second"]
        );
        assert!(prepared.request.raster.is_some());
        let generated_raster = prepared
            .generated_raster
            .as_ref()
            .expect("Raster requests retain their generated origin metadata");
        assert_eq!(
            generated_raster.source.journal_id,
            prepared.ink_binding.journal_id
        );
        assert_eq!(
            generated_raster.source.last_sequence,
            prepared.ink_binding.last_sequence
        );
        assert_eq!(
            generated_raster.source.input_view_id,
            prepared.ink_binding.input_view_id
        );
        assert_eq!(generated_raster.output_width_px, CONVERT_RASTER_WIDTH_PX);
        assert_eq!(generated_raster.output_height_px, CONVERT_RASTER_HEIGHT_PX);
        let serialized_raster = serde_json::to_string(generated_raster).unwrap();
        assert!(!serialized_raster.contains("raw_payload_hex"));
        assert!(serialized_raster.contains("png_bytes_len"));
        assert!(serialized_raster.contains("pixel_bytes_sha256"));
        assert!(!serialized_raster.contains("\"png_bytes\""));
        assert!(!serialized_raster.contains("\"pixel_bytes\""));
        assert!(serialized_raster.contains("\"rgba8_premultiplied_srgb_top_down\""));
        let synthetic_execution = synthetic_senocr_execution(&prepared.request);
        assert_eq!(
            projection_from_execution(
                &prepared.request,
                prepared.ink_binding.clone(),
                None,
                &synthetic_execution,
            )
            .unwrap_err(),
            ConvertPreparationError::RasterRejected
        );
        let projection = projection_from_execution(
            &prepared.request,
            prepared.ink_binding.clone(),
            prepared.generated_raster.clone(),
            &synthetic_execution,
        )
        .unwrap();
        assert_eq!(projection.generated_raster, prepared.generated_raster);
        assert_eq!(
            projection.input_modalities,
            Some(vec![ProjectionInputModalityV1::Raster])
        );
        let mut second_provider_version = synthetic_senocr_execution(&retry.request);
        second_provider_version.provider.provider_version = "synthetic-version-2".to_owned();
        second_provider_version.result.provider.provider_version = "synthetic-version-2".to_owned();
        let retry_projection = projection_from_execution(
            &retry.request,
            retry.ink_binding.clone(),
            retry.generated_raster.clone(),
            &second_provider_version,
        )
        .unwrap();
        assert_ne!(projection.projection_id, retry_projection.projection_id);
        assert_eq!(projection.ink.region_id, retry_projection.ink.region_id);
        assert_ne!(
            projection.provider.provider_version,
            retry_projection.provider.provider_version
        );
        assert_eq!(
            prepared.request.source_revision.last_sequence,
            before.last_sequence
        );
        assert_eq!(writer.replay_state(), &before);

        let mut unrelated_hover = direct_sample(&first_target, 99, 400, 400);
        unrelated_hover.stroke_id = None;
        unrelated_hover.source_device_id = None;
        unrelated_hover.pointer_id = None;
        writer.append_sample(unrelated_hover).unwrap();
        writer
            .append_metadata(JournalMetadata {
                scope: MetadataScope::Session,
                scope_id: "session-1".to_owned(),
                source_api: None,
                device_id: None,
                key: "unrelated-convert-observation".to_owned(),
                value: "not part of selected ink".to_owned(),
                provenance: "test-observation".to_owned(),
                app_arrival_elapsed_ns: 500,
            })
            .unwrap();
        let after_unrelated = writer.replay_state().clone();
        let refreshed = prepare_conversion(
            &after_unrelated,
            &[second_target.clone(), first_target.clone()],
            "convert-order-retry",
            "line-1",
            &provider,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            refreshed.request.source_revision.last_sequence,
            after_unrelated.last_sequence
        );
        assert_eq!(
            refreshed.request.input_view_id,
            prepared.request.input_view_id
        );
        assert_eq!(
            refreshed.ink_binding.ink_binding_sha256,
            prepared.ink_binding.ink_binding_sha256
        );
        assert_eq!(
            refreshed.ink_binding.source_sample_sequences.as_slice(),
            prepared.ink_binding.source_sample_sequences.as_slice()
        );
        assert!(same_generated_raster_output(
            prepared.generated_raster.as_ref(),
            refreshed.generated_raster.as_ref(),
        ));
        assert_ne!(
            prepared
                .generated_raster
                .as_ref()
                .unwrap()
                .source
                .last_sequence,
            refreshed
                .generated_raster
                .as_ref()
                .unwrap()
                .source
                .last_sequence
        );
        assert_eq!(
            prepared
                .generated_raster
                .as_ref()
                .unwrap()
                .source_content_sha256,
            refreshed
                .generated_raster
                .as_ref()
                .unwrap()
                .source_content_sha256
        );
        assert_eq!(
            prepared.generated_raster.as_ref().unwrap().geometry_sha256,
            refreshed.generated_raster.as_ref().unwrap().geometry_sha256
        );
        assert_ne!(
            prepared
                .generated_raster
                .as_ref()
                .unwrap()
                .raster_artifact_sha256,
            refreshed
                .generated_raster
                .as_ref()
                .unwrap()
                .raster_artifact_sha256,
            "the artifact hash includes the exact source boundary"
        );
        let mut different_pixels = refreshed.generated_raster.clone().unwrap();
        different_pixels.pixel_bytes_sha256 = "f".repeat(64);
        assert!(!same_generated_raster_output(
            prepared.generated_raster.as_ref(),
            Some(&different_pixels),
        ));
        let mut different_source_content = refreshed.generated_raster.clone().unwrap();
        different_source_content.source_content_sha256 = "f".repeat(64);
        assert!(!same_generated_raster_output(
            prepared.generated_raster.as_ref(),
            Some(&different_source_content),
        ));
        let mut different_geometry = refreshed.generated_raster.clone().unwrap();
        different_geometry.geometry_sha256 = "f".repeat(64);
        assert!(!same_generated_raster_output(
            prepared.generated_raster.as_ref(),
            Some(&different_geometry),
        ));
        let mut different_artifact = prepared.generated_raster.clone().unwrap();
        different_artifact.raster_artifact_sha256 = "f".repeat(64);
        assert!(!same_generated_raster_output(
            prepared.generated_raster.as_ref(),
            Some(&different_artifact),
        ));
        let mut different_view = refreshed.generated_raster.clone().unwrap();
        different_view.source.input_view_id = "input-view-v1-0000000000000002".to_owned();
        assert!(!same_generated_raster_output(
            prepared.generated_raster.as_ref(),
            Some(&different_view),
        ));
        assert!(!same_generated_raster_output(
            prepared.generated_raster.as_ref(),
            None,
        ));

        writer
            .apply_edit_action_record(
                600,
                crate::journal::EditCommand::Move {
                    target: first_target.clone(),
                    delta_x_raw: 10,
                    delta_y_raw: 0,
                    coordinate_space: "windows-screen-coordinates".to_owned(),
                    units: "screen-pixel".to_owned(),
                },
            )
            .unwrap();
        let moved_state = writer.replay_state().clone();
        let after_logical_move = prepare_conversion(
            &moved_state,
            &[second_target.clone(), first_target.clone()],
            "convert-order-after-move",
            "line-1",
            &provider,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            after_logical_move.request.region_id,
            prepared.request.region_id
        );
        assert_ne!(
            after_logical_move.request.input_view_id,
            prepared.request.input_view_id
        );
        assert_ne!(
            after_logical_move.ink_binding.ink_binding_sha256,
            prepared.ink_binding.ink_binding_sha256
        );
        assert_eq!(
            &writer.replay_state().physical_samples[..2],
            before.physical_samples.as_slice()
        );
        writer.flush().unwrap();
        drop(writer);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(config_path);
    }

    #[test]
    fn convert_preparation_rejects_uncommitted_strokes_and_prelaunch_cancel() {
        let journal_id = "convert-uncommitted-project";
        let path = std::env::temp_dir().join(format!(
            "lassoink-convert-uncommitted-{}-{}.inkj",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let mut writer = JournalWriter::create(
            path.clone(),
            JournalHeader {
                journal_id: journal_id.to_owned(),
                session_id: "session-1".to_owned(),
                config_id: None,
                device_model_declared: None,
                tilt_supported_declared: None,
            },
        )
        .unwrap();
        let target = direct_target(journal_id, "unfinished");
        writer
            .start_stroke(target.clone(), StrokeViewFrame::default(), 1)
            .unwrap();
        writer
            .append_sample(direct_sample(&target, 1, 10, 20))
            .unwrap();
        let snapshot = writer.replay_state().clone();
        let config_path = write_provider_config(&[LOCAL_SENOCR_PROVIDER_ID], &["raster"]);
        let provider = LocalConvertProviderV1::load(&config_path, None).unwrap();
        let not_cancelled = AtomicBool::new(false);
        assert_eq!(
            prepare_conversion(
                &snapshot,
                std::slice::from_ref(&target),
                "unfinished-request",
                "line-1",
                &provider,
                &not_cancelled,
            )
            .unwrap_err(),
            ConvertPreparationError::UnsupportedSource
        );
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            prepare_conversion(
                &JournalReplayState::default(),
                &[],
                "cancelled-request",
                "line-1",
                &provider,
                &cancelled,
            )
            .unwrap_err(),
            ConvertPreparationError::Cancelled
        );
        writer.flush().unwrap();
        drop(writer);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(config_path);
    }
}
