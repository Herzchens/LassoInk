//! Bounded single-region Markdown/HTML export derived from a validated project snapshot.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    canvas::{
        CanonicalRasterProjectionSpecV1, MAX_CANONICAL_RASTER_PNG_BYTES,
        build_canonical_raster_projection_plan, render_canonical_raster,
        transform_canonical_raster_geometry,
    },
    convert::{
        CONVERT_RASTER_HEIGHT_PX, CONVERT_RASTER_SOURCE_PADDING_PX, CONVERT_RASTER_WIDTH_PX,
    },
    correction::CorrectionSession,
    journal::{
        JournalReplayState, MAX_JOURNAL_TEXT_BYTES, ProjectionInkBindingV1, ProjectionStrokeViewV1,
        RegionCorrectionActionV1, StrokeRef, validate_region_correction_text,
    },
};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

const EXPORT_SCHEMA_VERSION: u32 = 1;
const MARKDOWN_FILE_NAME: &str = "document.md";
const HTML_FILE_NAME: &str = "index.html";
const DOCX_FILE_NAME: &str = "document.docx";
const PDF_FILE_NAME: &str = "document.pdf";
const INK_ASSET_FILE_NAME: &str = "assets/selected-region.png";
const INK_ASSET_ALT_TEXT: &str = "Original selected ink";
const MAX_EXPORT_DOCUMENT_BYTES: usize = MAX_JOURNAL_TEXT_BYTES * 8 + 16 * 1024;
const MAX_EXPORT_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_EXPORT_BINDING_BYTES: usize = 32 * 1024 * 1024;
const MAX_EXPORT_SELECTED_STROKES: usize = 512;
const MAX_EXPORT_SELECTED_SAMPLES: usize = 4096;
const MAX_STAGE_NAME_ATTEMPTS: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExportError {
    Cancelled,
    InvalidTarget,
    InvalidSelection,
    StaleSource,
    InvalidText,
    InkUnavailable,
    AllocationFailed,
    OutputTooLarge,
    DestinationExists,
    IoFailure,
    NoFormatsRequested,
    IncompleteOutputSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExportFormat {
    Markdown,
    Html,
    Docx,
    Pdf,
}

impl ExportFormat {
    pub(crate) const fn display_name(self) -> &'static str {
        match self {
            Self::Markdown => "Markdown",
            Self::Html => "HTML",
            Self::Docx => "DOCX",
            Self::Pdf => "PDF",
        }
    }

    pub(crate) const fn ui_label(self, selected: bool) -> &'static str {
        match (self, selected) {
            (Self::Markdown, true) => "[MD*]",
            (Self::Markdown, false) => "[MD]",
            (Self::Html, true) => "[HTML*]",
            (Self::Html, false) => "[HTML]",
            (Self::Docx, true) => "[DOCX*]",
            (Self::Docx, false) => "[DOCX]",
            (Self::Pdf, true) => "[PDF*]",
            (Self::Pdf, false) => "[PDF]",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExportFormats {
    pub markdown: bool,
    pub html: bool,
    pub docx: bool,
    pub pdf: bool,
}

impl ExportFormats {
    pub(crate) const DEFAULT: Self = Self {
        markdown: true,
        html: true,
        docx: false,
        pdf: false,
    };

    pub(crate) const fn any(self) -> bool {
        self.markdown || self.html || self.docx || self.pdf
    }

    pub(crate) const fn contains(self, format: ExportFormat) -> bool {
        match format {
            ExportFormat::Markdown => self.markdown,
            ExportFormat::Html => self.html,
            ExportFormat::Docx => self.docx,
            ExportFormat::Pdf => self.pdf,
        }
    }

    pub(crate) fn toggle(&mut self, format: ExportFormat) -> bool {
        let another_format_selected = match format {
            ExportFormat::Markdown => self.html || self.docx || self.pdf,
            ExportFormat::Html => self.markdown || self.docx || self.pdf,
            ExportFormat::Docx => self.markdown || self.html || self.pdf,
            ExportFormat::Pdf => self.markdown || self.html || self.docx,
        };
        let selected = match format {
            ExportFormat::Markdown => &mut self.markdown,
            ExportFormat::Html => &mut self.html,
            ExportFormat::Docx => &mut self.docx,
            ExportFormat::Pdf => &mut self.pdf,
        };
        if *selected && !another_format_selected {
            return false;
        }
        *selected = !*selected;
        true
    }

    pub(crate) fn selected_names(self) -> String {
        [
            ExportFormat::Markdown,
            ExportFormat::Html,
            ExportFormat::Docx,
            ExportFormat::Pdf,
        ]
        .into_iter()
        .filter(|format| self.contains(*format))
        .map(ExportFormat::display_name)
        .collect::<Vec<_>>()
        .join(", ")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExportRequestError {
    Export(ExportError),
    Format {
        format: ExportFormat,
        error: ExportError,
    },
}

impl From<ExportError> for ExportRequestError {
    fn from(error: ExportError) -> Self {
        Self::Export(error)
    }
}

impl ExportRequestError {
    #[cfg(test)]
    fn into_export_error(self) -> ExportError {
        match self {
            Self::Export(error) | Self::Format { error, .. } => error,
        }
    }
}

fn format_failure(format: ExportFormat, error: ExportError) -> ExportRequestError {
    if error == ExportError::Cancelled {
        ExportRequestError::Export(error)
    } else {
        ExportRequestError::Format { format, error }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TranscriptOriginV1 {
    InkOnly,
    NoProviderCandidate,
    Provider,
    SetText,
    Reset,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TextRunV1 {
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LineV1 {
    pub runs: Vec<TextRunV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParagraphV1 {
    pub lines: Vec<LineV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawInkFallbackV1 {
    pub asset_file_name: &'static str,
    pub alt_text: &'static str,
}

/// Exact internal source binding for the frozen project snapshot. It is only
/// serialized into a bounded hash; document output uses the explicit allowlist
/// in `render_provenance_*` and never emits StrokeRefs or sample values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "binding_kind", rename_all = "snake_case")]
pub(crate) enum ExportSourceBindingV1 {
    Projection {
        snapshot_last_sequence: u64,
        binding: ProjectionInkBindingV1,
    },
    InkOnly {
        journal_id: String,
        logical_revision: u64,
        snapshot_last_sequence: u64,
        selected_strokes: Vec<StrokeRef>,
        source_sample_sequences: Vec<u64>,
        stroke_views: Vec<ProjectionStrokeViewV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExportProjectionIdentityV1 {
    pub projection_id: String,
    pub correction_id: Option<String>,
    pub provider_id: String,
    pub provider_version: String,
    pub model_version: Option<String>,
    pub resource_version: Option<String>,
    pub configuration_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExportRasterProvenanceV1 {
    pub output_width_px: u32,
    pub output_height_px: u32,
    pub source_content_sha256: String,
    pub projection_spec_sha256: String,
    pub png_bytes_sha256: String,
    pub raster_artifact_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExportProvenanceV1 {
    pub source_binding: ExportSourceBindingV1,
    pub source_binding_sha256: String,
    pub projection: Option<ExportProjectionIdentityV1>,
    pub raster: ExportRasterProvenanceV1,
}

/// Internal semantic IR for one immutable selected region. `None` text and an
/// empty paragraph remain distinct; provenance records whether it is ink-only
/// or bound to provider output, a saved user correction, or Reset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExportRegionV1 {
    pub schema_version: u32,
    pub transcript_origin: TranscriptOriginV1,
    pub paragraph: Option<ParagraphV1>,
    pub raw_ink_fallback: RawInkFallbackV1,
    pub provenance: ExportProvenanceV1,
}

#[derive(Debug)]
pub(crate) struct ExportBundleV1 {
    pub region: ExportRegionV1,
    pub formats: ExportFormats,
    pub markdown: Option<Vec<u8>>,
    pub html: Option<Vec<u8>>,
    pub docx: Option<Vec<u8>>,
    pub pdf: Option<Vec<u8>>,
    pub selected_ink_png: Vec<u8>,
}

pub(crate) fn is_absolute_local_target(target: &Path) -> bool {
    if !target.is_absolute() || target.file_name().is_none() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        matches!(
            target.components().next(),
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
        )
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn validate_export_target_path(target: &Path) -> bool {
    is_absolute_local_target(target) && target.parent().is_some_and(|parent| parent.is_dir())
}

/// Builds owned output from one writer-acknowledged snapshot. The binding's
/// source prefix may precede later derived rows; journal validation checks that
/// its selected samples, captured view, and logical revision remain unchanged.
#[cfg(test)]
pub(crate) fn build_selected_region_bundle(
    state: &JournalReplayState,
    projection_id: &str,
    binding: &ProjectionInkBindingV1,
    selected_strokes: &[StrokeRef],
    cancelled: &AtomicBool,
) -> Result<ExportBundleV1, ExportError> {
    build_selected_region_bundle_with_formats(
        state,
        projection_id,
        binding,
        selected_strokes,
        ExportFormats::DEFAULT,
        cancelled,
    )
    .map_err(ExportRequestError::into_export_error)
}

pub(crate) fn build_selected_region_bundle_with_formats(
    state: &JournalReplayState,
    projection_id: &str,
    binding: &ProjectionInkBindingV1,
    selected_strokes: &[StrokeRef],
    formats: ExportFormats,
    cancelled: &AtomicBool,
) -> Result<ExportBundleV1, ExportRequestError> {
    if !formats.any() {
        return Err(ExportError::NoFormatsRequested.into());
    }
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled.into());
    }
    if !selected_strokes_match_binding(selected_strokes, &binding.selected_strokes) {
        return Err(ExportError::InvalidSelection.into());
    }
    state
        .validate_export_projection_binding(projection_id, binding)
        .map_err(|_| ExportError::StaleSource)?;
    let projection = state
        .recognition_projections
        .iter()
        .find(|stored| stored.projection.projection_id == projection_id)
        .map(|stored| &stored.projection)
        .ok_or(ExportError::StaleSource)?;
    let session =
        CorrectionSession::open(state, projection_id).map_err(|_| ExportError::StaleSource)?;
    let transcript_origin = match session.latest_saved_action() {
        Some(RegionCorrectionActionV1::SetText(_)) => TranscriptOriginV1::SetText,
        Some(RegionCorrectionActionV1::Reset) => TranscriptOriginV1::Reset,
        None if projection
            .candidates
            .iter()
            .any(|candidate| candidate.rank == 0) =>
        {
            TranscriptOriginV1::Provider
        }
        None => TranscriptOriginV1::NoProviderCandidate,
    };
    let effective_text = session.effective_text().map(str::to_owned);
    let paragraph = match effective_text.as_deref() {
        Some(text) => {
            validate_region_correction_text(text).map_err(|_| ExportError::InvalidText)?;
            Some(paragraph_from_text(text)?)
        }
        None => None,
    };
    let source_binding = ExportSourceBindingV1::Projection {
        snapshot_last_sequence: state.last_sequence,
        binding: binding.clone(),
    };
    let source_binding_sha256 = hash_source_binding(&source_binding)?;
    let correction_id = state
        .region_corrections
        .iter()
        .rev()
        .find(|stored| stored.correction.projection_id == projection_id)
        .map(|stored| stored.correction.correction_id.clone());
    let projection_identity = ExportProjectionIdentityV1 {
        projection_id: projection_id.to_owned(),
        correction_id,
        provider_id: projection.provider.provider_id.clone(),
        provider_version: projection.provider.provider_version.clone(),
        model_version: projection.provider.model_version.clone(),
        resource_version: projection.provider.resource_version.clone(),
        configuration_fingerprint: projection.provider.configuration_fingerprint.clone(),
    };
    let (selected_ink_png, raster, _) = render_export_ink(
        state,
        &binding.selected_strokes,
        Some(&binding.selected_strokes),
        cancelled,
    )?;
    let region = ExportRegionV1 {
        schema_version: EXPORT_SCHEMA_VERSION,
        transcript_origin,
        paragraph,
        raw_ink_fallback: RawInkFallbackV1 {
            asset_file_name: INK_ASSET_FILE_NAME,
            alt_text: INK_ASSET_ALT_TEXT,
        },
        provenance: ExportProvenanceV1 {
            source_binding,
            source_binding_sha256,
            projection: Some(projection_identity),
            raster,
        },
    };
    finish_export_bundle(region, selected_ink_png, formats, cancelled)
}

/// Builds a local ink-only export for a durable selection with no stored
/// recognition projection. This path creates no provider or M4 identities.
#[cfg(test)]
pub(crate) fn build_ink_only_bundle(
    state: &JournalReplayState,
    selected_strokes: &[StrokeRef],
    cancelled: &AtomicBool,
) -> Result<ExportBundleV1, ExportError> {
    build_ink_only_bundle_with_formats(state, selected_strokes, ExportFormats::DEFAULT, cancelled)
        .map_err(ExportRequestError::into_export_error)
}

pub(crate) fn build_ink_only_bundle_with_formats(
    state: &JournalReplayState,
    selected_strokes: &[StrokeRef],
    formats: ExportFormats,
    cancelled: &AtomicBool,
) -> Result<ExportBundleV1, ExportRequestError> {
    if !formats.any() {
        return Err(ExportError::NoFormatsRequested.into());
    }
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled.into());
    }
    if selected_strokes.is_empty() || selected_strokes.len() > MAX_EXPORT_SELECTED_STROKES {
        return Err(ExportError::InvalidSelection.into());
    }
    if state.recognition_projections.iter().any(|stored| {
        selected_strokes_match_binding(selected_strokes, &stored.projection.ink.selected_strokes)
    }) {
        return Err(ExportError::StaleSource.into());
    }
    let (selected_ink_png, raster, canonical_order) =
        render_export_ink(state, selected_strokes, None, cancelled)?;
    let mut source_sample_sequences = Vec::new();
    source_sample_sequences
        .try_reserve_exact(
            state
                .physical_samples
                .len()
                .min(MAX_EXPORT_SELECTED_SAMPLES),
        )
        .map_err(|_| ExportError::AllocationFailed)?;
    for stored_sample in &state.physical_samples {
        let Some(stroke) = stored_sample.sample.stroke_ref(&state.journal_id) else {
            continue;
        };
        if !canonical_order.contains(&stroke) {
            continue;
        }
        if source_sample_sequences.len() >= MAX_EXPORT_SELECTED_SAMPLES {
            return Err(ExportError::OutputTooLarge.into());
        }
        source_sample_sequences
            .try_reserve(1)
            .map_err(|_| ExportError::AllocationFailed)?;
        source_sample_sequences.push(stored_sample.sequence);
    }
    let mut stroke_views = Vec::new();
    stroke_views
        .try_reserve_exact(canonical_order.len())
        .map_err(|_| ExportError::AllocationFailed)?;
    for stroke in &canonical_order {
        let start = state
            .stroke_starts
            .iter()
            .find(|start| &start.target == stroke)
            .ok_or(ExportError::InkUnavailable)?;
        stroke_views.push(ProjectionStrokeViewV1 {
            stroke: stroke.clone(),
            frame: start.view_frame,
        });
    }
    let source_binding = ExportSourceBindingV1::InkOnly {
        journal_id: state.journal_id.clone(),
        logical_revision: state.logical_revision,
        snapshot_last_sequence: state.last_sequence,
        selected_strokes: canonical_order,
        source_sample_sequences,
        stroke_views,
    };
    let source_binding_sha256 = hash_source_binding(&source_binding)?;
    let region = ExportRegionV1 {
        schema_version: EXPORT_SCHEMA_VERSION,
        transcript_origin: TranscriptOriginV1::InkOnly,
        paragraph: None,
        raw_ink_fallback: RawInkFallbackV1 {
            asset_file_name: INK_ASSET_FILE_NAME,
            alt_text: INK_ASSET_ALT_TEXT,
        },
        provenance: ExportProvenanceV1 {
            source_binding,
            source_binding_sha256,
            projection: None,
            raster,
        },
    };
    finish_export_bundle(region, selected_ink_png, formats, cancelled)
}

fn render_export_ink(
    state: &JournalReplayState,
    selected_strokes: &[StrokeRef],
    expected_canonical_order: Option<&[StrokeRef]>,
    cancelled: &AtomicBool,
) -> Result<(Vec<u8>, ExportRasterProvenanceV1, Vec<StrokeRef>), ExportError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled);
    }
    let plan = build_canonical_raster_projection_plan(state, selected_strokes)
        .map_err(|_| ExportError::InkUnavailable)?;
    let canonical_order = plan
        .journal_first_occurrence_stroke_order()
        .map_err(|_| ExportError::InkUnavailable)?;
    if let Some(expected_canonical_order) = expected_canonical_order {
        if canonical_order.as_slice() != expected_canonical_order {
            return Err(ExportError::StaleSource);
        }
    } else if !selected_strokes_match_binding(selected_strokes, &canonical_order) {
        return Err(ExportError::InvalidSelection);
    }
    let spec = CanonicalRasterProjectionSpecV1::new(
        CONVERT_RASTER_WIDTH_PX,
        CONVERT_RASTER_HEIGHT_PX,
        plan.source_crop_with_padding(CONVERT_RASTER_SOURCE_PADDING_PX)
            .map_err(|_| ExportError::InkUnavailable)?,
    );
    let geometry = transform_canonical_raster_geometry(&plan, &spec)
        .map_err(|_| ExportError::InkUnavailable)?;
    let image = render_canonical_raster(&geometry).map_err(|_| ExportError::InkUnavailable)?;
    let png = image.png_bytes();
    if png.is_empty() || png.len() > MAX_CANONICAL_RASTER_PNG_BYTES {
        return Err(ExportError::OutputTooLarge);
    }
    let png_digest: [u8; 32] = Sha256::digest(png).into();
    if image.source_revision_parts()
        != (
            state.journal_id.as_str(),
            state.logical_revision,
            state.last_sequence,
        )
        || png_digest != image.png_bytes_sha256()
    {
        return Err(ExportError::InkUnavailable);
    }
    let mut selected_ink_png = Vec::new();
    selected_ink_png
        .try_reserve_exact(png.len())
        .map_err(|_| ExportError::AllocationFailed)?;
    selected_ink_png.extend_from_slice(png);
    let (output_width_px, output_height_px, _) = image.output_dimensions_and_stride();
    let raster = ExportRasterProvenanceV1 {
        output_width_px,
        output_height_px,
        source_content_sha256: hex_sha256(&image.source_content_sha256())?,
        projection_spec_sha256: hex_sha256(&image.projection_spec_sha256())?,
        png_bytes_sha256: hex_sha256(&image.png_bytes_sha256())?,
        raster_artifact_sha256: hex_sha256(&image.raster_artifact_sha256())?,
    };
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled);
    }
    Ok((selected_ink_png, raster, canonical_order))
}

fn finish_export_bundle(
    region: ExportRegionV1,
    selected_ink_png: Vec<u8>,
    formats: ExportFormats,
    cancelled: &AtomicBool,
) -> Result<ExportBundleV1, ExportRequestError> {
    if !formats.any() {
        return Err(ExportError::NoFormatsRequested.into());
    }
    let markdown = formats
        .markdown
        .then(|| render_markdown(&region))
        .transpose()
        .map_err(|error| format_failure(ExportFormat::Markdown, error))?;
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled.into());
    }
    let html = formats
        .html
        .then(|| render_html(&region))
        .transpose()
        .map_err(|error| format_failure(ExportFormat::Html, error))?;
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled.into());
    }
    let docx = formats
        .docx
        .then(|| docx_serializer::serialize_docx_cancellable(&region, &selected_ink_png, cancelled))
        .transpose()
        .map_err(|error| format_failure(ExportFormat::Docx, error))?;
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled.into());
    }
    let pdf = formats
        .pdf
        .then(|| pdf_serializer::serialize_pdf_cancellable(&region, &selected_ink_png, cancelled))
        .transpose()
        .map_err(|error| format_failure(ExportFormat::Pdf, error))?;
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled.into());
    }
    let _published_set_bytes = checked_published_set_bytes(
        formats,
        markdown.as_deref(),
        html.as_deref(),
        docx.as_deref(),
        pdf.as_deref(),
        &selected_ink_png,
    )?;
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled.into());
    }
    Ok(ExportBundleV1 {
        region,
        formats,
        markdown,
        html,
        docx,
        pdf,
        selected_ink_png,
    })
}

struct BoundedBindingHasher {
    hasher: Sha256,
    bytes_written: usize,
}

impl BoundedBindingHasher {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes_written: 0,
        }
    }

    fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl Write for BoundedBindingHasher {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_len = self
            .bytes_written
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("binding hash input exceeded its fixed bound"))?;
        if next_len > MAX_EXPORT_BINDING_BYTES {
            return Err(io::Error::other(
                "binding hash input exceeded its fixed bound",
            ));
        }
        self.hasher.update(bytes);
        self.bytes_written = next_len;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hash_source_binding(binding: &ExportSourceBindingV1) -> Result<String, ExportError> {
    let mut writer = BoundedBindingHasher::new();
    serde_json::to_writer(&mut writer, binding).map_err(|_| ExportError::OutputTooLarge)?;
    hex_sha256(&writer.finish())
}

pub(super) fn hex_sha256(bytes: &[u8; 32]) -> Result<String, ExportError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::new();
    output
        .try_reserve_exact(64)
        .map_err(|_| ExportError::AllocationFailed)?;
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(output)
}

fn sha256_text(text: &str) -> Result<String, ExportError> {
    let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
    hex_sha256(&digest)
}

pub(crate) fn selected_strokes_match_binding(
    selected_strokes: &[StrokeRef],
    bound_strokes: &[StrokeRef],
) -> bool {
    if selected_strokes.is_empty() || selected_strokes.len() != bound_strokes.len() {
        return false;
    }
    let mut selected = selected_strokes.to_vec();
    let mut bound = bound_strokes.to_vec();
    selected.sort();
    bound.sort();
    selected == bound
}

fn paragraph_from_text(text: &str) -> Result<ParagraphV1, ExportError> {
    let mut normalized = String::new();
    normalized
        .try_reserve(text.len())
        .map_err(|_| ExportError::AllocationFailed)?;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\r' {
            if characters.peek() == Some(&'\n') {
                characters.next();
            }
            normalized.push('\n');
        } else {
            normalized.push(character);
        }
    }
    let line_count = normalized.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let mut lines = Vec::new();
    lines
        .try_reserve_exact(line_count)
        .map_err(|_| ExportError::AllocationFailed)?;
    for line in normalized.split('\n') {
        let mut run_text = String::new();
        run_text
            .try_reserve_exact(line.len())
            .map_err(|_| ExportError::AllocationFailed)?;
        run_text.push_str(line);
        lines.push(LineV1 {
            runs: vec![TextRunV1 { text: run_text }],
        });
    }
    Ok(ParagraphV1 { lines })
}

fn transcript_state_label(region: &ExportRegionV1) -> &'static str {
    let is_empty = region.paragraph.as_ref().is_some_and(|paragraph| {
        paragraph
            .lines
            .iter()
            .flat_map(|line| &line.runs)
            .all(|run| run.text.is_empty())
    });
    match (
        region.transcript_origin,
        region.paragraph.is_some(),
        is_empty,
    ) {
        (TranscriptOriginV1::InkOnly, _, _) => {
            "No stored transcript is attached; this is an ink-only export."
        }
        (TranscriptOriginV1::NoProviderCandidate, _, _) => "No provider transcript is available.",
        (TranscriptOriginV1::Provider, true, true) => "Provider returned an empty transcript.",
        (TranscriptOriginV1::Provider, _, _) => "Transcript source: provider result.",
        (TranscriptOriginV1::SetText, true, true) => {
            "The saved user correction intentionally contains no text."
        }
        (TranscriptOriginV1::SetText, _, _) => "Transcript source: saved user correction.",
        (TranscriptOriginV1::Reset, false, _) => {
            "The correction was reset; no provider transcript is available."
        }
        (TranscriptOriginV1::Reset, true, true) => {
            "The correction was reset to an empty provider transcript."
        }
        (TranscriptOriginV1::Reset, _, _) => "Transcript reset to provider output.",
    }
}

fn render_markdown(region: &ExportRegionV1) -> Result<Vec<u8>, ExportError> {
    let mut output = String::new();
    output
        .try_reserve(MAX_EXPORT_DOCUMENT_BYTES)
        .map_err(|_| ExportError::AllocationFailed)?;
    push_bounded(&mut output, "# Selected region\n\n")?;
    push_bounded(&mut output, transcript_state_label(region))?;
    push_bounded(&mut output, "\n\n")?;
    if let Some(paragraph) = &region.paragraph {
        for (line_index, line) in paragraph.lines.iter().enumerate() {
            if line_index > 0 {
                push_bounded(&mut output, "  \n")?;
            }
            for run in &line.runs {
                push_markdown_text(&mut output, &run.text)?;
            }
        }
        push_bounded(&mut output, "\n\n")?;
    }
    render_provenance_markdown(&mut output, &region.provenance)?;
    push_bounded(&mut output, "![")?;
    push_bounded(&mut output, region.raw_ink_fallback.alt_text)?;
    push_bounded(&mut output, "](")?;
    push_bounded(&mut output, region.raw_ink_fallback.asset_file_name)?;
    push_bounded(&mut output, ")\n")?;
    Ok(output.into_bytes())
}

fn render_html(region: &ExportRegionV1) -> Result<Vec<u8>, ExportError> {
    let mut output = String::new();
    output
        .try_reserve(MAX_EXPORT_DOCUMENT_BYTES)
        .map_err(|_| ExportError::AllocationFailed)?;
    push_bounded(
        &mut output,
        "<!doctype html>\n<html lang=\"und\">\n<head>\n<meta charset=\"utf-8\">\n<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src 'self'; base-uri 'none'; form-action 'none'\">\n<title>Selected region</title>\n</head>\n<body>\n<main>\n",
    )?;
    push_bounded(&mut output, "<p class=\"transcript-state\">")?;
    push_html_text(&mut output, transcript_state_label(region))?;
    push_bounded(&mut output, "</p>\n")?;
    if let Some(paragraph) = &region.paragraph {
        push_bounded(&mut output, "<p>\n")?;
        for (line_index, line) in paragraph.lines.iter().enumerate() {
            if line_index > 0 {
                push_bounded(&mut output, "<br>\n")?;
            }
            for run in &line.runs {
                push_html_text(&mut output, &run.text)?;
            }
        }
        push_bounded(&mut output, "\n</p>\n")?;
    }
    render_provenance_html(&mut output, &region.provenance)?;
    push_bounded(&mut output, "<figure><img src=\"")?;
    push_bounded(&mut output, region.raw_ink_fallback.asset_file_name)?;
    push_bounded(&mut output, "\" alt=\"")?;
    push_html_text(&mut output, region.raw_ink_fallback.alt_text)?;
    push_bounded(&mut output, "\"></figure>\n</main>\n</body>\n</html>\n")?;
    Ok(output.into_bytes())
}

// Document serializers deliberately emit a small allowlist. The source binding
// itself stays in the IR and contributes to its digest; StrokeRefs, sample
// values, paths, provider settings, and raw model markup are never serialized.
fn render_provenance_markdown(
    output: &mut String,
    provenance: &ExportProvenanceV1,
) -> Result<(), ExportError> {
    push_bounded(output, "## Provenance\n\n")?;
    push_provenance_markdown_field(
        output,
        "Provenance schema",
        &EXPORT_SCHEMA_VERSION.to_string(),
    )?;
    match &provenance.source_binding {
        ExportSourceBindingV1::Projection {
            snapshot_last_sequence,
            binding,
        } => {
            push_provenance_markdown_field(output, "Binding kind", "stored projection")?;
            push_provenance_markdown_field(
                output,
                "Logical revision",
                &binding.logical_revision.to_string(),
            )?;
            push_provenance_markdown_field(
                output,
                "Snapshot sequence",
                &snapshot_last_sequence.to_string(),
            )?;
            push_provenance_markdown_field(
                output,
                "Projection source sequence",
                &binding.last_sequence.to_string(),
            )?;
            push_provenance_markdown_field(
                output,
                "Ink binding SHA-256",
                &binding.ink_binding_sha256,
            )?;
            push_provenance_markdown_field(
                output,
                "Selected stroke count",
                &binding.selected_strokes.len().to_string(),
            )?;
            push_provenance_markdown_field(
                output,
                "Bound source sample count",
                &binding.source_sample_sequences.len().to_string(),
            )?;
        }
        ExportSourceBindingV1::InkOnly {
            logical_revision,
            snapshot_last_sequence,
            selected_strokes,
            source_sample_sequences,
            ..
        } => {
            push_provenance_markdown_field(output, "Binding kind", "ink only")?;
            push_provenance_markdown_field(
                output,
                "Logical revision",
                &logical_revision.to_string(),
            )?;
            push_provenance_markdown_field(
                output,
                "Snapshot sequence",
                &snapshot_last_sequence.to_string(),
            )?;
            push_provenance_markdown_field(
                output,
                "Selected stroke count",
                &selected_strokes.len().to_string(),
            )?;
            push_provenance_markdown_field(
                output,
                "Bound source sample count",
                &source_sample_sequences.len().to_string(),
            )?;
        }
    }
    push_provenance_markdown_field(
        output,
        "Selection binding SHA-256",
        &provenance.source_binding_sha256,
    )?;
    if let Some(projection) = &provenance.projection {
        push_provenance_markdown_field(
            output,
            "Projection identity SHA-256",
            &sha256_text(&projection.projection_id)?,
        )?;
        if let Some(correction_id) = projection.correction_id.as_deref() {
            push_provenance_markdown_field(
                output,
                "Correction identity SHA-256",
                &sha256_text(correction_id)?,
            )?;
        }
        push_provenance_markdown_field(
            output,
            "Provider identity SHA-256",
            &sha256_text(&projection.provider_id)?,
        )?;
        push_provenance_markdown_version(
            output,
            "Provider version",
            "Provider version SHA-256",
            &projection.provider_version,
        )?;
        if let Some(model_version) = projection.model_version.as_deref() {
            push_provenance_markdown_version(
                output,
                "Model version",
                "Model version SHA-256",
                model_version,
            )?;
        }
        if let Some(resource_version) = projection.resource_version.as_deref() {
            push_provenance_markdown_version(
                output,
                "Resource version",
                "Resource version SHA-256",
                resource_version,
            )?;
        }
        push_provenance_markdown_field(
            output,
            "Provider configuration fingerprint SHA-256",
            &sha256_text(&projection.configuration_fingerprint)?,
        )?;
    }
    push_provenance_markdown_field(
        output,
        "Export raster source SHA-256",
        &provenance.raster.source_content_sha256,
    )?;
    push_provenance_markdown_field(
        output,
        "Export raster spec SHA-256",
        &provenance.raster.projection_spec_sha256,
    )?;
    push_provenance_markdown_field(
        output,
        "Export PNG SHA-256",
        &provenance.raster.png_bytes_sha256,
    )?;
    push_provenance_markdown_field(
        output,
        "Export raster artifact SHA-256",
        &provenance.raster.raster_artifact_sha256,
    )?;
    push_provenance_markdown_field(
        output,
        "Export PNG dimensions",
        &format!(
            "{} x {}",
            provenance.raster.output_width_px, provenance.raster.output_height_px
        ),
    )?;
    push_bounded(
        output,
        "\nExport PNG is an export render, not a claim about recognizer input.\n\n",
    )
}

fn push_provenance_markdown_field(
    output: &mut String,
    label: &str,
    value: &str,
) -> Result<(), ExportError> {
    push_bounded(output, "- ")?;
    push_bounded(output, label)?;
    push_bounded(output, ": ")?;
    push_single_line_markdown_text(output, value)?;
    push_bounded(output, "\n")
}

fn push_provenance_markdown_version(
    output: &mut String,
    label: &str,
    hash_label: &str,
    value: &str,
) -> Result<(), ExportError> {
    if is_safe_version_metadata(value) {
        push_provenance_markdown_field(output, label, value)
    } else {
        let digest = sha256_text(value)?;
        push_provenance_markdown_field(output, hash_label, &digest)
    }
}

fn render_provenance_html(
    output: &mut String,
    provenance: &ExportProvenanceV1,
) -> Result<(), ExportError> {
    push_bounded(
        output,
        "<section aria-label=\"Export provenance\"><h2>Provenance</h2><dl>\n",
    )?;
    push_provenance_html_field(
        output,
        "Provenance schema",
        &EXPORT_SCHEMA_VERSION.to_string(),
    )?;
    match &provenance.source_binding {
        ExportSourceBindingV1::Projection {
            snapshot_last_sequence,
            binding,
        } => {
            push_provenance_html_field(output, "Binding kind", "stored projection")?;
            push_provenance_html_field(
                output,
                "Logical revision",
                &binding.logical_revision.to_string(),
            )?;
            push_provenance_html_field(
                output,
                "Snapshot sequence",
                &snapshot_last_sequence.to_string(),
            )?;
            push_provenance_html_field(
                output,
                "Projection source sequence",
                &binding.last_sequence.to_string(),
            )?;
            push_provenance_html_field(output, "Ink binding SHA-256", &binding.ink_binding_sha256)?;
            push_provenance_html_field(
                output,
                "Selected stroke count",
                &binding.selected_strokes.len().to_string(),
            )?;
            push_provenance_html_field(
                output,
                "Bound source sample count",
                &binding.source_sample_sequences.len().to_string(),
            )?;
        }
        ExportSourceBindingV1::InkOnly {
            logical_revision,
            snapshot_last_sequence,
            selected_strokes,
            source_sample_sequences,
            ..
        } => {
            push_provenance_html_field(output, "Binding kind", "ink only")?;
            push_provenance_html_field(output, "Logical revision", &logical_revision.to_string())?;
            push_provenance_html_field(
                output,
                "Snapshot sequence",
                &snapshot_last_sequence.to_string(),
            )?;
            push_provenance_html_field(
                output,
                "Selected stroke count",
                &selected_strokes.len().to_string(),
            )?;
            push_provenance_html_field(
                output,
                "Bound source sample count",
                &source_sample_sequences.len().to_string(),
            )?;
        }
    }
    push_provenance_html_field(
        output,
        "Selection binding SHA-256",
        &provenance.source_binding_sha256,
    )?;
    if let Some(projection) = &provenance.projection {
        push_provenance_html_field(
            output,
            "Projection identity SHA-256",
            &sha256_text(&projection.projection_id)?,
        )?;
        if let Some(correction_id) = projection.correction_id.as_deref() {
            push_provenance_html_field(
                output,
                "Correction identity SHA-256",
                &sha256_text(correction_id)?,
            )?;
        }
        push_provenance_html_field(
            output,
            "Provider identity SHA-256",
            &sha256_text(&projection.provider_id)?,
        )?;
        push_provenance_html_version(
            output,
            "Provider version",
            "Provider version SHA-256",
            &projection.provider_version,
        )?;
        if let Some(model_version) = projection.model_version.as_deref() {
            push_provenance_html_version(
                output,
                "Model version",
                "Model version SHA-256",
                model_version,
            )?;
        }
        if let Some(resource_version) = projection.resource_version.as_deref() {
            push_provenance_html_version(
                output,
                "Resource version",
                "Resource version SHA-256",
                resource_version,
            )?;
        }
        push_provenance_html_field(
            output,
            "Provider configuration fingerprint SHA-256",
            &sha256_text(&projection.configuration_fingerprint)?,
        )?;
    }
    push_provenance_html_field(
        output,
        "Export raster source SHA-256",
        &provenance.raster.source_content_sha256,
    )?;
    push_provenance_html_field(
        output,
        "Export raster spec SHA-256",
        &provenance.raster.projection_spec_sha256,
    )?;
    push_provenance_html_field(
        output,
        "Export PNG SHA-256",
        &provenance.raster.png_bytes_sha256,
    )?;
    push_provenance_html_field(
        output,
        "Export raster artifact SHA-256",
        &provenance.raster.raster_artifact_sha256,
    )?;
    push_provenance_html_field(
        output,
        "Export PNG dimensions",
        &format!(
            "{} x {}",
            provenance.raster.output_width_px, provenance.raster.output_height_px
        ),
    )?;
    push_bounded(
        output,
        "</dl><p>Export PNG is an export render, not a claim about recognizer input.</p></section>\n",
    )
}

fn push_provenance_html_field(
    output: &mut String,
    label: &str,
    value: &str,
) -> Result<(), ExportError> {
    push_bounded(output, "<dt>")?;
    push_html_text(output, label)?;
    push_bounded(output, "</dt><dd>")?;
    push_single_line_html_text(output, value)?;
    push_bounded(output, "</dd>\n")
}

fn push_provenance_html_version(
    output: &mut String,
    label: &str,
    hash_label: &str,
    value: &str,
) -> Result<(), ExportError> {
    if is_safe_version_metadata(value) {
        push_provenance_html_field(output, label, value)
    } else {
        let digest = sha256_text(value)?;
        push_provenance_html_field(output, hash_label, &digest)
    }
}

fn is_safe_version_metadata(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn push_single_line_markdown_text(output: &mut String, text: &str) -> Result<(), ExportError> {
    for character in text.chars() {
        push_markdown_character(
            output,
            if matches!(character, '\r' | '\n') {
                ' '
            } else {
                character
            },
        )?;
    }
    Ok(())
}

fn push_single_line_html_text(output: &mut String, text: &str) -> Result<(), ExportError> {
    for character in text.chars() {
        if matches!(character, '\r' | '\n') {
            push_bounded(output, " ")?;
        } else {
            let mut encoded = [0u8; 4];
            push_html_text(output, character.encode_utf8(&mut encoded))?;
        }
    }
    Ok(())
}

fn push_bounded(output: &mut String, text: &str) -> Result<(), ExportError> {
    let next_len = output
        .len()
        .checked_add(text.len())
        .ok_or(ExportError::OutputTooLarge)?;
    if next_len > MAX_EXPORT_DOCUMENT_BYTES {
        return Err(ExportError::OutputTooLarge);
    }
    output
        .try_reserve(text.len())
        .map_err(|_| ExportError::AllocationFailed)?;
    output.push_str(text);
    Ok(())
}

fn push_markdown_text(output: &mut String, text: &str) -> Result<(), ExportError> {
    for character in text.chars() {
        push_markdown_character(output, character)?;
    }
    Ok(())
}

fn push_markdown_character(output: &mut String, character: char) -> Result<(), ExportError> {
    if matches!(character, '!'..='/' | ':'..='@' | '['..='`' | '{'..='~') {
        push_bounded(output, "\\")?;
    }
    let mut encoded = [0u8; 4];
    push_bounded(output, character.encode_utf8(&mut encoded))
}

fn push_html_text(output: &mut String, text: &str) -> Result<(), ExportError> {
    for character in text.chars() {
        let escaped = match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#39;",
            _ => {
                let mut encoded = [0u8; 4];
                push_bounded(output, character.encode_utf8(&mut encoded))?;
                continue;
            }
        };
        push_bounded(output, escaped)?;
    }
    Ok(())
}

pub(crate) fn publish_export_bundle(
    target: &Path,
    bundle: &ExportBundleV1,
    export_id: u64,
    cancelled: &AtomicBool,
) -> Result<(), ExportError> {
    publish_export_bundle_with_hooks(
        target,
        bundle,
        export_id,
        cancelled,
        |file| file.sync_all(),
        |_| Ok(()),
    )
}

fn publish_export_bundle_with_hooks<S, P>(
    target: &Path,
    bundle: &ExportBundleV1,
    export_id: u64,
    cancelled: &AtomicBool,
    mut sync_file: S,
    before_publish: P,
) -> Result<(), ExportError>
where
    S: FnMut(&File) -> std::io::Result<()>,
    P: FnOnce(&Path) -> std::io::Result<()>,
{
    if bundle.region.schema_version != EXPORT_SCHEMA_VERSION {
        return Err(ExportError::StaleSource);
    }
    if !validate_export_target_path(target) {
        return Err(ExportError::InvalidTarget);
    }
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled);
    }
    let _published_set_bytes = checked_published_set_bytes(
        bundle.formats,
        bundle.markdown.as_deref(),
        bundle.html.as_deref(),
        bundle.docx.as_deref(),
        bundle.pdf.as_deref(),
        &bundle.selected_ink_png,
    )?;

    let mut stage = OwnedStagingDirectory::create(target, export_id)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled);
    }
    if let Some(markdown) = bundle.markdown.as_deref() {
        write_create_new_with_sync(
            &stage.path.join(MARKDOWN_FILE_NAME),
            markdown,
            &mut sync_file,
        )?;
        if cancelled.load(Ordering::Acquire) {
            return Err(ExportError::Cancelled);
        }
    }
    if let Some(html) = bundle.html.as_deref() {
        write_create_new_with_sync(&stage.path.join(HTML_FILE_NAME), html, &mut sync_file)?;
        if cancelled.load(Ordering::Acquire) {
            return Err(ExportError::Cancelled);
        }
    }
    let assets = stage.path.join("assets");
    fs::create_dir(&assets).map_err(|_| ExportError::IoFailure)?;
    write_create_new_with_sync(
        &stage.path.join(INK_ASSET_FILE_NAME),
        &bundle.selected_ink_png,
        &mut sync_file,
    )?;
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled);
    }
    if let Some(docx) = bundle.docx.as_deref() {
        write_create_new_with_sync(&stage.path.join(DOCX_FILE_NAME), docx, &mut sync_file)?;
        if cancelled.load(Ordering::Acquire) {
            return Err(ExportError::Cancelled);
        }
    }
    if let Some(pdf) = bundle.pdf.as_deref() {
        write_create_new_with_sync(&stage.path.join(PDF_FILE_NAME), pdf, &mut sync_file)?;
        if cancelled.load(Ordering::Acquire) {
            return Err(ExportError::Cancelled);
        }
    }
    before_publish(target).map_err(|_| ExportError::IoFailure)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(ExportError::Cancelled);
    }
    stage.publish(target)
}

fn output_matches_selection(selected: bool, output: Option<&[u8]>, maximum: usize) -> bool {
    match (selected, output) {
        (false, None) => true,
        (true, Some(bytes)) => !bytes.is_empty() && bytes.len() <= maximum,
        _ => false,
    }
}

fn checked_published_set_bytes(
    formats: ExportFormats,
    markdown: Option<&[u8]>,
    html: Option<&[u8]>,
    docx: Option<&[u8]>,
    pdf: Option<&[u8]>,
    selected_ink_png: &[u8],
) -> Result<usize, ExportError> {
    if !formats.any() {
        return Err(ExportError::NoFormatsRequested);
    }
    if !output_matches_selection(formats.markdown, markdown, MAX_EXPORT_DOCUMENT_BYTES)
        || !output_matches_selection(formats.html, html, MAX_EXPORT_DOCUMENT_BYTES)
        || !output_matches_selection(formats.docx, docx, docx_serializer::MAX_DOCX_BYTES)
        || !output_matches_selection(formats.pdf, pdf, pdf_serializer::MAX_PDF_BYTES)
    {
        return Err(ExportError::IncompleteOutputSet);
    }
    if selected_ink_png.is_empty() || selected_ink_png.len() > MAX_CANONICAL_RASTER_PNG_BYTES {
        return Err(ExportError::OutputTooLarge);
    }
    let total_bytes = [
        markdown.map_or(0, |bytes| bytes.len()),
        html.map_or(0, |bytes| bytes.len()),
        docx.map_or(0, |bytes| bytes.len()),
        pdf.map_or(0, |bytes| bytes.len()),
        selected_ink_png.len(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .ok_or(ExportError::OutputTooLarge)?;
    if total_bytes > MAX_EXPORT_BUNDLE_BYTES {
        return Err(ExportError::OutputTooLarge);
    }
    Ok(total_bytes)
}

#[cfg(test)]
fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), ExportError> {
    write_create_new_with_sync(path, bytes, &mut |file| file.sync_all())
}

fn write_create_new_with_sync(
    path: &Path,
    bytes: &[u8],
    sync_file: &mut impl FnMut(&File) -> std::io::Result<()>,
) -> Result<(), ExportError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ExportError::DestinationExists
            } else {
                ExportError::IoFailure
            }
        })?;
    file.write_all(bytes).map_err(|_| ExportError::IoFailure)?;
    sync_file(&file).map_err(|_| ExportError::IoFailure)
}

struct OwnedStagingDirectory {
    path: PathBuf,
    published: bool,
}

impl OwnedStagingDirectory {
    fn create(target: &Path, export_id: u64) -> Result<Self, ExportError> {
        let parent = target.parent().ok_or(ExportError::InvalidTarget)?;
        let target_name = target
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or(ExportError::InvalidTarget)?;
        for attempt in 0..MAX_STAGE_NAME_ATTEMPTS {
            let stage_name = format!(
                ".{target_name}.lassoink-export-{}-{export_id}-{attempt}.partial",
                std::process::id()
            );
            let path = parent.join(stage_name);
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        published: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(ExportError::IoFailure),
            }
        }
        Err(ExportError::IoFailure)
    }

    fn publish(&mut self, target: &Path) -> Result<(), ExportError> {
        #[cfg(windows)]
        {
            let source_wide = wide_path(&self.path)?;
            let target_wide = wide_path(target)?;
            // SAFETY: both NUL-terminated paths are owned for the duration of the call. The
            // source is this export's unique same-parent staging directory. Omitting
            // MOVEFILE_REPLACE_EXISTING preserves every pre-existing destination.
            if unsafe {
                MoveFileExW(
                    source_wide.as_ptr(),
                    target_wide.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                let error = std::io::Error::last_os_error();
                return if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Err(ExportError::DestinationExists)
                } else {
                    Err(ExportError::IoFailure)
                };
            }
            self.published = true;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = target;
            Err(ExportError::InvalidTarget)
        }
    }
}

impl Drop for OwnedStagingDirectory {
    fn drop(&mut self) {
        if !self.published {
            // This is best-effort: process termination or a filesystem error can
            // leave the uniquely named `.partial` directory for manual cleanup.
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Result<Vec<u16>, ExportError> {
    let units = path.as_os_str().encode_wide().count();
    if units == 0 || units >= 32_767 || path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(ExportError::InvalidTarget);
    }
    let mut wide = Vec::new();
    wide.try_reserve_exact(units.saturating_add(1))
        .map_err(|_| ExportError::AllocationFailed)?;
    wide.extend(path.as_os_str().encode_wide());
    wide.push(0);
    Ok(wide)
}

// The semantic projection and serializers are also used by production exports.
pub(super) mod document;
#[cfg(test)]
mod document_export_tests;
#[cfg(test)]
pub(super) mod document_fixtures;
pub(super) mod docx_serializer;
pub(super) mod pdf_serializer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canvas::PROVISIONAL_DIRECT_SOURCE_API,
        journal::{
            JournalHeader, JournalWriter, PhysicalSample, ProjectionProviderProvenanceV1,
            ProjectionStrokeRangeV1, ProjectionStrokeViewV1, RawPosition, RecognitionCandidateV1,
            RecognitionProjectionV1, RegionCorrectionV1, StrokeViewFrame,
        },
    };
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    static NEXT_PUBLISH_TEST_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn published_set_cap_is_16_mib_and_counts_the_png_asset_once() {
        assert_eq!(MAX_EXPORT_BUNDLE_BYTES, 16 * 1024 * 1024);
        let formats = ExportFormats {
            markdown: false,
            html: false,
            docx: true,
            pdf: false,
        };
        assert_eq!(
            checked_published_set_bytes(formats, None, None, Some(b"docx"), None, b"png-bytes",),
            Ok(b"docx".len() + b"png-bytes".len())
        );
    }

    struct ExportJournalFixture {
        directory: PathBuf,
        writer: Option<JournalWriter>,
        target: StrokeRef,
        other_target: StrokeRef,
        projection_id: String,
        binding: ProjectionInkBindingV1,
    }

    struct InkOnlyJournalFixture {
        directory: PathBuf,
        writer: Option<JournalWriter>,
        target: StrokeRef,
    }

    impl Drop for ExportJournalFixture {
        fn drop(&mut self) {
            drop(self.writer.take());
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    impl Drop for InkOnlyJournalFixture {
        fn drop(&mut self) {
            drop(self.writer.take());
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn fixture_sample(
        target: &StrokeRef,
        source_sequence: u64,
        app_arrival_elapsed_ns: u128,
        x_raw: i64,
        y_raw: i64,
    ) -> PhysicalSample {
        PhysicalSample {
            session_id: target.session_id.clone(),
            source_api: target.source_api.clone(),
            source_device_id: target.device_id.clone(),
            pointer_id: target.pointer_id,
            stroke_id: Some(target.stroke_id.clone()),
            source_sequence,
            config_id: Some("export-fixture-config".to_owned()),
            app_arrival_elapsed_ns,
            position: Some(RawPosition {
                coordinate_space: "windows-screen-coordinates".to_owned(),
                units: "screen-pixel".to_owned(),
                x_raw,
                y_raw,
            }),
            pressure: None,
            native_timestamp: None,
            contact_range_state: Some("contact".to_owned()),
            button_state_raw: None,
            tilt_x_raw: None,
            tilt_y_raw: None,
            rotation_raw: None,
            raw_payload: vec![0xE1],
        }
    }

    impl InkOnlyJournalFixture {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "lassoink-export-ink-only-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create ink-only export fixture directory");
            let journal_id = format!("ink-only-export-project-{id}");
            let session_id = format!("ink-only-export-session-{id}");
            let target = StrokeRef {
                journal_id: journal_id.clone(),
                session_id: session_id.clone(),
                source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
                device_id: Some("ink-only-export-device".to_owned()),
                pointer_id: Some(1),
                stroke_id: format!("ink-only-export-stroke-{id}"),
            };
            let mut writer = JournalWriter::create(
                directory.join("source.inkj"),
                JournalHeader {
                    journal_id,
                    session_id,
                    config_id: Some("export-fixture-config".to_owned()),
                    device_model_declared: None,
                    tilt_supported_declared: Some(false),
                },
            )
            .expect("create ink-only export journal");
            writer
                .start_stroke(target.clone(), StrokeViewFrame::default(), 1)
                .expect("start ink-only source stroke");
            writer
                .append_sample(fixture_sample(&target, 1, 2, 35, 48))
                .expect("append ink-only source sample");
            writer
                .commit_stroke(target.clone(), 3)
                .expect("commit ink-only source stroke");
            Self {
                directory,
                writer: Some(writer),
                target,
            }
        }

        fn state(&self) -> JournalReplayState {
            self.writer.as_ref().unwrap().replay_state().clone()
        }
    }

    impl ExportJournalFixture {
        fn new(provider_text: Option<&str>) -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "lassoink-export-fixture-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create isolated export journal directory");
            let journal_id = format!("export-fixture-project-{id}");
            let session_id = format!("export-fixture-session-{id}");
            let target = StrokeRef {
                journal_id: journal_id.clone(),
                session_id: session_id.clone(),
                source_api: PROVISIONAL_DIRECT_SOURCE_API.to_owned(),
                device_id: Some("export-fixture-device".to_owned()),
                pointer_id: Some(1),
                stroke_id: format!("export-fixture-stroke-{id}"),
            };
            let other_target = StrokeRef {
                journal_id: journal_id.clone(),
                session_id: target.session_id.clone(),
                source_api: target.source_api.clone(),
                device_id: Some("export-fixture-device-2".to_owned()),
                pointer_id: Some(2),
                stroke_id: format!("export-fixture-other-stroke-{id}"),
            };
            let frame = StrokeViewFrame::default();
            let mut writer = JournalWriter::create(
                directory.join("source.inkj"),
                JournalHeader {
                    journal_id: journal_id.clone(),
                    session_id,
                    config_id: Some("export-fixture-config".to_owned()),
                    device_model_declared: None,
                    tilt_supported_declared: Some(false),
                },
            )
            .expect("create bounded export fixture journal");
            writer
                .start_stroke(target.clone(), frame, 1)
                .expect("append fixture stroke start");
            let first_sample_sequence = writer
                .append_sample(fixture_sample(&target, 1, 2, 40, 50))
                .expect("append first fixture sample");
            let last_sample_sequence = writer
                .append_sample(fixture_sample(&target, 2, 3, 64, 74))
                .expect("append second fixture sample");
            writer
                .commit_stroke(target.clone(), 4)
                .expect("commit fixture stroke");
            writer
                .start_stroke(other_target.clone(), frame, 5)
                .expect("append other fixture stroke start");
            writer
                .append_sample(fixture_sample(&other_target, 1, 6, 120, 140))
                .expect("append other fixture sample");
            writer
                .commit_stroke(other_target.clone(), 7)
                .expect("commit other fixture stroke");
            let source_state = writer.replay_state().clone();
            let projection_id = format!("export-fixture-projection-{id}");
            let binding = ProjectionInkBindingV1 {
                journal_id,
                logical_revision: source_state.logical_revision,
                last_sequence: source_state.last_sequence,
                region_id: format!("export-fixture-region-{id}"),
                line_id: Some("export-fixture-line".to_owned()),
                input_view_id: "input-view-v1-0000000000000001".to_owned(),
                ink_binding_sha256: "a".repeat(64),
                selected_strokes: vec![target.clone()],
                source_sample_sequences: vec![first_sample_sequence, last_sample_sequence],
                stroke_views: vec![ProjectionStrokeViewV1 {
                    stroke: target.clone(),
                    frame,
                }],
            };
            let candidates = provider_text.map_or_else(Vec::new, |text| {
                vec![RecognitionCandidateV1 {
                    rank: 0,
                    recognized_text: text.to_owned(),
                    native_score_raw: None,
                    stroke_ranges: vec![ProjectionStrokeRangeV1 {
                        stroke: target.clone(),
                        first_journal_sequence: first_sample_sequence,
                        last_journal_sequence: last_sample_sequence,
                    }],
                }]
            });
            writer
                .append_recognition_projection_record(
                    RecognitionProjectionV1 {
                        projection_id: projection_id.clone(),
                        ink: binding.clone(),
                        provider: ProjectionProviderProvenanceV1 {
                            provider_id: "export-fixture-provider".to_owned(),
                            provider_version: "fixture-v1".to_owned(),
                            model_version: None,
                            resource_version: Some("fixture-resource-v1".to_owned()),
                            configuration_id: "export-fixture-config".to_owned(),
                            configuration_fingerprint: "provider-config-v1-fnv64-0000000000000001"
                                .to_owned(),
                        },
                        candidates,
                        input_modalities: None,
                        generated_raster: None,
                    },
                    8,
                )
                .expect("append fixture projection");
            Self {
                directory,
                writer: Some(writer),
                target,
                other_target,
                projection_id,
                binding,
            }
        }

        fn state(&self) -> JournalReplayState {
            self.writer.as_ref().unwrap().replay_state().clone()
        }

        fn append_correction(&mut self, action: RegionCorrectionActionV1) {
            self.writer
                .as_mut()
                .unwrap()
                .append_region_correction_record(
                    RegionCorrectionV1 {
                        correction_id: "export-fixture-correction".to_owned(),
                        projection_id: self.projection_id.clone(),
                        ink: self.binding.clone(),
                        action,
                    },
                    9,
                )
                .expect("append fixture correction");
        }
    }

    fn render_fixture_ink_png(
        state: &JournalReplayState,
        selected_strokes: &[StrokeRef],
    ) -> (Vec<u8>, [u8; 32]) {
        let plan = build_canonical_raster_projection_plan(state, selected_strokes).unwrap();
        let canonical_order = plan.journal_first_occurrence_stroke_order().unwrap();
        assert_eq!(canonical_order.as_slice(), selected_strokes);
        let spec = CanonicalRasterProjectionSpecV1::new(
            CONVERT_RASTER_WIDTH_PX,
            CONVERT_RASTER_HEIGHT_PX,
            plan.source_crop_with_padding(CONVERT_RASTER_SOURCE_PADDING_PX)
                .unwrap(),
        );
        let geometry = transform_canonical_raster_geometry(&plan, &spec).unwrap();
        let image = render_canonical_raster(&geometry).unwrap();
        (image.png_bytes().to_vec(), image.projection_spec_sha256())
    }

    fn region(origin: TranscriptOriginV1, text: Option<&str>) -> ExportRegionV1 {
        ExportRegionV1 {
            schema_version: EXPORT_SCHEMA_VERSION,
            transcript_origin: origin,
            paragraph: text.map(|text| paragraph_from_text(text).unwrap()),
            raw_ink_fallback: RawInkFallbackV1 {
                asset_file_name: INK_ASSET_FILE_NAME,
                alt_text: INK_ASSET_ALT_TEXT,
            },
            provenance: test_provenance(),
        }
    }

    fn test_provenance() -> ExportProvenanceV1 {
        let source_binding = ExportSourceBindingV1::InkOnly {
            journal_id: "export-test-journal".to_owned(),
            logical_revision: 1,
            snapshot_last_sequence: 1,
            selected_strokes: Vec::new(),
            source_sample_sequences: Vec::new(),
            stroke_views: Vec::new(),
        };
        ExportProvenanceV1 {
            source_binding_sha256: hash_source_binding(&source_binding).unwrap(),
            source_binding,
            projection: None,
            raster: ExportRasterProvenanceV1 {
                output_width_px: CONVERT_RASTER_WIDTH_PX,
                output_height_px: CONVERT_RASTER_HEIGHT_PX,
                source_content_sha256: "0".repeat(64),
                projection_spec_sha256: "1".repeat(64),
                png_bytes_sha256: "2".repeat(64),
                raster_artifact_sha256: "3".repeat(64),
            },
        }
    }

    #[test]
    fn transcript_states_keep_absence_provider_empty_user_empty_and_reset_distinct() {
        let ink_only = region(TranscriptOriginV1::InkOnly, None);
        let absent = region(TranscriptOriginV1::NoProviderCandidate, None);
        let provider_empty = region(TranscriptOriginV1::Provider, Some(""));
        let user_empty = region(TranscriptOriginV1::SetText, Some(""));
        let reset = region(TranscriptOriginV1::Reset, Some("provider base"));

        assert!(ink_only.paragraph.is_none());
        assert_eq!(
            transcript_state_label(&ink_only),
            "No stored transcript is attached; this is an ink-only export."
        );
        assert!(absent.paragraph.is_none());
        assert!(provider_empty.paragraph.is_some());
        assert!(user_empty.paragraph.is_some());
        assert_eq!(
            provider_empty.transcript_origin,
            TranscriptOriginV1::Provider
        );
        assert_eq!(user_empty.transcript_origin, TranscriptOriginV1::SetText);
        assert_eq!(reset.transcript_origin, TranscriptOriginV1::Reset);
        assert_ne!(provider_empty, user_empty);
        assert_eq!(absent.raw_ink_fallback.asset_file_name, INK_ASSET_FILE_NAME);
    }

    #[test]
    fn markdown_and_html_escape_multiline_unicode_and_markup_as_plain_text() {
        let text = "NFD e\u{301}\nhello\n===\n<script>alert(1)</script>\n[remote](https://example.invalid)\n&\"'";
        let region = region(TranscriptOriginV1::SetText, Some(text));
        let markdown = String::from_utf8(render_markdown(&region).unwrap()).unwrap();
        let html = String::from_utf8(render_html(&region).unwrap()).unwrap();

        assert!(markdown.contains("NFD e\u{301}"));
        assert!(markdown.contains("  \n"));
        assert!(markdown.contains("hello  \n\\=\\=\\="));
        assert!(markdown.contains("\\<script\\>"));
        assert!(!markdown.contains("<script>"));
        assert!(markdown.contains("\\&\\\"\\'"));
        assert!(!markdown.contains("[remote](https://example.invalid)"));
        assert!(html.contains("NFD e\u{301}"));
        assert!(html.contains("<br>\n"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&amp;&quot;&#39;"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<a href="));
        assert!(markdown.contains("assets/selected-region.png"));
        assert!(markdown.contains("Selection binding SHA-256"));
        assert!(html.contains("src=\"assets/selected-region.png\""));
        assert!(html.contains("Export PNG SHA-256"));
        assert!(!html.contains("https://example.invalid\""));
    }

    #[test]
    fn provenance_serializers_hash_pathlike_identities_and_versions() {
        let mut region = region(TranscriptOriginV1::Provider, Some("safe text"));
        region.provenance.projection = Some(ExportProjectionIdentityV1 {
            projection_id: r"C:\private\projection".to_owned(),
            correction_id: Some(r"C:\private\correction".to_owned()),
            provider_id: r"C:\private\provider-config".to_owned(),
            provider_version: r"C:\private\provider.exe".to_owned(),
            model_version: Some("models/SenOCR".to_owned()),
            resource_version: Some(r"C:\private\resource-version".to_owned()),
            configuration_fingerprint: r"C:\private\configuration-fingerprint".to_owned(),
        });
        let markdown = String::from_utf8(render_markdown(&region).unwrap()).unwrap();
        let html = String::from_utf8(render_html(&region).unwrap()).unwrap();

        for pathlike_identity in [
            r"C:\private\projection",
            r"C:\private\correction",
            r"C:\private\provider-config",
            r"C:\private\provider.exe",
            r"C:\private\resource-version",
            r"C:\private\configuration-fingerprint",
            "models/SenOCR",
        ] {
            assert!(!markdown.contains(pathlike_identity));
            assert!(!html.contains(pathlike_identity));
        }
        assert!(markdown.contains("Projection identity SHA-256"));
        assert!(markdown.contains("Correction identity SHA-256"));
        assert!(markdown.contains("Provider identity SHA-256"));
        assert!(markdown.contains("Provider version SHA-256"));
        assert!(markdown.contains("Model version SHA-256"));
        assert!(markdown.contains("Resource version SHA-256"));
        assert!(markdown.contains("Provider configuration fingerprint SHA-256"));
        assert!(!markdown.contains("configuration-fingerprint"));
        assert!(!html.contains("configuration-fingerprint"));

        let mut absent_resource_region = region.clone();
        absent_resource_region
            .provenance
            .projection
            .as_mut()
            .unwrap()
            .resource_version = None;
        let absent_resource_markdown =
            String::from_utf8(render_markdown(&absent_resource_region).unwrap()).unwrap();
        let absent_resource_html =
            String::from_utf8(render_html(&absent_resource_region).unwrap()).unwrap();
        assert!(!absent_resource_markdown.contains("Resource version"));
        assert!(!absent_resource_html.contains("Resource version"));
    }

    #[test]
    fn export_snapshot_keeps_provider_empty_user_empty_reset_and_absent_distinct() {
        let provider_empty = ExportJournalFixture::new(Some(""));
        let provider_empty_bundle = build_selected_region_bundle(
            &provider_empty.state(),
            &provider_empty.projection_id,
            &provider_empty.binding,
            std::slice::from_ref(&provider_empty.target),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            provider_empty_bundle.region.transcript_origin,
            TranscriptOriginV1::Provider
        );
        assert!(provider_empty_bundle.region.paragraph.is_some());
        assert!(
            provider_empty_bundle
                .selected_ink_png
                .starts_with(b"\x89PNG\r\n\x1a\n")
        );

        let mut user_empty = ExportJournalFixture::new(Some("provider base"));
        user_empty.append_correction(RegionCorrectionActionV1::SetText(String::new()));
        let user_empty_bundle = build_selected_region_bundle(
            &user_empty.state(),
            &user_empty.projection_id,
            &user_empty.binding,
            std::slice::from_ref(&user_empty.target),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            user_empty_bundle.region.transcript_origin,
            TranscriptOriginV1::SetText
        );
        let projection_provenance = user_empty_bundle
            .region
            .provenance
            .projection
            .as_ref()
            .unwrap();
        assert_eq!(
            projection_provenance.projection_id.as_str(),
            user_empty.projection_id.as_str()
        );
        assert_eq!(
            projection_provenance.correction_id.as_deref(),
            Some("export-fixture-correction")
        );
        assert_eq!(
            projection_provenance.provider_id.as_str(),
            "export-fixture-provider"
        );
        assert_eq!(
            projection_provenance.provider_version.as_str(),
            "fixture-v1"
        );
        assert_eq!(
            projection_provenance.resource_version.as_deref(),
            Some("fixture-resource-v1")
        );
        assert_eq!(
            projection_provenance.configuration_fingerprint.as_str(),
            "provider-config-v1-fnv64-0000000000000001"
        );
        assert!(user_empty_bundle.region.paragraph.is_some());
        assert!(
            user_empty_bundle
                .selected_ink_png
                .starts_with(b"\x89PNG\r\n\x1a\n")
        );
        assert_ne!(provider_empty_bundle.region, user_empty_bundle.region);

        let mut reset = ExportJournalFixture::new(Some("provider base"));
        reset.append_correction(RegionCorrectionActionV1::Reset);
        let reset_bundle = build_selected_region_bundle(
            &reset.state(),
            &reset.projection_id,
            &reset.binding,
            std::slice::from_ref(&reset.target),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            reset_bundle.region.transcript_origin,
            TranscriptOriginV1::Reset
        );
        assert_eq!(
            reset_bundle.region.paragraph.as_ref().unwrap().lines[0].runs[0].text,
            "provider base"
        );
        assert!(
            reset_bundle
                .selected_ink_png
                .starts_with(b"\x89PNG\r\n\x1a\n")
        );

        let mut reset_empty = ExportJournalFixture::new(Some(""));
        reset_empty.append_correction(RegionCorrectionActionV1::Reset);
        let reset_empty_bundle = build_selected_region_bundle(
            &reset_empty.state(),
            &reset_empty.projection_id,
            &reset_empty.binding,
            std::slice::from_ref(&reset_empty.target),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            reset_empty_bundle.region.transcript_origin,
            TranscriptOriginV1::Reset
        );
        assert_eq!(
            reset_empty_bundle.region.paragraph.as_ref().unwrap().lines[0].runs[0].text,
            ""
        );
        assert!(
            reset_empty_bundle
                .selected_ink_png
                .starts_with(b"\x89PNG\r\n\x1a\n")
        );

        let absent = ExportJournalFixture::new(None);
        let absent_bundle = build_selected_region_bundle(
            &absent.state(),
            &absent.projection_id,
            &absent.binding,
            std::slice::from_ref(&absent.target),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            absent_bundle.region.transcript_origin,
            TranscriptOriginV1::NoProviderCandidate
        );
        assert!(absent_bundle.region.paragraph.is_none());
        let absent_markdown = String::from_utf8(absent_bundle.markdown.unwrap()).unwrap();
        assert!(absent_markdown.contains("No provider transcript is available."));
        assert!(absent_markdown.contains("assets/selected-region.png"));
        assert!(
            absent_bundle
                .selected_ink_png
                .starts_with(b"\x89PNG\r\n\x1a\n")
        );
    }

    #[test]
    fn ink_only_export_without_projection_uses_snapshot_binding_and_no_provider_identity() {
        let fixture = InkOnlyJournalFixture::new();
        let state = fixture.state();
        assert!(state.recognition_projections.is_empty());
        let bundle = build_ink_only_bundle(
            &state,
            std::slice::from_ref(&fixture.target),
            &AtomicBool::new(false),
        )
        .unwrap();

        assert_eq!(bundle.region.transcript_origin, TranscriptOriginV1::InkOnly);
        assert!(bundle.region.paragraph.is_none());
        assert!(bundle.region.provenance.projection.is_none());
        assert_eq!(bundle.region.provenance.source_binding_sha256.len(), 64);
        assert!(bundle.selected_ink_png.starts_with(b"\x89PNG\r\n\x1a\n"));
        let (expected_png, expected_spec_sha256) =
            render_fixture_ink_png(&state, std::slice::from_ref(&fixture.target));
        assert_eq!(bundle.selected_ink_png, expected_png);
        assert_eq!(
            bundle.region.provenance.raster.projection_spec_sha256,
            hex_sha256(&expected_spec_sha256).unwrap()
        );
        match &bundle.region.provenance.source_binding {
            ExportSourceBindingV1::InkOnly {
                journal_id,
                logical_revision,
                snapshot_last_sequence,
                selected_strokes,
                source_sample_sequences,
                ..
            } => {
                assert_eq!(journal_id, &state.journal_id);
                assert_eq!(*logical_revision, state.logical_revision);
                assert_eq!(*snapshot_last_sequence, state.last_sequence);
                assert_eq!(
                    selected_strokes.as_slice(),
                    std::slice::from_ref(&fixture.target)
                );
                assert_eq!(source_sample_sequences.len(), 1);
            }
            ExportSourceBindingV1::Projection { .. } => {
                panic!("ink-only export fabricated a projection binding")
            }
        }
        let markdown = String::from_utf8(bundle.markdown.unwrap()).unwrap();
        assert!(markdown.contains("ink-only export"));
        assert!(markdown.contains("Binding kind: ink only"));
        assert!(!markdown.contains("Projection identity SHA-256"));
        assert!(!markdown.contains("Provider identity SHA-256"));
    }

    #[test]
    fn export_revalidates_exact_selection_and_allows_derived_rows_after_source_prefix() {
        let mut fixture = ExportJournalFixture::new(Some("source text"));
        let state_before_correction = fixture.state();
        let mut wrong_project = state_before_correction.clone();
        wrong_project.logical_revision = wrong_project.logical_revision.saturating_add(1);
        assert_eq!(
            build_selected_region_bundle(
                &wrong_project,
                &fixture.projection_id,
                &fixture.binding,
                std::slice::from_ref(&fixture.target),
                &AtomicBool::new(false),
            )
            .unwrap_err(),
            ExportError::StaleSource
        );
        assert_eq!(
            build_selected_region_bundle(
                &state_before_correction,
                &fixture.projection_id,
                &fixture.binding,
                &[],
                &AtomicBool::new(false),
            )
            .unwrap_err(),
            ExportError::InvalidSelection
        );
        let changed_selection = StrokeRef {
            stroke_id: "different-selected-stroke".to_owned(),
            ..fixture.target.clone()
        };
        assert_eq!(
            build_selected_region_bundle(
                &state_before_correction,
                &fixture.projection_id,
                &fixture.binding,
                std::slice::from_ref(&changed_selection),
                &AtomicBool::new(false),
            )
            .unwrap_err(),
            ExportError::InvalidSelection
        );
        assert_eq!(
            build_ink_only_bundle(
                &state_before_correction,
                std::slice::from_ref(&fixture.target),
                &AtomicBool::new(false),
            )
            .unwrap_err(),
            ExportError::StaleSource
        );

        let mut moved_source = ExportJournalFixture::new(Some("source text"));
        moved_source
            .writer
            .as_mut()
            .unwrap()
            .move_stroke(
                9,
                moved_source.target.clone(),
                12,
                0,
                "windows-screen-coordinates".to_owned(),
                "screen-pixel".to_owned(),
            )
            .unwrap();
        let moved_state = moved_source.state();
        assert!(moved_state.last_sequence > moved_source.binding.last_sequence);
        assert_eq!(
            build_selected_region_bundle(
                &moved_state,
                &moved_source.projection_id,
                &moved_source.binding,
                std::slice::from_ref(&moved_source.target),
                &AtomicBool::new(false),
            )
            .unwrap_err(),
            ExportError::StaleSource
        );
        assert_eq!(
            build_ink_only_bundle(
                &moved_state,
                std::slice::from_ref(&moved_source.target),
                &AtomicBool::new(false),
            )
            .unwrap_err(),
            ExportError::StaleSource
        );

        fixture.append_correction(RegionCorrectionActionV1::SetText("saved edit".to_owned()));
        let after_derived_correction = fixture.state();
        assert!(after_derived_correction.last_sequence > fixture.binding.last_sequence);
        let bundle = build_selected_region_bundle(
            &after_derived_correction,
            &fixture.projection_id,
            &fixture.binding,
            std::slice::from_ref(&fixture.target),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(bundle.region.transcript_origin, TranscriptOriginV1::SetText);
        assert_eq!(
            bundle.region.paragraph.as_ref().unwrap().lines[0].runs[0].text,
            "saved edit"
        );
    }

    #[test]
    fn canceled_or_over_limit_exports_do_not_build_or_publish_partial_content() {
        let fixture = ExportJournalFixture::new(Some("source text"));
        assert_eq!(
            build_selected_region_bundle(
                &fixture.state(),
                &fixture.projection_id,
                &fixture.binding,
                std::slice::from_ref(&fixture.target),
                &AtomicBool::new(true),
            )
            .unwrap_err(),
            ExportError::Cancelled
        );

        let oversized = region(
            TranscriptOriginV1::SetText,
            Some(&"x".repeat(MAX_EXPORT_DOCUMENT_BYTES)),
        );
        assert_eq!(
            render_markdown(&oversized).unwrap_err(),
            ExportError::OutputTooLarge
        );
    }

    #[test]
    fn selected_region_export_preserves_source_text_and_original_ink_asset() {
        let fixture = ExportJournalFixture::new(Some("NFD e\u{301}\nsecond line"));
        let state = fixture.state();
        let bundle = build_selected_region_bundle(
            &state,
            &fixture.projection_id,
            &fixture.binding,
            std::slice::from_ref(&fixture.target),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            bundle.region.transcript_origin,
            TranscriptOriginV1::Provider
        );
        let paragraph = bundle.region.paragraph.as_ref().unwrap();
        assert_eq!(paragraph.lines.len(), 2);
        assert_eq!(paragraph.lines[0].runs[0].text, "NFD e\u{301}");
        assert_eq!(paragraph.lines[1].runs[0].text, "second line");
        match &bundle.region.provenance.source_binding {
            ExportSourceBindingV1::Projection {
                snapshot_last_sequence,
                binding,
            } => {
                assert_eq!(binding, &fixture.binding);
                assert_eq!(*snapshot_last_sequence, state.last_sequence);
            }
            ExportSourceBindingV1::InkOnly { .. } => {
                panic!("projection export lost its stored source binding")
            }
        }
        assert_eq!(
            bundle.region.raw_ink_fallback.asset_file_name,
            INK_ASSET_FILE_NAME
        );
        assert!(bundle.selected_ink_png.starts_with(b"\x89PNG\r\n\x1a\n"));
        let (bound_source_png, bound_source_spec_sha256) =
            render_fixture_ink_png(&state, std::slice::from_ref(&fixture.target));
        let (other_source_png, _) =
            render_fixture_ink_png(&state, std::slice::from_ref(&fixture.other_target));
        assert_eq!(bundle.selected_ink_png, bound_source_png);
        assert_ne!(bundle.selected_ink_png, other_source_png);
        assert!(
            String::from_utf8(bundle.markdown.as_ref().unwrap().clone())
                .unwrap()
                .contains("NFD e\u{301}")
        );
        assert!(
            String::from_utf8(bundle.html.as_ref().unwrap().clone())
                .unwrap()
                .contains("NFD e\u{301}")
        );
        let markdown = String::from_utf8(bundle.markdown.as_ref().unwrap().clone()).unwrap();
        let html = String::from_utf8(bundle.html.as_ref().unwrap().clone()).unwrap();
        assert!(markdown.contains("Projection identity SHA-256"));
        assert!(!markdown.contains(fixture.projection_id.as_str()));
        assert!(markdown.contains("Provider identity SHA-256"));
        assert!(!markdown.contains("export-fixture-provider"));
        assert!(html.contains("fixture-v1"));
        assert!(html.contains("fixture-resource-v1"));
        assert!(html.contains("Provider configuration fingerprint SHA-256"));
        assert!(!html.contains("provider-config-v1-fnv64-0000000000000001"));
        assert!(!markdown.contains("export-fixture-device"));
        assert!(!markdown.contains(PROVISIONAL_DIRECT_SOURCE_API));
        assert!(!html.contains("export-fixture-device"));
        assert!(!html.contains(fixture.binding.journal_id.as_str()));
        let png_digest: [u8; 32] = Sha256::digest(&bundle.selected_ink_png).into();
        assert_eq!(
            bundle.region.provenance.raster.png_bytes_sha256,
            hex_sha256(&png_digest).unwrap()
        );
        assert_eq!(
            bundle.region.provenance.raster.projection_spec_sha256,
            hex_sha256(&bound_source_spec_sha256).unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn wide_path_rejects_embedded_nul_before_win32_call() {
        assert_eq!(
            wide_path(Path::new("C:\\export\0bundle")),
            Err(ExportError::InvalidTarget)
        );
    }

    #[cfg(windows)]
    #[test]
    fn selected_docx_and_pdf_are_published_as_one_durable_no_clobber_set() {
        let fixture = ExportJournalFixture::new(Some("NFD e\u{301}\nsecond line"));
        let formats = ExportFormats {
            markdown: true,
            html: true,
            docx: true,
            pdf: true,
        };
        let bundle = build_selected_region_bundle_with_formats(
            &fixture.state(),
            &fixture.projection_id,
            &fixture.binding,
            std::slice::from_ref(&fixture.target),
            formats,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(bundle.formats, formats);
        assert!(bundle.docx.is_some());
        assert!(bundle.pdf.is_some());

        let parent = std::env::temp_dir().join(format!(
            "lassoink-all-format-publish-{}-{}",
            std::process::id(),
            NEXT_PUBLISH_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&parent).unwrap();
        let target = parent.join("complete-set");
        publish_export_bundle(&target, &bundle, 20, &AtomicBool::new(false)).unwrap();
        assert!(target.join(MARKDOWN_FILE_NAME).is_file());
        assert!(target.join(HTML_FILE_NAME).is_file());
        assert!(target.join(DOCX_FILE_NAME).is_file());
        assert!(target.join(PDF_FILE_NAME).is_file());
        assert!(target.join(INK_ASSET_FILE_NAME).is_file());
        assert!(
            fs::read(target.join(DOCX_FILE_NAME))
                .unwrap()
                .starts_with(b"PK\x03\x04")
        );
        assert!(
            fs::read(target.join(PDF_FILE_NAME))
                .unwrap()
                .starts_with(b"%PDF-")
        );

        let collision = parent.join("existing-set");
        fs::create_dir(&collision).unwrap();
        fs::write(collision.join("sentinel.txt"), b"preserve me").unwrap();
        assert_eq!(
            publish_export_bundle(&collision, &bundle, 21, &AtomicBool::new(false)),
            Err(ExportError::DestinationExists)
        );
        assert_eq!(
            fs::read(collision.join("sentinel.txt")).unwrap(),
            b"preserve me"
        );

        let canceled = parent.join("canceled-set");
        let cancellation = AtomicBool::new(false);
        assert_eq!(
            publish_export_bundle_with_hooks(
                &canceled,
                &bundle,
                22,
                &cancellation,
                |file| file.sync_all(),
                |_| {
                    cancellation.store(true, Ordering::Release);
                    Ok(())
                },
            ),
            Err(ExportError::Cancelled)
        );
        assert!(!canceled.exists());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 2);
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn single_docx_publication_includes_the_exact_selected_png_asset() {
        let fixture = ExportJournalFixture::new(Some("single format fixture"));
        let formats = ExportFormats {
            markdown: false,
            html: false,
            docx: true,
            pdf: false,
        };
        let bundle = build_selected_region_bundle_with_formats(
            &fixture.state(),
            &fixture.projection_id,
            &fixture.binding,
            std::slice::from_ref(&fixture.target),
            formats,
            &AtomicBool::new(false),
        )
        .unwrap();
        let selected_png = bundle.selected_ink_png.clone();
        let parent = std::env::temp_dir().join(format!(
            "lassoink-docx-only-publish-{}-{}",
            std::process::id(),
            NEXT_PUBLISH_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&parent).unwrap();
        let target = parent.join("docx-only");

        publish_export_bundle(&target, &bundle, 23, &AtomicBool::new(false)).unwrap();

        assert!(target.join(DOCX_FILE_NAME).is_file());
        assert_eq!(
            fs::read(target.join(INK_ASSET_FILE_NAME)).unwrap(),
            selected_png
        );
        assert!(!target.join(MARKDOWN_FILE_NAME).exists());
        assert!(!target.join(HTML_FILE_NAME).exists());
        assert!(!target.join(PDF_FILE_NAME).exists());
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(all(test, windows))]
    #[test]
    #[ignore = "guarded hosted Windows export bundle publication and cleanup"]
    fn guarded_export_publication_syncs_owned_files_and_preserves_existing_destination() {
        crate::require_native_ui_test_opt_in();
        let fixture = ExportJournalFixture::new(Some("bounded export fixture"));
        let bundle = build_selected_region_bundle(
            &fixture.state(),
            &fixture.projection_id,
            &fixture.binding,
            std::slice::from_ref(&fixture.target),
            &AtomicBool::new(false),
        )
        .unwrap();
        let parent = std::env::temp_dir().join(format!(
            "lassoink-export-publish-{}-{}",
            std::process::id(),
            NEXT_PUBLISH_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&parent).unwrap();
        let mut incomplete_bundle = build_selected_region_bundle(
            &fixture.state(),
            &fixture.projection_id,
            &fixture.binding,
            std::slice::from_ref(&fixture.target),
            &AtomicBool::new(false),
        )
        .unwrap();
        incomplete_bundle.formats.docx = true;
        let missing_output_target = parent.join("missing-output-set");
        assert_eq!(
            publish_export_bundle(
                &missing_output_target,
                &incomplete_bundle,
                19,
                &AtomicBool::new(false),
            ),
            Err(ExportError::IncompleteOutputSet)
        );
        assert!(!missing_output_target.exists());

        let target = parent.join("new-bundle");
        publish_export_bundle(&target, &bundle, 1, &AtomicBool::new(false)).unwrap();
        let markdown = fs::read(target.join(MARKDOWN_FILE_NAME)).unwrap();
        let html = fs::read(target.join(HTML_FILE_NAME)).unwrap();
        let png = fs::read(target.join(INK_ASSET_FILE_NAME)).unwrap();
        assert!(
            String::from_utf8(markdown)
                .unwrap()
                .contains("bounded export fixture")
        );
        assert!(html.windows(8).any(|window| window == b"<figure>"));
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));

        let occupied = parent.join("occupied-bundle");
        fs::create_dir(&occupied).unwrap();
        fs::write(occupied.join("sentinel.txt"), b"preserve me").unwrap();
        assert_eq!(
            publish_export_bundle(&occupied, &bundle, 2, &AtomicBool::new(false)),
            Err(ExportError::DestinationExists)
        );
        assert_eq!(
            fs::read(occupied.join("sentinel.txt")).unwrap(),
            b"preserve me"
        );

        let cleanup_target = parent.join("cleanup-bundle");
        let stage = OwnedStagingDirectory::create(&cleanup_target, 4).unwrap();
        let stage_path = stage.path.clone();
        write_create_new(&stage_path.join("partial.txt"), b"owned partial").unwrap();
        drop(stage);
        assert!(!stage_path.exists());
        assert!(!cleanup_target.exists());
        assert_eq!(
            fs::read(occupied.join("sentinel.txt")).unwrap(),
            b"preserve me"
        );
        let entries = fs::read_dir(&parent).unwrap().count();
        assert_eq!(
            entries, 2,
            "failed/canceled staging directories are cleaned"
        );

        let canceled_target = parent.join("canceled-bundle");
        assert_eq!(
            publish_export_bundle(&canceled_target, &bundle, 3, &AtomicBool::new(true)),
            Err(ExportError::Cancelled)
        );
        assert!(!canceled_target.exists());

        let sync_failure_target = parent.join("sync-failure-bundle");
        let sync_failure_stage = parent.join(format!(
            ".sync-failure-bundle.lassoink-export-{}-5-0.partial",
            std::process::id()
        ));
        assert_eq!(
            publish_export_bundle_with_hooks(
                &sync_failure_target,
                &bundle,
                5,
                &AtomicBool::new(false),
                |file| {
                    assert!(file.metadata()?.len() > 0);
                    Err(std::io::Error::other("injected sync failure"))
                },
                |_| Ok(()),
            ),
            Err(ExportError::IoFailure)
        );
        assert!(!sync_failure_target.exists());
        assert!(!sync_failure_stage.exists());

        let cancel_after_write_target = parent.join("cancel-after-write-bundle");
        let cancel_after_write_stage = parent.join(format!(
            ".cancel-after-write-bundle.lassoink-export-{}-6-0.partial",
            std::process::id()
        ));
        let cancel_after_write = AtomicBool::new(false);
        assert_eq!(
            publish_export_bundle_with_hooks(
                &cancel_after_write_target,
                &bundle,
                6,
                &cancel_after_write,
                |file| file.sync_all(),
                |_| {
                    cancel_after_write.store(true, Ordering::Release);
                    Ok(())
                },
            ),
            Err(ExportError::Cancelled)
        );
        assert!(!cancel_after_write_target.exists());
        assert!(!cancel_after_write_stage.exists());

        let late_target = parent.join("late-collision-bundle");
        let late_stage = parent.join(format!(
            ".late-collision-bundle.lassoink-export-{}-7-0.partial",
            std::process::id()
        ));
        assert_eq!(
            publish_export_bundle_with_hooks(
                &late_target,
                &bundle,
                7,
                &AtomicBool::new(false),
                |file| file.sync_all(),
                |target| {
                    let staged_markdown = fs::read(late_stage.join(MARKDOWN_FILE_NAME))?;
                    let staged_html = fs::read(late_stage.join(HTML_FILE_NAME))?;
                    let staged_png = fs::read(late_stage.join(INK_ASSET_FILE_NAME))?;
                    assert_eq!(
                        staged_markdown.as_slice(),
                        bundle.markdown.as_ref().unwrap().as_slice()
                    );
                    assert_eq!(
                        staged_html.as_slice(),
                        bundle.html.as_ref().unwrap().as_slice()
                    );
                    assert_eq!(staged_png.as_slice(), bundle.selected_ink_png.as_slice());
                    fs::create_dir(target)?;
                    fs::write(target.join("sentinel.txt"), b"late destination remains")?;
                    Ok(())
                },
            ),
            Err(ExportError::DestinationExists)
        );
        assert!(!late_stage.exists());
        assert_eq!(
            fs::read(late_target.join("sentinel.txt")).unwrap(),
            b"late destination remains"
        );
        fs::remove_dir_all(parent).unwrap();
    }
}
