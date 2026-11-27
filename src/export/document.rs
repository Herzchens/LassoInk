use super::{
    EXPORT_SCHEMA_VERSION, ExportError, ExportProvenanceV1, ExportRegionV1, ExportSourceBindingV1,
    MAX_EXPORT_DOCUMENT_BYTES, MAX_JOURNAL_TEXT_BYTES, is_safe_version_metadata, sha256_text,
    transcript_state_label,
};
use sha2::{Digest, Sha256};

use super::MAX_CANONICAL_RASTER_PNG_BYTES;

const MAX_EXPORT_PROVENANCE_FIELDS: usize = 24;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProvenanceFieldV1 {
    pub label: String,
    pub value: String,
}

pub(super) fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DocumentViewV1 {
    pub state_label: &'static str,
    pub lines: Option<Vec<String>>,
    pub provenance_fields: Vec<ProvenanceFieldV1>,
    pub raster_width_px: u32,
    pub raster_height_px: u32,
}

/// Projects the already-validated semantic IR into the small content surface
/// supported by the DOCX and PDF feasibility serializers. It preserves NFD
/// text and distinguishes `None` from a present empty paragraph.
pub(super) fn project_region(region: &ExportRegionV1) -> Result<DocumentViewV1, ExportError> {
    if region.schema_version != EXPORT_SCHEMA_VERSION {
        return Err(ExportError::StaleSource);
    }

    let lines = if let Some(paragraph) = &region.paragraph {
        if paragraph.lines.len() > MAX_JOURNAL_TEXT_BYTES.saturating_add(1) {
            return Err(ExportError::OutputTooLarge);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(paragraph.lines.len())
            .map_err(|_| ExportError::AllocationFailed)?;
        let mut text_bytes = paragraph.lines.len().saturating_sub(1);
        for line in &paragraph.lines {
            let line_bytes = line
                .runs
                .iter()
                .try_fold(0usize, |total, run| total.checked_add(run.text.len()));
            let line_bytes = line_bytes.ok_or(ExportError::OutputTooLarge)?;
            text_bytes = text_bytes
                .checked_add(line_bytes)
                .ok_or(ExportError::OutputTooLarge)?;
            if text_bytes > MAX_JOURNAL_TEXT_BYTES {
                return Err(ExportError::OutputTooLarge);
            }

            let mut text = String::new();
            text.try_reserve_exact(line_bytes)
                .map_err(|_| ExportError::AllocationFailed)?;
            for run in &line.runs {
                text.push_str(&run.text);
            }
            output.push(text);
        }
        Some(output)
    } else {
        None
    };

    Ok(DocumentViewV1 {
        state_label: transcript_state_label(region),
        lines,
        provenance_fields: safe_provenance_fields(&region.provenance)?,
        raster_width_px: region.provenance.raster.output_width_px,
        raster_height_px: region.provenance.raster.output_height_px,
    })
}

/// Builds the explicit safe provenance allowlist used by both document
/// formats. Raw journal, projection, correction, provider, configuration and
/// filesystem values are either omitted or hashed before they reach a writer.
pub(super) fn safe_provenance_fields(
    provenance: &ExportProvenanceV1,
) -> Result<Vec<ProvenanceFieldV1>, ExportError> {
    let mut fields = Vec::new();
    fields
        .try_reserve_exact(MAX_EXPORT_PROVENANCE_FIELDS)
        .map_err(|_| ExportError::AllocationFailed)?;
    let mut total_bytes = 0usize;

    let mut push = |label: &'static str, value: &str| -> Result<(), ExportError> {
        let next_bytes = total_bytes
            .checked_add(label.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(ExportError::OutputTooLarge)?;
        if next_bytes > MAX_EXPORT_DOCUMENT_BYTES || fields.len() >= MAX_EXPORT_PROVENANCE_FIELDS {
            return Err(ExportError::OutputTooLarge);
        }
        let mut owned_label = String::new();
        owned_label
            .try_reserve_exact(label.len())
            .map_err(|_| ExportError::AllocationFailed)?;
        owned_label.push_str(label);
        let mut owned_value = String::new();
        owned_value
            .try_reserve_exact(value.len())
            .map_err(|_| ExportError::AllocationFailed)?;
        owned_value.push_str(value);
        fields.push(ProvenanceFieldV1 {
            label: owned_label,
            value: owned_value,
        });
        total_bytes = next_bytes;
        Ok(())
    };

    push("Provenance schema", &EXPORT_SCHEMA_VERSION.to_string())?;
    match &provenance.source_binding {
        ExportSourceBindingV1::Projection {
            snapshot_last_sequence,
            binding,
        } => {
            push("Binding kind", "stored projection")?;
            push("Logical revision", &binding.logical_revision.to_string())?;
            push("Snapshot sequence", &snapshot_last_sequence.to_string())?;
            push(
                "Projection source sequence",
                &binding.last_sequence.to_string(),
            )?;
            push("Ink binding SHA-256", &binding.ink_binding_sha256)?;
            push(
                "Selected stroke count",
                &binding.selected_strokes.len().to_string(),
            )?;
            push(
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
            push("Binding kind", "ink only")?;
            push("Logical revision", &logical_revision.to_string())?;
            push("Snapshot sequence", &snapshot_last_sequence.to_string())?;
            push("Selected stroke count", &selected_strokes.len().to_string())?;
            push(
                "Bound source sample count",
                &source_sample_sequences.len().to_string(),
            )?;
        }
    }
    push(
        "Selection binding SHA-256",
        &provenance.source_binding_sha256,
    )?;

    if let Some(projection) = &provenance.projection {
        push(
            "Projection identity SHA-256",
            &sha256_text(&projection.projection_id)?,
        )?;
        if let Some(correction_id) = projection.correction_id.as_deref() {
            push("Correction identity SHA-256", &sha256_text(correction_id)?)?;
        }
        push(
            "Provider identity SHA-256",
            &sha256_text(&projection.provider_id)?,
        )?;
        push_version(
            &mut push,
            "Provider version",
            "Provider version SHA-256",
            &projection.provider_version,
        )?;
        if let Some(model_version) = projection.model_version.as_deref() {
            push_version(
                &mut push,
                "Model version",
                "Model version SHA-256",
                model_version,
            )?;
        }
        if let Some(resource_version) = projection.resource_version.as_deref() {
            push_version(
                &mut push,
                "Resource version",
                "Resource version SHA-256",
                resource_version,
            )?;
        }
        push(
            "Provider configuration fingerprint SHA-256",
            &sha256_text(&projection.configuration_fingerprint)?,
        )?;
    }

    push(
        "Export raster source SHA-256",
        &provenance.raster.source_content_sha256,
    )?;
    push(
        "Export raster spec SHA-256",
        &provenance.raster.projection_spec_sha256,
    )?;
    push("Export PNG SHA-256", &provenance.raster.png_bytes_sha256)?;
    push(
        "Export raster artifact SHA-256",
        &provenance.raster.raster_artifact_sha256,
    )?;
    push(
        "Export PNG dimensions",
        &format!(
            "{} x {}",
            provenance.raster.output_width_px, provenance.raster.output_height_px
        ),
    )?;
    push(
        "Export image note",
        "The selected ink image is an export render, not recognizer input.",
    )?;

    Ok(fields)
}

fn push_version(
    push: &mut impl FnMut(&'static str, &str) -> Result<(), ExportError>,
    label: &'static str,
    hash_label: &'static str,
    value: &str,
) -> Result<(), ExportError> {
    if is_safe_version_metadata(value) {
        push(label, value)
    } else {
        push(hash_label, &sha256_text(value)?)
    }
}

/// XML 1.0 Fifth Edition's Char production. TAB/LF/CR are representable; LF
/// and CR have already been projected into line boundaries by the existing IR.
pub(super) fn validate_docx_text(text: &str) -> Result<(), ExportError> {
    if text.chars().any(|character| {
        let codepoint = character as u32;
        !(matches!(codepoint, 0x09 | 0x0A | 0x0D)
            || (0x20..=0xD7FF).contains(&codepoint)
            || (0xE000..=0xFFFD).contains(&codepoint)
            || (0x10000..=0x10FFFF).contains(&codepoint))
    }) {
        return Err(ExportError::InvalidText);
    }
    Ok(())
}

pub(super) fn validate_docx_view_text(view: &DocumentViewV1) -> Result<(), ExportError> {
    validate_docx_text(view.state_label)?;
    if let Some(lines) = &view.lines {
        for line in lines {
            validate_docx_text(line)?;
        }
    }
    for field in &view.provenance_fields {
        validate_docx_text(&field.label)?;
        validate_docx_text(&field.value)?;
    }
    Ok(())
}

pub(super) fn validate_selected_ink(
    region: &ExportRegionV1,
    selected_ink_png: &[u8],
) -> Result<(), ExportError> {
    if selected_ink_png.is_empty()
        || selected_ink_png.len() > MAX_CANONICAL_RASTER_PNG_BYTES
        || region.provenance.raster.output_width_px == 0
        || region.provenance.raster.output_height_px == 0
        || region.provenance.raster.output_width_px > 2048
        || region.provenance.raster.output_height_px > 2048
        || u64::from(region.provenance.raster.output_width_px)
            .checked_mul(u64::from(region.provenance.raster.output_height_px))
            .is_none_or(|pixels| pixels > 262_144)
    {
        return Err(ExportError::InkUnavailable);
    }
    let digest: [u8; 32] = Sha256::digest(selected_ink_png).into();
    if super::hex_sha256(&digest)? != region.provenance.raster.png_bytes_sha256 {
        return Err(ExportError::StaleSource);
    }
    Ok(())
}
