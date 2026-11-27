use std::io::Cursor;

use docx_rs::{
    BreakType, Docx, LineSpacing, LineSpacingType, PageMargin, Paragraph, Pic, Run, RunFonts,
};

use super::{
    ExportError, ExportRegionV1,
    document::{
        is_sha256_digest, project_region, validate_docx_text, validate_docx_view_text,
        validate_selected_ink,
    },
};

const MAX_DOCX_BYTES: usize = 4 * 1024 * 1024;
const DOCX_PAGE_WIDTH_TWIPS: u32 = 11_906;
const DOCX_PAGE_HEIGHT_TWIPS: u32 = 16_838;
const DOCX_PAGE_MARGIN_TWIPS: i32 = 1_020;
const DOCX_DEFAULT_FONT_HALF_POINTS: usize = 22;
const DOCX_DEFAULT_LINE_SPACING_TWIPS: i32 = 280;
const EMU_PER_PIXEL: u64 = 9_525;
const EMU_PER_TWIP: u64 = 635;
const DOCX_IMAGE_MAX_WIDTH_EMU: u64 = 6_263_000;
const DOCX_IMAGE_MAX_HEIGHT_EMU: u64 = 6_858_000;
const DOCX_FONT_FAMILY: &str = "Noto Sans";

/// Serializes the frozen semantic region as a minimal DOCX package. This
/// feasibility path writes plain text, explicit line breaks, allowlisted
/// provenance, and one internally-related PNG image only.
pub(super) fn serialize_docx(
    region: &ExportRegionV1,
    selected_ink_png: &[u8],
) -> Result<Vec<u8>, ExportError> {
    validate_selected_ink(region, selected_ink_png)?;
    let view = project_region(region)?;
    validate_docx_view_text(&view)?;
    validate_docx_text(region.raw_ink_fallback.alt_text)?;

    let font = RunFonts::new()
        .ascii(DOCX_FONT_FAMILY)
        .hi_ansi(DOCX_FONT_FAMILY)
        .east_asia(DOCX_FONT_FAMILY)
        .cs(DOCX_FONT_FAMILY);
    let mut docx = Docx::new()
        .page_size(DOCX_PAGE_WIDTH_TWIPS, DOCX_PAGE_HEIGHT_TWIPS)
        .page_margin(
            PageMargin::new()
                .top(DOCX_PAGE_MARGIN_TWIPS)
                .right(DOCX_PAGE_MARGIN_TWIPS)
                .bottom(DOCX_PAGE_MARGIN_TWIPS)
                .left(DOCX_PAGE_MARGIN_TWIPS),
        )
        .default_fonts(font)
        .default_size(DOCX_DEFAULT_FONT_HALF_POINTS)
        .default_spacing(0)
        .default_line_spacing(
            LineSpacing::new()
                .line_rule(LineSpacingType::Exact)
                .line(DOCX_DEFAULT_LINE_SPACING_TWIPS),
        )
        .add_paragraph(Paragraph::new().add_run(Run::new().add_text("Selected region")))
        .add_paragraph(Paragraph::new().add_run(Run::new().add_text(view.state_label)));

    if let Some(lines) = &view.lines {
        let mut run = Run::new();
        for (line_index, line) in lines.iter().enumerate() {
            if line_index > 0 {
                run = run.add_break(BreakType::TextWrapping);
            }
            run = append_xml_safe_text(run, line)?;
        }
        docx = docx.add_paragraph(Paragraph::new().add_run(run));
    }

    docx = docx.add_paragraph(Paragraph::new().add_run(Run::new().add_text("Provenance")));
    for field in &view.provenance_fields {
        if is_sha256_digest(&field.value) {
            let mut label_run = Run::new();
            label_run = append_xml_safe_text(label_run, &field.label)?;
            label_run = label_run.add_text(":");
            docx = docx.add_paragraph(Paragraph::new().add_run(label_run));

            let mut value_run = Run::new();
            value_run = append_xml_safe_text(value_run, &field.value)?;
            docx = docx.add_paragraph(Paragraph::new().add_run(value_run));
            continue;
        }
        let mut run = Run::new();
        run = append_xml_safe_text(run, &field.label)?;
        run = run.add_text(": ");
        run = append_xml_safe_text(run, &field.value)?;
        docx = docx.add_paragraph(Paragraph::new().add_run(run));
    }

    docx = docx.add_paragraph(Paragraph::new().add_run(Run::new().add_break(BreakType::Page)));
    docx = docx.add_paragraph(
        Paragraph::new().add_run(Run::new().add_text(region.raw_ink_fallback.alt_text)),
    );
    let (image_width_emu, image_height_emu) =
        fit_image_size_emu(view.raster_width_px, view.raster_height_px)?;
    let mut image_bytes = Vec::new();
    image_bytes
        .try_reserve_exact(selected_ink_png.len())
        .map_err(|_| ExportError::AllocationFailed)?;
    image_bytes.extend_from_slice(selected_ink_png);
    let picture =
        Pic::new_with_dimensions(image_bytes, view.raster_width_px, view.raster_height_px)
            .size(image_width_emu, image_height_emu);
    let image_line_height_twips = u64::from(image_height_emu)
        .checked_add(EMU_PER_TWIP - 1)
        .ok_or(ExportError::OutputTooLarge)?
        / EMU_PER_TWIP;
    let image_line_height_twips =
        i32::try_from(image_line_height_twips).map_err(|_| ExportError::OutputTooLarge)?;
    docx = docx.add_paragraph(
        Paragraph::new()
            .line_spacing(
                LineSpacing::new()
                    .line_rule(LineSpacingType::AtLeast)
                    .line(image_line_height_twips),
            )
            .add_run(Run::new().add_image(picture)),
    );

    let mut output = Cursor::new(Vec::new());
    docx.pack(&mut output).map_err(|_| ExportError::IoFailure)?;
    let bytes = output.into_inner();
    if bytes.is_empty() || bytes.len() > MAX_DOCX_BYTES {
        return Err(ExportError::OutputTooLarge);
    }
    if !bytes.starts_with(b"PK\x03\x04") {
        return Err(ExportError::IoFailure);
    }
    Ok(bytes)
}

fn append_xml_safe_text(mut run: Run, text: &str) -> Result<Run, ExportError> {
    validate_docx_text(text)?;
    let mut start = 0usize;
    for (offset, character) in text.char_indices() {
        if character == '\t' {
            if offset > start {
                run = run.add_text(text[start..offset].to_owned());
            }
            run = run.add_tab();
            start = offset + character.len_utf8();
        }
    }
    if start < text.len() {
        run = run.add_text(text[start..].to_owned());
    }
    Ok(run)
}

fn fit_image_size_emu(width_px: u32, height_px: u32) -> Result<(u32, u32), ExportError> {
    if width_px == 0 || height_px == 0 {
        return Err(ExportError::InkUnavailable);
    }
    let width = u64::from(width_px)
        .checked_mul(EMU_PER_PIXEL)
        .ok_or(ExportError::OutputTooLarge)?;
    let height = u64::from(height_px)
        .checked_mul(EMU_PER_PIXEL)
        .ok_or(ExportError::OutputTooLarge)?;
    let width_at_max_height = width
        .checked_mul(DOCX_IMAGE_MAX_HEIGHT_EMU)
        .ok_or(ExportError::OutputTooLarge)?;
    let height_at_max_width = height
        .checked_mul(DOCX_IMAGE_MAX_WIDTH_EMU)
        .ok_or(ExportError::OutputTooLarge)?;
    let (fitted_width, fitted_height) = if width_at_max_height <= height_at_max_width {
        (
            (width * DOCX_IMAGE_MAX_HEIGHT_EMU / height).min(DOCX_IMAGE_MAX_WIDTH_EMU),
            DOCX_IMAGE_MAX_HEIGHT_EMU,
        )
    } else {
        (
            DOCX_IMAGE_MAX_WIDTH_EMU,
            (height * DOCX_IMAGE_MAX_WIDTH_EMU / width).min(DOCX_IMAGE_MAX_HEIGHT_EMU),
        )
    };
    let fitted_width = u32::try_from(fitted_width).map_err(|_| ExportError::OutputTooLarge)?;
    let fitted_height = u32::try_from(fitted_height).map_err(|_| ExportError::OutputTooLarge)?;
    if fitted_width == 0 || fitted_height == 0 {
        return Err(ExportError::OutputTooLarge);
    }
    Ok((fitted_width, fitted_height))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{TranscriptOriginV1, document_fixtures::synthetic_fixture};
    use crate::journal::MAX_JOURNAL_TEXT_BYTES;

    #[test]
    fn png_geometry_is_aspect_preserving_and_bounded() {
        let (width, height) = fit_image_size_emu(2048, 128).unwrap();
        assert!(u64::from(width) <= DOCX_IMAGE_MAX_WIDTH_EMU);
        assert!(u64::from(height) <= DOCX_IMAGE_MAX_HEIGHT_EMU);
        let width_product = u64::from(width) * 128;
        let height_product = u64::from(height) * 2048;
        assert!(width_product.abs_diff(height_product) <= 2048);
    }

    #[test]
    fn nfd_and_all_logical_line_breaks_remain_in_docx_text() {
        let text = "NFC ấ; NFD a\u{0302}\u{0301}\nsecond line";
        let (region, png) = synthetic_fixture(Some(text), TranscriptOriginV1::Provider);
        assert_eq!(region.transcript_origin, TranscriptOriginV1::Provider);
        let paragraph = region.paragraph.as_ref().unwrap();
        assert_eq!(paragraph.lines.len(), 2);
        assert_eq!(
            paragraph.lines[0].runs[0].text,
            "NFC ấ; NFD a\u{0302}\u{0301}"
        );
        let bytes = serialize_docx(&region, &png).unwrap();
        assert!(bytes.starts_with(b"PK\x03\x04"));
        assert!(bytes.len() <= MAX_DOCX_BYTES);
    }

    #[test]
    fn all_4096_line_feed_bytes_produce_4097_docx_lines() {
        let text = "\n".repeat(MAX_JOURNAL_TEXT_BYTES);
        let (region, png) = synthetic_fixture(Some(&text), TranscriptOriginV1::SetText);
        assert_eq!(region.paragraph.as_ref().unwrap().lines.len(), 4097);
        let bytes = serialize_docx(&region, &png).unwrap();
        assert!(bytes.starts_with(b"PK\x03\x04"));
        assert!(bytes.len() <= MAX_DOCX_BYTES);
    }
}
