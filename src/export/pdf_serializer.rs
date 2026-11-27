use std::collections::BTreeMap;

use printpdf::xobject::DictItem;
use printpdf::{
    LineShaper, Mm, Op, ParsedFont, PdfDocument, PdfPage, PdfSaveOptions, Pt, RawImage, TextMatrix,
    XObjectTransform, show_placed_glyphs,
};
use unicode_segmentation::UnicodeSegmentation;

use super::{
    ExportError, ExportRegionV1,
    document::{DocumentViewV1, is_sha256_digest, project_region, validate_selected_ink},
};
use crate::journal::MAX_JOURNAL_TEXT_BYTES;

const MAX_PDF_BYTES: usize = 8 * 1024 * 1024;
const MAX_PDF_PAGES: usize = 96;
const LINES_PER_PAGE: usize = 52;
const FONT_SIZE: Pt = Pt(11.0);
const LINE_HEIGHT_PT: f32 = 14.0;
const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const PAGE_MARGIN_MM: f32 = 18.0;
const MAX_IMAGE_DPI: f32 = 300.0;
const NOTO_SANS_REGULAR: &[u8] = include_bytes!("../../assets/fonts/NotoSans-Regular.ttf");

struct PdfTextLine {
    text: String,
    append_line_feed: bool,
}

/// Serializes one immutable export region with positioned text-showing
/// operations and the original selected-raster pixels. It deliberately builds
/// only PDF page operations; it does not pass IR text through HTML or any
/// active content.
///
/// Feasibility only: exact `/ToUnicode` mapping for every shaped source cluster
/// remains unverified against pinned printpdf 0.13.0. The supplemental
/// `/ActualText` spans below do not satisfy that separate acceptance gate.
pub(super) fn serialize_pdf(
    region: &ExportRegionV1,
    selected_ink_png: &[u8],
) -> Result<Vec<u8>, ExportError> {
    validate_selected_ink(region, selected_ink_png)?;
    let view = project_region(region)?;

    let mut warnings = Vec::new();
    let mut font_warnings = Vec::new();
    let font = ParsedFont::from_bytes(NOTO_SANS_REGULAR, 0, &mut font_warnings)
        .ok_or(ExportError::InvalidText)?;
    let mut document = PdfDocument::new("Selected region");
    let font_id = document.add_font(&font);
    let font_refs = [(font_id.clone(), font.as_azul())];
    let shaper = LineShaper::new(&font);

    let page_width = Mm(PAGE_WIDTH_MM);
    let page_height = Mm(PAGE_HEIGHT_MM);
    let page_height_pt: Pt = page_height.into();
    let margin_pt: Pt = Mm(PAGE_MARGIN_MM).into();
    let content_width_pt: Pt = Mm(PAGE_WIDTH_MM - PAGE_MARGIN_MM * 2.0).into();
    let text_lines = ordered_text_lines(&view)?;

    let mut pages = Vec::new();
    let mut operations = vec![Op::StartTextSection];
    let mut row_on_page = 0usize;
    for text_line in &text_lines {
        let mut shaped_lines = wrap_and_shape(&text_line.text, &shaper, &font, content_width_pt)?;
        let last_line = shaped_lines.len().saturating_sub(1);
        for (line_index, (mut actual_text, shaped_line)) in shaped_lines.drain(..).enumerate() {
            if row_on_page == LINES_PER_PAGE {
                operations.push(Op::EndTextSection);
                push_text_page(&mut pages, std::mem::take(&mut operations))?;
                operations.push(Op::StartTextSection);
                row_on_page = 0;
            }
            let baseline_pt =
                page_height_pt.0 - margin_pt.0 - FONT_SIZE.0 - row_on_page as f32 * LINE_HEIGHT_PT;
            operations.push(Op::SetTextMatrix {
                matrix: TextMatrix::Translate(margin_pt, Pt(baseline_pt)),
            });
            if text_line.append_line_feed && line_index == last_line {
                actual_text.push('\n');
            }
            let actual_text_bytes = utf16_be_with_bom(&actual_text)?;
            operations.push(Op::BeginMarkedContentWithProperties {
                tag: "Span".to_owned(),
                properties: DictItem::Dict {
                    map: BTreeMap::from([(
                        "ActualText".to_owned(),
                        DictItem::Bytes(actual_text_bytes),
                    )]),
                },
            });
            operations.extend(show_placed_glyphs(
                &font_refs,
                FONT_SIZE,
                &shaped_line.glyphs,
                None,
            ));
            operations.push(Op::EndMarkedContent);
            row_on_page += 1;
        }
    }
    operations.push(Op::EndTextSection);
    push_text_page(&mut pages, operations)?;

    let image = RawImage::decode_from_bytes(selected_ink_png, &mut warnings)
        .map_err(|_| ExportError::InkUnavailable)?;
    if image.width != view.raster_width_px as usize
        || image.height != view.raster_height_px as usize
    {
        return Err(ExportError::StaleSource);
    }
    let image_id = document.add_image(&image);
    let caption = shape_validated_text(region.raw_ink_fallback.alt_text, &shaper, &font)?;
    let caption_y = page_height_pt.0 - margin_pt.0 - FONT_SIZE.0;
    let available_image_height_pt = Pt(page_height_pt.0 - margin_pt.0 * 2.0 - LINE_HEIGHT_PT);
    let base_image_width_pt = image.width as f32 * 72.0 / MAX_IMAGE_DPI;
    let base_image_height_pt = image.height as f32 * 72.0 / MAX_IMAGE_DPI;
    if !(base_image_width_pt.is_finite() && base_image_height_pt.is_finite())
        || base_image_width_pt <= 0.0
        || base_image_height_pt <= 0.0
        || available_image_height_pt.0 <= 0.0
    {
        return Err(ExportError::InkUnavailable);
    }
    let image_scale = (content_width_pt.0 / base_image_width_pt)
        .min(available_image_height_pt.0 / base_image_height_pt);
    if !(image_scale.is_finite() && image_scale > 0.0) {
        return Err(ExportError::InkUnavailable);
    }
    let mut image_page_ops = vec![
        Op::StartTextSection,
        Op::SetTextMatrix {
            matrix: TextMatrix::Translate(margin_pt, Pt(caption_y)),
        },
    ];
    image_page_ops.extend(show_placed_glyphs(
        &font_refs,
        FONT_SIZE,
        &caption.glyphs,
        None,
    ));
    image_page_ops.push(Op::EndTextSection);
    image_page_ops.push(Op::UseXobject {
        id: image_id,
        transform: XObjectTransform {
            translate_x: Some(margin_pt),
            translate_y: Some(margin_pt),
            scale_x: Some(image_scale),
            scale_y: Some(image_scale),
            dpi: Some(MAX_IMAGE_DPI),
            ..Default::default()
        },
    });
    if pages.len().saturating_add(1) > MAX_PDF_PAGES {
        return Err(ExportError::OutputTooLarge);
    }
    pages.push(PdfPage::new(page_width, page_height, image_page_ops));
    document.pages = pages;

    let bytes = document.save(
        &PdfSaveOptions {
            subset_fonts: true,
            optimize: false,
            ..Default::default()
        },
        &mut warnings,
    );
    if bytes.len() > MAX_PDF_BYTES {
        return Err(ExportError::OutputTooLarge);
    }
    if !bytes.starts_with(b"%PDF-") {
        return Err(ExportError::IoFailure);
    }
    Ok(bytes)
}

fn ordered_text_lines(view: &DocumentViewV1) -> Result<Vec<PdfTextLine>, ExportError> {
    let mut text_lines = Vec::new();
    let digest_field_count = view
        .provenance_fields
        .iter()
        .filter(|field| is_sha256_digest(&field.value))
        .count();
    text_lines
        .try_reserve_exact(
            3usize
                .saturating_add(view.lines.as_ref().map_or(0, Vec::len))
                .saturating_add(view.provenance_fields.len())
                .saturating_add(digest_field_count),
        )
        .map_err(|_| ExportError::AllocationFailed)?;
    text_lines.push(PdfTextLine {
        text: "Selected region".to_owned(),
        append_line_feed: false,
    });
    text_lines.push(PdfTextLine {
        text: view.state_label.to_owned(),
        append_line_feed: false,
    });
    if let Some(lines) = &view.lines {
        for (index, line) in lines.iter().enumerate() {
            text_lines.push(PdfTextLine {
                text: line.clone(),
                append_line_feed: index + 1 < lines.len(),
            });
        }
    }
    text_lines.push(PdfTextLine {
        text: "Provenance".to_owned(),
        append_line_feed: false,
    });
    for field in &view.provenance_fields {
        if is_sha256_digest(&field.value) {
            let label_length = field
                .label
                .len()
                .checked_add(1)
                .ok_or(ExportError::OutputTooLarge)?;
            if label_length > super::MAX_EXPORT_DOCUMENT_BYTES {
                return Err(ExportError::OutputTooLarge);
            }
            let mut label_line = String::new();
            label_line
                .try_reserve_exact(label_length)
                .map_err(|_| ExportError::AllocationFailed)?;
            label_line.push_str(&field.label);
            label_line.push(':');
            text_lines.push(PdfTextLine {
                text: label_line,
                append_line_feed: false,
            });

            let mut value_line = String::new();
            value_line
                .try_reserve_exact(field.value.len())
                .map_err(|_| ExportError::AllocationFailed)?;
            value_line.push_str(&field.value);
            text_lines.push(PdfTextLine {
                text: value_line,
                append_line_feed: false,
            });
            continue;
        }
        let mut line = String::new();
        let length = field
            .label
            .len()
            .checked_add(field.value.len())
            .and_then(|value| value.checked_add(2))
            .ok_or(ExportError::OutputTooLarge)?;
        if length > super::MAX_EXPORT_DOCUMENT_BYTES {
            return Err(ExportError::OutputTooLarge);
        }
        line.try_reserve_exact(length)
            .map_err(|_| ExportError::AllocationFailed)?;
        line.push_str(&field.label);
        line.push_str(": ");
        line.push_str(&field.value);
        text_lines.push(PdfTextLine {
            text: line,
            append_line_feed: false,
        });
    }
    Ok(text_lines)
}

fn wrap_and_shape(
    text: &str,
    shaper: &LineShaper,
    font: &ParsedFont,
    maximum_width: Pt,
) -> Result<Vec<(String, printpdf::PlacedLine)>, ExportError> {
    validate_pdf_text(text, font)?;
    let mut output = Vec::new();
    output
        .try_reserve(1)
        .map_err(|_| ExportError::AllocationFailed)?;
    if text.is_empty() {
        // A space glyph anchors a legitimate empty IR line so PDF extractors can
        // retain its ActualText line boundary; unsupported source scalars fail above.
        let anchor = shape_validated_text(" ", shaper, font)?;
        output.push((String::new(), anchor));
        return Ok(output);
    }
    let mut current_actual = String::new();
    let mut current_visual = String::new();
    for grapheme in text.graphemes(true) {
        let visual_grapheme = if grapheme == "\t" { "    " } else { grapheme };
        let candidate_len = current_visual
            .len()
            .checked_add(visual_grapheme.len())
            .ok_or(ExportError::OutputTooLarge)?;
        if candidate_len
            > MAX_JOURNAL_TEXT_BYTES
                .saturating_mul(4)
                .saturating_add(1024)
        {
            return Err(ExportError::OutputTooLarge);
        }
        let mut candidate = String::new();
        candidate
            .try_reserve_exact(candidate_len)
            .map_err(|_| ExportError::AllocationFailed)?;
        candidate.push_str(&current_visual);
        candidate.push_str(visual_grapheme);
        let candidate_line = shape_validated_text(&candidate, shaper, font)?;
        if !current_visual.is_empty() && candidate_line.width.0 > maximum_width.0 {
            finish_shaped_fragment(
                &mut current_actual,
                &mut current_visual,
                shaper,
                font,
                &mut output,
            )?;
            current_actual
                .try_reserve(grapheme.len())
                .map_err(|_| ExportError::AllocationFailed)?;
            current_actual.push_str(grapheme);
            current_visual
                .try_reserve(visual_grapheme.len())
                .map_err(|_| ExportError::AllocationFailed)?;
            current_visual.push_str(visual_grapheme);
        } else {
            current_actual
                .try_reserve(grapheme.len())
                .map_err(|_| ExportError::AllocationFailed)?;
            current_actual.push_str(grapheme);
            current_visual = candidate;
        }
    }
    if !current_actual.is_empty() || output.is_empty() {
        finish_shaped_fragment(
            &mut current_actual,
            &mut current_visual,
            shaper,
            font,
            &mut output,
        )?;
    }
    Ok(output)
}

fn finish_shaped_fragment(
    actual_text: &mut String,
    visual_text: &mut String,
    shaper: &LineShaper,
    font: &ParsedFont,
    output: &mut Vec<(String, printpdf::PlacedLine)>,
) -> Result<(), ExportError> {
    let shaped = if visual_text.is_empty() {
        printpdf::PlacedLine::empty()
    } else {
        shape_validated_text(visual_text, shaper, font)?
    };
    output
        .try_reserve(1)
        .map_err(|_| ExportError::AllocationFailed)?;
    output.push((std::mem::take(actual_text), shaped));
    visual_text.clear();
    Ok(())
}

fn validate_pdf_text(text: &str, font: &ParsedFont) -> Result<(), ExportError> {
    for character in text.chars() {
        if character == '\t' {
            continue;
        }
        if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
            return Err(ExportError::InvalidText);
        }
        let glyph_id = font
            .lookup_glyph_index(character as u32)
            .filter(|glyph_id| *glyph_id != 0)
            .ok_or(ExportError::InvalidText)?;
        if font.get_or_decode_glyph(glyph_id).is_none() {
            return Err(ExportError::InvalidText);
        }
    }
    Ok(())
}

fn shape_validated_text(
    text: &str,
    shaper: &LineShaper,
    font: &ParsedFont,
) -> Result<printpdf::PlacedLine, ExportError> {
    validate_pdf_text(text, font)?;
    let shaped = shaper
        .shape(text, FONT_SIZE)
        .map_err(|_| ExportError::InvalidText)?;
    let mut shaped_unicode = String::new();
    for glyph in &shaped.glyphs {
        if glyph.gid == 0 || font.get_or_decode_glyph(glyph.gid).is_none() {
            return Err(ExportError::InvalidText);
        }
        shaped_unicode
            .try_reserve(glyph.text.len())
            .map_err(|_| ExportError::AllocationFailed)?;
        shaped_unicode.push_str(&glyph.text);
    }
    if shaped_unicode != text {
        return Err(ExportError::InvalidText);
    }
    Ok(shaped)
}

fn utf16_be_with_bom(text: &str) -> Result<Vec<u8>, ExportError> {
    let byte_capacity = 2usize
        .checked_add(
            text.encode_utf16()
                .count()
                .checked_mul(2)
                .ok_or(ExportError::OutputTooLarge)?,
        )
        .ok_or(ExportError::OutputTooLarge)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(byte_capacity)
        .map_err(|_| ExportError::AllocationFailed)?;
    output.extend_from_slice(&[0xFE, 0xFF]);
    for code_unit in text.encode_utf16() {
        output.extend_from_slice(&code_unit.to_be_bytes());
    }
    Ok(output)
}

fn push_text_page(pages: &mut Vec<PdfPage>, operations: Vec<Op>) -> Result<(), ExportError> {
    if pages.len().saturating_add(2) > MAX_PDF_PAGES {
        return Err(ExportError::OutputTooLarge);
    }
    pages
        .try_reserve(1)
        .map_err(|_| ExportError::AllocationFailed)?;
    pages.push(PdfPage::new(
        Mm(PAGE_WIDTH_MM),
        Mm(PAGE_HEIGHT_MM),
        operations,
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{TranscriptOriginV1, document_fixtures::synthetic_fixture};

    #[test]
    fn nfd_shaping_keeps_original_cluster_text_and_real_glyphs() {
        // This checks the shaper input to the serializer; the hosted PDFBox
        // proof separately checks the serialized /ToUnicode CMap.
        let nfc = "ấ";
        let nfd = "a\u{0302}\u{0301}";
        let font = ParsedFont::from_bytes(NOTO_SANS_REGULAR, 0, &mut Vec::new()).unwrap();
        let shaper = LineShaper::new(&font);
        for expected in [nfc, nfd] {
            let shaped = shape_validated_text(expected, &shaper, &font).unwrap();
            let mapped = shaped
                .glyphs
                .iter()
                .fold(String::new(), |mut output, glyph| {
                    output.push_str(&glyph.text);
                    output
                });
            assert_eq!(mapped, expected);
            assert!(shaped.glyphs.iter().all(|glyph| glyph.gid != 0));
        }
    }

    #[test]
    fn all_4096_line_feed_bytes_fit_the_bounded_pdf_page_count() {
        let text = "\n".repeat(MAX_JOURNAL_TEXT_BYTES);
        let (region, png) = synthetic_fixture(Some(&text), TranscriptOriginV1::Provider);
        assert_eq!(region.paragraph.as_ref().unwrap().lines.len(), 4097);
        let bytes = serialize_pdf(&region, &png).unwrap();
        assert!(bytes.starts_with(b"%PDF-"));
        assert!(bytes.len() <= MAX_PDF_BYTES);
    }
}
