#[cfg(feature = "document-export-fixture-emitter")]
use super::document_fixtures::synthetic_grayscale_antialias_fixture;
use super::{
    ExportError, ExportFormat, ExportFormats, ExportRequestError, TranscriptOriginV1,
    document::project_region, document::validate_selected_ink,
    document_fixtures::synthetic_fixture,
};
use std::sync::atomic::AtomicBool;

#[test]
fn transcript_presence_empty_state_and_reset_remain_distinct() {
    let cases = [
        (TranscriptOriginV1::InkOnly, None, None),
        (TranscriptOriginV1::NoProviderCandidate, None, None),
        (TranscriptOriginV1::Provider, Some(""), Some(1usize)),
        (TranscriptOriginV1::SetText, Some(""), Some(1usize)),
        (TranscriptOriginV1::Reset, None, None),
        (TranscriptOriginV1::Reset, Some(""), Some(1usize)),
    ];

    for (origin, source_text, expected_lines) in cases {
        let (region, _png) = synthetic_fixture(source_text, origin);
        let projected = project_region(&region).unwrap();
        assert_eq!(projected.lines.as_ref().map(Vec::len), expected_lines);
        assert!(projected.state_label.contains(match origin {
            TranscriptOriginV1::InkOnly => "ink-only",
            TranscriptOriginV1::NoProviderCandidate => "No provider",
            TranscriptOriginV1::Provider => "Provider returned",
            TranscriptOriginV1::SetText => "user correction",
            TranscriptOriginV1::Reset => "reset",
        }));
    }
}

#[test]
fn provenance_projection_does_not_emit_source_ids_or_paths() {
    let (region, _) = synthetic_fixture(Some("synthetic text"), TranscriptOriginV1::Provider);
    let projected = project_region(&region).unwrap();
    let display = projected
        .provenance_fields
        .iter()
        .map(|field| format!("{}: {}", field.label, field.value))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!display.contains("PRIVATE-SYNTHETIC-JOURNAL-PATH-CANARY"));
    assert!(!display.contains("C:\\"));
    assert!(display.contains("Export PNG SHA-256"));
}

#[test]
fn docx_rejects_xml_forbidden_controls_without_rewriting_source_ir() {
    let source_text = "kept\u{0001}source";
    let (region, png) = synthetic_fixture(Some(source_text), TranscriptOriginV1::SetText);
    let binding_hash_before = region.provenance.source_binding_sha256.clone();
    assert_eq!(
        super::docx_serializer::serialize_docx(&region, &png),
        Err(ExportError::InvalidText)
    );
    let paragraph = region.paragraph.as_ref().unwrap();
    assert_eq!(paragraph.lines[0].runs[0].text, source_text);
    assert_eq!(region.provenance.source_binding_sha256, binding_hash_before);
}

#[test]
fn optional_format_failures_are_isolated_and_report_the_selected_format() {
    let source_text = "kept\u{0001}source";
    let (region, png) = synthetic_fixture(Some(source_text), TranscriptOriginV1::SetText);
    let binding_hash_before = region.provenance.source_binding_sha256.clone();
    let markdown_html = super::finish_export_bundle(
        region.clone(),
        png.clone(),
        ExportFormats::DEFAULT,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(markdown_html.markdown.is_some());
    assert!(markdown_html.html.is_some());
    assert!(markdown_html.docx.is_none());
    assert!(markdown_html.pdf.is_none());
    assert!(
        String::from_utf8(markdown_html.markdown.unwrap())
            .unwrap()
            .contains(source_text)
    );
    assert!(
        String::from_utf8(markdown_html.html.unwrap())
            .unwrap()
            .contains(source_text)
    );

    let docx_only = ExportFormats {
        markdown: false,
        html: false,
        docx: true,
        pdf: false,
    };
    let docx_failure = super::finish_export_bundle(
        region.clone(),
        png.clone(),
        docx_only,
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert_eq!(
        docx_failure,
        ExportRequestError::Format {
            format: ExportFormat::Docx,
            error: ExportError::InvalidText,
        }
    );

    let pdf_only = ExportFormats {
        markdown: false,
        html: false,
        docx: false,
        pdf: true,
    };
    let pdf_failure =
        super::finish_export_bundle(region.clone(), png, pdf_only, &AtomicBool::new(false))
            .unwrap_err();
    assert_eq!(
        pdf_failure,
        ExportRequestError::Format {
            format: ExportFormat::Pdf,
            error: ExportError::InvalidText,
        }
    );
    assert_eq!(
        region.paragraph.as_ref().unwrap().lines[0].runs[0].text,
        source_text
    );
    assert_eq!(region.provenance.source_binding_sha256, binding_hash_before);
}

#[test]
fn export_request_rejects_an_empty_format_set() {
    let (region, png) = synthetic_fixture(Some("text"), TranscriptOriginV1::Provider);
    let failure = super::finish_export_bundle(
        region,
        png,
        ExportFormats {
            markdown: false,
            html: false,
            docx: false,
            pdf: false,
        },
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert_eq!(
        failure,
        ExportRequestError::Export(ExportError::NoFormatsRequested)
    );
}

#[test]
fn requested_serializer_cancellation_returns_before_creating_output() {
    let (region, png) =
        synthetic_fixture(Some("NFD a\u{0302}\u{0301}"), TranscriptOriginV1::Provider);
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        super::docx_serializer::serialize_docx_cancellable(&region, &png, &cancelled),
        Err(ExportError::Cancelled)
    );
    assert_eq!(
        super::pdf_serializer::serialize_pdf_cancellable(&region, &png, &cancelled),
        Err(ExportError::Cancelled)
    );
}

#[test]
fn docx_keeps_xml_valid_c1_scalars_eligible() {
    let source_text = "valid\u{007F}\u{0085}\u{009F} text";
    let (region, png) = synthetic_fixture(Some(source_text), TranscriptOriginV1::SetText);
    let bytes = super::docx_serializer::serialize_docx(&region, &png).unwrap();
    assert!(bytes.starts_with(b"PK\x03\x04"));
}

#[test]
fn pdf_rejects_nonprinting_controls_and_separators_explicitly() {
    for character in [
        '\u{0001}', '\u{000B}', '\u{000C}', '\u{007F}', '\u{0085}', '\u{009F}', '\u{2028}',
        '\u{2029}',
    ] {
        let source_text = format!("before{character}after");
        let (region, png) = synthetic_fixture(Some(&source_text), TranscriptOriginV1::SetText);
        assert_eq!(
            super::pdf_serializer::serialize_pdf(&region, &png),
            Err(ExportError::InvalidText),
            "unsupported scalar U+{:04X} must fail explicitly",
            character as u32,
        );
    }
}

#[test]
fn original_ink_bytes_are_bound_to_the_raster_provenance_hash() {
    let (region, png) = synthetic_fixture(
        Some("synthetic NFD a\u{0302}\u{0301}"),
        TranscriptOriginV1::Provider,
    );
    assert_eq!(validate_selected_ink(&region, &png), Ok(()));
    let mut changed_png = png;
    changed_png.push(0);
    assert_eq!(
        validate_selected_ink(&region, &changed_png),
        Err(ExportError::StaleSource)
    );
}

#[cfg(feature = "document-export-fixture-emitter")]
#[test]
#[ignore = "opt-in hosted Windows DOCX/PDF renderer fixture emitter"]
fn emit_document_export_fixtures_under_runner_temp() {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        path::{Path, PathBuf},
    };

    use serde_json::json;

    fn write_new(root: &Path, name: &str, bytes: &[u8]) {
        assert!(
            name.bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_') })
        );
        let path = root.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("synthetic fixture output must be new");
        file.write_all(bytes)
            .expect("synthetic fixture bytes must be written");
    }

    let runner_temp = PathBuf::from(
        std::env::var_os("RUNNER_TEMP").expect("RUNNER_TEMP is required for fixture emission"),
    )
    .canonicalize()
    .expect("RUNNER_TEMP must exist");
    let output_path = PathBuf::from(
        std::env::var_os("LASSOINK_DOCUMENT_EXPORT_FIXTURE_OUT")
            .expect("LASSOINK_DOCUMENT_EXPORT_FIXTURE_OUT is required"),
    );
    assert!(output_path.is_absolute(), "fixture output must be absolute");
    fs::create_dir(&output_path).expect("fixture output directory must be new");
    let output = output_path
        .canonicalize()
        .expect("fixture output directory must resolve");
    assert!(
        output.starts_with(&runner_temp),
        "fixture output must stay under RUNNER_TEMP"
    );

    let maximum_line_breaks = "\n".repeat(crate::journal::MAX_JOURNAL_TEXT_BYTES);
    let cases: Vec<(&str, Option<&str>, TranscriptOriginV1)> = vec![
        ("ink-only", None, TranscriptOriginV1::InkOnly),
        (
            "no-provider-candidate",
            None,
            TranscriptOriginV1::NoProviderCandidate,
        ),
        ("provider-empty", Some(""), TranscriptOriginV1::Provider),
        ("user-empty", Some(""), TranscriptOriginV1::SetText),
        ("reset-absent", None, TranscriptOriginV1::Reset),
        ("reset-empty", Some(""), TranscriptOriginV1::Reset),
        (
            "nfc-vietnamese",
            Some("[[NFC: ấ]]"),
            TranscriptOriginV1::Provider,
        ),
        (
            "nfd-vietnamese",
            Some("[[NFD: a\u{0302}\u{0301}]]"),
            TranscriptOriginV1::Provider,
        ),
        (
            "mixed-normalization-ligatures",
            Some("[[MIXED: ấ | a\u{0302}\u{0301} | repeated repeated | office fi fl ffi]]"),
            TranscriptOriginV1::SetText,
        ),
        (
            "line-order",
            Some("[[first line\nsecond line\nthird line]]"),
            TranscriptOriginV1::Provider,
        ),
        (
            "maximum-lines",
            Some(maximum_line_breaks.as_str()),
            TranscriptOriginV1::SetText,
        ),
    ];

    let mut manifest_cases = Vec::new();
    let mut shared_png: Option<Vec<u8>> = None;
    let mut png_sha256 = String::new();
    let mut fallback_alt_text = String::new();
    for (name, source_text, origin) in cases {
        let (region, png) = synthetic_fixture(source_text, origin);
        if let Some(previous_png) = &shared_png {
            assert_eq!(
                previous_png.as_slice(),
                png.as_slice(),
                "all fixture cases use the same PNG"
            );
        } else {
            png_sha256 = region.provenance.raster.png_bytes_sha256.clone();
            fallback_alt_text = region.raw_ink_fallback.alt_text.to_owned();
            write_new(&output, "selected-ink.png", &png);
            shared_png = Some(png.clone());
        }
        let docx_name = format!("{name}.docx");
        let pdf_name = format!("{name}.pdf");
        let docx = super::docx_serializer::serialize_docx(&region, &png)
            .expect("valid synthetic DOCX must serialize");
        let pdf = super::pdf_serializer::serialize_pdf(&region, &png)
            .expect("valid synthetic PDF must serialize");
        write_new(&output, &docx_name, &docx);
        write_new(&output, &pdf_name, &pdf);
        let projected = project_region(&region).expect("synthetic IR must project");
        manifest_cases.push(json!({
            "name": name,
            "origin": format!("{origin:?}"),
            "state_label": projected.state_label,
            "source_text": source_text,
            "docx": docx_name,
            "pdf": pdf_name,
            "png_sha256": png_sha256,
            "strict_pdf_text": matches!(
                name,
                "nfc-vietnamese"
                    | "nfd-vietnamese"
                    | "mixed-normalization-ligatures"
                    | "line-order"
                    | "maximum-lines"
            ),
        }));
    }

    let grayscale_name = "grayscale-antialias";
    let grayscale_source = "[[GRAY-MIDTONE]]";
    let (grayscale_region, grayscale_png) =
        synthetic_grayscale_antialias_fixture(Some(grayscale_source), TranscriptOriginV1::SetText);
    let grayscale_png_name = format!("{grayscale_name}.png");
    let grayscale_docx_name = format!("{grayscale_name}.docx");
    let grayscale_pdf_name = format!("{grayscale_name}.pdf");
    let grayscale_docx = super::docx_serializer::serialize_docx(&grayscale_region, &grayscale_png)
        .expect("valid grayscale synthetic DOCX must serialize");
    let grayscale_pdf = super::pdf_serializer::serialize_pdf(&grayscale_region, &grayscale_png)
        .expect("valid grayscale synthetic PDF must serialize");
    write_new(&output, &grayscale_png_name, &grayscale_png);
    write_new(&output, &grayscale_docx_name, &grayscale_docx);
    write_new(&output, &grayscale_pdf_name, &grayscale_pdf);
    let grayscale_projected =
        project_region(&grayscale_region).expect("grayscale synthetic IR must project");
    manifest_cases.push(json!({
        "name": grayscale_name,
        "origin": format!("{:?}", TranscriptOriginV1::SetText),
        "state_label": grayscale_projected.state_label,
        "source_text": grayscale_source,
        "docx": grayscale_docx_name,
        "pdf": grayscale_pdf_name,
        "png": grayscale_png_name,
        "png_sha256": grayscale_region.provenance.raster.png_bytes_sha256,
        "strict_pdf_text": true,
        "image_fixture_kind": "grayscale-antialiased-midtone",
    }));

    let c1_text = "XML C1: \u{007F}\u{0085}\u{009F}; separators: \u{2028}\u{2029}";
    let (c1_region, c1_png) = synthetic_fixture(Some(c1_text), TranscriptOriginV1::SetText);
    let c1_docx = super::docx_serializer::serialize_docx(&c1_region, &c1_png)
        .expect("XML-valid C1 and separator scalars remain DOCX-eligible");
    write_new(&output, "xml-valid-controls.docx", &c1_docx);

    let forbidden_docx_text = "before\u{0001}after";
    let (forbidden_docx_region, forbidden_docx_png) =
        synthetic_fixture(Some(forbidden_docx_text), TranscriptOriginV1::SetText);
    assert_eq!(
        super::docx_serializer::serialize_docx(&forbidden_docx_region, &forbidden_docx_png),
        Err(ExportError::InvalidText)
    );

    let rejected_pdf_scalars = [
        '\u{0001}', '\u{000B}', '\u{000C}', '\u{007F}', '\u{0085}', '\u{009F}', '\u{2028}',
        '\u{2029}',
    ];
    for character in rejected_pdf_scalars {
        let text = format!("before{character}after");
        let (region, png) = synthetic_fixture(Some(&text), TranscriptOriginV1::SetText);
        assert_eq!(
            super::pdf_serializer::serialize_pdf(&region, &png),
            Err(ExportError::InvalidText)
        );
    }

    let manifest = json!({
        "schema_version": 1,
        "fixtures_are_fixed_synthetic_inputs": true,
        "selected_ink_png": "selected-ink.png",
        "png_sha256": png_sha256,
        "fallback_alt_text": fallback_alt_text,
        "maximum_input_utf8_bytes": crate::journal::MAX_JOURNAL_TEXT_BYTES,
        "maximum_logical_lines": crate::journal::MAX_JOURNAL_TEXT_BYTES + 1,
        "pdf_page_limit": 96,
        "xml_valid_controls_docx": "xml-valid-controls.docx",
        "xml_valid_controls_expected": c1_text,
        "xml_valid_controls_state_label": project_region(&c1_region)
            .expect("synthetic C1 IR must project")
            .state_label,
        "xml_forbidden_control_docx_rejected": true,
        "unsupported_pdf_scalars_rejected": rejected_pdf_scalars
            .iter()
            .map(|character| format!("U+{:04X}", *character as u32))
            .collect::<Vec<_>>(),
        "cases": manifest_cases,
    });
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).expect("fixed synthetic manifest must serialize");
    write_new(&output, "manifest.json", &manifest_bytes);
}
