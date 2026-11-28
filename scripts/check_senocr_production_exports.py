#!/usr/bin/env python3
"""Hosted-only independent checks for temporary SenOCR export outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

from check_document_export_fixtures import (
    MAX_DOCX_BYTES,
    MAX_PDF_BYTES,
    check_docx,
    check_exact_docx_transcript,
    require,
    sha256,
)


REQUIRED_PROVENANCE_LABELS = (
    "Provenance schema",
    "Binding kind",
    "Logical revision",
    "Snapshot sequence",
    "Projection source sequence",
    "Ink binding SHA-256",
    "Selected stroke count",
    "Bound source sample count",
    "Selection binding SHA-256",
    "Projection identity SHA-256",
    "Correction identity SHA-256",
    "Provider identity SHA-256",
    "Provider version",
    "Model version",
    "Resource version",
    "Provider configuration fingerprint SHA-256",
    "Export raster source SHA-256",
    "Export raster spec SHA-256",
    "Export PNG SHA-256",
    "Export raster artifact SHA-256",
    "Export PNG dimensions",
)

MARKDOWN_ESCAPED_ASCII_RANGES = ((0x21, 0x2F), (0x3A, 0x40), (0x5B, 0x60), (0x7B, 0x7E))
PDFBOX_PROOF_FAILURE_MARKERS = (
    ("PDF page count exceeds the manifest page bound", "page_count_bound"),
    ("fixed fixture PNG could not be decoded", "fixture_png_decode"),
    ("PDF must contain exactly one embedded image XObject", "embedded_image_count"),
    ("private path or metadata value appeared in decoded PDF text", "private_metadata_scan"),
    ("raw glyph-code /ToUnicode text did not match input", "to_unicode_text_mismatch"),
    ("consecutive empty-line ActualText spans did not match the LF-only source", "linefeed_actual_text_mismatch"),
    ("PDFTextStripper text did not match input scalars", "pdf_text_stripper_mismatch"),
    ("ActualText was not associated with matching glyph text", "actual_text_association_mismatch"),
    ("PDF page is missing resources", "page_resources_missing"),
    ("source_png_header_invalid", "source_png_header_invalid"),
    ("source_png_dimensions_invalid", "source_png_dimensions_invalid"),
    ("expected_provenance_fields_invalid", "expected_provenance_fields_invalid"),
    ("expected provenance requires source text and state label", "provenance_source_context_missing"),
    ("provenance_fields_require_visible_source", "provenance_source_context_unsupported"),
    ("provenance_fields_raw_cmap_mismatch", "provenance_raw_cmap_mismatch"),
    ("provenance_fields_pdf_text_stripper_mismatch", "provenance_text_stripper_mismatch"),
    ("provenance_fields_actualtext_mismatch", "provenance_actualtext_mismatch"),
    ("malformed Tf operator", "font_operator_malformed"),
    ("expected an embedded Type 0 text font", "embedded_type0_font_missing"),
    ("embedded Type 0 font has no /ToUnicode CMap stream", "to_unicode_cmap_missing"),
    ("malformed Tj operator", "tj_operator_malformed"),
    ("malformed TJ operator", "tj_array_operator_malformed"),
    ("unbalanced EMC operator", "marked_content_unbalanced"),
    ("unclosed marked-content sequence", "marked_content_unclosed"),
    ("no_final_page_image", "no_final_page_image"),
    ("final_page_image_pixels_differ", "final_page_image_pixels_differ"),
    ("final_page_resources_missing", "final_page_resources_missing"),
    ("PDF catalog actions or attachments are forbidden", "catalog_active_content"),
    ("PDF JavaScript or embedded files are forbidden", "javascript_or_attachment"),
    ("PDF page actions and annotations are forbidden", "page_active_content"),
    ("text-showing operator lacks an embedded Type 0 font", "text_font_missing"),
    ("missing /ToUnicode entry for glyph code ", "to_unicode_entry_missing"),
)
PDFBOX_IMAGE_AGGREGATE_PREFIX = b"PDF_IMAGE_AGGREGATE "
PDFBOX_IMAGE_AGGREGATE_INTEGER_FIELDS = (
    "source_png_width",
    "source_png_height",
    "source_png_bit_depth",
    "source_png_color_type",
    "source_alpha_min",
    "source_alpha_max",
    "pdf_xobject_width",
    "pdf_xobject_height",
    "pdf_xobject_bits_per_component",
    "final_page_image_invocation_count",
    "decoded_alpha_min",
    "decoded_alpha_max",
    "unequal_pixel_count",
    "max_rgb_delta",
    "max_alpha_delta",
)
PDFBOX_IMAGE_COLOR_SPACES = {
    "DeviceGray",
    "DeviceRGB",
    "DeviceCMYK",
    "ICCBased",
    "Indexed",
    "Separation",
    "DeviceN",
    "Pattern",
    "other",
}
PDFBOX_IMAGE_FILTERS = {
    "FlateDecode",
    "DCTDecode",
    "LZWDecode",
    "RunLengthDecode",
    "JPXDecode",
    "CCITTFaxDecode",
    "ASCII85Decode",
    "ASCIIHexDecode",
    "Crypt",
    "none",
    "other",
}


def unescape_markdown_provenance_value(value: str) -> str:
    characters: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            next_codepoint = ord(value[index + 1])
            if any(start <= next_codepoint <= end for start, end in MARKDOWN_ESCAPED_ASCII_RANGES):
                index += 1
        characters.append(value[index])
        index += 1
    return "".join(characters)


def safe_pdfbox_proof_failure_details(stderr: bytes) -> tuple[str, dict[str, object] | None]:
    failure_category = "unclassified"
    for marker, category in PDFBOX_PROOF_FAILURE_MARKERS:
        if marker.encode("utf-8") in stderr:
            failure_category = category
            break
    aggregate = None
    for line in stderr.splitlines():
        if not line.startswith(PDFBOX_IMAGE_AGGREGATE_PREFIX):
            continue
        try:
            candidate = json.loads(line[len(PDFBOX_IMAGE_AGGREGATE_PREFIX) :])
        except (UnicodeDecodeError, json.JSONDecodeError):
            break
        required_fields = set(PDFBOX_IMAGE_AGGREGATE_INTEGER_FIELDS) | {
            "pdf_xobject_color_space",
            "pdf_xobject_filter",
            "pdf_xobject_has_smask",
        }
        if not isinstance(candidate, dict) or set(candidate) != required_fields:
            break
        if any(type(candidate[field]) is not int for field in PDFBOX_IMAGE_AGGREGATE_INTEGER_FIELDS):
            break
        if type(candidate["pdf_xobject_has_smask"]) is not bool:
            break
        color_space = candidate["pdf_xobject_color_space"]
        image_filter = candidate["pdf_xobject_filter"]
        if not isinstance(color_space, str) or color_space not in PDFBOX_IMAGE_COLOR_SPACES:
            break
        if not isinstance(image_filter, str) or not all(
            item in PDFBOX_IMAGE_FILTERS for item in image_filter.split("+")
        ):
            break
        if candidate["source_png_color_type"] not in {0, 2, 3, 4, 6}:
            break
        if not 1 <= candidate["source_png_bit_depth"] <= 16:
            break
        if not 0 <= candidate["source_alpha_min"] <= candidate["source_alpha_max"] <= 255:
            break
        if not -1 <= candidate["decoded_alpha_min"] <= candidate["decoded_alpha_max"] <= 255:
            break
        if any(
            not 0 <= candidate[field] <= 1_000_000
            for field in (
                "source_png_width",
                "source_png_height",
                "pdf_xobject_width",
                "pdf_xobject_height",
                "final_page_image_invocation_count",
            )
        ):
            break
        if candidate["pdf_xobject_bits_per_component"] not in {-1, 1, 2, 4, 8, 16, 32}:
            break
        if any(not 0 <= candidate[field] <= 255 for field in ("max_rgb_delta", "max_alpha_delta")):
            break
        if not 0 <= candidate["unequal_pixel_count"] <= 2_000_000_000:
            break
        aggregate = candidate
        break
    return failure_category, aggregate


def run_quiet(command: list[str], label: str) -> None:
    result = subprocess.run(command, capture_output=True, check=False)
    if label == "PDFBox production structure proof":
        category, aggregate = safe_pdfbox_proof_failure_details(result.stderr)
        if aggregate is not None:
            print(
                "PDFBox actual image aggregate: "
                + json.dumps(aggregate, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
            )
        if result.returncode != 0:
            raise RuntimeError(
                f"{label} exited with status {result.returncode} category={category}"
            )
    elif result.returncode != 0:
        raise RuntimeError(f"{label} exited with status {result.returncode}")


def is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def markdown_provenance(markdown: str) -> dict[str, str]:
    require("## Provenance\n" in markdown, "Markdown provenance section is missing")
    fields: dict[str, str] = {}
    for line in markdown.splitlines():
        if not line.startswith("- ") or ": " not in line:
            continue
        label, value = line[2:].split(": ", 1)
        fields[label] = unescape_markdown_provenance_value(value)
    require(
        all(label in fields for label in REQUIRED_PROVENANCE_LABELS),
        "Markdown is missing a required provenance field",
    )
    return fields


def require_docx_field(paragraphs: list[str], label: str, value: str) -> None:
    if is_sha256(value):
        label_paragraph = f"{label}:"
        require(
            any(
                paragraphs[index] == label_paragraph
                and index + 1 < len(paragraphs)
                and paragraphs[index + 1] == value
                for index in range(len(paragraphs))
            ),
            f"DOCX provenance field changed: {label}",
        )
    else:
        require(
            f"{label}: {value}" in paragraphs,
            f"DOCX provenance field changed: {label}",
        )


def check_docx_output(
    docx_path: Path,
    export_root: Path,
    png_bytes: bytes,
    manifest: dict[str, object],
    expected_provenance: dict[str, str],
) -> None:
    expected_source = manifest["expected_source"]
    state_label = manifest["state_label"]
    fallback_alt_text = manifest["fallback_alt_text"]
    require(isinstance(expected_source, str), "DOCX source text is invalid")
    require(isinstance(state_label, str), "DOCX state label is invalid")
    require(isinstance(fallback_alt_text, str), "DOCX fallback caption is invalid")

    text, _, relation_count, paragraphs = check_docx(
        docx_path,
        str(manifest["png_sha256"]),
        fallback_alt_text,
    )
    check_exact_docx_transcript(paragraphs, state_label, expected_source, docx_path.name)
    require(relation_count > 0, "DOCX internal relationships are missing")
    require(fallback_alt_text in text, "DOCX ink fallback caption is missing")
    require(str(manifest["model_revision"]) in text, "DOCX model revision provenance is missing")
    for label in REQUIRED_PROVENANCE_LABELS:
        require_docx_field(paragraphs, label, expected_provenance[label])

    for value in manifest["forbidden_values"]:
        if isinstance(value, str) and value:
            require(value not in text, "private value appeared in extracted DOCX text")
    forbidden_values = [
        value.encode("utf-8")
        for value in manifest["forbidden_values"]
        if isinstance(value, str) and value
    ]
    with zipfile.ZipFile(docx_path, "r") as package:
        for name in package.namelist():
            if name.endswith((".xml", ".rels")) or name == "[Content_Types].xml":
                decoded_part = package.read(name)
                for forbidden in forbidden_values:
                    require(forbidden not in decoded_part, "private value appeared in decoded DOCX XML")

    require(png_bytes == (export_root / "assets" / "selected-region.png").read_bytes(),
            "selected PNG changed after DOCX creation")


def check_pdf_output(
    pdf_path: Path,
    export_root: Path,
    proof_root: Path,
    manifest: dict[str, object],
    expected_provenance: dict[str, str],
    java: str,
    javac: str,
    pdfbox_jar: Path,
    proof_source: Path,
) -> None:
    expected_source = manifest["expected_source"]
    state_label = manifest["state_label"]
    require(isinstance(expected_source, str), "PDF source text is invalid")
    require(isinstance(state_label, str), "PDF state label is invalid")

    expected_text_path = proof_root / "expected-human-text.txt"
    require(expected_text_path.is_file(), "temporary expected source text is missing")
    require(
        expected_text_path.read_bytes().decode("utf-8") == expected_source,
        "temporary expected source text differs from the manifest",
    )
    forbidden_values_path = proof_root / "forbidden-values.txt"
    with forbidden_values_path.open("x", encoding="utf-8", newline="\n") as stream:
        for value in manifest["forbidden_values"]:
            if isinstance(value, str) and value:
                stream.write(value + "\n")

    expected_provenance_path = proof_root / "expected-provenance.tsv"
    expected_provenance_bytes = 0
    with expected_provenance_path.open("x", encoding="utf-8", newline="\n") as stream:
        for label in REQUIRED_PROVENANCE_LABELS:
            value = expected_provenance[label]
            require(
                "\t" not in label + value and "\r" not in label + value and "\n" not in label + value,
                "expected provenance fields must be single-line TSV values",
            )
            record = f"{label}\t{value}\n"
            expected_provenance_bytes += len(record.encode("utf-8"))
            require(expected_provenance_bytes <= 256 * 1024,
                    "expected provenance file exceeds its temporary size cap")
            stream.write(record)

    class_dir = proof_root / "pdfbox-classes"
    class_dir.mkdir()
    run_quiet(
        [
            javac,
            "-encoding",
            "UTF-8",
            "-cp",
            str(pdfbox_jar),
            "-d",
            str(class_dir),
            str(proof_source),
        ],
        "PDFBox verifier compilation",
    )
    proof_json_path = proof_root / "pdfbox-proof.json"
    classpath = os.pathsep.join((str(class_dir), str(pdfbox_jar)))
    png_path = export_root / "assets" / "selected-region.png"
    run_quiet(
        [
            java,
            "-cp",
            classpath,
            "DocumentExportPdfProof",
            str(pdf_path),
            str(expected_text_path),
            str(proof_json_path),
            "96",
            str(png_path),
            state_label,
            str(forbidden_values_path),
            str(expected_provenance_path),
        ],
        "PDFBox production structure proof",
    )
    proof = json.loads(proof_json_path.read_text(encoding="utf-8"))
    require(proof.get("page_count", 97) <= 96, "production PDF exceeds the 96-page cap")
    require(proof.get("embedded_image_xobject_count") == 1, "production PDF image count changed")
    for key in (
        "embedded_png_pixels_match_fixture_on_final_page",
        "source_sequence_checked",
        "to_unicode_matches_visible_source",
        "pdf_text_stripper_matches_input",
        "actual_text_associated_with_matching_glyph_text",
        "provenance_fields_checked",
        "provenance_fields_raw_cmap_matches",
        "provenance_fields_pdf_text_stripper_matches",
        "provenance_fields_actualtext_matches",
        "private_values_absent_from_decoded_text_and_info",
    ):
        require(proof.get(key) is True, f"PDFBox production proof failed: {key}")
    expected_digest = hashlib.sha256(expected_source.encode("utf-8")).hexdigest()
    require(proof.get("expected_utf8_sha256") == expected_digest,
            "PDFBox proof used a different expected source text")

    extracted_path = proof_root / "pdfbox-extracted.txt"
    run_quiet(
        [
            java,
            "-jar",
            str(pdfbox_jar),
            "export:text",
            f"-i={pdf_path}",
            f"-o={extracted_path}",
            "-encoding=UTF-8",
        ],
        "PDFBox production text extraction",
    )
    extracted_text = extracted_path.read_bytes().decode("utf-8")
    require(state_label in extracted_text, "PDF state label is missing from independent extraction")
    require(str(manifest["model_revision"]) in extracted_text,
            "PDF model revision provenance is missing")
    for value in manifest["forbidden_values"]:
        if isinstance(value, str) and value:
            require(value not in extracted_text, "private value appeared in extracted PDF text")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--export-dir", required=True, type=Path)
    parser.add_argument("--proof-dir", required=True, type=Path)
    parser.add_argument("--java", required=True)
    parser.add_argument("--javac", required=True)
    parser.add_argument("--pdfbox-jar", required=True, type=Path)
    parser.add_argument("--proof-source", required=True, type=Path)
    args = parser.parse_args()

    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    export_root = args.export_dir.resolve(strict=True)
    proof_root = args.proof_dir.resolve(strict=True)
    require(export_root.parent == runner_temp, "production exports must be direct children of RUNNER_TEMP")
    require(proof_root.parent == runner_temp, "production proof files must be direct children of RUNNER_TEMP")
    require(export_root.is_dir() and proof_root.is_dir(), "production export proof directories are missing")
    require(
        {path.name for path in export_root.iterdir()} == {
            "document.md",
            "index.html",
            "document.docx",
            "document.pdf",
            "assets",
        },
        "production output set does not match the four selected formats and PNG asset",
    )
    asset_root = export_root / "assets"
    require(
        asset_root.is_dir() and {path.name for path in asset_root.iterdir()} == {"selected-region.png"},
        "production PNG asset set is incomplete or contains unexpected files",
    )
    published_files = [
        export_root / "document.md",
        export_root / "index.html",
        export_root / "document.docx",
        export_root / "document.pdf",
        asset_root / "selected-region.png",
    ]
    require(
        sum(path.stat().st_size for path in published_files) <= 16 * 1024 * 1024,
        "production published output set exceeds the 16 MiB aggregate cap",
    )

    manifest_path = proof_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("schema_version") == 1, "production proof manifest version changed")
    require(isinstance(manifest.get("forbidden_values"), list), "private-value scan list is missing")

    expected_provenance = markdown_provenance(
        (export_root / "document.md").read_text(encoding="utf-8")
    )
    forbidden_values = [
        value
        for value in manifest["forbidden_values"]
        if isinstance(value, str) and value
    ]
    markdown = (export_root / "document.md").read_text(encoding="utf-8")
    html = (export_root / "index.html").read_text(encoding="utf-8")
    for value in forbidden_values:
        require(value not in markdown and value not in html,
                "private value appeared in Markdown or HTML output")
    png_bytes = (asset_root / "selected-region.png").read_bytes()
    require(sha256(png_bytes) == expected_provenance["Export PNG SHA-256"],
            "published PNG bytes differ from Markdown raster provenance")
    require(sha256(png_bytes) == manifest.get("png_sha256"),
            "published PNG bytes differ from the frozen production snapshot")

    docx_path = export_root / "document.docx"
    pdf_path = export_root / "document.pdf"
    require(docx_path.is_file() and docx_path.stat().st_size <= MAX_DOCX_BYTES,
            "production DOCX is missing or exceeds its cap")
    require(pdf_path.is_file() and pdf_path.stat().st_size <= MAX_PDF_BYTES,
            "production PDF is missing or exceeds its cap")
    check_docx_output(docx_path, export_root, png_bytes, manifest, expected_provenance)
    check_pdf_output(
        pdf_path,
        export_root,
        proof_root,
        manifest,
        expected_provenance,
        args.java,
        args.javac,
        args.pdfbox_jar.resolve(strict=True),
        args.proof_source.resolve(strict=True),
    )
    print("SenOCR production DOCX/PDF outputs passed independent content, provenance, and privacy checks.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"SenOCR production export proof failed: {error}", file=sys.stderr)
        raise
