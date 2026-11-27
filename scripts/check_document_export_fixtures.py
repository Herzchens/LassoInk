#!/usr/bin/env python3
"""Hosted-only structural and renderer checks for fixed synthetic DOCX/PDF fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import struct
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET
import zlib


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
REL_EXT = ".rels"
MAIN_DOC_CONTENT_TYPE = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
)
DOCX_INTERNAL_RELATION_TYPES = frozenset(
    {
        "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings",
        "http://schemas.microsoft.com/office/2011/relationships/commentsExtended",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
    }
)
MAX_DOCX_BYTES = 4 * 1024 * 1024
MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_PNG_BYTES = 2 * 1024 * 1024
MAX_PDFBOX_TRANSCRIPT_EXCERPT_BYTES = 512
MAX_RENDERED_PAGE_PIXELS = 4_000_000
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_png_rows(data: bytes, name: str) -> tuple[int, int, int, int, list[bytes]]:
    require(data.startswith(PNG_SIGNATURE), f"invalid PNG signature: {name}")
    width = height = bit_depth = color_type = None
    idat_parts: list[bytes] = []
    offset = len(PNG_SIGNATURE)
    saw_end = False
    while offset + 12 <= len(data):
        chunk_length = struct.unpack_from(">I", data, offset)[0]
        chunk_type = data[offset + 4 : offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + chunk_length
        require(payload_end + 4 <= len(data), f"truncated PNG chunk: {name}")
        payload = data[payload_start:payload_end]
        if chunk_type == b"IHDR":
            require(chunk_length == 13, f"invalid PNG IHDR length: {name}")
            (
                width,
                height,
                bit_depth,
                color_type,
                compression_method,
                filter_method,
                interlace_method,
            ) = struct.unpack(">IIBBBBB", payload)
            require(
                compression_method == 0 and filter_method == 0 and interlace_method == 0,
                f"unsupported PNG encoding: {name}",
            )
        elif chunk_type == b"IDAT":
            idat_parts.append(payload)
        elif chunk_type == b"IEND":
            saw_end = True
            break
        offset = payload_end + 4

    require(saw_end and width and height, f"incomplete PNG: {name}")
    require(width * height <= MAX_RENDERED_PAGE_PIXELS, f"PNG pixel cap exceeded: {name}")
    require(bit_depth == 8, f"unsupported PNG bit depth: {name}")
    channels_by_color_type = {0: 1, 2: 3, 4: 2, 6: 4}
    channels = channels_by_color_type.get(color_type)
    require(channels is not None, f"unsupported PNG color type: {name}")

    bytes_per_pixel = channels
    row_bytes = width * bytes_per_pixel
    decompressed = zlib.decompress(b"".join(idat_parts))
    require(
        len(decompressed) == height * (row_bytes + 1),
        f"PNG pixel data length is invalid: {name}",
    )

    rows: list[bytes] = []
    previous = bytearray(row_bytes)
    source_offset = 0
    for _ in range(height):
        filter_type = decompressed[source_offset]
        source_offset += 1
        encoded = decompressed[source_offset : source_offset + row_bytes]
        source_offset += row_bytes
        row = bytearray(row_bytes)
        for index, value in enumerate(encoded):
            left = row[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            up = previous[index]
            upper_left = previous[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            if filter_type == 0:
                reconstructed = value
            elif filter_type == 1:
                reconstructed = value + left
            elif filter_type == 2:
                reconstructed = value + up
            elif filter_type == 3:
                reconstructed = value + ((left + up) // 2)
            elif filter_type == 4:
                predictor = left + up - upper_left
                left_distance = abs(predictor - left)
                up_distance = abs(predictor - up)
                diagonal_distance = abs(predictor - upper_left)
                if left_distance <= up_distance and left_distance <= diagonal_distance:
                    nearest = left
                elif up_distance <= diagonal_distance:
                    nearest = up
                else:
                    nearest = upper_left
                reconstructed = value + nearest
            else:
                raise RuntimeError(f"unsupported PNG filter type {filter_type}: {name}")
            row[index] = reconstructed & 0xFF
        rows.append(bytes(row))
        previous = row
    return width, height, color_type, channels, rows


def marker_color(pixel: tuple[int, int, int, int]) -> str | None:
    red, green, blue, alpha = pixel
    if alpha < 128:
        return None
    if red >= 192 and green <= 80 and blue <= 80:
        return "top_left_red"
    if green >= 160 and red <= 80 and blue <= 80:
        return "top_right_green"
    if blue >= 192 and red <= 80 and green <= 80:
        return "bottom_left_blue"
    if red >= 192 and 150 <= green < 240 and blue <= 80:
        return "bottom_right_yellow"
    return None


def inspect_corner_marker(
    image_bytes: bytes, name: str
) -> tuple[int, int, dict[str, tuple[int, int, int, int]]]:
    width, height, color_type, channels, rows = decode_png_rows(image_bytes, name)
    markers: dict[str, dict[str, int]] = {
        color: {
            "min_x": width,
            "min_y": height,
            "max_x": -1,
            "max_y": -1,
            "count": 0,
        }
        for color in (
            "top_left_red",
            "top_right_green",
            "bottom_left_blue",
            "bottom_right_yellow",
        )
    }
    for y, row in enumerate(rows):
        for x in range(width):
            offset = x * channels
            if color_type in (0, 4):
                red = green = blue = row[offset]
                alpha = row[offset + 1] if color_type == 4 else 255
            else:
                red, green, blue = row[offset : offset + 3]
                alpha = row[offset + 3] if color_type == 6 else 255
            color = marker_color((red, green, blue, alpha))
            if color is None:
                continue
            marker = markers[color]
            marker["min_x"] = min(marker["min_x"], x)
            marker["min_y"] = min(marker["min_y"], y)
            marker["max_x"] = max(marker["max_x"], x)
            marker["max_y"] = max(marker["max_y"], y)
            marker["count"] += 1
    bounds: dict[str, tuple[int, int, int, int]] = {}
    for color, marker in markers.items():
        require(marker["count"] > 0, f"synthetic image marker missing ({color}): {name}")
        bounds[color] = (
            marker["min_x"],
            marker["min_y"],
            marker["max_x"],
            marker["max_y"],
        )
    return width, height, bounds


def check_docx_maximum_lines_image_page(
    page_png: Path, source_png: bytes
) -> dict[str, object]:
    source_width, source_height, source_markers = inspect_corner_marker(
        source_png, "synthetic source PNG"
    )
    expected_source_markers = {
        "top_left_red": (0, 0, 7, 7),
        "top_right_green": (26, 0, 31, 9),
        "bottom_left_blue": (0, 27, 9, 31),
        "bottom_right_yellow": (27, 24, 31, 31),
    }
    require(
        (source_width, source_height) == (32, 32)
        and source_markers == expected_source_markers,
        "synthetic image marker layout changed",
    )

    page_bytes = page_png.read_bytes()
    page_width, page_height, page_markers = inspect_corner_marker(
        page_bytes, page_png.name
    )
    image_left = min(bounds[0] for bounds in page_markers.values())
    image_top = min(bounds[1] for bounds in page_markers.values())
    image_right = max(bounds[2] for bounds in page_markers.values())
    image_bottom = max(bounds[3] for bounds in page_markers.values())
    image_width = image_right - image_left + 1
    image_height = image_bottom - image_top + 1
    source_aspect = source_width / source_height
    rendered_aspect = image_width / image_height
    require(
        abs(rendered_aspect - source_aspect) <= 0.05,
        "DOCX rendered image aspect ratio differs from the source marker",
    )
    require(
        image_width >= page_width * 0.70 and image_height >= page_height * 0.50,
        "DOCX rendered image bounds are clipped or too small",
    )

    tolerance = max(3, round(min(image_width, image_height) * 0.05))
    require(
        page_markers["top_left_red"][0] <= image_left + tolerance
        and page_markers["top_left_red"][1] <= image_top + tolerance,
        "DOCX rendered top-left marker is missing from the image corner",
    )
    require(
        page_markers["top_right_green"][2] >= image_right - tolerance
        and page_markers["top_right_green"][1] <= image_top + tolerance,
        "DOCX rendered top-right marker is missing from the image corner",
    )
    require(
        page_markers["bottom_left_blue"][0] <= image_left + tolerance
        and page_markers["bottom_left_blue"][3] >= image_bottom - tolerance,
        "DOCX rendered bottom-left marker is missing from the image corner",
    )
    require(
        page_markers["bottom_right_yellow"][2] >= image_right - tolerance
        and page_markers["bottom_right_yellow"][3] >= image_bottom - tolerance,
        "DOCX rendered bottom-right marker is missing from the image corner",
    )

    return {
        "page_png": page_png.name,
        "source_png_sha256": sha256(source_png),
        "source_png_dimensions": [source_width, source_height],
        "source_marker_bounds": {
            name: list(bounds) for name, bounds in source_markers.items()
        },
        "rendered_page_dimensions": [page_width, page_height],
        "rendered_image_bounds": [image_left, image_top, image_right, image_bottom],
        "rendered_image_aspect_ratio": round(rendered_aspect, 4),
        "rendered_marker_bounds": {
            name: list(bounds) for name, bounds in page_markers.items()
        },
        "four_distinct_marker_corners_visible": True,
    }


def extract_delimited_transcript(text: str, name: str) -> str:
    start = text.find("[[")
    end = text.find("]]", start + 2) if start >= 0 else -1
    require(start >= 0 and end >= start, f"transcript markers are missing from {name}")
    return text[start : end + 2]


def capture_pdfbox_transcript_excerpt(text: str) -> dict[str, object]:
    start = text.find("[[")
    if start < 0:
        return {"status": "missing-start-marker", "excerpt": None, "byte_count": None}
    end = text.find("]]", start + 2)
    if end < start:
        return {"status": "missing-end-marker", "excerpt": None, "byte_count": None}
    excerpt = text[start : end + 2]
    byte_count = len(excerpt.encode("utf-8"))
    if byte_count > MAX_PDFBOX_TRANSCRIPT_EXCERPT_BYTES:
        return {"status": "over-cap", "excerpt": None, "byte_count": byte_count}
    return {"status": "captured", "excerpt": excerpt, "byte_count": byte_count}


def contains_exact_linefeed_run(text: str, expected_count: int) -> bool:
    return any(len(match.group(0)) == expected_count for match in re.finditer(r"\n+", text))


def safe_fixture_name(name: str) -> str:
    require(name and Path(name).name == name, f"fixture name is not a basename: {name!r}")
    require("/" not in name and "\\" not in name, f"fixture name contains a path: {name!r}")
    return name


def relationship_source_part(rels_name: str) -> PurePosixPath:
    path = PurePosixPath(rels_name)
    if rels_name == "_rels/.rels":
        return PurePosixPath(".")
    require(path.parent.name == "_rels", f"unexpected relationships location: {rels_name}")
    return path.parent.parent


def check_relationships(zipped: zipfile.ZipFile, names: set[str]) -> int:
    count = 0
    for rels_name in sorted(name for name in names if name.endswith(REL_EXT)):
        root = ET.fromstring(zipped.read(rels_name))
        require(root.tag == f"{{{REL_NS}}}Relationships", "invalid relationships root")
        source_parent = relationship_source_part(rels_name)
        for relation in root.findall(f"{{{REL_NS}}}Relationship"):
            count += 1
            target_mode = relation.attrib.get("TargetMode", "Internal")
            target = relation.attrib.get("Target", "")
            relation_type = relation.attrib.get("Type", "")
            require(target_mode == "Internal", "non-internal DOCX relationship is forbidden")
            require(
                relation_type in DOCX_INTERNAL_RELATION_TYPES,
                "unexpected or active DOCX relationship type is forbidden",
            )
            require(target and not target.startswith(("/", "\\")), "unsafe relationship target")
            require(":" not in target and "\\" not in target, "URI or backslash relationship target")
            require("?" not in target and "#" not in target, "query or fragment relationship target")
            resolved = posixpath.normpath((source_parent / target).as_posix())
            require(resolved != ".." and not resolved.startswith("../"), "relationship escapes package")
            require(resolved in names, f"relationship target is missing: {resolved}")
    return count


def extract_docx_text(
    document_root: ET.Element,
) -> tuple[str, int, int, list[str], list[int], list[int]]:
    paragraphs: list[str] = []
    page_breaks = 0
    image_paragraphs = 0
    page_break_paragraphs: list[int] = []
    image_paragraph_indices: list[int] = []
    for paragraph_index, paragraph in enumerate(document_root.iter(f"{{{W_NS}}}p")):
        parts: list[str] = []
        has_image = False
        for node in paragraph.iter():
            if node.tag == f"{{{W_NS}}}t":
                parts.append(node.text or "")
            elif node.tag == f"{{{W_NS}}}tab":
                parts.append("\t")
            elif node.tag == f"{{{W_NS}}}br":
                break_type = node.attrib.get(f"{{{W_NS}}}type", "textWrapping")
                if break_type == "page":
                    page_breaks += 1
                    page_break_paragraphs.append(paragraph_index)
                else:
                    parts.append("\n")
            elif node.tag == f"{{{W_NS}}}drawing":
                has_image = True
        if has_image:
            image_paragraphs += 1
            image_paragraph_indices.append(paragraph_index)
        paragraphs.append("".join(parts))
    return (
        "\n".join(paragraphs),
        page_breaks,
        image_paragraphs,
        paragraphs,
        page_break_paragraphs,
        image_paragraph_indices,
    )


def check_exact_docx_transcript(
    paragraphs: list[str], state_label: str, expected_source: str | None, name: str
) -> None:
    try:
        state_index = paragraphs.index(state_label)
    except ValueError as error:
        raise RuntimeError(f"DOCX state label is missing: {name}") from error
    transcript_index = state_index + 1
    require(transcript_index < len(paragraphs), f"DOCX transcript boundary is missing: {name}")
    if expected_source is None:
        require(paragraphs[transcript_index] == "Provenance", f"absent transcript was not preserved: {name}")
    else:
        require(paragraphs[transcript_index] == expected_source, f"exact DOCX transcript scalars changed: {name}")


def check_docx(
    path: Path, expected_png_hash: str, fallback_alt_text: str
) -> tuple[str, int, int, list[str]]:
    require(path.stat().st_size <= MAX_DOCX_BYTES, "DOCX exceeds the 4 MiB output cap")
    with zipfile.ZipFile(path, "r") as zipped:
        infos = zipped.infolist()
        names_list = [info.filename for info in infos]
        names = set(names_list)
        require(len(names) == len(names_list), "DOCX contains duplicate ZIP members")
        for name in names:
            member_path = PurePosixPath(name)
            require(not member_path.is_absolute() and ".." not in member_path.parts and "\\" not in name, "unsafe ZIP member path")
        for info in infos:
            mode = info.external_attr >> 16
            require((mode & 0o170000) != 0o120000, "DOCX contains a symlink member")
        require("[Content_Types].xml" in names, "DOCX missing content types")
        require("word/document.xml" in names, "DOCX missing main document")

        forbidden_parts = ("vbaproject", "activex", "embeddings", "webextensions")
        for name in names:
            lowered = name.casefold()
            require(not any(token in lowered for token in forbidden_parts), "active DOCX part is forbidden")
            require(not lowered.endswith((".html", ".htm", ".mhtml", ".js")), "active HTML/script part is forbidden")

        content_types = ET.fromstring(zipped.read("[Content_Types].xml"))
        overrides = {
            item.attrib.get("PartName", ""): item.attrib.get("ContentType", "")
            for item in content_types.findall(f"{{{CT_NS}}}Override")
        }
        defaults = {
            item.attrib.get("Extension", "").casefold(): item.attrib.get("ContentType", "")
            for item in content_types.findall(f"{{{CT_NS}}}Default")
        }
        require(overrides.get("/word/document.xml") == MAIN_DOC_CONTENT_TYPE, "unexpected DOCX main content type")
        require("macroenabled" not in " ".join(overrides.values()).casefold(), "macro-enabled DOCX content type")
        require("html" not in " ".join(overrides.values()).casefold(), "HTML content type in DOCX")
        require("javascript" not in " ".join(overrides.values()).casefold(), "script content type in DOCX")
        require(defaults.get("png", "").startswith("image/png"), "PNG content type missing")

        relation_count = check_relationships(zipped, names)
        require(relation_count > 0, "DOCX has no relationships")

        for name in names:
            if name.endswith((".xml", ".rels")) or name == "[Content_Types].xml":
                content = zipped.read(name)
                require(re.search(rb"\b[A-Za-z]:[\\/]", content) is None, "absolute drive path leaked into DOCX")
                lowered = content.lower()
                for canary in (b"private-synthetic-journal-path-canary", b"herzchen", b"runner_temp"):
                    require(canary not in lowered, "private path or user canary leaked into DOCX")
                ET.fromstring(content)

        image_parts = sorted(name for name in names if name.startswith("word/media/") and name.casefold().endswith(".png"))
        require(len(image_parts) == 1, "DOCX must contain exactly one internal PNG image")
        image_bytes = zipped.read(image_parts[0])
        require(len(image_bytes) <= MAX_PNG_BYTES, "DOCX PNG exceeds the 2 MiB raster cap")
        image_hash = sha256(image_bytes)
        require(image_hash == expected_png_hash, "DOCX image bytes do not match raster provenance hash")

        document_root = ET.fromstring(zipped.read("word/document.xml"))
        active_elements = {
            f"{{{W_NS}}}altChunk",
            f"{{{W_NS}}}hyperlink",
            f"{{{W_NS}}}object",
        }
        require(
            not any(node.tag in active_elements for node in document_root.iter()),
            "active HTML, link, or object content is forbidden",
        )
        (
            text,
            page_breaks,
            image_paragraphs,
            paragraph_texts,
            page_break_paragraphs,
            image_paragraph_indices,
        ) = extract_docx_text(document_root)
        require(expected_png_hash in text, "DOCX raster provenance is missing the selected PNG hash")
        require(page_breaks >= 1, "DOCX ink image must start after an explicit page break")
        require(image_paragraphs == 1, "DOCX must contain one image paragraph")
        image_index = image_paragraph_indices[0]
        require(image_index == len(paragraph_texts) - 1, "DOCX image is not the final paragraph")
        caption_index = image_index - 1
        require(caption_index >= 1, "DOCX image caption is missing")
        require(paragraph_texts[caption_index] == fallback_alt_text, "DOCX caption differs from IR fallback alt text")
        require(
            page_break_paragraphs and page_break_paragraphs[-1] == caption_index - 1,
            "DOCX final ink page break is not immediately before its caption",
        )
        return text, page_breaks, relation_count, paragraph_texts


def run_command(command: list[str], *, cwd: Path | None = None) -> None:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        detail = (result.stdout + "\n" + result.stderr)[-8000:]
        raise RuntimeError(f"command failed ({result.returncode}): {Path(command[0]).name}\n{detail}")


def check_extracted_text(
    text: str,
    expected_png_hash: str,
    expected_source: str | None,
    expected_state_label: str,
    name: str,
    check_source_sequence: bool = True,
) -> str:
    excerpt = extract_raster_hash_provenance_excerpt(text, expected_png_hash, name)
    require(expected_state_label in text, f"transcript state label missing from extracted text: {name}")
    require("PRIVATE-SYNTHETIC-JOURNAL-PATH-CANARY" not in text, f"private source canary leaked: {name}")
    require("Herzchen" not in text and "RUNNER_TEMP" not in text, f"runner or user path canary leaked: {name}")
    require(re.search(r"\b[A-Za-z]:[\\/]", text) is None, f"absolute drive path leaked: {name}")
    if expected_source is not None and check_source_sequence:
        if expected_source and all(character == "\n" for character in expected_source):
            require(
                contains_exact_linefeed_run(text, len(expected_source)),
                f"PDFBox did not extract the exact consecutive source line feeds: {name}",
            )
        else:
            require(
                extract_delimited_transcript(text, name) == expected_source,
                f"isolated transcript scalar sequence changed: {name}",
            )
    return excerpt


def extract_raster_hash_provenance_excerpt(
    text: str, expected_png_hash: str, name: str
) -> str:
    label = "Export PNG SHA-256:"
    label_start = text.find(label)
    require(label_start >= 0, f"raster provenance label missing from extracted text: {name}")
    value_start = label_start + len(label)
    if text.startswith("\r\n", value_start):
        value_start += 2
    elif text.startswith("\n", value_start):
        value_start += 1
    else:
        raise RuntimeError(f"raster digest is not on its own extracted line: {name}")
    require(
        text.startswith(expected_png_hash, value_start),
        f"contiguous raster provenance digest missing from extracted text: {name}",
    )
    excerpt_end = value_start + len(expected_png_hash)
    return text[label_start:excerpt_end]


def pdfbox_export_text(java: str, pdfbox_jar: Path, pdf: Path, destination: Path) -> str:
    run_command([
        java,
        "-jar",
        str(pdfbox_jar),
        "export:text",
        f"-i={pdf}",
        f"-o={destination}",
        "-encoding=UTF-8",
    ])
    return destination.read_bytes().decode("utf-8")


def run_pdf_proof(
    java: str,
    class_dir: Path,
    pdfbox_jar: Path,
    pdf: Path,
    expected_text: str | None,
    page_limit: int,
    fixture_png: Path,
    expected_file: Path,
    proof_file: Path,
) -> dict[str, object]:
    if expected_text is None:
        expected_arg = "-"
    else:
        with expected_file.open("w", encoding="utf-8", newline="") as stream:
            stream.write(expected_text)
        expected_arg = str(expected_file)
    classpath = os.pathsep.join((str(class_dir), str(pdfbox_jar)))
    run_command([
        java,
        "-cp",
        classpath,
        "DocumentExportPdfProof",
        str(pdf),
        expected_arg,
        str(proof_file),
        str(page_limit),
        str(fixture_png),
    ])
    return json.loads(proof_file.read_text(encoding="utf-8"))


def render_pdfbox(java: str, pdfbox_jar: Path, pdf: Path, output_dir: Path, prefix: str) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    prefix_path = output_dir / prefix
    run_command([
        java,
        "-jar",
        str(pdfbox_jar),
        "render",
        f"-i={pdf}",
        "-format=png",
        "-dpi=120",
        f"-prefix={prefix_path}",
    ])
    images = list(output_dir.glob(f"{prefix}-*.png"))
    require(bool(images), f"PDFBox rendered no PNG pages for {pdf.name}")
    for image in images:
        page_number = image.stem.rsplit("-", 1)[-1]
        require(page_number.isdecimal(), f"unexpected PDFBox page filename: {image.name}")
    images.sort(key=lambda image: int(image.stem.rsplit("-", 1)[-1]))
    require(all(path.stat().st_size > 0 for path in images), "PDFBox emitted an empty page image")
    return images


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--soffice", required=True)
    parser.add_argument("--java", required=True)
    parser.add_argument("--javac", required=True)
    parser.add_argument("--pdfbox-jar", required=True, type=Path)
    parser.add_argument("--proof-source", required=True, type=Path)
    args = parser.parse_args()

    fixture_root = args.fixtures.resolve(strict=True)
    scratch = args.scratch.resolve()
    artifact_root = args.artifact_root.resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(fixture_root.is_relative_to(runner_temp), "fixtures must stay under RUNNER_TEMP")
    require(scratch.is_relative_to(runner_temp), "renderer scratch must stay under RUNNER_TEMP")
    require(artifact_root.is_relative_to(runner_temp), "renderer artifacts must stay under RUNNER_TEMP")
    scratch.mkdir(parents=True, exist_ok=True)
    artifact_root.mkdir(parents=True, exist_ok=True)
    render_root = artifact_root / "rendered-pages"
    proof_root = artifact_root / "structural-proof"
    render_root.mkdir(parents=True, exist_ok=True)
    proof_root.mkdir(parents=True, exist_ok=True)

    manifest = json.loads((fixture_root / "manifest.json").read_text(encoding="utf-8"))
    require(manifest.get("fixtures_are_fixed_synthetic_inputs") is True, "fixture manifest must identify fixed synthetic inputs")
    require(manifest.get("maximum_input_utf8_bytes") == 4096, "unexpected input byte cap")
    require(manifest.get("maximum_logical_lines") == 4097, "maximum 4097 lines must remain accepted")
    require(manifest.get("pdf_page_limit") == 96, "unexpected PDF page cap")
    required_origins = {
        "InkOnly",
        "NoProviderCandidate",
        "Provider",
        "SetText",
        "Reset",
    }
    require(required_origins.issubset({case["origin"] for case in manifest["cases"]}), "one or more transcript origins are missing")
    by_name = {case["name"]: case for case in manifest["cases"]}
    maximum_text = by_name["maximum-lines"]["source_text"]
    require(len(maximum_text.encode("utf-8")) == 4096, "maximum line fixture is not exactly 4096 input bytes")
    require(maximum_text.count("\n") + 1 == 4097, "maximum line fixture is not exactly 4097 logical lines")
    require(by_name["line-order"]["source_text"] == "[[first line\nsecond line\nthird line]]", "line-order fixture changed")
    require(
        by_name["nfd-vietnamese"]["source_text"] == "[[NFD: a\u0302\u0301]]",
        "NFD Vietnamese source scalars changed",
    )
    require(by_name["nfc-vietnamese"]["source_text"] == "[[NFC: ấ]]", "NFC Vietnamese source scalars changed")
    require(
        manifest.get("unsupported_pdf_scalars_rejected")
        == ["U+0001", "U+000B", "U+000C", "U+007F", "U+0085", "U+009F", "U+2028", "U+2029"],
        "PDF control-rejection fixture changed",
    )
    expected_png_hash = manifest["png_sha256"]
    fallback_alt_text = manifest["fallback_alt_text"]
    png_bytes = (fixture_root / manifest["selected_ink_png"]).read_bytes()
    require(sha256(png_bytes) == expected_png_hash, "synthetic PNG hash differs from manifest")
    require(len(png_bytes) <= MAX_PNG_BYTES, "synthetic PNG exceeds the 2 MiB raster cap")

    docx_checks: list[dict[str, object]] = []
    docx_paths: list[Path] = []
    docx_state_by_name: dict[str, str] = {}
    case_by_pdf_name: dict[str, dict[str, object]] = {}
    for case in manifest["cases"]:
        docx_name = safe_fixture_name(case["docx"])
        docx_path = fixture_root / docx_name
        require(docx_path.is_file() and docx_path.stat().st_size <= MAX_DOCX_BYTES, f"DOCX exceeds the 4 MiB output cap: {docx_name}")
        text, page_breaks, relationship_count, paragraph_texts = check_docx(
            docx_path, case["png_sha256"], fallback_alt_text
        )
        expected_text = case["source_text"]
        check_exact_docx_transcript(paragraph_texts, case["state_label"], expected_text, docx_name)
        docx_checks.append({
            "fixture": docx_name,
            "internal_relationship_count": relationship_count,
            "explicit_final_image_page_break": page_breaks >= 1,
            "exact_source_scalar_sequence": True,
            "png_sha256_matches_manifest": True,
        })
        docx_paths.append(docx_path)
        docx_state_by_name[docx_name] = case["state_label"]
        case_by_pdf_name[case["pdf"]] = case

    c1_docx_name = safe_fixture_name(manifest["xml_valid_controls_docx"])
    c1_docx_path = fixture_root / c1_docx_name
    require(c1_docx_path.is_file() and c1_docx_path.stat().st_size <= MAX_DOCX_BYTES, "XML-control DOCX exceeds the 4 MiB output cap")
    c1_docx_text, c1_page_breaks, c1_relation_count, c1_paragraphs = check_docx(
        c1_docx_path, expected_png_hash, fallback_alt_text
    )
    c1_expected = manifest["xml_valid_controls_expected"]
    c1_state_label = manifest["xml_valid_controls_state_label"]
    check_exact_docx_transcript(c1_paragraphs, c1_state_label, c1_expected, c1_docx_name)
    require(manifest.get("xml_forbidden_control_docx_rejected") is True, "XML-forbidden control rejection fixture is absent")
    docx_checks.append({
        "fixture": c1_docx_name,
        "internal_relationship_count": c1_relation_count,
        "explicit_final_image_page_break": c1_page_breaks >= 1,
        "exact_source_scalar_sequence": True,
        "png_sha256_matches_manifest": True,
    })
    docx_paths.append(fixture_root / c1_docx_name)
    docx_state_by_name[c1_docx_name] = c1_state_label

    proof_source = args.proof_source.resolve(strict=True)
    class_dir = scratch / "pdfbox-classes"
    class_dir.mkdir(parents=True, exist_ok=True)
    run_command([
        args.javac,
        "-encoding",
        "UTF-8",
        "-cp",
        str(args.pdfbox_jar.resolve(strict=True)),
        "-d",
        str(class_dir),
        str(proof_source),
    ])

    docx_pdf_dir = scratch / "libreoffice-pdf"
    docx_pdf_dir.mkdir(parents=True, exist_ok=True)
    lo_profile = scratch / "libreoffice-profile"
    lo_profile.mkdir(parents=True, exist_ok=True)
    lo_profile_uri = lo_profile.as_uri()
    converted_docx_pdfs: list[Path] = []
    for docx_path in docx_paths:
        run_command([
            args.soffice,
            "--headless",
            f"-env:UserInstallation={lo_profile_uri}",
            "--convert-to",
            "pdf",
            "--outdir",
            str(docx_pdf_dir),
            str(docx_path),
        ])
        converted = docx_pdf_dir / f"{docx_path.stem}.pdf"
        require(converted.is_file() and converted.stat().st_size > 0, f"LibreOffice did not render {docx_path.name}")
        converted_docx_pdfs.append(converted)

    strict_cases = {
        case["pdf"]: case["source_text"]
        for case in manifest["cases"]
        if case.get("strict_pdf_text") is True
    }
    generated_pdfs = [fixture_root / safe_fixture_name(case["pdf"]) for case in manifest["cases"]]
    for pdf_path in generated_pdfs:
        require(pdf_path.is_file() and pdf_path.stat().st_size <= MAX_PDF_BYTES, f"PDF exceeds the 8 MiB output cap: {pdf_path.name}")
    pdf_proofs: list[dict[str, object]] = []
    for pdf_path in generated_pdfs:
        case = case_by_pdf_name[pdf_path.name]
        expected = strict_cases.get(pdf_path.name)
        state_label = case["state_label"]
        expected_path = scratch / f"expected-pdf-{pdf_path.stem}.txt"
        proof_path = proof_root / f"pdf-{pdf_path.stem}.json"
        proof = run_pdf_proof(
            args.java,
            class_dir,
            args.pdfbox_jar,
            pdf_path,
            expected,
            manifest["pdf_page_limit"],
            fixture_root / manifest["selected_ink_png"],
            expected_path,
            proof_path,
        )
        require(proof["page_count"] <= manifest["pdf_page_limit"], f"PDF exceeds manifest page cap: {pdf_path.name}")
        require(
            proof["embedded_png_pixels_match_fixture_on_final_page"] is True,
            f"embedded image pixels differ: {pdf_path.name}",
        )

        text_path = scratch / f"pdf-{pdf_path.stem}.txt"
        extracted_text = pdfbox_export_text(args.java, args.pdfbox_jar, pdf_path, text_path)
        linefeed_only = expected is not None and bool(expected) and all(character == "\n" for character in expected)
        strict_source_proof = expected is not None and bool(expected) and not linefeed_only
        if strict_source_proof:
            for proof_field in (
                "source_sequence_checked",
                "to_unicode_matches_visible_source",
                "pdf_text_stripper_matches_input",
                "actual_text_associated_with_matching_glyph_text",
            ):
                require(
                    proof.get(proof_field) is True,
                    f"strict PDF source proof failed ({proof_field}): {pdf_path.name}",
                )
        if expected is not None and expected and not linefeed_only:
            transcript_diagnostic = capture_pdfbox_transcript_excerpt(extracted_text)
            proof["pdfbox_cli_transcript_excerpt_status"] = transcript_diagnostic["status"]
            proof["pdfbox_cli_transcript_excerpt_bytes"] = transcript_diagnostic["byte_count"]
            if transcript_diagnostic["excerpt"] is not None:
                proof["pdfbox_cli_transcript_excerpt"] = transcript_diagnostic["excerpt"]
            proof_path.write_text(
                json.dumps(proof, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        provenance_excerpt = check_extracted_text(
            extracted_text,
            expected_png_hash,
            expected,
            state_label,
            pdf_path.name,
            check_source_sequence=not linefeed_only and not strict_source_proof,
        )
        proof["pdfbox_raster_provenance_excerpt"] = provenance_excerpt
        images = render_pdfbox(
            args.java,
            args.pdfbox_jar,
            pdf_path,
            render_root,
            f"pdf-{pdf_path.stem}",
        )
        require(len(images) == proof["page_count"], f"rendered page count differs from PDFBox page count: {pdf_path.name}")
        proof["pdfbox_cli_utf8_extraction_ran"] = True
        proof["pdfbox_page_png_count"] = len(images)
        proof_path.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        pdf_proofs.append(proof)

    docx_render_page_counts: dict[str, int] = {}
    docx_pdfbox_raster_provenance_excerpts: dict[str, str] = {}
    docx_maximum_lines_image_page_proof: dict[str, object] | None = None
    for pdf_path in converted_docx_pdfs:
        text_path = scratch / f"docx-{pdf_path.stem}.txt"
        extracted_text = pdfbox_export_text(args.java, args.pdfbox_jar, pdf_path, text_path)
        docx_name = f"{pdf_path.stem}.docx"
        provenance_excerpt = check_extracted_text(
            extracted_text,
            expected_png_hash,
            None,
            docx_state_by_name[docx_name],
            pdf_path.name,
        )
        docx_pdfbox_raster_provenance_excerpts[docx_name] = provenance_excerpt
        images = render_pdfbox(
            args.java,
            args.pdfbox_jar,
            pdf_path,
            render_root,
            f"docx-{pdf_path.stem}",
        )
        if docx_name == "maximum-lines.docx":
            require(bool(images), "maximum-lines DOCX conversion rendered no pages")
            docx_maximum_lines_image_page_proof = check_docx_maximum_lines_image_page(
                images[-1], png_bytes
            )
        docx_render_page_counts[f"{pdf_path.stem}.docx"] = len(images)

    require(
        docx_maximum_lines_image_page_proof is not None,
        "maximum-lines DOCX rendered image proof is missing",
    )
    summary = {
        "fixture_count": len(manifest["cases"]) + 1,
        "fixed_synthetic_inputs_only": True,
        "visual_review_pending": True,
        "docx_checks": docx_checks,
        "pdf_proofs": pdf_proofs,
        "docx_renderer_page_counts": docx_render_page_counts,
        "docx_pdfbox_raster_provenance_excerpts": docx_pdfbox_raster_provenance_excerpts,
        "docx_maximum_lines_image_page_proof": docx_maximum_lines_image_page_proof,
        "pdfbox_png_count": sum(int(proof["pdfbox_page_png_count"]) for proof in pdf_proofs)
        + sum(docx_render_page_counts.values()),
        "max_input_bytes": manifest["maximum_input_utf8_bytes"],
        "max_logical_lines": manifest["maximum_logical_lines"],
        "pdf_page_limit": manifest["pdf_page_limit"],
    }
    summary_path = proof_root / "qa-summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # preserve a failing workflow result with concise diagnostics
        print(f"document-export feasibility QA failed: {error}", file=sys.stderr)
        raise
