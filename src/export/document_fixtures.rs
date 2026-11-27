use sha2::{Digest, Sha256};
use tiny_skia::{Color, Pixmap};

use super::{
    ExportProvenanceV1, ExportRasterProvenanceV1, ExportRegionV1, ExportSourceBindingV1,
    RawInkFallbackV1, TranscriptOriginV1, paragraph_from_text,
};

/// Fixed, model-free source fixture shared by both format serializers. The
/// sentinel identifiers deliberately must never appear in emitted documents.
pub(super) fn synthetic_fixture(
    text: Option<&str>,
    transcript_origin: TranscriptOriginV1,
) -> (ExportRegionV1, Vec<u8>) {
    let mut pixmap = Pixmap::new(32, 32).expect("small synthetic pixmap allocates");
    pixmap.fill(Color::from_rgba8(255, 255, 255, 255));
    // The asymmetric fixed marker makes rendered image bounds and all four
    // corners observable without using real ink.
    paint_marker_rect(pixmap.data_mut(), 0, 0, 8, 8, [255, 0, 0, 255]);
    paint_marker_rect(pixmap.data_mut(), 26, 0, 6, 10, [0, 192, 0, 255]);
    paint_marker_rect(pixmap.data_mut(), 0, 27, 10, 5, [0, 0, 255, 255]);
    paint_marker_rect(pixmap.data_mut(), 27, 24, 5, 8, [255, 200, 0, 255]);
    let selected_ink_png = pixmap.encode_png().expect("synthetic PNG encodes");
    let png_digest: [u8; 32] = Sha256::digest(&selected_ink_png).into();
    let png_sha256 = super::hex_sha256(&png_digest).expect("synthetic digest formats");
    let paragraph = text.map(|value| paragraph_from_text(value).expect("fixture text validates"));

    let region = ExportRegionV1 {
        schema_version: 1,
        transcript_origin,
        paragraph,
        raw_ink_fallback: RawInkFallbackV1 {
            asset_file_name: "assets/selected-region.png",
            alt_text: "Original selected ink",
        },
        provenance: ExportProvenanceV1 {
            source_binding: ExportSourceBindingV1::InkOnly {
                journal_id: "PRIVATE-SYNTHETIC-JOURNAL-PATH-CANARY".to_owned(),
                logical_revision: 7,
                snapshot_last_sequence: 11,
                selected_strokes: Vec::new(),
                source_sample_sequences: Vec::new(),
                stroke_views: Vec::new(),
            },
            source_binding_sha256: "b".repeat(64),
            projection: None,
            raster: ExportRasterProvenanceV1 {
                output_width_px: 32,
                output_height_px: 32,
                source_content_sha256: "a".repeat(64),
                projection_spec_sha256: "c".repeat(64),
                png_bytes_sha256: png_sha256,
                raster_artifact_sha256: "d".repeat(64),
            },
        },
    };

    (region, selected_ink_png)
}

fn paint_marker_rect(pixels: &mut [u8], x: u32, y: u32, width: u32, height: u32, color: [u8; 4]) {
    for row in y..y + height {
        for column in x..x + width {
            let offset = ((row * 32 + column) * 4) as usize;
            pixels[offset..offset + 4].copy_from_slice(&color);
        }
    }
}
