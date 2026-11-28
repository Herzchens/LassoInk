import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

import javax.imageio.ImageIO;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.contentstream.operator.Operator;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSInteger;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSNull;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdfparser.PDFStreamParser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.graphics.PDXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.text.PDFTextStripper;

/** Structural PDF proof for source text; ActualText is inspected separately. */
public final class DocumentExportPdfProof {
    private static final class MarkedSpan {
        private final String actualText;
        private final StringBuilder glyphText = new StringBuilder();

        private MarkedSpan(String actualText) {
            this.actualText = actualText;
        }
    }

    private static final class PageProof {
        private final StringBuilder toUnicodeText = new StringBuilder();
        private final List<MarkedSpan> spans = new ArrayList<>();
    }

    private static final class FinalPageImageCheck {
        private final int imageInvocationCount;
        private final boolean pixelsMatch;
        private final String safeAggregateJson;

        private FinalPageImageCheck(
            int imageInvocationCount,
            boolean pixelsMatch,
            String safeAggregateJson
        ) {
            this.imageInvocationCount = imageInvocationCount;
            this.pixelsMatch = pixelsMatch;
            this.safeAggregateJson = safeAggregateJson;
        }
    }

    private static final class PngMetadata {
        private final int width;
        private final int height;
        private final int bitDepth;
        private final int colorType;

        private PngMetadata(int width, int height, int bitDepth, int colorType) {
            this.width = width;
            this.height = height;
            this.bitDepth = bitDepth;
            this.colorType = colorType;
        }
    }

    private static final class ProvenanceField {
        private final String label;
        private final String value;

        private ProvenanceField(String label, String value) {
            this.label = label;
            this.value = value;
        }
    }

    private DocumentExportPdfProof() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 5 && args.length != 6 && args.length != 7 && args.length != 8) {
            throw new IllegalArgumentException(
                "usage: DocumentExportPdfProof <pdf> <expected-utf8-file-or-dash> <proof-json> <page-limit> <png> [state-label [forbidden-values-file [expected-provenance-tsv]]]"
            );
        }

        Path pdfPath = Path.of(args[0]);
        Path expectedPath = Path.of(args[1]);
        Path proofPath = Path.of(args[2]);
        int pageLimit = Integer.parseInt(args[3]);
        Path fixturePngPath = Path.of(args[4]);
        String stateLabel = args.length >= 6 ? args[5] : null;
        if (args.length >= 7) {
            stateLabel = args[5];
            if (stateLabel.isEmpty()) {
                throw new IllegalArgumentException("state label is required with private-value checks");
            }
        }
        List<String> forbiddenValues = new ArrayList<>();
        if (args.length >= 7) {
            forbiddenValues.addAll(Files.readAllLines(Path.of(args[6]), StandardCharsets.UTF_8));
        }
        forbiddenValues.removeIf(String::isEmpty);
        if (pageLimit < 1 || pageLimit > 96) {
            throw new IllegalArgumentException("manifest PDF page limit is outside the supported bound");
        }
        String expected = "-".equals(args[1])
            ? null
            : Files.readString(expectedPath, StandardCharsets.UTF_8);
        List<ProvenanceField> expectedProvenanceFields = args.length == 8
            ? readExpectedProvenance(Path.of(args[7]))
            : null;
        if (expectedProvenanceFields != null && (stateLabel == null || expected == null)) {
            throw new IllegalArgumentException("expected provenance requires source text and state label");
        }

        try (PDDocument document = Loader.loadPDF(pdfPath.toFile())) {
            int pageCount = document.getNumberOfPages();
            if (pageCount < 1 || pageCount > pageLimit) {
                throw new IllegalStateException("PDF page count exceeds the manifest page bound");
            }
            rejectActiveContent(document);
            BufferedImage fixtureImage = ImageIO.read(fixturePngPath.toFile());
            if (fixtureImage == null) {
                throw new IllegalStateException("fixed fixture PNG could not be decoded");
            }
            PngMetadata sourcePngMetadata = readPngMetadata(fixturePngPath);
            int embeddedImageCount = verifyFinalEmbeddedImage(
                document,
                fixtureImage,
                sourcePngMetadata,
                expectedProvenanceFields != null
            );
            if (embeddedImageCount != 1) {
                throw new IllegalStateException("PDF must contain exactly one embedded image XObject");
            }

            StringBuilder toUnicodeText = new StringBuilder();
            List<MarkedSpan> spans = new ArrayList<>();
            for (PDPage page : document.getPages()) {
                PageProof pageProof = inspectPage(page);
                toUnicodeText.append(pageProof.toUnicodeText);
                spans.addAll(pageProof.spans);
            }

            PDFTextStripper sourceStripper = new PDFTextStripper();
            sourceStripper.setLineSeparator("");
            sourceStripper.setPageStart("");
            sourceStripper.setPageEnd("");
            String strippedText = sourceStripper.getText(document);
            StringBuilder infoText = new StringBuilder();
            COSDictionary infoDictionary = document.getDocumentInformation().getCOSObject();
            for (COSName key : infoDictionary.keySet()) {
                COSBase value = infoDictionary.getDictionaryObject(key);
                if (value instanceof COSString) {
                    infoText.append(((COSString) value).getString()).append('\n');
                }
            }
            byte[] xmpBytes = new byte[0];
            PDMetadata xmpMetadata = document.getDocumentCatalog().getMetadata();
            if (xmpMetadata != null) {
                try (InputStream metadataStream = xmpMetadata.createInputStream()) {
                    xmpBytes = metadataStream.readAllBytes();
                }
            }
            boolean privateValuesAbsent = true;
            for (String privateValue : forbiddenValues) {
                if (strippedText.contains(privateValue)
                    || toUnicodeText.toString().contains(privateValue)
                    || infoText.toString().contains(privateValue)
                    || containsEncodedText(xmpBytes, privateValue)) {
                    privateValuesAbsent = false;
                    break;
                }
                for (MarkedSpan span : spans) {
                    if (span.actualText != null && span.actualText.contains(privateValue)) {
                        privateValuesAbsent = false;
                        break;
                    }
                }
                if (!privateValuesAbsent) {
                    break;
                }
            }
            if (!privateValuesAbsent) {
                throw new IllegalStateException("private path or metadata value appeared in decoded PDF text");
            }
            boolean sourceChecked = expected != null;
            boolean lineFeedOnlySource = sourceChecked && isLineFeedOnly(expected);
            // IR line feeds have no glyph code; verify every visible scalar via
            // ToUnicode and the exact line separators via ActualText/TextStripper.
            String expectedGlyphSequence = sourceChecked ? expected.replace("\n", "") : null;
            String decodedTranscript = stateLabel == null
                ? extractDelimitedTranscript(toUnicodeText.toString())
                : extractStateBoundedTranscript(toUnicodeText.toString(), stateLabel);
            String strippedTranscript = stateLabel == null
                ? extractDelimitedTranscript(strippedText)
                : extractStateBoundedTranscript(strippedText, stateLabel);
            boolean toUnicodeMatch = sourceChecked && !lineFeedOnlySource
                && expectedGlyphSequence.equals(decodedTranscript);
            boolean lineFeedSpansMatch = lineFeedOnlySource && matchesLineFeedSpans(spans, expected.length());
            boolean textStripperMatch = sourceChecked && (lineFeedOnlySource
                ? containsExactLineFeedRun(strippedText, expected.length())
                : expected.equals(strippedTranscript));
            boolean actualTextAssociation = sourceChecked && (lineFeedOnlySource
                ? lineFeedSpansMatch
                : matchesTranscriptSpans(spans, expected));

            if (sourceChecked && !lineFeedOnlySource && !toUnicodeMatch) {
                throw new IllegalStateException("raw glyph-code /ToUnicode text did not match input");
            }
            if (lineFeedOnlySource && !lineFeedSpansMatch) {
                throw new IllegalStateException("consecutive empty-line ActualText spans did not match the LF-only source");
            }
            if (sourceChecked && !textStripperMatch) {
                throw new IllegalStateException("PDFTextStripper text did not match input scalars");
            }
            if (sourceChecked && !actualTextAssociation) {
                throw new IllegalStateException("ActualText was not associated with matching glyph text");
            }

            boolean provenanceFieldsChecked = expectedProvenanceFields != null;
            boolean provenanceRawCMapMatches = false;
            boolean provenanceTextStripperMatches = false;
            boolean provenanceActualTextMatches = false;
            if (provenanceFieldsChecked) {
                if (lineFeedOnlySource) {
                    throw new IllegalStateException("provenance_fields_require_visible_source");
                }
                String expectedProvenance = expectedProvenanceVisibleSequence(expectedProvenanceFields);
                provenanceRawCMapMatches = matchesBoundedProvenanceText(
                    toUnicodeText.toString(),
                    stateLabel,
                    expected,
                    expectedProvenance,
                    true
                );
                if (!provenanceRawCMapMatches) {
                    throw new IllegalStateException("provenance_fields_raw_cmap_mismatch");
                }
                provenanceTextStripperMatches = matchesBoundedProvenanceText(
                    strippedText,
                    stateLabel,
                    expected,
                    expectedProvenance,
                    false
                );
                if (!provenanceTextStripperMatches) {
                    throw new IllegalStateException("provenance_fields_pdf_text_stripper_mismatch");
                }
                provenanceActualTextMatches = matchesProvenanceSpanSequence(
                    spans,
                    stateLabel,
                    expected,
                    expectedProvenanceFields
                );
                if (!provenanceActualTextMatches) {
                    throw new IllegalStateException("provenance_fields_actualtext_mismatch");
                }
            }

            String expectedHash = expected == null ? "" : sha256(expected.getBytes(StandardCharsets.UTF_8));
            String toUnicodeMatchJson = lineFeedOnlySource ? "null" : Boolean.toString(toUnicodeMatch);
            String lineFeedSpansMatchJson = lineFeedOnlySource ? Boolean.toString(lineFeedSpansMatch) : "null";
            String provenanceFieldsCheckedJson = provenanceFieldsChecked ? "true" : "null";
            String provenanceRawCMapMatchesJson = provenanceFieldsChecked
                ? Boolean.toString(provenanceRawCMapMatches)
                : "null";
            String provenanceTextStripperMatchesJson = provenanceFieldsChecked
                ? Boolean.toString(provenanceTextStripperMatches)
                : "null";
            String provenanceActualTextMatchesJson = provenanceFieldsChecked
                ? Boolean.toString(provenanceActualTextMatches)
                : "null";
            String json = "{\n"
                + "  \"fixture\": \"" + escapeJson(pdfPath.getFileName().toString()) + "\",\n"
                + "  \"page_count\": " + pageCount + ",\n"
                + "  \"page_limit\": " + pageLimit + ",\n"
                + "  \"embedded_image_xobject_count\": " + embeddedImageCount + ",\n"
                + "  \"embedded_png_pixels_match_fixture_on_final_page\": true,\n"
                + "  \"source_sequence_checked\": " + sourceChecked + ",\n"
                + "  \"linefeed_only_source_mode\": " + lineFeedOnlySource + ",\n"
                + "  \"to_unicode_matches_visible_source\": " + toUnicodeMatchJson + ",\n"
                + "  \"consecutive_linefeed_actualtext_spans_match_input\": " + lineFeedSpansMatchJson + ",\n"
                + "  \"pdf_text_stripper_matches_input\": " + textStripperMatch + ",\n"
                + "  \"actual_text_associated_with_matching_glyph_text\": " + actualTextAssociation + ",\n"
                + "  \"provenance_fields_checked\": " + provenanceFieldsCheckedJson + ",\n"
                + "  \"provenance_fields_raw_cmap_matches\": " + provenanceRawCMapMatchesJson + ",\n"
                + "  \"provenance_fields_pdf_text_stripper_matches\": " + provenanceTextStripperMatchesJson + ",\n"
                + "  \"provenance_fields_actualtext_matches\": " + provenanceActualTextMatchesJson + ",\n"
                + "  \"private_values_absent_from_decoded_text_and_info\": " + privateValuesAbsent + ",\n"
                + "  \"expected_utf8_sha256\": \"" + expectedHash + "\"\n"
                + "}\n";
            Files.writeString(proofPath, json, StandardCharsets.UTF_8);
        }
    }

    private static List<ProvenanceField> readExpectedProvenance(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        if (lines.isEmpty() || lines.size() > 32) {
            throw new IllegalArgumentException("expected_provenance_fields_invalid");
        }
        Set<String> labels = new HashSet<>();
        List<ProvenanceField> fields = new ArrayList<>();
        for (String line : lines) {
            int separator = line.indexOf('\t');
            if (separator <= 0
                || line.indexOf('\t', separator + 1) >= 0
                || line.indexOf('\r') >= 0
                || line.indexOf('\n') >= 0) {
                throw new IllegalArgumentException("expected_provenance_fields_invalid");
            }
            String label = line.substring(0, separator);
            String value = line.substring(separator + 1);
            if (!labels.add(label)) {
                throw new IllegalArgumentException("expected_provenance_fields_invalid");
            }
            fields.add(new ProvenanceField(label, value));
        }
        return fields;
    }

    private static boolean isSha256Digest(String value) {
        if (value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f')
                || (character >= 'A' && character <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    private static String expectedProvenanceVisibleSequence(List<ProvenanceField> fields) {
        StringBuilder expected = new StringBuilder("Provenance");
        for (ProvenanceField field : fields) {
            if (isSha256Digest(field.value)) {
                expected.append(field.label).append(':').append(field.value);
            } else {
                expected.append(field.label).append(": ").append(field.value);
            }
        }
        return expected.toString();
    }

    private static boolean matchesBoundedProvenanceText(
        String text,
        String stateLabel,
        String expectedSource,
        String expectedProvenance,
        boolean toUnicodeText
    ) {
        int stateStart = text.indexOf(stateLabel);
        if (stateStart < 0) {
            return false;
        }
        String sourceSequence = toUnicodeText
            ? expectedSource.replace("\n", "")
            : expectedSource;
        int sourceStart = text.indexOf(sourceSequence, stateStart + stateLabel.length());
        if (sourceStart < 0) {
            return false;
        }
        int provenanceStart = text.indexOf(
            "Provenance",
            sourceStart + sourceSequence.length()
        );
        return provenanceStart >= 0 && text.startsWith(expectedProvenance, provenanceStart);
    }

    private static boolean matchesProvenanceSpanSequence(
        List<MarkedSpan> spans,
        String stateLabel,
        String expectedSource,
        List<ProvenanceField> fields
    ) {
        String expectedSourceGlyphs = expectedSource.replace("\n", "");
        StringBuilder allGlyphs = new StringBuilder();
        int[] spanStarts = new int[spans.size()];
        for (int index = 0; index < spans.size(); index++) {
            spanStarts[index] = allGlyphs.length();
            allGlyphs.append(spans.get(index).glyphText);
        }
        int stateStart = allGlyphs.indexOf(stateLabel);
        if (stateStart < 0) {
            return false;
        }
        int sourceStart = allGlyphs.indexOf(expectedSourceGlyphs, stateStart + stateLabel.length());
        if (sourceStart < 0) {
            return false;
        }
        int afterSource = sourceStart + expectedSourceGlyphs.length();
        for (int index = 0; index < spans.size(); index++) {
            MarkedSpan span = spans.get(index);
            if (spanStarts[index] < afterSource
                || !"Provenance".equals(span.actualText)
                || !"Provenance".equals(span.glyphText.toString())) {
                continue;
            }
            int[] nextSpan = {index + 1};
            if (matchesProvenanceFieldSpans(spans, nextSpan, fields)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesProvenanceFieldSpans(
        List<MarkedSpan> spans,
        int[] nextSpan,
        List<ProvenanceField> fields
    ) {
        for (ProvenanceField field : fields) {
            if (isSha256Digest(field.value)) {
                if (!consumeExactProvenanceLine(spans, nextSpan, field.label + ":")
                    || !consumeExactProvenanceLine(spans, nextSpan, field.value)) {
                    return false;
                }
            } else if (!consumeExactProvenanceLine(
                spans,
                nextSpan,
                field.label + ": " + field.value
            )) {
                return false;
            }
        }
        return true;
    }

    private static boolean consumeExactProvenanceLine(
        List<MarkedSpan> spans,
        int[] nextSpan,
        String expectedLine
    ) {
        StringBuilder actualText = new StringBuilder();
        StringBuilder glyphText = new StringBuilder();
        while (nextSpan[0] < spans.size() && actualText.length() < expectedLine.length()) {
            MarkedSpan span = spans.get(nextSpan[0]++);
            if (span.actualText == null) {
                return false;
            }
            actualText.append(span.actualText);
            glyphText.append(span.glyphText);
            if (actualText.length() > expectedLine.length()
                || glyphText.length() > expectedLine.length()) {
                return false;
            }
        }
        return expectedLine.contentEquals(actualText)
            && expectedLine.contentEquals(glyphText);
    }

    private static PageProof inspectPage(PDPage page) throws IOException {
        PageProof proof = new PageProof();
        PDResources resources = page.getResources();
        if (resources == null) {
            throw new IllegalStateException("PDF page is missing resources");
        }
        Deque<MarkedSpan> markedContent = new ArrayDeque<>();
        List<Object> operands = new ArrayList<>();
        PDFont currentFont = null;
        List<Object> tokens = new PDFStreamParser(page).parse();

        for (Object token : tokens) {
            if (!(token instanceof Operator)) {
                operands.add(token);
                continue;
            }

            String operator = ((Operator) token).getName();
            switch (operator) {
                case "Tf":
                    if (operands.size() < 2 || !(operands.get(0) instanceof COSName)) {
                        throw new IllegalStateException("malformed Tf operator");
                    }
                    currentFont = resources.getFont((COSName) operands.get(0));
                    if (!(currentFont instanceof PDType0Font) || !currentFont.isEmbedded()) {
                        throw new IllegalStateException("expected an embedded Type 0 text font");
                    }
                    if (!(currentFont.getCOSObject().getDictionaryObject(
                        COSName.getPDFName("ToUnicode")
                    ) instanceof COSStream)) {
                        throw new IllegalStateException("embedded Type 0 font has no /ToUnicode CMap stream");
                    }
                    break;
                case "Tj":
                    if (operands.isEmpty() || !(operands.get(0) instanceof COSString)) {
                        throw new IllegalStateException("malformed Tj operator");
                    }
                    appendDecoded(
                        (COSString) operands.get(0), currentFont, proof, markedContent
                    );
                    break;
                case "TJ":
                    if (operands.isEmpty() || !(operands.get(0) instanceof COSArray)) {
                        throw new IllegalStateException("malformed TJ operator");
                    }
                    COSArray textArray = (COSArray) operands.get(0);
                    for (int index = 0; index < textArray.size(); index++) {
                        COSBase item = textArray.get(index);
                        if (item instanceof COSString) {
                            appendDecoded((COSString) item, currentFont, proof, markedContent);
                        }
                    }
                    break;
                case "BMC":
                    markedContent.push(new MarkedSpan(null));
                    break;
                case "BDC":
                    String actualText = null;
                    if (operands.size() >= 2 && operands.get(1) instanceof COSDictionary) {
                        actualText = ((COSDictionary) operands.get(1))
                            .getString(COSName.getPDFName("ActualText"));
                    }
                    markedContent.push(new MarkedSpan(actualText));
                    break;
                case "EMC":
                    if (markedContent.isEmpty()) {
                        throw new IllegalStateException("unbalanced EMC operator");
                    }
                    MarkedSpan span = markedContent.pop();
                    if (span.actualText != null) {
                        proof.spans.add(span);
                    }
                    break;
                default:
                    break;
            }
            operands.clear();
        }
        if (!markedContent.isEmpty()) {
            throw new IllegalStateException("unclosed marked-content sequence");
        }
        return proof;
    }

    private static int verifyFinalEmbeddedImage(
        PDDocument document,
        BufferedImage expected,
        PngMetadata sourceMetadata,
        boolean emitSafeAggregate
    ) throws IOException {
        Set<COSBase> imageObjects = Collections.newSetFromMap(new IdentityHashMap<>());
        FinalPageImageCheck imageCheck = null;
        int pageIndex = 0;
        int finalPageIndex = document.getNumberOfPages() - 1;
        for (PDPage page : document.getPages()) {
            PDResources resources = page.getResources();
            if (pageIndex == finalPageIndex && resources == null) {
                throw new IllegalStateException("final_page_resources_missing");
            }
            if (resources != null) {
                for (COSName name : resources.getXObjectNames()) {
                    PDXObject object = resources.getXObject(name);
                    if (object instanceof PDImageXObject) {
                        imageObjects.add(object.getCOSObject());
                    }
                }
                if (pageIndex == finalPageIndex) {
                    imageCheck = inspectFinalPageImage(page, resources, expected, sourceMetadata);
                }
            }
            pageIndex++;
        }
        int imageCount = imageObjects.size();
        if (imageCheck == null) {
            throw new IllegalStateException("final_page_resources_missing");
        }
        if (emitSafeAggregate && imageCheck.safeAggregateJson != null) {
            System.err.println("PDF_IMAGE_AGGREGATE " + imageCheck.safeAggregateJson);
        }
        if (imageCheck.imageInvocationCount == 0) {
            throw new IllegalStateException("no_final_page_image");
        }
        if (!imageCheck.pixelsMatch) {
            throw new IllegalStateException("final_page_image_pixels_differ");
        }
        return imageCount;
    }

    private static FinalPageImageCheck inspectFinalPageImage(
        PDPage page,
        PDResources resources,
        BufferedImage expected,
        PngMetadata sourceMetadata
    ) throws IOException {
        List<Object> operands = new ArrayList<>();
        List<Object> tokens = new PDFStreamParser(page).parse();
        int imageInvocationCount = 0;
        boolean pixelsMatch = false;
        PDImageXObject diagnosticImage = null;
        BufferedImage diagnosticDecodedImage = null;
        for (Object token : tokens) {
            if (!(token instanceof Operator)) {
                operands.add(token);
                continue;
            }
            if ("Do".equals(((Operator) token).getName())
                && !operands.isEmpty()
                && operands.get(0) instanceof COSName) {
                PDXObject object = resources.getXObject((COSName) operands.get(0));
                if (object instanceof PDImageXObject) {
                    imageInvocationCount++;
                    PDImageXObject image = (PDImageXObject) object;
                    BufferedImage actual = image.getImage();
                    if (diagnosticImage == null) {
                        diagnosticImage = image;
                        diagnosticDecodedImage = actual;
                    }
                    if (actual != null && samePixels(expected, actual)) {
                        pixelsMatch = true;
                    }
                }
            }
            operands.clear();
        }
        if (diagnosticImage == null) {
            for (COSName name : resources.getXObjectNames()) {
                PDXObject object = resources.getXObject(name);
                if (object instanceof PDImageXObject) {
                    diagnosticImage = (PDImageXObject) object;
                    diagnosticDecodedImage = diagnosticImage.getImage();
                    break;
                }
            }
        }
        String safeAggregateJson = diagnosticImage == null
            ? null
            : imageAggregateJson(
                sourceMetadata,
                expected,
                diagnosticImage,
                diagnosticDecodedImage,
                imageInvocationCount
            );
        return new FinalPageImageCheck(imageInvocationCount, pixelsMatch, safeAggregateJson);
    }

    private static PngMetadata readPngMetadata(Path path) throws IOException {
        byte[] header;
        try (InputStream input = Files.newInputStream(path)) {
            header = input.readNBytes(26);
        }
        if (header.length != 26
            || (header[0] & 0xff) != 0x89
            || header[1] != 'P'
            || header[2] != 'N'
            || header[3] != 'G'
            || (header[4] & 0xff) != 0x0d
            || (header[5] & 0xff) != 0x0a
            || (header[6] & 0xff) != 0x1a
            || (header[7] & 0xff) != 0x0a
            || header[12] != 'I'
            || header[13] != 'H'
            || header[14] != 'D'
            || header[15] != 'R'
            || unsignedPngInt(header, 8) != 13) {
            throw new IllegalStateException("source_png_header_invalid");
        }
        long width = unsignedPngInt(header, 16);
        long height = unsignedPngInt(header, 20);
        if (width < 1 || height < 1 || width > Integer.MAX_VALUE || height > Integer.MAX_VALUE) {
            throw new IllegalStateException("source_png_dimensions_invalid");
        }
        return new PngMetadata(
            (int) width,
            (int) height,
            header[24] & 0xff,
            header[25] & 0xff
        );
    }

    private static long unsignedPngInt(byte[] bytes, int offset) {
        return ((long) (bytes[offset] & 0xff) << 24)
            | ((long) (bytes[offset + 1] & 0xff) << 16)
            | ((long) (bytes[offset + 2] & 0xff) << 8)
            | (long) (bytes[offset + 3] & 0xff);
    }

    private static String imageAggregateJson(
        PngMetadata sourceMetadata,
        BufferedImage source,
        PDImageXObject image,
        BufferedImage decoded,
        int invocationCount
    ) {
        int[] sourceAlphaRange = alphaRange(source);
        int[] decodedAlphaRange = decoded == null
            ? new int[] {-1, -1}
            : alphaRange(decoded);
        long unequalPixelCount = (long) source.getWidth() * source.getHeight();
        int maxRgbDelta = 0;
        int maxAlphaDelta = 0;
        if (decoded != null) {
            long sourceArea = (long) source.getWidth() * source.getHeight();
            long decodedArea = (long) decoded.getWidth() * decoded.getHeight();
            long overlapArea = (long) Math.min(source.getWidth(), decoded.getWidth())
                * Math.min(source.getHeight(), decoded.getHeight());
            unequalPixelCount = sourceArea + decodedArea - (2 * overlapArea);
            for (int y = 0; y < Math.min(source.getHeight(), decoded.getHeight()); y++) {
                for (int x = 0; x < Math.min(source.getWidth(), decoded.getWidth()); x++) {
                    int sourcePixel = source.getRGB(x, y);
                    int decodedPixel = decoded.getRGB(x, y);
                    int redDelta = Math.abs(((sourcePixel >> 16) & 0xff) - ((decodedPixel >> 16) & 0xff));
                    int greenDelta = Math.abs(((sourcePixel >> 8) & 0xff) - ((decodedPixel >> 8) & 0xff));
                    int blueDelta = Math.abs((sourcePixel & 0xff) - (decodedPixel & 0xff));
                    int alphaDelta = Math.abs(((sourcePixel >> 24) & 0xff) - ((decodedPixel >> 24) & 0xff));
                    maxRgbDelta = Math.max(maxRgbDelta, Math.max(redDelta, Math.max(greenDelta, blueDelta)));
                    maxAlphaDelta = Math.max(maxAlphaDelta, alphaDelta);
                    if (redDelta != 0 || greenDelta != 0 || blueDelta != 0 || alphaDelta != 0) {
                        unequalPixelCount++;
                    }
                }
            }
        }

        COSDictionary dictionary = image.getCOSObject();
        COSBase bitsPerComponent = dictionary.getDictionaryObject(COSName.getPDFName("BitsPerComponent"));
        int bits = bitsPerComponent instanceof COSInteger
            ? ((COSInteger) bitsPerComponent).intValue()
            : -1;
        String colorSpace = safeColorSpaceName(
            dictionary.getDictionaryObject(COSName.getPDFName("ColorSpace"))
        );
        String filter = safeFilterName(dictionary.getDictionaryObject(COSName.getPDFName("Filter")));
        COSBase softMask = dictionary.getDictionaryObject(COSName.getPDFName("SMask"));
        boolean hasSoftMask = softMask != null && !(softMask instanceof COSNull);

        return "{"
            + "\"source_png_width\":" + sourceMetadata.width + ","
            + "\"source_png_height\":" + sourceMetadata.height + ","
            + "\"source_png_bit_depth\":" + sourceMetadata.bitDepth + ","
            + "\"source_png_color_type\":" + sourceMetadata.colorType + ","
            + "\"source_alpha_min\":" + sourceAlphaRange[0] + ","
            + "\"source_alpha_max\":" + sourceAlphaRange[1] + ","
            + "\"pdf_xobject_width\":" + image.getWidth() + ","
            + "\"pdf_xobject_height\":" + image.getHeight() + ","
            + "\"pdf_xobject_bits_per_component\":" + bits + ","
            + "\"pdf_xobject_color_space\":\"" + escapeJson(colorSpace) + "\","
            + "\"pdf_xobject_filter\":\"" + escapeJson(filter) + "\","
            + "\"pdf_xobject_has_smask\":" + hasSoftMask + ","
            + "\"final_page_image_invocation_count\":" + invocationCount + ","
            + "\"decoded_alpha_min\":" + decodedAlphaRange[0] + ","
            + "\"decoded_alpha_max\":" + decodedAlphaRange[1] + ","
            + "\"unequal_pixel_count\":" + unequalPixelCount + ","
            + "\"max_rgb_delta\":" + maxRgbDelta + ","
            + "\"max_alpha_delta\":" + maxAlphaDelta
            + "}";
    }

    private static int[] alphaRange(BufferedImage image) {
        int minimum = 255;
        int maximum = 0;
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int alpha = (image.getRGB(x, y) >> 24) & 0xff;
                minimum = Math.min(minimum, alpha);
                maximum = Math.max(maximum, alpha);
            }
        }
        return new int[] {minimum, maximum};
    }

    private static String safeColorSpaceName(COSBase value) {
        if (value instanceof COSArray) {
            COSArray array = (COSArray) value;
            return array.size() == 0 ? "other" : safeColorSpaceName(array.getObject(0));
        }
        if (!(value instanceof COSName)) {
            return "other";
        }
        String name = ((COSName) value).getName();
        switch (name) {
            case "DeviceGray":
            case "DeviceRGB":
            case "DeviceCMYK":
            case "ICCBased":
            case "Indexed":
            case "Separation":
            case "DeviceN":
            case "Pattern":
                return name;
            default:
                return "other";
        }
    }

    private static String safeFilterName(COSBase value) {
        if (value instanceof COSArray) {
            COSArray array = (COSArray) value;
            List<String> names = new ArrayList<>();
            for (int index = 0; index < array.size(); index++) {
                names.add(safeFilterName(array.getObject(index)));
            }
            return names.isEmpty() ? "none" : String.join("+", names);
        }
        if (!(value instanceof COSName)) {
            return value == null ? "none" : "other";
        }
        String name = ((COSName) value).getName();
        switch (name) {
            case "FlateDecode":
            case "DCTDecode":
            case "LZWDecode":
            case "RunLengthDecode":
            case "JPXDecode":
            case "CCITTFaxDecode":
            case "ASCII85Decode":
            case "ASCIIHexDecode":
            case "Crypt":
                return name;
            default:
                return "other";
        }
    }

    private static void rejectActiveContent(PDDocument document) throws IOException {
        COSDictionary catalog = document.getDocumentCatalog().getCOSObject();
        if (catalog.getDictionaryObject(COSName.getPDFName("OpenAction")) != null
            || catalog.getDictionaryObject(COSName.getPDFName("AA")) != null
            || catalog.getDictionaryObject(COSName.getPDFName("AF")) != null
            || catalog.getDictionaryObject(COSName.getPDFName("AcroForm")) != null
            || catalog.getDictionaryObject(COSName.getPDFName("Outlines")) != null) {
            throw new IllegalStateException("PDF catalog actions or attachments are forbidden");
        }
        COSBase namesObject = catalog.getDictionaryObject(COSName.getPDFName("Names"));
        if (namesObject instanceof COSDictionary) {
            COSDictionary names = (COSDictionary) namesObject;
            if (names.getDictionaryObject(COSName.getPDFName("JavaScript")) != null
                || names.getDictionaryObject(COSName.getPDFName("EmbeddedFiles")) != null) {
                throw new IllegalStateException("PDF JavaScript or embedded files are forbidden");
            }
        }
        for (PDPage page : document.getPages()) {
            if (page.getCOSObject().getDictionaryObject(COSName.getPDFName("AA")) != null
                || !page.getAnnotations().isEmpty()) {
                throw new IllegalStateException("PDF page actions and annotations are forbidden");
            }
        }
    }

    private static boolean samePixels(BufferedImage expected, BufferedImage actual) {
        if (expected.getWidth() != actual.getWidth() || expected.getHeight() != actual.getHeight()) {
            return false;
        }
        for (int y = 0; y < expected.getHeight(); y++) {
            for (int x = 0; x < expected.getWidth(); x++) {
                if (expected.getRGB(x, y) != actual.getRGB(x, y)) {
                    return false;
                }
            }
        }
        return true;
    }

    private static void appendDecoded(
        COSString string,
        PDFont font,
        PageProof proof,
        Deque<MarkedSpan> markedContent
    ) throws IOException {
        if (!(font instanceof PDType0Font) || !font.isEmbedded()) {
            throw new IllegalStateException("text-showing operator lacks an embedded Type 0 font");
        }
        ByteArrayInputStream input = new ByteArrayInputStream(string.getBytes());
        StringBuilder decoded = new StringBuilder();
        while (input.available() > 0) {
            int code = font.readCode(input);
            String unicode = font.toUnicode(code);
            if (unicode == null) {
                throw new IllegalStateException("missing /ToUnicode entry for glyph code " + code);
            }
            decoded.append(unicode);
        }
        proof.toUnicodeText.append(decoded);
        for (MarkedSpan span : markedContent) {
            if (span.actualText != null) {
                span.glyphText.append(decoded);
            }
        }
    }

    private static String sha256(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder output = new StringBuilder(digest.length * 2);
        for (byte value : digest) {
            output.append(String.format("%02x", value & 0xff));
        }
        return output.toString();
    }

    private static boolean containsEncodedText(byte[] source, String value) {
        return containsBytes(source, value.getBytes(StandardCharsets.UTF_8))
            || containsBytes(source, value.getBytes(StandardCharsets.UTF_16BE))
            || containsBytes(source, value.getBytes(StandardCharsets.UTF_16LE));
    }

    private static boolean containsBytes(byte[] source, byte[] needle) {
        if (needle.length == 0 || needle.length > source.length) {
            return false;
        }
        for (int start = 0; start <= source.length - needle.length; start++) {
            boolean matches = true;
            for (int index = 0; index < needle.length; index++) {
                if (source[start + index] != needle[index]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return true;
            }
        }
        return false;
    }

    private static String extractDelimitedTranscript(String text) {
        int start = text.indexOf("[[");
        if (start < 0) {
            return null;
        }
        int end = text.indexOf("]]", start + 2);
        return end < 0 ? null : text.substring(start, end + 2);
    }

    private static String extractStateBoundedTranscript(String text, String stateLabel) {
        int stateStart = text.indexOf(stateLabel);
        if (stateStart < 0) {
            return null;
        }
        int transcriptStart = stateStart + stateLabel.length();
        int provenanceStart = text.indexOf("Provenance", transcriptStart);
        if (provenanceStart < transcriptStart) {
            return null;
        }
        return text.substring(transcriptStart, provenanceStart);
    }

    private static boolean matchesTranscriptSpans(List<MarkedSpan> spans, String expected) {
        String[] lines = expected.split("\n", -1);
        if (lines.length == 0 || spans.size() < lines.length) {
            return false;
        }
        for (int start = 0; start <= spans.size() - lines.length; start++) {
            boolean matches = true;
            for (int lineIndex = 0; lineIndex < lines.length; lineIndex++) {
                String expectedActualText = lines[lineIndex] + (lineIndex + 1 < lines.length ? "\n" : "");
                MarkedSpan span = spans.get(start + lineIndex);
                if (!expectedActualText.equals(span.actualText)
                    || !lines[lineIndex].equals(span.glyphText.toString())) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return true;
            }
        }
        return false;
    }

    private static boolean isLineFeedOnly(String text) {
        if (text.isEmpty()) {
            return false;
        }
        for (int index = 0; index < text.length(); index++) {
            if (text.charAt(index) != '\n') {
                return false;
            }
        }
        return true;
    }

    private static boolean matchesLineFeedSpans(List<MarkedSpan> spans, int lineFeedCount) {
        int lineCount = lineFeedCount + 1;
        for (int start = 0; start <= spans.size() - lineCount; start++) {
            boolean matches = true;
            for (int lineIndex = 0; lineIndex < lineCount; lineIndex++) {
                String expectedActualText = lineIndex < lineFeedCount ? "\n" : "";
                MarkedSpan span = spans.get(start + lineIndex);
                if (!expectedActualText.equals(span.actualText) || !" ".equals(span.glyphText.toString())) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsExactLineFeedRun(String text, int expectedCount) {
        int runLength = 0;
        for (int index = 0; index < text.length(); index++) {
            if (text.charAt(index) == '\n') {
                runLength++;
            } else {
                if (runLength == expectedCount) {
                    return true;
                }
                runLength = 0;
            }
        }
        return runLength == expectedCount;
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
