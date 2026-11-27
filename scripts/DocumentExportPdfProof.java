import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

import javax.imageio.ImageIO;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.contentstream.operator.Operator;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdfparser.PDFStreamParser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.graphics.PDXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.text.PDFTextStripper;

/** Structural PDF proof for fixed synthetic fixtures; ActualText is inspected separately. */
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

    private DocumentExportPdfProof() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            throw new IllegalArgumentException(
                "usage: DocumentExportPdfProof <pdf> <expected-utf8-file-or-dash> <proof-json> <page-limit> <fixture-png>"
            );
        }

        Path pdfPath = Path.of(args[0]);
        Path expectedPath = Path.of(args[1]);
        Path proofPath = Path.of(args[2]);
        int pageLimit = Integer.parseInt(args[3]);
        Path fixturePngPath = Path.of(args[4]);
        if (pageLimit < 1 || pageLimit > 96) {
            throw new IllegalArgumentException("manifest PDF page limit is outside the supported bound");
        }
        String expected = "-".equals(args[1])
            ? null
            : Files.readString(expectedPath, StandardCharsets.UTF_8);

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
            int embeddedImageCount = verifyFinalEmbeddedImage(document, fixtureImage);
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
            boolean sourceChecked = expected != null;
            boolean lineFeedOnlySource = sourceChecked && isLineFeedOnly(expected);
            // IR line feeds have no glyph code; verify every visible scalar via
            // ToUnicode and the exact line separators via ActualText/TextStripper.
            String expectedGlyphSequence = sourceChecked ? expected.replace("\n", "") : null;
            boolean toUnicodeMatch = sourceChecked && !lineFeedOnlySource && expectedGlyphSequence.equals(
                extractDelimitedTranscript(toUnicodeText.toString())
            );
            boolean lineFeedSpansMatch = lineFeedOnlySource && matchesLineFeedSpans(spans, expected.length());
            boolean textStripperMatch = sourceChecked && (lineFeedOnlySource
                ? containsExactLineFeedRun(strippedText, expected.length())
                : expected.equals(extractDelimitedTranscript(strippedText)));
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

            String expectedHash = expected == null ? "" : sha256(expected.getBytes(StandardCharsets.UTF_8));
            String toUnicodeMatchJson = lineFeedOnlySource ? "null" : Boolean.toString(toUnicodeMatch);
            String lineFeedSpansMatchJson = lineFeedOnlySource ? Boolean.toString(lineFeedSpansMatch) : "null";
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
                + "  \"expected_utf8_sha256\": \"" + expectedHash + "\"\n"
                + "}\n";
            Files.writeString(proofPath, json, StandardCharsets.UTF_8);
        }
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

    private static int verifyFinalEmbeddedImage(PDDocument document, BufferedImage expected)
        throws IOException {
        Set<COSBase> imageObjects = Collections.newSetFromMap(new IdentityHashMap<>());
        boolean finalPageMatch = false;
        int pageIndex = 0;
        int finalPageIndex = document.getNumberOfPages() - 1;
        for (PDPage page : document.getPages()) {
            PDResources resources = page.getResources();
            if (resources != null) {
                for (COSName name : resources.getXObjectNames()) {
                    PDXObject object = resources.getXObject(name);
                    if (object instanceof PDImageXObject) {
                        imageObjects.add(object.getCOSObject());
                    }
                }
                if (pageIndex == finalPageIndex) {
                    finalPageMatch = finalPageUsesMatchingImage(page, resources, expected);
                }
            }
            pageIndex++;
        }
        int imageCount = imageObjects.size();
        if (!finalPageMatch) {
            throw new IllegalStateException("final PDF page does not invoke the matching fixture image XObject");
        }
        return imageCount;
    }

    private static boolean finalPageUsesMatchingImage(
        PDPage page,
        PDResources resources,
        BufferedImage expected
    ) throws IOException {
        List<Object> operands = new ArrayList<>();
        List<Object> tokens = new PDFStreamParser(page).parse();
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
                    BufferedImage actual = ((PDImageXObject) object).getImage();
                    if (actual != null && samePixels(expected, actual)) {
                        return true;
                    }
                }
            }
            operands.clear();
        }
        return false;
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

    private static String extractDelimitedTranscript(String text) {
        int start = text.indexOf("[[");
        if (start < 0) {
            return null;
        }
        int end = text.indexOf("]]", start + 2);
        return end < 0 ? null : text.substring(start, end + 2);
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
