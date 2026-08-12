import java.io.File;
import java.io.FileWriter;
import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Proves log4j-xxe's flaw is real: a genuine local file's contents are read
 * through an external entity and appear in the parsed Document, using the
 * exact hardening XmlConfiguration.newDocumentBuilder() applies to show it
 * actually blocks the same attack.
 */
class XxeProof {

    private static int failed = 0;
    private static final String CANARY = "CANARY-3f9c1a7e-do-not-leak";

    public static void main(String[] args) throws Exception {
        System.out.println("=== XXE: dynamic proof ===\n");

        File secret = File.createTempFile("xxe-proof-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }

        String maliciousXml = "<?xml version=\"1.0\"?>\n"
                + "<!DOCTYPE root [\n"
                + "  <!ENTITY leaked SYSTEM \"file://" + secret.getAbsolutePath() + "\">\n"
                + "]>\n"
                + "<root>&leaked;</root>";

        unhardenedParserLeaksTheFile(maliciousXml);
        hardenedParserBlocksIt(maliciousXml);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    private static void unhardenedParserLeaksTheFile(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ruleid: log4j-xxe -- no hardening applied
        DocumentBuilder builder = factory.newDocumentBuilder();

        Document doc = builder.parse(new InputSource(new StringReader(xml)));
        String text = doc.getDocumentElement().getTextContent();

        assertTrue("the local file's real contents appear in the parsed document",
                text.contains(CANARY));
        System.out.println("  vulnerable: parsed <root> text content = \"" + text
                + "\" -- the secret file was actually read off disk.");
    }

    /** XmlConfiguration.newDocumentBuilder()'s hardening, reproduced exactly. */
    private static DocumentBuilder hardenedBuilder() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setExpandEntityReferences(false);
        setFeature(factory, "http://xml.org/sax/features/external-general-entities", false);
        setFeature(factory, "http://xml.org/sax/features/external-parameter-entities", false);
        setFeature(factory, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        // ok: log4j-xxe -- hardening applied before newDocumentBuilder()
        return factory.newDocumentBuilder();
    }

    private static void setFeature(DocumentBuilderFactory factory, String feature, boolean value) {
        try {
            factory.setFeature(feature, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void hardenedParserBlocksIt(String xml) throws Exception {
        DocumentBuilder builder = hardenedBuilder();

        boolean blocked;
        String text = null;
        try {
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
            text = doc.getDocumentElement().getTextContent();
            blocked = !text.contains(CANARY);
        } catch (SAXException expectedParseFailure) {
            blocked = true;
        }

        assertTrue("the hardened parser never leaked the file "
                + (text != null ? "(entity resolved to: \"" + text + "\")" : "(parsing was rejected outright)"),
                blocked);
        System.out.println("  guarded:    hardened DocumentBuilder did not leak the secret file.");
    }

    private static void assertTrue(String what, boolean ok) {
        if (ok) {
            System.out.println("  [PASS] " + what);
        } else {
            failed++;
            System.out.println("  [FAIL] " + what);
        }
    }
}
