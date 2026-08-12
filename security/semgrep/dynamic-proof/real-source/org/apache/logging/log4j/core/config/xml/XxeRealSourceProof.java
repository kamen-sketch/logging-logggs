package org.apache.logging.log4j.core.config.xml;

// Deliberately in the real org.apache.logging.log4j.core.config.xml package:
// XmlConfiguration.newDocumentBuilder() is package-private, and the point of
// this proof is to call the REAL method (source-verified: it always applies
// disableDtdProcessing()) rather than a copy of its logic.

import java.io.File;
import java.io.FileWriter;
import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

class XxeRealSourceProof {

    private static int failed = 0;
    private static final String CANARY = "CANARY-3f9c1a7e-do-not-leak";

    public static void main(String[] args) throws Exception {
        System.out.println("=== XXE: proof through the REAL Log4j source ===\n");

        File secret = File.createTempFile("xxe-real-proof-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }

        String maliciousXml = "<?xml version=\"1.0\"?>\n"
                + "<!DOCTYPE root [\n"
                + "  <!ENTITY leaked SYSTEM \"file://" + secret.getAbsolutePath() + "\">\n"
                + "]>\n"
                + "<root>&leaked;</root>";

        realBuilderBlocksTheExactSameAttack(maliciousXml);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println("\nNote: there is no \"vulnerable\" case to demonstrate here against real "
                + "source -- XmlConfiguration.newDocumentBuilder() unconditionally calls "
                + "disableDtdProcessing() for every DocumentBuilder it ever returns. Unlike the "
                + "JNDI case (config-flag opt-out exists), this hardening is not configurable at "
                + "all in the current source -- confirmed by reading newDocumentBuilder()'s real "
                + "implementation, not assumed.");
    }

    /** Calls the REAL XmlConfiguration.newDocumentBuilder(), unmodified, package-private. */
    private static void realBuilderBlocksTheExactSameAttack(String xml) throws Exception {
        DocumentBuilder builder = XmlConfiguration.newDocumentBuilder(true);

        boolean blocked;
        String text = null;
        try {
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
            text = doc.getDocumentElement().getTextContent();
            blocked = !text.contains(CANARY);
        } catch (SAXException expectedParseFailure) {
            blocked = true;
            System.out.println("  real XmlConfiguration.newDocumentBuilder() rejected the malicious "
                    + "document outright: " + expectedParseFailure.getMessage());
        }

        assertTrue("the real DocumentBuilder Log4j's own XML config loader uses did not leak the "
                + "file" + (text != null ? " (entity resolved to: \"" + text + "\")" : ""),
                blocked);
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
