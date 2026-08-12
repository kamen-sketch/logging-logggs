import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/** Fixtures for log4j-xinclude. Compiles against the JDK alone. */
class XIncludeCases {

    // --- vulnerable ------------------------------------------------------

    /** XInclude enabled with no restriction: local files can be read via <xi:include>. */
    public DocumentBuilder xIncludeEnabled() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ruleid: log4j-xinclude
        factory.setXIncludeAware(true);
        return factory.newDocumentBuilder();
    }

    /**
     * FEATURE_SECURE_PROCESSING is often assumed to be a blanket XML-safety
     * switch. Confirmed empirically (dynamic-proof/real-source/XIncludeProbe.java)
     * that it does NOT block XInclude.
     */
    public DocumentBuilder xIncludeEnabledWithSecureProcessing() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // ruleid: log4j-xinclude
        factory.setXIncludeAware(true);
        return factory.newDocumentBuilder();
    }

    // --- safe --------------------------------------------------------------

    /** The only fix confirmed to work in this session's testing: don't enable XInclude. */
    public DocumentBuilder xIncludeDisabled() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ok: log4j-xinclude
        factory.setXIncludeAware(false);
        return factory.newDocumentBuilder();
    }
}
