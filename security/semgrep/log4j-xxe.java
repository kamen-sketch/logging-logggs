import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/** Fixtures for log4j-xxe. Compiles against the JDK alone. */
class XxeCases {

    // --- vulnerable ------------------------------------------------------

    /** No hardening at all: external entities are resolved. */
    public DocumentBuilder unhardened() throws ParserConfigurationException {
        // ruleid: log4j-xxe
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder();
    }

    // --- safe ------------------------------------------------------------

    /** disallow-doctype-decl is the strongest single switch. */
    public DocumentBuilder doctypeDisallowed() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: log4j-xxe
        return factory.newDocumentBuilder();
    }

    /** The hardening XmlConfiguration.newDocumentBuilder() actually performs. */
    public DocumentBuilder log4jStyleHardening() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setExpandEntityReferences(false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        // ok: log4j-xxe
        return factory.newDocumentBuilder();
    }

    // --- regression: conditional hardening --------------------------------

    /**
     * Hardening is applied only when `strict` is true, but newDocumentBuilder()
     * always runs -- when strict is false, this is exactly as vulnerable as
     * unhardened() above. This probes whether "..." in pattern-not can
     * wrongly match through an untaken if-branch, treating conditional
     * hardening as if it were unconditional.
     */
    public DocumentBuilder conditionallyHardened(boolean strict) throws ParserConfigurationException {
        // ruleid: log4j-xxe
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        if (strict) {
            factory.setExpandEntityReferences(false);
        }
        return factory.newDocumentBuilder();
    }
}
