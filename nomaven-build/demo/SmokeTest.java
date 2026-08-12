import java.nio.file.*;
import java.util.List;
import org.apache.logging.log4j.*;
import org.apache.logging.log4j.core.LoggerContext;

/**
 * Smoke test for the locally-compiled Log4j (no Maven, no network).
 * Each check asserts on observable behaviour and the process exits non-zero
 * if any check fails -- so "it printed something" is never mistaken for a pass.
 */
public class SmokeTest {

    private static final Logger log = LogManager.getLogger(SmokeTest.class);
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        banner("Log4j smoke test -- built from source with javac");

        checkImplementationIsCore();
        checkLevels();
        checkParameterisedAndThrowable();
        checkThreadContext();
        checkLevelFilteringIsEnforced();
        checkFileAppenderWroteToDisk();
        checkRollingAppenderRolled();

        LogManager.shutdown();
        reportRolloverThreadBehaviour();

        System.out.println();
        if (failed == 0) {
            banner("ALL CHECKS PASSED");
        } else {
            banner(failed + " CHECK(S) FAILED");
        }
        // Explicit exit: RollingFileManager's async-compression pool uses
        // Log4jThreadFactory.createThreadFactory(), i.e. NON-daemon threads
        // (RollingFileManager.java:65,77). LogManager.shutdown() does not
        // release them, so returning from main would hang the JVM until the
        // shutdown hook fires. See FINDINGS in README-nomaven.md.
        System.exit(failed == 0 ? 0 : 1);
    }

    private static void reportRolloverThreadBehaviour() throws Exception {
        long alive = 0;
        for (int i = 0; i < 20; i++) {                 // observe for ~1s
            alive = Thread.getAllStackTraces().keySet().stream()
                    .filter(t -> !t.isDaemon() && t.getName().contains("RollingFileManager"))
                    .count();
            if (alive == 0) break;
            Thread.sleep(50);
        }
        section("post-shutdown thread state");
        System.out.println("  [NOTE] non-daemon RollingFileManager threads still alive "
                + "after LogManager.shutdown(): " + alive);
        if (alive > 0) {
            System.out.println("         -> JVM would not exit on its own; "
                    + "this test calls System.exit() deliberately.");
        }
    }

    // ---------------------------------------------------------------- checks

    /** If the Provider service file were missing, LogManager silently falls
     *  back to SimpleLogger -- that must be treated as a failure, not a pass. */
    private static void checkImplementationIsCore() {
        String impl = LogManager.getFactory().getClass().getName();
        assertThat("log4j-core is the active implementation (not SimpleLogger)",
                impl.contains("core"), "factory=" + impl);

        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        assertThat("configuration loaded from log4j2.xml",
                "NoMavenSmokeTest".equals(ctx.getConfiguration().getName()),
                "config name=" + ctx.getConfiguration().getName());
    }

    private static void checkLevels() {
        section("all six levels through the root logger");
        log.trace("TRACE - filtered out, root is debug");
        log.debug("DEBUG - visible");
        log.info("INFO  - visible");
        log.warn("WARN  - visible");
        log.error("ERROR - visible");
        log.fatal("FATAL - visible");
        assertThat("root logger is at DEBUG", log.isDebugEnabled(), "isDebugEnabled=false");
        assertThat("TRACE is below threshold", !log.isTraceEnabled(), "isTraceEnabled=true");
    }

    private static void checkParameterisedAndThrowable() {
        section("parameterised messages + stack traces");
        log.info("user {} bought {} items for ${}", "kamen", 3, 24.50);
        log.info("lazily built only when INFO is on: {}",
                (org.apache.logging.log4j.util.Supplier<String>) () -> "computed-on-demand");
        try {
            Integer.parseInt("not-a-number");
        } catch (NumberFormatException e) {
            log.error("parsing failed for input {}", "not-a-number", e);
        }
    }


    private static void checkThreadContext() {
        section("ThreadContext (MDC) -- see %X{orderId} in the pattern");
        ThreadContext.put("orderId", "[order=A-1001]");
        log.info("processing order");
        ThreadContext.clearAll();
        log.info("order id is gone from this line");
    }

    private static void checkLevelFilteringIsEnforced() {
        section("per-logger level + additivity");
        Logger noisy = LogManager.getLogger("com.example.noisy");
        noisy.info("INFO on com.example.noisy -- must NOT appear (logger is warn)");
        noisy.warn("WARN on com.example.noisy -- must appear exactly once");
        assertThat("com.example.noisy suppresses INFO", !noisy.isInfoEnabled(),
                "isInfoEnabled=true");
        assertThat("com.example.noisy allows WARN", noisy.isWarnEnabled(),
                "isWarnEnabled=false");
    }

    private static void checkFileAppenderWroteToDisk() throws Exception {
        LogManager.getLogger("com.example.file").info("written to the file appender");
        ((LoggerContext) LogManager.getContext(false)).getConfiguration()
                .getAppender("File").stop();          // flush

        Path p = Paths.get("logs/app.log");
        boolean exists = Files.exists(p);
        assertThat("File appender created logs/app.log", exists, "missing");
        if (!exists) return;

        List<String> lines = Files.readAllLines(p);
        assertThat("logs/app.log has content", !lines.isEmpty(), "0 lines");
        assertThat("stack trace reached the file",
                lines.stream().anyMatch(l -> l.contains("NumberFormatException")),
                "no NumberFormatException in file");
        section("logs/app.log (" + lines.size() + " lines, first 4)");
        lines.stream().limit(4).forEach(l -> System.out.println("    | " + l));
    }

    private static void checkRollingAppenderRolled() throws Exception {
        Logger r = LogManager.getLogger("com.example.rolling");
        for (int i = 0; i < 200; i++) {
            r.info("rolling payload line {} ----------------------------------", i);
        }
        ((LoggerContext) LogManager.getContext(false)).getConfiguration()
                .getAppender("Rolling").stop();

        try (var s = Files.list(Paths.get("logs"))) {
            List<String> rolled = s.map(x -> x.getFileName().toString())
                    .filter(n -> n.startsWith("rolling-")).sorted().toList();
            assertThat("SizeBasedTriggeringPolicy produced rollover files",
                    !rolled.isEmpty(), "no rolling-*.log.gz created");
            section("rollover files: " + rolled);
            assertThat("rollover files are gzip-compressed",
                    rolled.stream().allMatch(n -> n.endsWith(".gz")),
                    "not all .gz: " + rolled);
        }
    }

    // ---------------------------------------------------------------- helpers

    private static void assertThat(String what, boolean ok, String detail) {
        if (ok) {
            System.out.println("  [PASS] " + what);
        } else {
            failed++;
            System.out.println("  [FAIL] " + what + "  (" + detail + ")");
        }
    }

    private static void section(String s) {
        System.out.println("\n--- " + s + " ---");
    }

    private static void banner(String s) {
        String bar = "=".repeat(Math.max(s.length() + 4, 30));
        System.out.println(bar + "\n  " + s + "\n" + bar);
    }
}
