import java.io.File;
import java.nio.file.Files;
import javax.script.SimpleBindings;
import org.apache.logging.log4j.core.script.Script;
import org.apache.logging.log4j.core.script.ScriptManager;

/**
 * Drives the real ScriptManager.addScript()/execute() -- the class Log4j's
 * <Script>/<ScriptFile> configuration elements actually use -- with the
 * real TinyScriptEngine discovered through the real JSR-223 ServiceLoader
 * mechanism (META-INF/services/javax.script.ScriptEngineFactory), not a
 * hand-rolled substitute for ScriptManager itself.
 */
class ScriptRealSourceProof {

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== Script injection: proof through the REAL Log4j source ===\n");

        File canaryTarget = File.createTempFile("script-real-proof-canary", ".txt");
        canaryTarget.delete();
        canaryTarget.deleteOnExit();

        realScriptManagerDiscoversTheEngineAndRunsIt(canaryTarget);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    private static void realScriptManagerDiscoversTheEngineAndRunsIt(File target) throws Exception {
        // null Configuration/WatchManager: neither is touched by addScript()/execute()
        // for a non-file-backed Script, only by ScriptFile's watch registration.
        ScriptManager manager = new ScriptManager(null, null, "tiny");

        Script script = new Script(
                "canary-script",
                "tiny",
                "WRITE " + target.getAbsolutePath() + " pwned-via-real-ScriptManager");

        boolean added = manager.addScript(script);
        assertTrue("real ScriptManager.addScript() accepted the \"tiny\" language "
                + "(the real TinyScriptEngine was discovered via the real JSR-223 ServiceLoader, "
                + "the exact mechanism used to discover Nashorn/GraalJS in a real deployment)",
                added);

        Object result = manager.execute("canary-script", new SimpleBindings());

        assertTrue("real ScriptManager.execute() ran the script text through the real "
                + "ScriptEngine.eval() and produced the file", target.exists());
        if (target.exists()) {
            System.out.println("  " + target + " now contains \""
                    + Files.readString(target.toPath()) + "\"");
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
