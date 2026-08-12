import java.io.File;
import java.io.Reader;
import java.nio.file.Files;
import java.util.Map;
import javax.script.AbstractScriptEngine;
import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.script.ScriptException;
import javax.script.SimpleBindings;

/**
 * Proves log4j-script-injection's sink is real. The JDK bundles no
 * ScriptEngine since Nashorn was removed in 15, and fetching one (GraalJS)
 * hits the same blocked package registries documented in ../README.md -- so
 * this implements javax.script.ScriptEngine directly. The interpreter is
 * intentionally tiny (one command, WRITE <path> <text>) but it is a real
 * implementation of the real interface our rule's sink pattern matches
 * (ScriptEngine.eval), and its one command performs a real filesystem
 * side effect -- enough to show that arbitrary text reaching eval() becomes
 * arbitrary action, which is what CWE-94 means.
 */
class ScriptInjectionProof {

    /** A minimal, real JSR-223 engine: `eval(script)` runs `WRITE <path> <text>` lines. */
    static final class TinyScriptEngine extends AbstractScriptEngine {
        @Override
        public Object eval(String script, ScriptContext context) throws ScriptException {
            for (String line : script.split("\n")) {
                line = line.strip();
                if (line.isEmpty()) continue;
                String[] parts = line.split(" ", 3);
                if (!"WRITE".equals(parts[0]) || parts.length < 3) {
                    throw new ScriptException("unsupported command: " + line);
                }
                try {
                    Files.writeString(new File(parts[1]).toPath(), parts[2]);
                } catch (Exception e) {
                    throw new ScriptException(e);
                }
            }
            return null;
        }

        @Override
        public Object eval(Reader reader, ScriptContext context) throws ScriptException {
            return eval(new java.io.BufferedReader(reader).lines()
                    .reduce("", (a, b) -> a + "\n" + b), context);
        }

        @Override
        public Bindings createBindings() {
            return new SimpleBindings();
        }

        @Override
        public ScriptEngineFactory getFactory() {
            throw new UnsupportedOperationException("not needed for this proof");
        }
    }

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== Script injection: dynamic proof ===\n");

        File canaryTarget = File.createTempFile("script-proof-canary", ".txt");
        canaryTarget.delete(); // must not exist yet; its creation IS the proof
        canaryTarget.deleteOnExit();

        vulnerableEvalWritesAttackerControlledFile(canaryTarget);
        guardedRegistryNeverEvaluatesAttackerText(canaryTarget);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    /** Attacker-controlled text reaches eval() and is executed as commands. */
    private static void vulnerableEvalWritesAttackerControlledFile(File target) throws Exception {
        ScriptEngine engine = new TinyScriptEngine();
        String attackerScript = "WRITE " + target.getAbsolutePath() + " pwned-by-eval";

        // ruleid: log4j-script-injection -- attacker text passed straight to eval()
        engine.eval(attackerScript);

        assertTrue("eval() of attacker-controlled text created a file that did not exist before",
                target.exists());
        if (target.exists()) {
            System.out.println("  vulnerable: " + target + " now contains \""
                    + Files.readString(target.toPath()) + "\" -- eval() executed attacker text.");
        }
        target.delete();
    }

    /** The only correct fix: script text comes from a fixed registry, never from input. */
    private static void guardedRegistryNeverEvaluatesAttackerText(File target) throws Exception {
        Map<String, String> configuredScripts = Map.of("noop", "WRITE /dev/null ignored");
        ScriptEngine engine = new TinyScriptEngine();

        String attackerSuppliedId = "'; WRITE " + target.getAbsolutePath() + " pwned; --";
        String resolved = configuredScripts.get(attackerSuppliedId); // never matches -> null

        boolean rejectedBeforeEval = (resolved == null);
        if (resolved != null) {
            engine.eval(resolved); // ok: log4j-script-injection -- would only run configured text
        }

        assertTrue("an unrecognised id resolves to null and is never passed to eval()",
                rejectedBeforeEval);
        assertTrue("no file was created -- attacker text never reached eval()", !target.exists());
        System.out.println("  guarded:    registry lookup for a malicious id returned null; "
                + "eval() was never called with it.");
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
