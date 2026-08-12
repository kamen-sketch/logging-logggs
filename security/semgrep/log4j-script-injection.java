import java.util.Map;
import java.util.Set;
import javax.script.Bindings;
import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

/** Fixtures for log4j-script-injection. Compiles against the JDK alone. */
class ScriptInjectionCases {

    private final ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
    private final Map<String, String> configuredScripts = Map.of("audit", "1 + 1");
    private static final Set<String> ALLOWED = Set.of("audit");

    // --- vulnerable ------------------------------------------------------

    /** Script text taken directly from a caller-supplied string. */
    public Object evalUserSupplied(String scriptText) throws ScriptException {
        // ruleid: log4j-script-injection
        return engine.eval(scriptText);
    }

    /** Same, with bindings -- the sink is still the script argument. */
    public Object evalUserSuppliedWithBindings(String scriptText, Bindings bindings)
            throws ScriptException {
        // ruleid: log4j-script-injection
        return engine.eval(scriptText, bindings);
    }

    /** Building the script from a log message is code injection. */
    public Object evalFromLogMessage(String formatted) throws ScriptException {
        String script = "var msg = '" + formatted + "'; msg.length";
        // ruleid: log4j-script-injection
        return engine.eval(script);
    }

    /** Compiling attacker-controlled text is as dangerous as evaluating it. */
    public CompiledScript compileUserSupplied(String scriptText) throws ScriptException {
        Compilable compilable = (Compilable) engine;
        // ruleid: log4j-script-injection
        return compilable.compile(scriptText);
    }

    // --- safe ------------------------------------------------------------

    /** Script text resolved from the configured registry, not from input. */
    public Object evalConfiguredScript(String id) throws ScriptException {
        String script = configuredScripts.get(id);
        // ok: log4j-script-injection
        return engine.eval(script);
    }

    /** Allow-listed id before resolution. */
    public Object evalAllowListed(String id) throws ScriptException {
        if (ALLOWED.contains(id)) {
            // ok: log4j-script-injection
            return engine.eval(configuredScripts.get(id));
        }
        return null;
    }

    /** A literal script is trusted. */
    public Object evalConstant() throws ScriptException {
        // ok: log4j-script-injection
        return engine.eval("return 42;");
    }
}
