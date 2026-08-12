import java.io.Reader;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;
import javax.script.AbstractScriptEngine;
import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.script.ScriptException;
import javax.script.SimpleBindings;

/**
 * A real, minimal JSR-223 engine, registered as a real ServiceLoader provider
 * (see META-INF/services/javax.script.ScriptEngineFactory) so the REAL
 * ScriptManager discovers it exactly as it would discover Nashorn or GraalJS
 * in a real deployment -- the JDK bundles no engine since Nashorn was removed
 * in 15, and installing one hits the same blocked package registries as
 * Semgrep itself (see ../../README.md). Its one command, WRITE <path> <text>,
 * performs a real filesystem side effect: enough to show that arbitrary text
 * reaching eval() -- through the real ScriptManager.execute() -- becomes
 * arbitrary action.
 */
public final class TinyScriptEngine extends AbstractScriptEngine {

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
                Files.writeString(new java.io.File(parts[1]).toPath(), parts[2]);
            } catch (Exception e) {
                throw new ScriptException(e);
            }
        }
        return null;
    }

    @Override
    public Object eval(Reader reader, ScriptContext context) throws ScriptException {
        return eval(new java.io.BufferedReader(reader).lines().reduce("", (a, b) -> a + "\n" + b), context);
    }

    @Override
    public Bindings createBindings() {
        return new SimpleBindings();
    }

    @Override
    public ScriptEngineFactory getFactory() {
        return new Factory();
    }

    public static final class Factory implements ScriptEngineFactory {
        @Override
        public String getEngineName() {
            return "tiny";
        }

        @Override
        public String getEngineVersion() {
            return "1.0";
        }

        @Override
        public List<String> getExtensions() {
            return Collections.singletonList("tiny");
        }

        @Override
        public List<String> getMimeTypes() {
            return Collections.emptyList();
        }

        @Override
        public List<String> getNames() {
            return Collections.singletonList("tiny");
        }

        @Override
        public String getLanguageName() {
            return "tiny";
        }

        @Override
        public String getLanguageVersion() {
            return "1.0";
        }

        @Override
        public Object getParameter(String key) {
            return null;
        }

        @Override
        public String getMethodCallSyntax(String obj, String m, String... args) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getOutputStatement(String toDisplay) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getProgram(String... statements) {
            return String.join("\n", statements);
        }

        @Override
        public ScriptEngine getScriptEngine() {
            return new TinyScriptEngine();
        }
    }
}
