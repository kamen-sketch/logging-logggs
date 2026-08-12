import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

/** Fixtures for log4j-jndi-injection. Compiles against the JDK alone. */
class JndiInjectionCases {

    private static final String JAVA_SCHEME = "java";
    private static final Set<String> ALLOWED = Set.of("java");

    private final InitialContext context = null;
    private final DirContext dirContext = null;

    // --- vulnerable ------------------------------------------------------

    /** The Log4Shell shape: substitution key flows straight into lookup(). */
    public Object lookupUnchecked(String key) throws NamingException {
        // ruleid: log4j-jndi-injection
        return context.lookup(key);
    }

    /** Concatenation does not sanitise; the attacker still controls the scheme. */
    public Object lookupPrefixedButUnvalidated(String key) throws NamingException {
        String name = "java:comp/env/" + key;
        // ruleid: log4j-jndi-injection
        return context.lookup(name);
    }

    /** A DirContext sink is equally dangerous. */
    public Object lookupViaDirContext(String key) throws NamingException {
        // ruleid: log4j-jndi-injection
        return dirContext.lookup(key);
    }

    /** lookupLink() resolves names the same way. */
    public Object lookupLinkUnchecked(String key) throws NamingException {
        // ruleid: log4j-jndi-injection
        return context.lookupLink(key);
    }

    /** Taint surviving an intermediate local is still taint. */
    public Object lookupThroughLocal(String key) throws NamingException {
        String copied = key;
        String target = copied.trim();
        // ruleid: log4j-jndi-injection
        return context.lookup(target);
    }

    // --- safe ------------------------------------------------------------

    /** The real JndiManager.lookup() guard: only null or "java" scheme passes. */
    public Object lookupWithSchemeCheck(String name) throws NamingException {
        try {
            final URI uri = new URI(name);
            if (uri.getScheme() == null || uri.getScheme().equals(JAVA_SCHEME)) {
                // ok: log4j-jndi-injection
                return context.lookup(name);
            }
        } catch (URISyntaxException ignored) {
            // fall through
        }
        return null;
    }

    /** Allow-list membership check before the lookup. */
    public Object lookupAllowListed(String key) throws NamingException {
        if (ALLOWED.contains(key)) {
            // ok: log4j-jndi-injection
            return context.lookup(key);
        }
        return null;
    }

    /** A constant name is not attacker-controlled. */
    public Object lookupConstant() throws NamingException {
        // ok: log4j-jndi-injection
        return context.lookup("java:comp/env/jdbc/AppDataSource");
    }
}
