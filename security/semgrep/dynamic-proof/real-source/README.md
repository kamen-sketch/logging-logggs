# Real-source proof: driving the actual Log4j classes, not a stand-in

The proofs one directory up (`../JndiInjectionProof.java` etc.) use
`java.lang.reflect.Proxy` and hand-written interpreters standing in for
`javax.naming.Context`, `java.sql.Connection`, `javax.script.ScriptEngine`.
That's enough to prove the *sink API* is dangerous in general, but it proves
nothing about *this codebase*: whether its actual `JndiLookup`, actual
`JdbcDatabaseManager`, actual `XmlConfiguration` are reachable from untrusted
input, or actually guarded, in the code as it exists right now.

This directory answers that instead, by compiling against the real compiled
classes in `nomaven-build/out/` (see `../../../../nomaven-build/`) and
calling their real public — and in one case, same-package — entry points.

```bash
../../../../nomaven-build/build.sh   # once, if out/ doesn't exist yet
./run-all.sh
```

## Why this matters: history repeats through *reachability*, not just APIs

Log4j 1.x's RCE and Log4Shell (CVE-2021-44228) share a root cause — a
dangerous sink (deserialization, JNDI lookup) — but they differ in
**reachability**: log4j 1.x's `SocketServer`/`SocketNode` deserialized
whatever arrived on a raw socket; Log4Shell was novel specifically because
*log message content itself*, not just configuration, could trigger a JNDI
lookup. A sink being dangerous in isolation says nothing about whether an
attacker can actually drive data to it in a given codebase and version. That
is what these proofs check, per rule:

| Rule | What was actually driven | Real classes involved |
|---|---|---|
| `log4j-jndi-injection` | a log message containing `${jndi:ldap://...}`, through the real formatting/lookup pipeline | `MessagePatternConverter`, `Interpolator`, `JndiLookup`, `JndiManager` |
| `log4j-xxe` | a malicious external-entity document, through the real config XML parser | `XmlConfiguration.newDocumentBuilder()` (package-private, called from its own package) |
| `log4j-xinclude` | a malicious `<xi:include>` document, through the SAME real config XML parser | `XmlConfiguration.newDocumentBuilder()` (same method as `log4j-xxe`, a different mechanism it doesn't harden) |
| `log4j-sql-injection` | a malicious "table name," through the real JDBC appender's manager construction | `JdbcDatabaseManager.getManager()`, `ColumnConfig` |
| `log4j-script-injection` | a script, through the real script engine discovery and execution | `ScriptManager`, a real `javax.script.ScriptEngineFactory` registered via `META-INF/services` |
| `log4j-ssl-hostname-verification` | a real local TLS server presenting a certificate for the WRONG hostname | `SslConfiguration`, `SslSocketManager.createSocket()` (private, reached via reflection) |
| `log4j-unsafe-deserialization` | nothing — investigated and found not reachable | see `DESERIALIZATION_FINDING.md` |

## What each proof found, concretely

**JNDI** turned out to have *three* independent real layers, not one —
found by running the real code and reading what it actually did, not by
assuming the URI-scheme check (the only guard the static rule models) was
the whole story:

1. `MessagePatternConverter`'s real source contains the comment *"Message
   Lookups are no longer supported"* — log message content is never passed
   through the substitutor at all, unconditionally. Proven by formatting a
   real `LogEvent` whose message *is* the payload and getting it back
   byte-for-byte unresolved.
2. `Interpolator`'s real, plugin-discovered lookup map (built from the same
   `Log4j2Plugins.dat` a production build generates) simply doesn't contain
   `"jndi"` unless `log4j2.enableJndiLookup=true` is set — read via
   reflection on the real field, not asserted from documentation.
3. `JndiLookup`'s own constructor throws `IllegalStateException` without
   that same property — discovered empirically when the first version of
   this proof crashed on `new JndiLookup()`, which is exactly the point:
   real code surprised the proof, rather than the proof asserting what it
   expected to find.

Only past all three — simulating an operator who explicitly opted back in,
which the property exists to allow — does `JndiManager`'s real
scheme-validating `lookup()` become reachable at all, and *that* real method
is what blocks `ldap:`/`rmi:`/etc. while still attempting `java:` names (the
attempt surfaces as a real `NamingException` at the real `javax.naming`
boundary in this sandbox, since no `InitialContext` provider is registered —
that exception is itself proof the call was reached, not evidence of a bug).

**XXE**: there is no vulnerable case to show against real source for classic
DTD-based external entities specifically. `XmlConfiguration.newDocumentBuilder()`
calls its hardening unconditionally, with no configuration flag to disable
it — stricter than the JNDI case.

**XInclude — found by re-checking that XXE claim, not by assuming it held**:
the same `newDocumentBuilder()` call also enables XInclude unconditionally
(`factory.setXIncludeAware(true)`), and XInclude is a *separate* JAXP
mechanism the DTD hardening above does not touch at all. A crafted
`<xi:include href="file:///path" parse="text"/>` reads the target as raw
text — confirmed against the real method, a real local file leaked
verbatim. Also confirmed: `javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING`,
often assumed to be a blanket XML-safety switch, does **not** block this —
tested directly rather than trusted from documentation. The only
mitigation that worked in this session's testing was not enabling
XInclude at all. Same trust boundary as XXE, **not** unauthenticated remote
input — see `XINCLUDE_FINDING.md` in this directory for the full
prerequisite/impact writeup, including a correction: the read is **not**
blind. `XIncludeExfilProof.java` drives the real startup path
(`Configurator.initialize()`) with a config where a `<Property>` sourced
via `<xi:include>` is referenced as `${leak}` in a real `File` appender's
`fileName` — the secret file's contents came back out as part of a real
output file's name on disk, through log4j's own Properties +
attribute-substitution mechanism, no second bug needed. A network appender
pointed at attacker infrastructure would exfiltrate the same content
off-host (not verified here — no outbound network in this sandbox — but
the substitution step is identical). Why this still stays MEDIUM: reaching it still requires some control over
the target process's configuration or launch environment, not an
unauthenticated remote attacker sending ordinary application input.

That prerequisite turned out to be smaller than first assumed, though —
corrected twice in `XINCLUDE_FINDING.md`, each time by testing an
assumption instead of keeping it. The first version of the real-world
scenario assumed an attacker could overwrite `log4j2.xml` on disk; pushed
back on as unrealistic (most real deployments don't let an attacker write
to that path without already having far more access than this finding
needs), it was rechecked against real code instead of defended, and found
to be avoidable entirely: `XIncludeRemoteConfigProof.java` drives the
ordinary, no-explicit-source `LogManager`/`ConfigurationFactory` startup
path and shows that `log4j.configurationFile` — documented as the
`LOG4J_CONFIGURATION_FILE` environment variable — accepts a URL, resolved
through `ConfigurationSource.fromUri()`/`UrlConnectionFactory`. No
filesystem write to the target host is needed at all: an attacker who can
influence one environment variable passed to a target JVM (a tenant setting
env vars for their own workload on a shared platform, or CI/CD pipeline env
var injection — both well-documented real categories) can point it at
infrastructure they host, and the same `XIncludeExfilProof.java` chain
fires from there. Also confirmed, not assumed: `UrlConnectionFactory`'s
default protocol allow-list (`file, https, jar`) genuinely blocks a
plain-`http` version of this — real log output showed the exact rejection
(`Protocol http has not been enabled as an allowed protocol`) — so the
proof demonstrates the mechanism with `http` explicitly re-allowed (an
operator-level property, not a code change) alongside that negative
control, rather than glossing over the mitigation that exists.

Asked to go narrower still — no CI/CD, no env var, no filesystem write at
all — `XIncludeClasspathShadowProof.java` first appeared to find one:
Log4j's auto-configuration resolves `log4j2.xml` against the thread's
*context* classloader, and a plugin's own child-first classloader (a real,
common isolation pattern) could shadow it. That claim was directly
challenged — isn't a plugin resolving its own resources just intended
classloader-isolation behavior, not different from normal? — and checking
it harder, instead of defending it, disproved it as a general scenario.
`ClassLoaderContextSelector.locateContext()` walks up to an *existing*
ancestor context before ever doing a fresh classpath scan; in the
realistic ordering (the host touches Log4j first, true of almost any real
app), the plugin is simply handed the host's already-resolved context —
`hostCtx == pluginCtx`, confirmed directly — and nothing shadows. Only the
opposite, attacker-uncontrolled ordering leaks, which isn't something an
attacker who merely gets a plugin loaded can reliably force. The proof and
the full correction are kept on record in
`CONFIG_DELIVERY_VECTORS.md` — not as a viable scenario, but because
testing a claim harder instead of defending it is exactly the standard
this ruleset holds itself to, wrong claims included.

Asked once more for a way needing neither an env var nor a plugin, one
held up. Log4j's `HttpWatcher` (`AbstractConfiguration.monitorSource()`)
polls a `monitorInterval`-configured config URL on its own — a real,
documented pattern for centralized config management. If an application
already, legitimately loads config from such a URL, a takeover of that
URL's origin (subdomain takeover, expired-domain takeover, or a
compromise of the config server itself — real, independent, well-
documented vulnerability categories) delivers a new config with no
property, env var, or plugin touched at all: the property is set exactly
once, by a simulated legitimate operator, before the takeover, and never
touched again. Proven end to end
(`XIncludeWatcherTakeoverProof.java`) — including a real bug caught in the
proof's own test harness, not just in Log4j: the mock HTTP server needed
a `Last-Modified` response header, or `monitorSource()` silently declines
to install any watcher at all (logged plainly as "does not support
dynamic reconfiguration," found only by reading the actual debug output).
`CONFIG_DELIVERY_VECTORS.md` has the full ranking of every vector that
holds and every one retracted, and which other rules each reaches.

**SQL**: the real `JdbcDatabaseManager.getManager()` — the exact method a
configured `<JDBC>` appender calls — was driven with a `DROP TABLE` payload
as a table name, and the resulting SQL field (read via reflection, since it
backs the real `prepareStatement()` call at
`JdbcDatabaseManager.java:728`) contained it verbatim. No validation exists
on this real path.

**Script injection**: the real `ScriptManager` discovered `TinyScriptEngine`
through the genuine JSR-223 `ServiceLoader` mechanism (a
`META-INF/services/javax.script.ScriptEngineFactory` file, exactly how
Nashorn or GraalJS would be discovered in a real deployment) and executed a
script through it via `ScriptManager.execute()`, not a bypass of it.

**Deserialization**: see `DESERIALIZATION_FINDING.md`. The vulnerable
component (`TcpSocketServer`/`UdpSocketServer`, log4j-core's equivalent of
log4j 1.x's `SocketServer`/`SocketNode`) genuinely existed — the changelog
even shows its `ObjectInputFilter` mitigation (`LOG4J2-1863`) — but it has
since been removed from this branch's source entirely, so there is nothing
left to drive a reachability proof through.

**SSL hostname verification**: found while following up on a different
historical CVE (CVE-2020-9488, improper certificate validation in the SMTP
appender) to check whether related code elsewhere had the same class of
bug. `SslConfiguration.verifyHostName` defaults to `false`
(`manual/appenders/network.adoc`), and `SslSocketManager.createSocket()`
(the code `SocketAppender` uses, reached here via reflection since the
method is `private`) only calls `setEndpointIdentificationAlgorithm("HTTPS")`
-- the mechanism that actually performs hostname verification -- when that
flag is `true`. Proven end to end with a real local `SSLServerSocket`
(`gen-ssl-certs.sh` generates a self-signed cert for `attacker.invalid` and
a truststore that trusts it, so the trust chain passes and only hostname
verification could catch the mismatch): with the default, a real TLS
handshake against a client connecting to `"localhost"` completes anyway;
with `verifyHostName=true`, the same certificate is rejected with
`CertificateException: No subject alternative DNS name matching localhost
found.` No external network access is used — the whole proof runs on
`127.0.0.1`.

Unlike the other five rules, this one's reachability doesn't require config
control or an explicit opt-in from the victim: a network man-in-the-middle
(rogue Wi-Fi, compromised router) needs no access to the victim's systems
at all, just network position. `HttpAppender`'s own `verifyHostName`
defaults to `true` — the inconsistency between two TLS configuration
surfaces in the same codebase is itself a sign this wasn't a deliberate,
reviewed choice so much as a gap.
