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
| `log4j-sql-injection` | a malicious "table name," through the real JDBC appender's manager construction | `JdbcDatabaseManager.getManager()`, `ColumnConfig` |
| `log4j-script-injection` | a script, through the real script engine discovery and execution | `ScriptManager`, a real `javax.script.ScriptEngineFactory` registered via `META-INF/services` |
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

**XXE**: there is no vulnerable case to show against real source at all.
`XmlConfiguration.newDocumentBuilder()` calls its hardening unconditionally,
with no configuration flag to disable it — stricter than the JNDI case.

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
