# Dynamic proof: the sinks are real, not pattern-matching artifacts

`semgrep --test` (in `security/semgrep/`) only proves the Semgrep *pattern*
matches or doesn't match some text. It cannot prove:

- that the matched sink is actually dangerous when reached with attacker data
- that the "safe" fixture is actually safe, rather than merely not matching
  the pattern by coincidence

Both are exactly what a false positive/negative looks like: a rule that fires
on code that can't really be exploited, or one that stays quiet on code that
still is. This directory answers that with runtime evidence instead of text
matching — each proof actually executes the vulnerable path and the guarded
path and shows the observable difference.

```bash
./run-all.sh
```

## What each proof demonstrates, and how

| Proof | Rule under test | Vulnerable path shows | Guarded path shows |
|---|---|---|---|
| `JndiInjectionProof.java` | `log4j-jndi-injection` | attacker string reaches `Context.lookup()` verbatim | the `JndiManager`-style URI-scheme check stops it before the call — `Context.lookup()` is never invoked for `ldap:`/`rmi:` |
| `SqlInjectionProof.java` | `log4j-sql-injection` | a `DROP TABLE` payload appears **inside the literal SQL text** that reaches `prepareStatement()` | an identifier allow-list pattern rejects the payload before any SQL is built, and bound parameters never enter the SQL text at all |
| `UnsafeDeserializationProof.java` | `log4j-unsafe-deserialization` | `readObject()` runs attacker-defined code — a gadget's side effect fires — before any type check is possible | an `ObjectInputFilter` blocks the class by name; the side effect never fires |
| `XxeProof.java` | `log4j-xxe` | an external entity reads a local file and its contents leak into the parsed document | `XmlConfiguration`'s hardening sequence (`setExpandEntityReferences(false)` + three `setFeature` calls) blocks it — parsing fails, nothing leaks |
| `ScriptInjectionProof.java` | `log4j-script-injection` | text passed to `ScriptEngine.eval()` is interpreted as commands and produces a real side effect (a file write) | resolving script text from a fixed registry by id means attacker text never reaches `eval()` at all |

`log4j-ssl-hostname-verification` has no synthetic proof here — its
`real-source/SslHostnameVerificationProof.java` (a real local TLS server
with a mismatched certificate) is already the strongest possible evidence,
so a `Proxy`-based stand-in would add nothing.

None of this depends on network access, a real LDAP/RMI server, a real
database, or a real scripting engine (the JDK dropped Nashorn in 15, and
downloading GraalJS was blocked the same way `pip install semgrep` was — see
`../README.md`). Each proof either uses only the JDK, or implements the
target JSR/interface directly — `ScriptInjectionProof` provides its own
`javax.script.ScriptEngine`, so the sink under test is the real interface
method our rule matches, not a stand-in.

## The methodology, per proof

**JNDI** — `javax.naming.Context` is an interface, so a `java.lang.reflect.Proxy`
stands in for it and records every call it receives. The unguarded fixture
hands the proxy `ldap://attacker.example/a` and the proxy's `lookup()` fires
with that exact string — this is the mechanism of Log4Shell, independent of
whether a real LDAP server exists to answer. The guarded fixture runs the same
URI-scheme check `JndiManager.lookup()` uses; the proxy asserts it received
zero calls for that payload, and exactly one call, unchanged, for a
`java:comp/env/x` value.

**SQL** — `Connection`/`PreparedStatement`/`Statement` are also interfaces, so
proxies capture the exact SQL string reaching the sink instead of executing
against a real database. `insertIntoConfiguredTable` (string concatenation)
is fed `logs; DROP TABLE users; --` as a "table name" and the proxy's recorded
SQL contains that payload byte-for-byte — proving the injection is real, not
theoretical. The validated-identifier path rejects the same payload via
`matches("[A-Za-z_][A-Za-z0-9_]*")` before any SQL is built; the proxy records
zero calls.

**Deserialization** — a real `Serializable` class (`Gadget`) sets a static
flag inside `readObject()`, standing in for a exploit gadget's side effect.
Feeding its serialized bytes through a bare `ObjectInputStream` flips the
flag — proving code runs during deserialization itself, before the caller
ever inspects the returned type. Attaching an `ObjectInputFilter` that denies
the class by name blocks it: `readObject()` throws, the flag stays false.

**XXE** — a real local file (`secret.txt`) holds a canary string. The
unhardened `DocumentBuilder` parses a document whose `DOCTYPE` declares a
`SYSTEM` entity pointing at that file; the canary shows up in the parsed
`Document`'s text content. `XmlConfiguration.newDocumentBuilder()`'s exact
hardening sequence, reproduced in `factoryHardened()`, is applied to a builder
that parses the identical document; parsing throws before the entity is ever
resolved, and the canary never appears anywhere.

**Script injection** — the JDK ships no bundled `ScriptEngine` since Nashorn
was removed in JDK 15, and installing one (GraalJS, via Maven or npm) hits the
same blocked-registry wall documented in `../README.md`. So this proof
implements `javax.script.ScriptEngine` directly: a minimal line-oriented
interpreter whose only command, `WRITE <path> <text>`, performs a real
filesystem write — enough to demonstrate that arbitrary text reaching
`eval()` becomes arbitrary action, which is what CWE-94 actually means. The
unguarded fixture evaluates attacker text and the write happens; the guarded
fixture resolves script text from a fixed `Map` by id, so attacker text never
reaches `eval()`, and no file is written.

## Relationship to `semgrep --test`

This is a complement, not a replacement. `semgrep --test` (once it can
actually run — see `../README.md`) verifies the *pattern* fires on the right
lines. This verifies the lines it fires on describe *real* vulnerable
behaviour, and the lines it stays quiet on are *really* safe. A rule can pass
one and fail the other; both were needed.

## One more layer: `real-source/`

Everything above uses a `Proxy` or a hand-written interpreter standing in for
the real sink API (`Context`, `Connection`, `ScriptEngine`). That proves the
*API* is dangerous in general — it says nothing about whether *this
codebase's actual classes* are reachable from untrusted input, or actually
guarded, right now. `real-source/` answers that by compiling against the
real classes in `../../../nomaven-build/out/` and driving their real public
entry points instead — a log message through the real
`MessagePatternConverter → Interpolator → JndiLookup → JndiManager` pipeline,
a malicious table name through the real `JdbcDatabaseManager.getManager()`,
and so on. It also documents, with evidence rather than assumption, the one
case where no such path exists any more: the deserialization CVE's
vulnerable component was removed from this branch's source entirely, not
patched. See `real-source/README.md`.
