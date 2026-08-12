# Semgrep taint rules for Log4j

Source-to-sink taint rules for the injection classes that actually matter in
this codebase, with positive and negative fixtures for `semgrep --test`.

```bash
./run-tests.sh
```

## Is this a false positive? See `dynamic-proof/`

`semgrep --test` only proves a *pattern* matches or doesn't match some text —
it can't prove the matched sink is actually dangerous, or that the "safe"
fixture is actually safe rather than just not matching by coincidence. Both
are what a false positive/negative looks like.

`dynamic-proof/` answers that with runtime evidence instead: it actually
executes the vulnerable and guarded code paths for all five rules and shows
the observable difference — a real JNDI `lookup()` call captured with the
attacker's string, a real `DROP TABLE` payload appearing inside the literal
SQL reaching `prepareStatement()`, a real local file exfiltrated through an
XML external entity, real code running during deserialization itself, real
arbitrary-file-write from text reaching `eval()` — and shows each guarded
fixture genuinely blocking it, not just failing to match a pattern.

```bash
cd dynamic-proof && ./run-all.sh
```

Needs only a JDK — no network, no real LDAP/database/scripting-engine. See
`dynamic-proof/README.md` for how each proof works.

That still uses stand-ins (a `Proxy` for `Context`, a hand-written
`ScriptEngine`) for the sink *API*, which says nothing about whether *this
codebase's actual classes* are reachable and guarded right now.
`dynamic-proof/real-source/` goes one step further: it compiles against the
real Log4j classes built by `../../nomaven-build/` and drives their real
public entry points — a log message through the real message-formatting →
lookup pipeline, a malicious table name through the real
`JdbcDatabaseManager.getManager()`. It also found, and documented with
evidence, the one case where reachability no longer exists at all: the
deserialization CVE's vulnerable component was removed from this branch's
source, not patched. See `dynamic-proof/real-source/README.md`.

## Status: Semgrep pattern matching is UNVERIFIED

`semgrep --test` has **not** been run. Semgrep could not be installed in the
environment these were written in — both package sources are blocked by egress
policy:

```
$ pip install semgrep
ERROR: Could not find a version that satisfies the requirement semgrep

$ curl https://registry.npmjs.org/semgrep
Host not in allowlist: registry.npmjs.org
```

So treat the rules as reviewed-but-untested: the sinks and sanitizers are read
off the real source (line references below), but whether each *pattern* matches
what it is meant to match has not been demonstrated. Run `./run-tests.sh` where
Semgrep is available before relying on them or wiring them into CI.

What `validate.py` **does** verify locally, and passes:

- every rule parses and carries `id`, `message`, `severity`, `languages`
- taint rules declare both `pattern-sources` and `pattern-sinks`
- rule ids are unique and match their filenames
- every `// ruleid:` / `// ok:` annotation names a rule that exists and sits
  directly above a line of code
- **the fixtures compile with `javac`** — they are real Java, not sketches

## Rules

| Rule | CWE | Sink | Grounded in |
|---|---|---|---|
| `log4j-jndi-injection` | CWE-74 | `Context.lookup` | `net/JndiManager.java:244` |
| `log4j-script-injection` | CWE-94 | `ScriptEngine.eval` | `script/ScriptManager.java:260` |
| `log4j-sql-injection` | CWE-89 | `prepareStatement` / `execute*` | `appender/db/jdbc/JdbcDatabaseManager.java:125,728` |
| `log4j-unsafe-deserialization` | CWE-502 | `readObject()` | CVE-2019-17571 |
| `log4j-xxe` | CWE-611 | `newDocumentBuilder` | `config/xml/XmlConfiguration.java:175` |

22 positive, 13 negative, and 2 `todoruleid` (known-gap, not enforced)
fixture cases.

## Known gap: conditional hardening/filtering is not detected

A deep re-review added one adversarial case per rule — code that is
genuinely vulnerable but structured to probe whether a guard nearby, without
actually protecting the tainted value, would wrongly suppress the finding.
Testing them via CI (not just reasoning about the YAML) found real bugs in
**all five rules**, now split into two outcomes:

**Fixed** — `log4j-jndi-injection`, `log4j-sql-injection`,
`log4j-script-injection`: each sanitizer was written as an unbound
`if (<... $CHECK(...) ...>) { ... }` with no connection between the checked
variable and the one reaching the sink, so a guard checking a *different,
unrelated* variable inside the same if-block wrongly sanitized the real
payload. Fixed by binding the sanitizer's metavariable to the sink's via
`pattern-inside` + `pattern: $NAME`, the same idiom already used for
`pattern-sources` in these rules. See `lookupInsideUnrelatedSchemeCheck`,
`insertInsideUnrelatedMatchesCheck`, `evalInsideUnrelatedAllowListCheck`.

**Not fixed, documented instead** — `log4j-xxe`'s `conditionallyHardened`
and `log4j-unsafe-deserialization`'s `readConditionallyFiltered`: hardening
or filtering applied in only *one branch* of an `if`, while the dangerous
call runs unconditionally, is still flagged as safe. `...` in `pattern-not`
was confirmed via CI to match straight through an untaken if-branch — a real
limitation of sequential AST pattern matching without a true
control-flow-sensitive dataflow engine, not a wording problem a different
pattern was found to fix. Marked `// todoruleid:` rather than `// ruleid:`
so the ruleset is honest about what it currently can't catch, instead of
either silently missing it or having a fixture that permanently fails.

`log4j-jndi-injection`, `log4j-script-injection`, and `log4j-sql-injection`
are `mode: taint`. `log4j-xxe` and `log4j-unsafe-deserialization` are
sequential-pattern search rules instead: XXE's missing-hardening flaw has no
source to taint (it matches the construction of an unhardened parser), and
deserialization's first taint-mode attempt — a `by-side-effect` sanitizer on
`setObjectInputFilter()` — turned out not to actually desanitize the
variable for a later `readObject()` call (semgrep --test caught this as a
false positive on the "safe" fixture). A sequential `pattern`/`pattern-not`
requiring a filter call between construction and `readObject()` on the same
variable proved simpler to get right, at the cost of matching any unfiltered
`readObject()` rather than only ones from a provably untainted source.

### Sanitizers are modelled on the real fixes

The point of taint mode here is that the rules should stay quiet on code that
is already correct. Each sanitizer is the guard this codebase actually uses:

**JNDI** — `JndiManager.lookup()` admits only an absent or `java:` scheme, which
is the post-Log4Shell fix:

```java
final URI uri = new URI(name);
if (uri.getScheme() == null || uri.getScheme().equals(JAVA_SCHEME)) {
    return (T) this.context.lookup(name);   // ok: log4j-jndi-injection
}
```

**XXE** — `XmlConfiguration.newDocumentBuilder()` calls
`setExpandEntityReferences(false)` plus three `setFeature()` calls; the fixture
reproduces that exact sequence as a negative case.

**SQL** — table and column names are identifiers, so they cannot be bound as
parameters. The sanitizer is a strict pattern check, since that is the only
correct fix available:

```java
if (tableName.matches("[A-Za-z_][A-Za-z0-9_]*")) { ... }
```

A note on that rule: `JdbcDatabaseManager` builds `"insert into " + tableName`
by concatenation. That is only exploitable by someone who controls the Log4j
configuration — a lower-severity position than a remote input — which is why
its confidence is `MEDIUM`. It is included because config-supplied identifiers
are a real, checkable pattern, not because it is a live vulnerability.

## Layout

Semgrep's test runner pairs a rule with the fixture of the same basename, so
`log4j-jndi-injection.yaml` is tested by `log4j-jndi-injection.java`. That
requirement collides with javac's rule that a *public* class must match its
filename, so the fixture classes are deliberately package-private.

```
log4j-jndi-injection.yaml / .java
log4j-script-injection.yaml / .java
log4j-sql-injection.yaml / .java
log4j-unsafe-deserialization.yaml / .java
log4j-xxe.yaml / .java
validate.py      local checks (no Semgrep needed)
run-tests.sh     validate.py, then semgrep --test if available
```
