# Semgrep taint rules for Log4j

Source-to-sink taint rules for the injection classes that actually matter in
this codebase, with positive and negative fixtures for `semgrep --test`.

```bash
./run-tests.sh
```

## Status: patterns are UNVERIFIED

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
| `log4j-unsafe-deserialization` | CWE-502 | `new ObjectInputStream` | CVE-2019-17571 |
| `log4j-xxe` | CWE-611 | `newDocumentBuilder` | `config/xml/XmlConfiguration.java:175` |

19 positive and 13 negative fixture cases.

The first four are `mode: taint`. `log4j-xxe` is a search rule, because a
missing-hardening flaw has no source to taint — it matches the construction of
an unhardened parser instead.

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
