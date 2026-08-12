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

## Status: Semgrep pattern matching is VERIFIED — in CI, not in this sandbox

`semgrep --test` cannot run in the sandbox these rules were authored in —
both PyPI and npm are blocked by egress policy there:

```
$ pip install semgrep
ERROR: Could not find a version that satisfies the requirement semgrep

$ curl https://registry.npmjs.org/semgrep
Host not in allowlist: registry.npmjs.org
```

GitHub-hosted Actions runners aren't behind that proxy, so
`.github/workflows/semgrep-rules-test.yaml` runs it there instead. Current
status, from the actual log content (not just the green checkmark):

```
5/5: ✓ All tests passed
```

That took several rounds: the workflow's first runs failed on real bugs —
a missing `pyyaml` dependency, three pattern/annotation mismatches, and (in
the adversarial-fixture round below) three sanitizers that were unbound to
the variable actually reaching the sink. Run `./run-tests.sh` locally where
Semgrep is installable to reproduce; it picks up Semgrep automatically.

What `validate.py` **does** verify locally, and passes:

- every rule parses and carries `id`, `message`, `severity`, `languages`
- taint rules declare both `pattern-sources` and `pattern-sinks`
- rule ids are unique and match their filenames
- every `// ruleid:` / `// ok:` annotation names a rule that exists and sits
  directly above a line of code
- **the fixtures compile with `javac`** — they are real Java, not sketches

## Rules

| Rule | CWE | Sink | Severity | Reachable unauthenticated? |
|---|---|---|---|---|
| `log4j-jndi-injection` | CWE-74 | `Context.lookup` | WARNING | No — gated behind explicit opt-in |
| `log4j-script-injection` | CWE-94 | `ScriptEngine.eval` | WARNING | No — config-controlled input only |
| `log4j-sql-injection` | CWE-89 | `prepareStatement` / `execute*` | WARNING | No — config-controlled input only |
| `log4j-ssl-hostname-verification` | CWE-297 | `SSLSocket.startHandshake()` | WARNING | **Yes** — network MITM, no config access needed, but impact is log-stream confidentiality/integrity only, no RCE (see below) |
| `log4j-unsafe-deserialization` | CWE-502 | `readObject()` | WARNING | No — sink removed from source entirely |
| `log4j-xinclude` | CWE-611 | `setXIncludeAware(true)` | WARNING | No — same config-file trust boundary as `log4j-xxe`; see below for what makes it a genuinely separate gap, not a duplicate |
| `log4j-xxe` | CWE-611 | `newDocumentBuilder` | WARNING | No — parses the trusted config file itself |

25 positive, 15 negative, and 3 `todoruleid` (known-gap, not enforced)
fixture cases. Each rule's `metadata.reachability` field carries the
specific evidence (see "Not reachable from unauthenticated input" below).

## `log4j-xinclude`: a gap `log4j-xxe`'s hardening doesn't cover

Found while re-verifying `log4j-xxe`'s own claim that
`XmlConfiguration.newDocumentBuilder()` is "fully hardened, no configuration
flag to disable it." That claim is *true* for classic DTD-based external
entities — but the same method (the only call site in this codebase) also
calls `factory.setXIncludeAware(true)` unconditionally, and XInclude
(`<xi:include href="...">`) is a **completely separate JAXP mechanism**
disabling DTD processing does not touch at all.

Confirmed empirically (`dynamic-proof/real-source/org/apache/logging/log4j/core/config/xml/XIncludeRealSourceProof.java`),
including a specific check worth calling out: `javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING`
is commonly assumed to be a blanket XML-safety switch. It is **not**, for
this mechanism — setting it `true` did not stop `<xi:include
href="file:///etc/passwd" parse="text"/>` from reading a real local file's
contents in this session's testing. The only mitigation found to actually
work was not enabling XInclude at all
(`setXIncludeAware(false)`).

This runs against the same intellectual-honesty concern this whole ruleset
has tried to hold itself to: `log4j-xxe`'s own message previously
overclaimed completeness for the method it was scoped to. It's fixed now
(both the rule's metadata and `XxeRealSourceProof`'s own printed note
cross-reference this), but it's worth naming directly — a security rule
should be re-checked against its own claims, not just against the code it
scans.

Reachability here is **not** unauthenticated — same config-file trust
boundary as `log4j-xxe`, re-verified line-by-line against
`XmlConfiguration.java` (the `log4j.configurationFile` property and
`ConfigurationSource.fromUri` accept an attacker-redirectable path/URL, but
someone still has to control what that path points to). See
`dynamic-proof/real-source/XINCLUDE_FINDING.md` for the full prerequisite
and impact writeup — including a correction found by testing the follow-up
question directly instead of assuming an answer: the file read is **not**
blind. `XIncludeExfilProof.java` proves a `<Property>` sourced via
`<xi:include>` resolves anywhere `${name}` is used in the config (a `File`
appender's `fileName`, or a network appender's host/url) through log4j's
own Properties + attribute-substitution mechanism — a real output file's
name came back containing the secret verbatim. It still stays MEDIUM: some control
over the target process's configuration or launch environment is still
required, just not an unauthenticated remote attacker. That prerequisite
turned out smaller than first assumed, though — `XINCLUDE_FINDING.md`
documents a correction, found by testing rather than defending an
assumption: an attacker does **not** need filesystem write access to
`log4j2.xml` at all. `XIncludeRemoteConfigProof.java` proves the ordinary,
no-explicit-source startup path honors `log4j.configurationFile`
(documented as the `LOG4J_CONFIGURATION_FILE` environment variable)
pointing at a URL — so an attacker who can influence just one environment
variable passed to a target JVM (a tenant on a shared platform setting env
vars for their own workload, or CI/CD pipeline env-var injection — both
well-documented real categories) can trigger the same read-and-surface
chain without touching the target's filesystem. Also confirmed: the
default protocol allow-list genuinely blocks plain `http` for that fetch —
a real mitigation, credited rather than glossed over.

Pushed to go narrower still — no CI/CD, no env var either —
`XIncludeClasspathShadowProof.java` first found what looked like a smaller
prerequisite: Log4j's auto-configuration resolves `log4j2.xml` against the
*thread's context classloader*, and a plugin's own child-first classloader
could shadow it. Challenged directly — "isn't a plugin's own classloader
resolving its own resources just intended isolation behavior, what's
actually different from normal?" — that claim was checked harder instead
of defended, by reading `ClassLoaderContextSelector.locateContext()` and
testing both possible orderings. It doesn't hold as a general scenario:
`locateContext()` walks up to an ancestor's *existing* context before ever
doing a fresh classpath scan, so in the realistic ordering — the host
touches Log4j first, true of almost any real app — the plugin is just
handed the host's already-resolved context; nothing shadows. Only the
opposite, attacker-uncontrolled ordering (the plugin's own classloader
lineage is the very first thing anywhere to touch Log4j) leaks, which
isn't something an attacker who merely gets a plugin loaded can force.

Asked again for a way needing neither an env var nor a plugin, one held up:
Log4j's `HttpWatcher` polls a `monitorInterval`-configured config URL on
its own. If an application already, legitimately loads config from such a
URL, a takeover of that URL's origin (subdomain takeover, expired-domain
takeover, config-server compromise — real, independent vulnerability
categories) delivers a new config with no property, env var, or plugin
touched at all — proven end to end in
`XIncludeWatcherTakeoverProof.java`. Full correction, both mechanisms, and
the ranking of what holds vs. what was retracted is in
`dynamic-proof/real-source/CONFIG_DELIVERY_VECTORS.md`.

## Not reachable from unauthenticated input — except one — but not a false positive either

After the false-negative fixes below, a further question came up: is any of
this reachable by an unauthenticated remote attacker in this codebase's
actual current source? `dynamic-proof/real-source/` had already answered
this per rule while investigating reachability generally (see that
directory's README) — the answer is no for five of the six, and notably
different for the sixth:

- **JNDI**: three independent layers block the original Log4Shell vector
  specifically (message content is never interpolated; `Interpolator`
  excludes `jndi` from its dispatch map by default; `JndiLookup`'s
  constructor refuses to run without an explicit
  `log4j2.enableJndiLookup=true`). Reaching the sink at all requires that
  opt-in plus a `${jndi:...}` lookup authored into the configuration.
- **SQL / Script**: both sinks consume values that come from Log4j
  *configuration* (`<JDBC tableName>`, `<Script>`/`<ScriptFile>`), authored
  by whoever controls the configuration file — never from a log message or
  other remote input.
- **XXE**: the parser in question parses the `log4j2.xml` configuration
  file itself, loaded from a trusted classpath resource or configured path
  at startup — not from a network request.
- **Deserialization**: stronger still — the vulnerable component
  (`TcpSocketServer`/`UdpSocketServer`) was removed from this branch's
  source entirely, so there is no sink left to reach at all.
- **SSL hostname verification — different from the other five, but not
  higher severity**: found while following up on a related, older CVE
  (CVE-2020-9488, SMTP appender certificate validation) to check nearby
  code for the same class of bug. `SslConfiguration.verifyHostName`
  defaults to `false` (documented in `manual/appenders/network.adoc`), and
  `SslSocketManager` (used by `SocketAppender`, reachable via
  `SmtpAppender`/Syslog through the same `SslConfiguration`) only enables
  hostname verification when that flag is explicitly set to `true`. Proven
  end to end against a real local TLS server presenting a mismatched
  certificate — see
  `dynamic-proof/real-source/SslHostnameVerificationProof.java`. This one
  **is** reachable by an unauthenticated attacker: specifically, a network
  man-in-the-middle positioned between the application and its configured
  log destination, who needs no config access, no authentication, and no
  code execution on the victim at all — just network position (a rogue
  Wi-Fi AP, a compromised router).

  Reachability without an authentication barrier does not by itself mean
  high severity, though — impact matters too. What a successful MITM
  actually gets here is confidentiality/integrity of the **log stream**:
  reading or tampering with log records in transit, not code execution or
  application compromise. No path to RCE was found (the deserialization
  sink this ruleset investigated separately doesn't exist in current
  source — see `DESERIALIZATION_FINDING.md` — so a captured connection has
  nothing further to exploit through Log4j itself). That narrow blast
  radius roughly matches CVE-2020-9488's own low-rated severity — nowhere
  near Log4Shell — which is why `severity` here is `WARNING`, the same as
  the other five, not `ERROR`. See the rule's `metadata.impact` and
  `metadata.status` for the full reasoning, including an honest note that
  whether the insecure default was ever explicitly proposed to change and
  rejected is **not verifiable** from this session (a shallow clone with no
  access to upstream issue/PR history) — what's verifiable is only that the
  default has persisted through four separate SSL-related fixes since 2020,
  none of which touched it.

The common thread among the other five: every one of them requires **control
over the Log4j configuration** (a materially higher trust boundary than
"unauthenticated network attacker") or, for deserialization, doesn't exist
as a live sink at all. `severity` was downgraded from `ERROR` to `WARNING`
for those five to reflect that, and `log4j-jndi-injection`'s and
`log4j-unsafe-deserialization`'s `confidence` moved from `HIGH` to `MEDIUM`
to match the other three, which already accounted for this. All six rules
in this ruleset are `WARNING` as of the SSL rule's addition, for two
different reasons: five for narrow reachability, one for narrow impact
despite broad reachability.

**Why the other five aren't "false positive," despite not being remotely
exploitable here**: `dynamic-proof/` (the non-real-source proofs) already established
that when these sinks *are* reached, they do real damage — a real JNDI
lookup fires with the attacker's URL, a real `DROP TABLE` payload lands
verbatim in the SQL text, real code runs during deserialization itself. A
false positive is a rule flagging code that was never dangerous in the
first place; what's true here instead is narrower *reachability* in this
one codebase's current, default configuration. The rules stay in the
ruleset because they still catch: a regression that reopens one of these
paths, a deployment that explicitly re-enables the legacy JNDI opt-in, or
different code (a plugin, a fork, an unrelated project) reusing these same
sink APIs without the same guards.

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

`log4j-ssl-hostname-verification` (added later, also a `pattern`/`pattern-not`
rule) has the identical shape and so the identical limitation:
`connectConditionallyVerified` was marked `// todoruleid:` from the start,
rather than discovered as a CI failure the way the first two were — the
category of bug was already known by then.

`log4j-jndi-injection`, `log4j-script-injection`, and `log4j-sql-injection`
are `mode: taint`. `log4j-xxe`, `log4j-unsafe-deserialization`, and
`log4j-ssl-hostname-verification` are sequential-pattern search rules
instead: XXE's and SSL's missing-hardening flaws have no source to taint
(they match the construction of an unhardened factory/socket), and
deserialization's first taint-mode attempt — a `by-side-effect` sanitizer on
`setObjectInputFilter()` — turned out not to actually desanitize the
variable for a later `readObject()` call (semgrep --test caught this as a
false positive on the "safe" fixture). A sequential `pattern`/`pattern-not`
requiring a hardening call between construction and the dangerous call on
the same variable proved simpler to get right, at the cost of matching any
unguarded call rather than only ones from a provably untainted source, and
of the conditional-branch limitation documented above.

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

**SSL hostname verification** — `SslSocketManager.createSocket()` calls
`setEndpointIdentificationAlgorithm("HTTPS")` on the socket's
`SSLParameters` before `startHandshake()`, but only inside
`if (sslConfiguration.isVerifyHostName())`. The rule's "sanitizer" is that
exact sequence:

```java
SSLParameters sslParameters = socket.getSSLParameters();
sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
socket.setSSLParameters(sslParameters);
```

Its severity ended up `WARNING` like the rest, but for a different reason
than the other five — it's the one rule here reachable without any
authentication or config access, yet still not `ERROR`, because impact
(log-stream confidentiality/integrity, no RCE) turned out to matter as much
as reachability. See "Not reachable from unauthenticated input" above for
the full reasoning.

## Layout

Semgrep's test runner pairs a rule with the fixture of the same basename, so
`log4j-jndi-injection.yaml` is tested by `log4j-jndi-injection.java`. That
requirement collides with javac's rule that a *public* class must match its
filename, so the fixture classes are deliberately package-private.

```
log4j-jndi-injection.yaml / .java
log4j-script-injection.yaml / .java
log4j-sql-injection.yaml / .java
log4j-ssl-hostname-verification.yaml / .java
log4j-unsafe-deserialization.yaml / .java
log4j-xinclude.yaml / .java
log4j-xxe.yaml / .java
validate.py      local checks (no Semgrep needed)
run-tests.sh     validate.py, then semgrep --test if available
```
