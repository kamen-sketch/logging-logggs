# How does an attacker actually get malicious content into the config?

Every rule except `log4j-ssl-hostname-verification` shares the same
prerequisite: **the attacker needs to control what Log4j parses as
configuration.** That prerequisite was investigated five times in this
session, and — importantly — not every investigation held up. This note
collects what was found, including the one vector that turned out to be
wrong on closer inspection, and states plainly which rules each surviving
vector applies to.

## The vectors, in the order they were found — and corrected

| # | Vector | Filesystem write to host app? | Env var/property attacker-set? | CI/CD access? | Status |
|---|---|---|---|---|---|
| 1 | Direct filesystem write to `log4j2.xml` | Yes, by definition | No | No | Superseded — pushed back on as circular (see `XINCLUDE_FINDING.md`) |
| 2 | Config-location property/env var pointed at a URL (`log4j.configurationFile` / `LOG4J_CONFIGURATION_FILE`) | No | Yes | Only if that's *how* the env var is reached | **Holds** — proven end to end |
| 3 | Classpath resource shadowing via an uploaded plugin's own classloader | No | No | No | **Retracted as a general claim** — proven to only work under a narrow, attacker-uncontrolled ordering; does not hold as a realistic scenario |
| 4 | Takeover of an already-trusted, `monitorInterval`-polled config URL (`HttpWatcher`) | No | No | No | **Holds** — proven end to end |

Vector 4 was found in direct response to being asked for another way that
needs neither an env var nor a plugin. Unlike vector 2, the attacker never
sets or touches `log4j.configurationFile`/`LOG4J_CONFIGURATION_FILE` at
all — that property is set exactly once, by legitimate operators, before
any attacker is involved. Unlike vector 3, it does not depend on an
attacker-uncontrolled timing race; it fires deterministically every
`monitorInterval` once the takeover has happened.

### Vector 1 — superseded

Assumed an attacker could overwrite `log4j2.xml` directly. Pushed back on,
correctly: in most real deployments that path isn't writable without
already having far more access than this finding needs. Kept in the record
as a corrected assumption.

### Vector 2 — holds

`XIncludeRemoteConfigProof.java` drives the real, no-explicit-source
`ConfigurationFactory` startup path and shows `log4j.configurationFile`
(documented as the `LOG4J_CONFIGURATION_FILE` environment variable)
accepts a URL, with no filesystem write to the target host involved. An
attacker who can influence one environment variable passed to a target
JVM — a tenant setting env vars for their own workload on a shared
platform, or CI/CD pipeline env-var injection — can reach it. Also
confirmed: the default protocol allow-list genuinely blocks plain `http`,
a real mitigation. Full detail in `XINCLUDE_FINDING.md`.

### Vector 3 — retracted as a general claim, and here's exactly why

This was the response to being asked, correctly, "isn't classpath
shadowing just intended behavior — what's actually different from
normal?" That question was answered by reading
`ClassLoaderContextSelector.locateContext()` (the real default context
selector for non-Android JVMs) and testing both possible orderings, not by
re-arguing the first proof's result.

The mechanism: `locateContext()` does **not** give every classloader an
independently-resolved context. It only performs a fresh classpath scan
for `log4j2.xml` when **no context is already registered for that
classloader or any of its ancestors** — it walks the parent chain first
and **reuses an ancestor's existing context if one is found**. That walk
exists specifically to prevent cross-boundary config confusion between a
parent (host) and a child (plugin) classloader — it is the mechanism
working as designed, not a gap in it.

`XIncludeClasspathShadowProof.java` now tests both orderings and reports
both results:

- **Realistic ordering** (host touches Log4j first — true of almost every
  real application, which logs a startup message before ever loading a
  user-supplied plugin): the plugin's classloader was handed the *same*
  object as the host's already-established context. The plugin's shadowed
  `log4j2.xml` was **never read**. No leak. Confirmed: `hostCtx ==
  pluginCtx` is `true`.
- **Narrow ordering** (the plugin's classloader lineage is the very first
  thing anywhere in the process to touch Log4j, before the host's own
  lineage ever does): the shadowed config *is* read and the secret *does*
  leak — this is the case the earlier, corrected version of this proof
  tested exclusively, without checking whether it was representative.

The narrow ordering is not something an attacker who merely gets a plugin
loaded can reliably force — it depends on exactly when, relative to the
host's own first log statement, the plugin's classloader lineage happens
to touch Log4j, which the plugin author does not control. That makes
vector 3 a real but narrow, timing-dependent edge case, not a general
property of plugin/upload architectures. It is **not** presented as a
viable real-world scenario alongside vector 2. The proof and this note are
kept because the correction itself — and the mechanism that causes it — is
worth having on record, and because the narrow ordering is not literally
impossible (e.g. a plugin/module system that discovers and initializes
plugins very early, before the host's own first log call), just not the
general case worth building a scenario around.

### Vector 4 — holds, and needs neither an env var nor a plugin

Log4j has a first-class, documented feature for centralized config
management: host `log4j2.xml` on an `http(s)://` URL, set
`monitorInterval` on the `<Configuration>` root element, and Log4j polls
that same URL on its own
(`AbstractConfiguration.monitorSource()` → `WatcherFactory` →
`HttpWatcher`, a real `@Plugin(name = "http")`) and reconfigures live when
the content changes — not an attacker-invented mechanism, a real pattern
for fleets of applications pulling config from one internal server.

`XIncludeWatcherTakeoverProof.java` proves the full chain: a benign config
is loaded first from a URL (the property is set exactly once here, playing
the part of an operator's pre-existing, legitimate setup — never touched
again afterward); the secret does not leak yet. Then, with **no property,
env var, or plugin touched**, only the content served at that *same,
already-trusted* URL changes — modeling what a takeover of that URL's
origin looks like from the application's side. The watcher's next check
(forced via the real `WatchManager.checkFiles()`, the same method the
background scheduler calls) picks up the new content and the secret leaks.

The real-world equivalent of "the content at an already-trusted URL
changes underneath an application that keeps polling it" is not
hypothetical — it's a well-documented, independent vulnerability category:
subdomain takeover (a dangling DNS record pointing at a decommissioned,
re-claimable cloud resource), expired-domain takeover, or compromise of
the config-hosting server itself. All three require neither
`log4j.configurationFile` to be attacker-set nor any plugin/classloader
involvement — only that the URL an application *already*, legitimately
trusts stops being under its original owner's control. One real
precondition this vector needs that vectors 2 and 3 don't: the
organization has to have set up URL-hosted, monitored configuration in the
first place, which is a real but not universal deployment pattern (most
of this session's other proofs load config from a local classpath
resource or file instead).

One thing found and fixed while building this proof, worth recording for
the same reason every other bug in this session's own tooling was: the
first version silently failed, because `AbstractConfiguration.monitorSource()`
declines to install *any* watcher at all when `configSource.getLastModified()`
is `0` (logged plainly as `"... does not support dynamic reconfiguration"`,
found only by reading actual debug output, not assumed) — a plain HTTP
response with no `Last-Modified` header produces exactly that. Real HTTP
config servers normally send one; the proof's test server was fixed to
send one too, rather than the finding being quietly quiet-failed past.

## Which rules do the surviving vectors (2 and 4) actually reach?

Config control is config control — a vector that delivers one malicious
`<Configuration>` document delivers whichever payload is inside it,
regardless of whether that document arrived via an attacker-set env var
(vector 2) or a takeover of an already-trusted, polled URL (vector 4):

- **`log4j-xxe` / `log4j-xinclude`**: directly reached — proven by both.
- **`log4j-sql-injection`** (`<JDBC tableName>`) and
  **`log4j-script-injection`** (`<Script>`/`<ScriptFile>`): reached the
  same way by both — these payloads just need to be XML elements inside
  the same attacker-supplied `<Configuration>` document
  `XIncludeRemoteConfigProof.java`/`XIncludeWatcherTakeoverProof.java`
  already prove can be delivered. Not re-proven separately: the delivery
  mechanism, not the payload string, is what those proofs test.
- **`log4j-jndi-injection`**: **partially** reached, and this is the one
  honest exception for both. Either vector gets an attacker's
  `${jndi:...}` lookup into the config, but `JndiLookup`'s constructor
  separately requires `log4j2.enableJndiLookup=true` (`JndiLookup.java:46`)
  — a JVM system property/environment variable, not config-document
  content. Config content alone cannot set it (and vector 4 in particular
  touches *no* property at all), so JNDI needs a **second**,
  independent condition: either the target environment already opted back
  into JNDI lookups (organizations that re-enabled it post-Log4Shell for
  legacy compatibility), or a further way to influence that specific
  property, neither of which was found or tested here.
- **`log4j-ssl-hostname-verification`**: outside this discussion entirely
  — the one rule needing none of it. A network man-in-the-middle position
  is sufficient on its own, which is why it remains the strongest "real
  world, no config control at all" finding in this ruleset.
- **`log4j-unsafe-deserialization`**: moot — no live sink in this branch's
  source (`DESERIALIZATION_FINDING.md`).

## What this changes

Two vectors now demonstrably cross the config-control boundary — for
every config-driven rule except JNDI — without needing "sysadmin access":
vector 2 (one environment variable/property, attacker-set) and vector 4
(no attacker-set property at all, just a takeover of a URL the
application was already, legitimately configured to trust and poll). They
suit different deployments: vector 2 applies wherever the attacker can
influence a target JVM's launch environment; vector 4 applies wherever an
organization already hosts config centrally over HTTP(S) with
`monitorInterval` set, regardless of who can touch that process's own env
vars.

Vector 3 looked smaller than both at first, and the honest result of
checking it harder — after being challenged directly on whether it was
really different from normal behavior — is that it isn't a general,
realistic scenario at all. That's kept on record deliberately: in a
ruleset built around not overclaiming, "found a proof that passes" is not
the same as "found a realistic scenario," and the gap between them is
worth testing for directly, including when the result contradicts a claim
already written down, rather than assumed away.
