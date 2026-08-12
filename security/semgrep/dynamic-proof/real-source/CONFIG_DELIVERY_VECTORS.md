# How does an attacker actually get malicious content into the config?

Every rule except `log4j-ssl-hostname-verification` shares the same
prerequisite: **the attacker needs to control what Log4j parses as
configuration.** That prerequisite was investigated four times in this
session, and — importantly — not every investigation held up. This note
collects what was found, including the one vector that turned out to be
wrong on closer inspection, and states plainly which rules each surviving
vector applies to.

## The vectors, in the order they were found — and corrected

| # | Vector | Filesystem write to host app? | CI/CD access? | Status |
|---|---|---|---|---|
| 1 | Direct filesystem write to `log4j2.xml` | Yes, by definition | No | Superseded — pushed back on as circular (see `XINCLUDE_FINDING.md`) |
| 2 | Config-location property/env var pointed at a URL (`log4j.configurationFile` / `LOG4J_CONFIGURATION_FILE`) | No | Only if that's *how* the env var is reached | **Holds** — proven end to end |
| 3 | Classpath resource shadowing via an uploaded plugin's own classloader | No | No | **Retracted as a general claim** — proven to only work under a narrow, attacker-uncontrolled ordering; does not hold as a realistic scenario |

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

## Which rules does the surviving vector (2) actually reach?

Config control is config control — a vector that delivers one malicious
`<Configuration>` document delivers whichever payload is inside it:

- **`log4j-xxe` / `log4j-xinclude`**: directly reached — proven.
- **`log4j-sql-injection`** (`<JDBC tableName>`) and
  **`log4j-script-injection`** (`<Script>`/`<ScriptFile>`): reached the
  same way — these payloads just need to be XML elements inside the same
  attacker-supplied `<Configuration>` document `XIncludeRemoteConfigProof.java`
  already proves can be delivered. Not re-proven separately: the delivery
  mechanism, not the payload string, is what that proof tests.
- **`log4j-jndi-injection`**: **partially** reached, and this is the one
  honest exception even for vector 2. It gets an attacker's `${jndi:...}`
  lookup into the config, but `JndiLookup`'s constructor separately
  requires `log4j2.enableJndiLookup=true` (`JndiLookup.java:46`) — a JVM
  system property/environment variable, not config-document content.
  Config content alone cannot set it, so JNDI needs a **second**,
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

The smallest *demonstrated and realistic* way to cross the config-control
boundary — for every config-driven rule except JNDI — is vector 2:
influence over one environment variable/property at process launch, which
is a materially lower bar than "sysadmin access" but still real,
attacker-relevant control, not a passive side effect of normal
architecture. Vector 3 looked smaller still at first, and the honest
result of checking it harder is that it isn't — a useful reminder, in a
ruleset built specifically around not overclaiming, that "found a proof
that passes" is not the same as "found a realistic scenario," and that the
difference is worth testing for directly rather than assuming away.
