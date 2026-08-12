# How does an attacker actually get malicious content into the config, without CI/CD access or a filesystem write?

Every rule except `log4j-ssl-hostname-verification` shares the same
prerequisite: **the attacker needs to control what Log4j parses as
configuration.** That prerequisite was investigated three times in this
session, each time narrowed further by testing an assumption instead of
keeping it. This note collects the three vectors found, ranks them by how
little they actually require, and states plainly which rules each one
applies to — because "config control" is not XInclude-specific: whatever
delivers a malicious `log4j2.xml` delivers *any* payload this ruleset
covers.

## The three vectors, narrowest first

| # | Vector | Needs a filesystem write to the host app? | Needs CI/CD access? | Proof |
|---|---|---|---|---|
| 1 | **Classpath resource shadowing** — an uploaded plugin/driver/theme's own classloader is queried (as thread-context classloader) by Log4j's default `log4j2.xml` auto-detection before the host app's own classloader is | **No** | **No** | `XIncludeClasspathShadowProof.java` |
| 2 | **Config-location property/env var pointed at a URL** (`log4j.configurationFile` / documented `LOG4J_CONFIGURATION_FILE`) | No | Only if that's *how* the attacker reaches the env var — see below | `XIncludeRemoteConfigProof.java` |
| 3 | **Direct filesystem write to `log4j2.xml`** | Yes, by definition | No | superseded, see `XINCLUDE_FINDING.md` |

Vector 3 was the first one written up in this session and was correctly
pushed back on: in most real deployments, being able to overwrite that
specific path already implies access well beyond what this finding needs.
It's kept in the record as a corrected assumption, not as the leading
scenario.

Vector 2 doesn't strictly require CI/CD — a multi-tenant platform where a
tenant sets environment variables for *their own* workload is one way to
reach it without any pipeline involved (see `XINCLUDE_FINDING.md`'s
"Real-world scenario" section) — but CI/CD env-var injection is the
best-documented, most concrete real category, so it tends to dominate the
write-up.

**Vector 1 is the narrowest of the three and needs neither.** Proven
directly (`XIncludeClasspathShadowProof.java`, driven through this
repository's real `ConfigurationFactory`/`LoaderUtil` code, not a
description of how classloaders are supposed to work): a plugin that
merely gets *loaded* — through whatever self-service upload feature an
application already exposes for something unrelated to logging (a custom
JDBC driver, a UI theme, a data connector, an analysis plugin) — can have
its own classloader become the thread-context classloader Log4j's
auto-configuration consults, if that plugin architecture uses child-first
delegation (real, common, and specifically chosen by many real Java plugin
systems, including OSGi, so a plugin's own resources can override the
host's). A `log4j2.xml` bundled in that plugin gets picked up ahead of the
host application's real one — no write to any path the host app controls,
no environment variable, no pipeline. The one thing NOT verified in this
session: that any *specific* real product's plugin/upload feature has
exactly this classloading shape. That architectural pattern (child-first
plugin isolation) is real and common, not invented for this write-up, but
which products expose it in an exploitable way was not checked against a
named product here.

## Which rules does each vector actually reach?

Config control is config control — a vector that delivers one malicious
`<Configuration>` document delivers whichever payload is inside it. None of
the three vectors above is XInclude-specific:

- **`log4j-xxe` / `log4j-xinclude`**: directly reached — this is what all
  three proofs above demonstrate.
- **`log4j-sql-injection`** (`<JDBC tableName>`) and
  **`log4j-script-injection`** (`<Script>`/`<ScriptFile>`): reached the
  same way, by the same vectors — these payloads just need to be XML
  elements inside the same attacker-supplied `<Configuration>` document
  that `XIncludeClasspathShadowProof.java` and `XIncludeRemoteConfigProof.java`
  already prove can be delivered without CI/CD or a filesystem write to the
  host app. Not re-proven separately here because the delivery mechanism,
  not the payload, is what those proofs are about — re-running them with a
  different payload string would not test anything new.
- **`log4j-jndi-injection`**: **partially** reached, and this is the one
  honest exception. These vectors get an attacker's `${jndi:...}` lookup
  into the config, but `JndiLookup`'s constructor separately requires
  `log4j2.enableJndiLookup=true`
  (`JndiLookup.java:46`) — a JVM system property/environment variable, not
  config-document content. None of the three vectors above sets that
  property; config content alone cannot set it. So `log4j-jndi-injection`
  still needs a **second**, independent condition beyond config delivery:
  either the target environment already opted back into JNDI lookups (a
  real category — organizations that explicitly re-enabled it post-Log4Shell
  for legacy compatibility) or a further, separate way to influence that
  specific property. Neither was found or tested in this session. This
  keeps JNDI's real-world bar meaningfully higher than the other
  config-driven rules, even after narrowing the config-delivery
  prerequisite itself.
- **`log4j-ssl-hostname-verification`**: not part of this discussion at
  all — it is the one rule that needs none of this. A network
  man-in-the-middle position is sufficient on its own (see
  `dynamic-proof/real-source/README.md`), which is why it was already the
  strongest "real world, no config control" finding in this ruleset before
  any of the above was investigated.
- **`log4j-unsafe-deserialization`**: moot — the sink was removed from this
  branch's source entirely (`DESERIALIZATION_FINDING.md`), so there's
  nothing for any delivery vector to reach.

## What this changes

Before this note, "config control" was documented per-rule as a single,
somewhat abstract trust boundary. After it: the smallest concrete way to
cross that boundary — for every config-driven rule except JNDI — is
control of a classloader an application's own plugin/upload feature
willingly loads, which is a materially lower bar than "sysadmin access" or
"a CI pipeline misconfiguration," and does not require the target
filesystem to be touched at all.
