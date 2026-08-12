# How does an attacker actually get malicious content into the config?

Every rule except `log4j-ssl-hostname-verification` **and**
`log4j-jmx-remote-reconfig`'s sibling finding, `MDC_PATH_TRAVERSAL_FINDING.md`
(a config-content *sink*, not covered by a rule yet, that needs no
config-authoring trust at all — see that file), shares the same
prerequisite: **the attacker needs to control what Log4j parses as
configuration.** That prerequisite was investigated seven times in this
session — including a broadened pass across `log4j-web`,
`log4j-spring-boot`, and `log4j-spring-cloud-config-client`, not just
`log4j-core` — and, importantly, not every investigation held up. This
note collects what was found, including one vector that turned out to be
wrong on closer inspection and one hypothesis that was tested and
disproved mid-investigation, and states plainly which rules each
surviving vector applies to.

**One distinction this whole note depends on, worth stating up front**:
"delivery vector" and "sink" are two different questions with two
different answers. `log4j-xinclude`'s own finding — `XmlConfiguration`
enabling XInclude unconditionally, uncovered by the DTD/XXE hardening next
to it — is a real, confirmed gap in Log4j's own code, unaffected by any of
what follows. What varies per vector below is only *how a bug bounty
hunter's or attacker's content reaches that sink at all*, and for some of
these vectors (5, specifically) reaching it isn't a Log4j bug either — it
depends on an operator having exposed a different, intended feature
without the access control that feature assumes. Retracted (3) means
"doesn't work as a general scenario, full stop." Intended-feature (5)
means something different: "works, but the part that's a security problem
lives entirely outside Log4j's own code, in how JMX access was set up."
Neither of those changes whether `log4j-xinclude` itself is a real
finding — it does.

## The vectors, in the order they were found — and corrected

| # | Vector | Filesystem write to host app? | Env var/property attacker-set? | Needs a URL at all? | `monitorInterval` needed? | Status |
|---|---|---|---|---|---|---|
| 1 | Direct filesystem write to `log4j2.xml` | Yes, by definition | No | No | No | Superseded — pushed back on as circular (see `XINCLUDE_FINDING.md`) |
| 2 | Config-location property/env var pointed at a URL (`log4j.configurationFile` / `LOG4J_CONFIGURATION_FILE`) | No | Yes | Yes (attacker-hosted) | No | **Holds** — proven end to end |
| 3 | Classpath resource shadowing via an uploaded plugin's own classloader | No | No | No | No | **Retracted as a general claim** — only works under a narrow, attacker-uncontrolled ordering |
| 4 | Takeover of an already-trusted, polled config URL (`HttpWatcher`) | No | No | Yes (someone else's, taken over) | **Yes** | **Holds** — proven end to end. Refinement: with `log4j-spring-cloud-config-client` present, an Actuator `/actuator/refresh` call triggers reconfiguration instantly instead of waiting out the poll interval — `monitorInterval` is still required either way, an initial hypothesis that it wasn't was tested and disproved |
| 5 | JMX `LoggerContextAdminMBean.setConfigText()` — config content pushed directly, no URL | No | No | **No** | No | **Holds as a delivery path — but not a Log4j bug.** The MBean is intended remote-management behavior; the security problem is entirely in JMX's own access control, external to Log4j. |

Vector 4 was found in response to being asked for a way needing neither an
env var nor a plugin — but it still needed `monitorInterval` and an
existing, already-trusted URL to take over. Vector 5 was found in response
to being asked for something narrower still: no `monitorInterval`, and the
content genuinely, directly attacker-controlled rather than depending on
compromising something that was already someone else's.

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

#### Vector 4 refinement: instant reconfiguration via Spring Cloud Config, not a new vector

Broadening the search past the modules already checked (`log4j-web`,
`log4j-spring-boot`) turned up `log4j-spring-cloud-config-client`, whose
`Log4j2EventListener` reacts to Spring's own `EnvironmentChangeEvent` —
fired by, among other things, Spring Boot Actuator's `/actuator/refresh`
endpoint — by calling `WatchManager.checkFiles()` immediately.

The first hypothesis this produced was wrong, and tested directly rather
than trusted: `AbstractConfiguration.initializeWatchers()` has a branch
that looks, in isolation, like it doesn't need `monitorInterval` —
`watchManager.hasEventListeners() && configSource.getURL() != null &&
monitorIntervalSeconds >= 0`. It registers the watched source either way.
But `WatchManager.start()` — the method that actually subscribes to any
`WatchEventService` at all — is separately gated by
`AbstractConfiguration.isConfigurationMonitoringEnabled()`, which requires
`watchManager.getIntervalSeconds() > 0` regardless of event listeners.
Without `monitorInterval` set, the event mechanism has nothing to
subscribe to. `XIncludeSpringCloudWatchProof.java`'s first run confirmed
this the hard way (a failing assertion), not by reading the source and
guessing correctly — so this is **not** a `monitorInterval`-free path,
and is folded into vector 4 rather than numbered separately.

What the corrected proof demonstrates instead, with `monitorInterval` set
deliberately high (3600s, so a leak within the proof's few-second wait
window can only be the event firing, not the periodic poll catching up):
an attacker who has already taken over a monitored config URL (vector 4's
real prerequisite, unchanged) doesn't have to wait out the poll interval
if they can also reach a Spring Boot Actuator `/actuator/refresh`
endpoint — itself a separate, well-documented category of exposure. A
genuine, real refinement of vector 4's timing, not an escape from its
core prerequisite.

### Vector 5 — holds, but unlike vector 3 this is the feature working exactly as designed

Directly asked, correctly: is JMX-driven reconfiguration actually intended
Log4j behavior, or a gap — and if intended, what makes it a finding at
all? This deserves a different answer than vector 3 got, not the same
"retracted" treatment, because the underlying question is different in
kind.

`LoggerContextAdminMBean` is not incidental exposure of something that
should have stayed private — it is a deliberately designed, documented
remote-management interface, exactly like `java.util.logging`'s
`LoggingMXBean`, or the JMX MBeans Tomcat/Kafka/many other JVM services
ship for the same reason: let an authorized operator change runtime
behavior without a restart. `setConfigText()` doing exactly what its own
log message says — reconfiguring from pushed text — is the feature
working correctly, not a logic bug in Log4j's own code. This is the
opposite situation from vector 3: there, the retracted claim rested on a
*misreading* of what `ClassLoaderContextSelector` does (it actually
prevents cross-boundary config confusion by design). Here, the read of
what `setConfigText()` does is accurate — it reconfigures from arbitrary
content, on purpose — and the finding is entirely about *who gets to call
it*, not about what it does once called.

Asked for something narrower than vector 4: no `monitorInterval`, and the
content genuinely, directly attacker-controlled — not dependent on
compromising infrastructure that already belonged to someone else.

Log4j ships a JMX-managed operation for exactly this:
`LoggerContextAdminMBean.setConfigText(String configText, String
charsetName)` (`log4j-core/.../jmx/LoggerContextAdmin.java:201`), whose own
internal log message is literally `"Remote request to reconfigure from
config text"` — a real, documented remote-management feature, not
something pieced together from unrelated parts. It takes the configuration
as a raw string and runs it through the exact same
`ConfigurationFactory.getInstance().getConfiguration()` path every other
config source in this investigation goes through. There is no URL to host,
no file to write, and nothing that has to already be trusted and later
subverted — the attacker's payload is sent directly, the moment they reach
this operation.

`XIncludeJmxProof.java` proves it end to end: with Log4j's JMX
instrumentation enabled, the real `LoggerContextAdmin` MBean is located on
the platform `MBeanServer` (`mbs.queryNames(...)`, exactly as
`LoggerContextAdminMBean`'s own Javadoc documents doing), and a single
`setConfigText()` invocation carrying the XInclude/exfil payload as a
plain string leaks the secret.

The one real precondition, stated plainly: Log4j's JMX instrumentation is
**disabled by default** (`JmxUtil.isJmxDisabled()` defaults to `true`) — an
operator has to explicitly set `log4j2.disable.jmx=false`. That's not
something the attacker does, and it's set once, ahead of time, the same
way vector 4's `monitorInterval` was. Reaching the operation at all
additionally requires the JVM's own JMX remote management to be enabled
and reachable — a separate, well-documented, independent vulnerability
category on its own (unauthenticated exposed JMX/RMI ports are a
long-standing, common real-world misconfiguration, with established tooling
built around exploiting exactly that). This proof does not stand up a real
remote RMI listener — it invokes the MBean operation through the local
platform `MBeanServer`, which is what a remote JMX client's call becomes
once past the RMI transport; the transport layer is generic JMX/RMI
behavior, not Log4j-specific, and wasn't what needed testing here. What
*is* proven directly against real Log4j code: once anything reaches this
operation with content of its choosing, XInclude fires exactly as
everywhere else in this investigation.

**Not verified in this session, stated as an open question rather than
assumed either way**: JMX's own remote connectors support a `readonly` /
`readwrite` access model (`jmxremote.access` file), and the standard JMX
RMI connector's access controller is understood to block `invoke()`
operations — `setConfigText()` among them — for principals granted only
`readonly`, reserving that for attribute getters and read-style queries.
If that holds for this MBean specifically (not independently confirmed
here — it would require standing up a real authenticated RMI connector,
which tests generic JMX security semantics, not Log4j), the real
precondition for vector 5 is narrower than "JMX reachable": it's "JMX
reachable **and** either unauthenticated or granted a `readwrite` role."
Plenty of real deployments run JMX with authentication specifically
restricted to `readonly` for monitoring dashboards (Prometheus/Grafana JMX
exporters and similar), which would sit outside this vector even with JMX
fully enabled and network-reachable. This matters because it's the
difference between "any exposed JMX is enough" and "exposed JMX with
write access is required" — a materially different bar, left open rather
than resolved in either direction.

Also worth noting in passing, found while reading the surrounding code,
not chased further: the sibling operation `setConfigLocationUri(String)`
opens the given URL via a plain `new URL(configLocation).openStream()`
call — it does **not** go through `UrlConnectionFactory`'s protocol
allow-list (the mechanism that blocks plain `http` by default for vectors
2 and 4). Whether that's a meaningfully different exposure or simply
unreachable in the same deployments as `setConfigText()` was not
investigated.

## Which rules do the surviving vectors (2, 4, and 5) actually reach?

Config control is config control — a vector that delivers one malicious
`<Configuration>` document delivers whichever payload is inside it,
regardless of whether that document arrived via an attacker-set env var
(vector 2), a takeover of an already-trusted, polled URL (vector 4), or
content pushed directly through JMX (vector 5):

- **`log4j-xxe` / `log4j-xinclude`**: directly reached — proven by all
  three.
- **`log4j-sql-injection`** (`<JDBC tableName>`) and
  **`log4j-script-injection`** (`<Script>`/`<ScriptFile>`): reached the
  same way by all three — these payloads just need to be XML elements
  inside the same attacker-supplied `<Configuration>` document
  `XIncludeRemoteConfigProof.java`/`XIncludeWatcherTakeoverProof.java`/`XIncludeJmxProof.java`
  already prove can be delivered. Not re-proven separately: the delivery
  mechanism, not the payload string, is what those proofs test.
- **`log4j-jndi-injection`**: **partially** reached, and this is the one
  honest exception across all three. Every vector gets an attacker's
  `${jndi:...}` lookup into the config, but `JndiLookup`'s constructor
  separately requires `log4j2.enableJndiLookup=true` (`JndiLookup.java:46`)
  — a JVM system property/environment variable, not config-document
  content. Config content alone cannot set it (vectors 4 and 5 in
  particular touch *no* config-location property at all), so JNDI needs a
  **second**, independent condition: either the target environment already
  opted back into JNDI lookups (organizations that re-enabled it
  post-Log4Shell for legacy compatibility), or a further way to influence
  that specific property, neither of which was found or tested here.
- **`log4j-ssl-hostname-verification`**: outside this discussion entirely
  — the one rule needing none of it. A network man-in-the-middle position
  is sufficient on its own, which is why it remains the strongest "real
  world, no config control at all" finding in this ruleset.
- **`log4j-unsafe-deserialization`**: moot — no live sink in this branch's
  source (`DESERIALIZATION_FINDING.md`).

## What this changes

Three vectors now demonstrably cross the config-control boundary — for
every config-driven rule except JNDI — without needing "sysadmin access,"
each suited to a different real deployment shape:

- **Vector 2**: one environment variable/property, attacker-set — applies
  wherever the attacker can influence a target JVM's launch environment
  (a shared PaaS tenant's own workload, CI/CD env-var injection).
- **Vector 4**: no attacker-set property at all — applies wherever an
  organization already hosts config centrally over HTTP(S) with
  `monitorInterval` set, and that URL's origin can be taken over
  (subdomain/expired-domain takeover, config-server compromise).
- **Vector 5**: no property, no URL, no `monitorInterval` — applies
  wherever Log4j's JMX instrumentation is enabled
  (`log4j2.disable.jmx=false`, not the default) and the JVM's own JMX
  remote management is reachable, commonly without authentication in real
  misconfigured deployments. The attacker's content is pushed directly,
  not hosted or planted anywhere.

Each has a genuine, separate real-world prerequisite outside Log4j itself
— env-var-reachability, URL-takeover-ability, or exposed-JMX — rather than
one being strictly weaker than the others; which one is realistic depends
entirely on how a given target is actually deployed.

Vector 3 looked smaller than both at first, and the honest result of
checking it harder — after being challenged directly on whether it was
really different from normal behavior — is that it isn't a general,
realistic scenario at all. That's kept on record deliberately: in a
ruleset built around not overclaiming, "found a proof that passes" is not
the same as "found a realistic scenario," and the gap between them is
worth testing for directly, including when the result contradicts a claim
already written down, rather than assumed away.

## Was there a sixth, independent vector — asked directly, searched broadly

After vector 5 turned out to be intended behavior rather than a bug, the
direct follow-up was to search harder for something that is neither an
admin feature's intended use nor gated behind an external
compromise-something-else prerequisite (env var reachability, URL-takeover
capability). That search was broadened past `log4j-core` alone to
`log4j-web` (servlet context init-param resolution — same trust level as
vector 2, deployer-set, not a new lower-privilege path),
`log4j-spring-boot`, and `log4j-spring-cloud-config-client` (covered
above, refines vector 4, doesn't replace it).

No sixth, independent vector was found. Every path into config-content
control in this codebase, across everything checked, resolves to one of
three shapes: an external bug/misconfiguration granting the attacker
control of a property or environment variable (vector 2), an external
bug/misconfiguration compromising infrastructure the application already,
legitimately trusts (vector 4), or an intended administrative feature
exposed without the access control it assumes (vector 5, not really a
"vector" into a Log4j gap at all). There is no code path found in this
investigation where ordinary, unauthenticated application input —
a log message, an HTTP request the application merely logs — influences
what Log4j parses as configuration. That boundary is exactly what
separates every finding in this ruleset from Log4Shell, and it held up
against every angle tried here, not just the ones that were convenient to
stop at.
