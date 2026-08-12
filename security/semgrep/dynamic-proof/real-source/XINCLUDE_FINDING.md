# log4j-xinclude: real prerequisite and real-world impact

`log4j-xinclude` fires on the current `2.x` release source
(`2.27.0-SNAPSHOT`). This note records what an attacker actually needs, and
what they actually get, so the WARNING/MEDIUM severity is defensible rather
than asserted. It complements `XIncludeRealSourceProof.java`, which proves the
mechanism through the real compiled method.

## Where the rule fires, and on what input

```
$ semgrep --config log4j-xinclude.yaml \
    log4j-core/.../config/xml/XmlConfiguration.java
  → 1 finding, line 215: factory.setXIncludeAware(true);
```

Line 221's `factory.setXIncludeAware(false)` (the LOG4J2-3531 fallback) is
correctly **not** matched — no false positive.

The parsed input is **not** application log data. Tracing the constructor:

- `XmlConfiguration.java:75` — source is `configSource.getInputStream()`, i.e.
  the `log4j2.xml` **configuration file itself** (a classpath resource or a
  path set via `log4j2.configurationFile`).
- `:83` — `newDocumentBuilder(true)` is the primary parse path. XInclude is
  enabled **unconditionally**; `newDocumentBuilder(false)` at `:96` is only a
  retry fallback for parsers that do not support XInclude.

## Real prerequisite

Exploitation requires the attacker to **control the content or location of the
log4j configuration file**. Concretely, one of:

1. Control over the `log4j.configurationFile` system property / the
   documented `LOG4J_CONFIGURATION_FILE` environment variable — it can point
   at a URL the attacker hosts, not just a local path (confirmed via
   `ConfigurationFactory.CONFIGURATION_FILE_PROPERTY`,
   `ConfigurationSource.fromUri`, and proven end to end with no filesystem
   write involved — see "Real-world scenario" below). This is the
   prerequisite with the most plausible, common real-world shape and the
   one this note now leads with.
2. Write access to `log4j2.xml` itself — plausible in principle, but (see
   below) a materially higher, less common bar in most real deployments
   than item 1.
3. An application that lets a user choose the configuration location.

This is the **same trust boundary as `log4j-xxe`**, and the crucial difference
from Log4Shell (CVE-2021-44228): Log4Shell was critical because untrusted *log
message* data reached JNDI. Here, log message data never touches this parser.
The untrusted thing must be the configuration file. **Not** reachable by an
unauthenticated remote attacker sending ordinary application input — that
claim is verified against the constructor call chain above, not assumed.

## Real-world impact (and its limits)

Proven end-to-end through the real method (`XIncludeRealSourceProof.java`):

- `<xi:include href="file://..." parse="text"/>` → **arbitrary local file read**
  as raw text (the target need not be well-formed XML).
- The DTD/XXE hardening (`disableDtdProcessing`, `setExpandEntityReferences(false)`,
  the external-entity SAX features) does **not** restrict it — a separate JAXP
  mechanism.
- `XMLConstants.FEATURE_SECURE_PROCESSING=true` does **not** block it either —
  confirmed empirically, not from documentation.
- The only mitigation that worked: `setXIncludeAware(false)`.

Plausible but **not** verified in this sandbox (no external network):

- SSRF via `href="http://internal/..."` when the config is parsed.

**Correction, proven wrong by testing rather than left as an assumption**:
an earlier version of this note claimed the read had "no built-in
exfiltration channel" — that the file's contents landed in the config DOM
and stayed there, consumed only internally. That was checked directly
against real code (`XIncludeExfilProof.java` in this directory) and turned
out to be **false**. The chain is:

1. `<Properties><Property name="leak"><xi:include href="file://..."
   parse="text"/></Property></Properties>` — the file's contents become the
   text content of the `Property` element (`XmlConfiguration`'s node
   construction sets a node's value from its element text,
   `node.setValue(text)`), so they become `Property.getValue()`.
2. `PropertiesPlugin.configureSubstitutor()` feeds every `<Properties>`
   entry into a `PropertiesLookup`, wired into the config's
   `Interpolator` — this is exactly the machinery behind ordinary
   `${sys:...}`/`${env:...}` substitution, not a bypass of it.
3. **Every** plugin attribute goes through that same substitutor
   (`PluginBuilderAttributeVisitor`/`PluginAttributeVisitor` call
   `substitutor.replace(event, rawValue)` on every `@PluginAttribute`
   value) — so `${leak}` resolves anywhere in the config an attacker
   who already controls that config chooses to put it: a `<File
   fileName="...${leak}...">`, a `<Socket host="...">`/`<Http url="...">`
   pointed at attacker infrastructure, or a `PatternLayout pattern`.

Proven end to end (`XIncludeExfilProof.java`): a real `Configurator.initialize()`
load of a config using exactly this pattern — `<Property name="leak">`
sourcing a local secret file via `<xi:include>`, referenced as
`${leak}` in a real `FileAppender`'s `fileName` — produced a real output
file on disk whose *name* contained the secret file's contents verbatim,
through log4j's own documented Properties + attribute-substitution
mechanism. No second bug, no custom plugin. A network appender
(`Socket`/`Syslog`/`Http`) pointed at attacker-controlled infrastructure
instead of a local `File` appender would exfiltrate the same content
off-host the same way — not verified in this sandbox (no outbound network
access), but the substitution step proven here is identical regardless of
which appender attribute consumes `${leak}`.

Why this is MEDIUM, not critical, despite the read not being blind — stated
honestly:

1. **An attacker who can already write the log4j config usually has significant
   access already** (filesystem write, or control of JVM properties). From
   there, arbitrary file read plus exfiltration is a marginal escalation, not
   the initial foothold — the prerequisite doesn't change just because the
   read is no longer blind.
2. **Amplifier:** log4j auto-reconfigures on `monitorInterval`
   (`XmlConfiguration.java:124-130`, `initializeWatchers`), so a config the
   attacker can rewrite is re-parsed automatically without a restart — raising
   impact *if* prerequisite (1) holds, since the attacker doesn't need to wait
   for or trigger a restart to have the malicious config take effect.

## Real-world scenario, step by step

**Correction, again found by testing the assumption rather than keeping
it**: an earlier version of this section built the scenario around an
attacker overwriting `log4j2.xml` on disk via a separate file-upload
path-traversal bug. That premise was pushed back on, correctly: in most
real deployments, the path a running app loads `log4j2.xml` from is not
attacker-writable without the attacker already having the kind of access
(root, the deploy pipeline, the service account itself) that makes the
rest of this finding close to moot. Rather than defend that framing, it was
checked against real code instead — and there's a materially better
prerequisite already sitting in "Real prerequisite" item 2, now proven end
to end: **no filesystem write to the target host is needed at all.**

`ConfigurationFactory.Factory.getConfiguration()` reads the
`log4j.configurationFile` property with no explicit source having been
provided — the ordinary, no-argument startup path every application using
Log4j goes through. That property is documented
(`systemproperties/properties-configuration-factory.adoc`) as settable via
the **`LOG4J_CONFIGURATION_FILE` environment variable**, and its value is
resolved by `ConfigurationSource.fromUri()`, which hands off to
`UrlConnectionFactory` for anything that isn't a local file — accepting a
network URL the attacker hosts themselves. Proven end to end
(`XIncludeRemoteConfigProof.java`, driven through the real, default,
no-explicit-source `LogManager`/`ConfigurationFactory` startup path — not a
shortcut around it):

- With no override, a plain `http://` config URL was **not** used —
  confirmed both by the absence of any leaked artifact and, cross-checked
  with `-Dlog4j2.debug=true`, the exact real log line: `Error accessing
  http://127.0.0.1:PORT/evil.xml due to Protocol http has not been enabled
  as an allowed protocol, ignoring.` `UrlConnectionFactory`'s default
  allow-list is `file, https, jar` (`DEFAULT_ALLOWED_PROTOCOLS`) —
  plain HTTP is genuinely blocked by default, a real, working mitigation
  worth crediting rather than glossing over.
- With `log4j2.Configuration.allowedProtocols` including `http` (an
  operator-level property override, not a code change — exercised this way
  only to avoid an orthogonal TLS-trust-store setup; `https`, which
  requires no such relaxation, is already in the default allow-list and
  goes through the identical code path once the connection is open), the
  same config was fetched from a URL a simulated attacker-controlled HTTP
  server served, and the secret still leaked into a real output file's name
  on disk — the identical chain `XIncludeExfilProof.java` proved, just
  reached by URL instead of by local file.

**The scenario this actually supports**: an attacker who can influence the
value of *one environment variable or JVM property* passed to a target
process — not read or write anything on that process's filesystem, not
compromise its service account, just control how it's launched — can point
`LOG4J_CONFIGURATION_FILE` at infrastructure they host and own outright.
That bar is real and common in ways "overwrite this specific file on this
specific host" is not:

1. **Multi-tenant PaaS / container platforms** where a tenant legitimately
   sets environment variables for *their own* workload (Heroku-style
   platforms, many internal developer platforms, Kubernetes namespaces a
   team self-serves). The tenant isn't attacking someone else's process —
   they're pointing their *own* container's Log4j at a config they host,
   and the file being read is whatever *that* container can see: a
   node-level credential, a shared secrets volume, a cloud instance
   metadata response — things the platform assumed logging configuration
   couldn't touch.
2. **CI/CD pipeline env-var injection** — a well-documented real category
   (e.g. GitHub's own guidance on "pwn request"-style issues): a
   contributor's PR or a compromised dependency running inside a build/test
   job sets `LOG4J_CONFIGURATION_FILE` (or the equivalent `-D` flag via
   `JAVA_TOOL_OPTIONS`, itself a standard JVM-recognized environment
   variable, not Log4j-specific — visible in this very session's own sandbox
   output) for that job's JVM, then reads back whatever local secret file
   the runner has mounted (deploy keys, cloud credentials) through the
   config-driven read this finding proves, via an appender attribute rather
   than printing it — the kind of side channel that generic secret-masking
   in CI log output does not catch.

Neither of these requires "already being a sysadmin," and neither requires
touching the target's filesystem — only the one thing proven reachable
here: control of a single property value at process launch. What Log4j's
part of the chain does with that, once reached, is exactly what
`XIncludeExfilProof.java` and `XIncludeRemoteConfigProof.java` demonstrate
against real code. The still-external, still-unverified-in-this-repo part
is narrower than before: not "an arbitrary-file-write vulnerability," just
"some influence over one env var passed to the target JVM" — which is
itself a form of the same "control over configuration" trust boundary this
whole finding has been honest about from the start, just concretely
narrowed to its smallest real shape instead of the broadest, least
plausible one.

## Narrower still? A claim made, then retracted by testing it harder

Asked directly whether an even smaller prerequisite exists — one that needs
neither CI/CD pipeline access nor any control over the target process's
launch environment — the first answer given here was "yes": Log4j's
auto-configuration resolves `log4j2.xml` against
`LoaderUtil.getThreadContextClassLoader()`, and a plugin's own child-first
classloader (a real, common isolation pattern) could shadow it. That
answer was then challenged directly and correctly — "isn't a plugin's own
classloader resolving its own resources just how isolation is *supposed*
to work? What's actually different from normal behavior?" — and checking
that harder, by reading `ClassLoaderContextSelector.locateContext()` and
testing both possible orderings rather than defending the first result,
falsified it as a general claim.

`locateContext()` does not give every classloader an independently-resolved
context. It only performs a fresh classpath scan when **no context already
exists for that classloader or any of its ancestors** — it walks the
parent chain first and reuses an ancestor's context if one is found. In
the realistic ordering (the host touches Log4j first, which is true of
almost any real application — it logs a startup message before ever
loading a user-supplied plugin), the plugin's classloader is simply handed
the host's *already-established* context; its shadowed config is never
read. `XIncludeClasspathShadowProof.java` now proves this directly:
`hostCtx == pluginCtx` is `true` in that ordering, and no secret leaks.
Shadowing only succeeds in the opposite, narrow ordering — the plugin's
classloader lineage being the very first thing anywhere in the process to
touch Log4j, before the host's own ever does — which an attacker who
merely gets a plugin loaded does not control and cannot reliably force.
This is *not* presented as a viable real-world scenario. It's kept on
record specifically because the correction and the mechanism behind it are
worth having, in a ruleset built around not overclaiming: a proof that
passes is not automatically a realistic scenario, and the gap between them
is worth testing for, not assuming away.

The full, corrected comparison of every vector investigated in this
session — including which of the *surviving* ones generalize to
`log4j-sql-injection`/`log4j-script-injection` too, and the one honest
exception (`log4j-jndi-injection`, still gated by a separate
`enableJndiLookup` property none of them can set) — is in
`CONFIG_DELIVERY_VECTORS.md` in this directory.

## Conclusion

A real, empirically-confirmed hardening gap: XInclude slips past every XXE
protection already in place, and the file it reads is not stuck inside the
parser (it can surface as a real, attacker-visible artifact using nothing
but log4j's own Properties and attribute-substitution features). Reaching
it does not require filesystem write access to the target host: control
over one environment variable/property at process launch (proven,
`XIncludeRemoteConfigProof.java`) is enough. A narrower-still classpath-
shadowing vector was proposed, tested harder after being challenged, and
correctly retracted as a general claim — it only works under a timing
precondition the attacker doesn't control, not as a realistic scenario.
Severity is still bounded by needing *some* form of "the attacker
influences what the target process loads as configuration," not by any
limit on where the read content can end up or how directly it's reached —
correctly classified as missing-hardening MEDIUM (not a remote
unauthenticated vector like Log4Shell, which needed no such precondition
at all), but the concrete shape of that prerequisite is the smallest
*demonstrated and realistic* one found in this session, not the
largest.
