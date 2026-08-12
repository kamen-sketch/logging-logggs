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

1. Write access to `log4j2.xml`, or
2. Control over the `log4j.configurationFile` system property / env var (it can
   point at a URL or attacker-controlled path — confirmed via
   `ConfigurationFactory.CONFIGURATION_FILE_PROPERTY` and
   `ConfigurationSource.fromUri`, which accepts an arbitrary URI including
   `http(s)://`), or
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

Everything above proves the *log4j-side* mechanics against real code. This
section is different in kind: it's the plausible chain an attacker would
actually walk, split explicitly into what's proven here vs. what's a
reasonable assumption about a *separate* bug class this repository doesn't
contain. Log4j itself never hands an attacker the initial foothold — some
other, independent weakness has to give them prerequisite (1) or (2) from
"Real prerequisite" above. What follows is one concrete, common shape for
that, chosen because it's a textbook bug class (arbitrary file write via
path traversal), not a contrived one.

**Setup**: a Java web app runs as a service account that can read
`/opt/app/secrets/db-credentials.properties` (a file the attacker's own,
separate foothold cannot read directly). The app loads
`log4j2.xml` from `/opt/app/config/log4j2.xml` with `monitorInterval="30"`
already set — an ordinary, common config choice for picking up logging
changes without a restart, unrelated to this bug.

1. **Attacker gets an unrelated, lower-value bug**: a file-upload endpoint
   with a path-traversal flaw lets them write arbitrary bytes to arbitrary
   paths the service account can write to — including
   `/opt/app/config/log4j2.xml`. On its own this primitive is limited: the
   attacker can already write files, but the *interesting* files
   (`db-credentials.properties`, cloud instance-metadata caches, etc.) are
   read-only to them or outside the upload directory's reach. (Verified as
   real-world-common; not part of this repository — this is the external
   prerequisite, stated as an assumption, not tested here.)
2. **Attacker overwrites the config**, not the app: they use the upload bug
   to plant a `log4j2.xml` containing the `<Properties>`/`<xi:include>`/
   `${leak}` pattern from `XIncludeExfilProof.java` above, with `href`
   pointed at `db-credentials.properties` and the destination attribute
   (a `File` `fileName`, or a `Socket`/`Http` `host`/`url`) pointed at
   somewhere the attacker *can* reach — a location inside the same upload
   directory they already read from, or, if the host has outbound network
   access, a server they control.
3. **No restart needed**: because `monitorInterval` was already configured
   (common in production for exactly its intended purpose), Log4j's own
   watcher thread notices the modified file within the configured interval
   and reloads it automatically — `initializeWatchers()`,
   `XmlConfiguration.java:130`. The attacker doesn't need a second bug to
   trigger a restart or touch the running process at all.
4. **The reload executes the chain proven above**: `newDocumentBuilder(true)`
   parses the attacker's config, `<xi:include>` reads
   `db-credentials.properties` with the *service account's* read
   permissions (not the attacker's), the content becomes `${leak}`'s value,
   and the substitutor writes it into the destination attribute the
   attacker chose in step 2.
5. **Attacker retrieves it**: either by reading the resulting artifact
   through the same upload-directory access they already had (step 1's
   bug, reused — no new capability required), or, if a network appender was
   used instead, by receiving it on infrastructure they control.

The point of walking it this way: step 1 alone is a low/medium-severity
file-write bug with a narrow blast radius (the attacker can already write
whatever they want to that directory). Steps 2-5 — which are exactly what
`XIncludeExfilProof.java` demonstrates against real Log4j code — are what
turn it into credential theft, by using the *service account's* file-read
permissions instead of the attacker's own. That's the concrete shape of
"marginal escalation" from the severity discussion above: not marginal
because the outcome is small, but because it depends entirely on a
prerequisite bug elsewhere carrying most of the initial risk. Log4j's part
is real and proven; the file-write primitive that gets an attacker to
`log4j2.xml` in the first place is a plausible, common, but *external* and
*unverified-in-this-repo* assumption.

## Conclusion

A real, empirically-confirmed hardening gap: XInclude slips past every XXE
protection already in place, and — contrary to this note's own earlier,
untested assumption — the file it reads is not stuck inside the parser: it
can surface as a real, attacker-visible artifact using nothing but log4j's
own Properties and attribute-substitution features. Its severity is still
bounded by the config-file trust boundary, not by any limit on where the
read content can end up — correctly classified as missing-hardening MEDIUM
(config-write prerequisite, not a remote unauthenticated vector), not an
untrusted-input RCE like Log4Shell.
