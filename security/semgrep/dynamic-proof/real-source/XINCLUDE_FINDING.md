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

Why this is MEDIUM, not critical — stated honestly:

1. **No built-in exfiltration channel.** The included file lands in the DOM and
   is consumed internally by log4j as configuration structure; its contents
   are not returned to the attacker by this mechanism itself. The read
   primitive is real, but leaking it back out needs a separate channel (e.g.
   the attacker also controlling where that DOM content ends up being used —
   a `<Property>` value later interpolated into a log pattern the attacker can
   read — which is a further, non-guaranteed step, not something
   `setXIncludeAware(true)` hands the attacker automatically).
2. **An attacker who can already write the log4j config usually has significant
   access already** (filesystem write, or control of JVM properties). From
   there, arbitrary file read is a marginal escalation, not the initial
   foothold.
3. **Amplifier:** log4j auto-reconfigures on `monitorInterval`
   (`XmlConfiguration.java:124-130`, `initializeWatchers`), so a config the
   attacker can rewrite is re-parsed automatically without a restart — raising
   impact *if* prerequisite (1) holds, since the attacker doesn't need to wait
   for or trigger a restart to have the malicious config take effect.

## Conclusion

A real, empirically-confirmed hardening gap: XInclude slips past every XXE
protection already in place. Its severity is bounded by the config-file trust
boundary and the absence of a direct exfiltration path — correctly classified
as missing-hardening MEDIUM, not an untrusted-input RCE like Log4Shell.
