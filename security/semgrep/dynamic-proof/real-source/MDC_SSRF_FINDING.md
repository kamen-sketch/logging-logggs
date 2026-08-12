# SSRF via untrusted MDC data — same mechanism, a different sink

`MDC_PATH_TRAVERSAL_FINDING.md` proved that `RoutingAppender` builds its
nested appender node fresh per event, resolving that node's attributes
against the *current* `ThreadContext` (MDC) snapshot with no validation —
and used `FileAppender`'s `fileName` as the sink. That doc's own "what
wasn't verified" list flagged the natural next question: does the same
substitution reach *other* appender types' attributes too? Tested directly
rather than left as "plausible" — yes, and the sink it reaches this time
is materially different in kind, not just in appender name: `HttpAppender`
turns the same untrusted-MDC-value-into-attribute mechanism into
**Server-Side Request Forgery**, not a file-write.

## The mechanism, grounded in real code

- The per-event node-construction path is identical to the path-traversal
  finding: `RoutingAppender.append()` resolves `Routes.pattern` against the
  event (`RoutingAppender.java:296-300`), then `createAppender()` builds the
  route's nested appender node fresh, per event, via
  `configuration.createConfiguration(appNode, event)` (`:365-382`).
- `HttpAppender.Builder#url` (`HttpAppender.java:48-50`) is a
  `@PluginBuilderAttribute` of type `java.net.URL`:
  ```java
  @PluginBuilderAttribute
  @Required(message = "No URL provided for HttpAppender")
  private URL url;
  ```
- Attribute values — **regardless of their declared Java type** — are run
  through the configuration's string substitutor before type conversion.
  `PluginBuilder.java:190-193` sets the substitutor
  (`configuration.getConfigurationStrSubstitutor()` /
  `getStrSubstitutor()`) used to resolve every plugin attribute's raw
  string value, `fileName` and `url` alike, before handing it to the
  `URL`/`String`/`int`/etc. type converter. Nothing about being a `URL`
  instead of a `String` attribute exempts it from that substitution, and
  nothing after substitution checks the resulting host against an
  allow-list.

Put together: an operator template like
`url="http://${ctx:tenant}-metrics.internal:9000/report"` — a completely
reasonable design, giving each tenant's telemetry its own destination —
lets an attacker who controls the `tenant` MDC value supply the *entire*
authority component, not just the intended subdomain label, because
nothing constrains what characters or shape that substituted value can
take.

## Checked against the manual, not just the source

The per-event substitution timing itself is not a hidden implementation
detail — it's documented as a deliberate feature, in two places:

- `delegating.adoc:920-928` — a `[WARNING]` block stating plainly that
  "Lookups in the **children** of the `Route` component are **not**
  evaluated at configuration time. The substitution is delayed until the
  `Route` element is evaluated... in the context of the current event."
- `configuration.adoc:939-948` — a `[NOTE]` calling the `Route`-child case
  "a different case altogether," evaluated at runtime, unescaped.

Read carefully, though, both of those callouts are about **syntax**
(don't escape `${...}` as `$${...}` inside a `Route`'s child appender) —
neither says anything about the security implication that the "current
event" context this evaluates against routinely carries request-derived
data (`${ctx:...}` is documented in `lookups.adoc` as reading `LogEvent`
context data — i.e. MDC/`ThreadContext`, which `thread-context.adoc`
describes applications populating from things like request/session
state). No caveat anywhere says "validate this before it reaches a
`Route` child's attributes."

Also checked: `appenders.adoc`'s own "Runtime evaluation of attributes"
table (`#runtime-evaluation`) — the authoritative list of which attributes
support runtime lookups — does **not** include `HttpAppender`'s `url` or
`FileAppender`'s `fileName`. That's not an omission; it's because this
per-event behavior isn't a property of those appenders at all — it's
exclusive to the separately-documented `Route`-child mechanism above,
which applies uniformly to *whatever* appender type is nested inside a
`Route`, regardless of which of its attributes end up attacker-reachable.
The mechanism is intended. Nothing in the documentation suggests the
value flowing through it was ever expected to need validation.

## Proven end to end, not assumed

`MdcSsrfProof.java` drives the real mechanism against two real local HTTP
listeners (JDK-bundled `com.sun.net.httpserver.HttpServer`, not a mocked
stand-in) — one representing the operator's actually-intended destination,
one representing an attacker-chosen target standing in for whatever a real
deployment's network position can reach but a public attacker cannot dial
directly (a cloud metadata service, an internal admin API, a database's
status port):

```xml
<Routing name="PerTenant">
  <Routes pattern="$${ctx:tenant}">
    <Route>
      <Http name="Route-${ctx:tenant}" url="http://${ctx:target}/report">
        <PatternLayout pattern="%msg%n"/>
      </Http>
    </Route>
  </Routes>
</Routing>
```

The "attacker" action is the same shape as the path-traversal finding —
one unvalidated `ThreadContext.put()` — but the payload is a host:port
pair instead of a `../` sequence:

```java
ThreadContext.put("tenant", "attacker");
ThreadContext.put("target", "127.0.0.1:" + attackerPort);
logger.info("ssrf-probe");
```

Result, confirmed by two independent real HTTP listeners actually
receiving (or not receiving) the request, not by inspecting the URL object
Log4j built:

```
[PASS] the attacker-chosen host:port (simulating an internal-only service) received the request
[PASS] the operator's actually-intended destination was NOT the one contacted (the attacker fully redirected the request, not merely appended to it)
[PASS] the request path/method reached the attacker target intact (saw: /report)
```

The attacker's target received the request; the operator's intended
target never saw it at all. This is a full redirect of the outbound
request, not a request that merely also reaches an unintended extra host.

## Why this is a different class of impact than the path-traversal finding, not just a different appender name

1. **Network-reachability primitive, not filesystem-write.** The
   path-traversal finding's impact is bounded by what the *process itself*
   can write to on its own filesystem. SSRF is bounded by what the
   *process's network position* can reach — commonly a strictly larger
   blast radius in real deployments: cloud instance metadata endpoints
   (credential theft), internal admin APIs with no auth because they were
   never meant to be internet-facing, other internal services behind a
   firewall the attacker's own network position can't reach directly, or
   `localhost`-bound management ports on the same host.
2. **No file-content or extension question at all.** Every caveat in the
   path-traversal finding about the fixed `.log` suffix, `append`
   semantics, or what downstream code might execute a dropped file simply
   doesn't apply here — the attacker doesn't need anything downstream to
   *read and act on* a file. The HTTP request itself is the impact.
3. **Same low bar to reach it.** Identical entry points to the
   path-traversal finding's Scenario A/B apply unchanged — a self-service
   tenant/org field that ends up in MDC, or a client-supplied header
   trusted without cross-checking. Nothing about reaching this finding is
   harder than reaching the file one; it's the same `ThreadContext.put()`
   call, read by a different appender's attribute.

## What was not verified

- **Response exfiltration.** This proof confirms the *request* is
  attacker-redirected; it does not test whether the response body (from
  whatever internal service the attacker reached) is ever logged back or
  otherwise made observable to the attacker. In a real deployment that
  depends on whether anything logs `HttpManager`'s response — plausible
  (error/debug logging of a failed or unexpected response) but not tested
  here. If the response is never surfaced anywhere the attacker can see,
  this is a blind SSRF (still capable of side effects on the internal
  target, e.g. hitting a state-changing internal API, but not direct data
  exfiltration via the response body).
- **Full authority-override vs. partial-field injection.** This proof used
  a template where the *entire* `url` value's authority is the MDC
  placeholder (`http://${ctx:target}/report`), the cleanest and most
  direct case. A template where only a subdomain label is meant to be
  attacker-influenced (`http://${ctx:tenant}.internal:9000/report`) was
  not separately tested here — whether a value like
  `attacker.com#` or `@attacker.com` can still hijack the authority
  through `java.net.URL`'s parsing quirks in that narrower template shape
  is a real, related, but distinct question not answered by this proof.
- **Other non-file appender types** (`Syslog`, `Kafka`, `JDBC`, etc.) as a
  Route's nested appender. Plausible by the same generic
  `PluginBuilder` substitution mechanism, not independently tested here —
  flagged the same way the path-traversal finding flagged untested
  appender types, now with one more (`Http`) moved from "plausible" to
  "confirmed."
- **A Semgrep rule for this.** Written since: `../../log4j-mdc-ssrf.yaml`,
  with fixtures at `../../log4j-mdc-ssrf.xml` — same shape and same
  reasoning as `log4j-mdc-path-traversal.yaml` (`pattern-regex` under
  `languages: [generic]`, scoped to the `Route`-child case only, the
  `$${ctx:...}` escaped form excluded via the same negative lookbehind).
  The `url` attribute name is matched generically rather than scoped to
  `<Http>` specifically, since the underlying mechanism (every
  `PluginBuilderAttribute` goes through the identical substitute-then-convert
  path) isn't specific to that one appender type either.
