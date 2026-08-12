# Path traversal via untrusted MDC data — no config-authoring trust required

Every other finding in this ruleset shares one prerequisite: the attacker
needs to control what Log4j parses as *configuration* (`CONFIG_DELIVERY_VECTORS.md`
covers five different ways to get there, `log4j-ssl-hostname-verification`
being the one earlier exception that needs none of it). This finding is a
**second** exception, and a more severe one: it needs **no config-authoring
trust at all**. The config is entirely legitimate — exactly what a
`RoutingAppender` per-key-file tutorial recommends — and the untrusted
input is ordinary application data most developers would not think of as
attacker-controlled.

## The mechanism, grounded in real code

- `RoutingAppender.append()` (`log4j-core/.../appender/routing/RoutingAppender.java:296-300`)
  resolves the route's `pattern` attribute against the *current LogEvent*:
  `configuration.getStrSubstitutor().replace(event, pattern)`.
- `RoutingAppender.createAppender()` (same file, `:365-382`) then builds the
  route's nested appender node **fresh, per event**:
  `configuration.createConfiguration(appNode, event)` — unlike an ordinary,
  static `<File>` appender (built once, at config-load time, before any
  request-scoped context exists), this node's attributes — including
  `fileName` — are resolved against *that event's* `ThreadContext` (MDC)
  snapshot.
- `${ctx:KEY}` is a real, documented Lookup for exactly this: reading a
  key out of MDC into a config attribute.
- `FileManager` (`log4j-core/.../appender/FileManager.java:226,265`)
  constructs the target with a plain `new File(filename)` — no
  canonicalization, no containment check against the intended base
  directory, anywhere in the chain.

None of this is a bug in any single piece — each part does exactly what
it's documented to do. The gap is that nothing in the chain validates that
an MDC-sourced path segment doesn't contain `../`.

## Proven end to end, not assumed

`MdcPathTraversalProof.java` drives the real mechanism with a config that
mirrors `log4j-core-test/src/test/resources/log4j-routing-purge.xml`
(this repository's own test fixture for `RoutingAppender`, not an invented
shape):

```xml
<Routing name="PerTenant">
  <Routes pattern="$${ctx:tenant}">
    <Route>
      <File name="Route-${ctx:tenant}" fileName="/intended/dir/${ctx:tenant}.log">
        <PatternLayout pattern="%msg%n"/>
      </File>
    </Route>
  </Routes>
</Routing>
```

The only "attacker" action: `ThreadContext.put("tenant", "../mdc-traversal-ESCAPED-<marker>")`
— standing in for **an unvalidated request header, query parameter, or
JWT claim** that a developer put into MDC for entirely ordinary structured
logging, the way `${ctx:tenant}`-based per-tenant log routing is
documented to be used. Logging a single message afterward produced a real
file **outside** the intended directory, and correspondingly no file was
created inside it — confirmed by listing both directories, not by
assuming the write succeeded.

One real bug was found and fixed in this proof's own construction along
the way, not just in the target system: the first version wrapped the
nested `File` node's `fileName` in `$$` (double-dollar) escaping, copying
the reference fixture's convention for `Routes`' own `pattern` attribute
without checking whether it applied here too. It doesn't — the nested
`File` node is *always* built fresh per event (unlike `Routes.pattern`,
built once at Routing-level construction and deferred deliberately), so
escaping it left `${ctx:tenant}` sitting as unresolved literal text in the
file name instead of being substituted. Found by reading the actual debug
log (`FileAppender$Builder(fileName="...${ctx:tenant}.log"...)`, unresolved)
rather than assumed correct, then fixed to match how the working case
(`name="Route-${sd:id}"`, unescaped) is actually written in the reference
fixture.

## Why this is a materially different, and materially more severe, finding

1. **No config-authoring trust boundary.** Every other finding in this
   ruleset needed the attacker to influence *what Log4j parses as
   configuration* — an env var, a compromised URL, JMX access. Here the
   config is fixed, legitimate, and written by a trusted operator
   following documented advice. The untrusted input is application data
   flowing into `ThreadContext`, which is an extremely common,
   unremarkable pattern (request headers, tenant/user IDs, correlation
   IDs, JWT claims) — not a special-purpose feature an attacker needs to
   discover or abuse.
2. **Write, not read.** Every prior file-content finding in this session
   (`log4j-xxe`, `log4j-xinclude`) was a *read* primitive. This is a
   *write* primitive: the resulting file's location is attacker-chosen
   (via `../` depth) and its content is whatever the `PatternLayout`
   renders — typically including the log message itself, which the
   attacker plausibly also influences in the same request. Combined,
   that is attacker-chosen content at an attacker-chosen path, limited
   only by the process's own filesystem write permissions — a concrete
   path toward webshell drops, cron persistence, SSH `authorized_keys`
   injection, or overwriting other application files, depending on
   deployment.
3. **The prerequisite is a common, legitimate feature, not a
   misconfiguration.** Unlike the JMX finding (`log4j-jmx-remote-reconfig`,
   downgraded to INFO specifically because reaching it needs *disabled-
   by-default* settings), per-key file routing via `${ctx:...}` is exactly
   how `RoutingAppender` is documented to be used, with no unusual opt-in
   required. This raises the bar for likelihood, not lowers it.

## What was not verified

- **Absolute-path escape.** Not tested: whether a value like
  `/etc/cron.d/x` (no `../`) can escape the intended directory on its own.
  Since `fileName` is built by plain string concatenation
  (`baseDir + "/" + ${ctx:tenant} + ".log"`) rather than two-argument
  `new File(baseDir, relativePath)`, a leading `/` most likely just
  becomes an odd path segment rather than a true absolute-path jump —
  `../` traversal (tested and confirmed) is the real vector, not raw
  absolute-path injection.
- **Whether other appenders (`RollingFile`, `Syslog`, etc.) used as a
  Route's nested appender show the same behavior.** Plausible by the same
  mechanism (all appender attributes go through the same
  `PluginBuilderAttributeVisitor` substitution), not independently tested
  here.
- **A Semgrep AST rule for this.** Every other finding in this ruleset has
  a matching `.yaml`/`.java` rule pair scanning *Java source*. This
  finding's dangerous pattern lives in **XML configuration content**
  (`fileName="...${ctx:...}..."` with no accompanying validation), a
  different rule shape (Semgrep's generic/XML matching, not Java AST) this
  ruleset hasn't used yet — not written here; flagged as a natural next
  step rather than assumed out of scope.
