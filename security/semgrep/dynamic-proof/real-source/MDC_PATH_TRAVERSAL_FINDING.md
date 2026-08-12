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

Also confirmed directly, not just claimed: the escaped file's *contents*
are exactly what `PatternLayout`'s `%msg%n` rendered — the two log
messages, verbatim:

```
$ cat /tmp/mdc-traversal-ESCAPED-<marker>.log
request handled
second line, same file handle
```

That's the same substitution mechanism as the path — whatever the
application logs becomes the file's content, no separate vulnerability
needed to control both the destination and the payload.

## Real-world scenario, step by step

Two different real entry points get an attacker's value into the MDC key
a route pattern reads. Both are ordinary, unremarkable application
patterns — neither requires discovering a special Log4j feature.

**Scenario A — self-service multi-tenant signup, the lower bar.** Many
SaaS products let a user pick their own organization/tenant slug at
signup (`https://app.example.com/{tenant-slug}/...`, or a header derived
from it), and use exactly this `RoutingAppender` pattern so each tenant's
logs land in a separate file — a completely reasonable, common ops
requirement.

1. Attacker signs up for a free/trial account — no privileged access, no
   network position, nothing beyond what any ordinary user can do.
2. At signup, the app asks for an organization name or slug. If that
   field isn't restricted to a safe charset (allowing only what looks
   like a URL-safe identifier is a very plausible, common oversight for a
   field most developers think of as "a name," not "a path segment"),
   the attacker sets it to something like `../../../../var/www/html/pwn`.
3. The app stores this value and, on every subsequent request from that
   attacker (now an authenticated user of their own account), request-handling
   code does the unremarkable thing: `ThreadContext.put("tenant",
   session.getOrgSlug())` before logging proceeds, for correlation and
   per-tenant routing exactly as configured.
4. The attacker performs any action in the app that produces a log line
   at or above the configured level — logging into their own account is
   often enough by itself. `RoutingAppender` builds a fresh route appender
   for that event, resolving `fileName="/var/log/myapp/tenants/${ctx:tenant}.log"`
   against the poisoned MDC value, escaping the intended `tenants/`
   directory.
5. Content: the same request very plausibly logs other attacker-supplied
   data too (a request path, a form field, an error message echoing input)
   — which is what determines the escaped file's actual bytes, confirmed
   directly above to be exactly what gets logged. A crafted message —
   e.g. one shaped like a cron entry, an SSH `authorized_keys` line, or a
   web-shell payload if the traversal reaches a web-served directory —
   becomes the file's content the moment it's logged.
6. Impact depends on where the traversal lands and what the process can
   write — see "Does the fixed `.log` suffix actually limit impact?"
   below: it constrains less than it first appears to.

**Scenario B — a client-supplied header trusted without cross-checking.**
Some deployments read the routing key from a request header instead of
session state — `ThreadContext.put("tenant", request.getHeader("X-Tenant-Id"))`
— intending it to be set by a trusted API gateway/reverse proxy in front
of the app. This is the same trust-boundary-confusion class as the
long-documented `X-Forwarded-For` spoofing problem: if the application is
also reachable directly (a misconfigured load balancer, an internal
network path, a staging environment without the gateway in front of it),
or the gateway itself doesn't strip/overwrite the header from external
clients, an attacker sends the traversal payload as the header value
directly, needing no account and no signup step at all — a lower bar
than Scenario A, but resting on a separate, not-universal deployment
mistake (trusting an unvalidated header) rather than Scenario A's more
generic "a self-service text field wasn't charset-restricted."

Neither scenario requires config-authoring access, an environment
variable, JMX, or a URL takeover — the config in both is exactly what
operators are told to write for legitimate per-tenant log routing. The
only thing either scenario needs is one unsanitized string reaching
`ThreadContext`, which is a normal, everyday thing for logging code to
do.

## Does the fixed `.log` suffix actually limit impact? Tested, and the answer is mixed — largely no, with real exceptions

Pushed back on directly: the route template's fixed `.log` suffix
(`fileName="...${ctx:tenant}.log"`) was treated above as if it mattered —
implying a webshell needs a `.php`/`.jsp` extension the traversal can't
produce. That's only true for **extension-based dispatch**: a web server
deciding whether to execute or serve-as-text by looking at the URL's file
extension (Apache's `mod_php`/`AddHandler`, a servlet container's
`<servlet-mapping>` for `.jsp`). It is not true in general, and this was
checked directly rather than left as an assumption, with the interpreters
actually installed on this machine:

```
$ php webshell.log            # content: <?php echo "..."; ?>
PHP-EXECUTED-DESPITE-DOT-LOG-EXTENSION:4

$ node -e "require('./payload.log')"   # content: console.log(...); module.exports = ...
NODE-EXECUTED-DESPITE-DOT-LOG-EXTENSION:4

$ node payload.log
NODE-EXECUTED-DESPITE-DOT-LOG-EXTENSION:4

$ python3 script.log          # content: print(...)
PYTHON-EXECUTED-DESPITE-DOT-LOG-EXTENSION:4

$ bash cmd.log                 # content: echo $((2+2))
BASH-EXECUTED-DESPITE-DOT-LOG-EXTENSION:4
```

Every one of PHP, Node.js (both `require()` and direct CLI invocation),
Python, and Bash executed `.log` content with zero regard for the
extension, the moment something invokes an interpreter on that exact
path. The extension only matters to code that specifically inspects it
before deciding what to do with the file — and plenty of real code paths
don't:

- **PHP's `include()`/`require()`** — the same functions, called with the
  log file's path (e.g. a misguided "view recent activity" feature that
  builds a path from user/tenant identifiers and includes it), execute
  `.log` content exactly like the CLI test above. This is not a novel
  technique: it's the well-known **"log poisoning" LFI-to-RCE** pattern
  (poison a log file via a header/field the app logs, then trigger a
  separate Local File Inclusion bug to `include()` it). What this finding
  changes is that the *placement* half of that classic two-bug chain —
  normally requiring its own, separate path-traversal/LFI vulnerability
  on the **read** side — is done by the **same** bug that does the
  poisoning, via the traversal on the **write** side. One bug instead of
  two.
- **Node's `require()` extension fallback** — confirmed above: an
  unrecognized extension does not stop `require()` from parsing the file
  as JavaScript.
- **A custom directory-watcher, CI job, or ad-hoc deploy script that
  invokes an interpreter on files by iterating a directory**
  (`for f in dir/*; do bash "$f"; done`, a supervisor that runs whatever
  appears in a "jobs" folder) rather than filtering by name pattern
  first. Real, but *ad hoc* — application- or pipeline-specific, not a
  standard OS mechanism, and not the same as the next point.

**Checked and corrected, not assumed: the standard Linux cron mechanism
is NOT one of these.** `/etc/cron.daily`, `/etc/cron.hourly`, and
`/etc/cron.d` are processed via `run-parts` on Debian/Ubuntu-family
systems, and `run-parts` **filters out any filename containing a period
by default** — tested directly on this machine, not assumed from the man
page:

```
$ ls
evil.log  noext  script.sh          # all three chmod +x, all three echo their own name

$ run-parts -v /the/dir              # DEFAULT mode, no flags
run-parts: executing /the/dir/noext  # only the dotless one runs
NOEXT EXECUTED

$ run-parts --regex='.*' -v /the/dir # explicit override needed to include dotted names
run-parts: executing /the/dir/evil.log
EVIL.LOG EXECUTED
...
```

So the most obvious candidate for "some standard Linux service picks up
and runs a dropped `.log` file automatically" is, by default, a dead end
— a real, honest correction, not the answer that would have made this
finding tidier. (`/etc/logrotate.d/*` is a plausible *different* avenue —
logrotate configs support a `postrotate ... endscript` block that runs
arbitrary shell, and logrotate does not filter that directory's filenames
the way `run-parts` does — but it needs write access to
`/etc/logrotate.d/` specifically, usually root-only, and valid logrotate
config syntax as the file's content rather than a plain script; not
verified here.)

What *does* still hold, honestly: reaching a web server's own
extension-based execution path specifically (an HTTP request causing
`mod_php`/a JSP servlet container to execute the dropped file *because
the server's own routing logic looked at its name*) is genuinely blocked
by the fixed `.log` suffix, unless the traversal target directory's own
handler configuration is unusually broad. That narrower claim was the
one worth correcting; the general "the `.log` suffix makes this safe"
framing was not accurate and has been removed from the impact reasoning
below.

### Pushed further: is there some OTHER standard Linux service that isn't as careful as `run-parts`?

Asked directly to keep looking, rather than stop at the one negative
result. Checked what else exists for "drop a script in a directory, it
gets run" on real systems — and hit a real, honest limit of this specific
sandbox: it doesn't run an actual init system (`/proc/1/comm` is
`process_api`, a container-runtime wrapper, not `systemd` or `sysvinit`),
and none of `anacron`, `ifupdown` (`/etc/network/if-up.d/`), or
`NetworkManager` (`/etc/NetworkManager/dispatcher.d/`) are installed on
it — confirmed by checking, not assumed absent:

```
$ dpkg -l anacron          # "un" = not installed, not even unpacked
$ ls /etc/network/if-up.d  # No such file or directory
$ ls /etc/NetworkManager/dispatcher.d  # No such file or directory
```

So none of those three could be tested against real behavior here, and
that limitation is stated plainly rather than papered over with a guess.
What can be said with reasonable, but not proof-level, confidence:

- **`ifupdown`'s `if-up.d`/`if-down.d`/`if-pre-up.d`/`if-post-down.d`** are,
  by Debian packaging convention, invoked through the same `run-parts`
  mechanism `cron.d` uses — plausibly the same dotted-filename filtering,
  but not independently confirmed on a real instance here.
- **NetworkManager's `dispatcher.d`** does its own directory scan in C,
  not via `run-parts` — genuinely uncertain whether it filters dotted
  names the same way; not verified either direction.
- **The broader pattern already found (`run-parts`, `docker-entrypoint.d/*.sh`
  globs, `/etc/profile.d/*.sh` sourcing) is that well-maintained drop-in
  directories tend to filter by an explicit name pattern specifically to
  prevent this exact class of attack** — a lesson the ecosystem has
  largely already learned. Continuing to search for a standard,
  widely-deployed service that skips this precaution is a reasonable
  next step for someone with a real, non-containerized Linux host to
  verify directly, but isn't something this sandbox can settle further.

The reliable, already-proven exploitation shape remains what's confirmed
above: either something *application-specific* explicitly reads/executes
the file at that exact path (the "log poisoning" pattern — `include()`,
`require()`, a custom deploy/watcher script), or an operator/attacker
with the right access invokes an interpreter on it directly. "A generic
Linux service will find and run it with no further help" is not
established, and the one concrete candidate tested for it (`run-parts`)
turned out to actively prevent it.

## Does this apply to Java itself — the very runtime the vulnerable app is written in?

Asked directly, and checked rather than assumed either way, since the
answer differs by which JDK tool is asked:

```
$ java Payload.log          # content: a full Payload class, valid Java source
Error: Could not find or load main class Payload.log
Caused by: java.lang.ClassNotFoundException: Payload.log
```

The plain `java` launcher's single-file source-code execution (JEP 330,
`java SomeFile.java` compiling and running a `.java` file directly with no
separate `javac` step) **requires the exact `.java` suffix** — given
`Payload.log`, `java` doesn't try to compile it as source at all; it
assumes the argument is a fully-qualified class name and fails to find
one. This one genuinely is extension-gated, unlike the four interpreters
above.

`jshell` — the JDK's own REPL/scripting tool, bundled with every JDK
since 9 — is not:

```
$ echo "/exit" | jshell script.log     # content: a plain Java statement
JSHELL-EXECUTED-DESPITE-DOT-LOG:4
|  Welcome to JShell -- Version 21.0.10
...
```

`jshell` executed the `.log` file's Java statements with zero regard for
its extension, the same way PHP/Node/Python/Bash did. The practical
relevance depends entirely on whether anything in a given deployment
already invokes `jshell` (or embeds a JSR-223 scripting engine — which,
notably, `log4j-script-injection`'s own `<ScriptFile>` mechanism does,
independently of this finding) against a path this traversal can reach;
nothing about a stock JVM process makes that happen on its own. Recorded
as an honest, mixed result — one JDK tool is extension-sensitive, the
other explicitly is not — rather than either overclaimed or dismissed.

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
   (via `../` depth), and its content — confirmed directly above, not
   assumed — is exactly whatever `PatternLayout` renders, typically
   including the log message itself, which the same request very
   plausibly also influences. Combined, that is attacker-chosen content
   at an attacker-chosen path, limited only by the process's own
   filesystem write permissions — a concrete path toward webshell drops,
   cron persistence, SSH `authorized_keys` injection, or overwriting
   other application files, depending on deployment (see "Real-world
   scenario, step by step" below for both).
3. **The prerequisite is a common, legitimate feature, not a
   misconfiguration.** Unlike the JMX finding (`log4j-jmx-remote-reconfig`,
   downgraded to INFO specifically because reaching it needs *disabled-
   by-default* settings), per-key file routing via `${ctx:...}` is exactly
   how `RoutingAppender` is documented to be used, with no unusual opt-in
   required. This raises the bar for likelihood, not lowers it.

## Chaining to the RCE this session already proved elsewhere — tested, and the answer is "conditionally," not "always"

Asked directly whether this chains into the genuine RCE
`log4j-script-injection` already demonstrated
(`ScriptRealSourceProof.java`, a real `ScriptEngine.eval()` executing
attacker-supplied script text). The obvious chain: use this write
primitive to overwrite Log4j's *own* config file with a malicious
`<Script>`-based document, then whatever reloads that file (`monitorInterval`,
or the next process restart) hands the attacker the already-proven script
sink — turning a foothold that needed no config-authoring trust at all
into full config control, the trust boundary every other finding in this
ruleset assumed the attacker already had.

That chain has exactly one link that isn't automatic, and it was tested
rather than assumed either way: `FileAppender`'s `append` attribute
**defaults to `true`** (`FileAppender.java:63`). `MdcPathTraversalOverwriteProof.java`
targets a pre-existing "victim" file (a well-formed `<Configuration>`
document, standing in for a real `log4j2.xml`) through the identical
traversal mechanism, under both settings:

- **`append="true"` (the default)**: the victim's original, valid XML is
  **not removed** — the attacker's content lands appended after it,
  producing a document with text after the closing `</Configuration>`
  tag. That is not well-formed XML; a config reload against this file
  fails to parse cleanly rather than swapping in the attacker's intended
  replacement. Real impact, but integrity/DoS (a config that no longer
  loads, or a process that keeps running its last-good configuration
  until restart), not a clean RCE handoff.
- **`append="false"` (an operator's explicit, plausible-but-not-default
  choice)**: the victim's original content is **completely gone**,
  replaced by exactly what the attacker logged — a clean, fully
  attacker-controlled document. This is precisely the condition the
  script-injection chain needs.

So: **yes, this chains into the already-proven script-injection RCE — but
only when the operator's route template sets `append="false"`** (or the
traversal happens to target a path that doesn't exist yet, sidestepping
the append-vs-overwrite question entirely by creating the malicious file
fresh). Under the FileAppender default, the same primitive still causes
real damage (breaking whatever existing file it targets) but does not, on
its own, hand the attacker a clean malicious-config swap. Neither
condition was assumed — both were driven against real code and the actual
resulting file content was read back and compared, not inferred.

Not re-executed here as a single, further, end-to-end proof: actually
reloading the overwritten file as a live `Configuration` and confirming
`ScriptEngine.eval()` fires from it. That reload step and the script sink
itself are what `ScriptRealSourceProof.java` already establishes
independently and thoroughly (real `ScriptManager` discovery via JSR-223
`ServiceLoader`, real script execution producing a real file) — combining
"this proof's clean-overwrite capability, under `append=\"false\"`" with
"that proof's already-demonstrated script sink" is a grounded conclusion
from two independently verified facts, not an unverified leap, but the
two were not stitched into one single running proof.

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
