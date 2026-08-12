# nomaven-build — building and running Log4j without Maven

Builds `log4j-api` + `log4j-core` from this working tree with plain `javac`,
then runs a smoke test that exercises real logging behaviour.

```bash
./build.sh   # compile api + core, generate plugin descriptor and services
./run.sh     # compile and run the smoke test
```

Requires only a JDK (verified on 21). No network access, no Maven.

## Why this exists

The environment this was developed in blocks every Maven repository host at
the network layer, so `./mvnw` cannot resolve even the parent POM:

```
Non-resolvable parent POM for org.apache.logging.log4j:log4j-bom:${revision}:
org.apache.logging:logging-parent:pom:12.1.1 — status code: 403, Forbidden
```

Downloading a released binary instead is not an option there either: Maven
Central, `downloads.apache.org`, `archive.apache.org` and `dlcdn.apache.org`
are all unreachable, and GitHub release assets require API access the session
does not have. Compiling from source was the only remaining path.

It turns out to be a short one, because of how Log4j declares dependencies:

- `log4j-api` has exactly two, both `provided` (jspecify, OSGi) — annotations.
- `log4j-core` has one non-`optional` dependency: `log4j-api`.

So the core logging path has **no mandatory third-party code**. Everything
missing is either an annotation (stub it) or an optional appender (skip it).

## What the build does

| Step | Action |
|-----:|--------|
| 1 | Compile `stubs/` — annotations and the small OSGi/Disruptor API surface |
| 2 | Compile `log4j-api` (152 sources → 197 classes) |
| 3 | Compile `log4j-core` minus optional-dependency appenders (647 → 1020 classes) |
| 4 | Generate `Log4j2Plugins.dat` by re-running `javac` with `PluginProcessor` |
| 5 | Generate `META-INF/services/*` from `@ServiceProvider` annotations |

Steps 4 and 5 replace work the Maven build normally does. They are not
optional:

- **Step 4** — Log4j resolves plugins (`Console`, `PatternLayout`, …) through
  `Log4j2Plugins.dat`, produced by `PluginProcessor`. That processor lives
  inside `log4j-core` itself, so once core is compiled it can be pointed back
  at its own sources.
- **Step 5** — `Log4jProvider` is registered via bnd's `@ServiceProvider`,
  which real builds turn into `META-INF/services` entries. Our stub annotation
  is a no-op, so without this `LogManager` finds no provider and **silently
  degrades to `SimpleLogger`** — logging still "works", which is exactly why
  the smoke test asserts the active implementation is `log4j-core`.

## What is stubbed, and what that costs

`stubs/` contains compile-only substitutes. Annotations (jspecify, bnd,
errorprone, OSGi `@Version`/`@Export`) are behaviourally complete — they carry
no runtime semantics here.

Two are **not** behaviourally complete, and every entry point throws
`UnsupportedOperationException` rather than silently doing nothing:

- `com.lmax.disruptor.*` — needed because `Configuration` and `LoggerConfig`
  reference the async package. **Async logging does not work in this build.**
- `org.apache.commons.compress.*` — used only by `CommonsCompressAction`.
  Note `ZipCompressAction` and gzip rollover use JDK `java.util.zip` and are
  fully functional.

Excluded sources are those needing a genuinely absent library — Jackson
(JSON/YAML/XML layouts and config), JMS, mail, Kafka, ZeroMQ, CSV,
MongoDB/JDBC — plus the OSGi bundle activators. See the `grep -v` list in
`build.sh`. Everything else compiles, including the whole rolling-file stack.

## Smoke test coverage

`run.sh` asserts on observable behaviour and exits non-zero on failure, so a
wall of log output is never mistaken for a pass. 11 checks, all passing:

- `log4j-core` is the active implementation, not `SimpleLogger`
- `log4j2.xml` is parsed and the named configuration is live
- all six levels, with `TRACE` correctly filtered below the root threshold
- parameterised messages, lazy `Supplier` arguments, exception stack traces
- `ThreadContext` (MDC) values appearing and clearing via `%X{orderId}`
- per-logger level override and `additivity="false"`
- `File` appender content on disk, including the stack trace
- `SizeBasedTriggeringPolicy` rollover producing gzip-compressed files

## FINDINGS

**A `RollingFile` appender leaves a non-daemon thread that prevents JVM exit,
and `LogManager.shutdown()` does not release it.**

`RollingFileManager` builds its async-compression executor from the
*non-daemon* factory:

```java
// RollingFileManager.java:65,77
private final Log4jThreadFactory threadFactory =
        Log4jThreadFactory.createThreadFactory("RollingFileManager");
private final ScheduledExecutorService asyncExecutor =
        new ScheduledThreadPoolExecutor(1, threadFactory);
```

`Log4jThreadFactory.createThreadFactory` is the non-daemon variant, whose own
javadoc warns against this use:

> This is mainly used for tests. Production code should be very careful with
> creating non-daemon threads since those will block application shutdown
> (see https://issues.apache.org/jira/browse/LOG4J2-1748).

Observed with a config that triggers a rollover: after `LogManager.shutdown()`
returns, `Log4j2-TF-1-RollingFileManager-1` is still alive and non-daemon, and
the JVM never exits. The teardown that *does* release it
(`RollingFileManager.releaseSub`, line 534) runs only when the JVM shutdown
hook fires — in a traced run, a full 60 seconds later, on `pool-1-thread-1`,
and only because the process was being killed:

```
00:51:04  LogManager.shutdown() returns   → thread still alive, JVM hangs
00:52:04  Stopping LoggerContext          ← shutdown hook, on SIGTERM
00:52:04  All asynchronous threads have terminated
```

`demo/SmokeTest.java` therefore calls `System.exit()` deliberately.

**Caveat on this finding.** It was observed against this stub build. The code
path involved touches none of the stubbed or excluded classes, so it should
reproduce on a normal Maven build — but that could not be cross-checked here,
because no Maven repository or release binary was reachable. Worth confirming
against a stock build before treating it as an upstream bug report.
