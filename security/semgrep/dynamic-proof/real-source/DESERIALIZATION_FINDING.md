# log4j-unsafe-deserialization: no real-source reachability proof, and why

Every other rule in this ruleset has a `*RealSourceProof.java` in this
directory that drives the real compiled Log4j classes. This one doesn't,
because the investigation below found there is nothing left to drive.

## What the evidence shows

```
$ grep -rl 'ObjectInputStream' log4j-core/src/main/java/
core/util/datetime/FastDatePrinter.java
core/impl/MutableLogEvent.java
core/impl/Log4jLogEvent.java
core/async/RingBufferLogEvent.java
```

All four are `readObject()` implementations for the standard
`java.io.Serializable` contract on log-event classes -- ordinary Java
deserialization idiom, not a network-facing receiver. None of them is a sink
reachable from untrusted external input.

```
$ find log4j-core/src/main/java -iname '*socketserver*' -o -iname '*socketnode*'
(nothing)

$ grep -rli 'socketserver' src/changelog/ | xargs -I{} basename {}
LOG4J2-1068_Exceptions_not_logged_when_using_TcpSocketServer_Serialize.xml
LOG4J2-1604_Log4j2_TcpSocketServer_in_background.xml
LOG4J2-1605_Improve_error_messages_for_TcpSocketServer_and_UdpSocketServ.xml
LOG4J2-1863_Add_support_for_filtering_input_in_TcpSocketServer_and_UdpSo.xml
LOG4J2-1994_TcpSocketServer_does_not_close_accepted_Sockets.xml
```

`TcpSocketServer`/`UdpSocketServer` — the class this rule's CWE-502/
CVE-2019-17571 reference actually points at, log4j-core's equivalent of
log4j 1.x's `SocketServer`/`SocketNode` — genuinely existed. The changelog
even shows its exact mitigation history: `LOG4J2-1863` **"Add support for
filtering input in TcpSocketServer and UdpSocketServer"** is precisely the
`ObjectInputFilter` fix this rule's sanitizer models. But the class itself is
gone from the current `2.x` branch source entirely — not filtered, removed.

## What this means for the rule

The rule and its `dynamic-proof/UnsafeDeserializationProof.java` (the
synthetic Gadget-based proof) still describe a real, historically-accurate
vulnerability class, worth keeping in the ruleset for **future code that
might reintroduce it** — a new appender, a receiver added for some other
protocol, a plugin. That's what static analysis is for: catching a pattern
*before* it's exploited, including in code that doesn't exist yet.

What it can't do, honestly, is what the other four proofs do: show that
*this specific codebase's current, real, named class* is reachable and
either vulnerable or guarded. There is no such class left to point at. That
absence is itself the finding, and the strongest possible answer to "is this
a false positive" for this particular CVE reference in this particular
codebase: the vulnerable component was not patched, it was deleted.
