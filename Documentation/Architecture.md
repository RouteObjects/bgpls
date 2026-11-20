# Architecture

`BGPLSClient` is a receive-only BGP-LS protocol and collection library.
`BGPLSCLI` supplies argument parsing, terminal presentation, and process-signal
handling. The `BGPLSExecutable` target is a thin executable entry point.
Swift Service Lifecycle's `UnixSignals` dependency belongs to the CLI; the
library does not install process signal handlers.

## Pipeline and ownership

```text
TCP
  → optional PCAP capture
  → BGP framing and message codecs
  → lazy KEEPALIVE / hold-timer handler
  → BGP finite-state machine
  → NIOAsyncChannel<SessionInput, Never>
  → one serial consumer
  → BGPSession actor: callbacks → diagnostics → RIB commit → watch publication
```

The NIO event loop owns channel state, protocol decisions, timers, outbound BGP
messages, and UPDATE admission. It prepares each complete UPDATE synchronously,
bounded by the supported 4,096-byte BGP message limit. Preparation produces an
immutable observation; it does not mutate the RIB.

The consumer awaits actor processing of each observation before requesting the
next. The actor owns application callbacks, diagnostics, the RIB, and subscriber
publication. Successful prepared content is committed and its diffs are
published without an intervening suspension or a second parse.

This separation follows [SwiftNIO's concurrency guidance](https://github.com/apple/swift-nio/blob/2.104.0/Sources/NIOCore/Docs.docc/swift-concurrency.md):
protocol handlers stay on the event loop; application processing crosses a
defined async boundary. There is no task per UPDATE.

## Native backpressure and capacity

The native bridge uses low/high watermarks of 8/64 observations. Fresh channels
use a fixed 4,096-byte receive allocation and one socket read per read cycle.
These are internal settings, not public capacity promises.

Watermarks control read demand, not an exact queue capacity: decoding a read can
produce several messages, and transport EOF handling may drain data despite
paused demand. A separate event-loop-owned admission guard allows at most
**1,024 pending UPDATE observations**, including the one being processed.

A credit is reserved before copying or preparing an UPDATE and released after
actor processing returns. Retained raw bodies are compact copies. Credits
remain owned during transport teardown until admitted observations drain.
Finite FSM state observations are carried separately.

At the hard limit, the FSM latches a local-capacity failure, disarms timers, and
closes transport. The overflowing body was never admitted: it produces no raw
callback, RIB mutation, or parser diagnostic. Earlier admitted work still drains.
The error reports a collection gap and the last RIB remains available.

This bounds pending UPDATE work, **not total memory**. RIB growth, subscriber
buffers, retained snapshots, outgoing writes, and work started by callbacks
have their own lifetimes and resource requirements. PCAP capture has its own
independent pending-data limits described below.

Hold timers continue while reads are suspended. Moving timers earlier in the
pipeline cannot make unread KEEPALIVEs refresh them. Negotiated hold zero can
allow a pause to continue indefinitely; there is no separate overload deadline.

## PCAP capture budget

`NIOWritePCAPHandler` emits encoded capture chunks through a synchronous
callback. The sink admits those chunks under a short lock and writes them on
its existing serial DispatchQueue using the safely opened POSIX descriptor.
Filesystem I/O and error callbacks do not run under the admission lock or on
the NIO event loop.

Each capture has internal limits of **8 MiB (8,388,608 bytes)** of pending
encoded PCAP data and **4,096 pending chunks**. Queued chunks and the active
write count until processing finishes. The byte count includes encoded record
headers and packet data. The fixed 24-byte file header is written before the
session connects, outside this asynchronous budget.

Admission checks both limits before copying or enqueuing a chunk. Accepted
readable bytes are copied into independent compact storage so a small slice
cannot retain a much larger input allocation. The byte metric excludes
allocator and queue metadata; the chunk cap separately bounds the number of
queued work items. These are resource safeguards, not throughput guarantees
or a bound on total process memory. Each simultaneous capture has its own
budget.

The first chunk that would exceed either limit is rejected whole. Capture
admission then stops permanently for that session: no later chunk is copied,
queued, or recorded. Already admitted chunks drain in order, then the sink
closes automatically. Later session cleanup joins or observes the same close
result. BGP processing, RIB updates, watch publication, and session exit
statuses are unaffected; capture overload does not pause socket reads.

If admitted writes succeed, the file contains the captured prefix before the
cutoff and will lack later traffic, including the final TCP close records.
An actual filesystem write failure can still leave a partial record. A
successful BGP session therefore does not establish capture completeness.
The overload warning identifies the file and limit, and is delivered on the
file queue before close completes. It may be delayed by stalled I/O; neither
the byte budget nor cancellation supplies a filesystem-operation timeout.

The budget does not limit capture-file growth on disk. File rotation, storage
quotas, and additional capture-completeness policies remain separate concerns.
See [capture-file safety](../SECURITY.md#capture-file-safety) for creation and
partial-evidence behavior.

## Callback and subscription contracts

Both `onUpdate` and `onStateChange` execute synchronously on the session actor.
`@Sendable` does not make a closure asynchronous. They must return promptly and
avoid blocking I/O, expensive work, sleeps, or synchronous waits for actor work.

`onUpdate` receives the raw admitted UPDATE body before that observation's RIB
mutation, including rejected bodies. Invalid outer BGP messages and bodies
rejected by admission are outside that contract. Preparation has already run
on the event loop; the callback cannot change its interpretation.

Slow callbacks delay RIB work, actor operations, and cleanup. Task cancellation
can request transport closure independently, but cannot interrupt arbitrary
synchronous callback code. Diagnostic stderr writes can also block, even when
`--log-updates` is disabled. Expensive consumers should use an explicitly owned
worker with deliberate buffering, overload, and shutdown policies. Work
independently launched by a callback is outside `run()`'s drain guarantee.

The independent `ribChanges` stream retains the newest 512 pending events per
subscriber by default. Overflow discards older events, potentially including
the catch-up snapshot. It does not remove RIB objects or throttle socket intake.
Exact replay requires complete event delivery; overflow detection and automatic
resynchronization are not implemented. Increasing stream capacity is not an
ingress flow-control policy.

## Identity, observations, and snapshots

The RIB has node, link, and prefix dictionaries with stable identity keys.
Values are `BGPLSNodeRecord`, `BGPLSLinkRecord`, and `BGPLSPrefixRecord`,
combining the identity-bearing NLRI, applicable typed attributes, and attribute
observation metadata.

Reachability prefixes store canonical `IPNetwork<Family>` values. Mixed-family
prefix records retain their IPv4/IPv6 cases. Address-valued link descriptors
remain addresses; they are not converted into reachability networks. IS-IS
identities retain System-ID/pseudonode semantics rather than being flattened
into IPv4 router IDs.

Attributes do not participate in topology keys. Every accepted advertisement
replaces the complete observation at its key, including absent or discarded
attributes. An attribute-only change preserves identity and counts. Identical
refreshes still produce upsert events; withdrawals carry identity only.

Structural equality and hashing include retained evidence. Descriptor order,
reserved bits, padding, or unknown fields can therefore make two observations
unequal while their canonical RIB keys match. Withdrawal matching uses those
keys, not complete record equality.

A `RIBSnapshot` is a deterministic, Codable projection with identity fields,
canonical CIDR networks, typed attributes, availability, and issue summaries.
It is not a packet archive. Older snapshots missing attribute fields mean
“attributes not recorded,” not proof of wire absence. Raw evidence remains in
RIB records, complete upsert events, and capture facilities.

## Failure ordering and cleanup

One `SessionOutcome` selects the session result. Establishment is a state
transition, not completion of that outcome. Normal established peer closure
succeeds; premature closure and terminal protocol/transport failures fail.

The FSM records terminal failure before ordinary close can select success.
For supported outbound NOTIFICATION cases, it first latches the error and
disarms timers, then attempts one write. Outcome publication waits for write
completion, failure, disconnection, or a private one-second deadline. Later
errors cannot replace the original cause.

The pending-channel registration and permanent stop latch close a channel even
if stop races connection establishment. Repeated stop requests are harmless.
The session owns and awaits its serial consumer: transport closes, admitted
observations drain, capture output closes, and subscriber streams finish before
`run()` returns or throws. `stop()` requests this process; awaiting `run()`
is the cleanup barrier.

The CLI additionally awaits its watch task before its terminal report. SIGINT
and SIGTERM preserve their selected shell statuses, 130 and 143. See
[protocol support](ProtocolSupport.md) for scoped NOTIFICATION behavior and
[CLI usage](../README.md#cli-output-and-shutdown) for report options.

## Product boundary

Protocol decoding, typed observations, fault handling, and composable collection
APIs belong in the open-source library. A production service can depend on
released `BGPLSClient` while supplying multi-peer supervision, reconnection,
durable storage, restart recovery, metrics, alerts, control APIs, and proprietary
analysis. Those policies do not require a private fork of the protocol engine.

The current collector does not reconcile stale state after a collection gap.
Discarded NLRIs cause no RIB mutation; a rejected withdrawal or replacement can
leave previously accepted information stale. No partial withdrawal key is
inferred. The retained RIB after disconnect is an observation history endpoint,
not proof of the current network.
