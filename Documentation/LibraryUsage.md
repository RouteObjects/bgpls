# Using BGPLSClient

Add the `BGPLSClient` library product to your SwiftPM target. Code that names
swift-cidr types should also declare the `CIDR` product dependency and import it
explicitly. The package requires Swift 6.3 and declares macOS 15 and iOS 18
deployment floors; macOS and Linux are the CLI platforms.

## A complete collector example

This source can be compiled as a Swift executable target with `BGPLSClient`
and `CIDR` dependencies. It connects to the default reference lab's relay
only when executed. Build/deploy the lab separately using the
[quickstart](../lab-examples/bgpls/README.md).

The example owns one watch task and awaits it on both success and failure.
It installs no signal handlers; use the `bgpls` CLI for a Terminal demonstration,
or have your application request `stop()` or cancel the task running collection.

```swift
import BGPLSClient
import CIDR
import Foundation

enum ExampleError: Error {
    case invalidConfiguration
}

func makeSession() throws -> BGPSession<AF.V4> {
    guard let peer = IPv4Address("127.0.0.1"),
        let identifier = BGPIdentifier("192.0.2.101")
    else {
        throw ExampleError.invalidConfiguration
    }
    let configuration = BGPSessionConfiguration(
        peer: .tcp(address: peer, port: 11790),
        localAS: AutonomousSystemNumber(65001),
        peerAS: AutonomousSystemNumber(65001),
        bgpIdentifier: identifier
    )
    return BGPSession(configuration: configuration)
}

func collect(_ session: BGPSession<AF.V4>) async throws -> RIBSnapshot {
    let changes = await session.ribChanges()
    let watcher = Task {
        for await change in changes {
            print(change.watchLine(showAttributes: true))
        }
    }

    do {
        try await session.run()
    } catch {
        await watcher.value
        throw error
    }

    await watcher.value
    return await session.ribSnapshot(at: Date())
}

@main
struct Example {
    static func main() async throws {
        let session = try makeSession()
        let snapshot = try await collect(session)
        print(try snapshot.jsonUTF8String())
    }
}
```

Printing is appropriate for this small demonstration, but a slow output
destination can delay the watch consumer and cause its bounded stream to drop
events. Use the session's snapshot as the authoritative current in-memory
view rather than assuming terminal output is a lossless journal.

## Configuration and session ownership

Construct every session explicitly. There are no implicit physical-lab
addresses or ASNs. `BGPSessionConfiguration<Family>` binds the peer endpoint
and optional local address to the same IPv4 or IPv6 family. Use a host-length
address, numeric nonzero peer port, local/peer `AutonomousSystemNumber` values,
and an independent `BGPIdentifier`.

The identifier is a nonzero 32-bit speaker identity displayed as four decimal
octets. It is not an IPv6 address or a socket address; choose it independently
of transport and uniquely within the AS. DNS names, service-name ports,
IPv6 scope zones, link-local IPv6 endpoints, and IPv4-mapped IPv6 transport are
unsupported. See [transport and negotiation](ProtocolSupport.md#transport-and-open-negotiation).

`connectTimeout` defaults to ten seconds and must be positive. It bounds TCP
connection establishment, not the BGP handshake or session lifetime.
`holdTimeSeconds` defaults to 90 and accepts zero or `3...65535`.

Run at most one operation on a session at a time. A stop request permanently
latches that session; construct a new session for a new lifecycle after stop.
`stop()` is idempotent and requests closure, while the task awaiting `run()`
provides the cleanup guarantee. A normal return means ordinary established
peer closure; errors and cancellation must remain visible to your supervisor.

Applications own retry/backoff, peer authorization, service lifecycle, and
whether a failed session's retained topology remains usable. The library does
not reconnect automatically.

## Optional PCAP capture

Pass `pcapPath` to `run()` to record a capture in a new file in a trusted
directory. Omitting it disables capture. Creation and initial header-write
failures prevent connection; later capture-write failures are reported to
stderr while BGP collection continues. See
[capture-file safety](../SECURITY.md#capture-file-safety).

Each capture has internal pending-data limits of **8 MiB of encoded PCAP bytes**
and **4,096 chunks**, including the active write. Exceeding either stops capture
for the rest of that session, drains accepted chunks, and closes the file.
The incomplete-capture warning does not fail the session, change the RIB, or
stop watch events. Capture does not resume when capacity becomes available.

Awaiting `run()` still awaits capture cleanup. The warning is emitted on the
serial file queue and can wait behind stalled I/O. The budget is not a disk
quota or shutdown deadline, and a normal session return does not certify a
complete capture. These limits are per capture, not an application-wide
memory bound; they are not public tuning options. The
[architecture guide](Architecture.md#pcap-capture-budget) defines the accounting
and overload behavior.

## Callbacks

`run(onUpdate:onStateChange:)` provides synchronous observation hooks on the
session actor. They are `@Sendable` closures, not async work handlers.

- `onUpdate` observes the admitted raw body before its RIB mutation, including
  rejected UPDATE bodies. Outer BGP framing failures and capacity-rejected
  bodies are not admitted.
- `onStateChange` observes session progress such as OpenSent, OpenConfirm,
  Established, and Stopped.
- Both must return promptly. Avoid blocking I/O, sleeps, expensive computation,
  and synchronous waits for actor work.
- Independently launched work is outside the library's drain guarantee. Use an
  explicitly owned worker with a chosen buffering, overload, and shutdown
  policy for expensive processing; do not launch one task per UPDATE.

A slow callback can delay actor queries, RIB processing, and cleanup.
Cancellation can close transport but cannot interrupt synchronous callback
code. Diagnostic writes to stderr have the same slow-destination risk and may
occur without raw UPDATE logging.

## RIB, records, and change streams

`await session.ribSnapshot()` returns an `LSRIB` value, containing node, link,
and prefix record dictionaries. `await session.ribSnapshot(at: date)` returns a
Codable `RIBSnapshot` projection. Records contain the NLRI, applicable typed
attributes, and the complete attribute observation. Prefix NLRIs retain
canonical IPv4/IPv6 networks and original descriptors.

`ribChanges(includeCatchUpSnapshot:bufferingNewest:)` returns an
`AsyncStream<RIBDiff>` with three forms:

| Event | Content |
| --- | --- |
| `snapshot` | Catch-up projected RIB, enabled by default |
| `upsert` | Complete `BGPLSRecord`, including attributes and raw observation evidence |
| `withdraw` | Identity-bearing `BGPLSNLRI` |

Each accepted advertisement emits an upsert, even if identical to the previous
observation. Every advertisement replaces the complete attribute observation;
missing or discarded fields do not carry previous values forward.

Each subscriber retains the newest 512 pending events by default. A slow
subscriber can lose older events, including its catch-up snapshot, without
losing objects from the session RIB. This buffer is separate from native socket
backpressure. Exact replay requires delivery of every event; overflow
detection and automatic resynchronization are future work.

Typed attribute absence is not zero. Inspect `record.observation.availability`
and diagnostics to distinguish absent, present, and discarded wire attributes.
A present observation can still lack an unusable projection. For example,
`record.attributes.igpMetric` on a link is optional; bandwidth values expose
`bytesPerSecond` and `bitsPerSecond`. Unreserved bandwidth has exactly eight
entries, with priorities 0 through 7.

## Direct parsing and recovery

For offline analysis, `LSRIB.apply(update:)` is strict and atomic: any rejected
NLRI or unusable attribute projection throws before mutation. Harmless warnings
do not throw. `applyIsolating(update:)` uses the live collector's recovery rules
and returns committed diffs plus complete diagnostics.

Both prepare all applicable reachability and withdrawal fields before
committing. Recoverable rejected NLRIs leave valid siblings usable; fatal
framing leaves the entire UPDATE unapplied. Reachability is applied before
withdrawals. See the [fault-handling rules](ProtocolSupport.md#update-recovery)
for attribute-specific behavior.

Discarded NLRIs cause no RIB mutation. A rejected withdrawal or replacement
advertisement can therefore leave previously accepted information stale; the
diagnostic identifies the collection gap. The collector does not derive
partial withdrawal keys or automatically mark stale entries.

Snapshots are projections, not raw packet archives. Missing attribute fields
in an older snapshot mean “not recorded,” not “absent on the wire.” Preserve
records or captures when raw evidence is required, and protect topology data
according to your application's security policy.
