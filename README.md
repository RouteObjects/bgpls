<h1 align="left">
  <img src="Documentation/Assets/bgpls-icon.png" alt="bgpls icon" width="75" height="75" valign="middle">
  &nbsp;bgpls
</h1>

[![Swift versions](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FRouteObjects%2Fbgpls%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/RouteObjects/bgpls)
[![Platforms](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FRouteObjects%2Fbgpls%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/RouteObjects/bgpls)

`bgpls` collects BGP Link-State topology into a typed, in-memory RIB. It provides
the `BGPLSClient` Swift library and a command-line client for inspecting nodes,
directed links, IPv4/IPv6 prefixes, and selected advertised attributes.

`bgpls` is part of [RouteObjects’ **Swift for Infrastructure** initiative](https://routeobjects.com/),
demonstrating practical network-control software built in Swift. It is powered by
[swift-cidr](https://github.com/RouteObjects/swift-cidr) for typed IP addresses,
canonical network prefixes, endpoints, and autonomous system numbers.

The client makes an outbound connection to a BGP-LS producer. It does not run an
IGP, originate BGP-LS routes, or forward traffic. The reference lab demonstrates
FRRouting and optional Arista cEOS producers with a native macOS collector.

**Release preparation:** `0.1.0` is an unreleased source release candidate.
The sections below describe supported features, usage, and validation.

## Build and try it

**Here for the network demo?** The [operator walkthrough](Documentation/Lab/Operators/GettingStarted.md)
shows how to observe a backbone link withdrawal and recovery on a prepared FRR lab.

Use Swift 6.3 or later on macOS 15 or later, or on Linux:

```sh
swift build --product bgpls
.build/debug/bgpls --help
./scripts/test.sh
```

New to the demo? **[Run your first bgpls lab on a Mac](Documentation/Lab/GettingStarted.md)**
walks you from installing the tools to watching a backbone link disappear and
return. It uses macOS Terminal for the collector and an optional VS Code window
for the topology. If your lab host is already set up, use the
[short FRR quickstart](lab-examples/bgpls/README.md).

Once that lab is deployed, run:

```sh
.build/debug/bgpls run \
  --peer 127.0.0.1 --port 11790 \
  --local-as 65001 --peer-as 65001 \
  --bgp-identifier 192.0.2.101 \
  --watch --show-attributes --dump-rib
```

The default FRR profile supplies **5 nodes, 14 directed links, and 10 prefixes**.
The optional [FRR + cEOS profile](lab-examples/bgpls/CEOS.md) supplies
**6 nodes, 18 directed links, and 12 prefixes per producer**, with separate
collectors on ports `11790` and `11791`. The cEOS image requires the user's own
vendor entitlement. The two profiles are alternative deployments, both named
`bgpls`; each producer accepts one collector at a time.

Read the [prerequisites and lab guide](Documentation/Lab/README.md) before
deploying. The lab scripts manage only their recorded, owned deployment.

## CLI output and shutdown

`--watch` prints RIB snapshots, upserts, and withdrawals as they arrive.
`--show-attributes` adds typed attribute fields to upserts and requested dumps.
`--dump-rib` prints the full RIB on termination; without it, termination prints
the status and one counts line. Neither `--watch` nor `--show-attributes` enables
a final dump implicitly.

Node output uses `AS not-advertised` when the Node Descriptor's ASN sub-TLV
(512) is absent. It does not infer a topology ASN from the BGP session's ASN.
Other unknown descriptor fields retain their own placeholders.

Ctrl-C or SIGTERM requests orderly cleanup. Admitted observations finish before
the optional watch task, PCAP output, and final report complete.

| Termination | Process status |
| --- | ---: |
| Normal established peer closure | `0` |
| Connection or session failure | `1` |
| SIGINT after cleanup | `130` |
| SIGTERM after cleanup | `143` |

Capture is opt-in: `--pcap FILE` records session traffic at an explicit path,
while `--pcap-auto` selects a filename in the current working directory.
Omitting both disables capture; combining them is a validation error.

Automatic filenames use
`bgpls_yyyyMMdd_HHmmssZ_peer-ADDRESS_port-PORT_UUID.pcap`.
The timestamp is selected before connecting, using UTC, the Gregorian calendar,
and a fixed POSIX locale; `Z` is literal. `ADDRESS` is the configured numeric
peer address without a prefix, with IPv6 colons replaced by hyphens. `UUID` is
a full lowercase, hyphenated UUID. The peer can be a relay, so its address and
port do not identify the vendor or topology producer. The CLI prints the selected
absolute path with control characters escaped before creating the session;
the existing `writing PCAP` message separately confirms capture setup.

Both options require a **new file in a trusted directory**. Existing paths are
refused, including symbolic links; automatic naming does not probe for available
names, overwrite, or retry a collision. New files request owner-only permissions
(`0600`, subject to a more restrictive umask). Ordinary parent-directory
symlinks, such as macOS `/tmp`, are supported; this does not isolate the path
from an untrusted directory owner. Creation or header-write failures stop setup
before connecting. Later capture-write errors are logged while collection
continues, so a successful session does not by itself certify a complete capture.

Each capture admits at most **8 MiB of pending encoded PCAP bytes** and
**4,096 pending chunks**, including the write in progress. If either limit
would be exceeded, capture stops for the rest of that session, accepted chunks
drain, and the file closes. A warning identifies the incomplete capture;
**BGP collection, RIB updates, and watch events continue** with unchanged exit
statuses. The warning runs on the file queue and may wait behind stalled I/O.
These internal limits bound pending capture data and chunk count, not total
process memory, disk usage, or shutdown duration. See the
[capture budget](Documentation/Architecture.md#pcap-capture-budget) for details.

`--log-updates` enables capped raw UPDATE hexadecimal logging. Protocol
diagnostics are also emitted when that logging is disabled. Capture files and
logs may contain sensitive topology information.

`bgpls show` and `bgpls stop` print usage guidance; there is no daemon control
socket or cross-process RIB query interface. Use the foreground `run` command
and its signal handling.

## Library and protocol scope

The library is independent of CLI signal handling. Applications construct an
explicit `BGPSessionConfiguration`, run a session, consume `ribChanges`, and
read a typed RIB or a JSON snapshot. See the
[compilable library example](Documentation/LibraryUsage.md).

- IPv4 and unscoped IPv6 session transport, with an independent nonzero BGP identifier.
- Two-byte and four-byte ASN session negotiation, including capability 65.
- IS-IS and OSPF node identities, links, and canonical IPv4/IPv6 reachability networks.
- Advertisements, withdrawals, deterministic snapshots, and typed watch records.
- Node names, link IGP metrics, prefix metrics, and advertised link bandwidth.
- Unknown data and original attribute evidence retained alongside typed projections.
- Native NIO read backpressure, bounded pending UPDATE admission, and ordered cleanup.

See [protocol support](Documentation/ProtocolSupport.md) for exact parsing,
timer, recovery, and interoperability boundaries. `swift-cidr` supplies typed
addresses, networks, endpoints, and ASNs; this candidate adopts its `0.11.0`
release without enabling an additional strict-address policy.

## Operational limits

The library is a collector and reference implementation. Production deployment
needs an application-owned policy for reconnection, persistence, reconciliation,
monitoring, authentication, and resource limits.

- Callbacks run synchronously on the session actor and must return promptly.
  Blocking callbacks or slow stderr destinations can delay processing and
  cleanup. Cancellation cannot interrupt arbitrary synchronous callback code.
- Native watermarks reduce read demand; a separate limit permits at most 1,024
  pending UPDATE observations. Exceeding it terminates the session and reports
  a collection gap. This does not bound the RIB or total process memory.
- Each `ribChanges` subscription retains the newest 512 events by default.
  Slow subscribers can lose events; exact replay requires the complete event
  sequence. There is no overflow notification or automatic resynchronization.
- Rejected withdrawals or replacements can leave earlier accepted information
  stale. Disconnect retains the last RIB without proving it is still current.
- Hold timers continue during read suspension. An unread KEEPALIVE cannot
  refresh a deadline; negotiated hold zero can allow an indefinite pause.
- Outbound NOTIFICATION support is deliberately limited. AS paths remain raw
  evidence; there is no general path reconstruction or route selection.

The [architecture guide](Documentation/Architecture.md) explains ownership,
buffering, failure ordering, and cleanup. Historical lab qualification is
summarized separately from current checks in the
[public validation record](lab-examples/bgpls/VALIDATION.md). Native AMD64
package tests do not establish AMD64 vendor-lab qualification.

## Documentation and contributions

- [Documentation index](Documentation/README.md)
- [Draft 0.1.0 release notes](Documentation/ReleaseNotes/0.1.0.md)
- [Contributing and offline checks](CONTRIBUTING.md)
- [Report a vulnerability privately](SECURITY.md#report-a-vulnerability-privately)

Licensed under [Apache License 2.0](LICENSE). Vendor images are not included.
