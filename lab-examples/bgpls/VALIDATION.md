# Qualification summary

This file separates **previous live qualification** from verification of the
public-release candidate. Each test records its tested versions, workload,
and observed results.

The [packaged FRR-only quickstart](#2026-11-20-packaged-frr-quickstart)
passed on 2026-11-20 with two directed withdrawals, exact restoration, and
scoped teardown. It used explicit down/up commands and waited for the events.
The [2026-11-15 rehearsal](#2026-11-15-containerlab-0830-fresh-frr-only-rehearsal)
records the different result for a fixed ten-second flap. The separate
[Swift 6.3 paired-producer regression](#2026-11-09-swift-63-paired-producer-live-regression)
passed on 2026-11-09; earlier attempts below retain their original outcomes.

## Previous live qualification

The reference lab has been exercised on native ARM64 Linux hosted by OrbStack,
using stable Containerlab **0.81.1**, the pinned
**FRR `containerlab-10.7.1`** image, **HAProxy 3.0.27**, and the optional entitled
**cEOS ARM64 4.36.2F** image. Native macOS collectors connected through the IPv4
relay; prepared native Linux ARM64 collectors tested direct IPv6 transport.

| Coverage | Previous observed result |
| --- | --- |
| FRR-only convergence | `5 nodes / 14 links / 10 prefixes` |
| FRR + cEOS convergence | `6 nodes / 18 links / 12 prefixes` independently per producer |
| Topology families | IPv4 and IPv6 prefixes and link descriptors |
| Session transports | IPv4 and IPv6 |
| Session ASN | `65001` and private four-byte ASN `4200000001` |
| Churn | Physical-link and independent IPv6-prefix withdrawal/restoration |
| Typed attributes | Wire/native/Swift/CLI comparison and metric probes with exact restoration |
| Shutdown | Independent producer sessions, SIGINT `130`, SIGTERM `143`, complete final reports and captures |

The supplied cEOS image reports `4.36.2F-49692632.4362F.1 (engineering build)`.
These observations do not qualify arbitrary newer images or runtime versions.
Retained [capture fixtures](../../Documentation/Lab/FixtureProvenance.md) cover
specific messages and preserve their original bytes; they are not complete
packet archives or a substitute for testing an entire session.

## Public-release candidate: offline verification

The isolated public export passed the checks below on 2026-10-27, starting
from fresh build caches. The complete Swift suites and builds were repeated
after the final synthetic-fixture and PCAP-hint edits. The export contained
no development Git history, private documentation, local package overrides,
or retained build caches.

| Offline check | Completed result |
| --- | --- |
| macOS, Apple Swift 6.3.3 | 371 tests across 35 suites; explicit `BGPLSClient`, `BGPLSCLI`, and `bgpls` builds passed |
| Native ARM64 Linux, Swift 6.2.4 | 371 tests across 35 suites and all three explicit builds passed |
| Native ARM64 Linux, Swift 6.3.3 | 371 tests across 35 suites and all three explicit builds passed |
| macOS deployment floor | macOS 15 minimum verified in the built product |
| iOS library compile | `BGPLSClient` compiled for the iOS 18 ARM64 simulator |
| External SwiftPM consumer | Complete public `LibraryUsage` example compiled; it was not run against a peer |
| Formatting | Strict configured Swift formatting passed |
| Python tests | 444 tests passed |
| Mocked shell workflows | 314 guard checks passed |
| Script compatibility and syntax | Python 3.9 syntax checked for 32 files; Bash syntax checked for 12 scripts |
| Documentation structure | 16 Markdown files, one draw.io file, and three SVGs checked |
| Preserved vendor evidence | All 36 retained virtual-lab capture byte strings unchanged |
| Diagram correspondence | All 11 physical links in the cEOS-superset YAML checked against the diagram |

The stress sweep and externally supplied capture-replay tests remain opt-in
and were not run; the retained vendor-capture suites ran in every full suite.
Linux test/build containers had external networking disabled after dependency
resolution. swift-cidr resolved to published `0.8.0`; all other pins were unchanged.

These are local offline results. No live collector connection, deployment
operation, or end-to-end quickstart rehearsal was performed during the
2026-10-27 offline verification. Hosted CI has not run, and local native AMD64 qualification was not
performed. The iOS result is a library compile check, not an iOS runtime or lab
test.

## Fresh-machine host setup: 2026-10-28

The [one-time OrbStack guide](../../Documentation/Lab/OrbStackSetup.md) was
rehearsed in a newly created Ubuntu Noble ARM64 machine. The existing macOS and
OrbStack installation was reused; this was not a first-time installation of
those host components. A disposable copy of the reviewed public export supplied
the source paths. The original deployment and global forwarding setting were
left unchanged.

| Setup check | Observed result |
| --- | --- |
| Host | Apple Silicon, macOS 26.7.1, OrbStack 2.2.5 |
| Mac tools | Apple Swift 6.3.3, Bash 3.2.57, Python 3.12.6 |
| Fresh guest | Ubuntu 24.04.5 LTS, native ARM64 |
| Rehearsal limits | 4 GiB memory, 2 CPUs, 32 GiB disk; setup limits, not router-lab capacity qualification |
| Docker Engine and CLI | 29.9.2, installed from Docker's signed Ubuntu repository |
| Supporting Docker packages | containerd 2.4.2, Buildx 0.38.1, Compose 5.6.1 |
| Containerlab | 0.81.1 ARM64 package; release checksum and package metadata verified |
| Runtime identity | Local Unix socket, new daemon ID distinct from the existing lab, no endpoint overrides |
| Guest utilities and shared paths | Python 3.12.3, `ss` available; identical absolute source/deployment-parent paths accessible from Mac and guest |
| Basic container | ARM64 `hello-world` completed successfully and was removed |
| Containerlab network smoke | Two temporary Linux nodes; three successful pings in each direction over their explicit link |
| macOS localhost smoke | Pinned HAProxy 3.0.27 image returned a unique response through an unused loopback-bound port; guest and Mac checks passed |
| Scoped cleanup | Temporary containers, custom network, and port listener removed; prepared machine retained |
| Guide checks | Eleven shell blocks passed Bash syntax checks; existing-name refusal and Ctrl-C status `130` shell handoff verified |

Containerlab's package printed a non-root group-setup warning when installed
directly as root; installation and the documented root-based runtime checks
passed. An initial temporary HTTP probe failed because its minimal image did
not contain the assumed server executable. That failed harness evidence was
retained; the corrected HAProxy probe validated its configuration and running
state before checking connectivity. No installation workaround was required.

No bgpls routers were deployed, no BGP-LS collector connected, and no link or
metric probe was run against the existing lab. This run qualified host setup
and basic networking. Full FRR/cEOS interoperability remained outside its
scope. No public package source, dependency, or runtime script changed.
The later [November 20 packaged FRR quickstart](#2026-11-20-packaged-frr-quickstart)
verified both p1–p2 withdrawals, exact restoration, and scoped teardown.

## Remaining publication and qualification gates

- Run hosted CI on the eventual public repository, including native AMD64 package tests.
- Review public export contents, repository setup, security-reporting route, licensing, and fixture provenance before publication.
- Qualify native AMD64 vendor-lab operation separately; AMD64 package testing alone does not establish it.
- Treat long-duration operation, multi-peer supervision, reconnection, persistence, observability, and capacity planning as separate work.

The collector bounds pending UPDATE observations, but this is not a bound on the
entire process: RIB size, snapshots, subscriber buffers, capture writes, and
consumer-owned work remain separate. Synchronous callbacks must return promptly.
A slow subscriber can miss bounded watch events; exact replay requires the
complete sequence. Rejected withdrawals or replacement advertisements can leave
previously accepted information stale, and a disconnected RIB is retained data,
not a claim of current network state.

## PCAP file-safety follow-up: 2026-10-29

PCAP output now creates a new file exclusively, requests owner-only `0600`
permissions subject to the caller's umask, and retains the opened descriptor
through ordered writes and closure. Existing files, links, and special files
are refused. The containing directory must be trusted. Capture encoding and
the policy of logging later capture errors while collection continues are
unchanged; see [capture-file safety](../../SECURITY.md#capture-file-safety).

Validation used an isolated source copy with the committed dependency graph
and newly built package outputs on native ARM64 macOS 26.7.1, Apple Swift
6.3.3 (`swiftlang-6.3.3.1.3`).

| Follow-up check | Observed result |
| --- | --- |
| Full Swift suite | 389 tests across 37 suites passed, including retained captures and IPv4/IPv6 lifecycle tests |
| Explicit builds | `BGPLSClient`, `BGPLSCLI`, and `bgpls` passed |
| Deployment floors | Executable reports macOS 15 minimum; library compiled for the iOS 18 ARM64 simulator |
| Filesystem regressions | Existing regular files, hard links, valid/dangling symlinks, directories, FIFOs, and UNIX sockets preserved; concurrent creation and pathname replacement tested |
| Sink regressions | Partial/interrupted writes, header failures, close-on-exec, ordered draining, repeated/concurrent closure, and capture-error policy passed |
| Session regressions | Refused capture destinations fail before connecting on IPv4 and IPv6 and finish subscribers |
| Bounded CLI subprocesses | 34 cases passed: both transports and final-report modes, normal `0`, protocol failure `1`, SIGINT `130`, SIGTERM `143`, watch delivery, and complete captures |
| Subprocess filesystem failures | Existing destinations refused before TCP; `0600` creation and a restrictive umask verified; partial header failure exits `1`, while a later write failure is logged once and collection exits `0` |
| Formatting and scripts | Strict configured Swift formatting, 444 Python tests, 314 mocked workflow guard checks, Python 3.9 syntax, and Bash syntax passed |

The full Swift suite was repeated after the final test-only warning cleanup.
No runtime source changed after the recorded build checks.

### Isolated native ARM64 Linux follow-up: 2026-10-29

The same source passed validation in a temporary, isolated Ubuntu 24.04.5
ARM64 machine. Host sharing and SSH-agent forwarding were disabled; only a
disposable validation directory was mounted, and access to other machines was
blocked. Each toolchain used a separate build directory, with the 19 committed
dependency revisions verified before copying their sources. No compiled
macOS artifacts were reused. Test containers had external networking disabled.

| Linux check | Swift 6.2.4 | Swift 6.3.3 |
| --- | --- | --- |
| Full suite | 389 tests across 37 suites passed | 389 tests across 37 suites passed |
| Explicit builds | `BGPLSClient`, `BGPLSCLI`, `bgpls` passed | `BGPLSClient`, `BGPLSCLI`, `bgpls` passed |
| Bounded subprocesses | 34/34 passed; 18 complete wire-exact captures | 34/34 passed; 18 complete wire-exact captures |
| Changed-file formatting | Passed | Passed |
| Whole-package formatting | One pre-existing diagnostic, described below | Passed |

The actual compilers reported `swift-6.2.4-RELEASE` and
`swift-6.3.3-RELEASE`, both targeting `aarch64-unknown-linux-gnu`. Full suites
and builds passed first in the official Swift images, then again in images
derived solely to add the Python subprocess harness. Both versions preserved
the committed manifest and lockfile. The subprocess matrices covered both
transports, summary/full reports, normal and protocol-failure exits, signals,
destination refusal, restrictive umasks, and header/later-write failures.

Swift 6.2's formatter reports `UseExplicitNilCheckInConditions` for the existing
discarded reserved-byte binding in `Sources/BGPLSClient/BGPMessage.swift`.
That file is byte-identical to the branch base and was left unchanged. This is
an unrelated formatting difference, not a PCAP regression; the changed Swift
files pass both formatters. Neither compiler emitted warnings.

The temporary validation machine was removed after saving the evidence. The
two preserved machines retained their original identities, configuration, and
running states. No runtime source or tests changed during this Linux follow-up.

No vendor collector connection, deployment operation, or lab change was part
of this follow-up.

## Automatic PCAP filenames: 2026-10-29

`--pcap-auto` now selects one capture destination in the current working
directory after configuration validation. Its name contains the UTC selection
time, configured numeric peer and port, and a full lowercase UUID. IPv6 colons
become hyphens and CIDR prefix lengths are omitted. Selection is announced with
an escaped absolute path; it does not claim that file creation succeeded.
Explicit `--pcap FILE` behavior and the library API remain unchanged. Neither
option means no capture, and combining them is rejected. Both modes retain the
exclusive-creation and trusted-directory rules described above.

The runtime and test sources were frozen before the full validation runs.
Separate source/build directories used the same 19 pinned dependency revisions;
manifests and lockfiles were unchanged. All validation used synthetic loopback
peers, with no vendor-lab connections.

| Check | Native ARM64 macOS | Native ARM64 Linux 6.2 | Native ARM64 Linux 6.3 |
| --- | --- | --- | --- |
| Actual compiler | Apple Swift 6.3.3, macOS 26.7.1, Xcode 26.6 | Swift 6.2.4 release | Swift 6.3.3 release |
| Full Swift suite | 404 tests in 38 suites passed | 404 tests in 38 suites passed | 404 tests in 38 suites passed |
| Explicit builds | `BGPLSClient`, `BGPLSCLI`, `bgpls` passed | All three passed | All three passed |
| CLI subprocess matrix | 32/32 cases, 34 children passed | 32/32 cases, 34 children passed | 32/32 cases, 34 children passed |
| Complete PCAP wire audits | 24/24 passed | 24/24 passed | 24/24 passed |
| Changed-file formatting | Passed | Passed | Passed |
| Whole-package formatting | Passed | Existing diagnostic documented above | Passed |

The macOS 15 deployment-floor executable build also passed. Compiler output
contained no warnings. Permanent regressions cover UTC day/year boundaries,
calendar-year formatting, canonical IPv4/IPv6 literals, relay ports, UUID
variation, spaces/control characters, display-option combinations, omitted and
explicit capture options, missing/empty values, and mutual exclusion. A real
session test confirms that a generated-path collision preserves the existing
file and permissions, performs no retry, and fails before TCP connection.

Each subprocess matrix exercised IPv4/IPv6 automatic capture with normal exit
`0`, protocol failure `1`, SIGINT `130`, and SIGTERM `143`, with both final-report
modes. It also covered unchanged explicit paths, omission creating no capture,
validation/setup failures before TCP, and two simultaneous collectors using
the same directory, peer, and port. Filenames matched their UTC execution
window, address, port, and UUID; the selection notice preceded connection.
Captures matched the peer's exact wire bytes through the final records, and all
28 completed-session reports retained the expected topology. Signals targeted
only harness-owned subprocesses.

Linux tests used pinned official Swift ARM64 images with a separate Python
harness prefix, isolated build caches, and external networking disabled. The
temporary validation machine was removed after evidence preservation. The two
existing machines retained their identities, configuration, addresses, and
running states. The private archive was not accessed.

Public documentation/export checks, validation-harness syntax, and Git whitespace
checks passed. The refreshed public candidate contains 162 allowlisted files;
raw validation evidence remains outside it. No staging, commits, deployment
operations, or changes to lab qualification commands were part of this pass.

## SwiftNIO 2.104.0 qualification: 2026-10-29

The declared SwiftNIO minimum is now 2.104.0 within the 2.x series. Targeted
SwiftPM resolution selected the published tag at
`6db9d9abd92ad7399b8a564cafbb87d3507245fa`. The other 18 dependency pins are
unchanged, including NIOExtras 1.34.3 and swift-cidr 0.8.0. No application
source, tests, filesystem products, capture behavior, or public signatures
changed for this qualification.

Frozen source copies used fresh build caches and automatic dependency
resolution was disabled during validation. Linux ran in a disposable native
ARM64 environment, with separate compiler caches and external container
networking disabled. Package hashes and all 19 dependency revisions were
checked; 6,168 dependency source-file and symlink entries also matched the
frozen input after Linux validation.

| Check | Native ARM64 macOS | Native ARM64 Linux 6.2 | Native ARM64 Linux 6.3 |
| --- | --- | --- | --- |
| Actual compiler | Apple Swift 6.3.3, Xcode 26.6, macOS 26.7.1 | Swift 6.2.4 release | Swift 6.3.3 release |
| Focused lifecycle/capture tests | 146 tests in 9 suites passed | 128 tests in 7 suites passed | 128 tests in 7 suites passed |
| Full Swift suite | 404 tests in 38 suites passed | 404 tests in 38 suites passed | 404 tests in 38 suites passed |
| Explicit builds | `BGPLSClient`, `BGPLSCLI`, `bgpls` passed | All three passed | All three passed |
| CLI subprocess matrix | 32/32 cases, 34 children, 302 assertions passed | Same matrix passed | Same matrix passed |
| Complete PCAP wire audits | 24/24 passed | 24/24 passed | 24/24 passed |
| Optimized synthetic cases | `smoke` and `bridge-native` passed | Both passed | Both passed |
| Whole-package formatting | Passed | Existing Swift 6.2 diagnostic documented above | Passed |

The macOS 15 deployment-floor executable build passed and its load command
records minimum OS 15.0. The library compiled for the iOS 18 ARM64 simulator.
The subprocess matrix retained IPv4/IPv6, normal/protocol-failure exits,
SIGINT/SIGTERM, summary/full reports, automatic/explicit/omitted captures,
concurrent captures, and complete final records. All 28 completed-session
reports per platform retained their expected topology.

The synthetic smoke case applied 39 observations for a 7-node, 18-link,
14-prefix topology. The bridge case applied 10,000 updates to one object with
an initial two-second consumer pause and a one-millisecond per-update delay.
It completed with peak pending observations of 76 on macOS, 77 on Linux 6.2,
and 84 on Linux 6.3, below the existing 1,024 admission limit. Every case
completed within the unchanged 120-second runner deadline.

These are compatibility checks. Workload timings cover the test actor's
processing through drain and teardown; they exclude production callbacks,
watch publication, CLI output, and PCAP. Compiler startup and build time are
separate from workload time. No before/after performance comparison was made.
Copied runners were adapted outside the package for isolated source paths;
an initial macOS helper-path error and a nonportable Linux Git-metadata audit
were retained in the evidence. The corrected helper and portable dependency
source-hash audit passed without application changes.

Offline tooling passed 444 Python tests, 314 mocked workflow checks, Python
3.9 syntax checks for 32 files, and Bash syntax checks for 12 scripts. Public
documentation, refreshed export, and Git whitespace checks passed. The export
retains 162 allowlisted files, with raw evidence stored separately.

The temporary Linux validation machine was removed after evidence preservation;
existing machines, the running lab, and the private archive were unchanged.
No live vendor qualification was repeated for this dependency update. Hosted
CI and native AMD64 package qualification remain publication gates.

## 2026-10-29 — PCAP capture-budget qualification

The existing POSIX/DispatchQueue capture sink now limits each capture to
8 MiB of pending encoded data and 4,096 pending chunks, counting the active
write. Admission checks precede compact copying and queue submission. An
overflow stops capture admission, drains accepted chunks, reports the incomplete
capture once, and closes the file while BGP/RIB/watch processing continues.
No public API, CLI option, dependency, manifest, or lockfile changed.

Frozen source copies were qualified offline with automatic dependency
resolution disabled. All 19 dependency pins and their source contents remained
unchanged. The Apple toolchain was Swift 6.3.3 with Xcode 26.6 on macOS 26.7.1;
the Linux toolchains were official native ARM64 Swift 6.2.4 and 6.3.3 on Ubuntu
24.04.5, with separate fresh build caches and network-disabled test containers.

| Check | macOS ARM64 | Linux ARM64 Swift 6.2.4 | Linux ARM64 Swift 6.3.3 |
| --- | --- | --- | --- |
| Focused capture/lifecycle tests | 64 tests / 6 suites passed | 64 / 6 passed | 64 / 6 passed |
| Full Swift suite | 415 tests / 39 suites passed | 415 / 39 passed | 415 / 39 passed |
| Explicit client, CLI, executable builds | Passed | Passed | Passed |
| Bounded subprocess matrix | 32 cases / 302 assertions passed | 32 / 302 passed | 32 / 302 passed |
| Changed Swift-file formatting | Passed | Passed | Passed |
| Whole-package formatting | Passed | Existing Swift 6.2 diagnostic documented above | Passed |

The macOS 15 executable build passed with minimum OS 15.0 recorded in the
Mach-O load command. The library also compiled for the iOS 18 ARM64 simulator.
The known Swift 6.2 formatter diagnostic in `BGPMessage.swift` remains confined
to the unchanged file; it was not suppressed or repaired as part of this work.

New deterministic tests cover byte and chunk boundaries, accounting for the
active write, independent storage for small slices, empty/oversized inputs,
capacity reuse, permanent cutoff, first-failure selection, concurrent/repeated
close, close errors, escaped diagnostics, and complete PCAP record boundaries
in the retained prefix. IPv4 and IPv6 loopbacks continue receiving topology
after forced capture overload and complete normal, stop, and cancellation
cleanup. Existing capture safety and partial-write regressions remain covered.

A controlled slow-writer test held the first payload write and offered 12,048
chunks of 4,096 bytes. Exactly 2,048 chunks were admitted, reaching 8,388,608
pending bytes including the active write. The additional 10,000 chunks did not
increase pending data. Releasing the writer drained all accepted bytes and
closed once. The same assertions passed on all three toolchains. This measures
logical pending data and admission behavior, not process RSS or disk throughput;
allocator and queue overhead are outside the byte metric.

The subprocess matrix exercised IPv4/IPv6, normal and protocol-failure exits,
SIGINT/SIGTERM, summary/full reports, automatic/explicit/omitted captures,
concurrent captures, and capture-path failures. Each platform produced 24
complete captures and 28 expected final topology reports. Budget-cutoff files
are intentionally incomplete captures; their accepted record prefixes are
checked separately by the new deterministic tests.

Offline tooling passed 444 Python tests, 314 mocked workflow checks, Python
3.9 syntax checks for 32 files, and Bash syntax checks for 12 scripts.
Documentation, export consistency, and Git whitespace checks passed. The public
export now contains 163 files, including the new capture-budget regression suite.

No vendor connections or lab operations were performed. Capture-file growth,
rotation, and filesystem-operation deadlines remain separate concerns. Hosted
CI and native AMD64 qualification remain publication gates.

## 2026-10-29 — Reserved capability octet formatter cleanup

The multiprotocol OPEN capability parser now uses an explicit `UInt8` read and
nil check for the reserved octet between AFI and SAFI. Its adjacent comment
explains RFC 4760 section 8: senders should use zero; receivers consume the
octet while ignoring its value, including nonzero values. Accepted inputs and
byte consumption are unchanged.

Local Apple Swift 6.3.3 validation passed 72 capability/handler tests in two
suites, including reserved values 0, 1, and 255, AFI/SAFI alignment, malformed
lengths, and capability negotiation. Whole-package configured strict formatting,
checkout/export documentation checks, and Git whitespace checks passed. The
refreshed public export retains 163 files and matches the checkout exactly.

The discarded binding responsible for the earlier Swift 6.2 diagnostic has
been removed. Earlier qualification logs remain historical evidence; this
small follow-up did not rerun Linux toolchains or operate any machines.

## 2026-10-30 — Isolated FRR quickstart attempt

The terminal-first quickstart was attempted from a disposable copy of the
reviewed 163-file public export, with no development Git history, local package
overrides, or retained build directory. The existing SwiftPM download cache
was available. The native macOS build passed with Apple Swift 6.3.3 and reported
CLI version `0.1.0`; all source files and `Package.resolved` remained unchanged.

The separately prepared host used OrbStack 2.2.5, Ubuntu 24.04.5 ARM64, Docker
29.9.2, Containerlab 0.81.1, and the unchanged pinned FRR and HAProxy images.
The unmodified FRR-only deployment command returned success, with all five
routers and the relay running. Before starting a collector, read-only checks
found that `edge-frr` had not applied its supplied configuration.

Its startup log recorded:

```text
/usr/lib/frr/frrcommon.sh: line 82: /usr/bin/vtysh: No such file or directory
```

The startup command exited `127`. Although the daemons subsequently reported
up, the running configuration lacked the supplied interfaces, IS-IS, and BGP
configuration, and the expected collector neighbor was absent. The other four
routers had applied their configurations. For every router, the exported source,
deployment copy, and captured `/etc/frr/frr.conf` matched byte-for-byte. This
records a configuration-application failure in this boot; the cause of the
failed executable invocation has not been established.

The rehearsal stopped before a BGP-LS collector or link flap started. No
configuration reload, router restart, or automatic retry was performed. The
failed boot and read-only evidence were retained; the separate original
deployment was unchanged.

The end-to-end quickstart gate remains open. Collection, link withdrawal and
restoration, signal shutdown, final-RIB output, automated capture verification,
and owned destruction were not exercised in this attempt. Earlier successful
qualification remains historical evidence, not a pass for this rehearsal.


## 2026-10-30: Native AMD64 package qualification

The frozen public candidate passed the complete `./scripts/test.sh` run and
explicit `BGPLSClient`, `BGPLSCLI`, and `bgpls` builds on native x86_64 Ubuntu
24.04.5 LTS with both Swift 6.2.4 and Swift 6.3.3. Each compiler used separate
fresh source, build, package-cache, configuration, and security directories,
with two build jobs and the existing resolved dependency graph. All 163 source
file hashes, including the lockfile, remained unchanged. No source repair or
host toolchain-selection change was required.

| Check | Swift 6.2.4 | Swift 6.3.3 |
| --- | --- | --- |
| Locked dependency resolution | Passed | Passed |
| Full Swift suite | 415 tests across 39 suites passed | Passed; detailed log retrieval remains pending |
| Explicit library, CLI, and executable builds | Passed | Passed |
| Source and dependency-pin preservation | Passed | Passed |

Both runs' successful command results and driver exit status were preserved
locally. Complete 6.2.4 logs are local; the detailed 6.3.3 logs remain retained
in the qualification environment. The two opt-in stress/external-capture cases
were skipped in the retrieved 6.2.4 log; ordinary retained-fixture, loopback,
shutdown, and PCAP coverage ran. This is native AMD64 package qualification,
not hosted CI execution or AMD64 vendor-lab qualification.

## 2026-10-30: Isolated patched-runtime rehearsal

A fresh macOS build of the public candidate passed with Apple Swift 6.3.3.
The native collector was exercised against a separate Ubuntu 24.04.5 ARM64
machine with 4 GiB RAM, two CPUs, Docker 29.9.2, and unchanged pinned FRR and
HAProxy images and router configurations.

This rehearsal used the development binary `0.82.0-vtysh-pr` for
[Containerlab PR #3555](https://github.com/srl-labs/containerlab/pull/3555).
Its source matches the reviewed patch subsequently committed as
`da31ef28da2ee4f55ec3b6618e4eace7f2c0e478`; it was built before that commit and
retains the embedded build identifier `ad0b2cc7-dirty`. It is not a released
Containerlab version. Only a private rehearsal copy accepted that exact version
and verified binary SHA-256; the public stable-version check is unchanged.
Deployment ran inside the isolated guest, with an SSH forward from macOS port
11792 to the guest's unchanged relay listener 11790, avoiding the preserved lab.

| Phase | Observed result |
| --- | --- |
| Fresh FRR startup | All six containers deployed; no `vtysh` executable-not-found failure |
| Routing and collection | IS-IS, both reflectors, and native/collector typed baseline reached exactly `5/14/10` |
| Documented ten-second flap | Both interfaces restored, but neither native FRR nor bgpls exposed the expected withdrawals during the flap |
| Longer flap observation | Both views reached `5/12/10`; a private harness wait was too short for the forty-second command, so this run did not pass end to end |
| Restoration check | After the interfaces were restored, native FRR retained two additional link forms; the corrected harness stopped at its bounded baseline check |
| Fresh collector corroboration | A new collector matched FRR at `5/16/10`, exited `130`, and produced one final RIB and a complete PCAP |

FRR 10.7.1 defaults its level-2 LSP generation interval to 30 seconds. The
absence of withdrawals during the short flap is consistent with a down/up
change being coalesced inside that interval; this is an inference from the
observations and [FRR's timer definition](https://github.com/FRRouting/frr/blob/frr-10.7.1/yang/frr-isisd.yang#L1348-L1356),
not a complete timer trace.

The two extra restored-link forms have IPv4-only local address descriptors
alongside the expected complete dual-stack forms. They remain in FRR's own
selected table and are advertised to a fresh bgpls process. The root cause is
not established. Exact restoration to `5/14/10` therefore remains **unpassed**;
no assertions were relaxed and no configuration reload or router restart was
used to repair the result. The first observations, harness failure, later native
and collector evidence, and this isolated boot were preserved. Both pre-existing
labs remain unchanged, and no automated collector remains connected.

The startup patch allowed collection to proceed, but this is not a successful
end-to-end quickstart qualification. Investigate the restoration discrepancy,
review the short-flap demonstration timing, and rehearse with a released
Containerlab containing the fix before closing the public-instructions gate.

## 2026-11-09: Swift 6.3 paired-producer live regression

The Swift 6.3 wire-constant change passed live verification with a native
macOS ARM64 debug collector built by Apple Swift 6.3.3. Testing reused the
existing FRR/cEOS deployment with private four-byte ASN `4200000001`,
OrbStack 2.2.5, Ubuntu 26.04.1 LTS ARM64, Docker 29.1.3, and Containerlab
0.81.1. Router images remained the pinned FRR `containerlab-10.7.1` and
cEOS ARM64 `4.36.2F` images. Sessions used IPv4 TCP while carrying both
IPv4 and IPv6 BGP-LS topology.

A VM reboot had removed the virtual links. Generated configuration and logs
were preserved before guarded reconciliation recreated five FRR containers,
restarted cEOS, and restored eleven links. The recorded topology/configuration
hashes and management-network identity were preserved.

The baseline run used `verify.sh --attributes`; the second added
`--attribute-probes --churn --reverse-shutdown` against the same deployment
and collector build.

| Check | Observed result |
| --- | --- |
| Baseline | Both producers independently reached `6 nodes / 18 links / 12 prefixes` |
| Link churn | Exactly two directed links withdrawn; the complete original 36-key topology restored |
| IPv6 prefix probes | Both producers observed add, withdrawal, re-add, and removal for each temporary prefix |
| Directional metric probes | FRR and cEOS metrics changed `10 → 20 → 10`; keys, reverse directions, and unrelated projections remained unchanged |
| Configuration restoration | Captured running configurations restored byte-for-byte |
| Typed verification | Wire/native/CLI comparisons and offline Swift public-library replay passed with no reported attribute issues |
| Shutdown | Baseline: FRR SIGINT `130`, cEOS SIGTERM `143`; churn run: cEOS SIGINT `130`, FRR SIGTERM `143` |

Both verifier runs published successful final results after cleanup. Captures
were retained, owned collectors stopped, and the verification lock released.
The lab containers and selected OrbStack machine were then stopped, restoring
their initial stopped state.

Retained results are identified by `verification-ceos-x2d6imet` (baseline) and
`verification-ceos-8tc_7zgy` (churn). Their provenance records bind both runs to
the tested source bytes and collector binary. The subsequent signed Swift 6.3
commit contains the same implementation; only six `CHANGE:` comment labels
were removed from the three constants files after live testing. The retained
hashes identify the tested version.

This existing-deployment regression does not qualify a fresh installation or
complete the default FRR-only quickstart. It does not change the October 30
startup and restoration failures or establish direct IPv6 TCP, a Linux
collector rebuild, or live snapshot-subscriber coverage for this change.
The stale-link behavior was not reproduced in this workload; the proposed
[FRR correction](https://github.com/FRRouting/frr/pull/24113) remains unmerged
as of 2026-11-09.

Separately, [Containerlab PR #3555](https://github.com/srl-labs/containerlab/pull/3555)
merged on November 1 and is included in the November 7
[0.83.0 release](https://github.com/srl-labs/containerlab/releases/tag/v0.83.0).
That released startup fix is available for the outstanding fresh FRR-only
rehearsal, which must observe withdrawals and exact restoration to `5/14/10`.


## 2026-11-15: Containerlab 0.83.0 fresh FRR-only rehearsal

A new isolated Ubuntu 24.04.5 ARM64 machine ran the documented Docker and
Containerlab setup payloads and one fresh default FRR-only deployment. The
source copy contained only the 163 reviewed public files, with fresh SwiftPM
build/configuration/security caches and automatic dependency resolution disabled.
No local package overrides or retained build products were used. The existing
machines and labs were not entered or changed.

| Check | Observed result |
| --- | --- |
| macOS collector | macOS 27.2.1, Apple Swift 6.4.2, ARM64; fresh `swift build --product bgpls` passed |
| Guest runtime | Ubuntu 24.04.5 ARM64, Docker Engine/CLI 29.9.3, official Containerlab 0.83.0 ARM64 Debian package |
| Installation integrity | Release checksum and GitHub asset digest matched; package version/architecture, installed version, and `dpkg --verify` passed |
| Rehearsal limits | 8 GiB memory, 4 CPUs, 64 GiB disk cap; measured environment, not a minimum-resource recommendation |
| Fresh deployment | Five FRR routers plus HAProxy; each router loaded configuration and reported all configured daemons up; no missing-vtysh failure, restart, or OOM kill |
| Manual baseline | Native FRR, typed WATCH replay, and full-key wire replay agreed on `5 nodes / 14 links / 10 prefixes` |
| Ten-second flap | Command completed and both interfaces returned UP; 158 native samples and the capture showed no topology withdrawal; final typed and full-key RIBs matched the baseline |
| Manual capture/shutdown | 50 PCAP records, two OPENs, 42 KEEPALIVEs, eight UPDATEs, zero NLRI withdrawals; one final RIB and SIGINT exit `130` |
| Subsequent bounded `--churn` verifier | Passed: two directed links withdrawn, exact original topology restored, temporary IPv6 prefix added/withdrawn/re-added/removed |
| Verifier capture/shutdown | 107 PCAP records, two OPENs, 92 KEEPALIVEs, 14 UPDATEs, four NLRI withdrawals; exact 29-key final topology, one final RIB, SIGINT exit `130` |
| Restoration | All five running configurations restored byte-for-byte; original BGP connection preserved within each collector run |
| Offline checks | 444 Python tests, 389 mocked workflow checks, 12 shell files, 12 documented shell blocks, and public documentation checks passed |
| Cleanup | Both owned collectors and the SSH tunnel stopped; temporary link/prefix changes restored; deployment and new guest retained |

Isolation used a selective host mount and an owned SSH forward from macOS
`127.0.0.1:21790` to the new guest's `127.0.0.1:11790`. The collector argument
and PCAP expected endpoint used that forwarded port; the public verifier's
assertions, router configurations, YAML, and image digests were unchanged. The
manual run added PCAP recording and read-only native sampling. No custom
Containerlab binary or development-version exception was used. The root-based
package installation emitted a non-root group-setup warning; installation and
all subsequent runtime checks passed.

The released startup fix and bounded churn are demonstrated by this fresh
run. The fixed ten-second flap is still not a reliable withdrawal/restoration
demonstration: equality of the initial and final state does not establish that
a withdrawal occurred between them. The strict combined rehearsal therefore
remains incomplete, and scoped destruction was deliberately not attempted so
the short-flap evidence and lab state could be retained. No repeated boot,
router configuration repair, relaxed count/key assertion, or FRR image change
was used. Earlier failure evidence remains intact.

This checkpoint covers the default FRR-only profile, ASN `65001`, IPv4 TCP,
and both topology address families. It does not qualify cEOS, direct IPv6 TCP,
Linux collector builds, a full Swift test rerun, or native AMD64. The source
and setup updates remain subject to review before staging or publication.

## 2026-11-20 packaged FRR quickstart

The Apple Silicon `0.1.0` preview archive supplied the native macOS collector
and matching FRR lab scripts. The rehearsal verified the archive and placed its
files in the draft formula's install layout outside a source checkout. A fresh
network-isolated Ubuntu ARM64 guest ran Docker 29.10.0, stock Containerlab
0.83.0, and the pinned FRR `containerlab-10.7.1` image. A dedicated SSH
forward connected Mac port `22790` to the new guest’s relay on `11790`.

| Check | Observed result |
| --- | --- |
| Baseline | One established IPv4 BGP session collected 5 nodes, 14 directed links, and 10 IPv4/IPv6 prefixes. |
| Link down | FRR withdrew p1 → p2 and p2 → p1. The collector retained exactly the other 27 topology objects (`5/12/10`). |
| Link up | Both original directions returned on the same session. The final 29 typed records matched the baseline. FRR's NLRI descriptors and the wire identities also matched. |
| Stop | SIGINT exited `130` and printed one final RIB with `5/14/10`. The complete capture contained 53 PCAP records and both link withdrawals. |
| Scoped teardown | The five router configurations matched their pre-churn snapshots. The packaged destroy script removed the six owned containers and their management network. The guest's original Docker networks remained and the relay listener was gone. |

This run qualifies the [operator exercise](../../Documentation/Lab/Operators/GettingStarted.md)
with a wait for both withdrawals before restoring the circuit. The fixed
ten-second flap remains a timing-dependent physical-link example. The live
run used the prepared package payload; it did not reinstall Homebrew, exercise
cEOS, or test IPv6 session transport.
