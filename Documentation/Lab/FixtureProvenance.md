# Captured-fixture provenance

The four capture suites listed below retain genuine vendor-generated BGP bytes
from isolated reference labs. They exercise decoding without routers, container
images, packet-capture resources, or network access. Synthetic parser/codec
fixtures elsewhere in the suite are distinct from these retained captures.

The OSPF UPDATE bodies in `BGPUpdateParserTests` and the duplicated two-node
body in `ForegroundSessionLoopbackTests` are synthetic fixtures, not captured
vendor evidence. They use documentation addresses: Router-IDs `192.0.2.1` and
`192.0.2.2`, next hop `192.0.2.254`, link endpoints `198.51.100.5` and
`198.51.100.6`, and reachability `198.51.100.0/30`. They retain four-octet OSPF
Router-ID descriptors, ASN 65001, area zero, node ordering, metrics, and framing
for parser, presentation, RIB, and lifecycle regression coverage. Their bodies
are 149 bytes (link), 127 bytes (two nodes), and 92 bytes (prefix). They must not
be cited as evidence of live OSPF interoperability. The genuine FRR/cEOS fixture
bytes and hashes below are unaffected.

## Capture and preservation boundary

The lab routers ran natively on ARM64 Linux in OrbStack. Native macOS collectors
connected through the IPv4 TCP relay. The dual-stack fixtures prove **IPv6
topology** decoding over an IPv4 session; they are not IPv6 TCP captures.
The older captures predate the current Containerlab-packaged FRR image and do
not qualify that image's startup integration.

Source captures were written by SwiftNIO's `NIOWritePCAPHandler` from the
application byte stream, using synthetic packet framing. They are not independent
physical-interface captures. The retained bodies/messages were checked against
complete captured streams. In particular, long messages were extracted from the
capture rather than reconstructed from the CLI's truncated hexadecimal display.
No selected body or message was re-encoded or edited to sanitize its fields.

Names, addresses, ASNs, and System IDs in these suites belong to the generated
reference topologies. They are not production-network data or credentials. Full
PCAPs, timestamps, transport metadata, vendor archives, and deployment state are
not package resources. Fixtures retain raw path attributes and unknown evidence;
the typed projections do not rewrite those bytes.

The first two suites embed **UPDATE bodies**, without the 19-byte BGP header.
The dual-stack suites embed **complete BGP messages**, including marker, length,
and type. The SHA-256 inventory below hashes the decoded hexadecimal bytes, not
the Swift source text. Preserve these bytes and paths when editing tests.

FRR's missing optional ASN descriptor is retained as received. Session ASN
65001 must not be invented as topology metadata; the CLI reports
`AS not-advertised`. cEOS includes the optional descriptor in its captured nodes.
Tests cover those vendor differences explicitly.

## FRR IPv4 UPDATE bodies

[FRRCapturedUpdateTests.swift](../../Tests/BGPLSClientTests/FRRCapturedUpdateTests.swift)

Two-router FRR 10.7.1 / IS-IS Level 2 experiment; two nodes, two directed links, three prefixes.

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| `edgeNode` | 86 | `bb97ddc5d5db5dc4cbe16e6d2d4fcb0fcd7857a8885bb3a020145c029c8abb99` |
| `coreNode` | 86 | `468be631af17530337bae287e7fdaddebb477d7432cae0fee186241dddd78092` |
| `prefixes` | 152 | `ba97682816236c596f202030223aef755d94bc2f1d6ca89d058a8d0dd9a5e255` |
| `links` | 207 | `9eb7b37d27023b99cf9526581856428f9c7573532d22f813a2f809cefaee0b0f` |
| `endOfRIB` | 10 | `53fd9cea9e96d52ff7aaf102ab366f7f4843472502211f4dd7f8a5996118a133` |
| `withdrawEdgeLink` | 68 | `268f13d2768001de006d173cb597ebc324fd2e97bfe1228899a55c4122b7f225` |
| `withdrawCoreLink` | 68 | `2f2205cd27fa9e34160bdebefdec67b11169e3b91a5b2397de1521b91e09440c` |

## cEOS IPv4 UPDATE bodies

[CEOSCapturedUpdateTests.swift](../../Tests/BGPLSClientTests/CEOSCapturedUpdateTests.swift)

Six-router FRR/cEOS 4.36.2F profile; IPv4-only prefix baseline. The selected subset includes six nodes, four directed links, six prefixes, and a withdrawal.

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| `edgeNode` | 110 | `1232d44452ab7f65226ed4e98d2b9e7488b529a71f4c7aa04c713c87a220afbd` |
| `rr1Node` | 104 | `9b49b5ce9f4b3c4b1afc2dcc287d1e4fc85537d44f2409d76756151d9e3dba5f` |
| `rr2Node` | 104 | `cf3e70431df57d2371e2019cc587901e67c6b766e51e7e5396fd9cc93efde01b` |
| `p1Node` | 103 | `61b353fbc45d3c29a02c315db4ed3464dc71369b6a90c57ca3b9d2ed4bc725ee` |
| `p2Node` | 103 | `8293661ba8e0cee32f23887212c05c1c2b8d09b37b548bf1826c411cc2f5ad9a` |
| `frrNode` | 109 | `ac16fb4d9c8d13a59e1601adeac8d31b15a4f5d2a70bffc91240433978ca8b76` |
| `edgeToP1` | 198 | `a68e3706c75b07a9468d7391704b5e2e22bf85fe6145fc5391f78839b33b8cda` |
| `p1ToEdge` | 198 | `92023420f11f09bfaaa34d6055dece7c471473bf9499f72414e83f26800180c8` |
| `p1ToP2` | 198 | `34d5a697653f4777aedeaa09760e0eace710815c6ffc1c06a54498bda0f778cf` |
| `p2ToP1` | 198 | `adfc4a5687db875ea58ed0e61f1c80991507eee87b935cb81c708ae45e24136c` |
| `prefixes` | 359 | `2cf8fd5b3067ec431983b29635000c100602ecc4b0ffad16eec6875f606aaedf` |
| `withdrawCoreLinks` | 189 | `ca77564eacbd603f00cdcc39a5f839dcf283bb3c84238535eed5e4f22cd911bd` |

## FRR dual-stack complete BGP messages

[FRRDualStackCapturedUpdateTests.swift](../../Tests/BGPLSClientTests/FRRDualStackCapturedUpdateTests.swift)

Five-router FRR 10.7.1 profile; mixed-family baseline, link churn, End-of-RIB, and IPv6 prefix probes.

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| `advertiseProbe` | 111 | `c3453833fa6aa3d886ab920920b49a2b013c5bdfdfde3be88ee459d99c5bec6a` |
| `withdrawProbe` | 78 | `c18121a0bef5177a9df8fe5fe364edc122aa1d429fe0ee1595136b91981dc84e` |
| `prefixes` | 483 | `257fccd178f3e12a50d6e7730bee28a807f8baeff623e882fd0346033d8a0ad4` |
| `links` | 1470 | `b81915f0675d831e51ca5fc79c831ad1996b4820a252029e3b9da85fc6fac438` |
| `endOfRIB` | 29 | `e55f7b636bb225c7cb9126bdddd4c968cbb5b2798759dbd8f0d3857d3ce362da` |
| `withdrawCoreLink` | 224 | `95688475618d049ed487aa4c4bc2128877cb7b743dab87e2a1616a6d8b6d55ab` |
| `restoreCoreLink` | 306 | `bebf9c466bbfbc2b077ad0f749e9407937085dc1c67f7946a6cac7f4fc2f8714` |

## cEOS dual-stack complete BGP messages

[CEOSDualStackCapturedUpdateTests.swift](../../Tests/BGPLSClientTests/CEOSDualStackCapturedUpdateTests.swift)

Six-router profile exported by cEOS 4.36.2F; twelve mixed-family prefixes, selected links/withdrawals, and independent IPv6 prefix probes.

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| `prefixes` | 762 | `1f12c900df9301ccf0cefb2f02bd54f6ee78e92f3d00b559645d567536887b12` |
| `edgeToP1` | 277 | `7b1047f56d1ac71aed71e9b14d438083dedc1af6231b3ea52b42420cfde1243a` |
| `p1ToEdge` | 277 | `32e93354d5ddca41e9446957d6c42c3ca11b6de42d17fada5538123945828dad` |
| `p1ToP2` | 257 | `caf5b9f0591e717f33ba97f5f7ef25fdd3ea8641e963bde803d2d23deb4888d6` |
| `p2ToP1` | 257 | `820827be6b67e69c4f3d1ec51275d37000cde402ee0a073b01a7333a4878ce32` |
| `withdrawCoreLinks` | 288 | `7901e77c20ea8e19482d920bbfa3ae2b7b72886811c83a913a49faeb9a09a54f` |
| `advertiseFRRProbe` | 130 | `0c02dadad5be8e7ebc9817f78b48f8014d52b34c67c5c6cff878a1e0b5559a84` |
| `withdrawFRRProbe` | 94 | `7f1ac20082b6d10a0f9964abe7d0bdd5c757a266a8e4e3b35e7e2ba191709472` |
| `advertiseCEOSProbe` | 130 | `72b2c62a1c68c5f7cb8b36d691842b9e0bf56c9e1f3956faaf06af4abb151db3` |
| `withdrawCEOSProbe` | 94 | `3e140383675c0fb409c316dfb24fc10ebf3509dd7c9b3127034c568faa2f57f7` |

## Replaying the evidence

From the repository root, run the retained-capture suites:

```sh
swift test --filter CapturedUpdateTests
```

The package's full test script also runs these suites. Lab Python audits compare
complete wire messages with native-router expectations and Swift replay; see the
[typed-attribute workflow](../../lab-examples/bgpls/ATTRIBUTES.md). An accepted
fixture is evidence for that message, not comprehensive conformance, startup
reliability, throughput, or long-duration qualification.
