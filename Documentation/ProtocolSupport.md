# Protocol support and limits

`BGPLSClient` implements a receive-only BGP-LS collection session using
[RFC 9552](https://www.rfc-editor.org/rfc/rfc9552.html). It is not a general BGP
routing implementation, IGP implementation, or claim of complete RFC conformance.

## Transport and OPEN negotiation

| Area | Implemented behavior |
| --- | --- |
| Connection | Outbound TCP with numeric peer endpoint; optional same-family local bind |
| Transport | IPv4 and unscoped IPv6 host addresses |
| Identity | Explicit, nonzero 32-bit `BGPIdentifier`, independent of transport |
| Multiprotocol capability | BGP-LS AFI 16388 / SAFI 71 required from the peer |
| ASN capability | Capability 65 advertised for both small and large local ASNs |
| ASN matching | Capability 65 is authoritative when present; otherwise use legacy My AS |
| Frame size | Standard BGP messages up to 4,096 bytes |
| Capture | Optional session PCAP output in a new file, closed after admitted work drains |

The legacy OPEN My AS field remains 16 bits: it carries the real ASN when
representable and AS_TRANS (`23456`) otherwise. Configured peer identity must
match the effective peer ASN exactly; naked AS_TRANS is not a wildcard.
Local/peer ASN zero and AS_TRANS are rejected as configured identities.
Other registry/allocation policy belongs to the caller.
See [RFC 6793](https://www.rfc-editor.org/rfc/rfc6793.html#section-4.1)
and [RFC 6286](https://www.rfc-editor.org/rfc/rfc6286.html).

The capability decoder validates nested lengths and exact optional-data
consumption. It accepts multiple capability parameters, unknown capability
codes, and identical duplicates. Conflicting AS4 values are rejected as a local
ambiguity policy. Extended OPEN optional-parameter encoding and optional
parameter types other than capabilities are unsupported.

DNS/service-name resolution, scoped or link-local IPv6 endpoints, IPv4-mapped
IPv6 transport, BGP-LS VPN SAFI 72, Extended Messages, and transport
authentication are outside this release's support.

The CLI enables PCAP output with either `--pcap FILE` for an explicit path or
`--pcap-auto` for a generated filename in the current working directory.
Omitting both disables capture; specifying both fails validation. Automatic
names follow `bgpls_yyyyMMdd_HHmmssZ_peer-ADDRESS_port-PORT_UUID.pcap` using a
UTC timestamp selected before connecting, Gregorian/POSIX formatting, a literal
`Z`, and a full lowercase, hyphenated UUID. The configured numeric peer address
has no prefix and uses hyphens in place of IPv6 colons. The endpoint can be a
relay rather than the topology producer. The CLI reports the escaped absolute
selected path before session creation; capture setup retains its separate
`writing PCAP` confirmation. The library's `pcapPath` API remains explicit.

PCAP output must name a new file in a trusted directory. Automatic naming does
not probe for available filenames, overwrite, or retry a collision. Existing
paths, including symbolic links and special files, are refused. The sink requests
owner-only `0600` permissions (subject to a more restrictive umask) and writes
only through the exclusively created descriptor. Ordinary parent-directory
symlinks are supported; ancestor directories must still be trusted. Creation
or initial header-write failure stops setup before connecting. Later capture
errors are logged without changing the session outcome, so successful
collection does not prove that the capture is complete. See
[capture-file safety](../SECURITY.md#capture-file-safety).

## Topology and typed attributes

The RIB models Node, Link, IPv4 Prefix, and IPv6 Prefix NLRIs. Node identities
retain protocol-specific IS-IS System-ID/pseudonode and OSPF router-ID/pseudonode
forms. IPv4 and IPv6 link endpoint descriptors can coexist on one link.
Reachability uses canonical `IPNetwork<Family>`; retained descriptor bytes
preserve the original observation.

| Typed attribute | TLV | Interpretation |
| --- | ---: | --- |
| Node name | 1026 | Optional ASCII, at most 255 octets; no trimming or normalization |
| Link IGP metric | 1095 | One, two, or three octets; reserved high bits in one-octet form ignored |
| Prefix metric | 1155 | Four-octet unsigned value |
| Maximum link bandwidth | 1089 | Finite, nonnegative binary32 bytes per second |
| Maximum reservable bandwidth | 1090 | Same bandwidth representation |
| Unreserved bandwidth | 1091 | Exactly eight bandwidth values, in priority order 0–7 |

Bandwidth exposes a `Double` bits-per-second projection. Zero, negative zero,
and oversubscription are accepted advertisements, not measurements of
utilization. Original binary32 bytes remain in observation evidence. Missing
values remain optional; they are never silently replaced with zero.
See [RFC 9552 section 5.3](https://www.rfc-editor.org/rfc/rfc9552.html#section-5.3)
and [RFC 5305](https://www.rfc-editor.org/rfc/rfc5305.html#section-3.4).

Unknown NLRIs remain observable without entering supported-object dictionaries.
Unknown TLVs, original type-29 values and flags, ordering, and diagnostic
coordinates remain available. AS_PATH, AS4_PATH, AGGREGATOR, and related
compatibility attributes remain raw evidence: this milestone does not
reconstruct paths, select routes, or compute traffic-engineering paths.

Other traffic-engineering projections, SRLGs, administrative groups, and
additional attribute families remain future work.

## UPDATE recovery

The strict `LSRIB.apply(update:)` API and live recovery share preparation and
commit behavior. All applicable NLRI fields are prepared before mutation, with
reachability committed before withdrawals. Attribute decoding happens once.
Strict application throws before mutation on rejected content or unavailable
projections; harmless warnings are allowed.

Live sessions and `applyIsolating` use these rules:

| Condition | Result |
| --- | --- |
| Complete outer NLRI with unusable content | Discard that NLRI; retain accepted siblings |
| Truncated outer NLRI header or length beyond the enclosing field | Fatal UPDATE; no mutation from any part of it |
| Duplicate MP_REACH or MP_UNREACH | Reject the UPDATE and terminate with scoped NOTIFICATION |
| Broken framing inside type-29 attribute | Discard its entire interpretation; retain valid topology |
| Bounded unusable recognized attribute value | Omit the affected projection; retain valid siblings |
| Invalid member of unreserved bandwidth | Omit the whole eight-priority projection |
| Unknown, unordered, or wrong-context TLV | Preserve evidence; do not reject for its presence |
| Duplicate outer type-29 attributes | Interpret the first; retain and diagnose excluded occurrences |
| Identical duplicate supported singleton TLV | Expose one value with a warning |
| Conflicting duplicate supported singleton TLV | Make that projection unavailable |
| Empty type-29 value or invalid Optional/Transitive flags | Discard the entire interpretation |

The first type-29 occurrence remains authoritative even if unusable; a later
occurrence is not a fallback. Every accepted advertisement replaces the
previous attribute observation completely. Withdrawal identity does not depend
on advertised attributes.

Duplicate MP detection follows complete outer path-attribute framing and
precedes inner MP decoding. The first repeated type in wire order is rejected,
even when values or address families differ. One reach plus one unreach is
valid. Incomplete outer framing retains its fatal behavior.

Diagnostics distinguish malformed encoding from invalid content. Widths,
truncation, impossible prefix lengths, invalid Router-ID byte counts, and
duplicate Node Descriptor sub-TLVs are malformed encoding. Missing identity or
reachability descriptors, ambiguous repeated singleton descriptors, and a
zero IS-IS pseudonode value are invalid content. Node Descriptor sub-TLV
uniqueness is specifically required by
[RFC 9552 section 8.2.2](https://www.rfc-editor.org/rfc/rfc9552.html#section-8.2.2);
these categories are collector diagnostics, not comprehensive conformance verdicts.

Link-local IPv4/IPv6 topology endpoint descriptors and nonzero unused prefix
padding bits are accepted with warnings and raw evidence retained. Padding is
canonicalized for network identity. These warnings concern topology descriptors,
not legitimate IGP next hops; tolerant collection does not make the encoding
conformant.

Stderr reports at most eight detail entries per UPDATE across NLRI and
attribute diagnostics, followed by an omitted-count summary when needed.
Structured results retain all diagnostics. Raw hexadecimal is opt-in.
Attribute coordinates do not invent NLRI indexes.

**Discarded NLRIs cause no RIB mutation. A rejected withdrawal or replacement
advertisement can therefore leave previously accepted information stale; the
diagnostic identifies the collection gap.** No partial withdrawal key is
derived. There is no automatic stale marking, reconciliation, or recovery
journal. These rules distinguish RFC attribute-framing discard from local
interpretation policy; they do not claim general
[RFC 7606](https://www.rfc-editor.org/rfc/rfc7606.html) fault-management support.

## Timers and terminal outcomes

After TCP establishment, a 240-second startup hold deadline bounds the wait
for an acceptable OPEN, even if the local hold offer is zero. The offered hold
time defaults to 90 seconds; local values and peer offers of 1 or 2 are rejected.

After validated OPEN negotiation, the smaller hold offer applies. Zero disables
negotiated hold expiry and periodic KEEPALIVEs; the initial handshake KEEPALIVE
is still sent. Nonzero KEEPALIVE cadence is the whole-second negotiated hold
time divided by three.

The confirming KEEPALIVE refreshes the deadline before the Established state
callback. Established KEEPALIVEs and successfully prepared UPDATEs, including
recoverable rejection, refresh it. Partial frames, ignored duplicate OPENs,
fatal UPDATEs, and outbound traffic do not. Lazy deadline checks avoid
per-message timer cancellation and rescheduling.

| Locally detected condition | Attempted NOTIFICATION |
| --- | --- |
| Duplicate MP_REACH / MP_UNREACH | UPDATE Message Error, 3/1, empty Data |
| Hold timer expired | 4/0, empty Data |
| Unacceptable peer hold time | OPEN Message Error, 2/6 |
| Missing required BGP-LS capability | OPEN Message Error, 2/7, required capability data |

Only these outbound mappings are implemented. General OPEN/FSM error responses
are not comprehensive. The FSM latches the original error and disarms timers
before attempting one NOTIFICATION. It waits for completion, failure,
disconnection, or a one-second write deadline before publishing that outcome.
Delivery is attempted, not guaranteed after disconnect or explicit cancellation.

Normal closure after establishment succeeds; premature closure and session
failures throw after cleanup. Earlier admitted work drains and captures and
subscriber streams finish. The retained RIB is the last accepted observation,
not proof of current topology after disconnect.

## Qualification boundaries

Retained captures and synthetic tests cover parsing, identity, attributes,
atomicity, negotiation, timers, backpressure, and lifecycle behavior. Historical
ARM64 FRR/cEOS lab qualification includes IPv4/IPv6 transport and topology,
four-byte ASNs, attribute probes, churn, restoration, and independent shutdown.
See the [qualification record](../lab-examples/bgpls/VALIDATION.md) for evidence
and which checks were refreshed for this candidate.

The reference lab's live IGP is IS-IS. Decoder support and synthetic OSPF tests
do not constitute a fresh OSPF/OSPFv3 vendor-lab qualification. BGP-LS through a
route reflector and native AMD64 vendor-lab qualification remain separate;
the lab's route-reflector sessions carry IPv4 unicast, while collectors connect
to the BGP-LS producers independently.
