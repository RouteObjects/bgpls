//===----------------------------------------------------------------------===//
//
// This source file is part of the bgpls project.
//
// Copyright (c) 2026 Craig A. Munro
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file for details.
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CIDR
import Foundation
import Testing

@testable import BGPLSClient

struct IPv6TopologyRIBTests {
    @Test
    func defaultRoutesKeepIndependentFamilyKeysAndWithdrawals() throws {
        let ipv4 = try IPv6TopologyFixture.parse(IPv6TopologyFixture.prefixWire([0], type: 3))
        let ipv6 = try IPv6TopologyFixture.prefix([0])
        guard case .ipv4Prefix(let prefix4) = ipv4 else {
            Issue.record("expected IPv4 default route")
            return
        }
        let key4 = LSRIB.prefixKey(prefix4)
        let key6 = LSRIB.prefixKey(ipv6)
        #expect(key4.hasPrefix("prefix:2:42:"))
        #expect(key6.hasPrefix("prefix6:2:42:"))
        #expect(key4 != key6)
        var rib = LSRIB()
        rib.apply(BGPLSRecord(nlri: ipv4))
        rib.apply(BGPLSRecord(nlri: .ipv6Prefix(ipv6)))
        #expect(rib.prefixCount == 2)
        #expect(rib.prefixes[key4]?.nlri == .v4(prefix4))
        #expect(rib.prefixes[key6]?.nlri == .v6(ipv6))
        #expect(rib.prefixes[key4]?.nlri.network == AnyIPNetwork("0.0.0.0/0"))
        #expect(rib.prefixes[key6]?.nlri.network == AnyIPNetwork("::/0"))
        rib.withdraw(ipv4)
        #expect(rib.prefixCount == 1)
        #expect(rib.prefixes[key6]?.nlri == .v6(ipv6))
        rib.withdraw(.ipv6Prefix(ipv6))
        #expect(rib.prefixCount == 0)
    }

    @Test
    func mixedFamilyUpdatesRefreshWithdrawAndPublishTypedDiffs() throws {
        let ipv4Wire = IPv6TopologyFixture.prefixWire([24, 192, 0, 2], type: 3)
        let ipv6Wire = IPv6TopologyFixture.prefixWire([64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0])
        let nodeWire = IPv6TopologyFixture.wire(type: 1, descriptors: [IPv6TopologyFixture.nodeDescriptor()])
        let linkWire = IPv6TopologyFixture.wire(
            type: 2,
            descriptors: [
                IPv6TopologyFixture.nodeDescriptor(), IPv6TopologyFixture.nodeDescriptor(257, lastByte: 2),
                BGPLSTLV(type: 261, value: try IPv6TopologyFixture.addressBytes("2001:db8::1")),
            ]
        )
        let update = try IPv6TopologyFixture.update(
            reachable: true, nlris: nodeWire + linkWire + ipv4Wire + ipv6Wire
        )
        var rib = LSRIB()
        let diffs = try rib.apply(update: update)
        #expect(rib.summaryLine == "nodes=1 links=1 prefixes=2")
        #expect(diffs.count == 4)
        #expect(diffs[2].watchLine == "WATCH upsert prefix 192.0.2.0/24 node 0000.0000.0001")
        #expect(diffs[3].watchLine == "WATCH upsert prefix 2001:db8::/64 node 0000.0000.0001")
        guard case .upsert(.prefix(let record)) = diffs[3], case .v6(let prefix6) = record.nlri else {
            Issue.record("IPv6 watch events must contain the typed prefix")
            return
        }
        #expect(rib.prefixes[LSRIB.prefixKey(prefix6)]?.nlri == .v6(prefix6))
        let refreshed = try rib.apply(update: update)
        #expect(refreshed == diffs)
        #expect(rib.prefixCount == 2)
        let withdrawn = try rib.apply(update: IPv6TopologyFixture.update(reachable: false, nlris: ipv6Wire))
        #expect(withdrawn == [.withdraw(.ipv6Prefix(prefix6))])
        #expect(withdrawn[0].watchLine == "WATCH withdraw prefix 2001:db8::/64 node 0000.0000.0001")
        #expect(rib.summaryLine == "nodes=1 links=1 prefixes=1")
        #expect(rib.dump(topic: "prefixes") == "prefix 192.0.2.0/24 node 0000.0000.0001")
        try rib.apply(update: IPv6TopologyFixture.update(reachable: true, nlris: ipv6Wire))
        #expect(rib.prefixCount == 2)
        let endOfRIB = try IPv6TopologyFixture.update(reachable: false, nlris: [])
        #expect(try rib.apply(update: endOfRIB).isEmpty)
        #expect(rib.prefixCount == 2)
        try rib.apply(update: IPv6TopologyFixture.update(reachable: false, nlris: ipv6Wire + ipv4Wire))
        #expect(rib.summaryLine == "nodes=1 links=1 prefixes=0")
    }

    @Test
    func ipv6KeysPreserveDomainTopologyUnknownDescriptorsAndMultiplicity() throws {
        let extra = BGPLSTLV(type: 60_001, value: [0xaa])
        let base = try IPv6TopologyFixture.prefix("2001:db8::/64", extra: [extra, extra])
        var variants = [base]
        var changed = base
        changed.protocolID = 1
        variants.append(changed)
        changed = base
        changed.identifier += 1
        variants.append(changed)
        changed = base
        changed.localNode.autonomousSystem = AutonomousSystemNumber(65_002)
        variants.append(changed)
        changed = base
        changed.localNode.ospfAreaID = OSPFAreaID(1)
        variants.append(changed)
        changed = base
        changed.localNode.igpRouterID = .isisSystemID(try #require(ISISSystemID("0000.0000.0002")))
        variants.append(changed)
        changed = base
        changed.prefixDescriptors.removeLast()
        variants.append(changed)
        changed = base
        changed.prefixDescriptors.append(BGPLSTLV(type: 60_001, value: [0xbb]))
        variants.append(changed)
        changed = base
        changed.prefixDescriptors.append(BGPLSTLV(type: 264, value: [1]))
        variants.append(changed)
        changed = base
        changed.prefixDescriptors.append(BGPLSTLV(type: 263, value: [0, 1]))
        variants.append(changed)

        var rib = LSRIB()
        for prefix in variants { rib.apply(BGPLSRecord(nlri: .ipv6Prefix(prefix))) }
        #expect(rib.prefixCount == variants.count)
        for lhsIndex in variants.indices {
            for rhsIndex in variants.indices where rhsIndex > lhsIndex {
                #expect(LSRIB.prefixKey(variants[lhsIndex]) != LSRIB.prefixKey(variants[rhsIndex]))
            }
        }
        var reordered = base
        reordered.prefixDescriptors.reverse()
        reordered.localNode.rawTLVs.reverse()
        #expect(LSRIB.prefixKey(reordered) == LSRIB.prefixKey(base))
        rib.withdraw(.ipv6Prefix(reordered))
        #expect(rib.prefixCount == variants.count - 1)
        #expect(rib.prefixes[LSRIB.prefixKey(base)] == nil)

        var reserved = changed
        reserved.prefixDescriptors[reserved.prefixDescriptors.count - 1] = BGPLSTLV(type: 263, value: [0xf0, 1])
        #expect(LSRIB.prefixKey(changed) == LSRIB.prefixKey(reserved))
        reserved.prefixDescriptors[reserved.prefixDescriptors.count - 1] = BGPLSTLV(type: 263, value: [0, 2])
        #expect(LSRIB.prefixKey(changed) != LSRIB.prefixKey(reserved))
    }

    @Test
    func typedIPv6MutationsOverrideStaleRawCopiesWithoutDroppingUnknownTLVs() throws {
        let unknown = BGPLSTLV(type: 60_001, value: [7])
        let parsed = try IPv6TopologyFixture.link([
            BGPLSTLV(type: 261, value: try IPv6TopologyFixture.addressBytes("2001:db8::1")),
            BGPLSTLV(type: 262, value: try IPv6TopologyFixture.addressBytes("2001:db8::2")), unknown,
        ])
        var mutated = parsed
        mutated.localIPv6Interface = nil
        let changedAddress = try #require(IPv6Address("2001:db8::3"))
        mutated.remoteIPv6Neighbor = changedAddress
        var clean = mutated
        clean.linkDescriptors = [unknown]
        #expect(LSRIB.linkKey(mutated) == LSRIB.linkKey(clean))
        #expect(LSRIB.linkKey(mutated) != LSRIB.linkKey(parsed))
        mutated.remoteIPv6Neighbor = nil
        clean.remoteIPv6Neighbor = nil
        #expect(LSRIB.linkKey(mutated) == LSRIB.linkKey(clean))
        var withoutUnknown = clean
        withoutUnknown.linkDescriptors = []
        #expect(LSRIB.linkKey(clean) != LSRIB.linkKey(withoutUnknown))

        var prefix = try IPv6TopologyFixture.prefix("2001:db8::/64", extra: [unknown])
        prefix.network = try #require(IPv6Network("2001:db8:1::abcd/64"))
        var canonical = prefix
        canonical.network = try #require(IPv6Network("2001:db8:1::/64"))
        canonical.prefixDescriptors = [unknown]
        #expect(LSRIB.prefixKey(prefix) == LSRIB.prefixKey(canonical))
        #expect(prefix.network.description == "2001:db8:1::/64")
    }

    @Test
    func dualStackPresentationAndSnapshotsKeepBothFamiliesInStableOrder() throws {
        let link = try dualStackLink()
        let ipv4 = try IPv6TopologyFixture.parse(IPv6TopologyFixture.prefixWire([24, 192, 0, 2], type: 3))
        let ipv6 = try IPv6TopologyFixture.prefix("2001:db8::/64")
        let nlris: [BGPLSNLRI] = [.link(link), ipv4, .ipv6Prefix(ipv6)]
        var forward = LSRIB()
        var reverse = LSRIB()
        for nlri in nlris { forward.apply(BGPLSRecord(nlri: nlri)) }
        for nlri in nlris.reversed() { reverse.apply(BGPLSRecord(nlri: nlri)) }
        let expectedLink = "link 0000.0000.0001 192.0.2.1,2001:db8::1 → 0000.0000.0002 192.0.2.2,2001:db8::2"
        #expect(forward.dump(topic: "links") == expectedLink)
        #expect(RIBDiff.upsert(BGPLSRecord(nlri: .link(link))).watchLine == "WATCH upsert \(expectedLink)")
        #expect(RIBDiff.withdraw(.link(link)).watchLine == "WATCH withdraw \(expectedLink)")
        #expect(forward.dump() == reverse.dump())
        let date = Date(timeIntervalSince1970: 0)
        let snapshot = forward.snapshot(at: date)
        #expect(snapshot == reverse.snapshot(at: date))
        #expect(snapshot.nodeCount == snapshot.nodes.count)
        #expect(snapshot.linkCount == snapshot.links.count)
        #expect(snapshot.prefixCount == snapshot.prefixes.count)
        #expect(snapshot.prefixCount == 2)
        #expect(snapshot.prefixes.map(\.ribKey) == snapshot.prefixes.map(\.ribKey).sorted())
        #expect(snapshot.prefixes.map(\.network.description).sorted() == ["192.0.2.0/24", "2001:db8::/64"])
        let snapshotLink = try #require(snapshot.links.first)
        #expect(snapshotLink.localInterface == link.localIPv4Interface)
        #expect(snapshotLink.remoteInterface == link.remoteIPv4Neighbor)
        #expect(snapshotLink.localIPv6Interface == link.localIPv6Interface)
        #expect(snapshotLink.remoteIPv6Interface == link.remoteIPv6Neighbor)
        #expect(snapshotLink.localIPv4RouterID == nil)
        let json = try snapshot.jsonUTF8String()
        let object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let encodedLinks = try #require(object["links"] as? [[String: Any]])
        #expect(encodedLinks.first?["localIPv6Interface"] as? String == "2001:db8::1/128")
        let encodedPrefixes = try #require(object["prefixes"] as? [[String: Any]])
        #expect(encodedPrefixes.compactMap { $0["network"] as? String }.contains("2001:db8::/64"))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(RIBSnapshot.self, from: Data(json.utf8))
        #expect(decoded == snapshot)
        let originalHash = snapshot.hashValue
        let decodedHash = decoded.hashValue
        #expect(originalHash == decodedHash)
        #expect(Set([snapshot]).contains(decoded))
        #expect([snapshot: "snapshot"][decoded] == "snapshot")
    }

    @Test
    func ipv6MissingNeighborAndIdentifierOnlyPresentationStayHonest() throws {
        let local = BGPLSTLV(type: 261, value: try IPv6TopologyFixture.addressBytes("2001:db8::1"))
        let partial = try IPv6TopologyFixture.link([local])
        #expect(
            RIBDiff.upsert(BGPLSRecord(nlri: .link(partial))).watchLine
                == "WATCH upsert link 0000.0000.0001 2001:db8::1 → 0000.0000.0002 ?"
        )
        let unnumbered = try IPv6TopologyFixture.link([
            BGPLSTLV(type: 258, value: [0, 0, 0, 7, 0, 0, 0, 9])
        ])
        #expect(
            RIBDiff.upsert(BGPLSRecord(nlri: .link(unnumbered))).watchLine
                == "WATCH upsert link 0000.0000.0001 id:7 → 0000.0000.0002 id:9"
        )
    }

    @Test
    func legacyIPv4SnapshotJSONDecodesAndReencodesWithoutNewFields() throws {
        //  An old snapshot contains CIDR strings and no IPv6 fields. Preserve that schema,
        // rather than only proving that the new encoder can decode its own output.
        let legacy = """
            {"capturedAt":"1970-01-01T00:00:00Z","nodeCount":0,"linkCount":1,"prefixCount":1,
            "nodes":[],"links":[{"ribKey":"legacy-link","protocolID":2,"identifier":42,
            "localInterface":"192.0.2.1/32","remoteInterface":"192.0.2.2/32"}],
            "prefixes":[{"ribKey":"legacy-prefix","protocolID":2,"identifier":42,"network":"192.0.2.0/24"}]}
            """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let snapshot = try decoder.decode(RIBSnapshot.self, from: Data(legacy.utf8))
        let prefix = try #require(snapshot.prefixes.first)
        #expect(prefix.network.isIPv4)
        #expect(prefix.network.description == "192.0.2.0/24")
        let link = try #require(snapshot.links.first)
        #expect(link.localIPv6Interface == nil)
        #expect(link.remoteIPv6Interface == nil)
        let encoded = try snapshot.jsonUTF8String()
        #expect(!encoded.contains("localIPv6Interface"))
        #expect(!encoded.contains("remoteIPv6Interface"))
        let originalJSON = try #require(JSONSerialization.jsonObject(with: Data(legacy.utf8)) as? NSDictionary)
        let encodedJSON = try #require(JSONSerialization.jsonObject(with: Data(encoded.utf8)) as? NSDictionary)
        #expect(originalJSON == encodedJSON)
    }

    @Test
    func ipv4PrefixKeyAndTextAreByteForByteCompatible() throws {
        let nlri = try IPv6TopologyFixture.parse(IPv6TopologyFixture.prefixWire([24, 192, 0, 2], type: 3))
        guard case .ipv4Prefix(let prefix) = nlri else {
            Issue.record("expected IPv4 prefix")
            return
        }
        #expect(
            LSRIB.prefixKey(prefix)
                == "prefix:2:42:local[512:4:0000fde9;515:6:000000000001;]:descriptors[265:4:18c00002;]"
        )
        #expect(
            RIBDiff.upsert(BGPLSRecord(nlri: nlri)).watchLine == "WATCH upsert prefix 192.0.2.0/24 node 0000.0000.0001")
        var rib = LSRIB()
        rib.apply(BGPLSRecord(nlri: nlri))
        #expect(rib.dump(topic: "prefixes") == "prefix 192.0.2.0/24 node 0000.0000.0001")
    }

    @Test
    func typedAndErasedPrefixEqualityHashingAndLookupsRemainFamilyAware() throws {
        let first = try IPv6TopologyFixture.prefix("2001:db8::/64")
        let equal = try IPv6TopologyFixture.prefix("2001:0db8:0000:0000::/64")
        let different = try IPv6TopologyFixture.prefix("2001:db8::/65")
        #expect(first == equal)
        #expect(first != different)
        let firstHash = first.hashValue
        let equalHash = equal.hashValue
        #expect(firstHash == equalHash)
        #expect(Set([first]).contains(equal))
        #expect(!Set([first]).contains(different))
        #expect([first: "prefix"][equal] == "prefix")
        let erased = AnyBGPLSPrefixNLRI.v6(first)
        let equalErased = AnyBGPLSPrefixNLRI.v6(equal)
        let differentErased = AnyBGPLSPrefixNLRI.v6(different)
        #expect(erased == equalErased)
        #expect(erased != differentErased)
        let erasedHash = erased.hashValue
        let equalErasedHash = equalErased.hashValue
        #expect(erasedHash == equalErasedHash)
        #expect(Set([erased]).contains(equalErased))
        #expect([erased: "erased"][equalErased] == "erased")
        #expect(erased.protocolID == first.protocolID)
        #expect(erased.identifier == first.identifier)
        #expect(erased.localNode == first.localNode)
        #expect(erased.network == .v6(first.network))
    }

    @Test(.timeLimit(.minutes(1)))
    func sessionStreamCarriesBothFamiliesAndFinishesAfterStop() async throws {
        let ipv4 = IPv6TopologyFixture.prefixWire([24, 192, 0, 2], type: 3)
        let ipv6 = IPv6TopologyFixture.prefixWire([64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0])
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: true)
        try await session.applyInboundUpdateForTesting(
            IPv6TopologyFixture.updateBody(reachable: true, nlris: ipv4 + ipv6))
        try await session.applyInboundUpdateForTesting(IPv6TopologyFixture.updateBody(reachable: false, nlris: ipv6))
        try await session.applyInboundUpdateForTesting(IPv6TopologyFixture.updateBody(reachable: true, nlris: ipv6))
        //  Await each actor operation and finish the stream before collecting; no scheduling sleeps.
        await session.stop()
        var events: [RIBDiff] = []
        for await event in changes { events.append(event) }
        #expect(events.count == 5)
        guard events.count == 5, case .snapshot(let catchUp) = events[0] else {
            Issue.record("expected catch-up followed by four typed prefix changes")
            return
        }
        #expect(catchUp.prefixCount == 0)
        #expect(events[1].watchLine == "WATCH upsert prefix 192.0.2.0/24 node 0000.0000.0001")
        #expect(events[2].watchLine == "WATCH upsert prefix 2001:db8::/64 node 0000.0000.0001")
        #expect(events[3].watchLine == "WATCH withdraw prefix 2001:db8::/64 node 0000.0000.0001")
        #expect(events[4] == events[2])
        let final = await session.ribSnapshot(at: Date(timeIntervalSince1970: 0))
        #expect(final.prefixCount == 2)
        #expect(final.prefixes.map(\.network.description).sorted() == ["192.0.2.0/24", "2001:db8::/64"])
    }

    private func dualStackLink() throws -> BGPLSLinkNLRI {
        try IPv6TopologyFixture.link([
            BGPLSTLV(type: 259, value: [192, 0, 2, 1]),
            BGPLSTLV(type: 260, value: [192, 0, 2, 2]),
            BGPLSTLV(type: 261, value: IPv6TopologyFixture.addressBytes("2001:db8::1")),
            BGPLSTLV(type: 262, value: IPv6TopologyFixture.addressBytes("2001:db8::2")),
        ])
    }
}
