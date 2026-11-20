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

struct ISISPresentationTests {
    @Test
    func snapshotRetainsAllIdentityFormsAndMissingIdentities() throws {
        let systemID = try #require(ISISSystemID("0000.0000.0001"))
        let pseudonodeID = try #require(ISISPseudonodeID(systemID: systemID, pseudonodeID: 7))
        let routerID = IPv4Address(address: 0xc000_0201)
        let interfaceAddress = IPv4Address(address: 0xc000_0202)
        let identities: [BGPLSIGPRouterID?] = [
            .isisSystemID(systemID),
            .isisPseudonode(pseudonodeID),
            .ospfRouterID(routerID),
            .ospfv2Pseudonode(routerID: routerID, interfaceAddress: interfaceAddress),
            .ospfv3Pseudonode(routerID: routerID, interfaceID: 42),
            .opaque([0xaa, 0xbb, 0xcc]),
            nil,
        ]
        var rib = LSRIB()
        for (index, identity) in identities.enumerated() {
            let instance = UInt64(index)
            let node = nodeIdentity(identity)
            rib.apply(BGPLSRecord(nlri: .node(BGPLSNodeNLRI(protocolID: 2, identifier: instance, localNode: node))))
            rib.apply(BGPLSRecord(nlri: .link(link(local: node, remote: node, identifier: instance))))
            rib.apply(BGPLSRecord(nlri: .ipv4Prefix(try prefix(node: node, identifier: instance))))
        }

        let snapshot = rib.snapshot(at: Date(timeIntervalSince1970: 0))
        #expect(snapshot.nodeCount == identities.count)
        #expect(snapshot.nodes.count == snapshot.nodeCount)
        #expect(snapshot.links.count == snapshot.linkCount)
        #expect(snapshot.prefixes.count == snapshot.prefixCount)
        #expect(snapshot.linkCount == identities.count)
        #expect(snapshot.prefixCount == identities.count)
        for (index, identity) in identities.enumerated() {
            let node = try #require(snapshot.nodes.first { $0.identifier == UInt64(index) })
            let link = try #require(snapshot.links.first { $0.identifier == UInt64(index) })
            let prefix = try #require(snapshot.prefixes.first { $0.identifier == UInt64(index) })
            #expect(node.routerID == identity)
            #expect(link.localRouterID == identity)
            #expect(link.remoteRouterID == identity)
            #expect(prefix.nodeRouterID == identity)
            #expect(node.ipv4RouterID == identity?.ipv4RouterID)
            #expect(link.localIPv4RouterID == identity?.ipv4RouterID)
            #expect(link.remoteIPv4RouterID == identity?.ipv4RouterID)
            #expect(prefix.nodeIPv4RouterID == identity?.ipv4RouterID)
            #expect(link.localLinkIdentifier == 101)
            #expect(link.remoteLinkIdentifier == 202)
            #expect(node.protocolID == 2)
            #expect(link.protocolID == 2)
            #expect(prefix.protocolID == 2)
        }

        //  Codable must preserve opaque and non-IP identities instead of dropping them.
        let json = try snapshot.jsonUTF8String()
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        #expect(try decoder.decode(RIBSnapshot.self, from: Data(json.utf8)) == snapshot)
    }

    @Test
    func snapshotAndDumpOrderingDoNotDependOnInsertionOrder() throws {
        let systemID = try #require(ISISSystemID("0000.0000.0001"))
        let node = nodeIdentity(.isisSystemID(systemID))
        var nlris: [BGPLSNLRI] = []
        for protocolID: UInt8 in [1, 2] {
            for instance: UInt64 in [0, 1] {
                nlris.append(.node(BGPLSNodeNLRI(protocolID: protocolID, identifier: instance, localNode: node)))
                nlris.append(.link(link(local: node, remote: node, protocolID: protocolID, identifier: instance)))
                nlris.append(.ipv4Prefix(try prefix(node: node, protocolID: protocolID, identifier: instance)))
            }
        }
        var forward = LSRIB()
        var reverse = LSRIB()
        for nlri in nlris { forward.apply(BGPLSRecord(nlri: nlri)) }
        for nlri in nlris.reversed() { reverse.apply(BGPLSRecord(nlri: nlri)) }
        let date = Date(timeIntervalSince1970: 0)
        let snapshot = forward.snapshot(at: date)
        #expect(snapshot == reverse.snapshot(at: date))
        #expect(forward.dump() == reverse.dump())
        #expect(snapshot.nodes.count == 4)
        #expect(snapshot.links.count == 4)
        #expect(snapshot.prefixes.count == 4)
        #expect(Set(snapshot.nodes.map(\.ribKey)).count == 4)
        #expect(Set(snapshot.links.map(\.ribKey)).count == 4)
        #expect(Set(snapshot.prefixes.map(\.ribKey)).count == 4)
        #expect(snapshot.nodes.map(\.ribKey) == snapshot.nodes.map(\.ribKey).sorted())
        #expect(snapshot.links.map(\.ribKey) == snapshot.links.map(\.ribKey).sorted())
        #expect(snapshot.prefixes.map(\.ribKey) == snapshot.prefixes.map(\.ribKey).sorted())
    }

    @Test
    func isisWatchDumpAndWithdrawalPreserveSystemAndPseudonodeIDs() throws {
        let localID = try #require(ISISSystemID("0000.0000.0001"))
        let remoteSystemID = try #require(ISISSystemID("0000.0000.0002"))
        let remoteID = try #require(ISISPseudonodeID(systemID: remoteSystemID, pseudonodeID: 7))
        let local = nodeIdentity(.isisSystemID(localID))
        let remote = nodeIdentity(.isisPseudonode(remoteID))
        let node = BGPLSNLRI.node(BGPLSNodeNLRI(protocolID: 2, identifier: 0, localNode: local))
        let link = BGPLSNLRI.link(link(local: local, remote: remote))
        let prefix = BGPLSNLRI.ipv4Prefix(try prefix(node: remote))
        let expected: [(BGPLSNLRI, String)] = [
            (node, "node \(localID)"),
            (link, "link \(localID) id:101 → \(remoteID) id:202"),
            (prefix, "prefix 192.0.2.0/24 node \(remoteID)"),
        ]
        var rib = LSRIB()
        for (nlri, summary) in expected {
            rib.apply(BGPLSRecord(nlri: nlri))
            #expect(RIBDiff.upsert(BGPLSRecord(nlri: nlri)).watchLine == "WATCH upsert \(summary)")
            #expect(RIBDiff.withdraw(nlri).watchLine == "WATCH withdraw \(summary)")
            #expect(rib.dump().contains(summary))
        }
        #expect(!rib.dump().contains("?"))
        #expect(rib.dump(topic: "nodes") == "node \(localID) AS 65001")
        for (nlri, _) in expected { rib.withdraw(nlri) }
        #expect(rib.summaryLine == "nodes=0 links=0 prefixes=0")
    }

    @Test
    func missingIDsUseQuestionMarksButOpaqueIDsRemainVisible() {
        var rib = LSRIB()
        let missing = nodeIdentity(nil)
        let opaque = nodeIdentity(.opaque([0xde, 0xad]))
        let missingNode = BGPLSNLRI.node(BGPLSNodeNLRI(protocolID: 2, identifier: 0, localNode: missing))
        let opaqueNode = BGPLSNLRI.node(BGPLSNodeNLRI(protocolID: 2, identifier: 0, localNode: opaque))
        rib.apply(BGPLSRecord(nlri: missingNode))
        rib.apply(BGPLSRecord(nlri: opaqueNode))
        #expect(RIBDiff.upsert(BGPLSRecord(nlri: missingNode)).watchLine == "WATCH upsert node ?")
        #expect(
            RIBDiff.upsert(BGPLSRecord(nlri: opaqueNode)).watchLine
                == "WATCH upsert node \(BGPLSIGPRouterID.opaque([0xde, 0xad]))")
        #expect(rib.dump(topic: "nodes").contains("node ? AS 65001"))
        #expect(rib.nodeCount == 2)
    }

    @Test
    func syntheticOSPFTextAndIPv4SnapshotProjectionsRemainCompatible() throws {
        var rib = LSRIB()
        for fixture in [
            BGPUpdateParserTests.nodeUpdateHex,
            BGPUpdateParserTests.linkUpdateHex,
            BGPUpdateParserTests.prefixUpdateHex,
        ] {
            let update = try BGPUpdateParser.parse(HexFixture.buffer(fixture))
            try rib.apply(update: update)
        }
        #expect(
            rib.dump(topic: "nodes") == "node 192.0.2.1 AS 65001\nnode 192.0.2.2 AS 65001"
        )
        #expect(rib.dump(topic: "links") == "link 192.0.2.1 198.51.100.5 → 192.0.2.2 198.51.100.6")
        #expect(rib.dump(topic: "prefixes") == "prefix 198.51.100.0/30 node 192.0.2.1")
        let snapshot = rib.snapshot()
        #expect(snapshot.nodes.map { $0.ipv4RouterID?.formatted(.addressOnly) } == ["192.0.2.1", "192.0.2.2"])
        let link = try #require(snapshot.links.first)
        #expect(link.localIPv4RouterID?.formatted(.addressOnly) == "192.0.2.1")
        #expect(link.remoteIPv4RouterID?.formatted(.addressOnly) == "192.0.2.2")
        #expect(link.localInterface?.formatted(.addressOnly) == "198.51.100.5")
        #expect(link.remoteInterface?.formatted(.addressOnly) == "198.51.100.6")
        let prefix = try #require(snapshot.prefixes.first)
        #expect(prefix.nodeIPv4RouterID?.formatted(.addressOnly) == "192.0.2.1")
    }

    private func nodeIdentity(_ routerID: BGPLSIGPRouterID?) -> BGPLSNodeIdentity {
        var result = BGPLSNodeIdentity(autonomousSystem: AutonomousSystemNumber(65_001))
        result.igpRouterID = routerID
        return result
    }

    private func link(
        local: BGPLSNodeIdentity,
        remote: BGPLSNodeIdentity,
        protocolID: UInt8 = 2,
        identifier: UInt64 = 0
    ) -> BGPLSLinkNLRI {
        var result = BGPLSLinkNLRI(
            protocolID: protocolID,
            identifier: identifier,
            localNode: local,
            remoteNode: remote,
            linkDescriptors: [],
            localIPv4Interface: nil,
            remoteIPv4Neighbor: nil
        )
        result.localLinkIdentifier = 101
        result.remoteLinkIdentifier = 202
        return result
    }

    private func prefix(
        node: BGPLSNodeIdentity,
        protocolID: UInt8 = 2,
        identifier: UInt64 = 0
    ) throws -> BGPLSIPv4PrefixNLRI {
        let network = try #require(IPv4Network("192.0.2.0/24"))
        return BGPLSIPv4PrefixNLRI(
            protocolID: protocolID,
            identifier: identifier,
            localNode: node,
            network: network,
            prefixDescriptors: []
        )
    }
}
