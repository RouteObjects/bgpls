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

import BGPLSClient
import CIDR
import Testing

struct LSRIBTests {
    @Test
    func emptyRIBSummary() {
        #expect(LSRIB().summaryLine == "nodes=0 links=0 prefixes=0")
    }

    @Test
    func applyLinkAndPrefixFromSyntheticFixtures() throws {
        var rib = LSRIB()
        let linkUpdate = try BGPUpdateParser.parse(
            HexFixture.buffer(BGPUpdateParserTests.linkUpdateHex)
        )
        try rib.apply(update: linkUpdate)
        #expect(rib.linkCount == 1)
        #expect(rib.summaryLine.contains("links=1"))

        let prefixUpdate = try BGPUpdateParser.parse(
            HexFixture.buffer(BGPUpdateParserTests.prefixUpdateHex)
        )
        try rib.apply(update: prefixUpdate)
        #expect(rib.prefixCount == 1)
        #expect(rib.dump(topic: "prefixes").contains("198.51.100.0/30"))

        let nodeUpdate = try BGPUpdateParser.parse(
            HexFixture.buffer(BGPUpdateParserTests.nodeUpdateHex)
        )
        try rib.apply(update: nodeUpdate)
        #expect(rib.nodeCount == 2)
    }

    @Test
    func withdrawRemovesLink() throws {
        var rib = LSRIB()
        let linkUpdate = try BGPUpdateParser.parse(
            HexFixture.buffer(BGPUpdateParserTests.linkUpdateHex)
        )
        try rib.apply(update: linkUpdate)
        #expect(rib.linkCount == 1)

        // Withdraw using same NLRI set via synthetic unreach is heavier; withdraw parsed NLRI directly.
        let reach = try #require(linkUpdate.mpReach)
        let nlris = try BGPLSNLRIParser.parseAll(reach.nlri)
        for nlri in nlris {
            rib.withdraw(nlri)
        }
        #expect(rib.linkCount == 0)
    }

    @Test
    func instanceIDSegregatesOtherwiseIdenticalNodes() {
        var rib = LSRIB()
        let baseIdentity = BGPLSNodeIdentity(
            autonomousSystem: AutonomousSystemNumber(65_001),
            ipv4RouterID: IPv4Address(address: 0xC000_0201)
        )
        let instance0 = BGPLSNodeNLRI(protocolID: 3, identifier: 0, localNode: baseIdentity)
        let instance1 = BGPLSNodeNLRI(protocolID: 3, identifier: 1, localNode: baseIdentity)
        rib.apply(BGPLSRecord(nlri: .node(instance0)))
        rib.apply(BGPLSRecord(nlri: .node(instance1)))
        #expect(rib.nodeCount == 2)
        // Deprecated TLV 513 must not affect keys: same Instance-ID collapses.
        var with513 = baseIdentity
        with513.bgpLSIdentifier = 99
        rib.apply(BGPLSRecord(nlri: .node(BGPLSNodeNLRI(protocolID: 3, identifier: 0, localNode: with513))))
        #expect(rib.nodeCount == 2)
    }

    @Test
    func snapshotJSONContainsSyntheticPrefix() throws {
        var rib = LSRIB()
        try rib.apply(
            update: BGPUpdateParser.parse(HexFixture.buffer(BGPUpdateParserTests.prefixUpdateHex))
        )
        let snapshot = rib.snapshot()
        #expect(snapshot.prefixCount == 1)
        #expect(snapshot.prefixes.contains { $0.network.description == "198.51.100.0/30" })
        #expect(
            snapshot.prefixes.contains {
                $0.nodeIPv4RouterID?.formatted(.addressOnly) == "192.0.2.1"
            }
        )
        let json = try snapshot.jsonUTF8String()
        #expect(json.contains("198.51.100.0"))
        #expect(json.contains("192.0.2.1"))
    }
}
