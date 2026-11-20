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
import NIOCore
import Testing

/// Complete, unmodified cEOS ARM64 4.36.2F UPDATE bodies from the six-router lab.
/// See Documentation/Lab/FixtureProvenance.md for capture scope and hashes.
struct CEOSCapturedUpdateTests {
    @Test(arguments: Fixture.allCases)
    func completeCapturedBodiesParse(fixture: Fixture) throws {
        let bytes = try Self.bytes(fixture.hex)
        #expect(bytes.count == fixture.byteCount)
        let update = try BGPUpdateParser.parse(ByteBuffer(bytes: bytes))
        #expect(update.withdrawnRoutes.readableBytes == 0)
        #expect(update.nlri.readableBytes == 0)
        if fixture == .withdrawCoreLinks {
            let unreach = try #require(update.mpUnreach)
            #expect(unreach.isBGPLS)
            #expect(!unreach.isEndOfRIB)
            #expect(update.mpReach == nil)
            #expect(update.pathAttributes.map(\.typeCode) == [15])
            #expect(try BGPLSNLRIParser.parseAll(unreach.withdrawnNLRI).count == 2)
        } else {
            let reach = try #require(update.mpReach)
            #expect(reach.isBGPLS)
            #expect(update.mpUnreach == nil)
            #expect(Array(reach.nextHop.readableBytesView) == [10, 254, 254, 2])
            #expect(update.pathAttributes.map(\.typeCode) == [1, 2, 5, 14, 29])
            let expectedCount = fixture == .prefixes ? 6 : 1
            #expect(try BGPLSNLRIParser.parseAll(reach.nlri).count == expectedCount)
        }
    }

    @Test
    func nodeAdvertisementsKeepASAndLegacyIdentifierWithoutChangingSystemIdentity() throws {
        for (fixture, lastByte) in Self.nodeFixtures {
            let update = try Self.parse(fixture)
            let reach = try #require(update.mpReach)
            let nlris = try BGPLSNLRIParser.parseAll(reach.nlri)
            guard case .node(let node) = try #require(nlris.first) else {
                Issue.record("expected captured node NLRI")
                return
            }
            let systemIDText = "0000.0000.000\(lastByte)"
            #expect(node.protocolID == BGPLSProtocolID.isisLevel2.rawValue)
            #expect(node.identifier == 0)
            try Self.expectIdentity(node.localNode, lastByte: lastByte)
            #expect(node.additionalDescriptors.isEmpty)
            var rib = LSRIB()
            try rib.apply(update: update)
            let identity = "node \(systemIDText) AS 65001"
            let record = try #require(rib.nodes.values.first)
            for showAttributes in [false, true] {
                let nodeLine = identity + (showAttributes ? " \(BGPLSRecord.node(record).attributeSummary)" : "")
                #expect(rib.dump(topic: "nodes", showAttributes: showAttributes) == nodeLine)
                #expect(rib.dump(showAttributes: showAttributes) == "nodes=1 links=0 prefixes=0\n" + nodeLine)
            }
            //  cEOS includes AS and deprecated TLV 513; only the AS contributes to the RIB key.
            #expect(
                Array(rib.nodes.keys)
                    == ["node:2:0:local[512:4:0000fde9;515:6:00000000000\(lastByte);]:additional[]"])
        }
    }

    @Test
    func numberedLinksAndLoopbackPrefixesKeepTypedOwners() throws {
        let rib = try Self.baseline()
        //  This fixture subset retains all nodes/prefixes but only four directed links.
        #expect(rib.summaryLine == "nodes=6 links=4 prefixes=6")
        for (local, remote, localAddress, remoteAddress) in [
            (UInt8(6), UInt8(3), "10.254.0.15", "10.254.0.14"),
            (UInt8(3), UInt8(6), "10.254.0.14", "10.254.0.15"),
            (UInt8(3), UInt8(4), "10.254.0.8", "10.254.0.9"),
            (UInt8(4), UInt8(3), "10.254.0.9", "10.254.0.8"),
        ] {
            let link = try #require(
                rib.links.values.map(\.nlri).first {
                    $0.localIPv4Interface == IPv4Address(localAddress)
                        && $0.remoteIPv4Neighbor == IPv4Address(remoteAddress)
                })
            #expect(link.protocolID == BGPLSProtocolID.isisLevel2.rawValue)
            #expect(link.identifier == 0)
            try Self.expectIdentity(link.localNode, lastByte: local)
            try Self.expectIdentity(link.remoteNode, lastByte: remote)
            #expect(link.localLinkIdentifier == nil)
            #expect(link.remoteLinkIdentifier == nil)
            #expect(link.linkDescriptors.map(\.type) == [259, 260])
        }
        for lastByte in UInt8(1)...6 {
            let network = "10.255.0.\(lastByte)/32"
            let stored = try #require(rib.prefixes.values.map(\.nlri).first { $0.network.description == network })
            guard case .v4(let prefix) = stored else {
                Issue.record("existing cEOS capture must retain its IPv4 prefix family")
                continue
            }
            #expect(prefix.protocolID == BGPLSProtocolID.isisLevel2.rawValue)
            #expect(prefix.identifier == 0)
            try Self.expectIdentity(prefix.localNode, lastByte: lastByte)
            #expect(prefix.prefixDescriptors.map(\.type) == [265])
            #expect(prefix.network.description == network)
        }
        #expect(!rib.dump(topic: "links").contains("?"))
        #expect(!rib.dump(topic: "prefixes").contains("?"))
    }

    @Test
    func typedLinkStateAttributesRetainTheirOriginalBytes() throws {
        let expectedValues: [(Fixture, String)] = [
            (
                .edgeNode,
                "04 00 00 01 00 04 03 00 03 49 00 01 04 02 00 09 65 64 67 65 2d 63 65 6f 73 04 04 00 04 0a ff 00 06"
            ),
            (.p1Node, "04 00 00 01 00 04 03 00 03 49 00 01 04 02 00 02 70 31 04 04 00 04 0a ff 00 03"),
            (.prefixes, "04 80 00 01 00 04 83 00 04 00 00 00 0a"),
            (
                .edgeToP1,
                """
                04 06 00 04 0a ff 00 03 04 41 00 04 4c ee 6b 28
                04 42 00 04 00 00 00 00 04 43 00 20 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 04 47 00 03
                00 00 0a 04 04 00 04 0a ff 00 06
                """
            ),
            (
                .p1ToP2,
                """
                04 06 00 04 0a ff 00 04 04 41 00 04 49 98 96 80
                04 42 00 04 49 98 96 80 04 43 00 20 49 98 96 80
                49 98 96 80 49 98 96 80 49 98 96 80 49 98 96 80
                49 98 96 80 49 98 96 80 49 98 96 80 04 47 00 03
                00 00 0a 04 04 00 04 0a ff 00 03
                """
            ),
        ]
        for (fixture, expectedHex) in expectedValues {
            let update = try Self.parse(fixture)
            let attribute = try #require(
                update.pathAttributes.first { $0.typeCode == BGPPathAttributeType.bgpLSAttribute })
            #expect(attribute.flags == 0x80)
            #expect(attribute.isOptional)
            #expect(!attribute.isExtendedLength)
            #expect(!attribute.isTransitive)
            //  cEOS's short-length type 29 attribute retains its own TLV order and metric width.
            #expect(Array(attribute.value.readableBytesView) == (try Self.bytes(expectedHex)))
            let originalAttributes = update.pathAttributes
            var rib = LSRIB()
            let diffs = try rib.apply(update: update)
            #expect(update.pathAttributes == originalAttributes)
            for diff in diffs {
                guard case .upsert(let record) = diff else {
                    Issue.record("capture must advertise complete records")
                    continue
                }
                #expect(record.observation.availability == .present)
                #expect(record.observation.diagnostics.isEmpty)
                let evidence = try #require(record.observation.attributes.first)
                #expect(evidence.attributeIndex == 4)
                #expect(evidence.flags == attribute.flags)
                #expect(evidence.value == Array(attribute.value.readableBytesView))
                switch record {
                case .node(let node):
                    #expect(node.attributes.name == (fixture == .edgeNode ? "edge-ceos" : "p1"))
                case .link(let link):
                    #expect(link.attributes.igpMetric == 10)
                    #expect(evidence.tlvs.first { $0.type == 1095 }?.value == [0, 0, 10])
                    let edge = fixture == .edgeToP1
                    #expect(link.attributes.maximumLinkBandwidth?.bytesPerSecond == (edge ? 125_000_000 : 1_250_000))
                    #expect(link.attributes.maximumLinkBandwidth?.bitsPerSecond == (edge ? 1_000_000_000 : 10_000_000))
                    #expect(link.attributes.maximumReservableBandwidth?.bytesPerSecond == (edge ? 0 : 1_250_000))
                    #expect(
                        link.attributes.unreservedBandwidth?.values.map(\.bytesPerSecond)
                            == Array(repeating: edge ? 0 : 1_250_000, count: 8))
                case .prefix(let prefix):
                    #expect(prefix.attributes.metric == 10)
                case .unknown:
                    Issue.record("fixture contains only supported topology")
                }
            }
        }
    }

    @Test
    func capturedWithdrawalRemovesBothDirectionsAndReadvertisementRestoresExactKeys() throws {
        var rib = try Self.baseline()
        let baseline = rib
        let removed = baseline.links.filter {
            ($0.value.nlri.localNode.igpRouterIDString == "0000.0000.0003"
                && $0.value.nlri.remoteNode.igpRouterIDString == "0000.0000.0004")
                || ($0.value.nlri.localNode.igpRouterIDString == "0000.0000.0004"
                    && $0.value.nlri.remoteNode.igpRouterIDString == "0000.0000.0003")
        }
        #expect(removed.count == 2)
        let update = try Self.parse(.withdrawCoreLinks)
        let unreach = try #require(update.mpUnreach)
        let withdrawn = try BGPLSNLRIParser.parseAll(unreach.withdrawnNLRI)
        #expect(Set(withdrawn) == Set(removed.values.map { BGPLSNLRI.link($0.nlri) }))
        #expect(try rib.apply(update: update) == withdrawn.map { .withdraw($0) })
        #expect(rib.linkCount == 2)
        #expect(Set(rib.links.keys).isDisjoint(with: removed.keys))
        #expect(rib.nodes == baseline.nodes)
        #expect(rib.prefixes == baseline.prefixes)

        //  Both captured restored UPDATEs are byte-identical to their initial advertisements.
        #expect(try rib.apply(update: Self.parse(.p2ToP1)).count == 1)
        #expect(rib.linkCount == 3)
        #expect(try rib.apply(update: Self.parse(.p1ToP2)).count == 1)
        #expect(Set(rib.links.keys) == Set(baseline.links.keys))
        #expect(rib == baseline)
        try rib.apply(update: Self.parse(.p1ToP2))
        try rib.apply(update: Self.parse(.p2ToP1))
        #expect(rib == baseline)
    }

    private static let nodeFixtures: [(Fixture, UInt8)] = [
        (.rr1Node, 1), (.rr2Node, 2), (.p1Node, 3), (.p2Node, 4), (.frrNode, 5), (.edgeNode, 6),
    ]

    private static func expectIdentity(_ identity: BGPLSNodeIdentity, lastByte: UInt8) throws {
        let systemID = try #require(ISISSystemID("0000.0000.000\(lastByte)"))
        #expect(identity.igpRouterID == .isisSystemID(systemID))
        #expect(identity.ipv4RouterID == nil)
        #expect(identity.autonomousSystem == AutonomousSystemNumber(65_001))
        #expect(identity.bgpLSIdentifier == 0)
        #expect(identity.ospfAreaID == nil)
        #expect(
            identity.rawTLVs == [
                BGPLSTLV(type: 512, value: [0, 0, 0xfd, 0xe9]),
                BGPLSTLV(type: 513, value: [0, 0, 0, 0]),
                BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, lastByte]),
            ])
    }

    private static func baseline() throws -> LSRIB {
        var rib = LSRIB()
        for (fixture, _) in nodeFixtures {
            try rib.apply(update: parse(fixture))
        }
        for fixture: Fixture in [.edgeToP1, .p1ToEdge, .p1ToP2, .p2ToP1, .prefixes] {
            try rib.apply(update: parse(fixture))
        }
        return rib
    }

    private static func parse(_ fixture: Fixture) throws -> BGPUpdateMessage {
        try BGPUpdateParser.parse(ByteBuffer(bytes: bytes(fixture.hex)))
    }

    private static func bytes(_ hex: String) throws -> [UInt8] {
        try hex.split(whereSeparator: \.isWhitespace).map { token in
            try #require(UInt8(token, radix: 16))
        }
    }

    //  Preserve whole vendor UPDATE bodies, never re-encode or invent missing EOR messages.
    enum Fixture: CaseIterable, Sendable {
        case edgeNode
        case rr1Node
        case rr2Node
        case p1Node
        case p2Node
        case frrNode
        case edgeToP1
        case p1ToEdge
        case p1ToP2
        case p2ToP1
        case prefixes
        case withdrawCoreLinks

        var byteCount: Int {
            switch self {
            case .edgeNode: 110
            case .rr1Node: 104
            case .rr2Node: 104
            case .p1Node: 103
            case .p2Node: 103
            case .frrNode: 109
            case .edgeToP1: 198
            case .p1ToEdge: 198
            case .p1ToP2: 198
            case .p2ToP1: 198
            case .prefixes: 359
            case .withdrawCoreLinks: 189
            }
        }

        var hex: String {
            switch self {
            case .edgeNode:
                """
                00 00 00 6a 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 34 40 04 47 04 0a fe fe 02 00 00
                01 00 27 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 06 80 1d 21 04 00 00
                01 00 04 03 00 03 49 00 01 04 02 00 09 65 64 67
                65 2d 63 65 6f 73 04 04 00 04 0a ff 00 06
                """
            case .rr1Node:
                """
                00 00 00 64 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 34 40 04 47 04 0a fe fe 02 00 00
                01 00 27 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 01 80 1d 1b 04 00 00
                01 00 04 03 00 03 49 00 01 04 02 00 03 72 72 31
                04 04 00 04 0a ff 00 01
                """
            case .rr2Node:
                """
                00 00 00 64 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 34 40 04 47 04 0a fe fe 02 00 00
                01 00 27 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 02 80 1d 1b 04 00 00
                01 00 04 03 00 03 49 00 01 04 02 00 03 72 72 32
                04 04 00 04 0a ff 00 02
                """
            case .p1Node:
                """
                00 00 00 63 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 34 40 04 47 04 0a fe fe 02 00 00
                01 00 27 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 03 80 1d 1a 04 00 00
                01 00 04 03 00 03 49 00 01 04 02 00 02 70 31 04
                04 00 04 0a ff 00 03
                """
            case .p2Node:
                """
                00 00 00 63 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 34 40 04 47 04 0a fe fe 02 00 00
                01 00 27 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 04 80 1d 1a 04 00 00
                01 00 04 03 00 03 49 00 01 04 02 00 02 70 32 04
                04 00 04 0a ff 00 04
                """
            case .frrNode:
                """
                00 00 00 69 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 34 40 04 47 04 0a fe fe 02 00 00
                01 00 27 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 05 80 1d 20 04 00 00
                01 00 04 03 00 03 49 00 01 04 02 00 08 65 64 67
                65 2d 66 72 72 04 04 00 04 0a ff 00 05
                """
            case .edgeToP1:
                """
                00 00 00 c2 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 62 40 04 47 04 0a fe fe 02 00 00
                02 00 55 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 06 01 01 00 1a 02 00
                00 04 00 00 fd e9 02 01 00 04 00 00 00 00 02 03
                00 06 00 00 00 00 00 03 01 03 00 04 0a fe 00 0f
                01 04 00 04 0a fe 00 0e 80 1d 4b 04 06 00 04 0a
                ff 00 03 04 41 00 04 4c ee 6b 28 04 42 00 04 00
                00 00 00 04 43 00 20 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 04 47 00 03 00 00 0a 04 04
                00 04 0a ff 00 06
                """
            case .p1ToEdge:
                """
                00 00 00 c2 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 62 40 04 47 04 0a fe fe 02 00 00
                02 00 55 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 03 01 01 00 1a 02 00
                00 04 00 00 fd e9 02 01 00 04 00 00 00 00 02 03
                00 06 00 00 00 00 00 06 01 03 00 04 0a fe 00 0e
                01 04 00 04 0a fe 00 0f 80 1d 4b 04 06 00 04 0a
                ff 00 06 04 41 00 04 49 98 96 80 04 42 00 04 49
                98 96 80 04 43 00 20 49 98 96 80 49 98 96 80 49
                98 96 80 49 98 96 80 49 98 96 80 49 98 96 80 49
                98 96 80 49 98 96 80 04 47 00 03 00 00 0a 04 04
                00 04 0a ff 00 03
                """
            case .p1ToP2:
                """
                00 00 00 c2 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 62 40 04 47 04 0a fe fe 02 00 00
                02 00 55 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 03 01 01 00 1a 02 00
                00 04 00 00 fd e9 02 01 00 04 00 00 00 00 02 03
                00 06 00 00 00 00 00 04 01 03 00 04 0a fe 00 08
                01 04 00 04 0a fe 00 09 80 1d 4b 04 06 00 04 0a
                ff 00 04 04 41 00 04 49 98 96 80 04 42 00 04 49
                98 96 80 04 43 00 20 49 98 96 80 49 98 96 80 49
                98 96 80 49 98 96 80 49 98 96 80 49 98 96 80 49
                98 96 80 49 98 96 80 04 47 00 03 00 00 0a 04 04
                00 04 0a ff 00 03
                """
            case .p2ToP1:
                """
                00 00 00 c2 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 00 62 40 04 47 04 0a fe fe 02 00 00
                02 00 55 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 04 01 01 00 1a 02 00
                00 04 00 00 fd e9 02 01 00 04 00 00 00 00 02 03
                00 06 00 00 00 00 00 03 01 03 00 04 0a fe 00 09
                01 04 00 04 0a fe 00 08 80 1d 4b 04 06 00 04 0a
                ff 00 03 04 41 00 04 49 98 96 80 04 42 00 04 49
                98 96 80 04 43 00 20 49 98 96 80 49 98 96 80 49
                98 96 80 49 98 96 80 49 98 96 80 49 98 96 80 49
                98 96 80 49 98 96 80 04 47 00 03 00 00 0a 04 04
                00 04 0a ff 00 04
                """
            case .prefixes:
                """
                00 00 01 63 40 01 01 00 40 02 00 40 05 04 00 00
                00 64 90 0e 01 41 40 04 47 04 0a fe fe 02 00 00
                03 00 30 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 06 01 09 00 05 20 0a
                ff 00 06 00 03 00 30 02 00 00 00 00 00 00 00 00
                01 00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04
                00 00 00 00 02 03 00 06 00 00 00 00 00 05 01 09
                00 05 20 0a ff 00 05 00 03 00 30 02 00 00 00 00
                00 00 00 00 01 00 00 1a 02 00 00 04 00 00 fd e9
                02 01 00 04 00 00 00 00 02 03 00 06 00 00 00 00
                00 01 01 09 00 05 20 0a ff 00 01 00 03 00 30 02
                00 00 00 00 00 00 00 00 01 00 00 1a 02 00 00 04
                00 00 fd e9 02 01 00 04 00 00 00 00 02 03 00 06
                00 00 00 00 00 02 01 09 00 05 20 0a ff 00 02 00
                03 00 30 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 03 01 09 00 05 20 0a
                ff 00 03 00 03 00 30 02 00 00 00 00 00 00 00 00
                01 00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04
                00 00 00 00 02 03 00 06 00 00 00 00 00 04 01 09
                00 05 20 0a ff 00 04 80 1d 0d 04 80 00 01 00 04
                83 00 04 00 00 00 0a
                """
            case .withdrawCoreLinks:
                """
                00 00 00 b9 90 0f 00 b5 40 04 47 00 02 00 55 02
                00 00 00 00 00 00 00 00 01 00 00 1a 02 00 00 04
                00 00 fd e9 02 01 00 04 00 00 00 00 02 03 00 06
                00 00 00 00 00 03 01 01 00 1a 02 00 00 04 00 00
                fd e9 02 01 00 04 00 00 00 00 02 03 00 06 00 00
                00 00 00 04 01 03 00 04 0a fe 00 08 01 04 00 04
                0a fe 00 09 00 02 00 55 02 00 00 00 00 00 00 00
                00 01 00 00 1a 02 00 00 04 00 00 fd e9 02 01 00
                04 00 00 00 00 02 03 00 06 00 00 00 00 00 04 01
                01 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04 00
                00 00 00 02 03 00 06 00 00 00 00 00 03 01 03 00
                04 0a fe 00 09 01 04 00 04 0a fe 00 08
                """
            }
        }
    }
}
