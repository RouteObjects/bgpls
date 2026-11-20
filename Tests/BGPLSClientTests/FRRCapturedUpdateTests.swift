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

/// Actual FRR 10.7.1 UPDATE bodies from the two-router ARM64 relay spike.
/// See Documentation/Lab/FixtureProvenance.md; these are not five-router fixtures.
struct FRRCapturedUpdateTests {
    @Test(arguments: Fixture.allCases)
    func completeCapturedBodiesParse(fixture: Fixture) throws {
        let bytes = try Self.bytes(fixture.hex)
        #expect(bytes.count == fixture.byteCount)
        let update = try BGPUpdateParser.parse(ByteBuffer(bytes: bytes))
        #expect(update.withdrawnRoutes.readableBytes == 0)
        #expect(update.nlri.readableBytes == 0)
        #expect(update.mpReach?.isBGPLS == true || update.mpUnreach?.isBGPLS == true)
    }

    @Test
    func nodeAdvertisementsKeepTypedSystemIDsAndOmittedAS() throws {
        for (fixture, systemIDText, lastByte) in [
            (Fixture.edgeNode, "0000.0000.0005", UInt8(5)),
            (Fixture.coreNode, "0000.0000.0003", UInt8(3)),
        ] {
            let update = try Self.parse(fixture)
            let reach = try #require(update.mpReach)
            #expect(Array(reach.nextHop.readableBytesView) == [10, 254, 254, 0])
            let nlris = try BGPLSNLRIParser.parseAll(reach.nlri)
            #expect(nlris.count == 1)
            guard case .node(let node) = try #require(nlris.first) else {
                Issue.record("expected captured node NLRI")
                return
            }
            let systemID = try #require(ISISSystemID(systemIDText))
            #expect(node.protocolID == BGPLSProtocolID.isisLevel2.rawValue)
            #expect(node.identifier == 0)
            #expect(node.localNode.igpRouterID == .isisSystemID(systemID))
            #expect(node.localNode.ipv4RouterID == nil)
            //  Peer AS 65001 is transport configuration, not a missing topology descriptor.
            #expect(node.localNode.autonomousSystem == nil)
            #expect(node.localNode.bgpLSIdentifier == nil)
            #expect(node.localNode.ospfAreaID == nil)
            #expect(node.localNode.rawTLVs == [BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, lastByte])])
            #expect(node.additionalDescriptors.isEmpty)
            var rib = LSRIB()
            try rib.apply(update: update)
            let identity = "node \(systemIDText) AS not-advertised"
            let record = try #require(rib.nodes.values.first)
            for showAttributes in [false, true] {
                let nodeLine = identity + (showAttributes ? " \(BGPLSRecord.node(record).attributeSummary)" : "")
                #expect(rib.dump(topic: "nodes", showAttributes: showAttributes) == nodeLine)
                #expect(rib.dump(showAttributes: showAttributes) == "nodes=1 links=0 prefixes=0\n" + nodeLine)
            }
            #expect(
                Array(rib.nodes.keys)
                    == ["node:2:0:local[515:6:00000000000\(lastByte);]:additional[]"])
        }
    }

    @Test
    func directedLinksAndCanonicalIPv4PrefixesKeepTheirOwners() throws {
        let rib = try Self.baseline()
        #expect(rib.summaryLine == "nodes=2 links=2 prefixes=3")
        let expectedDirections = [
            ("0000.0000.0003", "0000.0000.0005", "10.254.0.1", "10.254.0.0"),
            ("0000.0000.0005", "0000.0000.0003", "10.254.0.0", "10.254.0.1"),
        ]
        for (localID, remoteID, localAddress, remoteAddress) in expectedDirections {
            let link = try #require(rib.links.values.map(\.nlri).first { $0.localNode.igpRouterIDString == localID })
            #expect(link.protocolID == BGPLSProtocolID.isisLevel2.rawValue)
            #expect(link.identifier == 0)
            #expect(link.localNode.igpRouterID == .isisSystemID(try #require(ISISSystemID(localID))))
            #expect(link.remoteNode.igpRouterID == .isisSystemID(try #require(ISISSystemID(remoteID))))
            #expect(link.localIPv4Interface == IPv4Address(localAddress))
            #expect(link.remoteIPv4Neighbor == IPv4Address(remoteAddress))
            #expect(link.localLinkIdentifier == nil)
            #expect(link.remoteLinkIdentifier == nil)
            #expect(link.localNode.autonomousSystem == nil)
            #expect(link.remoteNode.autonomousSystem == nil)
            #expect(link.linkDescriptors.map(\.type) == [259, 260])
        }
        let expectedPrefixes = [
            ("0000.0000.0005", "10.255.0.5/32"),
            ("0000.0000.0003", "10.255.0.3/32"),
            ("0000.0000.0003", "10.254.0.0/31"),
        ]
        for (systemID, network) in expectedPrefixes {
            let stored = try #require(
                rib.prefixes.values.map(\.nlri).first {
                    $0.localNode.igpRouterIDString == systemID && $0.network.description == network
                })
            guard case .v4(let prefix) = stored else {
                Issue.record("existing FRR capture must retain its IPv4 prefix family")
                continue
            }
            #expect(prefix.protocolID == BGPLSProtocolID.isisLevel2.rawValue)
            #expect(prefix.identifier == 0)
            #expect(prefix.localNode.igpRouterID == .isisSystemID(try #require(ISISSystemID(systemID))))
            #expect(prefix.localNode.autonomousSystem == nil)
            #expect(prefix.prefixDescriptors.map(\.type) == [265])
            #expect(prefix.network.description == network)
        }
        #expect(!rib.dump(topic: "links").contains("?"))
        #expect(!rib.dump(topic: "prefixes").contains("?"))
    }

    @Test
    func typedLinkStateAttributesRetainTheirOriginalBytes() throws {
        let expectedValues: [(Fixture, String)] = [
            (.edgeNode, "04 02 00 04 65 64 67 65 04 03 00 03 49 00 01 04 04 00 04 0a ff 00 05"),
            (.coreNode, "04 02 00 04 63 6f 72 65 04 03 00 03 49 00 01 04 04 00 04 0a ff 00 03"),
            (.prefixes, "04 83 00 04 00 00 00 0a"),
            (
                .links,
                """
                04 41 00 04 49 98 96 80 04 42 00 04 49 98 96 80 04
                43 00 20 49 98 96 80 49 98 96 80 49 98 96 80 49 98
                96 80 49 98 96 80 49 98 96 80 49 98 96 80 49 98 96
                80 04 47 00 01 0a
                """
            ),
        ]
        for (fixture, expectedHex) in expectedValues {
            let update = try Self.parse(fixture)
            #expect(update.pathAttributes.map(\.typeCode) == [14, 1, 2, 5, 29])
            let attribute = try #require(
                update.pathAttributes.first { $0.typeCode == BGPPathAttributeType.bgpLSAttribute })
            #expect(attribute.flags == 0x90)
            #expect(attribute.isOptional)
            #expect(attribute.isExtendedLength)
            #expect(!attribute.isTransitive)
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
                    #expect(node.attributes.name == (fixture == .edgeNode ? "edge" : "core"))
                case .link(let link):
                    #expect(link.attributes.igpMetric == 10)
                    #expect(evidence.tlvs.first { $0.type == 1095 }?.value == [10])
                    #expect(link.attributes.maximumLinkBandwidth?.bytesPerSecond == 1_250_000)
                    #expect(link.attributes.maximumReservableBandwidth?.bitsPerSecond == 10_000_000)
                    #expect(
                        link.attributes.unreservedBandwidth?.values.map(\.bytesPerSecond)
                            == Array(repeating: 1_250_000, count: 8))
                case .prefix(let prefix):
                    #expect(prefix.attributes.metric == 10)
                case .unknown:
                    Issue.record("fixture contains only supported topology")
                }
            }
        }
    }

    @Test
    func bothCapturedWithdrawalsRemoveExactKeysAndReadvertisementRestoresBaseline() throws {
        var rib = try Self.baseline()
        let baseline = rib
        let originalKeys = Set(rib.links.keys)
        #expect(originalKeys.count == 2)
        for (fixture, localID, remainingCount) in [
            (Fixture.withdrawEdgeLink, "0000.0000.0005", 1),
            (Fixture.withdrawCoreLink, "0000.0000.0003", 0),
        ] {
            let removedKey = try #require(
                rib.links.first { $0.value.nlri.localNode.igpRouterIDString == localID }?.key)
            let update = try Self.parse(fixture)
            let unreach = try #require(update.mpUnreach)
            #expect(!unreach.isEndOfRIB)
            let withdrawn = try BGPLSNLRIParser.parseAll(unreach.withdrawnNLRI)
            #expect(withdrawn.count == 1)
            #expect(withdrawn == [.link(try #require(baseline.links[removedKey]).nlri)])
            let diffs = try rib.apply(update: update)
            #expect(diffs == withdrawn.map { .withdraw($0) })
            #expect(rib.linkCount == remainingCount)
            #expect(rib.links[removedKey] == nil)
            #expect(rib.nodes == baseline.nodes)
            #expect(rib.prefixes == baseline.prefixes)
        }

        //  The actual restored two-link UPDATE is byte-identical to the initial one.
        let restoredDiffs = try rib.apply(update: Self.parse(.links))
        #expect(restoredDiffs.count == 2)
        #expect(Set(rib.links.keys) == originalKeys)
        #expect(rib == baseline)
        try rib.apply(update: Self.parse(.links))
        #expect(rib == baseline)
    }

    @Test
    func capturedEndOfRIBDoesNotWithdrawOrEmitRIBChanges() throws {
        let update = try Self.parse(.endOfRIB)
        #expect(update.mpReach == nil)
        #expect(update.pathAttributes.map(\.typeCode) == [15])
        let unreach = try #require(update.mpUnreach)
        #expect(unreach.isBGPLS)
        #expect(unreach.isEndOfRIB)
        #expect(try BGPLSNLRIParser.parseAll(unreach.withdrawnNLRI).isEmpty)
        var rib = try Self.baseline()
        let before = rib
        #expect(try rib.apply(update: update).isEmpty)
        #expect(rib == before)
        var empty = LSRIB()
        #expect(try empty.apply(update: update).isEmpty)
        #expect(empty == LSRIB())
    }

    private static func baseline() throws -> LSRIB {
        var rib = LSRIB()
        for fixture: Fixture in [.edgeNode, .coreNode, .prefixes, .links] {
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

    //  Keep complete captured UPDATE bodies, not re-encoded synthetic versions of FRR NLRIs.
    // Headers, TCP metadata, timestamps, and repeated keepalives are outside these parser fixtures.
    enum Fixture: CaseIterable, Sendable {
        case edgeNode
        case coreNode
        case prefixes
        case links
        case endOfRIB
        case withdrawEdgeLink
        case withdrawCoreLink

        var byteCount: Int {
            switch self {
            case .edgeNode, .coreNode: 86
            case .prefixes: 152
            case .links: 207
            case .endOfRIB: 10
            case .withdrawEdgeLink, .withdrawCoreLink: 68
            }
        }

        var hex: String {
            switch self {
            case .edgeNode:
                """
                00 00 00 52 90 0e 00 24 40 04 47 04 0a fe fe 00
                00 00 01 00 17 02 00 00 00 00 00 00 00 00 01 00
                00 0a 02 03 00 06 00 00 00 00 00 05 40 01 01 02
                50 02 00 00 40 05 04 00 00 00 64 90 1d 00 17 04
                02 00 04 65 64 67 65 04 03 00 03 49 00 01 04 04
                00 04 0a ff 00 05
                """
            case .coreNode:
                """
                00 00 00 52 90 0e 00 24 40 04 47 04 0a fe fe 00
                00 00 01 00 17 02 00 00 00 00 00 00 00 00 01 00
                00 0a 02 03 00 06 00 00 00 00 00 03 40 01 01 02
                50 02 00 00 40 05 04 00 00 00 64 90 1d 00 17 04
                02 00 04 63 6f 72 65 04 03 00 03 49 00 01 04 04
                00 04 0a ff 00 03
                """
            case .prefixes:
                """
                00 00 00 94 90 0e 00 75 40 04 47 04 0a fe fe 00
                00 00 03 00 20 02 00 00 00 00 00 00 00 00 01 00
                00 0a 02 03 00 06 00 00 00 00 00 05 01 09 00 05
                20 0a ff 00 05 00 03 00 20 02 00 00 00 00 00 00
                00 00 01 00 00 0a 02 03 00 06 00 00 00 00 00 03
                01 09 00 05 20 0a ff 00 03 00 03 00 20 02 00 00
                00 00 00 00 00 00 01 00 00 0a 02 03 00 06 00 00
                00 00 00 03 01 09 00 05 1f 0a fe 00 00 40 01 01
                02 50 02 00 00 40 05 04 00 00 00 64 90 1d 00 08
                04 83 00 04 00 00 00 0a
                """
            case .links:
                """
                00 00 00 cb 90 0e 00 7b 40 04 47 04 0a fe fe 00
                00 00 02 00 35 02 00 00 00 00 00 00 00 00 01 00
                00 0a 02 03 00 06 00 00 00 00 00 03 01 01 00 0a
                02 03 00 06 00 00 00 00 00 05 01 03 00 04 0a fe
                00 01 01 04 00 04 0a fe 00 00 00 02 00 35 02 00
                00 00 00 00 00 00 00 01 00 00 0a 02 03 00 06 00
                00 00 00 00 05 01 01 00 0a 02 03 00 06 00 00 00
                00 00 03 01 03 00 04 0a fe 00 00 01 04 00 04 0a
                fe 00 01 40 01 01 02 50 02 00 00 40 05 04 00 00
                00 64 90 1d 00 39 04 41 00 04 49 98 96 80 04 42
                00 04 49 98 96 80 04 43 00 20 49 98 96 80 49 98
                96 80 49 98 96 80 49 98 96 80 49 98 96 80 49 98
                96 80 49 98 96 80 49 98 96 80 04 47 00 01 0a
                """
            case .endOfRIB:
                """
                00 00 00 06 80 0f 03 40 04 47
                """
            case .withdrawEdgeLink:
                """
                00 00 00 40 90 0f 00 3c 40 04 47 00 02 00 35 02
                00 00 00 00 00 00 00 00 01 00 00 0a 02 03 00 06
                00 00 00 00 00 05 01 01 00 0a 02 03 00 06 00 00
                00 00 00 03 01 03 00 04 0a fe 00 00 01 04 00 04
                0a fe 00 01
                """
            case .withdrawCoreLink:
                """
                00 00 00 40 90 0f 00 3c 40 04 47 00 02 00 35 02
                00 00 00 00 00 00 00 00 01 00 00 0a 02 03 00 06
                00 00 00 00 00 03 01 01 00 0a 02 03 00 06 00 00
                00 00 00 05 01 03 00 04 0a fe 00 01 01 04 00 04
                0a fe 00 00
                """
            }
        }
    }
}
