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
import NIOEmbedded
import Testing

/// Genuine cEOS ARM64 4.36.2F messages from the successful dual-stack run on 2026-10-16.
/// See Documentation/Lab/FixtureProvenance.md; no vendor bytes are synthesized.
struct CEOSDualStackCapturedUpdateTests {
    @Test(arguments: Fixture.allCases)
    func completeCapturedMessagesPassFramingAndUPDATEParsing(fixture: Fixture) throws {
        let update = try Self.parse(fixture)
        #expect(update.withdrawnRoutes.readableBytes == 0)
        #expect(update.nlri.readableBytes == 0)
        if fixture.isWithdrawal {
            let unreach = try #require(update.mpUnreach)
            #expect(unreach.isBGPLS)
            #expect(!unreach.isEndOfRIB)
            #expect(update.mpReach == nil)
            #expect(update.pathAttributes.map(\.typeCode) == [15])
        } else {
            let reach = try #require(update.mpReach)
            #expect(reach.afi == 16_388)
            #expect(reach.safi == 71)
            #expect(Array(reach.nextHop.readableBytesView) == [10, 254, 254, 2])
            #expect(update.pathAttributes.map(\.typeCode) == [1, 2, 5, 14, 29])
        }
    }

    @Test
    func capturedMixedPrefixesRetainBothFamiliesAndAllSixOwners() throws {
        let update = try Self.parse(.prefixes)
        var rib = LSRIB()
        let diffs = try rib.apply(update: update)
        #expect(diffs.count == 12)
        #expect(rib.prefixCount == 12)
        #expect(rib.prefixes.values.allSatisfy { $0.attributes.metric == 10 })
        #expect(rib.prefixes.values.allSatisfy { $0.observation.availability == .present })
        for number in 1...6 {
            let owner = "0000.0000.000\(number)"
            let ipv4 = try #require(
                rib.prefixes.values.map(\.nlri).first { $0.network.description == "10.255.0.\(number)/32" })
            let ipv6 = try #require(
                rib.prefixes.values.map(\.nlri).first { $0.network.description == "2001:db8:6501::\(number)/128" })
            guard case .v4(let prefix4) = ipv4, case .v6(let prefix6) = ipv6 else {
                Issue.record("captured NLRI family must select the corresponding typed prefix")
                continue
            }
            #expect(prefix4.localNode.igpRouterIDString == owner)
            #expect(prefix6.localNode.igpRouterIDString == owner)
            #expect(prefix6.localNode.ipv4RouterID == nil)
            #expect(prefix6.localNode.autonomousSystem == AutonomousSystemNumber(65_001))
            #expect(prefix6.localNode.bgpLSIdentifier == 0)
            #expect(prefix6.localNode.rawTLVs.map(\.type) == [512, 513, 515])
            #expect(prefix6.protocolID == 2)
            #expect(prefix6.identifier == 0)
            #expect(prefix6.prefixDescriptors.map(\.type) == [265])
            #expect(prefix6.prefixLength == 128)
            #expect(
                diffs.contains {
                    if case .upsert(let record) = $0 { record.nlri == .ipv6Prefix(prefix6) } else { false }
                })
        }
        let attribute = try #require(update.pathAttributes.first { $0.typeCode == 29 })
        #expect(attribute.flags == 0x80)
        #expect(Array(attribute.value.readableBytesView) == [4, 128, 0, 1, 0, 4, 131, 0, 4, 0, 0, 0, 10])
    }

    @Test
    func capturedCEOSAndCoreLinksRetainIPv4AndIPv6Descriptors() throws {
        let rib = try Self.baseline()
        //  Keep all twelve prefixes, but only four representative directed links in this subset.
        #expect(rib.summaryLine == "nodes=0 links=4 prefixes=12")
        for (local, remote, local4, remote4, local6, remote6) in [
            (6, 3, "10.254.0.15", "10.254.0.14", "2001:db8:6501:8::1", "2001:db8:6501:8::"),
            (3, 6, "10.254.0.14", "10.254.0.15", "2001:db8:6501:8::", "2001:db8:6501:8::1"),
            (3, 4, "10.254.0.8", "10.254.0.9", "2001:db8:6501:5::", "2001:db8:6501:5::1"),
            (4, 3, "10.254.0.9", "10.254.0.8", "2001:db8:6501:5::1", "2001:db8:6501:5::"),
        ] {
            let link = try #require(
                rib.links.values.map(\.nlri).first {
                    $0.localNode.igpRouterIDString == "0000.0000.000\(local)"
                        && $0.remoteNode.igpRouterIDString == "0000.0000.000\(remote)"
                })
            #expect(link.localIPv4Interface == IPv4Address(local4))
            #expect(link.remoteIPv4Neighbor == IPv4Address(remote4))
            #expect(link.localIPv6Interface == IPv6Address(local6))
            #expect(link.remoteIPv6Neighbor == IPv6Address(remote6))
            #expect(link.linkDescriptors.map(\.type) == [259, 260, 261, 262])
            #expect(link.localNode.autonomousSystem == AutonomousSystemNumber(65_001))
            #expect(link.remoteNode.autonomousSystem == AutonomousSystemNumber(65_001))
            #expect(link.localLinkIdentifier == nil)
            #expect(link.remoteLinkIdentifier == nil)
            #expect(link.protocolID == 2)
            #expect(link.identifier == 0)
        }
    }

    @Test
    func capturedDualStackCoreLinkWithdrawalAndRestorationAreExact() throws {
        var rib = try Self.baseline()
        let baseline = rib
        let removed = try rib.apply(update: Self.parse(.withdrawCoreLinks))
        #expect(removed.count == 2)
        #expect(rib.linkCount == 2)
        #expect(rib.prefixes == baseline.prefixes)
        for diff in removed {
            guard case .withdraw(.link(let link)) = diff else {
                Issue.record("expected genuine core-link withdrawal")
                continue
            }
            #expect(link.localIPv6Interface != nil)
            #expect(link.remoteIPv6Neighbor != nil)
            #expect(!rib.links.values.map(\.nlri).contains(link))
            #expect(baseline.links.values.map(\.nlri).contains(link))
        }
        //  Both real restoration messages are byte-identical to their original advertisements.
        try rib.apply(update: Self.parse(.p1ToP2))
        try rib.apply(update: Self.parse(.p2ToP1))
        #expect(rib == baseline)
        try rib.apply(update: Self.parse(.p1ToP2))
        #expect(rib == baseline)
    }

    @Test(arguments: [5, 6])
    func capturedProbeCyclesRetainTheIGPOriginAndRestoreBaseline(owner: Int) throws {
        let advertisement: Fixture = owner == 5 ? .advertiseFRRProbe : .advertiseCEOSProbe
        let withdrawal: Fixture = owner == 5 ? .withdrawFRRProbe : .withdrawCEOSProbe
        var rib = try Self.baseline()
        let baseline = rib
        for _ in 0..<2 {
            let diffs = try rib.apply(update: Self.parse(advertisement))
            #expect(diffs.count == 1)
            guard case .upsert(.prefix(let record)) = try #require(diffs.first),
                case .v6(let prefix) = record.nlri
            else {
                Issue.record("expected genuine IPv6 prefix probe")
                return
            }
            #expect(prefix.network.description == "2001:db8:6501:ffff::\(owner)/128")
            #expect(prefix.localNode.igpRouterIDString == "0000.0000.000\(owner)")
            #expect(prefix.localNode.autonomousSystem == AutonomousSystemNumber(65_001))
            #expect(rib.prefixCount == baseline.prefixCount + 1)
            #expect(rib.links == baseline.links)
            for (key, value) in baseline.prefixes { #expect(rib.prefixes[key] == value) }
            #expect(try rib.apply(update: Self.parse(withdrawal)) == [.withdraw(.ipv6Prefix(prefix))])
            #expect(rib == baseline)
        }
    }

    @Test
    func capturedIPv6TEAttributeBytesRemainUnmodifiedAlongsideTypedValues() throws {
        let update = try Self.parse(.edgeToP1)
        let attribute = try #require(update.pathAttributes.first { $0.typeCode == 29 })
        let expected = try Self.bytes(
            """
            04 06 00 04 0a ff 00 03 04 41 00 04 4c ee 6b 28
            04 42 00 04 00 00 00 00 04 43 00 20 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 04 47 00 03
            00 00 0a 04 04 00 04 0a ff 00 06 04 05 00 10 20
            01 0d b8 65 01 00 00 00 00 00 00 00 00 00 06
            """)
        #expect(attribute.flags == 0x80)
        #expect(Array(attribute.value.readableBytesView) == expected)
        var rib = LSRIB()
        try rib.apply(update: update)
        let record = try #require(rib.links.values.first)
        #expect(record.attributes.igpMetric == 10)
        #expect(record.attributes.maximumLinkBandwidth?.bitsPerSecond == 1_000_000_000)
        #expect(record.observation.attributes.first?.value == expected)
        #expect(record.observation.attributes.first?.tlvs.last?.type == 1029)
    }

    private static func baseline() throws -> LSRIB {
        var rib = LSRIB()
        for fixture: Fixture in [.prefixes, .edgeToP1, .p1ToEdge, .p1ToP2, .p2ToP1] {
            try rib.apply(update: parse(fixture))
        }
        return rib
    }

    private static func bytes(_ hex: String) throws -> [UInt8] {
        try hex.split(whereSeparator: \.isWhitespace).map { token in
            try #require(UInt8(token, radix: 16))
        }
    }

    private static func parse(_ fixture: Fixture) throws -> BGPUpdateMessage {
        let bytes = try bytes(fixture.hex)
        #expect(bytes.count == fixture.byteCount)
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        defer { _ = try? channel.finish() }
        try channel.writeInbound(ByteBuffer(bytes: bytes))
        let message: BGPMessage? = try channel.readInbound()
        guard case .update(let body) = message else {
            throw BGPLSClientError.protocolError("test expected one captured UPDATE")
        }
        #expect(Array(body.readableBytesView) == Array(bytes.dropFirst(19)))
        let extra: BGPMessage? = try channel.readInbound()
        #expect(extra == nil)
        return try BGPUpdateParser.parse(body)
    }

    //  Complete vendor messages including BGP headers; no re-encoded or invented EOR fixture.
    enum Fixture: CaseIterable, Sendable {
        case prefixes
        case edgeToP1
        case p1ToEdge
        case p1ToP2
        case p2ToP1
        case withdrawCoreLinks
        case advertiseFRRProbe
        case withdrawFRRProbe
        case advertiseCEOSProbe
        case withdrawCEOSProbe

        var isWithdrawal: Bool {
            switch self {
            case .withdrawCoreLinks, .withdrawFRRProbe, .withdrawCEOSProbe: true
            default: false
            }
        }

        var byteCount: Int {
            switch self {
            case .prefixes: 762
            case .edgeToP1: 277
            case .p1ToEdge: 277
            case .p1ToP2: 257
            case .p2ToP1: 257
            case .withdrawCoreLinks: 288
            case .advertiseFRRProbe: 130
            case .withdrawFRRProbe: 94
            case .advertiseCEOSProbe: 130
            case .withdrawCEOSProbe: 94
            }
        }

        var hex: String {
            switch self {
            case .prefixes:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                02 fa 02 00 00 02 e3 40 01 01 00 40 02 00 40 05
                04 00 00 00 64 90 0e 02 c1 40 04 47 04 0a fe fe
                02 00 00 03 00 30 02 00 00 00 00 00 00 00 00 01
                00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04 00
                00 00 00 02 03 00 06 00 00 00 00 00 06 01 09 00
                05 20 0a ff 00 06 00 03 00 30 02 00 00 00 00 00
                00 00 00 01 00 00 1a 02 00 00 04 00 00 fd e9 02
                01 00 04 00 00 00 00 02 03 00 06 00 00 00 00 00
                05 01 09 00 05 20 0a ff 00 05 00 03 00 30 02 00
                00 00 00 00 00 00 00 01 00 00 1a 02 00 00 04 00
                00 fd e9 02 01 00 04 00 00 00 00 02 03 00 06 00
                00 00 00 00 04 01 09 00 05 20 0a ff 00 04 00 03
                00 30 02 00 00 00 00 00 00 00 00 01 00 00 1a 02
                00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00 02
                03 00 06 00 00 00 00 00 03 01 09 00 05 20 0a ff
                00 03 00 03 00 30 02 00 00 00 00 00 00 00 00 01
                00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04 00
                00 00 00 02 03 00 06 00 00 00 00 00 02 01 09 00
                05 20 0a ff 00 02 00 03 00 30 02 00 00 00 00 00
                00 00 00 01 00 00 1a 02 00 00 04 00 00 fd e9 02
                01 00 04 00 00 00 00 02 03 00 06 00 00 00 00 00
                01 01 09 00 05 20 0a ff 00 01 00 04 00 3c 02 00
                00 00 00 00 00 00 00 01 00 00 1a 02 00 00 04 00
                00 fd e9 02 01 00 04 00 00 00 00 02 03 00 06 00
                00 00 00 00 06 01 09 00 11 80 20 01 0d b8 65 01
                00 00 00 00 00 00 00 00 00 06 00 04 00 3c 02 00
                00 00 00 00 00 00 00 01 00 00 1a 02 00 00 04 00
                00 fd e9 02 01 00 04 00 00 00 00 02 03 00 06 00
                00 00 00 00 05 01 09 00 11 80 20 01 0d b8 65 01
                00 00 00 00 00 00 00 00 00 05 00 04 00 3c 02 00
                00 00 00 00 00 00 00 01 00 00 1a 02 00 00 04 00
                00 fd e9 02 01 00 04 00 00 00 00 02 03 00 06 00
                00 00 00 00 04 01 09 00 11 80 20 01 0d b8 65 01
                00 00 00 00 00 00 00 00 00 04 00 04 00 3c 02 00
                00 00 00 00 00 00 00 01 00 00 1a 02 00 00 04 00
                00 fd e9 02 01 00 04 00 00 00 00 02 03 00 06 00
                00 00 00 00 03 01 09 00 11 80 20 01 0d b8 65 01
                00 00 00 00 00 00 00 00 00 03 00 04 00 3c 02 00
                00 00 00 00 00 00 00 01 00 00 1a 02 00 00 04 00
                00 fd e9 02 01 00 04 00 00 00 00 02 03 00 06 00
                00 00 00 00 02 01 09 00 11 80 20 01 0d b8 65 01
                00 00 00 00 00 00 00 00 00 02 00 04 00 3c 02 00
                00 00 00 00 00 00 00 01 00 00 1a 02 00 00 04 00
                00 fd e9 02 01 00 04 00 00 00 00 02 03 00 06 00
                00 00 00 00 01 01 09 00 11 80 20 01 0d b8 65 01
                00 00 00 00 00 00 00 00 00 01 80 1d 0d 04 80 00
                01 00 04 83 00 04 00 00 00 0a
                """
            case .edgeToP1:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                01 15 02 00 00 00 fe 40 01 01 00 40 02 00 40 05
                04 00 00 00 64 90 0e 00 8a 40 04 47 04 0a fe fe
                02 00 00 02 00 7d 02 00 00 00 00 00 00 00 00 01
                00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04 00
                00 00 00 02 03 00 06 00 00 00 00 00 06 01 01 00
                1a 02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00
                00 02 03 00 06 00 00 00 00 00 03 01 03 00 04 0a
                fe 00 0f 01 04 00 04 0a fe 00 0e 01 05 00 10 20
                01 0d b8 65 01 00 08 00 00 00 00 00 00 00 01 01
                06 00 10 20 01 0d b8 65 01 00 08 00 00 00 00 00
                00 00 00 80 1d 5f 04 06 00 04 0a ff 00 03 04 41
                00 04 4c ee 6b 28 04 42 00 04 00 00 00 00 04 43
                00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 04 47 00 03 00 00 0a 04 04 00 04 0a ff 00
                06 04 05 00 10 20 01 0d b8 65 01 00 00 00 00 00
                00 00 00 00 06
                """
            case .p1ToEdge:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                01 15 02 00 00 00 fe 40 01 01 00 40 02 00 40 05
                04 00 00 00 64 90 0e 00 8a 40 04 47 04 0a fe fe
                02 00 00 02 00 7d 02 00 00 00 00 00 00 00 00 01
                00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04 00
                00 00 00 02 03 00 06 00 00 00 00 00 03 01 01 00
                1a 02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00
                00 02 03 00 06 00 00 00 00 00 06 01 03 00 04 0a
                fe 00 0e 01 04 00 04 0a fe 00 0f 01 05 00 10 20
                01 0d b8 65 01 00 08 00 00 00 00 00 00 00 00 01
                06 00 10 20 01 0d b8 65 01 00 08 00 00 00 00 00
                00 00 01 80 1d 5f 04 06 00 04 0a ff 00 06 04 07
                00 10 20 01 0d b8 65 01 00 00 00 00 00 00 00 00
                00 06 04 41 00 04 49 98 96 80 04 42 00 04 49 98
                96 80 04 43 00 20 49 98 96 80 49 98 96 80 49 98
                96 80 49 98 96 80 49 98 96 80 49 98 96 80 49 98
                96 80 49 98 96 80 04 47 00 03 00 00 0a 04 04 00
                04 0a ff 00 03
                """
            case .p1ToP2:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                01 01 02 00 00 00 ea 40 01 01 00 40 02 00 40 05
                04 00 00 00 64 90 0e 00 8a 40 04 47 04 0a fe fe
                02 00 00 02 00 7d 02 00 00 00 00 00 00 00 00 01
                00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04 00
                00 00 00 02 03 00 06 00 00 00 00 00 03 01 01 00
                1a 02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00
                00 02 03 00 06 00 00 00 00 00 04 01 03 00 04 0a
                fe 00 08 01 04 00 04 0a fe 00 09 01 05 00 10 20
                01 0d b8 65 01 00 05 00 00 00 00 00 00 00 00 01
                06 00 10 20 01 0d b8 65 01 00 05 00 00 00 00 00
                00 00 01 80 1d 4b 04 06 00 04 0a ff 00 04 04 41
                00 04 49 98 96 80 04 42 00 04 49 98 96 80 04 43
                00 20 49 98 96 80 49 98 96 80 49 98 96 80 49 98
                96 80 49 98 96 80 49 98 96 80 49 98 96 80 49 98
                96 80 04 47 00 03 00 00 0a 04 04 00 04 0a ff 00
                03
                """
            case .p2ToP1:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                01 01 02 00 00 00 ea 40 01 01 00 40 02 00 40 05
                04 00 00 00 64 90 0e 00 8a 40 04 47 04 0a fe fe
                02 00 00 02 00 7d 02 00 00 00 00 00 00 00 00 01
                00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04 00
                00 00 00 02 03 00 06 00 00 00 00 00 04 01 01 00
                1a 02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00
                00 02 03 00 06 00 00 00 00 00 03 01 03 00 04 0a
                fe 00 09 01 04 00 04 0a fe 00 08 01 05 00 10 20
                01 0d b8 65 01 00 05 00 00 00 00 00 00 00 01 01
                06 00 10 20 01 0d b8 65 01 00 05 00 00 00 00 00
                00 00 00 80 1d 4b 04 06 00 04 0a ff 00 03 04 41
                00 04 49 98 96 80 04 42 00 04 49 98 96 80 04 43
                00 20 49 98 96 80 49 98 96 80 49 98 96 80 49 98
                96 80 49 98 96 80 49 98 96 80 49 98 96 80 49 98
                96 80 04 47 00 03 00 00 0a 04 04 00 04 0a ff 00
                04
                """
            case .withdrawCoreLinks:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                01 20 02 00 00 01 09 90 0f 01 05 40 04 47 00 02
                00 7d 02 00 00 00 00 00 00 00 00 01 00 00 1a 02
                00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00 02
                03 00 06 00 00 00 00 00 03 01 01 00 1a 02 00 00
                04 00 00 fd e9 02 01 00 04 00 00 00 00 02 03 00
                06 00 00 00 00 00 04 01 03 00 04 0a fe 00 08 01
                04 00 04 0a fe 00 09 01 05 00 10 20 01 0d b8 65
                01 00 05 00 00 00 00 00 00 00 00 01 06 00 10 20
                01 0d b8 65 01 00 05 00 00 00 00 00 00 00 01 00
                02 00 7d 02 00 00 00 00 00 00 00 00 01 00 00 1a
                02 00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00
                02 03 00 06 00 00 00 00 00 04 01 01 00 1a 02 00
                00 04 00 00 fd e9 02 01 00 04 00 00 00 00 02 03
                00 06 00 00 00 00 00 03 01 03 00 04 0a fe 00 09
                01 04 00 04 0a fe 00 08 01 05 00 10 20 01 0d b8
                65 01 00 05 00 00 00 00 00 00 00 01 01 06 00 10
                20 01 0d b8 65 01 00 05 00 00 00 00 00 00 00 00
                """
            case .advertiseFRRProbe:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                00 82 02 00 00 00 6b 40 01 01 00 40 02 00 40 05
                04 00 00 00 64 90 0e 00 49 40 04 47 04 0a fe fe
                02 00 00 04 00 3c 02 00 00 00 00 00 00 00 00 01
                00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04 00
                00 00 00 02 03 00 06 00 00 00 00 00 05 01 09 00
                11 80 20 01 0d b8 65 01 ff ff 00 00 00 00 00 00
                00 05 80 1d 0d 04 80 00 01 00 04 83 00 04 00 00
                00 0a
                """
            case .withdrawFRRProbe:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                00 5e 02 00 00 00 47 90 0f 00 43 40 04 47 00 04
                00 3c 02 00 00 00 00 00 00 00 00 01 00 00 1a 02
                00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00 02
                03 00 06 00 00 00 00 00 05 01 09 00 11 80 20 01
                0d b8 65 01 ff ff 00 00 00 00 00 00 00 05
                """
            case .advertiseCEOSProbe:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                00 82 02 00 00 00 6b 40 01 01 00 40 02 00 40 05
                04 00 00 00 64 90 0e 00 49 40 04 47 04 0a fe fe
                02 00 00 04 00 3c 02 00 00 00 00 00 00 00 00 01
                00 00 1a 02 00 00 04 00 00 fd e9 02 01 00 04 00
                00 00 00 02 03 00 06 00 00 00 00 00 06 01 09 00
                11 80 20 01 0d b8 65 01 ff ff 00 00 00 00 00 00
                00 06 80 1d 0d 04 80 00 01 00 04 83 00 04 00 00
                00 0a
                """
            case .withdrawCEOSProbe:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                00 5e 02 00 00 00 47 90 0f 00 43 40 04 47 00 04
                00 3c 02 00 00 00 00 00 00 00 00 01 00 00 1a 02
                00 00 04 00 00 fd e9 02 01 00 04 00 00 00 00 02
                03 00 06 00 00 00 00 00 06 01 09 00 11 80 20 01
                0d b8 65 01 ff ff 00 00 00 00 00 00 00 06
                """
            }
        }
    }
}
