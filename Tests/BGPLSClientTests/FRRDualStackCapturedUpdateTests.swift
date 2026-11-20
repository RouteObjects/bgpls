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

/// Genuine FRR 10.7.1 messages from the five-router dual-stack ARM64 lab on 2026-10-16.
/// See Documentation/Lab/FixtureProvenance.md. Existing IPv4 captures remain separate.
struct FRRDualStackCapturedUpdateTests {
    @Test(arguments: Fixture.allCases)
    func completeCapturedMessagesPassFramingAndUPDATEParsing(fixture: Fixture) throws {
        let update = try Self.parse(fixture)
        #expect(update.withdrawnRoutes.readableBytes == 0)
        #expect(update.nlri.readableBytes == 0)
        #expect(update.mpReach?.isBGPLS == true || update.mpUnreach?.isBGPLS == true)
    }

    @Test
    func capturedMixedPrefixesRetainBothFamiliesAndAllFiveOwners() throws {
        let update = try Self.parse(.prefixes)
        let reach = try #require(update.mpReach)
        #expect(reach.afi == 16_388)
        #expect(reach.safi == 71)
        #expect(Array(reach.nextHop.readableBytesView) == [10, 254, 254, 0])
        let nlris = try BGPLSNLRIParser.parseAll(reach.nlri)
        #expect(nlris.count == 10)
        var rib = LSRIB()
        let diffs = try rib.apply(update: update)
        #expect(diffs.count == 10)
        #expect(rib.prefixCount == 10)
        #expect(rib.prefixes.values.allSatisfy { $0.attributes.metric == 10 })
        #expect(rib.prefixes.values.allSatisfy { $0.observation.availability == .present })
        for number in 1...5 {
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
            #expect(prefix6.localNode.autonomousSystem == nil)
            #expect(prefix6.protocolID == 2)
            #expect(prefix6.identifier == 0)
            #expect(prefix6.prefixDescriptors.map(\.type) == [265])
            #expect(prefix6.prefixLength == 128)
            #expect(
                diffs.contains {
                    if case .upsert(let record) = $0 { record.nlri == .ipv6Prefix(prefix6) } else { false }
                })
        }
        #expect(update.pathAttributes.map(\.typeCode) == [14, 1, 2, 5, 29])
        let attributes = try #require(update.pathAttributes.first { $0.typeCode == 29 })
        #expect(Array(attributes.value.readableBytesView) == [4, 131, 0, 4, 0, 0, 0, 10])
    }

    @Test
    func capturedLinksContainBothAddressFamiliesForEveryDirection() throws {
        var rib = LSRIB()
        try rib.apply(update: Self.parse(.links))
        #expect(rib.linkCount == 14)
        let adjacencies = [
            (1, 3, 0, 1), (1, 4, 2, 2), (2, 3, 4, 3), (2, 4, 6, 4),
            (3, 4, 8, 5), (3, 5, 10, 6), (4, 5, 12, 7),
        ]
        for (first, second, subnet, linkNumber) in adjacencies {
            for reversed in [false, true] {
                let local = reversed ? second : first
                let remote = reversed ? first : second
                let link = try #require(
                    rib.links.values.map(\.nlri).first {
                        $0.localNode.igpRouterIDString == "0000.0000.000\(local)"
                            && $0.remoteNode.igpRouterIDString == "0000.0000.000\(remote)"
                    })
                #expect(link.localIPv4Interface == IPv4Address("10.254.0.\(subnet + (reversed ? 1 : 0))"))
                #expect(link.remoteIPv4Neighbor == IPv4Address("10.254.0.\(subnet + (reversed ? 0 : 1))"))
                #expect(link.localIPv6Interface == IPv6Address("2001:db8:6501:\(linkNumber)::\(reversed ? "1" : "")"))
                #expect(link.remoteIPv6Neighbor == IPv6Address("2001:db8:6501:\(linkNumber)::\(reversed ? "" : "1")"))
                #expect(link.linkDescriptors.map(\.type) == [259, 260, 261, 262])
                #expect(link.localNode.autonomousSystem == nil)
                #expect(link.remoteNode.autonomousSystem == nil)
                #expect(link.localLinkIdentifier == nil)
                #expect(link.remoteLinkIdentifier == nil)
                #expect(link.protocolID == 2)
                #expect(link.identifier == 0)
            }
        }
    }

    @Test
    func capturedDualStackLinkWithdrawalAndRestorationPreserveEveryOtherObject() throws {
        var rib = LSRIB()
        try rib.apply(update: Self.parse(.prefixes))
        try rib.apply(update: Self.parse(.links))
        let baseline = rib
        let withdrawn = try rib.apply(update: Self.parse(.withdrawCoreLink))
        #expect(withdrawn.count == 2)
        #expect(rib.linkCount == 12)
        #expect(rib.prefixes == baseline.prefixes)
        for diff in withdrawn {
            guard case .withdraw(.link(let link)) = diff else {
                Issue.record("expected captured dual-stack link withdrawal")
                continue
            }
            #expect(link.localIPv6Interface != nil)
            #expect(link.remoteIPv6Neighbor != nil)
            #expect(!rib.links.values.map(\.nlri).contains(link))
            #expect(baseline.links.values.map(\.nlri).contains(link))
            #expect(["0000.0000.0003", "0000.0000.0004"].contains(link.localNode.igpRouterIDString ?? ""))
        }
        let restored = try rib.apply(update: Self.parse(.restoreCoreLink))
        #expect(restored.count == 2)
        #expect(rib == baseline)
        try rib.apply(update: Self.parse(.restoreCoreLink))
        #expect(rib == baseline)
        #expect(try rib.apply(update: Self.parse(.endOfRIB)).isEmpty)
        #expect(rib == baseline)
    }

    @Test
    func capturedIPv6ProbeWithdrawsAndReadvertisesWithoutChangingBaseline() throws {
        var rib = LSRIB()
        try rib.apply(update: Self.parse(.prefixes))
        try rib.apply(update: Self.parse(.links))
        let baseline = rib
        //  The second capture's readvertisement/removal are byte-identical to its first
        // advertisement/withdrawal; reuse those real messages without synthesizing a withdrawal.
        for _ in 0..<2 {
            let diffs = try rib.apply(update: Self.parse(.advertiseProbe))
            #expect(diffs.count == 1)
            guard case .upsert(.prefix(let record)) = try #require(diffs.first),
                case .v6(let probe) = record.nlri
            else {
                Issue.record("expected genuine IPv6 probe advertisement")
                return
            }
            #expect(probe.network.description == "2001:db8:6501:ffff::5/128")
            #expect(probe.localNode.igpRouterIDString == "0000.0000.0005")
            #expect(rib.prefixCount == baseline.prefixCount + 1)
            #expect(rib.links == baseline.links)
            #expect(rib.nodes == baseline.nodes)
            for (key, value) in baseline.prefixes { #expect(rib.prefixes[key] == value) }
            let withdrawn = try rib.apply(update: Self.parse(.withdrawProbe))
            #expect(withdrawn == [.withdraw(.ipv6Prefix(probe))])
            #expect(rib == baseline)
        }
    }

    private static func parse(_ fixture: Fixture) throws -> BGPUpdateMessage {
        let bytes = try fixture.hex.split(whereSeparator: \.isWhitespace).map { token in
            try #require(UInt8(token, radix: 16))
        }
        #expect(bytes.count == fixture.byteCount)
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        defer { _ = try? channel.finish() }
        //  Retain and exercise the real BGP header, not a reconstructed NLRI-only fixture.
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

    //  Complete, unmodified captured BGP messages, including their original path attributes.
    // PCAP packet/TCP headers and timestamps remain outside the portable regression fixtures.
    enum Fixture: CaseIterable, Sendable {
        case prefixes
        case links
        case endOfRIB
        case withdrawCoreLink
        case restoreCoreLink
        case advertiseProbe
        case withdrawProbe

        var byteCount: Int {
            switch self {
            case .prefixes: 483
            case .links: 1470
            case .endOfRIB: 29
            case .withdrawCoreLink: 224
            case .restoreCoreLink: 306
            case .advertiseProbe: 111
            case .withdrawProbe: 78
            }
        }

        var hex: String {
            switch self {
            case .advertiseProbe:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                00 6f 02 00 00 00 58 90 0e 00 39 40 04 47 04 0a
                fe fe 00 00 00 04 00 2c 02 00 00 00 00 00 00 00
                00 01 00 00 0a 02 03 00 06 00 00 00 00 00 05 01
                09 00 11 80 20 01 0d b8 65 01 ff ff 00 00 00 00
                00 00 00 05 40 01 01 02 50 02 00 00 40 05 04 00
                00 00 64 90 1d 00 08 04 83 00 04 00 00 00 0a
                """
            case .withdrawProbe:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                00 4e 02 00 00 00 37 90 0f 00 33 40 04 47 00 04
                00 2c 02 00 00 00 00 00 00 00 00 01 00 00 0a 02
                03 00 06 00 00 00 00 00 05 01 09 00 11 80 20 01
                0d b8 65 01 ff ff 00 00 00 00 00 00 00 05
                """
            case .prefixes:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                01 e3 02 00 00 01 cc 90 0e 01 ad 40 04 47 04 0a
                fe fe 00 00 00 03 00 20 02 00 00 00 00 00 00 00
                00 01 00 00 0a 02 03 00 06 00 00 00 00 00 05 01
                09 00 05 20 0a ff 00 05 00 04 00 2c 02 00 00 00
                00 00 00 00 00 01 00 00 0a 02 03 00 06 00 00 00
                00 00 05 01 09 00 11 80 20 01 0d b8 65 01 00 00
                00 00 00 00 00 00 00 05 00 03 00 20 02 00 00 00
                00 00 00 00 00 01 00 00 0a 02 03 00 06 00 00 00
                00 00 03 01 09 00 05 20 0a ff 00 03 00 04 00 2c
                02 00 00 00 00 00 00 00 00 01 00 00 0a 02 03 00
                06 00 00 00 00 00 03 01 09 00 11 80 20 01 0d b8
                65 01 00 00 00 00 00 00 00 00 00 03 00 03 00 20
                02 00 00 00 00 00 00 00 00 01 00 00 0a 02 03 00
                06 00 00 00 00 00 02 01 09 00 05 20 0a ff 00 02
                00 04 00 2c 02 00 00 00 00 00 00 00 00 01 00 00
                0a 02 03 00 06 00 00 00 00 00 02 01 09 00 11 80
                20 01 0d b8 65 01 00 00 00 00 00 00 00 00 00 02
                00 03 00 20 02 00 00 00 00 00 00 00 00 01 00 00
                0a 02 03 00 06 00 00 00 00 00 01 01 09 00 05 20
                0a ff 00 01 00 04 00 2c 02 00 00 00 00 00 00 00
                00 01 00 00 0a 02 03 00 06 00 00 00 00 00 01 01
                09 00 11 80 20 01 0d b8 65 01 00 00 00 00 00 00
                00 00 00 01 00 03 00 20 02 00 00 00 00 00 00 00
                00 01 00 00 0a 02 03 00 06 00 00 00 00 00 04 01
                09 00 05 20 0a ff 00 04 00 04 00 2c 02 00 00 00
                00 00 00 00 00 01 00 00 0a 02 03 00 06 00 00 00
                00 00 04 01 09 00 11 80 20 01 0d b8 65 01 00 00
                00 00 00 00 00 00 00 04 40 01 01 02 50 02 00 00
                40 05 04 00 00 00 64 90 1d 00 08 04 83 00 04 00
                00 00 0a
                """
            case .links:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                05 be 02 00 00 05 a7 90 0e 05 57 40 04 47 04 0a
                fe fe 00 00 00 02 00 5d 02 00 00 00 00 00 00 00
                00 01 00 00 0a 02 03 00 06 00 00 00 00 00 03 01
                01 00 0a 02 03 00 06 00 00 00 00 00 05 01 03 00
                04 0a fe 00 0a 01 04 00 04 0a fe 00 0b 01 05 00
                10 20 01 0d b8 65 01 00 06 00 00 00 00 00 00 00
                00 01 06 00 10 20 01 0d b8 65 01 00 06 00 00 00
                00 00 00 00 01 00 02 00 5d 02 00 00 00 00 00 00
                00 00 01 00 00 0a 02 03 00 06 00 00 00 00 00 05
                01 01 00 0a 02 03 00 06 00 00 00 00 00 03 01 03
                00 04 0a fe 00 0b 01 04 00 04 0a fe 00 0a 01 05
                00 10 20 01 0d b8 65 01 00 06 00 00 00 00 00 00
                00 01 01 06 00 10 20 01 0d b8 65 01 00 06 00 00
                00 00 00 00 00 00 00 02 00 5d 02 00 00 00 00 00
                00 00 00 01 00 00 0a 02 03 00 06 00 00 00 00 00
                02 01 01 00 0a 02 03 00 06 00 00 00 00 00 03 01
                03 00 04 0a fe 00 04 01 04 00 04 0a fe 00 05 01
                05 00 10 20 01 0d b8 65 01 00 03 00 00 00 00 00
                00 00 00 01 06 00 10 20 01 0d b8 65 01 00 03 00
                00 00 00 00 00 00 01 00 02 00 5d 02 00 00 00 00
                00 00 00 00 01 00 00 0a 02 03 00 06 00 00 00 00
                00 03 01 01 00 0a 02 03 00 06 00 00 00 00 00 02
                01 03 00 04 0a fe 00 05 01 04 00 04 0a fe 00 04
                01 05 00 10 20 01 0d b8 65 01 00 03 00 00 00 00
                00 00 00 01 01 06 00 10 20 01 0d b8 65 01 00 03
                00 00 00 00 00 00 00 00 00 02 00 5d 02 00 00 00
                00 00 00 00 00 01 00 00 0a 02 03 00 06 00 00 00
                00 00 01 01 01 00 0a 02 03 00 06 00 00 00 00 00
                03 01 03 00 04 0a fe 00 00 01 04 00 04 0a fe 00
                01 01 05 00 10 20 01 0d b8 65 01 00 01 00 00 00
                00 00 00 00 00 01 06 00 10 20 01 0d b8 65 01 00
                01 00 00 00 00 00 00 00 01 00 02 00 5d 02 00 00
                00 00 00 00 00 00 01 00 00 0a 02 03 00 06 00 00
                00 00 00 03 01 01 00 0a 02 03 00 06 00 00 00 00
                00 01 01 03 00 04 0a fe 00 01 01 04 00 04 0a fe
                00 00 01 05 00 10 20 01 0d b8 65 01 00 01 00 00
                00 00 00 00 00 01 01 06 00 10 20 01 0d b8 65 01
                00 01 00 00 00 00 00 00 00 00 00 02 00 5d 02 00
                00 00 00 00 00 00 00 01 00 00 0a 02 03 00 06 00
                00 00 00 00 04 01 01 00 0a 02 03 00 06 00 00 00
                00 00 01 01 03 00 04 0a fe 00 03 01 04 00 04 0a
                fe 00 02 01 05 00 10 20 01 0d b8 65 01 00 02 00
                00 00 00 00 00 00 01 01 06 00 10 20 01 0d b8 65
                01 00 02 00 00 00 00 00 00 00 00 00 02 00 5d 02
                00 00 00 00 00 00 00 00 01 00 00 0a 02 03 00 06
                00 00 00 00 00 01 01 01 00 0a 02 03 00 06 00 00
                00 00 00 04 01 03 00 04 0a fe 00 02 01 04 00 04
                0a fe 00 03 01 05 00 10 20 01 0d b8 65 01 00 02
                00 00 00 00 00 00 00 00 01 06 00 10 20 01 0d b8
                65 01 00 02 00 00 00 00 00 00 00 01 00 02 00 5d
                02 00 00 00 00 00 00 00 00 01 00 00 0a 02 03 00
                06 00 00 00 00 00 04 01 01 00 0a 02 03 00 06 00
                00 00 00 00 02 01 03 00 04 0a fe 00 07 01 04 00
                04 0a fe 00 06 01 05 00 10 20 01 0d b8 65 01 00
                04 00 00 00 00 00 00 00 01 01 06 00 10 20 01 0d
                b8 65 01 00 04 00 00 00 00 00 00 00 00 00 02 00
                5d 02 00 00 00 00 00 00 00 00 01 00 00 0a 02 03
                00 06 00 00 00 00 00 02 01 01 00 0a 02 03 00 06
                00 00 00 00 00 04 01 03 00 04 0a fe 00 06 01 04
                00 04 0a fe 00 07 01 05 00 10 20 01 0d b8 65 01
                00 04 00 00 00 00 00 00 00 00 01 06 00 10 20 01
                0d b8 65 01 00 04 00 00 00 00 00 00 00 01 00 02
                00 5d 02 00 00 00 00 00 00 00 00 01 00 00 0a 02
                03 00 06 00 00 00 00 00 04 01 01 00 0a 02 03 00
                06 00 00 00 00 00 03 01 03 00 04 0a fe 00 09 01
                04 00 04 0a fe 00 08 01 05 00 10 20 01 0d b8 65
                01 00 05 00 00 00 00 00 00 00 01 01 06 00 10 20
                01 0d b8 65 01 00 05 00 00 00 00 00 00 00 00 00
                02 00 5d 02 00 00 00 00 00 00 00 00 01 00 00 0a
                02 03 00 06 00 00 00 00 00 03 01 01 00 0a 02 03
                00 06 00 00 00 00 00 04 01 03 00 04 0a fe 00 08
                01 04 00 04 0a fe 00 09 01 05 00 10 20 01 0d b8
                65 01 00 05 00 00 00 00 00 00 00 00 01 06 00 10
                20 01 0d b8 65 01 00 05 00 00 00 00 00 00 00 01
                00 02 00 5d 02 00 00 00 00 00 00 00 00 01 00 00
                0a 02 03 00 06 00 00 00 00 00 04 01 01 00 0a 02
                03 00 06 00 00 00 00 00 05 01 03 00 04 0a fe 00
                0c 01 04 00 04 0a fe 00 0d 01 05 00 10 20 01 0d
                b8 65 01 00 07 00 00 00 00 00 00 00 00 01 06 00
                10 20 01 0d b8 65 01 00 07 00 00 00 00 00 00 00
                01 00 02 00 5d 02 00 00 00 00 00 00 00 00 01 00
                00 0a 02 03 00 06 00 00 00 00 00 05 01 01 00 0a
                02 03 00 06 00 00 00 00 00 04 01 03 00 04 0a fe
                00 0d 01 04 00 04 0a fe 00 0c 01 05 00 10 20 01
                0d b8 65 01 00 07 00 00 00 00 00 00 00 01 01 06
                00 10 20 01 0d b8 65 01 00 07 00 00 00 00 00 00
                00 00 40 01 01 02 50 02 00 00 40 05 04 00 00 00
                64 90 1d 00 39 04 41 00 04 49 98 96 80 04 42 00
                04 49 98 96 80 04 43 00 20 49 98 96 80 49 98 96
                80 49 98 96 80 49 98 96 80 49 98 96 80 49 98 96
                80 49 98 96 80 49 98 96 80 04 47 00 01 0a
                """
            case .endOfRIB:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                00 1d 02 00 00 00 06 80 0f 03 40 04 47
                """
            case .withdrawCoreLink:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                00 e0 02 00 00 00 c9 90 0f 00 c5 40 04 47 00 02
                00 5d 02 00 00 00 00 00 00 00 00 01 00 00 0a 02
                03 00 06 00 00 00 00 00 04 01 01 00 0a 02 03 00
                06 00 00 00 00 00 03 01 03 00 04 0a fe 00 09 01
                04 00 04 0a fe 00 08 01 05 00 10 20 01 0d b8 65
                01 00 05 00 00 00 00 00 00 00 01 01 06 00 10 20
                01 0d b8 65 01 00 05 00 00 00 00 00 00 00 00 00
                02 00 5d 02 00 00 00 00 00 00 00 00 01 00 00 0a
                02 03 00 06 00 00 00 00 00 03 01 01 00 0a 02 03
                00 06 00 00 00 00 00 04 01 03 00 04 0a fe 00 08
                01 04 00 04 0a fe 00 09 01 05 00 10 20 01 0d b8
                65 01 00 05 00 00 00 00 00 00 00 00 01 06 00 10
                20 01 0d b8 65 01 00 05 00 00 00 00 00 00 00 01
                """
            case .restoreCoreLink:
                """
                ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                01 32 02 00 00 01 1b 90 0e 00 cb 40 04 47 04 0a
                fe fe 00 00 00 02 00 5d 02 00 00 00 00 00 00 00
                00 01 00 00 0a 02 03 00 06 00 00 00 00 00 04 01
                01 00 0a 02 03 00 06 00 00 00 00 00 03 01 03 00
                04 0a fe 00 09 01 04 00 04 0a fe 00 08 01 05 00
                10 20 01 0d b8 65 01 00 05 00 00 00 00 00 00 00
                01 01 06 00 10 20 01 0d b8 65 01 00 05 00 00 00
                00 00 00 00 00 00 02 00 5d 02 00 00 00 00 00 00
                00 00 01 00 00 0a 02 03 00 06 00 00 00 00 00 03
                01 01 00 0a 02 03 00 06 00 00 00 00 00 04 01 03
                00 04 0a fe 00 08 01 04 00 04 0a fe 00 09 01 05
                00 10 20 01 0d b8 65 01 00 05 00 00 00 00 00 00
                00 00 01 06 00 10 20 01 0d b8 65 01 00 05 00 00
                00 00 00 00 00 01 40 01 01 02 50 02 00 00 40 05
                04 00 00 00 64 90 1d 00 39 04 41 00 04 49 98 96
                80 04 42 00 04 49 98 96 80 04 43 00 20 49 98 96
                80 49 98 96 80 49 98 96 80 49 98 96 80 49 98 96
                80 49 98 96 80 49 98 96 80 49 98 96 80 04 47 00
                01 0a
                """
            }
        }
    }
}
