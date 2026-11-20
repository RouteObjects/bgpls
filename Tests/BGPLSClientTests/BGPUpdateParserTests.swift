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
import NIOCore
import Testing

/// Synthetic OSPF BGP-LS UPDATEs using documentation addresses (AFI 16388 / SAFI 71).
struct BGPUpdateParserTests {
    /// LINK NLRI: 198.51.100.5 ↔ 198.51.100.6 between Router-IDs 192.0.2.1 and 192.0.2.2.
    static let linkUpdateHex = """
        00 00 00 91 40 01 01 00 40 02 00 40 05 04 00 00 00 64 80 1d 1e \
        04 40 00 04 00 00 00 00 04 41 00 04 4c ee 6b 28 04 44 00 04 00 00 00 14 \
        04 47 00 02 00 01 90 0e 00 5e 40 04 47 04 c0 00 02 fe 00 \
        00 02 00 51 03 00 00 00 00 00 00 00 00 01 00 00 18 02 00 00 04 00 00 fd e9 \
        02 02 00 04 00 00 00 00 02 03 00 04 c0 00 02 01 01 01 00 18 02 00 00 04 00 00 fd e9 \
        02 02 00 04 00 00 00 00 02 03 00 04 c0 00 02 02 01 03 00 04 c6 33 64 05 01 04 00 04 c6 33 64 06
        """

    /// Two NODE NLRIs (Router-ID 192.0.2.2, then 192.0.2.1).
    static let nodeUpdateHex = """
        00 00 00 7b 40 01 01 00 40 02 00 40 05 04 00 00 00 64 80 1d 0b \
        01 07 00 02 00 00 04 00 00 01 00 90 0e 00 5b 40 04 47 04 c0 00 02 fe 00 \
        00 01 00 25 03 00 00 00 00 00 00 00 00 01 00 00 18 02 00 00 04 00 00 fd e9 \
        02 02 00 04 00 00 00 00 02 03 00 04 c0 00 02 02 \
        00 01 00 25 03 00 00 00 00 00 00 00 00 01 00 00 18 02 00 00 04 00 00 fd e9 \
        02 02 00 04 00 00 00 00 02 03 00 04 c0 00 02 01
        """

    /// One PREFIX NLRI for 198.51.100.0/30 on Router-ID 192.0.2.1.
    static let prefixUpdateHex = """
        00 00 00 58 40 01 01 00 40 02 00 40 05 04 00 00 00 64 80 1d 08 \
        04 83 00 04 00 00 00 01 90 0e 00 3b 40 04 47 04 c0 00 02 fe 00 \
        00 03 00 2e 03 00 00 00 00 00 00 00 00 01 00 00 18 02 00 00 04 00 00 fd e9 \
        02 02 00 04 00 00 00 00 02 03 00 04 c0 00 02 01 01 09 00 05 1e c6 33 64 00
        """

    /// End-of-RIB style empty MP_UNREACH for link-state.
    static let unreachEORHex = "00 00 00 07 90 0f 00 03 40 04 47"

    @Test
    func parseLinkUpdateMPReach() throws {
        let update = try BGPUpdateParser.parse(HexFixture.buffer(Self.linkUpdateHex))
        let reach = try #require(update.mpReach)
        #expect(reach.afi == 16_388)
        #expect(reach.safi == 71)
        #expect(reach.isBGPLS)
        #expect(reach.nextHop.readableBytes == 4)

        let nlris = try BGPLSNLRIParser.parseAll(reach.nlri)
        #expect(nlris.count == 1)
        guard case .link(let link) = nlris[0] else {
            Issue.record("expected LINK NLRI")
            return
        }
        #expect(link.protocolID == BGPLSProtocolID.ospfv2.rawValue)
        #expect(link.localNode.autonomousSystem?.rawValue == 65_001)
        #expect(link.localNode.ipv4RouterIDString == "192.0.2.1")
        #expect(link.remoteNode.ipv4RouterIDString == "192.0.2.2")
        #expect(link.localIPv4Interface?.formatted(.addressOnly) == "198.51.100.5")
        #expect(link.remoteIPv4Neighbor?.formatted(.addressOnly) == "198.51.100.6")
    }

    @Test
    func parseNodeUpdate() throws {
        let update = try BGPUpdateParser.parse(HexFixture.buffer(Self.nodeUpdateHex))
        let reach = try #require(update.mpReach)
        let nlris = try BGPLSNLRIParser.parseAll(reach.nlri)
        #expect(nlris.count == 2)

        guard case .node(let first) = nlris[0],
            case .node(let second) = nlris[1]
        else {
            Issue.record("expected two NODE NLRIs")
            return
        }
        #expect(first.localNode.ipv4RouterIDString == "192.0.2.2")
        #expect(second.localNode.ipv4RouterIDString == "192.0.2.1")
        #expect(first.localNode.autonomousSystem?.rawValue == 65_001)
    }

    @Test
    func parsePrefixUpdate() throws {
        let update = try BGPUpdateParser.parse(HexFixture.buffer(Self.prefixUpdateHex))
        let reach = try #require(update.mpReach)
        let nlris = try BGPLSNLRIParser.parseAll(reach.nlri)
        #expect(nlris.count == 1)
        guard case .ipv4Prefix(let prefix) = nlris[0] else {
            Issue.record("expected IPv4 PREFIX NLRI")
            return
        }
        #expect(prefix.localNode.ipv4RouterIDString == "192.0.2.1")
        #expect(prefix.prefixLength == 30)
        #expect(prefix.network.formatted(.addressOnly) == "198.51.100.0")
        #expect(prefix.network.description == "198.51.100.0/30")
    }

    @Test
    func parseMPUnreachEndOfRIB() throws {
        let update = try BGPUpdateParser.parse(HexFixture.buffer(Self.unreachEORHex))
        let unreach = try #require(update.mpUnreach)
        #expect(unreach.afi == 16_388)
        #expect(unreach.safi == 71)
        #expect(unreach.isEndOfRIB)
        #expect(update.mpReach == nil)
    }

    @Test(arguments: [UInt8(14), 15])
    func duplicateMPTypesAreRejectedAcrossValuesFamiliesPositionsAndLengthEncodings(type: UInt8) throws {
        let original = DuplicateMPFixture.value(type: type)
        let alternatives = [
            original,
            DuplicateMPFixture.value(type: type, nlri: [0, 1, 0, 0]),
            DuplicateMPFixture.value(type: type, afi: 2),
            DuplicateMPFixture.value(type: type, safi: 1),
        ]
        for alternative in alternatives {
            for firstExtended in [false, true] {
                for secondExtended in [false, true] {
                    for separated in [false, true] {
                        var attributes = [
                            DuplicateMPFixture.attribute(type: type, value: original, extended: firstExtended)
                        ]
                        if separated {
                            attributes.append(DuplicateMPFixture.attribute(type: 250, value: [9, 8, 7]))
                        }
                        attributes.append(
                            DuplicateMPFixture.attribute(type: type, value: alternative, extended: secondExtended))
                        let body = DuplicateMPFixture.body(attributes: attributes)
                        let originalBody = body
                        #expect(throws: BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: type)) {
                            try BGPUpdateParser.parse(body)
                        }
                        #expect(body == originalBody)
                    }
                }
            }
        }
    }

    @Test(arguments: [UInt8(14), 15])
    func firstRepeatedMPTypeInWireOrderWins(type: UInt8) throws {
        let other: UInt8 = type == 14 ? 15 : 14
        let attributes = [other, type, type, other].map {
            DuplicateMPFixture.attribute(type: $0, value: DuplicateMPFixture.value(type: $0))
        }
        #expect(throws: BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: type)) {
            try BGPUpdateParser.parse(DuplicateMPFixture.body(attributes: attributes))
        }
    }

    @Test(arguments: [UInt8(14), 15])
    func duplicateDetectionPrecedesInnerMPDecoding(type: UInt8) throws {
        let good = DuplicateMPFixture.attribute(type: type, value: DuplicateMPFixture.value(type: type))
        let bad = DuplicateMPFixture.attribute(type: type, value: [])
        let other: UInt8 = type == 14 ? 15 : 14
        let malformedOther = DuplicateMPFixture.attribute(type: other, value: [])
        for attributes in [[bad, good], [good, bad], [bad, bad], [malformedOther, good, good]] {
            #expect(throws: BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: type)) {
                try BGPUpdateParser.parse(DuplicateMPFixture.body(attributes: attributes))
            }
        }
    }

    @Test(arguments: [UInt8(14), 15])
    func outerFramingFailureStillPrecedesDuplicateDetection(type: UInt8) throws {
        let attribute = DuplicateMPFixture.attribute(type: type, value: DuplicateMPFixture.value(type: type))
        for (tail, detail) in [
            ([UInt8(0x80)], "path attribute header truncated"),
            ([0x90, type, 0], "extended path attribute length truncated"),
            ([0x80, type, 4, 0], "path attribute value truncated (type \(type))"),
        ] {
            #expect(throws: BGPLSClientError.protocolError(detail)) {
                try BGPUpdateParser.parse(DuplicateMPFixture.body(attributes: [attribute, attribute, tail]))
            }
        }
        var body = DuplicateMPFixture.body(attributes: [attribute, attribute])
        body.moveWriterIndex(to: body.writerIndex - 1)
        #expect(throws: BGPLSClientError.protocolError("UPDATE truncated path attributes")) {
            try BGPUpdateParser.parse(body)
        }
    }

    @Test(arguments: [false, true])
    func oneReachAndOneUnreachPreserveOrderingRawFieldsAndOtherDuplicates(reachFirst: Bool) throws {
        let reach = DuplicateMPFixture.attribute(type: 14, value: DuplicateMPFixture.value(type: 14), extended: true)
        let unreach = DuplicateMPFixture.attribute(type: 15, value: DuplicateMPFixture.value(type: 15))
        let opaque = DuplicateMPFixture.attribute(type: 250, value: [9, 8, 7])
        let linkState = DuplicateMPFixture.attribute(type: 29, value: [4, 131, 0, 4, 0, 0, 0, 10])
        let values = (reachFirst ? [reach, unreach] : [unreach, reach]) + [opaque, linkState, opaque, linkState]
        let body = DuplicateMPFixture.body(attributes: values, withdrawn: [24, 192, 0, 2], nlri: [24, 198, 51, 100])
        let update = try BGPUpdateParser.parse(body)
        #expect(update.mpReach?.isBGPLS == true)
        #expect(update.mpUnreach?.isEndOfRIB == true)
        #expect(Array(update.withdrawnRoutes.readableBytesView) == [24, 192, 0, 2])
        #expect(Array(update.nlri.readableBytesView) == [24, 198, 51, 100])
        var rawAttributes = ByteBuffer(bytes: values.flatMap { $0 })
        #expect(try BGPUpdateParser.parsePathAttributes(&rawAttributes) == update.pathAttributes)
        #expect(rawAttributes.readableBytes == 0)
        #expect(update.pathAttributes.map(\.typeCode) == (reachFirst ? [14, 15] : [15, 14]) + [250, 29, 250, 29])
        #expect(update.pathAttributes[2].value == update.pathAttributes[4].value)
        #expect(update.pathAttributes[3].value == update.pathAttributes[5].value)
    }

    @Test(arguments: [UInt8(14), 15])
    func framingOnlyHelperRetainsDuplicateMPAttributes(type: UInt8) throws {
        let attribute = DuplicateMPFixture.attribute(type: type, value: [])
        var bytes = ByteBuffer(bytes: attribute + attribute)
        let attributes = try BGPUpdateParser.parsePathAttributes(&bytes)
        #expect(attributes.count == 2)
        #expect(attributes.map(\.typeCode) == [type, type])
        #expect(attributes.allSatisfy { $0.value.readableBytes == 0 })
        #expect(bytes.readableBytes == 0)
    }

    @Test
    func duplicateErrorDescriptionsNameTheWireAttributes() {
        #expect(
            BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: 14).description
                == "Protocol error: duplicate MP_REACH_NLRI attribute")
        #expect(
            BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: 15).description
                == "Protocol error: duplicate MP_UNREACH_NLRI attribute")
    }
}

/// Wire-level builders deliberately permit duplicate and malformed attributes.
enum DuplicateMPFixture {
    static func attribute(type: UInt8, value: [UInt8], extended: Bool = false) -> [UInt8] {
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt8(extended ? 0x90 : 0x80))
        buffer.writeInteger(type)
        if extended {
            buffer.writeInteger(UInt16(value.count))
        } else {
            buffer.writeInteger(UInt8(value.count))
        }
        buffer.writeBytes(value)
        return Array(buffer.readableBytesView)
    }

    static func value(type: UInt8, afi: UInt16 = 16_388, safi: UInt8 = 71, nlri: [UInt8] = []) -> [UInt8] {
        var buffer = ByteBuffer()
        buffer.writeInteger(afi)
        buffer.writeInteger(safi)
        if type == 14 { buffer.writeBytes([4, 192, 0, 2, 254, 0]) }
        buffer.writeBytes(nlri)
        return Array(buffer.readableBytesView)
    }

    static func body(attributes: [[UInt8]], withdrawn: [UInt8] = [], nlri: [UInt8] = []) -> ByteBuffer {
        let bytes = attributes.flatMap { $0 }
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt16(withdrawn.count))
        buffer.writeBytes(withdrawn)
        buffer.writeInteger(UInt16(bytes.count))
        buffer.writeBytes(bytes)
        buffer.writeBytes(nlri)
        return buffer
    }
}
