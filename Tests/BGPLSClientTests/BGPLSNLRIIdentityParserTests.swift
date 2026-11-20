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

/// Synthetic RFC 9552 wire fixtures, not captures from FRR or another vendor.
struct BGPLSNLRIIdentityParserTests {
    @Test(arguments: [UInt8(1), UInt8(2)])
    func parsesISISSystemAndPseudonodeIdentities(protocolID: UInt8) throws {
        let system = try #require(ISISSystemID("1920.0000.2001"))
        let pseudo = try #require(ISISPseudonodeID("1920.0000.2001.02"))
        let first = try node(protocolID: protocolID, routerID: system.bytes)
        let second = try node(protocolID: protocolID, routerID: pseudo.bytes)
        #expect(first.protocolID == protocolID)
        #expect(first.identifier == 42)
        #expect(first.localNode.igpRouterID == .isisSystemID(system))
        #expect(first.localNode.igpRouterIDString == system.description)
        #expect(first.localNode.ipv4RouterID == nil)
        #expect(second.localNode.igpRouterID == .isisPseudonode(pseudo))
        #expect(second.localNode.igpRouterIDString == pseudo.description)
        #expect(second.localNode.ipv4RouterID == nil)
    }

    @Test(arguments: [UInt8(3), UInt8(6)])
    func parsesOSPFRouterIdentity(protocolID: UInt8) throws {
        let parsed = try node(protocolID: protocolID, routerID: [192, 0, 2, 1])
        #expect(parsed.localNode.igpRouterID == .ospfRouterID(IPv4Address(address: 0xc000_0201)))
        #expect(parsed.localNode.igpRouterIDString == "192.0.2.1")
        #expect(parsed.localNode.ipv4RouterIDString == "192.0.2.1")
    }

    @Test
    func distinguishesOSPFPseudonodeEncodings() throws {
        let routerID = IPv4Address(address: 0xc000_0201)
        let v2 = try node(protocolID: 3, routerID: [192, 0, 2, 1, 198, 51, 100, 1])
        let v3 = try node(protocolID: 6, routerID: [192, 0, 2, 1, 0, 0, 0, 37])
        #expect(
            v2.localNode.igpRouterID
                == .ospfv2Pseudonode(routerID: routerID, interfaceAddress: IPv4Address(address: 0xc633_6401))
        )
        #expect(v3.localNode.igpRouterID == .ospfv3Pseudonode(routerID: routerID, interfaceID: 37))
        #expect(v2.localNode.ipv4RouterID == routerID)
        #expect(v3.localNode.ipv4RouterID == routerID)
    }

    @Test(arguments: [UInt8(4), UInt8(5), UInt8(250)])
    func unknownAndNonIGPProtocolsPreserveOpaqueIDs(protocolID: UInt8) throws {
        for bytes: [UInt8] in [[192, 0, 2, 1], [0, 1, 2, 3, 4, 5], Array(repeating: 17, count: 16)] {
            let parsed = try node(protocolID: protocolID, routerID: bytes)
            #expect(parsed.localNode.igpRouterID == .opaque(bytes))
            #expect(parsed.localNode.igpRouterID?.rawValue == bytes)
            #expect(parsed.localNode.ipv4RouterID == nil)
        }
    }

    @Test
    func retainsUnknownNodeAndLinkDescriptorsAndExtractsUnnumberedIdentifiers() throws {
        let unknownNode = BGPLSTLV(type: 60_001, value: [0xde, 0xad])
        let local = descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1], extra: [unknownNode])
        let remote = descriptors(type: 257, routerID: [0, 0, 0, 0, 0, 2])
        let linkIDs = BGPLSTLV(type: 258, value: uint32Bytes(37) + uint32Bytes(58))
        let topology = BGPLSTLV(type: 263, value: [0, 2])
        let unknownLink = BGPLSTLV(type: 60_002, value: [0xbe, 0xef, 1])
        let parsed = try parse(
            nlri(type: 2, protocolID: 2, body: local + remote + tlvs([linkIDs, topology, unknownLink]))
        )
        guard case .link(let link) = parsed else {
            Issue.record("expected link NLRI")
            return
        }
        #expect(link.localLinkIdentifier == 37)
        #expect(link.remoteLinkIdentifier == 58)
        #expect(link.localIPv4Interface == nil)
        #expect(link.remoteIPv4Neighbor == nil)
        #expect(link.localNode.rawTLVs.contains(unknownNode))
        #expect(link.linkDescriptors == [linkIDs, topology, unknownLink])
        #expect(link.localNode.igpRouterIDString == "0000.0000.0001")
        #expect(link.remoteNode.igpRouterIDString == "0000.0000.0002")
    }

    @Test
    func preservesRepeatedUnknownLinkAndPrefixDescriptorsAndTheirRIBIdentity() throws {
        let local = descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1])
        let remote = descriptors(type: 257, routerID: [0, 0, 0, 0, 0, 2])
        let firstUnknown = BGPLSTLV(type: 60_001, value: [1])
        let secondUnknown = BGPLSTLV(type: 60_001, value: [2])
        let repeated = [firstUnknown, firstUnknown, secondUnknown]
        let shorter = [firstUnknown, secondUnknown]
        let reachability = BGPLSTLV(type: 265, value: [24, 192, 0, 2])
        let linkWire = nlri(type: 2, protocolID: 2, body: local + remote + tlvs(repeated))
        let prefixWire = nlri(type: 3, protocolID: 2, body: local + tlvs([reachability] + repeated))
        let shorterLink = nlri(type: 2, protocolID: 2, body: local + remote + tlvs(shorter))
        let shorterPrefix = nlri(type: 3, protocolID: 2, body: local + tlvs([reachability] + shorter))
        guard case .link(let link) = try parse(linkWire),
            case .ipv4Prefix(let prefix) = try parse(prefixWire)
        else {
            Issue.record("expected link and prefix NLRIs")
            return
        }
        //  Unknown TLVs are not assumed singleton; both payloads and multiplicity affect identity.
        #expect(link.linkDescriptors == repeated)
        #expect(prefix.prefixDescriptors == [reachability] + repeated)
        var rib = LSRIB()
        try rib.apply(update: BGPUpdateParser.parse(update(reachable: true, nlris: linkWire + prefixWire)))
        try rib.apply(update: BGPUpdateParser.parse(update(reachable: true, nlris: shorterLink + shorterPrefix)))
        #expect(rib.linkCount == 2)
        #expect(rib.prefixCount == 2)
        let reorderedLink = nlri(type: 2, protocolID: 2, body: local + remote + tlvs(Array(repeated.reversed())))
        let reorderedPrefix = nlri(
            type: 3, protocolID: 2, body: tlvs(Array(repeated.reversed()) + [reachability]) + local)
        try rib.apply(
            update: BGPUpdateParser.parse(update(reachable: false, nlris: reorderedLink + reorderedPrefix))
        )
        #expect(rib.linkCount == 1)
        #expect(rib.prefixCount == 1)
        #expect(!rib.links.values.map(\.nlri).contains(link))
        #expect(!rib.prefixes.values.map(\.nlri).contains(.v4(prefix)))
    }

    @Test
    func preservesAdditionalNodeDescriptorsBeforeAndAfterLocalNodeAndInRIBKeys() throws {
        let local = descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1])
        let firstUnknown = BGPLSTLV(type: 60_001, value: [1])
        let secondUnknown = BGPLSTLV(type: 60_001, value: [2])
        let unexpected = BGPLSTLV(type: 259, value: [192, 0, 2, 1])
        let extras = [firstUnknown, secondUnknown, firstUnknown, unexpected]
        let wire = nlri(
            type: 1,
            protocolID: 2,
            body: tlvs([firstUnknown]) + local + tlvs([secondUnknown, firstUnknown, unexpected])
        )
        let parsed = try parse(wire)
        guard case .node(let node) = parsed else {
            Issue.record("expected node NLRI")
            return
        }
        #expect(node.localNode.igpRouterIDString == "0000.0000.0001")
        #expect(node.additionalDescriptors == extras)
        var rib = LSRIB()
        rib.apply(BGPLSRecord(nlri: parsed))
        rib.apply(
            BGPLSRecord(nlri: try parse(nlri(type: 1, protocolID: 2, body: local + tlvs([firstUnknown, unexpected])))))
        rib.apply(
            BGPLSRecord(nlri: try parse(nlri(type: 1, protocolID: 2, body: local + tlvs([secondUnknown, unexpected])))))
        #expect(rib.nodeCount == 3)
        let reordered = nlri(type: 1, protocolID: 2, body: tlvs(Array(extras.reversed())) + local)
        try rib.apply(update: BGPUpdateParser.parse(update(reachable: false, nlris: reordered)))
        #expect(rib.nodeCount == 2)
        #expect(!rib.nodes.values.map(\.nlri).contains(node))
    }

    @Test
    func parsesSingletonLinkDescriptorsIndependentOfWireOrder() throws {
        let local = descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1])
        let remote = descriptors(type: 257, routerID: [0, 0, 0, 0, 0, 2])
        let identifiers = BGPLSTLV(type: 258, value: uint32Bytes(37) + uint32Bytes(58))
        let topology = BGPLSTLV(type: 263, value: [0, 2])
        let wire = nlri(type: 2, protocolID: 2, body: tlvs([topology]) + remote + tlvs([identifiers]) + local)
        guard case .link(let link) = try parse(wire) else {
            Issue.record("expected link NLRI")
            return
        }
        #expect(link.localNode.igpRouterIDString == "0000.0000.0001")
        #expect(link.remoteNode.igpRouterIDString == "0000.0000.0002")
        #expect(link.localLinkIdentifier == 37)
        #expect(link.remoteLinkIdentifier == 58)
        #expect(link.linkDescriptors == [topology, identifiers])
    }

    @Test
    func prefixAndReachWithdrawEndOfRIBRoundTripPreserveIdentity() throws {
        let local = descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1])
        let topology = BGPLSTLV(type: 263, value: [0, 2])
        let reachability = BGPLSTLV(type: 265, value: [25, 192, 0, 2, 128])
        let unknown = BGPLSTLV(type: 60_003, value: [1, 2])
        let prefixWire = nlri(type: 3, protocolID: 2, body: local + tlvs([topology, reachability, unknown]))
        let nodeWire = nlri(type: 1, protocolID: 2, body: local)
        let remote = descriptors(type: 257, routerID: [0, 0, 0, 0, 0, 2])
        let linkWire = nlri(
            type: 2,
            protocolID: 2,
            body: local + remote + tlvs([BGPLSTLV(type: 258, value: uint32Bytes(1) + uint32Bytes(2))])
        )
        let wire = nodeWire + linkWire + prefixWire
        let reached = try BGPUpdateParser.parse(update(reachable: true, nlris: wire))
        let reach = try #require(reached.mpReach)
        #expect(reach.isBGPLS)
        #expect(Array(reach.nextHop.readableBytesView) == [192, 0, 2, 254])
        let announced = try BGPLSNLRIParser.parseAll(reach.nlri)
        #expect(announced.count == 3)
        guard case .ipv4Prefix(let prefix) = announced[2] else {
            Issue.record("expected IPv4 prefix NLRI")
            return
        }
        #expect(prefix.network.description == "192.0.2.128/25")
        #expect(prefix.localNode.igpRouterIDString == "0000.0000.0001")
        #expect(prefix.prefixDescriptors == [topology, reachability, unknown])

        let withdrawn = try BGPUpdateParser.parse(update(reachable: false, nlris: wire))
        let unreach = try #require(withdrawn.mpUnreach)
        #expect(unreach.isBGPLS)
        #expect(!unreach.isEndOfRIB)
        #expect(try BGPLSNLRIParser.parseAll(unreach.withdrawnNLRI) == announced)
        let end = try BGPUpdateParser.parse(update(reachable: false, nlris: []))
        let endUnreach = try #require(end.mpUnreach)
        #expect(endUnreach.isEndOfRIB)
        #expect(try BGPLSNLRIParser.parseAll(endUnreach.withdrawnNLRI).isEmpty)
    }

    @Test
    func rejectsInvalidProtocolSpecificRouterIDWidths() {
        for protocolID: UInt8 in [1, 2] {
            for count in [0, 1, 4, 5, 8, 16] {
                #expect(throws: BGPLSClientError.self) {
                    try node(protocolID: protocolID, routerID: Array(repeating: 1, count: count))
                }
            }
            #expect(throws: BGPLSClientError.self) {
                try node(protocolID: protocolID, routerID: [0, 0, 0, 0, 0, 1, 0])
            }
        }
        for protocolID: UInt8 in [3, 6] {
            for count in [0, 1, 3, 5, 6, 7, 9, 16] {
                #expect(throws: BGPLSClientError.self) {
                    try node(protocolID: protocolID, routerID: Array(repeating: 1, count: count))
                }
            }
        }
    }

    @Test
    func rejectsMissingMandatoryAndDuplicateNodeDescriptors() {
        for protocolID: UInt8 in [1, 2, 3, 4, 5, 6] {
            let missing = tlvs([BGPLSTLV(type: 256, value: tlvs([BGPLSTLV(type: 512, value: uint32Bytes(65_001))]))])
            #expect(throws: BGPLSClientError.self) {
                try parse(nlri(type: 1, protocolID: protocolID, body: missing))
            }
        }
        for duplicate in [
            BGPLSTLV(type: 512, value: uint32Bytes(65_001)),
            BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, 1]),
            BGPLSTLV(type: 60_001, value: [1]),
        ] {
            var subTLVs = [
                BGPLSTLV(type: 512, value: uint32Bytes(65_001)), BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, 1]),
            ]
            if duplicate.type == 60_001 { subTLVs.append(duplicate) }
            subTLVs.append(duplicate)
            let body = tlvs([BGPLSTLV(type: 256, value: tlvs(subTLVs.sorted { $0.type < $1.type }))])
            #expect(throws: BGPLSClientError.self) {
                try parse(nlri(type: 1, protocolID: 2, body: body))
            }
        }
    }

    @Test
    func rejectsMalformedKnownNodeDescriptorLengths() {
        for type: UInt16 in [512, 513, 514] {
            for count in [0, 3, 5] {
                let invalid = BGPLSTLV(type: type, value: Array(repeating: 0, count: count))
                let identity = BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, 1])
                let body = tlvs([BGPLSTLV(type: 256, value: tlvs([invalid, identity]))])
                #expect(throws: BGPLSClientError.self) {
                    try parse(nlri(type: 1, protocolID: 2, body: body))
                }
            }
        }
    }

    @Test
    func rejectsMalformedOrDuplicateLinkDescriptors() {
        let nodes =
            descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1])
            + descriptors(type: 257, routerID: [0, 0, 0, 0, 0, 2])
        for (type, lengths): (UInt16, [Int]) in [
            (258, [0, 4, 7, 9]), (259, [0, 3, 5]), (260, [0, 3, 5]), (263, [0, 1, 3, 4]),
        ] {
            for count in lengths {
                let invalid = BGPLSTLV(type: type, value: Array(repeating: 0, count: count))
                #expect(throws: BGPLSClientError.self) {
                    try parse(nlri(type: 2, protocolID: 2, body: nodes + tlvs([invalid])))
                }
            }
        }
        for duplicate in [
            BGPLSTLV(type: 258, value: uint32Bytes(1) + uint32Bytes(2)),
            BGPLSTLV(type: 263, value: [0, 2]),
        ] {
            #expect(throws: BGPLSClientError.self) {
                try parse(nlri(type: 2, protocolID: 2, body: nodes + tlvs([duplicate, duplicate])))
            }
        }
    }

    @Test
    func rejectsMissingMalformedOrDuplicatePrefixDescriptors() {
        let local = descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1])
        let valid = BGPLSTLV(type: 265, value: [24, 192, 0, 2])
        for badReachability: [UInt8] in [[], [33], [24, 192, 0], [24, 192, 0, 2, 0]] {
            #expect(throws: BGPLSClientError.self) {
                try parse(
                    nlri(type: 3, protocolID: 2, body: local + tlvs([BGPLSTLV(type: 265, value: badReachability)])))
            }
        }
        #expect(throws: BGPLSClientError.self) {
            try parse(nlri(type: 3, protocolID: 2, body: local))
        }
        #expect(throws: BGPLSClientError.self) {
            try parse(nlri(type: 3, protocolID: 2, body: local + tlvs([valid, valid])))
        }
        for count in [0, 1, 3, 4] {
            let topology = BGPLSTLV(type: 263, value: Array(repeating: 0, count: count))
            #expect(throws: BGPLSClientError.self) {
                try parse(nlri(type: 3, protocolID: 2, body: local + tlvs([topology, valid])))
            }
        }
    }

    @Test
    func prefixPaddingCanonicalizesAndWithdrawsCanonicalNetwork() throws {
        let local = descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1])
        let padded = BGPLSTLV(type: 265, value: [25, 192, 0, 2, 129])
        let canonical = BGPLSTLV(type: 265, value: [25, 192, 0, 2, 128])
        let paddedWire = nlri(type: 3, protocolID: 2, body: local + tlvs([padded]))
        let canonicalWire = nlri(type: 3, protocolID: 2, body: local + tlvs([canonical]))
        guard case .ipv4Prefix(let prefix) = try parse(paddedWire) else {
            Issue.record("expected IPv4 prefix NLRI")
            return
        }
        #expect(prefix.network.description == "192.0.2.128/25")
        var rib = LSRIB()
        rib.apply(BGPLSRecord(nlri: .ipv4Prefix(prefix)))
        rib.apply(BGPLSRecord(nlri: try parse(canonicalWire)))
        #expect(rib.prefixCount == 1)
        try rib.apply(update: BGPUpdateParser.parse(update(reachable: false, nlris: canonicalWire)))
        #expect(rib.prefixCount == 0)
    }

    @Test
    func acceptsDefaultAndHostPrefixes() throws {
        let local = descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1])
        for (bytes, expected): ([UInt8], String) in [([0], "0.0.0.0/0"), ([32, 192, 0, 2, 1], "192.0.2.1/32")] {
            let parsed = try parse(
                nlri(type: 3, protocolID: 2, body: local + tlvs([BGPLSTLV(type: 265, value: bytes)])))
            guard case .ipv4Prefix(let prefix) = parsed else {
                Issue.record("expected IPv4 prefix NLRI")
                continue
            }
            #expect(prefix.network.description == expected)
        }
    }

    @Test
    func rejectsTruncatedWireAndUnexpectedNodeTrailingData() {
        let valid = nlri(type: 1, protocolID: 2, body: descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1]))
        for count in 1..<valid.count {
            #expect(throws: BGPLSClientError.self) {
                try BGPLSNLRIParser.parseAll(ByteBuffer(bytes: valid.prefix(count)))
            }
        }
        let duplicateLocal = descriptors(type: 256, routerID: [0, 0, 0, 0, 0, 1])
        #expect(throws: BGPLSClientError.self) {
            try parse(nlri(type: 1, protocolID: 2, body: duplicateLocal + duplicateLocal))
        }
        let incompleteSubTLV = tlvs([BGPLSTLV(type: 256, value: [2, 3, 0, 6, 0])])
        #expect(throws: BGPLSClientError.self) {
            try parse(nlri(type: 1, protocolID: 2, body: incompleteSubTLV))
        }
    }

    private func node(protocolID: UInt8, routerID: [UInt8]) throws -> BGPLSNodeNLRI {
        let parsed = try parse(nlri(type: 1, protocolID: protocolID, body: descriptors(type: 256, routerID: routerID)))
        guard case .node(let node) = parsed else {
            throw BGPLSClientError.protocolError("test expected node NLRI")
        }
        return node
    }

    private func parse(_ bytes: [UInt8]) throws -> BGPLSNLRI {
        let values = try BGPLSNLRIParser.parseAll(ByteBuffer(bytes: bytes))
        return try #require(values.first)
    }

    private func descriptors(type: UInt16, routerID: [UInt8], extra: [BGPLSTLV] = []) -> [UInt8] {
        let values = [BGPLSTLV(type: 512, value: uint32Bytes(65_001)), BGPLSTLV(type: 515, value: routerID)] + extra
        return tlvs([BGPLSTLV(type: type, value: tlvs(values.sorted { $0.type < $1.type }))])
    }

    private func tlvs(_ values: [BGPLSTLV]) -> [UInt8] {
        var buffer = ByteBuffer()
        for value in values {
            buffer.writeInteger(value.type)
            buffer.writeInteger(UInt16(value.value.count))
            buffer.writeBytes(value.value)
        }
        return Array(buffer.readableBytesView)
    }

    private func uint32Bytes(_ value: UInt32) -> [UInt8] {
        var buffer = ByteBuffer()
        buffer.writeInteger(value)
        return Array(buffer.readableBytesView)
    }

    private func nlri(type: UInt16, protocolID: UInt8, body: [UInt8]) -> [UInt8] {
        var buffer = ByteBuffer()
        buffer.writeInteger(type)
        buffer.writeInteger(UInt16(9 + body.count))
        buffer.writeInteger(protocolID)
        buffer.writeInteger(UInt64(42))
        buffer.writeBytes(body)
        return Array(buffer.readableBytesView)
    }

    private func update(reachable: Bool, nlris: [UInt8]) -> ByteBuffer {
        var attribute = ByteBuffer()
        attribute.writeInteger(UInt16(16_388))
        attribute.writeInteger(UInt8(71))
        if reachable {
            attribute.writeInteger(UInt8(4))
            attribute.writeBytes([192, 0, 2, 254])
            attribute.writeInteger(UInt8(0))
        }
        attribute.writeBytes(nlris)
        var body = ByteBuffer()
        body.writeInteger(UInt16(0))
        body.writeInteger(UInt16(attribute.readableBytes + 4))
        body.writeInteger(UInt8(0x90))
        body.writeInteger(UInt8(reachable ? 14 : 15))
        body.writeInteger(UInt16(attribute.readableBytes))
        body.writeBuffer(&attribute)
        return body
    }
}
