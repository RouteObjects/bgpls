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
import NIOCore
import Testing

@testable import BGPLSClient

struct BGPLSIdentityKeyTests {
    @Test
    func isisSystemAndPseudonodeIdentifiersDoNotCollide() throws {
        let identifiers: [[UInt8]] = [
            [0, 0, 0, 0, 0, 1],
            [0, 0, 0, 0, 0, 2],
            [0, 0, 0, 0, 0, 1, 1],
            [0, 0, 0, 0, 0, 1, 2],
        ]
        var rib = LSRIB()
        for identifier in identifiers {
            rib.apply(BGPLSRecord(nlri: .node(try node(routerID: identifier))))
        }
        #expect(rib.nodeCount == identifiers.count)
    }

    @Test
    func nodesIncludeProtocolInstanceASAreaAndUnknownDescriptors() throws {
        let base = try node()
        var variants = [base]
        var changed = base
        changed.protocolID = 1
        variants.append(changed)
        changed = base
        changed.identifier = 1
        variants.append(changed)
        changed = base
        changed.localNode.autonomousSystem = AutonomousSystemNumber(65_002)
        variants.append(changed)
        changed = base
        changed.localNode.ospfAreaID = OSPFAreaID(1)
        variants.append(changed)
        changed = base
        changed.localNode.ospfAreaID = nil
        variants.append(changed)
        changed = base
        changed.localNode.rawTLVs.append(BGPLSTLV(type: 65_000, value: [1]))
        variants.append(changed)

        var rib = LSRIB()
        for variant in variants { rib.apply(BGPLSRecord(nlri: .node(variant))) }
        #expect(rib.nodeCount == variants.count)
    }

    @Test
    func linksKeepCompleteLocalAndRemoteDomainDescriptors() throws {
        let base = try link()
        var variants = [base]
        var changed = base
        changed.protocolID = 1
        variants.append(changed)
        changed = base
        changed.identifier = 1
        variants.append(changed)
        changed = base
        changed.localNode.autonomousSystem = AutonomousSystemNumber(65_002)
        variants.append(changed)
        changed = base
        changed.remoteNode.autonomousSystem = AutonomousSystemNumber(65_002)
        variants.append(changed)
        changed = base
        changed.localNode.ospfAreaID = OSPFAreaID(1)
        variants.append(changed)
        changed = base
        changed.remoteNode.ospfAreaID = OSPFAreaID(1)
        variants.append(changed)
        changed = base
        changed.localNode.igpRouterID = try node(routerID: [0, 0, 0, 0, 0, 3]).localNode.igpRouterID
        variants.append(changed)
        changed = base
        changed.remoteNode.igpRouterID = try node(routerID: [0, 0, 0, 0, 0, 3]).localNode.igpRouterID
        variants.append(changed)
        changed = base
        changed.localNode.rawTLVs.append(BGPLSTLV(type: 65_000, value: [1]))
        variants.append(changed)
        changed = base
        changed.remoteNode.rawTLVs.append(BGPLSTLV(type: 65_000, value: [1]))
        variants.append(changed)

        var rib = LSRIB()
        for variant in variants { rib.apply(BGPLSRecord(nlri: .link(variant))) }
        #expect(rib.linkCount == variants.count)
    }

    @Test
    func unnumberedLinksAndPartialProgrammaticIdentifiersRemainDistinct() throws {
        let first = try link(descriptors: [BGPLSTLV(type: 258, value: [0, 0, 0, 10, 0, 0, 0, 20])])
        let second = try link(descriptors: [BGPLSTLV(type: 258, value: [0, 0, 0, 11, 0, 0, 0, 21])])
        let absent = try link(descriptors: [])
        var localOnly = absent
        localOnly.localLinkIdentifier = 0
        var remoteOnly = absent
        remoteOnly.remoteLinkIdentifier = 0
        var bothZero = localOnly
        bothZero.remoteLinkIdentifier = 0
        let variants = [first, second, absent, localOnly, remoteOnly, bothZero]
        var rib = LSRIB()
        for variant in variants { rib.apply(BGPLSRecord(nlri: .link(variant))) }
        #expect(rib.linkCount == variants.count)
    }

    @Test
    func prefixesIncludeNodeDomainAndRouteTypeDescriptors() throws {
        let base = try prefix()
        var variants = [base]
        var changed = base
        changed.protocolID = 1
        variants.append(changed)
        changed = base
        changed.identifier = 1
        variants.append(changed)
        changed = base
        changed.localNode.autonomousSystem = AutonomousSystemNumber(65_002)
        variants.append(changed)
        changed = base
        changed.localNode.ospfAreaID = OSPFAreaID(1)
        variants.append(changed)
        changed = base
        changed.localNode.igpRouterID = try node(routerID: [0, 0, 0, 0, 0, 3]).localNode.igpRouterID
        variants.append(changed)
        changed = base
        changed.prefixDescriptors.append(BGPLSTLV(type: 264, value: [1]))
        variants.append(changed)
        changed = base
        changed.prefixDescriptors.append(BGPLSTLV(type: 264, value: [2]))
        variants.append(changed)
        changed = base
        changed.prefixDescriptors.append(BGPLSTLV(type: 65_000, value: [1]))
        variants.append(changed)

        var rib = LSRIB()
        for variant in variants { rib.apply(BGPLSRecord(nlri: .ipv4Prefix(variant))) }
        #expect(rib.prefixCount == variants.count)
    }

    @Test(arguments: [UInt8(1), UInt8(2)])
    func isisTopologyReservedBitsAreIgnoredButTopologyIDsRemainDistinct(protocolID: UInt8) throws {
        var baseLink = try link(descriptors: [BGPLSTLV(type: 263, value: [0, 1])])
        baseLink.protocolID = protocolID
        var reservedLink = baseLink
        reservedLink.linkDescriptors = [BGPLSTLV(type: 263, value: [0xf0, 1])]
        var differentLink = baseLink
        differentLink.linkDescriptors = [BGPLSTLV(type: 263, value: [0, 2])]
        #expect(LSRIB.linkKey(baseLink) == LSRIB.linkKey(reservedLink))
        #expect(LSRIB.linkKey(baseLink) != LSRIB.linkKey(differentLink))

        var basePrefix = try prefix(extra: [BGPLSTLV(type: 263, value: [0, 1])])
        basePrefix.protocolID = protocolID
        var reservedPrefix = basePrefix
        reservedPrefix.prefixDescriptors = [BGPLSTLV(type: 263, value: [0xf0, 1])]
        var differentPrefix = basePrefix
        differentPrefix.prefixDescriptors = [BGPLSTLV(type: 263, value: [0, 2])]
        #expect(LSRIB.prefixKey(basePrefix) == LSRIB.prefixKey(reservedPrefix))
        #expect(LSRIB.prefixKey(basePrefix) != LSRIB.prefixKey(differentPrefix))
    }

    @Test
    func typedIPv6LinkDescriptorsAndNonISISReservedBitsRemainDistinct() throws {
        let address: [UInt8] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        let base = try link(descriptors: [BGPLSTLV(type: 261, value: address)])
        var changedValue = base
        let changedAddress = try #require(IPv6Address("2001:db8::2"))
        changedValue.localIPv6Interface = changedAddress
        var changedType = base
        changedType.localIPv6Interface = nil
        changedType.remoteIPv6Neighbor = base.localIPv6Interface
        #expect(LSRIB.linkKey(base) != LSRIB.linkKey(changedValue))
        #expect(LSRIB.linkKey(base) != LSRIB.linkKey(changedType))

        var ospfLink = try link(descriptors: [BGPLSTLV(type: 263, value: [0, 1])])
        ospfLink.protocolID = BGPLSProtocolID.ospfv2.rawValue
        var changedOSPFLink = ospfLink
        changedOSPFLink.linkDescriptors[0].value[0] = 0xf0
        #expect(LSRIB.linkKey(ospfLink) != LSRIB.linkKey(changedOSPFLink))
    }

    @Test(arguments: [UInt8(0), 1, 7, 8, 9, 25, 31, 32])
    func prefixKeysUseCIDRCanonicalNetworkAtEveryByteBoundary(length: UInt8) throws {
        let octetCount = (Int(length) + 7) / 8
        let advertised = try prefix(reachability: [length] + Array(repeating: UInt8(255), count: octetCount))
        var canonical = advertised
        canonical.prefixDescriptors = []
        #expect(LSRIB.prefixKey(advertised) == LSRIB.prefixKey(canonical))
    }

    @Test
    func descriptorOrderingDoesNotChangeKeysAndFramingDoesNotCollide() throws {
        let extras = [BGPLSTLV(type: 65_000, value: [1, 2]), BGPLSTLV(type: 65_001, value: [3])]
        var originalNode = try node()
        originalNode.localNode.rawTLVs += extras
        var reorderedNode = originalNode
        reorderedNode.localNode.rawTLVs.reverse()
        #expect(LSRIB.nodeKey(originalNode) == LSRIB.nodeKey(reorderedNode))

        let originalLink = try link(descriptors: extras)
        var reorderedLink = originalLink
        reorderedLink.linkDescriptors.reverse()
        #expect(LSRIB.linkKey(originalLink) == LSRIB.linkKey(reorderedLink))

        let originalPrefix = try prefix(extra: extras)
        var reorderedPrefix = originalPrefix
        reorderedPrefix.prefixDescriptors.reverse()
        #expect(LSRIB.prefixKey(originalPrefix) == LSRIB.prefixKey(reorderedPrefix))

        let regrouped = [BGPLSTLV(type: 65_000, value: [1]), BGPLSTLV(type: 65_001, value: [2, 3])]
        let differentLink = try link(descriptors: regrouped)
        let differentPrefix = try prefix(extra: regrouped)
        #expect(LSRIB.linkKey(originalLink) != LSRIB.linkKey(differentLink))
        #expect(LSRIB.prefixKey(originalPrefix) != LSRIB.prefixKey(differentPrefix))
        let differentTypes = try link(descriptors: [BGPLSTLV(type: 65_002, value: [1, 2, 3])])
        #expect(LSRIB.linkKey(originalLink) != LSRIB.linkKey(differentTypes))
    }

    @Test
    func repeatedUnknownDescriptorsSortByTypeThenLengthThenValue() throws {
        let unknown = [
            BGPLSTLV(type: 65_001, value: []),
            BGPLSTLV(type: 65_000, value: [0, 0]),
            BGPLSTLV(type: 65_000, value: [255]),
            BGPLSTLV(type: 65_000, value: [1]),
            BGPLSTLV(type: 65_000, value: [1]),
        ]
        let sorted = "65000:1:01;65000:1:01;65000:1:ff;65000:2:0000;65001:0:;"
        var originalNode = try node()
        originalNode.localNode.rawTLVs += unknown
        var reorderedNode = originalNode
        reorderedNode.localNode.rawTLVs.reverse()
        #expect(LSRIB.nodeKey(originalNode).contains(sorted))
        #expect(LSRIB.nodeKey(originalNode) == LSRIB.nodeKey(reorderedNode))

        let originalLink = try link(descriptors: unknown)
        var reorderedLink = originalLink
        reorderedLink.linkDescriptors.reverse()
        #expect(LSRIB.linkKey(originalLink).contains(sorted))
        #expect(LSRIB.linkKey(originalLink) == LSRIB.linkKey(reorderedLink))

        let originalPrefix = try prefix(extra: unknown)
        var reorderedPrefix = originalPrefix
        reorderedPrefix.prefixDescriptors.reverse()
        #expect(LSRIB.prefixKey(originalPrefix).contains(sorted))
        #expect(LSRIB.prefixKey(originalPrefix) == LSRIB.prefixKey(reorderedPrefix))
    }

    @Test
    func additionalNodeDescriptorsAreDistinctFromLocalSubTLVsAndKeepRepeatedValues() throws {
        let extra = [
            BGPLSTLV(type: 65_000, value: [0, 0]),
            BGPLSTLV(type: 65_000, value: [255]),
            BGPLSTLV(type: 65_000, value: [255]),
        ]
        guard
            case .node(let original) = try parse(
                type: 1,
                descriptors: [nodeDescriptor(256, [0, 0, 0, 0, 0, 1])] + extra
            )
        else {
            throw FixtureError.unexpectedNLRI
        }
        #expect(original.additionalDescriptors == extra)
        #expect(LSRIB.nodeKey(original).contains("additional[65000:1:ff;65000:1:ff;65000:2:0000;]"))
        var reordered = original
        reordered.additionalDescriptors.reverse()
        #expect(LSRIB.nodeKey(original) == LSRIB.nodeKey(reordered))

        var localOnly = original
        localOnly.additionalDescriptors = []
        localOnly.localNode.rawTLVs += extra
        var oneLessOccurrence = original
        oneLessOccurrence.additionalDescriptors.removeLast()
        let missing = try node()
        var rib = LSRIB()
        for node in [original, localOnly, oneLessOccurrence, missing] { rib.apply(BGPLSRecord(nlri: .node(node))) }
        #expect(rib.nodeCount == 4)
        rib.withdraw(.node(reordered))
        #expect(rib.nodeCount == 3)
        #expect(rib.nodes[LSRIB.nodeKey(original)] == nil)
        #expect(rib.nodes[LSRIB.nodeKey(localOnly)] != nil)
    }

    @Test
    func mutableTypedDescriptorsOverrideAndRemoveStaleRawCopies() throws {
        var modifiedNode = try node()
        modifiedNode.localNode.autonomousSystem = nil
        modifiedNode.localNode.ospfAreaID = OSPFAreaID(99)
        modifiedNode.localNode.igpRouterID = try node(routerID: [0, 0, 0, 0, 0, 3]).localNode.igpRouterID
        var cleanNode = modifiedNode
        cleanNode.localNode.rawTLVs = []
        #expect(LSRIB.nodeKey(modifiedNode) == LSRIB.nodeKey(cleanNode))
        modifiedNode.localNode.igpRouterID = nil
        cleanNode.localNode.igpRouterID = nil
        #expect(LSRIB.nodeKey(modifiedNode) == LSRIB.nodeKey(cleanNode))

        var modifiedLink = try link()
        modifiedLink.localIPv4Interface = nil
        modifiedLink.remoteIPv4Neighbor = IPv4Address(address: 0xc000_0203)
        var cleanLink = modifiedLink
        cleanLink.linkDescriptors = []
        #expect(LSRIB.linkKey(modifiedLink) == LSRIB.linkKey(cleanLink))
        var identifiers = try link(descriptors: [BGPLSTLV(type: 258, value: [0, 0, 0, 10, 0, 0, 0, 20])])
        identifiers.localLinkIdentifier = nil
        identifiers.remoteLinkIdentifier = nil
        let noIdentifiers = try link(descriptors: [])
        #expect(LSRIB.linkKey(identifiers) == LSRIB.linkKey(noIdentifiers))

        var modifiedPrefix = try prefix()
        modifiedPrefix.network = try #require(IPv4Network("198.51.100.129/25"))
        var cleanPrefix = modifiedPrefix
        cleanPrefix.prefixDescriptors = []
        #expect(LSRIB.prefixKey(modifiedPrefix) == LSRIB.prefixKey(cleanPrefix))
    }

    @Test
    func deprecatedIdentifierDoesNotAffectAnyObjectKey() throws {
        let baseNode = try node()
        var changedNode = baseNode
        changeDeprecatedIdentifier(&changedNode.localNode)
        #expect(LSRIB.nodeKey(baseNode) == LSRIB.nodeKey(changedNode))

        let baseLink = try link()
        var changedLink = baseLink
        changeDeprecatedIdentifier(&changedLink.localNode)
        changeDeprecatedIdentifier(&changedLink.remoteNode)
        #expect(LSRIB.linkKey(baseLink) == LSRIB.linkKey(changedLink))

        let basePrefix = try prefix()
        var changedPrefix = basePrefix
        changeDeprecatedIdentifier(&changedPrefix.localNode)
        #expect(LSRIB.prefixKey(basePrefix) == LSRIB.prefixKey(changedPrefix))
    }

    @Test
    func canonicalWithdrawalsAndReadvertisementsTargetExactlyOneObject() throws {
        let nodeOne = try node()
        let nodeTwo = try node(routerID: [0, 0, 0, 0, 0, 2])
        let linkOne = try link(descriptors: [BGPLSTLV(type: 263, value: [0, 1])])
        let linkTwo = try link(descriptors: [BGPLSTLV(type: 263, value: [0, 2])])
        let prefixOne = try prefix(reachability: [25, 192, 0, 2, 255])
        let prefixTwo = try prefix(reachability: [25, 192, 0, 2, 0])
        var rib = LSRIB()
        for nlri: BGPLSNLRI in [
            .node(nodeOne), .node(nodeTwo), .link(linkOne), .link(linkTwo),
            .ipv4Prefix(prefixOne), .ipv4Prefix(prefixTwo),
        ] {
            rib.apply(BGPLSRecord(nlri: nlri))
        }
        #expect(rib.summaryLine == "nodes=2 links=2 prefixes=2")
        var equivalentNode = nodeOne
        equivalentNode.localNode.rawTLVs.reverse()
        changeDeprecatedIdentifier(&equivalentNode.localNode)
        var equivalentLink = linkOne
        equivalentLink.linkDescriptors = [BGPLSTLV(type: 263, value: [0xf0, 1])]
        let equivalentPrefix = try prefix(reachability: [25, 192, 0, 2, 128])
        rib.withdraw(.node(equivalentNode))
        rib.withdraw(.link(equivalentLink))
        rib.withdraw(.ipv4Prefix(equivalentPrefix))
        #expect(rib.summaryLine == "nodes=1 links=1 prefixes=1")
        rib.apply(BGPLSRecord(nlri: .node(equivalentNode)))
        rib.apply(BGPLSRecord(nlri: .link(equivalentLink)))
        rib.apply(BGPLSRecord(nlri: .ipv4Prefix(equivalentPrefix)))
        #expect(rib.summaryLine == "nodes=2 links=2 prefixes=2")
        rib.apply(BGPLSRecord(nlri: .node(nodeOne)))
        rib.apply(BGPLSRecord(nlri: .link(linkOne)))
        rib.apply(BGPLSRecord(nlri: .ipv4Prefix(prefixOne)))
        #expect(rib.summaryLine == "nodes=2 links=2 prefixes=2")
    }

    private func changeDeprecatedIdentifier(_ identity: inout BGPLSNodeIdentity) {
        identity.bgpLSIdentifier = 99
        identity.rawTLVs.append(BGPLSTLV(type: 513, value: [0, 0, 0, 99]))
    }

    private func node(routerID: [UInt8] = [0, 0, 0, 0, 0, 1]) throws -> BGPLSNodeNLRI {
        guard case .node(let result) = try parse(type: 1, descriptors: [nodeDescriptor(256, routerID)]) else {
            throw FixtureError.unexpectedNLRI
        }
        return result
    }

    private func link(
        descriptors: [BGPLSTLV] = [
            BGPLSTLV(type: 259, value: [192, 0, 2, 1]),
            BGPLSTLV(type: 260, value: [192, 0, 2, 2]),
        ]
    ) throws -> BGPLSLinkNLRI {
        let nodes = [nodeDescriptor(256, [0, 0, 0, 0, 0, 1]), nodeDescriptor(257, [0, 0, 0, 0, 0, 2])]
        guard case .link(let result) = try parse(type: 2, descriptors: nodes + descriptors) else {
            throw FixtureError.unexpectedNLRI
        }
        return result
    }

    private func prefix(
        reachability: [UInt8] = [24, 192, 0, 2],
        extra: [BGPLSTLV] = []
    ) throws -> BGPLSIPv4PrefixNLRI {
        let descriptors = [nodeDescriptor(256, [0, 0, 0, 0, 0, 1]), BGPLSTLV(type: 265, value: reachability)]
        guard case .ipv4Prefix(let result) = try parse(type: 3, descriptors: descriptors + extra) else {
            throw FixtureError.unexpectedNLRI
        }
        return result
    }

    private func nodeDescriptor(_ type: UInt16, _ routerID: [UInt8]) -> BGPLSTLV {
        let fields = [
            BGPLSTLV(type: 512, value: [0, 0, 253, 233]),
            BGPLSTLV(type: 514, value: [0, 0, 0, 0]),
            BGPLSTLV(type: 515, value: routerID),
        ]
        return BGPLSTLV(type: type, value: Array(encode(fields).readableBytesView))
    }

    private func parse(type: UInt16, descriptors: [BGPLSTLV]) throws -> BGPLSNLRI {
        var body = ByteBuffer()
        body.writeInteger(UInt8(2))
        body.writeInteger(UInt64(0))
        var descriptorBuffer = encode(descriptors)
        body.writeBuffer(&descriptorBuffer)
        var wire = ByteBuffer()
        wire.writeInteger(type)
        wire.writeInteger(UInt16(body.readableBytes))
        wire.writeBuffer(&body)
        return try BGPLSNLRIParser.parseOne(&wire)
    }

    private func encode(_ descriptors: [BGPLSTLV]) -> ByteBuffer {
        var buffer = ByteBuffer()
        for descriptor in descriptors {
            buffer.writeInteger(descriptor.type)
            buffer.writeInteger(UInt16(descriptor.value.count))
            buffer.writeBytes(descriptor.value)
        }
        return buffer
    }

    private enum FixtureError: Error {
        case unexpectedNLRI
    }
}
