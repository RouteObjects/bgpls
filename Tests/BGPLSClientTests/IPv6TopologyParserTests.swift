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

struct IPv6TopologyParserTests {
    @Test(arguments: [UInt8(0), 1, 7, 8, 9, 63, 64, 65, 127, 128])
    func parsesAndCanonicalizesEveryPrefixBoundary(length: UInt8) throws {
        let count = (Int(length) + 7) / 8
        let reachability = [length] + Array(repeating: UInt8(255), count: count)
        let parsed = try IPv6TopologyFixture.prefix(reachability)
        let prefixLength = try #require(IPv6PrefixLength(rawValue: length))
        let expected = IPv6Network(prefix: UInt128.max, prefixLength: prefixLength)
        #expect(parsed.protocolID == 2)
        #expect(parsed.identifier == 42)
        #expect(parsed.localNode.igpRouterIDString == "0000.0000.0001")
        #expect(parsed.network.prefix == expected.prefix)
        #expect(parsed.network.prefixLength == prefixLength)
        #expect(parsed.network.description == expected.description)
        #expect(parsed.prefixDescriptors == [BGPLSTLV(type: 265, value: reachability)])

        //  Wire padding is retained as evidence, but must not change canonical RIB identity.
        var canonical = parsed
        canonical.prefixDescriptors = []
        #expect(LSRIB.prefixKey(parsed) == LSRIB.prefixKey(canonical))
        var rib = LSRIB()
        rib.apply(BGPLSRecord(nlri: .ipv6Prefix(parsed)))
        rib.withdraw(.ipv6Prefix(canonical))
        #expect(rib.prefixCount == 0)
    }

    @Test
    func preservesFullIPv6HostBitsInNetworkByteOrder() throws {
        let bytes: [UInt8] = [0x20, 1, 0x0d, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        let parsed = try IPv6TopologyFixture.prefix([128] + bytes)
        #expect(parsed.network.prefix == 0x2001_0db8_0102_0304_0506_0708_090a_0b0c)
        #expect(parsed.network.description == "2001:db8:102:304:506:708:90a:b0c/128")
        #expect(parsed.prefixLength == 128)
        #expect(parsed.prefixAddressBits == parsed.network.prefix)
    }

    @Test
    func ipv6TopologyPrefixKeepsOSPFv3RouterIDAsItsFourByteIdentity() throws {
        let router = BGPLSTLV(type: 515, value: [192, 0, 2, 1])
        let local = BGPLSTLV(type: 256, value: IPv6TopologyFixture.encode([router]))
        let reachability = BGPLSTLV(type: 265, value: [64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0])
        let wire = IPv6TopologyFixture.wire(type: 4, descriptors: [local, reachability], protocolID: 6)
        guard case .ipv6Prefix(let prefix) = try IPv6TopologyFixture.parse(wire) else {
            Issue.record("expected typed IPv6 topology prefix")
            return
        }
        //  Prefix family comes from NLRI type 4, not the independently encoded IGP Router-ID.
        #expect(prefix.protocolID == BGPLSProtocolID.ospfv3.rawValue)
        #expect(prefix.localNode.igpRouterID == .ospfRouterID(IPv4Address(address: 0xc000_0201)))
        #expect(prefix.localNode.ipv4RouterID == IPv4Address("192.0.2.1"))
        #expect(prefix.network.description == "2001:db8::/64")
        #expect(
            RIBDiff.upsert(BGPLSRecord(nlri: .ipv6Prefix(prefix))).watchLine
                == "WATCH upsert prefix 2001:db8::/64 node 192.0.2.1"
        )
    }

    @Test(arguments: [UInt8(0), 1, 7, 8, 9, 63, 64, 65, 127, 128])
    func rejectsIncorrectReachabilityPayloadWidth(length: UInt8) {
        let count = (Int(length) + 7) / 8
        let valid = [length] + Array(repeating: UInt8(0), count: count)
        #expect(throws: BGPLSClientError.self) {
            try IPv6TopologyFixture.prefix(valid + [0])
        }
        #expect(throws: BGPLSClientError.self) {
            try IPv6TopologyFixture.prefix(Array(valid.dropLast()))
        }
    }

    @Test
    func rejectsMissingDuplicateAndOutOfRangePrefixDescriptors() {
        let local = IPv6TopologyFixture.nodeDescriptor()
        let valid = BGPLSTLV(type: 265, value: [0])
        for bytes: [UInt8] in [[], [129], [255], [129] + Array(repeating: 0, count: 17)] {
            #expect(throws: BGPLSClientError.self) {
                try IPv6TopologyFixture.prefix(bytes)
            }
        }
        for descriptors in [[local], [valid], [local, local, valid], [local, valid, valid]] {
            #expect(throws: BGPLSClientError.self) {
                try IPv6TopologyFixture.parse(IPv6TopologyFixture.wire(type: 4, descriptors: descriptors))
            }
        }
        for extra in [
            [BGPLSTLV(type: 263, value: [])],
            [BGPLSTLV(type: 263, value: [0])],
            [BGPLSTLV(type: 263, value: [0, 0, 0])],
            [BGPLSTLV(type: 263, value: [0, 0]), BGPLSTLV(type: 263, value: [0, 0])],
            [BGPLSTLV(type: 264, value: [])],
            [BGPLSTLV(type: 264, value: [0, 0])],
            [BGPLSTLV(type: 264, value: [1]), BGPLSTLV(type: 264, value: [1])],
        ] {
            #expect(throws: BGPLSClientError.self) {
                try IPv6TopologyFixture.prefix([0], extra: extra)
            }
        }
    }

    @Test
    func rejectsEveryTruncatedIPv6NLRIWireBoundary() {
        let wire = IPv6TopologyFixture.prefixWire([128] + Array(repeating: 0, count: 16))
        for count in 1..<wire.count {
            #expect(throws: BGPLSClientError.self) {
                try BGPLSNLRIParser.parseAll(ByteBuffer(bytes: wire.prefix(count)))
            }
        }
    }

    @Test
    func paddingCanonicalizesAndWithdrawsOnlyItsIPv6Network() throws {
        let padded = try IPv6TopologyFixture.prefix("2001:db8::ffff:ffff:ffff:ffff/65")
        let canonical = try IPv6TopologyFixture.prefix("2001:db8:0:0:8000::/65")
        let lower = try IPv6TopologyFixture.prefix("2001:db8::/65")
        #expect(padded.network == canonical.network)
        #expect(padded.prefixDescriptors != canonical.prefixDescriptors)
        var rib = LSRIB()
        rib.apply(BGPLSRecord(nlri: .ipv6Prefix(padded)))
        rib.apply(BGPLSRecord(nlri: .ipv6Prefix(lower)))
        rib.withdraw(.ipv6Prefix(canonical))
        #expect(rib.prefixCount == 1)
        #expect(rib.prefixes[LSRIB.prefixKey(lower)]?.nlri == .v6(lower))
        rib.apply(BGPLSRecord(nlri: .ipv6Prefix(canonical)))
        #expect(rib.prefixCount == 2)
    }

    @Test
    func parsesDualStackLinkAndPreservesUnknownDescriptors() throws {
        let unknown = BGPLSTLV(type: 60_001, value: [1, 2, 3])
        let descriptors = [
            BGPLSTLV(type: 262, value: try IPv6TopologyFixture.addressBytes("2001:db8:1::1")),
            BGPLSTLV(type: 260, value: [192, 0, 2, 2]),
            unknown,
            BGPLSTLV(type: 261, value: try IPv6TopologyFixture.addressBytes("2001:db8:1::")),
            BGPLSTLV(type: 259, value: [192, 0, 2, 1]),
            unknown,
            BGPLSTLV(type: 263, value: [0, 0]),
        ]
        let parsed = try IPv6TopologyFixture.link(descriptors)
        #expect(parsed.localIPv4Interface == IPv4Address("192.0.2.1"))
        #expect(parsed.remoteIPv4Neighbor == IPv4Address("192.0.2.2"))
        #expect(parsed.localIPv6Interface == IPv6Address("2001:db8:1::"))
        #expect(parsed.remoteIPv6Neighbor == IPv6Address("2001:db8:1::1"))
        #expect(parsed.localIPv6Interface?.prefixLength == .maximum)
        #expect(parsed.remoteIPv6Neighbor?.prefixLength == .maximum)
        #expect(parsed.linkDescriptors == descriptors)
        let reversed = try IPv6TopologyFixture.link(Array(descriptors.reversed()))
        #expect(LSRIB.linkKey(parsed) == LSRIB.linkKey(reversed))
    }

    @Test
    func parsesIPv6OnlyMissingNeighborAndIdentifierOnlyLinks() throws {
        let local = BGPLSTLV(type: 261, value: try IPv6TopologyFixture.addressBytes("2001:db8::1"))
        let remote = BGPLSTLV(type: 262, value: try IPv6TopologyFixture.addressBytes("2001:db8::2"))
        let both = try IPv6TopologyFixture.link([local, remote])
        #expect(both.localIPv4Interface == nil)
        #expect(both.remoteIPv4Neighbor == nil)
        #expect(both.localIPv6Interface == IPv6Address("2001:db8::1"))
        #expect(both.remoteIPv6Neighbor == IPv6Address("2001:db8::2"))
        let partial = try IPv6TopologyFixture.link([local])
        #expect(partial.localIPv6Interface == both.localIPv6Interface)
        #expect(partial.remoteIPv6Neighbor == nil)

        //  Link-local-only/unnumbered topology uses link IDs; no collector-local zone is invented.
        let identifiers = try IPv6TopologyFixture.link([
            BGPLSTLV(type: 258, value: [0, 0, 0, 7, 0, 0, 0, 9])
        ])
        #expect(identifiers.localLinkIdentifier == 7)
        #expect(identifiers.remoteLinkIdentifier == 9)
        #expect(identifiers.localIPv6Interface == nil)
        #expect(identifiers.remoteIPv6Neighbor == nil)
    }

    @Test(arguments: [UInt16(261), 262])
    func rejectsWrongWidthAndDuplicateIPv6LinkDescriptors(type: UInt16) throws {
        for count in [0, 4, 15, 17, 32] {
            #expect(throws: BGPLSClientError.self) {
                try IPv6TopologyFixture.link([BGPLSTLV(type: type, value: Array(repeating: 0, count: count))])
            }
        }
        let valid = BGPLSTLV(type: type, value: try IPv6TopologyFixture.addressBytes("2001:db8::1"))
        #expect(throws: BGPLSClientError.self) {
            try IPv6TopologyFixture.link([valid, valid])
        }
    }
}
