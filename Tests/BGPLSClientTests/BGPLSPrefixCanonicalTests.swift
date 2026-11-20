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
import Testing

@testable import BGPLSClient

struct BGPLSPrefixCanonicalTests {
    @Test
    func ipv4ConstructionAndReassignmentAlwaysStoreCanonicalNetworks() throws {
        let cases: [(Int, UInt32)] = [(0, 0), (25, 0xc000_0280), (32, 0xc000_02ff)]
        for (length, expected) in cases {
            let prefixLength = try #require(IPv4PrefixLength(length))
            assertCanonicalStorage(
                raw: UInt32(0xc000_02ff), prefixLength: prefixLength, expected: expected,
                erase: AnyBGPLSPrefixNLRI.v4
            )
        }
    }

    @Test
    func ipv6ConstructionAndReassignmentAlwaysStoreCanonicalNetworks() throws {
        let raw: UInt128 = 0x2001_0db8_0000_0000_ffff_ffff_ffff_ffff
        let cases: [(Int, UInt128)] = [
            (0, 0), (65, 0x2001_0db8_0000_0000_8000_0000_0000_0000), (128, raw),
        ]
        for (length, expected) in cases {
            let prefixLength = try #require(IPv6PrefixLength(length))
            assertCanonicalStorage(
                raw: raw, prefixLength: prefixLength, expected: expected,
                erase: AnyBGPLSPrefixNLRI.v6
            )
        }
    }

    @Test
    func ipv4StructuralEvidenceRemainsDistinctFromCanonicalRIBIdentity() throws {
        let original = try IPv6TopologyFixture.parse(
            IPv6TopologyFixture.prefixWire([1, 0x80], type: 3, extra: Self.extraDescriptors)
        )
        guard case .ipv4Prefix(let prefix) = original else {
            Issue.record("expected IPv4 prefix")
            return
        }
        assertEvidenceIdentity(prefix, wrap: BGPLSNLRI.ipv4Prefix, erase: AnyBGPLSPrefixNLRI.v4)
    }

    @Test
    func ipv6StructuralEvidenceRemainsDistinctFromCanonicalRIBIdentity() throws {
        let prefix = try IPv6TopologyFixture.prefix([1, 0x80], extra: Self.extraDescriptors)
        assertEvidenceIdentity(prefix, wrap: BGPLSNLRI.ipv6Prefix, erase: AnyBGPLSPrefixNLRI.v6)
    }

    private static let extraDescriptors = [
        BGPLSTLV(type: 263, value: [0, 1]), BGPLSTLV(type: 60_000, value: [7]),
    ]

    private func assertCanonicalStorage<Family: IPAddressFamily>(
        raw: Family.Storage, prefixLength: PrefixLength<Family>, expected: Family.Storage,
        erase: (BGPLSPrefixNLRI<Family>) -> AnyBGPLSPrefixNLRI
    ) {
        let evidence = [BGPLSTLV(type: 60_000, value: [1, 2, 3])]
        let network = IPNetwork<Family>(prefix: raw, prefixLength: prefixLength)
        let original = BGPLSPrefixNLRI(
            protocolID: 2, identifier: 42, localNode: BGPLSNodeIdentity(),
            network: network, prefixDescriptors: evidence
        )
        #expect(original.network.prefix == expected)
        #expect(original.network.prefixLength == prefixLength)
        #expect(original.prefixAddressBits == expected)
        #expect(original.prefixLength == prefixLength.rawValue)
        #expect(original.prefixDescriptors == evidence)

        var reassigned = original
        let maximum = PrefixLength<Family>.maximum
        reassigned.network = IPNetwork(prefix: 1, prefixLength: maximum)
        #expect(reassigned.network.prefix == 1)
        #expect(reassigned.prefixLength == maximum.rawValue)
        #expect(reassigned != original)
        reassigned.network = IPNetwork(host: IPAddress(address: raw, prefixLength: prefixLength))
        #expect(reassigned == original)
        #expect(reassigned.prefixDescriptors == evidence)
        let originalHash = original.hashValue
        let reassignedHash = reassigned.hashValue
        #expect(originalHash == reassignedHash)
        #expect(Set([original]).contains(reassigned))
        #expect([original: "canonical"][reassigned] == "canonical")

        let erased = erase(original)
        let erasedReassigned = erase(reassigned)
        #expect(erased == erasedReassigned)
        #expect(erased.network.description == network.description)
        #expect(erased.prefixDescriptors == evidence)
        let erasedHash = erased.hashValue
        let erasedReassignedHash = erasedReassigned.hashValue
        #expect(erasedHash == erasedReassignedHash)
        #expect(Set([erased]).contains(erasedReassigned))
        #expect([erased: "canonical"][erasedReassigned] == "canonical")
    }

    private func assertEvidenceIdentity<Family: IPAddressFamily>(
        _ original: BGPLSPrefixNLRI<Family>, wrap: (BGPLSPrefixNLRI<Family>) -> BGPLSNLRI,
        erase: (BGPLSPrefixNLRI<Family>) -> AnyBGPLSPrefixNLRI
    ) {
        var padding = original
        padding.prefixDescriptors[0].value = [1, 0xff]
        var reordered = original
        reordered.prefixDescriptors.reverse()
        reordered.localNode.rawTLVs.reverse()
        var reserved = original
        reserved.prefixDescriptors[1].value = [0xf0, 1]
        var ignored = original
        ignored.localNode.bgpLSIdentifier = 7
        ignored.localNode.rawTLVs.append(BGPLSTLV(type: 513, value: [0, 0, 0, 7]))

        for changed in [padding, reordered, reserved, ignored] {
            //  Canonical topology identity deliberately ignores some retained evidence;
            // structural equality must continue to distinguish those complete observations.
            #expect(changed != original)
            #expect(changed.network == original.network)
            #expect(!Set([original]).contains(changed))
            #expect([original: "observed"][changed] == nil)
            let erased = erase(original)
            let erasedChanged = erase(changed)
            #expect(erasedChanged != erased)
            #expect(!Set([erased]).contains(erasedChanged))
            #expect([erased: "observed"][erasedChanged] == nil)
            #expect(erasedChanged.prefixDescriptors == changed.prefixDescriptors)

            var rib = LSRIB()
            rib.apply(BGPLSRecord(nlri: wrap(original)))
            let originalKey = rib.prefixes.keys.first
            rib.apply(BGPLSRecord(nlri: wrap(changed)))
            #expect(rib.prefixCount == 1)
            #expect(rib.prefixes.keys.first == originalKey)
            #expect(rib.prefixes.values.map(\.nlri).first == erasedChanged)
            rib.withdraw(wrap(original))
            #expect(rib.prefixCount == 0)
            rib.apply(BGPLSRecord(nlri: wrap(original)))
            rib.withdraw(wrap(changed))
            #expect(rib.prefixCount == 0)
        }
    }
}
