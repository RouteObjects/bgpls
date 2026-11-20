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

struct BGPOpenCapabilitiesTests {
    @Test(arguments: [UInt32(1), 65_001, 65_535, 65_536, 4_200_000_001, UInt32.max])
    func combinedCapabilitiesCarryRealASN(raw: UInt32) throws {
        let asn = AutonomousSystemNumber(raw)
        let parsed = try BGPOpenCapabilities.parse(BGPOpenCapabilities.bgpLS(localAS: asn))
        #expect(parsed.fourOctetAS == asn)
        #expect(parsed.supportsBGPLS)
        let expectedLegacy = raw <= UInt16.max ? UInt16(raw) : 23_456
        #expect(BGPOpenCapabilities.legacyAS(for: asn) == expectedLegacy)
    }

    @Test
    func legacyAndEmptyOptionalParametersHaveNoAS4Capability() throws {
        #expect(try BGPOpenCapabilities.parse([]).fourOctetAS == nil)
        #expect(try BGPOpenCapabilities.parse(BGPOpenCapabilities.multiprotocolBGPLS()).fourOctetAS == nil)
        #expect(try BGPOpenCapabilities.parse(BGPOpenCapabilities.multiprotocolBGPLS()).supportsBGPLS)
    }

    @Test(arguments: [
        [UInt8](),
        [2, 6, 65, 4, 0, 0, 253, 233],
        [2, 2, 200, 0],
        [2, 6, 1, 4, 0, 1, 0, 1],
        [2, 6, 1, 4, 0, 2, 0, 71],
        [2, 6, 1, 4, 0x40, 4, 0, 1],
        [2, 6, 1, 4, 0x40, 4, 0, 72],
    ])
    func unrelatedCapabilitiesDoNotAdvertiseBGPLS(parameters: [UInt8]) throws {
        #expect(try !BGPOpenCapabilities.parse(parameters).supportsBGPLS)
    }

    @Test(arguments: [UInt8(0), 1, 255], [false, true])
    func requiredFamilySurvivesDuplicatesAndUnrelatedFamilies(reserved: UInt8, split: Bool) throws {
        let required: [UInt8] = [1, 4, 0x40, 4, reserved, 71]
        let unrelated: [UInt8] = [1, 4, 0, 1, 0, 1]
        let unknown: [UInt8] = [200, 0]
        for values in [
            [required, unrelated],
            [unrelated, required],
            [required, unrelated, unknown, required],
            [unrelated, required, required, unknown],
        ] {
            let parameters: [UInt8]
            if split {
                parameters = values.flatMap { [2, UInt8($0.count)] + $0 }
            } else {
                let bytes = values.flatMap { $0 }
                parameters = [2, UInt8(bytes.count)] + bytes
            }
            #expect(try BGPOpenCapabilities.parse(parameters).supportsBGPLS)
        }
    }

    @Test(arguments: [
        [UInt8(2)],
        [2, 6, 1, 4, 0x40],
        [2, 1, 1],
        [2, 5, 1, 3, 0x40, 4, 71],
        [2, 5, 65, 3, 0, 0, 1],
        [99, 0],
        [2, 12, 65, 4, 0, 0, 253, 233, 65, 4, 0, 1, 0, 0],
    ])
    func validCapabilityDoesNotHideLaterMalformedData(trailing: [UInt8]) {
        let parameters = BGPOpenCapabilities.multiprotocolBGPLS() + trailing
        #expect(throws: (any Error).self) { try BGPOpenCapabilities.parse(parameters) }
    }

    @Test
    func identicalDuplicatesAndMultipleParameterBlocksAreAccepted() throws {
        let capability: [UInt8] = [65, 4, 250, 86, 234, 1]
        let singleBlock = [2, 12] + capability + capability
        let splitBlocks = [2, 6] + capability + [2, 6] + capability
        let expected = AutonomousSystemNumber(4_200_000_001)
        #expect(try BGPOpenCapabilities.parse(singleBlock).fourOctetAS == expected)
        #expect(try BGPOpenCapabilities.parse(splitBlocks).fourOctetAS == expected)
        let withMP = BGPOpenCapabilities.multiprotocolBGPLS() + splitBlocks
        #expect(try BGPOpenCapabilities.parse(withMP).fourOctetAS == expected)
    }

    @Test
    func unknownCapabilitiesAreIgnoredWithoutLosingAS4() throws {
        // Unknown empty and nonempty capability values are both correctly framed.
        let parameters: [UInt8] = [2, 13, 200, 0, 65, 4, 0, 1, 0, 0, 201, 3, 1, 2, 3]
        #expect(try BGPOpenCapabilities.parse(parameters).fourOctetAS == AutonomousSystemNumber(65_536))
    }

    @Test(arguments: [
        [UInt8(2)],
        [2, 6, 65, 4, 0],
        [2, 1, 65],
        [2, 4, 65, 4, 0, 0],
        [2, 0],
        [2, 2, 65, 0],
        [2, 5, 65, 3, 0, 0, 1],
        [2, 7, 65, 5, 0, 0, 0, 0, 1],
        [2, 5, 1, 3, 0x40, 4, 71],
        [2, 7, 1, 5, 0x40, 4, 0, 71, 0],
        [2, 3, 200, 2, 0],
        [99, 0],
    ])
    func malformedOrUnsupportedParametersAreRejected(bytes: [UInt8]) {
        #expect(throws: (any Error).self) { try BGPOpenCapabilities.parse(bytes) }
    }

    @Test(arguments: [false, true])
    func conflictingAS4IdentitiesAreRejectedRegardlessOfOrder(reverse: Bool) {
        let first: [UInt8] = [2, 6, 65, 4, 0, 0, 253, 233]
        let second: [UInt8] = [2, 6, 65, 4, 0, 1, 0, 0]
        let parameters = reverse ? second + first : first + second
        #expect(throws: BGPLSClientError.protocolError("conflicting four-octet AS capabilities")) {
            try BGPOpenCapabilities.parse(parameters)
        }
    }
}
