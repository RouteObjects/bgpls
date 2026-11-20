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
import Foundation
import Testing

struct IGPRouterIDTests {
    @Test
    func systemIDCanonicalTextBytesAndEquality() throws {
        let id = try #require(ISISSystemID("ABCD.0123.EF45"))
        #expect(id.description == "abcd.0123.ef45")
        #expect(id.bytes == [0xab, 0xcd, 0x01, 0x23, 0xef, 0x45])
        #expect(ISISSystemID(bytes: id.bytes) == id)
        #expect(ISISSystemID(id.description) == id)
        #expect(Set([id, try #require(ISISSystemID("abcd.0123.ef45"))]).count == 1)
        #expect(ISISSystemID("0000.0000.0000")?.bytes == Array(repeating: 0, count: 6))
        #expect(ISISSystemID("ffff.ffff.ffff")?.bytes == Array(repeating: 255, count: 6))
    }

    @Test(arguments: [
        "", "abcd0123ef45", "ab:cd:01:23:ef:45", "abc.0123.ef45", "abcde.0123.ef45",
        "abcd.123.ef45", "abcd.0123.ef4", "abcd.0123.ef456", "abcd.0123.ef45.00",
        "abcd.0123.efgg", "+bcd.0123.ef45", "-bcd.0123.ef45", " abcd.0123.ef45",
        "abcd.0123.ef45 ", "abcd.0123.ef45\n", "ａｂｃｄ.0123.ef45", "abcd．0123.ef45",
    ])
    func rejectsNonCanonicalSystemIDGrammar(text: String) {
        #expect(ISISSystemID(text) == nil)
    }

    @Test(arguments: [0, 1, 4, 5, 7, 8, 20])
    func rejectsIncorrectSystemIDByteWidths(count: Int) {
        #expect(ISISSystemID(bytes: Array(repeating: 0, count: count)) == nil)
    }

    @Test
    func pseudonodeCanonicalTextAndBytes() throws {
        let systemID = try #require(ISISSystemID("ABCD.0123.EF45"))
        let id = try #require(ISISPseudonodeID(systemID: systemID, pseudonodeID: 0xaf))
        #expect(id.systemID == systemID)
        #expect(id.pseudonodeID == 0xaf)
        #expect(id.description == "abcd.0123.ef45.af")
        #expect(id.bytes == [0xab, 0xcd, 0x01, 0x23, 0xef, 0x45, 0xaf])
        #expect(ISISPseudonodeID("ABCD.0123.EF45.AF") == id)
        #expect(ISISPseudonodeID(id.description) == id)
        #expect(ISISPseudonodeID(systemID: systemID, pseudonodeID: 0) == nil)
        #expect(ISISPseudonodeID("0000.0000.0000.01")?.pseudonodeID == 1)
        #expect(ISISPseudonodeID("ffff.ffff.ffff.ff")?.pseudonodeID == 255)
    }

    @Test(arguments: [
        "", "abcd.0123.ef45", "abcd.0123.ef45.00", "abcd.0123.ef45.a",
        "abcd.0123.ef45.0af", "abcd.0123.ef45.gg", "abcd.0123.ef45.+1",
        "abcd.0123.ef45.-1", "abcd.0123.ef45.１a", "abcd.0123.ef45.af ",
        " abcd.0123.ef45.af", "abcd.0123.ef45.af\n", "abcd.0123.ef45.af.00",
    ])
    func rejectsInvalidPseudonodes(text: String) {
        #expect(ISISPseudonodeID(text) == nil)
    }

    @Test
    func identityCodableRoundTripsValidateConstruction() throws {
        let systemID = try #require(ISISSystemID("ABCD.0123.EF45"))
        let pseudonode = try #require(ISISPseudonodeID("ABCD.0123.EF45.AF"))
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let encodedSystemID = try encoder.encode(systemID)
        let encodedPseudonode = try encoder.encode(pseudonode)
        #expect(try decoder.decode(ISISSystemID.self, from: encodedSystemID) == systemID)
        #expect(try decoder.decode(ISISPseudonodeID.self, from: encodedPseudonode) == pseudonode)
        #expect(try decoder.decode(String.self, from: encodedSystemID) == "abcd.0123.ef45")
        #expect(try decoder.decode(String.self, from: encodedPseudonode) == "abcd.0123.ef45.af")

        for invalid in ["abcd.0123.ef4", "abcd.0123.ef45.00", "abcd.0123.efgg"] {
            let data = try encoder.encode(invalid)
            #expect(throws: DecodingError.self) {
                try decoder.decode(ISISSystemID.self, from: data)
            }
        }
        for invalid in ["abcd.0123.ef45.00", "abcd.0123.ef45", "abcd.0123.ef45.gg"] {
            let data = try encoder.encode(invalid)
            #expect(throws: DecodingError.self) {
                try decoder.decode(ISISPseudonodeID.self, from: data)
            }
        }
        //  Codable must not bypass the same width/nonzero invariants as public initializers.
        for invalidJSON in ["null", "17", "[0,0,0,0,0]", "{\"bytes\":[0,0,0,0,0,0,0]}"] {
            let data = Data(invalidJSON.utf8)
            #expect(throws: DecodingError.self) {
                try decoder.decode(ISISSystemID.self, from: data)
            }
            #expect(throws: DecodingError.self) {
                try decoder.decode(ISISPseudonodeID.self, from: data)
            }
        }
    }

    @Test
    func routerIdentityPreservesProtocolMeaningAndRawBytes() throws {
        let systemID = try #require(ISISSystemID("1920.0000.2001"))
        let pseudonode = try #require(ISISPseudonodeID("1920.0000.2001.02"))
        let routerID = IPv4Address(address: 0xc000_0201)
        let interfaceAddress = IPv4Address(address: 0xc633_6401)
        let identities: [BGPLSIGPRouterID] = [
            .isisSystemID(systemID),
            .isisPseudonode(pseudonode),
            .ospfRouterID(routerID),
            .ospfv2Pseudonode(routerID: routerID, interfaceAddress: interfaceAddress),
            .ospfv3Pseudonode(routerID: routerID, interfaceID: 37),
            .opaque([0xc0, 0x00, 0x02, 0x01]),
        ]
        let expectedBytes: [[UInt8]] = [
            [0x19, 0x20, 0, 0, 0x20, 1],
            [0x19, 0x20, 0, 0, 0x20, 1, 2],
            [192, 0, 2, 1],
            [192, 0, 2, 1, 198, 51, 100, 1],
            [192, 0, 2, 1, 0, 0, 0, 37],
            [192, 0, 2, 1],
        ]
        #expect(identities.map(\.rawValue) == expectedBytes)
        #expect(Set(identities).count == identities.count)
        #expect(identities[0].description == "1920.0000.2001")
        #expect(identities[1].description == "1920.0000.2001.02")
        #expect(identities[2].description == "192.0.2.1")
        #expect(identities[3].description == "192.0.2.1:198.51.100.1")
        #expect(identities[4].description == "192.0.2.1:37")
        #expect(identities[5].description == "opaque:c0000201")
        #expect(identities[0].ipv4RouterID == nil)
        #expect(identities[1].ipv4RouterID == nil)
        #expect(identities[2].ipv4RouterID == routerID)
        #expect(identities[3].ipv4RouterID == routerID)
        #expect(identities[4].ipv4RouterID == routerID)
        #expect(identities[5].ipv4RouterID == nil)
        for identity in identities {
            #expect(
                try JSONDecoder().decode(BGPLSIGPRouterID.self, from: JSONEncoder().encode(identity)) == identity
            )
        }
    }
}
