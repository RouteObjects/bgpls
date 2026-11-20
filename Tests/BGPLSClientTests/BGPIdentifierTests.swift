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
import Testing

struct BGPIdentifierTests {
    @Test(arguments: [UInt32(1), 0xC000_0201, 0xE000_0001, UInt32.max])
    func everyNonzeroBitPatternIsAnIdentifier(raw: UInt32) throws {
        let identifier = try #require(BGPIdentifier(rawValue: raw))
        #expect(identifier.rawValue == raw)
        #expect(BGPIdentifier(identifier.description) == identifier)
    }

    @Test
    func zeroIsNotAnIdentifier() {
        #expect(BGPIdentifier(rawValue: 0) == nil)
        #expect(BGPIdentifier("0.0.0.0") == nil)
    }

    @Test(arguments: [
        "", "0", "1", "4294967295", "4294967296", "0.0.0.0", "000.000.000.000",
        "1.2.3", "1.2.3.4.5", ".1.2.3", "1.2.3.", "1..2.3", "256.1.2.3", "0001.2.3.4",
        "+1.2.3.4", "-1.2.3.4", "1.2.3.+4", "1.2.3.-0", " 1.2.3.4", "1.2.3.4 ",
        "1.2.3.4\n", "１.2.3.4", "1.2.3.4/32", "1.2.3.4/24", "::1", "::ffff:192.0.2.1",
    ])
    func invalidTextIsRejected(text: String) {
        #expect(BGPIdentifier(text) == nil)
    }

    @Test
    func paddingCanonicalizesAndIdentityUsesOnlyBits() throws {
        let first = try #require(BGPIdentifier("192.000.002.001"))
        let equal = try #require(BGPIdentifier("192.0.2.1"))
        let other = try #require(BGPIdentifier("192.0.2.2"))
        #expect(first.description == "192.0.2.1")
        #expect(first == equal)
        #expect(first != other)
        let firstHash = first.hashValue
        let equalHash = equal.hashValue
        #expect(firstHash == equalHash)
        #expect(Set([first]).contains(equal))
        #expect(!Set([first]).contains(other))
        #expect([first: "speaker"][equal] == "speaker")
        #expect([first: "speaker"][other] == nil)
    }
}
