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

struct BGPLSNLRIRecoveryTests {
    private static let valid4 = IPv6TopologyFixture.prefixWire([24, 192, 0, 2], type: 3)
    private static let valid6 = IPv6TopologyFixture.prefixWire([32, 0x20, 1, 0x0d, 0xb8])
    private static let invalid6 = IPv6TopologyFixture.prefixWire([129] + Array(repeating: 0, count: 17))

    @Test(arguments: [0, 1, 2], [true, false])
    func isolatesFirstMiddleAndLastContentFailureInEitherField(index: Int, reachable: Bool) throws {
        var frames = [Self.valid4, Self.valid6]
        frames.insert(Self.invalid6, at: index)
        let update = Self.update(
            reach: reachable ? frames.flatMap { $0 } : nil,
            unreach: reachable ? nil : frames.flatMap { $0 })
        let good = try BGPLSNLRIParser.parseAll(ByteBuffer(bytes: Self.valid4 + Self.valid6))
        var strict = try Self.seededRIB()
        let beforeStrict = strict
        #expect(throws: BGPLSClientError.self) { try strict.apply(update: update) }
        #expect(strict == beforeStrict)
        var rib = LSRIB()
        if !reachable {
            for nlri in good { rib.apply(BGPLSRecord(nlri: nlri)) }
        }
        let result = try rib.applyIsolating(update: update)
        #expect(rib.prefixCount == (reachable ? 2 : 0))
        #expect(result.diffs == good.map { reachable ? .upsert(BGPLSRecord(nlri: $0)) : .withdraw($0) })
        let diagnostic = try #require(nlriDiagnostics(result.diagnostics).first)
        #expect(result.diagnostics.count == 1)
        #expect(diagnostic.field == (reachable ? .mpReach : .mpUnreach))
        #expect(diagnostic.diagnostic.disposition == .discarded)
        #expect(diagnostic.diagnostic.category == .malformedEncoding)
        #expect(diagnostic.diagnostic.nlriType == 4)
        #expect(diagnostic.diagnostic.nlriIndex == index)
        #expect(diagnostic.diagnostic.byteOffset == frames.prefix(index).reduce(0) { $0 + $1.count })
        #expect(diagnostic.diagnostic.rawNLRI == Self.invalid6)
        #expect(diagnostic.diagnostic.descriptorType == 265)
    }

    @Test(arguments: [true, false])
    func strictCrossAttributeFailureNeverMutatesSeededRIB(failureInReach: Bool) throws {
        var rib = try Self.seededRIB()
        let before = rib
        let update = Self.update(
            reach: failureInReach ? Self.invalid6 : Self.valid4,
            unreach: failureInReach ? Self.valid6 : Self.invalid6
        )
        #expect(throws: BGPLSClientError.self) { try rib.apply(update: update) }
        #expect(rib == before)
        #expect(rib.snapshot(at: .distantPast) == before.snapshot(at: .distantPast))
    }

    @Test(arguments: [true, false])
    func outerFramingFailureNeverCommitsAnyField(failureInReach: Bool) throws {
        //  Complete siblings cannot make a lost outer boundary safe to guess.
        let broken = Self.valid4 + Array(Self.valid6.dropLast())
        let update = Self.update(
            reach: failureInReach ? broken : Self.valid4,
            unreach: failureInReach ? Self.valid6 : broken
        )
        var rib = try Self.seededRIB()
        let before = rib
        do {
            _ = try rib.applyIsolating(update: update)
            Issue.record("incomplete outer frame was accepted")
        } catch BGPLSClientError.protocolError(let message) {
            #expect(message.hasPrefix(failureInReach ? "MP_REACH:" : "MP_UNREACH:"))
        }
        #expect(rib == before)
        #expect(throws: BGPLSClientError.self) { try rib.apply(update: update) }
        #expect(rib == before)
    }

    @Test
    func everyOuterHeaderAndBodyTruncationIsFatal() {
        for count in 1..<Self.valid6.count {
            let bytes = Self.valid4 + Self.valid6.prefix(count)
            #expect(throws: BGPLSClientError.self) {
                try BGPLSNLRIParser.parseAllIsolating(ByteBuffer(bytes: bytes))
            }
        }
    }

    @Test(arguments: [0, 5])
    func fatalLaterFrameRetainsFieldRelativeCoordinatesWithoutChangingStrictErrors(
        readerPrefixCount: Int
    ) throws {
        let earlier = Self.frame(type: 60_000, body: [7]) + Self.valid4
        for truncation: [UInt8] in [[0], [0, 4], [0, 4, 0], [0, 4, 0, 9], [0, 4, 0, 9, 2]] {
            var buffer = ByteBuffer(
                bytes: Array(repeating: UInt8(0xee), count: readerPrefixCount) + earlier + truncation)
            buffer.moveReaderIndex(forwardBy: readerPrefixCount)
            do {
                _ = try BGPLSNLRIParser.parseAllIsolating(buffer)
                Issue.record("incomplete later frame was accepted")
            } catch BGPLSClientError.protocolError(let message) {
                #expect(
                    message.contains("disposition=fatal category=malformedEncoding index=2 offset=\(earlier.count)"))
                #expect(message.contains(" type=4") == (truncation.count >= 2))
                #expect(message.contains("BGP-LS NLRI"))
                #expect(message.contains("truncated"))
                #expect(!message.contains("eeee"))
            }
            do {
                _ = try BGPLSNLRIParser.parseAll(buffer)
                Issue.record("strict parsing accepted an incomplete frame")
            } catch BGPLSClientError.protocolError(let message) {
                #expect(!message.contains("disposition="))
                #expect(!message.contains("offset="))
                #expect(message.hasPrefix("BGP-LS NLRI"))
            }
        }
    }

    @Test
    func classifiesOnlyExplicitBodyFailuresAndKeepsStrictErrors() throws {
        let local = IPv6TopologyFixture.nodeDescriptor()
        let reach = BGPLSTLV(type: 265, value: [0])
        let duplicateNodeSubTLV = BGPLSTLV(
            type: 256,
            value: IPv6TopologyFixture.encode([
                BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, 1]),
                BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, 1]),
            ])
        )
        let nestedTruncation = BGPLSTLV(type: 256, value: [2, 3, 0, 6, 0])
        let duplicateUnknownNodeSubTLV = BGPLSTLV(
            type: 256,
            value: IPv6TopologyFixture.encode([
                BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, 1]),
                BGPLSTLV(type: 60_001, value: [1]), BGPLSTLV(type: 60_001, value: [2]),
            ])
        )
        let cases: [([UInt8], BGPLSNLRIParser.Category)] = [
            (Self.frame(type: 4, body: [2]), .malformedEncoding),
            (Self.frame(type: 4, body: Self.commonHeader + [1]), .malformedEncoding),
            (Self.frame(type: 4, body: Self.commonHeader + [1, 0, 0, 5, 0]), .malformedEncoding),
            (IPv6TopologyFixture.wire(type: 4, descriptors: [nestedTruncation, reach]), .malformedEncoding),
            (IPv6TopologyFixture.wire(type: 4, descriptors: [duplicateNodeSubTLV, reach]), .malformedEncoding),
            (IPv6TopologyFixture.wire(type: 4, descriptors: [duplicateUnknownNodeSubTLV, reach]), .malformedEncoding),
            (Self.invalid6, .malformedEncoding),
            (IPv6TopologyFixture.prefixWire([33], type: 3), .malformedEncoding),
            (IPv6TopologyFixture.prefixWire([]), .malformedEncoding),
            (IPv6TopologyFixture.wire(type: 4, descriptors: [local]), .invalidContent),
            (IPv6TopologyFixture.wire(type: 4, descriptors: [reach]), .invalidContent),
            (IPv6TopologyFixture.wire(type: 4, descriptors: [local, reach, reach]), .invalidContent),
            (IPv6TopologyFixture.wire(type: 4, descriptors: [local, local, reach]), .invalidContent),
            (IPv6TopologyFixture.prefixWire([64, 0]), .malformedEncoding),
            (IPv6TopologyFixture.prefixWire([0, 0]), .malformedEncoding),
            (IPv6TopologyFixture.prefixWire([0], extra: [BGPLSTLV(type: 263, value: [0])]), .malformedEncoding),
            (
                IPv6TopologyFixture.wire(type: 4, descriptors: [BGPLSTLV(type: 256, value: []), reach]),
                .invalidContent
            ),
            (
                IPv6TopologyFixture.wire(
                    type: 4,
                    descriptors: [
                        BGPLSTLV(type: 256, value: IPv6TopologyFixture.encode([BGPLSTLV(type: 515, value: [1])])),
                        reach,
                    ]), .malformedEncoding
            ),
        ]
        for (bad, category) in cases {
            let result = try BGPLSNLRIParser.parseAllIsolating(ByteBuffer(bytes: bad + Self.valid4))
            #expect(result.nlris.count == 1)
            #expect(result.diagnostics.count == 1)
            let diagnostic = try #require(result.diagnostics.first)
            #expect(diagnostic.category == category)
            #expect(diagnostic.disposition == .discarded)
            #expect(diagnostic.rawNLRI == bad)
            var strict = ByteBuffer(bytes: bad)
            do {
                _ = try BGPLSNLRIParser.parseOne(&strict)
                Issue.record("strict parser accepted rejected content")
            } catch BGPLSClientError.protocolError(let message) {
                #expect(message == diagnostic.message)
            }
        }
    }

    @Test
    func recognizedDescriptorWidthFailuresAreMalformedEncoding() throws {
        //  Exact field widths are encoded shape constraints, not merely limits of
        // the typed model. Exercise every existing fixed-width descriptor validation site.
        for type: UInt16 in [512, 513, 514] {
            for length in [0, 3, 5] {
                let local = BGPLSTLV(
                    type: 256,
                    value: IPv6TopologyFixture.encode([
                        BGPLSTLV(type: type, value: Array(repeating: 0, count: length)),
                        BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, 1]),
                    ])
                )
                let wire = IPv6TopologyFixture.wire(type: 1, descriptors: [local])
                try Self.expectRejection(wire, category: .malformedEncoding, descriptorType: type)
            }
        }
        let linkWidths: [(UInt16, Int)] = [(258, 8), (259, 4), (260, 4), (261, 16), (262, 16), (263, 2)]
        for (type, width) in linkWidths {
            for length in [0, width - 1, width + 1] {
                let wire = Self.linkWire([BGPLSTLV(type: type, value: Array(repeating: 0, count: length))])
                try Self.expectRejection(wire, category: .malformedEncoding, descriptorType: type)
            }
        }
        let prefixWidths: [(UInt16, Int)] = [(263, 2), (264, 1)]
        for (type, width) in prefixWidths {
            for length in [0, width + 1] {
                let wire = IPv6TopologyFixture.prefixWire(
                    [0], extra: [BGPLSTLV(type: type, value: Array(repeating: 0, count: length))])
                try Self.expectRejection(wire, category: .malformedEncoding, descriptorType: type)
            }
        }
        for type: UInt16 in [3, 4] {
            for reachability: [UInt8] in [[], [8], [8, 192, 0], [0, 0]] {
                let wire = IPv6TopologyFixture.prefixWire(reachability, type: type)
                try Self.expectRejection(wire, category: .malformedEncoding, descriptorType: 265)
            }
        }
    }

    @Test
    func missingAndAmbiguousIdentityContentRemainsInvalidContent() throws {
        let local = IPv6TopologyFixture.nodeDescriptor()
        let remote = IPv6TopologyFixture.nodeDescriptor(257, lastByte: 2)
        for descriptors in [[remote], [local, local, remote]] {
            try Self.expectRejection(
                IPv6TopologyFixture.wire(type: 2, descriptors: descriptors),
                category: .invalidContent, descriptorType: 256)
        }
        for descriptors in [[local], [local, remote, remote]] {
            try Self.expectRejection(
                IPv6TopologyFixture.wire(type: 2, descriptors: descriptors),
                category: .invalidContent, descriptorType: 257)
        }
        let linkWidths: [(UInt16, Int)] = [(258, 8), (259, 4), (260, 4), (261, 16), (262, 16), (263, 2)]
        for (type, width) in linkWidths {
            let descriptor = BGPLSTLV(type: type, value: Array(repeating: 0, count: width))
            try Self.expectRejection(
                Self.linkWire([descriptor, descriptor]), category: .invalidContent, descriptorType: type)
        }
        for descriptor in [BGPLSTLV(type: 263, value: [0, 1]), BGPLSTLV(type: 264, value: [1])] {
            try Self.expectRejection(
                IPv6TopologyFixture.prefixWire([0], extra: [descriptor, descriptor]),
                category: .invalidContent, descriptorType: descriptor.type)
        }
        let missingRouterID = BGPLSTLV(
            type: 256, value: IPv6TopologyFixture.encode([BGPLSTLV(type: 512, value: [0, 0, 253, 233])]))
        try Self.expectRejection(
            IPv6TopologyFixture.wire(type: 1, descriptors: [missingRouterID]),
            category: .invalidContent, descriptorType: 515)
    }

    @Test
    func routerIDShapeAndValueFailuresHaveDistinctCategoriesWithoutChangingStrictErrors() throws {
        let protocolsAndLengths: [(UInt8, [Int])] = [
            (1, [0, 1, 5, 8]), (2, [0, 1, 5, 8]),
            (3, [0, 1, 3, 5, 7, 9]), (6, [0, 1, 3, 5, 7, 9]),
        ]
        for (protocolID, lengths) in protocolsAndLengths {
            for length in lengths {
                let wire = Self.routerIDWire(protocolID: protocolID, bytes: Array(repeating: 1, count: length))
                try Self.expectRejection(
                    wire, category: .malformedEncoding, descriptorType: 515,
                    expectedMessage: "invalid IGP Router-ID for Protocol-ID \(protocolID)")
            }
        }
        for protocolID: UInt8 in [1, 2] {
            //  A seven-octet pseudonode is correctly sized even when its PSN value is zero.
            let wire = Self.routerIDWire(protocolID: protocolID, bytes: [0, 0, 0, 0, 0, 1, 0])
            try Self.expectRejection(
                wire, category: .invalidContent, descriptorType: 515,
                expectedMessage: "invalid IGP Router-ID for Protocol-ID \(protocolID)")
        }
        for protocolID: UInt8 in [4, 5, 250] {
            for bytes: [UInt8] in [[], [1], [1, 2, 3, 4, 5]] {
                let wire = Self.routerIDWire(protocolID: protocolID, bytes: bytes)
                let result = try BGPLSNLRIParser.parseAllIsolating(ByteBuffer(bytes: wire))
                #expect(result.diagnostics.isEmpty)
                guard case .node(let node) = result.nlris.first else {
                    Issue.record("expected an accepted opaque Router-ID")
                    continue
                }
                #expect(node.localNode.igpRouterID == .opaque(bytes))
            }
        }
    }

    @Test
    func rejectedReplacementAndWithdrawalRetainPriorStateUntilValidWithdrawal() throws {
        for type: UInt16 in [3, 4] {
            let reachability: [UInt8] = type == 3 ? [24, 192, 0, 2] : [32, 0x20, 1, 0x0d, 0xb8]
            let valid = IPv6TopologyFixture.prefixWire(reachability, type: type)
            let nlri = try IPv6TopologyFixture.parse(valid)
            let rejected: [(BGPLSTLV, BGPLSNLRIParser.Category)] = [
                (BGPLSTLV(type: 264, value: []), .malformedEncoding),
                (BGPLSTLV(type: 265, value: reachability), .invalidContent),
            ]
            for reachable in [true, false] {
                for (descriptor, category) in rejected {
                    var rib = LSRIB()
                    rib.apply(BGPLSRecord(nlri: nlri))
                    let before = rib
                    let bad = IPv6TopologyFixture.prefixWire(reachability, type: type, extra: [descriptor])
                    let result = try rib.applyIsolating(
                        update: Self.update(reach: reachable ? bad : nil, unreach: reachable ? nil : bad))
                    //  Do not infer a withdrawal or replacement from rejected content;
                    // the previous entry may be stale, but neither state nor diffs may invent a change.
                    #expect(rib == before)
                    #expect(rib.snapshot(at: .distantPast) == before.snapshot(at: .distantPast))
                    #expect(result.diffs.isEmpty)
                    #expect(result.diagnostics.count == 1)
                    let diagnostic = try #require(nlriDiagnostics(result.diagnostics).first)
                    #expect(diagnostic.field == (reachable ? .mpReach : .mpUnreach))
                    #expect(diagnostic.diagnostic.category == category)
                    #expect(diagnostic.diagnostic.disposition == .discarded)
                    #expect(diagnostic.diagnostic.rawNLRI == bad)

                    let withdrawn = try rib.applyIsolating(update: Self.update(unreach: valid))
                    #expect(withdrawn.diagnostics.isEmpty)
                    #expect(withdrawn.diffs == [.withdraw(nlri)])
                    #expect(rib == LSRIB())
                }
            }
        }
    }

    @Test
    func positionsAreFieldRelativeAndUnknownFramesCount() throws {
        let unknown = Self.frame(type: 60_000, body: [1, 2, 3])
        let padded = IPv6TopologyFixture.prefixWire([1, 0xff])
        var buffer = ByteBuffer(bytes: [99, 98, 97] + unknown + padded + Self.invalid6)
        buffer.moveReaderIndex(forwardBy: 3)
        let original = buffer
        let result = try BGPLSNLRIParser.parseAllIsolating(buffer)
        #expect(buffer == original)
        #expect(result.nlris.count == 2)
        #expect(result.nlris.first == .unknown(type: 60_000, raw: [1, 2, 3]))
        #expect(result.diagnostics.map(\.nlriIndex) == [1, 2])
        #expect(result.diagnostics.map(\.byteOffset) == [unknown.count, unknown.count + padded.count])
        #expect(result.diagnostics.map(\.rawNLRI) == [padded, Self.invalid6])
        #expect(result.diagnostics.map(\.disposition) == [.acceptedWithWarning, .discarded])
        #expect(result.diagnostics.map(\.category) == [.nonZeroPrefixPadding, .malformedEncoding])
    }

    @Test
    func preservesUnknownNLRIsAndDescriptorsWithoutDiagnostics() throws {
        let unknown = Self.frame(type: 60_000, body: [1, 2, 3])
        let extra = BGPLSTLV(type: 60_001, value: [9, 8, 7])
        let known = IPv6TopologyFixture.prefixWire([0], extra: [extra, extra])
        let result = try BGPLSNLRIParser.parseAllIsolating(ByteBuffer(bytes: unknown + known))
        #expect(result.diagnostics.isEmpty)
        #expect(result.nlris.first == .unknown(type: 60_000, raw: [1, 2, 3]))
        guard case .ipv6Prefix(let prefix) = result.nlris.last else {
            Issue.record("expected known IPv6 prefix")
            return
        }
        #expect(prefix.prefixDescriptors.suffix(2) == [extra, extra])

        var rib = try Self.seededRIB()
        let before = rib
        let applied = try rib.applyIsolating(update: Self.update(reach: unknown, unreach: unknown))
        #expect(rib == before)
        #expect(applied.diagnostics.isEmpty)
        #expect(
            applied.diffs == [
                .upsert(BGPLSRecord(nlri: .unknown(type: 60_000, raw: [1, 2, 3]))),
                .withdraw(.unknown(type: 60_000, raw: [1, 2, 3])),
            ])
    }

    @Test
    func linkLocalWarningsCoverBothFamiliesAndBoundaries() throws {
        let samples: [(String, UInt16, Bool)] = [
            ("169.253.255.255", 259, false), ("169.254.0.0", 259, true),
            ("169.254.255.255", 260, true), ("169.255.0.0", 260, false),
            ("fe7f:ffff::1", 261, false), ("fe80::", 261, true),
            ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 262, true), ("fec0::1", 262, false),
        ]
        for (text, type, warns) in samples {
            let bytes: [UInt8]
            if type < 261 {
                let address = try #require(IPv4Address(text)).address
                bytes = [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: address >> $0) }
            } else {
                bytes = try IPv6TopologyFixture.addressBytes(text)
            }
            let wire = Self.linkWire([BGPLSTLV(type: type, value: bytes)])
            let result = try BGPLSNLRIParser.parseAllIsolating(ByteBuffer(bytes: wire))
            #expect(result.nlris == (try BGPLSNLRIParser.parseAll(ByteBuffer(bytes: wire))))
            #expect(result.diagnostics.count == (warns ? 1 : 0))
            if let diagnostic = result.diagnostics.first {
                #expect(diagnostic.disposition == .acceptedWithWarning)
                #expect(diagnostic.category == .linkLocalAddress)
                #expect(diagnostic.descriptorType == type)
                #expect(diagnostic.rawNLRI == wire)
            }
        }
    }

    @Test
    func linkLocalMPReachNextHopIsNotALinkDescriptorWarning() throws {
        var update = Self.update(reach: Self.valid4 + Self.valid6)
        //  The warning concerns topology descriptor TLVs, not the independently
        // scoped BGP next hop where an IPv6 link-local component is permitted.
        update.mpReach?.nextHop = ByteBuffer(
            bytes:
                try IPv6TopologyFixture.addressBytes("2001:db8::1")
                + IPv6TopologyFixture.addressBytes("fe80::1")
        )
        var rib = LSRIB()
        let result = try rib.applyIsolating(update: update)
        #expect(rib.prefixCount == 2)
        #expect(result.diagnostics.isEmpty)
    }

    @Test
    func multipleLinkWarningsRetainDescriptorOrderAndOneObject() throws {
        let wire = Self.linkWire([
            BGPLSTLV(type: 262, value: try IPv6TopologyFixture.addressBytes("fe80::2")),
            BGPLSTLV(type: 259, value: [169, 254, 0, 1]),
            BGPLSTLV(type: 261, value: try IPv6TopologyFixture.addressBytes("fe80::1")),
            BGPLSTLV(type: 260, value: [169, 254, 0, 2]),
        ])
        var rib = LSRIB()
        let result = try rib.applyIsolating(update: Self.update(reach: wire))
        #expect(rib.linkCount == 1)
        #expect(result.diffs.count == 1)
        #expect(nlriDiagnostics(result.diagnostics).map { $0.diagnostic.descriptorType } == [262, 259, 261, 260])
        #expect(nlriDiagnostics(result.diagnostics).allSatisfy { $0.diagnostic.rawNLRI == wire })
        let withdrawal = try rib.applyIsolating(update: Self.update(unreach: wire))
        #expect(rib.linkCount == 0)
        #expect(nlriDiagnostics(withdrawal.diagnostics).allSatisfy { $0.field == .mpUnreach })
    }

    @Test
    func discardedNLRIHasNoAcceptedContentWarnings() throws {
        let local = BGPLSTLV(type: 259, value: [169, 254, 0, 1])
        let wire = Self.linkWire([local, local])
        let result = try BGPLSNLRIParser.parseAllIsolating(ByteBuffer(bytes: wire))
        #expect(result.nlris.isEmpty)
        #expect(result.diagnostics.count == 1)
        #expect(result.diagnostics.first?.disposition == .discarded)
        #expect(result.diagnostics.first?.category == .invalidContent)
    }

    @Test
    func prefixPaddingWarningsPreserveCanonicalIdentityAtBothFamilyBoundaries() throws {
        for type: UInt16 in [3, 4] {
            let lengths = type == 3 ? [0, 1, 7, 8, 9, 31, 32] : [0, 1, 7, 8, 9, 63, 64, 65, 127, 128]
            for length in lengths {
                let bytes = [UInt8(length)] + Array(repeating: UInt8(255), count: (length + 7) / 8)
                let padded = IPv6TopologyFixture.prefixWire(bytes, type: type)
                var canonicalBytes = bytes
                if length % 8 != 0 {
                    canonicalBytes[canonicalBytes.count - 1] &= UInt8.max << (8 - length % 8)
                }
                let canonical = IPv6TopologyFixture.prefixWire(canonicalBytes, type: type)
                var rib = LSRIB()
                let result = try rib.applyIsolating(update: Self.update(reach: padded))
                #expect(result.diagnostics.count == (length % 8 == 0 ? 0 : 1))
                #expect(
                    nlriDiagnostics(result.diagnostics).allSatisfy {
                        $0.diagnostic.category == .nonZeroPrefixPadding
                            && $0.diagnostic.disposition == .acceptedWithWarning
                            && $0.diagnostic.rawNLRI == padded && $0.diagnostic.descriptorType == 265
                    })
                #expect(rib.prefixCount == 1)
                let erased = try #require(rib.prefixes.values.map(\.nlri).first)
                #expect(erased.prefixDescriptors.first?.value == bytes)
                #expect(
                    nlriDiagnostics(result.diagnostics).allSatisfy {
                        $0.diagnostic.message
                            == "nonzero trailing bits in IP Reachability descriptor for \(erased.network.description)"
                    })
                let result2 = try rib.applyIsolating(update: Self.update(unreach: canonical))
                #expect(result2.diagnostics.isEmpty)
                #expect(rib.prefixCount == 0)
            }
        }
    }

    @Test
    func emptyEORAndNonBGPLSFieldsAreNoops() throws {
        var rib = try Self.seededRIB()
        let before = rib
        let values = [
            BGPUpdateMessage(),
            Self.update(reach: [], unreach: []),
            Self.update(reach: [0xff], unreach: [0xff], afi: 2),
            Self.update(reach: [0xff], unreach: [0xff], safi: 72),
        ]
        for update in values {
            #expect(try rib.apply(update: update).isEmpty)
            let isolated = try rib.applyIsolating(update: update)
            #expect(isolated.diffs.isEmpty)
            #expect(isolated.diagnostics.isEmpty)
            #expect(rib == before)
        }
        let empty = try BGPLSNLRIParser.parseAllIsolating(ByteBuffer())
        #expect(empty.nlris.isEmpty)
        #expect(empty.diagnostics.isEmpty)
    }

    @Test
    func preparationIsPureAndCommitPreservesReachThenWithdrawOrdering() throws {
        let update = Self.update(reach: Self.valid4 + Self.invalid6, unreach: Self.invalid6 + Self.valid4)
        var rib = try Self.seededRIB()
        let before = rib
        let prepared = try LSRIB.prepareIsolating(update: update)
        #expect(rib == before)
        let result = rib.commit(prepared)
        let good = try IPv6TopologyFixture.parse(Self.valid4)
        #expect(result.diffs == [.upsert(BGPLSRecord(nlri: good)), .withdraw(good)])
        #expect(nlriDiagnostics(result.diagnostics).map(\.field) == [.mpReach, .mpUnreach])
        #expect(nlriDiagnostics(result.diagnostics).map { $0.diagnostic.nlriIndex } == [1, 0])
        #expect(nlriDiagnostics(result.diagnostics).map { $0.diagnostic.byteOffset } == [Self.valid4.count, 0])
        #expect(rib == before)
    }

    @Test
    func erasedPrefixDescriptorsPreserveExactStoredEvidenceForBothFamilies() throws {
        let descriptors = [
            BGPLSTLV(type: 60_001, value: [3, 2, 1]),
            BGPLSTLV(type: 263, value: [0, 7]),
            BGPLSTLV(type: 264, value: [2]),
            BGPLSTLV(type: 60_001, value: [4]),
        ]
        for type: UInt16 in [3, 4] {
            let wire = IPv6TopologyFixture.prefixWire([1, 0xff], type: type, extra: descriptors)
            var rib = LSRIB()
            try rib.apply(update: Self.update(reach: wire))
            let erased = try #require(rib.prefixes.values.map(\.nlri).first)
            #expect(erased.prefixDescriptors == [BGPLSTLV(type: 265, value: [1, 0xff])] + descriptors)
        }
    }

    private static var commonHeader: [UInt8] { [2] + Array(repeating: 0, count: 8) }

    private static func expectRejection(
        _ wire: [UInt8], category: BGPLSNLRIParser.Category, descriptorType: UInt16,
        expectedMessage: String? = nil
    ) throws {
        let result = try BGPLSNLRIParser.parseAllIsolating(ByteBuffer(bytes: wire + valid4))
        #expect(result.nlris.count == 1)
        #expect(result.diagnostics.count == 1)
        let diagnostic = try #require(result.diagnostics.first)
        #expect(diagnostic.category == category)
        #expect(diagnostic.disposition == .discarded)
        #expect(diagnostic.descriptorType == descriptorType)
        #expect(diagnostic.rawNLRI == wire)
        #expect(diagnostic.nlriIndex == 0)
        #expect(diagnostic.byteOffset == 0)
        if let expectedMessage { #expect(diagnostic.message == expectedMessage) }
        var strict = ByteBuffer(bytes: wire)
        do {
            _ = try BGPLSNLRIParser.parseOne(&strict)
            Issue.record("strict parser accepted rejected content")
        } catch BGPLSClientError.protocolError(let message) {
            #expect(message == diagnostic.message)
        }
    }

    private static func routerIDWire(protocolID: UInt8, bytes: [UInt8]) -> [UInt8] {
        let local = BGPLSTLV(type: 256, value: IPv6TopologyFixture.encode([BGPLSTLV(type: 515, value: bytes)]))
        return IPv6TopologyFixture.wire(type: 1, descriptors: [local], protocolID: protocolID)
    }

    private static func frame(type: UInt16, body: [UInt8]) -> [UInt8] {
        var buffer = ByteBuffer()
        buffer.writeInteger(type)
        buffer.writeInteger(UInt16(body.count))
        buffer.writeBytes(body)
        return Array(buffer.readableBytesView)
    }

    private static func linkWire(_ descriptors: [BGPLSTLV]) -> [UInt8] {
        IPv6TopologyFixture.wire(
            type: 2,
            descriptors: [
                IPv6TopologyFixture.nodeDescriptor(), IPv6TopologyFixture.nodeDescriptor(257, lastByte: 2),
            ] + descriptors)
    }

    private static func seededRIB() throws -> LSRIB {
        var rib = LSRIB()
        rib.apply(BGPLSRecord(nlri: try IPv6TopologyFixture.parse(valid6)))
        return rib
    }

    private static func update(
        reach: [UInt8]? = nil, unreach: [UInt8]? = nil, afi: UInt16 = 16_388, safi: UInt8 = 71
    ) -> BGPUpdateMessage {
        BGPUpdateMessage(
            mpReach: reach.map {
                BGPMPReach(
                    afi: afi, safi: safi, nextHop: ByteBuffer(bytes: [192, 0, 2, 254]), nlri: ByteBuffer(bytes: $0))
            },
            mpUnreach: unreach.map { BGPMPUnreach(afi: afi, safi: safi, withdrawnNLRI: ByteBuffer(bytes: $0)) }
        )
    }
}
