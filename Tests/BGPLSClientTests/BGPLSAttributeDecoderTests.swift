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

import Foundation
import NIOCore
import Testing

@testable import BGPLSClient

struct BGPLSAttributeDecoderTests {
    @Test
    func absentIsDistinctFromPresentUnknownOrEmpty() {
        let absent = BGPLSAttributeDecoder.decode(pathAttributes: [])
        #expect(absent.observation == BGPLSAttributeObservation())
        #expect(absent.node == BGPLSNodeAttributes())
        #expect(absent.link == BGPLSLinkAttributes())
        #expect(absent.prefix == BGPLSPrefixAttributes())

        let unknown = Self.decode(Self.tlv(60_000, [0, 255]))
        #expect(unknown.observation.availability == .present)
        #expect(unknown.observation.diagnostics.isEmpty)
        #expect(unknown.node.name == nil)
        #expect(unknown.link.igpMetric == nil)
        #expect(unknown.prefix.metric == nil)

        let empty = Self.decode([])
        #expect(empty.observation.availability == .discarded)
        #expect(empty.observation.diagnostics.map(\.category) == [.emptyAttribute])
    }

    @Test
    func allInitialProjectionsPreserveWireUnitsAndPriorityOrder() throws {
        let priorities = (0..<8).flatMap { Self.floatBytes(Float($0 * 125)) }
        let bytes =
            Self.tlv(1155, [0, 0, 0, 11]) + Self.tlv(1026, Array("r1".utf8))
            + Self.tlv(1095, [0, 0, 10]) + Self.tlv(1089, Self.floatBytes(125_000_000))
            + Self.tlv(1090, Self.floatBytes(250_000_000)) + Self.tlv(1091, priorities)
        let decoded = Self.decode(bytes)
        #expect(decoded.observation.availability == .present)
        #expect(decoded.observation.diagnostics.isEmpty)
        #expect(decoded.node.name == "r1")
        #expect(decoded.link.igpMetric == 10)
        #expect(decoded.prefix.metric == 11)
        #expect(decoded.link.maximumLinkBandwidth?.bytesPerSecond == 125_000_000)
        #expect(decoded.link.maximumLinkBandwidth?.bitsPerSecond == 1_000_000_000)
        // Advertised reservable bandwidth may exceed the physical maximum.
        #expect(decoded.link.maximumReservableBandwidth?.bytesPerSecond == 250_000_000)
        let unreserved = try #require(decoded.link.unreservedBandwidth)
        #expect(unreserved.values.count == 8)
        for priority in 0..<8 {
            #expect(unreserved[priority].bytesPerSecond == Float(priority * 125))
            #expect(unreserved[priority].bitsPerSecond == Double(priority * 1_000))
        }
        #expect(decoded.observation.attributes.first?.value == bytes)
    }

    @Test(arguments: [0, 1, 127, 255])
    func nodeNameASCIIBoundariesAndControlsAreNotNormalized(count: Int) {
        let bytes = Array((0..<count).map { UInt8($0 % 128) })
        let decoded = Self.decode(Self.tlv(1026, bytes))
        #expect(decoded.node.name == String(decoding: bytes, as: UTF8.self))
        #expect(decoded.observation.diagnostics.isEmpty)
        #expect(Array(decoded.node.name?.utf8 ?? "".utf8) == bytes)
    }

    @Test
    func invalidNamesOmitOnlyName() {
        for (name, category): ([UInt8], BGPLSAttributeDiagnostic.Category) in [
            (Array(repeating: 65, count: 256), .invalidLength), ([0x80], .invalidASCII), ([0xc3, 0xa9], .invalidASCII),
        ] {
            let decoded = Self.decode(Self.tlv(1026, name) + Self.tlv(1155, [0, 0, 0, 3]))
            #expect(decoded.observation.availability == .present)
            #expect(decoded.node.name == nil)
            #expect(decoded.prefix.metric == 3)
            #expect(decoded.observation.diagnostics.map(\.category) == [category])
            #expect(decoded.observation.diagnostics.allSatisfy { $0.isError })
        }
    }

    @Test
    func metricWidthsReservedBitsAndUnsignedBoundaries() {
        for (bytes, expected): ([UInt8], UInt32) in [
            ([0], 0), ([0xff], 63), ([0xc0], 0), ([0x8a], 10),
            ([0xff, 0xff], 65_535), ([0xff, 0xff, 0xff], 16_777_215),
            ([0, 10], 10), ([0, 0, 10], 10),
        ] {
            let decoded = Self.decode(Self.tlv(1095, bytes))
            #expect(decoded.link.igpMetric == expected)
            #expect(decoded.observation.diagnostics.isEmpty)
            #expect(decoded.observation.attributes.first?.tlvs.first?.value == bytes)
        }
        let prefix = Self.decode(Self.tlv(1155, [255, 255, 255, 255]))
        #expect(prefix.prefix.metric == UInt32.max)
        #expect(prefix.observation.diagnostics.isEmpty)
    }

    @Test
    func incorrectRecognizedWidthsRejectOnlyAffectedProjection() {
        for (type, lengths): (UInt16, [Int]) in [
            (1095, [0, 4, 5]), (1155, [0, 1, 2, 3, 5]),
            (1089, [0, 1, 3, 5]), (1090, [0, 3, 8]), (1091, [0, 4, 28, 31, 33, 36]),
        ] {
            for length in lengths {
                let decoded = Self.decode(Self.tlv(type, Array(repeating: 0, count: length)) + Self.tlv(1026, [65]))
                #expect(decoded.node.name == "A")
                #expect(decoded.link == BGPLSLinkAttributes())
                #expect(decoded.prefix == BGPLSPrefixAttributes())
                #expect(decoded.observation.availability == .present)
                #expect(decoded.observation.diagnostics.map(\.category) == [.invalidLength])
                #expect(decoded.observation.diagnostics.first?.disposition == .projectionRejected)
            }
        }
    }

    @Test(arguments: [UInt32(0), 0x8000_0000, 1, 0x007f_ffff, 0x0080_0000, 0x7f7f_ffff])
    func finiteNonnegativeBandwidthIncludesBothZerosAndExtremes(bits: UInt32) throws {
        let bytes = Self.integerBytes(bits)
        let decoded = Self.decode(Self.tlv(1089, bytes))
        let bandwidth = try #require(decoded.link.maximumLinkBandwidth)
        #expect(bandwidth.bytesPerSecond.bitPattern == bits)
        #expect(bandwidth.bitsPerSecond.isFinite)
        #expect(bandwidth.bitsPerSecond == Double(Float(bitPattern: bits)) * 8)
        #expect(decoded.observation.diagnostics.isEmpty)
        #expect(decoded.observation.attributes.first?.tlvs.first?.value == bytes)
    }

    @Test(arguments: [
        UInt32(0xbf80_0000), 0x8000_0001, 0xff7f_ffff, 0x7f80_0000, 0xff80_0000, 0x7fc0_0000, 0x7f80_0001,
    ])
    func invalidBandwidthRejectsProjectionButKeepsValidSiblings(bits: UInt32) {
        let decoded = Self.decode(
            Self.tlv(1089, Self.integerBytes(bits)) + Self.tlv(1090, Self.floatBytes(5)) + Self.tlv(1095, [7]))
        #expect(decoded.link.maximumLinkBandwidth == nil)
        #expect(decoded.link.maximumReservableBandwidth?.bytesPerSecond == 5)
        #expect(decoded.link.igpMetric == 7)
        #expect(decoded.observation.availability == .present)
        #expect(decoded.observation.diagnostics.map(\.category) == [.invalidValue])
        #expect(BGPLSBandwidth(bytesPerSecond: Float(bitPattern: bits)) == nil)
    }

    @Test(arguments: Array(0..<8))
    func oneInvalidPriorityRejectsEntireUnreservedProperty(priority: Int) {
        var values = (0..<8).flatMap { Self.floatBytes(Float($0)) }
        values.replaceSubrange((priority * 4)..<(priority * 4 + 4), with: Self.floatBytes(.infinity))
        let decoded = Self.decode(Self.tlv(1091, values) + Self.tlv(1089, Self.floatBytes(9)))
        #expect(decoded.link.unreservedBandwidth == nil)
        #expect(decoded.link.maximumLinkBandwidth?.bytesPerSecond == 9)
        #expect(decoded.observation.diagnostics.map(\.category) == [.invalidValue])
        #expect(decoded.observation.diagnostics.first?.originalBytes == Self.tlv(1091, values))
    }

    @Test
    func modelConstructionAndCodableKeepBandwidthValidated() throws {
        let value = try #require(BGPLSBandwidth(bytesPerSecond: Float.greatestFiniteMagnitude))
        let encoded = try JSONEncoder().encode(value)
        #expect(try JSONDecoder().decode(BGPLSBandwidth.self, from: encoded) == value)
        #expect(value.bitsPerSecond == Double(Float.greatestFiniteMagnitude) * 8)
        for text in ["-1", "1e100"] {
            #expect(throws: (any Error).self) {
                try JSONDecoder().decode(BGPLSBandwidth.self, from: Data(text.utf8))
            }
        }
        let decoder = JSONDecoder()
        decoder.nonConformingFloatDecodingStrategy = .convertFromString(
            positiveInfinity: "Infinity", negativeInfinity: "-Infinity", nan: "NaN")
        for text in ["\"Infinity\"", "\"-Infinity\"", "\"NaN\""] {
            #expect(throws: (any Error).self) {
                try decoder.decode(BGPLSBandwidth.self, from: Data(text.utf8))
            }
        }
        let values = Array(repeating: value, count: 8)
        let priorities = try #require(BGPLSUnreservedBandwidth(values: values))
        #expect(
            try JSONDecoder().decode(BGPLSUnreservedBandwidth.self, from: JSONEncoder().encode(priorities))
                == priorities)
        for count in [0, 1, 7, 9] {
            #expect(BGPLSUnreservedBandwidth(values: Array(repeating: value, count: count)) == nil)
            let invalid = try JSONEncoder().encode(Array(repeating: value, count: count))
            #expect(throws: (any Error).self) { try JSONDecoder().decode(BGPLSUnreservedBandwidth.self, from: invalid) }
        }
        let attributes = BGPLSLinkAttributes(
            igpMetric: 10, maximumLinkBandwidth: value, maximumReservableBandwidth: value,
            unreservedBandwidth: priorities)
        #expect(
            try JSONDecoder().decode(BGPLSLinkAttributes.self, from: JSONEncoder().encode(attributes)) == attributes)
    }

    @Test
    func zeroWireEvidenceRemainsDistinctEvenWhenNumericValuesCompareEqual() throws {
        let positive = Self.decode(Self.tlv(1089, Self.integerBytes(0)))
        let negative = Self.decode(Self.tlv(1089, Self.integerBytes(0x8000_0000)))
        #expect(positive.link == negative.link)
        #expect(positive.observation != negative.observation)
        let lhs = try #require(positive.link.maximumLinkBandwidth)
        let rhs = try #require(negative.link.maximumLinkBandwidth)
        let lhsHash = lhs.hashValue
        let rhsHash = rhs.hashValue
        #expect(lhsHash == rhsHash)
        #expect(Set([lhs]).contains(rhs))
        #expect([lhs: "bandwidth"][rhs] == "bandwidth")
    }

    @Test
    func unknownAndWrongContextFieldsAreRetainedWithoutProjectionOrRejection() {
        let bytes =
            Self.tlv(1095, []) + Self.tlv(60_001, [0xde, 0xad]) + Self.tlv(1026, [65])
            + Self.tlv(1155, [0]) + Self.tlv(1095, [1, 2, 3, 4])
        let decoded = BGPLSAttributeDecoder.decode(pathAttributes: [Self.attribute(bytes)], contexts: [.node])
        #expect(decoded.node.name == "A")
        #expect(decoded.link == BGPLSLinkAttributes())
        #expect(decoded.prefix == BGPLSPrefixAttributes())
        #expect(decoded.observation.diagnostics.isEmpty)
        #expect(decoded.observation.attributes.first?.value == bytes)
        #expect(decoded.observation.attributes.first?.tlvs.map(\.type) == [1095, 60_001, 1026, 1155, 1095])
    }

    @Test
    func arbitraryTLVOrderProducesSameProjectionsButDifferentEvidence() {
        let a = Self.tlv(1095, [10])
        let b = Self.tlv(1026, [82, 49])
        let c = Self.tlv(1155, [0, 0, 0, 9])
        let first = Self.decode(a + b + c)
        let second = Self.decode(c + a + b)
        #expect(first.node == second.node)
        #expect(first.link == second.link)
        #expect(first.prefix == second.prefix)
        #expect(first.observation != second.observation)
        #expect(first.observation.diagnostics.isEmpty)
        #expect(second.observation.diagnostics.isEmpty)
    }

    @Test
    func identicalSingletonDuplicatesWarnAndConflictsRejectOnlyTheirProperty() {
        let name = Self.tlv(1026, [65])
        let first = Self.decode(name + Self.tlv(1095, [10]) + name + Self.tlv(1095, [11]))
        #expect(first.node.name == "A")
        #expect(first.link.igpMetric == nil)
        #expect(first.observation.availability == .present)
        #expect(first.observation.diagnostics.map(\.category) == [.duplicateTLV, .conflictingTLV])
        #expect(first.observation.diagnostics.map(\.tlvIndex) == [2, 3])
        #expect(first.observation.diagnostics.map(\.isError) == [false, true])

        // Equal decoded metrics with different wire widths still conflict.
        let metric = Self.decode(Self.tlv(1095, [10]) + Self.tlv(1095, [0, 10]))
        #expect(metric.link.igpMetric == nil)
        #expect(metric.observation.diagnostics.map(\.category) == [.conflictingTLV])
    }

    @Test
    func identicalInvalidSingletonDoesNotTurnIntoValidData() {
        let invalid = Self.tlv(1089, Self.floatBytes(.nan))
        let decoded = Self.decode(invalid + invalid)
        #expect(decoded.link.maximumLinkBandwidth == nil)
        #expect(decoded.observation.availability == .present)
        #expect(decoded.observation.diagnostics.map(\.category) == [.invalidValue, .duplicateTLV])
        #expect(decoded.observation.diagnostics.map(\.tlvIndex) == [0, 1])
    }

    @Test
    func conflictingDuplicateDoesNotPoisonOtherFieldsOrHideLaterCoordinates() {
        let decoded = Self.decode(
            Self.tlv(1089, Self.floatBytes(10)) + Self.tlv(1155, [1]) + Self.tlv(1095, [9])
                + Self.tlv(1089, Self.floatBytes(11)))
        #expect(decoded.link.maximumLinkBandwidth == nil)
        #expect(decoded.link.igpMetric == 9)
        #expect(decoded.prefix.metric == nil)
        #expect(decoded.observation.diagnostics.map(\.category) == [.invalidLength, .conflictingTLV])
        #expect(decoded.observation.diagnostics.map(\.tlvIndex) == [1, 3])
    }

    @Test
    func brokenFramingDiscardsEarlierValidProjectionsAndRetainsAllBytes() {
        let valid = Self.tlv(1026, [65])
        for tail: [UInt8] in [[4], [4, 0x47, 0], [4, 0x47, 0, 4, 0]] {
            let bytes = valid + tail
            let decoded = Self.decode(bytes)
            #expect(decoded.observation.availability == .discarded)
            #expect(decoded.node.name == nil)
            #expect(decoded.link == BGPLSLinkAttributes())
            #expect(decoded.observation.attributes.first?.value == bytes)
            #expect(decoded.observation.attributes.first?.tlvs.count == 1)
            #expect(decoded.observation.diagnostics.map(\.category) == [.malformedFraming])
            #expect(decoded.observation.diagnostics.first?.byteOffset == valid.count)
            #expect(decoded.observation.diagnostics.first?.tlvIndex == 1)
            #expect(decoded.observation.diagnostics.first?.originalBytes == tail)
        }
    }

    @Test
    func zeroLengthUnknownTLVsAdvanceFraming() {
        let decoded = Self.decode(Self.tlv(60_000, []) + Self.tlv(60_001, []) + Self.tlv(1026, []))
        #expect(decoded.observation.availability == .present)
        #expect(decoded.node.name == "")
        #expect(decoded.observation.attributes.first?.tlvs.map(\.byteOffset) == [0, 4, 8])
        #expect(decoded.observation.diagnostics.isEmpty)
    }

    @Test
    func flagsDiscardOnlyWhenOptionalOrTransitiveConflicts() {
        let bytes = Self.tlv(1026, [65])
        for flags: UInt8 in [0, 0x40, 0xc0, 0xd0, 0x70] {
            let decoded = BGPLSAttributeDecoder.decode(pathAttributes: [Self.attribute(bytes, flags: flags)])
            #expect(decoded.observation.availability == .discarded)
            #expect(decoded.node.name == nil)
            #expect(decoded.observation.diagnostics.map(\.category) == [.invalidFlags])
            #expect(decoded.observation.attributes.first?.flags == flags)
        }
        for flags: UInt8 in [0x80, 0x90, 0xa0, 0xb0, 0xbf] {
            let decoded = BGPLSAttributeDecoder.decode(pathAttributes: [Self.attribute(bytes, flags: flags)])
            #expect(decoded.observation.availability == .present)
            #expect(decoded.node.name == "A")
            #expect(decoded.observation.diagnostics.isEmpty)
            #expect(decoded.observation.attributes.first?.flags == flags)
        }
    }

    @Test
    func firstOuterOccurrenceWinsEvenWhenItsInterpretationIsDiscarded() {
        for first in [Self.tlv(1026, [65]), [], [4, 2, 0, 5, 65]] {
            let second = Self.tlv(1026, [66])
            let decoded = BGPLSAttributeDecoder.decode(pathAttributes: [Self.attribute(first), Self.attribute(second)])
            #expect(decoded.node.name == (first == Self.tlv(1026, [65]) ? "A" : nil))
            #expect(decoded.observation.attributes.map(\.value) == [first, second])
            #expect(decoded.observation.diagnostics.last?.category == .duplicateAttribute)
            #expect(decoded.observation.diagnostics.last?.isError == false)
            #expect(decoded.observation.diagnostics.last?.attributeIndex == 1)
            #expect(decoded.observation.diagnostics.last?.tlvIndex == nil)
            #expect(decoded.observation.diagnostics.last?.byteOffset == nil)
        }
    }

    @Test
    func excludedOuterDuplicateIsNotSemanticallyDecodedOrUsedAsFallback() {
        let decoded = BGPLSAttributeDecoder.decode(pathAttributes: [
            Self.attribute(Self.tlv(1026, [65])), Self.attribute([4], flags: 0),
        ])
        #expect(decoded.node.name == "A")
        #expect(decoded.observation.availability == .present)
        #expect(decoded.observation.diagnostics.map(\.category) == [.duplicateAttribute])
        #expect(decoded.observation.attributes.last?.value == [4])
        #expect(decoded.observation.attributes.last?.flags == 0)
    }

    @Test
    func evidenceAndDiagnosticCoordinatesUseOriginalPathAttributeIndexes() throws {
        let first = Self.tlv(60_000, [1, 2, 3])
        let invalid = Self.tlv(1095, [0, 0, 0, 10])
        let decoded = BGPLSAttributeDecoder.decode(pathAttributes: [
            BGPPathAttribute(flags: 0x40, typeCode: BGPPathAttributeType.origin, value: ByteBuffer(bytes: [0])),
            Self.attribute(first + invalid),
            BGPPathAttribute(flags: 0x40, typeCode: BGPPathAttributeType.asPath, value: ByteBuffer()),
            Self.attribute(Self.tlv(1026, [66])),
        ])
        #expect(decoded.observation.attributes.map(\.attributeIndex) == [1, 3])
        let issue = try #require(decoded.observation.diagnostics.first)
        #expect(issue.attributeIndex == 1)
        #expect(issue.tlvIndex == 1)
        #expect(issue.tlvType == 1095)
        #expect(issue.byteOffset == first.count)
        #expect(issue.originalBytes == invalid)
        #expect(decoded.observation.attributes.first?.tlvs.map(\.originalBytes) == [first, invalid])
        let observationHash = decoded.observation.hashValue
        let copiedHash = decoded.observation.hashValue
        #expect(observationHash == copiedHash)
        #expect(Set([decoded.observation]).contains(decoded.observation))
    }

    @Test
    func decodingDoesNotMutateOriginalPathAttributeBuffers() {
        var buffer = ByteBuffer(bytes: [0, 0] + Self.tlv(1026, [65]))
        buffer.moveReaderIndex(forwardBy: 2)
        let original = BGPPathAttribute(flags: 0x90, typeCode: 29, value: buffer)
        let before = original
        let decoded = BGPLSAttributeDecoder.decode(pathAttributes: [original])
        #expect(original == before)
        #expect(original.value.readerIndex == 2)
        #expect(decoded.node.name == "A")
        #expect(decoded.observation.attributes.first?.value == Self.tlv(1026, [65]))
    }

    private static func decode(_ bytes: [UInt8]) -> BGPLSAttributeDecoder.DecodedAttributes {
        BGPLSAttributeDecoder.decode(pathAttributes: [attribute(bytes)])
    }

    private static func attribute(_ bytes: [UInt8], flags: UInt8 = 0x80) -> BGPPathAttribute {
        BGPPathAttribute(flags: flags, typeCode: BGPPathAttributeType.bgpLSAttribute, value: ByteBuffer(bytes: bytes))
    }

    private static func tlv(_ type: UInt16, _ value: [UInt8]) -> [UInt8] {
        [
            UInt8(type >> 8), UInt8(truncatingIfNeeded: type), UInt8(value.count >> 8),
            UInt8(truncatingIfNeeded: value.count),
        ]
            + value
    }

    private static func integerBytes(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value >> 24), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ]
    }

    private static func floatBytes(_ value: Float) -> [UInt8] { integerBytes(value.bitPattern) }
}
