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

/// A finite, nonnegative advertised bandwidth, measured in bytes per second.
///
/// The binary32 value is the unit used by RFC 5305. Zero (including negative
/// zero) and oversubscription are valid advertisements, not utilization claims.
/// Original wire bytes belong to the attribute observation, not this value.
public struct BGPLSBandwidth: Sendable, Hashable, Codable {
    public let bytesPerSecond: Float

    /// Conversion uses binary64 arithmetic so every finite binary32 input is safe.
    public var bitsPerSecond: Double { Double(bytesPerSecond) * 8 }

    public init?(bytesPerSecond: Float) {
        guard bytesPerSecond.isFinite, bytesPerSecond >= 0 else { return nil }
        self.bytesPerSecond = bytesPerSecond
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(Float.self)
        guard let bandwidth = Self(bytesPerSecond: value) else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "Bandwidth must be finite and nonnegative bytes per second")
        }
        self = bandwidth
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(bytesPerSecond)
    }
}

/// Advertised unreserved bandwidth in priority order, from 0 through 7.
public struct BGPLSUnreservedBandwidth: Sendable, Hashable, Codable {
    public let values: [BGPLSBandwidth]

    public init?(values: [BGPLSBandwidth]) {
        guard values.count == 8 else { return nil }
        self.values = values
    }

    /// The caller must supply a priority in `0...7`.
    public subscript(priority: Int) -> BGPLSBandwidth { values[priority] }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let values = try container.decode([BGPLSBandwidth].self)
        guard let bandwidth = Self(values: values) else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "Unreserved bandwidth requires exactly eight priorities")
        }
        self = bandwidth
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(values)
    }
}

/// Supported node projections from the BGP-LS attribute. Missing is not zero.
public struct BGPLSNodeAttributes: Sendable, Hashable, Codable {
    /// The wire decoder accepts at most 255 ASCII octets, without normalization.
    public var name: String?

    public init(name: String? = nil) { self.name = name }
}

/// Supported link projections from the BGP-LS attribute.
public struct BGPLSLinkAttributes: Sendable, Hashable, Codable {
    public var igpMetric: UInt32?
    public var maximumLinkBandwidth: BGPLSBandwidth?
    public var maximumReservableBandwidth: BGPLSBandwidth?
    public var unreservedBandwidth: BGPLSUnreservedBandwidth?

    public init(
        igpMetric: UInt32? = nil,
        maximumLinkBandwidth: BGPLSBandwidth? = nil,
        maximumReservableBandwidth: BGPLSBandwidth? = nil,
        unreservedBandwidth: BGPLSUnreservedBandwidth? = nil
    ) {
        self.igpMetric = igpMetric
        self.maximumLinkBandwidth = maximumLinkBandwidth
        self.maximumReservableBandwidth = maximumReservableBandwidth
        self.unreservedBandwidth = unreservedBandwidth
    }
}

/// Supported IPv4 or IPv6 prefix projections from the BGP-LS attribute.
public struct BGPLSPrefixAttributes: Sendable, Hashable, Codable {
    public var metric: UInt32?

    public init(metric: UInt32? = nil) { self.metric = metric }
}

/// Whether an UPDATE supplied a usable BGP-LS attribute interpretation.
///
/// `present` may still contain rejected individual projections; inspect issues.
/// Legacy snapshots with no recorded attributes are distinct from `absent`.
public enum BGPLSAttributeAvailability: String, Sendable, Hashable, Codable {
    case absent
    case present
    case discarded
}

/// One framed TLV, preserving order and coordinates within a type-29 value.
public struct BGPLSAttributeTLVEvidence: Sendable, Hashable {
    public let tlvIndex: Int
    public let type: UInt16
    /// Offset of the TLV header from the beginning of the attribute value.
    public let byteOffset: Int
    public let value: [UInt8]

    public init(tlvIndex: Int, type: UInt16, byteOffset: Int, value: [UInt8]) {
        self.tlvIndex = tlvIndex
        self.type = type
        self.byteOffset = byteOffset
        self.value = value
    }

    /// Original TLV header and value, including unknown or uninterpreted fields.
    public var originalBytes: [UInt8] {
        [
            UInt8(type >> 8), UInt8(truncatingIfNeeded: type), UInt8(truncatingIfNeeded: value.count >> 8),
            UInt8(truncatingIfNeeded: value.count),
        ] + value
    }
}

/// Raw evidence for one outer type-29 occurrence, including excluded duplicates.
public struct BGPLSAttributeEvidence: Sendable, Hashable {
    /// Index in the original UPDATE's `pathAttributes` array, not a filtered list.
    public let attributeIndex: Int
    public let flags: UInt8
    public let value: [UInt8]
    /// Complete frames only; `value` also retains any malformed trailing bytes.
    public let tlvs: [BGPLSAttributeTLVEvidence]

    public init(attributeIndex: Int, flags: UInt8, value: [UInt8], tlvs: [BGPLSAttributeTLVEvidence]) {
        self.attributeIndex = attributeIndex
        self.flags = flags
        self.value = value
        self.tlvs = tlvs
    }
}

/// A collection gap or harmless warning with attribute-specific coordinates.
///
/// Malformed inner framing follows RFC 9552 attribute-discard behavior. Width,
/// value, duplicate-singleton and flag decisions are this collector's explicit
/// interpretation policy, not a claim of general RFC 7606 fault management.
public struct BGPLSAttributeDiagnostic: Sendable, Hashable {
    public enum Disposition: String, Sendable, Hashable, Codable {
        case attributeDiscarded
        case projectionRejected
        case acceptedWithWarning
    }

    public enum Category: String, Sendable, Hashable, Codable {
        case malformedFraming
        case invalidFlags
        case emptyAttribute
        case duplicateAttribute
        case invalidLength
        case invalidValue
        case invalidASCII
        case duplicateTLV
        case conflictingTLV
    }

    public let disposition: Disposition
    public let category: Category
    public let attributeIndex: Int
    public let tlvIndex: Int?
    public let tlvType: UInt16?
    /// Offset within the type-29 value; nil for outer-attribute-only issues.
    public let byteOffset: Int?
    public let originalBytes: [UInt8]
    public let message: String

    /// Strict UPDATE application rejects information loss, but allows warnings.
    public var isError: Bool { disposition != .acceptedWithWarning }

    public init(
        disposition: Disposition, category: Category, attributeIndex: Int,
        tlvIndex: Int? = nil, tlvType: UInt16? = nil, byteOffset: Int? = nil,
        originalBytes: [UInt8], message: String
    ) {
        self.disposition = disposition
        self.category = category
        self.attributeIndex = attributeIndex
        self.tlvIndex = tlvIndex
        self.tlvType = tlvType
        self.byteOffset = byteOffset
        self.originalBytes = originalBytes
        self.message = message
    }
}

/// Complete type-29 evidence shared by advertisements from one UPDATE.
///
/// Equality includes evidence and diagnostics. Equal RIB identity keys need not
/// imply equal observations. A later advertisement replaces this whole value.
public struct BGPLSAttributeObservation: Sendable, Hashable {
    public let availability: BGPLSAttributeAvailability
    public let attributes: [BGPLSAttributeEvidence]
    public let diagnostics: [BGPLSAttributeDiagnostic]

    public init(
        availability: BGPLSAttributeAvailability = .absent,
        attributes: [BGPLSAttributeEvidence] = [], diagnostics: [BGPLSAttributeDiagnostic] = []
    ) {
        self.availability = availability
        self.attributes = attributes
        self.diagnostics = diagnostics
    }
}
