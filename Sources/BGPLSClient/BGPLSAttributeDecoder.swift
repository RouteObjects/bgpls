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

/// Bounded interpretation of already-framed path attributes, performed once
/// during UPDATE preparation rather than separately for every advertised NLRI.
enum BGPLSAttributeDecoder {
    enum Context: Sendable, Hashable { case node, link, prefix }

    struct DecodedAttributes: Sendable {
        var node = BGPLSNodeAttributes()
        var link = BGPLSLinkAttributes()
        var prefix = BGPLSPrefixAttributes()
        var observation = BGPLSAttributeObservation()
    }

    static func decode(
        pathAttributes: [BGPPathAttribute], contexts: Set<Context> = [.node, .link, .prefix]
    ) -> DecodedAttributes {
        var evidence: [BGPLSAttributeEvidence] = []
        var firstFramingFailure: BGPLSAttributeDiagnostic?
        for (index, attribute) in pathAttributes.enumerated()
        where attribute.typeCode == BGPPathAttributeType.bgpLSAttribute {
            let bytes = Array(attribute.value.readableBytesView)
            let framed = frame(bytes, attributeIndex: index)
            if evidence.isEmpty { firstFramingFailure = framed.failure }
            evidence.append(
                BGPLSAttributeEvidence(attributeIndex: index, flags: attribute.flags, value: bytes, tlvs: framed.tlvs))
        }
        guard let first = evidence.first else { return DecodedAttributes() }

        var diagnostics: [BGPLSAttributeDiagnostic] = []
        var result = DecodedAttributes()
        var discarded = false
        // Only Optional and Transitive define this check. Extended-length and
        // other retained flag bits do not alter the type-29 interpretation.
        if first.flags & 0xc0 != 0x80 {
            diagnostics.append(
                BGPLSAttributeDiagnostic(
                    disposition: .attributeDiscarded, category: .invalidFlags, attributeIndex: first.attributeIndex,
                    originalBytes: first.value, message: "BGP-LS attribute must be Optional and non-Transitive"))
            discarded = true
        } else if first.value.isEmpty {
            diagnostics.append(
                BGPLSAttributeDiagnostic(
                    disposition: .attributeDiscarded, category: .emptyAttribute, attributeIndex: first.attributeIndex,
                    originalBytes: [], message: "Empty BGP-LS attribute has no usable interpretation"))
            discarded = true
        } else if let firstFramingFailure {
            diagnostics.append(firstFramingFailure)
            discarded = true
        } else {
            interpret(first, contexts: contexts, into: &result, diagnostics: &diagnostics)
        }

        // Outer duplicates are evidence, never fallback candidates. In
        // particular, a later good occurrence cannot repair a broken first one.
        for excluded in evidence.dropFirst() {
            diagnostics.append(
                BGPLSAttributeDiagnostic(
                    disposition: .acceptedWithWarning, category: .duplicateAttribute,
                    attributeIndex: excluded.attributeIndex, originalBytes: excluded.value,
                    message: "Duplicate BGP-LS attribute excluded; first occurrence is authoritative"))
        }
        result.observation = BGPLSAttributeObservation(
            availability: discarded ? .discarded : .present, attributes: evidence, diagnostics: diagnostics)
        return result
    }

    private static func frame(
        _ bytes: [UInt8], attributeIndex: Int
    ) -> (tlvs: [BGPLSAttributeTLVEvidence], failure: BGPLSAttributeDiagnostic?) {
        var offset = 0
        var tlvs: [BGPLSAttributeTLVEvidence] = []
        while offset < bytes.count {
            let remaining = bytes.count - offset
            let type = remaining >= 2 ? UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1]) : nil
            guard remaining >= 4 else {
                return (
                    tlvs,
                    BGPLSAttributeDiagnostic(
                        disposition: .attributeDiscarded, category: .malformedFraming, attributeIndex: attributeIndex,
                        tlvIndex: tlvs.count, tlvType: type, byteOffset: offset, originalBytes: Array(bytes[offset...]),
                        message: "Truncated BGP-LS attribute TLV header; whole attribute interpretation discarded")
                )
            }
            let length = Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
            guard length <= remaining - 4 else {
                return (
                    tlvs,
                    BGPLSAttributeDiagnostic(
                        disposition: .attributeDiscarded, category: .malformedFraming, attributeIndex: attributeIndex,
                        tlvIndex: tlvs.count, tlvType: type, byteOffset: offset, originalBytes: Array(bytes[offset...]),
                        message:
                            "BGP-LS attribute TLV exceeds enclosing value; whole attribute interpretation discarded")
                )
            }
            // The full header guard above establishes the nonoptional type.
            let framedType = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
            tlvs.append(
                BGPLSAttributeTLVEvidence(
                    tlvIndex: tlvs.count, type: framedType, byteOffset: offset,
                    value: Array(bytes[(offset + 4)..<(offset + 4 + length)])))
            offset += 4 + length
        }
        return (tlvs, nil)
    }

    private static func interpret(
        _ evidence: BGPLSAttributeEvidence, contexts: Set<Context>, into result: inout DecodedAttributes,
        diagnostics: inout [BGPLSAttributeDiagnostic]
    ) {
        let groups = Dictionary(grouping: evidence.tlvs, by: \.type)
        var visited: Set<UInt16> = []
        for tlv in evidence.tlvs {
            guard let context = context(for: tlv.type), contexts.contains(context), visited.insert(tlv.type).inserted
            else {
                continue
            }
            let occurrences = groups[tlv.type, default: []]
            var conflicting = false
            for duplicate in occurrences.dropFirst() {
                let identical = duplicate.value == tlv.value
                conflicting = conflicting || !identical
                diagnostics.append(
                    issue(
                        identical ? .acceptedWithWarning : .projectionRejected,
                        identical ? .duplicateTLV : .conflictingTLV,
                        evidence: evidence, tlv: duplicate,
                        message: identical
                            ? "Identical duplicate singleton TLV; one value exposed"
                            : "Conflicting singleton TLV values; projection unavailable"))
            }
            guard !conflicting else { continue }

            switch tlv.type {
            case 1026:
                if tlv.value.count > 255 {
                    diagnostics.append(invalidLength(evidence, tlv, expected: "at most 255 ASCII octets"))
                } else if !tlv.value.allSatisfy({ $0 < 128 }) {
                    diagnostics.append(
                        issue(
                            .projectionRejected, .invalidASCII, evidence: evidence, tlv: tlv,
                            message: "Node name contains non-ASCII octets; name unavailable"))
                } else {
                    result.node.name = String(decoding: tlv.value, as: UTF8.self)
                }
            case 1095:
                if (1...3).contains(tlv.value.count) {
                    result.link.igpMetric = tlv.value.count == 1 ? UInt32(tlv.value[0] & 0x3f) : integer(tlv.value)
                } else {
                    diagnostics.append(invalidLength(evidence, tlv, expected: "one, two, or three octets"))
                }
            case 1155:
                if tlv.value.count == 4 {
                    result.prefix.metric = integer(tlv.value)
                } else {
                    diagnostics.append(invalidLength(evidence, tlv, expected: "four octets"))
                }
            case 1089, 1090:
                guard tlv.value.count == 4 else {
                    diagnostics.append(invalidLength(evidence, tlv, expected: "four octets"))
                    continue
                }
                guard let value = bandwidth(tlv.value) else {
                    diagnostics.append(invalidBandwidth(evidence, tlv))
                    continue
                }
                if tlv.type == 1089 {
                    result.link.maximumLinkBandwidth = value
                } else {
                    result.link.maximumReservableBandwidth = value
                }
            case 1091:
                guard tlv.value.count == 32 else {
                    diagnostics.append(invalidLength(evidence, tlv, expected: "32 octets (eight priorities)"))
                    continue
                }
                let values = stride(from: 0, to: 32, by: 4).compactMap { offset in
                    bandwidth(Array(tlv.value[offset..<(offset + 4)]))
                }
                if let unreserved = BGPLSUnreservedBandwidth(values: values) {
                    result.link.unreservedBandwidth = unreserved
                } else {
                    diagnostics.append(invalidBandwidth(evidence, tlv))
                }
            default:
                break
            }
        }
        // Keep diagnostic coordinates in wire order even when a later duplicate
        // affects the interpretation of a singleton first encountered earlier.
        diagnostics.sort { ($0.tlvIndex ?? -1) < ($1.tlvIndex ?? -1) }
    }

    private static func context(for type: UInt16) -> Context? {
        switch type {
        case 1026: return .node
        case 1089, 1090, 1091, 1095: return .link
        case 1155: return .prefix
        default: return nil
        }
    }

    private static func integer(_ bytes: [UInt8]) -> UInt32 {
        bytes.reduce(0) { ($0 << 8) | UInt32($1) }
    }

    private static func bandwidth(_ bytes: [UInt8]) -> BGPLSBandwidth? {
        BGPLSBandwidth(bytesPerSecond: Float(bitPattern: integer(bytes)))
    }

    private static func invalidLength(
        _ evidence: BGPLSAttributeEvidence, _ tlv: BGPLSAttributeTLVEvidence, expected: String
    ) -> BGPLSAttributeDiagnostic {
        issue(
            .projectionRejected, .invalidLength, evidence: evidence, tlv: tlv,
            message: "TLV \(tlv.type) requires \(expected); projection unavailable")
    }

    private static func invalidBandwidth(
        _ evidence: BGPLSAttributeEvidence, _ tlv: BGPLSAttributeTLVEvidence
    ) -> BGPLSAttributeDiagnostic {
        issue(
            .projectionRejected, .invalidValue, evidence: evidence, tlv: tlv,
            message: "Bandwidth must be finite and nonnegative; whole TLV projection unavailable")
    }

    private static func issue(
        _ disposition: BGPLSAttributeDiagnostic.Disposition, _ category: BGPLSAttributeDiagnostic.Category,
        evidence: BGPLSAttributeEvidence, tlv: BGPLSAttributeTLVEvidence, message: String
    ) -> BGPLSAttributeDiagnostic {
        BGPLSAttributeDiagnostic(
            disposition: disposition, category: category, attributeIndex: evidence.attributeIndex,
            tlvIndex: tlv.tlvIndex, tlvType: tlv.type, byteOffset: tlv.byteOffset,
            originalBytes: tlv.originalBytes, message: message)
    }
}
