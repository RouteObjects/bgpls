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

/// Parses BGP-LS NLRI blobs (RFC 7752 / RFC 9552) for AFI 16388 / SAFI 71.
public enum BGPLSNLRIParser {
    /// Whether a diagnostic describes a discarded object or retained, nonconforming wire data.
    public enum Disposition: String, Sendable, Hashable {
        case discarded
        case acceptedWithWarning
    }

    /// Collector classifications, not a claim of comprehensive BGP protocol validation.
    /// Categories describe the reason, not the disposition: a complete outer frame can be
    /// discarded even when its contents have malformed encoding.
    public enum Category: String, Sendable, Hashable {
        /// Invalid byte structure, recognized field width/range, or Node Descriptor sub-TLV uniqueness.
        case malformedEncoding
        /// Missing or ambiguous identity content, or a value rejected by the typed collector.
        /// This does not imply that the content otherwise conforms to the protocol.
        case invalidContent
        case linkLocalAddress
        case nonZeroPrefixPadding
    }

    /// Evidence for one completely framed NLRI, relative to the start of its NLRI field.
    public struct Diagnostic: Sendable, Hashable {
        public let disposition: Disposition
        public let category: Category
        public let nlriType: UInt16
        /// Zero-based position, including unknown and discarded NLRIs.
        public let nlriIndex: Int
        /// Zero-based byte offset of the outer NLRI type/length header.
        public let byteOffset: Int
        /// Complete original NLRI, including its four-octet type/length header.
        public let rawNLRI: [UInt8]
        public let message: String
        public let descriptorType: UInt16?

        public init(
            disposition: Disposition, category: Category, nlriType: UInt16,
            nlriIndex: Int, byteOffset: Int, rawNLRI: [UInt8], message: String,
            descriptorType: UInt16? = nil
        ) {
            self.disposition = disposition
            self.category = category
            self.nlriType = nlriType
            self.nlriIndex = nlriIndex
            self.byteOffset = byteOffset
            self.rawNLRI = rawNLRI
            self.message = message
            self.descriptorType = descriptorType
        }
    }

    /// Accepted NLRIs and ordered evidence for discarded or nonconforming objects.
    public struct ParseResult: Sendable, Hashable {
        public let nlris: [BGPLSNLRI]
        public let diagnostics: [Diagnostic]
    }

    /// Parses consecutive NLRIs from an MP_REACH / MP_UNREACH NLRI field.
    public static func parseAll(_ buffer: ByteBuffer) throws -> [BGPLSNLRI] {
        var buffer = buffer
        var result: [BGPLSNLRI] = []
        while buffer.readableBytes > 0 {
            result.append(try parseOne(&buffer))
        }
        return result
    }

    public static func parseOne(_ buffer: inout ByteBuffer) throws -> BGPLSNLRI {
        let frame = try readFrame(&buffer)
        do {
            return try decode(typeRaw: frame.type, body: frame.body)
        } catch let rejection as BodyRejection {
            //  Strict callers keep the existing public error category and messages.
            throw BGPLSClientError.protocolError(rejection.message)
        }
    }

    /// Isolates explicitly classified content failures inside complete NLRI frames.
    ///
    /// An incomplete outer header or advertised body remains fatal: no boundary is guessed,
    /// and no partially collected result is returned. Unknown NLRI/TLV types remain accepted.
    public static func parseAllIsolating(_ buffer: ByteBuffer) throws -> ParseResult {
        var buffer = buffer
        let fieldStart = buffer.readerIndex
        var nlris: [BGPLSNLRI] = []
        var diagnostics: [Diagnostic] = []
        var index = 0
        while buffer.readableBytes > 0 {
            let offset = buffer.readerIndex - fieldStart
            let availableType = buffer.getInteger(at: buffer.readerIndex, as: UInt16.self)
            let frame: (type: UInt16, body: ByteBuffer, raw: [UInt8])
            do {
                frame = try readFrame(&buffer)
            } catch BGPLSClientError.protocolError(let message) {
                //  Even an incomplete frame has a known starting position. Preserve
                // those coordinates without guessing its extent or changing strict parser errors.
                let typeDetail = availableType.map { " type=\($0)" } ?? ""
                throw BGPLSClientError.protocolError(
                    "disposition=fatal category=malformedEncoding index=\(index) offset=\(offset)\(typeDetail): \(message)"
                )
            }
            do {
                let nlri = try decode(typeRaw: frame.type, body: frame.body)
                nlris.append(nlri)
                diagnostics.append(
                    contentsOf: warnings(for: nlri).map { warning in
                        Diagnostic(
                            disposition: .acceptedWithWarning, category: warning.category,
                            nlriType: frame.type, nlriIndex: index, byteOffset: offset,
                            rawNLRI: frame.raw, message: warning.message, descriptorType: warning.descriptorType
                        )
                    })
            } catch let rejection as BodyRejection {
                //  Catch only deliberate parser rejections, never arbitrary implementation errors.
                diagnostics.append(
                    Diagnostic(
                        disposition: .discarded, category: rejection.category,
                        nlriType: frame.type, nlriIndex: index, byteOffset: offset,
                        rawNLRI: frame.raw, message: rejection.message, descriptorType: rejection.descriptorType
                    )
                )
            }
            index += 1
        }
        return ParseResult(nlris: nlris, diagnostics: diagnostics)
    }

    private struct BodyRejection: Error {
        let category: Category
        let message: String
        let descriptorType: UInt16?

        init(_ category: Category, _ message: String, descriptorType: UInt16? = nil) {
            self.category = category
            self.message = message
            self.descriptorType = descriptorType
        }
    }

    private static func readFrame(_ buffer: inout ByteBuffer) throws -> (
        type: UInt16, body: ByteBuffer, raw: [UInt8]
    ) {
        //  NIO byte reads are limited to the readable range; retain the original
        // view so advancing the parser cannot erase the diagnostic's outer header.
        let original = buffer
        guard let typeRaw: UInt16 = buffer.readInteger(),
            let length: UInt16 = buffer.readInteger()
        else {
            throw BGPLSClientError.protocolError("BGP-LS NLRI type/length truncated")
        }
        guard buffer.readableBytes >= Int(length) else {
            throw BGPLSClientError.protocolError("BGP-LS NLRI truncated (type \(typeRaw))")
        }
        let body = buffer.readSlice(length: Int(length)) ?? ByteBuffer()
        let raw = Array(original.readableBytesView.prefix(4 + Int(length)))
        return (typeRaw, body, raw)
    }

    private static func decode(typeRaw: UInt16, body: ByteBuffer) throws -> BGPLSNLRI {
        var body = body
        let raw = body.getBytes(at: body.readerIndex, length: body.readableBytes) ?? []

        guard let type = BGPLSNLRIType(rawValue: typeRaw) else {
            return .unknown(type: typeRaw, raw: raw)
        }

        guard let protocolID: UInt8 = body.readInteger(),
            let identifier: UInt64 = body.readInteger()
        else {
            throw BodyRejection(.malformedEncoding, "BGP-LS NLRI protocol/identifier truncated")
        }

        //  Unknown top-level TLVs may precede or follow familiar descriptors. Preserve
        // them rather than treating a forward-compatible NLRI as malformed (RFC 9552 §5.1).
        var descriptors: [BGPLSTLV] = []
        while body.readableBytes > 0 { descriptors.append(try readTLV(&body)) }

        switch type {
        case .node:
            let local = try takeNodeDescriptors(
                &descriptors, expectedType: BGPLSDescriptorType.localNodeDescriptors, protocolID: protocolID
            )
            return .node(
                BGPLSNodeNLRI(
                    protocolID: protocolID, identifier: identifier, localNode: local,
                    additionalDescriptors: descriptors
                )
            )

        case .link:
            let local = try takeNodeDescriptors(
                &descriptors, expectedType: BGPLSDescriptorType.localNodeDescriptors, protocolID: protocolID
            )
            let remote = try takeNodeDescriptors(
                &descriptors, expectedType: BGPLSDescriptorType.remoteNodeDescriptors, protocolID: protocolID
            )
            let parsed = try parseLinkDescriptors(descriptors)
            return .link(
                BGPLSLinkNLRI(
                    protocolID: protocolID,
                    identifier: identifier,
                    localNode: local,
                    remoteNode: remote,
                    linkDescriptors: descriptors,
                    localIPv4Interface: parsed.localIPv4,
                    remoteIPv4Neighbor: parsed.remoteIPv4,
                    localLinkIdentifier: parsed.localIdentifier,
                    remoteLinkIdentifier: parsed.remoteIdentifier,
                    localIPv6Interface: parsed.localIPv6,
                    remoteIPv6Neighbor: parsed.remoteIPv6
                )
            )

        case .ipv4TopologyPrefix:
            let local = try takeNodeDescriptors(
                &descriptors, expectedType: BGPLSDescriptorType.localNodeDescriptors, protocolID: protocolID
            )
            let network = try parsePrefixDescriptors(descriptors, as: AF.V4.self)
            return .ipv4Prefix(
                BGPLSIPv4PrefixNLRI(
                    protocolID: protocolID,
                    identifier: identifier,
                    localNode: local,
                    network: network,
                    prefixDescriptors: descriptors
                )
            )

        case .ipv6TopologyPrefix:
            let local = try takeNodeDescriptors(
                &descriptors, expectedType: BGPLSDescriptorType.localNodeDescriptors, protocolID: protocolID
            )
            let network = try parsePrefixDescriptors(descriptors, as: AF.V6.self)
            return .ipv6Prefix(
                BGPLSIPv6PrefixNLRI(
                    protocolID: protocolID,
                    identifier: identifier,
                    localNode: local,
                    network: network,
                    prefixDescriptors: descriptors
                )
            )
        }
    }

    // MARK: - Accepted-content diagnostics

    private struct Warning {
        let category: Category
        let message: String
        let descriptorType: UInt16
    }

    private static func warnings(for nlri: BGPLSNLRI) -> [Warning] {
        switch nlri {
        case .link(let link):
            return link.linkDescriptors.compactMap { descriptor in
                let isLinkLocal: Bool
                switch descriptor.type {
                case BGPLSDescriptorType.ipv4InterfaceAddress, BGPLSDescriptorType.ipv4NeighborAddress:
                    isLinkLocal = descriptor.value[0] == 169 && descriptor.value[1] == 254
                case BGPLSDescriptorType.ipv6InterfaceAddress, BGPLSDescriptorType.ipv6NeighborAddress:
                    isLinkLocal = descriptor.value[0] == 0xfe && descriptor.value[1] & 0xc0 == 0x80
                default:
                    return nil
                }
                guard isLinkLocal else { return nil }
                //  RFC 9552 forbids these sender encodings; retain observed topology
                // and its original bytes while distinguishing acceptance from conformance.
                return Warning(
                    category: .linkLocalAddress,
                    message: "link-local address in Link Descriptor \(descriptor.type)",
                    descriptorType: descriptor.type
                )
            }
        case .ipv4Prefix(let prefix):
            return prefixWarnings(prefix)
        case .ipv6Prefix(let prefix):
            return prefixWarnings(prefix)
        case .node, .unknown:
            return []
        }
    }

    private static func prefixWarnings<Family: IPAddressFamily>(_ prefix: BGPLSPrefixNLRI<Family>) -> [Warning] {
        guard
            let reachability = prefix.prefixDescriptors.first(where: { $0.type == BGPLSDescriptorType.ipReachability }),
            let length = reachability.value.first, let last = reachability.value.last,
            length % 8 != 0
        else { return [] }
        let unusedBits = 8 - Int(length % 8)
        guard last & UInt8((1 << unusedBits) - 1) != 0 else { return [] }
        //  Name the canonical prefix while retaining the sender's original padding in
        // the diagnostic frame; the log can identify the object without dumping raw bytes.
        return [
            Warning(
                category: .nonZeroPrefixPadding,
                message: "nonzero trailing bits in IP Reachability descriptor for \(prefix.network.description)",
                descriptorType: BGPLSDescriptorType.ipReachability
            )
        ]
    }

    // MARK: - Descriptors

    private static func takeNodeDescriptors(
        _ descriptors: inout [BGPLSTLV],
        expectedType: UInt16,
        protocolID: UInt8
    ) throws -> BGPLSNodeIdentity {
        let matches = descriptors.indices.filter { descriptors[$0].type == expectedType }
        guard matches.count == 1, let index = matches.first else {
            throw BodyRejection(
                .invalidContent, "expected exactly one Node Descriptor TLV \(expectedType)",
                descriptorType: expectedType
            )
        }
        let tlv = descriptors.remove(at: index)
        var sub = ByteBuffer(bytes: tlv.value)
        var identity = BGPLSNodeIdentity()
        var raw: [BGPLSTLV] = []
        var seen: Set<UInt16> = []
        while sub.readableBytes > 0 {
            let subTLV = try readTLV(&sub)
            try recordDescriptor(subTLV, seen: &seen, category: .malformedEncoding)
            raw.append(subTLV)
            switch subTLV.type {
            case BGPLSDescriptorType.autonomousSystem:
                try requireWidth(subTLV, 4)
                identity.autonomousSystem = AutonomousSystemNumber(readUInt32(subTLV.value))
            case BGPLSDescriptorType.bgpLSIdentifier:
                try requireWidth(subTLV, 4)
                identity.bgpLSIdentifier = readUInt32(subTLV.value)
            case BGPLSDescriptorType.ospfAreaID:
                try requireWidth(subTLV, 4)
                identity.ospfAreaID = OSPFAreaID(readUInt32(subTLV.value))
            case BGPLSDescriptorType.igpRouterID:
                do {
                    identity.igpRouterID = try BGPLSIGPRouterID.decode(protocolID: protocolID, bytes: subTLV.value)
                } catch let failure as BGPLSIGPRouterID.DecodingFailure {
                    //  Preserve the strict parser's public message while distinguishing
                    // a wrong encoded width from a well-sized, invalid identity value.
                    let category: Category
                    switch failure {
                    case .invalidLength: category = .malformedEncoding
                    case .invalidValue: category = .invalidContent
                    }
                    throw BodyRejection(
                        category, "invalid IGP Router-ID for Protocol-ID \(protocolID)", descriptorType: subTLV.type
                    )
                }
            default:
                break
            }
        }
        if BGPLSProtocolID(rawValue: protocolID) != nil, identity.igpRouterID == nil {
            throw BodyRejection(
                .invalidContent, "missing IGP Router-ID in Node Descriptor",
                descriptorType: BGPLSDescriptorType.igpRouterID
            )
        }
        identity.rawTLVs = raw
        return identity
    }

    private static func parseLinkDescriptors(
        _ descriptors: [BGPLSTLV]
    ) throws -> (
        localIPv4: IPv4Address?, remoteIPv4: IPv4Address?,
        localIPv6: IPv6Address?, remoteIPv6: IPv6Address?,
        localIdentifier: UInt32?, remoteIdentifier: UInt32?
    ) {
        var localIPv4: IPv4Address?
        var remoteIPv4: IPv4Address?
        var localIPv6: IPv6Address?
        var remoteIPv6: IPv6Address?
        var localIdentifier: UInt32?
        var remoteIdentifier: UInt32?
        var seen: Set<UInt16> = []
        for tlv in descriptors {
            switch tlv.type {
            case BGPLSDescriptorType.linkLocalRemoteIdentifiers:
                try recordDescriptor(tlv, seen: &seen)
                try requireWidth(tlv, 8)
                localIdentifier = readUInt32(Array(tlv.value.prefix(4)))
                remoteIdentifier = readUInt32(Array(tlv.value.suffix(4)))
            case BGPLSDescriptorType.ipv4InterfaceAddress:
                try recordDescriptor(tlv, seen: &seen)
                try requireWidth(tlv, 4)
                localIPv4 = IPv4Address(address: readUInt32(tlv.value))
            case BGPLSDescriptorType.ipv4NeighborAddress:
                try recordDescriptor(tlv, seen: &seen)
                try requireWidth(tlv, 4)
                remoteIPv4 = IPv4Address(address: readUInt32(tlv.value))
            case BGPLSDescriptorType.ipv6InterfaceAddress:
                try recordDescriptor(tlv, seen: &seen)
                try requireWidth(tlv, 16)
                localIPv6 = IPv6Address(address: readUInt128(tlv.value))
            case BGPLSDescriptorType.ipv6NeighborAddress:
                try recordDescriptor(tlv, seen: &seen)
                try requireWidth(tlv, 16)
                remoteIPv6 = IPv6Address(address: readUInt128(tlv.value))
            case BGPLSDescriptorType.multiTopologyID:
                try recordDescriptor(tlv, seen: &seen)
                try requireWidth(tlv, 2)
            default:
                break
            }
        }
        return (localIPv4, remoteIPv4, localIPv6, remoteIPv6, localIdentifier, remoteIdentifier)
    }

    private static func parsePrefixDescriptors<Family: IPAddressFamily>(
        _ descriptors: [BGPLSTLV], as family: Family.Type
    ) throws -> IPNetwork<Family> {
        var network: IPNetwork<Family>?
        var seen: Set<UInt16> = []
        for tlv in descriptors {
            switch tlv.type {
            case BGPLSDescriptorType.multiTopologyID:
                try recordDescriptor(tlv, seen: &seen)
                try requireWidth(tlv, 2)
            case BGPLSDescriptorType.ospfRouteType:
                try recordDescriptor(tlv, seen: &seen)
                try requireWidth(tlv, 1)
            case BGPLSDescriptorType.ipReachability:
                try recordDescriptor(tlv, seen: &seen)
                guard let rawLength = tlv.value.first else {
                    throw BodyRejection(
                        .malformedEncoding, "IP Reachability descriptor missing prefix length",
                        descriptorType: tlv.type
                    )
                }
                // IP Reachability: prefix length (1) + prefix octets → canonical swift-cidr network.
                let lengthRaw = Int(rawLength)
                guard let prefixLength = PrefixLength<Family>(lengthRaw) else {
                    throw BodyRejection(
                        .malformedEncoding,
                        "invalid \(Family.familyName) prefix length \(lengthRaw) in BGP-LS reachability TLV",
                        descriptorType: tlv.type
                    )
                }
                let octetCount = (lengthRaw + 7) / 8
                //  A truncated prefix must not be padded into another valid RIB identity.
                try requireWidth(tlv, 1 + octetCount)
                //  The NLRI type selects the address width, not the BGP transport or
                // IGP Protocol-ID. Both families retain identical padding canonicalization.
                var addr: Family.Storage = 0
                for i in 0..<octetCount {
                    addr |= Family.Storage(tlv.value[1 + i]) << (Family.bitWidth - 8 - 8 * i)
                }
                //  Reachability carries a canonical prefix, so retain that form directly.
                network = IPNetwork<Family>(prefix: addr, prefixLength: prefixLength)
            default:
                break
            }
        }
        guard let network else {
            throw BodyRejection(
                .invalidContent, "\(Family.familyName) prefix NLRI missing IP Reachability TLV",
                descriptorType: BGPLSDescriptorType.ipReachability
            )
        }
        return network
    }

    private static func recordDescriptor(
        _ tlv: BGPLSTLV, seen: inout Set<UInt16>, category: Category = .invalidContent
    ) throws {
        //  Node sub-TLV uniqueness is an explicit wire rule; other recognized singleton
        // duplicates make this collector's projection ambiguous without guessing which to use.
        guard seen.insert(tlv.type).inserted else {
            throw BodyRejection(category, "duplicate BGP-LS descriptor \(tlv.type)", descriptorType: tlv.type)
        }
    }

    private static func requireWidth(_ tlv: BGPLSTLV, _ width: Int) throws {
        guard tlv.value.count == width else {
            throw BodyRejection(
                .malformedEncoding, "invalid BGP-LS descriptor length (type \(tlv.type))",
                descriptorType: tlv.type
            )
        }
    }

    private static func readTLV(_ buffer: inout ByteBuffer) throws -> BGPLSTLV {
        guard let type: UInt16 = buffer.readInteger(),
            let length: UInt16 = buffer.readInteger()
        else {
            throw BodyRejection(.malformedEncoding, "BGP-LS TLV header truncated")
        }
        guard buffer.readableBytes >= Int(length) else {
            throw BodyRejection(
                .malformedEncoding, "BGP-LS TLV value truncated (type \(type))", descriptorType: type
            )
        }
        let value = buffer.readBytes(length: Int(length)) ?? []
        return BGPLSTLV(type: type, value: value)
    }

    private static func readUInt32(_ bytes: [UInt8]) -> UInt32 {
        guard bytes.count >= 4 else { return 0 }
        return (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) | (UInt32(bytes[2]) << 8)
            | UInt32(bytes[3])
    }

    private static func readUInt128(_ bytes: [UInt8]) -> UInt128 {
        bytes.reduce(UInt128.zero) { ($0 << 8) | UInt128($1) }
    }
}
