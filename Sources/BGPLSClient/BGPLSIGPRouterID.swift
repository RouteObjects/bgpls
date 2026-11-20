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

/// A six-octet IS-IS System ID, canonically written as `xxxx.xxxx.xxxx`.
///
/// This is an ISO identifier, not an IP address. Uppercase ASCII hexadecimal input is
/// accepted; descriptions and JSON use lowercase, fixed-width hexadecimal groups.
public struct ISISSystemID: Sendable, Hashable, LosslessStringConvertible, Codable {
    public let bytes: [UInt8]

    public init?(bytes: [UInt8]) {
        guard bytes.count == 6 else { return nil }
        self.bytes = bytes
    }

    public init?(_ description: String) {
        let groups = description.split(separator: ".", omittingEmptySubsequences: false)
        guard groups.count == 3 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(6)
        for group in groups {
            guard group.utf8.count == 4, group.utf8.allSatisfy(isASCIIHex),
                let word = UInt16(group, radix: 16)
            else { return nil }
            bytes.append(UInt8(truncatingIfNeeded: word >> 8))
            bytes.append(UInt8(truncatingIfNeeded: word))
        }
        self.init(bytes: bytes)
    }

    public var description: String {
        stride(from: 0, to: 6, by: 2).map { hexByte(bytes[$0]) + hexByte(bytes[$0 + 1]) }
            .joined(separator: ".")
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let value = Self(text) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid IS-IS System ID")
        }
        self = value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// An IS-IS LAN pseudonode: the DIS System ID followed by a nonzero one-octet PSN ID.
public struct ISISPseudonodeID: Sendable, Hashable, LosslessStringConvertible, Codable {
    public let systemID: ISISSystemID
    public let pseudonodeID: UInt8

    public init?(systemID: ISISSystemID, pseudonodeID: UInt8) {
        //  RFC 9552 identifies real nodes with six octets; a seven-octet ID must use a nonzero PSN.
        guard pseudonodeID != 0 else { return nil }
        self.systemID = systemID
        self.pseudonodeID = pseudonodeID
    }

    public init?(_ description: String) {
        let groups = description.split(separator: ".", omittingEmptySubsequences: false)
        guard groups.count == 4, let last = groups.last,
            last.utf8.count == 2, last.utf8.allSatisfy(isASCIIHex),
            let systemID = ISISSystemID(groups.prefix(3).joined(separator: ".")),
            let pseudonodeID = UInt8(last, radix: 16)
        else { return nil }
        self.init(systemID: systemID, pseudonodeID: pseudonodeID)
    }

    public var bytes: [UInt8] { systemID.bytes + [pseudonodeID] }
    public var description: String { "\(systemID).\(hexByte(pseudonodeID))" }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let value = Self(text) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid IS-IS pseudonode ID")
        }
        self = value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// Protocol-aware IGP Router-ID carried in BGP-LS Node Descriptor sub-TLV 515.
///
/// IS-IS identities must not be projected onto IPv4 addresses. Unknown protocols retain
/// the original descriptor bytes so future identities remain distinct and visible.
public enum BGPLSIGPRouterID: Sendable, Hashable, Codable, CustomStringConvertible {
    case isisSystemID(ISISSystemID)
    case isisPseudonode(ISISPseudonodeID)
    case ospfRouterID(IPv4Address)
    case ospfv2Pseudonode(routerID: IPv4Address, interfaceAddress: IPv4Address)
    case ospfv3Pseudonode(routerID: IPv4Address, interfaceID: UInt32)
    case opaque([UInt8])

    /// The OSPF router component, when present; never interprets IS-IS or opaque bytes as IPv4.
    public var ipv4RouterID: IPv4Address? {
        switch self {
        case .ospfRouterID(let address), .ospfv2Pseudonode(let address, _), .ospfv3Pseudonode(let address, _):
            return IPv4Address(address: address.address)
        case .isisSystemID, .isisPseudonode, .opaque:
            return nil
        }
    }

    /// Descriptor payload bytes, excluding the enclosing TLV type and length.
    public var rawValue: [UInt8] {
        switch self {
        case .isisSystemID(let id): return id.bytes
        case .isisPseudonode(let id): return id.bytes
        case .ospfRouterID(let id): return Self.bytes(id.address)
        case .ospfv2Pseudonode(let id, let address): return Self.bytes(id.address) + Self.bytes(address.address)
        case .ospfv3Pseudonode(let id, let interface): return Self.bytes(id.address) + Self.bytes(interface)
        case .opaque(let bytes): return bytes
        }
    }

    public var description: String {
        switch self {
        case .isisSystemID(let id): return id.description
        case .isisPseudonode(let id): return id.description
        case .ospfRouterID(let id): return id.formatted(.addressOnly)
        case .ospfv2Pseudonode(let id, let address):
            return "\(id.formatted(.addressOnly)):\(address.formatted(.addressOnly))"
        case .ospfv3Pseudonode(let id, let interface): return "\(id.formatted(.addressOnly)):\(interface)"
        case .opaque(let bytes): return "opaque:" + bytes.map(hexByte).joined()
        }
    }

    //  Separate encoded shape from identity values without exposing parser diagnostics
    // or changing the public protocol-error contract at the NLRI parser boundary.
    enum DecodingFailure: Error {
        case invalidLength
        case invalidValue
    }

    //  Length alone cannot distinguish an OSPF identity from a future protocol's opaque identifier.
    static func decode(protocolID: UInt8, bytes: [UInt8]) throws -> Self {
        switch BGPLSProtocolID(rawValue: protocolID) {
        case .isisLevel1, .isisLevel2:
            if let systemID = ISISSystemID(bytes: bytes) { return .isisSystemID(systemID) }
            guard bytes.count == 7 else { throw DecodingFailure.invalidLength }
            guard let systemID = ISISSystemID(bytes: Array(bytes.prefix(6))),
                let id = ISISPseudonodeID(systemID: systemID, pseudonodeID: bytes[6])
            else { throw DecodingFailure.invalidValue }
            return .isisPseudonode(id)
        case .ospfv2, .ospfv3:
            if bytes.count == 4 { return .ospfRouterID(IPv4Address(address: uint32(bytes))) }
            if bytes.count == 8 {
                let routerID = IPv4Address(address: uint32(Array(bytes.prefix(4))))
                let suffix = uint32(Array(bytes.suffix(4)))
                if protocolID == BGPLSProtocolID.ospfv2.rawValue {
                    return .ospfv2Pseudonode(routerID: routerID, interfaceAddress: IPv4Address(address: suffix))
                }
                return .ospfv3Pseudonode(routerID: routerID, interfaceID: suffix)
            }
            throw DecodingFailure.invalidLength
        case .direct, .static, .none:
            return .opaque(bytes)
        }
    }

    private static func uint32(_ bytes: [UInt8]) -> UInt32 {
        bytes.reduce(0) { ($0 << 8) | UInt32($1) }
    }

    private static func bytes(_ value: UInt32) -> [UInt8] {
        [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> $0) }
    }
}

private func isASCIIHex(_ byte: UInt8) -> Bool {
    (48...57).contains(byte) || (65...70).contains(byte) || (97...102).contains(byte)
}

private func hexByte(_ byte: UInt8) -> String {
    let text = String(byte, radix: 16)
    return byte < 16 ? "0" + text : text
}
