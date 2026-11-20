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
import NIOCore
import Testing

/// Synthetic RFC 9552 topology fixtures; these are not vendor captures.
enum IPv6TopologyFixture {
    static func nodeDescriptor(_ type: UInt16 = 256, lastByte: UInt8 = 1) -> BGPLSTLV {
        BGPLSTLV(
            type: type,
            value: encode([
                BGPLSTLV(type: 512, value: [0, 0, 253, 233]),
                BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, lastByte]),
            ])
        )
    }

    static func encode(_ descriptors: [BGPLSTLV]) -> [UInt8] {
        var buffer = ByteBuffer()
        for descriptor in descriptors {
            buffer.writeInteger(descriptor.type)
            buffer.writeInteger(UInt16(descriptor.value.count))
            buffer.writeBytes(descriptor.value)
        }
        return Array(buffer.readableBytesView)
    }

    static func wire(
        type: UInt16, descriptors: [BGPLSTLV], protocolID: UInt8 = 2, identifier: UInt64 = 42
    ) -> [UInt8] {
        let body = encode(descriptors)
        var buffer = ByteBuffer()
        buffer.writeInteger(type)
        buffer.writeInteger(UInt16(9 + body.count))
        buffer.writeInteger(protocolID)
        buffer.writeInteger(identifier)
        buffer.writeBytes(body)
        return Array(buffer.readableBytesView)
    }

    static func prefixWire(
        _ reachability: [UInt8], type: UInt16 = 4, extra: [BGPLSTLV] = []
    ) -> [UInt8] {
        wire(
            type: type,
            descriptors: [nodeDescriptor(), BGPLSTLV(type: 265, value: reachability)] + extra
        )
    }

    static func parse(_ bytes: [UInt8]) throws -> BGPLSNLRI {
        let parsed = try BGPLSNLRIParser.parseAll(ByteBuffer(bytes: bytes))
        #expect(parsed.count == 1)
        return try #require(parsed.first)
    }

    static func prefix(_ reachability: [UInt8], extra: [BGPLSTLV] = []) throws -> BGPLSIPv6PrefixNLRI {
        guard case .ipv6Prefix(let value) = try parse(prefixWire(reachability, extra: extra)) else {
            throw BGPLSClientError.protocolError("test expected typed IPv6 prefix")
        }
        return value
    }

    static func prefix(_ text: String, extra: [BGPLSTLV] = []) throws -> BGPLSIPv6PrefixNLRI {
        let address = try #require(IPv6Address(text))
        let count = (address.prefixLength.intValue + 7) / 8
        let bytes = Array(addressBytes(address.address).prefix(count))
        return try prefix([address.prefixLength.rawValue] + bytes, extra: extra)
    }

    static func addressBytes(_ text: String) throws -> [UInt8] {
        let address = try #require(IPv6Address(text))
        return addressBytes(address.address)
    }

    private static func addressBytes(_ address: UInt128) -> [UInt8] {
        //  UInt128 remains available at the macOS 15 floor; InlineArray requires macOS 26.
        (0..<16).map { UInt8(truncatingIfNeeded: address >> (120 - 8 * $0)) }
    }

    static func link(_ descriptors: [BGPLSTLV]) throws -> BGPLSLinkNLRI {
        guard
            case .link(let value) = try parse(
                wire(type: 2, descriptors: [nodeDescriptor(), nodeDescriptor(257, lastByte: 2)] + descriptors)
            )
        else {
            throw BGPLSClientError.protocolError("test expected link")
        }
        return value
    }

    static func update(reachable: Bool, nlris: [UInt8]) throws -> BGPUpdateMessage {
        try BGPUpdateParser.parse(updateBody(reachable: reachable, nlris: nlris))
    }

    static func updateBody(reachable: Bool, nlris: [UInt8]) -> ByteBuffer {
        var attribute = ByteBuffer()
        attribute.writeInteger(UInt16(16_388))
        attribute.writeInteger(UInt8(71))
        if reachable {
            //  IPv6 topology uses the existing IPv4 BGP-LS session/next hop, not AFI 2.
            attribute.writeInteger(UInt8(4))
            attribute.writeBytes([192, 0, 2, 254])
            attribute.writeInteger(UInt8(0))
        }
        attribute.writeBytes(nlris)
        var body = ByteBuffer()
        body.writeInteger(UInt16(0))
        body.writeInteger(UInt16(attribute.readableBytes + 4))
        body.writeInteger(UInt8(0x90))
        body.writeInteger(UInt8(reachable ? 14 : 15))
        body.writeInteger(UInt16(attribute.readableBytes))
        body.writeBuffer(&attribute)
        return body
    }
}
