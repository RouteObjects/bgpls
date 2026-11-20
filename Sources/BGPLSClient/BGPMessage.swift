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

/// BGP message type codes (RFC 4271 §4.1).
public enum BGPMessageType: UInt8, Sendable, Hashable {
    case open = 1
    case update = 2
    case notification = 3
    case keepalive = 4
}

/// Decoded BGP OPEN body (RFC 4271 §4.2), without the common header.
public struct BGPOpenMessage: Sendable, Hashable {
    public var version: UInt8
    /// 2-octet My AS field from the OPEN (legacy encoding).
    public var myAS: UInt16
    public var holdTime: UInt16
    /// BGP Identifier as four octets (IPv4 address wire order).
    public var bgpIdentifier: UInt32
    /// Raw optional-parameter bytes (including capability TLVs).
    public var optionalParameters: [UInt8]

    public init(
        version: UInt8 = 4,
        myAS: UInt16,
        holdTime: UInt16,
        bgpIdentifier: UInt32,
        optionalParameters: [UInt8] = []
    ) {
        self.version = version
        self.myAS = myAS
        self.holdTime = holdTime
        self.bgpIdentifier = bgpIdentifier
        self.optionalParameters = optionalParameters
    }
}

/// BGP NOTIFICATION body (RFC 4271 §4.5).
public struct BGPNotificationMessage: Sendable, Hashable {
    public var errorCode: UInt8
    public var errorSubcode: UInt8
    public var data: [UInt8]

    public init(errorCode: UInt8, errorSubcode: UInt8 = 0, data: [UInt8] = []) {
        self.errorCode = errorCode
        self.errorSubcode = errorSubcode
        self.data = data
    }
}

/// A complete BGP message after framing (marker + length + type + body).
public enum BGPMessage: Sendable {
    case open(BGPOpenMessage)
    /// Opaque UPDATE body for Phase 1 (parsed in Phase 2).
    case update(ByteBuffer)
    case notification(BGPNotificationMessage)
    case keepalive

    public var type: BGPMessageType {
        switch self {
        case .open: return .open
        case .update: return .update
        case .notification: return .notification
        case .keepalive: return .keepalive
        }
    }
}

// MARK: - Optional parameters / capabilities

public enum BGPCapabilityCode {
    // Export fixed wire-code implementations so clients can fold them without shared storage.
    /// Multiprotocol Extensions (RFC 4760).
    @export(implementation)
    public static var multiprotocol: UInt8 { 1 }
    /// Four-octet autonomous system number support (RFC 6793).
    @export(implementation)
    public static var fourOctetAS: UInt8 { 65 }
}

/// Builds OPEN optional parameters for BGP-LS and four-octet AS support.
public enum BGPOpenCapabilities {
    // Make the fixed AFI/SAFI values available to client optimizers.
    @export(implementation)
    public static var bgpLSAFI: UInt16 { 16_388 }
    @export(implementation)
    public static var bgpLSSAFI: UInt8 { 71 }

    /// AS_TRANS represents a non-mappable ASN in the legacy two-octet OPEN field.
    static let asTrans: UInt16 = 23_456

    /// Capability TLV shared by OPEN advertisement and Unsupported Capability NOTIFICATION Data.
    static let bgpLSCapabilityValue: [UInt8] = [
        BGPCapabilityCode.multiprotocol, 4,
        UInt8((bgpLSAFI >> 8) & 0xff), UInt8(bgpLSAFI & 0xff), 0, bgpLSSAFI,
    ]

    /// Capability optional parameter (type 2) wrapping multiprotocol BGP-LS.
    public static func multiprotocolBGPLS() -> [UInt8] {
        [2, 6] + bgpLSCapabilityValue
    }

    /// BGP-LS and AS4 capabilities in one type-2 parameter, including the real local ASN.
    ///
    /// AS4 support is advertised even when the ASN fits the legacy two-octet field.
    public static func bgpLS(localAS: AutonomousSystemNumber) -> [UInt8] {
        let raw = localAS.rawValue
        return [2, 12] + bgpLSCapabilityValue + [
            BGPCapabilityCode.fourOctetAS, 4,
            UInt8((raw >> 24) & 0xff), UInt8((raw >> 16) & 0xff),
            UInt8((raw >> 8) & 0xff), UInt8(raw & 0xff),
        ]
    }

    static func legacyAS(for asn: AutonomousSystemNumber) -> UInt16 {
        UInt16(exactly: asn.rawValue) ?? asTrans
    }

    struct Parsed: Sendable, Equatable {
        var fourOctetAS: AutonomousSystemNumber?
        var supportsBGPLS = false
    }

    /// Validates the nested parameter/capability framing without interpreting unknown capabilities.
    static func parse(_ optionalParameters: [UInt8]) throws -> Parsed {
        var parameters = ByteBuffer(bytes: optionalParameters)
        var result = Parsed()
        while parameters.readableBytes > 0 {
            guard let type: UInt8 = parameters.readInteger(),
                let length: UInt8 = parameters.readInteger()
            else {
                throw BGPLSClientError.protocolError("OPEN optional parameter header truncated")
            }
            guard var capabilities = parameters.readSlice(length: Int(length)) else {
                throw BGPLSClientError.protocolError("OPEN optional parameter value truncated")
            }
            guard type == 2 else {
                throw BGPLSClientError.protocolError("unsupported OPEN optional parameter \(type)")
            }
            guard capabilities.readableBytes > 0 else {
                throw BGPLSClientError.protocolError("OPEN capabilities parameter is empty")
            }
            while capabilities.readableBytes > 0 {
                guard let code: UInt8 = capabilities.readInteger(),
                    let capabilityLength: UInt8 = capabilities.readInteger()
                else {
                    throw BGPLSClientError.protocolError("OPEN capability header truncated")
                }
                guard var value = capabilities.readSlice(length: Int(capabilityLength)) else {
                    throw BGPLSClientError.protocolError("OPEN capability value truncated")
                }
                switch code {
                case BGPCapabilityCode.multiprotocol:
                    guard capabilityLength == 4,
                        let afi: UInt16 = value.readInteger(),
                        // Consume the RFC 4760 §8 reserved octet. Senders should use zero;
                        // receivers ignore its value, including nonzero values.
                        value.readInteger(as: UInt8.self) != nil,
                        let safi: UInt8 = value.readInteger()
                    else {
                        throw BGPLSClientError.protocolError("multiprotocol capability length must be 4")
                    }
                    // Multiple families accumulate. Continue framing all capabilities
                    // even after finding the required pair.
                    result.supportsBGPLS = result.supportsBGPLS || (afi == bgpLSAFI && safi == bgpLSSAFI)
                case BGPCapabilityCode.fourOctetAS:
                    guard capabilityLength == 4, let raw: UInt32 = value.readInteger() else {
                        throw BGPLSClientError.protocolError("four-octet AS capability length must be 4")
                    }
                    let asn = AutonomousSystemNumber(raw)
                    //  RFC 5492 permits identical repeats and split parameter blocks.
                    // Conflicting AS4 identities are ambiguous, so never select one by wire order.
                    if let previous = result.fourOctetAS, previous != asn {
                        throw BGPLSClientError.protocolError("conflicting four-octet AS capabilities")
                    }
                    result.fourOctetAS = asn
                default:
                    break
                }
            }
        }
        return result
    }
}

// MARK: - Codec

public enum BGPMessageCodec {
    // Export fixed framing sizes; keep the supported limit and shared marker storage intact.
    @export(implementation)
    public static var markerByteCount: Int { 16 }
    @export(implementation)
    public static var headerByteCount: Int { 19 }  // marker + length + type
    public static let maximumMessageLength = 4_096

    public static let marker = Array(repeating: UInt8(0xff), count: markerByteCount)

    /// Encodes a full BGP message into `buffer`.
    public static func encode(_ message: BGPMessage, into buffer: inout ByteBuffer) throws {
        var body = ByteBuffer()
        let type: BGPMessageType

        switch message {
        case .open(let open):
            type = .open
            body.writeInteger(open.version)
            body.writeInteger(open.myAS)
            body.writeInteger(open.holdTime)
            body.writeInteger(open.bgpIdentifier)
            guard open.optionalParameters.count <= 255 else {
                throw BGPLSClientError.protocolError("OPEN optional parameters too long")
            }
            body.writeInteger(UInt8(open.optionalParameters.count))
            body.writeBytes(open.optionalParameters)

        case .update(var updateBody):
            type = .update
            body.writeBuffer(&updateBody)

        case .notification(let note):
            type = .notification
            body.writeInteger(note.errorCode)
            body.writeInteger(note.errorSubcode)
            body.writeBytes(note.data)

        case .keepalive:
            type = .keepalive
        }

        let length = headerByteCount + body.readableBytes
        guard length <= maximumMessageLength else {
            throw BGPLSClientError.protocolError("BGP message length \(length) exceeds maximum")
        }

        buffer.writeBytes(marker)
        buffer.writeInteger(UInt16(length))
        buffer.writeInteger(type.rawValue)
        buffer.writeBuffer(&body)
    }

    /// Decodes one BGP message body (after header validation).
    public static func decodeBody(type: BGPMessageType, body: ByteBuffer) throws -> BGPMessage {
        var body = body
        switch type {
        case .open:
            guard let version: UInt8 = body.readInteger(),
                let myAS: UInt16 = body.readInteger(),
                let holdTime: UInt16 = body.readInteger(),
                let bgpIdentifier: UInt32 = body.readInteger(),
                let optLen: UInt8 = body.readInteger()
            else {
                throw BGPLSClientError.protocolError("OPEN body truncated")
            }
            guard body.readableBytes >= Int(optLen) else {
                throw BGPLSClientError.protocolError("OPEN optional parameters truncated")
            }
            guard body.readableBytes == Int(optLen) else {
                throw BGPLSClientError.protocolError("OPEN has trailing bytes after optional parameters")
            }
            let opts = body.readBytes(length: Int(optLen)) ?? []
            return .open(
                BGPOpenMessage(
                    version: version,
                    myAS: myAS,
                    holdTime: holdTime,
                    bgpIdentifier: bgpIdentifier,
                    optionalParameters: opts
                )
            )

        case .update:
            return .update(body)

        case .notification:
            guard let code: UInt8 = body.readInteger(),
                let sub: UInt8 = body.readInteger()
            else {
                throw BGPLSClientError.protocolError("NOTIFICATION body truncated")
            }
            let data = body.readBytes(length: body.readableBytes) ?? []
            return .notification(BGPNotificationMessage(errorCode: code, errorSubcode: sub, data: data))

        case .keepalive:
            guard body.readableBytes == 0 else {
                throw BGPLSClientError.protocolError("KEEPALIVE must have empty body")
            }
            return .keepalive
        }
    }
}
