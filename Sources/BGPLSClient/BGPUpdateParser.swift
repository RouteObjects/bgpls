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

import NIOCore

/// Parses BGP UPDATE bodies (RFC 4271) including MP_REACH / MP_UNREACH.
public enum BGPUpdateParser {
    public static func parse(_ body: ByteBuffer) throws -> BGPUpdateMessage {
        var buffer = body

        guard let withdrawnLength: UInt16 = buffer.readInteger() else {
            throw BGPLSClientError.protocolError("UPDATE missing withdrawn length")
        }
        guard buffer.readableBytes >= Int(withdrawnLength) else {
            throw BGPLSClientError.protocolError("UPDATE truncated withdrawn routes")
        }
        let withdrawn = buffer.readSlice(length: Int(withdrawnLength)) ?? ByteBuffer()

        guard let attributeLength: UInt16 = buffer.readInteger() else {
            throw BGPLSClientError.protocolError("UPDATE missing path attribute length")
        }
        guard buffer.readableBytes >= Int(attributeLength) else {
            throw BGPLSClientError.protocolError("UPDATE truncated path attributes")
        }
        var attributeSlice = buffer.readSlice(length: Int(attributeLength)) ?? ByteBuffer()
        let attributes = try parsePathAttributes(&attributeSlice)

        // RFC 7606 section 3(g) rejects repeated MP types regardless of
        // payload or family. Check the framed list before any MP value can fail decoding.
        var seenReach = false
        var seenUnreach = false
        for attribute in attributes {
            switch attribute.typeCode {
            case BGPPathAttributeType.mpReachNLRI:
                guard !seenReach else {
                    throw BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: attribute.typeCode)
                }
                seenReach = true
            case BGPPathAttributeType.mpUnreachNLRI:
                guard !seenUnreach else {
                    throw BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: attribute.typeCode)
                }
                seenUnreach = true
            default:
                break
            }
        }

        let nlri = buffer  // remainder — classic IPv4 NLRI

        var mpReach: BGPMPReach?
        var mpUnreach: BGPMPUnreach?
        for attribute in attributes {
            switch attribute.typeCode {
            case BGPPathAttributeType.mpReachNLRI:
                var value = attribute.value
                mpReach = try parseMPReach(&value)
            case BGPPathAttributeType.mpUnreachNLRI:
                var value = attribute.value
                mpUnreach = try parseMPUnreach(&value)
            default:
                break
            }
        }

        return BGPUpdateMessage(
            withdrawnRoutes: withdrawn,
            pathAttributes: attributes,
            nlri: nlri,
            mpReach: mpReach,
            mpUnreach: mpUnreach
        )
    }

    public static func parsePathAttributes(_ buffer: inout ByteBuffer) throws -> [BGPPathAttribute] {
        var attributes: [BGPPathAttribute] = []
        while buffer.readableBytes > 0 {
            guard let flags: UInt8 = buffer.readInteger(),
                let typeCode: UInt8 = buffer.readInteger()
            else {
                throw BGPLSClientError.protocolError("path attribute header truncated")
            }
            let length: Int
            if flags & 0x10 != 0 {
                guard let ext: UInt16 = buffer.readInteger() else {
                    throw BGPLSClientError.protocolError("extended path attribute length truncated")
                }
                length = Int(ext)
            } else {
                guard let short: UInt8 = buffer.readInteger() else {
                    throw BGPLSClientError.protocolError("path attribute length truncated")
                }
                length = Int(short)
            }
            guard buffer.readableBytes >= length else {
                throw BGPLSClientError.protocolError("path attribute value truncated (type \(typeCode))")
            }
            let value = buffer.readSlice(length: length) ?? ByteBuffer()
            attributes.append(BGPPathAttribute(flags: flags, typeCode: typeCode, value: value))
        }
        return attributes
    }

    public static func parseMPReach(_ buffer: inout ByteBuffer) throws -> BGPMPReach {
        guard let afi: UInt16 = buffer.readInteger(),
            let safi: UInt8 = buffer.readInteger(),
            let nextHopLength: UInt8 = buffer.readInteger()
        else {
            throw BGPLSClientError.protocolError("MP_REACH header truncated")
        }
        guard buffer.readableBytes >= Int(nextHopLength) + 1 else {
            throw BGPLSClientError.protocolError("MP_REACH next-hop/reserved truncated")
        }
        let nextHop = buffer.readSlice(length: Int(nextHopLength)) ?? ByteBuffer()
        _ = buffer.readInteger(as: UInt8.self)  // reserved
        let nlri = buffer
        return BGPMPReach(afi: afi, safi: safi, nextHop: nextHop, nlri: nlri)
    }

    public static func parseMPUnreach(_ buffer: inout ByteBuffer) throws -> BGPMPUnreach {
        guard let afi: UInt16 = buffer.readInteger(),
            let safi: UInt8 = buffer.readInteger()
        else {
            throw BGPLSClientError.protocolError("MP_UNREACH header truncated")
        }
        let withdrawn = buffer
        return BGPMPUnreach(afi: afi, safi: safi, withdrawnNLRI: withdrawn)
    }
}
