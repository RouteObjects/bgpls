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

/// Frames BGP messages from a TCP byte stream (RFC 4271 §4.1).
public final class BGPMessageDecoder: ByteToMessageDecoder, Sendable {
    public typealias InboundOut = BGPMessage

    public init() {}

    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard buffer.readableBytes >= BGPMessageCodec.headerByteCount else {
            return .needMoreData
        }

        let headerStart = buffer.readerIndex
        // Marker
        guard let marker = buffer.getBytes(at: headerStart, length: BGPMessageCodec.markerByteCount),
            marker.allSatisfy({ $0 == 0xff })
        else {
            throw BGPLSClientError.protocolError("invalid BGP marker")
        }

        guard let length: UInt16 = buffer.getInteger(at: headerStart + BGPMessageCodec.markerByteCount)
        else {
            return .needMoreData
        }

        let totalLength = Int(length)
        guard totalLength >= BGPMessageCodec.headerByteCount,
            totalLength <= BGPMessageCodec.maximumMessageLength
        else {
            throw BGPLSClientError.protocolError("invalid BGP message length \(totalLength)")
        }

        guard buffer.readableBytes >= totalLength else {
            return .needMoreData
        }

        buffer.moveReaderIndex(forwardBy: BGPMessageCodec.markerByteCount)
        _ = buffer.readInteger(as: UInt16.self)  // length already validated
        guard let typeRaw: UInt8 = buffer.readInteger(),
            let type = BGPMessageType(rawValue: typeRaw)
        else {
            throw BGPLSClientError.protocolError("unknown or missing BGP message type")
        }

        let bodyLength = totalLength - BGPMessageCodec.headerByteCount
        guard let bodySlice = buffer.readSlice(length: bodyLength) else {
            throw BGPLSClientError.protocolError("truncated BGP message body")
        }

        let message = try BGPMessageCodec.decodeBody(type: type, body: bodySlice)
        context.fireChannelRead(Self.wrapInboundOut(message))
        return .continue
    }

    public func decodeLast(
        context: ChannelHandlerContext,
        buffer: inout ByteBuffer,
        seenEOF: Bool
    ) throws -> DecodingState {
        while true {
            switch try decode(context: context, buffer: &buffer) {
            case .needMoreData:
                if buffer.readableBytes > 0 && seenEOF {
                    throw BGPLSClientError.protocolError("incomplete BGP message at EOF")
                }
                return .needMoreData
            case .continue:
                continue
            }
        }
    }
}
