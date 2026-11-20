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
import NIOEmbedded
import Testing

struct BGPMessageCodecTests {
    @Test
    func keepaliveRoundTrip() throws {
        var buffer = ByteBuffer()
        try BGPMessageCodec.encode(.keepalive, into: &buffer)
        #expect(buffer.readableBytes == 19)
        #expect(buffer.getBytes(at: 0, length: 16) == BGPMessageCodec.marker)

        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        try channel.writeInbound(buffer)
        let message: BGPMessage? = try channel.readInbound()
        guard case .keepalive = message else {
            Issue.record("expected keepalive, got \(String(describing: message))")
            return
        }
        try #require(channel.finish().isClean)
    }

    @Test
    func openRoundTripWithBGPLSCapability() throws {
        let open = BGPOpenMessage(
            version: 4,
            myAS: 65001,
            holdTime: 90,
            bgpIdentifier: 0xC000_0201,  // 192.0.2.1
            optionalParameters: BGPOpenCapabilities.multiprotocolBGPLS()
        )
        var buffer = ByteBuffer()
        try BGPMessageCodec.encode(.open(open), into: &buffer)

        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        try channel.writeInbound(buffer)
        let message: BGPMessage? = try channel.readInbound()
        guard case .open(let decoded) = message else {
            Issue.record("expected open, got \(String(describing: message))")
            return
        }
        #expect(decoded.version == 4)
        #expect(decoded.myAS == 65001)
        #expect(decoded.holdTime == 90)
        #expect(decoded.bgpIdentifier == 0xC000_0201)
        #expect(decoded.optionalParameters == BGPOpenCapabilities.multiprotocolBGPLS())
        try #require(channel.finish().isClean)
    }

    @Test(arguments: [
        (UInt32(65_535), UInt16(65_535), [UInt8(0), 0, 255, 255]),
        (UInt32(65_536), UInt16(23_456), [UInt8(0), 1, 0, 0]),
        (UInt32(4_200_000_001), UInt16(23_456), [UInt8(250), 86, 234, 1]),
        (UInt32.max, UInt16(23_456), [UInt8(255), 255, 255, 255]),
    ])
    func openRoundTripWithFourOctetAS(fixture: (UInt32, UInt16, [UInt8])) throws {
        let (asn, legacy, octets) = fixture
        let parameters = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(asn))
        #expect(parameters == [2, 12, 1, 4, 0x40, 0x04, 0, 71, 65, 4] + octets)
        let open = BGPOpenMessage(
            myAS: legacy, holdTime: 90, bgpIdentifier: 0xC000_02FE, optionalParameters: parameters
        )
        var buffer = ByteBuffer()
        try BGPMessageCodec.encode(.open(open), into: &buffer)
        #expect(buffer.getInteger(at: 20, as: UInt16.self) == legacy)
        #expect(buffer.getInteger(at: 28, as: UInt8.self) == 14)
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        defer { _ = try? channel.finish() }
        try channel.writeInbound(buffer)
        guard case .open(let decoded) = try channel.readInbound(as: BGPMessage.self) else {
            Issue.record("expected OPEN")
            return
        }
        #expect(decoded == open)
    }

    @Test(arguments: [UInt8(0), UInt8(1), UInt8(3)], [0, 3])
    func openRejectsIncorrectDeclaredOptionalParameterLength(declaredLength: UInt8, readerOffset: Int) {
        let body = Self.bodyBuffer(
            [4, 0xFD, 0xE9, 0, 90, 192, 0, 2, 1, declaredLength, 2, 0], readerOffset: readerOffset)
        let original = body
        let error = BGPLSClientError.protocolError(
            declaredLength > 2
                ? "OPEN optional parameters truncated"
                : "OPEN has trailing bytes after optional parameters")
        #expect(throws: error) {
            try BGPMessageCodec.decodeBody(type: .open, body: body)
        }
        Self.expectUnchanged(body, original: original)
    }

    @Test(arguments: 0..<10, [0, 3])
    func truncatedOpenFixedFieldsPreserveErrorAndInput(length: Int, readerOffset: Int) {
        let complete: [UInt8] = [4, 0xfd, 0xe9, 0, 90, 192, 0, 2, 1, 0]
        let body = Self.bodyBuffer(Array(complete.prefix(length)), readerOffset: readerOffset)
        let original = body

        #expect(throws: BGPLSClientError.protocolError("OPEN body truncated")) {
            try BGPMessageCodec.decodeBody(type: .open, body: body)
        }

        Self.expectUnchanged(body, original: original)
    }

    @Test(arguments: 0..<2, [0, 3])
    func truncatedNotificationFixedFieldsPreserveErrorAndInput(length: Int, readerOffset: Int) {
        let body = Self.bodyBuffer(Array([UInt8(6), 2].prefix(length)), readerOffset: readerOffset)
        let original = body

        #expect(throws: BGPLSClientError.protocolError("NOTIFICATION body truncated")) {
            try BGPMessageCodec.decodeBody(type: .notification, body: body)
        }

        Self.expectUnchanged(body, original: original)
    }

    @Test(arguments: [0, 14, 255], [0, 3])
    func openBodyPreservesFieldsOptionalBytesAndInput(optionalLength: Int, readerOffset: Int) throws {
        // Body decoding retains the optional bytes; capability interpretation happens later.
        let optionalBytes = (0..<optionalLength).map { UInt8($0) }
        let body = Self.bodyBuffer(
            [4, 0xfd, 0xe9, 0, 90, 192, 0, 2, 1, UInt8(optionalLength)] + optionalBytes,
            readerOffset: readerOffset
        )
        let original = body

        guard case .open(let decoded) = try BGPMessageCodec.decodeBody(type: .open, body: body) else {
            Issue.record("Expected an OPEN body")
            return
        }

        #expect(
            decoded
                == BGPOpenMessage(
                    version: 4, myAS: 65001, holdTime: 90, bgpIdentifier: 0xc000_0201,
                    optionalParameters: optionalBytes
                ))
        Self.expectUnchanged(body, original: original)
    }

    @Test(arguments: [[UInt8](), [0, 0xff, 0x80, 1]], [0, 3])
    func notificationBodyPreservesDataAndInput(data: [UInt8], readerOffset: Int) throws {
        let body = Self.bodyBuffer([6, 2] + data, readerOffset: readerOffset)
        let original = body

        guard case .notification(let decoded) = try BGPMessageCodec.decodeBody(type: .notification, body: body) else {
            Issue.record("Expected a NOTIFICATION body")
            return
        }

        #expect(decoded == BGPNotificationMessage(errorCode: 6, errorSubcode: 2, data: data))
        Self.expectUnchanged(body, original: original)
    }

    @Test(arguments: [BGPMessageType.open, .notification])
    func decoderWaitsForCompleteFragmentedOpenAndNotification(type: BGPMessageType) throws {
        let open = BGPOpenMessage(
            myAS: 65001, holdTime: 90, bgpIdentifier: 0xc000_0201,
            optionalParameters: BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(65001))
        )
        let note = BGPNotificationMessage(errorCode: 2, errorSubcode: 7, data: [1, 4, 0x40, 4, 0, 71])
        var wire = ByteBuffer()
        try BGPMessageCodec.encode(type == .open ? .open(open) : .notification(note), into: &wire)
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        defer { _ = try? channel.finish() }

        // Every boundary, including the fixed body fields, must wait for the enclosing frame.
        while wire.readableBytes > 1 {
            let fragment = wire.readSlice(length: 1)
            try channel.writeInbound(try #require(fragment))
            #expect(try channel.readInbound(as: BGPMessage.self) == nil)
        }
        try channel.writeInbound(wire)
        let received = try channel.readInbound(as: BGPMessage.self)
        let decoded = try #require(received)
        switch decoded {
        case .open(let actual):
            #expect(type == .open)
            #expect(actual == open)
        case .notification(let actual):
            #expect(type == .notification)
            #expect(actual == note)
        default:
            Issue.record("Expected OPEN or NOTIFICATION after the final fragment")
        }
        #expect(try channel.readInbound(as: BGPMessage.self) == nil)
        try #require(channel.finish().isClean)
    }

    @Test
    func notificationRoundTrip() throws {
        let note = BGPNotificationMessage(errorCode: 6, errorSubcode: 2, data: [0x01])
        var buffer = ByteBuffer()
        try BGPMessageCodec.encode(.notification(note), into: &buffer)

        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        try channel.writeInbound(buffer)
        let message: BGPMessage? = try channel.readInbound()
        guard case .notification(let decoded) = message else {
            Issue.record("expected notification")
            return
        }
        #expect(decoded.errorCode == 6)
        #expect(decoded.errorSubcode == 2)
        #expect(decoded.data == [0x01])
        try #require(channel.finish().isClean)
    }

    @Test
    func malformedAttributeListNotificationHasExactWireEncoding() throws {
        let note = BGPNotificationMessage(errorCode: 3, errorSubcode: 1)
        var buffer = ByteBuffer()
        try BGPMessageCodec.encode(.notification(note), into: &buffer)
        #expect(Array(buffer.readableBytesView) == Array(repeating: UInt8(0xff), count: 16) + [0, 21, 3, 3, 1])

        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        try channel.writeInbound(buffer)
        guard case .notification(let decoded) = try channel.readInbound(as: BGPMessage.self) else {
            Issue.record("expected Malformed Attribute List NOTIFICATION")
            return
        }
        #expect(decoded == note)
        try #require(channel.finish().isClean)
    }

    @Test
    func missingBGPLSCapabilityNotificationHasExactWireEncoding() throws {
        let note = BGPNotificationMessage(errorCode: 2, errorSubcode: 7, data: [1, 4, 0x40, 4, 0, 71])
        var buffer = ByteBuffer()
        try BGPMessageCodec.encode(.notification(note), into: &buffer)
        let expected = Array(repeating: UInt8(0xff), count: 16) + [0, 27, 3, 2, 7, 1, 4, 0x40, 4, 0, 71]
        #expect(Array(buffer.readableBytesView) == expected)

        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        try channel.writeInbound(buffer)
        guard case .notification(let decoded) = try channel.readInbound(as: BGPMessage.self) else {
            Issue.record("expected Unsupported Capability NOTIFICATION")
            return
        }
        #expect(decoded == note)
        try #require(channel.finish().isClean)
    }

    @Test(arguments: [UInt8(4), 2])
    func holdTimeNotificationsHaveExactWireEncoding(errorCode: UInt8) throws {
        let note = BGPNotificationMessage(errorCode: errorCode, errorSubcode: errorCode == 4 ? 0 : 6)
        var buffer = ByteBuffer()
        try BGPMessageCodec.encode(.notification(note), into: &buffer)
        let suffix: [UInt8] = errorCode == 4 ? [0, 21, 3, 4, 0] : [0, 21, 3, 2, 6]
        #expect(Array(buffer.readableBytesView) == Array(repeating: UInt8(0xff), count: 16) + suffix)

        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        try channel.writeInbound(buffer)
        guard case .notification(let decoded) = try channel.readInbound(as: BGPMessage.self) else {
            Issue.record("expected hold-time NOTIFICATION")
            return
        }
        #expect(decoded == note)
        #expect(decoded.data.isEmpty)
        try #require(channel.finish().isClean)
    }

    @Test
    func decoderNeedsMoreDataForPartialHeader() throws {
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(BGPMessageDecoder()))
        var partial = ByteBuffer()
        partial.writeBytes([0xff, 0xff, 0xff])
        try channel.writeInbound(partial)
        let message: BGPMessage? = try channel.readInbound()
        #expect(message == nil)
        _ = try? channel.finish()
    }

    private static func bodyBuffer(_ bytes: [UInt8], readerOffset: Int) -> ByteBuffer {
        var buffer = ByteBuffer(bytes: Array(repeating: 0xa5, count: readerOffset) + bytes)
        buffer.moveReaderIndex(forwardBy: readerOffset)
        return buffer
    }

    private static func expectUnchanged(_ body: ByteBuffer, original: ByteBuffer) {
        #expect(body == original)
        #expect(body.readerIndex == original.readerIndex)
        #expect(body.writerIndex == original.writerIndex)
        var allBody = body
        var allOriginal = original
        allBody.moveReaderIndex(to: 0)
        allOriginal.moveReaderIndex(to: 0)
        #expect(allBody == allOriginal)
    }
}
