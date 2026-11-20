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
import NIOEmbedded
import Testing

@testable import BGPLSClient

struct BGPSessionHandlerTests {
    @Test(arguments: [
        [UInt8](),
        [2, 6, 65, 4, 0, 0, 253, 233],
        [2, 2, 200, 0],
        [2, 6, 1, 4, 0, 1, 0, 1],
        [2, 6, 1, 4, 0, 2, 0, 71],
        [2, 6, 1, 4, 0x40, 4, 0, 1],
        [2, 6, 1, 4, 0x40, 4, 0, 72],
    ])
    func missingBGPLSIsRejectedBeforeOpenAcceptance(parameters: [UInt8]) throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peerOpen = HandlerSession.peerOpen
        peerOpen.optionalParameters = parameters

        try session.channel.writeInbound(BGPMessage.open(peerOpen))

        #expect(!session.channel.isActive)
        #expect(session.states.value == [.openSent, .stopped])
        #expect(session.completionCount.value == 1)
        #expect(throws: BGPLSClientError.missingBGPLSCapability) {
            try #require(session.result.value).get()
        }
        guard case .notification(let notification) = try session.channel.readOutbound(as: BGPMessage.self) else {
            Issue.record("missing BGP-LS must produce its Unsupported Capability notification")
            return
        }
        #expect(notification == Self.missingBGPLSNotification)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
        session.channel.pipeline.fireChannelRead(BGPMessage.keepalive)
        session.channel.pipeline.fireChannelRead(BGPMessage.update(ByteBuffer(bytes: [0])))
        #expect(session.observations.value.isEmpty)
        #expect(session.states.value == [.openSent, .stopped])
    }

    @Test(arguments: [UInt32(65_001), 4_200_000_001], [false, true])
    func mixedCapabilityFamiliesStillEstablishBGPLS(asn: UInt32, split: Bool) throws {
        let required: [UInt8] = [1, 4, 0x40, 4, 255, 71]
        let unrelated: [UInt8] = [1, 4, 0, 1, 0, 1]
        let unknown: [UInt8] = [200, 0]
        let as4: [UInt8] = [
            65, 4, UInt8((asn >> 24) & 0xff), UInt8((asn >> 16) & 0xff),
            UInt8((asn >> 8) & 0xff), UInt8(asn & 0xff),
        ]
        for capabilities in [
            [required, required, unrelated, unknown, as4],
            [as4, unknown, unrelated, required, required],
        ] {
            let session = try HandlerSession(localAS: asn, peerAS: asn)
            defer { _ = try? session.channel.finish() }
            var peerOpen = HandlerSession.peerOpen
            peerOpen.myAS = BGPOpenCapabilities.legacyAS(for: AutonomousSystemNumber(asn))
            if split {
                peerOpen.optionalParameters = capabilities.flatMap { [2, UInt8($0.count)] + $0 }
            } else {
                let bytes = capabilities.flatMap { $0 }
                peerOpen.optionalParameters = [2, UInt8(bytes.count)] + bytes
            }

            try session.establish(peerOpen: peerOpen)

            #expect(session.states.value == [.openSent, .openConfirm, .established])
            #expect(session.result.value == nil)
            #expect(session.channel.isActive)
            #expect(session.observations.value.isEmpty)
        }
    }

    @Test(arguments: OpenFailureBeforeMissingCapability.allCases)
    func existingOpenErrorsTakePrecedenceOverMissingBGPLS(failure: OpenFailureBeforeMissingCapability) throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peerOpen = HandlerSession.peerOpen
        peerOpen.optionalParameters = []
        let expected: BGPLSClientError
        switch failure {
        case .version:
            peerOpen.version = 3
            expected = .protocolError("unsupported BGP version 3")
        case .malformedParameter:
            peerOpen.optionalParameters = [2, 6, 1]
            expected = .protocolError("OPEN optional parameter value truncated")
        case .zeroAS:
            peerOpen.myAS = 0
            expected = .protocolError("peer AS must be non-zero")
        case .wrongAS:
            peerOpen.myAS = 65002
            expected = .sessionFailed("peer AS 65002 does not match expected 65001")
        case .zeroIdentifier:
            peerOpen.bgpIdentifier = 0
            expected = .protocolError("peer BGP identifier must be non-zero")
        case .sameIdentifier:
            peerOpen.bgpIdentifier = 0xC000_0225
            expected = .protocolError("peer BGP identifier matches local identifier in iBGP")
        case .holdTime:
            peerOpen.holdTime = 1
            expected = .unacceptableHoldTime(seconds: 1)
        }

        try session.channel.writeInbound(BGPMessage.open(peerOpen))

        #expect(throws: expected) { try #require(session.result.value).get() }
        #expect(session.states.value == [.openSent, .stopped])
        #expect(!session.channel.isActive)
        if failure == .holdTime {
            guard case .notification(let notification) = try session.channel.readOutbound(as: BGPMessage.self) else {
                Issue.record("unacceptable Hold Time must produce its OPEN error notification")
                return
            }
            #expect(notification == BGPNotificationMessage(errorCode: 2, errorSubcode: 6))
        }
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: HeldNotificationEnd.allCases)
    func missingBGPLSNotificationWaitsForWriteAndPreservesFailure(end: HeldNotificationEnd) throws {
        let gate = NotificationWriteGate()
        let session = try HandlerSession(notificationGate: gate, holdTime: 3)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peerOpen = HandlerSession.peerOpen
        peerOpen.optionalParameters = []
        peerOpen.holdTime = 3

        try session.channel.writeInbound(BGPMessage.open(peerOpen))

        #expect(session.result.value == nil)
        #expect(session.completionCount.value == 0)
        #expect(session.channel.isActive)
        #expect(gate.isPending)
        #expect(gate.notifications == [Self.missingBGPLSNotification])
        #expect(session.states.value == [.openSent, .stopped])
        // No buffered input may turn the rejected OPEN into an established session.
        session.channel.pipeline.fireChannelRead(BGPMessage.open(HandlerSession.peerOpen))
        session.channel.pipeline.fireChannelRead(BGPMessage.keepalive)
        session.channel.pipeline.fireChannelRead(BGPMessage.update(ByteBuffer(bytes: [0])))
        session.channel.pipeline.fireErrorCaught(OutcomeTestError.later)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(999))
        #expect(session.channel.isActive)
        #expect(session.result.value == nil)
        #expect(session.observations.value.isEmpty)
        #expect(gate.notifications.count == 1)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)

        switch end {
        case .writeSuccess: gate.resolve(.success(()))
        case .writeFailure: gate.resolve(.failure(OutcomeTestError.transport))
        case .peerClosure: try session.channel.close().wait()
        case .deadline: session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(1))
        }

        #expect(!session.channel.isActive)
        #expect(!gate.isPending)
        #expect(session.completionCount.value == 1)
        #expect(throws: BGPLSClientError.missingBGPLSCapability) {
            try #require(session.result.value).get()
        }
        session.channel.pipeline.fireChannelInactive()
        session.channel.pipeline.fireErrorCaught(OutcomeTestError.later)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(30))
        #expect(session.completionCount.value == 1)
        #expect(gate.notifications.count == 1)
        #expect(session.states.value == [.openSent, .stopped])
        #expect(session.observations.value.isEmpty)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: ImmediateNotificationEnd.allCases)
    func missingBGPLSNotificationHandlesReentrantWriteAndOutcomeCallbacks(end: ImmediateNotificationEnd) throws {
        let gate = NotificationWriteGate(immediate: end)
        let session = try HandlerSession(notificationGate: gate)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        let bound = NIOLoopBound(session.channel, eventLoop: session.channel.eventLoop)
        session.outcome.futureResult.whenComplete { _ in
            bound.value.pipeline.fireChannelInactive()
            bound.value.pipeline.fireErrorCaught(OutcomeTestError.later)
            bound.value.close(promise: nil)
        }
        var peerOpen = HandlerSession.peerOpen
        peerOpen.optionalParameters = []

        try session.channel.writeInbound(BGPMessage.open(peerOpen))

        #expect(!session.channel.isActive)
        #expect(!gate.isPending)
        #expect(gate.notifications == [Self.missingBGPLSNotification])
        #expect(session.completionCount.value == 1)
        #expect(session.observations.value.isEmpty)
        #expect(throws: BGPLSClientError.missingBGPLSCapability) {
            try #require(session.result.value).get()
        }
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        #expect(session.completionCount.value == 1)
        #expect(gate.notifications.count == 1)
        #expect(session.states.value == [.openSent, .stopped])
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test
    func missingBGPLSStateCallbackClosurePreventsStartingNotification() throws {
        let gate = NotificationWriteGate()
        let session = try HandlerSession(notificationGate: gate, closeWhenStopped: true)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peerOpen = HandlerSession.peerOpen
        peerOpen.optionalParameters = []

        try session.channel.writeInbound(BGPMessage.open(peerOpen))

        #expect(!session.channel.isActive)
        #expect(gate.notifications.isEmpty)
        #expect(!gate.isPending)
        #expect(session.completionCount.value == 1)
        #expect(session.observations.value.isEmpty)
        #expect(throws: BGPLSClientError.missingBGPLSCapability) {
            try #require(session.result.value).get()
        }
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        #expect(gate.notifications.isEmpty)
        #expect(session.completionCount.value == 1)
    }

    @Test
    func missingBGPLSLateWriteCannotCompleteOutcomeAgain() throws {
        let gate = NotificationWriteGate(resolveOnClose: false)
        let session = try HandlerSession(notificationGate: gate)
        defer {
            gate.resolve(.failure(OutcomeTestError.transport))
            _ = try? session.channel.finish()
        }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peerOpen = HandlerSession.peerOpen
        peerOpen.optionalParameters = []
        try session.channel.writeInbound(BGPMessage.open(peerOpen))

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))

        #expect(!session.channel.isActive)
        #expect(gate.isPending)
        #expect(session.completionCount.value == 1)
        gate.resolve(.success(()))
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        #expect(!gate.isPending)
        #expect(session.completionCount.value == 1)
        #expect(gate.notifications == [Self.missingBGPLSNotification])
        #expect(throws: BGPLSClientError.missingBGPLSCapability) {
            try #require(session.result.value).get()
        }
    }

    private static var missingBGPLSNotification: BGPNotificationMessage {
        BGPNotificationMessage(errorCode: 2, errorSubcode: 7, data: [1, 4, 0x40, 4, 0, 71])
    }

    @Test(arguments: [UInt32(65001), UInt32(65002)])
    func zeroPeerIdentifierFailsForBothASRelationships(localAS: UInt32) throws {
        let session = try HandlerSession(localAS: localAS)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peerOpen = HandlerSession.peerOpen
        peerOpen.bgpIdentifier = 0

        try session.channel.writeInbound(BGPMessage.open(peerOpen))

        #expect(throws: BGPLSClientError.protocolError("peer BGP identifier must be non-zero")) {
            try #require(session.result.value).get()
        }
        #expect(!session.channel.isActive)
        #expect(!session.states.value.contains(.openConfirm))
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: [UInt16(65001), UInt16(23_456)])
    func sameIBGPIdentifierFailsUsingConfiguredASRelationship(assertedPeerAS: UInt16) throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peerOpen = HandlerSession.peerOpen
        peerOpen.myAS = assertedPeerAS
        peerOpen.optionalParameters = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(65001))
        peerOpen.bgpIdentifier = 0xC000_0225

        try session.channel.writeInbound(BGPMessage.open(peerOpen))

        #expect(throws: BGPLSClientError.protocolError("peer BGP identifier matches local identifier in iBGP")) {
            try #require(session.result.value).get()
        }
        #expect(!session.channel.isActive)
        #expect(!session.states.value.contains(.openConfirm))
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test
    func sameIdentifierIsPermittedOnEBGP() throws {
        let session = try HandlerSession(localAS: 65002)
        defer { _ = try? session.channel.finish() }
        var peerOpen = HandlerSession.peerOpen
        peerOpen.bgpIdentifier = 0xC000_0225

        try session.channel.writeInbound(BGPMessage.open(peerOpen))
        try session.channel.writeInbound(BGPMessage.keepalive)

        #expect(session.states.value.last == .established)
        #expect(session.result.value == nil)
        #expect(session.channel.isActive)
    }

    @Test(arguments: [UInt32(65_001), 65_535, 65_536, 4_200_000_001, UInt32.max])
    func capabilityIdentityIsAuthoritativeOverLegacyField(peerAS: UInt32) throws {
        let session = try HandlerSession(peerAS: peerAS)
        defer { _ = try? session.channel.finish() }
        var peerOpen = HandlerSession.peerOpen
        peerOpen.myAS = 65002
        peerOpen.optionalParameters = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(peerAS))
        try session.establish(peerOpen: peerOpen)
        #expect(session.result.value == nil)
        #expect(session.states.value.last == .established)
        #expect(session.channel.isActive)
    }

    @Test(arguments: [UInt32(65_001), 4_200_000_001])
    func legacyPeerRemainsSupportedWithoutAS4Capability(localAS: UInt32) throws {
        let session = try HandlerSession(localAS: localAS)
        defer { _ = try? session.channel.finish() }
        try session.establish()
        #expect(session.result.value == nil)
        #expect(session.states.value.last == .established)
    }

    @Test(arguments: [UInt32(65_001), 4_200_000_001])
    func nakedASTransCannotBypassExpectedPeerIdentity(expected: UInt32) throws {
        let session = try HandlerSession(peerAS: expected)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peerOpen = HandlerSession.peerOpen
        peerOpen.myAS = 23_456
        try session.channel.writeInbound(BGPMessage.open(peerOpen))
        #expect(throws: BGPLSClientError.sessionFailed("peer AS 23456 does not match expected \(expected)")) {
            try #require(session.result.value).get()
        }
        #expect(!session.channel.isActive)
        #expect(!session.states.value.contains(.openConfirm))
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test
    func wrongCapabilityFailsDespiteMatchingLegacyField() throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        var peerOpen = HandlerSession.peerOpen
        peerOpen.optionalParameters = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(4_200_000_001))
        try session.channel.writeInbound(BGPMessage.open(peerOpen))
        #expect(throws: BGPLSClientError.sessionFailed("peer AS 4200000001 does not match expected 65001")) {
            try #require(session.result.value).get()
        }
        #expect(!session.channel.isActive)
        #expect(!session.states.value.contains(.openConfirm))
    }

    @Test(arguments: [false, true])
    func effectivePeerASZeroIsRejected(withCapability: Bool) throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        var peerOpen = HandlerSession.peerOpen
        if withCapability {
            peerOpen.optionalParameters = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(0))
        } else {
            peerOpen.myAS = 0
        }
        try session.channel.writeInbound(BGPMessage.open(peerOpen))
        #expect(throws: BGPLSClientError.protocolError("peer AS must be non-zero")) {
            try #require(session.result.value).get()
        }
        #expect(!session.channel.isActive)
        #expect(!session.states.value.contains(.openConfirm))
    }

    @Test(arguments: [false, true])
    func fourOctetASRelationshipDeterminesIdentifierUniqueness(sameAS: Bool) throws {
        let localAS: UInt32 = 4_200_000_001
        let peerAS: UInt32 = sameAS ? localAS : 4_200_000_002
        let session = try HandlerSession(localAS: localAS, peerAS: peerAS)
        defer { _ = try? session.channel.finish() }
        var peerOpen = HandlerSession.peerOpen
        peerOpen.myAS = 23_456
        peerOpen.optionalParameters = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(peerAS))
        peerOpen.bgpIdentifier = 0xC000_0225
        try session.channel.writeInbound(BGPMessage.open(peerOpen))
        if sameAS {
            #expect(throws: BGPLSClientError.protocolError("peer BGP identifier matches local identifier in iBGP")) {
                try #require(session.result.value).get()
            }
            #expect(!session.channel.isActive)
        } else {
            try session.channel.writeInbound(BGPMessage.keepalive)
            #expect(session.result.value == nil)
            #expect(session.states.value.last == .established)
        }
    }

    @Test
    func malformedAS4CapabilityFailsBeforeClosureAndRejectsSubsequentUpdates() throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peerOpen = HandlerSession.peerOpen
        peerOpen.optionalParameters = [2, 5, 65, 3, 0, 0, 1]
        try session.channel.writeInbound(BGPMessage.open(peerOpen))
        session.channel.pipeline.fireChannelInactive()
        session.channel.pipeline.fireChannelRead(BGPMessage.keepalive)
        session.channel.pipeline.fireChannelRead(
            BGPMessage.update(IPv6TopologyFixture.updateBody(reachable: false, nlris: []))
        )
        #expect(throws: BGPLSClientError.protocolError("four-octet AS capability length must be 4")) {
            try #require(session.result.value).get()
        }
        #expect(!session.channel.isActive)
        #expect(!session.states.value.contains(.openConfirm))
        #expect(session.observations.value.isEmpty)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: [false, true])
    func negotiatedAS4DoesNotInterpretOpaquePathAttributes(usesAS4: Bool) throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        var peerOpen = HandlerSession.peerOpen
        if usesAS4 {
            peerOpen.optionalParameters = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(65001))
        }
        try session.establish(peerOpen: peerOpen)
        let path: [UInt8] = usesAS4 ? [2, 1, 0, 0, 253, 233] : [2, 1, 253, 233]
        let aggregator: [UInt8] =
            usesAS4 ? [0, 0, 253, 233, 192, 0, 2, 1] : [253, 233, 192, 0, 2, 1]
        //  Explicit byte-array assembly keeps this fixture tractable for Swift 6.2.
        var attributes: [UInt8] = [0x40, 2, UInt8(path.count)]
        attributes.append(contentsOf: path)
        attributes.append(contentsOf: [0xC0, 7, UInt8(aggregator.count)])
        attributes.append(contentsOf: aggregator)
        attributes.append(contentsOf: [0xC0, 17, 6, 2, 1, 250, 86, 234, 1])
        attributes.append(contentsOf: [0xC0, 18, 8, 250, 86, 234, 1, 192, 0, 2, 1])
        var body = ByteBuffer()
        body.writeInteger(UInt16(0))
        body.writeInteger(UInt16(attributes.count))
        body.writeBytes(attributes)
        try session.channel.writeInbound(BGPMessage.update(body))
        let observation = try #require(session.observations.value.first)
        #expect(observation.rawBody == body)
        if case .failure(let error) = observation.preparation {
            Issue.record("opaque attributes unexpectedly failed preparation: \(error)")
        }
        let parsed = try BGPUpdateParser.parse(observation.rawBody)
        #expect(parsed.pathAttributes.map(\.typeCode) == [2, 7, 17, 18])
        #expect(parsed.pathAttributes[0].value == ByteBuffer(bytes: path))
        #expect(parsed.pathAttributes[1].value == ByteBuffer(bytes: aggregator))
        #expect(session.result.value == nil)
        #expect(session.channel.isActive)
    }

    @Test(arguments: [UInt32(1), 0xE000_0001, UInt32.max])
    func peerIdentifierIsNotRestrictedToIPv4Unicast(identifier: UInt32) throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        var peerOpen = HandlerSession.peerOpen
        peerOpen.bgpIdentifier = identifier

        try session.channel.writeInbound(BGPMessage.open(peerOpen))
        try session.channel.writeInbound(BGPMessage.keepalive)

        #expect(session.states.value.last == .established)
        #expect(session.result.value == nil)
    }

    @Test
    func openKeepaliveReachesEstablished() throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }

        try session.establish()

        #expect(session.states.value == [.openSent, .openConfirm, .established])
        //  readiness is state progress, not the outcome of the entire session.
        #expect(session.result.value == nil)
        #expect(session.channel.isActive)
    }

    @Test
    func normalEstablishedClosureSucceeds() throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        try session.establish()

        try session.channel.close().wait()

        try #require(session.result.value).get()
        #expect(session.states.value.last == .stopped)
        #expect(!session.channel.isActive)
    }

    @Test(arguments: [false, true])
    func closureBeforeEstablishmentFails(afterPeerOpen: Bool) throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        if afterPeerOpen {
            try session.channel.writeInbound(BGPMessage.open(HandlerSession.peerOpen))
        }

        try session.channel.close().wait()

        let expectedState = afterPeerOpen ? BGPSessionState.openConfirm : .openSent
        #expect(throws: BGPLSClientError.sessionFailed("channel closed in state \(expectedState)")) {
            try #require(session.result.value).get()
        }
        #expect(session.states.value.last == .stopped)
    }

    @Test
    func notificationAfterEstablishmentPreservesFailureAcrossClosure() throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        try session.establish()

        try session.channel.writeInbound(
            BGPMessage.notification(BGPNotificationMessage(errorCode: 6, errorSubcode: 2))
        )

        #expect(!session.channel.isActive)
        #expect(throws: BGPLSClientError.sessionFailed("NOTIFICATION code=6 subcode=2")) {
            try #require(session.result.value).get()
        }
        #expect(session.states.value.last == .stopped)
    }

    @Test
    func unexpectedOpenAfterEstablishmentPreservesFailureAcrossClosure() throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        try session.establish()

        try session.channel.writeInbound(BGPMessage.open(HandlerSession.peerOpen))

        #expect(!session.channel.isActive)
        #expect(throws: BGPLSClientError.protocolError("unexpected OPEN while Established")) {
            try #require(session.result.value).get()
        }
        #expect(session.states.value.last == .stopped)
    }

    @Test
    func transportErrorAfterEstablishmentPreservesFailureAcrossClosure() throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        try session.establish()

        session.channel.pipeline.fireErrorCaught(OutcomeTestError.transport)

        #expect(!session.channel.isActive)
        #expect(throws: OutcomeTestError.transport) {
            try #require(session.result.value).get()
        }
        #expect(session.states.value.last == .stopped)
    }

    @Test
    func recoverableUpdateKeepsSessionOpenAndPreparesLaterGoodUpdates() throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        try session.establish()
        let ipv4 = IPv6TopologyFixture.prefixWire([24, 192, 0, 2], type: 3)
        let bad = IPv6TopologyFixture.prefixWire([129])
        let ipv6 = IPv6TopologyFixture.prefixWire([0])
        let firstBody = IPv6TopologyFixture.updateBody(reachable: true, nlris: ipv4 + bad)
        let secondBody = IPv6TopologyFixture.updateBody(reachable: true, nlris: ipv6)

        try session.channel.writeInbound(BGPMessage.update(firstBody))
        try session.channel.writeInbound(BGPMessage.update(secondBody))

        #expect(session.channel.isActive)
        #expect(session.result.value == nil)
        #expect(session.observations.value.map(\.rawBody) == [firstBody, secondBody])
        var rib = LSRIB()
        let observations = session.observations.value
        #expect(observations.count == 2)
        let first = rib.commit(try #require(observations.first).preparation.get())
        #expect(first.diffs.count == 1)
        #expect(first.diagnostics.count == 1)
        let second = rib.commit(try #require(observations.last).preparation.get())
        #expect(second.diffs.count == 1)
        #expect(second.diagnostics.isEmpty)
        #expect(rib.prefixCount == 2)
    }

    @Test(arguments: [false, true])
    func fatalUpdateIsObservedBeforeOutcomeFailureAndCannotAdmitLaterWork(
        malformedOuterUpdate: Bool
    ) throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        try session.establish()
        let body =
            malformedOuterUpdate
            ? ByteBuffer(bytes: [0])
            : IPv6TopologyFixture.updateBody(reachable: true, nlris: [0, 4, 0, 100])

        try session.channel.writeInbound(BGPMessage.update(body))

        #expect(!session.channel.isActive)
        #expect(session.observations.value.map(\.rawBody) == [body])
        let observed = try #require(session.observations.value.first)
        #expect(throws: BGPLSClientError.self) { try observed.preparation.get() }
        guard case .failure(let original) = try #require(session.result.value) else {
            Issue.record("fatal framing must fail the outcome before closure")
            return
        }
        guard case .failure(let preparationError) = observed.preparation else {
            Issue.record("fatal observation must preserve its preparation failure")
            return
        }
        #expect(original as? BGPLSClientError == preparationError as? BGPLSClientError)
        //  Model already-buffered input after failure without depending on network timing.
        let later = IPv6TopologyFixture.updateBody(
            reachable: true, nlris: IPv6TopologyFixture.prefixWire([0])
        )
        session.channel.pipeline.fireChannelRead(BGPMessage.update(later))
        session.channel.pipeline.fireChannelInactive()
        #expect(session.observations.value.count == 1)
        guard case .failure(let final) = try #require(session.result.value) else {
            Issue.record("normal closure must not replace the framing failure")
            return
        }
        #expect(final as? BGPLSClientError == original as? BGPLSClientError)
    }

    @Test(arguments: [UInt8(14), 15], HeldNotificationEnd.allCases)
    func duplicateMPNotificationWaitsForWriteAndPreservesFailure(type: UInt8, end: HeldNotificationEnd) throws {
        let gate = NotificationWriteGate()
        let session = try HandlerSession(notificationGate: gate, holdTime: 3)
        defer { _ = try? session.channel.finish() }
        var peerOpen = HandlerSession.peerOpen
        peerOpen.holdTime = 3
        try session.establish(peerOpen: peerOpen)
        let attribute = DuplicateMPFixture.attribute(type: type, value: DuplicateMPFixture.value(type: type))
        let body = DuplicateMPFixture.body(attributes: [attribute, attribute])
        let original = BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: type)

        try session.channel.writeInbound(BGPMessage.update(body))

        #expect(session.result.value == nil)
        #expect(session.completionCount.value == 0)
        #expect(session.channel.isActive)
        #expect(gate.isPending)
        #expect(gate.notifications == [BGPNotificationMessage(errorCode: 3, errorSubcode: 1)])
        #expect(session.observations.value.map(\.rawBody) == [body])
        #expect(throws: original) { try #require(session.observations.value.first).preparation.get() }

        // Buffered messages and a later transport error must not restart termination or replace its cause.
        session.channel.pipeline.fireChannelRead(BGPMessage.update(body))
        session.channel.pipeline.fireChannelRead(BGPMessage.keepalive)
        session.channel.pipeline.fireChannelRead(BGPMessage.open(peerOpen))
        session.channel.pipeline.fireErrorCaught(OutcomeTestError.later)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(999))
        #expect(session.channel.isActive)
        #expect(session.result.value == nil)
        #expect(session.observations.value.count == 1)
        #expect(gate.notifications.count == 1)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)

        switch end {
        case .writeSuccess: gate.resolve(.success(()))
        case .writeFailure: gate.resolve(.failure(OutcomeTestError.transport))
        case .peerClosure: try session.channel.close().wait()
        case .deadline: session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(1))
        }

        #expect(!session.channel.isActive)
        #expect(!gate.isPending)
        #expect(session.completionCount.value == 1)
        #expect(throws: original) { try #require(session.result.value).get() }
        #expect(session.states.value.filter { $0 == .stopped }.count == 1)
        session.channel.pipeline.fireChannelInactive()
        session.channel.pipeline.fireErrorCaught(OutcomeTestError.later)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(30))
        #expect(session.completionCount.value == 1)
        #expect(gate.notifications.count == 1)
        #expect(session.observations.value.count == 1)
        #expect(throws: original) { try #require(session.result.value).get() }
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: [UInt8(14), 15], ImmediateNotificationEnd.allCases)
    func notificationWriteAndOutcomeCallbacksCanReenterInTheSameTurn(
        type: UInt8, end: ImmediateNotificationEnd
    ) throws {
        let gate = NotificationWriteGate(immediate: end)
        let session = try HandlerSession(notificationGate: gate)
        defer { _ = try? session.channel.finish() }
        try session.establish()
        let bound = NIOLoopBound(session.channel, eventLoop: session.channel.eventLoop)
        session.outcome.futureResult.whenComplete { _ in
            // Model cleanup waking immediately while the write callback still owns the stack.
            bound.value.pipeline.fireChannelInactive()
            bound.value.pipeline.fireErrorCaught(OutcomeTestError.later)
            bound.value.close(promise: nil)
        }
        let attribute = DuplicateMPFixture.attribute(type: type, value: DuplicateMPFixture.value(type: type))
        let body = DuplicateMPFixture.body(attributes: [attribute, attribute])

        try session.channel.writeInbound(BGPMessage.update(body))

        #expect(!session.channel.isActive)
        #expect(!gate.isPending)
        #expect(gate.notifications == [BGPNotificationMessage(errorCode: 3, errorSubcode: 1)])
        #expect(session.completionCount.value == 1)
        #expect(session.observations.value.map(\.rawBody) == [body])
        #expect(throws: BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: type)) {
            try #require(session.result.value).get()
        }
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        #expect(session.completionCount.value == 1)
        #expect(gate.notifications.count == 1)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: [UInt8(14), 15])
    func reentrantStateCallbackClosurePreventsStartingANotification(type: UInt8) throws {
        let gate = NotificationWriteGate()
        let session = try HandlerSession(notificationGate: gate, closeWhenStopped: true)
        defer { _ = try? session.channel.finish() }
        try session.establish()
        let attribute = DuplicateMPFixture.attribute(type: type, value: DuplicateMPFixture.value(type: type))
        let body = DuplicateMPFixture.body(attributes: [attribute, attribute])

        try session.channel.writeInbound(BGPMessage.update(body))

        #expect(!session.channel.isActive)
        #expect(gate.notifications.isEmpty)
        #expect(!gate.isPending)
        #expect(session.completionCount.value == 1)
        #expect(session.observations.value.map(\.rawBody) == [body])
        #expect(throws: BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: type)) {
            try #require(session.result.value).get()
        }
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        #expect(gate.notifications.isEmpty)
        #expect(session.completionCount.value == 1)
    }

    @Test(arguments: [UInt8(14), 15])
    func lateWriteSuccessAfterNotificationDeadlineCannotCompleteAgain(type: UInt8) throws {
        let gate = NotificationWriteGate(resolveOnClose: false)
        let session = try HandlerSession(notificationGate: gate)
        defer {
            gate.resolve(.failure(OutcomeTestError.transport))
            _ = try? session.channel.finish()
        }
        try session.establish()
        let attribute = DuplicateMPFixture.attribute(type: type, value: DuplicateMPFixture.value(type: type))
        try session.channel.writeInbound(
            BGPMessage.update(DuplicateMPFixture.body(attributes: [attribute, attribute])))

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))

        #expect(!session.channel.isActive)
        #expect(gate.isPending)
        #expect(session.completionCount.value == 1)
        gate.resolve(.success(()))
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        #expect(!gate.isPending)
        #expect(session.completionCount.value == 1)
        #expect(gate.notifications.count == 1)
        #expect(throws: BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: type)) {
            try #require(session.result.value).get()
        }
    }

    @Test(arguments: [
        BGPLSClientError.protocolError("unrelated UPDATE failure"),
        .duplicateMultiprotocolAttribute(typeCode: 99),
    ])
    func unrelatedErrorsDoNotAcquireNotificationMappings(error: BGPLSClientError) throws {
        let gate = NotificationWriteGate()
        let session = try HandlerSession(notificationGate: gate)
        defer { _ = try? session.channel.finish() }
        try session.establish()

        session.channel.pipeline.fireErrorCaught(error)

        #expect(!session.channel.isActive)
        #expect(gate.notifications.isEmpty)
        #expect(!gate.isPending)
        #expect(session.completionCount.value == 1)
        #expect(throws: error) { try #require(session.result.value).get() }
    }

    @Test
    func invalidInitialOpenFailsOutcome() throws {
        let session = try HandlerSession()
        defer { _ = try? session.channel.finish() }
        var peerOpen = HandlerSession.peerOpen
        peerOpen.myAS = 65002

        try session.channel.writeInbound(BGPMessage.open(peerOpen))

        #expect(!session.channel.isActive)
        #expect(throws: BGPLSClientError.sessionFailed("peer AS 65002 does not match expected 65001")) {
            try #require(session.result.value).get()
        }
    }

    @Test
    func outcomeFailureCannotBeReplacedByLaterCompletion() throws {
        let loop = EmbeddedEventLoop()
        let outcome = SessionOutcome(eventLoop: loop)
        let result = NIOLoopBoundBox<Result<Void, any Error>?>(nil, eventLoop: loop)
        outcome.futureResult.whenComplete { result.value = $0 }

        outcome.complete(.failure(OutcomeTestError.transport))
        outcome.complete(.success(()))
        outcome.complete(.failure(OutcomeTestError.later))

        #expect(throws: OutcomeTestError.transport) {
            try #require(result.value).get()
        }
    }

    @Test
    func outcomeSuccessCannotBeReplacedByLaterFailure() throws {
        let loop = EmbeddedEventLoop()
        let outcome = SessionOutcome(eventLoop: loop)
        let result = NIOLoopBoundBox<Result<Void, any Error>?>(nil, eventLoop: loop)
        outcome.futureResult.whenComplete { result.value = $0 }

        outcome.complete(.success(()))
        outcome.complete(.failure(OutcomeTestError.later))
        outcome.complete(.success(()))

        try #require(result.value).get()
    }

    @Test
    func outcomeCompletionIsSafeWhenCallbackCompletesItAgain() throws {
        let loop = EmbeddedEventLoop()
        let outcome = SessionOutcome(eventLoop: loop)
        let results = NIOLoopBoundBox<[Result<Void, any Error>]>([], eventLoop: loop)
        outcome.futureResult.whenComplete { result in
            results.value.append(result)
            //  completion callbacks may reenter the owner before complete returns.
            outcome.complete(.failure(OutcomeTestError.later))
        }

        outcome.complete(.success(()))

        #expect(results.value.count == 1)
        try #require(results.value.first).get()
    }

    @Test(.timeLimit(.minutes(1)))
    func outcomeCanBeCreatedAndCompletedOffItsEventLoop() async throws {
        let loop = NIOAsyncTestingEventLoop()
        #expect(!loop.inEventLoop)
        let outcome = SessionOutcome(eventLoop: loop)
        let result = NIOLoopBoundBox<Result<Void, any Error>?>.makeEmptyBox(eventLoop: loop)
        outcome.futureResult.whenComplete { result.value = $0 }

        outcome.complete(.failure(OutcomeTestError.transport))
        outcome.complete(.success(()))
        await loop.run()

        _ = try await loop.executeInContext {
            #expect(throws: OutcomeTestError.transport) {
                try #require(result.value).get()
            }
        }
        await loop.run()
    }
}

extension BGPSessionHandlerTests {
    @Test(arguments: [UInt16(0), 3, 90, .max])
    func openSentExpiresAfter240SecondsRegardlessOfOfferedHoldTime(localHold: UInt16) throws {
        let session = try HandlerSession(holdTime: localHold)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(239))
        #expect(session.channel.isActive)
        #expect(session.result.value == nil)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))

        try assertHoldExpiry(session)
        let notification = try requireNotification(session.channel)
        #expect(notification == BGPNotificationMessage(errorCode: 4, errorSubcode: 0))
        var encoded = ByteBufferAllocator().buffer(capacity: 21)
        try BGPMessageCodec.encode(.notification(notification), into: &encoded)
        #expect(Array(encoded.readableBytesView) == Array(repeating: 0xff, count: 16) + [0, 21, 3, 4, 0])
        #expect(session.states.value == [.openSent, .stopped])
    }

    @Test(arguments: [UInt16(0), 3, 90], [UInt16(1), 2])
    func peerHoldTimeOneOrTwoIsRejectedEvenWhenLocalHoldIsZero(localHold: UInt16, peerHold: UInt16) throws {
        let session = try HandlerSession(holdTime: localHold)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peer = HandlerSession.peerOpen
        peer.holdTime = peerHold

        try session.channel.writeInbound(BGPMessage.open(peer))

        #expect(throws: BGPLSClientError.unacceptableHoldTime(seconds: peerHold)) {
            try #require(session.result.value).get()
        }
        #expect(try requireNotification(session.channel) == BGPNotificationMessage(errorCode: 2, errorSubcode: 6))
        #expect(session.states.value == [.openSent, .stopped])
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(241))
        #expect(session.completionCount.value == 1)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: [false, true])
    func acceptedOpenReplacesStartupTimerAndCoversOpenConfirm(establish: Bool) throws {
        let session = try HandlerSession(holdTime: 9)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(239))
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.channel.writeInbound(BGPMessage.open(peer))
        #expect(try session.channel.readOutbound(as: BGPMessage.self)?.type == .keepalive)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))
        #expect(session.channel.isActive)
        #expect(try session.channel.readOutbound(as: BGPMessage.self)?.type == .keepalive)
        if establish { try session.channel.writeInbound(BGPMessage.keepalive) }
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(establish ? 2 : 1))
        #expect(session.channel.isActive)
        _ = try drainOutbound(session.channel)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))
        try assertHoldExpiry(session)
        #expect(try requireNotification(session.channel) == BGPNotificationMessage(errorCode: 4, errorSubcode: 0))
    }

    @Test(arguments: [(UInt16(0), UInt16(0)), (0, 90), (3, 0)], [false, true])
    func negotiatedZeroDisablesBothTimers(holds: (UInt16, UInt16), establish: Bool) throws {
        let session = try HandlerSession(holdTime: holds.0)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peer = HandlerSession.peerOpen
        peer.holdTime = holds.1
        try session.channel.writeInbound(BGPMessage.open(peer))
        #expect(try session.channel.readOutbound(as: BGPMessage.self)?.type == .keepalive)
        if establish { try session.channel.writeInbound(BGPMessage.keepalive) }

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(100_000))

        #expect(session.channel.isActive)
        #expect(session.result.value == nil)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: [(UInt16(3), UInt16(9)), (9, 3), (.max, .max)])
    func negotiatedHoldUsesMinimumWithoutNarrowing(holds: (UInt16, UInt16)) throws {
        let session = try HandlerSession(holdTime: holds.0)
        defer { _ = try? session.channel.finish() }
        var peer = HandlerSession.peerOpen
        peer.holdTime = holds.1
        try session.establish(peerOpen: peer)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(Int64(min(holds.0, holds.1)) - 1))
        #expect(session.channel.isActive)
        _ = try drainOutbound(session.channel)

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))

        try assertHoldExpiry(session)
        #expect(try requireNotification(session.channel) == BGPNotificationMessage(errorCode: 4, errorSubcode: 0))
    }

    @Test
    func establishedKeepaliveRefreshesHoldWithoutRestartingOutboundCadence() throws {
        let session = try HandlerSession(holdTime: 3)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.channel.writeInbound(BGPMessage.open(peer))
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(500))
        try session.channel.writeInbound(BGPMessage.keepalive)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(500))
        #expect(try session.channel.readOutbound(as: BGPMessage.self)?.type == .keepalive)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        try session.channel.writeInbound(BGPMessage.keepalive)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(2999))
        #expect(session.channel.isActive)
        _ = try drainOutbound(session.channel)

        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(1))

        try assertHoldExpiry(session)
        #expect(try requireNotification(session.channel) == BGPNotificationMessage(errorCode: 4, errorSubcode: 0))
    }

    @Test(arguments: HoldRefreshUpdate.allCases)
    func acceptedAndRecoverableUpdatesRefreshHold(kind: HoldRefreshUpdate) throws {
        let session = try HandlerSession(holdTime: 3)
        defer { _ = try? session.channel.finish() }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        let body: ByteBuffer
        switch kind {
        case .endOfRIB:
            body = IPv6TopologyFixture.updateBody(reachable: false, nlris: [])
        case .otherFamily:
            body = DuplicateMPFixture.body(attributes: [
                DuplicateMPFixture.attribute(type: 15, value: [0, 1, 1])
            ])
        case .recoverableNLRI:
            body = IPv6TopologyFixture.updateBody(
                reachable: true, nlris: IPv6TopologyFixture.prefixWire([129]))
        case .recoverableAttribute:
            let malformedAttribute = DuplicateMPFixture.attribute(type: 29, value: [4])
            body = DuplicateMPFixture.body(attributes: [malformedAttribute])
        }

        try session.channel.writeInbound(BGPMessage.update(body))

        #expect(session.observations.value.count == 1)
        _ = try #require(session.observations.value.first).preparation.get()
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(2999))
        #expect(session.channel.isActive)
        _ = try drainOutbound(session.channel)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(1))
        try assertHoldExpiry(session)
    }

    @Test
    func duplicateOpenAndOutboundKeepalivesDoNotRefreshHold() throws {
        let session = try HandlerSession(holdTime: 3)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.channel.writeInbound(BGPMessage.open(peer))
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        #expect(try drainOutbound(session.channel).map(\.type) == [.keepalive, .keepalive])
        try session.channel.writeInbound(BGPMessage.open(peer))

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))

        try assertHoldExpiry(session)
        #expect(session.states.value == [.openSent, .openConfirm, .stopped])
    }

    @Test
    func partialTCPMessageDoesNotRefreshHold() throws {
        let session = try HandlerSession(holdTime: 3, decodeInboundBytes: true)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        var opening = ByteBufferAllocator().buffer(capacity: 100)
        try BGPMessageCodec.encode(.open(peer), into: &opening)
        try BGPMessageCodec.encode(.keepalive, into: &opening)
        try session.channel.writeInbound(opening)
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        try session.channel.writeInbound(ByteBuffer(bytes: Array(repeating: 0xff, count: 18)))
        _ = try drainOutbound(session.channel)

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))

        try assertHoldExpiry(session)
        #expect(try requireNotification(session.channel) == BGPNotificationMessage(errorCode: 4, errorSubcode: 0))
    }

    @Test
    func alreadyDequeuedExpiryCannotOverrideSameDeadlineKeepaliveRefresh() throws {
        let session = try HandlerSession(holdTime: 3)
        defer { _ = try? session.channel.finish() }
        let bound = NIOLoopBound(session.channel, eventLoop: session.channel.eventLoop)
        // EmbeddedEventLoop dequeues all tasks for a deadline before invoking the first one.
        session.channel.embeddedEventLoop.scheduleTask(in: .seconds(3)) {
            bound.value.pipeline.fireChannelRead(BGPMessage.keepalive)
        }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(3))

        #expect(session.channel.isActive)
        #expect(session.result.value == nil)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(2999))
        #expect(session.channel.isActive)
        _ = try drainOutbound(session.channel)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(1))
        try assertHoldExpiry(session)
    }

    @Test
    func alreadyDequeuedKeepaliveCannotWriteAfterTerminalFailure() throws {
        let gate = NotificationWriteGate()
        let session = try HandlerSession(notificationGate: gate, holdTime: 3)
        defer { _ = try? session.channel.finish() }
        let bound = NIOLoopBound(session.channel, eventLoop: session.channel.eventLoop)
        let attribute = DuplicateMPFixture.attribute(type: 14, value: DuplicateMPFixture.value(type: 14))
        let body = DuplicateMPFixture.body(attributes: [attribute, attribute])
        session.channel.embeddedEventLoop.scheduleTask(in: .seconds(1)) {
            bound.value.pipeline.fireChannelRead(BGPMessage.update(body))
        }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))

        #expect(gate.isPending)
        #expect(session.channel.isActive)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(5))
        #expect(gate.notifications == [BGPNotificationMessage(errorCode: 3, errorSubcode: 1)])
        #expect(throws: BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: 14)) {
            try #require(session.result.value).get()
        }
    }

    @Test(arguments: [BGPSessionState.openSent, .openConfirm, .established, .stopped])
    func stateCallbackClosureCannotResurrectTimersOrWrites(closeState: BGPSessionState) throws {
        let session = try HandlerSession(holdTime: 3, closeOnState: closeState)
        defer { _ = try? session.channel.finish() }
        if closeState != .openSent {
            _ = try session.channel.readOutbound(as: BGPMessage.self)
            var peer = HandlerSession.peerOpen
            peer.holdTime = 3
            try session.channel.writeInbound(BGPMessage.open(peer))
            if closeState != .openConfirm {
                _ = try session.channel.readOutbound(as: BGPMessage.self)
                try session.channel.writeInbound(BGPMessage.keepalive)
            }
        }
        if closeState == .stopped {
            session.channel.embeddedEventLoop.advanceTime(by: .seconds(3))
            _ = try drainOutbound(session.channel)
        }
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(500))
        #expect(!session.channel.isActive)
        #expect(session.completionCount.value == 1)
        #expect(session.states.value.filter { $0 == .stopped }.count == 1)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
        if closeState == .established { try #require(session.result.value).get() }
        if closeState == .stopped { try assertHoldExpiry(session) }
    }

    @Test
    func updateCallbackClosureDoesNotRearmHold() throws {
        let session = try HandlerSession(holdTime: 3, closeOnUpdate: true)
        defer { _ = try? session.channel.finish() }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)
        try session.channel.writeInbound(BGPMessage.update(ByteBuffer(bytes: [0, 0, 0, 0])))
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(500))
        try #require(session.result.value).get()
        #expect(session.completionCount.value == 1)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: HeldNotificationEnd.allCases)
    func holdExpiryWaitsForNotificationAndPreservesFirstFailure(end: HeldNotificationEnd) throws {
        let gate = NotificationWriteGate()
        let session = try HandlerSession(notificationGate: gate, holdTime: 3)
        defer { _ = try? session.channel.finish() }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(3))
        _ = try drainOutbound(session.channel)
        #expect(session.result.value == nil)
        #expect(session.channel.isActive)
        #expect(gate.isPending)
        #expect(gate.notifications == [BGPNotificationMessage(errorCode: 4, errorSubcode: 0)])
        session.channel.pipeline.fireChannelRead(BGPMessage.keepalive)
        session.channel.pipeline.fireChannelRead(BGPMessage.update(ByteBuffer(bytes: [0])))
        session.channel.pipeline.fireErrorCaught(OutcomeTestError.later)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(999))
        #expect(session.result.value == nil)
        #expect(session.observations.value.isEmpty)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)

        switch end {
        case .writeSuccess: gate.resolve(.success(()))
        case .writeFailure: gate.resolve(.failure(OutcomeTestError.transport))
        case .peerClosure: try session.channel.close().wait()
        case .deadline: session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(1))
        }

        try assertHoldExpiry(session)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(500))
        #expect(gate.notifications.count == 1)
        #expect(session.completionCount.value == 1)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: ImmediateNotificationEnd.allCases)
    func holdExpiryNotificationHandlesReentrantCompletion(end: ImmediateNotificationEnd) throws {
        let gate = NotificationWriteGate(immediate: end)
        let session = try HandlerSession(notificationGate: gate)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        let bound = NIOLoopBound(session.channel, eventLoop: session.channel.eventLoop)
        session.outcome.futureResult.whenComplete { _ in
            bound.value.pipeline.fireChannelInactive()
            bound.value.pipeline.fireErrorCaught(OutcomeTestError.later)
            bound.value.close(promise: nil)
        }

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(240))

        try assertHoldExpiry(session)
        #expect(gate.notifications == [BGPNotificationMessage(errorCode: 4, errorSubcode: 0)])
        #expect(session.observations.value.isEmpty)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(500))
        #expect(session.completionCount.value == 1)
        #expect(gate.notifications.count == 1)
    }

    @Test
    func lateHoldNotificationCompletionAfterDeadlineCannotReplaceOutcome() throws {
        let gate = NotificationWriteGate(resolveOnClose: false)
        let session = try HandlerSession(notificationGate: gate)
        defer {
            gate.resolve(.failure(OutcomeTestError.later))
            _ = try? session.channel.finish()
        }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(241))
        try assertHoldExpiry(session)
        #expect(gate.isPending)

        gate.resolve(.success(()))
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(500))

        try assertHoldExpiry(session)
        #expect(gate.notifications.count == 1)
    }

    @Test(arguments: [UInt16(1), 2], HeldNotificationEnd.allCases)
    func unacceptableHoldTimeWaitsForNotificationAndPreservesFailure(peerHold: UInt16, end: HeldNotificationEnd) throws
    {
        let gate = NotificationWriteGate()
        let session = try HandlerSession(notificationGate: gate, holdTime: 0)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        var peer = HandlerSession.peerOpen
        peer.holdTime = peerHold

        try session.channel.writeInbound(BGPMessage.open(peer))

        #expect(session.result.value == nil)
        #expect(session.channel.isActive)
        #expect(gate.isPending)
        #expect(gate.notifications == [BGPNotificationMessage(errorCode: 2, errorSubcode: 6)])
        session.channel.pipeline.fireChannelRead(BGPMessage.open(HandlerSession.peerOpen))
        session.channel.pipeline.fireChannelRead(BGPMessage.keepalive)
        session.channel.pipeline.fireChannelRead(BGPMessage.update(ByteBuffer(bytes: [0])))
        session.channel.pipeline.fireErrorCaught(OutcomeTestError.later)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(999))
        #expect(session.result.value == nil)
        #expect(session.observations.value.isEmpty)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)

        switch end {
        case .writeSuccess: gate.resolve(.success(()))
        case .writeFailure: gate.resolve(.failure(OutcomeTestError.transport))
        case .peerClosure: try session.channel.close().wait()
        case .deadline: session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(1))
        }

        #expect(!session.channel.isActive)
        #expect(throws: BGPLSClientError.unacceptableHoldTime(seconds: peerHold)) {
            try #require(session.result.value).get()
        }
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(500))
        #expect(gate.notifications.count == 1)
        #expect(session.completionCount.value == 1)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test(arguments: ImmediateNotificationEnd.allCases)
    func unacceptableHoldTimeNotificationHandlesReentrantCompletion(end: ImmediateNotificationEnd) throws {
        let gate = NotificationWriteGate(immediate: end)
        let session = try HandlerSession(notificationGate: gate, holdTime: 0)
        defer { _ = try? session.channel.finish() }
        _ = try session.channel.readOutbound(as: BGPMessage.self)
        let bound = NIOLoopBound(session.channel, eventLoop: session.channel.eventLoop)
        session.outcome.futureResult.whenComplete { _ in
            bound.value.pipeline.fireChannelInactive()
            bound.value.pipeline.fireErrorCaught(OutcomeTestError.later)
            bound.value.close(promise: nil)
        }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 2

        try session.channel.writeInbound(BGPMessage.open(peer))

        #expect(!session.channel.isActive)
        #expect(throws: BGPLSClientError.unacceptableHoldTime(seconds: 2)) {
            try #require(session.result.value).get()
        }
        #expect(gate.notifications == [BGPNotificationMessage(errorCode: 2, errorSubcode: 6)])
        #expect(session.observations.value.isEmpty)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(500))
        #expect(session.completionCount.value == 1)
        #expect(gate.notifications.count == 1)
    }

    @Test
    func fatalUpdateImmediatelyBeforeDeadlineRetainsItsFailure() throws {
        let session = try HandlerSession(holdTime: 3)
        defer { _ = try? session.channel.finish() }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)
        session.channel.embeddedEventLoop.advanceTime(by: .milliseconds(2999))
        _ = try drainOutbound(session.channel)
        let body = ByteBuffer(bytes: [0])

        try session.channel.writeInbound(BGPMessage.update(body))
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(500))

        #expect(!session.channel.isActive)
        #expect(session.observations.value.map(\.rawBody) == [body])
        #expect(throws: BGPLSClientError.protocolError("UPDATE missing withdrawn length")) {
            try #require(session.result.value).get()
        }
        #expect(session.completionCount.value == 1)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test
    func lazyHoldChecksRescheduleAcrossMultipleActivityBursts() throws {
        let session = try HandlerSession(holdTime: 3)
        defer { _ = try? session.channel.finish() }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)
        let loop = session.channel.embeddedEventLoop
        let origin = loop.now
        let initialCheck = try #require(session.timers.holdTask).futureResult

        loop.advanceTime(by: .seconds(2))
        try session.channel.writeInbound(BGPMessage.update(ByteBuffer(bytes: [0, 0, 0, 0])))
        #expect(session.timers.lastInboundActivity == origin + .seconds(2))
        #expect(session.timers.holdTask?.futureResult === initialCheck)
        #expect(session.timers.holdDeadline == origin + .seconds(3))

        loop.advanceTime(by: .seconds(1))
        #expect(session.channel.isActive)
        let secondCheck = try #require(session.timers.holdTask).futureResult
        #expect(secondCheck !== initialCheck)
        #expect(session.timers.holdDeadline == origin + .seconds(5))

        loop.advanceTime(by: .seconds(1))
        try session.channel.writeInbound(BGPMessage.keepalive)
        #expect(session.timers.holdTask?.futureResult === secondCheck)
        #expect(session.timers.lastInboundActivity == origin + .seconds(4))
        loop.advanceTime(by: .seconds(1))
        #expect(session.channel.isActive)
        let thirdCheck = try #require(session.timers.holdTask).futureResult
        #expect(thirdCheck !== secondCheck)
        #expect(session.timers.holdDeadline == origin + .seconds(7))

        loop.advanceTime(by: .seconds(1))
        try session.channel.writeInbound(BGPMessage.update(ByteBuffer(bytes: [0, 0, 0, 0])))
        #expect(session.timers.holdTask?.futureResult === thirdCheck)
        loop.advanceTime(by: .seconds(1))
        #expect(session.timers.holdDeadline == origin + .seconds(9))
        loop.advanceTime(by: .milliseconds(1999))
        #expect(session.channel.isActive)
        _ = try drainOutbound(session.channel)
        loop.advanceTime(by: .milliseconds(1))

        try assertHoldExpiry(session)
        #expect(try requireNotification(session.channel) == BGPNotificationMessage(errorCode: 4, errorSubcode: 0))
        #expect(session.timers.holdTask == nil)
        #expect(session.timers.keepaliveTask == nil)
    }

    @Test
    func acceptedActivityBurstPreservesScheduledTimerIdentity() throws {
        let session = try HandlerSession(holdTime: 90)
        defer { _ = try? session.channel.finish() }
        try session.establish()
        let scheduledCheck = try #require(session.timers.holdTask).futureResult
        let scheduledKeepalives = try #require(session.timers.keepaliveTask)
        let initialDeadline = try #require(session.timers.holdDeadline)
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(1))
        let activityTime = session.channel.embeddedEventLoop.now

        // task identity proves refresh avoids timer rescheduling, not global allocation freedom.
        for index in 0..<1_024 {
            if index.isMultiple(of: 2) {
                try session.channel.writeInbound(BGPMessage.keepalive)
            } else {
                try session.channel.writeInbound(BGPMessage.update(ByteBuffer(bytes: [0, 0, 0, 0])))
            }
            #expect(session.timers.holdTask?.futureResult === scheduledCheck)
            #expect(session.timers.keepaliveTask === scheduledKeepalives)
        }

        #expect(session.timers.lastInboundActivity == activityTime)
        #expect(session.timers.holdDeadline == initialDeadline)
        #expect(session.observations.value.count == 512)
        #expect(session.result.value == nil)
    }

    @Test
    func sameDeadlineExpiryThatExecutesFirstCannotBeRevivedByActivity() throws {
        let session = try HandlerSession(holdTime: 3)
        defer { _ = try? session.channel.finish() }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)
        let bound = NIOLoopBound(session.channel, eventLoop: session.channel.eventLoop)
        // enqueue activity after the expiry to exercise the opposite same-deadline ordering.
        session.channel.embeddedEventLoop.scheduleTask(in: .seconds(3)) {
            bound.value.pipeline.fireChannelRead(BGPMessage.keepalive)
        }

        session.channel.embeddedEventLoop.advanceTime(by: .seconds(3))

        try assertHoldExpiry(session)
        #expect(session.states.value == [.openSent, .openConfirm, .established, .stopped])
        let messages = try drainOutbound(session.channel)
        let notifications = messages.compactMap { message -> BGPNotificationMessage? in
            guard case .notification(let notification) = message else { return nil }
            return notification
        }
        #expect(notifications == [BGPNotificationMessage(errorCode: 4, errorSubcode: 0)])
        #expect(session.timers.holdTask == nil)
        #expect(session.timers.keepaliveTask == nil)
    }

    @Test(arguments: [UInt16(0), 3])
    func acceptedOpenInvalidatesAlreadyDequeuedStartupExpiry(negotiatedHold: UInt16) throws {
        // schedule acceptance first, then add the pipeline that arms the same-deadline startup task.
        let loop = EmbeddedEventLoop()
        let callbackChannel = NIOLoopBoundBox<EmbeddedChannel?>(nil, eventLoop: loop)
        var peer = HandlerSession.peerOpen
        peer.holdTime = negotiatedHold
        let peerMessage = BGPMessage.open(peer)
        loop.scheduleTask(in: .seconds(240)) {
            callbackChannel.value?.pipeline.fireChannelRead(peerMessage)
        }
        let session = try HandlerSession(holdTime: 3, eventLoop: loop)
        callbackChannel.value = session.channel
        defer { _ = try? session.channel.finish() }
        let startupCheck = try #require(session.timers.holdTask).futureResult
        _ = try session.channel.readOutbound(as: BGPMessage.self)

        loop.advanceTime(by: .seconds(240))

        #expect(session.channel.isActive)
        #expect(session.result.value == nil)
        #expect(session.states.value == [.openSent, .openConfirm])
        #expect(try session.channel.readOutbound(as: BGPMessage.self)?.type == .keepalive)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
        if negotiatedHold == 0 {
            #expect(session.timers.holdTask == nil)
            #expect(session.timers.keepaliveTask == nil)
            loop.advanceTime(by: .seconds(500))
            #expect(session.result.value == nil)
            #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
        } else {
            #expect(session.timers.holdTask?.futureResult !== startupCheck)
            #expect(session.timers.holdDeadline == loop.now + .seconds(3))
            loop.advanceTime(by: .seconds(3))
            try assertHoldExpiry(session)
        }
    }

    @Test(arguments: [false, true])
    func timerClosureOrRemovalPreventsRearming(removeHandler: Bool) throws {
        let session = try HandlerSession(holdTime: 3)
        defer { _ = try? session.channel.finish() }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)

        if removeHandler {
            try session.channel.pipeline.syncOperations.removeHandler(session.timers).wait()
        } else {
            try session.channel.close().wait()
        }
        session.timers.startStartupHoldTimer()
        session.timers.startNegotiatedTimers(holdTime: 3)
        session.timers.recordAcceptedActivity()
        session.channel.embeddedEventLoop.advanceTime(by: .seconds(500))

        #expect(session.timers.holdTask == nil)
        #expect(session.timers.keepaliveTask == nil)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
        if removeHandler {
            #expect(session.channel.isActive)
            #expect(session.result.value == nil)
        } else {
            #expect(!session.channel.isActive)
            try #require(session.result.value).get()
            #expect(session.completionCount.value == 1)
        }
    }

    @Test
    func removalInvalidatesAlreadyDequeuedHoldAndKeepaliveCallbacks() throws {
        let session = try HandlerSession(holdTime: 3)
        defer { _ = try? session.channel.finish() }
        let loop = session.channel.embeddedEventLoop
        let owner = NIOLoopBound((channel: session.channel, timers: session.timers), eventLoop: loop)
        let removalResult = NIOLoopBoundBox<Result<Void, any Error>?>(nil, eventLoop: loop)
        // removal runs first after all three same-deadline callbacks have been dequeued.
        loop.scheduleTask(in: .seconds(3)) {
            let bound = owner.value
            bound.channel.pipeline.syncOperations.removeHandler(bound.timers).whenComplete { result in
                removalResult.value = result
            }
        }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)
        loop.advanceTime(by: .seconds(2))
        let earlierMessages = try drainOutbound(session.channel)
        #expect(earlierMessages.map(\.type) == [.keepalive, .keepalive])

        loop.advanceTime(by: .seconds(1))

        try #require(removalResult.value).get()
        #expect(session.timers.holdTask == nil)
        #expect(session.timers.keepaliveTask == nil)
        #expect(session.channel.isActive)
        #expect(session.result.value == nil)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
        loop.advanceTime(by: .seconds(500))
        #expect(session.result.value == nil)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
    }

    @Test
    func terminalFailureDisarmsBeforeReentrantStoppedCallback() throws {
        let gate = NotificationWriteGate()
        let session = try HandlerSession(notificationGate: gate, holdTime: 3, advanceWhenStopped: .seconds(1))
        defer { _ = try? session.channel.finish() }
        var peer = HandlerSession.peerOpen
        peer.holdTime = 3
        try session.establish(peerOpen: peer)
        let attribute = DuplicateMPFixture.attribute(type: 14, value: DuplicateMPFixture.value(type: 14))
        let body = DuplicateMPFixture.body(attributes: [attribute, attribute])

        try session.channel.writeInbound(BGPMessage.update(body))

        #expect(gate.isPending)
        #expect(session.channel.isActive)
        #expect(session.result.value == nil)
        #expect(try session.channel.readOutbound(as: BGPMessage.self) == nil)
        #expect(gate.notifications == [BGPNotificationMessage(errorCode: 3, errorSubcode: 1)])
        gate.resolve(.success(()))
        #expect(throws: BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: 14)) {
            try #require(session.result.value).get()
        }
        #expect(session.completionCount.value == 1)
    }

    private func assertHoldExpiry(_ session: HandlerSession) throws {
        #expect(!session.channel.isActive)
        #expect(session.completionCount.value == 1)
        #expect(throws: BGPLSClientError.holdTimerExpired) { try #require(session.result.value).get() }
    }

    private func requireNotification(_ channel: EmbeddedChannel) throws -> BGPNotificationMessage {
        guard case .notification(let notification) = try channel.readOutbound(as: BGPMessage.self) else {
            throw BGPLSClientError.sessionFailed("test expected a NOTIFICATION")
        }
        return notification
    }

    private func drainOutbound(_ channel: EmbeddedChannel) throws -> [BGPMessage] {
        var messages: [BGPMessage] = []
        while let message = try channel.readOutbound(as: BGPMessage.self) { messages.append(message) }
        return messages
    }
}

enum HoldRefreshUpdate: CaseIterable, Sendable {
    case endOfRIB
    case otherFamily
    case recoverableNLRI
    case recoverableAttribute
}

enum OpenFailureBeforeMissingCapability: CaseIterable, Sendable {
    case version
    case malformedParameter
    case zeroAS
    case wrongAS
    case zeroIdentifier
    case sameIdentifier
    case holdTime
}

private enum OutcomeTestError: Error, Equatable {
    case transport
    case later
}

enum HeldNotificationEnd: CaseIterable, Sendable {
    case writeSuccess
    case writeFailure
    case peerClosure
    case deadline
}

enum ImmediateNotificationEnd: CaseIterable, Sendable {
    case writeSuccess
    case writeFailure
    case peerClosure
}

/// Holds only the NOTIFICATION completion; OPEN and KEEPALIVE retain normal outbound behavior.
private final class NotificationWriteGate: ChannelOutboundHandler {
    typealias OutboundIn = BGPMessage
    typealias OutboundOut = BGPMessage

    let immediate: ImmediateNotificationEnd?
    let resolveOnClose: Bool
    private var held: EventLoopPromise<Void>?
    private(set) var notifications: [BGPNotificationMessage] = []
    var isPending: Bool { held != nil }

    init(immediate: ImmediateNotificationEnd? = nil, resolveOnClose: Bool = true) {
        self.immediate = immediate
        self.resolveOnClose = resolveOnClose
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        guard case .notification(let notification) = unwrapOutboundIn(data) else {
            context.write(data, promise: promise)
            return
        }
        notifications.append(notification)
        guard let promise else {
            Issue.record("NOTIFICATION must provide a write completion promise")
            return
        }
        #expect(held == nil)
        held = promise
        if let immediate {
            // Reenter before resolving the write so the first terminal cause must already be latched.
            context.fireErrorCaught(OutcomeTestError.later)
            context.fireChannelRead(NIOAny(BGPMessage.update(ByteBuffer(bytes: [0]))))
            switch immediate {
            case .writeSuccess: resolve(.success(()))
            case .writeFailure: resolve(.failure(OutcomeTestError.transport))
            case .peerClosure: context.channel.close(promise: nil)
            }
        }
    }

    func close(context: ChannelHandlerContext, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        // Deliver channelInactive before failing the held write to exercise the opposite callback order.
        context.close(mode: mode, promise: promise)
        if resolveOnClose { resolve(.failure(ChannelError.ioOnClosedChannel)) }
    }

    func resolve(_ result: Result<Void, any Error>) {
        let promise = held
        held = nil
        promise?.completeWith(result)
    }
}

private struct HandlerSession {
    static var peerOpen: BGPOpenMessage {
        BGPOpenMessage(
            version: 4,
            myAS: 65001,
            holdTime: 90,
            bgpIdentifier: 0xC000_0201,
            optionalParameters: BGPOpenCapabilities.multiprotocolBGPLS()
        )
    }

    let channel: EmbeddedChannel
    let timers: BGPKeepaliveHoldTimerHandler
    let outcome: SessionOutcome
    let states: NIOLoopBoundBox<[BGPSessionState]>
    let result: NIOLoopBoundBox<Result<Void, any Error>?>
    let completionCount: NIOLoopBoundBox<Int>
    let observations: NIOLoopBoundBox<[BGPLSUpdateObservation]>

    init(
        localAS: UInt32 = 65001, peerAS: UInt32 = 65001,
        notificationGate: NotificationWriteGate? = nil, holdTime: UInt16 = 90,
        closeWhenStopped: Bool = false, closeOnState: BGPSessionState? = nil,
        closeOnUpdate: Bool = false, decodeInboundBytes: Bool = false,
        advanceWhenStopped: TimeAmount? = nil, eventLoop: EmbeddedEventLoop? = nil
    ) throws {
        let loop = eventLoop ?? EmbeddedEventLoop()
        let timers = BGPKeepaliveHoldTimerHandler()
        let timerOwner = NIOLoopBound((timers: timers, loop: loop), eventLoop: loop)
        let outcome = SessionOutcome(eventLoop: loop)
        let states = NIOLoopBoundBox<[BGPSessionState]>([], eventLoop: loop)
        let result = NIOLoopBoundBox<Result<Void, any Error>?>(nil, eventLoop: loop)
        let completionCount = NIOLoopBoundBox(0, eventLoop: loop)
        let observations = NIOLoopBoundBox<[BGPLSUpdateObservation]>([], eventLoop: loop)
        let callbackChannel = NIOLoopBoundBox<Channel?>(nil, eventLoop: loop)
        self.states = states
        self.timers = timers
        self.outcome = outcome
        self.result = result
        self.completionCount = completionCount
        self.observations = observations
        outcome.futureResult.whenComplete {
            result.value = $0
            completionCount.value += 1
        }

        var localOpen = Self.peerOpen
        localOpen.myAS = BGPOpenCapabilities.legacyAS(for: AutonomousSystemNumber(localAS))
        localOpen.optionalParameters = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(localAS))
        localOpen.bgpIdentifier = 0xC000_0225  // 192.0.2.37
        localOpen.holdTime = holdTime

        let admission = SessionInputAdmission(eventLoop: loop)
        let handler = BGPSessionHandler(
            openToSend: localOpen,
            localAS: AutonomousSystemNumber(localAS),
            expectedPeerAS: AutonomousSystemNumber(peerAS),
            outcome: outcome,
            timers: timers,
            admission: admission
        )
        let observer = HandlerObservationRecorder(
            admission: admission,
            stateCallback: {
                states.value.append($0)
                if $0 == .stopped, let advanceWhenStopped {
                    // exercise reentrant work before the FSM writes its terminal NOTIFICATION.
                    let owner = timerOwner.value
                    #expect(owner.timers.holdTask == nil)
                    #expect(owner.timers.keepaliveTask == nil)
                    owner.loop.advanceTime(by: advanceWhenStopped)
                }
                if (closeWhenStopped && $0 == .stopped) || $0 == closeOnState {
                    let channel = callbackChannel.value
                    callbackChannel.value = nil
                    channel?.close(promise: nil)
                }
            },
            updateObserver: {
                observations.value.append($0)
                if closeOnUpdate {
                    let channel = callbackChannel.value
                    callbackChannel.value = nil
                    channel?.close(promise: nil)
                }
            }
        )

        var handlers: [ChannelHandler] = []
        if let notificationGate { handlers.append(notificationGate) }
        if decodeInboundBytes { handlers.append(ByteToMessageHandler(BGPMessageDecoder())) }
        handlers.append(timers)
        handlers.append(handler)
        handlers.append(observer)
        channel = EmbeddedChannel(handlers: handlers, loop: loop)
        if closeWhenStopped || closeOnState != nil || closeOnUpdate { callbackChannel.value = channel }
        try channel.connect(to: try SocketAddress(ipAddress: "192.0.2.1", port: 179)).wait()
    }

    func establish(peerOpen: BGPOpenMessage = Self.peerOpen) throws {
        let outboundOpen = try #require(try channel.readOutbound(as: BGPMessage.self))
        #expect(outboundOpen.type == .open)
        try channel.writeInbound(BGPMessage.open(peerOpen))

        let keepalive = try #require(try channel.readOutbound(as: BGPMessage.self))
        #expect(keepalive.type == .keepalive)

        try channel.writeInbound(BGPMessage.keepalive)
    }
}

/// Keep synchronous FSM/reentrancy assertions at the pipeline boundary; production
/// callbacks are delivered by the native bridge on the session actor instead.
private final class HandlerObservationRecorder: ChannelInboundHandler {
    typealias InboundIn = SessionInput
    private let admission: SessionInputAdmission
    private let stateCallback: (BGPSessionState) -> Void
    private let updateObserver: (BGPLSUpdateObservation) -> Void

    init(
        admission: SessionInputAdmission,
        stateCallback: @escaping (BGPSessionState) -> Void,
        updateObserver: @escaping (BGPLSUpdateObservation) -> Void
    ) {
        self.admission = admission
        self.stateCallback = stateCallback
        self.updateObserver = updateObserver
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .state(let state): stateCallback(state)
        case .update(let observation):
            updateObserver(observation)
            admission.releaseOnEventLoop()
        }
    }
}
