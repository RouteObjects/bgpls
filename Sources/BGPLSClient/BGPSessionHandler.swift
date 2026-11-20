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

/// Channel handler implementing a receive-oriented BGP FSM through Established.
///
/// OPEN + KEEPALIVE exchange, inbound hold timers, and bounded UPDATE preparation.
/// RIB mutation and observation remain ordered work on the session actor.
final class BGPSessionHandler: ChannelDuplexHandler {
    typealias InboundIn = BGPMessage
    typealias InboundOut = SessionInput
    typealias OutboundIn = BGPMessage
    typealias OutboundOut = BGPMessage

    private let openToSend: BGPOpenMessage
    private let localAS: AutonomousSystemNumber
    private let expectedPeerAS: AutonomousSystemNumber
    private let admission: SessionInputAdmission
    private let outcome: SessionOutcome
    private let timers: BGPKeepaliveHoldTimerHandler

    private var state: BGPSessionState = .idle
    private var negotiatedHoldTime: UInt16 = 0
    private var updateCount: UInt64 = 0
    private var terminalError: (any Error)?
    private var terminationFinished = false
    private var notificationDeadline: Scheduled<Void>?

    init(
        openToSend: BGPOpenMessage,
        localAS: AutonomousSystemNumber,
        expectedPeerAS: AutonomousSystemNumber,
        outcome: SessionOutcome,
        timers: BGPKeepaliveHoldTimerHandler,
        admission: SessionInputAdmission
    ) {
        self.openToSend = openToSend
        self.localAS = localAS
        self.expectedPeerAS = expectedPeerAS
        self.outcome = outcome
        self.timers = timers
        self.admission = admission
    }

    func channelActive(context: ChannelHandlerContext) {
        context.fireChannelActive()
        guard isActive(context: context) else { return }
        transition(to: .openSent, context: context)
        guard isActive(context: context), state == .openSent else { return }
        // Bound the OPEN exchange even when the offered negotiated Hold Time is zero.
        timers.startStartupHoldTimer()
        context.writeAndFlush(Self.wrapOutboundOut(.open(openToSend)), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard terminalError == nil, state != .stopped else { return }
        let message = unwrapInboundIn(data)
        do {
            try handle(message, context: context)
        } catch {
            fail(error, context: context)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        admission.close()
        timers.disarm()
        notificationDeadline?.cancel()
        notificationDeadline = nil
        if terminalError != nil {
            finishFailure(context: context, closeChannel: false)
        } else if !terminationFinished {
            terminationFinished = true
            if state == .established {
                outcome.complete(.success(()))
            } else {
                outcome.complete(.failure(BGPLSClientError.sessionFailed("channel closed in state \(state)")))
            }
        }
        if state != .stopped { transition(to: .stopped, context: context) }
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        admission.close()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        fail(error, context: context)
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is BGPHoldTimerExpiredEvent {
            fail(BGPLSClientError.holdTimerExpired, context: context)
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }

    private func handle(_ message: BGPMessage, context: ChannelHandlerContext) throws {
        switch (state, message) {
        case (.openSent, .open(let peerOpen)):
            try acceptPeerOpen(peerOpen)
            transition(to: .openConfirm, context: context)
            guard isActive(context: context), state == .openConfirm else { return }
            timers.startNegotiatedTimers(holdTime: negotiatedHoldTime)
            context.writeAndFlush(Self.wrapOutboundOut(.keepalive), promise: nil)

        case (.openConfirm, .keepalive):
            enterEstablished(context: context)

        case (.openConfirm, .open):
            // Some stacks may retransmit; ignore duplicate OPEN once in openConfirm.
            break

        case (.established, .keepalive):
            timers.recordAcceptedActivity()

        case (.established, .update(let body)):
            guard admission.reserve() else { throw admission.capacityError }
            updateCount += 1
            //  The decoder bounds wire messages to 4096 bytes. Prepare synchronously
            // so fatal framing wins before channelInactive can report ordinary peer closure.
            // A bounded copy avoids retaining a larger decoder cumulation through a slice.
            var retained = context.channel.allocator.buffer(capacity: body.readableBytes)
            retained.writeImmutableBuffer(body)
            let observation = BGPLSUpdateObservation(rawBody: retained)
            context.fireChannelRead(Self.wrapInboundOut(.update(observation)))
            if case .failure(let error) = observation.preparation { throw error }
            // Recoverable content rejection still proves that the peer is sending UPDATEs.
            if isActive(context: context), state == .established {
                timers.recordAcceptedActivity()
            }

        case (_, .notification(let note)):
            throw BGPLSClientError.sessionFailed(
                "NOTIFICATION code=\(note.errorCode) subcode=\(note.errorSubcode)"
            )

        case (.established, .open):
            throw BGPLSClientError.protocolError("unexpected OPEN while Established")

        default:
            throw BGPLSClientError.protocolError(
                "unexpected message \(message.type) in state \(state)"
            )
        }
    }

    private func acceptPeerOpen(_ peerOpen: BGPOpenMessage) throws {
        guard peerOpen.version == 4 else {
            throw BGPLSClientError.protocolError("unsupported BGP version \(peerOpen.version)")
        }
        let capabilities = try BGPOpenCapabilities.parse(peerOpen.optionalParameters)
        //  RFC 6793 makes capability 65 authoritative. AS_TRANS is a wire
        // placeholder, never a wildcard that can bypass the configured peer identity.
        let peerAS = capabilities.fourOctetAS ?? AutonomousSystemNumber(UInt32(peerOpen.myAS))
        guard peerAS.rawValue != 0 else {
            throw BGPLSClientError.protocolError("peer AS must be non-zero")
        }
        if peerAS != expectedPeerAS {
            throw BGPLSClientError.sessionFailed(
                "peer AS \(peerAS) does not match expected \(expectedPeerAS)"
            )
        }
        guard BGPIdentifier(rawValue: peerOpen.bgpIdentifier) != nil else {
            throw BGPLSClientError.protocolError("peer BGP identifier must be non-zero")
        }
        //  RFC 6286 identifier uniqueness is within an AS. Use the configured
        // AS relationship, not the peer's asserted My AS, and permit equal IDs on eBGP.
        if expectedPeerAS == localAS && peerOpen.bgpIdentifier == openToSend.bgpIdentifier {
            throw BGPLSClientError.protocolError("peer BGP identifier matches local identifier in iBGP")
        }
        guard peerOpen.holdTime == 0 || peerOpen.holdTime >= 3 else {
            throw BGPLSClientError.unacceptableHoldTime(seconds: peerOpen.holdTime)
        }
        negotiatedHoldTime = min(openToSend.holdTime, peerOpen.holdTime)
        // Require BGP-LS after existing OPEN validation, before any acceptance or KEEPALIVE.
        guard capabilities.supportsBGPLS else {
            throw BGPLSClientError.missingBGPLSCapability
        }
    }

    private func enterEstablished(context: ChannelHandlerContext) {
        timers.recordAcceptedActivity()
        // The outcome stays pending; the outbound cadence began when OPEN was accepted.
        transition(to: .established, context: context)
    }

    private func isActive(context: ChannelHandlerContext) -> Bool {
        terminalError == nil && !terminationFinished && context.channel.isActive
    }

    private func transition(to newState: BGPSessionState, context: ChannelHandlerContext) {
        state = newState
        context.fireChannelRead(Self.wrapInboundOut(.state(newState)))
        // Startup and terminal states can occur outside a socket read cycle. Deliver them
        // without waiting for another read; UPDATE batches otherwise use readComplete.
        context.fireChannelReadComplete()
        context.fireUserInboundEventTriggered(BGPSessionStateEvent(state: newState))
    }

    private func fail(_ error: Error, context: ChannelHandlerContext) {
        guard terminalError == nil, !terminationFinished else { return }
        // Latch the cause before callbacks or writes can reenter the handler.
        terminalError = error
        admission.close()
        // disarm before callbacks can reenter while NOTIFICATION completion is pending.
        timers.disarm()
        transition(to: .stopped, context: context)
        guard !terminationFinished else { return }

        guard let notification = Self.notification(for: error) else {
            finishFailure(context: context)
            return
        }
        // Publishing the outcome wakes actor cleanup, which closes the socket.
        // Keep it pending until this bounded notification write finishes or the peer closes.
        let bound = NIOLoopBound((handler: self, context: context), eventLoop: context.eventLoop)
        notificationDeadline = context.eventLoop.scheduleTask(in: .seconds(1)) {
            let owner = bound.value
            owner.handler.notificationDeadline = nil
            owner.handler.finishFailure(context: owner.context)
        }
        let written = context.eventLoop.makePromise(of: Void.self)
        written.futureResult.whenComplete { _ in
            let owner = bound.value
            owner.handler.finishFailure(context: owner.context)
        }
        context.writeAndFlush(Self.wrapOutboundOut(.notification(notification)), promise: written)
    }

    private static func notification(for error: any Error) -> BGPNotificationMessage? {
        switch error as? BGPLSClientError {
        case .duplicateMultiprotocolAttribute(let typeCode)
        where typeCode == BGPPathAttributeType.mpReachNLRI || typeCode == BGPPathAttributeType.mpUnreachNLRI:
            return BGPNotificationMessage(errorCode: 3, errorSubcode: 1)
        case .holdTimerExpired:
            return BGPNotificationMessage(errorCode: 4, errorSubcode: 0)
        case .unacceptableHoldTime:
            return BGPNotificationMessage(errorCode: 2, errorSubcode: 6)
        case .missingBGPLSCapability:
            // RFC 5492 reports the required capability TLV, without its OPEN parameter wrapper.
            return BGPNotificationMessage(
                errorCode: 2, errorSubcode: 7, data: BGPOpenCapabilities.bgpLSCapabilityValue
            )
        default:
            return nil
        }
    }

    private func finishFailure(context: ChannelHandlerContext, closeChannel: Bool = true) {
        guard let terminalError, !terminationFinished else { return }
        terminationFinished = true
        notificationDeadline?.cancel()
        notificationDeadline = nil
        outcome.complete(.failure(terminalError))
        if closeChannel { context.close(promise: nil) }
    }
}

/// User event fired when the session FSM state changes.
public struct BGPSessionStateEvent: Sendable {
    public let state: BGPSessionState
    public init(state: BGPSessionState) {
        self.state = state
    }
}
