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

/// Scheduling mechanics for the FSM's explicit, event-loop-confined timer decisions.
/// Messages pass through unchanged; observing traffic does not imply FSM acceptance.
final class BGPKeepaliveHoldTimerHandler: ChannelDuplexHandler, RemovableChannelHandler {
    typealias InboundIn = BGPMessage
    typealias InboundOut = BGPMessage
    typealias OutboundIn = BGPMessage
    typealias OutboundOut = BGPMessage

    private enum Mode {
        case waiting, startup, negotiated, stopped
    }

    private var context: ChannelHandlerContext?
    private var mode: Mode = .waiting
    private var generation: UInt64 = 0

    // Internal read-only inspection lets tests verify scheduling without runtime counters.
    private(set) var holdTask: Scheduled<Void>?
    private(set) var keepaliveTask: RepeatedTask?
    private(set) var holdDuration: TimeAmount = .zero
    private(set) var lastInboundActivity: NIODeadline?
    private(set) var holdDeadline: NIODeadline?

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        disarm()
        self.context = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        context.write(data, promise: promise)
    }

    func close(context: ChannelHandlerContext, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        disarm()
        context.close(mode: mode, promise: promise)
    }

    func channelInactive(context: ChannelHandlerContext) {
        disarm()
        context.fireChannelInactive()
    }

    func startStartupHoldTimer() {
        guard let context else { return }
        context.eventLoop.preconditionInEventLoop()
        guard mode == .waiting, context.channel.isActive else { return }
        mode = .startup
        startHoldTimer(seconds: 240, context: context)
    }

    func startNegotiatedTimers(holdTime: UInt16) {
        guard let context else { return }
        context.eventLoop.preconditionInEventLoop()
        guard mode == .startup, context.channel.isActive else { return }
        mode = .negotiated
        startHoldTimer(seconds: holdTime, context: context)
        guard holdTime >= 3 else { return }

        let interval = TimeAmount.seconds(Int64(holdTime / 3))
        let generation = generation
        let bound = NIOLoopBound((handler: self, context: context), eventLoop: context.eventLoop)
        keepaliveTask = context.eventLoop.scheduleRepeatedTask(initialDelay: interval, delay: interval) { _ in
            let owner = bound.value
            // cancellation cannot retract a callback already dequeued by the event loop.
            guard owner.handler.generation == generation,
                owner.handler.mode == .negotiated, owner.context.channel.isActive
            else { return }
            owner.context.writeAndFlush(Self.wrapOutboundOut(.keepalive), promise: nil)
        }
    }

    func recordAcceptedActivity() {
        guard let context else { return }
        context.eventLoop.preconditionInEventLoop()
        guard mode == .negotiated, holdDuration > .zero, context.channel.isActive else { return }
        // move the logical deadline without replacing the pending scheduled check.
        lastInboundActivity = context.eventLoop.now
    }

    func disarm() {
        context?.eventLoop.preconditionInEventLoop()
        mode = .stopped
        cancelTasks()
    }

    private func cancelTasks() {
        generation &+= 1
        holdTask?.cancel()
        holdTask = nil
        keepaliveTask?.cancel()
        keepaliveTask = nil
        holdDuration = .zero
        lastInboundActivity = nil
        holdDeadline = nil
    }

    private func startHoldTimer(seconds: UInt16, context: ChannelHandlerContext) {
        cancelTasks()
        guard seconds != 0 else { return }
        holdDuration = .seconds(Int64(seconds))
        let now = context.eventLoop.now
        lastInboundActivity = now
        let deadline = now + holdDuration
        scheduleHoldCheck(at: deadline, generation: generation, context: context)
    }

    private func scheduleHoldCheck(at deadline: NIODeadline, generation: UInt64, context: ChannelHandlerContext) {
        holdDeadline = deadline
        let bound = NIOLoopBound((handler: self, context: context), eventLoop: context.eventLoop)
        holdTask = context.eventLoop.scheduleTask(deadline: deadline) {
            let owner = bound.value
            let handler = owner.handler
            let context = owner.context
            guard handler.generation == generation, handler.mode != .stopped,
                context.channel.isActive, let lastActivity = handler.lastInboundActivity
            else { return }
            handler.holdTask = nil
            let latestDeadline = lastActivity + handler.holdDuration
            if context.eventLoop.now < latestDeadline {
                handler.scheduleHoldCheck(at: latestDeadline, generation: generation, context: context)
            } else {
                // stop both schedules before expiry enters the FSM's notification path.
                handler.disarm()
                context.fireUserInboundEventTriggered(BGPHoldTimerExpiredEvent())
            }
        }
    }
}

/// The timer reports expiry; the FSM owns the terminal error, NOTIFICATION, and outcome.
struct BGPHoldTimerExpiredEvent: Sendable {}
