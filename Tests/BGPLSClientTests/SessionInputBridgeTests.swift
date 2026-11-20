//===----------------------------------------------------------------------===//
//
// Copyright (c) 2026 Craig A. Munro
// Licensed under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CIDR
import NIOCore
import NIOEmbedded
import NIOPosix
import Testing

@testable import BGPLSClient

struct SessionInputBridgeTests {
    @Test(.timeLimit(.minutes(1)))
    func creditsIncludeCurrentWorkAndSurviveAdmissionClosure() async throws {
        let loop = NIOAsyncTestingEventLoop()
        let admission = SessionInputAdmission(eventLoop: loop, limit: 2)
        try await loop.executeInContext {
            #expect(admission.reserve())
            #expect(admission.reserve())
            #expect(!admission.reserve())
            #expect(admission.pendingCount == 2)
            admission.releaseOnEventLoop()
            #expect(admission.reserve())
            admission.close()
            #expect(!admission.reserve())
            #expect(admission.pendingCount == 2)
        }
        await admission.release()
        await admission.release()
        try await loop.executeInContext {
            #expect(admission.pendingCount == 0)
            #expect(!admission.reserve())
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func overflowWinsBeforeParsingAndDrainsAfterClosureBeforeFirstIterator() async throws {
        let session = try await BridgeTestSession.make(limit: 4)
        defer { session.channel.close(promise: nil) }
        let probe = BridgeProbe()
        let deadline = bridgeDeadline(session: session, probe: probe)
        defer { deadline.cancel() }
        try await session.establish()
        let bodies = (0..<4).map(Self.body)
        for body in bodies { try await session.send(.update(body)) }
        #expect(try await session.pending() == 4)

        // This malformed body must never be prepared or observed once all credits are held.
        try await session.send(.update(ByteBuffer(bytes: [0])))
        #expect(!session.channel.isActive)
        await #expect(throws: session.admission.capacityError) {
            try await session.outcome.futureResult.get()
        }
        try await session.loop.executeInContext {
            session.channel.pipeline.fireErrorCaught(BGPLSClientError.protocolError("later failure"))
            session.channel.pipeline.fireChannelRead(Self.encoded(.update(Self.body(99))))
        }
        #expect(try await session.channel.readOutbound(as: BGPMessage.self) == nil)

        let consumer = session.consumer(probe: probe)
        await consumer.finish()
        #expect(await probe.bodies == bodies)
        #expect(await probe.states == [.openSent, .openConfirm, .established, .stopped])
        #expect(await probe.maximumActive == 1)
        #expect(try await session.pending() == 0)
        await #expect(throws: session.admission.capacityError) {
            try await session.outcome.futureResult.get()
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func finite1024BurstDrainsExactlyOnceWithoutConcurrentHandlers() async throws {
        let gate = BridgeGate()
        defer { gate.open() }
        let session = try await BridgeTestSession.make(limit: 1_024)
        defer { session.channel.close(promise: nil) }
        let probe = BridgeProbe(gates: [1: gate])
        let deadline = bridgeDeadline(session: session, probe: probe, gates: [gate])
        defer { deadline.cancel() }
        let consumer = session.consumer(probe: probe)
        try await session.establish()
        var started = probe.started.makeAsyncIterator()
        let expected = (0..<1_024).map(Self.body)
        try await session.send(.update(expected[0]))
        #expect(await started.next() == 1)
        for body in expected.dropFirst() { try await session.send(.update(body)) }
        #expect(try await session.pending() == 1_024)
        #expect(await probe.active == 1)
        #expect(await probe.bodies.isEmpty)
        try await session.channel.close().get()

        let completion = BridgeCompletion()
        let waiter = Task {
            await consumer.finish()
            await completion.finish()
        }
        waiter.cancel()
        #expect(!(await completion.isFinished))
        gate.open()
        await waiter.value
        #expect(await completion.isFinished)
        #expect(await probe.bodies == expected)
        #expect(await probe.maximumActive == 1)
        #expect(await probe.active == 0)
        #expect(try await session.pending() == 0)
    }

    @Test(.timeLimit(.minutes(1)))
    func nativeDemandPausesAndResumesAcrossTwoConsumerStalls() async throws {
        let first = BridgeGate()
        let second = BridgeGate()
        defer {
            first.open()
            second.open()
        }
        let session = try await BridgeTestSession.make(limit: 32, low: 1, high: 4)
        defer { session.channel.close(promise: nil) }
        let probe = BridgeProbe(gates: [1: first, 6: second])
        let deadline = bridgeDeadline(session: session, probe: probe, gates: [first, second])
        defer { deadline.cancel() }
        let consumer = session.consumer(probe: probe)
        try await session.establish()
        var started = probe.started.makeAsyncIterator()
        var completed = probe.completed.makeAsyncIterator()
        var reads = session.reads.makeAsyncIterator()

        for (offset, gate) in [(0, first), (5, second)] {
            try await session.send(.update(Self.body(offset)))
            while let count = await started.next(), count < offset + 1 {}
            for value in (offset + 1)..<(offset + 5) {
                try await session.send(.update(Self.body(value)))
            }
            let before = try await session.readCount()
            session.channel.read()
            try await session.loop.executeInContext {}
            #expect(try await session.readCount() == before)
            #expect(await probe.active == 1)
            gate.open()
            while let count = await reads.next(), count <= before {}
            while let count = await completed.next(), count < offset + 5 {}
            #expect(try await session.readCount() > before)
        }
        try await session.channel.close().get()
        await consumer.finish()
        #expect(await probe.bodies == (0..<10).map(Self.body))
        #expect(await probe.maximumActive == 1)
        #expect(try await session.pending() == 0)
    }

    @Test(.timeLimit(.minutes(1)))
    func admittedMalformedObservationDoesNotClosePendingNotification() async throws {
        let session = try await BridgeTestSession.make(limit: 4, holdNotification: true)
        defer { session.channel.close(promise: nil) }
        let probe = BridgeProbe()
        let deadline = bridgeDeadline(session: session, probe: probe)
        defer { deadline.cancel() }
        let consumer = session.consumer(probe: probe)
        try await session.establish()
        var completed = probe.completed.makeAsyncIterator()
        let body = ByteBuffer(bytes: [0, 0, 0, 12, 0x80, 15, 3, 0x40, 4, 71, 0x80, 15, 3, 0x40, 4, 71])
        try await session.send(.update(body))
        #expect(await completed.next() == 1)
        #expect(session.channel.isActive)
        #expect(try await session.loop.executeInContext { session.result.value == nil })
        #expect(try await session.loop.executeInContext { session.notification.value?.pending != nil })
        try await session.loop.executeInContext { session.notification.value?.complete() }
        await #expect(throws: BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: 15)) {
            try await session.outcome.futureResult.get()
        }
        await consumer.finish()
        #expect(await probe.bodies == [body])
        #expect(try await session.pending() == 0)
    }

    @Test(.timeLimit(.minutes(1)))
    func nativeStreamFailureIsSelectedBeforeAutomaticChannelClosure() async throws {
        let session = try await BridgeTestSession.make(limit: 4)
        defer { session.channel.close(promise: nil) }
        let probe = BridgeProbe()
        let deadline = bridgeDeadline(session: session, probe: probe)
        defer { deadline.cancel() }
        try await session.establish()
        let body = Self.body(123)
        try await session.send(.update(body))
        try await session.loop.executeInContext {
            session.channel.pipeline.fireUserInboundEventTriggered(BridgeInjectedFailure.transport)
        }
        let consumer = session.consumer(probe: probe)
        await consumer.finish()

        await #expect(throws: BridgeInjectedFailure.transport) {
            try await session.outcome.futureResult.get()
        }
        #expect(!session.channel.isActive)
        #expect(await probe.bodies == [body])
        #expect(try await session.pending() == 0)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func fragmentedMinimumAndMaximumFramesRetainExactBodies(maximum: Bool) async throws {
        let session = try await BridgeTestSession.make()
        defer { session.channel.close(promise: nil) }
        let probe = BridgeProbe()
        let deadline = bridgeDeadline(session: session, probe: probe)
        defer { deadline.cancel() }
        let consumer = session.consumer(probe: probe)
        try await session.establish()
        let body: ByteBuffer
        if maximum {
            body = ByteBuffer(bytes: [0, 0, 0x0f, 0xe9, 0x90, 99, 0x0f, 0xe5] + Array(repeating: 0x5a, count: 4_069))
        } else {
            body = ByteBuffer(bytes: [0, 0, 0, 0])
        }
        let wire = Self.encoded(.update(body))
        let bytes = Array(wire.readableBytesView)
        for part in [Array(bytes.prefix(7)), Array(bytes.dropFirst(7).prefix(15)), Array(bytes.dropFirst(22))] {
            try await session.channel.writeInbound(ByteBuffer(bytes: part))
        }
        try await session.channel.close().get()
        await consumer.finish()
        #expect(await probe.bodies == [body])
        #expect(try await session.pending() == 0)
    }

    static func body(_ value: Int) -> ByteBuffer {
        var body = ByteBuffer(bytes: [0, 0, 0, 7, 0x80, 99, 4])
        body.writeInteger(UInt32(value))
        return body
    }

    static func encoded(_ message: BGPMessage) -> ByteBuffer {
        var buffer = ByteBuffer()
        do { try BGPMessageCodec.encode(message, into: &buffer) } catch { Issue.record(error) }
        return buffer
    }
}

private struct BridgeTestSession: Sendable {
    let loop: NIOAsyncTestingEventLoop
    let channel: NIOAsyncTestingChannel
    let wrapped: NIOAsyncChannel<SessionInput, Never>
    let admission: SessionInputAdmission
    let outcome: SessionOutcome
    let result: NIOLoopBoundBox<Result<Void, any Error>?>
    let readCounter: NIOLoopBoundBox<Int>
    let reads: AsyncStream<Int>
    let notification: NIOLoopBoundBox<BridgeNotificationGate?>
    let readProbe: NIOLoopBoundBox<BridgeReadProbe?>
    let holdTime: UInt16

    static func make(
        limit: Int = 1_024, low: Int = 8, high: Int = 64, holdNotification: Bool = false, holdTime: UInt16 = 0
    ) async throws -> Self {
        let loop = NIOAsyncTestingEventLoop()
        let admission = SessionInputAdmission(eventLoop: loop, limit: limit)
        let outcome = SessionOutcome(eventLoop: loop)
        let result = NIOLoopBoundBox<Result<Void, any Error>?>.makeEmptyBox(eventLoop: loop)
        outcome.futureResult.whenComplete { result.value = $0 }
        let readCounter = NIOLoopBoundBox.makeBoxSendingValue(0, eventLoop: loop)
        let (reads, readContinuation) = AsyncStream.makeStream(of: Int.self)
        let notification = NIOLoopBoundBox<BridgeNotificationGate?>.makeEmptyBox(eventLoop: loop)
        let readProbe = NIOLoopBoundBox<BridgeReadProbe?>.makeEmptyBox(eventLoop: loop)
        let owner = NIOLoopBoundBox<NIOAsyncChannel<SessionInput, Never>?>.makeEmptyBox(eventLoop: loop)
        let channel = try await NIOAsyncTestingChannel(loop: loop) { channel in
            let timers = BGPKeepaliveHoldTimerHandler()
            let reader = BridgeReadProbe(count: readCounter, reads: readContinuation)
            readProbe.value = reader
            try channel.pipeline.syncOperations.addHandler(reader)
            if holdNotification {
                let gate = BridgeNotificationGate()
                notification.value = gate
                try channel.pipeline.syncOperations.addHandler(gate)
            }
            try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(BGPMessageDecoder()))
            try channel.pipeline.syncOperations.addHandler(timers)
            try channel.pipeline.syncOperations.addHandler(
                BGPSessionHandler(
                    openToSend: bridgeOpen(identifier: 0xc000_0201, holdTime: holdTime),
                    localAS: AutonomousSystemNumber(65_001), expectedPeerAS: AutonomousSystemNumber(65_001),
                    outcome: outcome, timers: timers, admission: admission
                )
            )
            try channel.pipeline.syncOperations.addHandler(BridgeErrorInjector())
            owner.value = try NIOAsyncChannel<SessionInput, Never>(
                wrappingChannelSynchronously: channel,
                configuration: .init(backPressureStrategy: .init(lowWatermark: low, highWatermark: high))
            )
        }
        let wrapped = try await loop.executeInContext { try #require(owner.value) }
        try await loop.executeInContext { owner.value = nil }
        try await channel.connect(to: SocketAddress(ipAddress: "192.0.2.2", port: 179)).get()
        return Self(
            loop: loop, channel: channel, wrapped: wrapped, admission: admission, outcome: outcome,
            result: result, readCounter: readCounter, reads: reads, notification: notification,
            readProbe: readProbe, holdTime: holdTime
        )
    }

    func establish() async throws {
        _ = try #require(await channel.readOutbound(as: BGPMessage.self))
        try await send(.open(bridgeOpen(identifier: 0xc000_0202, holdTime: holdTime)))
        _ = try #require(await channel.readOutbound(as: BGPMessage.self))
        try await send(.keepalive)
    }

    func send(_ message: BGPMessage) async throws {
        try await channel.writeInbound(SessionInputBridgeTests.encoded(message))
    }

    func pending() async throws -> Int { try await loop.executeInContext { admission.pendingCount } }
    func readCount() async throws -> Int { try await loop.executeInContext { readCounter.value } }

    func consumer(probe: BridgeProbe) -> SessionInputConsumer {
        SessionInputConsumer(channel: wrapped, admission: admission, outcome: outcome) { input in
            await probe.consume(input)
        }
    }
}

private func bridgeOpen(identifier: UInt32, holdTime: UInt16 = 0) -> BGPOpenMessage {
    BGPOpenMessage(
        myAS: 65_001, holdTime: holdTime, bgpIdentifier: identifier,
        optionalParameters: BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(65_001))
    )
}

private struct BridgeGate: Sendable {
    let stream: AsyncStream<Void>
    let continuation: AsyncStream<Void>.Continuation

    init() { (stream, continuation) = AsyncStream.makeStream(of: Void.self) }
    func wait() async { for await _ in stream { break } }
    func open() { continuation.finish() }
}

private actor BridgeProbe {
    let started: AsyncStream<Int>
    let completed: AsyncStream<Int>
    let transitions: AsyncStream<BGPSessionState>
    private let startContinuation: AsyncStream<Int>.Continuation
    private let completionContinuation: AsyncStream<Int>.Continuation
    private let transitionContinuation: AsyncStream<BGPSessionState>.Continuation
    private let gates: [Int: BridgeGate]
    private(set) var bodies: [ByteBuffer] = []
    private(set) var states: [BGPSessionState] = []
    private(set) var active = 0
    private(set) var maximumActive = 0
    private var sequence = 0

    init(gates: [Int: BridgeGate] = [:]) {
        (started, startContinuation) = AsyncStream.makeStream(of: Int.self)
        (completed, completionContinuation) = AsyncStream.makeStream(of: Int.self)
        (transitions, transitionContinuation) = AsyncStream.makeStream(of: BGPSessionState.self)
        self.gates = gates
    }

    func finishEvents() {
        startContinuation.finish()
        completionContinuation.finish()
        transitionContinuation.finish()
    }

    func consume(_ input: SessionInput) async {
        switch input {
        case .state(let state):
            states.append(state)
            transitionContinuation.yield(state)
        case .update(let observation):
            sequence += 1
            let index = sequence
            active += 1
            maximumActive = max(maximumActive, active)
            startContinuation.yield(index)
            if let gate = gates[index] { await gate.wait() }
            bodies.append(observation.rawBody)
            active -= 1
            completionContinuation.yield(index)
        }
    }
}

private actor BridgeCompletion {
    private(set) var isFinished = false
    func finish() { isFinished = true }
}

private final class BridgeReadProbe: ChannelOutboundHandler {
    typealias OutboundIn = BGPMessage
    let count: NIOLoopBoundBox<Int>
    let reads: AsyncStream<Int>.Continuation
    var pendingBytes: ByteBuffer?

    init(count: NIOLoopBoundBox<Int>, reads: AsyncStream<Int>.Continuation) {
        self.count = count
        self.reads = reads
    }

    func read(context: ChannelHandlerContext) {
        count.value += 1
        reads.yield(count.value)
        if let bytes = pendingBytes {
            pendingBytes = nil
            context.fireChannelRead(NIOAny(bytes))
            context.fireChannelReadComplete()
        } else {
            context.read()
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) { reads.finish() }
}

private final class BridgeNotificationGate: ChannelOutboundHandler {
    typealias OutboundIn = BGPMessage
    var pending: EventLoopPromise<Void>?

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        if case .notification = unwrapOutboundIn(data) {
            pending = promise
        } else {
            context.write(data, promise: promise)
        }
    }

    func complete() {
        let promise = pending
        pending = nil
        promise?.succeed(())
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        let promise = pending
        pending = nil
        promise?.fail(ChannelError.ioOnClosedChannel)
    }
}

extension SessionInputBridgeTests {
    @Test(.timeLimit(.minutes(1)), arguments: [UInt16(0), 3])
    func readPausePreservesHoldSemanticsEvenWithUnreadKeepalive(holdTime: UInt16) async throws {
        let gate = BridgeGate()
        defer { gate.open() }
        let session = try await BridgeTestSession.make(limit: 16, low: 1, high: 4, holdTime: holdTime)
        defer { session.channel.close(promise: nil) }
        let probe = BridgeProbe(gates: [1: gate])
        let deadline = bridgeDeadline(session: session, probe: probe, gates: [gate])
        defer { deadline.cancel() }
        let consumer = session.consumer(probe: probe)
        try await session.establish()
        var started = probe.started.makeAsyncIterator()
        try await session.send(.update(Self.body(0)))
        #expect(await started.next() == 1)
        for value in 1...4 { try await session.send(.update(Self.body(value))) }
        try await session.loop.executeInContext {
            session.readProbe.value?.pendingBytes = Self.encoded(.keepalive)
        }
        session.channel.read()
        try await session.loop.executeInContext {
            #expect(session.readProbe.value?.pendingBytes != nil)
        }
        await session.loop.advanceTime(by: .seconds(holdTime == 0 ? 3_600 : 3))
        if holdTime == 0 {
            #expect(session.channel.isActive)
            #expect(try await session.loop.executeInContext { session.result.value == nil })
            try await session.channel.close().get()
        } else {
            #expect(!session.channel.isActive)
            await #expect(throws: BGPLSClientError.holdTimerExpired) {
                try await session.outcome.futureResult.get()
            }
        }
        let readsAtClose = try await session.readCount()
        gate.open()
        await consumer.finish()
        await session.loop.run()
        #expect(!session.channel.isActive)
        #expect(try await session.readCount() == readsAtClose)
        #expect(await probe.bodies == (0...4).map(Self.body))
        #expect(try await session.pending() == 0)
    }

    @Test(.timeLimit(.minutes(1)), arguments: ["127.0.0.1", "::1"], [false, true])
    func realPeerEOFOrResetCannotOverflowPausedAdmission(host: String, reset: Bool) async throws {
        let gate = BridgeGate()
        defer { gate.open() }
        let probe = BridgeProbe(gates: [1: gate])
        let (accepted, acceptedContinuation) = AsyncStream.makeStream(of: BridgeSocketSession.self)
        defer { acceptedContinuation.finish() }
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.backlog, value: 1)
            .childChannelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 4_096))
            .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let admission = SessionInputAdmission(eventLoop: channel.eventLoop, limit: 512)
                    let outcome = SessionOutcome(eventLoop: channel.eventLoop)
                    let (batches, continuation) = AsyncStream.makeStream(of: Int.self)
                    let timers = BGPKeepaliveHoldTimerHandler()
                    let metrics = NIOLoopBoundBox(BridgeSocketMetrics(), eventLoop: channel.eventLoop)
                    try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(BGPMessageDecoder()))
                    try channel.pipeline.syncOperations.addHandler(MessageToByteHandler(BGPMessageEncoder()))
                    try channel.pipeline.syncOperations.addHandler(timers)
                    try channel.pipeline.syncOperations.addHandler(
                        BGPSessionHandler(
                            openToSend: bridgeOpen(identifier: 0xc000_0201),
                            localAS: AutonomousSystemNumber(65_001), expectedPeerAS: AutonomousSystemNumber(65_001),
                            outcome: outcome, timers: timers, admission: admission
                        )
                    )
                    try channel.pipeline.syncOperations.addHandler(
                        BridgeBatchProbe(admission: admission, batches: continuation, metrics: metrics)
                    )
                    let wrapped = try NIOAsyncChannel<SessionInput, Never>(
                        wrappingChannelSynchronously: channel,
                        configuration: .init(backPressureStrategy: .init(lowWatermark: 8, highWatermark: 64))
                    )
                    acceptedContinuation.yield(
                        BridgeSocketSession(
                            wrapped: wrapped, admission: admission, outcome: outcome, batches: batches, metrics: metrics
                        )
                    )
                }
            }
            .bind(to: SocketAddress(ipAddress: host, port: 0)).get()
        defer { server.close(promise: nil) }
        let port = try #require(server.localAddress?.port)
        let (peerMessages, peerContinuation) = AsyncStream.makeStream(of: BGPMessageType.self)
        defer { peerContinuation.finish() }
        let peer = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            // Unread OPEN/KEEPALIVE data makes close reset the connection in the reset case.
            .channelOption(ChannelOptions.autoRead, value: !reset)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(BGPMessageDecoder()))
                    try channel.pipeline.syncOperations.addHandler(BridgePeerObserver(messages: peerContinuation))
                }
            }
            .connect(to: SocketAddress(ipAddress: host, port: port)).get()
        defer { peer.close(promise: nil) }
        var acceptedIterator = accepted.makeAsyncIterator()
        let session = try #require(await acceptedIterator.next())
        defer { session.wrapped.channel.close(promise: nil) }
        let consumer = SessionInputConsumer(
            channel: session.wrapped, admission: session.admission, outcome: session.outcome,
            handler: { await probe.consume($0) }
        )
        let watchdog = Task {
            do { try await Task.sleep(for: .seconds(20)) } catch { return }
            Issue.record("EOF/reset backpressure test exceeded its bounded deadline")
            gate.open()
            peer.close(promise: nil)
            session.wrapped.channel.close(promise: nil)
            await probe.finishEvents()
        }
        defer { watchdog.cancel() }

        var transitions = probe.transitions.makeAsyncIterator()
        var starts = probe.started.makeAsyncIterator()
        var batches = session.batches.makeAsyncIterator()
        var peerIterator = peerMessages.makeAsyncIterator()
        try await peer.writeAndFlush(Self.encoded(.open(bridgeOpen(identifier: 0xc000_0202)))).get()
        try await peer.writeAndFlush(Self.encoded(.keepalive)).get()
        while let state = await transitions.next(), state != .established {}
        if !reset {
            while let type = await peerIterator.next(), type != .keepalive {}
        }
        try await peer.writeAndFlush(Self.encoded(.update(Self.body(0)))).get()
        #expect(await starts.next() == 1)
        var wire = ByteBuffer()
        for value in 1...1_024 {
            var frame = Self.encoded(.update(Self.body(value)))
            wire.writeBuffer(&frame)
        }
        try await peer.writeAndFlush(wire).get()
        while let count = await batches.next(), count < 64 {}
        let beforeClosure = try await session.wrapped.channel.eventLoop.submit {
            session.admission.pendingCount
        }.get()
        #expect(beforeClosure >= 64)
        #expect(beforeClosure < 512)
        try await peer.close().get()
        #if canImport(Darwin)
            // NIO disables early EOF delivery on Darwin (SelectorGeneric.swift, rdar://53656794).
            // A paused reader must resume before its selector can discover the peer's closure.
            gate.open()
        #endif

        var failure: (any Error)?
        do { try await session.outcome.futureResult.get() } catch { failure = error }
        let atOutcome = try await session.wrapped.channel.eventLoop.submit {
            session.metrics.value
        }.get()
        #expect(atOutcome.maximumPending <= 512)
        #if !canImport(Darwin)
            // epoll can report EOF while ordinary read demand is paused, forcing a terminal burst.
            #expect(failure != nil)
            if !reset {
                #expect(failure as? BGPLSClientError == session.admission.capacityError)
                #expect(atOutcome.maximumPending == 512)
            }
        #endif
        if let capacity = failure as? BGPLSClientError, capacity == session.admission.capacityError {
            #expect(atOutcome.maximumPending == 512)
        } else if reset {
            #expect(failure != nil)
        } else {
            #expect(failure == nil)
            #expect(atOutcome.admitted == 1_025)
        }
        gate.open()
        await consumer.finish()
        let final = try await session.wrapped.channel.eventLoop.submit { session.metrics.value }.get()
        #expect(await probe.bodies == (0..<final.admitted).map(Self.body))
        print(
            "BRIDGE_EOF host=\(host) reset=\(reset) admitted=\(final.admitted) peak=\(final.maximumPending) failure=\(String(describing: failure))"
        )
        #expect(await probe.maximumActive == 1)
        #expect(try await session.wrapped.channel.eventLoop.submit { session.admission.pendingCount }.get() == 0)
    }
}

private struct BridgeSocketSession: Sendable {
    let wrapped: NIOAsyncChannel<SessionInput, Never>
    let admission: SessionInputAdmission
    let outcome: SessionOutcome
    let batches: AsyncStream<Int>
    let metrics: NIOLoopBoundBox<BridgeSocketMetrics>
}

private struct BridgeSocketMetrics: Sendable {
    var admitted = 0
    var maximumPending = 0
}

private final class BridgeBatchProbe: ChannelInboundHandler {
    typealias InboundIn = SessionInput
    let admission: SessionInputAdmission
    let batches: AsyncStream<Int>.Continuation
    let metrics: NIOLoopBoundBox<BridgeSocketMetrics>

    init(
        admission: SessionInputAdmission, batches: AsyncStream<Int>.Continuation,
        metrics: NIOLoopBoundBox<BridgeSocketMetrics>
    ) {
        self.admission = admission
        self.batches = batches
        self.metrics = metrics
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .update = unwrapInboundIn(data) {
            metrics.value.admitted += 1
            metrics.value.maximumPending = max(metrics.value.maximumPending, admission.pendingCount)
        }
        context.fireChannelRead(data)
    }
    func channelReadComplete(context: ChannelHandlerContext) {
        context.fireChannelReadComplete()
        batches.yield(admission.pendingCount)
    }
    func handlerRemoved(context: ChannelHandlerContext) { batches.finish() }
}

private final class BridgePeerObserver: ChannelInboundHandler {
    typealias InboundIn = BGPMessage
    let messages: AsyncStream<BGPMessageType>.Continuation
    init(messages: AsyncStream<BGPMessageType>.Continuation) { self.messages = messages }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) { messages.yield(unwrapInboundIn(data).type) }
    func handlerRemoved(context: ChannelHandlerContext) { messages.finish() }
}

private func bridgeDeadline(
    session: BridgeTestSession, probe: BridgeProbe, gates: [BridgeGate] = []
) -> Task<Void, Never> {
    Task {
        do { try await Task.sleep(for: .seconds(20)) } catch { return }
        Issue.record("Native bridge test exceeded its bounded deadline")
        for gate in gates { gate.open() }
        session.channel.close(promise: nil)
        await probe.finishEvents()
    }
}

private enum BridgeInjectedFailure: Error, Equatable { case transport }

private final class BridgeErrorInjector: ChannelInboundHandler {
    typealias InboundIn = SessionInput

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let failure = event as? BridgeInjectedFailure {
            context.fireErrorCaught(failure)
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }
}
