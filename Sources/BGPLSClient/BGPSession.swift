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
import Foundation
import NIOCore
import NIOExtras
import NIOPosix

/// Receive-only BGP-LS session coordinator (RFC 4271 subset + RFC 9552 consumer).
///
/// Outbound TCP connect and OPEN/KEEPALIVE reach **Established**. Bounded UPDATE preparation
/// runs on the event loop; this actor applies the ordered mixed-family RIB observations.
public actor BGPSession<Family: IPAddressFamily> {
    /// Session parameters (typed peer endpoint and optional local bind address).
    public let configuration: BGPSessionConfiguration<Family>

    private var state: BGPSessionState = .idle
    private var rib = LSRIB()
    // This control is shared with NIO's event loop so a stop can close a channel while
    // connect() is still suspended and before the actor receives the connected Channel.
    private let channelControl = SessionChannelControl()
    private var runInProgress = false
    private var inputConsumer: SessionInputConsumer?
    private let inputConsumerFactory: SessionInputConsumer.Factory?
    private let pcapSinkFactory: PCAPFileSink.Factory
    /// Active ``ribChanges`` subscribers (in-process AsyncStream destinations).
    private var ribChangeContinuations: [UUID: AsyncStream<RIBDiff>.Continuation] = [:]

    private enum RunStage {
        case setup
        case connecting
        case active
    }

    /// Creates a session with the given configuration.
    public init(configuration: BGPSessionConfiguration<Family>) {
        self.configuration = configuration
        inputConsumerFactory = nil
        pcapSinkFactory = PCAPFileSink.liveFactory
    }

    /// A test can suspend the actual consumer without blocking a synchronous callback.
    /// This changes construction only; the public path has no per-observation hook.
    init(
        configuration: BGPSessionConfiguration<Family>,
        inputConsumerFactory: @escaping SessionInputConsumer.Factory
    ) {
        self.configuration = configuration
        self.inputConsumerFactory = inputConsumerFactory
        pcapSinkFactory = PCAPFileSink.liveFactory
    }

    /// Allows bounded file-I/O tests without changing capture defaults or the public API.
    init(configuration: BGPSessionConfiguration<Family>, pcapSinkFactory: @escaping PCAPFileSink.Factory) {
        self.configuration = configuration
        self.pcapSinkFactory = pcapSinkFactory
        inputConsumerFactory = nil
    }

    /// Current FSM state.
    public func sessionState() -> BGPSessionState { state }

    /// Snapshot of the in-memory LS RIB.
    public func ribSnapshot() -> LSRIB { rib }

    /// Validates configuration, connects outbound, completes OPEN exchange, and holds
    /// Established until cancelled, a fatal session error occurs, or the peer closes.
    /// Returns or throws only after channel, UPDATE, PCAP, and subscriber cleanup completes.
    ///
    /// Both callbacks execute synchronously on this actor and must return promptly.
    /// `@Sendable` permits safe transfer of the closure; it does not make execution asynchronous.
    /// Avoid blocking I/O, expensive processing, sleeps, and synchronous waits for actor work.
    /// A slow callback delays RIB processing, other actor operations (including ``stop()``),
    /// and cleanup. Task cancellation can request channel closure independently, but cannot
    /// interrupt synchronous callback code or bypass the ordered drain. Work independently
    /// launched by a callback is not awaited by this method.
    ///
    /// Native read backpressure slows intake when the ordered consumer falls behind. A separate
    /// 1,024-UPDATE admission limit includes queued and actively processed observations. Exhaustion
    /// fails the session before admitting another body; previously admitted work still drains.
    /// This does not bound topology storage or arbitrary callback-owned work. Optional capture
    /// separately limits pending encoded bytes to 8 MiB and pending chunks to 4,096 per capture,
    /// including its active write; exceeding either limit stops capture while BGP continues.
    /// Synchronous stderr output can also stall processing, including diagnostics
    /// emitted when `logUpdates` is false. Use a promptly drained output destination.
    /// For expensive consumer work, use an explicitly owned worker with a deliberate buffering,
    /// overload, and shutdown policy; launching a task per UPDATE merely moves the backlog.
    ///
    /// - Parameters:
    ///   - pcapPath: Optional new file in a trusted directory for a `.pcap` written by
    ///     ``NIOWritePCAPHandler`` (Wireshark). Existing paths are refused; creation uses
    ///     owner-only permissions. Later write errors or capture-budget exhaustion are logged
    ///     without failing collection, so successful session completion does not certify a complete
    ///     capture. Budget exhaustion drains admitted chunks and closes capture without resuming.
    ///     Its warning waits behind admitted I/O; these limits do not impose an I/O deadline.
    ///   - logUpdates: When true, synchronously logs a capped hex dump of each UPDATE body and
    ///     RIB counts to stderr. Disabling it does not suppress diagnostic output.
    ///   - onUpdate: Optional observer for admitted raw UPDATE bodies, including parser-rejected bodies.
    ///     A body refused by the admission limit is not observed or interpreted.
    ///     Invoked synchronously in wire order on this actor, before that UPDATE's RIB mutation.
    ///     Invalid outer BGP messages are outside this callback's contract. All admitted
    ///     observations finish before this method returns or throws.
    ///   - onStateChange: Optional synchronous FSM observer on this actor (e.g. CLI logging).
    ///     The initial connect state is reported directly; later reports use the ordered queue.
    public func run(
        pcapPath: String? = nil,
        logUpdates: Bool = false,
        onUpdate: (@Sendable (ByteBuffer) -> Void)? = nil,
        onStateChange: (@Sendable (BGPSessionState) -> Void)? = nil
    ) async throws {
        guard !runInProgress else {
            throw BGPLSClientError.sessionFailed("run is already in progress")
        }
        guard !channelControl.isStopRequested else {
            state = .stopped
            finishRIBChangeStreams()
            throw CancellationError()
        }

        runInProgress = true
        defer { runInProgress = false }

        var runStage = RunStage.setup
        var pcapSink: PCAPFileSink?
        var connectedChannel: Channel?
        //  The outcome and channel share one event loop for the entire session,
        // including failures before the TCP connection or pipeline setup has completed.
        let eventLoop = MultiThreadedEventLoopGroup.singleton.next()
        let outcome = SessionOutcome(eventLoop: eventLoop)
        let admission = SessionInputAdmission(eventLoop: eventLoop)
        // Keep the wrapper reachable even if connection fails after pipeline setup. Taking
        // it clears the holder, avoiding a retained channel/handler/holder cycle.
        let inputChannel = NIOLoopBoundBox<NIOAsyncChannel<SessionInput, Never>?>.makeEmptyBox(eventLoop: eventLoop)

        do {
            try validateConfiguration()
            state = .connect
            onStateChange?(.connect)

            let open = makeOpenMessage()
            let localAS = configuration.localAS
            let expectedPeerAS = configuration.peerAS
            let peerAddress = try SocketAddressBuilder.make(endpoint: configuration.peer)
            let localAddress: SocketAddress?
            if let local = configuration.localAddress {
                localAddress = try SocketAddressBuilder.make(address: local, port: 0)
            } else {
                localAddress = nil
            }

            let connectTimeout = try configuration.validatedConnectTimeout()

            // Optional PCAP sink — closed when the session ends.
            if let pcapPath {
                pcapSink = try await pcapSinkFactory(pcapPath) { error in
                    let prefix: String
                    if let failure = error as? PCAPFileSink.Failure,
                        case .captureBudgetExceeded = failure
                    {
                        prefix = "bgpls: "
                    } else {
                        prefix = "bgpls: pcap write error: "
                    }
                    FileHandle.standardError.write(
                        Data("\(prefix)\(error)\n".utf8)
                    )
                }
            }
            let capturedSink = pcapSink

            let bootstrap = ClientBootstrap(group: eventLoop)
                .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .channelOption(
                    ChannelOptions.recvAllocator,
                    value: FixedSizeRecvByteBufferAllocator(capacity: SessionInputSettings.receiveBufferSize)
                )
                .channelOption(ChannelOptions.maxMessagesPerRead, value: 1)
                .connectTimeout(connectTimeout)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        guard self.channelControl.register(channel) else {
                            throw CancellationError()
                        }

                        do {
                            inputChannel.value = try Self.configurePipeline(
                                channel: channel,
                                capturedSink: capturedSink,
                                outcome: outcome,
                                open: open,
                                localAS: localAS,
                                expectedPeerAS: expectedPeerAS,
                                admission: admission
                            )
                        } catch {
                            self.channelControl.clear(channel)
                            throw error
                        }
                    }
                }

            runStage = .connecting
            let connecting: EventLoopFuture<Channel>
            if let localAddress {
                connecting = bootstrap.bind(to: localAddress).connect(to: peerAddress)
            } else {
                connecting = bootstrap.connect(to: peerAddress)
            }
            let connected = try await withTaskCancellationHandler {
                try await connecting.get()
            } onCancel: {
                channelControl.requestStop()
            }
            connectedChannel = connected
            runStage = .active
            await startInputConsumer(
                from: inputChannel, admission: admission, outcome: outcome,
                logUpdates: logUpdates, onUpdate: onUpdate, onStateChange: onStateChange
            )

            if let pcapPath {
                FileHandle.standardError.write(
                    Data(
                        "bgpls: writing PCAP to \(pcapPath) (Wireshark: filter on the configured peer port)\n".utf8
                    )
                )
            }

            //  Established is progress, not successful session completion.
            // closeFuture only confirms cleanup and cannot carry the BGP termination reason.
            try await withTaskCancellationHandler {
                try await outcome.futureResult.get()
            } onCancel: {
                channelControl.requestStop()
            }
        } catch {
            let mappedError = normalizedRunError(error, stage: runStage)
            outcome.complete(.failure(mappedError))
            await startInputConsumer(
                from: inputChannel, admission: admission, outcome: outcome,
                logUpdates: logUpdates, onUpdate: onUpdate, onStateChange: onStateChange
            )
            await finishRun(channel: connectedChannel, pcapSink: pcapSink)
            throw mappedError
        }

        await finishRun(channel: connectedChannel, pcapSink: pcapSink)
        // Intentional close can fulfill the outcome successfully; preserve stop/cancellation
        // even if it arrives while the successful session's cleanup is draining.
        if channelControl.isStopRequested || Task.isCancelled {
            throw CancellationError()
        }
    }

    /// Closes input, drains ordered UPDATE work, and only then finishes observable resources.
    private func finishRun(
        channel: Channel?,
        pcapSink: PCAPFileSink?
    ) async {
        if let channel = channel ?? inputConsumer?.channel {
            channel.close(promise: nil)
            try? await channel.closeFuture.get()
            channelControl.clear(channel)
        } else {
            channelControl.clear()
        }

        if let inputConsumer {
            self.inputConsumer = nil
            await inputConsumer.finish()
        }
        await closePcapSink(pcapSink)
        finishRIBChangeStreams()
        state = .stopped
    }

    /// Taking the wrapper also works after failed connect or an early peer close: NIO
    /// retains finished-source observations until this sole iterator drains them.
    private func startInputConsumer(
        from holder: NIOLoopBoundBox<NIOAsyncChannel<SessionInput, Never>?>,
        admission: SessionInputAdmission,
        outcome: SessionOutcome,
        logUpdates: Bool,
        onUpdate: (@Sendable (ByteBuffer) -> Void)?,
        onStateChange: (@Sendable (BGPSessionState) -> Void)?
    ) async {
        let channel = await withCheckedContinuation { continuation in
            holder.eventLoop.execute {
                let channel = holder.value
                holder.value = nil
                continuation.resume(returning: channel)
            }
        }
        guard let channel else { return }
        let handler: @Sendable (SessionInput) async -> Void = { [weak self] input in
            guard let self else { return }
            switch input {
            case .state(let state):
                await self.applyState(state, onStateChange: onStateChange)
            case .update(let observation):
                await self.applyUpdateObservation(observation, logUpdates: logUpdates, onUpdate: onUpdate)
            }
        }
        if let inputConsumerFactory {
            inputConsumer = inputConsumerFactory(channel, admission, outcome, handler)
        } else {
            inputConsumer = SessionInputConsumer(
                channel: channel, admission: admission, outcome: outcome, handler: handler
            )
        }
    }

    /// Keeps existing public error categories while using one common cleanup path.
    private func normalizedRunError(_ error: any Error, stage: RunStage) -> any Error {
        if error is CancellationError || channelControl.isStopRequested || Task.isCancelled {
            return CancellationError()
        }
        if let clientError = error as? BGPLSClientError {
            return clientError
        }
        switch stage {
        case .setup:
            return error
        case .connecting:
            return BGPLSClientError.connectFailed(String(describing: error))
        case .active:
            return BGPLSClientError.sessionFailed(String(describing: error))
        }
    }

    private nonisolated static func configurePipeline(
        channel: Channel,
        capturedSink: PCAPFileSink?,
        outcome: SessionOutcome,
        open: BGPOpenMessage,
        localAS: AutonomousSystemNumber,
        expectedPeerAS: AutonomousSystemNumber,
        admission: SessionInputAdmission
    ) throws -> NIOAsyncChannel<SessionInput, Never> {
        // Sync pipeline ops (Weiß): ordered, no async addHandler races.
        // https://forums.swift.org/t/adding-and-removing-handlers/54915/2
        if let sink = capturedSink {
            let pcapHandler = NIOWritePCAPHandler(
                mode: .client,
                fileSink: sink.write(buffer:)
            )
            try channel.pipeline.syncOperations.addHandler(
                pcapHandler,
                position: .first
            )
        }

        try channel.pipeline.syncOperations.addHandler(
            ByteToMessageHandler(BGPMessageDecoder())
        )
        try channel.pipeline.syncOperations.addHandler(
            MessageToByteHandler(BGPMessageEncoder())
        )
        // scheduling and FSM decisions share the event loop through explicit commands.
        let timers = BGPKeepaliveHoldTimerHandler()
        try channel.pipeline.syncOperations.addHandler(timers)
        try channel.pipeline.syncOperations.addHandler(
            BGPSessionHandler(
                openToSend: open,
                localAS: localAS,
                expectedPeerAS: expectedPeerAS,
                outcome: outcome,
                timers: timers,
                admission: admission
            )
        )
        return try NIOAsyncChannel(
            wrappingChannelSynchronously: channel,
            configuration: .init(
                backPressureStrategy: .init(
                    lowWatermark: SessionInputSettings.lowWatermark,
                    highWatermark: SessionInputSettings.highWatermark
                ),
                isOutboundHalfClosureEnabled: false
            )
        )
    }

    /// Permanently requests that this session stop and closes a connecting or established channel.
    ///
    /// Repeated calls are harmless. Create a new session rather than calling
    /// ``run(pcapPath:logUpdates:onUpdate:onStateChange:)`` after requesting a stop.
    public func stop() {
        channelControl.requestStop()
        state = .stopped
        // Active run cleanup drains the ordered UPDATE processor before closing subscribers.
        if !runInProgress {
            finishRIBChangeStreams()
        }
    }

    /// Text dump of the current RIB (`summary` / `nodes` / `links` / `prefixes`).
    public func ribDump(topic: String = "summary", showAttributes: Bool = false) -> String {
        rib.dump(topic: topic, showAttributes: showAttributes)
    }

    /// Counts for CLI termination without constructing a snapshot or sorting topology records.
    package func ribSummaryLine() -> String {
        rib.summaryLine
    }

    /// Codable snapshot for application integration or export.
    public func ribSnapshot(at date: Date = Date()) -> RIBSnapshot {
        rib.snapshot(at: date)
    }

    /// In-process push feed of RIB changes (does not replace ``ribSnapshot()`` / ``LSRIB``).
    ///
    /// Each NLRI apply/withdraw yields a ``RIBDiff``. Optional catch-up sends one ``RIBDiff/snapshot``
    /// with the current RIB before live events. Destinations are whatever awaits this stream in-process
    /// (CLI `--watch`, tests, and application consumers)—not a network socket.
    /// Each subscriber retains at most `bufferingNewest` pending events (512 by default), dropping
    /// the oldest when full, potentially including the catch-up snapshot. This does not discard
    /// objects from the session RIB. It is separate from native ingress backpressure:
    /// changing subscriber capacity does not throttle socket intake or RIB processing.
    /// Exact replay requires delivery of the complete event sequence. This bounded
    /// stream does not yet detect overflow or automatically resynchronize consumers.
    public func ribChanges(
        includeCatchUpSnapshot: Bool = true,
        bufferingNewest: Int = 512
    ) -> AsyncStream<RIBDiff> {
        let id = UUID()
        let (stream, continuation) = AsyncStream.makeStream(
            of: RIBDiff.self,
            bufferingPolicy: .bufferingNewest(bufferingNewest)
        )
        ribChangeContinuations[id] = continuation
        continuation.onTermination = { @Sendable _ in
            Task { await self.removeRIBChangeContinuation(id) }
        }
        if includeCatchUpSnapshot {
            continuation.yield(.snapshot(rib.snapshot()))
        }
        return stream
    }

    private func removeRIBChangeContinuation(_ id: UUID) {
        ribChangeContinuations.removeValue(forKey: id)
    }

    private func broadcastRIBDiffs(_ diffs: [RIBDiff]) {
        guard !diffs.isEmpty, !ribChangeContinuations.isEmpty else { return }
        for continuation in ribChangeContinuations.values {
            for diff in diffs {
                continuation.yield(diff)
            }
        }
    }

    private func finishRIBChangeStreams() {
        for continuation in ribChangeContinuations.values {
            continuation.finish()
        }
        ribChangeContinuations.removeAll()
    }

    private func applyState(
        _ newState: BGPSessionState,
        onStateChange: (@Sendable (BGPSessionState) -> Void)?
    ) {
        onStateChange?(newState)
        guard !channelControl.isStopRequested else { return }
        state = newState
    }

    /// Applies a raw UPDATE body as if received from the peer (tests / replay).
    package func applyInboundUpdateForTesting(_ body: ByteBuffer) throws {
        let observation = BGPLSUpdateObservation(rawBody: body)
        _ = try observation.preparation.get()
        applyUpdateObservation(observation, logUpdates: false, onUpdate: nil)
    }

    private func applyUpdateObservation(
        _ observation: BGPLSUpdateObservation,
        logUpdates: Bool,
        onUpdate: (@Sendable (ByteBuffer) -> Void)?
    ) {
        let body = observation.rawBody
        onUpdate?(body)
        if logUpdates {
            let line =
                "bgpls: \(Self.logTimestamp()) UPDATE \(body.hexDump(maxBytes: 256))\n"
            FileHandle.standardError.write(Data(line.utf8))
        }
        switch observation.preparation {
        case .success(let prepared):
            //  Both NLRI fields are already prepared. No throwing operation or actor
            // suspension can separate committed RIB changes from their observable diffs.
            let result = rib.commit(prepared)
            broadcastRIBDiffs(result.diffs)
            let diagnosticLines = BGPLSUpdateDiagnosticFormatter.lines(
                result.diagnostics, peer: configuration.peer.description, timestamp: Self.logTimestamp()
            )
            if !diagnosticLines.isEmpty {
                FileHandle.standardError.write(Data((diagnosticLines.joined(separator: "\n") + "\n").utf8))
            }
            if logUpdates {
                let line =
                    "bgpls: \(Self.logTimestamp()) RIB \(rib.summaryLine)\n"
                FileHandle.standardError.write(Data(line.utf8))
            }
        case .failure(let error):
            // The handler retains the terminal cause, including while a NOTIFICATION is
            // being written. This observation never resolves the outcome or changes the stop latch.
            let line = BGPLSUpdateDiagnosticFormatter.fatalLine(
                error, peer: configuration.peer.description, timestamp: Self.logTimestamp()
            )
            FileHandle.standardError.write(Data((line + "\n").utf8))
        }
    }

    private func closePcapSink(_ sink: PCAPFileSink?) async {
        guard let sink else { return }
        do {
            try await sink.close()
        } catch {
            FileHandle.standardError.write(
                Data("bgpls: pcap close error: \(error)\n".utf8)
            )
        }
    }

    private func validateConfiguration() throws {
        try configuration.validate()
    }

    private func makeOpenMessage() -> BGPOpenMessage {
        BGPOpenMessage(
            version: 4,
            myAS: BGPOpenCapabilities.legacyAS(for: configuration.localAS),
            holdTime: configuration.holdTimeSeconds,
            //  Speaker identity is explicit; neither IPv4 nor IPv6 transport
            // addresses (especially the remote peer) determine the local BGP identifier.
            bgpIdentifier: configuration.bgpIdentifier.rawValue,
            optionalParameters: BGPOpenCapabilities.bgpLS(localAS: configuration.localAS)
        )
    }

    /// Local wall-clock stamp for stderr logs (ISO-8601 with fractional seconds).
    nonisolated private static func logTimestamp() -> String {
        Date().formatted(.iso8601.dateTimeSeparator(.standard).time(includingFractionalSeconds: true))
    }
}

// MARK: - Event-loop bridges

/// Synchronously owns a channel across the NIO event-loop/actor boundary.
///
/// Registration happens in `channelInitializer`, before a connect future can complete. A stop
/// request is permanent so a channel that races in later is closed instead of being adopted.
final class SessionChannelControl: @unchecked Sendable {
    private let lock = NSLock()
    private var channel: Channel?
    private var stopRequested = false

    var isStopRequested: Bool {
        withLock { stopRequested }
    }

    /// Registers the pending channel, or closes it when stopping has already been requested.
    @discardableResult
    func register(_ candidate: Channel) -> Bool {
        let accepted = withLock {
            guard !stopRequested, channel == nil else { return false }
            channel = candidate
            return true
        }
        if !accepted {
            candidate.close(promise: nil)
        }
        return accepted
    }

    /// Latches the stop request and closes the currently registered channel, if any.
    func requestStop() {
        let channelToClose = withLock {
            stopRequested = true
            defer { channel = nil }
            return channel
        }
        channelToClose?.close(promise: nil)
    }

    /// Releases a specific channel without changing the permanent stop latch.
    func clear(_ candidate: Channel) {
        withLock {
            if channel === candidate {
                channel = nil
            }
        }
    }

    /// Releases whichever channel is registered without changing the permanent stop latch.
    func clear() {
        withLock {
            channel = nil
        }
    }

    private func withLock<Value>(_ body: () throws -> Value) rethrows -> Value {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

/// Owns the one terminal result independently of state progress and transport cleanup.
final class SessionOutcome: Sendable {
    let futureResult: EventLoopFuture<Void>
    private let pending: NIOLoopBoundBox<EventLoopPromise<Void>?>

    init(eventLoop: any EventLoop) {
        let promise = eventLoop.makePromise(of: Void.self)
        self.futureResult = promise.futureResult
        self.pending = .makeBoxSendingValue(promise, eventLoop: eventLoop)
    }

    func complete(_ result: Result<Void, any Error>) {
        if pending.eventLoop.inEventLoop {
            completeOnEventLoop(result)
        } else {
            pending.eventLoop.execute { self.completeOnEventLoop(result) }
        }
    }

    private func completeOnEventLoop(_ result: Result<Void, any Error>) {
        guard let promise = pending.value else { return }
        //  Clear the single shared owner before invoking callbacks. A later close
        // or reentrant completion must never overwrite the original session failure.
        pending.value = nil
        promise.completeWith(result)
    }
}
