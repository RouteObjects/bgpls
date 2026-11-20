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
import Dispatch
import Foundation
import NIOCore
import NIOEmbedded
import NIOExtras
import NIOPosix
import Synchronization
import Testing

@testable import BGPLSClient

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

struct PCAPCaptureBudgetTests {
    @Test(.timeLimit(.minutes(1)), arguments: [0, -1], [false, true])
    func invalidLimitsFailBeforeCreatingFile(value: Int, chunks: Bool) async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("invalid.pcap")
        let limits = PCAPFileSink.Limits(
            maximumPendingBytes: chunks ? 1 : value, maximumPendingChunks: chunks ? value : 1
        )
        await #expect(throws: PCAPFileSink.Failure.invalidLimits) {
            try await PCAPFileSink.create(path: path.path, limits: limits)
        }
        #expect(!FileManager.default.fileExists(atPath: path.path))
        #expect(PCAPFileSink.Limits().maximumPendingBytes == 8 * 1024 * 1024)
        #expect(PCAPFileSink.Limits().maximumPendingChunks == 4096)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func exactBudgetIncludesActiveWriteAndOverloadDrainsOnlyAcceptedChunks(chunks: Bool) async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("budget.pcap")
        let probe = CaptureWriteProbe()
        defer { probe.release() }
        let failures = Mutex<[PCAPFileSink.Failure]>([])
        let callbackOnEventLoop = Mutex(false)
        let callbackBeforeClose = Mutex(false)
        let loop = MultiThreadedEventLoopGroup.singleton.next()
        let limits = PCAPFileSink.Limits(maximumPendingBytes: chunks ? 64 : 6, maximumPendingChunks: chunks ? 2 : 8)
        let sink = try await PCAPFileSink.create(path: path.path, limits: limits, operations: probe.operations) {
            error in
            callbackOnEventLoop.withLock { $0 = loop.inEventLoop }
            callbackBeforeClose.withLock { $0 = probe.snapshot.closes == 0 }
            if let failure = error as? PCAPFileSink.Failure { failures.withLock { $0.append(failure) } }
        }
        sink.write(buffer: ByteBuffer(bytes: [1, 2, 3]))
        var started = probe.started.makeAsyncIterator()
        _ = try #require(await started.next())
        #expect(sink.pendingCapture == .init(bytes: 3, chunks: 1))
        sink.write(buffer: ByteBuffer(bytes: [4, 5, 6]))
        #expect(sink.pendingCapture == .init(bytes: 6, chunks: 2))

        try await loop.submit { sink.write(buffer: ByteBuffer(bytes: [7])) }.get()
        for _ in 0..<100 { sink.write(buffer: ByteBuffer(bytes: [8, 9])) }
        sink.write(buffer: ByteBuffer())
        #expect(sink.pendingCapture == .init(bytes: 6, chunks: 2))
        #expect(failures.withLock { $0.isEmpty })
        #expect(probe.snapshot.closes == 0)

        probe.release()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<8 { group.addTask { try await sink.close() } }
            try await group.waitForAll()
        }
        #expect(!callbackOnEventLoop.withLock { $0 })
        #expect(callbackBeforeClose.withLock { $0 })
        #expect(
            failures.withLock { $0 }
                == [.captureBudgetExceeded(path: path.path, resource: chunks ? .chunks : .bytes, limit: chunks ? 2 : 6)]
        )
        #expect(sink.pendingCapture == .init(bytes: 0, chunks: 0))
        #expect(probe.snapshot.closes == 1)
        #expect(probe.snapshot.payloadWrites == 2)
        #expect(!probe.snapshot.timedOut)
        #expect(try Data(contentsOf: path) == captureData([1, 2, 3, 4, 5, 6]))
        sink.write(buffer: ByteBuffer(bytes: [10]))
        try await sink.close()
        #expect(probe.snapshot.payloadWrites == 2)
    }

    @Test(.timeLimit(.minutes(1)))
    func oversizedChunkStopsCaptureAndEmptyChunksConsumeNoBudget() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("oversized.pcap")
        let failures = Mutex<[PCAPFileSink.Failure]>([])
        let sink = try await PCAPFileSink.create(
            path: path.path, limits: .init(maximumPendingBytes: 4, maximumPendingChunks: 1)
        ) { error in
            if let failure = error as? PCAPFileSink.Failure { failures.withLock { $0.append(failure) } }
        }
        for _ in 0..<100 { sink.write(buffer: ByteBuffer()) }
        #expect(sink.pendingCapture == .init(bytes: 0, chunks: 0))
        sink.write(buffer: ByteBuffer(bytes: [1, 2, 3, 4, 5]))
        sink.write(buffer: ByteBuffer(bytes: [1]))
        try await sink.close()
        #expect(try Data(contentsOf: path) == captureData([]))
        #expect(failures.withLock { $0 } == [.captureBudgetExceeded(path: path.path, resource: .bytes, limit: 4)])
    }

    @Test(.timeLimit(.minutes(1)))
    func defaultByteBudgetPlateausUnderAControlledSlowWriter() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("default-budget.pcap")
        let probe = CaptureWriteProbe()
        defer { probe.release() }
        let failures = Mutex<[PCAPFileSink.Failure]>([])
        let sink = try await PCAPFileSink.create(path: path.path, operations: probe.operations) { error in
            if let failure = error as? PCAPFileSink.Failure { failures.withLock { $0.append(failure) } }
        }
        let chunk = ByteBuffer(bytes: [UInt8](repeating: 0x5a, count: 4096))
        let admitted = 2048
        let rejected = 10_000
        sink.write(buffer: chunk)
        var started = probe.started.makeAsyncIterator()
        _ = try #require(await started.next())
        for _ in 1..<admitted { sink.write(buffer: chunk) }
        let peak = sink.pendingCapture
        #expect(peak == .init(bytes: 8 * 1024 * 1024, chunks: admitted))
        for _ in 0..<rejected { sink.write(buffer: chunk) }
        #expect(sink.pendingCapture == peak)
        #expect(probe.snapshot.payloadWrites == 1)
        probe.release()
        try await sink.close()
        #expect(sink.pendingCapture == .init(bytes: 0, chunks: 0))
        #expect(probe.snapshot.payloadWrites == admitted)
        #expect(probe.snapshot.closes == 1)
        #expect(!probe.snapshot.timedOut)
        #expect(try Data(contentsOf: path) == captureData([UInt8](repeating: 0x5a, count: peak.bytes)))
        let expected = PCAPFileSink.Failure.captureBudgetExceeded(
            path: path.path, resource: .bytes, limit: 8 * 1024 * 1024)
        #expect(failures.withLock { $0 } == [expected])
        print(
            "PCAP budget evidence: offered=\(admitted + rejected) chunks, admitted=\(admitted), "
                + "peak=\(peak.bytes) bytes/\(peak.chunks) chunks, accepted-output=\(peak.bytes) bytes"
        )
    }

    @Test(.timeLimit(.minutes(1)))
    func smallSliceUsesIndependentCompactStorage() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("compact.pcap")
        let probe = CaptureWriteProbe()
        defer { probe.release() }
        var original = ByteBufferAllocator().buffer(capacity: 1024 * 1024)
        original.writeBytes([1, 2, 3])
        let slice = try #require(original.getSlice(at: 0, length: 3))
        let sourceAddress = slice.withUnsafeReadableBytes { UInt(bitPattern: $0.baseAddress) }
        let sink = try await PCAPFileSink.create(
            path: path.path, limits: .init(maximumPendingBytes: 4, maximumPendingChunks: 2),
            operations: probe.operations
        )
        sink.write(buffer: slice)
        var started = probe.started.makeAsyncIterator()
        _ = try #require(await started.next())
        sink.write(buffer: ByteBuffer(bytes: [4]))
        #expect(sink.pendingCapture == .init(bytes: 4, chunks: 2))
        probe.release()
        try await sink.close()
        let firstAddress = try #require(probe.snapshot.payloadAddresses.first)
        #expect(firstAddress != sourceAddress)
        #expect(original.capacity >= 1024 * 1024)
        #expect(Array(slice.readableBytesView) == [1, 2, 3])
        #expect(try Data(contentsOf: path) == captureData([1, 2, 3, 4]))
        #expect(!probe.snapshot.timedOut)
    }

    @Test(.timeLimit(.minutes(1)))
    func finishedWriteReturnsCapacityBeforeTheNextAdmission() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("reuse.pcap")
        let probe = CaptureWriteProbe(gatedPayload: 2)
        defer { probe.release() }
        let failures = Mutex(0)
        let sink = try await PCAPFileSink.create(
            path: path.path, limits: .init(maximumPendingBytes: 2, maximumPendingChunks: 2),
            operations: probe.operations
        ) { _ in failures.withLock { $0 += 1 } }
        sink.write(buffer: ByteBuffer(bytes: [1]))
        sink.write(buffer: ByteBuffer(bytes: [2]))
        var started = probe.started.makeAsyncIterator()
        _ = try #require(await started.next())
        // The second write cannot start until the first write has released its credits.
        #expect(sink.pendingCapture == .init(bytes: 1, chunks: 1))
        sink.write(buffer: ByteBuffer(bytes: [3]))
        #expect(sink.pendingCapture == .init(bytes: 2, chunks: 2))
        probe.release()
        try await sink.close()
        #expect(failures.withLock { $0 } == 0)
        #expect(try Data(contentsOf: path) == captureData([1, 2, 3]))
        #expect(sink.pendingCapture == .init(bytes: 0, chunks: 0))
        #expect(!probe.snapshot.timedOut)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func overloadAndWriteFailurePreserveFirstFailureAndReleaseCredits(overloadFirst: Bool) async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("failure.pcap")
        let probe = CaptureWriteProbe(failGatedWrite: true)
        defer { probe.release() }
        let (reported, reportedContinuation) = AsyncStream.makeStream(of: PCAPFileSink.Failure.self)
        defer { reportedContinuation.finish() }
        let failures = Mutex<[PCAPFileSink.Failure]>([])
        let sink = try await PCAPFileSink.create(
            path: path.path, limits: .init(maximumPendingBytes: 2, maximumPendingChunks: 2),
            operations: probe.operations
        ) { error in
            if let failure = error as? PCAPFileSink.Failure {
                failures.withLock { $0.append(failure) }
                reportedContinuation.yield(failure)
            }
        }
        sink.write(buffer: ByteBuffer(bytes: [1, 2]))
        var started = probe.started.makeAsyncIterator()
        _ = try #require(await started.next())
        if overloadFirst { sink.write(buffer: ByteBuffer(bytes: [3])) }
        probe.release()
        var reportIterator = reported.makeAsyncIterator()
        _ = try #require(await reportIterator.next())
        for _ in 0..<100 { sink.write(buffer: ByteBuffer(bytes: [4, 5, 6])) }
        try await sink.close()
        let expected: PCAPFileSink.Failure =
            overloadFirst
            ? .captureBudgetExceeded(path: path.path, resource: .bytes, limit: 2)
            : .systemCall(operation: "write", code: ENOSPC)
        #expect(failures.withLock { $0 } == [expected])
        #expect(sink.pendingCapture == .init(bytes: 0, chunks: 0))
        #expect(probe.snapshot.payloadWrites == 1)
        #expect(probe.snapshot.closes == 1)
        #expect(!probe.snapshot.timedOut)
        #expect(try Data(contentsOf: path) == captureData([]))
    }

    @Test(.timeLimit(.minutes(1)))
    func overloadCloseFailureIsSharedWithoutRetryingDescriptorClose() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("close.pcap")
        let probe = CaptureWriteProbe(failClose: true)
        defer { probe.release() }
        let failures = Mutex(0)
        let sink = try await PCAPFileSink.create(
            path: path.path, limits: .init(maximumPendingBytes: 1, maximumPendingChunks: 1),
            operations: probe.operations
        ) { _ in failures.withLock { $0 += 1 } }
        sink.write(buffer: ByteBuffer(bytes: [1]))
        var started = probe.started.makeAsyncIterator()
        _ = try #require(await started.next())
        sink.write(buffer: ByteBuffer(bytes: [2]))
        probe.release()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    await #expect(throws: PCAPFileSink.Failure.systemCall(operation: "close", code: EINTR)) {
                        try await sink.close()
                    }
                }
            }
        }
        #expect(failures.withLock { $0 } == 1)
        #expect(probe.snapshot.closes == 1)
        #expect(sink.pendingCapture == .init(bytes: 0, chunks: 0))
        #expect(try Data(contentsOf: path) == captureData([1]))
    }

    @Test(.timeLimit(.minutes(1)))
    func overloadPreservesCompletePCAPRecordsBeforeTheCutoff() async throws {
        let chunks = try encodedCaptureChunks()
        try #require(chunks.count >= 3)
        let accepted = Array(chunks.prefix(2))
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("framing.pcap")
        let probe = CaptureWriteProbe()
        defer { probe.release() }
        let sink = try await PCAPFileSink.create(
            path: path.path,
            limits: .init(maximumPendingBytes: accepted.reduce(0) { $0 + $1.readableBytes }, maximumPendingChunks: 2),
            operations: probe.operations
        )
        sink.write(buffer: accepted[0])
        var started = probe.started.makeAsyncIterator()
        _ = try #require(await started.next())
        sink.write(buffer: accepted[1])
        for chunk in chunks.dropFirst(2) { sink.write(buffer: chunk) }
        probe.release()
        try await sink.close()
        let bytes = try Data(contentsOf: path)
        #expect(bytes == captureData(accepted.flatMap { Array($0.readableBytesView) }))
        let records = try captureRecordCount(bytes)
        #expect(records >= 4)
        #expect(!probe.snapshot.timedOut)
    }

    @Test
    func overloadDiagnosticEscapesTheCapturePath() {
        let failure = PCAPFileSink.Failure.captureBudgetExceeded(
            path: "capture\n\u{1b}[31m.pcap", resource: .bytes, limit: 8
        )
        #expect(!failure.description.contains("\n"))
        #expect(!failure.description.contains("\u{1b}"))
        #expect(failure.description.contains("incomplete"))
        #expect(failure.description.contains("BGP collection continues"))
        #expect(failure.description.contains("8"))
    }

    enum Termination: CaseIterable, Sendable, Equatable { case normal, stop, cancel }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true], Termination.allCases)
    func overloadedCaptureDoesNotStopTopologyOrShutdown(ipv6: Bool, termination: Termination) async throws {
        if ipv6 {
            try await expectSessionSurvivesOverload(loopback: #require(IPv6Address("::1")), termination: termination)
        } else {
            try await expectSessionSurvivesOverload(
                loopback: #require(IPv4Address("127.0.0.1")), termination: termination)
        }
    }

    private func expectSessionSurvivesOverload<Family: IPAddressFamily>(
        loopback: IPAddress<Family>, termination: Termination
    ) async throws {
        let (accepted, acceptedContinuation) = AsyncStream.makeStream(of: Channel.self)
        let (states, stateContinuation) = AsyncStream.makeStream(of: BGPSessionState.self)
        let (raw, rawContinuation) = AsyncStream.makeStream(of: ByteBuffer.self)
        let (sinks, sinkContinuation) = AsyncStream.makeStream(of: PCAPFileSink.self)
        let (failures, failureContinuation) = AsyncStream.makeStream(of: PCAPFileSink.Failure.self)
        defer {
            acceptedContinuation.finish()
            stateContinuation.finish()
            rawContinuation.finish()
            sinkContinuation.finish()
            failureContinuation.finish()
        }
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                acceptedContinuation.yield(channel)
                return channel.eventLoop.makeSucceededVoidFuture()
            }
            .bind(to: SocketAddress(ipAddress: loopback.addressLiteral, port: 0)).get()
        defer { server.close(promise: nil) }
        let port = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("session.pcap")
        let probe = CaptureWriteProbe()
        defer { probe.release() }
        let failureCount = Mutex(0)
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: port),
                localAS: AutonomousSystemNumber(65001), peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")), connectTimeout: .seconds(5)
            ),
            pcapSinkFactory: { path, onError in
                let sink = try await PCAPFileSink.create(
                    path: path, limits: .init(maximumPendingBytes: 8192, maximumPendingChunks: 1),
                    operations: probe.operations
                ) { error in
                    failureCount.withLock { $0 += 1 }
                    if let failure = error as? PCAPFileSink.Failure { failureContinuation.yield(failure) }
                    onError(error)
                }
                sinkContinuation.yield(sink)
                return sink
            }
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let watcher = Task {
            var events: [RIBDiff] = []
            for await event in changes { events.append(event) }
            return events
        }
        defer { watcher.cancel() }
        let runner = Task {
            try await session.run(
                pcapPath: path.path, onUpdate: { rawContinuation.yield($0) },
                onStateChange: { stateContinuation.yield($0) }
            )
        }
        defer { runner.cancel() }
        let watchdog = Task {
            do { try await Task.sleep(for: .seconds(20)) } catch { return }
            Issue.record("PCAP overload session exceeded its bounded deadline")
            probe.release()
            runner.cancel()
            acceptedContinuation.finish()
            stateContinuation.finish()
            rawContinuation.finish()
            sinkContinuation.finish()
            failureContinuation.finish()
        }
        defer { watchdog.cancel() }

        var sinkIterator = sinks.makeAsyncIterator()
        let sink = try #require(await sinkIterator.next())
        var peerIterator = accepted.makeAsyncIterator()
        let peer = try #require(await peerIterator.next())
        defer { peer.close(promise: nil) }
        var started = probe.started.makeAsyncIterator()
        _ = try #require(await started.next())
        var opening = ByteBuffer()
        try BGPMessageCodec.encode(
            .open(
                BGPOpenMessage(
                    myAS: 65001, holdTime: 0, bgpIdentifier: 0xc000_0201,
                    optionalParameters: BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(65001))
                )), into: &opening
        )
        try BGPMessageCodec.encode(.keepalive, into: &opening)
        try await peer.writeAndFlush(opening).get()
        var stateIterator = states.makeAsyncIterator()
        while let state = await stateIterator.next(), state != .established {}
        #expect(await session.sessionState() == .established)

        let bodies = (1...2).map { value in
            IPv6TopologyFixture.updateBody(
                reachable: true,
                nlris: IPv6TopologyFixture.wire(
                    type: 1, descriptors: [IPv6TopologyFixture.nodeDescriptor(lastByte: UInt8(value))]
                )
            )
        }
        var rawIterator = raw.makeAsyncIterator()
        var first = ByteBuffer()
        try BGPMessageCodec.encode(.update(bodies[0]), into: &first)
        try await peer.writeAndFlush(first).get()
        #expect(await rawIterator.next() == bodies[0])
        #expect(await session.ribSnapshot().nodeCount == 1)
        #expect(probe.snapshot.closes == 0)
        #expect(sink.pendingCapture.chunks == 1)

        probe.release()
        var failureIterator = failures.makeAsyncIterator()
        let failure = try #require(await failureIterator.next())
        #expect(failure == .captureBudgetExceeded(path: path.path, resource: .chunks, limit: 1))
        try await sink.close()
        let capturedBeforeLaterUpdate = try Data(contentsOf: path)
        #expect(try captureRecordCount(capturedBeforeLaterUpdate) == 3)
        #expect(sink.pendingCapture == .init(bytes: 0, chunks: 0))
        #expect(await session.sessionState() == .established)

        var second = ByteBuffer()
        try BGPMessageCodec.encode(.update(bodies[1]), into: &second)
        try await peer.writeAndFlush(second).get()
        #expect(await rawIterator.next() == bodies[1])
        #expect(await session.ribSnapshot().nodeCount == 2)
        switch termination {
        case .normal: try await peer.close().get()
        case .stop: await session.stop()
        case .cancel: runner.cancel()
        }
        if termination == .normal {
            try await runner.value
        } else {
            await #expect(throws: CancellationError.self) { try await runner.value }
        }
        var expected = LSRIB()
        var expectedEvents: [RIBDiff] = []
        for body in bodies { expectedEvents += try expected.apply(update: BGPUpdateParser.parse(body)) }
        #expect(await watcher.value == expectedEvents)
        #expect(await session.ribSnapshot() == expected)
        #expect(await session.sessionState() == .stopped)
        #expect(try Data(contentsOf: path) == capturedBeforeLaterUpdate)
        #expect(probe.snapshot.closes == 1)
        #expect(failureCount.withLock { $0 } == 1)
        #expect(!probe.snapshot.timedOut)
        try await peer.closeFuture.get()
    }

    private func encodedCaptureChunks() throws -> [ByteBuffer] {
        let buffers = Mutex<[ByteBuffer]>([])
        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandler(
            NIOWritePCAPHandler(
                mode: .client,
                fakeLocalAddress: SocketAddress(ipAddress: "192.0.2.1", port: 12000),
                fakeRemoteAddress: SocketAddress(ipAddress: "192.0.2.2", port: 179),
                fileSink: { buffer in buffers.withLock { $0.append(buffer) } }
            )
        )
        try channel.connect(to: SocketAddress(ipAddress: "192.0.2.2", port: 179)).wait()
        var wire = ByteBuffer()
        try BGPMessageCodec.encode(.keepalive, into: &wire)
        _ = try channel.writeInbound(wire)
        let _: ByteBuffer? = try channel.readInbound()
        _ = try channel.finish()
        return buffers.withLock { $0 }
    }

    private func captureRecordCount(_ data: Data) throws -> Int {
        var capture = ByteBuffer(bytes: data)
        let headerValue = capture.readBytes(length: 24)
        let header = try #require(headerValue)
        #expect(header == Array(NIOWritePCAPHandler.pcapFileHeader.readableBytesView))
        var count = 0
        while capture.readableBytes > 0 {
            let timestamp = capture.readSlice(length: 8)
            _ = try #require(timestamp)
            let includedValue = capture.readInteger(endianness: .host, as: UInt32.self)
            let originalValue = capture.readInteger(endianness: .host, as: UInt32.self)
            let included = try #require(includedValue)
            let original = try #require(originalValue)
            #expect(included == original)
            let packetValue = capture.readSlice(length: Int(included))
            var packet = try #require(packetValue)
            let familyValue = packet.readInteger(endianness: .host, as: UInt32.self)
            let family = try #require(familyValue)
            #expect(family == 2 || family == 24)
            let ipHeader = packet.readSlice(length: family == 2 ? 20 : 40)
            _ = try #require(ipHeader)
            let tcpHeader = packet.readSlice(length: 20)
            _ = try #require(tcpHeader)
            count += 1
        }
        return count
    }

    private func captureData(_ bytes: [UInt8]) -> Data {
        Data(Array(NIOWritePCAPHandler.pcapFileHeader.readableBytesView) + bytes)
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("bgpls-pcap-budget-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }
}

private final class CaptureWriteProbe: Sendable {
    struct Snapshot: Sendable {
        var payloadWrites = 0
        var payloadAddresses: [UInt] = []
        var closes = 0
        var timedOut = false
        var headerWritten = false
    }

    let started: AsyncStream<Void>
    private let startedContinuation: AsyncStream<Void>.Continuation
    private let state = Mutex(Snapshot())
    private let gate = DispatchSemaphore(value: 0)
    private let gatedPayload: Int
    private let failGatedWrite: Bool
    private let failClose: Bool

    init(gatedPayload: Int = 1, failGatedWrite: Bool = false, failClose: Bool = false) {
        (started, startedContinuation) = AsyncStream.makeStream(of: Void.self)
        self.gatedPayload = gatedPayload
        self.failGatedWrite = failGatedWrite
        self.failClose = failClose
    }

    var snapshot: Snapshot { state.withLock { $0 } }

    func release() { gate.signal() }

    var operations: PCAPFileSink.Operations {
        var operations = PCAPFileSink.Operations.live
        operations.write = { [self] descriptor, bytes in
            let payload = state.withLock { state in
                guard state.headerWritten else {
                    state.headerWritten = true
                    return 0
                }
                state.payloadWrites += 1
                state.payloadAddresses.append(UInt(bitPattern: bytes.baseAddress))
                return state.payloadWrites
            }
            if payload == gatedPayload {
                startedContinuation.yield(())
                // Only the injected file syscall waits, with guaranteed release and a finite bound.
                if gate.wait(timeout: .now() + 10) == .timedOut { state.withLock { $0.timedOut = true } }
                if failGatedWrite { return .init(value: -1, errorCode: ENOSPC) }
            }
            return PCAPFileSink.Operations.live.write(descriptor, bytes)
        }
        operations.close = { [self] descriptor in
            state.withLock { $0.closes += 1 }
            let result = PCAPFileSink.Operations.live.close(descriptor)
            return failClose ? .init(value: -1, errorCode: EINTR) : result
        }
        return operations
    }

    deinit { startedContinuation.finish() }
}
