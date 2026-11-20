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

import Dispatch
import Foundation
import NIOCore
import NIOExtras
import Synchronization
import Testing

@testable import BGPLSClient

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

struct PCAPFileSinkTests {
    @Test(.timeLimit(.minutes(1)))
    func shortInterruptedWritesPreserveHeaderAndPayloadAndCloseOnExec() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("capture.pcap")
        let calls = Mutex(0)
        let descriptorFlags = Mutex<[CInt]>([])
        var operations = PCAPFileSink.Operations.live
        operations.write = { descriptor, bytes in
            descriptorFlags.withLock { $0.append(fcntl(descriptor, F_GETFD)) }
            let call = calls.withLock {
                $0 += 1
                return $0
            }
            if call == 1 { return .init(value: -1, errorCode: EINTR) }
            return PCAPFileSink.Operations.live.write(
                descriptor, UnsafeRawBufferPointer(rebasing: bytes.prefix(3))
            )
        }
        let sink = try await PCAPFileSink.create(path: path.path, operations: operations)
        let payload = ByteBuffer(bytes: [1, 2, 3, 4, 5, 6, 7])
        sink.write(buffer: payload)
        try await sink.close()
        let expected = Array(NIOWritePCAPHandler.pcapFileHeader.readableBytesView) + Array(payload.readableBytesView)
        #expect(try Data(contentsOf: path) == Data(expected))
        #expect(calls.withLock { $0 } > 2)
        #expect(descriptorFlags.withLock { $0.allSatisfy { $0 >= 0 && $0 & FD_CLOEXEC != 0 } })
    }

    @Test(.timeLimit(.minutes(1)), arguments: [true, false])
    func headerFailureClosesExactlyOnceAndRetainsPartialEvidence(zeroProgress: Bool) async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("capture.pcap")
        let closes = Mutex(0)
        let calls = Mutex(0)
        var operations = PCAPFileSink.Operations.live
        operations.write = { descriptor, bytes in
            let call = calls.withLock {
                $0 += 1
                return $0
            }
            if call == 1 {
                return PCAPFileSink.Operations.live.write(descriptor, UnsafeRawBufferPointer(rebasing: bytes.prefix(4)))
            }
            return .init(value: zeroProgress ? 0 : -1, errorCode: zeroProgress ? 0 : ENOSPC)
        }
        operations.close = { descriptor in
            closes.withLock { $0 += 1 }
            return PCAPFileSink.Operations.live.close(descriptor)
        }
        let expected: PCAPFileSink.Failure =
            zeroProgress ? .writeMadeNoProgress : .systemCall(operation: "write", code: ENOSPC)
        await #expect(throws: expected) {
            try await PCAPFileSink.create(path: path.path, operations: operations)
        }
        #expect(closes.withLock { $0 } == 1)
        #expect(try Data(contentsOf: path) == Data(NIOWritePCAPHandler.pcapFileHeader.readableBytesView.prefix(4)))
    }

    @Test(.timeLimit(.minutes(1)))
    func createPermissionFailureDoesNotCreateAFile() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("capture.pcap")
        var operations = PCAPFileSink.Operations.live
        operations.createFile = { _, _ in throw PCAPFileSink.Failure.systemCall(operation: "create", code: EACCES) }
        await #expect(throws: PCAPFileSink.Failure.systemCall(operation: "create", code: EACCES)) {
            try await PCAPFileSink.create(path: path.path, operations: operations)
        }
        #expect(!FileManager.default.fileExists(atPath: path.path))
    }

    @Test(.timeLimit(.minutes(1)))
    func nonRegularDescriptorIsRejectedAndClosed() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let closes = Mutex(0)
        var operations = PCAPFileSink.Operations.live
        operations.createFile = { parent, _ in
            let descriptor = dup(parent)
            guard descriptor >= 0 else { throw PCAPFileSink.Failure.systemCall(operation: "dup", code: errno) }
            return descriptor
        }
        operations.close = { descriptor in
            closes.withLock { $0 += 1 }
            return PCAPFileSink.Operations.live.close(descriptor)
        }
        await #expect(throws: PCAPFileSink.Failure.notRegularFile) {
            try await PCAPFileSink.create(
                path: directory.appendingPathComponent("capture.pcap").path, operations: operations)
        }
        #expect(closes.withLock { $0 } == 1)
    }

    @Test(.timeLimit(.minutes(1)))
    func midstreamFailureReportsOnceAndCloseStillDrains() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("capture.pcap")
        let writes = Mutex(0)
        let errors = Mutex<[PCAPFileSink.Failure]>([])
        let closes = Mutex(0)
        var operations = PCAPFileSink.Operations.live
        operations.write = { descriptor, bytes in
            let count = writes.withLock {
                $0 += 1
                return $0
            }
            if count > 1 { return .init(value: -1, errorCode: ENOSPC) }
            return PCAPFileSink.Operations.live.write(descriptor, bytes)
        }
        operations.close = { descriptor in
            closes.withLock { $0 += 1 }
            return PCAPFileSink.Operations.live.close(descriptor)
        }
        let sink = try await PCAPFileSink.create(path: path.path, operations: operations) { error in
            if let failure = error as? PCAPFileSink.Failure { errors.withLock { $0.append(failure) } }
        }
        sink.write(buffer: ByteBuffer(bytes: [1]))
        sink.write(buffer: ByteBuffer(bytes: [2]))
        try await sink.close()
        try await sink.close()
        sink.write(buffer: ByteBuffer(bytes: [3]))
        try await sink.close()
        #expect(writes.withLock { $0 } == 2)
        #expect(errors.withLock { $0 } == [.systemCall(operation: "write", code: ENOSPC)])
        #expect(closes.withLock { $0 } == 1)
        #expect(try Data(contentsOf: path) == Data(NIOWritePCAPHandler.pcapFileHeader.readableBytesView))
    }

    @Test(.timeLimit(.minutes(1)))
    func slowWriteDoesNotHoldAdmissionLockAndConcurrentCloseDrainsInOrder() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("capture.pcap")
        let gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        let (started, continuation) = AsyncStream.makeStream(of: Void.self)
        defer { continuation.finish() }
        let timedOut = Mutex(false)
        let closes = Mutex(0)
        var operations = PCAPFileSink.Operations.live
        operations.write = { descriptor, bytes in
            if bytes.count == 1, bytes.first == 1 {
                continuation.yield(())
                // A bounded syscall substitute, not a real callback or arbitrary sleep.
                if gate.wait(timeout: .now() + 5) == .timedOut { timedOut.withLock { $0 = true } }
            }
            return PCAPFileSink.Operations.live.write(descriptor, bytes)
        }
        operations.close = { descriptor in
            closes.withLock { $0 += 1 }
            return PCAPFileSink.Operations.live.close(descriptor)
        }
        let sink = try await PCAPFileSink.create(path: path.path, operations: operations)
        sink.write(buffer: ByteBuffer(bytes: [1]))
        var iterator = started.makeAsyncIterator()
        let first: Void? = await iterator.next()
        try #require(first != nil)
        sink.write(buffer: ByteBuffer(bytes: [2]))
        #expect(closes.withLock { $0 } == 0)
        gate.signal()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<8 { group.addTask { try await sink.close() } }
            try await group.waitForAll()
        }
        #expect(!timedOut.withLock { $0 })
        #expect(closes.withLock { $0 } == 1)
        let expected = Array(NIOWritePCAPHandler.pcapFileHeader.readableBytesView) + [1, 2]
        #expect(try Data(contentsOf: path) == Data(expected))
    }

    @Test(.timeLimit(.minutes(1)))
    func closeErrorIsSharedAndNotRetried() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let closes = Mutex(0)
        var operations = PCAPFileSink.Operations.live
        operations.close = { descriptor in
            closes.withLock { $0 += 1 }
            _ = PCAPFileSink.Operations.live.close(descriptor)
            return .init(value: -1, errorCode: EINTR)
        }
        let sink = try await PCAPFileSink.create(
            path: directory.appendingPathComponent("capture.pcap").path, operations: operations
        )
        for _ in 0..<3 {
            await #expect(throws: PCAPFileSink.Failure.systemCall(operation: "close", code: EINTR)) {
                try await sink.close()
            }
        }
        #expect(closes.withLock { $0 } == 1)
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("bgpls-pcap-io-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }
}
