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
import NIOCore
import NIOExtras
import Synchronization

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// Owns a newly created capture descriptor. The queue performs I/O; the lock only
/// orders admission and closure. The containing directory must be trusted.
final class PCAPFileSink: Sendable {
    struct Limits: Sendable {
        var maximumPendingBytes: Int = 8 * 1024 * 1024
        var maximumPendingChunks: Int = 4096
    }

    enum BudgetResource: String, Sendable {
        case bytes
        case chunks
    }

    struct PendingCapture: Sendable, Equatable {
        let bytes: Int
        let chunks: Int
    }

    typealias Factory = @Sendable (String, @escaping @Sendable (any Error) -> Void) async throws -> PCAPFileSink

    static let liveFactory: Factory = { path, onError in
        try await create(path: path, onError: onError)
    }

    enum Failure: Error, Sendable, Equatable, CustomStringConvertible {
        case invalidPath
        case invalidLimits
        case systemCall(operation: String, code: CInt)
        case notRegularFile
        case writeMadeNoProgress
        case captureBudgetExceeded(path: String, resource: BudgetResource, limit: Int)

        var description: String {
            switch self {
            case .invalidPath:
                "PCAP output must name a new file; empty, NUL-containing, and directory paths are invalid"
            case .invalidLimits:
                "PCAP pending byte and chunk limits must be positive"
            case .systemCall(operation: "create", code: EEXIST):
                "PCAP output already exists; choose a new capture filename"
            case .systemCall(let operation, let code):
                "PCAP \(operation) failed (errno \(code))"
            case .notRegularFile:
                "PCAP output must be a regular file"
            case .writeMadeNoProgress:
                "PCAP write made no progress"
            case .captureBudgetExceeded(let path, let resource, let limit):
                "PCAP capture stopped for \(String(reflecting: path)): pending \(resource.rawValue) limit exceeded "
                    + "(\(limit)); capture is incomplete; BGP collection continues"
            }
        }
    }

    /// Captures errno at the syscall boundary, before logging or another syscall.
    struct SystemCallResult: Sendable {
        let value: Int
        let errorCode: CInt
    }

    /// Internal syscall seams allow deterministic failure tests without changing
    /// process-wide limits, signals, permissions, or the filesystem implementation.
    struct Operations: Sendable {
        var createFile: @Sendable (CInt, String) throws -> CInt
        var write: @Sendable (CInt, UnsafeRawBufferPointer) -> SystemCallResult
        var close: @Sendable (CInt) -> SystemCallResult

        static let live = Operations(
            createFile: { directory, name in
                let descriptor = name.withCString {
                    openat(directory, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
                }
                guard descriptor >= 0 else {
                    throw Failure.systemCall(operation: "create", code: errno)
                }
                return descriptor
            },
            write: { descriptor, bytes in
                #if canImport(Darwin)
                    let count = Darwin.write(descriptor, bytes.baseAddress, bytes.count)
                #else
                    let count = Glibc.write(descriptor, bytes.baseAddress, bytes.count)
                #endif
                return SystemCallResult(value: count, errorCode: count < 0 ? errno : 0)
            },
            close: { descriptor in
                #if canImport(Darwin)
                    let result = Darwin.close(descriptor)
                #else
                    let result = Glibc.close(descriptor)
                #endif
                return SystemCallResult(value: Int(result), errorCode: result < 0 ? errno : 0)
            }
        )
    }

    private enum Phase {
        case accepting
        case closing
        case closed(Result<Void, Failure>)
    }

    private struct State {
        var descriptor: CInt?
        var phase: Phase = .accepting
        var writeFailed = false
        var failureSelected = false
        var pendingBytes = 0
        var pendingChunks = 0
        var closeWaiters: [CheckedContinuation<Void, any Error>] = []
    }

    private let state: Mutex<State>
    private let queue: DispatchQueue
    private let operations: Operations
    private let onError: @Sendable (any Error) -> Void
    private let path: String
    private let limits: Limits

    var pendingCapture: PendingCapture {
        state.withLock { PendingCapture(bytes: $0.pendingBytes, chunks: $0.pendingChunks) }
    }

    private init(
        descriptor: CInt, queue: DispatchQueue, operations: Operations, path: String, limits: Limits,
        onError: @escaping @Sendable (any Error) -> Void
    ) {
        self.state = Mutex(State(descriptor: descriptor))
        self.queue = queue
        self.operations = operations
        self.onError = onError
        self.path = path
        self.limits = limits
    }

    /// Header creation also runs off the actor/event loop and must succeed before
    /// the session can connect. Failures retain a partial new file as evidence.
    static func create(
        path: String, limits: Limits = Limits(), operations: Operations = .live,
        onError: @escaping @Sendable (any Error) -> Void = { _ in }
    ) async throws -> PCAPFileSink {
        guard limits.maximumPendingBytes > 0, limits.maximumPendingChunks > 0 else { throw Failure.invalidLimits }
        let (parent, name) = try splitPath(path)
        let queue = DispatchQueue(label: "io.routeobjects.bgpls.pcap")
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    // Pin the parent once and create exclusively; never check
                    // existence then reopen a pathname that may have been substituted.
                    let directory = parent.withCString { open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC) }
                    guard directory >= 0 else {
                        throw Failure.systemCall(operation: "open parent directory", code: errno)
                    }
                    defer { _ = Operations.live.close(directory) }
                    let descriptor = try operations.createFile(directory, name)
                    do {
                        var metadata = stat()
                        guard fstat(descriptor, &metadata) == 0 else {
                            throw Failure.systemCall(operation: "inspect", code: errno)
                        }
                        guard metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
                            throw Failure.notRegularFile
                        }
                        try writeAll(NIOWritePCAPHandler.pcapFileHeader, descriptor: descriptor, operations: operations)
                    } catch {
                        // Do not unlink the name: another process might have replaced it.
                        _ = operations.close(descriptor)
                        throw error
                    }
                    continuation.resume(
                        returning: PCAPFileSink(
                            descriptor: descriptor, queue: queue, operations: operations,
                            path: path, limits: limits, onError: onError
                        )
                    )
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private static func splitPath(_ path: String) throws -> (parent: String, name: String) {
        guard !path.isEmpty, !path.utf8.contains(0), !path.hasSuffix("/") else { throw Failure.invalidPath }
        let parent: String
        let name: String
        if let slash = path.lastIndex(of: "/") {
            parent = slash == path.startIndex ? "/" : String(path[..<slash])
            name = String(path[path.index(after: slash)...])
        } else {
            parent = "."
            name = path
        }
        guard name != ".", name != ".." else { throw Failure.invalidPath }
        return (parent, name)
    }

    func write(buffer: ByteBuffer) {
        let count = buffer.readableBytes
        guard count > 0 else { return }
        state.withLock { state in
            guard case .accepting = state.phase, !state.writeFailed else { return }
            let failure: Failure?
            if count > limits.maximumPendingBytes - state.pendingBytes {
                failure = .captureBudgetExceeded(path: path, resource: .bytes, limit: limits.maximumPendingBytes)
            } else if state.pendingChunks >= limits.maximumPendingChunks {
                failure = .captureBudgetExceeded(path: path, resource: .chunks, limit: limits.maximumPendingChunks)
            } else {
                failure = nil
            }
            if let failure {
                // Stop capture admission without failing BGP or discarding accepted chunks.
                // The queue orders the diagnostic and automatic close after that accepted prefix.
                state.failureSelected = true
                state.phase = .closing
                queue.async { self.onError(failure) }
                queue.async { self.finishClose() }
                return
            }
            state.pendingBytes += count
            state.pendingChunks += 1
            // A readable ByteBuffer slice can retain much larger backing storage.
            // Reserve, copy, and enqueue together so close cannot overtake an admitted chunk.
            // This counts encoded bytes, excluding allocator and Dispatch metadata overhead.
            let bytes = Array(buffer.readableBytesView)
            queue.async { self.performWrite(bytes) }
        }
    }

    private func performWrite(_ bytes: [UInt8]) {
        defer {
            state.withLock { state in
                state.pendingBytes -= bytes.count
                state.pendingChunks -= 1
            }
        }
        let descriptor = state.withLock { $0.writeFailed ? nil : $0.descriptor }
        guard let descriptor else { return }
        do {
            try bytes.withUnsafeBytes { try Self.writeAll($0, descriptor: descriptor, operations: operations) }
        } catch {
            let report = state.withLock { state in
                state.writeFailed = true
                guard !state.failureSelected else { return false }
                state.failureSelected = true
                return true
            }
            // Preserve best-effort capture semantics: report once, discard later
            // capture writes, and let the BGP session keep collecting.
            if report { onError(error) }
        }
    }

    private static func writeAll(_ buffer: ByteBuffer, descriptor: CInt, operations: Operations) throws {
        try buffer.withUnsafeReadableBytes { bytes in
            try writeAll(bytes, descriptor: descriptor, operations: operations)
        }
    }

    private static func writeAll(_ bytes: UnsafeRawBufferPointer, descriptor: CInt, operations: Operations) throws {
        var offset = 0
        while offset < bytes.count {
            let remaining = UnsafeRawBufferPointer(rebasing: bytes[offset...])
            let result = operations.write(descriptor, remaining)
            if result.value < 0 {
                if result.errorCode == EINTR { continue }
                throw Failure.systemCall(operation: "write", code: result.errorCode)
            }
            guard result.value > 0, result.value <= remaining.count else { throw Failure.writeMadeNoProgress }
            offset += result.value
        }
    }

    /// Drains all admitted buffers before closing once. Concurrent/repeated callers
    /// observe the same close result; write-error policy remains independent.
    func close() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let completed: Result<Void, Failure>? = state.withLock { state in
                switch state.phase {
                case .accepting:
                    state.phase = .closing
                    state.closeWaiters.append(continuation)
                    queue.async { self.finishClose() }
                    return nil
                case .closing:
                    state.closeWaiters.append(continuation)
                    return nil
                case .closed(let result):
                    return result
                }
            }
            if let completed { continuation.resume(with: completed.mapError { $0 as any Error }) }
        }
    }

    private func finishClose() {
        let descriptor = state.withLock { state in
            defer { state.descriptor = nil }
            return state.descriptor
        }
        let result: Result<Void, Failure>
        if let descriptor {
            let closed = operations.close(descriptor)
            // Retrying close after EINTR can close a reused descriptor on some systems.
            result =
                closed.value == 0 ? .success(()) : .failure(.systemCall(operation: "close", code: closed.errorCode))
        } else {
            result = .success(())
        }
        let waiters = state.withLock { state in
            state.phase = .closed(result)
            defer { state.closeWaiters.removeAll() }
            return state.closeWaiters
        }
        for waiter in waiters { waiter.resume(with: result.mapError { $0 as any Error }) }
    }

    deinit {
        // Queued work retains self; this is only a final safeguard for an unused sink.
        if let descriptor = state.withLock({ $0.descriptor }) {
            _ = operations.close(descriptor)
        }
    }
}
