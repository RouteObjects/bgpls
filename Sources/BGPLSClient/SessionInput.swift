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

/// Ordered application observations; protocol decisions stay on the event loop.
enum SessionInput: Sendable {
    case state(BGPSessionState)
    case update(BGPLSUpdateObservation)
}

/// Experimental settings, deliberately not public tuning knobs.
enum SessionInputSettings {
    static let lowWatermark = 8
    static let highWatermark = 64
    static let receiveBufferSize = 4096
    static let pendingUpdateLimit = 1024
}

/// Credits include preparation, the native read batch/queue, and the active actor call.
/// This owner outlives pipeline removal so draining observations can still return credits.
final class SessionInputAdmission: Sendable {
    private struct State: Sendable {
        var pending = 0
        var closed = false
    }

    let limit: Int
    private let state: NIOLoopBoundBox<State>

    init(eventLoop: any EventLoop, limit: Int = SessionInputSettings.pendingUpdateLimit) {
        precondition(limit > 0)
        self.limit = limit
        state = .makeBoxSendingValue(State(), eventLoop: eventLoop)
    }

    var pendingCount: Int { state.value.pending }

    var capacityError: BGPLSClientError {
        .sessionFailed("pending UPDATE capacity exceeded (limit: \(limit)); unadmitted input creates a collection gap")
    }

    func reserve() -> Bool {
        guard !state.value.closed, state.value.pending < limit else { return false }
        state.value.pending += 1
        return true
    }

    func close() {
        state.value.closed = true
    }

    func releaseOnEventLoop() {
        precondition(state.value.pending > 0, "Each admitted UPDATE owns exactly one credit")
        state.value.pending -= 1
    }

    func release() async {
        // Await feedback before asking the native iterator for more work. A separate
        // fire-and-forget acknowledgment queue would hide outstanding observations.
        await withCheckedContinuation { continuation in
            state.eventLoop.execute {
                self.releaseOnEventLoop()
                continuation.resume()
            }
        }
    }
}

/// One owned consumer drains normally after transport closure, even when run() is cancelled.
/// Cancelling its iterator instead would discard observations already admitted by NIO.
final class SessionInputConsumer: Sendable {
    /// Internal construction seam for lifecycle tests; production uses the direct initializer.
    typealias Factory =
        @Sendable (
            NIOAsyncChannel<SessionInput, Never>, SessionInputAdmission, SessionOutcome,
            @escaping @Sendable (SessionInput) async -> Void
        ) -> SessionInputConsumer

    let channel: any Channel
    private let task: Task<Void, Never>

    init(
        channel: NIOAsyncChannel<SessionInput, Never>,
        admission: SessionInputAdmission,
        outcome: SessionOutcome,
        handler: @escaping @Sendable (SessionInput) async -> Void
    ) {
        self.channel = channel.channel
        task = Task {
            do {
                try await channel.executeThenClose { inbound in
                    do {
                        for try await input in inbound {
                            await handler(input)
                            if case .update = input {
                                await admission.release()
                            }
                        }
                    } catch {
                        // Publish an unexpected bridge failure before executeThenClose
                        // closes transport and channelInactive can select ordinary success.
                        outcome.complete(.failure(error))
                        throw error
                    }
                }
            } catch {
                outcome.complete(.failure(error))
            }
        }
    }

    func finish() async {
        await task.value
    }
}
