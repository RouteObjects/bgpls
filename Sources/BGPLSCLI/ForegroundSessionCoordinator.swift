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

import UnixSignals

/// The reason a foreground session returned normally from its coordinator.
package enum ForegroundSessionTermination: Equatable, Sendable {
    case operationCompleted
    case signal(UnixSignal)
}

/// Coordinates one foreground operation with a stream of process signals.
package enum ForegroundSessionCoordinator {
    private enum Event: Sendable {
        case operationCompleted
        case signal(UnixSignal)
        case signalStreamEnded
    }

    /// Runs `operation` until it completes or the first signal requests an orderly stop.
    package static func run<Signals: AsyncSequence & Sendable>(
        signals: Signals,
        operation: @escaping @Sendable () async throws -> Void,
        onSignal: @escaping @Sendable (UnixSignal) async -> Void = { _ in },
        // This observer makes finite-stream behavior deterministically testable.
        onSignalStreamEnd: @escaping @Sendable () async -> Void = {},
        stop: @escaping @Sendable () async -> Void
    ) async throws -> ForegroundSessionTermination where Signals.Element == UnixSignal {
        try await withThrowingTaskGroup(of: Event.self) { group in
            group.addTask {
                try await operation()
                return .operationCompleted
            }
            group.addTask {
                for try await signal in signals {
                    return .signal(signal)
                }
                return .signalStreamEnded
            }

            while let event = try await group.next() {
                switch event {
                case .operationCompleted:
                    group.cancelAll()
                    // A cancellation handler may finish its operation successfully;
                    // preserve parent cancellation rather than misreporting cleanup as normal exit.
                    try Task.checkCancellation()
                    return .operationCompleted

                case .signal(let signal):
                    await onSignal(signal)
                    await stop()

                    // Wait for operation cleanup after requesting stop so the caller can
                    // safely emit its one final snapshot after all live output has ceased.
                    group.cancelAll()
                    while !group.isEmpty {
                        do {
                            _ = try await group.next()
                        } catch {
                            // The operation commonly reports cancellation or channel closure after
                            // an intentional signal-driven stop. The signal remains authoritative.
                        }
                    }
                    return .signal(signal)

                case .signalStreamEnded:
                    // A platform without functioning signals, or an injected finite test stream,
                    // must not terminate an otherwise healthy foreground operation.
                    await onSignalStreamEnd()
                    continue
                }
            }

            throw CancellationError()
        }
    }
}
