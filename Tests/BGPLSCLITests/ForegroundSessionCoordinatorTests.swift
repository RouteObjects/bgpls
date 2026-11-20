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

import BGPLSCLI
import Testing
import UnixSignals

struct ForegroundSessionCoordinatorTests {
    @Test
    func operationCompletionWinsWithoutStopping() async throws {
        let (signals, continuation) = AsyncStream.makeStream(of: UnixSignal.self)
        let probe = CoordinatorProbe()

        let result = try await ForegroundSessionCoordinator.run(
            signals: signals,
            operation: {},
            stop: { await probe.recordStop() }
        )
        continuation.finish()

        #expect(result == .operationCompleted)
        #expect(await probe.stopCount == 0)
    }

    @Test
    func sigintStopsOnceAndWaitsForOperationCleanup() async throws {
        let result = try await runSignalledSession(
            signalsToSend: [.sigint, .sigterm]
        )

        #expect(result.termination == .signal(.sigint))
        #expect(result.stopCount == 1)
        #expect(result.observedSignals == [.sigint])
        #expect(result.operationFinished)
    }

    @Test
    func sigtermStopsOnceAndWaitsForOperationCleanup() async throws {
        let result = try await runSignalledSession(
            signalsToSend: [.sigterm]
        )

        #expect(result.termination == .signal(.sigterm))
        #expect(result.stopCount == 1)
        #expect(result.observedSignals == [.sigterm])
        #expect(result.operationFinished)
    }

    @Test
    func signalStreamEndingDoesNotStopOperation() async throws {
        let (signals, signalContinuation) = AsyncStream.makeStream(of: UnixSignal.self)
        let (release, releaseContinuation) = AsyncStream.makeStream(of: Void.self)
        let probe = CoordinatorProbe()

        let task = Task {
            try await ForegroundSessionCoordinator.run(
                signals: signals,
                operation: {
                    await probe.markOperationStarted()
                    for await _ in release { break }
                    await probe.markOperationFinished()
                },
                onSignalStreamEnd: { await probe.markSignalStreamEnded() },
                stop: { await probe.recordStop() }
            )
        }

        await probe.waitUntilOperationStarted()
        signalContinuation.finish()
        await probe.waitUntilSignalStreamEnded()

        #expect(await probe.stopCount == 0)
        #expect(!(await probe.operationFinished))

        releaseContinuation.yield(())
        releaseContinuation.finish()

        #expect(try await task.value == .operationCompleted)
        #expect(await probe.stopCount == 0)
        #expect(await probe.operationFinished)
    }

    @Test
    func operationErrorPropagates() async {
        let (signals, continuation) = AsyncStream.makeStream(of: UnixSignal.self)

        do {
            _ = try await ForegroundSessionCoordinator.run(
                signals: signals,
                operation: { throw ExpectedError.failed },
                stop: {}
            )
            Issue.record("Expected operation error to propagate")
        } catch let error as ExpectedError {
            #expect(error == .failed)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        continuation.finish()
    }

    @Test
    func parentCancellationCannotBecomeNormalCompletion() async {
        let (signals, continuation) = AsyncStream.makeStream(of: UnixSignal.self)
        let probe = CoordinatorProbe()

        let task = Task {
            try await ForegroundSessionCoordinator.run(
                signals: signals,
                operation: { await cancellationSwallowingOperation(probe: probe) },
                stop: { await probe.recordStop() }
            )
        }

        await probe.waitUntilOperationStarted()
        task.cancel()

        do {
            _ = try await task.value
            Issue.record("Expected parent cancellation to propagate")
        } catch is CancellationError {
            // Expected.
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        continuation.finish()
        #expect(await probe.operationFinished)
        #expect(await probe.stopCount == 0)
    }

    @Test
    func shellExitCodesFollowSignalConvention() {
        #expect(BGPLSCommand.RunCommand.shellExitCode(for: .sigint)?.rawValue == 130)
        #expect(BGPLSCommand.RunCommand.shellExitCode(for: .sigterm)?.rawValue == 143)
        #expect(BGPLSCommand.RunCommand.shellExitCode(for: .sighup) == nil)
    }

    private func runSignalledSession(
        signalsToSend: [UnixSignal]
    ) async throws -> SignalledSessionResult {
        let (signals, continuation) = AsyncStream.makeStream(of: UnixSignal.self)
        let probe = CoordinatorProbe()

        let task = Task {
            try await ForegroundSessionCoordinator.run(
                signals: signals,
                operation: { try await cancellationAwareOperation(probe: probe) },
                onSignal: { await probe.recordSignal($0) },
                stop: { await probe.recordStop() }
            )
        }

        await probe.waitUntilOperationStarted()
        for signal in signalsToSend {
            continuation.yield(signal)
        }

        let termination = try await task.value
        continuation.finish()
        return SignalledSessionResult(
            termination: termination,
            stopCount: await probe.stopCount,
            observedSignals: await probe.observedSignals,
            operationFinished: await probe.operationFinished
        )
    }
}

private enum ExpectedError: Error, Equatable {
    case failed
}

private struct SignalledSessionResult {
    var termination: ForegroundSessionTermination
    var stopCount: Int
    var observedSignals: [UnixSignal]
    var operationFinished: Bool
}

private actor CoordinatorProbe {
    private(set) var stopCount = 0
    private(set) var observedSignals: [UnixSignal] = []
    private(set) var operationFinished = false

    private var operationStarted = false
    private var operationStartWaiters: [CheckedContinuation<Void, Never>] = []
    private var signalStreamEnded = false
    private var signalStreamEndWaiters: [CheckedContinuation<Void, Never>] = []

    func markOperationStarted() {
        operationStarted = true
        let waiters = operationStartWaiters
        operationStartWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }

    func waitUntilOperationStarted() async {
        guard !operationStarted else { return }
        await withCheckedContinuation { continuation in
            operationStartWaiters.append(continuation)
        }
    }

    func markOperationFinished() {
        operationFinished = true
    }

    func markSignalStreamEnded() {
        signalStreamEnded = true
        let waiters = signalStreamEndWaiters
        signalStreamEndWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }

    func waitUntilSignalStreamEnded() async {
        guard !signalStreamEnded else { return }
        await withCheckedContinuation { continuation in
            signalStreamEndWaiters.append(continuation)
        }
    }

    func recordSignal(_ signal: UnixSignal) {
        observedSignals.append(signal)
    }

    func recordStop() {
        stopCount += 1
    }
}

private func cancellationAwareOperation(probe: CoordinatorProbe) async throws {
    await probe.markOperationStarted()
    do {
        try await Task.sleep(for: .seconds(30))
        await probe.markOperationFinished()
    } catch {
        await probe.markOperationFinished()
        throw error
    }
}

private func cancellationSwallowingOperation(probe: CoordinatorProbe) async {
    await probe.markOperationStarted()
    do {
        try await Task.sleep(for: .seconds(30))
    } catch is CancellationError {
        // Model cleanup APIs that consume cancellation and return successfully.
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
    await probe.markOperationFinished()
}
