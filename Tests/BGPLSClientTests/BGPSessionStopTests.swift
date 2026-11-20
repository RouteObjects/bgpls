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
import NIOEmbedded
import NIOPosix
import Synchronization
import Testing

@testable import BGPLSClient

struct BGPSessionStopTests {
    @Test
    func stopBeforeChannelRegistrationRejectsAndClosesLateChannel() throws {
        let control = SessionChannelControl()
        control.requestStop()
        let channel = try activeEmbeddedChannel()

        #expect(!control.register(channel))
        #expect(control.isStopRequested)
        #expect(!channel.isActive)

        _ = try? channel.finish()
    }

    @Test
    func stopAfterChannelRegistrationClosesChannel() throws {
        let control = SessionChannelControl()
        let channel = try activeEmbeddedChannel()

        #expect(control.register(channel))
        control.requestStop()

        #expect(control.isStopRequested)
        #expect(!channel.isActive)

        _ = try? channel.finish()
    }

    @Test
    func repeatedStopRequestsAreHarmless() throws {
        let control = SessionChannelControl()
        let channel = try activeEmbeddedChannel()

        #expect(control.register(channel))
        control.requestStop()
        control.requestStop()

        #expect(control.isStopRequested)
        #expect(!channel.isActive)

        _ = try? channel.finish()
    }

    @Test
    func stopBeforeRunThrowsCancellationWithoutConnecting() async throws {
        // Port zero proves run exits at the stop latch before validation or any network attempt.
        let peer = try #require(IPv4Address("192.0.2.1"))
        let configuration = BGPSessionConfiguration(
            peer: .tcp(address: peer, port: 0),
            localAS: AutonomousSystemNumber(65001),
            peerAS: AutonomousSystemNumber(65001),
            bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")),
            connectTimeout: .seconds(30)
        )
        let session = BGPSession(configuration: configuration)

        await session.stop()

        do {
            try await session.run()
            Issue.record("Expected CancellationError")
        } catch is CancellationError {
            // Expected: the permanent stop latch is checked before configuration and connect work.
        } catch {
            Issue.record("Unexpected error type \(error)")
        }
        #expect(await session.sessionState() == .stopped)
    }

    @Test
    func stopWithoutRunFinishesExistingRIBStream() async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let stream = await session.ribChanges(includeCatchUpSnapshot: false)
        let collector = Task {
            var iterator = stream.makeAsyncIterator()
            return await iterator.next()
        }

        await session.stop()

        #expect(await collector.value == nil)
        #expect(await session.sessionState() == .stopped)
    }

    @Test
    func earlyValidationFailureStopsSessionAndFinishesRIBStream() async throws {
        let peer = try #require(IPv4Address("192.0.2.1"))
        let configuration = BGPSessionConfiguration(
            peer: .tcp(address: peer, port: 0),
            localAS: AutonomousSystemNumber(65001),
            peerAS: AutonomousSystemNumber(65001),
            bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
        )
        let session = BGPSession(configuration: configuration)
        let stream = await session.ribChanges(includeCatchUpSnapshot: false)
        let collector = Task {
            var iterator = stream.makeAsyncIterator()
            return await iterator.next()
        }

        do {
            try await session.run()
            Issue.record("Expected invalid configuration")
        } catch let error as BGPLSClientError {
            #expect(error == .invalidConfiguration("peer port must be non-zero"))
        } catch {
            Issue.record("Unexpected error type \(error)")
        }

        #expect(await collector.value == nil)
        #expect(await session.sessionState() == .stopped)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func pcapSetupFailureFinishesRIBStream(ipv6: Bool) async throws {
        if ipv6 {
            try await Self.expectPCAPSetupFailure(loopback: #require(IPv6Address("::1")))
        } else {
            try await Self.expectPCAPSetupFailure(loopback: #require(IPv4Address("127.0.0.1")))
        }
    }

    enum ExistingPCAPDestination: CaseIterable, Sendable {
        case regularFile, symbolicLink, danglingSymbolicLink
    }

    @Test(.timeLimit(.minutes(1)), arguments: ExistingPCAPDestination.allCases, [false, true])
    func existingPCAPDestinationFailsBeforeConnectingAndFinishesRIBStream(
        destination: ExistingPCAPDestination, ipv6: Bool
    ) async throws {
        if ipv6 {
            try await Self.expectExistingPCAPDestinationFailure(
                destination, loopback: #require(IPv6Address("::1")))
        } else {
            try await Self.expectExistingPCAPDestinationFailure(
                destination, loopback: #require(IPv4Address("127.0.0.1")))
        }
    }

    private static func expectExistingPCAPDestinationFailure<Family: IPAddressFamily>(
        _ destination: ExistingPCAPDestination, loopback: IPAddress<Family>
    ) async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("bgpls-existing-pcap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let capture = directory.appendingPathComponent("session.pcap")
        let target = directory.appendingPathComponent("sentinel.txt")
        let missingTarget = directory.appendingPathComponent("absent.txt")
        let sentinel = Data("Existing data must survive rejected capture setup.\n".utf8)
        try sentinel.write(to: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: target.path)
        switch destination {
        case .regularFile:
            try sentinel.write(to: capture)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: capture.path)
        case .symbolicLink:
            try FileManager.default.createSymbolicLink(at: capture, withDestinationURL: target)
        case .danglingSymbolicLink:
            try FileManager.default.createSymbolicLink(at: capture, withDestinationURL: missingTarget)
        }

        let acceptedConnections = Mutex(0)
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                acceptedConnections.withLock { $0 += 1 }
                // A regression that reaches TCP must terminate promptly instead of waiting for OPEN.
                return channel.close()
            }
            .bind(to: SocketAddress(ipAddress: loopback.addressLiteral, port: 0)).get()
        defer { server.close(promise: nil) }
        let peerPort = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: peerPort),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")),
                connectTimeout: .seconds(1)
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let observedStates = Mutex([BGPSessionState]())
        let observedUpdates = Mutex(0)
        await #expect(throws: (any Error).self) {
            try await session.run(
                pcapPath: capture.path,
                onUpdate: { _ in observedUpdates.withLock { $0 += 1 } },
                onStateChange: { state in observedStates.withLock { $0.append(state) } }
            )
        }
        try await server.close().get()

        #expect(acceptedConnections.withLock { $0 } == 0)
        #expect(observedStates.withLock { $0 } == [.connect])
        #expect(observedUpdates.withLock { $0 } == 0)
        var iterator = changes.makeAsyncIterator()
        #expect(await iterator.next() == nil)
        #expect(await session.sessionState() == .stopped)
        #expect(await session.ribSummaryLine() == "nodes=0 links=0 prefixes=0")
        #expect(try Data(contentsOf: target) == sentinel)
        let targetPermissions = try #require(
            FileManager.default.attributesOfItem(atPath: target.path)[.posixPermissions] as? NSNumber)
        #expect(targetPermissions.uint16Value == 0o644)
        #expect(!FileManager.default.fileExists(atPath: missingTarget.path))
        switch destination {
        case .regularFile:
            #expect(try Data(contentsOf: capture) == sentinel)
            let capturePermissions = try #require(
                FileManager.default.attributesOfItem(atPath: capture.path)[.posixPermissions] as? NSNumber)
            #expect(capturePermissions.uint16Value == 0o644)
        case .symbolicLink:
            #expect(try FileManager.default.destinationOfSymbolicLink(atPath: capture.path) == target.path)
        case .danglingSymbolicLink:
            #expect(try FileManager.default.destinationOfSymbolicLink(atPath: capture.path) == missingTarget.path)
        }
    }

    @Test(.timeLimit(.minutes(1)), arguments: [Duration.zero, .milliseconds(-250)], [false, true])
    func invalidTimeoutFailsBeforeSetupAndFinishesRIBStream(timeout: Duration, ipv6: Bool) async throws {
        if ipv6 {
            try await Self.expectInvalidTimeoutBeforeSetup(timeout, loopback: #require(IPv6Address("::1")))
        } else {
            try await Self.expectInvalidTimeoutBeforeSetup(timeout, loopback: #require(IPv4Address("127.0.0.1")))
        }
    }

    @Test(.timeLimit(.minutes(1)), arguments: [UInt16(1), 2], [false, true])
    func invalidHoldTimeFailsBeforeSetupAndFinishesRIBStream(seconds: UInt16, ipv6: Bool) async throws {
        if ipv6 {
            try await Self.expectInvalidHoldTimeBeforeSetup(seconds, loopback: #require(IPv6Address("::1")))
        } else {
            try await Self.expectInvalidHoldTimeBeforeSetup(seconds, loopback: #require(IPv4Address("127.0.0.1")))
        }
    }

    private static func expectInvalidHoldTimeBeforeSetup<Family: IPAddressFamily>(
        _ seconds: UInt16, loopback: IPAddress<Family>
    ) async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")),
                holdTimeSeconds: seconds
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        // A missing parent exposes any accidental PCAP setup before validation.
        let missingParent = FileManager.default.temporaryDirectory
            .appendingPathComponent("bgpls-invalid-hold-time-\(UUID().uuidString)")
        #expect(!FileManager.default.fileExists(atPath: missingParent.path))
        await #expect(throws: BGPLSClientError.invalidConfiguration("hold time must be 0 or at least 3 seconds")) {
            try await session.run(
                pcapPath: missingParent.appendingPathComponent("session.pcap").path,
                onStateChange: { _ in Issue.record("Invalid hold time must fail before connection state reporting") }
            )
        }
        var iterator = changes.makeAsyncIterator()
        #expect(await iterator.next() == nil)
        #expect(await session.sessionState() == .stopped)
        #expect(await session.ribSummaryLine() == "nodes=0 links=0 prefixes=0")
        #expect(!FileManager.default.fileExists(atPath: missingParent.path))
    }

    private static func expectInvalidTimeoutBeforeSetup<Family: IPAddressFamily>(
        _ timeout: Duration, loopback: IPAddress<Family>
    ) async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")),
                connectTimeout: timeout
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        // A missing parent makes accidental PCAP setup fail before any network connection.
        let missingParent = FileManager.default.temporaryDirectory
            .appendingPathComponent("bgpls-invalid-timeout-\(UUID().uuidString)")
        let pcapPath = missingParent.appendingPathComponent("session.pcap").path
        #expect(!FileManager.default.fileExists(atPath: missingParent.path))
        await #expect(throws: BGPLSClientError.invalidConfiguration("connect timeout must be positive")) {
            try await session.run(
                pcapPath: pcapPath,
                onStateChange: { _ in Issue.record("Invalid timeout must fail before connection state reporting") }
            )
        }
        var iterator = changes.makeAsyncIterator()
        #expect(await iterator.next() == nil)
        #expect(await session.sessionState() == .stopped)
        #expect(await session.ribSummaryLine() == "nodes=0 links=0 prefixes=0")
        #expect(!FileManager.default.fileExists(atPath: missingParent.path))
    }

    private static func expectPCAPSetupFailure<Family: IPAddressFamily>(
        loopback: IPAddress<Family>
    ) async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let collector = Task {
            var iterator = changes.makeAsyncIterator()
            return await iterator.next()
        }
        // The parent does not exist, so setup fails before attempting any connection.
        let missingPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("bgpls-missing-\(UUID().uuidString)")
            .appendingPathComponent("session.pcap").path

        await #expect(throws: (any Error).self) {
            try await session.run(pcapPath: missingPath)
        }
        #expect(await collector.value == nil)
        #expect(await session.sessionState() == .stopped)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func refusedConnectionPreservesConnectFailedAndFinishesRIBStream(ipv6: Bool) async throws {
        if ipv6 {
            try await Self.expectRefusedConnection(loopback: #require(IPv6Address("::1")))
        } else {
            try await Self.expectRefusedConnection(loopback: #require(IPv4Address("127.0.0.1")))
        }
    }

    private static func expectRefusedConnection<Family: IPAddressFamily>(
        loopback: IPAddress<Family>
    ) async throws {
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .bind(to: SocketAddress(ipAddress: loopback.addressLiteral, port: 0)).get()
        let port = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        try await server.close().get()
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: port),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")),
                connectTimeout: .seconds(1)
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let collector = Task {
            var iterator = changes.makeAsyncIterator()
            return await iterator.next()
        }

        do {
            try await session.run()
            Issue.record("Expected connection refusal")
        } catch let error as BGPLSClientError {
            guard case .connectFailed = error else {
                Issue.record("Expected connectFailed, got \(error)")
                return
            }
        } catch {
            Issue.record("Unexpected error type \(error)")
        }
        #expect(await collector.value == nil)
        #expect(await session.sessionState() == .stopped)
    }

    @Test(.timeLimit(.minutes(1)))
    func ipv6StopBeforeRunDoesNotWaitForConnectionTimeout() async throws {
        let peer = try #require(IPv6Address("::1"))
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: peer, port: 0),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")),
                connectTimeout: .seconds(30)
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        await session.stop()
        await session.stop()
        await #expect(throws: CancellationError.self) { try await session.run() }
        var iterator = changes.makeAsyncIterator()
        #expect(await iterator.next() == nil)
        #expect(await session.sessionState() == .stopped)
    }

    @Test(.timeLimit(.minutes(1)))
    func rejectedIPv6TransportFinishesSubscribersBeforeThrowing() async throws {
        let peer = try #require(IPv6Address("fe80::1"))
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: peer, port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        await #expect(
            throws: BGPLSClientError.invalidConfiguration("peer IPv6 link-local address requires unsupported scope")
        ) {
            try await session.run()
        }
        var iterator = changes.makeAsyncIterator()
        #expect(await iterator.next() == nil)
        #expect(await session.sessionState() == .stopped)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func overlappingRunIsRejectedAndStopDrainsQueuedUpdate(ipv6: Bool) async throws {
        if ipv6 {
            try await Self.expectOverlappingRunRejection(loopback: #require(IPv6Address("::1")))
        } else {
            try await Self.expectOverlappingRunRejection(loopback: #require(IPv4Address("127.0.0.1")))
        }
    }

    private static func expectOverlappingRunRejection<Family: IPAddressFamily>(
        loopback: IPAddress<Family>
    ) async throws {
        let (acceptedChannels, acceptedContinuation) = AsyncStream.makeStream(of: Channel.self)
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.backlog, value: 1)
            .childChannelInitializer { channel in
                acceptedContinuation.yield(channel)
                return channel.eventLoop.makeSucceededVoidFuture()
            }
            .bind(to: SocketAddress(ipAddress: loopback.addressLiteral, port: 0))
            .get()
        defer {
            server.close(promise: nil)
            acceptedContinuation.finish()
        }

        let peerPort = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: peerPort),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")),
                connectTimeout: .seconds(5)
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let collectedChanges = Task {
            var collected: [RIBDiff] = []
            for await change in changes {
                collected.append(change)
            }
            return collected
        }
        let (observedUpdates, observedContinuation) = AsyncStream.makeStream(of: Void.self)
        defer { observedContinuation.finish() }
        let firstRun = Task {
            do {
                try await session.run(onUpdate: { _ in observedContinuation.yield(()) })
                return nil as (any Error)?
            } catch {
                return error
            }
        }

        var acceptedIterator = acceptedChannels.makeAsyncIterator()
        let acceptedChannel = try #require(await acceptedIterator.next())

        do {
            try await session.run()
            Issue.record("Expected overlapping run rejection")
        } catch let error as BGPLSClientError {
            #expect(error == .sessionFailed("run is already in progress"))
        } catch {
            Issue.record("Unexpected overlapping-run error \(error)")
        }

        // Admit through the actual wire/FSM/credit path rather than bypassing the queue.
        var wire = ByteBuffer()
        let open = BGPOpenMessage(
            version: 4, myAS: 65001, holdTime: 90, bgpIdentifier: 0xC000_0201,
            optionalParameters: BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(65001))
        )
        try BGPMessageCodec.encode(.open(open), into: &wire)
        try BGPMessageCodec.encode(.keepalive, into: &wire)
        try BGPMessageCodec.encode(.update(HexFixture.buffer(BGPUpdateParserTests.linkUpdateHex)), into: &wire)
        try await acceptedChannel.writeAndFlush(wire).get()
        var observedIterator = observedUpdates.makeAsyncIterator()
        let observed: Void? = await observedIterator.next()
        #expect(observed != nil)
        await session.stop()

        #expect(await firstRun.value is CancellationError)
        let diffs = await collectedChanges.value
        #expect(
            diffs.contains { diff in
                if case .upsert(.link) = diff { return true }
                return false
            })
        #expect(await session.ribSnapshot().linkCount == 1)
        try await acceptedChannel.closeFuture.get()
        try await server.close().get()
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true], [false, true])
    func stopOrCancellationWhileNativeReadsArePausedDrainsActualSession(ipv6: Bool, cancel: Bool) async throws {
        if ipv6 {
            try await Self.expectPausedSessionShutdown(loopback: #require(IPv6Address("::1")), cancel: cancel)
        } else {
            try await Self.expectPausedSessionShutdown(loopback: #require(IPv4Address("127.0.0.1")), cancel: cancel)
        }
    }

    private static func expectPausedSessionShutdown<Family: IPAddressFamily>(
        loopback: IPAddress<Family>, cancel: Bool
    ) async throws {
        let (accepted, acceptedContinuation) = AsyncStream.makeStream(of: Channel.self)
        defer { acceptedContinuation.finish() }
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                acceptedContinuation.yield(channel)
                return channel.eventLoop.makeSucceededVoidFuture()
            }
            .bind(to: SocketAddress(ipAddress: loopback.addressLiteral, port: 0)).get()
        defer { server.close(promise: nil) }
        let port = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let gate = PausedSessionGate()
        defer { gate.open() }
        let (consumerEntered, enteredContinuation) = AsyncStream.makeStream(of: Void.self)
        let (intakes, intakeContinuation) = AsyncStream.makeStream(of: PausedSessionIntake.self)
        let (states, stateContinuation) = AsyncStream.makeStream(of: BGPSessionState.self)
        let (rawUpdates, rawContinuation) = AsyncStream.makeStream(of: ByteBuffer.self)
        defer {
            enteredContinuation.finish()
            intakeContinuation.finish()
            stateContinuation.finish()
            rawContinuation.finish()
        }
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: port),
                localAS: AutonomousSystemNumber(65001), peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")), connectTimeout: .seconds(5)
            ),
            inputConsumerFactory: { wrapped, admission, outcome, handler in
                intakeContinuation.yield(PausedSessionIntake(channel: wrapped.channel, admission: admission))
                return SessionInputConsumer(channel: wrapped, admission: admission, outcome: outcome) { input in
                    if case .update = input {
                        enteredContinuation.yield(())
                        await gate.wait()
                    }
                    await handler(input)
                }
            }
        )
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let pcap = directory.appendingPathComponent("paused-session.pcap")
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let watchFinished = Mutex(false)
        let watcher = Task {
            var events: [RIBDiff] = []
            for await event in changes { events.append(event) }
            watchFinished.withLock { $0 = true }
            return events
        }
        defer { watcher.cancel() }
        let rawCollector = Task {
            var bodies: [ByteBuffer] = []
            for await body in rawUpdates { bodies.append(body) }
            return bodies
        }
        defer { rawCollector.cancel() }
        let runFinished = Mutex(false)
        let runner = Task {
            defer {
                rawContinuation.finish()
                stateContinuation.finish()
                runFinished.withLock { $0 = true }
            }
            try await session.run(
                pcapPath: pcap.path, onUpdate: { rawContinuation.yield($0) },
                onStateChange: { stateContinuation.yield($0) }
            )
        }
        defer { runner.cancel() }
        let watchdog = Task {
            do { try await Task.sleep(for: .seconds(20)) } catch { return }
            Issue.record("Paused public-session shutdown exceeded its bounded deadline")
            gate.open()
            runner.cancel()
            enteredContinuation.finish()
            intakeContinuation.finish()
            acceptedContinuation.finish()
            stateContinuation.finish()
        }
        defer { watchdog.cancel() }

        var acceptedIterator = accepted.makeAsyncIterator()
        let peer = try #require(await acceptedIterator.next())
        defer { peer.close(promise: nil) }
        var intakeIterator = intakes.makeAsyncIterator()
        let intake = try #require(await intakeIterator.next())
        defer { intake.channel.close(promise: nil) }
        let clientPort = try #require(intake.channel.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let loop = intake.channel.eventLoop
        let readCount = NIOLoopBoundBox.makeBoxSendingValue(0, eventLoop: loop)
        let (batches, batchContinuation) = AsyncStream.makeStream(of: Int.self)
        defer { batchContinuation.finish() }
        try await loop.submit {
            try intake.channel.pipeline.syncOperations.addHandler(
                PausedSessionReadProbe(
                    admission: intake.admission, reads: readCount, batches: batchContinuation
                ), position: .first
            )
        }.get()

        let peerOpen = BGPOpenMessage(
            myAS: 65001, holdTime: 0, bgpIdentifier: 0xc000_0201,
            optionalParameters: BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(65001))
        )
        var offered = ByteBuffer()
        try BGPMessageCodec.encode(.open(peerOpen), into: &offered)
        try BGPMessageCodec.encode(.keepalive, into: &offered)
        try await peer.writeAndFlush(offered).get()
        var stateIterator = states.makeAsyncIterator()
        while let state = await stateIterator.next(), state != .established {}
        #expect(await session.sessionState() == .established)

        // One active UPDATE plus exactly one high-watermark buffer ensures every
        // offered frame is admitted before demand pauses, regardless of TCP splitting.
        let count = SessionInputSettings.highWatermark + 1
        let bodies = (1...count).map { value in
            IPv6TopologyFixture.updateBody(
                reachable: true,
                nlris: IPv6TopologyFixture.wire(
                    type: 1, descriptors: [IPv6TopologyFixture.nodeDescriptor(lastByte: UInt8(value))]
                )
            )
        }
        var first = ByteBuffer()
        try BGPMessageCodec.encode(.update(try #require(bodies.first)), into: &first)
        offered.writeImmutableBuffer(first)
        try await peer.writeAndFlush(first).get()
        var enteredIterator = consumerEntered.makeAsyncIterator()
        _ = try #require(await enteredIterator.next())
        var remaining = ByteBuffer()
        for body in bodies.dropFirst() { try BGPMessageCodec.encode(.update(body), into: &remaining) }
        offered.writeImmutableBuffer(remaining)
        try await peer.writeAndFlush(remaining).get()
        var batchIterator = batches.makeAsyncIterator()
        while let pending = await batchIterator.next(), pending < count {}
        let before = try await loop.submit { readCount.value }.get()
        intake.channel.read()
        try await loop.submit {}.get()
        #expect(try await loop.submit { readCount.value }.get() == before)
        #expect(try await loop.submit { intake.admission.pendingCount }.get() == count)
        #expect(await session.ribSnapshot().nodeCount == 0)

        if cancel { runner.cancel() } else { await session.stop() }
        try await intake.channel.closeFuture.get()
        try await peer.closeFuture.get()
        #expect(!intake.channel.isActive)
        #expect(!runFinished.withLock { $0 })
        #expect(!watchFinished.withLock { $0 })
        #expect(try await loop.submit { intake.admission.pendingCount }.get() == count)
        gate.open()
        await #expect(throws: CancellationError.self) { try await runner.value }

        #expect(await rawCollector.value == bodies)
        var expected = LSRIB()
        var expectedEvents: [RIBDiff] = []
        for body in bodies { expectedEvents += try expected.apply(update: BGPUpdateParser.parse(body)) }
        #expect(await watcher.value == expectedEvents)
        #expect(await session.ribSnapshot() == expected)
        #expect(await session.sessionState() == .stopped)
        #expect(try await loop.submit { intake.admission.pendingCount }.get() == 0)
        #expect(runFinished.withLock { $0 })
        #expect(watchFinished.withLock { $0 })
        var collectorWire = ByteBuffer()
        try BGPMessageCodec.encode(
            .open(
                BGPOpenMessage(
                    myAS: 65001, holdTime: 90, bgpIdentifier: 0xc000_02fe,
                    optionalParameters: BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(65001))
                )), into: &collectorWire
        )
        try BGPMessageCodec.encode(.keepalive, into: &collectorWire)
        try expectPausedSessionPCAP(
            pcap, ipv6: Family.bitWidth == 128, clientPort: clientPort, peerPort: port,
            offered: offered, collectorWire: collectorWire
        )
    }

    private static func expectPausedSessionPCAP(
        _ url: URL, ipv6: Bool, clientPort: UInt16, peerPort: UInt16,
        offered: ByteBuffer, collectorWire: ByteBuffer
    ) throws {
        var capture = ByteBuffer(bytes: try Data(contentsOf: url))
        let magic: UInt32? = capture.readInteger(endianness: .host)
        #expect(magic == 0xa1b2_c3d4)
        let globalFields = capture.readSlice(length: 16)
        _ = try #require(globalFields)
        let linkType: UInt32? = capture.readInteger(endianness: .host)
        #expect(linkType == 0)
        var inbound: [UInt8] = []
        var outbound: [UInt8] = []
        var fins = 0
        var syns = 0
        while capture.readableBytes > 0 {
            let timestamp = capture.readSlice(length: 8)
            _ = try #require(timestamp)
            let includedValue: UInt32? = capture.readInteger(endianness: .host)
            let originalValue: UInt32? = capture.readInteger(endianness: .host)
            let included = try #require(includedValue)
            let original = try #require(originalValue)
            #expect(included == original)
            let packetValue = capture.readSlice(length: Int(included))
            var packet = try #require(packetValue)
            let addressFamily: UInt32? = packet.readInteger(endianness: .host)
            #expect(addressFamily == (ipv6 ? 24 : 2))
            let version = try #require(packet.getInteger(at: packet.readerIndex, as: UInt8.self))
            #expect(version >> 4 == (ipv6 ? 6 : 4))
            let ipHeader = packet.readSlice(length: ipv6 ? 40 : 20)
            _ = try #require(ipHeader)
            let sourcePort = try #require(packet.getInteger(at: packet.readerIndex, as: UInt16.self))
            let destinationPort = try #require(packet.getInteger(at: packet.readerIndex + 2, as: UInt16.self))
            let offset = try #require(packet.getInteger(at: packet.readerIndex + 12, as: UInt8.self))
            #expect(offset >> 4 == 5)
            let flags = try #require(packet.getInteger(at: packet.readerIndex + 13, as: UInt8.self))
            if flags & 1 != 0 { fins += 1 }
            if flags & 2 != 0 { syns += 1 }
            let tcpHeader = packet.readSlice(length: 20)
            _ = try #require(tcpHeader)
            if sourcePort == peerPort {
                #expect(destinationPort == clientPort)
                inbound.append(contentsOf: packet.readableBytesView)
            } else {
                #expect(sourcePort == clientPort)
                #expect(destinationPort == peerPort)
                outbound.append(contentsOf: packet.readableBytesView)
            }
        }
        #expect(syns == 2)
        #expect(fins == 2)
        #expect(inbound == Array(offered.readableBytesView))
        #expect(outbound == Array(collectorWire.readableBytesView))
    }

    private func activeEmbeddedChannel() throws -> EmbeddedChannel {
        let channel = EmbeddedChannel()
        try channel.connect(
            to: SocketAddress(ipAddress: "192.0.2.1", port: 179)
        ).wait()
        #expect(channel.isActive)
        return channel
    }
}

private struct PausedSessionGate: Sendable {
    private let stream: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation
    init() { (stream, continuation) = AsyncStream.makeStream(of: Void.self) }
    func wait() async { for await _ in stream { break } }
    func open() { continuation.finish() }
}

private struct PausedSessionIntake: Sendable {
    let channel: any Channel
    let admission: SessionInputAdmission
}

private final class PausedSessionReadProbe: ChannelDuplexHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    private let admission: SessionInputAdmission
    private let reads: NIOLoopBoundBox<Int>
    private let batches: AsyncStream<Int>.Continuation

    init(admission: SessionInputAdmission, reads: NIOLoopBoundBox<Int>, batches: AsyncStream<Int>.Continuation) {
        self.admission = admission
        self.reads = reads
        self.batches = batches
    }
    func read(context: ChannelHandlerContext) {
        reads.value += 1
        context.read()
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) { context.fireChannelRead(data) }
    func channelReadComplete(context: ChannelHandlerContext) {
        context.fireChannelReadComplete()
        batches.yield(admission.pendingCount)
    }
    func handlerRemoved(context: ChannelHandlerContext) { batches.finish() }
}
