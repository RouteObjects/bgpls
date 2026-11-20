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
import BGPLSClient
import CIDR
import Foundation
import NIOCore
import NIOPosix
import Testing
import UnixSignals

struct ForegroundSessionLoopbackTests {
    @Test(.timeLimit(.minutes(1)), arguments: LoopbackTermination.allCases, LoopbackTransport.allCases)
    func establishedSessionRetainsUpdatesThroughTermination(
        termination: LoopbackTermination,
        transport: LoopbackTransport
    ) async throws {
        //  IPv6 is a required test case, not a capability-based skip. Keep the
        // complete lifecycle matrix identical for each real loopback socket family.
        switch transport {
        case .ipv4:
            try await establishedSession(
                termination: termination, transport: transport, loopback: #require(IPv4Address(transport.host))
            )
        case .ipv6:
            try await establishedSession(
                termination: termination, transport: transport, loopback: #require(IPv6Address(transport.host))
            )
        }
    }

    private func establishedSession<Family: IPAddressFamily>(
        termination: LoopbackTermination,
        transport: LoopbackTransport,
        loopback: IPAddress<Family>,
        bind: LoopbackBind = .explicit,
        asns: LoopbackASNs = .legacy,
        peerHoldTime: UInt16 = 0
    ) async throws {
        let peerOpen = BGPOpenMessage(
            myAS: asns.peerOpen.myAS, holdTime: peerHoldTime,
            bgpIdentifier: asns.peerOpen.bgpIdentifier, optionalParameters: asns.peerOpen.optionalParameters
        )
        let (acceptedChannels, acceptedContinuation) = AsyncStream.makeStream(of: Channel.self)
        let (opens, openContinuation) = AsyncStream.makeStream(of: BGPOpenMessage.self)
        defer { openContinuation.finish() }
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.backlog, value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        ByteToMessageHandler(BGPMessageDecoder())
                    )
                    try channel.pipeline.syncOperations.addHandler(
                        MessageToByteHandler(BGPMessageEncoder())
                    )
                    try channel.pipeline.syncOperations.addHandler(
                        LoopbackPeerHandler(
                            sendMixedFamilyPrefixes: true, peerOpen: peerOpen,
                            onOpen: { openContinuation.yield($0) }
                        )
                    )
                    acceptedContinuation.yield(channel)
                }
            }
            // CHANGE: Bind the literal directly so IPv6 loopback works independently of host resolver policy.
            .bind(to: SocketAddress(ipAddress: transport.host, port: 0))
            .get()
        defer {
            server.close(promise: nil)
            acceptedContinuation.finish()
        }

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let pcap = directory.appendingPathComponent("termination.pcap")
        let peerPort = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let localAddress: IPAddress<Family>?
        switch bind {
        case .explicit: localAddress = loopback
        case .omitted: localAddress = nil
        case .wildcard:
            let wildcard: IPAddress<Family>? = IPAddress<Family>(transport.wildcard)
            let requiredWildcard: IPAddress<Family> = try #require(wildcard)
            localAddress = requiredWildcard
        }
        let configuration = BGPSessionConfiguration(
            peer: .tcp(address: loopback, port: peerPort),
            localAS: asns.local,
            peerAS: asns.peer,
            bgpIdentifier: try #require(BGPIdentifier("192.0.2.37")),
            localAddress: localAddress,
            connectTimeout: .seconds(5)
        )
        let session = BGPSession(configuration: configuration)
        let (signals, signalContinuation) = AsyncStream.makeStream(of: UnixSignal.self)
        defer { signalContinuation.finish() }

        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let (receivedUpdate, updateContinuation) = AsyncStream.makeStream(of: Void.self)
        let watcher = Task {
            defer { updateContinuation.finish() }
            var collected: [RIBDiff] = []
            for await diff in changes {
                collected.append(diff)
                if case .upsert(.prefix(let record)) = diff, case .v6 = record.nlri {
                    updateContinuation.yield(())
                }
            }
            return collected
        }
        defer { watcher.cancel() }

        let runner = Task {
            //  Direct stop/cancellation cases exercise the library independently of
            // the coordinator's cancellation check, which could otherwise mask a false success.
            if termination == .directStop || termination == .parentCancellation {
                try await session.run(pcapPath: pcap.path)
                return ForegroundSessionTermination.operationCompleted
            }
            return try await ForegroundSessionCoordinator.run(
                signals: signals,
                operation: { try await session.run(pcapPath: pcap.path) },
                stop: { await session.stop() }
            )
        }
        defer { runner.cancel() }

        var acceptedIterator = acceptedChannels.makeAsyncIterator()
        let acceptedChannel = try #require(await acceptedIterator.next())
        defer { acceptedChannel.close(promise: nil) }
        let clientAddress = try #require(acceptedChannel.remoteAddress)
        let peerAddress = try #require(acceptedChannel.localAddress)
        #expect(clientAddress.ipAddress == transport.host)
        #expect(peerAddress.ipAddress == transport.host)
        var openIterator = opens.makeAsyncIterator()
        let open = try #require(await openIterator.next())
        #expect(open.bgpIdentifier == 0xc000_0225)
        #expect(open.myAS == (UInt16(exactly: asns.local.rawValue) ?? 23_456))
        #expect(open.optionalParameters == BGPOpenCapabilities.bgpLS(localAS: asns.local))

        // Receiving a decoded NLRI proves OPEN/KEEPALIVE reached Established. This
        // avoids timing sleeps and tests shutdown after real protocol traffic, not only TCP.
        var updateIterator = receivedUpdate.makeAsyncIterator()
        _ = try #require(await updateIterator.next())
        #expect(await session.sessionState() == .established)

        switch termination {
        case .sigint:
            signalContinuation.yield(.sigint)
        case .sigterm:
            signalContinuation.yield(.sigterm)
        case .normalClose:
            try await acceptedChannel.close().get()
        case .notification:
            try await acceptedChannel.writeAndFlush(
                BGPMessage.notification(BGPNotificationMessage(errorCode: 6, errorSubcode: 0))
            ).get()
        case .unexpectedOpen:
            try await acceptedChannel.writeAndFlush(BGPMessage.open(LoopbackPeerHandler.open)).get()
        case .directStop:
            await session.stop()
        case .parentCancellation:
            runner.cancel()
        }

        let result = await runner.result
        let diffs = await watcher.value
        try await acceptedChannel.closeFuture.get()
        #expect(await session.sessionState() == .stopped)

        let snapshot = await session.ribSnapshot()
        #expect(await session.ribSummaryLine() == "nodes=2 links=0 prefixes=2")
        #expect(await session.ribSummaryLine() == snapshot.summaryLine)
        #expect(snapshot.nodeCount == 2)
        #expect(
            snapshot.nodes.values.map(\.nlri).compactMap { $0.localNode.ipv4RouterIDString }.sorted()
                == ["192.0.2.1", "192.0.2.2"]
        )
        #expect(snapshot.prefixCount == 2)
        #expect(
            snapshot.prefixes.values.map(\.nlri).map { $0.network.description }.sorted() == [
                "192.0.2.0/24", "2001:db8::/64",
            ])
        #expect(snapshot.prefixes.values.allSatisfy { $0.attributes.metric == 10 })
        #expect(snapshot.prefixes.values.allSatisfy { $0.observation.availability == .present })
        #expect(diffs.count == 4)
        #expect(
            diffs.contains { if case .upsert(.prefix(let record)) = $0, case .v4 = record.nlri { true } else { false } }
        )
        #expect(
            diffs.contains { if case .upsert(.prefix(let record)) = $0, case .v6 = record.nlri { true } else { false } }
        )
        try Self.expectCompletePCAP(
            pcap, transport: transport, client: clientAddress, peer: peerAddress,
            localAS: asns.local, peerOpen: peerOpen
        )

        switch termination {
        case .sigint:
            #expect(try result.get() == .signal(.sigint))
        case .sigterm:
            #expect(try result.get() == .signal(.sigterm))
        case .normalClose:
            #expect(try result.get() == .operationCompleted)
        case .notification:
            guard case .failure(let error) = result else {
                Issue.record("Expected the post-establishment NOTIFICATION to fail the session")
                return
            }
            #expect(error as? BGPLSClientError == .sessionFailed("NOTIFICATION code=6 subcode=0"))
        case .unexpectedOpen:
            guard case .failure(let error) = result else {
                Issue.record("Expected the post-establishment OPEN to fail the session")
                return
            }
            #expect(error as? BGPLSClientError == .protocolError("unexpected OPEN while Established"))
        case .directStop, .parentCancellation:
            guard case .failure(let error) = result else {
                Issue.record("Expected intentional shutdown to preserve CancellationError")
                return
            }
            #expect(error is CancellationError)
        }
        try await server.close().get()
    }

    @Test(
        .timeLimit(.minutes(1)),
        arguments: [LoopbackTermination.sigint, .sigterm, .directStop, .parentCancellation], LoopbackTransport.allCases
    )
    func intentionalTerminationCancelsActiveHoldTimer(
        termination: LoopbackTermination, transport: LoopbackTransport
    ) async throws {
        switch transport {
        case .ipv4:
            try await establishedSession(
                termination: termination, transport: transport, loopback: #require(IPv4Address(transport.host)),
                peerHoldTime: 3
            )
        case .ipv6:
            try await establishedSession(
                termination: termination, transport: transport, loopback: #require(IPv6Address(transport.host)),
                peerHoldTime: 3
            )
        }
    }

    @Test(.timeLimit(.minutes(1)), arguments: LoopbackASNs.allCases, LoopbackTransport.allCases)
    func sessionASNWidthsAreIndependentOfTransport(asns: LoopbackASNs, transport: LoopbackTransport) async throws {
        switch transport {
        case .ipv4:
            try await establishedSession(
                termination: .normalClose, transport: transport,
                loopback: #require(IPv4Address(transport.host)), asns: asns
            )
        case .ipv6:
            try await establishedSession(
                termination: .normalClose, transport: transport,
                loopback: #require(IPv6Address(transport.host)), asns: asns
            )
        }
    }

    @Test(.timeLimit(.minutes(1)), arguments: LoopbackTermination.allCases, LoopbackTransport.allCases)
    func largeASNsPreserveAllTerminationPaths(
        termination: LoopbackTermination, transport: LoopbackTransport
    ) async throws {
        //  Reuse the complete cleanup/PCAP contract with real four-byte OPENs;
        // no signals are delivered to the parallel unit-test process.
        switch transport {
        case .ipv4:
            try await establishedSession(
                termination: termination, transport: transport,
                loopback: #require(IPv4Address(transport.host)), asns: .large
            )
        case .ipv6:
            try await establishedSession(
                termination: termination, transport: transport,
                loopback: #require(IPv6Address(transport.host)), asns: .large
            )
        }
    }

    @Test(.timeLimit(.minutes(1)), arguments: LoopbackASNFailure.allCases, LoopbackTransport.allCases)
    func rejectedASNOpenFinishesStreamsAndCapture(failure: LoopbackASNFailure, transport: LoopbackTransport)
        async throws
    {
        switch transport {
        case .ipv4:
            try await rejectedOpen(
                failure: failure, transport: transport, loopback: #require(IPv4Address(transport.host)))
        case .ipv6:
            try await rejectedOpen(
                failure: failure, transport: transport, loopback: #require(IPv6Address(transport.host)))
        }
    }

    private func rejectedOpen<Family: IPAddressFamily>(
        failure: LoopbackASNFailure, transport: LoopbackTransport, loopback: IPAddress<Family>
    ) async throws {
        let (accepted, continuation) = AsyncStream.makeStream(of: (Channel, SocketAddress, SocketAddress).self)
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(BGPMessageDecoder()))
                    try channel.pipeline.syncOperations.addHandler(MessageToByteHandler(BGPMessageEncoder()))
                    try channel.pipeline.syncOperations.addHandler(LoopbackPeerHandler(peerOpen: failure.open))
                    //  Rejected OPENs can close before the test task resumes.
                    // Snapshot endpoints on the event loop while the channel is live.
                    continuation.yield(
                        (channel, try #require(channel.remoteAddress), try #require(channel.localAddress)))
                }
            }
            .bind(to: SocketAddress(ipAddress: transport.host, port: 0)).get()
        defer {
            continuation.finish()
            server.close(promise: nil)
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let pcap = directory.appendingPathComponent("rejected-open.pcap")
        let localAS = AutonomousSystemNumber(4_200_000_001)
        let port = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: port), localAS: localAS, peerAS: localAS,
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.37")),
                localAddress: loopback, connectTimeout: .seconds(5)
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let watcher = Task {
            var count = 0
            for await _ in changes { count += 1 }
            return count
        }
        defer { watcher.cancel() }
        let runner = Task { try await session.run(pcapPath: pcap.path) }
        defer { runner.cancel() }
        var iterator = accepted.makeAsyncIterator()
        let (channel, client, peer) = try #require(await iterator.next())
        defer { channel.close(promise: nil) }
        let result = await runner.result
        guard case .failure(let error) = result else {
            Issue.record("Rejected OPEN must fail, not become ordinary channel closure")
            return
        }
        #expect(error is BGPLSClientError)
        #expect(!(error is CancellationError))
        #expect(await watcher.value == 0)
        #expect(await session.ribSnapshot().nodeCount == 0)
        #expect(await session.sessionState() == .stopped)
        try await channel.closeFuture.get()
        try Self.expectCompletePCAP(
            pcap, transport: transport, client: client, peer: peer,
            localAS: localAS, peerOpen: failure.open, outboundMessages: .openOnly, inboundMessages: .openOnly
        )
        try await server.close().get()
    }

    @Test(.timeLimit(.minutes(1)), arguments: LoopbackBGPLSCapabilityFailure.allCases, LoopbackTransport.allCases)
    func missingBGPLSCapabilityNotifiesBeforeFinishingStreamsAndCapture(
        failure: LoopbackBGPLSCapabilityFailure, transport: LoopbackTransport
    ) async throws {
        switch transport {
        case .ipv4:
            try await rejectedBGPLSCapability(
                failure: failure, transport: transport, loopback: #require(IPv4Address(transport.host)))
        case .ipv6:
            try await rejectedBGPLSCapability(
                failure: failure, transport: transport, loopback: #require(IPv6Address(transport.host)))
        }
    }

    @Test(.timeLimit(.minutes(1)), arguments: LoopbackTransport.allCases)
    func missingBGPLSCapabilitySurvivesImmediatePeerClosure(transport: LoopbackTransport) async throws {
        switch transport {
        case .ipv4:
            try await rejectedBGPLSCapability(
                failure: .as4Only, transport: transport, loopback: #require(IPv4Address(transport.host)),
                closeAfterOpen: true
            )
        case .ipv6:
            try await rejectedBGPLSCapability(
                failure: .as4Only, transport: transport, loopback: #require(IPv6Address(transport.host)),
                closeAfterOpen: true
            )
        }
    }

    private func rejectedBGPLSCapability<Family: IPAddressFamily>(
        failure: LoopbackBGPLSCapabilityFailure, transport: LoopbackTransport, loopback: IPAddress<Family>,
        closeAfterOpen: Bool = false
    ) async throws {
        let (accepted, acceptedContinuation) = AsyncStream.makeStream(of: (Channel, SocketAddress, SocketAddress).self)
        let (notifications, notificationContinuation) = AsyncStream.makeStream(of: BGPNotificationMessage.self)
        defer { notificationContinuation.finish() }
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(BGPMessageDecoder()))
                    try channel.pipeline.syncOperations.addHandler(MessageToByteHandler(BGPMessageEncoder()))
                    try channel.pipeline.syncOperations.addHandler(
                        LoopbackPeerHandler(
                            peerOpen: failure.open, closeAfterOpen: closeAfterOpen,
                            onNotification: { notificationContinuation.yield($0) },
                            onInactive: { notificationContinuation.finish() }
                        )
                    )
                    acceptedContinuation.yield(
                        (channel, try #require(channel.remoteAddress), try #require(channel.localAddress)))
                }
            }
            .bind(to: SocketAddress(ipAddress: transport.host, port: 0)).get()
        defer {
            acceptedContinuation.finish()
            server.close(promise: nil)
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let pcap = directory.appendingPathComponent("missing-bgpls-capability.pcap")
        let port = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: port), localAS: failure.asn, peerAS: failure.asn,
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.37")),
                localAddress: loopback, connectTimeout: .seconds(5)
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let watcher = Task {
            var diffs: [RIBDiff] = []
            for await diff in changes { diffs.append(diff) }
            return diffs
        }
        defer { watcher.cancel() }
        let (rawBodies, rawContinuation) = AsyncStream.makeStream(of: ByteBuffer.self)
        let (states, stateContinuation) = AsyncStream.makeStream(of: BGPSessionState.self)
        defer {
            rawContinuation.finish()
            stateContinuation.finish()
        }
        let runner = Task {
            defer {
                rawContinuation.finish()
                stateContinuation.finish()
            }
            try await session.run(
                pcapPath: pcap.path, onUpdate: { rawContinuation.yield($0) },
                onStateChange: { stateContinuation.yield($0) }
            )
        }
        defer { runner.cancel() }
        var acceptedIterator = accepted.makeAsyncIterator()
        let (channel, client, peer) = try #require(await acceptedIterator.next())
        defer { channel.close(promise: nil) }
        let expectedNotification = BGPNotificationMessage(
            errorCode: 2, errorSubcode: 7, data: [1, 4, 0x40, 4, 0, 71])
        var notificationIterator = notifications.makeAsyncIterator()
        if !closeAfterOpen {
            // Receipt proves notification-before-cleanup ordering over the real socket.
            #expect(try #require(await notificationIterator.next()) == expectedNotification)
        }
        let result = await runner.result
        guard case .failure(let error) = result else {
            Issue.record("Missing BGP-LS capability must fail before establishment")
            return
        }
        #expect(error as? BGPLSClientError == .missingBGPLSCapability)
        #expect(!(error is CancellationError))
        #expect(await watcher.value.isEmpty)
        #expect(await session.ribSummaryLine() == "nodes=0 links=0 prefixes=0")
        #expect(await session.sessionState() == .stopped)
        var observedBodies: [ByteBuffer] = []
        for await body in rawBodies { observedBodies.append(body) }
        #expect(observedBodies.isEmpty)
        var observedStates: [BGPSessionState] = []
        for await state in states { observedStates.append(state) }
        #expect(!observedStates.contains(.openConfirm))
        #expect(!observedStates.contains(.established))
        #expect(observedStates.filter { $0 == .stopped }.count == 1)
        try await channel.closeFuture.get()
        if !closeAfterOpen { #expect(await notificationIterator.next() == nil) }
        try Self.expectCompletePCAP(
            pcap, transport: transport, client: client, peer: peer,
            localAS: failure.asn, peerOpen: failure.open, outboundMessages: .openOnly, inboundMessages: .openOnly,
            expectedNotification: closeAfterOpen ? nil : expectedNotification
        )
        try await server.close().get()
    }

    @Test(.timeLimit(.minutes(1)), arguments: LoopbackHoldFailure.allCases, LoopbackTransport.allCases)
    func holdTimeFailureNotifiesPeerAndCompletesCleanup(
        failure: LoopbackHoldFailure, transport: LoopbackTransport
    ) async throws {
        switch transport {
        case .ipv4:
            try await holdTimeFailure(
                failure: failure, transport: transport, loopback: #require(IPv4Address(transport.host)))
        case .ipv6:
            try await holdTimeFailure(
                failure: failure, transport: transport, loopback: #require(IPv6Address(transport.host)))
        }
    }

    private func holdTimeFailure<Family: IPAddressFamily>(
        failure: LoopbackHoldFailure, transport: LoopbackTransport, loopback: IPAddress<Family>
    ) async throws {
        let (accepted, acceptedContinuation) = AsyncStream.makeStream(of: (Channel, SocketAddress, SocketAddress).self)
        let (notifications, notificationContinuation) = AsyncStream.makeStream(of: BGPNotificationMessage.self)
        defer { notificationContinuation.finish() }
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(BGPMessageDecoder()))
                    try channel.pipeline.syncOperations.addHandler(MessageToByteHandler(BGPMessageEncoder()))
                    try channel.pipeline.syncOperations.addHandler(
                        LoopbackPeerHandler(
                            sendMixedFamilyPrefixes: true, peerOpen: failure.open,
                            completeHandshake: failure.establishes,
                            onNotification: { notificationContinuation.yield($0) },
                            onInactive: { notificationContinuation.finish() }
                        )
                    )
                    acceptedContinuation.yield(
                        (channel, try #require(channel.remoteAddress), try #require(channel.localAddress)))
                }
            }
            .bind(to: SocketAddress(ipAddress: transport.host, port: 0)).get()
        defer {
            acceptedContinuation.finish()
            server.close(promise: nil)
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let pcap = directory.appendingPathComponent("hold-time-failure.pcap")
        let port = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: port),
                localAS: AutonomousSystemNumber(65001), peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.37")),
                localAddress: loopback, holdTimeSeconds: failure.localHoldTime, connectTimeout: .seconds(5)
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let watcher = Task {
            var diffs: [RIBDiff] = []
            for await diff in changes { diffs.append(diff) }
            return diffs
        }
        defer { watcher.cancel() }
        let (rawBodies, rawContinuation) = AsyncStream.makeStream(of: ByteBuffer.self)
        let (states, stateContinuation) = AsyncStream.makeStream(of: BGPSessionState.self)
        let runner = Task {
            defer {
                rawContinuation.finish()
                stateContinuation.finish()
            }
            try await session.run(
                pcapPath: pcap.path, onUpdate: { rawContinuation.yield($0) },
                onStateChange: { stateContinuation.yield($0) }
            )
        }
        defer { runner.cancel() }
        var acceptedIterator = accepted.makeAsyncIterator()
        let (channel, client, peer) = try #require(await acceptedIterator.next())
        defer { channel.close(promise: nil) }
        // Three seconds is a legal negotiated hold time. This much larger bound
        // turns a missing expiry into an assertion failure instead of a hanging test.
        let watchdog = channel.eventLoop.scheduleTask(in: .seconds(15)) { channel.close(promise: nil) }
        defer { watchdog.cancel() }
        var notificationIterator = notifications.makeAsyncIterator()
        #expect(try #require(await notificationIterator.next()) == failure.notification)
        let result = await runner.result
        guard case .failure(let error) = result else {
            Issue.record("A hold-time failure must not become normal peer closure")
            return
        }
        #expect(error as? BGPLSClientError == failure.error)
        #expect(!(error is CancellationError))
        let diffs = await watcher.value
        var observedBodies: [ByteBuffer] = []
        for await body in rawBodies { observedBodies.append(body) }
        #expect(
            observedBodies
                == (failure.establishes ? [LoopbackPeerHandler.nodeUpdate, LoopbackPeerHandler.mixedFamilyUpdate] : [])
        )
        var observedStates: [BGPSessionState] = []
        for await state in states { observedStates.append(state) }
        #expect(observedStates.contains(.openConfirm) == failure.acceptsOpen)
        #expect(observedStates.contains(.established) == failure.establishes)
        #expect(observedStates.filter { $0 == .stopped }.count == 1)
        #expect(await session.sessionState() == .stopped)
        let rib = await session.ribSnapshot()
        #expect(rib.summaryLine == (failure.establishes ? "nodes=2 links=0 prefixes=2" : "nodes=0 links=0 prefixes=0"))
        #expect(await session.ribSummaryLine() == rib.summaryLine)
        #expect(diffs.count == (failure.establishes ? 4 : 0))
        var replay = LSRIB()
        for diff in diffs {
            switch diff {
            case .upsert(let record): replay.apply(record)
            case .withdraw(let nlri): replay.withdraw(nlri)
            case .snapshot: Issue.record("catch-up was disabled")
            }
        }
        #expect(replay == rib)
        if failure.establishes {
            #expect(
                rib.prefixes.values.map(\.nlri.network.description).sorted() == ["192.0.2.0/24", "2001:db8::/64"])
            #expect(rib.prefixes.values.allSatisfy { $0.attributes.metric == 10 })
        }
        try await channel.closeFuture.get()
        #expect(await notificationIterator.next() == nil)
        try Self.expectCompletePCAP(
            pcap, transport: transport, client: client, peer: peer,
            localHoldTime: failure.localHoldTime, peerOpen: failure.open,
            outboundMessages: failure.acceptsOpen ? .collector : .openOnly,
            inboundMessages: failure.establishes ? .establishedPeer : .openOnly,
            expectedNotification: failure.notification
        )
        try await server.close().get()
    }

    @Test(.timeLimit(.minutes(1)), arguments: LoopbackTransport.allCases, LoopbackBind.allCases)
    func bindChoiceDoesNotChangeSpeakerIdentifier(transport: LoopbackTransport, bind: LoopbackBind) async throws {
        //  Exercise the actual selected source address, including wildcard resolution,
        // while proving the configured OPEN identifier never depends on bind selection.
        switch transport {
        case .ipv4:
            try await establishedSession(
                termination: .normalClose, transport: transport,
                loopback: #require(IPv4Address(transport.host)), bind: bind
            )
        case .ipv6:
            try await establishedSession(
                termination: .normalClose, transport: transport,
                loopback: #require(IPv6Address(transport.host)), bind: bind
            )
        }
    }

    @Test(.timeLimit(.minutes(1)), arguments: LoopbackUpdateFault.allCases, LoopbackTransport.allCases)
    func updateFaultsPreserveRawObservationAndDrainCleanup(
        fault: LoopbackUpdateFault, transport: LoopbackTransport
    ) async throws {
        switch transport {
        case .ipv4:
            try await updateFaults(fault: fault, transport: transport, loopback: #require(IPv4Address(transport.host)))
        case .ipv6:
            try await updateFaults(fault: fault, transport: transport, loopback: #require(IPv6Address(transport.host)))
        }
    }

    @Test(
        .timeLimit(.minutes(1)), arguments: [LoopbackUpdateFault.duplicateReach, .duplicateUnreach],
        LoopbackTransport.allCases
    )
    func duplicateMPFailureSurvivesImmediatePeerClosure(
        fault: LoopbackUpdateFault, transport: LoopbackTransport
    ) async throws {
        switch transport {
        case .ipv4:
            try await updateFaults(
                fault: fault, transport: transport, loopback: #require(IPv4Address(transport.host)),
                waitForNotification: false
            )
        case .ipv6:
            try await updateFaults(
                fault: fault, transport: transport, loopback: #require(IPv6Address(transport.host)),
                waitForNotification: false
            )
        }
    }

    private func updateFaults<Family: IPAddressFamily>(
        fault: LoopbackUpdateFault, transport: LoopbackTransport, loopback: IPAddress<Family>,
        waitForNotification: Bool = true
    ) async throws {
        let (accepted, acceptedContinuation) = AsyncStream.makeStream(of: Channel.self)
        let (notifications, notificationContinuation) = AsyncStream.makeStream(of: BGPNotificationMessage.self)
        defer { notificationContinuation.finish() }
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(BGPMessageDecoder()))
                    try channel.pipeline.syncOperations.addHandler(MessageToByteHandler(BGPMessageEncoder()))
                    try channel.pipeline.syncOperations.addHandler(
                        LoopbackPeerHandler(
                            onNotification: { notificationContinuation.yield($0) },
                            onInactive: { notificationContinuation.finish() }
                        )
                    )
                    acceptedContinuation.yield(channel)
                }
            }
            .bind(to: SocketAddress(ipAddress: transport.host, port: 0)).get()
        defer {
            server.close(promise: nil)
            acceptedContinuation.finish()
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let pcap = directory.appendingPathComponent("update-fault.pcap")
        let peerPort = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: loopback, port: peerPort),
                localAS: AutonomousSystemNumber(65001), peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.37")),
                localAddress: loopback, connectTimeout: .seconds(5)
            )
        )
        let changes = await session.ribChanges(includeCatchUpSnapshot: false)
        let (observedChanges, changeContinuation) = AsyncStream.makeStream(of: RIBDiff.self)
        let watcher = Task {
            defer { changeContinuation.finish() }
            var diffs: [RIBDiff] = []
            for await diff in changes {
                diffs.append(diff)
                changeContinuation.yield(diff)
            }
            return diffs
        }
        defer { watcher.cancel() }
        let (rawBodies, rawContinuation) = AsyncStream.makeStream(of: ByteBuffer.self)
        defer { rawContinuation.finish() }
        let runner = Task {
            try await session.run(pcapPath: pcap.path, onUpdate: { rawContinuation.yield($0) })
        }
        defer { runner.cancel() }
        var acceptedIterator = accepted.makeAsyncIterator()
        let channel = try #require(await acceptedIterator.next())
        defer { channel.close(promise: nil) }
        let clientAddress = try #require(channel.remoteAddress)
        let peerAddress = try #require(channel.localAddress)
        var changeIterator = observedChanges.makeAsyncIterator()
        _ = try #require(await changeIterator.next())
        #expect(await session.sessionState() == .established)

        let first = LoopbackUpdateFaultFixture.prefix(type: 3, reachability: [24, 192, 0, 2])
        let second = LoopbackUpdateFaultFixture.prefix(type: 3, reachability: [24, 198, 51, 100])
        let priorBody = LoopbackUpdateFaultFixture.update(reaches: first, linkState: [4, 131, 0, 4, 0, 0, 0, 10])
        let triggeringBody: ByteBuffer
        switch fault {
        case .recoverableContent:
            let malformed = LoopbackUpdateFaultFixture.prefix(type: 4, reachability: [129])
            triggeringBody = LoopbackUpdateFaultFixture.update(reaches: first + malformed)
        case .recoverableAttributeFraming:
            triggeringBody = LoopbackUpdateFaultFixture.update(reaches: first, linkState: [4, 131, 0, 4, 0])
        case .recoverableAttributeProjection:
            triggeringBody = LoopbackUpdateFaultFixture.update(reaches: first, linkState: [4, 131, 0, 1, 10])
        case .truncatedNLRI:
            triggeringBody = LoopbackUpdateFaultFixture.update(reaches: second + [0, 4, 0, 100])
        case .truncatedWithdrawal:
            triggeringBody = LoopbackUpdateFaultFixture.update(reaches: second, withdrawals: [0, 4, 0, 100])
        case .truncatedUpdate:
            triggeringBody = ByteBuffer(bytes: [0])
        case .duplicateReach:
            triggeringBody = LoopbackUpdateFaultFixture.update(reaches: second, duplicateTypeCode: 14)
        case .duplicateUnreach:
            triggeringBody = LoopbackUpdateFaultFixture.update(
                reaches: second, withdrawals: first, duplicateTypeCode: 15
            )
        }
        //  Do not wait for actor processing between these writes and peer closure.
        // The prior update must drain, but fatal preparation must win the terminal result.
        if fault.duplicateTypeCode != nil {
            let laterBody = LoopbackUpdateFaultFixture.update(reaches: second)
            // Queue a later valid message in the same flush; terminal rejection must prevent its observation.
            try await channel.eventLoop.flatSubmit {
                channel.write(BGPMessage.update(priorBody), promise: nil)
                channel.write(BGPMessage.update(triggeringBody), promise: nil)
                return channel.writeAndFlush(BGPMessage.update(laterBody))
            }.get()
        } else {
            try await channel.writeAndFlush(BGPMessage.update(priorBody)).get()
            try await channel.writeAndFlush(BGPMessage.update(triggeringBody)).get()
        }
        var expectedBodies = [LoopbackPeerHandler.nodeUpdate, priorBody, triggeringBody]
        if fault.isRecoverable {
            let laterBody = LoopbackUpdateFaultFixture.update(reaches: second, linkState: [4, 131, 0, 4, 0, 0, 0, 20])
            try await channel.writeAndFlush(BGPMessage.update(laterBody)).get()
            expectedBodies.append(laterBody)
            var sawLater = false
            while let diff = await changeIterator.next() {
                if diff.watchLine.contains("198.51.100.0/24") {
                    sawLater = true
                    break
                }
            }
            #expect(sawLater)
            #expect(await session.sessionState() == .established)
        }
        let expectedNotification = BGPNotificationMessage(errorCode: 3, errorSubcode: 1)
        var notificationIterator = notifications.makeAsyncIterator()
        if fault.duplicateTypeCode != nil && waitForNotification {
            // Observe delivery before closing the peer; a successful local write alone cannot prove receipt.
            #expect(try #require(await notificationIterator.next()) == expectedNotification)
        }
        // The client's fatal close can win this race; either way wait for actual cleanup below.
        try? await channel.close().get()
        let result = await runner.result
        let diffs = await watcher.value
        rawContinuation.finish()
        var observedBodies: [ByteBuffer] = []
        for await body in rawBodies { observedBodies.append(body) }
        #expect(observedBodies == expectedBodies)
        #expect(observedBodies.filter { $0 == triggeringBody }.count == 1)
        let rib = await session.ribSnapshot()
        #expect(await session.ribSummaryLine() == rib.summaryLine)
        #expect(rib.nodeCount == 2)
        #expect(rib.prefixCount == (fault.isRecoverable ? 2 : 1))
        #expect(rib.prefixes.values.map(\.nlri).contains { $0.network.description == "192.0.2.0/24" })
        let firstRecord = try #require(rib.prefixes.values.first { $0.nlri.network.description == "192.0.2.0/24" })
        #expect(firstRecord.attributes.metric == (fault.isRecoverable ? nil : 10))
        if fault == .recoverableAttributeFraming { #expect(firstRecord.observation.availability == .discarded) }
        if fault == .recoverableAttributeProjection { #expect(firstRecord.observation.availability == .present) }
        if fault.isRecoverable {
            let laterRecord = try #require(
                rib.prefixes.values.first { $0.nlri.network.description == "198.51.100.0/24" })
            #expect(laterRecord.attributes.metric == 20)
        }
        var replay = LSRIB()
        for diff in diffs {
            switch diff {
            case .upsert(let nlri): replay.apply(nlri)
            case .withdraw(let nlri): replay.withdraw(nlri)
            case .snapshot: Issue.record("catch-up was disabled")
            }
        }
        #expect(replay == rib)
        #expect(await session.sessionState() == .stopped)
        if fault.duplicateTypeCode != nil && waitForNotification {
            #expect(await notificationIterator.next() == nil)
            #expect(diffs.count == 3)
        }
        if fault.isRecoverable {
            try result.get()
        } else {
            guard case .failure(let error) = result else {
                Issue.record("fatal framing followed by peer closure must fail the session")
                return
            }
            if let typeCode = fault.duplicateTypeCode {
                #expect(error as? BGPLSClientError == .duplicateMultiprotocolAttribute(typeCode: typeCode))
            } else {
                guard case .protocolError(let detail) = error as? BGPLSClientError else {
                    Issue.record("expected the original framing error, got \(error)")
                    return
                }
                switch fault {
                case .truncatedNLRI: #expect(detail.contains("MP_REACH"))
                case .truncatedWithdrawal: #expect(detail.contains("MP_UNREACH"))
                case .truncatedUpdate: #expect(detail.contains("UPDATE"))
                case .recoverableContent, .recoverableAttributeFraming, .recoverableAttributeProjection,
                    .duplicateReach, .duplicateUnreach:
                    Issue.record("expected a fatal framing test case")
                }
            }
            #expect(!(error is CancellationError))
        }
        try Self.expectCompletePCAP(
            pcap, transport: transport, client: clientAddress, peer: peerAddress,
            expectedNotification: fault.duplicateTypeCode != nil && waitForNotification ? expectedNotification : nil
        )
        try await channel.closeFuture.get()
        try await server.close().get()
    }

    private static func expectCompletePCAP(
        _ url: URL, transport: LoopbackTransport, client: SocketAddress, peer: SocketAddress,
        localAS: AutonomousSystemNumber = AutonomousSystemNumber(65001),
        localHoldTime: UInt16 = 90,
        peerOpen: BGPOpenMessage = LoopbackPeerHandler.open,
        outboundMessages: LoopbackPCAPMessages = .collector,
        inboundMessages: LoopbackPCAPMessages = .establishedPeer,
        expectedNotification: BGPNotificationMessage? = nil
    ) throws {
        var bytes = ByteBuffer(bytes: try Data(contentsOf: url))
        let magic = bytes.readInteger(endianness: .host, as: UInt32.self)
        #expect(magic == 0xa1b2_c3d4)
        let majorVersion = bytes.readInteger(endianness: .host, as: UInt16.self)
        let minorVersion = bytes.readInteger(endianness: .host, as: UInt16.self)
        let headerFields = bytes.readSlice(length: 12)
        let linkType = bytes.readInteger(endianness: .host, as: UInt32.self)
        #expect(majorVersion == 2)
        #expect(minorVersion == 4)
        _ = try #require(headerFields)
        #expect(linkType == 0)
        var records = 0
        var syns = 0
        var fins = 0
        var outbound: [UInt8] = []
        var inbound: [UInt8] = []
        let clientPort = try #require(client.port.flatMap(UInt16.init(exactly:)))
        let peerPort = try #require(peer.port.flatMap(UInt16.init(exactly:)))
        #expect(clientPort != peerPort)
        while bytes.readableBytes > 0 {
            let timestamp = bytes.readSlice(length: 8)
            _ = try #require(timestamp)
            let includedValue = bytes.readInteger(endianness: .host, as: UInt32.self)
            let originalValue = bytes.readInteger(endianness: .host, as: UInt32.self)
            let included = try #require(includedValue)
            let original = try #require(originalValue)
            #expect(included == original)
            let recordBytes = bytes.readSlice(length: Int(included))
            var record = try #require(recordBytes)
            //  NIO's synthesized DLT_NULL captures use fixed family values 2/24,
            // including on Linux. Validate IP/TCP framing and real socket endpoints, not
            // just a non-empty file (which could hide an IPv4 fallback or unfinished sink).
            let family = record.readInteger(endianness: .host, as: UInt32.self)
            #expect(family == transport.pcapFamily)
            let ipLength = record.readableBytes
            let firstByte = try #require(record.getInteger(at: record.readerIndex, as: UInt8.self))
            #expect(firstByte >> 4 == transport.version)
            let headerLength: Int
            let sourceOffset: Int
            switch transport {
            case .ipv4:
                headerLength = 20
                sourceOffset = 12
                #expect(firstByte == 0x45)
                #expect(record.getInteger(at: record.readerIndex + 2, as: UInt16.self) == UInt16(ipLength))
                #expect(record.getInteger(at: record.readerIndex + 6, as: UInt16.self) == 0x4000)
                #expect(record.getInteger(at: record.readerIndex + 9, as: UInt8.self) == 6)
            case .ipv6:
                headerLength = 40
                sourceOffset = 8
                #expect(record.getInteger(at: record.readerIndex + 4, as: UInt16.self) == UInt16(ipLength - 40))
                #expect(record.getInteger(at: record.readerIndex + 6, as: UInt8.self) == 6)
            }
            let addressLength = transport.addressBytes.count
            let source = record.getBytes(at: record.readerIndex + sourceOffset, length: addressLength)
            let destination = record.getBytes(
                at: record.readerIndex + sourceOffset + addressLength, length: addressLength)
            #expect(source == transport.addressBytes)
            #expect(destination == transport.addressBytes)
            let ipHeader = record.readSlice(length: headerLength)
            _ = try #require(ipHeader)
            let sourcePort = try #require(record.getInteger(at: record.readerIndex, as: UInt16.self))
            let destinationPort = try #require(record.getInteger(at: record.readerIndex + 2, as: UInt16.self))
            let offset = try #require(record.getInteger(at: record.readerIndex + 12, as: UInt8.self))
            #expect(offset >> 4 == 5)
            let flags = try #require(record.getInteger(at: record.readerIndex + 13, as: UInt8.self))
            if flags & 0x02 != 0 { syns += 1 }
            if flags & 0x01 != 0 { fins += 1 }
            let tcpHeader = record.readSlice(length: 20)
            _ = try #require(tcpHeader)
            if sourcePort == clientPort {
                #expect(destinationPort == peerPort)
                outbound.append(contentsOf: record.readableBytesView)
            } else {
                #expect(sourcePort == peerPort)
                #expect(destinationPort == clientPort)
                inbound.append(contentsOf: record.readableBytesView)
            }
            records += 1
        }
        #expect(records > 0)
        #expect(syns == 2)
        #expect(fins == 2)
        try expectCompleteBGPStream(
            outbound, identifier: 0xc000_0225,
            legacyAS: UInt16(exactly: localAS.rawValue) ?? 23_456,
            holdTime: localHoldTime,
            capabilities: BGPOpenCapabilities.bgpLS(localAS: localAS),
            expectedMessages: outboundMessages,
            expectedNotification: expectedNotification
        )
        try expectCompleteBGPStream(
            inbound, identifier: 0xc000_02fe,
            legacyAS: peerOpen.myAS, holdTime: peerOpen.holdTime, capabilities: peerOpen.optionalParameters,
            expectedMessages: inboundMessages
        )
    }

    private static func expectCompleteBGPStream(
        _ bytes: [UInt8], identifier: UInt32, legacyAS: UInt16, holdTime: UInt16, capabilities: [UInt8],
        expectedMessages: LoopbackPCAPMessages,
        expectedNotification: BGPNotificationMessage? = nil
    ) throws {
        var stream = ByteBuffer(bytes: bytes)
        var types: [UInt8] = []
        var notifications: [BGPNotificationMessage] = []
        while stream.readableBytes > 0 {
            let markerBytes = stream.readBytes(length: 16)
            let marker = try #require(markerBytes)
            #expect(marker == Array(repeating: 0xff, count: 16))
            let lengthField = stream.readInteger(as: UInt16.self)
            let typeField = stream.readInteger(as: UInt8.self)
            let length = try #require(lengthField)
            let type = try #require(typeField)
            try #require(length >= 19)
            let bodyBytes = stream.readSlice(length: Int(length) - 19)
            let body = try #require(bodyBytes)
            if types.isEmpty, expectedMessages.open {
                #expect(type == BGPMessageType.open.rawValue)
                #expect(body.getInteger(at: body.readerIndex + 5, as: UInt32.self) == identifier)
                guard case .open(let open) = try BGPMessageCodec.decodeBody(type: .open, body: body) else {
                    Issue.record("Expected an OPEN body")
                    return
                }
                #expect(open.myAS == legacyAS)
                #expect(open.holdTime == holdTime)
                #expect(open.optionalParameters == capabilities)
            }
            if type == BGPMessageType.notification.rawValue {
                guard case .notification(let note) = try BGPMessageCodec.decodeBody(type: .notification, body: body)
                else {
                    Issue.record("Expected a NOTIFICATION body")
                    return
                }
                notifications.append(note)
                if let expectedNotification {
                    let expectedBody =
                        [
                            expectedNotification.errorCode, expectedNotification.errorSubcode,
                        ] + expectedNotification.data
                    #expect(Int(length) == 19 + expectedBody.count)
                    #expect(Array(body.readableBytesView) == expectedBody)
                }
            }
            types.append(type)
        }
        #expect(types.contains(BGPMessageType.open.rawValue) == expectedMessages.open)
        #expect(types.contains(BGPMessageType.keepalive.rawValue) == expectedMessages.keepalive)
        #expect(types.contains(BGPMessageType.update.rawValue) == expectedMessages.update)
        if let expectedNotification {
            #expect(notifications == [expectedNotification])
            #expect(types.last == BGPMessageType.notification.rawValue)
        }
    }
}

private struct LoopbackPCAPMessages: Sendable {
    var open: Bool
    var keepalive: Bool
    var update: Bool

    static let collector = Self(open: true, keepalive: true, update: false)
    static let establishedPeer = Self(open: true, keepalive: true, update: true)
    static let openOnly = Self(open: true, keepalive: false, update: false)
}

enum LoopbackHoldFailure: CaseIterable, Sendable {
    case silentOpenConfirm, silentEstablished
    case oneSecondWithZeroLocal, twoSecondsWithZeroLocal
    case oneSecondWithDefaultLocal, twoSecondsWithDefaultLocal

    var localHoldTime: UInt16 {
        switch self {
        case .oneSecondWithZeroLocal, .twoSecondsWithZeroLocal: 0
        default: 90
        }
    }

    var peerHoldTime: UInt16 {
        switch self {
        case .oneSecondWithZeroLocal, .oneSecondWithDefaultLocal: 1
        case .twoSecondsWithZeroLocal, .twoSecondsWithDefaultLocal: 2
        case .silentOpenConfirm, .silentEstablished: 3
        }
    }

    var acceptsOpen: Bool { peerHoldTime == 3 }
    var establishes: Bool { self == .silentEstablished }

    var open: BGPOpenMessage {
        BGPOpenMessage(
            myAS: 65001, holdTime: peerHoldTime, bgpIdentifier: 0xc000_02fe,
            optionalParameters: BGPOpenCapabilities.multiprotocolBGPLS()
        )
    }

    var notification: BGPNotificationMessage {
        acceptsOpen
            ? BGPNotificationMessage(errorCode: 4, errorSubcode: 0)
            : BGPNotificationMessage(errorCode: 2, errorSubcode: 6)
    }

    var error: BGPLSClientError {
        acceptsOpen ? .holdTimerExpired : .unacceptableHoldTime(seconds: peerHoldTime)
    }
}

enum LoopbackBGPLSCapabilityFailure: CaseIterable, Sendable {
    case absent, ipv4Only, ipv6Only, vpnOnly, as4Only

    var asn: AutonomousSystemNumber {
        AutonomousSystemNumber(self == .as4Only ? 4_200_000_001 : 65001)
    }

    var open: BGPOpenMessage {
        let options: [UInt8]
        switch self {
        case .absent: options = []
        case .ipv4Only: options = [2, 6, 1, 4, 0, 1, 0, 1]
        case .ipv6Only: options = [2, 6, 1, 4, 0, 2, 0, 1]
        case .vpnOnly: options = [2, 6, 1, 4, 0x40, 4, 0, 72]
        case .as4Only: options = [2, 6, 65, 4, 250, 86, 234, 1]
        }
        return BGPOpenMessage(
            myAS: UInt16(exactly: asn.rawValue) ?? 23_456, holdTime: 0,
            bgpIdentifier: 0xc000_02fe, optionalParameters: options
        )
    }
}

enum LoopbackASNFailure: CaseIterable, Sendable {
    case missingCapability, wrongASN, zeroASN, malformedCapability

    var open: BGPOpenMessage {
        let options: [UInt8]
        switch self {
        case .missingCapability: options = BGPOpenCapabilities.multiprotocolBGPLS()
        case .wrongASN: options = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(4_200_000_002))
        case .zeroASN: options = BGPOpenCapabilities.bgpLS(localAS: AutonomousSystemNumber(0))
        case .malformedCapability: options = [2, 5, 65, 3, 0, 0, 1]
        }
        return BGPOpenMessage(myAS: 23_456, holdTime: 0, bgpIdentifier: 0xc000_02fe, optionalParameters: options)
    }
}

enum LoopbackASNs: CaseIterable, Sendable {
    case legacy, modernSmall, large, largeToLegacy, smallToLarge, largeToSmall

    var local: AutonomousSystemNumber {
        AutonomousSystemNumber(
            self == .large || self == .largeToLegacy || self == .largeToSmall ? 4_200_000_001 : 65001)
    }

    var peer: AutonomousSystemNumber {
        AutonomousSystemNumber(self == .large || self == .smallToLarge ? 4_200_000_001 : 65001)
    }

    var peerOpen: BGPOpenMessage {
        BGPOpenMessage(
            myAS: UInt16(exactly: peer.rawValue) ?? 23_456,
            holdTime: 0, bgpIdentifier: 0xc000_02fe,
            optionalParameters: self == .legacy || self == .largeToLegacy
                ? BGPOpenCapabilities.multiprotocolBGPLS() : BGPOpenCapabilities.bgpLS(localAS: peer)
        )
    }
}

enum LoopbackTransport: CaseIterable, Sendable {
    case ipv4
    case ipv6

    var host: String { self == .ipv4 ? "127.0.0.1" : "::1" }
    var wildcard: String { self == .ipv4 ? "0.0.0.0" : "::" }
    var version: UInt8 { self == .ipv4 ? 4 : 6 }
    var pcapFamily: UInt32 { self == .ipv4 ? 2 : 24 }
    var addressBytes: [UInt8] { self == .ipv4 ? [127, 0, 0, 1] : Array(repeating: 0, count: 15) + [1] }
}

enum LoopbackBind: CaseIterable, Sendable {
    case explicit
    case omitted
    case wildcard
}

enum LoopbackUpdateFault: CaseIterable, Sendable {
    case recoverableContent
    case recoverableAttributeFraming
    case recoverableAttributeProjection
    case truncatedNLRI
    case truncatedWithdrawal
    case truncatedUpdate
    case duplicateReach
    case duplicateUnreach

    var duplicateTypeCode: UInt8? {
        switch self {
        case .duplicateReach: 14
        case .duplicateUnreach: 15
        default: nil
        }
    }

    var isRecoverable: Bool {
        switch self {
        case .recoverableContent, .recoverableAttributeFraming, .recoverableAttributeProjection: true
        case .truncatedNLRI, .truncatedWithdrawal, .truncatedUpdate, .duplicateReach, .duplicateUnreach: false
        }
    }
}

private enum LoopbackUpdateFaultFixture {
    static func prefix(type: UInt16, reachability: [UInt8]) -> [UInt8] {
        var body = ByteBuffer()
        body.writeInteger(UInt8(2))
        body.writeInteger(UInt64(0))
        body.writeInteger(UInt16(256))
        body.writeInteger(UInt16(10))
        body.writeInteger(UInt16(515))
        body.writeInteger(UInt16(6))
        body.writeBytes([0, 0, 0, 0, 0, 1])
        body.writeInteger(UInt16(265))
        body.writeInteger(UInt16(reachability.count))
        body.writeBytes(reachability)
        var nlri = ByteBuffer()
        nlri.writeInteger(type)
        nlri.writeInteger(UInt16(body.readableBytes))
        nlri.writeBuffer(&body)
        return Array(nlri.readableBytesView)
    }

    static func update(
        reaches: [UInt8], withdrawals: [UInt8]? = nil, linkState: [UInt8]? = nil,
        duplicateTypeCode: UInt8? = nil
    ) -> ByteBuffer {
        var attributes = ByteBuffer()
        appendAttribute(code: 14, nlris: reaches, into: &attributes)
        if let withdrawals { appendAttribute(code: 15, nlris: withdrawals, into: &attributes) }
        if let linkState {
            attributes.writeInteger(UInt8(0x90))
            attributes.writeInteger(UInt8(29))
            attributes.writeInteger(UInt16(linkState.count))
            attributes.writeBytes(linkState)
        }
        if let duplicateTypeCode {
            appendAttribute(
                code: duplicateTypeCode, nlris: duplicateTypeCode == 14 ? reaches : withdrawals ?? [], into: &attributes
            )
        }
        var body = ByteBuffer()
        body.writeInteger(UInt16(0))
        body.writeInteger(UInt16(attributes.readableBytes))
        body.writeBuffer(&attributes)
        return body
    }

    private static func appendAttribute(code: UInt8, nlris: [UInt8], into attributes: inout ByteBuffer) {
        var value = ByteBuffer()
        value.writeInteger(UInt16(16_388))
        value.writeInteger(UInt8(71))
        if code == 14 { value.writeBytes([4, 192, 0, 2, 254, 0]) }
        value.writeBytes(nlris)
        attributes.writeInteger(UInt8(0x90))
        attributes.writeInteger(code)
        attributes.writeInteger(UInt16(value.readableBytes))
        attributes.writeBuffer(&value)
    }
}

enum LoopbackTermination: CaseIterable, Sendable {
    case sigint
    case sigterm
    case normalClose
    case notification
    case unexpectedOpen
    case directStop
    case parentCancellation
}

/// A deterministic BGP peer, confined to the accepted channel's event loop.
private final class LoopbackPeerHandler: ChannelInboundHandler {
    typealias InboundIn = BGPMessage

    static let open = BGPOpenMessage(
        myAS: 65001,
        holdTime: 0,
        bgpIdentifier: 0xC000_02FE,
        optionalParameters: BGPOpenCapabilities.multiprotocolBGPLS()
    )

    private var sentUpdate = false
    private let sendMixedFamilyPrefixes: Bool
    private let peerOpen: BGPOpenMessage
    private let closeAfterOpen: Bool
    private let completeHandshake: Bool
    private let onOpen: @Sendable (BGPOpenMessage) -> Void
    private let onNotification: @Sendable (BGPNotificationMessage) -> Void
    private let onInactive: @Sendable () -> Void

    init(
        sendMixedFamilyPrefixes: Bool = false, peerOpen: BGPOpenMessage = LoopbackPeerHandler.open,
        closeAfterOpen: Bool = false, completeHandshake: Bool = true,
        onOpen: @escaping @Sendable (BGPOpenMessage) -> Void = { _ in },
        onNotification: @escaping @Sendable (BGPNotificationMessage) -> Void = { _ in },
        onInactive: @escaping @Sendable () -> Void = {}
    ) {
        self.sendMixedFamilyPrefixes = sendMixedFamilyPrefixes
        self.peerOpen = peerOpen
        self.closeAfterOpen = closeAfterOpen
        self.completeHandshake = completeHandshake
        self.onOpen = onOpen
        self.onNotification = onNotification
        self.onInactive = onInactive
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .open(let open):
            onOpen(open)
            if closeAfterOpen {
                let channel = context.channel
                context.writeAndFlush(NIOAny(BGPMessage.open(peerOpen))).whenComplete { _ in
                    channel.close(promise: nil)
                }
            } else {
                context.writeAndFlush(NIOAny(BGPMessage.open(peerOpen)), promise: nil)
            }
        case .keepalive where completeHandshake && !sentUpdate:
            sentUpdate = true
            context.write(NIOAny(BGPMessage.keepalive), promise: nil)
            context.write(NIOAny(BGPMessage.update(Self.nodeUpdate)), promise: nil)
            if sendMixedFamilyPrefixes {
                context.write(NIOAny(BGPMessage.update(Self.mixedFamilyUpdate)), promise: nil)
            }
            context.flush()
        case .notification(let note):
            onNotification(note)
        default:
            break
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        onInactive()
        context.fireChannelInactive()
    }

    static var mixedFamilyUpdate: ByteBuffer {
        let v4 = LoopbackUpdateFaultFixture.prefix(type: 3, reachability: [24, 192, 0, 2])
        let v6 = LoopbackUpdateFaultFixture.prefix(
            type: 4, reachability: [64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0])
        return LoopbackUpdateFaultFixture.update(reaches: v4 + v6, linkState: [4, 131, 0, 4, 0, 0, 0, 10])
    }

    // The synthetic two-node OSPF UPDATE fixture is also covered by
    // BGPUpdateParserTests; send its wire body through the real client decoder here.
    static var nodeUpdate: ByteBuffer {
        let bytes: [UInt8] = [
            0x00, 0x00, 0x00, 0x7b, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x00,
            0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x80, 0x1d, 0x0b,
            0x01, 0x07, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00,
            0x90, 0x0e, 0x00, 0x5b, 0x40, 0x04, 0x47, 0x04, 0xc0, 0x00, 0x02, 0xfe, 0x00,
            0x00, 0x01, 0x00, 0x25, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x18, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe9,
            0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x02,
            0x00, 0x01, 0x00, 0x25, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x18, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe9,
            0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
        ]
        return ByteBuffer(bytes: bytes)
    }
}
