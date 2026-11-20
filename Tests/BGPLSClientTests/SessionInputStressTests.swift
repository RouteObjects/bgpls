//===----------------------------------------------------------------------===//
// This source file is part of the bgpls project.
// Copyright (c) 2026 Craig A. Munro
// Licensed under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//===----------------------------------------------------------------------===//

import CIDR
import Dispatch
import Foundation
import NIOCore
import NIOPosix
import Testing

@testable import BGPLSClient

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// Opt-in measurements, not a throughput assertion or a vendor qualification.
/// Each selected case runs in its own process under scripts/backpressure-stress.sh.
struct SessionInputStressTests {
    @Test(
        .enabled(
            if: ProcessInfo.processInfo.environment["BGPLS_BACKPRESSURE_CASE"] != nil,
            "Run scripts/backpressure-stress.sh to collect bounded synthetic evidence"
        ), .timeLimit(.minutes(2)))
    func selectedCase() async throws {
        let environment = ProcessInfo.processInfo.environment
        let name = try #require(environment["BGPLS_BACKPRESSURE_CASE"])
        let output = try #require(environment["BGPLS_BACKPRESSURE_OUTPUT"])
        guard output.hasPrefix("/"), !FileManager.default.fileExists(atPath: output) else {
            throw StressFailure("Output must be a fresh absolute path")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data
        if name == "copy-cost" {
            data = try encoder.encode(StressCopyCost.measure())
        } else {
            #if BGPLS_LEGACY_BASELINE
                let result = try await legacyComparison(name: name)
            #else
                let result = try await NativeStressRun.run(try StressCase(name: name))
            #endif
            data = try encoder.encode(result)
        }
        try data.write(to: URL(fileURLWithPath: output), options: .withoutOverwriting)
    }

    @Test
    func syntheticReferenceHasDistinctDirectedLinksAndDualStackPrefixes() throws {
        let topology = StressTopology(nodes: 7, connections: 9)
        var rib = LSRIB()
        for index in 0..<topology.objectCount {
            let body = topology.body(at: index, sentAt: 0)
            try rib.apply(update: BGPUpdateParser.parse(body))
        }
        #expect(rib.nodeCount == 7)
        #expect(rib.linkCount == 18)
        #expect(rib.prefixCount == 14)
        #expect(StressTopology.reference.objectCount == 61_587)
        #expect(StressTopology.large.objectCount == 615_870)
        #expect(StressTopology.minimumBody.readableBytes + 19 == 23)
        #expect(StressTopology.maximumBody(sentAt: 1).readableBytes + 19 == 4096)
        #expect(try BGPUpdateParser.parse(StressTopology.maximumBody(sentAt: 1)).pathAttributes.count == 2)
    }

    @Test
    func measurementReportSeparatesWorkloadAndSessionProbeScopes() async throws {
        let metrics = StressMetrics()
        await metrics.consume(BGPLSUpdateObservation(rawBody: StressTopology.reference.body(at: 0, sentAt: 0)))
        await metrics.beginMeasurement()
        await metrics.consume(BGPLSUpdateObservation(rawBody: StressTopology.reference.body(at: 1, sentAt: 0)))
        let result = await metrics.result(
            name: "measurement-scope", started: 0, peakPending: 2, readRequests: 3,
            maximumReadGapNanoseconds: 4, timedOut: false, notes: [])
        let recorded = try JSONDecoder().decode(StressResult.self, from: JSONEncoder().encode(result))
        #expect(recorded.processed == 1)
        #expect(recorded.nodes == 2)
        #expect(
            recorded.measurementScope.pendingAndReadCounters == "sessionLifetimeIncludingHandshakeSeedingAndTeardown")
        #expect(recorded.measurementScope.workload == "afterHandshakeAndSeedingThroughDrainAndTeardown")
        #expect(recorded.measurementScope.consumer == "testActorCallingLSRIBCommit")
        #expect(recorded.measurementScope.excludedWork.contains("BGPSessionCallbacks"))
        #expect(recorded.measurementScope.excludedWork.contains("RIBDiffBroadcastAndWatchDelivery"))
        #expect(recorded.measurementScope.excludedWork.contains("CLIRenderingAndDiagnosticLogging"))
        #expect(recorded.measurementScope.excludedWork.contains("PCAP"))
    }

    #if BGPLS_LEGACY_BASELINE
        /// Compiles against the exact main baseline, using its actual old processor.
        /// This measures the bridge alone; it is deliberately not called a TCP benchmark.
        private func legacyComparison(name: String) async throws -> StressResult {
            guard name == "bridge-baseline" else { throw StressFailure("Baseline supports bridge-baseline only") }
            let metrics = StressMetrics(delay: .milliseconds(1))
            await metrics.beginMeasurement(pause: .seconds(2))
            let processor = SessionUpdateProcessor<BGPLSUpdateObservation> { observation in
                await metrics.consume(observation)
            }
            let started = DispatchTime.now().uptimeNanoseconds
            for _ in 0..<10_000 {
                let body = StressTopology.reference.body(at: 0, sentAt: DispatchTime.now().uptimeNanoseconds)
                processor.yield(BGPLSUpdateObservation(rawBody: body))
            }
            let sampledOutstanding = 10_000 - (await metrics.completedCount())
            await processor.finish()
            return await metrics.result(
                name: name, started: started, peakPending: nil, readRequests: nil,
                maximumReadGapNanoseconds: nil, timedOut: false, sampledOutstandingAfterProduction: sampledOutstanding,
                measurementScope: .legacyBridge,
                notes: [
                    "Actual f25a74e SessionUpdateProcessor; bridge-only 10000 UPDATE burst with 1ms consumer delay.",
                    "Same 10000 one-node bodies/1ms handler/2s initial pause as bridge-native; baseline producer is eager.",
                    "No socket, native read gate, compact copy, credit hop, or capacity guard; throughput is not directly comparable.",
                    "sampledOutstandingAfterProduction = offered minus completed at one post-production actor sample; not an internal peak.",
                ]
            )
        }
    #endif
}

private struct StressFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Isolates the exact compact-copy operation used by the handler. No parser,
/// actor hop, or socket is involved, and the checksum keeps the result observable.
private enum StressCopyCost {
    struct Sample: Encodable {
        let method: String
        let bodyBytes: Int
        let iterations: Int
        let elapsedNanoseconds: UInt64
        let nanosecondsPerOperation: Double
        let checksum: UInt64
    }

    struct Report: Encodable {
        let name = "copy-cost"
        let timedOut = false
        let toolchainRecord = "toolchain.txt (written by backpressure-stress.sh)"
        let samples: [Sample]
        let notes = [
            "100000 operations per body size/method; consume is not inlined.",
            "Compact copy matches allocator.buffer(capacity:) plus writeImmutableBuffer in the FSM.",
            "Retain-only measures the previous no-copy operation; this does not measure allocations or full-session throughput.",
        ]
    }

    static func measure() -> Report {
        let allocator = ByteBufferAllocator()
        var samples: [Sample] = []
        for body in [StressTopology.minimumBody, StressTopology.maximumBody(sentAt: 1)] {
            for copying in [false, true] {
                var checksum: UInt64 = 0
                let start = DispatchTime.now().uptimeNanoseconds
                for _ in 0..<100_000 {
                    if copying {
                        var compact = allocator.buffer(capacity: body.readableBytes)
                        compact.writeImmutableBuffer(body)
                        consume(compact, checksum: &checksum)
                    } else {
                        consume(body, checksum: &checksum)
                    }
                }
                let elapsed = DispatchTime.now().uptimeNanoseconds - start
                samples.append(
                    .init(
                        method: copying ? "compact-copy" : "retain-only", bodyBytes: body.readableBytes,
                        iterations: 100_000, elapsedNanoseconds: elapsed,
                        nanosecondsPerOperation: Double(elapsed) / 100_000, checksum: checksum))
            }
        }
        return Report(samples: samples)
    }

    @inline(never)
    private static func consume(_ buffer: ByteBuffer, checksum: inout UInt64) {
        let first: UInt8 = buffer.getInteger(at: buffer.readerIndex) ?? 0
        let last: UInt8 = buffer.getInteger(at: buffer.writerIndex - 1) ?? 0
        checksum &+= UInt64(buffer.readableBytes) + UInt64(first) + UInt64(last)
    }
}

private struct StressTopology: Sendable {
    let nodes: Int
    let connections: Int
    static let reference = Self(nodes: 11_403, connections: 13_689)
    static let large = Self(nodes: 114_030, connections: 136_890)
    var objectCount: Int { nodes * 3 + connections * 2 }

    /// A generated ring with extra chords, not a reconstruction of AT&T's graph.
    func body(at index: Int, sentAt: UInt64) -> ByteBuffer {
        let index = index % objectCount
        let type: UInt16
        let descriptors: [BGPLSTLV]
        if index < nodes {
            type = 1
            descriptors = [node(index)]
        } else if index < nodes + connections * 2 {
            type = 2
            let directed = index - nodes
            let edge = directed / 2
            let first = edge < nodes ? edge : edge - nodes
            let second = (first + (edge < nodes ? 1 : 2)) % nodes
            let local = directed % 2 == 0 ? first : second
            let remote = directed % 2 == 0 ? second : first
            let localID = UInt32(edge * 2 + (directed % 2 == 0 ? 1 : 2))
            let remoteID = UInt32(edge * 2 + (directed % 2 == 0 ? 2 : 1))
            descriptors = [
                node(local), node(remote, type: 257),
                .init(type: 258, value: bytes(localID) + bytes(remoteID)),
            ]
        } else {
            let offset = index - nodes - connections * 2
            let nodeIndex = offset % nodes
            let v6 = offset >= nodes
            type = v6 ? 4 : 3
            let address: [UInt8] =
                v6
                ? [0x20, 1, 0x0d, 0xb8] + Array(repeating: 0, count: 8) + bytes(UInt32(nodeIndex + 1))
                : bytes(UInt32(0x0a00_0000) + UInt32(nodeIndex + 1))
            descriptors = [node(nodeIndex), .init(type: 265, value: [v6 ? 128 : 32] + address)]
        }
        let nlri = IPv6TopologyFixture.wire(type: type, descriptors: descriptors, identifier: 1)
        var reach = ByteBuffer(bytes: [0x40, 0x04, 71, 4, 192, 0, 2, 1, 0])
        reach.writeBytes(nlri)
        var attributes = Self.timestamp(sentAt)
        Self.appendAttribute(type: 14, value: Array(reach.readableBytesView), to: &attributes)
        let typed = IPv6TopologyFixture.encode([
            .init(type: 1026, value: Array("synthetic".utf8)),
            .init(type: 1095, value: [0, 0, 10]),
            .init(type: 1155, value: [0, 0, 0, 100]),
            .init(type: 1089, value: bytes(Float(125_000_000).bitPattern)),
        ])
        Self.appendAttribute(type: 29, value: typed, to: &attributes)
        return Self.update(attributes)
    }

    private func node(_ index: Int, type: UInt16 = 256) -> BGPLSTLV {
        .init(
            type: type,
            value: IPv6TopologyFixture.encode([
                .init(type: 512, value: bytes(UInt32(4_200_000_001))),
                .init(type: 515, value: [0, 0] + bytes(UInt32(index + 1))),
            ]))
    }

    static var minimumBody: ByteBuffer { ByteBuffer(bytes: [0, 0, 0, 0]) }

    static func maximumBody(sentAt: UInt64) -> ByteBuffer {
        var attributes = Self.timestamp(sentAt)
        appendAttribute(type: 201, value: Array(repeating: 0, count: 4058), to: &attributes)
        return Self.update(attributes)
    }

    /// Unknown optional attributes carry test timing only; they do not alter RIB identity.
    private static func timestamp(_ value: UInt64) -> ByteBuffer {
        var buffer = ByteBuffer(bytes: [0x80, 200, 8])
        buffer.writeInteger(value)
        return buffer
    }

    private static func appendAttribute(type: UInt8, value: [UInt8], to buffer: inout ByteBuffer) {
        buffer.writeInteger(UInt8(0x90))
        buffer.writeInteger(type)
        buffer.writeInteger(UInt16(value.count))
        buffer.writeBytes(value)
    }

    private static func update(_ attributes: ByteBuffer) -> ByteBuffer {
        var body = ByteBuffer()
        body.writeInteger(UInt16(0))
        body.writeInteger(UInt16(attributes.readableBytes))
        body.writeImmutableBuffer(attributes)
        return body
    }

    private func bytes(_ value: UInt32) -> [UInt8] { Self.bytes(value) }
    private static func bytes(_ value: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value),
        ]
    }
}

/// Keep scope alongside the numbers: the native probe is never reset after seeding.
/// These labels preserve the meaning of existing fields and historical measurements.
private struct StressMeasurementScope: Codable, Sendable {
    let workload: String
    let pendingAndReadCounters: String?
    let residentMemory: String
    let consumer: String
    let excludedWork: [String]

    static let native = Self(
        workload: "afterHandshakeAndSeedingThroughDrainAndTeardown",
        pendingAndReadCounters: "sessionLifetimeIncludingHandshakeSeedingAndTeardown")
    static let nativeMultiSession = Self(
        workload: "earliestSessionMeasurementStartThroughLatestSessionFinish",
        pendingAndReadCounters: "sessionLifetimeIncludingHandshakeSeedingAndTeardown")
    static let legacyBridge = Self(
        workload: "beforeEagerProductionThroughProcessorDrain", pendingAndReadCounters: nil)

    private init(workload: String, pendingAndReadCounters: String?) {
        self.workload = workload
        self.pendingAndReadCounters = pendingAndReadCounters
        residentMemory = "sampledProcessWideRSSDuringWorkloadWindow"
        consumer = "testActorCallingLSRIBCommit"
        excludedWork = [
            "BGPSessionCallbacks", "RIBDiffBroadcastAndWatchDelivery", "CLIRenderingAndDiagnosticLogging", "PCAP",
        ]
    }
}

private struct StressResult: Codable, Sendable {
    let name: String
    let startedMonotonicNanoseconds: UInt64
    let finishedMonotonicNanoseconds: UInt64
    let elapsedSeconds: Double
    let processed: Int
    let updatesPerSecond: Double
    let sendToCommitP50Milliseconds: Double?
    let sendToCommitP95Milliseconds: Double?
    let sendToCommitP99Milliseconds: Double?
    let peakPending: Int?
    let sampledOutstandingAfterProduction: Int?
    let readRequests: Int?
    let maximumReadGapMilliseconds: Double?
    let residentStartBytes: UInt64?
    let residentPeakBytes: UInt64?
    let residentEndBytes: UInt64?
    let nodes: Int
    let links: Int
    let prefixes: Int
    let timedOut: Bool
    let failure: String?
    let sessions: [StressResult]?
    let measurementScope: StressMeasurementScope
    let notes: [String]
}

private actor StressMetrics {
    private var rib = LSRIB()
    private let delay: Duration
    private var total = 0
    private var measured = 0
    private var measuring = false
    private var terminated = false
    private var waiters: [(Int, CheckedContinuation<Bool, Never>)] = []
    // A fixed-size logarithmic histogram avoids retaining one timing sample per UPDATE.
    private var histogram = Array(repeating: 0, count: 8192)
    private var samples = 0
    private var measurementStarted: UInt64?
    private var pause = Duration.zero
    private var residentStart: UInt64?
    private var residentPeak: UInt64?

    init(delay: Duration = .zero) { self.delay = delay }

    func beginMeasurement(pause: Duration = .zero) {
        self.pause = pause
        measurementStarted = DispatchTime.now().uptimeNanoseconds
        measuring = true
        residentStart = residentBytes()
        residentPeak = residentStart
    }

    func consume(_ observation: BGPLSUpdateObservation) async {
        if measuring {
            if pause != .zero {
                let duration = pause
                pause = .zero
                try? await Task.sleep(for: duration)
            }
            if delay != .zero { try? await Task.sleep(for: delay) }
        }
        switch observation.preparation {
        case .success(let prepared): _ = rib.commit(prepared)
        case .failure(let error): Issue.record("Synthetic UPDATE failed: \(error)")
        }
        total += 1
        if measuring {
            measured += 1
            if observation.rawBody.readableBytes >= 15,
                let sent: UInt64 = observation.rawBody.getInteger(at: observation.rawBody.readerIndex + 7), sent != 0
            {
                let now = DispatchTime.now().uptimeNanoseconds
                let elapsed = max(now - min(now, sent), 1)
                histogram[min(8191, Int(log2(Double(elapsed)) * 128))] += 1
                samples += 1
            }
            if measured % 256 == 0, let resident = residentBytes() {
                residentPeak = max(residentPeak ?? 0, resident)
            }
        }
        var remaining: [(Int, CheckedContinuation<Bool, Never>)] = []
        for (target, continuation) in waiters {
            if total >= target {
                continuation.resume(returning: true)
            } else {
                remaining.append((target, continuation))
            }
        }
        waiters = remaining
    }

    func wait(until target: Int) async -> Bool {
        if total >= target { return true }
        if terminated { return false }
        return await withCheckedContinuation { waiters.append((target, $0)) }
    }

    func completedCount() -> Int { total }

    func wasTerminated() -> Bool { terminated }

    func terminate() {
        terminated = true
        let saved = waiters
        waiters.removeAll()
        for (_, continuation) in saved { continuation.resume(returning: false) }
    }

    func result(
        name: String, started: UInt64, peakPending: Int?, readRequests: Int?,
        maximumReadGapNanoseconds: UInt64?, timedOut: Bool, failure: String? = nil,
        sampledOutstandingAfterProduction: Int? = nil, measurementScope: StressMeasurementScope = .native,
        notes: [String]
    ) -> StressResult {
        let finished = DispatchTime.now().uptimeNanoseconds
        let began = measurementStarted ?? started
        let elapsed = Double(finished - began) / 1_000_000_000
        let residentEnd = residentBytes()
        let peak = [residentPeak, residentEnd].compactMap { $0 }.max()
        return .init(
            name: name, startedMonotonicNanoseconds: began, finishedMonotonicNanoseconds: finished,
            elapsedSeconds: elapsed, processed: measured, updatesPerSecond: Double(measured) / elapsed,
            sendToCommitP50Milliseconds: percentile(0.50), sendToCommitP95Milliseconds: percentile(0.95),
            sendToCommitP99Milliseconds: percentile(0.99), peakPending: peakPending,
            sampledOutstandingAfterProduction: sampledOutstandingAfterProduction, readRequests: readRequests,
            maximumReadGapMilliseconds: maximumReadGapNanoseconds.map { Double($0) / 1_000_000 },
            residentStartBytes: residentStart, residentPeakBytes: peak, residentEndBytes: residentEnd,
            nodes: rib.nodeCount, links: rib.linkCount, prefixes: rib.prefixCount, timedOut: timedOut, failure: failure,
            sessions: nil, measurementScope: measurementScope,
            notes: notes)
    }

    private func percentile(_ fraction: Double) -> Double? {
        guard samples != 0 else { return nil }
        let target = max(1, Int(ceil(Double(samples) * fraction)))
        var cumulative = 0
        for (bucket, count) in histogram.enumerated() {
            cumulative += count
            if cumulative >= target { return pow(2, Double(bucket) / 128) / 1_000_000 }
        }
        return nil
    }
}

private func residentBytes() -> UInt64? {
    #if canImport(Darwin)
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? UInt64(info.resident_size) : nil
    #else
        guard let contents = try? String(contentsOfFile: "/proc/self/statm", encoding: .utf8),
            let resident = contents.split(separator: " ").dropFirst().first.flatMap({ UInt64($0) })
        else { return nil }
        return resident * UInt64(sysconf(Int32(_SC_PAGESIZE)))
    #endif
}

#if !BGPLS_LEGACY_BASELINE
    private struct StressCase: Sendable {
        let name: String
        let topology: StressTopology
        let populationOnly: Bool
        let updates: Int
        let rate: Int
        let delay: Duration
        let peers: Int
        let pause: Duration
        let bodySize: Int?

        init(name: String) throws {
            self.name = name
            topology =
                name == "smoke" ? .init(nodes: 7, connections: 9) : name == "population-10x" ? .large : .reference
            populationOnly = name.hasPrefix("population-") || name == "smoke"
            rate = name == "refresh-1000" ? 1000 : name == "refresh-10000" ? 10_000 : 0
            delay =
                (name == "delay-1ms" || name == "bridge-native")
                ? .milliseconds(1) : name == "delay-10ms" ? .milliseconds(10) : .zero
            peers = name == "peers-4" ? 4 : name == "peers-16" ? 16 : 1
            pause = name == "paused" || name == "peers-16" || name == "bridge-native" ? .seconds(2) : .zero
            bodySize = name == "frames-minimum" ? 23 : name == "frames-maximum" ? 4096 : nil
            updates =
                populationOnly
                ? topology.objectCount
                : name == "bridge-native" ? 10_000 : delay != .zero ? 5000 : rate != 0 ? 30_000 : 100_000
            guard
                [
                    "population-reference", "population-10x", "refresh-1000", "refresh-10000", "refresh-max",
                    "delay-1ms", "delay-10ms", "paused", "frames-minimum", "frames-maximum", "peers-4", "peers-16",
                    "bridge-native", "smoke",
                ]
                .contains(name)
            else { throw StressFailure("Unknown case \(name)") }
        }
    }

    private enum NativeStressRun {
        static func run(_ configuration: StressCase) async throws -> StressResult {
            // Multiple independent sessions share a fixed aggregate topology, not N copies.
            let results = try await withThrowingTaskGroup(of: StressResult.self) { group in
                for peer in 0..<configuration.peers {
                    group.addTask { try await onePeer(configuration, peer: peer) }
                }
                var results: [StressResult] = []
                for try await result in group { results.append(result) }
                return results
            }
            if results.count == 1 { return try #require(results.first) }
            let began = try #require(results.map(\.startedMonotonicNanoseconds).min())
            let finished = try #require(results.map(\.finishedMonotonicNanoseconds).max())
            let elapsed = Double(finished - began) / 1_000_000_000
            let processed = results.reduce(0) { $0 + $1.processed }
            let residentEnd = residentBytes()
            let residentPeak = (results.compactMap(\.residentPeakBytes) + [residentEnd].compactMap { $0 }).max()
            return .init(
                name: configuration.name, startedMonotonicNanoseconds: began, finishedMonotonicNanoseconds: finished,
                elapsedSeconds: elapsed, processed: processed,
                updatesPerSecond: Double(processed) / elapsed,
                sendToCommitP50Milliseconds: nil, sendToCommitP95Milliseconds: nil, sendToCommitP99Milliseconds: nil,
                peakPending: results.compactMap(\.peakPending).max(), sampledOutstandingAfterProduction: nil,
                readRequests: results.compactMap(\.readRequests).reduce(0, +),
                maximumReadGapMilliseconds: results.compactMap(\.maximumReadGapMilliseconds).max(),
                residentStartBytes: results.compactMap(\.residentStartBytes).min(),
                residentPeakBytes: residentPeak,
                residentEndBytes: residentEnd, nodes: results.reduce(0) { $0 + $1.nodes },
                links: results.reduce(0) { $0 + $1.links }, prefixes: results.reduce(0) { $0 + $1.prefixes },
                timedOut: results.contains(where: \.timedOut), failure: results.compactMap(\.failure).first,
                sessions: results, measurementScope: .nativeMultiSession,
                notes: [
                    "\(configuration.peers) independent sessions; fixed aggregate generated topology.",
                    "RSS is process-wide; peakPending is the maximum per session; latency percentiles are not averaged.",
                    "Each session excludes its own seeding from workload time; another session's seeding may overlap that interval.",
                    "Pending/read counters cover each whole session, including handshake and seeding; they are not workload-window counters.",
                ])
        }

        private static func onePeer(_ configuration: StressCase, peer: Int) async throws -> StressResult {
            let group = MultiThreadedEventLoopGroup.singleton
            let loop = group.next()
            let accepted = loop.makePromise(of: NIOAsyncChannel<BGPMessage, BGPMessage>.self)
            let server = try await ServerBootstrap(group: loop)
                .childChannelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(BGPMessageDecoder()))
                        try channel.pipeline.syncOperations.addHandler(MessageToByteHandler(BGPMessageEncoder()))
                        accepted.succeed(
                            try NIOAsyncChannel<BGPMessage, BGPMessage>(wrappingChannelSynchronously: channel))
                    }
                }.bind(host: "127.0.0.1", port: 0).get()
            let address = try #require(server.localAddress)
            let admission = SessionInputAdmission(eventLoop: loop)
            let outcome = SessionOutcome(eventLoop: loop)
            let probe = NIOLoopBoundBox.makeBoxSendingValue(StressProbe.State(), eventLoop: loop)
            let metrics = StressMetrics(delay: configuration.delay)
            let wrapped = NIOLoopBoundBox<NIOAsyncChannel<SessionInput, Never>?>.makeBoxSendingValue(
                nil, eventLoop: loop)
            let asn = AutonomousSystemNumber(65_001)
            let open = BGPOpenMessage(
                myAS: 65_001, holdTime: 0, bgpIdentifier: 0xc000_0202,
                optionalParameters: BGPOpenCapabilities.bgpLS(localAS: asn))
            let channel: Channel
            do {
                channel = try await ClientBootstrap(group: loop)
                    .channelOption(
                        ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 4096)
                    )
                    .channelOption(ChannelOptions.maxMessagesPerRead, value: 1)
                    .channelInitializer { channel in
                        channel.eventLoop.makeCompletedFuture {
                            try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(BGPMessageDecoder()))
                            try channel.pipeline.syncOperations.addHandler(MessageToByteHandler(BGPMessageEncoder()))
                            let timers = BGPKeepaliveHoldTimerHandler()
                            try channel.pipeline.syncOperations.addHandler(timers)
                            try channel.pipeline.syncOperations.addHandler(
                                BGPSessionHandler(
                                    openToSend: open, localAS: asn, expectedPeerAS: asn, outcome: outcome,
                                    timers: timers, admission: admission))
                            try channel.pipeline.syncOperations.addHandler(
                                StressProbe(state: probe, admission: admission))
                            wrapped.value = try NIOAsyncChannel<SessionInput, Never>(
                                wrappingChannelSynchronously: channel,
                                configuration: .init(backPressureStrategy: .init(lowWatermark: 8, highWatermark: 64)))
                        }
                    }.connect(to: address).get()
            } catch {
                try? await server.close().get()
                throw error
            }
            let bridge = try await loop.submit { try #require(wrapped.value) }.get()
            try await loop.submit { wrapped.value = nil }.get()
            let remote = try await accepted.futureResult.get()
            let consumer = SessionInputConsumer(channel: bridge, admission: admission, outcome: outcome) { input in
                if case .update(let observation) = input { await metrics.consume(observation) }
            }
            let started = DispatchTime.now().uptimeNanoseconds
            let deadline = Task {
                try await Task.sleep(for: .seconds(90))
                await metrics.terminate()
                channel.close(promise: nil)
                remote.channel.close(promise: nil)
            }
            var timedOut = false
            var failure: String?
            do {
                try await remote.executeThenClose { inbound, outbound in
                    var iterator = inbound.makeAsyncIterator()
                    guard case .open? = try await iterator.next() else { throw StressFailure("Expected OPEN") }
                    var reply = open
                    reply.bgpIdentifier = 0xc000_0201
                    try await outbound.write(.open(reply))
                    try await outbound.write(.keepalive)
                    guard case .keepalive? = try await iterator.next() else {
                        throw StressFailure("Expected KEEPALIVE")
                    }
                    var sent = 0
                    if !configuration.populationOnly, configuration.bodySize == nil,
                        configuration.name != "bridge-native"
                    {
                        for index in stride(from: peer, to: configuration.topology.objectCount, by: configuration.peers)
                        {
                            try await outbound.write(.update(configuration.topology.body(at: index, sentAt: 0)))
                            sent += 1
                        }
                        guard await metrics.wait(until: sent) else { throw StressFailure("Seed timed out") }
                    }
                    await metrics.beginMeasurement(pause: peer == 0 ? configuration.pause : .zero)
                    let paceStart = ContinuousClock.now
                    var measuredSent = 0
                    for index in stride(from: peer, to: configuration.updates, by: configuration.peers) {
                        try Task.checkCancellation()
                        if configuration.rate != 0 {
                            let due =
                                paceStart
                                + .nanoseconds(Int64(measuredSent) * 1_000_000_000 / Int64(configuration.rate))
                            try await Task.sleep(until: due, clock: .continuous)
                        }
                        let now = DispatchTime.now().uptimeNanoseconds
                        let topologyIndex: Int
                        if configuration.name == "bridge-native" {
                            topologyIndex = 0
                        } else if configuration.populationOnly {
                            topologyIndex = index
                        } else {
                            let ownedCount = (configuration.topology.objectCount - 1 - peer) / configuration.peers + 1
                            topologyIndex = peer + (measuredSent % ownedCount) * configuration.peers
                        }
                        let body =
                            configuration.bodySize == 23
                            ? StressTopology.minimumBody
                            : configuration.bodySize == 4096
                                ? StressTopology.maximumBody(sentAt: now)
                                : configuration.topology.body(
                                    at: topologyIndex, sentAt: now)
                        try await outbound.write(.update(body))
                        sent += 1
                        measuredSent += 1
                    }
                    guard await metrics.wait(until: sent) else { throw StressFailure("Drain timed out") }
                }
            } catch {
                timedOut = await metrics.wasTerminated()
                failure = String(describing: error)
                channel.close(promise: nil)
                remote.channel.close(promise: nil)
            }
            deadline.cancel()
            _ = await deadline.result
            channel.close(promise: nil)
            await consumer.finish()
            do { try await outcome.futureResult.get() } catch {
                if failure == nil { failure = String(describing: error) }
            }
            try? await server.close().get()
            let counters = try await loop.submit { probe.value }.get()
            let pending = try await loop.submit { admission.pendingCount }.get()
            #expect(pending == 0)
            #expect(counters.peakPending <= 1024)
            if failure != nil && !timedOut { Issue.record("Stress transport failed: \(failure ?? "unknown")") }
            let result = await metrics.result(
                name: configuration.name, started: started, peakPending: counters.peakPending,
                readRequests: counters.readRequests, maximumReadGapNanoseconds: counters.maximumReadGap,
                timedOut: timedOut, failure: failure,
                notes: [
                    "Loopback TCP; actual codec/timers/FSM/native bridge; zero Hold Time; capture disabled.",
                    "Includes preparation, raw-body compact copy, serial actor commit, and awaited credit release.",
                    "The test actor calls LSRIB.commit; production BGPSession callbacks, diff broadcast/watch delivery, CLI logging, and PCAP are excluded.",
                    "peakPending/readRequests/maximumReadGapMilliseconds cover the whole session, including handshake and seeding; throughput and latency exclude seeding.",
                    "Send-to-commit latency includes sender/socket buffering; fixed logarithmic histogram (<0.6% bins).",
                    "Read-request gaps include producer inactivity and are not all native backpressure pauses.",
                    "Historical-size-inspired generated graph, not AT&T inventory or Tier-1 qualification.",
                ])
            if !timedOut, failure == nil {
                if configuration.bodySize != nil {
                    #expect(result.nodes == 0 && result.links == 0 && result.prefixes == 0)
                } else if configuration.name == "bridge-native" {
                    #expect(result.nodes == 1 && result.links == 0 && result.prefixes == 0)
                } else {
                    func owned(_ upper: Int) -> Int {
                        upper > peer ? (upper - 1 - peer) / configuration.peers + 1 : 0
                    }
                    let nodes = owned(configuration.topology.nodes)
                    let throughLinks = owned(configuration.topology.nodes + configuration.topology.connections * 2)
                    #expect(result.nodes == nodes)
                    #expect(result.links == throughLinks - nodes)
                    #expect(result.prefixes == owned(configuration.topology.objectCount) - throughLinks)
                }
            }
            return result
        }
    }

    private final class StressProbe: ChannelDuplexHandler {
        typealias InboundIn = SessionInput
        typealias InboundOut = SessionInput
        typealias OutboundIn = Never
        struct State: Sendable {
            var peakPending = 0
            var readRequests = 0
            var lastRead: UInt64?
            var maximumReadGap: UInt64 = 0
        }
        let state: NIOLoopBoundBox<State>
        let admission: SessionInputAdmission
        init(state: NIOLoopBoundBox<State>, admission: SessionInputAdmission) {
            self.state = state
            self.admission = admission
        }
        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            state.value.peakPending = max(state.value.peakPending, admission.pendingCount)
            context.fireChannelRead(data)
        }
        func read(context: ChannelHandlerContext) {
            let now = DispatchTime.now().uptimeNanoseconds
            if let last = state.value.lastRead {
                state.value.maximumReadGap = max(state.value.maximumReadGap, now - last)
            }
            state.value.lastRead = now
            state.value.readRequests += 1
            context.read()
        }
    }
#endif
