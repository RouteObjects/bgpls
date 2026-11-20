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
import NIOCore
import Testing

@testable import BGPLSClient

struct BGPLSUpdateObservationTests {
    @Test
    func combinedNLRIAndAttributeDiagnosticsShareOneDetailLimitWithDistinctCoordinates() throws {
        let malformed = IPv6TopologyFixture.prefixWire([129])
        let wire = TypedAttributeFixture.topology() + Array(repeating: malformed, count: 5).flatMap { $0 }
        let badFields = TypedAttributeFixture.attribute([
            .init(type: 1026, value: [255]),
            .init(type: 1095, value: []),
            .init(type: 1155, value: [10]),
            .init(type: 1089, value: [0x7f, 0x80, 0, 0]),
            .init(type: 1091, value: []),
        ])
        var rib = LSRIB()
        let result = try rib.applyIsolating(
            update: TypedAttributeFixture.update(reaches: wire, attributes: [badFields, badFields]))
        #expect(result.diagnostics.count == 11)
        #expect(rib.summaryLine == "nodes=1 links=1 prefixes=2")
        let lines = BGPLSUpdateDiagnosticFormatter.lines(
            result.diagnostics, peer: "192.0.2.1/32:179", timestamp: "time")
        #expect(lines.count == 9)
        #expect(lines.filter { $0.contains("MP_REACH NLRI") }.count == 5)
        let attributeLines = lines.filter { $0.contains("attribute index=") }
        #expect(attributeLines.count == 3)
        #expect(attributeLines.allSatisfy { $0.contains("attribute index=1 type=29 TLV index=") })
        #expect(attributeLines.allSatisfy { !$0.contains("NLRI") && !$0.contains("MP_REACH") && !$0.contains("raw=") })
        #expect(lines.last?.contains("omitted=3 (detail limit=8)") == true)
        #expect(result.diagnostics.filter { if case .attribute = $0 { true } else { false } }.count == 6)
    }

    @Test
    func diagnosticsArePeerQualifiedFieldSpecificAndCappedWithoutRawBytes() throws {
        let malformed = IPv6TopologyFixture.prefixWire([129])
        let bytes = Array(repeating: malformed, count: 10).flatMap { $0 }
        var rib = LSRIB()
        let result = try rib.applyIsolating(update: IPv6TopologyFixture.update(reachable: false, nlris: bytes))
        let lines = BGPLSUpdateDiagnosticFormatter.lines(
            result.diagnostics, peer: "192.0.2.1/32:179", timestamp: "12:34:56.789"
        )

        #expect(result.diagnostics.count == 10)
        #expect(lines.count == 9)
        for (index, line) in lines.dropLast().enumerated() {
            #expect(line.contains("peer=192.0.2.1/32:179 MP_UNREACH"))
            #expect(line.contains("index=\(index) offset=\(index * malformed.count) type=4 discarded"))
            #expect(line.contains("category=malformedEncoding"))
            #expect(!line.contains("raw="))
            #expect(!line.contains("000400"))
        }
        #expect(lines.last?.contains("diagnostics omitted=2 (detail limit=8)") == true)
        #expect(BGPLSUpdateDiagnosticFormatter.lines([], peer: "peer", timestamp: "time").isEmpty)
    }

    @Test
    func warningFormattingDoesNotDescribeAcceptedNLRIAsDiscarded() throws {
        let ipv4 = IPv6TopologyFixture.prefixWire([25, 192, 0, 2, 129], type: 3)
        let ipv6 = IPv6TopologyFixture.prefixWire([63, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 1])
        let networks = ["192.0.2.128/25", "2001:db8::/63"]
        for reachable in [true, false] {
            var rib = LSRIB()
            let result = try rib.applyIsolating(
                update: IPv6TopologyFixture.update(reachable: reachable, nlris: ipv4 + ipv6)
            )
            let lines = BGPLSUpdateDiagnosticFormatter.lines(result.diagnostics, peer: "peer", timestamp: "time")
            #expect(lines.count == 2)
            #expect(nlriDiagnostics(result.diagnostics).map { $0.diagnostic.rawNLRI } == [ipv4, ipv6])
            #expect(nlriDiagnostics(result.diagnostics).map { $0.diagnostic.byteOffset } == [0, ipv4.count])
            for (index, line) in lines.enumerated() {
                #expect(line.contains(reachable ? "MP_REACH" : "MP_UNREACH"))
                #expect(line.contains("index=\(index)"))
                #expect(line.contains("accepted-with-warning category=nonZeroPrefixPadding descriptor=265"))
                #expect(line.contains("nonzero trailing bits in IP Reachability descriptor for \(networks[index])"))
                #expect(!line.contains("discarded"))
                #expect(!line.contains("raw="))
                #expect(!line.hasSuffix("…"))
            }
            #expect(result.diffs.count == 2)
            #expect(rib.prefixCount == (reachable ? 2 : 0))
        }
    }

    @Test
    func invalidContentCategoryIsEmittedWithoutTheRetiredName() throws {
        let wire = IPv6TopologyFixture.prefixWire([0], extra: [BGPLSTLV(type: 265, value: [0])])
        var rib = LSRIB()
        let result = try rib.applyIsolating(update: IPv6TopologyFixture.update(reachable: true, nlris: wire))
        let line = try #require(
            BGPLSUpdateDiagnosticFormatter.lines(result.diagnostics, peer: "peer", timestamp: "time").first)
        #expect(line.contains("discarded category=invalidContent descriptor=265"))
        #expect(result.diffs.isEmpty)
        #expect(rib == LSRIB())
    }

    @Test
    func fatalPresentationIsBoundedAndSingleLine() {
        let line = BGPLSUpdateDiagnosticFormatter.fatalLine(
            BGPLSClientError.protocolError("failure\n" + String(repeating: "x", count: 400)),
            peer: "192.0.2.1/32:179", timestamp: "time"
        )
        #expect(line.contains("peer=192.0.2.1/32:179 UPDATE rejected; session terminating:"))
        #expect(!line.contains("\n"))
        #expect(line.hasSuffix("…"))
        #expect(line.count < 400)
    }

    @Test
    func fatalCoordinatesSurviveWithdrawalContextAndFormatting() throws {
        let good = IPv6TopologyFixture.prefixWire([0])
        let observation = BGPLSUpdateObservation(
            rawBody: IPv6TopologyFixture.updateBody(reachable: false, nlris: good + [0, 4, 0, 100])
        )
        guard case .failure(let error) = observation.preparation else {
            Issue.record("expected fatal withdrawal framing")
            return
        }
        let line = BGPLSUpdateDiagnosticFormatter.fatalLine(error, peer: "192.0.2.1/32:179", timestamp: "time")
        #expect(line.contains("peer=192.0.2.1/32:179 UPDATE rejected; session terminating:"))
        #expect(line.contains("MP_UNREACH: disposition=fatal category=malformedEncoding"))
        #expect(line.contains("index=1 offset=\(good.count) type=4"))
        #expect(line.contains("BGP-LS NLRI truncated"))
        #expect(!line.contains("raw="))
        #expect(!line.hasSuffix("…"))
    }

    @Test(.timeLimit(.minutes(1)))
    func recoveredSessionDiffsReconstructItsSnapshotWithoutHiddenMutations() async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let stream = await session.ribChanges(includeCatchUpSnapshot: false)
        let ipv4 = IPv6TopologyFixture.prefixWire([24, 192, 0, 2], type: 3)
        let ipv6 = IPv6TopologyFixture.prefixWire([0])
        let malformed = IPv6TopologyFixture.prefixWire([129])
        try await session.applyInboundUpdateForTesting(
            IPv6TopologyFixture.updateBody(reachable: true, nlris: ipv4 + malformed + ipv6)
        )
        try await session.applyInboundUpdateForTesting(
            IPv6TopologyFixture.updateBody(reachable: false, nlris: malformed + ipv4)
        )
        await session.stop()

        var replay = LSRIB()
        var events: [RIBDiff] = []
        for await event in stream {
            events.append(event)
            switch event {
            case .upsert(let nlri): replay.apply(nlri)
            case .withdraw(let nlri): replay.withdraw(nlri)
            case .snapshot: Issue.record("catch-up was disabled")
            }
        }
        #expect(events.count == 3)
        let snapshot = await session.ribSnapshot()
        #expect(replay == snapshot)
    }

    @Test(.timeLimit(.minutes(1)))
    func replayHelperRejectsFatalFramingWithoutMutatingOrEmitting() async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let stream = await session.ribChanges(includeCatchUpSnapshot: false)
        do {
            try await session.applyInboundUpdateForTesting(
                IPv6TopologyFixture.updateBody(reachable: true, nlris: [0, 4, 0, 100])
            )
            Issue.record("expected fatal NLRI framing to throw")
        } catch is BGPLSClientError {
            // Replay helpers expose the same fatal preparation result without a live outcome.
        }
        await session.stop()
        var events: [RIBDiff] = []
        for await event in stream { events.append(event) }
        #expect(events.isEmpty)
        #expect(await session.ribSnapshot() == LSRIB())
    }

    @Test(.timeLimit(.minutes(1)), arguments: [UInt8(14), 15])
    func duplicateMPAttributesPreserveSeededRIBRawBodyAndEventHistory(type: UInt8) async throws {
        let ipv4 = IPv6TopologyFixture.prefixWire([24, 192, 0, 2], type: 3)
        let ipv6 = IPv6TopologyFixture.prefixWire([0])
        let seed = IPv6TopologyFixture.updateBody(reachable: true, nlris: ipv4 + ipv6)
        let newPrefix = IPv6TopologyFixture.prefixWire([24, 198, 51, 100], type: 3)
        let reach = DuplicateMPFixture.attribute(type: 14, value: DuplicateMPFixture.value(type: 14, nlri: newPrefix))
        let unreach = DuplicateMPFixture.attribute(type: 15, value: DuplicateMPFixture.value(type: 15, nlri: ipv4))
        let repeated = DuplicateMPFixture.attribute(type: type, value: DuplicateMPFixture.value(type: type))
        let rejectedBody = DuplicateMPFixture.body(attributes: [reach, unreach, repeated])
        let expectedError = BGPLSClientError.duplicateMultiprotocolAttribute(typeCode: type)
        let observation = BGPLSUpdateObservation(rawBody: rejectedBody)
        #expect(observation.rawBody == rejectedBody)
        #expect(throws: expectedError) { try observation.preparation.get() }

        var rib = LSRIB()
        try rib.apply(update: BGPUpdateParser.parse(seed))
        let before = rib
        #expect(throws: expectedError) { try rib.apply(update: BGPUpdateParser.parse(rejectedBody)) }
        #expect(rib == before)

        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let stream = await session.ribChanges(includeCatchUpSnapshot: false)
        try await session.applyInboundUpdateForTesting(seed)
        #expect(await session.ribSnapshot() == before)
        await #expect(throws: expectedError) {
            try await session.applyInboundUpdateForTesting(rejectedBody)
        }
        #expect(await session.ribSnapshot() == before)
        await session.stop()
        var replay = LSRIB()
        var events: [RIBDiff] = []
        for await event in stream {
            events.append(event)
            switch event {
            case .upsert(let record): replay.apply(record)
            case .withdraw: Issue.record("Rejected UPDATE must not withdraw the seeded prefix")
            case .snapshot: Issue.record("catch-up was disabled")
            }
        }
        #expect(events.count == 2)
        #expect(replay == before)
        #expect(await session.ribSnapshot() == before)
    }
}
