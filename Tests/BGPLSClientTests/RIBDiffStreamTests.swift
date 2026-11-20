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
import Testing

@testable import BGPLSClient

struct RIBDiffStreamTests {
    @Test
    func ribApplyReturnsUpsertDiffs() throws {
        var rib = LSRIB()
        let diffs = try rib.apply(
            update: BGPUpdateParser.parse(HexFixture.buffer(BGPUpdateParserTests.linkUpdateHex))
        )
        #expect(diffs.count == 1)
        guard case .upsert(.link) = diffs[0] else {
            Issue.record("expected link upsert")
            return
        }
        #expect(diffs[0].watchLine.contains("WATCH upsert link"))
    }

    @Test
    func sessionStreamCatchUpThenUpsert() async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let stream = await session.ribChanges(includeCatchUpSnapshot: true)

        let collector = Task { () -> [RIBDiff] in
            var collected: [RIBDiff] = []
            for await diff in stream {
                collected.append(diff)
                if collected.count >= 2 { break }
            }
            return collected
        }

        // Let the catch-up snapshot be observed, then inject a wire UPDATE.
        try await Task.sleep(for: .milliseconds(30))
        try await session.applyInboundUpdateForTesting(
            HexFixture.buffer(BGPUpdateParserTests.linkUpdateHex)
        )

        let events = await collector.value
        #expect(events.count >= 2)
        guard case .snapshot = events[0] else {
            Issue.record("expected catch-up snapshot first, got \(events[0])")
            return
        }
        guard case .upsert(.link) = events[1] else {
            Issue.record("expected link upsert second, got \(events[1])")
            return
        }
    }

    @Test
    func nodeWatchLineFormat() throws {
        var rib = LSRIB()
        let diffs = try rib.apply(
            update: BGPUpdateParser.parse(HexFixture.buffer(BGPUpdateParserTests.nodeUpdateHex))
        )
        #expect(diffs.count == 2)
        #expect(diffs[0].watchLine.contains("WATCH upsert node"))
    }

    @Test(.timeLimit(.minutes(1)))
    func boundedSubscriberDropsOldEventsWithoutDroppingRIBObjects() async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let stream = await session.ribChanges(includeCatchUpSnapshot: false, bufferingNewest: 2)
        var expectedRIB = LSRIB()
        var expectedEvents: [RIBDiff] = []

        // No iterator consumes this stream until all four distinct upserts have
        // been published, making the two oldest dropped events deterministic.
        for hex in [
            BGPUpdateParserTests.nodeUpdateHex,
            BGPUpdateParserTests.linkUpdateHex,
            BGPUpdateParserTests.prefixUpdateHex,
        ] {
            let body = HexFixture.buffer(hex)
            expectedEvents.append(contentsOf: try expectedRIB.apply(update: BGPUpdateParser.parse(body)))
            try await session.applyInboundUpdateForTesting(body)
        }
        await session.stop()

        var received: [RIBDiff] = []
        for await event in stream {
            received.append(event)
        }

        let actualRIB = await session.ribSnapshot()
        let distinctEventCount = Set(expectedEvents).count
        #expect(expectedEvents.count == 4)
        #expect(distinctEventCount == 4)
        #expect(received == Array(expectedEvents.suffix(2)))
        #expect(actualRIB == expectedRIB)
        #expect(actualRIB.nodeCount == 2)
        #expect(actualRIB.linkCount == 1)
        #expect(actualRIB.prefixCount == 1)
    }
}
