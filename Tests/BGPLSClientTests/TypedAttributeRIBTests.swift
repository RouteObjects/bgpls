//===----------------------------------------------------------------------===//
//
// This source file is part of the bgpls project.
// Copyright (c) 2026 Craig A. Munro
// Licensed under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CIDR
import Foundation
import NIOCore
import Testing

@testable import BGPLSClient

struct TypedAttributeRIBTests {
    @Test(arguments: [UInt8(2), 3])
    func oneObservationProjectsToItsApplicableRecordsWithoutChangingIdentity(protocolID: UInt8) throws {
        let wire = TypedAttributeFixture.topology(protocolID: protocolID)
        let attribute = TypedAttributeFixture.attribute([
            .init(type: 1155, value: [0, 0, 0, 20]),
            .init(type: 60_000, value: [9, 8, 7]),
            .init(type: 1026, value: Array("router\tA".utf8)),
            .init(type: 1095, value: [0, 30]),
        ])
        let update = try TypedAttributeFixture.update(reaches: wire, attributes: [attribute])
        let original = update
        var rib = LSRIB()
        let result = try rib.applyIsolating(update: update)
        #expect(update == original)
        #expect(result.diagnostics.isEmpty)
        #expect(rib.summaryLine == "nodes=1 links=1 prefixes=2")
        #expect(result.diffs.count == 4)
        #expect(rib.nodes.values.first?.attributes.name == "router\tA")
        #expect(rib.links.values.first?.attributes.igpMetric == 30)
        #expect(rib.prefixes.values.allSatisfy { $0.attributes.metric == 20 })
        #expect(Set(rib.prefixes.values.map { $0.nlri.network.description }) == ["192.0.2.0/24", "2001:db8::/64"])
        let records = result.diffs.compactMap { diff -> BGPLSRecord? in
            guard case .upsert(let record) = diff else { return nil }
            return record
        }
        #expect(records.count == 4)
        #expect(records.allSatisfy { $0.observation == records.first?.observation })
        #expect(records.first?.observation.attributes.first?.value == Array(attribute.value.readableBytesView))
        #expect(records.first?.observation.attributes.first?.tlvs.map(\.type) == [1155, 60_000, 1026, 1095])
        let snapshot = rib.snapshot(at: .distantPast)
        #expect(snapshot.nodes.first?.attributes?.name == "router\tA")
        #expect(snapshot.links.first?.attributes?.igpMetric == 30)
        #expect(snapshot.prefixes.allSatisfy { $0.attributes?.metric == 20 })
    }

    @Test
    func replacementRefreshAndWithdrawalRetainKeysWithoutRetainingStaleAttributes() throws {
        let wire = TypedAttributeFixture.topology()
        let full = TypedAttributeFixture.attribute([
            .init(type: 1026, value: Array("first".utf8)),
            .init(type: 1095, value: [10]),
            .init(type: 1155, value: [0, 0, 0, 10]),
        ])
        var rib = LSRIB()
        let originalDiffs = try rib.apply(update: TypedAttributeFixture.update(reaches: wire, attributes: [full]))
        let original = rib
        let keys = (Set(rib.nodes.keys), Set(rib.links.keys), Set(rib.prefixes.keys))
        let changed = TypedAttributeFixture.attribute([
            .init(type: 1026, value: Array("second".utf8)),
            .init(type: 1095, value: [20]),
            .init(type: 1155, value: [0, 0, 0, 30]),
        ])
        let changedUpdate = try TypedAttributeFixture.update(reaches: wire, attributes: [changed])
        let changes = try rib.apply(update: changedUpdate)
        #expect(changes.count == 4)
        #expect(changes != originalDiffs)
        #expect(rib.nodes.values.first?.attributes.name == "second")
        #expect(rib.links.values.first?.attributes.igpMetric == 20)
        #expect(rib.prefixes.values.allSatisfy { $0.attributes.metric == 30 })
        #expect(try rib.apply(update: changedUpdate) == changes)
        #expect(Set(rib.nodes.keys) == keys.0)
        #expect(Set(rib.links.keys) == keys.1)
        #expect(Set(rib.prefixes.keys) == keys.2)

        let missing = try TypedAttributeFixture.update(reaches: wire)
        #expect(try rib.apply(update: missing).count == 4)
        #expect(rib.nodes.values.first?.attributes.name == nil)
        #expect(rib.links.values.first?.attributes.igpMetric == nil)
        #expect(
            rib.prefixes.values.allSatisfy { $0.attributes.metric == nil && $0.observation.availability == .absent })

        try rib.apply(update: changedUpdate)
        let broken = BGPPathAttribute(flags: 0x80, typeCode: 29, value: ByteBuffer(bytes: [4, 2, 0, 100]))
        let discarded = try rib.applyIsolating(
            update: TypedAttributeFixture.update(reaches: wire, attributes: [broken]))
        #expect(discarded.diffs.count == 4)
        #expect(discarded.diagnostics.count == 1)
        #expect(rib.nodes.values.first?.attributes.name == nil)
        #expect(rib.links.values.first?.attributes.igpMetric == nil)
        #expect(
            rib.prefixes.values.allSatisfy { $0.attributes.metric == nil && $0.observation.availability == .discarded })

        let withdrawals = try rib.applyIsolating(
            update: TypedAttributeFixture.update(withdrawals: wire, attributes: [changed]))
        #expect(withdrawals.diffs.count == 4)
        #expect(withdrawals.diffs.allSatisfy { if case .withdraw = $0 { true } else { false } })
        #expect(rib == LSRIB())
        #expect(try rib.apply(update: TypedAttributeFixture.update(reaches: wire, attributes: [full])) == originalDiffs)
        #expect(rib == original)
    }

    @Test
    func strictAttributeRejectionIsAtomicAcrossReachAndWithdrawWhileWarningsAreHarmless() throws {
        let wire = TypedAttributeFixture.topology()
        let seed = TypedAttributeFixture.attribute([.init(type: 1026, value: Array("seed".utf8))])
        var rib = LSRIB()
        try rib.apply(update: TypedAttributeFixture.update(reaches: wire, attributes: [seed]))
        let before = rib
        let cases = [
            BGPPathAttribute(flags: 0x80, typeCode: 29, value: ByteBuffer(bytes: [4, 2, 0])),
            TypedAttributeFixture.attribute([.init(type: 1026, value: [255])]),
            TypedAttributeFixture.attribute([.init(type: 1155, value: [10])]),
            TypedAttributeFixture.attribute([.init(type: 1095, value: [10]), .init(type: 1095, value: [20])]),
            BGPPathAttribute(flags: 0xc0, typeCode: 29, value: seed.value),
            BGPPathAttribute(flags: 0x80, typeCode: 29, value: ByteBuffer()),
        ]
        for attribute in cases {
            let update = try TypedAttributeFixture.update(reaches: wire, withdrawals: wire, attributes: [attribute])
            #expect(throws: BGPLSClientError.self) { try rib.apply(update: update) }
            #expect(rib == before)
            #expect(rib.snapshot(at: .distantPast) == before.snapshot(at: .distantPast))
        }
        let duplicate = TypedAttributeFixture.attribute([
            .init(type: 1026, value: Array("seed".utf8)), .init(type: 1026, value: Array("seed".utf8)),
        ])
        #expect(
            try rib.apply(update: TypedAttributeFixture.update(reaches: wire, attributes: [duplicate, seed])).count == 4
        )
        #expect(rib.nodes.values.first?.attributes.name == "seed")
        #expect(rib.nodes.values.first?.observation.diagnostics.count == 2)
    }

    @Test
    func rejectedProjectionClearsOnlyItsPropertyAndWrongContextTLVsRemainEvidence() throws {
        let wire = TypedAttributeFixture.topology()
        var rib = LSRIB()
        try rib.apply(
            update: TypedAttributeFixture.update(
                reaches: wire,
                attributes: [
                    TypedAttributeFixture.attribute([
                        .init(type: 1089, value: [0x49, 0x98, 0x96, 0x80]),
                        .init(type: 1090, value: [0x49, 0x98, 0x96, 0x80]),
                        .init(type: 1095, value: [20]),
                    ])
                ]))
        #expect(rib.links.values.first?.attributes.maximumLinkBandwidth?.bytesPerSecond == 1_250_000)
        let update = try TypedAttributeFixture.update(
            reaches: wire,
            attributes: [
                TypedAttributeFixture.attribute([
                    .init(type: 1026, value: Array("kept".utf8)),
                    .init(type: 1095, value: [0, 0, 10]),
                    .init(type: 1089, value: [0x7f, 0x80, 0, 0]),
                    .init(type: 1155, value: [0, 0, 0, 99]),
                ])
            ])
        let result = try rib.applyIsolating(update: update)
        #expect(result.diagnostics.count == 1)
        #expect(rib.nodes.values.first?.attributes.name == "kept")
        #expect(rib.links.values.first?.attributes.igpMetric == 10)
        #expect(rib.links.values.first?.attributes.maximumLinkBandwidth == nil)
        #expect(rib.links.values.first?.attributes.maximumReservableBandwidth == nil)
        #expect(rib.prefixes.values.allSatisfy { $0.attributes.metric == 99 })

        let nodeWire = IPv6TopologyFixture.wire(type: 1, descriptors: [IPv6TopologyFixture.nodeDescriptor()])
        let wrongContext = TypedAttributeFixture.attribute([.init(type: 1095, value: [])])
        let nodeOnly = try rib.apply(
            update: TypedAttributeFixture.update(reaches: nodeWire, attributes: [wrongContext]))
        guard case .upsert(.node(let record)) = try #require(nodeOnly.first) else {
            Issue.record("expected node record")
            return
        }
        #expect(record.observation.availability == .present)
        #expect(record.observation.diagnostics.isEmpty)
        #expect(record.observation.attributes.first?.tlvs.first?.value == [])
    }

    @Test
    func unknownNLRIObservationsCarryAttributeEvidenceButNeverEnterSupportedDictionaries() throws {
        let wire: [UInt8] = [0xea, 0x60, 0, 3, 1, 2, 3]
        let attribute = TypedAttributeFixture.attribute([.init(type: 60_001, value: [3, 2, 1])])
        var rib = LSRIB()
        let result = try rib.applyIsolating(
            update: TypedAttributeFixture.update(reaches: wire, attributes: [attribute]))
        #expect(rib == LSRIB())
        #expect(result.diffs.count == 1)
        guard case .upsert(.unknown(let nlri, let observation)) = try #require(result.diffs.first) else {
            Issue.record("unknown topology remains observable as a complete record")
            return
        }
        #expect(nlri == .unknown(type: 60_000, raw: [1, 2, 3]))
        #expect(observation.availability == .present)
        #expect(observation.attributes.first?.tlvs.first?.type == 60_001)
        #expect(result.diagnostics.isEmpty)
        let withdrawn = try rib.apply(update: TypedAttributeFixture.update(withdrawals: wire))
        #expect(withdrawn == [.withdraw(nlri)])
        #expect(rib == LSRIB())
    }

    @Test
    func retainedAttributeEvidenceParticipatesInEqualityButNotKeys() throws {
        let wire = IPv6TopologyFixture.wire(type: 1, descriptors: [IPv6TopologyFixture.nodeDescriptor()])
        let name = BGPLSTLV(type: 1026, value: Array("router".utf8))
        let unknown = BGPLSTLV(type: 60_000, value: [1])
        var rib = LSRIB()
        let first = try rib.apply(
            update: TypedAttributeFixture.update(
                reaches: wire, attributes: [TypedAttributeFixture.attribute([name, unknown])]))
        let firstRecord = try #require(rib.nodes.values.first)
        let firstKey = try #require(rib.nodes.keys.first)
        let second = try rib.apply(
            update: TypedAttributeFixture.update(
                reaches: wire, attributes: [TypedAttributeFixture.attribute([unknown, name])]))
        let secondRecord = try #require(rib.nodes.values.first)
        #expect(rib.nodeCount == 1)
        #expect(rib.nodes.keys.first == firstKey)
        #expect(firstRecord.nlri == secondRecord.nlri)
        #expect(firstRecord.attributes == secondRecord.attributes)
        #expect(firstRecord != secondRecord)
        #expect(first != second)
        let equal = firstRecord
        let hash = firstRecord.hashValue
        let equalHash = equal.hashValue
        #expect(hash == equalHash)
        #expect(Set([firstRecord]).contains(equal))
        #expect(!Set([firstRecord]).contains(secondRecord))
        #expect([firstRecord: "original"][equal] == "original")
        #expect([firstRecord: "original"][secondRecord] == nil)
        try rib.apply(update: TypedAttributeFixture.update(withdrawals: wire))
        #expect(rib.nodeCount == 0)
    }

    @Test(.timeLimit(.minutes(1)))
    func completeEventReplayIncludesAttributesAndRecoverableGaps() async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let events = await session.ribChanges(includeCatchUpSnapshot: false)
        let wire = TypedAttributeFixture.topology()
        let good = TypedAttributeFixture.attribute([.init(type: 1155, value: [0, 0, 0, 10])])
        let broken = BGPPathAttribute(flags: 0x80, typeCode: 29, value: ByteBuffer(bytes: [4, 131, 0, 4, 0]))
        for attributes in [[good], [broken], [], [good], [good]] {
            try await session.applyInboundUpdateForTesting(
                TypedAttributeFixture.body(reaches: wire, attributes: attributes))
        }
        let v4 = TypedAttributeFixture.prefix()
        try await session.applyInboundUpdateForTesting(TypedAttributeFixture.body(withdrawals: v4))
        await session.stop()
        var replay = LSRIB()
        var count = 0
        for await event in events {
            count += 1
            switch event {
            case .upsert(let record): replay.apply(record)
            case .withdraw(let nlri): replay.withdraw(nlri)
            case .snapshot: Issue.record("catch-up was disabled")
            }
        }
        #expect(count == 21)
        let current = await session.ribSnapshot()
        #expect(replay == current)
        #expect(replay.prefixCount == 1)
        #expect(replay.prefixes.values.first?.attributes.metric == 10)
    }

    @Test(.timeLimit(.minutes(1)))
    func catchUpProjectionAndCompleteSubsequentEventsReproduceSnapshot() async throws {
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
                localAS: AutonomousSystemNumber(65001),
                peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
            )
        )
        let wire = TypedAttributeFixture.topology()
        let initial = TypedAttributeFixture.attribute([.init(type: 1155, value: [0, 0, 0, 10])])
        try await session.applyInboundUpdateForTesting(TypedAttributeFixture.body(reaches: wire, attributes: [initial]))
        let events = await session.ribChanges(includeCatchUpSnapshot: true)
        let revised = TypedAttributeFixture.attribute([
            .init(type: 1026, value: Array("revised".utf8)), .init(type: 1155, value: [0, 0, 0, 99]),
        ])
        try await session.applyInboundUpdateForTesting(TypedAttributeFixture.body(reaches: wire, attributes: [revised]))
        try await session.applyInboundUpdateForTesting(
            TypedAttributeFixture.body(withdrawals: TypedAttributeFixture.prefix()))
        await session.stop()
        var iterator = events.makeAsyncIterator()
        guard case .snapshot(var projection) = try #require(await iterator.next()) else {
            Issue.record("expected catch-up snapshot before subsequent records")
            return
        }
        #expect(projection.prefixes.allSatisfy { $0.attributes?.metric == 10 })
        var count = 0
        while let event = await iterator.next() {
            count += 1
            let record: BGPLSRecord
            let withdrawing: Bool
            switch event {
            case .upsert(let value):
                record = value
                withdrawing = false
            case .withdraw(let nlri):
                record = BGPLSRecord(nlri: nlri)
                withdrawing = true
            case .snapshot:
                Issue.record("unexpected additional snapshot")
                continue
            }
            // A snapshot is only a projection: derive this event's projected row,
            // then apply its stable key without inventing missing historical evidence.
            var single = LSRIB()
            single.apply(record)
            let delta = single.snapshot(at: projection.capturedAt)
            for node in delta.nodes {
                projection.nodes.removeAll { $0.ribKey == node.ribKey }
                if !withdrawing { projection.nodes.append(node) }
            }
            for link in delta.links {
                projection.links.removeAll { $0.ribKey == link.ribKey }
                if !withdrawing { projection.links.append(link) }
            }
            for prefix in delta.prefixes {
                projection.prefixes.removeAll { $0.ribKey == prefix.ribKey }
                if !withdrawing { projection.prefixes.append(prefix) }
            }
        }
        projection.nodes.sort { $0.ribKey < $1.ribKey }
        projection.links.sort { $0.ribKey < $1.ribKey }
        projection.prefixes.sort { $0.ribKey < $1.ribKey }
        projection.nodeCount = projection.nodes.count
        projection.linkCount = projection.links.count
        projection.prefixCount = projection.prefixes.count
        #expect(count == 5)
        let current = await session.ribSnapshot(at: projection.capturedAt)
        #expect(projection == current)
    }
}

enum TypedAttributeFixture {
    static func attribute(_ tlvs: [BGPLSTLV]) -> BGPPathAttribute {
        BGPPathAttribute(flags: 0x80, typeCode: 29, value: ByteBuffer(bytes: IPv6TopologyFixture.encode(tlvs)))
    }

    static func prefix() -> [UInt8] {
        let identity = IPv6TopologyFixture.encode([.init(type: 515, value: [0, 0, 0, 0, 0, 1])])
        return IPv6TopologyFixture.wire(
            type: 3, descriptors: [.init(type: 256, value: identity), .init(type: 265, value: [24, 192, 0, 2])])
    }

    static func topology(protocolID: UInt8 = 2) -> [UInt8] {
        let router: [UInt8] = protocolID == 3 ? [192, 0, 2, 1] : [0, 0, 0, 0, 0, 1]
        let identity = IPv6TopologyFixture.encode([.init(type: 515, value: router)])
        let local = BGPLSTLV(type: 256, value: identity)
        let remote = BGPLSTLV(type: 257, value: identity)
        return IPv6TopologyFixture.wire(type: 1, descriptors: [local], protocolID: protocolID)
            + IPv6TopologyFixture.wire(
                type: 2, descriptors: [local, remote, .init(type: 259, value: [192, 0, 2, 1])], protocolID: protocolID)
            + IPv6TopologyFixture.wire(
                type: 3, descriptors: [local, .init(type: 265, value: [24, 192, 0, 2])], protocolID: protocolID)
            + IPv6TopologyFixture.wire(
                type: 4, descriptors: [local, .init(type: 265, value: [64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0])],
                protocolID: protocolID)
    }

    static func update(reaches: [UInt8]? = nil, withdrawals: [UInt8]? = nil, attributes: [BGPPathAttribute] = []) throws
        -> BGPUpdateMessage
    {
        try BGPUpdateParser.parse(body(reaches: reaches, withdrawals: withdrawals, attributes: attributes))
    }

    static func body(reaches: [UInt8]? = nil, withdrawals: [UInt8]? = nil, attributes: [BGPPathAttribute] = [])
        -> ByteBuffer
    {
        var encoded = ByteBuffer()
        for (code, wire) in [(UInt8(14), reaches), (UInt8(15), withdrawals)] {
            guard let wire else { continue }
            var value = ByteBuffer()
            value.writeInteger(UInt16(16_388))
            value.writeInteger(UInt8(71))
            if code == 14 { value.writeBytes([4, 192, 0, 2, 254, 0]) }
            value.writeBytes(wire)
            encoded.writeBytes([0x90, code])
            encoded.writeInteger(UInt16(value.readableBytes))
            encoded.writeBuffer(&value)
        }
        for attribute in attributes {
            encoded.writeInteger(attribute.flags | 0x10)
            encoded.writeInteger(attribute.typeCode)
            encoded.writeInteger(UInt16(attribute.value.readableBytes))
            encoded.writeBytes(attribute.value.readableBytesView)
        }
        var body = ByteBuffer()
        body.writeInteger(UInt16(0))
        body.writeInteger(UInt16(encoded.readableBytes))
        body.writeBuffer(&encoded)
        return body
    }
}
