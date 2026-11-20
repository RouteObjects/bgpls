//===----------------------------------------------------------------------===//
//
// This source file is part of the bgpls project.
// Copyright (c) 2026 Craig A. Munro
// Licensed under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import BGPLSClient
import Foundation
import NIOCore
import Testing

/// Test-only bridge from independently audited capture bodies to public-library
/// records and snapshots. It never connects to a peer or controls a deployment.
struct TypedAttributeCaptureReplayTests {
    @Test(
        .enabled(
            if: ProcessInfo.processInfo.environment["BGPLS_ATTRIBUTE_REPLAY_INPUT"] != nil,
            "Set BGPLS_ATTRIBUTE_REPLAY_INPUT and BGPLS_ATTRIBUTE_REPLAY_OUTPUT for capture qualification"
        ))
    func externalCapture() throws {
        let environment = ProcessInfo.processInfo.environment
        let inputPath = try #require(environment["BGPLS_ATTRIBUTE_REPLAY_INPUT"])
        let outputPath = try #require(environment["BGPLS_ATTRIBUTE_REPLAY_OUTPUT"])
        guard inputPath.hasPrefix("/"), outputPath.hasPrefix("/"), inputPath != outputPath else {
            throw AttributeReplayError("Replay input and output must be distinct absolute paths")
        }
        guard !FileManager.default.fileExists(atPath: outputPath) else {
            throw AttributeReplayError("Refusing to overwrite replay evidence at \(outputPath)")
        }
        let input = try JSONDecoder().decode(
            AttributeReplayInput.self, from: Data(contentsOf: URL(fileURLWithPath: inputPath)))
        let result = try AttributeCaptureReplay.run(input: input)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        // A fresh result is a completion marker: mismatch or incomplete replay
        // throws before publication, and historical evidence is never overwritten.
        try encoder.encode(result).write(to: URL(fileURLWithPath: outputPath), options: .withoutOverwriting)
    }

    @Test
    func retainedVendorCapturesExerciseExportAndCompleteReplay() throws {
        let frr = try FRRCapturedUpdateTests.Fixture.allCases.map {
            try AttributeCaptureReplay.bytes($0.hex)
        }
        let ceos = try CEOSCapturedUpdateTests.Fixture.allCases.map {
            try AttributeCaptureReplay.bytes($0.hex)
        }
        for (bodies, expectedName) in [(frr, "edge"), (ceos, "edge-ceos")] {
            let result = try AttributeCaptureReplay.run(bodies: bodies)
            #expect(result["updateCount"] == .number(Double(bodies.count)))
            let updates = try #require(result["updates"]?.array)
            let first = try #require(updates.first?["events"]?.array?.first)
            #expect(first["attributes"]?["name"] == .string(expectedName))
            #expect(first["availability"] == .string("present"))
            #expect(first["evidence"]?.array?.first?["attributeIndex"] == .number(4))
            #expect(first["issues"] == .array([]))
            #expect(result["checks"]?["completeRecordReplay"] == .bool(true))
            #expect(result["checks"]?["catchUpReplay"] == .bool(true))
            #expect(result["checks"]?["updateAttributeDiagnostics"] == .bool(true))
            #expect(result["schema"] == .number(2))
            #expect(updates.allSatisfy { $0["attributeDiagnostics"] == .array([]) })
            let encoded = try JSONEncoder().encode(result)
            #expect(try JSONDecoder().decode(AttributeReplayJSON.self, from: encoded) == result)
        }
    }

    @Test
    func retainedDualStackCapturesExportBothPrefixFamiliesAndRestoration() throws {
        let captures = [
            FRRDualStackCapturedUpdateTests.Fixture.allCases.map(\.hex),
            CEOSDualStackCapturedUpdateTests.Fixture.allCases.map(\.hex),
        ]
        for messages in captures {
            let bodies = try messages.map { try AttributeCaptureReplay.messageBody($0) }
            let result = try AttributeCaptureReplay.run(bodies: bodies)
            let updates = try #require(result["updates"]?.array)
            let displays = updates.flatMap { $0["events"]?.array ?? [] }.compactMap { $0["display"]?.string }
            #expect(displays.contains { $0.hasPrefix("prefix 2001:db8:") })
            #expect(displays.contains { $0.hasPrefix("prefix 10.255.") })
            #expect(result["checks"]?["snapshotRoundTrips"] == .bool(true))
        }
    }

    @Test
    func replacementGapsEvidenceAndWithdrawalsSurviveReplay() throws {
        let topology = TypedAttributeFixture.topology()
        let good = TypedAttributeFixture.attribute([
            .init(type: 1026, value: Array("router\n\u{1b}[31m".utf8)),
            .init(type: 1095, value: [0, 0, 10]),
            .init(type: 1089, value: [0x80, 0, 0, 0]),
            .init(type: 1155, value: [0, 0, 0, 99]),
            .init(type: 60_000, value: [1, 2, 3]),
        ])
        let unusable = TypedAttributeFixture.attribute([
            .init(type: 1095, value: [10]), .init(type: 1095, value: [20]),
            .init(type: 1089, value: [0x7f, 0x80, 0, 0]),
        ])
        let malformed = BGPPathAttribute(flags: 0x80, typeCode: 29, value: ByteBuffer(bytes: [4, 2, 0]))
        let bodies = [
            TypedAttributeFixture.body(reaches: topology, attributes: [good]),
            TypedAttributeFixture.body(reaches: topology, attributes: [unusable]),
            TypedAttributeFixture.body(reaches: topology, attributes: [malformed]),
            TypedAttributeFixture.body(reaches: topology),
            TypedAttributeFixture.body(reaches: topology, attributes: [good]),
            TypedAttributeFixture.body(withdrawals: topology),
        ].map { Array($0.readableBytesView) }
        let result = try AttributeCaptureReplay.run(bodies: bodies)
        let updates = try #require(result["updates"]?.array)
        let firstEvents = try #require(updates[0]["events"]?.array)
        #expect(firstEvents[0]["attributes"]?["name"] == .string("router\n\u{1b}[31m"))
        #expect(firstEvents[1]["attributes"]?["maximumLinkBandwidth"] == .number(0))
        #expect(firstEvents[1]["attributes"]?["maximumReservableBandwidth"] == .null)
        #expect(firstEvents[0]["evidence"]?.array?.first?["tlvs"]?.array?.last?["type"] == .number(60_000))
        let rejected = try #require(updates[1]["events"]?.array?[1])
        #expect(rejected["attributes"]?["igpMetric"] == .null)
        #expect(rejected["issues"]?.array?.count == 2)
        #expect(updates[2]["events"]?.array?.first?["availability"] == .string("discarded"))
        #expect(updates[3]["events"]?.array?.first?["availability"] == .string("absent"))
        #expect(updates[4]["events"] == updates[0]["events"])
        #expect(updates[5]["events"]?.array?.allSatisfy { $0.object?.count == 3 } == true)
        #expect(result["finalRecords"] == .array([]))
    }

    @Test
    func independentExpectationMismatchAndInvalidHexCannotPublishSuccess() throws {
        let body = try AttributeCaptureReplay.bytes(FRRCapturedUpdateTests.Fixture.edgeNode.hex)
        #expect(throws: AttributeReplayError.self) {
            try AttributeCaptureReplay.run(bodies: [body], expectedEvents: [[]])
        }
        for text in ["0", "gg", "0x01", "00\nzz"] {
            #expect(throws: AttributeReplayError.self) { try AttributeCaptureReplay.bytes(text) }
        }
        let output = try AttributeCaptureReplay.run(bodies: [body])
        let expected = try #require(output["updates"]?.array?.first?["events"]?.array)
        #expect(
            try AttributeCaptureReplay.run(bodies: [body], expectedEvents: [expected]) == output)
    }

    @Test(arguments: [false, true])
    func withdrawalAndEndOfRIBExportDiagnosticsWithoutUpserts(endOfRIB: Bool) throws {
        let topology = TypedAttributeFixture.topology()
        let malformed = BGPPathAttribute(flags: 0x80, typeCode: 29, value: ByteBuffer(bytes: [4, 2, 0]))
        let bodies = [
            TypedAttributeFixture.body(reaches: topology),
            TypedAttributeFixture.body(withdrawals: endOfRIB ? [] : topology, attributes: [malformed]),
            TypedAttributeFixture.body(withdrawals: endOfRIB ? [] : topology),
        ].map { Array($0.readableBytesView) }
        let expected: AttributeReplayJSON = .object([
            "disposition": .string("attributeDiscarded"), "category": .string("malformedFraming"),
            "attributeIndex": .number(1), "tlvIndex": .number(0), "tlvType": .number(1026),
            "byteOffset": .number(0), "originalHex": .string("040200"),
        ])
        let result = try AttributeCaptureReplay.run(
            bodies: bodies, expectedAttributeDiagnostics: [[], [expected], []])
        let updates = try #require(result["updates"]?.array)
        #expect(updates[0]["attributeDiagnostics"] == .array([]))
        #expect(updates[1]["attributeDiagnostics"] == .array([expected]))
        #expect(updates[2]["attributeDiagnostics"] == .array([]))
        let events = try #require(updates[1]["events"]?.array)
        if endOfRIB {
            #expect(events.isEmpty)
            #expect(result["finalRecords"]?.array?.count == 4)
        } else {
            #expect(events.count == 4)
            #expect(events.allSatisfy { $0["operation"] == .string("withdraw") && $0.object?.count == 3 })
            #expect(result["finalRecords"] == .array([]))
        }
    }

    @Test(arguments: [false, true])
    func noUpsertDiagnosticMismatchCannotPublishSuccess(endOfRIB: Bool) throws {
        // A complete unknown TLV precedes the malformed header, so coordinates
        // are nonzero. An excluded outer duplicate also makes ordering observable.
        let malformed = BGPPathAttribute(
            flags: 0x80, typeCode: 29, value: ByteBuffer(bytes: [234, 96, 0, 1, 7, 4, 2, 0]))
        let duplicate = TypedAttributeFixture.attribute([.init(type: 60_001, value: [8])])
        let body = Array(
            TypedAttributeFixture.body(
                withdrawals: endOfRIB ? [] : TypedAttributeFixture.topology(), attributes: [malformed, duplicate]
            ).readableBytesView)
        let first: [String: AttributeReplayJSON] = [
            "disposition": .string("attributeDiscarded"), "category": .string("malformedFraming"),
            "attributeIndex": .number(1), "tlvIndex": .number(1), "tlvType": .number(1026),
            "byteOffset": .number(5), "originalHex": .string("040200"),
        ]
        let second: AttributeReplayJSON = .object([
            "disposition": .string("acceptedWithWarning"), "category": .string("duplicateAttribute"),
            "attributeIndex": .number(2), "tlvIndex": .null, "tlvType": .null,
            "byteOffset": .null, "originalHex": .string("ea61000108"),
        ])
        let expected: [AttributeReplayJSON] = [.object(first), second]
        let result = try AttributeCaptureReplay.run(bodies: [body], expectedAttributeDiagnostics: [expected])
        #expect(result["updates"]?.array?.first?["attributeDiagnostics"] == .array(expected))
        let mutations: [String: AttributeReplayJSON] = [
            "disposition": .string("projectionRejected"), "category": .string("invalidLength"),
            "attributeIndex": .number(0), "tlvIndex": .number(0), "tlvType": .number(1027),
            "byteOffset": .number(0), "originalHex": .string("040201"),
        ]
        var mismatches: [[AttributeReplayJSON]] = [[], [.object(first)], [second, .object(first)]]
        for (key, value) in mutations {
            var changed = first
            changed[key] = value
            mismatches.append([.object(changed), second])
        }
        for mismatch in mismatches {
            #expect(throws: AttributeReplayError.self) {
                try AttributeCaptureReplay.run(bodies: [body], expectedAttributeDiagnostics: [mismatch])
            }
        }
        #expect(throws: AttributeReplayError.self) {
            try AttributeCaptureReplay.run(bodies: [body], expectedAttributeDiagnostics: [])
        }
        let clean = Array(TypedAttributeFixture.body(withdrawals: []).readableBytesView)
        #expect(throws: AttributeReplayError.self) {
            try AttributeCaptureReplay.run(bodies: [clean], expectedAttributeDiagnostics: [expected])
        }
    }

    @Test
    func externalReplayRequiresCurrentSchemaAndExplicitDiagnostics() throws {
        let missingDiagnostics = Data(#"{"schema":2,"updates":[{"bodyHex":"00000000","events":[]}]}"#.utf8)
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(AttributeReplayInput.self, from: missingDiagnostics)
        }
        for schema in [1, 2] {
            let data = Data(
                """
                {"schema":\(schema),"updates":[{"bodyHex":"00000000","events":[],"attributeDiagnostics":[]}]}
                """.utf8)
            let input = try JSONDecoder().decode(AttributeReplayInput.self, from: data)
            if schema == 1 {
                #expect(throws: AttributeReplayError.self) { try AttributeCaptureReplay.run(input: input) }
            } else {
                let result = try AttributeCaptureReplay.run(input: input)
                #expect(result["updates"]?.array?.first?["attributeDiagnostics"] == .array([]))
                #expect(result["checks"]?["updateAttributeDiagnostics"] == .bool(true))
            }
        }
    }
}

private struct AttributeReplayInput: Decodable {
    let schema: Int
    let updates: [Update]

    struct Update: Decodable {
        let bodyHex: String
        let events: [AttributeReplayJSON]
        let attributeDiagnostics: [AttributeReplayJSON]
    }
}

private struct AttributeReplayError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// JSON values make nulls explicit and compare binary32 advertisements after exact
/// widening to Double, rather than comparing differently rounded JSON text.
private indirect enum AttributeReplayJSON: Codable, Equatable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([Self])
    case object([String: Self])

    var array: [Self]? { if case .array(let value) = self { value } else { nil } }
    var object: [String: Self]? { if case .object(let value) = self { value } else { nil } }
    var string: String? { if case .string(let value) = self { value } else { nil } }
    subscript(key: String) -> Self? { object?[key] }

    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([Self].self) {
            self = .array(value)
        } else {
            self = .object(try container.decode([String: Self].self))
        }
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

private enum AttributeCaptureReplay {
    typealias JSON = AttributeReplayJSON
    static let capturedAt = Date(timeIntervalSince1970: 0)

    static func run(input: AttributeReplayInput) throws -> JSON {
        guard input.schema == 2, !input.updates.isEmpty else {
            throw AttributeReplayError("Replay requires schema 2 and at least one UPDATE")
        }
        return try run(
            bodies: input.updates.map { try bytes($0.bodyHex) }, expectedEvents: input.updates.map(\.events),
            expectedAttributeDiagnostics: input.updates.map(\.attributeDiagnostics))
    }

    static func run(
        bodies: [[UInt8]], expectedEvents: [[JSON]]? = nil, expectedAttributeDiagnostics: [[JSON]]? = nil
    ) throws -> JSON {
        if let expectedEvents, expectedEvents.count != bodies.count {
            throw AttributeReplayError("Expected-event count does not match UPDATE count")
        }
        if let expectedAttributeDiagnostics, expectedAttributeDiagnostics.count != bodies.count {
            throw AttributeReplayError("Expected-diagnostic count does not match UPDATE count")
        }
        var rib = LSRIB()
        var replay = LSRIB()
        var updates: [JSON] = []
        // Retain a catch-up projection at the midpoint, then apply only subsequent
        // diffs. Historical raw records cannot be reconstructed from a snapshot.
        let catchUpIndex = bodies.count / 2
        var projection = rib.snapshot(at: capturedAt)
        for (index, body) in bodies.enumerated() {
            if index == catchUpIndex { projection = rib.snapshot(at: capturedAt) }
            let update = try BGPUpdateParser.parse(ByteBuffer(bytes: body))
            let original = update
            let result = try rib.applyIsolating(update: update)
            let events = try result.diffs.map(normalize)
            // Diagnostics belong to the UPDATE, including withdrawals and EORs
            // that have no upsert record from which to recover the observation.
            let attributeDiagnostics = result.diagnostics.compactMap { diagnostic -> JSON? in
                guard case .attribute(let issue) = diagnostic else { return nil }
                return normalize(issue)
            }
            if let expectedEvents {
                try compare(events, with: expectedEvents[index], updateIndex: index, field: "events")
            }
            if let expectedAttributeDiagnostics {
                try compare(
                    attributeDiagnostics, with: expectedAttributeDiagnostics[index], updateIndex: index,
                    field: "attributeDiagnostics")
            }
            guard update == original else { throw AttributeReplayError("UPDATE raw evidence changed") }
            for diff in result.diffs {
                switch diff {
                case .upsert(let record): replay.apply(record)
                case .withdraw(let nlri): replay.withdraw(nlri)
                case .snapshot: throw AttributeReplayError("UPDATE unexpectedly produced a snapshot")
                }
                if index >= catchUpIndex { try apply(diff, to: &projection) }
            }
            guard replay == rib else {
                throw AttributeReplayError("Complete-record replay mismatch at UPDATE \(index)")
            }
            let snapshot = rib.snapshot(at: capturedAt)
            let data = try JSONEncoder().encode(snapshot)
            guard try JSONDecoder().decode(RIBSnapshot.self, from: data) == snapshot else {
                throw AttributeReplayError("Snapshot JSON round-trip mismatch at UPDATE \(index)")
            }
            if index >= catchUpIndex, projection != snapshot {
                throw AttributeReplayError("Catch-up projection mismatch at UPDATE \(index)")
            }
            updates.append(
                .object([
                    "bodyHex": .string(hex(body)), "events": .array(events),
                    "attributeDiagnostics": .array(attributeDiagnostics),
                    "snapshot": try JSONDecoder().decode(JSON.self, from: data),
                ]))
        }
        let records =
            rib.nodes.values.map(BGPLSRecord.node) + rib.links.values.map(BGPLSRecord.link)
            + rib.prefixes.values.map(BGPLSRecord.prefix)
        let finalRecords = try records.map { try normalize(.upsert($0)) }.sorted {
            ($0["key"]?.string ?? "") < ($1["key"]?.string ?? "")
        }
        return .object([
            "schema": .number(2), "updateCount": .number(Double(bodies.count)),
            "checks": .object([
                "completeRecordReplay": .bool(true), "snapshotRoundTrips": .bool(true), "catchUpReplay": .bool(true),
                "updateAttributeDiagnostics": .bool(true),
            ]),
            "updates": .array(updates), "finalRecords": .array(finalRecords),
        ])
    }

    static func compare(_ actual: [JSON], with expected: [JSON], updateIndex: Int, field: String) throws {
        guard actual != expected else { return }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let actualText = String(decoding: try encoder.encode(actual), as: UTF8.self)
        let expectedText = String(decoding: try encoder.encode(expected), as: UTF8.self)
        throw AttributeReplayError(
            "UPDATE \(updateIndex) \(field) differs from independent audit:\nexpected \(expectedText)\nactual \(actualText)"
        )
    }

    static func normalize(_ diff: RIBDiff) throws -> JSON {
        let nlri: BGPLSNLRI
        let operation: String
        let record: BGPLSRecord?
        switch diff {
        case .upsert(let value):
            nlri = value.nlri
            operation = "upsert"
            record = value
        case .withdraw(let value):
            nlri = value
            operation = "withdraw"
            record = nil
        case .snapshot: throw AttributeReplayError("Snapshot is not an UPDATE event")
        }
        let prefix = "WATCH \(operation) "
        guard diff.watchLine.hasPrefix(prefix) else { throw AttributeReplayError("Unexpected watch presentation") }
        var object: [String: JSON] = [
            "operation": .string(operation), "key": .string(try key(nlri)),
            "display": .string(String(diff.watchLine.dropFirst(prefix.count))),
        ]
        if let record {
            object["availability"] = .string(record.observation.availability.rawValue)
            object["attributes"] = attributes(record)
            object["evidence"] = .array(
                record.observation.attributes.map { attribute in
                    .object([
                        "attributeIndex": .number(Double(attribute.attributeIndex)),
                        "flags": .number(Double(attribute.flags)), "valueHex": .string(hex(attribute.value)),
                        "tlvs": .array(
                            attribute.tlvs.map { tlv in
                                .object([
                                    "index": .number(Double(tlv.tlvIndex)), "type": .number(Double(tlv.type)),
                                    "byteOffset": .number(Double(tlv.byteOffset)), "valueHex": .string(hex(tlv.value)),
                                ])
                            }),
                    ])
                })
            object["issues"] = .array(record.observation.diagnostics.map(normalize))
        }
        return .object(object)
    }

    static func normalize(_ issue: BGPLSAttributeDiagnostic) -> JSON {
        .object([
            "disposition": .string(issue.disposition.rawValue), "category": .string(issue.category.rawValue),
            "attributeIndex": .number(Double(issue.attributeIndex)),
            "tlvIndex": number(issue.tlvIndex), "tlvType": number(issue.tlvType),
            "byteOffset": number(issue.byteOffset), "originalHex": .string(hex(issue.originalBytes)),
        ])
    }

    static func attributes(_ record: BGPLSRecord) -> JSON {
        switch record {
        case .node(let node):
            .object(["name": node.attributes.name.map(JSON.string) ?? .null])
        case .link(let link):
            .object([
                "igpMetric": number(link.attributes.igpMetric),
                "maximumLinkBandwidth": bandwidth(link.attributes.maximumLinkBandwidth),
                "maximumReservableBandwidth": bandwidth(link.attributes.maximumReservableBandwidth),
                "unreservedBandwidth": link.attributes.unreservedBandwidth.map {
                    .array($0.values.map { .number(Double($0.bytesPerSecond)) })
                } ?? .null,
            ])
        case .prefix(let prefix): .object(["metric": number(prefix.attributes.metric)])
        case .unknown: .object([:])
        }
    }

    static func number<T: BinaryInteger>(_ value: T?) -> JSON { value.map { .number(Double($0)) } ?? .null }
    static func bandwidth(_ value: BGPLSBandwidth?) -> JSON {
        value.map { .number(Double($0.bytesPerSecond)) } ?? .null
    }

    static func key(_ nlri: BGPLSNLRI) throws -> String {
        if case .unknown(let type, let raw) = nlri { return "unknown:\(type):\(hex(raw))" }
        // RIB key helpers are internal. A one-record public snapshot exposes the
        // authoritative key without duplicating the library's identity algorithm.
        var single = LSRIB()
        single.apply(BGPLSRecord(nlri: nlri))
        let snapshot = single.snapshot(at: capturedAt)
        guard
            let value = snapshot.nodes.first?.ribKey ?? snapshot.links.first?.ribKey ?? snapshot.prefixes.first?.ribKey
        else { throw AttributeReplayError("Supported NLRI did not produce a snapshot key") }
        return value
    }

    static func apply(_ diff: RIBDiff, to projection: inout RIBSnapshot) throws {
        let record: BGPLSRecord
        let withdrawing: Bool
        switch diff {
        case .upsert(let value):
            record = value
            withdrawing = false
        case .withdraw(let nlri):
            record = BGPLSRecord(nlri: nlri)
            withdrawing = true
        case .snapshot: throw AttributeReplayError("Unexpected additional catch-up snapshot")
        }
        var single = LSRIB()
        single.apply(record)
        let delta = single.snapshot(at: projection.capturedAt)
        for row in delta.nodes {
            projection.nodes.removeAll { $0.ribKey == row.ribKey }
            if !withdrawing { projection.nodes.append(row) }
        }
        for row in delta.links {
            projection.links.removeAll { $0.ribKey == row.ribKey }
            if !withdrawing { projection.links.append(row) }
        }
        for row in delta.prefixes {
            projection.prefixes.removeAll { $0.ribKey == row.ribKey }
            if !withdrawing { projection.prefixes.append(row) }
        }
        projection.nodes.sort { $0.ribKey < $1.ribKey }
        projection.links.sort { $0.ribKey < $1.ribKey }
        projection.prefixes.sort { $0.ribKey < $1.ribKey }
        projection.nodeCount = projection.nodes.count
        projection.linkCount = projection.links.count
        projection.prefixCount = projection.prefixes.count
    }

    static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

    static func bytes(_ text: String) throws -> [UInt8] {
        let digits = Array(text.filter { !$0.isWhitespace }.utf8)
        guard digits.count.isMultiple(of: 2) else { throw AttributeReplayError("Odd-length hexadecimal input") }
        guard digits.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else {
            throw AttributeReplayError("Invalid hexadecimal input")
        }
        return try stride(from: 0, to: digits.count, by: 2).map { offset in
            let pair = String(decoding: digits[offset..<(offset + 2)], as: UTF8.self)
            guard let value = UInt8(pair, radix: 16) else { throw AttributeReplayError("Invalid hexadecimal input") }
            return value
        }
    }

    static func messageBody(_ text: String) throws -> [UInt8] {
        let message = try bytes(text)
        guard message.count >= 19, message.prefix(16).allSatisfy({ $0 == 255 }), message[18] == 2,
            Int(message[16]) * 256 + Int(message[17]) == message.count
        else { throw AttributeReplayError("Fixture is not one complete BGP UPDATE") }
        return Array(message.dropFirst(19))
    }
}
