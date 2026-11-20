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

struct TypedAttributePresentationTests {
    private let capturedAt = Date(timeIntervalSince1970: 0)

    @Test(arguments: [nil, UInt32(65_001), UInt32(4_200_000_001)], [false, true])
    func nodeASNLabelsDescribeAdvertisedMetadata(asn: UInt32?, showAttributes: Bool) throws {
        let source = try #require(records(name: "edge", metric: 10).first)
        guard case .node(var node) = source else {
            Issue.record("Expected node record")
            return
        }
        node.nlri.localNode.autonomousSystem = asn.map { AutonomousSystemNumber($0) }
        let record = BGPLSRecord.node(node)
        var rib = LSRIB()
        rib.apply(record)
        let label = asn.map(String.init) ?? "not-advertised"
        let line = "node 192.0.2.1 AS \(label)" + (showAttributes ? " \(record.attributeSummary)" : "")
        #expect(rib.dump(topic: "nodes", showAttributes: showAttributes) == line)
        #expect(rib.dump(showAttributes: showAttributes) == "nodes=1 links=0 prefixes=0\n" + line)
        #expect(rib.snapshot(at: capturedAt).nodes.first?.autonomousSystem?.rawValue == asn)
        #expect(RIBDiff.upsert(record).watchLine == "WATCH upsert node 192.0.2.1")
    }

    @Test
    func defaultWatchAndDumpTextStayIdentityOnly() throws {
        let records = try records(name: "edge-ceos", metric: 10)
        let expected = [
            "node 192.0.2.1",
            "link 192.0.2.1 192.0.2.1 → 192.0.2.2 192.0.2.2",
            "prefix 192.0.2.0/24 node 192.0.2.1",
            "prefix 2001:db8::/64 node 192.0.2.1",
        ]
        var rib = LSRIB()
        for (record, identity) in zip(records, expected) {
            rib.apply(record)
            let upsert = RIBDiff.upsert(record)
            let withdrawal = RIBDiff.withdraw(record.nlri)
            #expect(upsert.watchLine == "WATCH upsert \(identity)")
            #expect(upsert.watchLine(showAttributes: false) == upsert.watchLine)
            #expect(withdrawal.watchLine == "WATCH withdraw \(identity)")
            #expect(withdrawal.watchLine(showAttributes: true) == withdrawal.watchLine)
            #expect(upsert.watchLine(showAttributes: true).hasPrefix(upsert.watchLine + " attributes=present"))
        }
        #expect(rib.dump(topic: "nodes") == "node 192.0.2.1 AS 65001")
        #expect(!rib.dump().contains("name="))
        #expect(!rib.dump().contains("metric="))
        #expect(rib.dump(showAttributes: true).contains("name=\"edge-ceos\""))
        #expect(rib.dump(showAttributes: true).contains("prefix-metric=10"))
        let catchUp = RIBDiff.snapshot(rib.snapshot(at: capturedAt))
        #expect(catchUp.watchLine == "WATCH snapshot nodes=1 links=1 prefixes=2")
        #expect(catchUp.watchLine(showAttributes: true) == catchUp.watchLine)
        let unknown = BGPLSRecord(nlri: .unknown(type: 999, raw: [1, 2, 3]))
        #expect(RIBDiff.upsert(unknown).watchLine == "WATCH upsert unknown type=999")
        #expect(
            RIBDiff.upsert(unknown).watchLine(showAttributes: true) == "WATCH upsert unknown type=999 attributes=absent"
        )
    }

    @Test
    func optInNamesCannotInjectTerminalControlsOrLines() throws {
        let name = "edge\u{0}\t\n\r\u{1b}[31m\"\\\u{7f}"
        let record = try #require(records(name: name, metric: 0).first)
        let line = RIBDiff.upsert(record).watchLine(showAttributes: true)
        #expect(line == #"WATCH upsert node 192.0.2.1 attributes=present name="edge\0\t\n\r\u{1b}[31m\"\\\u{7f}""#)
        #expect(!line.contains("\n"))
        #expect(!line.contains("\r"))
        #expect(!line.contains("\u{1b}"))
        guard case .node(let node) = record else {
            Issue.record("Expected node record")
            return
        }
        #expect(node.attributes.name == name)

        // Public models and decoded snapshots may be constructed independently of the wire
        // parser. Their names also cannot introduce Unicode line separators into a terminal.
        let constructed = BGPLSRecord.node(
            .init(nlri: node.nlri, attributes: .init(name: "a\u{85}\u{2028}\u{2029}b")))
        #expect(constructed.attributeSummary.contains(#"name="a\u{85}\u{2028}\u{2029}b""#))
    }

    @Test
    func optInBandwidthFieldsAreNamedAndUnitQualifiedInPriorityOrder() throws {
        let record = try #require(records(name: "edge", metric: 10).dropFirst().first)
        let line = record.attributeSummary
        #expect(line.contains("igp-metric=10"))
        #expect(line.contains("maximum-link-bandwidth=125000000.0B/s(1000000000.0bit/s)"))
        #expect(line.contains("maximum-reservable-bandwidth=250000000.0B/s(2000000000.0bit/s)"))
        #expect(line.contains("unreserved-bandwidth=[0:0.0B/s(0.0bit/s),1:1.0B/s(8.0bit/s),2:2.0B/s(16.0bit/s)"))
        #expect(line.hasSuffix("7:7.0B/s(56.0bit/s)]"))

        let absent = BGPLSRecord(nlri: record.nlri)
        #expect(
            absent.attributeSummary
                == "attributes=absent igp-metric=unavailable maximum-link-bandwidth=unavailable maximum-reservable-bandwidth=unavailable unreserved-bandwidth=unavailable"
        )
        let discarded = BGPLSRecord(
            nlri: record.nlri, decoded: BGPLSAttributeDecoder.decode(pathAttributes: [attribute([0])]))
        #expect(discarded.attributeSummary.hasPrefix("attributes=discarded igp-metric=unavailable"))
    }

    @Test
    func snapshotIncludesTypedProjectionsButNotRawPacketEvidence() throws {
        var rib = LSRIB()
        for record in try records(name: "edge-ceos", metric: 10) { rib.apply(record) }
        let snapshot = rib.snapshot(at: capturedAt)
        #expect(snapshot.nodes.first?.attributes?.name == "edge-ceos")
        #expect(snapshot.links.first?.attributes?.igpMetric == 10)
        #expect(snapshot.links.first?.attributes?.maximumLinkBandwidth?.bytesPerSecond == 125_000_000)
        #expect(snapshot.links.first?.attributes?.unreservedBandwidth?.values.count == 8)
        #expect(snapshot.prefixes.allSatisfy { $0.attributes?.metric == 10 })
        #expect(snapshot.nodes.first?.attributeAvailability == .present)
        #expect(snapshot.links.first?.attributeIssues == [])
        #expect(snapshot.prefixes.map(\.network.description).sorted() == ["192.0.2.0/24", "2001:db8::/64"])
        let json = try snapshot.jsonUTF8String()
        #expect(!json.contains("originalBytes"))
        #expect(!json.contains("tlvs"))
        #expect(!json.contains("flags"))
        #expect(try decode(json) == snapshot)
    }

    @Test
    func legacySnapshotOmissionsMeanNotRecordedRatherThanAbsent() throws {
        var rib = LSRIB()
        for record in try records(name: "edge", metric: 10) { rib.apply(record) }
        let snapshot = rib.snapshot(at: capturedAt)
        var object = try #require(
            JSONSerialization.jsonObject(with: Data(snapshot.jsonUTF8String().utf8)) as? [String: Any])
        for collection in ["nodes", "links", "prefixes"] {
            let records = try #require(object[collection] as? [[String: Any]])
            object[collection] = records.map { record in
                record.filter { !["attributes", "attributeAvailability", "attributeIssues"].contains($0.key) }
            }
        }
        let oldJSON = try JSONSerialization.data(withJSONObject: object)
        let legacy = try decode(String(decoding: oldJSON, as: UTF8.self))
        #expect(
            legacy.nodes.allSatisfy {
                $0.attributes == nil && $0.attributeAvailability == nil && $0.attributeIssues == nil
            })
        #expect(
            legacy.links.allSatisfy {
                $0.attributes == nil && $0.attributeAvailability == nil && $0.attributeIssues == nil
            })
        #expect(
            legacy.prefixes.allSatisfy {
                $0.attributes == nil && $0.attributeAvailability == nil && $0.attributeIssues == nil
            })
        #expect(try decode(legacy.jsonUTF8String()) == legacy)

        let first = try #require(records(name: "edge", metric: 10).first)
        var absentRIB = LSRIB()
        absentRIB.apply(BGPLSRecord(nlri: first.nlri))
        let absent = try #require(absentRIB.snapshot(at: capturedAt).nodes.first)
        #expect(absent.attributeAvailability == .absent)
        #expect(absent.attributes == BGPLSNodeAttributes())
        #expect(absent.attributeIssues == [])
    }

    @Test
    func snapshotIssueSummariesPreserveCoordinatesWithoutRawEvidence() throws {
        let first = try #require(records(name: "edge", metric: 10).first)
        let decoded = BGPLSAttributeDecoder.decode(pathAttributes: [attribute(tlv(1026, [0xff]))])
        let record = BGPLSRecord(nlri: first.nlri, decoded: decoded)
        var rib = LSRIB()
        rib.apply(record)
        let snapshot = rib.snapshot(at: capturedAt)
        let node = try #require(snapshot.nodes.first)
        #expect(node.attributeAvailability == .present)
        #expect(node.attributes?.name == nil)
        let issue = try #require(node.attributeIssues?.first)
        #expect(issue.disposition == .projectionRejected)
        #expect(issue.category == .invalidASCII)
        #expect(issue.attributeIndex == 0)
        #expect(issue.tlvIndex == 0)
        #expect(issue.tlvType == 1026)
        #expect(issue.byteOffset == 0)
        #expect(record.observation.diagnostics.first?.originalBytes == tlv(1026, [0xff]))
        let json = try snapshot.jsonUTF8String()
        #expect(!json.contains("originalBytes"))
        #expect(try decode(json) == snapshot)
    }

    @Test(arguments: [Float(0), -Float.zero, Float.leastNonzeroMagnitude, Float.greatestFiniteMagnitude])
    func validatedBandwidthRoundTripsThroughSnapshotJSON(bytesPerSecond: Float) throws {
        let source = try #require(records(name: "edge", metric: 10).dropFirst().first)
        guard case .link(var link) = source else {
            Issue.record("Expected link record")
            return
        }
        let bandwidth = try #require(BGPLSBandwidth(bytesPerSecond: bytesPerSecond))
        link.attributes.maximumLinkBandwidth = bandwidth
        var rib = LSRIB()
        rib.apply(.link(link))
        let snapshot = rib.snapshot(at: capturedAt)
        let decoded = try decode(snapshot.jsonUTF8String())
        #expect(decoded == snapshot)
        #expect(decoded.links.first?.attributes?.maximumLinkBandwidth?.bytesPerSecond == bytesPerSecond)
        #expect(decoded.links.first?.attributes?.maximumLinkBandwidth?.bitsPerSecond.isFinite == true)
    }

    @Test(arguments: ["-1", "1e100", #""NaN""#, #""Infinity""#])
    func snapshotJSONCannotBypassBandwidthValidation(invalid: String) throws {
        var rib = LSRIB()
        for record in try records(name: "edge", metric: 10) { rib.apply(record) }
        let json = try rib.snapshot(at: capturedAt).jsonUTF8String(pretty: false)
        var object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        var links = try #require(object["links"] as? [[String: Any]])
        var attributes = try #require(links[0]["attributes"] as? [String: Any])
        attributes["maximumLinkBandwidth"] = "INVALID_BANDWIDTH_TEST_VALUE"
        links[0]["attributes"] = attributes
        object["links"] = links
        let template = String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
        let changed = template.replacingOccurrences(of: #""INVALID_BANDWIDTH_TEST_VALUE""#, with: invalid)
        #expect(changed != template)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        decoder.nonConformingFloatDecodingStrategy = .convertFromString(
            positiveInfinity: "Infinity", negativeInfinity: "-Infinity", nan: "NaN")
        #expect(throws: (any Error).self) { try decoder.decode(RIBSnapshot.self, from: Data(changed.utf8)) }
    }

    private func records(name: String, metric: UInt8) throws -> [BGPLSRecord] {
        let local = BGPLSNodeIdentity(
            autonomousSystem: AutonomousSystemNumber(65_001), ipv4RouterID: IPv4Address(address: 0xc000_0201))
        let remote = BGPLSNodeIdentity(
            autonomousSystem: AutonomousSystemNumber(65_001), ipv4RouterID: IPv4Address(address: 0xc000_0202))
        let node = BGPLSNLRI.node(.init(protocolID: 3, identifier: 0, localNode: local))
        let link = BGPLSNLRI.link(
            .init(
                protocolID: 3, identifier: 0, localNode: local, remoteNode: remote, linkDescriptors: [],
                localIPv4Interface: local.ipv4RouterID, remoteIPv4Neighbor: remote.ipv4RouterID))
        let v4 = BGPLSNLRI.ipv4Prefix(
            .init(
                protocolID: 3, identifier: 0, localNode: local,
                network: try #require(IPv4Network("192.0.2.0/24")), prefixDescriptors: []))
        let v6 = BGPLSNLRI.ipv6Prefix(
            .init(
                protocolID: 3, identifier: 0, localNode: local,
                network: try #require(IPv6Network("2001:db8::/64")), prefixDescriptors: []))
        let bytes =
            tlv(1026, Array(name.utf8)) + tlv(1095, [0, metric]) + tlv(1155, [0, 0, 0, metric])
            + tlv(1089, binary32(125_000_000)) + tlv(1090, binary32(250_000_000))
            + tlv(1091, (0..<8).flatMap { binary32(Float($0)) })
        let decoded = BGPLSAttributeDecoder.decode(pathAttributes: [attribute(bytes)])
        return [node, link, v4, v6].map { BGPLSRecord(nlri: $0, decoded: decoded) }
    }

    private func decode(_ json: String) throws -> RIBSnapshot {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(RIBSnapshot.self, from: Data(json.utf8))
    }

    private func attribute(_ bytes: [UInt8]) -> BGPPathAttribute {
        .init(flags: 0x80, typeCode: 29, value: ByteBuffer(bytes: bytes))
    }

    private func tlv(_ type: UInt16, _ value: [UInt8]) -> [UInt8] {
        [
            UInt8(type >> 8), UInt8(truncatingIfNeeded: type), UInt8(value.count >> 8),
            UInt8(truncatingIfNeeded: value.count),
        ] + value
    }

    private func binary32(_ value: Float) -> [UInt8] {
        stride(from: 24, through: 0, by: -8).map { UInt8(truncatingIfNeeded: value.bitPattern >> $0) }
    }
}
