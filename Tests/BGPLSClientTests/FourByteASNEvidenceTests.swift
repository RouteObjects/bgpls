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
import Testing

@testable import BGPLSClient

struct FourByteASNEvidenceTests {
    @Test(arguments: [UInt32(65_536), 4_200_000_001, UInt32.max])
    func topologyASNRetainsFullWidthIdentityAndWithdrawal(asn: UInt32) throws {
        func wire(_ value: UInt32) -> [UInt8] {
            var bytes = ByteBuffer()
            bytes.writeInteger(value)
            let descriptor = BGPLSTLV(
                type: 256,
                value: IPv6TopologyFixture.encode([
                    BGPLSTLV(type: 512, value: Array(bytes.readableBytesView)),
                    BGPLSTLV(type: 515, value: [0, 0, 0, 0, 0, 1]),
                ])
            )
            return IPv6TopologyFixture.wire(type: 1, descriptors: [descriptor])
        }
        let highWire = wire(asn)
        let lowWire = wire(65_001)
        guard case .node(let node) = try IPv6TopologyFixture.parse(highWire),
            case .node(let lowNode) = try IPv6TopologyFixture.parse(lowWire)
        else {
            Issue.record("Expected two typed Node NLRIs")
            return
        }
        #expect(node.localNode.autonomousSystem == AutonomousSystemNumber(asn))
        #expect(LSRIB.nodeKey(node) != LSRIB.nodeKey(lowNode))
        var rib = LSRIB()
        let diffs = try rib.apply(update: IPv6TopologyFixture.update(reachable: true, nlris: highWire + lowWire))
        #expect(diffs.count == 2)
        #expect(rib.nodeCount == 2)
        #expect(rib.dump(topic: "nodes").contains("node 0000.0000.0001 AS \(asn)"))
        let snapshot = rib.snapshot(at: Date(timeIntervalSince1970: 0))
        let json = try snapshot.jsonUTF8String()
        #expect(json.contains(String(asn)))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        #expect(try decoder.decode(RIBSnapshot.self, from: Data(json.utf8)) == snapshot)
        let withdrawals = try rib.apply(update: IPv6TopologyFixture.update(reachable: false, nlris: highWire))
        #expect(withdrawals == [.withdraw(.node(node))])
        #expect(rib.nodeCount == 1)
        #expect(rib.nodes[LSRIB.nodeKey(lowNode)]?.nlri == lowNode)
    }

    @Test(arguments: [false, true])
    func pathAttributesRemainExactOpaqueEvidence(fourOctet: Bool) throws {
        //  AS_PATH width depends on OPEN negotiation, not the ASN's magnitude.
        // These synthetic nonempty paths prove preservation, not path reconstruction.
        var path = ByteBuffer(bytes: [2, 2])  // AS_SEQUENCE containing two ASNs.
        var aggregator = ByteBuffer()
        if fourOctet {
            path.writeInteger(UInt32(65_001))
            path.writeInteger(UInt32(4_200_000_001))
            aggregator.writeInteger(UInt32(4_200_000_001))
        } else {
            path.writeInteger(UInt16(65_001))
            path.writeInteger(UInt16(23_456))
            aggregator.writeInteger(UInt16(23_456))
        }
        aggregator.writeBytes([192, 0, 2, 254])
        let evidence: [(UInt8, [UInt8])] = [
            (2, Array(path.readableBytesView)), (7, Array(aggregator.readableBytesView)),
            (17, [2, 1, 0xfa, 0x56, 0xea, 0x01]), (18, [0xfa, 0x56, 0xea, 0x01, 192, 0, 2, 254]),
        ]
        var attributes = ByteBuffer()
        for (code, value) in evidence {
            attributes.writeInteger(UInt8(code == 2 ? 0x40 : 0xc0))
            attributes.writeInteger(code)
            attributes.writeInteger(UInt8(value.count))
            attributes.writeBytes(value)
        }
        let nodeWire = IPv6TopologyFixture.wire(type: 1, descriptors: [IPv6TopologyFixture.nodeDescriptor()])
        var base = IPv6TopologyFixture.updateBody(reachable: true, nlris: nodeWire)
        base.moveReaderIndex(forwardBy: 4)
        attributes.writeBuffer(&base)
        var body = ByteBuffer()
        body.writeInteger(UInt16(0))
        body.writeInteger(UInt16(attributes.readableBytes))
        body.writeBuffer(&attributes)
        let update = try BGPUpdateParser.parse(body)
        for (index, item) in evidence.enumerated() {
            #expect(update.pathAttributes[index].typeCode == item.0)
            #expect(Array(update.pathAttributes[index].value.readableBytesView) == item.1)
        }
        var rib = LSRIB()
        #expect(try rib.apply(update: update).count == 1)
        #expect(rib.nodeCount == 1)
    }
}
