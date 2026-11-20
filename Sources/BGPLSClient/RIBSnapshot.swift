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

/// Point-in-time, serializable projection of ``LSRIB`` for application consumers.
///
/// Router identities retain their IGP-specific form; swift-cidr remains the currency for
/// IP addresses, networks, and AS numbers. Records with missing or opaque router identities
/// are preserved. The stable RIB key and protocol/instance fields distinguish otherwise
/// identical displayed identities across IGP domains.
///
/// Attribute fields are projections, not packet archives. A nil attribute availability
/// means an older snapshot did not record attributes; it does not imply wire absence.
public struct RIBSnapshot: Sendable, Hashable, Codable {
    public var capturedAt: Date
    public var nodeCount: Int
    public var linkCount: Int
    public var prefixCount: Int
    public var nodes: [Node]
    public var links: [Link]
    public var prefixes: [Prefix]

    public struct Node: Sendable, Hashable, Codable {
        public var ribKey: String
        public var protocolID: UInt8
        public var identifier: UInt64
        public var routerID: BGPLSIGPRouterID?
        public var autonomousSystem: AutonomousSystemNumber?
        public var attributes: BGPLSNodeAttributes?
        public var attributeAvailability: BGPLSAttributeAvailability?
        public var attributeIssues: [AttributeIssue]?

        /// Compatibility projection for consumers that specifically need an OSPF Router-ID.
        public var ipv4RouterID: IPv4Address? { routerID?.ipv4RouterID }
    }

    public struct Link: Sendable, Hashable, Codable {
        public var ribKey: String
        public var protocolID: UInt8
        public var identifier: UInt64
        public var localRouterID: BGPLSIGPRouterID?
        public var localInterface: IPv4Address?
        public var remoteRouterID: BGPLSIGPRouterID?
        public var remoteInterface: IPv4Address?
        //  Retain the IPv4 JSON keys and use optional additions so old snapshots
        // decode with nil IPv6 fields, while dual-address links retain both families.
        public var localIPv6Interface: IPv6Address?
        public var remoteIPv6Interface: IPv6Address?
        public var localLinkIdentifier: UInt32?
        public var remoteLinkIdentifier: UInt32?
        public var attributes: BGPLSLinkAttributes?
        public var attributeAvailability: BGPLSAttributeAvailability?
        public var attributeIssues: [AttributeIssue]?

        /// Compatibility projections; IS-IS identities do not become IPv4 addresses.
        public var localIPv4RouterID: IPv4Address? { localRouterID?.ipv4RouterID }
        public var remoteIPv4RouterID: IPv4Address? { remoteRouterID?.ipv4RouterID }
    }

    public struct Prefix: Sendable, Hashable, Codable {
        public var ribKey: String
        public var protocolID: UInt8
        public var identifier: UInt64
        /// Observed topology prefix (canonical network).
        //  AnyIPNetwork uses the same canonical CIDR string encoding as IPv4Network,
        // preserving the existing JSON shape while allowing IPv6 topology records.
        public var network: AnyIPNetwork
        public var nodeRouterID: BGPLSIGPRouterID?
        public var attributes: BGPLSPrefixAttributes?
        public var attributeAvailability: BGPLSAttributeAvailability?
        public var attributeIssues: [AttributeIssue]?

        /// Compatibility projection for an OSPF node's Router-ID.
        public var nodeIPv4RouterID: IPv4Address? { nodeRouterID?.ipv4RouterID }
    }

    /// Structured collection-gap summary without raw packet evidence.
    public struct AttributeIssue: Sendable, Hashable, Codable {
        public var disposition: BGPLSAttributeDiagnostic.Disposition
        public var category: BGPLSAttributeDiagnostic.Category
        public var attributeIndex: Int
        public var tlvIndex: Int?
        public var tlvType: UInt16?
        public var byteOffset: Int?
        public var message: String

        public init(_ diagnostic: BGPLSAttributeDiagnostic) {
            disposition = diagnostic.disposition
            category = diagnostic.category
            attributeIndex = diagnostic.attributeIndex
            tlvIndex = diagnostic.tlvIndex
            tlvType = diagnostic.tlvType
            byteOffset = diagnostic.byteOffset
            message = diagnostic.message
        }
    }

    public init(from rib: LSRIB, capturedAt: Date = Date()) {
        self.capturedAt = capturedAt
        self.nodeCount = rib.nodeCount
        self.linkCount = rib.linkCount
        self.prefixCount = rib.prefixCount
        //  Map every RIB entry, ordered by complete identity rather than an IPv4-only
        // projection. This preserves IS-IS/opaque/missing identities and removes sort ties.
        self.nodes = rib.nodes.sorted { $0.key < $1.key }
            .map { key, record in
                let node = record.nlri
                return Node(
                    ribKey: key,
                    protocolID: node.protocolID,
                    identifier: node.identifier,
                    routerID: node.localNode.igpRouterID,
                    autonomousSystem: node.localNode.autonomousSystem,
                    attributes: record.attributes,
                    attributeAvailability: record.observation.availability,
                    attributeIssues: record.observation.diagnostics.map(AttributeIssue.init)
                )
            }
        self.links = rib.links.sorted { $0.key < $1.key }
            .map { key, record in
                let link = record.nlri
                return Link(
                    ribKey: key,
                    protocolID: link.protocolID,
                    identifier: link.identifier,
                    localRouterID: link.localNode.igpRouterID,
                    localInterface: link.localIPv4Interface,
                    remoteRouterID: link.remoteNode.igpRouterID,
                    remoteInterface: link.remoteIPv4Neighbor,
                    localIPv6Interface: link.localIPv6Interface,
                    remoteIPv6Interface: link.remoteIPv6Neighbor,
                    localLinkIdentifier: link.localLinkIdentifier,
                    remoteLinkIdentifier: link.remoteLinkIdentifier,
                    attributes: record.attributes,
                    attributeAvailability: record.observation.availability,
                    attributeIssues: record.observation.diagnostics.map(AttributeIssue.init)
                )
            }
        self.prefixes = rib.prefixes.sorted { $0.key < $1.key }
            .map { key, record in
                let prefix = record.nlri
                return Prefix(
                    ribKey: key,
                    protocolID: prefix.protocolID,
                    identifier: prefix.identifier,
                    network: prefix.network,
                    nodeRouterID: prefix.localNode.igpRouterID,
                    attributes: record.attributes,
                    attributeAvailability: record.observation.availability,
                    attributeIssues: record.observation.diagnostics.map(AttributeIssue.init)
                )
            }
    }

    /// JSON for application interchange or debugging.
    public func jsonUTF8String(pretty: Bool = true) throws -> String {
        let encoder = JSONEncoder()
        if pretty {
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        }
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(self)
        return String(decoding: data, as: UTF8.self)
    }
}

extension LSRIB {
    /// Snapshot suitable for App consumption / file export.
    public func snapshot(at date: Date = Date()) -> RIBSnapshot {
        RIBSnapshot(from: self, capturedAt: date)
    }
}
