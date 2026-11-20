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

/// In-memory link-state RIB for objects learned via BGP-LS (AFI 16388 / SAFI 71).
public struct LSRIB: Sendable, Hashable {
    /// The UPDATE field containing the diagnosed NLRI.
    public enum NLRIField: String, Sendable, Hashable {
        case mpReach = "MP_REACH"
        case mpUnreach = "MP_UNREACH"
    }

    /// A diagnostic with coordinates appropriate to its wire grammar.
    public enum UpdateDiagnostic: Sendable, Hashable {
        case nlri(field: NLRIField, diagnostic: BGPLSNLRIParser.Diagnostic)
        case attribute(BGPLSAttributeDiagnostic)
    }

    /// Committed diffs and complete, ordered diagnostics from an isolated UPDATE.
    public struct UpdateResult: Sendable, Hashable {
        public let diffs: [RIBDiff]
        public let diagnostics: [UpdateDiagnostic]
    }

    //  Preparation is immutable and contains no RIB state. The session can validate
    // every field before committing once and broadcasting exactly the committed diffs.
    struct PreparedUpdate: Sendable {
        let reaches: [BGPLSRecord]
        let withdrawals: [BGPLSNLRI]
        let diagnostics: [UpdateDiagnostic]
    }

    public private(set) var nodes: [String: BGPLSNodeRecord] = [:]
    public private(set) var links: [String: BGPLSLinkRecord] = [:]
    //  One authoritative collection keeps counts, withdrawals, and snapshots complete
    // for both families; callers can switch on the value when family-specific access is needed.
    public private(set) var prefixes: [String: BGPLSPrefixRecord] = [:]

    public init() {}

    public var nodeCount: Int { nodes.count }
    public var linkCount: Int { links.count }
    public var prefixCount: Int { prefixes.count }

    /// One-line summary for CLI output.
    public var summaryLine: String {
        "nodes=\(nodeCount) links=\(linkCount) prefixes=\(prefixCount)"
    }

    /// Replaces the complete observation at a topology identity key.
    public mutating func apply(_ record: BGPLSRecord) {
        switch record {
        case .node(let node):
            nodes[Self.nodeKey(node.nlri)] = node
        case .link(let link):
            links[Self.linkKey(link.nlri)] = link
        case .prefix(let record):
            switch record.nlri {
            case .v4(let prefix): prefixes[Self.prefixKey(prefix)] = record
            case .v6(let prefix): prefixes[Self.prefixKey(prefix)] = record
            }
        case .unknown:
            break
        }
    }

    /// Applies a withdrawal NLRI.
    public mutating func withdraw(_ nlri: BGPLSNLRI) {
        switch nlri {
        case .node(let node):
            nodes.removeValue(forKey: Self.nodeKey(node))
        case .link(let link):
            links.removeValue(forKey: Self.linkKey(link))
        case .ipv4Prefix(let prefix):
            prefixes.removeValue(forKey: Self.prefixKey(prefix))
        case .ipv6Prefix(let prefix):
            prefixes.removeValue(forKey: Self.prefixKey(prefix))
        case .unknown:
            break
        }
    }

    /// Applies a full parsed UPDATE (MP_REACH / MP_UNREACH for BGP-LS).
    ///
    /// Returns per-NLRI ``RIBDiff`` events describing what was applied (for AsyncStream watchers).
    /// Strict and atomic: any decoding failure leaves the entire RIB unchanged.
    @discardableResult
    public mutating func apply(update: BGPUpdateMessage) throws -> [RIBDiff] {
        //  Validate both fields before the first mutation, so a rejected withdrawal
        // cannot leave accepted reachability hidden from the caller's diff stream.
        commit(try Self.prepare(update: update, isolating: false)).diffs
    }

    /// Applies accepted records and reports NLRI and attribute information gaps.
    /// Broken inner attribute framing discards its interpretation, not valid topology;
    /// bounded unusable fields reject only their projections. An incomplete outer
    /// UPDATE/NLRI frame throws before any RIB mutation.
    ///
    /// Discarded NLRIs cause no mutation: a rejected withdrawal or replacement can leave
    /// previously accepted information stale. Diagnostics identify that collection gap;
    /// this collector does not infer partial withdrawal keys or reconcile peer state.
    @discardableResult
    public mutating func applyIsolating(update: BGPUpdateMessage) throws -> UpdateResult {
        commit(try Self.prepareIsolating(update: update))
    }

    static func prepareIsolating(update: BGPUpdateMessage) throws -> PreparedUpdate {
        try prepare(update: update, isolating: true)
    }

    private static func prepare(update: BGPUpdateMessage, isolating: Bool) throws -> PreparedUpdate {
        var reaches: [BGPLSNLRI] = []
        var withdrawals: [BGPLSNLRI] = []
        var diagnostics: [UpdateDiagnostic] = []
        if let reach = update.mpReach, reach.isBGPLS {
            let parsed = try parseField(reach.nlri, field: .mpReach, isolating: isolating)
            reaches = parsed.nlris
            diagnostics.append(contentsOf: parsed.diagnostics.map { .nlri(field: .mpReach, diagnostic: $0) })
        }
        if let unreach = update.mpUnreach, unreach.isBGPLS, !unreach.isEndOfRIB {
            let parsed = try parseField(unreach.withdrawnNLRI, field: .mpUnreach, isolating: isolating)
            withdrawals = parsed.nlris
            diagnostics.append(
                contentsOf: parsed.diagnostics.map { .nlri(field: .mpUnreach, diagnostic: $0) })
        }
        let contexts = Set(
            reaches.compactMap { nlri -> BGPLSAttributeDecoder.Context? in
                switch nlri {
                case .node: .node
                case .link: .link
                case .ipv4Prefix, .ipv6Prefix: .prefix
                case .unknown: nil
                }
            })
        // Decode once before mutation. The observation replaces the previous one even
        // when the new attribute is absent or discarded; old properties must not leak forward.
        let attributes = BGPLSAttributeDecoder.decode(pathAttributes: update.pathAttributes, contexts: contexts)
        if !isolating, let failure = attributes.observation.diagnostics.first(where: \.isError) {
            throw BGPLSClientError.protocolError("BGP-LS attribute: \(failure.message)")
        }
        diagnostics.append(contentsOf: attributes.observation.diagnostics.map(UpdateDiagnostic.attribute))
        return PreparedUpdate(
            reaches: reaches.map { BGPLSRecord(nlri: $0, decoded: attributes) },
            withdrawals: withdrawals, diagnostics: diagnostics
        )
    }

    private static func parseField(
        _ buffer: ByteBuffer, field: NLRIField, isolating: Bool
    ) throws -> BGPLSNLRIParser.ParseResult {
        guard isolating else {
            return BGPLSNLRIParser.ParseResult(nlris: try BGPLSNLRIParser.parseAll(buffer), diagnostics: [])
        }
        do {
            return try BGPLSNLRIParser.parseAllIsolating(buffer)
        } catch BGPLSClientError.protocolError(let message) {
            //  A fatal field-level error has no complete NLRI diagnostic, so retain
            // its UPDATE context in the error while preserving the public error category.
            throw BGPLSClientError.protocolError("\(field.rawValue): \(message)")
        }
    }

    mutating func commit(_ prepared: PreparedUpdate) -> UpdateResult {
        var diffs: [RIBDiff] = []
        diffs.reserveCapacity(prepared.reaches.count + prepared.withdrawals.count)
        for nlri in prepared.reaches {
            apply(nlri)
            diffs.append(.upsert(nlri))
        }
        for nlri in prepared.withdrawals {
            withdraw(nlri)
            diffs.append(.withdraw(nlri))
        }
        return UpdateResult(diffs: diffs, diagnostics: prepared.diagnostics)
    }

    /// Multi-line text dump for `show` / session-end summary.
    public func dump(topic: String = "summary", showAttributes: Bool = false) -> String {
        switch topic.lowercased() {
        case "nodes":
            if nodes.isEmpty { return "nodes: (none)" }
            //  Complete RIB keys provide deterministic ordering across IGP domains.
            return nodes.sorted { $0.key < $1.key }
                .map { _, record in
                    let node = record.nlri
                    let rid = node.localNode.igpRouterIDString ?? "?"
                    // Missing descriptor 512 is absent topology metadata, not an unknown session ASN.
                    let asn = node.localNode.autonomousSystem.map { "\($0.rawValue)" } ?? "not-advertised"
                    return "node \(rid) AS \(asn)"
                        + (showAttributes ? " \(BGPLSRecord.node(record).attributeSummary)" : "")
                }
                .joined(separator: "\n")

        case "links":
            if links.isEmpty { return "links: (none)" }
            return links.sorted { $0.key < $1.key }
                .map { _, record in
                    let link = record.nlri
                    let local = link.localNode.igpRouterIDString ?? "?"
                    let remote = link.remoteNode.igpRouterIDString ?? "?"
                    let lif = link.localInterfaceDescription
                    let rif = link.remoteInterfaceDescription
                    return "link \(local) \(lif) → \(remote) \(rif)"
                        + (showAttributes ? " \(BGPLSRecord.link(record).attributeSummary)" : "")
                }
                .joined(separator: "\n")

        case "prefixes":
            if prefixes.isEmpty { return "prefixes: (none)" }
            return prefixes.sorted { $0.key < $1.key }
                .map { _, record in
                    let prefix = record.nlri
                    let rid = prefix.localNode.igpRouterIDString ?? "?"
                    return "prefix \(prefix.network.description) node \(rid)"
                        + (showAttributes ? " \(BGPLSRecord.prefix(record).attributeSummary)" : "")
                }
                .joined(separator: "\n")

        default:
            var lines = [summaryLine]
            if !nodes.isEmpty {
                lines.append(dump(topic: "nodes", showAttributes: showAttributes))
            }
            if !links.isEmpty {
                lines.append(dump(topic: "links", showAttributes: showAttributes))
            }
            if !prefixes.isEmpty {
                lines.append(dump(topic: "prefixes", showAttributes: showAttributes))
            }
            return lines.joined(separator: "\n")
        }
    }

    // MARK: - Keys

    /// RIB keys use **protocol-ID + Instance-ID** for domain segregation (RFC 9552), plus
    /// complete canonical descriptors. Deprecated Node Descriptor TLV 513 is **not** part of the key.
    static func nodeKey(_ node: BGPLSNodeNLRI) -> String {
        BGPLSIdentityKey.node(node)
    }

    static func linkKey(_ link: BGPLSLinkNLRI) -> String {
        BGPLSIdentityKey.link(link)
    }

    static func prefixKey(_ prefix: BGPLSIPv4PrefixNLRI) -> String {
        BGPLSIdentityKey.prefix(prefix)
    }

    static func prefixKey(_ prefix: BGPLSIPv6PrefixNLRI) -> String {
        BGPLSIdentityKey.prefix(prefix)
    }
}
