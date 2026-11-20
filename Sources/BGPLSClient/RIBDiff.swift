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

/// A RIB change event for ``AsyncStream`` subscribers, including CLI `--watch`.
///
/// Emitted **as each NLRI is applied** to ``LSRIB`` (not a full-table diff pass).
public enum RIBDiff: Sendable, Hashable {
    /// Complete observation installed or refreshed in the RIB (MP_REACH).
    case upsert(BGPLSRecord)
    /// NLRI removed from the RIB (MP_UNREACH).
    case withdraw(BGPLSNLRI)
    /// Optional catch-up when a subscriber attaches (current full snapshot).
    case snapshot(RIBSnapshot)

    /// One-line CLI / log form.
    public var watchLine: String {
        watchLine(showAttributes: false)
    }

    /// Opt-in attribute presentation. Withdrawals and catch-up summaries remain identity-only.
    public func watchLine(showAttributes: Bool) -> String {
        switch self {
        case .upsert(let record):
            let summary = "WATCH upsert \(Self.nlriSummary(record.nlri))"
            return showAttributes ? "\(summary) \(record.attributeSummary)" : summary
        case .withdraw(let nlri):
            return "WATCH withdraw \(Self.nlriSummary(nlri))"
        case .snapshot(let snap):
            return
                "WATCH snapshot nodes=\(snap.nodeCount) links=\(snap.linkCount) prefixes=\(snap.prefixCount)"
        }
    }

    private static func nlriSummary(_ nlri: BGPLSNLRI) -> String {
        switch nlri {
        case .node(let node):
            let rid = node.localNode.igpRouterIDString ?? "?"
            return "node \(rid)"
        case .link(let link):
            let local = link.localNode.igpRouterIDString ?? "?"
            let remote = link.remoteNode.igpRouterIDString ?? "?"
            let lif = link.localInterfaceDescription
            let rif = link.remoteInterfaceDescription
            return "link \(local) \(lif) → \(remote) \(rif)"
        case .ipv4Prefix(let prefix):
            let rid = prefix.localNode.igpRouterIDString ?? "?"
            return "prefix \(prefix.network.description) node \(rid)"
        case .ipv6Prefix(let prefix):
            let rid = prefix.localNode.igpRouterIDString ?? "?"
            return "prefix \(prefix.network.description) node \(rid)"
        case .unknown(let type, _):
            return "unknown type=\(type)"
        }
    }
}
