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

import Foundation
import NIOCore

/// One ordered observation, including bodies whose framing requires session termination.
//  Preparation happens before event-loop completion; raw callbacks and logging still
// run on the session actor, and cleanup drains this envelope even when preparation failed.
struct BGPLSUpdateObservation: Sendable {
    let rawBody: ByteBuffer
    let preparation: Result<LSRIB.PreparedUpdate, any Error>

    init(rawBody: ByteBuffer) {
        self.rawBody = rawBody
        self.preparation = Result {
            try LSRIB.prepareIsolating(update: BGPUpdateParser.parse(rawBody))
        }
    }
}

/// Pure presentation keeps diagnostics testable without intercepting process-wide stderr.
enum BGPLSUpdateDiagnosticFormatter {
    static let maximumDetails = 8

    static func lines(
        _ diagnostics: [LSRIB.UpdateDiagnostic], peer: String, timestamp: String
    ) -> [String] {
        var lines = diagnostics.prefix(maximumDetails).map { contextual in
            switch contextual {
            case .nlri(let field, let diagnostic):
                let disposition: String
                switch diagnostic.disposition {
                case .discarded: disposition = "discarded"
                case .acceptedWithWarning: disposition = "accepted-with-warning"
                }
                let descriptor = diagnostic.descriptorType.map { " descriptor=\($0)" } ?? ""
                return
                    "bgpls: \(timestamp) peer=\(peer) \(field.rawValue) NLRI index=\(diagnostic.nlriIndex) offset=\(diagnostic.byteOffset) type=\(diagnostic.nlriType) \(disposition) category=\(diagnostic.category.rawValue)\(descriptor): \(bounded(diagnostic.message))"
            case .attribute(let diagnostic):
                let tlv = diagnostic.tlvIndex.map { " TLV index=\($0)" } ?? ""
                let offset = diagnostic.byteOffset.map { " offset=\($0)" } ?? ""
                let type = diagnostic.tlvType.map { " type=\($0)" } ?? ""
                return
                    "bgpls: \(timestamp) peer=\(peer) attribute index=\(diagnostic.attributeIndex) type=29\(tlv)\(offset)\(type) \(diagnostic.disposition.rawValue) category=\(diagnostic.category.rawValue): \(bounded(diagnostic.message))"
            }
        }
        if diagnostics.count > maximumDetails {
            lines.append(
                "bgpls: \(timestamp) peer=\(peer) UPDATE diagnostics omitted=\(diagnostics.count - maximumDetails) (detail limit=\(maximumDetails))"
            )
        }
        return lines
    }

    static func fatalLine(_ error: any Error, peer: String, timestamp: String) -> String {
        "bgpls: \(timestamp) peer=\(peer) UPDATE rejected; session terminating: \(bounded(String(describing: error)))"
    }

    private static func bounded(_ message: String) -> String {
        //  Peer-driven errors never dump raw NLRI bytes or unbounded detail by default.
        let singleLine = message.replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
        return singleLine.count > 240 ? String(singleLine.prefix(240)) + "…" : singleLine
    }
}
