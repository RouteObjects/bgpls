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

import ArgumentParser
import CIDR
import Foundation

/// CLI capture selection only; file creation remains the session sink's responsibility.
package struct PCAPDestination: Sendable, Equatable {
    package let path: String
    package let isAutomatic: Bool

    /// Announce selection without claiming that a file has already been created.
    package var selectionMessage: String? {
        guard isAutomatic else { return nil }
        return "bgpls: PCAP destination selected: \(String(reflecting: path))\n"
    }

    package static func validate(explicitPath: String?, automatic: Bool) throws {
        guard !automatic || explicitPath == nil else {
            throw ValidationError("--pcap-auto and --pcap are mutually exclusive.")
        }
    }

    /// Explicit inputs keep naming deterministic in tests without changing process state.
    package static func select<Family: IPAddressFamily>(
        explicitPath: String?, automatic: Bool, peer: IPEndpoint<Family>,
        date: Date, uuid: UUID, workingDirectory: String
    ) throws -> PCAPDestination? {
        try validate(explicitPath: explicitPath, automatic: automatic)
        if let explicitPath {
            return PCAPDestination(path: explicitPath, isAutomatic: false)
        }
        guard automatic else { return nil }

        // Pin calendar, locale and timezone; filenames must not inherit
        // local daylight-saving rules or use the ISO week-numbering year.
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = .gmt
        formatter.dateFormat = "yyyyMMdd_HHmmss'Z'"
        let timestamp = formatter.string(from: date)

        // Address descriptions include a CIDR slash. Use only the literal,
        // and keep exclusive creation authoritative even with a random suffix.
        let address = peer.address.addressLiteral.replacingOccurrences(of: ":", with: "-")
        let filename =
            "bgpls_\(timestamp)_peer-\(address)_port-\(peer.port.rawValue)_\(uuid.uuidString.lowercased()).pcap"
        let path = URL(fileURLWithPath: workingDirectory, isDirectory: true)
            .appendingPathComponent(filename, isDirectory: false).path
        return PCAPDestination(path: path, isAutomatic: true)
    }
}
