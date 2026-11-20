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

/// OSPF Area Identifier (32-bit).
///
/// Wire encoding matches an IPv4-sized field and is conventionally written in dotted-quad form
/// (e.g. `0.0.0.0`), but an area ID is **not** an IP address: it has no host/prefix semantics.
///
/// Future device-config parsing may *detect* dotted-quad text and still map it here (or later to a
/// shared swift-cidr type). For now this small bgpls type keeps presentation clear without
/// overloading ``IPAddress``.
public struct OSPFAreaID: RawRepresentable, Sendable, Hashable, Codable, CustomStringConvertible,
    LosslessStringConvertible
{
    public var rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    public init(_ rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Dotted-quad presentation using swift-cidr IPv4 formatting of the raw bits.
    public var description: String {
        AF.V4.formatAddress(rawValue)
    }

    /// Parses dotted-quad (`0.0.0.0`) or decimal (`0`) area identifiers.
    public init?(_ description: String) {
        let trimmed = description.trimmingCharacters(in: .whitespacesAndNewlines)
        if let dotted = IPv4Address(trimmed) {
            self.rawValue = dotted.address
            return
        }
        if let decimal = UInt32(trimmed) {
            self.rawValue = decimal
            return
        }
        return nil
    }
}
