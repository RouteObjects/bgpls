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

/// A nonzero, 32-bit BGP speaker identifier, independent of its transport addresses.
///
/// RFC 6286 identifiers are not IP endpoints and have no prefix or address-scope semantics.
/// Their conventional dotted-decimal presentation does not impose IPv4 unicast restrictions.
/// The operator must choose a stable identifier that is unique within the autonomous system.
public struct BGPIdentifier: RawRepresentable, Sendable, Hashable, CustomStringConvertible,
    LosslessStringConvertible
{
    /// The four identifier octets as a nonzero integer in network significance order.
    public let rawValue: UInt32

    /// Creates an identifier from any nonzero 32-bit value.
    public init?(rawValue: UInt32) {
        guard rawValue != 0 else { return nil }
        self.rawValue = rawValue
    }

    /// Parses four decimal octets, each containing one to three ASCII digits in `0...255`.
    ///
    /// Padded octets are accepted and formatted without padding. Zero, signs, whitespace,
    /// CIDR suffixes, abbreviated addresses, plain integer text, and IPv6 are rejected.
    public init?(_ description: String) {
        //  Reuse the dotted-quad parser only for octet decoding; a BGP identifier
        // has no CIDR context, so even an otherwise valid /32 suffix must be rejected.
        guard !description.contains("/"), let octets = IPv4Address(description) else { return nil }
        self.init(rawValue: octets.address)
    }

    /// Canonical, unpadded dotted-decimal text without a prefix suffix.
    public var description: String {
        AF.V4.formatAddress(rawValue)
    }
}
