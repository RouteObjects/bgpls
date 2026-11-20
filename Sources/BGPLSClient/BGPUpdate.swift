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

import NIOCore

/// Parsed BGP UPDATE body (RFC 4271 §4.3) with multiprotocol reachability.
public struct BGPUpdateMessage: Sendable, Hashable {
    /// Classic IPv4 withdrawn routes (usually empty for MP-only sessions).
    public var withdrawnRoutes: ByteBuffer
    /// Path attributes in order.
    public var pathAttributes: [BGPPathAttribute]
    /// Classic IPv4 NLRI (usually empty when using MP_REACH).
    public var nlri: ByteBuffer
    /// Parsed MP_REACH_NLRI (attribute 14), if present.
    public var mpReach: BGPMPReach?
    /// Parsed MP_UNREACH_NLRI (attribute 15), if present.
    public var mpUnreach: BGPMPUnreach?

    public init(
        withdrawnRoutes: ByteBuffer = ByteBuffer(),
        pathAttributes: [BGPPathAttribute] = [],
        nlri: ByteBuffer = ByteBuffer(),
        mpReach: BGPMPReach? = nil,
        mpUnreach: BGPMPUnreach? = nil
    ) {
        self.withdrawnRoutes = withdrawnRoutes
        self.pathAttributes = pathAttributes
        self.nlri = nlri
        self.mpReach = mpReach
        self.mpUnreach = mpUnreach
    }
}

/// One BGP path attribute (header + value).
public struct BGPPathAttribute: Sendable, Hashable {
    public var flags: UInt8
    public var typeCode: UInt8
    public var value: ByteBuffer

    public var isOptional: Bool { flags & 0x80 != 0 }
    public var isTransitive: Bool { flags & 0x40 != 0 }
    public var isPartial: Bool { flags & 0x20 != 0 }
    public var isExtendedLength: Bool { flags & 0x10 != 0 }

    public init(flags: UInt8, typeCode: UInt8, value: ByteBuffer) {
        self.flags = flags
        self.typeCode = typeCode
        self.value = value
    }
}

public enum BGPPathAttributeType {
    // Export fixed attribute-code implementations without requiring shared constant storage.
    @export(implementation)
    public static var origin: UInt8 { 1 }
    @export(implementation)
    public static var asPath: UInt8 { 2 }
    @export(implementation)
    public static var nextHop: UInt8 { 3 }
    @export(implementation)
    public static var localPref: UInt8 { 5 }
    @export(implementation)
    public static var mpReachNLRI: UInt8 { 14 }
    @export(implementation)
    public static var mpUnreachNLRI: UInt8 { 15 }
    @export(implementation)
    public static var bgpLSAttribute: UInt8 { 29 }
}

/// MP_REACH_NLRI (RFC 4760) for a single AFI/SAFI.
public struct BGPMPReach: Sendable, Hashable {
    public var afi: UInt16
    public var safi: UInt8
    public var nextHop: ByteBuffer
    public var nlri: ByteBuffer

    public var isBGPLS: Bool {
        afi == BGPLSAFISAFIs.afi && safi == BGPLSAFISAFIs.safi
    }
}

/// MP_UNREACH_NLRI (RFC 4760).
public struct BGPMPUnreach: Sendable, Hashable {
    public var afi: UInt16
    public var safi: UInt8
    public var withdrawnNLRI: ByteBuffer

    public var isBGPLS: Bool {
        afi == BGPLSAFISAFIs.afi && safi == BGPLSAFISAFIs.safi
    }

    /// End-of-RIB for this AFI/SAFI when withdrawn NLRI is empty.
    public var isEndOfRIB: Bool { withdrawnNLRI.readableBytes == 0 }
}

public enum BGPLSAFISAFIs {
    // Export the fixed family identifiers for client-side comparisons and encoding.
    /// BGP-LS / link-state AFI (IANA).
    @export(implementation)
    public static var afi: UInt16 { 16_388 }
    /// BGP-LS SAFI (IANA) — Junos `te-unicast` uses this NLRI encoding.
    @export(implementation)
    public static var safi: UInt8 { 71 }
}
