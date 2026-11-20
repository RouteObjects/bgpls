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

/// BGP-LS NLRI type codes (RFC 7752 / RFC 9552).
public enum BGPLSNLRIType: UInt16, Sendable, Hashable {
    case node = 1
    case link = 2
    case ipv4TopologyPrefix = 3
    case ipv6TopologyPrefix = 4
}

/// Protocol-ID in BGP-LS NLRI (RFC 7752 §3).
public enum BGPLSProtocolID: UInt8, Sendable, Hashable {
    case isisLevel1 = 1
    case isisLevel2 = 2
    case ospfv2 = 3
    case direct = 4
    case `static` = 5
    case ospfv3 = 6
}

/// TLV (type + length + value) used inside descriptors and attributes.
public struct BGPLSTLV: Sendable, Hashable {
    public var type: UInt16
    public var value: [UInt8]

    public init(type: UInt16, value: [UInt8]) {
        self.type = type
        self.value = value
    }
}

/// Common node identity fields extracted from Node Descriptor sub-TLVs.
public struct BGPLSNodeIdentity: Sendable, Hashable {
    /// AS from descriptor 512 (swift-cidr currency).
    public var autonomousSystem: AutonomousSystemNumber?
    /// Node Descriptor sub-TLV 513 (BGP-LS Identifier).
    ///
    /// Deprecated by RFC 9552 in favor of the NLRI **Instance-ID** (`identifier` on each NLRI).
    /// Parsed when present for RFC 7752 compatibility; **not** used for RIB keys.
    public var bgpLSIdentifier: UInt32?
    /// OSPF Area ID (descriptor 514) — dotted-quad presentation, not an ``IPAddress``.
    public var ospfAreaID: OSPFAreaID?
    /// Protocol-aware IGP Router-ID (descriptor 515), including IS-IS and OSPF pseudonodes.
    public var igpRouterID: BGPLSIGPRouterID?
    /// OSPF router component as a host-length address; `nil` for IS-IS and opaque identifiers.
    ///
    /// Setting this compatibility projection updates the OSPF router component while preserving
    /// an existing OSPF pseudonode suffix. Setting `nil` removes the IGP Router-ID.
    public var ipv4RouterID: IPv4Address? {
        get { igpRouterID?.ipv4RouterID }
        set {
            guard let newValue else {
                igpRouterID = nil
                return
            }
            let address = IPv4Address(address: newValue.address)
            switch igpRouterID {
            case .ospfv2Pseudonode(_, let interfaceAddress):
                igpRouterID = .ospfv2Pseudonode(routerID: address, interfaceAddress: interfaceAddress)
            case .ospfv3Pseudonode(_, let interfaceID):
                igpRouterID = .ospfv3Pseudonode(routerID: address, interfaceID: interfaceID)
            default:
                igpRouterID = .ospfRouterID(address)
            }
        }
    }
    public var rawTLVs: [BGPLSTLV]

    public init(
        autonomousSystem: AutonomousSystemNumber? = nil,
        bgpLSIdentifier: UInt32? = nil,
        ospfAreaID: OSPFAreaID? = nil,
        ipv4RouterID: IPv4Address? = nil,
        rawTLVs: [BGPLSTLV] = [],
        igpRouterID: BGPLSIGPRouterID? = nil
    ) {
        self.autonomousSystem = autonomousSystem
        self.bgpLSIdentifier = bgpLSIdentifier
        self.ospfAreaID = ospfAreaID
        //  Keep the existing OSPF initializer source-compatible without making IS-IS an IP address.
        self.igpRouterID = igpRouterID ?? ipv4RouterID.map { .ospfRouterID(IPv4Address(address: $0.address)) }
        self.rawTLVs = rawTLVs
    }

    /// Address-only presentation of the IPv4 Router-ID (swift-cidr formatting).
    public var ipv4RouterIDString: String? {
        ipv4RouterID?.formatted(.addressOnly)
    }

    /// Protocol-neutral presentation, including IS-IS System IDs and pseudonodes.
    public var igpRouterIDString: String? { igpRouterID?.description }
}

/// One BGP-LS NLRI (NODE, LINK, or PREFIX).
public enum BGPLSNLRI: Sendable, Hashable {
    case node(BGPLSNodeNLRI)
    case link(BGPLSLinkNLRI)
    case ipv4Prefix(BGPLSIPv4PrefixNLRI)
    case ipv6Prefix(BGPLSIPv6PrefixNLRI)
    case unknown(type: UInt16, raw: [UInt8])
}

public struct BGPLSNodeNLRI: Sendable, Hashable {
    public var protocolID: UInt8
    /// BGP-LS **Instance-ID** (64-bit Identifier in the fixed NLRI header). Segregates IGP domains
    /// per RFC 9552; used in ``LSRIB`` keys. Distinct from deprecated Node Descriptor TLV 513.
    public var identifier: UInt64
    public var localNode: BGPLSNodeIdentity
    /// Unexpected/unknown top-level TLVs retained for forward-compatible NLRI identity.
    public var additionalDescriptors: [BGPLSTLV]

    public init(
        protocolID: UInt8, identifier: UInt64, localNode: BGPLSNodeIdentity,
        additionalDescriptors: [BGPLSTLV] = []
    ) {
        self.protocolID = protocolID
        self.identifier = identifier
        self.localNode = localNode
        self.additionalDescriptors = additionalDescriptors
    }
}

public struct BGPLSLinkNLRI: Sendable, Hashable {
    public var protocolID: UInt8
    /// BGP-LS Instance-ID (see ``BGPLSNodeNLRI/identifier``).
    public var identifier: UInt64
    public var localNode: BGPLSNodeIdentity
    public var remoteNode: BGPLSNodeIdentity
    public var linkDescriptors: [BGPLSTLV]
    /// Local IPv4 interface address (descriptor 259), as swift-cidr currency.
    public var localIPv4Interface: IPv4Address?
    /// Remote IPv4 neighbor address (descriptor 260), as swift-cidr currency.
    public var remoteIPv4Neighbor: IPv4Address?
    /// Local IPv6 interface address (descriptor 261), independent of an IPv4 descriptor.
    public var localIPv6Interface: IPv6Address?
    /// Remote IPv6 neighbor address (descriptor 262), independent of an IPv4 descriptor.
    public var remoteIPv6Neighbor: IPv6Address?
    /// Local and remote identifiers from descriptor 258, including unnumbered link identities.
    public var localLinkIdentifier: UInt32?
    public var remoteLinkIdentifier: UInt32?

    public init(
        protocolID: UInt8,
        identifier: UInt64,
        localNode: BGPLSNodeIdentity,
        remoteNode: BGPLSNodeIdentity,
        linkDescriptors: [BGPLSTLV],
        localIPv4Interface: IPv4Address?,
        remoteIPv4Neighbor: IPv4Address?,
        localLinkIdentifier: UInt32? = nil,
        remoteLinkIdentifier: UInt32? = nil,
        localIPv6Interface: IPv6Address? = nil,
        remoteIPv6Neighbor: IPv6Address? = nil
    ) {
        self.protocolID = protocolID
        self.identifier = identifier
        self.localNode = localNode
        self.remoteNode = remoteNode
        self.linkDescriptors = linkDescriptors
        self.localIPv4Interface = localIPv4Interface
        self.remoteIPv4Neighbor = remoteIPv4Neighbor
        self.localIPv6Interface = localIPv6Interface
        self.remoteIPv6Neighbor = remoteIPv6Neighbor
        self.localLinkIdentifier = localLinkIdentifier
        self.remoteLinkIdentifier = remoteLinkIdentifier
    }

    var localInterfaceDescription: String {
        Self.interfaceDescription(
            ipv4: localIPv4Interface, ipv6: localIPv6Interface, identifier: localLinkIdentifier
        )
    }

    var remoteInterfaceDescription: String {
        Self.interfaceDescription(
            ipv4: remoteIPv4Neighbor, ipv6: remoteIPv6Neighbor, identifier: remoteLinkIdentifier
        )
    }

    private static func interfaceDescription(
        ipv4: IPv4Address?, ipv6: IPv6Address?, identifier: UInt32?
    ) -> String {
        //  A link can carry both address families. Share their ordered display between
        // dump and watch output without changing IPv4-only text or inventing missing addresses.
        let addresses = [ipv4?.formatted(.addressOnly), ipv6?.formatted(.addressOnly)].compactMap { $0 }
        if !addresses.isEmpty { return addresses.joined(separator: ",") }
        return identifier.map { "id:\($0)" } ?? "?"
    }
}

/// Family-typed topology prefix; both NLRI families share the same descriptor grammar.
/// Structural equality includes retained descriptor evidence; canonical RIB identity is separate.
//  IP Reachability is a canonical prefix, not an address with prefix context.
// IPNetwork enforces alignment at construction and reassignment without discarding raw evidence.
public struct BGPLSPrefixNLRI<Family: IPAddressFamily>: Sendable, Hashable {
    public var protocolID: UInt8
    /// BGP-LS Instance-ID (see ``BGPLSNodeNLRI/identifier``).
    public var identifier: UInt64
    public var localNode: BGPLSNodeIdentity
    /// Canonical topology prefix; host bits are always zero below the prefix length.
    public var network: IPNetwork<Family>
    /// Original descriptors, including order, unknown values, and received prefix padding.
    public var prefixDescriptors: [BGPLSTLV]

    public var prefixLength: UInt8 { network.prefixLength.rawValue }
    public var prefixAddressBits: Family.Storage { network.prefix }

    public init(
        protocolID: UInt8,
        identifier: UInt64,
        localNode: BGPLSNodeIdentity,
        network: IPNetwork<Family>,
        prefixDescriptors: [BGPLSTLV]
    ) {
        self.protocolID = protocolID
        self.identifier = identifier
        self.localNode = localNode
        self.network = network
        self.prefixDescriptors = prefixDescriptors
    }
}

/// IPv4 topology prefix (NLRI type 3).
public typealias BGPLSIPv4PrefixNLRI = BGPLSPrefixNLRI<AF.V4>
/// IPv6 topology prefix (NLRI type 4).
public typealias BGPLSIPv6PrefixNLRI = BGPLSPrefixNLRI<AF.V6>

/// Mixed-family prefix currency for the RIB; case selection preserves the NLRI address family.
public enum AnyBGPLSPrefixNLRI: Sendable, Hashable {
    case v4(BGPLSIPv4PrefixNLRI)
    case v6(BGPLSIPv6PrefixNLRI)

    public var protocolID: UInt8 {
        switch self {
        case .v4(let prefix): prefix.protocolID
        case .v6(let prefix): prefix.protocolID
        }
    }

    public var identifier: UInt64 {
        switch self {
        case .v4(let prefix): prefix.identifier
        case .v6(let prefix): prefix.identifier
        }
    }

    public var localNode: BGPLSNodeIdentity {
        switch self {
        case .v4(let prefix): prefix.localNode
        case .v6(let prefix): prefix.localNode
        }
    }

    public var network: AnyIPNetwork {
        switch self {
        case .v4(let prefix): .v4(prefix.network)
        case .v6(let prefix): .v6(prefix.network)
        }
    }

    /// Original prefix descriptors, preserving order, unknown values, and wire padding evidence.
    public var prefixDescriptors: [BGPLSTLV] {
        switch self {
        case .v4(let prefix): prefix.prefixDescriptors
        case .v6(let prefix): prefix.prefixDescriptors
        }
    }
}

/// Descriptor / sub-TLV type codes (RFC 7752 / RFC 9552).
public enum BGPLSDescriptorType {
    // Export fixed descriptor codes while preserving the compatibility alias below.
    @export(implementation)
    public static var localNodeDescriptors: UInt16 { 256 }
    @export(implementation)
    public static var remoteNodeDescriptors: UInt16 { 257 }
    @export(implementation)
    public static var linkLocalRemoteIdentifiers: UInt16 { 258 }
    @export(implementation)
    public static var ipv4InterfaceAddress: UInt16 { 259 }
    @export(implementation)
    public static var ipv4NeighborAddress: UInt16 { 260 }
    @export(implementation)
    public static var ipv6InterfaceAddress: UInt16 { 261 }
    @export(implementation)
    public static var ipv6NeighborAddress: UInt16 { 262 }
    @export(implementation)
    public static var multiTopologyID: UInt16 { 263 }
    @export(implementation)
    public static var ospfRouteType: UInt16 { 264 }
    @export(implementation)
    public static var ipReachability: UInt16 { 265 }

    @export(implementation)
    public static var autonomousSystem: UInt16 { 512 }
    /// Deprecated by RFC 9552; optional for RFC 7752 compatibility. Not used in RIB keys.
    @export(implementation)
    public static var bgpLSIdentifier: UInt16 { 513 }
    @export(implementation)
    public static var ospfAreaID: UInt16 { 514 }
    @export(implementation)
    public static var igpRouterID: UInt16 { 515 }
    /// Compatibility spelling; descriptor 515 also carries IS-IS and OSPF pseudonode identities.
    @export(implementation)
    public static var ipv4RouterID: UInt16 { igpRouterID }
}
