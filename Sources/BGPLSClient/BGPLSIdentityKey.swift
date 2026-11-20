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

/// Canonical, lossless identity keys, not a wire encoder or a display format.
enum BGPLSIdentityKey {
    static func node(_ node: BGPLSNodeNLRI) -> String {
        "node:\(domain(node.protocolID, node.identifier)):local[\(nodeDescriptors(node.localNode))]"
            + ":additional[\(encode(node.additionalDescriptors))]"
    }

    static func link(_ link: BGPLSLinkNLRI) -> String {
        let descriptors = linkDescriptors(link)
        //  Wire identifiers are a pair, but independently mutable public properties can be
        // partial. Preserve that invalid-but-representable distinction instead of treating it as absent.
        let partialIdentifiers: String
        if (link.localLinkIdentifier == nil) != (link.remoteLinkIdentifier == nil) {
            let local = link.localLinkIdentifier.map(String.init) ?? "-"
            let remote = link.remoteLinkIdentifier.map(String.init) ?? "-"
            partialIdentifiers = ":partial-identifiers[\(local):\(remote)]"
        } else {
            partialIdentifiers = ""
        }
        return "link:\(domain(link.protocolID, link.identifier))"
            + ":local[\(nodeDescriptors(link.localNode))]:remote[\(nodeDescriptors(link.remoteNode))]"
            + ":descriptors[\(encode(descriptors, protocolID: link.protocolID))]"
            + partialIdentifiers
    }

    static func prefix(_ prefix: BGPLSIPv4PrefixNLRI) -> String {
        prefixKey(prefix, namespace: "prefix")
    }

    static func prefix(_ prefix: BGPLSIPv6PrefixNLRI) -> String {
        //  Keep existing IPv4 keys stable while separating equal descriptor bytes
        // from the two NLRI families, including their otherwise identical default routes.
        prefixKey(prefix, namespace: "prefix6")
    }

    private static func prefixKey<Family: IPAddressFamily>(
        _ prefix: BGPLSPrefixNLRI<Family>, namespace: String
    ) -> String {
        var descriptors = prefix.prefixDescriptors.filter { $0.type != BGPLSDescriptorType.ipReachability }
        //  CIDR owns host-bit canonicalization, including unused bits in the last wire octet.
        let network = prefix.network
        let length = network.prefixLength.rawValue
        let octetCount = (Int(length) + 7) / 8
        descriptors.append(
            BGPLSTLV(
                type: BGPLSDescriptorType.ipReachability,
                value: [length] + bytes(network.prefix).prefix(octetCount)
            )
        )
        return "\(namespace):\(domain(prefix.protocolID, prefix.identifier))"
            + ":local[\(nodeDescriptors(prefix.localNode))]"
            + ":descriptors[\(encode(descriptors, protocolID: prefix.protocolID))]"
    }

    private static func domain(_ protocolID: UInt8, _ identifier: UInt64) -> String {
        "\(protocolID):\(identifier)"
    }

    private static func nodeDescriptors(_ node: BGPLSNodeIdentity) -> String {
        //  Mutable typed properties are authoritative; raw copies must not resurrect removed
        // fields. Unknown descriptors still distinguish nodes, while deprecated TLV 513 never does.
        var descriptors = node.rawTLVs.filter {
            ![
                BGPLSDescriptorType.autonomousSystem,
                BGPLSDescriptorType.bgpLSIdentifier,
                BGPLSDescriptorType.ospfAreaID,
                BGPLSDescriptorType.ipv4RouterID,
            ].contains($0.type)
        }
        if let asn = node.autonomousSystem {
            descriptors.append(BGPLSTLV(type: BGPLSDescriptorType.autonomousSystem, value: bytes(asn.rawValue)))
        }
        if let area = node.ospfAreaID {
            descriptors.append(BGPLSTLV(type: BGPLSDescriptorType.ospfAreaID, value: bytes(area.rawValue)))
        }
        if let routerID = node.igpRouterID {
            descriptors.append(BGPLSTLV(type: BGPLSDescriptorType.ipv4RouterID, value: routerID.rawValue))
        }
        return encode(descriptors)
    }

    private static func linkDescriptors(_ link: BGPLSLinkNLRI) -> [BGPLSTLV] {
        var descriptors = link.linkDescriptors.filter {
            ![
                BGPLSDescriptorType.linkLocalRemoteIdentifiers,
                BGPLSDescriptorType.ipv4InterfaceAddress,
                BGPLSDescriptorType.ipv4NeighborAddress,
                BGPLSDescriptorType.ipv6InterfaceAddress,
                BGPLSDescriptorType.ipv6NeighborAddress,
            ].contains($0.type)
        }
        if let local = link.localLinkIdentifier, let remote = link.remoteLinkIdentifier {
            descriptors.append(
                BGPLSTLV(type: BGPLSDescriptorType.linkLocalRemoteIdentifiers, value: bytes(local) + bytes(remote))
            )
        }
        if let local = link.localIPv4Interface {
            descriptors.append(BGPLSTLV(type: BGPLSDescriptorType.ipv4InterfaceAddress, value: bytes(local.address)))
        }
        if let remote = link.remoteIPv4Neighbor {
            descriptors.append(BGPLSTLV(type: BGPLSDescriptorType.ipv4NeighborAddress, value: bytes(remote.address)))
        }
        //  IPv6 descriptors now follow the same typed-authority rule as IPv4;
        // stale raw TLVs must not restore an address removed from the public model.
        if let local = link.localIPv6Interface {
            descriptors.append(BGPLSTLV(type: BGPLSDescriptorType.ipv6InterfaceAddress, value: bytes(local.address)))
        }
        if let remote = link.remoteIPv6Neighbor {
            descriptors.append(BGPLSTLV(type: BGPLSDescriptorType.ipv6NeighborAddress, value: bytes(remote.address)))
        }
        return descriptors
    }

    private static func encode(_ descriptors: [BGPLSTLV], protocolID: UInt8? = nil) -> String {
        let canonical = descriptors.map { descriptor in
            var descriptor = descriptor
            if protocolID == BGPLSProtocolID.isisLevel1.rawValue || protocolID == BGPLSProtocolID.isisLevel2.rawValue,
                descriptor.type == 263, descriptor.value.count == 2
            {
                //  RFC 9552 §5.2.2.1 requires ignoring IS-IS descriptor MT-ID reserved bits.
                descriptor.value[0] &= 0x0f
            }
            return descriptor
        }.sorted {
            if $0.type != $1.type { return $0.type < $1.type }
            if $0.value.count != $1.value.count { return $0.value.count < $1.value.count }
            return $0.value.lexicographicallyPrecedes($1.value)
        }
        //  Frame type, length, and hexadecimal value so descriptor boundaries cannot collide;
        // RFC 9552 §5.1 type/length/value sorting also preserves repeated unknown descriptors.
        return canonical.map { descriptor in
            let value = descriptor.value.map { byte in
                let text = String(byte, radix: 16)
                return byte < 16 ? "0" + text : text
            }.joined()
            return "\(descriptor.type):\(descriptor.value.count):\(value);"
        }.joined()
    }

    private static func bytes<Storage: FixedWidthInteger & UnsignedInteger>(_ value: Storage) -> [UInt8] {
        stride(from: Storage.bitWidth - 8, through: 0, by: -8).map {
            UInt8(truncatingIfNeeded: value >> $0)
        }
    }
}
