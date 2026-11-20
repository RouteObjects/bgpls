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
import CIDRNIO
import NIOCore

/// Thin wrappers over **CIDRNIO** for BGP session bind/connect.
///
/// Dogfooding: prefer ``IPEndpoint/makeSocketAddress()``; extend CIDRNIO when gaps appear
/// (see `Documentation/ProtocolSupport.md`).
enum SocketAddressBuilder {
    static func make(endpoint: IPEndpoint<AF.V4>) throws -> SocketAddress {
        try endpoint.makeSocketAddress()
    }

    static func make(address: IPAddress<AF.V4>, port: UInt16) throws -> SocketAddress {
        try IPEndpoint(address: address, port: Port(port)).makeSocketAddress()
    }

    static func make<Family: IPAddressFamily>(endpoint: IPEndpoint<Family>) throws -> SocketAddress {
        if let ipv4 = endpoint as? IPEndpoint<AF.V4> {
            return try make(endpoint: ipv4)
        }
        if let ipv6 = endpoint as? IPEndpoint<AF.V6> {
            return try ipv6.makeSocketAddress()
        }
        throw BGPLSClientError.invalidConfiguration("unsupported address family for socket bind/connect")
    }

    static func make<Family: IPAddressFamily>(
        address: IPAddress<Family>,
        port: UInt16
    ) throws -> SocketAddress {
        if let ipv4 = address as? IPv4Address {
            return try make(address: ipv4, port: port)
        }
        if let ipv6 = address as? IPv6Address {
            return try IPEndpoint(address: ipv6, port: Port(port))
                .makeSocketAddress()
        }
        throw BGPLSClientError.invalidConfiguration("unsupported address family for socket bind/connect")
    }
}
