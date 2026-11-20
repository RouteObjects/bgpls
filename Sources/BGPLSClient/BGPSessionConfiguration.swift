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

/// Connection and identity settings for a receive-only BGP-LS session.
///
/// Control-plane peers are **IP endpoints**, not DNS names: the client
/// **outbound-connects** to ``peer``. It does not originate link-state
/// into BGP-LS (RFC 9552 consumer role).
///
/// - ``peer``: remote speaker as ``IPEndpoint`` (address + ``Port``, typically 179).
/// - ``localAddress``: optional bind address as host-length ``IPAddress``.
/// - ``bgpIdentifier``: explicit speaker identity, unrelated to either transport address.
public struct BGPSessionConfiguration<Family: IPAddressFamily>: Sendable, Hashable {
    /// Outbound peer (IP address + TCP port).
    public var peer: IPEndpoint<Family>

    /// Local autonomous system number.
    public var localAS: AutonomousSystemNumber

    /// Peer autonomous system number.
    public var peerAS: AutonomousSystemNumber

    /// Stable local speaker identifier, configured independently of the transport family.
    public var bgpIdentifier: BGPIdentifier

    /// Optional local bind address with a host-length prefix.
    public var localAddress: IPAddress<Family>?

    /// BGP hold time offered in OPEN: zero or at least three seconds, defaulting to 90.
    ///
    /// Zero disables the negotiated inbound hold timer and periodic KEEPALIVEs.
    /// The initial 240-second wait for a valid peer OPEN still applies.
    public var holdTimeSeconds: UInt16

    /// Positive TCP connection timeout; defaults to ten seconds.
    ///
    /// Converted to NIO's nanosecond precision, truncating fractional nanoseconds.
    /// Positive values below one nanosecond use one nanosecond; values above
    /// `Int64.max` nanoseconds are clamped to that limit. Zero and negative values
    /// fail validation before connection or PCAP setup. This is not a BGP handshake timeout.
    public var connectTimeout: Duration

    /// Creates a session configuration.
    public init(
        peer: IPEndpoint<Family>,
        localAS: AutonomousSystemNumber,
        peerAS: AutonomousSystemNumber,
        bgpIdentifier: BGPIdentifier,
        localAddress: IPAddress<Family>? = nil,
        holdTimeSeconds: UInt16 = 90,
        connectTimeout: Duration = .seconds(10)
    ) {
        self.peer = peer
        self.localAS = localAS
        self.peerAS = peerAS
        self.bgpIdentifier = bgpIdentifier
        self.localAddress = localAddress
        self.holdTimeSeconds = holdTimeSeconds
        self.connectTimeout = connectTimeout
    }

    /// Peer TCP port (convenience; same as ``peer``.port).
    public var peerPort: Port { peer.port }

    /// Peer address (convenience; same as ``peer``.address).
    public var peerAddress: IPAddress<Family> { peer.address }

    /// Validates the supported transport boundary before opening files or connecting.
    ///
    /// Host-length addresses are required. IPv6 scope identifiers, link-local addresses,
    /// and IPv4-mapped forms are not supported; wildcard local binds remain valid.
    package func validate() throws {
        _ = try validatedConnectTimeout()
        guard holdTimeSeconds == 0 || holdTimeSeconds >= 3 else {
            throw BGPLSClientError.invalidConfiguration("hold time must be 0 or at least 3 seconds")
        }
        guard peer.port.rawValue > 0 else {
            throw BGPLSClientError.invalidConfiguration("peer port must be non-zero")
        }
        for (role, asn) in [("local", localAS), ("peer", peerAS)] {
            //  General ASN currency includes these values, but a session identity cannot.
            guard asn.rawValue != 0, asn.rawValue != UInt32(BGPOpenCapabilities.asTrans) else {
                throw BGPLSClientError.invalidConfiguration(
                    "\(role) AS must not be 0 or AS_TRANS (23456)"
                )
            }
        }
        try Self.validateAddress(peer.address, isPeer: true)
        if let localAddress { try Self.validateAddress(localAddress, isPeer: false) }
    }

    /// The checked timeout shared by configuration validation and ClientBootstrap.
    package func validatedConnectTimeout() throws -> TimeAmount {
        // Reject nonpositive durations before conversion instead of silently choosing the default.
        guard connectTimeout > .zero else {
            throw BGPLSClientError.invalidConfiguration("connect timeout must be positive")
        }
        // Clamp in Duration space before NIO reads components, whose seconds can overflow Int64.
        let bounded = min(connectTimeout, .nanoseconds(Int64.max))
        // Preserve fractional seconds without letting a positive subnanosecond timeout become zero.
        return .nanoseconds(max(1, TimeAmount(bounded).nanoseconds))
    }

    private static func validateAddress(_ address: IPAddress<Family>, isPeer: Bool) throws {
        let role = isPeer ? "peer" : "local bind"
        //  A socket cannot carry CIDR context. Reject its accidental loss at this
        // application boundary while leaving swift-cidr's general projection unchanged.
        guard address.prefixLength == .maximum else {
            throw BGPLSClientError.invalidConfiguration("\(role) address must have a host-length prefix")
        }
        if let ipv4 = address as? IPv4Address {
            if isPeer && ipv4.address == 0 {
                throw BGPLSClientError.invalidConfiguration("peer address must not be unspecified")
            }
            guard ipv4.address >> 28 != 0xE else {
                throw BGPLSClientError.invalidConfiguration("\(role) address must not be multicast")
            }
        } else if let ipv6 = address as? IPv6Address {
            let bits = ipv6.address
            if isPeer && bits == 0 {
                throw BGPLSClientError.invalidConfiguration("peer address must not be unspecified")
            }
            guard bits >> 120 != 0xFF else {
                throw BGPLSClientError.invalidConfiguration("\(role) address must not be multicast")
            }
            //  CIDRNIO currently constructs scope-free sockets. Link-local fe80::/10
            // needs an interface zone, and ::ffff:0:0/96 would silently use IPv4 transport.
            guard bits >> 118 != 0x3FA else {
                throw BGPLSClientError.invalidConfiguration(
                    "\(role) IPv6 link-local address requires unsupported scope")
            }
            guard bits >> 32 != 0xFFFF else {
                throw BGPLSClientError.invalidConfiguration("\(role) IPv4-mapped IPv6 address is unsupported; use IPv4")
            }
        } else {
            throw BGPLSClientError.invalidConfiguration("unsupported address family for socket bind/connect")
        }
    }
}

extension IPEndpoint {
    /// Builds a TCP-style endpoint from a host-length address and numeric port.
    ///
    /// Kept on ``IPEndpoint`` so callers that also import Foundation avoid the
    /// `Port` vs `Foundation.Port` (NSPort) name clash at the use site.
    public static func tcp(address: IPAddress<Family>, port rawValue: UInt16) -> IPEndpoint<Family> {
        IPEndpoint(address: address, port: Port(rawValue))
    }
}
