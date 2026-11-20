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
import Testing

@testable import BGPLSClient

struct SocketAddressBuilderTests {
    @Test(arguments: [UInt16(0), 179, UInt16.max])
    func ipv4SocketRetainsHostBitsAndNumericPort(port: UInt16) throws {
        let address = try #require(IPv4Address("192.0.2.37"))
        let endpoint = IPEndpoint(address: address, port: Port(port))
        let socket = try Self.genericSocket(endpoint)
        let roundTrip = try IPEndpoint<AF.V4>(socketAddress: socket)
        #expect(roundTrip == endpoint)
        #expect(socket.ipAddress == "192.0.2.37")
        #expect(socket.port == Int(port))
        #expect(try Self.genericSocket(address: address, port: port) == socket)
        #expect(try SocketAddressBuilder.make(address: address, port: port) == socket)
    }

    @Test(arguments: [UInt16(0), 179, UInt16.max])
    func ipv6SocketRetainsHostBitsPortAndZeroScope(port: UInt16) throws {
        let address = try #require(IPv6Address("2001:db8:1234:5678:90ab:cdef:1234:5678"))
        let endpoint = IPEndpoint(address: address, port: Port(port))
        let socket = try Self.genericSocket(endpoint)
        let addressSocket = try Self.genericSocket(address: address, port: port)
        let roundTrip = try IPEndpoint<AF.V6>(socketAddress: socket)
        #expect(roundTrip == endpoint)
        #expect(socket.port == Int(port))
        #expect(addressSocket == socket)
        #expect(try SocketAddressBuilder.make(address: address, port: port) == socket)
        for projection in [socket, addressSocket] {
            guard case .v6(let value) = projection else {
                Issue.record("Expected an IPv6 socket")
                return
            }
            #expect(value.address.sin6_scope_id == 0)
            #expect(value.address.sin6_flowinfo == 0)
        }
    }

    @Test
    func genericIPv4ProjectionRetainsPrefixedHostBits() throws {
        let address = try #require(IPv4Address("192.0.2.37/24"))
        let endpoint = IPEndpoint(address: address, port: Port(179))
        let socket = try Self.genericSocket(endpoint)
        let addressSocket = try Self.genericSocket(address: address, port: 179)
        let roundTrip = try IPEndpoint<AF.V4>(socketAddress: socket)
        #expect(addressSocket == socket)
        #expect(socket.ipAddress == "192.0.2.37")
        #expect(socket.port == 179)
        #expect(roundTrip.address.address == address.address)
        #expect(roundTrip.address.prefixLength == .maximum)
        #expect(roundTrip.port == endpoint.port)
        #expect(address.prefixLength.intValue == 24)
    }

    @Test(arguments: [
        ("192.0.2.0/24", NIOSocketAddressConversionError.ipv4NetworkAddress(prefixLength: 24)),
        ("192.0.2.255/24", NIOSocketAddressConversionError.ipv4DirectedBroadcastAddress(prefixLength: 24)),
    ])
    func genericIPv4ProjectionPreservesCIDRNIOBoundaryErrors(
        fixture: (String, NIOSocketAddressConversionError)
    ) throws {
        let (text, error) = fixture
        let address = try #require(IPv4Address(text))
        let endpoint = IPEndpoint(address: address, port: Port(179))
        #expect(throws: error) { try Self.genericSocket(endpoint) }
        #expect(throws: error) { try Self.genericSocket(address: address, port: 179) }
    }

    @Test
    func unsupportedConcreteFamilyIsNotInferredFromIPv4Metadata() {
        let address = IPAddress<IPv4LikeFamily>(address: 0xc000_0225)
        let endpoint = IPEndpoint(address: address, port: Port(179))
        let error = BGPLSClientError.invalidConfiguration("unsupported address family for socket bind/connect")
        #expect(throws: error) { try Self.genericSocket(endpoint) }
        #expect(throws: error) { try Self.genericSocket(address: address, port: 179) }
    }

    private static func genericSocket<Family: IPAddressFamily>(
        _ endpoint: IPEndpoint<Family>
    ) throws -> SocketAddress {
        try SocketAddressBuilder.make(endpoint: endpoint)
    }

    private static func genericSocket<Family: IPAddressFamily>(
        address: IPAddress<Family>, port: UInt16
    ) throws -> SocketAddress {
        // A generic call site exercises dispatch that a concrete IPv4 overload would bypass.
        try SocketAddressBuilder.make(address: address, port: port)
    }
}

private enum IPv4LikeFamily: IPAddressFamily {
    typealias Storage = UInt32

    static let ianaValue = AF.V4.ianaValue
    static let bitWidth = AF.V4.bitWidth
    static let familyName = AF.V4.familyName

    static func parseAddress(_ string: String) -> UInt32? {
        AF.V4.parseAddress(string)
    }

    static func formatAddress(_ address: UInt32) -> String {
        AF.V4.formatAddress(address)
    }
}
