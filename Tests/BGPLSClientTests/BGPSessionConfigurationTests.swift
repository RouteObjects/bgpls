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

import BGPLSClient
import CIDR
import Testing

struct BGPSessionConfigurationTests {
    @Test(arguments: [UInt16(0), 3, 90, .max])
    func validHoldTimesArePreserved(seconds: UInt16) throws {
        var ipv4 = try Self.configuration(peer: #require(IPv4Address("127.0.0.1")))
        var ipv6 = try Self.configuration(peer: #require(IPv6Address("::1")))
        ipv4.holdTimeSeconds = seconds
        ipv6.holdTimeSeconds = seconds
        try ipv4.validate()
        try ipv6.validate()
        #expect(ipv4.holdTimeSeconds == seconds)
        #expect(ipv6.holdTimeSeconds == seconds)
    }

    @Test(arguments: [UInt16(1), 2])
    func invalidHoldTimesAreRejected(seconds: UInt16) throws {
        var ipv4 = try Self.configuration(peer: #require(IPv4Address("127.0.0.1")))
        var ipv6 = try Self.configuration(peer: #require(IPv6Address("::1")))
        ipv4.holdTimeSeconds = seconds
        ipv6.holdTimeSeconds = seconds
        let error = BGPLSClientError.invalidConfiguration("hold time must be 0 or at least 3 seconds")
        #expect(throws: error) { try ipv4.validate() }
        #expect(throws: error) { try ipv6.validate() }
    }

    @Test(arguments: [
        TimeoutCase(duration: .milliseconds(250), nanoseconds: 250_000_000),
        TimeoutCase(duration: .milliseconds(500), nanoseconds: 500_000_000),
        TimeoutCase(duration: .milliseconds(1500), nanoseconds: 1_500_000_000),
        TimeoutCase(duration: .seconds(10), nanoseconds: 10_000_000_000),
        TimeoutCase(duration: .nanoseconds(1), nanoseconds: 1),
        TimeoutCase(duration: Duration(secondsComponent: 0, attosecondsComponent: 1), nanoseconds: 1),
        TimeoutCase(duration: Duration(secondsComponent: 0, attosecondsComponent: 1_999_999_999), nanoseconds: 1),
        TimeoutCase(duration: .nanoseconds(Int64.max), nanoseconds: Int64.max),
        TimeoutCase(duration: .nanoseconds(Int64.max) + .nanoseconds(1), nanoseconds: Int64.max),
        TimeoutCase(duration: .seconds(Int64.max), nanoseconds: Int64.max),
    ])
    func connectTimeoutConversionPreservesPrecisionAndBounds(test: TimeoutCase) throws {
        var ipv4 = try Self.configuration(peer: #require(IPv4Address("127.0.0.1")))
        var ipv6 = try Self.configuration(peer: #require(IPv6Address("::1")))
        ipv4.connectTimeout = test.duration
        ipv6.connectTimeout = test.duration
        try ipv4.validate()
        try ipv6.validate()
        #expect(try ipv4.validatedConnectTimeout().nanoseconds == test.nanoseconds)
        #expect(try ipv6.validatedConnectTimeout().nanoseconds == test.nanoseconds)
        #expect(ipv4.connectTimeout == test.duration)
        #expect(ipv6.connectTimeout == test.duration)
    }

    @Test(arguments: [
        Duration.zero, .nanoseconds(-1), .milliseconds(-250), .seconds(-1), .seconds(Int64.min),
        Duration(secondsComponent: 0, attosecondsComponent: -1),
    ])
    func nonpositiveConnectTimeoutIsRejectedBeforeConversion(duration: Duration) throws {
        var ipv4 = try Self.configuration(peer: #require(IPv4Address("127.0.0.1")))
        var ipv6 = try Self.configuration(peer: #require(IPv6Address("::1")))
        ipv4.connectTimeout = duration
        ipv6.connectTimeout = duration
        let error = BGPLSClientError.invalidConfiguration("connect timeout must be positive")
        #expect(throws: error) { try ipv4.validate() }
        #expect(throws: error) { try ipv6.validate() }
        #expect(throws: error) { try ipv4.validatedConnectTimeout() }
        #expect(throws: error) { try ipv6.validatedConnectTimeout() }
    }

    struct TimeoutCase: Sendable {
        let duration: Duration
        let nanoseconds: Int64
    }

    @Test
    func durationsBeyondInt64SecondsAreHandledBeforeComponentDecomposition() throws {
        var ipv4 = try Self.configuration(peer: #require(IPv4Address("127.0.0.1")))
        var ipv6 = try Self.configuration(peer: #require(IPv6Address("::1")))
        // These are valid Durations, but asking for their Int64 seconds components would trap.
        for duration in [Duration.seconds(Int64.max) + .seconds(1), .seconds(Int64.max) * 18] {
            ipv4.connectTimeout = duration
            ipv6.connectTimeout = duration
            try ipv4.validate()
            try ipv6.validate()
            #expect(try ipv4.validatedConnectTimeout().nanoseconds == Int64.max)
            #expect(try ipv6.validatedConnectTimeout().nanoseconds == Int64.max)
        }
        let error = BGPLSClientError.invalidConfiguration("connect timeout must be positive")
        for duration in [Duration.seconds(Int64.min) - .seconds(1), .seconds(Int64.min) * 18] {
            ipv4.connectTimeout = duration
            ipv6.connectTimeout = duration
            #expect(throws: error) { try ipv4.validate() }
            #expect(throws: error) { try ipv6.validate() }
            #expect(throws: error) { try ipv4.validatedConnectTimeout() }
            #expect(throws: error) { try ipv6.validatedConnectTimeout() }
        }
    }

    @Test
    func explicitConfigurationPreservesSuppliedIdentityAndDefaults() throws {
        let identifier = try #require(BGPIdentifier("192.0.2.254"))
        let local: IPv4Address = try #require(IPv4Address("192.0.2.37"))
        let configuration = BGPSessionConfiguration(
            peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
            localAS: AutonomousSystemNumber(65001),
            peerAS: AutonomousSystemNumber(65001),
            bgpIdentifier: identifier,
            localAddress: local
        )
        #expect(configuration.peer.address.description == "192.0.2.1/32")
        #expect(configuration.peer.port.rawValue == 179)
        #expect(configuration.localAddress?.description == "192.0.2.37/32")
        #expect(configuration.localAS.rawValue == 65001)
        #expect(configuration.peerAS.rawValue == 65001)
        #expect(configuration.peerPort.rawValue == 179)
        #expect(configuration.bgpIdentifier == identifier)
        #expect(configuration.connectTimeout == .seconds(10))
        #expect(try configuration.validatedConnectTimeout().nanoseconds == 10_000_000_000)
    }

    @Test
    func peerEndpointAndIdentifierAreHashableCurrency() throws {
        let identifier = try #require(BGPIdentifier("192.0.2.254"))
        let local: IPv4Address = try #require(IPv4Address("192.0.2.37"))
        let a = BGPSessionConfiguration(
            peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
            localAS: AutonomousSystemNumber(65001),
            peerAS: AutonomousSystemNumber(65001),
            bgpIdentifier: identifier,
            localAddress: local
        )
        var b = BGPSessionConfiguration(
            peer: .tcp(address: try #require(IPv4Address("192.0.2.1")), port: 179),
            localAS: AutonomousSystemNumber(65001),
            peerAS: AutonomousSystemNumber(65001),
            bgpIdentifier: identifier,
            localAddress: local
        )
        #expect(a == b)
        let aHash = a.hashValue
        let bHash = b.hashValue
        #expect(aHash == bHash)
        #expect(Set([a]).contains(b))
        #expect([a: "session"][b] == "session")
        b.bgpIdentifier = try #require(BGPIdentifier("192.0.2.253"))
        #expect(a != b)
        #expect(!Set([a]).contains(b))
        #expect([a: "session"][b] == nil)
    }

    @Test(arguments: ["192.0.2.1", "127.0.0.1", "192.0.2.1/32", "169.254.0.1", "169.254.255.254"])
    func ipv4HostPeersAndWildcardOrOmittedBindsAreValid(text: String) throws {
        let peer = try #require(IPv4Address(text))
        var configuration = try Self.configuration(peer: peer)
        try configuration.validate()
        let wildcard: IPv4Address = try #require(IPv4Address("0.0.0.0"))
        configuration.localAddress = wildcard
        try configuration.validate()
        let loopback: IPv4Address = try #require(IPv4Address("127.0.0.1"))
        configuration.localAddress = loopback
        try configuration.validate()
        configuration.peer = .tcp(address: peer, port: UInt16.max)
        try configuration.validate()
    }

    @Test(arguments: ["::1", "2001:db8::1", "fd00::1", "2001:db8::1/128", "fe7f:ffff::1", "fec0::1"])
    func unscopedIPv6HostsAndWildcardOrOmittedBindsAreValid(text: String) throws {
        let peer = try #require(IPv6Address(text))
        var configuration = try Self.configuration(peer: peer)
        try configuration.validate()
        let wildcard: IPv6Address = try #require(IPv6Address("::"))
        configuration.localAddress = wildcard
        try configuration.validate()
        let loopback: IPv6Address = try #require(IPv6Address("::1"))
        configuration.localAddress = loopback
        try configuration.validate()
    }

    @Test
    func ipv6ConfigurationIdentityIncludesTheIndependentIdentifier() throws {
        let first = try Self.configuration(peer: #require(IPv6Address("2001:db8::1")))
        var equal = try Self.configuration(peer: #require(IPv6Address("2001:db8::1")))
        #expect(first == equal)
        let firstHash = first.hashValue
        let equalHash = equal.hashValue
        #expect(firstHash == equalHash)
        #expect(Set([first]).contains(equal))
        #expect([first: "ipv6"][equal] == "ipv6")
        equal.bgpIdentifier = try #require(BGPIdentifier("255.255.255.255"))
        try equal.validate()
        #expect(first != equal)
        #expect(!Set([first]).contains(equal))
        #expect([first: "ipv6"][equal] == nil)
    }

    @Test(arguments: ["0.0.0.0", "224.0.0.0", "239.255.255.255", "192.0.2.1/24"])
    func invalidIPv4PeerIsRejected(text: String) throws {
        let configuration = try Self.configuration(peer: #require(IPv4Address(text)))
        #expect(throws: (any Error).self) { try configuration.validate() }
    }

    @Test(arguments: ["224.0.0.1", "239.255.255.255", "192.0.2.1/24"])
    func invalidIPv4BindIsRejected(text: String) throws {
        var configuration = try Self.configuration(peer: #require(IPv4Address("192.0.2.1")))
        let local: IPv4Address = try #require(IPv4Address(text))
        configuration.localAddress = local
        #expect(throws: (any Error).self) { try configuration.validate() }
    }

    @Test(arguments: [
        "::", "ff00::1", "ffff::1", "fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "::ffff:0.0.0.0", "::ffff:192.0.2.1", "::ffff:255.255.255.255", "2001:db8::1/64",
    ])
    func invalidIPv6PeerIsRejected(text: String) throws {
        let configuration = try Self.configuration(peer: #require(IPv6Address(text)))
        #expect(throws: (any Error).self) { try configuration.validate() }
    }

    @Test(arguments: ["ff02::1", "fe80::1", "febf::1", "::ffff:192.0.2.1", "2001:db8::1/64"])
    func invalidIPv6BindIsRejected(text: String) throws {
        var configuration = try Self.configuration(peer: #require(IPv6Address("2001:db8::1")))
        let local: IPv6Address = try #require(IPv6Address(text))
        configuration.localAddress = local
        #expect(throws: (any Error).self) { try configuration.validate() }
    }

    @Test
    func zeroPeerPortRemainsInvalid() throws {
        let peer = try #require(IPv6Address("::1"))
        var configuration = try Self.configuration(peer: peer)
        configuration.peer = .tcp(address: peer, port: 0)
        #expect(throws: BGPLSClientError.invalidConfiguration("peer port must be non-zero")) {
            try configuration.validate()
        }
    }

    @Test(arguments: [UInt32(1), 65_535, 65_536, 4_200_000_001, UInt32.max])
    func fullWidthSessionASNsValidateForBothTransportFamilies(raw: UInt32) throws {
        var ipv4 = try Self.configuration(peer: #require(IPv4Address("127.0.0.1")))
        var ipv6 = try Self.configuration(peer: #require(IPv6Address("::1")))
        ipv4.localAS = AutonomousSystemNumber(raw)
        ipv4.peerAS = AutonomousSystemNumber(raw)
        ipv6.localAS = AutonomousSystemNumber(raw)
        ipv6.peerAS = AutonomousSystemNumber(raw)
        try ipv4.validate()
        try ipv6.validate()
    }

    @Test(arguments: [UInt32(0), 23_456], [false, true])
    func reservedSessionIdentitiesAreRejected(raw: UInt32, isLocal: Bool) throws {
        var ipv4 = try Self.configuration(peer: #require(IPv4Address("127.0.0.1")))
        var ipv6 = try Self.configuration(peer: #require(IPv6Address("::1")))
        if isLocal {
            ipv4.localAS = AutonomousSystemNumber(raw)
            ipv6.localAS = AutonomousSystemNumber(raw)
        } else {
            ipv4.peerAS = AutonomousSystemNumber(raw)
            ipv6.peerAS = AutonomousSystemNumber(raw)
        }
        let role = isLocal ? "local" : "peer"
        let expected = BGPLSClientError.invalidConfiguration("\(role) AS must not be 0 or AS_TRANS (23456)")
        #expect(throws: expected) { try ipv4.validate() }
        #expect(throws: expected) { try ipv6.validate() }
    }

    @Test
    func configurationIdentityRetainsAddressPrefixContext() throws {
        try Self.checkPrefixContext(
            host: #require(IPv4Address("192.0.2.1/32")),
            contextual: #require(IPv4Address("192.0.2.1/24"))
        )
        try Self.checkPrefixContext(
            host: #require(IPv6Address("2001:db8::1/128")),
            contextual: #require(IPv6Address("2001:db8::1/64"))
        )
    }

    @Test
    func widelySeparatedIPv6ConfigurationsSupportEqualityAndLookup() throws {
        let low = try Self.configuration(peer: #require(IPv6Address("::1")))
        let high = try Self.configuration(peer: #require(IPv6Address("8000::2")))
        let highCopy = try Self.configuration(peer: #require(IPv6Address("8000::2/128")))
        let highHash = high.hashValue
        let copyHash = highCopy.hashValue
        #expect(low != high)
        #expect(high == highCopy)
        #expect(highHash == copyHash)
        #expect(Set([low, high]).contains(highCopy))
        #expect([low: "low", high: "high"][highCopy] == "high")
    }

    private static func checkPrefixContext<Family: IPAddressFamily>(
        host: IPAddress<Family>, contextual: IPAddress<Family>
    ) throws {
        let valid = try configuration(peer: host)
        let validCopy = try configuration(peer: host)
        let contextualPeer = try configuration(peer: contextual)
        let validHash = valid.hashValue
        let copyHash = validCopy.hashValue
        #expect(valid == validCopy)
        #expect(validHash == copyHash)
        #expect(valid != contextualPeer)
        #expect(Set([valid, contextualPeer]).count == 2)
        #expect([valid: "host", contextualPeer: "context"][validCopy] == "host")
        #expect([valid: "host", contextualPeer: "context"][contextualPeer] == "context")
        try valid.validate()
        #expect(throws: (any Error).self) { try contextualPeer.validate() }

        var boundHost = valid
        boundHost.localAddress = host
        var boundContext = valid
        boundContext.localAddress = contextual
        #expect(boundHost != boundContext)
        #expect(Set([boundHost, boundContext]).count == 2)
        try boundHost.validate()
        #expect(throws: (any Error).self) { try boundContext.validate() }
    }

    private static func configuration<Family: IPAddressFamily>(
        peer: IPAddress<Family>
    ) throws -> BGPSessionConfiguration<Family> {
        BGPSessionConfiguration(
            peer: .tcp(address: peer, port: 179),
            localAS: AutonomousSystemNumber(65001),
            peerAS: AutonomousSystemNumber(65001),
            bgpIdentifier: try #require(BGPIdentifier("192.0.2.254"))
        )
    }
}
