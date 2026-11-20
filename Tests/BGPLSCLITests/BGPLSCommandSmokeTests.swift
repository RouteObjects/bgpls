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
import BGPLSCLI
import BGPLSClient
import CIDR
import CIDRArgumentParser
import Testing

struct BGPLSCommandSmokeTests {
    @Test(arguments: ["192.0.2.1", "2001:db8::1"], ["65535", "65536", "4200000001", "4294967295"])
    func parsesFullWidthSessionASNs(peer: String, asn: String) throws {
        let command = try BGPLSCommand.RunCommand.parse([
            "--peer", peer, "--local-as", asn, "--peer-as", asn,
            "--bgp-identifier", "192.0.2.37",
        ])
        let expected = try #require(AutonomousSystemNumber(asn))
        switch try command.sessionConfiguration() {
        case .v4(let configuration):
            #expect(configuration.localAS == expected)
            #expect(configuration.peerAS == expected)
        case .v6(let configuration):
            #expect(configuration.localAS == expected)
            #expect(configuration.peerAS == expected)
        }
    }

    @Test(
        arguments: ["--local-as", "--peer-as"],
        [
            "0", "23456", "", "-1", "+65001", " 65001", "65001 ", "AS65001", "1.10", "4294967296",
        ])
    func rejectsInvalidSessionASNs(option: String, asn: String) {
        let local = option == "--local-as" ? asn : "65001"
        let peer = option == "--peer-as" ? asn : "65001"
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse([
                "--peer", "::1", "--local-as", local, "--peer-as", peer,
                "--bgp-identifier", "192.0.2.37",
            ])
        }
    }

    @Test
    func commandConfigurationName() {
        #expect(BGPLSCommand.configuration.commandName == "bgpls")
        #expect(BGPLSCommand.version == "0.1.0")
    }

    @Test
    func parseRequiresPeerASNsAndIdentifier() {
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse([])
        }
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse([
                "--peer", "192.0.2.1", "--local-as", "65001", "--peer-as", "65001",
            ])
        }
    }

    @Test
    func runHelpDocumentsOrderlySignalShutdown() {
        let help = BGPLSCommand.RunCommand.helpMessage(columns: 100)
            .split(whereSeparator: \.isWhitespace).joined(separator: " ")
        #expect(help.contains("SIGINT (Ctrl-C) and SIGTERM stop the session cleanly"))
        #expect(help.contains("130 and 143"))
        #expect(help.contains("--bgp-identifier"))
        #expect(help.contains("IPv4 or IPv6 host address"))
        #expect(help.contains("(default: 179)"))
        #expect(help.contains("--show-attributes"))
        #expect(help.contains("--dump-rib"))
        #expect(help.contains("one RIB summary"))
        #expect(help.contains("complete final RIB"))
    }

    @Test
    func pcapHelpRequiresANewFileInATrustedDirectory() {
        let help = BGPLSCommand.RunCommand.helpMessage(columns: 100)
            .split(whereSeparator: \.isWhitespace).joined(separator: " ")
        #expect(help.contains("--pcap"))
        #expect(help.contains("--pcap-auto"))
        #expect(help.contains("new .pcap file in a trusted directory"))
        #expect(help.contains("Existing paths are refused"))
        #expect(help.contains("filter on the configured peer port"))
    }

    @Test(
        arguments: [[], ["--pcap-auto"], ["--pcap", "capture space.pcap"], ["--pcap", ""]],
        [
            [], ["--watch"], ["--show-attributes"], ["--dump-rib"],
            ["--watch", "--show-attributes"], ["--watch", "--dump-rib"],
            ["--show-attributes", "--dump-rib"], ["--watch", "--show-attributes", "--dump-rib"],
        ])
    func captureSelectionIsIndependentOfDisplayFlags(captureFlags: [String], displayFlags: [String]) throws {
        let command = try BGPLSCommand.RunCommand.parse(Self.arguments() + captureFlags + displayFlags)
        #expect(command.pcapAuto == captureFlags.contains("--pcap-auto"))
        let expectedExplicitPath = captureFlags.first == "--pcap" ? captureFlags.last : nil
        #expect(command.pcap == expectedExplicitPath)
        #expect(command.showAttributes == displayFlags.contains("--show-attributes"))
        #expect(command.dumpRIB == displayFlags.contains("--dump-rib"))
    }

    @Test(arguments: [
        ["--pcap", "capture.pcap", "--pcap-auto"],
        ["--pcap-auto", "--pcap", "capture.pcap"],
        ["--pcap", "", "--pcap-auto"],
        ["--pcap-auto", "--pcap", ""],
    ])
    func captureModesAreMutuallyExclusive(flags: [String]) {
        do {
            _ = try BGPLSCommand.RunCommand.parse(Self.arguments() + flags)
            Issue.record("Expected explicit and automatic capture options to conflict")
        } catch {
            #expect(
                BGPLSCommand.RunCommand.message(for: error)
                    .contains("--pcap-auto and --pcap are mutually exclusive.")
            )
        }
    }

    @Test(arguments: [["--pcap"], ["--pcap-auto", "--pcap"], ["--pcap", "--pcap-auto"]])
    func explicitCaptureRequiresAValue(flags: [String]) {
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse(Self.arguments() + flags)
        }
    }

    @Test(arguments: [[], ["--pcap-auto"]])
    func emptyEqualsRemainsAMissingValue(flags: [String]) {
        // ArgumentParser rejects --pcap= before validation, unlike a separate explicit empty argument.
        do {
            _ = try BGPLSCommand.RunCommand.parse(Self.arguments() + flags + ["--pcap="])
            Issue.record("Expected an equals sign with no value to remain a parser error")
        } catch {
            #expect(BGPLSCommand.RunCommand.message(for: error).contains("Missing value for '--pcap <pcap>'"))
        }
    }

    @Test
    func typedAttributeDisplayIsOptIn() throws {
        let defaultCommand = try BGPLSCommand.RunCommand.parse(Self.arguments())
        #expect(!defaultCommand.showAttributes)
        let enrichedCommand = try BGPLSCommand.RunCommand.parse(Self.arguments() + ["--show-attributes"])
        #expect(enrichedCommand.showAttributes)
    }

    @Test(arguments: [false, true], [[], ["--watch"], ["--show-attributes"], ["--watch", "--show-attributes"]])
    func finalDumpIsIndependentOfWatchAndAttributes(dumpRIB: Bool, otherFlags: [String]) throws {
        let command = try BGPLSCommand.RunCommand.parse(
            Self.arguments() + otherFlags + (dumpRIB ? ["--dump-rib"] : [])
        )
        #expect(command.dumpRIB == dumpRIB)
        #expect(command.showAttributes == otherFlags.contains("--show-attributes"))
    }

    @Test
    func parseExplicitFlagsIntoSessionConfiguration() throws {
        let command = try BGPLSCommand.RunCommand.parse([
            "--peer", "192.0.2.1",
            "--local-as", "65001",
            "--peer-as", "65001",
            "--bgp-identifier", "192.0.2.37",
            "--local-address", "192.0.2.37",
        ])
        guard case .v4(let configuration) = try command.sessionConfiguration() else {
            Issue.record("Expected IPv4 session configuration")
            return
        }
        #expect(configuration.peer.port.rawValue == 179)
        #expect(configuration.peer.address.description.hasPrefix("192.0.2.1"))
        #expect(configuration.localAddress?.description.hasPrefix("192.0.2.37") == true)
        #expect(configuration.localAS.rawValue == 65001)
        #expect(configuration.peerAS.rawValue == 65001)
        #expect(configuration.bgpIdentifier.description == "192.0.2.37")
    }

    @Test(arguments: ["192.0.2.1", "2001:db8::1"])
    func omitLocalAddressSkipsBind(peer: String) throws {
        let command = try BGPLSCommand.RunCommand.parse(Self.arguments(peer: peer))
        #expect(command.localAddress == nil)
        switch try command.sessionConfiguration() {
        case .v4(let configuration): #expect(configuration.localAddress == nil)
        case .v6(let configuration): #expect(configuration.localAddress == nil)
        }
    }

    @Test(arguments: [
        "", "rr.example.com", "garbage", "192.0.2.1/24", "2001:db8::1/64",
        "0.0.0.0", "::", "224.0.0.1", "ff02::1", "fe80::1",
        "fe80::1%en0", "::1%lo0", "::ffff:192.0.2.1",
    ])
    func parseRejectsUnsupportedPeer(peer: String) {
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse(Self.arguments(peer: peer))
        }
    }

    @Test(arguments: [
        ("192.0.2.1", "192.0.2.1/032"),
        ("192.0.2.1", "192.0.2.1/+32"),
        ("192.0.2.1", "192.0.2.1/-0"),
        ("2001:db8::1", "2001:db8::1/0128"),
        ("2001:db8::1", "2001:db8::1/+128"),
        ("2001:db8::1", "2001:db8::1/-0"),
    ])
    func rejectsNoncanonicalPrefixGrammar(test: (peer: String, invalid: String)) {
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse(Self.arguments(peer: test.invalid))
        }
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse(
                Self.arguments(peer: test.peer) + ["--local-address", test.invalid]
            )
        }
    }

    @Test
    func parseRejectsZeroPeerPort() {
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse(Self.arguments() + ["--port", "0"])
        }
    }

    @Test(arguments: [UInt16(0), 3, 90, .max], ["192.0.2.1", "2001:db8::1"])
    func parseAcceptsLegalHoldTimes(seconds: UInt16, peer: String) throws {
        let command = try BGPLSCommand.RunCommand.parse(Self.arguments(peer: peer) + ["--hold-time", String(seconds)])
        switch try command.sessionConfiguration() {
        case .v4(let configuration): #expect(configuration.holdTimeSeconds == seconds)
        case .v6(let configuration): #expect(configuration.holdTimeSeconds == seconds)
        }
    }

    @Test(arguments: ["1", "2", "-1", "65536", ""], ["192.0.2.1", "2001:db8::1"])
    func parseRejectsIllegalHoldTimes(seconds: String, peer: String) {
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse(Self.arguments(peer: peer) + ["--hold-time", seconds])
        }
    }

    @Test
    func holdTimeHelpDescribesZeroAndMinimum() {
        let help = BGPLSCommand.RunCommand.helpMessage()
        #expect(help.contains("--hold-time"))
        #expect(help.contains("0 or 3–65535 seconds"))
        #expect(help.contains("Zero disables negotiated"))
    }

    @Test
    func parseIPv6FlagsIntoSessionConfiguration() throws {
        let command = try BGPLSCommand.RunCommand.parse(
            Self.arguments(peer: "2001:db8::1/128")
                + ["--local-address", "2001:db8::37", "--port", "11791", "--hold-time", "9"]
        )
        guard case .v6(let configuration) = try command.sessionConfiguration() else {
            Issue.record("Expected IPv6 session configuration")
            return
        }
        #expect(configuration.peer.address.description == "2001:db8::1/128")
        #expect(configuration.localAddress?.description == "2001:db8::37/128")
        #expect(configuration.peer.port.rawValue == 11791)
        #expect(configuration.holdTimeSeconds == 9)
        #expect(configuration.bgpIdentifier.description == "192.0.2.37")
    }

    @Test(arguments: [
        ("192.0.2.1", "::1"), ("2001:db8::1", "127.0.0.1"),
        ("192.0.2.1", ""), ("2001:db8::1", ""),
        ("192.0.2.1", "192.0.2.37/24"), ("2001:db8::1", "2001:db8::37/64"),
        ("192.0.2.1", "224.0.0.1"), ("2001:db8::1", "ff02::1"),
        ("2001:db8::1", "fe80::1"),
        ("2001:db8::1", "fe80::1%en0"), ("2001:db8::1", "::ffff:192.0.2.37"),
    ])
    func parseRejectsInvalidLocalAddress(peer: String, local: String) {
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse(Self.arguments(peer: peer) + ["--local-address", local])
        }
    }

    @Test(arguments: [("192.0.2.1/32", "0.0.0.0"), ("2001:db8::1/128", "::")])
    func parseAcceptsExplicitHostLengthsAndWildcardBind(peer: String, local: String) throws {
        let command = try BGPLSCommand.RunCommand.parse(Self.arguments(peer: peer) + ["--local-address", local])
        #expect(command.localAddress != nil)
        _ = try command.sessionConfiguration()
    }

    @Test(arguments: ["", "0.0.0.0", "192.0.2.37/32", "::1", "+192.0.2.37", "192.0.2.256", "3221226021"])
    func parseRejectsInvalidIdentifier(identifier: String) {
        #expect(throws: (any Error).self) {
            try BGPLSCommand.RunCommand.parse([
                "--peer", "::1", "--local-as", "65001", "--peer-as", "65001",
                "--bgp-identifier", identifier,
            ])
        }
    }

    @Test
    func identifierArgumentWitnessUsesCoreParsing() throws {
        let identifier = try #require(BGPIdentifier(argument: "192.0.2.37"))
        #expect(identifier.rawValue == 0xc000_0225)
        #expect(identifier.defaultValueDescription == "192.0.2.37")
        let padded = try #require(BGPIdentifier(argument: "192.000.002.037"))
        #expect(padded == identifier)
        #expect(padded.defaultValueDescription == "192.0.2.37")
        #expect(BGPIdentifier.allValueStrings.isEmpty)
    }

    @Test
    func defaultedIdentifierHelpUsesDottedQuadGrammar() throws {
        let command = try DefaultedIdentifierArguments.parse([])
        #expect(command.identifier.description == "192.0.2.37")
        let help = DefaultedIdentifierArguments.helpMessage(columns: 100)
        #expect(help.contains("default: 192.0.2.37"))
        #expect(!help.contains("3221226021"))
    }

    private static func arguments(peer: String = "192.0.2.1") -> [String] {
        [
            "--peer", peer, "--local-as", "65001", "--peer-as", "65001",
            "--bgp-identifier", "192.0.2.37",
        ]
    }
}

private struct DefaultedIdentifierArguments: ParsableArguments {
    @Option var identifier: BGPIdentifier

    init() {
        // Guard the known fixture instead of force-unwrapping or using the deprecated
        // optional-default initializer. Production's identifier remains required.
        guard let identifier = BGPIdentifier("192.000.002.037") else {
            preconditionFailure("Invalid default identifier fixture")
        }
        _identifier = Option(wrappedValue: identifier, name: .long)
    }
}
