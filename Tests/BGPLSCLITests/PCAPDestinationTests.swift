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
import CIDR
import Foundation
import NIOCore
import NIOPosix
import Synchronization
import Testing

@testable import BGPLSClient

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

struct PCAPDestinationTests {
    @Test
    func omittedCaptureHasNoDestination() throws {
        #expect(try selectIPv4(explicitPath: nil, automatic: false) == nil)
    }

    @Test(arguments: ["capture.pcap", "capture space.pcap", "/tmp/explicit.pcap", "", "invalid\0path"])
    func explicitPathIsPreservedWithoutAutomaticFallback(path: String) throws {
        let selected = try #require(try selectIPv4(explicitPath: path, automatic: false))
        #expect(selected.path == path)
        #expect(!selected.isAutomatic)
        #expect(selected.selectionMessage == nil)
    }

    @Test(arguments: ["capture.pcap", ""])
    func conflictingModesFailBeforeSelectingAPath(path: String) throws {
        for operation in [
            { try PCAPDestination.validate(explicitPath: path, automatic: true) },
            { _ = try selectIPv4(explicitPath: path, automatic: true) },
        ] {
            do {
                try operation()
                Issue.record("Expected mutually exclusive capture modes to fail")
            } catch let error as ValidationError {
                #expect(error.message == "--pcap-auto and --pcap are mutually exclusive.")
            }
        }
    }

    @Test(arguments: [UInt16(179), 11791])
    func ipv4NameUsesLiteralPeerPortAndFullLowercaseUUID(port: UInt16) throws {
        let selected = try #require(try selectIPv4(port: port))
        #expect(
            selected.path
                == "/tmp/capture directory/bgpls_20261029_143025Z_peer-192.0.2.1_port-\(port)_7d18c1ac-9c42-478d-b1b7-19cdf208eb51.pcap"
        )
        #expect(selected.isAutomatic)
        let filename = URL(fileURLWithPath: selected.path).lastPathComponent
        #expect(!filename.contains("/32"))
        #expect(!filename.contains(":"))
    }

    @Test(arguments: [
        ("2001:0DB8:0000:0000:0000:0000:0000:0001/128", "2001-db8--1"),
        ("::1/128", "--1"),
    ])
    func ipv6NameUsesCanonicalLiteralWithoutPrefixOrColons(input: String, filenamePeer: String) throws {
        let address = try #require(IPv6Address(input))
        let selected = try #require(
            try PCAPDestination.select(
                explicitPath: nil, automatic: true,
                peer: .tcp(address: address, port: 11791),
                date: fixtureDate(), uuid: fixtureUUID(), workingDirectory: "/tmp/capture directory"
            )
        )
        #expect(
            selected.path
                == "/tmp/capture directory/bgpls_20261029_143025Z_peer-\(filenamePeer)_port-11791_7d18c1ac-9c42-478d-b1b7-19cdf208eb51.pcap"
        )
        let filename = URL(fileURLWithPath: selected.path).lastPathComponent
        #expect(!filename.contains("/128"))
        #expect(!filename.contains(":"))
    }

    @Test(arguments: [
        ("2019-12-30T00:00:00Z", "20191230_000000Z"),
        ("2021-01-01T00:00:00Z", "20210101_000000Z"),
        ("2026-10-30T00:30:25+10:00", "20261029_143025Z"),
        ("2026-10-28T23:30:25-05:00", "20261029_043025Z"),
        ("2026-12-31T19:30:25-05:00", "20270101_003025Z"),
    ])
    func timestampUsesUTCGregorianCalendarYear(input: String, expected: String) throws {
        // Offset-bearing fixtures exercise UTC day and year rollover without changing process time zone.
        let date = try #require(ISO8601DateFormatter().date(from: input))
        let selected = try #require(try selectIPv4(date: date))
        #expect(URL(fileURLWithPath: selected.path).lastPathComponent.hasPrefix("bgpls_\(expected)_peer-"))
    }

    @Test
    func injectedUUIDSeparatesOtherwiseIdenticalNames() throws {
        let first = try #require(try selectIPv4())
        let secondUUID = try #require(UUID(uuidString: "09388544-6446-4609-AB3C-3591393FC62D"))
        let second = try #require(try selectIPv4(uuid: secondUUID))
        #expect(first != second)
        #expect(second.path.hasSuffix("_09388544-6446-4609-ab3c-3591393fc62d.pcap"))
    }

    @Test
    func selectionReportsTheCompleteEscapedAbsolutePath() throws {
        let directory = "/tmp/capture space\nline\rreturn\u{1B}escape\"quote\\backslash"
        let selected = try #require(try selectIPv4(workingDirectory: directory))
        #expect(URL(fileURLWithPath: selected.path).deletingLastPathComponent().path == directory)
        let message = try #require(selected.selectionMessage)
        #expect(message == "bgpls: PCAP destination selected: \(String(reflecting: selected.path))\n")
        #expect(message.filter { $0 == "\n" }.count == 1)
        #expect(message.hasSuffix("\"\n"))
        #expect(message.contains("\\n"))
        #expect(message.contains("\\r"))
        #expect(!message.contains("\u{1B}"))
    }

    @Test
    func relativeWorkingDirectoryResolvesWithoutChangingCurrentDirectory() throws {
        let selected = try #require(try selectIPv4(workingDirectory: "capture directory"))
        let expectedDirectory = URL(fileURLWithPath: "capture directory", isDirectory: true).path
        #expect(selected.path.hasPrefix("/"))
        #expect(URL(fileURLWithPath: selected.path).deletingLastPathComponent().path == expectedDirectory)
    }

    @Test
    func selectingDoesNotCreateFilesOrDirectories() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("bgpls-selection-only-\(UUID().uuidString)", isDirectory: true)
        #expect(!FileManager.default.fileExists(atPath: directory.path))
        let selected = try #require(try selectIPv4(workingDirectory: directory.path))
        #expect(!FileManager.default.fileExists(atPath: selected.path))
        #expect(!FileManager.default.fileExists(atPath: directory.path))
    }

    @Test(.timeLimit(.minutes(1)))
    func generatedPathCollisionPreservesExistingFileAndFailsBeforeTCP() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("bgpls-auto-collision-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }

        let acceptedConnections = Mutex(0)
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                acceptedConnections.withLock { $0 += 1 }
                return channel.close()
            }
            .bind(host: "127.0.0.1", port: 0).get()
        defer { server.close(promise: nil) }
        let port = try #require(server.localAddress?.port.flatMap(UInt16.init(exactly:)))
        let peer = IPEndpoint.tcp(address: try #require(IPv4Address("127.0.0.1")), port: port)
        let selected = try #require(
            try PCAPDestination.select(
                explicitPath: nil, automatic: true, peer: peer,
                date: fixtureDate(), uuid: fixtureUUID(), workingDirectory: directory.path
            )
        )
        let capture = URL(fileURLWithPath: selected.path)
        let sentinel = Data("An existing generated capture must survive.\n".utf8)
        try sentinel.write(to: capture)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: capture.path)
        let session = BGPSession(
            configuration: BGPSessionConfiguration(
                peer: peer, localAS: AutonomousSystemNumber(65001), peerAS: AutonomousSystemNumber(65001),
                bgpIdentifier: try #require(BGPIdentifier("192.0.2.254")), connectTimeout: .seconds(1)
            )
        )

        // Exercise the real sink and session ordering with the generated filename, including a deliberate collision.
        await #expect(throws: PCAPFileSink.Failure.systemCall(operation: "create", code: EEXIST)) {
            try await session.run(pcapPath: selected.path)
        }
        try await server.close().get()
        #expect(acceptedConnections.withLock { $0 } == 0)
        #expect(await session.sessionState() == .stopped)
        #expect(try Data(contentsOf: capture) == sentinel)
        let permissions = try #require(
            FileManager.default.attributesOfItem(atPath: capture.path)[.posixPermissions] as? NSNumber)
        #expect(permissions.uint16Value == 0o644)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == [capture.lastPathComponent])
    }

    private func selectIPv4(
        explicitPath: String? = nil, automatic: Bool = true, port: UInt16 = 179,
        date: Date? = nil, uuid: UUID? = nil, workingDirectory: String = "/tmp/capture directory"
    ) throws -> PCAPDestination? {
        try PCAPDestination.select(
            explicitPath: explicitPath, automatic: automatic,
            peer: .tcp(address: #require(IPv4Address("192.0.2.1/32")), port: port),
            date: date ?? fixtureDate(), uuid: uuid ?? fixtureUUID(), workingDirectory: workingDirectory
        )
    }

    private func fixtureDate() throws -> Date {
        try #require(ISO8601DateFormatter().date(from: "2026-10-29T14:30:25Z"))
    }

    private func fixtureUUID() throws -> UUID {
        try #require(UUID(uuidString: "7D18C1AC-9C42-478D-B1B7-19CDF208EB51"))
    }
}
