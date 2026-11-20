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

import Foundation
import NIOCore
import NIOExtras
import NIOPosix
import Testing

@testable import BGPLSClient

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

struct PCAPFileSafetyTests {
    @Test(.timeLimit(.minutes(1)))
    func freshCaptureHasHeaderAndOwnerOnlyPermissions() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("fresh.pcap")
        let sink = try await PCAPFileSink.create(path: path.path)
        try await sink.close()

        #expect(try Data(contentsOf: path) == header)
        let attributes = try FileManager.default.attributesOfItem(atPath: path.path)
        #expect(attributes[.type] as? FileAttributeType == .typeRegular)
        let mode = try #require(attributes[.posixPermissions] as? NSNumber).intValue
        // A caller's more restrictive umask is preserved; no group/other or executable bits are granted.
        #expect(mode & ~0o600 == 0)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [0o600, 0o644])
    func existingFilesAndHardLinksAreUnchanged(mode: Int) async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let original = directory.appendingPathComponent("sentinel")
        let alias = directory.appendingPathComponent("alias.pcap")
        let sentinel = Data("existing file must survive".utf8)
        try sentinel.write(to: original)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: original.path)
        try FileManager.default.linkItem(at: original, to: alias)

        await expectRejected(original.path)
        await expectRejected(alias.path)

        for path in [original, alias] {
            #expect(try Data(contentsOf: path) == sentinel)
            #expect(try permissions(path) == mode)
        }
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func finalSymlinkIsRefusedWithoutTouchingTarget(dangling: Bool) async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target")
        let link = directory.appendingPathComponent("capture.pcap")
        let sentinel = Data("symlink target must survive".utf8)
        if !dangling {
            try sentinel.write(to: target)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: target.path)
        }
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        await expectRejected(link.path)

        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == target.path)
        if dangling {
            #expect(!FileManager.default.fileExists(atPath: target.path))
        } else {
            #expect(try Data(contentsOf: target) == sentinel)
            #expect(try permissions(target) == 0o644)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func directoriesAndFIFOsAreRefusedWithoutOpeningThemForOutput() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fifo = directory.appendingPathComponent("capture.fifo")
        #expect(fifo.path.withCString { mkfifo($0, 0o600) } == 0)
        // Keep a reader present so a regression to a blocking FIFO open cannot hang the test runner.
        let keeper = fifo.path.withCString { open($0, O_RDWR | O_NONBLOCK) }
        try #require(keeper >= 0)
        defer { _ = close(keeper) }

        await expectRejected(directory.path)
        await expectRejected(fifo.path)

        var information = stat()
        #expect(fifo.path.withCString { lstat($0, &information) } == 0)
        #expect(information.st_mode & mode_t(S_IFMT) == mode_t(S_IFIFO))
        var bytes = [UInt8](repeating: 0, count: 32)
        let count = bytes.withUnsafeMutableBytes { read(keeper, $0.baseAddress, $0.count) }
        let readError = errno
        #expect(count == -1)
        #expect(readError == EAGAIN || readError == EWOULDBLOCK)
    }

    @Test(.timeLimit(.minutes(1)))
    func unixSocketIsRefusedWithoutReplacingIt() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let socketPath = directory.appendingPathComponent("capture.sock")
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .bind(unixDomainSocketPath: socketPath.path).get()
        do {
            await expectRejected(socketPath.path)
            let type = try FileManager.default.attributesOfItem(atPath: socketPath.path)[.type] as? FileAttributeType
            #expect(type == .typeSocket)
            #expect(channel.isActive)
            try await channel.close().get()
        } catch {
            try? await channel.close().get()
            throw error
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func invalidPathsAndMissingParentCreateNoCollateralFiles() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let prefix = directory.appendingPathComponent("prefix.pcap").path
        let invalid = [
            "", "/", directory.path + "/", directory.path + "/.", directory.path + "/..",
            prefix + "\0ignored", directory.appendingPathComponent("missing/child.pcap").path,
        ]
        for path in invalid { await expectRejected(path) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
    }

    @Test(.timeLimit(.minutes(1)))
    func relativeUnicodePathsAndSymlinkedParentsWork() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let parentLink = directory.appendingPathComponent("parent-link")
        let realParent = directory.appendingPathComponent("real parent")
        try FileManager.default.createDirectory(at: realParent, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(at: parentLink, withDestinationURL: realParent)
        let destinations = [
            realParent.appendingPathComponent("capture space.pcap"),
            parentLink.appendingPathComponent("réseau IPv6.pcap"),
        ]
        for destination in destinations {
            // Traverse to the root from the current directory without changing process-wide cwd.
            let depth = FileManager.default.currentDirectoryPath.split(separator: "/").count
            let relative = String(repeating: "../", count: depth) + destination.path.dropFirst()
            let sink = try await PCAPFileSink.create(path: relative)
            try await sink.close()
            #expect(try Data(contentsOf: destination) == header)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func concurrentCreatorsHaveExactlyOneWinner() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("contended.pcap").path
        let winners = await withTaskGroup(of: PCAPFileSink?.self, returning: [PCAPFileSink].self) { group in
            for _ in 0..<2 {
                group.addTask { try? await PCAPFileSink.create(path: path) }
            }
            var winners: [PCAPFileSink] = []
            for await result in group {
                if let result { winners.append(result) }
            }
            return winners
        }
        for sink in winners { try await sink.close() }
        #expect(winners.count == 1)
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == header)
    }

    @Test(.timeLimit(.minutes(1)))
    func replacingPathAfterCreationCannotRedirectWrites() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let original = directory.appendingPathComponent("capture.pcap")
        let retained = directory.appendingPathComponent("retained.pcap")
        let target = directory.appendingPathComponent("sentinel")
        let sentinel = Data("replacement target must survive".utf8)
        try sentinel.write(to: target)
        let sink = try await PCAPFileSink.create(path: original.path)
        do {
            try FileManager.default.moveItem(at: original, to: retained)
            try FileManager.default.createSymbolicLink(at: original, withDestinationURL: target)
            let payload: [UInt8] = [0x12, 0x34, 0x56, 0x78]
            sink.write(buffer: ByteBuffer(bytes: payload))
            try await sink.close()
            #expect(try Data(contentsOf: retained) == header + Data(payload))
            #expect(try Data(contentsOf: target) == sentinel)
            #expect(try FileManager.default.destinationOfSymbolicLink(atPath: original.path) == target.path)
        } catch {
            try? await sink.close()
            throw error
        }
    }

    private var header: Data { Data(NIOWritePCAPHandler.pcapFileHeader.readableBytesView) }

    private func temporaryDirectory() throws -> URL {
        // The short path also fits UNIX-domain socket limits; /tmp may itself be a valid parent symlink.
        let path = URL(fileURLWithPath: "/tmp/bgpls-pcap-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return path
    }

    private func permissions(_ path: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: path.path)
        return try #require(attributes[.posixPermissions] as? NSNumber).intValue
    }

    private func expectRejected(_ path: String, sourceLocation: SourceLocation = #_sourceLocation) async {
        await #expect(throws: (any Error).self, sourceLocation: sourceLocation) {
            let unexpected = try await PCAPFileSink.create(path: path)
            try await unexpected.close()
        }
    }
}
