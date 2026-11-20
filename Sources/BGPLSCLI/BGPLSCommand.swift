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
import BGPLSClient
import CIDR
import CIDRArgumentParser
import Foundation
import UnixSignals

/// Root command for the `bgpls` tool.
package struct BGPLSCommand: AsyncParsableCommand {
    package static let version = "0.1.0"

    package static let configuration = CommandConfiguration(
        commandName: "bgpls",
        abstract: "Receive-only BGP-LS collector (RFC 9552) and reference CLI.",
        discussion: """
            Connects outbound to a BGP speaker exporting link-state. The peer must be an IP literal, \
            not a DNS name. Does not originate BGP-LS. Foreground `run` owns the session and RIB; use \
            --watch for changes and --dump-rib for the final topology. There is no control socket; \
            `show` and `stop` print usage guidance rather than controlling another process.
            """,
        version: version,
        subcommands: [RunCommand.self, ShowCommand.self, StopCommand.self],
        defaultSubcommand: nil
    )

    package init() {}
}

// MARK: - run

extension BGPLSCommand {
    /// Blocking session: connect outbound and hold until cancelled or error.
    package struct RunCommand: AsyncParsableCommand {
        package static let configuration = CommandConfiguration(
            commandName: "run",
            abstract: "Connect outbound to a BGP-LS speaker and hold the session (foreground).",
            discussion: """
                SIGINT (Ctrl-C) and SIGTERM stop the session cleanly, finish live output, and print \
                one RIB summary. Add --dump-rib for the complete final RIB. Their shell exit \
                statuses are 130 and 143, respectively.
                """
        )

        @Option(name: .long, help: "BGP peer IPv4 or IPv6 host address. DNS and scope zones are not used.")
        package var peer: AnyIPAddress

        @Option(name: .long, help: "BGP peer TCP port (IANA BGP).")
        package var port: BGPPort = BGPPort(179)

        @Option(name: .long, help: "Local AS number (asplain).")
        package var localAs: AutonomousSystemNumber

        @Option(name: .long, help: "Peer AS number (asplain).")
        package var peerAs: AutonomousSystemNumber

        @Option(
            name: .long,
            help: "Non-zero 32-bit BGP identifier in dotted-quad form, independent of the transport address.")
        package var bgpIdentifier: BGPIdentifier

        @Option(
            name: .long,
            help:
                "Local bind host address, matching the peer's IP family. Omit to let the stack pick the source address."
        )
        package var localAddress: AnyIPAddress?

        @Option(
            name: .long,
            help: "Hold time offered in OPEN (0 or 3–65535 seconds). Zero disables negotiated hold/keepalive timers.")
        package var holdTime: UInt16 = 90

        @Option(
            name: .long,
            help: """
                Record the BGP TCP session in a new .pcap file in a trusted directory. Existing paths are refused.
                In Wireshark, filter on the configured peer port.
                """
        )
        package var pcap: String?

        @Flag(
            name: .long,
            help: """
                Record the session in the current directory using a UTC timestamp, peer, port, and UUID filename.
                Use a trusted directory. Cannot be combined with --pcap.
                """
        )
        package var pcapAuto: Bool = false

        @Flag(name: .long, help: "Log capped hex dumps of BGP UPDATE bodies to stderr.")
        var logUpdates: Bool = false

        @Flag(
            name: .long,
            help: "Print RIBDiff events (AsyncStream): catch-up snapshot then live upsert/withdraw."
        )
        var watch: Bool = false

        @Flag(
            name: .long,
            help: "Include typed BGP-LS attributes and explicit bandwidth units in watch and --dump-rib output.")
        package var showAttributes: Bool = false

        @Flag(name: .long, help: "Print the complete final RIB on termination instead of only counts.")
        package var dumpRIB: Bool = false

        package init() {}

        package mutating func validate() throws {
            try PCAPDestination.validate(explicitPath: pcap, automatic: pcapAuto)
            _ = try sessionConfiguration()
        }

        package mutating func run() async throws {
            try PCAPDestination.validate(explicitPath: pcap, automatic: pcapAuto)
            let configuration = try sessionConfiguration()
            // Await registration before connection work so an early SIGINT/SIGTERM is not
            // lost between starting the command and establishing the BGP session.
            let signals = await UnixSignalsSequence(trapping: .sigint, .sigterm)
            //  Erase the address family only at the CLI boundary. Both cases use
            // the same generic lifecycle so transport choice cannot diverge in teardown.
            switch configuration {
            case .v4(let configuration):
                try await runSession(configuration: configuration, signals: signals)
            case .v6(let configuration):
                try await runSession(configuration: configuration, signals: signals)
            }
        }

        private func runSession<Family: IPAddressFamily>(
            configuration: BGPSessionConfiguration<Family>,
            signals: UnixSignalsSequence
        ) async throws {
            let capture = try PCAPDestination.select(
                explicitPath: pcap, automatic: pcapAuto, peer: configuration.peer,
                date: Date(), uuid: UUID(), workingDirectory: FileManager.default.currentDirectoryPath
            )
            if let message = capture?.selectionMessage {
                FileHandle.standardError.write(Data(message.utf8))
            }
            let connectTS = Date().formatted(
                .iso8601.dateTimeSeparator(.standard).time(includingFractionalSeconds: true)
            )
            FileHandle.standardError.write(
                Data(
                    """
                    bgpls: \(connectTS) outbound connect to \(configuration.peer) \
                    local-as \(configuration.localAS) peer-as \(configuration.peerAS) \
                    bgp-identifier \(configuration.bgpIdentifier)\
                    \(configuration.localAddress.map { " local-address \($0)" } ?? "")\n
                    """.utf8
                )
            )

            let session = BGPSession(configuration: configuration)
            let shouldShowAttributes = showAttributes

            // Subscribe before run so initial UPDATEs are not missed (in-process AsyncStream).
            let watchTask: Task<Void, Never>?
            if watch {
                let stream = await session.ribChanges(includeCatchUpSnapshot: true)
                watchTask = Task {
                    for await diff in stream {
                        let ts = Date().formatted(
                            .iso8601.dateTimeSeparator(.standard).time(
                                includingFractionalSeconds: true
                            )
                        )
                        FileHandle.standardError.write(
                            Data("bgpls: \(ts) \(diff.watchLine(showAttributes: shouldShowAttributes))\n".utf8)
                        )
                    }
                }
            } else {
                watchTask = nil
            }

            let pcapPath = capture?.path
            let shouldLogUpdates = logUpdates
            let sessionResult: Result<ForegroundSessionTermination, any Error>
            do {
                let termination = try await ForegroundSessionCoordinator.run(
                    signals: signals,
                    operation: {
                        try await session.run(
                            pcapPath: pcapPath,
                            logUpdates: shouldLogUpdates,
                            onStateChange: { state in
                                // The single final report is the terminal CLI output.
                                if state == .stopped { return }
                                let ts = Date().formatted(
                                    .iso8601.dateTimeSeparator(.standard).time(
                                        includingFractionalSeconds: true
                                    )
                                )
                                let line: String
                                switch state {
                                case .established:
                                    line =
                                        "bgpls: \(ts) state Established — holding session "
                                        + "(Ctrl-C or SIGTERM to stop)\n"
                                default:
                                    line = "bgpls: \(ts) state \(state)\n"
                                }
                                FileHandle.standardError.write(Data(line.utf8))
                            }
                        )
                    },
                    onSignal: { signal in
                        FileHandle.standardError.write(
                            Data("bgpls: \(signal) — stopping session…\n".utf8)
                        )
                        try? FileHandle.standardError.synchronize()
                    },
                    stop: {
                        await session.stop()
                    }
                )
                sessionResult = .success(termination)
            } catch {
                sessionResult = .failure(error)
            }

            // Session teardown finishes the RIB stream after draining ordered UPDATEs;
            // await that natural completion so buffered final diffs precede the final report.
            await watchTask?.value

            // All outcomes report once after cleanup; summary mode never renders topology records.
            await Self.printRIBFinal(
                session: session, result: sessionResult, dumpRIB: dumpRIB, showAttributes: showAttributes
            )

            switch sessionResult {
            case .success(.operationCompleted):
                return

            case .success(.signal(let signal)):
                guard let exitCode = Self.shellExitCode(for: signal) else {
                    throw ExitCode.failure
                }
                throw exitCode

            case .failure(let error) where error is CancellationError:
                throw ExitCode(128 + UnixSignal.sigint.rawValue)

            case .failure(is BGPLSClientError):
                throw ExitCode.failure

            case .failure(let error):
                throw error
            }
        }

        /// Returns the conventional shell status for the signals handled by `bgpls run`.
        package static func shellExitCode(for signal: UnixSignal) -> ExitCode? {
            guard signal == .sigint || signal == .sigterm else { return nil }
            return ExitCode(128 + signal.rawValue)
        }

        /// Single final report after process teardown, with full topology rendering only on request.
        private static func printRIBFinal<Family: IPAddressFamily>(
            session: BGPSession<Family>, result: Result<ForegroundSessionTermination, any Error>,
            dumpRIB: Bool, showAttributes: Bool
        ) async {
            let ts = Date().formatted(
                .iso8601.dateTimeSeparator(.standard).time(includingFractionalSeconds: true)
            )
            let report = await terminationReport(
                result: result, timestamp: ts, dumpRIB: dumpRIB,
                summaryLine: { await session.ribSummaryLine() },
                fullDump: { await session.ribDump(topic: "summary", showAttributes: showAttributes) }
            )
            FileHandle.standardError.write(Data(report.utf8))
            try? FileHandle.standardError.synchronize()
        }

        /// Constructs terminal text independently of stderr, evaluating only the selected RIB projection.
        package static func terminationReport(
            result: Result<ForegroundSessionTermination, any Error>, timestamp: String, dumpRIB: Bool,
            summaryLine: () async -> String, fullDump: () async -> String
        ) async -> String {
            let preface: String
            switch result {
            case .success(.operationCompleted): preface = "session ended"
            case .success(.signal(let signal)):
                preface =
                    shellExitCode(for: signal) == nil
                    ? "unsupported termination signal \(signal)" : "\(signal) — session stopped"
            case .failure(let error) where error is CancellationError: preface = "cancelled"
            case .failure(let error): preface = "\(error)"
            }
            let status = "bgpls: \(timestamp) \(preface)\n"
            // Lazy projections avoid snapshots, sorting, and full-dump allocation for quiet termination.
            if dumpRIB {
                return status + "bgpls: \(timestamp) RIB final\n\(await fullDump())\n"
            }
            return status + "bgpls: \(timestamp) RIB summary \(await summaryLine())\n"
        }

        package enum TransportConfiguration {
            case v4(BGPSessionConfiguration<AF.V4>)
            case v6(BGPSessionConfiguration<AF.V6>)
        }

        /// Checks the family relationship before constructing a typed session.
        package func sessionConfiguration() throws -> TransportConfiguration {
            switch (peer, localAddress) {
            case (.v4(let peer), .none):
                return .v4(try makeConfiguration(peer: peer, localAddress: nil))
            case (.v4(let peer), .some(.v4(let local))):
                return .v4(try makeConfiguration(peer: peer, localAddress: local))
            case (.v6(let peer), .none):
                return .v6(try makeConfiguration(peer: peer, localAddress: nil))
            case (.v6(let peer), .some(.v6(let local))):
                return .v6(try makeConfiguration(peer: peer, localAddress: local))
            default:
                throw ValidationError("Local bind address must use the same IP family as the peer.")
            }
        }

        /// Reuses core validation before any signal registration, connection, or PCAP creation.
        private func makeConfiguration<Family: IPAddressFamily>(
            peer: IPAddress<Family>,
            localAddress: IPAddress<Family>?
        ) throws -> BGPSessionConfiguration<Family> {
            let configuration = BGPSessionConfiguration(
                peer: .tcp(address: peer, port: port.rawValue),
                localAS: localAs,
                peerAS: peerAs,
                bgpIdentifier: bgpIdentifier,
                localAddress: localAddress,
                holdTimeSeconds: holdTime
            )
            do {
                try configuration.validate()
            } catch {
                throw ValidationError(String(describing: error))
            }
            return configuration
        }
    }
}

// MARK: - show

extension BGPLSCommand {
    /// Explains how to view the foreground session's RIB; there is no cross-process control service.
    package struct ShowCommand: AsyncParsableCommand {
        package static let configuration = CommandConfiguration(
            commandName: "show",
            abstract: "Explain how to display the foreground session RIB (no control socket)."
        )

        @Argument(help: "Requested topic: summary | session | nodes | links | prefixes (guidance only)")
        var topic: String = "summary"

        package init() {}

        package mutating func run() async throws {
            let message = """
                bgpls show \(topic): no live session in this process (no control socket).
                Use `bgpls run --dump-rib` (optionally --show-attributes); on exit it prints a RIB final dump \
                (nodes/links/prefixes). Use --watch to see changes while it runs.
                """
            print(message)
        }
    }
}

// MARK: - stop

extension BGPLSCommand {
    /// Explains how to signal a foreground session; it does not stop another process.
    package struct StopCommand: AsyncParsableCommand {
        package static let configuration = CommandConfiguration(
            commandName: "stop",
            abstract: "Explain how to stop a foreground session (no control socket)."
        )

        package init() {}

        package mutating func run() async throws {
            print(
                """
                bgpls stop: no control socket is available.
                Stop a foreground `bgpls run` with Ctrl-C / SIGINT or SIGTERM.
                """
            )
        }
    }
}
