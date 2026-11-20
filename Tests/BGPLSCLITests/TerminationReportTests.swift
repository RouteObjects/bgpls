//===----------------------------------------------------------------------===//
//
// This source file is part of the bgpls project.
// Copyright (c) 2026 Craig A. Munro
// Licensed under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import BGPLSCLI
import BGPLSClient
import CIDR
import Testing
import UnixSignals

struct TerminationReportTests {
    @Test(arguments: Termination.allCases, [false, true])
    func summaryIsCountsOnlyWithoutEvaluatingFullDump(termination: Termination, populated: Bool) async {
        let summary = populated ? "nodes=6 links=18 prefixes=12" : "nodes=0 links=0 prefixes=0"
        var summaryCalls = 0
        var fullDumpCalls = 0
        let report = await BGPLSCommand.RunCommand.terminationReport(
            result: termination.result, timestamp: "12:34:56.789", dumpRIB: false,
            summaryLine: {
                summaryCalls += 1
                return summary
            },
            fullDump: {
                fullDumpCalls += 1
                Issue.record("Quiet termination must not render the full RIB")
                return "unexpected full dump"
            }
        )
        #expect(summaryCalls == 1)
        #expect(fullDumpCalls == 0)
        #expect(report == "bgpls: 12:34:56.789 \(termination.preface)\nbgpls: 12:34:56.789 RIB summary \(summary)\n")
        #expect(report.split(separator: "\n").count == 2)
        #expect(!report.contains("RIB final"))
    }

    @Test(arguments: Termination.allCases, [false, true])
    func optInFullDumpHasOneStatusAndNoAdditionalSummary(termination: Termination, populated: Bool) async {
        let body =
            populated
            ? "nodes=1 links=0 prefixes=0\nnode 192.0.2.1 AS not-advertised attributes=present name=\"edge\""
            : "nodes=0 links=0 prefixes=0"
        var fullDumpCalls = 0
        let report = await BGPLSCommand.RunCommand.terminationReport(
            result: termination.result, timestamp: "12:34:56.789", dumpRIB: true,
            summaryLine: {
                Issue.record("A full report must not request a second summary")
                return "unexpected summary"
            },
            fullDump: {
                fullDumpCalls += 1
                return body
            }
        )
        #expect(fullDumpCalls == 1)
        #expect(report == "bgpls: 12:34:56.789 \(termination.preface)\nbgpls: 12:34:56.789 RIB final\n\(body)\n")
        #expect(!report.contains("RIB summary"))
        #expect(report.split(separator: "\n").filter { $0.hasPrefix("bgpls:") }.count == 2)
    }

    @Test
    func newSessionProvidesEmptyCountsWithoutStartingTransport() async throws {
        let address = try #require(IPv6Address("::1"))
        let configuration = BGPSessionConfiguration(
            peer: .tcp(address: address, port: 179), localAS: AutonomousSystemNumber(65_001),
            peerAS: AutonomousSystemNumber(65_001), bgpIdentifier: try #require(BGPIdentifier("192.0.2.1"))
        )
        let session = BGPSession(configuration: configuration)
        #expect(await session.ribSummaryLine() == "nodes=0 links=0 prefixes=0")
    }

    enum Termination: CaseIterable, Sendable {
        case normal, sigint, sigterm, unsupportedSignal, cancellation, connectionFailure, protocolFailure,
            unexpectedFailure

        var result: Result<ForegroundSessionTermination, any Error> {
            switch self {
            case .normal: .success(.operationCompleted)
            case .sigint: .success(.signal(.sigint))
            case .sigterm: .success(.signal(.sigterm))
            case .unsupportedSignal: .success(.signal(.sighup))
            case .cancellation: .failure(CancellationError())
            case .connectionFailure: .failure(BGPLSClientError.connectFailed("connection refused"))
            case .protocolFailure: .failure(BGPLSClientError.protocolError("invalid frame"))
            case .unexpectedFailure: .failure(UnexpectedFailure())
            }
        }

        var preface: String {
            switch self {
            case .normal: "session ended"
            case .sigint: "SIGINT — session stopped"
            case .sigterm: "SIGTERM — session stopped"
            case .unsupportedSignal: "unsupported termination signal SIGHUP"
            case .cancellation: "cancelled"
            case .connectionFailure: "Connect failed: connection refused"
            case .protocolFailure: "Protocol error: invalid frame"
            case .unexpectedFailure: "unexpected failure"
            }
        }
    }

    private struct UnexpectedFailure: Error, CustomStringConvertible {
        var description: String { "unexpected failure" }
    }
}
