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

/// Errors raised by the receive-only BGP-LS client.
public enum BGPLSClientError: Error, Sendable, Equatable, CustomStringConvertible {
    case invalidConfiguration(String)
    case notImplemented(String)
    case sessionFailed(String)
    case protocolError(String)
    /// No qualifying inbound message arrived before the active BGP Hold Timer expired.
    case holdTimerExpired
    /// A peer offered an invalid nonzero Hold Time below three seconds.
    case unacceptableHoldTime(seconds: UInt16)
    /// The peer OPEN does not advertise non-VPN BGP-LS (AFI 16388 / SAFI 71).
    case missingBGPLSCapability
    /// An UPDATE repeats MP_REACH_NLRI (14) or MP_UNREACH_NLRI (15).
    case duplicateMultiprotocolAttribute(typeCode: UInt8)
    case connectFailed(String)

    public var description: String {
        switch self {
        case .invalidConfiguration(let detail):
            return "Invalid configuration: \(detail)"
        case .notImplemented(let detail):
            return "Not implemented: \(detail)"
        case .sessionFailed(let detail):
            return "Session failed: \(detail)"
        case .protocolError(let detail):
            return "Protocol error: \(detail)"
        case .holdTimerExpired:
            return "Session failed: BGP Hold Timer expired"
        case .unacceptableHoldTime(let seconds):
            return "Protocol error: unacceptable peer Hold Time \(seconds); expected zero or at least 3 seconds"
        case .missingBGPLSCapability:
            return "Protocol error: peer does not advertise BGP-LS capability (AFI 16388 / SAFI 71)"
        case .duplicateMultiprotocolAttribute(let typeCode):
            let name: String
            switch typeCode {
            case 14: name = "MP_REACH_NLRI"
            case 15: name = "MP_UNREACH_NLRI"
            default: name = "multiprotocol type \(typeCode)"
            }
            return "Protocol error: duplicate \(name) attribute"
        case .connectFailed(let detail):
            return "Connect failed: \(detail)"
        }
    }
}
