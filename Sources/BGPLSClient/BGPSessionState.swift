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

/// Subset of the BGP finite-state machine (RFC 4271) used by this client.
public enum BGPSessionState: String, Sendable, Hashable, CustomStringConvertible {
    case idle
    case connect
    case active
    case openSent
    case openConfirm
    case established
    case stopped

    public var description: String { rawValue }
}
