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

import NIOCore

extension ByteBuffer {
    /// Hex dump of readable bytes for lab/debug (capped).
    func hexDump(maxBytes: Int = 256) -> String {
        let count = min(readableBytes, maxBytes)
        guard count > 0 else { return "(empty)" }
        var copy = self
        guard let bytes = copy.readBytes(length: count) else { return "(unreadable)" }
        let hex = bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
        if readableBytes > maxBytes {
            return "\(hex) … (\(readableBytes) bytes total)"
        }
        return "\(hex) (\(readableBytes) bytes)"
    }
}
