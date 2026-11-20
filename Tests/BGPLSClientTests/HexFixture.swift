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

enum HexFixture {
    /// Parses space-separated hex bytes into a `ByteBuffer`.
    static func buffer(_ hex: String) -> ByteBuffer {
        let bytes: [UInt8] = hex.split(whereSeparator: { $0.isWhitespace }).compactMap {
            UInt8($0, radix: 16)
        }
        return ByteBuffer(bytes: bytes)
    }
}
