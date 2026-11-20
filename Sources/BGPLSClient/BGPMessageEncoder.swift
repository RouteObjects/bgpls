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

/// Encodes ``BGPMessage`` values to the wire format.
public final class BGPMessageEncoder: MessageToByteEncoder, Sendable {
    public typealias OutboundIn = BGPMessage

    public init() {}

    public func encode(data: BGPMessage, out: inout ByteBuffer) throws {
        try BGPMessageCodec.encode(data, into: &out)
    }
}
