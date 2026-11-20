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

import BGPLSClient
import Testing

struct OSPFAreaIDTests {
    @Test
    func dottedQuadAndDecimal() {
        #expect(OSPFAreaID("0.0.0.0")?.rawValue == 0)
        #expect(OSPFAreaID(0).description == "0.0.0.0")
        #expect(OSPFAreaID("10.0.0.1")?.description == "10.0.0.1")
    }
}
