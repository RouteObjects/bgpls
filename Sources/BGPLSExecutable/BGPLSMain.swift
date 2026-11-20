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

import BGPLSCLI

@main
enum BGPLSMain {
    static func main() async {
        // Delegate to the package-visible command; keep logic in BGPLSCLI for tests.
        await BGPLSCommand.main()
    }
}
