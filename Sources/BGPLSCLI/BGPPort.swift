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

import CIDR
import CIDRArgumentParser

/// `CIDR.Port` for CLI options. Files that also `import Foundation` cannot spell `Port`
/// without clashing with `Foundation.Port` (NSPort).
///
/// **Future (Swift 6.4+):** drop this file and the alias; disambiguate with a module selector
/// (WWDC26), e.g. `CIDR::Port` vs `Foundation::Port`, on `@Option` / `makeIPv4Configuration`.
package typealias BGPPort = Port
