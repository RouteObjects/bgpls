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

//  Parsing belongs to the CLI adapter; the protocol engine remains independent
// of ArgumentParser. Its lossless witnesses preserve BGPIdentifier's strict grammar.
// Same-package conformances cannot use @retroactive, even across separate targets.
extension BGPIdentifier: ExpressibleByArgument {
    /// Canonical dotted-quad presentation for a defaulted CLI option.
    public var defaultValueDescription: String {
        //  RawRepresentable's conditional witness renders the integer storage;
        // CLI help must show the same dotted-quad grammar accepted by the lossless parser.
        description
    }
}
