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

/// A complete node observation. Attributes and retained evidence are not topology identity.
public struct BGPLSNodeRecord: Sendable, Hashable {
    public var nlri: BGPLSNodeNLRI
    public var attributes: BGPLSNodeAttributes
    public var observation: BGPLSAttributeObservation

    public init(
        nlri: BGPLSNodeNLRI, attributes: BGPLSNodeAttributes = .init(),
        observation: BGPLSAttributeObservation = .init()
    ) {
        self.nlri = nlri
        self.attributes = attributes
        self.observation = observation
    }
}

/// A complete link observation; advertised bandwidth is not measured utilization.
public struct BGPLSLinkRecord: Sendable, Hashable {
    public var nlri: BGPLSLinkNLRI
    public var attributes: BGPLSLinkAttributes
    public var observation: BGPLSAttributeObservation

    public init(
        nlri: BGPLSLinkNLRI, attributes: BGPLSLinkAttributes = .init(),
        observation: BGPLSAttributeObservation = .init()
    ) {
        self.nlri = nlri
        self.attributes = attributes
        self.observation = observation
    }
}

/// A complete prefix observation, retaining family-typed canonical reachability.
public struct BGPLSPrefixRecord: Sendable, Hashable {
    public var nlri: AnyBGPLSPrefixNLRI
    public var attributes: BGPLSPrefixAttributes
    public var observation: BGPLSAttributeObservation

    public init(
        nlri: AnyBGPLSPrefixNLRI, attributes: BGPLSPrefixAttributes = .init(),
        observation: BGPLSAttributeObservation = .init()
    ) {
        self.nlri = nlri
        self.attributes = attributes
        self.observation = observation
    }
}

/// Complete advertisement payload for RIB installation and watch-event replay.
///
/// Equality and hashing include retained evidence. Equal RIB identity keys need not
/// imply equal records. Unknown NLRIs remain observable but are not installed in the
/// supported node, link, or prefix dictionaries.
public enum BGPLSRecord: Sendable, Hashable {
    case node(BGPLSNodeRecord)
    case link(BGPLSLinkRecord)
    case prefix(BGPLSPrefixRecord)
    case unknown(BGPLSNLRI, BGPLSAttributeObservation)

    /// Constructs an advertisement without a BGP-LS path attribute.
    public init(nlri: BGPLSNLRI) {
        self.init(nlri: nlri, decoded: BGPLSAttributeDecoder.decode(pathAttributes: []))
    }

    init(nlri: BGPLSNLRI, decoded: BGPLSAttributeDecoder.DecodedAttributes) {
        switch nlri {
        case .node(let node):
            self = .node(.init(nlri: node, attributes: decoded.node, observation: decoded.observation))
        case .link(let link):
            self = .link(.init(nlri: link, attributes: decoded.link, observation: decoded.observation))
        case .ipv4Prefix(let prefix):
            self = .prefix(.init(nlri: .v4(prefix), attributes: decoded.prefix, observation: decoded.observation))
        case .ipv6Prefix(let prefix):
            self = .prefix(.init(nlri: .v6(prefix), attributes: decoded.prefix, observation: decoded.observation))
        case .unknown:
            self = .unknown(nlri, decoded.observation)
        }
    }

    /// Identity-bearing NLRI, independent of advertised attributes.
    public var nlri: BGPLSNLRI {
        switch self {
        case .node(let record): .node(record.nlri)
        case .link(let record): .link(record.nlri)
        case .prefix(let record):
            switch record.nlri {
            case .v4(let prefix): .ipv4Prefix(prefix)
            case .v6(let prefix): .ipv6Prefix(prefix)
            }
        case .unknown(let nlri, _): nlri
        }
    }

    /// Original attribute evidence shared by all advertisements in this UPDATE.
    public var observation: BGPLSAttributeObservation {
        switch self {
        case .node(let record): record.observation
        case .link(let record): record.observation
        case .prefix(let record): record.observation
        case .unknown(_, let observation): observation
        }
    }
}
