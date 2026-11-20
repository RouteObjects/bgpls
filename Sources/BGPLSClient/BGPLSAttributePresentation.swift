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

extension BGPLSRecord {
    /// Deterministic, single-line attribute fields for opt-in CLI presentation.
    ///
    /// Names are escaped before presentation; raw evidence and the original ASCII string
    /// remain unchanged in the record. Bandwidth is advertised capacity, not utilization.
    public var attributeSummary: String {
        let fields: [String]
        switch self {
        case .node(let record):
            fields = [
                "attributes=\(record.observation.availability.rawValue)",
                "name=\(record.attributes.name.map(Self.quotedName) ?? "unavailable")",
            ]
        case .link(let record):
            fields = [
                "attributes=\(record.observation.availability.rawValue)",
                "igp-metric=\(record.attributes.igpMetric.map(String.init) ?? "unavailable")",
                "maximum-link-bandwidth=\(Self.bandwidth(record.attributes.maximumLinkBandwidth))",
                "maximum-reservable-bandwidth=\(Self.bandwidth(record.attributes.maximumReservableBandwidth))",
                "unreserved-bandwidth=\(Self.unreserved(record.attributes.unreservedBandwidth))",
            ]
        case .prefix(let record):
            fields = [
                "attributes=\(record.observation.availability.rawValue)",
                "prefix-metric=\(record.attributes.metric.map(String.init) ?? "unavailable")",
            ]
        case .unknown(_, let observation):
            fields = ["attributes=\(observation.availability.rawValue)"]
        }
        return fields.joined(separator: " ")
    }

    private static func bandwidth(_ value: BGPLSBandwidth?) -> String {
        guard let value else { return "unavailable" }
        let bytes = value.bytesPerSecond == 0 ? 0 : Double(value.bytesPerSecond)
        let bits = value.bitsPerSecond == 0 ? 0 : value.bitsPerSecond
        return "\(bytes)B/s(\(bits)bit/s)"
    }

    private static func unreserved(_ value: BGPLSUnreservedBandwidth?) -> String {
        guard let value else { return "unavailable" }
        return "["
            + value.values.enumerated().map { "\($0.offset):\(bandwidth($0.element))" }.joined(separator: ",")
            + "]"
    }

    private static func quotedName(_ value: String) -> String {
        var escaped = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0: escaped += "\\0"
            case 9: escaped += "\\t"
            case 10: escaped += "\\n"
            case 13: escaped += "\\r"
            case 34: escaped += "\\\""
            case 92: escaped += "\\\\"
            case 32...126: escaped.unicodeScalars.append(scalar)
            default: escaped += "\\u{\(String(scalar.value, radix: 16))}"
            }
        }
        escaped += "\""
        return escaped
    }
}
