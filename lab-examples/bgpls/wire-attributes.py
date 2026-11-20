#!/usr/bin/env python3
"""Independent type-29 audit for complete NIO captures, without Swift decoding.

Identity, TCP and BGP framing reuse the existing strict wire audit. Attribute
interpretation is deliberately implemented here in Python: comparison with a
Swift replay must not use the client decoder as its own expected-value oracle.
This is a bounded lab qualifier, not a general BGP recovery implementation.
"""

import argparse
import collections
import copy
import importlib.util
import json
import math
from pathlib import Path
import struct


SPEC = importlib.util.spec_from_file_location("bgpls_attribute_topology", Path(__file__).with_name("wire-topology.py"))
WIRE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WIRE)
WireError = WIRE.WireError

FIELDS = {
    "node": ("name",),
    "link": ("igpMetric", "maximumLinkBandwidth", "maximumReservableBandwidth", "unreservedBandwidth"),
    "prefix": ("metric",),
    "unknown": (),
}
TYPES = {1026: ("node", "name"), 1095: ("link", "igpMetric"), 1155: ("prefix", "metric"),
         1089: ("link", "maximumLinkBandwidth"), 1090: ("link", "maximumReservableBandwidth"),
         1091: ("link", "unreservedBandwidth")}


def context(kind):
    return {1: "node", 2: "link", 3: "prefix", 4: "prefix"}.get(kind, "unknown")


def issue(disposition, category, attribute_index, *, tlv=None, original=b"",
          tlv_index=None, tlv_type=None, byte_offset=None):
    if tlv is not None:
        tlv_index, tlv_type, byte_offset = tlv["index"], tlv["type"], tlv["byteOffset"]
        value = bytes.fromhex(tlv["valueHex"])
        original = struct.pack("!HH", tlv_type, len(value)) + value
    return {"disposition": disposition, "category": category, "attributeIndex": attribute_index,
            "tlvIndex": tlv_index, "tlvType": tlv_type, "byteOffset": byte_offset,
            "originalHex": original.hex()}


def frame(value, attribute_index):
    """Retain complete TLVs and the exact fatal remainder, without salvage."""
    offset, result = 0, []
    while offset < len(value):
        remainder = value[offset:]
        kind = int.from_bytes(remainder[:2], "big") if len(remainder) >= 2 else None
        if len(remainder) < 4 or int.from_bytes(remainder[2:4], "big") > len(remainder) - 4:
            return result, issue("attributeDiscarded", "malformedFraming", attribute_index,
                                 tlv_index=len(result), tlv_type=kind, byte_offset=offset, original=remainder)
        size = int.from_bytes(remainder[2:4], "big")
        result.append({"index": len(result), "byteOffset": offset, "type": kind,
                       "valueHex": remainder[4:4 + size].hex()})
        offset += 4 + size
    return result, None


def path_attributes(body):
    reader = WIRE.Reader(body)
    reader.take(reader.integer(2))
    attributes = WIRE.Reader(reader.take(reader.integer(2)))
    result = []
    while attributes.remaining():
        flags, kind = attributes.integer(1), attributes.integer(1)
        value = attributes.take(attributes.integer(2 if flags & 16 else 1))
        result.append((flags, kind, value))
    return result


def project(kind, value):
    """Return a typed value or the bounded consumer-policy rejection reason."""
    if kind == 1026:
        if len(value) > 255:
            return None, "invalidLength"
        if any(octet > 127 for octet in value):
            return None, "invalidASCII"
        return value.decode("ascii"), None
    if kind == 1095:
        if not 1 <= len(value) <= 3:
            return None, "invalidLength"
        return (value[0] & 63 if len(value) == 1 else int.from_bytes(value, "big")), None
    if kind == 1155:
        return ((int.from_bytes(value, "big"), None) if len(value) == 4 else (None, "invalidLength"))
    if len(value) != (32 if kind == 1091 else 4):
        return None, "invalidLength"
    numbers = list(struct.unpack("!" + "f" * (len(value) // 4), value))
    # IEEE negative zero is a valid nonnegative advertisement. Keep its sign
    # in evidence even though semantic comparison treats it as ordinary zero.
    if any(not math.isfinite(number) or number < 0 for number in numbers):
        return None, "invalidValue"
    return (numbers if kind == 1091 else numbers[0]), None


def decode_attributes(attributes, contexts):
    evidence, framing_failures = [], []
    projections = {name: dict.fromkeys(fields) for name, fields in FIELDS.items()}
    for index, (flags, kind, value) in enumerate(attributes):
        if kind != 29:
            continue
        tlvs, failure = frame(value, index)
        evidence.append({"attributeIndex": index, "flags": flags, "valueHex": value.hex(), "tlvs": tlvs})
        framing_failures.append(failure)
    if not evidence:
        return "absent", projections, evidence, []
    first, issues = evidence[0], []
    index, value = first["attributeIndex"], bytes.fromhex(first["valueHex"])
    availability = "present"
    if first["flags"] & 0xc0 != 0x80:
        issues.append(issue("attributeDiscarded", "invalidFlags", index, original=value))
    elif not value:
        issues.append(issue("attributeDiscarded", "emptyAttribute", index))
    elif framing_failures[0] is not None:
        issues.append(framing_failures[0])
    else:
        groups = collections.defaultdict(list)
        for item in first["tlvs"]:
            groups[item["type"]].append(item)
        for kind, members in groups.items():
            if kind not in TYPES or TYPES[kind][0] not in contexts:
                continue
            initial, *duplicates = members
            conflict = False
            for duplicate in duplicates:
                identical = duplicate["valueHex"] == initial["valueHex"]
                conflict |= not identical
                issues.append(issue("acceptedWithWarning" if identical else "projectionRejected",
                                    "duplicateTLV" if identical else "conflictingTLV", index, tlv=duplicate))
            if conflict:
                continue
            decoded, rejection = project(kind, bytes.fromhex(initial["valueHex"]))
            if rejection:
                issues.append(issue("projectionRejected", rejection, index, tlv=initial))
            else:
                object_context, field = TYPES[kind]
                projections[object_context][field] = decoded
        issues.sort(key=lambda diagnostic: diagnostic["tlvIndex"])
    if issues and issues[0]["disposition"] == "attributeDiscarded":
        availability = "discarded"
    # A duplicate is never a fallback, even when the first occurrence is bad.
    for excluded in evidence[1:]:
        issues.append(issue("acceptedWithWarning", "duplicateAttribute", excluded["attributeIndex"],
                            original=bytes.fromhex(excluded["valueHex"])))
    return availability, projections, evidence, issues


def decode_update(body):
    """Decode one body to JSON-compatible events and UPDATE-level diagnostics.

    The complete UPDATE is framed before any event is exposed. Unknown NLRIs
    remain observations; the capture replay does not install them in its RIB.
    """
    WIRE.require(len(body) <= 4096 - 19, "UPDATE exceeds the qualified BGP message limit")
    identity_events = WIRE.update_events(body)
    contexts = {context(record["nlri_type"]) for operation, record in identity_events if operation == "upsert"}
    availability, projections, evidence, issues = decode_attributes(path_attributes(body), contexts)
    result = []
    for operation, record in identity_events:
        event = {"operation": operation, "key": record["key"], "display": record["display"]}
        if operation == "upsert":
            event.update(availability=availability, attributes=projections[context(record["nlri_type"])],
                         evidence=evidence, issues=issues)
        # Keep the public value-shaped result independent between siblings.
        result.append(copy.deepcopy(event))
    # Withdrawals and End-of-RIB can carry attribute issues without an upsert.
    # Retain that observation independently rather than inferring it from records.
    return {"events": result, "attributeDiagnostics": issues, "attributeEvidence": evidence}


def audit_capture(path):
    """Audit the incoming producer identified by the collector's active open."""
    path = Path(path)
    capture = WIRE.parse_capture(path)
    try:
        packets = list(WIRE.PCAP.tcp_packets(path.read_bytes()))
    except WIRE.PCAP.CaptureError as error:
        raise WireError(str(error)) from error
    active = {packet["stream_key"] for packet in packets if packet["flags"] & 0x12 == 2}
    WIRE.require(len(active) == 1, "expected one collector active-open TCP direction")
    forward = next(iter(active))
    reverse = (forward[0], forward[3], forward[4], forward[1], forward[2])
    flows = {packet["stream_key"]: packet["stream"] for packet in packets}
    WIRE.require(set(flows) == {forward, reverse}, "expected exactly two reciprocal TCP directions")
    incoming = flows[reverse]
    WIRE.require(capture["events"] and all(event["stream"] == incoming for event in capture["events"]),
                 "expected topology only in the incoming producer direction")
    updates, state = [], {}
    availability, projections, issues = collections.Counter(), collections.Counter(), collections.Counter()
    kinds, operations = set(), collections.Counter()
    for update in capture["updates"]:
        if update["stream"] != incoming:
            continue
        body = bytes.fromhex(update["message_hex"])[19:]
        observation = decode_update(body)
        events = observation["events"]
        updates.append({"bodyHex": body.hex(), "events": events, "packet": update["packet"],
                        "timestampUS": update["timestamp_us"],
                        "attributeDiagnostics": observation["attributeDiagnostics"]})
        for event in events:
            operations[event["operation"]] += 1
            if event["operation"] == "withdraw":
                state.pop(event["key"], None)
                continue
            if not event["key"].startswith("unknown:"):
                state[event["key"]] = event
            availability[event["availability"]] += 1
            projections.update(field for field, value in event["attributes"].items() if value is not None)
        # Count attribute diagnostics/encodings once per UPDATE, not once per
        # advertisement, because one observation can apply to many objects.
        kinds.update(tlv["type"] for attribute in observation["attributeEvidence"] for tlv in attribute["tlvs"])
        issues.update(item["category"] for item in observation["attributeDiagnostics"])
    return {"schema": 2, "producerStream": incoming, "updates": updates,
            "finalRecords": [state[key] for key in sorted(state)],
            "coverage": {"updates": len(updates), "upserts": operations["upsert"],
                         "withdrawals": operations["withdraw"], "availability": dict(availability),
                         "projections": dict(projections), "tlvTypes": sorted(kinds), "issues": dict(issues)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="complete NIO synthetic capture")
    args = parser.parse_args()
    try:
        print(json.dumps(audit_capture(args.pcap), indent=2, sort_keys=True, allow_nan=False))
    except (OSError, WireError) as error:
        parser.exit(1, f"wire-attributes: {error}\n")


if __name__ == "__main__":
    main()
