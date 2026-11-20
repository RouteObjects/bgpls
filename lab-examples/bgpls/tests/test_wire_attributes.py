#!/usr/bin/env python3
"""Independent typed-attribute oracle tests; no lab, network, or runtime calls."""

import importlib.util
import json
import math
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest import mock


DIRECTORY = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUDIT = load("bgpls_wire_attributes", DIRECTORY.parent / "wire-attributes.py")
FIXTURE = load("bgpls_wire_attribute_fixtures", DIRECTORY / "test_wire_topology.py")
tlv = FIXTURE.tlv
node = lambda: FIXTURE.nlri(1, FIXTURE.node())


def attribute(value, flags=0x90, kind=29):
    return bytes([flags, kind]) + struct.pack("!H" if flags & 16 else "!B", len(value)) + value


def body(value=None, *, nlris=None, extra=b"", flags=0x90, withdraw=False):
    objects = [node()] if nlris is None else nlris
    return FIXTURE.update(*objects, extended=True, withdraw=withdraw,
                          extra=(b"" if value is None else attribute(value, flags)) + extra)[19:]


def f32(value):
    return struct.pack("!f", value)


def session(*bodies, family=4, outgoing_body=None):
    incoming = b"".join(FIXTURE.bgp(2, value) for value in bodies)
    packets = [FIXTURE.packet(b"", 0, outbound=True, flags=2, family=family),
               FIXTURE.packet(b"", 0, flags=18, family=family),
               FIXTURE.packet(incoming, 1, family=family)]
    if outgoing_body is not None:
        packets.append(FIXTURE.packet(FIXTURE.bgp(2, outgoing_body), 1, outbound=True, family=family))
    return FIXTURE.pcap(*packets)


def retained(name):
    path = DIRECTORY.parents[2] / "Tests" / "BGPLSClientTests" / name
    source = path.read_text()
    section = source[source.index("var hex: String"):]
    return {name: bytes.fromhex(value) for name, value in
            re.findall(r'case \.(\w+):\s*"""\s*([0-9a-fA-F\s]+?)\s*"""', section)}


class WireAttributesTests(unittest.TestCase):
    def event(self, value=None, **kwargs):
        return AUDIT.decode_update(body(value, **kwargs))["events"][0]

    def audit(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            path.write_bytes(data)
            return AUDIT.audit_capture(path)

    def test_all_projections_and_raw_evidence_are_contextual(self):
        raw = (tlv(1155, (7).to_bytes(4, "big")) + tlv(1026, b"r1") + tlv(1095, b"\x8a")
               + tlv(1089, f32(125)) + tlv(1090, f32(250))
               + tlv(1091, b"".join(f32(priority * 10) for priority in range(8))))
        events = AUDIT.decode_update(body(raw, nlris=[node(), FIXTURE.link(), FIXTURE.prefix(),
                                                     FIXTURE.prefix("192.0.2.1/32")]))["events"]
        self.assertEqual(events[0]["attributes"], {"name": "r1"})
        self.assertEqual(events[1]["attributes"], {"igpMetric": 10, "maximumLinkBandwidth": 125,
                         "maximumReservableBandwidth": 250, "unreservedBandwidth": list(range(0, 80, 10))})
        self.assertEqual(events[2]["attributes"], {"metric": 7})
        self.assertEqual(events[3]["attributes"], {"metric": 7})
        for event in events:
            self.assertEqual(event["availability"], "present")
            self.assertEqual(event["issues"], [])
            self.assertEqual(event["evidence"][0]["valueHex"], raw.hex())
            self.assertEqual(event["evidence"][0]["flags"], 0x90)
        events[0]["evidence"][0]["tlvs"].clear()
        self.assertEqual(len(events[1]["evidence"][0]["tlvs"]), 6)

    def test_absent_present_unknown_and_discarded_are_distinct(self):
        absent = self.event()
        unknown = self.event(tlv(60000, b"\0\xff"))
        empty = self.event(b"")
        self.assertEqual([event["availability"] for event in (absent, unknown, empty)],
                         ["absent", "present", "discarded"])
        self.assertEqual(absent["evidence"], [])
        self.assertEqual(unknown["evidence"][0]["tlvs"][0]["type"], 60000)
        for event in (absent, unknown, empty):
            self.assertEqual(event["attributes"], {"name": None})
        self.assertEqual(empty["issues"][0], {
            "disposition": "attributeDiscarded", "category": "emptyAttribute", "attributeIndex": 1,
            "tlvIndex": None, "tlvType": None, "byteOffset": None, "originalHex": ""})

    def test_wrong_context_tlvs_remain_evidence_without_projection_diagnostics(self):
        event = self.event(tlv(1095, b"") + tlv(1155, b"bad") + tlv(1026, b"node"))
        self.assertEqual(event["attributes"], {"name": "node"})
        self.assertEqual(event["issues"], [])
        self.assertEqual([entry["type"] for entry in event["evidence"][0]["tlvs"]], [1095, 1155, 1026])

    def test_names_keep_spaces_empty_and_ascii_controls(self):
        for raw in (b"", b"  router  ", b"\n\t\x1b\0\\\"", bytes(range(128)), b"a" * 255):
            with self.subTest(raw=raw):
                event = self.event(tlv(1026, raw))
                self.assertEqual(event["attributes"]["name"], raw.decode("ascii"))
                self.assertEqual(event["issues"], [])
                self.assertEqual(json.loads(json.dumps(event)), event)

    def test_invalid_names_do_not_poison_prefix_projection(self):
        for raw, category in ((b"a" * 256, "invalidLength"), (b"\xff", "invalidASCII")):
            with self.subTest(category=category):
                events = AUDIT.decode_update(body(tlv(1026, raw) + tlv(1155, bytes(4)),
                                                 nlris=[node(), FIXTURE.prefix()]))["events"]
                self.assertIsNone(events[0]["attributes"]["name"])
                self.assertEqual(events[1]["attributes"]["metric"], 0)
                self.assertEqual(events[0]["issues"][0]["category"], category)

    def test_metric_widths_reserved_bits_and_unsigned_limits(self):
        for raw, expected in ((b"\xc0", 0), (b"\xff", 63), (b"\xff\xff", 65535),
                              (b"\xff\xff\xff", 16777215), (b"\0\0\x0a", 10)):
            with self.subTest(raw=raw):
                event = self.event(tlv(1095, raw), nlris=[FIXTURE.link()])
                self.assertEqual(event["attributes"]["igpMetric"], expected)
        prefix = self.event(tlv(1155, b"\xff" * 4), nlris=[FIXTURE.prefix()])
        self.assertEqual(prefix["attributes"]["metric"], 4294967295)
        for kind, invalid, nlri in ((1095, b"", FIXTURE.link()), (1095, bytes(4), FIXTURE.link()),
                                    (1155, bytes(3), FIXTURE.prefix())):
            self.assertEqual(self.event(tlv(kind, invalid), nlris=[nlri])["issues"][0]["category"], "invalidLength")

    def test_bandwidth_binary32_zero_extremes_and_oversubscription(self):
        for bits in (0, 0x80000000, 1, 0x7f7fffff):
            value = struct.pack("!I", bits)
            event = self.event(tlv(1089, value), nlris=[FIXTURE.link()])
            self.assertEqual(event["attributes"]["maximumLinkBandwidth"], struct.unpack("!f", value)[0])
            self.assertEqual(event["evidence"][0]["tlvs"][0]["valueHex"], value.hex())
            self.assertEqual(event["issues"], [])
        negative_zero = self.event(tlv(1089, f32(-0.0)), nlris=[FIXTURE.link()])
        self.assertEqual(math.copysign(1, negative_zero["attributes"]["maximumLinkBandwidth"]), -1)

    def test_invalid_bandwidth_omits_only_affected_property(self):
        for value in (-1, math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                raw = tlv(1089, f32(value)) + tlv(1090, f32(999)) + tlv(1095, b"\x0a")
                event = self.event(raw, nlris=[FIXTURE.link()])
                self.assertIsNone(event["attributes"]["maximumLinkBandwidth"])
                self.assertEqual(event["attributes"]["maximumReservableBandwidth"], 999)
                self.assertEqual(event["attributes"]["igpMetric"], 10)
                self.assertEqual(event["issues"][0]["category"], "invalidValue")
        for kind, value in ((1089, b"abc"), (1090, b""), (1091, bytes(31))):
            self.assertEqual(self.event(tlv(kind, value), nlris=[FIXTURE.link()])["issues"][0]["category"],
                             "invalidLength")

    def test_invalid_priority_rejects_whole_eight_value_projection(self):
        for priority in range(8):
            values = [f32(100)] * 8
            values[priority] = f32(-1)
            event = self.event(tlv(1091, b"".join(values)), nlris=[FIXTURE.link()])
            self.assertIsNone(event["attributes"]["unreservedBandwidth"])
            self.assertEqual(event["issues"][0]["category"], "invalidValue")

    def test_duplicate_tlvs_preserve_coordinates_and_wire_issue_order(self):
        raw = tlv(1095, b"\x0a") + tlv(1089, bytes(3)) + tlv(1095, b"\x0a") + tlv(1095, b"\x0b")
        event = self.event(raw, nlris=[FIXTURE.link()])
        self.assertIsNone(event["attributes"]["igpMetric"])
        self.assertEqual([item["category"] for item in event["issues"]],
                         ["invalidLength", "duplicateTLV", "conflictingTLV"])
        self.assertEqual([item["tlvIndex"] for item in event["issues"]], [1, 2, 3])
        self.assertEqual([item["byteOffset"] for item in event["issues"]], [5, 12, 17])
        self.assertEqual(event["issues"][-1]["originalHex"], tlv(1095, b"\x0b").hex())
        identical = self.event(tlv(1026, b"same") * 2)
        self.assertEqual(identical["attributes"]["name"], "same")
        self.assertEqual(identical["issues"][0]["disposition"], "acceptedWithWarning")

    def test_duplicate_outer_attributes_never_repair_bad_first(self):
        for first in (b"", b"\x04", tlv(1026, b"\xff")):
            with self.subTest(first=first):
                event = self.event(first, extra=attribute(tlv(1026, b"replacement")))
                self.assertIsNone(event["attributes"]["name"])
                self.assertEqual(event["issues"][-1]["category"], "duplicateAttribute")
                self.assertEqual(event["issues"][-1]["attributeIndex"], 2)
                self.assertEqual(len(event["evidence"]), 2)
        event = self.event(tlv(1026, b"first"), extra=attribute(b"\x04", flags=0))
        self.assertEqual(event["attributes"]["name"], "first")
        self.assertEqual([entry["category"] for entry in event["issues"]], ["duplicateAttribute"])
        self.assertEqual(event["evidence"][-1]["valueHex"], "04")

    def test_flags_only_optional_and_transitive_affect_interpretation(self):
        for flags in (0x80, 0x90, 0xa0, 0xbf):
            self.assertEqual(self.event(tlv(1026, b"ok"), flags=flags)["attributes"]["name"], "ok")
        for flags in (0, 0x40, 0xc0, 0xff):
            event = self.event(tlv(1026, b"ok"), flags=flags)
            self.assertEqual(event["availability"], "discarded")
            self.assertEqual(event["issues"][0]["category"], "invalidFlags")

    def test_inner_framing_discards_all_projections_and_retains_valid_frames(self):
        valid = tlv(1026, b"discard me")
        for tail, kind in ((b"\x04", None), (b"\x04\x47", 1095), (b"\x04\x47\0", 1095),
                           (b"\x04\x47\0\x02\x01", 1095)):
            with self.subTest(tail=tail):
                event = self.event(valid + tail)
                self.assertEqual(event["availability"], "discarded")
                self.assertIsNone(event["attributes"]["name"])
                self.assertEqual(len(event["evidence"][0]["tlvs"]), 1)
                self.assertEqual(event["evidence"][0]["valueHex"], (valid + tail).hex())
                self.assertEqual(event["issues"][0], {
                    "disposition": "attributeDiscarded", "category": "malformedFraming", "attributeIndex": 1,
                    "tlvIndex": 1, "tlvType": kind, "byteOffset": len(valid), "originalHex": tail.hex()})

    def test_outer_coordinates_include_unrelated_attributes(self):
        packet_body = body(None, extra=attribute(b"\0", kind=1) + attribute(tlv(1026, b"x"))
                           + attribute(b"opaque", kind=100) + attribute(tlv(1026, b"y")))
        event = AUDIT.decode_update(packet_body)["events"][0]
        self.assertEqual([entry["attributeIndex"] for entry in event["evidence"]], [2, 4])

    def test_reach_before_withdraw_even_with_reversed_outer_attribute_order(self):
        reach = body(tlv(1026, b"new"))
        withdrawal_attributes = body(withdraw=True)[4:]
        combined = bytes(2) + struct.pack("!H", len(withdrawal_attributes) + len(reach) - 4)
        combined += withdrawal_attributes + reach[4:]
        events = AUDIT.decode_update(combined)["events"]
        self.assertEqual([event["operation"] for event in events], ["upsert", "withdraw"])
        self.assertEqual(events[0]["key"], events[1]["key"])
        self.assertEqual(set(events[1]), {"operation", "key", "display"})

    def test_withdrawal_and_eor_retain_malformed_attribute_diagnostics(self):
        valid = tlv(60000, b"opaque")
        remainder = b"\x04\x47\0\x02\x01"
        expected = {"disposition": "attributeDiscarded", "category": "malformedFraming",
                    "attributeIndex": 1, "tlvIndex": 1, "tlvType": 1095,
                    "byteOffset": len(valid), "originalHex": remainder.hex()}
        for objects in ([node()], []):
            with self.subTest(eor=not objects):
                observation = AUDIT.decode_update(body(valid + remainder, nlris=objects, withdraw=True))
                self.assertEqual(observation["attributeDiagnostics"], [expected])
                self.assertEqual(observation["attributeEvidence"][0]["valueHex"], (valid + remainder).hex())
                self.assertEqual(len(observation["events"]), len(objects))
                for event in observation["events"]:
                    self.assertEqual(event["operation"], "withdraw")
                    self.assertEqual(set(event), {"operation", "key", "display"})

    def test_clean_updates_always_expose_empty_attribute_diagnostics(self):
        for objects, withdrawal in (([node()], False), ([node()], True), ([], True)):
            for value in (None, tlv(60000, b"opaque"), tlv(1026, b"name")):
                with self.subTest(objects=len(objects), withdrawal=withdrawal, value=value):
                    observation = AUDIT.decode_update(body(value, nlris=objects, withdraw=withdrawal))
                    self.assertEqual(observation["attributeDiagnostics"], [])
        audit = self.audit(session(body(), body(withdraw=True), body(nlris=[], withdraw=True)))
        self.assertEqual(audit["schema"], 2)
        self.assertEqual([entry["attributeDiagnostics"] for entry in audit["updates"]], [[], [], []])

    def test_non_upsert_outer_attribute_diagnostics_preserve_order_and_evidence(self):
        replacement = tlv(1026, b"replacement")
        duplicate = {"disposition": "acceptedWithWarning", "category": "duplicateAttribute",
                     "attributeIndex": 2, "tlvIndex": None, "tlvType": None,
                     "byteOffset": None, "originalHex": replacement.hex()}
        for objects in ([node()], []):
            for value, flags, category in ((b"", 0x90, "emptyAttribute"),
                                          (tlv(1026, b"first"), 0xc0, "invalidFlags")):
                with self.subTest(eor=not objects, category=category):
                    observation = AUDIT.decode_update(body(value, nlris=objects, withdraw=True, flags=flags,
                                                           extra=attribute(replacement)))
                    self.assertEqual(observation["attributeDiagnostics"], [
                        {"disposition": "attributeDiscarded", "category": category, "attributeIndex": 1,
                         "tlvIndex": None, "tlvType": None, "byteOffset": None, "originalHex": value.hex()},
                        duplicate])
        # Recognized projection validation remains contextual: a withdrawal is
        # not a new advertisement, but its outer attribute observation survives.
        observation = AUDIT.decode_update(body(tlv(1026, b"\xff"), withdraw=True))
        self.assertEqual(observation["attributeDiagnostics"], [])

    def test_capture_diagnostics_and_coverage_are_once_per_update_not_per_upsert(self):
        raw = tlv(60000, b"opaque") + b"\x04"
        updates = (body(raw, nlris=[node(), FIXTURE.link(), FIXTURE.prefix()]),
                   body(raw, withdraw=True), body(raw, nlris=[], withdraw=True))
        with mock.patch.object(AUDIT, "decode_attributes", wraps=AUDIT.decode_attributes) as decode:
            audit = self.audit(session(*updates))
        self.assertEqual(decode.call_count, len(updates))
        self.assertEqual(audit["coverage"]["upserts"], 3)
        self.assertEqual(audit["coverage"]["withdrawals"], 1)
        self.assertEqual(audit["coverage"]["tlvTypes"], [60000])
        self.assertEqual(audit["coverage"]["issues"], {"malformedFraming": 3})
        for update in audit["updates"]:
            self.assertEqual(len(update["attributeDiagnostics"]), 1)
            self.assertEqual(update["attributeDiagnostics"][0]["category"], "malformedFraming")
            for event in update["events"]:
                if event["operation"] == "upsert":
                    self.assertEqual(event["issues"], update["attributeDiagnostics"])
        # Event evidence is value-shaped, not an alias for UPDATE-level evidence.
        audit["updates"][0]["events"][0]["issues"].clear()
        self.assertEqual(len(audit["updates"][0]["attributeDiagnostics"]), 1)
        self.assertEqual(len(audit["updates"][0]["events"][1]["issues"]), 1)

    def test_replacement_drops_old_values_and_final_records_are_sorted(self):
        first = body(tlv(1026, b"old"))
        absent = body()
        discarded = body(b"\x04")
        new = body(tlv(1026, b"new"))
        data = session(first, absent, discarded, new, body(nlris=[FIXTURE.prefix()]))
        audit = self.audit(data)
        self.assertEqual([update["events"][0]["availability"] for update in audit["updates"]],
                         ["present", "absent", "discarded", "present", "absent"])
        self.assertEqual(audit["coverage"]["upserts"], 5)
        self.assertEqual(audit["coverage"]["issues"], {"malformedFraming": 1})
        self.assertEqual([record["key"] for record in audit["finalRecords"]],
                         sorted(record["key"] for record in audit["finalRecords"]))
        self.assertEqual(audit["finalRecords"][0]["attributes"], {"name": "new"})

    def test_unknown_nlris_are_observed_not_installed_and_eor_is_retained(self):
        unknown = FIXTURE.nlri(60000, b"opaque")
        audit = self.audit(session(body(tlv(1026, b"name")), body(tlv(1026, b"ignored"), nlris=[unknown]),
                                  body(nlris=[], withdraw=True)))
        event = audit["updates"][1]["events"][0]
        self.assertEqual(event["display"], "unknown type=60000")
        self.assertTrue(event["key"].startswith("unknown:60000:"))
        self.assertEqual(event["attributes"], {})
        self.assertEqual(event["issues"], [])
        self.assertEqual(len(audit["finalRecords"]), 1)
        self.assertEqual(audit["updates"][2]["events"], [])

    def test_ipv4_and_ipv6_incoming_capture_audits_agree(self):
        bodies = [body(tlv(1026, b"router")), body(tlv(1095, b"\x0a"), nlris=[FIXTURE.link()]),
                  body(nlris=[FIXTURE.link()], withdraw=True)]
        first, second = [self.audit(session(*bodies, family=family)) for family in (4, 6)]
        self.assertEqual(first["updates"], second["updates"])
        self.assertEqual(first["finalRecords"], second["finalRecords"])
        self.assertEqual(first["coverage"], second["coverage"])
        self.assertNotEqual(first["producerStream"], second["producerStream"])

    def test_wrong_or_ambiguous_producing_direction_is_rejected(self):
        with self.assertRaisesRegex(AUDIT.WireError, "incoming producer"):
            self.audit(session(body(), outgoing_body=body()))
        with self.assertRaisesRegex(AUDIT.WireError, "active-open"):
            self.audit(FIXTURE.capture(FIXTURE.bgp(2, body())))
        data = session(body())
        extra = FIXTURE.packet(b"", 0, flags=2, addresses=("127.0.0.2", "127.0.0.1"))
        data += struct.pack("<IIII", 2, 0, len(extra), len(extra)) + extra
        with self.assertRaisesRegex(AUDIT.WireError, "active-open"):
            self.audit(data)

    def test_outer_framing_is_fatal_not_partial_success(self):
        valid = body(tlv(1026, b"valid"))
        for bad in (b"", b"\0", valid[:-1], valid[:2] + b"\xff\xff" + valid[4:], bytes(4096)):
            with self.subTest(bad=bad[:10]), self.assertRaises(AUDIT.WireError):
                AUDIT.decode_update(bad)

    def test_retained_vendor_updates_and_distinct_metric_encodings(self):
        frr = retained("FRRCapturedUpdateTests.swift")
        ceos = retained("CEOSCapturedUpdateTests.swift")
        self.assertEqual(len(frr), 7)
        self.assertEqual(len(ceos), 12)
        for vendor in (frr, ceos):
            for value in vendor.values():
                for event in AUDIT.decode_update(value)["events"]:
                    if event["operation"] == "upsert":
                        self.assertEqual(event["availability"], "present")
                        self.assertEqual(event["issues"], [])
        frr_link = AUDIT.decode_update(frr["links"])["events"][0]
        ceos_frr_link = AUDIT.decode_update(ceos["p1ToP2"])["events"][0]
        ceos_link = AUDIT.decode_update(ceos["edgeToP1"])["events"][0]
        self.assertEqual(frr_link["attributes"], ceos_frr_link["attributes"])
        self.assertEqual(frr_link["attributes"]["maximumLinkBandwidth"], 1_250_000)
        self.assertEqual(ceos_link["attributes"]["maximumLinkBandwidth"], 125_000_000)
        self.assertEqual(ceos_link["attributes"]["maximumReservableBandwidth"], 0)
        self.assertEqual(ceos_link["attributes"]["unreservedBandwidth"], [0] * 8)
        for event, length in ((frr_link, 1), (ceos_frr_link, 3)):
            metric = next(value for value in event["evidence"][0]["tlvs"] if value["type"] == 1095)
            self.assertEqual(len(bytes.fromhex(metric["valueHex"])), length)

    def test_retained_dual_stack_frames_preserve_both_prefix_families(self):
        for name in ("FRRDualStackCapturedUpdateTests.swift", "CEOSDualStackCapturedUpdateTests.swift"):
            fixtures = retained(name)
            events = []
            for message in fixtures.values():
                self.assertEqual(message[:16], b"\xff" * 16)
                self.assertEqual(int.from_bytes(message[16:18], "big"), len(message))
                events.extend(AUDIT.decode_update(message[19:])["events"])
            prefixes = [event for event in events if event["key"].startswith(("prefix:", "prefix6:"))
                        and event["operation"] == "upsert"]
            self.assertTrue(any(event["key"].startswith("prefix:") for event in prefixes))
            self.assertTrue(any(event["key"].startswith("prefix6:") for event in prefixes))
            self.assertTrue(all(event["attributes"]["metric"] == 10 for event in prefixes))


if __name__ == "__main__":
    unittest.main()
