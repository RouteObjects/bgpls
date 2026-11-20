#!/usr/bin/env python3
"""Synthetic wire audit regressions; no containers, sockets, or real signals."""

import importlib.util
import ipaddress
from pathlib import Path
import struct
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "bgpls_wire_topology", Path(__file__).resolve().parents[1] / "wire-topology.py"
)
WIRE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WIRE)


def tlv(kind, value):
    return struct.pack("!HH", kind, len(value)) + value


def node(kind=256, last=1, extra=b""):
    return tlv(kind, tlv(512, struct.pack("!I", 65001)) + tlv(515, bytes(5) + bytes([last])) + extra)


def nlri(kind, descriptors, protocol=2, instance=0):
    body = struct.pack("!BQ", protocol, instance) + descriptors
    return struct.pack("!HH", kind, len(body)) + body


def prefix(text="2001:db8::1/128", extra=b"", instance=0):
    address = ipaddress.ip_interface(text)
    count = (address.network.prefixlen + 7) // 8
    return nlri(3 if address.version == 4 else 4,
                node() + tlv(265, bytes([address.network.prefixlen]) + address.ip.packed[:count]) + extra,
                instance=instance)


def link(extra=b""):
    return nlri(2, node() + node(257, 2)
                + tlv(259, ipaddress.IPv4Address("192.0.2.1").packed)
                + tlv(260, ipaddress.IPv4Address("192.0.2.2").packed)
                + tlv(261, ipaddress.IPv6Address("2001:db8:1::1").packed)
                + tlv(262, ipaddress.IPv6Address("2001:db8:1::2").packed) + extra)


def attribute(kind, value, extended=False):
    return bytes([0x90 if extended else 0x80, kind]) + struct.pack("!H" if extended else "!B", len(value)) + value


def update(*nlris, withdraw=False, extended=False, afi=16388, safi=71, extra=b""):
    value = struct.pack("!HB", afi, safi)
    if not withdraw:
        value += b"\x04\xc0\x00\x02\xfe\0"
    attrs = attribute(15 if withdraw else 14, value + b"".join(nlris), extended) + extra
    return bgp(2, struct.pack("!HH", 0, len(attrs)) + attrs)


def bgp(kind, body=b""):
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), kind) + body


def packet(payload, sequence=1, outbound=False, flags=0, family=4, addresses=None):
    ports = (50000, 11790) if outbound else (11790, 50000)
    addresses = addresses or (("127.0.0.1",) * 2 if family == 4 else ("::1",) * 2)
    packed = [ipaddress.ip_address(address).packed for address in addresses]
    if family == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 0, 0x4000, 64, 6, 0, *packed)
    else:
        header = struct.pack("!IHBB16s16s", 6 << 28, 20 + len(payload), 6, 64, *packed)
    tcp = struct.pack("!HHIIBBHHH", *ports, sequence, 0, 0x50, flags, 65535, 0, 0)
    return struct.pack("<I", 2 if family == 4 else 24) + header + tcp + payload


def pcap(*packets):
    header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 0)
    return header + b"".join(struct.pack("<IIII", 1, index, len(value), len(value)) + value
                             for index, value in enumerate(packets))


def capture(*messages, family=4):
    packets = []
    sequence = 1
    for message in messages:
        packets.append(packet(message, sequence, family=family))
        sequence += len(message)
    return pcap(*packets)


class WireTests(unittest.TestCase):
    def parse(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.pcap"
            path.write_bytes(data)
            return WIRE.parse_capture(path)

    def audit(self, data, expected, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.pcap"
            path.write_bytes(data)
            return WIRE.audit_capture(path, expected, **kwargs)

    def test_complete_bgp_framing_split_across_packets_and_directions(self):
        opening = bgp(1, struct.pack("!BHH4sB", 4, 65001, 9, b"\xc0\x00\x02\x01", 0))
        incoming = opening + update(nlri(1, node()), link(), prefix(), extended=True) + bgp(4) * 4
        outgoing = opening + bgp(4) * 4
        result = self.parse(pcap(
            packet(b"", 0, outbound=True, flags=2), packet(b"", 0, flags=18),
            packet(incoming[:7], 1), packet(outgoing, 1, outbound=True),
            packet(incoming[7:31], 8), packet(incoming[31:], 32),
            packet(b"", 1 + len(incoming), flags=1),
        ))
        self.assertEqual(result["bgp_messages_by_type"], {1: 2, 2: 1, 4: 8})
        self.assertEqual([event["record"]["nlri_type"] for event in result["events"]], [1, 2, 4])
        self.assertEqual(result["events"][1]["record"]["ipv6_link_descriptors"], [261, 262])
        self.assertEqual(bytes.fromhex(result["updates"][0]["message_hex"]),
                         update(nlri(1, node()), link(), prefix(), extended=True))

    def test_ipv6_transport_preserves_split_coalesced_topology_and_wire_keys(self):
        opening = bgp(1, struct.pack("!BHH4sB", 4, 65001, 9, b"\xc0\x00\x02\x65", 0))
        incoming = opening + update(nlri(1, node()), link(), prefix(), extended=True) + bgp(4) * 4
        outgoing = opening + bgp(4) * 4
        results = []
        for family in (4, 6):
            results.append(self.parse(pcap(
                packet(b"", 0, outbound=True, flags=2, family=family),
                packet(b"", 0, flags=18, family=family),
                packet(incoming[:7], 1, family=family), packet(outgoing, 1, outbound=True, family=family),
                packet(incoming[7:31], 8, family=family), packet(incoming[31:], 32, family=family),
                packet(b"", 1 + len(incoming), flags=1, family=family),
            )))
        self.assertEqual(results[0]["bgp_messages_by_type"], results[1]["bgp_messages_by_type"])
        self.assertEqual([event["record"] for event in results[0]["events"]],
                         [event["record"] for event in results[1]["events"]])
        self.assertEqual(results[1]["updates"][0]["stream"], "[::1]:11790->[::1]:50000")
        self.assertEqual(results[0]["updates"][0]["message_hex"], results[1]["updates"][0]["message_hex"])

    def test_ipv6_transport_keeps_churn_probe_and_prefix_retention_audits(self):
        base = [nlri(1, node()), link(), prefix("192.0.2.1/32"), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        removed = {WIRE.parse_nlris(link())[0]["display"]}
        probe = prefix("2001:db8:ffff::5/128")
        messages = [update(*base, extended=True), update(link(), withdraw=True), update(link()),
                    update(probe), update(probe, withdraw=True), update(probe), update(probe, withdraw=True)]
        args = {"churn_objects": removed, "probe_objects": [WIRE.parse_nlris(probe)[0]["display"]]}
        ipv4 = self.audit(capture(*messages), expected, **args)
        ipv6 = self.audit(capture(*messages, family=6), expected, **args)
        self.assertEqual(ipv4, ipv6)
        for lost in base[2:]:
            with self.subTest(lost=lost), self.assertRaisesRegex(WIRE.WireError, "baseline prefix keys missing"):
                self.audit(capture(messages[0], update(lost, withdraw=True), update(lost), family=6), expected)

    def test_ipv6_streams_cannot_merge_by_port_or_address_family(self):
        message = update(prefix())
        for family, addresses in ((4, ("127.0.0.1", "127.0.0.1")),
                                  (6, ("::2", "::1")), (6, ("::1", "::2"))):
            with self.subTest(family=family, addresses=addresses), self.assertRaises(WIRE.WireError):
                self.parse(pcap(packet(message[:7], family=6),
                                packet(message[7:], sequence=8, family=family, addresses=addresses)))

    def test_ipv6_gaps_and_oversized_bgp_messages_are_rejected(self):
        message = update(prefix())
        for sequence in (1, len(message), len(message) + 2):
            with self.subTest(sequence=sequence), self.assertRaisesRegex(WIRE.WireError, "TCP gap"):
                self.parse(pcap(packet(message, family=6), packet(message, sequence, family=6)))
        with self.assertRaisesRegex(WIRE.WireError, "invalid BGP header"):
            self.parse(capture(bgp(2, bytes(4096 - 19 + 1)), family=6))

    def test_ipv6_transport_malformed_frames_are_wire_errors(self):
        valid = packet(bgp(4), family=6)
        malformed = [valid[:cut] for cut in (3, 4, 43, 44, 63)]
        for offset, value in ((0, 2), (0, 10), (0, 28), (0, 30), (4, 0x45),
                              (10, 0), (10, 17), (10, 43), (10, 44), (10, 59), (56, 0x40), (56, 0xf0)):
            changed = bytearray(valid)
            changed[offset] = value
            malformed.append(changed)
        for length in (0, 19, 38, 40, 65535):
            changed = bytearray(valid)
            struct.pack_into("!H", changed, 8, length)
            malformed.append(changed)
        for index, value in enumerate(malformed):
            with self.subTest(index=index), self.assertRaises(WIRE.WireError):
                self.parse(pcap(value))

    def test_canonical_keys_preserve_ipv4_namespace_and_separate_family_domain(self):
        node_record = WIRE.parse_nlris(nlri(1, node()))[0]
        self.assertEqual(node_record["key"],
                         "node:2:0:local[512:4:0000fde9;515:6:000000000001;]:additional[]")
        v4, v6, other = [WIRE.parse_nlris(value)[0] for value in
                         (prefix("0.0.0.0/0"), prefix("::/0"), prefix("::/0", instance=7))]
        self.assertTrue(v4["key"].startswith("prefix:2:0:"))
        self.assertTrue(v6["key"].startswith("prefix6:2:0:"))
        self.assertEqual(len({v4["key"], v6["key"], other["key"]}), 3)

    def test_unknown_tlvs_order_duplicates_and_deprecated_513(self):
        first = tlv(65000, b"ab") + tlv(65000, b"c")
        reverse = tlv(65000, b"c") + tlv(65000, b"ab")
        merged = tlv(65000, b"abc")
        keys = [WIRE.parse_nlris(prefix(extra=value))[0]["key"] for value in (first, reverse, merged)]
        self.assertEqual(keys[0], keys[1])
        self.assertNotEqual(keys[0], keys[2])
        with_513 = nlri(1, node(extra=tlv(513, struct.pack("!I", 123))))
        self.assertEqual(WIRE.parse_nlris(with_513)[0]["key"], WIRE.parse_nlris(nlri(1, node()))[0]["key"])
        self.assertNotEqual(WIRE.parse_nlris(with_513)[0]["wire_hex"], WIRE.parse_nlris(nlri(1, node()))[0]["wire_hex"])
        changed_unknown = nlri(1, node(extra=tlv(65001, b"x")))
        self.assertNotEqual(WIRE.parse_nlris(changed_unknown)[0]["key"], WIRE.parse_nlris(nlri(1, node()))[0]["key"])

    def test_prefix_padding_and_isis_mt_reserved_bits_normalize(self):
        for length in (0, 1, 7, 8, 9, 63, 64, 65, 127, 128):
            with self.subTest(length=length):
                raw = prefix(f"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/{length}", extra=tlv(263, b"\xf0\x02"))
                network = str(ipaddress.IPv6Network((2**128 - 1, length), strict=False))
                canonical = prefix(network, extra=tlv(263, b"\0\x02"))
                self.assertEqual(WIRE.parse_nlris(raw)[0]["key"], WIRE.parse_nlris(canonical)[0]["key"])

    def test_lab_rejects_nondefault_topology_without_restricting_generic_parser(self):
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in (link(), prefix())}
        for code in (0, 2, 0xf000, 0xf002):
            descriptor = tlv(263, struct.pack("!H", code))
            for values in ((link(extra=descriptor), prefix()), (link(), prefix(extra=descriptor))):
                records = [WIRE.parse_nlris(value)[0] for value in values]
                self.assertIn(code & 0x0fff, [record["multi_topology_id"] for record in records])
                with self.subTest(code=code, values=values):
                    if code & 0x0fff:
                        with self.assertRaisesRegex(WIRE.WireError, "non-default topology"):
                            self.audit(capture(update(*values, extended=True)), expected)
                    else:
                        self.audit(capture(update(*values, extended=True)), expected)

    def test_lab_rejects_stable_wrong_domain_without_restricting_generic_parser(self):
        base = [nlri(1, node()), link(), prefix("192.0.2.1/32"), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        for protocol, instance in ((2, 0), (1, 0), (2, 7), (1, 7)):
            values = [value[:4] + struct.pack("!BQ", protocol, instance) + value[13:] for value in base]
            records = [WIRE.parse_nlris(value)[0] for value in values]
            self.assertEqual({record["display"] for record in records}, expected)
            self.assertEqual({(record["protocol_id"], record["identifier"]) for record in records},
                             {(protocol, instance)})
            with self.subTest(protocol=protocol, instance=instance):
                if (protocol, instance) == (2, 0):
                    self.audit(capture(update(*values, extended=True)), expected)
                else:
                    with self.assertRaisesRegex(WIRE.WireError, "unexpected protocol or instance"):
                        self.audit(capture(update(*values, extended=True)), expected)

    def test_unknown_nlri_is_preserved_without_assuming_fixed_header(self):
        record = WIRE.parse_nlris(struct.pack("!HH", 65000, 2) + b"ab")[0]
        self.assertEqual(record["key"], "unknown:65000:6162")

    def test_identifier_and_missing_neighbor_link_display(self):
        ids = WIRE.parse_nlris(nlri(2, node() + node(257, 2) + tlv(258, struct.pack("!II", 100, 200))))[0]
        self.assertEqual(ids["display"], "link 0000.0000.0001 id:100 → 0000.0000.0002 id:200")
        partial = WIRE.parse_nlris(nlri(2, node() + node(257, 2)
                                     + tlv(261, ipaddress.IPv6Address("2001:db8::1").packed)))[0]
        self.assertEqual(partial["display"], "link 0000.0000.0001 2001:db8::1 → 0000.0000.0002 ?")

    def test_other_afi_and_end_of_rib_are_not_topology_events(self):
        data = capture(update(afi=1, safi=1), update(withdraw=True),
                       update(prefix(), extra=attribute(29, b"opaque attributes")))
        result = self.parse(data)
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["record"]["nlri_type"], 4)

    def test_exact_wire_key_churn_and_two_probe_cycles_restore(self):
        base = [nlri(1, node()), link(), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        removed = {WIRE.parse_nlris(link())[0]["display"]}
        probes = [prefix("2001:db8:ffff::5/128"), prefix("2001:db8:ffff::6/128")]
        messages = [update(*base, extended=True), update(link(), withdraw=True), update(link())]
        for probe in probes:
            messages += [update(probe), update(probe, withdraw=True), update(probe), update(probe, withdraw=True)]
        result = self.audit(capture(*messages), expected, churn_objects=removed,
                            probe_objects=[WIRE.parse_nlris(value)[0]["display"] for value in probes])
        self.assertEqual(len(result["final_records"]), 3)
        self.assertEqual(result["withdrawals"], 5)
        self.assertEqual(len(result["checkpoints"]), 11)
        self.assertEqual(result["checkpoints"][0]["keys"], result["checkpoints"][-1]["keys"])

    def test_same_key_refresh_and_unknown_withdrawal_do_not_change_state(self):
        base = [link(), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        result = self.audit(capture(update(*base, extended=True), update(prefix()),
                                    update(prefix("2001:db8:999::/64"), withdraw=True)), expected)
        self.assertEqual(len(result["final_records"]), 2)

    def test_churn_rejects_temporary_baseline_prefix_loss(self):
        base = [nlri(1, node()), link(), prefix("192.0.2.1/32"), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        removed = {WIRE.parse_nlris(link())[0]["display"]}
        cycle = [update(link(), withdraw=True), update(link())]
        for lost in base[2:]:
            for position in range(len(cycle) + 1):
                messages = ([update(*base, extended=True)] + cycle[:position]
                            + [update(lost, withdraw=True), update(lost)] + cycle[position:])
                with self.subTest(prefix=lost, position=position), self.assertRaisesRegex(
                    WIRE.WireError, "baseline prefix keys missing after UPDATE"
                ):
                    self.audit(capture(*messages), expected, churn_objects=removed)

    def test_probe_cycles_reject_temporary_baseline_prefix_loss(self):
        base = [link(), prefix("192.0.2.1/32"), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        probe = prefix("2001:db8:ffff::5/128")
        probe_display = WIRE.parse_nlris(probe)[0]["display"]
        cycle = [update(probe), update(probe, withdraw=True), update(probe), update(probe, withdraw=True)]
        for lost in base[1:]:
            for position in range(1, len(cycle) + 1):
                messages = ([update(*base, extended=True)] + cycle[:position]
                            + [update(lost, withdraw=True), update(lost)] + cycle[position:])
                with self.subTest(prefix=lost, position=position), self.assertRaisesRegex(
                    WIRE.WireError, "baseline prefix keys missing after UPDATE"
                ):
                    self.audit(capture(*messages), expected, probe_objects=[probe_display])

    def test_checks_end_of_update_that_first_reaches_baseline(self):
        base = [link(), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        withdrawal = attribute(15, struct.pack("!HB", 16388, 71) + prefix())
        #  Reaching the expected state mid-UPDATE must not exempt its
        # later withdrawal from the complete-UPDATE retention check.
        messages = [update(*base, extended=True, extra=withdrawal), update(prefix())]
        with self.assertRaisesRegex(WIRE.WireError, "baseline prefix keys missing after UPDATE 0"):
            self.audit(capture(*messages), expected)

    def test_retention_uses_update_boundaries_not_tcp_packets(self):
        base = [link(), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        messages = (update(*base, extended=True) + update(prefix(), withdraw=True)
                    + update(prefix()) + update(withdraw=True))
        with self.assertRaisesRegex(WIRE.WireError, "baseline prefix keys missing after UPDATE 1"):
            self.audit(pcap(packet(messages)), expected)

    def test_restored_display_cannot_replace_protected_full_prefix_key(self):
        original = prefix()
        replacement = prefix(extra=tlv(65000, b"different identity"))
        base = [link(), original]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        self.assertEqual(WIRE.parse_nlris(original)[0]["display"], WIRE.parse_nlris(replacement)[0]["display"])
        messages = [update(*base, extended=True), update(original, withdraw=True), update(replacement),
                    update(replacement, withdraw=True), update(original)]
        with self.assertRaisesRegex(WIRE.WireError, "baseline prefix keys missing after UPDATE"):
            self.audit(capture(*messages), expected)

    def test_retention_allows_canonical_refresh_and_non_topology_updates(self):
        original = prefix("2001:db8::/63", extra=tlv(263, b"\0\0"))
        refresh = prefix("2001:db8:0:1::/63", extra=tlv(263, b"\xf0\0"))
        base = [link(), prefix("192.0.2.1/32"), original]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        self.assertEqual(WIRE.parse_nlris(original)[0]["key"], WIRE.parse_nlris(refresh)[0]["key"])
        unknown_withdrawal = attribute(15, struct.pack("!HB", 16388, 71) + prefix("2001:db8:999::/64"))
        messages = [update(*base, refresh, extended=True, extra=unknown_withdrawal),
                    update(refresh), update(afi=1, safi=1), update(withdraw=True)]
        result = self.audit(capture(*messages), expected)
        self.assertEqual(len(result["final_records"]), len(base))

    def test_distinct_keys_with_same_display_are_rejected_not_collapsed(self):
        base = [link(), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        for collision in (prefix(extra=tlv(263, b"\0\0")), prefix(extra=tlv(65000, b"x"))):
            with self.subTest(collision=collision), self.assertRaisesRegex(WIRE.WireError, "collide"):
                self.audit(capture(update(*base, extended=True), update(collision)), expected)

    def test_missing_churn_or_probe_withdrawal_fails_even_if_final_display_matches(self):
        base = [link(), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        with self.assertRaisesRegex(WIRE.WireError, "links-withdrawn"):
            self.audit(capture(update(*base, extended=True)), expected,
                       churn_objects={WIRE.parse_nlris(link())[0]["display"]})
        probe = prefix("2001:db8:ffff::5/128")
        with self.assertRaisesRegex(WIRE.WireError, "readd"):
            self.audit(capture(update(*base, extended=True), update(probe), update(probe, withdraw=True)),
                       expected, probe_objects=[WIRE.parse_nlris(probe)[0]["display"]])

    def test_final_key_change_is_not_hidden_by_same_display(self):
        base = [link(), prefix()]
        expected = {WIRE.parse_nlris(value)[0]["display"] for value in base}
        data = capture(update(*base, extended=True), update(prefix(), withdraw=True),
                       update(prefix(extra=tlv(65000, b"x"))))
        with self.assertRaisesRegex(WIRE.WireError, "final full NLRI keys"):
            self.audit(data, expected)

    def test_rejects_topology_from_multiple_tcp_directions(self):
        message = update(link(), prefix(), extended=True)
        with self.assertRaisesRegex(WIRE.WireError, "one topology-producing"):
            self.audit(pcap(packet(message), packet(message, outbound=True)), set())

    def test_rejects_invalid_pcap_and_tcp_framing(self):
        valid = capture(update(prefix()))
        mutations = [b"", valid[:23], valid[:-1], valid + b"\0", valid[:20] + struct.pack("<I", 1) + valid[24:]]
        for data in mutations:
            with self.subTest(length=len(data)), self.assertRaises(WIRE.WireError):
                self.parse(data)
        for bad in (packet(b"", flags=0),):
            wrong_family = bytearray(bad)
            wrong_family[0] = 24
            fragment = bytearray(bad)
            fragment[10:12] = b"\x20\0"
            bad_tcp = bytearray(bad)
            bad_tcp[36] = 0x40
            for value in (wrong_family, fragment, bad_tcp):
                with self.assertRaises(WIRE.WireError):
                    self.parse(pcap(bytes(value)))
        message = update(prefix())
        for second_sequence in (1, len(message), len(message) + 2):
            with self.assertRaisesRegex(WIRE.WireError, "TCP gap"):
                self.parse(pcap(packet(message), packet(message, second_sequence)))

    def test_rejects_truncated_bgp_attribute_and_nlri_fields(self):
        for message in (bgp(4)[:-1], b"\0" * 19, b"\xff" * 16 + b"\0\x12\x04",
                        bgp(2, b"\0"), bgp(2, b"\0\0\0\x04\x90\x0e\0"),
                        update(prefix()[:-1])):
            with self.subTest(message=message), self.assertRaises(WIRE.WireError):
                self.parse(capture(message))

    def test_rejects_duplicate_known_and_malformed_descriptors(self):
        cases = [nlri(4, node()), nlri(4, node() + tlv(265, b"\x81")),
                 nlri(4, node() + tlv(265, b"\0\0")),
                 nlri(4, node() + tlv(265, b"\0") + tlv(265, b"\0")),
                 nlri(4, node() + node() + tlv(265, b"\0")),
                 nlri(1, node(extra=tlv(515, bytes(6))))]
        for kind in (261, 262):
            for count in (0, 15, 17):
                cases.append(nlri(2, node() + node(257, 2) + tlv(kind, bytes(count))))
            cases.append(nlri(2, node() + node(257, 2) + tlv(kind, bytes(16)) * 2))
        for value in cases:
            with self.subTest(value=value), self.assertRaises(WIRE.WireError):
                WIRE.parse_nlris(value)

    def test_rejects_duplicate_mp_attributes(self):
        mp = struct.pack("!HB", 16388, 71)
        with self.assertRaisesRegex(WIRE.WireError, "duplicate MP"):
            self.parse(capture(update(withdraw=True, extra=attribute(15, mp))))


if __name__ == "__main__":
    unittest.main()
