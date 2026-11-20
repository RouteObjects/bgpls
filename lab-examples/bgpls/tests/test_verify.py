#!/usr/bin/env python3
"""Offline verifier regressions using synthetic data, never a running lab."""

import copy
import importlib.util
import ipaddress
from pathlib import Path
import struct
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "bgpls_lab_verify", Path(__file__).resolve().parents[1] / "verify.py"
)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def nlri(kind="node", local="0000.0000.0001.00"):
    """Synthetic equivalents of the pinned FRR JSON presentation fields."""
    value = {
        "nlriType": kind,
        "protocolId": 2,
        "identifier": 0,
        "localNodeDescriptors": {"igpRouterId": local},
    }
    if kind == "link":
        value["remoteNodeDescriptors"] = {"igpRouterId": "0000.0000.0003.00"}
        value["linkDescriptors"] = {
            "ipv4InterfaceAddress": "10.254.0.0",
            "ipv4NeighborAddress": "10.254.0.1",
        }
    elif kind == "ipv4Prefix":
        value["prefixDescriptors"] = {"ipReachabilityInformation": "10.255.0.1/32"}
    elif kind == "ipv6Prefix":
        value["prefixDescriptors"] = {"ipReachabilityInformation": "2001:db8:6501::1/128"}
    return value


def native_table(*values):
    return {
        "routes": {
            f"synthetic-{index}": [{"valid": True, "bestpath": True, "nlri": value}]
            for index, value in enumerate(values)
        }
    }


def reflected_path(cluster, originator="10.255.0.5", valid=True):
    return {
        "valid": valid,
        "originatorId": originator,
        "peer": {"routerId": cluster},
        "clusterList": {"list": [cluster]},
    }


def bgp_message(kind, body=b""):
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), kind) + body


def bgp_open(router_id):
    body = struct.pack("!BHH4sB", 4, 65001, 9, ipaddress.IPv4Address(router_id).packed, 0)
    return bgp_message(1, body)


def tcp_packet(payload, ports=(50000, 11790), *, family=4, sequence=1, addresses=None):
    """Synthetic NIO-style BSD loopback / IPv4 or IPv6 / TCP; no wire I/O."""
    addresses = addresses or (("127.0.0.1",) * 2 if family == 4 else ("::1",) * 2)
    packed = [ipaddress.ip_address(address).packed for address in addresses]
    if family == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 0, 0, 64, 6, 0, *packed)
    else:
        header = struct.pack("!IHBB16s16s", 6 << 28, 20 + len(payload), 6, 64, *packed)
    tcp = struct.pack("!HHIIBBHHH", *ports, sequence, 1, 0x50, 0x18, 65535, 0, 0)
    return struct.pack("<I", 2 if family == 4 else 24) + header + tcp + payload


def pcap_record(packet):
    return struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet


def pcap(*packets):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0)
    return header + b"".join(pcap_record(packet) for packet in packets)


def complete_exchange(split=False, family=4):
    keepalive = bgp_message(4)
    outbound = bgp_open("127.0.0.1") + keepalive * 4
    inbound = bgp_open("10.255.0.5") + bgp_message(2, b"\x00\x00\x00\x00") + keepalive * 4
    if split:
        return pcap(
            tcp_packet(outbound[:7], family=family),
            tcp_packet(inbound[:17], ports=(11790, 50000), family=family),
            tcp_packet(outbound[7:], sequence=8, family=family),
            tcp_packet(inbound[17:], ports=(11790, 50000), sequence=18, family=family),
        )
    return pcap(tcp_packet(outbound, family=family), tcp_packet(inbound, ports=(11790, 50000), family=family))


class WatchStateTests(unittest.TestCase):
    def test_upserts_are_idempotent_and_unrelated_output_is_ignored(self):
        text = (
            "bgpls: state Established\n"
            "bgpls: WATCH snapshot nodes=0 links=0 prefixes=0\n"
            "bgpls: WATCH upsert node 0000.0000.0001\n"
            "bgpls: WATCH upsert node 0000.0000.0001\r\n"
            "node 0000.0000.9999\n"
        )
        self.assertEqual(VERIFY.watch_state(text), {"node 0000.0000.0001"})

    def test_link_withdrawal_and_restoration_replay_in_order(self):
        link = "link 0000.0000.0003 10.254.0.8 → 0000.0000.0004 10.254.0.9"
        node = "node 0000.0000.0003"
        baseline = f"WATCH upsert {node}\nWATCH upsert {link}\n"
        down = baseline + f"WATCH withdraw {link}\nWATCH withdraw {link}\n"
        self.assertEqual(VERIFY.watch_state(down), {node})
        self.assertEqual(VERIFY.watch_state(down + f"WATCH upsert {link}\n"), {node, link})

    def test_prefix_is_withdrawn_without_removing_other_nodes_prefix(self):
        first = "prefix 10.254.0.8/31 node 0000.0000.0003"
        second = "prefix 10.254.0.8/31 node 0000.0000.0004"
        text = f"WATCH upsert {first}\nWATCH upsert {second}\nWATCH withdraw {first}\n"
        self.assertEqual(VERIFY.watch_state(text), {second})

    def test_empty_stream_and_unknown_withdrawal_are_empty(self):
        self.assertEqual(VERIFY.watch_state(""), set())
        self.assertEqual(VERIFY.watch_state("WATCH withdraw node 0000.0000.0001\n"), set())


class NativeObjectsTests(unittest.TestCase):
    def test_node_link_prefix_and_zero_pseudonode_presentation(self):
        result = VERIFY.native_objects(native_table(nlri(), nlri("link"), nlri("ipv4Prefix")))
        self.assertEqual(result, {
            "node 0000.0000.0001",
            "link 0000.0000.0001 10.254.0.0 → 0000.0000.0003 10.254.0.1",
            "prefix 10.255.0.1/32 node 0000.0000.0001",
        })

    def test_route_map_keys_are_opaque_and_nonbest_paths_are_ignored(self):
        table = native_table(nlri())
        paths = table["routes"].pop("synthetic-0")
        paths.append({"valid": True, "bestpath": False, "nlri": nlri("unknown")})
        paths.append({"valid": False, "bestpath": True, "nlri": nlri("unknown")})
        table["routes"]["not-parsed-as-an-identity"] = paths
        self.assertEqual(VERIFY.native_objects(table), {"node 0000.0000.0001"})

    def test_other_protocol_or_instance_is_rejected(self):
        for field, value in (("protocolId", 1), ("protocolId", 3), ("identifier", 1)):
            with self.subTest(field=field, value=value):
                item = nlri()
                item[field] = value
                with self.assertRaises(AssertionError):
                    VERIFY.native_objects(native_table(item))

    def test_nonzero_pseudonode_and_malformed_identity_are_rejected(self):
        for identity in ("0000.0000.0001.01", "0000.0000.0001", "192.0.2.1", "garbage"):
            with self.subTest(identity=identity), self.assertRaises(AssertionError):
                VERIFY.native_objects(native_table(nlri(local=identity)))

    def test_nonzero_remote_pseudonode_is_rejected(self):
        item = nlri("link")
        item["remoteNodeDescriptors"]["igpRouterId"] = "0000.0000.0003.01"
        with self.assertRaises(AssertionError):
            VERIFY.native_objects(native_table(item))

    def test_duplicate_presentation_cannot_be_silently_flattened(self):
        for kind in ("node", "link", "ipv4Prefix"):
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                VERIFY.native_objects(native_table(nlri(kind), nlri(kind)))

    def test_unknown_nlri_are_rejected_by_dual_stack_baseline(self):
        for kind in ("unknown", "srv6Sid"):
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                VERIFY.native_objects(native_table(nlri(kind)))

    def test_requires_exactly_one_valid_best_path_per_nlri(self):
        for paths in (
            [],
            [{"valid": False, "bestpath": True, "nlri": nlri()}],
            [{"valid": True, "bestpath": False, "nlri": nlri()}],
            [{"valid": True, "bestpath": True, "nlri": nlri()}] * 2,
        ):
            with self.subTest(paths=paths), self.assertRaises(AssertionError):
                VERIFY.native_objects({"routes": {"synthetic": paths}})

    def test_invalid_ipv4_prefix_is_not_normalized_into_a_valid_object(self):
        for prefix in ("10.0.0.1/24", "10.0.0.0/33", "example.net/32", "2001:db8::/32"):
            item = nlri("ipv4Prefix")
            item["prefixDescriptors"]["ipReachabilityInformation"] = prefix
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                VERIFY.native_objects(native_table(item))


class ReflectedRouteTests(unittest.TestCase):
    def test_both_reflectors_with_correct_originator_pass(self):
        table = {"paths": [reflected_path("10.255.0.1"), reflected_path("10.255.0.2")]}
        self.assertTrue(VERIFY.reflected_by_both(table, "10.255.0.5"))

    def test_one_reflector_or_duplicate_path_does_not_prove_both(self):
        path = reflected_path("10.255.0.1")
        for paths in ([path], [path, copy.deepcopy(path)]):
            with self.subTest(paths=paths):
                self.assertFalse(VERIFY.reflected_by_both({"paths": paths}, "10.255.0.5"))

    def test_wrong_originator_or_invalid_path_does_not_count(self):
        for second in (
            reflected_path("10.255.0.2", originator="10.255.0.4"),
            reflected_path("10.255.0.2", valid=False),
        ):
            table = {"paths": [reflected_path("10.255.0.1"), second]}
            with self.subTest(second=second):
                self.assertFalse(VERIFY.reflected_by_both(table, "10.255.0.5"))

    def test_kernel_route_and_missing_attributes_are_not_reflection_proof(self):
        tables = (
            {},
            {"10.255.0.5/32": [{"protocol": "isis", "selected": True}]},
            {"paths": [{"valid": True, "originatorId": "10.255.0.5"}]},
            {"paths": [{"valid": True, "clusterList": {"list": ["10.255.0.1", "10.255.0.2"]}}]},
        )
        for table in tables:
            with self.subTest(table=table):
                self.assertFalse(VERIFY.reflected_by_both(table, "10.255.0.5"))

    def test_single_serially_reflected_path_does_not_prove_both_rr_sessions(self):
        path = reflected_path("10.255.0.1")
        path["clusterList"]["list"].append("10.255.0.2")
        self.assertFalse(VERIFY.reflected_by_both({"paths": [path]}, "10.255.0.5"))

    def test_peer_must_match_the_single_cluster_attribute(self):
        for peer in ({}, {"routerId": "10.255.0.1"}, {"routerId": "192.0.2.123"}):
            second = reflected_path("10.255.0.2")
            second["peer"] = peer
            table = {"paths": [reflected_path("10.255.0.1"), second]}
            with self.subTest(peer=peer):
                self.assertFalse(VERIFY.reflected_by_both(table, "10.255.0.5"))

    def test_missing_peer_does_not_count_even_with_valid_cluster_and_originator(self):
        first = reflected_path("10.255.0.1")
        second = reflected_path("10.255.0.2")
        del second["peer"]
        self.assertFalse(VERIFY.reflected_by_both({"paths": [first, second]}, "10.255.0.5"))


class PCAPTests(unittest.TestCase):
    def validate(self, data):
        with tempfile.TemporaryDirectory(prefix="bgpls-verifier-test-") as directory:
            path = Path(directory) / "synthetic.pcap"
            path.write_bytes(data)
            return VERIFY.validate_pcap(path)

    def test_complete_exchange_counts_messages_and_records(self):
        self.assertEqual(self.validate(complete_exchange()), {
            "records": 2, "bgp_messages_by_type": {1: 2, 2: 1, 4: 8},
        })

    def test_tcp_payload_fragmentation_keeps_directions_separate(self):
        self.assertEqual(self.validate(complete_exchange(split=True)), {
            "records": 4, "bgp_messages_by_type": {1: 2, 2: 1, 4: 8},
        })

    def test_ipv6_complete_and_split_exchanges_count_identically(self):
        for split in (False, True):
            with self.subTest(split=split):
                self.assertEqual(self.validate(complete_exchange(split, family=6)), {
                    "records": 4 if split else 2, "bgp_messages_by_type": {1: 2, 2: 1, 4: 8},
                })

    def test_ipv6_direction_keys_include_both_addresses_and_ports(self):
        packet = VERIFY.WIRE.PCAP.tcp_packet(tcp_packet(b"", family=6, addresses=("2001:db8::1", "2001:db8::2")))
        self.assertEqual(packet["stream_key"], (6, "2001:db8::1", 50000, "2001:db8::2", 11790))
        self.assertEqual(packet["stream"], "[2001:db8::1]:50000->[2001:db8::2]:11790")

    def test_same_ports_cannot_join_different_family_or_address_streams(self):
        payload = bgp_open("192.0.2.101") * 2 + bgp_message(2, b"\0\0\0\0") + bgp_message(4) * 8
        cases = ((4, ("127.0.0.1", "127.0.0.1")),
                 (6, ("::2", "::1")), (6, ("::1", "::2")))
        for family, addresses in cases:
            with self.subTest(family=family, addresses=addresses), self.assertRaises(AssertionError):
                self.validate(pcap(tcp_packet(payload[:7], family=6),
                                   tcp_packet(payload[7:], sequence=8, family=family, addresses=addresses)))

    def test_ipv6_family_version_and_os_family_codes_are_rejected(self):
        for family_code in (2, 10, 28, 30, 999):
            packet = bytearray(tcp_packet(bgp_message(4), family=6))
            struct.pack_into("<I", packet, 0, family_code)
            with self.subTest(family=family_code), self.assertRaises(AssertionError):
                self.validate(pcap(packet))
        packet = bytearray(tcp_packet(bgp_message(4), family=6))
        packet[4] = 0x45
        with self.assertRaises(AssertionError):
            self.validate(pcap(packet))

    def test_ipv6_lengths_headers_jumbograms_and_extensions_fail_closed(self):
        valid = tcp_packet(bgp_message(4), family=6)
        for cut in (3, 4, 43, 44, 63):
            with self.subTest(cut=cut), self.assertRaises(AssertionError):
                self.validate(pcap(valid[:cut]))
        for length in (0, 19, 38, 40, 65535):
            packet = bytearray(valid)
            struct.pack_into("!H", packet, 8, length)
            with self.subTest(payload_length=length), self.assertRaises(AssertionError):
                self.validate(pcap(packet))
        for header in (0, 17, 43, 44, 50, 51, 58, 59, 60):
            packet = bytearray(valid)
            packet[10] = header
            with self.subTest(next_header=header), self.assertRaises(AssertionError):
                self.validate(pcap(packet))
        for offset in (0x00, 0x40, 0xF0):
            packet = bytearray(valid)
            packet[44 + 12] = offset
            with self.subTest(tcp_header=offset), self.assertRaises(AssertionError):
                self.validate(pcap(packet))

    def test_tcp_gaps_retransmissions_and_reordering_are_rejected_in_both_families(self):
        message = bgp_message(4)
        for family in (4, 6):
            for sequence in (1, len(message), len(message) + 2):
                with self.subTest(family=family, sequence=sequence), self.assertRaisesRegex(AssertionError, "TCP gap"):
                    self.validate(pcap(tcp_packet(message, family=family),
                                       tcp_packet(message, family=family, sequence=sequence)))

    def test_invalid_microseconds_and_record_exceeding_snaplen_are_rejected(self):
        for field, value in ((28, 1_000_000), (16, 1)):
            data = bytearray(complete_exchange(family=6))
            struct.pack_into("<I", data, field, value)
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.validate(data)

    def test_oversized_bgp_and_unknown_message_type_are_rejected(self):
        for family in (4, 6):
            for payload in (bgp_message(2, bytes(4096 - 19 + 1)), bgp_message(0), bgp_message(6)):
                with self.subTest(family=family), self.assertRaises(AssertionError):
                    self.validate(pcap(tcp_packet(payload, family=family)))

    def test_global_header_truncation_magic_and_link_type_are_rejected(self):
        data = complete_exchange()
        wrong_link_type = bytearray(data)
        struct.pack_into("<I", wrong_link_type, 20, 1)
        for malformed in (b"", data[:23], b"\x00" + data[1:], wrong_link_type):
            with self.subTest(length=len(malformed)), self.assertRaises(AssertionError):
                self.validate(malformed)

    def test_record_header_and_packet_truncation_are_rejected(self):
        data = complete_exchange()
        for malformed in (data[:24] + b"\x00", data[:-1]):
            with self.subTest(length=len(malformed)), self.assertRaises(AssertionError):
                self.validate(malformed)

    def test_snaplen_truncation_is_rejected_even_when_record_bytes_are_complete(self):
        data = bytearray(complete_exchange())
        captured = struct.unpack_from("<I", data, 32)[0]
        struct.pack_into("<I", data, 36, captured + 1)
        with self.assertRaises(AssertionError):
            self.validate(data)

    def test_non_tcp_or_non_ipv4_packet_is_rejected(self):
        packet = bytearray(tcp_packet(bgp_message(4)))
        for offset, value in ((4, 0x65), (13, 17)):
            malformed = bytearray(packet)
            malformed[offset] = value
            with self.subTest(offset=offset), self.assertRaises(AssertionError):
                self.validate(pcap(malformed))

    def test_ipv4_header_length_bounds_are_checked_before_tcp_access(self):
        for header_length in (0x40, 0x44, 0x4F):
            packet = bytearray(tcp_packet(b""))
            packet[4] = header_length
            with self.subTest(header_length=header_length), self.assertRaises(AssertionError):
                self.validate(pcap(packet))

    def test_ipv4_total_length_must_match_the_complete_capture(self):
        for delta in (-1, 1):
            packet = bytearray(tcp_packet(bgp_message(4)))
            struct.pack_into("!H", packet, 6, len(packet) - 4 + delta)
            with self.subTest(delta=delta), self.assertRaises(AssertionError):
                self.validate(pcap(packet))

    def test_tcp_header_length_bounds_are_checked_before_payload_access(self):
        for header_length in (0x00, 0x40, 0xF0):
            packet = bytearray(tcp_packet(b""))
            packet[4 + 20 + 12] = header_length
            with self.subTest(header_length=header_length), self.assertRaises(AssertionError):
                self.validate(pcap(packet))

    def test_bgp_header_marker_length_and_truncated_body_are_rejected(self):
        malformed = (
            b"\xff" * 18,
            b"\x00" * 16 + struct.pack("!HB", 19, 4),
            b"\xff" * 16 + struct.pack("!HB", 18, 4),
            b"\xff" * 16 + struct.pack("!HB", 23, 2) + b"\x00",
        )
        for payload in malformed:
            with self.subTest(payload=payload.hex()), self.assertRaises(AssertionError):
                self.validate(pcap(tcp_packet(payload)))

    def test_complete_file_still_requires_open_update_and_keepalive_exchange(self):
        for payload in (
            b"",
            bgp_message(4) * 8,
            bgp_open("127.0.0.1") * 2 + bgp_message(4) * 8,
            bgp_open("127.0.0.1") * 2 + bgp_message(2, b"\x00\x00\x00\x00"),
        ):
            with self.subTest(length=len(payload)), self.assertRaises(AssertionError):
                self.validate(pcap(tcp_packet(payload)))


if __name__ == "__main__":
    unittest.main()
