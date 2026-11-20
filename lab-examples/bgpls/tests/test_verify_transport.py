#!/usr/bin/env python3
"""Offline transport/ownership integration: no Docker, Orb, or network I/O."""

import argparse
import copy
import contextlib
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import signal
import struct
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("transport_verify", ROOT / "verify.py")
CEOS = load("transport_ceos", ROOT / "verify-ceos.py")
FIXTURE = load("transport_fixtures", ROOT / "tests/test_verify.py")


def open_body(identifier, asn, *, mp=True, as4=True, my_as=None, options=None):
    if options is None:
        values = bytes.fromhex("010440040047") if mp else b""
        if as4:
            values += bytes([65, 4]) + struct.pack("!I", asn)
        options = bytes([2, len(values)]) + values if values else b""
    return struct.pack("!BHH4sB", 4, (asn if asn <= 65535 else 23456) if my_as is None else my_as,
                       9, ipaddress.IPv4Address(identifier).packed, len(options)) + options


def qualified_capture(expected, *, client_identifier=None, peer_identifier=None, caps=(True, True),
                      as4=(True, True), asns=None, my_as=(None, None), options=(None, None),
                      next_hop=b"\x0a\xff\x00\x05", finish=True, extra=False):
    """Complete synthetic NIO handshake/exchange/close, with real OPEN structure."""
    def opened(identifier, direction):
        asn = expected["asn"] if asns is None else asns[direction]
        return FIXTURE.bgp_message(1, open_body(
            identifier, asn, mp=caps[direction], as4=as4[direction],
            my_as=my_as[direction], options=options[direction]))
    reach = struct.pack("!HBB", 16388, 71, len(next_hop)) + next_hop + b"\0"
    attribute = bytes([0x80, 14, len(reach)]) + reach
    update = FIXTURE.bgp_message(2, b"\0\0" + struct.pack("!H", len(attribute)) + attribute)
    keepalive = FIXTURE.bgp_message(4)
    outbound = opened(client_identifier or expected["identifier"], 0) + keepalive * 4
    inbound = opened(peer_identifier or expected["router_identifier"], 1) + update + keepalive * 4
    packets = []
    for reverse, payload in ((False, outbound), (True, inbound)):
        addresses = (expected["source"], expected["peer"])
        ports = (50000, expected["port"])
        if reverse:
            addresses, ports = addresses[::-1], ports[::-1]
        def packet(body, sequence, flags):
            value = bytearray(FIXTURE.tcp_packet(body, ports, family=expected["family"],
                                               sequence=sequence, addresses=addresses))
            value[4 + (20 if expected["family"] == 4 else 40) + 13] = flags
            return bytes(value)
        packets += [packet(b"", 1, 0x12 if reverse else 2), packet(payload, 2, 0x18)]
        if finish:
            packets.append(packet(b"", 2 + len(payload), 0x11))
    if extra:
        packets.append(FIXTURE.tcp_packet(b"", (51000, 179), family=6,
                                          addresses=("2001:db8::1", "2001:db8::2")))
    return FIXTURE.pcap(*packets)


class CaptureQualificationTests(unittest.TestCase):
    def audit(self, data, expected):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "complete.pcap"
            path.write_bytes(data)
            return BASE.validate_pcap(path, expected)

    def test_both_transports_and_producers_prove_independent_identifier_capabilities_and_completion(self):
        for transport in ("ipv4", "ipv6"):
            for producer in ("frr", "ceos"):
                for asn in (65001, 4200000001):
                    with self.subTest(transport=transport, producer=producer, asn=asn):
                        expected = BASE.capture_expectation(producer, transport, asn)
                        result = self.audit(qualified_capture(expected), expected)
                        self.assertEqual(result["flow"]["family"], 4 if transport == "ipv4" else 6)
                        self.assertEqual(result["flow"]["client_port"], 50000)
                        self.assertEqual(result["opens"]["collector"]["identifier"], expected["identifier"])
                        self.assertEqual(result["opens"]["producer"]["identifier"], expected["router_identifier"])
                        for opened in result["opens"].values():
                            self.assertEqual(opened["multiprotocol_capabilities"], [(16388, 71)])
                            self.assertEqual(opened["my_as"], asn if asn <= 65535 else 23456)
                            self.assertEqual(opened["four_byte_asn"], asn)
                            self.assertEqual(opened["effective_asn"], asn)

    def test_asn_mismatch_missing_capability_and_wrong_my_as_fail_in_either_direction(self):
        for transport in ("ipv4", "ipv6"):
            for asn in (65001, 4200000001):
                expected = BASE.capture_expectation("frr", transport, asn)
                for direction in (0, 1):
                    mismatched = [asn, asn]
                    mismatched[direction] = asn + 1
                    missing = [True, True]
                    missing[direction] = False
                    wrong_my_as = [None, None]
                    wrong_my_as[direction] = 23456 if asn <= 65535 else 65001
                    for mutation in ({"asns": mismatched}, {"as4": missing}, {"my_as": wrong_my_as}):
                        with self.subTest(transport=transport, asn=asn, direction=direction, mutation=mutation), \
                                self.assertRaises(AssertionError):
                            self.audit(qualified_capture(expected, **mutation), expected)

    def test_historical_legacy_collector_is_explicit_and_never_weakens_producer_checks(self):
        for transport in ("ipv4", "ipv6"):
            for producer in ("frr", "ceos"):
                strict = BASE.capture_expectation(producer, transport)
                data = qualified_capture(strict, as4=(False, True))
                with self.subTest(transport=transport, producer=producer), self.assertRaises(AssertionError):
                    self.audit(data, strict)
                legacy = BASE.capture_expectation(producer, transport, legacy_collector=True)
                result = self.audit(data, legacy)
                self.assertIsNone(result["opens"]["collector"]["four_byte_asn"])
                self.assertEqual(result["opens"]["collector"]["effective_asn"], 65001)
                for mutation in ({"as4": (False, False)}, {"asns": (65002, 65001)},
                                 {"asns": (65001, 65002)}):
                    with self.assertRaises(AssertionError):
                        self.audit(qualified_capture(legacy, **mutation), legacy)
        with self.assertRaises(ValueError):
            BASE.capture_expectation("frr", "ipv6", 4200000001, legacy_collector=True)

    def test_capability_lengths_conflicts_and_nested_truncation_fail_in_both_directions(self):
        mp = bytes.fromhex("010440040047")
        for asn in (65001, 4200000001):
            cap = bytes([65, 4]) + struct.pack("!I", asn)
            conflict = bytes([65, 4]) + struct.pack("!I", asn + 1)
            invalid_values = (
                bytes([65, 0]), bytes([65, 3]) + b"\0" * 3, bytes([65, 5]) + b"\0" * 5,
                bytes([65, 4]) + b"\0" * 3, b"\x41", cap + conflict,
            )
            malformed_options = [bytes([2, len(mp + value)]) + mp + value for value in invalid_values]
            malformed_options += [
                b"\x02", bytes([2, len(mp + cap) + 1]) + mp + cap,
                bytes([2, len(mp + cap)]) + mp + cap + bytes([2, len(conflict)]) + conflict,
            ]
            for transport in ("ipv4", "ipv6"):
                expected = BASE.capture_expectation("ceos", transport, asn)
                for direction in (0, 1):
                    for options in malformed_options:
                        pair = [None, None]
                        pair[direction] = options
                        with self.subTest(asn=asn, transport=transport, direction=direction, options=options.hex()), \
                                self.assertRaises(AssertionError):
                            self.audit(qualified_capture(expected, options=pair), expected)

    def test_multiple_optional_parameters_identical_duplicates_and_unknown_capabilities_pass(self):
        for asn in (65001, 4200000001):
            cap = bytes([65, 4]) + struct.pack("!I", asn)
            # Unknown capability values are opaque, even when containing bytes
            # resembling capability 65; duplicates may span parameters.
            unknown = b"\xc8\x03\x41\x04\0"
            options = (bytes.fromhex("0206010440040047")
                       + bytes([2, len(cap + unknown)]) + cap + unknown
                       + bytes([2, len(cap * 2)]) + cap * 2)
            for transport in ("ipv4", "ipv6"):
                expected = BASE.capture_expectation("frr", transport, asn)
                result = self.audit(qualified_capture(expected, options=(options, options)), expected)
                self.assertEqual(result["opens"]["collector"]["effective_asn"], asn)
                self.assertEqual(result["opens"]["producer"]["effective_asn"], asn)

    def test_unsupported_and_empty_capability_parameters_fail_in_both_directions(self):
        for asn in (65001, 4200000001):
            valid = bytes.fromhex("0206010440040047") + bytes([2, 6, 65, 4]) + struct.pack("!I", asn)
            for transport in ("ipv4", "ipv6"):
                expected = BASE.capture_expectation("frr", transport, asn)
                for direction in (0, 1):
                    for parameter in (b"\0\0", b"\x01\0", b"\x63\x02\x41\x04", b"\xff\0", b"\x02\0"):
                        for options in (parameter + valid, valid + parameter):
                            pair = [None, None]
                            pair[direction] = options
                            with self.subTest(asn=asn, transport=transport, direction=direction,
                                              options=options.hex()), self.assertRaisesRegex(
                                                  AssertionError, "optional.parameter"):
                                self.audit(qualified_capture(expected, options=pair), expected)

    def test_open_outer_optional_length_must_match_exact_body_length(self):
        body = open_body("192.0.2.101", 4200000001)
        for malformed in (body[:-1], body + b"\0", body[:9], body[:9] + b"\xff" + body[10:]):
            with self.subTest(body=malformed.hex()), self.assertRaises(AssertionError):
                BASE.open_identity(malformed)

    def test_decoder_records_capability_authority_without_imposing_lab_encoding(self):
        identity = BASE.open_identity(open_body("192.0.2.101", 4200000001, my_as=65001))
        self.assertEqual(identity["my_as"], 65001)
        self.assertEqual(identity["effective_asn"], 4200000001)

    def test_ipv6_socket_does_not_relabel_ipv4_ipv6_or_paired_next_hop_encoding(self):
        expected = BASE.capture_expectation("ceos", "ipv6")
        for packed, encoding, addresses in (
            (ipaddress.IPv4Address("10.255.0.6").packed, "ipv4", ["10.255.0.6"]),
            (ipaddress.IPv6Address("2001:db8::6").packed, "ipv6", ["2001:db8::6"]),
            (ipaddress.IPv6Address("2001:db8::6").packed + ipaddress.IPv6Address("fe80::6").packed,
             "ipv6-pair", ["2001:db8::6", "fe80::6"]),
        ):
            result = self.audit(qualified_capture(expected, next_hop=packed), expected)
            hop = result["mp_reach_next_hops"][0]
            self.assertEqual((hop["encoding"], hop["length"], hop["addresses"]),
                             (encoding, len(packed), addresses))
            self.assertEqual(hop["hex"], packed.hex())

    def test_wrong_bind_peer_family_port_identifiers_capabilities_or_extra_flow_fail(self):
        expected = BASE.capture_expectation("frr", "ipv6")
        for mutation in (
            {"source": "2001:db8::99"}, {"peer": "2001:db8::5"}, {"port": 11790},
            {"family": 4, "source": "127.0.0.1", "peer": "127.0.0.1"},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                self.audit(qualified_capture({**expected, **mutation}), expected)
        for options in ({"client_identifier": "192.0.2.102"}, {"peer_identifier": "10.255.0.6"},
                        {"caps": (False, True)}, {"caps": (True, False)},
                        {"finish": False}, {"extra": True}):
            with self.subTest(options=options), self.assertRaises(AssertionError):
                self.audit(qualified_capture(expected, **options), expected)

    def test_duplicate_open_per_direction_is_not_hidden_by_two_total_opens(self):
        expected = BASE.capture_expectation("frr", "ipv6")
        packets = list(BASE.WIRE.PCAP.tcp_packets(qualified_capture(expected)))
        # Two client OPENs plus none from the peer still satisfy the old total count.
        first_open = packets[1]["payload"][:struct.unpack_from("!H", packets[1]["payload"], 16)[0]]
        body = first_open + first_open + FIXTURE.bgp_message(4) * 8
        update = FIXTURE.bgp_message(2, b"\0\0\0\0")
        data = FIXTURE.pcap(FIXTURE.tcp_packet(body, (50000, 179), family=6,
                                             addresses=(expected["source"], expected["peer"])),
                            FIXTURE.tcp_packet(update, (179, 50000), family=6,
                                               addresses=(expected["peer"], expected["source"])))
        with self.assertRaisesRegex(AssertionError, "more than one OPEN"):
            self.audit(data, expected)


class TransportInputTests(unittest.TestCase):
    def test_native_default_and_explicit_ipv4_require_only_binary(self):
        for explicit in ({}, {"transport": "ipv4"}):
            args = argparse.Namespace(binary=sys.executable, **explicit)
            self.assertEqual(BASE.collector_inputs(args), ("ipv4", Path(sys.executable).resolve(), None))

    def test_ipv6_artifact_validates_before_return_without_launching(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.json"
            artifact.write_text("{}")
            loader = mock.Mock()
            with mock.patch.object(BASE, "helper", return_value=loader), \
                    mock.patch.object(BASE.subprocess, "Popen") as launch:
                result = BASE.collector_inputs(argparse.Namespace(transport="ipv6", artifact=str(artifact)))
            self.assertEqual(result, ("ipv6", None, artifact.resolve()))
            loader.load_artifact.assert_called_once_with(artifact.resolve())
            launch.assert_not_called()

    def test_wrong_transport_artifact_binary_combinations_fail_without_runtime_calls(self):
        for args in (
            dict(transport="ipv6", binary=sys.executable), dict(transport="ipv4", artifact="/unused"),
            dict(transport="ipv6", binary=sys.executable, artifact="/unused"), dict(transport="ipv6"),
        ):
            with self.subTest(args=args), mock.patch.object(BASE, "helper") as helper, self.assertRaises(ValueError):
                BASE.collector_inputs(argparse.Namespace(**args))
            helper.assert_not_called()

    def test_parser_defaults_ipv4_and_forbids_two_executable_sources(self):
        parser = argparse.ArgumentParser()
        BASE.add_transport_arguments(parser)
        self.assertEqual(parser.parse_args(["--binary", sys.executable]).transport, "ipv4")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["--binary", sys.executable, "--artifact", "/unused"])


class SourceAndCompetitionTests(unittest.TestCase):
    def lab(self, transport="ipv6", profile="ceos"):
        lab = CEOS.CeosLab(Path("/unused-state"), Path("/unused-output"), transport)
        lab.state_info = {"transport": "ipv6", "profile": profile, "asn": 65001}
        lab.ids = {"bgpls-relay": "a" * 64}
        lab.save = mock.Mock()
        lab.producer_neighbor = mock.Mock(return_value={"bgpState": "Idle"})
        inspected = {"Id": "a" * 64, "State": {"Running": True, "Pid": 1234, "StartedAt": "2026-10-19T00:00:00Z"},
                     "Config": {"Labels": {"containerlab": "bgpls", "clab-topo-file": "/unused-state/bgpls.clab.yml"}}}
        lab.docker = mock.Mock(return_value=json.dumps([inspected]))
        def command(*args):
            endpoint = next(value["ipv6"] for value in BASE.TRANSPORTS.values()
                            if value["ipv6"]["interface"] == args[-1] or value["ipv6"]["source"] == args[-1])
            if "address" in args:
                return json.dumps([{"addr_info": [{"family": "inet6", "local": endpoint["source"],
                                                   "prefixlen": 127, "scope": "global"}]}])
            return json.dumps([{"dev": endpoint["interface"], "from": endpoint["source"]}])
        lab.command = mock.Mock(side_effect=command)
        return lab

    def test_ipv4_regression_on_ipv6_deployment_still_checks_both_families_and_namespace(self):
        lab = self.lab("ipv4")
        state = mock.Mock(spec=["assert_no_namespace_holders"])
        with mock.patch.object(CEOS.BASE, "helper", return_value=state):
            lab.transport_preflight(("frr", "ceos"))
        self.assertEqual(lab.producer_neighbor.call_args_list, [
            mock.call("frr", "ipv4"), mock.call("frr", "ipv6"),
            mock.call("ceos", "ipv4"), mock.call("ceos", "ipv6"),
        ])
        state.assert_no_namespace_holders.assert_called_once()
        lab.docker.assert_not_called()

    def test_any_configured_active_collector_refuses_both_execution_modes(self):
        for mode in ("ipv4", "ipv6"):
            for family in ("ipv4", "ipv6"):
                for status in ("Established", "OpenSent", "OpenConfirm"):
                    lab = self.lab(mode)
                    lab.producer_neighbor.side_effect = lambda _producer, transport: {
                        "bgpState": status if transport == family else "Idle"}
                    with self.subTest(mode=mode, family=family, status=status), \
                            self.assertRaisesRegex(AssertionError, "already connected"):
                        lab.transport_preflight(("frr", "ceos"))
                    lab.docker.assert_not_called()

    def test_malformed_neighbor_schema_is_fatal_not_readiness_retry(self):
        lab = self.lab()
        lab.producer_neighbor.return_value = {}
        with self.assertRaises(KeyError):
            lab.transport_preflight(("frr",))
        lab.producer_neighbor.return_value = {"bgpState": "Unknown"}
        with self.assertRaisesRegex(AssertionError, "unrecognized"):
            lab.transport_preflight(("frr",))

    def test_direct_ipv6_sources_are_checked_in_immutable_relay_namespace(self):
        lab = self.lab()
        with mock.patch.object(CEOS.BASE, "helper", return_value=mock.Mock(spec=["assert_no_namespace_holders"])):
            lab.transport_preflight(("frr", "ceos"))
        self.assertEqual(lab.docker.call_count, 8)
        for call in lab.docker.call_args_list:
            self.assertEqual(call.args, ("inspect", "a" * 64))
        self.assertEqual(lab.command.call_count, 4)
        for call in lab.command.call_args_list:
            self.assertEqual(call.args[:8], ("nsenter", "--target", "1234", "--net", "--", "ip", "-j", "-6"))

    def test_invalid_relay_identity_refuses_before_entering_any_namespace(self):
        for mutate in (
            lambda value: value.update(Id="b" * 64),
            lambda value: value["State"].update(Running=False),
            lambda value: value["State"].update(Pid=0),
            lambda value: value["State"].update(Pid=-1),
            lambda value: value["State"].update(Pid=True),
            lambda value: value["State"].update(Pid="1234"),
            lambda value: value["State"].update(StartedAt=""),
            lambda value: value["Config"]["Labels"].update(containerlab="other-lab"),
            lambda value: value["Config"]["Labels"].update({"clab-topo-file": "/other/bgpls.clab.yml"}),
        ):
            lab = self.lab()
            inspected = json.loads(lab.docker.return_value)[0]
            mutate(inspected)
            lab.docker.return_value = json.dumps([inspected])
            with self.subTest(mutate=mutate), self.assertRaisesRegex(AssertionError, "identity"):
                lab.relay_ip_json("address", "show", "dev", "eth1")
            lab.command.assert_not_called()
        lab = self.lab()
        lab.ids["bgpls-relay"] = "clab-bgpls-bgpls-relay"
        with self.assertRaisesRegex(AssertionError, "immutable"):
            lab.relay_ip_json("address", "show", "dev", "eth1")
        lab.docker.assert_not_called()
        lab.command.assert_not_called()

    def test_relay_restart_or_ownership_change_during_read_rejects_output(self):
        for mutate in (
            lambda value: value["State"].update(Pid=5678),
            lambda value: value["State"].update(StartedAt="2026-10-19T00:01:00Z"),
            lambda value: value["State"].update(Running=False),
            lambda value: value["Config"]["Labels"].update(containerlab="other-lab"),
        ):
            lab = self.lab()
            before = json.loads(lab.docker.return_value)[0]
            after = copy.deepcopy(before)
            mutate(after)
            lab.docker.side_effect = [json.dumps([before]), json.dumps([after])]
            with self.subTest(mutate=mutate), self.assertRaises(AssertionError):
                lab.relay_ip_json("address", "show", "dev", "eth1")
            lab.command.assert_called_once()

    def test_missing_host_tools_privileges_or_bad_json_fail_with_no_container_exec(self):
        for error in (FileNotFoundError("nsenter"), RuntimeError("Operation not permitted")):
            lab = self.lab()
            lab.command.side_effect = error
            with self.subTest(error=error), self.assertRaisesRegex(RuntimeError, "requires host iproute2.*permission"):
                lab.relay_ip_json("address", "show", "dev", "eth1")
            lab.docker.assert_called_once_with("inspect", "a" * 64)
        for output in ("not JSON", "{}"):
            lab = self.lab()
            lab.command.side_effect = None
            lab.command.return_value = output
            with self.subTest(output=output), self.assertRaisesRegex(AssertionError, "JSON"):
                lab.relay_ip_json("address", "show", "dev", "eth1")
            self.assertEqual(lab.docker.call_count, 2)

    def test_source_dad_prefix_interface_gateway_and_route_identity_fail_closed(self):
        for mutation in (
            lambda address, route: address.update(tentative=True),
            lambda address, route: address.update(dadfailed=True),
            lambda address, route: address.update(flags=["tentative"]),
            lambda address, route: address.update(prefixlen=64),
            lambda address, route: address.update(local="2001:db8::bad"),
            lambda address, route: route.update(dev="eth0"),
            lambda address, route: route.update(gateway="fe80::1"),
            lambda address, route: route.update(**{"from": "2001:db8::bad"}),
        ):
            lab = self.lab()
            endpoint = BASE.TRANSPORTS["frr"]["ipv6"]
            address = {"family": "inet6", "local": endpoint["source"], "prefixlen": 127, "scope": "global"}
            route = {"dev": "eth1", "from": endpoint["source"]}
            mutation(address, route)
            lab.command.side_effect = [json.dumps([{"addr_info": [address]}]), json.dumps([route])]
            with self.subTest(mutation=mutation), mock.patch.object(CEOS.BASE, "helper", return_value=mock.Mock(spec=["assert_no_namespace_holders"])), \
                    self.assertRaises(AssertionError):
                lab.transport_preflight(("frr",))

    def test_foreign_namespace_holder_refuses_before_source_checks(self):
        lab = self.lab()
        helper = mock.Mock(spec=["assert_no_namespace_holders"])
        helper.assert_no_namespace_holders.side_effect = AssertionError("namespace holder exists")
        with mock.patch.object(CEOS.BASE, "helper", return_value=helper), self.assertRaisesRegex(AssertionError, "holder"):
            lab.transport_preflight(("frr",))
        lab.docker.assert_not_called()

    def test_producer_socket_actuals_require_matching_family_bind_and_port179(self):
        for producer in ("frr", "ceos"):
            for transport in ("ipv4", "ipv6"):
                endpoint = BASE.TRANSPORTS[producer][transport]
                actual = {"hostForeign": endpoint["source"], "hostLocal": endpoint["peer"],
                          "portForeign": 40000, "portLocal": 179, "localAs": 4200000001, "remoteAs": 4200000001}
                BASE.assert_neighbor_endpoint(actual, producer, transport, 4200000001)
                for replacement in ({"hostForeign": "::1"}, {"hostLocal": "::1"},
                                    {"portLocal": 11790}, {"portForeign": 0},
                                    {"localAs": 65001}, {"remoteAs": 65001},
                                    {"localAs": "4200000001"}, {"remoteAs": True}):
                    with self.subTest(producer=producer, transport=transport, replacement=replacement), \
                            self.assertRaises(AssertionError):
                        BASE.assert_neighbor_endpoint({**actual, **replacement}, producer, transport, 4200000001)


class OfflineRunIntegrationTests(unittest.TestCase):
    def test_empty_native_tables_are_preserved_as_evidence_before_readiness_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            frr = BASE.Lab(path, path)
            frr.vty = mock.Mock(return_value={"routes": {}})
            self.assertEqual(frr.native_objects(), set())
            self.assertEqual(json.loads((path / "frr-link-state-latest.json").read_text()), {"routes": {}})
            ceos = CEOS.CeosLab(path, path)
            ceos.state_info = {"asn": 65001}
            table = {"vrfs": {"default": {"bgpLsRoutes": {}}}}
            ceos.native_table = mock.Mock(return_value=table)
            self.assertEqual(ceos.native_objects("ceos"), set())
            self.assertEqual(json.loads((path / "ceos-link-state-latest.json").read_text()), table)

    def test_lock_encloses_preflight_and_cleanup_in_both_modes_and_profiles(self):
        for module in (BASE, CEOS):
            for transport in ("ipv4", "ipv6"):
                events = []
                @contextlib.contextmanager
                def locked(_state):
                    events.append("locked")
                    try:
                        yield
                    finally:
                        events.append("unlocked")
                def run(*_args):
                    events.append("preflight-through-cleanup")
                    raise RuntimeError("mock failure")
                base = BASE if module is BASE else CEOS.BASE
                with tempfile.TemporaryDirectory() as directory, \
                        mock.patch.object(base, "collector_inputs", return_value=(transport, None, None)), \
                        mock.patch.object(base, "verification_lock", side_effect=locked), \
                        mock.patch.object(module, "run_locked", side_effect=run), self.assertRaises(RuntimeError):
                    module.run(argparse.Namespace(state=directory))
                self.assertEqual(events, ["locked", "preflight-through-cleanup", "unlocked"])

    def test_frr_ipv6_start_has_fresh_paths_and_prelaunch_readiness_failure_never_creates_collector(self):
        for fail_readiness in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                state = Path(directory).resolve()
                lab, factory, process = mock.Mock(), mock.Mock(), mock.Mock()
                events = []
                baseline = BASE.expected_links() | BASE.expected_loopbacks() | {f"node {v}" for v in BASE.IDS.values()}
                lab.native_objects.return_value = baseline
                lab.neighbor.return_value = {"hostForeign": BASE.TRANSPORTS["frr"]["ipv6"]["source"]}
                process.returncode = None
                process.poll.return_value = None
                def construct(_lab, producer, artifact, output, log, pcap):
                    self.assertFalse(log.exists(), "container runner requires a fresh log path")
                    self.assertFalse(pcap.exists())
                    self.assertEqual(producer, "frr")
                    events.append("construct")
                    process.start.side_effect = RuntimeError("mock failure after container creation")
                    return process
                factory.ContainerProcess.side_effect = construct
                def wait(description, condition, *args):
                    events.append(description)
                    if fail_readiness:
                        raise TimeoutError("native baseline unavailable")
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.object(BASE, "Lab", return_value=lab))
                    stack.enter_context(mock.patch.object(BASE, "helper", return_value=factory))
                    stack.enter_context(mock.patch.object(BASE, "wait_until", side_effect=wait))
                    stack.enter_context(mock.patch.object(BASE.signal, "signal"))
                    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                    with self.assertRaises(TimeoutError if fail_readiness else RuntimeError):
                        BASE.run_locked(argparse.Namespace(churn=False, signal="INT"), state, "ipv6", None, state / "artifact.json")
                if fail_readiness:
                    factory.ContainerProcess.assert_not_called()
                    process.cleanup.assert_not_called()
                    lab.save.assert_called_with("failure", {"type": "TimeoutError", "error": "native baseline unavailable",
                                                           "transport": "ipv6"})
                else:
                    self.assertEqual(events[:3], ["routing is ready before starting the collector",
                                                "native FRR BGP-LS baseline is ready before starting the collector", "construct"])
                    process.cleanup.assert_called_once()

    def test_frr_ipv6_complete_mock_run_refreshes_log_audits_capture_then_cleans_owned_runner(self):
        result = self.exercise_frr_completion()
        self.assertEqual(result["saved"]["result"]["container"], {"removed": True})
        self.assertIn("PASS: nodes=5", result["stdout"])

    def test_frr_completion_uses_state_asn_in_both_transports_and_result_metadata(self):
        for transport in ("ipv4", "ipv6"):
            for asn in (65001, 4200000001):
                with self.subTest(transport=transport, asn=asn):
                    result = self.exercise_frr_completion(transport=transport, asn=asn)
                    self.assertEqual(result["saved"]["result"]["asn"], asn)
                    self.assertEqual(result["saved"]["result"]["transport"], transport)

    def exercise_frr_completion(self, *, cleanup_error=None, primary_error=None, result_error=None,
                                transport="ipv6", asn=65001):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            baseline = BASE.expected_links() | BASE.expected_loopbacks() | {f"node {v}" for v in BASE.IDS.values()}
            lab, factory, process = mock.Mock(), mock.Mock(), mock.Mock()
            lab.state_info = {"asn": asn}
            endpoint = BASE.TRANSPORTS["frr"][transport]
            lab.native_objects.return_value = baseline
            lab.verify_routing.return_value = True
            lab.neighbor.return_value = {
                "bgpState": "Established", "hostForeign": endpoint["source"], "hostLocal": endpoint["peer"],
                "portForeign": 40000, "portLocal": 179, "connectionsEstablished": 1, "connectionsDropped": 0,
                "localAs": asn, "remoteAs": asn,
                "bgpTimerUpMsec": 12000, "messageStats": {"keepalivesRecv": 5, "keepalivesSent": 5},
            }
            process.poll.return_value = None
            process.metadata = {"removed": False}
            saved = {}
            def save(name, value):
                if name == "result" and result_error is not None:
                    raise result_error
                saved[name] = copy.deepcopy(value)
            lab.save.side_effect = save
            def cleanup():
                if cleanup_error is not None:
                    raise cleanup_error
                process.metadata["removed"] = True
            process.cleanup.side_effect = cleanup
            def construct(_lab, producer, artifact, output, log, pcap):
                if transport == "ipv6":
                    self.assertFalse(log.exists())
                self.assertFalse(pcap.exists())
                def started():
                    log.write_text("bgpls: state Established\n" + "".join(f"WATCH upsert {v}\n" for v in sorted(baseline)))
                def waited(timeout):
                    self.assertEqual(timeout, 15)
                    with log.open("a") as stream:
                        stream.write("bgpls: SIGINT — stopping session…\nbgpls: RIB final\n"
                                     + BASE.rib_summary(baseline) + "\n" + "\n".join(sorted(baseline)) + "\n")
                    process.poll.return_value = 130
                    return 130
                process.start.side_effect = started
                process.wait.side_effect = waited
                return process
            factory.ContainerProcess.side_effect = construct
            def launch(arguments, *, stdout, stderr):
                for option in ("--local-as", "--peer-as"):
                    self.assertEqual(arguments[arguments.index(option) + 1], str(asn))
                self.assertEqual(arguments.count("--dump-rib"), 1)
                log = Path(stdout.name)
                construct(lab, "frr", None, log.parent, log, log.with_suffix(".pcap"))
                process.start()
                return process
            def ready(_description, condition, _process=None):
                self.assertTrue(condition())
            stdout = io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(BASE, "Lab", return_value=lab))
                stack.enter_context(mock.patch.object(BASE, "helper", return_value=factory))
                stack.enter_context(mock.patch.object(BASE, "wait_until", side_effect=ready))
                stack.enter_context(mock.patch.object(BASE.subprocess, "Popen", side_effect=launch))
                capture = stack.enter_context(mock.patch.object(
                    BASE, "validate_pcap", return_value={"verified": True}, side_effect=primary_error))
                stack.enter_context(mock.patch.object(BASE.WIRE, "audit_capture", return_value={"verified": True}))
                stack.enter_context(mock.patch.object(BASE.signal, "signal"))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                error = None
                try:
                    status = BASE.run_locked(argparse.Namespace(churn=False, signal="INT"), state,
                                             transport, Path("/mock-bgpls") if transport == "ipv4" else None,
                                             state / "artifact.json" if transport == "ipv6" else None)
                except Exception as caught:
                    error = caught
                if cleanup_error is None and primary_error is None and result_error is None:
                    self.assertIsNone(error)
                    self.assertEqual(status, 0)
                else:
                    self.assertIsNotNone(error)
            process.send_signal.assert_called_once_with(signal.SIGINT)
            if transport == "ipv6":
                process.cleanup.assert_called_once()
                self.assertGreater(process.refresh.call_count, 0)
            else:
                process.cleanup.assert_not_called()
                process.terminate.assert_not_called()
                process.refresh.assert_not_called()
            self.assertEqual(capture.call_args.args[1], BASE.capture_expectation("frr", transport, asn))
            process.metadata["after_handoff"] = True
            if "result" in saved and transport == "ipv6":
                self.assertNotIn("after_handoff", saved["result"]["container"])
            return {"saved": saved, "error": error, "stdout": stdout.getvalue()}

    def test_frr_cleanup_only_failure_never_publishes_success(self):
        cleanup_error = OSError("owned container removal failed")
        result = self.exercise_frr_completion(cleanup_error=cleanup_error)
        self.assertNotIn("result", result["saved"])
        self.assertNotIn("PASS: nodes=5", result["stdout"])
        self.assertIs(result["error"].failures[0][1], cleanup_error)
        self.assertEqual(result["saved"]["failure"]["cleanup_errors"], [
            {"action": "reap collector", "type": "OSError", "error": str(cleanup_error)},
        ])

    def test_frr_primary_and_cleanup_errors_both_survive(self):
        primary, cleanup = AssertionError("capture failed"), OSError("removal failed")
        result = self.exercise_frr_completion(primary_error=primary, cleanup_error=cleanup)
        self.assertIs(result["error"].primary_error, primary)
        self.assertIs(result["error"].__cause__, primary)
        self.assertIs(result["error"].cleanup_error.failures[0][1], cleanup)
        self.assertNotIn("result", result["saved"])
        self.assertNotIn("PASS: nodes=5", result["stdout"])
        self.assertEqual(result["saved"]["failure"]["primary_error"],
                         {"type": "AssertionError", "error": "capture failed"})
        self.assertEqual(result["saved"]["failure"]["cleanup_errors"][0]["error"], "removal failed")

    def test_frr_result_save_failure_after_cleanup_records_failure_without_pass(self):
        error = OSError("result storage unavailable")
        result = self.exercise_frr_completion(result_error=error)
        self.assertIs(result["error"], error)
        self.assertNotIn("result", result["saved"])
        self.assertNotIn("PASS: nodes=5", result["stdout"])
        self.assertEqual(result["saved"]["failure"]["error"], str(error))

    def test_two_producer_shutdown_orders_keep_survivor_and_cleanup_independent(self):
        for transport in ("ipv4", "ipv6"):
            for reverse in (False, True):
                with tempfile.TemporaryDirectory() as directory:
                    state = Path(directory).resolve()
                    lab = mock.Mock()
                    lab.state_info = {"asn": 65001}
                    collectors = [mock.Mock(producer=name) for name in ("frr", "ceos")]
                    lab.producer_neighbor.side_effect = lambda producer: {
                        "hostForeign": BASE.TRANSPORTS[producer][transport]["source"],
                        "hostLocal": BASE.TRANSPORTS[producer][transport]["peer"],
                        "portForeign": 40000, "portLocal": 179, "localAs": 65001, "remoteAs": 65001}
                    events = []
                    for collector in collectors:
                        collector.start.side_effect = lambda collector=collector: events.append("start-" + collector.producer)
                        def stopped(selected, *_args, collector=collector, **_kw):
                            events.append((collector.producer, selected))
                            return {}
                        collector.stop.side_effect = stopped
                    def readiness(description, _condition):
                        events.append(description)
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(mock.patch.object(CEOS, "CeosLab", return_value=lab))
                        stack.enter_context(mock.patch.object(CEOS, "Collector", side_effect=collectors))
                        stack.enter_context(mock.patch.object(CEOS.BASE, "wait_until", side_effect=readiness))
                        stack.enter_context(mock.patch.object(CEOS, "wait_for"))
                        stack.enter_context(mock.patch.object(CEOS, "same_connection", return_value=True))
                        survivor = stack.enter_context(mock.patch.object(CEOS, "verify_independent_survivor"))
                        stack.enter_context(mock.patch.object(CEOS.signal, "signal"))
                        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                        CEOS.run_locked(argparse.Namespace(churn=False, reverse_shutdown=reverse), state,
                                        transport, Path(sys.executable) if transport == "ipv4" else None,
                                        state / "artifact.json" if transport == "ipv6" else None)
                    self.assertEqual(events[:4], ["routing is ready before starting either collector",
                                                 "both native BGP-LS baselines are ready before starting either collector",
                                                 "start-frr", "start-ceos"])
                    first, second = ("ceos", "frr") if reverse else ("frr", "ceos")
                    self.assertEqual(events[-2:], [(first, signal.SIGINT), (second, signal.SIGTERM)])
                    self.assertEqual(survivor.call_args.args[-2:], (second, first))
                    for collector in collectors:
                        collector.cleanup.assert_called_once()

    def test_ceos_ipv6_constructs_owned_runner_before_start_without_creating_log(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            factory = mock.Mock()
            process = mock.Mock()
            def construct(*args):
                self.assertFalse(args[-2].exists())
                self.assertFalse(args[-1].exists())
                return process
            factory.ContainerProcess.side_effect = construct
            collector = CEOS.Collector("ceos", None, output, lab=mock.Mock(state_info={"asn": 65001}),
                                       artifact=output / "manifest.json", transport="ipv6")
            with mock.patch.object(CEOS.BASE, "helper", return_value=factory):
                collector.start()
                collector.cleanup()
            process.start.assert_called_once()
            process.cleanup.assert_called_once()


class PairedOutcomePublicationTests(unittest.TestCase):
    def exercise(self, *, primary_error=None, cleanup_errors=(None, None), result_error=None, asn=65001):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            lab = mock.Mock()
            lab.state_info = {"asn": asn}
            collectors = [mock.Mock(producer=name) for name in ("frr", "ceos")]
            saved, events = {}, []
            lab.producer_neighbor.side_effect = lambda producer: {
                "hostForeign": BASE.TRANSPORTS[producer]["ipv6"]["source"],
                "hostLocal": BASE.TRANSPORTS[producer]["ipv6"]["peer"],
                "portForeign": 40000, "portLocal": 179, "localAs": asn, "remoteAs": asn,
            }
            for index, collector in enumerate(collectors):
                collector.process.metadata = {"producer": collector.producer, "removed": False}
                collector.stop.return_value = {"exit_status": 130 if index == 0 else 143}
                def cleanup(collector=collector, error=cleanup_errors[index]):
                    events.append("cleanup-" + collector.producer)
                    if error is not None:
                        raise error
                    collector.process.metadata["removed"] = True
                collector.cleanup.side_effect = cleanup
            collectors[0].stop.side_effect = primary_error
            def save(name, value):
                events.append("save-" + name)
                if name == "result":
                    self.assertTrue(all(collector.process.metadata["removed"] for collector in collectors))
                    if result_error is not None:
                        raise result_error
                saved[name] = copy.deepcopy(value)
            lab.save.side_effect = save
            stdout = io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(CEOS, "CeosLab", return_value=lab))
                stack.enter_context(mock.patch.object(CEOS, "Collector", side_effect=collectors))
                stack.enter_context(mock.patch.object(CEOS.BASE, "wait_until"))
                stack.enter_context(mock.patch.object(CEOS, "wait_for"))
                stack.enter_context(mock.patch.object(CEOS, "same_connection", return_value=True))
                stack.enter_context(mock.patch.object(CEOS, "verify_independent_survivor"))
                stack.enter_context(mock.patch.object(CEOS.signal, "signal"))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                error = None
                try:
                    status = CEOS.run_locked(argparse.Namespace(churn=False, reverse_shutdown=False),
                                             state, "ipv6", None, state / "artifact.json")
                except Exception as caught:
                    error = caught
                if primary_error is None and not any(cleanup_errors) and result_error is None:
                    self.assertIsNone(error)
                    self.assertEqual(status, 0)
                else:
                    self.assertIsNotNone(error)
            for collector in collectors:
                collector.cleanup.assert_called_once()
                collector.process.metadata["after_handoff"] = True
            return saved, events, error, stdout.getvalue()

    def test_success_snapshots_both_collectors_only_after_cleanup(self):
        saved, events, error, stdout = self.exercise()
        self.assertEqual(events, ["cleanup-frr", "cleanup-ceos", "save-result"])
        self.assertNotIn("failure", saved)
        for producer, result in saved["result"]["producers"].items():
            self.assertEqual(result["container"], {"producer": producer, "removed": True})
        self.assertIn("PASS: both native RIBs", stdout)

    def test_four_byte_profile_records_the_deployment_asn_after_independent_cleanup(self):
        saved, events, error, stdout = self.exercise(asn=4200000001)
        self.assertIsNone(error)
        self.assertEqual(saved["result"]["asn"], 4200000001)
        self.assertEqual(events, ["cleanup-frr", "cleanup-ceos", "save-result"])

    def test_cleanup_only_failure_still_attempts_second_collector_and_never_publishes_success(self):
        cleanup_error = OSError("first removal failed")
        saved, events, error, stdout = self.exercise(cleanup_errors=(cleanup_error, None))
        self.assertEqual(events, ["cleanup-frr", "cleanup-ceos", "save-failure"])
        self.assertIs(error.failures[0][1], cleanup_error)
        self.assertNotIn("result", saved)
        self.assertNotIn("PASS: both native RIBs", stdout)
        self.assertEqual(saved["failure"]["cleanup_errors"][0]["action"], "reap frr")

    def test_primary_and_both_cleanup_failures_preserve_each_original_error(self):
        primary = AssertionError("FRR capture failed")
        failures = (OSError("FRR removal failed"), RuntimeError("cEOS removal failed"))
        saved, events, error, stdout = self.exercise(primary_error=primary, cleanup_errors=failures)
        self.assertEqual(events, ["cleanup-frr", "cleanup-ceos", "save-failure"])
        self.assertIs(error.primary_error, primary)
        self.assertIs(error.__cause__, primary)
        self.assertEqual(tuple(failure for _, failure in error.cleanup_error.failures), failures)
        self.assertEqual(saved["failure"]["primary_error"]["error"], str(primary))
        self.assertEqual([item["error"] for item in saved["failure"]["cleanup_errors"]],
                         [str(failure) for failure in failures])
        self.assertNotIn("result", saved)
        self.assertNotIn("PASS: both native RIBs", stdout)

    def test_result_save_failure_cannot_print_success_after_both_cleanups(self):
        failure = OSError("result storage unavailable")
        saved, events, error, stdout = self.exercise(result_error=failure)
        self.assertEqual(events, ["cleanup-frr", "cleanup-ceos", "save-result", "save-failure"])
        self.assertIs(error, failure)
        self.assertNotIn("result", saved)
        self.assertEqual(saved["failure"]["error"], str(failure))
        self.assertNotIn("PASS: both native RIBs", stdout)


if __name__ == "__main__":
    unittest.main()
