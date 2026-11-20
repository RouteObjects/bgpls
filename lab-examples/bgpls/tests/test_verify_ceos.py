#!/usr/bin/env python3
"""Offline two-producer lifecycle checks; no Docker calls or real process signals."""

import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "bgpls_ceos_verify", Path(__file__).resolve().parents[1] / "verify-ceos.py"
)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def normalized_neighbor(source="10.254.254.3"):
    return {
        "bgpState": "Established", "connectionsEstablished": 1, "connectionsDropped": 0,
        "localAs": 65001, "remoteAs": 65001,
        "hostForeign": source, "portForeign": 40000,
        "hostLocal": "10.254.254.0" if source == "10.254.254.1" else "10.254.254.2",
        "portLocal": 179, "bgpTimerUpMsec": 12000,
        "messageStats": {"keepalivesSent": 5, "keepalivesRecv": 5},
    }


def completed_log(objects=None):
    objects = VERIFY.expected_objects() if objects is None else objects
    return ("bgpls: state Established\n"
            + "".join(f"bgpls: WATCH upsert {value}\n" for value in sorted(objects))
            + "bgpls: SIGINT — stopping session…\n"
            + "bgpls: RIB final\nnodes=6 links=18 prefixes=12\n"
            + "\n".join(sorted(objects)) + "\n")


def ownership_files(state):
    state = state.resolve()
    topology = state / "bgpls.clab.yml"
    topology.write_text("name: bgpls\n")
    marker = state / ".bgpls-lab-state"
    marker.write_text("\n".join((
        "bgpls-lab-v2", str(state), "daemon-test",
        hashlib.sha256(topology.read_bytes()).hexdigest(), "ceos", "",
    )))
    return marker, topology


def eos_route(kind="node"):
    """Minimal synthetic equivalent of observed cEOS 4.36.2F CLI fields."""
    route = {
        "protocolId": "isisLevel2", "identifier": 0, "nlriType": kind,
        "localNodeDescriptor": {
            "isisSystemId": "0000.0000.0006", "igpRouterIdType": "isisSystemId", "asn": "65001",
        },
        "paths": [{
            "routeType": {"valid": True, "active": True},
            "asPathEntry": {"asPathType": "Local"}, "peerEntry": {"peerAddr": ""},
        }],
    }
    if kind == "ipv4Prefix":
        route["prefixDescriptor"] = {"prefix": "10.255.0.6/32"}
    elif kind == "ipv6Prefix":
        route["prefixDescriptor"] = {"prefix": "2001:db8:6501::6/128"}
    elif kind == "link":
        route["remoteNodeDescriptor"] = {
            "isisSystemId": "0000.0000.0003", "igpRouterIdType": "isisSystemId", "asn": "65001",
        }
        route["linkDescriptor"] = {"localIpv4Addrs": ["10.254.0.15"], "remoteIpv4Addrs": ["10.254.0.14"],
                                   "localIpv6Addrs": [], "remoteIpv6Addrs": []}
    return route


def eos_table(*routes):
    return {"vrfs": {"default": {"bgpLsRoutes": {
        f"opaque-synthetic-key-{index}": route for index, route in enumerate(routes)
    }}}}


class NativeCeosObjectsTests(unittest.TestCase):
    def test_four_byte_descriptor_asn_is_checked_on_local_and_remote_nodes(self):
        route = eos_route("link")
        for key in ("localNodeDescriptor", "remoteNodeDescriptor"):
            route[key]["asn"] = "4200000001"
        expected = {"link 0000.0000.0006 10.254.0.15 → 0000.0000.0003 10.254.0.14"}
        self.assertEqual(VERIFY.native_ceos_objects(eos_table(route), 4200000001), expected)
        with self.assertRaisesRegex(AssertionError, "descriptor AS"):
            VERIFY.native_ceos_objects(eos_table(route), 65001)
        for key in ("localNodeDescriptor", "remoteNodeDescriptor"):
            bad = copy.deepcopy(route)
            bad[key]["asn"] = "65001"
            with self.subTest(key=key), self.assertRaisesRegex(AssertionError, "descriptor AS"):
                VERIFY.native_ceos_objects(eos_table(bad), 4200000001)

    def test_native_node_and_prefix_ignore_opaque_table_keys(self):
        self.assertEqual(VERIFY.native_ceos_objects(eos_table(eos_route(), eos_route("ipv4Prefix"))), {
            "node 0000.0000.0006", "prefix 10.255.0.6/32 node 0000.0000.0006",
        })

    def test_real_link_descriptor_array_shape_becomes_one_directed_link(self):
        self.assertEqual(VERIFY.native_ceos_objects(eos_table(eos_route("link"))), {
            "link 0000.0000.0006 10.254.0.15 → 0000.0000.0003 10.254.0.14",
        })

    def test_empty_multiple_or_invalid_link_addresses_fail(self):
        for field, value in (("localIpv4Addrs", []), ("remoteIpv4Addrs", []),
                             ("localIpv4Addrs", ["10.254.0.15", "10.254.0.17"]),
                             ("remoteIpv4Addrs", ["example.net"]),
                             ("localIpv6Addrs", ["192.0.2.1"]),
                             ("remoteIpv6Addrs", ["2001:db8::1", "2001:db8::2"])):
            route = eos_route("link")
            route["linkDescriptor"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises((AssertionError, ValueError)):
                VERIFY.native_ceos_objects(eos_table(route))

    def test_remote_identity_is_checked_as_strictly_as_local(self):
        route = eos_route("link")
        route["remoteNodeDescriptor"]["igpRouterIdType"] = "isisPseudonodeId"
        with self.assertRaises(AssertionError):
            VERIFY.native_ceos_objects(eos_table(route))

    def test_received_or_reflected_route_cannot_prove_independent_producer(self):
        for field, value in (("peerEntry", {"peerAddr": "10.255.0.5"}),
                             ("asPathEntry", {"asPathType": "Internal"})):
            route = eos_route()
            route["paths"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, "independently originated"):
                VERIFY.native_ceos_objects(eos_table(route))

    def test_exactly_one_active_valid_path_is_required(self):
        for paths in ([], eos_route()["paths"] * 2,
                      [{**eos_route()["paths"][0], "routeType": {"valid": False, "active": True}}],
                      [{**eos_route()["paths"][0], "routeType": {"valid": True, "active": False}}]):
            route = eos_route()
            route["paths"] = paths
            with self.subTest(paths=paths), self.assertRaises(AssertionError):
                VERIFY.native_ceos_objects(eos_table(route))

    def test_unselected_received_path_does_not_override_selected_local_path(self):
        route = eos_route()
        received = copy.deepcopy(route["paths"][0])
        received["routeType"]["active"] = False
        received["peerEntry"]["peerAddr"] = "10.255.0.5"
        route["paths"].append(received)
        self.assertEqual(VERIFY.native_ceos_objects(eos_table(route)), {"node 0000.0000.0006"})

    def test_other_protocol_instance_or_as_fails(self):
        for field, value in (("protocolId", "isisLevel1"), ("protocolId", "ospf"), ("identifier", 1)):
            route = eos_route()
            route[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                VERIFY.native_ceos_objects(eos_table(route))
        route = eos_route()
        route["localNodeDescriptor"]["asn"] = "65002"
        with self.assertRaises(AssertionError):
            VERIFY.native_ceos_objects(eos_table(route))

    def test_pseudonode_or_invalid_identity_fails(self):
        for field, value in (("isisSystemId", "0000.0000.0006.01"),
                             ("isisSystemId", "10.255.0.6"), ("igpRouterIdType", "isisPseudonodeId")):
            route = eos_route()
            route["localNodeDescriptor"][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                VERIFY.native_ceos_objects(eos_table(route))

    def test_duplicate_presentation_unknown_type_and_invalid_prefix_fail(self):
        with self.assertRaises(AssertionError):
            VERIFY.native_ceos_objects(eos_table(eos_route(), eos_route()))
        with self.assertRaises(AssertionError):
            VERIFY.native_ceos_objects(eos_table(eos_route("unknown")))
        for prefix in ("10.255.0.6/24", "10.255.0.6/33", "2001:db8::/32", "example.net/32"):
            route = eos_route("ipv4Prefix")
            route["prefixDescriptor"]["prefix"] = prefix
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                VERIFY.native_ceos_objects(eos_table(route))


class ExpectedTopologyTests(unittest.TestCase):
    def test_exact_six_nodes_eighteen_links_twelve_loopback_prefixes(self):
        objects = VERIFY.expected_objects()
        self.assertEqual(len(objects), 36)
        for kind, count in (("node ", 6), ("link ", 18), ("prefix ", 12)):
            self.assertEqual(sum(item.startswith(kind) for item in objects), count)
        self.assertIn("node 0000.0000.0006", objects)
        self.assertIn("prefix 10.255.0.6/32 node 0000.0000.0006", objects)

    def test_every_link_is_present_in_both_directions(self):
        objects = VERIFY.expected_objects()
        for slot, (left, right, local, remote) in enumerate(VERIFY.ADJACENCIES, 1):
            local += f",2001:db8:6501:{slot}::"
            remote += f",2001:db8:6501:{slot}::1"
            self.assertIn(f"link {VERIFY.IDS[left]} {local} → {VERIFY.IDS[right]} {remote}", objects)
            self.assertIn(f"link {VERIFY.IDS[right]} {remote} → {VERIFY.IDS[left]} {local}", objects)

    def test_baseline_does_not_contain_relay_or_test_service_prefixes(self):
        self.assertFalse(any("10.254.254." in item or "192.0.2." in item for item in VERIFY.expected_objects()))

    def test_churn_removes_only_two_core_links(self):
        baseline = VERIFY.expected_objects()
        self.assertEqual(len(VERIFY.REMOVED), 2)
        self.assertLess(VERIFY.REMOVED, baseline)
        reduced = baseline - VERIFY.REMOVED
        self.assertEqual(sum(item.startswith("link ") for item in reduced), 16)
        self.assertTrue(all("0000.0000.0006" not in item for item in VERIFY.REMOVED))


class StateOwnershipTests(unittest.TestCase):
    def test_unchanged_exact_profile_marker_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            ownership_files(state)
            self.assertEqual(VERIFY.validate_state(state), "daemon-test")

    def test_profile_path_schema_daemon_or_topology_tampering_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            marker, topology = ownership_files(state)
            original = marker.read_text()
            for index, replacement in ((0, "bgpls-frr-lab-v1"), (1, "/different"), (2, ""),
                                       (3, "0" * 64), (4, "frr")):
                lines = original.splitlines()
                lines[index] = replacement
                marker.write_text("\n".join(lines) + "\n")
                with self.subTest(index=index), self.assertRaises(AssertionError):
                    VERIFY.validate_state(state)
            marker.write_text(original + "extra\n")
            with self.assertRaises(AssertionError):
                VERIFY.validate_state(state)
            marker.write_text(original)
            topology.write_text("name: another-lab\n")
            with self.assertRaises(AssertionError):
                VERIFY.validate_state(state)

    def test_symlink_marker_or_topology_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            for name in (".bgpls-lab-state", "bgpls.clab.yml"):
                ownership_files(state)
                selected = state / name
                target = state / (name + ".original")
                selected.rename(target)
                selected.symlink_to(target)
                with self.subTest(name=name), self.assertRaises(AssertionError):
                    VERIFY.validate_state(state)
                selected.unlink()


class NeighborReadinessTests(unittest.TestCase):
    def test_qualified_normalized_neighbor_is_ready(self):
        self.assertTrue(VERIFY.ready_neighbor(normalized_neighbor()))

    def test_state_uptime_and_both_keepalive_directions_are_required(self):
        for field, value in (("bgpState", "Idle"), ("bgpTimerUpMsec", 11999)):
            item = normalized_neighbor()
            item[field] = value
            with self.subTest(field=field):
                self.assertFalse(VERIFY.ready_neighbor(item))
        for field in ("keepalivesSent", "keepalivesRecv"):
            item = normalized_neighbor()
            item["messageStats"][field] = 4
            with self.subTest(field=field):
                self.assertFalse(VERIFY.ready_neighbor(item))
        self.assertFalse(VERIFY.ready_neighbor({}))


def eos_neighbor_table():
    return {"vrfs": {"default": {"peerList": [{
        "peerAddress": "10.254.254.3", "state": "Established", "asn": "65001", "localAsn": "65001",
        "holdTime": 9, "keepaliveTime": 3, "establishedTransitions": 1, "establishedTime": 20,
        "remotePort": 57348, "localPort": 179, "updateSource": "10.254.254.2", "linkStateReceived": 0,
        "inMessageStats": {"keepalives": 7}, "outMessageStats": {"keepalives": 9},
        "neighborCapabilities": {"multiprotocolCaps": {"linkState": {"enabled": True}}},
    }]}}}


class NativeCeosNeighborTests(unittest.TestCase):
    def test_four_byte_local_and_remote_asns_use_state_for_both_transports(self):
        for source in ("10.254.254.3", "2001:db8:6501:ff02::1"):
            table = eos_neighbor_table()
            peer = table["vrfs"]["default"]["peerList"][0]
            peer.update(asn="4200000001", localAsn="4200000001", peerAddress=source)
            result = VERIFY.ceos_neighbor(table, source, 4200000001)
            self.assertEqual((result["localAs"], result["remoteAs"]), (4200000001, 4200000001))
            with self.assertRaises(AssertionError):
                VERIFY.ceos_neighbor(table, source, 65001)
            for field in ("asn", "localAsn"):
                bad = copy.deepcopy(table)
                bad["vrfs"]["default"]["peerList"][0][field] = "23456"
                with self.subTest(field=field, source=source), self.assertRaises(AssertionError):
                    VERIFY.ceos_neighbor(bad, source, 4200000001)

    def test_observed_schema_normalizes_without_inventing_drop_counter(self):
        item = VERIFY.ceos_neighbor(eos_neighbor_table())
        self.assertEqual(item["connectionsEstablished"], 1)
        self.assertEqual(item["bgpTimerUpMsec"], 20000)
        self.assertEqual(item["messageStats"], {"keepalivesSent": 9, "keepalivesRecv": 7})
        self.assertEqual((item["hostLocal"], item["hostForeign"]), ("10.254.254.2", "10.254.254.3"))
        self.assertNotIn("connectionsDropped", item)

    def test_idle_configured_neighbor_does_not_require_established_only_fields(self):
        table = {"vrfs": {"default": {"peerList": [{"peerAddress": "10.254.254.3", "state": "Idle"}]}}}
        self.assertEqual(VERIFY.ceos_neighbor(table), {"bgpState": "Idle"})

    def test_missing_duplicate_or_wrong_neighbor_fails(self):
        for peers in ([], [{"peerAddress": "192.0.2.1"}],
                      eos_neighbor_table()["vrfs"]["default"]["peerList"] * 2):
            with self.subTest(peers=peers), self.assertRaises(AssertionError):
                VERIFY.ceos_neighbor({"vrfs": {"default": {"peerList": peers}}})

    def test_wrong_as_timers_imported_routes_or_disabled_family_fails(self):
        for field, value in (("asn", "65002"), ("localAsn", "65002"), ("holdTime", 180),
                             ("keepaliveTime", 60), ("linkStateReceived", 1)):
            table = eos_neighbor_table()
            table["vrfs"]["default"]["peerList"][0][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                VERIFY.ceos_neighbor(table)
        table = eos_neighbor_table()
        table["vrfs"]["default"]["peerList"][0]["neighborCapabilities"]["multiprotocolCaps"]["linkState"]["enabled"] = False
        with self.assertRaises(AssertionError):
            VERIFY.ceos_neighbor(table)

    def test_same_eos_session_with_counter_progress_passes(self):
        before = VERIFY.ceos_neighbor(eos_neighbor_table())
        after = copy.deepcopy(before)
        after["bgpTimerUpMsec"] += 3000
        after["messageStats"]["keepalivesSent"] += 1
        after["messageStats"]["keepalivesRecv"] += 1
        self.assertTrue(VERIFY.same_connection("ceos", before, after))

    def test_changed_socket_transition_reset_uptime_or_counter_fails(self):
        before = VERIFY.ceos_neighbor(eos_neighbor_table())
        for field, value in (("hostForeign", "10.254.254.1"), ("portForeign", 57349),
                             ("hostLocal", "10.254.254.0"), ("portLocal", 180),
                             ("connectionsEstablished", 2), ("bgpTimerUpMsec", 19000), ("bgpState", "Idle")):
            after = copy.deepcopy(before)
            after[field] = value
            with self.subTest(field=field):
                self.assertFalse(VERIFY.same_connection("ceos", before, after))
        for field in ("keepalivesSent", "keepalivesRecv"):
            after = copy.deepcopy(before)
            after["messageStats"][field] -= 1
            with self.subTest(field=field):
                self.assertFalse(VERIFY.same_connection("ceos", before, after))


class NativeCeosRoutingTests(unittest.TestCase):
    def adjacency_table(self):
        return {"vrfs": {"default": {"isisInstances": {"CORE": {"neighbors": {
            f"0000.0000.000{index + 2}": {"adjacencies": [{
                "hostname": f"p{index}", "interfaceName": f"Ethernet{index}", "state": "up", "level": "level-2",
            }]} for index in (1, 2)
        }}}}}}

    def reflected_table(self):
        return {"vrfs": {"default": {"bgpRouteEntries": {"192.0.2.5/32": {"bgpRoutePaths": [{
            "routeType": {"valid": True}, "peerEntry": {"peerRouterId": f"10.255.0.{index}"},
            "routeDetail": {"originator": "10.255.0.5", "clusterList": f"10.255.0.{index} "},
        } for index in (1, 2)]}}}}}

    def test_both_expected_level_two_point_to_point_adjacencies_pass(self):
        self.assertTrue(VERIFY.ceos_adjacencies_ready(self.adjacency_table()))

    def test_down_wrong_level_or_wrong_interface_adjacency_fails(self):
        for field, value in (("state", "down"), ("level", "level-1"), ("interfaceName", "Ethernet3")):
            table = self.adjacency_table()
            table["vrfs"]["default"]["isisInstances"]["CORE"]["neighbors"]["0000.0000.0003"]["adjacencies"][0][field] = value
            with self.subTest(field=field):
                self.assertFalse(VERIFY.ceos_adjacencies_ready(table))

    def test_two_direct_reflected_paths_pass(self):
        self.assertTrue(VERIFY.ceos_reflected_by_both(self.reflected_table()))

    def test_single_invalid_wrong_originator_or_serial_reflection_fails(self):
        for mutation in (
            lambda paths: paths.pop(),
            lambda paths: paths[1]["routeType"].update(valid=False),
            lambda paths: paths[1]["routeDetail"].update(originator="10.255.0.4"),
            lambda paths: paths[1]["routeDetail"].update(clusterList="10.255.0.2 10.255.0.1 "),
        ):
            table = self.reflected_table()
            mutation(table["vrfs"]["default"]["bgpRouteEntries"]["192.0.2.5/32"]["bgpRoutePaths"])
            with self.subTest(mutation=mutation):
                self.assertFalse(VERIFY.ceos_reflected_by_both(table))


class CollectorLifecycleTests(unittest.TestCase):
    def lab(self, asn=65001):
        return mock.Mock(state_info={"asn": asn})

    def test_launch_uses_distinct_ports_logs_and_captures(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with mock.patch.object(VERIFY.subprocess, "Popen") as launch:
                collectors = [VERIFY.Collector(name, Path("/mock-bgpls"), output, lab=self.lab())
                              for name in VERIFY.PORTS]
                for collector in collectors:
                    collector.start()
                arguments = [call.args[0] for call in launch.call_args_list]
                self.assertEqual([args[args.index("--port") + 1] for args in arguments], ["11790", "11791"])
                self.assertEqual([args[args.index("--bgp-identifier") + 1] for args in arguments],
                                 ["192.0.2.101", "192.0.2.102"])
                self.assertTrue(all(args.count("--dump-rib") == 1 for args in arguments))
                self.assertNotEqual(collectors[0].log_path, collectors[1].log_path)
                self.assertNotEqual(collectors[0].pcap_path, collectors[1].pcap_path)
                with self.assertRaises(RuntimeError):
                    collectors[0].start()

    def test_unknown_producer_is_rejected(self):
        with self.assertRaises(ValueError):
            VERIFY.Collector("other", Path("/unused"), Path("/unused"), lab=self.lab())

    def test_native_collectors_use_deployment_asn_for_both_producers(self):
        for asn in (65001, 4200000001):
            with self.subTest(asn=asn), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(VERIFY.subprocess, "Popen") as launch:
                for producer in VERIFY.PORTS:
                    VERIFY.Collector(producer, Path("/mock-bgpls"), Path(directory), lab=self.lab(asn)).start()
                for call in launch.call_args_list:
                    for option in ("--local-as", "--peer-as"):
                        self.assertEqual(call.args[0][call.args[0].index(option) + 1], str(asn))

    def test_missing_deployment_asn_has_no_implicit_collector_default(self):
        with self.assertRaises(KeyError):
            VERIFY.Collector("frr", Path("/unused"), Path("/unused"), lab=mock.Mock(state_info={}))

    def test_wait_checks_both_children_even_when_condition_would_pass(self):
        first, second = mock.Mock(), mock.Mock()
        second.ensure_running.side_effect = AssertionError("ceos died")
        condition = mock.Mock(return_value=True)
        with self.assertRaisesRegex(AssertionError, "ceos died"):
            VERIFY.wait_for("mock", condition, [first, second])
        first.ensure_running.assert_called_once()
        second.ensure_running.assert_called_once()
        condition.assert_not_called()

    def test_stop_sends_only_selected_signal_and_checks_complete_output(self):
        for selected in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                asn = 65001 if selected == signal.SIGINT else 4200000001
                collector = VERIFY.Collector("frr", Path("/unused"), Path(directory), lab=self.lab(asn))
                collector.process = mock.Mock()
                collector.process.poll.return_value = None
                collector.process.wait.return_value = 128 + selected
                collector.log_path.write_text(completed_log())
                with mock.patch.object(VERIFY.BASE, "validate_pcap", return_value={"records": 20}) as pcap, \
                        mock.patch.object(VERIFY.BASE.WIRE, "audit_capture", return_value={"verified": True}) as wire:
                    result = collector.stop(selected, VERIFY.expected_objects())
                self.assertEqual(result["exit_status"], 128 + selected)
                self.assertEqual(result["asn"], asn)
                collector.process.send_signal.assert_called_once_with(selected)
                collector.process.wait.assert_called_once_with(timeout=15)
                pcap.assert_called_once_with(collector.pcap_path, VERIFY.BASE.capture_expectation("frr", "ipv4", asn))
                wire.assert_called_once_with(collector.pcap_path, VERIFY.expected_objects(), churn_objects=(), probe_objects=())

    def test_incomplete_duplicate_or_error_output_cannot_pass_shutdown(self):
        modifications = (
            lambda text: text.split("bgpls: RIB final\n")[0]
            + "bgpls: RIB summary nodes=6 links=18 prefixes=12\n",
            lambda text: text + "bgpls: RIB final\n",
            lambda text: text + "bgpls: SIGINT — stopping session…\n",
            lambda text: text + "bgpls: state Established\n",
            lambda text: text + "bgpls: parse error\n",
            lambda text: text.replace("nodes=6 links=18 prefixes=12", "nodes=6 links=17 prefixes=12"),
            lambda text: text.replace("prefix 10.255.0.6/32", "prefix 10.255.0.7/32"),
        )
        with tempfile.TemporaryDirectory() as directory:
            collector = VERIFY.Collector("frr", Path("/unused"), Path(directory), lab=self.lab())
            collector.process = mock.Mock()
            collector.process.poll.return_value = None
            collector.process.wait.return_value = 130
            for mutation in modifications:
                collector.log_path.write_text(mutation(completed_log()))
                with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                    collector.stop(signal.SIGINT, VERIFY.expected_objects())

    def test_signal_exit_instead_of_orderly_numeric_status_fails(self):
        collector = VERIFY.Collector("ceos", Path("/unused"), Path("/unused"), lab=self.lab())
        collector.process = mock.Mock()
        collector.process.poll.return_value = None
        collector.process.wait.return_value = -signal.SIGTERM
        with self.assertRaisesRegex(AssertionError, "exit status"):
            collector.stop(signal.SIGTERM, VERIFY.expected_objects())

    def test_cleanup_escalates_only_its_stubborn_child_and_reaps(self):
        collector = VERIFY.Collector("ceos", Path("/unused"), Path("/unused"), lab=self.lab())
        collector.process = mock.Mock()
        collector.process.poll.return_value = None
        collector.process.wait.side_effect = [subprocess.TimeoutExpired("mock", 15), -9]
        collector.cleanup()
        collector.process.terminate.assert_called_once()
        collector.process.kill.assert_called_once()
        self.assertEqual(collector.process.wait.call_args_list, [mock.call(timeout=15), mock.call(timeout=5)])

    def test_cleanup_does_not_signal_unstarted_or_already_exited_child(self):
        collector = VERIFY.Collector("ceos", Path("/unused"), Path("/unused"), lab=self.lab())
        collector.cleanup()
        collector.process = mock.Mock()
        collector.process.poll.return_value = 143
        collector.cleanup()
        collector.process.terminate.assert_not_called()
        collector.process.kill.assert_not_called()


class IndependentCleanupTests(unittest.TestCase):
    def test_every_cleanup_attempt_runs_even_if_restoration_and_first_child_fail(self):
        events = []
        lab = mock.Mock()
        first, second = mock.Mock(producer="frr"), mock.Mock(producer="ceos")
        def fail_restore(_state):
            events.append("restore")
            raise RuntimeError("restoration failed")
        def fail_first():
            events.append("first")
            raise subprocess.TimeoutExpired("mock", 5)
        lab.link.side_effect = fail_restore
        first.cleanup.side_effect = fail_first
        second.cleanup.side_effect = lambda: events.append("second")
        with mock.patch.object(VERIFY.signal, "signal") as handler:
            with self.assertRaisesRegex(RuntimeError, "cleanup incomplete"):
                VERIFY.cleanup(lab, True, [first, second])
        self.assertEqual(events, ["restore", "first", "second"])
        self.assertEqual(handler.call_args_list, [
            mock.call(signal.SIGINT, signal.SIG_IGN), mock.call(signal.SIGTERM, signal.SIG_IGN),
        ])

    def test_second_launch_failure_reaps_first_and_does_not_mutate_links(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = mock.Mock(producer="frr"), mock.Mock(producer="ceos")
            second.start.side_effect = OSError("mock second launch failure")
            lab = mock.Mock()
            options = argparse.Namespace(state=directory, binary=sys.executable, churn=True)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(VERIFY.BASE, "verification_lock", return_value=contextlib.nullcontext()))
                stack.enter_context(mock.patch.object(VERIFY.BASE, "wait_until"))
                stack.enter_context(mock.patch.object(VERIFY, "CeosLab", return_value=lab))
                stack.enter_context(mock.patch.object(VERIFY, "Collector", side_effect=[first, second]))
                stack.enter_context(mock.patch.object(VERIFY.signal, "signal"))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                with self.assertRaisesRegex(OSError, "second launch"):
                    VERIFY.run(options)
            first.cleanup.assert_called_once()
            second.cleanup.assert_called_once()
            lab.link.assert_not_called()

    def test_parent_interruption_after_partial_link_change_restores_and_reaps_both(self):
        with tempfile.TemporaryDirectory() as directory:
            events = []
            lab = mock.Mock()
            lab.state_info = {"asn": 65001}
            lab.producer_neighbor.side_effect = lambda producer: normalized_neighbor(
                "10.254.254.1" if producer == "frr" else "10.254.254.3"
            )
            def link(state):
                events.append(state)
                if state == "down":
                    raise VERIFY.BASE.VerificationInterrupted(signal.SIGINT)
            lab.link.side_effect = link
            first, second = mock.Mock(producer="frr"), mock.Mock(producer="ceos")
            first.cleanup.side_effect = lambda: events.append("frr")
            second.cleanup.side_effect = lambda: events.append("ceos")
            options = argparse.Namespace(state=directory, binary=sys.executable, churn=True)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(VERIFY.BASE, "verification_lock", return_value=contextlib.nullcontext()))
                stack.enter_context(mock.patch.object(VERIFY.BASE, "wait_until"))
                stack.enter_context(mock.patch.object(VERIFY, "CeosLab", return_value=lab))
                stack.enter_context(mock.patch.object(VERIFY, "Collector", side_effect=[first, second]))
                stack.enter_context(mock.patch.object(VERIFY, "wait_for"))
                stack.enter_context(mock.patch.object(VERIFY.signal, "signal"))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                with self.assertRaises(VERIFY.BASE.VerificationInterrupted):
                    VERIFY.run(options)
            self.assertEqual(events, ["down", "up", "frr", "ceos"])


class SurvivorIndependenceTests(unittest.TestCase):
    def test_progress_during_frr_stop_does_not_count_as_progress_after_it(self):
        before = normalized_neighbor()
        after_stop = copy.deepcopy(before)
        # Simulate keepalives that arrived while FRR.stop() was still cleaning up.
        after_stop["messageStats"] = {"keepalivesSent": 9, "keepalivesRecv": 9}
        current = copy.deepcopy(after_stop)
        baseline = VERIFY.expected_objects()
        lab, collector = mock.Mock(), mock.Mock()
        lab.producer_neighbor.side_effect = lambda _producer: copy.deepcopy(current)
        lab.native_objects.return_value = baseline
        collector.objects.return_value = baseline

        def checkpoint(_description, condition, collectors):
            self.assertEqual(collectors, [collector])
            self.assertFalse(condition(), "only pre-exit keepalives have arrived")
            current["messageStats"]["keepalivesSent"] += 1
            self.assertFalse(condition(), "both directions must progress after FRR exits")
            current["messageStats"]["keepalivesRecv"] += 1
            self.assertTrue(condition())

        with mock.patch.object(VERIFY, "wait_for", side_effect=checkpoint):
            VERIFY.verify_independent_survivor(lab, collector, before, baseline)
        lab.save.assert_any_call("ceos-neighbor-immediately-after-frr-shutdown", after_stop)

    def test_reconnect_during_frr_shutdown_fails_before_progress_wait(self):
        before = normalized_neighbor()
        after_stop = copy.deepcopy(before)
        after_stop["connectionsEstablished"] += 1
        lab, collector = mock.Mock(), mock.Mock()
        lab.producer_neighbor.return_value = after_stop
        with mock.patch.object(VERIFY, "wait_for") as wait:
            with self.assertRaisesRegex(AssertionError, "while stopping"):
                VERIFY.verify_independent_survivor(lab, collector, before, VERIFY.expected_objects())
        wait.assert_not_called()


class PreflightTests(unittest.TestCase):
    def exercise(self, mutation=None, neighbor_state="Idle", daemon="daemon-test",
                 engine_architecture="aarch64", image_architecture="arm64", os_type="linux"):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            ownership_files(state)
            lab = VERIFY.CeosLab(state, state)
            lab.save = mock.Mock()
            lab.producer_neighbor = mock.Mock(return_value={"bgpState": neighbor_state})
            def docker(*arguments):
                if arguments[0] == "info":
                    return json.dumps({"ID": daemon, "Architecture": engine_architecture, "OSType": os_type})
                if arguments[:2] == ("image", "inspect"):
                    return json.dumps([{"Architecture": image_architecture}])
                node = arguments[1].removeprefix("clab-bgpls-")
                inspected = {
                    "Id": "container-id", "Image": "image-id", "State": {"Running": True},
                    "Config": {"Image": "ceosarm:4.36.2F" if node == "edge-ceos" else "mock-image", "Labels": {
                        "containerlab": "bgpls", "clab-topo-file": str(state / "bgpls.clab.yml"),
                    }},
                    "HostConfig": {"PortBindings": {
                        f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
                        for port in VERIFY.PORTS.values()
                    }},
                }
                if mutation:
                    mutation(node, inspected)
                return json.dumps([inspected])
            lab.docker = mock.Mock(side_effect=docker)
            state_helper = VERIFY.BASE.helper("lab-state")
            state_helper.assert_no_namespace_holders = mock.Mock()
            with mock.patch.object(VERIFY.BASE, "helper", return_value=state_helper):
                lab.preflight()

    def test_owned_running_nodes_and_both_exact_local_listeners_pass(self):
        self.exercise()
        self.exercise(engine_architecture="arm64")

    def test_non_native_engine_or_image_fails_even_if_ownership_labels_match(self):
        for arguments in ({"engine_architecture": "x86_64"}, {"engine_architecture": "amd64"},
                          {"os_type": "windows"}, {"image_architecture": "amd64"}):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(AssertionError, "native ARM64"):
                self.exercise(**arguments)

    def test_different_ceos_image_reference_fails(self):
        def different_image(node, inspected):
            if node == "edge-ceos":
                inspected["Config"]["Image"] = "ceosarm:other-version"
        with self.assertRaisesRegex(AssertionError, "qualified ceosarm"):
            self.exercise(different_image)

    def test_wrong_daemon_is_rejected_before_container_access(self):
        with self.assertRaisesRegex(AssertionError, "different Docker daemon"):
            self.exercise(daemon="other-daemon")

    def test_preexisting_collector_is_not_disrupted(self):
        with self.assertRaisesRegex(AssertionError, "already connected"):
            self.exercise(neighbor_state="Established")

    def test_foreign_topology_or_stopped_node_fails(self):
        def foreign(_node, inspected):
            inspected["Config"]["Labels"]["clab-topo-file"] = "/another/bgpls.clab.yml"
        def stopped(_node, inspected):
            inspected["State"]["Running"] = False
        for mutation in (foreign, stopped):
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                self.exercise(mutation)

    def test_extra_missing_or_nonlocal_relay_port_fails(self):
        def wildcard(node, inspected):
            if node == "bgpls-relay":
                inspected["HostConfig"]["PortBindings"]["11791/tcp"][0]["HostIp"] = "0.0.0.0"
        def missing(node, inspected):
            if node == "bgpls-relay":
                del inspected["HostConfig"]["PortBindings"]["11791/tcp"]
        def extra(node, inspected):
            if node == "bgpls-relay":
                inspected["HostConfig"]["PortBindings"]["22/tcp"] = [{"HostIp": "127.0.0.1", "HostPort": "22"}]
        for mutation in (wildcard, missing, extra):
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                self.exercise(mutation)


if __name__ == "__main__":
    unittest.main()
