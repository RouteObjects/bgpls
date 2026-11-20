#!/usr/bin/env python3
"""Offline dual-stack normalization, routing, and temporary-prefix ownership."""

import argparse
import contextlib
import copy
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


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("ipv6_base_verify", "verify.py")
CEOS = load("ipv6_ceos_verify", "verify-ceos.py")


def frr_nlri(kind="link"):
    value = {"protocolId": 2, "identifier": 0, "nlriType": kind,
             "localNodeDescriptors": {"igpRouterId": "0000.0000.0001.00"}}
    if kind == "link":
        value["remoteNodeDescriptors"] = {"igpRouterId": "0000.0000.0003.00"}
        value["linkDescriptors"] = {
            "ipv4InterfaceAddress": "10.254.0.0", "ipv4NeighborAddress": "10.254.0.1",
            "ipv6InterfaceAddress": "2001:0db8:6501:1:0:0:0:0", "ipv6NeighborAddress": "2001:db8:6501:1::1",
        }
    else:
        value["prefixDescriptors"] = {"ipReachabilityInformation": "2001:db8:6501::1/128"}
    return value


def frr_table(*nlris):
    return {"routes": {str(index): [{"valid": True, "bestpath": True, "nlri": nlri}]
                       for index, nlri in enumerate(nlris)}}


def eos_route(kind="link"):
    value = {"protocolId": "isisLevel2", "identifier": 0, "nlriType": kind,
             "localNodeDescriptor": {"isisSystemId": "0000.0000.0001", "igpRouterIdType": "isisSystemId", "asn": "65001"},
             "paths": [{"routeType": {"valid": True, "active": True},
                        "peerEntry": {"peerAddr": ""}, "asPathEntry": {"asPathType": "Local"}}]}
    if kind == "link":
        value["remoteNodeDescriptor"] = {"isisSystemId": "0000.0000.0003", "igpRouterIdType": "isisSystemId", "asn": "65001"}
        value["linkDescriptor"] = {
            "localIpv4Addrs": ["10.254.0.0"], "remoteIpv4Addrs": ["10.254.0.1"],
            "localIpv6Addrs": ["2001:0db8:6501:1:0:0:0:0"], "remoteIpv6Addrs": ["2001:db8:6501:1::1"],
        }
    else:
        value["prefixDescriptor"] = {"prefix": "2001:db8:6501::1/128"}
    return value


def eos_table(*routes):
    return {"vrfs": {"default": {"bgpLsRoutes": {str(i): route for i, route in enumerate(routes)}}}}


class DualStackNormalizationTests(unittest.TestCase):
    def test_both_vendor_shapes_preserve_both_link_families_and_ipv6_prefix(self):
        expected = {"link 0000.0000.0001 10.254.0.0,2001:db8:6501:1:: → 0000.0000.0003 10.254.0.1,2001:db8:6501:1::1",
                    "prefix 2001:db8:6501::1/128 node 0000.0000.0001"}
        self.assertEqual(BASE.native_objects(frr_table(frr_nlri(), frr_nlri("ipv6Prefix"))), expected)
        self.assertEqual(CEOS.native_ceos_objects(eos_table(eos_route(), eos_route("ipv6Prefix"))), expected)

    def test_single_family_format_remains_unchanged_and_empty_is_rejected(self):
        self.assertEqual(BASE.endpoint_addresses("192.0.2.1"), "192.0.2.1")
        self.assertEqual(BASE.endpoint_addresses(ipv6="2001:0db8::1"), "2001:db8::1")
        with self.assertRaises(AssertionError):
            BASE.endpoint_addresses()

    def test_invalid_family_mismatch_and_host_bits_are_rejected(self):
        for prefix in ("192.0.2.1/32", "2001:db8::1/64", "2001:db8::/129", "host.example/128"):
            frr, eos = frr_nlri("ipv6Prefix"), eos_route("ipv6Prefix")
            frr["prefixDescriptors"]["ipReachabilityInformation"] = prefix
            eos["prefixDescriptor"]["prefix"] = prefix
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                BASE.native_objects(frr_table(frr))
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                CEOS.native_ceos_objects(eos_table(eos))
        for field in ("ipv6InterfaceAddress", "ipv6NeighborAddress"):
            item = frr_nlri()
            item["linkDescriptors"][field] = "192.0.2.1"
            with self.subTest(field=field), self.assertRaises(ValueError):
                BASE.native_objects(frr_table(item))

    def test_duplicate_native_presentations_are_never_silently_deduplicated(self):
        with self.assertRaisesRegex(AssertionError, "collide"):
            BASE.native_objects(frr_table(frr_nlri("ipv6Prefix"), frr_nlri("ipv6Prefix")))
        with self.assertRaisesRegex(AssertionError, "collide"):
            CEOS.native_ceos_objects(eos_table(eos_route("ipv6Prefix"), eos_route("ipv6Prefix")))

    def test_expected_baseline_and_churn_keep_exact_prefix_families(self):
        for routers, ids, adjacencies in ((BASE.ROUTERS, BASE.IDS, BASE.ADJACENCIES),
                                          (CEOS.ROUTERS, CEOS.IDS, CEOS.ADJACENCIES)):
            prefixes = BASE.expected_loopbacks(routers, ids)
            self.assertEqual(len(prefixes), len(routers) * 2)
            self.assertEqual(sum("/128 " in prefix for prefix in prefixes), len(routers))
            objects = BASE.expected_links(adjacencies, ids) | prefixes | {f"node {value}" for value in ids.values()}
            removed = BASE.core_link_objects(objects)
            self.assertEqual(len(removed), 2)
            self.assertEqual({v for v in objects - removed if v.startswith("prefix ")}, prefixes)
            self.assertIn(f"prefixes={2 * len(routers)}", BASE.rib_summary(objects))


class NativeSelectionPollingTests(unittest.TestCase):
    @staticmethod
    def pending_table():
        table = frr_table(frr_nlri("ipv6Prefix"))
        table["routes"]["0"][0]["bestpath"] = False
        return table

    def test_frr_no_best_path_remains_a_rejected_native_snapshot(self):
        with self.assertRaises(BASE.NativeSelectionPending):
            BASE.native_objects(self.pending_table())

    def test_both_profiles_retry_only_pending_selection_and_preserve_candidate_evidence(self):
        for module, lab_type in ((BASE, BASE.Lab), (CEOS.BASE, CEOS.CeosLab)):
            with self.subTest(profile=lab_type.__name__), tempfile.TemporaryDirectory() as directory:
                lab = lab_type(Path(directory), Path(directory))
                pending = self.pending_table()
                complete = frr_table(frr_nlri("ipv6Prefix"))
                expected = module.native_objects(complete)
                lab.vty = mock.Mock(side_effect=[pending, complete])
                condition = ((lambda: lab.native_objects("frr") == expected) if lab_type is CEOS.CeosLab
                             else (lambda: lab.native_objects() == expected))
                with mock.patch.object(module.time, "monotonic", side_effect=[0, 0, 1]), \
                        mock.patch.object(module.time, "sleep") as sleep, \
                        contextlib.redirect_stdout(io.StringIO()):
                    module.wait_until("exact native state", condition, timeout=2)
                self.assertEqual(lab.vty.call_count, 2)
                sleep.assert_called_once_with(0.5)
                saved = Path(directory) / "frr-link-state-selection-pending.json"
                self.assertEqual(json.loads(saved.read_text()), pending)

    def test_persistent_pending_selection_times_out_with_diagnostic(self):
        condition = mock.Mock(side_effect=BASE.NativeSelectionPending("no valid best path"))
        with mock.patch.object(BASE.time, "monotonic", side_effect=[0, 0, 1, 2]), \
                mock.patch.object(BASE.time, "sleep"), \
                self.assertRaisesRegex(TimeoutError, "last native selection state: no valid best path"):
            BASE.wait_until("exact native state", condition, timeout=2)
        self.assertEqual(condition.call_count, 2)

    def test_duplicate_best_paths_and_malformed_nlris_are_not_retried(self):
        duplicate = frr_table(frr_nlri("ipv6Prefix"))
        duplicate["routes"]["0"] *= 2
        malformed = frr_nlri("ipv6Prefix")
        malformed["prefixDescriptors"]["ipReachabilityInformation"] = "2001:db8::1/64"
        for table, error in ((duplicate, AssertionError), (frr_table(malformed), ValueError)):
            with self.subTest(error=error), \
                    mock.patch.object(BASE.time, "monotonic", return_value=0), \
                    mock.patch.object(BASE.time, "sleep") as sleep, self.assertRaises(error) as caught:
                BASE.wait_until("exact native state", lambda: BASE.native_objects(table), timeout=2)
            self.assertNotIsInstance(caught.exception, BASE.NativeSelectionPending)
            sleep.assert_not_called()

    def test_collector_exit_still_interrupts_native_selection_polling(self):
        child = mock.Mock(returncode=1)
        child.poll.side_effect = [None, 1]
        condition = mock.Mock(side_effect=BASE.NativeSelectionPending("no valid best path"))
        with mock.patch.object(BASE.time, "monotonic", side_effect=[0, 0, 1]), \
                mock.patch.object(BASE.time, "sleep"), self.assertRaisesRegex(AssertionError, "collector exited 1"):
            BASE.wait_until("exact native state", condition, child, timeout=2)
        condition.assert_called_once()


def ipv6_routes(node="edge-frr", routers=BASE.ROUTERS):
    return {f"2001:db8:6501::{index}/128": [{"protocol": "isis", "selected": True, "installed": True,
             "nexthops": [{"active": True, "fib": True, "afi": "ipv6", "ip": "fe80::1"}]}]
            for index, name in enumerate(routers, 1) if name != node}


class IPv6RouteTests(unittest.TestCase):
    def test_every_remote_loopback_is_installed_with_valid_link_local_next_hop(self):
        self.assertTrue(BASE.frr_ipv6_routes_ready(ipv6_routes(), "edge-frr"))

    def test_missing_extra_unselected_uninstalled_or_wrong_family_routes_fail(self):
        table = ipv6_routes()
        for mutation in (
            lambda t: t.pop(next(iter(t))),
            lambda t: t.update({"2001:db8:6501:1::/127": [copy.deepcopy(next(iter(t.values()))[0])]}),
            lambda t: next(iter(t.values()))[0].update(selected=False),
            lambda t: next(iter(t.values()))[0].update(installed=False),
            lambda t: next(iter(t.values()))[0].update(protocol="bgp"),
            lambda t: next(iter(t.values()))[0]["nexthops"][0].update(fib=False),
            lambda t: next(iter(t.values()))[0]["nexthops"][0].update(ip="192.0.2.1"),
        ):
            value = copy.deepcopy(table)
            mutation(value)
            with self.subTest(mutation=mutation):
                self.assertFalse(BASE.frr_ipv6_routes_ready(value, "edge-frr"))

    def test_observed_ceos_route_shape_proves_every_remote_ipv6_loopback(self):
        table = self.ceos_routes()
        self.assertTrue(CEOS.ceos_ipv6_routes_ready(table))

    @staticmethod
    def ceos_routes():
        return {"vrfs": {"default": {"routingDisabled": False, "allRoutesProgrammedHardware": True,
                "allRoutesProgrammedKernel": True, "routes": {
                    f"2001:db8:6501::{index}/128": {
                        "hardwareProgrammed": True, "kernelProgrammed": True, "routeType": "isisL2",
                        "routeLeaked": False, "directlyConnected": False, "routeAction": "forward",
                        "vias": [{"nexthopAddr": "fe80::1", "interface": "Ethernet1"}],
                    } for index in range(1, 6)
                }}}}

    def test_ceos_missing_disabled_unprogrammed_wrong_family_or_management_route_fails(self):
        for mutation in (
            lambda v: v.update(routingDisabled=True),
            lambda v: v.update(allRoutesProgrammedKernel=False),
            lambda v: v["routes"].pop("2001:db8:6501::1/128"),
            lambda v: v["routes"]["2001:db8:6501::1/128"].update(routeType="bgp"),
            lambda v: v["routes"]["2001:db8:6501::1/128"].update(hardwareProgrammed=False),
            lambda v: v["routes"]["2001:db8:6501::1/128"].update(routeAction="drop"),
            lambda v: v["routes"]["2001:db8:6501::1/128"].update(routeLeaked=True),
            lambda v: v["routes"]["2001:db8:6501::1/128"]["vias"][0].update(nexthopAddr="192.0.2.1"),
            lambda v: v["routes"]["2001:db8:6501::1/128"]["vias"][0].update(interface="Management0"),
        ):
            value = self.ceos_routes()
            mutation(value["vrfs"]["default"])
            with self.subTest(mutation=mutation):
                self.assertFalse(CEOS.ceos_ipv6_routes_ready(value))


class PrefixProbeTests(unittest.TestCase):
    def exercise(self, node="edge-frr", *, fail_at=None, preexisting=False):
        lab = mock.Mock()
        present = preexisting
        actions = []
        def change(_node, _prefix, desired):
            nonlocal present
            present = desired
            actions.append(desired)
            if len(actions) == fail_at:
                raise RuntimeError("response failed after configuration changed")
        lab.probe_present.side_effect = lambda *_args: present
        lab.set_probe.side_effect = change
        probe = BASE.PrefixProbe(lab, node, "0000.0000.0005" if node == "edge-frr" else "0000.0000.0006")
        baseline = {"node 0000.0000.0001", "prefix 10.255.0.1/32 node 0000.0000.0001"}
        phases = []
        def wait(_description, condition):
            self.assertTrue(condition())
        def tables():
            objects = baseline | ({probe.value} if present else set())
            return [objects, objects.copy(), objects.copy(), objects.copy()]
        return lab, probe, baseline, actions, phases, wait, tables

    def test_both_vendors_announce_withdraw_reannounce_and_restore_exact_baseline(self):
        for node in ("edge-frr", "edge-ceos"):
            lab, probe, baseline, actions, phases, wait, tables = self.exercise(node)
            BASE.exercise_prefix_probe(probe, wait, tables, baseline, phases.append)
            self.assertEqual(actions, [True, False, True, False])
            self.assertEqual(len(phases), 4)
            self.assertFalse(probe.changed)
            probe.restore()
            self.assertEqual(len(actions), 4)
            self.assertFalse(lab.probe_present(node, probe.prefix))

    def test_preexisting_address_is_not_owned_or_removed(self):
        lab, probe, baseline, actions, _, wait, tables = self.exercise(preexisting=True)
        with self.assertRaisesRegex(AssertionError, "already exists"):
            BASE.exercise_prefix_probe(probe, wait, tables, baseline, mock.Mock())
        probe.restore()
        self.assertEqual(actions, [])
        self.assertTrue(lab.probe_present(probe.node, probe.prefix))

    def test_partial_add_or_remove_failure_still_owns_cleanup(self):
        for failure in range(1, 5):
            lab, probe, baseline, actions, _, wait, tables = self.exercise(fail_at=failure)
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                BASE.exercise_prefix_probe(probe, wait, tables, baseline, mock.Mock())
            self.assertTrue(probe.changed)
            probe.restore()
            self.assertFalse(probe.changed)
            self.assertFalse(lab.probe_present(probe.node, probe.prefix))
            self.assertEqual(actions[-1], False)

    def test_timeout_or_parent_signal_during_add_is_restored_before_children_reaped(self):
        for error in (TimeoutError("convergence timeout"), BASE.VerificationInterrupted(signal.SIGINT)):
            lab, probe, baseline, actions, _, _, tables = self.exercise()
            with self.subTest(error=error), self.assertRaises(type(error)):
                BASE.exercise_prefix_probe(probe, mock.Mock(side_effect=error), tables, baseline, mock.Mock())
            child = mock.Mock(producer="test")
            child.cleanup.side_effect = lambda: self.assertFalse(lab.probe_present(probe.node, probe.prefix))
            with mock.patch.object(CEOS.signal, "signal"):
                CEOS.cleanup(lab, False, [child], [probe])
            child.cleanup.assert_called_once()
            self.assertEqual(actions, [True, False])

    def test_probe_cleanup_failure_cannot_skip_other_probe_link_or_children(self):
        for error in (RuntimeError("probe restore failed"), ValueError("malformed IPv6 config")):
            with self.subTest(error=error):
                self.check_cleanup_failure(error)

    def check_cleanup_failure(self, error):
        events = []
        first = mock.Mock(node="edge-frr")
        first.restore.side_effect = error
        second = mock.Mock(node="edge-ceos")
        second.restore.side_effect = lambda: events.append("second probe")
        lab = mock.Mock()
        lab.link.side_effect = lambda _state: events.append("link")
        children = [mock.Mock(producer=name) for name in ("frr", "ceos")]
        for child in children:
            child.cleanup.side_effect = lambda child=child: events.append(child.producer)
        with mock.patch.object(CEOS.signal, "signal"), self.assertRaisesRegex(RuntimeError, "cleanup incomplete"):
            CEOS.cleanup(lab, True, children, [first, second])
        self.assertEqual(events, ["second probe", "link", "frr", "ceos"])

    def test_frr_run_owns_partial_probe_failure_until_config_and_child_cleanup(self):
        self.exercise_frr_run_cleanup()

    def test_frr_probe_config_parse_error_cannot_skip_child_cleanup(self):
        self.exercise_frr_run_cleanup(ValueError("malformed IPv6 config"))

    def exercise_frr_run_cleanup(self, cleanup_error=None):
        #  Exercise run()'s actual finally block, not only the probe's
        # cleanup method, with no router, real subprocess, or process signal.
        events = []
        baseline = BASE.expected_links() | BASE.expected_loopbacks() | {f"node {v}" for v in BASE.IDS.values()}
        child = mock.Mock()
        child.poll.return_value = None
        child.terminate.side_effect = lambda: events.append("terminate")
        child.wait.return_value = 143
        present = False
        def set_probe(_node, _prefix, desired):
            nonlocal present
            present = desired
            events.append("add" if desired else "remove")
            if desired:
                raise BASE.VerificationInterrupted(signal.SIGTERM)
            if cleanup_error is not None:
                raise cleanup_error
        def launch(_args, *, stdout, stderr):
            stdout.write("".join(f"WATCH upsert {value}\n" for value in sorted(baseline)))
            stdout.flush()
            return child
        def exercise(probe, *_args):
            probe.preflight()
            probe.add()
        with tempfile.TemporaryDirectory() as directory:
            lab = mock.Mock()
            lab.state_info = {"asn": 65001}
            lab.neighbor.return_value = {"hostForeign": "10.254.254.1", "hostLocal": "10.254.254.0",
                                         "portForeign": 40000, "portLocal": 179, "localAs": 65001, "remoteAs": 65001}
            lab.link.side_effect = lambda state: events.append(state)
            lab.probe_present.side_effect = lambda *_args: present
            lab.set_probe.side_effect = set_probe
            options = argparse.Namespace(state=directory, binary=sys.executable, churn=True, signal="INT")
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(BASE, "verification_lock", return_value=contextlib.nullcontext()))
                stack.enter_context(mock.patch.object(BASE, "Lab", return_value=lab))
                stack.enter_context(mock.patch.object(BASE, "wait_until"))
                stack.enter_context(mock.patch.object(BASE, "native_objects", return_value=baseline - BASE.core_link_objects(baseline)))
                stack.enter_context(mock.patch.object(BASE, "exercise_prefix_probe", side_effect=exercise))
                stack.enter_context(mock.patch.object(BASE.subprocess, "Popen", side_effect=launch))
                stack.enter_context(mock.patch.object(BASE.signal, "signal"))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                with self.assertRaises(BASE.VerificationInterrupted if cleanup_error is None else RuntimeError):
                    BASE.run(options)
        self.assertEqual(events, ["down", "up", "add", "remove", "terminate"])
        self.assertFalse(present)
        child.wait.assert_called_once_with(timeout=15)

    def test_reserved_address_commands_never_save_config_or_modify_other_interfaces(self):
        for node, lab in (("edge-frr", BASE.Lab(Path("/unused"), Path("/unused"))),
                          ("edge-ceos", CEOS.CeosLab(Path("/unused"), Path("/unused")))):
            lab.docker = mock.Mock(return_value="")
            lab.probe_present = mock.Mock(return_value=True)
            lab.set_probe(node, BASE.PROBE_PREFIXES[node], True)
            args = lab.docker.call_args.args
            self.assertNotIn("write", " ".join(args))
            self.assertIn("interface lo" if node == "edge-frr" else "interface Loopback0", " ".join(args))
            with self.assertRaises(ValueError):
                lab.set_probe(node, "2001:db8::1/128", True)

    def test_configuration_stdout_error_is_failure_even_when_command_exits_zero(self):
        for lab, node in ((BASE.Lab(Path("/unused"), Path("/unused")), "edge-frr"),
                          (CEOS.CeosLab(Path("/unused"), Path("/unused")), "edge-ceos")):
            lab.docker = mock.Mock(return_value="% Invalid input")
            with self.assertRaises(RuntimeError):
                lab.set_probe(node, BASE.PROBE_PREFIXES[node], True)

    def test_frr_exact_mgmtd_note_requires_matching_observed_state_and_no_other_error(self):
        note = "% Configuration applied with notes:\nNo changes found to be committed!\n"
        lab = BASE.Lab(Path("/unused"), Path("/unused"))
        lab.docker = mock.Mock(return_value=note)
        for present in (True, False):
            lab.probe_present = mock.Mock(return_value=present)
            lab.set_probe("edge-frr", BASE.PROBE_PREFIXES["edge-frr"], present)
            lab.probe_present = mock.Mock(return_value=not present)
            with self.assertRaises(AssertionError):
                lab.set_probe("edge-frr", BASE.PROBE_PREFIXES["edge-frr"], present)
        for output in (note + "% Invalid input", "% Configuration applied with notes:\nSome other problem!"):
            lab.docker = mock.Mock(return_value=output)
            with self.assertRaises(RuntimeError):
                lab.set_probe("edge-frr", BASE.PROBE_PREFIXES["edge-frr"], True)


if __name__ == "__main__":
    unittest.main()
