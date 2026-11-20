#!/usr/bin/env python3
"""Offline typed-presentation/native/probe checks; no runtime or lab commands."""

import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("bgpls_attribute_checks", Path(__file__).resolve().parents[1] / "attribute-checks.py")
CHECKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKS)

NODE = "node 0000.0000.0001"
LINK = "link 0000.0000.0001 10.254.0.0,2001:db8:6501:1:: → 0000.0000.0003 10.254.0.1,2001:db8:6501:1::1"
PREFIX = "prefix 2001:db8:6501::1/128 node 0000.0000.0001"


def link_text(metric=10, bandwidth=1250000.0):
    value = f"{bandwidth}B/s({bandwidth * 8}bit/s)"
    priorities = ",".join(f"{index}:{value}" for index in range(8))
    return (f"{LINK} attributes=present igp-metric={metric} maximum-link-bandwidth={value} "
            f"maximum-reservable-bandwidth={value} unreserved-bandwidth=[{priorities}]")


class PresentationTests(unittest.TestCase):
    def test_full_watch_prefix_and_quoted_attribute_delimiter(self):
        # Build the escape explicitly so this regression is readable without a
        # Python/Swift quoting coincidence.
        line = f'bgpls: 04:48:41.020 WATCH upsert {NODE} attributes=present name="literal attributes=present '
        line += '\\"name\\""'
        record = CHECKS.parse_line(line)
        self.assertEqual(record, {"display": NODE, "availability": "present", "attributes": {"name": 'literal attributes=present "name"'}})

    def test_every_emitted_ascii_escape(self):
        encoded = r'"\0\t\n\r\"\\\u{1}\u{1b}\u{7f}"'
        parsed = CHECKS.parse_line(f"WATCH upsert {NODE} attributes=present name={encoded}")
        self.assertEqual(parsed["attributes"]["name"], '\0\t\n\r"\\\x01\x1b\x7f')

    def test_names_empty_ascii_boundaries_and_unavailable(self):
        for name in ("", "a" * 255, " attributes=discarded name=unavailable "):
            with self.subTest(name=name):
                self.assertEqual(CHECKS.parse_line(f'WATCH upsert {NODE} attributes=present name="{name}"')["attributes"]["name"], name)
        for availability in ("present", "absent", "discarded"):
            record = CHECKS.parse_line(f"WATCH upsert {NODE} attributes={availability} name=unavailable")
            self.assertIsNone(record["attributes"]["name"])

    def test_reject_invalid_names_suffixes_and_partial_grammar(self):
        bad = ['"a" junk', '"a" attributes=present', '"é"', '"a\t"', r'"\x1b"', r'"\u{80}"',
               r'"\u{a}"', r'"\u{41}"', '"' + "a" * 256 + '"', '"unterminated']
        for encoded in bad:
            with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                CHECKS.parse_line(f"WATCH upsert {NODE} attributes=present name={encoded}")
        with self.assertRaises(ValueError):
            CHECKS.parse_line(f'WATCH upsert {NODE} attributes=absent name="not absent"')

    def test_bandwidth_units_priority_order_and_zero(self):
        for value in (0.0, 1250000.0, 125000000.0):
            attrs = CHECKS.parse_line("WATCH upsert " + link_text(bandwidth=value))["attributes"]
            self.assertEqual(attrs["maximumLinkBandwidth"], value)
            self.assertEqual(attrs["unreservedBandwidth"], [value] * 8)
        failures = [link_text().replace("10000000.0bit/s", "1250000.0bit/s", 1),
                    link_text().replace("0:1250000", "1:1250000", 1),
                    link_text().replace("B/s", "b/s", 1),
                    link_text().replace("igp-metric=10", "igp-metric=4294967296"),
                    link_text().replace("1250000.0B/s", "nanB/s", 1),
                    link_text().replace("1250000.0B/s", "-1.0B/s", 1)]
        for text in failures:
            with self.subTest(text=text), self.assertRaises(ValueError):
                CHECKS.parse_line("WATCH upsert " + text)

    def test_all_applicable_fields_explicitly_none(self):
        text = (f"WATCH upsert {LINK} attributes=discarded igp-metric=unavailable "
                "maximum-link-bandwidth=unavailable maximum-reservable-bandwidth=unavailable unreserved-bandwidth=unavailable")
        self.assertEqual(CHECKS.parse_line(text)["attributes"], dict.fromkeys(CHECKS.FIELDS["link"]))
        self.assertEqual(CHECKS.parse_line(f"WATCH upsert {PREFIX} attributes=present prefix-metric=0")["attributes"], {"metric": 0})

    def test_refresh_replacement_withdrawal_and_event_order(self):
        first = "WATCH upsert " + link_text()
        changed = "WATCH upsert " + link_text(metric=20)
        text = f"bgpls: WATCH snapshot nodes=0 links=0 prefixes=0\n{first}\n{first}\n{changed}\n"
        events = CHECKS.watch_events(text)
        self.assertEqual(len(events), 3)
        self.assertEqual(CHECKS.watch_records(text)[LINK]["attributes"]["igpMetric"], 20)
        self.assertEqual(CHECKS.watch_records(text + f"WATCH withdraw {LINK}\n"), {})
        self.assertEqual(CHECKS.watch_events(f"WATCH withdraw {LINK}\n"), [{"operation": "withdraw", "display": LINK}])
        with self.assertRaises(ValueError):
            CHECKS.watch_records(f"WATCH withdraw {LINK} attributes=present\n")
        # Polling can observe a partially written final line. Do not install it
        # or reject its unfinished grammar before the terminating newline.
        self.assertEqual(CHECKS.watch_records(first), {})
        self.assertEqual(CHECKS.watch_records(first + "\n" + changed[:-8]),
                         CHECKS.watch_records(first + "\n"))
        self.assertEqual(CHECKS.watch_records(first + "\n" + changed + "\n")[LINK]["attributes"]["igpMetric"], 20)

    def test_present_to_absent_replaces_all_prior_values(self):
        text = f'WATCH upsert {NODE} attributes=present name="rr1"\n'
        for availability in ("absent", "discarded", "present"):
            with self.subTest(availability=availability):
                result = CHECKS.watch_records(text + f"WATCH upsert {NODE} attributes={availability} name=unavailable\n")
                self.assertEqual(result[NODE], {"display": NODE, "availability": availability, "attributes": {"name": None}})

    def test_final_node_as_identity_and_duplicate_detection(self):
        text = f'bgpls: RIB final\nnodes=1 links=0 prefixes=0\n{NODE} AS 4200000001 attributes=present name="rr1"\n'
        self.assertEqual(set(CHECKS.final_records(text)), {NODE})
        self.assertEqual(CHECKS.final_records(text)[NODE]["attributes"], {"name": "rr1"})
        with self.assertRaises(ValueError):
            CHECKS.final_records(text + text)
        with self.assertRaises(ValueError):
            CHECKS.parse_line(f'{NODE} attributes=present name="rr1"', final=True)
        with self.assertRaises(ValueError):
            CHECKS.parse_line(f'WATCH upsert {NODE} AS 65001 attributes=present name="rr1"')

    def test_current_and_historical_missing_asn_are_identical_projections(self):
        suffix = ' attributes=present name="rr1"'
        expected = CHECKS.parse_line(f"WATCH upsert {NODE}{suffix}")
        for label in ("not-advertised", "?", "0", "65001", "4200000001", "4294967295"):
            with self.subTest(label=label):
                text = f"bgpls: RIB final\nnodes=1 links=0 prefixes=0\n{NODE} AS {label}{suffix}\n"
                self.assertEqual(CHECKS.final_records(text), {NODE: expected})
                for operation in ("upsert", "withdraw"):
                    with self.assertRaises(ValueError):
                        CHECKS.parse_line(f"WATCH {operation} {NODE} AS {label}"
                                          + (suffix if operation == "upsert" else ""))

    def test_malformed_asn_labels_are_not_accepted_as_final_node_records(self):
        for label in ("", "not-advertise", "not-advertised?", "not-advertised-extra", "Not-advertised",
                      "not advertised", "??", "?suffix", "+65001", "-1", "AS65001", "65001suffix", "1.10"):
            with self.subTest(label=label), self.assertRaises(ValueError):
                CHECKS.parse_line(f'{NODE} AS {label} attributes=present name="rr1"', final=True)

    def test_noncanonical_addresses_prefixes_and_malformed_line_prefix(self):
        for line in ("WATCH upsert " + link_text().replace("2001:db8:", "2001:DB8:", 1),
                     f"WATCH upsert {PREFIX.replace('::1/128', '::1/64')} attributes=present prefix-metric=10",
                     f'garbage WATCH upsert {NODE} attributes=present name="rr1"'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                CHECKS.parse_line(line)


def frr_table(kind="link", attrs=None):
    nlri = {"protocolId": 2, "identifier": 0, "nlriType": kind,
            "localNodeDescriptors": {"igpRouterId": "0000.0000.0001.00"}}
    if kind == "link":
        nlri.update(remoteNodeDescriptors={"igpRouterId": "0000.0000.0003.00"},
                    linkDescriptors={"ipv4InterfaceAddress": "10.254.0.0", "ipv4NeighborAddress": "10.254.0.1",
                                     "ipv6InterfaceAddress": "2001:db8:6501:1::", "ipv6NeighborAddress": "2001:db8:6501:1::1"})
    elif kind in ("ipv4Prefix", "ipv6Prefix"):
        nlri["prefixDescriptors"] = {"ipReachabilityInformation": "2001:db8:6501::1/128" if kind == "ipv6Prefix" else "10.255.0.1/32"}
    path = {"valid": True, "bestpath": True, "nlri": nlri}
    if attrs is not None:
        path["linkStateAttrs"] = attrs
    return {"routes": {"not-parsed": [path]}}


def ceos_table(kind="link", attrs=None):
    descriptor = {"igpRouterIdType": "isisSystemId", "isisSystemId": "0000.0000.0001", "asn": "4200000001"}
    path = {"routeType": {"valid": True, "active": True}, "peerEntry": {"peerAddr": ""},
            "asPathEntry": {"asPathType": "Local"}, "routeDetail": {}}
    route = {"protocolId": "isisLevel2", "identifier": 0, "nlriType": kind,
             "localNodeDescriptor": descriptor, "paths": [path]}
    if kind == "link":
        route.update(remoteNodeDescriptor={**descriptor, "isisSystemId": "0000.0000.0003"},
                     linkDescriptor={"localIpv4Addrs": ["10.254.0.0"], "remoteIpv4Addrs": ["10.254.0.1"],
                                     "localIpv6Addrs": ["2001:db8:6501:1::"], "remoteIpv6Addrs": ["2001:db8:6501:1::1"]})
        field = "bgpLsLinkAttributes"
    elif kind == "node":
        field = "bgpLsNodeAttributes"
    else:
        route["prefixDescriptor"] = {"prefix": "2001:db8:6501::1/128" if kind == "ipv6Prefix" else "10.255.0.1/32"}
        field = "bgpLsPrefixAttributes"
    if attrs is not None:
        path["routeDetail"][field] = attrs
    return {"vrfs": {"default": {"bgpLsRoutes": {"not-parsed": route}}}}


class NativeTests(unittest.TestCase):
    def test_pending_selection_uses_the_stable_adapter_exception(self):
        table = frr_table(attrs={"igpMetric": 10})
        table["routes"]["not-parsed"][0]["bestpath"] = False
        for _ in range(2):
            with self.assertRaises(CHECKS.NativeAttributesPending) as raised:
                CHECKS.native_records(table, "frr")
            self.assertEqual(type(raised.exception.__cause__).__name__, "NativeSelectionPending")
        table["routes"]["not-parsed"][0]["bestpath"] = True
        self.assertEqual(CHECKS.native_records(table, "frr")[LINK]["attributes"]["igpMetric"], 10)

    def test_ambiguous_and_malformed_native_data_are_not_pending(self):
        table = frr_table(attrs={})
        table["routes"]["not-parsed"].append(copy.deepcopy(table["routes"]["not-parsed"][0]))
        with self.assertRaises(AssertionError) as ambiguous:
            CHECKS.native_records(table, "frr")
        self.assertNotIsInstance(ambiguous.exception, CHECKS.NativeAttributesPending)
        with self.assertRaises(KeyError):
            CHECKS.native_records({"routes": {"key": [{"valid": True, "bestpath": True}]}}, "frr")

    def test_explicit_vendor_units_priority_schema(self):
        frr = {"igpMetric": 10, "maxLinkBandwidth": 1250000, "maxResvLinkBandwidth": 1250000,
               "unreservedBandwidth": [{f"classType{index}": index * 1250000} for index in range(8)]}
        eos = {"igpMetric": 10, "maxLinkBw": 10000000, "maxReservableLinkBw": 10000000,
               "unreservedBw": {f"priority{index}": index * 10000000 for index in range(8)}}
        frr_record = CHECKS.native_records(frr_table(attrs=frr), "frr")[LINK]
        eos_record = CHECKS.native_records(ceos_table(attrs=eos), "ceos", 4200000001)[LINK]
        self.assertEqual(frr_record, eos_record)
        self.assertEqual(frr_record["attributes"]["unreservedBandwidth"], [index * 1250000 for index in range(8)])

    def test_missing_is_not_zero_and_empty_group_is_present(self):
        for producer, factory in (("frr", frr_table), ("ceos", ceos_table)):
            for attrs, availability in ((None, "absent"), ({}, "present"), ({"igpMetric": 0}, "present")):
                with self.subTest(producer=producer, attrs=attrs):
                    result = CHECKS.native_records(factory(attrs=attrs), producer, 4200000001)[LINK]
                    self.assertEqual(result["availability"], availability)
                    self.assertIsNone(result["attributes"]["maximumLinkBandwidth"])
                    self.assertEqual(result["attributes"]["igpMetric"], 0 if attrs else None)

    def test_node_prefix_both_families(self):
        for producer, factory in (("frr", frr_table), ("ceos", ceos_table)):
            self.assertEqual(next(iter(CHECKS.native_records(factory("node", {"nodeName": "rr1"}), producer, 4200000001).values()))["attributes"], {"name": "rr1"})
            for kind in ("ipv4Prefix", "ipv6Prefix"):
                result = CHECKS.native_records(factory(kind, {"prefixMetric" if producer == "frr" else "metric": 10}), producer, 4200000001)
                self.assertEqual(next(iter(result.values()))["attributes"], {"metric": 10})

    def test_bad_native_numbers_priorities_and_colliding_identities(self):
        for attrs in ({"igpMetric": True}, {"igpMetric": -1}, {"maxLinkBandwidth": float("nan")},
                      {"unreservedBandwidth": []}, {"unreservedBandwidth": [{"classType0": 0}] * 8}):
            with self.subTest(attrs=attrs), self.assertRaises(ValueError):
                CHECKS.native_records(frr_table(attrs=attrs), "frr")
        table = frr_table(attrs={})
        table["routes"]["duplicate"] = copy.deepcopy(table["routes"]["not-parsed"])
        with self.assertRaises(ValueError):
            CHECKS.native_records(table, "frr")

    def test_origin_aware_baseline_profiles(self):
        for profile, count in (("frr", 29), ("ceos", 36)):
            result = CHECKS.expected_records(profile)
            self.assertEqual(len(result), count)
            for display, record in result.items():
                if display.startswith("link "):
                    ceos_origin = display.split()[1] == "0000.0000.0006"
                    self.assertEqual(record["attributes"]["maximumLinkBandwidth"], 125000000 if ceos_origin else 1250000)
                    self.assertEqual(record["attributes"]["maximumReservableBandwidth"], 0 if ceos_origin else 1250000)


class MockRouter:
    def __init__(self, producer="frr", metric=None):
        self.interface = "eth3" if producer == "frr" else "Ethernet1"
        self.commands = ["ip router isis CORE" if producer == "frr" else "isis enable CORE",
                         "isis circuit-type " + ("level-2-only" if producer == "frr" else "level-2"),
                         "isis network point-to-point"]
        if metric is not None:
            self.commands.append(f"isis metric {metric}")
        self.calls = []
        self.failure = None
        self.ignore_restore = False
        self.probe = CHECKS.MetricProbe(producer, self.read, self.configure, self.metric, timeout=3)

    def read(self, node, interface, *, timeout):
        self.calls.append(("read", node, interface, timeout))
        return f"interface {self.interface}\n" + "\n".join(" " + command for command in self.commands) + "\n!\n"

    def metric(self, node, interface, *, timeout):
        self.calls.append(("metric", node, interface, timeout))
        return next((int(line.split()[-1]) for line in self.commands if line.startswith("isis metric ")), 10)

    def configure(self, node, commands, *, timeout):
        self.calls.append(("configure", node, list(commands), timeout))
        self.assert_armed()
        if not (self.ignore_restore and commands[2] == "no isis metric"):
            self.commands = [line for line in self.commands if not line.startswith("isis metric ")]
            if commands[2] != "no isis metric":
                self.commands.append(commands[2])
        if self.failure is not None:
            error, self.failure = self.failure, None
            raise error

    def assert_armed(self):
        if not self.probe.armed:
            raise AssertionError("rollback must be armed before every write")


class MetricProbeTests(unittest.TestCase):
    def test_cross_vendor_circuit_type_spelling_rejected_before_write(self):
        for producer, wrong in (("frr", "level-2"), ("ceos", "level-2-only")):
            router = MockRouter(producer)
            router.commands[1] = f"isis circuit-type {wrong}"
            with self.subTest(producer=producer), self.assertRaisesRegex(ValueError, "Level-2 point-to-point CORE"):
                router.probe.apply()
            self.assertFalse(router.probe.armed)
            self.assertFalse(any(call[0] == "configure" for call in router.calls))

    def test_both_vendors_restore_implicit_and_explicit_configuration(self):
        for producer in ("frr", "ceos"):
            for metric in (None, 11):
                router = MockRouter(producer, metric)
                before = list(router.commands)
                with router.probe:
                    self.assertEqual(router.commands[-1], "isis metric 20")
                    self.assertTrue(router.probe.armed)
                self.assertEqual(router.commands, before)
                self.assertFalse(router.probe.armed)
                writes = [call for call in router.calls if call[0] == "configure"]
                self.assertEqual(writes[-1][2][2], "no isis metric" if metric is None else "isis metric 11")
                self.assertTrue(all(call[-1] == 3 for call in router.calls))
                router.probe.restore()
                self.assertEqual(len([call for call in router.calls if call[0] == "configure"]), 2)

    def test_timeout_partial_command_and_interruption_restore(self):
        for error in (TimeoutError("partial write"), RuntimeError("command failed"), KeyboardInterrupt()):
            router = MockRouter()
            before = list(router.commands)
            router.failure = error
            with self.assertRaises(type(error)):
                router.probe.apply()
            self.assertEqual(router.commands, before)
            self.assertFalse(router.probe.armed)
        router = MockRouter()
        with self.assertRaises(KeyboardInterrupt):
            with router.probe:
                raise KeyboardInterrupt()
        self.assertFalse(router.probe.armed)

    def test_unsupported_config_and_drift_fail_before_write(self):
        for line in ("isis metric level-2 10", "isis metric 10 level-2", "isis ipv6 metric 10", "no isis metric"):
            router = MockRouter()
            router.commands.append(line)
            with self.subTest(line=line), self.assertRaises(ValueError):
                router.probe.apply()
            self.assertFalse(any(call[0] == "configure" for call in router.calls))
        router = MockRouter()
        router.probe.prepare()
        router.commands.append("description changed")
        with self.assertRaises(ValueError):
            router.probe.apply()
        self.assertFalse(any(call[0] == "configure" for call in router.calls))

    def test_restore_refuses_unowned_drift_and_remains_armed(self):
        router = MockRouter()
        router.probe.apply()
        router.commands[-1] = "isis metric 33"
        with self.assertRaises(RuntimeError):
            router.probe.restore()
        self.assertTrue(router.probe.armed)
        self.assertEqual(router.commands[-1], "isis metric 33")
        self.assertEqual(len([call for call in router.calls if call[0] == "configure"]), 1)

    def test_failed_restoration_remains_armed(self):
        router = MockRouter()
        router.probe.apply()
        router.ignore_restore = True
        with self.assertRaises(RuntimeError):
            router.probe.restore()
        self.assertTrue(router.probe.armed)

    def test_original_and_failed_rollback_errors_are_both_reported(self):
        router = MockRouter()
        router.failure = TimeoutError("partial metric write")
        router.ignore_restore = True
        with self.assertRaisesRegex(RuntimeError, "partial metric write.*rollback also failed.*restoration failed"):
            router.probe.apply()
        self.assertTrue(router.probe.armed)

    def test_evidence_precedes_write_and_invalid_limits_rejected(self):
        router = MockRouter()
        seen = []
        router.probe.record = lambda event, data: seen.append((event, data, len(router.calls)))
        with router.probe:
            self.assertEqual([event for event, _, _ in seen], ["prepared", "armed", "applied"])
            self.assertIn("configuration", seen[0][1])
        self.assertEqual(seen[-1][0], "restored")
        for kwargs in ({"timeout": 0}, {"timeout": float("inf")}, {"timeout": 31}, {"target_metric": 64}, {"target_metric": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                CHECKS.MetricProbe("frr", router.read, router.configure, router.metric, **kwargs)


if __name__ == "__main__":
    unittest.main()
