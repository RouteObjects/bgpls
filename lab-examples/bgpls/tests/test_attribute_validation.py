#!/usr/bin/env python3
"""Offline integration: no router, Docker, collector process, or Swift subprocess."""

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location("test_typed_" + name.replace("-", "_"), ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATE = load("attribute-validation")
BASE = load("verify")
CEOS = load("verify-ceos")


class ReplayProcessTests(unittest.TestCase):
    def test_summary_only_log_cannot_replace_required_full_dump(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = mock.Mock()
            with self.assertRaisesRegex(AssertionError, "one complete final-RIB log"):
                VALIDATE.audit(Path(directory) / "not-read.pcap",
                               "bgpls: RIB summary nodes=6 links=18 prefixes=12\n", {},
                               Path(directory) / "audit", runner=runner)
            runner.assert_not_called()

    def test_success_requires_real_fresh_artifact_and_matching_events(self):
        wire = {"schema": 2, "updates": [{"bodyHex": "00000000", "events": [], "attributeDiagnostics": []}],
                "finalRecords": []}
        def runner(command, **kwargs):
            self.assertIn("--disable-automatic-resolution", command)
            self.assertEqual(command[-1], "TypedAttributeCaptureReplayTests/externalCapture")
            self.assertEqual(kwargs["timeout"], 300)
            self.assertEqual(kwargs["cwd"], VALIDATE.ROOT)
            source = json.loads(Path(kwargs["env"]["BGPLS_ATTRIBUTE_REPLAY_INPUT"]).read_text())
            self.assertEqual(source["schema"], 2)
            result = {"schema": 2, "updateCount": 1, "updates": source["updates"], "finalRecords": [],
                      "checks": {"completeRecordReplay": True, "snapshotRoundTrips": True, "catchUpReplay": True,
                                 "updateAttributeDiagnostics": True}}
            Path(kwargs["env"]["BGPLS_ATTRIBUTE_REPLAY_OUTPUT"]).write_text(json.dumps(result))
            return subprocess.CompletedProcess(command, 0)
        with tempfile.TemporaryDirectory() as output:
            result = VALIDATE.replay_swift(wire, output, runner=runner)
            self.assertEqual(result["updateCount"], 1)
            self.assertTrue((Path(output) / "swift-replay-provenance.json").is_file())
            with self.assertRaises(FileExistsError):
                VALIDATE.replay_swift(wire, output, runner=runner)

    def test_failed_skipped_partial_or_mismatched_replay_cannot_pass(self):
        wire = {"schema": 2, "updates": [{"bodyHex": "00000000", "events": [], "attributeDiagnostics": []}],
                "finalRecords": []}
        for mode in ("failed", "skipped", "partial", "mismatch", "timeout"):
            def runner(command, **kwargs):
                if mode == "timeout":
                    raise subprocess.TimeoutExpired(command, 300)
                if mode not in ("failed", "skipped"):
                    result = {"schema": 2, "updateCount": 1, "updates": wire["updates"], "finalRecords": [],
                              "checks": {"completeRecordReplay": True, "snapshotRoundTrips": True,
                                         "catchUpReplay": mode != "partial", "updateAttributeDiagnostics": True}}
                    if mode == "mismatch":
                        result["finalRecords"] = [{"key": "unexpected"}]
                    Path(kwargs["env"]["BGPLS_ATTRIBUTE_REPLAY_OUTPUT"]).write_text(json.dumps(result))
                return subprocess.CompletedProcess(command, int(mode == "failed"))
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as output:
                with self.assertRaises((AssertionError, FileNotFoundError, subprocess.TimeoutExpired)):
                    VALIDATE.replay_swift(wire, output, runner=runner)

    def test_source_drift_fails_before_result_acceptance(self):
        with tempfile.TemporaryDirectory() as output, mock.patch.object(
                VALIDATE, "source_fingerprint", side_effect=[{"file": "before"}, {"file": "after"}]):
            with self.assertRaisesRegex(AssertionError, "source changed"):
                VALIDATE.replay_swift({"schema": 2, "updates": [], "finalRecords": []}, output,
                                     runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0))


class VerifierIntegrationTests(unittest.TestCase):
    def test_pending_attribute_selection_converges_within_callers_bounded_wait(self):
        run = VALIDATE.AttributeRun(mock.Mock(), {"frr": lambda: ""}, profile="frr")
        with mock.patch.object(run, "native", side_effect=[run.checks.NativeAttributesPending("selecting"), run.expected]) as native, \
                mock.patch.object(run.checks, "watch_records", return_value=run.expected), \
                mock.patch.object(BASE.time, "monotonic", side_effect=[0, 0, 0.5]), \
                mock.patch.object(BASE.time, "sleep") as sleep:
            BASE.wait_until("typed selection", run.ready, timeout=1)
        self.assertEqual(native.call_count, 2)
        sleep.assert_called_once_with(0.5)

    def test_persistent_attribute_selection_obeys_timeout_without_real_sleep(self):
        run = VALIDATE.AttributeRun(mock.Mock(), {"frr": lambda: ""}, profile="frr")
        with mock.patch.object(run, "native", side_effect=run.checks.NativeAttributesPending("selecting")) as native, \
                mock.patch.object(BASE.time, "monotonic", side_effect=[0, 0, 0.5, 1]), \
                mock.patch.object(BASE.time, "sleep") as sleep:
            with self.assertRaisesRegex(TimeoutError, "typed selection"):
                BASE.wait_until("typed selection", run.ready, timeout=1)
        self.assertEqual(native.call_count, 2)
        self.assertEqual(sleep.call_count, 2)

    def test_other_native_failures_do_not_become_retryable_attribute_gaps(self):
        for error in (AssertionError("ambiguous selected paths"), KeyError("malformed schema")):
            run = VALIDATE.AttributeRun(mock.Mock(), {"frr": lambda: ""}, profile="frr")
            with self.subTest(error=error), mock.patch.object(run, "native", side_effect=error) as native, \
                    mock.patch.object(BASE.time, "monotonic", side_effect=[0, 0]), \
                    mock.patch.object(BASE.time, "sleep") as sleep:
                with self.assertRaises(type(error)):
                    BASE.wait_until("typed selection", run.ready, timeout=1)
            native.assert_called_once_with("frr")
            sleep.assert_not_called()

    def test_opt_in_is_explicit_and_probe_without_attributes_fails_before_inputs(self):
        parser = argparse.ArgumentParser()
        BASE.add_transport_arguments(parser)
        options = parser.parse_args(["--binary", "/not-used", "--attributes", "--attribute-probes"])
        self.assertTrue(options.attributes)
        self.assertTrue(options.attribute_probes)
        with self.assertRaisesRegex(ValueError, "requires --attributes"):
            BASE.collector_inputs(argparse.Namespace(attribute_probes=True, attributes=False))

    def test_typed_state_replaces_and_withdraws_while_default_path_stays_unchanged(self):
        line = "link 0000.0000.0003 10.254.0.8,2001:db8:6501:5:: → 0000.0000.0004 10.254.0.9,2001:db8:6501:5::1"
        def record(metric):
            return (line + f" attributes=present igp-metric={metric} maximum-link-bandwidth=unavailable"
                    " maximum-reservable-bandwidth=unavailable unreserved-bandwidth=unavailable")
        text = "WATCH upsert " + record(10) + "\nWATCH upsert " + record(20) + "\n"
        self.assertEqual(BASE.watch_state(text, attributes=True), {line})
        self.assertEqual(BASE.watch_state(text + "WATCH upsert " + record(30)[:90], attributes=True), {line})
        self.assertEqual(BASE.watch_state(text + "WATCH withdraw " + line + "\n", attributes=True), set())
        self.assertEqual(BASE.watch_state("WATCH upsert " + line + "\n"), {line})
        self.assertEqual(BASE.final_objects([record(20)], attributes=True), {line})
        with self.assertRaises(AssertionError):
            BASE.final_objects([record(20), record(20)], attributes=True)

    def test_native_collector_option_does_not_escape_into_default_argv(self):
        lab = mock.Mock(state_info={"asn": 4200000001})
        for attributes in (False, True):
            with tempfile.TemporaryDirectory() as output, mock.patch.object(CEOS.subprocess, "Popen") as popen:
                collector = CEOS.Collector("frr", Path("/native/bgpls"), Path(output), lab=lab, attributes=attributes)
                collector.start()
                self.assertEqual("--show-attributes" in popen.call_args.args[0], attributes)
                self.assertEqual(popen.call_args.args[0].count("--dump-rib"), 1)
                self.assertIn("4200000001", popen.call_args.args[0])

    def test_ipv6_collector_receives_only_explicit_boolean_option(self):
        lab = mock.Mock(state_info={"asn": 4200000001})
        for attributes in (False, True):
            with tempfile.TemporaryDirectory() as output, mock.patch.object(CEOS.BASE, "helper") as helper:
                collector = CEOS.Collector("ceos", None, Path(output), lab=lab,
                                           artifact="artifact.json", transport="ipv6", attributes=attributes)
                collector.start()
                self.assertEqual(helper.return_value.ContainerProcess.call_args.kwargs,
                                 {"show_attributes": True} if attributes else {})

    def test_metric_cleanup_failure_does_not_prevent_other_cleanup(self):
        lab, child, attributes = mock.Mock(), mock.Mock(), mock.Mock()
        child.poll.return_value = None
        attributes.restore.side_effect = RuntimeError("restore failed")
        with mock.patch.object(BASE.signal, "signal"), self.assertRaises(BASE.CleanupFailure):
            BASE.cleanup(lab, True, child, "ipv4", attribute_run=attributes)
        lab.link.assert_called_once_with("up")
        child.terminate.assert_called_once()
        with mock.patch.object(CEOS.signal, "signal"), self.assertRaises(CEOS.BASE.CleanupFailure):
            CEOS.cleanup(lab, True, [child], attribute_run=attributes)
        child.cleanup.assert_called_once()

    def test_complete_key_collision_is_not_hidden_by_display_map(self):
        event = {"key": "first", "display": "node 0000.0000.0001", "availability": "present",
                 "attributes": {"name": "rr1"}}
        other = dict(event, key="different")
        with self.assertRaisesRegex(AssertionError, "collide"):
            VALIDATE.by_display([event, other])


if __name__ == "__main__":
    unittest.main()
