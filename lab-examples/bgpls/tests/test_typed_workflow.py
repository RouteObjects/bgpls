#!/usr/bin/env python3
"""End-to-end verifier orchestration with fake collectors; no lab or Swift calls."""

import argparse
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import signal
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location("typed_workflow_" + name.replace("-", "_"), ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("verify")
CEOS = load("verify-ceos")
CHECKS = load("attribute-checks")
STATE = load("lab-state")


def summary(record):
    """Synthetic output in the public CLI grammar, parsed by the real adapter."""
    attrs = record["attributes"]
    result = " attributes=" + record["availability"]
    if record["display"].startswith("node "):
        return result + " name=" + json.dumps(attrs["name"])
    if record["display"].startswith("prefix "):
        return result + " prefix-metric=" + str(attrs["metric"])

    def bandwidth(value):
        return f"{float(value)}B/s({float(value * 8)}bit/s)"

    return (result + f" igp-metric={attrs['igpMetric']}"
            + " maximum-link-bandwidth=" + bandwidth(attrs["maximumLinkBandwidth"])
            + " maximum-reservable-bandwidth=" + bandwidth(attrs["maximumReservableBandwidth"])
            + " unreserved-bandwidth=["
            + ",".join(f"{priority}:" + bandwidth(value) for priority, value in enumerate(attrs["unreservedBandwidth"])) + "]")


class FakeProcess:
    def __init__(self, producer, log, records, attributes, events, *, cleanup_error=None):
        self.producer, self.log = producer, log
        self.records, self.attributes = records, attributes
        self.events, self.cleanup_error = events, cleanup_error
        self.metadata = {"producer": producer, "removed": False}
        self.returncode = None
        self.selected = None

    def start(self):
        self.events.append("start-" + self.producer)
        lines = ["bgpls: state Established"]
        lines += ["WATCH upsert " + display + (summary(record) if self.attributes else "")
                  for display, record in sorted(self.records.items())]
        self.log.write_text("\n".join(lines) + "\n")

    def poll(self):
        return self.returncode

    def refresh(self):
        pass

    def send_signal(self, selected):
        self.selected = selected
        self.events.append(("signal-" + self.producer, selected))

    def wait(self, timeout):
        if timeout != 15:
            raise AssertionError("unexpected wait deadline")
        if self.selected is None:
            raise AssertionError("wait occurred before shutdown selection")
        lines = [f"bgpls: {signal.Signals(self.selected).name} — stopping session…", "bgpls: RIB final",
                 BASE.rib_summary(self.records)]
        lines += [display + ((" AS not-advertised" if self.producer == "frr" else " AS 4200000001")
                             if display.startswith("node ") else "")
                  + (summary(record) if self.attributes else "")
                  for display, record in sorted(self.records.items())]
        with self.log.open("a") as stream:
            stream.write("\n".join(lines) + "\n")
        self.returncode = 128 + self.selected
        self.events.append("stopped-" + self.producer)
        return self.returncode

    def terminate(self):
        self.send_signal(signal.SIGTERM)

    def kill(self):
        raise AssertionError("mock collector should not require escalation")

    def cleanup(self):
        self.events.append("container-cleanup-" + self.producer)
        if self.cleanup_error is not None:
            raise self.cleanup_error
        self.metadata["removed"] = True


class TypedWorkflowTests(unittest.TestCase):
    def exercise(self, *, profile="ceos", transport="ipv4", attributes=True, probes=False,
                 reverse=False, audit_error=None, cleanup_error=None, probe_error=None, restore_error=None,
                 provenance_error=None):
        module = CEOS if profile == "ceos" else BASE
        base = CEOS.BASE if profile == "ceos" else BASE
        records = CHECKS.expected_records(profile)
        baseline = set(records)
        producers = ("frr", "ceos") if profile == "ceos" else ("frr",)
        events, saved, processes, launches = [], {}, {}, []
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            lab = mock.Mock()
            lab.state_info = {"asn": 4200000001}
            lab.native_objects.return_value = baseline
            lab.verify_routing.return_value = True
            lab.preflight.side_effect = lambda: events.append("preflight")

            def neighbor(producer="frr"):
                endpoint = base.TRANSPORTS[producer][transport]
                return {"bgpState": "Established", "hostForeign": endpoint["source"], "hostLocal": endpoint["peer"],
                        "portForeign": 40000, "portLocal": 179, "connectionsEstablished": 1, "connectionsDropped": 0,
                        "localAs": 4200000001, "remoteAs": 4200000001,
                        "bgpTimerUpMsec": 12000, "messageStats": {"keepalivesRecv": 5, "keepalivesSent": 5}}

            lab.neighbor.side_effect = neighbor
            lab.producer_neighbor.side_effect = neighbor

            def save(name, value):
                saved[name] = copy.deepcopy(value)
                events.append("save-" + name)
                if name == "result":
                    for producer in producers:
                        self.assertIsNotNone(processes[producer].poll())
                        if transport == "ipv6":
                            self.assertTrue(processes[producer].metadata["removed"])

            lab.save.side_effect = save
            attribute_run = mock.Mock()
            attribute_run.ready.return_value = True
            attribute_run.capture.side_effect = lambda phase: events.append("typed-capture-" + phase)
            attribute_run.probe_results = []
            attribute_run.native.side_effect = lambda producer: {"producer": producer, "source": "native"}

            def exercise_probes(wait):
                events.append("probe-exercise")
                for producer in producers:
                    events.append("probe-apply-" + producer)
                    if probe_error is not None:
                        raise probe_error
                    wait("mock metric advertised", lambda: True)
                    events.append("probe-restore-" + producer)
                    wait("mock metric restored", lambda: True)
                    attribute_run.probe_results.append({"producer": producer, "before": 10, "target": 20})

            attribute_run.exercise.side_effect = exercise_probes

            def restore():
                events.append("typed-restore")
                if restore_error is not None:
                    raise restore_error

            attribute_run.restore.side_effect = restore
            provenance = {"source": "mock-current-source", "transport": transport}
            validation = mock.Mock()

            def prepare_provenance(binary, artifact, output):
                self.assertTrue(output.is_dir())
                self.assertEqual(binary is not None, transport == "ipv4")
                self.assertEqual(artifact is not None, transport == "ipv6")
                events.append("provenance")
                return provenance

            validation.collector_provenance.side_effect = prepare_provenance

            def verify_provenance(value):
                self.assertEqual(value, provenance)
                events.append("verify-provenance")
                if provenance_error is not None:
                    raise provenance_error

            validation.verify_collector_provenance.side_effect = verify_provenance

            def construct_attribute_run(actual_lab, logs, *, profile):
                self.assertIs(actual_lab, lab)
                self.assertEqual(set(logs), set(producers))
                self.assertEqual(profile, "ceos" if len(producers) == 2 else "frr")
                for reader in logs.values():
                    self.assertEqual(CHECKS.watch_records(reader()), records)
                events.append("typed-run")
                return attribute_run

            validation.AttributeRun.side_effect = construct_attribute_run

            def audit(pcap, text, native, output, *, profile, probes, producer="frr"):
                self.assertEqual(producer, native["producer"])
                self.assertIsNotNone(processes[producer].poll(), "audit must inspect a drained collector")
                self.assertEqual(CHECKS.watch_records(text), records)
                self.assertEqual(CHECKS.final_records(text), records)
                self.assertEqual(profile, "ceos" if len(producers) == 2 else "frr")
                self.assertEqual(probes, attribute_run.probe_results)
                self.assertEqual(output.name, "attributes-" + producer)
                events.append("audit-" + producer)
                if audit_error is not None:
                    raise audit_error
                return {"audited": True, "producer": producer, "probe_count": len(probes)}

            validation.audit.side_effect = audit

            def construct_container(actual_lab, producer, artifact, output, log, pcap, **kwargs):
                self.assertIs(actual_lab, lab)
                self.assertFalse(log.exists())
                self.assertEqual(kwargs, {"show_attributes": True} if attributes else {})
                launches.append((producer, kwargs))
                process = FakeProcess(producer, log, records, kwargs.get("show_attributes", False), events,
                                      cleanup_error=cleanup_error if producer == "frr" else None)
                processes[producer] = process
                return process

            factory = types.SimpleNamespace(ContainerProcess=construct_container)

            def helper(name):
                if name == "attribute-validation":
                    return validation
                if name == "attribute-checks":
                    return CHECKS
                if name == "container-collector":
                    return factory
                if name == "lab-state":
                    return STATE
                raise AssertionError("unexpected helper in offline fake workflow: " + name)

            def launch(arguments, *, stdout, stderr):
                producer = "ceos" if arguments[arguments.index("--port") + 1] == "11791" else "frr"
                for option in ("--local-as", "--peer-as"):
                    self.assertEqual(arguments[arguments.index(option) + 1], "4200000001")
                self.assertEqual(arguments.count("--show-attributes"), int(attributes))
                self.assertEqual(arguments.count("--dump-rib"), 1)
                launches.append((producer, list(arguments)))
                process = FakeProcess(producer, Path(stdout.name), records, "--show-attributes" in arguments, events)
                processes[producer] = process
                process.start()
                return process

            def ready(description, condition, *_args, **_kwargs):
                self.assertTrue(condition(), description)

            def survivor(_lab, collector, *_args):
                self.assertIsNone(collector.process.poll())
                events.append("survivor-" + collector.producer)

            stdout = io.StringIO()
            args = argparse.Namespace(churn=False, signal="INT", reverse_shutdown=reverse,
                                      attributes=attributes, attribute_probes=probes)
            error = None
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(module, "CeosLab" if profile == "ceos" else "Lab", return_value=lab))
                stack.enter_context(mock.patch.object(base, "helper", side_effect=helper))
                stack.enter_context(mock.patch.object(base, "wait_until", side_effect=ready))
                stack.enter_context(mock.patch.object(base.subprocess, "Popen", side_effect=launch))
                stack.enter_context(mock.patch.object(base, "validate_pcap", return_value={"complete": True}))
                stack.enter_context(mock.patch.object(base.WIRE, "audit_capture", return_value={"complete_keys": True}))
                stack.enter_context(mock.patch.object(base.signal, "signal"))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                if profile == "ceos":
                    stack.enter_context(mock.patch.object(CEOS, "verify_independent_survivor", side_effect=survivor))
                try:
                    status = module.run_locked(args, state, transport, Path(sys.executable) if transport == "ipv4" else None,
                                               state / "artifact.json" if transport == "ipv6" else None)
                    self.assertEqual(status, 0)
                except Exception as caught:
                    error = caught
            return types.SimpleNamespace(events=events, saved=saved, error=error, stdout=stdout.getvalue(),
                                         validation=validation, attributes=attribute_run, launches=launches,
                                         processes=processes, lab=lab)

    def test_both_profiles_and_transports_enrich_collectors_and_audit_before_success(self):
        for profile in ("frr", "ceos"):
            for transport in ("ipv4", "ipv6"):
                with self.subTest(profile=profile, transport=transport):
                    result = self.exercise(profile=profile, transport=transport)
                    self.assertIsNone(result.error)
                    self.assertIn("result", result.saved)
                    events = result.events
                    self.assertLess(events.index("provenance"), events.index("preflight"))
                    self.assertLess(events.index("typed-capture-restored"), events.index("audit-frr"))
                    self.assertLess(events.index("audit-frr"), events.index("typed-restore"))
                    self.assertLess(events.index("typed-restore"), events.index("verify-provenance"))
                    self.assertLess(events.index("verify-provenance"), events.index("save-result"))
                    self.assertEqual(result.validation.audit.call_count, 2 if profile == "ceos" else 1)
                    result.attributes.exercise.assert_not_called()
                    result.attributes.restore.assert_called_once()
                    result.lab.link.assert_not_called()
                    if transport == "ipv6":
                        self.assertLess(events.index("typed-restore"), events.index("container-cleanup-frr"))
                        self.assertLess(events.index("container-cleanup-frr"), events.index("save-result"))

    def test_paired_explicit_probes_restore_before_audit_in_both_transports(self):
        for transport in ("ipv4", "ipv6"):
            result = self.exercise(transport=transport, probes=True)
            self.assertIsNone(result.error)
            result.attributes.exercise.assert_called_once()
            for producer in ("frr", "ceos"):
                self.assertLess(result.events.index("probe-apply-" + producer), result.events.index("probe-restore-" + producer))
                self.assertLess(result.events.index("probe-restore-" + producer), result.events.index("audit-" + producer))
                self.assertEqual(result.saved["result"]["producers"][producer]["typed_attributes"]["probe_count"], 2)

    def test_paired_reverse_shutdown_preserves_real_collector_signal_selection(self):
        for transport in ("ipv4", "ipv6"):
            result = self.exercise(transport=transport, reverse=True)
            self.assertIsNone(result.error)
            self.assertEqual(result.processes["ceos"].returncode, 130)
            self.assertEqual(result.processes["frr"].returncode, 143)
            self.assertEqual(result.saved["result"]["shutdown_order"], ["ceos", "frr"])

    def test_default_runs_require_full_dump_without_typed_checks_or_attribute_flag(self):
        for profile in ("frr", "ceos"):
            for transport in ("ipv4", "ipv6"):
                with self.subTest(profile=profile, transport=transport):
                    result = self.exercise(profile=profile, transport=transport, attributes=False)
                    self.assertIsNone(result.error)
                    self.assertIn("result", result.saved)
                    result.validation.collector_provenance.assert_not_called()
                    result.validation.AttributeRun.assert_not_called()
                    result.validation.audit.assert_not_called()
                    result.validation.verify_collector_provenance.assert_not_called()
                    self.assertNotIn("typed-restore", result.events)
                    self.assertNotIn("collector_provenance", result.saved["result"])

    def test_audit_failure_preserves_evidence_and_cleans_both_collectors(self):
        failure = AssertionError("typed wire audit mismatch")
        result = self.exercise(transport="ipv6", audit_error=failure)
        self.assertIs(result.error, failure)
        self.assertNotIn("result", result.saved)
        self.assertEqual(result.saved["failure"]["error"], str(failure))
        self.assertNotIn("PASS: both native RIBs", result.stdout)
        for producer in ("frr", "ceos"):
            self.assertTrue(result.processes[producer].metadata["removed"])
        result.attributes.restore.assert_called_once()

    def test_probe_failure_and_restore_failure_preserve_both_and_suppress_result(self):
        primary = TimeoutError("attribute convergence timed out")
        rollback = OSError("metric restoration failed")
        result = self.exercise(transport="ipv6", probes=True, probe_error=primary, restore_error=rollback)
        self.assertIs(result.error.primary_error, primary)
        self.assertIs(result.error.cleanup_error.failures[0][1], rollback)
        self.assertNotIn("result", result.saved)
        result.validation.audit.assert_not_called()
        for producer in ("frr", "ceos"):
            self.assertTrue(result.processes[producer].metadata["removed"])
        result.attributes.restore.assert_called_once()

    def test_collector_cleanup_failure_suppresses_top_level_success(self):
        failure = OSError("owned collector removal failed")
        result = self.exercise(transport="ipv6", cleanup_error=failure)
        self.assertIs(result.error.failures[0][1], failure)
        self.assertNotIn("result", result.saved)
        self.assertNotIn("PASS: both native RIBs", result.stdout)
        self.assertEqual(result.validation.audit.call_count, 2)
        self.assertTrue(result.processes["ceos"].metadata["removed"])
        result.validation.verify_collector_provenance.assert_not_called()

    def test_late_provenance_drift_never_publishes_success(self):
        failure = AssertionError("collector changed during qualification")
        result = self.exercise(transport="ipv6", provenance_error=failure)
        self.assertIs(result.error, failure)
        self.assertNotIn("result", result.saved)
        self.assertNotIn("PASS: both native RIBs", result.stdout)
        self.assertTrue(all(process.metadata["removed"] for process in result.processes.values()))

    def test_probe_flag_requires_attributes_before_any_runtime_preparation(self):
        for module in (BASE, CEOS.BASE):
            parser = argparse.ArgumentParser()
            module.add_transport_arguments(parser)
            options = parser.parse_args(["--binary", sys.executable, "--attribute-probes"])
            with mock.patch.object(module, "helper") as helper, self.assertRaisesRegex(ValueError, "requires --attributes"):
                module.collector_inputs(options)
            helper.assert_not_called()

    def test_historical_capture_expectations_remain_explicit_and_separate(self):
        for producer in ("frr", "ceos"):
            for transport in ("ipv4", "ipv6"):
                current = BASE.capture_expectation(producer, transport, 65001)
                historical = BASE.capture_expectation(producer, transport, 65001, legacy_collector=True)
                self.assertEqual(historical, {**current, "legacy_collector": True})
                self.assertFalse(current["legacy_collector"])
                self.assertNotIn("attributes", current)
                with self.assertRaises(ValueError):
                    BASE.capture_expectation(producer, transport, 4200000001, legacy_collector=True)


if __name__ == "__main__":
    unittest.main()
