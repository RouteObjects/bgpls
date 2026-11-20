#!/usr/bin/env python3
"""Offline provenance and publication gates; no Swift, containers, or router I/O."""

import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location("provenance_test_" + name.replace("-", "_"),
                                                ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATE = load("attribute-validation")
VERIFY = load("verify")
CEOS = load("verify-ceos")


def source_fixture(directory):
    root = Path(directory)
    for name, value in {
        "Package.swift": "manifest", "Package.resolved": "pins",
        "Sources/Client.swift": "production", "Tests/ClientTests.swift": "tests",
    }.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    built = root / "build"
    built.mkdir()
    (built / "bgpls").write_bytes(b"current executable")
    binary = root / "selected-bgpls"
    binary.write_bytes(b"current executable")
    output = root / "evidence"
    output.mkdir()
    return root, binary, built, output


def build_runner(built):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=str(built) + "\n")
    return mock.Mock(side_effect=run)


def swift_result(wire):
    return {"schema": 2, "updateCount": len(wire["updates"]),
            "updates": copy.deepcopy(wire["updates"]), "finalRecords": copy.deepcopy(wire["finalRecords"]),
            "checks": {"completeRecordReplay": True, "snapshotRoundTrips": True, "catchUpReplay": True,
                       "updateAttributeDiagnostics": True}}


class NativeCollectorProvenanceTests(unittest.TestCase):
    def test_fresh_native_build_is_hash_bound_before_provenance_is_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root, binary, built, output = source_fixture(directory)
            runner = build_runner(built)
            with mock.patch.object(VALIDATE, "ROOT", root):
                result = VALIDATE.collector_provenance(binary, None, output, runner=runner)
                VALIDATE.verify_collector_provenance(result)
                self.assertEqual(set(result["productionSHA256"]),
                                 {"Package.swift", "Package.resolved", "Sources/Client.swift"})
            self.assertEqual(result["binarySHA256"], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertIsNone(result["artifact"])
            self.assertEqual(json.loads((output / "typed-collector-provenance.json").read_text()), result)
            self.assertEqual(len(runner.call_args_list), 2)
            for call, timeout in zip(runner.call_args_list, (300, 30)):
                self.assertEqual(call.kwargs["timeout"], timeout)
                self.assertEqual(call.kwargs["cwd"], root)
                self.assertIn("--disable-automatic-resolution", call.args[0])
            self.assertEqual(runner.call_args_list[0].args[0][-2:], ["--product", "bgpls"])
            self.assertEqual(runner.call_args_list[1].args[0][-1], "--show-bin-path")

    def test_wrong_binary_failed_build_and_timeout_never_publish_provenance(self):
        for mode in ("binary", "failed", "timeout"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root, binary, built, output = source_fixture(directory)
                runner = build_runner(built)
                if mode == "binary":
                    binary.write_bytes(b"different executable")
                elif mode == "failed":
                    runner.side_effect = lambda command, **kwargs: subprocess.CompletedProcess(command, 1)
                else:
                    runner.side_effect = subprocess.TimeoutExpired("mock swift", 300)
                with mock.patch.object(VALIDATE, "ROOT", root), self.assertRaises(
                        (AssertionError, subprocess.TimeoutExpired)):
                    VALIDATE.collector_provenance(binary, None, output, runner=runner)
                self.assertFalse((output / "typed-collector-provenance.json").exists())
                self.assertTrue((output / "native-collector-build.log").exists())

    def test_source_edit_during_build_fails_even_when_binary_hash_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root, binary, built, output = source_fixture(directory)
            def runner(command, **kwargs):
                (root / "Sources/Client.swift").write_text("changed during build")
                return subprocess.CompletedProcess(command, 0, stdout=str(built) + "\n")
            with mock.patch.object(VALIDATE, "ROOT", root), self.assertRaisesRegex(AssertionError, "sources changed"):
                VALIDATE.collector_provenance(binary, None, output, runner=runner)
            self.assertFalse((output / "typed-collector-provenance.json").exists())

    def test_final_gate_rejects_binary_source_and_lockfile_drift_but_not_test_only_edits(self):
        for changed in ("selected-bgpls", "Sources/Client.swift", "Package.resolved", "Tests/ClientTests.swift"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root, binary, built, output = source_fixture(directory)
                with mock.patch.object(VALIDATE, "ROOT", root):
                    result = VALIDATE.collector_provenance(binary, None, output, runner=build_runner(built))
                    (root / changed).write_text("modified after collection")
                    if changed.startswith("Tests/"):
                        VALIDATE.verify_collector_provenance(result)
                    else:
                        with self.assertRaisesRegex(AssertionError, "changed during qualification"):
                            VALIDATE.verify_collector_provenance(result)


class ArtifactProvenanceTests(unittest.TestCase):
    def artifact(self, root, binary, *, mode=None):
        archive_path = root / "source.tar"
        names = ["Package.swift", "Package.resolved", "Sources/Client.swift"]
        if mode == "missing":
            names.remove("Sources/Client.swift")
        with tarfile.open(archive_path, "w") as archive:
            for name in names:
                payload = b"stale production" if mode == "stale" and name.startswith("Sources/") else (root / name).read_bytes()
                item = tarfile.TarInfo(name)
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            if mode in ("extra", "duplicate"):
                item = tarfile.TarInfo("Sources/Extra.swift" if mode == "extra" else "Sources/Client.swift")
                item.size = 1
                archive.addfile(item, io.BytesIO(b"x"))
        manifest = root / "artifact.json"
        manifest.write_text("hash-bound manifest fixture")
        data = {"source": {"archive": {"path": str(archive_path)}}, "binary": {"path": str(binary)}}
        loader = SimpleNamespace(load_artifact=mock.Mock(return_value=data))
        return manifest, loader

    def test_current_archived_production_is_accepted_without_native_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root, binary, _, output = source_fixture(directory)
            manifest, loader = self.artifact(root, binary)
            runner = mock.Mock(side_effect=AssertionError("unexpected subprocess"))
            with mock.patch.object(VALIDATE, "ROOT", root), mock.patch.object(VALIDATE, "load", return_value=loader):
                result = VALIDATE.collector_provenance(None, manifest, output, runner=runner)
                VALIDATE.verify_collector_provenance(result)
            runner.assert_not_called()
            self.assertEqual(result["artifactSHA256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
            self.assertEqual(loader.load_artifact.call_count, 3)

    def test_missing_extra_stale_or_duplicate_archive_sources_fail_closed(self):
        for mode in ("missing", "extra", "stale", "duplicate"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root, binary, _, output = source_fixture(directory)
                manifest, loader = self.artifact(root, binary, mode=mode)
                with mock.patch.object(VALIDATE, "ROOT", root), mock.patch.object(VALIDATE, "load", return_value=loader):
                    with self.assertRaises((AssertionError, ValueError)):
                        VALIDATE.collector_provenance(None, manifest, output,
                                                      runner=mock.Mock(side_effect=AssertionError("unexpected build")))
                self.assertFalse((output / "typed-collector-provenance.json").exists())

    def test_final_gate_rejects_changed_manifest_and_revalidates_archive_integrity(self):
        for mode in ("manifest", "archive"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root, binary, _, output = source_fixture(directory)
                manifest, loader = self.artifact(root, binary)
                with mock.patch.object(VALIDATE, "ROOT", root), mock.patch.object(VALIDATE, "load", return_value=loader):
                    result = VALIDATE.collector_provenance(None, manifest, output)
                    if mode == "manifest":
                        manifest.write_text("changed manifest")
                    else:
                        loader.load_artifact.side_effect = ValueError("collector artifact hash changed: archive")
                    with self.assertRaisesRegex((AssertionError, ValueError), "changed"):
                        VALIDATE.verify_collector_provenance(result)


class ReplayInputBindingTests(unittest.TestCase):
    def test_input_requires_versioned_explicit_diagnostic_lists_before_running_swift(self):
        for mode in ("legacy", "missing", "null", "object"):
            wire = {"schema": 2, "updates": [{"bodyHex": "00000000", "events": [], "attributeDiagnostics": []}],
                    "finalRecords": []}
            if mode == "legacy":
                wire["schema"] = 1
            elif mode == "missing":
                del wire["updates"][0]["attributeDiagnostics"]
            else:
                wire["updates"][0]["attributeDiagnostics"] = None if mode == "null" else {}
            runner = mock.Mock(side_effect=AssertionError("must reject before Swift"))
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as output:
                with self.assertRaisesRegex(ValueError, "per-UPDATE attribute diagnostics"):
                    VALIDATE.replay_swift(wire, output, runner=runner)
                runner.assert_not_called()
                self.assertEqual(list(Path(output).iterdir()), [])

    def test_output_diagnostic_omissions_and_mismatches_cannot_pass(self):
        issue = {"disposition": "attributeDiscarded", "category": "malformedFraming", "attributeIndex": 1,
                 "tlvIndex": 0, "tlvType": None, "byteOffset": 0, "originalHex": "04"}
        duplicate = {"disposition": "acceptedWithWarning", "category": "duplicateAttribute", "attributeIndex": 2,
                     "tlvIndex": None, "tlvType": None, "byteOffset": None, "originalHex": ""}
        # The wrapper compares diagnostics even when there are no upsert records
        # to carry observation metadata. Swift/wire tests supply real withdrawal/EOR bodies.
        for mode in ("legacy", "unchecked", "missing", "null", "dropped", "extra", "reordered",
                     "disposition", "category", "attributeIndex", "tlvIndex", "tlvType", "byteOffset", "originalHex"):
            wire = {"schema": 2, "updates": [{"bodyHex": "00000000", "events": [],
                                             "attributeDiagnostics": [issue, duplicate]}], "finalRecords": []}
            def runner(command, **kwargs):
                actual = swift_result(wire)
                diagnostics = actual["updates"][0]["attributeDiagnostics"]
                if mode == "legacy":
                    actual["schema"] = 1
                elif mode == "unchecked":
                    del actual["checks"]["updateAttributeDiagnostics"]
                elif mode == "missing":
                    del actual["updates"][0]["attributeDiagnostics"]
                elif mode == "null":
                    actual["updates"][0]["attributeDiagnostics"] = None
                elif mode == "dropped":
                    diagnostics.clear()
                elif mode == "extra":
                    diagnostics.append(copy.deepcopy(issue))
                elif mode == "reordered":
                    diagnostics.reverse()
                else:
                    diagnostics[0][mode] = "different" if mode in ("category", "disposition", "originalHex") else 99
                Path(kwargs["env"]["BGPLS_ATTRIBUTE_REPLAY_OUTPUT"]).write_text(json.dumps(actual))
                return subprocess.CompletedProcess(command, 0)
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as output:
                with self.assertRaises(AssertionError):
                    VALIDATE.replay_swift(wire, output, runner=runner)

    def test_missing_output_empty_list_is_not_equivalent_to_verified_empty_diagnostics(self):
        wire = {"schema": 2, "updates": [{"bodyHex": "00000000", "events": [], "attributeDiagnostics": []}],
                "finalRecords": []}
        def runner(command, **kwargs):
            actual = swift_result(wire)
            del actual["updates"][0]["attributeDiagnostics"]
            Path(kwargs["env"]["BGPLS_ATTRIBUTE_REPLAY_OUTPUT"]).write_text(json.dumps(actual))
            return subprocess.CompletedProcess(command, 0)
        with tempfile.TemporaryDirectory() as output, self.assertRaisesRegex(AssertionError, "incomplete"):
            VALIDATE.replay_swift(wire, output, runner=runner)

    def test_modified_input_manifest_is_rejected_despite_matching_result(self):
        wire = {"schema": 2, "updates": [{"bodyHex": "00000000", "events": [], "attributeDiagnostics": []}],
                "finalRecords": []}
        def runner(command, **kwargs):
            manifest = Path(kwargs["env"]["BGPLS_ATTRIBUTE_REPLAY_INPUT"])
            manifest.write_text(manifest.read_text() + "\n")
            Path(kwargs["env"]["BGPLS_ATTRIBUTE_REPLAY_OUTPUT"]).write_text(json.dumps(swift_result(wire)))
            return subprocess.CompletedProcess(command, 0)
        with tempfile.TemporaryDirectory() as output, self.assertRaisesRegex(AssertionError, "input changed"):
            VALIDATE.replay_swift(wire, output, runner=runner)

    def test_equal_events_from_different_update_bytes_are_rejected(self):
        wire = {"schema": 2, "updates": [{"bodyHex": "00000000", "events": [], "attributeDiagnostics": []}],
                "finalRecords": []}
        def runner(command, **kwargs):
            actual = swift_result(wire)
            actual["updates"][0]["bodyHex"] = "00010000"
            Path(kwargs["env"]["BGPLS_ATTRIBUTE_REPLAY_OUTPUT"]).write_text(json.dumps(actual))
            return subprocess.CompletedProcess(command, 0)
        with tempfile.TemporaryDirectory() as output, self.assertRaisesRegex(AssertionError, "independent wire"):
            VALIDATE.replay_swift(wire, output, runner=runner)


class PublicationBoundaryTests(unittest.TestCase):
    def test_completed_attribute_audit_cannot_publish_pass_before_failed_cleanup(self):
        event = {"operation": "upsert", "key": "test-key", "display": "node 0000.0000.0001",
                 "availability": "present", "attributes": {"name": "rr1"}, "evidence": [], "issues": []}
        wire = {"schema": 2, "updates": [{"bodyHex": "00000000", "events": [event], "attributeDiagnostics": []}],
                "finalRecords": [event], "coverage": {"upserts": 1}}
        projected = VALIDATE.projected(event)
        native = {event["display"]: projected}
        checks = SimpleNamespace(expected_records=lambda profile: native,
                                 watch_records=lambda text: native, final_records=lambda text: native,
                                 watch_events=lambda text: [{"operation": "upsert", **projected}])
        def helper(name):
            return checks if name == "attribute-checks" else SimpleNamespace(audit_capture=lambda path: wire)
        def runner(command, **kwargs):
            Path(kwargs["env"]["BGPLS_ATTRIBUTE_REPLAY_OUTPUT"]).write_text(json.dumps(swift_result(wire)))
            return subprocess.CompletedProcess(command, 0)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            capture = output / "capture.pcap"
            capture.write_bytes(b"mocked capture input")
            lab = VERIFY.Lab(output, output)
            failed_cleanup = mock.Mock(side_effect=RuntimeError("collector removal failed"))
            with mock.patch.object(VALIDATE, "load", side_effect=helper), self.assertRaisesRegex(
                    RuntimeError, "collector removal failed"):
                with VERIFY.verification_cleanup(lab, "ipv6", failed_cleanup):
                    candidate = VALIDATE.audit(capture, "bgpls: RIB final\nnodes=1 links=0 prefixes=0\n",
                                               native, output / "attributes", runner=runner)
                    self.assertTrue(candidate["audited"])
                    self.assertNotIn("passed", candidate)
                self.fail("cleanup failure must prevent result publication")
            self.assertFalse((output / "result.json").exists())
            self.assertFalse((output / "attributes/result.json").exists())
            self.assertTrue((output / "attributes/audit-candidate.json").is_file())
            self.assertEqual(json.loads((output / "failure.json").read_text())["error"], "collector removal failed")

    def test_provenance_failure_precedes_runtime_preflight_for_both_verifiers(self):
        for module, base, lab_name in ((VERIFY, VERIFY, "Lab"), (CEOS, CEOS.BASE, "CeosLab")):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory:
                helper = mock.Mock()
                helper.collector_provenance.side_effect = AssertionError("stale collector")
                args = argparse.Namespace(attributes=True)
                with mock.patch.object(base, "helper", return_value=helper), \
                        mock.patch.object(module, lab_name) as lab, contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(AssertionError, "stale collector"):
                        module.run_locked(args, Path(directory), "ipv4", Path("/unused/bgpls"), None)
                    lab.assert_not_called()
                helper.collector_provenance.assert_called_once()


if __name__ == "__main__":
    unittest.main()
