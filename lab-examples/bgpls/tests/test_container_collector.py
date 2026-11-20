#!/usr/bin/env python3
"""Offline container ownership/lifecycle tests: no Docker or OrbStack execution."""

import copy
import importlib.util
import json
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("bgpls_container_test", Path(__file__).resolve().parents[1] / "container-collector.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
IMAGE_ID = "sha256:" + "a" * 64
CONTAINER_ID = "b" * 64
RELAY_ID = "c" * 64


def artifact(root):
    directory = root / "artifact"
    directory.mkdir()
    binary = directory / "bgpls"
    header = bytearray(20)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 18, 183)
    binary.write_bytes(header)
    binary.chmod(0o755)
    source = {"revision": "d" * 40}
    for key in ("archive", "package", "resolved"):
        path = directory / key
        path.write_text(key)
        source[key] = {"path": str(path), "sha256": MODULE.digest(path)}
    data = {"version": 1, "source": source,
            "image": {"reference": "swift:6.3.3@sha256:" + "e" * 64, "id": IMAGE_ID,
                      "os": "linux", "architecture": "arm64"},
            "binary": {"path": str(binary), "sha256": MODULE.digest(binary)},
            "toolchain": {"version": "Swift version 6.3.3", "target": "aarch64-unknown-linux-gnu"}}
    manifest = directory / "artifact.json"
    manifest.write_text(json.dumps(data))
    return manifest


class FakeLab:
    def __init__(self, root):
        self.state = root / "state"
        self.state.mkdir()
        self.calls = []
        self.daemon = "daemon-one"
        self.image = {"Id": IMAGE_ID, "Architecture": "arm64", "Os": "linux"}
        self.relay = {"Id": RELAY_ID, "RestartCount": 0,
                      "State": {"Running": True, "StartedAt": "2026-10-19T12:00:00.123456789Z"},
                      "Config": {"Labels": {"containerlab": "bgpls", "clab-topo-file": str(self.state / "bgpls.clab.yml")}}}
        self.container = None
        self.logs = ""
        self.fail_create = False
        self.fail_start = False
        self.ignore_signals = False
        self.process = None

    def docker(self, *args, timeout=20, combine_output=False):
        self.calls.append((args, timeout, combine_output))
        assert timeout > 0
        if args[0] == "info":
            return json.dumps({"ID": self.daemon, "OSType": "linux", "Architecture": "aarch64"})
        if args[:2] == ("image", "inspect"):
            return json.dumps([self.image])
        if args[0] == "inspect":
            return json.dumps([self.relay if args[1] in (RELAY_ID, "clab-bgpls-bgpls-relay") else self.container])
        if args[0] == "create":
            process = self.process
            self.container = {"Id": CONTAINER_ID, "Image": IMAGE_ID,
                              "Config": {"Labels": copy.deepcopy(process.labels), "Entrypoint": [process.args[0]], "Cmd": process.args[1:]},
                              "HostConfig": {"NetworkMode": f"container:{RELAY_ID}", "Privileged": False,
                                             "ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": None,
                                             "Init": True, "SecurityOpt": ["no-new-privileges"],
                                             "RestartPolicy": {"Name": "no"}, "PortBindings": {}},
                              "Mounts": [{"Source": a, "Destination": b, "RW": c, "Type": "bind"} for a, b, c in process.mounts],
                              "State": {"Running": False, "Status": "created", "ExitCode": 0, "OOMKilled": False}}
            if self.fail_create:
                raise subprocess.TimeoutExpired(args, timeout)
            return CONTAINER_ID + "\n"
        if args[0] == "start":
            self.container["State"].update(Running=True, Status="running")
            self.logs = "bgpls: WATCH snapshot nodes=0 links=0 prefixes=0\n"
            if self.fail_start:
                raise subprocess.TimeoutExpired(args, timeout)
            return CONTAINER_ID
        if args[0] == "logs":
            assert combine_output
            return self.logs
        if args[0] == "kill":
            if not self.ignore_signals:
                code = {"INT": 130, "TERM": 143, "KILL": 137}[args[2]]
                self.container["State"].update(Running=False, Status="exited", ExitCode=code)
                self.logs += f"bgpls: SIG{args[2]} — stopping session…\nbgpls: RIB final\n"
            return CONTAINER_ID
        if args[0] == "rm":
            self.container = None
            return CONTAINER_ID
        if args[0] == "ps":
            return CONTAINER_ID if self.container else ""
        raise AssertionError(f"unqualified Docker command: {args!r}")


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bgpls-container-test-")
        self.root = Path(self.temp.name).resolve()
        self.manifest = artifact(self.root)
        self.lab = FakeLab(self.root)
        self.output = self.root / "evidence"
        self.output.mkdir()
        self.now = 0
        self.state = {"profile": "ceos", "transport": "ipv6", "daemon_id": self.lab.daemon, "asn": 65001}
        self.state_patch = mock.patch.object(MODULE, "read_state", return_value=self.state)
        self.state_patch.start()
        self.process = MODULE.ContainerProcess(self.lab, "frr", self.manifest, self.output,
                                               self.output / "collector.log", self.output / "collector.pcap",
                                               clock=lambda: self.now, sleep=self.sleep)
        self.lab.process = self.process

    def tearDown(self):
        self.state_patch.stop()
        self.temp.cleanup()

    def sleep(self, seconds):
        self.now += seconds

    def test_artifact_rejects_modified_binary_before_runtime(self):
        Path(json.loads(self.manifest.read_text())["binary"]["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "hash changed"):
            MODULE.load_artifact(self.manifest)
        self.assertEqual(self.lab.calls, [])

    def test_artifact_rejects_wrong_architecture_and_unpinned_image(self):
        original = json.loads(self.manifest.read_text())
        for key, value in (("architecture", "amd64"), ("reference", "swift:6.3.3")):
            data = copy.deepcopy(original)
            data["image"][key] = value
            self.manifest.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                MODULE.load_artifact(self.manifest)

    def test_artifact_rejects_symlink_and_escaping_file(self):
        link = self.root / "link.json"
        link.symlink_to(self.manifest)
        with self.assertRaisesRegex(ValueError, "symlink"):
            MODULE.load_artifact(link)
        data = json.loads(self.manifest.read_text())
        outside = self.root / "outside"
        outside.write_text("archive")
        data["source"]["archive"]["path"] = str(outside)
        self.manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "beneath"):
            MODULE.load_artifact(self.manifest)

    def test_start_creates_without_privilege_and_records_before_start(self):
        self.process.start()
        command = next(args for args, _, _ in self.lab.calls if args[0] == "create")
        self.assertIn(f"container:{RELAY_ID}", command)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("--rm", command)
        self.assertNotIn("--publish", command)
        self.assertEqual(command.count("--dump-rib"), 1)
        self.assertEqual(self.process.args[self.process.args.index("--peer") + 1], "2001:db8:6501:ff01::")
        self.assertEqual(self.process.args[self.process.args.index("--bgp-identifier") + 1], "192.0.2.101")
        self.assertEqual(self.process.metadata["container_id"], CONTAINER_ID)
        self.assertEqual(self.process.poll(), None)

    def test_sigint_and_sigterm_use_container_status_not_cli_status(self):
        self.process.start()
        self.process.send_signal(signal.SIGINT)
        self.assertEqual(self.process.wait(1), 130)
        self.assertIn("RIB final", self.process.log_path.read_text())
        self.process.cleanup()
        self.assertTrue(self.process.removed)
        self.process.cleanup()
        self.assertEqual(sum(args[0] == "rm" for args, _, _ in self.lab.calls), 1)

    def test_terminate_returns_143(self):
        self.process.start()
        self.process.terminate()
        self.assertEqual(self.process.wait(1), 143)

    def test_ceos_has_independent_ipv6_endpoints_and_identifier(self):
        process = MODULE.ContainerProcess(self.lab, "ceos", self.manifest, self.output,
                                          self.output / "ceos.log", self.output / "ceos.pcap")
        self.assertEqual(process.args[process.args.index("--peer") + 1], "2001:db8:6501:ff02::")
        self.assertEqual(process.args[process.args.index("--local-address") + 1], "2001:db8:6501:ff02::1")
        self.assertEqual(process.args[process.args.index("--bgp-identifier") + 1], "192.0.2.102")
        self.assertNotEqual(process.run_id, self.process.run_id)

    def test_both_producers_use_only_deployment_asn_in_arguments_and_metadata(self):
        for asn in (65001, 4200000001):
            for producer in ("frr", "ceos"):
                with self.subTest(asn=asn, producer=producer):
                    self.state["asn"] = asn
                    process = MODULE.ContainerProcess(
                        self.lab, producer, self.manifest, self.output,
                        self.output / f"{producer}-{asn}.log", self.output / f"{producer}-{asn}.pcap")
                    for option in ("--local-as", "--peer-as"):
                        self.assertEqual(process.args[process.args.index(option) + 1], str(asn))
                    self.assertEqual(process.metadata["asn"], asn)
        self.assertEqual(self.lab.calls, [])

    def test_changed_deployment_asn_refuses_before_runtime_operations(self):
        self.state["asn"] = 4200000001
        with self.assertRaisesRegex(AssertionError, "ASN changed"):
            self.process.start()
        self.assertEqual(self.lab.calls, [])

    def test_full_dump_flag_is_required_once_for_every_container_qualification(self):
        for profile, producers in (("frr", ("frr",)), ("ceos", ("frr", "ceos"))):
            for producer in producers:
                for attributes in (False, True):
                    with self.subTest(profile=profile, producer=producer, attributes=attributes):
                        self.state["profile"] = profile
                        process = MODULE.ContainerProcess(
                            self.lab, producer, self.manifest, self.output,
                            self.output / "qualification.log", self.output / "qualification.pcap",
                            show_attributes=attributes)
                        self.assertEqual(process.args.count("--dump-rib"), 1)
                        self.assertEqual(process.args.count("--show-attributes"), int(attributes))
                        self.assertEqual(process.metadata["args"], process.args)
        self.assertEqual(self.lab.calls, [])

    def test_pcaps_and_logs_are_hashed_after_exit(self):
        self.process.start()
        self.process.pcap_path.write_bytes(b"complete capture")
        self.process.terminate()
        self.process.wait(1)
        self.assertEqual(self.process.metadata["pcap_sha256"], MODULE.digest(self.process.pcap_path))
        self.assertEqual(self.process.metadata["log_sha256"], MODULE.digest(self.process.log_path))

    def test_wait_is_bounded_and_rejects_nonfinite_timeouts(self):
        self.process.start()
        with self.assertRaises(subprocess.TimeoutExpired):
            self.process.wait(0.2)
        self.assertLessEqual(self.now, 0.21)
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                self.process.wait(timeout)

    def test_partial_create_is_recovered_by_unique_label_and_removed(self):
        self.lab.fail_create = True
        with self.assertRaises(subprocess.TimeoutExpired):
            self.process.start()
        self.assertIsNone(self.lab.container)
        self.assertTrue(self.process.removed)
        self.assertTrue(any(args[0] == "ps" for args, _, _ in self.lab.calls))

    def test_partial_start_stops_owned_process_and_retains_evidence(self):
        self.lab.fail_start = True
        with self.assertRaises(subprocess.TimeoutExpired):
            self.process.start()
        self.assertIsNone(self.lab.container)
        self.assertIn("SIGTERM", self.process.log_path.read_text())

    def test_changed_daemon_blocks_signal_and_remove(self):
        self.process.start()
        self.lab.daemon = "different"
        with self.assertRaisesRegex(AssertionError, "daemon changed"):
            self.process.cleanup()
        self.assertFalse(any(args[0] in ("kill", "rm") for args, _, _ in self.lab.calls))

    def test_changed_relay_boot_blocks_signal(self):
        self.process.start()
        self.lab.relay["RestartCount"] = 1
        with self.assertRaisesRegex(AssertionError, "boot changed"):
            self.process.terminate()

    def test_changed_ownership_or_mounts_blocks_removal(self):
        self.process.start()
        self.lab.container["Config"]["Labels"][MODULE.LABEL] = "unowned"
        with self.assertRaisesRegex(AssertionError, "ownership"):
            self.process.cleanup()
        self.assertFalse(any(args[0] == "rm" for args, _, _ in self.lab.calls))

    def test_extra_volume_or_security_drift_blocks_lifecycle(self):
        self.process.start()
        original = copy.deepcopy(self.lab.container)
        mutations = (
            lambda value: value["Mounts"].append({"Source": "/volume", "Destination": "/extra", "RW": True, "Type": "volume"}),
            lambda value: value["HostConfig"].update(SecurityOpt=[]),
            lambda value: value["HostConfig"].update(CapAdd=["NET_ADMIN"]),
            lambda value: value["HostConfig"].update(Init=False),
            lambda value: value["Config"]["Labels"].update(containerlab="bgpls"),
        )
        for mutation in mutations:
            self.lab.container = copy.deepcopy(original)
            mutation(self.lab.container)
            with self.assertRaisesRegex(AssertionError, "ownership"):
                self.process.terminate()
        self.assertFalse(any(args[0] == "kill" for args, _, _ in self.lab.calls))

    def test_wait_budget_is_shared_by_all_inspection_commands(self):
        self.process.start()
        original = self.lab.docker

        def slow(*args, **kwargs):
            self.now += min(0.08, kwargs.get("timeout", 20))
            return original(*args, **kwargs)

        with mock.patch.object(self.lab, "docker", side_effect=slow):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.process.wait(0.2)
        self.assertLessEqual(self.now, 0.201)

    def test_wrong_image_and_profile_fail_before_create(self):
        self.lab.image["Id"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(AssertionError, "runtime image"):
            self.process.start()
        self.assertFalse(any(args[0] == "create" for args, _, _ in self.lab.calls))

    def test_zero_and_invalid_relay_timestamps_are_rejected(self):
        for started in ("0001-01-01T00:00:00Z", "invalid", "2026-02-30T00:00:00Z"):
            self.lab.relay["State"]["StartedAt"] = started
            with self.assertRaises((AssertionError, ValueError)):
                self.process.start()

    def test_oom_status_is_a_failure(self):
        self.process.start()
        self.lab.container["State"].update(Running=False, Status="exited", ExitCode=137, OOMKilled=True)
        with self.assertRaisesRegex(AssertionError, "OOM"):
            self.process.poll()

    def test_oom_failure_retains_evidence_but_owned_cleanup_still_reaps(self):
        self.process.start()
        self.lab.container["State"].update(Running=False, Status="exited", ExitCode=137, OOMKilled=True)
        with self.assertRaisesRegex(AssertionError, "OOM"):
            self.process.poll()
        self.process.cleanup()
        self.assertTrue(self.process.removed)
        self.assertIsNone(self.lab.container)
        self.assertEqual(self.process.metadata["exit_code"], 137)
        self.assertTrue(self.process.metadata["last_inspect"]["State"]["OOMKilled"])


if __name__ == "__main__":
    unittest.main()
