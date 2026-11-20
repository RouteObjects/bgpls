#!/usr/bin/env python3
"""Offline state integrity, lifecycle locking and mocked Docker namespace tests."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


EXAMPLE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lab_state", EXAMPLE / "lab-state.py")
lab_state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab_state)


class LabStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="bgpls-state-test-")
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name).resolve()
        (self.state / "bgpls.clab.yml").write_text("name: bgpls\n")
        (self.state / "configs").mkdir()
        (self.state / "configs" / "relay.conf").write_text("relay config\n")

    def record(self, profile="frr", transport="ipv6", asn=65001):
        return lab_state.write_state(self.state, profile, transport, "mock-daemon", asn)

    def legacy(self, profile):
        lines = ["bgpls-frr-lab-v1" if profile == "frr" else "bgpls-lab-v2", str(self.state),
                 "mock-daemon", hashlib.sha256((self.state / "bgpls.clab.yml").read_bytes()).hexdigest()]
        if profile == "ceos":
            lines.append(profile)
        (self.state / lab_state.MARKER).write_text("\n".join(lines) + "\n")

    def test_both_legacy_formats_preserve_ipv4(self):
        for profile in ("frr", "ceos"):
            with self.subTest(profile=profile):
                self.legacy(profile)
                value = lab_state.read_state(self.state)
                self.assertEqual((value["state"], value["profile"], value["transport"], value["daemon_id"]),
                                 (self.state, profile, "ipv4", "mock-daemon"))
                self.assertEqual(value["asn"], 65001)
                with (self.state / lab_state.MARKER).open("a") as output:
                    output.write("extra")
                with self.assertRaises(ValueError):
                    lab_state.read_state(self.state)

    def test_v3_records_retain_implicit_asn_without_rewriting(self):
        marker = self.state / lab_state.MARKER
        for profile in ("frr", "ceos"):
            for transport in ("ipv4", "ipv6"):
                with self.subTest(profile=profile, transport=transport):
                    record = dict(state=str(self.state), profile=profile, transport=transport,
                                  daemon_id="mock-daemon", configs=lab_state.config_hashes(self.state),
                                  topology_sha256=lab_state._hash(self.state / "bgpls.clab.yml"))
                    original = ("bgpls-lab-v3\n" + json.dumps(record) + "\n").encode()
                    marker.write_bytes(original)
                    value = lab_state.read_state(self.state)
                    self.assertEqual((value["profile"], value["transport"], value["asn"]),
                                     (profile, transport, 65001))
                    self.assertEqual(marker.read_bytes(), original)
                    (self.state / "configs" / "relay.conf").write_text("drift\n")
                    with self.assertRaisesRegex(ValueError, "inventory"):
                        lab_state.read_state(self.state)
                    (self.state / "configs" / "relay.conf").write_text("relay config\n")
        record["asn"] = 65001
        marker.write_text("bgpls-lab-v3\n" + json.dumps(record) + "\n")
        with self.assertRaisesRegex(ValueError, "Unexpected v3"):
            lab_state.read_state(self.state)

    def test_v4_exact_inventory_both_profiles(self):
        for profile in ("frr", "ceos"):
            with self.subTest(profile=profile):
                self.record(profile, asn=4200000001)
                value = lab_state.read_state(self.state)
                self.assertEqual((value["profile"], value["asn"]), (profile, 4200000001))
                marker = (self.state / lab_state.MARKER).read_text().splitlines()
                self.assertEqual(marker[0], "bgpls-lab-v4")
                self.assertEqual(set(json.loads(marker[1])),
                                 {"state", "profile", "transport", "daemon_id", "configs", "topology_sha256", "asn"})
                with self.assertRaises(FileExistsError):
                    self.record(profile)
                (self.state / lab_state.MARKER).unlink()

    def test_changed_missing_and_added_config_are_rejected(self):
        self.record()
        config = self.state / "configs" / "relay.conf"
        config.write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "inventory"):
            lab_state.read_state(self.state)
        config.unlink()
        with self.assertRaises(ValueError):
            lab_state.read_state(self.state)
        config.write_text("relay config\n")
        (self.state / "configs" / "unknown").write_text("extra")
        with self.assertRaisesRegex(ValueError, "inventory"):
            lab_state.read_state(self.state)

    def test_topology_and_symlink_drift_are_rejected(self):
        self.record()
        topology = self.state / "bgpls.clab.yml"
        topology.write_text("name: foreign\n")
        with self.assertRaisesRegex(ValueError, "topology changed"):
            lab_state.read_state(self.state)
        topology.write_text("name: bgpls\n")
        (self.state / "configs" / "link").symlink_to(topology)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            lab_state.read_state(self.state)

    def test_invalid_schema_fields_and_duplicate_keys_fail(self):
        self.record()
        marker = self.state / lab_state.MARKER
        original = marker.read_text()
        record = json.loads(original.splitlines()[1])
        changes = [{**record, "profile": "unknown"}, {**record, "transport": "auto"},
                   {**record, "unknown": True}, {**record, "state": "/foreign"},
                   {**record, "daemon_id": "bad\nidentity"},
                   {**record, "configs": {"../elsewhere": "0" * 64}}]
        for value in changes:
            marker.write_text("bgpls-lab-v4\n" + json.dumps(value) + "\n")
            with self.assertRaises(ValueError):
                lab_state.read_state(self.state)
        marker.write_text(original.replace('"profile":"frr"', '"profile":"frr","profile":"ceos"'))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            lab_state.read_state(self.state)
        marker.write_text(original + "\n")
        with self.assertRaises(ValueError):
            lab_state.read_state(self.state)

    def test_v4_asn_range_type_and_required_key_validation(self):
        self.record()
        marker = self.state / lab_state.MARKER
        record = json.loads(marker.read_text().splitlines()[1])
        for value in (0, 23456, -1, 4294967296, True, False, "65001", 65001.0, None, [], {}):
            with self.subTest(value=value):
                marker.write_text("bgpls-lab-v4\n" + json.dumps({**record, "asn": value}) + "\n")
                with self.assertRaisesRegex(ValueError, "ASN"):
                    lab_state.read_state(self.state)
        marker.write_text("bgpls-lab-v4\n" + json.dumps({key: value for key, value in record.items() if key != "asn"}) + "\n")
        with self.assertRaisesRegex(ValueError, "Unexpected v4"):
            lab_state.read_state(self.state)

    def test_v4_writer_rejects_invalid_asn_before_creating_marker(self):
        for value in (0, 23456, -1, 4294967296, True, "65001"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.record(asn=value)
            self.assertFalse((self.state / lab_state.MARKER).exists())

    def test_strict_asplain_parser_and_integer_validation(self):
        for text, expected in (("1", 1), ("65001", 65001), ("00065001", 65001), ("65536", 65536),
                               ("4200000001", 4200000001), ("4294967295", 4294967295)):
            with self.subTest(text=text):
                self.assertEqual(lab_state.parse_asn(text), expected)
                self.assertEqual(lab_state.validate_asn(expected), expected)
        for text in ("", "0", "000", "23456", "00023456", "4294967296", "9" * 5000, "+65001", "-1",
                     " 65001", "65001 ", "65001\n", "AS65001", "1.10", "６５００１", "12_34"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                lab_state.parse_asn(text)

    def test_read_cli_includes_asn_and_asn_parser_needs_no_state(self):
        self.record(asn=4294967295)
        result = subprocess.run([sys.executable, str(EXAMPLE / "lab-state.py"), "read", "--state", str(self.state)],
                                text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout.splitlines(), ["frr", "ipv6", "mock-daemon", "4294967295"])
        result = subprocess.run([sys.executable, str(EXAMPLE / "lab-state.py"), "asn", "--asn", "0004200000001"],
                                text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, "4200000001\n")

    def test_lock_excludes_second_owner_and_releases_on_error(self):
        self.record()
        with self.assertRaisesRegex(RuntimeError, "operation failure"):
            with lab_state.verification_lock(self.state) as token:
                lab_state.assert_lock(self.state, token)
                with self.assertRaisesRegex(RuntimeError, "lock exists"):
                    with lab_state.verification_lock(self.state):
                        self.fail("Second owner acquired the lock")
                raise RuntimeError("operation failure")
        self.assertFalse((self.state / lab_state.LOCK).exists())

    def test_stale_lock_never_automatically_broken(self):
        self.record()
        lock = self.state / lab_state.LOCK
        lock.mkdir()
        (lock / "owner.json").write_text('{"pid":0,"token":"stale"}')
        with self.assertRaisesRegex(RuntimeError, "lock exists"):
            with lab_state.verification_lock(self.state):
                self.fail("Stale owner was ignored")
        self.assertTrue(lock.is_dir())

    def test_replaced_lock_is_retained(self):
        self.record()
        with self.assertRaisesRegex(ValueError, "another operation"):
            with lab_state.verification_lock(self.state):
                (self.state / lab_state.LOCK / "owner.json").write_text('{"pid":1,"token":"replacement"}')
        self.assertTrue((self.state / lab_state.LOCK).is_dir())

    def test_command_wrapper_returns_child_status_and_releases_lock(self):
        self.record()
        result = subprocess.run(["python3", str(EXAMPLE / "lab-state.py"), "locked", "--state", str(self.state),
                                 "--", "sh", "-c", 'test -n "$BGPLS_LOCK_TOKEN"; exit 17'], capture_output=True)
        self.assertEqual(result.returncode, 17)
        self.assertFalse((self.state / lab_state.LOCK).exists())

    def test_interrupted_wrapper_retains_lock_with_lingering_descendant(self):
        self.record()
        ready = self.state / "child-ready.json"
        child = '''import json, os, signal, subprocess, sys
descendant = subprocess.Popen([sys.executable, "-c", "import signal; signal.pause()"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open(sys.argv[1] + ".pending", "w") as output:
    json.dump({"child": os.getpid(), "descendant": descendant.pid}, output)
os.replace(sys.argv[1] + ".pending", sys.argv[1])
signal.pause()
'''
        process = subprocess.Popen([sys.executable, str(EXAMPLE / "lab-state.py"), "locked", "--state", str(self.state),
                                    "--", sys.executable, "-c", child, str(ready)],
                                   start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    self.fail("Mock child did not report readiness")
                time.sleep(0.01)
            identity = json.loads(ready.read_text())
            process.send_signal(signal.SIGTERM)
            _, errors = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 143)
            self.assertIn("lock retained", errors)
            os.kill(identity["descendant"], 0)
            self.assertTrue((self.state / lab_state.LOCK / "owner.json").is_file())
            with self.assertRaisesRegex(RuntimeError, "lock exists"):
                with lab_state.verification_lock(self.state):
                    self.fail("Interrupted operation's lock was broken")
        finally:
            # The isolated test session owns the entire fake process tree.
            # Kill its lingering child and reap the directly owned wrapper;
            # the orphaned grandchild is reaped by the platform's init process.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=5)

    def test_guard_cli_bounds_every_runtime_call(self):
        self.record()
        with patch.object(sys, "argv", ["lab-state.py", "guard", "--state", str(self.state), "--", "mock-docker"]), \
                patch.object(lab_state.subprocess, "check_output", return_value="") as command:
            self.assertEqual(lab_state.main(), 0)
        command.assert_called_once_with(["mock-docker", "ps", "-aq", "--no-trunc"], text=True, timeout=20)
        with patch.object(sys, "argv", ["lab-state.py", "guard", "--state", str(self.state), "--", "mock-docker"]), \
                patch.object(lab_state.subprocess, "check_output", side_effect=subprocess.TimeoutExpired("mock-docker", 20)):
            with self.assertRaises(subprocess.TimeoutExpired):
                lab_state.main()

    def container(self, number, name, mode="bridge", running=True):
        return dict(Id=f"{number:064x}", Name="/" + name, State={"Running": running},
                    HostConfig={"NetworkMode": mode}, NetworkSettings={"SandboxKey": ""},
                    Config={"Labels": {"containerlab": "bgpls", "clab-topo-file": str(self.state / "bgpls.clab.yml")}})

    def guard(self, containers, allowed=frozenset()):
        calls = []

        def docker(args):
            calls.append(args)
            if args == ["ps", "-aq", "--no-trunc"]:
                return "\n".join(container["Id"] for container in containers)
            if args == ["inspect", *[container["Id"] for container in containers]]:
                return json.dumps(containers)
            self.fail(f"Unexpected Docker call: {args}")
        lab_state.assert_no_namespace_holders(self.state, docker, allowed)
        return calls

    def test_no_holder_no_relay_and_stopped_holder_are_safe(self):
        self.record()
        relay = self.container(1, "clab-bgpls-bgpls-relay")
        self.guard([])
        self.guard([relay, self.container(2, "unrelated")])
        self.guard([relay, self.container(2, "stopped", "container:" + relay["Id"], False)])

    def test_name_full_short_id_and_indirect_holders_are_rejected(self):
        self.record()
        relay = self.container(0x100, "clab-bgpls-bgpls-relay")
        # Different leading digits make short-ID references unambiguous.
        relay["Id"] = "a" * 64
        for reference in (relay["Id"], relay["Id"][:12], "clab-bgpls-bgpls-relay"):
            with self.subTest(reference=reference), self.assertRaisesRegex(RuntimeError, "held by"):
                self.guard([relay, self.container(2, "manual-collector", "container:" + reference)])
        middle = self.container(3, "middle", "container:" + relay["Id"], False)
        leaf = self.container(4, "leaf", "container:middle")
        with self.assertRaisesRegex(RuntimeError, "leaf"):
            self.guard([relay, middle, leaf])

    def test_only_exact_owned_ids_can_be_allowed(self):
        self.record()
        relay = self.container(1, "clab-bgpls-bgpls-relay")
        collector = self.container(2, "owned", "container:" + relay["Id"])
        self.guard([relay, collector], {collector["Id"]})
        with self.assertRaises(ValueError):
            self.guard([relay, collector], {"owned"})
        external = self.container(3, "external", "container:owned")
        with self.assertRaisesRegex(RuntimeError, "external"):
            self.guard([relay, collector, external], {collector["Id"]})

    def test_unresolved_cycles_and_foreign_relay_fail_closed(self):
        self.record()
        relay = self.container(1, "clab-bgpls-bgpls-relay")
        with self.assertRaisesRegex(ValueError, "resolve"):
            self.guard([relay, self.container(2, "unknown", "container:missing")])
        with self.assertRaisesRegex(ValueError, "Cyclic"):
            self.guard([relay, self.container(2, "cycle", "container:cycle")])
        relay["Config"]["Labels"] = {"containerlab": "foreign"}
        with self.assertRaisesRegex(ValueError, "another deployment"):
            self.guard([relay])


if __name__ == "__main__":
    unittest.main()
