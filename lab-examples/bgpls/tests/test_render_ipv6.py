#!/usr/bin/env python3
"""Pure rendering and mocked DAD tests; never run Docker or contact a lab."""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


EXAMPLE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("render_ipv6", EXAMPLE / "render-ipv6.py")
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class IPv6RenderTests(unittest.TestCase):
    def copy(self, profile):
        temporary = tempfile.TemporaryDirectory(prefix="bgpls-render-test-")
        self.addCleanup(temporary.cleanup)
        state = Path(temporary.name).resolve()
        shutil.copytree(EXAMPLE / "configs", state / "configs")
        shutil.copyfile(EXAMPLE / ("bgpls-ceos.clab.yml" if profile == "ceos" else "bgpls.clab.yml"), state / "bgpls.clab.yml")
        return state

    def snapshot(self, root):
        return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    def test_shell_copy_workflow_all_profiles_and_transports(self):
        for profile in ("frr", "ceos"):
            for transport in ("ipv4", "ipv6"):
                with self.subTest(profile=profile, transport=transport):
                    temporary = tempfile.TemporaryDirectory(prefix="bgpls-copy-test-")
                    self.addCleanup(temporary.cleanup)
                    state = Path(temporary.name).resolve()
                    script = '''source "$1/deploy.sh"
bgpls_runtime() { echo 'Unexpected runtime call' >&2; return 99; }
bgpls_docker() { echo 'Unexpected Docker call' >&2; return 99; }
bgpls_containerlab() { echo 'Unexpected Containerlab call' >&2; return 99; }
bgpls_set_profile "$2"
BGPLS_TRANSPORT=$3
BGPLS_DAEMON_ID=mock-daemon
bgpls_init_state "$4"
bgpls_copy_deployment
'''
                    result = subprocess.run(["/bin/bash", "-c", script, "offline-copy", str(EXAMPLE), profile, transport, str(state)],
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    marker = (state / ".bgpls-lab-state").read_text().splitlines()
                    self.assertEqual(marker[0], "bgpls-lab-v4")
                    state_result = subprocess.run(["python3", str(EXAMPLE / "lab-state.py"), "read", "--state", str(state)],
                                                  text=True, capture_output=True)
                    self.assertEqual(state_result.returncode, 0, state_result.stderr)
                    self.assertEqual(state_result.stdout.splitlines(), [profile, transport, "mock-daemon", "65001"])
                    if transport == "ipv4":
                        self.assertEqual(self.snapshot(state / "configs"), self.snapshot(EXAMPLE / "configs"))
                        self.assertEqual((state / "bgpls.clab.yml").read_bytes(),
                                         (EXAMPLE / ("bgpls-ceos.clab.yml" if profile == "ceos" else "bgpls.clab.yml")).read_bytes())

    def test_verify_wrapper_preserves_legacy_and_flag_only_arguments(self):
        # An executable shim catches exec python3; shell functions cannot.
        # The real state parser still runs, while all runtime calls are mocks.
        temporary = tempfile.TemporaryDirectory(prefix="bgpls-wrapper-test-")
        self.addCleanup(temporary.cleanup)
        bin_dir = Path(temporary.name).resolve()
        shim = bin_dir / "python3"
        shim.write_text('''#!/bin/sh
case "$1" in
    */verify.py|*/verify-ceos.py) printf '%s\\n' "$@" ;;
    *) exec "$BGPLS_TEST_PYTHON" "$@" ;;
esac
''')
        shim.chmod(0o755)
        setup = '''uname() { printf 'Linux\\n'; }
docker() {
    case "$1" in
        context) printf 'unix:///var/run/docker.sock\\n' ;;
        info) printf 'mock-daemon\\n' ;;
        *) echo 'Unexpected Docker call' >&2; return 99 ;;
    esac
}
containerlab() { [ "$1" = version ] || return 99; printf 'mock version\\n'; }
orb() { echo 'Unexpected OrbStack call' >&2; return 99; }
export -f uname docker containerlab orb
exec /bin/bash "$@"
'''
        for profile in ("frr", "ceos"):
            state = self.copy(profile)
            subprocess.run([sys.executable, str(EXAMPLE / "lab-state.py"), "write", "--state", str(state),
                            "--profile", profile, "--transport", "ipv6", "--daemon-id", "mock-daemon"], check=True)
            for args, expected in ((["/tmp/native-bgpls", "--churn"], ["--binary", "/tmp/native-bgpls", "--churn"]),
                                   (["--transport", "ipv6", "--artifact", "/tmp/artifact.json"],
                                    ["--transport", "ipv6", "--artifact", "/tmp/artifact.json"])):
                with self.subTest(profile=profile, args=args):
                    result = subprocess.run(["/bin/bash", "-c", setup, "offline-wrapper", str(EXAMPLE / "verify.sh"), str(state), *args],
                                            env={**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                                                 "BGPLS_TEST_PYTHON": sys.executable}, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    filename = "verify-ceos.py" if profile == "ceos" else "verify.py"
                    self.assertEqual(result.stdout.splitlines(), [str(EXAMPLE / filename), "--state", str(state), *expected])

    def test_fixed_overlay_changes_only_collector_paths(self):
        source_before = self.snapshot(EXAMPLE / "configs")
        for profile in ("frr", "ceos"):
            with self.subTest(profile=profile):
                state = self.copy(profile)
                before = self.snapshot(state)
                paths = renderer.render(state, profile)
                after = self.snapshot(state)
                expected = {"bgpls.clab.yml", "configs/frr/edge-frr.conf"}
                expected.add("configs/relay/start.sh" if profile == "frr" else "configs/ceos-profile/relay-start.sh")
                if profile == "ceos":
                    expected.add("configs/ceos-profile/edge-ceos.cfg")
                self.assertEqual(set(paths), expected)
                self.assertEqual({path for path in before if before[path] != after[path]}, expected)
                yaml = after["bgpls.clab.yml"].decode()
                original_yaml = before["bgpls.clab.yml"].decode()
                self.assertEqual([line for line in yaml.splitlines() if "endpoints:" in line],
                                 [line for line in original_yaml.splitlines() if "endpoints:" in line])
                self.assertEqual([line for line in yaml.splitlines() if "image:" in line or "/tcp" in line],
                                 [line for line in original_yaml.splitlines() if "image:" in line or "/tcp" in line])
                self.assertEqual(yaml.count("sysctls:"), 1)
                self.assertIn('net.ipv6.conf.all.disable_ipv6: "0"', yaml)
                frr = after["configs/frr/edge-frr.conf"].decode()
                self.assertIn("interface eth3\n ip address 10.254.254.0/31\n ipv6 address 2001:db8:6501:ff01::/127\n!", frr)
                self.assertIn("neighbor 2001:db8:6501:ff01::1 passive", frr)
                self.assertIn(" address-family link-state\n  neighbor 10.254.254.1 activate\n  neighbor 2001:db8:6501:ff01::1 activate", frr)
                self.assertEqual(frr.split("\nrouter isis CORE\n", 1)[1].split("\nrouter bgp", 1)[0],
                                 before["configs/frr/edge-frr.conf"].decode().split("\nrouter isis CORE\n", 1)[1].split("\nrouter bgp", 1)[0])
                if profile == "ceos":
                    eos = after["configs/ceos-profile/edge-ceos.cfg"].decode()
                    self.assertIn("   ipv6 address 2001:db8:6501:ff02::/127\n!", eos)
                    self.assertIn("   neighbor 2001:db8:6501:ff02::1 passive", eos)
                    self.assertIn("      neighbor 2001:db8:6501:ff02::1 activate", eos)
                for relative in paths:
                    if relative.endswith(".sh"):
                        subprocess.run(["sh", "-n", str(state / relative)], check=True)
                        self.assertNotIn("nodad", after[relative].decode())
                # Repeated rendering must fail, not add duplicate neighbors.
                with self.assertRaises(ValueError):
                    renderer.render(state, profile)
                self.assertEqual(after, self.snapshot(state))
        self.assertEqual(source_before, self.snapshot(EXAMPLE / "configs"))

    def test_unexpected_anchor_fails_before_any_write(self):
        state = self.copy("ceos")
        path = state / "configs/ceos-profile/relay-start.sh"
        path.write_text(path.read_text().replace("ip link set eth2 up", "ip link set other up"))
        before = self.snapshot(state)
        with self.assertRaisesRegex(ValueError, "anchor"):
            renderer.render(state, "ceos")
        self.assertEqual(before, self.snapshot(state))

    def test_wrong_profile_recorded_state_and_symlinks_rejected(self):
        state = self.copy("frr")
        with self.assertRaises(ValueError):
            renderer.render(state, "ceos")
        (state / ".bgpls-lab-state").write_text("existing")
        with self.assertRaisesRegex(ValueError, "recorded"):
            renderer.render(state, "frr")
        (state / ".bgpls-lab-state").unlink()
        path = state / "configs/frr/edge-frr.conf"
        path.unlink()
        path.symlink_to(EXAMPLE / "configs/frr/edge-frr.conf")
        with self.assertRaisesRegex(ValueError, "symlinked"):
            renderer.render(state, "frr")

    def dad(self, address_line):
        script = renderer.DAD_WAIT + '''
ip() { printf '%s\\n' "$DAD_TEST_LINE"; }
sleep() { printf 'sleep\\n'; }
wait_ipv6_ready eth1 2001:db8:6501:ff01::1/127
'''
        return subprocess.run(["sh", "-c", script], text=True, capture_output=True,
                              env={**os.environ, "DAD_TEST_LINE": address_line})

    def test_dad_accepts_only_present_ready_exact_address(self):
        ready = self.dad("2: eth1 inet6 2001:db8:6501:ff01::1/127 scope global")
        self.assertEqual(ready.returncode, 0)
        self.assertEqual(ready.stdout, "")
        for line in ("", "2: eth1 inet6 2001:db8:6501:ff01::2/127 scope global",
                     "2: eth1 inet6 2001:db8:6501:ff01::1/127 scope global tentative"):
            result = self.dad(line)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout.count("sleep\n"), 30)
            self.assertIn("not ready within 30 seconds", result.stderr)

    def test_dadfailed_is_immediate_failure(self):
        result = self.dad("2: eth1 inet6 2001:db8:6501:ff01::1/127 scope global tentative dadfailed")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("duplicate IPv6 address", result.stderr)


if __name__ == "__main__":
    unittest.main()
