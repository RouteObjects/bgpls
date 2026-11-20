#!/usr/bin/env python3
"""Offline ASN rendering tests; all writes stay in fresh temporary copies."""

import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


EXAMPLE = Path(__file__).resolve().parents[1]


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, EXAMPLE / filename)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


renderer = load("asn_renderer", "render-asn.py")
ipv6_renderer = load("asn_ipv6_renderer", "render-ipv6.py")


class ASNRenderTests(unittest.TestCase):
    def copy(self, profile, transport="ipv4"):
        temporary = tempfile.TemporaryDirectory(prefix="bgpls-asn-render-")
        self.addCleanup(temporary.cleanup)
        state = Path(temporary.name).resolve()
        shutil.copytree(EXAMPLE / "configs", state / "configs")
        topology = "bgpls-ceos.clab.yml" if profile == "ceos" else "bgpls.clab.yml"
        shutil.copyfile(EXAMPLE / topology, state / "bgpls.clab.yml")
        if transport == "ipv6":
            ipv6_renderer.render(state, profile)
        return state

    def snapshot(self, state):
        return {path.relative_to(state).as_posix(): path.read_bytes()
                for path in state.rglob("*") if path.is_file()}

    def test_default_is_byte_identical_for_both_profiles_and_transports(self):
        for profile in ("frr", "ceos"):
            for transport in ("ipv4", "ipv6"):
                with self.subTest(profile=profile, transport=transport):
                    state = self.copy(profile, transport)
                    before = self.snapshot(state)
                    self.assertEqual(renderer.render(state, profile, 65001, transport), [])
                    self.assertEqual(self.snapshot(state), before)

    def test_only_selected_process_and_neighbor_as_directives_change(self):
        sources = self.snapshot(EXAMPLE / "configs")
        for profile in ("frr", "ceos"):
            for transport in ("ipv4", "ipv6"):
                for asn in (65535, 65536, 4200000001, 4294967295):
                    with self.subTest(profile=profile, transport=transport, asn=asn):
                        state = self.copy(profile, transport)
                        before = self.snapshot(state)
                        changed = renderer.render(state, profile, asn, transport)
                        after = self.snapshot(state)
                        expected = set(renderer.selected_configs(profile, transport))
                        self.assertEqual(set(changed), expected)
                        self.assertEqual({path for path in before if before[path] != after[path]}, expected)
                        pattern = re.compile(rb"(?m)^([ \t]*(?:router bgp|neighbor \S+ remote-as) )65001$")
                        for relative in expected:
                            wanted = pattern.sub(lambda match: match[1] + str(asn).encode(), before[relative])
                            self.assertEqual(after[relative], wanted)
                        with self.assertRaises(ValueError):
                            renderer.render(state, profile, asn, transport)
                        self.assertEqual(self.snapshot(state), after)
        self.assertEqual(self.snapshot(EXAMPLE / "configs"), sources)

    def test_comments_addresses_and_unrelated_numbers_remain_unchanged(self):
        state = self.copy("ceos", "ipv6")
        path = state / "configs/ceos-profile/edge-ceos.cfg"
        extra = "! Keep comment65001\n! router bgp 65001\n! neighbor CORE remote-as 65001\n"
        path.write_text(path.read_text() + extra)
        before = self.snapshot(state)
        renderer.render(state, "ceos", 4200000001, "ipv6")
        after = self.snapshot(state)
        self.assertTrue(after["configs/ceos-profile/edge-ceos.cfg"].endswith(extra.encode()))
        for relative in renderer.selected_configs("ceos", "ipv6"):
            untouched_before = [line for line in before[relative].splitlines()
                                if not re.match(rb"^[ \t]*(router bgp|neighbor \S+ remote-as) ", line)]
            untouched_after = [line for line in after[relative].splitlines()
                               if not re.match(rb"^[ \t]*(router bgp|neighbor \S+ remote-as) ", line)]
            self.assertEqual(untouched_after, untouched_before)

    def test_anchor_drift_fails_before_any_config_write(self):
        changes = (
            ("router bgp 65001", "router bgp 65002"),
            ("router bgp 65001", "router bgp 65001\nrouter bgp 65001"),
            ("   neighbor CORE remote-as 65001\n", ""),
            ("   neighbor CORE remote-as 65001", "   neighbor CORE remote-as 65001\n   neighbor CORE remote-as 65001"),
            ("   neighbor CORE remote-as 65001", "   neighbor CORE remote-as 65002"),
            ("   neighbor CORE remote-as 65001", "   neighbor CORE local-as 65001"),
            ("   neighbor CORE remote-as 65001", "   neighbor OTHER remote-as 65001"),
        )
        for old, new in changes:
            with self.subTest(new=new):
                state = self.copy("ceos")
                path = state / "configs/ceos-profile/edge-ceos.cfg"
                path.write_text(path.read_text().replace(old, new, 1))
                before = self.snapshot(state)
                with self.assertRaisesRegex(ValueError, "anchor"):
                    renderer.render(state, "ceos", 4200000001)
                self.assertEqual(self.snapshot(state), before)

    def test_default_still_rejects_drift(self):
        state = self.copy("frr")
        path = state / "configs/frr/rr1.conf"
        path.write_text(path.read_text().replace("router bgp 65001", "router bgp 65002"))
        before = self.snapshot(state)
        with self.assertRaises(ValueError):
            renderer.render(state, "frr", 65001)
        self.assertEqual(self.snapshot(state), before)

    def test_wrong_profile_transport_and_topology_bindings_are_rejected(self):
        for profile, transport in (("ceos", "ipv4"), ("frr", "ipv6")):
            state = self.copy("frr")
            before = self.snapshot(state)
            with self.assertRaises(ValueError):
                renderer.render(state, profile, 4200000001, transport)
            self.assertEqual(self.snapshot(state), before)
        state = self.copy("ceos", "ipv6")
        before = self.snapshot(state)
        with self.assertRaises(ValueError):
            renderer.render(state, "ceos", 4200000001, "ipv4")
        self.assertEqual(self.snapshot(state), before)
        topology = state / "bgpls.clab.yml"
        topology.write_text(topology.read_text().replace("startup-config: configs/frr/edge-frr.conf",
                                                        "startup-config: configs/frr/foreign.conf"))
        before = self.snapshot(state)
        with self.assertRaisesRegex(ValueError, "Topology"):
            renderer.render(state, "ceos", 4200000001, "ipv6")
        self.assertEqual(self.snapshot(state), before)

    def test_recorded_deployment_repo_sources_and_symlinks_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "repository"):
            renderer.render(EXAMPLE, "frr", 4200000001)
        state = self.copy("frr")
        (state / ".bgpls-lab-state").write_text("existing\n")
        with self.assertRaisesRegex(ValueError, "recorded"):
            renderer.render(state, "frr", 4200000001)
        (state / ".bgpls-lab-state").unlink()
        path = state / "configs/frr/rr1.conf"
        path.unlink()
        path.symlink_to(EXAMPLE / "configs/frr/rr1.conf")
        with self.assertRaisesRegex(ValueError, "symlinked"):
            renderer.render(state, "frr", 4200000001)

    def test_invalid_asn_never_modifies_copied_state(self):
        state = self.copy("frr")
        before = self.snapshot(state)
        for asn in (0, 23456, -1, 4294967296, True, "65001"):
            with self.subTest(asn=asn), self.assertRaises(ValueError):
                renderer.render(state, "frr", asn)
            self.assertEqual(self.snapshot(state), before)

    def test_shell_deployment_copies_then_renders_and_records_v4(self):
        script = '''source "$1/deploy.sh"
bgpls_runtime() { echo 'Unexpected runtime call' >&2; return 99; }
bgpls_docker() { echo 'Unexpected Docker call' >&2; return 99; }
bgpls_containerlab() { echo 'Unexpected Containerlab call' >&2; return 99; }
bgpls_set_profile "$2"
BGPLS_TRANSPORT=$3
BGPLS_DAEMON_ID=mock-daemon
bgpls_parse_deploy_args --asn "$4" "$5"
bgpls_init_state "$BGPLS_REQUESTED_STATE"
bgpls_copy_deployment
'''
        for profile in ("frr", "ceos"):
            for transport in ("ipv4", "ipv6"):
                with self.subTest(profile=profile, transport=transport):
                    temporary = tempfile.TemporaryDirectory(prefix="bgpls-asn-copy-")
                    self.addCleanup(temporary.cleanup)
                    state = Path(temporary.name).resolve()
                    result = subprocess.run(["bash", "-c", script, "offline-deploy", str(EXAMPLE),
                                             profile, transport, "04200000001", str(state)],
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    marker = (state / ".bgpls-lab-state").read_text().splitlines()
                    self.assertEqual(marker[0], "bgpls-lab-v4")
                    self.assertEqual(json.loads(marker[1])["asn"], 4200000001)
                    record = renderer.STATE.read_state(state)
                    self.assertEqual((record["profile"], record["transport"], record["asn"]),
                                     (profile, transport, 4200000001))
                    for relative in renderer.selected_configs(profile, transport):
                        self.assertIn("router bgp 4200000001\n", (state / relative).read_text())
                    with self.assertRaisesRegex(ValueError, "recorded"):
                        renderer.render(state, profile, 4200000001, transport)


if __name__ == "__main__":
    unittest.main()
