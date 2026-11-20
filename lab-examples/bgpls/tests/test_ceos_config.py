#!/usr/bin/env python3
"""Static cEOS-profile invariants; no YAML dependency, vendor image, or lab I/O."""

import ast
import ipaddress
from pathlib import Path
import re
import unittest


EXAMPLE = Path(__file__).resolve().parents[1]
BASE = EXAMPLE / "configs" / "frr"
PROFILE = EXAMPLE / "configs" / "ceos-profile"
#  Exact node-block assertions retain the Containerlab image/index pin
# without silently replacing it with the plain image or an ARM64-only manifest.
FRR_IMAGE = "quay.io/frrouting/frr:containerlab-10.7.1@sha256:f7d98e4faa24333c1fdb638f72678111de07a7aef90566132655dbadceca86c7"
RELAY_IMAGE = "docker.io/library/haproxy:3.0.27-alpine@sha256:30860bc97b3a4b1e48011ce0687d4ba1e4711344af8480c4bec85e3ff8411fee"


def commands(text):
    """Ignore comments/blank lines, but preserve command order and indentation."""
    return "\n".join(
        line.rstrip() for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("!", "#"))
    ) + "\n"


def config(path):
    return commands(path.read_text())


def block(text, header):
    """Read one known, indentation-delimited config block, not general YAML."""
    lines = text.splitlines()
    matches = [index for index, line in enumerate(lines) if line == header]
    if len(matches) != 1:
        raise AssertionError(f"Expected exactly one {header!r} block, found {len(matches)}")
    start = matches[0]
    indentation = len(header) - len(header.lstrip())
    body = []
    for line in lines[start + 1:]:
        if len(line) - len(line.lstrip()) <= indentation:
            break
        body.append(line.strip())
    return body


def links(text):
    """Read the committed topology's explicit endpoint arrays and MTU fields."""
    result = {}
    current = None
    for line in commands(text).splitlines():
        match = re.fullmatch(r"    - endpoints: (.+)", line)
        if match:
            current = tuple(ast.literal_eval(match[1]))
            if current in result:
                raise AssertionError(f"Duplicate topology link: {current}")
            result[current] = None
        elif match := re.fullmatch(r"      mtu: ([0-9]+)", line):
            if current is None or result[current] is not None:
                raise AssertionError("Unexpected or repeated link MTU")
            result[current] = int(match[1])
    return result


class CEOSConfigTests(unittest.TestCase):
    def test_every_isis_link_has_the_same_dual_stack_topology(self):
        all_addresses = set()
        for directory in (BASE, PROFILE):
            for path in sorted(directory.glob("*.conf")):
                text = config(path)
                self.assertNotIn("topology ipv6-unicast", text)
                for header in re.findall(r"^interface (?:lo|eth\d+)$", text, re.MULTILINE):
                    body = block(text, header)
                    if "ip router isis CORE" not in body:
                        self.assertFalse(any(line.startswith("ipv6 ") for line in body))
                        continue
                    self.assertIn("ipv6 router isis CORE", body)
                    ipv4 = [line.split()[-1] for line in body if line.startswith("ip address ")]
                    ipv6 = [line.split()[-1] for line in body if line.startswith("ipv6 address ")]
                    self.assertEqual(len(ipv4), 1)
                    self.assertEqual(len(ipv6), 1)
                    v4, v6 = ipaddress.IPv4Interface(ipv4[0]), ipaddress.IPv6Interface(ipv6[0])
                    last = int(str(v4.ip).rsplit(".", 1)[1])
                    if header == "interface lo":
                        self.assertEqual(str(v6), f"2001:db8:6501::{last}/128")
                    else:
                        expected = ipaddress.IPv6Interface(f"2001:db8:6501:{last // 2 + 1}::{last % 2}/127")
                        self.assertEqual(v6, expected)
                        all_addresses.add(str(v6))
        self.assertEqual(len(all_addresses), 16)  # Two EOS endpoints are checked below.
        eos = config(PROFILE / "edge-ceos.cfg")
        self.assertIn("ipv6 unicast-routing\n", eos)
        self.assertEqual(block(eos, "router traffic-engineering"), [
            "router-id ipv4 10.255.0.6", "router-id ipv6 2001:db8:6501::6",
        ])
        self.assertEqual(block(eos, "   address-family ipv6 unicast"), ["no multi-topology"])
        for interface, slot in (("Ethernet1", 8), ("Ethernet2", 9)):
            body = block(eos, f"interface {interface}")
            self.assertIn(f"ipv6 address 2001:db8:6501:{slot}::1/127", body)
            self.assertIn("isis enable CORE", body)
            all_addresses.add(str(ipaddress.IPv6Interface(f"2001:db8:6501:{slot}::1/127")))
        networks = {}
        for address in all_addresses:
            value = ipaddress.IPv6Interface(address)
            networks.setdefault(value.network, set()).add(value.ip)
        self.assertEqual(len(networks), 9)
        self.assertTrue(all(len(addresses) == 2 for addresses in networks.values()))

    def test_p_router_profiles_add_only_the_fifth_interface(self):
        #  An unanchored replacement of "router isis CORE" can match
        # "ip router isis CORE" inside the loopback and silently lose its prefix.
        for node, address in (("p1", "10.254.0.14"), ("p2", "10.254.0.16")):
            with self.subTest(node=node):
                original = config(BASE / f"{node}.conf")
                anchor = "\nrouter isis CORE\n"
                self.assertEqual(original.count(anchor), 1)
                addition = (
                    "\ninterface eth5\n"
                    f" ip address {address}/31\n"
                    f" ipv6 address 2001:db8:6501:{8 if node == 'p1' else 9}::0/127\n"
                    " ip router isis CORE\n"
                    " ipv6 router isis CORE\n"
                    " isis circuit-type level-2\n"
                    " isis network point-to-point\n"
                    " link-params\n"
                    " exit-link-params\n"
                    "router isis CORE\n"
                )
                self.assertEqual(
                    config(PROFILE / f"{node}.conf"),
                    original.replace(anchor, addition),
                )

    def test_reflector_profiles_add_only_the_ceos_ipv4_client(self):
        for node in ("rr1", "rr2"):
            with self.subTest(node=node):
                expected = config(BASE / f"{node}.conf")
                for anchor, addition in (
                    (
                        " neighbor 10.255.0.5 peer-group CORE\n",
                        " neighbor 10.255.0.6 peer-group CORE\n",
                    ),
                    (
                        "  neighbor 10.255.0.5 route-reflector-client\n",
                        "  neighbor 10.255.0.6 activate\n"
                        "  neighbor 10.255.0.6 route-reflector-client\n",
                    ),
                ):
                    self.assertEqual(expected.count(anchor), 1)
                    expected = expected.replace(anchor, anchor + addition)
                self.assertEqual(config(PROFILE / f"{node}.conf"), expected)

    def test_all_router_loopbacks_remain_passive_isis_prefixes(self):
        for number, node in enumerate(("rr1", "rr2", "p1", "p2", "edge-frr"), 1):
            paths = [BASE / f"{node}.conf"]
            if node != "edge-frr":
                paths.append(PROFILE / f"{node}.conf")
            for path in paths:
                with self.subTest(path=path.relative_to(EXAMPLE)):
                    self.assertEqual(block(config(path), "interface lo"), [
                        f"ip address 10.255.0.{number}/32",
                        f"ipv6 address 2001:db8:6501::{number}/128",
                        "ip router isis CORE",
                        "ipv6 router isis CORE",
                        "isis passive",
                    ])
        self.assertEqual(block(config(PROFILE / "edge-ceos.cfg"), "interface Loopback0"), [
            "ip address 10.255.0.6/32", "ipv6 address 2001:db8:6501::6/128",
            "isis enable CORE", "isis passive",
        ])

    def test_topology_preserves_base_links_and_adds_three_ceos_mtu_limits(self):
        original = links((EXAMPLE / "bgpls.clab.yml").read_text())
        combined = links((EXAMPLE / "bgpls-ceos.clab.yml").read_text())
        self.assertEqual(combined, original | {
            ("p1:eth5", "edge-ceos:eth1"): 1500,
            ("p2:eth5", "edge-ceos:eth2"): 1500,
            ("edge-ceos:eth3", "bgpls-relay:eth2"): 1500,
        })

    def test_ceos_image_is_explicitly_local_only_and_baseline_stays_opt_in(self):
        original = config(EXAMPLE / "bgpls.clab.yml")
        combined = config(EXAMPLE / "bgpls-ceos.clab.yml")
        self.assertNotIn("edge-ceos", original)
        self.assertNotIn("ceosarm", original)
        self.assertNotIn("11791", original)
        self.assertEqual(block(combined, "    edge-ceos:"), [
            "kind: arista_ceos",
            "image: ceosarm:4.36.2F",
            "image-pull-policy: Never",
            "mgmt-ipv4: 172.31.250.17",
            "startup-config: configs/ceos-profile/edge-ceos.cfg",
        ])

    def test_frr_nodes_keep_their_settings_except_the_selected_profile_config(self):
        original = config(EXAMPLE / "bgpls.clab.yml")
        combined = config(EXAMPLE / "bgpls-ceos.clab.yml")
        for node in ("rr1", "rr2", "p1", "p2", "edge-frr"):
            with self.subTest(node=node):
                expected = block(original, f"    {node}:")
                if node != "edge-frr":
                    expected = [line.replace(
                        f"configs/frr/{node}.conf",
                        f"configs/ceos-profile/{node}.conf",
                    ) for line in expected]
                self.assertEqual(block(combined, f"    {node}:"), expected)

    def test_native_frr_kind_uses_only_bgp_and_isis_without_changing_other_kinds(self):
        for name in ("bgpls.clab.yml", "bgpls-ceos.clab.yml"):
            with self.subTest(topology=name):
                text = config(EXAMPLE / name)
                self.assertEqual(block(text, "  defaults:"), [
                    "kind: linux", 'restart-policy: "no"',
                ])
                self.assertEqual(block(text, "  kinds:"), [
                    "frr:", "daemons: [bgpd, isisd]",
                ])
                self.assertEqual(block(text, "    frr:"), ["daemons: [bgpd, isisd]"])
                self.assertEqual(text.count("      kind: frr\n"), 5)

    def test_native_frr_nodes_keep_image_addresses_and_existing_startup_configs(self):
        for name in ("bgpls.clab.yml", "bgpls-ceos.clab.yml"):
            text = config(EXAMPLE / name)
            for number, node in enumerate(("rr1", "rr2", "p1", "p2", "edge-frr"), 11):
                directory = "ceos-profile" if name == "bgpls-ceos.clab.yml" and node != "edge-frr" else "frr"
                source = f"configs/{directory}/{node}.conf"
                with self.subTest(topology=name, node=node):
                    #  Exact blocks prevent stale per-file binds, daemon
                    # overrides, or enforced overwrites of saved generated state.
                    self.assertEqual(block(text, f"    {node}:"), [
                        "kind: frr", f"image: {FRR_IMAGE}",
                        f"mgmt-ipv4: 172.31.250.{number}", f"startup-config: {source}",
                    ])
                    self.assertTrue((EXAMPLE / source).is_file())

    def test_native_frr_topologies_drop_legacy_bind_mounts_and_extras(self):
        for name in ("bgpls.clab.yml", "bgpls-ceos.clab.yml"):
            with self.subTest(topology=name):
                text = config(EXAMPLE / name)
                self.assertNotIn("/etc/frr", text)
                self.assertNotRegex(text, r"(?m)^\s*extras:")
                self.assertNotIn("enforce-startup-config:", text)
        self.assertFalse((BASE / "daemons").exists())
        self.assertFalse((BASE / "vtysh.conf").exists())

    def test_native_frr_migration_keeps_relay_configuration_and_local_listeners(self):
        for name, directory, script, ports in (
            ("bgpls.clab.yml", "relay", "start.sh", (11790,)),
            ("bgpls-ceos.clab.yml", "ceos-profile", "relay-start.sh", (11790, 11791)),
        ):
            with self.subTest(topology=name):
                text = config(EXAMPLE / name)
                self.assertEqual(block(text, "    bgpls-relay:"), [
                    f"image: {RELAY_IMAGE}", "mgmt-ipv4: 172.31.250.16",
                    "user: root", "entrypoint: /bin/sh", "cmd: /etc/bgpls-relay/start.sh",
                    "binds:",
                    f"- configs/{directory}/{script}:/etc/bgpls-relay/start.sh:ro",
                    f"- configs/{directory}/haproxy.cfg:/etc/bgpls-relay/haproxy.cfg:ro",
                    "ports:",
                    *(f'- "127.0.0.1:{port}:{port}/tcp"' for port in ports),
                ])

    def test_core_routers_never_activate_link_state_or_export_their_lsdb(self):
        for directory in (BASE, PROFILE):
            for node in ("rr1", "rr2", "p1", "p2"):
                with self.subTest(directory=directory.name, node=node):
                    text = config(directory / f"{node}.conf")
                    self.assertEqual(
                        re.findall(r"^ address-family (.+)$", text, re.MULTILINE),
                        ["ipv4 unicast"],
                    )
                    self.assertNotIn("mpls-te export", text)

    def test_producers_originate_independently_with_only_relay_link_state_peers(self):
        frr = config(BASE / "edge-frr.conf")
        ceos = config(PROFILE / "edge-ceos.cfg")
        self.assertEqual(block(frr, " address-family link-state"), [
            "neighbor 10.254.254.1 activate",
        ])
        self.assertEqual(block(ceos, "   address-family link-state"), [
            "isis instance CORE", "neighbor 10.254.254.3 activate",
        ])
        self.assertIn("mpls-te export", block(frr, "router isis CORE"))
        self.assertIn("isis instance CORE", block(ceos, "   address-family link-state"))
        for text, expected_peers in (
            (frr, {"10.255.0.1", "10.255.0.2", "10.254.254.1"}),
            (ceos, {"10.255.0.1", "10.255.0.2", "10.254.254.3"}),
        ):
            self.assertEqual(set(re.findall(
                r"^ +neighbor ([0-9.]+) (?:peer-group|peer group|remote-as) ",
                text, re.MULTILINE,
            )), expected_peers)

    def test_collector_interfaces_stay_out_of_isis(self):
        self.assertEqual(block(config(BASE / "edge-frr.conf"), "interface eth3"), [
            "ip address 10.254.254.0/31",
        ])
        self.assertEqual(block(config(PROFILE / "edge-ceos.cfg"), "interface Ethernet3"), [
            "no switchport", "ip address 10.254.254.2/31",
        ])


if __name__ == "__main__":
    unittest.main()
