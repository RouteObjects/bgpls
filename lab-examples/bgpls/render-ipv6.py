#!/usr/bin/env python3
"""Render only the opt-in IPv6 collector overlay in a fresh deployment copy."""

import argparse
from pathlib import Path
import sys


def replace_once(text, anchor, replacement, name):
    if text.count(anchor) != 1:
        raise ValueError(f"Expected exactly one unchanged {name} anchor")
    return text.replace(anchor, replacement, 1)


DAD_WAIT = '''#  Only this relay namespace enables IPv6; keep DAD and bound readiness.
wait_ipv6_ready() {
    interface=$1
    address=$2
    attempt=0
    while [ "$attempt" -lt 30 ]; do
        addresses=$(ip -6 -o address show dev "$interface")
        match=$(printf '%s\\n' "$addresses" | awk -v expected="$address" '$4 == expected { print }')
        case " $match " in
            *" dadfailed "*) echo "bgpls-relay: duplicate IPv6 address $address on $interface" >&2; return 1 ;;
        esac
        case " $match " in
            *" tentative "*) ;;
            *) [ -z "$match" ] || return 0 ;;
        esac
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "bgpls-relay: IPv6 address $address on $interface not ready within 30 seconds" >&2
    return 1
}
'''


def render(state, profile):
    state = Path(state)
    repository = Path(__file__).resolve().parents[2]
    if not state.is_absolute() or state.is_symlink() or not state.is_dir():
        raise ValueError("Render requires an absolute, non-symlink deployment directory")
    state = state.resolve()
    if state == repository or repository in state.parents:
        raise ValueError("Refusing to render into repository sources")
    if profile not in ("frr", "ceos"):
        raise ValueError("Unknown profile")
    if (state / ".bgpls-lab-state").exists() or (state / ".bgpls-lab-state").is_symlink():
        raise ValueError("Refusing to render an already recorded deployment")
    replacements = {}

    def read(relative):
        path = state / relative
        if any(parent.is_symlink() for parent in path.parents if parent != state.parent) or path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing or symlinked copied file: {relative}")
        return path.read_text()

    topology = read("bgpls.clab.yml")
    if ("    edge-ceos:\n" in topology) != (profile == "ceos"):
        raise ValueError("Topology does not match the requested profile")
    relay_anchor = "      mgmt-ipv4: 172.31.250.16\n"
    topology = replace_once(topology, relay_anchor, relay_anchor +
        "      #  IPv6 is enabled only in the relay's network namespace.\n"
        "      sysctls:\n"
        '        net.ipv6.conf.all.disable_ipv6: "0"\n'
        '        net.ipv6.conf.default.disable_ipv6: "0"\n', "relay sysctls")
    topology = replace_once(topology,
        "# topology; management, BGP sessions, and " + ("both collector relays" if profile == "ceos" else "the collector relay") + " stay IPv4.\n",
        "# topology; management and IPv4 relays stay IPv4; direct IPv6 collectors are opt-in.\n", "topology description")
    replacements["bgpls.clab.yml"] = topology

    frr = read("configs/frr/edge-frr.conf")
    anchor = "interface eth3\n ip address 10.254.254.0/31\n!\n"
    frr = replace_once(frr, anchor, anchor.replace("\n!\n", "\n ipv6 address 2001:db8:6501:ff01::/127\n!\n"), "FRR collector interface")
    anchor = " neighbor 10.254.254.1 timers 3 9\n"
    frr = replace_once(frr, anchor, anchor +
        " ! Direct IPv6 collector transport, separate from the IPv4 relay.\n"
        " neighbor 2001:db8:6501:ff01::1 remote-as 65001\n"
        " neighbor 2001:db8:6501:ff01::1 passive\n"
        " neighbor 2001:db8:6501:ff01::1 timers 3 9\n", "FRR collector peer")
    anchor = " address-family link-state\n  neighbor 10.254.254.1 activate\n"
    frr = replace_once(frr, anchor, anchor + "  neighbor 2001:db8:6501:ff01::1 activate\n", "FRR link-state activation")
    replacements["configs/frr/edge-frr.conf"] = frr

    if profile == "ceos":
        eos = read("configs/ceos-profile/edge-ceos.cfg")
        anchor = "interface Ethernet3\n   no switchport\n   ip address 10.254.254.2/31\n!\n"
        eos = replace_once(eos, anchor, anchor.replace("\n!\n", "\n   ipv6 address 2001:db8:6501:ff02::/127\n!\n"), "EOS collector interface")
        anchor = "   neighbor 10.254.254.3 timers 3 9\n"
        eos = replace_once(eos, anchor, anchor +
            "   ! Direct IPv6 collector peer; not an IPv6-unicast AF session.\n"
            "   neighbor 2001:db8:6501:ff02::1 remote-as 65001\n"
            "   neighbor 2001:db8:6501:ff02::1 passive\n"
            "   neighbor 2001:db8:6501:ff02::1 timers 3 9\n", "EOS collector peer")
        anchor = "      neighbor 10.254.254.3 activate\n"
        eos = replace_once(eos, anchor, anchor + "      neighbor 2001:db8:6501:ff02::1 activate\n", "EOS link-state activation")
        replacements["configs/ceos-profile/edge-ceos.cfg"] = eos

    relay_path = "configs/ceos-profile/relay-start.sh" if profile == "ceos" else "configs/relay/start.sh"
    relay = read(relay_path)
    relay = replace_once(relay, "set -eu\n", "set -eu\n\n" + DAD_WAIT, "relay initialization")
    for interface, subnet in (("eth1", "ff01"), ("eth2", "ff02")) if profile == "ceos" else (("eth1", "ff01"),):
        anchor = f"ip link set {interface} up\n"
        address = f"2001:db8:6501:{subnet}::1/127"
        relay = replace_once(relay, anchor, anchor +
            f"ip -6 address replace {address} dev {interface}\n"
            f"wait_ipv6_ready {interface} {address}\n", f"relay {interface} address")
    replacements[relay_path] = relay
    #  Validate every anchor before writing anything; drift fails closed.
    for relative, text in replacements.items():
        (state / relative).write_text(text)
    return sorted(replacements)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    parser.add_argument("--profile", choices=("frr", "ceos"), required=True)
    args = parser.parse_args()
    render(args.state, args.profile)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"bgpls-lab: {error}", file=sys.stderr)
        sys.exit(1)
