#!/usr/bin/env python3
"""Render one lab-wide ASN only in fresh, copied router configurations."""

import argparse
import importlib.util
from pathlib import Path
import re
import sys


SPEC = importlib.util.spec_from_file_location("asn_lab_state", Path(__file__).with_name("lab-state.py"))
STATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATE)


def selected_configs(profile, transport):
    if profile not in ("frr", "ceos") or transport not in ("ipv4", "ipv6"):
        raise ValueError("Unknown profile or transport")
    directory = "frr" if profile == "frr" else "ceos-profile"
    result = {f"configs/{directory}/{node}.conf": {"CORE"} for node in ("rr1", "rr2", "p1", "p2")}
    result["configs/frr/edge-frr.conf"] = {"CORE", "10.254.254.1"}
    if transport == "ipv6":
        result["configs/frr/edge-frr.conf"].add("2001:db8:6501:ff01::1")
    if profile == "ceos":
        result["configs/ceos-profile/edge-ceos.cfg"] = {"CORE", "10.254.254.3"}
        if transport == "ipv6":
            result["configs/ceos-profile/edge-ceos.cfg"].add("2001:db8:6501:ff02::1")
    return result


def render(state, profile, asn, transport="ipv4"):
    asn = STATE.validate_asn(asn)
    state = STATE._state_path(state)
    if (state / STATE.MARKER).exists() or (state / STATE.MARKER).is_symlink():
        raise ValueError("Refusing to render an already recorded deployment")
    selected = selected_configs(profile, transport)

    def read(relative):
        path = state / relative
        if path.is_symlink() or not path.is_file() or any(
            parent.is_symlink() for parent in path.parents if state in parent.parents
        ):
            raise ValueError(f"Missing or symlinked copied file: {relative}")
        return path.read_bytes().decode("utf-8")

    bindings = re.findall(r"^      startup-config: (\S+)$", read("bgpls.clab.yml"), re.MULTILINE)
    if len(bindings) != len(selected) or set(bindings) != set(selected):
        raise ValueError("Topology startup-config anchors do not match the selected profile")

    replacements = {}
    for relative, peers in selected.items():
        text = read(relative)
        lines = []
        processes = 0
        seen_peers = set()
        for line in text.splitlines(keepends=True):
            tokens = line.split()
            match = None
            if tokens[:2] == ["router", "bgp"]:
                processes += 1
                match = re.fullmatch(r"([ \t]*router[ \t]+bgp[ \t]+)65001([ \t]*(?:\r?\n)?)", line)
                if match is None or processes > 1:
                    raise ValueError(f"Expected one unchanged router bgp 65001 anchor: {relative}")
            elif len(tokens) >= 3 and tokens[0] == "neighbor" and tokens[2] in ("remote-as", "local-as"):
                peer = tokens[1]
                match = re.fullmatch(r"([ \t]*neighbor[ \t]+\S+[ \t]+remote-as[ \t]+)65001([ \t]*(?:\r?\n)?)", line)
                if match is None or peer not in peers or peer in seen_peers:
                    raise ValueError(f"Unexpected or repeated neighbor-AS anchor: {relative}: {peer}")
                seen_peers.add(peer)
            lines.append(match[1] + str(asn) + match[2] if match else line)
        if processes != 1 or seen_peers != peers:
            raise ValueError(f"Missing router or neighbor-AS anchors: {relative}")
        replacements[relative] = "".join(lines).encode("utf-8")
    #  Validate every selected router and collector peer before writing.
    # Never substitute numbers globally: addresses, router IDs, IS-IS NETs,
    # comments and unused-profile configs are not ASN configuration directives.
    # The default remains byte-for-byte identical, including copied comments.
    if asn == STATE.DEFAULT_ASN:
        return []
    for relative, content in replacements.items():
        (state / relative).write_bytes(content)
    return sorted(replacements)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    parser.add_argument("--profile", choices=("frr", "ceos"), required=True)
    parser.add_argument("--transport", choices=("ipv4", "ipv6"), default="ipv4")
    parser.add_argument("--asn", type=STATE.parse_asn, default=STATE.DEFAULT_ASN)
    args = parser.parse_args()
    render(args.state, args.profile, args.asn, args.transport)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"bgpls-lab: {error}", file=sys.stderr)
        sys.exit(1)
