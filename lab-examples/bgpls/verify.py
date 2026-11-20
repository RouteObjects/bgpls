#!/usr/bin/env python3
"""Bounded live checks for this lab only; never sends signals to Swift unit tests."""

import argparse
import collections
from contextlib import contextmanager, nullcontext
import copy
import datetime
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time


WIRE_SPEC = importlib.util.spec_from_file_location("bgpls_wire_topology", Path(__file__).with_name("wire-topology.py"))
WIRE = importlib.util.module_from_spec(WIRE_SPEC)
WIRE_SPEC.loader.exec_module(WIRE)


def helper(name):
    spec = importlib.util.spec_from_file_location("bgpls_" + name.replace("-", "_"),
                                                Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verification_lock(state):
    return helper("lab-state").verification_lock(state)


TRANSPORTS = {
    "frr": {"identifier": "192.0.2.101", "router_identifier": "10.255.0.5", "port": 11790,
            "ipv4": {"peer": "10.254.254.0", "source": "10.254.254.1"},
            "ipv6": {"peer": "2001:db8:6501:ff01::", "source": "2001:db8:6501:ff01::1", "interface": "eth1"}},
    "ceos": {"identifier": "192.0.2.102", "router_identifier": "10.255.0.6", "port": 11791,
             "ipv4": {"peer": "10.254.254.2", "source": "10.254.254.3"},
             "ipv6": {"peer": "2001:db8:6501:ff02::", "source": "2001:db8:6501:ff02::1", "interface": "eth2"}},
}


def collector_inputs(args):
    if getattr(args, "attribute_probes", False) and not getattr(args, "attributes", False):
        raise ValueError("--attribute-probes requires --attributes")
    transport = getattr(args, "transport", "ipv4")
    binary, artifact = getattr(args, "binary", None), getattr(args, "artifact", None)
    if transport == "ipv4" and binary and not artifact:
        binary = Path(binary).resolve(strict=True)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError("--binary must name an executable bgpls file")
        return transport, binary, None
    if transport == "ipv6" and artifact and not binary:
        artifact = Path(artifact).resolve(strict=True)
        helper("container-collector").load_artifact(artifact)
        return transport, None, artifact
    raise ValueError("IPv4 verification requires only --binary; IPv6 verification requires only --artifact")


def add_transport_arguments(parser):
    parser.add_argument("--transport", choices=("ipv4", "ipv6"), default="ipv4")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--binary", help="native executable for the IPv4 relay path")
    source.add_argument("--artifact", help="validated Linux ARM64 artifact manifest for direct IPv6")
    parser.add_argument("--attributes", action="store_true",
                        help="qualify typed presentation, native values, PCAP evidence, and Swift replay")
    parser.add_argument("--attribute-probes", action="store_true",
                        help="with --attributes, temporarily change and exactly restore selected IS-IS metrics")


def capture_expectation(producer, transport, asn=65001, *, legacy_collector=False):
    #  Live qualification requires AS4 even for a two-octet ASN. Only an
    # explicit historical replay may accept the old collector's absent capability.
    helper("lab-state").validate_asn(asn)
    if legacy_collector and asn > 65535:
        raise ValueError("a legacy collector cannot qualify a four-byte ASN")
    settings = TRANSPORTS[producer]
    return {"family": 6 if transport == "ipv6" else 4,
            "source": settings["ipv6"]["source"] if transport == "ipv6" else "127.0.0.1",
            "peer": settings["ipv6"]["peer"] if transport == "ipv6" else "127.0.0.1",
            "port": 179 if transport == "ipv6" else settings["port"],
            "identifier": settings["identifier"], "router_identifier": settings["router_identifier"],
            "asn": asn, "legacy_collector": legacy_collector}


def assert_neighbor_endpoint(neighbor, producer, transport, asn):
    endpoint = TRANSPORTS[producer][transport]
    if (neighbor["hostForeign"] != endpoint["source"] or neighbor["hostLocal"] != endpoint["peer"]
            or neighbor["portLocal"] != 179 or not 0 < neighbor["portForeign"] <= 65535):
        raise AssertionError(f"{producer} exporter sees the wrong relay source or BGP socket")
    if (type(neighbor["localAs"]) is not int or type(neighbor["remoteAs"]) is not int
            or neighbor["localAs"] != asn or neighbor["remoteAs"] != asn):
        raise AssertionError(f"{producer} exporter ASNs differ from deployment state")


ROUTERS = ("rr1", "rr2", "p1", "p2", "edge-frr")
IDS = {name: f"0000.0000.000{i}" for i, name in enumerate(ROUTERS, 1)}
ADJACENCIES = (
    ("rr1", "p1", "10.254.0.0", "10.254.0.1"),
    ("rr1", "p2", "10.254.0.2", "10.254.0.3"),
    ("rr2", "p1", "10.254.0.4", "10.254.0.5"),
    ("rr2", "p2", "10.254.0.6", "10.254.0.7"),
    ("p1", "p2", "10.254.0.8", "10.254.0.9"),
    ("p1", "edge-frr", "10.254.0.10", "10.254.0.11"),
    ("p2", "edge-frr", "10.254.0.12", "10.254.0.13"),
)


class VerificationInterrupted(Exception):
    def __init__(self, signum):
        super().__init__(f"verification interrupted by {signal.Signals(signum).name}")
        self.signum = signum


class CleanupFailure(RuntimeError):
    def __init__(self, failures):
        self.failures = tuple(failures)
        super().__init__("cleanup incomplete: " + "; ".join(f"{name}: {error}" for name, error in failures))


class VerificationFailure(RuntimeError):
    def __init__(self, primary_error, cleanup_error):
        self.primary_error, self.cleanup_error = primary_error, cleanup_error
        super().__init__(f"verification failed: {primary_error}; cleanup failed: {cleanup_error}")


def run_cleanup(actions):
    """Attempt every owned resource independently, retaining the original errors."""
    failures = []
    for name, action in actions:
        try:
            action()
        except Exception as error:
            failures.append((name, error))
    if failures:
        raise CleanupFailure(failures)


def record_failure(lab, transport, error):
    record = {"type": type(error).__name__, "error": str(error), "transport": transport}
    cleanup_error = error.cleanup_error if isinstance(error, VerificationFailure) else error
    if isinstance(error, VerificationFailure):
        record["primary_error"] = {"type": type(error.primary_error).__name__, "error": str(error.primary_error)}
    if isinstance(cleanup_error, CleanupFailure):
        record["cleanup_errors"] = [
            {"action": name, "type": type(failure).__name__, "error": str(failure)}
            for name, failure in cleanup_error.failures
        ]
    elif isinstance(error, VerificationFailure):
        record["cleanup_errors"] = [{"type": type(cleanup_error).__name__, "error": str(cleanup_error)}]
    try:
        lab.save("failure", record)
    except Exception as evidence_error:
        #  Evidence storage can fail too; never replace the actual
        # verification/cleanup error with a secondary diagnostic write failure.
        try:
            print(f"WARNING: could not save failure evidence: {evidence_error}", file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass


@contextmanager
def verification_cleanup(lab, transport, cleanup):
    primary_error = cleanup_error = None
    try:
        yield
    except BaseException as error:
        primary_error = error
    finally:
        try:
            cleanup()
        except BaseException as error:
            cleanup_error = error
    #  Cleanup is part of the outcome, not a finally block that can
    # overwrite the primary failure after a successful result was published.
    if primary_error is not None and cleanup_error is not None:
        error = VerificationFailure(primary_error, cleanup_error)
        record_failure(lab, transport, error)
        raise error from primary_error
    error = primary_error if primary_error is not None else cleanup_error
    if error is not None:
        record_failure(lab, transport, error)
        raise error


def publish_result(lab, transport, summary):
    try:
        # Snapshot only after cleanup updates ownership/removal metadata.
        completed = copy.deepcopy(summary)
        completed["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        lab.save("result", completed)
    except Exception as error:
        record_failure(lab, transport, error)
        raise


class NativeSelectionPending(AssertionError):
    """A native route exists but FRR has not selected a valid path yet."""


def install_signal_handlers():
    def interrupted(signum, _frame):
        #  Reach run()'s cleanup even when the verifier, not its child, is stopped.
        # Further interrupts must not cut short restoring both links and reaping the child.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise VerificationInterrupted(signum)

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)


def endpoint_addresses(ipv4=None, ipv6=None):
    """Match the CLI's family-ordered display without erasing either descriptor."""
    values = []
    if ipv4 is not None:
        values.append(str(ipaddress.IPv4Address(ipv4)))
    if ipv6 is not None:
        values.append(str(ipaddress.IPv6Address(ipv6)))
    if not values:
        raise AssertionError("expected at least one numbered link descriptor")
    return ",".join(values)


def expected_links(adjacencies=ADJACENCIES, identities=IDS):
    links = set()
    for slot, (left, right, local, remote) in enumerate(adjacencies, 1):
        local = endpoint_addresses(local, f"2001:db8:6501:{slot}::")
        remote = endpoint_addresses(remote, f"2001:db8:6501:{slot}::1")
        links.add(f"link {identities[left]} {local} → {identities[right]} {remote}")
        links.add(f"link {identities[right]} {remote} → {identities[left]} {local}")
    return links


def expected_loopbacks(routers=ROUTERS, identities=IDS):
    return {f"prefix {prefix} node {identities[node]}"
            for index, node in enumerate(routers, 1)
            for prefix in (f"10.255.0.{index}/32", f"2001:db8:6501::{index}/128")}


def rib_summary(objects):
    return " ".join(f"{plural}={sum(value.startswith(kind + ' ') for value in objects)}"
                    for kind, plural in (("node", "nodes"), ("link", "links"), ("prefix", "prefixes")))


def core_link_objects(objects):
    """Select the qualified p1-p2 link identities, retaining every address family."""
    pairs = {(IDS["p1"], IDS["p2"]), (IDS["p2"], IDS["p1"])}
    return {value for value in objects if value.startswith("link ")
            and (value.split()[1], value.split()[4]) in pairs}


def frr_ipv6_routes_ready(table, node, routers=ROUTERS):
    expected = {f"2001:db8:6501::{index}/128"
                for index, name in enumerate(routers, 1) if name != node}
    if set(table) != expected:
        return False
    for paths in table.values():
        selected = [path for path in paths if path.get("protocol") == "isis"
                    and path.get("selected") and path.get("installed")]
        if len(selected) != 1:
            return False
        nexthops = selected[0].get("nexthops", [])
        #  IPv6 IS-IS normally installs scoped link-local next hops;
        # those are valid even though the topology descriptors use global IPs.
        if not any(hop.get("active") and hop.get("fib") and hop.get("afi") == "ipv6"
                   and isinstance(ipaddress.ip_address(hop["ip"]), ipaddress.IPv6Address)
                   for hop in nexthops):
            return False
    return True


def watch_state(text, *, attributes=False):
    """Replay the CLI's observable stream; Swift tests separately verify full keys."""
    if attributes:
        return set(helper("attribute-checks").watch_records(text))
    objects = set()
    for operation, value in re.findall(r"WATCH (upsert|withdraw) ([^\r\n]+)", text):
        if operation == "upsert":
            objects.add(value)
        else:
            objects.discard(value)
    return objects


def final_objects(lines, *, attributes=False):
    if attributes:
        records = [helper("attribute-checks").parse_line(line, final=True) for line in lines if line]
        identities = [record["display"] for record in records]
        if len(identities) != len(set(identities)):
            raise AssertionError("duplicate final typed identity")
        return set(identities)
    return {re.sub(r" AS .*", "", line) for line in lines if line}


def native_objects(table):
    """Normalize only the verified FRR 10.7.1 baseline's presentation fields."""
    def identity(descriptors):
        value = descriptors["igpRouterId"]
        if not re.fullmatch(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\.00", value):
            raise AssertionError(f"unexpected baseline IS-IS identity: {value}")
        # FRR displays the zero pseudonode octet; bgpls displays the System ID.
        return value[:-3]

    objects = set()
    for key, paths in table["routes"].items():
        best = [path for path in paths if path.get("valid") and path.get("bestpath")]
        if not best:
            #  FRR can expose an entry between its update and best-path
            # selection. It is never a valid snapshot; only bounded polling may retry it.
            raise NativeSelectionPending(f"FRR native route {key!r} has no valid best path yet")
        if len(best) != 1:
            raise AssertionError("expected one valid best path per locally originated NLRI")
        nlri = best[0]["nlri"]
        if nlri["protocolId"] != 2 or nlri["identifier"] != 0:
            raise AssertionError("unexpected IGP protocol or instance in baseline")
        local = identity(nlri["localNodeDescriptors"])
        if nlri["nlriType"] == "node":
            value = f"node {local}"
        elif nlri["nlriType"] == "link":
            remote = identity(nlri["remoteNodeDescriptors"])
            link = nlri["linkDescriptors"]
            local_address = endpoint_addresses(link.get("ipv4InterfaceAddress"), link.get("ipv6InterfaceAddress"))
            remote_address = endpoint_addresses(link.get("ipv4NeighborAddress"), link.get("ipv6NeighborAddress"))
            value = f"link {local} {local_address} → {remote} {remote_address}"
        elif nlri["nlriType"] in ("ipv4Prefix", "ipv6Prefix"):
            family = ipaddress.IPv4Network if nlri["nlriType"] == "ipv4Prefix" else ipaddress.IPv6Network
            prefix = str(family(nlri["prefixDescriptors"]["ipReachabilityInformation"]))
            value = f"prefix {prefix} node {local}"
        else:
            raise AssertionError(f"unexpected NLRI type: {nlri['nlriType']}")
        if value in objects:
            raise AssertionError("native NLRI identities collide in baseline comparison")
        objects.add(value)
    return objects


def reflected_by_both(table, originator):
    reflectors = set()
    for path in table.get("paths", []):
        peer = path.get("peer", {}).get("routerId")
        if (path.get("valid") and path.get("originatorId") == originator
                and path.get("clusterList", {}).get("list") == [peer]):
            reflectors.add(peer)
    return {"10.255.0.1", "10.255.0.2"} <= reflectors


def same_bgp_connection(before, after):
    # FRR recomputes its displayed establishment epoch from rounded uptime; it
    # can differ by a second without a reconnect. Use socket identity/counters.
    stable = ("connectionsEstablished", "connectionsDropped", "hostForeign", "portForeign", "hostLocal", "portLocal")
    return (after["bgpState"] == "Established"
            and all(before[field] == after[field] for field in stable)
            and after["bgpTimerUpMsec"] >= before["bgpTimerUpMsec"]
            and all(after["messageStats"][field] >= before["messageStats"][field]
                    for field in ("keepalivesSent", "keepalivesRecv")))


def open_identity(body):
    """Decode OPEN identity/capabilities without inferring ASN from TCP addresses."""
    reader = WIRE.Reader(body)
    version, asn, hold = reader.integer(1), reader.integer(2), reader.integer(2)
    identifier = str(ipaddress.IPv4Address(reader.take(4)))
    options = WIRE.Reader(reader.take(reader.integer(1)))
    if reader.remaining() or version != 4 or hold != 9:
        raise AssertionError("unexpected OPEN version, hold time, or optional-parameter length")
    capabilities = []
    four_byte_asn = None
    while options.remaining():
        kind, value = options.integer(1), options.take(options.integer(1))
        #  Match the client's optional-parameter checks; tolerance for
        # unknown capability codes does not admit unsupported parameter types.
        if kind != 2:
            raise AssertionError("unsupported OPEN optional-parameter type")
        if not value:
            raise AssertionError("empty OPEN capabilities optional parameter")
        values = WIRE.Reader(value)
        while values.remaining():
            code, value = values.integer(1), values.take(values.integer(1))
            if code == 1:
                if len(value) != 4:
                    raise AssertionError("invalid multiprotocol capability width")
                afi, reserved, safi = struct.unpack("!HBB", value)
                if reserved != 0:
                    raise AssertionError("invalid multiprotocol capability reserved octet")
                capabilities.append((afi, safi))
            elif code == 65:
                if len(value) != 4:
                    raise AssertionError("invalid four-byte ASN capability width")
                candidate = int.from_bytes(value, "big")
                if four_byte_asn is not None and four_byte_asn != candidate:
                    raise AssertionError("conflicting four-byte ASN capabilities")
                four_byte_asn = candidate
    return {"identifier": identifier, "multiprotocol_capabilities": capabilities,
            "my_as": asn, "four_byte_asn": four_byte_asn,
            "effective_asn": four_byte_asn if four_byte_asn is not None else asn}


def validate_pcap(path, expected=None):
    """Check complete NIO capture; optionally qualify the exact socket and OPENs."""
    streams = {}
    flags = collections.defaultdict(collections.Counter)
    records = 0
    #  Both capture consumers require the same NIO-only transport framing;
    # family/address/port keys prevent unrelated same-port streams being joined.
    for packet in WIRE.PCAP.tcp_packets(path.read_bytes()):
        records = packet["packet"]
        WIRE.PCAP.append_payload(streams, packet)
        for name, mask in (("syn", 2), ("fin", 1), ("reset", 4)):
            if packet["flags"] & mask:
                flags[packet["stream_key"]][name] += 1
    counts = collections.Counter()
    opens, next_hops = {}, []
    for key, state in streams.items():
        stream = state["buffer"]
        cursor = 0
        while cursor < len(stream):
            if stream[cursor:cursor + 16] != b"\xff" * 16 or cursor + 19 > len(stream):
                raise AssertionError("truncated or invalid BGP header in PCAP")
            length, message_type = struct.unpack_from("!HB", stream, cursor + 16)
            if not 19 <= length <= 4096 or not 1 <= message_type <= 5 or cursor + length > len(stream):
                raise AssertionError("truncated BGP body in PCAP")
            counts[message_type] += 1
            body = bytes(stream[cursor + 19:cursor + length])
            if expected is not None and message_type == 1:
                if key in opens:
                    raise AssertionError("more than one OPEN in one capture direction")
                opens[key] = open_identity(body)
            if expected is not None and message_type == 2:
                next_hops.extend(WIRE.update_next_hops(body))
            cursor += length
    if counts[1] != 2 or counts[2] == 0 or counts[4] < 8:
        raise AssertionError(f"missing OPEN/UPDATE/keepalive exchange: {dict(counts)}")
    result = {"records": records, "bgp_messages_by_type": dict(counts)}
    if expected is not None:
        outbound = [key for key in streams if key[0] == expected["family"]
                    and key[1] == expected["source"] and key[3] == expected["peer"]
                    and key[4] == expected["port"] and 0 < key[2] <= 65535 and key[2] != expected["port"]]
        if len(outbound) != 1:
            raise AssertionError("capture does not contain the expected bound client-to-producer flow")
        forward = outbound[0]
        reverse = (forward[0], forward[3], forward[4], forward[1], forward[2])
        if set(streams) != {forward, reverse} or set(opens) != {forward, reverse}:
            raise AssertionError("capture must contain exactly two reciprocal flows and one OPEN in each")
        for flow, identifier in ((forward, expected["identifier"]), (reverse, expected["router_identifier"])):
            if opens[flow]["identifier"] != identifier:
                raise AssertionError("OPEN BGP identifier differs from the independently configured identifier")
            if (16388, 71) not in opens[flow]["multiprotocol_capabilities"]:
                raise AssertionError("both OPENs must advertise BGP-LS AFI 16388 / SAFI 71")
            identity = opens[flow]
            asn = expected["asn"]
            if identity["my_as"] != (asn if asn <= 65535 else 23456) or identity["effective_asn"] != asn:
                raise AssertionError("OPEN My AS or effective ASN differs from deployment state")
            if identity["four_byte_asn"] != asn:
                if not (flow == forward and expected["legacy_collector"] and identity["four_byte_asn"] is None):
                    raise AssertionError("both OPENs must advertise the expected four-byte ASN capability")
            if flags[flow]["syn"] != 1 or flags[flow]["fin"] != 1 or flags[flow]["reset"]:
                raise AssertionError("capture is missing orderly SYN/FIN completion in both directions")
        result.update(flow={**expected, "client_port": forward[2]},
                      opens={"collector": opens[forward], "producer": opens[reverse]},
                      mp_reach_next_hops=next_hops)
    return result


PROBE_PREFIXES = {"edge-frr": "2001:db8:6501:ffff::5/128", "edge-ceos": "2001:db8:6501:ffff::6/128"}


def configured_ipv6_prefixes(text):
    """Read explicit interface addresses, not route or neighbor commands."""
    return {str(ipaddress.IPv6Interface(value))
            for value in re.findall(r"^\s+ipv6 address (\S+)", text, re.MULTILINE)}


class PrefixProbe:
    def __init__(self, lab, node, identity):
        if node not in PROBE_PREFIXES:
            raise ValueError("unknown probe router")
        self.lab = lab
        self.node = node
        self.prefix = PROBE_PREFIXES[node]
        self.value = f"prefix {self.prefix} node {identity}"
        self.changed = False

    def preflight(self):
        if self.lab.probe_present(self.node, self.prefix):
            raise AssertionError(f"reserved probe prefix already exists on {self.node}; refusing to change it")

    def add(self):
        #  A command can take effect before its response fails. Own the
        # temporary address before issuing it so outer cleanup always removes it.
        self.changed = True
        self.lab.set_probe(self.node, self.prefix, True)

    def restore(self):
        if self.changed:
            self.lab.set_probe(self.node, self.prefix, False)
            if self.lab.probe_present(self.node, self.prefix):
                raise AssertionError(f"probe address remains configured on {self.node}")
            self.changed = False


def exercise_prefix_probe(probe, wait, tables, baseline, capture):
    """Verify announcement, withdrawal, and reannouncement without dropping BGP."""
    probe.preflight()
    expanded = baseline | {probe.value}
    for phase, expected in (("add", expanded), ("withdraw", baseline),
                            ("readd", expanded), ("restore", baseline)):
        if phase in ("add", "readd"):
            probe.add()
        else:
            probe.restore()
        wait(f"{probe.node} IPv6 prefix {phase} reaches every native and collector RIB",
             lambda: all(table == expected for table in tables()))
        capture(f"probe-{probe.node}-{phase}")


class Lab:
    def __init__(self, state, output, transport="ipv4"):
        self.state = state
        self.output = output
        self.transport = transport
        self.ids = {}
        self.state_info = None
        self.prefix = []
        if platform.system() == "Darwin":
            self.prefix = ["orb", "-m", os.environ.get("CLAB_MACHINE", "clab"), "-u", "root"]

    def command(self, *args, timeout=20, combine_output=False):
        result = subprocess.run(self.prefix + list(args), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT if combine_output else subprocess.PIPE,
                                text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"{' '.join(args)} failed: {(result.stderr or '').strip()} {result.stdout.strip()}")
        return result.stdout

    def docker(self, *args, timeout=20, combine_output=False):
        return self.command("docker", *args, timeout=timeout, combine_output=combine_output)

    def container_id(self, node):
        return self.ids[node]

    def vty(self, node, command):
        if node not in ROUTERS:
            raise ValueError("unknown lab router")
        return json.loads(self.docker("exec", self.ids.get(node, f"clab-bgpls-{node}"), "vtysh", "-c", command))

    def save(self, name, value):
        #  A failed write must not leave a valid-looking success result
        # or replace earlier evidence with a partial JSON document.
        data = json.dumps(value, indent=2) + "\n"
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.output,
                                             prefix=f".{name}-", suffix=".json", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(data)
            temporary.replace(self.output / f"{name}.json")
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass  # Preserve the original evidence-write error.

    def neighbor(self, transport=None):
        source = TRANSPORTS["frr"][transport or self.transport]["source"]
        return self.vty("edge-frr", f"show bgp neighbors {source} json")[source]

    def producer_neighbor(self, producer, transport=None):
        if producer != "frr":
            raise ValueError("unknown producer")
        return self.neighbor(transport)

    def native_table(self, producer="frr"):
        if producer != "frr":
            raise ValueError("unknown producer")
        return self.vty("edge-frr", "show bgp link-state link-state json")

    def relay_ip_json(self, *args):
        relay = self.container_id("bgpls-relay")
        if not isinstance(relay, str) or not re.fullmatch(r"[0-9a-f]{64}", relay):
            raise AssertionError("relay namespace inspection requires its immutable container ID")

        def identity():
            inspected = json.loads(self.docker("inspect", relay))
            if not isinstance(inspected, list) or len(inspected) != 1:
                raise AssertionError("relay namespace inspection requires exactly one container")
            inspected = inspected[0]
            state = inspected["State"]
            labels = inspected["Config"]["Labels"]
            pid = state["Pid"]
            started = state["StartedAt"]
            if (inspected["Id"] != relay or state["Running"] is not True
                    or type(pid) is not int or pid <= 0
                    or not isinstance(started, str) or not started
                    or labels.get("containerlab") != "bgpls"
                    or labels.get("clab-topo-file") != str(self.state / "bgpls.clab.yml")):
                raise AssertionError("relay namespace identity, running state, or ownership changed")
            return {"container_id": relay, "pid": pid, "started_at": started}

        #  The pinned relay has BusyBox ip, which cannot produce JSON.
        # Enter only its network namespace with host iproute2; no image changes,
        # added container privileges, or mounting of the Docker socket is needed.
        before = identity()
        self.save("relay-network-namespace", before)
        try:
            output = self.command("nsenter", "--target", str(before["pid"]), "--net", "--",
                                  "ip", "-j", "-6", *args)
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("read-only relay namespace inspection requires host iproute2 JSON support, "
                               "util-linux nsenter, and permission to enter the network namespace: "
                               + str(error)) from error
        if identity() != before:
            raise AssertionError("relay restarted during network namespace inspection")
        try:
            result = json.loads(output)
        except json.JSONDecodeError as error:
            raise AssertionError("host iproute2 did not return valid JSON for relay namespace inspection") from error
        if not isinstance(result, list):
            raise AssertionError("host iproute2 returned an unexpected JSON schema")
        return result

    def transport_preflight(self, producers):
        #  Even an IPv4 regression run in an IPv6-enabled deployment must not race
        # an IPv6 collector. Inspect both configured neighbors before launching.
        families = ("ipv4", "ipv6") if self.state_info["transport"] == "ipv6" else ("ipv4",)
        for producer in producers:
            for family in families:
                neighbor = self.producer_neighbor(producer, family)
                state = neighbor["bgpState"]
                if state not in ("Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established"):
                    raise AssertionError("unrecognized BGP neighbor state")
                if state in ("OpenSent", "OpenConfirm", "Established"):
                    raise AssertionError(f"a {producer} {family} collector is already connected; stop it before verification")
        helper("lab-state").assert_no_namespace_holders(self.state, lambda argv: self.docker(*argv))
        if self.transport != "ipv6":
            return
        for producer in producers:
            endpoint = TRANSPORTS[producer]["ipv6"]
            addresses = self.relay_ip_json("address", "show", "dev", endpoint["interface"])
            self.save(f"{producer}-relay-addresses", addresses)
            matching = [address for interface in addresses for address in interface["addr_info"]
                        if address["family"] == "inet6" and address["local"] == endpoint["source"]]
            if (len(matching) != 1 or matching[0]["prefixlen"] != 127
                    or matching[0]["scope"] != "global"
                    or {"tentative", "dadfailed", "deprecated"} & set(matching[0].get("flags", []))
                    or any(matching[0].get(flag, False) for flag in ("tentative", "dadfailed", "deprecated"))):
                raise AssertionError(f"{producer} relay IPv6 source is absent, tentative, or invalid")
            routes = self.relay_ip_json("route", "get", endpoint["peer"], "from", endpoint["source"])
            self.save(f"{producer}-relay-source-route", routes)
            if (len(routes) != 1 or routes[0]["dev"] != endpoint["interface"]
                    or routes[0].get("gateway")
                    or routes[0].get("from", routes[0].get("src", routes[0].get("prefsrc"))) != endpoint["source"]):
                raise AssertionError(f"{producer} IPv6 source route does not use its dedicated relay interface")

    def ownership_preflight(self, profile):
        self.state_info = helper("lab-state").read_state(self.state)
        if self.state_info["profile"] != profile:
            raise AssertionError(f"expected this directory's unchanged {profile} profile ownership marker")
        if self.transport == "ipv6" and self.state_info["transport"] != "ipv6":
            raise AssertionError("IPv6 verification requires an IPv6-enabled deployment")
        engine = json.loads(self.docker("info", "--format", "{{json .}}"))
        if engine.get("ID") != self.state_info["daemon_id"]:
            raise AssertionError("state belongs to a different Docker daemon")
        if engine.get("OSType") != "linux" or engine.get("Architecture") not in ("arm64", "aarch64"):
            raise AssertionError("this qualification requires a native ARM64 Linux Docker host")
        self.save("engine", {key: engine.get(key) for key in (
            "ID", "Architecture", "OSType", "OperatingSystem", "KernelVersion", "ServerVersion",
        )})
        return engine

    def native_objects(self):
        table = self.vty("edge-frr", "show bgp link-state link-state json")
        self.save("frr-link-state-latest", table)
        try:
            return native_objects(table)
        except NativeSelectionPending:
            # Retain the last transient candidate even if the next poll converges.
            self.save("frr-link-state-selection-pending", table)
            raise

    def probe_config(self, node):
        if node != "edge-frr":
            raise ValueError("unknown FRR probe router")
        return self.docker("exec", self.ids.get("edge-frr", "clab-bgpls-edge-frr"), "vtysh", "-c", "show running-config")

    def probe_present(self, node, prefix):
        return prefix in configured_ipv6_prefixes(self.probe_config(node))

    def set_probe(self, node, prefix, present):
        if node != "edge-frr" or prefix != PROBE_PREFIXES[node]:
            raise ValueError("only the reserved FRR loopback probe may be changed")
        command = ("" if present else "no ") + "ipv6 address " + prefix
        output = self.docker("exec", self.ids.get("edge-frr", "clab-bgpls-edge-frr"), "vtysh", "-c", "configure terminal",
                             "-c", "interface lo", "-c", command, "-c", "end")
        # vtysh/Cli can report configuration errors in stdout even on exit zero.
        #  FRR 10.7.1 mgmtd emits this exact informational commit note
        # for an already-applied command. Accept it only with the state check
        # below; other percent-prefixed diagnostics remain failures.
        diagnostic = output.replace("\r\n", "\n").replace(
            "% Configuration applied with notes:\nNo changes found to be committed!", ""
        )
        if re.search(r"(?im)^\s*%|unknown command|invalid input|incomplete command", diagnostic):
            raise RuntimeError(f"FRR probe configuration failed: {output.strip()}")
        if self.probe_present(node, prefix) != present:
            raise AssertionError("FRR did not apply the requested temporary prefix state")

    def link(self, state):
        #  Touch only this lab's p1-p2 pair, never management or relay links.
        failures = []
        for node in ("p1", "p2"):
            try:
                self.docker("exec", self.ids.get(node, f"clab-bgpls-{node}"), "ip", "link", "set", "eth3", state)
            except (RuntimeError, OSError, subprocess.SubprocessError) as error:
                failures.append(f"{node}: {error}")
        if failures:
            raise RuntimeError("link operation incomplete: " + "; ".join(failures))

    def verify_routing(self):
        for node in ROUTERS:
            adjacency = self.vty(node, "show isis neighbor json")
            self.save(f"isis-{node}", adjacency)
            actual = {circuit.get("adj") for area in adjacency["areas"]
                      for circuit in area.get("circuits", []) if circuit.get("state") == "Up"}
            expected = {right if left == node else left for left, right, _, _ in ADJACENCIES
                        if node in (left, right)}
            if actual != expected:
                return False
            routes6 = self.vty(node, "show ipv6 route isis json")
            self.save(f"isis-ipv6-{node}", routes6)
            if not frr_ipv6_routes_ready(routes6, node):
                return False
            self.save(f"unicast-{node}", self.vty(node, "show bgp ipv4 unicast json"))
        for node, originator in (("p1", "10.255.0.5"), ("p2", "10.255.0.3"), ("edge-frr", "10.255.0.4")):
            # Service prefixes differ from their IS-IS next-hop loopbacks.
            service = "192.0.2." + originator.rsplit(".", 1)[1]
            route = self.vty(node, f"show bgp ipv4 unicast {service}/32 json")
            self.save(f"reflected-{node}", route)
            if not reflected_by_both(route, originator):
                return False
        return True

    def preflight(self):
        self.ownership_preflight("frr")
        for node in (*ROUTERS, "bgpls-relay"):
            inspected = json.loads(self.docker("inspect", f"clab-bgpls-{node}"))[0]
            labels = inspected["Config"]["Labels"]
            if labels.get("containerlab") != "bgpls" or not inspected["State"]["Running"]:
                raise AssertionError(f"{node} is not a running member of this lab")
            if labels.get("clab-topo-file") != str(self.state / "bgpls.clab.yml"):
                raise AssertionError(f"{node} belongs to a different deployment directory")
            if node == "bgpls-relay":
                binding = inspected["HostConfig"]["PortBindings"]
                if binding != {"11790/tcp": [{"HostIp": "127.0.0.1", "HostPort": "11790"}]}:
                    raise AssertionError("relay must publish only 127.0.0.1:11790")
            self.ids[node] = inspected["Id"]
            self.save(f"container-{node}", {
                "id": inspected["Id"], "image": inspected["Config"]["Image"],
                "image_id": inspected["Image"], "labels": labels,
                "architecture": json.loads(self.docker("image", "inspect", inspected["Image"]))[0]["Architecture"],
            })
        self.transport_preflight(("frr",))


def wait_until(description, condition, process=None, timeout=90):
    deadline = time.monotonic() + timeout
    pending = None
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise AssertionError(f"collector exited {process.returncode} while waiting for {description}")
        try:
            if condition():
                print(f"PASS: {description}", flush=True)
                return
        except NativeSelectionPending as error:
            #  Retry only the observed no-best-path convergence state;
            # all schema, identity, origin, and duplicate-path failures remain fatal.
            pending = str(error)
        time.sleep(0.5)
    detail = f"; last native selection state: {pending}" if pending else ""
    raise TimeoutError(f"timed out waiting for {description}{detail}")


def run(args):
    state = Path(args.state).resolve(strict=True)
    transport, binary, artifact = collector_inputs(args)
    #  A single deployment lock covers preflight, both transport modes,
    # temporary mutations, and all cleanup. A stale lock is never auto-broken.
    with verification_lock(state):
        return run_locked(args, state, transport, binary, artifact)


def cleanup(lab, link_changed, process, transport, probes=(), attribute_run=None):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    actions = [(f"restore {probe.node} probe", probe.restore) for probe in probes]
    if attribute_run is not None:
        actions.insert(0, ("restore metric probes", attribute_run.restore))
    if link_changed:
        actions.append(("restore p1-p2", lambda: lab.link("up")))
    if process is not None:
        def reap():
            if transport == "ipv6":
                process.cleanup()
            elif process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        actions.append(("reap collector", reap))
    run_cleanup(actions)


def run_locked(args, state, transport, binary, artifact):
    output = Path(tempfile.mkdtemp(prefix="verification-", dir=state))
    print(f"Evidence: {output}", flush=True)
    provenance = (helper("attribute-validation").collector_provenance(binary, artifact, output)
                  if getattr(args, "attributes", False) else None)
    lab = Lab(state, output, transport)
    lab.preflight()
    log_path = output / "collector.log"
    pcap_path = output / "collector.pcap"
    process = None
    link_changed = False
    probes = []
    attributes = getattr(args, "attributes", False)
    attribute_run = None
    def objects(text):
        return watch_state(text, attributes=attributes)
    with verification_cleanup(lab, transport,
                              lambda: cleanup(lab, link_changed, process, transport, probes, attribute_run)):
        required = expected_links() | {f"node {value}" for value in IDS.values()} | expected_loopbacks()
        wait_until("routing is ready before starting the collector", lab.verify_routing)
        wait_until("native FRR BGP-LS baseline is ready before starting the collector",
                   lambda: lab.native_objects() == required)
        with (nullcontext() if transport == "ipv6" else log_path.open("w")) as log:
            if transport == "ipv6":
                process = helper("container-collector").ContainerProcess(
                    lab, "frr", artifact, output, log_path, pcap_path,
                    **({"show_attributes": True} if attributes else {}))
                process.start()
            else:
                process = subprocess.Popen([
                    str(binary), "run", "--peer", "127.0.0.1", "--port", "11790",
                    "--local-as", str(lab.state_info["asn"]), "--peer-as", str(lab.state_info["asn"]),
                    "--local-address", "127.0.0.1",
                    "--bgp-identifier", "192.0.2.101",
                    "--hold-time", "9", "--watch", "--dump-rib", "--log-updates", "--pcap", str(pcap_path),
                ] + (["--show-attributes"] if attributes else []), stdout=log, stderr=subprocess.STDOUT)
            def read_log():
                if transport == "ipv6":
                    process.refresh()
                return log_path.read_text()
            expected = expected_links()
            expected_nodes = {f"node {value}" for value in IDS.values()}
            prefixes = expected_loopbacks()
            required = expected | expected_nodes | prefixes
            wait_until("five identities, fourteen dual-stack links, and ten loopback prefixes",
                       lambda: required <= objects(read_log()), process)
            wait_until("at least three keepalive intervals in each direction",
                       lambda: lab.neighbor().get("messageStats", {}).get("keepalivesRecv", 0) >= 5
                       and lab.neighbor().get("messageStats", {}).get("keepalivesSent", 0) >= 5
                       and lab.neighbor().get("bgpTimerUpMsec", 0) >= 12_000, process)
            baseline = objects(read_log())
            if {item for item in baseline if item.startswith("node ")} != expected_nodes:
                raise AssertionError("unexpected or missing node identities")
            if {item for item in baseline if item.startswith("link ")} != expected:
                raise AssertionError("unexpected or missing directed links")
            if {item for item in baseline if item.startswith("prefix ")} != prefixes:
                raise AssertionError("expected exactly five passive loopbacks in each address family")
            if any("10.254.254." in item or "?" in item for item in baseline):
                raise AssertionError("relay prefix leaked into IS-IS or an identity is missing")
            neighbor_before = lab.neighbor()
            assert_neighbor_endpoint(neighbor_before, "frr", transport, lab.state_info["asn"])
            lab.save("neighbor-before", neighbor_before)
            wait_until("native FRR table matches the collector RIB",
                       lambda: lab.native_objects() == objects(read_log()), process)
            lab.save("link-state-before", lab.vty("edge-frr", "show bgp link-state link-state json"))
            wait_until("all IS-IS adjacencies and both route reflectors on every client",
                       lab.verify_routing, process)
            if attributes:
                attribute_run = helper("attribute-validation").AttributeRun(lab, {"frr": read_log}, profile="frr")
                wait_until("FRR typed native and collector baseline", attribute_run.ready, process)
                attribute_run.capture("baseline")
                if getattr(args, "attribute_probes", False):
                    attribute_run.exercise(lambda description, condition: wait_until(description, condition, process))
            if args.churn:
                # Latch before either command so even a partial failure restores both endpoints.
                link_changed = True
                lab.link("down")
                removed = core_link_objects(baseline)
                wait_until("both p1-p2 directed links withdrawn",
                           lambda: objects(read_log()) == baseline - removed, process)
                wait_until("native FRR withdrawal preserves every other link and both prefix families",
                           lambda: lab.native_objects() == baseline - removed, process)
                lab.save("link-state-down", lab.vty("edge-frr", "show bgp link-state link-state json"))
                lab.link("up")
                link_changed = False
                wait_until("original RIB restored after link recovery",
                           lambda: objects(read_log()) == baseline, process)
                wait_until("native FRR table restored after link recovery",
                           lambda: lab.native_objects() == baseline, process)
                probe = PrefixProbe(lab, "edge-frr", IDS["edge-frr"])
                probes.append(probe)
                exercise_prefix_probe(
                    probe, lambda description, condition: wait_until(description, condition, process),
                    lambda: [objects(read_log()), lab.native_objects()], baseline,
                    lambda phase: lab.save(phase, lab.vty("edge-frr", "show bgp link-state link-state json")),
                )
                wait_until("all IPv6 routes and IS-IS adjacencies restored after churn", lab.verify_routing, process)
            if attribute_run is not None:
                wait_until("FRR full typed baseline restored", attribute_run.ready, process)
                attribute_run.capture("restored")
            neighbor_after = lab.neighbor()
            lab.save("neighbor-after", neighbor_after)
            lab.save("link-state-after", lab.vty("edge-frr", "show bgp link-state link-state json"))
            if not same_bgp_connection(neighbor_before, neighbor_after):
                raise AssertionError("BGP-LS socket, counters, or uptime changed during verification")
            selected_signal = signal.SIGINT if args.signal == "INT" else signal.SIGTERM
            process.send_signal(selected_signal)
            status = process.wait(timeout=15)
        text = read_log()
        expected_status = 128 + selected_signal
        if status != expected_status:
            raise AssertionError(f"exit status {status}, expected {expected_status}")
        if text.count(" RIB final\n") != 1 or text.count("— stopping session…") != 1:
            raise AssertionError("expected exactly one stopping message and final RIB")
        if text.count("state Established") != 1:
            raise AssertionError("expected exactly one BGP establishment")
        if re.search(r"parse error|failed|invalid|pcap .*error", text, re.IGNORECASE):
            raise AssertionError("collector reported an error; inspect collector.log")
        final_lines = text.split(" RIB final\n", 1)[1].splitlines()
        expected_summary = rib_summary(baseline)
        if not final_lines or final_lines[0] != expected_summary:
            raise AssertionError("final RIB count differs from the drained watch stream")
        final = final_objects(final_lines[1:], attributes=attributes)
        if final != baseline:
            raise AssertionError("final RIB contents differ from the drained watch stream")
        summary = {
            "passed": True, "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "transport": transport, "asn": lab.state_info["asn"],
            "collector_binary": str(binary) if binary else None,
            "collector_artifact": str(artifact) if artifact else None,
            "exit_status": status, "churn": args.churn,
            "rib": expected_summary,
            "pcap": validate_pcap(pcap_path, capture_expectation("frr", transport, lab.state_info["asn"])),
            #  WATCH text is presentation, not complete NLRI identity.
            # Independently replay the completed capture before claiming success.
            "wire_topology": WIRE.audit_capture(
                pcap_path, baseline, churn_objects=core_link_objects(baseline) if args.churn else (),
                probe_objects=[probe.value for probe in probes],
            ),
            "scope": "five-FRR baseline; no second vendor or concurrent-producer claim",
        }
        if attribute_run is not None:
            summary["typed_attributes"] = helper("attribute-validation").audit(
                pcap_path, text, attribute_run.native("frr"), output / "attributes-frr", profile="frr",
                probes=attribute_run.probe_results)
    summary["container"] = process.metadata if transport == "ipv6" else None
    if provenance is not None:
        try:
            helper("attribute-validation").verify_collector_provenance(provenance)
        except Exception as error:
            record_failure(lab, transport, error)
            raise
        summary["collector_provenance"] = provenance
    publish_result(lab, transport, summary)
    print(f"PASS: {expected_summary}; SIG{args.signal} -> {status}; one final RIB", flush=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    add_transport_arguments(parser)
    parser.add_argument("--churn", action="store_true",
                        help="flap p1-p2 and add/withdraw/re-add a temporary IPv6 loopback prefix")
    parser.add_argument("--signal", choices=("INT", "TERM"), default="INT")
    options = parser.parse_args()
    install_signal_handlers()
    try:
        sys.exit(run(options))
    except VerificationInterrupted as error:
        print(f"STOPPED: {error}", file=sys.stderr)
        sys.exit(128 + error.signum)
    except (AssertionError, ValueError, RuntimeError, TimeoutError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
