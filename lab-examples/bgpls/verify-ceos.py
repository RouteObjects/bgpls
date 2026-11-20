#!/usr/bin/env python3
"""Bounded concurrent FRR/cEOS checks; use only the explicitly deployed cEOS profile."""

import argparse
import datetime
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile


SPEC = importlib.util.spec_from_file_location("bgpls_frr_verify", Path(__file__).with_name("verify.py"))
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)

ROUTERS = (*BASE.ROUTERS, "edge-ceos")
IDS = {**BASE.IDS, "edge-ceos": "0000.0000.0006"}
ADJACENCIES = (*BASE.ADJACENCIES,
               ("p1", "edge-ceos", "10.254.0.14", "10.254.0.15"),
               ("p2", "edge-ceos", "10.254.0.16", "10.254.0.17"))
PORTS = {"frr": 11790, "ceos": 11791}
REMOVED = BASE.core_link_objects(BASE.expected_links(ADJACENCIES, IDS))


def expected_objects():
    objects = {f"node {identity}" for identity in IDS.values()}
    objects |= BASE.expected_loopbacks(ROUTERS, IDS)
    objects |= BASE.expected_links(ADJACENCIES, IDS)
    return objects


def validate_state(state):
    try:
        record = BASE.helper("lab-state").read_state(state)
    except ValueError as error:
        raise AssertionError(str(error)) from error
    if record["profile"] != "ceos":
        raise AssertionError("expected this directory's unchanged cEOS profile ownership marker")
    return record["daemon_id"]


def native_ceos_objects(table, asn=65001):
    """Normalize cEOS 4.36.2F CLI fields; do not parse opaque route-map keys."""
    def identity(descriptor):
        value = descriptor["isisSystemId"]
        if (descriptor["igpRouterIdType"] != "isisSystemId"
                or not re.fullmatch(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", value)):
            raise AssertionError("expected a cEOS IS-IS System ID, not a pseudonode")
        if descriptor.get("asn") != str(asn):
            raise AssertionError("unexpected cEOS BGP-LS descriptor AS")
        return value

    objects = set()
    for route in table["vrfs"]["default"]["bgpLsRoutes"].values():
        if route["protocolId"] != "isisLevel2" or route["identifier"] != 0:
            raise AssertionError("unexpected cEOS IGP protocol or instance")
        best = [path for path in route["paths"]
                if path["routeType"].get("valid") and path["routeType"].get("active")]
        if len(best) != 1:
            raise AssertionError("expected exactly one valid active cEOS path")
        #  A matching reflected FRR advertisement is not evidence of a
        # second producer. The selected EOS path must be originated locally.
        if (best[0]["peerEntry"]["peerAddr"] != ""
                or best[0]["asPathEntry"]["asPathType"] != "Local"):
            raise AssertionError("cEOS BGP-LS path was received, not independently originated")
        local = identity(route["localNodeDescriptor"])
        if route["nlriType"] == "node":
            value = f"node {local}"
        elif route["nlriType"] == "link":
            remote = identity(route["remoteNodeDescriptor"])
            descriptor = route["linkDescriptor"]
            addresses = [descriptor[key] for key in
                         ("localIpv4Addrs", "localIpv6Addrs", "remoteIpv4Addrs", "remoteIpv6Addrs")]
            if any(len(values) > 1 for values in addresses):
                raise AssertionError("unqualified multiple same-family cEOS link addresses")
            local_address = BASE.endpoint_addresses(*(values[0] if values else None for values in addresses[:2]))
            remote_address = BASE.endpoint_addresses(*(values[0] if values else None for values in addresses[2:]))
            value = f"link {local} {local_address} → {remote} {remote_address}"
        elif route["nlriType"] in ("ipv4Prefix", "ipv6Prefix"):
            family = ipaddress.IPv4Network if route["nlriType"] == "ipv4Prefix" else ipaddress.IPv6Network
            prefix = str(family(route["prefixDescriptor"]["prefix"]))
            value = f"prefix {prefix} node {local}"
        else:
            raise AssertionError(f"unqualified cEOS NLRI presentation: {route['nlriType']}")
        if value in objects:
            raise AssertionError("cEOS NLRI identities collide in topology comparison")
        objects.add(value)
    return objects


def ceos_adjacencies_ready(table):
    neighbors = table["vrfs"]["default"]["isisInstances"]["CORE"]["neighbors"]
    actual = {(identity, adjacency["interfaceName"], adjacency["hostname"])
              for identity, neighbor in neighbors.items() for adjacency in neighbor["adjacencies"]
              if adjacency["state"] == "up" and adjacency["level"] == "level-2"}
    return actual == {("0000.0000.0003", "Ethernet1", "p1"), ("0000.0000.0004", "Ethernet2", "p2")}


def ceos_ipv6_routes_ready(table):
    """Check the qualified EOS 4.36.2F IPv6 IS-IS forwarding-table schema."""
    vrf = table["vrfs"]["default"]
    routes = vrf["routes"]
    expected = {f"2001:db8:6501::{index}/128" for index in range(1, 6)}
    if (vrf["routingDisabled"] or not vrf["allRoutesProgrammedHardware"]
            or not vrf["allRoutesProgrammedKernel"] or set(routes) != expected):
        return False
    for route in routes.values():
        if (route["routeType"] != "isisL2" or route["routeAction"] != "forward"
                or not route["hardwareProgrammed"] or not route["kernelProgrammed"]
                or route["directlyConnected"] or route["routeLeaked"]):
            return False
        if not any(via["interface"] in ("Ethernet1", "Ethernet2")
                   and isinstance(ipaddress.ip_address(via["nexthopAddr"]), ipaddress.IPv6Address)
                   for via in route["vias"]):
            return False
    return True


def ceos_reflected_by_both(table):
    routes = table["vrfs"]["default"]["bgpRouteEntries"]
    paths = routes.get("192.0.2.5/32", {}).get("bgpRoutePaths", [])
    normalized = {"paths": [{
        "valid": path["routeType"].get("valid"),
        "originatorId": path.get("routeDetail", {}).get("originator"),
        "peer": {"routerId": path.get("peerEntry", {}).get("peerRouterId")},
        "clusterList": {"list": path.get("routeDetail", {}).get("clusterList", "").split()},
    } for path in paths]}
    return BASE.reflected_by_both(normalized, "10.255.0.5")


def ceos_neighbor(table, source="10.254.254.3", asn=65001):
    """Normalize the actual cEOS BGP neighbor schema, not an assumed FRR schema."""
    peers = table["vrfs"]["default"]["peerList"]
    matching = [peer for peer in peers if peer["peerAddress"] == source]
    if len(matching) != 1:
        raise AssertionError("expected exactly the configured cEOS relay neighbor")
    peer = matching[0]
    if peer["state"] != "Established":
        return {"bgpState": peer["state"]}
    if (peer["asn"] != str(asn) or peer["localAsn"] != str(asn)
            or peer["holdTime"] != 9 or peer["keepaliveTime"] != 3
            or not peer["neighborCapabilities"]["multiprotocolCaps"]["linkState"]["enabled"]
            or peer["linkStateReceived"] != 0):
        raise AssertionError("unexpected cEOS BGP-LS session capability, AS, timers, or imported routes")
    return {
        "bgpState": peer["state"], "connectionsEstablished": peer["establishedTransitions"],
        "localAs": int(peer["localAsn"]), "remoteAs": int(peer["asn"]),
        "hostForeign": peer["peerAddress"], "portForeign": peer["remotePort"],
        "hostLocal": peer["updateSource"], "portLocal": peer["localPort"],
        "bgpTimerUpMsec": peer["establishedTime"] * 1000,
        "messageStats": {"keepalivesSent": peer["outMessageStats"]["keepalives"],
                         "keepalivesRecv": peer["inMessageStats"]["keepalives"]},
    }


def same_connection(producer, before, after):
    if producer == "frr":
        return BASE.same_bgp_connection(before, after)
    if producer != "ceos":
        raise ValueError("unknown producer")
    # EOS exposes establishment transitions, not FRR's separate drop counter.
    # Compare only observed EOS fields rather than inventing missing counters.
    stable = ("connectionsEstablished", "hostForeign", "portForeign", "hostLocal", "portLocal")
    return (after["bgpState"] == "Established"
            and all(before[field] == after[field] for field in stable)
            and after["bgpTimerUpMsec"] >= before["bgpTimerUpMsec"]
            and all(after["messageStats"][field] >= before["messageStats"][field]
                    for field in ("keepalivesSent", "keepalivesRecv")))


def ready_neighbor(neighbor):
    return (neighbor.get("bgpState") == "Established"
            and neighbor.get("bgpTimerUpMsec", 0) >= 12_000
            and all(neighbor.get("messageStats", {}).get(field, 0) >= 5
                    for field in ("keepalivesSent", "keepalivesRecv")))


class Collector:
    def __init__(self, producer, binary, output, *, lab, artifact=None, transport="ipv4", attributes=False):
        if producer not in PORTS:
            raise ValueError("unknown producer")
        self.producer = producer
        self.binary = binary
        self.lab = lab
        #  The owned deployment marker is the sole ASN authority; a
        # verifier-side override could otherwise qualify the wrong lab profile.
        self.asn = lab.state_info["asn"]
        self.artifact = artifact
        self.transport = transport
        self.attributes = attributes
        self.output = output
        self.log_path = output / f"collector-{producer}.log"
        self.pcap_path = output / f"collector-{producer}.pcap"
        self.process = None

    def start(self):
        if self.process is not None:
            raise RuntimeError("collector was already started")
        if self.transport == "ipv6":
            self.process = BASE.helper("container-collector").ContainerProcess(
                self.lab, self.producer, self.artifact, self.output, self.log_path, self.pcap_path,
                **({"show_attributes": True} if self.attributes else {}))
            self.process.start()
            return
        with self.log_path.open("w") as log:
            self.process = subprocess.Popen([
                str(self.binary), "run", "--peer", "127.0.0.1", "--port", str(PORTS[self.producer]),
                "--local-as", str(self.asn), "--peer-as", str(self.asn), "--local-address", "127.0.0.1",
                "--bgp-identifier", "192.0.2.101" if self.producer == "frr" else "192.0.2.102",
                "--hold-time", "9", "--watch", "--dump-rib", "--log-updates", "--pcap", str(self.pcap_path),
            ] + (["--show-attributes"] if self.attributes else []), stdout=log, stderr=subprocess.STDOUT)

    def read(self):
        if self.transport == "ipv6" and self.process is not None:
            self.process.refresh()
        return self.log_path.read_text()

    def objects(self):
        return BASE.watch_state(self.read(), attributes=self.attributes)

    def ensure_running(self):
        if self.process is None:
            raise AssertionError(f"{self.producer} collector was not started")
        status = self.process.poll()
        if status is not None:
            raise AssertionError(f"{self.producer} collector exited {status} unexpectedly")

    def stop(self, selected_signal, baseline, *, churn_objects=(), probe_objects=()):
        self.ensure_running()
        self.process.send_signal(selected_signal)
        status = self.process.wait(timeout=15)
        if status != 128 + selected_signal:
            raise AssertionError(f"{self.producer} exit status {status}, expected {128 + selected_signal}")
        text = self.read()
        if text.count(" RIB final\n") != 1 or text.count("— stopping session…") != 1:
            raise AssertionError(f"{self.producer}: expected exactly one stopping message and final RIB")
        if text.count("state Established") != 1:
            raise AssertionError(f"{self.producer}: expected exactly one BGP establishment")
        if re.search(r"parse error|failed|invalid|pcap .*error", text, re.IGNORECASE):
            raise AssertionError(f"{self.producer} collector reported an error")
        final_lines = text.split(" RIB final\n", 1)[1].splitlines()
        if not final_lines or final_lines[0] != BASE.rib_summary(baseline):
            raise AssertionError(f"{self.producer}: incorrect final RIB summary")
        final_objects = BASE.final_objects(final_lines[1:], attributes=self.attributes)
        if final_objects != baseline or self.objects() != baseline:
            raise AssertionError(f"{self.producer}: final RIB differs from the drained watch stream or baseline")
        return {"exit_status": status, "asn": self.asn, "rib": final_lines[0],
                "pcap": BASE.validate_pcap(self.pcap_path,
                                           BASE.capture_expectation(self.producer, self.transport, self.asn)),
                "wire_topology": BASE.WIRE.audit_capture(
                    self.pcap_path, baseline, churn_objects=churn_objects, probe_objects=probe_objects,
                )}

    def cleanup(self):
        if self.process is None:
            return
        if self.transport == "ipv6":
            self.process.cleanup()
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def wait_for(description, condition, collectors, timeout=90):
    def checked():
        for collector in collectors:
            collector.ensure_running()
        return condition()
    BASE.wait_until(description, checked, timeout=timeout)


def verify_independent_survivor(lab, collector, before, baseline, survivor="ceos", stopped="frr"):
    #  Progress during FRR cleanup is not proof of traffic after it exits.
    # Take a fresh counter baseline only after stop() has reaped the FRR child.
    after_stop = lab.producer_neighbor(survivor)
    if not same_connection(survivor, before, after_stop):
        raise AssertionError(f"{survivor} BGP session changed while stopping the {stopped} collector")
    lab.save(f"{survivor}-neighbor-immediately-after-{stopped}-shutdown", after_stop)

    def progressed():
        current = lab.producer_neighbor(survivor)
        return (same_connection(survivor, after_stop, current)
                and all(current["messageStats"][field] > after_stop["messageStats"][field]
                        for field in ("keepalivesSent", "keepalivesRecv"))
                and collector.objects() == baseline
                and lab.native_objects(survivor) == baseline)

    wait_for(f"{survivor} collector remains independent after {stopped} collector shutdown", progressed, [collector])
    lab.save(f"{survivor}-neighbor-after-{stopped}-shutdown", lab.producer_neighbor(survivor))


def cleanup(lab, link_changed, collectors, probes=(), attribute_run=None):
    #  Every resource owns an independent cleanup attempt; one failure
    # cannot leave the other collector running or interrupt link restoration.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    actions = [(f"restore {probe.node} probe", probe.restore) for probe in probes]
    if attribute_run is not None:
        actions.insert(0, ("restore metric probes", attribute_run.restore))
    if link_changed:
        actions.append(("restore p1-p2", lambda: lab.link("up")))
    actions.extend((f"reap {collector.producer}", collector.cleanup) for collector in collectors)
    BASE.run_cleanup(actions)


class CeosLab(BASE.Lab):
    def eos(self, command):
        return json.loads(self.docker("exec", self.ids.get("edge-ceos", "clab-bgpls-edge-ceos"),
                                      "Cli", "-p", "15", "-c", command + " | json"))

    def probe_config(self, node):
        if node == "edge-frr":
            return super().probe_config(node)
        if node != "edge-ceos":
            raise ValueError("unknown probe router")
        return self.docker("exec", self.ids.get("edge-ceos", "clab-bgpls-edge-ceos"),
                           "Cli", "-p", "15", "-c", "show running-config")

    def set_probe(self, node, prefix, present):
        if node == "edge-frr":
            return super().set_probe(node, prefix, present)
        if node != "edge-ceos" or prefix != BASE.PROBE_PREFIXES[node]:
            raise ValueError("only the reserved cEOS loopback probe may be changed")
        command = ("" if present else "no ") + "ipv6 address " + prefix
        output = self.docker("exec", self.ids.get("edge-ceos", "clab-bgpls-edge-ceos"), "Cli", "-p", "15", "-c",
                             "configure terminal\ninterface Loopback0\n" + command + "\nend")
        if re.search(r"(?im)^\s*%|unknown command|invalid input|incomplete command", output):
            raise RuntimeError(f"cEOS probe configuration failed: {output.strip()}")
        if self.probe_present(node, prefix) != present:
            raise AssertionError("cEOS did not apply the requested temporary prefix state")

    def producer_neighbor(self, producer, transport=None):
        if producer == "frr":
            return self.neighbor(transport)
        if producer == "ceos":
            source = BASE.TRANSPORTS[producer][transport or self.transport]["source"]
            return ceos_neighbor(self.eos(f"show bgp neighbors {source}"), source, self.state_info["asn"])
        raise ValueError("unknown producer")

    def native_table(self, producer):
        if producer == "frr":
            return self.vty("edge-frr", "show bgp link-state link-state json")
        if producer == "ceos":
            return self.eos("show bgp link-state detail")
        raise ValueError("unknown producer")

    def native_objects(self, producer):
        if producer == "frr":
            return super().native_objects()
        table = self.native_table(producer)
        self.save("ceos-link-state-latest", table)
        return native_ceos_objects(table, self.state_info["asn"])

    def capture(self, phase):
        for producer in PORTS:
            self.save(f"{producer}-link-state-{phase}", self.native_table(producer))
            self.save(f"{producer}-neighbor-{phase}", self.producer_neighbor(producer))

    def verify_routing(self):
        for node in BASE.ROUTERS:
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
            if not BASE.frr_ipv6_routes_ready(routes6, node, ROUTERS):
                return False
        for node, originator in (("p1", "10.255.0.5"), ("p2", "10.255.0.3"), ("edge-frr", "10.255.0.4")):
            service = "192.0.2." + originator.rsplit(".", 1)[1]
            route = self.vty(node, f"show bgp ipv4 unicast {service}/32 json")
            self.save(f"reflected-{node}", route)
            if not BASE.reflected_by_both(route, originator):
                return False
        adjacency = self.eos("show isis neighbors")
        self.save("isis-edge-ceos", adjacency)
        routes6 = self.eos("show ipv6 route isis")
        self.save("isis-ipv6-edge-ceos", routes6)
        route = self.eos("show ip bgp 192.0.2.5/32")
        self.save("reflected-edge-ceos", route)
        return (ceos_adjacencies_ready(adjacency) and ceos_reflected_by_both(route)
                and ceos_ipv6_routes_ready(routes6))

    def preflight(self):
        self.ownership_preflight("ceos")
        for node in (*ROUTERS, "bgpls-relay"):
            inspected = json.loads(self.docker("inspect", f"clab-bgpls-{node}"))[0]
            labels = inspected["Config"]["Labels"]
            if labels.get("containerlab") != "bgpls" or not inspected["State"]["Running"]:
                raise AssertionError(f"{node} is not a running member of this lab")
            if labels.get("clab-topo-file") != str(self.state / "bgpls.clab.yml"):
                raise AssertionError(f"{node} belongs to a different deployment directory")
            self.ids[node] = inspected["Id"]
            if node == "bgpls-relay":
                expected = {f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
                            for port in PORTS.values()}
                if inspected["HostConfig"]["PortBindings"] != expected:
                    raise AssertionError("relay must publish only both reviewed localhost listeners")
            architecture = json.loads(self.docker("image", "inspect", inspected["Image"]))[0]["Architecture"]
            if node == "edge-ceos" and (architecture != "arm64" or inspected["Config"]["Image"] != "ceosarm:4.36.2F"):
                raise AssertionError("expected the qualified ceosarm:4.36.2F native ARM64 image")
            self.save(f"container-{node}", {
                "id": inspected["Id"], "image": inspected["Config"]["Image"],
                "image_id": inspected["Image"], "labels": labels,
                "architecture": architecture,
            })
        self.transport_preflight(PORTS)


def run(args):
    state = Path(args.state).resolve(strict=True)
    transport, binary, artifact = BASE.collector_inputs(args)
    with BASE.verification_lock(state):
        return run_locked(args, state, transport, binary, artifact)


def run_locked(args, state, transport, binary, artifact):
    output = Path(tempfile.mkdtemp(prefix="verification-ceos-", dir=state))
    print(f"Evidence: {output}", flush=True)
    provenance = (BASE.helper("attribute-validation").collector_provenance(binary, artifact, output)
                  if getattr(args, "attributes", False) else None)
    lab = CeosLab(state, output, transport)
    lab.preflight()
    collectors = [Collector(producer, binary, output, lab=lab, artifact=artifact, transport=transport)
                  for producer in PORTS]
    for collector in collectors:
        collector.attributes = getattr(args, "attributes", False)
    baseline = expected_objects()
    link_changed = False
    probes = []
    attribute_run = None
    with BASE.verification_cleanup(lab, transport,
                                   lambda: cleanup(lab, link_changed, collectors, probes, attribute_run)):
        BASE.wait_until("routing is ready before starting either collector", lab.verify_routing)
        BASE.wait_until("both native BGP-LS baselines are ready before starting either collector",
                        lambda: all(lab.native_objects(producer) == baseline for producer in PORTS))
        for collector in collectors:
            collector.start()
        wait_for("both collectors contain six nodes, eighteen dual-stack links, and twelve loopback prefixes",
                 lambda: all(collector.objects() == baseline for collector in collectors), collectors)
        wait_for("both independent sessions exchange at least three keepalive intervals",
                 lambda: all(ready_neighbor(lab.producer_neighbor(producer)) for producer in PORTS), collectors)
        before = {producer: lab.producer_neighbor(producer) for producer in PORTS}
        for producer in PORTS:
            BASE.assert_neighbor_endpoint(before[producer], producer, transport, lab.state_info["asn"])
        wait_for("each producer's native BGP-LS table equals its collector RIB",
                 lambda: all(lab.native_objects(collector.producer) == collector.objects()
                             for collector in collectors), collectors)
        lab.capture("before")
        wait_for("all IS-IS adjacencies and both route reflectors remain healthy", lab.verify_routing, collectors)
        if getattr(args, "attributes", False):
            attribute_run = BASE.helper("attribute-validation").AttributeRun(
                lab, {collector.producer: collector.read for collector in collectors}, profile="ceos")
            wait_for("both producers have the expected typed native and collector baseline", attribute_run.ready, collectors)
            attribute_run.capture("baseline")
            if getattr(args, "attribute_probes", False):
                attribute_run.exercise(lambda description, condition: wait_for(description, condition, collectors))
        if args.churn:
            link_changed = True
            lab.link("down")
            reduced = baseline - REMOVED
            wait_for("both collectors withdraw exactly the p1-p2 directed links",
                     lambda: all(collector.objects() == reduced for collector in collectors), collectors)
            wait_for("both native BGP-LS tables confirm the withdrawal",
                     lambda: all(lab.native_objects(producer) == reduced for producer in PORTS), collectors)
            lab.capture("down")
            lab.link("up")
            link_changed = False
            wait_for("both collectors restore their complete original RIBs",
                     lambda: all(collector.objects() == baseline for collector in collectors), collectors)
            wait_for("both native BGP-LS tables restore their complete original RIBs",
                     lambda: all(lab.native_objects(producer) == baseline for producer in PORTS), collectors)
            for node in ("edge-frr", "edge-ceos"):
                probe = BASE.PrefixProbe(lab, node, IDS[node])
                probes.append(probe)
                BASE.exercise_prefix_probe(
                    probe, lambda description, condition: wait_for(description, condition, collectors),
                    lambda: ([collector.objects() for collector in collectors]
                             + [lab.native_objects(producer) for producer in PORTS]),
                    baseline, lab.capture,
                )
            wait_for("all IPv6 routes and IS-IS adjacencies restored after churn", lab.verify_routing, collectors)
        if attribute_run is not None:
            wait_for("both producers restore the complete typed baseline", attribute_run.ready, collectors)
            attribute_run.capture("restored")
        lab.capture("after")
        for producer in PORTS:
            if not same_connection(producer, before[producer], lab.producer_neighbor(producer)):
                raise AssertionError(f"{producer} BGP session changed during convergence checks")
        #  Stopping one collector must not merely coincide with a second
        # live PID: prove the untouched BGP session continues exchanging traffic.
        first, second = (collectors[::-1] if getattr(args, "reverse_shutdown", False) else collectors)
        survivor_before = lab.producer_neighbor(second.producer)
        wire_options = {"churn_objects": REMOVED if args.churn else (),
                        "probe_objects": [probe.value for probe in probes]}
        results = {first.producer: first.stop(signal.SIGINT, baseline, **wire_options)}
        verify_independent_survivor(lab, second, survivor_before, baseline, second.producer, first.producer)
        results[second.producer] = second.stop(signal.SIGTERM, baseline, **wire_options)
        if attribute_run is not None:
            for collector in collectors:
                results[collector.producer]["typed_attributes"] = BASE.helper("attribute-validation").audit(
                    collector.pcap_path, collector.read(), attribute_run.native(collector.producer),
                    output / f"attributes-{collector.producer}", profile="ceos", producer=collector.producer,
                    probes=attribute_run.probe_results)
        summary = {
            "passed": True, "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "transport": transport, "asn": lab.state_info["asn"],
            "collector_binary": str(binary) if binary else None,
            "collector_artifact": str(artifact) if artifact else None,
            "shutdown_order": [first.producer, second.producer], "churn": args.churn, "producers": results,
            "scope": "independent FRR and cEOS IS-IS BGP-LS producers, simultaneous single-peer collectors",
        }
    #  Publish the candidate only after both collectors and all temporary
    # state are cleaned up; metadata now includes the final removal evidence.
    for collector in collectors:
        results[collector.producer]["container"] = collector.process.metadata if transport == "ipv6" else None
    if provenance is not None:
        try:
            BASE.helper("attribute-validation").verify_collector_provenance(provenance)
        except Exception as error:
            BASE.record_failure(lab, transport, error)
            raise
        summary["collector_provenance"] = provenance
    BASE.publish_result(lab, transport, summary)
    print(f"PASS: both native RIBs; {first.producer} SIGINT -> 130; "
          f"{second.producer} SIGTERM -> 143; independent cleanup", flush=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    BASE.add_transport_arguments(parser)
    parser.add_argument("--reverse-shutdown", action="store_true",
                        help="stop cEOS with SIGINT first, then FRR with SIGTERM")
    parser.add_argument("--churn", action="store_true",
                        help="flap p1-p2 and exercise temporary IPv6 loopback prefixes on both producers")
    options = parser.parse_args()
    BASE.install_signal_handlers()
    try:
        sys.exit(run(options))
    except BASE.VerificationInterrupted as error:
        print(f"STOPPED: {error}", file=sys.stderr)
        sys.exit(128 + error.signum)
    except (AssertionError, KeyError, ValueError, RuntimeError, TimeoutError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
