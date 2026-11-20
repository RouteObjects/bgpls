#!/usr/bin/env python3
"""Typed lab qualification and offline capture replay; imports perform no I/O."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location("typed_" + name.replace("-", "_"),
                                                Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def projected(event):
    return {field: event[field] for field in ("display", "availability", "attributes")}


def by_display(events):
    result = {}
    for event in events:
        if event["display"] in result:
            raise AssertionError("distinct complete keys collide in typed presentation")
        result[event["display"]] = projected(event)
    return result


def save_new(path, value):
    with Path(path).open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def source_fingerprint():
    files = [ROOT / "Package.swift", ROOT / "Package.resolved"]
    files += sorted((ROOT / "Sources").rglob("*.swift"))
    files += sorted((ROOT / "Tests").rglob("*.swift"))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def production_fingerprint():
    return {path: digest for path, digest in source_fingerprint().items()
            if path.startswith("Sources/") or path in ("Package.swift", "Package.resolved")}


def collector_provenance(binary, artifact, output, *, runner=subprocess.run):
    """Bind the actual collector to current production sources before any lab operation."""
    production = production_fingerprint()
    if artifact is not None:
        data = load("container-collector").load_artifact(artifact)
        archived = {}
        with tarfile.open(data["source"]["archive"]["path"]) as archive:
            for item in archive.getmembers():
                if item.name in production or item.name.startswith("Sources/") and item.isfile():
                    if not item.isfile() or item.name in archived:
                        raise ValueError("unexpected collector archive member")
                    archived[item.name] = hashlib.sha256(archive.extractfile(item).read()).hexdigest()
        if archived != production:
            raise AssertionError("collector artifact does not contain the current production source/lockfile")
        binary = Path(data["binary"]["path"])
    else:
        with (Path(output) / "native-collector-build.log").open("x") as log:
            result = runner(["swift", "build", "--disable-sandbox", "--disable-automatic-resolution",
                             "--product", "bgpls"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        if result.returncode:
            raise AssertionError("native collector build failed")
        built = runner(["swift", "build", "--disable-sandbox", "--disable-automatic-resolution", "--show-bin-path"],
                       cwd=ROOT, capture_output=True, text=True, check=True, timeout=30)
        expected = Path(built.stdout.strip()) / "bgpls"
        if hashlib.sha256(Path(binary).read_bytes()).digest() != hashlib.sha256(expected.read_bytes()).digest():
            raise AssertionError("--binary differs from the freshly built current-source collector")
    result = {"productionSHA256": production, "binary": str(binary),
              "binarySHA256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              "artifact": str(artifact) if artifact else None,
              "artifactSHA256": hashlib.sha256(Path(artifact).read_bytes()).hexdigest() if artifact else None}
    verify_collector_provenance(result)
    save_new(Path(output) / "typed-collector-provenance.json", result)
    return result


def verify_collector_provenance(record):
    if (production_fingerprint() != record["productionSHA256"]
            or hashlib.sha256(Path(record["binary"]).read_bytes()).hexdigest() != record["binarySHA256"]):
        raise AssertionError("collector binary or production sources changed during qualification")
    if record["artifact"]:
        if hashlib.sha256(Path(record["artifact"]).read_bytes()).hexdigest() != record["artifactSHA256"]:
            raise AssertionError("collector artifact changed during qualification")
        load("container-collector").load_artifact(record["artifact"])


def replay_swift(wire, output, *, runner=subprocess.run):
    """Compile the current tests, require their fresh success artifact, and bind inputs."""
    # A missing field must not be mistaken for an observed empty diagnostic list.
    # Schema 1 evidence remains historical; regenerate it from the original PCAP.
    if (wire.get("schema") != 2 or not isinstance(wire.get("updates"), list)
            or any(not isinstance(item, dict) or not isinstance(item.get("attributeDiagnostics"), list)
                   for item in wire["updates"])):
        raise ValueError("Swift replay requires schema 2 and per-UPDATE attribute diagnostics")
    output = Path(output).resolve(strict=True)
    manifest = output / "swift-replay-input.json"
    result = output / "swift-replay-output.json"
    save_new(manifest, {"schema": 2, "updates": wire["updates"]})
    if result.exists():
        raise ValueError("Swift replay output must be fresh")
    before = source_fingerprint()
    input_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
    env = dict(os.environ, BGPLS_ATTRIBUTE_REPLAY_INPUT=str(manifest), BGPLS_ATTRIBUTE_REPLAY_OUTPUT=str(result))
    command = [str(ROOT / "scripts/test.sh"), "--disable-sandbox", "--disable-automatic-resolution",
               "--filter", "TypedAttributeCaptureReplayTests/externalCapture"]
    save_new(output / "swift-replay-provenance.json", {"sourceSHA256": before, "command": command,
             "inputSHA256": input_hash})
    with (output / "swift-replay.log").open("x", encoding="utf-8") as log:
        process = runner(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    if process.returncode != 0:
        raise AssertionError("Swift capture replay failed; inspect swift-replay.log")
    if source_fingerprint() != before:
        raise AssertionError("source changed during Swift replay")
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != input_hash:
        raise AssertionError("input changed during Swift replay")
    actual = json.loads(result.read_text())
    if (actual.get("schema") != 2 or actual.get("updateCount") != len(wire["updates"])
            or actual.get("checks") != {"completeRecordReplay": True, "snapshotRoundTrips": True,
                                        "catchUpReplay": True, "updateAttributeDiagnostics": True}
            or not isinstance(actual.get("updates"), list)
            or any(not isinstance(item, dict) or not isinstance(item.get("attributeDiagnostics"), list)
                   for item in actual["updates"])):
        raise AssertionError("missing or incomplete Swift replay success artifact")
    if ([item["bodyHex"] for item in actual["updates"]] != [item["bodyHex"] for item in wire["updates"]]
            or [item["events"] for item in actual["updates"]] != [item["events"] for item in wire["updates"]]
            or [item["attributeDiagnostics"] for item in actual["updates"]]
            != [item["attributeDiagnostics"] for item in wire["updates"]]
            or actual["finalRecords"] != wire["finalRecords"]):
        raise AssertionError("Swift replay differs from independent wire interpretation")
    return actual


def audit_probe_phases(events, probes, producer):
    """Verify attribute-only transitions using complete identity keys at every event."""
    for probe in probes:
        try:
            bounds = probe["eventRanges"][producer]
            start, end = bounds["start"], bounds["end"]
        except (KeyError, TypeError) as error:
            raise AssertionError("missing or invalid metric probe event range") from error
        if (type(start) is not int or type(end) is not int
                or not 0 <= start < end <= len(events)):
            raise AssertionError("invalid metric probe event range")
        records = {}

        def apply(event):
            if event["operation"] == "upsert":
                records[event["key"]] = event
            elif event["operation"] == "withdraw":
                records.pop(event["key"], None)
            else:
                raise AssertionError("unexpected metric phase operation")

        for event in events[:start]:
            apply(event)
        targets = [key for key, record in records.items() if record["display"] == probe["display"]]
        if len(targets) != 1:
            raise AssertionError("metric probe requires exactly one baseline full key")
        target_key, = targets
        if records[target_key]["attributes"]["igpMetric"] != probe["before"]:
            raise AssertionError("metric probe does not start at its baseline value")
        keys = set(records)
        baseline_values = {key: projected(record) for key, record in records.items()}
        values = [probe["before"]]
        for event in events[start:end]:
            apply(event)
            # Even a momentary withdraw/re-add or a same-display identity change
            # violates an attribute-only probe. Later physical churn is separate.
            if set(records) != keys:
                raise AssertionError("topology keys changed during metric-only probe")
            if event["operation"] == "upsert":
                observed = projected(event)
                if event["key"] == target_key:
                    if observed["attributes"]["igpMetric"] not in (probe["before"], probe["target"]):
                        raise AssertionError("unexpected target metric during probe")
                    observed["attributes"] = {**observed["attributes"], "igpMetric": probe["before"]}
                # Only the selected directed metric may change. Raw evidence
                # refreshes are legal, but transient reverse/sibling changes are not.
                if observed != baseline_values[event["key"]]:
                    raise AssertionError("unrelated typed values changed during metric-only probe")
            if event["operation"] == "upsert" and event["display"] == probe["display"]:
                if event["key"] != target_key:
                    raise AssertionError("metric probe changed its complete NLRI key")
                values.append(event["attributes"]["igpMetric"])
        cursor = 0
        for wanted in (probe["before"], probe["target"], probe["before"]):
            while cursor < len(values) and values[cursor] != wanted:
                cursor += 1
            if cursor == len(values):
                raise AssertionError("metric change/restoration missing from probe interval")
            cursor += 1
        if records[target_key]["attributes"]["igpMetric"] != probe["before"]:
            raise AssertionError("metric probe interval does not finish restored")


def audit(pcap, text, native, output, *, profile="ceos", producer="frr", probes=(), runner=subprocess.run):
    """No runtime access: compare complete PCAP, CLI evidence, native projection and Swift."""
    output = Path(output)
    output.mkdir(exist_ok=False)
    if not text.endswith("\n") or text.count(" RIB final\n") != 1:
        raise AssertionError("typed capture qualification requires one complete final-RIB log")
    checks = load("attribute-checks")
    wire = load("wire-attributes").audit_capture(pcap)
    save_new(output / "attributes-wire.json", wire)
    save_new(output / "native-projection.json", native)
    wire_final = by_display(wire["finalRecords"])
    expected = checks.expected_records(profile)
    if wire_final != expected or native != expected:
        raise AssertionError("typed wire/native baseline differs from pinned-profile expectations")
    if checks.watch_records(text) != wire_final or checks.final_records(text) != wire_final:
        raise AssertionError("typed watch/final output differs from wire records")
    wire_events = []
    for update in wire["updates"]:
        for event in update["events"]:
            value = {"operation": event["operation"], "display": event["display"]}
            if event["operation"] == "upsert":
                value.update(projected(event))
            wire_events.append(value)
    if checks.watch_events(text) != wire_events:
        raise AssertionError("typed watch event sequence differs from complete captured UPDATE sequence")
    audit_probe_phases([event for update in wire["updates"] for event in update["events"]], probes, producer)
    actual = replay_swift(wire, output, runner=runner)
    summary = {"audited": True, "scope": "live CLI evidence plus offline public-library replay; not a live snapshot subscriber",
               "pcapSHA256": hashlib.sha256(Path(pcap).read_bytes()).hexdigest(),
               "updateCount": actual["updateCount"], "coverage": wire["coverage"], "probes": list(probes),
               "evidence": str(output.resolve())}
    # This is evidence, not the live-run outcome. Only the enclosing verifier
    # publishes passed:true after restoration and all child cleanup succeeds.
    save_new(output / "audit-candidate.json", summary)
    return summary


class AttributeRun:
    """Optional runtime adapter; callers own the lab lock, children, waits, and cleanup."""

    def __init__(self, lab, reads, *, profile):
        self.lab, self.reads, self.profile = lab, reads, profile
        self.checks = load("attribute-checks")
        self.expected = self.checks.expected_records(profile)
        self.probes = []
        self.probe_results = []

    def native(self, producer):
        table = self.lab.native_table(producer)
        self.lab.save(f"{producer}-attributes-native-latest", table)
        return self.checks.native_records(table, producer, self.lab.state_info["asn"])

    def ready(self, expected=None):
        expected = self.expected if expected is None else expected
        try:
            return all(self.native(producer) == expected and self.checks.watch_records(read()) == expected
                       for producer, read in self.reads.items())
        except self.checks.NativeAttributesPending:
            # The caller owns the bounded convergence wait. Do not let a fresh
            # helper import's exception identity bypass that polling boundary.
            return False

    def capture(self, phase):
        for producer, read in self.reads.items():
            self.lab.save(f"{producer}-attributes-{phase}", {
                "native": self.native(producer), "watch": self.checks.watch_records(read())})

    def event_counts(self):
        # Bind command phases to complete watch-event boundaries. The final
        # audit compares every watch event with wire evidence before using them.
        result = {}
        for producer, read in self.reads.items():
            text = read()
            result[producer] = len(self.checks.watch_events(text[:text.rfind("\n") + 1]))
        return result

    def exercise(self, wait):
        for origin in (("frr", "ceos") if self.profile == "ceos" else ("frr",)):
            prefix = ("link 0000.0000.0003 10.254.0.8," if origin == "frr"
                      else "link 0000.0000.0006 10.254.0.15,")
            targets = [key for key in self.expected if key.startswith(prefix)]
            if len(targets) != 1:
                raise AssertionError("metric probe does not identify exactly one baseline directed link")
            display = targets[0]

            def read_config(node, interface, *, timeout):
                if node == "p1":
                    return self.lab.docker("exec", self.lab.container_id(node), "vtysh", "-c",
                                           "show running-config", timeout=timeout)
                return self.lab.docker("exec", self.lab.container_id(node), "Cli", "-p", "15", "-c",
                                       "show running-config", timeout=timeout)

            def configure(node, commands, *, timeout):
                if node == "p1":
                    argv = [item for command in commands for item in ("-c", command)]
                    output = self.lab.docker("exec", self.lab.container_id(node), "vtysh", *argv, timeout=timeout)
                else:
                    output = self.lab.docker("exec", self.lab.container_id(node), "Cli", "-p", "15", "-c",
                                             "\n".join(commands), timeout=timeout)
                diagnostic = output.replace("\r\n", "\n").replace(
                    "% Configuration applied with notes:\nNo changes found to be committed!", "")
                if re.search(r"(?im)^\s*%|unknown command|invalid input|incomplete command", diagnostic):
                    raise RuntimeError(f"metric probe configuration failed: {output.strip()}")

            def read_metric(node, interface, *, timeout):
                if origin == "frr":
                    raw = self.lab.docker("exec", self.lab.container_id("edge-frr"), "vtysh", "-c",
                                          "show bgp link-state link-state json", timeout=timeout)
                else:
                    raw = self.lab.docker("exec", self.lab.container_id("edge-ceos"), "Cli", "-p", "15", "-c",
                                          "show bgp link-state detail | json", timeout=timeout)
                records = self.checks.native_records(json.loads(raw), origin, self.lab.state_info["asn"])
                return records[display]["attributes"]["igpMetric"]

            probe = self.checks.MetricProbe(origin, read_config, configure, read_metric,
                record=lambda phase, value: self.lab.save(f"metric-{origin}-{phase}", value))
            self.probes.append(probe)
            probe.prepare()
            self.capture(f"metric-{origin}-before")
            changed = copy.deepcopy(self.expected)
            changed[display]["attributes"]["igpMetric"] = 20
            starts = self.event_counts()
            probe.apply()
            wait(f"both native and collector projections observe {origin} metric 20 without key changes",
                 lambda: self.ready(changed))
            if not self.lab.verify_routing():
                raise AssertionError("routing or adjacencies changed during metric probe")
            self.capture(f"metric-{origin}-changed")
            probe.restore()
            wait(f"{origin} original typed projections restored", self.ready)
            self.capture(f"metric-{origin}-restored")
            ends = self.event_counts()
            self.probe_results.append({"display": display, "before": 10, "target": 20,
                                       "eventRanges": {producer: {"start": starts[producer], "end": ends[producer]}
                                                       for producer in self.reads}})
            self.lab.save(f"metric-{origin}-event-ranges", self.probe_results[-1])

    def restore(self):
        failures = []
        for probe in reversed(self.probes):
            try:
                probe.restore()
            except Exception as error:
                failures.append(str(error))
        if failures:
            raise AssertionError("metric restoration failed: " + "; ".join(failures))
