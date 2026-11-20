#!/usr/bin/env python3
"""Owned, bounded Linux collectors; importing this module never contacts a runtime."""

import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import time
import uuid


ENDPOINTS = {
    "frr": ("2001:db8:6501:ff01::", "2001:db8:6501:ff01::1", "192.0.2.101"),
    "ceos": ("2001:db8:6501:ff02::", "2001:db8:6501:ff02::1", "192.0.2.102"),
}
LABEL = "io.routeobjects.bgpls.collector"
SHA = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"(?:docker\.io/library/)?swift:6\.3\.3(?:-[a-z0-9.-]+)?@sha256:[0-9a-f]{64}")


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def checked_path(value, *, file=False):
    path = Path(value)
    if not path.is_absolute() or any(part == ".." for part in path.parts):
        raise ValueError("artifact and evidence paths must be absolute")
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError(f"symlink path is not an ownership boundary: {path}")
    if any(character in str(path) for character in (",", "\n", "\r")):
        raise ValueError("Docker mount paths cannot contain commas or newlines")
    if file and not path.is_file():
        raise ValueError(f"missing regular file: {path}")
    return path


def load_artifact(path):
    """Validate the complete local manifest before any runtime/container mutation."""
    path = checked_path(path, file=True)
    try:
        artifact = json.loads(path.read_text())
        if artifact["version"] != 1:
            raise ValueError("unsupported collector artifact version")
        source, image, binary = (artifact[key] for key in ("source", "image", "binary"))
        if (not re.fullmatch(r"[0-9a-f]{40}", source["revision"])
                or not IMAGE.fullmatch(image["reference"])
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", image["id"])
                or image["architecture"] != "arm64" or image["os"] != "linux"):
            raise ValueError("expected a pinned Swift 6.3.3 native Linux ARM64 artifact")
        for key in ("archive", "package", "resolved", "binary"):
            record = artifact[key] if key == "binary" else source[key]
            item = checked_path(record["path"], file=True)
            if path.parent not in item.parents or not SHA.fullmatch(record["sha256"]):
                raise ValueError("artifact inputs must be hash-bound files beneath the manifest directory")
            if digest(item) != record["sha256"]:
                raise ValueError(f"collector artifact hash changed: {key}")
        binary_path = Path(binary["path"])
        with binary_path.open("rb") as binary_file:
            header = binary_file.read(20)
        if (len(header) < 20 or header[:6] != b"\x7fELF\x02\x01"
                or struct.unpack_from("<H", header, 18)[0] != 183
                or not os.access(binary_path, os.X_OK)):
            raise ValueError("collector is not an executable little-endian AArch64 ELF binary")
        toolchain = artifact["toolchain"]
        if ("Swift version 6.3.3" not in toolchain["version"]
                or not re.fullmatch(r"aarch64-[a-z0-9_-]+-linux-[a-z0-9_-]+", toolchain["target"])):
            raise ValueError("artifact toolchain does not identify native Swift 6.3.3 ARM64")
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
        raise ValueError(f"malformed collector artifact: {error}") from error
    return artifact


def read_state(state):
    spec = importlib.util.spec_from_file_location("bgpls_container_state", Path(__file__).with_name("lab-state.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.read_state(state)


def finite_timeout(value):
    if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError("timeout must be finite and positive")
    return value


def boot_identity(container):
    state = container["State"]
    started = state["StartedAt"]
    if (not isinstance(started, str)
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", started)
            or started.startswith("0001-")):
        raise AssertionError("relay has no valid current boot timestamp")
    datetime.datetime.fromisoformat(re.sub(r"\.[0-9]+Z$", "Z", started).replace("Z", "+00:00"))
    if state["Running"] is not True or not isinstance(container["RestartCount"], int):
        raise AssertionError("relay is not running")
    return started, container["RestartCount"]


class ContainerProcess:
    """Popen-shaped lifecycle whose authority is a Docker ID, never a CLI PID.

    The caller holds lab-state.verification_lock across creation and cleanup.
    ``lab.docker`` returns text and accepts timeout and combine_output keywords.
    """

    def __init__(self, lab, producer, artifact_path, output, log_path, pcap_path,
                 *, show_attributes=False, clock=time.monotonic, sleep=time.sleep):
        if producer not in ENDPOINTS:
            raise ValueError("unknown collector producer")
        if type(show_attributes) is not bool:
            raise ValueError("show_attributes must be a boolean")
        self.lab, self.producer = lab, producer
        #  Pin the deployment ASN before preparing argv, then recheck it
        # before any runtime operation so a changed marker cannot misdirect a run.
        self.asn = read_state(lab.state)["asn"]
        self.artifact_path = checked_path(artifact_path, file=True)
        self.artifact = load_artifact(self.artifact_path)
        self.output = checked_path(output)
        self.log_path, self.pcap_path = checked_path(log_path), checked_path(pcap_path)
        if (not self.output.is_dir() or self.log_path.parent != self.output
                or self.pcap_path.parent != self.output or self.log_path == self.pcap_path
                or self.log_path.exists() or self.pcap_path.exists()):
            raise ValueError("collector needs fresh log/PCAP paths directly in its evidence directory")
        self.clock, self.sleep = clock, sleep
        self.run_id = uuid.uuid4().hex
        self.name = f"bgpls-collector-{producer}-{self.run_id}"
        self.container_id = None
        self.returncode = None
        self.removed = False
        self.started = False
        self.metadata = {"run_id": self.run_id, "producer": producer, "asn": self.asn,
                         "artifact_path": str(self.artifact_path),
                         "source_revision": self.artifact["source"]["revision"],
                         "image_reference": self.artifact["image"]["reference"],
                         "artifact_sha256": digest(self.artifact_path),
                         "binary_sha256": self.artifact["binary"]["sha256"]}
        peer, local, identifier = ENDPOINTS[producer]
        # Qualification compares the complete drained RIB, independently of the
        # CLI's compact default or opt-in attribute presentation.
        self.args = ["/collector/bgpls", "run", "--peer", peer, "--port", "179",
                     "--local-as", str(self.asn), "--peer-as", str(self.asn), "--local-address", local,
                     "--bgp-identifier", identifier, "--hold-time", "9", "--watch", "--dump-rib", "--log-updates",
                     "--pcap", f"/evidence/{self.pcap_path.name}"]
        if show_attributes:
            self.args.append("--show-attributes")
        self.labels = {LABEL: self.run_id, f"{LABEL}.state": str(lab.state),
                       f"{LABEL}.producer": producer, f"{LABEL}.artifact": self.metadata["artifact_sha256"]}
        self.mounts = [(self.artifact["binary"]["path"], "/collector/bgpls", False),
                       (str(self.output), "/evidence", True)]
        self.metadata.update(args=self.args, labels=self.labels,
                             mounts=[{"source": a, "destination": b, "rw": c} for a, b, c in self.mounts])

    def _docker(self, *args, timeout=20, combine_output=False):
        return self.lab.docker(*args, timeout=finite_timeout(timeout), combine_output=combine_output)

    def _inspect(self, identity, timeout=20):
        data = json.loads(self._docker("inspect", identity, timeout=timeout))
        if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
            raise AssertionError("expected exactly one Docker inspect object")
        return data[0]

    def _save(self):
        (self.output / f"collector-{self.producer}-ownership.json").write_text(
            json.dumps(self.metadata, indent=2) + "\n")

    def _daemon(self, timeout=20):
        info = json.loads(self._docker("info", "--format", "{{json .}}", timeout=timeout))
        if info["OSType"] != "linux" or info["Architecture"] not in ("aarch64", "arm64"):
            raise AssertionError("collector requires a native ARM64 Linux Docker daemon")
        return info["ID"]

    def _validate_owned(self, timeout=20):
        deadline = self.clock() + finite_timeout(timeout)

        def remaining():
            value = deadline - self.clock()
            if value <= 0:
                raise subprocess.TimeoutExpired(self.args, timeout)
            return value

        if self._daemon(remaining()) != self.metadata["daemon_id"]:
            raise AssertionError("collector Docker daemon changed; refusing lifecycle operation")
        relay = self._inspect(self.metadata["relay_id"], remaining())
        if (relay["Id"] != self.metadata["relay_id"]
                or boot_identity(relay) != (self.metadata["relay_started_at"], self.metadata["relay_restart_count"])):
            raise AssertionError("collector relay identity or boot changed")
        value = self._inspect(self.container_id, remaining())
        config, host = value["Config"], value["HostConfig"]
        actual_mounts = {(item["Source"], item["Destination"], item["RW"])
                         for item in value["Mounts"] if item["Type"] == "bind"}
        if (value["Id"] != self.container_id or value["Image"] != self.metadata["image_id"]
                or any((config.get("Labels") or {}).get(k) != v for k, v in self.labels.items())
                or host["NetworkMode"] != f"container:{self.metadata['relay_id']}"
                or host["Privileged"] or not host["ReadonlyRootfs"]
                or set(host.get("CapDrop") or []) != {"ALL"} or host.get("CapAdd")
                or host.get("Init") is not True
                or set(host.get("SecurityOpt") or []) != {"no-new-privileges"}
                or host["RestartPolicy"]["Name"] != "no" or host.get("PortBindings")
                or len(value["Mounts"]) != len(self.mounts) or actual_mounts != set(self.mounts)
                or (config.get("Labels") or {}).get("containerlab") is not None
                or config["Entrypoint"] != [self.args[0]] or config["Cmd"] != self.args[1:]):
            raise AssertionError("collector container ownership/configuration changed")
        return value

    def start(self):
        if self.started or self.container_id is not None:
            raise RuntimeError("collector was already started")
        state = read_state(self.lab.state)
        if state["asn"] != self.asn:
            raise AssertionError("deployment ASN changed while preparing the collector")
        if state["transport"] != "ipv6" or (self.producer == "ceos" and state["profile"] != "ceos"):
            raise AssertionError("collector requires the matching IPv6 transport profile")
        daemon = self._daemon()
        if daemon != state["daemon_id"]:
            raise AssertionError("collector and lab state belong to different Docker daemons")
        relay = self._inspect("clab-bgpls-bgpls-relay")
        labels = relay["Config"].get("Labels") or {}
        if (not SHA.fullmatch(relay["Id"]) or labels.get("containerlab") != "bgpls"
                or labels.get("clab-topo-file") != str(self.lab.state / "bgpls.clab.yml")):
            raise AssertionError("relay is not owned by this lab state")
        started, restarts = boot_identity(relay)
        image = json.loads(self._docker("image", "inspect", self.artifact["image"]["reference"]))[0]
        if (image["Id"] != self.artifact["image"]["id"] or image["Architecture"] != "arm64"
                or image["Os"] != "linux"):
            raise AssertionError("collector runtime image does not match its build artifact")
        #  Rehash immediately before creation; mutable host bind mounts
        # must not silently replace the reviewed executable between runs.
        load_artifact(self.artifact_path)
        if digest(self.artifact_path) != self.metadata["artifact_sha256"]:
            raise AssertionError("collector artifact manifest changed")
        self.metadata.update(daemon_id=daemon, relay_id=relay["Id"], relay_started_at=started,
                             relay_restart_count=restarts, image_id=image["Id"], container_id=None)
        self._save()
        command = ["create", "--name", self.name, "--pull", "never", "--restart", "no",
                   "--init", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--network", f"container:{relay['Id']}", "--entrypoint", self.args[0]]
        for key, value in self.labels.items():
            command += ["--label", f"{key}={value}"]
        for source, destination, rw in self.mounts:
            command += ["--mount", f"type=bind,src={source},dst={destination}" + ("" if rw else ",readonly")]
        command += [image["Id"], *self.args[1:]]
        try:
            identity = self._docker(*command).strip()
            if not SHA.fullmatch(identity):
                raise AssertionError("Docker create did not return an immutable container ID")
            self.container_id = identity
            self.metadata["container_id"] = identity
            self._save()
            self._validate_owned()
            self._docker("start", identity)
            self.started = True
            self.refresh()
            return self
        except Exception as error:
            # A timed-out create/start can have succeeded remotely. Recover
            # only this unpredictable run label, never a reusable node name.
            try:
                if self.container_id is None:
                    candidates = self._docker("ps", "-aq", "--no-trunc", "--filter", f"label={LABEL}={self.run_id}").split()
                    if len(candidates) == 1 and SHA.fullmatch(candidates[0]):
                        self.container_id = candidates[0]
                        self.metadata["container_id"] = candidates[0]
                        self._save()
                    elif candidates:
                        raise AssertionError("ambiguous partial collector creation")
                self.cleanup()
            except Exception as cleanup_error:
                raise RuntimeError(f"collector start failed: {error}; cleanup blocked: {cleanup_error}; evidence: {self.output}") from error
            raise

    def refresh(self, timeout=20, *, allow_failed_exit=False):
        if self.container_id is None or self.removed:
            return
        deadline = self.clock() + finite_timeout(timeout)
        value = self._validate_owned(timeout)
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(self.args, timeout)
        text = self._docker("logs", self.container_id, timeout=remaining, combine_output=True)
        self.log_path.write_text(text)
        self.metadata["last_inspect"] = value
        state = value["State"]
        if state["Running"] is not True and state["Status"] != "created":
            self.returncode = state["ExitCode"]
            self.metadata["exit_code"] = self.returncode
            self.metadata["log_sha256"] = digest(self.log_path)
            self.metadata["pcap_sha256"] = digest(self.pcap_path) if self.pcap_path.is_file() else None
            self._save()
            if (type(self.returncode) is not int or not 0 <= self.returncode <= 255
                    or (state.get("OOMKilled") and not allow_failed_exit)):
                raise AssertionError("collector has invalid exit status or was OOM-killed")
        self._save()

    def poll(self):
        self.refresh()
        return self.returncode

    def wait(self, timeout, *, allow_failed_exit=False):
        deadline = self.clock() + finite_timeout(timeout)
        while True:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self.args, timeout)
            self.refresh(timeout=min(remaining, 2), allow_failed_exit=allow_failed_exit)
            if self.returncode is not None:
                return self.returncode
            self.sleep(min(0.1, max(0, deadline - self.clock())))

    def send_signal(self, sig):
        if sig not in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
            raise ValueError("only INT, TERM, and cleanup-only KILL are supported")
        value = self._validate_owned()
        if value["State"]["Running"]:
            self._docker("kill", "--signal", signal.Signals(sig).name.removeprefix("SIG"), self.container_id)

    def terminate(self):
        self.send_signal(signal.SIGTERM)

    def kill(self):
        self.send_signal(signal.SIGKILL)

    def cleanup(self):
        if self.container_id is None or self.removed:
            return
        value = self._validate_owned()
        if value["State"]["Running"]:
            self.terminate()
            try:
                self.wait(15, allow_failed_exit=True)
            except subprocess.TimeoutExpired:
                self.kill()
                self.wait(5, allow_failed_exit=True)
        # An OOM remains a verification failure, not a reason to leak a stopped
        # container whose immutable identity and complete evidence are retained.
        self.refresh(allow_failed_exit=True)
        self._validate_owned()
        self._docker("rm", self.container_id)
        self.removed = True
        self.metadata["removed"] = True
        self._save()
