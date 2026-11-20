#!/usr/bin/env python3
"""Strict, offline state records and shared lifecycle guards for the lab tools."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import uuid


MARKER = ".bgpls-lab-state"
LOCK = ".bgpls-verification-lock"
SHA256 = re.compile(r"[0-9a-f]{64}")
DEFAULT_ASN = 65001


def validate_asn(value):
    """The lab uses a usable UInt32 ASN, never AS_TRANS or JSON booleans."""
    if type(value) is not int or not 1 <= value <= 0xFFFFFFFF or value == 23456:
        raise ValueError("ASN must be an integer in 1...4294967295 other than AS_TRANS (23456)")
    return value


def parse_asn(text):
    """Strict ASCII asplain input; normalize leading zeros without signs."""
    if not isinstance(text, str) or not re.fullmatch(r"[0-9]+", text):
        raise ValueError("ASN must use decimal asplain digits without signs, whitespace or AS prefixes")
    digits = text.lstrip("0") or "0"
    if len(digits) > 10:
        raise ValueError("ASN exceeds UInt32")
    return validate_asn(int(digits))


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate state key: {key}")
        result[key] = value
    return result


def _state_path(state):
    path = Path(state)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ValueError("State must be an existing absolute, non-symlink directory")
    if "\n" in str(path) or "\r" in str(path):
        raise ValueError("State path contains a line break")
    path = path.resolve()
    if path in (Path("/"), Path.home(), Path(__file__).resolve().parents[2]):
        raise ValueError("State must be a dedicated directory outside the repository")
    if Path(__file__).resolve().parents[2] in path.parents:
        raise ValueError("State must be outside the repository")
    return path


def _hash(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Missing or symlinked state file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def config_hashes(state):
    """Hash the complete copied config inventory, not just selected bindings."""
    directory = state / "configs"
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Missing or symlinked configs directory")
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Symlink in config inventory: {path}")
        if path.is_dir():
            continue
        result[path.relative_to(state).as_posix()] = _hash(path)
    if not result:
        raise ValueError("Empty config inventory")
    return result


def read_state(state):
    """Validate v1-v4 without runtime I/O; legacy records imply ASN 65001."""
    path = _state_path(state)
    marker = path / MARKER
    _hash(marker)
    lines = marker.read_text().splitlines()
    if not lines:
        raise ValueError("Empty ownership marker")
    topology_hash = _hash(path / "bgpls.clab.yml")
    if lines[0] in ("bgpls-frr-lab-v1", "bgpls-lab-v2"):
        expected = 4 if lines[0] == "bgpls-frr-lab-v1" else 5
        if len(lines) != expected or (expected == 5 and lines[4] != "ceos"):
            raise ValueError("Invalid legacy ownership marker or unknown profile")
        record = dict(state=lines[1], daemon_id=lines[2], topology_sha256=lines[3],
                      profile="frr" if expected == 4 else "ceos", transport="ipv4")
    elif lines[0] in ("bgpls-lab-v3", "bgpls-lab-v4"):
        version = lines[0].removeprefix("bgpls-lab-")
        if len(lines) != 2:
            raise ValueError(f"The {version} ownership marker must contain exactly two lines")
        record = json.loads(lines[1], object_pairs_hook=_object)
        keys = {"state", "daemon_id", "profile", "transport", "topology_sha256", "configs"}
        if version == "v4":
            keys.add("asn")
        if not isinstance(record, dict) or set(record) != keys:
            raise ValueError(f"Unexpected {version} ownership fields")
        if version == "v4":
            validate_asn(record["asn"])
        if record["profile"] not in ("frr", "ceos") or record["transport"] not in ("ipv4", "ipv6"):
            raise ValueError("Unknown profile or transport")
        if not isinstance(record["configs"], dict) or record["configs"] != config_hashes(path):
            raise ValueError("The state config inventory or hashes changed after deployment")
    else:
        raise ValueError("Unknown ownership marker schema")
    if record["state"] != str(path):
        raise ValueError("The ownership marker does not match this state directory")
    if not isinstance(record["daemon_id"], str) or not record["daemon_id"] or any(
        character in record["daemon_id"] for character in "\r\n\t"
    ):
        raise ValueError("Invalid recorded Docker daemon identity")
    if record["topology_sha256"] != topology_hash:
        raise ValueError("The state topology changed after deployment")
    #  Legacy records are read-only evidence of the fixed-ASN lab.
    # Canonical identity gains an ASN without rewriting their marker or hashes.
    return {**record, "state": path, "asn": record.get("asn", DEFAULT_ASN)}


def write_state(state, profile, transport, daemon_id, asn=DEFAULT_ASN):
    path = _state_path(state)
    if profile not in ("frr", "ceos") or transport not in ("ipv4", "ipv6"):
        raise ValueError("Unknown profile or transport")
    if not daemon_id or any(c in daemon_id for c in "\r\n\t"):
        raise ValueError("Invalid Docker daemon identity")
    record = dict(state=str(path), profile=profile, transport=transport, daemon_id=daemon_id, asn=validate_asn(asn),
                  topology_sha256=_hash(path / "bgpls.clab.yml"), configs=config_hashes(path))
    #  Exclusive creation cannot overwrite a previous deployment's claim.
    with (path / MARKER).open("x") as output:
        output.write("bgpls-lab-v4\n" + json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    return read_state(path)


def assert_lock(state, token):
    path = _state_path(state) / LOCK
    owner = path / "owner.json"
    if path.is_symlink() or not path.is_dir() or owner.is_symlink() or not owner.is_file():
        raise ValueError("Missing or unsafe lifecycle lock")
    record = json.loads(owner.read_text(), object_pairs_hook=_object)
    if set(record) != {"token", "pid"} or not token or record["token"] != token:
        raise ValueError("The lifecycle lock belongs to another operation")


@contextmanager
def verification_lock(state, *, retain_on_error=False):
    """Exclusive across verification/destruction; never guess that a lock is stale."""
    record = read_state(state)
    directory = record["state"] / LOCK
    token = uuid.uuid4().hex
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError as error:
        raise RuntimeError(f"Lab lifecycle lock exists: {directory}; inspect its owner, do not auto-break it") from error
    owner = directory / "owner.json"
    try:
        with owner.open("x") as output:
            json.dump({"token": token, "pid": os.getpid()}, output)
    except BaseException:
        # A failed/ambiguous claim is deliberately left for manual inspection.
        raise
    completed = False
    try:
        yield token
        completed = True
    finally:
        #  Never remove a replacement lock or unknown files on cleanup.
        if completed or not retain_on_error:
            assert_lock(record["state"], token)
            if set(directory.iterdir()) != {owner}:
                raise RuntimeError(f"Unexpected files in lifecycle lock; leaving it intact: {directory}")
            owner.unlink()
            directory.rmdir()


def assert_no_namespace_holders(state, run_docker, allowed_ids=frozenset()):
    """Refuse active direct/indirect relay netns users; callback takes Docker args."""
    record = read_state(state)
    ids = run_docker(["ps", "-aq", "--no-trunc"]).split()
    if not ids:
        return
    if len(set(ids)) != len(ids) or any(not SHA256.fullmatch(value) for value in ids):
        raise ValueError("Docker returned an invalid container inventory")
    containers = json.loads(run_docker(["inspect", *ids]))
    if not isinstance(containers, list) or len(containers) != len(ids):
        raise ValueError("Cannot resolve the complete Docker container inventory")
    by_id = {}
    by_name = {}
    for container in containers:
        identifier = container.get("Id", "")
        name = container.get("Name", "").removeprefix("/")
        if identifier not in ids or identifier in by_id or not name or name in by_name:
            raise ValueError("Ambiguous Docker container identity")
        by_id[identifier] = container
        by_name[name] = identifier
    relay = by_name.get("clab-bgpls-bgpls-relay")
    if relay is not None:
        labels = by_id[relay].get("Config", {}).get("Labels") or {}
        if labels.get("containerlab") != "bgpls" or labels.get("clab-topo-file") != str(record["state"] / "bgpls.clab.yml"):
            raise ValueError("Relay belongs to another deployment")
    if any(not SHA256.fullmatch(value) or value not in by_id for value in allowed_ids):
        raise ValueError("Namespace allowlist must contain known immutable container IDs")

    def resolve(reference):
        if reference.removeprefix("/") in by_name:
            return by_name[reference.removeprefix("/")]
        matches = [identifier for identifier in by_id if identifier.startswith(reference)] if re.fullmatch(r"[0-9a-f]+", reference) else []
        if len(matches) != 1:
            raise ValueError(f"Cannot resolve container namespace reference: {reference}")
        return matches[0]

    def uses_relay(identifier, visited):
        if identifier in visited:
            raise ValueError("Cyclic container namespace references")
        if identifier == relay:
            return True
        mode = by_id[identifier].get("HostConfig", {}).get("NetworkMode")
        if not isinstance(mode, str):
            raise ValueError("Missing Docker namespace information")
        if mode.startswith("container:"):
            return uses_relay(resolve(mode.partition(":")[2]), visited | {identifier})
        return False

    relay_sandbox = (by_id[relay].get("NetworkSettings") or {}).get("SandboxKey") if relay else None
    for identifier, container in by_id.items():
        running = container.get("State", {}).get("Running")
        if not isinstance(running, bool):
            raise ValueError("Missing Docker container running state")
        if not running or identifier == relay:
            continue
        shared_sandbox = relay_sandbox and (container.get("NetworkSettings") or {}).get("SandboxKey") == relay_sandbox
        if (uses_relay(identifier, set()) or shared_sandbox) and identifier not in allowed_ids:
            raise RuntimeError(f"Relay namespace is held by {container['Name']} ({identifier}); stop that container explicitly first")


class InterruptedLifecycle(RuntimeError):
    def __init__(self, status):
        super().__init__("Lifecycle command interrupted; lock retained because descendant cleanup is unknown. "
                         "Inspect the owner and remaining processes before removing it manually.")
        self.status = status


def _locked_command(state, command):
    #  A shell may exit while its Containerlab descendant still mutates
    # Docker. An interrupted/ambiguous command must leave the ownership lock;
    # forwarding a signal to the immediate child does not prove tree cleanup.
    with verification_lock(state, retain_on_error=True) as token:
        process = subprocess.Popen(command, env={**os.environ, "BGPLS_LOCK_TOKEN": token})
        old_handlers = {}
        interrupted = None

        def forward(number, frame):
            nonlocal interrupted
            interrupted = number
            try:
                process.send_signal(number)
            except ProcessLookupError:
                pass

        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                old_handlers[number] = signal.signal(number, forward)
            status = process.wait()
            if interrupted is not None or status < 0 or status in (130, 143):
                raise InterruptedLifecycle(128 + interrupted if interrupted is not None else
                                           128 - status if status < 0 else status)
        finally:
            for number, handler in old_handlers.items():
                signal.signal(number, handler)
        return status if status >= 0 else 128 - status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("asn", "read", "write", "locked", "assert-lock", "guard"))
    parser.add_argument("--state")
    parser.add_argument("--profile", choices=("frr", "ceos"))
    parser.add_argument("--transport", choices=("ipv4", "ipv6"))
    parser.add_argument("--daemon-id")
    parser.add_argument("--token")
    parser.add_argument("--asn", type=parse_asn, default=DEFAULT_ASN)
    args, command = parser.parse_known_args()
    if command[:1] == ["--"]:
        command = command[1:]
    if args.operation not in ("locked", "guard") and command:
        parser.error("Unexpected arguments")
    if args.operation == "asn":
        print(args.asn)
    elif not args.state:
        parser.error("--state is required for this operation")
    elif args.operation == "read":
        state = read_state(args.state)
        print(f"{state['profile']}\n{state['transport']}\n{state['daemon_id']}\n{state['asn']}")
    elif args.operation == "write":
        if not all((args.profile, args.transport, args.daemon_id)):
            parser.error("write requires --profile, --transport and --daemon-id")
        write_state(args.state, args.profile, args.transport, args.daemon_id, args.asn)
    elif args.operation == "assert-lock":
        assert_lock(args.state, args.token)
    else:
        if not command:
            parser.error("A command after -- is required")
        if args.operation == "locked":
            return _locked_command(args.state, command)
        assert_no_namespace_holders(args.state, lambda argv: subprocess.check_output(command + argv, text=True, timeout=20))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except InterruptedLifecycle as error:
        print(f"bgpls-lab: {error}", file=sys.stderr)
        sys.exit(error.status)
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"bgpls-lab: {error}", file=sys.stderr)
        sys.exit(1)
