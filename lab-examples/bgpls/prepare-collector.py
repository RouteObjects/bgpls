#!/usr/bin/env python3
"""Prepare a pinned Linux ARM64 collector offline, outside the source checkout.

The optional seed is a SwiftPM --scratch-path directory. Only dependency
repositories/checkouts/artifacts and workspace-state.json are copied, never
modified in place. Relative symlinks confined to copied inputs are preserved,
including dangling test fixtures; absolute, escaping, or cyclic links fail.
Derived products are not copied. Missing dependencies retain offline evidence.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid


SPEC = importlib.util.spec_from_file_location("bgpls_prepare_container", Path(__file__).with_name("container-collector.py"))
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)
DEFAULT_IMAGE = "swift:6.3.3@sha256:cd45c27b3abc42310c33cfaf3008b18156cbdc9187834c9617e8f43a26d2675c"


class Runtime:
    def __init__(self, machine="clab"):
        system = platform.system()
        if system not in ("Darwin", "Linux"):
            raise ValueError("only macOS/OrbStack and native Linux are supported")
        self.prefix = ["orb", "-m", machine, "-u", "root"] if system == "Darwin" else []

    def command(self, *args, timeout=20):
        result = subprocess.run(self.prefix + list(args), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"command failed ({result.returncode}): {args!r}\n{result.stdout}")
        return result.stdout

    def docker(self, *args, timeout=20):
        return self.command("docker", *args, timeout=timeout)


def safe_extract(archive, destination):
    """Do not let tracked symlinks or archive paths reach outside the new tree."""
    destination.mkdir()
    with tarfile.open(archive) as source:
        members = source.getmembers()
        for item in members:
            name = Path(item.name)
            if name.is_absolute() or ".." in name.parts or not (item.isfile() or item.isdir()):
                raise ValueError(f"unsupported source archive member: {item.name}")
        for item in members:
            target = destination / item.name
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(item) as input_file, target.open("xb") as output_file:
                    shutil.copyfileobj(input_file, output_file)
                target.chmod(item.mode & 0o777)


def seed_cache(source, destination):
    source = COLLECTOR.checked_path(source)
    destination = COLLECTOR.checked_path(destination)
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError("seed and copied cache must be disjoint directories")
    if not source.is_dir():
        raise ValueError("seed cache must be an existing SwiftPM scratch directory")
    selected = [source / name for name in ("repositories", "checkouts", "artifacts", "workspace-state.json")
                if (source / name).exists() or (source / name).is_symlink()]

    def copied_path(path):
        return any(path == entry or (entry.is_dir() and entry in path.parents) for entry in selected)

    def validate_link(item):
        target = Path(os.readlink(item))
        if target.is_absolute():
            raise ValueError(f"unsafe seed cache link (absolute target): {item}")
        lexical = Path(os.path.abspath(item.parent / target))
        try:
            resolved = item.resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise ValueError(f"unsafe seed cache link (unresolvable or cyclic): {item}") from error
        if not copied_path(lexical) or not copied_path(resolved):
            raise ValueError(f"unsafe seed cache link (target outside copied inputs): {item}")

    for entry in selected:
        if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
            raise ValueError(f"unsafe seed cache entry: {entry}")
        for directory, directories, files in os.walk(entry, followlinks=False):
            for name in (*directories, *files):
                item = Path(directory) / name
                if item.is_symlink():
                    validate_link(item)
                elif not (item.is_dir() or item.is_file()):
                    raise ValueError(f"unsafe seed cache entry: {item}")
    destination.mkdir()
    for entry in selected:
        if entry.is_dir():
            #  Swift dependencies contain tracked source/test links.
            # Preserve their relative text without following them or reaching
            # the original cache; validate containment before copying anything.
            shutil.copytree(entry, destination / entry.name, symlinks=True)
        else:
            shutil.copyfile(entry, destination / entry.name)
    #  SwiftPM's shared Git clones may point back to the original cache.
    # Rebase copied alternates within the seed only; never mount or write it.
    for alternate in destination.rglob("objects/info/alternates"):
        original = source / alternate.relative_to(destination)
        replacements = []
        for line in alternate.read_text().splitlines():
            target = Path(line)
            if not target.is_absolute():
                target = original.parent.parent / target
            target = target.resolve()
            if source not in target.parents or not target.is_dir():
                raise ValueError(f"Git alternate escapes dependency seed: {original}")
            relative = target.relative_to(source)
            if not (destination / relative).is_dir():
                raise ValueError("Git alternate targets a directory not copied from the seed")
            replacements.append(str(Path("/cache") / relative))
        #  SwiftPM makes cached Git metadata read-only. Rebase only the
        # copied file, temporarily granting owner write and restoring its mode
        # even if writing fails; the seed's bytes and permissions stay intact.
        mode = stat.S_IMODE(alternate.stat().st_mode)
        alternate.chmod(mode | stat.S_IWUSR)
        try:
            alternate.write_text("\n".join(replacements) + ("\n" if replacements else ""))
        finally:
            alternate.chmod(mode)


def dependency_check_command(resolved):
    """Check the actual copied checkout bytes, not just workspace-state claims."""
    data = json.loads(resolved.read_text())
    if not isinstance(data.get("pins"), list) or not data["pins"]:
        raise ValueError("expected nonempty pinned dependency records")
    #  The copied index can hide modified source via assume-unchanged or
    # skip-worktree. Embed a raw-tree verifier; the pinned Swift image has Bash
    # and Git, but does not provide Python for an in-container implementation.
    statements = [Path(__file__).with_name("dependency-provenance.sh").read_text()]
    seen = set()
    for pin in data["pins"]:
        identity, revision = pin["identity"], pin["state"]["revision"]
        if (pin["kind"] != "remoteSourceControl" or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", identity)
                or identity in seen or not re.fullmatch(r"[0-9a-f]{40}", revision)):
            raise ValueError("unsupported or ambiguous pinned dependency")
        seen.add(identity)
        statements.append(f'verify_dependency "/cache/checkouts/{identity}" {revision}')
    return ["/bin/bash", "-euc", "\n".join(statements)]


def dependency_git_environment(resolved):
    """Trust only pinned copied checkouts, including SwiftPM's Git children."""
    dependency_check_command(resolved)
    identities = [pin["identity"] for pin in json.loads(resolved.read_text())["pins"]]
    environment = {"GIT_CONFIG_COUNT": str(len(identities))}
    for index, identity in enumerate(identities):
        environment[f"GIT_CONFIG_KEY_{index}"] = "safe.directory"
        environment[f"GIT_CONFIG_VALUE_{index}"] = f"/cache/checkouts/{identity}"
    return environment


def file_record(path):
    return {"path": str(path), "sha256": COLLECTOR.digest(path)}


def isolated_run(runtime, image, arguments, output, *, mounts=(), environment=None, timeout=60):
    """Every preparation process is network-isolated and cleaned up by ID."""
    token = uuid.uuid4().hex
    command = ["create", "--name", f"bgpls-prepare-{token}", "--pull", "never", "--restart", "no",
               "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--label", f"io.routeobjects.bgpls.prepare={token}", "--entrypoint", arguments[0]]
    for key, value in (environment or {}).items():
        command += ["--env", f"{key}={value}"]
    for source, target, readonly in mounts:
        command += ["--mount", f"type=bind,src={source},dst={target}" + (",readonly" if readonly else "")]
    command += [image, *arguments[1:]]
    identity = None
    daemon = json.loads(runtime.docker("info", "--format", "{{json .}}"))["ID"]

    def owned():
        if json.loads(runtime.docker("info", "--format", "{{json .}}"))["ID"] != daemon:
            raise AssertionError("preparation Docker daemon changed; refusing lifecycle operation")
        info = json.loads(runtime.docker("inspect", identity))[0]
        if (info["Id"] != identity or info["Image"] != image
                or (info["Config"].get("Labels") or {}).get("io.routeobjects.bgpls.prepare") != token):
            raise AssertionError("preparation ownership changed; refusing cleanup")
        return info

    primary_error = None
    text = None
    try:
        candidate = runtime.docker(*command).strip()
        if not COLLECTOR.SHA.fullmatch(candidate):
            raise AssertionError("prepare create did not return an immutable container ID")
        identity = candidate
        owned()
        output.with_suffix(".owner.json").write_text(json.dumps(
            {"container_id": identity, "daemon_id": daemon, "label": token,
             "image_id": image, "arguments": arguments, "environment": environment or {}}, indent=2) + "\n")
        runtime.docker("start", identity)
        status = runtime.docker("wait", identity, timeout=timeout).strip()
        text = runtime.docker("logs", identity)
        output.write_text(text)
        info = json.loads(runtime.docker("inspect", identity))[0]
        if info["State"]["Running"] or str(info["State"]["ExitCode"]) != status or status != "0":
            raise RuntimeError(f"isolated collector preparation failed ({status}); see {output}")
    except BaseException as error:
        primary_error = error

    #  Evidence collection must not short-circuit bounded cleanup.
    # Keep the operation's original exception, report every finalization failure,
    # and never let missing evidence weaken the immutable ownership checks.
    failures = []

    def attempt(description, operation):
        try:
            return operation()
        except BaseException as error:
            failures.append((description, error))
            return None

    def discover_partial():
        nonlocal identity
        if identity is None:
            matches = runtime.docker("ps", "-aq", "--no-trunc", "--filter",
                                     f"label=io.routeobjects.bgpls.prepare={token}").split()
            if len(matches) == 1 and COLLECTOR.SHA.fullmatch(matches[0]):
                identity = matches[0]
            elif matches:
                raise AssertionError("ambiguous partial preparation container; retained for inspection")

    attempt("discover partial container", discover_partial)
    if identity is not None:
        info = attempt("verify ownership before evidence capture", owned)
        if info is not None:
            attempt("capture logs", lambda: output.write_text(runtime.docker("logs", identity)))
            attempt("capture inspection", lambda: output.with_suffix(".inspect.json").write_text(
                json.dumps(info, indent=2) + "\n"))
            # Recheck after potentially slow diagnostics and immediately before
            # lifecycle operations; uncertain ownership always retains the ID.
            current = attempt("verify ownership before termination", owned)
            if current is not None:
                if current["State"]["Running"]:
                    attempt("terminate container", lambda: runtime.docker("kill", "--signal", "KILL", identity))
                    attempt("wait for termination", lambda: runtime.docker("wait", identity, timeout=10))
                final = attempt("verify ownership and stopped state before removal", owned)
                if final is not None:
                    if final["State"]["Running"]:
                        failures.append(("confirm termination", RuntimeError("container is still running; retained")))
                    else:
                        attempt("remove stopped container", lambda: runtime.docker("rm", identity))

    if failures:
        details = "; ".join(f"{description}: {type(error).__name__}: {error}"
                            for description, error in failures)
        # stderr remains useful when the filesystem cannot retain diagnostics.
        # If stderr itself is unavailable, still preserve the original failure.
        try:
            print(f"Preparation finalization incomplete for {identity or token}: {details}", file=sys.stderr)
        except (OSError, ValueError):
            pass
        if primary_error is None:
            raise RuntimeError(f"preparation finalization incomplete: {details}") from failures[0][1]
    if primary_error is not None:
        raise primary_error
    return text


def prepare(repository, revision, output, cache, *, image=DEFAULT_IMAGE, seed=None,
            runtime=None, run=subprocess.run):
    repository = COLLECTOR.checked_path(repository)
    output, cache = COLLECTOR.checked_path(output), COLLECTOR.checked_path(cache)
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("--revision must be an explicit full 40-character commit SHA")
    if not COLLECTOR.IMAGE.fullmatch(image):
        raise ValueError("--image must be official Swift 6.3.3 pinned by sha256")
    for path in (output, cache):
        if (path.exists() or repository == path or repository in path.parents
                or path == Path.home() or path == Path("/") or path in repository.parents):
            raise ValueError("artifact output and scratch cache must be new external directories")
    if output in cache.parents or cache in output.parents or output == cache:
        raise ValueError("artifact and cache directories must be separate")
    if seed is not None:
        seed = COLLECTOR.checked_path(seed)
        if not seed.is_dir():
            raise ValueError("seed cache must be an existing SwiftPM scratch directory")
        if any(path == seed or path in seed.parents or seed in path.parents for path in (output, cache)):
            raise ValueError("artifact output and cache must be disjoint from the seed")
    runtime = runtime or Runtime()
    # Refuse alternate remote contexts; this is the same local lab daemon used
    # by verification, not whichever engine happens to be selected on macOS.
    runtime.command("sh", "-c", 'test -z "${DOCKER_HOST:-}" && test -z "${DOCKER_CONTEXT:-}"')
    endpoint = runtime.docker("context", "inspect", "--format", "{{(index .Endpoints \"docker\").Host}}").strip()
    info = json.loads(runtime.docker("info", "--format", "{{json .}}"))
    if (endpoint != "unix:///var/run/docker.sock" or info["OSType"] != "linux"
            or info["Architecture"] not in ("aarch64", "arm64")):
        raise AssertionError("collector preparation requires the local native Linux ARM64 lab daemon")
    image_info = json.loads(runtime.docker("image", "inspect", image))[0]
    if image_info["Architecture"] != "arm64" or image_info["Os"] != "linux":
        raise AssertionError("pinned image is not Linux ARM64; no image is pulled automatically")
    image_id = image_info["Id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise AssertionError("invalid immutable runtime image ID")
    output.mkdir(parents=False)
    if seed is None:
        cache.mkdir(parents=False)
    else:
        seed_cache(seed, cache)
    request = {"revision": revision, "repository": str(repository), "cache": str(cache),
               "seed_cache": str(seed) if seed else None, "daemon_id": info["ID"],
               "image": image, "image_id": image_id, "network": "none"}
    (output / "request.json").write_text(json.dumps(request, indent=2) + "\n")
    archive = output / "source.tar"
    result = run(["git", "-C", str(repository), "archive", "--format=tar", revision],
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=True)
    archive.write_bytes(result.stdout)
    source = output / "source"
    safe_extract(archive, source)
    package, resolved = source / "Package.swift", source / "Package.resolved"
    source_records = {"revision": revision, "archive": file_record(archive),
                      "package": file_record(package), "resolved": file_record(resolved)}
    version = isolated_run(runtime, image_id, ["swift", "--version"], output / "swift-version.log")
    target_info = json.loads(isolated_run(runtime, image_id, ["swift", "-print-target-info"], output / "target-info.json"))
    target = target_info["target"]["triple"]
    if "Swift version 6.3.3" not in version or not target.startswith("aarch64-"):
        raise AssertionError("unexpected compiler version/target in pinned runtime")
    command = ["swift", "build", "--package-path", "/source", "--scratch-path", "/cache",
               "--configuration", "release", "--product", "bgpls", "--force-resolved-versions"]
    dependency_check = dependency_check_command(resolved)
    build_environment = dependency_git_environment(resolved)
    isolated_run(runtime, image_id, dependency_check, output / "dependencies-before.log",
                 mounts=((cache, "/cache", False),))
    isolated_run(runtime, image_id, command, output / "build.log",
                 mounts=((source, "/source", True), (cache, "/cache", False)),
                 environment=build_environment, timeout=1800)
    isolated_run(runtime, image_id, dependency_check, output / "dependencies-after.log",
                 mounts=((cache, "/cache", False),))
    for record in (source_records["package"], source_records["resolved"]):
        if COLLECTOR.digest(record["path"]) != record["sha256"]:
            raise AssertionError("archived manifest/lockfile changed during preparation")
    built_binary = cache / target / "release" / "bgpls"
    if not built_binary.is_file():
        raise AssertionError(f"release collector was not produced at {built_binary}")
    binary = output / "bgpls"
    shutil.copyfile(built_binary, binary)
    binary.chmod(0o755)
    isolated_run(runtime, image_id, ["/collector/bgpls", "--help"], output / "help.log",
                 mounts=((binary, "/collector/bgpls", True),))
    artifact = {"version": 1, "source": source_records,
                "image": {"reference": image, "id": image_id, "architecture": "arm64", "os": "linux"},
                "binary": file_record(binary), "toolchain": {"version": version, "target": target},
                "build": {"command": command, "log_path": str(output / "build.log"),
                          "environment": build_environment, "daemon_id": info["ID"], "network": "none"}}
    manifest = output / "artifact.json"
    manifest.write_text(json.dumps(artifact, indent=2) + "\n")
    COLLECTOR.load_artifact(manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--seed-cache", type=Path)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--machine", default="clab")
    args = parser.parse_args()
    print(prepare(args.repository, args.revision, args.output, args.cache,
                  image=args.image, seed=args.seed_cache, runtime=Runtime(args.machine)))


if __name__ == "__main__":
    main()
