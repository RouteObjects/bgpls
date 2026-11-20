#!/usr/bin/env python3
"""Mock-only artifact preparation; never starts containers or invokes a compiler."""

import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("bgpls_prepare_test", Path(__file__).resolve().parents[1] / "prepare-collector.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
IMAGE_ID = "sha256:" + "a" * 64
CONTAINER_ID = "b" * 64


def archive_bytes(files=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, body in (files or {"Package.swift": b"package", "Package.resolved": json.dumps({"pins": [
                {"identity": "swift-nio", "kind": "remoteSourceControl", "state": {"revision": "f" * 40}}
            ]}).encode(), "Sources/main.swift": b"main"}).items():
            item = tarfile.TarInfo(name)
            item.size = len(body)
            archive.addfile(item, io.BytesIO(body))
    return output.getvalue()


class FakeRuntime:
    def __init__(self):
        self.calls = []
        self.container = None
        self.status = "0"
        self.fail_wait = False
        self.logs = "mock retained output"

    def command(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return ""

    def docker(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == "context":
            return "unix:///var/run/docker.sock\n"
        if args[0] == "info":
            return json.dumps({"ID": "daemon", "OSType": "linux", "Architecture": "aarch64"})
        if args[:2] == ("image", "inspect"):
            return json.dumps([{"Id": IMAGE_ID, "Architecture": "arm64", "Os": "linux"}])
        if args[0] == "create":
            label = args[args.index("--label") + 1].split("=", 1)
            self.container = {"Id": CONTAINER_ID, "Image": IMAGE_ID, "Config": {"Labels": {label[0]: label[1]}},
                              "State": {"Running": False, "ExitCode": 0}}
            return CONTAINER_ID
        if args[0] == "start":
            self.container["State"]["Running"] = True
            return CONTAINER_ID
        if args[0] == "wait":
            if self.fail_wait:
                self.fail_wait = False
                raise subprocess.TimeoutExpired(args, kwargs["timeout"])
            self.container["State"].update(Running=False, ExitCode=int(self.status))
            return self.status
        if args[0] == "logs":
            return self.logs
        if args[0] == "inspect":
            return json.dumps([self.container])
        if args[0] == "kill":
            self.container["State"]["Running"] = False
            return ""
        if args[0] == "rm":
            self.container = None
            return CONTAINER_ID
        if args[0] == "ps":
            return CONTAINER_ID if self.container else ""
        raise AssertionError(args)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bgpls-prepare-test-")
        self.root = Path(self.temp.name).resolve()
        self.repository = self.root / "repo"
        self.repository.mkdir()
        self.output, self.cache = self.root / "artifact", self.root / "cache"
        self.runtime = FakeRuntime()

    def tearDown(self):
        self.temp.cleanup()

    def test_archive_rejects_parent_escape_before_writing_member(self):
        archive = self.root / "source.tar"
        archive.write_bytes(archive_bytes({"../outside": b"bad"}))
        with self.assertRaisesRegex(ValueError, "unsupported"):
            MODULE.safe_extract(archive, self.root / "source")
        self.assertFalse((self.root / "outside").exists())

    def test_archive_rejects_symlink(self):
        archive = self.root / "source.tar"
        with tarfile.open(archive, "w") as output:
            item = tarfile.TarInfo("link")
            item.type = tarfile.SYMTYPE
            item.linkname = "/tmp/outside"
            output.addfile(item)
        with self.assertRaises(ValueError):
            MODULE.safe_extract(archive, self.root / "source")

    def test_seed_rejects_nested_symlink_without_copying(self):
        seed = self.root / "seed"
        (seed / "checkouts").mkdir(parents=True)
        (seed / "checkouts" / "escape").symlink_to(self.repository, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "unsafe seed"):
            MODULE.seed_cache(seed, self.cache)
        self.assertFalse(self.cache.exists())

    def test_seed_preserves_internal_relative_file_directory_and_dangling_links(self):
        seed = self.root / "seed"
        dependency = seed / "checkouts" / "dependency"
        shared = dependency / "Shared"
        shared.mkdir(parents=True)
        (shared / "Locking.swift").write_text("original")
        plugin = dependency / "Plugins" / "Generate"
        plugin.mkdir(parents=True)
        (plugin / "Common").symlink_to("../../Shared", target_is_directory=True)
        (plugin / "Locking.swift").symlink_to("../../Shared/Locking.swift")
        (dependency / "Foo.symlink").symlink_to("Foo")
        (dependency / "chain").symlink_to("Foo.symlink")

        MODULE.seed_cache(seed, self.cache)

        copied = self.cache / "checkouts" / "dependency"
        for relative in ("Plugins/Generate/Common", "Plugins/Generate/Locking.swift", "Foo.symlink", "chain"):
            self.assertTrue((copied / relative).is_symlink())
            self.assertEqual((copied / relative).readlink(), (dependency / relative).readlink())
        (copied / "Plugins/Generate/Common/Locking.swift").write_text("copy only")
        self.assertEqual((shared / "Locking.swift").read_text(), "original")
        self.assertEqual((copied / "Plugins/Generate/Locking.swift").read_text(), "copy only")
        self.assertFalse((copied / "Foo.symlink").exists())
        self.assertFalse((copied / "chain").exists())

    def test_seed_rejects_relative_escape_omitted_input_and_cycles_before_copying(self):
        for target in ("../../outside", "../derived", "loop"):
            with self.subTest(target=target):
                seed = self.root / "seed"
                (seed / "checkouts").mkdir(parents=True, exist_ok=True)
                link = seed / "checkouts" / "loop"
                link.symlink_to(target)
                with self.assertRaisesRegex(ValueError, "unsafe seed cache link"):
                    MODULE.seed_cache(seed, self.cache)
                self.assertFalse(self.cache.exists())
                link.unlink()

    def test_seed_rejects_symlink_chain_that_escapes_copied_inputs(self):
        seed = self.root / "seed"
        (seed / "checkouts").mkdir(parents=True)
        (seed / "checkouts" / "first").symlink_to("second")
        (seed / "checkouts" / "second").symlink_to("../../outside")
        with self.assertRaisesRegex(ValueError, "unsafe seed cache link"):
            MODULE.seed_cache(seed, self.cache)
        self.assertFalse(self.cache.exists())

    def test_seed_rejects_absolute_link_even_with_internal_target(self):
        seed = self.root / "seed"
        (seed / "checkouts").mkdir(parents=True)
        original = seed / "checkouts" / "source"
        original.write_text("original")
        (seed / "checkouts" / "absolute").symlink_to(original)
        with self.assertRaisesRegex(ValueError, "absolute target"):
            MODULE.seed_cache(seed, self.cache)
        self.assertFalse(self.cache.exists())
        self.assertEqual(original.read_text(), "original")

    def test_seed_is_copied_and_original_untouched(self):
        seed = self.root / "seed"
        (seed / "repositories").mkdir(parents=True)
        original = seed / "repositories" / "entry"
        original.write_text("source")
        MODULE.seed_cache(seed, self.cache)
        (self.cache / "repositories" / "entry").write_text("changed")
        self.assertEqual(original.read_text(), "source")

    def test_seed_omits_products_and_rebases_only_copied_alternates(self):
        seed = self.root / "seed"
        objects = seed / "repositories" / "dependency" / "objects"
        objects.mkdir(parents=True)
        alternate = seed / "checkouts" / "dependency" / ".git" / "objects" / "info" / "alternates"
        alternate.parent.mkdir(parents=True)
        alternate.write_text(str(objects) + "\n")
        (seed / "release").symlink_to(self.repository)
        (seed / "aarch64-unknown-linux-gnu").mkdir()
        MODULE.seed_cache(seed, self.cache)
        self.assertFalse((self.cache / "release").exists())
        self.assertFalse((self.cache / "aarch64-unknown-linux-gnu").exists())
        self.assertEqual((self.cache / alternate.relative_to(seed)).read_text(), "/cache/repositories/dependency/objects\n")
        self.assertEqual(alternate.read_text(), str(objects) + "\n")

    def test_seed_rejects_external_git_alternate(self):
        seed = self.root / "seed"
        alternate = seed / "checkouts" / "dependency" / ".git" / "objects" / "info" / "alternates"
        alternate.parent.mkdir(parents=True)
        alternate.write_text(str(self.repository) + "\n")
        with self.assertRaisesRegex(ValueError, "escapes"):
            MODULE.seed_cache(seed, self.cache)
        self.assertEqual(alternate.read_text(), str(self.repository) + "\n")

    def test_seed_rebases_readonly_alternate_and_preserves_both_file_modes(self):
        seed = self.root / "seed"
        objects = seed / "repositories" / "dependency" / "objects"
        objects.mkdir(parents=True)
        alternate = seed / "checkouts" / "dependency" / ".git" / "objects" / "info" / "alternates"
        alternate.parent.mkdir(parents=True)
        original = str(objects) + "\n"
        alternate.write_text(original)
        alternate.chmod(0o444)

        MODULE.seed_cache(seed, self.cache)

        copied = self.cache / alternate.relative_to(seed)
        self.assertEqual(copied.read_text(), "/cache/repositories/dependency/objects\n")
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o444)
        self.assertEqual(alternate.read_text(), original)
        self.assertEqual(stat.S_IMODE(alternate.stat().st_mode), 0o444)

    def test_seed_restores_copied_alternate_mode_after_write_failure(self):
        seed = self.root / "seed"
        objects = seed / "repositories" / "dependency" / "objects"
        objects.mkdir(parents=True)
        alternate = seed / "checkouts" / "dependency" / ".git" / "objects" / "info" / "alternates"
        alternate.parent.mkdir(parents=True)
        original = str(objects) + "\n"
        alternate.write_text(original)
        alternate.chmod(0o444)
        copied = self.cache / alternate.relative_to(seed)
        write_text = Path.write_text

        def fail_rebase(path, *args, **kwargs):
            if path == copied:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
                raise OSError("injected write failure")
            return write_text(path, *args, **kwargs)

        with mock.patch.object(Path, "write_text", fail_rebase):
            with self.assertRaisesRegex(OSError, "injected write failure"):
                MODULE.seed_cache(seed, self.cache)
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o444)
        self.assertEqual(copied.read_text(), original)
        self.assertEqual(alternate.read_text(), original)
        self.assertEqual(stat.S_IMODE(alternate.stat().st_mode), 0o444)

    def test_seed_copy_refuses_overlap_in_both_directions(self):
        seed = self.root / "seed"
        (seed / "checkouts").mkdir(parents=True)
        for destination in (seed, seed / "checkouts" / "new-cache", self.root):
            with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, "disjoint"):
                MODULE.seed_cache(seed, destination)
        self.assertEqual(list((seed / "checkouts").iterdir()), [])

    def test_prepare_refuses_seed_overlap_before_runtime_or_writes(self):
        seed = self.root / "seed"
        (seed / "checkouts").mkdir(parents=True)
        combinations = ((seed / "artifact", self.cache), (self.output, seed / "checkouts" / "new-cache"))
        for output, cache in combinations:
            with self.subTest(output=output, cache=cache), self.assertRaisesRegex(ValueError, "disjoint"):
                MODULE.prepare(self.repository, "d" * 40, output, cache, seed=seed, runtime=self.runtime)
            self.assertFalse(output.exists())
            self.assertFalse(cache.exists())
        self.assertEqual(self.runtime.calls, [])

    def test_dependency_check_requires_pinned_clean_checkouts(self):
        resolved = self.root / "Package.resolved"
        resolved.write_text(json.dumps({"pins": [{"identity": "swift-nio", "kind": "remoteSourceControl",
                                                "state": {"revision": "a" * 40}}]}))
        command = MODULE.dependency_check_command(resolved)
        self.assertEqual(command[:2], ["/bin/bash", "-euc"])
        self.assertIn("rev-parse HEAD", command[2])
        self.assertIn("ls-tree -r -t -z", command[2])
        self.assertIn("hash-object --no-filters --stdin-paths", command[2])
        self.assertIn("a" * 40, command[2])
        self.assertEqual(MODULE.dependency_git_environment(resolved), {
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": "/cache/checkouts/swift-nio",
        })
        resolved.write_text(json.dumps({"pins": [{"identity": "../escape", "kind": "remoteSourceControl",
                                                "state": {"revision": "a" * 40}}]}))
        with self.assertRaises(ValueError):
            MODULE.dependency_check_command(resolved)

    def test_prepare_refuses_non_full_revision_before_runtime(self):
        for revision in ("main", "bb70441", "-" * 40):
            with self.assertRaisesRegex(ValueError, "explicit full"):
                MODULE.prepare(self.repository, revision, self.output, self.cache, runtime=self.runtime)
        self.assertEqual(self.runtime.calls, [])

    def test_prepare_refuses_existing_or_in_repository_outputs(self):
        for output in (self.repository / "artifact", self.repository, self.root):
            with self.assertRaisesRegex(ValueError, "new external"):
                MODULE.prepare(self.repository, "d" * 40, output, self.cache, runtime=self.runtime)
        self.assertEqual(self.runtime.calls, [])

    def test_prepare_refuses_unpinned_or_wrong_toolchain_image(self):
        for image in ("swift:6.3.3", "swift:6.2@sha256:" + "a" * 64, "private/swift:6.3.3@sha256:" + "a" * 64):
            with self.assertRaisesRegex(ValueError, "official Swift"):
                MODULE.prepare(self.repository, "d" * 40, self.output, self.cache,
                               runtime=self.runtime, image=image)

    def test_isolated_command_uses_no_network_or_pull_and_removes_by_id(self):
        output = self.root / "run.log"
        MODULE.isolated_run(self.runtime, IMAGE_ID, ["swift", "--version"], output)
        create = next(args for args, _ in self.runtime.calls if args[0] == "create")
        self.assertEqual(create[create.index("--network") + 1], "none")
        self.assertEqual(create[create.index("--pull") + 1], "never")
        self.assertEqual(output.read_text(), self.runtime.logs)
        self.assertEqual(self.runtime.calls[-1][0], ("rm", CONTAINER_ID))

    def test_nonzero_container_exit_retains_logs_and_cleans_up(self):
        self.runtime.status = "1"
        output = self.root / "build.log"
        with self.assertRaisesRegex(RuntimeError, r"failed \(1\)"):
            MODULE.isolated_run(self.runtime, IMAGE_ID, ["swift", "build"], output)
        self.assertEqual(output.read_text(), self.runtime.logs)
        self.assertIsNone(self.runtime.container)

    def test_timeout_retains_logs_and_kills_only_owned_id(self):
        self.runtime.fail_wait = True
        output = self.root / "build.log"
        with self.assertRaises(subprocess.TimeoutExpired):
            MODULE.isolated_run(self.runtime, IMAGE_ID, ["swift", "build"], output, timeout=1)
        self.assertEqual(output.read_text(), self.runtime.logs)
        self.assertIn((("kill", "--signal", "KILL", CONTAINER_ID), {}), self.runtime.calls)
        self.assertIsNone(self.runtime.container)

    def test_log_timeout_does_not_skip_cleanup_or_mask_build_timeout(self):
        self.runtime.fail_wait = True
        docker = self.runtime.docker
        stderr = io.StringIO()

        def fail_logs(*args, **kwargs):
            if args[0] == "logs":
                raise subprocess.TimeoutExpired(args, 20)
            return docker(*args, **kwargs)

        with mock.patch.object(self.runtime, "docker", side_effect=fail_logs), \
                mock.patch.object(MODULE.sys, "stderr", stderr):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                MODULE.isolated_run(self.runtime, IMAGE_ID, ["swift", "build"], self.root / "build.log", timeout=1)
        self.assertEqual(caught.exception.cmd, ("wait", CONTAINER_ID))
        self.assertIn((("kill", "--signal", "KILL", CONTAINER_ID), {}), self.runtime.calls)
        self.assertIsNone(self.runtime.container)
        self.assertIn("capture logs: TimeoutExpired", stderr.getvalue())

    def test_evidence_write_failures_never_skip_owned_cleanup(self):
        write_text = Path.write_text
        for suffix in (".log", ".inspect.json", ".owner.json"):
            with self.subTest(suffix=suffix):
                runtime = FakeRuntime()
                runtime.fail_wait = True
                output = self.root / "build.log"
                failed_path = output if suffix == ".log" else output.with_suffix(suffix)
                stderr = io.StringIO()

                def fail_write(path, *args, **kwargs):
                    if path == failed_path:
                        raise OSError("injected full evidence filesystem")
                    return write_text(path, *args, **kwargs)

                expected = OSError if suffix == ".owner.json" else subprocess.TimeoutExpired
                with mock.patch.object(Path, "write_text", fail_write), \
                        mock.patch.object(MODULE.sys, "stderr", stderr):
                    with self.assertRaises(expected):
                        MODULE.isolated_run(runtime, IMAGE_ID, ["swift", "build"], output, timeout=1)
                self.assertIsNone(runtime.container)
                self.assertEqual(runtime.calls[-1][0], ("rm", CONTAINER_ID))
                if suffix != ".owner.json":
                    self.assertIn("injected full evidence filesystem", stderr.getvalue())

    def test_evidence_only_failure_is_not_success_after_cleanup(self):
        output = self.root / "build.log"
        write_text = Path.write_text

        def fail_inspect(path, *args, **kwargs):
            if path == output.with_suffix(".inspect.json"):
                raise OSError("inspection evidence unavailable")
            return write_text(path, *args, **kwargs)

        with mock.patch.object(Path, "write_text", fail_inspect), \
                mock.patch.object(MODULE.sys, "stderr", io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "inspection evidence unavailable"):
                MODULE.isolated_run(self.runtime, IMAGE_ID, ["swift", "build"], output)
        self.assertIsNone(self.runtime.container)

    def test_cleanup_failure_preserves_primary_error_and_reports_retained_id(self):
        self.runtime.fail_wait = True
        docker = self.runtime.docker
        stderr = io.StringIO()

        def fail_remove(*args, **kwargs):
            if args[0] == "rm":
                raise RuntimeError("injected removal failure")
            return docker(*args, **kwargs)

        with mock.patch.object(self.runtime, "docker", side_effect=fail_remove), \
                mock.patch.object(MODULE.sys, "stderr", stderr):
            with self.assertRaises(subprocess.TimeoutExpired):
                MODULE.isolated_run(self.runtime, IMAGE_ID, ["swift", "build"], self.root / "build.log", timeout=1)
        self.assertFalse(self.runtime.container["State"]["Running"])
        self.assertIn("injected removal failure", stderr.getvalue())
        self.assertIn(CONTAINER_ID, stderr.getvalue())

    def test_unavailable_stderr_does_not_replace_primary_failure(self):
        self.runtime.fail_wait = True
        docker = self.runtime.docker
        stderr = io.StringIO()
        stderr.close()

        def fail_logs(*args, **kwargs):
            if args[0] == "logs":
                raise OSError("injected logs failure")
            return docker(*args, **kwargs)

        with mock.patch.object(self.runtime, "docker", side_effect=fail_logs), \
                mock.patch.object(MODULE.sys, "stderr", stderr):
            with self.assertRaises(subprocess.TimeoutExpired):
                MODULE.isolated_run(self.runtime, IMAGE_ID, ["swift", "build"], self.root / "build.log", timeout=1)
        self.assertIsNone(self.runtime.container)

    def test_changed_owner_or_daemon_during_evidence_capture_prevents_lifecycle_operations(self):
        for changed in ("daemon", "label", "image"):
            with self.subTest(changed=changed):
                runtime = FakeRuntime()
                runtime.fail_wait = True
                docker = runtime.docker
                evidence_started = False

                def change_identity(*args, **kwargs):
                    nonlocal evidence_started
                    if args[0] == "logs":
                        evidence_started = True
                        if changed == "label":
                            runtime.container["Config"]["Labels"].clear()
                        elif changed == "image":
                            runtime.container["Image"] = "sha256:" + "c" * 64
                        raise OSError("logs unavailable")
                    if args[0] == "info" and changed == "daemon" and evidence_started:
                        return json.dumps({"ID": "different-daemon"})
                    return docker(*args, **kwargs)

                with mock.patch.object(runtime, "docker", side_effect=change_identity), \
                        mock.patch.object(MODULE.sys, "stderr", io.StringIO()):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        MODULE.isolated_run(runtime, IMAGE_ID, ["swift", "build"], self.root / "build.log", timeout=1)
                self.assertTrue(runtime.container["State"]["Running"])
                self.assertFalse(any(args[0] in ("kill", "rm") for args, _ in runtime.calls))

    def test_failed_termination_does_not_remove_running_container(self):
        docker = self.runtime.docker
        stderr = io.StringIO()

        def fail_termination(*args, **kwargs):
            if args[0] == "wait":
                raise subprocess.TimeoutExpired(args, kwargs["timeout"])
            if args[0] == "kill":
                raise RuntimeError("injected kill failure")
            return docker(*args, **kwargs)

        with mock.patch.object(self.runtime, "docker", side_effect=fail_termination), \
                mock.patch.object(MODULE.sys, "stderr", stderr):
            with self.assertRaises(subprocess.TimeoutExpired):
                MODULE.isolated_run(self.runtime, IMAGE_ID, ["swift", "build"], self.root / "build.log", timeout=1)
        self.assertTrue(self.runtime.container["State"]["Running"])
        self.assertFalse(any(args[0] == "rm" for args, _ in self.runtime.calls))
        self.assertIn("container is still running; retained", stderr.getvalue())
        self.assertIn("injected kill failure", stderr.getvalue())

    def test_create_timeout_discovers_and_removes_only_partial_owned_container(self):
        docker = self.runtime.docker

        def fail_create(*args, **kwargs):
            result = docker(*args, **kwargs)
            if args[0] == "create":
                raise subprocess.TimeoutExpired(args, 20)
            return result

        with mock.patch.object(self.runtime, "docker", side_effect=fail_create):
            with self.assertRaises(subprocess.TimeoutExpired):
                MODULE.isolated_run(self.runtime, IMAGE_ID, ["swift", "build"], self.root / "build.log")
        self.assertIsNone(self.runtime.container)
        self.assertEqual(self.runtime.calls[-1][0], ("rm", CONTAINER_ID))

    def test_prepare_archives_explicit_commit_and_uses_frozen_offline_build(self):
        git = mock.Mock(return_value=subprocess.CompletedProcess([], 0, stdout=archive_bytes(), stderr=b""))
        commands = []

        def isolated(runtime, image, arguments, output, *, mounts=(), environment=None, timeout=60):
            commands.append((arguments, mounts, timeout, environment))
            if arguments == ["swift", "--version"]:
                text = "Swift version 6.3.3"
            elif arguments == ["swift", "-print-target-info"]:
                text = json.dumps({"target": {"triple": "aarch64-unknown-linux-gnu"}})
            elif arguments[:2] == ["swift", "build"]:
                binary = self.cache / "aarch64-unknown-linux-gnu" / "release" / "bgpls"
                binary.parent.mkdir(parents=True)
                data = bytearray(20)
                data[:6] = b"\x7fELF\x02\x01"
                struct.pack_into("<H", data, 18, 183)
                binary.write_bytes(data)
                text = "Build complete"
            else:
                text = "USAGE: bgpls"
            output.write_text(text)
            return text

        with mock.patch.object(MODULE, "isolated_run", side_effect=isolated):
            manifest = MODULE.prepare(self.repository, "d" * 40, self.output, self.cache,
                                      runtime=self.runtime, run=git)
        self.assertEqual(git.call_args.args[0][-1], "d" * 40)
        self.assertIn("archive", git.call_args.args[0])
        artifact = MODULE.COLLECTOR.load_artifact(manifest)
        self.assertEqual(artifact["source"]["revision"], "d" * 40)
        self.assertEqual(artifact["build"]["network"], "none")
        build = next(item for item in commands if item[0][:2] == ["swift", "build"])
        self.assertIn("--force-resolved-versions", build[0])
        self.assertEqual(build[1][0], (self.output / "source", "/source", True))
        self.assertEqual(build[3], artifact["build"]["environment"])
        self.assertEqual(build[3]["GIT_CONFIG_VALUE_0"], "/cache/checkouts/swift-nio")


if __name__ == "__main__":
    unittest.main()
