"""Real-Git regressions for copied dependency provenance, with no containers."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "prepare-collector.py"
SPEC = importlib.util.spec_from_file_location("bgpls_dependency_prepare", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DependencyProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="bgpls dependency ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.checkout = self.cache / "checkouts" / "swift-fixture"
        self.checkout.mkdir(parents=True)
        self.environment = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                                GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                                GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        self.git("init", "-q")
        (self.checkout / "source.swift").write_text("original\n")
        (self.checkout / "run.sh").write_text("#!/bin/sh\nexit 0\n")
        (self.checkout / "run.sh").chmod(0o755)
        (self.checkout / ".gitignore").write_text("ignored.swift\n")
        (self.checkout / "relative-link").symlink_to("source.swift")
        (self.checkout / "dangling-link").symlink_to("missing-fixture")
        self.pin()

    def git(self, *arguments, input=None, check=True):
        result = subprocess.run(["git", "-C", str(self.checkout), *arguments], input=input,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=self.environment, check=check)
        return result.stdout.strip()

    def pin(self):
        # Fixture-only plumbing: no real project index, branch or commit changes.
        self.git("add", "--all")
        tree = self.git("write-tree")
        self.revision = self.git("commit-tree", tree, input="dependency fixture\n")
        self.git("update-ref", "HEAD", self.revision)
        self.resolved = self.root / "Package.resolved"
        self.resolved.write_text(json.dumps({"pins": [{
            "identity": "swift-fixture", "kind": "remoteSourceControl",
            "state": {"revision": self.revision},
        }]}))

    def verify(self, *, environment=None):
        command = MODULE.dependency_check_command(self.resolved)
        # The production command names the mount, not the original seed. Here
        # the same copied-cache layout is supplied directly, without Docker.
        command[2] = command[2].replace('"/cache/checkouts/', f'"{self.cache}/checkouts/')
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, env=environment or self.environment, timeout=20)

    def assert_valid(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified pinned dependency:", result.stdout)

    def assert_invalid(self, *, environment=None):
        result = self.verify(environment=environment)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def test_pristine_tree_including_relative_and_dangling_links(self):
        self.assert_valid()

    def test_read_only_verification_does_not_refresh_index_or_modify_files(self):
        paths = [path for path in self.checkout.rglob("*") if path.is_file() and not path.is_symlink()]
        before = {path: (hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode))
                  for path in paths}
        self.assert_valid()
        after = {path: (hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode))
                 for path in paths}
        self.assertEqual(before, after)

    def test_changed_tracked_bytes_are_rejected(self):
        (self.checkout / "source.swift").write_text("modified\n")
        self.assert_invalid()

    def test_assume_unchanged_cannot_hide_changed_bytes(self):
        self.git("update-index", "--assume-unchanged", "source.swift")
        (self.checkout / "source.swift").write_text("modified\n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assert_invalid()

    def test_skip_worktree_cannot_hide_changed_bytes(self):
        self.git("update-index", "--skip-worktree", "source.swift")
        (self.checkout / "source.swift").write_text("modified\n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assert_invalid()

    def test_same_size_and_restored_mtime_cannot_hide_changed_bytes(self):
        source = self.checkout / "source.swift"
        previous = source.stat()
        source.write_text("modified\n")
        os.utime(source, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        self.assert_invalid()

    def test_clean_filter_cannot_normalize_changed_bytes(self):
        (self.checkout / ".gitattributes").write_text("source.swift filter=fixture\n")
        self.git("config", "filter.fixture.clean", "sed s/modified/original/g")
        self.pin()
        (self.checkout / "source.swift").write_text("modified\n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assert_invalid()

    def test_export_attributes_cannot_omit_or_substitute_raw_tree_entries(self):
        (self.checkout / ".gitattributes").write_text("source.swift export-ignore\nexport.txt export-subst\n")
        (self.checkout / "export.txt").write_text("$Format:%H$\n")
        self.pin()
        self.assert_valid()
        (self.checkout / "source.swift").write_text("modified\n")
        self.assert_invalid()

    def test_mode_changes_are_rejected_even_when_core_filemode_is_false(self):
        self.git("config", "core.filemode", "false")
        (self.checkout / "source.swift").chmod(0o755)
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assert_invalid()

    def test_lost_executable_bit_is_rejected(self):
        (self.checkout / "run.sh").chmod(0o644)
        self.assert_invalid()

    def test_symlink_substitution_for_regular_file_is_rejected(self):
        (self.checkout / "source.swift").unlink()
        (self.checkout / "source.swift").symlink_to("run.sh")
        self.assert_invalid()

    def test_directory_substitution_for_regular_file_is_rejected(self):
        (self.checkout / "source.swift").unlink()
        (self.checkout / "source.swift").mkdir()
        self.assert_invalid()

    def test_fifo_substitution_for_regular_file_is_rejected_without_opening_it(self):
        (self.checkout / "source.swift").unlink()
        os.mkfifo(self.checkout / "source.swift")
        self.assert_invalid()

    def test_regular_file_substitution_for_symlink_is_rejected(self):
        (self.checkout / "relative-link").unlink()
        (self.checkout / "relative-link").write_text("source.swift")
        self.assert_invalid()

    def test_changed_symlink_target_is_rejected(self):
        (self.checkout / "relative-link").unlink()
        (self.checkout / "relative-link").symlink_to("run.sh")
        self.assert_invalid()

    def test_symlink_target_trailing_newlines_are_preserved(self):
        link = self.checkout / "newline-link"
        link.symlink_to("missing\n\n")
        self.pin()
        self.assert_valid()
        link.unlink()
        link.symlink_to("missing\n")
        self.assert_invalid()

    def test_unknown_untracked_file_is_rejected(self):
        (self.checkout / "extra.swift").write_text("untracked\n")
        self.assert_invalid()

    def test_ignored_untracked_file_is_rejected(self):
        (self.checkout / "ignored.swift").write_text("ignored\n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assert_invalid()

    def test_untracked_symlink_is_rejected(self):
        (self.checkout / "extra-link").symlink_to("source.swift")
        self.assert_invalid()

    def test_missing_tracked_file_is_rejected(self):
        (self.checkout / "source.swift").unlink()
        self.assert_invalid()

    def test_gitlink_is_rejected(self):
        self.git("update-index", "--add", "--cacheinfo", f"160000,{self.revision},submodule")
        tree = self.git("write-tree")
        self.revision = self.git("commit-tree", tree, input="gitlink fixture\n")
        self.git("update-ref", "HEAD", self.revision)
        data = json.loads(self.resolved.read_text())
        data["pins"][0]["state"]["revision"] = self.revision
        self.resolved.write_text(json.dumps(data))
        (self.checkout / "submodule").mkdir()
        self.assert_invalid()

    def test_staged_change_is_rejected_even_when_worktree_bytes_match_pin(self):
        source = self.checkout / "source.swift"
        source.write_text("modified\n")
        self.git("add", "source.swift")
        source.write_text("original\n")
        self.assert_invalid()

    def test_wrong_head_is_rejected(self):
        data = json.loads(self.resolved.read_text())
        data["pins"][0]["state"]["revision"] = "a" * 40
        self.resolved.write_text(json.dumps(data))
        self.assert_invalid()

    def test_unusual_paths_survive_nul_inventory_and_git_c_quoting(self):
        for name in ["with space.swift", "with\ttab", "with\nnewline", '"quote"', "\\slash", "-dash", "ü.swift"]:
            (self.checkout / name).write_text(f"fixture: {name}\n")
        directory = self.checkout / "directory with space"
        directory.mkdir()
        (directory / "nested.swift").write_text("nested\n")
        self.pin()
        self.assert_valid()

    def test_checkout_config_cannot_redirect_worktree_byte_checks(self):
        other = self.root / "different worktree"
        shutil.copytree(self.checkout, other, symlinks=True)
        self.git("config", "core.worktree", str(other))
        (self.checkout / "source.swift").write_text("modified\n")
        self.assert_invalid()

    def test_batched_verification_of_ten_thousand_tracked_files(self):
        directory = self.checkout / "large dependency"
        directory.mkdir()
        for number in range(10_000):
            (directory / f"source-{number:05}.swift").write_text(f"let fixture = {number}\n")
        self.pin()
        self.assert_valid()

    def test_directory_symlink_substitution_is_rejected(self):
        directory = self.checkout / "nested"
        directory.mkdir()
        (directory / "file.swift").write_text("nested\n")
        self.pin()
        directory.rename(self.checkout / "outside")
        directory.symlink_to("outside")
        self.assert_invalid()

    def test_failed_external_commands_cannot_pass_as_empty_output(self):
        executable_directory = self.root / "failing-tools"
        executable_directory.mkdir()
        commands = [("git", "ls-tree"), ("git", "hash-object"),
                    ("find", None), ("sort", None), ("cmp", None), ("readlink", None)]
        for tool, subcommand in commands:
            with self.subTest(tool=tool, subcommand=subcommand):
                wrapper = executable_directory / tool
                real_tool = shutil.which(tool)
                if tool == "git":
                    body = (f'#!/bin/sh\nfor arg do\n'
                            f'  case "$arg" in {subcommand}) exit 72;; esac\n'
                            f'done\nexec "{real_tool}" "$@"\n')
                else:
                    body = "#!/bin/sh\nexit 72\n"
                wrapper.write_text(body)
                wrapper.chmod(0o755)
                environment = dict(self.environment, PATH=f"{executable_directory}:{os.environ['PATH']}")
                self.assert_invalid(environment=environment)
                wrapper.unlink()


if __name__ == "__main__":
    unittest.main()
