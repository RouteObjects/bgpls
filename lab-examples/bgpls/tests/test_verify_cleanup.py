#!/usr/bin/env python3
"""Offline cleanup regressions: no real signals, processes, Docker, or lab calls."""

import argparse
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "bgpls_lab_verify_cleanup", Path(__file__).resolve().parents[1] / "verify.py"
)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def neighbor():
    """Synthetic equivalent of the pinned FRR neighbor presentation."""
    return {
        "bgpState": "Established",
        "localAs": 65001, "remoteAs": 65001,
        "connectionsEstablished": 1,
        "connectionsDropped": 0,
        "hostForeign": "10.254.254.1",
        "portForeign": 40812,
        "hostLocal": "10.254.254.0",
        "portLocal": 179,
        "bgpTimerUpEstablishedEpoch": 1790132064,
        "bgpTimerUpMsec": 12000,
        "messageStats": {"keepalivesSent": 5, "keepalivesRecv": 5},
    }


class SameConnectionTests(unittest.TestCase):
    def test_same_socket_with_progress_and_one_second_epoch_rounding_passes(self):
        before = neighbor()
        after = copy.deepcopy(before)
        after["bgpTimerUpEstablishedEpoch"] += 1
        after["bgpTimerUpMsec"] = 43000
        after["messageStats"] = {"keepalivesSent": 15, "keepalivesRecv": 15}
        self.assertTrue(VERIFY.same_bgp_connection(before, after))

    def test_unchanged_connection_and_counters_pass(self):
        before = neighbor()
        self.assertTrue(VERIFY.same_bgp_connection(before, copy.deepcopy(before)))

    def test_either_connection_counter_change_fails(self):
        before = neighbor()
        for field in ("connectionsEstablished", "connectionsDropped"):
            for delta in (-1, 1):
                after = copy.deepcopy(before)
                after[field] += delta
                with self.subTest(field=field, delta=delta):
                    self.assertFalse(VERIFY.same_bgp_connection(before, after))

    def test_changed_local_or_foreign_socket_identity_fails(self):
        before = neighbor()
        for field, value in (
            ("hostForeign", "10.254.254.3"),
            ("portForeign", 40813),
            ("hostLocal", "10.254.254.2"),
            ("portLocal", 180),
        ):
            after = copy.deepcopy(before)
            after[field] = value
            with self.subTest(field=field):
                self.assertFalse(VERIFY.same_bgp_connection(before, after))

    def test_uptime_reset_or_either_keepalive_counter_decrease_fails(self):
        before = neighbor()
        after = copy.deepcopy(before)
        after["bgpTimerUpMsec"] -= 1
        self.assertFalse(VERIFY.same_bgp_connection(before, after))
        for field in ("keepalivesSent", "keepalivesRecv"):
            after = copy.deepcopy(before)
            after["messageStats"][field] -= 1
            with self.subTest(field=field):
                self.assertFalse(VERIFY.same_bgp_connection(before, after))

    def test_nonestablished_state_fails_even_with_unchanged_counters(self):
        before = neighbor()
        for state in ("Idle", "Connect", "Active", "OpenSent", "OpenConfirm"):
            after = copy.deepcopy(before)
            after["bgpState"] = state
            with self.subTest(state=state):
                self.assertFalse(VERIFY.same_bgp_connection(before, after))


class LinkCleanupTests(unittest.TestCase):
    def test_first_endpoint_failure_still_attempts_second(self):
        lab = VERIFY.Lab(Path("/unused-state"), Path("/unused-output"))
        errors = (
            RuntimeError("mock command failure"),
            OSError("mock OS failure"),
            subprocess.TimeoutExpired("mock docker", 20),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                lab.docker = mock.Mock(side_effect=[error, ""])
                with self.assertRaisesRegex(RuntimeError, "p1:"):
                    lab.link("up")
                self.assertEqual(lab.docker.call_args_list, [
                    mock.call("exec", "clab-bgpls-p1", "ip", "link", "set", "eth3", "up"),
                    mock.call("exec", "clab-bgpls-p2", "ip", "link", "set", "eth3", "up"),
                ])

    def test_both_failures_are_reported_after_both_attempts(self):
        lab = VERIFY.Lab(Path("/unused-state"), Path("/unused-output"))
        lab.docker = mock.Mock(side_effect=[RuntimeError("first failed"), OSError("second failed")])
        with self.assertRaises(RuntimeError) as caught:
            lab.link("up")
        self.assertEqual(lab.docker.call_count, 2)
        self.assertIn("p1: first failed", str(caught.exception))
        self.assertIn("p2: second failed", str(caught.exception))

    def test_successful_operation_visits_only_two_reviewed_interfaces(self):
        lab = VERIFY.Lab(Path("/unused-state"), Path("/unused-output"))
        lab.docker = mock.Mock(return_value="")
        lab.link("down")
        self.assertEqual(lab.docker.call_args_list, [
            mock.call("exec", "clab-bgpls-p1", "ip", "link", "set", "eth3", "down"),
            mock.call("exec", "clab-bgpls-p2", "ip", "link", "set", "eth3", "down"),
        ])


class ParentSignalCleanupTests(unittest.TestCase):
    def exercise_interruption(
        self, signum, *, stubborn_child=False, restore_failure=False, cleanup_signal_at=None
    ):
        events = []
        handlers = {}
        baseline = VERIFY.expected_links()
        baseline |= {f"node {system_id}" for system_id in VERIFY.IDS.values()}
        baseline |= VERIFY.expected_loopbacks()
        child = mock.Mock()
        child.poll.return_value = None
        child.terminate.side_effect = lambda: events.append("terminate")
        child.kill.side_effect = lambda: events.append("kill")
        waits = 0

        def parent_signal():
            events.append(("parent-signal", signum))
            handler = handlers[signum]
            if handler != signal.SIG_IGN:
                handler(signum, None)

        def wait(timeout):
            nonlocal waits
            waits += 1
            events.append(("wait", timeout))
            if cleanup_signal_at == "wait" and waits == 1:
                parent_signal()
            if stubborn_child and waits == 1:
                raise subprocess.TimeoutExpired("mock collector", timeout)
            return 143

        child.wait.side_effect = wait

        def launch(_args, *, stdout, stderr):
            self.assertEqual(_args[_args.index("--bgp-identifier") + 1], "192.0.2.101")
            stdout.write("".join(f"WATCH upsert {value}\n" for value in sorted(baseline)))
            stdout.flush()
            return child

        def register_handler(selected, handler):
            handlers[selected] = handler

        def command(*args):
            node, state = args[1], args[-1]
            events.append((node, state))
            if state == "up":
                if cleanup_signal_at == node:
                    parent_signal()
                # No real process signal is sent: inspect the handlers installed for cleanup.
                self.assertEqual(handlers[signal.SIGINT], signal.SIG_IGN)
                self.assertEqual(handlers[signal.SIGTERM], signal.SIG_IGN)
                if restore_failure and node == "clab-bgpls-p1":
                    raise RuntimeError("mock p1 restore failure")
            return ""

        def checkpoint(description, _condition, _process=None):
            if description == "both p1-p2 directed links withdrawn":
                if cleanup_signal_at:
                    events.append("ordinary-timeout")
                    raise TimeoutError("mock convergence timeout before any parent signal")
                parent_signal()

        with tempfile.TemporaryDirectory(prefix="bgpls-verifier-cleanup-test-") as directory:
            state = Path(directory)
            lab = VERIFY.Lab(state, state)
            lab.state_info = {"asn": 65001}
            lab.preflight = mock.Mock()
            lab.docker = mock.Mock(side_effect=command)
            lab.neighbor = mock.Mock(return_value=neighbor())
            lab.save = mock.Mock()
            lab.vty = mock.Mock(return_value={})
            args = argparse.Namespace(state=directory, binary=sys.executable, churn=True, signal="INT")
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(VERIFY, "verification_lock", return_value=contextlib.nullcontext()))
                stack.enter_context(mock.patch.object(VERIFY.signal, "signal", side_effect=register_handler))
                stack.enter_context(mock.patch.object(VERIFY, "Lab", return_value=lab))
                stack.enter_context(mock.patch.object(VERIFY, "wait_until", side_effect=checkpoint))
                stack.enter_context(mock.patch.object(VERIFY.subprocess, "Popen", side_effect=launch))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                VERIFY.install_signal_handlers()
                if restore_failure:
                    expected_error = RuntimeError
                elif cleanup_signal_at:
                    expected_error = TimeoutError
                else:
                    expected_error = VERIFY.VerificationInterrupted
                with self.assertRaises(expected_error) as caught:
                    VERIFY.run(args)
                if not restore_failure and not cleanup_signal_at:
                    self.assertEqual(caught.exception.signum, signum)
                    self.assertEqual(128 + caught.exception.signum, 130 if signum == signal.SIGINT else 143)

        if cleanup_signal_at:
            self.assertEqual(events.count(("parent-signal", signum)), 1)
            events.remove(("parent-signal", signum))
        self.assertEqual(events[:5], [
            ("clab-bgpls-p1", "down"),
            ("clab-bgpls-p2", "down"),
            "ordinary-timeout" if cleanup_signal_at else ("parent-signal", signum),
            ("clab-bgpls-p1", "up"),
            ("clab-bgpls-p2", "up"),
        ])
        self.assertEqual(events[5:7], ["terminate", ("wait", 15)])
        child.terminate.assert_called_once()
        if stubborn_child:
            self.assertEqual(events[7:], ["kill", ("wait", 5)])
            child.kill.assert_called_once()
        else:
            self.assertEqual(len(events), 7)
            child.kill.assert_not_called()
        child.send_signal.assert_not_called()

    def test_parent_sigint_restores_links_then_reaps_its_child(self):
        self.exercise_interruption(signal.SIGINT)

    def test_parent_sigterm_restores_links_then_reaps_its_child(self):
        self.exercise_interruption(signal.SIGTERM)

    def test_stubborn_child_is_killed_and_reaped_after_graceful_timeout(self):
        self.exercise_interruption(signal.SIGTERM, stubborn_child=True)

    def test_child_is_reaped_even_if_one_link_cannot_be_restored(self):
        self.exercise_interruption(signal.SIGTERM, restore_failure=True)

    def test_first_signal_during_either_endpoint_restoration_cannot_skip_cleanup(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            for node in ("clab-bgpls-p1", "clab-bgpls-p2"):
                with self.subTest(signum=signum, node=node):
                    self.exercise_interruption(signum, cleanup_signal_at=node)

    def test_first_signal_during_child_wait_cannot_skip_reaping_or_timeout_escalation(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            for stubborn in (False, True):
                with self.subTest(signum=signum, stubborn=stubborn):
                    self.exercise_interruption(signum, cleanup_signal_at="wait", stubborn_child=stubborn)


class OutcomeEvidenceTests(unittest.TestCase):
    def test_failure_evidence_error_never_replaces_primary_error(self):
        primary = AssertionError("capture failure")
        lab, cleanup = mock.Mock(), mock.Mock()
        lab.save.side_effect = OSError("evidence disk unavailable")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(AssertionError) as caught:
            with VERIFY.verification_cleanup(lab, "ipv6", cleanup):
                raise primary
        self.assertIs(caught.exception, primary)
        cleanup.assert_called_once()
        self.assertIn("could not save failure evidence", stderr.getvalue())
        self.assertEqual(lab.save.call_args.args[0], "failure")

    def test_failure_evidence_error_preserves_primary_and_cleanup_errors(self):
        primary, finalizer = AssertionError("capture failure"), OSError("cleanup failure")
        lab = mock.Mock()
        lab.save.side_effect = OSError("evidence disk unavailable")
        cleanup = mock.Mock(side_effect=finalizer)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(VERIFY.VerificationFailure) as caught:
            with VERIFY.verification_cleanup(lab, "ipv6", cleanup):
                raise primary
        self.assertIs(caught.exception.primary_error, primary)
        self.assertIs(caught.exception.cleanup_error, finalizer)
        self.assertIs(caught.exception.__cause__, primary)

    def test_unavailable_stderr_cannot_replace_original_failure(self):
        primary = AssertionError("capture failure")
        lab = mock.Mock()
        lab.save.side_effect = OSError("evidence disk unavailable")
        for diagnostic_error in (OSError("stderr unavailable"), ValueError("closed stderr")):
            stderr = mock.Mock()
            stderr.write.side_effect = diagnostic_error
            with self.subTest(error=diagnostic_error), mock.patch.object(VERIFY.sys, "stderr", stderr), \
                    self.assertRaises(AssertionError) as caught:
                with VERIFY.verification_cleanup(lab, "ipv6", mock.Mock()):
                    raise primary
            self.assertIs(caught.exception, primary)

    def test_primary_signal_is_preserved_after_successful_cleanup(self):
        primary = VERIFY.VerificationInterrupted(signal.SIGINT)
        cleanup, lab = mock.Mock(), mock.Mock()
        with self.assertRaises(VERIFY.VerificationInterrupted) as caught:
            with VERIFY.verification_cleanup(lab, "ipv6", cleanup):
                raise primary
        self.assertIs(caught.exception, primary)
        cleanup.assert_called_once()

    def test_save_failure_cannot_publish_partial_result_or_replace_existing_evidence(self):
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                lab = VERIFY.Lab(output, output)
                path = output / "result.json"
                if existing:
                    path.write_text('{"previous": true}\n')
                with mock.patch.object(VERIFY.Path, "replace", side_effect=OSError("rename failed")):
                    with self.assertRaisesRegex(OSError, "rename failed"):
                        lab.save("result", {"passed": True})
                if existing:
                    self.assertEqual(path.read_text(), '{"previous": true}\n')
                else:
                    self.assertFalse(path.exists())
                self.assertEqual(list(output.glob(".result-*.json")), [])

    def test_result_and_failure_write_failures_preserve_result_error_without_success_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            lab = VERIFY.Lab(output, output)
            primary = OSError("rename failed")
            with mock.patch.object(VERIFY.Path, "replace", side_effect=primary), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(OSError) as caught:
                VERIFY.publish_result(lab, "ipv6", {"passed": True})
            self.assertIs(caught.exception, primary)
            self.assertFalse((output / "result.json").exists())
            self.assertFalse((output / "failure.json").exists())
            self.assertEqual(list(output.iterdir()), [])

    def test_partial_json_write_cannot_publish_success_or_damage_previous_evidence(self):
        original = VERIFY.tempfile.NamedTemporaryFile
        primary = OSError("mock full evidence filesystem")
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                lab = VERIFY.Lab(output, output)
                path = output / "result.json"
                if existing:
                    path.write_text('{"previous": true}\n')
                def partial_file(**kwargs):
                    stream = original(**kwargs)
                    write = stream.write
                    def partial_write(data):
                        write(data[:20])
                        stream.flush()
                        raise primary
                    stream.write = partial_write
                    return stream
                with mock.patch.object(VERIFY.tempfile, "NamedTemporaryFile", side_effect=partial_file), \
                        self.assertRaises(OSError) as caught:
                    lab.save("result", {"passed": True, "details": "must never be visible"})
                self.assertIs(caught.exception, primary)
                if existing:
                    self.assertEqual(path.read_text(), '{"previous": true}\n')
                else:
                    self.assertFalse(path.exists())
                self.assertEqual(list(output.glob(".result-*.json")), [])


if __name__ == "__main__":
    unittest.main()
