#!/usr/bin/env python3
"""Wire-phase invariants for scoped metric probes; no lab, runtime, or file I/O."""

import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "attribute_phase_validation", Path(__file__).resolve().parents[1] / "attribute-validation.py"
)
VALIDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATE)

TARGET = "link 0000.0000.0003 10.254.0.8 → 0000.0000.0004 10.254.0.9"
SIBLING = "link 0000.0000.0004 10.254.0.9 → 0000.0000.0003 10.254.0.8"
TARGET_KEY = "link:complete-identity-p1-to-p2"
SIBLING_KEY = "link:complete-identity-p2-to-p1"


def upsert(metric=10, *, key=TARGET_KEY, display=TARGET):
    return {"operation": "upsert", "key": key, "display": display, "availability": "present",
            "attributes": {"igpMetric": metric, "maximumLinkBandwidth": 1250000,
                           "maximumReservableBandwidth": 1250000, "unreservedBandwidth": [1250000] * 8}}


def withdraw(*, key=TARGET_KEY, display=TARGET):
    return {"operation": "withdraw", "key": key, "display": display}


def sibling(metric=10):
    return upsert(metric, key=SIBLING_KEY, display=SIBLING)


def probe(start=2, end=4, *, other_range=None):
    return {"display": TARGET, "before": 10, "target": 20,
            "eventRanges": {"frr": {"start": start, "end": end},
                            "ceos": other_range if other_range is not None else {"start": start, "end": end}}}


class AttributePhaseTests(unittest.TestCase):
    def assert_rejected(self, events, phases, producer="frr"):
        with self.assertRaises((AssertionError, ValueError)):
            VALIDATE.audit_probe_phases(events, phases, producer)

    def test_baseline_before_range_and_half_open_boundaries(self):
        events = [upsert(), sibling(), upsert(20), upsert(10), withdraw(), upsert()]
        for producer in ("frr", "ceos"):
            with self.subTest(producer=producer):
                # The withdrawal at index 4 belongs to the later physical-link
                # churn, not to this completed metric-only [2,4) phase.
                VALIDATE.audit_probe_phases(events, [probe()], producer)

    def test_identical_refreshes_and_unmodified_sibling_refreshes_are_legal(self):
        events = [upsert(), sibling(), upsert(10), sibling(), upsert(20), upsert(20),
                  sibling(), upsert(10), upsert(10)]
        VALIDATE.audit_probe_phases(events, [probe(2, 9)], "frr")

    def test_withdraw_readd_target_fails_even_when_complete_key_is_identical(self):
        events = [upsert(), sibling(), upsert(20), withdraw(), upsert(20), upsert(10)]
        self.assert_rejected(events, [probe(2, 6)])

    def test_temporary_sibling_withdrawal_cannot_hide_behind_final_restoration(self):
        events = [upsert(), sibling(), upsert(20), withdraw(key=SIBLING_KEY, display=SIBLING), sibling(), upsert(10)]
        self.assert_rejected(events, [probe(2, 6)])

    def test_temporary_new_object_cannot_hide_behind_its_withdrawal(self):
        extra_key, extra_display = "node:complete-new-node", "node 0000.0000.9999"
        extra = {"operation": "upsert", "key": extra_key, "display": extra_display,
                 "availability": "present", "attributes": {"name": "temporary"}}
        events = [upsert(), sibling(), upsert(20), extra, withdraw(key=extra_key, display=extra_display), upsert(10)]
        self.assert_rejected(events, [probe(2, 6)])

    def test_same_display_cannot_change_the_complete_identity_key(self):
        events = [upsert(), sibling(), upsert(20, key="link:different-AS-or-instance"), upsert(10)]
        self.assert_rejected(events, [probe()])

    def test_transient_reverse_or_other_attribute_changes_are_not_metric_only(self):
        bad_target_bandwidth = upsert(20)
        bad_target_bandwidth["attributes"]["maximumLinkBandwidth"] = 0
        bad_sibling_bandwidth = sibling()
        bad_sibling_bandwidth["attributes"]["unreservedBandwidth"][3] = 0
        bad_availability = sibling()
        bad_availability["availability"] = "discarded"
        for changed in (sibling(20), bad_sibling_bandwidth, bad_target_bandwidth, bad_availability, upsert(99)):
            with self.subTest(changed=changed):
                events = [upsert(), sibling(), upsert(20), changed, sibling(), upsert(10)]
                self.assert_rejected(events, [probe(2, 6)])
        refreshed = sibling()
        refreshed["evidence"] = [{"unknownTLV": "retained raw evidence may differ"}]
        VALIDATE.audit_probe_phases([upsert(), sibling(), upsert(20), refreshed, upsert(10)], [probe(2, 5)], "frr")

    def test_reusing_an_existing_key_with_target_display_is_not_stable_identity(self):
        # A key-set-only comparison would miss this substitution: both keys are
        # still present, but the 20 advertisement belongs to the wrong full key.
        events = [upsert(), sibling(), upsert(20, key=SIBLING_KEY), upsert(10)]
        self.assert_rejected(events, [probe()])

    def test_target_baseline_is_required_before_change(self):
        cases = [
            [upsert(20), sibling(), upsert(20), upsert(10)],
            [sibling(), sibling(), upsert(20), upsert(10)],
            [upsert(10), sibling(), upsert(10), upsert(10)],
            [upsert(10), sibling(), upsert(20), upsert(20)],
        ]
        for events in cases:
            with self.subTest(events=events):
                self.assert_rejected(events, [probe()])

    def test_restore_and_target_outside_the_phase_do_not_satisfy_it(self):
        events = [upsert(), sibling(), upsert(20), upsert(10), sibling(), sibling()]
        self.assert_rejected(events, [probe(2, 3)])
        self.assert_rejected(events, [probe(4, 6)])

    def test_bounds_are_per_producer_and_cannot_be_borrowed_from_the_other(self):
        events = [upsert(), sibling(), upsert(20), upsert(10), withdraw(), upsert()]
        phases = [probe(other_range={"start": 2, "end": 6})]
        VALIDATE.audit_probe_phases(events, phases, "frr")
        self.assert_rejected(events, phases, "ceos")
        phases = [probe(2, 6, other_range={"start": 2, "end": 4})]
        VALIDATE.audit_probe_phases(events, phases, "ceos")
        self.assert_rejected(events, phases, "frr")

    def test_missing_and_invalid_bounds_fail_closed(self):
        events = [upsert(), sibling(), upsert(20), upsert(10)]
        invalid_ranges = [None, {}, {"start": 2}, {"end": 4}, {"start": -1, "end": 4},
                          {"start": 2, "end": 5}, {"start": 4, "end": 2}, {"start": 2, "end": 2},
                          {"start": True, "end": 4}, {"start": 2, "end": False},
                          {"start": 2.0, "end": 4}, {"start": 2, "end": "4"}]
        for bounds in invalid_ranges:
            phase = probe()
            phase["eventRanges"]["frr"] = bounds
            with self.subTest(bounds=bounds):
                self.assert_rejected(events, [phase])
        for field in ("eventRanges",):
            phase = probe()
            del phase[field]
            self.assert_rejected(events, [phase])
        phase = probe()
        del phase["eventRanges"]["frr"]
        self.assert_rejected(events, [phase])

    def test_two_distinct_metric_phases_use_their_own_target_key(self):
        events = [upsert(), sibling(), upsert(20), upsert(10), sibling(20), sibling(10), withdraw(), upsert()]
        second = copy.deepcopy(probe(4, 6))
        second["display"] = SIBLING
        VALIDATE.audit_probe_phases(events, [probe(), second], "ceos")

    def test_no_probes_does_not_reject_normal_physical_churn(self):
        events = [upsert(), sibling(), withdraw(), upsert()]
        VALIDATE.audit_probe_phases(events, [], "frr")


class RecordedPhaseTests(unittest.TestCase):
    def test_real_exercise_records_complete_per_producer_event_boundaries(self):
        checks = VALIDATE.load("attribute-checks")
        targets = {
            "frr": "link 0000.0000.0003 10.254.0.8,2001:db8:6501:5:: → 0000.0000.0004 10.254.0.9,2001:db8:6501:5::1",
            "ceos": "link 0000.0000.0006 10.254.0.15,2001:db8:6501:8::1 → 0000.0000.0003 10.254.0.14,2001:db8:6501:8::",
        }

        def line(origin, metric):
            return (f"WATCH upsert {targets[origin]} attributes=present igp-metric={metric}"
                    " maximum-link-bandwidth=unavailable maximum-reservable-bandwidth=unavailable"
                    " unreserved-bandwidth=unavailable\n")

        # Each next UPDATE is initially only partly written to the log. Finishing
        # it later models concurrent log appends without rewriting prior bytes.
        phases = {
            "frr": [[line("frr", 20)], [line("frr", 10)], [line("ceos", 20)], [line("ceos", 10)]],
            "ceos": [[line("ceos", 10), line("frr", 20)], [line("frr", 10), line("frr", 10)],
                     [line("ceos", 20), line("ceos", 20)], [line("ceos", 10)]],
        }
        logs = {"frr": line("frr", 10) + line("ceos", 10),
                "ceos": line("frr", 10) + line("ceos", 10) + line("ceos", 10)}
        for producer in logs:
            logs[producer] += phases[producer][0][0][:24]
        trace = []
        phase_number = 0

        def advance():
            nonlocal phase_number
            for producer in logs:
                items = phases[producer][phase_number]
                logs[producer] += items[0][24:] + "".join(items[1:])
                following = phases[producer][phase_number + 1][0] if phase_number < 3 else line("frr", 10)
                logs[producer] += following[:24]
            phase_number += 1

        def read(producer):
            trace.append("read-" + producer)
            return logs[producer]

        class FakeProbe:
            def __init__(self, origin, *_callbacks, **_kwargs):
                self.origin = origin
                self.armed = False

            def prepare(self):
                trace.append("prepare-" + self.origin)

            def apply(self):
                if trace[-2:] != ["read-frr", "read-ceos"]:
                    raise AssertionError("start boundaries must be sampled immediately before apply")
                trace.append("apply-" + self.origin)
                self.armed = True
                advance()

            def restore(self):
                if self.armed:
                    trace.append("restore-" + self.origin)
                    advance()
                    self.armed = False

        lab = mock.Mock(state_info={"asn": 4200000001})
        lab.verify_routing.return_value = True
        with mock.patch.object(VALIDATE, "load", return_value=checks), mock.patch.object(checks, "MetricProbe", FakeProbe):
            run = VALIDATE.AttributeRun(lab, {producer: lambda producer=producer: read(producer) for producer in logs}, profile="ceos")
            run.ready = mock.Mock(return_value=True)
            run.capture = mock.Mock(side_effect=lambda phase: trace.append("capture-" + phase))

            def wait(description, condition):
                trace.append("wait-" + description)
                self.assertTrue(condition())

            run.exercise(wait)
            self.assertEqual(len(run.probe_results), 2)
            self.assertEqual(run.probe_results[0], {
                "display": targets["frr"], "before": 10, "target": 20,
                "eventRanges": {"frr": {"start": 2, "end": 4}, "ceos": {"start": 3, "end": 7}},
            })
            self.assertEqual(run.probe_results[1], {
                "display": targets["ceos"], "before": 10, "target": 20,
                "eventRanges": {"frr": {"start": 4, "end": 6}, "ceos": {"start": 7, "end": 10}},
            })
            for origin in ("frr", "ceos"):
                self.assertLess(trace.index("restore-" + origin), trace.index("capture-metric-" + origin + "-restored"))
            self.assertEqual(run.event_counts(), {"frr": 6, "ceos": 10})
            saved = {call.args[0]: call.args[1] for call in lab.save.call_args_list}
            self.assertEqual(saved["metric-frr-event-ranges"], run.probe_results[0])
            self.assertEqual(saved["metric-ceos-event-ranges"], run.probe_results[1])
            run.restore()
        lab.docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
