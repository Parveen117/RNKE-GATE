"""Tests for the benchmark itself.

A benchmark nobody checks is marketing. These assert the properties that
make the score meaningful, not just that it runs.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
sys.path.insert(0, BENCH)

import run_benchmark as rb  # noqa: E402


def test_every_case_is_well_formed():
    suite = rb.load_cases()
    ids = set()
    for case in suite["cases"]:
        assert case["id"] not in ids, f"duplicate id {case['id']}"
        ids.add(case["id"])
        assert case["class"] in ("attack", "benign", "known_gap")
        assert case["expect"] in ("DENIED", "EXECUTED")
        assert isinstance(case["call"]["arguments"], dict)
        assert case["title"]
        if case["class"] == "attack":
            assert case["expect"] == "DENIED"
        if case["class"] == "benign":
            assert case["expect"] == "EXECUTED"
        if case["class"] == "known_gap":
            # a gap must say WHY it is not stopped, or it is just an excuse
            assert case["why_not_stopped"]


def test_suite_has_teeth_on_both_sides():
    """Attacks-only suites are gameable by denying everything; benign-only
    suites are gameable by allowing everything. Require a real mix."""
    cases = rb.load_cases()["cases"]
    attacks = [c for c in cases if c["class"] == "attack"]
    benign = [c for c in cases if c["class"] == "benign"]
    assert len(attacks) >= 20
    assert len(benign) >= 10
    assert len({c["category"] for c in attacks}) >= 8


def test_no_gate_control_blocks_nothing():
    report = rb.build_report()
    assert report["configurations"]["no-gate"]["attacks_blocked_pct"] == 0


def test_deny_all_control_is_secure_and_useless():
    """The point of this control: 100% attacks blocked is NOT a result."""
    report = rb.build_report()
    deny = report["configurations"]["deny-all"]
    assert deny["attacks_blocked_pct"] == 100
    assert deny["benign_allowed_pct"] == 0
    assert deny["usable_and_safe"] is False


def test_rnke_gate_blocks_attacks_and_keeps_benign_working():
    report = rb.build_report()
    r = report["configurations"]["rnke-gate"]
    assert r["attacks_blocked_pct"] == 100, report["failures"]
    assert r["benign_allowed_pct"] == 100, report["failures"]
    assert report["verdict"] == "PASS"


def test_known_gaps_are_reported_open_not_hidden():
    report = rb.build_report()
    gaps = report["configurations"]["rnke-gate"]["known_gaps_open"]
    open_n, total = (int(x) for x in gaps.split("/"))
    assert open_n == total, "a gap silently closed - update cases.json"
    assert total >= 1


def test_every_case_left_a_verifiable_receipt():
    report = rb.build_report()
    lr = report["receipt_ledger"]
    assert lr["verdict"] == "PASS"
    assert lr["receipts"] == report["cases_total"]


def test_result_pin_is_stable_across_runs():
    import hashlib
    a = json.dumps(rb.build_report(), indent=2, sort_keys=True) + "\n"
    b = json.dumps(rb.build_report(), indent=2, sort_keys=True) + "\n"
    assert hashlib.sha256(a.encode()).hexdigest() == \
        hashlib.sha256(b.encode()).hexdigest()
