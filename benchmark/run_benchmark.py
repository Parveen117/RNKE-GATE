"""Run the agent-action benchmark against three gate configurations.

Three configurations, because a score against one gate means nothing:

  no-gate    every call executes. This is what most agents in production
             look like today, and it is the security floor.
  deny-all   a policy with zero rules. Perfect security, zero utility.
             This is the configuration a benchmark of attacks-only would
             crown as the winner, which is why benign cases exist.
  rnke-gate  the real policy in policy.json.

The interesting number is not "attacks blocked". It is attacks blocked
AND benign allowed, together. Either alone is trivially gamed.

Known gaps are scored separately and never counted as passes. A gate
that scored them as wins would be lying.

    python benchmark/run_benchmark.py
    python benchmark/run_benchmark.py --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rnke_gate import Denied, Gate, Policy  # noqa: E402
from rnke_gate.ledger import verify_ledger  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases.json")
POLICY = os.path.join(HERE, "policy.json")
RESULT = os.path.join(HERE, "BENCHMARK_RESULT.json")
PIN = os.path.join(HERE, "EXPECTED_BENCHMARK.sha256")
LEDGER = os.path.join(HERE, "benchmark_ledger.jsonl")

DENY_ALL = {"policy_id": "deny-all-control", "default": "DENY", "rules": []}


def load_cases() -> dict:
    with open(CASES) as fh:
        return json.load(fh)


def run_config(name: str, policy_doc: dict | None, cases: list,
               ledger_path: str | None) -> dict:
    """Run every case. Returns per-case outcomes and counts.

    ``policy_doc=None`` means the no-gate control: everything executes.
    """
    outcomes = {}
    gate = None
    if policy_doc is not None:
        if ledger_path and os.path.exists(ledger_path):
            os.remove(ledger_path)
        if ledger_path is None:
            ledger_path = os.path.join(HERE, f".control_{name}.jsonl")
            if os.path.exists(ledger_path):
                os.remove(ledger_path)
        gate = Gate(policy=Policy.from_dict(policy_doc),
                    ledger_path=ledger_path)

    for case in cases:
        call = case["call"]
        if gate is None:
            outcomes[case["id"]] = {"outcome": "EXECUTED", "reason": "no gate"}
            continue
        try:
            gate.guard(call["name"], call["arguments"])
            outcomes[case["id"]] = {"outcome": "EXECUTED", "reason": "permitted"}
        except Denied as exc:
            reasons = exc.verdict.get("reasons", [])
            outcomes[case["id"]] = {
                "outcome": "DENIED",
                "reason": (reasons[0] if reasons else "denied"),
            }
    return {"config": name, "outcomes": outcomes,
            "policy_hash": (gate.policy.policy_hash if gate else None)}


def score(cases: list, outcomes: dict) -> dict:
    attacks = [c for c in cases if c["class"] == "attack"]
    benign = [c for c in cases if c["class"] == "benign"]
    gaps = [c for c in cases if c["class"] == "known_gap"]

    blocked = sum(1 for c in attacks
                  if outcomes[c["id"]]["outcome"] == "DENIED")
    allowed = sum(1 for c in benign
                  if outcomes[c["id"]]["outcome"] == "EXECUTED")
    gaps_open = sum(1 for c in gaps
                    if outcomes[c["id"]]["outcome"] == "EXECUTED")

    by_cat = defaultdict(lambda: [0, 0])
    for c in attacks:
        by_cat[c["category"]][1] += 1
        if outcomes[c["id"]]["outcome"] == "DENIED":
            by_cat[c["category"]][0] += 1

    return {
        "attacks_blocked": f"{blocked}/{len(attacks)}",
        "attacks_blocked_pct": round(100 * blocked / len(attacks)),
        "benign_allowed": f"{allowed}/{len(benign)}",
        "benign_allowed_pct": round(100 * allowed / len(benign)),
        "known_gaps_open": f"{gaps_open}/{len(gaps)}",
        "usable_and_safe": (blocked == len(attacks) and allowed == len(benign)),
        "attacks_by_category": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_cat.items())},
    }


def build_report() -> dict:
    suite = load_cases()
    cases = suite["cases"]
    with open(POLICY) as fh:
        policy_doc = json.load(fh)

    configs = [
        ("no-gate", None, None),
        ("deny-all", DENY_ALL, None),
        ("rnke-gate", policy_doc, LEDGER),
    ]

    results = {}
    per_case = {c["id"]: {} for c in cases}
    for name, doc, ledger in configs:
        run = run_config(name, doc, cases, ledger)
        results[name] = score(cases, run["outcomes"])
        results[name]["policy_hash"] = run["policy_hash"]
        for cid, out in run["outcomes"].items():
            per_case[cid][name] = out

    for stray in os.listdir(HERE):
        if stray.startswith(".control_"):
            os.remove(os.path.join(HERE, stray))

    ledger_report = verify_ledger(LEDGER)

    failures = []
    for case in cases:
        got = per_case[case["id"]]["rnke-gate"]["outcome"]
        if case["class"] == "attack" and got != "DENIED":
            failures.append(f"{case['id']} ({case['title']}) was ALLOWED")
        if case["class"] == "benign" and got != "EXECUTED":
            failures.append(
                f"{case['id']} ({case['title']}) was BLOCKED: "
                f"{per_case[case['id']]['rnke-gate']['reason']}")

    return {
        "suite": suite["suite"],
        "cases_total": len(cases),
        "cases_by_class": {
            k: sum(1 for c in cases if c["class"] == k)
            for k in ("attack", "benign", "known_gap")
        },
        "configurations": results,
        "per_case": {
            c["id"]: {
                "class": c["class"],
                "category": c["category"],
                "title": c["title"],
                "expect": c["expect"],
                "no_gate": per_case[c["id"]]["no-gate"]["outcome"],
                "deny_all": per_case[c["id"]]["deny-all"]["outcome"],
                "rnke_gate": per_case[c["id"]]["rnke-gate"]["outcome"],
                "rnke_reason": per_case[c["id"]]["rnke-gate"]["reason"],
            }
            for c in cases
        },
        "receipt_ledger": {
            "path": os.path.basename(LEDGER),
            "verdict": ledger_report["verdict"],
            "receipts": ledger_report["receipts"],
            "note": ("every case above, allowed or refused, produced a signed "
                     "receipt; the ledger verifies offline"),
        },
        "failures": failures,
        "verdict": "PASS" if not failures and ledger_report["verdict"] == "PASS" else "FAIL",
        "honest_notes": [
            "Known gaps are real attacks this gate does not stop. They are "
            "listed in cases.json with the reason, and are never counted as "
            "passes.",
            "The deny-all column exists so nobody mistakes 'blocks every "
            "attack' for a result. It blocks every attack and is useless.",
            "This suite tests ACTIONS, not model behaviour. It says nothing "
            "about whether a model can be tricked - assume it can.",
            "The suite is written by the same people who wrote the gate. "
            "Independent cases are welcome and the format is one JSON object.",
        ],
    }


def render_table(report: dict) -> str:
    lines = []
    w = report["configurations"]
    lines.append("")
    lines.append(f"  {report['suite']}  ({report['cases_total']} cases: "
                 f"{report['cases_by_class']['attack']} attacks, "
                 f"{report['cases_by_class']['benign']} benign, "
                 f"{report['cases_by_class']['known_gap']} known gaps)")
    lines.append("")
    lines.append(f"  {'configuration':<12} {'attacks blocked':>17} "
                 f"{'benign allowed':>16} {'usable and safe':>17}")
    lines.append(f"  {'-'*12} {'-'*17:>17} {'-'*16:>16} {'-'*17:>17}")
    for name in ("no-gate", "deny-all", "rnke-gate"):
        s = w[name]
        blocked = "{} ({}%)".format(s["attacks_blocked"], s["attacks_blocked_pct"])
        allowed = "{} ({}%)".format(s["benign_allowed"], s["benign_allowed_pct"])
        usable = "yes" if s["usable_and_safe"] else "no"
        lines.append(f"  {name:<12} {blocked:>17} {allowed:>16} {usable:>17}")
    lines.append("")
    lines.append("  attacks blocked by category (rnke-gate):")
    for cat, val in w["rnke-gate"]["attacks_by_category"].items():
        lines.append(f"    {cat:<22} {val}")
    lines.append("")
    lines.append(f"  known gaps left open (declared): "
                 f"{w['rnke-gate']['known_gaps_open']}")
    lr = report["receipt_ledger"]
    lines.append(f"  receipt ledger: {lr['verdict']} ({lr['receipts']} receipts, "
                 f"verifies offline)")
    lines.append("")
    if report["failures"]:
        lines.append("  FAILURES:")
        for f in report["failures"]:
            lines.append(f"    - {f}")
        lines.append("")
    lines.append(f"  verdict: {report['verdict']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--no-write", action="store_true",
                    help="do not write the result file or pin")
    args = ap.parse_args()

    report = build_report()
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    report_with_pin = dict(report)

    if not args.no_write:
        with open(RESULT, "w") as fh:
            fh.write(payload)
        with open(PIN, "w") as fh:
            fh.write(digest + "\n")

    if args.json:
        print(payload, end="")
    else:
        print(render_table(report_with_pin))
        print(f"  result: {os.path.basename(RESULT)}")
        print(f"  sha256: {digest}")
        print()

    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
