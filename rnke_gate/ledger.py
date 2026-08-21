"""Capsules and the receipt ledger.

Three capsule types, each self-hashed and signed:

  intent   — what the agent asked to do (signed by the AGENT key)
  verdict  — what the gate decided, and under which policy (gate key)
  receipt  — the durable record, chained to intent + verdict + the
             previous receipt (gate key)

The receipt's ``parents`` field is what makes the ledger auditable: a
receipt names the exact intent it authorised, the exact verdict that
authorised it, and the exact receipt before it. Remove or edit any
record in the middle and the chain stops verifying at that point — and
``verify_ledger`` reports the line number where it broke.

The ledger stores hashes of tool results, never the results themselves.
A receipt proves *what was authorised and what came back*, without the
ledger becoming a copy of your data.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .canonical import digest, seal, self_hash_ok
from .identity import Identity, verify_capsule

INTENT = "rnke.intent.v0"
VERDICT = "rnke.verdict.v0"
RECEIPT = "rnke.receipt.v0"
GENESIS = "0" * 64


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_intent(agent: Identity, tool: str, params: dict, nonce: str,
                issued_at: str | None = None) -> dict:
    body = {
        "capsule": INTENT,
        "agent_id": agent.id,
        "agent_public_b64": agent.public_b64,
        "tool": tool,
        "params": params,
        "params_hash": digest(params),
        "nonce": nonce,
        "issued_at": issued_at or now_iso(),
    }
    return agent.sign_capsule(seal(body))


def make_verdict(gate: Identity, intent: dict, decision: str, reasons: list,
                 policy_hash: str, policy_id: str,
                 rule_id: str | None) -> dict:
    body = {
        "capsule": VERDICT,
        "gate_id": gate.id,
        "gate_public_b64": gate.public_b64,
        "intent_hash": intent["self_hash"],
        "tool": intent["tool"],
        "decision": decision,
        "reasons": reasons,
        "rule_id": rule_id,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "decided_at": now_iso(),
    }
    return gate.sign_capsule(seal(body))


def make_receipt(gate: Identity, intent: dict, verdict: dict,
                 prev_hash: str, outcome: str,
                 result_hash: str | None = None,
                 error: str | None = None) -> dict:
    body = {
        "capsule": RECEIPT,
        "gate_id": gate.id,
        "gate_public_b64": gate.public_b64,
        "parents": {
            "intent": intent["self_hash"],
            "verdict": verdict["self_hash"],
            "previous_receipt": prev_hash,
        },
        "agent_id": intent["agent_id"],
        "tool": intent["tool"],
        "params_hash": intent["params_hash"],
        "decision": verdict["decision"],
        "rule_id": verdict.get("rule_id"),
        "policy_hash": verdict["policy_hash"],
        "outcome": outcome,          # EXECUTED | REFUSED | FAILED
        "result_hash": result_hash,  # sha256 of the tool result, or null
        "error": error,
        "recorded_at": now_iso(),
    }
    return gate.sign_capsule(seal(body))


class Ledger:
    """Append-only JSONL file of receipts, plus the intent and verdict
    each receipt points at. One JSON object per line, never rewritten."""

    def __init__(self, path: str):
        self.path = path
        self.head = self._recover_head()

    def _recover_head(self) -> str:
        if not os.path.exists(self.path):
            return GENESIS
        head = GENESIS
        with open(self.path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("capsule") == RECEIPT:
                    head = rec["self_hash"]
        return head

    def append(self, *capsules: dict) -> None:
        with open(self.path, "a") as fh:
            for cap in capsules:
                fh.write(json.dumps(cap, sort_keys=True,
                                    separators=(",", ":")) + "\n")
                if cap.get("capsule") == RECEIPT:
                    self.head = cap["self_hash"]
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                # Not every target supports fsync (os.devnull, some network
                # filesystems). Durability is best-effort; correctness of the
                # chain does not depend on it.
                pass

    def records(self) -> list:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out


def verify_ledger(path: str, expected_gate_key: str | None = None) -> dict:
    """Recompute every hash, check every signature, walk the chain.

    Returns a report: {'verdict': 'PASS'|'FAIL', 'receipts': n,
    'problems': [...]}. Any problem at all is a FAIL — there is no
    partial credit in an audit trail.

    A valid signature alone proves nothing: an attacker with write access
    to the file can append records signed by a key they own. So every
    gate-signed capsule must be signed by the SAME gate key — the one
    that opened the ledger, or ``expected_gate_key`` when the auditor
    knows which key to demand.
    """
    problems: list[str] = []
    gate_key: str | None = expected_gate_key
    gate_key_source = "expected_gate_key argument" if expected_gate_key else None
    by_hash: dict[str, dict] = {}
    receipts: list[tuple[int, dict]] = []

    if not os.path.exists(path):
        return {"verdict": "FAIL", "receipts": 0,
                "problems": [f"ledger not found: {path}"]}

    with open(path) as fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                cap = json.loads(raw)
            except json.JSONDecodeError as exc:
                problems.append(f"line {lineno}: not valid JSON ({exc})")
                continue
            kind = cap.get("capsule")
            if kind not in (INTENT, VERDICT, RECEIPT):
                problems.append(f"line {lineno}: unknown capsule {kind!r}")
                continue
            if not self_hash_ok(cap):
                problems.append(
                    f"line {lineno}: self_hash does not match content "
                    f"({kind}) — record was edited")
                continue
            key = ("agent_public_b64" if kind == INTENT else "gate_public_b64")
            if not verify_capsule(cap, cap.get(key, "")):
                problems.append(
                    f"line {lineno}: signature invalid ({kind}) — not signed "
                    f"by the key it names")
                continue
            if kind in (VERDICT, RECEIPT):
                this_key = cap.get("gate_public_b64", "")
                if gate_key is None:
                    gate_key, gate_key_source = this_key, f"line {lineno}"
                elif this_key != gate_key:
                    problems.append(
                        f"line {lineno}: signed by a DIFFERENT gate key "
                        f"({cap.get('gate_id')}) than the rest of the ledger "
                        f"(established at {gate_key_source}) — a record was "
                        f"appended by someone else")
                    continue
            by_hash[cap["self_hash"]] = cap
            if kind == RECEIPT:
                receipts.append((lineno, cap))

    expected_prev = GENESIS
    for lineno, rec in receipts:
        parents = rec.get("parents", {})
        if parents.get("previous_receipt") != expected_prev:
            problems.append(
                f"line {lineno}: chain broken — receipt points at "
                f"{parents.get('previous_receipt')!r}, expected "
                f"{expected_prev!r} (a record was removed or reordered)")
        intent = by_hash.get(parents.get("intent"))
        verdict = by_hash.get(parents.get("verdict"))
        if intent is None:
            problems.append(f"line {lineno}: intent capsule missing from ledger")
        if verdict is None:
            problems.append(f"line {lineno}: verdict capsule missing from ledger")
        if intent and verdict:
            if verdict.get("intent_hash") != intent.get("self_hash"):
                problems.append(
                    f"line {lineno}: verdict authorises a different intent")
            if rec.get("params_hash") != intent.get("params_hash"):
                problems.append(
                    f"line {lineno}: receipt params_hash does not match its "
                    f"intent — params were swapped after authorisation")
            if rec.get("decision") != verdict.get("decision"):
                problems.append(
                    f"line {lineno}: receipt decision contradicts its verdict")
            if verdict.get("decision") == "DENY" and rec.get("outcome") == "EXECUTED":
                problems.append(
                    f"line {lineno}: DENIED action recorded as EXECUTED")
        expected_prev = rec["self_hash"]

    seen_nonces: dict[str, int] = {}
    for lineno, rec in receipts:
        intent = by_hash.get(rec.get("parents", {}).get("intent"))
        if not intent:
            continue
        nonce = intent.get("nonce")
        if nonce in seen_nonces:
            problems.append(
                f"line {lineno}: nonce {nonce!r} replayed (first seen at line "
                f"{seen_nonces[nonce]})")
        else:
            seen_nonces[nonce] = lineno

    return {
        "verdict": "FAIL" if problems else "PASS",
        "receipts": len(receipts),
        "gate_key": gate_key,
        "problems": problems,
    }
