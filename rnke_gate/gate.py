"""The gate.

Usage is meant to be one line around an existing tool call:

    gate = Gate(policy=Policy.load("policy.json"), ledger_path="ledger.jsonl")

    @gate.guarded("fs.read")
    def read_file(path: str) -> str:
        return open(path).read()

Every call now produces three records (intent, verdict, receipt) and
either runs or raises ``Denied``. Nothing about the tool changes; the
model does not know the gate exists, which is the point — an agent
cannot talk its way past a gate it cannot address.

Replay protection: an intent nonce may be used once per gate process
and, on restart, is re-checked against the ledger.
"""

from __future__ import annotations

import secrets
from typing import Any, Callable

from .canonical import digest
from .identity import Identity
from .ledger import (
    GENESIS,
    Ledger,
    make_intent,
    make_receipt,
    make_verdict,
)
from .policy import ALLOW, DENY, Policy


class Denied(PermissionError):
    """Raised when the gate refuses an action. Carries the verdict."""

    def __init__(self, verdict: dict):
        self.verdict = verdict
        reasons = "; ".join(verdict.get("reasons", [])) or "no reason recorded"
        super().__init__(
            f"RNKE gate DENIED {verdict.get('tool')!r}: {reasons}"
        )


class Gate:
    def __init__(self, policy: Policy, ledger_path: str,
                 gate_identity: Identity | None = None,
                 agent_identity: Identity | None = None):
        self.policy = policy
        self.ledger = Ledger(ledger_path)
        self.gate_identity = gate_identity or Identity.generate()
        self.agent_identity = agent_identity or Identity.generate()
        self._nonces = self._load_nonces()

    def _load_nonces(self) -> set:
        used = set()
        for rec in self.ledger.records():
            if rec.get("capsule") == "rnke.intent.v0":
                used.add(rec.get("nonce"))
        return used

    # -- core ---------------------------------------------------------

    def guard(self, tool: str, params: dict, run: Callable[[], Any] | None = None) -> Any:
        """Authorise, record, and (if allowed) run.

        Returns the result of ``run`` when permitted. Raises ``Denied``
        when refused. If ``run`` raises, the failure is recorded as
        FAILED and the exception is re-raised — a crash never silently
        becomes an unrecorded action.
        """
        nonce = secrets.token_hex(16)
        intent = make_intent(self.agent_identity, tool, params, nonce)

        if nonce in self._nonces:
            decision, reasons, rule_id = DENY, ["nonce replay"], None
        else:
            self._nonces.add(nonce)
            d = self.policy.evaluate(tool, params)
            decision, reasons, rule_id = d.decision, d.reasons, d.rule_id

        verdict = make_verdict(
            self.gate_identity, intent, decision, reasons,
            self.policy.policy_hash, self.policy.policy_id, rule_id,
        )

        if decision != ALLOW:
            receipt = make_receipt(
                self.gate_identity, intent, verdict, self.ledger.head,
                outcome="REFUSED",
            )
            self.ledger.append(intent, verdict, receipt)
            raise Denied(verdict)

        if run is None:
            receipt = make_receipt(
                self.gate_identity, intent, verdict, self.ledger.head,
                outcome="EXECUTED", result_hash=None,
            )
            self.ledger.append(intent, verdict, receipt)
            return None

        try:
            result = run()
        except Exception as exc:  # noqa: BLE001 - recorded then re-raised
            receipt = make_receipt(
                self.gate_identity, intent, verdict, self.ledger.head,
                outcome="FAILED", error=f"{type(exc).__name__}: {exc}",
            )
            self.ledger.append(intent, verdict, receipt)
            raise

        receipt = make_receipt(
            self.gate_identity, intent, verdict, self.ledger.head,
            outcome="EXECUTED", result_hash=_result_hash(result),
        )
        self.ledger.append(intent, verdict, receipt)
        return result

    # -- ergonomics ---------------------------------------------------

    def guarded(self, tool: str) -> Callable:
        """Decorator form. Keyword arguments become the policy params."""

        def wrap(fn: Callable) -> Callable:
            def inner(**kwargs):
                return self.guard(tool, kwargs, lambda: fn(**kwargs))

            inner.__name__ = getattr(fn, "__name__", tool)
            inner.__doc__ = fn.__doc__
            inner.rnke_tool = tool
            return inner

        return wrap

    def dispatch(self, tool_calls: list, registry: dict) -> list:
        """Run a batch of model-emitted tool calls through the gate.

        ``tool_calls`` is a list of {'name': str, 'arguments': dict} —
        the shape every major tool-calling API produces. Denied calls
        do not raise here: they come back as refusal results you can
        hand straight back to the model, which is usually what you want
        in an agent loop.
        """
        out = []
        for call in tool_calls:
            name = call.get("name")
            args = call.get("arguments") or {}
            fn = registry.get(name)
            if fn is None:
                out.append({"name": name, "status": "DENIED",
                            "detail": f"tool {name!r} is not registered"})
                continue
            try:
                value = self.guard(name, args, lambda f=fn, a=args: f(**a))
                out.append({"name": name, "status": "EXECUTED", "result": value})
            except Denied as exc:
                out.append({"name": name, "status": "DENIED",
                            "detail": str(exc),
                            "verdict_hash": exc.verdict["self_hash"]})
        return out


def _result_hash(result: Any) -> str:
    """Hash of the tool result. Only the hash is ever stored."""
    if isinstance(result, (bytes, bytearray)):
        from .canonical import sha256_hex
        return sha256_hex(bytes(result))
    try:
        return digest(result)
    except (ValueError, TypeError):
        from .canonical import sha256_hex
        return sha256_hex(repr(result).encode("utf-8"))
