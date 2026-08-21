"""Policy: what an agent is allowed to do, and nothing more.

Design rules, in order of importance:

1. **Default DENY.** A tool that no rule names is refused. Adding a
   capability is an explicit, reviewable edit to a policy file.
2. **Fail closed on the unknown.** An unrecognised constraint operator,
   a malformed rule, a param the rule did not anticipate — every one of
   these DENIES. A gate that ignores what it does not understand is not
   a gate.
3. **Reasons are recorded.** Every verdict carries the rule that fired
   and why, so the receipt explains itself months later.

The policy file is content-addressed: its ``policy_hash`` goes into
every verdict, so you can always prove which rules were in force.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .canonical import digest

ALLOW = "ALLOW"
DENY = "DENY"

# Constraint operators. Anything not in here denies — see rule 2.
OPERATORS = (
    "eq",          # value equals literal
    "in",          # value is one of a list
    "prefix",      # string starts with
    "not_prefix",  # string does not start with
    "suffix",      # string ends with
    "max_len",     # len(value) <= int
    "max_int",     # int value <= int
    "min_int",     # int value >= int
    "forbid_substrings",  # none of these appear in the string
)

# Modifiers are not constraints: they change WHETHER a param is required,
# not what its value must be. Kept separate so an unknown *operator* still
# fails loudly while a known modifier does not get evaluated as one.
MODIFIERS = ("optional",)


class PolicyError(ValueError):
    """Raised at LOAD time for a malformed policy — never at call time.

    Loading is the moment to be loud; a policy that cannot be understood
    must not silently become a policy that allows things.
    """


@dataclass(frozen=True)
class Decision:
    decision: str
    reasons: list
    rule_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW


def _check_constraint(op: str, spec: Any, value: Any) -> tuple[bool, str]:
    if op == "eq":
        return (value == spec), f"expected {spec!r}, got {value!r}"
    if op == "in":
        if not isinstance(spec, list):
            return False, "'in' spec is not a list"
        return (value in spec), f"{value!r} not in allowed set"
    if op in ("prefix", "not_prefix", "suffix"):
        if not isinstance(value, str) or not isinstance(spec, str):
            return False, f"'{op}' needs string value and spec"
        if op == "prefix":
            return value.startswith(spec), f"{value!r} lacks prefix {spec!r}"
        if op == "not_prefix":
            return (not value.startswith(spec)), f"{value!r} has forbidden prefix {spec!r}"
        return value.endswith(spec), f"{value!r} lacks suffix {spec!r}"
    if op == "max_len":
        if not isinstance(spec, int):
            return False, "'max_len' spec is not an int"
        try:
            return (len(value) <= spec), f"length {len(value)} exceeds {spec}"
        except TypeError:
            return False, f"value of type {type(value).__name__} has no length"
    if op in ("max_int", "min_int"):
        if not isinstance(spec, int) or isinstance(value, bool) or not isinstance(value, int):
            return False, f"'{op}' needs an int value and an int spec"
        if op == "max_int":
            return (value <= spec), f"{value} exceeds max {spec}"
        return (value >= spec), f"{value} below min {spec}"
    if op == "forbid_substrings":
        if not isinstance(spec, list) or not isinstance(value, str):
            return False, "'forbid_substrings' needs a string value and list spec"
        for bad in spec:
            if isinstance(bad, str) and bad in value:
                return False, f"contains forbidden substring {bad!r}"
        return True, ""
    # Unreachable if the policy loaded cleanly, but fail closed anyway.
    return False, f"unknown operator {op!r}"


class Policy:
    """A loaded, validated policy. Immutable in use."""

    def __init__(self, doc: dict):
        self.doc = doc
        self.policy_id = doc.get("policy_id")
        self.default = doc.get("default", DENY)
        self.rules = doc.get("rules", [])
        self.policy_hash = digest(doc)
        self._by_tool: dict[str, list] = {}
        for rule in self.rules:
            self._by_tool.setdefault(rule["tool"], []).append(rule)

    # -- loading ------------------------------------------------------

    @classmethod
    def validate(cls, doc: Any) -> None:
        if not isinstance(doc, dict):
            raise PolicyError("policy must be a JSON object")
        if not isinstance(doc.get("policy_id"), str):
            raise PolicyError("policy_id (string) is required")
        default = doc.get("default", DENY)
        if default != DENY:
            raise PolicyError(
                "default must be 'DENY'; a default-allow policy is not a "
                "policy this gate will enforce"
            )
        rules = doc.get("rules", [])
        if not isinstance(rules, list):
            raise PolicyError("rules must be a list")
        seen_ids = set()
        for i, rule in enumerate(rules):
            where = f"rules[{i}]"
            if not isinstance(rule, dict):
                raise PolicyError(f"{where} is not an object")
            if not isinstance(rule.get("tool"), str):
                raise PolicyError(f"{where}.tool (string) is required")
            rid = rule.get("rule_id")
            if not isinstance(rid, str):
                raise PolicyError(f"{where}.rule_id (string) is required")
            if rid in seen_ids:
                raise PolicyError(f"duplicate rule_id {rid!r}")
            seen_ids.add(rid)
            params = rule.get("params", {})
            if not isinstance(params, dict):
                raise PolicyError(f"{where}.params must be an object")
            for pname, constraints in params.items():
                if not isinstance(constraints, dict):
                    raise PolicyError(
                        f"{where}.params.{pname} must be an object of constraints"
                    )
                for op, arg in constraints.items():
                    if op in MODIFIERS:
                        if not isinstance(arg, bool):
                            raise PolicyError(
                                f"{where}.params.{pname}.{op} must be a bool")
                        continue
                    if op not in OPERATORS:
                        raise PolicyError(
                            f"{where}.params.{pname}: unknown operator {op!r}; "
                            f"known operators are {', '.join(OPERATORS)}, "
                            f"known modifiers are {', '.join(MODIFIERS)}"
                        )
            extra = rule.get("forbid_extra_params", True)
            if not isinstance(extra, bool):
                raise PolicyError(f"{where}.forbid_extra_params must be a bool")

    @classmethod
    def from_dict(cls, doc: dict) -> "Policy":
        cls.validate(doc)
        return cls(doc)

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path) as fh:
            doc = json.load(fh)
        return cls.from_dict(doc)

    # -- evaluation ---------------------------------------------------

    def evaluate(self, tool: str, params: dict) -> Decision:
        """Decide a single call. Never raises: an internal problem is a
        DENY with the problem stated, because an exception escaping a
        gate is an open door."""
        try:
            return self._evaluate(tool, params)
        except Exception as exc:  # noqa: BLE001 - fail closed, deliberately
            return Decision(DENY, [f"gate error, failing closed: {exc}"])

    def _evaluate(self, tool: str, params: dict) -> Decision:
        if not isinstance(params, dict):
            return Decision(DENY, ["params must be an object"])
        candidates = self._by_tool.get(tool)
        if not candidates:
            return Decision(
                DENY,
                [f"no rule permits tool {tool!r} (default {self.default})"],
            )
        misses = []
        for rule in candidates:
            ok, why = self._rule_matches(rule, params)
            if ok:
                return Decision(
                    ALLOW,
                    [f"rule {rule['rule_id']} permits {tool!r}"],
                    rule["rule_id"],
                )
            misses.append(f"rule {rule['rule_id']}: {why}")
        return Decision(DENY, misses)

    @staticmethod
    def _rule_matches(rule: dict, params: dict) -> tuple[bool, str]:
        spec = rule.get("params", {})
        if rule.get("forbid_extra_params", True):
            extra = sorted(set(params) - set(spec))
            if extra:
                return False, f"unconstrained params present: {', '.join(extra)}"
        for pname, constraints in spec.items():
            if pname not in params:
                if constraints.get("optional") is True:
                    continue
                return False, f"required param {pname!r} missing"
            value = params[pname]
            for op, arg in constraints.items():
                if op in MODIFIERS:
                    continue
                ok, why = _check_constraint(op, arg, value)
                if not ok:
                    return False, f"param {pname!r}: {why}"
        return True, ""


DEFAULT_POLICY = {
    "policy_id": "starter-default-deny-v0",
    "default": DENY,
    "rules": [
        {
            "rule_id": "read-public-data",
            "tool": "fs.read",
            "params": {
                "path": {"prefix": "/data/public/", "max_len": 256,
                         "forbid_substrings": [".."]}
            },
        },
        {
            "rule_id": "get-allowed-hosts",
            "tool": "http.get",
            "params": {
                "url": {"prefix": "https://api.example.com/",
                        "max_len": 512}
            },
        },
    ],
}
