"""Command line interface.

The important command is ``verify``. It takes a ledger file and nothing
else — no keys, no server, no account. Anyone handed the file can check
it, which is what makes it evidence rather than a claim.

    rnke-gate verify ledger.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys

from .identity import Identity
from .ledger import verify_ledger
from .policy import DEFAULT_POLICY, Policy, PolicyError


def cmd_verify(args) -> int:
    report = verify_ledger(args.ledger, expected_gate_key=args.gate_key)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"ledger:   {args.ledger}")
        print(f"gate key: {report.get('gate_key')}")
        print(f"receipts: {report['receipts']}")
        print(f"verdict:  {report['verdict']}")
        for problem in report["problems"]:
            print(f"  - {problem}")
        if report["verdict"] == "PASS":
            print("\nEvery record hashes to its content, every signature is "
                  "valid, and the chain is unbroken.")
    return 0 if report["verdict"] == "PASS" else 1


def cmd_keygen(args) -> int:
    ident = Identity.generate()
    ident.save(args.out)
    print(f"wrote {args.out} (mode 0600)")
    print(f"id:     {ident.id}")
    print(f"public: {ident.public_b64}")
    return 0


def cmd_init_policy(args) -> int:
    with open(args.out, "w") as fh:
        json.dump(DEFAULT_POLICY, fh, indent=2)
        fh.write("\n")
    pol = Policy.from_dict(DEFAULT_POLICY)
    print(f"wrote {args.out}")
    print(f"policy_id:   {pol.policy_id}")
    print(f"policy_hash: {pol.policy_hash}")
    print("\nThis starter policy denies everything except two example "
          "tools. Edit it before you trust it.")
    return 0


def cmd_check_policy(args) -> int:
    try:
        pol = Policy.load(args.policy)
    except PolicyError as exc:
        print(f"INVALID: {exc}")
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"INVALID: cannot read policy ({exc})")
        return 1
    print(f"policy_id:   {pol.policy_id}")
    print(f"policy_hash: {pol.policy_hash}")
    print(f"rules:       {len(pol.rules)} (default {pol.default})")
    for rule in pol.rules:
        params = ", ".join(rule.get("params", {})) or "no params constrained"
        print(f"  - {rule['rule_id']}: {rule['tool']} [{params}]")
    return 0


def cmd_show(args) -> int:
    with open(args.ledger) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            cap = json.loads(line)
            kind = cap["capsule"].split(".")[1]
            if kind == "receipt":
                print(f"[receipt] {cap['decision']:5s} {cap['tool']:20s} "
                      f"{cap['outcome']:9s} rule={cap.get('rule_id')} "
                      f"{cap['self_hash'][:12]}")
            elif kind == "verdict" and args.verbose:
                print(f"[verdict] {cap['decision']:5s} {cap['tool']:20s} "
                      f"{'; '.join(cap['reasons'])}")
            elif kind == "intent" and args.verbose:
                print(f"[intent ] {cap['tool']:20s} {json.dumps(cap['params'])}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="rnke-gate",
        description="Proof-carrying authorization for AI agent actions.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("verify", help="check a receipt ledger end to end")
    p.add_argument("ledger")
    p.add_argument("--json", action="store_true")
    p.add_argument("--gate-key", dest="gate_key", default=None,
                   help="base64 public key the ledger MUST be signed by; "
                        "without it, the first gate key seen is taken as "
                        "the ledger's own")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("keygen", help="create a signing identity")
    p.add_argument("--out", default="gate_key.json")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("init-policy", help="write a starter default-deny policy")
    p.add_argument("--out", default="policy.json")
    p.set_defaults(func=cmd_init_policy)

    p = sub.add_parser("check-policy", help="validate and summarise a policy")
    p.add_argument("policy")
    p.set_defaults(func=cmd_check_policy)

    p = sub.add_parser("show", help="print a ledger in human form")
    p.add_argument("ledger")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_show)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
