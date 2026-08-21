# RNKE Gate

**Proof-carrying authorization for AI agent actions.**

Your agent is going to be talked into something. This is not a gate you
put around the model's *reasoning* — it is a gate you put around the
model's *hands*. Every action an agent attempts is checked against a
default-deny policy and recorded as a signed, hash-chained receipt that
verifies offline, with no server and no account.

```
rnke-gate verify ledger.jsonl
```

That command is the product. Anyone you hand the file to — an auditor,
a customer's security team, a regulator — can check for themselves what
your agent was authorized to do, what it actually did, and that nobody
edited the record afterwards.

## The 60-second demo

```bash
pip install -e .
python examples/agent_under_attack.py
rnke-gate verify demo_ledger.jsonl
```

The example assumes the prompt injection **worked**. The model is
compromised and is emitting exactly the calls the attacker wanted:

```
OK   db.query         EXECUTED
OK   email.send       EXECUTED
OK   billing.refund   EXECUTED
STOP billing.refund   DENIED
       why: rule refund-small: param 'amount_paise': 90000000 exceeds max 200000
STOP email.send       DENIED
       why: rule reply-to-customer: param 'to_domain': expected 'customer.example.com', got 'attacker.example'
STOP db.dump          DENIED
       why: no rule permits tool 'db.dump' (default DENY)
STOP shell.exec       DENIED
       why: no rule permits tool 'shell.exec' (default DENY)

3 of 7 calls executed; 4 refused and recorded.
ledger demo_ledger.jsonl: PASS (7 receipts, chain intact)
```

The gate never read the injected text. It didn't need to. It saw the
calls, and the calls were not in the policy.

## Benchmark

55 tool calls — 35 attacks, 16 legitimate, 4 declared gaps — run against
three configurations:

| configuration | attacks blocked | benign allowed | usable and safe |
|---|---|---|---|
| no-gate | 0/35 | 16/16 | no |
| deny-all | 35/35 | 0/16 | no |
| **rnke-gate** | **35/35** | **16/16** | **yes** |

The `deny-all` row is permanent: it blocks every attack and is useless,
which is why "blocks 100% of attacks" is not a result on its own. Four
attacks are honestly **not** stopped and are listed with reasons in
[`benchmark/README.md`](benchmark/README.md).

```bash
python benchmark/run_benchmark.py
```

## Using it

```python
from rnke_gate import Gate, Policy, Denied

gate = Gate(policy=Policy.load("policy.json"), ledger_path="ledger.jsonl")

@gate.guarded("billing.refund")
def refund(order_id: str, amount_paise: int) -> str:
    return payments.refund(order_id, amount_paise)

refund(order_id="ORD-1", amount_paise=1000)      # runs, receipt written
refund(order_id="ORD-1", amount_paise=10**9)     # raises Denied, receipt written
```

In an agent loop, hand the model's tool calls to `dispatch` — refusals
come back as results you can feed to the model rather than exceptions:

```python
results = gate.dispatch(model_tool_calls, tool_registry)
```

## Policy

Declarative JSON. Default DENY is not configurable — a policy with
`"default": "ALLOW"` is refused at load time.

```json
{
  "policy_id": "support-agent-v1",
  "default": "DENY",
  "rules": [
    {
      "rule_id": "refund-small",
      "tool": "billing.refund",
      "params": {
        "order_id": {"prefix": "ORD-", "max_len": 24},
        "amount_paise": {"max_int": 200000, "min_int": 1}
      }
    }
  ]
}
```

Operators: `eq`, `in`, `prefix`, `not_prefix`, `suffix`, `max_len`,
`max_int`, `min_int`, `forbid_substrings`. An unknown operator is a
**load-time error**, not a silently ignored constraint. A parameter the
rule does not mention is refused by default (`forbid_extra_params`).

The policy is content-addressed; its hash goes into every verdict, so
you can always prove which rules were in force at the time.

## What the receipt proves

Three capsules per action, each self-hashed and Ed25519-signed:

| capsule | signed by | says |
|---|---|---|
| `intent` | agent key | what was requested, with a hash of the params |
| `verdict` | gate key | the decision, the reasons, the policy hash, the rule |
| `receipt` | gate key | chained to intent + verdict + the previous receipt |

`verify` recomputes every hash, checks every signature, walks the chain,
and refuses the ledger if:

- any record was edited (`self_hash` mismatch)
- a record was edited *and re-hashed* (signature mismatch)
- a record was deleted or reordered (chain break, with the line number)
- a record was appended by a different key (gate-key mismatch)
- a DENIED action was relabelled as EXECUTED
- an intent nonce was replayed

Each of those is an attack test in `tests/test_gate.py` (A1–A14). If one
of them ever starts passing, this is not evidence and the test suite
says so.

**Results are never stored** — only `sha256` of the result. The ledger
proves what was authorized and what came back, without becoming a copy
of your data.

## Honest boundaries

Read these before trusting anything here.

- **Not audited.** No independent security review yet. Until then this
  is a well-tested implementation, not a certified one.
- **The gate protects actions, not secrets.** If the agent process is
  compromised, an attacker calls the tools directly and the gate is
  bypassed. Run the gate where the agent cannot rewrite it.
- **Policy quality is your problem.** A generous policy authorizes
  generously. The gate proves the rules were followed; it cannot tell
  you the rules were wise.
- **The ledger is append-only by convention, not by storage.** Anyone
  who can delete the file can delete it. Tamper-*evidence* is what is
  offered, not tamper-*proofness*; for stronger guarantees, ship
  receipts to append-only storage or countersign externally.
- **Single gate key per ledger.** Key rotation is not implemented yet.
- Ed25519, SHA-256 and the RNG come from `cryptography`. Nothing in this
  package invents a primitive.

## Install

```bash
pip install -e .          # then: rnke-gate --help
python -m pytest tests -q # 27 tests
```

Requires Python 3.10+ and `cryptography`.

## License

Apache-2.0. Patent position: the recognition-gated authorization and
proof-carrying validation mechanisms are covered by filed PCT
applications (Celextrix Private Limited).
