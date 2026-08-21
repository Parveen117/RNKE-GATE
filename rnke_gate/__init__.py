"""RNKE Gate — proof-carrying authorization for AI agent actions.

Default-deny policy enforcement plus a hash-chained, signed receipt for
every action an agent attempts. The receipts verify offline, with no
server and no account: ``rnke-gate verify ledger.jsonl``.
"""

from .gate import Denied, Gate
from .identity import Identity
from .ledger import Ledger, verify_ledger
from .policy import ALLOW, DENY, Policy, PolicyError

__version__ = "0.1.0"
__all__ = ["Gate", "Denied", "Policy", "PolicyError", "Identity",
           "Ledger", "verify_ledger", "ALLOW", "DENY"]
