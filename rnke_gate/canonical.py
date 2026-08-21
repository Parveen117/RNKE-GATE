"""Canonical serialisation.

Every hash and every signature in this package is taken over the bytes
produced here. If two parties disagree about these bytes, they disagree
about everything, so the rules are fixed and deliberately boring:

  - keys sorted, recursively
  - no insignificant whitespace
  - UTF-8, no ASCII escaping
  - floats REJECTED (repr differs across platforms; use strings or ints)

A capsule carries its own hash in the field ``self_hash``, computed over
the capsule with ``self_hash`` and ``signature`` removed. That makes a
capsule self-identifying: anyone can recompute the id from the content.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

RESERVED = ("self_hash", "signature")


def _reject_floats(obj: Any, path: str = "$") -> None:
    if isinstance(obj, float):
        raise ValueError(
            f"float at {path}: floats are not canonicalisable; "
            "use an int or a decimal string"
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"non-string key at {path}: {k!r}")
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _reject_floats(v, f"{path}[{i}]")


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic UTF-8 bytes for a JSON-shaped object."""
    _reject_floats(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    """sha256 of the canonical bytes of an object."""
    return sha256_hex(canonical_bytes(obj))


def unsigned_view(capsule: dict) -> dict:
    """The capsule with reserved fields stripped — what gets hashed."""
    return {k: v for k, v in capsule.items() if k not in RESERVED}


def seal(capsule: dict) -> dict:
    """Attach ``self_hash`` computed over the unsigned view."""
    out = dict(capsule)
    out.pop("self_hash", None)
    out["self_hash"] = digest(unsigned_view(out))
    return out


def self_hash_ok(capsule: dict) -> bool:
    """True iff the capsule's declared self_hash matches its content."""
    declared = capsule.get("self_hash")
    if not isinstance(declared, str):
        return False
    try:
        return declared == digest(unsigned_view(capsule))
    except ValueError:
        return False
