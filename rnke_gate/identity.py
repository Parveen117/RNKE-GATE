"""Identities and signatures.

Vetted primitives only: Ed25519 from ``cryptography``. Nothing in this
package invents a cipher, a hash, or a random source — the whole point
of the receipt is that an auditor can check it with standard tools.

An identity is named by the fingerprint of its public key, so an id is
never a claim: it is derived from the key that must sign for it.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_bytes, sha256_hex, unsigned_view

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NOENC = serialization.NoEncryption()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def fingerprint(public_key_bytes: bytes) -> str:
    """Short, stable name for a key: first 16 hex of sha256(raw pubkey)."""
    return sha256_hex(public_key_bytes)[:16]


@dataclass(frozen=True)
class Identity:
    """A signing identity. ``id`` is derived from the public key."""

    private_key: Ed25519PrivateKey
    public_bytes: bytes

    @property
    def id(self) -> str:
        return fingerprint(self.public_bytes)

    @property
    def public_b64(self) -> str:
        return b64(self.public_bytes)

    @classmethod
    def generate(cls) -> "Identity":
        sk = Ed25519PrivateKey.generate()
        return cls(sk, sk.public_key().public_bytes(_RAW, _RAW_PUB))

    @classmethod
    def from_private_b64(cls, seed_b64: str) -> "Identity":
        sk = Ed25519PrivateKey.from_private_bytes(unb64(seed_b64))
        return cls(sk, sk.public_key().public_bytes(_RAW, _RAW_PUB))

    def private_b64(self) -> str:
        return b64(
            self.private_key.private_bytes(_RAW, _RAW_PRIV, _NOENC)
        )

    def sign_bytes(self, data: bytes) -> str:
        return b64(self.private_key.sign(data))

    def sign_capsule(self, capsule: dict) -> dict:
        """Sign over the canonical bytes of the capsule's unsigned view.

        The signature therefore covers every field except the signature
        itself — including ``self_hash``, so a tampered body cannot be
        re-hashed without breaking the signature.
        """
        out = dict(capsule)
        out.pop("signature", None)
        out["signature"] = self.sign_bytes(canonical_bytes(unsigned_view(out)))
        return out

    def save(self, path: str) -> None:
        blob = {
            "capsule": "rnke.key.v0",
            "id": self.id,
            "public_b64": self.public_b64,
            "private_b64": self.private_b64(),
        }
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(blob, fh, indent=2)
            fh.write("\n")

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(path) as fh:
            blob = json.load(fh)
        ident = cls.from_private_b64(blob["private_b64"])
        if ident.id != blob.get("id"):
            raise ValueError("key file id does not match its private key")
        return ident


def verify_capsule(capsule: dict, public_b64: str) -> bool:
    """True iff ``signature`` is a valid Ed25519 signature by that key."""
    sig = capsule.get("signature")
    if not isinstance(sig, str):
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(unb64(public_b64))
        pk.verify(unb64(sig), canonical_bytes(unsigned_view(capsule)))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
