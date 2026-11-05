"""Policy bundle deployment + signature verification (흐름도 S7).

The security-team tool (S6) produces a *signed policy bundle*. This module
verifies that signature and, if valid, activates the bundle as the current
policy; an invalid bundle is ignored and the previous policy is kept.

IMPORTANT: the real bundle format and signing scheme are not finalized yet.
Everything format-specific is isolated behind:

  - the field-name constants below, and
  - the PolicyVerifier interface.

When the team delivers the real format, swap in a different PolicyVerifier (or
adjust the constants) — the store, router, and tests around them stay the same.

The default verifier assumes an Ed25519 signature over a canonical JSON
encoding of the bundle's payload, i.e. a bundle shaped like:

    {
      "payload": { "version": <int>, "rules": [...], ... },
      "signature": "<base64 ed25519 signature of canonical(payload)>",
      "key_id": "<str>"
    }

Only the public key lives on the server; the private key stays with the
security team (here a temporary key is generated for local/testing use).
"""
from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# --- Format-specific knobs (change these when the real format arrives) -------
FIELD_PAYLOAD = "payload"
FIELD_SIGNATURE = "signature"
FIELD_KEY_ID = "key_id"
FIELD_VERSION = "version"
FIELD_RULES = "rules"

BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = Path(os.getenv("POLICY_KEYS_DIR", BASE_DIR / "keys"))
PUB_KEY_PATH = KEYS_DIR / "policy_pub.pem"
# Temporary stand-in for the security team's private key (signing is theirs).
PRIV_KEY_PATH = KEYS_DIR / "policy_priv.pem"


class PolicyError(ValueError):
    """The bundle is malformed or its signature is invalid."""


@dataclass(frozen=True)
class VerifiedBundle:
    version: int
    key_id: Optional[str]
    rule_count: int
    rules: list
    payload: dict


def canonical_bytes(payload: dict) -> bytes:
    """Deterministic JSON encoding used as the signed message."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# --- Key management (temporary dev keys) ------------------------------------
def ensure_keys() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if PUB_KEY_PATH.exists():
        return
    priv = Ed25519PrivateKey.generate()
    PRIV_KEY_PATH.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    PUB_KEY_PATH.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_public_key() -> Ed25519PublicKey:
    ensure_keys()
    return serialization.load_pem_public_key(PUB_KEY_PATH.read_bytes())


def load_private_key() -> Ed25519PrivateKey:
    """Only for local signing in tests / demos; production signs offline."""
    ensure_keys()
    return serialization.load_pem_private_key(PRIV_KEY_PATH.read_bytes(), password=None)


def sign_payload(payload: dict) -> str:
    """Helper to produce a bundle signature with the temporary private key."""
    sig = load_private_key().sign(canonical_bytes(payload))
    return base64.b64encode(sig).decode("ascii")


# --- Verifier interface (swap this out for the real format later) ------------
class PolicyVerifier:
    def verify(self, bundle: dict) -> VerifiedBundle:  # pragma: no cover - interface
        raise NotImplementedError


class Ed25519Verifier(PolicyVerifier):
    """Default verifier: Ed25519 signature over canonical(payload)."""

    def __init__(self, public_key: Optional[Ed25519PublicKey] = None):
        self._public_key = public_key

    def _key(self) -> Ed25519PublicKey:
        return self._public_key or load_public_key()

    def verify(self, bundle: dict) -> VerifiedBundle:
        if not isinstance(bundle, dict):
            raise PolicyError("bundle must be an object")
        payload = bundle.get(FIELD_PAYLOAD)
        signature = bundle.get(FIELD_SIGNATURE)
        if not isinstance(payload, dict):
            raise PolicyError("bundle.payload must be an object")
        if not isinstance(signature, str) or not signature:
            raise PolicyError("bundle.signature is required")

        try:
            sig_bytes = base64.b64decode(signature, validate=True)
        except Exception as exc:
            raise PolicyError("signature is not valid base64") from exc

        try:
            self._key().verify(sig_bytes, canonical_bytes(payload))
        except InvalidSignature as exc:
            raise PolicyError("signature verification failed") from exc

        version = payload.get(FIELD_VERSION)
        if not isinstance(version, int) or isinstance(version, bool):
            raise PolicyError("payload.version must be an integer")
        rules = payload.get(FIELD_RULES, [])
        if not isinstance(rules, list):
            raise PolicyError("payload.rules must be a list")

        return VerifiedBundle(
            version=version,
            key_id=bundle.get(FIELD_KEY_ID),
            rule_count=len(rules),
            rules=rules,
            payload=payload,
        )


# --- Active-policy store -----------------------------------------------------
@dataclass
class ActivePolicy:
    version: int
    key_id: Optional[str]
    rule_count: int
    rules: list
    activated_at: str


class PolicyStore:
    """Holds the currently active (verified) policy. In-memory."""

    def __init__(self, verifier: Optional[PolicyVerifier] = None):
        self._verifier = verifier or Ed25519Verifier()
        self._active: Optional[ActivePolicy] = None
        self._lock = threading.Lock()

    def deploy(self, bundle: dict) -> tuple[bool, str]:
        """Verify and (if valid + newer) activate a bundle.

        Returns (accepted, reason). An invalid signature is ignored and the
        previous policy is left untouched (흐름도: 서명 검증 실패 → 번들 무시).
        """
        try:
            verified = self._verifier.verify(bundle)
        except PolicyError as exc:
            return False, f"rejected: {exc}"

        with self._lock:
            if self._active is not None and verified.version <= self._active.version:
                return (
                    False,
                    f"rejected: version {verified.version} is not newer than "
                    f"active version {self._active.version}",
                )
            self._active = ActivePolicy(
                version=verified.version,
                key_id=verified.key_id,
                rule_count=verified.rule_count,
                rules=verified.rules,
                activated_at=datetime.now(timezone.utc).isoformat(),
            )
            return True, f"activated version {verified.version}"

    def current(self) -> Optional[ActivePolicy]:
        with self._lock:
            return self._active

    def reset(self) -> None:
        with self._lock:
            self._active = None


# Module-level store shared by the policy router.
store = PolicyStore()
