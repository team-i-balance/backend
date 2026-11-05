"""Policy bundle verification + store, per the team DSSE spec (흐름도 S7).

Implements the "변환 정책 번들·서명 명세" (see message.txt):

  - Envelope: DSSE. {payloadType, payload(base64 of policy JSON), signatures:
    [{keyid, sig}]}. The signed message is the DSSE PAE byte string, NOT a
    canonicalized JSON, so key order / whitespace do not matter.
  - Signature: Ed25519. Verified against the trusted public key for the
    envelope's keyid. Only after the signature verifies is the payload JSON
    parsed.
  - Verification order (fail -> keep current policy, report a reason code):
      1 bad_type           payloadType mismatch
      2 bad_signature      signature does not match the PAE bytes
      3 unsupported_schema unknown schema value
      4 wrong_org          org is not ours
      5 rollback           version not greater than last good version
      6 expired            expires_at has passed
      7 model_mismatch     model.sha256 != installed model hash

Scope of this slice: envelope parsing, signature verification, the 7 checks,
and storing the active policy. Applying rules to the SLM (set_policy), the
/publish + /ack endpoints, and the model manifest are later steps.

Configuration (env):
  POLICY_KEYS_DIR         where trusted public keys + the temp signing key live
  POLICY_ORG              this device/org id (default "acme")
  POLICY_EXPECTED_MODEL_SHA256  installed model hash; if unset, model check is
                          skipped (hackathon convenience)
"""
from __future__ import annotations

import base64
import hashlib
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

POLICY_PAYLOAD_TYPE = "application/vnd.piiguard.policy+json"
MODEL_PAYLOAD_TYPE = "application/vnd.piiguard.model+json"
SUPPORTED_SCHEMA = 1

BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = Path(os.getenv("POLICY_KEYS_DIR", BASE_DIR / "keys"))
# Trusted public keys are trust/<keyid>.pub under the keys dir (MDM-installed).
TRUST_DIR = KEYS_DIR / "trust"
# Temporary signing key for local/demo publishing (console/KMS holds it in prod).
DEMO_KEY_ID = "console-demo"
PRIV_KEY_PATH = KEYS_DIR / f"{DEMO_KEY_ID}.key"


class PolicyError(ValueError):
    """Verification failed. ``code`` is the spec reason code."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


# --- DSSE PAE ----------------------------------------------------------------
def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding of (payloadType, payload)."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


# --- Keys (demo signing + trusted verification keys) -------------------------
def ensure_demo_key() -> None:
    """Create a demo Ed25519 signing key and publish its public half to trust/."""
    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    if PRIV_KEY_PATH.exists():
        return
    priv = Ed25519PrivateKey.generate()
    PRIV_KEY_PATH.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (TRUST_DIR / f"{DEMO_KEY_ID}.pub").write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_trusted_key(keyid: str) -> Optional[Ed25519PublicKey]:
    """Load a trusted public key by keyid, or None if not trusted."""
    pub_path = TRUST_DIR / f"{keyid}.pub"
    if not pub_path.is_file():
        return None
    key = serialization.load_pem_public_key(pub_path.read_bytes())
    return key if isinstance(key, Ed25519PublicKey) else None


def load_demo_private_key() -> Ed25519PrivateKey:
    ensure_demo_key()
    return serialization.load_pem_private_key(PRIV_KEY_PATH.read_bytes(), password=None)


def make_bundle(
    payload: dict, *, keyid: str = DEMO_KEY_ID, payload_type: str = POLICY_PAYLOAD_TYPE
) -> dict:
    """Build a signed DSSE bundle (demo/test helper; prod signs offline)."""
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    sig = load_demo_private_key().sign(pae(payload_type, payload_bytes))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def make_model_bundle(manifest: dict, *, keyid: str = DEMO_KEY_ID) -> dict:
    """Signed DSSE bundle for a model manifest (payloadType model+json)."""
    return make_bundle(manifest, keyid=keyid, payload_type=MODEL_PAYLOAD_TYPE)


def verify_model_envelope(bundle: dict, *, key_loader=None) -> dict:
    """Verify a model-manifest DSSE bundle's signature and return the manifest.

    Raises PolicyError(bad_type/bad_signature) on failure. Only the signature
    and payloadType are checked here (manifest content is validated by caller).
    """
    loader = key_loader or load_trusted_key
    if not isinstance(bundle, dict) or bundle.get("payloadType") != MODEL_PAYLOAD_TYPE:
        raise PolicyError("bad_type", "unexpected payloadType")
    payload_b64 = bundle.get("payload")
    signatures = bundle.get("signatures")
    if not isinstance(payload_b64, str) or not isinstance(signatures, list):
        raise PolicyError("bad_type", "malformed envelope")
    try:
        payload_bytes = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise PolicyError("bad_type", "payload is not valid base64") from exc
    message = pae(MODEL_PAYLOAD_TYPE, payload_bytes)
    ok = False
    for entry in signatures:
        if not isinstance(entry, dict):
            continue
        keyid, sig_b64 = entry.get("keyid"), entry.get("sig")
        if not isinstance(keyid, str) or not isinstance(sig_b64, str):
            continue
        key = loader(keyid)
        if key is None:
            continue
        try:
            sig = base64.b64decode(sig_b64, validate=True)
        except Exception:
            continue
        try:
            key.verify(sig, message)
            ok = True
            break
        except InvalidSignature:
            continue
    if not ok:
        raise PolicyError("bad_signature", "no trusted signature matched")
    try:
        manifest = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise PolicyError("bad_type", "manifest is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise PolicyError("bad_type", "manifest must be an object")
    return manifest


# --- Verified result ---------------------------------------------------------
@dataclass(frozen=True)
class VerifiedBundle:
    org: str
    version: int
    keyid: str
    rule_count: int
    rules: list
    expires_at: Optional[str]
    payload: dict
    types: dict
    thresholds: dict


def _parse_expiry(value) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


# --- Verifier (DSSE + 7-step checks) ----------------------------------------
class DsseVerifier:
    def __init__(
        self,
        *,
        org: Optional[str] = None,
        expected_model_sha256: Optional[str] = None,
        key_loader=None,
    ):
        self.org = org or os.getenv("POLICY_ORG", "acme")
        # If None, the model check is skipped (see module docstring).
        self.expected_model_sha256 = (
            expected_model_sha256
            if expected_model_sha256 is not None
            else os.getenv("POLICY_EXPECTED_MODEL_SHA256")
        )
        # Resolves a keyid -> Ed25519PublicKey (or None). Injectable for tests.
        self._key_loader = key_loader or load_trusted_key

    def verify(self, bundle: dict, *, last_version: Optional[int]) -> VerifiedBundle:
        if not isinstance(bundle, dict):
            raise PolicyError("bad_type", "bundle must be an object")

        # 1. payloadType
        if bundle.get("payloadType") != POLICY_PAYLOAD_TYPE:
            raise PolicyError("bad_type", "unexpected payloadType")

        payload_b64 = bundle.get("payload")
        signatures = bundle.get("signatures")
        if not isinstance(payload_b64, str) or not isinstance(signatures, list):
            raise PolicyError("bad_type", "malformed envelope")

        try:
            payload_bytes = base64.b64decode(payload_b64, validate=True)
        except Exception as exc:
            raise PolicyError("bad_type", "payload is not valid base64") from exc

        # 2. signature over the PAE bytes, from a trusted keyid
        message = pae(POLICY_PAYLOAD_TYPE, payload_bytes)
        if not self._any_signature_valid(signatures, message):
            raise PolicyError("bad_signature", "no trusted signature matched")

        # Only parse JSON AFTER the signature verifies.
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise PolicyError("bad_type", "payload is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise PolicyError("bad_type", "payload must be a JSON object")

        # 3. schema
        if payload.get("schema") != SUPPORTED_SCHEMA:
            raise PolicyError("unsupported_schema", "unknown schema")

        # 4. org
        if payload.get("org") != self.org:
            raise PolicyError("wrong_org", "bundle is for another org")

        # 5. version (rollback protection)
        version = payload.get("version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise PolicyError("rollback", "version must be an integer")
        if last_version is not None and version <= last_version:
            raise PolicyError("rollback", "version is not newer than last good")

        # 6. expiry
        expires = _parse_expiry(payload.get("expires_at"))
        if expires is not None:
            now = datetime.now(expires.tzinfo or timezone.utc)
            if expires <= now:
                raise PolicyError("expired", "bundle has expired")

        # 7. model hash (skipped if no expected hash configured)
        if self.expected_model_sha256 is not None:
            model = payload.get("model") or {}
            if model.get("sha256") != self.expected_model_sha256:
                raise PolicyError("model_mismatch", "model hash does not match")

        rules = payload.get("rules", [])
        if not isinstance(rules, list):
            raise PolicyError("unsupported_schema", "rules must be a list")

        keyid = signatures[0].get("keyid") if signatures else None
        types = payload.get("types") or {}
        thresholds = payload.get("thresholds") or {}
        return VerifiedBundle(
            org=payload["org"],
            version=version,
            keyid=keyid,
            rule_count=len(rules),
            rules=rules,
            expires_at=payload.get("expires_at"),
            payload=payload,
            types=types if isinstance(types, dict) else {},
            thresholds=thresholds if isinstance(thresholds, dict) else {},
        )

    def _any_signature_valid(self, signatures: list, message: bytes) -> bool:
        for entry in signatures:
            if not isinstance(entry, dict):
                continue
            keyid = entry.get("keyid")
            sig_b64 = entry.get("sig")
            if not isinstance(keyid, str) or not isinstance(sig_b64, str):
                continue
            key = self._key_loader(keyid)
            if key is None:
                continue
            try:
                sig = base64.b64decode(sig_b64, validate=True)
            except Exception:
                continue
            try:
                key.verify(sig, message)
                return True
            except InvalidSignature:
                continue
        return False


# --- Active-policy store -----------------------------------------------------
@dataclass
class ActivePolicy:
    org: str
    version: int
    keyid: Optional[str]
    rule_count: int
    rules: list
    types: dict
    thresholds: dict
    expires_at: Optional[str]
    activated_at: str
    bundle_sha256: str


def bundle_hash(bundle: dict) -> str:
    """sha256 over the canonical bytes of the whole DSSE envelope."""
    raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass
class StoredBundle:
    version: int
    envelope: dict
    sha256: str
    # UTC ISO time the server stored this bundle. Optional so a bundle stored
    # without one (older/imported data) is reported as null, not invented.
    stored_at: Optional[str]
    rule_count: int = 0


class PolicyStore:
    """Active policy + version history + ack tracking.

    Backend role (publish/latest/ack) and the PC-side verify (deploy) share one
    store here for the hackathon; in production they are separate services.
    """

    def __init__(self, verifier: Optional[DsseVerifier] = None):
        self._verifier = verifier or DsseVerifier()
        self._active: Optional[ActivePolicy] = None
        self._history: dict[int, StoredBundle] = {}      # version -> bundle
        self._latest_version: int = 0                    # for publish version+1
        self._acks: dict[str, dict] = {}                 # device_id -> last ack (any version)
        # version -> device_id -> that device's last ack for that version
        self._acks_by_version: dict[int, dict[str, dict]] = {}
        self._model_manifest: Optional[dict] = None      # latest model manifest
        self._lock = threading.Lock()

    # --- PC-side: verify + apply --------------------------------------------
    def deploy(self, bundle: dict) -> tuple[bool, str]:
        """Verify and (if valid + newer) activate. Returns (accepted, reason).

        On failure the current policy is kept and the reason is the spec code
        (bad_type/bad_signature/unsupported_schema/wrong_org/rollback/expired/
        model_mismatch).
        """
        with self._lock:
            last_version = self._active.version if self._active else None
        try:
            verified = self._verifier.verify(bundle, last_version=last_version)
        except PolicyError as exc:
            return False, exc.code

        with self._lock:
            if self._active is not None and verified.version <= self._active.version:
                return False, "rollback"
            self._active = ActivePolicy(
                org=verified.org,
                version=verified.version,
                keyid=verified.keyid,
                rule_count=verified.rule_count,
                rules=verified.rules,
                types=verified.types,
                thresholds=verified.thresholds,
                expires_at=verified.expires_at,
                activated_at=datetime.now(timezone.utc).isoformat(),
                bundle_sha256=bundle_hash(bundle),
            )
            return True, f"applied version {verified.version}"

    def current(self) -> Optional[ActivePolicy]:
        with self._lock:
            return self._active

    # --- Backend-side: publish + history + latest ---------------------------
    def next_version(self) -> int:
        with self._lock:
            return self._latest_version + 1

    def publish(self, payload: dict, *, signer=None) -> StoredBundle:
        """Sign a payload into a DSSE bundle, bump version, and store it.

        The payload's version is set to latest+1 by the store (the console does
        not pick versions). ``signer`` builds the signed envelope from a payload
        (defaults to the demo make_bundle).
        """
        signer = signer or make_bundle
        with self._lock:
            version = self._latest_version + 1
            payload = {**payload, "version": version}
            envelope = signer(payload)
            rules = payload.get("rules")
            stored = StoredBundle(
                version=version,
                envelope=envelope,
                sha256=bundle_hash(envelope),
                stored_at=datetime.now(timezone.utc).isoformat(),
                rule_count=len(rules) if isinstance(rules, list) else 0,
            )
            self._history[version] = stored
            self._latest_version = version
            return stored

    def latest(self) -> Optional[StoredBundle]:
        with self._lock:
            if self._latest_version == 0:
                return None
            return self._history.get(self._latest_version)

    def get_version(self, version: int) -> Optional[StoredBundle]:
        with self._lock:
            return self._history.get(version)

    def history(self) -> list[StoredBundle]:
        """All stored bundles, newest version first."""
        with self._lock:
            return [self._history[v] for v in sorted(self._history, reverse=True)]

    # --- Backend-side: ack tracking -----------------------------------------
    def record_ack(self, device_id: str, version: int, status: str, reason: Optional[str]) -> None:
        entry = {
            "device_id": device_id,
            "version": version,
            "status": status,
            "reason": reason,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._acks[device_id] = entry
            # A device re-sending for the same version overwrites its earlier ack.
            self._acks_by_version.setdefault(version, {})[device_id] = entry

    def has_acks(self, version: int) -> bool:
        with self._lock:
            return bool(self._acks_by_version.get(version))

    def ack_summary(self, version: Optional[int] = None) -> dict:
        """Apply/reject counts.

        version=None: each device's last ack, whatever version it was for
        (legacy console view). version=N: each device's last ack for N only.
        """
        with self._lock:
            if version is None:
                acks = list(self._acks.values())
            else:
                acks = list(self._acks_by_version.get(version, {}).values())
            applied = sum(1 for a in acks if a["status"] == "applied")
            rejected = sum(1 for a in acks if a["status"] == "rejected")
            reasons: dict[str, int] = {}
            for a in acks:
                if a["status"] == "rejected" and a["reason"]:
                    reasons[a["reason"]] = reasons.get(a["reason"], 0) + 1
            return {
                "devices": len(acks),
                "applied": applied,
                "rejected": rejected,
                "reject_reasons": reasons,
            }

    # --- model manifest ------------------------------------------------------
    def set_model_manifest(self, manifest: dict) -> None:
        with self._lock:
            self._model_manifest = manifest

    def model_manifest(self) -> Optional[dict]:
        with self._lock:
            return self._model_manifest

    def reset(self) -> None:
        with self._lock:
            self._active = None
            self._history.clear()
            self._latest_version = 0
            self._acks.clear()
            self._acks_by_version.clear()
            self._model_manifest = None


# Module-level store shared by the policy router.
store = PolicyStore()
