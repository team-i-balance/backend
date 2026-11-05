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

The backend's published/active policies, acknowledgements, and model manifest
are persisted in SQLite. Standalone PolicyStore() instances use isolated
in-memory SQLite unless a db_path is provided.

Configuration (env):
  POLICY_KEYS_DIR         where trusted public keys + the temp signing key live
  POLICY_DB_PATH          SQLite path (default backend/data/policy.db)
  POLICY_ORG              this device/org id (default "acme")
  POLICY_EXPECTED_MODEL_SHA256  installed model hash; if unset, model check is
                          skipped (hackathon convenience)
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.policy_db import PolicyDatabase
from app.policy_draft import DraftError, read_draft, reject_unsignable, require_match, save_draft

POLICY_PAYLOAD_TYPE = "application/vnd.piiguard.policy+json"
MODEL_PAYLOAD_TYPE = "application/vnd.piiguard.model+json"
SUPPORTED_SCHEMA = 1

BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = Path(os.getenv("POLICY_KEYS_DIR", BASE_DIR / "keys"))
POLICY_DB_PATH = Path(os.getenv("POLICY_DB_PATH", BASE_DIR / "data" / "policy.db"))
# Trusted public keys are trust/<keyid>.pub under the keys dir (MDM-installed).
TRUST_DIR = KEYS_DIR / "trust"
# Temporary signing key for local/demo publishing (console/KMS holds it in prod).
DEMO_KEY_ID = "console-demo"
PRIV_KEY_PATH = KEYS_DIR / f"{DEMO_KEY_ID}.key"
_KEY_LOCK = threading.Lock()


class SigningKeyError(RuntimeError):
    """Existing signing identity is missing or inconsistent; never rotate silently."""


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
def _atomic_key_write(path: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".key-", dir=path.parent)
    try:
        # mkstemp creates mode 0600. Flush bytes before atomically publishing.
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def ensure_demo_key() -> None:
    """Reuse the signing identity; recover a missing public half, never replace it."""
    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    public_path = TRUST_DIR / f"{DEMO_KEY_ID}.pub"
    with _KEY_LOCK, (KEYS_DIR / ".signing.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            if PRIV_KEY_PATH.exists():
                priv = serialization.load_pem_private_key(PRIV_KEY_PATH.read_bytes(), password=None)
                if not isinstance(priv, Ed25519PrivateKey):
                    raise SigningKeyError("signing key is not Ed25519")
            else:
                if public_path.exists():
                    raise SigningKeyError("restore the missing signing key; a public key already exists")
                priv = Ed25519PrivateKey.generate()
                _atomic_key_write(PRIV_KEY_PATH, priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            public_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if public_path.exists():
                trusted = serialization.load_pem_public_key(public_path.read_bytes())
                if not isinstance(trusted, Ed25519PublicKey) or trusted.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw,
                ) != priv.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw,
                ):
                    raise SigningKeyError("signing key and trusted public key do not match")
            else:
                _atomic_key_write(public_path, public_bytes)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def load_trusted_key(keyid: str) -> Optional[Ed25519PublicKey]:
    """Load a trusted public key by keyid, or None if not trusted."""
    pub_path = TRUST_DIR / f"{keyid}.pub"
    if not pub_path.is_file():
        return None
    key = serialization.load_pem_public_key(pub_path.read_bytes())
    return key if isinstance(key, Ed25519PublicKey) else None


def load_demo_private_key() -> Ed25519PrivateKey:
    try:
        ensure_demo_key()
        return serialization.load_pem_private_key(PRIV_KEY_PATH.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise SigningKeyError("signing key files are unavailable or invalid") from exc


def _sign_bundle(payload: dict, private_key, *, keyid: str, payload_type: str) -> dict:
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    sig = private_key.sign(pae(payload_type, payload_bytes))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def make_bundle(
    payload: dict, *, keyid: str = DEMO_KEY_ID, payload_type: str = POLICY_PAYLOAD_TYPE
) -> dict:
    """Build a signed DSSE bundle (demo/test helper; prod signs offline)."""
    return _sign_bundle(payload, load_demo_private_key(), keyid=keyid, payload_type=payload_type)


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

    def __init__(self, verifier: Optional[DsseVerifier] = None, *, db_path: Path | str | None = None):
        self._verifier = verifier or DsseVerifier()
        self._db = PolicyDatabase(db_path)

    def initialize(self) -> None:
        self._db.initialize()

    @staticmethod
    def _current(conn) -> Optional[ActivePolicy]:
        row = conn.execute("SELECT data FROM policy_active WHERE singleton = 1").fetchone()
        return ActivePolicy(**json.loads(row["data"])) if row else None

    @staticmethod
    def _next_version(conn) -> int:
        # Also respect a policy deployed from an external publisher, including
        # a saved pre-migration bundle used to restore the version floor.
        return conn.execute("""
            SELECT MAX(version) + 1 FROM (
                SELECT version FROM policy_bundle
                UNION ALL SELECT version FROM policy_active
                UNION ALL SELECT 0
            )
        """).fetchone()[0]

    @staticmethod
    def _stored(row) -> Optional[StoredBundle]:
        if row is None:
            return None
        return StoredBundle(
            version=row["version"], envelope=json.loads(row["envelope"]),
            sha256=row["sha256"], stored_at=row["stored_at"], rule_count=row["rule_count"],
        )

    @staticmethod
    def _sign(conn, payload: dict, payload_type: str) -> dict:
        pinned = conn.execute("SELECT public_key FROM policy_signing_key WHERE singleton = 1").fetchone()
        if pinned and not PRIV_KEY_PATH.is_file():
            raise SigningKeyError("restore the original signing key for this policy database")
        private_key = load_demo_private_key()
        public_hex = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()
        if pinned and pinned["public_key"] != public_hex:
            raise SigningKeyError("signing key differs from this policy database's public key")
        conn.execute(
            "INSERT OR IGNORE INTO policy_signing_key (singleton, public_key) VALUES (1, ?)",
            (public_hex,),
        )
        return _sign_bundle(payload, private_key, keyid=DEMO_KEY_ID, payload_type=payload_type)

    # --- PC-side: verify + apply --------------------------------------------
    def deploy(self, bundle: dict) -> tuple[bool, str]:
        """Verify and (if valid + newer) activate. Returns (accepted, reason).

        On failure the current policy is kept and the reason is the spec code
        (bad_type/bad_signature/unsupported_schema/wrong_org/rollback/expired/
        model_mismatch).
        """
        with self._db.transaction(write=True) as conn:
            active = self._current(conn)
            last_version = active.version if active else None
            try:
                verified = self._verifier.verify(bundle, last_version=last_version)
            except PolicyError as exc:
                return False, exc.code
            if last_version is not None and verified.version <= last_version:
                return False, "rollback"
            active = ActivePolicy(
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
            conn.execute(
                """INSERT INTO policy_active (singleton, version, data) VALUES (1, ?, ?)
                   ON CONFLICT(singleton) DO UPDATE SET version=excluded.version, data=excluded.data""",
                (active.version, json.dumps(asdict(active), ensure_ascii=False)),
            )
            return True, f"applied version {verified.version}"

    def current(self) -> Optional[ActivePolicy]:
        with self._db.transaction() as conn:
            return self._current(conn)

    # --- Backend-side: publish + history + latest ---------------------------
    def next_version(self) -> int:
        """Preview only; publish allocates the version inside its transaction."""
        with self._db.transaction() as conn:
            return self._next_version(conn)

    def draft(self) -> dict:
        with self._db.transaction() as conn:
            return read_draft(conn)

    def save_draft(self, payload: dict, changes: list[dict], *, if_match: str | None, editor: str,
                   console_state: dict | None = None) -> dict:
        with self._db.transaction(write=True) as conn:
            return save_draft(conn, payload, changes, if_match=if_match, editor=editor,
                              console_state=console_state)

    def publish(self, payload: Optional[dict] = None, *, signer=None, if_match: str | None = None) -> StoredBundle:
        """Sign a payload into a DSSE bundle, bump version, and store it.

        The version is allocated above both published and applied versions;
        the console cannot pick it. ``signer`` may override signing in tests.
        The default signer is bound to the persistent store's public key.
        """
        with self._db.transaction(write=True) as conn:
            draft = read_draft(conn)
            # Legacy payload publishing still works when no saved draft exists.
            # If there is one, no caller may silently discard another editor's work.
            if payload is None or draft["has_draft"] or if_match is not None:
                require_match(draft, if_match)
            if payload is None:
                if not draft["has_draft"]:
                    raise DraftError(409, "NO_POLICY_DRAFT")
                payload = draft["payload"]
            # Both paths: a saved draft or direct body carrying console plaintext
            # is refused rather than signed (console_state is never read here).
            reject_unsignable(payload)
            version = self._next_version(conn)
            payload = {**payload, "version": version}
            envelope = signer(payload) if signer else self._sign(conn, payload, POLICY_PAYLOAD_TYPE)
            rules = payload.get("rules")
            stored = StoredBundle(
                version=version,
                envelope=envelope,
                sha256=bundle_hash(envelope),
                stored_at=datetime.now(timezone.utc).isoformat(),
                rule_count=len(rules) if isinstance(rules, list) else 0,
            )
            conn.execute(
                """INSERT INTO policy_bundle (version, envelope, sha256, stored_at, rule_count)
                   VALUES (?, ?, ?, ?, ?)""",
                (stored.version, json.dumps(stored.envelope, ensure_ascii=False),
                 stored.sha256, stored.stored_at, stored.rule_count),
            )
            # Same transaction as the signed bundle: failure leaves the draft intact.
            # policy_console_state is deliberately kept for the console's reload.
            conn.execute("DELETE FROM policy_draft WHERE singleton = 1")
            return stored

    def latest(self) -> Optional[StoredBundle]:
        with self._db.transaction() as conn:
            row = conn.execute("SELECT * FROM policy_bundle ORDER BY version DESC LIMIT 1").fetchone()
            return self._stored(row)

    def get_version(self, version: int) -> Optional[StoredBundle]:
        with self._db.transaction() as conn:
            row = conn.execute("SELECT * FROM policy_bundle WHERE version = ?", (version,)).fetchone()
            return self._stored(row)

    def history(self) -> list[StoredBundle]:
        """All stored bundles, newest version first."""
        with self._db.transaction() as conn:
            rows = conn.execute("SELECT * FROM policy_bundle ORDER BY version DESC")
            return [self._stored(row) for row in rows]

    # --- Backend-side: ack tracking -----------------------------------------
    def record_ack(self, device_id: str, version: int, status: str, reason: Optional[str]) -> None:
        with self._db.transaction(write=True) as conn:
            conn.execute(
                "INSERT INTO policy_ack (device_id, version, status, reason, at) VALUES (?, ?, ?, ?, ?)",
                (device_id, version, status, reason, datetime.now(timezone.utc).isoformat()),
            )

    def has_acks(self, version: int) -> bool:
        with self._db.transaction() as conn:
            row = conn.execute("SELECT 1 FROM policy_ack WHERE version = ? LIMIT 1", (version,)).fetchone()
            return row is not None

    def ack_summary(self, version: Optional[int] = None) -> dict:
        """Apply/reject counts.

        version=None: each device's last ack, whatever version it was for
        (legacy console view). version=N: each device's last ack for N only.
        """
        with self._db.transaction() as conn:
            where = "WHERE version = ?" if version is not None else ""
            params = (version,) if version is not None else ()
            acks = conn.execute(f"""
                SELECT status, reason FROM policy_ack WHERE id IN (
                    SELECT MAX(id) FROM policy_ack {where} GROUP BY device_id
                )
            """, params).fetchall()
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
    def publish_model(self, manifest: dict) -> None:
        with self._db.transaction(write=True) as conn:
            envelope = self._sign(conn, manifest, MODEL_PAYLOAD_TYPE)
            self._set_model(conn, envelope)

    @staticmethod
    def _set_model(conn, manifest: dict) -> None:
        conn.execute(
            """INSERT INTO model_manifest (singleton, envelope) VALUES (1, ?)
               ON CONFLICT(singleton) DO UPDATE SET envelope=excluded.envelope""",
            (json.dumps(manifest, ensure_ascii=False),),
        )

    def set_model_manifest(self, manifest: dict) -> None:
        with self._db.transaction(write=True) as conn:
            self._set_model(conn, manifest)

    def model_manifest(self) -> Optional[dict]:
        with self._db.transaction() as conn:
            row = conn.execute("SELECT envelope FROM model_manifest WHERE singleton = 1").fetchone()
            return json.loads(row["envelope"]) if row else None

    def reset(self) -> None:
        """Reset isolated test stores; persistent version history cannot be reset here."""
        if self._db.path is not None:
            raise RuntimeError("reset is only available for in-memory test stores")
        with self._db.transaction(write=True) as conn:
            for table in ("policy_active", "policy_bundle", "policy_ack", "model_manifest", "policy_draft",
                          "policy_console_state"):
                conn.execute(f"DELETE FROM {table}")


# Module-level store shared by the policy router.
store = PolicyStore(db_path=POLICY_DB_PATH)
