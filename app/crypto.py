"""Encrypted export of logs for the security team.

Flow (S5): logs are serialized to JSON, then hybrid-encrypted with the
security team's PUBLIC key so only they (holding the private key) can read
the export.

Hybrid scheme:
  - generate a random AES-256 key
  - encrypt the JSON payload with AES-GCM
  - encrypt the AES key with the RSA public key (OAEP/SHA-256)
  - write a small JSON envelope with base64 fields

This is a TEMPORARY key setup (choice D). If no public key exists, we
generate an RSA keypair under backend/keys/ on first use. In production the
private key would belong to the security team and never live on the server.
"""
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = Path(os.getenv("LOG_KEYS_DIR", BASE_DIR / "keys"))
EXPORT_DIR = Path(os.getenv("LOG_EXPORT_DIR", BASE_DIR / "exports"))

PUB_KEY_PATH = KEYS_DIR / "security_team_pub.pem"
# Temporary only — stands in for a key the security team would hold offline.
PRIV_KEY_PATH = KEYS_DIR / "security_team_priv.pem"


def ensure_keys() -> None:
    """Create a temporary RSA keypair if none exists."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if PUB_KEY_PATH.exists():
        return

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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


def _load_public_key():
    return serialization.load_pem_public_key(PUB_KEY_PATH.read_bytes())


def public_key_fingerprint() -> str:
    """SHA-256 fingerprint of the public key (short hex) for traceability."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(PUB_KEY_PATH.read_bytes())
    return digest.finalize().hex()[:16]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encrypt_records(records: list[dict]) -> Path:
    """Encrypt records to a JSON envelope file. Returns the file path."""
    ensure_keys()
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(records, ensure_ascii=False).encode("utf-8")

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, payload, None)

    enc_key = _load_public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    envelope = {
        "scheme": "RSA-OAEP-SHA256 + AES-256-GCM",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(records),
        "public_key_fingerprint": public_key_fingerprint(),
        "enc_key": _b64(enc_key),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = EXPORT_DIR / f"logs_{ts}.enc.json"
    out.write_text(json.dumps(envelope, ensure_ascii=False, indent=2))
    return out


def decrypt_file(path: Path) -> list[dict]:
    """Decrypt an export using the TEMPORARY private key. For round-trip tests."""
    envelope = json.loads(Path(path).read_text())
    priv = serialization.load_pem_private_key(
        PRIV_KEY_PATH.read_bytes(), password=None
    )
    aes_key = priv.decrypt(
        base64.b64decode(envelope["enc_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = AESGCM(aes_key).decrypt(
        base64.b64decode(envelope["nonce"]),
        base64.b64decode(envelope["ciphertext"]),
        None,
    )
    return json.loads(plaintext.decode("utf-8"))
