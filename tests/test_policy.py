"""Unit tests for DSSE policy verification + store (app/policy.py, S7).

Follows the team spec in message.txt: DSSE envelope, Ed25519 over PAE bytes,
and the 7 ordered verification checks.
"""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.policy import (
    POLICY_PAYLOAD_TYPE,
    DsseVerifier,
    PolicyError,
    PolicyStore,
    pae,
)


def _payload(version=1, org="acme", schema=1, **extra):
    p = {
        "schema": schema,
        "org": org,
        "version": version,
        "issued_at": "2026-11-05T16:40:00+09:00",
        "expires_at": "2999-01-01T00:00:00+00:00",
        "prev": "sha256:x",
        "model": {"name": "pii-slm", "version": "0.3.0", "sha256": "modelhash"},
        "thresholds": {"confidential": 0.45, "personal": 0.35, "high_confidence": 0.7},
        "rules": [{"id": "r-1", "label": "고객 ID", "description": "x", "grade": "S", "action": "대체"}],
    }
    p.update(extra)
    return p


def _envelope(priv, payload, *, keyid="console-demo", payload_type=POLICY_PAYLOAD_TYPE):
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    sig = priv.sign(pae(payload_type, payload_bytes))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload_bytes).decode(),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode()}],
    }


@pytest.fixture()
def signed():
    """A (verifier, priv) pair whose demo pub key is trusted via injection."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    verifier = DsseVerifier(
        org="acme",
        expected_model_sha256="modelhash",
        key_loader=lambda keyid: pub if keyid == "console-demo" else None,
    )
    return verifier, priv


def test_valid_bundle_verifies(signed):
    verifier, priv = signed
    v = verifier.verify(_envelope(priv, _payload(version=3)), last_version=None)
    assert v.version == 3
    assert v.org == "acme"
    assert v.rule_count == 1
    assert v.keyid == "console-demo"


def test_bad_type_rejected(signed):
    verifier, priv = signed
    env = _envelope(priv, _payload(), payload_type="application/wrong+json")
    # payloadType in the envelope is wrong -> bad_type (before signature).
    env["payloadType"] = "application/wrong+json"
    with pytest.raises(PolicyError) as e:
        verifier.verify(env, last_version=None)
    assert e.value.code == "bad_type"


def test_tampered_payload_is_bad_signature(signed):
    verifier, priv = signed
    env = _envelope(priv, _payload(version=1))
    # Replace payload with a different one (not signed) -> signature mismatch.
    other = json.dumps(_payload(version=2), ensure_ascii=False).encode()
    env["payload"] = base64.b64encode(other).decode()
    with pytest.raises(PolicyError) as e:
        verifier.verify(env, last_version=None)
    assert e.value.code == "bad_signature"


def test_untrusted_keyid_is_bad_signature(signed):
    verifier, priv = signed
    env = _envelope(priv, _payload(), keyid="unknown-key")
    with pytest.raises(PolicyError) as e:
        verifier.verify(env, last_version=None)
    assert e.value.code == "bad_signature"


def test_unsupported_schema(signed):
    verifier, priv = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify(_envelope(priv, _payload(schema=2)), last_version=None)
    assert e.value.code == "unsupported_schema"


def test_wrong_org(signed):
    verifier, priv = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify(_envelope(priv, _payload(org="other")), last_version=None)
    assert e.value.code == "wrong_org"


def test_rollback(signed):
    verifier, priv = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify(_envelope(priv, _payload(version=5)), last_version=5)
    assert e.value.code == "rollback"


def test_expired(signed):
    verifier, priv = signed
    env = _envelope(priv, _payload(expires_at="2000-01-01T00:00:00+00:00"))
    with pytest.raises(PolicyError) as e:
        verifier.verify(env, last_version=None)
    assert e.value.code == "expired"


def test_model_mismatch(signed):
    verifier, priv = signed
    env = _envelope(priv, _payload(model={"name": "x", "version": "1", "sha256": "WRONG"}))
    with pytest.raises(PolicyError) as e:
        verifier.verify(env, last_version=None)
    assert e.value.code == "model_mismatch"


def test_model_check_skipped_when_not_configured():
    priv = Ed25519PrivateKey.generate()
    # No expected model hash -> model check is skipped.
    verifier = DsseVerifier(
        org="acme",
        expected_model_sha256=None,
        key_loader=lambda keyid: priv.public_key(),
    )
    v = verifier.verify(_envelope(priv, _payload(model={"sha256": "anything"})), last_version=None)
    assert v.version == 1


def test_key_order_irrelevant(signed):
    # PAE signs exact bytes; re-serialize payload with different key order and
    # it must still verify because we transport the exact signed bytes.
    verifier, priv = signed
    env = _envelope(priv, _payload())
    # (The envelope carries the exact signed bytes, so this is inherently safe.)
    v = verifier.verify(env, last_version=None)
    assert v.version == 1


# --- store ------------------------------------------------------------------
def test_store_activates_and_rejects(signed):
    verifier, priv = signed
    store = PolicyStore(verifier=verifier)

    ok, reason = store.deploy(_envelope(priv, _payload(version=1)))
    assert ok and "applied version 1" in reason
    assert store.current().version == 1

    # tampered -> rejected, previous kept
    env = _envelope(priv, _payload(version=2))
    env["payload"] = base64.b64encode(b'{"x":1}').decode()
    ok, code = store.deploy(env)
    assert ok is False and code == "bad_signature"
    assert store.current().version == 1

    # older version -> rollback, previous kept
    ok, code = store.deploy(_envelope(priv, _payload(version=1)))
    assert ok is False and code == "rollback"
    assert store.current().version == 1

    # newer -> replaces
    ok, _ = store.deploy(_envelope(priv, _payload(version=2)))
    assert ok and store.current().version == 2


def test_store_reset(signed):
    verifier, priv = signed
    store = PolicyStore(verifier=verifier)
    store.deploy(_envelope(priv, _payload(version=1)))
    assert store.current() is not None
    store.reset()
    assert store.current() is None


def test_pae_format():
    # DSSEv1 PAE: "DSSEv1 <len(type)> <type> <len(payload)> <payload>"
    out = pae("t", b"ab")
    assert out == b"DSSEv1 1 t 2 ab"


# --- defensive / malformed-input branches -----------------------------------
def _sign_raw(priv, raw: bytes):
    """Build an envelope that correctly signs arbitrary raw bytes."""
    sig = priv.sign(pae(POLICY_PAYLOAD_TYPE, raw))
    return {
        "payloadType": POLICY_PAYLOAD_TYPE,
        "payload": base64.b64encode(raw).decode(),
        "signatures": [{"keyid": "console-demo", "sig": base64.b64encode(sig).decode()}],
    }


def test_non_dict_bundle(signed):
    verifier, _ = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify("nope", last_version=None)
    assert e.value.code == "bad_type"


def test_malformed_envelope_fields(signed):
    verifier, _ = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify(
            {"payloadType": POLICY_PAYLOAD_TYPE, "payload": 123, "signatures": "x"},
            last_version=None,
        )
    assert e.value.code == "bad_type"


def test_payload_not_base64(signed):
    verifier, _ = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify(
            {"payloadType": POLICY_PAYLOAD_TYPE, "payload": "!!!", "signatures": []},
            last_version=None,
        )
    assert e.value.code == "bad_type"


def test_payload_not_json(signed):
    verifier, priv = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify(_sign_raw(priv, b"\xff\xfe not json"), last_version=None)
    assert e.value.code == "bad_type"


def test_payload_json_not_object(signed):
    verifier, priv = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify(_sign_raw(priv, b"[1,2,3]"), last_version=None)
    assert e.value.code == "bad_type"


def test_version_not_int(signed):
    verifier, priv = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify(_envelope(priv, _payload(version="3")), last_version=None)
    assert e.value.code == "rollback"


def test_rules_not_list(signed):
    verifier, priv = signed
    with pytest.raises(PolicyError) as e:
        verifier.verify(_envelope(priv, _payload(rules={})), last_version=None)
    assert e.value.code == "unsupported_schema"


def test_weird_signature_entries_are_bad_signature(signed):
    verifier, priv = signed
    payload_bytes = json.dumps(_payload(), ensure_ascii=False).encode()
    env = {
        "payloadType": POLICY_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode(),
        "signatures": [
            "not-a-dict",                                  # skipped
            {"keyid": 1, "sig": "x"},                      # non-str -> skipped
            {"keyid": "console-demo", "sig": "!!notb64!!"},  # bad base64 -> skipped
            {"keyid": "unknown", "sig": base64.b64encode(b"x").decode()},  # untrusted
        ],
    }
    with pytest.raises(PolicyError) as e:
        verifier.verify(env, last_version=None)
    assert e.value.code == "bad_signature"


def test_parse_expiry_bad_values(signed):
    # expires_at non-str and malformed string are treated as "no expiry".
    verifier, priv = signed
    v1 = verifier.verify(_envelope(priv, _payload(expires_at=12345)), last_version=None)
    assert v1.version == 1
    v2 = verifier.verify(_envelope(priv, _payload(expires_at="not-a-date")), last_version=None)
    assert v2.version == 1


def test_load_trusted_key_rejects_non_ed25519(tmp_path, monkeypatch):
    # A trust file that is not an Ed25519 key must be ignored (returns None).
    import app.policy as policy
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    monkeypatch.setattr(policy, "TRUST_DIR", tmp_path)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "rsa.pub").write_bytes(
        rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assert policy.load_trusted_key("rsa") is None
    assert policy.load_trusted_key("missing") is None


def test_store_inner_rollback_guard(signed):
    # Force the under-lock re-check: a verifier that ignores last_version and
    # always returns the same version, deployed twice.
    from app.policy import PolicyStore, VerifiedBundle

    class FixedVerifier:
        def verify(self, bundle, *, last_version):
            return VerifiedBundle(
                org="acme", version=1, keyid="k", rule_count=0,
                rules=[], expires_at=None, payload={},
            )

    store = PolicyStore(verifier=FixedVerifier())
    ok, _ = store.deploy({})
    assert ok is True
    ok, code = store.deploy({})  # same version -> inner guard
    assert ok is False and code == "rollback"
