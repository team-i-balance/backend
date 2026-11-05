"""Unit tests for policy bundle verification + store (app/policy.py, S7)."""
import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.policy import (
    Ed25519Verifier,
    PolicyError,
    PolicyStore,
    canonical_bytes,
)


def _keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def _bundle(priv, payload, key_id="sec-team"):
    sig = priv.sign(canonical_bytes(payload))
    return {
        "payload": payload,
        "signature": base64.b64encode(sig).decode(),
        "key_id": key_id,
    }


def test_valid_bundle_verifies():
    priv, pub = _keypair()
    verifier = Ed25519Verifier(public_key=pub)
    payload = {"version": 1, "rules": [{"a": 1}, {"b": 2}]}
    v = verifier.verify(_bundle(priv, payload))
    assert v.version == 1
    assert v.rule_count == 2
    assert v.key_id == "sec-team"


def test_tampered_payload_fails():
    priv, pub = _keypair()
    verifier = Ed25519Verifier(public_key=pub)
    bundle = _bundle(priv, {"version": 1, "rules": []})
    # Change the payload after signing -> signature no longer matches.
    bundle["payload"]["version"] = 2
    with pytest.raises(PolicyError, match="signature verification failed"):
        verifier.verify(bundle)


def test_wrong_key_fails():
    priv, _ = _keypair()
    _, other_pub = _keypair()
    verifier = Ed25519Verifier(public_key=other_pub)
    with pytest.raises(PolicyError, match="signature verification failed"):
        verifier.verify(_bundle(priv, {"version": 1, "rules": []}))


def test_key_order_does_not_break_verification():
    priv, pub = _keypair()
    verifier = Ed25519Verifier(public_key=pub)
    payload = {"version": 1, "rules": [], "note": "x", "created": "t"}
    bundle = _bundle(priv, payload)
    # Re-order the payload keys; canonical encoding must still match.
    bundle["payload"] = {"created": "t", "rules": [], "note": "x", "version": 1}
    v = verifier.verify(bundle)
    assert v.version == 1


@pytest.mark.parametrize(
    "bad",
    [
        {},                                   # no payload/signature
        {"payload": {}, "signature": ""},     # empty signature
        {"payload": "nope", "signature": "x"},  # payload not an object
        {"payload": {"version": 1}, "signature": "!!notbase64!!"},
    ],
)
def test_malformed_bundles_rejected(bad):
    priv, pub = _keypair()
    verifier = Ed25519Verifier(public_key=pub)
    with pytest.raises(PolicyError):
        verifier.verify(bad)


def test_version_must_be_int():
    priv, pub = _keypair()
    verifier = Ed25519Verifier(public_key=pub)
    with pytest.raises(PolicyError, match="version"):
        verifier.verify(_bundle(priv, {"version": "1", "rules": []}))


def test_rules_must_be_list():
    priv, pub = _keypair()
    verifier = Ed25519Verifier(public_key=pub)
    with pytest.raises(PolicyError, match="rules"):
        verifier.verify(_bundle(priv, {"version": 1, "rules": {}}))


# --- store ------------------------------------------------------------------
def test_store_activates_valid_bundle():
    priv, pub = _keypair()
    store = PolicyStore(verifier=Ed25519Verifier(public_key=pub))
    ok, reason = store.deploy(_bundle(priv, {"version": 1, "rules": [{"r": 1}]}))
    assert ok is True
    assert "activated version 1" in reason
    assert store.current().version == 1
    assert store.current().rule_count == 1


def test_store_rejects_invalid_keeps_previous():
    priv, pub = _keypair()
    store = PolicyStore(verifier=Ed25519Verifier(public_key=pub))
    store.deploy(_bundle(priv, {"version": 1, "rules": []}))

    # Tampered bundle must be ignored; previous policy stays active.
    bad = _bundle(priv, {"version": 2, "rules": []})
    bad["payload"]["version"] = 5
    ok, reason = store.deploy(bad)
    assert ok is False
    assert store.current().version == 1  # unchanged


def test_store_rejects_non_newer_version():
    priv, pub = _keypair()
    store = PolicyStore(verifier=Ed25519Verifier(public_key=pub))
    store.deploy(_bundle(priv, {"version": 5, "rules": []}))

    # Same version rejected.
    ok, _ = store.deploy(_bundle(priv, {"version": 5, "rules": []}))
    assert ok is False
    # Lower version rejected (rollback protection).
    ok, _ = store.deploy(_bundle(priv, {"version": 3, "rules": []}))
    assert ok is False
    assert store.current().version == 5


def test_store_accepts_newer_version():
    priv, pub = _keypair()
    store = PolicyStore(verifier=Ed25519Verifier(public_key=pub))
    store.deploy(_bundle(priv, {"version": 1, "rules": []}))
    ok, _ = store.deploy(_bundle(priv, {"version": 2, "rules": [{"r": 1}]}))
    assert ok is True
    assert store.current().version == 2


def test_verify_rejects_non_dict_bundle():
    _, pub = _keypair()
    verifier = Ed25519Verifier(public_key=pub)
    with pytest.raises(PolicyError, match="bundle must be an object"):
        verifier.verify("not a dict")


def test_store_reset_clears_active():
    priv, pub = _keypair()
    store = PolicyStore(verifier=Ed25519Verifier(public_key=pub))
    store.deploy(_bundle(priv, {"version": 1, "rules": []}))
    assert store.current() is not None
    store.reset()
    assert store.current() is None


def test_custom_verifier_can_be_swapped():
    # Simulates the future real format: a verifier that ignores signatures and
    # reads a different shape. Confirms the store is format-agnostic.
    from app.policy import PolicyVerifier, VerifiedBundle

    class FakeVerifier(PolicyVerifier):
        def verify(self, bundle):
            return VerifiedBundle(
                version=bundle["v"], key_id=None, rule_count=0, rules=[], payload=bundle
            )

    store = PolicyStore(verifier=FakeVerifier())
    ok, _ = store.deploy({"v": 7})
    assert ok is True
    assert store.current().version == 7
