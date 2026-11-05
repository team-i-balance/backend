"""API tests for /policy/deploy and /policy/current (DSSE spec, S7).

Bundles are signed with the module's demo key (POLICY_KEYS_DIR is isolated per
test by the client fixture), and the demo public key is trusted, so the server
verifies them. POLICY_EXPECTED_MODEL_SHA256 is unset, so the model check is
skipped.
"""
import base64
import json


def _payload(version=1, org="acme", **extra):
    p = {
        "schema": 1,
        "org": org,
        "version": version,
        "issued_at": "2026-11-05T16:40:00+09:00",
        "expires_at": "2999-01-01T00:00:00+00:00",
        "prev": "sha256:x",
        "model": {"name": "pii-slm", "version": "0.3.0", "sha256": "h"},
        "thresholds": {"confidential": 0.45, "personal": 0.35, "high_confidence": 0.7},
        "rules": [{"id": "r-1", "label": "고객 ID", "description": "x", "grade": "S", "action": "대체"}],
    }
    p.update(extra)
    return p


def _bundle(payload):
    from app.policy import make_bundle

    return make_bundle(payload)


def test_current_empty_before_deploy(client):
    r = client.get("/policy/current")
    assert r.status_code == 200
    assert r.json()["active"] is False


def test_deploy_valid_activates(client):
    r = client.post("/policy/deploy", json={"bundle": _bundle(_payload(version=1))})
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] is True
    assert "applied version 1" in body["reason"]
    assert body["policy"]["active"] is True
    assert body["policy"]["version"] == 1
    assert body["policy"]["org"] == "acme"
    assert body["policy"]["rule_count"] == 1

    cur = client.get("/policy/current").json()
    assert cur["version"] == 1
    assert cur["expires_at"]


def test_deploy_tampered_rejected(client):
    bundle = _bundle(_payload(version=1))
    # Swap in an unsigned payload -> bad_signature.
    bundle["payload"] = base64.b64encode(
        json.dumps(_payload(version=9)).encode()
    ).decode()
    body = client.post("/policy/deploy", json={"bundle": bundle}).json()
    assert body["accepted"] is False
    assert body["reason"] == "bad_signature"
    assert body["policy"]["active"] is False


def test_deploy_wrong_org_rejected(client):
    body = client.post(
        "/policy/deploy", json={"bundle": _bundle(_payload(org="other"))}
    ).json()
    assert body["accepted"] is False
    assert body["reason"] == "wrong_org"


def test_deploy_rollback_keeps_active(client):
    client.post("/policy/deploy", json={"bundle": _bundle(_payload(version=3))})
    body = client.post(
        "/policy/deploy", json={"bundle": _bundle(_payload(version=2))}
    ).json()
    assert body["accepted"] is False
    assert body["reason"] == "rollback"
    assert body["policy"]["version"] == 3


def test_deploy_newer_replaces(client):
    client.post("/policy/deploy", json={"bundle": _bundle(_payload(version=1))})
    body = client.post(
        "/policy/deploy", json={"bundle": _bundle(_payload(version=2))}
    ).json()
    assert body["accepted"] is True
    assert body["policy"]["version"] == 2


def test_deploy_bad_type_rejected(client):
    body = client.post("/policy/deploy", json={"bundle": {"not": "dsse"}}).json()
    assert body["accepted"] is False
    assert body["reason"] == "bad_type"


def test_deploy_expired_rejected(client):
    body = client.post(
        "/policy/deploy",
        json={"bundle": _bundle(_payload(expires_at="2000-01-01T00:00:00+00:00"))},
    ).json()
    assert body["accepted"] is False
    assert body["reason"] == "expired"
