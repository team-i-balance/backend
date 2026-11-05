"""API tests for /policy/deploy and /policy/current (S7).

These sign bundles with the server's temporary private key (POLICY_KEYS_DIR is
isolated per-test by the client fixture), so the server's public key verifies
them.
"""


def _signed_bundle(payload, key_id="sec-team"):
    # Imported inside the test so it uses the reloaded, tmp-keyed module.
    from app.policy import sign_payload

    return {
        "payload": payload,
        "signature": sign_payload(payload),
        "key_id": key_id,
    }


def test_current_empty_before_any_deploy(client):
    r = client.get("/policy/current")
    assert r.status_code == 200
    assert r.json() == {
        "active": False,
        "version": None,
        "key_id": None,
        "rule_count": None,
        "activated_at": None,
    }


def test_deploy_valid_bundle_activates(client):
    bundle = _signed_bundle({"version": 1, "rules": [{"r": 1}, {"r": 2}]})
    r = client.post("/policy/deploy", json={"bundle": bundle})
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] is True
    assert body["policy"]["active"] is True
    assert body["policy"]["version"] == 1
    assert body["policy"]["rule_count"] == 2

    cur = client.get("/policy/current").json()
    assert cur["version"] == 1
    assert cur["activated_at"]


def test_deploy_tampered_bundle_rejected(client):
    bundle = _signed_bundle({"version": 1, "rules": []})
    bundle["payload"]["version"] = 9  # break the signature
    r = client.post("/policy/deploy", json={"bundle": bundle})
    body = r.json()
    assert body["accepted"] is False
    assert "rejected" in body["reason"]
    assert body["policy"]["active"] is False  # nothing activated


def test_deploy_rejects_older_version_keeps_active(client):
    client.post("/policy/deploy", json={"bundle": _signed_bundle({"version": 3, "rules": []})})
    # Older version must be ignored, active stays at 3.
    r = client.post("/policy/deploy", json={"bundle": _signed_bundle({"version": 2, "rules": []})})
    body = r.json()
    assert body["accepted"] is False
    assert body["policy"]["version"] == 3


def test_deploy_newer_version_replaces(client):
    client.post("/policy/deploy", json={"bundle": _signed_bundle({"version": 1, "rules": []})})
    r = client.post("/policy/deploy", json={"bundle": _signed_bundle({"version": 2, "rules": [{"r": 1}]})})
    body = r.json()
    assert body["accepted"] is True
    assert body["policy"]["version"] == 2
    assert body["policy"]["rule_count"] == 1


def test_deploy_garbage_bundle_rejected(client):
    r = client.post("/policy/deploy", json={"bundle": {"not": "a bundle"}})
    assert r.status_code == 200
    assert r.json()["accepted"] is False
