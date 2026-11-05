"""API tests for publish / ack / latest / version / model (slices 2-4)
and the policy->detection feedback (slice 1 e2e)."""
import json


def _payload(org="acme", types=None, **extra):
    p = {
        "schema": 1,
        "org": org,
        "issued_at": "2026-11-05T16:40:00+09:00",
        "expires_at": "2999-01-01T00:00:00+00:00",
        "prev": "sha256:x",
        "model": {"sha256": "h"},
        "thresholds": {"confidential": 0.45, "personal": 0.35, "high_confidence": 0.7},
        "rules": [],
    }
    if types is not None:
        p["types"] = types
    p.update(extra)
    return p


def _bundle(payload):
    from app.policy import make_bundle
    return make_bundle(payload)


# --- slice 2: publish -------------------------------------------------------
def test_publish_assigns_incrementing_versions(client):
    r1 = client.post("/policy/publish", json={"payload": _payload()}).json()
    r2 = client.post("/policy/publish", json={"payload": _payload()}).json()
    assert r1["version"] == 1
    assert r2["version"] == 2
    assert r1["bundle_sha256"].startswith("sha256:")
    assert r1["keyid"]


def test_published_bundle_is_verifiable(client):
    # A published bundle must verify + deploy successfully.
    client.post("/policy/publish", json={"payload": _payload()})
    env = client.get("/policy/latest").json()
    r = client.post("/policy/deploy", json={"bundle": env}).json()
    assert r["accepted"] is True


# --- slice 4: latest (ETag/304) + version ----------------------------------
def test_latest_etag_and_304(client):
    client.post("/policy/publish", json={"payload": _payload()})
    r = client.get("/policy/latest")
    assert r.status_code == 200
    etag = r.headers["etag"]
    # Same ETag -> 304 Not Modified.
    r2 = client.get("/policy/latest", headers={"If-None-Match": etag})
    assert r2.status_code == 304


def test_latest_404_when_empty(client):
    assert client.get("/policy/latest").status_code == 404


def test_get_specific_version(client):
    client.post("/policy/publish", json={"payload": _payload()})
    client.post("/policy/publish", json={"payload": _payload()})
    env1 = client.get("/policy/1")
    assert env1.status_code == 200
    assert env1.json()["payloadType"] == "application/vnd.piiguard.policy+json"
    assert client.get("/policy/99").status_code == 404


# --- slice 3: ack -----------------------------------------------------------
def test_ack_aggregates(client):
    client.post("/policy/ack", json={"device_id": "pc-1", "version": 1, "status": "applied"})
    client.post("/policy/ack", json={"device_id": "pc-2", "version": 1, "status": "rejected", "reason": "expired"})
    r = client.post("/policy/ack", json={"device_id": "pc-3", "version": 1, "status": "rejected", "reason": "expired"})
    summary = r.json()["summary"]
    assert summary["devices"] == 3
    assert summary["applied"] == 1
    assert summary["rejected"] == 2
    assert summary["reject_reasons"]["expired"] == 2


def test_ack_latest_per_device(client):
    client.post("/policy/ack", json={"device_id": "pc-1", "version": 1, "status": "rejected", "reason": "rollback"})
    # Same device re-acks as applied -> counts once, as applied.
    client.post("/policy/ack", json={"device_id": "pc-1", "version": 2, "status": "applied"})
    s = client.get("/policy/acks").json()["summary"]
    assert s["devices"] == 1
    assert s["applied"] == 1
    assert s["rejected"] == 0


def test_ack_invalid_status_rejected(client):
    r = client.post("/policy/ack", json={"device_id": "pc", "version": 1, "status": "maybe"})
    assert r.status_code == 422


# --- slice 4: model manifest ------------------------------------------------
def test_model_publish_and_latest(client):
    client.post("/policy/model/publish", json={
        "name": "pii-slm", "version": "0.3.0", "sha256": "abc", "url": "https://x/m"})
    env = client.get("/policy/model/latest").json()
    assert env["payloadType"] == "application/vnd.piiguard.model+json"
    # The signed manifest verifies.
    from app.policy import verify_model_envelope
    manifest = verify_model_envelope(env)
    assert manifest["name"] == "pii-slm"
    assert manifest["sha256"] == "abc"


def test_model_latest_404_when_empty(client):
    assert client.get("/policy/model/latest").status_code == 404


# --- slice 1 e2e: active policy changes detection ---------------------------
def test_active_policy_disables_detection_in_process(client):
    # Phone normally detected.
    before = client.post("/process", json={"text": "연락 010-1234-5678", "rules_only": True}).json()
    assert "PHONE" in before["detected_types"]

    # Deploy a policy that turns 전화번호 off, then process again.
    bundle = _bundle(_payload(types={"전화번호": {"on": False}}, version=1))
    assert client.post("/policy/deploy", json={"bundle": bundle}).json()["accepted"]

    after = client.post("/process", json={"text": "연락 010-1234-5678", "rules_only": True}).json()
    assert "PHONE" not in after["detected_types"]
