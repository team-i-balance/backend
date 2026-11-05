"""Auth enforcement tests (issue #10)."""


def _ev():
    return {"grade": "public_O", "action": "send_as_is"}


# --- public endpoints -------------------------------------------------------
def test_health_and_root_are_public(anon_client):
    assert anon_client.get("/health").status_code == 200
    assert anon_client.get("/").status_code == 200


def test_dev_token_issues_api_and_security(anon_client):
    r = anon_client.post("/auth/dev-token", json={"scope": "api"})
    assert r.status_code == 200
    assert r.json()["scope"] == "api"
    assert r.json()["token"]
    r2 = anon_client.post("/auth/dev-token", json={"scope": "security"})
    assert r2.json()["scope"] == "security"


# --- enforcement ------------------------------------------------------------
def test_protected_endpoints_401_without_token(anon_client):
    assert anon_client.post("/process", json={"text": "hi", "rules_only": True}).status_code == 401
    assert anon_client.post("/logs/events", json=_ev()).status_code == 401
    assert anon_client.get("/logs/stats").status_code == 401
    assert anon_client.post("/logs/export").status_code == 401


def test_invalid_token_rejected(anon_client):
    h = {"Authorization": "Bearer not-a-real-token"}
    assert anon_client.get("/logs/stats", headers=h).status_code == 401   # security route
    assert anon_client.post("/logs/events", json=_ev(), headers=h).status_code == 401  # api route


def test_issue_token_rejects_bad_scope():
    import pytest

    from app.auth import issue_token

    with pytest.raises(ValueError):
        issue_token("admin")


def test_api_token_works_for_api_scope(anon_client):
    token = anon_client.post("/auth/dev-token", json={"scope": "api"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    # api scope: /process and POST /logs/events
    assert anon_client.post("/process", json={"text": "연락 010-1234-5678", "rules_only": True}, headers=h).status_code == 200
    assert anon_client.post("/logs/events", json=_ev(), headers=h).status_code == 201


def test_api_token_denied_on_security_scope(anon_client):
    token = anon_client.post("/auth/dev-token", json={"scope": "api"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    # security scope: reads / export
    assert anon_client.get("/logs/stats", headers=h).status_code == 403
    assert anon_client.get("/logs/events", headers=h).status_code == 403
    assert anon_client.post("/logs/export", headers=h).status_code == 403


def test_security_token_works_everywhere(anon_client):
    token = anon_client.post("/auth/dev-token", json={"scope": "security"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    assert anon_client.get("/logs/stats", headers=h).status_code == 200          # security
    assert anon_client.post("/logs/events", json=_ev(), headers=h).status_code == 201  # api too


def test_env_tokens_accepted(anon_client, monkeypatch):
    # A token provided via env must be accepted without dev-token issuance.
    monkeypatch.setenv("SECURITY_TOKENS", "env-sec-1, env-sec-2")
    h = {"Authorization": "Bearer env-sec-1"}
    assert anon_client.get("/logs/stats", headers=h).status_code == 200


def test_dev_token_can_be_disabled(anon_client, monkeypatch):
    monkeypatch.setenv("DISABLE_DEV_TOKEN", "1")
    assert anon_client.post("/auth/dev-token", json={"scope": "api"}).status_code == 403


def test_policy_write_requires_security(anon_client):
    api_tok = anon_client.post("/auth/dev-token", json={"scope": "api"}).json()["token"]
    sec_tok = anon_client.post("/auth/dev-token", json={"scope": "security"}).json()["token"]
    payload = {"payload": {"schema": 1, "org": "acme", "rules": []}}
    # publish needs security: api token is forbidden, security token passes the
    # auth check (the publish body behavior itself is covered elsewhere).
    assert anon_client.post("/policy/publish", json=payload, headers={"Authorization": f"Bearer {api_tok}"}).status_code == 403
    sec_code = anon_client.post("/policy/publish", json=payload, headers={"Authorization": f"Bearer {sec_tok}"}).status_code
    assert sec_code != 403  # not blocked by auth
