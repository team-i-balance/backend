"""#59 policy audit principal, #64 compile check before activation, #65 ops settings."""
import json
import os
from pathlib import Path

import pytest

from app.auth import token_label
from tests.test_policy_persistence import run_python

SECURITY = "sec-token-for-audit"
API = "api-token-for-audit"


def payload(version=1, rules=None, **extra):
    return {"schema": 1, "org": "acme", "version": version,
            "expires_at": "2999-01-01T00:00:00+00:00", "rules": rules or [], **extra}


def rule(rid, label, grade="S"):
    return {"id": rid, "label": label, "description": "d", "grade": grade, "action": "대체"}


@pytest.fixture()
def sec_client(client, monkeypatch):
    """The default client, but with an env-configured security token (as in production)."""
    monkeypatch.setenv("SECURITY_TOKENS", SECURITY)
    client.headers["Authorization"] = f"Bearer {SECURITY}"
    return client


def deploy(client, body):
    from app.policy import make_bundle

    return client.post("/policy/deploy", json={"bundle": make_bundle(body)})


# --- #59: who changed / published / activated ---------------------------------
def test_draft_publish_and_deploy_record_the_security_principal(sec_client):
    client = sec_client
    principal = f"security:{token_label(SECURITY)}"
    state = client.get("/policy/draft").json()
    saved = client.put("/policy/draft", headers={"If-Match": state["etag"]}, json={
        "payload": payload(), "changes": [{"what": "예외 인정", "src": "INC-29"}],
    }).json()
    assert saved["changes"][0]["by"] == saved["updated_by"] == principal
    assert SECURITY not in json.dumps(saved)  # never the raw token

    published = client.post("/policy/publish", headers={"If-Match": saved["etag"]})
    assert published.status_code == 200, published.text
    assert client.get("/policy/history").json()[0]["published_by"] == principal

    bundle = client.get("/policy/latest").json()
    assert client.post("/policy/deploy", json={"bundle": bundle}).json()["accepted"]
    assert client.get("/policy/current").json()["activated_by"] == principal


def test_existing_policy_db_gets_published_by_column(tmp_path):
    import sqlite3

    from app.policy import PolicyStore

    db = tmp_path / "old.db"
    with sqlite3.connect(db) as conn:  # schema before #59
        conn.execute("""CREATE TABLE policy_bundle (version INTEGER PRIMARY KEY, envelope TEXT NOT NULL,
                        sha256 TEXT NOT NULL, stored_at TEXT, rule_count INTEGER NOT NULL DEFAULT 0)""")
        conn.execute("INSERT INTO policy_bundle VALUES (1, '{}', 'sha256:x', NULL, 0)")
    store = PolicyStore(db_path=db)
    assert [b.published_by for b in store.history()] == [None]


# --- #64: refuse what the server cannot apply -----------------------------------
@pytest.mark.parametrize("rules", [
    [rule("r1", "고객 ID"), rule("r2", "고객 ID")],     # same label twice
    [rule("r1", "사람 이름")],                           # a fixed SLM label
    [rule("r1", "고객 ID"), rule("r1", "계약 코드")],   # same id twice
], ids=["duplicate_label", "fixed_label", "duplicate_id"])
def test_deploy_rejects_bundle_that_fails_to_compile(client, rules):
    assert deploy(client, payload(1, types={"전화번호": {"on": False}})).json()["accepted"]
    body = deploy(client, payload(2, rules=rules)).json()
    assert body["accepted"] is False and body["reason"] == "compile_failed"
    # The previous policy stays active; nothing about the rejected one is reported as applied.
    assert body["policy"]["version"] == 1
    current = client.get("/policy/current").json()
    assert current["version"] == current["effective_version"] == 1
    assert current["last_apply_error"] is None


def test_publish_refuses_to_sign_a_bundle_that_fails_to_compile(client):
    r = client.post("/policy/publish", json={"payload": payload(rules=[rule("r1", "주소")])})
    assert r.status_code == 422 and r.json()["detail"] == "POLICY_COMPILE_FAILED"
    assert client.get("/policy/history").json() == []


def test_compile_check_uses_the_loaded_slm_rules(client, tmp_path, monkeypatch):
    # A bundle rule may override a base rule with the same id AND label, but not reuse its label.
    base = tmp_path / "slm_policy.json"
    base.write_text(json.dumps({"rules": [rule("B-1", "프로젝트 코드")]}), encoding="utf-8")
    monkeypatch.setenv("LOCAL_SLM_POLICY", str(base))
    assert deploy(client, payload(1, rules=[rule("B-1", "프로젝트 코드", "C")])).json()["accepted"]
    assert deploy(client, payload(2, rules=[rule("N-1", "프로젝트 코드"), rule("N-2", "프로젝트 코드")])
                  ).json()["reason"] == "compile_failed"


def test_current_reports_effective_version_and_last_apply_error(client, monkeypatch):
    from app.policy import store

    assert deploy(client, payload(1, types={"전화번호": {"on": False}})).json()["accepted"]
    assert client.post("/process", json={"text": "010-1234-5678", "rules_only": True}).status_code == 200
    # A policy activated before the check existed (bypass it) that the SLM cannot apply.
    monkeypatch.setattr(store, "_precheck", lambda active: None)
    assert deploy(client, payload(2, rules=[rule("r1", "고객 ID"), rule("r2", "고객 ID")])).json()["accepted"]

    # Without an SLM on this server the duplicate labels are never compiled: v2 is in effect.
    current = client.get("/policy/current").json()
    assert (current["version"], current["effective_version"], current["last_apply_error"]) == (2, 2, None)

    # With an SLM configured the server keeps v1 and says why, as a code only.
    from app import policy_apply

    monkeypatch.setitem(policy_apply._runtime, "fingerprint", "<reset>")
    monkeypatch.setenv("LOCAL_SLM_MODEL_DIR", "/nonexistent-slm-for-test")
    current = client.get("/policy/current").json()
    assert current["version"] == 2 and current["effective_version"] == 1
    error = current["last_apply_error"]
    assert error["version"] == 2 and error["code"] == "rule_label_conflict" and error["at"]
    assert set(error) == {"version", "code", "at"}
    assert "고객 ID" not in json.dumps(current)


def test_current_reports_runtime_apply_failure(client, monkeypatch):
    import sys

    module = sys.modules["app.policy_apply"]
    assert deploy(client, payload(1, types={"전화번호": {"on": False}})).json()["accepted"]
    client.post("/process", json={"text": "010-1234-5678", "rules_only": True})
    real = module.compile_policy
    monkeypatch.setattr(module, "check_policy", lambda *a, **k: None)
    monkeypatch.setattr(module, "compile_policy",
                        lambda p: real(p) if p.version == 1 else (_ for _ in ()).throw(RuntimeError("boom")))
    assert deploy(client, payload(2)).json()["accepted"]
    client.post("/process", json={"text": "010-1234-5678", "rules_only": True})
    current = client.get("/policy/current").json()
    assert current["effective_version"] == 1
    assert current["last_apply_error"]["code"] == "compile_failed"
    assert "boom" not in json.dumps(current)


# --- #65: settings, export download, deploy scope, key id -----------------------
def test_current_reports_hash_key_presence_only(client, monkeypatch):
    monkeypatch.delenv("POLICY_VALUE_HASH_KEY", raising=False)
    assert client.get("/policy/current").json()["value_hash_key_set"] is False
    monkeypatch.setenv("POLICY_VALUE_HASH_KEY", "org-secret-value")
    body = client.get("/policy/current")
    assert body.json()["value_hash_key_set"] is True
    assert "org-secret-value" not in body.text


def test_security_downloads_export_file(client):
    client.post("/logs/events", json={"grade": "sensitive_S", "action": "send_transformed",
                                      "detected_types": ["rrn"], "detected_count": 1})
    path = Path(client.post("/logs/export").json()["file"])
    r = client.get(f"/logs/exports/{path.name}")
    assert r.status_code == 200
    assert r.content == path.read_bytes()
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["content-disposition"] == f'attachment; filename="{path.name}"'
    from app.crypto import decrypt_file

    out = path.parent.parent / "downloaded.enc.json"
    out.write_bytes(r.content)
    assert len(decrypt_file(out)) == 1


@pytest.mark.parametrize("name", [
    "..%2Fevents.db", "..%2F..%2Fetc%2Fpasswd", "%2Fetc%2Fpasswd", "events.db", "x.json",
    ".hidden.enc.json", "missing.enc.json", "dir.enc.json", "link.enc.json",
])
def test_export_download_only_serves_enc_json_files_in_the_folder(client, name):
    folder = Path(os.environ["LOG_EXPORT_DIR"])
    folder.mkdir(parents=True, exist_ok=True)
    secret = folder.parent / "outside.enc.json"
    secret.write_text("{}")
    (folder / "dir.enc.json").mkdir(exist_ok=True)
    if not (folder / "link.enc.json").exists():
        (folder / "link.enc.json").symlink_to(secret)
    (folder / "x.json").write_text("{}")
    assert client.get(f"/logs/exports/{name}").status_code == 404


def test_export_download_and_deploy_need_security(anon_client, monkeypatch):
    monkeypatch.setenv("API_TOKENS", API)
    monkeypatch.setenv("SECURITY_TOKENS", SECURITY)
    api = {"Authorization": f"Bearer {API}"}
    assert anon_client.get("/logs/exports/a.enc.json").status_code == 401
    assert anon_client.get("/logs/exports/a.enc.json", headers=api).status_code == 403
    assert anon_client.post("/policy/deploy", json={"bundle": {}}, headers=api).status_code == 403
    sec = {"Authorization": f"Bearer {SECURITY}"}
    assert anon_client.post("/policy/deploy", json={"bundle": {}}, headers=sec).json()["reason"] == "bad_type"
    # The employee program checks its api token with GET /policy/current: still allowed.
    assert anon_client.get("/policy/current", headers=api).status_code == 200


def test_default_key_id_is_unchanged(client):
    from app.policy import DEMO_KEY_ID

    assert DEMO_KEY_ID == "console-demo"
    r = client.post("/policy/publish", json={"payload": payload()})
    assert r.json()["keyid"] == "console-demo"


def test_key_id_can_be_renamed_and_old_bundles_still_verify(client):
    import shutil

    from app.policy import PRIV_KEY_PATH, TRUST_DIR

    assert client.post("/policy/publish", json={"payload": payload()}).status_code == 200
    old = client.get("/policy/1").json()
    # Renaming without the key files must not create a new identity silently.
    code = """
import json
from app.policy import store, SigningKeyError
store.initialize()
try:
    store.publish({"schema": 1, "org": "acme", "rules": []})
    print(json.dumps("published"))
except SigningKeyError:
    print(json.dumps("refused"))
"""
    assert run_python(code, POLICY_KEY_ID="ops-2026") == "refused"
    # Documented rename: copy both files; keep trust/console-demo.pub for older bundles.
    shutil.copy(PRIV_KEY_PATH, PRIV_KEY_PATH.with_name("ops-2026.key"))
    shutil.copy(TRUST_DIR / "console-demo.pub", TRUST_DIR / "ops-2026.pub")
    code = """
import json
from app.policy import store, DsseVerifier
store.initialize()
new = store.publish({"schema": 1, "org": "acme", "rules": []})
v = DsseVerifier()
print(json.dumps([new.envelope["signatures"][0]["keyid"],
                  v.verify(store.get_version(1).envelope, last_version=None).version,
                  v.verify(new.envelope, last_version=1).version]))
"""
    assert run_python(code, POLICY_KEY_ID="ops-2026") == ["ops-2026", 1, 2]
    assert old["signatures"][0]["keyid"] == "console-demo"


def test_invalid_key_id_fails_loudly():
    code = """
import json
try:
    import app.policy
    print(json.dumps("imported"))
except RuntimeError:
    print(json.dumps("refused"))
"""
    assert run_python(code, POLICY_KEY_ID="../escape") == "refused"
