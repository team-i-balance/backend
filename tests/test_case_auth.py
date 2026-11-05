"""/cases requires a security token, and history records the token's label (issue #45)."""
import os
import sqlite3

import pytest

from app.auth import token_label

_EVENT = {"grade": "sensitive_S", "action": "send_as_is", "detected_types": ["NAME"], "detected_count": 1}
_CLOSE = {"conclusion": "violation", "memo": "사유 확인 — 위반"}


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _dev_token(c, scope):
    return c.post("/auth/dev-token", json={"scope": scope}).json()["token"]


def _new_case(c, token, **overrides):
    r = c.post("/logs/events", json={**_EVENT, **overrides}, headers=_bearer(token))
    assert r.status_code == 201
    return f"INC-{r.json()['id']}"


def _routes(case_id):
    return [
        ("get", "/cases", None),
        ("get", "/cases?queue=closed", None),
        ("get", f"/cases/{case_id}", None),
        ("post", f"/cases/{case_id}/close", _CLOSE),
        ("post", f"/cases/{case_id}/reopen", None),
        ("post", "/cases/close-bulk", {"ids": [case_id], "conclusion": "legit"}),
    ]


def _call(c, method, path, body, headers=None):
    kwargs = {"headers": headers or {}}
    if body is not None:
        kwargs["json"] = body
    return getattr(c, method)(path, **kwargs)


def test_cases_401_without_token(anon_client):
    case_id = _new_case(anon_client, _dev_token(anon_client, "api"))
    for method, path, body in _routes(case_id):
        assert _call(anon_client, method, path, body).status_code == 401, path
    # Auth runs before body validation: an invalid body still gets 401, not 422.
    assert anon_client.post(f"/cases/{case_id}/close", json={"bad": 1}).status_code == 401


def test_cases_401_with_unknown_token(anon_client):
    case_id = _new_case(anon_client, _dev_token(anon_client, "api"))
    for method, path, body in _routes(case_id):
        r = _call(anon_client, method, path, body, _bearer("not-a-real-token"))
        assert r.status_code == 401, path


def test_cases_403_with_api_token_and_no_history_written(anon_client):
    api = _dev_token(anon_client, "api")
    sec = _dev_token(anon_client, "security")
    case_id = _new_case(anon_client, api)
    for method, path, body in _routes(case_id):
        assert _call(anon_client, method, path, body, _bearer(api)).status_code == 403, path
    detail = anon_client.get(f"/cases/{case_id}", headers=_bearer(sec)).json()
    assert detail["status"] == "open"
    assert detail["history"] == []


def test_cases_200_with_security_token_and_by_is_token_label(anon_client):
    sec = _dev_token(anon_client, "security")
    h = _bearer(sec)
    case_id = _new_case(anon_client, sec)
    assert anon_client.get("/cases", headers=h).status_code == 200
    assert anon_client.get(f"/cases/{case_id}", headers=h).status_code == 200

    closed = anon_client.post(f"/cases/{case_id}/close", json=_CLOSE,
                              headers={**h, "X-Reviewer": "fake-admin"})
    assert closed.status_code == 200
    expected = f"security-dev:{token_label(sec)}"
    assert closed.json()["close"]["by"] == expected

    reopened = anon_client.post(f"/cases/{case_id}/reopen", headers=h)
    assert reopened.status_code == 200
    assert [entry["by"] for entry in reopened.json()["history"]] == [expected, expected]
    assert [entry["operation"] for entry in reopened.json()["history"]] == ["close", "reopen"]


def test_env_security_token_label_and_raw_token_never_stored(anon_client, monkeypatch):
    raw = "env-sec-raw-secret-value"
    monkeypatch.setenv("SECURITY_TOKENS", f"other, {raw}")
    h = _bearer(raw)
    opt = _new_case(anon_client, raw, action="revert_original", reason="business_need")
    req = _new_case(anon_client, raw)
    assert anon_client.post(f"/cases/{req}/close", json=_CLOSE, headers=h).status_code == 200
    assert anon_client.post(f"/cases/{req}/reopen", headers=h).status_code == 200
    bulk = anon_client.post("/cases/close-bulk", json={"ids": [opt], "conclusion": "legit"}, headers=h)
    assert bulk.status_code == 200

    expected = f"security:{token_label(raw)}"
    assert bulk.json()["items"][0]["close"]["by"] == expected
    history = anon_client.get(f"/cases/{req}", headers=h).json()["history"]
    assert [entry["by"] for entry in history] == [expected, expected]
    # Two different tokens get different labels.
    assert token_label("other") != token_label(raw)

    with sqlite3.connect(os.environ["LOG_DB_PATH"]) as conn:
        rows = conn.execute("SELECT reviewer FROM case_history").fetchall()
        dump = "\n".join(conn.iterdump())
    assert {r[0] for r in rows} == {expected}
    assert raw not in dump


@pytest.mark.parametrize("scope,status", [("api", 403), ("security", 200)])
def test_dev_token_scope_matrix_on_list(anon_client, scope, status):
    token = _dev_token(anon_client, scope)
    assert anon_client.get("/cases", headers=_bearer(token)).status_code == status
