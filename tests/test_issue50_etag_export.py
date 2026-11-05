"""Issue #50: /policy/latest RFC ETag and paginated /logs/export."""
from pathlib import Path

import pytest

from app.etag import if_none_match_hits, quote_etag


# --- /policy/latest ETag ------------------------------------------------------
def _payload():
    return {
        "schema": 1, "org": "acme",
        "issued_at": "2026-11-05T16:40:00+09:00",
        "expires_at": "2999-01-01T00:00:00+00:00",
        "prev": "sha256:x", "model": {"sha256": "h"},
        "thresholds": {"confidential": 0.45, "personal": 0.35, "high_confidence": 0.7},
        "rules": [],
    }


@pytest.fixture()
def published(client):
    assert client.post("/policy/publish", json={"payload": _payload()}).status_code == 200
    r = client.get("/policy/latest")
    assert r.status_code == 200
    return r.headers["ETag"]


def _sha(client):
    return client.get("/policy/history").json()[0]["sha256"]


def test_latest_etag_is_quoted_rfc_form(client, published):
    sha = _sha(client)
    assert sha.startswith("sha256:") and '"' not in sha  # body value unchanged
    assert published == f'"{sha}"'


@pytest.mark.parametrize("make", [
    lambda sha: f'"{sha}"',                 # quoted (current form)
    lambda sha: sha,                        # unquoted (legacy client)
    lambda sha: f'W/"{sha}"',               # weak
    lambda sha: f'W/{sha}',                 # weak, unquoted
    lambda sha: f'"sha256:other", "{sha}"',  # list
    lambda sha: f'"sha256:other",{sha}',     # list, no space, unquoted
    lambda sha: "*",
])
def test_latest_304_variants(client, published, make):
    r = client.get("/policy/latest", headers={"If-None-Match": make(_sha(client))})
    assert r.status_code == 304
    assert r.headers["ETag"] == published


@pytest.mark.parametrize("value", [
    '"sha256:other"', "sha256:other", 'W/"sha256:other"', '"a", "b"', "", ",",
])
def test_latest_200_when_no_match(client, published, value):
    r = client.get("/policy/latest", headers={"If-None-Match": value})
    assert r.status_code == 200
    assert r.headers["ETag"] == published


@pytest.mark.parametrize("make", [
    lambda sha: f'"other,{sha},more"',      # comma inside one quoted tag (Codex P2)
    lambda sha: f'W/"x,{sha}"',
    lambda sha: f'"a", "b,{sha}"',
    lambda sha: f'"{sha}',                   # unterminated quote
    lambda sha: f'"x"{sha}',                 # junk after a quoted tag
])
def test_latest_quoted_commas_do_not_split(client, published, make):
    r = client.get("/policy/latest", headers={"If-None-Match": make(_sha(client))})
    assert r.status_code == 200


def test_latest_200_after_new_publish(client, published):
    client.post("/policy/publish", json={"payload": _payload()})
    r = client.get("/policy/latest", headers={"If-None-Match": published})
    assert r.status_code == 200 and r.headers["ETag"] != published


def test_etag_helpers():
    assert quote_etag("sha256:ab") == '"sha256:ab"'
    assert if_none_match_hits(None, "sha256:ab") is False
    assert if_none_match_hits('"sha256:ab"', '"sha256:ab"') is True  # current may be quoted
    assert if_none_match_hits('"other,sha256:ab,more"', "sha256:ab") is False
    assert if_none_match_hits('"x,y", W/"sha256:ab"', "sha256:ab") is True
    assert if_none_match_hits('sha256:zz, sha256:ab', "sha256:ab") is True


# --- /logs/export pagination ---------------------------------------------------
def _event(**kw):
    base = {"grade": "sensitive_S", "action": "send_transformed",
            "detected_types": ["rrn"], "detected_count": 1}
    base.update(kw)
    return base


def _decrypt(body):
    from app.crypto import decrypt_file
    return decrypt_file(Path(body["file"]))


def _set_created_at(ids_to_ts):
    from app.db import get_conn
    with get_conn() as conn:
        for event_id, ts in ids_to_ts.items():
            conn.execute("UPDATE event_log SET created_at = ? WHERE id = ?", (ts, event_id))


def test_export_cursor_pages_until_last(client):
    ids = [client.post("/logs/events", json=_event(request_id=f"r{i}")).json()["id"] for i in range(5)]
    seen = []
    params = {"limit": 2}
    pages = []
    while True:
        body = client.post("/logs/export", params=params).json()
        recs = _decrypt(body)
        assert body["exported"] == len(recs)
        pages.append(len(recs))
        seen += [r["id"] for r in recs]
        if body["next_cursor"] is None:
            break
        assert body["next_cursor"] == recs[-1]["id"]
        params["cursor"] = body["next_cursor"]
    assert pages == [2, 2, 1]
    assert seen == sorted(ids, reverse=True)


def test_export_exact_last_page_has_no_cursor(client):
    for i in range(2):
        client.post("/logs/events", json=_event())
    body = client.post("/logs/export", params={"limit": 2}).json()
    assert body["exported"] == 2 and body["next_cursor"] is None


def test_export_default_limit_unchanged(client):
    client.post("/logs/events", json=_event())
    body = client.post("/logs/export").json()
    assert body["exported"] == 1 and body["next_cursor"] is None
    assert client.post("/logs/export", params={"limit": 10001}).status_code == 422
    assert client.post("/logs/export", params={"cursor": 0}).status_code == 422


def test_export_period_filter(client):
    ids = [client.post("/logs/events", json=_event()).json()["id"] for _ in range(3)]
    _set_created_at({
        ids[0]: "2026-10-31T23:59:59+00:00",
        ids[1]: "2026-11-02T00:00:00+00:00",
        ids[2]: "2026-11-05T00:00:00+00:00",
    })
    body = client.post("/logs/export", params={
        "start": "2026-11-01T00:00:00Z", "end": "2026-11-05T00:00:00Z",
    }).json()
    assert sorted(r["id"] for r in _decrypt(body)) == [ids[1], ids[2]]
    body = client.post("/logs/export", params={"start": "2026-11-03"}).json()
    assert [r["id"] for r in _decrypt(body)] == [ids[2]]


def test_export_period_with_cursor(client):
    ids = [client.post("/logs/events", json=_event()).json()["id"] for _ in range(4)]
    _set_created_at({i: "2026-11-02T00:00:00+00:00" for i in ids[1:]})
    _set_created_at({ids[0]: "2026-10-01T00:00:00+00:00"})
    params = {"start": "2026-11-01T00:00:00Z", "limit": 2}
    first = client.post("/logs/export", params=params).json()
    assert [r["id"] for r in _decrypt(first)] == [ids[3], ids[2]]
    second = client.post("/logs/export", params={**params, "cursor": first["next_cursor"]}).json()
    assert [r["id"] for r in _decrypt(second)] == [ids[1]]
    assert second["next_cursor"] is None


@pytest.mark.parametrize("params", [
    {"start": "nope"}, {"end": ""}, {"start": "2026-11-05", "end": "2026-11-01"},
])
def test_export_bad_period_400(client, params):
    assert client.post("/logs/export", params=params).status_code == 400


def test_export_include_test(client):
    client.post("/logs/events", json=_event(test=True))
    real = client.post("/logs/events", json=_event()).json()["id"]
    body = client.post("/logs/export").json()
    assert [r["id"] for r in _decrypt(body)] == [real]
    body = client.post("/logs/export", params={"include_test": "true"}).json()
    assert body["exported"] == 2
    # Cursor paging keeps include_test semantics on later pages too.
    first = client.post("/logs/export", params={"include_test": "true", "limit": 1}).json()
    assert first["next_cursor"] == real
    second = client.post("/logs/export", params={
        "include_test": "true", "limit": 1, "cursor": first["next_cursor"],
    }).json()
    assert [r["test"] for r in _decrypt(second)] == [True] and second["next_cursor"] is None
