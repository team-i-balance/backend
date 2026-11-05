"""GET /logs/changes: revision markers the console polls (no event contents)."""
from datetime import datetime, timedelta, timezone

H1 = "a" * 64


def event(client, **overrides):
    body = {"grade": "sensitive_S", "action": "send_as_is",
            "detected_types": ["NAME"], "detected_count": 1}
    body.update(overrides)
    response = client.post("/logs/events", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def changes(client, etag=None):
    response = client.get("/logs/changes", headers={"If-None-Match": etag} if etag else {})
    assert response.headers["cache-control"] == "no-store"
    return response


def snapshot(client):
    response = changes(client)
    assert response.status_code == 200, response.text
    assert response.headers["etag"] == f'"changes:{response.json()["rev"]}"'
    return response.json(), response.headers["etag"]


def test_empty_server_shape(client):
    body, _ = snapshot(client)
    assert body["events"]["last_id"] is None
    assert body["cases"] == {"last_id": None}
    assert body["false_positives"]["last_id"] is None
    assert body["false_positives"]["reports"] == body["events"]
    assert body["policy"]["ack_last_id"] is None
    assert body["policy"]["latest"] is None and body["policy"]["active"] is None
    assert body["policy"]["draft_etag"] == client.get("/policy/draft").json()["etag"]


def test_unchanged_state_returns_304_with_same_etag(client):
    event(client)
    body, etag = snapshot(client)
    response = changes(client, etag)
    assert response.status_code == 304
    assert response.content == b""
    assert response.headers["etag"] == etag
    # Weak / unquoted / list forms of the same tag also match.
    for header in (f"W/{etag}", etag.strip('"'), f'"other", {etag}'):
        assert changes(client, header).status_code == 304
    assert changes(client, '"changes:stale"').status_code == 200


def test_new_event_moves_events_only(client):
    first = event(client)
    before, etag = snapshot(client)
    second = event(client, test=True)  # test events count too (console may show them)
    after = changes(client, etag).json()
    assert after["events"]["last_id"] == second["id"] > first["id"]
    for area in ("cases", "policy"):
        assert after[area] == before[area]
    assert after["false_positives"]["last_id"] == before["false_positives"]["last_id"]


def test_reason_submit_and_re_request_move_change_seq(client):
    raw = event(client, reason=None)
    before, etag = snapshot(client)
    assert client.post(f"/events/{raw['id']}/reason-request").status_code == 200
    requested = changes(client, etag).json()
    assert requested["events"]["change_seq"] > before["events"]["change_seq"]
    assert requested["events"]["last_id"] == before["events"]["last_id"]

    etag = f'"changes:{requested["rev"]}"'
    assert client.post(f"/events/{raw['id']}/reason",
                       json={"reason": "business_need", "text": "업무상 필요"}).status_code == 200
    submitted = changes(client, etag).json()
    assert submitted["events"]["change_seq"] > requested["events"]["change_seq"]


def test_re_request_is_seen_even_if_another_row_has_a_later_time(client):
    # A future reason_requested_at on another row (migrated data, clock fix) must not
    # hide a real re-request: the marker is a sequence, not a timestamp.
    import sqlite3
    from app.db import DB_PATH
    other = event(client, reason=None)
    raw = event(client, reason=None)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE event_log SET reason_requested_at = '2999-01-01T00:00:00+00:00' WHERE id = ?",
                     (other["id"],))
    before, etag = snapshot(client)
    assert client.post(f"/events/{raw['id']}/reason-request").status_code == 200
    assert changes(client, etag).json()["events"]["change_seq"] > before["events"]["change_seq"]


def test_new_report_moves_false_positive_area(client):
    # Reports live in event_log: a late reason that turns an event into a report
    # must change the false_positives area, not only events.
    raw = event(client, reason=None, items=[{"type": "NAME", "decision": "raw", "value_hash": H1}])
    before, etag = snapshot(client)
    event(client, action="revert_original", reason="false_positive",
          items=[{"type": "NAME", "decision": "reverted", "value_hash": H1}])
    after = changes(client, etag).json()
    assert after["false_positives"] != before["false_positives"]
    etag = f'"changes:{after["rev"]}"'
    assert client.post(f"/events/{raw['id']}/reason",
                       json={"reason": "false_positive", "text": "오탐"}).status_code == 200
    assert changes(client, etag).json()["false_positives"]["reports"]["change_seq"] > after["false_positives"]["reports"]["change_seq"]


def test_policy_ack_moves_policy(client):
    published = client.post("/policy/publish", json={"payload": {"schema": 1, "org": "acme"}},
                             headers={"If-Match": client.get("/policy/draft").json()["etag"]})
    assert published.status_code == 200, published.text
    before, etag = snapshot(client)
    ack = client.post("/policy/ack", json={"device_id": "pc-1", "version": published.json()["version"],
                                           "status": "applied"})
    assert ack.status_code in (200, 201), ack.text
    after = changes(client, etag).json()["policy"]
    assert after["ack_last_id"] is not None and after["ack_last_id"] != before["policy"]["ack_last_id"]


def test_change_seq_is_internal(client):
    ev = event(client, reason=None)
    client.post(f"/events/{ev['id']}/reason-request")
    assert "change_seq" not in client.get("/logs/events").json()[0]
    assert "change_seq" not in client.post(f"/events/{ev['id']}/reason-request").json()


def test_case_close_and_reopen_move_cases(client):
    case_id = f"INC-{event(client)['id']}"
    before, etag = snapshot(client)
    assert client.post(f"/cases/{case_id}/close",
                       json={"conclusion": "violation", "memo": "위반"}).status_code == 200
    closed = changes(client, etag).json()
    assert closed["cases"]["last_id"] is not None
    assert closed["events"] == before["events"]
    assert client.post(f"/cases/{case_id}/reopen").status_code == 200
    assert changes(client, f'"changes:{closed["rev"]}"').json()["cases"]["last_id"] > closed["cases"]["last_id"]


def test_false_positive_decision_moves_false_positives(client):
    event(client, action="revert_original", reason="false_positive",
          items=[{"type": "NAME", "decision": "reverted", "value_hash": H1}])
    before, etag = snapshot(client)
    assert client.post(f"/false-positives/{H1}/decide", json={"decision": "keep"}).status_code == 200
    after = changes(client, etag).json()
    assert after["false_positives"]["last_id"] is not None
    assert after["events"] == before["events"] and after["cases"] == before["cases"]


def test_policy_draft_publish_and_deploy_move_policy(client):
    before, etag = snapshot(client)
    draft = client.get("/policy/draft").json()
    saved = client.put("/policy/draft", json={"payload": {"schema": 1, "org": "acme"}, "changes": []},
                       headers={"If-Match": draft["etag"]})
    assert saved.status_code == 200, saved.text
    after_draft = changes(client, etag).json()["policy"]
    # The console compares this with the etag it got from its own save.
    assert after_draft["draft_etag"] == saved.json()["etag"] != before["policy"]["draft_etag"]

    published = client.post("/policy/publish", json={"payload": {"schema": 1, "org": "acme"}},
                            headers={"If-Match": saved.json()["etag"]})
    assert published.status_code == 200, published.text
    body, etag = snapshot(client)
    assert body["policy"]["latest"] == published.json()["version"]

    envelope = client.get(f"/policy/{body['policy']['latest']}").json()
    assert client.post("/policy/deploy", json={"bundle": envelope}).json()["accepted"]
    deployed = changes(client, etag).json()["policy"]
    assert deployed["active"] == body["policy"]["latest"]
    assert deployed["activated_at"]


def test_does_not_expose_event_contents(client):
    event(client, user_id="emp-secret", dept="개발팀", reason_text="민감한 사유",
          items=[{"type": "NAME", "decision": "raw", "value_hash": H1, "preview": "윤*아"}])
    text = changes(client).text
    for leaked in ("emp-secret", "개발팀", "민감한 사유", "윤*아", H1):
        assert leaked not in text


def test_security_scope_required(anon_client):
    assert anon_client.get("/logs/changes").status_code == 401
    api = anon_client.post("/auth/dev-token", json={"scope": "api"}).json()["token"]
    assert anon_client.get("/logs/changes", headers={"Authorization": f"Bearer {api}"}).status_code == 403
    sec = anon_client.post("/auth/dev-token", json={"scope": "security"}).json()["token"]
    assert anon_client.get("/logs/changes", headers={"Authorization": f"Bearer {sec}"}).status_code == 200


def test_change_seq_index_exists(client):
    import sqlite3
    from app.db import DB_PATH
    with sqlite3.connect(DB_PATH) as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_event_change_seq" in names
