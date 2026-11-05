"""False-positive report review and reason re-request (issue #48)."""
import sqlite3

import pytest

H1 = "a" * 64
H2 = "b" * 64


def event(client, **overrides):
    body = {"grade": "sensitive_S", "action": "revert_original", "reason": "false_positive",
            "detected_types": ["NAME"], "detected_count": 1}
    body.update(overrides)
    response = client.post("/logs/events", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def item(value_hash, preview=None, **extra):
    data = {"type": "NAME", "decision": "reverted", "value_hash": value_hash, **extra}
    if preview:
        data["preview"] = preview
    return data


def report(client, value_hash, user="emp-1", preview="윤*아", **overrides):
    return event(client, user_id=user, items=[item(value_hash, preview)], **overrides)


def groups(client, status="open"):
    response = client.get("/false-positives", params={"status": status})
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return {g["value_hash"]: g for g in response.json()}


def decide(client, value_hash, decision="exclude", **extra):
    return client.post(f"/false-positives/{value_hash}/decide",
                       json={"decision": decision, **extra})


def test_groups_by_value_hash_with_counts_preview_and_last_time(client):
    report(client, H1, user="emp-1", preview="윤*아")
    report(client, H1, user="emp-1", preview="윤**")
    last = report(client, H1, user="emp-2", preview=None)
    report(client, H2.upper(), user="emp-3", preview="******-*******")
    # Event reason business_need, but this item is reported as false positive.
    event(client, reason="business_need", user_id="emp-4",
          items=[item(H2, "010-****-****", reason="false_positive")])
    # Not counted: item-level business_need override, no value_hash, no items,
    # a non-FP event, and a test event.
    event(client, user_id="emp-9", items=[item(H1, reason="business_need")])
    event(client, user_id="emp-9", items=[{"type": "NAME", "decision": "reverted"}])
    event(client, user_id="emp-9")
    event(client, reason="business_need", user_id="emp-9", items=[item(H1)])
    event(client, user_id="emp-9", test=True, items=[item(H1)])

    open_ = groups(client)
    assert list(open_) == [H2, H1]  # latest report first
    g1 = open_[H1]
    assert g1["status"] == "open"
    assert g1["report_count"] == 3
    assert g1["employee_count"] == 2
    assert g1["last_reported_at"] == last["reason_at"]
    assert g1["preview"] == "윤**"  # latest non-null preview
    assert g1["types"] == ["NAME"]
    assert g1["decision"] is None
    assert open_[H2]["report_count"] == 2  # upper-case hash merged
    assert open_[H2]["employee_count"] == 2
    assert groups(client, "done") == {}


def test_same_hash_twice_in_one_event_counts_once(client):
    event(client, user_id="emp-1", items=[item(H1), item(H1)])
    assert groups(client)[H1]["report_count"] == 1


@pytest.mark.parametrize("decision", ["keep", "exclude"])
def test_decide_saves_and_moves_group_to_done(client, decision):
    report(client, H1)
    response = decide(client, H1, decision, why="  이름 아님  ")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "done"
    assert body["decision"]["decision"] == decision
    assert body["decision"]["why"] == "이름 아님"
    assert body["decision"]["by"]  # server-owned principal
    assert groups(client) == {}
    done = groups(client, "done")[H1]
    assert done["decision"] == body["decision"]


def test_decide_without_why_and_redecide_keeps_history(client):
    report(client, H1)
    assert decide(client, H1, "keep").json()["decision"]["why"] is None
    assert decide(client, H1.upper(), "exclude").json()["decision"]["decision"] == "exclude"
    from app.db import get_conn
    with get_conn() as conn:
        rows = conn.execute("SELECT value_hash, decision FROM false_positive_decision ORDER BY id")
        assert [tuple(r) for r in rows] == [(H1, "keep"), (H1, "exclude")]


def test_new_report_after_decision_reopens(client):
    report(client, H1, user="emp-1")
    decide(client, H1, "keep")
    assert H1 in groups(client, "done")
    report(client, H1, user="emp-2", preview="윤*아")
    g = groups(client)[H1]
    assert g["status"] == "open"
    assert g["report_count"] == 2
    assert g["decision"]["decision"] == "keep"  # previous verdict still shown
    assert groups(client, "done") == {}


def test_late_reason_submission_counts_as_new_report(client):
    # Raw send reported earlier; the employee explains FP after the decision.
    raw = event(client, action="send_as_is", reason=None, user_id="emp-2", items=[item(H1)])
    report(client, H1)
    decide(client, H1, "exclude")
    assert groups(client) == {}
    r = client.post(f"/events/{raw['id']}/reason",
                    json={"reason": "false_positive", "text": "이름이 아닙니다"})
    assert r.status_code == 200
    assert groups(client)[H1]["report_count"] == 2


def test_decide_validation_and_unknown_hash(client):
    report(client, H1)
    assert decide(client, H2).status_code == 404
    assert decide(client, H2).json()["detail"] == "FALSE_POSITIVE_NOT_FOUND"
    assert decide(client, "xyz").status_code == 422
    assert decide(client, H1, "delete").status_code == 422
    assert decide(client, H1, why="").status_code == 422
    assert client.post(f"/false-positives/{H1}/decide",
                       json={"decision": "keep", "by": "spoof"}).status_code == 422
    assert client.get("/false-positives", params={"status": "all"}).status_code == 422


def test_no_raw_value_is_stored_in_decisions(client):
    report(client, H1, preview="윤*아")
    decide(client, H1, why="사람 이름 아님")
    from app.db import get_conn
    with get_conn() as conn:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(false_positive_decision)")]
    assert cols == ["id", "value_hash", "decision", "why", "decided_by", "decided_at"]


# --- reason re-request ------------------------------------------------------
def test_reason_request_bumps_requested_at(client):
    raw = event(client, action="send_as_is", reason=None)
    before = raw["reason_requested_at"]
    response = client.post(f"/events/{raw['id']}/reason-request")
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    after = response.json()
    assert after["reason_requested_at"] > before
    assert after["reason_at"] is None and after["reason"] is None
    # Repeatable while still unexplained.
    again = client.post(f"/events/{raw['id']}/reason-request").json()
    assert again["reason_requested_at"] >= after["reason_requested_at"]


@pytest.mark.parametrize("grade,action", [
    ("sensitive_S", "revert_original"), ("confidential_C", "send_as_is"),
    ("confidential_C", "revert_original"),
])
def test_reason_request_covers_revert_and_confidential_raw_sends(client, grade, action):
    raw = event(client, grade=grade, action=action, reason=None)
    assert raw["reason_requested_at"] is not None
    response = client.post(f"/events/{raw['id']}/reason-request")
    assert response.status_code == 200, response.text
    assert response.json()["reason_requested_at"] > raw["reason_requested_at"]


def test_reason_request_rejects_ineligible_events(client):
    explained = event(client, action="send_as_is", reason=None)
    client.post(f"/events/{explained['id']}/reason",
                json={"reason": "business_need", "text": "업무상 필요"})
    with_reason = event(client, action="send_as_is", reason="business_need")
    transformed = event(client, action="send_transformed", reason=None)
    public = event(client, grade="public_O", action="send_as_is", reason=None)
    c_cancel = event(client, grade="confidential_C", action="cancel", reason=None)
    cases = [
        (c_cancel, 409, "REASON_NOT_REQUESTED"),
        (explained, 409, "REASON_ALREADY_SUBMITTED"),
        (with_reason, 409, "REASON_ALREADY_SUBMITTED"),
        (transformed, 409, "REASON_NOT_REQUESTED"),
        (public, 409, "REASON_NOT_REQUESTED"),
    ]
    for ev, code, detail in cases:
        r = client.post(f"/events/{ev['id']}/reason-request")
        assert (r.status_code, r.json()["detail"]) == (code, detail)
    r = client.post("/events/999999/reason-request")
    assert (r.status_code, r.json()["detail"]) == (404, "EVENT_NOT_FOUND")
    assert client.post("/events/0/reason-request").status_code == 422


# --- auth -------------------------------------------------------------------
def test_security_scope_required(anon_client):
    api = anon_client.post("/auth/dev-token", json={"scope": "api"}).json()["token"]
    sec = anon_client.post("/auth/dev-token", json={"scope": "security"}).json()["token"]
    calls = [
        ("get", "/false-positives", None),
        ("post", f"/false-positives/{H1}/decide", {"decision": "keep"}),
        ("post", "/events/1/reason-request", None),
    ]
    for method, url, body in calls:
        kw = {"json": body} if body else {}
        assert getattr(anon_client, method)(url, **kw).status_code == 401
        bad = {"Authorization": "Bearer nope"}
        assert getattr(anon_client, method)(url, headers=bad, **kw).status_code == 401
        h = {"Authorization": f"Bearer {api}"}
        assert getattr(anon_client, method)(url, headers=h, **kw).status_code == 403
    h = {"Authorization": f"Bearer {sec}"}
    assert anon_client.get("/false-positives", headers=h).status_code == 200
    # The decider is the authenticated principal: a token fingerprint, never the token.
    ev = anon_client.post("/logs/events", headers=h, json={
        "grade": "sensitive_S", "action": "revert_original", "reason": "false_positive",
        "items": [item(H1)],
    })
    assert ev.status_code == 201
    by = anon_client.post(f"/false-positives/{H1}/decide", headers=h,
                          json={"decision": "keep"}).json()["decision"]["by"]
    assert by.startswith("security-dev:") and sec not in by  # app.auth.security_principal


# --- migration --------------------------------------------------------------
def test_migration_is_idempotent_and_keeps_decisions(tmp_path, monkeypatch):
    from app import db

    path = tmp_path / "existing.db"
    with sqlite3.connect(path) as conn:  # DB from before #48
        conn.executescript(db.SCHEMA)
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    with db.get_conn() as conn:
        conn.execute("""INSERT INTO false_positive_decision
            (value_hash, decision, why, decided_by, decided_at)
            VALUES (?, 'keep', NULL, 'security:x', '2026-11-05T00:00:00+00:00')""", (H1,))
    db.init_db()
    db.init_db()
    with db.get_conn() as conn:
        rows = conn.execute("SELECT value_hash, decision FROM false_positive_decision").fetchall()
        assert [tuple(r) for r in rows] == [(H1, "keep")]
        indexes = [r["name"] for r in conn.execute("PRAGMA index_list(false_positive_decision)")]
        assert "idx_fp_decision_hash" in indexes
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("""INSERT INTO false_positive_decision
                (value_hash, decision, decided_by, decided_at)
                VALUES (?, 'maybe', 'x', 'y')""", (H1,))


# --- review fixes (PR #53) --------------------------------------------------
def test_item_level_report_keeps_creation_time_after_unrelated_reason(client):
    # Raw send with an explicit item-level FP report, event reason still pending.
    raw = event(client, action="send_as_is", reason=None, user_id="emp-1",
                items=[item(H1, "윤*아", reason="false_positive")])
    assert groups(client)[H1]["last_reported_at"] == raw["created_at"]
    decide(client, H1, "keep")
    # The employee later explains the raw send itself as business need.
    r = client.post(f"/events/{raw['id']}/reason",
                    json={"reason": "business_need", "text": "업무상 필요"})
    assert r.status_code == 200
    assert groups(client) == {}  # not reopened
    assert groups(client, "done")[H1]["last_reported_at"] == raw["created_at"]


def page(client, **params):
    response = client.get("/false-positives", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_groups_paginate_by_last_event_id_cursor(client):
    hashes = [f"{i:x}" * 64 for i in range(1, 6)]
    ids = [report(client, h)["id"] for h in hashes]
    first = page(client, limit=2)
    assert [g["last_event_id"] for g in first] == [ids[4], ids[3]]
    second = page(client, limit=2, cursor=first[-1]["last_event_id"])
    assert [g["last_event_id"] for g in second] == [ids[2], ids[1]]
    third = page(client, limit=2, cursor=second[-1]["last_event_id"])
    assert [g["last_event_id"] for g in third] == [ids[0]]
    assert page(client, limit=2, cursor=ids[0]) == []
    # Status filter applies before paging.
    decide(client, hashes[4], "keep")
    assert [g["value_hash"] for g in page(client, limit=1)] == [hashes[3]]
    assert [g["value_hash"] for g in page(client, status="done", limit=1)] == [hashes[4]]
    for bad in ({"limit": 0}, {"limit": 1001}, {"cursor": 0}, {"cursor": "x"}):
        assert client.get("/false-positives", params=bad).status_code == 422


def test_groups_sharing_last_event_are_not_split_across_pages(client):
    report(client, H2)
    shared = event(client, user_id="emp-1", items=[item(H1), item("c" * 64)])
    first = page(client, limit=1)
    assert [g["value_hash"] for g in first] == ["c" * 64, H1]
    assert {g["last_event_id"] for g in first} == {shared["id"]}
    rest = page(client, limit=1, cursor=shared["id"])
    assert [g["value_hash"] for g in rest] == [H2]


def test_employee_can_poll_reason_status_and_see_re_request(anon_client):
    api = anon_client.post("/auth/dev-token", json={"scope": "api"}).json()["token"]
    sec = anon_client.post("/auth/dev-token", json={"scope": "security"}).json()["token"]
    emp = {"Authorization": f"Bearer {api}"}
    sec_h = {"Authorization": f"Bearer {sec}"}
    raw = anon_client.post("/logs/events", headers=emp, json={
        "grade": "sensitive_S", "action": "send_as_is", "detected_types": ["NAME"],
    }).json()
    status = anon_client.get(f"/events/{raw['id']}/reason", headers=emp)
    assert status.status_code == 200
    assert status.headers["cache-control"] == "no-store"
    before = status.json()
    assert before == {"event_id": raw["id"], "reason_needed": True,
                      "reason_requested_at": raw["reason_requested_at"],
                      "reason": None, "reason_at": None}
    r = anon_client.post(f"/events/{raw['id']}/reason-request", headers=sec_h)
    assert r.status_code == 200
    after = anon_client.get(f"/events/{raw['id']}/reason", headers=emp).json()
    assert after["reason_needed"] is True
    assert after["reason_requested_at"] > before["reason_requested_at"]
    anon_client.post(f"/events/{raw['id']}/reason", headers=emp,
                     json={"reason": "false_positive", "text": "이름 아님"})
    done = anon_client.get(f"/events/{raw['id']}/reason", headers=emp).json()
    assert done["reason_needed"] is False and done["reason"] == "false_positive"
    public = anon_client.post("/logs/events", headers=emp, json={
        "grade": "public_O", "action": "send_as_is"}).json()
    r = anon_client.get(f"/events/{public['id']}/reason", headers=emp)
    assert r.json()["reason_needed"] is False
    r = anon_client.get("/events/999999/reason", headers=emp)
    assert (r.status_code, r.json()["detail"]) == (404, "EVENT_NOT_FOUND")
    assert anon_client.get(f"/events/{raw['id']}/reason").status_code == 401
