"""Case persistence, queue boundaries, audit trail and atomic transitions."""
import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier

import pytest


def event(client, **overrides):
    body = {
        "grade": "sensitive_S", "action": "send_as_is",
        "detected_types": ["NAME"], "detected_count": 1,
    }
    body.update(overrides)
    response = client.post("/logs/events", json=body)
    assert response.status_code == 201
    return response.json()


def new_case(client, optional=False, **overrides):
    if optional:
        overrides = {"action": "revert_original", "reason": "business_need", **overrides}
    return f"INC-{event(client, **overrides)['id']}"


def close(client, case_id, **overrides):
    return client.post(f"/cases/{case_id}/close", json={
        "conclusion": "violation", "memo": "사유 확인 — 위반", **overrides,
    })


def detail(client, case_id):
    response = client.get(f"/cases/{case_id}")
    assert response.status_code == 200
    return response.json()


def principal(client):
    """Expected `by` for the default client's runtime-issued security token."""
    from app.auth import token_label

    token = client.headers["Authorization"].split(" ", 1)[1]
    return f"security-dev:{token_label(token)}"


def page(client, queue="required", **params):
    response = client.get("/cases", params={"queue": queue, **params})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def test_need_follows_reason_at_send_time_not_action(client):
    # #60: required = raw send without a reason, optional = business_need at send time.
    required = new_case(client)
    optional = new_case(client, optional=True)
    revert_no_reason = new_case(client, action="revert_original")
    send_business = new_case(client, reason="business_need")
    excluded = [
        event(client, grade="public_O"),
        event(client, grade="public_O", action="revert_original"),
        event(client, action="cancel", detection_confidence="high"),
        event(client, action="send_transformed", reason="business_need"),
        event(client, grade="confidential_C", action="send_transformed"),
        event(client, grade="confidential_C", action="cancel"),
        # False positive at send time is a detection report (/false-positives).
        event(client, action="revert_original", reason="false_positive"),
        event(client, reason="false_positive"),
    ]
    req = page(client)["items"]
    assert [c["id"] for c in req] == [revert_no_reason, required]
    assert {c["need"] for c in req} == {"required"}
    opt = page(client, "optional")["items"]
    assert [c["id"] for c in opt] == [send_business, optional]
    assert [c["event"]["action"] for c in opt] == ["send_as_is", "revert_original"]
    assert {c["need"] for c in opt} == {"optional"}
    assert all(c["event"]["reason"] == "business_need" for c in opt)
    assert opt[0]["close"] is None
    assert detail(client, revert_no_reason)["need"] == "required"
    assert detail(client, send_business)["need"] == "optional"
    assert page(client, "closed") == {"items": [], "next_cursor": None}
    for ev in excluded:
        case_id = f"INC-{ev['id']}"
        assert client.get(f"/cases/{case_id}").status_code == 404
        assert close(client, case_id).status_code == 404


@pytest.mark.parametrize("action", ["send_as_is", "revert_original"])
@pytest.mark.parametrize("reason", [None, "business_need", "false_positive"])
def test_confidential_raw_send_is_always_required_case(client, action, reason):
    # #62: the C original left the company, so it is reviewed whatever the reason.
    created = event(client, grade="confidential_C", action=action, reason=reason)
    case_id = f"INC-{created['id']}"
    assert [c["id"] for c in page(client)["items"]] == [case_id]
    assert page(client, "optional")["items"] == []
    assert detail(client, case_id)["need"] == "required"
    if reason is None:
        assert created["reason_requested_at"] == created["created_at"]
    else:
        assert created["reason_requested_at"] is None
    bulk = client.post("/cases/close-bulk", json={"ids": [case_id], "conclusion": "legit"})
    assert bulk.status_code == 409
    assert bulk.json() == {"detail": "BULK_REQUIRES_OPTIONAL_CASES"}


@pytest.mark.parametrize("grade", ["sensitive_S", "confidential_C"])
@pytest.mark.parametrize("action", ["send_as_is", "revert_original"])
@pytest.mark.parametrize("reason", ["business_need", "false_positive"])
def test_reason_after_request_stays_required(client, grade, action, reason):
    created = event(client, grade=grade, action=action)
    case_id = f"INC-{created['id']}"
    assert created["reason_requested_at"] is not None
    assert detail(client, case_id)["need"] == "required"
    submitted = client.post(f"/events/{created['id']}/reason",
                            json={"reason": reason, "text": "늦게 낸 사유"})
    assert submitted.status_code == 200, submitted.text
    after = detail(client, case_id)
    assert after["need"] == "required"
    assert after["event"]["reason"] == reason
    assert [c["id"] for c in page(client)["items"]] == [case_id]
    assert page(client, "optional")["items"] == []
    bulk = client.post("/cases/close-bulk", json={"ids": [case_id], "conclusion": "legit"})
    assert bulk.status_code == 409
    assert bulk.json() == {"detail": "BULK_REQUIRES_OPTIONAL_CASES"}


def test_bulk_close_accepts_business_need_sent_as_is_and_rejects_required(client):
    send_business = new_case(client, reason="business_need")
    revert_business = new_case(client, optional=True)
    for required in (new_case(client, action="revert_original"), new_case(client),
                     new_case(client, grade="confidential_C", reason="business_need")):
        response = client.post("/cases/close-bulk", json={
            "ids": [send_business, revert_business, required], "conclusion": "legit"})
        assert response.status_code == 409
        assert response.json() == {"detail": "BULK_REQUIRES_OPTIONAL_CASES"}
        assert detail(client, send_business)["history"] == []
    response = client.post("/cases/close-bulk", json={
        "ids": [send_business, revert_business], "conclusion": "legit"})
    assert response.status_code == 200
    assert [c["status"] for c in response.json()["items"]] == ["closed", "closed"]


@pytest.mark.parametrize("conclusion,cause", [
    ("violation", "intent"), ("legit", "fit"), ("fp", None),
])
def test_close_detail_reopen_reclose_preserves_history_and_event(client, conclusion, cause):
    case_id = new_case(client, optional=True, content_hash="b" * 64)
    before = detail(client, case_id)
    logs = client.get("/logs/events").json()
    stats = client.get("/logs/stats").json()
    assert before["history"] == []
    start = datetime.now(timezone.utc)
    response = close(client, case_id, conclusion=conclusion, cause=cause,
                     memo="  판단 근거  ", rule=" 이름 → 태그 ")
    end = datetime.now(timezone.utc)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    closed = response.json()
    assert closed["status"] == "closed"
    assert closed["close"]["conclusion"] == conclusion
    assert closed["close"]["cause"] == cause
    assert closed["close"]["memo"] == "판단 근거"
    assert closed["close"]["rule"] == "이름 → 태그"
    assert closed["close"]["by"] == principal(client)
    assert start <= datetime.fromisoformat(closed["close"]["at"]) <= end
    assert detail(client, case_id) == closed
    assert page(client, "optional")["items"] == []
    assert page(client, "closed")["items"][0]["id"] == case_id
    assert close(client, case_id).status_code == 409
    assert detail(client, case_id)["history"] == closed["history"]

    reopened = client.post(f"/cases/{case_id}/reopen")
    assert reopened.status_code == 200
    opened = reopened.json()
    assert opened["status"] == "open" and opened["close"] is None
    assert opened["history"][0] == closed["history"][0]
    assert opened["history"][1]["operation"] == "reopen"
    assert opened["history"][1]["conclusion"] is None
    assert opened["history"][1]["memo"] is None
    assert page(client, "closed")["items"] == []
    assert page(client, "optional")["items"][0]["id"] == case_id
    assert client.post(f"/cases/{case_id}/reopen").status_code == 409
    assert close(client, case_id, conclusion="fp").status_code == 200
    after = detail(client, case_id)
    assert [h["operation"] for h in after["history"]] == ["close", "reopen", "close"]
    assert len({h["id"] for h in after["history"]}) == 3
    assert after["history"][0] == closed["history"][0]
    assert after["event"] == before["event"]
    assert client.get("/logs/events").json() == logs
    assert client.get("/logs/stats").json() == stats


def test_server_reviewer_dependency_ignores_caller_header(client):
    from app.case_router import get_reviewer

    case_id = new_case(client)
    response = client.post(f"/cases/{case_id}/close", headers={"X-Reviewer": "fake-admin"},
                           json={"conclusion": "legit", "memo": "사유 확인"})
    assert response.json()["close"]["by"] == principal(client)
    client.app.dependency_overrides[get_reviewer] = lambda: "verified-reviewer-42"
    try:
        response = client.post(f"/cases/{case_id}/reopen")
        assert response.json()["history"][-1]["by"] == "verified-reviewer-42"
    finally:
        client.app.dependency_overrides.clear()


def test_cases_and_history_survive_process_restart(client):
    case_id = new_case(client)
    assert close(client, case_id).status_code == 200
    assert client.post(f"/cases/{case_id}/reopen").status_code == 200
    assert close(client, case_id, conclusion="legit").status_code == 200
    expected = detail(client, case_id)
    # Fresh interpreter, no module globals or TestClient memory carried over.
    output = subprocess.check_output([
        sys.executable, "-c",
        "import json; from app.db import init_db; from app.case_crud import get_case; "
        "init_db(); init_db(); print(json.dumps(get_case('" + case_id + "')))",
    ], text=True)
    assert json.loads(output) == expected


def test_existing_event_only_database_is_upgraded_without_backfill(client):
    from app.db import get_conn, init_db

    case_id = new_case(client)
    original = client.get("/logs/events").json()
    with get_conn() as conn:
        conn.execute("DROP TABLE case_history")
    init_db()
    init_db()
    assert client.get("/logs/events").json() == original
    result = detail(client, case_id)
    assert result["status"] == "open" and result["history"] == []
    assert close(client, case_id).status_code == 200


@pytest.mark.parametrize("queue", ["required", "optional", "closed"])
def test_keyset_pagination_has_no_duplicates_and_excludes_new_head(client, queue):
    ids = [new_case(client, optional=queue == "optional") for _ in range(5)]
    if queue == "closed":
        # Close in reverse event order: closed pages use review order, not event ID.
        for case_id in reversed(ids):
            assert close(client, case_id).status_code == 200
        expected = ids
    else:
        expected = list(reversed(ids))
    first = page(client, queue, limit=2)
    assert [c["id"] for c in first["items"]] == expected[:2]
    newest = new_case(client, optional=queue == "optional")
    if queue == "closed":
        assert close(client, newest).status_code == 200
    second = page(client, queue, cursor=first["next_cursor"], limit=2)
    third = page(client, queue, cursor=second["next_cursor"], limit=2)
    assert third["next_cursor"] is None
    combined = first["items"] + second["items"] + third["items"]
    assert [c["id"] for c in combined] == expected
    assert page(client, queue)["items"][0]["id"] == newest


def test_bulk_close_only_optional_cases_and_records_same_server_actor(client):
    ids = [new_case(client, optional=True) for _ in range(3)]
    response = client.post("/cases/close-bulk", json={"ids": ids, "conclusion": "legit"})
    assert response.status_code == 200
    assert [c["id"] for c in response.json()["items"]] == ids
    assert page(client, "optional")["items"] == []
    for case_id in ids:
        result = detail(client, case_id)
        assert result["status"] == "closed"
        assert result["close"]["conclusion"] == "legit"
        assert result["close"]["memo"] == "사유 확인 — 업무 범위 내 사용"
        assert result["close"]["by"] == principal(client)
        assert len(result["history"]) == 1
    assert client.post("/cases/close-bulk", json={"ids": ids, "conclusion": "legit"}).status_code == 409
    assert all(len(detail(client, case_id)["history"]) == 1 for case_id in ids)


@pytest.mark.parametrize("invalid", ["missing", "required", "closed"])
def test_invalid_bulk_rolls_back_every_case(client, invalid):
    first = new_case(client, optional=True)
    if invalid == "missing":
        other = "INC-99999"
    else:
        other = new_case(client, optional=invalid == "closed")
        if invalid == "closed":
            assert close(client, other).status_code == 200
    response = client.post("/cases/close-bulk", json={"ids": [first, other], "conclusion": "legit"})
    assert response.status_code == (404 if invalid == "missing" else 409)
    assert detail(client, first)["history"] == []
    assert detail(client, first)["status"] == "open"


def test_storage_failure_rolls_back_prior_bulk_writes(client):
    from app.db import get_conn

    ids = [new_case(client, optional=True) for _ in range(2)]
    with get_conn() as conn:
        conn.execute(f"""CREATE TRIGGER fail_history BEFORE INSERT ON case_history
            WHEN NEW.event_id = {int(ids[1][4:])}
            BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="simulated storage failure"):
        client.post("/cases/close-bulk", json={"ids": ids, "conclusion": "legit"})
    for case_id in ids:
        result = detail(client, case_id)
        assert result["status"] == "open" and result["history"] == []


def test_concurrent_close_has_one_winner_and_one_audit_entry(client):
    case_id = new_case(client)
    barrier = Barrier(2)

    def submit(conclusion):
        barrier.wait(timeout=5)
        return close(client, case_id, conclusion=conclusion)

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(submit, ["violation", "fp"]))
    assert sorted(r.status_code for r in responses) == [200, 409]
    winner = next(r.json() for r in responses if r.status_code == 200)
    stored = detail(client, case_id)
    assert len(stored["history"]) == 1
    assert stored["close"] == winner["close"]


@pytest.mark.parametrize("body", [
    {"conclusion": "other", "memo": "사유"},
    {"conclusion": "fp"},
    {"conclusion": "fp", "memo": "  \n "},
    {"conclusion": "fp", "memo": "x" * 4001},
    {"conclusion": "fp", "memo": "사유", "cause": "other"},
    {"conclusion": "fp", "memo": "사유", "rule": "  "},
    {"conclusion": "fp", "memo": "사유", "rule": "x" * 2001},
    {"conclusion": "fp", "memo": "사유", "by": "fake-admin"},
    {"conclusion": "fp", "memo": "사유", "at": "2000-01-01T00:00:00Z"},
])
def test_invalid_close_does_not_write_history(client, body):
    case_id = new_case(client)
    assert client.post(f"/cases/{case_id}/close", json=body).status_code == 422
    assert detail(client, case_id)["history"] == []


@pytest.mark.parametrize("body", [
    {"ids": [], "conclusion": "legit"},
    {"ids": ["INC-1", "INC-1"], "conclusion": "legit"},
    {"ids": [f"INC-{i}" for i in range(1, 102)], "conclusion": "legit"},
    {"ids": ["INC-1"], "conclusion": "violation"},
    {"ids": ["INC-1"], "conclusion": "fp"},
    {"ids": ["INC-1"], "conclusion": "legit", "memo": " "},
    {"ids": ["INC-1"], "conclusion": "legit", "by": "fake-admin"},
    {"ids": ["INC-0"], "conclusion": "legit"},
])
def test_invalid_bulk_request(client, body):
    case_id = new_case(client, optional=True)
    assert client.post("/cases/close-bulk", json=body).status_code == 422
    assert detail(client, case_id)["history"] == []


@pytest.mark.parametrize("case_id", ["INC-0", "INC--1", "INC-01", "1", "INC-9223372036854775808"])
def test_invalid_case_id(client, case_id):
    assert client.get(f"/cases/{case_id}").status_code == 422
    assert close(client, case_id).status_code == 422
    assert client.post(f"/cases/{case_id}/reopen").status_code == 422


@pytest.mark.parametrize("params,status", [
    ({"queue": "other"}, 422),
    ({"limit": 0}, 422),
    ({"limit": 101}, 422),
    ({"cursor": ""}, 400),
    ({"cursor": "optional:1"}, 400),
    ({"cursor": "required:0"}, 400),
    ({"cursor": "required:9223372036854775808"}, 400),
    ({"cursor": "required:1 OR 1=1"}, 400),
])
def test_invalid_list_query(client, params, status):
    assert client.get("/cases", params=params).status_code == status


def test_missing_case_and_reopen_open_are_errors(client):
    assert client.get("/cases/INC-99999").status_code == 404
    assert close(client, "INC-99999").status_code == 404
    assert client.post("/cases/INC-99999/reopen").status_code == 404
    case_id = new_case(client)
    assert client.post(f"/cases/{case_id}/reopen").status_code == 409
    assert detail(client, case_id)["history"] == []


def test_openapi_includes_case_routes_and_response_models(client):
    schema = client.get("/openapi.json").json()
    for path, method in [
        ("/cases", "get"), ("/cases/{case_id}", "get"),
        ("/cases/{case_id}/close", "post"),
        ("/cases/{case_id}/reopen", "post"), ("/cases/close-bulk", "post"),
    ]:
        assert "200" in schema["paths"][path][method]["responses"]
    assert schema["components"]["schemas"]["CaseCloseIn"]["additionalProperties"] is False
