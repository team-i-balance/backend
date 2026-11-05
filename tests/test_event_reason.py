"""Late employee reasons: persistence, migration, retries and concurrency."""
import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier

import pytest


def create(client, **overrides):
    body = {
        "grade": "sensitive_S", "action": "send_as_is",
        "detected_types": ["PHONE"], "detected_count": 1,
        "content_hash": "a" * 64, "request_id": "expired-work-id",
    }
    body.update(overrides)
    response = client.post("/logs/events", json=body)
    assert response.status_code == 201
    return response.json()


def submit(client, event_id, reason="business_need", text="거래처 확인에 실제 연락처가 필요했습니다."):
    return client.post(f"/events/{event_id}/reason", json={"reason": reason, "text": text})


def get_event(client, event_id):
    return next(e for e in client.get("/logs/events").json() if e["id"] == event_id)


@pytest.mark.parametrize("reason,queue", [
    ("business_need", "violation_candidate"), ("false_positive", "detection_improve"),
])
def test_pending_reason_arrives_in_logs_queue_and_stats(client, reason, queue):
    original = create(client)
    assert original["reason_requested_at"] == original["created_at"]
    assert original["reason_at"] is None and original["reason_text"] is None
    start = datetime.now(timezone.utc)
    response = submit(client, original["id"], reason, "  업무 설명  \n")
    end = datetime.now(timezone.utc)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    saved = response.json()
    assert saved["reason"] == reason and saved["reason_text"] == "업무 설명"
    assert saved["queue"] == queue
    assert start <= datetime.fromisoformat(saved["reason_at"]) <= end
    # All transmission metadata and the original request time stay intact.
    for key in original.keys() - {"reason", "reason_text", "reason_at", "queue"}:
        assert saved[key] == original[key]
    assert get_event(client, original["id"]) == saved
    assert client.get(f"/logs/queues/{queue}").json() == [saved]
    assert client.get(f"/logs/queues/{original['queue']}").json() == []
    stats = client.get("/logs/stats").json()
    assert stats["total"] == 1 and stats["by_queue"] == {queue: 1}
    assert stats["evasion_suspect"] == int(reason == "business_need")


def test_process_decide_returns_pending_event_and_reason_works_after_session_release(client):
    processed = client.post("/process", json={"text": "연락처 010-1234-5678", "rules_only": True})
    assert processed.status_code == 200
    work_id = processed.json()["work_id"]
    decided = client.post("/process/decide", json={"work_id": work_id, "action": "send_as_is"})
    assert decided.status_code == 200
    event = decided.json()["event"]
    assert event["reason_requested_at"] == event["created_at"]
    assert decided.json()["restore_available"] is False
    assert client.post("/process/decide", json={"work_id": work_id, "action": "send_as_is"}).status_code == 404
    saved = submit(client, event["id"])
    assert saved.status_code == 200
    assert saved.json()["reason_at"] is not None


def test_identical_retry_is_idempotent_but_other_explanation_cannot_overwrite(client):
    event = create(client)
    first = submit(client, event["id"]).json()
    assert submit(client, event["id"]).json() == first
    assert submit(client, event["id"], text="  거래처 확인에 실제 연락처가 필요했습니다. ").json() == first
    for reason, text in [("false_positive", first["reason_text"]), ("business_need", "변경한 사유")]:
        conflict = submit(client, event["id"], reason, text)
        assert conflict.status_code == 409
        assert conflict.json() == {"detail": "REASON_ALREADY_SUBMITTED"}
        assert get_event(client, event["id"]) == first


@pytest.mark.parametrize("overrides", [
    {"grade": "public_O"}, {"grade": "confidential_C"},
    {"action": "send_transformed"}, {"action": "cancel"},
    {"action": "revert_original"},
    {"action": "revert_original", "reason": "business_need"},
    {"reason": "false_positive"},
])
def test_non_pending_events_cannot_be_changed(client, overrides):
    original = create(client, **overrides)
    assert original["reason_requested_at"] is None
    expected_reason_at = original["created_at"] if original["reason"] else None
    assert original["reason_at"] == expected_reason_at
    response = submit(client, original["id"])
    assert response.status_code == 409
    assert response.json() == {"detail": "REASON_NOT_REQUESTED"}
    assert get_event(client, original["id"]) == original


@pytest.mark.parametrize("body", [
    {}, {"reason": "business_need"}, {"text": "업무 설명"},
    {"reason": "other", "text": "업무 설명"},
    {"reason": "business_need", "text": ""},
    {"reason": "business_need", "text": " \n\t\u3000"},
    {"reason": "business_need", "text": "가" * 501},
    {"reason": "business_need", "text": None},
    {"reason": "business_need", "text": 123},
    {"reason": "business_need", "text": "업무 설명", "reason_at": "2000-01-01"},
    {"reason": "business_need", "text": "업무 설명", "reason_requested_at": "2000-01-01"},
    {"reason": "business_need", "text": "업무 설명", "user_id": "fake-employee"},
])
def test_invalid_input_has_no_side_effects(client, body):
    original = create(client)
    assert client.post(f"/events/{original['id']}/reason", json=body).status_code == 422
    assert get_event(client, original["id"]) == original


def test_text_boundary_and_ingest_cannot_spoof_server_timestamps(client):
    event = create(client, reason_requested_at="2000-01-01", reason_at="2000-01-02")
    assert event["reason_requested_at"] == event["created_at"] and event["reason_at"] is None
    response = submit(client, event["id"], text=" 가" + "나" * 499 + " ")
    assert response.status_code == 200
    assert len(response.json()["reason_text"]) == 500


@pytest.mark.parametrize("event_id,status", [(0, 422), (-1, 422), (2**63, 422), ("INC-1", 422), (99999, 404)])
def test_invalid_or_missing_event(client, event_id, status):
    response = submit(client, event_id)
    assert response.status_code == status
    if status == 404:
        assert response.json() == {"detail": "EVENT_NOT_FOUND"}


@pytest.mark.parametrize("identical", [False, True])
def test_concurrent_submissions_preserve_one_reason_and_timestamp(client, identical):
    event = create(client)
    barrier = Barrier(2)

    def send(reason):
        barrier.wait(timeout=5)
        return submit(client, event["id"], reason)

    reasons = ["business_need", "business_need" if identical else "false_positive"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(send, reasons))
    assert sorted(r.status_code for r in responses) == ([200, 200] if identical else [200, 409])
    successes = [r.json() for r in responses if r.status_code == 200]
    assert all(saved == successes[0] for saved in successes)
    assert get_event(client, event["id"]) == successes[0]


def test_persists_across_new_process_and_repeated_initialization(client):
    event = create(client)
    saved = submit(client, event["id"]).json()
    output = subprocess.check_output([
        sys.executable, "-c",
        "import json; from app.db import init_db; from app.crud import list_events; "
        "init_db(); init_db(); print(json.dumps(list_events()))",
    ], text=True)
    assert json.loads(output) == [saved]


def test_failed_database_update_leaves_reason_and_queue_pending(client):
    from app.db import get_conn

    original = create(client)
    with get_conn() as conn:
        conn.execute("""CREATE TRIGGER reject_reason BEFORE UPDATE OF reason ON event_log
            BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="simulated storage failure"):
        submit(client, original["id"])
    assert get_event(client, original["id"]) == original


def test_legacy_database_upgrade_keeps_rows_and_backfills_tracking(client, tmp_path, monkeypatch):
    from app import db

    # Original schema, without any of the new columns.
    legacy_path = tmp_path / "legacy.db"
    with sqlite3.connect(legacy_path) as conn:
        conn.execute("""CREATE TABLE event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            request_id TEXT, grade TEXT NOT NULL, action TEXT NOT NULL, reason TEXT,
            detection_confidence TEXT, detected_types TEXT NOT NULL DEFAULT '[]',
            detected_count INTEGER NOT NULL DEFAULT 0, reverted INTEGER NOT NULL DEFAULT 0,
            restored INTEGER NOT NULL DEFAULT 0, content_hash TEXT, queue TEXT NOT NULL
        )""")
        conn.executemany("""INSERT INTO event_log (created_at, grade, action, reason, queue)
            VALUES ('2026-01-01T01:00:00+00:00', ?, ?, ?, ?)""", [
            ("sensitive_S", "send_as_is", None, "pre_warning"),
            ("sensitive_S", "revert_original", "business_need", "violation_candidate"),
            ("public_O", "send_as_is", None, "pre_warning"),
        ])
    monkeypatch.setattr(db, "DB_PATH", legacy_path)
    db.init_db()
    db.init_db()
    pending, immediate, public = [get_event(client, i) for i in (1, 2, 3)]
    assert pending["reason_requested_at"] == pending["created_at"]
    assert pending["reason_at"] is None and pending["reason_text"] is None
    assert immediate["reason_at"] == immediate["created_at"]
    assert immediate["reason_requested_at"] is None
    assert public["reason_requested_at"] is None and public["reason_at"] is None
    result = submit(client, 1)
    assert result.status_code == 200
    db.init_db()
    assert get_event(client, 1) == result.json()
    assert get_event(client, 2) == immediate
    assert get_event(client, 3) == public


def test_existing_reason_text_column_and_content_survive_upgrade(client, tmp_path, monkeypatch):
    from app import db

    # Another additive migration may already provide reason_text (#21).
    path = tmp_path / "context.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(db.SCHEMA)
        conn.execute("""INSERT INTO event_log
            (created_at, grade, action, reason, reason_text, queue)
            VALUES ('2026-01-01T01:00:00+00:00', 'sensitive_S', 'revert_original',
                    'business_need', '기존 사유', 'violation_candidate')""")
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    db.init_db()
    saved = get_event(client, 1)
    assert saved["reason_text"] == "기존 사유" and saved["reason"] == "business_need"


def test_parallel_initialization_does_not_race_column_migrations(client, tmp_path, monkeypatch):
    from app import db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "startup.db")
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: db.init_db(), range(2)))
    event = create(client)
    assert event["reason_requested_at"] == event["created_at"]
    assert submit(client, event["id"]).status_code == 200


def test_reason_route_is_in_openapi(client):
    schema = client.get("/openapi.json").json()
    route = schema["paths"]["/events/{event_id}/reason"]["post"]
    assert route["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("/EventOut")
    assert schema["components"]["schemas"]["EventReasonIn"]["additionalProperties"] is False


@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("reason", ["business_need", "false_positive"])
def test_case_sees_late_reason_without_changing_review_state_or_history(client, closed, reason):
    event = create(client)
    case_id = f"INC-{event['id']}"
    if closed:
        response = client.post(f"/cases/{case_id}/close", json={
            "conclusion": "violation", "cause": "care", "memo": "사유 미제출로 판단",
        })
        assert response.status_code == 200
    before = client.get(f"/cases/{case_id}").json()
    submitted = submit(client, event["id"], reason)
    assert submitted.status_code == 200
    after = client.get(f"/cases/{case_id}").json()
    assert after["event"] == submitted.json()
    assert after["need"] == "required"
    for key in ("status", "close", "history"):
        assert after[key] == before[key]
    queue = "closed" if closed else "required"
    listed = client.get("/cases", params={"queue": queue}).json()["items"]
    assert listed[0]["event"] == submitted.json()
    if not closed:
        reviewed = client.post(f"/cases/{case_id}/close", json={
            "conclusion": "legit", "memo": "직원 사유를 확인하고 예외 인정",
        })
        assert reviewed.status_code == 200
        assert reviewed.json()["event"] == submitted.json()
        assert reviewed.json()["close"]["conclusion"] == "legit"


def test_encrypted_export_includes_the_saved_reason_and_times(client):
    from app.crypto import decrypt_file

    event = create(client)
    saved = submit(client, event["id"], text="employee reason export marker").json()
    response = client.post("/logs/export", params={"queue": "violation_candidate"})
    assert response.status_code == 200
    path = Path(response.json()["file"])
    assert saved["reason_text"] not in path.read_text()
    assert decrypt_file(path) == [saved]
