"""Security-log events for file works (issue #32): metadata only, never values."""
import hashlib
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from tests.test_file_api import api, upload, workbook_bytes  # noqa: F401 (fixture)

SECRET = "API_KEY=TEST_KEY_1234567890"


def hidden_secret(book):
    book["숨김시트"]["A1"] = SECRET


def events(api):
    return api.client.get("/logs/events").json()


def assert_metadata_only(event):
    text = str(event)
    for private in ("김민수", "박영희", "TEST_KEY", "원본", ".xlsx"):
        assert private not in text


def test_blocked_file_is_logged_when_answered(api):
    data = workbook_bytes(hidden_secret)
    body = upload(api, data, filename="김민수_원본.xlsx").json()
    assert body["status"] == "BLOCKED"
    [event] = events(api)
    assert event["source"] == "file"
    assert event["request_id"] == body["work_id"]
    assert (event["grade"], event["action"]) == ("confidential_C", "cancel")
    assert event["detected_types"] == body["detected_types"] == ["API_KEY", "NAME"]
    assert event["detected_count"] == body["detected_count"]
    assert event["content_hash"] == hashlib.sha256(data).hexdigest()
    assert event["detection_confidence"] == "high"
    assert event["reason"] is None and event["reason_requested_at"] is None
    assert not event["reverted"] and not event["restored"]
    # Nothing was sent, so this is a warning under the current rules (#20).
    assert event["queue"] == "pre_warning"
    assert_metadata_only(event)


def test_ready_file_is_logged_once_when_its_copy_is_downloaded(api):
    data = workbook_bytes()
    body = upload(api, data).json()
    assert body["status"] == "READY"
    assert events(api) == []  # Not until the copy actually leaves.
    assert api.client.get(f"/files/{body['work_id']}/download").status_code == 200
    assert api.client.get(f"/files/{body['work_id']}/download").status_code == 404
    [event] = events(api)
    assert (event["source"], event["action"], event["grade"]) == (
        "file", "send_transformed", "sensitive_S",
    )
    assert event["request_id"] == body["work_id"]
    assert event["detected_types"] == ["NAME"] and event["detected_count"] == 5
    assert event["content_hash"] == hashlib.sha256(data).hexdigest()
    assert event["queue"] == "pre_warning"
    assert_metadata_only(event)
    # File events never become console cases (no raw send).
    assert api.client.get("/cases", params={"queue": "required"}).json()["items"] == []


@pytest.mark.parametrize("downloaded", [False, True])
def test_expiry_logs_cancel_only_for_copies_never_downloaded(api, monkeypatch, downloaded):
    from app import file_store

    now = [100.0]
    monkeypatch.setattr(file_store, "time", SimpleNamespace(monotonic=lambda: now[0]))
    work_id = upload(api).json()["work_id"]
    if downloaded:
        assert api.client.get(f"/files/{work_id}/download").status_code == 200
    sent = ["send_transformed"] if downloaded else []
    now[0] += 600
    assert api.client.get(f"/files/{work_id}/download").status_code == 404
    assert len(api.store) == 0 and api.sessions[0].closed.is_set()
    # Requests only purge; the sweeper writes the event, off every request path.
    assert [e["action"] for e in events(api)] == sent
    api.store.sweep()
    actions = [e["action"] for e in events(api)]
    assert actions == (sent or ["cancel"])
    assert all(e["request_id"] == work_id and e["source"] == "file" for e in events(api))


def test_failed_and_disconnected_uploads_are_not_logged(api):
    assert upload(api, b"not an xlsx").json()["status"] == "FAILED"
    work_id = upload(api).json()["work_id"]
    api.store.discard(work_id)  # What a client disconnect after processing does.
    assert events(api) == []


def test_blocked_answer_fails_closed_when_the_event_cannot_be_stored(api, monkeypatch):
    from app import file_events

    def down(_event):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(file_events.crud, "insert_event", down)
    response = upload(api, workbook_bytes(hidden_secret))
    assert response.status_code == 500
    body = response.json()
    assert (body["status"], body["reason"]) == ("FAILED", "EVENT_LOG_FAILED")
    assert body["blocked_types"] is None and "TEST_KEY" not in response.text
    assert len(api.store) == 0 and api.sessions[0].closed.is_set()


def test_copy_is_not_handed_out_when_its_event_cannot_be_stored(api, monkeypatch):
    from app import file_events

    work_id = upload(api).json()["work_id"]
    original = file_events.crud.insert_event
    monkeypatch.setattr(file_events.crud, "insert_event", lambda _event: 1 / 0)
    response = api.client.get(f"/files/{work_id}/download")
    assert response.status_code == 500
    assert response.json() == {"detail": "EVENT_LOG_FAILED"}
    assert response.headers["cache-control"] == "no-store"
    assert "content-disposition" not in response.headers
    monkeypatch.setattr(file_events.crud, "insert_event", original)
    # The claim is not undone; the mapping stays until expiry as for any download.
    assert api.client.get(f"/files/{work_id}/download").status_code == 404
    assert not api.sessions[0].closed.is_set()
    assert events(api) == []


def test_sweeper_reports_expiry_outside_the_lock_and_survives_errors():
    from app.file_events import FileEvent
    from app.file_store import FileWorkStore
    from app.schemas import Confidence, Grade

    class Session:
        def close(self):
            pass

    reported = []
    store = None

    def on_expired(event):
        len(store)  # Reporting runs unlocked: using the store here must not deadlock.
        reported.append(event.work_id)
        raise RuntimeError("logging is down")

    store = FileWorkStore(ttl_seconds=0.02, sweep_interval=0.01, on_expired=on_expired)
    for work_id, logged in (("logged", True), ("unlogged", False), ("downloaded", True)):
        event = FileEvent(work_id, Grade.sensitive, ("NAME",), 1, Confidence.high, "a" * 64)
        store.add(work_id=work_id, file_bytes=b"copy", session=Session(), grade=Grade.sensitive,
                  summary=None, event=event if logged else None)
    assert store.take_download("downloaded").event.work_id == "downloaded"
    done = threading.Event()
    store.start()
    try:
        for _ in range(200):
            if reported:
                break
            done.wait(0.01)
        done.wait(0.05)  # Further sweeps must keep running despite the error.
    finally:
        store.close()
    assert reported == ["logged"]


def test_text_events_keep_text_source_and_clients_may_send_file_events(client):
    processed = client.post("/process", json={"text": "010-1234-5678", "rules_only": True}).json()
    decided = client.post("/process/decide", json={
        "work_id": processed["work_id"], "action": "send_transformed",
    }).json()
    assert decided["event"]["source"] == "text"
    body = {"grade": "sensitive_S", "action": "send_transformed"}
    assert client.post("/logs/events", json=body).json()["source"] == "text"
    assert client.post("/logs/events", json={**body, "source": "file"}).json()["source"] == "file"
    assert client.post("/logs/events", json={**body, "source": "mail"}).status_code == 422


def test_existing_database_gains_source_and_keeps_rows_as_text(client, tmp_path, monkeypatch):
    from app import db

    path = tmp_path / "before-source.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(db.SCHEMA)
        conn.execute("""INSERT INTO event_log (created_at, grade, action, queue)
            VALUES ('2026-01-01T01:00:00+00:00', 'sensitive_S', 'cancel', 'pre_warning')""")
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    db.init_db()
    [old] = client.get("/logs/events").json()
    assert old["source"] == "text"
    created = client.post("/logs/events", json={
        "grade": "public_O", "action": "send_transformed", "source": "file",
    }).json()
    assert created["source"] == "file"
