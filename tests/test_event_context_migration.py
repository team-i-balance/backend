"""Upgrade existing event databases before indexing new context columns."""
import sqlite3
from contextlib import contextmanager

import pytest


LEGACY_SCHEMA = """
CREATE TABLE event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
    request_id TEXT, grade TEXT NOT NULL, action TEXT NOT NULL, reason TEXT,
    detection_confidence TEXT, detected_types TEXT NOT NULL DEFAULT '[]',
    detected_count INTEGER NOT NULL DEFAULT 0, reverted INTEGER NOT NULL DEFAULT 0,
    restored INTEGER NOT NULL DEFAULT 0, content_hash TEXT, queue TEXT NOT NULL
);
"""


def legacy_database(path, *, recent):
    with sqlite3.connect(path) as conn:
        conn.executescript(LEGACY_SCHEMA)
        conn.execute("""INSERT INTO event_log
            (created_at, request_id, grade, action, queue, detected_types, detected_count)
            VALUES ('2026-11-01T00:00:00Z', 'existing-work', 'sensitive_S',
                    'send_as_is', 'pre_warning', '["NAME"]', 1)""")
        if recent:
            for column in ("reason_requested_at TEXT", "reason_at TEXT", "reason_text TEXT",
                           "source TEXT NOT NULL DEFAULT 'text'", "is_test INTEGER NOT NULL DEFAULT 0"):
                conn.execute(f"ALTER TABLE event_log ADD COLUMN {column}")
            conn.execute("""UPDATE event_log SET reason = 'business_need',
                reason_text = '기존 업무 사유', reason_at = '2026-11-02T00:00:00Z',
                source = 'file', is_test = 1""")
        conn.row_factory = sqlite3.Row
        return dict(conn.execute("SELECT * FROM event_log").fetchone())


@pytest.mark.parametrize("recent", [False, True], ids=["pre-context-db", "current-main-db"])
def test_upgrade_adds_columns_before_user_index_and_preserves_rows(tmp_path, monkeypatch, recent):
    from app import db

    path = tmp_path / "existing.db"
    before = legacy_database(path, recent=recent)
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    db.init_db()  # Repeated startup must not erase context or existing metadata.
    with db.get_conn() as conn:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(event_log)")}
        assert {"user_id", "dept", "target_ai", "device_id", "reason_text", "items"} <= columns
        assert [row["name"] for row in conn.execute("PRAGMA index_info(idx_event_user_id)")] == ["user_id"]
        after = dict(conn.execute("SELECT * FROM event_log").fetchone())
        assert conn.execute("SELECT COUNT(*) FROM event_log").fetchone()[0] == 1
    assert {key: after[key] for key in before} == before
    assert after["user_id"] is None and after["items"] == "[]"


def test_index_failure_rolls_back_additive_migrations_and_can_be_retried(tmp_path, monkeypatch):
    from app import db

    path = tmp_path / "failed-upgrade.db"
    before = legacy_database(path, recent=False)
    monkeypatch.setattr(db, "DB_PATH", path)
    original_get_conn = db.get_conn

    @contextmanager
    def reject_context_index():
        with original_get_conn() as conn:
            conn.set_authorizer(lambda action, name, *_:
                                sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_CREATE_INDEX
                                and name == "idx_event_user_id" else sqlite3.SQLITE_OK)
            yield conn

    monkeypatch.setattr(db, "get_conn", reject_context_index)
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        db.init_db()
    with original_get_conn() as conn:
        assert dict(conn.execute("SELECT * FROM event_log").fetchone()) == before
        assert "user_id" not in {row["name"] for row in conn.execute("PRAGMA table_info(event_log)")}
    monkeypatch.setattr(db, "get_conn", original_get_conn)
    db.init_db()
    with db.get_conn() as conn:
        assert conn.execute("SELECT user_id, items FROM event_log").fetchone()["items"] == "[]"


def test_existing_database_starts_server_and_keeps_context_through_case_and_reason_flows(tmp_path):
    from tests.test_policy_persistence import run_python

    path = tmp_path / "startup.db"
    legacy_database(path, recent=False)
    actual = run_python("""
import json
from fastapi.testclient import TestClient
from main import app
with TestClient(app) as client:
    health = client.get('/health')
    old = client.get('/logs/events').json()[0]
    created = client.post('/logs/events', json={
        'grade': 'sensitive_S', 'action': 'send_as_is', 'user_id': 'emp-21',
        'dept': '보안팀', 'target_ai': 'ChatGPT', 'device_id': 'pc-21',
        'source': 'file', 'test': False,
        'items': [{'type': 'NAME', 'decision': 'raw', 'preview': '김*수', 'value_hash': 'a' * 64}],
    })
    assert created.status_code == 201, created.text
    event = created.json()
    case_id = f"INC-{event['id']}"
    initial = client.get(f'/cases/{case_id}')
    reason = client.post(f"/events/{event['id']}/reason", json={'reason': 'business_need', 'text': '업무상 필요'})
    closed = client.post(f'/cases/{case_id}/close', json={'conclusion': 'legit', 'memo': '검토 완료'})
    page = client.get('/cases', params={'queue': 'closed'})
    reopened = client.post(f'/cases/{case_id}/reopen')
    print(json.dumps({'health': health.status_code, 'old': old, 'created': event,
        'initial': initial.json(), 'reason': reason.json(), 'closed': closed.json(),
        'listed': page.json(), 'reopened': reopened.json(),
        'codes': [r.status_code for r in (initial, reason, closed, page, reopened)]}))
""", LOG_DB_PATH=str(path), LOG_KEYS_DIR=str(tmp_path / "log-keys"),
        LOG_EXPORT_DIR=str(tmp_path / "exports"), POLICY_DB_PATH=str(tmp_path / "policy.db"),
        POLICY_KEYS_DIR=str(tmp_path / "policy-keys"))
    assert actual["health"] == 200 and actual["codes"] == [200] * 5
    assert actual["old"]["user_id"] is None and actual["old"]["items"] == []
    assert actual["old"]["request_id"] == "existing-work"
    created = actual["created"]
    assert actual["initial"]["event"] == created
    for event in (actual["reason"], actual["closed"]["event"],
                  actual["listed"]["items"][0]["event"], actual["reopened"]["event"]):
        for field in ("user_id", "dept", "target_ai", "device_id", "items", "source", "test"):
            assert event[field] == created[field]
        assert event["reason_text"] == "업무상 필요"
        assert event["reason_at"] is not None
