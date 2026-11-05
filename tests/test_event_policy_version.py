"""Policy version on events (issue #49): store, return, migrate, count."""
import sqlite3

import pytest

from tests.test_file_api import api, upload, workbook_bytes  # noqa: F401 (fixture)
from tests.test_policy_flow import _bundle, _payload

BASE = {"grade": "sensitive_S", "action": "send_as_is"}


def deploy(client, version):
    bundle = _bundle(_payload(version=version))
    assert client.post("/policy/deploy", json={"bundle": bundle}).json()["accepted"]


def stats(client, **params):
    return client.get("/logs/stats", params=params).json()


# --- store and return --------------------------------------------------------
def test_client_policy_version_is_stored_and_returned_everywhere(client):
    created = client.post("/logs/events", json={**BASE, "policy_version": 12}).json()
    assert created["policy_version"] == 12
    [listed] = client.get("/logs/events").json()
    assert listed["policy_version"] == 12

    [case] = client.get("/cases", params={"queue": "required"}).json()["items"]
    assert case["event"]["policy_version"] == 12
    assert client.get(f"/cases/{case['id']}").json()["event"]["policy_version"] == 12


def test_policy_version_is_optional_and_null_when_missing(client):
    created = client.post("/logs/events", json=BASE).json()
    assert created["policy_version"] is None
    assert client.post("/logs/events", json={**BASE, "policy_version": None}).json()["policy_version"] is None
    assert [e["policy_version"] for e in client.get("/logs/events").json()] == [None, None]
    [case, _] = client.get("/cases", params={"queue": "required"}).json()["items"]
    assert case["event"]["policy_version"] is None


@pytest.mark.parametrize("bad", ["v12", 1.5])
def test_invalid_policy_version_is_rejected(client, bad):
    assert client.post("/logs/events", json={**BASE, "policy_version": bad}).status_code == 422


def test_every_deployable_version_can_be_logged(api):
    # The verifier accepts any integer newer than the last one, including a
    # negative first version; server-built events must still be stored.
    deploy(api.client, -1)
    assert client_version(api.client, -1)
    work = api.client.post("/process", json={"text": "010-1234-5678", "rules_only": True}).json()
    decided = api.client.post("/process/decide", json={"work_id": work["work_id"], "action": "cancel"})
    assert decided.status_code == 200 and decided.json()["event"]["policy_version"] == -1
    ready = upload(api, workbook_bytes()).json()
    assert api.client.get(f"/files/{ready['work_id']}/download").status_code == 200
    assert [e["policy_version"] for e in api.client.get("/logs/events").json()] == [-1, -1, -1]
    assert stats(api.client)["by_policy_version"] == {"-1": 3}


def client_version(client, version):
    return client.post("/logs/events", json={**BASE, "policy_version": version}).json()[
        "policy_version"] == version


# --- server-built events -----------------------------------------------------
def _decide(client, work_id, action="send_transformed"):
    return client.post("/process/decide", json={"work_id": work_id, "action": action}).json()


def test_decide_without_active_policy_records_null(client):
    work = client.post("/process", json={"text": "010-1234-5678", "rules_only": True}).json()
    assert _decide(client, work["work_id"])["event"]["policy_version"] is None


def test_decide_records_the_version_active_when_the_text_was_processed(client):
    deploy(client, 3)
    work = client.post("/process", json={"text": "010-1234-5678", "rules_only": True}).json()
    deploy(client, 4)  # A newer policy arriving before decide does not relabel it.
    event = _decide(client, work["work_id"], action="send_as_is")["event"]
    assert event["policy_version"] == 3

    later = client.post("/process", json={"text": "010-1234-5678", "rules_only": True}).json()
    assert _decide(client, later["work_id"])["event"]["policy_version"] == 4
    assert [e["policy_version"] for e in client.get("/logs/events").json()] == [4, 3]
    [case] = client.get("/cases", params={"queue": "required"}).json()["items"]
    assert case["event"]["policy_version"] == 3


def test_file_events_record_the_server_policy_version(api):
    assert api.client.post("/logs/events", json=BASE).status_code == 201  # Unrelated null row.
    deploy(api.client, 7)
    ready = upload(api, workbook_bytes()).json()
    assert ready["status"] == "READY"
    assert api.client.get(f"/files/{ready['work_id']}/download").status_code == 200

    def hidden_secret(book):
        book["숨김시트"]["A1"] = "API_KEY=TEST_KEY_1234567890"

    deploy(api.client, 8)
    assert upload(api, workbook_bytes(hidden_secret)).json()["status"] == "BLOCKED"
    files = [(e["action"], e["policy_version"])
             for e in api.client.get("/logs/events").json() if e["source"] == "file"]
    assert files == [("cancel", 8), ("send_transformed", 7)]


def _with_phone(book):
    book.active["E3"] = "010-1234-5678"


def test_file_is_checked_under_the_policy_it_is_logged_with(api):
    phone_off = _bundle(_payload(types={"전화번호": {"on": False}}, version=5))
    assert api.client.post("/policy/deploy", json={"bundle": phone_off}).json()["accepted"]
    # No /process call first: the file path itself must apply the policy.
    body = upload(api, workbook_bytes(_with_phone)).json()
    assert body["status"] == "READY"
    assert "PHONE" not in body["detected_types"]
    assert api.client.get(f"/files/{body['work_id']}/download").status_code == 200
    [event] = api.client.get("/logs/events").json()
    assert event["policy_version"] == 5 and "PHONE" not in event["detected_types"]


def test_file_keeps_the_version_snapshotted_before_a_concurrent_deploy(api, monkeypatch):
    deploy(api.client, 1)
    real = api.service.sanitize_xlsx

    def deploy_while_sanitizing(*args, **kwargs):
        result = real(*args, **kwargs)
        phone_off = _bundle(_payload(types={"전화번호": {"on": False}}, version=2))
        assert api.client.post("/policy/deploy", json={"bundle": phone_off}).json()["accepted"]
        return result

    monkeypatch.setattr(api.service, "sanitize_xlsx", deploy_while_sanitizing)
    body = upload(api, workbook_bytes(_with_phone)).json()
    assert "PHONE" in body["detected_types"]  # Checked under version 1.
    assert api.client.get(f"/files/{body['work_id']}/download").status_code == 200
    [event] = api.client.get("/logs/events").json()
    assert event["policy_version"] == 1


# --- stats -------------------------------------------------------------------
def test_stats_count_events_by_policy_version(client):
    assert stats(client)["by_policy_version"] == {}
    for version in (12, 3, 12, None):
        client.post("/logs/events", json={**BASE, "policy_version": version})
    client.post("/logs/events", json={**BASE, "policy_version": 3, "test": True})

    result = stats(client)
    assert result["by_policy_version"] == {"3": 1, "12": 2, "none": 1}
    assert list(result["by_policy_version"]) == ["3", "12", "none"]
    assert sum(result["by_policy_version"].values()) == result["total"] == 4
    assert stats(client, include_test="true")["by_policy_version"] == {"3": 2, "12": 2, "none": 1}


def test_stats_by_policy_version_follows_the_period_filter(client):
    from app.db import get_conn

    with get_conn() as conn:
        conn.executemany(
            """INSERT INTO event_log (created_at, grade, action, queue, policy_version)
               VALUES (?, 'public_O', 'send_as_is', 'pre_warning', ?)""",
            [("2026-06-01T00:00:00+00:00", 1), ("2026-06-02T00:00:00+00:00", 2),
             ("2026-06-02T12:00:00+00:00", None), ("2026-06-03T00:00:00+00:00", 2)],
        )
    result = stats(client, start="2026-06-02T00:00:00Z", end="2026-06-02T23:59:59Z")
    assert result["by_policy_version"] == {"2": 1, "none": 1}
    assert stats(client)["by_policy_version"] == {"1": 1, "2": 2, "none": 1}


# --- migration ---------------------------------------------------------------
LEGACY_SCHEMA = """
CREATE TABLE event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
    request_id TEXT, grade TEXT NOT NULL, action TEXT NOT NULL, reason TEXT,
    detection_confidence TEXT, detected_types TEXT NOT NULL DEFAULT '[]',
    detected_count INTEGER NOT NULL DEFAULT 0, reverted INTEGER NOT NULL DEFAULT 0,
    restored INTEGER NOT NULL DEFAULT 0, content_hash TEXT, queue TEXT NOT NULL
);
"""
# Every event_log column on main before this change (c7e8a48).
MAIN_COLUMNS = (
    "reason_requested_at TEXT", "reason_at TEXT", "reason_text TEXT", "user_id TEXT",
    "dept TEXT", "target_ai TEXT", "device_id TEXT", "items TEXT NOT NULL DEFAULT '[]'",
    "source TEXT NOT NULL DEFAULT 'text'", "is_test INTEGER NOT NULL DEFAULT 0",
)


@pytest.mark.parametrize("recent", [False, True], ids=["pre-context-db", "current-main-db"])
def test_migration_adds_nullable_integer_column_and_is_repeatable(tmp_path, monkeypatch, recent):
    from app import db

    path = tmp_path / "existing.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(LEGACY_SCHEMA)
        if recent:
            for column in MAIN_COLUMNS:
                conn.execute(f"ALTER TABLE event_log ADD COLUMN {column}")
        conn.execute("""INSERT INTO event_log (created_at, grade, action, queue)
                        VALUES ('2026-11-01T00:00:00Z', 'sensitive_S', 'send_as_is', 'pre_warning')""")
    monkeypatch.setattr(db, "DB_PATH", path)

    db.init_db()
    db.init_db()  # Repeated startup: no duplicate-column error, same result.

    with db.get_conn() as conn:
        info = {row["name"]: row for row in conn.execute("PRAGMA table_info(event_log)")}
        rows = conn.execute("SELECT policy_version FROM event_log").fetchall()
    assert info["policy_version"]["type"] == "INTEGER"
    assert info["policy_version"]["notnull"] == 0
    assert info["policy_version"]["dflt_value"] is None
    assert [row["policy_version"] for row in rows] == [None]


def test_migrated_database_serves_policy_version(client, tmp_path, monkeypatch):
    from app import db

    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(LEGACY_SCHEMA)
        for column in MAIN_COLUMNS:
            conn.execute(f"ALTER TABLE event_log ADD COLUMN {column}")
        conn.execute("""INSERT INTO event_log (created_at, grade, action, queue)
                        VALUES ('2026-11-01T00:00:00Z', 'sensitive_S', 'send_as_is', 'pre_warning')""")
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    db.init_db()

    assert client.post("/logs/events", json={**BASE, "policy_version": 5}).json()["policy_version"] == 5
    assert [e["policy_version"] for e in client.get("/logs/events").json()] == [5, None]
    assert stats(client)["by_policy_version"] == {"5": 1, "none": 1}
