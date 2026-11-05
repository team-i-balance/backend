"""Test-event flag (issue #27): is_test column, migration, and filtering.

Integration-check events are stored and classified normally but excluded from
list/queue/stats/export unless include_test=true. Nothing is ever deleted.
"""
import importlib
import sqlite3
import sys
from pathlib import Path

# event_log as it existed before the is_test column was added.
_OLD_SCHEMA = """
CREATE TABLE event_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL,
    request_id      TEXT,
    grade           TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    reason          TEXT,
    detection_confidence TEXT,
    detected_types  TEXT    NOT NULL DEFAULT '[]',
    detected_count  INTEGER NOT NULL DEFAULT 0,
    reverted        INTEGER NOT NULL DEFAULT 0,
    restored        INTEGER NOT NULL DEFAULT 0,
    content_hash    TEXT,
    queue           TEXT    NOT NULL
);
"""


def _event(**kw):
    base = {"grade": "sensitive_S", "action": "send_transformed"}
    base.update(kw)
    return base


def _fresh_db_module(db_path: Path, monkeypatch):
    monkeypatch.setenv("LOG_DB_PATH", str(db_path))
    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            del sys.modules[name]
    import app.db

    return importlib.reload(app.db)


# --- migration ---------------------------------------------------------------


def test_migration_adds_column_and_flags_console_tests(tmp_path, monkeypatch):
    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(_OLD_SCHEMA)
    rows = [f"console-test-{i}" for i in range(1, 8)] + ["work-abc", None,
                                                          "my-console-test-1"]
    for rid in rows:
        conn.execute(
            "INSERT INTO event_log (created_at, request_id, grade, action, queue)"
            " VALUES ('2026-10-01T00:00:00+00:00', ?, 'sensitive_S',"
            " 'send_transformed', 'pre_warning')",
            (rid,),
        )
    conn.commit()
    conn.close()

    db = _fresh_db_module(db_path, monkeypatch)
    db.init_db()
    db.init_db()  # second run must be a no-op

    conn = sqlite3.connect(db_path)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(event_log)")]
    assert cols.count("is_test") == 1
    flagged = {
        r[0] for r in conn.execute(
            "SELECT request_id FROM event_log WHERE is_test = 1")
    }
    total = conn.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]
    conn.close()

    assert flagged == {f"console-test-{i}" for i in range(1, 8)}
    assert total == len(rows)  # nothing deleted


def test_migration_on_fresh_db_is_idempotent(tmp_path, monkeypatch):
    db = _fresh_db_module(tmp_path / "new.db", monkeypatch)
    db.init_db()
    db.init_db()
    conn = sqlite3.connect(tmp_path / "new.db")
    cols = [r[1] for r in conn.execute("PRAGMA table_info(event_log)")]
    conn.close()
    assert cols.count("is_test") == 1


def test_migrated_db_serves_api(tmp_path, monkeypatch):
    """An old DB with console-test rows is filtered right after startup."""
    db_path = tmp_path / "events.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(_OLD_SCHEMA)
    for rid in ("console-test-1", "real-1"):
        conn.execute(
            "INSERT INTO event_log (created_at, request_id, grade, action, queue)"
            " VALUES ('2026-10-01T00:00:00+00:00', ?, 'sensitive_S',"
            " 'send_transformed', 'pre_warning')",
            (rid,),
        )
    conn.commit()
    conn.close()

    monkeypatch.setenv("LOG_DB_PATH", str(db_path))
    monkeypatch.setenv("LOG_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("LOG_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.setenv("POLICY_KEYS_DIR", str(tmp_path / "policy_keys"))
    for name in list(sys.modules):
        if name == "main" or name == "app" or name.startswith("app."):
            del sys.modules[name]
    from fastapi.testclient import TestClient
    import main

    importlib.reload(main)
    with TestClient(main.app) as c:
        ids = [e["request_id"] for e in c.get("/logs/events").json()]
        assert ids == ["real-1"]
        all_events = c.get("/logs/events",
                           params={"include_test": "true"}).json()
        assert {e["request_id"]: e["test"] for e in all_events} == {
            "console-test-1": True, "real-1": False}
        assert c.get("/logs/stats").json()["total"] == 1


# --- ingest + filtering -----------------------------------------------------


def test_post_test_event_is_stored_and_classified(client):
    r = client.post("/logs/events", json=_event(test=True))
    assert r.status_code == 201
    body = r.json()
    assert body["test"] is True
    # Classified exactly like a normal event with the same fields.
    normal = client.post("/logs/events", json=_event()).json()
    assert normal["test"] is False
    assert body["queue"] == normal["queue"]


def test_list_excludes_test_by_default(client):
    client.post("/logs/events", json=_event(request_id="real"))
    client.post("/logs/events", json=_event(request_id="t", test=True))

    ids = [e["request_id"] for e in client.get("/logs/events").json()]
    assert ids == ["real"]

    ids = [e["request_id"] for e in client.get(
        "/logs/events", params={"include_test": "true"}).json()]
    assert sorted(ids) == ["real", "t"]


def test_queue_excludes_test_by_default(client):
    real = client.post("/logs/events", json=_event(request_id="real")).json()
    client.post("/logs/events", json=_event(request_id="t", test=True))
    q = real["queue"]

    ids = [e["request_id"] for e in client.get(f"/logs/queues/{q}").json()]
    assert ids == ["real"]
    ids = [e["request_id"] for e in client.get(
        f"/logs/queues/{q}", params={"include_test": "true"}).json()]
    assert sorted(ids) == ["real", "t"]


def test_stats_exclude_test_events(client):
    # Real: 1 accepted, 1 reverted -> total 2, acceptance 0.5, revert 0.5.
    client.post("/logs/events", json=_event(action="send_as_is",
                                            grade="public_O"))
    client.post("/logs/events", json=_event(action="revert_original",
                                            reverted=True))
    # Test: 2 business_need cancels that would skew every number.
    for _ in range(2):
        client.post("/logs/events", json=_event(
            action="cancel", reason="business_need", grade="confidential_C",
            test=True))

    s = client.get("/logs/stats").json()
    assert s["total"] == 2
    assert s["acceptance_rate"] == 0.5
    assert s["revert_rate"] == 0.5
    assert s["evasion_suspect"] == 0
    assert "confidential_C" not in s["by_grade"]
    assert sum(s["by_queue"].values()) == 2

    s = client.get("/logs/stats", params={"include_test": "true"}).json()
    assert s["total"] == 4
    assert s["acceptance_rate"] == 0.25
    assert s["evasion_suspect"] == 2
    assert s["by_grade"]["confidential_C"] == 2


def test_stats_only_test_events_looks_empty(client):
    client.post("/logs/events", json=_event(test=True))
    s = client.get("/logs/stats").json()
    assert s["total"] == 0
    assert s["by_queue"] == {}


def test_export_excludes_test_by_default(client):
    from app.crypto import decrypt_file

    client.post("/logs/events", json=_event(request_id="real"))
    client.post("/logs/events", json=_event(request_id="t", test=True))

    body = client.post("/logs/export").json()
    assert body["exported"] == 1
    recs = decrypt_file(Path(body["file"]))
    assert [r["request_id"] for r in recs] == ["real"]
    assert recs[0]["test"] is False

    body = client.post("/logs/export", params={"include_test": "true"}).json()
    assert body["exported"] == 2
    recs = decrypt_file(Path(body["file"]))
    assert {r["request_id"]: r["test"] for r in recs} == {
        "real": False, "t": True}


def test_test_flag_never_deletes(client):
    client.post("/logs/events", json=_event(test=True))
    from app.db import get_conn

    with get_conn() as conn:
        n = conn.execute("SELECT COUNT(*) AS c FROM event_log").fetchone()["c"]
    assert n == 1


def test_test_events_never_become_cases(client):
    real = client.post("/logs/events", json={"grade": "sensitive_S", "action": "send_as_is",
                                              "detected_types": ["NAME"], "detected_count": 1}).json()
    client.post("/logs/events", json={"grade": "sensitive_S", "action": "send_as_is", "test": True,
                                      "detected_types": ["NAME"], "detected_count": 1})
    items = client.get("/cases", params={"queue": "required"}).json()["items"]
    assert [c["event"]["id"] for c in items] == [real["id"]]
    assert items[0]["event"]["test"] is False
    assert "is_test" not in items[0]["event"]
