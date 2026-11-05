"""Integration tests for /logs/events, /queues, and persistence."""


def _event(**kw):
    base = {
        "grade": "sensitive_S",
        "action": "send_transformed",
        "detected_types": ["email"],
        "detected_count": 1,
    }
    base.update(kw)
    return base


def test_create_event_returns_record_with_queue(client):
    r = client.post("/logs/events", json=_event(reason="false_positive"))
    assert r.status_code == 201
    body = r.json()
    assert body["queue"] == "detection_improve"
    assert body["id"] >= 1
    assert body["created_at"]  # ISO timestamp present
    assert body["detected_types"] == ["email"]


def test_health_and_root_still_work(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["detection"] in ("model", "rules_only")
    assert client.get("/").json()["service"] == "ibalance-backend"


def test_events_persist_and_list_newest_first(client):
    for i in range(3):
        client.post("/logs/events", json=_event(request_id=f"r{i}"))
    rows = client.get("/logs/events").json()
    assert len(rows) == 3
    # newest (highest id) first
    assert [row["request_id"] for row in rows] == ["r2", "r1", "r0"]


def test_filter_by_grade_and_queue(client):
    client.post("/logs/events", json=_event(grade="public_O", action="send_as_is"))
    client.post("/logs/events", json=_event(grade="confidential_C", action="send_as_is",
                                            detection_confidence="high"))
    only_public = client.get("/logs/events", params={"grade": "public_O"}).json()
    assert len(only_public) == 1
    assert only_public[0]["grade"] == "public_O"

    real = client.get("/logs/queues/real_violation").json()
    assert len(real) == 1
    assert real[0]["grade"] == "confidential_C"


def test_limit_param(client):
    for _ in range(5):
        client.post("/logs/events", json=_event())
    rows = client.get("/logs/events", params={"limit": 2}).json()
    assert len(rows) == 2


def test_no_raw_content_field_stored(client):
    client.post("/logs/events", json=_event(content_hash="a" * 64))
    row = client.get("/logs/events").json()[0]
    assert "content" not in row
    assert "text" not in row
    assert row["content_hash"] == "a" * 64


def test_empty_queue_returns_empty_list(client):
    assert client.get("/logs/queues/real_violation").json() == []
