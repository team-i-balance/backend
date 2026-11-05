"""Input validation tests for POST /logs/events."""


def _event(**kw):
    base = {"grade": "sensitive_S", "action": "send_transformed"}
    base.update(kw)
    return base


def test_rejects_invalid_grade(client):
    r = client.post("/logs/events", json=_event(grade="nope"))
    assert r.status_code == 422


def test_rejects_invalid_action(client):
    r = client.post("/logs/events", json=_event(action="explode"))
    assert r.status_code == 422


def test_rejects_invalid_reason(client):
    r = client.post("/logs/events", json=_event(reason="because"))
    assert r.status_code == 422


def test_rejects_negative_count(client):
    r = client.post("/logs/events", json=_event(detected_count=-1))
    assert r.status_code == 422


def test_missing_required_fields(client):
    assert client.post("/logs/events", json={"grade": "public_O"}).status_code == 422
    assert client.post("/logs/events", json={"action": "cancel"}).status_code == 422


def test_defaults_applied(client):
    # Only required fields -> optional ones take defaults.
    r = client.post("/logs/events", json=_event())
    assert r.status_code == 201
    body = r.json()
    assert body["detected_count"] == 0
    assert body["detected_types"] == []
    assert body["reverted"] is False
    assert body["restored"] is False
    assert body["reason"] is None


def test_limit_out_of_range_rejected(client):
    assert client.get("/logs/events", params={"limit": 0}).status_code == 422
    assert client.get("/logs/events", params={"limit": 5000}).status_code == 422
