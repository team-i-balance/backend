"""Boundary / abnormal-input tests for the logging module."""


def _event(**kw):
    base = {"grade": "sensitive_S", "action": "send_transformed"}
    base.update(kw)
    return base


# --- content_hash: must be exactly 64 hex chars -----------------------------
def test_content_hash_valid_64_hex(client):
    r = client.post("/logs/events", json=_event(content_hash="a" * 64))
    assert r.status_code == 201
    assert r.json()["content_hash"] == "a" * 64


def test_content_hash_too_short_rejected(client):
    assert client.post("/logs/events", json=_event(content_hash="a" * 63)).status_code == 422


def test_content_hash_too_long_rejected(client):
    assert client.post("/logs/events", json=_event(content_hash="a" * 65)).status_code == 422


def test_content_hash_non_hex_rejected(client):
    # 64 chars but contains 'z' -> not a hex digest.
    bad = "z" + "a" * 63
    assert client.post("/logs/events", json=_event(content_hash=bad)).status_code == 422


def test_content_hash_empty_string_rejected(client):
    assert client.post("/logs/events", json=_event(content_hash="")).status_code == 422


def test_content_hash_null_ok(client):
    r = client.post("/logs/events", json=_event(content_hash=None))
    assert r.status_code == 201
    assert r.json()["content_hash"] is None


# --- request_id length boundary (max 128) -----------------------------------
def test_request_id_at_limit_ok(client):
    r = client.post("/logs/events", json=_event(request_id="x" * 128))
    assert r.status_code == 201


def test_request_id_over_limit_rejected(client):
    assert client.post("/logs/events", json=_event(request_id="x" * 129)).status_code == 422


# --- detected_types: unicode / large / nested round-trips through JSON -------
def test_unicode_detected_types_preserved(client):
    types = ["주민등록번호", "카드번호💳", "e-mail@도메인"]
    client.post("/logs/events", json=_event(detected_types=types))
    row = client.get("/logs/events").json()[0]
    assert row["detected_types"] == types


def test_large_detected_types_list(client):
    types = [f"type_{i}" for i in range(500)]
    client.post("/logs/events", json=_event(detected_types=types, detected_count=500))
    row = client.get("/logs/events").json()[0]
    assert len(row["detected_types"]) == 500


def test_very_large_detected_count(client):
    big = 2**31
    r = client.post("/logs/events", json=_event(detected_count=big))
    assert r.status_code == 201
    assert client.get("/logs/events").json()[0]["detected_count"] == big


# --- date filter: malformed values must be rejected, not silently wrong -----
def test_malformed_start_rejected(client):
    r = client.get("/logs/events", params={"start": "not-a-date"})
    assert r.status_code == 400


def test_malformed_end_rejected(client):
    r = client.get("/logs/events", params={"end": "2026-13-99"})
    assert r.status_code == 400


def test_valid_iso_date_accepted(client):
    r = client.get("/logs/events", params={"start": "2026-01-01T00:00:00+00:00"})
    assert r.status_code == 200


# --- limit abnormal values ---------------------------------------------------
def test_limit_non_integer_rejected(client):
    assert client.get("/logs/events", params={"limit": "abc"}).status_code == 422


def test_limit_negative_rejected(client):
    assert client.get("/logs/events", params={"limit": -5}).status_code == 422


# --- unknown queue name is just empty, not an error --------------------------
def test_unknown_queue_name_returns_empty(client):
    r = client.get("/logs/queues/does_not_exist")
    assert r.status_code == 200
    assert r.json() == []
