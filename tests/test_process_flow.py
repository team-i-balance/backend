"""Integration + e2e tests for /process and /process/decide.

Runs local_ai on the server in rules_only mode (no ONNX model needed).
"""


def test_process_rules_only_masks_phone_and_email(client):
    text = "연락: 010-1234-5678, user@example.com"
    r = client.post("/process", json={"text": text, "rules_only": True})
    assert r.status_code == 200
    body = r.json()

    assert body["work_id"]
    # masked text must not contain the originals
    assert "010-1234-5678" not in body["masked_text"]
    assert "user@example.com" not in body["masked_text"]
    assert set(body["detected_types"]) == {"PHONE", "EMAIL"}
    assert body["grade"] == "sensitive_S"          # personal data -> sensitive
    assert body["detection_confidence"] == "low"   # rules_only -> low


def test_process_secret_is_confidential(client):
    r = client.post(
        "/process",
        json={"text": "API_KEY=TEST_KEY_1234567890", "rules_only": True},
    )
    body = r.json()
    assert body["grade"] == "confidential_C"
    assert "API_KEY" in body["detected_types"]


def test_detected_count_is_span_count_not_distinct_types(client):
    # Regression (P2-D): two phone numbers = 2 spans but 1 distinct type.
    # detected_count must be 2 (spans), not 1 (types).
    text = "010-1111-2222 그리고 010-3333-4444"
    body = client.post("/process", json={"text": text, "rules_only": True}).json()
    assert body["detected_types"] == ["PHONE"]
    assert body["detected_count"] == 2


def test_process_clean_text_is_public(client):
    r = client.post("/process", json={"text": "오늘 날씨 좋네요", "rules_only": True})
    body = r.json()
    assert body["grade"] == "public_O"
    assert body["detected_types"] == []
    assert body["detected_count"] == 0


def test_process_response_never_contains_original(client):
    secret = "user@example.com"
    r = client.post("/process", json={"text": secret, "rules_only": True})
    assert secret not in r.text  # not in masked_text nor anywhere in response


def test_full_mode_without_model_dir_rejected(client, monkeypatch):
    monkeypatch.delenv("LOCAL_PII_MODEL_DIR", raising=False)
    monkeypatch.delenv("LOCAL_SLM_MODEL_DIR", raising=False)
    r = client.post("/process", json={"text": "hi", "rules_only": False})
    assert r.status_code == 400


def test_empty_text_rejected(client):
    assert client.post("/process", json={"text": "", "rules_only": True}).status_code == 422


def test_oversized_text_rejected(client):
    # Regression (P1-C): input is bounded to prevent unbounded CPU/memory.
    big = "a" * 50_001
    assert client.post("/process", json={"text": big, "rules_only": True}).status_code == 422
    # At the limit it is accepted.
    ok = "a" * 50_000
    assert client.post("/process", json={"text": ok, "rules_only": True}).status_code == 200


# --- decide -----------------------------------------------------------------
def _process(client, text="연락 010-1234-5678"):
    return client.post("/process", json={"text": text, "rules_only": True}).json()


def test_decide_send_transformed_logs_and_keeps_session(client):
    proc = _process(client)
    r = client.post(
        "/process/decide",
        json={"work_id": proc["work_id"], "action": "send_transformed"},
    )
    assert r.status_code == 200
    body = r.json()
    # masked text is what gets sent onward
    assert body["outgoing_text"] == proc["masked_text"]
    assert "010-1234-5678" not in body["outgoing_text"]
    # session is kept for later restore of the AI reply
    assert body["restore_available"] is True
    ev = body["event"]
    # restored is False at decide time (restore happens via /process/restore)
    assert ev["restored"] is False
    assert ev["grade"] == "sensitive_S"
    assert ev["request_id"] == proc["work_id"]
    # event persisted to the log
    assert len(client.get("/logs/events").json()) == 1


def test_restore_after_send_transformed(client):
    # Send masked text, then restore originals in a (fake) AI reply.
    proc = _process(client, "연락 010-1234-5678")
    masked = proc["masked_text"]  # contains [전화번호_1]
    client.post(
        "/process/decide",
        json={"work_id": proc["work_id"], "action": "send_transformed"},
    )
    # AI reply echoes the placeholder; restore should bring back the original.
    reply = f"확인했습니다. {masked} 로 연락드릴게요."
    r = client.post(
        "/process/restore",
        json={"work_id": proc["work_id"], "text": reply},
    )
    assert r.status_code == 200
    body = r.json()
    assert "010-1234-5678" in body["text"]
    assert body["blocked"] == []

    # Work item is consumed after restore.
    again = client.post(
        "/process/restore",
        json={"work_id": proc["work_id"], "text": reply},
    )
    assert again.status_code == 404


def test_restore_without_session_404(client):
    r = client.post(
        "/process/restore",
        json={"work_id": "nope", "text": "hi"},
    )
    assert r.status_code == 404


def test_non_transformed_decide_releases_session(client):
    # cancel must not keep a session around for restore.
    proc = _process(client)
    body = client.post(
        "/process/decide",
        json={"work_id": proc["work_id"], "action": "cancel"},
    ).json()
    assert body["restore_available"] is False
    r = client.post(
        "/process/restore",
        json={"work_id": proc["work_id"], "text": "x"},
    )
    assert r.status_code == 404


def test_decide_send_as_is_returns_original(client):
    proc = _process(client)
    r = client.post(
        "/process/decide",
        json={"work_id": proc["work_id"], "action": "send_as_is"},
    )
    assert r.json()["outgoing_text"] == "연락 010-1234-5678"


def test_decide_cancel_sends_nothing(client):
    proc = _process(client)
    r = client.post(
        "/process/decide",
        json={"work_id": proc["work_id"], "action": "cancel"},
    )
    assert r.json()["outgoing_text"] is None


def test_decide_revert_with_reason(client):
    proc = _process(client)
    r = client.post(
        "/process/decide",
        json={
            "work_id": proc["work_id"],
            "action": "revert_original",
            "reason": "business_need",
        },
    )
    ev = r.json()["event"]
    assert ev["reverted"] is True
    assert ev["reason"] == "business_need"
    assert ev["queue"] == "violation_candidate"  # business_need -> this queue


def test_decide_release_session_on_insert_failure(client, monkeypatch):
    # If logging the event fails, the work item's session must still be closed
    # and the error propagated (not leaked as a dangling session). We call the
    # route function directly so the raised error is observable.
    import pytest

    import app.process_router as pr
    from app.sessions import store
    from app.schemas import DecideIn

    proc = _process(client)
    item = store.get(proc["work_id"])

    def boom(_event):
        raise RuntimeError("db down")

    monkeypatch.setattr(pr.crud, "insert_event", boom)

    with pytest.raises(RuntimeError):
        pr.decide(DecideIn(work_id=proc["work_id"], action="cancel"))
    # LocalSession marks itself closed via the private _closed flag.
    assert item.session._closed is True


def test_decide_unknown_work_id_404(client):
    r = client.post(
        "/process/decide",
        json={"work_id": "deadbeef", "action": "cancel"},
    )
    assert r.status_code == 404


def test_work_id_consumed_after_decide(client):
    proc = _process(client)
    first = client.post(
        "/process/decide",
        json={"work_id": proc["work_id"], "action": "cancel"},
    )
    assert first.status_code == 200
    # second decide on the same work_id must fail (already consumed)
    second = client.post(
        "/process/decide",
        json={"work_id": proc["work_id"], "action": "cancel"},
    )
    assert second.status_code == 404


def test_process_detection_failure_returns_422_without_text(client, monkeypatch):
    # Force local_ai to raise during process(); the endpoint must return 422
    # and must not leak the input text in the error.
    import app.process_router as pr

    class BoomSession:
        def __init__(self, detector):
            pass

        def process(self, text):
            raise RuntimeError(f"boom with {text}")

        def close(self):
            pass

    class DummyDetector:
        def set_policy(self, **kw):
            pass

    monkeypatch.setattr(pr, "_get_detector", lambda rules_only: DummyDetector())
    import local_ai.pipeline as pipeline

    monkeypatch.setattr(pipeline, "LocalSession", BoomSession)

    secret = "leak-me@example.com"
    r = client.post("/process", json={"text": secret, "rules_only": True})
    assert r.status_code == 422
    assert secret not in r.text


def test_full_mode_with_model_dir_builds_detector(client, monkeypatch, tmp_path):
    # Covers the model-dir branch of _build_detector. We stub Detector so no
    # real ONNX model is needed, and stub LocalSession to return a fixed result.
    import app.process_router as pr

    monkeypatch.setenv("LOCAL_PII_MODEL_DIR", str(tmp_path))

    built = {"model_dir": None}

    class FakeDetector:
        def __init__(self, model_dir=None, **kw):
            built["model_dir"] = model_dir

        def set_policy(self, **kw):
            pass

    import local_ai.detector as det

    monkeypatch.setattr(det, "Detector", FakeDetector)

    class FakeResult:
        text = "[이름_1]"
        detection_types = ("NAME",)
        remaining = ()
        coverage = "model_and_rules"
        detection_count = 1

    class FakeSession:
        def __init__(self, detector):
            pass

        def process(self, text):
            return FakeResult()

        def close(self):
            pass

    import local_ai.pipeline as pipeline

    monkeypatch.setattr(pipeline, "LocalSession", FakeSession)

    r = client.post("/process", json={"text": "김민수", "rules_only": False})
    assert r.status_code == 200
    body = r.json()
    assert built["model_dir"] == str(tmp_path)  # model dir branch taken
    assert body["detection_confidence"] == "high"  # model_and_rules -> high
    assert body["grade"] == "sensitive_S"

    # Issue #20: a certain detection sent as-is is the console's required review.
    d = client.post("/process/decide", json={"work_id": body["work_id"], "action": "send_as_is"}).json()
    assert d["event"]["queue"] == "real_violation"


def test_detector_is_reused_across_requests(client):
    # Regression (P1-A): the detector must be built once per mode and reused,
    # not rebuilt (tokenizer + ONNX session) on every /process call.
    import app.process_router as pr
    import local_ai.detector as det

    builds = {"n": 0}
    real = det.Detector

    class CountingDetector(real):
        def __init__(self, *a, **kw):
            builds["n"] += 1
            super().__init__(*a, **kw)

    pr._reset_detectors()
    det.Detector = CountingDetector
    try:
        for _ in range(3):
            assert client.post(
                "/process", json={"text": "010-1234-5678", "rules_only": True}
            ).status_code == 200
    finally:
        det.Detector = real
        pr._reset_detectors()

    assert builds["n"] == 1  # built once, reused for the other two requests


def test_e2e_process_decide_stats(client):
    # Two sensitive + one confidential, varied actions, then check stats.
    p1 = _process(client, "전화 010-1111-2222")
    client.post("/process/decide", json={"work_id": p1["work_id"], "action": "send_transformed"})
    p2 = _process(client, "메일 a@b.com")
    client.post("/process/decide", json={"work_id": p2["work_id"], "action": "cancel"})
    p3 = _process(client, "API_KEY=TEST_KEY_1234567890")
    client.post("/process/decide", json={"work_id": p3["work_id"], "action": "revert_original", "reason": "business_need"})

    stats = client.get("/logs/stats").json()
    assert stats["total"] == 3
    assert stats["by_grade"]["sensitive_S"] == 2
    assert stats["by_grade"]["confidential_C"] == 1
    assert stats["evasion_suspect"] == 1  # one business_need

    # Export round-trips and contains no raw text.
    exp = client.post("/logs/export").json()
    assert exp["exported"] == 3


def test_live_draft_ranges_without_work_or_logging(client, monkeypatch):
    from app.process_router import store
    def unexpected(*args, **kwargs):
        raise AssertionError("a preview must not create work")
    monkeypatch.setattr(store, "add", unexpected)
    text = "🧪 연락 010-2345-6789, 또 010-2345-6789"
    response = client.post("/process/preview", json={"text": text, "rules_only": True})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    starts = [text.index("010"), text.rindex("010")]
    assert response.json() == {"spans": [{"start": i, "end": i + 13, "type": "PHONE"} for i in starts]}
    assert "010-2345" not in response.text
