"""Tests for issue #21 — context fields on EventIn/EventOut.

Covers:
  - Schema validation (Decision enum, EventItem structure, field constraints)
  - Round-trip: context fields posted → stored → returned in EventOut
  - items[] per-item decisions with value_hash / preview
  - reason_text free-text field
  - Backward compatibility: old requests without new fields still work
  - Raw PII never stored (content text not accepted)
"""
import hashlib

import pytest

from app.ingest import build_event
from app.schemas import (
    Action,
    Confidence,
    Decision,
    EventIn,
    EventItem,
    Grade,
    Reason,
)


# ---------------------------------------------------------------------------
# Schema unit tests
# ---------------------------------------------------------------------------

class TestDecisionEnum:
    def test_values(self):
        assert Decision.converted == "converted"
        assert Decision.reverted == "reverted"
        assert Decision.raw == "raw"


class TestEventItemSchema:
    def test_minimal_item(self):
        item = EventItem(type="NAME", decision=Decision.converted)
        assert item.type == "NAME"
        assert item.decision == Decision.converted
        assert item.reason is None
        assert item.value_hash is None
        assert item.preview is None

    def test_full_item(self):
        vh = "a" * 64
        item = EventItem(
            type="PHONE",
            decision=Decision.reverted,
            reason=Reason.false_positive,
            value_hash=vh,
            preview="010-****-5678",
        )
        assert item.value_hash == vh
        assert item.preview == "010-****-5678"

    def test_value_hash_must_be_64_hex(self):
        with pytest.raises(Exception):
            EventItem(type="NAME", decision=Decision.converted, value_hash="short")

    def test_preview_max_length(self):
        with pytest.raises(Exception):
            EventItem(type="NAME", decision=Decision.converted, preview="x" * 101)


class TestEventInContextFields:
    def _base(self, **kw):
        return dict(grade="sensitive_S", action="send_transformed", **kw)

    def test_defaults_are_none_and_empty(self):
        ev = EventIn(**self._base())
        assert ev.user_id is None
        assert ev.dept is None
        assert ev.target_ai is None
        assert ev.device_id is None
        assert ev.reason_text is None
        assert ev.items == []

    def test_context_fields_accepted(self):
        ev = EventIn(**self._base(
            user_id="emp-001",
            dept="보안팀",
            target_ai="ChatGPT",
            device_id="mac-abc123",
            reason_text="업무상 필요한 정보입니다",
        ))
        assert ev.user_id == "emp-001"
        assert ev.dept == "보안팀"
        assert ev.target_ai == "ChatGPT"
        assert ev.reason_text == "업무상 필요한 정보입니다"

    def test_user_id_max_length(self):
        with pytest.raises(Exception):
            EventIn(**self._base(user_id="x" * 65))

    def test_reason_text_max_length(self):
        with pytest.raises(Exception):
            EventIn(**self._base(reason_text="x" * 501))

    def test_items_accepted(self):
        ev = EventIn(**self._base(items=[
            {"type": "NAME", "decision": "converted", "preview": "김*수"},
            {"type": "PHONE", "decision": "reverted", "reason": "false_positive"},
        ]))
        assert len(ev.items) == 2
        assert ev.items[0].preview == "김*수"
        assert ev.items[1].reason == Reason.false_positive


# ---------------------------------------------------------------------------
# Integration: round-trip through API
# ---------------------------------------------------------------------------

def _event(**kw):
    base = {"grade": "sensitive_S", "action": "send_transformed"}
    base.update(kw)
    return base


class TestContextFieldsRoundTrip:
    def test_context_fields_stored_and_returned(self, client):
        payload = _event(
            user_id="emp-042",
            dept="개발팀",
            target_ai="Claude",
            device_id="win-xyz",
            reason_text="고객사 요청 내용입니다",
            items=[
                {"type": "NAME", "decision": "converted", "preview": "윤*아"},
            ],
        )
        r = client.post("/logs/events", json=payload)
        assert r.status_code == 201
        body = r.json()
        assert body["user_id"] == "emp-042"
        assert body["dept"] == "개발팀"
        assert body["target_ai"] == "Claude"
        assert body["device_id"] == "win-xyz"
        assert body["reason_text"] == "고객사 요청 내용입니다"
        assert len(body["items"]) == 1
        assert body["items"][0]["type"] == "NAME"
        assert body["items"][0]["preview"] == "윤*아"

    def test_items_with_value_hash_stored(self, client):
        vh = "b" * 64
        payload = _event(items=[
            {"type": "PHONE", "decision": "converted", "value_hash": vh},
        ])
        r = client.post("/logs/events", json=payload)
        assert r.status_code == 201
        assert r.json()["items"][0]["value_hash"] == vh

    def test_items_per_item_reason(self, client):
        """Different items may carry different reasons in the same event."""
        payload = _event(items=[
            {"type": "NAME", "decision": "converted", "reason": "false_positive"},
            {"type": "PHONE", "decision": "reverted", "reason": "business_need"},
        ])
        r = client.post("/logs/events", json=payload)
        assert r.status_code == 201
        items = r.json()["items"]
        assert items[0]["reason"] == "false_positive"
        assert items[1]["reason"] == "business_need"

    def test_backward_compat_no_context_fields(self, client):
        """Old requests without new fields must still be accepted."""
        r = client.post("/logs/events", json=_event())
        assert r.status_code == 201
        body = r.json()
        assert body["user_id"] is None
        assert body["items"] == []

    def test_context_fields_appear_in_list(self, client):
        client.post("/logs/events", json=_event(user_id="emp-007", dept="법무팀"))
        rows = client.get("/logs/events").json()
        assert rows[0]["user_id"] == "emp-007"
        assert rows[0]["dept"] == "법무팀"

    def test_no_raw_content_in_context_fields(self, client):
        """reason_text must be accepted but raw detection text must never appear."""
        r = client.post("/logs/events", json=_event(reason_text="업무상 필요"))
        body = r.json()
        # reason_text is metadata, not detection content — it is stored as-is.
        # The test verifies it round-trips and contains no 'text' or 'content' keys.
        assert "text" not in body
        assert "content" not in body
        assert body["reason_text"] == "업무상 필요"


# ---------------------------------------------------------------------------
# ingest.build_event context field forwarding
# ---------------------------------------------------------------------------

class TestBuildEventContextFields:
    def _build(self, **kw):
        return build_event(
            work_id="w1",
            original_text="테스트 원문",
            detected_types=["NAME"],
            detected_count=1,
            grade=Grade.sensitive,
            detection_confidence=Confidence.high,
            action=Action.send_transformed,
            reason=None,
            **kw,
        )

    def test_defaults_are_none(self):
        ev = self._build()
        assert ev.user_id is None
        assert ev.dept is None
        assert ev.target_ai is None
        assert ev.items == []

    def test_context_fields_forwarded(self):
        item = EventItem(type="NAME", decision=Decision.converted, preview="김*수")
        ev = self._build(
            user_id="emp-001",
            dept="보안팀",
            target_ai="GPT-4",
            device_id="mac-01",
            reason_text="업무상 필요",
            items=[item],
        )
        assert ev.user_id == "emp-001"
        assert ev.target_ai == "GPT-4"
        assert ev.reason_text == "업무상 필요"
        assert len(ev.items) == 1
        assert ev.items[0].preview == "김*수"
