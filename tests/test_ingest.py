"""Unit tests for the ingest bridge (app/ingest.py)."""
import hashlib

import pytest

from app.ingest import build_event, coverage_to_confidence, hash_text
from app.schemas import Action, Confidence, Grade, Reason


def test_coverage_mapping():
    assert coverage_to_confidence("model_and_rules") == Confidence.high
    assert coverage_to_confidence("rules_only_incomplete") == Confidence.low
    # Unknown coverage falls back to medium rather than guessing high/low.
    assert coverage_to_confidence("weird") == Confidence.medium


def test_hash_text_is_sha256_hex():
    text = "김민수 010-1234-5678"
    assert hash_text(text) == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert len(hash_text(text)) == 64


def _event(action, reason=None):
    return build_event(
        work_id="w1",
        original_text="secret original text",
        detected_types=["PHONE", "NAME", "PHONE"],  # dup on purpose
        detected_count=2,
        grade=Grade.sensitive,
        detection_confidence=Confidence.high,
        action=action,
        reason=reason,
    )


def test_build_event_core_fields():
    ev = _event(Action.send_transformed)
    assert ev.request_id == "w1"
    assert ev.grade == Grade.sensitive
    assert ev.detection_confidence == Confidence.high
    # types deduped + sorted
    assert ev.detected_types == ["NAME", "PHONE"]
    assert ev.detected_count == 2
    # content_hash is the hash of the ORIGINAL, never the text itself
    assert ev.content_hash == hash_text("secret original text")


def test_reverted_and_restored_flags():
    assert _event(Action.send_transformed).restored is True
    assert _event(Action.send_transformed).reverted is False
    assert _event(Action.revert_original).reverted is True
    assert _event(Action.revert_original).restored is False
    assert _event(Action.cancel).reverted is False
    assert _event(Action.cancel).restored is False


def test_reason_passed_through():
    ev = _event(Action.revert_original, reason=Reason.business_need)
    assert ev.reason == Reason.business_need


def test_event_never_contains_raw_text():
    ev = _event(Action.send_transformed)
    dumped = ev.model_dump_json()
    assert "secret original text" not in dumped
