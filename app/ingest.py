"""Bridge: turn a processed work item + user decision into a log EventIn.

Keeps the logging module's rule intact: no raw/masked body text is placed in
the event, only metadata (types, count, grade, confidence) plus a SHA-256
hash of the original for correlation. See rules.md section 6.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from app.schemas import (
    Action,
    Confidence,
    EventIn,
    EventItem,
    Grade,
    Reason,
)

# coverage (from local_ai) -> detection_confidence
#   model_and_rules        -> high (checked thoroughly: AI model + rules)
#   rules_only_incomplete  -> low  (checked loosely: rules only)
_COVERAGE_TO_CONFIDENCE = {
    "model_and_rules": Confidence.high,
    "rules_only_incomplete": Confidence.low,
}


def coverage_to_confidence(coverage: str) -> Confidence:
    return _COVERAGE_TO_CONFIDENCE.get(coverage, Confidence.medium)


def active_policy_version() -> Optional[int]:
    """Version of the policy the server has active now, or None (read-only, #49)."""
    from app.policy import store as policy_store

    active = policy_store.current()
    return active.version if active is not None else None


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_event(
    *,
    work_id: str,
    original_text: str,
    detected_types,
    detected_count: int,
    grade: Grade,
    detection_confidence: Confidence,
    action: Action,
    reason: Optional[Reason],
    # Context fields (issue #21) — all optional for backward compatibility
    user_id: Optional[str] = None,
    dept: Optional[str] = None,
    target_ai: Optional[str] = None,
    device_id: Optional[str] = None,
    reason_text: Optional[str] = None,
    items: Optional[list[EventItem]] = None,
    policy_version: Optional[int] = None,
) -> EventIn:
    """Construct the EventIn for a user's decision on a processed item."""
    # reverted: user rolled back to the original (revert_original).
    # restored: whether the AI reply's originals were restored. At decide time
    #   this has not happened yet, so it is always False here; the actual
    #   restore step (/process/restore) is a separate action.
    reverted = action == Action.revert_original
    return EventIn(
        request_id=work_id,
        grade=grade,
        action=action,
        reason=reason,
        detection_confidence=detection_confidence,
        detected_types=sorted(set(detected_types)),
        detected_count=detected_count,
        reverted=reverted,
        restored=False,
        content_hash=hash_text(original_text),
        user_id=user_id,
        dept=dept,
        target_ai=target_ai,
        device_id=device_id,
        reason_text=reason_text,
        items=items or [],
        policy_version=policy_version,
    )
