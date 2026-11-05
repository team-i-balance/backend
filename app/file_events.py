"""Security-log events for file works (issue #32).

Like the text flow's /process/decide, an event holds metadata only: grade, types,
count, and a SHA-256 of the uploaded bytes. Never values, positions or file names.

  BLOCKED response          -> cancel           (nothing can be sent)
  protected copy download   -> send_transformed (the copy left for the AI)
  READY expired, never downloaded -> cancel
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Optional

from app import crud
from app.ingest import active_policy_version, coverage_to_confidence
from app.schemas import Action, Confidence, EventIn, Grade, Source


@dataclass(frozen=True)
class FileEvent:
    """What the security log records about one file work."""

    work_id: str
    grade: Grade
    detected_types: tuple[str, ...]
    detected_count: int
    detection_confidence: Confidence
    content_hash: str  # SHA-256 of the uploaded file bytes
    # Server's active policy version when the file was checked (issue #49).
    policy_version: Optional[int] = None

    @classmethod
    def of(cls, *, work_id: str, grade: Grade, findings, data: bytes, model_enabled: bool):
        return cls(
            work_id=work_id,
            grade=grade,
            detected_types=tuple(findings.types),
            detected_count=findings.count,
            detection_confidence=coverage_to_confidence(
                "model_and_rules" if model_enabled else "rules_only_incomplete"
            ),
            content_hash=hashlib.sha256(data).hexdigest(),
            policy_version=active_policy_version(),
        )


def record(event: FileEvent, action: Action) -> dict:
    """Insert one event; errors propagate so callers can fail closed."""
    return crud.insert_event(EventIn(
        request_id=event.work_id,
        grade=event.grade,
        action=action,
        detection_confidence=event.detection_confidence,
        detected_types=list(event.detected_types),
        detected_count=event.detected_count,
        content_hash=event.content_hash,
        source=Source.file,
        policy_version=event.policy_version,
    ))
