"""Request/response models for the logging module.

Enum values mirror app/rules.md (the temporary in-house classification rules).
"""
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Grade(str, Enum):
    public = "public_O"
    sensitive = "sensitive_S"
    confidential = "confidential_C"


class Action(str, Enum):
    send_as_is = "send_as_is"
    send_transformed = "send_transformed"
    cancel = "cancel"
    revert_original = "revert_original"


class Reason(str, Enum):
    false_positive = "false_positive"
    business_need = "business_need"


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class Queue(str, Enum):
    detection_improve = "detection_improve"
    violation_candidate = "violation_candidate"
    real_violation = "real_violation"
    pre_warning = "pre_warning"


class EventIn(BaseModel):
    """Incoming runtime event. Body text is NOT accepted — only metadata.

    If a content_hash is not provided, the server leaves it null (we never
    store raw content; see rules.md section 6).
    """

    request_id: Optional[str] = Field(default=None, max_length=128)
    grade: Grade
    action: Action
    reason: Optional[Reason] = None
    detection_confidence: Optional[Confidence] = None
    detected_types: list[str] = Field(default_factory=list)
    detected_count: int = Field(default=0, ge=0)
    reverted: bool = False
    restored: bool = False
    # SHA-256 hex digest: exactly 64 hex chars. We never store raw content,
    # only this optional fingerprint (see rules.md section 6).
    content_hash: Optional[str] = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")


class EventOut(BaseModel):
    id: int
    created_at: str
    request_id: Optional[str]
    grade: str
    action: str
    reason: Optional[str]
    detection_confidence: Optional[str]
    detected_types: list[str]
    detected_count: int
    reverted: bool
    restored: bool
    content_hash: Optional[str]
    queue: str


class Stats(BaseModel):
    total: int
    acceptance_rate: float
    revert_rate: float
    evasion_suspect: int
    by_queue: dict[str, int]
    by_grade: dict[str, int]


class ExportResult(BaseModel):
    exported: int
    file: str
    public_key_fingerprint: str
