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


class Decision(str, Enum):
    """Per-item decision: how the value was handled."""
    converted = "converted"    # sent as pseudonymized
    reverted = "reverted"      # user reverted to original
    raw = "raw"                # sent as-is (no masking)


class EventItem(BaseModel):
    """Per-detected-item detail for security team review.

    Stores enough context to cluster repeated false-positive reports on the
    same value (via value_hash) without ever storing the raw value itself.
    """

    type: str = Field(description="Detection type, e.g. 'NAME', 'PHONE'")
    decision: Decision
    reason: Optional[Reason] = Field(
        default=None,
        description="Per-item reason when it differs from the event-level reason",
    )
    # HMAC-SHA256(org_key, value): lets the security team cluster repeated
    # false-positive reports for the same underlying value without storing it.
    value_hash: Optional[str] = Field(
        default=None,
        pattern=r"^[0-9a-fA-F]{64}$",
        description="HMAC-SHA256 hex of the detected value; used for FP clustering only",
    )
    # Masked preview shown in the console card, e.g. "윤*아", "******-*******".
    preview: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Masked preview of the value for display (no raw content)",
    )


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

    # --- Context fields (issue #21) ------------------------------------------
    # Identifiers for the submitting employee and channel. All optional to
    # preserve backward compatibility; never store raw personal text here.
    user_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Employee ID or pseudonymous user identifier",
    )
    dept: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Department or team name",
    )
    target_ai: Optional[str] = Field(
        default=None,
        max_length=128,
        description="AI system the message was destined for",
    )
    device_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Device or client identifier",
    )
    reason_text: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Free-text reason written by the employee (no raw PII)",
    )
    # Per-item decisions; allows different reason per detected value in one event.
    items: list[EventItem] = Field(
        default_factory=list,
        description="Per-detected-item details for console display and FP clustering",
    )


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
    # Context fields (issue #21)
    user_id: Optional[str] = None
    dept: Optional[str] = None
    target_ai: Optional[str] = None
    device_id: Optional[str] = None
    reason_text: Optional[str] = None
    items: list[EventItem] = Field(default_factory=list)


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


# --- Process / decide flow (local_ai on the in-house server) -----------------


class ProcessIn(BaseModel):
    """Raw text the client sends for on-server detection + pseudonymization.

    The server (in-house) runs local_ai on this text. The raw text is used only
    in memory; it is never written to disk, logged, or stored in an event.
    """

    # Bounded so one request cannot consume unbounded CPU (detection runs twice)
    # or memory (original + masked text are retained until decide/restore/TTL).
    text: str = Field(min_length=1, max_length=50_000)
    # rules_only = phone/email rules only (name/address NOT checked).
    # Full model mode requires a local model dir configured on the server.
    rules_only: bool = False


class ProcessOut(BaseModel):
    """Result of /process. Contains the masked text, never the original."""

    work_id: str
    masked_text: str
    detected_types: list[str]
    detected_count: int
    grade: str
    # high  = checked thoroughly (AI model + rules)
    # low   = checked loosely (rules only; names/addresses not inspected)
    detection_confidence: str
    # Re-scan findings on the masked text (possible leftover / false positives).
    remaining_count: int


class DecideIn(BaseModel):
    """The user's choice for a previously processed work item."""

    work_id: str
    action: Action
    reason: Optional[Reason] = None


class DecideOut(BaseModel):
    """Outcome of a decision: the logged event plus any text to actually send."""

    event: EventOut
    # Text the client should send onward, depending on the action:
    #   send_transformed -> masked text; send_as_is/revert_original -> original.
    # cancel -> null (nothing is sent).
    outgoing_text: Optional[str]
    # True only for send_transformed: the work item (pseudonym mapping) is kept
    # so the client can later call /process/restore on the AI reply. For every
    # other action the work item is already released.
    restore_available: bool = False


class RestoreIn(BaseModel):
    """AI reply text whose current-session pseudonyms should be restored."""

    work_id: str
    text: str = Field(max_length=200_000)


class RestoreOut(BaseModel):
    """Restored reply. Secret placeholders (keys/tokens/passwords) stay masked."""

    text: str
    unknown: list[str]   # placeholders not from this session (left as-is)
    blocked: list[str]   # secret placeholders intentionally not restored
