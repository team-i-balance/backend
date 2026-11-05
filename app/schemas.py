"""Request/response models for the logging module.

Enum values mirror app/rules.md (the temporary in-house classification rules).
"""
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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


class Source(str, Enum):
    """Which flow produced an event (issue #32)."""

    text = "text"  # /process -> /process/decide, or a client posting /logs/events
    file = "file"  # XLSX file API: BLOCKED response, protected copy download, expiry


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
    # Integration/smoke-test event. Stored and classified like any other, but
    # excluded from list/queue/stats/export unless include_test=true.
    test: bool = False
    source: Source = Source.text
    # Policy version the client applied to this input (/policy/current's
    # version), issue #49. Server-built events (/process/decide, file events)
    # set the server's active version. Null = unknown / no active policy.
    policy_version: Optional[int] = Field(default=None, ge=0)

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
    reason_text: Optional[str] = None
    reason_requested_at: Optional[str] = None
    reason_at: Optional[str] = None
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
    items: list[EventItem] = Field(default_factory=list)
    test: bool = False
    source: str = Source.text.value
    policy_version: Optional[int] = None


class EventReasonIn(BaseModel):
    """Employee explanation submitted after a sensitive raw send."""

    model_config = ConfigDict(extra="forbid")

    reason: Reason
    text: str = Field(min_length=1, max_length=500)

    @field_validator("text", mode="before")
    @classmethod
    def strip_text(cls, value):
        return value.strip() if isinstance(value, str) else value


class Stats(BaseModel):
    total: int
    acceptance_rate: float
    revert_rate: float
    evasion_suspect: int
    by_queue: dict[str, int]
    by_grade: dict[str, int]
    by_action: dict[str, int]
    # Event count per policy_version ("12": n); null versions count as "none".
    by_policy_version: dict[str, int] = Field(default_factory=dict)


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
    # A READY file work this question goes out with (issue #29). Its placeholders
    # are numbered in that file's mapping, so one placeholder never stands for two
    # values, and either restore covers both. The file is checked with the model,
    # so a linked question is too: rules_only must stay false.
    file_work_id: Optional[str] = Field(default=None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def _linked_question_uses_full_detection(self):
        if self.file_work_id is not None and self.rules_only:
            raise ValueError("file_work_id requires full detection (rules_only=false)")
        return self


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


# --- Policy bundle deploy + signature verification (흐름도 S7) ----------------
#
# The exact bundle format and signing scheme are owned by the security-team
# tool (S6) and will be finalized later. To avoid blocking on that, the deploy
# endpoint accepts the whole bundle as an opaque object and hands it to a
# pluggable verifier (see app/policy.py). When the real format arrives, only
# the verifier/adapter changes; these models and the endpoint stay the same.


class DeployIn(BaseModel):
    """A signed policy bundle to deploy. Shape is intentionally loose."""

    # The entire bundle object exactly as produced by the security-team tool.
    # Interpreted by the configured PolicyVerifier, not here.
    bundle: dict


class PolicyInfo(BaseModel):
    """Metadata about the currently active policy (no rule bodies dumped)."""

    active: bool
    version: Optional[int] = None
    org: Optional[str] = None
    key_id: Optional[str] = None
    rule_count: Optional[int] = None
    activated_at: Optional[str] = None
    expires_at: Optional[str] = None


class DeployOut(BaseModel):
    """Result of a deploy attempt."""

    accepted: bool
    reason: str          # why it was accepted or rejected
    policy: PolicyInfo   # the active policy AFTER this attempt


class PublishIn(BaseModel):
    """Console publishes a policy payload; the backend assigns version+1,
    signs it into a DSSE bundle, and stores it. version (if provided) is
    ignored — the store sets it."""

    payload: dict


class PublishOut(BaseModel):
    version: int
    keyid: str
    bundle_sha256: str


class AckStatus(str, Enum):
    applied = "applied"
    rejected = "rejected"


class AckIn(BaseModel):
    """A PC agent reports the outcome of applying a bundle version."""

    device_id: str = Field(min_length=1, max_length=128)
    version: int
    status: AckStatus
    reason: Optional[str] = Field(default=None, max_length=64)


class AckOut(BaseModel):
    ok: bool
    summary: dict  # devices / applied / rejected / reject_reasons


class ModelPublishIn(BaseModel):
    """Console publishes a model manifest {name, version, sha256, url}."""

    name: str
    version: str
    sha256: str
    url: str
