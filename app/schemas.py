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
