"""False-positive report review contracts (issue #48). No raw values, ever."""
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, StringConstraints

ValueHash = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")]
FpStatus = Literal["open", "done"]
FpDecision = Literal["keep", "exclude"]
Why = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


class FpDecideIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: FpDecision
    why: Optional[Why] = None


class FpDecisionOut(BaseModel):
    decision: FpDecision
    why: Optional[str]
    by: str
    at: str


class FpGroup(BaseModel):
    value_hash: str
    status: FpStatus
    report_count: int
    employee_count: int
    last_reported_at: str
    preview: Optional[str]
    types: list[str]
    # Latest decision. Present on a reopened group too (the previous verdict).
    decision: Optional[FpDecisionOut]


class FpPage(BaseModel):
    items: list[FpGroup]
