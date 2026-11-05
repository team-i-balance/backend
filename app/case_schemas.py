"""Console case contracts. Actor and timestamp are always server-owned."""
from typing import Annotated, Literal

from pydantic import (
    AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, field_validator,
)

from app.schemas import EventOut

MAX_SQLITE_ID = 2**63 - 1


def _valid_case_id(value: str) -> str:
    if int(value[4:]) > MAX_SQLITE_ID:
        raise ValueError("case ID is out of range")
    return value


CaseId = Annotated[
    str,
    StringConstraints(pattern=r"^INC-[1-9][0-9]{0,18}$"),
    AfterValidator(_valid_case_id),
]
CaseQueue = Literal["required", "optional", "closed"]
CaseNeed = Literal["required", "optional"]
Conclusion = Literal["violation", "legit", "fp"]
Cause = Literal["fit", "care", "intent"]
Memo = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]
Rule = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class CaseCloseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conclusion: Conclusion
    cause: Cause | None = None
    memo: Memo
    rule: Rule | None = None


class CaseBulkCloseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[CaseId] = Field(min_length=1, max_length=100)
    # Bulk review is only the console's optional "all OK" action.
    conclusion: Literal["legit"]
    memo: Memo = "사유 확인 — 업무 범위 내 사용"

    @field_validator("ids")
    @classmethod
    def distinct_ids(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("ids must be unique")
        return value


class CaseCloseOut(BaseModel):
    conclusion: Conclusion
    cause: Cause | None
    memo: str
    rule: str | None
    by: str
    at: str


class CaseHistoryOut(BaseModel):
    id: int
    operation: Literal["close", "reopen"]
    conclusion: Conclusion | None
    cause: Cause | None
    memo: str | None
    rule: str | None
    by: str
    at: str


class CaseOut(BaseModel):
    id: CaseId
    need: CaseNeed
    status: Literal["open", "closed"]
    event: EventOut
    close: CaseCloseOut | None


class CaseDetail(CaseOut):
    history: list[CaseHistoryOut]


class CasePage(BaseModel):
    items: list[CaseOut]
    next_cursor: str | None


class CaseBulkResult(BaseModel):
    items: list[CaseOut]
