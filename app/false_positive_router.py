"""Security-console endpoints for issue #48. Security scope only (401/403).

- GET  /false-positives?status=open|done
- POST /false-positives/{value_hash}/decide
- POST /events/{event_id}/reason-request
"""
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response

from app import false_positive as fp
from app.auth import require_security, security_principal
from app.false_positive_schemas import FpDecideIn, FpGroup, FpStatus, ValueHash
from app.schemas import EventOut


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def _call(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except fp.FalsePositiveError as exc:
        raise HTTPException(
            status_code=exc.status_code, detail=exc.detail,
            headers={"Cache-Control": "no-store"},
        ) from exc


_DEPS = [Depends(require_security), Depends(_no_store)]
router = APIRouter(prefix="/false-positives", tags=["false-positives"], dependencies=_DEPS)
reason_request_router = APIRouter(prefix="/events", tags=["events"], dependencies=_DEPS)


@router.get("", response_model=list[FpGroup])
def list_false_positives(
    status: FpStatus = "open",
    limit: int = Query(default=100, ge=1, le=1000),
    cursor: Optional[int] = Query(
        default=None, ge=1, le=2**63 - 1,
        description="last_event_id of the last group on the previous page",
    ),
):
    return _call(fp.list_groups, status, limit=limit, cursor=cursor)


@router.post("/{value_hash}/decide", response_model=FpGroup)
def decide_false_positive(
    value_hash: Annotated[ValueHash, Path()],
    body: FpDecideIn,
    by: Annotated[str, Depends(security_principal)],
):
    return _call(fp.decide, value_hash, decision=body.decision, why=body.why, decided_by=by)


@reason_request_router.post("/{event_id}/reason-request", response_model=EventOut)
def post_reason_request(event_id: Annotated[int, Path(ge=1, le=2**63 - 1)]):
    return _call(fp.request_reason, event_id)
