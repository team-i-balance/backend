"""Employee reason submission and status. Authentication/ownership is tracked in #10."""
from typing import Annotated, Optional

from fastapi import APIRouter, HTTPException, Path, Response
from pydantic import BaseModel

from app.event_reason import ReasonError, reason_status, submit_reason
from app.schemas import EventOut, EventReasonIn

router = APIRouter(prefix="/events", tags=["events"])
EventId = Annotated[int, Path(ge=1, le=2**63 - 1)]


class EventReasonStatus(BaseModel):
    """What the employee app polls at startup to see a re-request (#48)."""

    event_id: int
    reason_needed: bool
    reason_requested_at: Optional[str]
    reason: Optional[str]
    reason_at: Optional[str]


def _reason_call(response: Response, operation, *args):
    response.headers["Cache-Control"] = "no-store"
    try:
        return operation(*args)
    except ReasonError as exc:
        raise HTTPException(
            status_code=exc.status_code, detail=exc.detail,
            headers={"Cache-Control": "no-store"},
        ) from exc


@router.get("/{event_id}/reason", response_model=EventReasonStatus)
def get_reason(event_id: EventId, response: Response):
    return _reason_call(response, reason_status, event_id)


@router.post("/{event_id}/reason", response_model=EventOut)
def post_reason(event_id: EventId, body: EventReasonIn, response: Response):
    return _reason_call(response, submit_reason, event_id, body)
