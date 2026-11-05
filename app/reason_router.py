"""Employee reason submission. Authentication/ownership is tracked in #10."""
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Response

from app.event_reason import ReasonError, submit_reason
from app.schemas import EventOut, EventReasonIn

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/{event_id}/reason", response_model=EventOut)
def post_reason(
    event_id: Annotated[int, Path(ge=1, le=2**63 - 1)],
    body: EventReasonIn,
    response: Response,
):
    response.headers["Cache-Control"] = "no-store"
    try:
        return submit_reason(event_id, body)
    except ReasonError as exc:
        raise HTTPException(
            status_code=exc.status_code, detail=exc.detail,
            headers={"Cache-Control": "no-store"},
        ) from exc
