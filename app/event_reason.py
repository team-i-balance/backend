"""One-time employee explanations, stored independently of a work session."""
from datetime import datetime, timezone

from app.classify import classify
from app.crud import _row_to_dict
from app.db import get_conn
from app.schemas import Action, EventIn, EventReasonIn, Grade


class ReasonError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def submit_reason(event_id: int, body: EventReasonIn) -> dict:
    with get_conn() as conn:
        # Lock before reading: concurrent submissions must not overwrite one
        # another, and reason/code/timestamp/queue must commit together.
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM event_log WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            raise ReasonError(404, "EVENT_NOT_FOUND")
        event = _row_to_dict(row)
        if (
            event["grade"] != Grade.sensitive.value
            or event["action"] != Action.send_as_is.value
            or event["reason_requested_at"] is None
        ):
            raise ReasonError(409, "REASON_NOT_REQUESTED")
        if event["reason_at"] is not None:
            # A lost response can be retried, but an existing explanation is
            # never edited by this endpoint (including its submission time).
            if event["reason"] == body.reason.value and event["reason_text"] == body.text:
                return event
            raise ReasonError(409, "REASON_ALREADY_SUBMITTED")

        event["reason"] = body.reason.value
        queue = classify(EventIn.model_validate(event)).value
        conn.execute(
            """UPDATE event_log
               SET reason = ?, reason_text = ?, reason_at = ?, queue = ?
               WHERE id = ?""",
            (body.reason.value, body.text, datetime.now(timezone.utc).isoformat(), queue, event_id),
        )
        saved = conn.execute("SELECT * FROM event_log WHERE id = ?", (event_id,)).fetchone()
        return _row_to_dict(saved)


def reason_status(event_id: int) -> dict:
    """Employee-readable reason state, so the app can see a security re-request (#48).

    Returns only the reason workflow fields, not the event's detection metadata.
    """
    with get_conn() as conn:
        row = conn.execute(
            """SELECT id, grade, action, reason, reason_requested_at, reason_at
               FROM event_log WHERE id = ?""",
            (event_id,),
        ).fetchone()
    if row is None:
        raise ReasonError(404, "EVENT_NOT_FOUND")
    return {
        "event_id": row["id"],
        "reason_needed": (
            row["grade"] == Grade.sensitive.value
            and row["action"] == Action.send_as_is.value
            and row["reason_requested_at"] is not None
            and row["reason_at"] is None
        ),
        "reason_requested_at": row["reason_requested_at"],
        "reason": row["reason"],
        "reason_at": row["reason_at"],
    }
