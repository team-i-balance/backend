"""Persistent review overlay on immutable event metadata.

Only the latest history entry determines state. State transitions and history
therefore cannot diverge, including when a bulk operation fails midway.
"""
import json
import re
from datetime import datetime, timezone

from app.case_schemas import CaseCloseIn, MAX_SQLITE_ID
from app.db import get_conn

# Review cases are raw sends (the original text reached the external AI).
# - sensitive_S: sent without a reason or with business_need (#60). A
#   false_positive chosen at send time is a detection report, not a case
#   (/false-positives). An event that was waiting for a reason
#   (reason_requested_at set) stays a case whatever reason arrives later.
# - confidential_C: always a case, false_positive included (#62).
# Separate from the legacy log queues (app/classify.py).
_ELIGIBLE = """
    e.is_test = 0 AND e.action IN ('send_as_is', 'revert_original') AND (
        e.grade = 'confidential_C'
        OR (e.grade = 'sensitive_S' AND (
            e.reason IS NULL OR e.reason = 'business_need'
            OR e.reason_requested_at IS NOT NULL
        ))
    )
"""
# optional = an S raw send whose employee chose business_need when sending.
# A reason given only after the request (sent without one) stays required,
# and every confidential raw send is required.
_NEED = """
    CASE WHEN e.grade = 'sensitive_S' AND e.reason = 'business_need'
              AND e.reason_requested_at IS NULL
         THEN 'optional' ELSE 'required' END
"""
_SELECT = f"""
    SELECT e.*, {_NEED} AS review_need,
        h.id AS review_id, h.operation AS review_operation,
        h.created_at AS review_at, h.reviewer AS review_by,
        h.conclusion AS review_conclusion, h.cause AS review_cause,
        h.memo AS review_memo, h.rule AS review_rule
    FROM event_log e
    LEFT JOIN case_history h ON h.id = (
        SELECT id FROM case_history WHERE event_id = e.id ORDER BY id DESC LIMIT 1
    )
    WHERE {_ELIGIBLE}
"""


class CaseError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _case(row) -> dict:
    event = {k: row[k] for k in row.keys() if not k.startswith("review_")}
    event["detected_types"] = json.loads(event["detected_types"])
    event["items"] = json.loads(event.get("items") or "[]")
    event["reverted"] = bool(event["reverted"])
    event["restored"] = bool(event["restored"])
    # Same field name as /logs/events (EventOut.test); test events never become cases.
    event["test"] = bool(event.pop("is_test", 0))
    event.pop("change_seq", None)  # internal polling marker (app/changes.py)
    closed = row["review_operation"] == "close"
    return {
        "id": f"INC-{event['id']}",
        "need": row["review_need"],
        "status": "closed" if closed else "open",
        "event": event,
        "close": {
            field: row[f"review_{field}"]
            for field in ("conclusion", "cause", "memo", "rule", "by", "at")
        } if closed else None,
    }


def _get(conn, case_id: str) -> dict:
    row = conn.execute(_SELECT + " AND e.id = ?", (int(case_id[4:]),)).fetchone()
    if row is None:
        raise CaseError(404, "CASE_NOT_FOUND")
    return _case(row)


def _detail(conn, case_id: str) -> dict:
    result = _get(conn, case_id)
    result["history"] = [dict(row) for row in conn.execute(
        """SELECT id, operation, conclusion, cause, memo, rule,
                  reviewer AS 'by', created_at AS at
           FROM case_history WHERE event_id = ? ORDER BY id""",
        (int(case_id[4:]),),
    )]
    return result


def get_case(case_id: str) -> dict:
    with get_conn() as conn:
        # Keep current state and history in the same read snapshot.
        conn.execute("BEGIN")
        return _detail(conn, case_id)


def list_cases(*, queue: str, cursor: str | None, limit: int) -> dict:
    boundary = None
    if cursor is not None:
        match = re.fullmatch(r"(required|optional|closed):([1-9][0-9]{0,18})", cursor)
        if not match or match[1] != queue or int(match[2]) > MAX_SQLITE_ID:
            raise CaseError(400, "INVALID_CURSOR")
        boundary = int(match[2])
    params: list = []
    if queue == "closed":
        where = " AND h.operation = 'close'"
        order = "h.id"
    else:
        where = f" AND (h.operation IS NULL OR h.operation = 'reopen') AND {_NEED} = ?"
        params.append(queue)
        order = "e.id"
    if boundary is not None:
        where += f" AND {order} < ?"
        params.append(boundary)
    params.append(limit + 1)
    with get_conn() as conn:
        rows = conn.execute(_SELECT + where + f" ORDER BY {order} DESC LIMIT ?", params).fetchall()
    page = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = page[-1]["review_id" if queue == "closed" else "id"]
        next_cursor = f"{queue}:{last}"
    return {"items": [_case(row) for row in page], "next_cursor": next_cursor}


def _append(conn, case_id: str, reviewer: str, decision: CaseCloseIn | None) -> None:
    conn.execute(
        """INSERT INTO case_history
           (event_id, operation, created_at, reviewer, conclusion, cause, memo, rule)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            int(case_id[4:]), "close" if decision else "reopen",
            datetime.now(timezone.utc).isoformat(), reviewer,
            decision.conclusion if decision else None,
            decision.cause if decision else None,
            decision.memo if decision else None,
            decision.rule if decision else None,
        ),
    )


def transition(case_id: str, *, reviewer: str, decision: CaseCloseIn | None) -> dict:
    with get_conn() as conn:
        # Acquire the write lock BEFORE reading state so concurrent reviews
        # cannot both pass the check and overwrite each other's decision.
        conn.execute("BEGIN IMMEDIATE")
        case = _get(conn, case_id)
        expected = "open" if decision else "closed"
        if case["status"] != expected:
            raise CaseError(409, "CASE_ALREADY_CLOSED" if decision else "CASE_ALREADY_OPEN")
        _append(conn, case_id, reviewer, decision)
        return _detail(conn, case_id)


def close_bulk(ids: list[str], *, reviewer: str, decision: CaseCloseIn) -> dict:
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        for case_id in ids:
            case = _get(conn, case_id)
            if case["need"] != "optional":
                raise CaseError(409, "BULK_REQUIRES_OPTIONAL_CASES")
            if case["status"] != "open":
                raise CaseError(409, "CASE_ALREADY_CLOSED")
        for case_id in ids:
            _append(conn, case_id, reviewer, decision)
        return {"items": [_get(conn, case_id) for case_id in ids]}
