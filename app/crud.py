"""Data access for event_log: insert, query, aggregate."""
import json
from datetime import datetime, timezone
from typing import Optional

from app.classify import classify
from app.db import get_conn
from app.log_time import utc_microseconds
from app.schemas import Action, EventIn, Grade, Stats

# Actions that count as "accepted" (sent to the AI in some form).
_ACCEPTED_ACTIONS = ("send_as_is", "send_transformed")


# Raw sends that let the original text reach the external AI (issues #60, #62).
# A sensitive (S) or confidential (C) raw send without a reason waits for the
# employee's explanation; the same set is a security review case (app/case_crud.py).
RAW_SEND_ACTIONS = (Action.send_as_is.value, Action.revert_original.value)
REASON_FOLLOWUP_GRADES = (Grade.sensitive.value, Grade.confidential.value)


def is_reason_followup_target(grade, action) -> bool:
    """Whether an unexplained raw send of this grade/action waits for a reason."""
    grade = getattr(grade, "value", grade)
    action = getattr(action, "value", action)
    return grade in REASON_FOLLOWUP_GRADES and action in RAW_SEND_ACTIONS


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["detected_types"] = json.loads(d.get("detected_types") or "[]")
    d["reverted"] = bool(d["reverted"])
    d["restored"] = bool(d["restored"])
    d["items"] = json.loads(d.get("items") or "[]")
    d["test"] = bool(d.pop("is_test", 0))
    d.pop("change_seq", None)  # internal polling marker, never returned or exported
    return d


def insert_event(event: EventIn) -> dict:
    queue = classify(event)
    created_at = _now_utc_iso()

    items_json = json.dumps(
        [item.model_dump(exclude_none=True) for item in event.items],
        ensure_ascii=False,
    )

    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO event_log (
                created_at, request_id, grade, action, reason,
                detection_confidence, detected_types, detected_count,
                reverted, restored, content_hash, queue,
                user_id, dept, target_ai, device_id, reason_text, items, is_test, source,
                policy_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                event.request_id,
                event.grade.value,
                event.action.value,
                event.reason.value if event.reason else None,
                event.detection_confidence.value
                if event.detection_confidence
                else None,
                json.dumps(event.detected_types, ensure_ascii=False),
                event.detected_count,
                int(event.reverted),
                int(event.restored),
                event.content_hash,
                queue.value,
                event.user_id,
                event.dept,
                event.target_ai,
                event.device_id,
                event.reason_text,
                items_json,
                int(event.test),
                event.source.value,
                event.policy_version,
            ),
        )
        new_id = cur.lastrowid
        needs_reason = (
            is_reason_followup_target(event.grade, event.action)
            and event.reason is None
        )
        conn.execute(
            "UPDATE event_log SET reason_requested_at = ?, reason_at = ? WHERE id = ?",
            (created_at if needs_reason else None,
             created_at if event.reason is not None else None, new_id),
        )
        row = conn.execute(
            "SELECT * FROM event_log WHERE id = ?", (new_id,)
        ).fetchone()

    return _row_to_dict(row)


def _event_filter(*, grade=None, queue=None, start=None, end=None, cursor=None, include_test=False):
    """One set of date/filter semantics for lists and aggregate queries."""
    clauses = []
    params: list = []
    if not include_test:
        clauses.append("is_test = 0")
    if grade:
        clauses.append("grade = ?")
        params.append(grade)
    if queue:
        clauses.append("queue = ?")
        params.append(queue)
    if start is not None:
        clauses.append("utc_microseconds(created_at) >= ?")
        params.append(utc_microseconds(start))
    if end is not None:
        clauses.append("utc_microseconds(created_at) <= ?")
        params.append(utc_microseconds(end))
    if cursor is not None:
        clauses.append("id < ?")
        params.append(cursor)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def list_events(
    *,
    grade: Optional[str] = None,
    queue: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[int] = None,
    include_test: bool = False,
) -> list[dict]:
    where, params = _event_filter(
        grade=grade, queue=queue, start=start, end=end, cursor=cursor, include_test=include_test,
    )
    sql = f"SELECT * FROM event_log {where} ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_stats(
    *, start: Optional[str] = None, end: Optional[str] = None, include_test: bool = False,
) -> Stats:
    where, params = _event_filter(start=start, end=end, include_test=include_test)
    # One aggregate query sees one database snapshot and is not bounded by the
    # event-list page size. With the current enums it returns at most 48 groups.
    with get_conn() as conn:
        rows = conn.execute(f"""
            SELECT action, grade, queue, policy_version, COUNT(*) AS count,
                   SUM(reverted = 1) AS reverted,
                   SUM(CASE WHEN reason = 'business_need' THEN 1 ELSE 0 END) AS evasion
            FROM event_log {where} GROUP BY action, grade, queue, policy_version
        """, params).fetchall()

    total = accepted = reverted = evasion = 0
    by_action = {action.value: 0 for action in Action}
    by_queue: dict[str, int] = {}
    by_grade: dict[str, int] = {}
    by_version: dict[int | None, int] = {}
    for row in rows:
        count = row["count"]
        total += count
        if row["action"] in _ACCEPTED_ACTIONS:
            accepted += count
        reverted += row["reverted"]
        evasion += row["evasion"]
        by_action[row["action"]] = by_action.get(row["action"], 0) + count
        by_queue[row["queue"]] = by_queue.get(row["queue"], 0) + count
        by_grade[row["grade"]] = by_grade.get(row["grade"], 0) + count
        version = row["policy_version"]
        by_version[version] = by_version.get(version, 0) + count

    return Stats(
        total=total,
        acceptance_rate=round(accepted / total, 4) if total else 0.0,
        revert_rate=round(reverted / total, 4) if total else 0.0,
        evasion_suspect=evasion,
        by_queue=by_queue,
        by_grade=by_grade,
        by_action=by_action,
        # Ascending versions, then "none" (events without a known version).
        by_policy_version={
            "none" if v is None else str(v): by_version[v]
            for v in sorted(by_version, key=lambda v: (v is None, v or 0))
        },
    )
