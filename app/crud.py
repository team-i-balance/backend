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


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["detected_types"] = json.loads(d.get("detected_types") or "[]")
    d["reverted"] = bool(d["reverted"])
    d["restored"] = bool(d["restored"])
    return d


def insert_event(event: EventIn) -> dict:
    queue = classify(event)
    created_at = _now_utc_iso()

    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO event_log (
                created_at, request_id, grade, action, reason,
                detection_confidence, detected_types, detected_count,
                reverted, restored, content_hash, queue, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                event.source.value,
            ),
        )
        new_id = cur.lastrowid
        needs_reason = (
            event.grade == Grade.sensitive
            and event.action == Action.send_as_is
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


def _event_filter(*, grade=None, queue=None, start=None, end=None, cursor=None):
    """One set of date/filter semantics for lists and aggregate queries."""
    clauses = []
    params: list = []
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
) -> list[dict]:
    where, params = _event_filter(grade=grade, queue=queue, start=start, end=end, cursor=cursor)
    sql = f"SELECT * FROM event_log {where} ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_stats(*, start: Optional[str] = None, end: Optional[str] = None) -> Stats:
    where, params = _event_filter(start=start, end=end)
    # One aggregate query sees one database snapshot and is not bounded by the
    # event-list page size. With the current enums it returns at most 48 groups.
    with get_conn() as conn:
        rows = conn.execute(f"""
            SELECT action, grade, queue, COUNT(*) AS count,
                   SUM(reverted = 1) AS reverted,
                   SUM(CASE WHEN reason = 'business_need' THEN 1 ELSE 0 END) AS evasion
            FROM event_log {where} GROUP BY action, grade, queue
        """, params).fetchall()

    total = accepted = reverted = evasion = 0
    by_action = {action.value: 0 for action in Action}
    by_queue: dict[str, int] = {}
    by_grade: dict[str, int] = {}
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

    return Stats(
        total=total,
        acceptance_rate=round(accepted / total, 4) if total else 0.0,
        revert_rate=round(reverted / total, 4) if total else 0.0,
        evasion_suspect=evasion,
        by_queue=by_queue,
        by_grade=by_grade,
        by_action=by_action,
    )
