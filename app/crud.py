"""Data access for event_log: insert, query, aggregate."""
import json
from datetime import datetime, timezone
from typing import Optional

from app.classify import classify
from app.db import get_conn
from app.schemas import EventIn, Stats

# Actions that count as "accepted" (sent to the AI in some form).
_ACCEPTED_ACTIONS = ("send_as_is", "send_transformed")


def _to_utc_iso(value: str) -> str:
    """Normalize an ISO8601 string to a canonical UTC representation.

    Stored timestamps are always UTC with a '+00:00' offset (see insert_event).
    Query bounds may arrive with a different offset or a 'Z' suffix; comparing
    them lexicographically against stored values would be wrong. We parse the
    bound, convert to UTC, and render it the same way rows are stored, so the
    string comparison in SQL is equivalent to an instant comparison.

    A naive datetime (no offset) is treated as UTC.
    """
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


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
                reverted, restored, content_hash, queue
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
        new_id = cur.lastrowid
        row = conn.execute(
            "SELECT * FROM event_log WHERE id = ?", (new_id,)
        ).fetchone()

    return _row_to_dict(row)


def list_events(
    *,
    grade: Optional[str] = None,
    queue: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = 100,
) -> list[dict]:
    clauses = []
    params: list = []
    if grade:
        clauses.append("grade = ?")
        params.append(grade)
    if queue:
        clauses.append("queue = ?")
        params.append(queue)
    # Compare as instants via SQLite's datetime(), with both the stored value
    # and the bound normalized to UTC. This avoids lexical comparison pitfalls
    # (differing offsets, 'Z' suffix, or microsecond presence).
    if start:
        clauses.append("datetime(created_at) >= datetime(?)")
        params.append(_to_utc_iso(start))
    if end:
        clauses.append("datetime(created_at) <= datetime(?)")
        params.append(_to_utc_iso(end))

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM event_log {where} ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_stats() -> Stats:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM event_log").fetchone()["c"]

        if total == 0:
            return Stats(
                total=0,
                acceptance_rate=0.0,
                revert_rate=0.0,
                evasion_suspect=0,
                by_queue={},
                by_grade={},
            )

        placeholders = ",".join("?" * len(_ACCEPTED_ACTIONS))
        accepted = conn.execute(
            f"SELECT COUNT(*) AS c FROM event_log WHERE action IN ({placeholders})",
            _ACCEPTED_ACTIONS,
        ).fetchone()["c"]

        reverted = conn.execute(
            "SELECT COUNT(*) AS c FROM event_log WHERE reverted = 1"
        ).fetchone()["c"]

        evasion = conn.execute(
            "SELECT COUNT(*) AS c FROM event_log WHERE reason = 'business_need'"
        ).fetchone()["c"]

        by_queue = {
            r["queue"]: r["c"]
            for r in conn.execute(
                "SELECT queue, COUNT(*) AS c FROM event_log GROUP BY queue"
            ).fetchall()
        }
        by_grade = {
            r["grade"]: r["c"]
            for r in conn.execute(
                "SELECT grade, COUNT(*) AS c FROM event_log GROUP BY grade"
            ).fetchall()
        }

    return Stats(
        total=total,
        acceptance_rate=round(accepted / total, 4),
        revert_rate=round(reverted / total, 4),
        evasion_suspect=evasion,
        by_queue=by_queue,
        by_grade=by_grade,
    )
