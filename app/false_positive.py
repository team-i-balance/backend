"""False-positive report clustering and security-team decisions (issue #48).

A report is an event item whose effective reason (item reason, else event
reason) is ``false_positive`` and that carries a ``value_hash``. A ``converted``
item (still masked) does not inherit the event reason: the employee reported
only the values they sent as original (#63). Items without
a value_hash cannot be clustered and are not listed here; those events remain
visible through /logs (detection_improve queue).

Report time: an explicit item reason was given when the event was created, so
it is dated ``created_at``. An inherited event-level reason is dated
``reason_at`` (a late reason submission is a new report).

A group is ``done`` when its latest decision is at or after its latest report,
otherwise ``open``: a new report after a decision reopens it.

Aggregation runs in SQLite and pages by ``last_event_id`` (like /logs/events'
``cursor``), so a request never materializes the whole history in Python.
"""
from datetime import datetime, timezone

from app.crud import _row_to_dict
from app.db import get_conn
from app.log_time import sql_utc_microseconds
from app.schemas import Action, Grade

_ITEM_REASON = "json_extract(j.value, '$.reason')"
_ITEM_HASH = "lower(json_extract(j.value, '$.value_hash'))"

_REPORTS = f"""
    SELECT e.id AS event_id, e.user_id,
           CASE WHEN {_ITEM_REASON} IS NOT NULL THEN e.created_at
                ELSE COALESCE(e.reason_at, e.created_at) END AS reported_at,
           {_ITEM_HASH} AS value_hash,
           json_extract(j.value, '$.preview') AS preview,
           json_extract(j.value, '$.type') AS type
    FROM event_log e, json_each(CASE WHEN json_valid(e.items) THEN e.items ELSE '[]' END) j
    WHERE e.is_test = 0
      AND (e.reason = 'false_positive' OR instr(e.items, 'false_positive') > 0)
      AND COALESCE({_ITEM_REASON},
                   CASE WHEN json_extract(j.value, '$.decision') = 'converted'
                        THEN NULL ELSE e.reason END) = 'false_positive'
      AND json_extract(j.value, '$.value_hash') IS NOT NULL
"""

_GROUPS = f"""
    SELECT * FROM (
        SELECT g.*, d.decision, d.why, d.decided_by, d.decided_at,
               CASE WHEN d.id IS NOT NULL
                         AND utc_microseconds(d.decided_at) >= g.last_us
                    THEN 'done' ELSE 'open' END AS status
        FROM (
            SELECT value_hash,
                   count(DISTINCT event_id) AS report_count,
                   count(DISTINCT user_id) AS employee_count,
                   max(event_id) AS last_event_id,
                   max(utc_microseconds(reported_at)) AS last_us
            FROM ({_REPORTS} {{hash_filter}}) GROUP BY value_hash
        ) g
        LEFT JOIN false_positive_decision d ON d.id = (
            SELECT max(id) FROM false_positive_decision WHERE value_hash = g.value_hash
        )
    ) WHERE 1 = 1 {{where}}
    ORDER BY last_event_id DESC, value_hash DESC
"""


class FalsePositiveError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _ts(value) -> int:
    return sql_utc_microseconds(value) or -1


def _query_groups(conn, *, hashes=None, where="", params=(), limit=None) -> list:
    hash_filter, hash_params = "", []
    if hashes is not None:
        hash_filter = f" AND {_ITEM_HASH} IN ({','.join('?' * len(hashes))})"
        hash_params = list(hashes)
    sql = _GROUPS.format(hash_filter=hash_filter, where=where)
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    return conn.execute(sql, [*hash_params, *params]).fetchall()


def _details(conn, rows) -> list[dict]:
    """Add last_reported_at, preview and types for one page of groups."""
    if not rows:
        return []
    hashes = [r["value_hash"] for r in rows]
    sql = _REPORTS + f" AND {_ITEM_HASH} IN ({','.join('?' * len(hashes))})"
    extra = {h: {"last": None, "last_ts": -2, "preview": None, "preview_ts": -2, "types": set()}
             for h in hashes}
    for r in conn.execute(sql, hashes):
        x = extra[r["value_hash"]]
        ts = _ts(r["reported_at"])
        if ts > x["last_ts"]:
            x["last"], x["last_ts"] = r["reported_at"], ts
        if r["preview"] and ts >= x["preview_ts"]:
            x["preview"], x["preview_ts"] = r["preview"], ts
        if r["type"]:
            x["types"].add(r["type"])
    return [{
        "value_hash": r["value_hash"],
        "status": r["status"],
        "report_count": r["report_count"],
        "employee_count": r["employee_count"],
        "last_event_id": r["last_event_id"],
        "last_reported_at": extra[r["value_hash"]]["last"],
        "preview": extra[r["value_hash"]]["preview"],
        "types": sorted(extra[r["value_hash"]]["types"]),
        "decision": {
            "decision": r["decision"], "why": r["why"],
            "by": r["decided_by"], "at": r["decided_at"],
        } if r["decision"] else None,
    } for r in rows]


def list_groups(status: str, *, limit: int, cursor: int | None) -> list[dict]:
    where, params = " AND status = ?", [status]
    if cursor is not None:
        where += " AND last_event_id < ?"
        params.append(cursor)
    with get_conn() as conn:
        conn.execute("BEGIN")  # reports and decisions from one snapshot
        rows = _query_groups(conn, where=where, params=params, limit=limit)
        if len(rows) == limit:
            # Never split groups sharing a last_event_id across pages: the
            # next cursor (< last_event_id) would skip the rest.
            last = rows[-1]
            rows += _query_groups(
                conn, where=where + " AND last_event_id = ? AND value_hash < ?",
                params=[*params, last["last_event_id"], last["value_hash"]],
            )
        return _details(conn, rows)


def _one(conn, value_hash: str) -> dict | None:
    rows = _query_groups(conn, hashes=[value_hash])
    return _details(conn, rows)[0] if rows else None


def decide(value_hash: str, *, decision: str, why: str | None, decided_by: str) -> dict:
    value_hash = value_hash.lower()
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if _one(conn, value_hash) is None:
            raise FalsePositiveError(404, "FALSE_POSITIVE_NOT_FOUND")
        conn.execute(
            """INSERT INTO false_positive_decision
               (value_hash, decision, why, decided_by, decided_at)
               VALUES (?, ?, ?, ?, ?)""",
            (value_hash, decision, why, decided_by, datetime.now(timezone.utc).isoformat()),
        )
        return _one(conn, value_hash)


def request_reason(event_id: int) -> dict:
    """Ask the employee again: bump reason_requested_at on an unexplained raw send.

    Employee clients observe this through GET /events/{id}/reason.
    """
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM event_log WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            raise FalsePositiveError(404, "EVENT_NOT_FOUND")
        if row["grade"] != Grade.sensitive.value or row["action"] != Action.send_as_is.value:
            raise FalsePositiveError(409, "REASON_NOT_REQUESTED")
        if row["reason_at"] is not None or row["reason"] is not None:
            raise FalsePositiveError(409, "REASON_ALREADY_SUBMITTED")
        conn.execute(
            "UPDATE event_log SET reason_requested_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), event_id),
        )
        return _row_to_dict(
            conn.execute("SELECT * FROM event_log WHERE id = ?", (event_id,)).fetchone()
        )
