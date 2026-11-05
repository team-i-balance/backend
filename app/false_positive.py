"""False-positive report clustering and security-team decisions (issue #48).

A report is an event item whose effective reason (item reason, else event
reason) is ``false_positive`` and that carries a ``value_hash``. Items without
a value_hash cannot be clustered and are not listed here; those events remain
visible through /logs (detection_improve queue).

A group is ``done`` when its latest decision is newer than its latest report,
otherwise ``open``: a new report after a decision reopens it.
"""
from datetime import datetime, timezone

from app.crud import _row_to_dict
from app.db import get_conn
from app.log_time import sql_utc_microseconds
from app.schemas import Action, Grade

_REPORTS = """
    SELECT e.id AS event_id, e.user_id,
           COALESCE(e.reason_at, e.created_at) AS reported_at,
           lower(json_extract(j.value, '$.value_hash')) AS value_hash,
           json_extract(j.value, '$.preview') AS preview,
           json_extract(j.value, '$.type') AS type
    FROM event_log e, json_each(CASE WHEN json_valid(e.items) THEN e.items ELSE '[]' END) j
    WHERE e.is_test = 0
      AND COALESCE(json_extract(j.value, '$.reason'), e.reason) = 'false_positive'
      AND json_extract(j.value, '$.value_hash') IS NOT NULL
"""

_LATEST_DECISIONS = """
    SELECT d.* FROM false_positive_decision d
    WHERE d.id = (SELECT max(id) FROM false_positive_decision WHERE value_hash = d.value_hash)
"""


class FalsePositiveError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _ts(value: str) -> int:
    return sql_utc_microseconds(value) or 0


def _groups(conn, only_hash: str | None = None) -> list[dict]:
    sql, params = _REPORTS, []
    if only_hash is not None:
        sql += " AND lower(json_extract(j.value, '$.value_hash')) = ?"
        params.append(only_hash)
    groups: dict[str, dict] = {}
    for row in conn.execute(sql, params):
        g = groups.setdefault(row["value_hash"], {
            "events": set(), "users": set(), "types": set(),
            "last": None, "preview": None, "preview_ts": -1,
        })
        g["events"].add(row["event_id"])
        if row["user_id"]:
            g["users"].add(row["user_id"])
        if row["type"]:
            g["types"].add(row["type"])
        ts = _ts(row["reported_at"])
        if g["last"] is None or ts > _ts(g["last"]):
            g["last"] = row["reported_at"]
        if row["preview"] and ts >= g["preview_ts"]:
            g["preview"], g["preview_ts"] = row["preview"], ts

    decisions = {}
    if groups:
        sql, params = _LATEST_DECISIONS, []
        if only_hash is not None:
            sql += " AND d.value_hash = ?"
            params.append(only_hash)
        decisions = {r["value_hash"]: r for r in conn.execute(sql, params)}

    result = []
    for value_hash, g in groups.items():
        d = decisions.get(value_hash)
        done = d is not None and _ts(d["decided_at"]) >= _ts(g["last"])
        result.append({
            "value_hash": value_hash,
            "status": "done" if done else "open",
            "report_count": len(g["events"]),
            "employee_count": len(g["users"]),
            "last_reported_at": g["last"],
            "preview": g["preview"],
            "types": sorted(g["types"]),
            "decision": {
                "decision": d["decision"], "why": d["why"],
                "by": d["decided_by"], "at": d["decided_at"],
            } if d else None,
        })
    result.sort(key=lambda x: (_ts(x["last_reported_at"]), x["value_hash"]), reverse=True)
    return result


def list_groups(status: str) -> dict:
    with get_conn() as conn:
        conn.execute("BEGIN")  # reports and decisions from one snapshot
        return {"items": [g for g in _groups(conn) if g["status"] == status]}


def decide(value_hash: str, *, decision: str, why: str | None, decided_by: str) -> dict:
    value_hash = value_hash.lower()
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if not _groups(conn, value_hash):
            raise FalsePositiveError(404, "FALSE_POSITIVE_NOT_FOUND")
        conn.execute(
            """INSERT INTO false_positive_decision
               (value_hash, decision, why, decided_by, decided_at)
               VALUES (?, ?, ?, ?, ?)""",
            (value_hash, decision, why, decided_by, datetime.now(timezone.utc).isoformat()),
        )
        return _groups(conn, value_hash)[0]


def request_reason(event_id: int) -> dict:
    """Ask the employee again: bump reason_requested_at on an unexplained raw send."""
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
