"""Change summary for console polling (GET /logs/changes).

The console polls every few seconds to keep its flowchart and queues current.
This returns only revision markers per area, never event contents, so an
unchanged poll is a few indexed MAX/COUNT lookups and a 304.

Areas and what moves them:
  events          new event (last_id; AUTOINCREMENT ids are never reused) or a
                  reason submitted (reason count) / re-requested (latest time)
  cases           a close or reopen (case_history is append-only)
  false_positives a decision (false_positive_decision is append-only)
  policy          a publish (latest), a server deploy (active) or a draft save
"""
import hashlib
import json

from app.db import get_conn
from app.policy import store as policy_store


def _events(conn) -> dict:
    # Separate subqueries so each MAX/COUNT is answered from its own index
    # (one combined aggregate would scan the whole table).
    row = conn.execute(
        """SELECT (SELECT MAX(id) FROM event_log) AS last_id,
                  (SELECT MAX(reason_at) FROM event_log) AS reason_at,
                  (SELECT COUNT(reason_at) FROM event_log) AS reasons,
                  (SELECT MAX(reason_requested_at) FROM event_log) AS requested_at,
                  (SELECT COUNT(reason_requested_at) FROM event_log) AS requests"""
    ).fetchone()
    marker = f'{row["reason_at"]}|{row["reasons"]}|{row["requested_at"]}|{row["requests"]}'
    return {
        "last_id": row["last_id"],
        # Opaque: changes whenever any event's reason state changes.
        "reason_rev": hashlib.sha256(marker.encode("utf-8")).hexdigest()[:16],
    }


def _last_id(conn, table: str):
    return conn.execute(f"SELECT MAX(id) AS last_id FROM {table}").fetchone()["last_id"]


def _policy() -> dict:
    latest = policy_store.latest()
    active = policy_store.current()
    return {
        "latest": latest.version if latest else None,
        "active": active.version if active else None,
        "activated_at": active.activated_at if active else None,
        # Same quoted value GET /policy/draft returns as `etag`.
        "draft_etag": policy_store.draft()["etag"],
    }


def summary() -> dict:
    with get_conn() as conn:
        out = {
            "events": _events(conn),
            "cases": {"last_id": _last_id(conn, "case_history")},
            "false_positives": {"last_id": _last_id(conn, "false_positive_decision")},
        }
    out["policy"] = _policy()
    canonical = json.dumps(out, sort_keys=True, separators=(",", ":"))
    out["rev"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return out
