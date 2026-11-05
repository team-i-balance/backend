"""Change summary for console polling (GET /logs/changes).

The console polls every few seconds to keep its flowchart and queues current.
This returns only revision markers per area, never event contents, so an
unchanged poll is a few indexed MAX/COUNT lookups and a 304.

Areas and what moves them:
  events          new event (last_id; AUTOINCREMENT ids are never reused) or an
                  edited event, e.g. reason submitted / re-requested (change_seq,
                  bumped by a trigger on every UPDATE; see app/db.py)
  cases           a close or reopen (case_history is append-only)
  false_positives a decision (false_positive_decision is append-only) or a new
                  report: reports live in event_log, so the events markers are
                  repeated here
  policy          a publish (latest), a server deploy (active), a draft save or a
                  device acknowledgement (ack_last_id)
"""
import hashlib
import json

from app.db import get_conn
from app.policy import store as policy_store


def _events(conn) -> dict:
    # MAX on the indexed id / change_seq columns: no table scan.
    row = conn.execute(
        """SELECT (SELECT MAX(id) FROM event_log) AS last_id,
                  (SELECT MAX(change_seq) FROM event_log) AS change_seq"""
    ).fetchone()
    return {"last_id": row["last_id"], "change_seq": row["change_seq"] or 0}


def _last_id(conn, table: str):
    return conn.execute(f"SELECT MAX(id) AS last_id FROM {table}").fetchone()["last_id"]


def _policy() -> dict:
    latest = policy_store.latest()
    acks = policy_store.ack_last_id()
    active = policy_store.current()
    return {
        "latest": latest.version if latest else None,
        "active": active.version if active else None,
        "activated_at": active.activated_at if active else None,
        # Same quoted value GET /policy/draft returns as `etag`.
        "draft_etag": policy_store.draft()["etag"],
        "ack_last_id": acks,
    }


def summary() -> dict:
    with get_conn() as conn:
        events = _events(conn)
        out = {
            "events": events,
            "cases": {"last_id": _last_id(conn, "case_history")},
            "false_positives": {
                "last_id": _last_id(conn, "false_positive_decision"),
                # Reports come from events (also via a later reason), not this table.
                "reports": dict(events),
            },
        }
    out["policy"] = _policy()
    canonical = json.dumps(out, sort_keys=True, separators=(",", ":"))
    out["rev"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return out
