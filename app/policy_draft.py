"""Draft snapshots and optimistic locking inside the policy DB transaction."""
import base64
import hashlib
import json
from collections import defaultdict, deque
from datetime import datetime, timezone


# Top-level payload key that once carried console plaintext; never signable.
FORBIDDEN_PAYLOAD_KEYS = ("console",)


class DraftError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def read_draft(conn) -> dict:
    row = conn.execute("SELECT * FROM policy_draft WHERE singleton = 1").fetchone()
    if row:
        state = {
            "payload": json.loads(row["payload"]), "changes": json.loads(row["changes"]),
            "has_draft": True, "base_version": row["base_version"],
            "revision": row["revision"], "updated_at": row["updated_at"], "updated_by": row["updated_by"],
        }
    else:
        latest = conn.execute("SELECT version, envelope FROM policy_bundle ORDER BY version DESC LIMIT 1").fetchone()
        payload = None
        if latest:
            envelope = json.loads(latest["envelope"])
            payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
        state = {
            "payload": payload, "changes": [], "has_draft": False,
            "base_version": latest["version"] if latest else None,
            "revision": 0, "updated_at": None, "updated_by": None,
        }
    console = conn.execute("SELECT state FROM policy_console_state WHERE singleton = 1").fetchone()
    state["console_state"] = json.loads(console["state"]) if console else None
    # Revision prevents an old writer from passing the check after A -> B -> A,
    # even with the same payload/changes and a frozen server clock.
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    state["etag"] = '"sha256:' + hashlib.sha256(canonical.encode("utf-8")).hexdigest() + '"'
    return state


def require_match(state: dict, if_match: str | None) -> None:
    if if_match is None:
        raise DraftError(428, "DRAFT_PRECONDITION_REQUIRED")
    # Exactly one strong ETag; wildcard/weak tags cannot protect against edits.
    if if_match != state["etag"]:
        raise DraftError(409, "DRAFT_CONFLICT")


def reject_unsignable(payload: dict) -> None:
    """Console screen state belongs in console_state, never in a signed bundle."""
    if any(key in payload for key in FORBIDDEN_PAYLOAD_KEYS):
        raise DraftError(422, "POLICY_PAYLOAD_CONSOLE_FORBIDDEN")


def save_draft(conn, payload: dict, changes: list[dict], *, if_match: str | None, editor: str,
               console_state: dict | None = None) -> dict:
    before = read_draft(conn)
    require_match(before, if_match)
    now = datetime.now(timezone.utc).isoformat()
    previous = defaultdict(deque)
    for change in before["changes"]:
        previous[(change["what"], change["src"])].append(change)
    stamped = []
    for change in changes:
        key = (change["what"], change["src"])
        # Full-snapshot clients may resend server at/by fields; never trust
        # those fields. Preserve existing metadata or stamp a new description.
        stamped.append(previous[key].popleft() if previous[key] else {
            "what": change["what"], "src": change["src"], "at": now, "by": editor,
        })
    conn.execute(
        """INSERT INTO policy_draft
           (singleton, revision, payload, changes, base_version, updated_at, updated_by)
           VALUES (1, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(singleton) DO UPDATE SET
             revision=excluded.revision, payload=excluded.payload, changes=excluded.changes,
             base_version=excluded.base_version, updated_at=excluded.updated_at, updated_by=excluded.updated_by""",
        (before["revision"] + 1, json.dumps(payload, ensure_ascii=False),
         json.dumps(stamped, ensure_ascii=False), before["base_version"], now, editor),
    )
    if console_state is None:
        conn.execute("DELETE FROM policy_console_state WHERE singleton = 1")
    else:
        conn.execute(
            """INSERT INTO policy_console_state (singleton, state) VALUES (1, ?)
               ON CONFLICT(singleton) DO UPDATE SET state=excluded.state""",
            (json.dumps(console_state, ensure_ascii=False),),
        )
    return read_draft(conn)
