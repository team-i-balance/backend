"""SQLite connection and initialization.

Uses the stdlib sqlite3. The DB file lives under backend/data/ (gitignored).
"""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.log_time import sql_utc_microseconds

# backend/ root (parent of this app/ package)
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.getenv("LOG_DB_PATH", DATA_DIR / "events.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS event_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL,
    request_id      TEXT,
    grade           TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    reason          TEXT,
    detection_confidence TEXT,
    detected_types  TEXT    NOT NULL DEFAULT '[]',
    detected_count  INTEGER NOT NULL DEFAULT 0,
    reverted        INTEGER NOT NULL DEFAULT 0,
    restored        INTEGER NOT NULL DEFAULT 0,
    content_hash    TEXT,
    queue           TEXT    NOT NULL,
    is_test         INTEGER NOT NULL DEFAULT 0,
    -- Context fields (issue #21)
    user_id         TEXT,
    dept            TEXT,
    target_ai       TEXT,
    device_id       TEXT,
    reason_text     TEXT,
    items           TEXT    NOT NULL DEFAULT '[]',
    -- Policy version in effect when the input was processed (issue #49)
    policy_version  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_event_created_at ON event_log (created_at);
CREATE INDEX IF NOT EXISTS idx_event_queue      ON event_log (queue);
CREATE INDEX IF NOT EXISTS idx_event_grade      ON event_log (grade);

-- Review history is the source of case state: no history / reopen = open,
-- latest close = closed. Existing events therefore need no backfill.
CREATE TABLE IF NOT EXISTS case_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER NOT NULL REFERENCES event_log(id),
    operation   TEXT NOT NULL CHECK (operation IN ('close', 'reopen')),
    created_at  TEXT NOT NULL,
    reviewer    TEXT NOT NULL,
    conclusion  TEXT CHECK (conclusion IN ('violation', 'legit', 'fp')),
    cause       TEXT CHECK (cause IN ('fit', 'care', 'intent')),
    memo        TEXT,
    rule        TEXT,
    CHECK (
        (operation = 'close' AND conclusion IS NOT NULL AND memo IS NOT NULL)
        OR (operation = 'reopen' AND conclusion IS NULL AND cause IS NULL
            AND memo IS NULL AND rule IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_case_history_event ON case_history (event_id, id);
"""


# Integration-check events that were sent to the deployed server before the
# `test` flag existed (issue #27). They are flagged, never deleted.
LEGACY_TEST_REQUEST_ID_PATTERN = "console-test-%"


def _columns(conn, table: str) -> set[str]:
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}


def _migrate_is_test(conn) -> None:
    """Add event_log.is_test to DBs created before it existed.

    Idempotent: does nothing once the column is present. Adding the column
    and flagging the legacy console-test-* rows happen in one transaction, so
    a crash cannot leave the column added but the rows unflagged.
    """
    if "is_test" in _columns(conn, "event_log"):
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Re-check under the write lock in case another process migrated.
        if "is_test" not in _columns(conn, "event_log"):
            conn.execute(
                "ALTER TABLE event_log "
                "ADD COLUMN is_test INTEGER NOT NULL DEFAULT 0"
            )
            conn.execute(
                "UPDATE event_log SET is_test = 1 WHERE request_id LIKE ?",
                (LEGACY_TEST_REQUEST_ID_PATTERN,),
            )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def init_db() -> None:
    """Create tables and migrate event context, reason tracking, source and test flags."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        # Serialize schema inspection + ALTER across concurrent server starts.
        # reason_text is also used by event-context metadata (issue #21).
        conn.execute("BEGIN IMMEDIATE")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(event_log)")}
        for name in ("reason_requested_at", "reason_at", "reason_text",
                     "user_id", "dept", "target_ai", "device_id"):
            if name not in columns:
                conn.execute(f"ALTER TABLE event_log ADD COLUMN {name} TEXT")
        if "items" not in columns:
            conn.execute("ALTER TABLE event_log ADD COLUMN items TEXT NOT NULL DEFAULT '[]'")
        if "source" not in columns:
            # Which flow produced the event (issue #32); all earlier rows are text events.
            conn.execute("ALTER TABLE event_log ADD COLUMN source TEXT NOT NULL DEFAULT 'text'")
        if "policy_version" not in columns:
            # Policy version in effect when the input was processed (issue #49).
            # Earlier rows stay NULL: their version is unknown, never guessed.
            conn.execute("ALTER TABLE event_log ADD COLUMN policy_version INTEGER")
        # Older databases lack user_id until the migrations above finish.
        # Keep the new index in the same transaction; don't hide DDL failures.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_user_id ON event_log (user_id)")
        # Older rows have no independent request/submission timestamps. Use
        # event creation time for their initial waiting state / initial reason.
        conn.execute("""
            UPDATE event_log SET reason_requested_at = created_at
            WHERE grade = 'sensitive_S' AND action = 'send_as_is'
              AND reason IS NULL AND reason_requested_at IS NULL
        """)
        conn.execute("""
            UPDATE event_log SET reason_at = created_at
            WHERE reason IS NOT NULL AND reason_at IS NULL
        """)
        # Finish this transaction before the is_test migration opens its own.
        conn.commit()
        _migrate_is_test(conn)


@contextmanager
def get_conn():
    """Yield a sqlite3 connection with Row factory, committing on success."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.create_function("utc_microseconds", 1, sql_utc_microseconds, deterministic=True)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
