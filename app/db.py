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
    queue           TEXT    NOT NULL
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


def init_db() -> None:
    """Create tables and add reason tracking to existing event databases."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        # Serialize schema inspection + ALTER across concurrent server starts.
        # reason_text is also used by event-context metadata (issue #21).
        conn.execute("BEGIN IMMEDIATE")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(event_log)")}
        for name in ("reason_requested_at", "reason_at", "reason_text"):
            if name not in columns:
                conn.execute(f"ALTER TABLE event_log ADD COLUMN {name} TEXT")
        if "source" not in columns:
            # Which flow produced the event (issue #32); all earlier rows are text events.
            conn.execute("ALTER TABLE event_log ADD COLUMN source TEXT NOT NULL DEFAULT 'text'")
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
