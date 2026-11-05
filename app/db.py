"""SQLite connection and initialization.

Uses the stdlib sqlite3. The DB file lives under backend/data/ (gitignored).
"""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

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
"""


def init_db() -> None:
    """Create the data dir, DB file, and tables if missing."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def get_conn():
    """Yield a sqlite3 connection with Row factory, committing on success."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
