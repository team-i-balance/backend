"""SQLite transactions for policy state, separate from the event-log schema."""
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS policy_bundle (
    version INTEGER PRIMARY KEY,
    envelope TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    stored_at TEXT,
    rule_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS policy_active (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_ack (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('applied', 'rejected')),
    reason TEXT,
    at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policy_ack_device ON policy_ack (device_id, id);
CREATE INDEX IF NOT EXISTS idx_policy_ack_version ON policy_ack (version, device_id, id);
CREATE TABLE IF NOT EXISTS model_manifest (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    envelope TEXT NOT NULL
);
-- Bind the persistent store to its public signing key. Never store the private key here.
CREATE TABLE IF NOT EXISTS policy_signing_key (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_draft (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL,
    payload TEXT NOT NULL,
    changes TEXT NOT NULL,
    base_version INTEGER,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
"""


class PolicyDatabase:
    def __init__(self, path: Path | str | None):
        self.path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        # Isolated in-memory SQLite is for standalone unit-test stores only.
        self._memory = self._connect(":memory:") if path is None else None
        self._initialized = False

    @staticmethod
    def _connect(path):
        conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        with self._lock:
            if self._initialized:
                return
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = self._memory if self._memory is not None else self._connect(self.path)
            try:
                conn.executescript(SCHEMA)
            finally:
                if self._memory is None:
                    conn.close()
            self._initialized = True

    @contextmanager
    def transaction(self, *, write=False):
        with self._lock:
            self.initialize()
            conn = self._memory if self._memory is not None else self._connect(self.path)
            try:
                # SQLite's lock, unlike the Python lock, also serializes other
                # workers/processes before they allocate or compare versions.
                conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                if self._memory is None:
                    conn.close()
