"""In-memory store of in-flight work items for the /process -> /decide flow.

Each /process call creates a WorkItem holding:
  - the live local_ai LocalSession (needed to restore pseudonyms later),
  - the original and masked text (kept in memory only, never persisted),
  - the detection metadata used to build the log event on /decide.

Items expire after a TTL and are also capped in count so memory can't grow
unbounded. A background sweeper discards expired items even if no further
store call arrives. Nothing here is written to disk or logged.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

# How long an unresolved work item lives before it is discarded.
DEFAULT_TTL_SECONDS = 600  # 10 minutes
# Hard cap on concurrently stored items (oldest evicted first).
MAX_ITEMS = 1000
# How often the background sweeper runs.
SWEEP_INTERVAL_SECONDS = 60


@dataclass
class WorkItem:
    work_id: str
    session: object  # local_ai LocalSession
    original_text: str
    masked_text: str
    detected_types: tuple[str, ...]
    detected_count: int  # number of detected spans (not distinct types)
    grade: str
    detection_confidence: str
    remaining_count: int
    created_at: float = field(default_factory=time.monotonic)


class SessionStore:
    def __init__(
        self,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_items: int = MAX_ITEMS,
        sweep_interval: float = SWEEP_INTERVAL_SECONDS,
    ):
        self._ttl = ttl_seconds
        self._max = max_items
        self._items: dict[str, WorkItem] = {}
        self._lock = threading.Lock()
        self._sweeper: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._sweep_interval = sweep_interval

    # --- background expiry ---------------------------------------------------
    def start_sweeper(self) -> None:
        """Start a daemon thread that expires items on a timer.

        Safe to call more than once; only one sweeper runs. Idempotent so the
        app lifespan can call it on startup.
        """
        with self._lock:
            if self._sweeper is not None and self._sweeper.is_alive():
                return
            self._stop.clear()
            self._sweeper = threading.Thread(
                target=self._sweep_loop, name="session-sweeper", daemon=True
            )
            self._sweeper.start()

    def stop_sweeper(self) -> None:
        self._stop.set()

    def _sweep_loop(self) -> None:
        while not self._stop.wait(self._sweep_interval):
            with self._lock:
                self._purge_expired_locked()

    # --- core store ----------------------------------------------------------
    def _purge_expired_locked(self) -> None:
        now = time.monotonic()
        expired = [k for k, v in self._items.items() if now - v.created_at > self._ttl]
        for k in expired:
            self._discard_locked(k)

    def _discard_locked(self, work_id: str) -> None:
        item = self._items.pop(work_id, None)
        if item is not None:
            try:
                item.session.close()
            except Exception:
                pass  # closing is best-effort; never raise from cleanup

    def add(self, **kwargs) -> WorkItem:
        work_id = uuid.uuid4().hex
        item = WorkItem(work_id=work_id, **kwargs)
        with self._lock:
            self._purge_expired_locked()
            # Enforce the cap by evicting the oldest items.
            while len(self._items) >= self._max:
                oldest = min(self._items.values(), key=lambda w: w.created_at)
                self._discard_locked(oldest.work_id)
            self._items[work_id] = item
        return item

    def get(self, work_id: str) -> Optional[WorkItem]:
        with self._lock:
            self._purge_expired_locked()
            return self._items.get(work_id)

    def pop(self, work_id: str) -> Optional[WorkItem]:
        """Remove and return an item WITHOUT closing it (caller owns cleanup)."""
        with self._lock:
            self._purge_expired_locked()
            return self._items.pop(work_id, None)

    def put(self, item: WorkItem) -> None:
        """Re-insert a previously popped item under its existing work_id.

        Used when /decide keeps a send_transformed session alive for a later
        /process/restore. Capacity is enforced the same way as add().
        """
        with self._lock:
            self._purge_expired_locked()
            while len(self._items) >= self._max and item.work_id not in self._items:
                oldest = min(self._items.values(), key=lambda w: w.created_at)
                self._discard_locked(oldest.work_id)
            self._items[item.work_id] = item

    def discard(self, work_id: str) -> None:
        with self._lock:
            self._discard_locked(work_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


# Module-level store shared by the process router.
store = SessionStore()
