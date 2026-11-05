"""Bounded, process-local ownership of protected files and their mappings."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import threading
import time
from typing import TYPE_CHECKING

from app.file_schemas import FileSummary
from app.schemas import Grade

if TYPE_CHECKING:
    from local_ai.pipeline import LocalSession


class FileStoreFull(RuntimeError):
    pass


@dataclass
class FileWorkItem:
    work_id: str
    file_bytes: bytes = field(repr=False)
    session: LocalSession = field(repr=False)
    grade: Grade
    summary: FileSummary
    expires_at: datetime
    deadline: float = field(repr=False)

    def close(self) -> None:
        try:
            self.session.close()
        finally:
            self.file_bytes = b""


class FileWorkStore:
    """add transfers ownership on success; take transfers it to the caller.

    take is internal, not an authorization check. A future AI route must check
    access before taking a work item, and close it in finally after use.
    """

    def __init__(self, *, ttl_seconds=600, max_items=20,
                 max_bytes=64 * 1024 * 1024, sweep_interval=60):
        self._ttl = ttl_seconds
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._sweep_interval = sweep_interval
        self._items: dict[str, FileWorkItem] = {}
        self._bytes = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False

    def add(self, *, work_id, file_bytes, session, grade, summary) -> FileWorkItem:
        with self._lock:
            self._purge_locked()
            if (self._closed or len(self._items) >= self._max_items
                    or self._bytes + len(file_bytes) > self._max_bytes):
                raise FileStoreFull()
            if work_id in self._items:
                raise ValueError("duplicate file work ID")
            item = FileWorkItem(
                work_id, file_bytes, session, grade, summary,
                datetime.now(timezone.utc) + timedelta(seconds=self._ttl),
                time.monotonic() + self._ttl,
            )
            self._items[work_id] = item
            self._bytes += len(file_bytes)
            return item

    def take(self, work_id: str) -> FileWorkItem | None:
        with self._lock:
            self._purge_locked()
            return self._pop_locked(work_id)

    def discard(self, work_id: str) -> None:
        with self._lock:
            self._discard_locked(work_id)

    def _pop_locked(self, work_id):
        item = self._items.pop(work_id, None)
        if item is not None:
            self._bytes -= len(item.file_bytes)
        return item

    def _discard_locked(self, work_id):
        item = self._pop_locked(work_id)
        if item is not None:
            try:
                item.close()
            except Exception:
                # Continue releasing other work; never log sensitive exceptions.
                pass

    def _purge_locked(self):
        now = time.monotonic()
        for work_id in [k for k, v in self._items.items() if v.deadline <= now]:
            self._discard_locked(work_id)

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._closed = False
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._sweep, name="file-work-expiry", daemon=True,
            )
            self._thread.start()

    def _sweep(self):
        while not self._stop.wait(self._sweep_interval):
            with self._lock:
                self._purge_locked()

    def close(self) -> None:
        self._stop.set()
        with self._lock:
            self._closed = True
            for work_id in list(self._items):
                self._discard_locked(work_id)
        if self._thread is not None:
            self._thread.join()

    def __len__(self):
        with self._lock:
            self._purge_locked()
            return len(self._items)


store = FileWorkStore()
