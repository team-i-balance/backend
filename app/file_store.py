"""Bounded, process-local ownership of protected files and their mappings."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import threading
import time
from typing import TYPE_CHECKING, NamedTuple

from app.file_schemas import FileSummary
from app.schemas import Action, Grade

if TYPE_CHECKING:
    from app.file_events import FileEvent
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
    downloaded: bool = False
    # What the security log records about this work (#32); None is never logged.
    event: FileEvent | None = field(default=None, repr=False)

    def close(self) -> None:
        try:
            self.session.close()
        finally:
            self.file_bytes = b""


class Download(NamedTuple):
    data: bytes
    event: FileEvent | None


class FileWorkStore:
    """add transfers ownership on success; take transfers it to the caller.

    take_download consumes only the file bytes, leaving the session until expiry.
    take is internal, not an authorization check. A future AI route must check
    access before taking a work item, and close it in finally after use.
    on_expired receives the event of each work that expired before its copy was
    downloaded. Only sweep() calls it, outside the lock, ignoring its errors: add
    runs under the processing job's lock and discard on the event loop, so no
    request path waits for the event log.
    """

    def __init__(self, *, ttl_seconds=600, max_items=20,
                 max_bytes=64 * 1024 * 1024, sweep_interval=60,
                 on_expired: Callable[[FileEvent], None] | None = None):
        self._ttl = ttl_seconds
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._sweep_interval = sweep_interval
        self._on_expired = on_expired
        self._expired: list[FileEvent] = []  # Waiting for the next sweep().
        self._items: dict[str, FileWorkItem] = {}
        self._bytes = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False

    def add(self, *, work_id, file_bytes, session, grade, summary, event=None) -> FileWorkItem:
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
                time.monotonic() + self._ttl, event=event,
            )
            self._items[work_id] = item
            self._bytes += len(file_bytes)
            return item

    def take(self, work_id: str) -> FileWorkItem | None:
        """Transfer the whole work item, possibly already downloaded, to a caller."""
        with self._lock:
            self._purge_locked()
            return self._pop_locked(work_id)

    def take_download(self, work_id: str) -> Download | None:
        """Claim a copy once without consuming its restoration mapping or TTL."""
        with self._lock:
            self._purge_locked()
            item = self._items.get(work_id)
            if item is None or item.downloaded:
                return None
            data = item.file_bytes
            item.downloaded = True
            item.file_bytes = b""
            self._bytes -= len(data)
            return Download(data, item.event)

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
            item = self._items[work_id]
            if self._on_expired is not None and item.event is not None and not item.downloaded:
                self._expired.append(item.event)
            self._discard_locked(work_id)

    def sweep(self) -> None:
        """Purge expired work and report what expired before its download."""
        with self._lock:
            self._purge_locked()
            expired, self._expired = self._expired, []
        for event in expired:
            try:
                self._on_expired(event)
            except Exception:
                # Keep sweeping; never log sensitive exceptions.
                pass

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
            self.sweep()

    def close(self) -> None:
        self._stop.set()
        self.sweep()  # Report work that already expired; the rest just ends.
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


def _record_expiry(event: FileEvent) -> None:
    # Imported here so the store module does not pull in the database layer.
    from app.file_events import record

    record(event, Action.cancel)


store = FileWorkStore(on_expired=_record_expiry)
