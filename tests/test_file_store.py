"""Ownership, capacity and expiry of file bytes plus their restoration session."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import threading

import pytest


@pytest.fixture
def storage():
    # Import inside the fixture: API fixtures reload app modules between tests.
    from app import file_store
    from app.file_schemas import FileSummary
    from app.schemas import Grade

    return SimpleNamespace(module=file_store, summary=FileSummary(
        changed_cells=1, removed_comments=0, removed_sheets=0,
        removed_rows=0, removed_columns=0,
    ), grade=Grade.sensitive)


class Session:
    def __init__(self):
        self.closed = threading.Event()

    def close(self):
        self.closed.set()


def add(storage, store, work_id="one", data=b"protected"):
    session = Session()
    item = store.add(work_id=work_id, file_bytes=data, session=session,
                     grade=storage.grade, summary=storage.summary)
    return item, session


def test_take_transfers_live_session_once(storage):
    store = storage.module.FileWorkStore(max_items=1)
    item, session = add(storage, store)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(store.take, ["one", "one"]))
    assert sum(r is item for r in results) == 1
    assert sum(r is None for r in results) == 1
    store.close()
    assert not session.closed.is_set()  # Caller, not store, now owns it.
    item.close()
    assert session.closed.is_set() and item.file_bytes == b""


def test_expiry_does_not_extend_on_access(storage, monkeypatch):
    clock = SimpleNamespace(monotonic=lambda: 100.0)
    monkeypatch.setattr(storage.module, "time", clock)
    store = storage.module.FileWorkStore(ttl_seconds=10)
    item, session = add(storage, store)
    clock.monotonic = lambda: 109.0
    assert len(store) == 1
    clock.monotonic = lambda: 110.0
    assert store.take("one") is None
    assert session.closed.is_set() and item.file_bytes == b""


@pytest.mark.parametrize("limits", [{"max_items": 1}, {"max_bytes": 9}])
def test_capacity_rejects_new_without_evicting_existing(storage, limits):
    store = storage.module.FileWorkStore(**limits)
    item, session = add(storage, store)
    rejected = Session()
    with pytest.raises(storage.module.FileStoreFull):
        store.add(work_id="two", file_bytes=b"more", session=rejected,
                  grade=storage.grade, summary=storage.summary)
    assert not session.closed.is_set()
    assert not rejected.closed.is_set()  # A failed add never transfers ownership.
    assert store.take("one") is item
    item.close()
    rejected.close()
    # Taking releases both byte and count capacity.
    replacement, _ = add(storage, store, "two")
    store.close()
    assert replacement.file_bytes == b""


def test_duplicate_id_does_not_overwrite_mapping(storage):
    store = storage.module.FileWorkStore()
    item, _ = add(storage, store)
    with pytest.raises(ValueError):
        add(storage, store)
    assert store.take("one") is item
    item.close()


def test_background_expiry_without_further_requests(storage):
    store = storage.module.FileWorkStore(ttl_seconds=0.02, sweep_interval=0.01)
    item, session = add(storage, store)
    store.start()
    try:
        assert session.closed.wait(2)
        assert item.file_bytes == b""
    finally:
        store.close()


def test_shutdown_closes_all_and_refuses_late_publish(storage):
    store = storage.module.FileWorkStore()
    store.start()
    items = [add(storage, store, str(i)) for i in range(2)]
    store.close()
    assert all(s.closed.is_set() and item.file_bytes == b"" for item, s in items)
    assert not store._thread.is_alive()
    with pytest.raises(storage.module.FileStoreFull):
        add(storage, store, "late")


def test_expiry_uses_monotonic_clock(storage, monkeypatch):
    clock = SimpleNamespace(monotonic=lambda: 10.0)
    monkeypatch.setattr(storage.module, "time", clock)
    store = storage.module.FileWorkStore(ttl_seconds=600)
    item, session = add(storage, store)
    assert item.deadline == 610.0 and item.expires_at.tzinfo is not None
    clock.monotonic = lambda: 611.0
    assert store.take(item.work_id) is None
    assert session.closed.is_set()


def test_cleanup_continues_when_one_session_close_raises(storage):
    store = storage.module.FileWorkStore()
    first, _ = add(storage, store)
    second, session = add(storage, store, "two")

    def broken():
        raise RuntimeError("private")

    first.session.close = broken
    store.close()
    assert first.file_bytes == second.file_bytes == b""
    assert session.closed.is_set() and len(store) == 0
