"""Tests for the in-memory work-item store (app/sessions.py)."""
import time

from app.sessions import SessionStore


class FakeSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _add(store, **over):
    kwargs = dict(
        session=FakeSession(),
        original_text="orig",
        masked_text="masked",
        detected_types=("NAME",),
        detected_count=1,
        grade="sensitive_S",
        detection_confidence="low",
        remaining_count=0,
    )
    kwargs.update(over)
    return store.add(**kwargs)


def test_add_and_get():
    store = SessionStore()
    item = _add(store)
    assert store.get(item.work_id) is item
    assert len(store) == 1


def test_work_ids_unique():
    store = SessionStore()
    ids = {_add(store).work_id for _ in range(50)}
    assert len(ids) == 50


def test_pop_removes_without_closing():
    store = SessionStore()
    item = _add(store)
    popped = store.pop(item.work_id)
    assert popped is item
    assert item.session.closed is False  # caller owns cleanup
    assert store.get(item.work_id) is None


def test_discard_closes_session():
    store = SessionStore()
    item = _add(store)
    store.discard(item.work_id)
    assert item.session.closed is True
    assert store.get(item.work_id) is None


def test_ttl_expiry_closes_and_removes():
    store = SessionStore(ttl_seconds=0)  # everything is immediately stale
    item = _add(store)
    time.sleep(0.01)
    assert store.get(item.work_id) is None
    assert item.session.closed is True


def test_discard_swallows_close_errors():
    # Cleanup must be best-effort: a failing close() must not propagate.
    class BadSession:
        def close(self):
            raise RuntimeError("close failed")

    store = SessionStore()
    item = _add(store, session=BadSession())
    store.discard(item.work_id)  # must not raise
    assert store.get(item.work_id) is None


def test_background_sweeper_expires_without_other_calls():
    # Regression (P2-E): an abandoned item must be discarded by the sweeper
    # even if no further add/get/pop happens.
    store = SessionStore(ttl_seconds=0, sweep_interval=0.02)
    item = _add(store)
    store.start_sweeper()
    try:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if item.session.closed:
                break
            time.sleep(0.02)
        assert item.session.closed is True
        assert len(store) == 0
    finally:
        store.stop_sweeper()


def test_start_sweeper_is_idempotent():
    store = SessionStore(sweep_interval=0.05)
    store.start_sweeper()
    first = store._sweeper
    store.start_sweeper()  # must not start a second thread
    assert store._sweeper is first
    store.stop_sweeper()


def test_put_reinserts_existing_item():
    store = SessionStore()
    item = _add(store)
    popped = store.pop(item.work_id)
    store.put(popped)
    assert store.get(item.work_id) is popped


def test_put_evicts_oldest_when_full():
    store = SessionStore(max_items=1)
    first = _add(store)
    # Build a second, distinct item and put() it while at capacity.
    import time as _t
    from app.sessions import WorkItem

    second = WorkItem(
        work_id="second",
        session=FakeSession(),
        original_text="o",
        masked_text="m",
        detected_types=("NAME",),
        detected_count=1,
        grade="sensitive_S",
        detection_confidence="low",
        remaining_count=0,
        created_at=_t.monotonic() + 1,
    )
    store.put(second)
    assert store.get(first.work_id) is None  # oldest evicted
    assert first.session.closed is True
    assert store.get("second") is second


def test_capacity_evicts_oldest():
    store = SessionStore(max_items=3)
    items = [_add(store) for _ in range(3)]
    # Adding a 4th evicts the oldest (items[0]).
    newest = _add(store)
    assert store.get(items[0].work_id) is None
    assert items[0].session.closed is True
    assert store.get(newest.work_id) is newest
    assert len(store) == 3
