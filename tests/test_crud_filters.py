"""Lower-level tests for date filtering and DB transaction behavior.

These touch crud.list_events / db.get_conn directly so we can control
created_at timestamps (the API always stamps 'now').
"""
import sqlite3

import pytest


def _seed(created_at: str, request_id: str):
    """Insert a row with an explicit created_at."""
    from app.db import get_conn

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO event_log (created_at, request_id, grade, action,
                detected_types, detected_count, reverted, restored, queue)
            VALUES (?, ?, 'sensitive_S', 'send_transformed', '[]', 0, 0, 0,
                'pre_warning')
            """,
            (created_at, request_id),
        )


def test_date_range_filtering(client):
    # client fixture sets up the isolated DB/env for this test's imports.
    from app import crud

    _seed("2026-01-01T00:00:00+00:00", "jan")
    _seed("2026-06-01T00:00:00+00:00", "jun")
    _seed("2026-12-01T00:00:00+00:00", "dec")

    # start only
    rows = crud.list_events(start="2026-05-01T00:00:00+00:00")
    assert {r["request_id"] for r in rows} == {"jun", "dec"}

    # end only
    rows = crud.list_events(end="2026-05-01T00:00:00+00:00")
    assert {r["request_id"] for r in rows} == {"jan"}

    # both (window)
    rows = crud.list_events(
        start="2026-02-01T00:00:00+00:00", end="2026-07-01T00:00:00+00:00"
    )
    assert {r["request_id"] for r in rows} == {"jun"}


def test_date_bound_with_different_offset_compares_instants(client):
    # Regression (P2-1): a bound given in +02:00 must be compared as an instant,
    # not lexically against the stored +00:00 string.
    from app import crud

    _seed("2026-06-01T00:00:00+00:00", "evt")

    # 2026-06-01T01:00:00+02:00 == 2026-05-31T23:00:00Z, i.e. one hour BEFORE
    # the event. So the event must be included when used as a start bound.
    rows = crud.list_events(start="2026-06-01T01:00:00+02:00")
    assert {r["request_id"] for r in rows} == {"evt"}

    # 2026-06-01T01:00:00-02:00 == 2026-06-01T03:00:00Z, i.e. three hours AFTER
    # the event. As a start bound it must EXCLUDE the event.
    rows = crud.list_events(start="2026-06-01T01:00:00-02:00")
    assert rows == []


def test_date_bound_with_z_suffix(client):
    # Regression (P2-1): 'Z' suffix must be accepted and treated as UTC.
    from app import crud

    _seed("2026-06-01T12:00:00+00:00", "noon")

    rows = crud.list_events(start="2026-06-01T11:00:00Z")
    assert {r["request_id"] for r in rows} == {"noon"}

    rows = crud.list_events(end="2026-06-01T11:00:00Z")
    assert rows == []


def test_naive_date_bound_treated_as_utc(client):
    from app import crud

    _seed("2026-06-01T12:00:00+00:00", "noon")
    # No offset -> treated as UTC.
    rows = crud.list_events(start="2026-06-01T11:00:00")
    assert {r["request_id"] for r in rows} == {"noon"}


def test_get_conn_rolls_back_on_error(client):
    from app.db import get_conn

    # A failing statement inside the context must roll back and re-raise,
    # leaving no partial row behind.
    with pytest.raises(sqlite3.Error):
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO event_log (created_at, grade, action, queue)
                VALUES ('2026-01-01T00:00:00+00:00', 'sensitive_S',
                        'send_transformed', 'pre_warning')
                """
            )
            # Invalid SQL -> triggers rollback of the insert above.
            conn.execute("INSERT INTO nonexistent_table VALUES (1)")

    from app import crud

    assert crud.list_events() == []
