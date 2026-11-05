"""Exact UTC boundaries for event-list and statistics queries."""
from datetime import date, datetime, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_utc(value: str) -> datetime:
    # Python 3.10's fromisoformat does not accept the Z suffix directly.
    has_z = value.endswith("Z")
    if has_z:
        value = value[:-1]
        try:
            date.fromisoformat(value)
        except ValueError:
            pass
        else:
            raise ValueError("Z requires a date and time")
    dt = datetime.fromisoformat(value)
    if has_z and dt.tzinfo is not None:
        raise ValueError("Z cannot be combined with another timezone offset")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def utc_microseconds(value: str) -> int:
    delta = parse_utc(value) - _EPOCH
    # Avoid float timestamps and SQLite datetime()'s truncation to seconds.
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def sql_utc_microseconds(value):
    try:
        return utc_microseconds(value)
    except (ValueError, TypeError, AttributeError, OverflowError):
        # Like SQLite datetime(), invalid historical timestamps don't match a
        # date range. Request boundaries are separately validated by the API.
        return None
