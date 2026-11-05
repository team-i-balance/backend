"""API routes for the logging / DB module.

Mounted under /logs in main.py.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app import crud
from app.auth import require_api, require_security
from app.crypto import encrypt_records, public_key_fingerprint
from app.log_time import parse_utc
from app.schemas import EventIn, EventOut, ExportResult, Stats

router = APIRouter(prefix="/logs", tags=["logs"])

_INCLUDE_TEST = Query(
    default=False,
    description="Include integration-test events (test=true). Default: excluded.",
)


def _validate_period(start: Optional[str], end: Optional[str]) -> None:
    bounds = {}
    for field, value in (("start", start), ("end", end)):
        if value is None:
            continue
        try:
            bounds[field] = parse_utc(value)
        except (ValueError, OverflowError) as exc:
            raise HTTPException(
                status_code=400, detail=f"{field} must be a valid ISO8601 datetime",
            ) from exc
    if start is not None and end is not None and bounds["start"] > bounds["end"]:
        raise HTTPException(status_code=400, detail="start must be earlier than or equal to end")


@router.post(
    "/events", response_model=EventOut, status_code=201,
    dependencies=[Depends(require_api)],
)
def create_event(event: EventIn):
    """Ingest one runtime event. Classifies into a queue on insert."""
    return crud.insert_event(event)


@router.get(
    "/events", response_model=list[EventOut],
    dependencies=[Depends(require_security)],
)
def get_events(
    grade: Optional[str] = None,
    queue: Optional[str] = None,
    start: Optional[str] = Query(default=None, description="ISO8601 lower bound"),
    end: Optional[str] = Query(default=None, description="ISO8601 upper bound"),
    limit: int = Query(default=100, ge=1, le=1000),
    include_test: bool = _INCLUDE_TEST,
    cursor: Optional[int] = Query(
        default=None, ge=1, le=2**63 - 1, description="Last event ID from the previous page",
    ),
):
    _validate_period(start, end)
    return crud.list_events(
        grade=grade, queue=queue, start=start, end=end, limit=limit, cursor=cursor,
        include_test=include_test,
    )


@router.get(
    "/queues/{name}", response_model=list[EventOut],
    dependencies=[Depends(require_security)],
)
def get_queue(
    name: str,
    limit: int = Query(default=100, ge=1, le=1000),
    include_test: bool = _INCLUDE_TEST,
):
    return crud.list_events(queue=name, limit=limit, include_test=include_test)


@router.get("/stats", response_model=Stats, dependencies=[Depends(require_security)])
def get_stats(
    start: Optional[str] = Query(default=None, description="Inclusive ISO8601 lower bound"),
    end: Optional[str] = Query(default=None, description="Inclusive ISO8601 upper bound"),
    include_test: bool = _INCLUDE_TEST,
):
    _validate_period(start, end)
    return crud.get_stats(start=start, end=end, include_test=include_test)


@router.post(
    "/export", response_model=ExportResult,
    dependencies=[Depends(require_security)],
)
def export_logs(
    queue: Optional[str] = None,
    start: Optional[str] = Query(default=None, description="Inclusive ISO8601 lower bound"),
    end: Optional[str] = Query(default=None, description="Inclusive ISO8601 upper bound"),
    limit: int = Query(default=1000, ge=1, le=10000),
    include_test: bool = _INCLUDE_TEST,
    cursor: Optional[int] = Query(
        default=None, ge=1, le=2**63 - 1,
        description="next_cursor from the previous export (same as /logs/events cursor)",
    ),
):
    """Encrypt matching logs with the security team public key and write a file.

    Pages newest-first by ID like GET /logs/events. When more rows match,
    next_cursor is the last exported ID; pass it back as cursor.
    """
    _validate_period(start, end)
    records = crud.list_events(
        queue=queue, start=start, end=end, limit=limit + 1, cursor=cursor,
        include_test=include_test,
    )
    next_cursor = None
    if len(records) > limit:
        records = records[:limit]
        next_cursor = records[-1]["id"]
    path = encrypt_records(records)
    return ExportResult(
        exported=len(records),
        file=str(path),
        public_key_fingerprint=public_key_fingerprint(),
        next_cursor=next_cursor,
    )
