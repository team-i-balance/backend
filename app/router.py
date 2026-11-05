"""API routes for the logging / DB module.

Mounted under /logs in main.py.
"""
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app import crud
from app.crypto import encrypt_records, public_key_fingerprint
from app.log_time import parse_utc
from app.schemas import EventIn, EventOut, ExportResult, Stats

router = APIRouter(prefix="/logs", tags=["logs"])


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


@router.post("/events", response_model=EventOut, status_code=201)
def create_event(event: EventIn):
    """Ingest one runtime event. Classifies into a queue on insert."""
    return crud.insert_event(event)


@router.get("/events", response_model=list[EventOut])
def get_events(
    grade: Optional[str] = None,
    queue: Optional[str] = None,
    start: Optional[str] = Query(default=None, description="ISO8601 lower bound"),
    end: Optional[str] = Query(default=None, description="ISO8601 upper bound"),
    limit: int = Query(default=100, ge=1, le=1000),
    cursor: Optional[int] = Query(
        default=None, ge=1, le=2**63 - 1, description="Last event ID from the previous page",
    ),
):
    _validate_period(start, end)
    return crud.list_events(
        grade=grade, queue=queue, start=start, end=end, limit=limit, cursor=cursor
    )


@router.get("/queues/{name}", response_model=list[EventOut])
def get_queue(name: str, limit: int = Query(default=100, ge=1, le=1000)):
    return crud.list_events(queue=name, limit=limit)


@router.get("/stats", response_model=Stats)
def get_stats(
    start: Optional[str] = Query(default=None, description="Inclusive ISO8601 lower bound"),
    end: Optional[str] = Query(default=None, description="Inclusive ISO8601 upper bound"),
):
    _validate_period(start, end)
    return crud.get_stats(start=start, end=end)


@router.post("/export", response_model=ExportResult)
def export_logs(
    queue: Optional[str] = None,
    limit: int = Query(default=1000, ge=1, le=10000),
):
    """Encrypt matching logs with the security team public key and write a file."""
    records = crud.list_events(queue=queue, limit=limit)
    path = encrypt_records(records)
    return ExportResult(
        exported=len(records),
        file=str(path),
        public_key_fingerprint=public_key_fingerprint(),
    )
