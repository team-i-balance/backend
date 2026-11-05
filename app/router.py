"""API routes for the logging / DB module.

Mounted under /logs in main.py.
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app import crud
from app.crypto import encrypt_records, public_key_fingerprint
from app.schemas import EventIn, EventOut, ExportResult, Stats

router = APIRouter(prefix="/logs", tags=["logs"])


def _validate_iso(value: Optional[str], field: str) -> None:
    """Reject malformed date filters so they can't silently mis-filter."""
    if value is None:
        return
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"{field} must be an ISO8601 datetime, got: {value!r}",
        )


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
):
    _validate_iso(start, "start")
    _validate_iso(end, "end")
    return crud.list_events(
        grade=grade, queue=queue, start=start, end=end, limit=limit
    )


@router.get("/queues/{name}", response_model=list[EventOut])
def get_queue(name: str, limit: int = Query(default=100, ge=1, le=1000)):
    return crud.list_events(queue=name, limit=limit)


@router.get("/stats", response_model=Stats)
def get_stats():
    return crud.get_stats()


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
