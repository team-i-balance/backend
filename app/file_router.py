"""Prepare an XLSX and let its caller download the protected copy once."""
import threading
from urllib.parse import quote
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from starlette.responses import JSONResponse, Response

from app.file_schemas import FileResult
from app.file_service import FileProcessingJob
from app.file_store import store
from app.file_upload import FileRequestError, read_upload

router = APIRouter(prefix="/files", tags=["files"])
_processing_slot = threading.BoundedSemaphore(1)
XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _response(code: int, result: FileResult):
    headers = {"Cache-Control": "no-store"}
    if code == 429:
        headers["Retry-After"] = "1"
    return JSONResponse(result.model_dump(mode="json"), status_code=code, headers=headers)


@router.post(
    "/sanitize",
    response_model=FileResult,
    responses={code: {"model": FileResult} for code in (413, 415, 422, 429, 500, 503)},
    openapi_extra={"requestBody": {"required": True, "content": {
        "multipart/form-data": {"schema": {
            "type": "object", "required": ["file"], "additionalProperties": False,
            "properties": {"file": {"type": "string", "format": "binary"}},
        }},
    }}},
)
async def sanitize_file(request: Request):
    """Upload one XLSX (8 MiB max). READY retains its protected copy for 10 minutes."""
    if not _processing_slot.acquire(blocking=False):
        return _response(429, FileResult(
            work_id=uuid4().hex, status="FAILED", reason="FILE_PROCESSING_BUSY",
        ))
    job = FileProcessingJob(store, _processing_slot)
    try:
        data, filename = await read_upload(request)
        code, result = await run_in_threadpool(job.run, data, filename)
        if await request.is_disconnected():
            job.cancel()
        return _response(code, result)
    except FileRequestError as exc:
        job.cancel()
        return _response(*job.failure(exc.status_code, exc.reason))
    except ClientDisconnect:
        job.cancel()
        raise
    except Exception:
        job.cancel()
        return _response(*job.failure(500, "PROCESSING_ERROR"))
    except BaseException:
        job.cancel()
        raise


@router.get(
    "/{work_id}/download",
    response_class=Response,
    responses={
        200: {
            "description": "One-time protected XLSX download; restoration mapping remains until expiry.",
            "content": {XLSX_MEDIA_TYPE: {"schema": {"type": "string", "format": "binary"}}},
        },
        404: {
            "description": "Unknown, expired or already downloaded work_id.",
            "content": {"application/json": {"schema": {
                "type": "object", "properties": {"detail": {"type": "string"}},
                "required": ["detail"],
            }}},
        },
    },
)
def download_file(work_id: str):
    """The opaque work_id grants access until token ownership is implemented (#10)."""
    data = store.take_download(work_id)
    if data is None:
        raise HTTPException(
            status_code=404, detail="FILE_NOT_AVAILABLE", headers={"Cache-Control": "no-store"},
        )
    return Response(
        data,
        media_type=XLSX_MEDIA_TYPE,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (
                'attachment; filename="protected.xlsx"; '
                f"filename*=UTF-8''{quote('보호본.xlsx')}"
            ),
        },
    )
