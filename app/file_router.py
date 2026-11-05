"""Prepare one XLSX for future server-side AI delivery; metadata response only."""
import threading
from uuid import uuid4

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from starlette.responses import JSONResponse

from app.file_schemas import FileResult
from app.file_service import FileProcessingJob
from app.file_store import store
from app.file_upload import FileRequestError, read_upload

router = APIRouter(prefix="/files", tags=["files"])
_processing_slot = threading.BoundedSemaphore(1)


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
