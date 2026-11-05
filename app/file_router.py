"""Prepare an XLSX, let its caller download the protected copy once, and restore replies."""
import threading
from urllib.parse import quote
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from starlette.responses import JSONResponse, Response

from app import file_events
from app.file_schemas import FileRestoreIn, FileResult
from app.file_service import FileProcessingJob
from app.file_store import store
from app.file_upload import FileRequestError, read_upload
from app.schemas import Action, RestoreOut

router = APIRouter(prefix="/files", tags=["files"])
_processing_slot = threading.BoundedSemaphore(1)
XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_DETAIL = {
    "type": "object", "properties": {"detail": {"type": "string"}}, "required": ["detail"],
}


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
            "content": {"application/json": {"schema": _DETAIL}},
        },
        500: {
            "description": "EVENT_LOG_FAILED: the copy was claimed but not logged, so not sent.",
            "content": {"application/json": {"schema": _DETAIL}},
        },
    },
)
def download_file(work_id: str):
    """The opaque work_id grants access until token ownership is implemented (#10)."""
    claimed = store.take_download(work_id)
    if claimed is None:
        raise HTTPException(
            status_code=404, detail="FILE_NOT_AVAILABLE", headers={"Cache-Control": "no-store"},
        )
    if claimed.event is not None:
        # Like /process/decide, hand the copy out only once its event is stored (#32).
        try:
            file_events.record(claimed.event, Action.send_transformed)
        except Exception:
            raise HTTPException(
                status_code=500, detail="EVENT_LOG_FAILED",
                headers={"Cache-Control": "no-store"},
            ) from None
    return Response(
        claimed.data,
        media_type=XLSX_MEDIA_TYPE,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (
                'attachment; filename="protected.xlsx"; '
                f"filename*=UTF-8''{quote('보호본.xlsx')}"
            ),
        },
    )


@router.post(
    "/{work_id}/restore",
    response_model=RestoreOut,
    responses={404: {
        "description": "Unknown, expired, blocked or failed work_id.",
        "content": {"application/json": {"schema": _DETAIL}},
    }},
)
def restore_reply(work_id: str, body: FileRestoreIn, response: Response):
    """Restore an AI reply with this file's mapping, as often as needed until it expires.

    Placeholders of questions sent with file_work_id are restored too. Secret
    placeholders (keys, tokens, passwords) stay masked, as in /process/restore.
    Like download, the opaque work_id grants access until #10.
    """
    result = store.restore(work_id, body.text)
    if result is None:
        raise HTTPException(
            status_code=404, detail="FILE_NOT_AVAILABLE", headers={"Cache-Control": "no-store"},
        )
    response.headers["Cache-Control"] = "no-store"  # The reply now holds original values.
    return RestoreOut(text=result.text, unknown=list(result.unknown), blocked=list(result.blocked))
