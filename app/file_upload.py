"""Bounded multipart ingestion, including cleanup on disconnect/cancellation."""
from fastapi import Request
from python_multipart.exceptions import MultipartParseError
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from file_sanitizer.package import MAX_UPLOAD

MAX_REQUEST = 9 * 1024 * 1024


class FileRequestError(Exception):
    def __init__(self, status_code: int, reason: str):
        self.status_code = status_code
        self.reason = reason


async def read_upload(request: Request) -> tuple[bytes, str]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "multipart/form-data":
        raise FileRequestError(415, "EXPECTED_MULTIPART")
    length = request.headers.get("content-length")
    if length is not None:
        try:
            size = int(length)
        except ValueError:
            raise FileRequestError(422, "INVALID_MULTIPART") from None
        if size < 0:
            raise FileRequestError(422, "INVALID_MULTIPART")
        if size > MAX_REQUEST:
            raise FileRequestError(413, "FILE_TOO_LARGE")

    async def bounded_stream():
        received = 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > MAX_REQUEST:
                raise FileRequestError(413, "FILE_TOO_LARGE")
            yield chunk

    parser = MultiPartParser(
        request.headers, bounded_stream(), max_files=1, max_fields=0,
    )
    try:
        form = await parser.parse()
        parts = form.multi_items()
        if (len(parts) != 1 or parts[0][0] != "file"
                or not isinstance(parts[0][1], UploadFile)):
            raise FileRequestError(422, "EXPECTED_ONE_FILE")
        upload = parts[0][1]
        if not upload.filename or not upload.filename.lower().endswith(".xlsx"):
            raise FileRequestError(415, "UNSUPPORTED_FILE_TYPE")
        data = await upload.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            raise FileRequestError(413, "FILE_TOO_LARGE")
        if not data:
            raise FileRequestError(422, "INVALID_XLSX")
        return data, upload.filename
    except (MultiPartException, MultipartParseError, UnicodeError, ValueError):
        raise FileRequestError(422, "INVALID_MULTIPART") from None
    finally:
        # Starlette 0.40/0.41 only closes these on MultiPartException. Also close
        # partially parsed spools on a body limit, disconnect, or cancellation.
        # Keep this version-specific access here and cover it with API tests.
        for temporary_file in parser._files_to_close_on_error:
            temporary_file.close()
