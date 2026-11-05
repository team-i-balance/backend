"""HTTP integration with real LocalSession/mapping and a deterministic detector."""
import asyncio
from datetime import date
from io import BytesIO
import re
import threading
from types import SimpleNamespace
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import httpx
from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment
import pytest

from local_ai.detector import Detector
from local_ai.pipeline import LocalSession


class DeterministicDetector:
    model_enabled = True  # Test double; never used by the application provider.

    def __init__(self):
        self.rules = Detector(None)

    def detect(self, text):
        names = [dict(start=m.start(), end=m.end(), type="NAME")
                 for m in re.finditer("김민수|박영희", text)]
        return self.rules.detect(text) + names


def workbook_bytes(edit=None):
    book = Workbook(iso_dates=True)
    sheet = book.active
    sheet.append(["고객", "수량", "금액", "일자", "메모"])
    sheet.append(["김민수", 2, 39000, date(2026, 1, 2), "김민수 요청 확인"])
    sheet.append(["박영희", 5, 12500])
    sheet["A2"].comment = Comment("제거할 메모", "김민수")
    sheet["F2"] = "숨김열표식"
    sheet.column_dimensions["F"].hidden = True
    hidden = book.create_sheet("숨김시트")
    hidden.sheet_state = "hidden"
    hidden["A1"] = "제거할숨김값"
    book.properties.creator = "김민수"
    if edit:
        edit(book)
    stream = BytesIO()
    book.save(stream)
    book.close()
    return stream.getvalue()


@pytest.fixture
def api(client, monkeypatch):
    from app import file_router, file_service

    sessions = []

    class TrackedSession(LocalSession):
        def __init__(self, detector):
            super().__init__(detector)
            self.closed = threading.Event()
            sessions.append(self)

        def close(self):
            super().close()
            self.closed.set()

    detector = DeterministicDetector()
    monkeypatch.setattr(file_service, "get_detector", lambda _: detector)
    monkeypatch.setattr(file_service, "LocalSession", TrackedSession)
    return SimpleNamespace(client=client, router=file_router, service=file_service,
                           store=file_router.store, sessions=sessions, detector=detector)


def upload(api, data=None, filename="입력.xlsx"):
    return api.client.post("/files/sanitize", files={
        "file": (filename, workbook_bytes() if data is None else data,
                 "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    })


def assert_failure(api, response, code, reason):
    assert response.status_code == code
    body = response.json()
    assert body["status"] == "FAILED"
    assert body["reason"] == reason
    assert body["summary"] is None and body["expires_at"] is None
    assert response.headers["cache-control"] == "no-store"
    assert api.store.take(body["work_id"]) is None
    assert all(s.closed.is_set() for s in api.sessions)


def test_upload_copy_and_live_mapping(api):
    response = upload(api, filename="김민수_원본.xlsx")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "READY"
    assert body["grade"] == "sensitive_S"
    assert body["expires_at"] is not None
    assert body["summary"]["removed_comments"] == 1
    assert body["summary"]["removed_sheets"] == 1
    assert body["summary"]["removed_columns"] == 1
    assert response.headers["cache-control"] == "no-store"
    assert "김민수" not in response.text and "입력.xlsx" not in response.text
    item = api.store.take(body["work_id"])
    assert item is not None and api.store.take(body["work_id"]) is None
    try:
        book = load_workbook(BytesIO(item.file_bytes))
        sheet = book.active
        first, second = sheet["A2"].value, sheet["A3"].value
        assert first != second and first in sheet["E2"].value
        assert (sheet["B2"].value, sheet["C2"].value) == (2, 39000)
        assert sheet["D2"].value == date(2026, 1, 2)
        assert sheet["A2"].comment is None and sheet["F2"].value is None
        # openpyxl supplies its default creator when loading an absent element.
        assert book.properties.creator != "김민수"
        assert book.sheetnames == ["시트1"]
        book.close()
        restored = item.session.restore(f"{first}와 {second}에게 안내")
        assert restored.text == "김민수와 박영희에게 안내"
        assert restored.unknown == () and restored.blocked == ()
        with ZipFile(BytesIO(item.file_bytes)) as zipped:
            core = ET.fromstring(zipped.read("docProps/core.xml"))
            assert core.find("{http://purl.org/dc/elements/1.1/}creator") is None
            strings = []
            for name in zipped.namelist():
                tree = ET.fromstring(zipped.read(name))
                strings.extend(tree.itertext())
                strings.extend(v for node in tree.iter() for v in node.attrib.values())
            xml = "\n".join(strings)
            for private in ("김민수", "박영희", "숨김열표식", "제거할숨김값", "제거할 메모"):
                assert private not in xml
    finally:
        item.close()
    assert item.file_bytes == b"" and api.sessions[0].closed.is_set()


def test_public_file_is_ready(api):
    book = Workbook()
    book.active["A1"] = 42
    stream = BytesIO()
    book.save(stream)
    response = upload(api, stream.getvalue())
    assert response.json()["grade"] == "public_O"
    assert response.json()["status"] == "READY"


@pytest.mark.parametrize("location", ["cell", "hidden", "comment", "author", "filename"])
def test_shared_secret_policy_blocks_whole_file(api, location):
    secret = "API_KEY=TEST_KEY_1234567890"

    def edit(book):
        if location == "cell":
            book.active["E2"] = secret
        elif location == "hidden":
            book["숨김시트"]["A1"] = secret
        elif location == "comment":
            book.active["A2"].comment = Comment(secret, "author")
        elif location == "author":
            book.properties.creator = secret

    response = upload(api, workbook_bytes(edit), secret + ".xlsx" if location == "filename" else "입력.xlsx")
    assert response.status_code == 200
    body = response.json()
    assert (body["status"], body["grade"], body["reason"]) == (
        "BLOCKED", "confidential_C", "CONFIDENTIAL",
    )
    assert body["summary"] is None and body["expires_at"] is None
    assert "TEST_KEY" not in response.text
    assert len(api.store) == 0 and api.sessions[0].closed.is_set()


@pytest.mark.parametrize("filename", ["book.xls", "book.xlsm", "book.pdf"])
def test_unsupported_extension(api, filename):
    assert_failure(api, upload(api, filename=filename), 415, "UNSUPPORTED_FILE_TYPE")


@pytest.mark.parametrize("data", [b"", b"not an xlsx", b"PK\x03\x04broken"])
def test_corrupt_upload(api, data):
    assert_failure(api, upload(api, data), 422, "INVALID_XLSX")


def test_formula_rejected(api):
    data = workbook_bytes(lambda b: setattr(b.active["B2"], "value", "=1+1"))
    assert_failure(api, upload(api, data), 422, "UNSUPPORTED_FEATURE")


def test_one_file_and_no_other_fields(api):
    for fields in (
        [("file", ("a.xlsx", b"one")), ("file", ("b.xlsx", b"two"))],
        [("file", ("a.xlsx", b"one")), ("text", (None, "김민수"))],
    ):
        response = api.client.post("/files/sanitize", files=fields)
        assert_failure(api, response, 422, "INVALID_MULTIPART")
    response = api.client.post("/files/sanitize", files={"other": ("a.xlsx", b"one")})
    assert_failure(api, response, 422, "EXPECTED_ONE_FILE")
    response = api.client.post("/files/sanitize", json={"file": "x"})
    assert_failure(api, response, 415, "EXPECTED_MULTIPART")


@pytest.mark.parametrize("length,code,reason", [
    (8 * 1024 * 1024, 422, "INVALID_XLSX"),
    (8 * 1024 * 1024 + 1, 413, "FILE_TOO_LARGE"),
    (9 * 1024 * 1024 + 1, 413, "FILE_TOO_LARGE"),
])
def test_upload_size_boundaries(api, length, code, reason):
    assert_failure(api, upload(api, b"x" * length), code, reason)


def test_no_content_length_still_bounded_and_spool_closed(api, monkeypatch):
    import starlette.formparsers as parsers

    opened = []
    original = parsers.SpooledTemporaryFile

    def tracked(*args, **kwargs):
        item = original(*args, **kwargs)
        opened.append(item)
        return item

    monkeypatch.setattr(parsers, "SpooledTemporaryFile", tracked)

    async def run():
        async def chunks():
            yield b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="a.xlsx"\r\n\r\n'
            for _ in range(10):
                yield b"x" * (1024 * 1024)
            yield b"\r\n--boundary--\r\n"

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.client.app), base_url="http://test") as c:
            return await c.post("/files/sanitize", content=chunks(), headers={
                "Content-Type": "multipart/form-data; boundary=boundary",
            })

    assert_failure(api, asyncio.run(run()), 413, "FILE_TOO_LARGE")
    assert opened and all(f.closed for f in opened)
    assert upload(api).json()["status"] == "READY"


def test_model_configuration_required(api, monkeypatch):
    from app.detectors import get_detector, reset_detectors

    reset_detectors()
    monkeypatch.setattr(api.service, "get_detector", get_detector)
    monkeypatch.delenv("LOCAL_PII_MODEL_DIR", raising=False)
    assert_failure(api, upload(api), 503, "MODEL_UNAVAILABLE")
    monkeypatch.setenv("LOCAL_PII_MODEL_DIR", "/missing/model/private-path")
    response = upload(api)
    assert_failure(api, response, 503, "MODEL_UNAVAILABLE")
    assert "private-path" not in response.text


def test_rules_only_not_silently_used(api, monkeypatch):
    monkeypatch.setattr(api.service, "get_detector", lambda _: Detector(None))
    assert_failure(api, upload(api), 503, "MODEL_UNAVAILABLE")


def test_processing_failure_closes_mapping_without_leaking_error(api, monkeypatch):
    def broken(_):
        raise RuntimeError("private original 김민수")

    monkeypatch.setattr(api.detector, "detect", broken)
    response = upload(api)
    assert_failure(api, response, 500, "PROCESSOR_ERROR")
    assert "김민수" not in response.text


def test_residual_check_fails_closed(api, monkeypatch):
    original = api.detector.detect

    def residual(text):
        if "[이름_" in text:
            return [dict(start=0, end=len(text), type="NAME")]
        return original(text)

    monkeypatch.setattr(api.detector, "detect", residual)
    assert_failure(api, upload(api), 422, "RESIDUAL_CHECK_FAILED")


def test_store_full_closes_new_session(api, monkeypatch):
    from app.file_store import FileWorkStore

    monkeypatch.setattr(api.router, "store", FileWorkStore(max_bytes=1))
    assert_failure(api, upload(api), 503, "FILE_STORE_FULL")


def test_two_files_keep_separate_mappings(api):
    def change(book):
        book.properties.creator = None
        book.active["A2"].comment = None
        book.active["A2"] = "박영희"
        book.active["A3"] = "김민수"

    ids = [upload(api).json()["work_id"], upload(api, workbook_bytes(change)).json()["work_id"]]
    assert ids[0] != ids[1]
    items = [api.store.take(work_id) for work_id in ids]
    try:
        assert items[0].session.restore("[이름_1]").text == "김민수"
        assert items[1].session.restore("[이름_1]").text == "박영희"
    finally:
        for item in items:
            item.close()


def test_cancelled_worker_keeps_slot_until_it_finishes(api, monkeypatch):
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = api.service.sanitize_xlsx

    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    original_run = api.service.FileProcessingJob.run

    def tracked_run(self, *args):
        try:
            return original_run(self, *args)
        finally:
            finished.set()

    monkeypatch.setattr(api.service, "sanitize_xlsx", slow)
    monkeypatch.setattr(api.service.FileProcessingJob, "run", tracked_run)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.client.app), base_url="http://test") as c:
            first = asyncio.create_task(c.post("/files/sanitize", files={"file": ("a.xlsx", workbook_bytes())}))
            try:
                assert await asyncio.to_thread(entered.wait, 5)
                busy = await c.post("/files/sanitize", content=b"not parsed")
                assert busy.status_code == 429
                first.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await first
                busy = await c.post("/files/sanitize", content=b"not parsed")
                assert busy.status_code == 429
            finally:
                release.set()
                assert await asyncio.to_thread(finished.wait, 5)

    asyncio.run(run())
    assert len(api.store) == 0 and api.sessions[0].closed.is_set()
    assert upload(api).json()["status"] == "READY"


def test_openapi_exposes_only_upload(api):
    schema = api.client.get("/openapi.json").json()
    routes = [p for p in schema["paths"] if p.startswith("/files")]
    assert routes == ["/files/sanitize"]
    body = schema["paths"][routes[0]]["post"]["requestBody"]
    assert body["required"]
    assert body["content"]["multipart/form-data"]["schema"]["required"] == ["file"]


@pytest.mark.parametrize("interrupt", ["disconnect", "cancel", "parser_error"])
def test_partial_upload_always_closes_spool(api, monkeypatch, interrupt):
    import starlette.formparsers as parsers
    from starlette.requests import ClientDisconnect

    opened = []
    original = parsers.SpooledTemporaryFile

    def tracked(*args, **kwargs):
        item = original(*args, **kwargs)
        opened.append(item)
        return item

    monkeypatch.setattr(parsers, "SpooledTemporaryFile", tracked)

    async def run():
        waiting = asyncio.Event()
        pieces = [
            b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="a.xlsx"\r\n\r\n',
            b"x" * (2 * 1024 * 1024),
        ]

        async def receive():
            if pieces:
                return {"type": "http.request", "body": pieces.pop(0), "more_body": True}
            waiting.set()
            if interrupt == "disconnect":
                return {"type": "http.disconnect"}
            if interrupt == "parser_error":
                return {"type": "http.request", "body": b"\r\n--boundary\r\ninvalid header\r\n", "more_body": False}
            await asyncio.Future()

        async def send(message):
            pass

        scope = dict(type="http", asgi={"version": "3.0"}, http_version="1.1",
                     method="POST", scheme="http", path="/files/sanitize",
                     raw_path=b"/files/sanitize", query_string=b"", root_path="",
                     headers=[(b"content-type", b"multipart/form-data; boundary=boundary")],
                     client=("test", 1), server=("test", 80))
        task = asyncio.create_task(api.client.app(scope, receive, send))
        await asyncio.wait_for(waiting.wait(), 5)
        if interrupt == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif interrupt == "disconnect":
            with pytest.raises(ClientDisconnect):
                await task
        else:
            await task

    asyncio.run(run())
    assert opened and all(f.closed for f in opened)
    assert len(api.store) == 0
    assert upload(api).json()["status"] == "READY"


def test_disconnect_after_processing_discards_published_work(api):
    async def run():
        request = httpx.Request("POST", "http://test/files/sanitize", files={
            "file": ("input.xlsx", workbook_bytes()),
        })
        data = request.read()
        messages = [{"type": "http.request", "body": data, "more_body": False}]

        async def receive():
            return messages.pop(0) if messages else {"type": "http.disconnect"}

        async def send(message):
            pass

        scope = dict(type="http", asgi={"version": "3.0"}, http_version="1.1",
                     method="POST", scheme="http", path="/files/sanitize",
                     raw_path=b"/files/sanitize", query_string=b"", root_path="",
                     headers=[(k.lower(), v) for k, v in request.headers.raw],
                     client=("test", 1), server=("test", 80))
        await api.client.app(scope, receive, send)

    asyncio.run(run())
    assert len(api.store) == 0
    assert api.sessions[0].closed.is_set()


def test_cancel_before_worker_starts_releases_admission_slot(api):
    from app.file_service import FileProcessingJob

    slot = threading.BoundedSemaphore(1)
    assert slot.acquire(blocking=False)
    job = FileProcessingJob(api.store, slot)
    job.cancel()
    assert job.run(workbook_bytes(), "a.xlsx")[1].reason == "PROCESSING_CANCELLED"
    assert slot.acquire(blocking=False)
    assert len(api.store) == 0 and not api.sessions
    slot.release()
