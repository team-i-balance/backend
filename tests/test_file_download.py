"""Upload -> binary download, one-time access, and retained restoration mapping."""
import asyncio
from io import BytesIO
from types import SimpleNamespace
from urllib.parse import quote

import httpx
from openpyxl import load_workbook
import pytest

from tests.test_file_api import api, upload, workbook_bytes

XLSX_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def assert_unavailable(response):
    assert response.status_code == 404
    assert response.json() == {"detail": "FILE_NOT_AVAILABLE"}
    assert response.headers["cache-control"] == "no-store"
    assert "content-disposition" not in response.headers


def test_download_returns_protected_xlsx_and_keeps_mapping(api):
    result = upload(api, filename="김민수_고객명단.xlsx").json()
    response = api.client.get(
        f"/files/{result['work_id']}/download", headers={"Origin": "http://client.test"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == XLSX_TYPE
    assert response.headers["cache-control"] == "no-store"
    assert int(response.headers["content-length"]) == len(response.content)
    assert response.headers["content-disposition"] == (
        'attachment; filename="protected.xlsx"; '
        f"filename*=UTF-8''{quote('보호본.xlsx')}"
    )
    assert "Content-Disposition" in response.headers["access-control-expose-headers"]
    assert "고객명단" not in str(response.headers)
    assert response.content.startswith(b"PK")
    book = load_workbook(BytesIO(response.content))
    first = book.active["A2"].value
    second = book.active["A3"].value
    assert first != "김민수" and second != "박영희" and first != second
    assert first in book.active["E2"].value
    assert (book.active["B2"].value, book.active["C2"].value) == (2, 39000)
    assert book.sheetnames == ["시트1"]
    assert book.active["A2"].comment is None
    book.close()

    assert_unavailable(api.client.get(f"/files/{result['work_id']}/download"))
    assert not api.sessions[0].closed.is_set()
    item = api.store.take(result["work_id"])
    try:
        assert item.downloaded and item.file_bytes == b""
        assert item.session.restore(f"{first}와 {second}").text == "김민수와 박영희"
        # Downloading must not extend the original expiry.
        assert item.expires_at.isoformat().replace("+00:00", "Z") == result["expires_at"]
    finally:
        item.close()


@pytest.mark.parametrize("work_id", ["0" * 32, "unknown-work"])
def test_unknown_id_cannot_consume_another_work(api, work_id):
    valid = upload(api).json()["work_id"]
    assert_unavailable(api.client.get(f"/files/{work_id}/download"))
    assert api.client.get(f"/files/{valid}/download").status_code == 200


@pytest.mark.parametrize("source,status", [
    (b"broken xlsx", "FAILED"),
    (None, "BLOCKED"),
])
def test_failed_or_blocked_work_has_no_download(api, source, status):
    if source is None:
        source = workbook_bytes(lambda b: setattr(
            b["숨김시트"]["A1"], "value", "API_KEY=TEST_KEY_1234567890",
        ))
    result = upload(api, data=source).json()
    assert result["status"] == status
    assert_unavailable(api.client.get(f"/files/{result['work_id']}/download"))
    assert len(api.store) == 0


@pytest.mark.parametrize("already_downloaded", [False, True])
def test_expiry_prevents_download_and_closes_mapping(api, monkeypatch, already_downloaded):
    from app import file_store

    now = [100.0]
    monkeypatch.setattr(file_store, "time", SimpleNamespace(monotonic=lambda: now[0]))
    work_id = upload(api).json()["work_id"]
    if already_downloaded:
        assert api.client.get(f"/files/{work_id}/download").status_code == 200
        assert not api.sessions[0].closed.is_set()
    now[0] += 600
    assert_unavailable(api.client.get(f"/files/{work_id}/download"))
    assert api.sessions[0].closed.is_set() and len(api.store) == 0


def test_concurrent_download_requests_have_only_one_winner(api):
    work_id = upload(api).json()["work_id"]

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api.client.app), base_url="http://test",
        ) as client:
            return await asyncio.gather(*[
                client.get(f"/files/{work_id}/download") for _ in range(2)
            ])

    responses = asyncio.run(run())
    assert sorted(r.status_code for r in responses) == [200, 404]
    assert next(r for r in responses if r.status_code == 200).content.startswith(b"PK")
    assert not api.sessions[0].closed.is_set()


def test_head_does_not_consume_download(api):
    work_id = upload(api).json()["work_id"]
    assert api.client.head(f"/files/{work_id}/download").status_code == 405
    assert api.client.get(f"/files/{work_id}/download").status_code == 200


def test_internal_take_before_download_remains_exclusive(api):
    work_id = upload(api).json()["work_id"]
    item = api.store.take(work_id)
    try:
        assert not item.downloaded and item.file_bytes.startswith(b"PK")
        assert_unavailable(api.client.get(f"/files/{work_id}/download"))
        assert not api.sessions[0].closed.is_set()
    finally:
        item.close()


def test_interrupted_transfer_stays_consumed_but_mapping_survives(api):
    work_id = upload(api).json()["work_id"]

    async def run():
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            if message["type"] == "http.response.body":
                raise RuntimeError("connection lost")

        path = f"/files/{work_id}/download"
        scope = dict(type="http", asgi={"version": "3.0"}, http_version="1.1",
                     method="GET", scheme="http", path=path, raw_path=path.encode(),
                     query_string=b"", root_path="", headers=[],
                     client=("test", 1), server=("test", 80))
        with pytest.raises(RuntimeError, match="connection lost"):
            await api.client.app(scope, receive, send)

    asyncio.run(run())
    assert_unavailable(api.client.get(f"/files/{work_id}/download"))
    assert not api.sessions[0].closed.is_set()
