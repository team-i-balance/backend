"""Small actual-model HTTP smoke suite, separate from detector-double API tests."""
from io import BytesIO
import os
import socket
from unittest.mock import patch

from openpyxl import Workbook, load_workbook
import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("LOCAL_PII_MODEL_DIR"), reason="set LOCAL_PII_MODEL_DIR for real model",
)


@pytest.mark.parametrize("case,status", [
    ("public", "READY"), ("pii", "READY"), ("hidden_secret", "BLOCKED"),
])
def test_real_model_upload(client, case, status):
    book = Workbook()
    book.active.append(["품목", "수량", "금액"])
    book.active.append(["복사용지", 2, 15000])
    if case == "pii":
        book.active["A3"] = "담당자: 김민수, 연락처: 010-1234-5678"
    if case == "hidden_secret":
        hidden = book.create_sheet("내부")
        hidden.sheet_state = "hidden"
        hidden["A1"] = "API_KEY=TEST_KEY_1234567890"
    stream = BytesIO()
    book.save(stream)
    book.close()

    # The ASGI test client runs in-process; model load/inference must not connect out.
    with patch.object(socket.socket, "connect", side_effect=RuntimeError("network disabled")):
        response = client.post("/files/sanitize", files={"file": ("sample.xlsx", stream.getvalue())})
    assert response.status_code == 200, response.json()
    result = response.json()
    assert result["status"] == status, result

    from app.file_store import store

    item = store.take(result["work_id"])
    if status == "BLOCKED":
        assert item is None and result["grade"] == "confidential_C"
        return
    assert item is not None
    try:
        copy = load_workbook(BytesIO(item.file_bytes))
        assert (copy.active["B2"].value, copy.active["C2"].value) == (2, 15000)
        if case == "pii":
            protected = copy.active["A3"].value
            assert "김민수" not in protected and "010-1234-5678" not in protected
            assert item.session.restore(protected).text == "담당자: 김민수, 연락처: 010-1234-5678"
        copy.close()
    finally:
        item.close()
