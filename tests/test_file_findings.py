"""Detected types and counts in file results (issue #30): types and counts only."""
from io import BytesIO
import re

from openpyxl import Workbook

from local_ai.detector import Detector
from local_ai.pipeline import LocalSession
from tests.test_file_api import api, upload, workbook_bytes  # noqa: F401 (fixture)

SECRET = "API_KEY=TEST_KEY_1234567890"


def book_bytes(fill):
    book = Workbook()
    fill(book.active)
    stream = BytesIO()
    book.save(stream)
    book.close()
    return stream.getvalue()


def test_local_session_counts_spans_per_type():
    with LocalSession(Detector(None)) as session:
        result = session.process("010-1111-2222, 010-3333-4444, a@example.com")
    assert result.detection_counts == (("EMAIL", 1), ("PHONE", 2))
    assert result.detection_count == 3


def test_ready_splits_counts_between_copy_cells_and_removed_parts(api):
    # Cells A2, A3 and E2 hold names. The comment author, the creator property
    # and the uploaded file name also hold one each; the copy leaves those out.
    response = upload(api, filename="김민수_원본.xlsx")
    body = response.json()
    assert body["status"] == "READY"
    assert body["detected_types"] == ["NAME"]
    assert body["detected_counts"] == {"NAME": 3}
    assert body["hidden_counts"] == {"NAME": 3}
    assert body["detected_count"] == 6
    assert body["blocked_types"] is None
    assert "김민수" not in response.text


def test_every_cell_is_counted_even_when_values_repeat(api):
    def fill(sheet):
        for row in range(1, 5):
            sheet.cell(row, 1, "김민수")
        sheet["B1"] = "010-1234-5678"

    body = upload(api, book_bytes(fill)).json()
    assert body["detected_types"] == ["NAME", "PHONE"]
    assert body["detected_counts"] == {"NAME": 4, "PHONE": 1}
    assert body["hidden_counts"] == {}
    assert body["detected_count"] == 5


def test_place_of_second_readings():
    from file_sanitizer.sanitizer import segment_place

    assert segment_place("s1:A2:raw") == "s1:A2"
    assert segment_place("number-format:3:label:0") == "number-format:3"
    for own in ("s1:A2", "s1:A2:comment", "s1:A2:author", "s2:title", "filename",
                "docProps/core.xml:1:creator"):
        assert segment_place(own) == own


def test_zero_padded_cell_is_counted_once(api, monkeypatch):
    # The displayed text and the stored number are two readings of one cell.
    def accounts(text):
        return [dict(start=m.start(), end=m.end(), type="ACCOUNT")
                for m in re.finditer(r"(?=\d*[1-9])\d{10,}", text)]

    monkeypatch.setattr(api.detector, "detect", accounts)

    def fill(sheet):
        sheet["A1"] = 1012345678
        sheet["A1"].number_format = "00000000000"

    body = upload(api, book_bytes(fill)).json()
    assert body["status"] == "READY"
    assert body["detected_counts"] == {"ACCOUNT": 1}
    assert body["hidden_counts"] == {}


def test_number_format_and_its_label_are_counted_once(api):
    def fill(sheet):
        sheet["A1"] = "값"
        sheet["B1"].number_format = '"담당 김민수 "0'  # Styled but empty: format only.

    body = upload(api, book_bytes(fill)).json()
    assert body["status"] == "READY"
    assert body["detected_counts"] == {}
    assert body["hidden_counts"] == {"NAME": 1}


def test_blocked_names_confidential_types_and_where_they_were(api):
    def hidden_secret(book):
        book["숨김시트"]["A1"] = SECRET

    response = upload(api, workbook_bytes(hidden_secret))
    body = response.json()
    assert body["status"] == "BLOCKED"
    assert body["blocked_types"] == ["API_KEY"]
    assert body["detected_types"] == ["API_KEY", "NAME"]
    assert body["detected_counts"] == {"NAME": 3}
    assert body["hidden_counts"] == {"API_KEY": 1, "NAME": 2}
    assert body["detected_count"] == 6
    assert "TEST_KEY" not in response.text

    def cell_secret(book):
        book.active["E3"] = f"{SECRET} 김민수"

    body = upload(api, workbook_bytes(cell_secret)).json()
    # Only the type that is confidential by itself blocks; NAME is reported, not blamed.
    assert body["blocked_types"] == ["API_KEY"]
    assert body["detected_counts"] == {"API_KEY": 1, "NAME": 4}


def test_public_file_reports_nothing_found(api):
    body = upload(api, book_bytes(lambda sheet: sheet.append(["수량", 42]))).json()
    assert body["status"] == "READY" and body["grade"] == "public_O"
    assert body["detected_types"] == [] and body["detected_count"] == 0
    assert body["detected_counts"] == {} and body["hidden_counts"] == {}
    assert body["blocked_types"] is None


def test_failed_file_reports_no_findings(api):
    body = upload(api, b"not an xlsx").json()
    assert body["status"] == "FAILED"
    for name in ("detected_types", "detected_count", "detected_counts",
                 "hidden_counts", "blocked_types"):
        assert body[name] is None
