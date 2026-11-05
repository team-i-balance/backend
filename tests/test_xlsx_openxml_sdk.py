"""XLSX written by the Open XML SDK (e.g. .NET ClosedXML/OpenXML generators).

Such files declare the workbook only through ``<Default Extension="xml">`` in
[Content_Types].xml, use an ``x:`` prefix, absolute relationship targets, a BOM
and frozen panes. A real customer-inquiry sample with these traits failed with
UNSUPPORTED_FEATURE, and a cell quoting "[이름_1]" then failed the whole file.
"""
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from openpyxl import load_workbook

from file_sanitizer.package import RejectedFile, inspect_package
from local_ai.detector import Detector
from local_ai.pipeline import LocalSession
from local_ai.pseudonym import PlaceholderReuseError
from tests.test_file_api import api, upload  # noqa: F401 (fixture)

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
WORKBOOK = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
BOM = "﻿"


def cell(ref, text, style=1):
    return f'<x:c r="{ref}" s="{style}" t="str"><x:v>{text}</x:v></x:c>'


def sdk_book(rows, *, content_types=None):
    sheet_rows = "".join(
        f'<x:row r="{r}">' + "".join(cell(f"{chr(65 + c)}{r}", v, 3 if r == 1 else 1)
                                     for c, v in enumerate(values)) + "</x:row>"
        for r, values in enumerate(rows, start=1)
    )
    parts = {
        "xl/workbook.xml": f'<?xml version="1.0" encoding="utf-8"?><x:workbook xmlns:x="{MAIN_NS}"><x:sheets>'
                           f'<x:sheet name="고객문의" sheetId="1" r:id="R1" xmlns:r="{REL_NS}" /></x:sheets></x:workbook>',
        "xl/styles.xml": f'<?xml version="1.0" encoding="utf-8"?><x:styleSheet xmlns:x="{MAIN_NS}">'
                         '<x:numFmts count="1"><x:numFmt numFmtId="200" formatCode="@" /></x:numFmts>'
                         '<x:fonts count="2"><x:font><x:sz val="11" /><x:name val="Carlito" /></x:font>'
                         '<x:font><x:b /><x:sz val="11" /><x:color rgb="FFFFFFFF" /><x:name val="Carlito" /></x:font></x:fonts>'
                         '<x:fills count="3"><x:fill><x:patternFill patternType="none" /></x:fill>'
                         '<x:fill><x:patternFill patternType="gray125" /></x:fill>'
                         '<x:fill><x:patternFill patternType="solid"><x:fgColor rgb="FF1F4E78" /></x:patternFill></x:fill></x:fills>'
                         '<x:borders count="1"><x:border><x:left /><x:right /><x:top /><x:bottom /><x:diagonal /></x:border></x:borders>'
                         '<x:cellStyleXfs count="1"><x:xf numFmtId="0" fontId="0" fillId="0" borderId="0" /></x:cellStyleXfs>'
                         '<x:cellXfs count="4"><x:xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" />'
                         '<x:xf numFmtId="200" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" />'
                         '<x:xf numFmtId="200" fontId="0" fillId="2" borderId="0" xfId="0" applyNumberFormat="1" />'
                         '<x:xf numFmtId="200" fontId="1" fillId="2" borderId="0" xfId="0" applyNumberFormat="1" /></x:cellXfs>'
                         '<x:cellStyles count="1"><x:cellStyle name="Normal" xfId="0" /></x:cellStyles></x:styleSheet>',
        "xl/sharedStrings.xml": f'<?xml version="1.0" encoding="utf-8"?><x:sst xmlns:x="{MAIN_NS}" />',
        "xl/worksheets/sheet1.xml": f'<?xml version="1.0" encoding="utf-8"?><x:worksheet xmlns:x="{MAIN_NS}">'
                                    '<x:sheetViews><x:sheetView workbookViewId="0"><x:pane ySplit="1" topLeftCell="A2" '
                                    'activePane="bottomLeft" state="frozen" /></x:sheetView></x:sheetViews>'
                                    '<x:sheetFormatPr defaultRowHeight="15" /><x:cols>'
                                    '<x:col min="1" max="5" width="24" hidden="0" customWidth="1" /></x:cols>'
                                    f'<x:sheetData>{sheet_rows}</x:sheetData>'
                                    '<x:pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3" />'
                                    '</x:worksheet>',
        "_rels/.rels": BOM + '<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       f'<Relationship Type="{REL_NS}/officeDocument" Target="/xl/workbook.xml" Id="R0" /></Relationships>',
        "xl/_rels/workbook.xml.rels": BOM + '<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                                      f'<Relationship Type="{REL_NS}/styles" Target="/xl/styles.xml" Id="Rs" />'
                                      f'<Relationship Type="{REL_NS}/sharedStrings" Target="/xl/sharedStrings.xml" Id="Rt" />'
                                      f'<Relationship Type="{REL_NS}/worksheet" Target="/xl/worksheets/sheet1.xml" Id="R1" /></Relationships>',
        "[Content_Types].xml": content_types or (
            BOM + '<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            f'<Default Extension="xml" ContentType="{WORKBOOK}" />'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml" />'
            '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml" />'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml" />'
            '</Types>'),
    }
    out = BytesIO()
    with ZipFile(out, "w", ZIP_DEFLATED) as package:
        for name, text in parts.items():
            package.writestr(name, text.encode("utf-8"))
    return out.getvalue()


ROWS = [
    ["사례", "고객명", "연락처", "상담 내용"],
    ["P01", "김민수", "010-2345-6789", "예약 일정을 확인해 주세요."],
    ["P04", "박영희", "02-234-5678", "유선번호"],
    ["P05", "김민수", "031-234-5678", "기존 가명 형태 [이름_1] 과 박영희"],
]


def test_workbook_declared_by_default_extension_is_accepted():
    inspect_package(sdk_book(ROWS))


def test_workbook_type_still_required():
    # No Override and no Default makes the workbook untyped: still rejected.
    untyped = ('<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
               '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" /></Types>')
    try:
        inspect_package(sdk_book(ROWS, content_types=untyped))
    except RejectedFile as exc:
        assert str(exc) == "UNSUPPORTED_FEATURE"
    else:
        raise AssertionError("untyped workbook accepted")


def test_two_workbook_parts_by_default_are_rejected():
    # A Default that types the workbook must not also type another part as a workbook.
    types = ('<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
             f'<Default Extension="xml" ContentType="{WORKBOOK}" />'
             '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />'
             '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml" />'
             '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml" />'
             '</Types>')  # worksheet left to the workbook Default
    try:
        inspect_package(sdk_book(ROWS, content_types=types))
    except RejectedFile as exc:
        assert str(exc) == "UNSUPPORTED_FEATURE"
    else:
        raise AssertionError("second workbook-typed part accepted")


def test_sdk_file_is_masked_end_to_end(api):
    response = upload(api, sdk_book(ROWS), filename="01_개인정보_검사.xlsx")
    body = response.json()
    assert response.status_code == 200, body
    assert body["status"] == "READY"
    assert body["detected_counts"]["PHONE"] == 3
    copy = api.client.get(f"/files/{body['work_id']}/download").content
    sheet = load_workbook(BytesIO(copy)).active
    values = [[c.value for c in row] for row in sheet.iter_rows()]
    text = repr(values)
    for raw in ("김민수", "박영희", "010-2345-6789", "02-234-5678", "031-234-5678"):
        assert raw not in text
    # The quoted literal stays as written and is not reused for a real name.
    memo = values[3][3]
    assert memo.startswith("기존 가명 형태 [이름_1] 과 [이름_")
    assert values[1][1] != "[이름_1]" and values[3][1] == values[1][1]


def test_literal_placeholder_in_a_later_text_is_reserved():
    with LocalSession(Detector(None)) as session:
        session.reserve_literals(["a@example.com", "기존 [이메일_1] 표기"])
        first = session.process("a@example.com")
        later = session.process("기존 [이메일_1] 표기")
        restored = session.restore("[이메일_1] [이메일_2]").text
    assert first.text == "[이메일_2]"
    assert later.text == "기존 [이메일_1] 표기"
    assert restored == "[이메일_1] a@example.com"


def test_assigned_placeholder_in_new_text_still_fails_closed():
    with LocalSession(Detector(None)) as session:
        session.process("a@example.com")
        session.reserve_literals(["[이메일_1]"])
        with pytest.raises(PlaceholderReuseError):
            session.process("다시 [이메일_1]")


def test_landline_numbers_are_phones():
    found = Detector(None).detect("서울 02-234-5678, 경기 031-234-5678, 인터넷 070-1234-5678, 제주 064 712 3456")
    assert sorted(d["type"] for d in found) == ["PHONE"] * 4
    # Not phones: dates, account-like long groups, short groups.
    for text in ("2026-02-15", "123-456-789012", "053-1234", "02-12-3456"):
        assert [d for d in Detector(None).detect(text) if d["type"] == "PHONE"] == [], text
