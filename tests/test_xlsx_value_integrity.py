"""Do not lose a raw value/comment before inspection or a calendar day on export."""

import unittest
from datetime import datetime, time, timedelta
from io import BytesIO
from unittest.mock import Mock
from xml.etree import ElementTree as ET
from zipfile import ZipFile

from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment
from openpyxl.utils.datetime import CALENDAR_MAC_1904

from file_sanitizer import sanitize_xlsx
from file_sanitizer.__main__ import DemoProcessor


MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
SHEET = "xl/worksheets/sheet1.xml"
SST = "xl/sharedStrings.xml"


def save(book):
    stream = BytesIO()
    book.save(stream)
    book.close()
    return stream.getvalue()


def rewrite_cell(body, table=None, *, kind="str"):
    book = Workbook()
    book.active["A1"] = "placeholder"
    src = save(book)
    out = BytesIO()
    with ZipFile(BytesIO(src)) as z, ZipFile(out, "w") as dest:
        for name in z.namelist():
            data = z.read(name)
            if name == SHEET:
                root = ET.fromstring(data)
                row = root.find(".//" + MAIN + "row")
                row.remove(row.find(MAIN + "c"))
                row.append(ET.fromstring(f'<c xmlns="{MAIN[1:-1]}" r="A1" t="{kind}">{body}</c>'))
                data = ET.tostring(root)
            elif name == "[Content_Types].xml" and table is not None:
                extra = b'<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
                data = data.replace(b"</Types>", extra + b"</Types>")
            elif name == "xl/_rels/workbook.xml.rels" and table is not None:
                extra = b'<Relationship Id="rId20" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>'
                data = data.replace(b"</Relationships>", extra + b"</Relationships>")
            dest.writestr(name, data)
        if table is not None:
            dest.writestr(SST, f'<sst xmlns="{MAIN[1:-1]}" uniqueCount="99">{table}</sst>')
    return out.getvalue()


class ValueIntegrityTests(unittest.TestCase):
    def assert_invalid_before_processing(self, data):
        processor = Mock()
        result = sanitize_xlsx(data, "regression", processor)
        self.assertEqual((result.status, result.reason, result.file_bytes), ("FAILED", "INVALID_XLSX", None))
        processor.process.assert_not_called()

    def test_ambiguous_payloads(self):
        value = '<v>public</v>'
        inline = '<is><t>기밀테스트-001</t></is>'
        for body, kind in [(value*2, "str"), (inline*2, "inlineStr"), (value+inline, "str"),
                           (inline+value, "inlineStr"), (inline, "str"), (value, "inlineStr")]:
            with self.subTest(body=body, kind=kind):
                self.assert_invalid_before_processing(rewrite_cell(body, kind=kind))

    def test_shared_string_indices_use_actual_entries(self):
        strings = "<si><t>기밀테스트-001</t></si><si><t>public</t></si>"
        for index in ("-1", "2", "98", "1.0", ""):
            with self.subTest(index=index):
                self.assert_invalid_before_processing(rewrite_cell(f"<v>{index}</v>", strings, kind="s"))
        for index, expected in ((0, "BLOCKED"), (1, "READY")):
            data = rewrite_cell(f"<v>{index}</v>", strings, kind="s")
            result = sanitize_xlsx(data, "regression", DemoProcessor())
            self.assertEqual(result.status, expected)

    def test_repeated_comment_coordinate_per_sheet(self):
        book = Workbook()
        for sheet in (book.active, book.create_sheet("second")):
            sheet["B3"].comment = Comment("ordinary note", "writer")
        original = save(book)
        self.assertEqual(sanitize_xlsx(original, "regression", DemoProcessor()).status, "READY")
        for ref in ("B3", "b03", "$B$3"):
            with self.subTest(ref=ref):
                out = BytesIO()
                with ZipFile(BytesIO(original)) as z, ZipFile(out, "w") as dest:
                    for name in z.namelist():
                        data = z.read(name)
                        if name == "xl/comments/comment1.xml":
                            root = ET.fromstring(data)
                            notes = root.find(MAIN+"commentList")
                            new = ET.fromstring(ET.tostring(notes[0]))
                            new.set("ref", ref)
                            new.find(".//" + MAIN + "t").text = "기밀테스트-001"
                            notes.insert(0, new)
                            data = ET.tostring(root)
                        dest.writestr(name, data)
                self.assert_invalid_before_processing(out.getvalue())

    def test_mac_epoch_numeric_day_zero_and_time_only_formats(self):
        book = Workbook()
        book.epoch = CALENDAR_MAC_1904
        sheet = book.active
        cases = [
            (0, "yyyy-mm-dd hh:mm", datetime(1904, 1, 1)),
            (0.5, "YYYY-MM-DD HH:MM", datetime(1904, 1, 1, 12)),
            (0.5, "mmm", datetime(1904, 1, 1, 12)),
            (0.5, 'hh:mm "day"', time(12)),
            (0.5, 'mm:ss', time(12)),
            (0.5, 'h:mm AM/PM', time(12)),
            (0.5, '[h]:mm', timedelta(hours=12)),
            (0, 'hh:mm;hh:mm;yyyy-mm-dd', datetime(1904, 1, 1)),
            (0, 'yyyy-mm-dd;yyyy-mm-dd;hh:mm', time(0)),
            (0.5, 'General', 0.5),
        ]
        for position, (serial, fmt, _) in enumerate(cases, 1):
            cell = sheet.cell(position, 1, serial)
            cell.number_format = fmt
        result = sanitize_xlsx(save(book), "regression", DemoProcessor())
        self.assertEqual(result.status, "READY")
        protected = load_workbook(BytesIO(result.file_bytes))
        for cell, (_, fmt, expected) in zip(protected.active["A"], cases):
            with self.subTest(fmt=fmt):
                self.assertIs(type(cell.value), type(expected))
                self.assertEqual(cell.value, expected)
        protected.close()

    def test_mac_epoch_explicit_iso_time_respects_stored_type(self):
        book = Workbook(iso_dates=True)
        book.epoch = CALENDAR_MAC_1904
        cell = book.active["C2"]
        cell.value = time(12, 13)
        cell.number_format = "yyyy-mm-dd hh:mm"
        result = sanitize_xlsx(save(book), "regression", DemoProcessor())
        self.assertEqual(result.status, "READY")
        protected = load_workbook(BytesIO(result.file_bytes))
        self.assertEqual(protected.active["C2"].value, time(12, 13))
        protected.close()
