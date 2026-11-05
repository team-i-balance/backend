"""Paired controls: valid representations stay readable; ambiguous ones never reach DLP."""

from copy import deepcopy
from datetime import datetime, time, timedelta
from io import BytesIO
import unittest
from unittest.mock import Mock
from xml.etree import ElementTree as ET
from zipfile import ZipFile

from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment
from openpyxl.utils.datetime import CALENDAR_MAC_1904

from file_sanitizer import sanitize_xlsx
from file_sanitizer.__main__ import DemoProcessor
from test_xlsx_value_integrity import MAIN, SHEET, rewrite_cell, save

BOOK = "xl/workbook.xml"
ROOT_LINKS = "_rels/.rels"
BOOK_LINKS = "xl/_rels/workbook.xml.rels"


def change(data, part, edit):
    out = BytesIO()
    with ZipFile(BytesIO(data)) as src, ZipFile(out, "w") as dst:
        for name in src.namelist():
            value = src.read(name)
            if name == part:
                xml = ET.fromstring(value)
                edit(xml)
                value = ET.tostring(xml)
            dst.writestr(name, value)
    return out.getvalue()


def text_sample(where, body):
    if where == "inline":
        return rewrite_cell(f"<is>{body}</is>", kind="inlineStr")
    if where == "shared":
        return rewrite_cell("<v>0</v>", table=f"<si>{body}</si>", kind="s")
    book = Workbook()
    book.active["C4"].comment = Comment("placeholder", "tester")

    def edit(root):
        comment = root.find(".//" + MAIN + "comment")
        comment.remove(comment.find(MAIN + "text"))
        comment.append(ET.fromstring(f'<text xmlns="{MAIN[1:-1]}">{body}</text>'))

    return change(save(book), "xl/comments/comment1.xml", edit)


class StructureTests(unittest.TestCase):
    def rejects(self, data, reason="INVALID_XLSX"):
        processor = Mock()
        result = sanitize_xlsx(data, "local", processor)
        self.assertEqual((result.status, result.reason, result.file_bytes), ("FAILED", reason, None))
        processor.process.assert_not_called()

    def test_text_boundaries_in_cells_tables_and_notes(self):
        for where in ("inline", "shared", "note"):
            with self.subTest(where=where):
                body = "<r><t>기밀테</t></r><r><t>스트-001</t></r>"
                result = sanitize_xlsx(text_sample(where, body), "local", DemoProcessor())
                self.assertEqual((result.status, result.file_bytes), ("BLOCKED", None))
            for first, last in (("기밀테스트-001", "공개"), ("공개", "기밀테스트-001")):
                pair = f"<t>{first}</t><t>{last}</t>"
                for malformed in (pair, f"<r>{pair}</r>"):
                    with self.subTest(where=where, malformed=malformed):
                        self.rejects(text_sample(where, malformed))

    def test_scalar_type_and_boolean_encoding(self):
        for kind, raw in (("custom", "123"), ("b", "2"), ("b", "-1"), ("b", "01")):
            with self.subTest(kind=kind, raw=raw):
                self.rejects(rewrite_cell(f"<v>{raw}</v>", kind=kind))
        for kind, raw, expected in (("str", "0", "0"), ("n", "0", 0), ("b", "0", False), ("b", "1", True)):
            with self.subTest(kind=kind, raw=raw):
                result = sanitize_xlsx(rewrite_cell(f"<v>{raw}</v>", kind=kind), "local", DemoProcessor())
                self.assertEqual(result.status, "READY")
                book = load_workbook(BytesIO(result.file_bytes))
                actual = book.active["A1"].value
                book.close()
                self.assertEqual((type(actual), actual), (type(expected), expected))

    def test_package_and_sheet_identity(self):
        book = Workbook()
        book.active.title = "Public"
        book.create_sheet("Second")["C5"] = "safe"
        data = save(book)

        def root_link(root):
            return next(r for r in root if r.get("Type").endswith("/officeDocument"))

        def alias_target(root):
            sheets = [r for r in root if r.get("Type").endswith("/worksheet")]
            sheets[1].set("Target", sheets[0].get("Target"))

        def duplicate_root(root):
            rel = deepcopy(root_link(root))
            rel.set("Id", "alternative")
            root.append(rel)

        for path in ("xl/workbook.xml", "/xl/workbook.xml"):
            with self.subTest(path=path):
                result = sanitize_xlsx(change(data, ROOT_LINKS, lambda r: root_link(r).set("Target", path)),
                                       "local", DemoProcessor())
                self.assertEqual(result.status, "READY")
        for part, edit in [
                (ROOT_LINKS, lambda r: r.remove(root_link(r))),
                (ROOT_LINKS, lambda r: root_link(r).set("Target", "xl/styles.xml")),
                (ROOT_LINKS, duplicate_root), (BOOK_LINKS, alias_target),
                (BOOK, lambda r: r.append(deepcopy(r.find(MAIN + "sheets")))),
                (BOOK, lambda r: r.find(MAIN + "sheets")[1].set("sheetId", "01")),
                (BOOK, lambda r: r.find(MAIN + "sheets")[1].set("name", "pUbLiC")),
        ]:
            with self.subTest(part=part, edit=edit):
                self.rejects(change(data, part, edit))

    def test_row_must_own_its_cells(self):
        book = Workbook()
        book.active["C8"] = "public"
        data = save(book)
        self.assertEqual(sanitize_xlsx(data, "local", DemoProcessor()).status, "READY")
        self.rejects(change(data, SHEET, lambda r: r.find(".//" + MAIN + "row").set("r", "9")))


class FormatTests(unittest.TestCase):
    def test_conditions_select_type_before_clock_rounding(self):
        book = Workbook()
        book.epoch = CALENDAR_MAC_1904
        noon = datetime(1904, 1, 1, 12)
        samples = [
            (0.5, '[Red][>=5E-1]yyyy-mm-dd;hh:mm', noon),
            (0.499999999, '[>=5E-1]yyyy-mm-dd;hh:mm', time(12)),
            (0.5, '[<>0.5]hh:mm;yyyy-mm-dd', noon),
            (0.5, '[=0.5]hh:mm;yyyy-mm-dd', time(12)),
            (0.5, '[<0.25]0.0;[>0.75]hh:mm;yyyy-mm-dd', noon),
            (0.5, '[<0.25]yyyy-mm-dd;0.00', 0.5),
            (0.5, '[<=0.25]yyyy-mm-dd;[h]:mm', timedelta(hours=12)),
            (0, 'hh:mm";"ss;hh:mm;yyyy-mm-dd', datetime(1904, 1, 1)),
        ]
        for row, (serial, fmt, _) in enumerate(samples, 1):
            book.active.cell(row, 2, serial).number_format = fmt
        result = sanitize_xlsx(save(book), "local", DemoProcessor())
        self.assertEqual(result.status, "READY")
        output = load_workbook(BytesIO(result.file_bytes))
        for cell, (_, fmt, expected) in zip(output.active["B"], samples):
            with self.subTest(fmt=fmt):
                self.assertEqual((type(cell.value), cell.value), (type(expected), expected))
        output.close()

    def test_ambiguous_format_does_not_get_a_copy(self):
        for fmt in ("[>threshold]yyyy-mm-dd;hh:mm", "[<0.1]hh:mm;[>0.9]yyyy-mm-dd",
                    "[>0][<1]yyyy-mm-dd;hh:mm"):
            with self.subTest(fmt=fmt):
                book = Workbook()
                book.epoch = CALENDAR_MAC_1904
                book.active["A4"] = 0.5
                book.active["A4"].number_format = fmt
                result = sanitize_xlsx(save(book), "local", DemoProcessor())
                self.assertEqual((result.status, result.reason, result.file_bytes),
                                 ("FAILED", "UNSUPPORTED_FEATURE", None))
