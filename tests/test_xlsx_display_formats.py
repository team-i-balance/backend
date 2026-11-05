"""Display-only source data must not be lost or exposed by values-only export."""

from hashlib import sha256
from io import BytesIO
import unittest
from zipfile import ZipFile

from openpyxl import Workbook, load_workbook

from file_sanitizer import Decision, LocalPIIProcessor, sanitize_xlsx
from file_sanitizer.__main__ import DemoProcessor
from local_ai.pipeline import LocalSession


def workbook_bytes(rows):
    book = Workbook()
    for row, (value, fmt) in enumerate(rows, 1):
        book.active.cell(row, 1, value).number_format = fmt
    stream = BytesIO()
    book.save(stream)
    book.close()
    return stream.getvalue()


class DisplayFormatTests(unittest.TestCase):
    def protect(self, rows, processor=None):
        return sanitize_xlsx(workbook_bytes(rows), "formats", processor or DemoProcessor())

    def test_zero_padding_keeps_numeric_value_and_safe_format(self):
        rows = [(value, "0" * width) for value in (0, 7, -42, 123456)
                for width in (2, 5, 8)]
        result = self.protect(rows)
        self.assertEqual(result.status, "READY")
        book = load_workbook(BytesIO(result.file_bytes))
        try:
            for row, (value, fmt) in enumerate(rows, 1):
                cell = book.active.cell(row, 1)
                with self.subTest(value=value, fmt=fmt):
                    self.assertEqual((cell.value, type(cell.value), cell.number_format), (value, int, fmt))
            self.assertEqual(result.summary.changed_cells, 0)
        finally:
            book.close()

    def test_displayed_identifier_is_processed_before_export(self):
        class IdentifierProcessor(DemoProcessor):
            def process(self, session_id, segments):
                self.seen = {s.id: s.text for s in segments}
                decisions = super().process(session_id, segments)
                for s in segments:
                    if s.text == "00123":
                        decisions[s.id] = Decision("S", "[식별번호_1]" if s.exportable else None)
                return decisions

        processor = IdentifierProcessor()
        result = self.protect([(123, "00000")], processor)
        self.assertEqual((result.status, result.grade), ("READY", "S"))
        self.assertEqual(processor.seen["s1:A1"], "00123")
        self.assertEqual(processor.seen["s1:A1:raw"], "123")
        book = load_workbook(BytesIO(result.file_bytes))
        self.assertEqual(book.active["A1"].value, "[식별번호_1]")
        self.assertEqual(book.active["A1"].number_format, "General")
        book.close()

    def test_raw_identifier_cannot_be_ignored_if_display_detection_disagrees(self):
        class RawProcessor(DemoProcessor):
            def process(self, session_id, segments):
                decisions = super().process(session_id, segments)
                for s in segments:
                    if s.text == "123":
                        decisions[s.id] = Decision("S", None)
                return decisions

        result = self.protect([(123, "00000")], RawProcessor())
        self.assertEqual((result.status, result.reason, result.file_bytes),
                         ("FAILED", "RESIDUAL_CHECK_FAILED", None))

    def test_team_mapping_restores_the_displayed_identifier(self):
        class IdentifierDetector:
            model_enabled = True

            def detect(self, text):
                if text == "00123":
                    return [{"start": 0, "end": 5, "type": "ID_NUMBER"}]
                return []

        # Fix detector output to test the real adapter/mapping independently of
        # model accuracy. Mapping ownership remains with the caller.
        with LocalSession(IdentifierDetector()) as session:
            result = self.protect([(123, "00000")], LocalPIIProcessor(session))
            self.assertEqual((result.status, result.grade), ("READY", "S"))
            book = load_workbook(BytesIO(result.file_bytes))
            token = book.active["A1"].value
            book.close()
            self.assertEqual(token, "[식별번호_1]")
            self.assertEqual(session.restore(token).text, "00123")

    def test_hidden_values_are_removed_from_package_without_changing_source(self):
        source = workbook_bytes([(318720, ";;;"), (171340, ";;;"), ("김민수", ";;;"), (19, "General")])
        digest = sha256(source).hexdigest()
        result = sanitize_xlsx(source, "formats", DemoProcessor())
        self.assertEqual((result.status, result.grade), ("READY", "S"))
        self.assertEqual(sha256(source).hexdigest(), digest)
        self.assertEqual(result.summary.changed_cells, 3)
        book = load_workbook(BytesIO(result.file_bytes))
        self.assertEqual([book.active.cell(i, 1).value for i in range(1, 5)], [None, None, None, 19])
        book.close()
        with ZipFile(BytesIO(result.file_bytes)) as archive:
            xml = b"\n".join(archive.read(name) for name in archive.namelist())
        for forbidden in ("318720", "171340", "김민수"):
            self.assertNotIn(forbidden.encode(), xml)

    def test_hidden_content_is_still_checked_for_confidentiality(self):
        result = self.protect([("기밀테스트-001", ";;;")])
        self.assertEqual((result.status, result.file_bytes), ("BLOCKED", None))

    def test_selected_section_hides_only_the_applicable_values(self):
        cases = [
            (12, "0;;", 12), (-12, "0;;", None), (0, "0;;", None),
            ("visible", "0;;", "visible"), ("hidden", "0;0;0;", None),
            ("visible", ";;;@", "visible"), (12, ";;;@", None),
            (99, "[>=100]0;", None), (100, "[>=100]0;", 100),
            (123, '"label only"', None), (123, '";"', None),
            (123, '[Red]""', None),
        ]
        result = self.protect([(value, fmt) for value, fmt, _ in cases])
        self.assertEqual(result.status, "READY")
        book = load_workbook(BytesIO(result.file_bytes))
        for row, (value, fmt, expected) in enumerate(cases, 1):
            with self.subTest(value=value, fmt=fmt):
                self.assertEqual(book.active.cell(row, 1).value, expected)
        book.close()

    def test_all_format_sections_and_literal_spellings_are_inspected(self):
        formats = [
            '"기밀테스트-001 "000',
            '"기밀테""스트-001 "0',
            r'\기\밀\테\스\트\-\0\0\1 0',
            '0;"기밀테스트-001"0;0;@',
            '0;0;0;"기밀테스트-001"@',
        ]
        for fmt in formats:
            with self.subTest(fmt=fmt):
                result = self.protect([(7, fmt)])
                self.assertEqual((result.status, result.grade, result.file_bytes), ("BLOCKED", "C", None))

    def test_format_on_empty_or_hidden_cell_is_still_inspected(self):
        for hidden in (False, True):
            with self.subTest(hidden=hidden):
                book = Workbook()
                book.active["A1"] = "public"
                sheet = book.create_sheet("Second")
                sheet["D5"].number_format = '"기밀테""스트-001"0'
                if hidden:
                    sheet.sheet_state = "hidden"
                stream = BytesIO()
                book.save(stream)
                book.close()
                result = sanitize_xlsx(stream.getvalue(), "formats", DemoProcessor())
                self.assertEqual((result.status, result.file_bytes), ("BLOCKED", None))

    def test_ambiguous_zero_masks_fail_without_returning_a_copy(self):
        for value, fmt in ((1.5, "00000"), (12, "000-00"), (12, '[Red]00000'),
                           (12, "000.00"), (-12, "000;000"), (12, '"unterminated')):
            with self.subTest(value=value, fmt=fmt):
                result = self.protect([(value, fmt)])
                self.assertEqual((result.status, result.reason, result.file_bytes),
                                 ("FAILED", "UNSUPPORTED_FEATURE", None))

    def test_inherited_number_format_is_rejected(self):
        for dimension in ("row", "column"):
            book = Workbook()
            book.active["B2"] = 123
            if dimension == "row":
                book.active.row_dimensions[2].number_format = ";;;"
            else:
                book.active.column_dimensions["B"].number_format = ";;;"
            stream = BytesIO()
            book.save(stream)
            book.close()
            with self.subTest(dimension=dimension):
                result = sanitize_xlsx(stream.getvalue(), "formats", DemoProcessor())
                self.assertEqual((result.status, result.reason, result.file_bytes),
                                 ("FAILED", "UNSUPPORTED_FEATURE", None))


if __name__ == "__main__":
    unittest.main()
