import hashlib
import unittest
from dataclasses import replace
from datetime import date
from io import BytesIO
from xml.etree import ElementTree as ET
from zipfile import ZipFile

from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment

from file_sanitizer import Decision, sanitize_xlsx
from file_sanitizer.__main__ import DemoProcessor, create_sample


def save(book):
    stream = BytesIO()
    book.save(stream)
    book.close()
    return stream.getvalue()


def modify(data, change):
    book = load_workbook(BytesIO(data))
    change(book)
    return save(book)


def package_with(data, changes):
    stream = BytesIO()
    with ZipFile(BytesIO(data)) as src, ZipFile(stream, "w") as dst:
        for name in src.namelist():
            dst.writestr(name, changes.get(name, src.read(name)))
        for name in changes.keys() - set(src.namelist()):
            dst.writestr(name, changes[name])
    return stream.getvalue()


class SanitizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = create_sample()

    def run_module(self, data=None, processor=None, **kwargs):
        return sanitize_xlsx(self.source if data is None else data, "session-test",
                             processor or DemoProcessor(), **kwargs)

    def assert_no_copy(self, result, status, reason):
        self.assertEqual((result.status, result.reason), (status, reason))
        self.assertIsNone(result.file_bytes)
        self.assertIsNone(result.summary)

    def test_normal_transformation_and_source_hash(self):
        before = hashlib.sha256(self.source).digest()
        result = self.run_module()
        self.assertEqual((result.status, result.grade), ("READY", "S"))
        self.assertEqual(hashlib.sha256(self.source).digest(), before)
        out = load_workbook(BytesIO(result.file_bytes))
        self.assertEqual(out.sheetnames, ["시트1"])
        sheet = out.active
        self.assertEqual([sheet[c].value for c in ("A2", "A3", "A4")], ["고객 A", "고객 B", "고객 A"])
        self.assertEqual([sheet[c].value for c in ("B2", "B3", "B4")], ["담당자 A"] * 3)
        self.assertEqual(sheet["C2"].value, "고객 A가 일정을 문의함")
        self.assertEqual(sheet["C4"].value, "고객 A가 일정을 다시 확인함")
        self.assertEqual((sheet["D2"].value, sheet["E2"].value), (2, 39000))
        self.assertEqual((sheet["D2"].data_type, sheet["E2"].data_type), ("n", "n"))
        self.assertIsNone(sheet["F2"].value)
        self.assertIsNone(sheet["A2"].comment)
        out.close()
        s = result.summary
        self.assertEqual((s.changed_cells, s.removed_comments, s.removed_sheets,
                          s.removed_rows, s.removed_columns), (10, 1, 1, 1, 1))

    def test_no_synthetic_secrets_in_any_package_part(self):
        result = self.run_module()
        with ZipFile(BytesIO(result.file_bytes)) as package:
            self.assertFalse(any("comment" in path.lower() for path in package.namelist()))
            strings = []
            for path in package.namelist():
                tree = ET.fromstring(package.read(path))
                strings.extend(tree.itertext())
                strings.extend(v for node in tree.iter() for v in node.attrib.values())
        whole_copy = "\n".join(strings)
        for original in (*DemoProcessor.substitutions, "내부메모표식", "메모작성자표식", "숨김열표식",
                         "숨김행표식", "숨김시트표식", "내부명단표식", "문서작성자표식", "가상업무표"):
            with self.subTest(original=original):
                self.assertNotIn(original, whole_copy)

    def test_inspection_inputs_and_verification_use_same_session(self):
        class Recording(DemoProcessor):
            def process(self, session_id, segments):
                self.session, self.segments = session_id, segments
                return super().process(session_id, segments)

            def verify(self, session_id, segments):
                self.second_session, self.second_segments = session_id, segments
                return super().verify(session_id, segments)

        spy = Recording()
        self.assertEqual(self.run_module(processor=spy, filename="원본이름.xlsx").status, "READY")
        by_id = {s.id: s for s in spy.segments}
        self.assertEqual((by_id["s1:A2"].column_header, by_id["s1:A2"].text), ("고객명", "김민수"))
        self.assertFalse(by_id["s1:G2"].exportable)
        self.assertFalse(by_id["s2:A1"].exportable)
        self.assertEqual(by_id["filename"].text, "원본이름.xlsx")
        self.assertEqual((spy.session, spy.second_session), ("session-test", "session-test"))
        self.assertIn("고객 A가 일정을 문의함", [s.text for s in spy.second_segments])

    def test_confidential_in_hidden_sheet(self):
        for state in ("hidden", "veryHidden"):
            with self.subTest(state=state):
                def setup(book):
                    sheet = book.worksheets[1]
                    sheet.sheet_state = state
                    sheet["B3"] = DemoProcessor.confidential
                self.assert_no_copy(self.run_module(modify(self.source, setup)), "BLOCKED", "CONFIDENTIAL")

    def test_confidential_in_removed_source_parts(self):
        secret = DemoProcessor.confidential
        for edit in [
            lambda b: setattr(b.properties, "creator", secret),
            lambda b: setattr(b.properties, "lastModifiedBy", secret),
            lambda b: setattr(b.active, "title", secret),
            lambda b: setattr(b.active["A2"], "comment", Comment(secret, "test")),
            lambda b: setattr(b.active["A2"], "comment", Comment("note", secret)),
            lambda b: setattr(b.active["A5"], "value", secret),
            lambda b: setattr(b.active["G2"], "value", secret),
        ]:
            with self.subTest(edit=edit):
                self.assert_no_copy(self.run_module(modify(self.source, edit)), "BLOCKED", "CONFIDENTIAL")
        self.assert_no_copy(self.run_module(filename=secret + ".xlsx"), "BLOCKED", "CONFIDENTIAL")

    def test_public_typed_values_and_hidden_group(self):
        book = Workbook()
        sheet = book.active
        sheet.append(["날짜", "사용", "수량", "금액", "기타"])
        sheet.append([date(2026, 1, 1), True, 0, 12.5, "그룹숨김"])
        sheet.column_dimensions.group("D", "E", hidden=True)
        result = self.run_module(save(book))
        self.assertEqual((result.status, result.grade, result.summary.removed_columns), ("READY", "O", 2))
        out = load_workbook(BytesIO(result.file_bytes))
        self.assertEqual(out.active["A2"].value.date(), date(2026, 1, 1))
        self.assertIs(out.active["B2"].value, True)
        self.assertEqual(out.active["C2"].value, 0)
        self.assertIsNone(out.active["D2"].value)
        self.assertIsNone(out.active["E2"].value)
        out.close()

    def test_sparse_multi_sheet_coordinates(self):
        book = Workbook()
        book.active.sheet_state = "hidden"
        book.create_sheet("자료")["C4"] = "첫 셀"
        book.create_sheet("자료2")["D5"] = 17
        result = self.run_module(save(book))
        out = load_workbook(BytesIO(result.file_bytes))
        self.assertEqual(out.sheetnames, ["시트1", "시트2"])
        self.assertEqual((out.worksheets[0]["C4"].value, out.worksheets[1]["D5"].value), ("첫 셀", 17))
        out.close()

    def test_zero_sized_dimensions_are_only_scanned(self):
        path = "xl/worksheets/sheet1.xml"
        with ZipFile(BytesIO(self.source)) as z:
            root = ET.fromstring(z.read(path))
        row = root.find(".//{*}row[@r='5']")
        col = root.find(".//{*}col[@min='7']")
        for element, dimension in ((row, "ht"), (col, "width")):
            del element.attrib["hidden"]
            element.set(dimension, "0")
        data = package_with(self.source, {path: ET.tostring(root)})
        result = self.run_module(data)
        self.assertEqual(result.status, "READY")
        out = load_workbook(BytesIO(result.file_bytes))
        self.assertIsNone(out.active["A5"].value)
        self.assertIsNone(out.active["G2"].value)
        out.close()

    def test_unsupported_formula_in_hidden_sheet(self):
        data = modify(self.source, lambda b: setattr(b.worksheets[1]["A1"], "value", "=SUM(1,2)"))
        self.assert_no_copy(self.run_module(data), "FAILED", "UNSUPPORTED_FEATURE")

    def test_macro_and_embedded_package_parts(self):
        for path in ("xl/vbaProject.bin", "xl/embeddings/object1.bin", "xl/drawings/drawing1.xml"):
            with self.subTest(path=path):
                self.assert_no_copy(self.run_module(package_with(self.source, {path: b"data"})),
                                    "FAILED", "UNSUPPORTED_FEATURE")

    def test_macro_enabled_content_type(self):
        with ZipFile(BytesIO(self.source)) as z:
            xml = z.read("[Content_Types].xml").replace(
                b"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
                b"application/vnd.ms-excel.sheet.macroEnabled.main+xml")
        self.assert_no_copy(self.run_module(package_with(self.source, {"[Content_Types].xml": xml})),
                            "FAILED", "UNSUPPORTED_FEATURE")

    def test_corrupt_zip_and_malformed_xml(self):
        for data in (b"broken file", package_with(self.source, {"xl/workbook.xml": b"<broken"})):
            with self.subTest(size=len(data)):
                self.assert_no_copy(self.run_module(data), "FAILED", "INVALID_XLSX")

    def test_broken_reference_to_hidden_sheet_is_not_ignored(self):
        with ZipFile(BytesIO(self.source)) as z:
            path = "xl/_rels/workbook.xml.rels"
            rels = z.read(path).replace(b"worksheets/sheet2.xml", b"worksheets/sheet9.xml")
        self.assert_no_copy(self.run_module(package_with(self.source, {path: rels})), "FAILED", "INVALID_XLSX")

    def test_rejects_macro_extension_even_if_content_is_a_plain_workbook(self):
        self.assert_no_copy(self.run_module(filename="sample.xlsm"), "FAILED", "UNSUPPORTED_FILE_TYPE")

    def test_missing_or_extra_processor_keys(self):
        class Missing(DemoProcessor):
            def process(self, session_id, segments):
                result = super().process(session_id, segments)
                del result["s1:A2"]
                return result

        class Extra(DemoProcessor):
            def process(self, session_id, segments):
                return dict(super().process(session_id, segments), unexpected=Decision("O", "x"))

        for processor in (Missing(), Extra()):
            with self.subTest(processor=processor):
                self.assert_no_copy(self.run_module(processor=processor), "FAILED", "INVALID_PROCESSOR_RESULT")

    def test_verifier_detects_untransformed_sensitive_value(self):
        class Incomplete(DemoProcessor):
            def process(self, session_id, segments):
                decisions = super().process(session_id, segments)
                decisions["s1:C2"] = Decision("S", "김민수가 일정을 문의함")
                return decisions

        self.assert_no_copy(self.run_module(processor=Incomplete()), "FAILED", "RESIDUAL_CHECK_FAILED")

    def test_invalid_processor_data_or_exception(self):
        class Invalid(DemoProcessor):
            def process(self, session_id, segments):
                decisions = super().process(session_id, segments)
                decisions["s1:A2"] = Decision("O", "silently changed")
                return decisions

        class Failure(DemoProcessor):
            def process(self, session_id, segments):
                raise RuntimeError("private raw content")

        self.assert_no_copy(self.run_module(processor=Invalid()), "FAILED", "INVALID_PROCESSOR_RESULT")
        self.assert_no_copy(self.run_module(processor=Failure()), "FAILED", "PROCESSOR_ERROR")

    def test_literal_formula_looking_replacements(self):
        class Literal(DemoProcessor):
            def process(self, session_id, segments):
                decisions = super().process(session_id, segments)
                decisions["s1:A2"] = replace(decisions["s1:A2"], text="=1+2")
                return decisions

        out = load_workbook(BytesIO(self.run_module(processor=Literal()).file_bytes))
        self.assertEqual((out.active["A2"].value, out.active["A2"].data_type), ("=1+2", "s"))
        out.close()

    def test_oversized_sparse_workbook_is_rejected(self):
        data = modify(self.source, lambda b: setattr(b.active["Z10000"], "value", 1))
        self.assert_no_copy(self.run_module(data), "FAILED", "FILE_TOO_LARGE")


if __name__ == "__main__":
    unittest.main()
