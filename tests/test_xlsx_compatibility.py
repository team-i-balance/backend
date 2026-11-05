"""Regression tests for raw cell addresses, date precision and Calc's values-only exports."""

import unittest
from datetime import date, datetime, time
from io import BytesIO
from unittest.mock import Mock
from zipfile import ZipFile

from openpyxl import Workbook, load_workbook

from file_sanitizer import sanitize_xlsx
from file_sanitizer.__main__ import DemoProcessor


SHEET = "xl/worksheets/sheet1.xml"
WORKBOOK = "xl/workbook.xml"
TRUE_CELL = '<c r="A1" t="b"><f aca="false">TRUE()</f><v>1</v></c>'
SETTINGS = ('<extLst><ext uri="{7626C862-2A13-11E5-B345-FEFF819CDC9F}">'
            '<lo:extCalcPr xmlns:lo="http://schemas.libreoffice.org/" stringRefSyntax="ExcelA1"/>'
            '</ext></extLst>')
CUSTOM = '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"/>'


def serialized(book):
    data = BytesIO()
    book.save(data)
    book.close()
    return data.getvalue()


def replace_parts(data, changes):
    result = BytesIO()
    with ZipFile(BytesIO(data)) as source, ZipFile(result, "w") as target:
        for name in source.namelist():
            if name not in changes:
                target.writestr(name, source.read(name))
        for name, xml in changes.items():
            target.writestr(name, xml)
    return result.getvalue()


class CompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        book = Workbook()
        book.active["A1"] = True
        book.active["B1"] = False
        cls.basic = serialized(book)
        with ZipFile(BytesIO(cls.basic)) as archive:
            cls.sheet_xml = archive.read(SHEET).decode()
            cls.workbook_xml = archive.read(WORKBOOK).decode()

    def calc_file(self, *, cell=TRUE_CELL, settings=SETTINGS, header='<oddHeader/><oddFooter/>', custom=CUSTOM):
        sheet = self.sheet_xml.replace('<c r="A1" t="b"><v>1</v></c>', cell)
        sheet = sheet.replace('<c r="B1" t="b"><v>0</v></c>',
                              '<c r="B1" t="b"><f>FALSE()</f><v>0</v></c>')
        sheet = sheet.replace('</worksheet>', f'<headerFooter differentFirst="false">{header}</headerFooter></worksheet>')
        return replace_parts(self.basic, {
            SHEET: sheet, WORKBOOK: self.workbook_xml.replace('</workbook>', settings + '</workbook>'),
            "docProps/custom.xml": custom,
        })

    def test_duplicate_cell_rejected_before_processing(self):
        for address in ('A1', 'a01'):
            for first in (True, False):
                with self.subTest(address=address, first=first):
                    visible = '<c r="A1" t="b"><v>1</v></c>'
                    confidential = f'<c r="{address}" t="inlineStr"><is><t>기밀테스트-001</t></is></c>'
                    pair = confidential + visible if first else visible + confidential
                    data = replace_parts(self.basic, {SHEET: self.sheet_xml.replace(visible, pair)})
                    processor = Mock()
                    result = sanitize_xlsx(data, "regression", processor)
                    self.assertEqual((result.status, result.reason, result.file_bytes), ("FAILED", "INVALID_XLSX", None))
                    processor.process.assert_not_called()

    def test_iso_date_midnight_timestamp_and_time_keep_distinct_types(self):
        book = Workbook(iso_dates=True)
        samples = [date(2024, 2, 29), datetime(2024, 2, 29), datetime(2024, 2, 29, 12, 34, 56, 123000), time(8, 30)]
        book.active.append(samples)
        result = sanitize_xlsx(serialized(book), "regression", DemoProcessor())
        self.assertEqual(result.status, "READY")
        output = load_workbook(BytesIO(result.file_bytes))
        for expected, cell in zip(samples, output.active[1]):
            self.assertIs(type(cell.value), type(expected))
            self.assertEqual(cell.value, expected)
        output.close()

    def test_calc_literal_booleans_written_as_plain_values(self):
        result = sanitize_xlsx(self.calc_file(), "regression", DemoProcessor())
        self.assertEqual(result.status, "READY")
        output = load_workbook(BytesIO(result.file_bytes), data_only=False)
        self.assertEqual([(c.value, c.data_type) for c in output.active[1]], [(True, 'b'), (False, 'b')])
        output.close()
        with ZipFile(BytesIO(result.file_bytes)) as z:
            self.assertNotIn('docProps/custom.xml', z.namelist())
            self.assertNotIn(b'extCalcPr', z.read(WORKBOOK))
            self.assertNotIn(b'headerFooter', z.read(SHEET))

    def test_calc_cached_value_cannot_hide_a_formula(self):
        unsafe = [
            TRUE_CELL.replace('TRUE()', 'A2=1'), TRUE_CELL.replace('TRUE()', 'IF(1,TRUE(),FALSE())'),
            TRUE_CELL.replace('t="b"', 't="n"'), TRUE_CELL.replace('aca="false"', 't="shared" si="1"'),
            TRUE_CELL.replace('>1</v>', '>0</v>'), TRUE_CELL.replace('<v>1</v>', ''),
            TRUE_CELL.replace('<v>1</v>', '<v>1</v><v>0</v>'),
        ]
        for cell in unsafe:
            with self.subTest(cell=cell):
                result = sanitize_xlsx(self.calc_file(cell=cell), "regression", DemoProcessor())
                self.assertEqual(result.status, "FAILED")
                self.assertIsNone(result.file_bytes)

    def test_calc_compatibility_does_not_ignore_unknown_metadata(self):
        for options in (
            {"settings": SETTINGS.replace('ExcelA1', 'arbitrary payload')},
            {"settings": SETTINGS.replace('libreoffice.org', 'example.com')},
            {"settings": SETTINGS.replace('</ext>', '<other/></ext>')},
            {"header": '<oddHeader>기밀테스트-001</oddHeader>'},
            {"custom": CUSTOM.replace('/>', '><property name="기밀테스트-001"/></Properties>')},
        ):
            with self.subTest(options=options):
                result = sanitize_xlsx(self.calc_file(**options), "regression", DemoProcessor())
                self.assertEqual((result.status, result.reason, result.file_bytes),
                                 ("FAILED", "UNSUPPORTED_FEATURE", None))

    def test_worksheet_relationship_cannot_bypass_package_inspection(self):
        path = "xl/_rels/workbook.xml.rels"
        with ZipFile(BytesIO(self.basic)) as z:
            rels = z.read(path).replace(b'worksheets/sheet1.xml', b'styles.xml')
        result = sanitize_xlsx(replace_parts(self.basic, {path: rels}), "regression", DemoProcessor())
        self.assertEqual((result.status, result.reason, result.file_bytes), ("FAILED", "INVALID_XLSX", None))
