"""The selected format section controls numeric/date conversion before DLP."""

from datetime import datetime, timedelta
from io import BytesIO
import unittest
import warnings

from openpyxl import Workbook, load_workbook
from openpyxl.utils.datetime import CALENDAR_MAC_1904, CALENDAR_WINDOWS_1900

from file_sanitizer import sanitize_xlsx
from file_sanitizer.__main__ import DemoProcessor


class RecordingProcessor(DemoProcessor):
    def process(self, session_id, segments):
        self.texts = {s.id: s.text for s in segments}
        return super().process(session_id, segments)


class ConditionalDateTests(unittest.TestCase):
    def check_value(self, epoch, value, fmt, expected):
        book = Workbook()
        book.epoch = epoch
        book.active["B2"] = value
        book.active["B2"].number_format = fmt
        stream = BytesIO()
        book.save(stream)
        book.close()
        processor = RecordingProcessor()
        # openpyxl may temporarily coerce a large number to an invalid date;
        # the raw XML number must remain recoverable before inspection.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="Cell .* is marked as a date")
            result = sanitize_xlsx(stream.getvalue(), "conditional-date", processor)
        self.assertEqual((result.status, result.grade), ("READY", "O"))
        self.assertEqual(processor.texts["s1:B2"], str(expected))
        output = load_workbook(BytesIO(result.file_bytes))
        try:
            actual = output.active["B2"].value
            self.assertEqual((type(actual), actual), (type(expected), expected))
        finally:
            output.close()

    def test_inactive_date_sections_cannot_change_numbers(self):
        for epoch in (CALENDAR_WINDOWS_1900, CALENDAR_MAC_1904):
            for value, fmt in (
                (12345, "[<0]yyyy-mm-dd;0"),
                (12345.5, "[<0]yyyy-mm-dd;0.0"),
                (123456789012, "[<0]yyyy-mm-dd;0"),
                (-12345, "[>=0]yyyy-mm-dd;0"),
                (-12345, "yyyy-mm-dd;0;0"),
                (0, "yyyy-mm-dd;yyyy-mm-dd;0"),
                (12345, "[<12345]yyyy-mm-dd;0"),
            ):
                with self.subTest(epoch=epoch, value=value, fmt=fmt):
                    self.check_value(epoch, value, fmt, value)

    def test_active_date_section_is_used_even_when_first_section_is_numeric(self):
        for epoch in (CALENDAR_WINDOWS_1900, CALENDAR_MAC_1904):
            for value in (12345, 12345.5):
                expected = epoch + timedelta(days=value)
                for fmt in ("[<0]0;yyyy-mm-dd hh:mm", "[<12345]0;yyyy-mm-dd hh:mm"):
                    with self.subTest(epoch=epoch, value=value, fmt=fmt):
                        self.check_value(epoch, value, fmt, expected)

    def test_active_elapsed_section_keeps_duration(self):
        for epoch in (CALENDAR_WINDOWS_1900, CALENDAR_MAC_1904):
            with self.subTest(epoch=epoch):
                self.check_value(epoch, 1.5, "[<0]0;[h]:mm", timedelta(hours=36))
                self.check_value(epoch, 12345, "[<0][h]:mm;0", 12345)

    def test_date_detection_happens_before_the_privacy_processor(self):
        # Windows serial 61 follows Excel's fictitious leap day; Mac serial 0
        # is an actual calendar day. Neither should remain a bare number.
        self.check_value(CALENDAR_WINDOWS_1900, 61, "[<0]0;yyyy-mm-dd", datetime(1900, 3, 1))
        self.check_value(CALENDAR_MAC_1904, 0, "[<0]0;yyyy-mm-dd", datetime(1904, 1, 1))


if __name__ == "__main__":
    unittest.main()
