import unittest

from local_ai.detector import Detector
from local_ai.pipeline import LocalSession
from local_ai.preprocessing import normalize_for_detection, restore_detection_offsets


class PreprocessingTests(unittest.TestCase):
    def test_offsets_cover_original_including_internal_removed_character(self):
        original = '📌 연락처: ０１０－１\u200b２３４－５６７８.'
        normalized, offsets = normalize_for_detection(original)
        value = '010-1234-5678'
        start = normalized.index(value)
        span = restore_detection_offsets([{'start': start, 'end': start + len(value), 'type': 'PHONE'}], offsets)[0]
        self.assertEqual(original[span['start']:span['end']], '０１０－１\u200b２３４－５６７８')

    def test_non_numeric_joiner_and_hyphen_are_preserved(self):
        text = '가\u200d나와 A－B'
        self.assertEqual(normalize_for_detection(text)[0], text)

    def test_masking_restores_only_the_original_phone_value(self):
        text = '📌 연락처: ０１０－１\u200b２３４－５６７８.'
        with LocalSession(Detector(None)) as session:
            result = session.process(text)
            self.assertEqual(result.text, '📌 연락처: [전화번호_1].')
            self.assertEqual(session.restore(result.text).text, text)

    def test_invalid_offsets_fail(self):
        with self.assertRaises(ValueError):
            restore_detection_offsets([{'start': 0, 'end': 2, 'type': 'PHONE'}], [0])


if __name__ == '__main__':
    unittest.main()
