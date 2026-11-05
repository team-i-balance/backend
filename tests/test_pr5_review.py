import unittest

from local_ai.detector import Detector
from local_ai.pipeline import LocalSession
from local_ai.preprocessing import normalize_for_detection


class CountingText(str):
    reads = 0

    def __getitem__(self, key):
        self.reads += 1
        return super().__getitem__(key)


class ReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        self.detector = Detector(None)

    def test_quoted_business_fields_and_prose(self):
        for text in ('{"사업자번호": "1234567891"}', "{'사업자번호': '1234567891'}", '사업자번호: 1234567891', '{"사업자번호":"123-45-67890"}'):
            with self.subTest(text=text):
                with LocalSession(self.detector) as session:
                    result = session.process(text)
                    self.assertIn('[사업자번호_1]', result.text)
                    self.assertNotIn('1234567891', result.text)
                    self.assertNotIn('123-45-67890', result.text)
        self.assertEqual(self.detector.detect('사업자번호를 알려줘. 회의번호 1234567891'), [])

    def test_contextual_secrets_take_precedence_over_provider_pattern(self):
        cases = [('access_token=', 'AIza' + 'A' * 30, '토큰'),
                 ('Authorization: Bearer ', 'AIza' + 'A' * 30, '토큰'),
                 ('password=', 'AIza' + 'A' * 30, '비밀번호'),
                 ('password=', 'sk-' + 'A' * 30, '비밀번호')]
        for prefix, value, label in cases:
            with self.subTest(prefix=prefix, label=label):
                with LocalSession(self.detector) as session:
                    result = session.process(prefix + value)
                    token = f'[{label}_1]'
                    self.assertEqual(result.text, prefix + token)
                    self.assertEqual(session.restore(token).blocked, (token,))
        provider_only = 'AIza' + 'A' * 30
        with LocalSession(self.detector) as session:
            self.assertEqual(session.process(provider_only).text, '[API키_1]')

    def test_zero_width_runs_are_scanned_in_linear_work(self):
        for prefix, suffix, expected in [('1', '2', '12'), ('a', 'b', 'a' + '\u200b' * 600 + 'b')]:
            with self.subTest(prefix=prefix):
                text = CountingText(prefix + '\u200b' * 600 + suffix)
                normalized, indexes = normalize_for_detection(text)
                self.assertEqual(normalized, expected)
                self.assertLess(text.reads, 20 * len(text))
                self.assertEqual(len(normalized), len(indexes))
                if prefix == '1':
                    self.assertEqual(indexes, [0, len(text)-1])
                else:
                    self.assertEqual(indexes, list(range(len(text))))


if __name__ == '__main__':
    unittest.main()
