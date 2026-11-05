import unittest

from local_ai.detector import Detector
from local_ai.pipeline import LocalSession


class ContextRulesTests(unittest.TestCase):
    def setUp(self):
        self.detector = Detector(None)

    def test_contextual_values_are_detected_entirely(self):
        cases = [
            ('주민등록번호: 991231-1234567', 'ID_NUMBER', '991231-1234567'),
            ('카드번호: 1111 2222 3333 4444', 'CARD', '1111 2222 3333 4444'),
            ('계좌번호: 1234-56-78*****', 'ACCOUNT', '1234-56-78*****'),
            ('사업자번호: 123-45-67890', 'BUSINESS_NUMBER', '123-45-67890'),
            ('password="samplePass123!"', 'PASSWORD', 'samplePass123!'),
            ('password=changeme', 'PASSWORD', 'changeme'),
            ('GENERIC_API_KEY=${KEY:-sampleSecret123456789}', 'API_KEY', 'sampleSecret123456789'),
        ]
        for text, kind, expected in cases:
            with self.subTest(kind=kind):
                self.assertIn((kind, expected), [(x['type'], text[x['start']:x['end']]) for x in self.detector.detect(text)])

    def test_negative_examples(self):
        for text in ('회의 코드 1234567890', 'API 키를 설정하세요', 'password=${PASSWORD}',
                     'api_key=<your-api-key>', 'password=[비밀번호_1]', 'access_token=$TOKEN'):
            with self.subTest(text=text):
                self.assertEqual(self.detector.detect(text), [])

    def test_password_is_not_restored(self):
        with LocalSession(self.detector) as session:
            result = session.process('password=samplePass123!')
            self.assertEqual(result.text, 'password=[비밀번호_1]')
            restored = session.restore(result.text)
            self.assertEqual(restored.text, result.text)
            self.assertEqual(restored.blocked, ('[비밀번호_1]',))


if __name__ == '__main__':
    unittest.main()
