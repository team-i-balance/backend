import unittest
from local_ai.detector import Detector, DetectionError
from local_ai.pipeline import LocalSession
from local_ai.pseudonym import PseudonymSession, PseudonymError


def span(text, value, kind, after=0):
    start = text.index(value, after)
    return {'start': start, 'end': start + len(value), 'type': kind}


class PseudonymTests(unittest.TestCase):
    def test_consistency_different_values_and_session_isolation(self):
        text = '김민수, 김민수, 이지은'
        spans = [span(text, '김민수', 'NAME'), span(text, '김민수', 'NAME', 4), span(text, '이지은', 'NAME')]
        a = PseudonymSession()
        self.assertEqual(a.pseudonymize(text, spans), '[이름_1], [이름_1], [이름_2]')
        b = PseudonymSession()
        self.assertEqual(b.pseudonymize('이지은', [span('이지은', '이지은', 'NAME')]), '[이름_1]')
        a.close()
        with self.assertRaises(PseudonymError): a.pseudonymize(text, spans)

    def test_collision_duplicate_and_invalid_spans(self):
        text = '[이름_1] 김민수'
        d = span(text, '김민수', 'NAME')
        self.assertEqual(PseudonymSession().pseudonymize(text, [d,d]), '[이름_1] [이름_2]')
        with self.assertRaises(PseudonymError):
            PseudonymSession().pseudonymize(text, [dict(start=0, end=999, type='NAME')])
        with self.assertRaises(PseudonymError):
            PseudonymSession().pseudonymize(text, [d, dict(start=d['start'], end=d['end'], type='ADDRESS')])

    def test_reinspection_and_incomplete_coverage(self):
        session = LocalSession(Detector(None))
        result = session.process('연락: 010-1234-5678, user@example.com')
        self.assertNotIn('010-1234-5678', result.text)
        self.assertNotIn('user@example.com', result.text)
        self.assertEqual(result.remaining, ())
        self.assertEqual(result.coverage, 'rules_only_incomplete')
        session.close()
        with self.assertRaises(RuntimeError): session.process('hello')

    def test_fail_on_detection_error(self):
        class Failed:
            model_enabled = True
            def detect(self, text): raise DetectionError('failed')
        with self.assertRaises(DetectionError): LocalSession(Failed()).process('test')

    def test_restore_current_session_and_secrets(self):
        text = '사업자번호 123-45-67891 API_KEY=TEST_KEY_1234 전화 010-1234-5678'
        with LocalSession(Detector(None)) as session:
            result = session.process(text)
            self.assertNotIn('123-45-67891', result.text)
            self.assertNotIn('TEST_KEY_1234', result.text)
            self.assertIn('[사업자번호_1]', result.text)
            self.assertIn('[API키_1]', result.text)
            restored = session.restore('[사업자번호_1] [API키_1] [전화번호_1] [이름_99]')
            self.assertIn('123-45-67891', restored.text)
            self.assertIn('010-1234-5678', restored.text)
            self.assertNotIn('TEST_KEY_1234', restored.text)
            self.assertEqual(restored.blocked, ('[API키_1]',))
            self.assertEqual(restored.unknown, ('[이름_99]',))
        with self.assertRaises(RuntimeError): session.restore('[사업자번호_1]')

    def test_sessions_do_not_share_mapping(self):
        first, second = LocalSession(Detector(None)), LocalSession(Detector(None))
        first.process('api_key=TEST_KEY_1234')
        result = second.restore('[API키_1]')
        self.assertEqual(result.unknown, ('[API키_1]',))
        first.close(); second.close()

    def test_missing_model_fails_closed(self):
        with self.assertRaises(DetectionError): Detector('/no/such/model/path')


if __name__ == '__main__': unittest.main()
