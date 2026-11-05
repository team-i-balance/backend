import unittest

from local_ai.sensitive_loop import SensitiveTransformLoop


class SequenceDetector:
    model_enabled = True

    def __init__(self, functions):
        self.functions = iter(functions)

    def detect(self, text):
        return next(self.functions)(text)


def span(text, value, kind):
    start = text.index(value)
    return {'start': start, 'end': start + len(value), 'type': kind}


class SensitiveLoopTests(unittest.TestCase):
    def test_residual_is_added_and_final_mapping_restores(self):
        detector = SequenceDetector([
            lambda t: [span(t, '김민수', 'NAME')],
            lambda t: [span(t, '010-1234-5678', 'PHONE')],
            lambda t: [],
        ])
        loop = SensitiveTransformLoop(detector)
        result = loop.process('김민수: 010-1234-5678')
        self.assertEqual((result.status, result.iterations), ('checked', 2))
        self.assertEqual(result.text, '[이름_1]: [전화번호_1]')
        self.assertEqual(loop.restore(result.text).text, '김민수: 010-1234-5678')
        loop.close()
        with self.assertRaises(RuntimeError):
            loop.restore(result.text)

    def test_generalization_escalates_when_detected(self):
        detector = SequenceDetector([
            lambda t: [span(t, '1990-01-02', 'DOB')],
            lambda t: [span(t, '1990년', 'DOB')],
            lambda t: [],
        ])
        loop = SensitiveTransformLoop(detector)
        result = loop.process('생일: 1990-01-02')
        self.assertEqual((result.status, result.iterations, result.text), ('checked', 2, '생일: [생년월일_1]'))

    def test_secret_is_blocked_and_not_returned(self):
        detector = SequenceDetector([lambda t: [span(t, 'abc123', 'PASSWORD')]])
        result = SensitiveTransformLoop(detector).process('password=abc123')
        self.assertEqual((result.status, result.text), ('blocked', None))

    def test_slm_sensitive_type_is_confidential(self):
        detector = SequenceDetector([lambda t: [span(t, '가상민감정보', 'SENSITIVE')]])
        result = SensitiveTransformLoop(detector).process('가상민감정보')
        self.assertEqual((result.status, result.text, result.reason), ('blocked', None, 'confidential_input'))

    def test_limit_requires_review(self):
        detector = SequenceDetector([
            lambda t: [],
            lambda t: [span(t, '김민수', 'NAME')],
            lambda t: [span(t, 'user@example.com', 'EMAIL')],
        ])
        result = SensitiveTransformLoop(detector, max_iterations=2).process('김민수 user@example.com')
        self.assertEqual((result.status, result.reason, result.text), ('review', 'iteration_limit', None))

    def test_incomplete_detector_never_reports_checked(self):
        detector = SequenceDetector([lambda t: [], lambda t: []])
        detector.model_enabled = False
        result = SensitiveTransformLoop(detector).process('일반 문장')
        self.assertEqual((result.status, result.reason), ('review', 'incomplete_detector'))

    def test_overlap_requires_review(self):
        detector = SequenceDetector([lambda t: [span(t, '12345', 'PHONE'), span(t, '2345', 'ACCOUNT')]])
        result = SensitiveTransformLoop(detector).process('12345')
        self.assertEqual((result.status, result.text), ('review', None))

    def test_explicit_deletion(self):
        detector = SequenceDetector([lambda t: [span(t, 'user@example.com', 'EMAIL')], lambda t: []])
        loop = SensitiveTransformLoop(detector, delete_types={'EMAIL'})
        result = loop.process('메일: user@example.com')
        self.assertEqual((result.status, result.text), ('checked', '메일: '))
        self.assertEqual(loop.restore('[이메일_1]').text, '[이메일_1]')

    def test_deletion_cannot_create_a_literal_matching_an_issued_alias(self):
        text = '[이름_user@example.com1] 김민수'
        spans = [span(text, 'user@example.com', 'EMAIL'), span(text, '김민수', 'NAME')]
        loop = SensitiveTransformLoop(SequenceDetector([lambda t: [], lambda t: []]), delete_types={'EMAIL'})
        result = loop.process(text, spans)
        self.assertEqual((result.status, result.text, result.reason), ('review', None, 'alias_collision'))
        with self.assertRaises(RuntimeError):
            loop.restore('[이름_1]')

    def test_generalization_does_not_create_reversible_alias(self):
        detector = SequenceDetector([lambda t: [span(t, '1990-01-02', 'DOB')], lambda t: []])
        loop = SensitiveTransformLoop(detector)
        result = loop.process('생일: 1990-01-02')
        self.assertEqual(result.text, '생일: 1990년')
        self.assertEqual(loop.restore('[생년월일_1]').text, '[생년월일_1]')

    def test_c_grade_input_is_blocked(self):
        detector = SequenceDetector([])
        result = SensitiveTransformLoop(detector).process('hello', [{'start': 0, 'end': 5, 'type': 'CONFIDENTIAL', 'grade': 'C'}])
        self.assertEqual(result.status, 'blocked')

    def test_detector_error_never_returns_output(self):
        def fail(_text):
            raise RuntimeError('test failure')
        result = SensitiveTransformLoop(SequenceDetector([fail])).process('hello')
        self.assertEqual((result.status, result.text, result.reason), ('review', None, 'detection_failed'))

    def test_detected_confidential_residual_is_blocked(self):
        detector = SequenceDetector([
            lambda t: [],
            lambda t: [{'start': 0, 'end': 5, 'type': 'CONFIDENTIAL', 'grade': 'C'}],
        ])
        result = SensitiveTransformLoop(detector).process('hello')
        self.assertEqual((result.status, result.text, result.reason), ('blocked', None, 'confidential_residual'))

    def test_external_spans_and_literal_alias_do_not_collide(self):
        text = '[이름_1] 김민수 김민수'
        first = text.index('김민수')
        second = text.rindex('김민수')
        incoming = [{'start': first, 'end': first + 3, 'type': 'NAME'},
                    {'start': second, 'end': second + 3, 'type': 'NAME'}]
        loop = SensitiveTransformLoop(SequenceDetector([lambda t: [], lambda t: []]))
        result = loop.process(text, incoming)
        self.assertEqual(result.text, '[이름_1] [이름_2] [이름_2]')
        self.assertEqual(loop.restore(result.text).text, text)

    def test_residual_crossing_alias_requires_review(self):
        detector = SequenceDetector([
            lambda t: [span(t, '김민수', 'NAME')],
            lambda t: [{'start': 0, 'end': len(t), 'type': 'NAME'}],
        ])
        result = SensitiveTransformLoop(detector).process('김민수님')
        self.assertEqual((result.status, result.text, result.reason), ('review', None, 'ambiguous_residual'))


if __name__ == '__main__':
    unittest.main()
