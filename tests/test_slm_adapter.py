"""local_ai/slm integration: overlap handling, policy-graded types, grading.

The fake SLM below needs no model. Set LOCAL_SLM_MODEL_DIR to a local SLM folder
(team-i-balance/slm release) to also run the real-model test at the bottom.
"""
import os
import unittest

from app.grading import decide_grade
from app.schemas import Grade
from local_ai.detector import Detector
from local_ai.pipeline import LocalSession
from local_ai.slm import SlmSpanDetector, resolve_overlaps


def span(text, value, kind, after=0, rule_id='R00'):
    start = text.index(value, after)
    return {'start': start, 'end': start + len(value), 'type': kind, 'rule_id': rule_id, 'score': 0.9}


class FakeSlm:
    """Finds the given (value, type, rule_id) strings in whatever text it is asked about,
    so the pipeline's re-inspection of the pseudonymized text sees fresh offsets."""

    def __init__(self, spans):
        self.items = spans

    def detect(self, text):
        found = [span(text, v, k, rule_id=r) for v, k, r in self.items if v in text]
        return resolve_overlaps(found)


def detector_with(spans):
    det = Detector(None)
    det._slm = FakeSlm(spans)
    det.model_enabled = True
    return det


class SlmAdapterTests(unittest.TestCase):
    def test_name_inside_confidential_is_absorbed(self):
        text = '박서윤 대리 근태 불량으로 경고 징계 내렸어'
        spans = [('박서윤', 'NAME', 'P-NAME'),
                 ('박서윤 대리 근태 불량으로 경고 징계', 'INTERNAL', 'R07'),
                 ('근태 불량으로 경고 징계', 'SENSITIVE', 'P-SENS')]
        with LocalSession(detector_with(spans)) as s:
            r = s.process(text)
        # One merged span, typed by the strongest (SENSITIVE > INTERNAL > NAME).
        self.assertEqual(r.text, '[민감정보_1] 내렸어')
        self.assertEqual(decide_grade(r.detection_types), Grade.confidential)

    def test_rule_engine_span_keeps_extent_inside_slm_span(self):
        text = '담당 김민수 010-1234-5678 연락처로 계약 단가 15% 인하 통보'
        spans = [('김민수 010-1234-5678 연락처로', 'NAME', 'P-NAME'),
                 ('계약 단가 15% 인하', 'INTERNAL', 'R05')]
        with LocalSession(detector_with(spans)) as s:
            r = s.process(text)
        self.assertIn('[전화번호_1]', r.text)
        self.assertNotIn('010-1234-5678', r.text)
        self.assertNotIn('계약 단가 15% 인하', r.text)
        self.assertEqual(decide_grade(r.detection_types), Grade.sensitive)
        self.assertEqual(r.coverage, 'model_and_rules')

    def test_grade_c_slm_span_absorbs_phone(self):
        text = '010-1234-5678'
        with LocalSession(detector_with([(text, 'CONFIDENTIAL', 'R10')])) as s:
            r = s.process(text)
        self.assertEqual(r.text, '[기밀_1]')
        self.assertEqual(decide_grade(r.detection_types), Grade.confidential)

    def test_secret_keeps_grade_and_no_restore(self):
        text = 'api_key=TEST_KEY_1234 확인해줘'
        with LocalSession(detector_with([('TEST_KEY_1234 확인', 'CONFIDENTIAL', 'R11')])) as s:
            r = s.process(text)
            self.assertIn('[API키_1]', r.text)
            self.assertEqual(s.restore('[API키_1]').blocked, ('[API키_1]',))
        self.assertEqual(decide_grade(r.detection_types), Grade.confidential)

    def test_aegis_password_beats_slm_name_and_chains_merge(self):
        det = detector_with([('hunter2', 'NAME', 'P-NAME')])
        aegis = [{'start': 0, 'end': 7, 'type': 'PASSWORD'}]
        self.assertEqual([s['type'] for s in det._add_slm_spans('hunter2', aegis)], ['PASSWORD'])
        det = detector_with([('abc', 'CONFIDENTIAL', 'R01'), ('hij', 'INTERNAL', 'R02')])
        spans = det._add_slm_spans('abcdefghij', [{'start': 0, 'end': 10, 'type': 'NAME'}])
        self.assertEqual([(s['start'], s['end'], s['type']) for s in spans], [(0, 10, 'CONFIDENTIAL')])

    def test_policy_grade_decides_type(self):
        slm = SlmSpanDetector.__new__(SlmSpanDetector)
        slm.fixed = []
        slm.set_policy([{'id': 'X1', 'label': '미공개 출시 일정', 'description': '', 'grade': 'S', 'action': '대체'},
                        {'id': 'X2', 'label': '인수 협상', 'description': '', 'grade': 'C', 'action': '삭제'}])
        self.assertEqual(slm._type('X1'), 'INTERNAL')
        self.assertEqual(slm._type('X2'), 'CONFIDENTIAL')
        self.assertEqual(slm._type('P-NAME'), 'NAME')

    def test_duplicate_or_fixed_label_rejected(self):
        slm = SlmSpanDetector.__new__(SlmSpanDetector)
        slm.fixed = [{'id': 'P-SENS', 'label': '개인 민감정보', 'grade': 'C'}]
        with self.assertRaises(ValueError):
            slm.set_policy([{'id': 'X1', 'label': '개인 민감정보', 'description': '', 'grade': 'S'}])
        with self.assertRaises(ValueError):
            slm.set_policy([{'id': 'X1', 'label': '계약 금액', 'grade': 'S'},
                            {'id': 'X2', 'label': '계약 금액', 'grade': 'C'}])

    def test_long_unpunctuated_text_is_windowed(self):
        import re
        slm = SlmSpanDetector.__new__(SlmSpanDetector)
        slm.splitter = lambda t: ((m.group(), m.start(), m.end()) for m in re.finditer(r'\S+', t))
        text = ' '.join(f'w{i}' for i in range(450))
        chunks = slm._chunks(text)
        self.assertGreater(len(chunks), 2)
        self.assertTrue(all(len(c.split()) <= 200 for _, c in chunks))
        for off, c in chunks:
            self.assertEqual(text[off:off + len(c)], c)
        self.assertTrue(text.endswith(chunks[-1][1]))  # tail is covered

    def test_grading_of_slm_types(self):
        self.assertEqual(decide_grade(['INTERNAL']), Grade.sensitive)
        self.assertEqual(decide_grade(['CONFIDENTIAL']), Grade.confidential)
        self.assertEqual(decide_grade(['SENSITIVE', 'NAME']), Grade.confidential)


@unittest.skipUnless(os.environ.get('LOCAL_SLM_MODEL_DIR'), 'LOCAL_SLM_MODEL_DIR not set')
class RealSlmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.det = Detector(None, slm_dir=os.environ['LOCAL_SLM_MODEL_DIR'])

    def check(self, text, grade):
        with LocalSession(self.det) as s:
            r = s.process(text)
        self.assertEqual(decide_grade(r.detection_types), grade, (text, r.text))
        return r.text

    def test_examples(self):
        masked = self.check('김민지 고객님 배송지 서울시 마포구 월드컵북로4길 17, 3층으로 변경 안내문 써줘', Grade.sensitive)
        self.assertNotIn('김민지', masked)
        self.assertNotIn('월드컵북로', masked)
        self.check('3분기 잠정 매출 1,240억, 영업이익 87억인데 IR 문구 다듬어줘', Grade.confidential)
        self.check('박서윤 대리 근태 불량으로 경고 징계 내렸어. 통보 메일 써줘', Grade.confidential)
        self.assertEqual(self.check('오로라 사진 여행 코스 추천해줘', Grade.public), '오로라 사진 여행 코스 추천해줘')


if __name__ == '__main__':
    unittest.main()
