import re
import unittest
from types import SimpleNamespace

import numpy as np

from local_ai.detector import Detector, _trim_korean_particle
from local_ai.pipeline import LocalSession


class FakeTokenizer:
    def encode(self, text, add_special_tokens=True):
        offsets, ids = [(0, 0)], [0]
        for match in re.finditer(r'김민수(?:에게|의)?', text):
            offsets.extend([(match.start(), match.start() + 1), (match.start() + 1, match.end())])
            ids.extend([1, 2])
        return SimpleNamespace(ids=ids, attention_mask=[1] * len(ids), token_type_ids=[0] * len(ids), offsets=offsets, overflowing=[])


class FakeSession:
    def get_inputs(self):
        return [SimpleNamespace(name='input_ids')]

    def run(self, _, inputs):
        return [np.eye(3, dtype=np.float32)[inputs['input_ids']]]


class KoreanParticleTests(unittest.TestCase):
    def test_particles_trimmed_but_common_name_endings_preserved(self):
        for text, kind, expected in [
            ('김민수의', 'NAME', '김민수'), ('김민수에게', 'NAME', '김민수'),
            ('박지훈이', 'NAME', '박지훈'), ('김민수가', 'NAME', '김민수'),
            ('서울시 강남구의', 'ADDRESS', '서울시 강남구'),
            ('신유나', 'NAME', '신유나'), ('박세로', 'NAME', '박세로'),
            ('오사랑', 'NAME', '오사랑'), ('김민아', 'NAME', '김민아'),
            ('테헤란로', 'ADDRESS', '테헤란로'), ('김민이', 'NAME', '김민이'),
            ('남궁민이', 'NAME', '남궁민이'),
        ]:
            with self.subTest(text=text):
                result = _trim_korean_particle(text, {'start': 0, 'end': len(text), 'type': kind})
                self.assertEqual(text[result['start']:result['end']], expected)

    def test_no_trim_when_model_span_ends_inside_hangul_word(self):
        text = '김민수의번호'
        result = _trim_korean_particle(text, {'start': 0, 'end': 4, 'type': 'NAME'})
        self.assertEqual(result['end'], 4)

    def test_same_name_uses_same_alias_and_restores_without_particle(self):
        detector = Detector(None)
        detector._tokenizer = FakeTokenizer()
        detector._session = FakeSession()
        detector._np = np
        detector._labels = {'0': 'O', '1': 'B-SURNAME', '2': 'B-GIVENNAME'}
        detector.model_enabled = True
        with LocalSession(detector) as session:
            result = session.process('김민수의 번호를 김민수에게 전달해줘')
            self.assertEqual(result.text, '[이름_1]의 번호를 [이름_1]에게 전달해줘')
            self.assertEqual(session.restore('[이름_1]님께 전달').text, '김민수님께 전달')


if __name__ == '__main__':
    unittest.main()
