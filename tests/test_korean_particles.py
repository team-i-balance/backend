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
            # '이'/'가'는 NAME 3자 stem에서 trim하지 않음 — 이름 마지막 글자일 수 있음
            # e.g. 박지훈이 → 훈+이 로 잘릴 수 있어 보수적으로 유지
            ('박지훈이', 'NAME', '박지훈이'), ('김민수가', 'NAME', '김민수가'),
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

    def test_ambiguous_single_particle_preserved_on_short_name(self):
        """Codex review #12: '이'/'가'는 NAME 3자 stem에서 trim 금지.

        '김다솜이'처럼 일반 성씨(1자) + 3음절 이름인 경우 모델이 올바르게
        4음절 이름 전체를 잡은 것일 수 있으므로 보수적으로 유지한다.
        """
        for text, kind, expected in [
            ('김다솜이', 'NAME', '김다솜이'),  # Codex가 직접 언급한 케이스
            ('박지훈이', 'NAME', '박지훈이'),  # 동일 패턴
            ('이순재가', 'NAME', '이순재가'),  # 가 조사도 동일
            ('김민수가', 'NAME', '김민수가'),  # 수(받침없음)+가 → 문법상 틀리지만 보수적 유지
        ]:
            with self.subTest(text=text):
                result = _trim_korean_particle(text, {'start': 0, 'end': len(text), 'type': kind})
                self.assertEqual(text[result['start']:result['end']], expected)

    def test_ambiguous_single_particle_trimmed_on_long_name(self):
        """stem 4자 이상이면 '이'/'가'도 trim한다 — 이름이 4음절일 가능성 희박."""
        for text, kind, expected in [
            ('홍길동민이', 'NAME', '홍길동민'),   # stem 4자, 민(받침O) + 이
            ('김철수환이', 'NAME', '김철수환'),   # stem 4자, 환(받침O) + 이
        ]:
            with self.subTest(text=text):
                result = _trim_korean_particle(text, {'start': 0, 'end': len(text), 'type': kind})
                self.assertEqual(text[result['start']:result['end']], expected)

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
