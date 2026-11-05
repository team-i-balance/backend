"""Korean structured rules (local_ai/kr_rules.py). All numbers are fake; checksums are computed."""
import unittest

from app.grading import decide_grade
from app.schemas import Grade
from local_ai.detector import Detector
from local_ai.kr_rules import id_checksum_ok, kr_structured_detections, luhn_ok
from local_ai.pipeline import LocalSession
from local_ai.pseudonym import PseudonymError


def id_number(prefix12, valid=True):
    return next(prefix12 + str(d) for d in range(10) if id_checksum_ok(prefix12 + str(d)) == valid)


def card(prefix):
    return next(prefix + str(d) for d in range(10) if luhn_ok(prefix + str(d)))


def dash_id(n):
    return n[:6] + '-' + n[6:]


def group4(n, sep=' '):
    return sep.join(n[i:i + 4] for i in range(0, len(n), 4))


RRN = id_number('900101123456')           # checksum ok
RRN_2020 = id_number('900101123456', False)  # post-2020 style: no checksum
FRN = id_number('850315512345')
VISA = card('411111111111111')
MASTER = card('555555555555444')
AMEX = card('37828224631000')
AMEX_FMT = AMEX[:4] + '-' + AMEX[4:10] + '-' + AMEX[10:]


class KrRulesTests(unittest.TestCase):
    def setUp(self):
        self.detector = Detector(None)

    def matched(self, text):
        return [(x['type'], text[x['start']:x['end']]) for x in self.detector.detect(text)]

    def test_positive(self):
        cases = [
            (f'주민번호 {dash_id(RRN)} 입니다', 'ID_NUMBER', dash_id(RRN)),
            (f'{dash_id(RRN_2020)} (2020년 이후 발급, 체크섬 무의미)', 'ID_NUMBER', dash_id(RRN_2020)),
            (f'외국인등록번호: {dash_id(FRN)}', 'ID_NUMBER', dash_id(FRN)),
            (f'주민 {RRN} 확인', 'ID_NUMBER', RRN),
            (f'카드 {group4(VISA)} 로 결제', 'CARD', group4(VISA)),
            (group4(MASTER, '-'), 'CARD', group4(MASTER, '-')),
            (f'아멕스 {AMEX_FMT}', 'CARD', AMEX_FMT),
            ('신한 110-123-456789 로 입금해줘', 'ACCOUNT', '110-123-456789'),
            ('카카오뱅크 3333-01-1234567', 'ACCOUNT', '3333-01-1234567'),
            ('계좌 1002123456789 예금주 홍길동', 'ACCOUNT', '1002123456789'),
            ('서버 192.168.0.10 접속 안 됨', 'IP_ADDRESS', '192.168.0.10'),
            ('접속지 203.0.113.7.', 'IP_ADDRESS', '203.0.113.7'),
            ('ping 2001:db8::1', 'IP_ADDRESS', '2001:db8::1'),
            ('DB_PASSWORD=Sup3r!Secret', 'PASSWORD', 'Sup3r!Secret'),
            ('{"user": "hong", "password": "hunter2"}', 'PASSWORD', 'hunter2'),
            ('비밀번호는 qwer1234!야', 'PASSWORD', 'qwer1234!'),
            ('비번: abcd1234', 'PASSWORD', 'abcd1234'),
            ('pw: zx9!kq', 'PASSWORD', 'zx9!kq'),
            ('생년월일: 1990-01-02', 'DOB', '1990-01-02'),
            ('생일은 1990년 1월 2일', 'DOB', '1990년 1월 2일'),
            ('DOB 19900102', 'DOB', '19900102'),
            ('1990.01.02생', 'DOB', '1990.01.02'),
        ]
        for text, kind, value in cases:
            with self.subTest(text=text):
                self.assertIn((kind, value), self.matched(text))

    def test_negative(self):
        cases = [
            '비밀번호 변경 방법 알려줘',
            '비밀번호 8자리 이상으로 설정',
            'PASSWORD_MIN_LENGTH=8',
            'password: ${DB_PASSWORD}',
            'DB_PASSWORD=${DB_PASSWORD}',
            '버전 v1.2.3.4 배포',
            '버전 1.2.3.4 배포',
            '회의는 12:30:45 에 시작',
            '2024-11-04 에 결제한 1,234,567원',
            '결제 금액 12,345,678원',
            '회의 날짜 2024.11.04',
            'localhost 127.0.0.1 로 띄움',
            '주문번호 2024110412345 조회',
            f'주문번호 {VISA} 조회',
            f'운송장 {VISA}',
            f'운송장번호 {RRN}',
            '송장번호 6012345678901 배송중',
            '그냥 숫자 1002123456789',
            'uuid 550e8400-e29b-41d4-a716-446655440000',
            'x[a::b] slice',
            '그냥 숫자 9001011234567',
            f'카드 주문번호 {VISA}',
            '신한 주문번호 110-123-456789',
            '비밀번호: {{SECRET}}',
            'version: 1.2.3.4',
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(self.matched(text), [])

    def test_reinspection_stays_clean(self):
        # Masked values are shorter and hold label words; re-inspection must not find new spans.
        texts = [
            '생년월일 1990-01-02, 주문일 2024-01-01',
            '계좌 ０１０-1234-5678',
            '카드 ４１１１ 1111 1111 1111',
            '신한 110-123-456789 그리고 1234567890',
            '비밀번호: abc123; 생년월일 1990-01-02',
        ]
        for text in texts:
            with self.subTest(text=text):
                with LocalSession(Detector(None)) as session:
                    self.assertEqual(session.process(text).remaining, ())
        self.assertEqual(self.matched('생년월일 1990-01-02, 주문일 2024-01-01'), [('DOB', '1990-01-02')])

    def test_no_cross_type_overlap(self):
        # Card digits must not also become phone/business numbers; account must not take a phone.
        texts = [
            f'카드 {VISA} 사업자번호 없음',
            f'카드번호: {group4(VISA)} 연락처 010-1234-5678',
            '신한 계좌 010-1234-5678 로 입금',
            'postgres://admin:s3cretpw@db.internal:5432/app',
            f'생년월일 {dash_id(RRN)}',
            'password=sk-abcdefghijklmnopqrstuvwx',
            'pw=hong@example.com',
        ]
        for text in texts:
            with self.subTest(text=text):
                spans = sorted(self.detector.detect(text), key=lambda x: x['start'])
                for a, b in zip(spans, spans[1:]):
                    self.assertFalse(a['end'] > b['start'] and a['type'] != b['type'], spans)
        self.assertEqual(self.matched(f'생년월일 {dash_id(RRN)}'), [('ID_NUMBER', dash_id(RRN))])

    def test_partial_overlap_fails_closed(self):
        # Dropping the password would leak 'abc'/'xyz'; keep it so pseudonymization refuses.
        spans = self.detector.detect('pw=abc010-1234-5678xyz')
        self.assertIn({'start': 3, 'end': 22, 'type': 'PASSWORD'}, spans)
        with self.assertRaises(PseudonymError):
            LocalSession(Detector(None)).process('pw=abc010-1234-5678xyz')

    def test_order_word_elsewhere_does_not_hide_card(self):
        self.assertEqual(self.matched(f'주문 완료, 카드 {VISA}'), [('CARD', VISA)])

    def test_function_contract(self):
        text = f'카드 {VISA} / 서버 10.0.0.5'
        spans = kr_structured_detections(text)
        self.assertEqual([(s['type'], text[s['start']:s['end']]) for s in spans],
                         [('CARD', VISA), ('IP_ADDRESS', '10.0.0.5')])
        self.assertTrue(all(set(s) == {'start', 'end', 'type'} for s in spans))
        self.assertEqual(kr_structured_detections(''), [])

    def test_end_to_end_pseudonymize(self):
        text = (f'주민 {dash_id(RRN)}, 카드 {group4(VISA)}, 신한 110-123-456789, '
                f'서버 192.168.0.10, 생년월일 1990-01-02, 비밀번호: Sup3r!Secret')
        with LocalSession(Detector(None)) as session:
            result = session.process(text)
            self.assertEqual(result.remaining, ())
            self.assertEqual(result.text, '주민 [식별번호_1], 카드 [카드번호_1], 신한 [계좌번호_1], '
                                          '서버 [IP주소_1], 생년월일 [생년월일_1], 비밀번호: [비밀번호_1]')
            self.assertEqual(set(result.detection_types),
                             {'ID_NUMBER', 'CARD', 'ACCOUNT', 'IP_ADDRESS', 'DOB', 'PASSWORD'})
            restored = session.restore(result.text)
            self.assertEqual(restored.blocked, ('[비밀번호_1]',))
            self.assertIn(dash_id(RRN), restored.text)

    def test_grades(self):
        self.assertEqual(decide_grade([t for t, _ in self.matched('비밀번호: Sup3r!Secret')]), Grade.confidential)
        for text in (f'주민번호 {dash_id(RRN)}', f'카드 {group4(VISA)}', '신한 110-123-456789 입금',
                     '서버 192.168.0.10', '생년월일 1990-01-02'):
            with self.subTest(text=text):
                types = [t for t, _ in self.matched(text)]
                self.assertTrue(types)
                self.assertEqual(decide_grade(types), Grade.sensitive)


if __name__ == '__main__':
    unittest.main()
