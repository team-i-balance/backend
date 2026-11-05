import unittest
from local_ai.detector import Detector, _valid_business_number


def gen_business(prefix='123456789'):
    return next(prefix + str(d) for d in range(10) if _valid_business_number(prefix+str(d)))

class RuleTests(unittest.TestCase):
 def setUp(self): self.detector=Detector(None)
 def matched(self,text):
    return [(x['type'],text[x['start']:x['end']]) for x in self.detector.detect(text)]
 def test_business(self):
    n=gen_business(); formatted=n[:3]+'-'+n[3:5]+'-'+n[5:]
    self.assertEqual(self.matched('사업자등록번호: '+n), [('BUSINESS_NUMBER',n)])
    self.assertEqual(self.matched('번호: '+formatted), [('BUSINESS_NUMBER',formatted)])
    self.assertEqual(self.matched('단순 숫자 '+n),[])
    bad=formatted[:-1]+str((int(formatted[-1])+1)%10)
    self.assertEqual(self.matched('번호 '+bad),[])
 def test_keys(self):
    for text, expected in [('API_KEY=TEST_KEY_1234567890',('API_KEY','TEST_KEY_1234567890')), ('"api_key": "hello world"', ('API_KEY','hello world')),('Authorization: Bearer TEST_TOKEN_1234',('ACCESS_TOKEN','TEST_TOKEN_1234')),('ACCESS_TOKEN=TEST_TOKEN_1234',('ACCESS_TOKEN','TEST_TOKEN_1234'))]:
     self.assertEqual(self.matched(text),[expected],text)
 def test_placeholders(self):
    self.assertEqual(self.matched('api_key=[API키_1] Authorization: Bearer [토큰_1]'),[])
 def test_negative(self):
    self.assertEqual(self.matched('API 키와 사업자번호를 알려줘. 그냥 1234567890 숫자다.'),[])

if __name__=='__main__': unittest.main()
