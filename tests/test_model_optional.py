"""Run with LOCAL_PII_MODEL_DIR set to an existing local model folder."""
import os
import socket
import unittest
from unittest.mock import patch
from local_ai.detector import Detector
from local_ai.pipeline import LocalSession

MODEL_DIR = os.environ.get('LOCAL_PII_MODEL_DIR')


@unittest.skipUnless(MODEL_DIR, 'set LOCAL_PII_MODEL_DIR for local model integration')
class ModelIntegrationTests(unittest.TestCase):
    def test_local_model_and_long_input(self):
        # Python-level connections are forbidden during model load and inference.
        with patch.object(socket.socket, 'connect', side_effect=RuntimeError('network disabled')):
            detector = Detector(MODEL_DIR, threads=2)
            text = ('공개 자료를 요약합니다. ' * 80) + ' 담당자: 김민수, 연락처: 010-1234-5678'
            with LocalSession(detector) as session:
                result = session.process(text)
            self.assertEqual(result.coverage, 'model_and_rules')
            self.assertNotIn('김민수', result.text)
            self.assertNotIn('010-1234-5678', result.text)


if __name__ == '__main__':
    unittest.main()
