"""Real SLM path for server policy rules (#47). Needs LOCAL_SLM_MODEL_DIR (skipped otherwise).

Avoids app.policy so it also runs in the SLM venv (no signing/web stack there).
"""
import os
from types import SimpleNamespace

import pytest

from app.policy_apply import apply_policy_to_detector
from local_ai.detector import Detector
from local_ai.pipeline import LocalSession


def policy(version, rules):
    return SimpleNamespace(version=version, bundle_sha256=f"sha256:v{version}", types={},
                           rules=rules, dict=[], exclude=[])


@pytest.mark.skipif(not os.environ.get("LOCAL_SLM_MODEL_DIR"), reason="LOCAL_SLM_MODEL_DIR not set")
def test_real_slm_takes_bundle_rules_and_survives_bad_ones():
    det = Detector(None, slm_dir=os.environ["LOCAL_SLM_MODEL_DIR"])
    base = set(det._slm.label2id)
    rules = [{"id": "r-1", "label": "고객 ID", "description": "CU로 시작하는 6자리 고객번호",
              "grade": "C", "action": "삭제"}]
    applied = apply_policy_to_detector(det, policy(1, rules))
    assert det._slm.label2id["고객 ID"] == "r-1"
    assert base <= set(det._slm.label2id)  # base rules from the loaded policy stay
    with LocalSession(det) as session:
        result = session.process("고객 CU-882910 의 주문 내역 정리해줘")
    assert "CU-882910" not in result.text, result.text
    assert "CONFIDENTIAL" in result.detection_types
    # A duplicate label is rejected by the SLM: the server keeps v1.
    bad = rules + [{"id": "r-2", "label": "고객 ID", "grade": "S"}]
    assert apply_policy_to_detector(det, policy(2, bad)) is applied
    assert det._slm.label2id["고객 ID"] == "r-1"
