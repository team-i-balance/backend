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
    assert applied.slm_view[1]["고객 ID"] == "r-1"
    assert base <= set(applied.slm_view[1])  # base rules from the loaded policy stay
    assert set(det._slm.label2id) == base  # the shared SLM itself is unchanged
    with LocalSession(applied.bind(det)) as session:
        result = session.process("고객 CU-882910 의 주문 내역 정리해줘")
    assert "CU-882910" not in result.text, result.text
    assert "CONFIDENTIAL" in result.detection_types
    # A duplicate label is rejected by the SLM: the server keeps v1.
    bad = rules + [{"id": "r-2", "label": "고객 ID", "grade": "S"}]
    assert apply_policy_to_detector(det, policy(2, bad)) is applied


@pytest.mark.skipif(not os.environ.get("LOCAL_SLM_MODEL_DIR"), reason="LOCAL_SLM_MODEL_DIR not set")
def test_deploy_compile_check_matches_the_real_slm(monkeypatch):
    """#64: the pre-activation check gives the loaded SLM's verdict, with or without the model."""
    from app import detectors
    from app.policy_apply import check_policy

    ok = [{"id": "r-1", "label": "고객 ID", "grade": "C"}]
    cases = {
        "ok": ok,
        "duplicate_label": ok + [{"id": "r-2", "label": "고객 ID", "grade": "S"}],
        "fixed_label": [{"id": "r-1", "label": "사람 이름", "grade": "S"}],
    }
    expected = {"ok": None, "duplicate_label": "rule_label_conflict", "fixed_label": "rule_label_conflict"}
    monkeypatch.delitem(detectors._detectors, False, raising=False)
    assert {k: check_policy(policy(1, r)) for k, r in cases.items()} == expected  # model not loaded
    monkeypatch.setitem(detectors._detectors, False, Detector(None, slm_dir=os.environ["LOCAL_SLM_MODEL_DIR"]))
    assert {k: check_policy(policy(1, r)) for k, r in cases.items()} == expected  # the running SLM
