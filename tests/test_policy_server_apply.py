"""Server-side policy application beyond on/off (#47): exclude, dict, grade, method, rules.

The real-SLM check is in test_policy_server_apply_slm.py (runs in the SLM venv too).
"""
import hashlib
import hmac
import json
import logging
import os

import pytest

from tests.test_file_api import api  # noqa: F401 (fixture)

from app.grading import decide_grade
from app.policy import ActivePolicy
from app.policy_apply import apply_policy_to_detector, compile_policy, value_hashes
from app.schemas import Grade
from local_ai.detector import Detector
from local_ai.pipeline import LocalSession
from local_ai.pseudonym import PseudonymSession
from local_ai.slm import SlmSpanDetector

PHONE = "010-1234-5678"
KEY = "org-test-key"


def sha(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def mac(value, key=KEY):
    return "hmac:" + hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()


def active(version=1, types=None, rules=None, dict_=None, exclude=None):
    return ActivePolicy(
        org="acme", version=version, keyid="k", rule_count=len(rules or []), rules=rules or [],
        types=types or {}, thresholds={}, expires_at=None, activated_at="t",
        bundle_sha256=f"sha256:v{version}", dict=dict_ or [], exclude=exclude or [],
    )


def found(det, text):
    return [(text[s["start"]:s["end"]], s["type"]) for s in det.detect(text)]


def masked(det, text):
    with LocalSession(det) as session:
        return session.process(text)


# --- hashes -------------------------------------------------------------------
def test_value_hashes_match_spec_formats():
    assert value_hashes("오로라", None) == (sha("오로라"),)
    assert value_hashes("오로라", KEY.encode()) == (sha("오로라"), mac("오로라"))


def test_bad_hash_entries_are_ignored_without_values_in_logs(caplog):
    with caplog.at_level(logging.WARNING, logger="app.policy_apply"):
        compiled = compile_policy(active(exclude=[{"h": "md5:abc"}, {"h": sha(PHONE)}, "x"]))
    assert compiled.exclude == {sha(PHONE)}
    assert "2 dict/exclude entries ignored" in caplog.text


# --- exclude --------------------------------------------------------------------
def test_exclude_sha256_drops_that_value_only():
    det = Detector(None)
    apply_policy_to_detector(det, active(exclude=[{"h": sha(PHONE)}]))
    assert found(det, f"대표번호 {PHONE}, 담당 010-9999-8888") == [("010-9999-8888", "PHONE")]


def test_exclude_hmac_uses_the_org_key(monkeypatch):
    monkeypatch.setenv("POLICY_VALUE_HASH_KEY", KEY)
    det = Detector(None)
    apply_policy_to_detector(det, active(exclude=[{"h": mac(PHONE)}]))
    assert found(det, f"대표번호 {PHONE}") == []


def test_exclude_hmac_without_key_is_ignored_with_warning(monkeypatch, caplog):
    monkeypatch.delenv("POLICY_VALUE_HASH_KEY", raising=False)
    det = Detector(None)
    with caplog.at_level(logging.WARNING, logger="app.policy_apply"):
        apply_policy_to_detector(det, active(exclude=[{"h": mac(PHONE)}]))
    assert found(det, f"대표번호 {PHONE}") == [(PHONE, "PHONE")]
    assert "1 hmac dict/exclude entries ignored" in caplog.text
    assert PHONE not in caplog.text and mac(PHONE) not in caplog.text


# --- dict -----------------------------------------------------------------------
def test_dict_word_found_with_particle_and_spaces():
    det = Detector(None)
    apply_policy_to_detector(det, active(dict_=[{"h": sha("프로젝트 오로라"), "type": "프로젝트 코드명"}]))
    assert found(det, "프로젝트 오로라는 다음 달 출시") == [("프로젝트 오로라", "INTERNAL")]
    assert found(det, "프로젝트, 오로라") == []  # punctuation does not join words


def test_dict_grade_c_is_confidential_and_off_type_is_skipped():
    entry = [{"h": sha("오로라"), "type": "미공개 실적"}]
    det = Detector(None)
    apply_policy_to_detector(det, active(types={"미공개 실적": {"on": True, "grade": "C"}}, dict_=entry))
    assert found(det, "오로라를 공유") == [("오로라", "CONFIDENTIAL")]
    assert decide_grade([t for _, t in found(det, "오로라를 공유")]) == Grade.confidential
    det2 = Detector(None)
    apply_policy_to_detector(det2, active(version=2, types={"미공개 실적": {"on": False}}, dict_=entry))
    assert found(det2, "오로라를 공유") == []


def test_dict_hmac_entry_and_word_limit(monkeypatch):
    monkeypatch.setenv("POLICY_VALUE_HASH_KEY", KEY)
    det = Detector(None)
    apply_policy_to_detector(det, active(dict_=[{"h": mac("메이플")}, {"h": sha("가 나 다 라 마")}]))
    assert found(det, "메이플에서") == [("메이플", "INTERNAL")]
    assert found(det, "가 나 다 라 마") == []  # longer than DICT_MAX_WORDS


def test_dict_word_absorbs_contained_spans_but_never_secrets():
    det = Detector(None)
    apply_policy_to_detector(det, active(dict_=[{"h": sha(f"오로라-{PHONE}")}, {"h": sha("Sup3r!Secret")}]))
    assert found(det, f"오로라-{PHONE}") == [(f"오로라-{PHONE}", "INTERNAL")]
    assert found(det, "비밀번호: Sup3r!Secret") == [("Sup3r!Secret", "PASSWORD")]


# --- grade ----------------------------------------------------------------------
def test_grade_override_raises_and_lowers():
    assert decide_grade(["NAME"], {"NAME": "C"}) == Grade.confidential
    assert decide_grade(["API_KEY"], {"API_KEY": "S"}) == Grade.sensitive
    assert decide_grade(["BUSINESS_NUMBER"], {"BUSINESS_NUMBER": "O"}) == Grade.public
    assert decide_grade(["BUSINESS_NUMBER", "PHONE"], {"BUSINESS_NUMBER": "O"}) == Grade.sensitive
    assert decide_grade(["NAME"], {}) == Grade.sensitive  # defaults unchanged


def test_grade_override_compiled_from_types():
    compiled = compile_policy(active(types={"이름": {"on": True, "grade": "C"}, "고객ID": {"grade": "C"}}))
    assert compiled.grade_overrides == {"NAME": "C"}


# --- method ---------------------------------------------------------------------
@pytest.mark.parametrize("method, expected", [
    ("대체", "연락 [전화번호_1]"), ("—", "연락 [전화번호_1]"),
    ("삭제", "연락 [삭제됨]"), ("태그", "연락 [전화번호]"),
    ("일반화", "연락 [전화번호_1]"),  # no generalization for phones: falls back to 대체
])
def test_method_output(method, expected):
    det = Detector(None)
    apply_policy_to_detector(det, active(types={"전화번호": {"on": True, "method": method}}))
    result = masked(det, f"연락 {PHONE}")
    assert result.text == expected
    assert result.remaining == ()


def test_delete_and_tag_do_not_restore():
    det = Detector(None)
    apply_policy_to_detector(det, active(types={"전화번호": {"method": "태그"}, "이메일": {"method": "대체"}}))
    with LocalSession(det) as session:
        out = session.process(f"{PHONE} a@b.com").text
        assert out == "[전화번호] [이메일_1]"
        assert session.restore(out).text == "[전화번호] a@b.com"


def test_generalize_address_and_dob():
    s = PseudonymSession()
    text = "서울시 마포구 월드컵북로 21 / 1994년 3월 12일 / 서울"
    def at(value, kind, after=0):
        start = text.index(value, after)
        return {"start": start, "end": start + len(value), "type": kind, "method": "일반화"}
    spans = [at("서울시 마포구 월드컵북로 21", "ADDRESS"), at("1994년 3월 12일", "DOB"),
             at("서울", "ADDRESS", text.index("/ 서울"))]
    assert s.pseudonymize(text, spans) == "서울시 마포구 / 1990년대 / [주소]"


def test_dict_word_uses_its_type_method():
    det = Detector(None)
    apply_policy_to_detector(det, active(
        types={"프로젝트 코드명": {"on": True, "grade": "S", "method": "태그"}},
        dict_=[{"h": sha("오로라")}],
    ))
    assert masked(det, "오로라 일정").text == "[사내정보] 일정"


# --- rules + failure handling ----------------------------------------------------
def slm_detector(base):
    det = Detector(None)
    slm = SlmSpanDetector.__new__(SlmSpanDetector)
    slm.fixed = json.loads((__import__("pathlib").Path("local_ai/slm/fixed_labels.json")).read_text("utf-8"))["labels"]
    slm.set_policy(base)
    det._slm = slm
    return det, slm


BASE = [{"id": "R01", "label": "미공개 프로젝트명", "description": "", "grade": "C", "action": "태그"},
        {"id": "R05", "label": "계약 금액", "description": "", "grade": "S", "action": "일반화"}]


def test_rules_merge_over_base_rules():
    det, slm = slm_detector(BASE)
    rules = [{"id": "r-1", "label": "고객 ID", "description": "CU로 시작", "grade": "S", "action": "삭제"},
             {"id": "r-2", "label": "계약 금액", "description": "", "grade": "C", "action": "대체"}]
    shared = dict(slm.rules)
    compiled = apply_policy_to_detector(det, active(rules=rules))
    assert slm.rules == shared  # the shared SLM is never modified; requests use the view
    view_rules, view_labels = compiled.slm_view
    assert view_labels["고객 ID"] == "r-1"
    labels = {r["label"]: (r["id"], r["grade"]) for r in view_rules.values()}
    assert labels["고객 ID"] == ("r-1", "S")
    assert labels["계약 금액"] == ("r-2", "C")  # bundle rule replaces the base rule
    assert labels["미공개 프로젝트명"] == ("R01", "C")
    assert compiled.rule_actions == {"r-1": "삭제", "r-2": "대체"}
    # A span from bundle rule r-1 takes the rule's action.
    assert compiled(" x", [{"start": 1, "end": 2, "type": "INTERNAL", "rule_id": "r-1"}])[0]["method"] == "삭제"
    # No policy: back to the base rules.
    none = apply_policy_to_detector(det, None)
    assert {r for r in none.slm_view[0] if not r.startswith("P-")} == {"R01", "R05"}


@pytest.mark.parametrize("bad", [
    [{"id": "r-1", "label": "고객 ID", "grade": "S"}, {"id": "r-2", "label": "고객 ID", "grade": "C"}],
    [{"id": "r-1", "label": "사람 이름", "grade": "S"}],  # fixed label
])
def test_rejected_rules_keep_previous_policy(bad, caplog):
    det, slm = slm_detector(BASE)
    good = apply_policy_to_detector(det, active(version=1, types={"전화번호": {"on": False}},
                                                 rules=[{"id": "r-9", "label": "고객 ID", "grade": "S"}]))
    before = dict(slm.rules)
    with caplog.at_level(logging.WARNING, logger="app.policy_apply"):
        effective = apply_policy_to_detector(det, active(version=2, types={"이메일": {"on": False}}, rules=bad))
    assert effective is good and effective.version == 1
    assert effective.slm_view[1]["고객 ID"] == "r-9"
    assert slm.rules == before
    assert found(det, f"{PHONE} a@b.com") == [("a@b.com", "EMAIL")]  # v1 still applies
    assert "keeping the previous policy" in caplog.text and "고객 ID" not in caplog.text
    # The failed version is not retried on every request.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="app.policy_apply"):
        apply_policy_to_detector(det, active(version=2, types={"이메일": {"on": False}}, rules=bad))
    assert caplog.text == ""


def test_malformed_rules_are_skipped_not_fatal():
    det, slm = slm_detector(BASE)
    apply_policy_to_detector(det, active(types={"전화번호": {"on": False}}, rules=[{"id": "r1", "label": "고객 ID"}]))
    assert found(det, PHONE) == []
    assert "r1" not in slm.rules
    assert "r1" not in apply_policy_to_detector(det, active(rules=[{"id": "r1", "label": "고객 ID"}])).slm_view[0]


class ViewSlm:
    """Fake SLM: reports which rules view each call used."""

    def __init__(self, base):
        real = SlmSpanDetector.__new__(SlmSpanDetector)
        real.fixed = []
        real.set_policy(base)
        self.rules, self.label2id, self.rules_view = real.rules, real.label2id, real.rules_view

    def detect(self, text, view=None):
        labels = (view or (self.rules, self.label2id))[1]
        if "고객 ID" in labels and "CU-1" in text:
            st = text.index("CU-1")
            return [{"start": st, "end": st + 4, "type": "CONFIDENTIAL", "rule_id": labels["고객 ID"]}]
        return []


def test_bound_policies_do_not_mix_on_a_shared_detector():
    det = Detector(None)
    det._slm, det.model_enabled = ViewSlm(BASE), True
    v1 = apply_policy_to_detector(det, active(version=1, types={"전화번호": {"on": False}},
                                              rules=[{"id": "r-1", "label": "고객 ID", "grade": "C", "action": "삭제"}]))
    v2 = apply_policy_to_detector(det, active(version=2))  # a deploy lands mid-request
    text = f"CU-1 {PHONE}"
    with LocalSession(v1.bind(det)) as session:
        assert session.process(text).text == "[삭제됨] " + PHONE
    with LocalSession(v2.bind(det)) as session:
        assert session.process(text).text == "CU-1 [전화번호_1]"
    assert (v1.version, v2.version) == (1, 2)


def test_unexpected_error_keeps_previous_policy(monkeypatch):
    det = Detector(None)
    good = apply_policy_to_detector(det, active(version=1, types={"전화번호": {"on": False}}))
    # Patch the module the imported function uses (other tests re-import app.* modules).
    monkeypatch.setitem(apply_policy_to_detector.__globals__, "compile_policy",
                        lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
    assert apply_policy_to_detector(det, active(version=2)) is good
    assert found(det, PHONE) == []


# --- end to end through the API -------------------------------------------------------
def _deploy(client, **extra):
    from app.policy import make_bundle
    payload = {"schema": 1, "org": "acme", "version": extra.pop("version", 1),
               "expires_at": "2999-01-01T00:00:00+00:00", "rules": [], **extra}
    assert client.post("/policy/deploy", json={"bundle": make_bundle(payload)}).json()["accepted"]


def test_process_follows_deployed_policy(client):
    _deploy(client, types={"이름": {"on": True, "grade": "C"}, "전화번호": {"on": True, "method": "삭제"},
                           "프로젝트 코드명": {"on": True, "grade": "C", "method": "태그"}},
            dict=[{"h": sha("오로라"), "type": "프로젝트 코드명"}],
            exclude=[{"h": sha("02-000-0000")}, {"h": sha("help@acme.test")}])
    r = client.post("/process", json={"text": f"오로라는 {PHONE}, 문의 help@acme.test", "rules_only": True}).json()
    assert r["masked_text"] == "[기밀]는 [삭제됨], 문의 help@acme.test"
    assert r["detected_types"] == ["CONFIDENTIAL", "PHONE"]
    assert r["grade"] == "confidential_C"


def test_process_grade_override(client):
    _deploy(client, types={"전화번호": {"on": True, "grade": "C"}})
    r = client.post("/process", json={"text": f"연락 {PHONE}", "rules_only": True}).json()
    assert r["grade"] == "confidential_C"


def test_failed_apply_logs_the_version_actually_used(api, monkeypatch):
    """Text and file events record the policy that detected, not a newer one that failed."""
    import sys
    from tests.test_file_api import upload, workbook_bytes

    client = api.client
    _deploy(client, version=1, types={"전화번호": {"on": False}})
    assert client.post("/process", json={"text": PHONE, "rules_only": True}).json()["detected_types"] == []
    module = sys.modules["app.policy_apply"]
    real = module.compile_policy
    monkeypatch.setattr(module, "compile_policy",
                        lambda p: real(p) if p.version == 1 else (_ for _ in ()).throw(RuntimeError("boom")))
    _deploy(client, version=2)
    work = client.post("/process", json={"text": PHONE, "rules_only": True}).json()
    assert work["detected_types"] == []  # v1 still detects
    decided = client.post("/process/decide", json={"work_id": work["work_id"], "action": "cancel"}).json()
    assert decided["event"]["policy_version"] == 1
    ready = upload(api, workbook_bytes()).json()
    assert client.get(f"/files/{ready['work_id']}/download").status_code == 200
    assert [e["policy_version"] for e in client.get("/logs/events").json()] == [1, 1]
