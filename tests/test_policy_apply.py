"""Tests for applying a policy's type toggles to detection (slice 1)."""
from local_ai.detector import Detector, _valid_business_number
from app.policy import ActivePolicy
from app.policy_apply import apply_policy_to_detector, disabled_detector_types


def _active(types):
    return ActivePolicy(
        org="acme", version=1, keyid="k", rule_count=0, rules=[],
        types=types, thresholds={}, expires_at=None,
        activated_at="t", bundle_sha256="sha256:x",
    )


def _biz():
    n = next("1234567890"[:9] + str(d) for d in range(10)
             if _valid_business_number("123456789" + str(d)))
    return n[:3] + "-" + n[3:5] + "-" + n[5:]


def test_disabled_types_mapping():
    pol = _active({"사업자번호": {"on": False}, "전화번호": {"on": True}})
    assert disabled_detector_types(pol) == {"BUSINESS_NUMBER"}


def test_no_policy_disables_nothing():
    assert disabled_detector_types(None) == set()
    assert disabled_detector_types(_active({})) == set()


def test_unknown_category_ignored():
    pol = _active({"알수없는카테고리": {"on": False}})
    assert disabled_detector_types(pol) == set()


def test_detector_set_policy_turns_off_a_type():
    d = Detector(None)
    text = "번호: " + _biz()
    # Default: business number detected.
    assert any(x["type"] == "BUSINESS_NUMBER" for x in d.detect(text))
    # Turn it off via policy.
    d.set_policy(disabled_types={"BUSINESS_NUMBER"})
    assert not any(x["type"] == "BUSINESS_NUMBER" for x in d.detect(text))
    # Restore.
    d.set_policy(disabled_types=None)
    assert any(x["type"] == "BUSINESS_NUMBER" for x in d.detect(text))


def test_apply_policy_to_detector():
    d = Detector(None)
    apply_policy_to_detector(d, _active({"전화번호": {"on": False}}))
    assert "010-1234-5678" and not any(
        x["type"] == "PHONE" for x in d.detect("연락 010-1234-5678")
    )
    # Email still detected (not disabled).
    assert any(x["type"] == "EMAIL" for x in d.detect("a@b.com"))
