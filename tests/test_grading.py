"""Unit tests for grade decision (app/grading.py, rules.md section 7)."""
import pytest

from app.grading import decide_grade
from app.schemas import Grade


@pytest.mark.parametrize("secret", ["API_KEY", "ACCESS_TOKEN", "PASSWORD"])
def test_any_secret_is_confidential(secret):
    assert decide_grade([secret]) == Grade.confidential


@pytest.mark.parametrize(
    "personal",
    ["NAME", "PHONE", "EMAIL", "ADDRESS", "ID_NUMBER", "ACCOUNT",
     "CARD", "DOB", "USERNAME", "IP_ADDRESS", "BUSINESS_NUMBER"],
)
def test_personal_data_is_sensitive(personal):
    assert decide_grade([personal]) == Grade.sensitive


def test_nothing_detected_is_public():
    assert decide_grade([]) == Grade.public


def test_secret_beats_personal():
    # Secret present alongside personal data -> whole payload confidential.
    assert decide_grade(["NAME", "PHONE", "API_KEY"]) == Grade.confidential


def test_unknown_type_ignored_defaults_public():
    assert decide_grade(["SOMETHING_ELSE"]) == Grade.public


def test_mixed_personal_types_sensitive():
    assert decide_grade(["NAME", "EMAIL", "CARD"]) == Grade.sensitive
