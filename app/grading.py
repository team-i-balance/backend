"""Grade decision (흐름도 S2 "등급 판정").

Maps the PII types that local_ai detected to a sensitivity grade:

  confidential_C : secrets whose exposure is high-impact
                   (API keys, access tokens, passwords)
  sensitive_S    : personal data that must be transformed before leaving
                   (name, phone, email, ID numbers, card, account, address,
                    date of birth, business number, username, IP)
  public_O       : nothing sensitive detected

Rule of thumb: if any secret is present the whole payload is treated as
confidential; otherwise any personal data makes it sensitive; otherwise public.
See rules.md section 7.

The active policy may re-grade a type (console `types[].grade`, #47): pass
``overrides`` as {type: "O"|"S"|"C"}. An overridden type counts at that grade
only; types without an override keep the defaults below.
"""
from app.schemas import Grade

# Detection type strings produced by local_ai (see local_ai/pseudonym.py labels).
# CONFIDENTIAL / INTERNAL / SENSITIVE come from local_ai/slm: the policy rule's grade
# (C / S) already chose the type, and SENSITIVE (a person's health, discipline...) is C.
_CONFIDENTIAL_TYPES = frozenset({"API_KEY", "ACCESS_TOKEN", "PASSWORD", "CONFIDENTIAL", "SENSITIVE"})
_SENSITIVE_TYPES = frozenset(
    {
        "NAME",
        "PHONE",
        "EMAIL",
        "ADDRESS",
        "ID",
        "ID_NUMBER",
        "ACCOUNT",
        "CARD",
        "DOB",
        "USERNAME",
        "IP_ADDRESS",
        "BUSINESS_NUMBER",
        "INTERNAL",
    }
)


_OVERRIDE_GRADES = {"C": Grade.confidential, "S": Grade.sensitive, "O": Grade.public}


def decide_grade(detected_types, overrides=None) -> Grade:
    """Return the grade for a set/list of detected type strings."""
    types = set(detected_types)
    if overrides:
        graded = {_OVERRIDE_GRADES[g] for t, g in overrides.items() if t in types and g in _OVERRIDE_GRADES}
        types -= {t for t, g in overrides.items() if g in _OVERRIDE_GRADES}
        if Grade.confidential in graded:
            return Grade.confidential
        rest = decide_grade(types)
        if rest == Grade.confidential:
            return rest
        return Grade.sensitive if Grade.sensitive in graded else rest
    if types & _CONFIDENTIAL_TYPES:
        return Grade.confidential
    if types & _SENSITIVE_TYPES:
        return Grade.sensitive
    return Grade.public
