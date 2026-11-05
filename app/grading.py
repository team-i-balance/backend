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
"""
from app.schemas import Grade

# Detection type strings produced by local_ai (see local_ai/pseudonym.py labels).
_CONFIDENTIAL_TYPES = frozenset({"API_KEY", "ACCESS_TOKEN", "PASSWORD"})
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
    }
)


def decide_grade(detected_types) -> Grade:
    """Return the grade for a set/list of detected type strings."""
    types = set(detected_types)
    if types & _CONFIDENTIAL_TYPES:
        return Grade.confidential
    if types & _SENSITIVE_TYPES:
        return Grade.sensitive
    return Grade.public
