"""Apply an active policy's `types` toggles to a local_ai detector.

Policy `types` keys are Korean category names (e.g. "사업자번호"); the detector
uses internal type codes (e.g. "BUSINESS_NUMBER"). This maps the categories the
rules-based detector can actually toggle. Unknown categories are ignored (the
spec says `types` may be ignored until the PC side supports them).
"""
from __future__ import annotations

from typing import Optional

from app.policy import ActivePolicy

# Console item name (team-i-balance/web src/domain/seed.ts entities) -> detector
# type code (local_ai/pseudonym.py _TYPE_LABELS). Only types the current
# detector actually emits are listed.
#
# Console items with no detector type yet (ignored): 나이, 고객ID,
# 프로젝트 코드명, 미공개 실적.
# Note: 주민등록번호 -> ID_NUMBER also covers other ID numbers (e.g. driver's
# licence) because the detector does not split them.
_CATEGORY_TO_DETECTOR_TYPE = {
    "이름": "NAME",
    "전화번호": "PHONE",
    "이메일": "EMAIL",
    "주소": "ADDRESS",
    "생년월일": "DOB",
    "계좌번호": "ACCOUNT",
    "카드번호": "CARD",
    "주민등록번호": "ID_NUMBER",
    "API 키": "API_KEY",   # console spells it with a space
    "API키": "API_KEY",    # legacy spelling, kept for older bundles
    "비밀번호": "PASSWORD",
    "사업자번호": "BUSINESS_NUMBER",
    "토큰": "ACCESS_TOKEN",  # not a console item today; kept for compatibility
}


def disabled_detector_types(policy: Optional[ActivePolicy]) -> set[str]:
    """Return detector type codes that the policy turns off."""
    if policy is None or not policy.types:
        return set()
    disabled: set[str] = set()
    for category, setting in policy.types.items():
        # setting looks like {"on": true/false}
        on = setting.get("on", True) if isinstance(setting, dict) else True
        if on:
            continue
        code = _CATEGORY_TO_DETECTOR_TYPE.get(category)
        if code:
            disabled.add(code)
    return disabled


def apply_policy_to_detector(detector, policy: Optional[ActivePolicy]) -> None:
    """Configure a detector from the active policy (idempotent)."""
    detector.set_policy(disabled_types=disabled_detector_types(policy))
