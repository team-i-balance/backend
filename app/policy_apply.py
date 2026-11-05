"""Apply an active policy's `types` toggles to a local_ai detector.

Policy `types` keys are Korean category names (e.g. "사업자번호"); the detector
uses internal type codes (e.g. "BUSINESS_NUMBER"). This maps the categories the
rules-based detector can actually toggle. Unknown categories are ignored (the
spec says `types` may be ignored until the PC side supports them).
"""
from __future__ import annotations

from typing import Optional

from app.policy import ActivePolicy

# Korean policy category -> detector type code.
_CATEGORY_TO_DETECTOR_TYPE = {
    "사업자번호": "BUSINESS_NUMBER",
    "전화번호": "PHONE",
    "이메일": "EMAIL",
    "API키": "API_KEY",
    "토큰": "ACCESS_TOKEN",
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
