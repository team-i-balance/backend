"""Per-span event items for /process/decide (issue #63).

The /process work item keeps its masked spans in memory. On decide they become
the event's ``items``: type, decision, an HMAC of the value and a masked preview.
The raw value never leaves this module: it is not stored, logged or returned.

value_hash uses the same key (POLICY_VALUE_HASH_KEY) and normalization (the
stripped value) as the policy's ``hmac:`` exclude entries, so the console can
turn a false-positive group straight into an exclusion. Without the key the
items carry no value_hash.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from app.policy_apply import _hash_key, value_hashes
from app.schemas import Action, Decision, EventItem

UNKNOWN_PLACEHOLDER = "UNKNOWN_PLACEHOLDER"

# Types whose preview hides every letter and digit.
_FULL_MASK_TYPES = frozenset({
    "PHONE", "ID", "ID_NUMBER", "ACCOUNT", "CARD", "DOB", "BUSINESS_NUMBER",
    "IP_ADDRESS", "PASSWORD", "API_KEY", "ACCESS_TOKEN",
})
# Secrets: not even the length is shown.
_SECRET_TYPES = frozenset({"PASSWORD", "API_KEY", "ACCESS_TOKEN"})
_PREVIEW_MAX = 30


def mask_preview(kind: str, value: str) -> str:
    """Masked display form, e.g. "윤*아", "***-****-****". Separators stay visible."""
    value = " ".join(value.split())
    if kind in _SECRET_TYPES or not value:
        return "********"
    keep = set()
    if kind not in _FULL_MASK_TYPES:
        hidden = [i for i, ch in enumerate(value) if ch.isalnum()]
        if len(hidden) >= 2:
            keep.add(hidden[0])
        if len(hidden) >= 3:
            keep.add(hidden[-1])
    out = "".join(ch if (i in keep or not ch.isalnum()) else "*" for i, ch in enumerate(value))
    return out if len(out) <= _PREVIEW_MAX else out[:_PREVIEW_MAX - 1] + "…"


def value_hash(value: str, key: Optional[bytes]) -> Optional[str]:
    """Hex HMAC of the value as policy ``hmac:`` entries hash it, or None without a key."""
    if key is None:
        return None
    hmac_entry = next(h for h in value_hashes(value.strip(), key) if h.startswith("hmac:"))
    return hmac_entry.split(":", 1)[1]


def check_reverted(spans, reverted: Iterable[str]) -> Optional[set[str]]:
    """The reverted placeholders as a set; raise ValueError for one not in this work."""
    known = {s.output for s in spans if s.restorable}
    chosen = set(reverted)
    if not chosen <= known:
        raise ValueError(UNKNOWN_PLACEHOLDER)
    return chosen


def _decision(action: Action, span, reverted: Optional[set[str]]) -> Optional[Decision]:
    if action == Action.cancel:
        return None
    if action == Action.send_as_is:
        return Decision.raw
    if action == Action.send_transformed:
        return Decision.converted
    # revert_original: an older client sends no list and reverts everything.
    if reverted is None or (span.restorable and span.output in reverted):
        return Decision.reverted
    return Decision.converted


def build_items(spans, action: Action, reverted: Optional[set[str]]) -> list[EventItem]:
    if action == Action.cancel:
        return []
    key = _hash_key()
    return [
        EventItem(
            type=s.kind,
            decision=_decision(action, s, reverted),
            value_hash=value_hash(s.value, key),
            preview=mask_preview(s.kind, s.value),
        )
        for s in spans
    ]


def partially_restored(masked_text: str, spans, reverted: set[str]) -> str:
    """Masked text with only the chosen placeholders put back, in a single pass."""
    if not reverted:
        return masked_text
    originals = {s.output: s.value for s in spans if s.restorable and s.output in reverted}
    pattern = re.compile("|".join(re.escape(t) for t in sorted(originals, key=len, reverse=True)))
    return pattern.sub(lambda m: originals[m.group()], masked_text)
