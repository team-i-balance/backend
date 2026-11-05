"""Apply the active policy to a local_ai detector on the server (#47).

What the server honours (see docs/policy-apply.md for the full table):

  types[].on      detection type off -> not detected, not pseudonymized
  types[].grade   per-type grade override for app/grading.decide_grade
  types[].method  대체/일반화/삭제/태그 per detection type (local_ai/pseudonym.py)
  rules           company rules for the server SLM (SlmSpanDetector.rules_view, per request),
                  merged over the rules the SLM was loaded with
  dict            hashed company words found in the input -> CONFIDENTIAL/INTERNAL
  exclude         hashed values never reported, whatever detector found them

Policy `types` keys are Korean console item names (e.g. "사업자번호"); the
detector uses internal type codes (e.g. "BUSINESS_NUMBER"). Unknown items are
ignored (the spec says `types` may be ignored until supported).

Hashes (docs: BUNDLE-SPEC.md section 3, `dict`/`exclude`):
  "sha256:<hex>"  SHA-256 of the UTF-8 plain value (values the console typed)
  "hmac:<hex>"    HMAC-SHA256(org key, UTF-8 value): the events' value_hash (#21).
                  The org key comes from POLICY_VALUE_HASH_KEY (UTF-8 bytes). Without
                  it hmac entries are skipped with a warning (counts only, no values).

Application is atomic per detector: everything is validated and compiled first;
if anything fails (e.g. the SLM rejects a duplicate rule label) the detector keeps
the previous policy and a warning is logged. Policy content is never logged.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import threading
import weakref
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # typing only: keeps this module importable without the signing stack
    from app.policy import ActivePolicy

log = logging.getLogger(__name__)

VALUE_HASH_KEY_ENV = "POLICY_VALUE_HASH_KEY"
# Company words are matched over runs of at most this many words (cost bound).
DICT_MAX_WORDS = 4

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
_GRADES = frozenset({"O", "S", "C"})
_METHODS = frozenset({"대체", "일반화", "삭제", "태그"})
# Console default for a dict entry without a type (web src/api/policy.ts).
_DICT_DEFAULT_TYPE = "프로젝트 코드명"
# Secrets are never swallowed by a company-word span.
_SECRET_TYPES = frozenset({"API_KEY", "ACCESS_TOKEN", "PASSWORD"})
_HASH = re.compile(r"^(sha256|hmac):([0-9a-fA-F]{64})$")
# Word candidates for company words: split on spaces and punctuation, keep . - _ inside.
_WORD = re.compile(r"[^\s,;:!?()\[\]{}<>\"'“”‘’「」『』《》〈〉/\\|·…]+")
# Trailing particles removed to form extra candidates ("오로라는" -> "오로라").
# A wrong strip only adds a candidate that will not hash-match.
_JOSA = tuple(sorted((
    "으로부터", "에게서", "한테서", "에서는", "에서도", "이라고", "라고", "에서", "에게", "한테",
    "까지", "부터", "으로", "처럼", "보다", "이나", "이랑", "랑", "이고", "하고", "은", "는", "이",
    "가", "을", "를", "의", "도", "만", "로", "에", "와", "과", "께", "나",
), key=len, reverse=True))


class PolicyApplyError(ValueError):
    """The policy cannot be applied; the previous policy stays in effect."""


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


def grade_overrides(policy: Optional[ActivePolicy]) -> dict[str, str]:
    """{detector type: "O"|"S"|"C"} from `types[].grade`."""
    out: dict[str, str] = {}
    for category, setting in ((policy.types or {}) if policy else {}).items():
        code = _CATEGORY_TO_DETECTOR_TYPE.get(category)
        grade = setting.get("grade") if isinstance(setting, dict) else None
        if code and grade in _GRADES:
            out[code] = grade
    return out


def type_methods(policy: Optional[ActivePolicy]) -> dict[str, str]:
    """{detector type: method} from `types[].method`; "—"/unknown methods mean 대체."""
    out: dict[str, str] = {}
    for category, setting in ((policy.types or {}) if policy else {}).items():
        code = _CATEGORY_TO_DETECTOR_TYPE.get(category)
        method = setting.get("method") if isinstance(setting, dict) else None
        if code and method in _METHODS:
            out[code] = method
    return out


# --- hashing -----------------------------------------------------------------
def _hash_key() -> Optional[bytes]:
    key = os.getenv(VALUE_HASH_KEY_ENV)
    return key.encode("utf-8") if key else None


def value_hashes(value: str, key: Optional[bytes]) -> tuple[str, ...]:
    """The spec hash strings of ``value`` ("sha256:…" and, with a key, "hmac:…")."""
    raw = value.encode("utf-8")
    out = ["sha256:" + hashlib.sha256(raw).hexdigest()]
    if key is not None:
        out.append("hmac:" + hmac.new(key, raw, hashlib.sha256).hexdigest())
    return tuple(out)


def _parse_hash(entry) -> Optional[tuple[str, str]]:
    h = entry.get("h") if isinstance(entry, dict) else None
    m = _HASH.match(h) if isinstance(h, str) else None
    return (m.group(1), m.group(1) + ":" + m.group(2).lower()) if m else None


def _strip_josa(word: str) -> list[str]:
    return [word[:-len(j)] for j in _JOSA if word.endswith(j) and len(word) > len(j)]


# --- compiled policy -----------------------------------------------------------
@dataclass(frozen=True)
class _DictEntry:
    type: str            # CONFIDENTIAL / INTERNAL
    method: Optional[str]


@dataclass(frozen=True)
class ServerPolicy:
    """Everything the server applies, compiled from one ActivePolicy.

    Immutable: a request binds it to the shared detector (``bind``) and detects with it
    alone, so a deploy in the middle of a request cannot mix two policies.
    """

    version: Optional[int] = None                        # policy version (None: no policy)
    disabled_types: frozenset = frozenset()
    grade_overrides: dict = field(default_factory=dict)
    methods: dict = field(default_factory=dict)          # detector type -> method
    rule_actions: dict = field(default_factory=dict)     # bundle rule id -> method
    rules: Optional[tuple] = None                        # bundle rules for the SLM, None = keep
    dict_entries: dict = field(default_factory=dict)     # hash -> _DictEntry
    exclude: frozenset = frozenset()
    hmac_key: Optional[bytes] = field(default=None, repr=False)
    # SLM (rules by id, label -> id) for this policy; None = the SLM's loaded rules.
    slm_view: Optional[tuple] = field(default=None, repr=False)

    def bind(self, detector):
        """A detector view that checks with this policy only (pass it to LocalSession)."""
        return BoundDetector(detector, self) if _accepts_policy(detector) else detector

    @property
    def has_span_policy(self) -> bool:
        return bool(self.dict_entries or self.exclude or self.methods or self.rule_actions)

    # --- runtime: (text, spans) -> spans ---------------------------------
    def __call__(self, text: str, spans: list[dict]) -> list[dict]:
        if self.dict_entries:
            spans = self._add_dict_spans(text, spans)
        if self.exclude:
            spans = [s for s in spans if not self._excluded(text[s["start"]:s["end"]])]
        if self.methods or self.rule_actions:
            spans = [self._with_method(s) for s in spans]
        return spans

    def _hashes(self, value: str) -> tuple[str, ...]:
        return value_hashes(value, self.hmac_key)

    def _excluded(self, value: str) -> bool:
        candidates = {value, value.strip(), *_strip_josa(value.strip())}
        return any(h in self.exclude for c in candidates if c for h in self._hashes(c))

    def _with_method(self, span: dict) -> dict:
        if span.get("method"):
            return span
        method = self.rule_actions.get(span.get("rule_id")) or self.methods.get(span["type"])
        return {**span, "method": method} if method else span

    def _dict_matches(self, text: str) -> list[dict]:
        words = []
        for m in _WORD.finditer(text):
            st, en = m.start(), m.end()
            while en > st and text[en - 1] == ".":
                en -= 1
            if en > st:
                words.append((st, en))
        found = []
        for i, (st, _) in enumerate(words):
            for n in range(1, DICT_MAX_WORDS + 1):
                if i + n > len(words):
                    break
                # Only spaces join the words of one company term.
                if n > 1 and text[words[i + n - 2][1]:words[i + n - 1][0]].strip():
                    break
                en = words[i + n - 1][1]
                key = " ".join(text[a:b] for a, b in words[i:i + n])
                for cand in (key, *_strip_josa(key)):
                    entry = next((self.dict_entries[h] for h in self._hashes(cand)
                                  if h in self.dict_entries), None)
                    if entry is not None:
                        end = en - (len(key) - len(cand))
                        found.append({"start": st, "end": end, "type": entry.type,
                                      **({"method": entry.method} if entry.method else {})})
                        break
        # Longest first, non-overlapping.
        found.sort(key=lambda s: (-(s["end"] - s["start"]), s["start"]))
        kept: list[dict] = []
        for s in found:
            if not any(k["start"] < s["end"] and s["start"] < k["end"] for k in kept):
                kept.append(s)
        return kept

    def _add_dict_spans(self, text: str, spans: list[dict]) -> list[dict]:
        """A company word replaces spans it fully contains; it never cuts a span or a secret."""
        out = list(spans)
        for word in self._dict_matches(text):
            hit = [s for s in out if s["start"] < word["end"] and word["start"] < s["end"]]
            if any(s["type"] in _SECRET_TYPES or s["start"] < word["start"] or s["end"] > word["end"]
                   for s in hit):
                continue  # Already masked by an overlapping detection.
            out = [s for s in out if s not in hit] + [word]
        return sorted(out, key=lambda x: (x["start"], x["end"], x["type"]))


def _compile_rules(rules, version) -> tuple[Optional[tuple], dict]:
    """Bundle rules in SLM form. A rule the SLM cannot use (no id/label, grade not S|C) is
    skipped with a warning; duplicates are left for SlmSpanDetector.rules_view to reject."""
    if not isinstance(rules, list):
        raise PolicyApplyError("rules must be a list")
    out, actions, skipped = [], {}, 0
    for r in rules:
        rid, label, grade = (r.get("id"), r.get("label"), r.get("grade")) if isinstance(r, dict) else (None,) * 3
        if not isinstance(rid, str) or not rid or not isinstance(label, str) or not label or grade not in ("S", "C"):
            skipped += 1
            continue
        if rid.startswith("P-"):
            continue  # Fixed labels ship with the model (spec), as in slm.load_policy.
        rule = {"id": rid, "label": label, "description": str(r.get("description") or ""),
                "grade": grade, "action": str(r.get("action") or "")}
        out.append(rule)
        if rule["action"] in _METHODS:
            actions[rid] = rule["action"]
    if skipped:
        log.warning("policy v%s: %d rules ignored (need id, label and grade S|C)", version, skipped)
    return tuple(out), actions


def compile_policy(policy: Optional[ActivePolicy]) -> ServerPolicy:
    """Validate and compile; raises PolicyApplyError for a policy that cannot apply."""
    if policy is None:
        return ServerPolicy()
    disabled = disabled_detector_types(policy)
    rules, actions = _compile_rules(policy.rules or [], policy.version)
    key = _hash_key()
    types = policy.types or {}
    skipped_hmac = invalid = 0

    def usable(entry) -> Optional[str]:
        nonlocal skipped_hmac, invalid
        parsed = _parse_hash(entry)
        if parsed is None:
            invalid += 1
            return None
        if parsed[0] == "hmac" and key is None:
            skipped_hmac += 1
            return None
        return parsed[1]

    exclude = frozenset(h for h in map(usable, getattr(policy, "exclude", None) or []) if h)
    dict_entries: dict[str, _DictEntry] = {}
    for entry in getattr(policy, "dict", None) or []:
        h = usable(entry)
        if h is None:
            continue
        category = entry.get("type") or _DICT_DEFAULT_TYPE
        setting = types.get(category)
        setting = setting if isinstance(setting, dict) else {}
        if setting.get("on", True) is False:
            continue
        method = setting.get("method")
        dict_entries[h] = _DictEntry(
            type="CONFIDENTIAL" if setting.get("grade") == "C" else "INTERNAL",
            method=method if method in _METHODS else None,
        )
    if skipped_hmac:
        log.warning("policy v%s: %d hmac dict/exclude entries ignored (%s is not set)",
                    policy.version, skipped_hmac, VALUE_HASH_KEY_ENV)
    if invalid:
        log.warning("policy v%s: %d dict/exclude entries ignored (bad hash format)",
                    policy.version, invalid)
    return ServerPolicy(
        version=policy.version,
        disabled_types=frozenset(disabled),
        grade_overrides=grade_overrides(policy),
        methods=type_methods(policy),
        rule_actions=actions,
        rules=rules,
        dict_entries=dict_entries,
        exclude=exclude,
        hmac_key=key,
    )


# --- applying to a detector -----------------------------------------------------
def _accepts_policy(detector) -> bool:
    from local_ai.detector import Detector
    return isinstance(detector, Detector)


class BoundDetector:
    """The shared detector plus one compiled policy, for one request or file job."""

    def __init__(self, detector, policy: ServerPolicy):
        self._detector = detector
        self.policy = policy

    @property
    def model_enabled(self) -> bool:
        return self._detector.model_enabled

    def detect(self, text: str) -> list[dict]:
        return self._detector.detect(text, policy=self.policy)


@dataclass
class _State:
    fingerprint: Optional[str]
    effective: ServerPolicy
    base_rules: Optional[list]   # rules the SLM was loaded with (LOCAL_SLM_POLICY)


_UNSET = "<unset>"  # never a sha256 hex fingerprint, nor None
_states: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_lock = threading.Lock()


def _remember(detector, state: _State) -> None:
    try:
        _states[detector] = state
    except TypeError:
        pass


def _fingerprint(policy: Optional[ActivePolicy]) -> Optional[str]:
    if policy is None:
        return None
    data = [policy.version, policy.bundle_sha256, policy.types, policy.rules,
            getattr(policy, "dict", None), getattr(policy, "exclude", None),
            os.getenv(VALUE_HASH_KEY_ENV) is not None]
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                          .encode("utf-8")).hexdigest()


def _slm_rules(base_rules: list, compiled: ServerPolicy) -> list:
    """SLM rules for this policy: bundle rules override base rules with the same id/label."""
    bundle = list(compiled.rules or ())
    labels, ids = {r["label"] for r in bundle}, {r["id"] for r in bundle}
    return [r for r in base_rules if r["label"] not in labels and r["id"] not in ids] + bundle


def _set_detector(detector, compiled: ServerPolicy) -> None:
    detector.set_policy(
        disabled_types=compiled.disabled_types,
        span_policy=compiled if compiled.has_span_policy else None,
    )


# The last policy that applied successfully (any detector), for detectors seeing a
# failing policy first.
_last_good: list = [None]


def _compile_for(slm, state: _State, policy) -> ServerPolicy:
    compiled = compile_policy(policy)
    if state.base_rules is not None and hasattr(slm, "rules_view"):
        # Raises ValueError for duplicate labels/ids or a fixed label.
        compiled = replace(compiled, slm_view=slm.rules_view(_slm_rules(state.base_rules, compiled)))
    return compiled


def apply_policy_to_detector(detector, policy: Optional[ActivePolicy]) -> ServerPolicy:
    """Compile the active policy for a detector (cached while the policy is unchanged).

    Returns the policy now in effect: the new one, or the previous one when the new
    one failed to apply. Never raises for a bad policy. Request paths detect with
    ``result.bind(detector)``; the shared SLM is never modified. For direct callers the
    detector's own set_policy state is also updated (types on/off, span policy).
    """
    fingerprint = _fingerprint(policy)
    with _lock:
        try:
            state = _states.get(detector)
        except TypeError:  # not weak-referenceable (test doubles): no caching
            state = None
        if state is not None and state.fingerprint == fingerprint:
            return state.effective
        slm = getattr(detector, "_slm", None)
        if state is None:
            base = ([r for rid, r in slm.rules.items() if not rid.startswith("P-")]
                    if slm is not None and isinstance(getattr(slm, "rules", None), dict) else None)
            state = _State(fingerprint=_UNSET, effective=ServerPolicy(), base_rules=base)
        try:
            compiled = _compile_for(slm, state, policy)
        except Exception as exc:
            # Keep the previous policy. Exception text may quote policy content: log the type only.
            log.warning("policy v%s could not be applied on the server (%s); keeping the previous policy",
                        getattr(policy, "version", None), type(exc).__name__)
            if state.fingerprint == _UNSET and _last_good[0] is not None:
                # A detector seeing its first policy (e.g. built after a restart or for another
                # mode): "previous" is the last policy that applied anywhere in this process.
                try:
                    state.effective = _compile_for(slm, state, _last_good[0])
                except Exception:
                    pass
            _set_detector(detector, state.effective)
            # Remember the failed policy so it is not retried (and logged) on every request.
            state.fingerprint = fingerprint
            _remember(detector, state)
            return state.effective
        _set_detector(detector, compiled)
        _last_good[0] = policy
        state.fingerprint = fingerprint
        state.effective = compiled
        _remember(detector, state)
        return compiled
