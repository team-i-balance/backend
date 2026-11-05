"""Local, per-work pseudonymisation of already detected character spans.

Span offsets are Python string indexes; ``end`` is exclusive. No text or
mapping is written to disk, logged, or sent over a network by this module.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import re


class PseudonymError(ValueError):
    """Input spans or placeholders are ambiguous; review is required."""


class PlaceholderReuseError(PseudonymError):
    """New source text contains a placeholder this session already assigned."""


_TYPE_LABELS = {
    "NAME": "이름",
    "PHONE": "전화번호",
    "EMAIL": "이메일",
    "ADDRESS": "주소",
    "ID": "식별번호",
    "ID_NUMBER": "식별번호",
    "ACCOUNT": "계좌번호",
    "CARD": "카드번호",
    "DOB": "생년월일",
    "USERNAME": "사용자명",
    "IP_ADDRESS": "IP주소",
    "PASSWORD": "비밀번호",
    "BUSINESS_NUMBER": "사업자번호",
    "API_KEY": "API키",
    "ACCESS_TOKEN": "토큰",
    # local_ai/slm: policy-graded spans
    "SENSITIVE": "민감정보",
    "CONFIDENTIAL": "기밀",
    "INTERNAL": "사내정보",
}


@dataclass(frozen=True)
class RestoreResult:
    """Local restored text, unknown placeholders and blocked secret placeholders."""

    text: str
    unknown: tuple[str, ...]
    blocked: tuple[str, ...]


_PLACEHOLDER = re.compile(r"\[[^\[\]\r\n]+_\d+\]")
_NO_RESTORE = frozenset({"API_KEY", "ACCESS_TOKEN", "PASSWORD"})

# Transform methods from the policy (console `types[].method`, rule `action`; #47).
# A detection may carry ``method``; anything else (missing, "대체", "—") replaces with a
# restorable placeholder. 삭제/태그/일반화 outputs are not placeholders and never restore.
METHOD_REPLACE, METHOD_GENERALIZE, METHOD_DELETE, METHOD_TAG = "대체", "일반화", "삭제", "태그"
DELETED_TOKEN = "[삭제됨]"
# Fixed outputs of 삭제/태그. The detector skips them like placeholders on re-inspection.
POLICY_TOKEN = re.compile(r"\[(?:" + "|".join(
    re.escape(label) for label in sorted(set(_TYPE_LABELS.values()) | {"삭제됨"}, key=len, reverse=True)
) + r")\]")
_YEAR = re.compile(r"(?<![0-9])(1[89][0-9]{2}|20[0-9]{2})(?![0-9])")


def _tag(kind: str) -> str:
    return f"[{_TYPE_LABELS[kind]}]"


def _generalize(kind: str, value: str) -> str | None:
    """Coarse value for 일반화, or None when the type has no generalization (then 대체).

    ADDRESS keeps the first two words (시·도 + 시·군·구), DOB keeps the decade.
    """
    if kind == "ADDRESS":
        words = value.split()
        coarse = " ".join(words[:2])
        return coarse if coarse and coarse != value.strip() else _tag(kind)
    if kind == "DOB":
        year = _YEAR.search(value)
        return f"{year.group(1)[:3]}0년대" if year else _tag(kind)
    return None


@dataclass(frozen=True)
class MaskedSpan:
    """One masked span of a pseudonymize call. ``value`` is raw: memory only, never log it."""

    kind: str
    value: str = field(repr=False)
    output: str          # placeholder, or the fixed 삭제/태그/일반화 output
    restorable: bool     # True when ``output`` is this session's restorable placeholder


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    kind: str
    method: str | None = None


def _spans(text: str, detections: Sequence[Mapping[str, object]]) -> list[_Span]:
    if not isinstance(text, str):
        raise PseudonymError("text must be a string")
    if not isinstance(detections, (list, tuple)):
        raise PseudonymError("detections must be a list or tuple")
    spans: list[_Span] = []
    for detection in detections:
        if not isinstance(detection, Mapping):
            raise PseudonymError("each detection must be a mapping")
        start, end, kind = detection.get("start"), detection.get("end"), detection.get("type")
        # bool is a subclass of int, but is never a valid offset.
        if type(start) is not int or type(end) is not int or not (0 <= start < end <= len(text)):
            raise PseudonymError("invalid detection offsets")
        if not isinstance(kind, str) or kind not in _TYPE_LABELS:
            raise PseudonymError("unsupported detection type")
        method = detection.get("method")
        spans.append(_Span(start, end, kind, method if isinstance(method, str) else None))

    spans.sort(key=lambda item: (item.start, item.end, item.kind))
    merged: list[_Span] = []
    for span in spans:
        if merged and span.start < merged[-1].end:
            previous = merged[-1]
            if previous.kind != span.kind:
                raise PseudonymError("overlapping detection types require review")
            merged[-1] = _Span(previous.start, max(previous.end, span.end), previous.kind, previous.method)
        else:
            merged.append(span)
    return merged


class PseudonymSession:
    """Keep mappings only in memory for one work session; call close when done."""

    def __init__(self) -> None:
        self._mapping: dict[tuple[str, str], str] = {}
        self._next: dict[str, int] = {}
        self._reserved_literals: set[str] = set()
        self._closed = False

    def pseudonymize(self, text: str, detections: Sequence[Mapping[str, object]]) -> str:
        return self.pseudonymize_spans(text, detections)[0]

    def pseudonymize_spans(
        self, text: str, detections: Sequence[Mapping[str, object]],
    ) -> tuple[str, tuple[MaskedSpan, ...]]:
        """Like ``pseudonymize``, also returning each masked span in text order."""
        if self._closed:
            raise PseudonymError("session is closed")
        spans = _spans(text, detections)
        # If an existing placeholder reappears in new source text, its meaning
        # cannot be distinguished from literal user content, so fail closed.
        if any(token in text for token in self._mapping.values()):
            raise PlaceholderReuseError("input contains an existing session placeholder")

        mapping = self._mapping.copy()
        counters = self._next.copy()
        literal_tokens = set(_PLACEHOLDER.findall(text))
        occupied = self._reserved_literals | literal_tokens | set(mapping.values())
        replacements: list[tuple[int, int, str]] = []
        masked: list[MaskedSpan] = []
        for span in spans:
            fixed = self._fixed_output(span, text[span.start:span.end])
            if fixed is not None:
                replacements.append((span.start, span.end, fixed))
                masked.append(MaskedSpan(span.kind, text[span.start:span.end], fixed, False))
                continue
            key = (span.kind, text[span.start:span.end])
            token = mapping.get(key)
            if token is None:
                index = counters.get(span.kind, 1)
                while True:
                    token = f"[{_TYPE_LABELS[span.kind]}_{index}]"
                    index += 1
                    if token not in occupied:
                        break
                counters[span.kind] = index
                mapping[key] = token
                occupied.add(token)
            replacements.append((span.start, span.end, token))
            masked.append(MaskedSpan(span.kind, text[span.start:span.end], token, True))
        result = text
        for start, end, token in reversed(replacements):
            result = result[:start] + token + result[end:]
        self._mapping = mapping
        self._next = counters
        self._reserved_literals.update(literal_tokens)
        return result, tuple(masked)

    @staticmethod
    def _fixed_output(span: _Span, value: str) -> str | None:
        """Output of a non-restorable method, or None to use a restorable placeholder."""
        if span.method == METHOD_DELETE:
            return DELETED_TOKEN
        if span.method == METHOD_TAG:
            return _tag(span.kind)
        if span.method == METHOD_GENERALIZE:
            return _generalize(span.kind, value)
        return None

    def restore(self, text: str) -> RestoreResult:
        """Restore only current-session non-secret placeholders in a single pass.

        Unknown and blocked placeholders remain unchanged. The callback is
        evaluated only on the original response, so replacement values that
        themselves resemble placeholders are never recursively expanded.
        """
        if self._closed:
            raise PseudonymError("session is closed")
        if not isinstance(text, str):
            raise PseudonymError("text must be a string")
        reverse = {token: (kind, original)
                   for (kind, original), token in self._mapping.items()}
        unknown: list[str] = []
        blocked: list[str] = []

        def replace(match: re.Match[str]) -> str:
            token = match.group()
            entry = reverse.get(token)
            if entry is None:
                if token not in unknown:
                    unknown.append(token)
                return token
            kind, original = entry
            if kind in _NO_RESTORE:
                if token not in blocked:
                    blocked.append(token)
                return token
            return original

        return RestoreResult(_PLACEHOLDER.sub(replace, text), tuple(unknown), tuple(blocked))

    def close(self) -> None:
        """Discard this session's mappings; a closed session cannot be reused."""
        self._mapping.clear()
        self._next.clear()
        self._reserved_literals.clear()
        self._closed = True
