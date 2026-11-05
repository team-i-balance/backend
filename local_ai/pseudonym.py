"""Local, per-work pseudonymisation of already detected character spans.

Span offsets are Python string indexes; ``end`` is exclusive. No text or
mapping is written to disk, logged, or sent over a network by this module.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
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


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    kind: str


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
        spans.append(_Span(start, end, kind))

    spans.sort(key=lambda item: (item.start, item.end, item.kind))
    merged: list[_Span] = []
    for span in spans:
        if merged and span.start < merged[-1].end:
            previous = merged[-1]
            if previous.kind != span.kind:
                raise PseudonymError("overlapping detection types require review")
            merged[-1] = _Span(previous.start, max(previous.end, span.end), previous.kind)
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
        for span in spans:
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
        result = text
        for start, end, token in reversed(replacements):
            result = result[:start] + token + result[end:]
        self._mapping = mapping
        self._next = counters
        self._reserved_literals.update(literal_tokens)
        return result

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
