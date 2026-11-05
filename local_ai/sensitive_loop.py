"""Bounded, local sensitive-text transformation and residual detection.

The caller supplies only S-grade work. ``checked`` means that the configured
detector found no remaining entities; it is not a re-identification guarantee.
"""
from dataclasses import dataclass
from datetime import date
import re

from .pseudonym import PseudonymSession, PseudonymError, _PLACEHOLDER, _spans

_SECRET = frozenset({'PASSWORD', 'API_KEY', 'ACCESS_TOKEN', 'CONFIDENTIAL'})


@dataclass(frozen=True)
class LoopResult:
    status: str
    text: str | None
    iterations: int
    reason: str
    remaining_count: int = 0


def _year(value):
    """Generalize an unambiguous ISO date; other forms use a pseudonym."""
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
        return None
    try:
        return f'{date.fromisoformat(value).year}년'
    except ValueError:
        return None


class SensitiveTransformLoop:
    """One local task, bounded retries, with a mapping for the final result."""

    def __init__(self, detector, *, max_iterations=3, delete_types=()):
        if not isinstance(max_iterations, int) or isinstance(max_iterations, bool) or not 1 <= max_iterations <= 10:
            raise ValueError('max_iterations must be between 1 and 10')
        self.detector = detector
        self.max_iterations = max_iterations
        self.delete_types = frozenset(delete_types)
        self._session = None
        self._used = False
        self._closed = False

    def process(self, text, initial_detections=None):
        if self._closed or self._used:
            raise RuntimeError('session is closed or already used')
        if not isinstance(text, str):
            raise TypeError('text must be a string')
        self._used = True
        attempt = None
        iterations = 0
        try:
            incoming = list(initial_detections or ())
            if any(d.get('type') in _SECRET or d.get('grade') in ('C', 'confidential_C') for d in incoming):
                return LoopResult('blocked', None, 0, 'confidential_input')
            initial = list(self.detector.detect(text)) + incoming
            if any(d.get('type') in _SECRET for d in initial):
                return LoopResult('blocked', None, 0, 'confidential_input')
            spans = _spans(text, initial)
            escalated = set()
            for iterations in range(1, self.max_iterations + 1):
                attempt = PseudonymSession()
                plans = []
                for s in spans:
                    generalized = _year(text[s.start:s.end]) if s.kind == 'DOB' and (s.start, s.end) not in escalated and s.kind not in self.delete_types else None
                    plans.append((s, generalized, s.kind in self.delete_types))
                # Deletions and generalized values are not reversible aliases.
                attempt.pseudonymize(text, [{'start': s.start, 'end': s.end, 'type': s.kind}
                                            for s, generalized, deleted in plans if not deleted and generalized is None])
                parts, provenance, protected = [], [], []
                cursor = 0
                for span, generalized, deleted in plans:
                    before = text[cursor:span.start]
                    parts.append(before)
                    provenance.extend(('raw', i, i + 1) for i in range(cursor, span.start))
                    value = text[span.start:span.end]
                    token = attempt._mapping[(span.kind, value)] if not deleted and generalized is None else ''
                    replacement = '' if deleted else (generalized or token)
                    kind = 'generalized' if generalized and replacement == generalized else 'alias'
                    start = len(provenance)
                    parts.append(replacement)
                    provenance.extend((kind, span.start, span.end) for _ in replacement)
                    if kind == 'alias' and replacement:
                        protected.append((start, start + len(replacement)))
                    cursor = span.end
                parts.append(text[cursor:])
                provenance.extend(('raw', i, i + 1) for i in range(cursor, len(text)))
                candidate = ''.join(parts)
                issued = set(attempt._mapping.values())
                if any(m.group() in issued and (m.start(), m.end()) not in protected
                       for m in _PLACEHOLDER.finditer(candidate)):
                    attempt.close()
                    return LoopResult('review', None, iterations, 'alias_collision')
                residual = self.detector.detect(candidate)
                if any(d.get('type') in _SECRET or d.get('grade') in ('C', 'confidential_C') for d in residual):
                    attempt.close()
                    return LoopResult('blocked', None, iterations, 'confidential_residual', len(residual))
                # Validate even detections inside generated aliases.
                validated = _spans(candidate, residual)
                remaining = [s for s in validated if not any(a <= s.start and s.end <= b for a, b in protected)]
                if not remaining:
                    self._session = attempt
                    attempt = None
                    if not getattr(self.detector, 'model_enabled', False):
                        return LoopResult('review', candidate, iterations, 'incomplete_detector')
                    return LoopResult('checked', candidate, iterations, 'no_residual_detected')
                extra = []
                changed = False
                for span in remaining:
                    source = provenance[span.start:span.end]
                    kinds = {p[0] for p in source}
                    if kinds == {'generalized'} and len({(p[1], p[2]) for p in source}) == 1:
                        origin = (source[0][1], source[0][2])
                        if origin not in escalated:
                            escalated.add(origin)
                            changed = True
                    elif kinds == {'raw'} and all(source[i][2] == source[i + 1][1] for i in range(len(source) - 1)):
                        extra.append({'start': source[0][1], 'end': source[-1][2], 'type': span.kind})
                        changed = True
                    else:
                        attempt.close()
                        return LoopResult('review', None, iterations, 'ambiguous_residual', len(remaining))
                attempt.close()
                attempt = None
                if not changed:
                    return LoopResult('review', None, iterations, 'no_progress', len(remaining))
                spans = _spans(text, [{'start': s.start, 'end': s.end, 'type': s.kind} for s in spans] + extra)
            return LoopResult('review', None, iterations, 'iteration_limit', len(remaining))
        except (PseudonymError, ValueError, TypeError, AttributeError, KeyError):
            if attempt:
                attempt.close()
            return LoopResult('review', None, iterations, 'invalid_or_overlapping_detection')
        except Exception:
            if attempt:
                attempt.close()
            return LoopResult('review', None, iterations, 'detection_failed')

    def restore(self, text):
        if self._closed or self._session is None:
            raise RuntimeError('no active final mapping')
        return self._session.restore(text)

    def close(self):
        if self._session:
            self._session.close()
            self._session = None
        self._closed = True
