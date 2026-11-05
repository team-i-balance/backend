"""Local-only PII pseudonymization. No server or external API calls."""
from collections import Counter
from dataclasses import dataclass, field
from .detector import Detector
from .pseudonym import PseudonymSession


@dataclass(frozen=True)
class CheckResult:
    text: str
    detection_types: tuple[str, ...]
    remaining: tuple[dict, ...]
    coverage: str
    detection_count: int = 0  # number of detected spans (not distinct types)
    # (type, span count) pairs sorted by type; the counts add up to detection_count.
    detection_counts: tuple[tuple[str, int], ...] = ()
    # Masked spans in text order (MaskedSpan); raw values, memory only.
    spans: tuple = field(default=(), repr=False, compare=False)


class LocalSession:
    """One in-memory mapping per task. Call close() to release it."""

    def __init__(self, detector: Detector):
        self.detector = detector
        self._pseudonyms = PseudonymSession()
        self._closed = False

    def process(self, text: str) -> CheckResult:
        if self._closed:
            raise RuntimeError('session is closed')
        # Both detections must complete; callers must treat exceptions as failure.
        detections = self.detector.detect(text)
        anonymized, spans = self._pseudonyms.pseudonymize_spans(text, detections)
        remaining = self.detector.detect(anonymized)
        counts = Counter(d['type'] for d in detections)
        return CheckResult(anonymized, tuple(sorted(counts)),
                           tuple(remaining), 'model_and_rules' if self.detector.model_enabled else 'rules_only_incomplete',
                           len(detections), tuple(sorted(counts.items())), spans)

    def restore(self, text: str):
        if self._closed:
            raise RuntimeError('session is closed')
        return self._pseudonyms.restore(text)

    def close(self):
        self._pseudonyms.close()
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
