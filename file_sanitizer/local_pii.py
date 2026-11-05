"""Use the team's on-device PII model for one XLSX document."""

from collections.abc import Callable, Sequence

from local_ai.pipeline import LocalSession

from .sanitizer import Decision, Grade, ResidualPIIError


def _default_grade(detected_types: Sequence[str]) -> Grade:
    return "S" if detected_types else "O"


class LocalPIIProcessor:
    def __init__(
        self,
        session: LocalSession,
        *,
        classify: Callable[[Sequence[str]], Grade] = _default_grade,
    ):
        if not session.detector.model_enabled:
            raise ValueError("XLSX PII processing requires a local model")
        self.session = session
        self.classify = classify

    def process(self, session_id, segments):
        decisions = {}
        # The same name or heading often occurs thousands of times in one file.
        # Reuse results only within this call and its existing pseudonym mapping.
        checked = {}
        for segment in segments:
            if segment.text not in checked:
                result = self.session.process(segment.text)
                if result.remaining:
                    raise ResidualPIIError()
                checked[segment.text] = result
            result = checked[segment.text]
            grade = self.classify(result.detection_types)
            decisions[segment.id] = Decision(grade, result.text if segment.exportable else None)
        return decisions

    def verify(self, session_id, segments):
        # Read the serialized copy without allocating any new tokens.
        texts = dict.fromkeys(segment.text for segment in segments)
        return all(not self.session.detector.detect(text) for text in texts)
