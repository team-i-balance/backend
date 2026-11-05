"""Use the team's on-device PII model for one XLSX document."""

from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from local_ai.pipeline import LocalSession

from .sanitizer import Decision, Grade, ResidualPIIError, segment_place


def _default_grade(detected_types: Sequence[str]) -> Grade:
    return "S" if detected_types else "O"


@dataclass
class Findings:
    """Detected types and counts only: never values, positions or file names."""

    # Places in the cells written to the protected copy, where they were masked.
    cells: Counter = field(default_factory=Counter)
    # Places the protected copy leaves out: the file name, document properties,
    # number formats, sheet names, comments and their authors, hidden sheets,
    # rows and columns, and cells hidden by their number format.
    removed: Counter = field(default_factory=Counter)
    # Types that made a part confidential (C) and so block the whole file.
    blocked: set = field(default_factory=set)

    @property
    def types(self) -> list[str]:
        return sorted(set(self.cells) | set(self.removed))

    @property
    def count(self) -> int:
        return sum(self.cells.values()) + sum(self.removed.values())


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
        # What the last completed process() call found.
        self.findings = Findings()

    def process(self, session_id, segments):
        decisions = {}
        findings = Findings()
        # Per place, the most of each type that any reading of it found: a cell
        # and its stored value, or a number format and its labels, count once.
        places: dict[str, Counter] = {}
        exported = set()
        # The same name or heading often occurs thousands of times in one file.
        # Reuse results only within this call and its existing pseudonym mapping.
        checked = {}
        # A cell may quote a placeholder ("[이름_1]") that an earlier cell would
        # otherwise be assigned; reserve such text from every part up front.
        self.session.reserve_literals(segment.text for segment in segments)
        for segment in segments:
            if segment.text not in checked:
                result = self.session.process(segment.text)
                if result.remaining:
                    raise ResidualPIIError()
                checked[segment.text] = result
            result = checked[segment.text]
            grade = self.classify(result.detection_types)
            decisions[segment.id] = Decision(grade, result.text if segment.exportable else None)
            if grade == "C":
                # Name the types that are confidential by themselves, if the policy has any.
                findings.blocked.update(
                    {kind for kind in result.detection_types if self.classify((kind,)) == "C"}
                    or result.detection_types
                )
            place = segment_place(segment.id)
            places[place] = places.get(place, Counter()) | Counter(dict(result.detection_counts))
            if segment.exportable:
                exported.add(place)
        for place, counts in places.items():
            (findings.cells if place in exported else findings.removed).update(counts)
        self.findings = findings
        return decisions

    def verify(self, session_id, segments):
        # Read the serialized copy without allocating any new tokens.
        texts = dict.fromkeys(segment.text for segment in segments)
        return all(not self.session.detector.detect(text) for text in texts)
