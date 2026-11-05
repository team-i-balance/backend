"""Dataset-driven classification accuracy.

Runs the labeled scenarios in tests/data/classification_dataset.json through
the real classifier and reports accuracy + a confusion matrix. This is the
"does it classify correctly, measured" test. When a detection engine exists
later, the same pattern can measure detection accuracy.
"""
import json
from collections import defaultdict
from pathlib import Path

import pytest

from app.classify import classify
from app.schemas import EventIn, Queue

DATASET = Path(__file__).parent / "data" / "classification_dataset.json"
CASES = json.loads(DATASET.read_text())["cases"]

# All labels must be valid queues (guards against typos in the dataset).
_VALID = {q.value for q in Queue}


def test_dataset_labels_are_valid_queues():
    bad = [c["id"] for c in CASES if c["expected_queue"] not in _VALID]
    assert not bad, f"invalid expected_queue labels: {bad}"


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_each_case_classified_correctly(case):
    got = classify(EventIn(**case["event"])).value
    assert got == case["expected_queue"], (
        f"{case['id']} ({case.get('note')}): expected "
        f"{case['expected_queue']}, got {got}"
    )


def test_overall_accuracy_and_confusion_matrix(capsys):
    confusion = defaultdict(lambda: defaultdict(int))  # expected -> got -> n
    correct = 0

    for case in CASES:
        expected = case["expected_queue"]
        got = classify(EventIn(**case["event"])).value
        confusion[expected][got] += 1
        if expected == got:
            correct += 1

    total = len(CASES)
    accuracy = correct / total

    # Per-queue precision/recall summary for visibility.
    labels = sorted(_VALID)
    lines = ["", f"Classification accuracy: {correct}/{total} = {accuracy:.1%}", ""]
    header = "expected \\ got".ljust(22) + "".join(l[:12].ljust(14) for l in labels)
    lines.append(header)
    for exp in labels:
        row = exp.ljust(22)
        for got in labels:
            row += str(confusion[exp][got]).ljust(14)
        lines.append(row)
    report = "\n".join(lines)
    print(report)

    # With the current rule set the dataset must classify perfectly.
    assert accuracy == 1.0, report


def test_dataset_covers_every_queue():
    labeled = {c["expected_queue"] for c in CASES}
    assert labeled == _VALID, f"dataset missing queues: {_VALID - labeled}"
