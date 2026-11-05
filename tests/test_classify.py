"""Unit tests for queue classification (app/classify.py).

Covers every rule in rules.md section 4 plus priority conflicts.
"""
import pytest

from app.classify import classify
from app.schemas import Action, Confidence, EventIn, Queue, Reason


def ev(**kw) -> EventIn:
    base = dict(grade="sensitive_S", action="send_transformed")
    base.update(kw)
    return EventIn(**base)


# --- Rule 1: 오탐 -> detection_improve ---------------------------------------
@pytest.mark.parametrize("action", list(Action))
@pytest.mark.parametrize("conf", [None, *list(Confidence)])
def test_false_positive_always_detection_improve(action, conf):
    e = ev(action=action, reason=Reason.false_positive, detection_confidence=conf)
    assert classify(e) == Queue.detection_improve


# --- Rule 2: 업무상 필요 -> violation_candidate ------------------------------
@pytest.mark.parametrize("action", list(Action))
def test_business_need_violation_candidate(action):
    e = ev(action=action, reason=Reason.business_need)
    assert classify(e) == Queue.violation_candidate


# --- Rule 3: 취소 + high -> real_violation -----------------------------------
def test_cancel_high_is_real_violation():
    e = ev(action=Action.cancel, detection_confidence=Confidence.high)
    assert classify(e) == Queue.real_violation


@pytest.mark.parametrize("conf", [Confidence.medium, Confidence.low, None])
def test_cancel_not_high_is_pre_warning(conf):
    e = ev(action=Action.cancel, detection_confidence=conf)
    assert classify(e) == Queue.pre_warning


# --- Rule 4/5: action based / default -> pre_warning -------------------------
@pytest.mark.parametrize(
    "action",
    [Action.send_transformed, Action.send_as_is, Action.revert_original],
)
def test_action_based_pre_warning(action):
    e = ev(action=action, detection_confidence=Confidence.high)
    assert classify(e) == Queue.pre_warning


# --- Priority conflicts ------------------------------------------------------
def test_false_positive_beats_cancel_high():
    # Rule 1 must win over rule 3 even though cancel+high would be real_violation.
    e = ev(
        action=Action.cancel,
        reason=Reason.false_positive,
        detection_confidence=Confidence.high,
    )
    assert classify(e) == Queue.detection_improve


def test_business_need_beats_cancel_high():
    # Rule 2 must win over rule 3.
    e = ev(
        action=Action.cancel,
        reason=Reason.business_need,
        detection_confidence=Confidence.high,
    )
    assert classify(e) == Queue.violation_candidate


def test_every_queue_is_reachable():
    produced = set()
    produced.add(classify(ev(reason=Reason.false_positive)))
    produced.add(classify(ev(reason=Reason.business_need)))
    produced.add(
        classify(ev(action=Action.cancel, detection_confidence=Confidence.high))
    )
    produced.add(classify(ev(action=Action.send_transformed)))
    assert produced == set(Queue)
