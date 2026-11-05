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


# --- Rule 3: 민감·기밀 + 원문 전송 + high -> real_violation (issue #20) --------
@pytest.mark.parametrize("grade", ["sensitive_S", "confidential_C"])
@pytest.mark.parametrize("action", [Action.send_as_is, Action.revert_original])
def test_raw_send_high_is_real_violation(grade, action):
    e = ev(grade=grade, action=action, detection_confidence=Confidence.high)
    assert classify(e) == Queue.real_violation


@pytest.mark.parametrize("conf", [Confidence.medium, Confidence.low, None])
@pytest.mark.parametrize("action", [Action.send_as_is, Action.revert_original])
def test_raw_send_not_high_is_pre_warning(action, conf):
    e = ev(action=action, detection_confidence=conf)
    assert classify(e) == Queue.pre_warning


@pytest.mark.parametrize("action", [Action.send_as_is, Action.revert_original])
def test_public_raw_send_is_pre_warning(action):
    e = ev(grade="public_O", action=action, detection_confidence=Confidence.high)
    assert classify(e) == Queue.pre_warning


@pytest.mark.parametrize("conf", [Confidence.high, Confidence.medium, Confidence.low, None])
def test_cancel_is_never_real_violation(conf):
    # Nothing reached the AI, so a cancel is not a violation even with a certain detection.
    e = ev(grade="confidential_C", action=Action.cancel, detection_confidence=conf)
    assert classify(e) == Queue.pre_warning


# --- Rule 4/5: action based / default -> pre_warning -------------------------
def test_transformed_high_is_pre_warning():
    e = ev(action=Action.send_transformed, detection_confidence=Confidence.high)
    assert classify(e) == Queue.pre_warning


# --- Priority conflicts ------------------------------------------------------
def test_false_positive_beats_raw_send_high():
    # Rule 1 must win over rule 3 even though revert+high would be real_violation.
    e = ev(
        action=Action.revert_original,
        reason=Reason.false_positive,
        detection_confidence=Confidence.high,
    )
    assert classify(e) == Queue.detection_improve


def test_business_need_beats_raw_send_high():
    # Rule 2 must win over rule 3.
    e = ev(
        action=Action.send_as_is,
        reason=Reason.business_need,
        detection_confidence=Confidence.high,
    )
    assert classify(e) == Queue.violation_candidate


def test_every_queue_is_reachable():
    produced = set()
    produced.add(classify(ev(reason=Reason.false_positive)))
    produced.add(classify(ev(reason=Reason.business_need)))
    produced.add(
        classify(ev(action=Action.send_as_is, detection_confidence=Confidence.high))
    )
    produced.add(classify(ev(action=Action.send_transformed)))
    assert produced == set(Queue)
