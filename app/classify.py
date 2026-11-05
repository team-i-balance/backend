"""Queue classification.

Implements the priority rules defined in app/rules.md section 4.
Evaluated top-down; the first matching rule wins.
"""
from app.schemas import Action, Confidence, EventIn, Queue, Reason


def classify(event: EventIn) -> Queue:
    # 1. 오탐 -> 탐지 개선 큐
    if event.reason == Reason.false_positive:
        return Queue.detection_improve

    # 2. 업무상 필요 -> 위반 후보 큐
    if event.reason == Reason.business_need:
        return Queue.violation_candidate

    # 3. 취소 + 확실한 탐지(high) -> 실제 위반 큐
    if (
        event.action == Action.cancel
        and event.detection_confidence == Confidence.high
    ):
        return Queue.real_violation

    # 4. 변환 전송 / 취소 -> 사전 경고 로그 (유형·건수만)
    if event.action in (Action.send_transformed, Action.cancel):
        return Queue.pre_warning

    # 5. 그 외 (send_as_is, revert_original 등) -> 사전 경고로 기본 수렴
    return Queue.pre_warning
