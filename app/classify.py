"""Queue classification.

Implements the priority rules defined in app/rules.md section 4.
Evaluated top-down; the first matching rule wins.
"""
from app.schemas import Action, Confidence, EventIn, Grade, Queue, Reason

# Actions that let the original text (or part of it) reach the external AI.
_RAW_SEND_ACTIONS = (Action.send_as_is, Action.revert_original)


def classify(event: EventIn) -> Queue:
    # 1. 오탐 -> 탐지 개선 큐
    if event.reason == Reason.false_positive:
        return Queue.detection_improve

    # 2. 업무상 필요 -> 위반 후보 큐
    if event.reason == Reason.business_need:
        return Queue.violation_candidate

    # 3. 민감·기밀 + 원문 전송(그대로 / 사유 없는 되돌림) + 확실한 탐지(high) -> 실제 위반 큐
    #    (사유가 있는 원문 전송은 규칙 1·2에서 이미 걸렀다)
    #    로그 큐는 보안팀 검토 건(/cases, app/case_crud.py)의 필수·선택과 별개다.
    #    검토 건은 탐지 신뢰도와 상관없이 S·C 원문 전송을 모두 다룬다(#60, #62).
    if (
        event.grade != Grade.public
        and event.action in _RAW_SEND_ACTIONS
        and event.detection_confidence == Confidence.high
    ):
        return Queue.real_violation

    # 4. 변환 전송 / 취소 -> 사전 경고 로그 (유형·건수만). 취소는 아무것도 나가지 않았으므로 위반이 아니다
    if event.action in (Action.send_transformed, Action.cancel):
        return Queue.pre_warning

    # 5. 그 외 (send_as_is, revert_original 등) -> 사전 경고로 기본 수렴
    return Queue.pre_warning
