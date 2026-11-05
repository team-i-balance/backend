# 사내 로그 분류 규칙 (임시 / v0.1)

> 이 문서는 런타임 이벤트를 로그 큐로 분류하기 위한 임시 사내 기준이다.
> 탐지 엔진이 아직 범위 밖이므로, 여기서 정의한 기준을 분류 로직
> (`app/classify.py`)이 그대로 참조한다. 값이 바뀌면 이 문서를 먼저 고친다.

## 1. 탐지 신뢰도 등급 (detection_confidence)

이벤트 payload의 `detection_confidence` 필드는 다음 중 하나다.

| 값       | 의미                 | "확실한 탐지" 여부 |
| -------- | -------------------- | ------------------ |
| `high`   | 확실한 탐지          | O (확실)           |
| `medium` | 가능성 있음          | X                  |
| `low`    | 약한 신호            | X                  |

- **"확실한 탐지" = `detection_confidence == "high"`** 로 정의한다.

## 2. 사용자 사유 (reason)

| 값                | 의미          |
| ----------------- | ------------- |
| `false_positive`  | 오탐          |
| `business_need`   | 업무상 필요   |
| `null` (없음)     | 사유 미입력   |

## 3. 사용자 액션 (action)

| 값                 | 의미                       |
| ------------------ | -------------------------- |
| `send_as_is`       | 그대로 전송 (공개 O 등)    |
| `send_transformed` | 변환문 전송                |
| `cancel`           | 취소                       |
| `revert_original`  | 일부 되돌림 / 원문 전송    |

## 4. 큐 분류 규칙 (우선순위 순, 먼저 매칭되는 하나로 배정)

흐름도 S5("큐 분류")를 따른다. 위에서부터 평가하여 **처음 일치하는 큐** 하나로 보낸다.

1. `reason == false_positive`
   → **detection_improve** (탐지 개선 큐)

2. `reason == business_need`
   → **violation_candidate** (위반 후보 큐)

3. `action == cancel` **그리고** `detection_confidence == high`
   → **real_violation** (실제 위반 큐)
   - "무시 + 확실한 탐지"에 해당. 사용자가 취소(=전송 포기)했고 탐지가 확실한 경우.

4. `action in {send_transformed, cancel}`
   → **pre_warning** (사전 경고 로그, 유형·건수만)
   - 위 1~3에 걸리지 않은 변환 전송/취소 건.

5. 그 외 (예: `send_as_is`, `revert_original`)
   → **pre_warning** 로 기본 수렴 (유형·건수만 남김)

> 비고: 규칙 3은 규칙 4보다 먼저 평가되므로, "확실한 탐지 + 취소"는
> real_violation 으로, 그렇지 않은 취소는 pre_warning 으로 간다.

## 5. 집계 지표 (조회 시 계산)

- **수용률(acceptance_rate)** = (`send_as_is` + `send_transformed`) / 전체
- **되돌림률(revert_rate)** = (`reverted == 1`) / 전체
- **회피 의심(evasion_suspect)** = `reason == business_need` 건수
  (업무상 필요를 반복적으로 선택하는 패턴을 1차 지표로 사용)

## 6. 로깅 원칙

- 원문/변환문 **본문은 저장하지 않는다.** 식별이 필요하면 `content_hash`
  (SHA-256) 만 남긴다.
- 사전 경고 로그는 **민감정보 유형과 건수만** 남긴다 (`detected_types`,
  `detected_count`).
