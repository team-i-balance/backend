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

## 7. 등급 판정 (흐름도 S2) — local_ai 탐지 결과 → 등급

서버(사내)에서 local_ai로 탐지한 유형을 보고 등급을 정한다.

| 조건 | 등급 |
| --- | --- |
| 비밀정보 유형이 하나라도 있음 (`API_KEY`, `ACCESS_TOKEN`, `PASSWORD`) | **기밀 C** (`confidential_C`) |
| 위가 없고 개인정보 유형이 있음 (`NAME`, `PHONE`, `EMAIL`, `ADDRESS`, `ID`/`ID_NUMBER`, `ACCOUNT`, `CARD`, `DOB`, `USERNAME`, `IP_ADDRESS`, `BUSINESS_NUMBER`) | **민감 S** (`sensitive_S`) |
| 아무것도 탐지되지 않음 | **공개 O** (`public_O`) |

비밀정보가 있으면 전체를 기밀로 본다(가장 높은 민감도 우선).

## 8. 탐지 신뢰도 매핑 (coverage → detection_confidence)

local_ai의 `coverage`를 로그의 `detection_confidence`로 바꾼다.

| local_ai coverage | confidence | 쉬운 설명 |
| --- | --- | --- |
| `model_and_rules` | `high` | 꼼꼼히 검사함 (AI 모델 + 규칙) |
| `rules_only_incomplete` | `low` | 대충만 검사함 (전화·이메일 규칙만, 이름·주소 못 봄) |

## 9. 서버 처리 원칙 (/process, /decide)

- 처리는 **사내 서버**에서 수행한다. 원문 텍스트는 **메모리에서만** 쓰고
  디스크 저장·로그 기록을 하지 않는다.
- 로그 이벤트에는 원문/가명문 본문을 넣지 않는다. 원문의 SHA-256 해시
  (`content_hash`)와 유형·건수·등급만 남긴다.
- 복원용 가명 매핑(`work_id` 단위)은 메모리에 잠시 보관하고 TTL 만료 또는
  `/decide` 처리 후 폐기한다.

## 10. 정책 번들 배포 + 서명 검증 (흐름도 S7)

보안팀 도구(S6)가 만든 **서명된 정책 번들**을 받아 서명을 검증하고,
유효하면 활성 정책으로 채택한다. 무효면 **번들을 무시**(기존 정책 유지).

> 번들 포맷과 서명 방식은 S6 팀원이 확정 예정이다. 그래서 포맷 의존 부분을
> `app/policy.py`의 **상수(FIELD_*)** 와 **`PolicyVerifier` 인터페이스**로
> 격리했다. 실제 포맷이 오면 verifier(또는 상수)만 교체하면 되고, 저장소·
> 라우터·테스트는 그대로다.

기본 가정(교체 가능):

```json
{
  "payload": { "version": <int>, "rules": [ ... ] },
  "signature": "<base64 Ed25519 서명 (canonical(payload) 대상)>",
  "key_id": "<문자열>"
}
```

- 서명 대상: `payload`의 **정규화 JSON**(키 정렬·공백 최소). 키 순서가 달라도
  검증이 깨지지 않는다.
- 서버는 **공개키만** 보관(검증용). 개인키는 보안팀 오프라인(여기선 테스트용
  임시 키 생성).
- **버전 규칙**: 활성 버전보다 **큰 version만** 채택(롤백 방지). 같거나 낮으면 거부.
- 검증/버전 거부 시 활성 정책은 바뀌지 않는다.

엔드포인트:

| Method | Path | 설명 |
| --- | --- | --- |
| POST | `/policy/deploy` | 번들 검증 → 유효+최신이면 활성화, 아니면 거부(무시) |
| GET | `/policy/current` | 현재 활성 정책 메타(버전·key_id·규칙 수·활성 시각) |

> 활성화된 정책을 실제 변환(S2 되먹임)에 적용하는 것은 다음 단계다.
