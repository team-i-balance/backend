# 오탐 신고 판단 · 사유 재요청 API

보안 콘솔이 쓰는 API입니다. 세 API 모두 **보안팀 토큰(`security` scope)** 이 필요합니다.
토큰이 없거나 모르는 토큰이면 `401`, `api` 토큰이면 `403`입니다. 응답에는 `Cache-Control: no-store`가 붙습니다.

## 오탐 신고 묶음

### 무엇을 신고로 세나

이벤트의 `items[]` 항목 하나가 아래 조건을 모두 만족하면 그 값에 대한 오탐 신고 1건입니다.

- 항목의 사유(`items[].reason`)가 `false_positive`이거나, 항목 사유가 없고 이벤트 사유(`reason`)가 `false_positive`
- 항목에 `value_hash`(조직 키 HMAC-SHA256)가 있음
- 테스트 이벤트(`test=true`)가 아님

`value_hash`가 없는 항목, `items`가 비어 있는 이벤트는 같은 값끼리 묶을 수 없어 이 목록에 나오지 않습니다.
이런 신고는 기존처럼 `/logs/queues/detection_improve`에서 이벤트 단위로 봅니다.
`value_hash`는 대소문자를 구분하지 않습니다(소문자로 묶음).

신고 시각은 사유 제출 시각(`reason_at`)이고, 없으면 이벤트 생성 시각입니다.
원문 전송 뒤 나중에 `POST /events/{id}/reason`으로 오탐 사유를 낸 경우도 그때 신고된 것으로 셉니다.

### `GET /false-positives?status=open|done`

`status` 기본값은 `open`. 마지막 신고가 최근인 묶음부터 돌려줍니다.

```json
{
  "items": [
    {
      "value_hash": "3f9a…(64자)",
      "status": "open",
      "report_count": 3,
      "employee_count": 2,
      "last_reported_at": "2026-11-05T01:02:03.456789+00:00",
      "preview": "윤*아",
      "types": ["NAME"],
      "decision": null
    }
  ]
}
```

| 필드 | 의미 |
| --- | --- |
| `report_count` | 신고한 이벤트 수(한 이벤트에 같은 값이 여러 번 있어도 1) |
| `employee_count` | 서로 다른 `user_id` 수(`user_id` 없는 이벤트는 세지 않음) |
| `preview` | 가장 최근 신고 중 preview가 있는 항목의 마스킹 값. 없으면 `null` |
| `types` | 그 값이 탐지된 유형 |
| `decision` | 가장 최근 판단 `{decision, why, by, at}`. 판단한 적 없으면 `null` |

`status`는 판단이 마지막 신고 이후에 있으면 `done`, 아니면 `open`입니다.
판단 뒤 같은 값으로 새 신고가 오면 다시 `open`이 되고, `decision`에는 이전 판단이 그대로 보입니다.

### `POST /false-positives/{value_hash}/decide`

```http
POST /false-positives/3f9a…/decide
Content-Type: application/json

{ "decision": "exclude", "why": "사람 이름이 아니라 제품명" }
```

- `decision`: `keep`(탐지 결과 유지) 또는 `exclude`(탐지 제외)
- `why`: 선택. 앞뒤 공백 제거 후 1~1000자
- 다른 필드는 거부(`422`). 처리자·시각은 서버가 정합니다.

성공하면 `200`과 갱신된 묶음 하나(위 `items[]` 항목과 같은 모양, `status: "done"`)를 돌려줍니다.
이미 판단한 값도 다시 판단할 수 있으며, 가장 최근 판단이 현재 판단입니다.

| 상태 | 의미 |
| --- | --- |
| `404 FALSE_POSITIVE_NOT_FOUND` | 그 값으로 들어온 오탐 신고가 없음 |
| `422` | 잘못된 해시(64자리 16진수 아님)·판단 값·빈 `why`·알 수 없는 필드 |

`exclude` 판단을 실제 탐지 정책에 반영하는 일(정책의 `hmac:` 제외 항목)은 콘솔이 정책 API로 합니다.
이 API는 판단만 저장합니다.

### 처리자(`by`)

현재 토큰에는 사람 신원이 없습니다. 그래서 클라이언트가 보낸 이름을 믿지 않고,
보안 토큰의 SHA-256 앞 12자리로 `security:1a2b3c4d5e6f` 형태를 기록합니다(토큰 자체는 저장하지 않음).
`AUTH_DISABLED=1`(테스트용)에서는 `auth-disabled`입니다.

### 저장

판단은 `false_positive_decision` 테이블에 추가만 합니다(덮어쓰지 않음).

| 열 | 내용 |
| --- | --- |
| `value_hash` | 소문자 64자리 HMAC 해시 |
| `decision` | `keep` / `exclude` |
| `why` | 판단 메모(선택) |
| `decided_by` / `decided_at` | 처리자 / UTC 시각 |

원문과 preview는 이 테이블에 저장하지 않습니다(preview는 이벤트 항목에서 읽음).
서버 시작 시 `init_db`가 `CREATE TABLE IF NOT EXISTS`로 만들며, 여러 번 실행해도 기존 판단은 그대로입니다.

## 사유 재요청

### `POST /events/{event_id}/reason-request`

원문 전송 뒤 사유를 내지 않은 직원에게 다시 묻게 합니다. 본문은 없습니다.
서버가 `reason_requested_at`을 지금 시각으로 바꾸고, 직원 앱은 다음 실행 때 이 값이 바뀐 것을 보고 다시 묻습니다.
알림 발송은 하지 않습니다(추후).

성공하면 `200`과 `EventOut` 전체를 돌려줍니다. 사유가 들어오기 전까지는 여러 번 호출할 수 있습니다.

| 상태 | 의미 |
| --- | --- |
| `404 EVENT_NOT_FOUND` | 없는 이벤트 |
| `409 REASON_NOT_REQUESTED` | 민감(`sensitive_S`) 원문 전송(`send_as_is`)이 아닌 이벤트 |
| `409 REASON_ALREADY_SUBMITTED` | 이미 사유가 있는 이벤트(전송 때 사유를 고른 경우 포함) |
| `422` | 잘못된 ID |

오류 코드는 직원 사유 제출 API([event-reason-api.md](event-reason-api.md))와 같습니다.
