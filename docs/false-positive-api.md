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

신고 시각은 다음과 같습니다.

- 항목에 직접 `reason: false_positive`를 단 경우: 이벤트 생성 시각(`created_at`). 이후 이벤트 사유가 따로 제출돼도 바뀌지 않습니다.
- 이벤트 사유를 물려받은 경우: 사유 제출 시각(`reason_at`), 없으면 생성 시각. 원문 전송 뒤 나중에
  `POST /events/{id}/reason`으로 오탐 사유를 내면 그때 새로 신고된 것으로 셉니다.

### `GET /false-positives?status=open|done&limit=100&cursor=…`

`status` 기본값은 `open`. 응답은 묶음 배열이며, 그 값을 마지막으로 신고한 이벤트 ID(`last_event_id`)가 큰 순서입니다.

```json
[
  {
    "value_hash": "3f9a…(64자)",
    "status": "open",
    "report_count": 3,
    "employee_count": 2,
    "last_event_id": 901,
    "last_reported_at": "2026-11-05T01:02:03.456789+00:00",
    "preview": "윤*아",
    "types": ["NAME"],
    "decision": null
  }
]
```

페이지 넘김은 `/logs/events`와 같은 방식입니다([log-stats-api.md](log-stats-api.md)).

- `limit`: 1~1000, 기본 100
- `cursor`: 이전 페이지 마지막 묶음의 `last_event_id`. 서버는 `last_event_id`가 그보다 작은 묶음을 돌려줍니다.
- 한 이벤트가 여러 값을 신고해 `last_event_id`가 같은 묶음은 한 페이지에 모두 담습니다. 그래서 페이지가 `limit`보다 조금 길 수 있습니다.
- 받은 개수가 `limit`보다 적으면 마지막 페이지입니다. 더 없으면 `[]`입니다. 잘못된 `limit`·`cursor`는 `422`입니다.
- `status`는 페이지를 나누기 전에 적용합니다. 조회 사이에 새 신고나 판단이 생기면 묶음이 다른 페이지나 다른 `status`로 옮겨갈 수 있습니다.

집계는 SQLite 안에서 하고, 한 페이지에 나온 묶음만 preview와 시각을 더 읽습니다.

| 필드 | 의미 |
| --- | --- |
| `last_event_id` | 그 값을 마지막으로 신고한 이벤트 ID(정렬·커서 기준) |
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

성공하면 `200`과 갱신된 묶음 하나(위 목록의 원소와 같은 모양, `status: "done"`)를 돌려줍니다.
이미 판단한 값도 다시 판단할 수 있으며, 가장 최근 판단이 현재 판단입니다.

| 상태 | 의미 |
| --- | --- |
| `404 FALSE_POSITIVE_NOT_FOUND` | 그 값으로 들어온 오탐 신고가 없음 |
| `422` | 잘못된 해시(64자리 16진수 아님)·판단 값·빈 `why`·알 수 없는 필드 |

`exclude` 판단을 실제 탐지 정책에 반영하는 일(정책의 `hmac:` 제외 항목)은 콘솔이 정책 API로 합니다.
이 API는 판단만 저장합니다.

### 처리자(`by`)

현재 토큰에는 사람 신원이 없습니다. 그래서 클라이언트가 보낸 이름을 믿지 않고,
`/cases`와 같은 `app.auth.security_principal`을 씁니다. 환경변수 토큰은 `security:<SHA-256 앞 12자리>`,
dev 토큰은 `security-dev:<…>`로 기록하며 토큰 자체는 저장하지 않습니다.
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
서버가 `reason_requested_at`을 지금 시각으로 바꿉니다. 직원 앱은 실행할 때 사유를 내지 않은 원문 전송 이벤트마다
`GET /events/{id}/reason`(api 토큰, [event-reason-api.md](event-reason-api.md))을 불러
`reason_needed=true`이고 `reason_requested_at`이 앱이 마지막으로 본 값보다 새로우면 다시 묻습니다.
푸시 알림 발송은 하지 않습니다(추후).

성공하면 `200`과 `EventOut` 전체를 돌려줍니다. 사유가 들어오기 전까지는 여러 번 호출할 수 있습니다.

| 상태 | 의미 |
| --- | --- |
| `404 EVENT_NOT_FOUND` | 없는 이벤트 |
| `409 REASON_NOT_REQUESTED` | 민감(`sensitive_S`)·기밀(`confidential_C`) 원문 전송(`send_as_is`·`revert_original`)이 아닌 이벤트 |
| `409 REASON_ALREADY_SUBMITTED` | 이미 사유가 있는 이벤트(전송 때 사유를 고른 경우 포함) |
| `422` | 잘못된 ID |

오류 코드는 직원 사유 제출 API([event-reason-api.md](event-reason-api.md))와 같습니다.
