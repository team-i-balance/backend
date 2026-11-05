# 원문 전송 후 직원 사유 제출

`POST /events/{event_id}/reason`은 직원이 민감정보 원문 전송 후 사유를 제출하는 API입니다.
이벤트 ID는 `/process/decide` 응답의 `event.id` 또는 `/logs/events`의 `id`를 사용합니다.
처리 세션의 `work_id`가 만료되거나 해제되어도 사유는 제출할 수 있습니다.

## 흐름

1. `grade=sensitive_S`, `action=send_as_is`, `reason=null` 이벤트가 저장되면
   서버가 `reason_requested_at`을 전송 이벤트 생성 시각으로 기록합니다.
   이는 사유 제출이 필요하다는 상태이며, 직원에게 알림을 전송하는 기능은 포함하지 않습니다.
2. 직원 앱이 이벤트 ID와 사유 코드·본문을 아래 API로 보냅니다.
3. 서버가 사유와 제출 시각을 SQLite에 저장하고 최신 이벤트를 반환합니다.
4. 콘솔이 로그를 다시 읽어 `reason_at`이 있으면 ‘사유 도착’으로 표시합니다.

공개 전송, 기밀 차단, 변환 전송, 취소, 되돌림, 이미 전송 시 사유를 선택한 이벤트는
후속 사유 요청 대상이 아닙니다. 현재 콘솔의 필수 검토 기준인 민감 원문 전송에 맞춥니다.

```http
POST /events/42/reason
Content-Type: application/json

{
  "reason": "business_need",
  "text": "거래처 확인에 실제 연락처가 필요했습니다."
}
```

- `event_id`: 양의 정수 이벤트 ID. `INC-42` 같은 콘솔 표시용 건 ID가 아닙니다.
- `reason`: `business_need` 또는 `false_positive`.
- `text`: 앞뒤 공백 제거 후 1~500자. 사유 설명을 보내며 원문 프롬프트·개인정보를 복사하지 않습니다.
- 요청 본문의 다른 필드는 거부합니다. 시각이나 직원 ID를 클라이언트에서 지정할 수 없습니다.

성공 응답은 `200`과 기존 `EventOut` 전체입니다. 추가되는 필드는 다음과 같습니다.

| 필드 | 의미 |
| --- | --- |
| `reason` | 제출한 사유 코드 |
| `reason_text` | 제출한 사유 본문. 미제출 시 `null` |
| `reason_requested_at` | 사유 대기 시작 시각. 후속 사유 요청 대상이 아니면 `null` |
| `reason_at` | 서버가 기록한 UTC 제출 시각. 미제출 시 `null` |

같은 필드는 `/process/decide`, `GET /logs/events`, `GET /logs/queues/{name}`에서도 반환하며,
암호화 로그 내보내기에도 포함합니다. 전송 시 사유 코드를 함께 보낸 이벤트의 `reason_at`은
이벤트 생성 시각이고 `reason_requested_at`은 `null`입니다.

사유 코드와 로그 큐는 기존 분류 규칙에 따라 함께 갱신됩니다.
`business_need`는 `violation_candidate`, `false_positive`는 `detection_improve`이며
`/logs/stats`도 갱신된 사유·큐를 집계합니다. 전송 행동·등급·해시·탐지 결과·생성 시각은 유지합니다.
직원의 사유는 보안팀 판단이 아니므로 **검토 건을 자동으로 종결하거나 다시 열지 않습니다.**

## 사유 상태 조회 (직원 앱)

`GET /events/{event_id}/reason`은 api 토큰으로 사유 진행 상태만 돌려줍니다(탐지 내용·직원 정보는 없음).
보안팀이 `POST /events/{id}/reason-request`([false-positive-api.md](false-positive-api.md))로
사유를 다시 요청하면 `reason_requested_at`이 바뀝니다. 직원 앱은 실행할 때 사유를 내지 않은 이벤트를
조회해서 `reason_needed=true`이고 `reason_requested_at`이 마지막으로 본 값보다 새로우면 다시 묻습니다.

```json
{
  "event_id": 42,
  "reason_needed": true,
  "reason_requested_at": "2026-11-05T06:00:00+00:00",
  "reason": null,
  "reason_at": null
}
```

`reason_needed`는 민감 원문 전송이면서 사유 대기 중이고 아직 제출하지 않았을 때만 `true`입니다.
없는 이벤트는 `404 EVENT_NOT_FOUND`이고, 응답에는 `Cache-Control: no-store`가 붙습니다.

## 재시도와 오류

| 상태 | 의미 |
| --- | --- |
| `200` | 최초 저장 또는 동일한 사유 코드·본문 재전송. 재전송은 최초 제출 시각을 유지 |
| `404 EVENT_NOT_FOUND` | 없는 이벤트 |
| `409 REASON_NOT_REQUESTED` | 후속 사유 요청 대상이 아닌 이벤트 |
| `409 REASON_ALREADY_SUBMITTED` | 이미 저장된 사유와 다른 내용으로 재제출 |
| `422` | 잘못된 ID·사유 코드·빈 본문·500자 초과·알 수 없는 필드 |

사유 수정·삭제 API는 제공하지 않습니다. 서로 다른 사유가 동시에 도착하면 하나만 저장됩니다.
사유 코드·본문·시각·큐는 하나의 DB 트랜잭션으로 저장됩니다.

## 기존 DB와 검토 API 연결

서버 시작 시 `LOG_DB_PATH`의 기존 DB에 부족한 필드를 추가합니다. `reason_text`가
이미 있는 DB에서도 해당 값은 보존합니다. 기존 미제출 민감 원문 전송은
`reason_requested_at=created_at`, 전송 시 사유가 있던 이벤트는 `reason_at=created_at`으로
보완합니다. 이는 기존 이벤트 생성 시각으로 추정한 값이며 과거 알림 발송 시각을 뜻하지 않습니다.
이미 저장된 제출 내용·시각은 재시작으로 바뀌지 않습니다.

검토 상세 `/cases/INC-42`의 `event.reason`, `event.reason_text`,
`event.reason_requested_at`, `event.reason_at`으로 사유를 읽습니다. 건 ID 대신 상세의
`event.id`를 직원 앱의 제출 경로에 사용하세요. 기존 종결·다시 열기 이력은 유지됩니다.

직원 앱의 제출 화면과 콘솔의 사유 표시 연결은 각 클라이언트에서 구현해야 합니다.
현재 서버에는 인증이 없어 제출자의 신원을 확인하지 않습니다. 인증 이슈
[#10](https://github.com/team-i-balance/backend/issues/10)에서 검증된 직원·기기와 대상 이벤트의
소유 관계를 확인하도록 연결해야 합니다. 이 PR은 클라이언트가 보낸 직원 이름을 신원으로 저장하지 않습니다.

## 테스트

```bash
python -m pytest tests/test_event_reason.py -q
python -m pytest -q
```

실제 `/process` → 원문 전송 → 사유 제출, 기존 DB 업그레이드·프로세스 재시작,
동일 요청 재시도, 동시 제출 충돌, 저장 실패 시 롤백과 입력 검증을 확인합니다.
