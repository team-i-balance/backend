# 보안팀 검토 API

이벤트에 보안팀 판단과 종결·다시 열기 이력을 연결합니다. 상태는 브라우저가 아니라
`LOG_DB_PATH`의 SQLite DB에 저장되어 새로고침·프로세스 재시작 후에도 유지됩니다.
서버 시작 시 기존 DB에 `case_history` 테이블을 추가합니다. 기존 이벤트는 수정하거나
복사하지 않으며, 검토 이력이 없는 대상 이벤트는 열린 건으로 조회됩니다.

## 검토 대상과 ID

콘솔(`team-i-balance/web`의 `src/api/client.ts`)의 검토 대상 기준을 사용합니다.
기존 `/logs`의 `real_violation` 등 로그 분류와는 별개입니다.

| `need` | 대상 이벤트 |
| --- | --- |
| `required` | `grade=sensitive_S`, `action=send_as_is` (민감 원문 전송) |
| `optional` | `grade=sensitive_S`, `action=revert_original`, `reason=business_need` (업무상 필요로 되돌림) |

안전한 전송·취소·기밀 차단·오탐 사유로만 되돌린 이벤트는 검토 건에 포함하지 않습니다.
유형 목록이 비어 있어도 위 조건에 맞으면 검토 대상으로 포함합니다.
ID는 콘솔과 동일하게 `INC-{event.id}`입니다. 예: 이벤트 42 → `INC-42`.
대상이 아닌 이벤트와 없는 ID는 상세 조회·처리 모두 `404 CASE_NOT_FOUND`입니다.

## 목록과 상세

```http
GET /cases?queue=required&limit=50
GET /cases?queue=optional&limit=50
GET /cases?queue=closed&limit=50
GET /cases/INC-42
```

`queue` 기본값은 `required`, `limit` 기본값은 50(1~100)입니다.
`required`/`optional`은 **열린 건만**, `closed`는 두 종류의 종결 건을 반환합니다.
열린 건은 이벤트 ID 내림차순, 종결 건은 마지막 종결 이력 ID 내림차순입니다.
목록은 `{ "items": [Case], "next_cursor": "required:42" }` 형태이며, 다음 페이지가
없으면 `next_cursor`는 `null`입니다. 같은 `queue`와 받은 `cursor`로 다음 페이지를
요청하세요. 다른 큐의 커서나 잘못된 커서는 `400 INVALID_CURSOR`입니다.
커서를 직접 만들지 마세요. 조회 도중 새 이벤트가 생겨도 다음 페이지에 중복되지
않지만, 종결·다시 열기로 큐에서 이동한 건은 최신 상태를 따릅니다(고정 스냅샷 아님).

목록 항목과 상세는 아래 필드를 공유합니다. `history`만 상세에 추가됩니다.

```json
{
  "id": "INC-42",
  "need": "required",
  "status": "closed",
  "event": {
    "id": 42,
    "created_at": "2026-11-05T06:00:00+00:00",
    "request_id": "work-id",
    "grade": "sensitive_S",
    "action": "send_as_is",
    "reason": null,
    "reason_text": null,
    "reason_requested_at": "2026-11-05T06:00:00+00:00",
    "reason_at": null,
    "detection_confidence": "high",
    "detected_types": ["NAME"],
    "detected_count": 1,
    "reverted": false,
    "restored": false,
    "content_hash": null,
    "queue": "pre_warning"
  },
  "close": {
    "conclusion": "violation",
    "cause": "care",
    "memo": "사유 확인 — 위반",
    "rule": null,
    "by": "security:3f2a9c1b7d4e",
    "at": "2026-11-05T06:10:00+00:00"
  },
  "history": [
    {
      "id": 1,
      "operation": "close",
      "conclusion": "violation",
      "cause": "care",
      "memo": "사유 확인 — 위반",
      "rule": null,
      "by": "security:3f2a9c1b7d4e",
      "at": "2026-11-05T06:10:00+00:00"
    }
  ]
}
```

- `event`는 기존 `/logs/events` 응답과 동일한 메타데이터입니다.
  직원 사유는 `event.reason` 코드(`business_need`/`false_positive`/`null`),
  `event.reason_text` 본문, `event.reason_requested_at` 대기 시작 시각,
  `event.reason_at` 제출 시각으로 읽습니다. 제출 방법은 [직원 사유 API](event-reason-api.md)를 참고하세요.
  사유가 늦게 도착해도 기존 보안팀 결론과 처리 이력은 바뀌지 않습니다.
  선택 컨텍스트 `user_id`, `dept`, `target_ai`, `device_id`와 항목별 `items`도 함께 반환합니다.
  예전 이벤트의 컨텍스트는 `null`, `items`는 빈 배열입니다. `user_id` 등은 클라이언트가
  전달한 메타데이터이며 인증된 처리자 정보가 아닙니다. 직원 이름·원문을 만들어내지 않습니다.
- `status`는 `open` 또는 `closed`, 열린 건의 `close`는 `null`입니다.
- `history`는 시간 순(이력 ID 오름차순)의 전체 종결·다시 열기 기록입니다.
  다시 열기 기록은 `conclusion`/`cause`/`memo`/`rule`이 모두 `null`입니다.
  이전 종결 기록은 다시 열거나 재종결해도 남습니다.
- 검토 처리는 기존 이벤트의 사유·등급·큐와 `/logs/stats` 집계를 바꾸지 않습니다.

## 종결·다시 열기

```http
POST /cases/INC-42/close
Content-Type: application/json

{"conclusion":"violation","cause":"care","memo":"사유 확인 — 위반","rule":null}
```

| 필드 | 허용값 |
| --- | --- |
| `conclusion` (필수) | `violation` 위반 / `legit` 예외 인정 / `fp` 오탐 |
| `cause` | `fit` 업무 적합성 / `care` 부주의 / `intent` 고의 / 생략 또는 `null` |
| `memo` (필수) | 앞뒤 공백 제거 후 1~4,000자 |
| `rule` | 재발 방지 규칙 설명, 앞뒤 공백 제거 후 1~2,000자 / 생략 또는 `null` |

`rule`은 판단 당시 설명을 저장하는 필드입니다. 정책 초안 등록·서명·배포를 수행하지 않습니다.
정책 반영은 [정책 초안 API](policy-draft-api.md)로 별도 처리합니다. 콘솔은 구조화된 규칙을
`payload.rules`에, 변경 설명과 `src: INC-…`를 `changes`에 넣어 `PUT /policy/draft`로 저장하세요.
종결과 초안 저장은 별도 요청이므로 각각의 성공 응답을 확인해야 합니다.

```http
POST /cases/INC-42/reopen
```

다시 열기는 요청 본문이 필요 없습니다. 두 API 모두 성공 시 `200`과 최신 상세를 반환합니다.
이미 종결된 건의 종결은 `409 CASE_ALREADY_CLOSED`, 열린 건의 다시 열기는
`409 CASE_ALREADY_OPEN`입니다. 동시 종결 중 한 요청만 저장됩니다.

## 선택 검토 일괄 종결

```http
POST /cases/close-bulk
Content-Type: application/json

{"ids":["INC-43","INC-44"],"conclusion":"legit","memo":"사유 확인 — 업무 범위 내 사용"}
```

- ID는 중복 없이 1~100개, 모두 열린 `optional` 건이어야 합니다.
- 콘솔의 ‘모두 문제 없음’ 동작이므로 `conclusion`은 `legit`만 허용합니다.
- `memo`는 생략 시 `사유 확인 — 업무 범위 내 사용`, 명시 시 종결과 같은 길이 검사를 적용합니다.
- 성공 시 `200 { "items": [Case, ...] }`를 요청 ID 순서대로 반환하고 건마다 이력을 남깁니다.
- 필수 검토가 섞이면 `409 BULK_REQUIRES_OPTIONAL_CASES`, 이미 종결된 건은
  `409 CASE_ALREADY_CLOSED`, 없는 건은 `404 CASE_NOT_FOUND`입니다.
  한 건이라도 실패하면 전체 요청을 취소합니다. DB 저장 도중 실패해도 앞선 건을 종결 상태로 남기지 않습니다.

그 외 요청 형식·길이·허용값 오류는 FastAPI 표준 `422`입니다. 알 수 없는 종결 요청 필드도 거부합니다.

## 인증

`/cases` 전체(목록·상세·종결·다시 열기·일괄 종결)는 **보안팀 토큰**이 필요합니다(이슈 #45).
`Authorization: Bearer <SECURITY_TOKENS 또는 dev-token(scope=security)>`를 붙이세요.

| 요청 | 응답 |
| --- | --- |
| 토큰 없음 / 알 수 없는 토큰 | `401` |
| api 토큰(`API_TOKENS`, dev-token `scope=api`) | `403 security token required` |
| security 토큰 | 정상 처리(`200` 등) |

인증·권한 검사는 본문 검증보다 먼저 수행되므로 권한이 없으면 이력이 남지 않습니다.
콘솔은 프록시가 `BACKEND_TOKEN`(보안팀 토큰)을 모든 요청에 붙이므로 웹 변경이 필요 없습니다.

## 처리자와 콘솔 연결

시각 `at`는 서버가 UTC로 기록합니다. 처리자 `by`는 서버의 `get_reviewer()` 의존성이
**검증된 토큰**에서 정하며, 요청 본문·헤더의 이름(`X-Reviewer` 등)을 신뢰하지 않습니다.
토큰에는 사람 이름이 없으므로 토큰별 라벨을 남깁니다.

| 토큰 출처 | `by` 값 |
| --- | --- |
| 환경변수 `SECURITY_TOKENS` | `security:<토큰 SHA-256 앞 12자리>` |
| 실행 중 발급한 dev-token(`scope=security`) | `security-dev:<토큰 SHA-256 앞 12자리>` |
| 테스트용 `AUTH_DISABLED=1`에서 유효 토큰 없이 호출 | `auth-disabled` |

토큰 원문은 기록하지 않습니다. 같은 토큰은 항상 같은 라벨이므로 운영자는 보유한 토큰의
해시 앞자리와 대조해 누가 처리했는지 확인할 수 있습니다. dev-token은 프로세스 재시작 시
사라지므로 장기 식별이 필요하면 `SECURITY_TOKENS`에 담당자별 토큰을 등록하세요.
#45 이전에 남은 `unauthenticated` 이력은 그대로 유지합니다.

프론트에서는 현재 `/logs/events`를 읽어 매번 열린 건으로 재생성하는 `casesFrom()` 대신
`/cases`를 조회하고, 처리 버튼에서 위 API를 호출한 **성공 응답**으로 상태를 갱신하세요.
`need=required|optional`은 기존 화면의 `req|opt`에 매핑하면 됩니다.
상세를 열 때 `/cases/{id}`에서 이력을 조회하고, `409`이면 상세·목록을 다시 읽어 다른
검토자의 선행 처리를 반영하세요. 모든 종결 건이 필요한 화면은 `next_cursor`가 `null`일
때까지 조회해야 합니다. 이 변경은 백엔드 API만 추가하며 웹 저장소의 버튼 연결은 포함하지 않습니다.

## 검증

```bash
python -m pytest tests/test_cases.py tests/test_case_auth.py -q
python -m pytest -q
```

대상 분류, 커서 페이지 이동, 결론별 종결·다시 열기·재종결, 프로세스 재시작과 기존 DB
업그레이드, 동시 요청 충돌, 일괄 처리 실패 시 전체 롤백, 입력 검증, 토큰별 401/403/200과
처리자 라벨(토큰 원문 미저장)을 확인합니다.
