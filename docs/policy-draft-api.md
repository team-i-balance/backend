# 정책 초안 API

콘솔의 미배포 변경을 `POLICY_DB_PATH`의 `policy_draft` 테이블에 저장합니다.
같은 DB를 사용하는 보안팀 콘솔·서버 워커가 하나의 초안을 공유하며, 새로고침과 서버
재시작 뒤에도 유지됩니다. 기존 정책 DB에는 앱 시작 시 테이블만 추가합니다.
초안 저장은 정책 발행이나 PC 적용을 수행하지 않습니다.

## 조회

```http
GET /policy/draft
```

```json
{
  "payload": {
    "schema": 1,
    "org": "acme",
    "thresholds": {"personal": 0.35},
    "rules": [],
    "types": {"이름": {"on": true, "grade": "S", "method": "가명"}},
    "dict": [],
    "exclude": []
  },
  "changes": [
    {"what": "이름 변환 방식 변경", "src": "직접 수정", "at": "2026-11-05T09:00:00+00:00", "by": "unauthenticated"}
  ],
  "console_state": {"dict": [{"word": "프로젝트-오로라", "type": "회사 고유 단어"}], "exclude": [{"value": "..."}]},
  "has_draft": true,
  "base_version": 1,
  "revision": 2,
  "updated_at": "2026-11-05T09:00:00+00:00",
  "updated_by": "unauthenticated",
  "etag": "\"sha256:...\""
}
```

- 저장된 초안이 없으면 **마지막 발행 번들의 payload**, 빈 `changes`, `has_draft: false`를
  반환합니다. 아직 발행한 정책도 없으면 `payload: null`, `base_version: null`입니다.
  콘솔은 이 경우에만 초기 기본 정책을 구성합니다.
- `base_version`은 편집을 시작한 발행 버전입니다. PC 적용 버전(`/policy/current`)과는 다릅니다.
- `console_state`는 콘솔이 새로고침 뒤 화면을 되살리는 데 쓰는 **서명하지 않는 칸**입니다.
  저장한 적이 없으면 `null`입니다. 발행 뒤(`has_draft: false`)에도 마지막으로 저장한 값이
  그대로 돌아옵니다. 자세한 규칙은 아래 "콘솔 화면 상태"를 봅니다.
- `revision`은 저장된 초안의 수정 횟수입니다. 초안이 없으면 `0`, `updated_at/by`는 `null`입니다.
- HTTP `ETag`와 JSON `etag`는 같은 값이며 **큰따옴표까지 포함**합니다. 브라우저에서도
  읽도록 CORS에 노출합니다. 조회·저장 응답은 `Cache-Control: no-store`입니다.
  초안 ETag는 `/policy/latest`의 번들 해시와 별개입니다.

## 전체 저장과 동시 수정

```http
PUT /policy/draft
Content-Type: application/json
If-Match: "sha256:조회 또는 직전 저장에서 받은 값"

{"payload":{"schema":1,"org":"acme","rules":[]},"changes":[{"what":"규칙 수정","src":"직접 수정"}],
 "console_state":{"dict":[{"word":"프로젝트-오로라"}]}}
```

성공 시 `200`과 조회와 같은 응답, **새 ETag**를 반환합니다. `payload`와 `changes`는
둘 다 필수이고, 전체 내용을 대체합니다. 배열에서 뺀 변경 설명은 삭제됩니다.
`console_state`는 선택이며(JSON 객체 또는 `null`) 역시 전체 대체입니다. **생략하거나
`null`로 보내면 저장된 화면 상태가 지워지므로** 콘솔은 매 저장마다 현재 값을 함께 보냅니다.

`payload`는 기존 발행 API와 같은 JSON 객체로, `schema, org, thresholds, rules, types,
dict, exclude`와 추가 필드를 그대로 보존합니다. 서버가 UI 상태를 재구성하지 않으므로
콘솔은 켬/끔뿐 아니라 등급·변환 방식 등 저장할 설정을 payload에 모두 넣어야 합니다.
**payload는 그대로 서명되어 모든 PC로 내려갑니다.** 회사 고유 단어·탐지 제외 값은 payload에
해시(`dict[].h`, `exclude[].h`)로만 넣고, 평문은 `console_state`에만 둡니다.

### 콘솔 화면 상태 (`console_state`)

- 평문 등 화면 복원용 값을 두는 칸입니다. 초안 저장·조회에서만 오가며 **발행 payload에는
  어떤 경로로도 들어가지 않습니다.** 서버는 내용을 해석하지 않습니다.
- 초안 ETag 계산에 포함되므로 이 칸만 바꿔도 ETag가 바뀌고, 동시 수정 검사를 받습니다.
- 발행은 초안을 비우지만 `console_state`는 남깁니다. 발행 직후 초안을 다시 저장하는 우회는
  필요 없습니다. 다음 `PUT /policy/draft`가 새 값으로 대체합니다.
- payload 최상위에 `console` 또는 `console_state` 키를 두면 발행이 `422 POLICY_PAYLOAD_CONSOLE_FORBIDDEN`으로
  거부됩니다(아래 발행 절 참고). 예전 방식으로 `payload.console`을 저장한 초안은 그 키를
  `console_state`로 옮겨 다시 저장한 뒤 발행합니다.

`changes`는 최대 500개이며 각 항목은 다음과 같습니다.

| 필드 | 동작 |
| --- | --- |
| `what` | 변경 설명, 공백 제거 후 1~2,000자 |
| `src` | 출처, 공백 제거 후 1~128자. 생략하면 `직접 수정`; 사건 출처는 `INC-42` 등 |
| `at`, `by` | 서버가 부여. 조회 응답을 그대로 다시 보내도 입력값은 신뢰하지 않음 |

동일한 `what, src` 항목을 다시 보내면 기존 서버 시각·처리자를 유지합니다. 새 항목에는
현재 서버 UTC 시각·처리자를 기록합니다. `changes`는 미배포 변경 설명 목록이며 불변 감사
이력이 아닙니다. 발행 성공 시 비워집니다. 사건 판단 이력은 기존 `/cases`에 남습니다.

현재 인증이 없으므로 `by`와 `updated_by`는 `unauthenticated`입니다. 인증 이슈 #10에서
`get_policy_editor()`를 검증된 보안팀 계정으로 교체하고 정책 API에 권한 검사를 연결해야 합니다.
클라이언트가 보낸 `by`로 실제 사용자를 식별하지 않습니다.

| 응답 | 의미와 처리 |
| --- | --- |
| `428 DRAFT_PRECONDITION_REQUIRED` | `If-Match` 누락. 먼저 초안 조회 |
| `409 DRAFT_CONFLICT` | 다른 저장·발행으로 초안이 바뀜. 최신 초안을 다시 읽고 변경을 검토·재적용 |
| `422` | payload/changes/console_state 형식·길이 오류 또는 알 수 없는 최상위/변경 항목 필드 |

ETag 비교와 저장은 같은 SQLite 쓰기 트랜잭션에서 수행합니다. 여러 프로세스가 같은
ETag로 요청해도 한 요청만 성공합니다. 내용을 A → B → A로 되돌려도 이전 ETag는
유효해지지 않습니다. `*`, 약한 ETag(`W/...`), 여러 ETag 나열은 허용하지 않습니다.

## 저장된 초안 발행

```http
POST /policy/publish
If-Match: "sha256:마지막 저장에서 받은 값"
```

본문 없이 호출하면 저장된 초안 payload를 서명·저장하고 초안을 비웁니다. `console_state`는
서명하지 않고 그대로 남깁니다. 발행 버전은
기존 방식대로 서버가 정합니다. 응답은 기존 `{version, keyid, bundle_sha256}` 형태입니다.
**서명 번들 저장과 초안 삭제를 하나의 트랜잭션**으로 처리하므로 서명·DB 실패 시 초안과
이전 발행 상태가 남습니다. PC 적용은 계속 별도의 `/policy/deploy` 단계입니다.

- 본문이 있든 없든 발행할 payload 최상위에 `console` 또는 `console_state` 키가 있으면
  `422 POLICY_PAYLOAD_CONSOLE_FORBIDDEN`이며, 버전·번들·초안 모두 바뀌지 않습니다.
  서버가 키를 몰래 지우지 않으므로 콘솔이 payload를 고쳐 다시 저장·발행해야 합니다.
- 저장된 초안 없이 본문 없는 발행을 요청하면, 현재 ETag를 보냈을 때 `409 NO_POLICY_DRAFT`입니다.
- 기존 `POST /policy/publish {"payload": {...}}`도 유지합니다. 저장된 초안이 없으면 예전처럼
  `If-Match` 없이 호출할 수 있습니다.
- **저장된 초안이 있으면 직접 payload를 보내더라도 현재 `If-Match`가 필수**입니다.
  다른 사람의 초안을 모르게 삭제하는 것을 막습니다. 올바른 ETag와 직접 payload를 보내면
  해당 payload를 발행하고 초안을 비웁니다.
- 발행 성공 후 `GET /policy/draft`를 다시 호출하여 마지막 발행 payload, 빈 변경 목록,
  남아 있는 `console_state`, 새 ETag로 화면을 갱신합니다. 이전 ETag로 저장·발행을 재시도하면 `409`입니다.
- 모델 발행(`/policy/model/publish`)과 PC 적용(`/policy/deploy`)은 초안을 비우지 않습니다.

## 콘솔 연결 순서

1. 정책 화면 시작 시 `/policy/latest` 대신 `/policy/draft`를 읽어 payload·변경 목록·
   `console_state`를 복원합니다. 평문 목록은 `console_state`에서만 읽습니다.
2. 설정 변경마다 전체 `{payload, changes, console_state}`를 `If-Match`와 함께 저장합니다.
   payload에는 해시만 넣고 `console`·`console_state` 키를 두지 않습니다. 평문은 `console_state`에만 둡니다. 연속 변경은
   한 콘솔 안에서 저장 요청을 순서대로 보내고 직전 성공 응답의 ETag를 사용합니다.
3. 저장 성공 응답을 화면 상태로 반영합니다. 실패한 저장을 완료로 표시하지 않습니다.
4. 발행 버튼은 진행 중인 저장이 끝난 뒤 현재 ETag로 본문 없는 `/policy/publish`를 호출합니다.
   `422 POLICY_PAYLOAD_CONSOLE_FORBIDDEN`이면 payload의 `console`을 `console_state`로 옮겨
   다시 저장한 뒤 발행합니다. 발행 뒤 초안을 다시 저장할 필요는 없습니다.
5. `409`이면 최신 초안을 재조회하고 사용자의 변경을 검토한 뒤 다시 저장합니다.
   최신 ETag만 가져와 오래된 전체 payload를 자동 재전송하면 다른 사람의 편집이 덮어써집니다.

사건 예외 인정으로 자동 변환 규칙을 만들 때는 콘솔이 **구조화된 규칙을 `payload.rules`에**,
설명을 `changes`에 넣어 함께 저장합니다.

```json
{"what":"자동 변환 추가: 주민등록번호가 포함된 입력 → 태그","src":"INC-42"}
```

`POST /cases/INC-42/close`의 `rule`은 판단 설명 문자열이므로 서버가 실행 규칙으로 추측해
변환하지 않습니다. 종결과 초안 저장은 별도 요청이며, 둘 다 성공했는지 확인해야 합니다.
종결 후 초안 저장만 실패한 경우 초안 저장을 재시도하고 이미 성공한 종결은 반복하지 않습니다.
이 PR은 백엔드 API와 계약을 제공하며 웹 저장소의 API 연결은 별도입니다.

## 검증

```bash
python -m pytest tests/test_policy_draft.py -q
python -m pytest -q
```

새 프로세스에서 초안·`console_state` 복원과 발행, 발행 번들에 평문이 없는지,
`payload.console` 거부(422), 4개 프로세스의 동시 저장, 저장/발행 충돌,
서명·DB 장애 롤백, 기존 DB 업그레이드, 사건 출처 보존과 CORS를 확인합니다.
