# 텍스트 전송 결정 API (`POST /process/decide`)

직원 앱이 `POST /process`로 검사한 문장을 어떻게 보낼지 정하면 호출합니다. **api 토큰**이 필요합니다.
서버는 이벤트 1건을 저장하고(`/logs/events`와 같은 큐 분류), 직원 앱이 실제로 보낼 문장을 돌려줍니다.

## 요청

```json
{
  "work_id": "…/process 응답의 work_id…",
  "action": "revert_original",
  "reason": "false_positive",
  "reason_text": "회사 대표번호입니다",
  "user_id": "emp-1024",
  "dept": "영업1팀",
  "target_ai": "chatgpt",
  "reverted": ["[전화번호_1]"]
}
```

| 필드 | 필수 | 규칙 |
| --- | --- | --- |
| `work_id` | 예 | `/process` 응답의 값. 모르는 값이거나 만료(10분)면 `404` |
| `action` | 예 | `send_as_is`·`send_transformed`·`revert_original`·`cancel` |
| `reason` | 아니요 | `false_positive`·`business_need` |
| `reason_text` | 아니요 | 직원 사유. 앞뒤 공백을 지운 뒤 1~500자. `reason`이 있을 때만 받고, 없으면 `422` |
| `user_id` | 아니요 | 문자열 64자 이하(`/logs/events`와 같음) |
| `dept` | 아니요 | 문자열 128자 이하 |
| `target_ai` | 아니요 | 문자열 128자 이하 |
| `reverted` | 아니요 | 직원이 원문으로 되돌린 가명 토큰 목록(예: `["[이름_1]","[전화번호_2]"]`). 최대 500개, 항목당 64자 이하, 중복은 한 번으로 셈. `action`이 `revert_original`이 아니면 `422` |

`reason` 뒤의 필드는 모두 선택입니다. 전부 빼면 예전과 같은 결과를 돌려줍니다(이벤트 `items`만 서버가 새로 채움).

### `reverted` 검사

- 그 작업의 `masked_text`에 서버가 넣은 토큰만 받습니다. 그 밖의 값(없는 번호, 다른 작업의 토큰,
  직원이 입력에 직접 적은 `[전화번호_1]` 같은 글자, `[삭제됨]`·`[이름]` 같은 고정 출력)이 하나라도 있으면
  `422 {"detail": "UNKNOWN_PLACEHOLDER"}`입니다.
- 요청 형식 오류(`422`)와 `UNKNOWN_PLACEHOLDER`는 작업을 소모하지 않습니다. 같은 `work_id`로 다시 보낼 수 있습니다.

## 응답

```json
{
  "event": { "id": 901, "action": "revert_original", "reverted": true, "items": [ … ], … },
  "outgoing_text": "연락처 010-1234-5678, 메일 [이메일_1]",
  "restore_available": false
}
```

| `action` | `outgoing_text` |
| --- | --- |
| `send_transformed` | 가린 문장(`masked_text`). 작업을 남겨 `/process/restore`로 답변을 복원할 수 있음 |
| `send_as_is` | 원문 전체 |
| `revert_original`, `reverted` 없음 | 원문 전체(예전 앱) |
| `revert_original`, `reverted` 있음 | 가린 문장에서 `reverted`의 토큰만 원문으로 되돌린 문장. 빈 목록이면 가린 문장 그대로 |
| `cancel` | `null` |

## 이벤트 `items`

서버가 `/process` 때 가린 구간마다 항목을 하나씩 만듭니다(문장 순서, 같은 값이 두 번 나오면 두 항목).
형식은 `/logs/events`의 `items`와 같습니다.

```json
{"type": "PHONE", "decision": "reverted", "value_hash": "3f9a…(64자)", "preview": "***-****-****"}
```

| `action` | `decision` |
| --- | --- |
| `send_as_is` | 모두 `raw` |
| `send_transformed` | 모두 `converted` |
| `revert_original`, `reverted` 없음 | 모두 `reverted` |
| `revert_original`, `reverted` 있음 | 목록에 든 토큰의 구간은 `reverted`, 나머지는 `converted` |
| `cancel` | `items` 없음 |

- `value_hash`: `HMAC-SHA256(POLICY_VALUE_HASH_KEY, 앞뒤 공백을 지운 값)`의 16진수 64자.
  정책 탐지 제외(`exclude`)의 `hmac:` 항목과 같은 키·정규화이므로, 콘솔은 `"hmac:" + value_hash`를 그대로
  탐지 제외에 넣을 수 있습니다([정책 적용 문서](policy-apply.md)). 서버에 키가 없으면 `value_hash`를 넣지 않습니다.
- `preview`: 가린 미리보기(최대 30자). 이름·주소 등은 첫·끝 글자만 보이고(`윤*아`), 전화·주민·계좌·카드·
  생년월일·사업자·IP는 숫자와 글자를 모두 가립니다(`******-*******`). 비밀번호·API 키·토큰은 `********`입니다.
  구분 기호(`-`, `@`, `.`, 공백)는 그대로 둡니다.
- 원문 값은 DB·로그·응답 이벤트 어디에도 남기지 않습니다. 구간 값은 작업이 끝날 때까지 메모리에만 있습니다.

## 오탐 신고와의 관계

`reason: false_positive`이면 `reverted`·`raw` 항목이 [오탐 신고 목록](false-positive-api.md)
(`GET /false-positives`)에 값 해시별로 잡힙니다. `converted` 항목(가린 채 보낸 값)은 이벤트 사유를 물려받지
않으므로 신고로 세지 않습니다. `user_id`를 보내야 `employee_count`가 셉니다.
