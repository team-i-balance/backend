# 기간 통계와 이벤트 페이지 넘김

## 기간 통계

```http
GET /logs/stats?start=2026-11-01T00:00:00Z&end=2026-11-05T09:00:00Z
```

`start`와 `end`는 각각 생략할 수 있습니다. 모두 생략하면 기존처럼 전체 기간을 집계합니다.
필터는 이벤트의 `created_at`에 적용하며 **양쪽 경계 시각을 포함**합니다.

- `Z`, `+09:00` 등 시간대가 있는 값은 UTC로 변환합니다. URL의 `+`는 `%2B`로 인코딩하세요.
  브라우저에서는 `URLSearchParams`를 사용하면 됩니다.
- 시간대가 없으면 UTC, 날짜만 보내면 해당 날짜의 UTC 자정입니다.
  예를 들어 `end=2026-11-05`는 11월 5일 하루 전체가 아니라 그날 00:00:00까지입니다.
- 소수 초는 마이크로초 단위로 비교하며, 목록과 통계에 같은 필터를 적용합니다.
- 잘못된 날짜·빈 문자열·UTC로 변환할 수 없는 날짜·`start > end`는 `400`입니다.

응답의 기존 필드는 유지하고 `by_action`과 `by_policy_version`을 추가합니다.

```json
{
  "total": 5,
  "acceptance_rate": 0.4,
  "revert_rate": 0.4,
  "evasion_suspect": 1,
  "by_queue": {"pre_warning": 3, "violation_candidate": 1, "detection_improve": 1},
  "by_grade": {"public_O": 1, "sensitive_S": 3, "confidential_C": 1},
  "by_action": {"send_as_is": 1, "send_transformed": 1, "cancel": 1, "revert_original": 2},
  "by_policy_version": {"11": 1, "12": 3, "none": 1}
}
```

- 모든 건수와 비율의 분모는 **지정한 기간의 전체 이벤트**입니다. 목록 API의 `limit=1000`에 제한되지 않습니다.
- `by_action`은 네 행동을 항상 반환하고 해당 행동이 없으면 `0`입니다.
- 기존 계산 기준을 유지합니다. `acceptance_rate`는 `send_as_is`와 `send_transformed` 건수의 비율,
  `revert_rate`는 `reverted=true`인 건수의 비율, `evasion_suspect`는 `reason=business_need` 건수입니다.
  `revert_rate`와 `by_action.revert_original`은 서로 다른 필드를 기준으로 합니다.
- `by_policy_version`은 이벤트의 `policy_version`별 건수입니다. 키는 버전 숫자의 문자열이고
  버전이 없는(`null`) 이벤트는 `"none"`으로 셉니다. 버전 오름차순, `"none"`은 마지막입니다.
  다른 지표와 같은 기간·`include_test` 조건을 따르므로 값의 합은 `total`과 같습니다.
  새 규칙 배포 전후로 기간을 나눠 `by_action`과 함께 보면 버전별 원문 전송 변화를 비교할 수 있습니다.
- 비율은 소수점 넷째 자리까지 반올림합니다. 빈 기간은 건수·비율이 모두 0이고
  `by_queue`/`by_grade`/`by_policy_version`은 `{}`입니다.
- 한 SQL 집계로 전체 지표를 계산하므로 요청 도중 새 이벤트가 생겨도 지표끼리 기준이 어긋나지 않습니다.

콘솔의 최근 7일 지표는 목록을 최대 1,000개 받아 세는 대신, 원하는 시작·종료 시각으로
이 API를 호출하세요. 새로운 구간이나 종료 시각으로 새로고침하면 최신 결과를 얻습니다.

## 이벤트의 정책 버전

이벤트에 그 입력을 처리할 때 적용 중이던 정책 버전 `policy_version`(정수 또는 `null`)을 기록합니다.

- `POST /logs/events`: PC가 적용 중인 정책 버전(`GET /policy/current`의 `version`)을 보냅니다.
  선택 필드이며 생략하거나 `null`이면 `null`로 저장합니다. 0 이상의 정수만 받고, 그 밖의 값은 `422`입니다.
- `POST /process/decide`: 서버가 `/process` 때 탐지에 적용한 활성 정책 버전(`/policy/current`의 `version`)을
  기록합니다. `/process`와 `decide` 사이에 새 정책이 배포되어도 탐지 당시 버전을 유지합니다.
- 파일 이벤트(`source: "file"`): 파일을 검사한 시점의 서버 활성 정책 버전을 기록합니다.
- 활성 정책이 없을 때와 이 필드가 생기기 전의 이벤트는 `null`입니다. 서버 시작 시 기존 DB에
  `policy_version` 열(INTEGER, NULL 허용)을 추가하며 기존 행은 채우지 않습니다.
- `/logs/events`, `/cases`의 `event`, `/process/decide`의 `event`에 저장된 값을 그대로 반환합니다.

## 이벤트 목록 페이지 넘김

응답은 기존과 동일한 이벤트 **배열**입니다. 기본 `limit=100`, 최대 `1000`이고 ID 내림차순입니다.

```http
GET /logs/events?limit=100&start=2026-11-01T00:00:00Z
GET /logs/events?limit=100&start=2026-11-01T00:00:00Z&cursor=901
```

첫 응답의 마지막 이벤트 ID가 `901`이라면 다음 요청에 `cursor=901`을 넣습니다.
서버는 **ID가 901보다 작은 이벤트** 중 조건에 맞는 다음 페이지를 반환합니다.
`grade`, `queue`, `start`, `end` 필터는 다음 요청에서도 동일하게 유지하세요.

```javascript
const params = new URLSearchParams({ start, end, limit: '1000' });
const rows = [];
for (;;) {
  const response = await fetch(`/logs/events?${params}`);
  if (!response.ok) throw new Error(`이벤트 조회 실패: ${response.status}`);
  const page = await response.json();
  rows.push(...page);
  if (page.length < 1000) break;
  params.set('cursor', String(page[page.length - 1].id));
}
```

`cursor`는 1~9,223,372,036,854,775,807 범위의 정수이며 잘못된 값은 `422`입니다.
없는 ID도 경계로 사용할 수 있고, 더 읽을 이벤트가 없으면 `[]`입니다.
조회 중 새 이벤트가 추가되어도 뒤쪽 페이지가 밀려 중복되지 않습니다. 전체 페이지에 대한
고정 DB 스냅샷은 아니므로 사유 제출 등으로 필터 조건이 바뀐 이벤트는 최신 상태를 따릅니다.
집계 숫자에는 `/logs/stats`를, 상세 행을 탐색할 때는 페이지 넘김을 사용하세요.

## 검증

```bash
python -m pytest tests/test_stats.py tests/test_log_stats_period.py tests/test_crud_filters.py -q
python -m pytest tests/test_event_policy_version.py -q
python -m pytest -q
```

1,007건 전체 집계·페이지 순회, 기간 경계·시간대·소수 초, 페이지 조회 중 새 행 추가,
필터 조합, 잘못된 기간·커서를 확인합니다. 클라이언트 코드 변경은 이 백엔드 PR에 포함하지 않습니다.
