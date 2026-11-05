# 콘솔 실시간 갱신용 변경 확인 (`GET /logs/changes`)

보안팀 콘솔은 흐름도·대기열(필수 검토, 오탐 신고 등)을 최신으로 유지하려고 이 API를 2~3초마다 부릅니다.
응답에는 영역별 **변경 표시값만** 있고 이벤트 내용(직원·사유·값)은 없습니다. 보안팀 토큰(security)이 필요합니다.

```http
GET /logs/changes
If-None-Match: "changes:…"   ← 이전 응답의 ETag
```

- 바뀐 것이 없으면 `304`(본문 없음)입니다. 바뀌었으면 `200`과 새 `ETag`를 돌려줍니다. 둘 다 `Cache-Control: no-store`입니다.
- 이벤트 10만 건 기준 한 번에 약 3ms입니다(인덱스로만 계산).
- `change_seq`는 `event_log`의 내부 열로, 행이 수정될 때마다 트리거가 1씩 올립니다. 시각이 아니라 순번이라
  다른 행에 미래 시각이 있어도 수정이 빠지지 않습니다. 이벤트 응답·내보내기에는 나오지 않습니다.

```json
{
  "events": {"last_id": 912, "change_seq": 40},
  "cases": {"last_id": 57},
  "false_positives": {"last_id": 12, "reports": {"last_id": 912, "change_seq": 40}},
  "policy": {"latest": 4, "active": 4, "activated_at": "2026-11-06T01:02:03+00:00", "draft_etag": "\"sha256:…\"", "ack_last_id": 31},
  "rev": "…"
}
```

| 영역 | 바뀌는 때 | 콘솔이 다시 읽을 것 |
| --- | --- | --- |
| `events.last_id` | 새 이벤트 | `/logs/events`, `/cases`, `/false-positives` |
| `events.change_seq` | 기존 이벤트 수정(직원 사유 제출, 보안팀 사유 재요청 등) | `/logs/events`, `/cases`, `/false-positives` |
| `cases.last_id` | 건 종결·다시 열기·일괄 종결 | `/cases` |
| `false_positives.last_id` | 오탐 판단 | `/false-positives` |
| `false_positives.reports` | 새 오탐 신고(이벤트에서 나오므로 `events` 값과 같음) | `/false-positives` |
| `policy.latest` / `active` | 서명 배포, 서버 적용 | `/policy/latest`, `/policy/current`, `/policy/history` |
| `policy.ack_last_id` | PC의 정책 적용·거부 보고 | `/policy/acks` |
| `policy.draft_etag` | 정책 초안 저장 | `/policy/draft` (내가 저장해 받은 `etag`와 같으면 안 읽어도 됨) |

- 시험 이벤트(`test=true`)도 변경으로 셉니다. `include_test` 설정과 관계없이 같은 값입니다.
- SSE 대신 폴링을 쓰는 이유: 콘솔(Vercel)이 서버 함수 프록시로 백엔드를 부르는데, 이 프록시는 응답을 다 받은 뒤 넘기므로 스트림을 흘려보낼 수 없습니다.
