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

3. `grade != public_O` **그리고** `action in {send_as_is, revert_original}` **그리고** `detection_confidence == high`
   → **real_violation** (실제 위반 큐, 보안팀 콘솔의 "필수 검토")
   - 민감·기밀 정보가 확실히 잡혔는데 원문을 그대로 보냈거나, 사유 없이 되돌려 원문을 보낸 경우.
   - 사유가 있는 되돌림(`false_positive`, `business_need`)은 규칙 1·2가 먼저 가져간다.
   - 취소(`cancel`)는 아무것도 전송되지 않았으므로 위반이 아니다 (이슈 #20).

4. `action in {send_transformed, cancel}`
   → **pre_warning** (사전 경고 로그, 유형·건수만)
   - 위 1~3에 걸리지 않은 변환 전송/취소 건 (확실한 탐지 + 취소 포함).

5. 그 외 (예: 공개 등급의 원문 전송, 확실하지 않은 탐지의 원문 전송)
   → **pre_warning** 로 기본 수렴 (유형·건수만 남김)

> 비고: 규칙 3은 규칙 4·5보다 먼저 평가되므로, "민감·기밀 + 확실한 탐지 + 원문 전송"은
> real_violation 으로, 그 밖의 원문 전송·취소는 pre_warning 으로 간다.

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
- `source`는 이벤트를 만든 흐름이다. `text`(기본값, 질문 `/process` → `/decide`)와
  `file`(XLSX 파일 API)이 있다. 파일 이벤트는 서버가 남긴다: 차단 응답은 `cancel`,
  보호본 다운로드는 `send_transformed`, 내려받지 않고 만료되면 `cancel`.
  파일의 `content_hash`는 올라온 파일 바이트의 SHA-256이다. 큐 분류는 텍스트와 같다.

## 7. 등급 판정 (흐름도 S2) — local_ai 탐지 결과 → 등급

서버(사내)에서 local_ai로 탐지한 유형을 보고 등급을 정한다.

| 조건 | 등급 |
| --- | --- |
| 비밀정보 유형이 하나라도 있음 (`API_KEY`, `ACCESS_TOKEN`, `PASSWORD`), 또는 SLM의 `CONFIDENTIAL`(정책 C 규칙)·`SENSITIVE`(개인 민감정보) | **기밀 C** (`confidential_C`) |
| 위가 없고 개인정보 유형이 있음 (`NAME`, `PHONE`, `EMAIL`, `ADDRESS`, `ID`/`ID_NUMBER`, `ACCOUNT`, `CARD`, `DOB`, `USERNAME`, `IP_ADDRESS`, `BUSINESS_NUMBER`), 또는 SLM의 `INTERNAL`(정책 S 규칙) | **민감 S** (`sensitive_S`) |
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
- 파일에 연결한 질문(`file_work_id`)은 그 파일의 매핑에서 가명화한다. 이 매핑은
  질문이 아니라 파일 작업이 끝날 때(만료 등) 폐기한다.

## 10. 정책 번들 배포 + 서명 검증 (흐름도 S7, DSSE 명세)

보안팀 콘솔(S6)이 서명한 **DSSE 정책 번들**을 받아 서명·내용을 검증하고,
통과하면 활성 정책으로 채택한다. 하나라도 실패하면 **쓰던 정책을 유지**하고
실패 사유 코드를 보고한다. (명세: `message.txt` "변환 정책 번들·서명 명세")

### DSSE 봉투

```json
{
  "payloadType": "application/vnd.piiguard.policy+json",
  "payload": "<정책 JSON 바이트의 base64>",
  "signatures": [{ "keyid": "console-2026-11", "sig": "<Ed25519 서명 base64>" }]
}
```

- 서명 대상은 JSON이 아니라 **PAE 바이트**:
  `"DSSEv1 " + len(type) + " " + type + " " + len(payload) + " " + payload`.
  그래서 JSON 키 순서·공백을 신경 쓸 필요가 없다.
- 검증 측은 `payload`를 base64 디코딩한 **그 바이트로 서명을 먼저 확인한 뒤에만**
  JSON을 파싱한다.
- 서버는 신뢰 공개키(`trust/<keyid>.pub`)만 보관. 개인키는 콘솔/KMS(여기선
  시연용 임시 키 생성).

### 검증 순서 (실패 시 적용 안 함 + 사유 코드)

| 순서 | 확인 | 실패 코드 |
| --- | --- | --- |
| 1 | `payloadType`이 맞는가 | `bad_type` |
| 2 | 신뢰 `keyid`의 서명이 PAE 바이트와 맞는가 | `bad_signature` |
| 3 | `schema`를 아는가 (현재 1) | `unsupported_schema` |
| 4 | `org`가 내 조직인가 | `wrong_org` |
| 5 | `version`이 마지막 정상본보다 큰가 | `rollback` |
| 6 | `expires_at`이 지나지 않았는가 | `expired` |
| 7 | `model.sha256`이 설치 모델과 같은가 | `model_mismatch` |

- 만료되면 **새 번들은 거부**하되, 쓰던 정책은 계속 쓴다.
- `model.sha256` 검사는 `POLICY_EXPECTED_MODEL_SHA256`가 설정됐을 때만 수행
  (미설정이면 건너뜀 — 시연 편의).
- 설정: `POLICY_ORG`(기본 `acme`), `POLICY_KEYS_DIR`(신뢰키·시연 서명키 위치).

### 엔드포인트

PC 측:

| Method | Path | 설명 |
| --- | --- | --- |
| POST | `/policy/deploy` | (security) 번들 검증·컴파일 → 통과+최신이면 적용, 아니면 거부(사유 코드, 서버가 적용 못 하면 `compile_failed`) |
| GET | `/policy/current` | 현재 활성 정책 메타(org·version·keyid·규칙 수·만료·적용 시각) + `effective_version(s)`·`last_apply_error(s)`(탐지기 모드별)·`value_hash_key_set` |

백엔드(콘솔) 측:

| Method | Path | 설명 |
| --- | --- | --- |
| POST | `/policy/publish` | payload를 받아 version+1 → 서명 → 저장. 응답 `{version, keyid, bundle_sha256}` |
| GET | `/policy/latest` | 최신 번들 봉투. `ETag`=`"sha256:…"`(따옴표 포함), `If-None-Match`가 맞으면 304 |
| GET | `/policy/{version}` | 특정 버전 봉투(감사·재현) |
| POST | `/policy/ack` | PC 적용 결과 보고 `{device_id, version, status, reason?}` |
| GET | `/policy/acks` | 적용/거부 집계(기기수·applied·rejected·사유별) |
| POST | `/policy/model/publish` | 모델 매니페스트 `{name, version, sha256, url}` 서명·저장 |
| GET | `/policy/model/latest` | 최신 모델 매니페스트 봉투(payloadType `...model+json`) |

`/policy/latest`의 ETag (이슈 #50):

- 응답 헤더는 RFC 9110 형식의 강한 ETag로 **큰따옴표를 포함**한다. 예: `ETag: "sha256:3f…"`.
  초안 ETag(`/policy/draft`)와 같은 모양이지만 값은 별개다.
- 헤더만 바뀌었다. `/policy/history`의 `sha256`, `/policy/publish`의 `bundle_sha256` 같은
  **본문 값은 그대로 따옴표 없는** `sha256:…`이다.
- `If-None-Match`는 약한 비교로 판단한다. 아래 중 하나라도 현재 번들과 맞으면 `304`:
  따옴표 있는 값, 따옴표 없는 값(기존 클라이언트 호환), `W/` 접두사, 콤마로 나열한 여러 값, `*`.
- 비교 함수는 `app/etag.py`. 초안 `If-Match`는 여전히 정확히 한 개의 강한 ETag만 허용한다.

### 실제 변환 적용 (S7 → S2 되먹임)

`/process`·`/files/sanitize` 요청마다 활성 정책을 탐지기에 적용한다. `types`의
on/off·grade·method, `rules`(서버 SLM 규칙에 합침), `dict`(회사 고유 단어 해시),
`exclude`(탐지 제외 값 해시)를 반영하고, 적용에 실패하면 이전 정책을 유지한다.
한국어 카테고리 → 탐지기 유형 매핑은 `app/policy_apply.py`에 있고, 매핑에 없는
카테고리는 무시한다. 필드별 동작과 서버·PC 분담은 `docs/policy-apply.md` 참고(#47).

## 11. 인증·CORS (이슈 #10)

### 토큰 인증 (항상 강제)

Bearer 토큰으로 보호한다. 토큰이 없거나 유효하지 않으면 401, 유효하지만
권한(scope)이 부족하면 403.

| scope | 대상 엔드포인트 |
| --- | --- |
| `api` | `POST /process*`, `POST /files/*`, `POST /logs/events`, `POST /policy/ack`, 정책 읽기(`GET /policy/current|latest|{version}|model/latest`) |
| `security` | 로그 조회·내보내기(`GET /logs/*`, `POST /logs/export`, `GET /logs/exports/{name}`), `GET /policy/acks`, 정책 쓰기(`PUT /policy/draft`, `POST /policy/publish`, `POST /policy/deploy`, `POST /policy/model/publish`) |

- security 토큰은 api scope도 만족한다(상위 포함).
- 토큰 출처: 환경변수 `API_TOKENS` / `SECURITY_TOKENS`(콤마 구분) + 런타임
  발급.
- `GET /health`, `GET /`, `POST /auth/dev-token`은 공개.

### 토큰 발급 ("스킵" 버튼)

`POST /auth/dev-token {scope}` → 즉석 Bearer 토큰 발급. 수동 토큰 설정을
건너뛰고 싶을 때 쓴다. `DISABLE_DEV_TOKEN=1`이면 비활성(운영에서 잠금).

### CORS

Bearer 토큰 기반이라 **쿠키를 쓰지 않으므로 `allow_credentials=False`**.
`ALLOWED_ORIGINS`로 허용 오리진을 지정한다. 허용 메서드는 GET/POST/OPTIONS,
허용 헤더는 Authorization·Content-Type·If-None-Match, ETag를 노출한다.

### HTTPS

운영/시연 서버는 uvicorn을 `127.0.0.1`에만 바인딩하고 리버스 프록시에서 TLS를
종료한다. 백엔드 도메인이 없으므로 시연은 자체서명 인증서를 쓴다(브라우저
경고가 뜨지만 전송 구간은 암호화된다).
