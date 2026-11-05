# XLSX 업로드·보호본 생성·다운로드

`POST /files/sanitize`는 XLSX를 검사·가명화하고 보호본과 복원 매핑을 서버 메모리에
임시 보관하고 JSON 메타데이터를 반환합니다. 클라이언트는 `READY` 응답의 `work_id`로
`GET /files/{work_id}/download`를 호출해 보호본을 받아 저장하거나 외부 AI에 첨부할 수 있습니다.
AI 답변은 `POST /files/{work_id}/restore`로 복원하고, 보호본과 함께 보낼 질문은 `/process`에
`file_work_id`를 넘겨 같은 매핑에서 가명화합니다. 서버의 실제 AI 호출은 별도 기능입니다.

## 실행

Python 3.10 이상에서 서버 의존성과 모델 의존성을 설치합니다.
이미 준비된 모델만 로컬에서 읽으며 자동 다운로드나 외부 AI 호출을 하지 않습니다.

```bash
pip install -r requirements.txt -r local_ai/requirements-model.txt
export LOCAL_PII_MODEL_DIR=/absolute/path/to/local-model
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
```

모델 디렉터리에는 `config.json`, `tokenizer.json`, 지원되는 ONNX 모델이 있어야 합니다.
설정·의존성·모델 로딩에 문제가 있으면 `503 / MODEL_UNAVAILABLE`이며,
규칙 전용 모드나 데모 처리기로 대체하지 않습니다. 탐지기는 텍스트 API와 공유하지만
매핑과 작업 저장소는 파일마다 분리합니다. 파일에 연결한 질문만 그 파일의 매핑을 함께 씁니다.

## 업로드 요청과 응답

`multipart/form-data`에 `file` 하나만 전달합니다. `.xlsx` 확장자와 실제 OOXML 내용을
검증합니다. MIME 이름만으로 통과시키지 않습니다. 파일 최대 8 MiB, multipart 전체 요청은
9 MiB이며 길이 헤더가 없는 요청도 실제 수신량으로 제한합니다.

```bash
curl -X POST http://localhost:8000/files/sanitize \
  -F 'file=@/absolute/path/to/sample.xlsx'
```

응답 예시(건수와 만료 시각은 파일·요청에 따라 달라집니다):

```json
{
  "work_id": "3185cc662f374751acb305005307108d",
  "status": "READY",
  "grade": "sensitive_S",
  "reason": null,
  "summary": {
    "changed_cells": 4,
    "removed_comments": 2,
    "removed_sheets": 1,
    "removed_rows": 0,
    "removed_columns": 0
  },
  "expires_at": "2026-11-05T09:10:00Z",
  "detected_types": ["NAME", "PHONE"],
  "detected_count": 6,
  "detected_counts": {"NAME": 2, "PHONE": 2},
  "hidden_counts": {"NAME": 2},
  "blocked_types": null
}
```

| 상태 | 의미 |
| --- | --- |
| `READY` | 재검사를 통과한 보호본과 살아 있는 매핑이 보관됨 |
| `BLOCKED` | 공통 등급 정책의 C 검출로 파일 전체 차단; 보관 없음 |
| `FAILED` | 입력·처리·보관 실패; 보관 없음 |

등급은 `public_O`, `sensitive_S`, `confidential_C`이며 판정 전 실패하면 `null`입니다.
실패·차단의 `summary`와 `expires_at`은 `null`입니다. 원본 파일명, 원문, 보호본 바이트,
매핑표는 업로드 JSON 응답에 들어가지 않습니다. 응답은 `Cache-Control: no-store`입니다.
`READY`는 구현된 검사 통과를 뜻하며, 모델이 놓친 개인정보까지 없음을 보증하지는 않습니다.

### 탐지 유형·건수

`READY`와 `BLOCKED`는 찾은 유형과 건수를 함께 돌려줍니다. 원문 값, 셀 위치, 파일 이름은
담지 않습니다. 유형 이름은 텍스트 API(`/process`)의 `detected_types`와 같습니다.
`FAILED`는 검사를 끝내지 못했으므로 아래 필드가 모두 `null`입니다.

| 필드 | 의미 |
| --- | --- |
| `detected_types` | 파일 어디에서든 찾은 유형. 등급은 이 유형으로 정합니다. |
| `detected_counts` | 유형별, 보호본 칸에 들어가 자리표시로 가린 곳 수 |
| `hidden_counts` | 유형별, 보호본에서 빠지는 곳에서 찾은 수: 원본 파일명, 문서 속성, 숫자 서식, 시트 이름, 메모와 작성자, 숨긴 시트·행·열, 서식으로 숨긴 셀 |
| `detected_count` | 파일 전체에서 찾은 곳 수 = `detected_counts` 합 + `hidden_counts` 합 |
| `blocked_types` | `BLOCKED`일 때만 파일을 기밀로 만든 유형(예: `["API_KEY"]`). 그 외에는 `null` |

- 같은 값이 여러 칸에 있으면 칸마다 셉니다. 한 칸에 이름이 둘이면 2입니다.
- 같은 곳을 두 번 읽는 경우는 한 곳으로 셉니다: 0으로 채운 숫자 셀의 표시값과 저장값,
  숫자 서식과 그 서식이 표시하는 문구. 유형별로 더 많이 찾은 쪽 수를 씁니다.
- `BLOCKED`도 같은 기준으로 칸과 빠지는 곳을 나눕니다. 보호본은 만들지 않습니다.
  `blocked_types`에는 그 자체로 기밀 등급인 유형만 넣고, 함께 찾은 이름 등은
  `detected_types`에만 둡니다.

| HTTP | reason / 용도 |
| --- | --- |
| 200 | `READY`, 또는 `BLOCKED / CONFIDENTIAL` |
| 413 | `FILE_TOO_LARGE`: 업로드·요청·압축 해제 크기 등 기존 파일 자원 한도 초과 |
| 415 | `EXPECTED_MULTIPART`, `UNSUPPORTED_FILE_TYPE` |
| 422 | `INVALID_MULTIPART`, `EXPECTED_ONE_FILE`, `INVALID_XLSX`, `UNSUPPORTED_FEATURE`, `RESIDUAL_CHECK_FAILED` |
| 429 | `FILE_PROCESSING_BUSY`: 다른 파일 처리 중; `Retry-After: 1` |
| 500 | `PROCESSOR_ERROR`, `INVALID_PROCESSOR_RESULT`, `INVALID_COPY`, `COPY_VERIFICATION_ERROR`, `PROCESSING_ERROR`, `EVENT_LOG_FAILED`(차단 이벤트 저장 실패) |
| 503 | `MODEL_UNAVAILABLE`, `FILE_STORE_FULL` |

클라이언트는 HTTP 코드와 `status`를 함께 확인합니다. 처리가 끝날 때 응답하며,
백그라운드 작업 ID 발급이나 진행률 조회 기능은 없습니다.

```javascript
async function prepareXlsx(file) {
  const form = new FormData();
  form.append("file", file);
  const response = await fetch(`${API_BASE}/files/sanitize`, {
    method: "POST",
    body: form,
  });
  // Content-Type은 브라우저가 multipart boundary와 함께 설정하게 둡니다.
  const result = await response.json();
  if (!response.ok || result.status !== "READY") {
    showFileError(result.status, result.reason);
    return;
  }
  showFileSummary(result.summary);
  const copyResponse = await fetch(
    `${API_BASE}/files/${encodeURIComponent(result.work_id)}/download`
  );
  if (!copyResponse.ok) {
    const error = await copyResponse.json();
    showFileError("FAILED", error.detail);
    return;
  }
  const protectedFile = new File([await copyResponse.blob()], "보호본.xlsx", {
    type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  });
  // 메모리의 File을 저장하거나 첨부합니다. 원본 file을 첨부하지 않습니다.
  setPreparedFile({
    workId: result.work_id, expiresAt: result.expires_at, file: protectedFile,
  });
}
```

## 보호본 다운로드

`GET /files/{work_id}/download`는 **한 번만** 보호본 바이트를 반환합니다.
업로드의 JSON 응답 형식은 바뀌지 않습니다. 차단·실패한 작업, 알 수 없는 ID,
만료됐거나 이미 다운로드한 작업은 모두 같은 `404 / {"detail": "FILE_NOT_AVAILABLE"}`입니다.
현재 매핑이 남아 있더라도 이미 받은 파일을 다시 받을 수는 없습니다.

```bash
curl --fail 'http://localhost:8000/files/WORK_ID/download' --output '보호본.xlsx'
```

성공 응답 헤더:

```http
Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
Content-Disposition: attachment; filename="protected.xlsx"; filename*=UTF-8''%EB%B3%B4%ED%98%B8%EB%B3%B8.xlsx
Cache-Control: no-store
```

파일명은 원본과 관계없이 `보호본.xlsx`로 고정합니다. UTF-8 파일명을 지원하지 않는
클라이언트를 위한 ASCII 이름은 `protected.xlsx`입니다. 브라우저의 다른 오리진에서도
`Content-Disposition`을 읽을 수 있도록 CORS의 exposed headers에 추가했습니다.
실패 응답에도 `Cache-Control: no-store`를 설정합니다.

파일 바이트를 가져오는 순간 다운로드가 소비됩니다. 동시에 여러 요청이 와도 한 요청만
성공합니다. 전송이 중단되거나 사용자가 파일을 저장하지 못한 경우에도 재다운로드는 404이며,
원본을 다시 업로드해야 합니다. 범위·재개 다운로드는 지원하지 않습니다.
보호본은 보안 이벤트를 저장한 뒤에만 내보냅니다. 저장에 실패하면
`500 / {"detail": "EVENT_LOG_FAILED"}`이며, 이때도 다운로드는 소비됩니다.

토큰 인증 [#10](https://github.com/team-i-balance/backend/issues/10)이 도입되기 전까지는
업로드 시 서버가 생성한 추측하기 어려운 UUID `work_id`가 접근 열쇠입니다.
ID를 아는 사람은 다운로드할 수 있으므로 공개 링크로 공유하지 않습니다.
#10 통합 시 업로드한 토큰과 다운로드 요청 토큰의 소유권을 함께 확인해야 합니다.

## AI 답변 복원

`POST /files/{work_id}/restore`는 외부 AI 답변 속 자리표시를 이 파일 매핑으로 되돌립니다.
요청·응답은 `/process/restore`와 같은 형식입니다.

```bash
curl -X POST 'http://localhost:8000/files/WORK_ID/restore' \
  -H 'Content-Type: application/json' \
  -d '{"text": "[이름_1]님께 [전화번호_1]로 연락하세요."}'
```

```json
{"text": "김민수님께 010-1234-5678로 연락하세요.", "unknown": [], "blocked": []}
```

- 이 매핑에 없는 자리표시는 그대로 두고 `unknown`에 넣습니다. 비밀값(API 키·토큰·비밀번호)
  자리표시는 텍스트처럼 되돌리지 않고 `blocked`에 넣습니다.
- 텍스트 작업과 달리 만료(보호본 생성 후 10분)까지 **여러 번** 복원할 수 있습니다.
  다운로드 전후 모두 가능하며, 복원해도 만료 시각은 늘어나지 않습니다.
- `text`는 최대 200,000자입니다. 응답에 원래 값이 들어가므로 `Cache-Control: no-store`입니다.
- 알 수 없는 ID와 만료·차단·실패한 작업은 `404 / {"detail": "FILE_NOT_AVAILABLE"}`입니다.
- #10 전까지는 다운로드처럼 `work_id`가 접근 열쇠입니다. #10 통합 시 업로드한 토큰으로만
  복원하게 묶어야 합니다.

## 질문을 파일 매핑에 연결

질문과 파일은 작업마다 자리표시 번호를 1부터 매깁니다. 따로 처리해 같은 대화에 보내면
`[이름_1]` 하나가 질문 속 사람과 파일 속 사람을 함께 가리킬 수 있습니다. 보호본과 함께
보낼 질문은 `POST /process`에 그 파일의 `work_id`를 `file_work_id`로 넘깁니다.

```json
{"text": "박영희가 김민수에게 보낼 안내문을 써줘", "file_work_id": "3185cc662f374751acb305005307108d"}
```

- 질문을 파일 매핑 안에서 가명화합니다. 파일에 있던 값은 파일과 같은 자리표시를 쓰고
  (파일의 `김민수`가 `[이름_1]`이면 질문에서도 `[이름_1]`), 새 값은 다음 번호를 받습니다
  (`박영희` → `[이름_2]`). 후속 질문도 같은 `file_work_id`로 보내면 번호가 이어집니다.
- 답변은 `/files/{work_id}/restore`(여러 번)나 질문의 `/process/restore`(한 번) 어느 쪽으로도
  질문과 파일의 자리표시를 함께 복원합니다.
- 응답 형식, `/process/decide` 흐름과 이벤트 기록은 연결하지 않은 질문과 같습니다.
- 파일은 모델로 검사하므로 연결한 질문도 전체 탐지를 씁니다. `rules_only: true`와 함께 보내면 422입니다.
- 알 수 없거나 만료된 `file_work_id`는 `404 / unknown or expired file_work_id`입니다.
  파일 작업이 끝나면 연결한 질문의 `/process/restore`도 404입니다.
- 질문에 보호본의 자리표시(예: `[이름_1]`)를 그대로 쓰면 원래 글자와 구별할 수 없어 처리하지 않고
  `422 / text contains a placeholder of the linked file; ...`를 반환합니다. 원래 값으로 묻게 안내합니다.
- 연결한 질문의 값도 파일 매핑에 들어가 파일 작업이 끝날 때 함께 지워집니다. 질문을 취소해도
  그때까지는 매핑에 남습니다.
- 질문 하나는 파일 하나에만 연결합니다. 여러 파일을 함께 보내면 파일끼리는 번호가 겹칠 수 있습니다.

## 보안 이벤트 기록

파일 작업도 텍스트의 `/process/decide`처럼 보안 이벤트 로그(`/logs/events`)에 남습니다.
앱이 따로 호출할 필요 없이 서버가 기록합니다.

| 시점 | `action` | 비고 |
| --- | --- | --- |
| `BLOCKED` 응답 | `cancel` | 이벤트 저장에 실패하면 `500 / EVENT_LOG_FAILED`로 응답 |
| 보호본 다운로드 | `send_transformed` | 텍스트의 변환문 전송에 해당. 저장 실패 시 보호본을 내보내지 않음 |
| `READY`인데 내려받지 않고 만료 | `cancel` | 60초마다 도는 정리 작업이 기록(만료 후 약 1분 안). 요청 처리 중에는 쓰지 않음 |

- 기존 이벤트 형식(`EventIn`)을 그대로 쓰고 `source: "file"`로 텍스트 이벤트와 구분합니다.
  기존 행과 텍스트 이벤트는 `source: "text"`입니다. 서버 시작 시 기존 DB에 열을 추가합니다.
- `request_id`는 파일 `work_id`, `grade`는 응답과 같은 등급, `detected_types`·`detected_count`는
  응답의 같은 필드(파일 전체에서 찾은 유형·곳 수)입니다. 파일 검사는 모델을 쓰므로
  `detection_confidence`는 `high`입니다.
- `content_hash`는 올라온 파일 바이트의 SHA-256입니다. 원문 값, 파일 이름, 셀 위치는 저장하지 않습니다.
- `FAILED`, 처리 후 연결이 끊겨 버린 작업, 서버 종료로 사라진 작업은 기록하지 않습니다.
- 큐는 텍스트 이벤트와 같은 규칙(`app/rules.md` 4절)으로 정합니다. 지금 규칙에서는
  전송이 없는 취소와 변환 전송 모두 `pre_warning`이며, 원문 전송이 아니므로 검토 건(`/cases`)이 되지 않습니다.

## 내부 복원·AI 전송 코드 연결

다운로드에는 `FileWorkStore.take_download(work_id)`를 사용합니다. 파일 바이트와 기록할 이벤트
정보를 원자적으로 꺼내 `Download(data, event)`로 반환하고, 같은 작업의 `LocalSession`은
원래 만료 시각까지 유지합니다. 파일 다운로드가 매핑의 유효기간을 연장하지는 않습니다.

내부 `FileWorkStore.take(work_id)`는 작업 전체를 저장소에서 제거하고 소유권을 호출자에게
넘깁니다. 이미 다운로드했다면 `item.downloaded`는 `True`, `item.file_bytes`는 `b""`이며,
매핑은 살아 있어 복원에 사용할 수 있습니다. 다운로드 전이라면 보호본 바이트도 함께 가져갑니다.
없거나 만료된 작업은 `None`입니다. 가져간 뒤 세션 정리는 호출자 책임입니다.

```python
from app.file_store import store

item = store.take(work_id)  # 내부 전용. 향후 외부 요청은 여기 호출 전 접근 권한 확인 필요.
if item is None:
    raise ValueError("unknown or expired file work")
try:
    # 이미 다운로드한 파일의 AI 답변도 같은 매핑으로 복원할 수 있습니다.
    # restored = item.session.restore(reply)
    # 서버가 직접 AI에 파일을 전송하는 경로라면 먼저
    # item.downloaded가 False이고 item.file_bytes가 있는지 확인해야 합니다.
    pass
finally:
    item.close()
```

`take()`는 로그인·권한 검사를 하지 않습니다. 공개 경로의 복원은 `FileWorkStore.restore()`,
질문 연결은 `FileWorkStore.lend()`를 쓰며 둘 다 매핑을 저장소에 둔 채 사용합니다.
`/process/restore`에는 파일 work_id를 보내지 않습니다. 그 경로는 텍스트 작업 저장소를 씁니다.
`item.session`은 매핑을 한 번에 한 요청만 쓰게 하는 `SharedMapping`이며 `restore()`와
`close()`는 `LocalSession`과 같습니다. 내부 `take()`는 보안 이벤트를 남기지 않으므로, 서버가
직접 AI에 파일을 보내는 경로를 만들면 그 경로에서 이벤트를 기록해야 합니다.

## 보관과 정리

- 보호본 생성 완료 후 10분간 유지하며, 최대 20개·보호본 바이트 합계 64 MiB입니다.
  이 용량은 프로세스 전체 메모리 한도가 아니며 모델·매핑·처리 중 메모리는 별도입니다.
- 다운로드 시 보호본 바이트는 저장소에서 제거되고 응답 완료 후 해제됩니다. 매핑을 유지하는
  작업은 여전히 20개 한도에 포함되며, 만료·내부 `take()`·서버 종료 시 슬롯이 반환됩니다.
- 원본 파일은 처리 후 보관하지 않습니다. 원래 개인정보 값은 복원에 필요한 매핑 안에
  남고, `take()` 이후 호출자 정리 또는 만료·서버 종료 시 세션을 닫아 제거합니다.
  파일에 연결한 질문의 값도 같은 매핑에 있어 함께 제거됩니다.
- 복원과 연결한 질문은 만료를 늘리지 않습니다. 만료 때 진행 중인 복원·질문 처리가 있으면
  그 처리가 끝난 뒤 매핑을 닫고, 그동안에도 저장소의 다른 요청은 기다리지 않습니다.
- 만료는 접근 시 및 60초 간격으로 검사합니다. 용량 부족 시 기존 작업을 밀어내지 않습니다.
- 파일 한 개를 처리하는 동안 추가 업로드는 429입니다. 수신 중단·파서 오류·취소 시에도
  업로드 임시 파일을 닫습니다. 취소된 모델 작업이 실제 끝나기 전에는 처리 슬롯을 재사용하지 않습니다.
- Starlette의 업로드 버퍼는 1 MiB를 넘으면 임시 디스크를 사용할 수 있습니다.
  종료 경로에서 닫으며 별도 영구 원본 저장·외부 전송은 하지 않습니다. DB에는 위의
  보안 이벤트 메타데이터만 기록합니다.
- 초기 운영은 단일 프로세스입니다. 서버 재시작 시 보호본·매핑은 사라집니다.
  여러 worker/서버에 분산하는 운영은 공유 저장소 설계 후 지원해야 합니다.

## 테스트

```bash
pip install -r requirements-dev.txt
python -m pytest
# 모델을 준비한 환경에서만 실제 모델 테스트 추가
LOCAL_PII_MODEL_DIR=/absolute/path/to/local-model python -m pytest tests/test_file_model_optional.py tests/test_model_optional.py
```

`test_file_api.py`는 테스트용 탐지기와 실제 `LocalSession`/가명화·복원 코드를 사용해
API와 보호본·매핑의 연결을 검사합니다. 모델 탐지 정확도 평가와 구분합니다.
`test_file_download.py`는 업로드 후 실제 XLSX 바이너리·고정 파일명, 1회 다운로드,
동시 요청, 만료·중단 및 다운로드 후 복원 매핑 유지를 검증합니다.
`test_file_findings.py`는 탐지 유형·건수, `test_file_events.py`는 보안 이벤트 기록,
`test_file_restore.py`는 답변 복원과 질문 연결·동시 사용을 검증합니다.

실제 모델 API 확인 테스트는 엑셀의 자동 생성·수정 시각을 고정해 재현성을 유지합니다.
검증 중 AEGIS 모델이 `2026-11-05T07:52:54Z`를 생년월일로 오탐해,
보호본의 자동 생성 시각 재검사에서 `RESIDUAL_CHECK_FAILED`를 반환하는 현상을 확인했습니다.
동일 입력 SHA-256과 동일 생성 시각으로 기존 main(`ba0a87d`)과 이 변경에서 같은 결과가
재현됐습니다. 다운로드 추가와 별개인 모델·메타데이터 판정 문제이며, 이 변경에서는
실패를 우회하거나 탐지 정책을 변경하지 않습니다. 업로드가 `FAILED`이면 다운로드도 404입니다.
