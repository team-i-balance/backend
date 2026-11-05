# XLSX 업로드·보호본 생성·다운로드

`POST /files/sanitize`는 XLSX를 검사·가명화하고 보호본과 복원 매핑을 서버 메모리에
임시 보관하고 JSON 메타데이터를 반환합니다. 클라이언트는 `READY` 응답의 `work_id`로
`GET /files/{work_id}/download`를 호출해 보호본을 받아 저장하거나 외부 AI에 첨부할 수 있습니다.
서버의 실제 AI 호출, 공개 복원 API, 질문 텍스트와의 매핑 통합은 별도 기능입니다.

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
매핑과 작업 저장소는 파일마다 분리합니다.

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
    "changed_cells": 12,
    "removed_comments": 2,
    "removed_sheets": 1,
    "removed_rows": 0,
    "removed_columns": 0
  },
  "expires_at": "2026-11-05T09:10:00Z"
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

| HTTP | reason / 용도 |
| --- | --- |
| 200 | `READY`, 또는 `BLOCKED / CONFIDENTIAL` |
| 413 | `FILE_TOO_LARGE`: 업로드·요청·압축 해제 크기 등 기존 파일 자원 한도 초과 |
| 415 | `EXPECTED_MULTIPART`, `UNSUPPORTED_FILE_TYPE` |
| 422 | `INVALID_MULTIPART`, `EXPECTED_ONE_FILE`, `INVALID_XLSX`, `UNSUPPORTED_FEATURE`, `RESIDUAL_CHECK_FAILED` |
| 429 | `FILE_PROCESSING_BUSY`: 다른 파일 처리 중; `Retry-After: 1` |
| 500 | `PROCESSOR_ERROR`, `INVALID_PROCESSOR_RESULT`, `INVALID_COPY`, `COPY_VERIFICATION_ERROR`, `PROCESSING_ERROR` |
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

토큰 인증 [#10](https://github.com/team-i-balance/backend/issues/10)이 도입되기 전까지는
업로드 시 서버가 생성한 추측하기 어려운 UUID `work_id`가 접근 열쇠입니다.
ID를 아는 사람은 다운로드할 수 있으므로 공개 링크로 공유하지 않습니다.
#10 통합 시 업로드한 토큰과 다운로드 요청 토큰의 소유권을 함께 확인해야 합니다.

## 내부 복원·AI 전송 코드 연결

다운로드에는 `FileWorkStore.take_download(work_id)`를 사용합니다. 파일 바이트만 원자적으로
꺼내 반환하고, 같은 작업의 `LocalSession`은 원래 만료 시각까지 유지합니다. 파일 다운로드가
매핑의 유효기간을 연장하지는 않습니다.

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

`take()`는 로그인·권한 검사를 하지 않습니다. 매핑을 조회하거나 파일의 AI 답변을 복원하는
공개 API는 아직 없습니다. 기존 `/process/restore`에는 파일 work_id를 보내지 않습니다.
해당 경로는 별도의 텍스트 작업 저장소를 사용합니다.

## 보관과 정리

- 보호본 생성 완료 후 10분간 유지하며, 최대 20개·보호본 바이트 합계 64 MiB입니다.
  이 용량은 프로세스 전체 메모리 한도가 아니며 모델·매핑·처리 중 메모리는 별도입니다.
- 다운로드 시 보호본 바이트는 저장소에서 제거되고 응답 완료 후 해제됩니다. 매핑을 유지하는
  작업은 여전히 20개 한도에 포함되며, 만료·내부 `take()`·서버 종료 시 슬롯이 반환됩니다.
- 원본 파일은 처리 후 보관하지 않습니다. 원래 개인정보 값은 복원에 필요한 매핑 안에
  남고, `take()` 이후 호출자 정리 또는 만료·서버 종료 시 세션을 닫아 제거합니다.
- 만료는 접근 시 및 60초 간격으로 검사합니다. 용량 부족 시 기존 작업을 밀어내지 않습니다.
- 파일 한 개를 처리하는 동안 추가 업로드는 429입니다. 수신 중단·파서 오류·취소 시에도
  업로드 임시 파일을 닫습니다. 취소된 모델 작업이 실제 끝나기 전에는 처리 슬롯을 재사용하지 않습니다.
- Starlette의 업로드 버퍼는 1 MiB를 넘으면 임시 디스크를 사용할 수 있습니다.
  종료 경로에서 닫으며 별도 영구 원본 저장·DB 기록·외부 전송은 하지 않습니다.
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

실제 모델 API 확인 테스트는 엑셀의 자동 생성·수정 시각을 고정해 재현성을 유지합니다.
검증 중 AEGIS 모델이 `2026-11-05T07:52:54Z`를 생년월일로 오탐해,
보호본의 자동 생성 시각 재검사에서 `RESIDUAL_CHECK_FAILED`를 반환하는 현상을 확인했습니다.
동일 입력 SHA-256과 동일 생성 시각으로 기존 main(`ba0a87d`)과 이 변경에서 같은 결과가
재현됐습니다. 다운로드 추가와 별개인 모델·메타데이터 판정 문제이며, 이 변경에서는
실패를 우회하거나 탐지 정책을 변경하지 않습니다. 업로드가 `FAILED`이면 다운로드도 404입니다.
