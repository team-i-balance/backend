# XLSX 업로드·보호본 생성

`POST /files/sanitize`는 XLSX를 검사·가명화하고 보호본과 복원 매핑을 서버 메모리에
임시 보관합니다. 클라이언트에는 JSON 메타데이터만 반환합니다. 실제 AI 호출, 파일 다운로드,
공개 복원 API, 질문 텍스트와의 매핑 통합은 이번 기능에 포함하지 않습니다.

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

## 요청과 응답

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
매핑표는 응답에 들어가지 않습니다. 응답은 `Cache-Control: no-store`입니다.
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
  // 이후 AI 전송 요청에 연결할 값. 이번 API 자체는 AI에 전송하지 않습니다.
  setPreparedFile({ workId: result.work_id, expiresAt: result.expires_at });
  showFileSummary(result.summary);
}
```

## 내부 AI 전송 코드 연결

`FileWorkStore.take(work_id)`는 보호본과 같은 파일의 `LocalSession`을 함께 반환하고
저장소에서 제거합니다. 동시에 두 번 호출해도 한 호출만 작업을 가져갑니다.
없거나 만료된 작업은 `None`입니다. 가져간 뒤 세션 정리는 호출자 책임입니다.

```python
from app.file_store import store

item = store.take(work_id)  # 내부 전용. 향후 외부 요청은 여기 호출 전 접근 권한 확인 필요.
if item is None:
    raise ValueError("unknown or expired file work")
try:
    protected_bytes = item.file_bytes
    # 향후 AI 전송 담당자가 protected_bytes만 전달하고 답변을 받습니다.
    # reply = await send_to_ai(protected_bytes)
    # restored = item.session.restore(reply)
finally:
    item.close()
```

`take()`는 로그인·권한 검사를 하지 않습니다. 이번에는 업로드만 공개하며, 보호본·매핑을
조회하는 HTTP API를 제공하지 않습니다. 기존 `/process/restore`에는 파일 work_id를
보내지 않습니다. 해당 경로는 별도의 텍스트 작업 저장소를 사용합니다.

## 보관과 정리

- 보호본 생성 완료 후 10분간 유지하며, 최대 20개·보호본 바이트 합계 64 MiB입니다.
  이 용량은 프로세스 전체 메모리 한도가 아니며 모델·매핑·처리 중 메모리는 별도입니다.
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
