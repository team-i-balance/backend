# iBalance Backend

FastAPI 기반 백엔드. 텍스트 개인정보 처리, 보안 이벤트 로그와 XLSX 보호본 생성·다운로드를 제공합니다.

## 엔드포인트

인증 열: `api` = api 또는 security 토큰, `security` = security 토큰만, `없음` = 토큰 불필요. 자세한 규칙은 [app/rules.md §11](app/rules.md)을 참고하세요.

| Method | Path | 인증 | 설명 |
| ------ | ---- | ---- | ---- |
| GET    | `/` | 없음 | 서비스 정보 + 상태 |
| GET    | `/health` | 없음 | `{"status": "ok"}` 헬스체크 |
| POST   | `/auth/dev-token` | 없음 | 즉석 Bearer 토큰 발급(`{"scope": "api"\|"security"}`); `DISABLE_DEV_TOKEN=1`이면 403 |
| POST   | `/logs/events` | api | 런타임 이벤트 1건 저장·큐 분류(`"test": true`면 시험 이벤트, 선택 `policy_version`) |
| GET    | `/logs/events` | security | 기간·등급·큐 필터와 커서 페이지 넘김 |
| GET    | `/logs/stats` | security | 기간별 통계 및 행동·등급·큐별 건수 |
| GET    | `/logs/changes` | security | 콘솔 폴링용 영역별 변경 표시값, `If-None-Match`가 맞으면 304 ([문서](docs/changes-api.md)) |
| POST   | `/logs/export` | security | 보안팀 공개키로 암호화한 로그 파일 생성. 큐·기간(`start`/`end`) 필터, `limit`(기본 1,000·최대 10,000), `cursor`/`next_cursor` 페이지 넘김 |
| GET    | `/logs/exports/{name}` | security | `/logs/export`가 만든 암호화 파일(`file`의 파일 이름) 내려받기. 내보내기 폴더 바로 아래 `*.enc.json`만, `no-store`, 없거나 형식이 다르면 404 |
| POST   | `/events/{event_id}/reason` | api | 민감 원문 전송 후 직원 사유 제출·저장 |
| GET    | `/events/{event_id}/reason` | api | 사유 필요 여부·재요청 시각(`reason_requested_at`) 조회, `no-store` ([문서](docs/event-reason-api.md)) |
| POST   | `/events/{event_id}/reason-request` | security | 보안팀이 직원에게 사유 재요청 |
| POST   | `/process/preview` | api | 작성 중인 프롬프트의 탐지 유형과 원문 위치(유니코드 코드 포인트, 끝 제외)를 반환합니다. 작업·매핑·로그를 생성하지 않습니다. |
| POST   | `/files/sanitize` | api | XLSX 업로드·검사·보호본 생성 및 임시 보관 |
| GET    | `/files/{work_id}/download` | api | 보호본 1회 다운로드; 복원 매핑은 만료까지 유지 |
| POST   | `/files/{work_id}/restore` | api | 파일 매핑으로 AI 답변 복원; 만료 전까지 여러 번 |
| GET    | `/cases` | security | 필수·선택 검토 및 종결 건 목록, 커서 페이지 이동 |
| GET    | `/cases/{id}` | security | 이벤트 메타데이터와 판단·처리 이력 |
| POST   | `/cases/{id}/close` | security | 위반·예외 인정·오탐으로 종결 |
| POST   | `/cases/{id}/reopen` | security | 이전 이력을 유지하고 다시 열기 |
| POST   | `/cases/close-bulk` | security | 선택 검토 건을 일괄 ‘문제 없음’으로 종결 |
| GET    | `/false-positives` | security | 오탐 신고를 값 해시별로 묶은 목록, `limit`/`cursor`(`last_event_id`) 페이지 넘김 ([문서](docs/false-positive-api.md)) |
| POST   | `/false-positives/{value_hash}/decide` | security | 오탐 신고 묶음 판단 |
| GET    | `/policy/latest` | api | 최신 서명 번들. `ETag: "sha256:…"`, `If-None-Match`가 맞으면 304 |
| GET    | `/policy/{version}` | api | 특정 버전 번들(감사·재현) |
| GET    | `/policy/current` | api | 활성 정책 메타 + 실제 탐지에 쓰는 버전(`effective_version`, 모드별 `effective_versions`)·마지막 적용 오류 코드(`last_apply_error`, 모드별 `last_apply_errors`)·`activated_by`·`value_hash_key_set`([정책 적용 문서](docs/policy-apply.md#배포-전-컴파일-확인과-적용-상태-64)) |
| POST   | `/policy/deploy` | security | 저장된 번들을 검증·컴파일한 뒤 서버 탐지에 활성화. 서버가 적용할 수 없으면 `accepted=false, reason="compile_failed"` |
| GET    | `/policy/history` | security | 발행된 번들 목록(최신순): 버전·`sha256`·저장 시각·규칙 수·발행자(`published_by`) |
| GET    | `/policy/acks` | security | PC 적용/거부 집계(`?version=N`으로 한 버전만) |
| GET    | `/policy/{version}/acks` | security | 한 버전의 기기 수·applied·rejected·거부 사유별 건수 |
| GET    | `/policy/draft` | security | 저장된 정책 초안과 변경 목록, ETag 조회 |
| PUT    | `/policy/draft` | security | If-Match로 동시 수정을 확인하고 초안 전체 저장 |
| POST   | `/policy/publish` | security | 저장된 초안 또는 직접 전달한 payload 서명·발행. 서버가 적용할 수 없는 정책은 422 `POLICY_COMPILE_FAILED` |
| POST   | `/policy/ack`, GET `/policy/acks` | api / security | PC 적용 결과 기록·집계(직원 프로그램이 아직 쓰지 않음, 유지 여부는 #65에서 결정) |

파일 API의 요청·응답, 오류 코드, 내부 AI 전송 연결 방법은 [파일 API 문서](docs/file-api.md)를 참고하세요.
검토 대상 기준, 요청·응답과 콘솔 연결 방법은 [보안팀 검토 API 문서](docs/case-api.md)를 참고하세요.
검토 상태는 기존 `LOG_DB_PATH`에 영구 저장합니다. 처리자는 검증된 security 토큰의 라벨로 기록합니다(#45 이전 이력은 `unauthenticated`).
정책 초안 변경(`changes[].by`·`updated_by`), 발행(`published_by`), 서버 활성화(`activated_by`)도 같은 라벨(`security:<sha256 12자리>`, 즉석 발급 토큰은 `security-dev:…`)로 남깁니다(#59). 그 전에 저장된 초안 변경은 `unauthenticated`, 발행·활성화 기록은 null입니다.
기존 텍스트·로그 API를 포함한 전체 명세는 서버의 `/docs`에서 확인할 수 있습니다.
최근 7일 집계와 1,000건 이상의 목록 조회는 [로그 통계·페이지 넘김 문서](docs/log-stats-api.md)를 참고하세요.
원문 전송 후 사유 제출 흐름, 추가 응답 필드와 재시도 규칙은 [직원 사유 API 문서](docs/event-reason-api.md)를 참고하세요.
정책 초안 저장·충돌 처리·발행과 사건 규칙 연결 방법은 [정책 초안 API 문서](docs/policy-draft-api.md)를 참고하세요.
서버가 배포 정책의 어떤 필드(켬/끔·등급·변환 방식·규칙·고유 단어·탐지 제외)를 어떻게 적용하는지는 [정책 적용 문서](docs/policy-apply.md)를 참고하세요.

### 로그 API 시험 이벤트

연동 확인용 이벤트는 `POST /logs/events` 본문에 `"test": true`를 넣어 보냅니다. 저장과 큐 분류는 일반 이벤트와 같지만, 아래 조회에서는 기본으로 빠집니다.

- `GET /logs/events`, `GET /logs/queues/{name}`, `GET /logs/stats`, `POST /logs/export`
- 시험 이벤트까지 보려면 쿼리에 `include_test=true`를 붙입니다. 예: `GET /logs/stats?include_test=true`
- 응답의 각 이벤트에는 `test` 필드(true/false)가 있습니다.
- 반면 `/cases*`는 시험 이벤트를 **항상** 제외합니다. `include_test` 쿼리가 없고, 시험 이벤트는 검토 건이 되지 않습니다.

`test` 필드가 생기기 전에 들어간 `request_id`가 `console-test-`로 시작하는 이벤트는 서버 시작 때 마이그레이션이 시험 이벤트로 표시합니다. 데이터는 지우지 않습니다.

## 로컬 실행

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

확인:

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

## 로컬 엑셀 첨부파일 보호

위 가상환경에서 의존성을 설치한 후 저장소 루트에서 실행합니다 (Python 3.10 이상).

```bash
python -m file_sanitizer demo
python -m unittest discover -s tests -v
```

데모는 실행마다 `demo-output/run-*/`에 합성 데이터로 만든 `원본.xlsx`와 검증된
`보호본.xlsx`를 저장합니다. 저장 위치는 `--output-dir`로 지정할 수 있습니다.
테스트용 가명화 규칙은 데모 명령에서만 사용합니다.

실제 개인정보 모델을 연결할 때는 `local_ai/requirements-model.txt`의 의존성과
로컬 모델 파일을 준비하고 파일 하나당 아래처럼 매핑 하나를 사용합니다.

```python
from file_sanitizer import LocalPIIProcessor, sanitize_xlsx
from local_ai.detector import Detector
from local_ai.pipeline import LocalSession

detector = Detector(model_dir)  # 같은 프로세스의 다음 파일에서도 재사용 가능
with LocalSession(detector) as mapping:
    result = sanitize_xlsx(data, work_id, LocalPIIProcessor(mapping), filename=input_name)
```

`LocalPIIProcessor`는 셀과 메타데이터의 원문을 검사하고, 보호본을 다시 읽어 잔존 여부를
확인합니다. 독립 모듈의 기본값은 O/S 판정이며, 파일 API는 공통 등급 정책을 연결해
API 키·접근 토큰·비밀번호를 C로 차단합니다. 가명 복원이
필요한 경우 매핑을 닫기 전에 `mapping.restore(text)`를 호출합니다.

**팀 모듈 연결.** `sanitize_xlsx(file_bytes, session_id, processor, filename=original_name)`를
호출합니다. 파일명까지 검사하려면 업로드 경로에서 반드시 `filename`을 넘깁니다.
파일과 프롬프트의 매핑을 통합하려면 같은 `LocalSession` 인스턴스를 연결해야 합니다.
ID 문자열만 같게 지정해도 서로 다른 인스턴스의 매핑은 공유되지 않습니다.
파일 API는 파일별 매핑을 보관하고, 보호본과 함께 보낼 질문은 `/process`의 `file_work_id`로
그 매핑에 연결합니다([파일 API 문서](docs/file-api.md)).
처리기가 구현할 함수는 두 개입니다.

| 함수 | 입력과 반환값 |
| --- | --- |
| `process(session_id, segments)` | 모든 조각 ID에 대해 `Decision(grade, text)`를 반환하는 딕셔너리. 셀 조각에는 위치 ID(예: `s1:A2`), 원문, 첫 행에서 읽은 열 제목, 출력 대상 여부가 들어갑니다. `O`인 출력 셀은 원문을 그대로 돌려주고, `S`는 변환문이나 빈 셀로 만들 `None`을 돌려줍니다. 한 조각이라도 `C`면 문서 전체를 차단합니다. |
| `verify(session_id, segments)` | 보호본을 저장한 후 다시 열어 읽은 텍스트를 검사합니다. 기존 세션 매핑을 사용해 원본 민감값이 남았는지 확인하고 통과한 경우에만 `True`를 반환합니다. 이 단계에서는 매핑을 추가하지 않습니다. |

결과의 `status`는 `READY`, `BLOCKED`, `FAILED` 중 하나입니다. `READY`일 때만
`file_bytes`와 변환 셀·제거 항목 건수를 담은 `summary`가 있습니다. 민감 등급(`S`)은
클라이언트에서 확인 후 전송합니다. 실패와 차단 시에는 `processing_id`와 `reason`을 사용하고
원본 첨부로 대체하지 않습니다. 실제 개인정보 탐지·가명 매핑·복원과 보안 이벤트 저장은
통합 담당 모듈에서 연결합니다.

**지원 범위.** 값으로 이루어진 일반 `.xlsx` 표를 처리합니다. 본문 외에 원본 파일명,
시트명, 메모와 메모 작성자, 문서 속성의 텍스트, 숨긴 시트·행·열의 셀도 검사합니다.
사용자 지정 숫자 서식의 원문과 따옴표·이스케이프를 풀어 이어 붙인 문구도 검사합니다.
현재 적용되지 않는 서식 구간, 빈 셀·숨긴 셀의 서식과 사용하지 않는 서식도 포함합니다.
보호본에는 보이는 셀만 기존 좌표에 쓰며 시트명은 `시트1`부터 다시 붙입니다.
변환하지 않은 숫자·날짜·불리언은 원래 자료형으로 쓰고 임의의 원본 서식은 복사하지 않습니다.
정수에 적용한 `00000`처럼 0만으로 이루어진 서식은 예외로 유지해 앞자리 0을 보존합니다.
이 경우 표시값(`04524`)과 저장값(`4524`)을 모두 검사하며, 가명화된 출력에는 숫자 서식을 붙이지 않습니다.
두 표현의 판정이 달라 저장값의 개인정보가 그대로 출력될 수 있으면 보호본을 반환하지 않습니다.
`;;;` 등 적용 구간이 비어 있는 서식으로 감춘 값은 검사한 뒤 보호본에서 제거합니다.
양수·음수·0·텍스트 구간과 지원되는 숫자 조건을 구분하며, 서식으로 제거한 셀도 `changed_cells`에 포함합니다.
분수 값의 0 채움, 구분자·조건·문구가 섞인 0 채움, 행·열에서 상속한 숫자 서식처럼
표시 의미를 안전하게 보존할 수 없는 경우는 `FAILED / UNSUPPORTED_FEATURE`로 반환합니다.
기밀 판정이 있으면 서식 미지원보다 `BLOCKED / CONFIDENTIAL`을 우선합니다.
날짜만 있는 셀과 자정 시각이 포함된 셀은 각각 날짜와 날짜·시간으로 저장합니다.
숫자로 저장된 셀은 원본 일련번호와 실제 적용되는 서식 구간으로 숫자·날짜·기간을
판단한 뒤 개인정보 처리기에 전달합니다. 적용되지 않는 구간의 날짜 표기로 숫자가 날짜로 바뀌지 않습니다.
1904 날짜 체계의 첫날은 숫자 0부터 시작하므로, 0 이상 1 미만인 일련번호는
달력 날짜를 표시하는 서식에서 `1904-01-01`의 날짜·시간으로 복원합니다. 시각 전용 값은 시각으로 저장합니다.
이때 조건이 붙은 숫자 서식은 반올림 전의 원본 일련번호로 조건을 비교합니다.
앞에서부터 최대 두 개의 숫자 조건과 나머지 값에 적용할 서식 하나를 지원합니다.
어떤 서식이 적용되는지 판단할 수 없으면 추측하지 않고 `FAILED / UNSUPPORTED_FEATURE`를 반환합니다.

내용을 읽기 전에 원본 XML에서 다음 구조를 확인합니다.

- 인라인 문자열, 공유 문자열, 메모 본문에 같은 텍스트 값이 두 번 정의되면 거부합니다.
  여러 서식 조각으로 나뉜 정상 문장은 이어서 검사합니다.
- 셀은 자신이 속한 행과 좌표가 맞아야 하고, 한 좌표에는 셀과 메모가 각각 하나까지만 올 수 있습니다.
  공유 문자열 인덱스는 실제 항목을 가리켜야 하며, 불리언 셀의 저장값은 0 또는 1이어야 합니다.
- 패키지에서 통합 문서로 가는 연결은 하나여야 합니다. 그 문서의 시트 목록·시트 ID·이름·실제 시트 파일의
  대응이 모호하면 거부합니다. 시트 이름은 대소문자를 구분하지 않고 비교합니다.

이런 구조가 모순되면 개인정보 처리기를 호출하지 않고 `FAILED / INVALID_XLSX`를 반환합니다.
정상 구조 안의 내용을 검사해 기밀을 찾은 경우는 `BLOCKED / CONFIDENTIAL`입니다. 두 경우 모두 보호본은 없습니다.

LibreOffice Calc의 기본 계산 설정과 빈 머리글·바닥글 및 빈 사용자 지정 문서 속성을
지원합니다. Calc가 불리언을 `TRUE()` 또는 `FALSE()`로 저장한 경우, 해당 셀이 불리언
형식이고 저장된 값(1 또는 0)이 식과 일치할 때만 보호본에 일반 불리언으로 씁니다.
다른 수식, 알 수 없는 확장 설정, 비어 있지 않은 머리글·바닥글 또는 사용자 지정
문서 속성은 미지원으로 처리합니다.

매크로, 도형·차트·삽입 개체, 외부 링크, 병합·필터·구조화된 표, 암호화 또는
지원하지 않는 파일 구조는 실패로 반환합니다. 입력 한도는 압축 8 MiB, 해제 후 24 MiB,
패키지 파일 256개, 전체 시트의 사용 직사각형 합계 10만 칸입니다.

## 환경 변수

- `POLICY_DB_PATH`: 정책 초안·번들·적용 상태·PC 기록·모델을 저장할 SQLite 경로. 기본값 `data/policy.db`.
- `POLICY_KEYS_DIR`: 정책 서명 개인키와 신뢰 공개키 디렉터리. 기본값 `keys/`.
  운영에서는 DB와 기존 키를 모두 영구 경로에 보관하세요. [저장·이전 안내](docs/policy-persistence.md).
- `POLICY_VALUE_HASH_KEY`: 정책 `dict`·`exclude`의 `hmac:` 항목(이벤트 `value_hash`)을 비교할 조직 키.
  PC 에이전트가 `value_hash`를 만들 때 쓰는 키와 같아야 합니다. 없으면 `hmac:` 항목은 무시하고 경고만 남깁니다.
  설정 여부(값은 아님)는 `GET /policy/current`의 `value_hash_key_set`으로 확인합니다.
- `POLICY_KEY_ID`: 정책 서명 키 이름(번들 `signatures[].keyid`, 키 파일 이름). 기본값 `console-demo`.
  바꿀 때는 기존 키 파일을 새 이름으로 **복사**하고 옛 공개키를 남겨 두세요([안내](docs/policy-persistence.md#서명-키-이름-바꾸기-policy_key_id)).
- `ALLOWED_ORIGINS`: CORS 허용 오리진(콤마 구분). 기본값 `*`.
  배포 시 프론트엔드 주소로 지정하세요. 예: `https://your-app.vercel.app`

## 서버 배포

서버(`13.193.207.69`)에서 systemd 서비스로 상시 실행됩니다.

- `ibalance-backend.service`: uvicorn을 8501 포트로 실행하는 systemd 유닛
- 서버의 `~/backend`는 이 저장소의 git clone이며, `venv/`는 서버에만 존재

수동 실행이 필요하면:

```bash
uvicorn main:app --host 0.0.0.0 --port 8501
```

## 자동 배포 (CI/CD)

`main` 브랜치에 push되면 GitHub Actions(`.github/workflows/deploy.yml`)가
자동으로 서버에 배포합니다.

흐름:

1. push → GitHub Actions 실행
2. Actions가 배포 전용 SSH 키로 서버에 접속
3. 서버에서 `deploy.sh` 실행 → `git pull` + 의존성 설치 + 서비스 재시작
4. `/health`로 헬스체크 (실패 시 워크플로우 실패 처리)

변경이 없으면 `deploy.sh`는 아무 작업 없이 종료합니다.

필요한 GitHub Secrets (이미 등록됨):

- `DEPLOY_SSH_KEY`: 배포 전용 SSH 개인키 (서버 접속용, 사용자 PEM과 무관)
- `SERVER_HOST`: 서버 공인 IP
- `SERVER_USER`: 서버 사용자(`ubuntu`)
