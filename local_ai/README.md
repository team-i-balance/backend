# 로컬 개인정보 가명화 프로토타입

제품 서버와 독립된 로컬 Python 모듈이다. 네트워크 서버를 열거나 외부 AI에 요청하지 않는다. 탐지와 가명화는 사용자의 PC에서 실행해야 한다. 현재 데스크톱 앱 연동은 제공하지 않는다.

## 실행

Python 3.10 이상에서 모델 실행 의존성을 사전에 설치한다.

```bash
python -m pip install -r local_ai/requirements-model.txt
printf '김민수의 연락처는 010-1234-5678입니다.\n' | python -m local_ai --model-dir /path/to/aegis
```

모델 폴더에는 사전에 준비된 AEGIS의 `model.onnx` 또는 `model_quantized.onnx`, `tokenizer.json`, `config.json`이 필요하다. 모델과 의존성 준비 단계에는 별도 다운로드가 필요할 수 있으나 프로그램 실행 중 모델을 다운로드하지 않는다. 모델 파일은 저장소에 포함되어 있지 않다.

전화번호·이메일만 점검하는 제한된 모드(이름·주소 등은 검사하지 않음):

```bash
printf '문의는 user@example.com\n' | python -m local_ai --rules-only
```

실제 개인정보를 터미널 명령줄 인자로 넣지 않는다. 결과에 탐지되지 않은 개인정보가 남을 수 있으므로 전송 전에 사용자가 확인해야 한다. 데스크톱 연동 전 임시 시연용 인터페이스다.

## 내부 사용

`Detector(model_dir)`와 `LocalSession(detector)`를 로컬 프로세스에서 생성한 뒤 `process(text)`를 호출한다. 오류가 나면 결과를 검사 완료로 취급하지 않는다. `close()`로 작업별 메모리 매핑을 폐기한다. `coverage`가 `rules_only_incomplete`인 경우에는 전화·이메일 외에는 검사하지 않았음을 의미한다. `remaining`은 가명화 결과를 다시 검사한 탐지 위치 목록이며, 가명 텍스트에 대한 오탐도 포함할 수 있다.

정규식과 모델은 모든 개인정보를 탐지하지 못한다. 탐지 결과에 모호한 겹침이 있으면 자동 가명화하지 않고 오류로 처리한다. 한 작업의 매핑은 프로세스 종료 시 사라진다. 별도 Backend API나 원격 전송은 구현하지 않았다.

## 검증 결과와 남은 작업

- 가상의 이름·전화번호·이메일로 실제 AEGIS 로컬 추론과 재검사를 수행했다. Python 소켓 연결 차단 하에서 실행했으나 네이티브 라이브러리를 포함한 모든 통신 차단은 확인하지 못했다.
- 일부 한국어 이름은 모델이 조사를 포함해 탐지한다. 예를 들어 같은 이름이 `김민수`와 `김민수의`로 탐지되면 서로 다른 가명으로 치환될 수 있다. 탐지 구간 검토·수정 기능이 필요하다.
- macOS ARM64, 2스레드의 별도 단일 실행에서 탐지와 재검사를 포함한 약 1,019자 455ms, 10,019자 4,705ms를 기록했다. 합성 반복 텍스트이며 실제 장비의 성능을 보장하지 않는다. 두 측정까지 누적 최대 RSS는 약 450MiB였다.
- 데스크톱 앱 연결, 실제 기기에서의 장기 자원 측정, OS 수준 네트워크 차단 검증은 미완료다. 가명화한 텍스트에도 민감한 내용이 남을 수 있다.

## 추가 탐지와 복원

사업자번호는 하이픈 형태와 검증 숫자를 확인한다. 하이픈 없는 10자리 번호는 앞쪽 같은 줄의 사업자번호 문맥도 필요하다. 검증 숫자는 실제 사업자 등록 여부를 뜻하지 않는다. API 키는 `api_key` 대입, `access_token` 대입, `Authorization: Bearer` 값과 `sk-`, `sk-proj-`, `ghp_`로 시작하는 일부 형식을 검사한다. 그 밖의 키 형식이나 동적인 코드 표현은 탐지하지 못할 수 있다.

`LocalSession.restore(text)`는 현재 작업에서 발급한 가명만 복원하고 `text`, `unknown`, `blocked`를 반환한다. API 키, 액세스 토큰, 비밀번호는 기본적으로 복원하지 않는다. 모르는 가명은 유지하며, 텍스트의 가명이 다른 작업에서 생성된 것인지 자체적으로 구별할 수 없으므로 호출자가 올바른 세션을 선택해야 한다. `close()` 후에는 복원할 수 없다. 사업자번호 표기에 하이픈 유무가 다르면 별도 원문 값으로 취급한다.

## 기밀·비정형 개인정보 SLM (`local_ai/slm`)

회사 기밀 규칙(정책)과 이름·주소·개인 민감정보를 찾는 로컬 SLM(GLiNER 미세조정, [team-i-balance/slm](https://github.com/team-i-balance/slm))을 선택적으로 붙인다.
모델 폴더는 저장소에 없고, 실행 중 다운로드하지 않는다.

```bash
python -m pip install -r local_ai/requirements-slm.txt
export LOCAL_SLM_MODEL_DIR=/path/to/slm-v2-trim        # gliner_config.json 이 있는 폴더
export LOCAL_SLM_POLICY=/path/to/policy.json           # 없으면 local_ai/slm/policy.example.json (가상 회사 예시)
```

`Detector(model_dir, slm_dir=..., slm_policy=...)` 처럼 AEGIS 모델과 함께 또는 단독으로 쓴다. `/process` 는 `LOCAL_PII_MODEL_DIR` 와 `LOCAL_SLM_MODEL_DIR` 중 하나만 있어도 전체 탐지 모드를 연다.

| 탐지 유형 | 출처 | 등급 (`app/grading.py`) |
|---|---|---|
| `NAME`, `ADDRESS` | 고정 라벨 | S |
| `SENSITIVE` | 고정 라벨: 특정인의 건강·징계·종교·범죄 경력 등 | C |
| `CONFIDENTIAL` | 정책 규칙 중 `grade: "C"` | C |
| `INTERNAL` | 정책 규칙 중 `grade: "S"` | S |

- 모델은 "어느 구간이 어느 규칙에 해당하는지"만 찾고, 등급은 보안팀 정책의 규칙 grade 로 정해진다. 새 규칙은 정책 파일만 바꾸면 재학습 없이 적용된다 (규칙 `label` 은 15자 이내 명사구)
- 겹치는 구간은 더 강한 유형(PASSWORD > API_KEY > ACCESS_TOKEN > CONFIDENTIAL > SENSITIVE > INTERNAL > ADDRESS > NAME > 기타)으로 합친다
- API 키·토큰 구간은 언제나 그대로 두고 SLM 구간을 그 주변으로 자른다. 전화·이메일·사업자번호도 그대로 두되, C 등급 SLM 구간(CONFIDENTIAL·SENSITIVE)이 덮으면 그 안에 흡수해 정책 등급을 유지한다
- 성능(합성 평가셋 719문장, 기준값 기밀 0.45 / 개인정보 0.35): 기밀 재현율 90.2%, 이름·주소 100%, 민감정보 89%, 오탐 문장률 8.1%, 등급 정확도 90%, 문장당 약 80ms(M5 CPU). 합성 데이터라 실제 입력에서는 더 낮을 수 있다
- 실제 모델 테스트: `LOCAL_SLM_MODEL_DIR=... python -m pytest tests/test_slm_adapter.py`
