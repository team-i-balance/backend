# iBalance Backend

FastAPI 기반 백엔드. 현재는 health check 엔드포인트만 제공합니다.

## 엔드포인트

| Method | Path      | 설명                          |
| ------ | --------- | ----------------------------- |
| GET    | `/`       | 서비스 정보 + 상태            |
| GET    | `/health` | `{"status": "ok"}` 헬스체크   |

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

## 환경 변수

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
