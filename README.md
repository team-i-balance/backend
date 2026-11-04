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

## 서버 배포 (예시)

열린 포트 8501을 사용하거나, 필요한 포트는 보안그룹에 직접 열어서 사용합니다.

```bash
uvicorn main:app --host 0.0.0.0 --port 8501
```
