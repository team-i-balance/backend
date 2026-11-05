from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

from fastapi import Depends

from app.auth import require_api
from app.auth_router import router as auth_router
from app.db import init_db
from app.router import router as logs_router
from app.reason_router import router as reason_router
from app.process_router import router as process_router
from app.file_router import router as file_router
from app.policy_router import router as policy_router
from app.case_router import router as case_router
from app.false_positive_router import router as fp_router, reason_request_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from app.policy import store as policy_store

    policy_store.initialize()
    from app.sessions import store
    from app.file_store import store as file_store

    store.start_sweeper()
    file_store.start()
    from app.detectors import warm_up_in_background

    warm_up_in_background()
    try:
        yield
    finally:
        file_store.close()
        store.stop_sweeper()


app = FastAPI(title="iBalance Backend", version="0.1.0", lifespan=lifespan)

# CORS. Set ALLOWED_ORIGINS to a comma-separated list of allowed frontends.
# We authenticate with bearer tokens (not cookies), so credentials are OFF;
# that also avoids the unsafe "*" + credentials combination.
allowed_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins or ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "If-None-Match", "If-Match"],
    # ETag for policy caching; Content-Disposition for file downloads.
    expose_headers=["ETag", "Content-Disposition"],
)


app.include_router(auth_router)  # public: issues tokens
# logs_router and policy_router carry per-route auth (mixed scopes) inside them.
app.include_router(logs_router)
# /process*, /files/*, and /reasons require an api (or security) token.
app.include_router(reason_router, dependencies=[Depends(require_api)])
app.include_router(process_router, dependencies=[Depends(require_api)])
app.include_router(file_router, dependencies=[Depends(require_api)])
app.include_router(policy_router)
app.include_router(case_router)
app.include_router(fp_router)  # require_security inside (#48)
app.include_router(reason_request_router)  # require_security inside (#48)


@app.get("/")
def root():
    return {"service": "ibalance-backend", "status": "ok"}


@app.get("/health")
def health():
    # Detection coverage lets clients tell full checks from rules-only before sending text.
    from app.detectors import detection_status

    return {"status": "ok", **detection_status()}
