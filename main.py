from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

from app.db import init_db
from app.router import router as logs_router
from app.process_router import router as process_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="iBalance Backend", version="0.1.0", lifespan=lifespan)

# CORS: allow the frontend (Vercel) to call the health check.
# Set ALLOWED_ORIGINS to a comma-separated list in production, e.g.
#   ALLOWED_ORIGINS="https://your-app.vercel.app"
allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in allowed_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(logs_router)
app.include_router(process_router)


@app.get("/")
def root():
    return {"service": "ibalance-backend", "status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}
