from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI(title="iBalance Backend", version="0.1.0")

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


@app.get("/")
def root():
    return {"service": "ibalance-backend", "status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}
