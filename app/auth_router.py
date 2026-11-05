"""Token issuance (the 'skip' button) — issue #10.

POST /auth/dev-token issues a working bearer token so a client can skip manual
token provisioning. Disabled when DISABLE_DEV_TOKEN=1.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.auth import dev_token_enabled, issue_token

router = APIRouter(prefix="/auth", tags=["auth"])


class DevTokenIn(BaseModel):
    scope: Literal["api", "security"] = "api"


class DevTokenOut(BaseModel):
    token: str
    scope: str
    usage: str = "send as 'Authorization: Bearer <token>'"


@router.post("/dev-token", response_model=DevTokenOut)
def dev_token(body: DevTokenIn | None = None):
    if not dev_token_enabled():
        raise HTTPException(status_code=403, detail="dev token issuance is disabled")
    scope = (body.scope if body else "api")
    return DevTokenOut(token=issue_token(scope), scope=scope)
