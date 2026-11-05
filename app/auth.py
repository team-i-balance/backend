"""Bearer-token authentication for the API (issue #10).

Two scopes:
  - "api"      : write / processing endpoints (/process*, /files/*,
                 POST /logs/events). A security token also satisfies this.
  - "security" : read / export / policy-write endpoints
                 (GET /logs/*, POST /logs/export, /policy/deploy|publish|ack|
                 model/publish). Only a security token satisfies this.

Tokens come from:
  - env API_TOKENS / SECURITY_TOKENS (comma-separated), and
  - tokens issued at runtime via POST /auth/dev-token (the "skip" button):
    these are kept in memory and honored until the process restarts.

Auth is always enforced: a request without a valid token for the required
scope gets 401. The dev-token endpoint exists so a client can quickly obtain a
working token when it just wants to skip manual provisioning; it can be turned
off in production with DISABLE_DEV_TOKEN=1.
"""
from __future__ import annotations

import os
import secrets
import threading

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)
_lock = threading.Lock()
# Tokens issued at runtime (dev-token). scope -> set of tokens.
_issued: dict[str, set[str]] = {"api": set(), "security": set()}


def _env_tokens(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {t.strip() for t in raw.split(",") if t.strip()}


def _valid_api_tokens() -> set[str]:
    with _lock:
        return _env_tokens("API_TOKENS") | _issued["api"]


def _valid_security_tokens() -> set[str]:
    with _lock:
        return _env_tokens("SECURITY_TOKENS") | _issued["security"]


def issue_token(scope: str) -> str:
    """Create and register a new token for the given scope ("api"/"security")."""
    if scope not in ("api", "security"):
        raise ValueError("scope must be 'api' or 'security'")
    token = secrets.token_urlsafe(32)
    with _lock:
        _issued[scope].add(token)
    return token


def dev_token_enabled() -> bool:
    return os.getenv("DISABLE_DEV_TOKEN", "") not in ("1", "true", "True")


def _token_from(creds: HTTPAuthorizationCredentials | None) -> str:
    if creds is None or (creds.scheme or "").lower() != "bearer" or not creds.credentials:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return creds.credentials


def require_api(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> None:
    """Allow api OR security tokens."""
    token = _token_from(creds)
    if token in _valid_api_tokens() or token in _valid_security_tokens():
        return
    raise HTTPException(status_code=401, detail="invalid token")


def require_security(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> None:
    """Allow only security tokens.

    401 if the token is not recognized at all; 403 if it is a valid api token
    that simply lacks security scope.
    """
    token = _token_from(creds)
    if token in _valid_security_tokens():
        return
    if token in _valid_api_tokens():
        raise HTTPException(status_code=403, detail="security token required")
    raise HTTPException(status_code=401, detail="invalid token")



