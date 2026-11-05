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

import hashlib
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


def _auth_disabled() -> bool:
    """Test/dev bypass. When AUTH_DISABLED=1, all auth checks pass.

    Production never sets this, so enforcement stays on there.
    """
    return os.getenv("AUTH_DISABLED", "") in ("1", "true", "True")


def _token_from(creds: HTTPAuthorizationCredentials | None) -> str:
    if creds is None or (creds.scheme or "").lower() != "bearer" or not creds.credentials:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return creds.credentials


def require_api(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> None:
    """Allow api OR security tokens."""
    if _auth_disabled():
        return
    token = _token_from(creds)
    if token in _valid_api_tokens() or token in _valid_security_tokens():
        return
    raise HTTPException(status_code=401, detail="invalid token")


def require_security(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> None:
    """Allow only security tokens.

    401 if the token is not recognized at all; 403 if it is a valid api token
    that simply lacks security scope.
    """
    if _auth_disabled():
        return
    token = _token_from(creds)
    if token in _valid_security_tokens():
        return
    if token in _valid_api_tokens():
        raise HTTPException(status_code=403, detail="security token required")
    raise HTTPException(status_code=401, detail="invalid token")





def token_label(token: str) -> str:
    """Stable, non-reversible per-token label: first 12 hex of SHA-256.

    Used wherever a principal must be recorded (e.g. case history `by`).
    The raw token is never stored or logged.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def security_principal(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    """Principal of the verified security token, for audit records.

    Returns "security:<sha256 prefix>" for env-configured SECURITY_TOKENS and
    "security-dev:<sha256 prefix>" for runtime-issued dev tokens. Never returns
    the raw token. Under AUTH_DISABLED without a valid security token it returns
    "auth-disabled" so records made by the test/dev bypass are distinguishable.
    """
    token = None
    if creds is not None and (creds.scheme or "").lower() == "bearer" and creds.credentials:
        token = creds.credentials
    if token is not None:
        if token in _env_tokens("SECURITY_TOKENS"):
            return f"security:{token_label(token)}"
        with _lock:
            issued = token in _issued["security"]
        if issued:
            return f"security-dev:{token_label(token)}"
    if _auth_disabled():
        return "auth-disabled"
    # Callers must already be behind require_security; fail closed otherwise.
    raise HTTPException(status_code=401, detail="invalid token")
