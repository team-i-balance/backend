"""Shared fixtures. Each test module gets an isolated DB and keys dir.

The logging modules read LOG_DB_PATH / LOG_KEYS_DIR / LOG_EXPORT_DIR at import
time, so we set them before anything under app/ is imported.
"""
import importlib
import os
import sys
from pathlib import Path

import pytest

# Some xlsx tests import sibling test modules directly
# (e.g. `from test_xlsx_value_integrity import ...`). Because tests/ is a
# package, pytest does not add this directory to sys.path, so make it
# importable here. Harmless for the other tests.
_TESTS_DIR = str(Path(__file__).resolve().parent)
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

# Tests run with auth bypassed (AUTH_DISABLED=1) so the suite doesn't need to
# thread tokens through every call, including subprocess-spawned TestClients
# (os.environ is inherited). Production never sets this. The auth-enforcement
# tests (anon_client) turn it back off to verify 401/403 behaviour.
os.environ.setdefault("AUTH_DISABLED", "1")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A TestClient backed by a fresh SQLite DB and temp key/export dirs."""
    monkeypatch.setenv("LOG_DB_PATH", str(tmp_path / "events.db"))
    monkeypatch.setenv("LOG_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("LOG_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.setenv("POLICY_KEYS_DIR", str(tmp_path / "policy_keys"))
    monkeypatch.setenv("POLICY_DB_PATH", str(tmp_path / "policy.db"))

    # Drop any already-imported app/main modules so they re-read env vars.
    for name in list(sys.modules):
        if name == "main" or name == "app" or name.startswith("app."):
            del sys.modules[name]

    from fastapi.testclient import TestClient
    import main
    import app.auth as auth

    importlib.reload(main)
    # Auth is always enforced. Give the default client a security token (which
    # also satisfies api-scope routes) so existing tests keep working. Tests
    # that exercise auth itself use the `anon_client` fixture below.
    token = auth.issue_token("security")
    with TestClient(main.app) as c:
        c.headers.update({"Authorization": f"Bearer {token}"})
        yield c


@pytest.fixture()
def anon_client(tmp_path, monkeypatch):
    """A TestClient with NO auth header, for testing auth enforcement."""
    monkeypatch.setenv("LOG_DB_PATH", str(tmp_path / "events.db"))
    monkeypatch.setenv("LOG_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("LOG_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.setenv("POLICY_KEYS_DIR", str(tmp_path / "policy_keys"))

    for name in list(sys.modules):
        if name == "main" or name == "app" or name.startswith("app."):
            del sys.modules[name]

    # Enforce auth for the enforcement tests (undo the session-wide bypass).
    monkeypatch.setenv("AUTH_DISABLED", "0")

    from fastapi.testclient import TestClient
    import main

    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c
