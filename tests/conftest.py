"""Shared fixtures. Each test module gets an isolated DB and keys dir.

The logging modules read LOG_DB_PATH / LOG_KEYS_DIR / LOG_EXPORT_DIR at import
time, so we set them before anything under app/ is imported.
"""
import importlib
import os
import sys

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A TestClient backed by a fresh SQLite DB and temp key/export dirs."""
    monkeypatch.setenv("LOG_DB_PATH", str(tmp_path / "events.db"))
    monkeypatch.setenv("LOG_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("LOG_EXPORT_DIR", str(tmp_path / "exports"))

    # Drop any already-imported app/main modules so they re-read env vars.
    for name in list(sys.modules):
        if name == "main" or name == "app" or name.startswith("app."):
            del sys.modules[name]

    from fastapi.testclient import TestClient
    import main

    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c
