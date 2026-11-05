"""Startup warm-up of the shared detector (app/detectors.py)."""
import app.detectors as detectors


def test_no_model_configured_skips_warm_up(monkeypatch):
    monkeypatch.delenv("LOCAL_PII_MODEL_DIR", raising=False)
    monkeypatch.delenv("LOCAL_SLM_MODEL_DIR", raising=False)
    assert detectors.warm_up_in_background() is None


def test_warm_up_loads_and_runs_once(monkeypatch):
    calls = []

    class Fake:
        def detect(self, text):
            calls.append(text)
            return []

    monkeypatch.setenv("LOCAL_SLM_MODEL_DIR", "/models/slm")
    monkeypatch.setattr(detectors, "get_detector", lambda rules_only=False: Fake())
    detectors.warm_up_in_background().join(5)
    assert len(calls) == 1


def test_warm_up_failure_is_swallowed_and_cache_reset(monkeypatch):
    reset = []

    def boom(rules_only=False):
        raise RuntimeError("secret /private/path")

    monkeypatch.setenv("LOCAL_SLM_MODEL_DIR", "/models/slm")
    monkeypatch.setattr(detectors, "get_detector", boom)
    monkeypatch.setattr(detectors, "reset_detectors", lambda: reset.append(True))
    detectors.warm_up_in_background().join(5)
    assert reset == [True]
