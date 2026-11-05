"""Startup warm-up of the shared detector (app/detectors.py)."""
import app.detectors as detectors


def test_no_model_configured_skips_warm_up(monkeypatch):
    monkeypatch.delenv("LOCAL_PII_MODEL_DIR", raising=False)
    monkeypatch.delenv("LOCAL_SLM_MODEL_DIR", raising=False)
    assert detectors.warm_up_in_background() is None


import threading


def test_warm_up_publishes_only_after_inference(monkeypatch):
    detectors.reset_detectors()
    started, release = threading.Event(), threading.Event()

    class Fake:
        calls = 0

        def detect(self, text):
            Fake.calls += 1
            started.set()
            release.wait(5)
            return []

    monkeypatch.setenv("LOCAL_SLM_MODEL_DIR", "/models/slm")
    monkeypatch.setattr(detectors, "_build", lambda rules_only: Fake())
    t = detectors.warm_up_in_background()
    started.wait(5)
    # A request during warm-up waits instead of getting the cold detector.
    got = []
    req = threading.Thread(target=lambda: got.append(detectors.get_detector(False)))
    req.start()
    req.join(0.3)
    assert got == [] and req.is_alive()
    release.set()
    t.join(5)
    req.join(5)
    assert isinstance(got[0], Fake) and Fake.calls == 1
    detectors.reset_detectors()


def test_warm_up_failure_is_swallowed_and_requests_proceed(monkeypatch):
    detectors.reset_detectors()

    def boom(rules_only):
        raise RuntimeError("secret /private/path")

    monkeypatch.setenv("LOCAL_SLM_MODEL_DIR", "/models/slm")
    monkeypatch.setattr(detectors, "_build", boom)
    detectors.warm_up_in_background().join(5)
    assert detectors._warm_done.is_set()
    assert False not in detectors._detectors
