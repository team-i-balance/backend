"""Shared lazy detector loading; each caller still owns its LocalSession."""
import logging
import os
import threading

log = logging.getLogger(__name__)

MODEL_DIR_ENV = "LOCAL_PII_MODEL_DIR"
# Optional confidential-policy SLM (local_ai/slm) folder and policy JSON. Either model
# enables full detection for both the text API and file sanitizing.
SLM_DIR_ENV = "LOCAL_SLM_MODEL_DIR"
SLM_POLICY_ENV = "LOCAL_SLM_POLICY"
_detectors: dict[bool, object] = {}
_lock = threading.Lock()
# Cleared while the startup warm-up runs; full-detection callers wait on it so they reuse the
# warmed detector instead of running cold inference alongside the warm-up.
_warm_done = threading.Event()
_warm_done.set()
WARM_WAIT_SECONDS = 120


class MissingModelConfiguration(RuntimeError):
    pass


def _build(rules_only: bool):
    from local_ai.detector import Detector

    model_dir = None if rules_only else os.getenv(MODEL_DIR_ENV)
    slm_dir = None if rules_only else os.getenv(SLM_DIR_ENV)
    if not rules_only and not model_dir and not slm_dir:
        raise MissingModelConfiguration(MODEL_DIR_ENV)
    if slm_dir:
        return Detector(model_dir or None, slm_dir=slm_dir, slm_policy=os.getenv(SLM_POLICY_ENV) or None)
    return Detector(model_dir)


def get_detector(rules_only: bool = False):
    if not rules_only:
        # If the warm-up fails or exceeds the wait, fall through and build here as before.
        _warm_done.wait(WARM_WAIT_SECONDS)
    with _lock:
        if rules_only not in _detectors:
            _detectors[rules_only] = _build(rules_only)
        return _detectors[rules_only]


def warm_up_in_background() -> threading.Thread | None:
    """Load the full detector (and run one fixed sentence) at startup when a model is configured.

    Loading the SLM takes several seconds, which otherwise lands on the first user request after
    every deploy. Runs in a daemon thread so startup and /health stay fast; full-detection
    requests arriving meanwhile wait (up to WARM_WAIT_SECONDS) and reuse the warmed detector.
    Failures are only logged: requests then build the detector themselves and report
    MODEL_UNAVAILABLE / 422 exactly as before.
    """
    if not os.getenv(MODEL_DIR_ENV) and not os.getenv(SLM_DIR_ENV):
        return None
    _warm_done.clear()

    def run():
        try:
            detector = _build(False)
            detector.detect("모델 예열용 고정 문장입니다.")
            # Publish only after the warm-up inference, so no caller sees a cold detector.
            with _lock:
                _detectors.setdefault(False, detector)
            log.info("detector warm-up finished")
        except Exception:
            # Never include exception text: it could carry paths or model details.
            log.warning("detector warm-up failed; it will be retried on the first request")
        finally:
            _warm_done.set()

    thread = threading.Thread(target=run, name="detector-warm-up", daemon=True)
    thread.start()
    return thread


def reset_detectors() -> None:
    """Drop cached detectors, primarily for isolated tests."""
    with _lock:
        _detectors.clear()
