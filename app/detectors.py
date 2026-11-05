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


class MissingModelConfiguration(RuntimeError):
    pass


def get_detector(rules_only: bool = False):
    from local_ai.detector import Detector

    with _lock:
        if rules_only not in _detectors:
            model_dir = None if rules_only else os.getenv(MODEL_DIR_ENV)
            slm_dir = None if rules_only else os.getenv(SLM_DIR_ENV)
            if not rules_only and not model_dir and not slm_dir:
                raise MissingModelConfiguration(MODEL_DIR_ENV)
            if slm_dir:
                _detectors[rules_only] = Detector(model_dir or None, slm_dir=slm_dir,
                                                  slm_policy=os.getenv(SLM_POLICY_ENV) or None)
            else:
                _detectors[rules_only] = Detector(model_dir)
        return _detectors[rules_only]


def warm_up_in_background() -> threading.Thread | None:
    """Load the full detector (and run one fixed sentence) at startup when a model is configured.

    Loading the SLM takes several seconds, which otherwise lands on the first user request after
    every deploy. Runs in a daemon thread so startup and /health stay fast; requests arriving
    meanwhile wait on the same lock and reuse the loaded detector. Failures are only logged:
    requests still report MODEL_UNAVAILABLE / 422 exactly as before.
    """
    if not os.getenv(MODEL_DIR_ENV) and not os.getenv(SLM_DIR_ENV):
        return None

    def run():
        try:
            get_detector(False).detect("모델 예열용 고정 문장입니다.")
            log.info("detector warm-up finished")
        except Exception:
            # Never include exception text: it could carry paths or model details.
            log.warning("detector warm-up failed; it will be retried on the first request")
            reset_detectors()

    thread = threading.Thread(target=run, name="detector-warm-up", daemon=True)
    thread.start()
    return thread


def reset_detectors() -> None:
    """Drop cached detectors, primarily for isolated tests."""
    with _lock:
        _detectors.clear()
