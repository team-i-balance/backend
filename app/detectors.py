"""Shared lazy detector loading; each caller still owns its LocalSession."""
import os
import threading

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


def reset_detectors() -> None:
    """Drop cached detectors, primarily for isolated tests."""
    with _lock:
        _detectors.clear()
