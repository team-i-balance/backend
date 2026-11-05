"""Shared lazy detector loading; each caller still owns its LocalSession."""
import os
import threading

MODEL_DIR_ENV = "LOCAL_PII_MODEL_DIR"
_detectors: dict[bool, object] = {}
_lock = threading.Lock()


class MissingModelConfiguration(RuntimeError):
    pass


def get_detector(rules_only: bool = False):
    from local_ai.detector import Detector

    with _lock:
        if rules_only not in _detectors:
            model_dir = None if rules_only else os.getenv(MODEL_DIR_ENV)
            if not rules_only and not model_dir:
                raise MissingModelConfiguration(MODEL_DIR_ENV)
            _detectors[rules_only] = Detector(model_dir)
        return _detectors[rules_only]


def reset_detectors() -> None:
    """Drop cached detectors, primarily for isolated tests."""
    with _lock:
        _detectors.clear()
