"""Importing the local AI modules must switch off telemetry and model downloads (#13).

Each check runs in a fresh interpreter: the variables only work when they are set before
onnxruntime / gliner / transformers / huggingface_hub are imported, so an already-warm
test process would prove nothing.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HF_VARS = ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY")
WATCHED = ("ORT_DISABLE_TELEMETRY",) + HF_VARS


def _run(code: str, **env_overrides: str) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in WATCHED}
    env.update(env_overrides)
    env["PYTHONPATH"] = str(ROOT)
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


_REPORT = "import json, os, sys; print(json.dumps({'env': {k: os.environ.get(k) for k in %r}, " \
          "'ort': 'onnxruntime' in sys.modules}))" % (WATCHED,)


def test_detector_import_disables_ort_telemetry_before_onnxruntime():
    got = _run("import local_ai.detector\n" + _REPORT)
    assert got["env"]["ORT_DISABLE_TELEMETRY"] == "1"
    # The variable must be in place before onnxruntime loads; importing the module must not load it.
    assert got["ort"] is False


def test_detector_import_keeps_explicit_ort_setting():
    got = _run("import local_ai.detector\n" + _REPORT, ORT_DISABLE_TELEMETRY="0")
    assert got["env"]["ORT_DISABLE_TELEMETRY"] == "0"


def test_slm_import_sets_hf_offline_without_gliner():
    # sys.modules[name] = None makes any later `import gliner` raise ImportError.
    code = "import sys\nfor m in ('gliner', 'transformers', 'huggingface_hub'): sys.modules[m] = None\n" \
           "import local_ai.slm\n" + _REPORT
    got = _run(code)
    assert all(got["env"][k] == "1" for k in HF_VARS), got


def test_slm_import_keeps_explicit_hf_setting():
    got = _run("import local_ai.slm\n" + _REPORT, HF_HUB_OFFLINE="0")
    assert got["env"]["HF_HUB_OFFLINE"] == "0"
    assert got["env"]["TRANSFORMERS_OFFLINE"] == "1"
