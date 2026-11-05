#!/usr/bin/env python3
"""Compare current local rules with candidate business/API-secret rules.

This is an offline experiment: it does not modify the backend detector, write
source text or detected values to the report, or attempt to contact any host.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import socket
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from local_ai.detector import Detector  # noqa: E402


# The candidate assignment rule recognizes common secret-field names, including
# provider prefixes. Captured spans are values only; key names are not replaced.
_CANDIDATE_FIELD = re.compile(
    r"(?i)(?<![\w])['\"]?(?P<field>(?:[A-Za-z][A-Za-z0-9_-]*[_-])?"
    r"(?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token|token))['\"]?"
    r"\s*[:=]\s*(?:\"(?P<double>[^\"\r\n]+)\"|"
    r"'(?P<single>[^'\r\n]+)'|(?P<bare>[^\s,;\]\[\}\{\"']+))"
)
_CANDIDATE_PROVIDER = re.compile(
    r"(?<![\w])(?:SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"AIza[A-Za-z0-9_-]{20,}|SK[0-9a-fA-F]{32})(?![\w-])"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:\[[^\[\]\r\n]+_\d+\]|\$\{[^}]+\}|\$[A-Za-z_][\w]*|"
    r"\{\{[^}]+\}\}|<[^>]+>|(?:your[-_ ]?)?(?:api[-_ ]?key|token)|"
    r"change[-_ ]?me|placeholder|dummy|example|none|null)$"
)
_BUSINESS_HYPHEN = re.compile(r"(?<![0-9])\d{3}-\d{2}-\d{5}(?![0-9])")
_BUSINESS_PLAIN = re.compile(r"(?<![0-9])\d{10}(?![0-9])")
_BUSINESS_CONTEXT = re.compile(
    r"(?:사업자\s*(?:등록)?\s*번호|business\s*(?:registration\s*)?(?:number|no))",
    re.I,
)


def _candidate_spans(text: str) -> list[dict]:
    """Return conservative candidates that are kept separate from production."""
    found: list[dict] = []

    # Hyphenated 3-2-5 values are high-recall candidates, even when their
    # checksum is invalid. Plain 10-digit values require a nearby label.
    for match in _BUSINESS_HYPHEN.finditer(text):
        found.append({"start": match.start(), "end": match.end(), "type": "BUSINESS_NUMBER"})
    for match in _BUSINESS_PLAIN.finditer(text):
        same_line = text[max(0, text.rfind("\n", 0, match.start()) + 1):match.start()]
        if _BUSINESS_CONTEXT.search(same_line[-80:]):
            found.append({"start": match.start(), "end": match.end(), "type": "BUSINESS_NUMBER"})

    for match in _CANDIDATE_FIELD.finditer(text):
        group = next((name for name in ("double", "single", "bare") if match.group(name) is not None), None)
        if group is None:
            continue
        value = match.group(group).strip()
        # Ignore unresolved template references and obvious documentation values.
        if not value or _PLACEHOLDER.fullmatch(value) or value.startswith(("${", "{{", "$")):
            continue
        kind = "ACCESS_TOKEN" if "token" in match.group("field").lower() else "API_KEY"
        found.append({"start": match.start(group), "end": match.end(group), "type": kind})

    for match in _CANDIDATE_PROVIDER.finditer(text):
        found.append({"start": match.start(), "end": match.end(), "type": "API_KEY"})
    return _merge_same_type(found)


def _merge_same_type(spans: list[dict]) -> list[dict]:
    by_type: dict[str, list[dict]] = collections.defaultdict(list)
    for span in spans:
        by_type[span["type"]].append(span)
    merged_all = []
    for kind, items in by_type.items():
        items.sort(key=lambda item: (item["start"], item["end"]))
        merged = []
        for span in items:
            if merged and span["start"] < merged[-1]["end"]:
                merged[-1]["end"] = max(merged[-1]["end"], span["end"])
            else:
                merged.append(dict(span))
        merged_all.extend(merged)
    return merged_all


def _union(base: list[dict], candidate: list[dict]) -> list[dict]:
    return _merge_same_type(base + candidate)


def _candidate_pipeline(text: str, base: list[dict], candidate: list[dict]) -> list[dict]:
    """Use shape/context business candidates and filter obvious secret placeholders."""
    retained = []
    for span in base:
        if span["type"] == "BUSINESS_NUMBER":
            continue
        if span["type"] in {"API_KEY", "ACCESS_TOKEN"}:
            value = text[span["start"]:span["end"]].strip()
            if not value or value.startswith(("$", "${", "{{")) or _PLACEHOLDER.fullmatch(value):
                continue
        retained.append(span)
    return _union(retained, candidate)


def _fully_covered(start: int, end: int, spans: list[dict], allowed: set[str]) -> bool:
    selected = sorted((max(start, s["start"]), min(end, s["end"]))
                      for s in spans if s["type"] in allowed and s["start"] < end and start < s["end"])
    cursor = start
    for left, right in selected:
        if left > cursor:
            return False
        cursor = max(cursor, right)
        if cursor >= end:
            return True
    return cursor >= end


TYPE_MAP = {
    "business_registration_id": {"BUSINESS_NUMBER"},
    "api_key": {"API_KEY", "ACCESS_TOKEN"},
}

# Safe synthetic tests. Values are fabricated and intentionally nonfunctional.
FIXTURES = {
    "positive_business_hyphen_invalid_checksum": ("사업자등록번호: 123-45-67890", True, "BUSINESS_NUMBER"),
    "positive_business_plain_context": ("사업자번호=1234567890", True, "BUSINESS_NUMBER"),
    "negative_business_unlabeled_number": ("회의 코드 1234567890", False, "BUSINESS_NUMBER"),
    "positive_api_environment_assignment": ("GENERIC_API_KEY=Zx91Qm72Lp44Vb83Nd65Rt20Kf11", True, "API_KEY"),
    "positive_bearer_assignment": ("Authorization: Bearer Tkn_91Qm72Lp44Vb83Nd65Rt20Kf11", True, "ACCESS_TOKEN"),
    "negative_api_shell_placeholder": ("API_KEY=${TOKEN}", False, "API_KEY"),
    "negative_api_variable_placeholder": ("access_token=$SERVICE_TOKEN", False, "ACCESS_TOKEN"),
    "negative_api_angle_placeholder": ("api_key=<your-api-key>", False, "API_KEY"),
    "negative_api_pseudonym": ("api_key=[API키_1]", False, "API_KEY"),
    "negative_normal_prose": ("API 키와 사업자번호 처리 방법을 설명한다", False, "API_KEY"),
}


def _fixture_result(detector: Detector) -> dict:
    results = {}
    failures = []
    for name, (text, expected, kind) in FIXTURES.items():
        spans = _candidate_pipeline(text, detector.detect(text), _candidate_spans(text))
        detected = any(s["type"] == kind for s in spans)
        results[name] = {"expected_detection": expected, "detected": detected,
                         "pass": detected == expected}
        if detected != expected:
            failures.append(name)
    return {"cases": results, "passed": len(results) - len(failures),
            "total": len(results), "failures": failures}


def _validate_unique_basenames(datasets: list[Path]) -> list[Path]:
    """Reject duplicate names because report keys use each dataset basename."""
    datasets = [Path(path) for path in datasets]
    names = [path.name for path in datasets]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError("Dataset filenames must be unique; duplicate basename(s): " + ", ".join(duplicates))
    return datasets


def run(datasets: list[Path]) -> dict:
    datasets = _validate_unique_basenames(datasets)
    missing = [str(path) for path in datasets if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"evaluation dataset not found: {', '.join(missing)}")

    # Block Python socket entry points in this runner. This is a guard, not proof
    # that every native dependency is incapable of networking.
    def blocked(*_args, **_kwargs):
        raise RuntimeError("network disabled by evaluation runner")
    socket.socket.connect = blocked
    socket.create_connection = blocked
    detector = Detector(None)  # deterministic rules-only comparison
    rows_by_file = {
        path.name: [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        for path in datasets
    }
    stats = {
        "business_registration_id": collections.Counter(),
        "api_key": collections.Counter(),
    }
    groups: dict[str, dict[str, collections.Counter]] = collections.defaultdict(
        lambda: {key: collections.Counter() for key in stats}
    )
    no_annotation_docs = collections.Counter()

    for filename, rows in rows_by_file.items():
        for row in rows:
            text = row["text"]
            gold = row.get("annotations", [])
            baseline = detector.detect(text)
            candidate = _candidate_spans(text)
            combined = _candidate_pipeline(text, baseline, candidate)
            group = f"{filename}: {row.get('source', {}).get('repo', 'unknown')} / {row.get('source', {}).get('split', 'unknown')}"
            if row.get("sampled_for") == "negative":
                no_annotation_docs["documents"] += 1
                no_annotation_docs["baseline_with_any_secret_candidate"] += any(
                    s["type"] in {"API_KEY", "ACCESS_TOKEN"} for s in baseline
                )
                no_annotation_docs["candidate_with_any_secret_candidate"] += any(
                    s["type"] in {"API_KEY", "ACCESS_TOKEN"} for s in combined
                )
            for annotation in gold:
                label = annotation.get("label")
                if label not in TYPE_MAP:
                    continue
                start, end = annotation["start"], annotation["end"]
                allowed = TYPE_MAP[label]
                for name, spans in (("baseline", baseline), ("candidate_only", candidate), ("combined", combined)):
                    hit = _fully_covered(start, end, spans, allowed)
                    stats[label][f"{name}_full_typed"] += hit
                    groups[group][label][f"{name}_full_typed"] += hit
                stats[label]["gold_spans"] += 1
                groups[group][label]["gold_spans"] += 1

    for counter in stats.values():
        for key in ("baseline_full_typed", "candidate_only_full_typed", "combined_full_typed", "gold_spans"):
            counter[key] = int(counter[key])
    return {
        "title": "Business/API candidate rule evaluation",
        "datasets": {path.name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                  "documents": len(rows_by_file[path.name])}
                      for path in datasets},
        "dataset_license": {"korean_pii_cc_by.jsonl": "CC-BY-4.0",
                             "secrets_noncommercial.jsonl": "CC-BY-NC-4.0; non-commercial use only unless rights are confirmed"},
        "documents": sum(map(len, rows_by_file.values())),
        "scope": "rules-only detector plus candidate overlay; no production files changed",
        "definition": "A gold span counts as detected only when the allowed type covers every gold character.",
        "metrics": {label: dict(counter) for label, counter in stats.items()},
        "by_source_split": {
            group: {label: dict(counter) for label, counter in data.items() if counter["gold_spans"]}
            for group, data in groups.items()
        },
        "unannotated_secret_examples": dict(no_annotation_docs),
        "synthetic_regression_fixtures": _fixture_result(detector),
        "network_guard": "Python socket connect/create_connection blocked; native dependency network behavior not proven",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--korean-dataset", type=Path, required=True,
                        help="Path to korean_pii_cc_by.jsonl (CC BY 4.0)")
    parser.add_argument("--secrets-dataset", type=Path, required=True,
                        help="Path to secrets_noncommercial.jsonl (CC BY-NC 4.0)")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "candidate_results.json")
    args = parser.parse_args()
    result = run([args.korean_dataset, args.secrets_dataset])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "metrics": result["metrics"],
        "unannotated_secret_examples": result["unannotated_secret_examples"],
        "fixtures": {"passed": result["synthetic_regression_fixtures"]["passed"],
                     "total": result["synthetic_regression_fixtures"]["total"],
                     "failures": result["synthetic_regression_fixtures"]["failures"]},
    }, ensure_ascii=False, indent=2))
    return 0 if not result["synthetic_regression_fixtures"]["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
