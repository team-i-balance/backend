"""Company-confidential + unstructured PII span detection with a local SLM.

The model (fine-tuned GLiNER, team-i-balance/slm) finds which spans match which
policy rule. Grades come from the policy, not the model: a rule's ``grade`` (S/C)
decides the detection type below, and app/grading.py turns types into O/S/C.

Detection types produced here:
  NAME, ADDRESS   fixed PII labels (grade S)
  SENSITIVE       fixed label for a person's health, discipline, religion... (grade C)
  CONFIDENTIAL    policy rule with grade C
  INTERNAL        policy rule with grade S

Model files are never downloaded at runtime; pass a local folder.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).parent
FIXED_TYPES = {"P-NAME": "NAME", "P-ADDR": "ADDRESS", "P-SENS": "SENSITIVE"}
RULE_TYPES = {"C": "CONFIDENTIAL", "S": "INTERNAL"}
# Thresholds picked on the SLM eval set (team-i-balance/slm README, v2).
DEFAULT_THRESHOLDS = {"CONFIDENTIAL": 0.45, "INTERNAL": 0.45, "NAME": 0.35, "ADDRESS": 0.35, "SENSITIVE": 0.35}
# When spans of different types overlap, the higher one absorbs the other. Secrets stay on top so
# they keep grade C and their no-restore rule; grade-C SLM types come next; unknown types last.
PRIORITY = ["PASSWORD", "API_KEY", "ACCESS_TOKEN", "CONFIDENTIAL", "SENSITIVE", "INTERNAL", "ADDRESS", "NAME"]


def _rank(kind: str) -> int:
    return PRIORITY.index(kind) if kind in PRIORITY else len(PRIORITY)
CHUNK_WORDS = 200
# Overlap between windows when one sentence alone exceeds CHUNK_WORDS.
CHUNK_OVERLAP = 20
_SENT_END = re.compile(r"(?<=[.!?。])\s+|\n+")


def load_policy(path: str | Path) -> list[dict]:
    """Policy JSON: {"rules": [{"id", "label", "description", "grade": "S"|"C", "action"}]}."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = data["rules"] if isinstance(data, dict) else data
    for r in rules:
        if r.get("grade") not in RULE_TYPES or not r.get("label") or not r.get("id"):
            raise ValueError("invalid policy rule")
    return [r for r in rules if not r["id"].startswith("P-")]


class SlmSpanDetector:
    def __init__(self, model_dir: str | Path, policy: str | Path | None = None, thresholds: dict | None = None):
        from gliner import GLiNER

        from .splitter import EojeolSplitter
        path = Path(model_dir).expanduser()
        if not (path / "gliner_config.json").is_file():
            raise FileNotFoundError("SLM model folder with gliner_config.json is required")
        self.model = GLiNER.from_pretrained(str(path), local_files_only=True, map_location="cpu")
        self.model.data_processor.words_splitter = EojeolSplitter()
        self.splitter = EojeolSplitter()
        self.thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.fixed = json.loads((HERE / "fixed_labels.json").read_text(encoding="utf-8"))["labels"]
        self.set_policy(load_policy(policy or HERE / "policy.example.json"))

    def set_policy(self, rules: list[dict]) -> None:
        """Swap policy rules; new rules apply without retraining.

        The model returns labels, so each label must map to exactly one rule: a duplicate
        label (or one reusing a fixed label) would silently re-grade detections.
        """
        all_rules = list(self.fixed) + list(rules)
        label2id: dict[str, str] = {}
        ids: set[str] = set()
        for r in all_rules:
            if r["label"] in label2id or r["id"] in ids:
                raise ValueError("policy rule labels and ids must be unique and not reuse fixed labels")
            label2id[r["label"]] = r["id"]
            ids.add(r["id"])
        self.rules = {r["id"]: r for r in all_rules}
        self.label2id = label2id

    def _type(self, rule_id: str) -> str:
        return FIXED_TYPES.get(rule_id) or RULE_TYPES[self.rules[rule_id]["grade"]]

    def _chunks(self, text: str):
        pieces, pos = [], 0
        for m in _SENT_END.finditer(text):
            pieces.extend(self._split_long(pos, text[pos:m.start()]))
            pos = m.end()
        pieces.extend(self._split_long(pos, text[pos:]))
        out, cur, end, n = [], None, 0, 0
        for st, p in pieces:
            w = sum(1 for _ in self.splitter(p))
            if cur is not None and n + w > CHUNK_WORDS:
                out.append((cur, text[cur:end]))
                cur, n = None, 0
            if cur is None:
                cur = st
            end, n = st + len(p), n + w
        if cur is not None:
            out.append((cur, text[cur:end]))
        return [(st, c) for st, c in out if c.strip()]

    def _split_long(self, offset: int, piece: str):
        """A sentence longer than CHUNK_WORDS becomes overlapping windows at word boundaries."""
        words = list(self.splitter(piece))
        if len(words) <= CHUNK_WORDS:
            return [(offset, piece)]
        out, step = [], CHUNK_WORDS - CHUNK_OVERLAP
        for i in range(0, len(words), step):
            w = words[i:i + CHUNK_WORDS]
            out.append((offset + w[0][1], piece[w[0][1]:w[-1][2]]))
            if i + CHUNK_WORDS >= len(words):
                break
        return out

    def detect(self, text: str) -> list[dict]:
        """Non-overlapping spans: {start, end, type, rule_id, score}."""
        raw = []
        low = min(self.thresholds.values())
        for off, chunk in self._chunks(text):
            for e in self.model.predict_entities(chunk, list(self.label2id), threshold=low,
                                                 flat_ner=False, multi_label=True):
                rid = self.label2id[e["label"]]
                kind = self._type(rid)
                if e["score"] >= self.thresholds[kind]:
                    raw.append({"start": off + e["start"], "end": off + e["end"], "type": kind,
                                "rule_id": rid, "score": round(float(e["score"]), 3)})
        return resolve_overlaps(raw)


def resolve_overlaps(spans: list[dict]) -> list[dict]:
    """Keep spans non-overlapping: higher-priority (then longer) spans absorb overlapping ones."""
    order = sorted(spans, key=lambda s: (_rank(s["type"]), -(s["end"] - s["start"]), s["start"]))
    kept: list[dict] = []
    for s in order:
        hit = [k for k in kept if k["start"] < s["end"] and s["start"] < k["end"]]
        if not hit:
            kept.append(dict(s))
            continue
        # Extend the strongest overlapping span so nothing the SLM flagged is left uncovered.
        k = hit[0]
        k["start"], k["end"] = min(k["start"], s["start"]), max(k["end"], s["end"])
    # Extensions may create new overlaps; merge until stable.
    kept.sort(key=lambda s: (s["start"], s["end"]))
    merged: list[dict] = []
    for s in kept:
        if merged and s["start"] < merged[-1]["end"]:
            m = merged[-1]
            top = m if _rank(m["type"]) <= _rank(s["type"]) else s
            merged[-1] = {**top, "start": m["start"], "end": max(m["end"], s["end"])}
        else:
            merged.append(s)
    return merged


def subtract(span: dict, blockers: list[dict]) -> list[dict]:
    """Parts of ``span`` not covered by ``blockers`` (rule-engine spans win), trimmed of spaces."""
    parts = [(span["start"], span["end"])]
    for b in blockers:
        nxt = []
        for s, e in parts:
            if b["end"] <= s or e <= b["start"]:
                nxt.append((s, e))
                continue
            if s < b["start"]:
                nxt.append((s, b["start"]))
            if b["end"] < e:
                nxt.append((b["end"], e))
        parts = nxt
    return [{**span, "start": s, "end": e} for s, e in parts if e > s]
