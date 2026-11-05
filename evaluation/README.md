# Business number and API key rule evaluation

This is an offline experiment for comparing the current local rules with candidate detection rules. It does not change or import the candidate rules into the production detector. The datasets are not included in this repository; pass their paths explicitly.

## Run

```bash
python evaluation/evaluate_secret_rule_candidates.py \
  --korean-dataset /path/to/korean_pii_cc_by.jsonl \
  --secrets-dataset /path/to/secrets_noncommercial.jsonl
```

The output defaults to `evaluation/candidate_results.json`. It contains aggregate counts, dataset hashes and source/split group metrics; it does not contain source text or detected values.

Dataset basenames must be unique because result metadata is keyed by filename. If two input paths share a basename, the runner stops with a clear `ValueError` instead of overwriting one dataset's rows or metrics.

## Candidate algorithm

- Hyphenated `3-2-5` business-number shaped strings are candidates regardless of checksum. Plain 10-digit values require a nearby business-number label on the same line.
- API-key candidates include common secret-field assignments and selected provider token patterns. Obvious unresolved variables and placeholders are excluded.
- The candidate comparison replaces the existing business-number spans, keeps other PII spans, and keeps existing API-key/token spans unless their value looks like a placeholder.
- A labeled span counts as detected only when every character is covered by an allowed detection type.

The runner uses `Detector(None)` and therefore measures rules only, without ONNX model inference, pseudonymization, restoration, latency, or resource use. The candidate rules remain experimental.

## Current result

Against the supplied 510 Korean PII rows and 90 synthetic secret rows:

| Type | Existing rules | Candidate pipeline | Labeled spans |
|---|---:|---:|---:|
| Business number | 0 | 26 | 26 |
| API key | 14 | 23 | 30 |

Ten hand-authored synthetic regression fixtures passed. These counts do not establish real-world precision: the business-number examples include intentionally invalid checksums, and unannotated documents are not confirmed negatives. The secret dataset is marked CC BY-NC 4.0; confirm licensing before any commercial use.
