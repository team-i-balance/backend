"""On-device PII span detection. No model downloads or request logging.

Offsets are Python Unicode string indexes; start is inclusive and end exclusive.
A configured model must be present and fully usable: errors are propagated and
never silently downgraded to rules-only results.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from .additional_rules import detect_additional
from .preprocessing import normalize_for_detection, restore_detection_offsets

_PHONE = re.compile(r'(?<![0-9])01[016789][ -]?[0-9]{3,4}[ -]?[0-9]{4}(?![0-9])')
_EMAIL = re.compile(r'(?i)(?<![\w.+-])[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?![a-z0-9-])')

# Business registration checksum confirms structure only, not registration.
_BUSINESS_HYPHEN = re.compile(r'(?<![0-9])([0-9]{3}-[0-9]{2}-[0-9]{5})(?![0-9])')
_BUSINESS_PLAIN = re.compile(r'(?<![0-9])([0-9]{10})(?![0-9])')
_BUSINESS_CONTEXT = re.compile(r'(?:사업자\s*(?:등록)?\s*번호|사업자\s*등록번호|business\s*(?:registration)?\s*(?:number|no))', re.I)
_BUSINESS_FIELD = re.compile(_BUSINESS_CONTEXT.pattern + r'''["']?\s*[:=：]?\s*["']?\s*$''', re.I)
# Match the value only; delimiters and key names must not be replaced.
_CREDENTIAL = re.compile(
    r"(?i)(?<![\w])(?:[\"']?(?P<field>api[_-]?key|access[_-]?token)[\"']?)\s*[:=]\s*"
    r"(?:\"(?P<double>[^\"\r\n]+)\"|'(?P<single>[^'\r\n]+)'|(?P<bare>[^\s,;\]\[\}\{\"']+))"
)
_BEARER = re.compile(r'(?i)\bauthorization\b[\"\']?\s*[:=]\s*[\"\']?bearer\s+(?P<value>[^\s\"\'\[\],;{}]+)')
_PROVIDER_API_KEY = re.compile(r'(?<![A-Za-z0-9_])(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,})(?![A-Za-z0-9_-])')
_PLACEHOLDER = re.compile(r'\[[^\[\]\r\n]+_\d+\]')


def _valid_business_number(value: str) -> bool:
    digits = value.replace('-', '')
    if len(digits) != 10 or not digits.isascii() or not digits.isdigit():
        return False
    nums = [int(c) for c in digits]
    weights = (1, 3, 7, 1, 3, 7, 1, 3, 5)
    total = sum(n*w for n, w in zip(nums[:9], weights)) + (nums[8]*5 // 10)
    return (10 - total % 10) % 10 == nums[9]


def _structured_detections(text: str) -> list[dict]:
    found = []
    for match in _BUSINESS_HYPHEN.finditer(text):
        context = text[max(0, match.start() - 40):match.start()].rsplit('\n', 1)[-1]
        if _valid_business_number(match.group(1)) or _BUSINESS_FIELD.search(context):
            found.append({'start': match.start(1), 'end': match.end(1), 'type': 'BUSINESS_NUMBER'})
    for match in _BUSINESS_PLAIN.finditer(text):
        # Only consider label preceding the value within the same short field.
        context = text[max(0, match.start() - 40):match.start()]
        last_line = context.rsplit('\n', 1)[-1]
        if _BUSINESS_FIELD.search(last_line):
            found.append({'start': match.start(1), 'end': match.end(1), 'type': 'BUSINESS_NUMBER'})
    for match in _CREDENTIAL.finditer(text):
        group = next((k for k in ('double', 'single', 'bare') if match.group(k) is not None), None)
        if group is None:
            continue
        value = match.group(group)
        if not value.strip() or _PLACEHOLDER.fullmatch(value) or value.startswith(('$', '<', '{{')):
            continue
        kind = 'ACCESS_TOKEN' if 'token' in match.group('field').lower() else 'API_KEY'
        found.append({'start': match.start(group), 'end': match.end(group), 'type': kind})
    for match in _BEARER.finditer(text):
        value = match.group('value')
        if not _PLACEHOLDER.fullmatch(value):
            found.append({'start': match.start('value'), 'end': match.end('value'), 'type': 'ACCESS_TOKEN'})
    found.extend(detect_additional(text, found))
    for match in _PROVIDER_API_KEY.finditer(text):
        if not any(x['type'] in ('API_KEY', 'ACCESS_TOKEN', 'PASSWORD') and x['start'] <= match.start() and x['end'] >= match.end() for x in found):
            found.append({'start': match.start(), 'end': match.end(), 'type': 'API_KEY'})
    return found


_TYPES = {
    'GIVENNAME': 'NAME', 'SURNAME': 'NAME',
    'USERNAME': 'USERNAME', 'EMAIL': 'EMAIL', 'TELEPHONENUM': 'PHONE',
    'DATEOFBIRTH': 'DOB', 'CREDITCARDNUMBER': 'CARD',
    'IDCARD': 'ID_NUMBER', 'STREET': 'ADDRESS', 'CITY': 'ADDRESS',
    'ZIPCODE': 'ADDRESS', 'BUILDINGNUM': 'ADDRESS', 'IP_ADDRESS': 'IP_ADDRESS',
    'PASSWORD': 'PASSWORD', 'ACCOUNTNUM': 'ACCOUNT',
    'DRIVERLICENSENUM': 'ID_NUMBER',
}


class DetectionError(RuntimeError):
    """The detector could not perform the requested complete check."""


class Detector:
    """Rules plus optional AEGIS ONNX model, loaded exclusively from local files.

    ``model_dir=None`` selects rules-only mode; it cannot detect person names or
    addresses and must not be represented as full PII coverage by callers.
    """

    def __init__(self, model_dir: str | Path | None, *, threads: int = 2):
        if not isinstance(threads, int) or isinstance(threads, bool) or threads < 1:
            raise ValueError('threads must be a positive integer')
        self.model_enabled = model_dir is not None
        self._tokenizer = self._session = self._np = None
        self._labels: dict[str, str] = {}
        if model_dir is None:
            return
        path = Path(model_dir).expanduser()
        candidates = [path / 'model.onnx', path / 'model_quantized.onnx',
                      path / 'onnx' / 'model_quantized.onnx']
        model = next((p for p in candidates if p.is_file()), None)
        if not path.is_dir() or model is None or not (path / 'config.json').is_file() or not (path / 'tokenizer.json').is_file():
            raise DetectionError('Local model, config.json, and tokenizer.json are required')
        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
            ort.disable_telemetry_events()
        except ImportError as exc:
            raise DetectionError('Local model dependencies are not installed') from exc
        try:
            labels = json.loads((path / 'config.json').read_text(encoding='utf-8'))['id2label']
            if not isinstance(labels, dict) or not labels:
                raise ValueError('invalid labels')
            self._labels = {str(k): str(v) for k, v in labels.items()}
            tokenizer = Tokenizer.from_file(str(path / 'tokenizer.json'))
            # 512 includes special tokens; overlapping windows ensure continuous coverage.
            tokenizer.enable_truncation(max_length=512, stride=32)
            tokenizer.no_padding()
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = threads
            opts.inter_op_num_threads = 1
            session = ort.InferenceSession(str(model), sess_options=opts, providers=['CPUExecutionProvider'])
            if any(i.name not in {'input_ids', 'attention_mask', 'token_type_ids'} for i in session.get_inputs()):
                raise ValueError('unsupported model inputs')
            self._tokenizer, self._session, self._np = tokenizer, session, np
        except Exception as exc:
            raise DetectionError('Failed to load the local detection model') from exc

    def detect(self, text: str) -> list[dict]:
        if not isinstance(text, str):
            raise TypeError('text must be a string')
        found = self._detect_raw(text)
        normalized, offsets = normalize_for_detection(text)
        if normalized == text:
            return found
        try:
            normalized_spans = self._detect_raw(normalized)
            return _merge_overlaps(found + restore_detection_offsets(normalized_spans, offsets))
        except Exception as exc:
            raise DetectionError('Normalized text detection failed; text was not fully checked') from exc

    def _detect_raw(self, text: str) -> list[dict]:
        found = [{'start': m.start(), 'end': m.end(), 'type': kind}
                 for kind, pattern in (('PHONE', _PHONE), ('EMAIL', _EMAIL))
                 for m in pattern.finditer(text)]
        structured = _structured_detections(text)
        found.extend(structured)
        if not self.model_enabled or not text:
            return _merge_overlaps(found)
        try:
            # Strong structured matches take precedence only when they fully
            # cover a model span. Partial overlaps still require review.
            model_spans = self._model_detect(text)
            found.extend(span for span in model_spans if not any(
                rule['start'] <= span['start'] and span['end'] <= rule['end']
                and rule['type'] != span['type'] for rule in structured))
        except Exception as exc:
            # Return no partial result; avoid leaking input through exception text.
            raise DetectionError('Local model inference failed; text was not fully checked') from exc
        return _merge_overlaps(found)

    def _model_detect(self, text: str) -> list[dict]:
        tok, session, np = self._tokenizer, self._session, self._np
        first = tok.encode(text, add_special_tokens=True)
        chunks = [first, *first.overflowing]
        results = []
        for chunk in chunks:
            feed = {}
            for inp in session.get_inputs():
                if inp.name == 'input_ids':
                    data = chunk.ids
                elif inp.name == 'attention_mask':
                    data = chunk.attention_mask
                else:
                    data = chunk.type_ids
                feed[inp.name] = np.asarray([data], dtype=np.int64)
            logits = session.run(None, feed)[0]
            if logits.ndim != 3 or logits.shape[:2] != (1, len(chunk.ids)):
                raise ValueError('unexpected model output dimensions')
            predictions = logits[0].argmax(axis=-1)
            active = None
            chunks_spans = []
            for idx, (start, end) in zip(predictions, chunk.offsets):
                if start == end:  # special tokens
                    continue
                label = self._labels.get(str(int(idx)))
                if label is None:
                    raise ValueError('unknown model output label')
                prefix, sep, raw_type = label.partition('-')
                kind = _TYPES.get(raw_type) if sep else None
                if kind is None:
                    if active:
                        chunks_spans.append(active)
                        active = None
                    continue
                # I-tag pieces may skip whitespace in tokenizer offsets; include
                # that whitespace within a model entity, not other content.
                if active and prefix == 'I' and active['type'] == kind and start >= active['end'] and text[active['end']:start].strip() == '':
                    active['end'] = end
                else:
                    if active:
                        chunks_spans.append(active)
                    active = {'start': start, 'end': end, 'type': kind, '_raw': raw_type}
            if active:
                chunks_spans.append(active)
            # Korean surname/given-name subentities may be adjacent or separated
            # by one space. Combine only SURNAME followed by GIVENNAME.
            merged = []
            for span in chunks_spans:
                if (merged and merged[-1]['_raw'] == 'SURNAME' and span['_raw'] == 'GIVENNAME'
                        and text[merged[-1]['end']:span['start']] in ('', ' ')):
                    merged[-1]['end'] = span['end']
                    merged[-1]['_raw'] = 'NAME'
                else:
                    merged.append(span)
            results.extend({k: v for k, v in span.items() if k != '_raw'} for span in merged)
        return results


def _merge_overlaps(spans: list[dict]) -> list[dict]:
    """Union overlapping spans only within a type, retaining conflicts for review."""
    by_type = {}
    for span in spans:
        by_type.setdefault(span['type'], []).append(span)
    result = []
    for kind, group in by_type.items():
        group.sort(key=lambda x: (x['start'], x['end']))
        merged = []
        for span in group:
            if merged and span['start'] < merged[-1]['end']:
                merged[-1]['end'] = max(merged[-1]['end'], span['end'])
            else:
                merged.append(dict(span))
        result.extend(merged)
    return sorted(result, key=lambda x: (x['start'], x['end'], x['type']))
