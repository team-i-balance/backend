"""On-device PII span detection. No model downloads or request logging.

Offsets are Python Unicode string indexes; start is inclusive and end exclusive.
A configured model must be present and fully usable: errors are propagated and
never silently downgraded to rules-only results.
"""
from __future__ import annotations

import os

# onnxruntime (1.31, Linux) still connects to Microsoft 1DS telemetry during inference unless this
# is set before onnxruntime is imported; disable_telemetry_events() alone is not enough (#13).
# setdefault keeps a value the operator set explicitly.
os.environ.setdefault('ORT_DISABLE_TELEMETRY', '1')

import json
import re
from pathlib import Path
from .additional_rules import detect_additional
from .kr_rules import kr_structured_detections, password_first
from .preprocessing import normalize_for_detection, restore_detection_offsets
from .pseudonym import POLICY_TOKEN

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
# Pseudonym placeholders, plus the fixed 태그/삭제 outputs of a policy method (#47).
_PLACEHOLDER = re.compile(r'\[[^\[\]\r\n]+_\d+\]|' + POLICY_TOKEN.pattern)


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
    found.extend(kr_structured_detections(text, found))
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


# Types produced by regex/structured rules; they keep their extent when the SLM overlaps them
# (see Detector._add_slm_spans for the grade-C exception).
_RULE_TYPES = frozenset({'PHONE', 'EMAIL', 'BUSINESS_NUMBER', 'API_KEY', 'ACCESS_TOKEN',
                         'ID_NUMBER', 'CARD', 'ACCOUNT', 'IP_ADDRESS', 'PASSWORD', 'DOB'})
# An SLM leftover made only of these field labels (plus particles) is dropped after the cut:
# "주민번호 900101-…" flagged whole by the SLM must not mask the word "주민번호" on its own.
_LABEL_ONLY = re.compile(
    r'(?i)(?:(?:주민등록번호|주민번호|외국인등록번호|외국인번호|카드번호|카드|계좌번호|계좌|전화번호|전화|연락처|'
    r'휴대폰|번호|ip|아이피|생년월일|생일|비밀번호|패스워드|pw|password|이메일|메일)'
    r'(?:은|는|이|가|을|를|의|도|와|과|로|으로|에|에서|만)?)+')
_LABEL_STRIP = re.compile(r'[\s\W_]+')
# Left at SLM span edges after cutting around rule spans.
_TRIM_CHARS = frozenset(' \t\r\n,.;:/·()[]')

# These are heuristic candidates, not a complete Korean morphology parser.
_JOSA_ANY = ('에게서', '한테서', '께서는', '으로부터', '에게', '한테', '께서', '에서', '까지', '부터', '님께', '의', '님', '씨', '께')
_JOSA_FINAL = ('으로', '은', '을', '과', '이')
_JOSA_NO_FINAL = ('는', '를', '와', '가')
_COMPOUND_SURNAMES = ('남궁', '황보', '선우', '제갈', '사공', '서문', '독고', '동방')
# Single-character particles that are also common name-final syllables.
# For NAME spans, these are only stripped when the stem is long enough (≥4 chars)
# to make it unlikely the character is part of the actual name.
# e.g. "김다솜이" (3-char stem) must not be trimmed — "이" may be the last
# syllable of the given name, not the subject particle — but "홍길동주이"
# (4-char stem) is safely trimmed.
_JOSA_AMBIGUOUS_SINGLE = frozenset({'이', '가'})


def _trim_korean_particle(text: str, span: dict) -> dict:
    """Trim a likely particle on AEGIS NAME/ADDRESS output conservatively.

    AEGIS sometimes includes a trailing Korean particle (조사) inside the
    detected span — e.g. "김민수의" instead of "김민수".  This causes two
    problems:
      1. The same person appears under two different keys in the pseudonym
         mapping ("김민수" vs "김민수의"), producing separate aliases.
      2. On restore the original particle is re-attached: "[이름_1]님께" →
         "김민수의님께".

    Strategy: only strip particles that are unlikely to be part of a genuine
    name or address token (이름 끝 흔한 글자 — 나/로/랑/야/아/도/만 — 는 떼지 않음).
    If removing the suffix would leave fewer than 2 Hangul characters the span
    is returned unchanged (too risky to trim a one-syllable stem).
    """
    if span['type'] not in {'NAME', 'ADDRESS'}:
        return span
    start, end = span['start'], span['end']
    # Guard: if the character immediately after the span is Hangul the model
    # has already truncated mid-word — don't trim further.
    if end < len(text) and '가' <= text[end] <= '힣':
        return span
    value = text[start:end]
    for suffix in sorted(_JOSA_ANY + _JOSA_FINAL + _JOSA_NO_FINAL, key=len, reverse=True):
        if not value.endswith(suffix):
            continue
        stem = value[:-len(suffix)]
        if not stem or not ('가' <= stem[-1] <= '힣'):
            continue
        hangul_count = sum('가' <= ch <= '힣' for ch in stem)
        # Require at least 3 Hangul chars for single-char suffixes (e.g. '의'),
        # and at least 2 for longer ones, to avoid trimming too aggressively.
        if hangul_count < (3 if len(suffix) == 1 else 2):
            continue
        # Compound surname + 1-char given name + 1-char particle: "남궁민이" →
        # stem "남궁민" is 3 chars but "이" is a valid name-final syllable.
        if span['type'] == 'NAME' and len(suffix) == 1 and len(value) == 4 and value.startswith(_COMPOUND_SURNAMES):
            continue
        has_final = (ord(stem[-1]) - 0xAC00) % 28 != 0
        if suffix in _JOSA_FINAL and not has_final:
            continue
        if suffix in _JOSA_NO_FINAL and has_final:
            continue
        # For NAME spans, single-char particles that are also common name-final
        # syllables ('이', '가') require a longer stem before we are confident
        # the character is a particle and not part of the name itself.
        # "박지훈이" and "김다솜이" are indistinguishable without context:
        # the model may have correctly captured the full 4-syllable name.
        # Require stem ≥ 4 Hangul chars for these ambiguous particles on NAME.
        if span['type'] == 'NAME' and suffix in _JOSA_AMBIGUOUS_SINGLE and hangul_count < 4:
            continue
        return {**span, 'end': end - len(suffix)}
    return span


class DetectionError(RuntimeError):
    """The detector could not perform the requested complete check."""


class Detector:
    """Rules plus optional AEGIS ONNX model and optional SLM, loaded exclusively from local files.

    ``model_dir=None`` and ``slm_dir=None`` select rules-only mode; it cannot detect person
    names or addresses and must not be represented as full PII coverage by callers.
    ``slm_dir`` adds the confidential-policy SLM (local_ai/slm): names, addresses, a person's
    sensitive facts, and company-confidential spans per ``slm_policy``.
    """

    def __init__(self, model_dir: str | Path | None, *, threads: int = 2,
                 slm_dir: str | Path | None = None, slm_policy: str | Path | None = None):
        if not isinstance(threads, int) or isinstance(threads, bool) or threads < 1:
            raise ValueError('threads must be a positive integer')
        self.model_enabled = model_dir is not None or slm_dir is not None
        # Detection types turned off by the active policy (types on/off). Empty
        # by default, so behaviour is unchanged until a policy disables a type.
        self._disabled_types: frozenset[str] = frozenset()
        # Optional (text, spans) -> spans hook for the rest of the policy (app/policy_apply.py).
        self._span_policy = None
        self._tokenizer = self._session = self._np = None
        self._labels: dict[str, str] = {}
        self._slm = None
        if slm_dir is not None:
            try:
                from .slm import SlmSpanDetector
                self._slm = SlmSpanDetector(slm_dir, slm_policy)
            except Exception as exc:
                raise DetectionError('Failed to load the local SLM') from exc
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

    def set_policy(self, *, disabled_types=None, span_policy=None) -> None:
        """Apply active-policy toggles. ``disabled_types`` turns detection types
        off (policy ``types`` on/off; unknown types are ignored). ``span_policy``
        is called as ``span_policy(text, spans)`` on the final spans and returns
        the spans to use (company words, exclusions, methods). Passing None/empty
        restores default behaviour."""
        self._disabled_types = frozenset(disabled_types or ())
        self._span_policy = span_policy

    def _apply_policy(self, spans: list[dict], disabled=None) -> list[dict]:
        disabled = self._disabled_types if disabled is None else disabled
        if not disabled:
            return spans
        return [s for s in spans if s['type'] not in disabled]

    def detect(self, text: str, policy=None) -> list[dict]:
        """Spans for ``text``.

        ``policy`` (app/policy_apply.ServerPolicy, or anything with ``disabled_types``,
        ``slm_view`` and ``has_span_policy`` that is callable as ``policy(text, spans)``)
        is used for this call only, instead of the state from set_policy, so requests
        sharing this detector never mix policies (#47).
        """
        if not isinstance(text, str):
            raise TypeError('text must be a string')
        if policy is None:
            disabled, span_policy, view = self._disabled_types, self._span_policy, None
        else:
            disabled = frozenset(policy.disabled_types)
            span_policy = policy if policy.has_span_policy else None
            view = policy.slm_view
        found = self._detect_raw(text, disabled, view)
        normalized, offsets = normalize_for_detection(text)
        if normalized != text:
            try:
                normalized_spans = self._detect_raw(normalized, disabled, view)
                found = self._apply_policy(
                    _merge_overlaps(found + restore_detection_offsets(normalized_spans, offsets)), disabled
                )
            except Exception as exc:
                raise DetectionError('Normalized text detection failed; text was not fully checked') from exc
        return span_policy(text, found) if span_policy is not None else found

    def _detect_raw(self, text: str, disabled=None, view=None) -> list[dict]:
        found = [{'start': m.start(), 'end': m.end(), 'type': kind}
                 for kind, pattern in (('PHONE', _PHONE), ('EMAIL', _EMAIL))
                 for m in pattern.finditer(text)]
        structured = _structured_detections(text)
        # A password value beats phone/email/number spans inside it (kr_rules.password_first).
        found = password_first(text, found + structured)
        if not self.model_enabled or not text:
            return self._apply_policy(_merge_overlaps(found), disabled)
        try:
            # Strong structured matches take precedence only when they fully
            # cover a model span. Partial overlaps still require review.
            if self._session is not None:
                model_spans = self._model_detect(text)
                found.extend(span for span in model_spans if not any(
                    rule['start'] <= span['start'] and span['end'] <= rule['end']
                    and rule['type'] != span['type'] for rule in structured))
            if self._slm is not None:
                found = self._add_slm_spans(text, found, view)
        except Exception as exc:
            # Return no partial result; avoid leaking input through exception text.
            raise DetectionError('Local model inference failed; text was not fully checked') from exc
        return self._apply_policy(_merge_overlaps(found), disabled)

    def _add_slm_spans(self, text: str, found: list[dict], view=None) -> list[dict]:
        """Add SLM spans without cross-type overlaps (which pseudonymization rejects).

        - Rule-engine spans (keys, passwords, phone, email, resident/card/account numbers, IP,
          birth dates) always keep their extent and type: checksums and formats are more
          reliable than the SLM, which tends to mislabel such numbers (e.g. a resident number
          as an address or a card number as an internal host). SLM spans are cut around them.
        - After the cut, leftovers that are only field labels (_LABEL_ONLY, "주민번호") are
          dropped; any other leftover keeps the SLM type, so "010-… HIV 양성" keeps
          "HIV 양성" as SENSITIVE (grade C).
        - Everything else (AEGIS and SLM spans) is merged by type priority (local_ai.slm.PRIORITY).
        """
        from .slm import resolve_overlaps, subtract
        rules = [s for s in found if s['type'] in _RULE_TYPES]
        others = [s for s in found if s['type'] not in _RULE_TYPES]
        # Pseudonym placeholders ([주소_1]) are not data; the SLM tends to re-flag them on re-inspection.
        placeholders = [{'start': m.start(), 'end': m.end()} for m in _PLACEHOLDER.finditer(text)]
        slm = []
        for span in (self._slm.detect(text) if view is None else self._slm.detect(text, view=view)):
            # A span touching a placeholder is the SLM re-reading already-masked content.
            if any(p['start'] < span['end'] and span['start'] < p['end'] for p in placeholders):
                continue
            pieces = subtract(span, rules)
            cut = len(pieces) != 1 or (pieces[0]['start'], pieces[0]['end']) != (span['start'], span['end'])
            for part in pieces:
                st, en = part['start'], part['end']
                while st < en and text[st] in _TRIM_CHARS:
                    st += 1
                while en > st and text[en - 1] in _TRIM_CHARS:
                    en -= 1
                # After a cut, a leftover that is only a field label is not content of its own.
                if en > st and not (cut and _LABEL_ONLY.fullmatch(_LABEL_STRIP.sub('', text[st:en]))):
                    slm.append({**part, 'start': st, 'end': en})
        return rules + resolve_overlaps(others + slm)

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
            results.extend(_trim_korean_particle(text, {k: v for k, v in span.items() if k != '_raw'})
                           for span in merged)
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
