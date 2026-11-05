"""Korean structured PII rules: ID number, card, account, IP, password, date of birth.

Ported from pii-guard (piiguard/detectors.py). Pipeline per candidate:
regex -> structure/checksum -> context score (0~1). Score >= MASK_T is a sure
hit; AMBIG_T~MASK_T is ambiguous and still masked (fail closed); below is dropped.
Offsets are Python string indexes; end is exclusive.
"""
from __future__ import annotations

import datetime
import ipaddress
import re

MASK_T = 0.75
AMBIG_T = 0.5

# Higher wins when kr candidates overlap each other.
_PRIORITY = {'PASSWORD': 10, 'ID_NUMBER': 8, 'CARD': 7, 'ACCOUNT': 4, 'IP_ADDRESS': 2, 'DOB': 1}

# Python's \b treats Hangul as word chars ("010-1234-5678로"), so bound on ASCII alnum only.
_L = r'(?<![0-9A-Za-z])'
_R = r'(?![0-9A-Za-z])'

# Pseudonym placeholders ([카드번호_1]) are already-masked content.
_TOKEN = re.compile(r'\[[^\[\]\r\n]+_\d+\]')


def _ctx(text, start, end, words, before=25, after=12, pattern=None):
    # Context stays on the value's own line, and stops at a neighbouring value (3+ digits)
    # or placeholder: a masked value ([계좌번호_1]) is shorter and holds label words, so
    # re-inspection would otherwise see other context. Short digits stay, so numbered
    # labels ('계좌1:', 'account1=') still count.
    window = text[max(0, start - before):start]
    left = window.rsplit('\n', 1)[-1]
    if not left.strip() and '\n' in window:
        # Value opens its line: a label-only previous line ("계좌:\n110-…") still counts.
        prev = window.rsplit('\n', 2)[-2] if window.count('\n') >= 1 else ''
        if prev.rstrip().endswith((':', '：')):
            left = prev
    right = text[end:end + after].split('\n', 1)[0]
    left = re.split(r'[0-9]{3,}|[\],;|]', left)[-1]
    right = re.split(r'[0-9]{3,}|[\[,;|]', right)[0]
    seg = (left + ' ' + right).lower()
    if pattern is not None and pattern.search(seg):
        return True
    for w in words:
        if w.isascii():
            # Whole word only: 'nh' must not hit 'enhance', 'account' not 'accounting'.
            if re.search(r'(?<![a-z])' + re.escape(w) + r'(?![a-z])', seg):
                return True
        elif w in seg:
            return True
    return False


def _last_pos(seg, words, pattern=None):
    pos = -1
    for w in words:
        rx = r'(?<![a-z])' + re.escape(w) + r'(?![a-z])' if w.isascii() else re.escape(w)
        for m in re.finditer(rx, seg):
            pos = max(pos, m.start())
    if pattern is not None:
        for m in pattern.finditer(seg):
            pos = max(pos, m.start())
    return pos


def _neg_nearest(text, start, neg, labels, pattern=None, before=25):
    """True when an order/parcel word is the label closest before the value.

    "주문번호: ABC 카드: 4111…" -> the card label is closer, so it is a card.
    """
    seg = re.split(r'[0-9\]]', text[max(0, start - before):start])[-1].lower()
    neg_pos = _last_pos(seg, neg)
    return neg_pos >= 0 and neg_pos > _last_pos(seg, labels, pattern)


def _digits(s):
    return re.sub(r'[^0-9]', '', s)


def _cand(kind, start, end, score):
    return {'start': start, 'end': end, 'type': kind, 'score': round(min(score, 0.99), 2)}


# ---- context words
_ID_CTX = ['주민', 'rrn', 'ssn', 'jumin', 'resident', '생년월일', '등록번호']
_FRN_CTX = ['외국인', 'alien', 'foreign', '등록번호', 'arc']
_ID_LABELS = ['주민', '외국인', 'rrn', 'ssn', 'jumin', 'resident', 'alien']
_CARD_CTX = ['카드', 'card', '신용', '결제', 'visa', 'master', 'cvc', '유효기간']
_BANKS = ['은행', '뱅크', 'kb', '신한', '농협', 'nh', 'ibk', '카뱅', '케이뱅크', 'sc제일', '씨티',
          '새마을', '신협', '우체국', '수협']
_ACC_CTX = ['계좌', '입금', '송금', '이체', '예금주', '통장', 'account', 'acct', 'bank'] + _BANKS
# Bank names that are also everyday words ("우리 매출") count only with 은행/뱅크/계좌 after them.
_AMBIG_BANK = re.compile(r'(?:우리|하나|국민|기업|산업|카카오|토스|부산|대구|경남|광주|전북|제주)\s?(?:은행|뱅크|계좌)')
# Money right after the digits ("10000000000원") is an amount, not an account.
_AMOUNT_AFTER = re.compile(r'\s?(?:원|억|만\s?원|천\s?원|달러|불|won|krw|usd|%)', re.I)
# Digit runs that are usually not personal data (orders, parcels, builds).
_NEG_CTX = ['주문번호', '송장', '운송장', '사번', '회원번호', '상품번호', '예약번호', '접수번호',
            '승인번호', '거래번호', 'order', 'invoice', 'tracking', 'sku', 'id:', 'build', 'commit']
# ID numbers also drop on the bare words; an explicit ID label still wins (_ID_LABELS).
_ID_NEG_CTX = _NEG_CTX + ['주문', '접수']
_DOB_CTX = ['생년월일', '생일', '출생', '생년', '태어난', 'dob', 'birth', 'birthday', 'birthdate', 'birth_date']


# ---- ID number (resident / foreigner registration)
# re.A: ASCII digits only, like _PHONE; full-width digits are seen on the normalized copy.
_ID_RE = re.compile(_L + r'(\d{6})(?:\s?[-–]\s?|\s)?([1-8]\d{6})' + _R, re.A)


def _birth_ok(front, gender):
    century = 1900 if gender in '1256' else 2000
    try:
        d = datetime.date(century + int(front[:2]), int(front[2:4]), int(front[4:6]))
    except ValueError:
        return False
    return d <= datetime.date.today()


def id_checksum_ok(d13):
    w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    s = sum(int(a) * b for a, b in zip(d13[:12], w))
    chk = (13 - s % 11) % 10 if d13[6] in '5678' else (11 - s % 11) % 10
    return chk == int(d13[12])


def _id_numbers(text):
    for m in _ID_RE.finditer(text):
        front, back = m.group(1), m.group(2)
        if not _birth_ok(front, back[0]):
            continue
        sep = len(m.group(0)) > 13
        # Numbers issued from 2020-10 have no checksum: date + gender digit decide.
        score = 0.8 if sep else 0.45
        if id_checksum_ok(front + back):
            score += 0.15 if sep else 0.25
        if _ctx(text, m.start(), m.end(), _FRN_CTX if back[0] in '5678' else _ID_CTX):
            score += 0.15
        # Order/parcel numbers drop it even with a valid checksum, unless an explicit
        # ID label ("주민번호") is closer to the value.
        if _neg_nearest(text, m.start(), _ID_NEG_CTX, _ID_LABELS):
            continue
        yield _cand('ID_NUMBER', m.start(), m.end(), score)


# ---- card
_CARD_RE = re.compile(_L + r'(\d(?:[ -]?\d){12,18})' + _R, re.A)
_CARD_PREFIX = re.compile(r'^(4|5[1-5]|2[2-7]|3[47]|3[0689]|35|6|9)')


def luhn_ok(d):
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _card_groups_ok(raw):
    parts = re.split(r'[ -]', raw)
    if len(parts) == 1:
        return True
    lens = [len(p) for p in parts]
    return lens in ([4, 6, 5], [4, 6, 4]) or (all(x == 4 for x in lens[:-1]) and 1 <= lens[-1] <= 4)


def _card_span(m):
    """Longest Luhn-valid run of whole digit groups ("4111 1111 1111 1111 123" -> first 16)."""
    groups = [g.span() for g in re.finditer(r'[0-9]+', m.group(0))]
    best = None
    for i in range(len(groups)):
        for j in range(i, len(groups)):
            st, en = m.start() + groups[i][0], m.start() + groups[j][1]
            d = _digits(m.string[st:en])
            if 13 <= len(d) <= 19 and luhn_ok(d) and (best is None or en - st > best[1] - best[0]):
                best = (st, en)
    return best


def _cards(text):
    for m in _CARD_RE.finditer(text):
        span = _card_span(m)
        ctx = _ctx(text, m.start(), m.end(), _CARD_CTX)
        if span:
            st, en = span
            score = 0.9 if _CARD_PREFIX.match(_digits(text[st:en])) else 0.65
        elif ctx and len(_digits(m.group(0))) in (15, 16):
            st, en = m.start(), m.end()
            score = 0.6  # typo or test value in a card field
        else:
            continue
        if not _card_groups_ok(text[st:en]):
            score -= 0.2
        if ctx:
            score += 0.1
        # From the whole digit run: "주문번호 123 4111 …" must not lose its label to the cut.
        if _neg_nearest(text, m.start(), _NEG_CTX, _CARD_CTX):
            continue  # order / parcel number
        yield _cand('CARD', st, en, score)


# ---- account: bank formats vary and have no public checksum, so context is required
_ACC_SEP_RE = re.compile(_L + r'(\d{2,6}(?:-\d{2,7}){1,3})' + _R, re.A)
_ACC_RAW_RE = re.compile(_L + r'(\d{10,14})' + _R, re.A)
# Landline/internet phone shapes (02-1234-5678) are not accounts.
_TEL_RE = re.compile(r'^(?:0(?:2|[3-6][1-5]|70|50[2-8]|1[016789]))-\d{3,4}-\d{4}$')


def _accounts(text):
    for rx, base in ((_ACC_SEP_RE, 0.5), (_ACC_RAW_RE, 0.4)):
        for m in rx.finditer(text):
            if not 10 <= len(_digits(m.group(0))) <= 14 or _TEL_RE.match(m.group(0)):
                continue
            if _AMOUNT_AFTER.match(text, m.end()):
                continue
            if not _ctx(text, m.start(), m.end(), _ACC_CTX, pattern=_AMBIG_BANK):
                continue
            if _neg_nearest(text, m.start(), _NEG_CTX, _ACC_CTX, _AMBIG_BANK):
                continue  # order / parcel number
            yield _cand('ACCOUNT', m.start(), m.end(), base + 0.35)


# ---- IP
_IPV4_RE = re.compile(r'(?<![0-9A-Za-z.])((?:\d{1,3}\.){3}\d{1,3})(/\d{1,2})?(?![0-9]|\.[0-9])', re.A)
_IPV6_RE = re.compile(r'(?<![0-9A-Za-z:])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(/\d{1,3})?(?![0-9A-Za-z:])')
_IP_SKIP = {'0.0.0.0', '127.0.0.1', '255.255.255.255', '::', '::1'}
_VERSION_BEFORE = re.compile(r'(version|ver\.?|버전|v)\s*[:=]?\s*$', re.I)


def _ips(text):
    for m in _IPV4_RE.finditer(text):
        try:
            ip = ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue
        if str(ip) in _IP_SKIP or str(ip).startswith('255.'):
            continue
        if _VERSION_BEFORE.search(text[max(0, m.start() - 10):m.start()]):
            continue
        yield _cand('IP_ADDRESS', m.start(), m.end(), 0.85)
    for m in _IPV6_RE.finditer(text):
        cand = m.group(1)
        # Skip short code-like tokens such as 'a::b'.
        if len(cand) < 6 or not any(len(g) >= 3 for g in cand.split(':')):
            continue
        try:
            ip = ipaddress.IPv6Address(cand)
        except ValueError:
            continue
        if str(ip) in _IP_SKIP:
            continue
        yield _cand('IP_ADDRESS', m.start(), m.end(), 0.85)


# ---- password: value only, never the key
# Key must END with a password word (password_min_length is not a field).
_PW_WORDS = r'password|passwd|passwort|pwd|pw|passphrase|비밀번호|비번|패스워드|암호'
_PW_KV_RE = re.compile(
    r'''(?i)(?<![A-Za-z0-9_])["']?(?P<k>[A-Za-z0-9_.\-]*?(?:''' + _PW_WORDS + r''')s?'''
    # Confirm/repeat fields only (password_confirmation, password2, 비밀번호 확인); metadata
    # keys such as password_min_length / password_hint do not end like this and stay out.
    r'''(?:[_.\-]?(?:confirmation|confirmed|confirm|again|repeat|retype|verify|check|\d)|\s?(?:확인|재확인|재입력|다시\s?입력))?)'''
    # Horizontal whitespace only: an empty field must not take the next line's key as its value.
    r'''["']?[ \t\u00a0]*(?P<sep>:=|=>|[:=：])[ \t\u00a0]*(?:\r?\n[ \t\u00a0]*)?'''
    r'''(?:"(?P<dq>(?:[^"\\\n]|\\.)*)"|'(?P<sq>(?:[^'\\\n]|\\.)*)'|(?P<v>[^\s"']+))'''
)
_PW_PLACEHOLDER = re.compile(
    r'(?i)^(\*+|x{3,}|<.*>|\$\{?[A-Za-z_][\w]*\}?|\{\{.*\}\}|%.*%|null|none|nil|undefined|true|false|\?+|\.{3}|…|'
    r'(process\.env|os\.environ|getenv|env\().*)$'
)
_URL_CRED_RE = re.compile(r'(?i)(?<![a-z0-9])[a-z][a-z0-9+.\-]*://[^:/\s@]+:(?P<pw>[^@\s/]+)@')
# Natural Korean: "비밀번호는 qwer1234!야", "비밀번호를 "한글 암호"로"
_KO_PW_RE = re.compile(
    # The label must end the word: '암호화=AES256' or '비밀번호정책=strict' is not a password field.
    r'''(?:비밀번호|비번|패스워드|암호)(?:(?:은|는|이|가|를|을|도)(?![가-힣])|(?![가-힣A-Za-z0-9_]))'''
    r'''[ \t\u00a0]*(?P<sep>:|=|->|→|은|는)?[ \t\u00a0]*(?:(?<=[:：])\r?\n[ \t\u00a0]*)?'''
    r'''(?:"(?P<dq>(?:[^"\\\n]|\\.)+)"|'(?P<sq>(?:[^'\\\n]|\\.)+)'|`(?P<bq>[^`\n]+)`|(?P<v>[^\s"'`]+))'''
)
_HANGUL = re.compile(r'[가-힣]')
# Particle/ending glued to an unquoted value: "qwer1234!야", "abc123입니다."
_PARTICLE_END = re.compile(
    r'(?:입니다|이에요|이예요|이라고|으로|이야|예요|에요|라고|이고|이다|이요|야|요|은|는|이|가|을|를|로|고|다|임|도|만)'
    r'[.!?,]*$')
# Prose, not a value: "비밀번호 8자리 이상", "5회 오류"
# Policy prose: "8자리 이상", "5회", "90일마다", "8~16자입니다" (Korean tail only; "8자리Secret!" is a value)
_PW_PROSE = re.compile(r'^\d{1,3}(?:[~-]\d{1,3})?(?:자리?|글자|회|번|개|일|개월|주|시간|분)[가-힣.,!?~]*$')
_PW_EMPTY = {'없음', '미입력', '미설정', '동일', '변경', '생략', '비공개', '모름'}


def _pw_value_ok(value, quoted=False):
    if not value or _PW_PLACEHOLDER.match(value) or _TOKEN.search(value):
        return False
    # A bare value stops at '}' ('{{SECRET'), so prefixes alone mark it as a placeholder; a
    # quoted value is complete, and only a full placeholder match excludes it ('"$Abc123!"').
    return quoted or not value.startswith(('[', '$', '{{', '<', '%'))


_CLOSE = {')': '(', ']': '[', '}': '{'}


def _cut_at_delimiter(value):
    """Stop at a setting delimiter (; , & |) or an unmatched closing bracket.

    "secret;user=alice" -> "secret", "abc&x=1" -> "abc", "abc)" in func(pw=abc) -> "abc",
    but "(abc)" keeps its own balanced brackets.
    """
    depth = {o: 0 for o in _CLOSE.values()}
    for i, ch in enumerate(value):
        if ch in ';,&|':
            return value[:i]
        if ch in depth:
            depth[ch] += 1
        elif ch in _CLOSE:
            if depth[_CLOSE[ch]] == 0:
                return value[:i]
            depth[_CLOSE[ch]] -= 1
    return value


def _bare_pw(value, assignment=False):
    """Unquoted value up to whitespace, minus trailing punctuation and a glued particle.

    ``assignment`` (pw=…) is config syntax, not prose: no particle is cut.
    A particle is cut only after a non-Hangul part ("abc123입니다"); "비밀123이" stays whole
    because the last syllable may be part of the password (ambiguous -> mask).
    """
    value = _cut_at_delimiter(value)
    if not assignment:
        m = _PARTICLE_END.search(value)
        if m and m.start() > 0 and not _HANGUL.search(value[:m.start()]):
            value = value[:m.start()]
    if not value or value in _PW_EMPTY or _PW_PROSE.match(value):
        return ''
    return value


def _quoted(m):
    return next(((g, m.group(g)) for g in ('dq', 'sq', 'bq') if g in m.groupdict() and m.group(g) is not None),
                (None, None))


def _scan(rx, text):
    """finditer that resumes right after a cut bare value, so the next field after ';' / '&'
    ("password=a;password2=b") is matched too instead of being swallowed."""
    pos = 0
    while (m := rx.search(text, pos)) is not None:
        yield m
        if m.group('sep') is not None and '\n' in text[m.end('sep'):m.end()]:
            # The value came from the next line: rescan that line ("password:\npassword2: x").
            pos = text.index('\n', m.end('sep')) + 1
        elif m.group('v') is not None:
            pos = max(m.start() + 1, m.start('v') + len(_cut_at_delimiter(m.group('v'))))
        else:
            pos = m.end()


def _next_line_key(m, g):
    """A value taken from the next line that is itself a key: 'password:\nusername: alice' or
    'password:\n"username": "alice"'."""
    if '\n' not in m.string[m.start('sep'):m.start(g)]:
        return False
    if g == 'v':
        return bool(re.match(r'[^\s"\'`:=]+[:=]', m.group(g)))
    return bool(re.match(r'[ \t]*[:=]', m.string[m.end(g) + 1:]))


def _passwords(text):
    for m in _scan(_PW_KV_RE, text):
        g, val = _quoted(m)
        if _next_line_key(m, g or 'v'):
            continue
        if g is None:
            g, val = 'v', _bare_pw(m.group('v'), assignment=m.group('sep') != ':' and m.group('sep') != '：')
        if val and _pw_value_ok(val, quoted=g != 'v'):
            yield _cand('PASSWORD', m.start(g), m.start(g) + len(val), 0.92)
    for m in _URL_CRED_RE.finditer(text):
        if _pw_value_ok(m.group('pw')):
            yield _cand('PASSWORD', m.start('pw'), m.end('pw'), 0.95)
    for m in _scan(_KO_PW_RE, text):
        g, val = _quoted(m)
        if m.group('sep') is not None and _next_line_key(m, g or 'v'):
            continue
        if g is None:
            g, val = 'v', _bare_pw(m.group('v'), assignment=m.group('sep') == '=')
            # Without ':' / '=' it may be prose ("비밀번호 재설정: …"): need an ASCII letter/digit
            # and no trailing ':' (that is a label, not a value).
            if m.group('sep') in (None, '은', '는') and (
                    len(val) < 3 or not re.search(r'[0-9A-Za-z]', val) or val.endswith((':', '：'))):
                continue
        if val and _pw_value_ok(val, quoted=g != 'v'):
            yield _cand('PASSWORD', m.start(g), m.start(g) + len(val), 0.85)


# ---- date of birth: needs a birth keyword
_DOB_OTHER_DATE = re.compile(r'(?:변경|수정|등록|가입|작성|발급|만료|갱신|입사|계약)\s*(?:일|일자|날짜)')
_DOB_RE = re.compile(
    r'(?<![0-9])(?:'
    r'(?P<y>(?:19|20)\d{2})\s*(?:[-./]|년)\s*(?P<m>\d{1,2})\s*(?:[-./]|월)\s*(?P<d>\d{1,2})(?:\s*일)?'
    r'|(?P<y8>(?:19|20)\d{2})(?P<m8>\d{2})(?P<d8>\d{2})'
    r'|(?P<y2>\d{2})[-./](?P<m2>\d{1,2})[-./](?P<d2>\d{1,2})'
    r'|(?P<y6>\d{2})(?P<m6>\d{2})(?P<d6>\d{2})'
    r')(?![0-9])', re.A
)


def _dob_date(m):
    today = datetime.date.today()
    for y, mo, d in (('y', 'm', 'd'), ('y8', 'm8', 'd8'), ('y2', 'm2', 'd2'), ('y6', 'm6', 'd6')):
        if m.group(y) is None:
            continue
        year = int(m.group(y))
        if len(m.group(y)) == 2:
            year += 2000 if 2000 + year <= today.year else 1900
        try:
            return datetime.date(year, int(m.group(mo)), int(m.group(d)))
        except ValueError:
            return None
    return None


def _dobs(text):
    for m in _DOB_RE.finditer(text):
        day = _dob_date(m)
        if day is None or not datetime.date(1900, 1, 1) <= day <= datetime.date.today():
            continue
        line_start = text.rfind('\n', 0, m.start()) + 1
        # Cut at an earlier value/placeholder or separator ("생년월일 …, 주문일 2024-01-01").
        before = re.split(r'[0-9\],;|]', text[max(line_start, m.start() - 20):m.start()])[-1]
        if not (_ctx(before, len(before), len(before), _DOB_CTX) or text[m.end():m.end() + 1] == '생'):
            continue
        # "생년월일 변경일 2024-01-01": the date belongs to a change/registration field.
        # Only words after the nearest birth label count ("등록일 미상 생년월일: 1990-…" is a DOB).
        if _DOB_OTHER_DATE.search(before[_last_pos(before.lower(), _DOB_CTX) + 1:]):
            continue
        yield _cand('DOB', m.start(), m.end(), 0.85)


_SECRET_TYPES = frozenset({'API_KEY', 'ACCESS_TOKEN'})
_RULES = (_passwords, _id_numbers, _cards, _accounts, _ips, _dobs)


def _overlaps(a, b):
    return a['start'] < b['end'] and b['start'] < a['end']


def kr_structured_detections(text: str, existing=()) -> list[dict]:
    """Return ``{'start','end','type'}`` spans for Korean structured PII.

    ``existing`` holds spans other rules already produced. A candidate fully
    inside one of a different type is dropped (already masked). A partial
    overlap is kept on purpose: dropping it would leak the uncovered part, and
    the cross-type overlap fails closed in pseudonymization (PseudonymError).
    """
    if not isinstance(text, str) or not text:
        return []
    # Phone/email run outside _structured_detections; check them here too.
    from .detector import _EMAIL, _PHONE
    taken = [*existing,
             *({'start': m.start(), 'end': m.end(), 'type': kind}
               for kind, rx in (('PHONE', _PHONE), ('EMAIL', _EMAIL)) for m in rx.finditer(text))]
    tokens = [{'start': m.start(), 'end': m.end()} for m in _TOKEN.finditer(text)]
    cands = [c for rule in _RULES for c in rule(text)
             if c['score'] >= AMBIG_T
             and not any(_overlaps(c, t) for t in tokens)
             and not any(t['start'] <= c['start'] and c['end'] <= t['end'] and t['type'] != c['type']
                         # A password value beats phone/email/number rules (password_first).
                         and (c['type'] != 'PASSWORD' or t['type'] in _SECRET_TYPES)
                         for t in taken)]
    # Greedy pick: sure hits > type priority > score > length.
    cands.sort(key=lambda c: (c['score'] >= MASK_T, _PRIORITY[c['type']], c['score'], c['end'] - c['start']),
               reverse=True)
    chosen = []
    for c in cands:
        # A candidate reaching past a password ("pw=4111 1111 …") is kept so that
        # password_first widens the password over it instead of leaking the rest.
        if any(x['type'] == 'PASSWORD' and _overlaps(c, x) for x in chosen) \
                or not any(_overlaps(c, x) for x in chosen):
            chosen.append(c)
    chosen = password_first(text, chosen)
    return sorted(({'start': c['start'], 'end': c['end'], 'type': c['type']} for c in chosen),
                  key=lambda x: (x['start'], x['end']))


def password_first(text: str, spans) -> list[dict]:
    """Resolve rule spans that overlap a PASSWORD value; the password always wins.

    - EMAIL: the password part is cut out; a leftover is kept only if it is still an
      email ('s3cret@db.internal' in a URL leaves '@db.internal' unmasked as a host).
    - Any other type inside the password is dropped; a partial overlap widens the
      password over both (ambiguous -> mask) so no cross-type overlap remains.
    """
    from .detector import _EMAIL
    pw = [dict(s) for s in spans if s['type'] == 'PASSWORD']
    rest = [dict(s) for s in spans if s['type'] != 'PASSWORD']
    changed = bool(pw)
    while changed:
        changed = False
        for s in list(rest):
            hits = [p for p in pw if _overlaps(p, s)]
            if not hits:
                continue
            rest.remove(s)
            changed = True
            if s['type'] == 'EMAIL':
                pos, pieces = s['start'], []
                for p in sorted(hits, key=lambda x: x['start']):
                    pieces.append((pos, max(pos, p['start'])))
                    pos = max(pos, p['end'])
                pieces.append((pos, s['end']))
                rest.extend({**s, 'start': a, 'end': b} for a, b in pieces
                            if b > a and _EMAIL.fullmatch(text[a:b]))
            elif not any(p['start'] <= s['start'] and s['end'] <= p['end'] for p in hits):
                hits[0]['start'] = min(hits[0]['start'], s['start'])
                hits[0]['end'] = max(hits[0]['end'], s['end'])
    return _containers_first(rest + pw)


# Structured values that can contain other rule matches ("계좌1: 123-010-1234-5678").
_CONTAINERS = frozenset({'ACCOUNT', 'CARD', 'ID_NUMBER'})


def _containers_first(spans):
    """A shorter non-secret match (phone, business number) inside an account/card/ID value is
    part of that value: drop it, or widen the container on a partial overlap."""
    cont = [s for s in spans if s['type'] in _CONTAINERS]
    keep = []
    for s in spans:
        if s['type'] in _CONTAINERS:
            continue
        hits = [c for c in cont if _overlaps(c, s)]
        if not hits or s['type'] in ('PASSWORD', 'API_KEY', 'ACCESS_TOKEN'):
            keep.append(s)
            continue
        c = hits[0]
        c['start'], c['end'] = min(c['start'], s['start']), max(c['end'], s['end'])
    return keep + cont
