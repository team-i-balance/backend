"""Context-bound local rules; offsets always refer to the original input."""
import re

_FIELD_VALUE = r'''(?:"(?P<double>[^"\r\n]+)"|'(?P<single>[^'\r\n]+)'|(?P<bare>[^\s,;\[\]{}"']+))'''
_SECRET = re.compile(
    r'''(?i)(?<![\w])['"]?(?P<field>(?:[a-z][a-z0-9_-]*[_-])?(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|secret[_-]?key|password|passwd|pwd|passphrase|client[_-]?secret))['"]?\s*[:=]\s*'''
    + _FIELD_VALUE
    # The value may sit on the next line (YAML), but not when it is itself a key:
    # an empty 'password:' followed by 'username: alice' / '"username": "alice"'.
    # A bare value is taken whole (no shortening by backtracking) and must not end in ':'.
    + r'''(?(bare)(?<![:：])(?=[\s,;\[\]{}"']|$))(?![ \t]*[:：])'''
)
_SHELL_DEFAULT = re.compile(r'''(?i)(?<![\w])(?:[a-z][a-z0-9_-]*[_-])?(?:api[_-]?key|api[_-]?token|access[_-]?token|password|passwd|pwd|client[_-]?secret)\s*=\s*\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}\s]+)\}''')
_PROVIDER = re.compile(r'(?<![\w-])(?:SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|AIza[A-Za-z0-9_-]{20,}|SK[0-9a-fA-F]{32})(?![\w-])')
_PLACEHOLDER = re.compile(r'''(?i)^(?:\[[^\[\]\r\n]+_\d+\]|\$\S*|\{\{.*\}\}|<[^>]+>)$''')
_ID = re.compile(r'(?i)(?:주민\s*(?:등록)?\s*번호|외국인\s*(?:등록)?\s*번호|resident\s*(?:id|number))\s*[:=：]?\s*(?P<value>[0-9]{6}[- ]?[0-9]{7})(?![0-9])')
_CARD = re.compile(r'(?i)(?:카드\s*번호|card\s*(?:number|no))\s*[:=：]?\s*(?P<value>[0-9](?:[0-9 -]{11,25}[0-9]))(?![0-9])')
_ACCOUNT = re.compile(r'(?i)(?:계좌\s*번호|account\s*(?:number|no))\s*[:=：]?\s*(?P<value>[0-9](?:[0-9* -]{5,25}[0-9*]))(?![0-9])')


def detect_additional(text, existing=()):
    result = []
    for pattern, kind in ((_ID, 'ID_NUMBER'), (_CARD, 'CARD'), (_ACCOUNT, 'ACCOUNT')):
        for match in pattern.finditer(text):
            value = match.group('value').rstrip(' -')
            digits = sum(ch.isdigit() for ch in value)
            if kind == 'CARD' and not 13 <= digits <= 19:
                continue
            if kind == 'ACCOUNT' and not 6 <= sum(ch.isdigit() or ch == '*' for ch in value) <= 20:
                continue
            result.append({'start': match.start('value'), 'end': match.start('value') + len(value), 'type': kind})
    for match in _SECRET.finditer(text):
        group = next((name for name in ('double', 'single', 'bare') if match.group(name) is not None), None)
        if not group:
            continue
        value = match.group(group)
        if not value.strip() or _PLACEHOLDER.fullmatch(value.strip()):
            continue
        field = match.group('field').lower()
        kind = 'PASSWORD' if any(x in field for x in ('password', 'passwd', 'pwd', 'passphrase', 'client_secret', 'client-secret')) else ('ACCESS_TOKEN' if 'token' in field else 'API_KEY')
        result.append({'start': match.start(group), 'end': match.end(group), 'type': kind})
    for match in _SHELL_DEFAULT.finditer(text):
        value = match.group(1)
        if not _PLACEHOLDER.fullmatch(value):
            field = match.group(0).split('=', 1)[0].lower()
            kind = 'PASSWORD' if any(x in field for x in ('password', 'passwd', 'pwd', 'client_secret')) else ('ACCESS_TOKEN' if 'token' in field else 'API_KEY')
            result.append({'start': match.start(1), 'end': match.end(1), 'type': kind})
    for match in _PROVIDER.finditer(text):
        if not any(x['type'] in ('API_KEY', 'ACCESS_TOKEN', 'PASSWORD')
                   and x['start'] <= match.start() and x['end'] >= match.end()
                   for x in (*existing, *result)):
            result.append({'start': match.start(), 'end': match.end(), 'type': 'API_KEY'})
    return result
