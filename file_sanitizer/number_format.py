"""Inspect display formats without copying arbitrary source styles."""

from datetime import datetime, time
import math
import operator
import re

from openpyxl.utils.datetime import CALENDAR_MAC_1904, from_excel
from openpyxl.styles.numbers import is_date_format, is_timedelta_format

from .package import RejectedFile

# Ignore quoted labels and escaped/padding characters before treating ';' as a separator.
FORMAT_TOKEN = re.compile(r'"[^"]*"|[\\_*].|\[[^\[\]]*\]|[^"\\_*\[\];]+|;')
CONDITION = re.compile(r"(<=|>=|<>|<|>|=)([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:E[+-]?[0-9]+)?)", re.I)
COMPARE = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge,
           "=": operator.eq, "<>": operator.ne}
DECORATION = re.compile(r"black|blue|cyan|green|magenta|red|white|yellow|color[0-9]+|\$[^\]]*", re.I)
ELAPSED = re.compile(r"h{1,2}|m{1,2}|s{1,2}", re.I)
DATE_TOKEN = re.compile(r"am/pm|a/p|y+|d+|h+|s+|m+", re.I)


def format_sections(fmt):
    """Split at real separators, keeping quoted and escaped characters intact."""
    if len(fmt) > 1024:
        raise RejectedFile("UNSUPPORTED_FEATURE")
    sections = [[]]
    pos = 0
    for match in FORMAT_TOKEN.finditer(fmt):
        if match.start() != pos:
            raise RejectedFile("UNSUPPORTED_FEATURE")
        pos = match.end()
        token = match[0]
        if token == ";":
            sections.append([])
        else:
            sections[-1].append(token)
    if pos != len(fmt) or len(sections) > 4:
        raise RejectedFile("UNSUPPORTED_FEATURE")
    return tuple(tuple(tokens) for tokens in sections)


def format_labels(fmt):
    """Also inspect adjoining literals that raw format syntax would split apart."""
    for tokens in format_sections(fmt):
        text = []
        for token in tokens:
            if token.startswith('"'):
                text.append(token[1:-1])
            elif token[0] in "\\*":
                text.append(token[1:])
            elif token.startswith("_"):
                text.append(" ")
            elif not token.startswith("["):
                text.append(token)
        if text:
            yield "".join(text)


def numeric_sections(fmt):
    sections = []
    for index, raw_tokens in enumerate(format_sections(fmt)):
        tokens, condition = [], None
        for token in raw_tokens:
            if token[0] in '"\\_*':
                continue
            if token[0] != "[":
                tokens.append(token)
            elif cond := CONDITION.fullmatch(token[1:-1]):
                threshold = float(cond[2])
                if condition or index >= 2 or not math.isfinite(threshold):
                    raise RejectedFile("UNSUPPORTED_FEATURE")
                condition = (COMPARE[cond[1]], threshold)
            elif ELAPSED.fullmatch(token[1:-1]):
                tokens.append(token)
            elif not DECORATION.fullmatch(token[1:-1]):
                raise RejectedFile("UNSUPPORTED_FEATURE")
        sections.append((condition, "".join(tokens)))
    return sections[:3]


def active_section(fmt, serial):
    sections = numeric_sections(fmt)
    conditions = [index for index, (condition, _) in enumerate(sections) if condition]
    if not conditions:
        index = 0
        if serial == 0 and len(sections) == 3:
            index = 2
        elif serial < 0 and len(sections) >= 2:
            index = 1
        return sections[index][1]
    # Support one or two leading comparisons, with at most one final fallback.
    if conditions != list(range(len(conditions))) or len(sections) - len(conditions) > 1:
        raise RejectedFile("UNSUPPORTED_FEATURE")
    for condition, section in sections:
        if condition is None or condition[0](serial, condition[1]):
            return section
    raise RejectedFile("UNSUPPORTED_FEATURE")


def display_policy(value, fmt, raw_numeric=None):
    """Return (hidden, safe number format). Reject ambiguous zero padding.

    A None format asks the caller to fail after confidential-text inspection.
    Plain integer zero masks are the only source formats retained on export.
    """
    sections = format_sections(fmt)
    if isinstance(value, str):
        # Without a fourth section, text is unaffected by numeric formatting.
        text_code = "@"
        if len(sections) == 4:
            text_code = "".join(t for t in sections[3] if t[0] not in '"\\_*[')
        return "@" not in text_code, "General"
    if isinstance(value, bool):
        return False, "General"
    if raw_numeric is None:
        # ISO-serialized dates have no numeric serial. Conditions cannot be
        # evaluated without one; do not expose a possibly hidden value.
        codes = numeric_sections(fmt)
        if len(sections) > 1 or any(condition for condition, _ in codes):
            return False, None
        return not codes[0][1].strip(), "General"
    serial = float(raw_numeric)
    code = active_section(fmt, serial)
    if not code.strip():
        return True, "General"
    if re.fullmatch(r"0{2,}", fmt):
        if type(value) not in (int, float) or not math.isfinite(serial) or not serial.is_integer():
            return False, None
        return False, fmt
    # Other integer masks (separators, conditions, labels, or decimals) need a
    # full renderer to preserve their meaning. Never silently drop those zeros.
    if "00" in code.split(".", 1)[0]:
        return False, None
    return False, "General"


def day_zero_value(raw, fmt):
    serial = float(raw) if any(c in raw for c in ".Ee") else int(raw)
    if fmt.lower() == "general":
        return serial
    section = active_section(fmt, serial).lower()
    if section == "general":
        return serial
    elapsed = "[" in section
    tokens = DATE_TOKEN.findall(section)
    if not tokens:
        # Numeric exponents are not calendar years; era/calendar codes are outside this profile.
        if re.search(r"[a-z]", re.sub(r"e[+-]?0+", "", section)):
            raise RejectedFile("UNSUPPORTED_FEATURE")
        return serial
    if re.search(r"[a-z]", DATE_TOKEN.sub("", section)):
        raise RejectedFile("UNSUPPORTED_FEATURE")
    calendar = any(t[0] in "yd" for t in tokens)
    for i, token in enumerate(tokens):
        if token[0] == "m" and not elapsed:
            after_hours = i > 0 and tokens[i - 1].startswith("h")
            before_seconds = i + 1 < len(tokens) and tokens[i + 1].startswith("s")
            calendar |= len(token) >= 3 or not (after_hours or before_seconds)
    if elapsed:
        if calendar:
            raise RejectedFile("UNSUPPORTED_FEATURE")
        return from_excel(serial, CALENDAR_MAC_1904, timedelta=True)
    value = from_excel(serial, CALENDAR_MAC_1904)
    if calendar:
        return datetime.combine(CALENDAR_MAC_1904.date(), value) if isinstance(value, time) else value
    return value.time() if isinstance(value, datetime) else value


def numeric_value(raw, fmt, epoch):
    """Resolve stored numbers from their active section before inspecting them.

    openpyxl's load-time classification uses the first format section, even
    when a condition selects a different one. Always start from the raw XML
    number so an inactive date section cannot corrupt the processor input.
    """
    serial = float(raw) if any(c in raw for c in ".Ee") else int(raw)
    if epoch == CALENDAR_MAC_1904 and 0 <= serial < 1:
        return day_zero_value(raw, fmt)
    section = active_section(fmt, serial)
    if not is_date_format(section):
        return serial
    try:
        return from_excel(serial, epoch, timedelta=is_timedelta_format(section))
    except (ValueError, OverflowError):
        raise RejectedFile("UNSUPPORTED_FEATURE") from None
