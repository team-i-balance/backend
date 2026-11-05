"""HTTP entity-tag helpers (RFC 9110 section 8.8.3 / 13.1.2).

Used by GET /policy/latest. Response ETags are always quoted strong tags
(`"sha256:<hex>"`); body fields such as /policy/history `sha256` stay unquoted.
"""
from __future__ import annotations


def quote_etag(value: str) -> str:
    """Wrap an opaque value as a strong RFC entity-tag: `"value"`."""
    return f'"{value}"'


def _opaque(tag: str) -> str:
    """Strip an optional `W/` prefix and surrounding quotes.

    Unquoted values are accepted for clients that stored the old bare ETag.
    """
    tag = tag.strip()
    if tag.startswith("W/"):
        tag = tag[2:].strip()
    if len(tag) >= 2 and tag[0] == '"' and tag[-1] == '"':
        tag = tag[1:-1]
    return tag


def if_none_match_hits(header: str | None, current: str) -> bool:
    """True when If-None-Match matches `current` (weak comparison).

    Accepts `*`, comma-separated lists, `W/` tags, and quoted or unquoted
    values. Our opaque values (`sha256:<hex>`) never contain commas.
    """
    if header is None:
        return False
    want = _opaque(current)
    for part in header.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "*" or _opaque(part) == want:
            return True
    return False
