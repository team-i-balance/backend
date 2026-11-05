"""HTTP entity-tag helpers (RFC 9110 section 8.8.3 / 13.1.2).

Used by GET /policy/latest. Response ETags are always quoted strong tags
(`"sha256:<hex>"`); body fields such as /policy/history `sha256` stay unquoted.
"""
from __future__ import annotations


def quote_etag(value: str) -> str:
    """Wrap an opaque value as a strong RFC entity-tag: `"value"`."""
    return f'"{value}"'


def _opaque(tag: str) -> str:
    """Strip an optional `W/` prefix and surrounding quotes from one tag."""
    tag = tag.strip()
    if tag.startswith("W/"):
        tag = tag[2:].strip()
    if len(tag) >= 2 and tag[0] == '"' and tag[-1] == '"':
        tag = tag[1:-1]
    return tag


def _parse_list(header: str) -> list[str] | None:
    """Split an If-None-Match list into opaque values, or "*".

    Quoted tags are read up to their closing quote, so a comma inside a tag
    (valid etagc per RFC 9110 8.8.3) is not a list separator. Unquoted
    members (legacy clients sent bare `sha256:<hex>`) end at the next comma.
    Returns None for a malformed list (e.g. an unterminated quote).
    """
    out: list[str] = []
    i, n = 0, len(header)
    while i < n:
        while i < n and header[i] in " \t,":
            i += 1
        if i >= n:
            break
        if header.startswith("W/", i):
            i += 2
        if i < n and header[i] == '"':
            close = header.find('"', i + 1)
            if close == -1:
                return None
            out.append(header[i + 1:close])
            i = close + 1
            while i < n and header[i] in " \t":
                i += 1
            if i < n and header[i] != ",":
                return None  # junk after a quoted tag
        else:
            comma = header.find(",", i)
            end = n if comma == -1 else comma
            out.append(header[i:end].strip())
            i = end
    return out


def if_none_match_hits(header: str | None, current: str) -> bool:
    """True when If-None-Match matches `current` (weak comparison).

    Accepts `*`, comma-separated lists, `W/` tags, and quoted or unquoted
    values. Commas inside quoted tags do not split the list.
    """
    if header is None:
        return False
    if header.strip() == "*":
        return True
    members = _parse_list(header)
    if members is None:
        return False
    want = _opaque(current)
    return any(m == want or m == "*" for m in members if m)
