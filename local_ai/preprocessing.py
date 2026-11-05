"""Build a numeric-normalized inspection copy with original character offsets."""

_HYPHENS = frozenset('‐‑‒–—−－')
_ZERO_WIDTH = frozenset('\u200b\u200c\u200d\ufeff')


def _numeric(char):
    return char.isdecimal()


def normalize_for_detection(text):
    result, offsets = [], []
    for index, char in enumerate(text):
        if char in _ZERO_WIDTH:
            left, right = index - 1, index + 1
            while left >= 0 and text[left] in _ZERO_WIDTH:
                left -= 1
            while right < len(text) and text[right] in _ZERO_WIDTH:
                right += 1
            if left >= 0 and right < len(text):
                a, b = text[left], text[right]
                if (_numeric(a) and (_numeric(b) or b in _HYPHENS or b == '-')) or (_numeric(b) and (a in _HYPHENS or a == '-')):
                    continue
        if '０' <= char <= '９':
            char = chr(ord('0') + ord(char) - ord('０'))
        elif char in _HYPHENS and index and index + 1 < len(text) and _numeric(text[index - 1]) and _numeric(text[index + 1]):
            char = '-'
        result.append(char)
        offsets.append(index)
    return ''.join(result), offsets


def restore_detection_offsets(spans, offsets):
    result = []
    for span in spans:
        start, end = span['start'], span['end']
        if not (0 <= start < end <= len(offsets)):
            raise ValueError('invalid normalized detection offsets')
        result.append({**span, 'start': offsets[start], 'end': offsets[end - 1] + 1})
    return result
