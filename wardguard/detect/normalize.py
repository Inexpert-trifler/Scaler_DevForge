"""Text normalization and index-mapping utilities.

Handles NFKC normalization, Devanagari digits to ASCII, zero-width stripping,
and homoglyph folding while maintaining an exact index mapping back to original offsets.
"""
from __future__ import annotations
from bisect import bisect_right
import re
import unicodedata
from typing import Sequence, Tuple

# Devanagari digit mapping: U+0966 to U+096F -> '0'..'9'
DEVA_DIGITS = {
    '\u0966': '0',
    '\u0967': '1',
    '\u0968': '2',
    '\u0969': '3',
    '\u096a': '4',
    '\u096b': '5',
    '\u096c': '6',
    '\u096d': '7',
    '\u096e': '8',
    '\u096f': '9',
}

# Zero-width and invisible control characters to strip
ZERO_WIDTH_CHARS = {
    '\u200b',  # zero-width space
    '\u200c',  # zero-width non-joiner (zwnj)
    '\u200d',  # zero-width joiner (zwj)
    '\ufeff',  # byte order mark / zero-width no-break space
    '\u200e',  # ltr mark
    '\u200f',  # rtl mark
    '\u00ad',  # soft hyphen
}

# Common homoglyphs / confusable characters (Latin lookalikes)
HOMOGLYPHS = {
    '\u0430': 'a',  # cyrillic small a
    '\u0435': 'e',  # cyrillic small e
    '\u043e': 'o',  # cyrillic small o
    '\u0440': 'p',  # cyrillic small er
    '\u0441': 'c',  # cyrillic small es
    '\u0443': 'y',  # cyrillic small u
    '\u0445': 'x',  # cyrillic small ha
    '\u0410': 'A',  # cyrillic capital A
    '\u0412': 'B',  # cyrillic capital Ve
    '\u0415': 'E',  # cyrillic capital Ie
    '\u041a': 'K',  # cyrillic capital Ka
    '\u041c': 'M',  # cyrillic capital Em
    '\u041d': 'H',  # cyrillic capital En
    '\u041e': 'O',  # cyrillic capital O
    '\u0420': 'P',  # cyrillic capital Er
    '\u0421': 'C',  # cyrillic capital Es
    '\u0422': 'T',  # cyrillic capital Te
    '\u0425': 'X',  # cyrillic capital Ha
}


_TRANS_TABLE = str.maketrans({
    **{ord(c): None for c in ZERO_WIDTH_CHARS},
    **{ord(k): v for k, v in DEVA_DIGITS.items()},
    **{ord(k): v for k, v in HOMOGLYPHS.items()},
})
_ASCII_NONASCII_RE = re.compile(r'[\x00-\x7f]+|[^\x00-\x7f]+')


class _RunOffsetMap:
    """Compact sequence mapping normalized offsets back to original text offsets."""
    __slots__ = ("_norm_starts", "_orig_starts", "_length", "_orig_end")

    def __init__(self, norm_starts: list[int], orig_starts: list[int], length: int, orig_end: int):
        self._norm_starts = norm_starts
        self._orig_starts = orig_starts
        self._length = length
        self._orig_end = orig_end

    def __len__(self) -> int:
        return self._length

    def __bool__(self) -> bool:
        return self._length > 0

    def __getitem__(self, idx: int) -> int:
        if idx < 0:
            idx += self._length
        if idx < 0 or idx >= self._length:
            raise IndexError(idx)
        if idx == self._length - 1:
            return self._orig_end
        pos = bisect_right(self._norm_starts, idx) - 1
        return self._orig_starts[pos] + (idx - self._norm_starts[pos])


def normalize_for_match(text: str) -> str:
    """Normalize text using NFKC, Devanagari digit conversion, and zero-width stripping.
    
    Required contract: pure function returning normalized string.
    """
    if not text:
        return ""
    if text.isascii():
        return text
    translated = text.translate(_TRANS_TABLE)
    if unicodedata.is_normalized("NFKC", translated):
        return translated
    return unicodedata.normalize("NFKC", translated)


def normalize_with_map(text: str) -> Tuple[str, Sequence[int]]:
    """Normalize text and produce an offset map back to the original text.
    
    Returns:
        (normalized_text, index_map)
        where index_map[norm_idx] gives the corresponding original character index.
        index_map has length len(normalized_text) + 1 (the last element maps the end offset).
    """
    if not text:
        return "", [0]

    if text.isascii():
        return text, range(len(text) + 1)

    translated = text.translate(_TRANS_TABLE)
    if len(translated) == len(text) and unicodedata.is_normalized("NFKC", translated):
        return translated, range(len(text) + 1)

    norm_chunks: list[str] = []
    norm_starts: list[int] = []
    orig_starts: list[int] = []
    norm_pos = 0
    last_delta: int | None = None

    for seg_m in _ASCII_NONASCII_RE.finditer(text):
        a, b = seg_m.start(), seg_m.end()
        seg = seg_m.group(0)
        if seg.isascii():
            delta = a - norm_pos
            if delta != last_delta:
                norm_starts.append(norm_pos)
                orig_starts.append(a)
                last_delta = delta
            norm_chunks.append(seg)
            norm_pos += b - a
        else:
            sub_chars: list[str] = []
            for idx in range(a, b):
                ch = text[idx]
                if ch in ZERO_WIDTH_CHARS:
                    continue
                if ch in DEVA_DIGITS:
                    ch = DEVA_DIGITS[ch]
                elif ch in HOMOGLYPHS:
                    ch = HOMOGLYPHS[ch]
                nfkc_ch = unicodedata.normalize("NFKC", ch) if ord(ch) >= 128 else ch
                for sub_ch in nfkc_ch:
                    delta = idx - norm_pos
                    if delta != last_delta:
                        norm_starts.append(norm_pos)
                        orig_starts.append(idx)
                        last_delta = delta
                    sub_chars.append(sub_ch)
                    norm_pos += 1
            if sub_chars:
                norm_chunks.append("".join(sub_chars))

    norm_str = "".join(norm_chunks)
    return norm_str, _RunOffsetMap(norm_starts, orig_starts, norm_pos + 1, len(text))


def map_span_back(start: int, end: int, index_map: Sequence[int], orig_len: int) -> Tuple[int, int]:
    """Map a span [start, end) in normalized text back to [orig_start, orig_end) in original text."""
    if not index_map or start >= len(index_map):
        return start, end
    orig_start = index_map[start]
    # For end, map to the next character's original offset, or orig_len
    if end < len(index_map):
        orig_end = index_map[end]
    else:
        orig_end = orig_len
    return orig_start, min(orig_end, orig_len)
