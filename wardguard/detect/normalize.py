"""Text normalization and index-mapping utilities.

Handles NFKC normalization, Devanagari digits to ASCII, zero-width stripping,
and homoglyph folding while maintaining an exact index mapping back to original offsets.
"""
from __future__ import annotations
import unicodedata
from typing import Tuple

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


def normalize_for_match(text: str) -> str:
    """Normalize text using NFKC, Devanagari digit conversion, and zero-width stripping.
    
    Required contract: pure function returning normalized string.
    """
    norm, _ = normalize_with_map(text)
    return norm


def normalize_with_map(text: str) -> Tuple[str, list[int]]:
    """Normalize text and produce an offset map back to the original text.
    
    Returns:
        (normalized_text, index_map)
        where index_map[norm_idx] gives the corresponding original character index.
        index_map has length len(normalized_text) + 1 (the last element maps the end offset).
    """
    if not text:
        return "", [0]

    # Step 1: Pre-process characters (strip zero-width, fold Devanagari digits & homoglyphs)
    # Track original index for each character
    step1_chars: list[str] = []
    step1_orig_indices: list[int] = []

    for orig_idx, ch in enumerate(text):
        if ch in ZERO_WIDTH_CHARS:
            continue
        if ch in DEVA_DIGITS:
            ch = DEVA_DIGITS[ch]
        elif ch in HOMOGLYPHS:
            ch = HOMOGLYPHS[ch]
        
        step1_chars.append(ch)
        step1_orig_indices.append(orig_idx)

    # Step 2: Apply NFKC normalization char-by-char or chunk-by-chunk to maintain accurate maps
    norm_chars: list[str] = []
    norm_to_orig_map: list[int] = []

    for ch, orig_idx in zip(step1_chars, step1_orig_indices):
        nfkc_ch = unicodedata.normalize("NFKC", ch)
        for sub_ch in nfkc_ch:
            norm_chars.append(sub_ch)
            norm_to_orig_map.append(orig_idx)

    # Append sentinel mapping for the end index
    norm_to_orig_map.append(len(text))
    return "".join(norm_chars), norm_to_orig_map


def map_span_back(start: int, end: int, index_map: list[int], orig_len: int) -> Tuple[int, int]:
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
