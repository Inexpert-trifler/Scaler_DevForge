"""Identifier patterns, checksum validators, and detector.

Implements TR-DET-1, TR-DET-2:
- Verhoeff algorithm for 12-digit Aadhaar
- Masked Aadhaar (XXXX-XXXX-1234 or XXXXXXXXX1234)
- ABHA Number (14 digits, 2-digit groups: 12-3456-7890-1234)
- ABHA Address (username@abdm or username@sbx)
- PAN ([A-Z]{5}[0-9]{4}[A-Z])
- Phone (+91/0, spaces/dashes, 10-digit Indian numbers, masked 98XXXXXX10)
- Email
- MRN / UHID / IPD hospital identifiers
- PIN (6 digits with context or standalone boundary)
- House / Address tokens
"""
from __future__ import annotations
import re
from typing import Optional
from wardguard.model import EType, Mention, Script
from wardguard.detect.normalize import normalize_with_map, map_span_back

# ==============================================================================
# Verhoeff Checksum Algorithm for Aadhaar (TR-DET-1)
# ==============================================================================

# The multiplication table (d)
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# The permutation table (p)
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def validate_verhoeff(num_str: str) -> bool:
    """Validate a numeric string with the Verhoeff checksum.
    
    Returns True if checksum passes, False otherwise.
    Example positive: '984521367098' (if valid)
    Example negative: '123456789012'
    """
    if not num_str.isdigit():
        return False
    c = 0
    # Process digits in reverse order
    for i, digit in enumerate(reversed(num_str)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(digit)]]
    return c == 0


def generate_verhoeff_check_digit(num_str: str) -> int:
    """Calculate the Verhoeff check digit for a string of digits."""
    c = 0
    for i, digit in enumerate(reversed(num_str)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(digit)]]
    # Invert
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    return inv[c]


# ==============================================================================
# Pre-compiled Regular Expressions
# ==============================================================================

# --- AADHAAR ---
# 12 digits, first digit 2-9, optional spaces/dashes every 4 digits
# POS: "9845 2136 7098" | NEG: "0123 4567 8901" (first digit 0/1 not allowed in Aadhaar)
RE_AADHAAR = re.compile(r'(?<!\d)([2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4})(?!\d)')

# --- AADHAAR_MASKED ---
# 8 masked digits/X followed by 4 digits, or 4-4-4 format with X
# POS: "XXXXXXXX1234", "XXXX-XXXX-1234", "xxxx xxxx 4567" | NEG: "XXXX-1234"
RE_AADHAAR_MASKED = re.compile(r'(?<![A-Za-z0-9])([xX*]{4}[-\s]?[xX*]{4}[-\s]?\d{4}|[xX*]{8}[-\s]?\d{4})(?!\d)')

# --- ABHA_NUMBER ---
# 14 digits, typically in 2-digit groups or 2-4-4-4 format: 14-1234-5678-9012 or 14123456789012
# POS: "14-1234-5678-9012" | NEG: "12345"
RE_ABHA_NUMBER = re.compile(r'(?<!\d)(1[1-9][-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})(?!\d)')

# --- ABHA_ADDRESS ---
# Username at abdm/sbx/phr
# POS: "rahul.sharma@abdm", "sunita123@sbx" | NEG: "test@gmail.com"
RE_ABHA_ADDRESS = re.compile(r'(?i)\b([a-zA-Z0-9_.]{3,32}@(abdm|sbx|phr|eash)\b)')

# --- PAN ---
# 5 letters, 4 digits, 1 letter. 4th letter is status (P, C, H, A, B, G, J, L, F, T)
# POS: "ABCDE1234F" | NEG: "ABC123456D"
RE_PAN = re.compile(r'(?<![A-Za-z0-9])([A-Z]{5}\d{4}[A-Z])(?![A-Za-z0-9])')

# --- PHONE ---
# Indian mobile numbers: starts with 6-9, optionally preceded by +91 or 0, with spaces/dashes
# Also masked forms: 98XXXXXX10
# POS: "+91 98765 43210", "098765-43210", "9876543210", "98XXXXXX10" | NEG: "650mg", "1-0-1", "150/90"
RE_PHONE = re.compile(r'(?<!\d)(?:(?:\+91|91|0)[-\s]?)?([6-9]\d{2}[-\s]?\d{3}[-\s]?\d{4}|[6-9]\d{4}[-\s]?\d{5}|[6-9]\d[xX*]{6}\d{2})(?!\d)')

# --- EMAIL ---
# Standard generic email pattern
# POS: "patient.care@hospital.org" | NEG: "@nodomain"
RE_EMAIL = re.compile(r'(?i)\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')

# --- MRN / HOSPITAL IDENTIFIERS ---
# Generic healthcare identifier formats:
# UHID-123456, ADM/24/1234, IP-23-4567, SNJ/26/064127, CR-987654, REGNO-123456
# POS: "SNJ/26/064127", "UHID-9876543", "IP-24-9081", "ADM2024001" | NEG: "BP 120/80", "1-0-1"
RE_MRN = re.compile(
    r'(?i)\b('
    r'(?:UHID|MRN|IPD?|OPD|ADM|REG|CR|PAT|IP)[-\s#/:]*[A-Z0-9]{2,6}(?:[/-][A-Z0-9]+){1,3}'
    r'|(?:UHID|MRN|IPD?|OPD|ADM|CRNO?)[-\s#/:]*\d{4,10}'
    r'|[A-Z]{2,4}/\d{2}/\d{4,8}'
    r'|[A-Z]{2,5}-\d{4,10}'
    r')\b'
)

# --- INSURANCE_ID ---
# Ayushman Bharat PM-JAY (e.g., PMJAY-..., AB-PMJAY-...), or policy numbers
# POS: "PMJAY-123456789", "ABPMJAY-987654321", "POL-987654321" | NEG: "OD 1 tab"
RE_INSURANCE = re.compile(
    r'(?i)\b('
    r'(?:PMJAY|AB-?PMJAY|INS|POLICY)[-\s#/:]*[A-Z0-9]{6,16}'
    r'|[A-Z]{2,4}/POL/\d{4,12}'
    r')\b'
)

# --- HOUSE / RESIDENTIAL TOKENS ---
# H.No. 123, House No 45/A, Flat 3B, Plot No. 89, मकान नं 45
# POS: "H.No. 364", "House No. 12/A", "Flat No 4B", "मकान नं. 78" | NEG: "x 5 days"
RE_HOUSE = re.compile(
    r'(?i)\b('
    r'(?:H\.?\s*No\.?|House\s*No\.?|Flat\s*No\.?|Plot\s*No\.?|मकान\s*नं\.?|मकान\s*नंबर)\s*[:#-]?\s*[A-Za-z0-9/,-]+'
    r')\b'
)

# --- PIN CODE ---
# 6 digits: first digit 1-8, with context or specific pin indicators
# POS: "PIN: 229073", "Pin code 226001", "Pincode: 208016" | NEG: "100000" (round number), "250000"
RE_PIN_WITH_LABEL = re.compile(r'(?i)\b(?:pin(?:\s*code)?|pincode|पिन\s*कोड?)\s*[:#-]?\s*([1-8]\d{5})\b')
RE_PIN_STANDALONE = re.compile(r'(?<!\d)([1-8]\d{5})(?!\d)')


def _detect_script(text: str) -> Script:
    """Detect whether text is Latin, Devanagari, or Hinglish."""
    has_deva = any('\u0900' <= ch <= '\u097f' for ch in text)
    has_latin = any('a' <= ch.lower() <= 'z' for ch in text)
    if has_deva and not has_latin:
        return "deva"
    if has_deva and has_latin:
        return "hinglish"
    return "latin"


def find_identifiers(text: str) -> list[Mention]:
    """Scan text for identifier patterns with verification and index mapping.
    
    Required contract: returns non-overlapping Mention objects sorted by start offset.
    Applies Verhoeff checksum for 12-digit Aadhaar.
    """
    if not text:
        return []

    norm_text, index_map = normalize_with_map(text)
    orig_len = len(text)
    raw_mentions: list[Mention] = []

    # 1. AADHAAR_MASKED
    for m in RE_AADHAAR_MASKED.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_text = text[start:end]
        raw_mentions.append(Mention(
            etype=EType.AADHAAR_MASKED,
            start=start,
            end=end,
            text=span_text,
            script=_detect_script(span_text),
            channel="content",
            role="patient",
            source="regex",
            confidence=0.98,
        ))

    # 2. AADHAAR (12 digits with Verhoeff verification)
    for m in RE_AADHAAR.finditer(norm_text):
        match_str = m.group(1)
        digits_only = re.sub(r'[-\s]', '', match_str)
        if len(digits_only) == 12 and validate_verhoeff(digits_only):
            start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
            span_text = text[start:end]
            raw_mentions.append(Mention(
                etype=EType.AADHAAR,
                start=start,
                end=end,
                text=span_text,
                script=_detect_script(span_text),
                channel="content",
                role="patient",
                source="regex",
                confidence=0.99,
            ))

    # 3. ABHA_NUMBER
    for m in RE_ABHA_NUMBER.finditer(norm_text):
        match_str = m.group(1)
        digits_only = re.sub(r'[-\s]', '', match_str)
        if len(digits_only) == 14:
            start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
            span_text = text[start:end]
            raw_mentions.append(Mention(
                etype=EType.ABHA_NUMBER,
                start=start,
                end=end,
                text=span_text,
                script=_detect_script(span_text),
                channel="content",
                role="patient",
                source="regex",
                confidence=0.98,
            ))

    # 4. ABHA_ADDRESS
    for m in RE_ABHA_ADDRESS.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_text = text[start:end]
        raw_mentions.append(Mention(
            etype=EType.ABHA_ADDRESS,
            start=start,
            end=end,
            text=span_text,
            script=_detect_script(span_text),
            channel="content",
            role="patient",
            source="regex",
            confidence=0.99,
        ))

    # 5. PAN
    for m in RE_PAN.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_text = text[start:end]
        raw_mentions.append(Mention(
            etype=EType.PAN,
            start=start,
            end=end,
            text=span_text,
            script=_detect_script(span_text),
            channel="content",
            role="patient",
            source="regex",
            confidence=0.98,
        ))

    # 6. PHONE
    for m in RE_PHONE.finditer(norm_text):
        full_match = m.group(0)
        # Avoid common clinical traps: doses (650mg), frequencies (1-0-1), ratios (150/90)
        if re.search(r'(?i)(mg|ml|mcg|tab|cap|dose|bp|bpm|mmhg|/min)', full_match):
            continue
        start, end = map_span_back(m.start(0), m.end(0), index_map, orig_len)
        span_text = text[start:end]
        raw_mentions.append(Mention(
            etype=EType.PHONE,
            start=start,
            end=end,
            text=span_text,
            script=_detect_script(span_text),
            channel="content",
            role="unknown",
            source="regex",
            confidence=0.95,
        ))

    # 7. EMAIL
    for m in RE_EMAIL.finditer(norm_text):
        # If already matched as ABHA_ADDRESS, skip
        if any(dom in m.group(1).lower() for dom in ["@abdm", "@sbx", "@phr"]):
            continue
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_text = text[start:end]
        raw_mentions.append(Mention(
            etype=EType.EMAIL,
            start=start,
            end=end,
            text=span_text,
            script=_detect_script(span_text),
            channel="content",
            role="unknown",
            source="regex",
            confidence=0.99,
        ))

    # 8. INSURANCE_ID
    for m in RE_INSURANCE.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_text = text[start:end]
        raw_mentions.append(Mention(
            etype=EType.INSURANCE_ID,
            start=start,
            end=end,
            text=span_text,
            script=_detect_script(span_text),
            channel="content",
            role="patient",
            source="regex",
            confidence=0.95,
        ))

    # 9. MRN
    for m in RE_MRN.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_text = text[start:end]
        raw_mentions.append(Mention(
            etype=EType.MRN,
            start=start,
            end=end,
            text=span_text,
            script=_detect_script(span_text),
            channel="content",
            role="patient",
            source="regex",
            confidence=0.95,
        ))

    # 10. HOUSE
    for m in RE_HOUSE.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_text = text[start:end]
        raw_mentions.append(Mention(
            etype=EType.HOUSE,
            start=start,
            end=end,
            text=span_text,
            script=_detect_script(span_text),
            channel="content",
            role="patient",
            source="regex",
            confidence=0.95,
        ))

    # 11. PIN (with label preferred)
    for m in RE_PIN_WITH_LABEL.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_text = text[start:end]
        raw_mentions.append(Mention(
            etype=EType.PIN,
            start=start,
            end=end,
            text=span_text,
            script=_detect_script(span_text),
            channel="content",
            role="patient",
            source="regex",
            confidence=0.95,
        ))

    # Resolve overlapping spans (longest span wins; on tie, highest priority EType wins)
    return resolve_overlaps(raw_mentions)


# Type priority ranking for tie-breaking
_ETYPE_PRIORITY = {
    EType.AADHAAR: 100,
    EType.AADHAAR_MASKED: 95,
    EType.ABHA_NUMBER: 90,
    EType.ABHA_ADDRESS: 85,
    EType.PAN: 80,
    EType.INSURANCE_ID: 75,
    EType.MRN: 70,
    EType.PHONE: 65,
    EType.EMAIL: 60,
    EType.HOUSE: 55,
    EType.PIN: 50,
}


def resolve_overlaps(mentions: list[Mention]) -> list[Mention]:
    """Sort and resolve overlapping spans: longer span wins; tie-break by priority."""
    if not mentions:
        return []

    # Sort primarily by start asc, length desc, priority desc
    def sort_key(m: Mention):
        length = m.end - m.start
        priority = _ETYPE_PRIORITY.get(m.etype, 0)
        return (m.start, -length, -priority)

    sorted_mentions = sorted(mentions, key=sort_key)
    resolved: list[Mention] = []

    last_end = -1
    for m in sorted_mentions:
        if m.start >= last_end:
            resolved.append(m)
            last_end = m.end
        else:
            # Overlap detected: check if current is strictly longer or higher priority
            prev = resolved[-1]
            prev_len = prev.end - prev.start
            curr_len = m.end - m.start
            prev_prio = _ETYPE_PRIORITY.get(prev.etype, 0)
            curr_prio = _ETYPE_PRIORITY.get(m.etype, 0)

            if curr_len > prev_len or (curr_len == prev_len and curr_prio > prev_prio):
                resolved[-1] = m
                last_end = m.end

    return sorted(resolved, key=lambda m: (m.start, m.end))
