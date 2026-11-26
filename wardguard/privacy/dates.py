"""Date shifting and format preservation.

Implements TR-PRV-3 and TR-PRV-4:
- Deterministic per-patient date offset in [-max_days, max_days] \\ {0}.
- Format-preserving date shift supporting:
  - YYYY-MM-DD (ISO)
  - DD/MM/YYYY and MM/DD/YYYY (month-first inference / Arogya)
  - DD-MM-YYYY and DD.MM.YYYY
  - DD-Mon-YYYY (e.g. 12-Apr-2023, 12-APR-2023)
  - YYYY/MM/DD
  - Datetimes (e.g. 2023-04-12 14:30:00, 2023-04-12T14:30:00Z)
  - Devanagari digits (०-९ -> shifted -> ०-९)
"""
from __future__ import annotations
from datetime import datetime, timedelta
import hashlib
import hmac
import re
from typing import Optional, Tuple


DEVA_DIGITS = "०१२३४५६७८९"
ASCII_DIGITS = "0123456789"
DEVA_TO_ASCII = str.maketrans(DEVA_DIGITS, ASCII_DIGITS)
ASCII_TO_DEVA = str.maketrans(ASCII_DIGITS, DEVA_DIGITS)


def date_offset(key: str, secret: bytes, policy: dict) -> int:
    r"""Deterministic per-patient date offset in [-max_days, max_days] \ {0}."""
    max_days = policy.get("date_shift_max_days", 180)
    h = hmac.new(secret, f"shift|{key}".encode("utf-8"), hashlib.sha256).digest()
    num = int.from_bytes(h[:4], "big")
    span = 2 * max_days
    val = num % span  # 0 to 2*max_days - 1
    if val < max_days:
        offset = val - max_days  # -max_days to -1
    else:
        offset = (val - max_days) + 1  # 1 to max_days
    return offset


# Regexes for extracting date vs time
ISO_DT_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})([ T]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)$")
SLASH_DT_RE = re.compile(r"^(\d{2}/\d{2}/\d{4})([ T]\d{2}:\d{2}(?::\d{2})?)$")
DASH_MON_RE = re.compile(r"^(\d{1,2})-([A-Za-z]{3})-(\d{4})$")


def shift_date_text(s: str, offset: int, month_first: bool = False) -> Optional[str]:
    """Shift date string by offset days while strictly preserving original format."""
    if not s or offset == 0:
        return s

    raw = s.strip()
    has_deva = any(c in DEVA_DIGITS for c in raw)
    if has_deva:
        raw = raw.translate(DEVA_TO_ASCII)

    # 1. Check for datetime with ISO date
    m_iso_dt = ISO_DT_RE.match(raw)
    if m_iso_dt:
        date_part, time_part = m_iso_dt.group(1), m_iso_dt.group(2)
        try:
            dt = datetime.strptime(date_part, "%Y-%m-%d")
            shifted = dt + timedelta(days=offset)
            out = f"{shifted.strftime('%Y-%m-%d')}{time_part}"
            return out.translate(ASCII_TO_DEVA) if has_deva else out
        except ValueError:
            pass

    # 2. Check for datetime with slash date
    m_slash_dt = SLASH_DT_RE.match(raw)
    if m_slash_dt:
        date_part, time_part = m_slash_dt.group(1), m_slash_dt.group(2)
        fmt = "%m/%d/%Y" if month_first else "%d/%m/%Y"
        try:
            dt = datetime.strptime(date_part, fmt)
            shifted = dt + timedelta(days=offset)
            out = f"{shifted.strftime(fmt)}{time_part}"
            return out.translate(ASCII_TO_DEVA) if has_deva else out
        except ValueError:
            pass

    # 3. Check for DD-Mon-YYYY (e.g. 12-Apr-2023, 12-APR-2023)
    m_mon = DASH_MON_RE.match(raw)
    if m_mon:
        d_str, mon_str, y_str = m_mon.group(1), m_mon.group(2), m_mon.group(3)
        is_upper = mon_str.isupper()
        is_lower = mon_str.islower()
        try:
            # Parse month name
            dt = datetime.strptime(f"{int(d_str):02d}-{mon_str.capitalize()}-{y_str}", "%d-%b-%Y")
            shifted = dt + timedelta(days=offset)
            out_mon = shifted.strftime("%b")
            if is_upper:
                out_mon = out_mon.upper()
            elif is_lower:
                out_mon = out_mon.lower()
            pad = len(d_str)
            out_day = f"{shifted.day:0{pad}d}"
            out = f"{out_day}-{out_mon}-{shifted.year:04d}"
            return out.translate(ASCII_TO_DEVA) if has_deva else out
        except ValueError:
            pass

    # 4. Standard delimited date formats
    # Formats to attempt: (regex, format_str)
    candidate_formats: list[Tuple[re.Pattern, str]] = []

    if month_first:
        candidate_formats.append((re.compile(r"^\d{2}/\d{2}/\d{4}$"), "%m/%d/%Y"))
    else:
        candidate_formats.append((re.compile(r"^\d{2}/\d{2}/\d{4}$"), "%d/%m/%Y"))

    candidate_formats.extend([
        (re.compile(r"^\d{4}-\d{2}-\d{2}$"), "%Y-%m-%d"),
        (re.compile(r"^\d{2}-\d{2}-\d{4}$"), "%d-%m-%Y"),
        (re.compile(r"^\d{2}\.\d{2}\.\d{4}$"), "%d.%m.%Y"),
        (re.compile(r"^\d{4}/\d{2}/\d{2}$"), "%Y/%m/%d"),
    ])

    if not month_first:
        candidate_formats.append((re.compile(r"^\d{2}/\d{2}/\d{4}$"), "%m/%d/%Y"))
    else:
        candidate_formats.append((re.compile(r"^\d{2}/\d{2}/\d{4}$"), "%d/%m/%Y"))

    for pattern, fmt in candidate_formats:
        if pattern.match(raw):
            try:
                dt = datetime.strptime(raw, fmt)
                shifted = dt + timedelta(days=offset)
                out = shifted.strftime(fmt)
                return out.translate(ASCII_TO_DEVA) if has_deva else out
            except ValueError:
                continue

    return None
