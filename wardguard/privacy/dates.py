"""Date shifting and format preservation."""
from datetime import datetime, timedelta
import hashlib
import hmac
import re
from typing import Optional


def date_offset(key: str, secret: bytes, policy: dict) -> int:
    r"""Deterministic per-patient date offset in [-max_days, max_days] \ {0}."""
    max_days = policy.get("date_shift_max_days", 180)
    h = hmac.new(secret, f"shift|{key}".encode("utf-8"), hashlib.sha256).digest()
    val = int.from_bytes(h[:4], "big")
    span = 2 * max_days
    offset = (val % span) - max_days
    if offset == 0:
        offset = 1
    return offset


DATE_PATTERNS = [
    (re.compile(r"^\d{4}-\d{2}-\d{2}$"), "%Y-%m-%d"),
    (re.compile(r"^\d{2}/\d{2}/\d{4}$"), "%d/%m/%Y"),
    (re.compile(r"^\d{2}-\d{2}-\d{4}$"), "%d-%m-%Y"),
    (re.compile(r"^\d{2}\.\d{2}\.\d{4}$"), "%d.%m.%Y"),
]


def shift_date_text(s: str, offset: int) -> Optional[str]:
    """Shift date string by offset days while strictly preserving original format."""
    s_strip = s.strip()
    for pattern, fmt in DATE_PATTERNS:
        if pattern.match(s_strip):
            try:
                dt = datetime.strptime(s_strip, fmt)
                shifted = dt + timedelta(days=offset)
                return shifted.strftime(fmt)
            except ValueError:
                continue
    return None
