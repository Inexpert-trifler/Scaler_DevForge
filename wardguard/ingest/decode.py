"""Encoding detection and decoding.

Implements TR-ING-3:
- Decode order:
  1. BOM check:
     - utf-8-sig (b"\\xef\\xbb\\xbf")
     - utf-16 (b"\\xff\\xfe" or b"\\xfe\\xff")
  2. Strict utf-8
  3. cp1252 (Windows-1252)
  4. Else None (quarantined as undecodable)
"""
from __future__ import annotations
from typing import Optional, Tuple


def decode(raw: bytes) -> Optional[Tuple[str, str]]:
    """Decode raw bytes trying BOM (utf-8-sig / utf-16), strict utf-8, then cp1252.
    
    Returns (decoded_text, encoding_name) or None if undecodable.
    """
    if not raw or len(raw) == 0:
        return "", "utf-8"

    # 1. BOM checks
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw.decode("utf-8-sig"), "utf-8-sig"
        except UnicodeDecodeError:
            pass

    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            pass

    # 2. Strict UTF-8
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass

    # 3. CP1252 (Windows-1252)
    # Binary with null bytes must not be falsely treated as cp1252 text
    if b"\x00" not in raw:
        try:
            return raw.decode("cp1252"), "cp1252"
        except UnicodeDecodeError:
            pass

    return None
