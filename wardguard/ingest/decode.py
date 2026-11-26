"""Encoding detection and decoding."""
from typing import Optional, Tuple


def decode(raw: bytes) -> Optional[Tuple[str, str]]:
    """Decode raw bytes trying UTF-8, UTF-8 with BOM, UTF-16, and cp1252.
    
    Returns (decoded_text, encoding_name) or None if undecodable.
    """
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

    for enc in ("utf-8", "utf-16", "cp1252"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue

    return None
