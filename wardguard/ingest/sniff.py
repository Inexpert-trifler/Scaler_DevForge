"""Content-based format sniffing.

Implements TR-ING-2:
- Sniff format by content:
  - Empty (0 bytes) -> "unsupported"
  - PDF: magic b"%PDF" -> "unsupported"
  - JPEG: magic b"\\xff\\xd8\\xff" -> "unsupported"
  - PNG: magic b"\\x89PNG\\r\\n\\x1a\\n" -> "unsupported"
  - GIF: magic b"GIF87a" or b"GIF89a" -> "unsupported"
  - XML: starts with b"<?xml" or b"<" tag -> "unsupported"
  - Binary: null bytes (outside UTF-16) -> "unsupported"
  - JSON / FHIR: content that actually parses as JSON
  - CSV / TSV: consistent delimiter detection across multiple lines
  - Text: plain decodable text
"""
from __future__ import annotations
import json
import re
from typing import Optional
from wardguard.ingest.decode import decode
from wardguard.model import Fmt


def _has_consistent_delimiter(text: str, delimiter: str) -> bool:
    """Check if delimiter appears consistently on non-empty lines."""
    non_empty_lines = [line for line in text.splitlines() if line.strip()]
    if len(non_empty_lines) < 2:
        return False
    sample = non_empty_lines[:10]
    counts = [line.count(delimiter) for line in sample]
    if any(c < 1 for c in counts):
        return False
    # Check if delimiter count is identical or nearly identical across lines
    mode_count = max(set(counts), key=counts.count)
    if mode_count < 1:
        return False
    matching = sum(1 for c in counts if c == mode_count)
    return (matching / len(counts)) >= 0.70


def _is_json_lines(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return False
    for ln in lines[:200]:
        try:
            json.loads(ln)
        except Exception:
            return False
    return True


def sniff(raw: bytes, rel: str) -> Fmt:
    """Sniff file format from raw bytes and relative path."""
    if not raw or len(raw) == 0:
        return "unsupported"

    # 1. Magic bytes for known unsupported binary formats
    if raw.startswith(b"%PDF"):
        return "unsupported"
    if raw.startswith(b"\xff\xd8\xff"):
        return "unsupported"
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "unsupported"
    if raw.startswith((b"GIF87a", b"GIF89a")):
        return "unsupported"
    if raw.startswith((b"PK\x03\x04", b"\x1f\x8b")):  # ZIP, GZIP, docx, etc.
        return "unsupported"

    # Check for UTF-16 BOM
    is_utf16_bom = raw.startswith((b"\xff\xfe", b"\xfe\xff"))

    # Check for raw binary / null bytes if not UTF-16
    if not is_utf16_bom and b"\x00" in raw[:2048]:
        return "unsupported"

    # 2. Check XML / HTML
    clean_bytes = raw
    if clean_bytes.startswith(b"\xef\xbb\xbf"):
        clean_bytes = clean_bytes[3:]
    clean_strip = clean_bytes.lstrip()

    if clean_strip.startswith(b"<?xml") or clean_strip.startswith(b"<!DOCTYPE") or clean_strip.startswith(b"<!doctype"):
        return "unsupported"
    if clean_strip.startswith(b"<") and re.match(rb"^<[A-Za-z/!]", clean_strip):
        return "unsupported"

    # 3. Decode text safely using the standard decode pipeline
    decoded_res = decode(raw)
    lower_rel = rel.lower()
    is_txt_ext = lower_rel.endswith((".txt", ".text", ".note", ".md", ".log"))
    is_json_ext = lower_rel.endswith(".json")

    if decoded_res is None:
        # If undecodable but had a text or tabular extension, return the format so
        # readers.py can quarantine it with reason='undecodable'
        if is_txt_ext:
            return "text"
        if is_json_ext:
            return "json"
        if lower_rel.endswith(".tsv"):
            return "tsv"
        if lower_rel.endswith(".csv"):
            return "csv"
        return "unsupported"

    decoded_text, _enc = decoded_res
    stripped_text = decoded_text.strip()

    # 4. JSON / FHIR validation
    # If content begins with { or [, check if it actually parses as JSON
    if stripped_text.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped_text)
            if isinstance(parsed, dict) and parsed.get("resourceType") == "Bundle":
                return "fhir"
            return "json"
        except Exception:
            # NDJSON / JSON Lines: every non-empty line is its own JSON value. It is NOT a CSV
            # (commas inside objects are not delimiters). Treat it as text so values are
            # rewritten in place and every line stays valid JSON.
            if _is_json_lines(stripped_text):
                return "text"
            # Did not parse as JSON!
            # If it had a .json extension, return "json" so it will be quarantined as malformed/truncated
            if is_json_ext:
                return "json"
            # Otherwise, it's NOT JSON. Continue sniffing!

    elif is_json_ext:
        # A .json file that does not start with { or [ stays "json" so it is quarantined
        return "json"

    # 5. Extension check for known text extensions
    # If .txt/.text/.note/.md/.log and not valid JSON -> "text" BEFORE delimiter heuristic
    if is_txt_ext:
        return "text"

    # 6. For CSV / TSV extensions or unknown extensions, check delimiter consistency
    if _has_consistent_delimiter(decoded_text, "\t"):
        return "tsv"
    if _has_consistent_delimiter(decoded_text, ","):
        return "csv"

    # Filename fallback if delimiters were not strongly regular
    if lower_rel.endswith(".tsv"):
        return "tsv"
    if lower_rel.endswith(".csv"):
        return "csv"

    # Default to text if decodable
    return "text"
