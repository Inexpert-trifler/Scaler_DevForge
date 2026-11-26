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
  - JSON / FHIR: starts with '{' or '[' (even behind .csv like mislabeled_export.csv)
  - CSV / TSV: delimiter detection
  - Text: plain decodable text
"""
from __future__ import annotations
import re
from typing import Optional
from wardguard.model import Fmt


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

    # Strip BOM for textual inspection
    clean = raw
    if clean.startswith(b"\xef\xbb\xbf"):
        clean = clean[3:]
    elif is_utf16_bom:
        try:
            decoded_prefix = raw[:4096].decode("utf-16", errors="ignore")
            # If UTF-16 decoded prefix starts with JSON or has delimiters
            clean_str = decoded_prefix.strip()
            if clean_str.startswith(("{", "[")):
                if '"resourceType"' in clean_str and '"Bundle"' in clean_str:
                    return "fhir"
                return "json"
            first_line = clean_str.split("\n", 1)[0]
            if "\t" in first_line:
                return "tsv"
            if "," in first_line:
                return "csv"
            lower_rel = rel.lower()
            if lower_rel.endswith(".tsv"):
                return "tsv"
            if lower_rel.endswith(".csv"):
                return "csv"
            return "text"
        except Exception:
            return "unsupported"

    clean = clean.lstrip()
    if not clean:
        return "unsupported"

    # 2. Check XML / HTML
    if clean.startswith(b"<?xml") or clean.startswith(b"<!DOCTYPE") or clean.startswith(b"<!doctype"):
        return "unsupported"
    if clean.startswith(b"<") and re.match(rb"^<[A-Za-z/!]", clean):
        return "unsupported"

    # 3. Content-based JSON / FHIR (even if filename is .csv, e.g. mislabeled_export.csv)
    if clean.startswith((b"{", b"[")):
        sample = clean[:4096]
        if b'"resourceType"' in sample and b'"Bundle"' in sample:
            return "fhir"
        return "json"

    # 4. Delimiter check in first lines
    first_chunk = clean[:4096]
    first_line = first_chunk.split(b"\n", 1)[0]

    tab_count = first_line.count(b"\t")
    comma_count = first_line.count(b",")

    lower_rel = rel.lower()

    if tab_count > 0 and tab_count >= comma_count:
        return "tsv"
    if comma_count > 0:
        return "csv"

    # 5. Filename hint fallback
    if lower_rel.endswith(".tsv"):
        return "tsv"
    if lower_rel.endswith(".csv"):
        return "csv"
    if lower_rel.endswith((".txt", ".text", ".note", ".md", ".log")):
        return "text"

    # 6. Verify if text decodable
    try:
        raw.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        try:
            raw.decode("cp1252")
            return "text"
        except UnicodeDecodeError:
            pass

    return "unsupported"
