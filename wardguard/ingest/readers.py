"""Robust readers for CSV, TSV, JSON, FHIR and Text.

Implements TR-ING-1, 4, 5, 6, 7, 8:
- Walk input tree deterministically sorted; never modify input.
- Content-based sniffing and multi-encoding decoding.
- CSV/TSV: detect delimiter, preserve header, handle ragged rows and quoted newlines.
- JSON: 1,500-deep nesting safe (iterative walk / raised recursion limit).
- Truncated / invalid JSON -> quarantine with 'malformed'.
- Unsupported formats (PDF, JPG, XML, binary, empty) -> quarantine with 'unsupported_format'.
- Undecodable bytes -> quarantine with 'undecodable'.
"""
from __future__ import annotations
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sys
from typing import List

from wardguard.ingest.decode import decode
from wardguard.ingest.sniff import sniff
from wardguard.model import ParsedFile
from wardguard.safety.log import safe_reason


def _is_safe_input_path(p: Path, root_resolved: Path) -> bool:
    """Return True only when p resolves inside root_resolved."""
    try:
        target = p.resolve()
        return target.is_relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError):
        return False


def load_all(input_dir: Path) -> List[ParsedFile]:
    """Read all files under input_dir recursively in deterministic sorted order."""
    results: List[ParsedFile] = []
    
    if not input_dir.exists():
        return results

    root_resolved = input_dir.resolve()
    paths: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(input_dir, followlinks=False):
        dirnames.sort()
        filenames.sort()
        dp = Path(dirpath)
        for name in filenames:
            p = dp / name
            if p.is_symlink() or p.is_file():
                paths.append(p)
    paths.sort(key=lambda p: p.relative_to(input_dir).as_posix())

    for p in paths:
        rel = p.relative_to(input_dir).as_posix()
        if p.is_symlink() and not _is_safe_input_path(p, root_resolved):
            results.append(
                ParsedFile(
                    rel=rel,
                    sha256="",
                    size=0,
                    fmt="unsupported",
                    status="quarantined",
                    reason="unsafe_symlink",
                )
            )
            continue
        if not p.is_file():
            results.append(
                ParsedFile(
                    rel=rel,
                    sha256="",
                    size=0,
                    fmt="unsupported",
                    status="quarantined",
                    reason="unsafe_symlink" if p.is_symlink() else "unsupported_format",
                )
            )
            continue
        try:
            raw = p.read_bytes()
        except Exception as e:
            results.append(
                ParsedFile(
                    rel=rel,
                    sha256="",
                    size=0,
                    fmt="unsupported",
                    status="quarantined",
                    reason=safe_reason(e),
                )
            )
            continue

        sha256_hash = hashlib.sha256(raw).hexdigest()
        size = len(raw)

        # Empty file check (TR-ING-2)
        if size == 0:
            results.append(
                ParsedFile(
                    rel=rel,
                    sha256=sha256_hash,
                    size=0,
                    fmt="unsupported",
                    status="quarantined",
                    reason="unsupported_format",
                )
            )
            continue

        fmt = sniff(raw, rel)

        if fmt == "unsupported":
            results.append(
                ParsedFile(
                    rel=rel,
                    sha256=sha256_hash,
                    size=size,
                    fmt=fmt,
                    status="quarantined",
                    reason="unsupported_format",
                )
            )
            continue

        decoded = decode(raw)
        if decoded is None:
            results.append(
                ParsedFile(
                    rel=rel,
                    sha256=sha256_hash,
                    size=size,
                    fmt=fmt,
                    status="quarantined",
                    reason="undecodable",
                )
            )
            continue

        text_content, encoding = decoded
        pf = ParsedFile(
            rel=rel,
            sha256=sha256_hash,
            size=size,
            fmt=fmt,
            encoding=encoding,
            status="pending",
        )

        try:
            if fmt in ("csv", "tsv"):
                delimiter = "\t" if fmt == "tsv" else ","
                # Detect delimiter using sniffer if possible
                sample = text_content[:4096]
                if fmt != "tsv" and ("," in sample or ";" in sample or "|" in sample):
                    try:
                        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
                        delimiter = dialect.delimiter
                    except Exception:
                        delimiter = ","

                # Parse rows with csv.reader (supports multi-line quoted cells)
                f = io.StringIO(text_content)
                reader = csv.reader(f, delimiter=delimiter)
                raw_rows = list(reader)

                if raw_rows:
                    pf.header = raw_rows[0]
                    # Handle ragged rows (TR-ING-4)
                    header_len = len(pf.header)
                    normalized_rows: List[List[str]] = []
                    for row in raw_rows[1:]:
                        if len(row) < header_len:
                            # Pad short rows with empty strings
                            padded = row + [""] * (header_len - len(row))
                            normalized_rows.append(padded)
                        else:
                            normalized_rows.append(row)
                    pf.rows = normalized_rows
                else:
                    pf.header = []
                    pf.rows = []
                pf.delimiter = delimiter

            elif fmt in ("json", "fhir"):
                # Safety for deep nesting up to 5,000 levels (TR-ING-5)
                orig_limit = sys.getrecursionlimit()
                try:
                    if orig_limit < 5000:
                        sys.setrecursionlimit(5000)
                    obj = json.loads(text_content)
                except (RecursionError, MemoryError):
                    pf.status = "quarantined"
                    pf.reason = "resource_limit"
                    results.append(pf)
                    continue
                except (json.JSONDecodeError, ValueError):
                    # Truncated or malformed JSON (TR-ING-6)
                    pf.status = "quarantined"
                    pf.reason = "malformed"
                    results.append(pf)
                    continue
                finally:
                    sys.setrecursionlimit(orig_limit)

                # FHIR R4 detection (TR-ING-7: resourceType == "Bundle")
                if isinstance(obj, dict) and obj.get("resourceType") == "Bundle":
                    pf.fmt = "fhir"
                pf.obj = obj

            else:  # text
                pf.text = text_content

            results.append(pf)

        except Exception as e:
            pf.status = "quarantined"
            pf.reason = safe_reason(e)
            results.append(pf)

    return results
