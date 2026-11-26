"""Rewrite engine for applying mentions and pseudonyms.

Implements format-preserving reconstruction:
- CSV/TSV: preserves delimiter, header, quotes multi-line cells and commas via csv.writer.
- JSON/FHIR: preserves JSON structure, types (int, float, bool, null, str), and key order.
- Text: UTF-8 encoding.
"""
from __future__ import annotations
import copy
import csv
import io
import json
from typing import Any
from wardguard.model import ParsedFile, Slot


def set_json_pointer(obj: Any, pointer: str, val_text: str, val_type: str) -> None:
    """Set the value at an RFC 6901 pointer in a JSON object, preserving primitive type."""
    if not pointer.startswith("/"):
        return
    parts = pointer[1:].split("/")
    # RFC 6901 unescaping: ~1 -> /, ~0 -> ~
    parts = [p.replace("~1", "/").replace("~0", "~") for p in parts]

    cur = obj
    for p in parts[:-1]:
        if isinstance(cur, list):
            try:
                idx = int(p)
                cur = cur[idx]
            except (ValueError, IndexError):
                return
        elif isinstance(cur, dict):
            if p in cur:
                cur = cur[p]
            else:
                return
        else:
            return

    last_p = parts[-1]
    typed_val: Any = val_text
    if val_type == "int":
        try:
            typed_val = int(val_text)
        except ValueError:
            typed_val = val_text
    elif val_type == "float":
        try:
            typed_val = float(val_text)
        except ValueError:
            typed_val = val_text
    elif val_type == "bool":
        typed_val = val_text.lower() in ("true", "1")
    elif val_type == "null":
        typed_val = None

    if isinstance(cur, list):
        try:
            idx = int(last_p)
            cur[idx] = typed_val
        except (ValueError, IndexError):
            pass
    elif isinstance(cur, dict):
        cur[last_p] = typed_val


def render(pf: ParsedFile, policy: dict) -> bytes:
    """Render sanitized bytes from ParsedFile and policy."""
    if pf.fmt in ("csv", "tsv"):
        delimiter = pf.delimiter or ("," if pf.fmt == "csv" else "\t")
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=delimiter, lineterminator="\n")
        if pf.header is not None:
            writer.writerow(pf.header)
        if pf.units:
            for u in pf.units:
                row_vals = [s.text for s in u.slots]
                writer.writerow(row_vals)
        elif pf.rows is not None:
            for row in pf.rows:
                writer.writerow(row)
        return buf.getvalue().encode("utf-8")

    elif pf.fmt in ("json", "fhir"):
        if pf.obj is not None:
            obj_to_write = copy.deepcopy(pf.obj)
            # Apply any updated slot values back into the JSON structure
            if pf.units:
                for u in pf.units:
                    for s in u.slots:
                        if s.path.startswith("/"):
                            set_json_pointer(obj_to_write, s.path, s.text, s.value_type)
            return json.dumps(obj_to_write, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
        return b"{}\n"

    else:  # text
        if pf.units and pf.units[0].slots:
            return pf.units[0].slots[0].text.encode("utf-8")
        if pf.text is not None:
            return pf.text.encode("utf-8")
        return b""
