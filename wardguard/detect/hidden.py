"""Hidden channels slot extractor and filename renaming engine.

Implements TR-DET-9 and TR-EXP-2:
- Extract hidden slots:
  - @filename (stem) with channel="filename"
  - @header:<index> with channel="header"
  - @key:<pointer>/<key> with channel="key"
  - Metadata pointers (source_path, export_meta, etc.) with channel="metadata"
  - Base64 payloads decoded to printable text -> slot <path>#b64
  - Encoded sequences (\\uXXXX, HTML entities, %-encoding) decoded -> slot <path>#decoded
- File renaming for files with PII in @filename:
  - Replaces detected mentions in stem with tokens (e.g. [PHONE]_report_0047.json)
  - Collision resolution using file_<sha8>.<ext>
  - Stores mapping in pf.out_rel
"""
from __future__ import annotations
import base64
import html
from pathlib import Path
import re
from typing import Any, List, Optional, Set

from wardguard.ingest.units import escape_pointer_segment
from wardguard.model import Channel, ParsedFile, Slot


METADATA_KEY_PATTERNS = {
    "source_path", "source", "exported_by", "exported_at", "creator", "created_by",
    "operator", "system_id", "facility_name", "generator", "meta"
}


def is_metadata_path(path: str) -> bool:
    """Check if slot path corresponds to a known metadata pointer."""
    lower = path.lower()
    return any(m in lower for m in METADATA_KEY_PATTERNS)


def try_decode_base64(val: str) -> Optional[str]:
    """If val is valid base64 encoding printable UTF-8 text, return decoded string."""
    clean = val.strip()
    if len(clean) < 8 or len(clean) % 4 != 0:
        return None
    if not re.match(r"^[A-Za-z0-9+/]+={0,2}$", clean):
        return None
    try:
        decoded_bytes = base64.b64decode(clean, validate=True)
        text = decoded_bytes.decode("utf-8")
        if any(c.isalpha() for c in text) and all(c.isprintable() or c in "\r\n\t" for c in text):
            return text
    except Exception:
        pass
    return None


def decode_escape_sequences(text: str) -> Optional[str]:
    """Decode HTML entities, %-encoding, and \\uXXXX escapes if present."""
    if not text:
        return None
    decoded = text

    # 1. HTML entities (e.g. &amp;, &#65;, &#x41;)
    if "&" in decoded and ";" in decoded:
        try:
            decoded = html.unescape(decoded)
        except Exception:
            pass

    # 2. URL %-encoding (e.g. %20, %41)
    if "%" in decoded and re.search(r"%[0-9a-fA-F]{2}", decoded):
        try:
            decoded = re.sub(
                r"%([0-9a-fA-F]{2})",
                lambda m: chr(int(m.group(1), 16)),
                decoded,
            )
        except Exception:
            pass

    # 3. Unicode escapes \\uXXXX
    if "\\u" in decoded and re.search(r"(?i)\\u[0-9a-f]{4}", decoded):
        try:
            decoded = decoded.encode("utf-8").decode("unicode_escape")
        except Exception:
            pass

    if decoded != text:
        return decoded
    return None


def extract_json_keys(obj: Any, parent_pointer: str = "") -> List[tuple[str, str]]:
    """Iteratively collect (path, key_text) for all dictionary keys (stack-safe for deep JSON)."""
    keys: List[tuple[str, str]] = []
    stack: list[tuple[Any, str]] = [(obj, parent_pointer)]
    while stack:
        cur_obj, cur_ptr = stack.pop()
        if isinstance(cur_obj, dict):
            # Collect keys at this level in forward order, push children in reverse so pop order is forward
            children: list[tuple[Any, str]] = []
            for k, v in cur_obj.items():
                k_str = str(k)
                escaped_k = escape_pointer_segment(k_str)
                slot_path = f"@key:{cur_ptr}/{escaped_k}" if cur_ptr else f"@key:/{escaped_k}"
                keys.append((slot_path, k_str))
                if isinstance(v, (dict, list)):
                    child_ptr = f"{cur_ptr}/{escaped_k}" if cur_ptr else f"/{escaped_k}"
                    children.append((v, child_ptr))
            for child in reversed(children):
                stack.append(child)
        elif isinstance(cur_obj, list):
            for idx in range(len(cur_obj) - 1, -1, -1):
                item = cur_obj[idx]
                if isinstance(item, (dict, list)):
                    stack.append((item, f"{cur_ptr}/{idx}"))
    return keys


def extract_hidden_slots(pf: ParsedFile) -> None:
    """Extract slots from hidden channels: filename, headers, metadata, keys, base64."""
    if pf.status != "pending":
        return

    # Clear existing file_slots to ensure idempotency
    pf.file_slots = []

    # 1. Add @filename slot (stem of the relative path)
    p = Path(pf.rel)
    stem = p.stem
    pf.file_slots.append(
        Slot(
            path="@filename",
            text=stem,
            channel="filename",
            value_type="str",
        )
    )

    # 1b. Add @dirname slot: folder names leak too ("scans/Sunita_Yadav/visit.txt")
    parent = p.parent.as_posix()
    if parent and parent != ".":
        pf.file_slots.append(
            Slot(
                path="@dirname",
                text=parent,
                channel="filename",
                value_type="str",
            )
        )

    # 2. Add @header:<index> slots for CSV/TSV
    if pf.header:
        for idx, h in enumerate(pf.header):
            clean_h = h.strip() if h else ""
            if clean_h:
                pf.file_slots.append(
                    Slot(
                        path=f"@header:{idx}",
                        text=clean_h,
                        channel="header",
                        value_type="str",
                    )
                )

    # 3. Add @key:<pointer>/<key> slots for JSON / FHIR
    if pf.fmt in ("json", "fhir") and pf.obj is not None:
        json_keys = extract_json_keys(pf.obj)
        for key_path, key_text in json_keys:
            pf.file_slots.append(
                Slot(
                    path=key_path,
                    text=key_text,
                    channel="key",
                    value_type="str",
                )
            )

    # 4. Check all unit slots for metadata pointers, base64 payloads, and escape sequences
    for u in pf.units:
        additional_slots: List[Slot] = []
        for s in u.slots:
            # Metadata classification
            if is_metadata_path(s.path) and s.channel == "content":
                s.channel = "metadata"

            # Base64 payload detection
            b64_text = try_decode_base64(s.text)
            if b64_text:
                additional_slots.append(
                    Slot(
                        path=f"{s.path}#b64",
                        text=b64_text,
                        channel="base64",
                        value_type="str",
                    )
                )

            # Escape sequences (\uXXXX, %XX, HTML entities)
            decoded_text = decode_escape_sequences(s.text)
            if decoded_text:
                additional_slots.append(
                    Slot(
                        path=f"{s.path}#decoded",
                        text=decoded_text,
                        channel=s.channel,
                        value_type="str",
                    )
                )

        u.slots.extend(additional_slots)


def apply_filename_renaming(files: List[ParsedFile], policy: Optional[dict] = None) -> None:
    """Rename files whose @filename slot has detected PII mentions.
    
    Implements TR-EXP-2:
    - Replaces detected spans in stem with tokens (e.g. [PHONE]_report_0047.json)
    - If collision occurs with an already assigned release path, uses file_<sha8>.<ext>
    - Assigns pf.out_rel for sanitized writing
    """
    token_map = {
        "PATIENT_NAME": "[NAME]",
        "RELATIVE_NAME": "[RELATIVE]",
        "PHONE": "[PHONE]",
        "AADHAAR": "[AADHAAR]",
        "AADHAAR_MASKED": "[AADHAAR]",
        "PAN": "[PAN]",
        "MRN": "[MRN]",
        "ABHA_NUMBER": "[ABHA]",
        "ABHA_ADDRESS": "[ABHA]",
        "EMAIL": "[EMAIL]",
        "INSURANCE_ID": "[INSURANCE]",
    }
    if policy and "tokens" in policy:
        token_map.update(policy["tokens"])

    def _replace(text: str, slot: Optional[Slot]) -> str:
        if not slot or not slot.mentions:
            return text
        out = text
        for m in sorted(slot.mentions, key=lambda m: (m.start, m.end), reverse=True):
            etype_key = m.etype.value if hasattr(m.etype, "value") else str(m.etype)
            rep = token_map.get(etype_key, f"[{etype_key}]")
            out = out[:m.start] + rep + out[m.end:]
        return out

    # Phase 1: desired output path for every pending file (sanitized stem AND folders)
    desired: list[tuple[ParsedFile, str]] = []
    for pf in (f for f in files if f.status == "pending"):  # load_all order is already deterministic
        p = Path(pf.rel)
        fn_slot = next((fs for fs in pf.file_slots if fs.path == "@filename"), None)
        dir_slot = next((fs for fs in pf.file_slots if fs.path == "@dirname"), None)
        parent_dir = p.parent.as_posix()
        new_parent = _replace(parent_dir, dir_slot) if parent_dir != "." else "."
        new_stem = _replace(p.stem, fn_slot)
        rel_out = f"{new_parent}/{new_stem}{p.suffix}" if new_parent != "." else f"{new_stem}{p.suffix}"
        desired.append((pf, f"sanitized/{rel_out}"))

    # Phase 2: deterministic collision resolution. Untouched paths are claimed first so a
    # renamed file can never overwrite (or be overwritten by) a file that kept its name.
    used_paths: Set[str] = set()
    unchanged = [(pf, t) for pf, t in desired if t == f"sanitized/{pf.rel}"]
    changed = [(pf, t) for pf, t in desired if t != f"sanitized/{pf.rel}"]
    for pf, target in unchanged + changed:
        if target in used_paths:
            parent = target.rsplit("/", 1)[0]
            suffix = Path(target).suffix
            sha8 = pf.sha256[:8] if pf.sha256 else "00000000"
            target = f"{parent}/file_{sha8}{suffix}"
            n = 2
            while target in used_paths:
                target = f"{parent}/file_{sha8}_{n}{suffix}"
                n += 1
        pf.out_rel = target
        used_paths.add(target)
