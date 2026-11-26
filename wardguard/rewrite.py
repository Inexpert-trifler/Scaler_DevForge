"""Rewrite engine for applying mentions and pseudonyms.

Implements format-preserving reconstruction and mention application:
- Mentions applied right-to-left per slot (preventing offset drift).
- Whole-cell replacement when slot.column_type is set.
- PSN placement (D-010, TR-PRV-2):
    - CSV: patient-name cell, or UHID cell if no name column. No new columns.
    - JSON: patient name field, or UHID field.
    - Text: replace patient-name mentions; prepend "Patient: PSN-XXXXXX\n" if no patient name.
    - FHIR: Patient.identifier / Patient.name.
- Quasi-identifier handling:
    - DATE: shifted by unit.date_offset, format preserved.
    - DOB: 4-digit year (policy dob_action == 'year') or shifted.
    - AGE: 5-year band containing true age, 90+ top-coded; numeric JSON fields keep band lower bound.
    - PIN: prefix 3 digits kept, remainder masked (e.g. 229***).
    - VILLAGE: generalized according to policy.village_action (tehsil/district/remove).
- Direct identifiers:
    - PATIENT_NAME -> unit.psn (if available) else "[NAME]"
    - RELATIVE_NAME -> "[RELATIVE]"
    - OTHER_PERSON -> "[NAME]"
    - CANARY -> "[CANARY]"
    - PHONE, AADHAAR, PAN, MRN, etc. -> tokens (or 0 for numeric JSON fields).
- Format preservation:
    - CSV/TSV: preserves delimiter, header, quotes multi-line cells and commas via csv.writer.
    - JSON/FHIR: preserves JSON structure, primitive types (int, float, bool, null, str), key order.
    - Text: UTF-8 encoding.
"""
from __future__ import annotations

import base64
import csv
import io
import json
import re
import sys
from typing import Any, List, Optional

from wardguard.detect.patterns import resolve_overlaps
from wardguard.model import DIRECT, EType, Mention, ParsedFile, Slot, Unit
from wardguard.privacy.dates import shift_date_text
from wardguard.privacy.generalize import age_band, generalize_pin, generalize_village


def get_replacement(
    etype: EType | str | None,
    text: str,
    unit: Optional[Unit],
    policy: dict,
    is_numeric: bool = False,
    is_psn_target: bool = False,
) -> str:
    """Return the replacement string for an entity mention or classified cell."""
    if etype is None:
        return text

    tokens = policy.get("tokens", {})

    # If this slot or mention is the designated PSN target for the unit
    if is_psn_target and unit and unit.psn:
        return unit.psn

    etype_str = etype.value if hasattr(etype, "value") else str(etype)

    # 1. Direct Identifiers
    if etype_str == "PATIENT_NAME":
        if unit and unit.psn:
            return unit.psn
        return tokens.get("PATIENT_NAME", "[NAME]")

    elif etype_str == "RELATIVE_NAME":
        return tokens.get("RELATIVE_NAME", "[RELATIVE]")

    elif etype_str == "OTHER_PERSON":
        return tokens.get("OTHER_PERSON", "[NAME]")

    elif etype_str == "CANARY":
        return tokens.get("CANARY", "[CANARY]")

    elif etype_str == "PHONE":
        return "0" if is_numeric else tokens.get("PHONE", "[PHONE]")

    elif etype_str in ("AADHAAR", "AADHAAR_MASKED"):
        return "0" if is_numeric else tokens.get("AADHAAR", "[AADHAAR]")

    elif etype_str in ("ABHA_NUMBER", "ABHA_ADDRESS"):
        return "0" if is_numeric else tokens.get(etype_str, "[ABHA]")

    elif etype_str == "PAN":
        return tokens.get("PAN", "[PAN]")

    elif etype_str == "MRN":
        return "0" if is_numeric else tokens.get("MRN", "[MRN]")

    elif etype_str == "INSURANCE_ID":
        return "0" if is_numeric else tokens.get("INSURANCE_ID", "[INSURANCE]")

    elif etype_str == "EMAIL":
        return tokens.get("EMAIL", "[EMAIL]")

    elif etype_str in ("HOUSE", "LANDMARK", "LOCALITY"):
        return tokens.get(etype_str, "[ADDRESS]")

    # 2. Quasi-Identifiers
    elif etype_str == "DATE":
        if unit and unit.date_offset is not None:
            shifted = shift_date_text(text, unit.date_offset)
            if shifted is not None:
                return shifted
        # Fail closed if a ragged/misaligned cell in a DATE column holds non-date direct PII
        if len(text.strip()) >= 6:
            return scrub_free_text(text, policy)
        return text

    elif etype_str == "DOB":
        dob_action = policy.get("dob_action", "year")
        if dob_action in ("redact", "mask", "suppress"):
            return "0" if is_numeric else tokens.get("DOB", "[DOB]")
        if dob_action == "year":
            ym = re.search(r"\b(19\d\d|20\d\d)\b", text)
            if ym:
                return ym.group(1)
        if unit and unit.date_offset is not None:
            shifted = shift_date_text(text, unit.date_offset)
            if shifted is not None:
                return shifted
        if len(text.strip()) >= 6:
            return scrub_free_text(text, policy)
        return text

    elif etype_str == "AGE":
        digits = re.sub(r"\D", "", text)
        if digits:
            try:
                age_num = int(digits)
                coarsen = unit.coarsen if unit else False
                band = age_band(age_num, policy, coarsen=coarsen)
                if is_numeric:
                    # TR-PRV-5 / D-012: lower bound for numeric JSON
                    lower_bound = int(band.split("-")[0].replace("+", ""))
                    return str(lower_bound)
                return band
            except ValueError:
                pass
        return text

    elif etype_str == "PIN":
        return generalize_pin(text, policy)

    elif etype_str == "VILLAGE":
        return generalize_village(text, unit, policy)

    elif etype_str == "DISTRICT":
        if unit and unit.coarsen and policy.get("district_action") != "keep":
            return ""
        return text

    elif etype_str == "TEHSIL":
        # Always suppress TEHSIL — sub-district quasi-identifier that narrows down
        # voter roll candidates to single individuals without clinical utility value.
        return ""

    elif etype_str == "GENDER":
        return text

    # Fallback for other direct identifiers
    if etype_str in [d.value for d in DIRECT]:
        return "0" if is_numeric else tokens.get(etype_str, f"[{etype_str}]")

    return text


def apply_mentions(
    text: str,
    mentions: List[Mention],
    unit: Optional[Unit],
    policy: dict,
    is_numeric: bool = False,
    is_psn_target: bool = False,
) -> str:
    """Apply mentions to text right-to-left to avoid offset drift."""
    if not mentions or not text:
        return text

    min_conf = policy.get("min_confidence", 0.5)
    valid_mentions = [
        m for m in mentions
        if m.confidence >= min_conf and 0 <= m.start < m.end <= len(text)
    ]
    if not valid_mentions:
        return text

    # Resolve any overlapping spans cleanly
    valid_mentions = resolve_overlaps(valid_mentions)

    # Sort descending by start offset; on tie, larger span first
    valid_mentions.sort(key=lambda m: (m.start, m.end), reverse=True)

    cur_text = text
    last_start = len(text) + 1

    for m in valid_mentions:
        if m.end > last_start:
            # Overlaps with already replaced span to the right
            continue
        rep = get_replacement(
            m.etype,
            m.text,
            unit,
            policy,
            is_numeric=is_numeric,
            is_psn_target=is_psn_target and (m.etype == EType.PATIENT_NAME or m.etype == EType.MRN),
        )
        cur_text = cur_text[: m.start] + rep + cur_text[m.end :]
        last_start = m.start

    return cur_text


def rewrite_whole_cell(
    slot: Slot,
    unit: Optional[Unit],
    policy: dict,
    is_psn_target: bool = False,
) -> str:
    """Perform whole-cell replacement when slot.column_type is set."""
    is_numeric = slot.value_type in ("int", "float")
    return get_replacement(
        slot.column_type,
        slot.text,
        unit,
        policy,
        is_numeric=is_numeric,
        is_psn_target=is_psn_target,
    )


def rewrite_unit(u: Unit, policy: dict) -> None:
    """Rewrite all slots in a unit, handling whole-cell, mentions, and PSN placement."""
    if not u.slots:
        return

    # 1. Determine if this unit has a patient name slot/mention
    has_patient_name = any(
        s.column_type == EType.PATIENT_NAME or any(m.etype == EType.PATIENT_NAME for m in s.mentions)
        for s in u.slots
    )

    # 2. If no patient name, find an MRN/UHID slot as PSN target (D-010)
    psn_target_slot = None
    if u.psn and not has_patient_name:
        psn_target_slot = next(
            (
                s for s in u.slots
                if s.column_type == EType.MRN
                or any(m.etype == EType.MRN for m in s.mentions)
                or any(k in s.path.lower() for k in ("uhid", "mrn", "patient_id"))
            ),
            None,
        )

    # 3. First pass: rewrite base64 and decoded slots, propagating to parent slots
    parent_map = {s.path: s for s in u.slots}
    for s in u.slots:
        if s.path.endswith("#b64"):
            is_num = s.value_type in ("int", "float")
            s.text = apply_mentions(s.text, s.mentions, u, policy, is_numeric=is_num)
            parent_path = s.path[:-4]
            if parent_path in parent_map:
                try:
                    re_b64 = base64.b64encode(s.text.encode("utf-8")).decode("ascii")
                    parent_map[parent_path].text = re_b64
                except Exception:
                    pass
        elif s.path.endswith("#decoded"):
            is_num = s.value_type in ("int", "float")
            s.text = apply_mentions(s.text, s.mentions, u, policy, is_numeric=is_num)
            parent_path = s.path[:-8]
            if parent_path in parent_map and s.mentions:
                parent_map[parent_path].text = s.text

    # 4. Second pass: rewrite standard slots
    for s in u.slots:
        if s.path.endswith(("#b64", "#decoded")):
            continue

        is_target = (s is psn_target_slot) or (s.column_type == EType.PATIENT_NAME)

        if is_target and u.psn:
            s.text = u.psn
        elif s.column_type is not None:
            s.text = rewrite_whole_cell(s, u, policy, is_psn_target=is_target)
        elif s.mentions:
            is_num = s.value_type in ("int", "float")
            s.text = apply_mentions(
                s.text,
                s.mentions,
                u,
                policy,
                is_numeric=is_num,
                is_psn_target=is_target,
            )


def rewrite_file_slots(pf: ParsedFile, policy: dict) -> None:
    """Rewrite file-level slots: @header, @key, metadata."""
    if not pf.file_slots:
        return

    for s in pf.file_slots:
        if s.path.startswith("@header:"):
            try:
                idx = int(s.path.split(":")[1])
                s.text = apply_mentions(s.text, s.mentions, None, policy)
                if pf.header and 0 <= idx < len(pf.header):
                    pf.header[idx] = s.text
            except (ValueError, IndexError):
                pass
        elif s.path.startswith("@key:"):
            s.text = apply_mentions(s.text, s.mentions, None, policy)
        elif s.mentions:
            s.text = apply_mentions(s.text, s.mentions, None, policy)


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
        except (ValueError, TypeError):
            typed_val = 0  # TR-PRV-8: Numeric JSON fields -> 0
    elif val_type == "float":
        try:
            typed_val = float(val_text)
        except (ValueError, TypeError):
            typed_val = 0.0
    elif val_type == "bool":
        typed_val = str(val_text).lower() in ("true", "1")
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


def rename_json_key(obj: Any, parent_ptr: str, orig_key: str, new_key: str) -> None:
    """Rename a key in a JSON object at parent_ptr, preserving key order and resolving collisions."""
    if not parent_ptr.startswith("/"):
        parent_dict = obj if isinstance(obj, dict) else None
    else:
        parts = parent_ptr[1:].split("/")
        parts = [p.replace("~1", "/").replace("~0", "~") for p in parts]
        cur = obj
        for p in parts:
            if isinstance(cur, list):
                try:
                    cur = cur[int(p)]
                except (ValueError, IndexError):
                    return
            elif isinstance(cur, dict):
                cur = cur.get(p)
                if cur is None:
                    return
            else:
                return
        parent_dict = cur if isinstance(cur, dict) else None

    # Unescape orig_key in case it is still RFC 6901 escaped (~1 -> /, then ~0 -> ~)
    orig_key_unescaped = orig_key.replace("~1", "/").replace("~0", "~")

    if parent_dict and isinstance(parent_dict, dict):
        # Look for orig_key or orig_key_unescaped
        actual_key = None
        if orig_key in parent_dict:
            actual_key = orig_key
        elif orig_key_unescaped in parent_dict:
            actual_key = orig_key_unescaped
        else:
            return

        if actual_key == new_key:
            return

        # Collision-safe target key generation
        final_key = new_key
        suffix_idx = 2
        while final_key in parent_dict and final_key != actual_key:
            final_key = f"{new_key}_{suffix_idx}"
            suffix_idx += 1

        new_items = []
        for k, v in parent_dict.items():
            if k == actual_key:
                new_items.append((final_key, v))
            else:
                new_items.append((k, v))
        parent_dict.clear()
        parent_dict.update(new_items)



def place_fhir_psn(obj: Any, psn_val: str) -> None:
    """Place PSN in Patient.identifier of FHIR Bundle or Patient resource."""
    if not isinstance(obj, dict):
        return

    def _ensure_psn_identifier(patient_dict: dict) -> None:
        idents = patient_dict.setdefault("identifier", [])
        if not any(isinstance(i, dict) and i.get("value") == psn_val for i in idents):
            idents.insert(0, {"system": "urn:wardguard:psn", "value": psn_val})

    if obj.get("resourceType") == "Bundle":
        for entry in obj.get("entry", []):
            if isinstance(entry, dict):
                res = entry.get("resource")
                if isinstance(res, dict) and res.get("resourceType") == "Patient":
                    _ensure_psn_identifier(res)
    elif obj.get("resourceType") == "Patient":
        _ensure_psn_identifier(obj)


_B64_TOKEN = re.compile(r'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])')


def scrub_free_text(text: str, policy: dict) -> str:
    """Detect and replace identifiers in a free-text string that has no unit context."""
    if not text:
        return text
    from wardguard.detect.context import detect_text  # local import: avoid an import cycle
    mentions = detect_text(text, channel="content", gaz=policy.get("_gazetteer"), policy=policy)
    return apply_mentions(text, mentions, None, policy) if mentions else text


def scrub_embedded_base64(text: str, policy: dict) -> str:
    """Base64 blobs embedded inside free text (attachments pasted into notes, NDJSON lines,
    half-parsed JSON) are decoded, scrubbed and re-encoded; blobs that are not readable
    text are left alone."""
    if not text or len(text) < 24:
        return text

    def _fix(m: re.Match) -> str:
        tok = m.group(1)
        if len(tok) % 4:
            return tok
        try:
            dec = base64.b64decode(tok, validate=True).decode("utf-8")
        except Exception:
            return tok
        if not dec or not all(c.isprintable() or c in "\r\n\t" for c in dec) or not any(c.isalpha() for c in dec):
            return tok
        clean = scrub_free_text(dec, policy)
        return tok if clean == dec else base64.b64encode(clean.encode("utf-8")).decode("ascii")

    return _B64_TOKEN.sub(_fix, text)


def _copy_json_iterative(obj: Any) -> Any:
    """Iteratively deep-copy a JSON tree (immune to Python recursion limits)."""
    if not isinstance(obj, (dict, list)):
        return obj
    root: Any = {} if isinstance(obj, dict) else []
    stack: list[tuple[Any, Any]] = [(obj, root)]
    while stack:
        src, dst = stack.pop()
        if isinstance(src, dict):
            for k, v in src.items():
                if isinstance(v, dict):
                    nv: Any = {}
                    dst[k] = nv
                    stack.append((v, nv))
                elif isinstance(v, list):
                    nl: Any = []
                    dst[k] = nl
                    stack.append((v, nl))
                else:
                    dst[k] = v
        else:
            for item in src:
                if isinstance(item, dict):
                    nv = {}
                    dst.append(nv)
                    stack.append((item, nv))
                elif isinstance(item, list):
                    nl = []
                    dst.append(nl)
                    stack.append((item, nl))
                else:
                    dst.append(item)
    return root


def render(pf: ParsedFile, policy: dict) -> bytes:
    """Render sanitized bytes from ParsedFile and policy.
    
    Applies every mention (DIRECT -> token/PSN; QUASI -> shift/band/prefix/generalize)
    to every slot, places PSN inside patient-bearing units, and rebuilds file in its
    ORIGINAL format, UTF-8.
    """
    if pf.status == "quarantined":
        return b""

    # Step 1: Rewrite all units
    if pf.units:
        for u in pf.units:
            rewrite_unit(u, policy)

    # Step 2: Rewrite file-level slots (@header, @key, metadata)
    rewrite_file_slots(pf, policy)

    # Step 3: Serialize according to format
    if pf.fmt in ("csv", "tsv"):
        delimiter = pf.delimiter or ("," if pf.fmt == "csv" else "\t")
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=delimiter, lineterminator="\n")
        def _cells(vals: list[str]) -> list[str]:
            return [scrub_embedded_base64(v, policy) if isinstance(v, str) else v for v in vals]

        if pf.header is not None:
            writer.writerow(_cells(pf.header))
        if pf.units:
            for u in pf.units:
                row_slots = [
                    s for s in u.slots
                    if not s.path.endswith(("#b64", "#decoded"))
                    and (s.path.startswith("col:") or s.path.startswith("col#") or s.channel == "content")
                ]
                if row_slots:
                    writer.writerow(_cells([s.text for s in row_slots]))
                else:
                    writer.writerow(_cells([s.text for s in u.slots]))
        elif pf.rows is not None:
            # Fail closed: rows without unit context are scrubbed, never written raw.
            for row in pf.rows:
                writer.writerow(_cells([scrub_free_text(c, policy) if isinstance(c, str) else c for c in row]))
        return buf.getvalue().encode("utf-8")

    elif pf.fmt in ("json", "fhir"):
        if pf.obj is not None:
            obj_to_write = _copy_json_iterative(pf.obj)

            # Apply rewritten unit slots back to obj_to_write
            if pf.units:
                for u in pf.units:
                    for s in u.slots:
                        if s.path.startswith("/") and not s.path.endswith(("#b64", "#decoded")):
                            set_json_pointer(obj_to_write, s.path, s.text, s.value_type)

            # Apply rewritten file_slots (metadata pointers)
            for s in pf.file_slots:
                if s.path.startswith("/"):
                    set_json_pointer(obj_to_write, s.path, s.text, s.value_type)

            # Key renaming for @key slots: deepest-pointer-first (by segment count desc),
            # while preserving original encounter order for ties
            key_slots = [s for s in pf.file_slots if s.path.startswith("@key:")]
            key_slots.sort(key=lambda s: s.path.count("/"), reverse=True)

            for s in key_slots:
                ptr_and_key = s.path[5:]
                if "/" in ptr_and_key:
                    parent_ptr, orig_key = ptr_and_key.rsplit("/", 1)
                    # Unescape orig_key (~1 -> /, then ~0 -> ~)
                    unescaped_orig_key = orig_key.replace("~1", "/").replace("~0", "~")
                    if s.text != orig_key and s.text != unescaped_orig_key:
                        rename_json_key(obj_to_write, parent_ptr, orig_key, s.text)

            # FHIR PSN placement (D-010) and optional birthDate removal on DOB redact
            if pf.fmt == "fhir":
                if pf.units and pf.units[0].psn:
                    place_fhir_psn(obj_to_write, pf.units[0].psn)
                if policy.get("dob_action") in ("redact", "mask", "suppress") and isinstance(obj_to_write, dict):
                    if obj_to_write.get("resourceType") == "Patient":
                        obj_to_write.pop("birthDate", None)
                    elif obj_to_write.get("resourceType") == "Bundle":
                        for ent in obj_to_write.get("entry") or []:
                            res = ent.get("resource") if isinstance(ent, dict) else None
                            if isinstance(res, dict) and res.get("resourceType") == "Patient":
                                res.pop("birthDate", None)

            orig_limit = sys.getrecursionlimit()
            try:
                if orig_limit < 5000:
                    sys.setrecursionlimit(5000)
                return json.dumps(obj_to_write, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
            finally:
                sys.setrecursionlimit(orig_limit)
        return b"{}\n"

    else:  # text
        text_out = ""
        if pf.units and pf.units[0].slots:
            text_out = pf.units[0].slots[0].text
            # D-010 PSN Placement for text:
            u0 = pf.units[0]
            if u0.patient_bearing and u0.psn:
                has_patient_name_mention = any(
                    m.etype == EType.PATIENT_NAME for s in u0.slots for m in s.mentions
                )
                if not has_patient_name_mention and u0.psn not in text_out:
                    text_out = f"Patient: {u0.psn}\n{text_out}"
        elif pf.text is not None:
            # Fail closed: a text file without a data unit is still scrubbed, never copied raw.
            text_out = scrub_free_text(pf.text, policy)

        text_out = scrub_embedded_base64(text_out, policy)
        return text_out.encode("utf-8")
