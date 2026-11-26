"""Unit and Slot enumeration for records.

Implements TR-ING-9:
- CSV row -> loc: "row:N" (0-based after header), Slots: "col:<header>" (or "col#<index>" if empty/duplicated)
- JSON list of objects -> loc: RFC 6901 pointer (e.g. "/visits/3" or "/0"), Slots: pointer leaves (keep value_type)
- Single-object JSON, FHIR R4 Bundle, or Text document -> loc: "doc", Slots for all leaves
- Deterministic and pure with respect to input.
"""
from __future__ import annotations
from typing import Any, List, Set, Tuple
from wardguard.model import ParsedFile, Slot, Unit, ValueType


def escape_pointer_segment(seg: str) -> str:
    """Escape a JSON pointer segment according to RFC 6901."""
    return seg.replace("~", "~0").replace("/", "~1")


def get_value_type_and_text(val: Any) -> Tuple[ValueType, str]:
    """Determine ValueType and string representation of a value."""
    if isinstance(val, bool):
        return "bool", "true" if val else "false"
    elif isinstance(val, int):
        return "int", str(val)
    elif isinstance(val, float):
        return "float", str(val)
    elif isinstance(val, str):
        return "str", val
    elif val is None:
        return "null", ""
    return "str", str(val)


def collect_leaf_slots(obj: Any, prefix: str = "") -> List[Slot]:
    """Recursively collect Slots for all primitive leaves in a JSON structure."""
    slots: List[Slot] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            seg = escape_pointer_segment(str(k))
            path = f"{prefix}/{seg}"
            slots.extend(collect_leaf_slots(v, path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            path = f"{prefix}/{idx}"
            slots.extend(collect_leaf_slots(item, path))
    else:
        v_type, text = get_value_type_and_text(obj)
        slots.append(
            Slot(
                path=prefix or "/",
                text=text,
                channel="content",
                value_type=v_type,
            )
        )
    return slots


def enumerate_units(pf: ParsedFile) -> None:
    """Enumerate units and slots from a parsed file."""
    if pf.status != "pending":
        return

    # Clear existing units to ensure idempotency
    pf.units = []

    # 1. CSV / TSV
    if pf.fmt in ("csv", "tsv") and pf.rows is not None and pf.header is not None:
        # Detect duplicated or empty headers
        counts: dict[str, int] = {}
        for h in pf.header:
            counts[h] = counts.get(h, 0) + 1
        duplicated: Set[str] = {h for h, c in counts.items() if c > 1}

        # Precompute slot path for each column index
        col_paths: List[str] = []
        for c_idx, h in enumerate(pf.header):
            clean_h = h.strip() if h else ""
            if not clean_h or h in duplicated:
                col_paths.append(f"col#{c_idx}")
            else:
                col_paths.append(f"col:{h}")

        for r_idx, row in enumerate(pf.rows):
            loc = f"row:{r_idx}"
            unit = Unit(
                uid=f"{pf.rel}#{loc}",
                file_rel=pf.rel,
                loc=loc,
            )
            for c_idx, val in enumerate(row):
                path = col_paths[c_idx] if c_idx < len(col_paths) else f"col#{c_idx}"
                unit.slots.append(
                    Slot(
                        path=path,
                        text=val if val is not None else "",
                        channel="content",
                        value_type="str",
                    )
                )
            pf.units.append(unit)

    # 2. FHIR R4 Bundle
    elif pf.fmt == "fhir" and pf.obj is not None:
        # TR-ING-9: text, FHIR or single-object JSON -> doc
        loc = "doc"
        unit = Unit(
            uid=f"{pf.rel}#{loc}",
            file_rel=pf.rel,
            loc=loc,
        )
        unit.slots.extend(collect_leaf_slots(pf.obj, ""))
        pf.units.append(unit)

    # 3. JSON
    elif pf.fmt == "json" and pf.obj is not None:
        # Check if obj is a top-level list of objects
        if isinstance(pf.obj, list):
            has_dicts = any(isinstance(item, dict) for item in pf.obj)
            if has_dicts:
                for idx, item in enumerate(pf.obj):
                    loc = f"/{idx}"
                    unit = Unit(
                        uid=f"{pf.rel}#{loc}",
                        file_rel=pf.rel,
                        loc=loc,
                    )
                    unit.slots.extend(collect_leaf_slots(item, loc))
                    pf.units.append(unit)
            else:
                # Top level list of primitives -> doc
                loc = "doc"
                unit = Unit(uid=f"{pf.rel}#{loc}", file_rel=pf.rel, loc=loc)
                unit.slots.extend(collect_leaf_slots(pf.obj, ""))
                pf.units.append(unit)

        elif isinstance(pf.obj, dict):
            # Check for keys whose values are lists of dicts (e.g. "visits": [...], "patients": [...])
            list_of_objects_keys = []
            for k, v in pf.obj.items():
                if isinstance(v, list) and any(isinstance(elem, dict) for elem in v):
                    list_of_objects_keys.append(k)

            if list_of_objects_keys:
                # Enumerate each element of the list of objects as a unit
                for k in list_of_objects_keys:
                    v = pf.obj[k]
                    escaped_k = escape_pointer_segment(str(k))
                    for idx, item in enumerate(v):
                        loc = f"/{escaped_k}/{idx}"
                        unit = Unit(
                            uid=f"{pf.rel}#{loc}",
                            file_rel=pf.rel,
                            loc=loc,
                        )
                        unit.slots.extend(collect_leaf_slots(item, loc))
                        pf.units.append(unit)

                # Collect any remaining non-list-of-objects fields as a doc unit
                other_fields = {k: v for k, v in pf.obj.items() if k not in list_of_objects_keys}
                if other_fields:
                    doc_unit = Unit(
                        uid=f"{pf.rel}#doc",
                        file_rel=pf.rel,
                        loc="doc",
                    )
                    for k, v in other_fields.items():
                        escaped_k = escape_pointer_segment(str(k))
                        doc_unit.slots.extend(collect_leaf_slots(v, f"/{escaped_k}"))
                    pf.units.append(doc_unit)

            else:
                # Single-object JSON -> doc (TR-ING-9)
                loc = "doc"
                unit = Unit(
                    uid=f"{pf.rel}#{loc}",
                    file_rel=pf.rel,
                    loc=loc,
                )
                unit.slots.extend(collect_leaf_slots(pf.obj, ""))
                pf.units.append(unit)

    # 4. Text
    elif pf.fmt == "text" and pf.text is not None:
        loc = "doc"
        unit = Unit(
            uid=f"{pf.rel}#{loc}",
            file_rel=pf.rel,
            loc=loc,
        )
        unit.slots.append(
            Slot(
                path="doc",
                text=pf.text,
                channel="content",
                value_type="str",
            )
        )
        pf.units.append(unit)
