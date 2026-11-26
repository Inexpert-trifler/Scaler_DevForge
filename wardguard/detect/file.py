"""File-level detection orchestrator and mention emitter.

Implements TR-DET-8, TR-LNK-1:
- detect_file(pf: ParsedFile, gaz: Gazetteer, policy: dict) -> None
    1. Classifies columns for tabular/structured files (CSV, TSV) -> sets slot.column_type
    2. Emits whole-cell mentions for slots with recognized column types
    3. Runs detect_text on all unclassified content slots, free-text documents, and hidden slots
    4. Emits Quasi-Identifier (QI) mentions (AGE, DOB, DATE, VILLAGE, PIN, GENDER)
    5. Populates unit.evidence via extract_unit_evidence
    6. Sets unit.patient_bearing = True if any personal identifier or patient clue was found
"""
from __future__ import annotations
import re
from typing import Optional
from wardguard.model import ParsedFile, Unit, Slot, Mention, EType, Role, Channel
from wardguard.detect.columns import classify_column
from wardguard.detect.context import detect_text
from wardguard.detect.evidence import extract_unit_evidence, parse_iso_date, parse_age, parse_gender, load_admin_areas
from wardguard.detect.guards import is_protected
from wardguard.detect.names import Gazetteer
from wardguard.detect.patterns import _detect_script, resolve_overlaps


def _emit_whole_cell_mention(slot: Slot, etype: EType) -> Optional[Mention]:
    """Emit a full-span Mention for a structured cell when column_type is known."""
    val = slot.text.strip()
    if not val:
        return None
    role: Role = "relative" if etype == EType.RELATIVE_NAME else "patient"
    return Mention(
        etype=etype,
        start=0,
        end=len(slot.text),
        text=slot.text,
        script=_detect_script(slot.text),
        channel=slot.channel,
        role=role,
        source="column",
        confidence=0.98,
    )


def detect_file(pf: ParsedFile, gaz: Gazetteer, policy: Optional[dict] = None) -> None:
    """Orchestrate detection for a parsed file.
    
    Required contract:
        detect_file(pf: ParsedFile, gaz: Gazetteer, policy: dict) -> None
    
    Pure w.r.t I/O. Deterministic.
    """
    if pf.status != "pending" or not pf.units:
        return

    # 1. Structured Column Classification for CSV/TSV
    if pf.fmt in ("csv", "tsv") and pf.header:
        # Group slot values by column path: "col:<header>"
        col_values: dict[str, list[str]] = {h: [] for h in pf.header}
        for u in pf.units:
            for s in u.slots:
                # s.path has format "col:<name>" or "col#<index>"
                if s.path.startswith("col:"):
                    col_name = s.path[4:]
                    if col_name in col_values:
                        col_values[col_name].append(s.text)

        # Classify each column
        col_types: dict[str, Optional[EType]] = {}
        for col_name, values in col_values.items():
            col_types[col_name] = classify_column(col_name, values)

        # Apply classified column_type to slots
        for u in pf.units:
            for s in u.slots:
                if s.path.startswith("col:"):
                    col_name = s.path[4:]
                    ctype = col_types.get(col_name)
                    if ctype:
                        s.column_type = ctype
                        m = _emit_whole_cell_mention(s, ctype)
                        if m:
                            s.mentions.append(m)

    # 2. Free-text scanning & Hidden channel scanning for each slot
    for u in pf.units:
        for s in u.slots:
            # If slot was already classified as a whole-cell direct identifier, skip free-text regex
            if s.column_type in (
                EType.PATIENT_NAME, EType.RELATIVE_NAME, EType.PHONE,
                EType.AADHAAR, EType.AADHAAR_MASKED, EType.PAN, EType.MRN,
                EType.ABHA_NUMBER, EType.ABHA_ADDRESS, EType.INSURANCE_ID, EType.EMAIL
            ):
                continue

            # Run free-text detector with gazetteer and context rules
            text_mentions = detect_text(s.text, channel=s.channel, gaz=gaz, policy=policy)
            if text_mentions:
                # Combine existing with new, resolving overlaps
                combined = s.mentions + text_mentions
                s.mentions = resolve_overlaps(combined)

    # 3. Scan file-level slots (e.g. @filename, @header)
    for fs in pf.file_slots:
        fs_mentions = detect_text(fs.text, channel=fs.channel, gaz=gaz, policy=policy)
        if fs_mentions:
            fs.mentions = resolve_overlaps(fs.mentions + fs_mentions)

    # 4. Populate Unit Evidence and determine patient_bearing status
    for u in pf.units:
        u.evidence = extract_unit_evidence(u)

        # A unit is patient_bearing if it contains patient identifiers or clues
        has_patient_pii = any(
            m.role != "relative" for s in u.slots for m in s.mentions
        ) or bool(u.evidence.name_keys or u.evidence.strong_ids or u.evidence.dob or u.evidence.age)

        u.patient_bearing = has_patient_pii
