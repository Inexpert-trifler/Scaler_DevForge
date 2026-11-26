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
from wardguard.detect.context import detect_text, detect_gazetteer
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


def _has_whole_cell_mention(slot: Slot, etype: EType) -> bool:
    return any(
        m.etype == etype and m.source == "column" and m.start == 0 and m.end == len(slot.text)
        for m in slot.mentions
    )


def _fhir_resource_types(pf: ParsedFile) -> dict[int, str]:
    """Map Bundle entry index -> FHIR resourceType."""
    out: dict[int, str] = {}
    if isinstance(pf.obj, dict) and pf.obj.get("resourceType") == "Bundle":
        for idx, entry in enumerate(pf.obj.get("entry") or []):
            if isinstance(entry, dict):
                res = entry.get("resource")
                if isinstance(res, dict) and isinstance(res.get("resourceType"), str):
                    out[idx] = res["resourceType"]
    return out


_JSON_SKIP_SUBTREES = {
    "facility", "hospital", "lab", "panels", "organization", "practitioner",
    "rx", "diagnosis", "vitals", "medication", "coding", "type", "system",
    "loinc", "range", "unit", "status", "schema",
}


def _classify_fhir_slot(pf: ParsedFile, slot: Slot, res_types: dict[int, str]) -> Optional[EType]:
    """Classify a FHIR R4 leaf slot path using resourceType and FHIR property paths."""
    p = slot.path
    if p.endswith(("#b64", "#decoded")) or not slot.text.strip():
        return None

    # Determine resourceType and relative path inside resource
    m_ent = re.match(r'^/entry/(\d+)/resource(/.*)$', p)
    if m_ent:
        idx = int(m_ent.group(1))
        rtype = res_types.get(idx, "")
        sub = m_ent.group(2)
    elif isinstance(pf.obj, dict) and pf.obj.get("resourceType") == "Patient":
        rtype = "Patient"
        sub = p
    else:
        return None

    if rtype in ("Composition", "Encounter", "Observation", "MedicationRequest", "Condition"):
        if sub == "/subject/display":
            return EType.PATIENT_NAME
        if sub == "/date" or sub == "/effectiveDateTime" or sub == "/authoredOn" or sub == "/period/start" or sub == "/period/end":
            return EType.DATE
        return None

    if rtype != "Patient":
        return None

    # Inside Patient resource
    if sub == "/birthDate":
        return EType.DOB
    if sub == "/gender":
        return EType.GENDER
    if re.match(r'^/name/\d+/(?:text|family|given/\d+)$', sub):
        return EType.PATIENT_NAME
    if re.match(r'^/contact/\d+/name/(?:text|family|given/\d+)$', sub):
        return EType.RELATIVE_NAME
    if re.match(r'^/address/\d+/postalCode$', sub):
        return EType.PIN
    if re.match(r'^/address/\d+/city$', sub):
        return EType.VILLAGE
    if re.match(r'^/address/\d+/district$', sub):
        return EType.DISTRICT
    if re.match(r'^/telecom/\d+/value$', sub):
        return EType.EMAIL if "@" in slot.text else EType.PHONE
    if "/extension/" in sub and sub.endswith("/valueString"):
        # Check extension URL in pf.obj to distinguish mother/father/guardian extensions
        m_ext = re.search(r'/extension/(\d+)/valueString$', sub)
        if m_ext and m_ent:
            ext_idx = int(m_ext.group(1))
            try:
                ext_obj = pf.obj["entry"][int(m_ent.group(1))]["resource"]["extension"][ext_idx]
                url = str(ext_obj.get("url", "")).lower()
                if any(k in url for k in ("mother", "father", "guardian", "relative", "spouse", "kin")):
                    return EType.RELATIVE_NAME
            except Exception:
                pass
    return None


def _classify_json_slot(slot: Slot) -> Optional[EType]:
    """Classify structured JSON leaf paths while protecting clinical/facility subtrees."""
    p = slot.path
    if p.endswith(("#b64", "#decoded")) or not slot.text.strip():
        return None

    segs = [s.lower() for s in p.split("/") if s and not s.isdigit()]
    if not segs:
        return None

    leaf = segs[-1]
    ancestors = set(segs[:-1])

    # Never classify facility/lab/medication/diagnosis subtrees as patient PII
    if ancestors & _JSON_SKIP_SUBTREES:
        return None
    if leaf in ("doctor", "referred_by", "hospital", "facility", "department"):
        return None

    # Guardian / relative subtree
    if ancestors & {"guardian", "relative", "next_of_kin", "attendant"}:
        if leaf in ("name", "full_name", "text"):
            return EType.RELATIVE_NAME
        if leaf in ("mobile", "phone", "contact"):
            return EType.PHONE
        return None

    # Metadata / ticket / raised_by person
    if "raised_by" in ancestors:
        if leaf in ("name", "full_name"):
            return EType.OTHER_PERSON
        if leaf in ("callback", "phone", "mobile"):
            return EType.PHONE

    # Patient/person fields
    if leaf in ("dob", "birth_date", "birthdate", "date_of_birth"):
        return EType.DOB
    if leaf in ("age", "age_sex", "age_gender", "age/sex", "age-sex", "age-gender"):
        return EType.AGE
    if leaf in ("gender", "sex"):
        return EType.GENDER
    if leaf in ("registered_on", "visit_date", "collected", "reported", "admission_date", "discharge_date"):
        return EType.DATE
    if leaf in ("pin", "pincode", "postalcode", "zip", "pin_code"):
        return EType.PIN
    if leaf in ("village", "gram", "gaon"):
        return EType.VILLAGE
    if leaf in ("tehsil", "taluka", "taluk"):
        return EType.TEHSIL
    if leaf in ("district", "jila", "zilla"):
        return EType.DISTRICT
    if leaf in ("uhid", "mrn", "patient_ref", "hospital_uhid", "patient_id"):
        return EType.MRN
    if leaf in ("mobile", "phone", "callback", "contact_no"):
        return EType.PHONE
    if leaf == "email":
        return EType.EMAIL
    if leaf in ("aadhar_no", "aadhaar_no", "aadhaar", "aadhar"):
        return EType.AADHAAR
    if leaf in ("abha", "abha_no", "abha_number"):
        return EType.ABHA_NUMBER
    if leaf == "abha_address":
        return EType.ABHA_ADDRESS
    if leaf in ("patient_name", "relative_name"):
        return EType.RELATIVE_NAME if leaf == "relative_name" else EType.PATIENT_NAME
    if leaf == "patient" and slot.value_type == "str":
        val = slot.text.strip()
        if not val or re.match(r'^(?:PSN-[0-9A-Z]{4,}|n/?a|none|null|unknown)$', val, re.IGNORECASE):
            return None
        if re.match(r'^[A-Za-z0-9_./-]+$', val) and any(ch.isdigit() for ch in val):
            return EType.MRN
        return EType.PATIENT_NAME
    if leaf in ("first", "last", "local", "full_name") and "name" in ancestors:
        return EType.PATIENT_NAME
    if leaf == "name" and (ancestors & {"patient", "patients"}):
        # Match /patient/name or /patients/0/name (when string leaf)
        return EType.PATIENT_NAME

    return None


def detect_file(
    pf: ParsedFile,
    gaz: Gazetteer,
    policy: Optional[dict] = None,
    *,
    gaz_only: bool = False,
) -> None:
    """Orchestrate detection for a parsed file.
    
    Required contract:
        detect_file(pf: ParsedFile, gaz: Gazetteer, policy: dict) -> None
    
    Pure w.r.t I/O. Deterministic.
    """
    # NOTE: a file with zero data units (a header-only CSV, an empty JSON object, a note whose
    # body failed to parse) still has file-level slots - header, file name, keys, metadata - and
    # those must be scanned too. Returning early here used to write such headers out verbatim.
    if pf.status != "pending":
        return

    if not gaz_only:
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
                            if not _has_whole_cell_mention(s, ctype):
                                m = _emit_whole_cell_mention(s, ctype)
                                if m:
                                    s.mentions.append(m)

        # 1b. Structured Key Classification for JSON & FHIR
        elif pf.fmt == "fhir":
            res_types = _fhir_resource_types(pf)
            for u in pf.units:
                for s in u.slots:
                    ctype = _classify_fhir_slot(pf, s, res_types)
                    if ctype:
                        s.column_type = ctype
                        if not _has_whole_cell_mention(s, ctype):
                            m = _emit_whole_cell_mention(s, ctype)
                            if m:
                                s.mentions.append(m)
        elif pf.fmt == "json":
            for u in pf.units:
                for s in u.slots:
                    ctype = _classify_json_slot(s)
                    if ctype:
                        s.column_type = ctype
                        if not _has_whole_cell_mention(s, ctype):
                            m = _emit_whole_cell_mention(s, ctype)
                            if m:
                                s.mentions.append(m)

    # 2. Free-text scanning & Hidden channel scanning for each slot
    _WHOLE_CELL_TYPES = {
        EType.PATIENT_NAME, EType.RELATIVE_NAME, EType.OTHER_PERSON, EType.PHONE,
        EType.AADHAAR, EType.AADHAAR_MASKED, EType.PAN, EType.MRN,
        EType.ABHA_NUMBER, EType.ABHA_ADDRESS, EType.INSURANCE_ID, EType.EMAIL,
        EType.DOB, EType.DATE, EType.AGE, EType.PIN, EType.VILLAGE,
        EType.TEHSIL, EType.DISTRICT, EType.GENDER,
    }
    text_cache: dict[tuple[str, str], tuple[Mention, ...]] = {}
    dirty_units: list[Unit] = []

    def _clone_mentions(cached: tuple[Mention, ...]) -> list[Mention]:
        return [
            Mention(
                etype=m.etype, start=m.start, end=m.end, text=m.text,
                script=m.script, channel=m.channel, role=m.role,
                source=m.source, confidence=m.confidence,
            )
            for m in cached
        ]

    for u in pf.units:
        unit_changed = False
        for s in u.slots:
            # Skip free-text regex on slots already handled cleanly as atomic structured cells
            if s.column_type in _WHOLE_CELL_TYPES:
                continue
            if not s.text:
                continue

            ckey = (s.text, s.channel) if len(s.text) <= 256 else None
            if ckey is not None and ckey in text_cache:
                cached = text_cache[ckey]
                new_mentions = _clone_mentions(cached) if cached else []
            else:
                if gaz_only:
                    new_mentions = detect_gazetteer(s.text, channel=s.channel, gaz=gaz)
                else:
                    new_mentions = detect_text(s.text, channel=s.channel, gaz=gaz, policy=policy)
                if ckey is not None and len(text_cache) < 8192:
                    text_cache[ckey] = tuple(new_mentions)

            if new_mentions:
                if s.mentions:
                    s.mentions = resolve_overlaps(s.mentions + new_mentions)
                else:
                    s.mentions = new_mentions
                unit_changed = True

        if gaz_only and unit_changed:
            dirty_units.append(u)

    # 3. Scan file-level slots (e.g. @filename, @header, @key)
    for fs in pf.file_slots:
        if not fs.text:
            continue
        if gaz_only:
            fs_mentions = detect_gazetteer(fs.text, channel=fs.channel, gaz=gaz)
        else:
            fs_mentions = detect_text(fs.text, channel=fs.channel, gaz=gaz, policy=policy)
        if fs_mentions:
            fs.mentions = resolve_overlaps(fs.mentions + fs_mentions) if fs.mentions else fs_mentions

    # 4. Populate Unit Evidence and determine patient_bearing status
    units_to_update = dirty_units if gaz_only else pf.units
    for u in units_to_update:
        u.evidence = extract_unit_evidence(u)

        # A unit is patient_bearing if it contains patient identifiers or clues
        has_patient_pii = any(
            m.role != "relative" for s in u.slots for m in s.mentions
        ) or bool(u.evidence.name_keys or u.evidence.strong_ids or u.evidence.dob or u.evidence.age)

        u.patient_bearing = has_patient_pii
