"""Evidence harvesting and Quasi-Identifier (QI) extraction for patient record linkage.

Implements TR-DET-8, TR-LNK-1:
- Normalizes and extracts identity clues into Unit.evidence:
    - name_keys: tuple[str, ...] (canonical Latin full names)
    - given_keys: tuple[str, ...]
    - surname_keys: tuple[str, ...]
    - relative_keys: tuple[str, ...]
    - dob: Optional[str] (ISO yyyy-mm-dd)
    - age: Optional[int]
    - gender: Optional[Literal["M", "F"]]
    - village_key: Optional[str]
    - district_key: Optional[str]
    - strong_ids: tuple[tuple[str, str], ...] (EType, normalized digit core)
    - dates: tuple[str, ...] (ISO dates)
- Extracts Quasi-Identifier mentions:
    - AGE (e.g., 48 Y, 54 वर्ष, 48/M)
    - DATE / DOB (ISO conversion and standard Indian formats DD/MM/YYYY)
    - GENDER (M/F, Male/Female, पुरुष/महिला)
    - VILLAGE / DISTRICT / TEHSIL from admin_areas_up.csv
    - PIN (6 digits)
"""
from __future__ import annotations
import csv
import os
import re
from functools import lru_cache
from typing import Optional, Literal
from wardguard.model import Unit, Evidence, EType, Mention, Script
from wardguard.detect.normalize import normalize_for_match
from wardguard.detect.translit import canonical_name, deva_to_latin
from wardguard.detect.patterns import _detect_script

# Regex to parse date strings: DD/MM/YYYY, YYYY-MM-DD, DD-MM-YYYY
RE_DATE_EXTRACT = re.compile(
    r'\b(?:(\d{4})[-/](\d{1,2})[-/](\d{1,2})|(\d{1,2})[-/](\d{1,2})[-/](\d{4}))\b'
)

# Regex to extract age from strings: "48 Y", "54 वर्ष", "age 32", "48/M"
RE_AGE_EXTRACT = re.compile(
    r'(?i)\b(?:age\s*[:=-]?\s*)?(\d{1,3})\s*(?:y(?:ears?|rs?)?|वर्ष|साल)?(?:\s*/\s*[mfMF])?\b'
)
# Strict age regex for free-text / un-typed slots: requires explicit age indicator (never matches dates/bills!)
RE_AGE_EXPLICIT = re.compile(
    r'(?i)(?:\b(?:age|उम्र|आयु)\s*[:=-]\s*(\d{1,3})\b|\b(\d{1,3})\s*(?:y(?:ears?|rs?)?\b|वर्ष|साल)(?:\s*/\s*(?:m(?:ale)?|f(?:emale)?))?|\b(\d{1,3})\s*/\s*(?:m(?:ale)?|f(?:emale)?)\b)'
)
RE_REL_PREFIX_STRIP = re.compile(
    r'(?i)^(?:s/o|d/o|w/o|c/o|h/o|f/o|m/o|son\s+of|daughter\s+of|wife\s+of|husband\s+of|father\s+of|mother\s+of|guardian|पत्नी|पति|पिता|पुत्र|पुत्री)\s*[:.-]?\s*'
)


_DEVA_TO_ASCII = str.maketrans("०१२३४५६७८९", "0123456789")


def _norm_id_core(etype_val: str, raw: str) -> str:
    """Normalize strong identifier core uniformly (Devanagari digits -> ASCII, strips +91/0 on Indian phones)."""
    ascii_raw = raw.translate(_DEVA_TO_ASCII)
    core = re.sub(r'[^A-Za-z0-9]', '', ascii_raw).upper()
    if etype_val == "PHONE":
        digits = re.sub(r'\D', '', ascii_raw)
        if len(digits) >= 10 and digits[-10] in "6789":
            return digits[-10:]
        return digits
    return core

# Regex for gender
RE_GENDER_M = re.compile(r'(?i)\b(?:m|male|पुरुष|purush)\b')
RE_GENDER_F = re.compile(r'(?i)\b(?:f|female|महिला|mahila|स्त्री)\b')


@lru_cache(maxsize=1)
def load_admin_areas() -> tuple[dict[str, str], set[str], set[str]]:
    """Load UP admin areas: tehsils, districts, and mapping from tehsil -> district."""
    res_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "resources",
        "admin_areas_up.csv"
    )
    tehsil_to_district: dict[str, str] = {}
    districts: set[str] = set()
    tehsils: set[str] = set()

    if os.path.exists(res_path):
        with open(res_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if len(row) >= 2:
                    dist, teh = row[0].strip(), row[1].strip()
                    dist_clean = dist.lower()
                    teh_clean = teh.lower()
                    districts.add(dist_clean)
                    tehsils.add(teh_clean)
                    tehsil_to_district[teh_clean] = dist_clean

    return tehsil_to_district, districts, tehsils


def is_history_duration(text: str, start: int, end: int) -> bool:
    """Check if number span is a symptom/disease duration rather than patient age."""
    before = text[max(0, start - 15):start].lower()
    after = text[end:min(len(text), end + 20)].lower()
    if any(k in before for k in ("x ", "for ", "since ", "h/o ", "k/c/o ", "c/o ")):
        return True
    if any(k in after for k in ("back", "ago", "prior", "history", "completed", "duration")):
        return True
    return False


def parse_iso_date(date_str: str) -> Optional[str]:
    """Parse date string into standard ISO format (YYYY-MM-DD)."""
    m = RE_DATE_EXTRACT.search(date_str.strip())
    if not m:
        return None
    y1, m1, d1, d2, m2, y2 = m.groups()
    if y1:
        year, month, day = int(y1), int(m1), int(d1)
    else:
        day, month, year = int(d2), int(m2), int(y2)

    # Sanity checks
    if 1900 <= year <= 2030 and 1 <= month <= 12 and 1 <= day <= 31:
        return f"{year:04d}-{month:02d}-{day:02d}"
    return None


def parse_age(age_str: str) -> Optional[int]:
    """Extract integer age (0-120) from an age string or token."""
    m = RE_AGE_EXTRACT.search(age_str.strip())
    if not m:
        return None
    try:
        val = int(m.group(1))
        if 0 <= val <= 120:
            return val
    except ValueError:
        pass
    return None


def parse_gender(gender_str: str) -> Optional[Literal["M", "F"]]:
    """Extract gender 'M' or 'F'."""
    s = gender_str.strip()
    if RE_GENDER_M.search(s):
        return "M"
    if RE_GENDER_F.search(s):
        return "F"
    return None


def extract_unit_evidence(unit: Unit) -> Evidence:
    """Harvest patient clues from Unit slots and mentions to populate unit.evidence."""
    name_keys: list[str] = []
    given_keys: list[str] = []
    surname_keys: list[str] = []
    relative_keys: list[str] = []
    dob_val: Optional[str] = None
    age_val: Optional[int] = None
    gender_val: Optional[Literal["M", "F"]] = None
    village_key: Optional[str] = None
    district_key: Optional[str] = None
    strong_ids: list[tuple[str, str]] = []
    dates: list[str] = []

    tehsil_to_dist, districts, _ = load_admin_areas()

    # 1. Process Structured Column Types (and group split first/last JSON/CSV name fields)
    first_parts: list[str] = []
    last_parts: list[str] = []

    for slot in unit.slots:
        val = slot.text.strip()
        if not val:
            continue

        ctype = slot.column_type
        if ctype == EType.PATIENT_NAME:
            lp = slot.path.lower()
            is_first = lp.endswith(("/first", "/given/0", "col:firstname", "col:first_name")) or lp == "/first"
            is_last = lp.endswith(("/last", "/family", "col:lastname", "col:last_name")) or lp == "/last"
            if is_first:
                first_parts.append(val)
            elif is_last:
                last_parts.append(val)
            else:
                canon = canonical_name(val)
                if canon:
                    name_keys.append(canon)
                    tokens = canon.split()
                    if len(tokens) >= 1:
                        given_keys.append(tokens[0])
                    if len(tokens) >= 2:
                        surname_keys.append(tokens[-1])
        elif ctype == EType.RELATIVE_NAME:
            cleaned_rel = RE_REL_PREFIX_STRIP.sub("", val).strip()
            canon = canonical_name(cleaned_rel or val)
            if canon:
                relative_keys.append(canon)
        elif ctype == EType.DOB:
            iso = parse_iso_date(val)
            if iso and not dob_val:
                dob_val = iso
        elif ctype == EType.DATE:
            iso = parse_iso_date(val)
            if iso:
                dates.append(iso)
        elif ctype == EType.AGE:
            parsed_a = parse_age(val)
            if parsed_a is not None and age_val is None:
                age_val = parsed_a
            if not gender_val:
                g = parse_gender(val)
                if g:
                    gender_val = g
        elif ctype == EType.GENDER:
            g = parse_gender(val)
            if g and not gender_val:
                gender_val = g
        elif ctype == EType.VILLAGE:
            village_key = canonical_name(val)
        elif ctype == EType.TEHSIL:
            teh_canon = canonical_name(val)
            if not district_key and teh_canon in tehsil_to_dist:
                district_key = tehsil_to_dist[teh_canon]
        elif ctype == EType.DISTRICT:
            district_key = (canonical_name(val) or val.lower().strip())
        elif ctype in (EType.PHONE, EType.AADHAAR, EType.ABHA_NUMBER, EType.PAN, EType.MRN):
            core = _norm_id_core(ctype.value, val)
            if core:
                strong_ids.append((ctype.value, core))

    # Combine split first + last name parts into a composite full canonical name
    if first_parts and last_parts:
        full_combined = f"{first_parts[0]} {last_parts[0]}"
        canon_full = canonical_name(full_combined)
        if canon_full:
            name_keys.append(canon_full)
            toks = canon_full.split()
            if toks:
                given_keys.append(toks[0])
            if len(toks) >= 2:
                surname_keys.append(toks[-1])
    elif first_parts and not name_keys:
        canon_f = canonical_name(first_parts[0])
        if canon_f:
            given_keys.append(canon_f)
    elif last_parts and not name_keys:
        canon_l = canonical_name(last_parts[0])
        if canon_l:
            surname_keys.append(canon_l)

    # 2. Process Mentions in Slots (free-text / hidden channels / regex hits)
    for slot in unit.slots:
        # Inspect un-typed free-text slots ONLY with strict explicit age pattern (avoids dates like 2026-05-26 -> age=26!)
        # Never extract patient age from clinical history, complaints, vitals, notes, or medication slots
        slot_path_lower = slot.path.lower()
        is_clinical_narrative = any(k in slot_path_lower for k in (
            "history", "complaint", "diag", "rx", "med", "dose", "range", "vitals", "notes"
        ))
        if age_val is None and slot.column_type is None and slot.value_type == "str" and not is_clinical_narrative:
            m_explicit = RE_AGE_EXPLICIT.search(slot.text)
            if m_explicit and not is_history_duration(slot.text, m_explicit.start(), m_explicit.end()):
                num_str = m_explicit.group(1) or m_explicit.group(2) or m_explicit.group(3)
                try:
                    cand_a = int(num_str)
                    if 0 <= cand_a <= 120:
                        age_val = cand_a
                except ValueError:
                    pass
        if not gender_val:
            g = parse_gender(slot.text)
            if g:
                gender_val = g

        for m in slot.mentions:
            m_text = m.text.strip()
            if not m_text:
                continue

            if m.etype == EType.PATIENT_NAME and m.role != "relative":
                canon = canonical_name(m_text)
                # Only add multi-token or standalone doc-level name keys; avoid 1-token noise when full name exists
                if canon and canon not in name_keys:
                    if len(canon.split()) >= 2 or not any(len(nk.split()) >= 2 for nk in name_keys):
                        name_keys.append(canon)
                    toks = canon.split()
                    if len(toks) >= 1:
                        given_keys.append(toks[0])
                    if len(toks) >= 2:
                        surname_keys.append(toks[-1])
            elif m.etype == EType.RELATIVE_NAME or m.role == "relative":
                cleaned_rel = RE_REL_PREFIX_STRIP.sub("", m_text).strip()
                canon = canonical_name(cleaned_rel or m_text)
                if canon and canon not in relative_keys:
                    relative_keys.append(canon)
            elif m.etype == EType.DOB and not dob_val:
                iso = parse_iso_date(m_text)
                if iso:
                    dob_val = iso
            elif m.etype == EType.DATE:
                iso = parse_iso_date(m_text)
                if iso and iso not in dates:
                    dates.append(iso)
            elif m.etype == EType.AGE and age_val is None:
                parsed_a = parse_age(m_text)
                if parsed_a is not None:
                    age_val = parsed_a
            elif m.etype in (EType.PHONE, EType.AADHAAR, EType.ABHA_NUMBER, EType.PAN, EType.MRN):
                # Do not treat metadata/filename-level ID mentions on @file/#doc as primary unit identity if unit already has content IDs,
                # except normalize PHONE/MRN uniformly.
                core = _norm_id_core(m.etype.value, m_text)
                if core:
                    item = (m.etype.value, core)
                    if item not in strong_ids:
                        strong_ids.append(item)

    # Deduplicate and sort tuples
    return Evidence(
        name_keys=tuple(sorted(set(name_keys))),
        given_keys=tuple(sorted(set(given_keys))),
        surname_keys=tuple(sorted(set(surname_keys))),
        relative_keys=tuple(sorted(set(relative_keys))),
        dob=dob_val,
        age=age_val,
        gender=gender_val,
        village_key=village_key,
        district_key=district_key,
        strong_ids=tuple(sorted(set(strong_ids))),
        dates=tuple(sorted(set(dates))),
    )
