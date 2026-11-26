"""Column classification using header lexicons and value profiling.

Implements TR-DET-3:
- Header fuzzy and exact matching against EN/HI label lexicons in resources/
- Value profiling (>= 60% of non-empty values matching an identifier type)
- Distinguishes PATIENT_NAME vs RELATIVE_NAME (Relative Name, Guardian, S/O, W/O, etc.)
- Resolves conflicts between header and values (trust values for strong IDs, header for names)
"""
from __future__ import annotations
import os
import re
from functools import lru_cache
from typing import Optional
from rapidfuzz import fuzz
from wardguard.model import EType
from wardguard.detect.normalize import normalize_for_match
from wardguard.detect.patterns import (
    RE_AADHAAR,
    RE_AADHAAR_MASKED,
    RE_ABHA_NUMBER,
    RE_ABHA_ADDRESS,
    RE_PAN,
    RE_PHONE,
    RE_EMAIL,
    RE_MRN,
    RE_INSURANCE,
    RE_HOUSE,
    RE_PIN_STANDALONE,
    validate_verhoeff,
)

# Relative indicators in column headers (English, Devanagari, Romanized Hindi)
RE_RELATIVE_HEADER = re.compile(
    r'(?i)(?<![A-Za-z])('
    r'relative|guardian|father|husband|mother|caregiver|s/o|d/o|w/o|c/o|h/o|f/o|m/o|'
    r'pita|pati|mata|putra|putri|abhibhavak|rishtedar|'
    r'पिता|पति|माता|अभिभावक|पुत्र|पुत्री|wali|valad'
    r')(?![A-Za-z])'
)

# Column headers that are NEVER patient names even if values look like alphabetic words
NON_NAME_HEADERS = {
    "procedure", "status", "category", "from", "to", "source", "destination",
    "remarks", "notes", "note", "diagnosis", "complaints", "history", "department",
    "dept", "hospital", "facility", "state", "country", "drug", "medicine", "rx",
    "test", "unit", "range", "loinc", "code", "display", "type", "role", "system",
    "visits", "bed", "ward", "trip", "gender", "sex", "ling", "district", "jila",
    "tehsil", "taluka", "village", "gaon", "city", "town", "relation", "relationship",
    "payer", "scheme", "bill_type", "outcome", "severity", "result", "specimen",
}

# Date/DOB regex for values: DD/MM/YYYY, YYYY-MM-DD, DD-MM-YYYY, etc.
# POS: "12/04/1977", "1985-06-20", "25-11-2001" | NEG: "650mg", "1-0-1"
_MON = r'(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*'
RE_DATE_VALUE = re.compile(
    r'(?i)^\s*([\d०-९]{1,2}[/.-][\d०-९]{1,2}[/.-][\d०-९]{2,4}|[\d०-९]{4}[/.-][\d०-९]{1,2}[/.-][\d०-९]{1,2}'
    r'|\d{1,2}[ -]' + _MON + r'\.?[ -,]*\d{2,4}|' + _MON + r'\.?\s+\d{1,2},?\s+\d{4})'
    r'(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?\s*$'
)
_YEAR_IN_DATE = re.compile(r'(?<!\d)((?:19|20)\d\d)(?!\d)')

# Header words that announce a date / a date of birth (EN, HI, Hinglish, abbreviations)
_DATE_HDR_TOKENS = {"date", "dt", "dated", "tithi", "tarikh", "tareekh", "din", "on", "datetime", "timestamp",
                    "तिथि", "दिनांक", "तारीख", "तारिख"}
_DOB_HDR_COMPACT = {"dob", "dateofbirth", "birthdate", "birthdt", "bdate", "janmtithi", "janamtithi", "janmdin",
                    "janmtarikh", "जन्मतिथि", "जन्मदिनांक", "जन्मतारीख"}


def _date_header_kind(header: str) -> Optional[EType]:
    """DOB / DATE from the header wording alone (None if it does not look like a date header)."""
    h = normalize_for_match(header.strip().lower())
    compact = re.sub(r'[\s_.\-/()]+', '', h)
    if compact in _DOB_HDR_COMPACT or "birth" in h or "जन्म" in h or compact.startswith("dob"):
        return EType.DOB
    toks = set(t for t in re.split(r'[\s_.\-/()]+', h) if t)
    if toks & _DATE_HDR_TOKENS:
        return EType.DATE
    return None


def _dates_look_like_birthdates(values: list[str]) -> bool:
    """Birth dates spread over decades; visit/admission dates cluster within a couple of years."""
    if len(values) > 500:
        step = max(1, len(values) // 500)
        values = values[::step][:500]
    years = sorted(int(m.group(1)) for v in values if v for m in [_YEAR_IN_DATE.search(str(v).translate(
        str.maketrans('०१२३४५६७८९', '0123456789')))] if m)
    if len(years) < 3:
        return False
    median = years[len(years) // 2]
    return (years[-1] - years[0]) >= 15 and median <= years[-1] - 8

# Age regex for values: 48, 54 Y, 54Y, 32 years, 45 वर्ष
# POS: "48", "54 Y", "32 yrs", "45 वर्ष" | NEG: "SNJ/26/064127"
RE_AGE_VALUE = re.compile(r'^\s*(\d{1,3})\s*(?:y(?:ears?|rs?)?|वर्ष|साल)?\s*$', re.IGNORECASE)

# Gender regex for values: M, F, Male, Female, M/F, पुरुष, महिला
RE_GENDER_VALUE = re.compile(r'^\s*(?:m(?:ale)?|f(?:emale)?|o(?:ther)?|पुरुष|महिला|स्त्री)\s*$', re.IGNORECASE)


@lru_cache(maxsize=1)
def load_header_lexicons() -> dict[EType, set[str]]:
    """Load label lexicons from resources/ directory."""
    lex_map: dict[EType, set[str]] = {
        EType.PATIENT_NAME: set(),
        EType.RELATIVE_NAME: set(),
        EType.PHONE: set(),
        EType.MRN: set(),
        EType.AADHAAR: set(),
        EType.ABHA_NUMBER: set(),
        EType.ABHA_ADDRESS: set(),
        EType.INSURANCE_ID: set(),
        EType.DOB: set(),
        EType.DATE: {
            "date", "visit date", "visit_date", "admission date", "admission_date",
            "discharge date", "discharge_date", "collected on", "collected_on",
            "reported on", "reported_on", "registered on", "registered_on",
            "registration date", "reg date", "registered", "तारीख", "दिनांक",
        },
        EType.AGE: set(),
        EType.VILLAGE: set(),
        EType.TEHSIL: set(),
        EType.DISTRICT: set(),
        EType.HOUSE: set(),
        EType.LOCALITY: set(),
        EType.LANDMARK: set(),
        EType.PIN: set(),
        EType.GENDER: {"gender", "sex", "लिंग", "gender/sex", "ling"},
    }

    res_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "resources")

    def _read_lines(filename: str) -> set[str]:
        path = os.path.join(res_dir, filename)
        if not os.path.exists(path):
            return set()
        with open(path, "r", encoding="utf-8") as f:
            return {
                normalize_for_match(line.strip().lower())
                for line in f
                if line.strip() and not line.startswith("#")
            }

    # Labels for name
    name_labels = _read_lines("labels_name.txt")
    for lbl in name_labels:
        if RE_RELATIVE_HEADER.search(lbl):
            lex_map[EType.RELATIVE_NAME].add(lbl)
        else:
            lex_map[EType.PATIENT_NAME].add(lbl)

    lex_map[EType.PHONE] = _read_lines("labels_phone.txt")
    for lbl in _read_lines("labels_id.txt"):
        if any(k in lbl for k in ("policy", "insurance", "beneficiary")):
            lex_map[EType.INSURANCE_ID].add(lbl)
        elif "aadhar" in lbl or "aadhaar" in lbl or "आधार" in lbl:
            lex_map[EType.AADHAAR].add(lbl)
        elif "abha address" in lbl:
            lex_map[EType.ABHA_ADDRESS].add(lbl)
        elif "abha" in lbl:
            lex_map[EType.ABHA_NUMBER].add(lbl)
        else:
            lex_map[EType.MRN].add(lbl)
    lex_map[EType.DOB] = _read_lines("labels_dob.txt")
    lex_map[EType.AGE] = _read_lines("labels_age.txt")

    for lbl in _read_lines("labels_village.txt"):
        if any(k in lbl for k in ("tehsil", "taluka", "taluk", "तहसील")):
            lex_map[EType.TEHSIL].add(lbl)
        elif any(k in lbl for k in ("district", "jila", "zilla", "जिला")):
            lex_map[EType.DISTRICT].add(lbl)
        elif "village" in lbl or "gaon" in lbl or "gram" in lbl:
            lex_map[EType.VILLAGE].add(lbl)
        elif any(k in lbl for k in ("mohalla", "ward", "colony", "मोहल्ला", "वार्ड")):
            lex_map[EType.LOCALITY].add(lbl)
        else:
            lex_map[EType.VILLAGE].add(lbl)

    addr_labels = _read_lines("labels_address.txt")
    for lbl in addr_labels:
        if "pin" in lbl or "pincode" in lbl or "zip" in lbl:
            lex_map[EType.PIN].add(lbl)
        elif any(k in lbl for k in ["tehsil", "taluka", "taluk", "तहसील"]):
            lex_map[EType.TEHSIL].add(lbl)
        elif any(k in lbl for k in ["district", "jila", "zilla", "जिला"]):
            lex_map[EType.DISTRICT].add(lbl)
        elif any(k in lbl for k in ["h.no", "house", "मकान", "makan", "flat", "plot",
                                     "pata", "address", "addr", "residence", "permanent",
                                     "present", "निवास", "पता"]):
            lex_map[EType.HOUSE].add(lbl)
        elif any(k in lbl for k in ["landmark", "near", "opp", "opposite", "निशान", "nikatatam"]):
            lex_map[EType.LANDMARK].add(lbl)
        elif any(k in lbl for k in ["ward", "mohalla", "colony", "locality", "area",
                                     "street", "gali", "मोहल्ला", "वार्ड", "कॉलोनी"]):
            lex_map[EType.LOCALITY].add(lbl)
        else:
            lex_map[EType.VILLAGE].add(lbl)

    return lex_map


@lru_cache(maxsize=1)
def load_medical_terms() -> set[str]:
    """Load medical words and complaints to avoid classifying medical columns as names."""
    res_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "resources")
    terms: set[str] = set()
    for fn in ["drugs.txt", "eponyms.txt", "complaints.txt", "medical_terms_en_hi.txt"]:
        path = os.path.join(res_dir, fn)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    w = line.strip().lower()
                    if w and not w.startswith("#"):
                        terms.add(w)
    return terms


def _match_header_lexicon(norm_header: str) -> Optional[EType]:
    """Match cleaned header against known label lexicons (exact + substring + fuzzy)."""
    if not norm_header:
        return None

    # Strip trailing format parenthetical like "registered (mm/dd/yyyy)" or "age (yrs)"
    base_header = re.sub(r'\s*\([^)]*\)\s*$', '', norm_header).strip()
    candidates = [norm_header] + ([base_header] if base_header and base_header != norm_header else [])

    # Check for relative header explicitly
    if RE_RELATIVE_HEADER.search(norm_header):
        if any(w in norm_header for w in ["name", "naam", "नाम", "nm"]) or len(norm_header.split()) <= 2:
            return EType.RELATIVE_NAME

    lex_map = load_header_lexicons()

    # 1a. Exact match across all types first (prevents "sex" substring matching "age/sex")
    for cand in candidates:
        for etype, labels in lex_map.items():
            if cand in labels or cand.replace("_", " ") in labels:
                return etype

    # 1b. Substring/token match: e.g. "patient name (in english)" -> "patient name"
    for cand in candidates:
        cand_sp = cand.replace("_", " ")
        for etype, labels in lex_map.items():
            for lbl in labels:
                if lbl and (lbl in cand_sp or cand_sp in lbl):
                    if len(lbl) >= 3 and len(cand_sp) >= 3:
                        if len(lbl) / max(len(cand_sp), 1) > 0.55:
                            return etype

    # 2. Fuzzy match with rapidfuzz (>= 86% similarity)
    best_type: Optional[EType] = None
    best_score = 0.0

    for cand in candidates:
        cand_sp = cand.replace("_", " ")
        for etype, labels in lex_map.items():
            for lbl in labels:
                if not lbl or len(lbl) < 3:
                    continue
                score = fuzz.ratio(cand_sp, lbl)
                if score > best_score and score >= 86:
                    best_score = score
                    best_type = etype

    return best_type


def _is_name_like(val: str, med_terms: set[str], min_tokens: int = 2) -> bool:
    """Check if value is name-like: multi-token alphabetic words, not a sentence, not a medical term."""
    norm = normalize_for_match(val.strip())
    if not norm or len(norm) < 2:
        return False
    # If it contains digits or common sentence punctuation, not a pure name cell
    if re.search(r'[0-9@#$%^&*()_+={}\[\]|\\:;"<>,?/~`!.]', norm):
        return False
    tokens = norm.split()
    if not (min_tokens <= len(tokens) <= 4):
        return False
    lower_norm = norm.lower()
    if lower_norm in med_terms:
        return False
    # Common English words indicating a sentence/phrase, not a name
    non_name_stop_words = {
        "is", "was", "for", "with", "by", "and", "or", "in", "at", "to",
        "of", "from", "the", "a", "an", "on", "accompanied", "brought", "given"
    }
    if any(tok.lower() in non_name_stop_words for tok in tokens):
        return False
    # Check if each token is alphabetic (Latin or Devanagari)
    for tok in tokens:
        clean_tok = tok.replace('.', '')
        if not (clean_tok.isalpha() or all('\u0900' <= ch <= '\u097f' for ch in clean_tok)):
            return False
        if clean_tok.lower() in med_terms:
            return False
    return True


def profile_values(values: list[str]) -> Optional[EType]:
    """Profile column values: if >= 60% of non-empty values match a type, return that type."""
    if len(values) > 2000:
        step = max(1, len(values) // 1000)
        values = values[::step][:1000]
    non_empty = [v.strip() for v in values if v and str(v).strip()]
    if not non_empty:
        return None
    if len(non_empty) > 500:
        step = max(1, len(non_empty) // 500)
        non_empty = non_empty[::step][:500]

    total = len(non_empty)
    med_terms = load_medical_terms()

    counts: dict[EType, int] = {
        EType.PHONE: 0,
        EType.AADHAAR: 0,
        EType.AADHAAR_MASKED: 0,
        EType.ABHA_NUMBER: 0,
        EType.ABHA_ADDRESS: 0,
        EType.PAN: 0,
        EType.MRN: 0,
        EType.INSURANCE_ID: 0,
        EType.EMAIL: 0,
        EType.DATE: 0,
        EType.AGE: 0,
        EType.PIN: 0,
        EType.GENDER: 0,
        EType.PATIENT_NAME: 0,
    }

    for val in non_empty:
        norm = normalize_for_match(val)

        # Phone
        digits_clean = re.sub(r'[-\s+]', '', norm)
        if (len(digits_clean) == 10 and digits_clean[0] in '6789') or (len(digits_clean) == 12 and digits_clean.startswith('91') and digits_clean[2] in '6789'):
            counts[EType.PHONE] += 1
            continue

        # Aadhaar
        if len(digits_clean) == 12 and digits_clean[0] in '23456789' and validate_verhoeff(digits_clean):
            counts[EType.AADHAAR] += 1
            continue

        if RE_AADHAAR_MASKED.fullmatch(norm):
            counts[EType.AADHAAR_MASKED] += 1
            continue

        # ABHA
        if RE_ABHA_NUMBER.fullmatch(norm):
            counts[EType.ABHA_NUMBER] += 1
            continue
        if RE_ABHA_ADDRESS.fullmatch(norm):
            counts[EType.ABHA_ADDRESS] += 1
            continue

        # PAN
        if RE_PAN.fullmatch(norm):
            counts[EType.PAN] += 1
            continue

        # MRN / Hospital identifiers
        if RE_MRN.fullmatch(norm):
            counts[EType.MRN] += 1
            continue

        # Insurance
        if RE_INSURANCE.fullmatch(norm):
            counts[EType.INSURANCE_ID] += 1
            continue

        # Email
        if RE_EMAIL.fullmatch(norm):
            counts[EType.EMAIL] += 1
            continue

        # Date / DOB (value profiling classifies as generic DATE; header decides DOB)
        if RE_DATE_VALUE.fullmatch(norm):
            counts[EType.DATE] += 1
            continue

        # PIN (exactly 6 digits starting 1-8)
        if RE_PIN_STANDALONE.fullmatch(digits_clean) and len(digits_clean) == 6:
            counts[EType.PIN] += 1
            continue

        # Gender
        if RE_GENDER_VALUE.fullmatch(norm):
            counts[EType.GENDER] += 1
            continue

        # Age
        if RE_AGE_VALUE.fullmatch(norm):
            # Check numerical sanity (0 to 120)
            m_age = RE_AGE_VALUE.match(norm)
            if m_age and 0 <= int(m_age.group(1)) <= 120:
                counts[EType.AGE] += 1
                continue

        # Name-like
        if _is_name_like(val, med_terms):
            counts[EType.PATIENT_NAME] += 1

    # Check for >= 60% threshold
    threshold = 0.60 * total
    for etype, count in counts.items():
        if count >= threshold:
            return etype

    return None


def classify_column(header: str, values: list[str]) -> Optional[EType]:
    """Classify a column into an EType based on header lexicons and value profiling.
    
    Required contract: classify_column(header, values) -> EType | None
    Rules:
      1. Fuzzy header match against label lexicons (EN + HI)
      2. Value profiling (>= 60% non-empty values match an identifier)
      3. If header and values disagree: trust values for ID types, header for names.
      4. Relative columns (e.g. 'Relative Name', 'Guardian', 'S/O ...') -> RELATIVE_NAME
    """
    clean_hdr = normalize_for_match(header.strip().lower()) if header else ""
    hdr_type = _match_header_lexicon(clean_hdr)
    val_type = profile_values(values)

    # If relative header indicated, always preserve RELATIVE_NAME
    if hdr_type == EType.RELATIVE_NAME or RE_RELATIVE_HEADER.search(clean_hdr):
        return EType.RELATIVE_NAME

    # If header explicitly says non-name (procedure, status, category, from, to, etc.),
    # never infer PATIENT_NAME from alphabetic values alone.
    base_hdr = re.sub(r'\s*\([^)]*\)\s*$', '', clean_hdr).strip()
    if val_type == EType.PATIENT_NAME and hdr_type is None:
        hdr_tokens = set(re.split(r'[\s_/-]+', base_hdr))
        if clean_hdr in NON_NAME_HEADERS or bool(hdr_tokens & NON_NAME_HEADERS):
            return None

    # Date columns: the header wording decides DOB vs DATE; with an unreadable header the
    # spread of the years decides (birth dates span decades, visit dates do not).
    if val_type == EType.DATE:
        kind = _date_header_kind(header) if header else None
        if kind is not None:
            return kind
        if hdr_type in (EType.DOB, EType.DATE):
            return hdr_type
        return EType.DOB if _dates_look_like_birthdates(values) else EType.DATE

    # If header is DOB and values are dates -> DOB
    if hdr_type == EType.DOB and val_type == EType.DATE:
        return EType.DOB

    # If header is DATE (admission_date, visit_date, collected_on, etc.) -> DATE
    if hdr_type == EType.DATE:
        return EType.DATE

    # If header and values agree
    if hdr_type and val_type and hdr_type == val_type:
        return hdr_type

    # Disagreement rule:
    # Strong ID types: AADHAAR, ABHA_NUMBER, PAN, PHONE, EMAIL, MRN, INSURANCE_ID
    strong_ids = {
        EType.AADHAAR,
        EType.AADHAAR_MASKED,
        EType.ABHA_NUMBER,
        EType.ABHA_ADDRESS,
        EType.PAN,
        EType.PHONE,
        EType.EMAIL,
        EType.MRN,
        EType.INSURANCE_ID,
    }

    if val_type in strong_ids:
        # Preserve INSURANCE_ID if header explicitly matched insurance/policy
        if hdr_type == EType.INSURANCE_ID and val_type == EType.MRN:
            return EType.INSURANCE_ID
        # Trust value profiling for strong IDs even if header is generic/obfuscated
        return val_type

    if hdr_type in {EType.PATIENT_NAME, EType.RELATIVE_NAME}:
        # Trust header for names
        return hdr_type

    # If header matched a quasi-identifier (DOB, AGE, VILLAGE, TEHSIL, DISTRICT, PIN, GENDER) or address
    if hdr_type:
        return hdr_type

    # Fallback to value profile
    return val_type
