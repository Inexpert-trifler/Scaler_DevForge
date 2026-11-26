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

# Relative indicators in column headers
RE_RELATIVE_HEADER = re.compile(
    r'(?i)\b('
    r'relative|guardian|father|husband|mother|caregiver|s/o|d/o|w/o|c/o|h/o|f/o|m/o|'
    r'पिता|पति|माता|अभिभावक|पुत्र|पुत्री|wali|valad'
    r')\b'
)

# Date/DOB regex for values: DD/MM/YYYY, YYYY-MM-DD, DD-MM-YYYY, etc.
# POS: "12/04/1977", "1985-06-20", "25-11-2001" | NEG: "650mg", "1-0-1"
RE_DATE_VALUE = re.compile(r'^\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\s*$')

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
        EType.DOB: set(),
        EType.AGE: set(),
        EType.VILLAGE: set(),
        EType.HOUSE: set(),
        EType.PIN: set(),
        EType.GENDER: {"gender", "sex", "लिंग", "gender/sex"},
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
    lex_map[EType.MRN] = _read_lines("labels_id.txt")
    lex_map[EType.DOB] = _read_lines("labels_dob.txt")
    lex_map[EType.AGE] = _read_lines("labels_age.txt")
    lex_map[EType.VILLAGE] = _read_lines("labels_village.txt")

    addr_labels = _read_lines("labels_address.txt")
    for lbl in addr_labels:
        if "pin" in lbl:
            lex_map[EType.PIN].add(lbl)
        elif any(k in lbl for k in ["h.no", "house", "मकान"]):
            lex_map[EType.HOUSE].add(lbl)
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
    """Match cleaned header against known label lexicons (exact + fuzzy)."""
    if not norm_header:
        return None

    # Check for relative header explicitly
    if RE_RELATIVE_HEADER.search(norm_header):
        if any(w in norm_header for w in ["name", "naam", "नाम", "nm"]):
            return EType.RELATIVE_NAME

    lex_map = load_header_lexicons()

    # 1. Exact match or token containment
    for etype, labels in lex_map.items():
        if norm_header in labels:
            return etype
        # Substring/token match: e.g. "patient name (in english)" -> "patient name"
        for lbl in labels:
            if lbl and (lbl in norm_header or norm_header in lbl):
                # Guard against short token misfires
                if len(lbl) >= 3 and len(norm_header) >= 3:
                    if len(lbl) / max(len(norm_header), 1) > 0.5:
                        return etype

    # 2. Fuzzy match with rapidfuzz (> 85% similarity)
    best_type: Optional[EType] = None
    best_score = 0.0

    for etype, labels in lex_map.items():
        for lbl in labels:
            if not lbl or len(lbl) < 3:
                continue
            score = fuzz.ratio(norm_header, lbl)
            if score > best_score and score >= 85:
                best_score = score
                best_type = etype

    return best_type


def _is_name_like(val: str, med_terms: set[str]) -> bool:
    """Check if value is name-like: 1-4 alphabetic tokens, not a number, not a medical term."""
    norm = normalize_for_match(val.strip())
    if not norm or len(norm) < 2:
        return False
    # If it contains digits or common punctuation (except period/hyphen), not a pure name
    if re.search(r'[0-9@#$%^&*()_+={}\[\]|\\:;"<>,?/~`]', norm):
        return False
    tokens = norm.split()
    if not (1 <= len(tokens) <= 5):
        return False
    lower_norm = norm.lower()
    if lower_norm in med_terms:
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
    non_empty = [v.strip() for v in values if v and str(v).strip()]
    if not non_empty:
        return None

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
        EType.DOB: 0,
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

        # Date / DOB
        if RE_DATE_VALUE.fullmatch(norm):
            counts[EType.DOB] += 1
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
        # Trust value profiling for strong IDs even if header is generic/obfuscated
        return val_type

    if hdr_type in {EType.PATIENT_NAME, EType.RELATIVE_NAME}:
        # Trust header for names
        return hdr_type

    # If header matched a quasi-identifier (DOB, AGE, VILLAGE, PIN, GENDER)
    if hdr_type:
        return hdr_type

    # Fallback to value profile
    return val_type
