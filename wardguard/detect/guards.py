"""Meaning-trap guards to protect clinical and contextual non-PII values.

Implements TR-DET-6:
Ensures clinical terms, medical figures, doctors, dosages, and eponyms are never
treated as patient PII or stripped from research texts.

Contract:
    is_protected(text: str, start: int, end: int) -> bool

Guards:
1. Doctor names / prefixes: Dr., Dr, डॉ., (MD ...), Consultant, Attending
2. Doses and frequencies: 650mg, 1-0-1, BD, TDS, OD, HS, SOS, x 5 days, x 2 wks
3. Vitals: BP 150/90, Pulse 72, SpO2 98%, Temp 99.4 F, RBS 140 mg/dL
4. Labs with units: mg/dL, mmol/L, g/dL, /cumm, IU/L, etc.
5. Medical eponyms: Parkinson's disease, Crohn's, Addison's, Bell's palsy, etc.
6. Wards / beds: General Ward, Ward-12, Bed 14, ICU-2
7. Complaints & clinical prefixes: C/O <complaint>, K/C/O, H/O, O/E
8. Healthcare workers as roles: ASHA worker, ASHA didi, ANM
"""
from __future__ import annotations
import os
import re
from functools import lru_cache
from wardguard.detect.normalize import normalize_for_match

# 1. Doctor indicators preceding or following a span
# POS: "Dr. Ramesh", "Dr Ramesh", "डॉ. रमेश", "Dr. (MD Med) Ramesh", "Consultant Ramesh"
# NEG: "Patient Ramesh"
RE_DOCTOR_PREFIX = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:dr\.?|doctor|डॉ\.?|डॉक्टर|dr\s*\(md[^)]*\)|consultant|attending|prof\.?|surgeon|physician)\s*$'
)
RE_DOCTOR_SUFFIX = re.compile(
    r'(?i)^\s*(?:,\s*)?(?:\(?(?:md|ms|mbbs|dnb|frcs|dm|mch|bams|bhms)\)?|consultant|mo|smo|cmo)\b'
)

# 2. Doses, frequencies, and durations
# POS: "650mg", "1-0-1", "0-1-0", "BD", "TDS", "OD", "HS", "SOS", "x 5 days", "x 2 wks"
RE_DOSE_STRICT = re.compile(
    r'(?i)^\s*('
    r'\d+(?:\.\d+)?\s*(?:mg|g|mcg|ml|l|iu|tab|cap|puff|drops|tsp|tbsp|units?)\b'
    r'|[0-2]-[0-2]-[0-2](?:-[0-2])?'
    r'|(?:od|bd|bid|tds|tid|qid|hs|sos|stat|prn|ac|pc|q\d+h)\b'
    r'|x\s*\d+\s*(?:days?|weeks?|wks?|months?|d|w|m)\b'
    r'|\b(?:daily|twice\s*daily|thrice\s*daily|at\s*bedtime|sos)\b'
    r')\s*$'
)

# 3. Vitals and lab units
# POS: "BP 150/90", "120/80 mmHg", "Pulse 72/min", "SpO2 98%", "Temp 99.4 F"
RE_VITALS_CONTEXT = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:bp|blood\s*pressure|pulse|pr|hr|heart\s*rate|spo2|temp|temperature|rbs|fbs|ppbs|hb|tlc|platelets?|esr|crp)\s*[:=]?\s*$'
)
RE_LAB_UNITS_SUFFIX = re.compile(
    r'(?i)^\s*(?:mmhg|bpm|/min|%|f|c|mg/dl|mmol/l|g/dl|/cumm|cells/cumm|iu/l|u/l|ng/ml|pg/ml|meq/l)\b'
)

# 4. Clinical prefixes (C/O, K/C/O, H/O, O/E)
# POS: "C/O fever", "K/C/O diabetes", "H/O asthma", "O/E soft"
RE_CLINICAL_PREFIX = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:c/o|complaining\s*of|k/c/o|known\s*case\s*of|h/o|history\s*of|o/e|on\s*examination|dx|diagnosis|adv|rx|p/a|p/v|cns|cvs|rs)\s*[:=]?\s*$'
)

# 5. Ward / Bed references
# POS: "Ward 4 Bed 12", "General Ward", "ICU-2", "Bed No. 5"
RE_WARD_BED = re.compile(
    r'(?i)^\s*('
    r'(?:general\s*ward|ward|bed|icu|micu|sicu|nicu|picu|ccu|ot|cabin)\s*(?:no\.?|#|-)?\s*\d+[a-z]?'
    r'|(?:general\s*ward|male\s*ward|female\s*ward|casualty|emergency)'
    r')\s*$'
)

# 6. Healthcare worker roles (ASHA worker, ASHA didi, ANM)
# POS: "ASHA didi", "ASHA worker", "ANM didi", "आशा वर्कर", "आशा दीदी"
RE_HEALTH_ROLE = re.compile(
    r'(?i)^\s*(?:asha\s*(?:worker|didi|didi ji)?|anm|anganwadi\s*worker|आशा\s*(?:वर्कर|दीदी))\s*$'
)


@lru_cache(maxsize=1)
def load_eponyms_and_clinical_terms() -> tuple[set[str], set[str]]:
    """Load medical eponyms and complaints from resources/."""
    res_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "resources")

    def _read_file(fn: str) -> set[str]:
        path = os.path.join(res_dir, fn)
        if not os.path.exists(path):
            return set()
        with open(path, "r", encoding="utf-8") as f:
            return {
                normalize_for_match(line.strip().lower())
                for line in f
                if line.strip() and not line.startswith("#")
            }

    eponyms = _read_file("eponyms.txt")
    complaints = _read_file("complaints.txt")
    drugs = _read_file("drugs.txt")
    med_terms = _read_file("medical_terms_en_hi.txt")
    all_clinical = complaints | drugs | med_terms

    return eponyms, all_clinical


def is_protected(text: str, start: int, end: int) -> bool:
    """Check if the span text[start:end] is a protected clinical / non-PII term.
    
    Required contract: is_protected(text, start, end) -> bool
    Returns True if the span should be preserved and NOT flagged as patient PII.
    """
    if not text or start < 0 or end > len(text) or start >= end:
        return False

    span_text = text[start:end].strip()
    if not span_text:
        return False

    norm_span = normalize_for_match(span_text.lower())
    eponyms, clinical_terms = load_eponyms_and_clinical_terms()

    # 1. Direct medical eponym check (e.g. "Parkinson's", "Crohn's", "Bell's palsy")
    if norm_span in eponyms or norm_span.rstrip("'s") in eponyms or norm_span.rstrip("’s") in eponyms:
        return True

    # 2. General clinical terms (diseases, complaints, drugs, tests)
    if norm_span in clinical_terms:
        return True

    # 3. Check for dose / frequency / duration match
    if RE_DOSE_STRICT.match(span_text):
        return True

    # 4. Check for Ward / Bed references
    if RE_WARD_BED.match(span_text):
        return True

    # 5. Check for Health worker role (ASHA worker / didi)
    if RE_HEALTH_ROLE.match(span_text):
        return True

    # 6. Check surrounding context in the original text (up to 40 chars before and after)
    ctx_before = text[max(0, start - 40):start]
    ctx_after = text[end:min(len(text), end + 40)]

    # Doctor check: preceded by Dr., Doctor, डॉ., etc. OR followed by MD, MS, MBBS, etc.
    if RE_DOCTOR_PREFIX.search(ctx_before) or RE_DOCTOR_SUFFIX.search(ctx_after):
        return True

    # Clinical complaint check: preceded by C/O, K/C/O, H/O, etc.
    if RE_CLINICAL_PREFIX.search(ctx_before):
        # If what follows is a disease, symptom, or eponym, protect it
        words = norm_span.split()
        if any(w in clinical_terms or w in eponyms for w in words):
            return True

    # Vitals context: preceded by "BP", "Pulse", "SpO2", "Temp", etc.
    if RE_VITALS_CONTEXT.search(ctx_before) or RE_LAB_UNITS_SUFFIX.search(ctx_after):
        return True

    # Followed by disease / syndrome / palsy / test (e.g. "<Name>'s disease", "<Name>'s syndrome")
    after_lower = ctx_after.lower().strip()
    if any(after_lower.startswith(suffix) for suffix in ["disease", "syndrome", "palsy", "sign", "triad", "criteria", "test"]):
        return True

    return False
