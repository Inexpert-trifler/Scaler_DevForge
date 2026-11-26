"""Free-text context rules and detect_text integration.

Implements TR-DET-4, TR-DET-7:
- Name detection following labels (Name:, Pt., Patient:, नाम:, etc.)
- Name detection following relations (S/o, W/o, D/o, etc.) -> RELATIVE_NAME
- Name detection around honorifics (Shahid sahab, Asha ji, श्रीमती सुनीता, etc.)
- Demographic context (<Name> 48 Y / F, <Name> 45/M)
- Contextual sentence starters / markers in Hindi (सुनीता पटेल को ...) and English (called by <Name>, attendant <Name>)
- Integrates patterns, context rules, and gazetteer into detect_text
- Resolves overlapping spans and drops protected spans (guards.is_protected)
"""
from __future__ import annotations
import os
import re
from functools import lru_cache
from typing import Optional, Protocol
from wardguard.model import EType, Mention, Role, Channel, Script
from wardguard.detect.normalize import normalize_with_map, map_span_back, normalize_for_match
from wardguard.detect.patterns import find_identifiers, resolve_overlaps, _detect_script
from wardguard.detect.guards import is_protected, load_eponyms_and_clinical_terms

# ==============================================================================
# Regexes for Free-text Context Patterns
# ==============================================================================

# 1. Names after explicit name labels
# POS: "Name: Rahul Sharma", "Patient: Sunita Patel", "नाम: महेश यादव", "Pt: Anita"
RE_LABEL_NAME = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:name|patient(?:\s*name)?|pt\.?(?:\s*name)?|naam|नाम|मरीज़|मरीज|रोगी)\s*[:=-]\s*'
    r'([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){0,3})'
)

# 1b. Patient prefix without delimiter: "Patient Sunita Devi ko...", "Pt. Rajesh was admitted"
RE_PATIENT_PREFIX_NAME = re.compile(
    r'(?i:\b(?:patient|pt\.?|मरीज़|मरीज|रोगी)\s+(?!name\b|naam\b|id\b|no\b|number\b|details\b|info\b))'
    r'([A-Z\u0900-\u097f][a-z\u0900-\u097f]*(?:\s+[A-Z\u0900-\u097f][a-z\u0900-\u097f]*){0,2})'
)

# 2. Names after relations -> RELATIVE_NAME
# POS: "S/o Shyam Patel", "W/O Ramesh Kumar", "D/o Mohan Lal", "wife: Rekha Devi", "husband Naresh Chauhan", "father Babu Ram", "पत्नी स्व. श्री रामेश्वर दयाल"
RE_RELATION_NAME = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:s/o|d/o|w/o|c/o|h/o|f/o|m/o|son\s+of|daughter\s+of|wife\s+of|husband\s+of|father\s+of|mother\s+of|care\s+of|guardian|husband|wife|father|mother|brother|sister|अभिभावक|पुत्र|पुत्री|पत्नी|पति|पिता|माता)\s*[:=-]?\s*'
    r'(?:(?:late|swargiya|swargwasi|shri|smt\.?|shrimati|mr\.?|mrs\.?|ms\.?|dr\.?|स्व\.?|स्वर्गीय|श्री|श्रीमती|पं\.?)\s+)*'
    r'([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){0,3})'
)

# 3. Honorifics before name: Shri, Smt, Mr, Mrs, Ms, श्रीमती, श्री, etc.
# POS: "Shri Ramesh Verma", "Smt. Sunita Devi", "श्रीमती सुनीता", "श्री मोहन लाल"
RE_HONORIFIC_PREFIX_NAME = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:shri|shree|smt\.?|shrimati|mr\.?|mrs\.?|ms\.?|km\.?|kumari|master|pandit|pt\.?|श्री|श्रीमती|सुश्री|कुमारी|पं\.?)\s+'
    r'([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){0,2})'
)

# 4. Honorifics after name: <Name> ji, <Name> sahab, <Name> saheb, <Name> बाबू
# POS: "Shahid sahab", "Asha ji", "Sunil babu", "शाहिद साहब", "सुनील बाबू", "आशा जी"
RE_HONORIFIC_SUFFIX_NAME = re.compile(
    r'(?i)(?:^|[\s,;:(])([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){0,2})\s+'
    r'(?:sahab|saheb|ji|babu|साहब|जी|बाबू)(?:[\s,;:\n।.]|$)'
)

# 5. Demographic pattern: <Name> 48 Y / F, <Name>, 45/M, <Name> 54 वर्ष
# POS: "Sunita Patel 48 Y / F", "Ramesh Kumar 52/M", "सुनीता 45 वर्ष"
RE_DEMOGRAPHIC_NAME = re.compile(
    r'(?i)(?:^|[\s,;:(])([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){1,3})\s*'
    r'(?:,\s*)?\b\d{1,3}\s*(?:y(?:ears?|rs?)?|वर्ष|साल)?\s*(?:[/-]\s*(?:m(?:ale)?|f(?:emale)?|पुरुष|महिला))?\b'
)

# 6. Attendant / Called-by / Contact person pattern (Visitor logs, transport, tickets)
# POS: "called by Kaveri Nambiar", "Zorawar Qadri (attendant", "raised by Ilavenil Bhattacharya"
RE_CONTACT_PERSON = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:called\s+by|raised\s+by(?:\s*[:,-])?|contact\s+person(?:\s*[:,-])?)\s*'
    r'([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){1,3})'
)
RE_ATTENDANT_NAME = re.compile(
    r'(?i)(?:^|[\s,;:(-])\s*([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){1,3})\s*\(\s*(?:attendant|visitor|relative)'
)

# 7. Hindi sentence structure: <Name> <Surname> को ... / ने ...
# POS: "सुनीता पटेल को बुखार है", "रमेश कुमार ने बताया"
RE_HINDI_SENTENCE_NAME = re.compile(
    r'(?:^|[\s।,\n])([\u0900-\u097f]{2,15}\s+[\u0900-\u097f]{2,15})\s+(?:को|ने|का|की|के|द्वारा)\b'
)

# 7b. Hinglish sentence structure: Capitalized Name + Surname before Hindi postposition
# POS: "Sunita Patel ko bukhar hai", "Ramesh Kumar ne bataya"
RE_HINGLISH_SENTENCE_NAME = re.compile(
    r'(?:^|[\s।,\n])([A-Z][a-z]{1,15}\s+[A-Z][a-z]{1,15})\s+(?:ko|ne|ka|ke|ki|dwara)\b'
)


class GazetteerProtocol(Protocol):
    def find(self, text: str) -> list[tuple[int, int, Role, str]]:
        ...


@lru_cache(maxsize=1)
def load_census_and_tokens() -> tuple[set[str], set[str]]:
    """Load generic given names and surnames from resources."""
    res_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "resources")

    def _read_lines(fn: str) -> set[str]:
        path = os.path.join(res_dir, fn)
        if not os.path.exists(path):
            return set()
        with open(path, "r", encoding="utf-8") as f:
            tokens: set[str] = set()
            for line in f:
                l = line.strip()
                if l and not l.startswith("#"):
                    for part in l.split():
                        tokens.add(normalize_for_match(part.lower()))
            return tokens

    given_latin = _read_lines("given_names_latin.txt")
    given_deva = _read_lines("given_names_deva.txt")
    surnames = _read_lines("surnames.txt")
    name_tokens = _read_lines("generic_name_tokens.txt")

    all_names = given_latin | given_deva | surnames | name_tokens
    return all_names, surnames


DISALLOWED_NAME_TOKENS = {
    "name", "naam", "patient", "pt", "details", "info", "record", "case",
    "status", "hospital", "clinic", "ward", "bed", "unit", "male", "female",
    "age", "years", "year", "yrs", "yr", "address", "residence", "village",
    "district", "city", "state", "date", "time", "dr", "doctor",
}


def _is_valid_name_span(span: str) -> bool:
    """Validate that candidate string is indeed name-like and not clinical/system words."""
    norm = normalize_for_match(span.strip())
    if not norm or len(norm) < 2:
        return False
    # Check tokens
    tokens = norm.split()
    if not (1 <= len(tokens) <= 4):
        return False

    eponyms, clinical_terms = load_eponyms_and_clinical_terms()

    # Reject if entire span is clinical/eponym or structural word
    if norm.lower() in eponyms or norm.lower() in clinical_terms or norm.lower() in DISALLOWED_NAME_TOKENS:
        return False

    # Check that tokens are purely alphabetic (Latin or Devanagari)
    for tok in tokens:
        clean_tok = tok.replace('.', '')
        if not (clean_tok.isalpha() or all('\u0900' <= ch <= '\u097f' for ch in clean_tok)):
            return False
        if clean_tok.lower() in clinical_terms or clean_tok.lower() in eponyms or clean_tok.lower() in DISALLOWED_NAME_TOKENS:
            return False

    return True


def find_context_mentions(text: str) -> list[Mention]:
    """Extract names and quasi-identifiers using contextual grammatical rules."""
    if not text:
        return []

    norm_text, index_map = normalize_with_map(text)
    orig_len = len(text)
    mentions: list[Mention] = []

    def _add_mention(m_start: int, m_end: int, etype: EType, role: Role):
        start, end = map_span_back(m_start, m_end, index_map, orig_len)
        span_str = text[start:end].strip()
        if not _is_valid_name_span(span_str):
            return
        if is_protected(text, start, end):
            return
        mentions.append(Mention(
            etype=etype,
            start=start,
            end=end,
            text=span_str,
            script=_detect_script(span_str),
            channel="content",
            role=role,
            source="context",
            confidence=0.90,
        ))

    # 1. Names after explicit label
    for m in RE_LABEL_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    for m in RE_PATIENT_PREFIX_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 2. Names after relation
    for m in RE_RELATION_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.RELATIVE_NAME, "relative")

    # 3. Honorific prefix
    for m in RE_HONORIFIC_PREFIX_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 4. Honorific suffix (<Name> ji, <Name> sahab)
    for m in RE_HONORIFIC_SUFFIX_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 5. Demographic pattern (<Name> 48 Y / F)
    for m in RE_DEMOGRAPHIC_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 6. Contact / visitor / attendant person (Zorawar Qadri, Kaveri Nambiar, Ilavenil Bhattacharya)
    for m in RE_CONTACT_PERSON.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    for m in RE_ATTENDANT_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 7. Hindi sentence structure
    for m in RE_HINDI_SENTENCE_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    for m in RE_HINGLISH_SENTENCE_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    return mentions


def detect_text(
    text: str,
    channel: Channel = "content",
    gaz: Optional[GazetteerProtocol] = None,
    policy: Optional[dict] = None,
) -> list[Mention]:
    """Free-text detector for content, documents, and hidden channels.
    
    Required contract:
        detect_text(text: str, channel: Channel, gaz: Gazetteer, policy: dict) -> list[Mention]
    
    1. Extracts identifier patterns (find_identifiers)
    2. Extracts contextual mentions (find_context_mentions)
    3. Finds gazetteer name hits if gazetteer is supplied
    4. Filters out any spans protected by guards (is_protected)
    5. Resolves overlapping spans (longest wins)
    6. Returns non-overlapping Mention objects sorted by start offset.
    """
    if not text:
        return []

    all_mentions: list[Mention] = []

    # 1. Identifier patterns (Aadhaar, Phone, MRN, Email, PAN, ABHA, House, PIN)
    id_mentions = find_identifiers(text)
    for m in id_mentions:
        m.channel = channel
        all_mentions.append(m)

    # 2. Contextual rules (names, relatives, honorifics, demographics)
    ctx_mentions = find_context_mentions(text)
    for m in ctx_mentions:
        m.channel = channel
        all_mentions.append(m)

    # 3. Dynamic Gazetteer matches
    if gaz is not None:
        gaz_hits = gaz.find(text)
        for g_start, g_end, g_role, _ in gaz_hits:
            if not is_protected(text, g_start, g_end):
                span_str = text[g_start:g_end]
                etype = EType.RELATIVE_NAME if g_role == "relative" else EType.PATIENT_NAME
                all_mentions.append(Mention(
                    etype=etype,
                    start=g_start,
                    end=g_end,
                    text=span_str,
                    script=_detect_script(span_str),
                    channel=channel,
                    role=g_role,
                    source="gazetteer",
                    confidence=0.88,
                ))

    # 4. Final filter with meaning-trap guards
    filtered_mentions: list[Mention] = [
        m for m in all_mentions
        if not is_protected(text, m.start, m.end)
    ]

    # 5. Resolve overlaps (longest span wins; tie broken by priority)
    return resolve_overlaps(filtered_mentions)
