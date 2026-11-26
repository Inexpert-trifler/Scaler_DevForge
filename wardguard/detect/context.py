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
    r'(?i:\b(?:patient|pt\.?|मरीज़|मरीज|रोगी)\s+(?!name\b|naam\b|id\b|no\b|number\b|details\b|info\b|का\s|की\s|के\s|नाम|का$))'
    r'([A-Z\u0900-\u097f][a-z\u0900-\u097f]*(?:\s+[A-Z\u0900-\u097f][a-z\u0900-\u097f]*){0,2})'
)

# 2. Names after relations -> RELATIVE_NAME
# POS: "S/o Shyam Patel", "W/O Ramesh Kumar", "D/o Mohan Lal", "wife: Rekha Devi", "pita: Shyam", "पत्नी स्व. श्री रामेश्वर दयाल"
# Note: c/o and h/o require Title Case or Devanagari start (never lowercase "C/O loose stools" or "H/O asthma"!).
RE_RELATION_NAME = re.compile(
    r'(?:(?i:(?:^|[\s,;:(])(?:s/o|d/o|w/o|f/o|m/o|son\s+of|daughter\s+of|wife\s+of|husband\s+of|father\s+of|mother\s+of|guardian|husband|wife|father|mother|brother|sister|अभिभावक|पुत्र|पुत्री|पत्नी|पति|पिता|माता)\s*[:=-]?\s*'
    r'(?:(?:late|swargiya|swargwasi|shri|smt\.?|shrimati|mr\.?|mrs\.?|ms\.?|dr\.?|स्व\.?|स्वर्गीय|श्री|श्रीमती|पं\.?)\s+)*)'
    r'([A-Za-z\u0900-\u097f]+(?:[ \t]+[A-Za-z\u0900-\u097f]+){0,3})'
    r'|(?i:(?:^|[\s,;:(])(?:c/o|care\s+of|h/o)\s*[:=-]?\s*)'
    r'((?:(?:Late|Shri|Smt\.?|Shrimati|Mr\.?|Mrs\.?|Ms\.?|श्री|श्रीमती)\s+)*'
    r'[A-Z\u0900-\u097f][a-z\u0900-\u097f]+(?:[ \t]+[A-Z\u0900-\u097f][a-z\u0900-\u097f]+){0,3}))'
)

# 3. Honorifics before name: Shri, Smt, Mr, Mrs, Ms, श्रीमती, श्री, etc.
# POS: "Shri Ramesh Verma", "Smt. Sunita Devi", "श्रीमती सुनीता", "श्री मोहन लाल"
RE_HONORIFIC_PREFIX_NAME = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:shri|shree|smt\.?|shrimati|mr\.?|mrs\.?|ms\.?|km\.?|kumari|master|pandit|pt\.?|श्री|श्रीमती|सुश्री|कुमारी|पं\.?)\s+'
    r'([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){0,2})'
)

# 4. Honorifics after name: <Name> ji, <Name> sahab, <Name> saheb, <Name> bhai, <Name> behenji
# POS: "Shahid sahab", "Asha ji", "Sunil babu", "Mahesh bhai", "Anita behenji", "शाहिद साहब"
RE_HONORIFIC_SUFFIX_NAME = re.compile(
    r'(?i)(?:^|[\s,;:(])([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){0,2})\s+'
    r'(?:sahab|saheb|ji|babu|bhai|bhaiya|behen|behenji|ben|didi|amma|abbu|dadi|dada|nani|nana|chacha|chachi|kaka|bua|mausi|uncle|aunty|साहब|जी|बाबू|भाई|भैया|बहन|दीदी|अम्मा)(?:[\s,;:\n।.]|$)'
)

# 4b. Single/short name immediately preceding relation marker: "Asha, W/o Kamal", "Ramu S/o Hari"
RE_BEFORE_RELATION_NAME = re.compile(
    r'(?:^|[\s,;:(])([A-Za-z\u0900-\u097f]{2,20}(?:[ \t]+[A-Za-z\u0900-\u097f]{2,20})?)\s*,\s*(?i:s/o|d/o|w/o|c/o|h/o|f/o|m/o)\b'
)

# 4c. Possessive patient reference before relative/attendant: "Asha's attendant", "Anita's husband"
RE_POSSESSIVE_PERSON = re.compile(
    r'(?:^|[\s,;:(])([A-Z\u0900-\u097f][a-z\u0900-\u097f]{1,20}(?:[ \t]+[A-Z\u0900-\u097f][a-z\u0900-\u097f]{1,20})?)\s*[\'\u2019]s\s+'
    r'(?i:attendant|relative|husband|wife|father|mother|son|daughter|brother|sister|family|guardian)\b'
)

# 5. Demographic pattern: <Name> 48 Y / F, <Name>, 45/M, <Name> 54 वर्ष, <div>Zainab Siddiqui, 23 yrs
# POS: "Sunita Patel 48 Y / F", "Ramesh Kumar 52/M", "सुनीता 45 वर्ष"
# The age marker is REQUIRED: either an age unit (Y, Yrs, years, वर्ष, साल) or a
# gender marker (/M, /F). Without it "Review in OPD after 2 weeks" looked like a name.
# Names must start with a capital letter (or Devanagari).
RE_DEMOGRAPHIC_NAME = re.compile(
    r'(?:^|[\s,;:(>])([A-Z\u0900-\u097f][A-Za-z\u0900-\u097f]*(?:[ \t]+[A-Z\u0900-\u097f][A-Za-z\u0900-\u097f]*){0,3})[ \t]*'
    r'(?:,[ \t]*)?\b\d{1,3}[ \t]*'
    r'(?i:(?:y|yrs?|years?|वर्ष|साल)\b[ \t]*(?:[/-][ \t]*(?:m|f|male|female|पुरुष|महिला)\b)?'
    r'|[/-][ \t]*(?:m|f|male|female|पुरुष|महिला)\b)'
)

# 6. Attendant / Called-by / Contact person pattern (Visitor logs, transport, tickets, consent)
# POS: "called by Kaveri Nambiar", "witnessed by Tsering Wangmo", "Zorawar Qadri (attendant", "raised by Ilavenil Bhattacharya"
RE_CONTACT_PERSON = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:called\s+by|raised\s+by(?:\s*[:,-])?|witnessed\s+by|signed\s+by|brought\s+by|verified\s+by|reported\s+by|submitted\s+by|informed\s+by|accompanied\s+by(?!\s+(?:husband|wife|father|mother|son|daughter|relative|brother|sister|guardian)\b)|contact\s+person(?:\s*[:,-])?)\s*'
    r'([A-Za-z\u0900-\u097f]+(?:[ \t]+[A-Za-z\u0900-\u097f]+){1,3})'
)
RE_ATTENDANT_LABEL = re.compile(
    r'(?i)(?:^|[\s,;:(])attendant\s*[:=-]\s*([A-Za-z\u0900-\u097f]+(?:[ \t]+[A-Za-z\u0900-\u097f]+){0,3})'
)
RE_ATTENDANT_NAME = re.compile(
    r'(?i)(?:^|[\s,;:(-])\s*([A-Za-z\u0900-\u097f]+(?:\s+[A-Za-z\u0900-\u097f]+){1,3})\s*\(\s*(?:attendant|visitor|relative)'
)

# 8. Quasi-Identifier context regexes for free text: DOB, Clinical DATE, VILLAGE, AGE
_MONTHS = r'(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)'
_HI_MONTHS = r'(?:जनवरी|फ़?फरवरी|मार्च|अप्रैल|मई|जून|जुलाई|अगस्त|सितंबर|अक्टूबर|नवंबर|दिसंबर)'
DATE_VALUE = (
    r'(?:[\d०-९]{1,4}[-/.][\d०-९]{1,2}[-/.][\d०-९]{2,4}'
    r'|[\d०-९]{1,2}(?:st|nd|rd|th)?[ \t-]*(?:' + _MONTHS + r'|' + _HI_MONTHS + r')\.?[ \t,-]*[\d०-९]{2,4}'
    r'|' + _MONTHS + r'\.?[ \t]+[\d०-९]{1,2}(?:st|nd|rd|th)?,?[ \t]+[\d०-९]{4})'
)
RE_DOB_CONTEXT = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:dob|d\.o\.b\.?|date\s+of\s+birth|birth\s+date|born\s+on|janm\s+tithi|janm\s+tarikh|जन्म\s*(?:तिथि|दिनांक|तारीख))\s*[:=-]?\s*'
    r'(' + DATE_VALUE + r')'
)
RE_DATE_CONTEXT = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:date(?:\s+of\s+(?:admission|discharge|visit|collection|report))?|admitted(?:\s+on)?|discharged(?:\s+on)?|visit|collected|reported|भर्ती\s+की\s+तारीख|छुट्टी\s+की\s+तारीख|तारीख|दिनांक)\s*[:=-]\s*'
    r'(' + DATE_VALUE + r')'
)
RE_VILLAGE_CONTEXT = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:village|gram|gaon|ग्राम|गाँव|गांव)\s*[:=-]?\s*'
    r'([A-Za-z\u0900-\u097f][A-Za-z\u0900-\u097f\s]{1,35}?)(?=[,\n।;]|$|\s+(?:tehsil|taluka|dist|distt|तहसील|जिला))'
)

# 9. Address lines: every comma-separated part after an address label is a
# location quasi-identifier unless it is an administrative unit we keep (tehsil,
# district, state) or a PIN (handled by the PIN pattern).
RE_ADDRESS_LINE = re.compile(
    r'(?im)(?:^|[\s,;(])(?:address|addr\.?|add\.|permanent\s+address|present\s+address|residence|r/o|resident\s+of|residing\s+at|pata|पता|निवासी|निवास)\s*[:=-]?[ \t]*'
    r'([^\n]{3,220})'
)
_ADMIN_PREFIX = re.compile(
    r'(?i)^(?:(?:tehsil|teh\.?|tahsil|taluka|taluk|block|distt?\.?|district|dist\.|jila|zila|state|u\.?\s?p\.?|'
    r'uttar\s+pradesh|bihar|india|pin(?:code)?|post|p\.?o\.?|thana|ps)(?![A-Za-z])'
    r'|(?:तहसील|जिला|ज़िला|जनपद|ब्लॉक|उत्तर\s+प्रदेश|पिन|डाकघर|थाना))'
)
# parts that are people, not places (handled by the relation / honorific rules)
_PERSON_PREFIX = re.compile(
    r'(?i)^(?:c/o|s/o|d/o|w/o|h/o|f/o|m/o|care\s+of|son\s+of|wife\s+of|daughter\s+of|shri|smt\.?|mr\.?|mrs\.?|'
    r'late|dr\.?|patient|name)(?![A-Za-z])|^(?:पुत्र|पुत्री|पत्नी|पति|पिता|श्री|श्रीमती|स्व\.?)'
)
_LANDMARK_HINT = re.compile(r'(?i)^(?:near|opp\.?|opposite|behind|beside|next\s+to)\b|(?:के\s+(?:पास|पीछे|सामने|नज़दीक|नजदीक|बगल))$')
_LOCALITY_HINT = re.compile(r'(?i)\b(?:ward|mohalla|mohalla|nagar|colony|basti|tola|gali|lane|road|marg|sector|chowk|bazar|bazaar|मोहल्ला|नगर|कॉलोनी|बस्ती|टोला|गली|वार्ड)\b')
_SENTENCE_END = re.compile(r'(?i)(?:;|\s(?:for|with|since|who|was|is|has|referred|admitted|kindly|aged)\s)')
_ABBREV_BEFORE_DOT = {"no", "nn", "h", "st", "dr", "mr", "mrs", "smt", "shri", "distt", "dist", "teh", "opp", "nr",
                      "p", "o", "po", "ps", "vill", "vil", "add", "addr", "mob", "ph", "r", "u", "नं", "स्व", "डॉ", "श्री"}


def _sentence_cut(seg: str) -> int:
    """Length of the address part of `seg` (stops at a real sentence end, not at 'No.' / 'नं.')."""
    cut = len(seg)
    m = _SENTENCE_END.search(seg)
    if m:
        cut = m.start()
    for dm in re.finditer(r'\.\s+', seg[:cut]):
        prev = re.search(r'([^\s.,]+)$', seg[:dm.start()])
        word = prev.group(1).lower() if prev else ""
        if word and word not in _ABBREV_BEFORE_DOT and len(word) > 2 and not word.isdigit():
            return dm.start()
    return cut

# 10. Kinship-named relatives: "Jagdish Chachu", "Ramesh Mama", "Sunil Bhaiya"
_KIN_WORDS = (r'chachu|chacha|chachi|mama|mami|mamu|papa|pappa|mummy|bhaiya|bhaiyya|didi|mausi|mausa|fufa|phupha|bua|'
              r'jiju|jija|bhabhi|nana|nani|dada|dadi|tau|tai|taiji|bhanja|bhatija|beta|beti|uncle|aunty|aunti')
RE_KIN_NAME = re.compile(
    r'(?<![A-Za-z])([A-Z][a-z]{1,20}(?:[ \t]+[A-Z][a-z]{1,20})?)[ \t]+(?i:' + _KIN_WORDS + r')(?![A-Za-z])'
)
RE_KIN_NAME_DEVA = re.compile(
    r'(?<![ऀ-ॿ])([ऀ-ॿ]{2,15}(?:[ \t]+[ऀ-ॿ]{2,15})?)[ \t]+'
    r'(?:चाचा|चाचू|चाची|मामा|मामी|पापा|भैया|दीदी|मौसी|मौसा|फूफा|बुआ|जीजा|जीजू|भाभी|नाना|नानी|दादा|दादी|ताऊ|ताई)(?![ऀ-ॿ])'
)
# 11. Chat exports: "[23/06/26, 8:11 pm] Jagdish Chachu: ..." -> the sender is a person
RE_CHAT_SENDER = re.compile(r'(?m)^\[[^\]\n]{4,40}\][ \t]*(?:-[ \t]*)?([^:\n\[\]]{2,40}?)[ \t]*:')

# 12. Ages in demographic context (banded at rewrite). Durations ("x 6 yrs") never match:
# a label (Age, Aged, Umar, आयु) or an age/sex marker ("45 Y / F", "66 Yrs/M") is required.
RE_AGE_LABEL = re.compile(
    r'(?i)(?:^|[\s,;:(])(?:age(?:\s*/\s*(?:sex|gender))?|aged|umar|umra|umr|आयु|उम्र|उमर)\s*[:=-]?\s*([\d०-९]{1,3})(?![\d०-९.])'
    r'(?=\s*(?:y\b|yrs?\b|years?\b|yr\b|वर्ष|साल|/|,|;|\s|$))'
)
RE_AGE_SEX = re.compile(
    r'(?i)(?<![\w/.])([\d०-९]{1,3})[ \t]*(?:y|yrs?|years?|वर्ष|साल)[ \t]*[/-][ \t]*(?:m|f|male|female|पुरुष|महिला)\b'
)

# 13. Initials + surname ("T. R. Chauhan", "R.K. Sharma") and alias labels ("also known as", "urf")
_ORG_WORDS = {"serum", "urine", "blood", "plasma", "total", "random", "fasting", "stool", "sputum", "culture",
              "police", "hospital", "clinic", "college", "school", "university", "bank", "road", "marg", "nagar",
              "colony", "ward", "block", "district", "government", "govt", "pharma", "pharmacy", "labs", "lab",
              "diagnostics", "nursing", "home", "trust", "society", "limited", "ltd", "india", "pradesh", "station",
              "medical", "centre", "center", "foundation", "insurance", "scheme", "department", "dept"}
RE_INITIALS_NAME = re.compile(r'(?<![A-Za-z.])((?:[A-Z]\.[ \t]?){1,3}[A-Z][a-z]{2,20})(?![A-Za-z])')
RE_ALIAS_NAME = re.compile(
    r'(?i)(?:also\s+known\s+as|a\.?k\.?a\.?|alias|urf|उर्फ)\s*[:=-]?\s*'
    r'([A-Za-zऀ-ॿ][A-Za-z.ऀ-ॿ]*(?:[ \t]+[A-Za-zऀ-ॿ][A-Za-z.ऀ-ॿ]*){0,3})'
)

# 14. JSON-style fields seen as plain text (broken / NDJSON exports): "pt_name": "Chhedi Maurya"
RE_JSON_NAME_FIELD = re.compile(
    r'"([A-Za-z_ \-]*(?:name|naam|nm)[A-Za-z_ \-]*)"\s*:\s*"([^"\\\n]{2,60})"', re.IGNORECASE
)
_JSON_NONPERSON_KEY = re.compile(r'(?i)doctor|dr_|consultant|hospital|facility|drug|medicine|test|file|system|'
                                 r'scheme|ward|dept|department|unit|lab|org|village|district|city|state|disease|dx')
_JSON_RELATIVE_KEY = re.compile(r'(?i)relative|father|husband|mother|guardian|spouse|wife|pita|pati|mata|kin')

# 7. Hindi sentence structure: <Name> <Surname> को ... / ने ...
# POS: "सुनीता पटेल को बुखार है", "रमेश कुमार ने बताया"
RE_HINDI_SENTENCE_NAME = re.compile(
    r'(?:^|[\s।,\n])([\u0900-\u097f]{2,15}\s+[\u0900-\u097f]{2,15})\s+(?:को|ने|का|की|के|द्वारा)(?![\u0900-\u097f])'
)

# 7b. Hinglish sentence structure: Capitalized Name (+ optional Surname) before Hindi postposition
# POS: "Sunita Patel ko bukhar hai", "Ramesh Kumar ne bataya", "Manoj ka BP 111/78"
RE_HINGLISH_SENTENCE_NAME = re.compile(
    r'(?:^|[\s।,\n])([A-Z][a-z]{2,15}(?:[ \t]+[A-Z][a-z]{1,15})?)\s+(?:ko|ne|ka|ke|ki|dwara)\b'
)


STRONG_ID_TYPES = frozenset({
    EType.PHONE, EType.AADHAAR, EType.AADHAAR_MASKED, EType.ABHA_NUMBER, EType.ABHA_ADDRESS,
    EType.PAN, EType.EMAIL, EType.MRN, EType.INSURANCE_ID, EType.CANARY,
})


class GazetteerProtocol(Protocol):
    def find(self, text: str, channel: Channel = "content") -> list[tuple[int, int, Role, str]]:
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
    # Devanagari label / grammar words that are never part of a name
    "का", "की", "के", "को", "ने", "नाम", "पता", "आयु", "उम्र", "लिंग", "तिथि", "दिनांक", "मरीज़", "मरीज", "रोगी",
    "मोबाइल", "फोन", "ग्राम", "तहसील", "जिला", "निदान", "दवा", "जन्म", "पिन", "आधार", "आभा", "वर्ष", "साल",
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
        clean_tok = tok.replace('.', '').replace("'", "").replace("\u2019", "")
        if not (clean_tok.isalpha() or all('\u0900' <= ch <= '\u097f' for ch in clean_tok)):
            return False
        if clean_tok.lower() in clinical_terms or clean_tok.lower() in eponyms or clean_tok.lower() in DISALLOWED_NAME_TOKENS:
            return False

    return True


_EDGE_STOP = {"report", "of", "the", "for", "to", "from", "with", "and", "by", "dear", "hi", "hello", "sir",
              "madam", "patient", "pt", "case", "name", "naam", "age", "sex", "gender", "yrs", "yr", "years", "male",
              "female", "mobile", "mob", "phone", "ph", "uhid", "mrn", "ipd", "opd", "dob", "address", "aged",
              "referring", "refer", "kindly", "is", "was", "ko", "ne", "ka", "ki", "ke", "ji", "on", "at", "in"}


_NAME_CUT = {"को", "ने", "का", "की", "के", "से", "में", "द्वारा", "ko", "ne", "ka", "ki", "ke", "se", "mein", "was", "is",
             "has", "had", "with", "admitted", "presented", "came", "complains", "c/o"}


def _trim_name_span(text: str, start: int, end: int) -> tuple[int, int]:
    """Drop structural words captured at the edges of a name ("Report of Sunita" -> "Sunita",
    "Harjinder Gill        Age" -> "Harjinder Gill"). Stops at a run of 2+ spaces or a tab, which
    separates fields in fixed-width documents."""
    seg = text[start:end]
    gap = re.search(r'[ ]{2,}|\t|\n', seg.strip())
    if gap:
        lead = len(seg) - len(seg.lstrip())
        end = start + lead + gap.start()
        seg = text[start:end]
    toks = [(m.start(), m.end()) for m in re.finditer(r'\S+', seg)]
    # a postposition / connector ends the name: "सुनीता पटेल को सिरदर्द" -> "सुनीता पटेल"
    for i, (a, b) in enumerate(toks):
        if i > 0 and seg[a:b].strip('.,:;।') in _NAME_CUT:
            toks = toks[:i]
            break
    while toks and normalize_for_match(seg[toks[0][0]:toks[0][1]]).lower().strip('.,:;') in _EDGE_STOP:
        toks.pop(0)
    while toks and normalize_for_match(seg[toks[-1][0]:toks[-1][1]]).lower().strip('.,:;') in _EDGE_STOP:
        toks.pop()
    if not toks:
        return start, start
    return start + toks[0][0], start + toks[-1][1]


def find_context_mentions(text: str) -> list[Mention]:
    """Extract names and quasi-identifiers using contextual grammatical rules."""
    if not text:
        return []

    norm_text, index_map = normalize_with_map(text)
    orig_len = len(text)
    mentions: list[Mention] = []

    def _add_mention(m_start: int, m_end: int, etype: EType, role: Role):
        start, end = map_span_back(m_start, m_end, index_map, orig_len)
        start, end = _trim_name_span(text, start, end)
        ap = re.match(r"['\u2019][A-Z][a-z]+", text[end:end + 25])
        if ap and end > start:
            end += ap.end()
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
        grp = 1 if m.group(1) is not None else 2
        _add_mention(m.start(grp), m.end(grp), EType.RELATIVE_NAME, "relative")

    # 3. Honorific prefix
    for m in RE_HONORIFIC_PREFIX_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 4. Honorific suffix (<Name> ji, <Name> sahab, <Name> bhai, <Name> behenji)
    for m in RE_HONORIFIC_SUFFIX_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 4b. Name preceding relation ("Asha, W/o Kamal")
    for m in RE_BEFORE_RELATION_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 4c. Possessive patient before attendant/relative ("Asha's attendant")
    for m in RE_POSSESSIVE_PERSON.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 5. Demographic pattern (<Name> 48 Y / F)
    for m in RE_DEMOGRAPHIC_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 6. Contact / visitor / attendant person (Zorawar Qadri, Kaveri Nambiar, Ilavenil Bhattacharya, Tsering Wangmo)
    for m in RE_CONTACT_PERSON.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    for m in RE_ATTENDANT_LABEL.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.RELATIVE_NAME, "relative")

    for m in RE_ATTENDANT_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 7. Hindi sentence structure
    for m in RE_HINDI_SENTENCE_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    for m in RE_HINGLISH_SENTENCE_NAME.finditer(norm_text):
        _add_mention(m.start(1), m.end(1), EType.PATIENT_NAME, "patient")

    # 8. Contextual Quasi-Identifiers: DOB, DATE, VILLAGE
    for m in RE_DOB_CONTEXT.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_str = text[start:end].strip()
        if span_str:
            mentions.append(Mention(
                etype=EType.DOB,
                start=start,
                end=end,
                text=span_str,
                script=_detect_script(span_str),
                channel="content",
                role="patient",
                source="context",
                confidence=0.95,
            ))

    for m in RE_DATE_CONTEXT.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_str = text[start:end].strip()
        if span_str:
            mentions.append(Mention(
                etype=EType.DATE,
                start=start,
                end=end,
                text=span_str,
                script=_detect_script(span_str),
                channel="content",
                role="patient",
                source="context",
                confidence=0.90,
            ))

    for m in RE_VILLAGE_CONTEXT.finditer(norm_text):
        start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
        span_str = text[start:end].strip()
        # Trim trailing whitespace back
        while end > start and text[end - 1].isspace():
            end -= 1
        span_str = text[start:end]
        if len(span_str) >= 3 and not is_protected(text, start, end):
            mentions.append(Mention(
                etype=EType.VILLAGE,
                start=start,
                end=end,
                text=span_str,
                script=_detect_script(span_str),
                channel="content",
                role="patient",
                source="context",
                confidence=0.88,
            ))

    def _add_raw(start: int, end: int, etype: EType, role: Role, conf: float, validate_name: bool) -> None:
        while start < end and text[start] in " \t,;:-":
            start += 1
        while end > start and text[end - 1] in " \t,;:-.":
            end -= 1
        span_str = text[start:end]
        if not span_str or (etype != EType.AGE and len(span_str) < 2):
            return
        if validate_name and not _is_valid_name_span(span_str):
            return
        mentions.append(Mention(
            etype=etype, start=start, end=end, text=span_str, script=_detect_script(span_str),
            channel="content", role=role, source="context", confidence=conf,
        ))

    # 9. Address-line segmentation
    for m in RE_ADDRESS_LINE.finditer(text):
        seg_text = m.group(1)
        base = m.start(1)
        seg_text = seg_text[:_sentence_cut(seg_text)]
        # split on commas / "-" before a PIN / " | "
        parts: list[tuple[int, int]] = []
        pos = 0
        for sm in re.finditer(r',|\s+-\s+|\s\|\s|।', seg_text):
            parts.append((pos, sm.start()))
            pos = sm.end()
        parts.append((pos, len(seg_text)))
        cleaned = []
        for a, b in parts:
            frag = seg_text[a:b]
            lead = len(frag) - len(frag.lstrip())
            frag_s = frag.strip()
            if frag_s:
                cleaned.append((base + a + lead, base + a + lead + len(frag_s), frag_s))
        for i, (a, b, frag) in enumerate(cleaned):
            if _ADMIN_PREFIX.match(frag) or _PERSON_PREFIX.match(frag):
                continue
            if re.fullmatch(r'[\d०-९\s*]+', frag):
                continue  # PIN / numbers: handled by the identifier patterns
            if not re.search(r'[A-Za-z\u0900-\u097f]', frag):
                continue
            if len(frag) > 60:
                continue
            nxt = cleaned[i + 1][2] if i + 1 < len(cleaned) else ""
            if _LANDMARK_HINT.search(frag):
                etype = EType.LANDMARK
            elif _LOCALITY_HINT.search(frag) and not re.match(r'(?i)^(?:house|h\.?\s*no|makan|flat|plot|मकान)', frag):
                etype = EType.LOCALITY
            elif re.match(r'(?i)^(?:house|h\.?\s*no|makan|flat|plot|मकान)', frag):
                etype = EType.HOUSE
            elif _ADMIN_PREFIX.match(nxt) or not nxt or i == len(cleaned) - 1:
                etype = EType.VILLAGE
            else:
                etype = EType.LOCALITY
            _add_raw(a, b, etype, "patient", 0.85, validate_name=False)

    # 10. Kinship-named relatives
    for rx in (RE_KIN_NAME, RE_KIN_NAME_DEVA):
        for m in rx.finditer(text):
            _add_raw(m.start(1), m.end(1), EType.RELATIVE_NAME, "relative", 0.88, validate_name=True)

    # 11. Chat senders
    for m in RE_CHAT_SENDER.finditer(text):
        sender = m.group(1)
        if re.search(r'\d', sender):
            continue  # a phone number sender is caught by the PHONE pattern
        km = re.search(r'(?i)[ \t]+(?:' + _KIN_WORDS + r')$', sender)
        end = m.start(1) + (km.start() if km else len(sender))
        _add_raw(m.start(1), end, EType.RELATIVE_NAME, "relative", 0.9, validate_name=True)

    # 13. Initials and aliases (doctors stay protected by the Dr./MD guards in detect_text)
    for m in RE_INITIALS_NAME.finditer(text):
        span = m.group(1)
        last = span.split(".")[-1].strip().lower()
        if re.search(r'[\d०-९]', text[max(0, m.start(1) - 8):m.start(1)]):
            continue  # "Temp 99.2 F. Serum ..." - a unit after a number, not an initial
        if (re.search(r'[a-z]{3,}', span) and last not in _ORG_WORDS and _is_valid_name_span(last)
                and not is_protected(text, m.start(1), m.end(1))):
            _add_raw(m.start(1), m.end(1), EType.PATIENT_NAME, "patient", 0.8, validate_name=False)
    for m in RE_ALIAS_NAME.finditer(text):
        a, b = _trim_name_span(text, m.start(1), m.end(1))
        if b > a:
            _add_raw(a, b, EType.PATIENT_NAME, "patient", 0.85, validate_name=False)

    # 14. JSON-style name fields in text
    for m in RE_JSON_NAME_FIELD.finditer(text):
        key = m.group(1)
        if _JSON_NONPERSON_KEY.search(key):
            continue
        a, b = _trim_name_span(text, m.start(2), m.end(2))
        if b > a:
            et = EType.RELATIVE_NAME if _JSON_RELATIVE_KEY.search(key) else EType.PATIENT_NAME
            _add_raw(a, b, et, "relative" if et == EType.RELATIVE_NAME else "patient", 0.88, validate_name=True)

    # 12. Ages
    for rx in (RE_AGE_LABEL, RE_AGE_SEX):
        for m in rx.finditer(text):
            _add_raw(m.start(1), m.end(1), EType.AGE, "patient", 0.9, validate_name=False)

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
        try:
            gaz_hits = gaz.find(text, channel=channel)
        except TypeError:
            gaz_hits = gaz.find(text)
        for g_start, g_end, g_role, g_canon in gaz_hits:
            if not is_protected(text, g_start, g_end):
                span_str = text[g_start:g_end]
                if g_canon == "__MRN__":
                    etype = EType.MRN
                elif g_role == "relative":
                    etype = EType.RELATIVE_NAME
                else:
                    etype = EType.PATIENT_NAME
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
    # Strong, format-validated identifiers (phone, Aadhaar, ABHA, PAN, MRN, e-mail, ...)
    # are never "doctors", "doses" or "complaints": the clinical guards are about
    # words, so they must not suppress a regex-validated identifier just because a
    # doctor title or a clinical keyword happens to sit next to it.
    filtered_mentions: list[Mention] = [
        m for m in all_mentions
        if (m.source == "regex" and m.etype in STRONG_ID_TYPES)
        or not is_protected(text, m.start, m.end)
    ]

    # 5. Resolve overlaps (longest span wins; tie broken by priority)
    return resolve_overlaps(filtered_mentions)
