"""Dynamic multilingual gazetteer and fast entity lookup.

Implements TR-DET-5:
- Harvests names from slots classified as PATIENT_NAME / RELATIVE_NAME (and context-rule hits)
- Generates cross-script variants (Latin, Devanagari, transliterated variants, initials, surname-first)
- Fast word-boundary search in text in both scripts using indexed token dictionaries
"""
from __future__ import annotations
from collections import defaultdict
import re
from typing import Optional, Sequence
from wardguard.model import Channel, ParsedFile, Role, EType
from wardguard.detect.normalize import normalize_for_match, normalize_with_map, map_span_back
from wardguard.detect.translit import (
    deva_to_latin,
    simplify_latin_phonetics,
    canonical_name,
    load_translit_variants,
    RE_DEVA,
)


_HIDDEN_CHANNELS = {"filename", "header", "key", "metadata"}
_GIVEN_STOPWORDS = {
    "name", "naam", "patient", "report", "summary", "discharge", "notes", "nursing",
    "export", "visits", "patients", "record", "records", "hospital", "clinic", "data",
    "source", "path", "meta", "system", "hardoi", "lucknow", "sitapur", "barabanki",
    "sultanpur", "bahraich", "devgarh", "india", "uttar", "pradesh", "devi", "kumari",
    "sharma", "patel", "verma", "singh", "yadav", "gupta", "mishra", "pandey", "tiwari",
}


_ALNUM_RE = re.compile(r'[A-Za-z0-9\u0900-\u097f]+')
_DIGIT_RUN_RE = re.compile(r'\d+')
_RB = r'(?![A-Za-z0-9\u0900-\u097f])'


class Gazetteer:
    """Dynamic gazetteer storing harvested names, hidden-channel given names, and MRN digit cores."""

    def __init__(self):
        # Maps surface phrase -> (Role, canonical_key)
        self._entries: dict[str, tuple[Role, str]] = {}
        self._given_names: dict[str, tuple[Role, str]] = {}
        self._mrn_cores: set[str] = set()
        # O(N) hash-indexed entry structures (entry tuples: [phrase, compiled_pat_or_None, role, canon])
        self._single_entries: dict[str, list[list]] = defaultdict(list)
        self._pair_entries: dict[tuple[str, str], list[list]] = defaultdict(list)
        self._fallback_regexes: list[tuple[re.Pattern, Role, str]] = []
        self._dirty = True

    @property
    def is_empty(self) -> bool:
        return not self._entries and not self._given_names and not self._mrn_cores

    def variants(self, name: str) -> set[str]:
        """Generate spelling, script, and ordering variants of a name."""
        name_clean = normalize_for_match(name.strip())
        if not name_clean:
            return set()

        vars_set: set[str] = {name_clean, name_clean.title()}
        canon = canonical_name(name_clean)
        if canon:
            vars_set.add(canon)
            vars_set.add(canon.title())

        # If Devanagari, add natural Latin transliteration
        if RE_DEVA.search(name_clean):
            lat = deva_to_latin(name_clean)
            if lat:
                vars_set.add(lat)
                vars_set.add(lat.title())

        # Token-level variant expansion
        var_map = load_translit_variants()
        tokens = name_clean.split()

        # Check translit variant expansion for individual tokens
        for t in tokens:
            t_clean = t.lower().replace('.', '')
            if t_clean in var_map:
                for v in var_map[t_clean]:
                    # Replace token in the full name with variant
                    vars_set.add(name_clean.lower().replace(t.lower(), v))
                    vars_set.add(name_clean.lower().replace(t.lower(), v).title())

        # If 2 tokens (Given Surname): add Initials and Inverted (Surname Given)
        if len(tokens) == 2:
            g, s = tokens[0], tokens[1]
            vars_set.add(f"{s} {g}")
            vars_set.add(f"{s.title()} {g.title()}")
            if g:
                vars_set.add(f"{g[0]}. {s}")
                vars_set.add(f"{g[0]} {s}")

        return {v.strip() for v in vars_set if len(v.strip()) >= 3}

    def add(self, name: str, role: Role = "patient") -> None:
        """Add a name and its expanded variants to the gazetteer."""
        name_clean = normalize_for_match(name.strip())
        if not name_clean or len(name_clean) < 3 or len(name_clean) > 80:
            return
        if any(c in name_clean for c in '{}[]":;\n\r\t'):
            return

        canon = canonical_name(name_clean)
        for var in self.variants(name_clean):
            existing = self._entries.get(var.lower())
            if not existing or (existing[0] != "patient" and role == "patient"):
                self._entries[var.lower()] = (role, canon)

        # Also index first/given token for hidden channels (@header, @key, metadata)
        # when derived from a multi-token patient name
        toks = name_clean.split()
        if len(toks) >= 2 and role == "patient":
            for tok in toks[:1]:
                tl = tok.lower().strip(".")
                if len(tl) >= 4 and tl not in _GIVEN_STOPWORDS:
                    self._given_names.setdefault(tl, (role, canon))
            canon_toks = canon.split() if canon else []
            if len(canon_toks) >= 2:
                gt = canon_toks[0]
                if len(gt) >= 4 and gt not in _GIVEN_STOPWORDS:
                    self._given_names.setdefault(gt, (role, canon))

        self._dirty = True

    def add_mrn(self, mrn_val: str) -> None:
        """Register numeric/alphanumeric MRN suffix (5-8 digits) for path/metadata matching."""
        if not mrn_val:
            return
        # Extract trailing digit block >= 5 digits (e.g., '010565' from 'UHID-010565', '0077058' from 'JJH-0077058')
        m = re.search(r'(\d{5,8})$', mrn_val.strip())
        if m:
            self._mrn_cores.add(m.group(1))
            self._dirty = True

    @staticmethod
    def _compile_entry_pat(phrase: str) -> re.Pattern:
        parts = phrase.split()
        if len(parts) > 1:
            body = r'[\s_]+'.join(re.escape(p) for p in parts)
        else:
            body = re.escape(phrase)
        return re.compile(r'(?i)' + body + _RB)

    def _compile(self) -> None:
        """Index stored variants into O(1) first-token / token-pair buckets for fast lookup."""
        if not self._dirty:
            return

        self._single_entries.clear()
        self._pair_entries.clear()
        self._fallback_regexes.clear()

        sorted_items = sorted(
            self._entries.items(),
            key=lambda x: (len(x[0].split()), len(x[0])),
            reverse=True,
        )
        for phrase, (role, canon) in sorted_items:
            toks = _ALNUM_RE.findall(phrase)
            if not toks or not _ALNUM_RE.match(phrase):
                lb = r'(?<![A-Za-z0-9\u0900-\u097f])'
                parts = phrase.split()
                body = r'[\s_]+'.join(re.escape(p) for p in parts) if len(parts) > 1 else re.escape(phrase)
                self._fallback_regexes.append((re.compile(r'(?i)' + lb + r'(' + body + r')' + _RB), role, canon))
            elif len(toks) == 1:
                self._single_entries[toks[0]].append([phrase, None, role, canon])
            else:
                self._pair_entries[(toks[0], toks[1])].append([phrase, None, role, canon])

        self._dirty = False

    def find(
        self,
        text: str,
        channel: Channel = "content",
        _pre_norm: Optional[tuple[str, Sequence[int]]] = None,
    ) -> list[tuple[int, int, Role, str]]:
        """Find gazetteer name occurrences in text with word/underscore boundaries.
        
        Uses normalize_with_map to guarantee exact offsets into original text.
        In hidden channels (filename, header, key, metadata), also matches harvested
        given names and numeric MRN cores.
        """
        if not text or self.is_empty:
            return []

        self._compile()
        hits: list[tuple[int, int, Role, str]] = []
        if _pre_norm is not None:
            norm_text, index_map = _pre_norm
        else:
            norm_text, index_map = normalize_with_map(text)
        orig_len = len(text)

        is_hidden = channel in _HIDDEN_CHANNELS
        single_entries = self._single_entries
        pair_entries = self._pair_entries
        given_names = self._given_names

        # Fast lowercase scan preserving character indices
        norm_lower = norm_text.lower()
        same_len = len(norm_lower) == len(norm_text)
        scan_str = norm_lower if same_len else norm_text

        prev_tok = ""
        prev_start = 0

        if single_entries or pair_entries or (is_hidden and given_names):
            for m in _ALNUM_RE.finditer(scan_str):
                cur_start = m.start()
                cur_end = m.end()
                cur_tok = m.group(0) if same_len else m.group(0).lower()

                if pair_entries and prev_tok:
                    bucket = pair_entries.get((prev_tok, cur_tok))
                    if bucket:
                        for entry in bucket:
                            pat = entry[1]
                            if pat is None:
                                pat = self._compile_entry_pat(entry[0])
                                entry[1] = pat
                            pm = pat.match(norm_text, prev_start)
                            if pm:
                                start, end = map_span_back(prev_start, pm.end(), index_map, orig_len)
                                if end > start:
                                    hits.append((start, end, entry[2], entry[3]))

                if single_entries:
                    sbucket = single_entries.get(cur_tok)
                    if sbucket:
                        for entry in sbucket:
                            phrase = entry[0]
                            if len(phrase) == len(cur_tok):
                                start, end = map_span_back(cur_start, cur_end, index_map, orig_len)
                                if end > start:
                                    hits.append((start, end, entry[2], entry[3]))
                            else:
                                pat = entry[1]
                                if pat is None:
                                    pat = self._compile_entry_pat(phrase)
                                    entry[1] = pat
                                pm = pat.match(norm_text, cur_start)
                                if pm:
                                    start, end = map_span_back(cur_start, pm.end(), index_map, orig_len)
                                    if end > start:
                                        hits.append((start, end, entry[2], entry[3]))

                if is_hidden and given_names:
                    g_info = given_names.get(cur_tok)
                    if g_info is not None:
                        start, end = map_span_back(cur_start, cur_end, index_map, orig_len)
                        if end > start:
                            hits.append((start, end, g_info[0], g_info[1]))

                prev_tok = cur_tok
                prev_start = cur_start

        for pat, role, canon in self._fallback_regexes:
            for m in pat.finditer(norm_text):
                start, end = map_span_back(m.start(1), m.end(1), index_map, orig_len)
                if end > start:
                    hits.append((start, end, role, canon))

        if is_hidden and self._mrn_cores:
            mrn_cores = self._mrn_cores
            for dm in _DIGIT_RUN_RE.finditer(norm_text):
                d_str = dm.group(0)
                if d_str in mrn_cores:
                    start, end = map_span_back(dm.start(), dm.end(), index_map, orig_len)
                    if end > start:
                        hits.append((start, end, "patient", "__MRN__"))

        if not hits:
            return []

        # Deduplicate and resolve overlapping spans (longest span wins)
        hits.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        resolved: list[tuple[int, int, Role, str]] = []
        last_end = -1
        for start, end, role, canon in hits:
            if start >= last_end:
                resolved.append((start, end, role, canon))
                last_end = end

        return resolved


def build_gazetteer(files: list[ParsedFile], policy: Optional[dict] = None) -> Gazetteer:
    """Harvest patient/relative names and MRN cores across structured columns, context hits, and units."""
    gaz = Gazetteer()
    if not files:
        return gaz

    for pf in files:
        for unit in pf.units:
            # Group composite name parts (e.g. name/first + name/last) in JSON/FHIR units
            first_part = ""
            last_part = ""
            for slot in unit.slots:
                val = slot.text.strip()
                if not val:
                    continue
                if slot.column_type in (EType.PATIENT_NAME, EType.RELATIVE_NAME):
                    role: Role = "relative" if slot.column_type == EType.RELATIVE_NAME else "patient"
                    lp = slot.path.lower()
                    if lp.endswith("/first") or lp.endswith("/given/0"):
                        first_part = val
                    elif lp.endswith("/last") or lp.endswith("/family"):
                        last_part = val
                    if len(val.split()) >= 2 or role == "patient":
                        gaz.add(val, role=role)
                elif slot.column_type == EType.MRN:
                    gaz.add_mrn(val)

                # Also harvest high-confidence context/regex mentions found in pass 1a
                for m in slot.mentions:
                    # Only confident rules feed the dataset-wide gazetteer: a weak guess (initials,
                    # aliases) must not spread to every other file.
                    if (m.etype in (EType.PATIENT_NAME, EType.RELATIVE_NAME) and m.source in ("context", "column")
                            and (m.confidence or 0) >= 0.85):
                        role_m: Role = "relative" if m.etype == EType.RELATIVE_NAME else "patient"
                        if len(m.text.split()) >= 2:
                            gaz.add(m.text, role=role_m)
                    elif m.etype == EType.MRN:
                        gaz.add_mrn(m.text)

            if first_part and last_part:
                gaz.add(f"{first_part} {last_part}", role="patient")

    return gaz
