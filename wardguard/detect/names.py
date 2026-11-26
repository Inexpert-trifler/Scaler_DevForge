"""Dynamic multilingual gazetteer and fast entity lookup.

Implements TR-DET-5:
- Harvests names from slots classified as PATIENT_NAME / RELATIVE_NAME (and context-rule hits)
- Generates cross-script variants (Latin, Devanagari, transliterated variants, initials, surname-first)
- Fast word-boundary search in text in both scripts using indexed token dictionaries
"""
from __future__ import annotations
import re
from typing import Optional
from wardguard.model import ParsedFile, Role, EType
from wardguard.detect.normalize import normalize_for_match
from wardguard.detect.translit import (
    deva_to_latin,
    simplify_latin_phonetics,
    canonical_name,
    load_translit_variants,
    RE_DEVA,
)


class Gazetteer:
    """Dynamic gazetteer storing harvested names and their cross-script variants."""

    def __init__(self):
        # Maps surface phrase -> (Role, canonical_key)
        self._entries: dict[str, tuple[Role, str]] = {}
        self._compiled_regexes: list[tuple[re.Pattern, Role, str]] = []
        self._dirty = True

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
        if not name_clean or len(name_clean) < 3:
            return

        canon = canonical_name(name_clean)
        for var in self.variants(name_clean):
            existing = self._entries.get(var.lower())
            if not existing or (existing[0] != "patient" and role == "patient"):
                self._entries[var.lower()] = (role, canon)
        self._dirty = True

    def _compile(self) -> None:
        """Compile stored variants into regexes sorted by length descending."""
        if not self._dirty:
            return

        # Sort entries longest first
        sorted_items = sorted(
            self._entries.items(),
            key=lambda x: (len(x[0].split()), len(x[0])),
            reverse=True
        )

        patterns: list[tuple[re.Pattern, Role, str]] = []
        for phrase, (role, canon) in sorted_items:
            escaped = re.escape(phrase)
            # Boundary check handling both ASCII word boundary and Unicode punctuation
            pattern = re.compile(
                r'(?i)(?:^|(?<=[\s,;:(।\'"/\-])|(?<=\b))(' + escaped + r')(?:$|(?=[\s,;:)।\'"/\-])|(?=\b))'
            )
            patterns.append((pattern, role, canon))

        self._compiled_regexes = patterns
        self._dirty = False

    def find(self, text: str) -> list[tuple[int, int, Role, str]]:
        """Find gazetteer name occurrences in text with word boundaries.
        
        Returns sorted list of (start_offset, end_offset, role, canonical_key).
        """
        if not text or not self._entries:
            return []

        self._compile()
        hits: list[tuple[int, int, Role, str]] = []
        norm_text = normalize_for_match(text)

        for pat, role, canon in self._compiled_regexes:
            for m in pat.finditer(norm_text):
                start, end = m.start(1), m.end(1)
                hits.append((start, end, role, canon))

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
    """Harvest patient and relative names from structured columns across files."""
    gaz = Gazetteer()
    if not files:
        return gaz

    for pf in files:
        for unit in pf.units:
            for slot in unit.slots:
                if slot.column_type in (EType.PATIENT_NAME, EType.RELATIVE_NAME):
                    val = slot.text.strip()
                    if val:
                        role: Role = "relative" if slot.column_type == EType.RELATIVE_NAME else "patient"
                        gaz.add(val, role=role)

    return gaz
