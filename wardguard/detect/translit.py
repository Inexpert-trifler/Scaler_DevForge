"""Cross-script transliteration and phonetic / canonical name normalization.

Implements TR-DET-5, TR-LNK-2:
- Devanagari to Latin transliteration using indic_transliteration sanscript:
  (drops final inherent schwa, standardizes vowels/consonants)
- Latin to Devanagari mapping
- Shared canonical_name(name: str) -> str:
  Standardized phonetic token key for cross-script linkage and matching.
"""
from __future__ import annotations
import os
import re
from functools import lru_cache
from indic_transliteration import sanscript

# Regex for Devanagari character detection
RE_DEVA = re.compile(r'[\u0900-\u097f]')


@lru_cache(maxsize=1)
def load_translit_variants() -> dict[str, str]:
    """Load canonical to variant token mappings from resources/translit_variants.tsv."""
    res_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "resources",
        "translit_variants.tsv"
    )
    var_map: dict[str, str] = {}
    if not os.path.exists(res_path):
        return var_map

    with open(res_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip().lower() for p in line.split("\t") if p.strip()]
            if parts:
                canon_tok = parts[0]
                for p in parts:
                    clean_p = p.replace('.', '')
                    var_map[clean_p] = canon_tok
                    var_map[p] = canon_tok
    return var_map


def deva_to_latin(text: str) -> str:
    """Transliterate Devanagari text to natural Latin representation."""
    if not text:
        return ""
    if not RE_DEVA.search(text):
        return text

    try:
        latin = sanscript.transliterate(text, sanscript.DEVANAGARI, sanscript.ITRANS)
    except Exception:
        latin = text

    return simplify_latin_phonetics(latin)


def simplify_latin_phonetics(text: str) -> str:
    """Normalize and simplify Latin phonetic ambiguities.
    
    Rules:
    - aa/A -> a, ee/I -> i, oo/U -> u
    - w -> v, ph -> f
    - Hindi inherent schwa deletion at end of words: ramesha -> ramesh, patela -> patel
    """
    if not text:
        return ""
    s = text.strip()
    # Normalize capitals from ITRANS
    s = s.replace("A", "aa").replace("I", "ee").replace("U", "oo")
    s = s.replace("T", "t").replace("D", "d").replace("N", "n").replace("R", "r")
    s = s.lower()
    s = re.sub(r'[\^~`_]', '', s)
    s = s.replace("aa", "a").replace("ee", "i").replace("oo", "u")
    s = s.replace("w", "v").replace("ph", "f")

    # Schwa deletion: if word ends with consonant + 'a' and length > 3
    # e.g., 'ramesha' -> 'ramesh', 'patela' -> 'patel'
    # But preserve long 'aa' / 'A' endings like 'sharma', 'varma', 'gupta', 'mishra', 'shukla'
    tokens = s.split()
    simplified: list[str] = []
    for tok in tokens:
        # Check if the Devanagari original had 'aa' / 'A' (which we mapped to 'aa' -> 'a')
        # Only drop 'a' if it's the inherent short schwa after a consonant, not after 'rm', 'pt', 'sh', 'kl', etc.
        if len(tok) > 4 and tok.endswith('a') and not any(tok.endswith(end) for end in ['ita', 'rma', 'pta', 'shra', 'kla', 'dha']):
            tok = tok[:-1]
        simplified.append(tok)

    return " ".join(simplified)


def canonical_name(name: str) -> str:
    """Produce standardized Latin canonical name key for linkage and matching."""
    if not name:
        return ""

    lat = deva_to_latin(name)
    lat = re.sub(r'[^a-zA-Z\s]', ' ', lat).lower()
    tokens = [t.strip() for t in lat.split() if t.strip()]

    var_map = load_translit_variants()
    norm_tokens = []
    for t in tokens:
        clean_t = t.replace('.', '')
        if clean_t in var_map:
            norm_tokens.append(var_map[clean_t])
        else:
            norm_tokens.append(simplify_latin_phonetics(clean_t))

    return " ".join(norm_tokens)
