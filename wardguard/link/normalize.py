"""Normalization and phonetic keys for linkage blocking.

Implements TR-LNK-1, TR-LNK-5:
- canonical_name: shared standard Latin phonetic token string
- phonetic_key: Soundex / Metaphone style key for blocking
"""
from __future__ import annotations
import re
import jellyfish
from wardguard.detect.translit import canonical_name


def phonetic_key(name: str) -> str:
    """Generate phonetic soundex/metaphone key for blocking.
    
    Required contract: phonetic_key(name: str) -> str
    """
    canon = canonical_name(re.sub(r"['\u2019]", "", name))
    if not canon:
        return ""
    tokens = []
    for t in canon.split():
        # Aspiration and spelling noise that differs between scripts / clerks:
        # kh->k, th->t, bh->b ... ; a silent h before a consonant (Mehboob/Mahbub);
        # any leading vowel collapses to "a" (Anthony / Enthoni).
        t = re.sub(r'(?<=[bcdgjklmnprstv])h', '', t)
        t = re.sub(r'h(?=[bcdfgjklmnpqrstvwxyz])', '', t)
        t = re.sub(r'^[aeiou]+', 'a', t)
        if t:
            tokens.append(t)
    meta_tokens = [jellyfish.metaphone(t) for t in tokens if t]
    return "_".join(meta_tokens)
