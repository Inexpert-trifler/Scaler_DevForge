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
    canon = canonical_name(name)
    if not canon:
        return ""
    # Metaphone on tokens
    tokens = canon.split()
    meta_tokens = [jellyfish.metaphone(t) for t in tokens if t]
    return "_".join(meta_tokens)
