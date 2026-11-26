"""Linkage package stubs (Saransh's domain)."""
from typing import List
from wardguard.model import Unit


def resolve(units: List[Unit], policy: dict) -> None:
    """Stub: resolve identity clusters."""
    pass


def canonical_name(name: str) -> str:
    """Stub: canonical name normalization."""
    return name.strip().lower()


def phonetic_key(name: str) -> str:
    """Stub: phonetic key."""
    return name.strip().lower()
