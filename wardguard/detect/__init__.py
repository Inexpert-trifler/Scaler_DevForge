"""Detection module initialization and public exports."""
from __future__ import annotations

from wardguard.detect.normalize import normalize_for_match, normalize_with_map
from wardguard.detect.patterns import find_identifiers
from wardguard.detect.columns import classify_column
from wardguard.detect.guards import is_protected
from wardguard.detect.context import detect_text

__all__ = [
    "normalize_for_match",
    "normalize_with_map",
    "find_identifiers",
    "classify_column",
    "is_protected",
    "detect_text",
]
