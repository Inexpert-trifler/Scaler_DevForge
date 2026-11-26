"""Detection module initialization and public exports."""
from __future__ import annotations

from wardguard.detect.normalize import normalize_for_match, normalize_with_map
from wardguard.detect.patterns import find_identifiers
from wardguard.detect.columns import classify_column
from wardguard.detect.guards import is_protected
from wardguard.detect.context import detect_text
from wardguard.detect.translit import deva_to_latin, canonical_name
from wardguard.detect.names import Gazetteer, build_gazetteer
from wardguard.detect.evidence import extract_unit_evidence
from wardguard.detect.file import detect_file

__all__ = [
    "normalize_for_match",
    "normalize_with_map",
    "find_identifiers",
    "classify_column",
    "is_protected",
    "detect_text",
    "deva_to_latin",
    "canonical_name",
    "Gazetteer",
    "build_gazetteer",
    "extract_unit_evidence",
    "detect_file",
]
