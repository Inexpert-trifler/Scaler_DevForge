"""Detection module initialization and public exports."""
from __future__ import annotations

from typing import List
from wardguard.model import ParsedFile
from wardguard.detect.normalize import normalize_for_match, normalize_with_map
from wardguard.detect.patterns import find_identifiers
from wardguard.detect.columns import classify_column
from wardguard.detect.guards import is_protected
from wardguard.detect.context import detect_text
from wardguard.detect.translit import deva_to_latin, canonical_name
from wardguard.detect.names import Gazetteer, build_gazetteer


def detect_file(pf: ParsedFile, gaz: Gazetteer, policy: dict) -> None:
    """Detection pass for a parsed file using Saransh's detection components."""
    # Detect in unit slots
    for unit in pf.units:
        for slot in unit.slots:
            mentions = detect_text(slot.text, slot.channel, gaz, policy)
            if mentions:
                slot.mentions.extend(mentions)
                unit.patient_bearing = True

    # Detect in file slots (headers, filename, etc.)
    for slot in pf.file_slots:
        mentions = detect_text(slot.text, slot.channel, gaz, policy)
        if mentions:
            slot.mentions.extend(mentions)


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
    "detect_file",
]
