"""Unit tests for translit.py and names.py / Gazetteer (Task S-06).

Tests:
- Devanagari to Latin transliteration and phonetic simplification
- Canonical name generation for linkage and cross-script alignment
- Gazetteer harvesting, variant generation (initials, spelling variants, script variants)
- Fast word-boundary search in text across English, Devanagari, and Hinglish
"""
from __future__ import annotations
import pytest
from wardguard.model import ParsedFile, Unit, Slot, EType
from wardguard.detect.translit import (
    deva_to_latin,
    simplify_latin_phonetics,
    canonical_name,
)
from wardguard.detect.names import Gazetteer, build_gazetteer


def test_deva_to_latin():
    """Test Devanagari to Latin transliteration with Hindi schwa deletion."""
    assert "ramesh" in deva_to_latin("रमेश")
    assert "patel" in deva_to_latin("पटेल")
    assert "sunita" in deva_to_latin("सुनीता")
    assert "sharma" in deva_to_latin("शर्मा")


def test_canonical_name():
    """Test canonical name normalization."""
    # Transliteration variants unified
    assert canonical_name("Mohd. Arif") == canonical_name("Mohammad Arif")
    assert canonical_name("सुनीता पटेल") == canonical_name("Sunita Patel")
    assert "dinesh" in canonical_name("Dinesh Kumar Singh") or "dines" in canonical_name("Dinesh Kumar Singh")


def test_gazetteer_variants_generation():
    """Test variant generation for names."""
    gaz = Gazetteer()
    vars_sunita = gaz.variants("Sunita Patel")
    assert "Sunita Patel" in vars_sunita
    # Inverted order
    assert "Patel Sunita" in vars_sunita
    # Initial
    assert "S. Patel" in vars_sunita

    # Spelling variant for Mohd
    vars_mohd = gaz.variants("Mohd Arif")
    assert any("mohammad" in v.lower() for v in vars_mohd)


def test_gazetteer_find_cross_script():
    """Test dynamic gazetteer matches across scripts."""
    gaz = Gazetteer()
    gaz.add("Ramesh Chauhan", role="patient")
    gaz.add("सुनीता पटेल", role="patient")

    # Match exact Latin
    text_lat = "Patient Ramesh Chauhan reported headache."
    hits_lat = gaz.find(text_lat)
    assert len(hits_lat) == 1
    assert "Ramesh Chauhan" in text_lat[hits_lat[0][0]:hits_lat[0][1]]

    # Match Devanagari
    text_deva = "ओपीडी में सुनीता पटेल उपस्थित हुईं।"
    hits_deva = gaz.find(text_deva)
    assert len(hits_deva) == 1
    assert "सुनीता पटेल" in text_deva[hits_deva[0][0]:hits_deva[0][1]]

    # Match cross-script: Devanagari name searched in Latin text
    text_cross = "Prescription written for Sunita Patel today."
    hits_cross = gaz.find(text_cross)
    assert len(hits_cross) == 1
    assert "Sunita Patel" in text_cross[hits_cross[0][0]:hits_cross[0][1]]


def test_build_gazetteer_from_files():
    """Test harvesting names from ParsedFiles."""
    slot1 = Slot(path="col:Name", text="Kavita Saxena", channel="content", column_type=EType.PATIENT_NAME)
    slot2 = Slot(path="col:Guardian", text="Babu Ram", channel="content", column_type=EType.RELATIVE_NAME)
    unit = Unit(uid="file1#row:0", file_rel="file1.csv", loc="row:0", slots=[slot1, slot2])
    pf = ParsedFile(rel="file1.csv", sha256="abc", size=100, fmt="csv", units=[unit])

    gaz = build_gazetteer([pf])
    text = "Visit notes: Kavita Saxena accompanied by Babu Ram."
    hits = gaz.find(text)
    assert len(hits) == 2
    roles = {h[2] for h in hits}
    assert "patient" in roles
    assert "relative" in roles
