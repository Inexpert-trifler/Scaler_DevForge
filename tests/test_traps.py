"""Comprehensive trap verification test suite (Task S-10).

Mandatory tests per 09_AI_VIBE_CODING_RULES.md §D-22:
- `Dr. Ramesh` kept
- relative `Ramesh` removed
- `C/O fever` kept
- `C/O Ramesh Kumar` removed
- `K/C/O addison's disease` kept
- `Dolo 650 BD x 5 days` kept
- `1-0-1` kept
- `650mg` kept
- `BP 150/90` kept
- `Parkinson's disease` kept
- `+91 72864 90658`, `072864-90658`, `९८७६५४३२१०` removed
- `नाम: सुनीता पटेल` removed
- `Shahid sahab ka BP` -> name removed, BP kept
"""
from __future__ import annotations
import pytest
from wardguard.model import EType
from wardguard.detect.guards import is_protected
from wardguard.detect.context import detect_text
from wardguard.detect.patterns import find_identifiers


def test_trap_dr_ramesh_vs_relative_ramesh():
    """Dr. Ramesh kept; relative Ramesh removed."""
    # 1. Doctor Ramesh -> kept (protected)
    doc_text = "Treatment advised by Dr. Ramesh in evening."
    doc_mentions = detect_text(doc_text)
    assert not any("Ramesh" in m.text for m in doc_mentions)
    start_r = doc_text.index("Ramesh")
    end_r = start_r + len("Ramesh")
    assert is_protected(doc_text, start_r, end_r) is True

    # 2. Relative Ramesh -> removed (detected as RELATIVE_NAME)
    rel_text = "Patient Meera, W/o Ramesh, admitted to Ward."
    rel_mentions = detect_text(rel_text)
    assert any("Ramesh" in m.text and m.etype == EType.RELATIVE_NAME for m in rel_mentions)


def test_trap_co_fever_vs_co_ramesh():
    """C/O fever kept; C/O Ramesh Kumar removed."""
    # 1. C/O fever -> kept
    fever_text = "Patient presented with C/O fever and vomiting."
    fever_mentions = detect_text(fever_text)
    assert not any("fever" in m.text for m in fever_mentions)
    start_f = fever_text.index("fever")
    end_f = start_f + len("fever")
    assert is_protected(fever_text, start_f, end_f) is True

    # 2. C/O Ramesh Kumar -> removed (RELATIVE_NAME)
    co_person = "Address: C/O Ramesh Kumar, Village Pipra"
    person_mentions = detect_text(co_person)
    assert any("Ramesh Kumar" in m.text and m.etype == EType.RELATIVE_NAME for m in person_mentions)


def test_trap_kco_addisons_and_parkinsons():
    """K/C/O addison's disease kept; Parkinson's disease kept."""
    text1 = "Past history: K/C/O addison's disease on hydrocortisone."
    m1 = detect_text(text1)
    assert not any("addison" in m.text.lower() for m in m1)

    text2 = "Clinical notes: Diagnosed with Parkinson's disease 3 years ago."
    m2 = detect_text(text2)
    assert not any("parkinson" in m.text.lower() for m in m2)


def test_trap_doses_and_regimens():
    """Dolo 650 BD x 5 days, 1-0-1, 650mg kept intact."""
    text = "Rx: Tab Dolo 650mg BD x 5 days, Pantocid 1-0-1 before meals."
    mentions = detect_text(text)
    # None of these clinical instructions should be flagged as phone, age, or name PII
    for term in ["650mg", "BD", "x 5 days", "1-0-1"]:
        assert not any(term in m.text for m in mentions), f"False positive on clinical term: {term}"


def test_trap_vitals_bp_150_90():
    """BP 150/90 kept intact."""
    text = "On examination: BP 150/90 mmHg, Pulse 76/min."
    mentions = detect_text(text)
    assert not any("150/90" in m.text for m in mentions)
    assert not any("76" in m.text for m in mentions)


def test_trap_phone_formats_removed():
    """+91 72864 90658, 072864-90658, ९८७६५४३२१० all removed."""
    # 1. +91 72864 90658
    t1 = "Primary contact: +91 72864 90658"
    m1 = find_identifiers(t1)
    assert any(m.etype == EType.PHONE for m in m1)

    # 2. 072864-90658
    t2 = "Alternate: 072864-90658"
    m2 = find_identifiers(t2)
    assert any(m.etype == EType.PHONE for m in m2)

    # 3. Devanagari digits: ९८७६५४३२१०
    t3 = "मोबाइल: ९८७६५४३२१०"
    m3 = find_identifiers(t3)
    assert any(m.etype == EType.PHONE for m in m3)


def test_trap_hindi_name_removed():
    """नाम: सुनीता पटेल removed."""
    text = "पंजीकरण विवरण - नाम: सुनीता पटेल, निवासी कानपुर।"
    mentions = detect_text(text)
    assert any("सुनीता पटेल" in m.text and m.etype == EType.PATIENT_NAME for m in mentions)


def test_trap_shahid_sahab_ka_bp():
    """Shahid sahab ka BP -> name removed, BP kept."""
    text = "आज शाहिद साहब का BP 140/90 रिकॉर्ड किया गया।"
    mentions = detect_text(text)
    # Name must be removed
    assert any("शाहिद" in m.text for m in mentions)
    # BP 140/90 must be kept intact (not in mentions)
    assert not any("140/90" in m.text for m in mentions)
