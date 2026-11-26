"""Unit tests for context rules and detect_text (Task S-05).

Tests:
- Name detection after labels (Name: Rahul Sharma, नाम: सुनीता पटेल)
- Name detection after relations (S/O Shyam Patel -> RELATIVE_NAME)
- Honorifics (Shahid sahab, Asha ji, श्रीमती रेखा)
- Demographic patterns (Sunita Patel 48 Y / F, Ramesh Kumar 52/M)
- Attendant / Visitor / Called-by patterns (canary equivalents)
- Full detect_text integration with overlap resolution and guards
"""
from __future__ import annotations
import pytest
from wardguard.model import EType
from wardguard.detect.context import detect_text, find_context_mentions


def test_name_after_label():
    """Test names after explicit label tokens in English and Hindi."""
    text1 = "Patient Name: Rahul Sharma, admitted yesterday."
    mentions1 = detect_text(text1)
    name_m1 = [m for m in mentions1 if m.etype == EType.PATIENT_NAME]
    assert len(name_m1) >= 1
    assert "Rahul Sharma" in name_m1[0].text

    text2 = "रोगी: सुनीता पटेल को सिरदर्द की शिकायत है।"
    mentions2 = detect_text(text2)
    name_m2 = [m for m in mentions2 if m.etype == EType.PATIENT_NAME]
    assert len(name_m2) >= 1
    assert "सुनीता पटेल" in name_m2[0].text


def test_relation_name():
    """Test relations (S/o, W/o, etc.) mapped to RELATIVE_NAME."""
    text1 = "Patient Meera, W/o Rajan Mishra, age 34"
    mentions1 = detect_text(text1)
    rel_m1 = [m for m in mentions1 if m.etype == EType.RELATIVE_NAME]
    assert len(rel_m1) >= 1
    assert "Rajan Mishra" in rel_m1[0].text

    text2 = "अभिभावक: रमेश चंद्रा"
    mentions2 = detect_text(text2)
    rel_m2 = [m for m in mentions2 if m.etype == EType.RELATIVE_NAME]
    assert len(rel_m2) >= 1
    assert "रमेश चंद्रा" in rel_m2[0].text


def test_honorifics_before_and_after():
    """Test honorific prefix and suffix."""
    text1 = "Contact Shahid sahab regarding report."
    mentions1 = detect_text(text1)
    assert any("Shahid" in m.text for m in mentions1)

    text2 = "Meeting with Smt. Anita Devi tomorrow."
    mentions2 = detect_text(text2)
    assert any("Anita Devi" in m.text for m in mentions2)

    text3 = "आशा जी ने दवा दी।"
    mentions3 = detect_text(text3)
    assert any("आशा" in m.text for m in mentions3)


def test_demographic_pattern():
    """Test <Name> 48 Y / F and <Name> 52/M."""
    text = "Initial assessment: Sunita Patel 48 Y / F conscious, oriented."
    mentions = detect_text(text)
    names = [m for m in mentions if m.etype == EType.PATIENT_NAME]
    assert len(names) >= 1
    assert "Sunita Patel" in names[0].text


def test_visitor_attendant_called_by():
    """Test attendant and called-by context (canary patterns)."""
    # Visitor log pattern
    text_vis = "18:40 - Zorawar Qadri (attendant, bed 12), mob 9876543210"
    m_vis = detect_text(text_vis)
    assert any("Zorawar Qadri" in m.text for m in m_vis)
    assert any(m.etype == EType.PHONE for m in m_vis)

    # Ambulance log pattern
    text_amb = "AMB-436, Sitapur, Lucknow, called by Kaveri Nambiar 94054-71434"
    m_amb = detect_text(text_amb)
    assert any("Kaveri Nambiar" in m.text for m in m_amb)
    assert any(m.etype == EType.PHONE for m in m_amb)

    # Helpdesk raised by pattern
    text_hd = 'raised by: Ilavenil Bhattacharya, contact 9876543210'
    m_hd = detect_text(text_hd)
    assert any("Ilavenil Bhattacharya" in m.text for m in m_hd)


def test_meaning_traps_in_detect_text():
    """Test that medical eponyms and doctors are not falsely detected as patient PII."""
    text = "Consultant Dr. Ramesh prescribed Dolo 650mg TDS for Parkinson's disease."
    mentions = detect_text(text)
    # Neither Dr. Ramesh nor Parkinson's nor 650mg TDS should be returned as PII
    assert not any("Ramesh" in m.text for m in mentions)
    assert not any("Parkinson" in m.text for m in mentions)
    assert not any("650" in m.text for m in mentions)
