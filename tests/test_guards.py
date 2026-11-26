"""Unit tests for meaning-trap guards (Task S-04).

Tests every trap case specified in 09_AI_VIBE_CODING_RULES §D-22:
- "Dr. Ramesh" kept
- "Ramesh" without doctor context NOT protected
- "C/O fever" kept
- "C/O Ramesh Kumar" -> Ramesh Kumar NOT protected (person name, not disease)
- "K/C/O addison's disease" kept
- "Dolo 650 BD x 5 days" kept
- "1-0-1" kept
- "650mg" kept
- "BP 150/90" kept
- "Parkinson's disease" kept
- Wards/beds (General Ward Bed 12) kept
- ASHA worker / ASHA didi kept
"""
from __future__ import annotations
import pytest
from wardguard.detect.guards import is_protected


def test_doctor_guards():
    """Test doctor names protected via prefix/suffix."""
    # Dr. Ramesh -> "Ramesh" span must be protected
    text1 = "Consulted with Dr. Ramesh for evaluation."
    start1 = text1.index("Ramesh")
    end1 = start1 + len("Ramesh")
    assert is_protected(text1, start1, end1) is True

    # Hindi doctor: डॉ. गुप्ता
    text2 = "रिपोर्ट डॉ. गुप्ता को दिखाएं।"
    start2 = text2.index("गुप्ता")
    end2 = start2 + len("गुप्ता")
    assert is_protected(text2, start2, end2) is True

    # Doctor with qualification suffix: Ramesh Kumar, MD
    text3 = "Signed by Ramesh Kumar (MD Medicine)"
    start3 = text3.index("Ramesh Kumar")
    end3 = start3 + len("Ramesh Kumar")
    assert is_protected(text3, start3, end3) is True

    # Standalone patient name -> NOT protected
    text_pt = "Patient Ramesh arrived at OPD."
    start_pt = text_pt.index("Ramesh")
    end_pt = start_pt + len("Ramesh")
    assert is_protected(text_pt, start_pt, end_pt) is False


def test_dose_and_frequency_guards():
    """Test dosage, frequencies, and durations protected."""
    assert is_protected("650mg", 0, 5) is True
    assert is_protected("1-0-1", 0, 5) is True
    assert is_protected("0-1-0", 0, 5) is True
    assert is_protected("BD", 0, 2) is True
    assert is_protected("TDS", 0, 3) is True
    assert is_protected("x 5 days", 0, 8) is True
    assert is_protected("x 2 wks", 0, 7) is True


def test_vitals_and_labs_guards():
    """Test BP, vitals, and lab values."""
    # BP 150/90
    text_bp = "Patient vitals: BP 150/90 mmHg recorded"
    start_bp = text_bp.index("150/90")
    end_bp = start_bp + len("150/90")
    assert is_protected(text_bp, start_bp, end_bp) is True

    # Pulse 72/min
    text_pr = "Vitals: Pulse 72/min"
    start_pr = text_pr.index("72")
    end_pr = start_pr + len("72")
    assert is_protected(text_pr, start_pr, end_pr) is True


def test_eponym_guards():
    """Test medical eponyms are preserved."""
    # Parkinson's disease
    text_park = "Diagnosed with Parkinson's disease"
    start_park = text_park.index("Parkinson's")
    end_park = start_park + len("Parkinson's")
    assert is_protected(text_park, start_park, end_park) is True

    # Bell's palsy
    text_bell = "Symptoms suggestive of Bell's palsy"
    start_bell = text_bell.index("Bell's")
    end_bell = start_bell + len("Bell's")
    assert is_protected(text_bell, start_bell, end_bell) is True

    # Addison's
    text_add = "History of addison's syndrome"
    start_add = text_add.index("addison's")
    end_add = start_add + len("addison's")
    assert is_protected(text_add, start_add, end_add) is True


def test_complaint_and_clinical_prefixes():
    """Test C/O complaint kept, but C/O Name not protected."""
    # C/O fever -> fever is protected
    text_fev = "Patient presents with C/O fever and body ache"
    start_fev = text_fev.index("fever")
    end_fev = start_fev + len("fever")
    assert is_protected(text_fev, start_fev, end_fev) is True

    # C/O Ramesh Kumar (care-of relative) -> Ramesh Kumar NOT protected
    text_care = "Address: C/O Ramesh Kumar, Village Durgamau"
    start_care = text_care.index("Ramesh Kumar")
    end_care = start_care + len("Ramesh Kumar")
    assert is_protected(text_care, start_care, end_care) is False


def test_ward_bed_and_asha_role():
    """Test wards, beds, and health worker roles."""
    assert is_protected("General Ward", 0, 12) is True
    assert is_protected("Bed 14", 0, 6) is True
    assert is_protected("ICU-2", 0, 5) is True

    # ASHA worker / didi as role
    assert is_protected("ASHA didi", 0, 9) is True
    assert is_protected("ASHA worker", 0, 11) is True
    assert is_protected("आशा दीदी", 0, 8) is True
