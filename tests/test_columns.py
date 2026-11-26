"""Unit tests for column classifier (Task S-03).

Tests:
- Renamed and obfuscated headers (Contact#, pt_nm, Pt. Name)
- Hindi headers (रोगी का नाम, दूरभाष, पता, उम्र)
- Relative columns (Guardian Name, S/O SHYAM PATEL, Father's Name)
- Unlabeled / blank headers profiled by values
- Header vs value disagreement arbitration
"""
from __future__ import annotations
import pytest
from wardguard.model import EType
from wardguard.detect.columns import classify_column, profile_values


def test_classify_standard_headers():
    """Test standard English and transliterated headers."""
    assert classify_column("Patient Name", ["Rahul Sharma", "Sunita Patel", "Mohd Arif"]) == EType.PATIENT_NAME
    assert classify_column("pt_nm", ["Amit Verma", "Deepak Gupta", "Ramesh Kumar"]) == EType.PATIENT_NAME
    assert classify_column("Contact#", ["9876543210", "9123456780", "9845123456"]) == EType.PHONE
    assert classify_column("Mobile No.", ["9876543210", "8765432109"]) == EType.PHONE
    assert classify_column("Age (Yrs)", ["48", "32", "54"]) == EType.AGE
    assert classify_column("Date of Birth", ["12/04/1977", "20/08/1985"]) == EType.DOB
    assert classify_column("Pincode", ["229073", "208016", "226001"]) == EType.PIN


def test_classify_hindi_headers():
    """Test Devanagari headers."""
    assert classify_column("रोगी का नाम", ["सुनीता पटेल", "अमित शर्मा", "महेश यादव"]) == EType.PATIENT_NAME
    assert classify_column("मरीज़ का नाम", ["मोहित कुमार", "दिनेश सिंह"]) == EType.PATIENT_NAME
    assert classify_column("दूरभाष", ["९८७६५४३२१०", "९१२३४५६७८०"]) == EType.PHONE
    assert classify_column("आयु", ["45", "54 वर्ष", "32"]) == EType.AGE
    assert classify_column("लिंग", ["M", "F", "Male", "महिला"]) == EType.GENDER


def test_classify_relative_columns():
    """Test relative and guardian column detection."""
    assert classify_column("Guardian Name", ["Shyam Patel", "Naresh Chauhan"]) == EType.RELATIVE_NAME
    assert classify_column("Father's Name", ["Babu Ram", "Harish Verma"]) == EType.RELATIVE_NAME
    assert classify_column("S/O", ["Ram Prakash", "Rajan Mishra"]) == EType.RELATIVE_NAME
    assert classify_column("अभिभावक", ["सुरेश चंद्रा", "कमल किशोर"]) == EType.RELATIVE_NAME


def test_unlabeled_column_value_profiling():
    """Test unlabeled/blank columns profiled purely from values."""
    # Phones
    phones = ["9876543210", "9845123456", "9123456789", "invalid", ""]
    assert classify_column("", phones) == EType.PHONE

    # PAN
    pans = ["ABCDE1234F", "XYZPK9876L", "PQRST5432M", ""]
    assert classify_column("col_3", pans) == EType.PAN

    # MRN
    mrns = ["SNJ/26/064127", "UHID-987654", "IP-24-9081", ""]
    assert classify_column("", mrns) == EType.MRN

    # Names without header
    names = ["Rohan Saxena", "Kavita Tiwari", "Pooja Banerjee", "Saurabh Joshi"]
    assert classify_column("field_x", names) == EType.PATIENT_NAME


def test_header_value_disagreement_arbitration():
    """Test conflict rules: trust strong IDs over header, trust header for names."""
    # Obfuscated header with clear Phone values -> trust values
    assert classify_column("Code_X", ["9876543210", "9812345678", "9988776655"]) == EType.PHONE

    # Header says Name, values are name-like -> PATIENT_NAME
    assert classify_column("Patient Name", ["Ashok Kumar", "Vijay Singh"]) == EType.PATIENT_NAME

    # Header says Relative Name, values are name-like -> RELATIVE_NAME
    assert classify_column("Relative", ["Ram Prasad", "Sita Devi"]) == EType.RELATIVE_NAME
