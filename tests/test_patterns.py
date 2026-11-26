"""Unit tests for normalize.py and patterns.py (Task S-02).

Includes positive matches, negative matches, and medical trap precision tests.
All test data is purely synthetic / invented.
"""
from __future__ import annotations
import pytest
from wardguard.model import EType
from wardguard.detect.normalize import normalize_for_match, normalize_with_map, map_span_back
from wardguard.detect.patterns import (
    validate_verhoeff,
    generate_verhoeff_check_digit,
    find_identifiers,
)


def test_verhoeff_checksum():
    """Test Verhoeff check digit generation and validation."""
    base = "98452136709"
    check = generate_verhoeff_check_digit(base)
    full_aadhaar = base + str(check)
    assert validate_verhoeff(full_aadhaar) is True
    # Mutate a digit -> must fail
    corrupt = base + str((check + 1) % 10)
    assert validate_verhoeff(corrupt) is False
    # Sequential / invalid numbers
    assert validate_verhoeff("123456789012") is False


def test_normalize_with_map():
    """Test NFKC normalization, zero-width stripping, and Devanagari digit folding."""
    # Devanagari digits: ९८७६५४३२१० -> 9876543210
    deva_text = "फ़ोन: ९८७६५४३२१०"
    norm, index_map = normalize_with_map(deva_text)
    assert "9876543210" in norm
    # Zero-width spaces embedded: "98\u200b76"
    zw_text = "98\u200b76543210"
    norm_zw, idx_map_zw = normalize_with_map(zw_text)
    assert norm_zw == "9876543210"
    # Mapping back
    start, end = map_span_back(0, len(norm_zw), idx_map_zw, len(zw_text))
    assert zw_text[start:end] == zw_text


def test_find_phone_positives_and_traps():
    """Test phone detection including Indian prefixes, formatting, and medical traps."""
    # Positives
    text_pos1 = "Contact patient at +91 98765 43210 immediately."
    mentions1 = find_identifiers(text_pos1)
    assert any(m.etype == EType.PHONE for m in mentions1)

    text_pos2 = "Mob: 098765-43210"
    mentions2 = find_identifiers(text_pos2)
    assert any(m.etype == EType.PHONE for m in mentions2)

    # Masked phone
    text_pos3 = "Registered phone 98XXXXXX10"
    mentions3 = find_identifiers(text_pos3)
    assert any(m.etype == EType.PHONE for m in mentions3)

    # Devanagari phone
    text_pos4 = "दूरभाष: ९८७६५४३२१०"
    mentions4 = find_identifiers(text_pos4)
    assert any(m.etype == EType.PHONE for m in mentions4)

    # Negative / Traps: doses, frequencies, ratios must NOT be flagged as phone
    traps = [
        "Dolo 650mg TDS",
        "Tab Paracetamol 1-0-1 x 5 days",
        "BP 150/90 mmHg",
        "Pulse 72/min regular",
        "Random blood sugar 140 mg/dL",
    ]
    for trap in traps:
        mentions = find_identifiers(trap)
        assert not any(m.etype == EType.PHONE for m in mentions), f"False positive on: {trap}"


def test_find_aadhaar_and_masked():
    """Test Aadhaar detection with Verhoeff and masked Aadhaar."""
    # Generate valid Aadhaar
    base = "45129834712"
    check = generate_verhoeff_check_digit(base)
    valid_aadhaar = f"{base[:4]} {base[4:8]} {base[8:]}{check}"

    text1 = f"Aadhaar card: {valid_aadhaar}"
    mentions1 = find_identifiers(text1)
    aadhaar_mentions = [m for m in mentions1 if m.etype == EType.AADHAAR]
    assert len(aadhaar_mentions) == 1

    # Invalid Aadhaar (first digit < 2 or invalid checksum)
    invalid_aadhaar = "1234 5678 9012"
    mentions_inv = find_identifiers(f"Card: {invalid_aadhaar}")
    assert not any(m.etype == EType.AADHAAR for m in mentions_inv)

    # Masked Aadhaar
    masked_text = "UID: XXXX-XXXX-4567 submitted"
    mentions_masked = find_identifiers(masked_text)
    assert any(m.etype == EType.AADHAAR_MASKED for m in mentions_masked)


def test_find_pan():
    """Test PAN detection."""
    text = "PAN number is ABCDE1234F verified."
    mentions = find_identifiers(text)
    pan_mentions = [m for m in mentions if m.etype == EType.PAN]
    assert len(pan_mentions) == 1
    assert pan_mentions[0].text == "ABCDE1234F"


def test_find_abha():
    """Test ABHA number and ABHA address."""
    text1 = "ABHA: 14-1234-5678-9012"
    mentions1 = find_identifiers(text1)
    assert any(m.etype == EType.ABHA_NUMBER for m in mentions1)

    text2 = "Health ID: priya.sharma@abdm"
    mentions2 = find_identifiers(text2)
    assert any(m.etype == EType.ABHA_ADDRESS for m in mentions2)


def test_find_mrn_and_insurance():
    """Test hospital MRN, UHID, and insurance IDs."""
    text_mrn = "Patient admit under SNJ/26/064127, UHID-987654"
    mentions_mrn = find_identifiers(text_mrn)
    mrn_mentions = [m for m in mentions_mrn if m.etype == EType.MRN]
    assert len(mrn_mentions) >= 1

    text_ins = "Covered under PMJAY-876543210 policy"
    mentions_ins = find_identifiers(text_ins)
    assert any(m.etype == EType.INSURANCE_ID for m in mentions_ins)


def test_find_house_and_pin():
    """Test House addresses and PIN codes."""
    text1 = "Address: H.No. 364, Sector 12"
    mentions1 = find_identifiers(text1)
    assert any(m.etype == EType.HOUSE for m in mentions1)

    text2 = "Pincode: 229073"
    mentions2 = find_identifiers(text2)
    pin_mentions = [m for m in mentions2 if m.etype == EType.PIN]
    assert len(pin_mentions) == 1
    assert pin_mentions[0].text == "229073"
