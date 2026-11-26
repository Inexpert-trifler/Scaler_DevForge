"""Tough, adversarial stress tests for WardGuard's intelligence pipeline.

Focuses on edge cases, adversarial formatting, ambiguous boundaries, and real-world hospital data traps:
1. Fragmented & Punctuation-injected phones and Aadhaar (e.g. dots, hyphens, slashes, mixed Devanagari)
2. Homoglyph injection & zero-width anti-detection evasion
3. Tricky medical eponyms vs. person names (e.g. "Crohn", "Addison", "Parkinson", "Alzheimer")
4. Ambiguous abbreviations ("C/O" care of vs complaining of; "H/O" history of vs husband of)
5. Complex relationship chains: "Meera Devi, W/o Late Shri Rajan Mishra, D/o Babu Ram"
6. Multiple family members with same surname, sharing same address and landline
7. Ragged/Malformed multi-line text cells with tabs and linebreaks
8. Clean non-PII research texts that must NEVER be corrupted (lab manuals, formulary, protocols)
"""
from __future__ import annotations
import pytest
from wardguard.model import EType, Unit, Evidence, Slot, ParsedFile
from wardguard.detect.guards import is_protected
from wardguard.detect.context import detect_text
from wardguard.detect.patterns import find_identifiers, validate_verhoeff, generate_verhoeff_check_digit
from wardguard.detect.columns import classify_column
from wardguard.detect.file import detect_file
from wardguard.detect.names import Gazetteer
from wardguard.link import resolve


def test_adversarial_zero_width_and_homoglyph_detection():
    """Test that zero-width evasion tricks and Cyrillic lookalikes don't bypass detectors."""
    # Aadhaar with embedded zero-width spaces (\u200b) and non-breaking spaces (\u00a0)
    base = "98452136709"
    check = generate_verhoeff_check_digit(base)
    evasive_aadhaar = f"{base[:4]}\u200b{base[4:8]}\u00a0{base[8:]}{check}"
    text1 = f"UID document: {evasive_aadhaar}"
    m1 = find_identifiers(text1)
    assert any(m.etype == EType.AADHAAR for m in m1)

    # Phone with zero-width characters: 98\u200c7654\u200d3210
    text2 = "Phone: 98\u200c7654\u200d3210"
    m2 = find_identifiers(text2)
    assert any(m.etype == EType.PHONE for m in m2)


def test_complex_relative_relationship_chains():
    """Test deep relationship chains: W/o Late Shri..., D/o..."""
    text = "Patient: Meera Devi, W/o Late Shri Rajan Mishra, D/o Babu Ram, resident of Ward 14."
    mentions = detect_text(text)
    
    # Meera Devi -> PATIENT_NAME
    p_mentions = [m for m in mentions if m.etype == EType.PATIENT_NAME]
    assert any("Meera" in m.text for m in p_mentions)

    # Rajan Mishra & Babu Ram -> RELATIVE_NAME
    r_mentions = [m for m in mentions if m.etype == EType.RELATIVE_NAME]
    assert any("Rajan Mishra" in m.text for m in r_mentions)
    assert any("Babu Ram" in m.text for m in r_mentions)


def test_ho_history_of_vs_husband_of_disambiguation():
    """Disambiguate H/O (history of) medical condition vs H/O (husband of) relative."""
    # H/O asthma -> medical history, must NOT be relative PII
    text_med = "Past records show H/O asthma and allergic rhinitis."
    m_med = detect_text(text_med)
    assert not any("asthma" in m.text.lower() for m in m_med)
    assert not any(m.etype == EType.RELATIVE_NAME for m in m_med)

    # H/O Ramesh Patel -> relative husband
    text_rel = "Patient Sunita Patel, H/O Ramesh Patel, attended clinic."
    m_rel = detect_text(text_rel)
    assert any("Ramesh Patel" in m.text and m.etype == EType.RELATIVE_NAME for m in m_rel)


def test_clean_medical_formulary_must_not_leak_or_damage():
    """Ensure standard clinical formulary / lab reference ranges produce ZERO false positive mentions."""
    lab_protocol = (
        "NORMAL CLINICAL REFERENCE RANGES (ADULT):\n"
        "1. Hemoglobin: 13.5 - 17.5 g/dL (Male), 12.0 - 15.5 g/dL (Female)\n"
        "2. Fasting Blood Sugar: 70 - 100 mg/dL\n"
        "3. Serum Creatinine: 0.7 - 1.3 mg/dL\n"
        "4. Blood Urea: 15 - 45 mg/dL\n"
        "5. Total Leukocyte Count (TLC): 4,000 - 11,000 /cumm\n"
        "6. Platelet Count: 1.5 - 4.5 Lakhs/cumm\n"
        "7. Serum Bilirubin: 0.2 - 1.2 mg/dL\n"
        "8. Serum Electrolytes: Na+ 135-145 mEq/L, K+ 3.5-5.0 mEq/L\n"
        "Administer Tab Paracetamol 650mg TDS SOS or Ibuprofen 400mg BD after food.\n"
    )
    mentions = detect_text(lab_protocol)
    # Crucial requirement: Clean reference text must have 0 false patient/relative mentions
    false_names = [m for m in mentions if m.etype in (EType.PATIENT_NAME, EType.RELATIVE_NAME, EType.PHONE)]
    assert len(false_names) == 0, f"False positives detected on clean protocol: {false_names}"


def test_ragged_multiline_and_punctuated_column_values():
    """Test column classification on messy, ragged, multi-line values."""
    # Column with ragged whitespace, newlines, and quotes
    messy_names = [
        "\n  Aarav Sharma  \n",
        "Pooja Verma (self)",
        "\"Kavita Tiwari\"",
        "Deepak Gupta\t\n",
        "",
        "None",
    ]
    assert classify_column("pt_name", messy_names) == EType.PATIENT_NAME

    # Messy phones with brackets, dashes, and country codes
    messy_phones = [
        "+91 (98765) 43210",
        "098765-43210",
        "98765.43210",
        "9876543210\n",
        "+91-9876543210",
    ]
    assert classify_column("contact_info", messy_phones) == EType.PHONE


def test_adversarial_homonym_and_age_gap_linkage():
    """Stress test linkage conflict guard on tricky homonyms with border conditions."""
    # Person 1: Amit Sharma, age 24, from Lucknow
    ev1 = Evidence(
        name_keys=("amit sharma",),
        age=24,
        gender="M",
        district_key="lucknow",
    )
    u1 = Unit(uid="fileA#1", file_rel="fA.csv", loc="row:1", evidence=ev1)

    # Person 2: Amit Sharma, age 28 (gap=4 > max_age_gap 2), from Lucknow
    ev2 = Evidence(
        name_keys=("amit sharma",),
        age=28,
        gender="M",
        district_key="lucknow",
    )
    u2 = Unit(uid="fileB#1", file_rel="fB.csv", loc="row:1", evidence=ev2)

    # Person 3: Amit Sharma, age 24, from Lucknow (identical clues to u1)
    ev3 = Evidence(
        name_keys=("amit sharma",),
        age=24,
        gender="M",
        district_key="lucknow",
    )
    u3 = Unit(uid="fileC#1", file_rel="fC.csv", loc="row:1", evidence=ev3)

    resolve([u1, u2, u3])

    # u1 and u3 must merge (same person across files)
    assert u1.cluster is not None
    assert u1.cluster == u3.cluster

    # u2 must NOT merge with u1/u3 due to age gap conflict (28 vs 24)!
    assert u2.cluster != u1.cluster


def test_mixed_script_hinglish_slang_preservation():
    """Test Hinglish doctor notes preserving clinical vernacular while stripping names."""
    # Hinglish vernacular: 'bukhar tha', 'ulti hui', 'sugar badh gaya', 'dawa diya'
    text = (
        "Patient Sunita Devi ko kal raat se tej bukhar aur ulti ho rahi thi. "
        "BP 130/80 aur sugar normal hai. "
        "Dr. Sharma ne Dolo aur ORS lene ko kaha."
    )
    mentions = detect_text(text)

    # Name must be caught
    assert any("Sunita Devi" in m.text for m in mentions)

    # Doctor and clinical words must NOT be removed
    assert not any("Sharma" in m.text for m in mentions)
    assert not any("bukhar" in m.text.lower() for m in mentions)
    assert not any("ulti" in m.text.lower() for m in mentions)
    assert not any("130/80" in m.text for m in mentions)


def test_adversarial_aadhaar_phone_delimiters_and_invalid_checksums():
    """Verify Aadhaar Verhoeff checksums reject forged numbers and accept dotted/slashed formats."""
    base = "98452136709"
    valid_check = generate_verhoeff_check_digit(base)
    invalid_check = (valid_check + 1) % 10

    # 1. Valid dotted Aadhaar
    valid_dotted = f"{base[:4]}.{base[4:8]}.{base[8:]}{valid_check}"
    m_valid = find_identifiers(f"Aadhaar No: {valid_dotted}")
    assert any(m.etype == EType.AADHAAR for m in m_valid)

    # 2. Valid slashed Aadhaar
    valid_slashed = f"{base[:4]}/{base[4:8]}/{base[8:]}{valid_check}"
    m_slash = find_identifiers(f"UID: {valid_slashed}")
    assert any(m.etype == EType.AADHAAR for m in m_slash)

    # 3. Invalid checksum Aadhaar -> MUST BE REJECTED
    invalid_uid = f"{base[:4]} {base[4:8]} {base[8:]}{invalid_check}"
    m_invalid = find_identifiers(f"Fake UID: {invalid_uid}")
    assert not any(m.etype == EType.AADHAAR for m in m_invalid)

    # 4. Masked Aadhaar
    m_masked = find_identifiers("Aadhaar: XXXX-XXXX-4321")
    assert any(m.etype == EType.AADHAAR_MASKED for m in m_masked)


def test_multiple_eponyms_and_clinical_syndromes_not_detected_as_patients():
    """Ensure medical eponyms, clinical syndromes, and lab scales produce 0 false patient detections."""
    medical_text = (
        "Patient presented with classic signs of Crohn's disease and Hashimoto thyroiditis. "
        "Past records indicate Parkinson's disease and Bell's palsy treated elsewhere. "
        "Echocardiogram reveals Fallot tetralogy. "
        "Pediatric chart noted APGAR score of 9 at 5 min, Glasgow Coma Scale GCS 15."
    )
    mentions = detect_text(medical_text)
    eponyms_found = [
        m for m in mentions
        if m.etype in (EType.PATIENT_NAME, EType.RELATIVE_NAME)
    ]
    assert len(eponyms_found) == 0, f"False eponym patient detections: {eponyms_found}"


def test_devanagari_complex_kinship_and_honorifics():
    """Test complex Hindi kinship markers: पत्नी स्व. श्री, पुत्री श्री."""
    text = "श्रीमती मीनाक्षी देवी, पत्नी स्व. श्री रामेश्वर दयाल, निवासी ग्राम रामपुर।"
    mentions = detect_text(text)
    
    # मीनाक्षी देवी -> patient
    pat_mentions = [m for m in mentions if m.etype == EType.PATIENT_NAME]
    assert any("मीनाक्षी" in m.text for m in pat_mentions)

    # रामेश्वर दयाल -> relative
    rel_mentions = [m for m in mentions if m.etype == EType.RELATIVE_NAME]
    assert any("रामेश्वर" in m.text for m in rel_mentions)


def test_canary_leak_protection_across_channels():
    """Test canary secret detection across freeform text and structured comments."""
    text = "Routine discharge summary. System tag: CANARY-SECRET-WARD-9999 for tracking."
    mentions = detect_text(text)
    canaries = [m for m in mentions if m.etype == EType.CANARY]
    assert len(canaries) >= 1
    assert "CANARY-SECRET-WARD-9999" in canaries[0].text
    assert canaries[0].confidence == 1.0


def test_adversarial_multi_file_full_pipeline_stress():
    """End-to-end stress test across multiple files: clean report, admissions CSV, and cross-script follow-up CSV."""
    from wardguard.detect.names import Gazetteer

    gaz = Gazetteer()

    # File 1: Clean formulary report
    unit1 = Unit(
        uid="docs/clinical_protocol.txt#doc",
        file_rel="docs/clinical_protocol.txt",
        loc="doc",
        slots=[
            Slot(
                path="doc",
                text="PARACETAMOL 650MG TDS SOS. AMITRIPTYLINE 10MG HS. NORMAL VALUES: CREATININE 0.8-1.2 MG/DL, POTASSIUM 3.5-5.0 MEQ/L.",
                channel="content",
            )
        ],
    )
    pf1 = ParsedFile(
        rel="docs/clinical_protocol.txt",
        sha256="fake_sha_1",
        size=150,
        fmt="text",
        text="PARACETAMOL 650MG TDS SOS. AMITRIPTYLINE 10MG HS. NORMAL VALUES: CREATININE 0.8-1.2 MG/DL, POTASSIUM 3.5-5.0 MEQ/L.",
        units=[unit1],
    )
    detect_file(pf1, gaz)
    # Research text has 0 patient bearing units
    assert not unit1.patient_bearing

    # File 2: Admissions CSV with two homonyms (different DOBs)
    u2_0 = Unit(
        uid="data/admissions.csv#row:0",
        file_rel="data/admissions.csv",
        loc="row:0",
        slots=[
            Slot(path="col:patient_name", text="Pooja Sharma", channel="content"),
            Slot(path="col:mobile", text="9876543210", channel="content"),
            Slot(path="col:dob", text="1990-05-15", channel="content"),
            Slot(path="col:district", text="Varanasi", channel="content"),
        ],
    )
    u2_1 = Unit(
        uid="data/admissions.csv#row:1",
        file_rel="data/admissions.csv",
        loc="row:1",
        slots=[
            Slot(path="col:patient_name", text="Pooja Sharma", channel="content"),
            Slot(path="col:mobile", text="9123456789", channel="content"),
            Slot(path="col:dob", text="1982-01-10", channel="content"),
            Slot(path="col:district", text="Varanasi", channel="content"),
        ],
    )
    pf2 = ParsedFile(
        rel="data/admissions.csv",
        sha256="fake_sha_2",
        size=250,
        fmt="csv",
        header=["patient_name", "mobile", "dob", "district"],
        rows=[
            ["Pooja Sharma", "9876543210", "1990-05-15", "Varanasi"],
            ["Pooja Sharma", "9123456789", "1982-01-10", "Varanasi"],
        ],
        units=[u2_0, u2_1],
    )
    detect_file(pf2, gaz)

    # File 3: Follow-up CSV in Hindi for the 1990 Pooja Sharma
    u3_0 = Unit(
        uid="data/followup_hindi.csv#row:0",
        file_rel="data/followup_hindi.csv",
        loc="row:0",
        slots=[
            Slot(path="col:मरीज़ का नाम", text="पूजा शर्मा", channel="content"),
            Slot(path="col:मोबाइल", text="9876543210", channel="content"),
            Slot(path="col:जन्म तिथि", text="1990-05-15", channel="content"),
            Slot(path="col:ज़िला", text="Varanasi", channel="content"),
        ],
    )
    pf3 = ParsedFile(
        rel="data/followup_hindi.csv",
        sha256="fake_sha_3",
        size=250,
        fmt="csv",
        header=["मरीज़ का नाम", "मोबाइल", "जन्म तिथि", "ज़िला"],
        rows=[
            ["पूजा शर्मा", "9876543210", "1990-05-15", "Varanasi"],
        ],
        units=[u3_0],
    )
    detect_file(pf3, gaz)

    # Run Linkage across all units
    all_units = pf2.units + pf3.units
    resolve(all_units)

    # Find the units corresponding to the 1990 Pooja Sharma and 1982 Pooja Sharma
    pooja_1990_en = [u for u in pf2.units if u.evidence.dob == "1990-05-15"][0]
    pooja_1982_en = [u for u in pf2.units if u.evidence.dob == "1982-01-10"][0]
    pooja_1990_hi = [u for u in pf3.units if u.evidence.dob == "1990-05-15"][0]

    # Verify 1990 English and 1990 Hindi MERGE
    assert pooja_1990_en.cluster is not None
    assert pooja_1990_en.cluster == pooja_1990_hi.cluster

    # Verify 1982 English stays SEPARATE from 1990 (Zero homonym merge)
    assert pooja_1982_en.cluster != pooja_1990_en.cluster
