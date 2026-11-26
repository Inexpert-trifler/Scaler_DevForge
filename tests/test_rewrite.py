"""Comprehensive tests for rewrite engine (L-10, Milestone M1).

Validates:
- Right-to-left mention application without offset drift
- Overlapping mentions resolved cleanly
- Whole-cell replacement when column_type is set
- PSN placement in existing fields (D-010):
    - CSV patient name cell or UHID cell (no new columns)
    - JSON patient name or UHID field
    - Text documents: name replacement or 'Patient: PSN-XXXXXX' prepended
    - FHIR Patient.identifier
- JSON numeric primitive type preservation (TR-PRV-5, TR-PRV-8)
- Quasi-identifier generalization and date shifting
- Hidden channels: base64 re-encoding and header rewriting
- Policy min_confidence thresholding
"""
import base64
import csv
import io
import json
import pytest

from wardguard.model import EType, Mention, ParsedFile, Slot, Unit
from wardguard.rewrite import (
    apply_mentions,
    get_replacement,
    render,
    rewrite_unit,
    rewrite_whole_cell,
    set_json_pointer,
)


@pytest.fixture
def default_policy():
    return {
        "psn_prefix": "PSN-",
        "date_shift_max_days": 180,
        "age_band_years": 5,
        "age_top_code": 90,
        "pin_keep_digits": 3,
        "dob_action": "year",
        "min_confidence": 0.5,
        "tokens": {
            "PATIENT_NAME": "[NAME]",
            "RELATIVE_NAME": "[RELATIVE]",
            "PHONE": "[PHONE]",
            "AADHAAR": "[AADHAAR]",
            "PAN": "[PAN]",
            "MRN": "[MRN]",
            "INSURANCE_ID": "[INSURANCE]",
            "EMAIL": "[EMAIL]",
            "HOUSE": "[ADDRESS]",
            "LANDMARK": "[ADDRESS]",
            "LOCALITY": "[ADDRESS]",
            "OTHER_PERSON": "[NAME]",
            "CANARY": "[CANARY]",
        },
    }


def test_apply_mentions_right_to_left_no_drift(default_policy):
    """Mentions of varying lengths should be replaced right-to-left without offset drift."""
    # text: "Patient Rajesh Kumar, Phone 9876543210, born 15/08/1985."
    # indexes:
    # 01234567890123456789012345678901234567890123456789012345
    #         Rajesh Kumar (8..20)
    #                             9876543210 (28..38)
    #                                                15/08/1985 (45..55)
    text = "Patient Rajesh Kumar, Phone 9876543210, born 15/08/1985."
    u = Unit(uid="doc#0", file_rel="doc.txt", loc="doc", psn="PSN-ABC123", date_offset=10)

    m1 = Mention(
        etype=EType.PATIENT_NAME,
        start=8,
        end=20,
        text="Rajesh Kumar",
        script="latin",
        channel="content",
        role="patient",
    )
    m2 = Mention(
        etype=EType.PHONE,
        start=28,
        end=38,
        text="9876543210",
        script="latin",
        channel="content",
    )
    m3 = Mention(
        etype=EType.DOB,
        start=45,
        end=55,
        text="15/08/1985",
        script="latin",
        channel="content",
    )

    out = apply_mentions(text, [m1, m2, m3], u, default_policy)
    # Rajesh Kumar -> PSN-ABC123 (length 10 vs 12)
    # 9876543210 -> [PHONE] (length 7 vs 10)
    # 15/08/1985 -> 1985 (length 4 vs 10)
    assert "Patient PSN-ABC123, Phone [PHONE], born 1985." == out


def test_overlapping_mentions_handled(default_policy):
    """When mentions overlap, right-to-left processing skips conflicting spans."""
    text = "Contact 9876543210 immediately."
    # Overlapping: entire phone (8..18) and subpart (8..13)
    m_full = Mention(
        etype=EType.PHONE,
        start=8,
        end=18,
        text="9876543210",
        script="latin",
        channel="content",
    )
    m_sub = Mention(
        etype=EType.PHONE,
        start=8,
        end=13,
        text="98765",
        script="latin",
        channel="content",
    )

    out = apply_mentions(text, [m_sub, m_full], None, default_policy)
    assert out == "Contact [PHONE] immediately."


def test_whole_cell_replacement_csv(default_policy):
    """Structured CSV columns are cleanly replaced without leaving trailing chars."""
    pf = ParsedFile(
        rel="opd.csv",
        sha256="abc",
        size=100,
        fmt="csv",
        delimiter=",",
        header=["Name", "Age", "Phone", "Date", "Diagnosis"],
        status="pending",
    )
    u = Unit(
        uid="opd.csv#row:0",
        file_rel="opd.csv",
        loc="row:0",
        psn="PSN-XYZ999",
        date_offset=30,
        patient_bearing=True,
    )
    s_name = Slot(path="col:Name", text="Aarav Sharma", channel="content", column_type=EType.PATIENT_NAME)
    s_age = Slot(path="col:Age", text="48", channel="content", column_type=EType.AGE)
    s_phone = Slot(path="col:Phone", text="9876543210", channel="content", column_type=EType.PHONE)
    s_date = Slot(path="col:Date", text="01/01/2023", channel="content", column_type=EType.DATE)
    s_diag = Slot(path="col:Diagnosis", text="Asthma", channel="content")

    u.slots = [s_name, s_age, s_phone, s_date, s_diag]
    pf.units = [u]

    data = render(pf, default_policy)
    decoded = data.decode("utf-8")
    rows = list(csv.reader(io.StringIO(decoded)))

    assert len(rows) == 2
    assert rows[0] == ["Name", "Age", "Phone", "Date", "Diagnosis"]
    row1 = rows[1]
    assert row1[0] == "PSN-XYZ999"  # Patient name cell gets PSN
    assert row1[1] == "45-49"       # 48 -> 45-49 band
    assert row1[2] == "[PHONE]"     # Phone -> [PHONE]
    assert row1[3] == "31/01/2023"  # Date shifted by +30 days preserving format
    assert row1[4] == "Asthma"      # Clinical diagnosis preserved


def test_numeric_json_types_preserved(default_policy):
    """In JSON, int/float fields must remain numbers (0 for IDs, lower bound for age)."""
    raw_obj = {
        "visit_id": 1001,
        "phone": 9876543210,
        "age": 48,
        "bill": 1500.50,
        "patient": "Rajesh Kumar",
    }
    pf = ParsedFile(
        rel="visit.json",
        sha256="123",
        size=100,
        fmt="json",
        obj=raw_obj,
        status="pending",
    )
    u = Unit(
        uid="visit.json#/0",
        file_rel="visit.json",
        loc="/0",
        psn="PSN-MED123",
        patient_bearing=True,
    )
    u.slots = [
        Slot(path="/visit_id", text="1001", channel="content", value_type="int"),
        Slot(path="/phone", text="9876543210", channel="content", value_type="int", column_type=EType.PHONE),
        Slot(path="/age", text="48", channel="content", value_type="int", column_type=EType.AGE),
        Slot(path="/bill", text="1500.5", channel="content", value_type="float"),
        Slot(path="/patient", text="Rajesh Kumar", channel="content", value_type="str", column_type=EType.PATIENT_NAME),
    ]
    pf.units = [u]

    data = render(pf, default_policy)
    sanitized = json.loads(data.decode("utf-8"))

    # Assert type preservation
    assert isinstance(sanitized["visit_id"], int)
    assert sanitized["visit_id"] == 1001

    assert isinstance(sanitized["phone"], int)
    assert sanitized["phone"] == 0  # TR-PRV-8: Numeric JSON fields -> 0

    assert isinstance(sanitized["age"], int)
    assert sanitized["age"] == 45  # TR-PRV-5 / D-012: Lower bound of 45-49 band as int

    assert isinstance(sanitized["bill"], float)
    assert sanitized["bill"] == 1500.5

    assert isinstance(sanitized["patient"], str)
    assert sanitized["patient"] == "PSN-MED123"


def test_psn_placement_in_uhid_when_no_name(default_policy):
    """When a table has no patient name column, PSN is placed in the UHID/MRN column (D-010)."""
    pf = ParsedFile(
        rel="lab.csv",
        sha256="lab1",
        size=80,
        fmt="csv",
        delimiter=",",
        header=["UHID", "Test", "Result"],
        status="pending",
    )
    u = Unit(
        uid="lab.csv#row:0",
        file_rel="lab.csv",
        loc="row:0",
        psn="PSN-LAB456",
        patient_bearing=True,
    )
    s_uhid = Slot(path="col:UHID", text="UHID-98765", channel="content", column_type=EType.MRN)
    s_test = Slot(path="col:Test", text="Hemoglobin", channel="content")
    s_res = Slot(path="col:Result", text="13.5", channel="content")

    u.slots = [s_uhid, s_test, s_res]
    pf.units = [u]

    data = render(pf, default_policy)
    rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))

    assert len(rows[0]) == 3  # TR-PRV-2: No new CSV columns added
    assert rows[1][0] == "PSN-LAB456"  # UHID received PSN
    assert rows[1][1] == "Hemoglobin"
    assert rows[1][2] == "13.5"


def test_psn_placement_in_text_document(default_policy):
    """Text doc replaces patient name if present, or prepends 'Patient: PSN-XXXXXX' if no name."""
    # Case A: Name present -> replaced in-place
    pf1 = ParsedFile(rel="doc1.txt", sha256="t1", size=50, fmt="text", status="pending")
    u1 = Unit(uid="doc1.txt#doc", file_rel="doc1.txt", loc="doc", psn="PSN-DOC111", patient_bearing=True)
    m1 = Mention(etype=EType.PATIENT_NAME, start=0, end=12, text="Rajesh Kumar", script="latin", channel="content")
    u1.slots = [Slot(path="doc", text="Rajesh Kumar is admitted.", channel="content", mentions=[m1])]
    pf1.units = [u1]

    data1 = render(pf1, default_policy).decode("utf-8")
    assert data1 == "PSN-DOC111 is admitted."

    # Case B: No name present, but patient-bearing (e.g. phone found) -> prepends "Patient: PSN-DOC222\n"
    pf2 = ParsedFile(rel="doc2.txt", sha256="t2", size=50, fmt="text", status="pending")
    u2 = Unit(uid="doc2.txt#doc", file_rel="doc2.txt", loc="doc", psn="PSN-DOC222", patient_bearing=True)
    m2 = Mention(etype=EType.PHONE, start=15, end=25, text="9876543210", script="latin", channel="content")
    u2.slots = [Slot(path="doc", text="Contact number 9876543210.", channel="content", mentions=[m2])]
    pf2.units = [u2]

    data2 = render(pf2, default_policy).decode("utf-8")
    assert data2.startswith("Patient: PSN-DOC222\n")
    assert "Contact number [PHONE]." in data2


def test_fhir_psn_placement(default_policy):
    """FHIR bundles should have PSN placed into Patient.identifier."""
    fhir_obj = {
        "resourceType": "Bundle",
        "entry": [
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": "pat1",
                    "identifier": [{"system": "hospital", "value": "UHID-123"}],
                }
            }
        ],
    }
    pf = ParsedFile(rel="bundle.json", sha256="f1", size=100, fmt="fhir", obj=fhir_obj, status="pending")
    u = Unit(uid="bundle.json#doc", file_rel="bundle.json", loc="doc", psn="PSN-FHIR789", patient_bearing=True)
    pf.units = [u]

    data = render(pf, default_policy)
    out_obj = json.loads(data.decode("utf-8"))

    pat = out_obj["entry"][0]["resource"]
    identifiers = pat["identifier"]
    assert any(i["value"] == "PSN-FHIR789" for i in identifiers)


def test_hidden_channel_base64_re_encoding(default_policy):
    """Base64 slot rewriting propagates sanitized text re-encoded to parent slot."""
    # "Rajesh Kumar" in base64 is "UmFqZXNoIEt1bWFy"
    orig_b64 = base64.b64encode(b"Rajesh Kumar").decode("ascii")
    parent_slot = Slot(path="/meta/notes", text=orig_b64, channel="metadata")
    b64_slot = Slot(
        path="/meta/notes#b64",
        text="Rajesh Kumar",
        channel="base64",
        mentions=[
            Mention(
                etype=EType.PATIENT_NAME,
                start=0,
                end=12,
                text="Rajesh Kumar",
                script="latin",
                channel="base64",
            )
        ],
    )
    u = Unit(uid="rec#0", file_rel="rec.json", loc="0", psn="PSN-B64XYZ", patient_bearing=True)
    u.slots = [parent_slot, b64_slot]

    rewrite_unit(u, default_policy)

    # Parent slot text must now be base64-encoded "PSN-B64XYZ"
    expected_b64 = base64.b64encode(b"PSN-B64XYZ").decode("ascii")
    assert parent_slot.text == expected_b64


def test_header_pii_rewritten(default_policy):
    """CSV headers containing patient PII are rewritten cleanly."""
    pf = ParsedFile(
        rel="export.csv",
        sha256="h1",
        size=100,
        fmt="csv",
        delimiter=",",
        header=["Record_ID", "Patient_Rajesh_Kumar", "Status"],
        status="pending",
    )
    h_slot = Slot(
        path="@header:1",
        text="Patient_Rajesh_Kumar",
        channel="header",
        mentions=[
            Mention(
                etype=EType.PATIENT_NAME,
                start=8,
                end=20,
                text="Rajesh_Kumar",
                script="latin",
                channel="header",
            )
        ],
    )
    pf.file_slots = [h_slot]

    data = render(pf, default_policy)
    rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))

    assert rows[0] == ["Record_ID", "Patient_[NAME]", "Status"]


def test_min_confidence_filter(default_policy):
    """Mentions with confidence below policy.min_confidence are ignored."""
    text = "Review for Rajesh Kumar."
    m_low = Mention(
        etype=EType.PATIENT_NAME,
        start=11,
        end=23,
        text="Rajesh Kumar",
        script="latin",
        channel="content",
        confidence=0.3,  # Below min_confidence 0.5
    )
    out = apply_mentions(text, [m_low], None, default_policy)
    assert out == text  # Unmodified


def test_canary_rewrite_token(default_policy):
    """Planted CANARY tokens are replaced with [CANARY]."""
    text = "Note CANARY-SECRET-WARD-9999 tag."
    canary_token = "CANARY-SECRET-WARD-9999"
    start = text.index(canary_token)
    end = start + len(canary_token)
    m_canary = Mention(
        etype=EType.CANARY,
        start=start,
        end=end,
        text=canary_token,
        script="latin",
        channel="content",
        confidence=1.0,
    )
    out = apply_mentions(text, [m_canary], None, default_policy)
    assert out == "Note [CANARY] tag."


def test_json_key_renaming_rfc6901_unescaping_and_collision_safety(default_policy):
    """Bug B test: RFC 6901 unescaping, deterministic suffix on collisions, nested parent/child."""
    # 1. Key containing '/' and '~' (RFC 6901 escaped)
    raw_obj = {
        "by_uhid": {
            "SNJ/126~1064511": {"patient": "Rajesh"}
        }
    }
    pf = ParsedFile(rel="test.json", sha256="abc", size=10, fmt="json", status="pending", obj=raw_obj)
    s = Slot(
        path="@key:/by_uhid/SNJ~1126~01064511",
        text="[MRN]",
        channel="key",
    )
    pf.file_slots = [s]
    rendered = render(pf, default_policy)
    parsed = json.loads(rendered.decode("utf-8"))
    assert "[MRN]" in parsed["by_uhid"]
    assert "SNJ/126~1064511" not in parsed["by_uhid"]
    assert parsed["by_uhid"]["[MRN]"] == {"patient": "Rajesh"}

    # 2. Three sibling keys all mapping to [MRN] keep 3 entries with distinct deterministic names
    obj_coll = {
        "index": {
            "MRN_A": 1,
            "MRN_B": 2,
            "MRN_C": 3,
        }
    }
    pf_coll = ParsedFile(rel="coll.json", sha256="abc", size=10, fmt="json", status="pending", obj=obj_coll)
    pf_coll.file_slots = [
        Slot(path="@key:/index/MRN_A", text="[MRN]", channel="key"),
        Slot(path="@key:/index/MRN_B", text="[MRN]", channel="key"),
        Slot(path="@key:/index/MRN_C", text="[MRN]", channel="key"),
    ]
    rendered_coll = render(pf_coll, default_policy)
    parsed_coll = json.loads(rendered_coll.decode("utf-8"))
    assert list(parsed_coll["index"].keys()) == ["[MRN]", "[MRN]_2", "[MRN]_3"]
    assert parsed_coll["index"]["[MRN]"] == 1
    assert parsed_coll["index"]["[MRN]_2"] == 2
    assert parsed_coll["index"]["[MRN]_3"] == 3

    # 3. Nested case: both parent key and child key contain PII -> both renamed
    obj_nested = {
        "Aadhaar_123456789012": {
            "UHID_9999": "patient data"
        }
    }
    pf_nested = ParsedFile(rel="nested.json", sha256="abc", size=10, fmt="json", status="pending", obj=obj_nested)
    pf_nested.file_slots = [
        Slot(path="@key:/Aadhaar_123456789012", text="[AADHAAR]", channel="key"),
        Slot(path="@key:/Aadhaar_123456789012/UHID_9999", text="[MRN]", channel="key"),
    ]
    rendered_nested = render(pf_nested, default_policy)
    parsed_nested = json.loads(rendered_nested.decode("utf-8"))
    assert "[AADHAAR]" in parsed_nested
    assert "[MRN]" in parsed_nested["[AADHAAR]"]
    assert parsed_nested["[AADHAAR]"]["[MRN]"] == "patient data"

    # 4. Same input twice -> identical bytes
    rendered_nested2 = render(pf_nested, default_policy)
    assert rendered_nested == rendered_nested2

