"""Unit tests for detect_file and evidence extraction (Task S-07).

Tests:
- Tabular file column classification and whole-cell mentions
- Free-text slot detection and QI mentions (Age, DOB, Date, Gender)
- Unit evidence population (name keys, strong IDs, DOB, relative keys)
- patient_bearing flag assignment
"""
from __future__ import annotations
import pytest
from wardguard.model import ParsedFile, Unit, Slot, EType
from wardguard.detect.names import Gazetteer
from wardguard.detect.file import detect_file


def test_detect_file_structured_csv():
    """Test full file detection on structured tabular units."""
    # Build parsed CSV unit
    slot_name = Slot(path="col:Patient Name", text="Sunita Patel", channel="content")
    slot_phone = Slot(path="col:Contact#", text="9876543210", channel="content")
    slot_dob = Slot(path="col:Date of Birth", text="12/04/1977", channel="content")
    slot_notes = Slot(path="col:Remarks", text="Accompanied by husband Naresh Chauhan.", channel="content")

    unit = Unit(
        uid="reg.csv#row:0",
        file_rel="registration/reg.csv",
        loc="row:0",
        slots=[slot_name, slot_phone, slot_dob, slot_notes]
    )

    pf = ParsedFile(
        rel="registration/reg.csv",
        sha256="dummy",
        size=200,
        fmt="csv",
        header=["Patient Name", "Contact#", "Date of Birth", "Remarks"],
        units=[unit]
    )

    gaz = Gazetteer()
    detect_file(pf, gaz)

    # 1. Whole cell mentions check
    assert slot_name.column_type == EType.PATIENT_NAME
    assert any(m.etype == EType.PATIENT_NAME for m in slot_name.mentions)

    assert slot_phone.column_type == EType.PHONE
    assert any(m.etype == EType.PHONE for m in slot_phone.mentions)

    # 2. Free-text detection on remarks
    rel_mentions = [m for m in slot_notes.mentions if m.etype == EType.RELATIVE_NAME]
    assert len(rel_mentions) >= 1
    assert "Naresh Chauhan" in rel_mentions[0].text

    # 3. Evidence check
    assert "sunita patel" in unit.evidence.name_keys
    assert unit.evidence.dob == "1977-04-12"
    assert ("PHONE", "9876543210") in unit.evidence.strong_ids
    assert any("chauhan" in k for k in unit.evidence.relative_keys)
    assert unit.patient_bearing is True


def test_detect_file_free_text_doc():
    """Test full file detection on clinical document."""
    text_content = (
        "ADMISSION NOTE\n"
        "Patient: Rahul Sharma, 48 Y / Male\n"
        "Address: C/O Mohan Lal, H.No. 364\n"
        "Phone: 9812345678\n"
        "Impression: Parkinson's disease, prescribed Dolo 650mg TDS\n"
    )
    slot_doc = Slot(path="doc", text=text_content, channel="content")
    unit = Unit(uid="note.txt#doc", file_rel="notes/note.txt", loc="doc", slots=[slot_doc])
    pf = ParsedFile(rel="notes/note.txt", sha256="dummy", size=200, fmt="text", units=[unit])

    gaz = Gazetteer()
    detect_file(pf, gaz)

    # Patient name detected
    m_names = [m for m in slot_doc.mentions if m.etype == EType.PATIENT_NAME]
    assert any("Rahul Sharma" in m.text for m in m_names)

    # Relative name detected
    m_rel = [m for m in slot_doc.mentions if m.etype == EType.RELATIVE_NAME]
    assert any("Mohan Lal" in m.text for m in m_rel)

    # Phone detected
    assert any(m.etype == EType.PHONE for m in slot_doc.mentions)

    # House address detected
    assert any(m.etype == EType.HOUSE for m in slot_doc.mentions)

    # Guarded terms NOT flagged: Parkinson's disease, Dolo 650mg
    assert not any("Parkinson" in m.text for m in slot_doc.mentions)
    assert not any("650" in m.text for m in slot_doc.mentions)

    # Unit evidence check
    assert any("rahul" in k for k in unit.evidence.name_keys)
    assert unit.evidence.age == 48
    assert ("PHONE", "9812345678") in unit.evidence.strong_ids
    assert unit.patient_bearing is True
