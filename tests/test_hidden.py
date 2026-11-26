"""Tests for Hidden Channels and Filename Renaming (TR-DET-9, TR-EXP-2)."""
import base64
from wardguard.detect.hidden import (
    apply_filename_renaming,
    decode_escape_sequences,
    extract_hidden_slots,
    try_decode_base64,
)
from wardguard.model import EType, Mention, ParsedFile, Slot, Unit


def test_try_decode_base64():
    # Valid base64 encoding printable text
    raw_text = "Patient Aarav Sharma admitted"
    encoded = base64.b64encode(raw_text.encode("utf-8")).decode("ascii")
    assert try_decode_base64(encoded) == raw_text

    # Invalid base64 or binary
    assert try_decode_base64("not_base64!!") is None
    # Short
    assert try_decode_base64("abc") is None
    # Pure non-printable binary
    bin_b64 = base64.b64encode(b"\x00\x01\x02\x03\xff").decode("ascii")
    assert try_decode_base64(bin_b64) is None


def test_decode_escape_sequences():
    # HTML entities
    assert decode_escape_sequences("Patient &amp; Guardian") == "Patient & Guardian"
    # %-encoding
    assert decode_escape_sequences("Aarav%20Sharma") == "Aarav Sharma"
    # Unicode escape \uXXXX
    assert decode_escape_sequences(r"Dr. \u0930\u092e\u0947\u0936") == "Dr. रमेश"
    # Plain text returns None
    assert decode_escape_sequences("Normal text without escapes") is None


def test_extract_hidden_slots_csv():
    pf = ParsedFile(
        rel="opd/records.csv",
        sha256="123",
        size=100,
        fmt="csv",
        header=["UHID", "Patient Name", "Phone"],
        status="pending",
    )
    extract_hidden_slots(pf)

    # Check file_slots: @filename and @header:0..2
    paths = [s.path for s in pf.file_slots]
    assert "@filename" in paths
    assert "@header:0" in paths
    assert "@header:1" in paths
    assert "@header:2" in paths

    fn_slot = [s for s in pf.file_slots if s.path == "@filename"][0]
    assert fn_slot.text == "records"
    assert fn_slot.channel == "filename"


def test_extract_hidden_slots_json_keys_and_metadata():
    pf = ParsedFile(
        rel="hospital/data.json",
        sha256="456",
        size=200,
        fmt="json",
        obj={
            "source_path": "/internal/db/backup.sql",
            "patients": [
                {"patient_name": "Aarav", "payload_b64": base64.b64encode(b"Contact: 9876543210").decode("ascii")}
            ],
        },
        status="pending",
    )
    u0 = Unit(uid="hospital/data.json#/patients/0", file_rel="hospital/data.json", loc="/patients/0")
    u0.slots = [
        Slot(path="/source_path", text="/internal/db/backup.sql", channel="content"),
        Slot(path="/patients/0/payload_b64", text=base64.b64encode(b"Contact: 9876543210").decode("ascii"), channel="content"),
    ]
    pf.units = [u0]

    extract_hidden_slots(pf)

    # 1. JSON keys in file_slots
    key_paths = [s.path for s in pf.file_slots if s.channel == "key"]
    assert "@key:/source_path" in key_paths
    assert "@key:/patients" in key_paths
    assert "@key:/patients/0/patient_name" in key_paths

    # 2. Metadata slot classified
    assert u0.slots[0].channel == "metadata"

    # 3. Base64 decoded slot attached
    slot_paths = [s.path for s in u0.slots]
    assert "/patients/0/payload_b64#b64" in slot_paths
    b64_slot = [s for s in u0.slots if s.path == "/patients/0/payload_b64#b64"][0]
    assert b64_slot.text == "Contact: 9876543210"
    assert b64_slot.channel == "base64"


def test_apply_filename_renaming_with_pii():
    pf = ParsedFile(
        rel="opd/7148988804_report_0047.json",
        sha256="abcdef1234567890",
        size=100,
        fmt="json",
        status="pending",
    )
    extract_hidden_slots(pf)

    # Simulate detection finding phone number in @filename
    fn_slot = [s for s in pf.file_slots if s.path == "@filename"][0]
    fn_slot.mentions.append(
        Mention(
            etype=EType.PHONE,
            start=0,
            end=10,
            text="7148988804",
            script="latin",
            channel="filename",
        )
    )

    apply_filename_renaming([pf], {})

    # Renamed to [PHONE]_report_0047.json under sanitized/opd/
    assert pf.out_rel == "sanitized/opd/[PHONE]_report_0047.json"


def test_apply_filename_renaming_collision_handling():
    # Two files with different original names but identical renamed target
    pf1 = ParsedFile(
        rel="opd/9876543210_report.csv",
        sha256="1111222233334444",
        size=50,
        fmt="csv",
        status="pending",
    )
    pf2 = ParsedFile(
        rel="opd/9123456789_report.csv",
        sha256="9999888877776666",
        size=50,
        fmt="csv",
        status="pending",
    )
    extract_hidden_slots(pf1)
    extract_hidden_slots(pf2)

    fn1 = [s for s in pf1.file_slots if s.path == "@filename"][0]
    fn1.mentions.append(Mention(etype=EType.PHONE, start=0, end=10, text="9876543210", script="latin", channel="filename"))

    fn2 = [s for s in pf2.file_slots if s.path == "@filename"][0]
    fn2.mentions.append(Mention(etype=EType.PHONE, start=0, end=10, text="9123456789", script="latin", channel="filename"))

    apply_filename_renaming([pf1, pf2], {})

    # First file gets target
    assert pf1.out_rel == "sanitized/opd/[PHONE]_report.csv"
    # Second file collides and falls back to file_<sha8>.csv
    assert pf2.out_rel == "sanitized/opd/file_99998888.csv"
