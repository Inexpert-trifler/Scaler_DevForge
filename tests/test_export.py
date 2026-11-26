"""Tests for Export module (TR-EXP-1..4)."""
import csv
import io
import json
from pathlib import Path
import tempfile

from wardguard.export.records import write_records
from wardguard.export.report import write_report
from wardguard.export.writers import write_file
from wardguard.model import ParsedFile, RunStats, Slot, Unit
from wardguard.rewrite import render


def test_export_csv_quoting_and_structure():
    # CSV with quotes, commas, and newlines in values
    pf = ParsedFile(
        rel="opd.csv",
        sha256="abc",
        size=100,
        fmt="csv",
        delimiter=",",
        header=["ID", "Name", "Notes"],
        status="pending",
    )
    u0 = Unit(uid="opd.csv#row:0", file_rel="opd.csv", loc="row:0")
    u0.slots = [
        Slot(path="col:ID", text="1", channel="content"),
        Slot(path="col:Name", text="Aarav, Jr.", channel="content"),
        Slot(path="col:Notes", text="Line 1\nLine 2", channel="content"),
    ]
    pf.units = [u0]

    data = render(pf, {})
    decoded = data.decode("utf-8")

    # Read back with standard csv.reader
    reader = list(csv.reader(io.StringIO(decoded), delimiter=","))
    assert len(reader) == 2
    assert reader[0] == ["ID", "Name", "Notes"]
    assert reader[1] == ["1", "Aarav, Jr.", "Line 1\nLine 2"]


def test_export_tsv_delimiter():
    pf = ParsedFile(
        rel="data.tsv",
        sha256="tsv123",
        size=50,
        fmt="tsv",
        delimiter="\t",
        header=["ColA", "ColB"],
        status="pending",
    )
    u0 = Unit(uid="data.tsv#row:0", file_rel="data.tsv", loc="row:0")
    u0.slots = [
        Slot(path="col:ColA", text="Val1", channel="content"),
        Slot(path="col:ColB", text="Val2", channel="content"),
    ]
    pf.units = [u0]

    data = render(pf, {})
    assert b"ColA\tColB\n" in data
    assert b"Val1\tVal2\n" in data


def test_export_json_types_and_structure():
    original_obj = {
        "hospital": "City Hospital",
        "active": True,
        "visits": [
            {"id": 101, "patient": "Old Name", "bill": 1250.50, "discharged": None}
        ],
    }
    pf = ParsedFile(
        rel="data.json",
        sha256="json123",
        size=120,
        fmt="json",
        obj=original_obj,
        status="pending",
    )
    u0 = Unit(uid="data.json#/visits/0", file_rel="data.json", loc="/visits/0")
    u0.slots = [
        Slot(path="/visits/0/id", text="101", channel="content", value_type="int"),
        Slot(path="/visits/0/patient", text="PSN-ABCDEF", channel="content", value_type="str"),
        Slot(path="/visits/0/bill", text="1250.5", channel="content", value_type="float"),
        Slot(path="/visits/0/discharged", text="", channel="content", value_type="null"),
    ]
    pf.units = [u0]

    data = render(pf, {})
    result = json.loads(data.decode("utf-8"))

    assert result["hospital"] == "City Hospital"
    assert result["active"] is True
    assert len(result["visits"]) == 1
    v0 = result["visits"][0]
    assert v0["id"] == 101
    assert isinstance(v0["id"], int)
    assert v0["patient"] == "PSN-ABCDEF"
    assert v0["bill"] == 1250.5
    assert isinstance(v0["bill"], float)
    assert v0["discharged"] is None


def test_export_records_jsonl():
    pf1 = ParsedFile(rel="notes/note.txt", sha256="1", size=10, fmt="text", status="sanitized", out_rel="sanitized/notes/note.txt")
    u1 = Unit(uid="u1", file_rel="notes/note.txt", loc="doc", patient_bearing=True, psn=None)
    pf1.units = [u1]

    pf2 = ParsedFile(rel="opd/x.json", sha256="2", size=20, fmt="json", status="sanitized", out_rel="sanitized/opd/x.json")
    u2 = Unit(uid="u2", file_rel="opd/x.json", loc="/visits/3", patient_bearing=True, psn="PSN-7Q2K9D")
    u3 = Unit(uid="u3", file_rel="opd/x.json", loc="/visits/1", patient_bearing=True, psn="PSN-1A2B3C")
    pf2.units = [u2, u3]

    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        write_records([pf1, pf2], out_dir)

        records_file = out_dir / "records.jsonl"
        assert records_file.exists()

        lines = [json.loads(line) for line in records_file.read_text(encoding="utf-8").splitlines() if line]
        assert len(lines) == 3

        # Must be sorted by (file, loc)
        assert lines[0] == {"file": "sanitized/notes/note.txt", "loc": "doc", "patient": None}
        assert lines[1] == {"file": "sanitized/opd/x.json", "loc": "/visits/1", "patient": "PSN-1A2B3C"}
        assert lines[2] == {"file": "sanitized/opd/x.json", "loc": "/visits/3", "patient": "PSN-7Q2K9D"}


def test_export_report_json():
    pf_ok = ParsedFile(rel="file1.csv", sha256="hash1", size=50, fmt="csv", status="sanitized", out_rel="sanitized/file1.csv")
    pf_err = ParsedFile(rel="file2.pdf", sha256="hash2", size=100, fmt="unsupported", status="quarantined", reason="unsupported_format")

    stats = RunStats(
        records_processed=10,
        identifiers_detected=5,
        records_linked=3,
        records_generalized=2,
        records_suppressed=0,
        records_quarantined=0,
        entities={"PHONE": 3, "PATIENT_NAME": 2},
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        write_report([pf_ok, pf_err], stats, out_dir, t0=1000.0)

        report_file = out_dir / "report.json"
        assert report_file.exists()

        report = json.loads(report_file.read_text(encoding="utf-8"))
        assert report["schema"] == "raksha-report/1"
        assert len(report["files"]) == 2
        assert report["counts"]["files_total"] == 2
        assert report["counts"]["files_sanitized"] == 1
        assert report["counts"]["files_quarantined"] == 1
        assert report["counts"]["records_processed"] == 10
        assert report["counts"]["identifiers_detected"] == 5
        assert report["counts"]["records_linked"] == 3
        assert report["counts"]["records_generalized"] == 2
        assert report["entities"] == {"PATIENT_NAME": 2, "PHONE": 3}
        assert "seconds" in report["timing"]
        assert "peak_rss_mb" in report["resources"]


def test_export_write_file_quarantine_on_failure():
    # Broken parsed file that raises during render
    pf = ParsedFile(rel="broken.csv", sha256="bad", size=10, fmt="csv", status="pending")
    # Missing header and rows or invalid structure causing render/write error
    def faulty_render(p, pol):
        raise ValueError("corrupt table")

    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        with patch("wardguard.export.writers.render", side_effect=ValueError("corrupt table")):
            write_file(pf, out_dir, {})

        assert pf.status == "quarantined"
        assert pf.reason == "malformed" or pf.reason == "ValueError"
        assert pf.out_rel is None
        # File must not be written to sanitized/
        assert not (out_dir / "sanitized" / "broken.csv").exists()
