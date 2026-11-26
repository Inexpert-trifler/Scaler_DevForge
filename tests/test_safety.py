import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import pytest

from wardguard.pipeline import run
from wardguard.safety.log import event, safe_reason


def test_safe_reason_never_leaks_message():
    err1 = ValueError("/secret/path/to/patient_data.csv: invalid patient Aadhaar 1234")
    assert safe_reason(err1) == "ValueError"

    err2 = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
    assert safe_reason(err2) == "undecodable"

    err3 = RecursionError("maximum recursion depth exceeded while parsing")
    assert safe_reason(err3) == "resource_limit"


def test_counts_only_logging(capsys):
    event("files_loaded", count=5, files=10)
    out, err = capsys.readouterr()
    assert "[EVENT] files_loaded count=5 files=10" in err
    assert "patient" not in err


def test_pipeline_crash_isolation_quarantine(capsys):
    """Inject a file that raises an unhandled exception during unit enumeration.
    
    The pipeline must:
    1. Still exit 0.
    2. Quarantine the faulty file with safe reason.
    3. Successfully sanitize the valid file.
    4. Write report.json and records.jsonl.
    5. Contain no PII or file contents in stderr.
    """
    policy = {
        "psn_prefix": "PSN-",
        "date_shift_max_days": 180,
        "age_band_years": 5,
        "age_top_code": 90,
        "pin_keep_digits": 3,
    }
    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
        inp = Path(in_dir)
        out = Path(out_dir)

        # Create two files: valid one and faulty one
        (inp / "good.txt").write_text("Patient visited OPD.", encoding="utf-8")
        (inp / "faulty.csv").write_text("col1,col2\nval1,val2\n", encoding="utf-8")

        # Mock enumerate_units to raise on faulty.csv
        from wardguard.ingest import units as ingest_units
        orig_enum = ingest_units.enumerate_units

        def buggy_enumerate(pf):
            if "faulty" in pf.rel:
                raise RuntimeError("Simulated crash on /secret/patient/record")
            orig_enum(pf)

        with patch("wardguard.pipeline.enumerate_units", side_effect=buggy_enumerate):
            code = run(inp, out, b"secret123", policy)

        assert code == 0

        # Verify report.json
        report_file = out / "report.json"
        assert report_file.exists()
        report = json.loads(report_file.read_text(encoding="utf-8"))
        assert report["counts"]["files_total"] == 2
        assert report["counts"]["files_sanitized"] == 1
        assert report["counts"]["files_quarantined"] == 1

        # Check file statuses in report
        statuses = {f["status"]: f["reason"] for f in report["files"]}
        assert "sanitized" in statuses
        assert statuses["quarantined"] == "RuntimeError"

        # Stderr must not contain sensitive details
        captured = capsys.readouterr()
        assert "Simulated crash" not in captured.err
        assert "patient" not in captured.err


def test_pipeline_fail_closed_privacy_steps():
    """Bug D tests: monkeypatch resolve, assign_identity, plan, apply_filename_renaming."""
    policy = {
        "psn_prefix": "PSN-",
        "date_shift_max_days": 180,
        "age_band_years": 5,
        "age_top_code": 90,
    }

    # 1. resolve fails -> continue with unlinked records (patient null), count it
    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
        inp = Path(in_dir)
        out = Path(out_dir)
        (inp / "rec.csv").write_text("Name,Age\nRajesh,45\n", encoding="utf-8")

        with patch("wardguard.pipeline.resolve", side_effect=RuntimeError("Linkage crash")):
            code = run(inp, out, b"secret123", policy)
            assert code == 0

        rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert rep["pipeline_errors"].get("resolve") == 1
        assert rep["counts"]["files_sanitized"] == 1

    # 2. assign_identity fails -> dates/ages cannot be protected: quarantine all pending files
    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
        inp = Path(in_dir)
        out = Path(out_dir)
        (inp / "rec.csv").write_text("Name,Date\nRajesh,12/04/2023\n", encoding="utf-8")

        with patch("wardguard.pipeline.assign_identity", side_effect=RuntimeError("Privacy crash")):
            code = run(inp, out, b"secret123", policy)
            assert code == 0

        rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert rep["pipeline_errors"].get("assign_identity") == 1
        assert rep["counts"]["files_sanitized"] == 0
        assert rep["counts"]["files_quarantined"] == 1
        # No unshifted/unredacted data written to sanitized/
        assert not (out / "sanitized" / "rec.csv").exists()

    # 3. plan (k-anonymity) fails -> set coarsen=True on all active units
    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
        inp = Path(in_dir)
        out = Path(out_dir)
        (inp / "rec.csv").write_text("Name,Age,Village\nRajesh,45,Kalyanpur\n", encoding="utf-8")

        with patch("wardguard.pipeline.plan", side_effect=RuntimeError("Plan crash")):
            code = run(inp, out, b"secret123", policy)
            assert code == 0

        rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert rep["pipeline_errors"].get("plan") == 1
        assert rep["counts"]["files_sanitized"] == 1
        assert rep["counts"]["records_suppressed"] >= 1

    # 4. apply_filename_renaming fails -> neutral hash fallback
    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
        inp = Path(in_dir)
        out = Path(out_dir)
        (inp / "9876543210_report.csv").write_text("Age,Diagnosis\n45,Hypertension\n", encoding="utf-8")

        with patch("wardguard.pipeline.apply_filename_renaming", side_effect=RuntimeError("Rename crash")):
            code = run(inp, out, b"secret123", policy)
            assert code == 0

        rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert rep["pipeline_errors"].get("filename_renaming") == 1
        # PII filename should NOT exist in sanitized/
        assert not (out / "sanitized" / "9876543210_report.csv").exists()

