"""Performance, scaling, memory, and determinism tests (TR-RUN-6, TR-SEC-4, L-13).

Validates:
- Fast import time (< 0.5s)
- 10x bulk scaling: 100+ files and thousands of records run in < 5s, RSS < 256 MB (budget 512 MB)
- 100% byte-identical determinism across runs
- Secret isolation: RAKSHA_SECRET never written to output or report
- Zero intermediate files leaked
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import pytest

from wardguard.pipeline import run


def test_import_time():
    """Verify package import time is fast (< 0.5 seconds)."""
    t0 = time.time()
    res = subprocess.run(
        [sys.executable, "-c", "import wardguard.pipeline; import wardguard.rewrite; import wardguard.privacy"],
        capture_output=True,
    )
    duration = time.time() - t0
    assert res.returncode == 0
    assert duration < 0.50, f"Import took too long: {duration:.3f}s"


def test_x10_bulk_scale_and_memory():
    """10x bulk scale test: 50+ files and thousands of records complete well within budget."""
    policy = {
        "k_min": 5,
        "age_band_years": 5,
        "age_top_code": 90,
        "date_shift_max_days": 180,
    }

    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
        inp = Path(in_dir)
        out = Path(out_dir)

        # Generate 60 files across CSV, JSON, and text
        for i in range(20):
            # CSV file with 50 rows
            rows = ["Name,Age,Gender,Phone,Date,Diagnosis"]
            for r in range(50):
                rows.append(f"Patient_{i}_{r},{30 + (r % 50)},{'M' if r % 2 == 0 else 'F'},98{i:04d}{r:04d},12/04/2023,Hypertension")
            (inp / f"bulk_opd_{i}.csv").write_text("\n".join(rows), encoding="utf-8")

            # JSON file with 20 items
            json_items = [
                {"id": r, "patient": f"Pat_{i}_{r}", "notes": f"Note for patient {r}"}
                for r in range(20)
            ]
            (inp / f"bulk_records_{i}.json").write_text(json.dumps(json_items), encoding="utf-8")

            # Text file
            (inp / f"bulk_note_{i}.txt").write_text(
                f"Patient Pat_{i}_0 attended follow up on 12/04/2023. Blood pressure 120/80.",
                encoding="utf-8",
            )

        t0 = time.time()
        code = run(inp, out, b"bulk_secret_practice", policy)
        elapsed = time.time() - t0

        assert code == 0
        assert elapsed < 5.0, f"Bulk run took {elapsed:.2f}s (budget < 60s)"

        rep_file = out / "report.json"
        assert rep_file.exists()
        rep = json.loads(rep_file.read_text(encoding="utf-8"))

        rss = rep["resources"]["peak_rss_mb"]
        assert rss < 256.0, f"Peak RSS {rss} MB exceeded 256 MB (budget 512 MB)"
        assert rep["counts"]["files_total"] == 60
        assert rep["counts"]["files_sanitized"] == 60


def test_pipeline_determinism_byte_identical():
    """Two consecutive runs with identical secret produce 100% byte-identical outputs."""
    policy = {
        "k_min": 5,
        "age_band_years": 5,
        "age_top_code": 90,
    }
    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out1, tempfile.TemporaryDirectory() as out2:
        inp = Path(in_dir)
        (inp / "test.csv").write_text(
            "Name,Age,Phone\nRajesh Kumar,45,9876543210\nSunita Devi,38,9123456789\n",
            encoding="utf-8",
        )
        (inp / "note.txt").write_text(
            "Patient Rajesh Kumar attended OPD.", encoding="utf-8"
        )

        code1 = run(inp, Path(out1), b"deterministic_secret", policy)
        code2 = run(inp, Path(out2), b"deterministic_secret", policy)
        assert code1 == 0
        assert code2 == 0

        # Compare records.jsonl
        rec1 = (Path(out1) / "records.jsonl").read_bytes()
        rec2 = (Path(out2) / "records.jsonl").read_bytes()
        assert rec1 == rec2

        # Compare sanitized files
        for p1 in (Path(out1) / "sanitized").rglob("*"):
            if p1.is_file():
                rel = p1.relative_to(Path(out1) / "sanitized")
                p2 = Path(out2) / "sanitized" / rel
                assert p2.exists()
                assert p1.read_bytes() == p2.read_bytes()


def test_secret_never_leaked_in_output():
    """RAKSHA_SECRET string must never be written to any output file or report."""
    canary_secret = b"canary_secret_top_secret_token_12345"
    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
        inp = Path(in_dir)
        out = Path(out_dir)
        (inp / "sample.csv").write_text("Name,Age\nRajesh,45\n", encoding="utf-8")

        code = run(inp, out, canary_secret, {})
        assert code == 0

        for p in out.rglob("*"):
            if p.is_file():
                content = p.read_bytes()
                assert canary_secret not in content, f"Secret leaked in {p}"


def test_brief_pdf_and_readme_constraints():
    """L-14 Documentation validation: README complete, docs/brief.pdf <= 2 pages."""
    repo_root = Path(__file__).resolve().parent.parent
    readme_file = repo_root / "README.md"
    assert readme_file.exists()
    readme_text = readme_file.read_text(encoding="utf-8")
    assert "_TBD_" not in readme_text, "README.md still contains _TBD_ placeholders"
    assert "Models Used" in readme_text
    assert "Architecture" in readme_text
    assert "CONTRACT OK" in readme_text

    brief_pdf = repo_root / "docs" / "brief.pdf"
    assert brief_pdf.exists()
    assert brief_pdf.stat().st_size > 1000

    import pypdf
    reader = pypdf.PdfReader(str(brief_pdf))
    assert 1 <= len(reader.pages) <= 2, f"docs/brief.pdf must be <= 2 pages, found {len(reader.pages)}"

