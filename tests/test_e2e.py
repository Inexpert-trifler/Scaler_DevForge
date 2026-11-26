import json
from pathlib import Path
import tempfile
from wardguard.pipeline import run


def test_pipeline_e2e_basic():
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

        # Create sample files
        (inp / "test.csv").write_text("name,age,notes\nRajesh,45,stable\n", encoding="utf-8")
        (inp / "note.txt").write_text("Patient visited OPD today.", encoding="utf-8")

        code = run(inp, out, b"secret123", policy)
        assert code == 0

        # Check outputs
        assert (out / "report.json").exists()
        assert (out / "records.jsonl").exists()
        assert (out / "sanitized" / "test.csv").exists()
        assert (out / "sanitized" / "note.txt").exists()

        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert report["schema"] == "raksha-report/1"
        assert report["counts"]["files_total"] == 2
        assert report["counts"]["files_sanitized"] == 2
