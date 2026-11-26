"""records.jsonl writer.

Implements TR-EXP-4:
- One line per patient-bearing unit of a WRITTEN file.
- loc = input locator, patient = PSN or null.
- Sorted deterministically by (file, loc).
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import List
from wardguard.model import ParsedFile


def write_records(files: List[ParsedFile], output_dir: Path) -> None:
    """Write records.jsonl mapping patient-bearing unit to pseudonym or null."""
    records = []
    for pf in files:
        if pf.status != "sanitized" or not pf.out_rel:
            continue
        for u in pf.units:
            if u.patient_bearing or u.psn is not None:
                records.append(
                    {
                        "file": pf.out_rel,
                        "loc": u.loc,
                        "patient": u.psn,
                    }
                )

    # Sort deterministically by (file, loc)
    records.sort(key=lambda r: (r["file"], r["loc"]))
    out_path = output_dir / "records.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
