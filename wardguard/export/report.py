"""report.json generator conforming to schema raksha-report/1.

Implements TR-EXP-3:
- Schema: raksha-report/1
- Files: every input by SHA-256, output path (or null), status, and generic reason token
- Honest counts: files_total, files_sanitized, files_quarantined, records_processed,
  identifiers_detected, records_linked, records_generalized, records_suppressed, records_quarantined
- Entities breakdown: EType counts
- Timing: seconds taken
- Resources: peak_rss_mb
- Deterministic output
"""
from __future__ import annotations
import json
from pathlib import Path
import resource
import time
from typing import List
from wardguard.model import ParsedFile, RunStats


def get_peak_rss_mb() -> float:
    """Get peak resident set size in megabytes."""
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # On macOS ru_maxrss is in bytes; on Linux in kilobytes
        import sys
        if sys.platform == "darwin":
            return round(usage.ru_maxrss / (1024 * 1024), 2)
        else:
            return round(usage.ru_maxrss / 1024, 2)
    except Exception:
        return 0.0


def write_report(
    files: List[ParsedFile],
    stats: RunStats,
    output_dir: Path,
    t0: float,
) -> None:
    """Write SPEC-compliant report.json."""
    duration = round(time.time() - t0, 3)
    peak_rss = get_peak_rss_mb()

    # Deterministic order for file entries: sort by sha256, then rel
    sorted_files = sorted(files, key=lambda f: (f.sha256, f.rel))

    file_entries = []
    sanitized_count = 0
    quarantined_count = 0

    for pf in sorted_files:
        if pf.status == "sanitized":
            sanitized_count += 1
            file_entries.append(
                {
                    "input_sha256": pf.sha256,
                    "output": pf.out_rel,
                    "status": "sanitized",
                    "reason": None,
                }
            )
        else:
            quarantined_count += 1
            file_entries.append(
                {
                    "input_sha256": pf.sha256,
                    "output": None,
                    "status": "quarantined",
                    "reason": pf.reason or "processing_error",
                }
            )

    # Sort entities deterministically by key
    sorted_entities = {k: v for k, v in sorted(stats.entities.items())}

    report_data = {
        "schema": "raksha-report/1",
        "files": file_entries,
        "counts": {
            "files_total": len(files),
            "files_sanitized": sanitized_count,
            "files_quarantined": quarantined_count,
            "records_processed": stats.records_processed,
            "identifiers_detected": stats.identifiers_detected,
            "records_linked": stats.records_linked,
            "records_generalized": stats.records_generalized,
            "records_suppressed": stats.records_suppressed,
            "records_quarantined": stats.records_quarantined,
        },
        "entities": sorted_entities,
        "timing": {
            "seconds": duration,
        },
        "resources": {
            "peak_rss_mb": peak_rss,
        },
    }

    out_path = output_dir / "report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
        f.write("\n")
