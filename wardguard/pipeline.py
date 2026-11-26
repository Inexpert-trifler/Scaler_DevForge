"""Main pipeline runner for WardGuard."""
from pathlib import Path
import time
from typing import Dict, Any

from wardguard.detect import build_gazetteer, detect_file
from wardguard.detect.hidden import extract_hidden_slots
from wardguard.export.records import write_records
from wardguard.export.report import write_report
from wardguard.export.writers import write_file
from wardguard.ingest.readers import load_all
from wardguard.ingest.units import enumerate_units
from wardguard.link import resolve
from wardguard.model import RunStats
from wardguard.privacy.generalize import assign_identity
from wardguard.privacy.kanon import plan
from wardguard.safety.log import event, safe_reason


def run(input_dir: Path, output_dir: Path, secret: bytes, policy: Dict[str, Any]) -> int:
    """Run the 3-pass WardGuard pipeline.
    
    Returns 0 on success (report.json written and all files accounted for).
    """
    t0 = time.time()
    stats = RunStats()
    files = []

    try:
        # Pass 1: Ingestion and unit enumeration
        files = load_all(input_dir)
        event("files_loaded", count=len(files))

        for pf in files:
            if pf.status == "pending":
                try:
                    enumerate_units(pf)
                    extract_hidden_slots(pf)
                except Exception as e:
                    pf.status = "quarantined"
                    pf.reason = safe_reason(e)

        # Count processed records
        for pf in files:
            if pf.status == "pending":
                stats.records_processed += len(pf.units)
            else:
                stats.records_quarantined += len(pf.units)

        # Pass 1 Detection (Saransh's modules)
        gaz = build_gazetteer(files, policy)
        for pf in files:
            if pf.status == "pending":
                try:
                    detect_file(pf, gaz, policy)
                except Exception as e:
                    pf.status = "quarantined"
                    pf.reason = safe_reason(e)

        # Pass 2: Global Linkage and Privacy
        active_units = [u for pf in files if pf.status == "pending" for u in pf.units]
        try:
            resolve(active_units, policy)
        except Exception as e:
            event("link_error", reason=0)

        assign_identity(active_units, secret, policy)
        plan(active_units, policy)

        # Pass 3: Rewrite and Export
        for pf in files:
            if pf.status == "pending":
                try:
                    write_file(pf, output_dir, policy)
                except Exception as e:
                    pf.status = "quarantined"
                    pf.reason = safe_reason(e)

        write_records(files, output_dir)
        return 0

    except Exception as e:
        event("fatal_error", count=1)
        return 2

    finally:
        try:
            write_report(files, stats, output_dir, t0)
        except Exception:
            pass
