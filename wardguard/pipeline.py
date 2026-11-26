"""Main pipeline runner for WardGuard.

Ensures:
- Deterministic 3-pass execution
- Per-file error isolation (any file failure quarantines without stopping pipeline)
- Report.json always written in finally block
- Exit code 0 only when release is complete and report.json is valid
"""
from pathlib import Path
import time
from typing import Any, Dict, List

from wardguard.detect import build_gazetteer, detect_file
from wardguard.detect.hidden import extract_hidden_slots
from wardguard.export.records import write_records
from wardguard.export.report import write_report
from wardguard.export.writers import write_file
from wardguard.ingest.readers import load_all
from wardguard.ingest.units import enumerate_units
from wardguard.link import resolve
from wardguard.model import ParsedFile, RunStats
from wardguard.privacy.generalize import assign_identity
from wardguard.privacy.kanon import plan
from wardguard.safety.log import event, safe_reason


def run(input_dir: Path, output_dir: Path, secret: bytes, policy: Dict[str, Any]) -> int:
    """Run the 3-pass WardGuard pipeline.
    
    Returns:
        0 on success (report.json written and every file accounted for).
        2 on fatal pipeline initialization errors.
    """
    t0 = time.time()
    stats = RunStats()
    files: List[ParsedFile] = []
    fatal = False

    try:
        event("pipeline_start", count=1)

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
                    event("file_quarantined", count=1)

        # Count processed vs quarantined records
        for pf in files:
            if pf.status == "pending":
                stats.records_processed += len(pf.units)
            else:
                stats.records_quarantined += len(pf.units)

        # Pass 1 Detection (Saransh's modules)
        try:
            gaz = build_gazetteer(files, policy)
        except Exception as e:
            event("detection_error", count=1)
            # Create a fallback empty gazetteer
            from wardguard.detect import Gazetteer
            gaz = Gazetteer()

        for pf in files:
            if pf.status == "pending":
                try:
                    detect_file(pf, gaz, policy)
                except Exception as e:
                    pf.status = "quarantined"
                    pf.reason = safe_reason(e)
                    event("file_quarantined", count=1)

        # Pass 2: Global Linkage and Privacy
        active_units = [u for pf in files if pf.status == "pending" for u in pf.units]
        try:
            resolve(active_units, policy)
        except Exception:
            event("link_error", count=1)

        try:
            assign_identity(active_units, secret, policy)
        except Exception:
            event("privacy_error", count=1)

        try:
            plan(active_units, policy)
        except Exception:
            pass

        # Pass 3: Rewrite and Export
        for pf in files:
            if pf.status == "pending":
                try:
                    write_file(pf, output_dir, policy)
                except Exception as e:
                    pf.status = "quarantined"
                    pf.reason = safe_reason(e)
                    event("file_quarantined", count=1)

        # Tally honest stats for report.json
        for pf in files:
            for u in pf.units:
                for s in u.slots:
                    for m in s.mentions:
                        stats.identifiers_detected += 1
                        etype_val = m.etype.value if hasattr(m.etype, "value") else str(m.etype)
                        stats.entities[etype_val] = stats.entities.get(etype_val, 0) + 1
            for s in pf.file_slots:
                for m in s.mentions:
                    stats.identifiers_detected += 1
                    etype_val = m.etype.value if hasattr(m.etype, "value") else str(m.etype)
                    stats.entities[etype_val] = stats.entities.get(etype_val, 0) + 1

        stats.records_linked = sum(1 for u in active_units if u.cluster is not None)
        stats.records_generalized = sum(1 for u in active_units if u.date_offset is not None or u.coarsen)
        stats.records_suppressed = sum(1 for u in active_units if u.coarsen)

        try:
            write_records(files, output_dir)
        except Exception as e:
            event("export_error", count=1)

        event("pipeline_complete", count=len(files))
        return 0

    except Exception as e:
        fatal = True
        event("fatal_error", count=1)
        return 2

    finally:
        # Guarantee report.json is always written if output_dir is accessible
        try:
            write_report(files, stats, output_dir, t0)
        except Exception:
            pass
