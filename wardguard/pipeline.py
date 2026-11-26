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
from wardguard.detect.hidden import extract_hidden_slots, apply_filename_renaming
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
    pipeline_errors: Dict[str, int] = {}

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
                    if pf.units:
                        pf.rows = None
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
            # 1a. Initial pass to classify structured columns across tabular files
            empty_gaz = build_gazetteer([], policy)
            for pf in files:
                if pf.status == "pending":
                    try:
                        detect_file(pf, empty_gaz, policy)
                    except Exception as e:
                        pf.status = "quarantined"
                        pf.reason = safe_reason(e)
                        event("file_quarantined", count=1)

            # 1b. Harvest dynamic gazetteer from now-classified structured name columns (TR-DET-5)
            gaz = build_gazetteer(files, policy)
            # in-memory only: lets the export safety nets (embedded base64, unit-less text)
            # recognise names harvested from the rest of the dataset
            policy = {**policy, "_gazetteer": gaz}

            # 1c. Full pass to scan free-text and hidden slots using the harvested gazetteer
            if not getattr(gaz, "is_empty", False):
                for pf in files:
                    if pf.status == "pending":
                        try:
                            detect_file(pf, gaz, policy, gaz_only=True)
                        except Exception as e:
                            pf.status = "quarantined"
                            pf.reason = safe_reason(e)
                            event("file_quarantined", count=1)
        except Exception as e:
            pipeline_errors["detection"] = pipeline_errors.get("detection", 0) + 1
            event("detection_error", count=1)
            from wardguard.detect import Gazetteer
            gaz = Gazetteer()

        # Apply filename renaming for files whose @filename contains PII mentions (TR-EXP-2)
        try:
            apply_filename_renaming(files, policy)
        except Exception as e:
            pipeline_errors["filename_renaming"] = pipeline_errors.get("filename_renaming", 0) + 1
            event("filename_rename_error", count=1)
            # Fail closed: neutral deterministic fallback name or quarantine
            for pf in files:
                if pf.status == "pending":
                    p = Path(pf.rel)
                    has_pii = any(m for s in pf.file_slots if s.path == "@filename" for m in s.mentions)
                    if has_pii:
                        # Fallback to neutral hash name: file_<sha8>.<ext>
                        pf.out_rel = f"sanitized/{p.parent.as_posix()}/file_{pf.sha256[:8]}{p.suffix}".replace("/./", "/")

        # Pass 2: Global Linkage and Privacy
        active_units = [u for pf in files if pf.status == "pending" for u in pf.units]

        # 2a. Resolve identity linkage
        try:
            resolve(active_units, policy)
        except Exception as e:
            pipeline_errors["resolve"] = pipeline_errors.get("resolve", 0) + 1
            event("link_error", count=1)
            # Fail closed: all units unlinked (cluster = None, patient = null)
            for u in active_units:
                u.cluster = None

        # 2b. Assign identity (pseudonyms + date shifting)
        try:
            assign_identity(active_units, secret, policy)
        except Exception as e:
            pipeline_errors["assign_identity"] = pipeline_errors.get("assign_identity", 0) + 1
            event("privacy_error", count=1)
            # Fail closed: dates and ages cannot be protected; quarantine all pending files
            for pf in files:
                if pf.status == "pending":
                    pf.status = "quarantined"
                    pf.reason = "privacy_error"
                    event("file_quarantined", count=1)
            active_units = []

        # 2c. Plan targeted k-anonymity
        if active_units:
            try:
                plan(active_units, policy)
            except Exception as e:
                pipeline_errors["plan"] = pipeline_errors.get("plan", 0) + 1
                event("kanon_error", count=1)
                # Fail closed: maximum generalization on all units
                for u in active_units:
                    u.coarsen = True

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
            pipeline_errors["write_records"] = pipeline_errors.get("write_records", 0) + 1
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
            write_report(files, stats, output_dir, t0, pipeline_errors=pipeline_errors)
        except Exception:
            pass
