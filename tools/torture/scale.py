"""Scale and performance benchmark harness for WardGuard (Section 6 Item 1).

Tests the 5 scale/adversarial workloads against the real CLI in a private sandbox:
  1. --patients 400 (~1,947 files)
  2. 200k-row CSV
  3. 50 MB single-line text file
  4. 1,500-deep JSON (sanitized) + 10,000-deep JSON (safely quarantined or sanitized)
  5. Repeated 'S/o S/o S/o ...' regex backtracking stress

Budgets:
  - Standard profile (p400): good <= 60s, limit 900s, RSS <= 512 MB good / 4 GB limit
  - Extreme single workloads: <= 60s good / 900s limit, RSS <= 4 GB limit

Usage: python -m tools.torture.scale --work /tmp/wg_scale
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.torture.check import run_cli  # noqa: E402
from tools.torture.gen import generate  # noqa: E402


def bench_p400(work: Path) -> dict:
    ds = work / "p400"
    if ds.exists():
        shutil.rmtree(ds)
    generate(1, ds, 400)
    n_files = sum(1 for p in (ds / "input").rglob("*") if p.is_file())
    r = run_cli(ds / "input", ds / "out", "scale-secret", ds / "sbx")
    rep = json.loads((ds / "out" / "report.json").read_text(encoding="utf-8"))
    rss = rep.get("resources", {}).get("peak_rss_mb", 0.0)
    ok = (r["code"] == 0 and r["secs"] <= 60.0 and rss <= 512.0 and rep["counts"]["files_total"] == n_files)
    return {"name": "p400", "files": n_files, "secs": round(r["secs"], 2), "rss_mb": rss, "ok": ok}


def bench_200k_csv(work: Path) -> dict:
    ds = work / "csv200k"
    if ds.exists():
        shutil.rmtree(ds)
    (ds / "input").mkdir(parents=True)
    hdr = "Patient Name,Age,Sex,Mobile No,District,Diagnosis,Admission Date\n"
    buf = io.StringIO()
    buf.write(hdr)
    for i in range(200_000):
        buf.write(f"Aarav Sharma {i},45,M,9876543210,Ayodhya,Essential hypertension (I10),12/04/2026\n")
    (ds / "input" / "big_200k.csv").write_text(buf.getvalue(), encoding="utf-8")
    r = run_cli(ds / "input", ds / "out", "scale-secret", ds / "sbx")
    rep = json.loads((ds / "out" / "report.json").read_text(encoding="utf-8"))
    rss = rep.get("resources", {}).get("peak_rss_mb", 0.0)
    out_csv = ds / "out" / "sanitized" / "big_200k.csv"
    out_text = out_csv.read_text(encoding="utf-8") if out_csv.exists() else ""
    leaked = ("Aarav Sharma" in out_text) or ("9876543210" in out_text)
    n_rows = out_text.count("\n") - 1 if out_text else 0
    ok = (r["code"] == 0 and r["secs"] <= 60.0 and rss <= 4096.0 and not leaked and n_rows == 200_000)
    return {"name": "csv_200k", "rows": n_rows, "secs": round(r["secs"], 2), "rss_mb": rss, "leaked": leaked, "ok": ok}


def bench_50mb_line(work: Path) -> dict:
    ds = work / "line50mb"
    if ds.exists():
        shutil.rmtree(ds)
    (ds / "input").mkdir(parents=True)
    chunk = "Normal clinical observation BP 120/80 mmHg stable. " * 1_000_000  # ~51 MB single line
    payload = "Patient Name: Sunita Yadav Mobile: 9876543210. " + chunk + " Attendant: Ramesh Kumar Ph. 9123456789."
    (ds / "input" / "huge_line.txt").write_text(payload, encoding="utf-8")
    r = run_cli(ds / "input", ds / "out", "scale-secret", ds / "sbx")
    rep = json.loads((ds / "out" / "report.json").read_text(encoding="utf-8"))
    rss = rep.get("resources", {}).get("peak_rss_mb", 0.0)
    out_txt = (ds / "out" / "sanitized" / "huge_line.txt").read_text(encoding="utf-8")
    leaked = any(s in out_txt for s in ("Sunita Yadav", "9876543210", "9123456789"))
    ok = (r["code"] == 0 and r["secs"] <= 60.0 and rss <= 512.0 and not leaked)
    return {"name": "line_50mb", "secs": round(r["secs"], 2), "rss_mb": rss, "leaked": leaked, "ok": ok}


def bench_deep_json(work: Path) -> dict:
    ds = work / "deep_json"
    if ds.exists():
        shutil.rmtree(ds)
    (ds / "input").mkdir(parents=True)
    (ds / "input" / "deep1500.json").write_text('{"a":' * 1500 + '{"patient":{"name":"Sunita Yadav"}}' + "}" * 1500)
    (ds / "input" / "deep10k.json").write_text('{"a":' * 10000 + '{"patient":{"name":"Sunita Yadav"}}' + "}" * 10000)
    r = run_cli(ds / "input", ds / "out", "scale-secret", ds / "sbx")
    rep = json.loads((ds / "out" / "report.json").read_text(encoding="utf-8"))
    rss = rep.get("resources", {}).get("peak_rss_mb", 0.0)
    d15_out = (ds / "out" / "sanitized" / "deep1500.json")
    d15_ok = d15_out.exists() and ("Sunita" not in d15_out.read_text(encoding="utf-8"))
    statuses = {f["status"]: f["reason"] for f in rep["files"]}
    ok = (r["code"] == 0 and r["secs"] <= 10.0 and len(rep["files"]) == 2 and d15_ok)
    return {"name": "deep_json", "secs": round(r["secs"], 2), "rss_mb": rss, "statuses": statuses, "d1500_ok": d15_ok, "ok": ok}


def bench_backtrack(work: Path) -> dict:
    ds = work / "backtrack"
    if ds.exists():
        shutil.rmtree(ds)
    (ds / "input").mkdir(parents=True)
    txt = (
        "S/o " * 50_000
        + "late " * 20_000
        + "Patient Name: Kavita Chauhan Mobile: 9876543210.\n"
        + "Address: near " * 5_000
        + "Mohalla Gandhi Nagar, Ayodhya.\n"
    )
    (ds / "input" / "backtrack.txt").write_text(txt, encoding="utf-8")
    r = run_cli(ds / "input", ds / "out", "scale-secret", ds / "sbx")
    rep = json.loads((ds / "out" / "report.json").read_text(encoding="utf-8"))
    out_txt = (ds / "out" / "sanitized" / "backtrack.txt").read_text(encoding="utf-8")
    leaked = any(s in out_txt for s in ("Kavita Chauhan", "9876543210", "Gandhi Nagar"))
    ok = (r["code"] == 0 and r["secs"] <= 10.0 and not leaked)
    return {"name": "backtrack_so", "secs": round(r["secs"], 2), "rss_mb": rep.get("resources", {}).get("peak_rss_mb", 0.0), "leaked": leaked, "ok": ok}


def main() -> int:
    ap = argparse.ArgumentParser(description="WardGuard scale & performance benchmark")
    ap.add_argument("--work", type=Path, required=True)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    results = []
    for fn in (bench_p400, bench_deep_json, bench_backtrack, bench_50mb_line, bench_200k_csv):
        res = fn(a.work)
        results.append(res)
        print(json.dumps(res), flush=True)
    all_ok = all(r["ok"] for r in results)
    print("SCALE", "OK" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
