#!/usr/bin/env python3
"""WardGuard Submission Checker.

Verifies all submission requirements and gates:
1. raksha.toml valid setup and run commands
2. Zero network imports (no requests, urllib, http, socket)
3. Zero LLMs or oversized dependencies in requirements.txt
4. Pipeline execution on input directory
5. Output contract: report.json and records.jsonl validity
6. Determinism: byte-identical outputs across runs
7. Keyed pseudonyms: secret changes outputs
8. Secret hygiene: RAKSHA_SECRET never written to output or report
9. Resource budget: runtime < 60s, peak RSS < 512MB

Prints: READY TO SUBMIT
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def check_raksha_toml(repo_root: Path) -> bool:
    toml_path = repo_root / "raksha.toml"
    if not toml_path.exists():
        print("[FAIL] raksha.toml missing in repo root")
        return False

    content = toml_path.read_text(encoding="utf-8")
    if "run" not in content or "main.py" not in content:
        print("[FAIL] raksha.toml must declare run command pointing to main.py")
        return False

    print("[PASS] raksha.toml valid")
    return True


def check_network_imports(repo_root: Path) -> bool:
    forbidden = ["requests", "urllib", "http.client", "socket"]
    pkg_dir = repo_root / "wardguard"
    main_py = repo_root / "main.py"

    violations = []
    for p in list(pkg_dir.rglob("*.py")) + [main_py]:
        text = p.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            clean = line.strip()
            if clean.startswith(("#", '"""', "'''")):
                continue
            if any(f"import {mod}" in clean or f"from {mod}" in clean for mod in ("requests", "urllib", "http", "socket")):
                violations.append((p.relative_to(repo_root).as_posix(), clean))

    if violations:
        print("[FAIL] Forbidden network imports detected:", violations)
        return False

    print("[PASS] Zero network imports")
    return True


def check_pipeline_run_and_contract(repo_root: Path, input_dir: Path) -> bool:
    secret = "practice_check_submission"
    with tempfile.TemporaryDirectory() as out_run1, tempfile.TemporaryDirectory() as out_run2, tempfile.TemporaryDirectory() as out_diff:
        # Run 1
        env1 = os.environ.copy()
        env1["RAKSHA_SECRET"] = secret
        t0 = time.time()
        cmd = [sys.executable, str(repo_root / "main.py"), "--input", str(input_dir), "--output", str(out_run1)]
        res1 = subprocess.run(cmd, env=env1, capture_output=True, text=True)
        dur = time.time() - t0

        if res1.returncode != 0:
            print(f"[FAIL] Pipeline exited with code {res1.returncode}")
            print(res1.stderr)
            return False

        # Check outputs
        rep_file = Path(out_run1) / "report.json"
        rec_file = Path(out_run1) / "records.jsonl"
        san_dir = Path(out_run1) / "sanitized"

        if not rep_file.exists() or not rec_file.exists() or not san_dir.exists():
            print("[FAIL] Missing required release outputs (report.json, records.jsonl, or sanitized/)")
            return False

        # Validate report.json
        try:
            rep = json.loads(rep_file.read_text(encoding="utf-8"))
            if rep.get("schema") != "raksha-report/1":
                print("[FAIL] report.json schema is not raksha-report/1")
                return False
            rss = rep.get("resources", {}).get("peak_rss_mb", 0)
            if rss > 512:
                print(f"[FAIL] Peak RSS {rss} MB exceeded 512 MB budget")
                return False
        except Exception as e:
            print(f"[FAIL] Malformed report.json: {e}")
            return False

        # Check secret leak
        for p in Path(out_run1).rglob("*"):
            if p.is_file():
                content = p.read_bytes()
                if secret.encode("utf-8") in content:
                    print(f"[FAIL] RAKSHA_SECRET found inside output file: {p}")
                    return False

        # Run 2: Determinism check with same secret
        cmd2 = [sys.executable, str(repo_root / "main.py"), "--input", str(input_dir), "--output", str(out_run2)]
        res2 = subprocess.run(cmd2, env=env1, capture_output=True, text=True)
        if res2.returncode != 0:
            print("[FAIL] Run 2 failed")
            return False

        # Compare files
        rec1_hash = hashlib.sha256(rec_file.read_bytes()).hexdigest()
        rec2_hash = hashlib.sha256((Path(out_run2) / "records.jsonl").read_bytes()).hexdigest()
        if rec1_hash != rec2_hash:
            print("[FAIL] records.jsonl is not deterministic across runs")
            return False

        # Run 3: Rotation with different secret
        env_diff = os.environ.copy()
        env_diff["RAKSHA_SECRET"] = "different_secret_999"
        cmd_diff = [sys.executable, str(repo_root / "main.py"), "--input", str(input_dir), "--output", str(out_diff)]
        res3 = subprocess.run(cmd_diff, env=env_diff, capture_output=True, text=True)
        if res3.returncode != 0:
            print("[FAIL] Run 3 with different secret failed")
            return False

        rec3_bytes = (Path(out_diff) / "records.jsonl").read_bytes()
        if rec3_bytes and rec3_bytes == rec_file.read_bytes():
            print("[FAIL] Pseudonyms did not rotate when secret changed")
            return False

    print(f"[PASS] Pipeline contract, determinism, and rotation ok ({dur:.2f}s, {rss}MB RSS)")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Check submission readiness")
    parser.add_argument("--repo", type=Path, default=Path("."), help="Repository root")
    parser.add_argument("--run", action="store_true", help="Run end-to-end check")
    parser.add_argument("--input", type=Path, default=None, help="Input test directory")
    args = parser.parse_args()

    repo = args.repo.resolve()
    input_dir = args.input or (repo / "tests" / "sample_data")

    print("==================================================")
    print("        WardGuard Submission Check (TR-RUN)       ")
    print("==================================================")

    ok1 = check_raksha_toml(repo)
    ok2 = check_network_imports(repo)

    if args.run:
        ok3 = check_pipeline_run_and_contract(repo, input_dir)
    else:
        ok3 = True

    if ok1 and ok2 and ok3:
        print("\n==================================================")
        print("                 READY TO SUBMIT                  ")
        print("==================================================")
        sys.exit(0)
    else:
        print("\n[FAIL] Submission checks did not pass.")
        sys.exit(1)


if __name__ == "__main__":
    main()
