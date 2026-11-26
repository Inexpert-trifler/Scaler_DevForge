"""Item 6: Sandbox fidelity, environment determinism, and containment checks.

Runs WardGuard under hostile / grader-like conditions without requiring root:
  1. Read-only input tree (chmod 0555/0444) + Merkle SHA-256 verification before & after.
  2. Read-only repo guard (PYTHONDONTWRITEBYTECODE=1 + snapshot of repo files).
  3. Fake unreachable proxies (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY) + stderr network scan.
  4. Private empty TMPDIR & HOME checked for zero leftover/temp files.
  5. Environment matrix determinism across PYTHONHASHSEED, TZ, and LANG/LC_ALL.
  6. Containment checks: symlink pointing outside input root (must not leak outside target),
     unreadable file (chmod 000, must not crash whole run), and no PII/secret in stderr.
  7. Reports optional Docker (--network none --cpus 2 --memory 4g) and Python 3.10-3.12
     availability cleanly when those runtimes are absent locally.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

from tools.torture.gen import Forge

REPO = Path(__file__).resolve().parents[2]
MAIN = REPO / "main.py"

NET_ERR_STRINGS = (
    "Temporary failure in name resolution",
    "Network is unreachable",
    "Max retries exceeded",
    "Name or service not known",
    "ConnectionRefused",
    "Connection refused",
)


def _tree_hashes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            out[p.relative_to(root).as_posix()] = f"symlink:{os.readlink(p)}"
        elif p.is_file():
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _chmod_tree(root: Path, readonly: bool) -> None:
    if os.geteuid() == 0:
        return
    for p in sorted(root.rglob("*"), reverse=True):
        if p.is_symlink():
            continue
        if p.is_dir():
            os.chmod(p, 0o555 if readonly else 0o755)
        elif p.is_file():
            os.chmod(p, 0o444 if readonly else 0o644)
    os.chmod(root, 0o555 if readonly else 0o755)


def _run_isolated(
    inp: Path,
    out: Path,
    secret: str,
    *,
    env_overrides: dict[str, str] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="wg_sbx_") as tmp_base_str:
        tmp_base = Path(tmp_base_str)
        sbx_tmp = tmp_base / "tmp"
        sbx_home = tmp_base / "home"
        sbx_tmp.mkdir()
        sbx_home.mkdir()

        env = os.environ.copy()
        env.update({
            "RAKSHA_SECRET": secret,
            "TMPDIR": str(sbx_tmp),
            "TEMP": str(sbx_tmp),
            "TMP": str(sbx_tmp),
            "HOME": str(sbx_home),
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        if env_overrides:
            env.update(env_overrides)

        t0 = time.monotonic()
        proc = subprocess.run(
            [sys.executable, str(MAIN), "--input", str(inp), "--output", str(out)],
            cwd=str(REPO),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        wall = round(time.monotonic() - t0, 3)

        tmp_leftovers = sorted(p.relative_to(sbx_tmp).as_posix() for p in sbx_tmp.rglob("*"))
        home_leftovers = sorted(p.relative_to(sbx_home).as_posix() for p in sbx_home.rglob("*"))
        combined = proc.stdout + "\n" + proc.stderr
        net_hits = [s for s in NET_ERR_STRINGS if s.lower() in combined.lower()]

        return {
            "returncode": proc.returncode,
            "wall_s": wall,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "tmp_leftovers": tmp_leftovers,
            "home_leftovers": home_leftovers,
            "net_hits": net_hits,
        }


def _release_digest(out: Path) -> dict[str, str]:
    dig: dict[str, str] = {}
    san = out / "sanitized"
    if san.exists():
        for p in sorted(san.rglob("*")):
            if p.is_file():
                dig[p.relative_to(out).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    rec = out / "records.jsonl"
    if rec.exists():
        dig["records.jsonl"] = hashlib.sha256(rec.read_bytes()).hexdigest()
    return dig


def check_sandbox(work: Path, seed: int = 1, n_patients: int = 10) -> dict[str, Any]:
    work = work.resolve()
    if work.exists():
        _chmod_tree(work, readonly=False) if (work / "input").exists() else None
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)

    fg = Forge(seed, n_patients)
    fg.build()
    fg.write(work)
    inp = work / "input"
    repo_before = _tree_hashes(REPO / "wardguard")
    input_before = _tree_hashes(inp)
    secret = "sbx_test_secret_!@#_unicode_परीक्षा"
    fails: list[dict[str, Any]] = []

    try:
        _chmod_tree(inp, readonly=True)

        # 1. Baseline isolated run with read-only input & fake proxy & empty TMPDIR/HOME
        out_base = work / "out_utc"
        res_base = _run_isolated(
            inp, out_base, secret,
            env_overrides={"PYTHONHASHSEED": "0", "TZ": "UTC", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        if res_base["returncode"] != 0:
            fails.append({"check": "baseline_exit", "sev": "S0", "detail": res_base["returncode"]})
        if res_base["tmp_leftovers"]:
            fails.append({"check": "tmpdir_not_empty", "sev": "S0", "detail": res_base["tmp_leftovers"]})
        if res_base["home_leftovers"]:
            fails.append({"check": "homedir_not_empty", "sev": "S0", "detail": res_base["home_leftovers"]})
        if res_base["net_hits"]:
            fails.append({"check": "network_attempt", "sev": "S0", "detail": res_base["net_hits"]})
        if secret in (out_base / "report.json").read_text(encoding="utf-8", errors="replace"):
            fails.append({"check": "secret_in_report", "sev": "S0"})
        if secret in res_base["stderr"]:
            fails.append({"check": "secret_in_stderr", "sev": "S0"})

        # Check canaries & patient names do not appear in stderr
        ans = json.loads((work / "answer.json").read_text(encoding="utf-8"))
        for c in ans.get("canaries", []):
            if c.lower() in res_base["stderr"].lower():
                fails.append({"check": "canary_in_stderr", "sev": "S0", "detail": c})

        # Input and repo must be completely unchanged
        if _tree_hashes(inp) != input_before:
            fails.append({"check": "input_modified", "sev": "S0"})
        if _tree_hashes(REPO / "wardguard") != repo_before:
            fails.append({"check": "repo_modified", "sev": "S0"})

        # 2. Environment determinism matrix: PYTHONHASHSEED, TZ, LANG
        base_digest = _release_digest(out_base)
        matrix = [
            ("hash1_kolkata", {"PYTHONHASHSEED": "1", "TZ": "Asia/Kolkata", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}),
            ("hash42_ny", {"PYTHONHASHSEED": "42", "TZ": "America/New_York", "LANG": "C", "LC_ALL": "C"}),
        ]
        for label, ov in matrix:
            out_m = work / f"out_{label}"
            res_m = _run_isolated(inp, out_m, secret, env_overrides=ov)
            if res_m["returncode"] != 0:
                fails.append({"check": f"matrix_exit_{label}", "sev": "S0", "detail": res_m["returncode"]})
                continue
            m_digest = _release_digest(out_m)
            if m_digest != base_digest:
                diffs = [k for k in sorted(set(base_digest) | set(m_digest)) if base_digest.get(k) != m_digest.get(k)]
                fails.append({"check": f"env_nondeterminism_{label}", "sev": "S0", "detail": diffs[:10]})
    finally:
        _chmod_tree(inp, readonly=False)

    # 3. Containment: symlink escape outside input root + unreadable (000) file
    hostile = work / "hostile_in"
    hostile.mkdir(parents=True, exist_ok=True)
    outside_secret = work / "OUTSIDE_SECRET_DO_NOT_READ.txt"
    outside_secret.write_text("TOP_SECRET_OUTSIDE_TOKEN_XYZ987", encoding="utf-8")
    (hostile / "ok.txt").write_text("Patient Name: Ramesh Gupta\nDiagnosis: Fever\n", encoding="utf-8")
    esc_link = hostile / "escape.txt"
    esc_link.symlink_to(outside_secret)
    unreadable = hostile / "locked.txt"
    unreadable.write_text("Patient Name: Secret Locked\n", encoding="utf-8")
    if os.geteuid() != 0:
        os.chmod(unreadable, 0o000)

    out_h = work / "out_hostile"
    try:
        res_h = _run_isolated(hostile, out_h, secret)
        if res_h["returncode"] != 0:
            fails.append({"check": "hostile_exit", "sev": "S0", "detail": res_h["returncode"]})
        else:
            for p in (out_h / "sanitized").rglob("*"):
                if p.is_file() and "TOP_SECRET_OUTSIDE_TOKEN_XYZ987" in p.read_text(encoding="utf-8", errors="replace"):
                    fails.append({"check": "symlink_escape_leaked", "sev": "S0", "detail": p.name})
            # Check output paths stay strictly under out_h
            for p in out_h.rglob("*"):
                if not p.resolve().is_relative_to(out_h.resolve()):
                    fails.append({"check": "output_path_escape", "sev": "S0", "detail": str(p)})
    finally:
        if os.geteuid() != 0 and unreadable.exists():
            os.chmod(unreadable, 0o644)

    # 4. Probe optional container / Python version availability (informational)
    docker_bin = shutil.which("docker")
    docker_status = "missing"
    if docker_bin:
        chk = subprocess.run([docker_bin, "info"], capture_output=True, text=True)
        docker_status = "running" if chk.returncode == 0 else "daemon_stopped"

    py_versions = {
        v: shutil.which(v) or "missing"
        for v in ("python3.10", "python3.11", "python3.12", "python3.13")
    }

    return {
        "seed": seed,
        "fails": fails,
        "wall_s": res_base.get("wall_s", 0.0),
        "docker": docker_status,
        "pythons": py_versions,
        "status": "SANDBOX OK" if not fails else "SANDBOX FAIL",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Run WardGuard sandbox fidelity suite (Item 6)")
    ap.add_argument("--work", type=Path, default=Path("/tmp/wg_sandbox"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--patients", type=int, default=10)
    a = ap.parse_args()
    res = check_sandbox(a.work, a.seed, a.patients)
    print(json.dumps(res, indent=2))
    print(res["status"])
    return 0 if not res["fails"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
