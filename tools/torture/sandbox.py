"""Unified OpenEnv / Docker Sandbox, Determinism Matrix, Containment & Security Suite (§6.1 & §6.10).

Wires our external OpenEnv/TestLab sandbox runner (`../wardguard-testlab/sandbox`) when present
(with a self-contained fallback when run standalone) into `tools/torture/` so one command tests:
  1. Host OS sandbox isolation: read-only input tree (chmod 0555/0444) + Merkle SHA-256 verification
     before & after, read-only repo guard, fake unreachable proxies (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY),
     zero TMPDIR/HOME leftovers, network-attempt stderr scan, secret/canary absence.
  2. Docker / OpenEnv containerized isolation (`--network none --cpus 2 --memory 4g --memory-swap 4g
     --pids-limit 512 --ulimit core=0 --ulimit fsize=2147483648`, `:ro` repo & `:ro` input mounts)
     across all available Python 3.10 / 3.11 / 3.12 images, checking identical output digests
     between host and every container Python version.
  3. Environment determinism matrix (`PYTHONHASHSEED`, `TZ`, `LANG`/`LC_ALL`) on host & Docker.
  4. Hostile containment (on host & inside Docker): external symlink (e.g. `/etc/passwd` & host secret),
     unreadable file (`chmod 000`), path-traversal filename (`..%2f..%2fevil.txt`) and JSON `source_file`.
  5. Security & hygiene suite (SEC-01..SEC-08): static AST scan of `wardguard/` & `main.py` for zero
     network/LLM imports, unusual secrets (`1-char`, spaces, 1 KB unicode), and CLI edge cases.

Also provides `--run` mode to execute WardGuard inside the OpenEnv Docker sandbox on any dataset.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Optional

from tools.torture.gen import Forge

REPO = Path(__file__).resolve().parents[2]
MAIN = REPO / "main.py"
TESTLAB_SANDBOX_DIR = REPO.parent / "wardguard-testlab" / "sandbox"

NET_ERR_STRINGS = (
    "Temporary failure in name resolution",
    "Network is unreachable",
    "Max retries exceeded",
    "Name or service not known",
    "ConnectionRefused",
    "Connection refused",
    "getaddrinfo failed",
)

BANNED_RUNTIME_ROOTS = {
    # Networking stdlib & libraries
    "socket", "urllib", "http", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "ssl",
    "requests", "httpx", "aiohttp", "urllib3", "websocket", "websockets", "grpc",
    # Hosted / large LLM SDKs
    "openai", "anthropic", "transformers", "torch", "langchain", "vllm", "ollama",
    "llama_cpp", "cohere", "groq", "together", "litellm", "google.generativeai", "google.genai",
}


def _load_testlab_runner():
    runner_py = TESTLAB_SANDBOX_DIR / "runner.py"
    if not runner_py.is_file():
        return None
    spec = importlib.util.spec_from_file_location("wardguard_testlab_sandbox_runner", runner_py)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree_hashes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            try:
                out[p.relative_to(root).as_posix()] = f"symlink:{os.readlink(p)}"
            except OSError:
                out[p.relative_to(root).as_posix()] = "symlink:unreadable"
        elif p.is_file():
            try:
                out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                out[p.relative_to(root).as_posix()] = "unreadable"
    return out


def _chmod_tree(root: Path, readonly: bool) -> None:
    if os.geteuid() == 0 or not root.exists():
        return
    for p in sorted(root.rglob("*"), reverse=True):
        if p.is_symlink():
            continue
        try:
            if p.is_dir():
                os.chmod(p, 0o555 if readonly else 0o755)
            elif p.is_file():
                os.chmod(p, 0o444 if readonly else 0o644)
        except OSError:
            pass
    try:
        os.chmod(root, 0o555 if readonly else 0o755)
    except OSError:
        pass


def _ru_maxrss_mb(ru_maxrss: int) -> float:
    if sys.platform == "darwin":
        return ru_maxrss / (1024.0 * 1024.0)
    return ru_maxrss / 1024.0


def _docker_available() -> str:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return "missing"
    chk = subprocess.run([docker_bin, "info"], capture_output=True, text=True)
    return "running" if chk.returncode == 0 else "daemon_stopped"


def ensure_openenv_images(versions: tuple[str, ...] = ("3.10", "3.11", "3.12")) -> dict[str, Optional[str]]:
    """Build or resolve versioned Docker OpenEnv images via testlab runner or inline Dockerfile."""
    mod = _load_testlab_runner()
    if mod is not None and hasattr(mod, "ensure_docker_images"):
        return mod.ensure_docker_images(REPO, versions)

    docker_bin = shutil.which("docker")
    if not docker_bin or _docker_available() != "running":
        return {v: None for v in versions}

    req = REPO / "requirements.txt"
    req_bytes = req.read_bytes() if req.exists() else b""
    req_hash = hashlib.sha256(req_bytes).hexdigest()[:10]
    out: dict[str, Optional[str]] = {}
    for ver in versions:
        tag = f"wardguard-sbx:py{ver.replace('.', '')}-{req_hash}"
        if subprocess.run([docker_bin, "image", "inspect", tag], capture_output=True).returncode == 0:
            out[ver] = tag
            continue
        with tempfile.TemporaryDirectory(prefix=f"wg_sbx_build_{ver}_") as ctx_str:
            ctx = Path(ctx_str)
            (ctx / "requirements-sub.txt").write_bytes(req_bytes)
            (ctx / "Dockerfile").write_text(
                f"FROM python:{ver}-slim\n"
                "ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PYTHONUNBUFFERED=1\n"
                "RUN useradd -m -u 1000 sub\n"
                "COPY requirements-sub.txt /tmp/req.txt\n"
                "RUN python -m venv /sub-venv && /sub-venv/bin/pip install -r /tmp/req.txt\n"
                "USER sub\nWORKDIR /sub\n",
                encoding="utf-8",
            )
            res = subprocess.run([docker_bin, "build", "-t", tag, "."], cwd=str(ctx), capture_output=True, text=True)
            out[ver] = tag if res.returncode == 0 else None
    return out


def run_openenv(
    inp: Path,
    out: Path,
    secret: str,
    *,
    mode: str = "auto",
    py_version: str = "3.12",
    docker_image: Optional[str] = None,
    meta_dir: Optional[Path] = None,
    env_overrides: Optional[dict[str, str]] = None,
    timeout: int = 900,
    mem_limit_mb: int = 4096,
    readonly_input: bool = False,
) -> dict[str, Any]:
    """Unified execution runner supporting Docker OpenEnv (`--network none`) and host subprocess."""
    inp = inp.resolve()
    out = out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    meta_out = meta_dir.resolve() if meta_dir else (out.parent / f"{out.name}.meta")
    meta_out.mkdir(parents=True, exist_ok=True)

    resolved_mode = mode
    if resolved_mode == "auto":
        if _docker_available() == "running":
            if not docker_image:
                docker_image = ensure_openenv_images((py_version,)).get(py_version)
            resolved_mode = "docker" if docker_image else "subprocess"
        else:
            resolved_mode = "subprocess"

    if resolved_mode == "docker":
        if not docker_image:
            docker_image = ensure_openenv_images((py_version,)).get(py_version)
        if not docker_image:
            raise RuntimeError(f"Docker image unavailable for Python {py_version}")

        mod = _load_testlab_runner()
        if mod is not None and hasattr(mod, "run_isolated"):
            res = mod.run_isolated(
                product_dir=REPO,
                python_bin=Path(sys.executable),
                input_dir=inp,
                output_dir=out,
                secret=secret,
                timeout_sec=timeout,
                memory_limit_mb=mem_limit_mb,
                mode="docker",
                docker_image=docker_image,
                meta_dir=meta_out,
                env_overrides=env_overrides,
                readonly_input=readonly_input,
            )
            stdout = (meta_out / "stdout.txt").read_text(encoding="utf-8", errors="replace") if (meta_out / "stdout.txt").exists() else ""
            stderr = (meta_out / "stderr.txt").read_text(encoding="utf-8", errors="replace") if (meta_out / "stderr.txt").exists() else ""
            return {
                "returncode": res.get("exit_code", 1),
                "status": res.get("status", "unknown"),
                "wall_s": res.get("wall_s", 0.0),
                "cpu_s": res.get("cpu_s", 0.0),
                "peak_rss_mb": res.get("peak_rss_mb", 0.0),
                "python": res.get("python", py_version),
                "image": docker_image,
                "isolation": res.get("isolation", "docker-netnone"),
                "input_sha256": res.get("input_sha256", ""),
                "input_modified": res.get("input_modified", False),
                "stdout": stdout,
                "stderr": stderr,
                "tmp_leftovers": res.get("tmp_leftovers", []),
                "home_leftovers": res.get("home_leftovers", []),
                "net_hits": res.get("network_attempt_strings", []),
                "meta_dir": str(meta_out),
            }

        # Fallback direct docker execution without external testlab module
        docker_bin = shutil.which("docker")
        assert docker_bin
        with tempfile.TemporaryDirectory(prefix="wg_dk_tmp_") as tmp_s, tempfile.TemporaryDirectory(prefix="wg_dk_home_") as home_s:
            sbx_tmp, sbx_home = Path(tmp_s), Path(home_s)
            for d in (sbx_tmp, sbx_home, out, meta_out):
                os.chmod(d, 0o777)
            cmd = [
                docker_bin, "run", "--rm",
                "--network", "none", "--cpus", "2",
                "--memory", f"{mem_limit_mb}m", "--memory-swap", f"{mem_limit_mb}m",
                "--pids-limit", "512", "--ulimit", "core=0", "--ulimit", "fsize=2147483648",
                "-v", f"{REPO}:/sub:ro", "-v", f"{inp}:/in:ro",
                "-v", f"{out}:/out/release",
                "-v", f"{sbx_tmp}:/sbx/tmp", "-v", f"{sbx_home}:/sbx/home",
                "-e", "TMPDIR=/sbx/tmp", "-e", "TEMP=/sbx/tmp", "-e", "TMP=/sbx/tmp",
                "-e", "HOME=/sbx/home", "-e", f"RAKSHA_SECRET={secret}",
                "-e", "PYTHONDONTWRITEBYTECODE=1",
                "-e", "HTTP_PROXY=http://127.0.0.1:9", "-e", "HTTPS_PROXY=http://127.0.0.1:9",
                "-e", "ALL_PROXY=http://127.0.0.1:9", "-e", "NO_PROXY=",
                "-w", "/sub",
            ]
            if env_overrides:
                for k, v in env_overrides.items():
                    cmd.extend(["-e", f"{k}={v}"])
            cmd.extend([docker_image, "/sub-venv/bin/python", "/sub/main.py", "--input", "/in", "--output", "/out/release"])
            t0 = time.monotonic()
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
            wall = round(time.monotonic() - t0, 3)
            combined = proc.stdout + "\n" + proc.stderr
            net_hits = [s for s in NET_ERR_STRINGS if s.lower() in combined.lower()]
            tmp_leftovers = sorted(p.relative_to(sbx_tmp).as_posix() for p in sbx_tmp.rglob("*"))
            home_leftovers = sorted(p.relative_to(sbx_home).as_posix() for p in sbx_home.rglob("*"))
            run_meta = {
                "status": "success" if proc.returncode == 0 else f"failed_exit_{proc.returncode}",
                "exit_code": proc.returncode,
                "wall_s": wall,
                "cpu_s": 0.0,
                "peak_rss_mb": 0.0,
                "python": py_version,
                "image": docker_image,
                "isolation": "docker-netnone",
                "input_modified": False,
                "network_attempt_strings": net_hits,
                "tmp_leftovers": tmp_leftovers,
                "home_leftovers": home_leftovers,
            }
            (meta_out / "stdout.txt").write_text(proc.stdout, encoding="utf-8")
            (meta_out / "stderr.txt").write_text(proc.stderr, encoding="utf-8")
            (meta_out / "run.json").write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
            return {
                "returncode": proc.returncode,
                "status": run_meta["status"],
                "wall_s": wall,
                "cpu_s": 0.0,
                "peak_rss_mb": 0.0,
                "python": py_version,
                "image": docker_image,
                "isolation": "docker-netnone",
                "input_modified": False,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "tmp_leftovers": tmp_leftovers,
                "home_leftovers": home_leftovers,
                "net_hits": net_hits,
                "meta_dir": str(meta_out),
            }

    return _run_isolated(
        inp, out, secret,
        env_overrides=env_overrides,
        timeout=timeout,
        readonly_input=readonly_input,
        meta_dir=meta_out,
    )


def _run_isolated(
    inp: Path,
    out: Path,
    secret: str,
    *,
    env_overrides: dict[str, str] | None = None,
    timeout: int = 120,
    readonly_input: bool = False,
    meta_dir: Optional[Path] = None,
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

        changed_ro = False
        if readonly_input:
            _chmod_tree(inp, readonly=True)
            changed_ro = True

        t0 = time.monotonic()
        stdout_txt = ""
        stderr_txt = ""
        cpu_s = 0.0
        peak_rss_mb = 0.0
        rc = 0
        try:
            proc = subprocess.Popen(
                [sys.executable, str(MAIN), "--input", str(inp), "--output", str(out)],
                cwd=str(REPO),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            out_b, err_b = b"", b""
            # Read pipes cleanly using communicate + rusage via resource.getrusage or wait4
            try:
                assert proc.stdout is not None and proc.stderr is not None
                out_b = proc.stdout.read()
                err_b = proc.stderr.read()
                try:
                    _, raw_status, rusage = os.wait4(proc.pid, 0)
                    rc = os.waitstatus_to_exitcode(raw_status)
                    cpu_s = round(float(rusage.ru_utime + rusage.ru_stime), 3)
                    peak_rss_mb = round(_ru_maxrss_mb(rusage.ru_maxrss), 2)
                except (ChildProcessError, AttributeError, OSError):
                    rc = proc.wait(timeout=timeout)
            finally:
                if proc.poll() is None:
                    proc.kill()
            stdout_txt = out_b.decode("utf-8", "replace")
            stderr_txt = err_b.decode("utf-8", "replace")
        finally:
            if changed_ro:
                _chmod_tree(inp, readonly=False)

        wall = round(time.monotonic() - t0, 3)
        tmp_leftovers = sorted(p.relative_to(sbx_tmp).as_posix() for p in sbx_tmp.rglob("*"))
        home_leftovers = sorted(p.relative_to(sbx_home).as_posix() for p in sbx_home.rglob("*"))
        combined = stdout_txt + "\n" + stderr_txt
        net_hits = [s for s in NET_ERR_STRINGS if s.lower() in combined.lower()]

        res = {
            "returncode": rc,
            "status": "success" if rc == 0 else f"failed_exit_{rc}",
            "wall_s": wall,
            "cpu_s": cpu_s,
            "peak_rss_mb": peak_rss_mb,
            "python": sys.version.split()[0],
            "image": f"host-py{sys.version_info.major}.{sys.version_info.minor}",
            "isolation": "host-subprocess",
            "stdout": stdout_txt,
            "stderr": stderr_txt,
            "tmp_leftovers": tmp_leftovers,
            "home_leftovers": home_leftovers,
            "net_hits": net_hits,
        }
        if meta_dir:
            meta_dir.mkdir(parents=True, exist_ok=True)
            (meta_dir / "stdout.txt").write_text(stdout_txt, encoding="utf-8")
            (meta_dir / "stderr.txt").write_text(stderr_txt, encoding="utf-8")
            (meta_dir / "run.json").write_text(json.dumps({k: v for k, v in res.items() if k not in ("stdout", "stderr")}, indent=2), encoding="utf-8")
        return res


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


def _check_static_imports() -> list[dict[str, Any]]:
    """SEC-01: AST static scan ensuring zero network or LLM/hosted-AI imports in product code."""
    fails: list[dict[str, Any]] = []
    targets = [MAIN] + sorted((REPO / "wardguard").rglob("*.py"))
    for pyf in targets:
        try:
            tree = ast.parse(pyf.read_text(encoding="utf-8"), filename=str(pyf))
        except SyntaxError as exc:
            fails.append({"check": "sec01_syntax", "sev": "S0", "file": str(pyf.relative_to(REPO)), "detail": str(exc)})
            continue
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            for mod in mods:
                root = mod.split(".")[0]
                if mod in BANNED_RUNTIME_ROOTS or root in BANNED_RUNTIME_ROOTS:
                    fails.append({
                        "check": "sec01_banned_import",
                        "sev": "S0",
                        "file": pyf.relative_to(REPO).as_posix(),
                        "module": mod,
                    })
    return fails


def _check_sec_hygiene(work: Path, inp: Path, canaries: list[str]) -> list[dict[str, Any]]:
    """SEC-02 (unusual secrets) & SEC-08 (CLI negative edge cases)."""
    fails: list[dict[str, Any]] = []

    # SEC-02: 1-char, spaces, and 1 KB unicode secrets
    weird_secrets = [
        ("1char", "x", False),
        ("spaces", "sec_spaces secret !@# 99817", True),
        ("unicode1k", ("गोपनीय_कुंजी_2026_" * 50)[:1024], True),
    ]
    for tag, sec, check_bytes in weird_secrets:
        out_s = work / f"sec02_{tag}"
        r = _run_isolated(inp, out_s, sec)
        if r["returncode"] != 0:
            fails.append({"check": f"sec02_exit_{tag}", "sev": "S1", "detail": r["returncode"]})
            continue
        if check_bytes:
            for f in out_s.rglob("*"):
                if f.is_file() and sec.encode("utf-8") in f.read_bytes():
                    fails.append({"check": f"sec02_secret_in_output_{tag}", "sev": "S0", "file": f.name})
            if sec in r["stdout"] or sec in r["stderr"]:
                fails.append({"check": f"sec02_secret_in_logs_{tag}", "sev": "S0"})

    # SEC-08: Missing/empty secret & output inside input
    with tempfile.TemporaryDirectory(prefix="wg_sec08_") as tmp_s:
        tmp = Path(tmp_s)
        sample_in = tmp / "in"
        sample_in.mkdir()
        (sample_in / "a.txt").write_text("Patient: Anita\n", encoding="utf-8")
        # 1) Empty secret -> must exit non-zero cleanly without traceback
        p1 = subprocess.run(
            [sys.executable, str(MAIN), "--input", str(sample_in), "--output", str(tmp / "o1")],
            cwd=str(REPO),
            env={"PATH": os.environ.get("PATH", ""), "RAKSHA_SECRET": "", "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=30,
        )
        if p1.returncode == 0 or "Traceback" in p1.stderr:
            fails.append({"check": "sec08_empty_secret", "sev": "S1", "code": p1.returncode})
        # 2) Output inside input -> must exit non-zero without touching input
        p2 = subprocess.run(
            [sys.executable, str(MAIN), "--input", str(sample_in), "--output", str(sample_in / "sub_out")],
            cwd=str(REPO),
            env={"PATH": os.environ.get("PATH", ""), "RAKSHA_SECRET": "abc", "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=30,
        )
        if p2.returncode == 0 or (sample_in / "sub_out").exists():
            fails.append({"check": "sec08_output_inside_input", "sev": "S1", "code": p2.returncode})
    return fails


def _verify_hostile_tree(hostile: Path, work: Path) -> None:
    hostile.mkdir(parents=True, exist_ok=True)
    outside_secret = work / "OUTSIDE_SECRET_DO_NOT_READ.txt"
    outside_secret.write_text("TOP_SECRET_OUTSIDE_TOKEN_XYZ987", encoding="utf-8")
    (hostile / "ok.txt").write_text("Patient Name: Ramesh Gupta\nDiagnosis: Fever\n", encoding="utf-8")
    # Symlink escaping input dir to host secret & /etc/passwd
    esc1 = hostile / "escape.txt"
    if not esc1.exists() and not esc1.is_symlink():
        esc1.symlink_to(outside_secret)
    esc2 = hostile / "escape_etc.txt"
    if not esc2.exists() and not esc2.is_symlink():
        esc2.symlink_to(Path("/etc/passwd"))
    # SEC-06: Path traversal in filenames and JSON metadata
    (hostile / "..%2f..%2fpwn.txt").write_text("Patient: Asha Verma\nDiagnosis: Cold\n", encoding="utf-8")
    (hostile / "trav.json").write_text(
        json.dumps({"source_file": "../../secret.txt", "patient": "Suresh Kumar", "diagnosis": "Flu"}),
        encoding="utf-8",
    )
    unreadable = hostile / "locked.txt"
    unreadable.write_text("Patient Name: Secret Locked\n", encoding="utf-8")
    if os.geteuid() != 0:
        os.chmod(unreadable, 0o000)


def _check_hostile_output(res_h: dict[str, Any], out_h: Path, fails: list[dict[str, Any]], label: str) -> None:
    if res_h["returncode"] != 0:
        fails.append({"check": f"{label}_hostile_exit", "sev": "S0", "detail": res_h["returncode"]})
        return
    san_h = out_h / "sanitized"
    if san_h.exists():
        for p in san_h.rglob("*"):
            if p.is_file():
                txt = p.read_text(encoding="utf-8", errors="replace")
                if "TOP_SECRET_OUTSIDE_TOKEN_XYZ987" in txt or "root:x:0:0" in txt or "/bin/bash" in txt or "/bin/sh" in txt:
                    fails.append({"check": f"{label}_symlink_escape_leaked", "sev": "S0", "detail": p.name})
                if "Asha Verma" in txt or "Suresh Kumar" in txt:
                    fails.append({"check": f"{label}_traversal_pii_leaked", "sev": "S1", "detail": p.name})
    for p in out_h.rglob("*"):
        try:
            if not p.resolve().is_relative_to(out_h.resolve()):
                fails.append({"check": f"{label}_output_path_escape", "sev": "S0", "detail": str(p)})
        except OSError:
            pass


def check_sandbox(
    work: Path,
    seed: int = 1,
    n_patients: int = 10,
    *,
    run_docker: bool = True,
    docker_versions: tuple[str, ...] = ("3.10", "3.11", "3.12"),
) -> dict[str, Any]:
    work = work.resolve()
    if work.exists():
        _chmod_tree(work, readonly=False) if (work / "input").exists() else None
        if (work / "hostile_in" / "locked.txt").exists() and os.geteuid() != 0:
            try:
                os.chmod(work / "hostile_in" / "locked.txt", 0o644)
            except OSError:
                pass
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

    ans = json.loads((work / "answer.json").read_text(encoding="utf-8"))
    canaries = ans.get("canaries", [])

    # Verify gen.py emits complete kit+torture artifacts intact
    for req_path in (work / "answer.json", work / "truth" / "truth.json",
                     work / "attacker" / "registry.csv", work / "attacker" / "known_facts.jsonl"):
        if not req_path.is_file():
            fails.append({"check": "forge_artifact_missing", "sev": "S0", "detail": req_path.name})

    try:
        _chmod_tree(inp, readonly=True)

        # 1. Host isolated baseline with read-only input & fake proxy & empty TMPDIR/HOME
        out_base = work / "out_utc"
        res_base = _run_isolated(
            inp, out_base, secret,
            env_overrides={"PYTHONHASHSEED": "0", "TZ": "UTC", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            meta_dir=work / "meta_utc",
        )
        if res_base["returncode"] != 0:
            fails.append({"check": "baseline_exit", "sev": "S0", "detail": res_base["returncode"]})
        if res_base["tmp_leftovers"]:
            fails.append({"check": "tmpdir_not_empty", "sev": "S0", "detail": res_base["tmp_leftovers"]})
        if res_base["home_leftovers"]:
            fails.append({"check": "homedir_not_empty", "sev": "S0", "detail": res_base["home_leftovers"]})
        if res_base["net_hits"]:
            fails.append({"check": "network_attempt", "sev": "S0", "detail": res_base["net_hits"]})
        if (out_base / "report.json").exists() and secret in (out_base / "report.json").read_text(encoding="utf-8", errors="replace"):
            fails.append({"check": "secret_in_report", "sev": "S0"})
        if secret in res_base["stderr"]:
            fails.append({"check": "secret_in_stderr", "sev": "S0"})
        for c in canaries:
            if c.lower() in res_base["stderr"].lower():
                fails.append({"check": "canary_in_stderr", "sev": "S0", "detail": c})

        if _tree_hashes(inp) != input_before:
            fails.append({"check": "input_modified", "sev": "S0"})
        if _tree_hashes(REPO / "wardguard") != repo_before:
            fails.append({"check": "repo_modified", "sev": "S0"})

        # 2. Host environment determinism matrix: PYTHONHASHSEED, TZ, LANG
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

        # 3. Docker / OpenEnv Multi-Python Verification (--network none --cpus 2 --memory 4g --pids-limit 512)
        docker_status = _docker_available()
        docker_results: dict[str, Any] = {}
        if run_docker and docker_status == "running":
            imgs = ensure_openenv_images(docker_versions)
            primary_img: Optional[str] = None
            for ver, img_tag in imgs.items():
                if not img_tag:
                    docker_results[ver] = {"status": "image_missing"}
                    continue
                if primary_img is None:
                    primary_img = img_tag
                out_dk = work / f"out_docker_py{ver.replace('.', '')}"
                meta_dk = work / f"meta_docker_py{ver.replace('.', '')}"
                res_dk = run_openenv(
                    inp, out_dk, secret,
                    mode="docker", py_version=ver, docker_image=img_tag, meta_dir=meta_dk,
                    env_overrides={"PYTHONHASHSEED": "0", "TZ": "UTC", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                )
                docker_results[ver] = {
                    "image": img_tag,
                    "status": res_dk["status"],
                    "returncode": res_dk["returncode"],
                    "wall_s": res_dk["wall_s"],
                    "peak_rss_mb": res_dk["peak_rss_mb"],
                }
                if res_dk["returncode"] != 0 or res_dk["status"] != "success":
                    fails.append({"check": f"docker_exit_py{ver}", "sev": "S0", "detail": res_dk.get("stderr", "")[-200:]})
                    continue
                if res_dk["tmp_leftovers"] or res_dk["home_leftovers"]:
                    fails.append({"check": f"docker_tmp_home_leftovers_py{ver}", "sev": "S0", "detail": res_dk["tmp_leftovers"] + res_dk["home_leftovers"]})
                if res_dk["net_hits"]:
                    fails.append({"check": f"docker_network_attempt_py{ver}", "sev": "S0", "detail": res_dk["net_hits"]})
                if _release_digest(out_dk) != base_digest:
                    diffs = [k for k in sorted(set(base_digest) | set(_release_digest(out_dk)))
                             if base_digest.get(k) != _release_digest(out_dk).get(k)]
                    fails.append({"check": f"docker_nondeterminism_py{ver}", "sev": "S0", "detail": diffs[:10]})
                for c in canaries:
                    if c.lower() in res_dk["stderr"].lower():
                        fails.append({"check": f"docker_canary_in_stderr_py{ver}", "sev": "S0", "detail": c})

            # Docker container env-determinism matrix check
            if primary_img:
                out_dk_env = work / "out_docker_env"
                res_dk_env = run_openenv(
                    inp, out_dk_env, secret,
                    mode="docker", docker_image=primary_img, meta_dir=work / "meta_docker_env",
                    env_overrides={"PYTHONHASHSEED": "42", "TZ": "America/New_York", "LANG": "C", "LC_ALL": "C"},
                )
                if res_dk_env["returncode"] != 0:
                    fails.append({"check": "docker_env_matrix_exit", "sev": "S0", "detail": res_dk_env["returncode"]})
                elif _release_digest(out_dk_env) != base_digest:
                    fails.append({"check": "docker_env_nondeterminism", "sev": "S0"})
    finally:
        _chmod_tree(inp, readonly=False)

    # 4. Security hygiene SEC-01, SEC-02, SEC-08
    fails.extend(_check_static_imports())
    fails.extend(_check_sec_hygiene(work, inp, canaries))

    # 5. Hostile containment on Host & inside Docker
    hostile = work / "hostile_in"
    _verify_hostile_tree(hostile, work)
    out_h = work / "out_hostile"
    out_h_dk = work / "out_hostile_docker"
    try:
        res_h = _run_isolated(hostile, out_h, secret)
        _check_hostile_output(res_h, out_h, fails, "host")
        if run_docker and _docker_available() == "running":
            imgs = ensure_openenv_images(("3.12",))
            if imgs.get("3.12"):
                res_h_dk = run_openenv(
                    hostile, out_h_dk, secret,
                    mode="docker", docker_image=imgs["3.12"], meta_dir=work / "meta_hostile_dk",
                )
                _check_hostile_output(res_h_dk, out_h_dk, fails, "docker")
    finally:
        if os.geteuid() != 0 and (hostile / "locked.txt").exists():
            os.chmod(hostile / "locked.txt", 0o644)

    py_versions = {
        v: shutil.which(v) or "missing"
        for v in ("python3.10", "python3.11", "python3.12", "python3.13")
    }

    return {
        "seed": seed,
        "fails": fails,
        "wall_s": res_base.get("wall_s", 0.0),
        "cpu_s": res_base.get("cpu_s", 0.0),
        "peak_rss_mb": res_base.get("peak_rss_mb", 0.0),
        "docker": docker_status,
        "docker_pythons": docker_results,
        "pythons": py_versions,
        "sec_static_clean": not any(f["check"].startswith("sec01") for f in fails),
        "status": "SANDBOX OK" if not fails else "SANDBOX FAIL",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Run unified OpenEnv / Docker sandbox suite & CLI runner")
    ap.add_argument("--work", type=Path, default=Path("/tmp/wg_sandbox"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--patients", type=int, default=10)
    ap.add_argument("--no-docker", action="store_true", help="Skip Docker multi-Python tests")
    # Direct execution mode inside OpenEnv sandbox (mirrors --network none --cpus 2 --memory 4g)
    ap.add_argument("--run", action="store_true", help="Execute WardGuard in OpenEnv sandbox on --input -> --output")
    ap.add_argument("--input", type=Path, default=None)
    ap.add_argument("--output", type=Path, default=None)
    ap.add_argument("--meta", type=Path, default=None)
    ap.add_argument("--secret", default=os.environ.get("RAKSHA_SECRET", "practice"))
    ap.add_argument("--mode", choices=["auto", "docker", "subprocess"], default="auto")
    ap.add_argument("--py", default="3.12")
    a = ap.parse_args()

    if a.run:
        if not a.input or not a.output:
            ap.error("--run requires --input and --output")
        meta = run_openenv(
            a.input, a.output, a.secret,
            mode=a.mode, py_version=a.py, meta_dir=a.meta,
        )
        print(json.dumps({k: v for k, v in meta.items() if k not in ("stdout", "stderr")}, indent=2))
        return 0 if meta.get("returncode") == 0 and meta.get("status") == "success" else (meta.get("returncode") or 1)

    res = check_sandbox(a.work, a.seed, a.patients, run_docker=not a.no_docker)
    print(json.dumps(res, indent=2))
    print(res["status"])
    return 0 if not res["fails"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
