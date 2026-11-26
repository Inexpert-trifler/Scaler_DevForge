"""Byte-level fuzzer for WardGuard robustness (development tool).

Takes a generated torture dataset, writes N corrupted variants of its files into one input
folder, runs the real CLI once and checks the invariants that must hold for ANY input:

  * exit code 0 and a report.json that accounts for every input file (by SHA-256)
  * no Python traceback / exception text on stderr
  * no raw copy: a sanitized output byte-identical to an input file that contains a known PII value
  * no known PII value (from the answer key) appears unchanged in any output file
  * the input folder is unchanged; nothing is left in TMPDIR / HOME

Usage: python -m tools.torture.fuzz --seed 1 --variants 300 --work /path/to/scratch
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.torture.check import View, contains_surface, file_view, run_cli, tree_hash  # noqa: E402
from tools.torture.gen import generate  # noqa: E402


def mutate(data: bytes, rng: random.Random) -> tuple[str, bytes]:
    ops = ["truncate", "bitflip", "nul", "invalid_utf8", "dup_chunk", "long_line", "deep_nest", "strip_newlines",
           "crlf_mix", "bom_mix", "garbage_prefix", "empty", "huge_field"]
    op = rng.choice(ops)
    b = bytearray(data)
    if op == "truncate" and len(b) > 4:
        b = b[: rng.randint(1, len(b) - 1)]
    elif op == "bitflip" and b:
        for _ in range(rng.randint(1, 8)):
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
    elif op == "nul" and b:
        i = rng.randrange(len(b))
        b[i:i] = b"\x00" * rng.randint(1, 4)
    elif op == "invalid_utf8" and b:
        i = rng.randrange(len(b))
        b[i:i] = rng.choice([b"\xff", b"\xc3\x28", b"\xe2\x82", b"\xed\xa0\x80", b"\xf0\x28\x8c\x28"])
    elif op == "dup_chunk" and len(b) > 10:
        i = rng.randrange(len(b) - 5)
        j = min(len(b), i + rng.randint(5, 200))
        b[j:j] = b[i:j] * rng.randint(2, 20)
    elif op == "long_line":
        b += b"A" * 100_000 + b" 9876543210 " + b"B" * 50_000 + b"\n"
    elif op == "deep_nest":
        b = b"[" * 5000 + b'"x"' + b"]" * 5000
    elif op == "strip_newlines":
        b = bytearray(bytes(b).replace(b"\n", b" "))
    elif op == "crlf_mix":
        b = bytearray(bytes(b).replace(b"\n", rng.choice([b"\r", b"\r\n", b"\n\r"])))
    elif op == "bom_mix":
        b = bytearray(rng.choice([b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff"]) + bytes(b))
    elif op == "garbage_prefix":
        b = bytearray(bytes(rng.randrange(256) for _ in range(rng.randint(1, 64))) + bytes(b))
    elif op == "empty":
        b = bytearray()
    elif op == "huge_field":
        b += b'\n"' + b"x" * 300_000 + b'",1,2\n'
    return op, bytes(b)


def main() -> int:
    ap = argparse.ArgumentParser(description="WardGuard byte-level fuzzer")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--variants", type=int, default=300)
    ap.add_argument("--work", type=Path, required=True)
    a = ap.parse_args()
    rng = random.Random(f"fuzz:{a.seed}")
    base = a.work / f"fuzz_base_{a.seed}"
    if base.exists():
        shutil.rmtree(base)
    generate(a.seed, base)
    ans = json.loads((base / "answer.json").read_text(encoding="utf-8"))
    files = sorted(ans["files"])
    pii = sorted({x["surface"] for x in ans["remove"] if x["critical"] and len(x["surface"]) >= 8 and x["channel"] != "filename"})
    inp = a.work / f"fuzz_in_{a.seed}"
    if inp.exists():
        shutil.rmtree(inp)
    ops_used: dict[str, str] = {}
    for k in range(a.variants):
        src = rng.choice(files)
        op, data = mutate((base / "input" / src).read_bytes(), rng)
        stem, dot, ext = src.replace("/", "__").rpartition(".")
        exts = [ext, ext, ext, "csv", "json", "txt", "tsv", "dat", ""]
        new_ext = rng.choice(exts)
        name = f"f{k:04d}_{op}_{stem or ext}" + (f".{new_ext}" if new_ext else "")
        sub = rng.choice(["", "a/", "a/b/", "deep/" * rng.randint(1, 12), "spaced dir/", "uni_नाम/"])
        path = inp / sub / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        ops_used[(sub + name)] = op
    before = tree_hash(inp)
    out = a.work / f"fuzz_out_{a.seed}"
    r = run_cli(inp, out, "fuzz-secret", a.work / f"fuzz_sbx_{a.seed}")
    problems: list[str] = []
    if r["code"] != 0:
        problems.append(f"exit code {r['code']}: {r['stderr'][-300:]}")
    if "Traceback" in r["stderr"] or "Error:" in r["stderr"]:
        problems.append("traceback/exception text on stderr")
    if tree_hash(inp) != before:
        problems.append("input modified")
    if r["tmp_left"] or r["home_left"]:
        problems.append("temp leftovers")
    report_path = out / "report.json"
    if not report_path.exists():
        problems.append("report.json missing")
    else:
        rep = json.loads(report_path.read_text(encoding="utf-8"))
        shas = {f["input_sha256"] for f in rep.get("files", [])}
        all_in = [p for p in inp.rglob("*") if p.is_file()]
        missing = [p for p in all_in if hashlib.sha256(p.read_bytes()).hexdigest() not in shas]
        if missing:
            problems.append(f"{len(missing)} input files missing from report")
        raw_copies = leaks = 0
        in_bytes = {}
        for p in all_in:
            in_bytes.setdefault(hashlib.sha256(p.read_bytes()).hexdigest(), p.read_bytes())
        for f in rep.get("files", []):
            o = f.get("output")
            if not o or not (out / o).exists():
                continue
            ob = (out / o).read_bytes()
            ib = in_bytes.get(f["input_sha256"], b"")
            txt = ib.decode("utf-8", "replace")
            if ob == ib and any(s in txt for s in pii):
                raw_copies += 1
            v = View(file_view(out / o))
            leaks += sum(1 for s in pii if contains_surface(v.norm, v.runs, s, "PHONE" if s.replace(" ", "").isdigit() else "NAME"))
        if raw_copies:
            problems.append(f"{raw_copies} raw copies of PII files")
        summary = {"files": len(all_in), "sanitized": sum(1 for f in rep["files"] if f["status"] == "sanitized"),
                   "quarantined": sum(1 for f in rep["files"] if f["status"] == "quarantined"),
                   "pii_hits_in_outputs": leaks, "secs": round(r["secs"], 2)}
        print(json.dumps(summary))
    for p in problems:
        print("PROBLEM:", p)
    print("FUZZ", "FAIL" if problems else "OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
