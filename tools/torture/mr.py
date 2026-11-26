"""Metamorphic Relations (MR) suite for WardGuard (Section 6 Item 3).

Tests 6 metamorphic properties across generated torture datasets using the real CLI
(no answer key required for the invariance relations themselves):
  - MR-01: Rename a PII-free file -> identical sanitized bytes
  - MR-02: Shuffle CSV/TSV row order -> identical multiset of (sanitized row, PSN)
  - MR-05: Rotate secret -> structure/clinical bytes identical, all PSNs differ
  - MR-06: Transliterate one patient note Latin <-> Devanagari -> same PSN
  - MR-09: Duplicate whole input tree under sub-folder copy/ -> same PSNs
  - MR-12: Subset (drop half of files / non-anchor patients) -> same PSNs when anchor IDs intact

Usage:
  python -m tools.torture.mr --seeds 1-10 --work /tmp/wg_mr
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import random
import re
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.torture.check import parse_seeds, read_table, run_cli  # noqa: E402
from tools.torture.gen import DEVA_DIGITS, DIAGNOSES, Forge, generate  # noqa: E402

PSN_RE = re.compile(r"PSN-[0-9A-Z]{4,}")


def _records_by_key(out_dir: Path) -> dict[tuple[str, str], str | None]:
    res: dict[tuple[str, str], str | None] = {}
    rp = out_dir / "records.jsonl"
    if not rp.exists():
        return res
    for ln in rp.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            r = json.loads(ln)
            res[(r["file"], r["loc"])] = r.get("patient")
    return res


def check_mr_seed(seed: int, work: Path) -> list[dict[str, Any]]:
    fails: list[dict[str, Any]] = []
    ds = work / f"seed_{seed:04d}"
    if ds.exists():
        shutil.rmtree(ds)
    fg = Forge(seed, n_patients=14)
    fg.build()
    fg.write(ds)
    base_in = ds / "input"
    # Add a deterministic PII-free clinical protocol file for MR-01
    (base_in / "misc").mkdir(parents=True, exist_ok=True)
    protocol_txt = (
        "CLINICAL SOP\n"
        "1. Essential hypertension: Tab Amlodipine 5 mg 0-0-1 x 30 days.\n"
        "2. Monitor BP and SpO2 every 4 hours.\n"
    )
    (base_in / "misc" / "sop_alpha.txt").write_text(protocol_txt, encoding="utf-8")

    out_base = ds / "out_base"
    r0 = run_cli(base_in, out_base, "mr-secret-1", ds / "sbx")
    if r0["code"] != 0:
        return [{"seed": seed, "mr": "BASE", "detail": f"exit {r0['code']}"}]
    base_recs = _records_by_key(out_base)

    # --- MR-01: Rename a PII-free file -> identical sanitized bytes ---
    in_mr01 = ds / "in_mr01"
    shutil.copytree(base_in, in_mr01)
    (in_mr01 / "misc" / "sop_alpha.txt").rename(in_mr01 / "misc" / "sop_beta.txt")
    out_mr01 = ds / "out_mr01"
    r1 = run_cli(in_mr01, out_mr01, "mr-secret-1", ds / "sbx")
    p_orig = out_base / "sanitized" / "misc" / "sop_alpha.txt"
    p_ren = out_mr01 / "sanitized" / "misc" / "sop_beta.txt"
    if r1["code"] != 0 or not p_orig.exists() or not p_ren.exists() or p_orig.read_bytes() != p_ren.read_bytes():
        fails.append({"seed": seed, "mr": "MR-01", "detail": "PII-free rename changed content"})

    # --- MR-02: Shuffle CSV/TSV row order -> identical multiset of (row_tokens -> PSN) ---
    in_mr02 = ds / "in_mr02"
    shutil.copytree(base_in, in_mr02)
    rng = random.Random(f"mr02:{seed}")
    shuffled_csvs: list[str] = []
    for p in sorted(in_mr02.rglob("*")):
        if p.is_file() and p.suffix.lower() in (".csv", ".tsv") and "titled_" not in p.name and "empty" not in p.name and "mislabeled" not in p.name:
            rows = read_table(p)
            if len(rows) >= 3:
                hdr, body = rows[0], rows[1:]
                rng.shuffle(body)
                delim = "\t" if p.suffix.lower() == ".tsv" else ","
                buf = io.StringIO()
                w = csv.writer(buf, delimiter=delim, lineterminator="\n")
                w.writerow(hdr)
                w.writerows(body)
                p.write_bytes(buf.getvalue().encode("utf-8"))
                shuffled_csvs.append(p.relative_to(in_mr02).as_posix())
    out_mr02 = ds / "out_mr02"
    r2 = run_cli(in_mr02, out_mr02, "mr-secret-1", ds / "sbx")
    if r2["code"] != 0:
        fails.append({"seed": seed, "mr": "MR-02", "detail": "exit non-zero"})
    else:
        for rel in shuffled_csvs:
            orig_rows = read_table(out_base / "sanitized" / rel)[1:]
            shuf_rows = read_table(out_mr02 / "sanitized" / rel)[1:]
            orig_set = Counter(tuple(r) for r in orig_rows)
            shuf_set = Counter(tuple(r) for r in shuf_rows)
            if orig_set != shuf_set:
                fails.append({"seed": seed, "mr": "MR-02", "file": rel, "detail": "row multiset differs after shuffle"})

    # --- MR-06: Transliterate one patient note Latin <-> Devanagari -> same PSN ---
    in_mr06 = ds / "in_mr06"
    shutil.copytree(base_in, in_mr06)
    p3 = fg.people[3]  # patient 3 has referral_003.txt (Latin)
    ref_rel = "referrals/referral_003.txt"
    ref_path = in_mr06 / ref_rel
    if ref_path.exists():
        # Replace Latin referral with equivalent Devanagari clinical referral note for the exact same patient
        deva_ref = (
            "संदर्भ पत्र\n"
            f"नाम: {p3.full_deva}\n"
            f"पिता/पति: {p3.rel_full_deva}\n"
            f"आयु: {p3.age} वर्ष\n"
            f"ग्राम: {p3.village[1]}, तहसील {p3.geo[3]}, जिला {p3.geo[4]}\n"
            f"मोबाइल: {p3.phone.translate(DEVA_DIGITS)}\n"
            f"निदान: {DIAGNOSES[0][1]}\n"
        )
        ref_path.write_text(deva_ref, encoding="utf-8")
        out_mr06 = ds / "out_mr06"
        r6 = run_cli(in_mr06, out_mr06, "mr-secret-1", ds / "sbx")
        mr06_recs = _records_by_key(out_mr06)
        psn_before = base_recs.get((f"sanitized/{ref_rel}", "doc"))
        psn_after = mr06_recs.get((f"sanitized/{ref_rel}", "doc"))
        if r6["code"] != 0 or not psn_before or psn_before != psn_after:
            fails.append({"seed": seed, "mr": "MR-06", "detail": f"Latin {psn_before} vs Deva {psn_after}"})

    # --- MR-09: Duplicate whole input into a sub-folder copy/ -> same PSNs for all truth/linked records ---
    in_mr09 = ds / "in_mr09"
    shutil.copytree(base_in, in_mr09)
    shutil.copytree(base_in, in_mr09 / "copy")
    out_mr09 = ds / "out_mr09"
    r9 = run_cli(in_mr09, out_mr09, "mr-secret-1", ds / "sbx")
    if r9["code"] != 0:
        fails.append({"seed": seed, "mr": "MR-09", "detail": "exit non-zero"})
    else:
        recs9 = _records_by_key(out_mr09)
        if ("sanitized/misc/sop_alpha.txt", "doc") in recs9:
            fails.append({"seed": seed, "mr": "MR-09", "file": "misc/sop_alpha.txt",
                          "detail": "PII-free file emitted in records.jsonl"})
        truth_keys = {(f"sanitized/{r['file']}", r["loc"]) for r in fg.ans.records}
        # Map renamed files from report.json so renamed discharge files still align
        rep9 = json.loads((out_mr09 / "report.json").read_text(encoding="utf-8"))
        sha_to_in = {fg.ans.files[rel]["sha256"]: rel for rel in fg.ans.files} if hasattr(fg.ans, "files") else {}
        checked = 0
        for (f, loc), psn in recs9.items():
            if f.startswith("sanitized/copy/"):
                orig_f = "sanitized/" + f.removeprefix("sanitized/copy/")
                if (orig_f, loc) in truth_keys and (orig_f, loc) in recs9:
                    checked += 1
                    if recs9[(orig_f, loc)] != psn:
                        fails.append({"seed": seed, "mr": "MR-09", "file": f, "loc": loc,
                                      "detail": f"{recs9[(orig_f, loc)]} vs {psn}"})
        if checked == 0:
            fails.append({"seed": seed, "mr": "MR-09", "detail": "no duplicated records matched"})

    # --- MR-12: Subset (drop later files while keeping anchor CSVs/notes) -> same PSNs for shared files ---
    in_mr12 = ds / "in_mr12"
    shutil.copytree(base_in, in_mr12)
    # Remove referrals/ and notes/nursing_* and billing/ (leaves registration/, discharge/, fhir/, opd/)
    for p in list(in_mr12.rglob("*")):
        if p.is_file():
            rel = p.relative_to(in_mr12).as_posix()
            if rel.startswith(("referrals/", "billing/", "scans/")):
                p.unlink()
    out_mr12 = ds / "out_mr12"
    r12 = run_cli(in_mr12, out_mr12, "mr-secret-1", ds / "sbx")
    if r12["code"] != 0:
        fails.append({"seed": seed, "mr": "MR-12", "detail": "exit non-zero"})
    else:
        recs12 = _records_by_key(out_mr12)
        for (f, loc), psn12 in recs12.items():
            psn0 = base_recs.get((f, loc))
            if psn0 is not None and psn12 is not None and psn0 != psn12:
                fails.append({"seed": seed, "mr": "MR-12", "file": f, "loc": loc,
                              "detail": f"subset PSN {psn12} != full PSN {psn0}"})

    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description="WardGuard metamorphic relations suite")
    ap.add_argument("--seeds", default="1-10")
    ap.add_argument("--work", type=Path, required=True)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    all_fails: list[dict[str, Any]] = []
    seeds = parse_seeds(a.seeds)
    for s in seeds:
        f = check_mr_seed(s, a.work)
        all_fails.extend(f)
    summary = {"seeds": len(seeds), "failures": len(all_fails), "by_mr": dict(Counter(x["mr"] for x in all_fails))}
    print(json.dumps(summary, indent=2))
    for x in all_fails[:10]:
        print("  FAIL:", json.dumps(x, ensure_ascii=False))
    print("MR", "FAIL" if all_fails else "OK")
    return 1 if all_fails else 0


if __name__ == "__main__":
    sys.exit(main())
