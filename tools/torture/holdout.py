"""Holdout variation generator and evaluator for WardGuard (Section 6 Item 4).

Tests unseen variations that never appeared in tools/torture/gen.py:
  - Non-UP states geography (Rajasthan, Jharkhand, Maharashtra, Odisha, Assam)
  - Voter ID (EPIC), Driving Licence, Ration Card
  - Unseen hospital MRN shapes (KGMU/2026/OPD/00123, R-77/1123, AIIMS.26.004918)
  - Unseen note templates (Lab Requisition, Death Summary, OT Notes)
  - Urdu-script fragments
  - Extended Indian kinship words (khalu, khala, devar, jeth, sasur, saas, bahu, damad, etc.)

Usage:
  python -m tools.torture.holdout --seeds 1-5 --work /tmp/wg_holdout
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.torture.check import View, contains_surface, file_view, norm, parse_seeds, run_cli  # noqa: E402

HOLDOUT_GEO = [
    ("Sikar", "Sikar", "Rajasthan", "332", "Piprali"),
    ("Barhi", "Koderma", "Jharkhand", "825", "Dhanwar"),
    ("Shirur", "Pune", "Maharashtra", "412", "Ranjangaon"),
    ("Athagarh", "Cuttack", "Odisha", "754", "Tigiria"),
    ("Nalbari", "Nalbari", "Assam", "781", "Tihu"),
]
HOLDOUT_NAMES = [
    ("Bhawani", "Shekhawat", "F", "Bhanwar", "Shekhawat"),
    ("Subhash", "Mohanty", "M", "Prakash", "Mohanty"),
    ("Archana", "Deshmukh", "F", "Vilas", "Deshmukh"),
    ("Pranjal", "Kalita", "M", "Dhiren", "Kalita"),
    ("Farida", "Khatoon", "F", "Rizwan", "Ansari"),
]
HOLDOUT_URDU = [
    ("رضوان احمد", "شکیل احمد"),
    ("فریدہ خاتون", "طارق محمود"),
]
HOLDOUT_KIN = ["Khalu", "Khala", "Devar", "Jeth", "Sasur", "Saas", "Bahu", "Damad", "Nandoi", "Samdhi"]


def generate_holdout(seed: int, out: Path) -> Path:
    rng = random.Random(f"holdout:{seed}")
    if out.exists():
        shutil.rmtree(out)
    inp = out / "input"
    inp.mkdir(parents=True)
    remove: list[dict[str, Any]] = []
    keep: list[dict[str, Any]] = []

    def put(rel: str, txt: str) -> None:
        p = inp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt, encoding="utf-8")

    def rm(rel: str, surface: str, etype: str, critical: bool = True) -> None:
        remove.append({"file": rel, "surface": surface, "type": etype, "critical": critical})

    def kp(rel: str, txt: str) -> None:
        keep.append({"file": rel, "text": txt})

    for i, (g, s, sex, rg, rs) in enumerate(HOLDOUT_NAMES):
        tehsil, dist, state, pin3, village = HOLDOUT_GEO[(seed + i) % len(HOLDOUT_GEO)]
        pin = pin3 + f"{rng.randint(100, 899):03d}"
        phone = str(rng.randint(6, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(9))
        epic = "".join(rng.choice("ABCDEFGHJKLMNPRSTUVWXYZ") for _ in range(3)) + f"{rng.randint(1000000, 9999999)}"
        dl = f"RJ14 {rng.randint(2015, 2024)}{rng.randint(1000000, 9999999)}"
        rc = f"RC-{rng.randint(2016, 2024)}-{rng.randint(1000000, 9999999)}"
        mrns = [
            f"KGMU/2026/OPD/{rng.randint(10000, 99999):05d}",
            f"R-{rng.randint(10, 99)}/{rng.randint(1000, 9999)}",
            f"AIIMS.26.{rng.randint(100000, 999999):06d}",
        ]
        mrn = mrns[i % len(mrns)]
        age = rng.randint(24, 72)

        # 1. Lab Requisition
        rel1 = f"labs/req_{i:02d}.txt"
        txt1 = (
            "LABORATORY REQUISITION FORM\n"
            f"Patient Name: {g} {s}\n"
            f"Lab Ref / UHID: {mrn}\n"
            f"Age/Sex: {age} Yrs/{sex}\n"
            f"Address: House {10 + i}, Shastri Nagar, near Clock Tower, {village}, Tehsil {tehsil}, Distt. {dist}, {state} - {pin}\n"
            f"Voter ID (EPIC): {epic}\n"
            f"Contact: {phone}\n"
            "Specimen: EDTA Blood\n"
            "Requested Tests: CBC, LFT, Serum Creatinine 1.1 mg/dL\n"
            "Ordered by: Dr. Ramesh Srivastava\n"
        )
        put(rel1, txt1)
        rm(rel1, f"{g} {s}", "PATIENT_NAME")
        rm(rel1, mrn, "MRN")
        rm(rel1, epic, "INSURANCE_ID")
        rm(rel1, phone, "PHONE")
        rm(rel1, village, "VILLAGE", critical=False)
        rm(rel1, pin, "PIN", critical=False)
        kp(rel1, "Serum Creatinine 1.1 mg/dL")
        kp(rel1, "Dr. Ramesh Srivastava")
        kp(rel1, dist)

        # 2. Death Summary (only for i == 0)
        if i == 0:
            rel2 = "summaries/death_00.txt"
            txt2 = (
                "DEATH SUMMARY\n"
                f"Deceased Name: {g} {s}\n"
                f"W/o {rg} {rs}\n"
                f"Age at death: {age} Yrs\n"
                f"Driving Licence: {dl}\n"
                f"Ration Card: {rc}\n"
                "Date of Expiry: 14/06/2026\n"
                "Cause of Death: Acute myocardial infarction (I21.9)\n"
                "Certifying Officer: Dr. Anjali Mehrotra\n"
            )
            put(rel2, txt2)
            rm(rel2, f"{g} {s}", "PATIENT_NAME")
            rm(rel2, f"{rg} {rs}", "RELATIVE_NAME", critical=False)
            rm(rel2, dl, "INSURANCE_ID")
            rm(rel2, rc, "INSURANCE_ID")
            kp(rel2, "Acute myocardial infarction (I21.9)")
            kp(rel2, "Dr. Anjali Mehrotra")

        # 3. OT Notes (for i == 1)
        if i == 1:
            rel3 = "ot/ot_note_01.txt"
            kin = HOLDOUT_KIN[(seed + i) % len(HOLDOUT_KIN)]
            txt3 = (
                "OPERATION THEATRE NOTES\n"
                f"Patient: {g} {s} ({age} Y / {sex})\n"
                f"UHID: {mrn}\n"
                f"Consent signed by: {rg} {kin}\n"
                "Surgeon: Dr. Jagdish Tandon\n"
                "Procedure: Open appendicectomy under spinal anaesthesia.\n"
                "Vitals stable: BP 118/74 mmHg, SpO2 99%.\n"
            )
            put(rel3, txt3)
            rm(rel3, f"{g} {s}", "PATIENT_NAME")
            rm(rel3, mrn, "MRN")
            rm(rel3, rg, "RELATIVE_NAME", critical=False)
            kp(rel3, "Open appendicectomy under spinal anaesthesia")
            kp(rel3, "Dr. Jagdish Tandon")

        # 4. Urdu script fragment (for i == 4)
        if i == 4:
            u_pat, u_rel = HOLDOUT_URDU[seed % len(HOLDOUT_URDU)]
            rel4 = "notes/urdu_04.txt"
            txt4 = (
                "OPD NOTE\n"
                f"نام: {u_pat}\n"
                f"ولد: {u_rel}\n"
                f"Phone: {phone}\n"
                "Diagnosis: Iron deficiency anaemia (D50.9)\n"
                "Rx: Tab Ferrous sulphate 200 mg 0-1-0 x 90 days\n"
            )
            put(rel4, txt4)
            rm(rel4, u_pat, "PATIENT_NAME")
            rm(rel4, u_rel, "RELATIVE_NAME", critical=False)
            rm(rel4, phone, "PHONE")
            kp(rel4, "Iron deficiency anaemia (D50.9)")

    out.joinpath("holdout_answer.json").write_text(
        json.dumps({"remove": remove, "keep": keep}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    return out


def check_holdout(seeds: list[int], work: Path) -> int:
    fails: list[dict[str, Any]] = []
    totals = 0
    kept_total = kept_ok = 0
    for s in seeds:
        ds = work / f"holdout_{s:04d}"
        generate_holdout(s, ds)
        r = run_cli(ds / "input", ds / "out", f"holdout-sec-{s}", ds / "sbx")
        if r["code"] != 0:
            fails.append({"seed": s, "kind": "exit_code", "detail": r["stderr"][-200:]})
            continue
        ans = json.loads((ds / "holdout_answer.json").read_text(encoding="utf-8"))
        rep = json.loads((ds / "out" / "report.json").read_text(encoding="utf-8"))
        sha2out = {f["input_sha256"]: f.get("output") for f in rep["files"]}
        import hashlib
        views: dict[str, View] = {}
        for p in (ds / "input").rglob("*"):
            if p.is_file():
                rel = p.relative_to(ds / "input").as_posix()
                out_rel = sha2out.get(hashlib.sha256(p.read_bytes()).hexdigest())
                if out_rel and (ds / "out" / out_rel).exists():
                    views[rel] = View(file_view(ds / "out" / out_rel))
        for item in ans["remove"]:
            totals += 1
            v = views.get(item["file"])
            if v and contains_surface(v.norm, v.runs, item["surface"], item["type"]):
                fails.append({"seed": s, "kind": "leak", "type": item["type"], "file": item["file"], "surface": item["surface"]})
        for item in ans["keep"]:
            kept_total += 1
            v = views.get(item["file"])
            if v and norm(item["text"]) in v.norm:
                kept_ok += 1
            else:
                fails.append({"seed": s, "kind": "lost_clinical", "file": item["file"], "text": item["text"]})

    by_kind = Counter((f["kind"], f.get("type", "")) for f in fails)
    print(json.dumps({
        "seeds": len(seeds), "entities": totals, "leaks": sum(1 for f in fails if f["kind"] == "leak"),
        "kept_pct": round(100 * kept_ok / max(kept_total, 1), 2),
        "by_kind": {f"{k}:{t}": c for (k, t), c in by_kind.most_common()},
    }, indent=2, ensure_ascii=False))
    for f in fails[:20]:
        print("  ", json.dumps(f, ensure_ascii=False))
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="WardGuard holdout variation test")
    ap.add_argument("--seeds", default="1-5")
    ap.add_argument("--work", type=Path, required=True)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    return check_holdout(parse_seeds(a.seeds), a.work)


if __name__ == "__main__":
    sys.exit(main())
