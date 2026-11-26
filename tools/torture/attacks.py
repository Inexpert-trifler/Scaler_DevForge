"""Independent A1-A7 Privacy Attack Arena (does NOT import tools/attack_sim.py or wardguard/).

Implements the adversary suite from kit docs/ATTACKS.md & TESTLAB_BUILD_GUIDE.md §6.5:
  - A1: Direct identifier exposure (content + side channels)
  - A2/A3: Single-record quasi-identifier linkage risk against 5x registry
  - A4: Profile pooling by shared PSN
  - A5: Targeted known-facts + global-shift recovery (>= 2 distinct high-confidence re-ids)
  - A6: Pseudonym inversion (transforms: case, digits, MD5/SHA-1/SHA-256/SHA-512 prefixes, base64, reverse, MRN/phone cores)
  - A7: Cross-release correlation under rotated secret (PSNs & shifted dates must not collide)

Usage:
  python -m tools.torture.attacks --seeds 1-20 --work /tmp/wg_attacks
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.torture.check import View, contains_surface, file_view, parse_date_any, parse_seeds, read_table, run_cli  # noqa: E402
from tools.torture.gen import generate  # noqa: E402

PSN_RE = re.compile(r"\bPSN-([0-9A-Z]{4,})\b")
DATE_RE = re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}-\d{2}-\d{4}|\d{2}\.\d{2}\.\d{4})\b")


def _extract_records(release_dir: Path, is_raw: bool = False) -> list[dict[str, Any]]:
    """Extract per-record quasi-identifiers and text independently from release (or raw input)."""
    loc_to_psn: dict[tuple[str, str], str | None] = {}
    rec_path = release_dir / "records.jsonl"
    if rec_path.exists() and not is_raw:
        for ln in rec_path.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                r = json.loads(ln)
                loc_to_psn[(r["file"], r["loc"])] = r.get("patient")

    scan_root = release_dir if is_raw else (release_dir / "sanitized")
    if not scan_root.exists():
        return []

    records: list[dict[str, Any]] = []
    for p in sorted(scan_root.rglob("*")):
        if not p.is_file():
            continue
        file_key = p.relative_to(scan_root).as_posix() if is_raw else p.relative_to(release_dir).as_posix()
        suf = p.suffix.lower()
        if suf in (".csv", ".tsv"):
            rows = read_table(p)
            if not rows:
                continue
            hdr = [h.strip().lower() for h in rows[0]]
            for ri, row in enumerate(rows[1:]):
                loc = f"row:{ri}"
                rec = {"id": f"{file_key}#{loc}", "file": file_key, "loc": loc,
                       "psn": loc_to_psn.get((file_key, loc)), "text": " ".join(row),
                       "dates": [], "conditions": []}
                for ci, val in enumerate(row):
                    hn = hdr[ci] if ci < len(hdr) else ""
                    v = val.strip()
                    _parse_field_clue(rec, hn, v)
                records.append(rec)
        elif suf == ".json":
            try:
                obj = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            if isinstance(obj, dict) and obj.get("resourceType") == "Bundle":
                loc = "doc"
                rec = {"id": f"{file_key}#doc", "file": file_key, "loc": loc,
                       "psn": loc_to_psn.get((file_key, loc)), "text": json.dumps(obj, ensure_ascii=False),
                       "dates": [], "conditions": []}
                _walk_json(obj, rec)
                records.append(rec)
            elif isinstance(obj, dict) and isinstance(obj.get("visits"), list):
                for vi, item in enumerate(obj["visits"]):
                    loc = f"/visits/{vi}"
                    rec = {"id": f"{file_key}#{loc}", "file": file_key, "loc": loc,
                           "psn": loc_to_psn.get((file_key, loc)), "text": json.dumps(item, ensure_ascii=False),
                           "dates": [], "conditions": []}
                    _walk_json(item, rec)
                    records.append(rec)
            else:
                loc = "doc"
                rec = {"id": f"{file_key}#doc", "file": file_key, "loc": loc,
                       "psn": loc_to_psn.get((file_key, loc)), "text": json.dumps(obj, ensure_ascii=False),
                       "dates": [], "conditions": []}
                _walk_json(obj, rec)
                records.append(rec)
        else:
            txt = p.read_text(encoding="utf-8", errors="replace")
            loc = "doc"
            rec = {"id": f"{file_key}#doc", "file": file_key, "loc": loc,
                   "psn": loc_to_psn.get((file_key, loc)), "text": txt,
                   "dates": [], "conditions": []}
            _parse_text_clues(rec, txt)
            records.append(rec)
    return records


def _parse_text_clues(rec: dict[str, Any], txt: str) -> None:
    if not rec.get("phone"):
        m = re.search(r"(?:\+91[- ]?)?([6-9]\d{9})\b", txt)
        if m:
            rec["phone"] = m.group(1)
    if not rec.get("email"):
        m = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", txt)
        if m:
            rec["email"] = m.group(0).lower()
    if not rec.get("pin"):
        m = re.search(r"\b([1-8]\d{2}[\d*]{3})\b", txt)
        if m:
            rec["pin"] = m.group(1)
    if not rec.get("age_range"):
        m = re.search(r"\b(\d{1,2})-(\d{1,2})\b", txt)
        if m and int(m.group(1)) < int(m.group(2)) <= 100 and (int(m.group(2)) - int(m.group(1))) in (4, 9):
            rec["age_range"] = (int(m.group(1)), int(m.group(2)))
        elif "90+" in txt:
            rec["age_range"] = (90, 120)
    if not rec.get("gender"):
        m = re.search(r"\b(male|female|पुरुष|महिला)\b", txt, re.I)
        if m:
            rec["gender"] = "M" if m.group(1).lower() in ("male", "पुरुष") else "F"
    if not rec.get("district"):
        m = re.search(r"(?:distt?\.?|district|जिला)[:\s]+([A-Za-z\u0900-\u097f ]{2,25})", txt, re.I)
        if m:
            rec["district"] = m.group(1).strip().split(",")[0].split("\n")[0].strip()
    for dm in DATE_RE.findall(txt):
        if dm not in rec["dates"]:
            rec["dates"].append(dm)


def _parse_field_clue(rec: dict[str, Any], key: str, val: str) -> None:
    if not val:
        return
    if any(k in key for k in ("gender", "sex", "ling", "लिंग")) or key in ("s",):
        v = val.strip().upper()
        if v.startswith(("M", "पु")):
            rec["gender"] = "M"
        elif v.startswith(("F", "म")):
            rec["gender"] = "F"
    elif any(k in key for k in ("age", "umar", "आयु")) or key == "a":
        m = re.search(r"(\d+)-(\d+)", val)
        if m:
            rec["age_range"] = (int(m.group(1)), int(m.group(2)))
        elif "90+" in val:
            rec["age_range"] = (90, 120)
        elif val.isdigit():
            rec["age_range"] = (int(val), int(val))
    elif any(k in key for k in ("dob", "birth", "जन्म")):
        m = re.search(r"\b(19\d\d|20\d\d)\b", val)
        if m and len(val.strip()) == 4:
            rec["birth_year"] = m.group(1)
    elif any(k in key for k in ("dist", "जिला", "jila")):
        rec["district"] = val
    elif any(k in key for k in ("teh", "tahsil", "तहसील")):
        rec["tehsil"] = val
    elif any(k in key for k in ("vill", "gram", "gaon", "ग्राम")):
        rec["village"] = val
    elif any(k in key for k in ("pin", "postal", "पिन")) or key == "pc":
        rec["pin"] = val
    elif any(k in key for k in ("diag", "dx", "cond", "निदान", "bimari")):
        rec["conditions"].append(val)
    elif any(k in key for k in ("date", "dt", "tithi", "तिथि")):
        rec["dates"].append(val)
    elif any(k in key for k in ("mob", "phone", "contact", "मोबाइल")):
        d = re.sub(r"\D", "", val)
        if len(d) >= 10:
            rec["phone"] = d[-10:]
    _parse_text_clues(rec, val)


def _walk_json(obj: Any, rec: dict[str, Any]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _walk_json(v, rec)
            else:
                _parse_field_clue(rec, str(k).lower(), str(v))
    elif isinstance(obj, list):
        for x in obj:
            _walk_json(x, rec)


def _filter_candidates(registry: list[dict[str, str]], rec: dict[str, Any]) -> list[dict[str, str]]:
    cur = list(registry)
    checks = [
        ("phone", lambda c, v: re.sub(r"\D", "", c.get("phone", ""))[-10:] == v),
        ("email", lambda c, v: c.get("email", "").lower() == v),
        ("district", lambda c, v: c.get("district", "").lower() == v.lower()),
        ("gender", lambda c, v: c.get("gender", "").upper() == v),
        ("birth_year", lambda c, v: c.get("birth_year", "") == str(v)),
        ("tehsil", lambda c, v: c.get("tehsil", "").lower() == v.lower()),
        ("village", lambda c, v: c.get("village", "").lower() == v.lower()),
    ]
    for attr, fn in checks:
        val = rec.get(attr)
        if val:
            nxt = [c for c in cur if fn(c, val)]
            if nxt:
                cur = nxt
    if rec.get("age_range"):
        lo, hi = rec["age_range"]
        nxt = [c for c in cur if c.get("age", "").isdigit() and lo <= int(c["age"]) <= hi]
        if nxt:
            cur = nxt
    if rec.get("pin"):
        p_pref = rec["pin"].replace("*", "").strip()
        if p_pref:
            nxt = [c for c in cur if c.get("pin", "").startswith(p_pref)]
            if nxt:
                cur = nxt
    return cur


def _score_candidates(cands: list[dict[str, str]], text: str) -> dict[str, float]:
    if not cands:
        return {}
    low = text.lower()
    w: dict[str, float] = {}
    for c in cands:
        sc = 1.0
        full = c.get("name", "").lower().strip()
        parts = full.split()
        rel = c.get("relative_name", "").lower().strip()
        house = c.get("house", "").lower().strip()
        if full and full in low:
            sc += 60.0
        if parts and len(parts[0]) > 2 and parts[0] in low:
            sc += 8.0
        if len(parts) > 1 and len(parts[-1]) > 2 and parts[-1] in low:
            sc += 3.0
        if rel and len(rel) > 3 and rel in low:
            sc += 8.0
        if house and len(house) > 2 and house in low:
            sc += 2.0
        w[c["rid"]] = sc
    tot = sum(w.values()) or 1.0
    return {k: v / tot for k, v in w.items()}


def _pool_by_psn(records: list[dict[str, Any]], *, is_raw: bool = False, ans: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    loc_to_pid = {}
    if is_raw and ans:
        loc_to_pid = {(r["file"], r["loc"]): r["patient"] for r in ans.get("records", []) if r.get("patient")}
    profs: dict[str, dict[str, Any]] = {}
    for r in records:
        k = (loc_to_pid.get((r.get("in_rel", r["file"]), r["loc"])) if is_raw else r["psn"]) or r["id"]
        if k not in profs:
            profs[k] = {"id": f"prof:{k}", "psn": r["psn"], "text": "", "dates": [], "conditions": []}
        pr = profs[k]
        pr["text"] += " " + r["text"]
        for attr in ("phone", "email", "district", "gender", "birth_year", "tehsil", "village", "pin"):
            if r.get(attr) and not pr.get(attr):
                pr[attr] = r[attr]
        if r.get("age_range"):
            if not pr.get("age_range"):
                pr["age_range"] = r["age_range"]
            else:
                lo = max(pr["age_range"][0], r["age_range"][0])
                hi = min(pr["age_range"][1], r["age_range"][1])
                if lo <= hi:
                    pr["age_range"] = (lo, hi)
        for d in r["dates"]:
            if d not in pr["dates"]:
                pr["dates"].append(d)
        for c in r["conditions"]:
            if c not in pr["conditions"]:
                pr["conditions"].append(c)
    return profs


def run_a6_inversion(release_dir: Path, ans: dict[str, Any]) -> int:
    """A6 Pseudonym inversion: build transform dictionary from all originals, check against emitted PSNs."""
    psns: set[str] = set()
    rec_path = release_dir / "records.jsonl"
    if rec_path.exists():
        for ln in rec_path.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                p = json.loads(ln).get("patient")
                if p:
                    psns.add(p)
    for f in (release_dir / "sanitized").rglob("*"):
        if f.is_file():
            for m in PSN_RE.findall(f.read_text(encoding="utf-8", errors="replace")):
                psns.add(f"PSN-{m}")

    psn_cores = {p.split("-", 1)[1].lower() if "-" in p else p.lower(): p for p in psns}
    if not psn_cores:
        return 0

    sensitive_digits: set[str] = set()
    transforms: set[str] = set()
    for pid, pmeta in ans.get("people", {}).items():
        vals = [pid, pmeta.get("name", ""), pmeta.get("phone", ""), pmeta.get("aadhaar", ""),
                pmeta.get("abha", ""), pmeta.get("pan", ""), *pmeta.get("mrns", [])]
        for v in vals:
            if not v:
                continue
            dig = re.sub(r"\D", "", v)
            if len(dig) >= 5:
                sensitive_digits.add(dig)
            for s in {v, v.lower(), v.upper(), dig, v[::-1]}:
                if not s:
                    continue
                b = s.encode("utf-8")
                b64 = base64.b64encode(b).decode("ascii").lower()
                transforms.add(s.lower())
                transforms.add(b64)
                for hfn in (hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512):
                    hd = hfn(b).hexdigest().lower()
                    transforms.add(hd)
                    transforms.add(hd[:8])
                    transforms.add(hd[:6])

    hits = 0
    for core in psn_cores:
        if any(t == core or t.startswith(core) for t in transforms if len(core) >= 6):
            hits += 1
        elif any(d in core or core in d for d in sensitive_digits if len(d) >= 5):
            hits += 1
    return hits


def run_a7_cross_release(out1: Path, out2: Path, ans: dict[str, Any]) -> dict[str, int]:
    """A7 Cross-release correlation: 0 shared PSNs AND 0 shared patient date shifts across secrets."""
    psn1 = set(PSN_RE.findall((out1 / "records.jsonl").read_text(encoding="utf-8")))
    psn2 = set(PSN_RE.findall((out2 / "records.jsonl").read_text(encoding="utf-8")))
    shared_psns = len(psn1 & psn2)

    # Map file+loc -> true patient id
    loc_to_pid = {(r["file"], r["loc"]): r["patient"] for r in ans.get("records", []) if r.get("patient")}
    collided_pids: set[str] = set()
    for item in ans.get("los", []):
        rel = "sanitized/" + item["file"]
        p1, p2 = out1 / rel, out2 / rel
        if not (p1.exists() and p2.exists()):
            continue
        r1, r2 = read_table(p1), read_table(p2)
        ri = int(item["loc"].split(":")[1]) + 1
        if ri < len(r1) and ri < len(r2):
            if r1[ri][item["col_in"]].strip() == r2[ri][item["col_in"]].strip():
                pid = loc_to_pid.get((item["file"], item["loc"]), f"{item['file']}#{item['loc']}")
                collided_pids.add(pid)
    return {"shared_psns": shared_psns, "shared_date_patients": len(collided_pids)}


def evaluate_attacks(
    ds_dir: Path,
    release_dir: Path,
    *,
    is_raw: bool = False,
    rotated_release_dir: Path | None = None,
) -> dict[str, Any]:
    ans = json.loads((ds_dir / "answer.json").read_text(encoding="utf-8"))
    reg = list(csv.DictReader(io.StringIO((ds_dir / "attacker" / "registry.csv").read_text(encoding="utf-8"))))
    facts = [json.loads(ln) for ln in (ds_dir / "attacker" / "known_facts.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
    reg_by_id = {r["rid"]: r for r in reg}
    real_rids = sorted(ans["people"])

    records = _extract_records(release_dir, is_raw=is_raw)
    profiles = _pool_by_psn(records, is_raw=is_raw, ans=ans)

    # Map record/profile -> true patient rid using sha256->input_rel from report.json so renamed files map accurately
    out_to_in_rel: dict[str, str] = {}
    if not is_raw and (release_dir / "report.json").exists():
        rep = json.loads((release_dir / "report.json").read_text(encoding="utf-8"))
        sha_to_in = {meta["sha256"]: rel for rel, meta in ans.get("files", {}).items() if meta.get("sha256")}
        for fe in rep.get("files", []):
            if fe.get("output") and fe.get("input_sha256") in sha_to_in:
                out_to_in_rel[fe["output"]] = sha_to_in[fe["input_sha256"]]

    loc_to_pid = {(r["file"], r["loc"]): r["patient"] for r in ans.get("records", []) if r.get("patient")}
    psn_to_pids: dict[str, set[str]] = defaultdict(set)
    for r in records:
        in_rel = r["file"] if is_raw else out_to_in_rel.get(r["file"], r["file"].removeprefix("sanitized/"))
        r["in_rel"] = in_rel
        pid_true = loc_to_pid.get((in_rel, r["loc"]))
        if pid_true and r["psn"]:
            psn_to_pids[r["psn"]].add(pid_true)

    # A1: Direct leak across real people
    scan_dir = release_dir if is_raw else (release_dir / "sanitized")
    views = [View(file_view(p)) for p in sorted(scan_dir.rglob("*")) if p.is_file()] if scan_dir.exists() else []
    a1_hits = 0
    for pid in real_rids:
        pm = ans["people"][pid]
        exposed = False
        for v in views:
            if contains_surface(v.norm, v.runs, pm["name"], "PATIENT_NAME") or contains_surface(v.norm, v.runs, pm["phone"], "PHONE"):
                exposed = True
                break
        if exposed:
            a1_hits += 1
    a1_risk = a1_hits / max(len(real_rids), 1)

    # A2/A3: Single-record linkage risk (true person probability, macro-averaged over registry cohort per ATTACKS.md)
    all_rids = [r["rid"] for r in reg]
    rec_risk: dict[str, float] = {pid: 0.0 for pid in real_rids}
    for r in records:
        true_pid = loc_to_pid.get((r["in_rel"], r["loc"]))
        if not true_pid:
            continue
        cands = _filter_candidates(reg, r)
        probs = _score_candidates(cands, r["text"])
        p_true = probs.get(true_pid, 0.0)
        if p_true > rec_risk.get(true_pid, 0.0):
            rec_risk[true_pid] = p_true
    a3_mean = sum(rec_risk.values()) / max(len(all_rids), 1)
    a3_ge50 = sum(1 for v in rec_risk.values() if v >= 0.5) / max(len(real_rids), 1)

    # A4: Profile pooling by PSN (true person probability, macro-averaged over registry cohort)
    prof_risk: dict[str, float] = {pid: 0.0 for pid in real_rids}
    high_conf_dates: dict[str, set[datetime]] = defaultdict(set)
    for pr in profiles.values():
        cands = _filter_candidates(reg, pr)
        probs = _score_candidates(cands, pr["text"])
        target_pids = (psn_to_pids.get(pr["psn"], set()) if pr["psn"] else set()) or set(real_rids)
        for rid, p_val in probs.items():
            if rid in prof_risk and rid in target_pids:
                if p_val > prof_risk[rid]:
                    prof_risk[rid] = p_val
            if p_val >= 0.90 and rid in ans["people"]:
                for ds in pr["dates"]:
                    d = parse_date_any(ds)
                    if d:
                        high_conf_dates[rid].add(d)
    a4_mean = sum(prof_risk.values()) / max(len(all_rids), 1)
    a4_ge50 = sum(1 for v in prof_risk.values() if v >= 0.5) / max(len(real_rids), 1)

    # A5: Targeted known facts + independent global shift recovery
    # Under a true global shift delta, EVERY known visit date kd of pid appears at kd + delta in released dates.
    person_deltas: dict[str, set[int]] = {}
    for kf in facts:
        pid = kf["rid"]
        if pid not in high_conf_dates:
            continue
        rel_dates = high_conf_dates[pid]
        k_dts = [d for ds in kf.get("visit_dates", []) if (d := parse_date_any(ds))]
        if not k_dts:
            continue
        deltas = {
            (rd - k_dts[0]).days
            for rd in rel_dates
            if -180 <= (rd - k_dts[0]).days <= 180 and rd != k_dts[0]
            and all((kd + timedelta(days=(rd - k_dts[0]).days)) in rel_dates for kd in k_dts)
        }
        if deltas:
            person_deltas[pid] = deltas
    recovered_shift = None
    if len(person_deltas) >= 2:
        votes: dict[int, int] = defaultdict(int)
        for dset in person_deltas.values():
            for d in dset:
                votes[d] += 1
        best_d, cnt = max(votes.items(), key=lambda x: x[1])
        if cnt >= 2 and (cnt / len(person_deltas)) >= 0.60:
            recovered_shift = best_d

    a5_probs: list[float] = []
    for kf in facts:
        pid = kf["rid"]
        pers = reg_by_id.get(pid, {})
        cond = kf.get("condition_hint", "").lower()
        matches = []
        for pr in profiles.values():
            cond_ok = not cond or (cond in pr["text"].lower()) or any(cond in c.lower() for c in pr["conditions"])
            g_ok = not pr.get("gender") or pr["gender"] == pers.get("gender")
            d_ok = not pr.get("district") or pr["district"].lower() == pers.get("district", "").lower()
            if cond_ok and g_ok and d_ok:
                matches.append(pr)
        a5_probs.append((1.0 / len(matches)) if matches else 0.0)
    a5_mean = sum(a5_probs) / max(len(a5_probs), 1)

    a6 = 0 if is_raw else run_a6_inversion(release_dir, ans)
    a7 = {"shared_psns": 0, "shared_date_patients": 0}
    if not is_raw and rotated_release_dir is not None:
        a7 = run_a7_cross_release(release_dir, rotated_release_dir, ans)

    return {
        "A1_pct": round(100 * a1_risk, 2),
        "A3_mean_pct": round(100 * a3_mean, 2),
        "A3_ge50_pct": round(100 * a3_ge50, 2),
        "A4_mean_pct": round(100 * a4_mean, 2),
        "A4_ge50_pct": round(100 * a4_ge50, 2),
        "A5_mean_pct": round(100 * a5_mean, 2),
        "global_shift_recovered": recovered_shift,
        "A6_inversion_hits": a6,
        "A7_shared_psns": a7["shared_psns"],
        "A7_shared_date_patients": a7["shared_date_patients"],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Independent A1-A7 Attack Arena on torture datasets")
    ap.add_argument("--seeds", default="1-10")
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--patients", type=int, default=100)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)

    raw_agg: list[dict[str, Any]] = []
    rel_agg: list[dict[str, Any]] = []
    fails: list[str] = []

    for s in parse_seeds(a.seeds):
        ds = a.work / f"seed_{s:04d}"
        if ds.exists():
            shutil.rmtree(ds)
        generate(s, ds, a.patients)
        r1 = run_cli(ds / "input", ds / "outA", "attack-secret-A", ds / "sbx")
        r2 = run_cli(ds / "input", ds / "outB", "attack-secret-B", ds / "sbx")
        if r1["code"] != 0 or r2["code"] != 0:
            fails.append(f"seed {s}: non-zero exit")
            continue
        raw_m = evaluate_attacks(ds, ds / "input", is_raw=True)
        rel_m = evaluate_attacks(ds, ds / "outA", is_raw=False, rotated_release_dir=ds / "outB")
        raw_agg.append(raw_m)
        rel_agg.append(rel_m)
        if rel_m["A1_pct"] > 0 or rel_m["A6_inversion_hits"] > 0 or rel_m["A7_shared_psns"] > 0 or rel_m["global_shift_recovered"] is not None:
            fails.append(f"seed {s}: invariant fail {rel_m}")

    def _avg(lst: list[dict[str, Any]], k: str) -> float:
        return round(sum(x[k] for x in lst) / max(len(lst), 1), 2)

    total_patients = len(rel_agg) * a.patients
    summary = {
        "seeds": len(rel_agg),
        "patients_per_seed": a.patients,
        "raw": {k: _avg(raw_agg, k) for k in ("A1_pct", "A3_mean_pct", "A4_mean_pct", "A5_mean_pct")},
        "release": {
            "A1_pct": _avg(rel_agg, "A1_pct"),
            "A3_mean_pct": _avg(rel_agg, "A3_mean_pct"),
            "A4_mean_pct": _avg(rel_agg, "A4_mean_pct"),
            "A5_mean_pct": _avg(rel_agg, "A5_mean_pct"),
            "A6_inversion_total": sum(x["A6_inversion_hits"] for x in rel_agg),
            "A7_shared_psns_total": sum(x["A7_shared_psns"] for x in rel_agg),
            "A7_shared_date_patients_total": sum(x["A7_shared_date_patients"] for x in rel_agg),
            "A7_shared_date_rate_pct": round(100 * sum(x["A7_shared_date_patients"] for x in rel_agg) / max(total_patients, 1), 2),
            "global_shift_recovered_count": sum(1 for x in rel_agg if x["global_shift_recovered"] is not None),
        },
    }
    print(json.dumps(summary, indent=2))
    rel = summary["release"]
    if (
        fails
        or rel["A1_pct"] > 0.0
        or rel["A3_mean_pct"] >= 27.7
        or rel["A4_mean_pct"] >= 16.7
        or rel["A5_mean_pct"] >= 40.1
        or rel["A6_inversion_total"] > 0
        or rel["A7_shared_psns_total"] > 0
        or rel["A7_shared_date_rate_pct"] >= 1.5
        or rel["global_shift_recovered_count"] > 0
    ):
        for f in fails[:10]:
            print("FAIL:", f)
        print("ATTACKS FAIL")
        return 1
    print("ATTACKS OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
