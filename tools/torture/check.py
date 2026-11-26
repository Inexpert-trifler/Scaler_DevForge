"""Torture checker: run the real WardGuard CLI on generated datasets and score them.

Usage:
  python -m tools.torture.check --seeds 1-20 --work /path/to/scratch [--patients 14] [--no-mr]

For each seed it:
  1. generates a dataset (tools/torture/gen.py) with an answer key,
  2. runs `python main.py` (real CLI, private TMPDIR/HOME) twice with one secret and once with another,
  3. checks leaks (per file and globally, normalized: NFKC, case, whitespace, Devanagari digits,
     digit-only numbers, decoded base64 and JSON escapes), kept clinical values, linkage
     (pairwise P/R, homonym/twin false merges), length-of-stay preservation and invariants
     (exit code, report accounting, quarantine, no raw copies, input unchanged, determinism,
     secret sensitivity, valid output formats, clean stdout/stderr, no temp files).
Exit code 0 only if there are zero critical failures.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from collections import Counter, defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.torture.gen import generate  # noqa: E402

DEVA_TO_ASCII = str.maketrans("०१२३४५६७८९", "0123456789")
ZW = dict.fromkeys(map(ord, "​‌‍﻿­"), None)
B64_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
DIGIT_RUN = re.compile(r"\d(?:[\d \-.()+/]*\d)?")
PSN_RE = re.compile(r"PSN-[0-9A-Z]{4,}")


def norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).translate(ZW).translate(DEVA_TO_ASCII)
    return re.sub(r"\s+", " ", s).strip().casefold()


def digits(s: str) -> str:
    return re.sub(r"\D", "", s.translate(DEVA_TO_ASCII))


def tree_hash(root: Path, skip_report_timing: bool = False) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            data = p.read_bytes()
            if skip_report_timing and p.name == "report.json" and p.parent == root:
                try:
                    r = json.loads(data)
                    r.pop("timing", None); r.pop("resources", None)
                    data = json.dumps(r, sort_keys=True).encode()
                except Exception:
                    pass
            h.update(p.relative_to(root).as_posix().encode() + b"\0" + hashlib.sha256(data).digest())
    return h.hexdigest()


def run_cli(inp: Path, out: Path, secret: str, sandbox: Path) -> dict[str, Any]:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    tmp, home = sandbox / "tmp", sandbox / "home"
    for d in (tmp, home):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    env = {"PATH": os.environ.get("PATH", ""), "RAKSHA_SECRET": secret, "TMPDIR": str(tmp), "HOME": str(home),
           "PYTHONHASHSEED": "random", "LANG": "C.UTF-8"}
    t0 = time.time()
    p = subprocess.run([sys.executable, str(REPO / "main.py"), "--input", str(inp), "--output", str(out)],
                       capture_output=True, env=env, cwd=str(sandbox), timeout=900)
    return {"code": p.returncode, "stdout": p.stdout.decode("utf-8", "replace"),
            "stderr": p.stderr.decode("utf-8", "replace"), "secs": time.time() - t0,
            "tmp_left": [str(x) for x in tmp.rglob("*")], "home_left": [str(x) for x in home.rglob("*")]}


def file_view(path: Path) -> str:
    """Everything a reader can recover from an output file (raw, JSON-unescaped, base64-decoded)."""
    raw = path.read_bytes()
    txt = raw.decode("utf-8", "replace")
    parts = [txt]
    try:
        parts.append(json.dumps(json.loads(txt), ensure_ascii=False))
    except Exception:
        pass
    for m in B64_RE.finditer(txt):
        tok = m.group(0)
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                b = dec(tok + "=" * (-len(tok) % 4))
                s = b.decode("utf-8")
                if sum(ch.isprintable() for ch in s) > 0.9 * len(s):
                    parts.append(s)
                break
            except Exception:
                continue
    return "\n".join(parts)


def contains_surface(view_norm: str, view_digit_runs: list[str], surface: str, etype: str) -> bool:
    d = digits(surface)
    if etype in {"AGE", "AGE90"}:
        return re.search(r"(?<![\d\-+])" + re.escape(norm(surface)), view_norm) is not None
    if etype in {"PHONE", "AADHAAR", "ABHA_NUMBER", "PIN"} or (len(d) >= 8 and len(d) >= 0.6 * len(surface.replace(" ", ""))):
        if len(d) < 6:
            return False
        if etype == "PHONE" and len(d) > 10:
            d = d[-10:]
        return any(d in run for run in view_digit_runs)
    s = norm(surface)
    if not s:
        return False
    pat = r"(?<![\wऀ-ॿ])" + re.escape(s) + r"(?![\wऀ-ॿ])"
    return re.search(pat, view_norm) is not None


class View:
    def __init__(self, text: str) -> None:
        self.norm = norm(text)
        self.runs = [digits(m.group(0)) for m in DIGIT_RUN.finditer(text.translate(DEVA_TO_ASCII))]


def parse_date_any(s: str) -> date | None:
    s = s.strip()
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d.%m.%Y", "%d %b %Y", "%d-%b-%Y", "%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def read_table(path: Path) -> list[list[str]]:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            txt = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        return []
    sample = txt.split("\n", 1)[0]
    delim = max([",", ";", "\t", "|"], key=sample.count)
    return list(csv.reader(io.StringIO(txt), delimiter=delim))


def check_seed(seed: int, work: Path, patients: int, mr: bool) -> dict[str, Any]:
    ds = work / f"seed_{seed:04d}"
    if ds.exists():
        shutil.rmtree(ds)
    generate(seed, ds, patients)
    inp, ans = ds / "input", json.loads((ds / "answer.json").read_text(encoding="utf-8"))
    fails: list[dict[str, Any]] = []

    def fail(kind: str, sev: str, **kw: Any) -> None:
        fails.append({"seed": seed, "kind": kind, "sev": sev, **kw})

    in_hash_before = tree_hash(inp)
    r1 = run_cli(inp, ds / "out1", "torture-secret-A", ds / "sbx")
    out = ds / "out1"
    if tree_hash(inp) != in_hash_before:
        fail("input_modified", "S0")
    if r1["code"] != 0:
        fail("exit_code", "S0", detail=r1["stderr"][-400:])
        return {"seed": seed, "fails": fails, "stats": {}}
    if r1["tmp_left"] or r1["home_left"]:
        fail("temp_leftovers", "S0", detail=(r1["tmp_left"] + r1["home_left"])[:5])
    extra = {p.name for p in out.iterdir()} - {"sanitized", "report.json", "records.jsonl"}
    if extra:
        fail("unexpected_output", "S2", detail=sorted(extra))

    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    sha2out: dict[str, dict[str, Any]] = {f["input_sha256"]: f for f in report.get("files", [])}
    in2out: dict[str, Path | None] = {}
    for rel, meta in ans["files"].items():
        entry = sha2out.get(meta["sha256"])
        if entry is None:
            fail("report_missing_file", "S0", file=rel)
            in2out[rel] = None
            continue
        o = entry.get("output")
        in2out[rel] = (out / o) if o else None
        if entry.get("status") == "sanitized" and (o is None or not (out / o).exists()):
            fail("report_output_missing", "S0", file=rel)
        if meta["expect"] == "quarantine" and entry.get("status") != "quarantined":
            fail("not_quarantined", "S1", file=rel)
        if meta["expect"] == "sanitize" and entry.get("status") != "sanitized":
            fail("wrongly_quarantined", "S2", file=rel, reason=entry.get("reason"))
        if o and (out / o).exists() and (out / o).read_bytes() == (inp / rel).read_bytes():
            if any(x["file"] == rel and x["channel"] != "filename" for x in ans["remove"]):
                fail("raw_copy", "S0", file=rel)
    if len(report.get("files", [])) != len(ans["files"]):
        fail("report_count", "S1", detail=f'{len(report.get("files", []))} vs {len(ans["files"])}')

    # output validity
    for rel, o in in2out.items():
        if not o or not o.exists():
            continue
        fmt = ans["files"][rel]["format"]
        try:
            o.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            fail("output_not_utf8", "S1", file=rel)
        if fmt in ("json", "fhir") and rel.endswith((".jsonl", ".ndjson")):
            try:
                for ln in o.read_text(encoding="utf-8").splitlines():
                    if ln.strip():
                        json.loads(ln)
            except Exception:
                fail("output_invalid_ndjson", "S1", file=rel)
        elif fmt in ("json", "fhir"):
            try:
                obj = json.loads(o.read_text(encoding="utf-8"))
                if fmt == "fhir" and obj.get("resourceType") != "Bundle":
                    fail("fhir_type_lost", "S1", file=rel)
            except Exception:
                fail("output_invalid_json", "S1", file=rel)
        if fmt in ("csv", "tsv"):
            rows_in, rows_out = read_table(inp / rel), read_table(o)
            if len(rows_in) != len(rows_out):
                fail("csv_row_count", "S1", file=rel, detail=f"{len(rows_in)}->{len(rows_out)}")
            elif any(len(a) != len(b) for a, b in zip(rows_in, rows_out)):
                fail("csv_col_count", "S1", file=rel)

    # leak + keep checks
    views: dict[str, View] = {}
    for rel, o in in2out.items():
        if o and o.exists():
            views[rel] = View(file_view(o))
    row_views: dict[tuple[str, str], View] = {}
    coarse_rows: set[tuple[str, str]] = set()
    for rel, o in in2out.items():
        if o and o.exists() and ans["files"][rel]["format"] in ("csv", "tsv"):
            rows = read_table(o)
            for i, row in enumerate(rows[1:]):
                row_views[(rel, f"row:{i}")] = View("\t".join(row))
    paths_view = View("\n".join(p.relative_to(out).as_posix().replace("_", " ") for p in out.rglob("*")))
    side = View(r1["stdout"] + "\n" + r1["stderr"] + "\n" + (out / "report.json").read_text(encoding="utf-8"))
    leaks: list[dict[str, Any]] = []
    totals: Counter = Counter()
    for item in ans["remove"]:
        rel = item["file"]
        key = (item["type"], item["script"], item["channel"])
        totals[key] += 1
        leaked = False
        if item["channel"] == "filename":
            leaked = contains_surface(paths_view.norm, paths_view.runs, item["surface"].replace("_", " "), item["type"])
        elif item.get("loc") and (rel, item["loc"]) in row_views:
            rv = row_views[(rel, item["loc"])]
            leaked = contains_surface(rv.norm, rv.runs, item["surface"], item["type"])
        elif rel in views:
            leaked = contains_surface(views[rel].norm, views[rel].runs, item["surface"], item["type"])
        if leaked:
            leaks.append(item)
        if item["critical"] and contains_surface(side.norm, side.runs, item["surface"], item["type"]):
            fail("side_channel_leak", "S0", file=rel, type=item["type"], where="stdout/stderr/report")
    for c in ans["canaries"]:
        for rel, v in views.items():
            if contains_surface(v.norm, v.runs, c, "PHONE" if c.isdigit() else "CANARY"):
                fail("canary_leak", "S0", file=rel)
    for item in leaks:
        fail("leak", "S1" if item["critical"] else "S2", file=item["file"], type=item["type"],
             script=item["script"], channel=item["channel"], surface=item["surface"])
    kept_total, kept_ok = 0, 0
    for item in ans["keep"]:
        kept_total += 1
        v = row_views.get((item["file"], item.get("loc"))) if item.get("loc") else None
        v = v or views.get(item["file"])
        if v and norm(item["text"]) in v.norm:
            kept_ok += 1
        elif item["kind"] == "district" and v is not None:
            # k-anonymity coarsening may blank district on rare rows: a utility cost, not a bug
            kept_total -= 1
            fail("district_coarsened", "S3", file=item["file"], text=item["text"])
        else:
            fail("lost_clinical", "S2", file=item["file"], kind_=item["kind"], text=item["text"])

    # over-redaction metric (Item 5): share of non-PII input words surviving in sanitized outputs
    word_re = re.compile(r"[A-Za-z0-9\u0900-\u097f]+")
    rm_words_by_file: dict[str, Counter] = defaultdict(Counter)
    for item in ans["remove"]:
        if item["channel"] != "filename":
            rm_words_by_file[item["file"]].update(word_re.findall(norm(item["surface"])))
    ret_total = ret_kept = 0
    for rel, o in in2out.items():
        if not o or not o.exists() or ans["files"][rel]["expect"] != "sanitize":
            continue
        raw_txt = (inp / rel).read_bytes()
        in_str = None
        for enc in ("utf-8-sig", "utf-16", "utf-8", "cp1252"):
            try:
                in_str = raw_txt.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if not in_str:
            continue
        in_wc = Counter(word_re.findall(norm(in_str)))
        non_pii = in_wc - rm_words_by_file.get(rel, Counter())
        out_wc = Counter(word_re.findall(views[rel].norm if rel in views else norm(o.read_text(encoding="utf-8", errors="replace"))))
        matched = sum((non_pii & out_wc).values())
        tot_w = sum(non_pii.values())
        ret_total += tot_w
        ret_kept += matched
    token_retention = (ret_kept / ret_total) if ret_total else 1.0
    if token_retention < 0.80:
        fail("over_redaction", "S2", detail=f"token_retention={round(100 * token_retention, 2)}%")

    # linkage
    out2in = {o.relative_to(out).as_posix(): rel for rel, o in in2out.items() if o}
    psn_of: dict[tuple[str, str], str | None] = {}
    for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        rel = out2in.get(rec.get("file", ""))
        if rel:
            psn_of[(rel, rec.get("loc"))] = rec.get("patient")
    truth = [(r["file"], r["loc"], r["patient"]) for r in ans["records"]]
    missing_loc = [t for t in truth if (t[0], t[1]) not in psn_of and in2out.get(t[0])]
    for t in missing_loc:
        fail("record_missing", "S2", file=t[0], loc=t[1])
    got = [(psn_of.get((f, l)), p) for f, l, p in truth if (f, l) in psn_of]
    tp = fp = fn = 0
    for i in range(len(got)):
        for j in range(i + 1, len(got)):
            same_true = got[i][1] == got[j][1]
            same_pred = got[i][0] is not None and got[i][0] == got[j][0]
            tp += same_true and same_pred
            fp += (not same_true) and same_pred
            fn += same_true and not same_pred
    psns_by_pid: dict[str, set[str]] = defaultdict(set)
    for psn, pid in got:
        if psn:
            psns_by_pid[pid].add(psn)
    for kind, groups in (("homonym_merge", ans["homonyms"]), ("twin_merge", ans["twins"])):
        for a, b in groups:
            if psns_by_pid[a] & psns_by_pid[b]:
                fail(kind, "S1", detail=f"{a}+{b}")
    pid_by_psn: dict[str, set[str]] = defaultdict(set)
    for psn, pid in got:
        if psn:
            pid_by_psn[psn].add(pid)
    for psn, pids in pid_by_psn.items():
        if len(pids) > 1:
            fail("false_merge", "S1", detail=sorted(pids))

    # length of stay preserved + dates actually shifted
    for item in ans["los"]:
        o = in2out.get(item["file"])
        if not o or not o.exists():
            continue
        rows = read_table(o)
        ri = int(item["loc"].split(":")[1]) + 1
        if ri >= len(rows):
            continue
        a, b = parse_date_any(rows[ri][item["col_in"]]), parse_date_any(rows[ri][item["col_out"]])
        if not a or not b:
            fail("date_unparseable_after_shift", "S2", file=item["file"], detail=[rows[ri][item["col_in"]], rows[ri][item["col_out"]]])
            continue
        if (b - a).days != item["days"]:
            fail("los_changed", "S2", file=item["file"], detail=f"{item['days']}->{(b - a).days}")
        if rows[ri][item["col_in"]].strip() == item["adm"]:
            fail("date_not_shifted", "S2", file=item["file"], detail=item["adm"])

    stats: dict[str, Any] = {
        "secs": round(r1["secs"], 2), "leaks": len(leaks), "entities": len(ans["remove"]),
        "critical_leaks": sum(1 for x in leaks if x["critical"]), "kept": kept_ok, "keep_total": kept_total,
        "ret_kept": ret_kept, "ret_total": ret_total,
        "tp": tp, "fp": fp, "fn": fn, "totals": {"|".join(k): v for k, v in totals.items()},
        "leak_keys": ["|".join((x["type"], x["script"], x["channel"])) for x in leaks],
    }

    if mr:
        # determinism (same secret) and secret sensitivity (MR-05)
        r2 = run_cli(inp, ds / "out2", "torture-secret-A", ds / "sbx")
        if tree_hash(ds / "out1", True) != tree_hash(ds / "out2", True):
            fail("nondeterministic", "S0")
        r3 = run_cli(inp, ds / "out3", "torture-secret-B", ds / "sbx")
        if r2["code"] or r3["code"]:
            fail("exit_code_rerun", "S0")
        psn1 = set(PSN_RE.findall((ds / "out1" / "records.jsonl").read_text()))
        psn3 = set(PSN_RE.findall((ds / "out3" / "records.jsonl").read_text()))
        if psn1 & psn3:
            fail("psn_stable_across_secrets", "S0", detail=len(psn1 & psn3))
        def masked(root: Path) -> dict[str, str]:
            res = {}
            for p in sorted((root / "sanitized").rglob("*")):
                if p.is_file():
                    t = p.read_bytes().decode("utf-8", "replace")

                    def _b64(m: re.Match) -> str:
                        try:
                            return base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4)).decode("utf-8")
                        except Exception:
                            return m.group(0)
                    t = B64_RE.sub(_b64, t)
                    t = PSN_RE.sub("PSN", t)
                    t = re.sub(r"\d{1,4}[-/.]\d{1,2}[-/.]\d{2,4}|\d{1,2} [A-Z][a-z]{2} \d{4}|\d{1,2}-[A-Z][a-z]{2}-\d{4}", "D", t)
                    res[p.relative_to(root).as_posix()] = t
            return res
        m1, m3 = masked(ds / "out1"), masked(ds / "out3")
        if set(m1) != set(m3):
            fail("mr05_paths_differ", "S2", detail=sorted(set(m1) ^ set(m3))[:5])
        else:
            diff = [k for k in m1 if m1[k] != m3[k]]
            if diff:
                fail("mr05_content_differs", "S2", detail=diff[:5])
        shutil.rmtree(ds / "out2", ignore_errors=True)
        shutil.rmtree(ds / "out3", ignore_errors=True)
    return {"seed": seed, "fails": fails, "stats": stats}


def parse_seeds(s: str) -> list[int]:
    out: list[int] = []
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    kinds: Counter = Counter()
    sev: Counter = Counter()
    for r in results:
        for f in r["fails"]:
            kinds[(f["sev"], f["kind"])] += 1
            sev[f["sev"]] += 1
    tot: Counter = Counter()
    lk: Counter = Counter()
    ent = leaks = crit = kept = keep_total = ret_kept = ret_total = tp = fp = fn = 0
    for r in results:
        s = r["stats"]
        if not s:
            continue
        ent += s["entities"]; leaks += s["leaks"]; crit += s["critical_leaks"]
        kept += s["kept"]; keep_total += s["keep_total"]; tp += s["tp"]; fp += s["fp"]; fn += s["fn"]
        ret_kept += s.get("ret_kept", 0); ret_total += s.get("ret_total", 0)
        tot.update(s["totals"]); lk.update(s["leak_keys"])
    by_type: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    by_script: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    by_channel: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for k, v in tot.items():
        t, sc, ch = k.split("|")
        for d, key in ((by_type, t), (by_script, sc), (by_channel, ch)):
            d[key][1] += v
            d[key][0] += lk.get(k, 0)
    p = tp / (tp + fp) if tp + fp else 1.0
    rc = tp / (tp + fn) if tp + fn else 1.0
    f05 = (1.25 * p * rc / (0.25 * p + rc)) if p + rc else 0.0
    return {
        "seeds": len(results), "entities": ent, "leaks": leaks, "leak_pct": round(100 * leaks / max(ent, 1), 2),
        "critical_leaks": crit, "kept_pct": round(100 * kept / max(keep_total, 1), 2),
        "token_retention_pct": round(100 * ret_kept / max(ret_total, 1), 2),
        "link_precision": round(p, 3), "link_recall": round(rc, 3), "link_f05": round(f05, 3),
        "by_type": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_type.items())},
        "by_script": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_script.items())},
        "by_channel": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_channel.items())},
        "failures_by_severity": dict(sev), "failure_kinds": {f"{a}:{b}": c for (a, b), c in kinds.most_common()},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="WardGuard torture checker")
    ap.add_argument("--seeds", default="1-10")
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--patients", type=int, default=14)
    ap.add_argument("--no-mr", action="store_true", help="skip determinism / secret-change reruns")
    ap.add_argument("--show", type=int, default=25)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    results = []
    for s in parse_seeds(a.seeds):
        res = check_seed(s, a.work, a.patients, not a.no_mr)
        results.append(res)
        st = res["stats"]
        print(f"seed {s:4d}: leaks {st.get('leaks', '?')}/{st.get('entities', '?')} "
              f"critical {st.get('critical_leaks', '?')} kept {st.get('kept', '?')}/{st.get('keep_total', '?')} "
              f"fails {len(res['fails'])} ({st.get('secs', '?')}s)", flush=True)
    summ = summarize(results)
    (a.work / "summary.json").write_text(json.dumps(summ, indent=1, ensure_ascii=False), encoding="utf-8")
    (a.work / "failures.jsonl").write_text(
        "\n".join(json.dumps(f, ensure_ascii=False) for r in results for f in r["fails"]), encoding="utf-8")
    print(json.dumps(summ, indent=1, ensure_ascii=False))
    shown = 0
    for r in results:
        for f in r["fails"]:
            if shown < a.show:
                print("  ", json.dumps(f, ensure_ascii=False)[:300])
                shown += 1
    s0 = summ["failures_by_severity"].get("S0", 0)
    s1 = summ["failures_by_severity"].get("S1", 0)
    return 1 if (s0 or s1) else 0


if __name__ == "__main__":
    sys.exit(main())
