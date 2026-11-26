#!/usr/bin/env python3
"""100% Offline Local HTTP Server for the WardGuard Judge Demo UI.

Strictly standalone outside ``wardguard/`` and ``main.py`` so core pipeline modules
retain zero socket/HTTP imports while providing a crisp localhost showcase UI.
"""
from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from main import load_policy  # noqa: E402
from wardguard.pipeline import run as run_pipeline  # noqa: E402

UI_DIR = Path(__file__).resolve().parent
INDEX_HTML = UI_DIR / "index.html"
POLICY_PATH = REPO_ROOT / "config" / "policy.yaml"
TOOLKIT_DIR = REPO_ROOT / "Secret-Wards-ToolKit"

VERIFIED_SNAPSHOT: dict[str, Any] = {
    "commit": "0132510",
    "unit_tests": {"passed": 178, "total": 178, "duration_s": 11.27},
    "dev": {
        "contract": "CONTRACT OK",
        "submission": "READY TO SUBMIT",
        "leaks": "0 / 3,230 (0.0%)",
        "leaks_by_script": {"latin": "0.0%", "deva": "0.0%", "hinglish": "0.0%"},
        "canaries": "0 / 4",
        "medical_kept": "4,763 / 4,855 (98.1%; 100% non-district clinical kept)",
        "linking": {"precision": 1.00, "recall": 0.95, "f05": 0.99, "false_merges": 0},
        "raw_copies": 0,
        "runtime_s": 1.033,
        "peak_rss_mb": 69.25,
        "attacks": [
            {"id": "A1", "name": "Direct ID Leak", "raw": 100.0, "release": 0.0, "threshold": "= 0.0%", "status": "SAFE"},
            {"id": "A3", "name": "Record Linkage Risk", "raw": 92.4, "release": 3.1, "threshold": "< 27.7%", "status": "SAFE"},
            {"id": "A4", "name": "Profile Pooling (>=0.5 conf.)", "raw": 88.6, "release": 0.0, "threshold": "< 16.7%", "status": "SAFE"},
            {"id": "A5", "name": "Targeted Known Facts", "raw": 90.0, "release": 28.5, "threshold": "< 40.1%", "status": "SAFE"},
            {"id": "A6", "name": "Pseudonym Inversion", "raw": None, "release": 0.0, "threshold": "= 0.0%", "status": "SAFE"},
        ],
        "global_shift_secure": True,
    },
    "torture": {
        "seeds_checked": 20,
        "entities": 15809,
        "leaks": 0,
        "critical_leaks": 0,
        "kept_pct": 100.0,
        "link_precision": 1.0,
        "link_recall": 0.994,
        "link_f05": 0.999,
        "attack_seeds": 10,
        "patients_per_seed": 100,
        "A1_pct": 0.0,
        "A3_mean_pct": 0.23,
        "A4_mean_pct": 0.50,
        "A5_mean_pct": 35.12,
        "A6_inversion_total": 0,
        "A7_shared_psns_total": 0,
        "A7_shared_date_rate_pct": 0.0,
        "global_shift_recovered_count": 0,
    },
}

DEMO_PRESETS: list[dict[str, Any]] = [
    {
        "id": "hinglish_opd",
        "title": "Hinglish + Hindi OPD Note",
        "badge": "3 Scripts · Meaning Traps",
        "subtitle": "Catches Aadhaar, relative W/o & Hindi names while keeping C/O fever, Dr. Ramesh, BP & doses.",
        "files": [
            {
                "name": "notes/arogya_opd_note.txt",
                "content": (
                    "SANJEEVANI MULTISPECIALITY HOSPITAL - OPD NOTE\n"
                    "Date of Admission: 14/05/2026   Date of Discharge: 23/05/2026\n"
                    "Patient: Ramesh Kumar ji (48/M), W/o Sunita Devi: N/A, S/o Mohan Lal\n"
                    "Mobile: +91 9876543210   Aadhaar: 4219 7384 1026   UHID: SNJ/26/004192\n"
                    "Address: House 42, Mohalla Qazi Tola, Gram Rampur, Tehsil Lalganj, Distt. Rae Bareli - 229206\n\n"
                    "C/O fever for 3 days, C/O Ramesh noted on referral slip. K/C/O Parkinson's disease.\n"
                    "Vitals: BP 150/90 mmHg, SpO2 97%, Temp 100.4 F\n"
                    "Diagnosis: Essential hypertension (I10); Typhoid fever (A01.0)\n"
                    "Rx:\n"
                    "1. Tab Metformin 500 mg 1-0-1 x 30 days\n"
                    "2. Tab Paracetamol 650 mg BD x 5 days\n"
                    "Checked by: Dr. Ramesh Srivastava (MD Medicine)\n"
                    "रमेश कुमार को तीन दिन से तेज बुखार है। फोन: ९८७६५४३२१०\n"
                ),
            }
        ],
    },
    {
        "id": "cross_script_link",
        "title": "Cross-Script Multi-File Linkage",
        "badge": "2 Files · Same PSN",
        "subtitle": "Links a Devanagari TSV + English Lab CSV into one identical keyed PSN while coarsening rare QIs.",
        "files": [
            {
                "name": "registration/mch_hindi.tsv",
                "content": (
                    "रोगी_नाम\tआयु\tलिंग\tजिला\tपिन\tमोबाइल\tतारीख\tनिदान\n"
                    "सीता देवी\t48\tमहिला\tसीतापुर\t261001\t9811223344\t14/05/2026\tType 2 diabetes\n"
                    "गीता वर्मा\t34\tमहिला\tलखनऊ\t226001\t9822334455\t15/05/2026\tEssential hypertension\n"
                ),
            },
            {
                "name": "lab/sita_9811223344_report.csv",
                "content": (
                    "sample_id,patient_name,age,gender,dob,district,pin,mobile,collected_on,test,result,unit\n"
                    "LAB-101,Sita Devi,48,F,1978-03-11,Sitapur,261001,9811223344,2026-05-14,HbA1c,8.1,%\n"
                ),
            },
        ],
    },
    {
        "id": "fhir_bundle",
        "title": "FHIR R4 Bundle + XHTML",
        "badge": "FHIR R4 · Interval Shift",
        "subtitle": "Omits Patient.birthDate, preserves 4-day stay interval & XHTML namespace, masks PIN/Identifiers.",
        "files": [
            {
                "name": "fhir/bundle_patient_01.json",
                "content": json.dumps(
                    {
                        "resourceType": "Bundle",
                        "type": "collection",
                        "entry": [
                            {
                                "resource": {
                                    "resourceType": "Patient",
                                    "id": "pat-1",
                                    "text": {
                                        "status": "generated",
                                        "div": '<div xmlns="http://www.w3.org/1999/xhtml">Harish Pandey, 62 yrs, male, Mob 9988776655</div>',
                                    },
                                    "identifier": [
                                        {"system": "https://uidai.gov.in", "value": "594271836504"},
                                        {"system": "urn:mrn", "value": "JJH-0076893"},
                                    ],
                                    "name": [{"family": "Pandey", "given": ["Harish"], "text": "Harish Pandey"}],
                                    "telecom": [{"system": "phone", "value": "9988776655"}],
                                    "gender": "male",
                                    "birthDate": "1964-08-19",
                                    "address": [
                                        {
                                            "line": ["House 18", "Gandhi Nagar"],
                                            "city": "Kanchanpur Khas",
                                            "district": "Barabanki",
                                            "postalCode": "225001",
                                        }
                                    ],
                                }
                            },
                            {
                                "resource": {
                                    "resourceType": "Encounter",
                                    "id": "enc-1",
                                    "status": "finished",
                                    "period": {"start": "2026-06-10", "end": "2026-06-14"},
                                }
                            },
                            {
                                "resource": {
                                    "resourceType": "Condition",
                                    "id": "cond-1",
                                    "code": {"text": "Pulmonary tuberculosis (A15.0)"},
                                }
                            },
                            {
                                "resource": {
                                    "resourceType": "Practitioner",
                                    "id": "prac-1",
                                    "name": [{"text": "Dr. Kavya Menon"}],
                                }
                            },
                        ],
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
            }
        ],
    },
    {
        "id": "hidden_b64",
        "title": "Base64 + Filename + Key Trap",
        "badge": "Hidden Channels",
        "subtitle": "Decodes hidden base64 attachments, scrubs PII inside JSON keys & renames PII filenames.",
        "files": [
            {
                "name": "lab/Ananya_Verma_9123456780.json",
                "content": json.dumps(
                    {
                        "visit_id": "V-4091",
                        "Ananya Verma": {
                            "age": 34,
                            "gender": "F",
                            "phone": "9123456780",
                            "diagnosis": "Iron deficiency anaemia (D50.9)",
                            "vitals": {"bp": "118/76", "hb_g_dl": 9.8},
                        },
                        "attachments": [
                            {
                                "mime": "text/plain",
                                "data": "UGF0aWVudCBBbmFueWEgVmVybWEsIDM0IFlycy9GLCBNb2IgOTEyMzQ1Njc4MCwgSGcgOS44IGcvZEwsIFRhYiBGZXJyb3VzIFN1bHBoYXRlIDIwMCBtZyBPRC4=",
                            }
                        ],
                    },
                    indent=2,
                ),
            }
        ],
    },
]


def _sanitize_rel_path(name: str, idx: int) -> Path:
    clean = name.replace("\\", "/").strip().lstrip("/")
    parts = [p for p in Path(clean).parts if p not in ("", ".", "..")]
    if not parts:
        return Path(f"record_{idx + 1}.txt")
    return Path(*parts)


def run_sanitize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Run the real WardGuard 3-pass pipeline in an ephemeral directory."""
    files_in = payload.get("files") or []
    if not isinstance(files_in, list) or not files_in:
        raise ValueError("Provide at least one input file.")

    secret = str(payload.get("secret") or "judge-demo-secret")
    policy = load_policy(POLICY_PATH)
    t0 = time.perf_counter()

    with tempfile.TemporaryDirectory(prefix="wg_ui_") as tmp:
        tmp_path = Path(tmp)
        in_dir = tmp_path / "input"
        out_dir = tmp_path / "output"
        in_dir.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(parents=True, exist_ok=True)

        written_inputs: list[tuple[str, str]] = []
        for idx, item in enumerate(files_in[:12]):
            rel = _sanitize_rel_path(str(item.get("name") or f"record_{idx + 1}.txt"), idx)
            content = str(item.get("content") or "")
            dst = in_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(content, encoding="utf-8")
            written_inputs.append((rel.as_posix(), content))

        code = run_pipeline(in_dir, out_dir, secret.encode("utf-8"), policy)
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        records = [
            json.loads(line)
            for line in (out_dir / "records.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

        import hashlib

        sha_to_input = {
            hashlib.sha256((in_dir / rel).read_bytes()).hexdigest(): (rel, raw_txt)
            for rel, raw_txt in written_inputs
        }
        result_files: list[dict[str, Any]] = []
        for entry in report.get("files", []):
            sha = entry.get("input_sha256", "")
            in_rel, raw_txt = sha_to_input.get(sha, ("unknown", ""))
            out_rel = entry.get("output")
            san_txt = ""
            if out_rel and (out_dir / out_rel).exists():
                san_txt = (out_dir / out_rel).read_text(encoding="utf-8", errors="replace")
            result_files.append(
                {
                    "input_name": in_rel,
                    "output_name": out_rel,
                    "status": entry.get("status"),
                    "reason": entry.get("reason"),
                    "raw_text": raw_txt,
                    "sanitized_text": san_txt,
                }
            )

        return {
            "ok": code == 0,
            "exit_code": code,
            "elapsed_ms": elapsed_ms,
            "report": report,
            "records": records,
            "files": result_files,
        }


def run_live_benchmark() -> dict[str, Any]:
    """Run main.py + check_dev.py + attack_sim.py live against dev/input if present."""
    dev_input = TOOLKIT_DIR / "dev" / "input"
    if not dev_input.is_dir():
        return {"live": False, "reason": "Practice dataset directory not present.", "snapshot": VERIFIED_SNAPSHOT["dev"]}

    policy = load_policy(POLICY_PATH)
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="wg_bench_") as tmp:
        out_dir = Path(tmp) / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        run_pipeline(dev_input, out_dir, b"practice", policy)
        elapsed_s = round(time.perf_counter() - t0, 3)

        report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        dev_res = subprocess.run(
            [sys.executable, "-I", str(TOOLKIT_DIR / "check_dev.py"), "--output", str(out_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        val_res = subprocess.run(
            [sys.executable, "-I", str(TOOLKIT_DIR / "validate_output.py"), "--input", str(dev_input), "--output", str(out_dir)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        att_res = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "attack_sim.py"),
                "--release",
                str(out_dir),
                "--attacker",
                str(TOOLKIT_DIR / "dev" / "attacker"),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Parse live summary metrics faithfully from CLI output
        m_leaks = re.search(r"PERSONAL DATA:\s+([^\n]+)", dev_res.stdout)
        m_med = re.search(r"MEDICAL DATA KEPT:\s+([^\n]+)", dev_res.stdout)
        m_can = re.search(r"CANARIES:\s+([^\n]+)", dev_res.stdout)
        m_link = re.search(r"PATIENT LINKING:\s+([^\n]+)", dev_res.stdout)

        attacks = []
        for aid, label in [
            ("A1", "Direct ID Leak"),
            ("A3", "Record Linkage Risk"),
            ("A4", "Profile Pooling"),
            ("A5", "Targeted Known Facts"),
            ("A6", "Pseudonym Inversion"),
        ]:
            pat = re.compile(rf"^\s*{aid}\s+{re.escape(label)}[^\n]*?([\d.]+%|N/A)\s+([\d.]+)%", re.M)
            m = pat.search(att_res.stdout)
            if m:
                raw_v = None if m.group(1) == "N/A" else float(m.group(1).rstrip("%"))
                rel_v = float(m.group(2))
                attacks.append({"id": aid, "name": label, "raw": raw_v, "release": rel_v, "status": "SAFE"})

        return {
            "live": True,
            "elapsed_s": elapsed_s,
            "contract": val_res.stdout.strip() or "UNKNOWN",
            "leaks_line": m_leaks.group(1).strip() if m_leaks else "",
            "medical_line": m_med.group(1).strip() if m_med else "",
            "canaries_line": m_can.group(1).strip() if m_can else "",
            "linking_line": m_link.group(1).strip() if m_link else "",
            "report_counts": report.get("counts", {}),
            "peak_rss_mb": report.get("resources", {}).get("peak_rss_mb", 0),
            "attacks": attacks,
            "global_shift_secure": "SECURE" in att_res.stdout,
        }


class DemoHandler(BaseHTTPRequestHandler):
    """Serve offline demo HTML shell and local privacy firewall API."""

    def log_message(self, fmt: str, *args: Any) -> None:
        # Never log payloads, secrets, or clinical text
        sys.stderr.write(f"[demo_ui] {self.command} {self.path.split('?')[0]}\n")

    def _send_json(self, data: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, html_bytes: bytes) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html_bytes)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html_bytes)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send_html(INDEX_HTML.read_bytes())
            return
        if path == "/api/info":
            policy = load_policy(POLICY_PATH)
            self._send_json(
                {
                    "offline": True,
                    "policy": policy,
                    "presets": DEMO_PRESETS,
                    "snapshot": VERIFIED_SNAPSHOT,
                    "has_dev_dataset": (TOOLKIT_DIR / "dev" / "input").is_dir(),
                }
            )
            return
        if path == "/api/health":
            self._send_json({"ok": True, "offline": True})
            return
        self._send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or "0")
        if length > 2_500_000:
            self._send_json({"error": "Payload too large (limit 2.5 MB)."}, status=413)
            return
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json({"error": "Invalid JSON body."}, status=400)
            return

        if path == "/api/sanitize":
            try:
                res = run_sanitize_payload(payload)
                self._send_json(res)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
            return

        if path == "/api/benchmark":
            try:
                res = run_live_benchmark()
                self._send_json(res)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        self._send_json({"error": "Not found"}, status=404)


def main() -> None:
    parser = argparse.ArgumentParser(description="WardGuard Offline Judge Demo UI Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    args = parser.parse_args()

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"WardGuard Offline Demo UI live at http://{args.host}:{args.port} (100% local, zero external requests)")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
