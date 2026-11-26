"""Offline Demo UI smoke, offline-assets, and multi-file linkage tests."""
from __future__ import annotations

import json
from pathlib import Path
import re
from http.server import ThreadingHTTPServer
import threading
import urllib.request

from demo_ui.server import DEMO_PRESETS, DemoHandler, run_sanitize_payload


def test_demo_ui_html_is_100_percent_offline():
    """Ensure demo_ui/index.html contains zero external CDN, font, script, or stylesheet links."""
    html_path = Path(__file__).resolve().parents[1] / "demo_ui" / "index.html"
    content = html_path.read_text(encoding="utf-8")
    assert not re.search(r"https?://", content, re.I)
    assert "color-scheme: light" in content
    assert 'role="tablist"' in content


def test_demo_ui_presets_and_secret_rotation():
    """Verify every judge demo preset sanitizes cleanly with 0 leaks and secret-keyed PSNs."""
    for preset in DEMO_PRESETS:
        res_a = run_sanitize_payload({"files": preset["files"], "secret": "demo-secret-A"})
        res_b = run_sanitize_payload({"files": preset["files"], "secret": "demo-secret-B"})
        assert res_a["ok"] is True
        assert res_a["report"]["counts"]["files_sanitized"] == len(preset["files"])

        if preset["id"] == "cross_script_link":
            psns = {r["patient"] for r in res_a["records"] if r.get("patient")}
            assert len(psns) >= 1
            # Same phone 9811223344 across Devanagari TSV + English CSV shares one PSN
            tsv_psn = [r["patient"] for r in res_a["records"] if "mch_hindi" in r["file"] and r["loc"] == "row:0"][0]
            csv_psn = [r["patient"] for r in res_a["records"] if "sita" in r["file"] or "LAB" in r["file"] or "lab/" in r["file"]][0]
            assert tsv_psn and tsv_psn == csv_psn

        if preset["id"] == "fhir_bundle":
            out_bundle = json.loads(res_a["files"][0]["sanitized_text"])
            pat = out_bundle["entry"][0]["resource"]
            assert "birthDate" not in pat
            assert "9988776655" not in res_a["files"][0]["sanitized_text"]

        # Secret rotation changes PSN
        rec_a = {r["patient"] for r in res_a["records"] if r.get("patient")}
        rec_b = {r["patient"] for r in res_b["records"] if r.get("patient")}
        if rec_a and rec_b:
            assert rec_a != rec_b


def test_demo_ui_local_http_endpoints():
    """Verify GET /, GET /api/info, and POST /api/sanitize against ephemeral localhost server."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        html_body = urllib.request.urlopen(f"{base}/", timeout=5).read().decode("utf-8")
        assert "WardGuard" in html_body

        info = json.loads(urllib.request.urlopen(f"{base}/api/info", timeout=5).read().decode("utf-8"))
        assert info["offline"] is True
        assert len(info["presets"]) == 4

        req = urllib.request.Request(
            f"{base}/api/sanitize",
            data=json.dumps({"files": DEMO_PRESETS[0]["files"], "secret": "http-test"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        res = json.loads(urllib.request.urlopen(req, timeout=10).read().decode("utf-8"))
        assert res["ok"] is True
        san_txt = res["files"][0]["sanitized_text"]
        assert "9876543210" not in san_txt
        assert "4219 7384 1026" not in san_txt
        assert "C/O fever for 3 days" in san_txt
        assert "Tab Metformin 500 mg" in san_txt
        assert "Dr. Ramesh Srivastava" in san_txt
    finally:
        server.shutdown()
        server.server_close()
