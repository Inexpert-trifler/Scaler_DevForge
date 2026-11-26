"""Regression tests for bugs found by the torture lab (tools/torture). All data is invented."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from wardguard.detect.context import detect_text
from wardguard.detect.columns import classify_column
from wardguard.detect.patterns import find_identifiers
from wardguard.ingest.sniff import sniff
from wardguard.link.normalize import phonetic_key
from wardguard.model import EType
from wardguard.pipeline import run
from wardguard.rewrite import scrub_embedded_base64

POLICY = {"age_band_years": 5, "age_top_code": 90, "date_shift_max_days": 180, "pin_keep_digits": 3,
          "village_action": "tehsil", "dob_action": "year", "psn_prefix": "PSN-", "tokens": {}}


def types(text: str) -> list[tuple[str, str]]:
    return [(m.etype.value, m.text) for m in detect_text(text)]


# --- detection -------------------------------------------------------------------------
def test_phone_next_to_doctor_line_is_not_protected():
    t = "Mobile: +91 72864 90658\nConsultant: Dr. Ramesh Srivastava (MD Medicine)"
    assert ("PHONE", "+91 72864 90658") in types(t)


@pytest.mark.parametrize("phone", ["91 8507 700 469", "(+91) 7383097485", "0738-309-7485", "98765.43210", "९८७६५४३२१०"])
def test_phone_groupings(phone):
    assert any(m.etype == EType.PHONE for m in find_identifiers(f"Mob {phone}"))


def test_plain_and_labelled_abha():
    assert any(m.etype == EType.ABHA_NUMBER for m in find_identifiers("ABHA: 78558672020786"))
    assert any(m.etype == EType.ABHA_NUMBER for m in find_identifiers("ABHA No 09613955209032"))


def test_clinical_phrase_not_a_name():
    assert types("Advice: Review in OPD after 2 weeks with Dr. Anjali Mehrotra.") == []


def test_address_line_parts():
    got = types("Address: House 380, Gandhi Nagar, near Pakki Masjid, Saraiya Kalan, Tehsil Musafirkhana, Distt. Amethi - 227084")
    assert ("VILLAGE", "Saraiya Kalan") in got and ("LOCALITY", "Gandhi Nagar") in got
    assert ("LANDMARK", "near Pakki Masjid") in got
    assert not any("Musafirkhana" in s or "Amethi" in s for _, s in got)  # tehsil/district kept


def test_hindi_address_and_abbreviation_dot():
    got = types("पता: मकान नं. 12, मोहल्ला काज़ी टोला, भिटौरा, तहसील खागा, जिला फतेहपुर")
    assert ("VILLAGE", "भिटौरा") in got and not any("फतेहपुर" in s for _, s in got)


def test_resident_of_village():
    assert ("VILLAGE", "Rampur Mathura") in types("referring Mrs. Kavita D'Souza, aged 41 years, R/o Rampur Mathura, Tehsil Khaga, for care")


def test_apostrophe_name():
    assert ("PATIENT_NAME", "Kavita D'Souza") in types("I am referring Mrs. Kavita D'Souza, aged 41 years")


def test_kinship_and_chat_sender():
    assert ("RELATIVE_NAME", "Ramesh") in types("[12/03/26, 8:11 pm] Ramesh Mama: <attachment: report.pdf>")


def test_label_name_with_wide_gap():
    assert ("PATIENT_NAME", "Harjinder Gill") in types("NAME = Harjinder Gill        Age/Sex: 66 Yrs/M")


@pytest.mark.parametrize("dob", ["11.10.1968", "12 Apr 1977", "16-01-1977"])
def test_dob_formats(dob):
    assert ("DOB", dob) in types(f"DOB: {dob}")


def test_single_digit_age_detected():
    assert ("AGE", "6") in types("Age/Sex: 6 Yrs/M")


def test_hindi_header_words_not_a_name():
    assert types("मरीज़ का नाम") == []


def test_initials_but_not_units_or_orgs():
    assert ("PATIENT_NAME", "T. R. Chauhan") in types("Also known as: T. R. Chauhan")
    assert types("Temp 99.2 F. Serum Creatinine 1.3 mg/dL") == []
    assert types("U.P. Police") == []


def test_date_column_classification():
    assert classify_column("भर्ती तिथि", ["13.04.2026", "03-04-2026", "12.05.2026"]) == EType.DATE
    assert classify_column("IN_DT", ["15.04.2026", "14.03.2026", "08.10.2026"]) == EType.DATE
    assert classify_column("D_O_B", ["11-07-1930", "15.04.1953", "1977-01-16"]) == EType.DOB


def test_cross_script_phonetic_keys():
    assert phonetic_key("Harjinder Gill") == phonetic_key("हरजिंदर गिल")
    assert phonetic_key("Sunita") == phonetic_key("Suneeta")
    assert phonetic_key("Ramesh") != phonetic_key("Mahesh")


def test_ndjson_is_not_csv():
    data = b'{"a": 1, "name": "x"}\n{"a": 2, "name": "y"}\n'
    assert sniff(data, "exports/v.jsonl") == "text"


def test_embedded_base64_scrubbed():
    blob = base64.b64encode(b"Referral: phone 9876543210, Aadhaar 3502 2272 4186.").decode()
    out = scrub_embedded_base64(f"note {blob} end", POLICY)
    assert b"9876543210" not in base64.b64decode(out.split()[1])


# --- end-to-end ------------------------------------------------------------------------
def _run(tmp_path: Path, files: dict[str, str]) -> Path:
    inp, out = tmp_path / "in", tmp_path / "out"
    for rel, txt in files.items():
        (inp / rel).parent.mkdir(parents=True, exist_ok=True)
        (inp / rel).write_text(txt, encoding="utf-8")
    assert run(inp, out, b"regression-secret", POLICY) == 0
    return out


def test_header_only_table_is_scrubbed(tmp_path):
    out = _run(tmp_path, {"a.csv": "Patient Sunita Yadav 9876543210,Aadhaar 3502 2272 4186\n"})
    txt = "".join(p.read_text() for p in (out / "sanitized").rglob("*") if p.is_file())
    assert "9876543210" not in txt and "3502 2272 4186" not in txt


def test_pii_in_folder_name_is_renamed(tmp_path):
    out = _run(tmp_path, {
        "registration/reg.csv": "Patient Name,Mobile\nSunita Yadav,9876543210\n",
        "scans/Sunita_Yadav/visit.txt": "Follow-up visit. BP 138/90 mmHg.\n",
    })
    paths = [p.relative_to(out).as_posix() for p in out.rglob("*")]
    assert not any("Sunita" in p for p in paths)
    assert "Sunita" not in (out / "report.json").read_text()


def test_deep_json_1500_sanitized_without_recursion_error(tmp_path):
    deep = {"patient": {"name": "Sunita Yadav", "phone": "9876543210"}}
    for _ in range(1500):
        deep = {"child": deep}
    out = _run(tmp_path, {"deep1500.json": json.dumps(deep)})
    rep = json.loads((out / "report.json").read_text())
    assert rep["files"][0]["status"] == "sanitized"
    txt = (out / "sanitized" / "deep1500.json").read_text()
    assert "Sunita" not in txt and "9876543210" not in txt


def test_deep_json_10k_is_safe(tmp_path):
    raw = '{"a":' * 10000 + '{"patient":{"name":"Sunita Yadav"}}' + "}" * 10000
    out = _run(tmp_path, {"deep10k.json": raw})
    rep = json.loads((out / "report.json").read_text())
    assert rep["counts"]["files_total"] == 1
    assert rep["files"][0]["status"] in ("sanitized", "quarantined")


def test_repeated_relation_backtracking_is_fast(tmp_path):
    import time
    txt = "S/o " * 10000 + "late " * 5000 + "Patient Name: Kavita Chauhan Mob: 9876543210.\n"
    t0 = time.time()
    out = _run(tmp_path, {"backtrack.txt": txt})
    assert time.time() - t0 < 2.0
    res = (out / "sanitized" / "backtrack.txt").read_text()
    assert "Kavita" not in res and "9876543210" not in res


def test_gazetteer_scales_with_many_names():
    import time
    from wardguard.detect.names import Gazetteer
    gaz = Gazetteer()
    for i in range(2000):
        gaz.add(f"Patient{i} Surname{i}", role="patient")
    t0 = time.time()
    hits = gaz.find("Patient1999 Surname1999 arrived with fever and normal vitals.")
    assert time.time() - t0 < 0.2
    assert len(hits) == 1


def test_tab_separated_phone_and_aadhaar_both_detected():
    # A phone ending in digits followed by \t and an Aadhaar must not merge across \t
    from wardguard.detect.patterns import generate_verhoeff_check_digit
    base = "82453744495"
    aad = base + str(generate_verhoeff_check_digit(base))
    aad_spaced = f"{aad[:4]} {aad[4:8]} {aad[8:]}"
    s = f"978-865-4045\t{aad_spaced}\t52-9208-1777-7323"
    got = {(m.etype, m.text) for m in find_identifiers(s)}
    assert (EType.PHONE, "978-865-4045") in got
    assert (EType.AADHAAR, aad_spaced) in got
    assert (EType.ABHA_NUMBER, "52-9208-1777-7323") in got


def test_comma_adjacent_aadhaar_after_phone_detected():
    from wardguard.detect.patterns import generate_verhoeff_check_digit
    base = "40430314988"
    aad = base + str(generate_verhoeff_check_digit(base))
    aad_dashed = f"{aad[:4]}-{aad[4:8]}-{aad[8:]}"
    s = f"751-438-9537,{aad_dashed},22-8852-3605-3929"
    got = {(m.etype, m.text) for m in find_identifiers(s)}
    assert (EType.PHONE, "751-438-9537") in got
    assert (EType.AADHAAR, aad_dashed) in got
    assert (EType.ABHA_NUMBER, "22-8852-3605-3929") in got


def test_ragged_csv_pii_in_date_column_scrubbed(tmp_path):
    from wardguard.detect.patterns import generate_verhoeff_check_digit
    base = "89571037815"
    aad = base + str(generate_verhoeff_check_digit(base))
    aad_sp = f"{aad[:4]} {aad[4:8]} {aad[8:]}"
    csv_txt = (
        "Patient Name,Admission Date,Diagnosis\n"
        "Aarav Sharma,12/04/2026,Fever\n"
        "Sunita Yadav,13/04/2026,Cough\n"
        f"Ramesh Patel,(+91) 6756192499,{aad_sp}\n"
    )
    out = _run(tmp_path, {"ragged.csv": csv_txt})
    res = (out / "sanitized" / "ragged.csv").read_text()
    assert "6756192499" not in res and aad_sp not in res


def test_independent_attack_arena_a1_a6_a7(tmp_path):
    from tools.torture.gen import generate
    from tools.torture.check import run_cli
    from tools.torture.attacks import evaluate_attacks
    ds = tmp_path / "ds"
    generate(1, ds, 20)
    assert (ds / "attacker" / "registry.csv").exists()
    assert (ds / "attacker" / "known_facts.jsonl").exists()
    r1 = run_cli(ds / "input", ds / "outA", "arena-secret-A", ds / "sbx")
    r2 = run_cli(ds / "input", ds / "outB", "arena-secret-B", ds / "sbx")
    assert r1["code"] == 0 and r2["code"] == 0
    m = evaluate_attacks(ds, ds / "outA", is_raw=False, rotated_release_dir=ds / "outB")
    assert m["A1_pct"] == 0.0
    assert m["A6_inversion_hits"] == 0
    assert m["A7_shared_psns"] == 0
    assert m["global_shift_recovered"] is None


def test_cross_script_aspiration_and_apostrophe_linkage():
    from wardguard.detect.evidence import _norm_id_core
    assert phonetic_key("Chhedi") == phonetic_key("छेदी")
    assert phonetic_key("Kavita D'Souza") == phonetic_key("कविता डिसूज़ा")
    assert phonetic_key("Hmar") == phonetic_key("हमार")
    assert _norm_id_core("PHONE", "९१८३८३५७८०") == "9183835780"


def test_metamorphic_relations_smoke(tmp_path):
    from tools.torture.mr import check_mr_seed
    assert check_mr_seed(1, tmp_path) == []


def test_holdout_unseen_ids_mrns_urdu_and_kinship(tmp_path):
    txt = (
        "DEATH SUMMARY\n"
        "Deceased Name: Bhawani Shekhawat\n"
        "Lab Ref / UHID: AIIMS.26.454957\n"
        "Alt Ref: R-77/5053\n"
        "Voter ID (EPIC): MZB9162888\n"
        "Driving Licence: RJ14 20239781466\n"
        "Attendant: Irshad Khalu\n"
        "نام: فریدہ خاتون\n"
        "ولد: طارق محمود\n"
        "Cause of Death: Acute myocardial infarction (I21.9)\n"
    )
    out = _run(tmp_path, {"holdout.txt": txt})
    res = (out / "sanitized" / "holdout.txt").read_text()
    for secret_tok in ("Bhawani", "AIIMS.26.454957", "R-77/5053", "MZB9162888", "20239781466", "Irshad", "فریدہ", "طارق"):
        assert secret_tok not in res, f"leaked {secret_tok}"
    assert "Acute myocardial infarction (I21.9)" in res


def test_over_redaction_token_retention(tmp_path):
    """Sanitized outputs preserve >=80% of non-PII tokens across a multi-format seed."""
    from tools.torture.check import check_seed
    res = check_seed(1, tmp_path, 12, mr=False)
    stats = res["stats"]
    assert stats["ret_total"] > 0
    assert (stats["ret_kept"] / stats["ret_total"]) >= 0.80
    assert not any(f["kind"] == "over_redaction" for f in res["fails"])


def test_sandbox_fidelity_and_symlink_containment(tmp_path):
    """Sandbox check enforces read-only input, zero temp/net leaks, env determinism, and symlink containment."""
    from tools.torture.sandbox import check_sandbox
    res = check_sandbox(tmp_path / "sbx", seed=1, n_patients=8)
    assert res["fails"] == [], json.dumps(res["fails"])


def test_torture_smoke(tmp_path):
    """Two generated torture datasets must have zero leaks and zero false merges."""
    from tools.torture.check import check_seed
    for seed in (1, 2):
        res = check_seed(seed, tmp_path, 10, mr=False)
        bad = [f for f in res["fails"] if f["sev"] in ("S0", "S1") or f["kind"] == "leak"]
        assert not bad, json.dumps(bad[:3], ensure_ascii=False)
