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


def test_json_scalar_patient_key_scrubbed_standalone(tmp_path):
    """Standalone JSON with scalar 'patient' name key scrubs patient name while preserving clinical text."""
    out = _run(tmp_path, {
        "trav.json": json.dumps({"source_file": "../../secret.txt", "patient": "Suresh Kumar", "diagnosis": "Flu"}),
        "id_only.json": json.dumps({"patient": "PT00981", "diagnosis": "Malaria"}),
    })
    trav = (out / "sanitized" / "trav.json").read_text(encoding="utf-8")
    assert "Suresh Kumar" not in trav
    assert "Flu" in trav
    assert "Malaria" in (out / "sanitized" / "id_only.json").read_text(encoding="utf-8")


def test_kit_truth_schema_raksha_truth_1(tmp_path):
    """Forge writes truth/truth.json conforming to raksha-truth/1 schema deterministically."""
    from tools.torture.gen import generate
    d1 = generate(3, tmp_path / "g1", 8)
    d2 = generate(3, tmp_path / "g2", 8)
    tpath = d1 / "truth" / "truth.json"
    assert tpath.exists()
    assert tpath.read_bytes() == (d2 / "truth" / "truth.json").read_bytes()
    truth = json.loads(tpath.read_text(encoding="utf-8"))
    assert truth["schema"] == "raksha-truth/1"
    for k in ("generator_version", "seed", "profile", "chaos", "ref_date", "files", "patients", "traps", "linkability", "canaries"):
        assert k in truth
    assert len(truth["patients"]) == 8
    assert truth["linkability"]["required_units"] > 0
    sample_file = next(iter(truth["files"].values()))
    assert {"path", "format", "encoding", "expect", "category", "sha256", "size", "units"} <= set(sample_file.keys())
    sample_unit = next(iter(sample_file["units"].values()))
    assert {"loc", "patient", "cid", "link", "entities", "preserve"} <= set(sample_unit.keys())


def test_torture_smoke(tmp_path):
    """Two generated torture datasets must have zero leaks and zero false merges."""
    from tools.torture.check import check_seed
    for seed in (1, 2):
        res = check_seed(seed, tmp_path, 10, mr=False)
        bad = [f for f in res["fails"] if f["sev"] in ("S0", "S1") or f["kind"] == "leak"]
        assert not bad, json.dumps(bad[:3], ensure_ascii=False)


def test_accuracy_hardening_doctor_lab_linkage():
    """Verify doctor qualifications, health workers, lab ranges, and linkage improvements."""
    from wardguard.detect.context import detect_text
    from wardguard.detect.guards import is_protected
    from wardguard.detect.patterns import find_identifiers
    from wardguard.detect.evidence import parse_age, parse_gender, extract_unit_evidence
    from wardguard.model import EType, Unit, Slot, Evidence
    from wardguard.link import resolve

    # 1. Doctor qualification (MS Surgery) is not matched as patient name
    doc_text = "Consultant: Dr. Imtiaz Ahmed (MS Surgery)"
    m_doc = detect_text(doc_text)
    assert not any(m.text == "Surgery" for m in m_doc)

    # 2. ASHA workers is protected
    asha_text = "ASHA workers coordinate field reporting."
    assert is_protected(asha_text, 0, 4)

    # 3. Lab range 150000-410000 is not a PIN
    lab_text = "Platelet Count: 150000-410000 /uL"
    m_lab = find_identifiers(lab_text)
    assert not any(m.etype == EType.PIN for m in m_lab)

    # 4. Composite age_sex extraction
    assert parse_age("66/F") == 66
    assert parse_gender("66/F") == "F"

    # 5. Linkage phone sharing merges units with same name
    u1 = Unit(uid="u1", file_rel="f1.json", loc="1", patient_bearing=True)
    u1.evidence = Evidence(name_keys=("mahesh chauhan",), given_keys=("mahesh",), strong_ids=(("PHONE", "7286490658"),), age=48)
    u2 = Unit(uid="u2", file_rel="f2.json", loc="2", patient_bearing=True)
    u2.evidence = Evidence(name_keys=("mahesh chauhan",), given_keys=("mahesh",), strong_ids=(("PHONE", "7286490658"),), age=49)
    u3 = Unit(uid="u3", file_rel="f3.json", loc="3", patient_bearing=True)
    u3.evidence = Evidence(name_keys=("sunita chauhan",), given_keys=("sunita",), strong_ids=(("PHONE", "7286490658"),), age=45)

    resolve([u1, u2, u3], {"link_conflict_age_gap": 3})
    assert u1.cluster == u2.cluster
    assert u1.cluster != u3.cluster


def test_honorific_kinship_and_date_linkage():
    """Verify honorific stripping, kinship relative matching, and date harvesting in linkage."""
    from wardguard.link.normalize import canonical_name, phonetic_key
    from wardguard.link.cluster import has_conflict
    from wardguard.model import Evidence

    # 1. Honorific suffix stripping in canonical names
    assert canonical_name("Jaspreet babu") == "jasprit"
    assert canonical_name("Sukhwinder Papa") == "sukhvinder"
    assert canonical_name("Mohan Papa") == "mohan"
    assert canonical_name("Vikas babu") == "vikas"

    # 2. Kinship relative given name matching (e.g. Sukhwinder Singh vs Sukhwinder Papa)
    ev1 = Evidence(
        name_keys=("jasprit singh",),
        given_keys=("jasprit",),
        relative_keys=("sukhvinder singh",),
        age=45,
        gender="M",
        strong_ids=(("PHONE", "6004394755"),),
    )
    ev2 = Evidence(
        name_keys=("jasprit",),
        given_keys=("jasprit",),
        relative_keys=("sukhvinder",),
        age=45,
        gender="M",
        strong_ids=(("PHONE", "6004394755"),),
    )
    assert not has_conflict(ev1, ev2, max_age_gap=3)


def test_qi_hardening_dob_redact_fhir_xhtml_headers_and_cluster_kanon():
    """Verify A3/A4/A5 hardening: DOB redaction, XHTML URL preservation, Hindi/variant headers, and cluster-level k-anon."""
    import json
    from wardguard.detect import build_gazetteer, detect_file
    from wardguard.detect.columns import classify_column
    from wardguard.detect.evidence import normalize_district_key
    from wardguard.ingest.units import enumerate_units
    from wardguard.model import ParsedFile, Unit, Evidence, EType
    from wardguard.privacy.dates import date_offset
    from wardguard.privacy.kanon import plan
    from wardguard.rewrite import render

    # 1. Hindi / Hinglish / abbreviated snake_case header classification
    assert classify_column("तहसील", ["Khaga"]) == EType.TEHSIL
    assert classify_column("जिला", ["सीतापुर"]) == EType.DISTRICT
    assert classify_column("पिन", ["226001"]) == EType.PIN
    assert classify_column("tahsil", ["Khaga"]) == EType.TEHSIL
    assert classify_column("distt", ["Sitapur"]) == EType.DISTRICT
    assert classify_column("addr_line", ["House 12"]) == EType.HOUSE
    assert classify_column("birth_dt", ["1999-05-14"]) == EType.DOB

    # 2. Devanagari & fuzzy district normalization
    assert normalize_district_key("सीतापुर") == "sitapur"
    assert normalize_district_key("रायबरेली") == normalize_district_key("Rae Bareli")
    assert normalize_district_key("Barabanki") == "barabanki"

    # 3. Bounded min/max date offset determinism and amplitude invariant
    off_pol = {"date_shift_min_days": 15, "date_shift_max_days": 90}
    d1 = date_offset("C:P1", b"sec-a", off_pol)
    d2 = date_offset("C:P1", b"sec-b", off_pol)
    assert 15 <= abs(d1) <= 90
    assert 15 <= abs(d2) <= 90
    assert d1 == date_offset("C:P1", b"sec-a", off_pol)

    # 4. FHIR XHTML namespace preservation, comma age-sex banding, and DOB birthDate omission on redact
    fhir_bundle = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [{
            "resource": {
                "resourceType": "Patient",
                "id": "pat-1",
                "text": {"status": "generated", "div": '<div xmlns="http://www.w3.org/1999/xhtml">Ramesh Kumar, 27 yrs, male</div>'},
                "name": [{"text": "Ramesh Kumar"}],
                "gender": "male",
                "birthDate": "1999-05-14",
                "address": [{"district": "Sitapur", "postalCode": "261001"}],
            }
        }],
    }
    raw_fhir = json.dumps(fhir_bundle).encode("utf-8")
    pf = ParsedFile(rel="fhir/bundle_1.json", sha256="fh1", size=len(raw_fhir), fmt="fhir", obj=fhir_bundle)
    enumerate_units(pf)
    for u in pf.units:
        u.psn = "PSN-TEST01"
        u.date_offset = 25
        u.coarsen = True
    redact_pol = {**POLICY, "dob_action": "redact", "age_band_years": 20, "age_band_years_coarsen": 30, "age_top_code": 60, "pin_keep_digits": 1}
    detect_file(pf, build_gazetteer([pf], redact_pol), redact_pol)
    rendered = json.loads(render(pf, redact_pol).decode("utf-8"))
    pat = rendered["entry"][0]["resource"]
    assert "http://www.w3.org/1999/xhtml" in pat["text"]["div"]
    assert "20-39" in pat["text"]["div"] or "0-29" in pat["text"]["div"]
    assert "birthDate" not in pat
    assert pat["address"][0]["postalCode"] == "2*****"

    # 5. Cluster-level k-anonymity propagation across units sharing a patient cluster (Devanagari vs Latin district + DOB fallback)
    from wardguard.model import Slot
    cluster_units = []
    for i in range(2):
        cu = Unit(uid=f"reg#{i}", file_rel="reg.csv", loc=f"row:{i}", patient_bearing=True, cluster=f"P{i}")
        cu.evidence = Evidence(dob="1999-05-14", gender="M", district_key="सीतापुर")
        cu.slots = [Slot(path="col:diagnosis", text="Typhoid fever", channel="content")]
        cluster_units.append(cu)
    linked_other = Unit(uid="other#0", file_rel="other.txt", loc="doc", patient_bearing=True, cluster="P0")
    linked_other.evidence = Evidence(district_key="sitapur")
    cluster_units.append(linked_other)
    plan(cluster_units, {"k_min": 5, "age_band_years": 20, "age_band_years_coarsen": 30, "age_top_code": 60})
    assert all(unit.coarsen for unit in cluster_units)

