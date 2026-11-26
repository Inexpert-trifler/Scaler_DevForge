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


def test_torture_smoke(tmp_path):
    """Two generated torture datasets must have zero leaks and zero false merges."""
    from tools.torture.check import check_seed
    for seed in (1, 2):
        res = check_seed(seed, tmp_path, 10, mr=False)
        bad = [f for f in res["fails"] if f["sev"] in ("S0", "S1") or f["kind"] == "leak"]
        assert not bad, json.dumps(bad[:3], ensure_ascii=False)
