"""Tests for Attack Simulator (TR-TOOL-2, L-11).

Validates:
- A1: Direct identifier leak detection
- A2/A3: Candidate filtering hierarchy and weighted scoring
- A4: Profile pooling by PSN
- A5: Global-shift recovery vs keyed per-patient offset resistance
- End-to-end attack simulation run on real pipeline output
"""
import json
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import pytest

from tools.attack_sim import (
    ReleaseEvidence,
    filter_candidates,
    score_candidates,
    pool_evidence_by_psn,
    detect_global_shift,
    run_attack_simulation,
    load_or_generate_attacker,
)
from wardguard.pipeline import run


@pytest.fixture
def mock_registry():
    return [
        {
            "patient_id": "P1",
            "name": "Rajesh Kumar",
            "given_name": "Rajesh",
            "surname": "Kumar",
            "relative_name": "Sita Devi",
            "gender": "M",
            "age": "45",
            "birth_year": "1978",
            "district": "Varanasi",
            "pin": "229073",
            "phone": "9876543210",
            "email": "rajesh@example.com",
            "aadhaar_last4": "1234",
        },
        {
            "patient_id": "P2",
            "name": "Sunita Devi",
            "given_name": "Sunita",
            "surname": "Devi",
            "relative_name": "Ramesh Kumar",
            "gender": "F",
            "age": "38",
            "birth_year": "1985",
            "district": "Varanasi",
            "pin": "229074",
            "phone": "9123456789",
            "email": "sunita@example.com",
            "aadhaar_last4": "5678",
        },
        {
            "patient_id": "P3",
            "name": "Amit Sharma",
            "given_name": "Amit",
            "surname": "Sharma",
            "relative_name": "Babu Lal",
            "gender": "M",
            "age": "46",
            "birth_year": "1977",
            "district": "Lucknow",
            "pin": "226001",
            "phone": "9998887776",
            "email": "amit@example.com",
            "aadhaar_last4": "9012",
        },
    ]


def test_candidate_filtering_hierarchy(mock_registry):
    """Test that candidate filtering narrows by district, gender, age band, and pin prefix."""
    ev = ReleaseEvidence(record_id="rec1", psn="PSN-001")
    ev.district = "Varanasi"
    ev.gender = "M"
    ev.age_range = (40.0, 50.0)
    ev.pin = "229***"

    filtered = filter_candidates(mock_registry, ev)
    # Only P1 matches (M, Varanasi, age 45, pin prefix 229)
    assert len(filtered) == 1
    assert filtered[0]["patient_id"] == "P1"


def test_candidate_filtering_skipped_when_empty(mock_registry):
    """Per ATTACKS.md §6, a filter that would empty the candidate set is skipped."""
    ev = ReleaseEvidence(record_id="rec2", psn="PSN-002")
    ev.district = "NonExistentDistrict"  # Unknown district
    ev.gender = "F"  # Female

    filtered = filter_candidates(mock_registry, ev)
    # District filter was skipped; gender filter applied -> P2
    assert len(filtered) == 1
    assert filtered[0]["patient_id"] == "P2"


def test_score_candidates_weights(mock_registry):
    """Test candidate scoring using ATTACKS.md §6 weights."""
    # Text contains full name of P1
    text = "Discharge summary for patient Rajesh Kumar with hypertension."
    probs = score_candidates(mock_registry, text)

    assert probs["P1"] > probs["P2"]
    assert probs["P1"] > probs["P3"]
    # P1 matched full name (weight 1 + 60 = 61), while P2/P3 have weight 1
    assert probs["P1"] > 0.90


def test_pool_evidence_by_psn():
    """A4 profile pooling merges evidence across records sharing the same PSN."""
    r1 = ReleaseEvidence(record_id="r1", psn="PSN-AARAV")
    r1.district = "Lucknow"
    r1.age_range = (45.0, 55.0)

    r2 = ReleaseEvidence(record_id="r2", psn="PSN-AARAV")
    r2.gender = "M"
    r2.age_range = (40.0, 50.0)
    r2.pin = "226***"

    profiles = pool_evidence_by_psn([r1, r2])
    assert "PSN-AARAV" in profiles
    prof = profiles["PSN-AARAV"]

    assert prof.district == "Lucknow"
    assert prof.gender == "M"
    assert prof.pin == "226***"
    # Intersected age range: [max(45, 40), min(55, 50)] = [45, 50]
    assert prof.age_range == (45.0, 50.0)


def test_global_shift_detection_recovered_on_constant_offset():
    """When all dates are shifted by a single constant offset, the attacker recovers it."""
    known_facts = [
        {"patient_id": "P1", "visit_date": "2023-04-10"},
        {"patient_id": "P2", "visit_date": "2023-04-15"},
        {"patient_id": "P3", "visit_date": "2023-04-20"},
        {"patient_id": "P4", "visit_date": "2023-04-25"},
        {"patient_id": "P5", "visit_date": "2023-04-30"},
    ]
    # Released records all shifted by exactly +10 days
    records = []
    for kf in known_facts:
        ev = ReleaseEvidence(record_id=f"r_{kf['patient_id']}")
        kf_dt = datetime.strptime(kf["visit_date"], "%Y-%m-%d")
        shifted_dt = kf_dt + timedelta(days=10)
        ev.dates.append(shifted_dt.strftime("%Y-%m-%d"))
        records.append(ev)

    recovered = detect_global_shift(known_facts, records)
    assert recovered == 10  # Constant shift recovered!


def test_global_shift_detection_recovered_with_registry():
    """Test global shift recovery when candidate registry is supplied."""
    registry = [
        {"rid": "R1", "name": "Rajesh Kumar"},
        {"rid": "R2", "name": "Sunita Devi"},
    ]
    known_facts = [
        {"rid": "R1", "visit_dates": ["2023-04-10"]},
        {"rid": "R2", "visit_dates": ["2023-04-15"]},
    ]
    r1 = ReleaseEvidence(record_id="rec1")
    r1.text_snippets.append("Patient Rajesh Kumar OPD note")
    r1.dates.append("2023-04-20")  # +10 days
    r2 = ReleaseEvidence(record_id="rec2")
    r2.text_snippets.append("Follow-up Sunita Devi clinic")
    r2.dates.append("2023-04-25")  # +10 days

    recovered = detect_global_shift(known_facts, [r1, r2], registry)
    assert recovered == 10


def test_attack_sim_kit_format_does_not_crash():
    """Verify load_or_generate_attacker and run_attack_simulation accept kit format (rid, visit_dates)."""
    with tempfile.TemporaryDirectory() as att_dir, tempfile.TemporaryDirectory() as rel_dir:
        att = Path(att_dir)
        rel = Path(rel_dir)
        (rel / "sanitized").mkdir()
        (rel / "records.jsonl").write_text("", encoding="utf-8")

        # Kit registry format
        (att / "registry.csv").write_text(
            "rid,name,relation,relative_name,gender,age,house_no,mohalla,village,tehsil,district,pin,phone,email,aadhaar_last4\n"
            "PAT-1,Aarav Singh,S/O,Balram,M,30,H1,M1,V1,T1,Lucknow,226001,9812345678,aarav@test.org,1234\n",
            encoding="utf-8",
        )
        # Kit known facts format
        (att / "known_facts.jsonl").write_text(
            json.dumps({"rid": "PAT-1", "visit_dates": ["2023-01-01"], "hospital": "HospA"}) + "\n",
            encoding="utf-8",
        )

        res = run_attack_simulation(rel, att)
        assert res["A1_direct_leak_risk"] == 0.0
        assert res["cohort_size"] == 1



def test_global_shift_detection_fails_on_random_offsets():
    """When dates are shifted by keyed per-patient offsets, global recovery fails."""
    known_facts = [
        {"patient_id": "P1", "visit_date": "2023-04-10"},
        {"patient_id": "P2", "visit_date": "2023-04-15"},
        {"patient_id": "P3", "visit_date": "2023-04-20"},
    ]
    # Released records shifted by diverse offsets: +12, -45, +88
    r1 = ReleaseEvidence(record_id="r1")
    r1.dates.append("2023-04-22")  # +12
    r2 = ReleaseEvidence(record_id="r2")
    r2.dates.append("2023-03-01")  # -45
    r3 = ReleaseEvidence(record_id="r3")
    r3.dates.append("2023-07-17")  # +88

    recovered = detect_global_shift(known_facts, [r1, r2, r3])
    assert recovered is None  # Attack defeated


def test_attack_simulation_end_to_end_on_eval_output():
    """Run full attack simulation suite on WardGuard release output and verify risk thresholds."""
    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
        inp = Path(in_dir)
        out = Path(out_dir)

        # Create sample clinical dataset
        (inp / "opd.csv").write_text(
            "Name,Age,Gender,Phone,Date,Diagnosis\n"
            "Rajesh Kumar,45,M,9876543210,12/04/2023,Hypertension\n"
            "Sunita Devi,38,F,9123456789,15/04/2023,Type 2 Diabetes\n",
            encoding="utf-8",
        )
        (inp / "notes.txt").write_text(
            "Patient Rajesh Kumar attended follow-up. Blood pressure 130/85.",
            encoding="utf-8",
        )

        code = run(inp, out, b"secret_eval_test", {})
        assert code == 0

        # Run attack simulation on sanitized output
        res = run_attack_simulation(out)

        # Assert all risks meet reference targets
        assert res["A1_direct_leak_risk"] == 0.0  # Zero leak
        assert res["A3_linkage_risk"] < 0.277     # Below reference 27.7%
        assert res["A4_profile_pooling_risk"] < 0.167  # Below reference 16.7%
        assert res["A5_targeted_facts_risk"] < 0.401   # Below reference 40.1%
        assert res["global_shift_recovered"] is False  # Per-patient HMAC offsets defeat shift recovery
