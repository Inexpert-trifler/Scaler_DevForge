"""Tests for k-anonymity and targeted coarsening (TR-PRV-7, L-12).

Validates:
- Equivalence class formation over (age_band, gender, district, diagnosis)
- Units in classes < k_min marked with unit.coarsen = True
- Common classes (>= k_min) preserved with unit.coarsen = False
- Targeted coarsening effects:
    - 10-year wider age band
    - Dropping village and tehsil
    - Suppressing district
- Non-patient bearing units ignored
- End-to-end integration and honest reporting of records_suppressed
"""
import json
from pathlib import Path
import tempfile
import pytest

from wardguard.model import EType, Evidence, ParsedFile, Slot, Unit
from wardguard.pipeline import run
from wardguard.privacy.generalize import age_band, generalize_village
from wardguard.privacy.kanon import extract_unit_qi_signature, plan
from wardguard.rewrite import render


@pytest.fixture
def policy():
    return {
        "k_min": 3,
        "age_band_years": 5,
        "age_band_years_coarsen": 10,
        "age_top_code": 90,
        "village_action": "tehsil",
    }


def test_extract_unit_qi_signature(policy):
    """Test extraction of QI signature (age_band, gender, district, diagnosis)."""
    u = Unit(uid="rec#0", file_rel="rec.csv", loc="row:0", patient_bearing=True)
    u.evidence = Evidence(age=48, gender="M", district_key="Varanasi")
    u.slots = [Slot(path="col:Diagnosis", text="Hypertension", channel="content")]

    sig = extract_unit_qi_signature(u, policy)
    assert sig == ("45-49", "M", "varanasi", "hypertension")


def test_kanon_plan_equivalence_classes(policy):
    """Classes with count >= k_min stay uncoarsened; classes < k_min get coarsen=True."""
    # Group 1: 3 identical units (meets k_min=3)
    g1_units = []
    for i in range(3):
        u = Unit(uid=f"u1_{i}", file_rel="file.csv", loc=f"row:{i}", patient_bearing=True)
        u.evidence = Evidence(age=45, gender="M", district_key="Varanasi")
        u.slots = [Slot(path="col:Diag", text="Asthma", channel="content")]
        g1_units.append(u)

    # Group 2: 1 rare unit (fails k_min=3)
    u_rare = Unit(uid="u_rare", file_rel="file.csv", loc="row:99", patient_bearing=True)
    u_rare.evidence = Evidence(age=72, gender="F", district_key="Gorakhpur")
    u_rare.slots = [Slot(path="col:Diag", text="Amyloidosis", channel="content")]

    all_units = g1_units + [u_rare]
    plan(all_units, policy)

    for u in g1_units:
        assert u.coarsen is False  # Group meets k=3 -> not coarsened

    assert u_rare.coarsen is True   # Rare group of 1 -> coarsened!


def test_targeted_coarsening_wider_age_band(policy):
    """A unit marked with coarsen=True receives a wider 10-year band."""
    age = 48
    normal_band = age_band(age, policy, coarsen=False)
    assert normal_band == "45-49"  # 5-year width

    coarsened_band = age_band(age, policy, coarsen=True)
    assert coarsened_band == "40-49"  # 10-year width; still contains 48


def test_targeted_coarsening_drops_village_and_district(policy):
    """Coarsened units drop village and district."""
    u_normal = Unit(uid="norm", file_rel="f.csv", loc="row:0", coarsen=False)
    u_normal.evidence = Evidence(district_key="Varanasi")
    v_norm = generalize_village("Rampur", u_normal, policy)
    assert v_norm == "Varanasi"  # Generalized to district

    u_rare = Unit(uid="rare", file_rel="f.csv", loc="row:1", coarsen=True)
    u_rare.evidence = Evidence(district_key="Varanasi")
    v_rare = generalize_village("Rampur", u_rare, policy)
    assert v_rare == ""  # Dropped completely for k-anonymity


def test_coarsening_in_rewrite_render(policy):
    """Render applies wider band and suppresses district when unit.coarsen=True."""
    pf = ParsedFile(
        rel="data.csv",
        sha256="d1",
        size=100,
        fmt="csv",
        header=["Age", "District", "Diagnosis"],
        status="pending",
    )
    u = Unit(
        uid="data.csv#row:0",
        file_rel="data.csv",
        loc="row:0",
        coarsen=True,  # Marked as rare
        patient_bearing=True,
    )
    u.slots = [
        Slot(path="col:Age", text="48", channel="content", column_type=EType.AGE),
        Slot(path="col:District", text="Gorakhpur", channel="content", column_type=EType.DISTRICT),
        Slot(path="col:Diagnosis", text="Rare Disease", channel="content"),
    ]
    pf.units = [u]

    data = render(pf, policy).decode("utf-8")
    lines = [line.strip() for line in data.strip().split("\n")]

    assert lines[0] == "Age,District,Diagnosis"
    # Row 1: Age gets 10-year band (40-49), District suppressed ("")
    assert lines[1] == "40-49,,Rare Disease"


def test_non_patient_bearing_units_not_coarsened(policy):
    """Units without patient data are not marked for coarsening."""
    u = Unit(uid="doc#0", file_rel="notice.txt", loc="doc", patient_bearing=False)
    u.slots = [Slot(path="doc", text="General Hospital Notice", channel="content")]

    plan([u], policy)
    assert u.coarsen is False


def test_pipeline_kanon_records_suppressed_reporting():
    """End-to-end pipeline correctly tallies records_suppressed in report.json."""
    policy = {
        "k_min": 5,
        "age_band_years": 5,
        "age_band_years_coarsen": 10,
        "age_top_code": 90,
    }
    with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
        inp = Path(in_dir)
        out = Path(out_dir)

        # 2 records in separate equivalence classes (both < k_min=5)
        (inp / "opd.csv").write_text(
            "Name,Age,Gender,Diagnosis\n"
            "Patient One,45,M,Fever\n"
            "Patient Two,72,F,Wilson Disease\n",
            encoding="utf-8",
        )

        code = run(inp, out, b"secret_kanon", policy)
        assert code == 0

        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        # Both units are rare (<5) so both are coarsened/suppressed
        assert report["counts"]["records_suppressed"] == 2
        assert report["counts"]["records_generalized"] >= 2
