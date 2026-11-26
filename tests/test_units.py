"""Tests for Unit and Slot enumeration (TR-ING-9)."""
from wardguard.ingest.units import enumerate_units, escape_pointer_segment
from wardguard.model import ParsedFile


def test_escape_pointer_segment():
    assert escape_pointer_segment("a/b~c") == "a~1b~0c"
    assert escape_pointer_segment("normal") == "normal"


def test_enumerate_units_csv():
    # CSV with normal, empty, and duplicated headers
    pf = ParsedFile(
        rel="opd/records.csv",
        sha256="abc",
        size=100,
        fmt="csv",
        header=["UHID", "Name", "Age", "Name", "  "],
        rows=[
            ["101", "Aarav", "35", "Aarav Alias", "Extra"],
            ["102", "Bhavna", "28", "Bhavna Alias", "None"],
        ],
        status="pending",
    )
    enumerate_units(pf)

    assert len(pf.units) == 2
    u0 = pf.units[0]
    assert u0.loc == "row:0"
    assert u0.uid == "opd/records.csv#row:0"
    assert len(u0.slots) == 5

    # Check slot paths
    paths = [s.path for s in u0.slots]
    # Unique header -> col:<header>
    assert paths[0] == "col:UHID"
    # Duplicated header -> col#<index>
    assert paths[1] == "col#1"
    assert paths[2] == "col:Age"
    assert paths[3] == "col#3"
    # Empty header -> col#<index>
    assert paths[4] == "col#4"

    # Check values and types
    assert u0.slots[0].text == "101"
    assert u0.slots[0].value_type == "str"


def test_enumerate_units_json_list_of_objects():
    # Top-level list of dicts
    pf = ParsedFile(
        rel="data/patients.json",
        sha256="123",
        size=100,
        fmt="json",
        obj=[
            {"id": 1, "name": "Chirag", "active": True},
            {"id": 2, "name": "Divya", "active": False},
        ],
        status="pending",
    )
    enumerate_units(pf)

    assert len(pf.units) == 2
    u0, u1 = pf.units[0], pf.units[1]

    assert u0.loc == "/0"
    assert u0.uid == "data/patients.json#/0"
    slot_map_0 = {s.path: (s.text, s.value_type) for s in u0.slots}
    assert slot_map_0["/0/id"] == ("1", "int")
    assert slot_map_0["/0/name"] == ("Chirag", "str")
    assert slot_map_0["/0/active"] == ("true", "bool")

    assert u1.loc == "/1"
    assert u1.uid == "data/patients.json#/1"
    slot_map_1 = {s.path: (s.text, s.value_type) for s in u1.slots}
    assert slot_map_1["/1/name"] == ("Divya", "str")
    assert slot_map_1["/1/active"] == ("false", "bool")


def test_enumerate_units_json_nested_visits():
    # Dict containing list of dicts at "visits"
    pf = ParsedFile(
        rel="hospital/export.json",
        sha256="456",
        size=200,
        fmt="json",
        obj={
            "hospital": "SGPGI",
            "visits": [
                {"token": "T1", "patient": {"name": "Eshan"}},
                {"token": "T2", "patient": {"name": "Farhan"}},
            ],
        },
        status="pending",
    )
    enumerate_units(pf)

    # 2 visit units + 1 doc unit for "hospital"
    assert len(pf.units) == 3
    locs = [u.loc for u in pf.units]
    assert "/visits/0" in locs
    assert "/visits/1" in locs
    assert "doc" in locs

    v0 = [u for u in pf.units if u.loc == "/visits/0"][0]
    v0_slots = {s.path: s.text for s in v0.slots}
    assert v0_slots["/visits/0/token"] == "T1"
    assert v0_slots["/visits/0/patient/name"] == "Eshan"


def test_enumerate_units_single_object_json():
    pf = ParsedFile(
        rel="lab/report.json",
        sha256="789",
        size=80,
        fmt="json",
        obj={"lab_id": 99, "patient": "Gauri", "score": 98.6},
        status="pending",
    )
    enumerate_units(pf)

    assert len(pf.units) == 1
    u = pf.units[0]
    assert u.loc == "doc"
    assert u.uid == "lab/report.json#doc"
    slots = {s.path: (s.text, s.value_type) for s in u.slots}
    assert slots["/lab_id"] == ("99", "int")
    assert slots["/patient"] == ("Gauri", "str")
    assert slots["/score"] == ("98.6", "float")


def test_enumerate_units_fhir():
    pf = ParsedFile(
        rel="fhir/bundle.json",
        sha256="fff",
        size=150,
        fmt="fhir",
        obj={"resourceType": "Bundle", "id": "b1", "total": 1},
        status="pending",
    )
    enumerate_units(pf)

    assert len(pf.units) == 1
    u = pf.units[0]
    assert u.loc == "doc"
    assert u.uid == "fhir/bundle.json#doc"
    slots = {s.path: s.text for s in u.slots}
    assert slots["/resourceType"] == "Bundle"
    assert slots["/id"] == "b1"


def test_enumerate_units_text():
    pf = ParsedFile(
        rel="notes/doctor.txt",
        sha256="ttt",
        size=50,
        fmt="text",
        text="Chief complaint: cough and fever for 2 days.",
        status="pending",
    )
    enumerate_units(pf)

    assert len(pf.units) == 1
    u = pf.units[0]
    assert u.loc == "doc"
    assert u.uid == "notes/doctor.txt#doc"
    assert len(u.slots) == 1
    assert u.slots[0].path == "doc"
    assert u.slots[0].text == "Chief complaint: cough and fever for 2 days."
    assert u.slots[0].channel == "content"
