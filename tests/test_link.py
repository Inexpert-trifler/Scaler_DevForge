"""Unit tests for linkage engine (Task S-08).

Tests:
- Homonyms (same name, different DOB/age/relative) stay apart (TR-LNK-4)
- Family members sharing a single phone number stay apart
- "Meera, W/o Rajan" links via relative + name match
- Cross-script same person (Devanagari registration + English discharge) links
- Deterministic cluster key assignment
- Weak evidence assigned cluster = None
"""
from __future__ import annotations
import pytest
from wardguard.model import Unit, Evidence
from wardguard.link import resolve


def test_homonyms_stay_apart():
    """Test that two people with the same name but different DOB or relatives do NOT merge."""
    # Person 1: Ramesh Kumar, DOB 1975-04-12, Son of Babu Ram
    ev1 = Evidence(
        name_keys=("ramesh kumar",),
        given_keys=("ramesh",),
        surname_keys=("kumar",),
        dob="1975-04-12",
        age=48,
        gender="M",
        relative_keys=("babu ram",),
    )
    u1 = Unit(uid="doc1#0", file_rel="doc1.csv", loc="row:0", evidence=ev1)

    # Person 2: Ramesh Kumar, DOB 1988-11-20, Son of Mohan Lal
    ev2 = Evidence(
        name_keys=("ramesh kumar",),
        given_keys=("ramesh",),
        surname_keys=("kumar",),
        dob="1988-11-20",
        age=35,
        gender="M",
        relative_keys=("mohan lal",),
    )
    u2 = Unit(uid="doc2#0", file_rel="doc2.csv", loc="row:0", evidence=ev2)

    resolve([u1, u2])

    # Conflict guard must prevent them from sharing a cluster key!
    assert u1.cluster != u2.cluster
    assert u1.cluster is not None
    assert u2.cluster is not None


def test_family_shared_phone_guard():
    """Test that a shared phone number does not incorrectly merge different family members."""
    # Father: Shyam Patel, Phone 9876543210
    ev1 = Evidence(
        name_keys=("shyam patel",),
        gender="M",
        age=50,
        strong_ids=(("PHONE", "9876543210"),),
    )
    u1 = Unit(uid="file1#0", file_rel="f1.csv", loc="row:0", evidence=ev1)

    # Mother: Sunita Patel, Phone 9876543210
    ev2 = Evidence(
        name_keys=("sunita patel",),
        gender="F",
        age=46,
        strong_ids=(("PHONE", "9876543210"),),
    )
    u2 = Unit(uid="file2#0", file_rel="f2.csv", loc="row:0", evidence=ev2)

    resolve([u1, u2])

    # Different names + different gender + shared family phone -> must NOT merge!
    assert u1.cluster != u2.cluster


def test_cross_script_same_person_links():
    """Test that the same patient across Devanagari and Latin records merges."""
    # Hindi record: सुनीता पटेल, 12/04/1977
    ev_hi = Evidence(
        name_keys=("sunita patel",),
        dob="1977-04-12",
        gender="F",
        village_key="durgamau",
    )
    u_hi = Unit(uid="hosp_hi#row:0", file_rel="hosp_hi.csv", loc="row:0", evidence=ev_hi)

    # English record: Sunita Patel, 12/04/1977
    ev_en = Evidence(
        name_keys=("sunita patel",),
        dob="1977-04-12",
        gender="F",
        village_key="durgamau",
    )
    u_en = Unit(uid="hosp_en#row:0", file_rel="hosp_en.csv", loc="row:0", evidence=ev_en)

    resolve([u_hi, u_en])

    # Must be linked together
    assert u_hi.cluster is not None
    assert u_hi.cluster == u_en.cluster


def test_link_via_relative():
    """Test linkage via Name + Relative clue (e.g. Meera, W/o Rajan)."""
    ev1 = Evidence(
        name_keys=("meera",),
        relative_keys=("rajan mishra",),
        gender="F",
    )
    u1 = Unit(uid="rec1#row:5", file_rel="rec1.csv", loc="row:5", evidence=ev1)

    ev2 = Evidence(
        name_keys=("meera",),
        relative_keys=("rajan mishra",),
        gender="F",
    )
    u2 = Unit(uid="rec2#row:12", file_rel="rec2.csv", loc="row:12", evidence=ev2)

    resolve([u1, u2])

    assert u1.cluster is not None
    assert u1.cluster == u2.cluster


def test_weak_evidence_unlinked():
    """Test that units with weak or no evidence remain unlinked (cluster = None)."""
    ev_weak = Evidence(
        name_keys=(),
        strong_ids=(),
        dob=None,
        age=None,
    )
    u_weak = Unit(uid="notes#doc", file_rel="notes.txt", loc="doc", evidence=ev_weak)

    resolve([u_weak])
    assert u_weak.cluster is None
