"""Tests for Privacy Core: Pseudonym, Generalizers, Identity Assignment (TR-PRV-1, 5, 6)."""
from wardguard.model import Unit
from wardguard.privacy.generalize import age_band, assign_identity, generalize_pin
from wardguard.privacy.pseudonym import CROCKFORD_ALPHABET, pseudonym


def test_pseudonym_crockford_base32():
    secret_a = b"secret-alpha"
    secret_b = b"secret-beta"
    policy = {"psn_prefix": "PSN-"}

    p1 = pseudonym("cluster-A", secret_a, policy)
    p2 = pseudonym("cluster-A", secret_a, policy)
    p3 = pseudonym("cluster-B", secret_a, policy)
    p4 = pseudonym("cluster-A", secret_b, policy)

    # 1. Deterministic
    assert p1 == p2
    # 2. Distinct clusters get distinct pseudonyms
    assert p1 != p3
    # 3. Different secrets give different pseudonyms
    assert p1 != p4

    # 4. Format: PSN- + 6 Crockford Base32 characters
    assert p1.startswith("PSN-")
    token = p1[4:]
    assert len(token) == 6
    assert all(c in CROCKFORD_ALPHABET for c in token)
    # Ensure excluded ambiguous characters (I, L, O, U) never appear
    for forbidden in "ILOU":
        assert forbidden not in token


def test_age_band_contains_true_age():
    policy = {"age_band_years": 5, "age_top_code": 90}

    # Verify that for ages 0 to 89, the generated band always contains the true age
    for age in range(0, 90):
        band = age_band(age, policy)
        parts = band.split("-")
        assert len(parts) == 2
        lower, upper = int(parts[0]), int(parts[1])
        assert lower <= age <= upper
        assert upper - lower == 4

    # Test top-coding 90+
    assert age_band(90, policy) == "90+"
    assert age_band(102, policy) == "90+"


def test_generalize_pin():
    policy = {"pin_keep_digits": 3}
    assert generalize_pin("229073", policy) == "229***"
    assert generalize_pin("110001", policy) == "110***"
    # Short PIN preserved safely
    assert generalize_pin("12", policy) == "12"


def test_assign_identity_clusters_and_offsets():
    secret = b"eval-secret"
    policy = {"psn_prefix": "PSN-", "date_shift_max_days": 180}

    u1 = Unit(uid="f1#row:0", file_rel="f1.csv", loc="row:0", cluster="patient:Aarav")
    u2 = Unit(uid="f2#row:5", file_rel="f2.csv", loc="row:5", cluster="patient:Aarav")
    u3 = Unit(uid="f3#row:1", file_rel="f3.csv", loc="row:1", cluster="patient:Bhavna")
    u4 = Unit(uid="f4#doc", file_rel="f4.txt", loc="doc", cluster=None)

    units = [u1, u2, u3, u4]
    assign_identity(units, secret, policy)

    # u1 and u2 share cluster -> must have IDENTICAL psn and date_offset
    assert u1.psn == u2.psn
    assert u1.date_offset == u2.date_offset

    # u3 is different cluster -> different psn and offset
    assert u1.psn != u3.psn
    assert u1.psn.startswith("PSN-")
    assert u3.psn.startswith("PSN-")

    # u4 has no cluster -> keyed on u.uid, non-zero offset
    assert u4.psn is not None
    assert u4.date_offset is not None
    assert u4.date_offset != 0
