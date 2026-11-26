from wardguard.privacy.dates import date_offset, shift_date_text
from wardguard.privacy.pseudonym import pseudonym
from wardguard.privacy.generalize import age_band, generalize_pin


def test_pseudonym_deterministic():
    secret = b"test-secret-key"
    policy = {"psn_prefix": "PSN-"}
    p1 = pseudonym("cluster-1", secret, policy)
    p2 = pseudonym("cluster-1", secret, policy)
    p3 = pseudonym("cluster-2", secret, policy)
    assert p1 == p2
    assert p1.startswith("PSN-")
    assert p1 != p3


def test_date_offset_and_shift():
    secret = b"test-secret-key"
    policy = {"date_shift_max_days": 180}
    offset = date_offset("cluster-1", secret, policy)
    assert -180 <= offset <= 180
    assert offset != 0

    orig = "2023-05-15"
    shifted = shift_date_text(orig, offset)
    assert shifted is not None
    assert shifted != orig
    # Reverse shift
    back = shift_date_text(shifted, -offset)
    assert back == orig


def test_age_band():
    policy = {"age_band_years": 5, "age_top_code": 90}
    assert age_band(47, policy) == "45-49"
    assert age_band(92, policy) == "90+"


def test_generalize_pin():
    policy = {"pin_keep_digits": 3}
    assert generalize_pin("229073", policy) == "229***"
