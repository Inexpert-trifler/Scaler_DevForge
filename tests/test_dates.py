"""Comprehensive tests for date shifting and format preservation (TR-PRV-3, TR-PRV-4)."""
from datetime import datetime
from wardguard.privacy.dates import date_offset, shift_date_text


def test_date_offset_properties():
    secret_a = b"practice-secret-key-1"
    secret_b = b"different-secret-key-2"
    policy = {"date_shift_max_days": 180}

    # Offset is never 0 and within [-max_days, max_days]
    offset_a = date_offset("cluster-1", secret_a, policy)
    assert -180 <= offset_a <= 180
    assert offset_a != 0

    # Deterministic across multiple calls with same key and secret
    assert date_offset("cluster-1", secret_a, policy) == offset_a

    # Different secret gives different offset (or key)
    offset_b = date_offset("cluster-1", secret_b, policy)
    assert offset_a != offset_b


def test_interval_preservation_nine_day_stay():
    """Requirement: A 9-day stay is still 9 days after date shifting."""
    secret = b"wardguard-secret"
    policy = {"date_shift_max_days": 180}
    offset = date_offset("patient-cluster-101", secret, policy)

    admit_date = "2023-04-10"
    discharge_date = "2023-04-19"

    shifted_admit = shift_date_text(admit_date, offset)
    shifted_discharge = shift_date_text(discharge_date, offset)

    assert shifted_admit is not None
    assert shifted_discharge is not None

    dt1 = datetime.strptime(shifted_admit, "%Y-%m-%d")
    dt2 = datetime.strptime(shifted_discharge, "%Y-%m-%d")
    stay_days = (dt2 - dt1).days
    assert stay_days == 9


def test_all_supported_date_formats():
    offset = 45

    # 1. ISO YYYY-MM-DD
    assert shift_date_text("2023-04-12", offset) == "2023-05-27"

    # 2. Indian DD/MM/YYYY
    assert shift_date_text("12/04/2023", offset) == "27/05/2023"

    # 3. Arogya legacy MM/DD/YYYY (month_first=True)
    assert shift_date_text("04/12/2023", offset, month_first=True) == "05/27/2023"

    # 4. DD-MM-YYYY
    assert shift_date_text("12-04-2023", offset) == "27-05-2023"

    # 5. DD.MM.YYYY
    assert shift_date_text("12.04.2023", offset) == "27.05.2023"

    # 6. YYYY/MM/DD
    assert shift_date_text("2023/04/12", offset) == "2023/05/27"

    # 7. DD-Mon-YYYY (uppercase and titlecase preservation)
    assert shift_date_text("12-Apr-2023", offset) == "27-May-2023"
    assert shift_date_text("12-APR-2023", offset) == "27-MAY-2023"


def test_datetime_and_timezone_preservation():
    offset = 10

    # ISO datetime with space
    res1 = shift_date_text("2023-04-12 14:30:00", offset)
    assert res1 == "2023-04-22 14:30:00"

    # ISO datetime with T and Z
    res2 = shift_date_text("2023-04-12T14:30:00Z", offset)
    assert res2 == "2023-04-22T14:30:00Z"

    # Slash datetime
    res3 = shift_date_text("12/04/2023 10:15", offset)
    assert res3 == "22/04/2023 10:15"


def test_devanagari_digits_date_shifting():
    offset = 5
    # १२/०४/२०२३ (12/04/2023) + 5 days -> 17/04/2023 -> १७/०४/२०२३
    deva_date = "१२/०४/२०२३"
    shifted_deva = shift_date_text(deva_date, offset)
    assert shifted_deva == "१७/०४/२०२३"
