"""Generalization rules for age, PIN, village and identity assignment."""
from typing import List
from wardguard.model import Unit
from wardguard.privacy.dates import date_offset
from wardguard.privacy.pseudonym import pseudonym


def age_band(age: int, policy: dict) -> str:
    """Return age band, e.g. '45-49', '90+'."""
    top = policy.get("age_top_code", 90)
    if age >= top:
        return f"{top}+"
    width = policy.get("age_band_years", 5)
    lower = (age // width) * width
    upper = lower + width - 1
    return f"{lower}-{upper}"


def generalize_pin(pin: str, policy: dict) -> str:
    """Generalize PIN code (e.g. '229073' -> '229***')."""
    keep = policy.get("pin_keep_digits", 3)
    clean = pin.strip()
    if len(clean) >= keep:
        return clean[:keep] + "*" * (len(clean) - keep)
    return clean


def assign_identity(units: List[Unit], secret: bytes, policy: dict) -> None:
    """Assign PSN and date_offset to patient-bearing units."""
    for u in units:
        key = u.cluster or u.uid
        if u.patient_bearing or u.cluster:
            u.psn = pseudonym(key, secret, policy)
            u.date_offset = date_offset(key, secret, policy)
