"""Generalization rules for age, PIN, village and identity assignment.

Implements TR-PRV-5, TR-PRV-6, and TR-PRV-8:
- age_band(age: int, policy: dict) -> str
  - Generates 5-year bands (e.g. "45-49") containing the true age
  - Top-codes ages >= 90 as "90+"
- generalize_pin(pin: str, policy: dict) -> str
  - Preserves true 3-digit prefix (e.g. "229073" -> "229***")
- generalize_village(village: str, unit: Unit, policy: dict) -> str
  - Generalizes village to tehsil / district or removes according to policy.village_action
- assign_identity(units: list[Unit], secret: bytes, policy: dict) -> None
  - Assigns deterministic keyed PSN and date_offset across all units
"""
from __future__ import annotations
from typing import List, Optional
from wardguard.model import Unit
from wardguard.privacy.dates import date_offset
from wardguard.privacy.pseudonym import pseudonym


def age_band(age: int, policy: dict, coarsen: bool = False) -> str:
    """Return age band, e.g. '45-49', '90+'.
    
    Guarantees the band always contains the true age.
    When coarsen=True, produces a wider band (default 10 years, e.g. '40-49').
    """
    top = policy.get("age_top_code", 90)
    if age >= top:
        return f"{top}+"
    width = policy.get("age_band_years_coarsen", 10) if coarsen else policy.get("age_band_years", 5)
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


def generalize_village(village: str, unit: Optional[Unit], policy: dict) -> str:
    """Generalize village name according to policy.village_action ('tehsil', 'district', 'remove')."""
    action = policy.get("village_action", "tehsil")
    if action == "remove":
        return ""

    if unit and unit.coarsen:
        # L-12: Coarsened rare records drop village and tehsil
        return ""

    if unit:
        # Check unit evidence for tehsil or district
        if action == "tehsil":
            if unit.evidence.relative_keys:
                pass
            if unit.evidence.district_key:
                return unit.evidence.district_key.capitalize()
        elif action == "district":
            if unit.evidence.district_key:
                return unit.evidence.district_key.capitalize()

    return ""


def assign_identity(units: List[Unit], secret: bytes, policy: dict) -> None:
    """Assign deterministic PSN and date_offset to all units based on cluster or uid."""
    for u in units:
        key = u.cluster or u.uid
        u.psn = pseudonym(key, secret, policy)
        u.date_offset = date_offset(key, secret, policy)
