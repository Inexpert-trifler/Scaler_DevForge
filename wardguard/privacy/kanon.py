"""k-anonymity planning and targeted coarsening.

Implements TR-PRV-7:
- Computes equivalence classes over quasi-identifiers: (age_band, gender, district, diagnosis)
- Identifies rare records where class size < k_min (default k=5)
- Sets unit.coarsen = True on rare records for targeted coarsening:
    - Wider age band (10-year band instead of 5-year band)
    - Dropping village and tehsil
    - Suppressing district
- Preserves common records at standard generalization level
"""
from __future__ import annotations

from collections import defaultdict
import re
from typing import Dict, List, Optional, Tuple

from wardguard.model import EType, Unit
from wardguard.privacy.generalize import age_band


def extract_unit_qi_signature(u: Unit, policy: dict) -> Tuple[str, str, str, str]:
    """Extract (age_band, gender, district, diagnosis) quasi-identifier signature."""
    # 1. Age band
    age_band_val = "*"
    if u.evidence and u.evidence.age is not None:
        age_band_val = age_band(u.evidence.age, policy, coarsen=False)
    else:
        for s in u.slots:
            if s.column_type == EType.AGE:
                m_num = re.search(r"\d+", s.text)
                if m_num:
                    age_band_val = age_band(int(m_num.group(0)), policy, coarsen=False)
                    break
            for m in s.mentions:
                if m.etype == EType.AGE:
                    m_num = re.search(r"\d+", m.text)
                    if m_num:
                        age_band_val = age_band(int(m_num.group(0)), policy, coarsen=False)
                        break
            if age_band_val != "*":
                break

    # 2. Gender
    gender_val = "*"
    if u.evidence and u.evidence.gender:
        gender_val = u.evidence.gender
    else:
        for s in u.slots:
            if s.column_type == EType.GENDER and s.text.strip():
                gender_val = s.text.strip()[0].upper()
                break

    # 3. District
    district_val = "*"
    if u.evidence and u.evidence.district_key:
        district_val = u.evidence.district_key.lower()
    else:
        for s in u.slots:
            if s.column_type == EType.DISTRICT and s.text.strip():
                district_val = s.text.strip().lower()
                break
            elif "district" in s.path.lower() and s.text.strip():
                district_val = s.text.strip().lower()
                break

    # 4. Diagnosis / condition
    diag_val = "*"
    for s in u.slots:
        if any(w in s.path.lower() for w in ("diag", "condition", "complaint", "disease")):
            clean_diag = s.text.strip().lower()
            if clean_diag:
                diag_val = clean_diag
                break

    return (age_band_val, gender_val, district_val, diag_val)


def plan(units: List[Unit], policy: dict) -> None:
    """Targeted coarsening plan for rare records.
    
    Forms equivalence classes over quasi-identifiers.
    Sets unit.coarsen = True for any patient-bearing unit belonging
    to an equivalence class with size < k_min.
    """
    if not units:
        return

    k_min = policy.get("k_min", 5)

    # Only patient-bearing units are subject to k-anonymity
    active_units = [u for u in units if u.patient_bearing]
    if not active_units:
        return

    # Count equivalence class frequencies
    eq_classes: Dict[Tuple[str, str, str, str], List[Unit]] = defaultdict(list)
    for u in active_units:
        sig = extract_unit_qi_signature(u, policy)
        eq_classes[sig].append(u)

    # Mark units in classes smaller than k_min for targeted coarsening
    for sig, member_units in eq_classes.items():
        is_rare = len(member_units) < k_min
        for u in member_units:
            u.coarsen = is_rare
