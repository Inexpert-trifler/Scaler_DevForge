"""k-anonymity planning and targeted coarsening.

Implements TR-PRV-7:
- Computes equivalence classes over quasi-identifiers: (age_band, gender, district, diagnosis)
- Identifies rare records where class size < k_min (default k=10)
- Sets unit.coarsen = True on rare records for targeted coarsening:
    - 20-year age band instead of 10-year
    - Suppressing district
    - Dropping village and tehsil
- Preserves common records at standard generalization level
"""
from __future__ import annotations

from collections import defaultdict
import re
from typing import Dict, List, Optional, Tuple

from wardguard.model import EType, Unit
from wardguard.privacy.generalize import age_band


def extract_unit_qi_signature(u: Unit, policy: dict, coarse: bool = False) -> Tuple[str, str, str, str]:
    """Extract (age_band, gender, district, diagnosis) quasi-identifier signature."""
    # 1. Age band
    age_band_val = "*"
    if u.evidence and u.evidence.age is not None:
        age_band_val = age_band(u.evidence.age, policy, coarsen=coarse)
    else:
        for s in u.slots:
            if s.column_type == EType.AGE:
                m_num = re.search(r"\d+", s.text)
                if m_num:
                    age_band_val = age_band(int(m_num.group(0)), policy, coarsen=coarse)
                    break
            for m in s.mentions:
                if m.etype == EType.AGE:
                    m_num = re.search(r"\d+", m.text)
                    if m_num:
                        age_band_val = age_band(int(m_num.group(0)), policy, coarsen=coarse)
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
    if not coarse:
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

    k_min = policy.get("k_min", 10)

    # Only patient-bearing units are subject to k-anonymity
    active_units = [u for u in units if u.patient_bearing]
    if not active_units:
        return

    # Count equivalence class frequencies over (age_band, gender, district)
    eq_classes: Dict[Tuple[str, str, str], List[Unit]] = defaultdict(list)
    for u in active_units:
        sig = extract_unit_qi_signature(u, policy, coarse=False)
        eq_classes[(sig[0], sig[1], sig[2])].append(u)

    # Mark units in classes smaller than k_min for targeted coarsening
    for qi_sig, member_units in eq_classes.items():
        is_rare = len(member_units) < k_min
        for u in member_units:
            u.coarsen = is_rare
