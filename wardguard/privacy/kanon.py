"""k-anonymity planning and targeted coarsening.

Implements TR-PRV-7:
- Computes equivalence classes over quasi-identifiers: (age_band, gender, district, diagnosis)
- Aggregates across all units belonging to the same linked patient cluster so all
  records of a patient receive consistent coarsening decisions (preventing cross-format
  profile leaks where registration coarsens district while a CSV/FHIR/TXT file leaks it)
- Identifies rare patient classes where distinct patient count < k_min (default k=10)
- Sets unit.coarsen = True on rare records for targeted coarsening:
    - 20-year age band instead of 10-year
    - Suppressing district
    - Dropping village and tehsil
"""
from __future__ import annotations

from collections import defaultdict
import re
from typing import Dict, List, Tuple

from wardguard.detect.evidence import normalize_district_key, parse_iso_date
from wardguard.model import EType, Unit
from wardguard.privacy.generalize import age_band


_DIAG_PATH_WORDS = ("diag", "condition", "complaint", "disease", "dx", "bimari", "निदान")


def _extract_unit_diag(u: Unit) -> str:
    """Extract canonical diagnosis/condition clue from structured or FHIR unit slots."""
    for s in u.slots:
        pl = s.path.lower()
        if any(w in pl for w in _DIAG_PATH_WORDS):
            clean_diag = s.text.strip().lower()
            if clean_diag:
                return clean_diag
    # FHIR Condition coding/text path (/entry/<i>/resource/code/text or .../display)
    for s in u.slots:
        pl = s.path.lower()
        if "/code/" in pl and (pl.endswith("/text") or pl.endswith("/display")):
            clean_diag = s.text.strip().lower()
            if clean_diag and clean_diag not in ("http://snomed.info/sct", "http://hl7.org/fhir/sid/icd-10"):
                return clean_diag
    return "*"


def extract_unit_qi_signature(u: Unit, policy: dict, coarse: bool = False) -> Tuple[str, str, str, str]:
    """Extract (age_band, gender, district, diagnosis) quasi-identifier signature."""
    # 1. Age band (explicit age -> column/mention age -> DOB birth-year fallback)
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
        if age_band_val == "*":
            dob_str = u.evidence.dob if (u.evidence and u.evidence.dob) else None
            if not dob_str:
                for s in u.slots:
                    if s.column_type == EType.DOB and s.text.strip():
                        dob_str = parse_iso_date(s.text) or s.text.strip()
                        if dob_str:
                            break
            if dob_str:
                m_yr = re.search(r"\b(19\d\d|20\d\d)\b", dob_str)
                if m_yr:
                    ref_yr = 2026
                    if u.evidence and u.evidence.dates:
                        yrs = [int(d[:4]) for d in u.evidence.dates if len(d) >= 4 and d[:4].isdigit()]
                        if yrs:
                            ref_yr = max(yrs)
                    inferred_age = max(0, min(120, ref_yr - int(m_yr.group(1))))
                    age_band_val = age_band(inferred_age, policy, coarsen=coarse)

    # 2. Gender
    gender_val = "*"
    if u.evidence and u.evidence.gender:
        gender_val = u.evidence.gender
    else:
        for s in u.slots:
            if s.column_type == EType.GENDER and s.text.strip():
                gender_val = s.text.strip()[0].upper()
                break

    # 3. District (canonically folded across Latin/Devanagari)
    district_val = "*"
    if not coarse:
        if u.evidence and u.evidence.district_key:
            district_val = normalize_district_key(u.evidence.district_key) or u.evidence.district_key.lower()
        else:
            for s in u.slots:
                if s.column_type == EType.DISTRICT and s.text.strip():
                    district_val = normalize_district_key(s.text) or s.text.strip().lower()
                    break
                elif "district" in s.path.lower() and s.text.strip():
                    district_val = normalize_district_key(s.text) or s.text.strip().lower()
                    break

    # 4. Diagnosis / condition
    diag_val = _extract_unit_diag(u)

    return (age_band_val, gender_val, district_val, diag_val)


def plan(units: List[Unit], policy: dict) -> None:
    """Targeted coarsening plan for rare records at patient-cluster granularity.

    Groups all units of the same linked patient cluster (or standalone unit UID when
    unlinked) so multi-record patients cannot artificially inflate class size above
    k_min AND every record belonging to a rare patient gets coarsened uniformly.
    """
    if not units:
        return

    k_min = policy.get("k_min", 10)

    active_units = [u for u in units if u.patient_bearing]
    if not active_units:
        return

    # Group units by linked patient cluster (unlinked singletons stay distinct via uid)
    cluster_units: Dict[str, List[Unit]] = defaultdict(list)
    for u in active_units:
        pkey = f"C:{u.cluster}" if u.cluster else f"U:{u.uid}"
        cluster_units[pkey].append(u)

    # Build merged QI signature per patient cluster across all formats/units
    eq_classes: Dict[Tuple[str, str, str, str], List[str]] = defaultdict(list)
    for pkey, p_units in cluster_units.items():
        sigs = [extract_unit_qi_signature(u, policy, coarse=False) for u in p_units]
        age_v = next((s[0] for s in sigs if s[0] != "*"), "*")
        gen_v = next((s[1] for s in sigs if s[1] != "*"), "*")
        dist_v = next((s[2] for s in sigs if s[2] != "*"), "*")
        diag_v = next((s[3] for s in sigs if s[3] != "*"), "*")
        eq_classes[(age_v, gen_v, dist_v, diag_v)].append(pkey)

    # Mark ALL units belonging to any patient cluster in a class < k_min as coarsen=True
    for _qi_sig, member_pkeys in eq_classes.items():
        is_rare = len(member_pkeys) < k_min
        for pkey in member_pkeys:
            for u in cluster_units[pkey]:
                u.coarsen = is_rare
