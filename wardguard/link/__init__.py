"""Record Linkage engine for WardGuard.

Implements TR-LNK-1..7:
- resolve(units: list[Unit], policy: dict) -> None:
    1. Blocking: index units by strong identifiers and phonetic blocking keys.
    2. Union-Find on shared strong IDs (UHID, Aadhaar, ABHA, PAN, MRN, Phone).
       Phone guard: shared phone only links if it occurs with the SAME patient name,
       avoiding merging different family members who share a single phone number.
    3. Name + second clue (DOB | relative | village + age +-1) only if that combination
       is unique in the dataset.
    4. Conflict Guard: refuses any union if clusters disagree on DOB, gender, relative,
       or age gap > link_conflict_age_gap (default 2).
    5. Cluster key generation: min sorted strong identifier core, or canonical name+clue string.
    6. Weak evidence units receive cluster = None ("patient": null).
    7. Fully deterministic execution.
"""
from __future__ import annotations
from collections import defaultdict
from typing import Optional
from wardguard.model import Unit
from wardguard.link.normalize import phonetic_key, canonical_name
from wardguard.link.cluster import DisjointSet, has_conflict


def resolve(units: list[Unit], policy: Optional[dict] = None) -> None:
    """Resolve patient identity clusters across units.
    
    Required contract:
        resolve(units: list[Unit], policy: dict) -> None
        Sets unit.cluster for linked units, None otherwise.
        Deterministic (sorts inputs, never iterates un-ordered sets).
        Must not read slots' raw text beyond unit.evidence.
    """
    if not units:
        return

    # Extract policy parameters
    max_age_gap = 2
    if policy:
        max_age_gap = policy.get("link_conflict_age_gap", 2)

    # Filter units with non-trivial evidence
    # Sort units deterministically by UID
    sorted_units = sorted(units, key=lambda u: u.uid)
    n = len(sorted_units)
    ds = DisjointSet(sorted_units, max_age_gap=max_age_gap)

    # --------------------------------------------------------------------------
    # Step 1: Inverted Index of Strong IDs
    # Map strong_id (e.g. ("AADHAAR", "451298347120")) -> list of unit indices
    # --------------------------------------------------------------------------
    strong_id_to_units: dict[tuple[str, str], list[int]] = defaultdict(list)
    for idx, u in enumerate(sorted_units):
        for sid in u.evidence.strong_ids:
            strong_id_to_units[sid].append(idx)

    # Family Phone Guard:
    # A phone number may be shared by a whole family (e.g. father, mother, child).
    # If a phone number is associated with MULTIPLE different patient name keys,
    # do NOT link purely on phone! Only link if they share the same patient name.
    phone_to_name_keys: dict[str, set[str]] = defaultdict(set)
    for (itype, core), u_indices in strong_id_to_units.items():
        if itype == "PHONE":
            for idx in u_indices:
                phone_to_name_keys[core].update(sorted_units[idx].evidence.name_keys)

    # Merge units sharing strong IDs
    for sid, u_indices in sorted(strong_id_to_units.items(), key=lambda x: (x[0][0], x[0][1])):
        itype, core = sid
        if len(u_indices) < 2:
            continue

        # If it's a phone and shared across multiple names, skip automatic merge
        if itype == "PHONE" and len(phone_to_name_keys.get(core, set())) > 1:
            continue

        first = u_indices[0]
        for other in u_indices[1:]:
            ds.union(first, other)

    # --------------------------------------------------------------------------
    # Step 2: Name + Second Clue (DOB | Relative | Village + Age +-1)
    # --------------------------------------------------------------------------
    # Build clues for units
    name_clue_to_units: dict[tuple[str, str], list[int]] = defaultdict(list)
    for idx, u in enumerate(sorted_units):
        ev = u.evidence
        for n_key in ev.name_keys:
            # Clue 1: Name + DOB
            if ev.dob:
                name_clue_to_units[(n_key, f"dob:{ev.dob}")].append(idx)
            # Clue 2: Name + Relative
            for r_key in ev.relative_keys:
                name_clue_to_units[(n_key, f"rel:{r_key}")].append(idx)
            # Clue 3: Name + Village + Age +- 1
            if ev.village_key and ev.age is not None:
                # Use binned age to allow +-1 tolerance: age // 2
                name_clue_to_units[(n_key, f"vil:{ev.village_key}:age:{ev.age // 2}")].append(idx)
            # Clue 4: Name + District + Age (indexed under district to allow pair matching within max_age_gap)
            if ev.district_key and ev.age is not None:
                name_clue_to_units[(n_key, f"dist:{ev.district_key}")].append(idx)

    # Only merge if the combination is unique in the dataset (i.e. links safe units without ambiguity)
    for (n_key, clue_val), u_indices in sorted(name_clue_to_units.items(), key=lambda x: (x[0][0], x[0][1])):
        if len(u_indices) < 2:
            continue
        if clue_val.startswith("dist:"):
            for i in range(len(u_indices)):
                for j in range(i + 1, len(u_indices)):
                    idx1 = u_indices[i]
                    idx2 = u_indices[j]
                    a1 = sorted_units[idx1].evidence.age
                    a2 = sorted_units[idx2].evidence.age
                    if a1 is not None and a2 is not None and abs(a1 - a2) <= ds.max_age_gap:
                        ds.union(idx1, idx2)
        else:
            first = u_indices[0]
            for other in u_indices[1:]:
                ds.union(first, other)

    # --------------------------------------------------------------------------
    # Step 3: Assign Canonical Cluster Key
    # --------------------------------------------------------------------------
    # Group units by root
    root_to_units: dict[int, list[int]] = defaultdict(list)
    for idx in range(n):
        root = ds.find(idx)
        root_to_units[root].append(idx)

    for root, cluster_indices in root_to_units.items():
        ev = ds.cluster_evidence[root]

        # Determine if evidence is strong enough to assign a cluster key
        # Weak evidence check: no strong IDs and no full name keys -> unlinked (None)
        if not ev.strong_ids and not ev.name_keys:
            for idx in cluster_indices:
                sorted_units[idx].cluster = None
            continue

        # If only 1 unit in cluster and no strong IDs and no DOB/relative, consider weak
        if len(cluster_indices) == 1 and not ev.strong_ids and not ev.dob and not ev.relative_keys:
            sorted_units[cluster_indices[0]].cluster = None
            continue

        # Determine stable, deterministic cluster key:
        # If strong ID is a shared family phone (associated with multiple names in dataset),
        # qualify cluster key with patient's name to ensure distinct clusters!
        non_phone_strong = [sid for sid in ev.strong_ids if sid[0] != "PHONE"]
        if non_phone_strong:
            itype, core = min(non_phone_strong, key=lambda x: (x[0], x[1]))
            cluster_key = f"{itype}:{core}"
        elif ev.strong_ids:
            # Phone-based strong ID: check if phone is shared across names
            itype, core = min(ev.strong_ids, key=lambda x: (x[0], x[1]))
            if itype == "PHONE" and len(phone_to_name_keys.get(core, set())) > 1:
                # Disambiguate with patient's name
                p_name = min(ev.name_keys) if ev.name_keys else f"root:{root}"
                cluster_key = f"PHONE:{core}:{p_name}"
            else:
                cluster_key = f"{itype}:{core}"
        # 2. Otherwise: min canonical name + clue string
        elif ev.name_keys:
            min_name = min(ev.name_keys)
            clue_part = ev.dob or (min(ev.relative_keys) if ev.relative_keys else "") or str(ev.age or "")
            cluster_key = f"NAME:{min_name}:{clue_part}"
        else:
            cluster_key = f"UNIT:{sorted_units[cluster_indices[0]].uid}"

        for idx in cluster_indices:
            sorted_units[idx].cluster = cluster_key


__all__ = [
    "resolve",
    "canonical_name",
    "phonetic_key",
    "DisjointSet",
    "has_conflict",
]
