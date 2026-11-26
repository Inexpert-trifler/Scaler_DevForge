"""Disjoint Set (Union-Find) and Conflict Guard for record linkage.

Implements TR-LNK-2, TR-LNK-4:
- Conflict Guard: Refuses union if two units or clusters disagree on:
    - DOB (different non-empty ISO strings)
    - Gender ('M' vs 'F')
    - Age gap > 2 years (link_conflict_age_gap)
    - Relative name mismatch (if both specify relatives that do not match)
- Fully deterministic: merges smaller index into larger, or ties broken deterministically.
"""
from __future__ import annotations
from typing import Optional, Any
from wardguard.model import Unit, Evidence
from wardguard.link.normalize import phonetic_key


def has_conflict(ev1: Evidence, ev2: Evidence, max_age_gap: int = 2) -> bool:
    """Check if two units' evidence sets have an irreconcilable conflict.
    
    Returns True if merging them would be unsafe (conflict exists).
    TR-LNK-4: A wrong merge costs more than a missed link!
    """
    # 1. DOB conflict
    if ev1.dob and ev2.dob and ev1.dob != ev2.dob:
        return True

    # 2. Gender conflict
    if ev1.gender and ev2.gender and ev1.gender != ev2.gender:
        return True

    # 3. Age gap > allowed gap (accounts for temporal date difference between visits)
    if ev1.age is not None and ev2.age is not None:
        allowed_gap = max_age_gap
        y1 = [int(d[:4]) for d in ev1.dates if len(d) >= 4 and d[:4].isdigit()]
        y2 = [int(d[:4]) for d in ev2.dates if len(d) >= 4 and d[:4].isdigit()]
        if y1 and y2:
            allowed_gap = max(max_age_gap, abs(max(y1) - min(y2)) + 1, abs(max(y2) - min(y1)) + 1)
        if abs(ev1.age - ev2.age) > allowed_gap:
            return True

    # 4. Relative mismatch (if both specify relatives and sets are completely disjoint)
    # If both units share an indisputable strong ID (MRN, AADHAAR, ABHA_NUMBER, PAN),
    # different recorded family attendants do not block linking the same patient.
    has_indisputable = any(
        sid[0] in ("MRN", "AADHAAR", "ABHA_NUMBER", "PAN")
        for sid in (set(ev1.strong_ids) & set(ev2.strong_ids))
    )
    if not has_indisputable and ev1.relative_keys and ev2.relative_keys:
        set1 = set(ev1.relative_keys)
        set2 = set(ev2.relative_keys)
        if not (set1 & set2):
            return True

    # 5. Name mismatch (if both have full name keys and they are completely different)
    if ev1.name_keys and ev2.name_keys:
        set_n1 = set(ev1.name_keys)
        set_n2 = set(ev2.name_keys)
        if not (set_n1 & set_n2):
            g1 = set(ev1.given_keys)
            g2 = set(ev2.given_keys)
            if not (g1 & g2):
                p1 = {phonetic_key(k) for k in g1}
                p2 = {phonetic_key(k) for k in g2}
                if not (p1 & p2):
                    return True

    return False


def merge_evidence(ev1: Evidence, ev2: Evidence) -> Evidence:
    """Combine evidence of two clusters safely."""
    return Evidence(
        name_keys=tuple(sorted(set(ev1.name_keys) | set(ev2.name_keys))),
        given_keys=tuple(sorted(set(ev1.given_keys) | set(ev2.given_keys))),
        surname_keys=tuple(sorted(set(ev1.surname_keys) | set(ev2.surname_keys))),
        relative_keys=tuple(sorted(set(ev1.relative_keys) | set(ev2.relative_keys))),
        dob=ev1.dob or ev2.dob,
        age=ev1.age if ev1.age is not None else ev2.age,
        gender=ev1.gender or ev2.gender,
        village_key=ev1.village_key or ev2.village_key,
        district_key=ev1.district_key or ev2.district_key,
        strong_ids=tuple(sorted(set(ev1.strong_ids) | set(ev2.strong_ids))),
        dates=tuple(sorted(set(ev1.dates) | set(ev2.dates))),
    )


class DisjointSet:
    """Union-Find data structure with deterministic operations and conflict gating."""

    def __init__(self, units: list[Unit], max_age_gap: int = 2):
        self.units = units
        self.max_age_gap = max_age_gap
        # parent pointer for each unit index
        self.parent = list(range(len(units)))
        # aggregated evidence per root
        self.cluster_evidence = [u.evidence for u in units]

    def find(self, i: int) -> int:
        """Find representative root with path compression."""
        path = []
        curr = i
        while self.parent[curr] != curr:
            path.append(curr)
            curr = self.parent[curr]
        for node in path:
            self.parent[node] = curr
        return curr

    def union(self, i: int, j: int) -> bool:
        """Attempt to merge sets containing i and j.
        
        Refuses union and returns False if a conflict exists between the cluster evidence.
        """
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i == root_j:
            return True

        # Conflict check
        ev_i = self.cluster_evidence[root_i]
        ev_j = self.cluster_evidence[root_j]
        if has_conflict(ev_i, ev_j, self.max_age_gap):
            return False

        # Merge deterministically: smaller root index becomes parent of larger
        if root_i < root_j:
            self.parent[root_j] = root_i
            self.cluster_evidence[root_i] = merge_evidence(ev_i, ev_j)
        else:
            self.parent[root_i] = root_j
            self.cluster_evidence[root_j] = merge_evidence(ev_j, ev_i)

        return True
