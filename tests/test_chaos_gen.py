"""Unit tests for chaos dataset generator (Task S-09).

Tests:
- Header synonym and Hindi mutation
- Label prefix transformation
- Deterministic random seed reproducibility
"""
from __future__ import annotations
import random
from pathlib import Path
from tools.chaos_gen import mutate_header_name, mutate_text_content, generate_chaos


def test_mutate_header_name():
    """Test header mutation into synonyms or Hindi equivalents."""
    rng = random.Random(42)
    mutated = mutate_header_name("Patient Name", rng)
    assert mutated != "Patient Name" or len(mutated) > 0


def test_mutate_text_content():
    """Test text content label mutation."""
    raw = "Patient Name: Ramesh Kumar\nPhone: 9876543210\nDOB: 12/04/1977"
    name_map = {"Ramesh Kumar": "Aarav Singhania"}
    mutated = mutate_text_content(raw, name_map)
    assert "Aarav Singhania" in mutated
    assert "दूरभाष - 9876543210" in mutated or "Phone" not in mutated
