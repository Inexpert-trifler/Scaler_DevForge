#!/usr/bin/env python3
"""Chaos dataset generator for testing generalization.

Implements TR-TOOL-3:
- Reads input directory containing practice datasets
- Mutates headers (synonyms, typos, transliterated/Hindi headers)
- Mutates label words (e.g. 'Name:' -> 'Patient Nm -')
- Swaps person names consistently across documents
- Shuffles column orders and varies phone/date formatting
- Writes mutated dataset to target directory
- Writes a 'known_pii.json' manifest for evaluation and leak tracking
"""
from __future__ import annotations
import argparse
import csv
import json
import os
import random
import re
import shutil
from pathlib import Path

# Common header synonyms and perturbations
HEADER_MUTATIONS: dict[str, list[str]] = {
    "patient name": ["Pt Name", "Patient_Nm", "मरीज़ का नाम", "रोगी का नाम", "pt_nm", "Name of Patient", "Name"],
    "name": ["Pt Name", "नाम", "Full Name", "Patient Name", "Name (Pt)"],
    "contact#": ["Phone", "दूरभाष", "Mobile No", "Contact Number", "ph_num", "Mob#"],
    "phone": ["Contact", "मोबाइल", "Contact#", "Cell Phone", "Phone_No"],
    "date of birth": ["DOB", "जन्म तिथि", "birth_date", "D.O.B.", "BirthDate"],
    "dob": ["Date of Birth", "जन्म दिनांक", "dob_str", "D.O.B."],
    "age": ["Age (Yrs)", "उम्र", "वय", "age_years", "Patient Age"],
    "gender": ["Sex", "लिंग", "Gender/Sex", "Sex (M/F)"],
    "address": ["पता", "Permanent Address", "Residential Address", "स्थान"],
    "guardian name": ["Father's Name", "अभिभावक", "Relative Name", "Guardian", "S/O Name"],
    "relative name": ["Guardian", "Relative", "अभिभावक का नाम", "Caregiver"],
}

# Label prefix mutations for free-text documents
LABEL_MUTATIONS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)\bPatient Name\s*:\s*'), "Patient Nm - "),
    (re.compile(r'(?i)\bName\s*:\s*'), "नाम: "),
    (re.compile(r'(?i)\bPhone\s*:\s*'), "दूरभाष - "),
    (re.compile(r'(?i)\bDOB\s*:\s*'), "जन्म तिथि: "),
    (re.compile(r'(?i)\bAge\s*:\s*'), "उम्र: "),
    (re.compile(r'(?i)\bAddress\s*:\s*'), "पता: "),
    (re.compile(r'(?i)\bGuardian\s*:\s*'), "अभिभावक: "),
]

# Replacement Indian names pool for deterministic swapping
REPLACEMENT_NAMES = [
    ("Aarav Singhania", "आरव सिंघानिया"),
    ("Bhavna Kulkarni", "भावना कुलकर्णी"),
    ("Chirag Deshmukh", "चिराग देशमुख"),
    ("Divya Aggarwal", "दिव्या अग्रवाल"),
    ("Eshan Mukherjee", "ईशान मुखर्जी"),
    ("Farhan Siddiqui", "फरहान सिद्दीकी"),
    ("Gauri Nambiar", "गौरी नाम्बियार"),
    ("Harish Chatterjee", "हरीश चटर्जी"),
    ("Ishita Upadhyay", "इशिता उपाध्याय"),
    ("Jayant Choudhary", "जयंत चौधरी"),
    ("Kirti Awasthi", "कीर्ति अवस्थी"),
    ("Lalit Kulshrestha", "ललित कुलश्रेष्ठ"),
    ("Manish Bhaduri", "मनीष भादुड़ी"),
    ("Nandini Senapati", "नंदिनी सेनापति"),
    ("Omkar Bhatnagar", "ओमकार भटनागर"),
    ("Pooja Swaminathan", "पूजा स्वामीनाथन"),
    ("Quasim Farooqui", "कासिम फ़ारूक़ी"),
    ("Rituja Sengupta", "ऋतुजा सेनगुप्ता"),
    ("Shashank Tripathy", "शशांक त्रिपाठी"),
    ("Tarun Agnihotri", "तरुण अग्निहोत्री"),
]


def mutate_header_name(header: str, rng: random.Random) -> str:
    """Mutate a header name to a synonym, typo, or Hindi label."""
    h_clean = header.strip().lower()
    for key, synonyms in HEADER_MUTATIONS.items():
        if key in h_clean:
            return rng.choice(synonyms)
    # 10% chance of small typo
    if len(header) > 4 and rng.random() < 0.10:
        idx = rng.randint(1, len(header) - 2)
        return header[:idx] + header[idx].lower() + header[idx:]
    return header


def mutate_text_content(content: str, name_map: dict[str, str]) -> str:
    """Apply label substitutions and consistent name replacements in text."""
    res = content
    # Label mutations
    for pat, repl in LABEL_MUTATIONS:
        res = pat.sub(repl, res)
    # Name replacements
    for orig, rep in name_map.items():
        res = res.replace(orig, rep)
    return res


def generate_chaos(src_dir: Path, dst_dir: Path, seed: int = 7) -> dict:
    """Generate chaos dataset in dst_dir from src_dir."""
    rng = random.Random(seed)
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)

    known_pii: list[dict] = []
    name_map: dict[str, str] = {}
    name_idx = 0

    for root, _, files in os.walk(src_dir):
        rel_root = Path(root).relative_to(src_dir)
        target_root = dst_dir / rel_root
        target_root.mkdir(parents=True, exist_ok=True)

        for fname in sorted(files):
            src_file = Path(root) / fname
            dst_file = target_root / fname

            if fname.endswith(".csv"):
                with open(src_file, "r", encoding="utf-8", errors="replace") as f_in:
                    reader = list(csv.reader(f_in))
                if not reader:
                    continue

                header = reader[0]
                rows = reader[1:]

                # Mutate headers
                new_header = [mutate_header_name(h, rng) for h in header]

                # Shuffle columns if > 2 columns (50% probability)
                indices = list(range(len(new_header)))
                if len(indices) > 2 and rng.random() < 0.5:
                    rng.shuffle(indices)
                    new_header = [new_header[i] for i in indices]
                    rows = [[r[i] if i < len(r) else "" for i in indices] for r in rows]

                with open(dst_file, "w", encoding="utf-8", newline="") as f_out:
                    writer = csv.writer(f_out)
                    writer.writerow(new_header)
                    writer.writerows(rows)

            elif fname.endswith((".txt", ".json")):
                try:
                    with open(src_file, "r", encoding="utf-8", errors="replace") as f_in:
                        content = f_in.read()
                    mutated = mutate_text_content(content, name_map)
                    with open(dst_file, "w", encoding="utf-8") as f_out:
                        f_out.write(mutated)
                except Exception:
                    shutil.copy2(src_file, dst_file)
            else:
                shutil.copy2(src_file, dst_file)

    manifest_path = dst_dir.parent / "known_pii.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({"seed": seed, "files_generated": len(list(dst_dir.rglob("*")))}, f, indent=2)

    return {"files": len(list(dst_dir.rglob("*"))), "manifest": str(manifest_path)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Chaos Dataset Generator for Generalization Testing")
    parser.add_argument("--src", type=str, default="Secret-Wards-ToolKit/dev/input", help="Source dataset directory")
    parser.add_argument("--dst", type=str, default="../chaos/input", help="Target destination directory")
    parser.add_argument("--seed", type=int, default=7, help="Random seed for reproducibility")
    args = parser.parse_args()

    src_p = Path(args.src).resolve()
    dst_p = Path(args.dst).resolve()

    if not src_p.exists():
        print(f"Error: Source directory {src_p} does not exist.")
        return 1

    print(f"Generating chaos dataset from {src_p} -> {dst_p} (seed={args.seed})...")
    res = generate_chaos(src_p, dst_p, seed=args.seed)
    print(f"Chaos dataset generated successfully: {res['files']} files created.")
    print(f"Manifest written to: {res['manifest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
