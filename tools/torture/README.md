# WardGuard Torture Lab: hand-off for continued testing

Development-only tools (never imported by `main.py`). They generate hard synthetic hospital dumps
with an **answer key**, run the **real CLI** on them, and fail loudly on any leak, crash, raw copy,
false merge, lost clinical value or nondeterminism.

## 1. Files

| File | What it does |
|---|---|
| `tools/torture/gen.py` | Seeded generator: messy multi-hospital dump + `answer.json` (what must be removed, what must stay, who is who) |
| `tools/torture/check.py` | Runs `python main.py` (private TMPDIR/HOME) and scores leaks, kept values, linking, LOS, invariants, determinism and secret change |
| `tools/torture/fuzz.py` | Byte-level fuzzer: hundreds of corrupted files in one run; checks no crash, every file reported, no raw copy, no PII left |
| `tests/test_torture_regressions.py` | 27 pytest regressions for every bug the lab found (also runs a 2-seed torture smoke test) |

## 2. Commands

```bash
# all unit + regression tests (must be 0 failed)
python3 -m pytest -q

# torture campaign (each seed ~2 s incl. determinism + secret-change reruns)
python3 -m tools.torture.check --seeds 1-100 --work /tmp/wg_torture --show 25
#   --no-mr        skip the determinism / secret-change reruns (3x faster)
#   --patients N   people per dataset (default 14; try 60-400 for scale)
#   outputs: /tmp/wg_torture/summary.json, failures.jsonl, seed_XXXX/{input,answer.json,out1}

# fuzzing (300 corrupted files per seed)
for s in 1 2 3 4 5; do python3 -m tools.torture.fuzz --seed $s --variants 300 --work /tmp/wg_fuzz; done

# organizer practice data (must stay at 0 leaks)
RAKSHA_SECRET=practice python3 main.py --input ../Secret-Wards-ToolKit/dev/input --output /tmp/wg_dev
python3 -I ../Secret-Wards-ToolKit/validate_output.py --input ../Secret-Wards-ToolKit/dev/input --output /tmp/wg_dev
python3 -I ../Secret-Wards-ToolKit/check_dev.py --output /tmp/wg_dev --show 20
```
Exit code of `check.py` / `fuzz.py` is non-zero if any S0/S1 failure exists.

## 3. Severity of failures

| Sev | Kinds |
|---|---|
| S0 | `exit_code`, `input_modified`, `temp_leftovers`, `raw_copy`, `canary_leak`, `side_channel_leak` (PII in stdout/stderr/report), `nondeterministic`, `psn_stable_across_secrets`, `report_missing_file` |
| S1 | critical `leak` (name, phone, Aadhaar, ABHA, MRN, PAN...), `false_merge` / `homonym_merge` / `twin_merge`, `not_quarantined`, `output_invalid_json`, `csv_row_count` / `csv_col_count` |
| S2 | quasi-identifier `leak` (village, locality, DOB, age...), `lost_clinical`, `date_not_shifted`, `los_changed`, `mr05_*`, `record_missing` |
| S3 | `district_coarsened` (k-anonymity blanked district on a rare row: utility cost, by policy) |

## 4. What is already covered (and passing)

Measured on commit with this README, 100 seeds / 79,470 labelled PII values:
**0 leaks, 0 critical, 100% clinical kept, link precision 1.00, recall 0.92, 0 false merges**;
5 x 300 fuzzed files: **0 crashes, 0 raw copies, 0 PII left**; kit practice data: **0 / 3230 leaked, 99.1% clinical kept, linking P 1.00 / R 0.75**.

Generator content per seed: 5 header styles (English, snake_case, Hindi, Hinglish, cryptic `PT/REL/D_O_B`),
encodings utf-8 / BOM / UTF-16 / cp1252, delimiters `, ; \t`; discharge summaries (label variants, 8 phone formats,
Aadhaar 4 formats, ABHA with/without dashes, address lines, consultant doctors, eponyms, doses, vitals, labs,
`Review in OPD`), Hindi notes (Devanagari digits), Hinglish WhatsApp chats (kinship senders), nursing notes,
referral letters (`R/o`), OPD JSON (PII in keys, metadata, base64 attachment, `\u`-escaped Devanagari), FHIR bundles,
canaries, broken files (truncated JSON, empty, PDF, JPEG, XML, JSON-in-.csv, invalid UTF-8, 60-deep JSON),
hard mode (PAN, PMJAY, e-mail, ABHA address, masked Aadhaar, initials, CAPS names, line-wrapped names, zero-width
and NBSP inside names, NDJSON, PII in folder names, title line above CSV header, spelling-variant fragments, 90+ ages),
homonym pairs and twins.

## 5. Bugs found and fixed by this lab (keep them fixed)

1. Clinical guards suppressed real phone numbers (a phone on the line before `Consultant: Dr ...`).
2. "Name + number" rule tagged `Review in OPD after 2 weeks` as a patient name (clinical text replaced by PSN).
3. Phone formats `91 8507 700 469`, `(+91) ...`, dotted; plain 14-digit ABHA; ABHA starting with 0 after a label.
4. Village / locality / landmark inside free-text address lines and `R/o` sentences leaked.
5. Kinship-named relatives (`Ramesh Mama`) and chat senders leaked.
6. DOB with dots or month names (`11.10.1968`, `12 Apr 1977`) leaked.
7. Ages in text were not banded (single-digit ages dropped by a length check).
8. Hindi header `मरीज़ का नाम` rewritten as a name; Hindi names cut at postpositions (`को`, `ने`).
9. Date columns with Hindi/Hinglish/abbreviated headers (`भर्ती तिथि`, `IN_DT`) were never shifted; DOB vs visit date now decided by header or by year spread.
10. PII in **folder names** was not renamed (also leaked via report.json); renamed files could collide with unrenamed ones.
11. Devanagari ↔ Latin names did not match for linking (anusvara, final schwa, aspiration); linker now compares phonetic keys; family-phone guard tolerates given-name-only mentions.
12. Header-only CSV/TSV (or a note saved as .csv) was written verbatim: `detect_file` returned early when a file had no data units.
13. Unit-less text / rows were written raw; base64 blobs inside free text and CSV cells were not scrubbed.
14. NDJSON (`.jsonl`) was sniffed as CSV and mangled.
15. Initials rule false positive `Temp 99.2 F. Serum` spread through the gazetteer; weak guesses no longer feed the gazetteer.

## 6. Still to do (continue here, in this order)

1. **Performance / scale (highest risk).** Fuzz runs of 300 files took 25-44 s, so some inputs are slow. Generate
   `--patients 400` (≈1,500 files) and a single 200k-row CSV, a 50 MB single-line file, 10,000-deep JSON, and
   repeated `S/o S/o S/o ...` (regex backtracking). Budget: standard profile good ≤ 60 s, limit 900 s, RSS ≤ 512 MB good / 4 GB limit.
   Profile with `python -m cProfile -s cumtime main.py ...` and fix the hot spots.
2. **Independent attack arena A1-A7** (kit `docs/ATTACKS.md`) against torture outputs, with registry + known facts
   generated from the answer key (add `attacker/registry.csv` + `known_facts.jsonl` to `gen.py`). Targets:
   A3 < 27.7%, A4 < 16.7%, A5 < 40.1%, A6 = 0, A7 = 0, no global shift recovered.
3. **More metamorphic relations** (only MR-05 secret change is automated): row shuffle → same PSN per row; rename a
   PII-free file → identical content; transliterate one file Latin→Devanagari → same PSN; run on a subset → same
   PSNs for shared patients; duplicate the input into a sub-folder → same PSNs.
4. **Holdout variation** the product has never seen (do not show these to whoever tunes the product): new states'
   geography, Voter ID (EPIC), driving licence, ration card, new hospital MRN shapes, new note templates
   (lab requisition, death summary, OT notes), Urdu-script fragments, new kinship words.
5. **Over-redaction metric**: share of non-PII words of the input that survive (token retention).
6. **Sandbox fidelity**: run the CLI in Docker `--network none --cpus 2 --memory 4g`, input mounted read-only;
   Python 3.10 / 3.11 / 3.12.
7. **Kit-format truth**: export `answer.json` as `raksha-truth/1` so the organizers' `check_dev.py` can score torture datasets.
8. Review `district_coarsened` (k-anonymity blanks district on rare rows in small datasets) with the team: policy decision.

## 7. Rules (do not break)

- Never weaken a check to make the product pass. If a check is wrong, fix the check and say so.
- Fixes must be **generic** (no names, files, headers or seeds from the generator hard-coded in `wardguard/`).
- Every product fix gets a regression test in `tests/test_torture_regressions.py` with invented data.
- After every fix re-run: `pytest`, `check.py --seeds 1-100`, `fuzz.py` seeds 1-5, kit `check_dev.py` (must stay 0 leaks).
- Product code stays offline, deterministic, LLM-free, counts-only logging; never write `RAKSHA_SECRET`.

## 8. Prompt for the Antigravity agent

```
You are continuing the hardening of WardGuard (offline, CPU-only, LLM-free PII de-identification
pipeline for multilingual Indian hospital records; Yugaantar DevForge Track 3). Read
tools/torture/README.md fully first, then wardguard/pipeline.py, tools/torture/gen.py,
tools/torture/check.py, tools/torture/fuzz.py and tests/test_torture_regressions.py.

Baseline you must reproduce before changing anything (sections 2 and 4 of the README):
pytest 0 failed; check.py --seeds 1-100: 0 leaks, 0 S0/S1; fuzz seeds 1-5: FUZZ OK; kit check_dev: 0/3230.

Then work through section 6 ("Still to do") in order. For each item:
1. extend the generator / checker / fuzzer with the new hard cases (deterministic, seeded, synthetic only),
2. run it and list every failure grouped by kind with 2 examples each,
3. decide for each group: product bug or checker bug (say which and why),
4. fix product bugs GENERICALLY in wardguard/ (no hard-coded test values), add a regression test,
5. re-run the full gate (pytest, 100 seeds, fuzz 1-5, kit check_dev) and report the numbers in a table.
Never weaken a check, never tune to a single seed, never add network/LLM/temp files/logging of values.
Commit after each item with message "[TORTURE-n] <area>: <what>" on branch lakshya/torture-hardening.
```
