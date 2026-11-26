# 01 · Product Requirements Document (PRD): WardGuard

> Track 3 "Secret Wards", Yugaantar DevForge (Scaler) 24-hour hackathon
> Team: **Lakshya** + **Saransh** · Doc owner: Lakshya · Status: **APPROVED v1.0** (2026-11-26)

---

## 1. Problem

Hospitals in "Yugaantar Pradesh" are merging patient records from **4 hospital systems** into one research database. The incoming data is chaotic:

- formats: CSV, UTF-16 TSV, cp1252 legacy CSV, nested JSON, FHIR R4 bundles, free-text notes, broken files
- languages: English, Hindi in Devanagari, and Hinglish, often in the same sentence
- identity: the same patient appears as "Mohammad Arif", "मोहम्मद आरिफ", "Md. Arif" and "Arif sahab", each with a different hospital ID and phone format
- hidden PII: names and numbers inside JSON keys, CSV headers, file names, metadata and base64 attachments

If the merged data is released as-is, an attacker with a voter list can re-identify patients. If everything is deleted, the data is useless for research.

## 2. Product in one sentence

**WardGuard** is an offline, CPU-only, LLM-free **privacy firewall**: a command-line pipeline that turns a messy multi-hospital records dump into a de-identified research release. It removes every personal identifier, keeps every medical value exactly, gives each real patient one stable pseudonym across all files and scripts, and resists a re-identification attacker.

## 3. Users and stakeholders

| User | What they need from WardGuard |
|---|---|
| **Evaluator / grader** (primary "user") | Runs `python main.py --input X --output Y`; expects the exact output contract, determinism and no leaks |
| **Public-health researcher** (release consumer) | Correct medicines, doses, labs, diagnoses, intervals, age bands and linked patient histories |
| **Patient** (data subject) | Can't be found from the release, even by someone holding a voter list and gossip |
| **Attacker** (adversary) | Has a registry, leaked contacts and known facts; WardGuard must defeat attacks A1–A7 |
| **Judges** (desk review and finals) | Clear architecture, measured privacy-utility numbers, honest limitations |

## 4. Goals and success metrics

All numbers are **targets**. "Measured" values are tracked in `tracking/CURRENT_STATUS.md`.

| Goal | Metric (tool) | Target |
|---|---|---|
| G1 Remove PII | Leak rate overall and **per script** (check_dev.py) | < 3% overall; < 5% per script; **0 canaries** |
| G2 Keep medical value | Clinical probes kept (check_dev.py) | > 95% |
| G3 Link identities | Pairwise F0.5 / homonym merges (check_dev.py) | F0.5 > 0.90; **0 homonym merges** |
| G4 Resist attacker | Our `tools/attack_sim.py` A2–A5 risk relative to raw | Better than the reference (A3 27.7%, A4 16.7%, A5 40.1%) |
| G5 Valid export | validate_output.py | `CONTRACT OK` on every build |
| G6 Fast and stable | report.json timing and RSS; 2 runs give identical bytes | < 60 s, < 512 MB, deterministic |
| G7 Generalize | Score drop on our chaos dataset vs dev | < 10 points |
| G8 Submission ready | check_submission.py --run | `READY TO SUBMIT` |

**Official benchmark:** the starter scores about 8/100. The organizers' reference scores about 80–85 on normal data and about 48–50 on the unseen-format data. **Our aim is to beat the reference, especially on unseen formats.**

## 5. Non-goals (explicitly out of scope)

- No web app, dashboard, hospital product, login or database is graded. **Don't build one** before the pipeline is done. See `04_APPROVED_SCOPE.md`.
- No LLMs, no generative models and no pretrained transformers above 50M parameters. This is a hard disqualification rule.
- No real patient data, ever.
- No other sector's data (finance etc.). The organizers' synthetic hospital data is the only input.
- No OCR of PDF or JPEG files. Those are quarantined.

## 6. Requirements (prioritized)

P0 = must have for the top 10. P1 = needed to beat the reference. P2 = stretch.

| ID | Requirement | Priority | Owner |
|---|---|---|---|
| R1 | Output contract: `sanitized/` mirror, `report.json`, `records.jsonl`, exit 0 only when complete | P0 | Lakshya |
| R2 | Ingest CSV/TSV/JSON/FHIR/text in UTF-8, UTF-8-BOM, UTF-16 and cp1252; quarantine unsupported or broken files; never copy raw | P0 | Lakshya |
| R3 | Detect direct identifiers (phone, Aadhaar, masked Aadhaar, ABHA, PAN, MRN/UHID, insurance ID, email) in every channel | P0 | Saransh |
| R4 | Structured column classification by **header lexicon + value profiling** (robust to renamed columns) | P0 | Saransh |
| R5 | Free-text name detection in Latin, Devanagari and Hinglish using context rules (labels, S/o W/o D/o C/O, honorifics) | P0 | Saransh |
| R6 | Meaning-trap guards: Dr. names, doses, `1-0-1`, vitals, eponyms, "C/O fever", K/C/O, H/O, wards, ASHA | P0 | Saransh |
| R7 | HMAC-SHA256 pseudonyms keyed by `RAKSHA_SECRET`, written **inside** each record | P0 | Lakshya |
| R8 | Per-patient date shift preserving every interval and length of stay, in the original date format | P0 | Lakshya |
| R9 | Hidden channels: JSON keys, CSV headers, file names, metadata, FHIR narrative, base64, `\uXXXX` | P0 | Lakshya (+ Saransh detectors) |
| R10 | PII-free logs, stdout and stderr; no temp files; secret never written; input untouched; deterministic output | P0 | Lakshya |
| R11 | Cross-script dynamic gazetteer + transliteration (Mohammad ≈ Mohd ≈ Md. ≈ मोहम्मद) | P1 | Saransh |
| R12 | Evidence-gated linkage: strong IDs + unique name+clue + conflict guard; `null` when unsure | P1 | Saransh |
| R13 | Generalization: truthful 5-year age bands, PIN → 3-digit prefix, village → tehsil/district | P1 | Lakshya |
| R14 | k-anonymity scan + **targeted** coarsening of rare records only | P1 | Lakshya |
| R15 | Own attacker simulator (A2–A5) + chaos-data generator for measurement | P1 | Lakshya / Saransh |
| R16 | README + 2-page brief with measured numbers | P0 | Lakshya (Saransh supplies numbers) |
| R17 | XML (HL7 CDA) sanitization instead of quarantine | P2 | stretch |
| R18 | Small self-trained CRF for names (declared in README) | P2 | stretch |
| R19 | Demo viewer (before/after) **outside** `main.py`, practice data only | P2 | stretch |

## 7. Milestones (hackathon hours, H0 = start)

| Milestone | Hour | Exit gate |
|---|---|---|
| M0 Scaffold + contracts frozen | H2 | CONTRACT OK; `model.py` and `07_API_CONTRACTS.md` agreed by both |
| M1 Integrated v1 (detection end to end) | **H8** | All 4 canaries caught; recall > 90% per script |
| M2 Linkage + privacy | H14 | F0.5 > 0.9, 0 homonym merges; attack_sim numbers logged |
| M3 Hardened | H18 | Chaos delta < 10; READY TO SUBMIT; **feature freeze** |
| M4 Release | H22 | README + brief committed; final verification |
| Buffer | H22–24 | Fixes only |

## 8. Release criteria

Everything in `12_RELEASE_CHECKLIST.md` is ticked, the last commit is pushed before the deadline, and the brief PDF is in `docs/brief.pdf` and submitted.
