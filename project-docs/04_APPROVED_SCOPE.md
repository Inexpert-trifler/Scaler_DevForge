# 04 · Approved Scope

> Anything not listed under "In scope" needs a new entry in `tracking/DECISIONS.md`, approved by **both** Lakshya and Saransh, before anyone (or any AI) works on it.

## ✅ In scope (approved v1.0)

| # | Item | Requirement IDs |
|---|---|---|
| S1 | CLI pipeline `main.py` + package `wardguard/` + `raksha.toml` | TR-RUN-* |
| S2 | Ingestion of CSV, TSV, JSON, FHIR R4 JSON, text (UTF-8, BOM, UTF-16, cp1252) | TR-ING-* |
| S3 | Quarantine of PDF, JPG, XML, binary, empty, truncated, undecodable files | TR-ING-6, 8 |
| S4 | Rule-based + gazetteer + transliteration PII detection in Latin, Devanagari, Hinglish | TR-DET-* |
| S5 | Hidden-channel sanitization (keys, headers, filenames, metadata, base64, escapes, FHIR narrative) | TR-DET-9 |
| S6 | Evidence-gated identity linkage with HMAC pseudonyms | TR-LNK-*, TR-PRV-1, 2 |
| S7 | Per-patient date shifting, age banding, PIN/village generalization, targeted k-anonymity | TR-PRV-* |
| S8 | report.json, records.jsonl, PII-free logging, determinism | TR-EXP-*, TR-SEC-* |
| S9 | Dev tooling: eval.sh, attack_sim.py, chaos_gen.py, pytest suite | TR-TOOL-* |
| S10 | README.md (root) + 2-page brief PDF (`docs/brief.pdf`) | R16 |

## 🟡 Stretch (only after M3 / H18, if every gate is green)

| # | Item | Condition |
|---|---|---|
| X1 | XML / HL7-CDA sanitization instead of quarantine | Only if robust; a bad parse = leak risk |
| X2 | Tiny self-trained CRF (sklearn-crfsuite) for names | < 50M params (trivially), declared in README, trained only on synthetic data |
| X3 | Before/after demo viewer (Streamlit or static HTML) in `demo/`, **not** imported by `main.py` | For the desk review only, practice data only |
| X4 | Multiprocessing | Only if it measurably helps under the 2-CPU / 4 GB limit |

## ❌ Out of scope (rejected)

| Item | Why |
|---|---|
| Any LLM / GPT / Gemini / Llama / large transformer **inside the product** | Disqualification |
| Web app, hospital product, login, database, REST server | Not graded; steals time |
| OCR of PDF/JPEG | Heavy, slow, risky; quarantine is scored as correct handling |
| Non-medical / other-sector data | Input is fixed by the organizers |
| Real patient data | Prohibited |
| Lists of practice-data names or file names in code | "No hardcoding" rule, and it fails the hidden data |
| Network calls of any kind at run time | Disqualification risk |

## Scope change process

1. Write a proposal in `tracking/DECISIONS.md` (status `PROPOSED`).
2. Both team members approve → status `APPROVED`. Then add it to this file and to `tracking/AI_TASK_STATES.md`.
3. AI assistants must **refuse** to implement unapproved scope and point to this file.
