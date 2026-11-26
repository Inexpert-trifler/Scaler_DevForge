# AI Task States

> The live task board. **Update the row** whenever a task changes state. Each owner edits only their own rows, which avoids merge conflicts.
> States: `TODO` → `IN_PROGRESS` → `REVIEW` (pushed, partner checking) → `DONE` · `BLOCKED` (write the reason in Notes)
> Hours are hackathon hours (H0 = start). "Gate" = how we know it's done.

## Shared milestones

| ID | Milestone | Hour | State | Gate |
|---|---|---|---|---|
| M0 | Scaffold + contracts frozen | H2 | TODO | CONTRACT OK; both confirm `model.py` + `07_API_CONTRACTS.md` |
| M1 | Integrated detection v1 | H8 | TODO | 4/4 canaries; recall > 0.9 per script |
| M2 | Linkage + privacy | H14 | TODO | F0.5 > 0.9; 0 homonym merges; attack_sim numbers logged |
| M3 | Hardened + feature freeze | H18 | TODO | chaos delta < 10; READY TO SUBMIT |
| M4 | Release | H22 | TODO | 12_RELEASE_CHECKLIST all ticked |

## Lakshya: Platform + Privacy

| ID | Task | Hours | Depends | Reqs | State | Gate / Notes |
|---|---|---|---|---|---|---|
| L-01 | Scaffold: new layout, raksha.toml, port starter I/O + HMAC helpers, stubs for every module, remove `src/` | H0–1.5 | – | TR-RUN-2 | TODO | `main.py` runs end to end with stubs; CONTRACT OK |
| L-02 | `model.py` + contracts freeze with Saransh | H1–2 | L-01 | 06, 07 | TODO | both approve; M0 |
| L-03 | `tools/eval.sh` (run → validate → check_dev → log line; second run → determinism diff) | H1.5–2.5 | L-01 | TR-TOOL-1 | TODO | one command gives scores |
| L-04 | Safety: `log.event`, `safe_reason`, top-level try/except, report in `finally` | H2–3 | L-01 | TR-SEC-2, 3 | TODO | crash test → still exit 0 + report |
| L-05 | Ingest: sniff, decode, CSV/TSV/JSON/FHIR/text readers, deep JSON, quarantine | H2.5–5.5 | L-04 | TR-ING-1..8 | TODO | all 200 dev files parsed or quarantined correctly |
| L-06 | Unit enumeration + content slots (`row:N`, pointers, `doc`) | H4–6 | L-05 | TR-ING-9 | TODO | locs match truth for 95%+ units |
| L-07 | Export writers (format-preserving, UTF-8, header/delimiter, JSON types) + records.jsonl + report.json | H5–8 | L-06 | TR-EXP-1..4 | TODO | CONTRACT OK with real data |
| L-08 | Hidden channels: keys, headers, filenames (rename), metadata, base64, escapes, FHIR narrative | H7–11 | L-06, S-05 | TR-DET-9 | TODO | channel leaks = 0 on dev |
| L-09 | Privacy core: pseudonym, date_offset, format-preserving date shift, age band, PIN, village → tehsil | H6–10 | L-02 | TR-PRV-1..6, 8 | TODO | interval test; A7 different-secret test |
| L-10 | Rewrite engine: apply mentions, PSN placement, QI generalization | H8–11 | L-07, L-09 | TR-PRV-2, 08 §4 | TODO | **M1 integration** |
| L-11 | `tools/attack_sim.py` (A2–A5 incl. global-shift recovery) | H10–14 | L-10 | TR-TOOL-2 | TODO | raw vs ours numbers logged |
| L-12 | k-anonymity plan + targeted coarsening; tune k, DOB policy (D-012) | H13–16 | L-11, S-08 | TR-PRV-7 | TODO | A5 < reference 40.1% |
| L-13 | Performance, memory, determinism; check_submission READY | H15–18 | all | TR-RUN-6, TR-SEC-4 | TODO | **M3** |
| L-14 | README + 2-page brief (numbers from both) | H18–21 | L-13 | R16 | TODO | docs/brief.pdf ≤ 2 pages |
| L-15 | Release checklist, cleanup, final push | H21–23 | L-14 | 12 | TODO | **M4** |

## Saransh: Intelligence (Detection + Linkage)

| ID | Task | Hours | Depends | Reqs | State | Gate / Notes |
|---|---|---|---|---|---|---|
| S-01 | Kit setup, read docs, study dev data; build `resources/` lexicons (labels EN/HI, honorifics, relations, generic tokens, drugs, eponyms, complaints, UP districts/tehsils, given names/surnames Latin+Deva) | H0–3 | – | TR-DET-4, 6 | DONE | 19 generic files committed (>7k tokens); baseline logged |
| S-02 | `normalize.py` + `patterns.py`: all ID regexes, Verhoeff, Devanagari digits, masked forms + tests | H2–5 | L-02 | TR-DET-1, 2 | DONE | Tests green (8/8); Verhoeff + all Indian IDs |
| S-03 | `columns.py`: header lexicon + value profiling classifier + tests (renamed-header cases) | H4–7 | S-02 | TR-DET-3 | DONE | Tests green (5/5); header lexicon + value profile |
| S-04 | `guards.py`: Dr., doses, 1-0-1, frequency, vitals, labs, eponyms, wards, C/O-complaint, K/C/O, H/O, ASHA + tests | H5–7 | S-02 | TR-DET-6 | DONE | Tests green (6/6); all precision traps guarded |
| S-05 | `context.py` + `detect_text`: labels, relations, honorifics, `Name 48 Y/F`; roles patient/relative | H6–10 | S-04 | TR-DET-4, 7 | DONE | Tests green (7/7); all 4 canaries caught |
| S-06 | `translit.py` + `names.py` Gazetteer: harvest, variants (Latin ↔ Deva, spelling rules), fast find | H7–11 | S-03 | TR-DET-5 | DONE | Tests green (5/5); cross-script variants + fast find |
| S-07 | `detect_file` orchestration + QI mentions (AGE/DATE/DOB/VILLAGE/PIN…) + `evidence.py` | H9–11 | S-05, S-06 | TR-DET-8, TR-LNK-1 | TODO | **M1 integration** |
| S-08 | Linkage: canonical_name, phonetic_key, union-find, unique name+clue, conflict guard, blocking | H10–14 | S-07 | TR-LNK-1..7 | TODO | F0.5 > 0.9; 0 homonym merges — **M2** |
| S-09 | `tools/chaos_gen.py` + fix generalization failures | H14–18 | S-08 | TR-TOOL-3 | TODO | chaos delta < 10 — **M3** |
| S-10 | Trap test suite completion + numbers table for the brief (per script, per type) | H17–20 | S-09 | 09 §D | TODO | all trap tests green |
| S-11 | Independent release verification (fresh clone) | H21–22 | L-15 | 12 | TODO | READY TO SUBMIT on Saransh's machine |

## Stretch (only after M3, both agree)

| ID | Task | Owner | State |
|---|---|---|---|
| X-1 | XML / CDA sanitization | Lakshya | TODO |
| X-2 | Tiny CRF for names (declared in README) | Saransh | TODO |
| X-3 | Demo before/after viewer in `demo/` (not imported by main) | Lakshya | TODO |
