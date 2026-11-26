# Lakshya: Work Assignment (Platform + Privacy lead)

> Read with: `team/WORKFLOW.md`, `06_DATA_MODELS.md`, `07_API_CONTRACTS.md`, `08_ARCHITECTURE.md`, `09_AI_VIBE_CODING_RULES.md`.
> Your partner: **Saransh** (detection + linkage). You produce the containers he fills, then you anonymize and write.

## Your mission
Make the pipeline **always run, never leak through side channels, always produce a valid contract**, and turn detected PII into a release that **defeats the attacker without destroying utility**.
You mainly own: Privacy (25) · Integrity (10) · Speed and reliability (10) · half of Utility (20).

## Files you own (only you, or your AI, edit these)
```
raksha.toml  requirements.txt  README.md  main.py  config/policy.yaml
wardguard/__init__.py  wardguard/pipeline.py  wardguard/rewrite.py  wardguard/model.py (shared, frozen at H2)
wardguard/ingest/*  wardguard/export/*  wardguard/safety/*  wardguard/privacy/*  wardguard/detect/hidden.py
tools/eval.sh  tools/attack_sim.py
tests/test_ingest.py  tests/test_dates.py  tests/test_privacy.py  tests/test_export.py  tests/test_e2e.py
docs/brief.pdf
```

---

## Task cards

### L-01 · Scaffold (H0–1.5)
**Goal:** the new repo layout runs end to end on stubs.
1. Delete `src/`, `tests/test_main.py`; create the tree from `08_ARCHITECTURE.md §2` (empty `__init__.py` files).
2. Copy the useful parts of the kit's `starter/main.py` into modules: `decode` → `ingest/decode.py`; CSV/JSON/text processing → `ingest/readers.py` + `export/writers.py`; `pseudonym`, `date_shift_days`, `age_band` → `privacy/`; `peak_rss_mb` + report → `export/report.py`.
3. Stubs for Saransh's API: `build_gazetteer` → empty Gazetteer, `detect_file` → no-op, `link.resolve` → all `None`. **Tell Saransh the stub file names.**
4. `raksha.toml` (07 §A1), `requirements.txt` (empty or pinned basics), `config/policy.yaml` (06 §4).
**Done when:** `RAKSHA_SECRET=practice python main.py --input ../Secret-Wards-ToolKit/dev/input --output /tmp/o` → `validate_output.py` prints CONTRACT OK.
**Commit:** `[L-01] scaffold: wardguard package layout with stubs`

### L-02 · Freeze `model.py` (H1–2)
Write `wardguard/model.py` exactly as in `06_DATA_MODELS.md`. Walk Saransh through it, apply his changes, and record approval in `07_API_CONTRACTS.md §C`. → **M0**
**Commit:** `[L-02] model: freeze v1 data model`

### L-03 · `tools/eval.sh` (H1.5–2.5)
Steps: run main (secret `practice`) → validate_output → check_dev (summary) → second run → `diff -r` (determinism) → run with secret `other` (PSNs must differ) → print one BUILD_LOG-format line. Optional arg: input dir (for the chaos set).
**Commit:** `[L-03] tools: eval script with determinism check`

### L-04 · Safety layer (H2–3)
`safety/log.py`: `event(name, **counts)` (ints only, writes to stderr), `safe_reason(exc)`. `pipeline.run`: per-file try/except → quarantine; `write_report` in `finally`; exit 0 only when every file is accounted for.
**Test:** inject a file that raises during parsing → still exit 0, report lists it as quarantined, and stderr has no content.
**Commit:** `[L-04] safety: counts-only logging and fail-safe pipeline`

### L-05 · Ingestion (H2.5–5.5)
`sniff.py` (content-based, TR-ING-2), `decode.py` (TR-ING-3), `readers.py` (CSV/TSV with Sniffer + ragged rows, JSON iterative/deep-safe, FHIR detection, text). Quarantine reasons: `unsupported_format`, `malformed`, `undecodable`, `processing_error`.
**Check against dev:** UTF-16 TSV, cp1252 CSV (month-first), BOM CSV, `misc/` (pdf/jpg/xml/corrupt/empty/truncated/deep/mislabeled).
**Commit:** `[L-05] ingest: content sniffing, multi-encoding decode, robust readers`

### L-06 · Units + content slots (H4–6)
`ingest/units.py`: CSV row → `row:N` with one Slot per cell (`col:<header>`); JSON: each element of a list of objects → a unit at its pointer (others → `doc`), with Slots for string/number leaves (keep `value_type`); text/FHIR → `doc`.
**Check:** compare your unit locs with `truth.json` units for 5 sample files (a tiny script in `tools/` is fine).
**Commit:** `[L-06] ingest: unit enumeration with scoring locators`

### L-07 · Export (H5–8)
Writers that rebuild each format from slots (same delimiter, header, row/column count; JSON same structure, key order and types; UTF-8). `records.jsonl` (sorted) and `report.json` (SPEC §5, honest counts, timing, peak RSS of the process tree).
**Commit:** `[L-07] export: format-preserving writers, records and report`

### L-08 · Hidden channels (H7–11)
`detect/hidden.py`: add Slots for `@filename` (stem), `@header:i`, `@key:…`, metadata pointers, base64 (decode if valid and printable → slot `…#b64`; re-encode on write), `\uXXXX`/HTML entities/%-encoding. Calls Saransh's `detect_text` via the normal `detect_file` flow. Rename files whose `@filename` slot has mentions, e.g. `[PHONE]_report_0047.json`; if that collides, use `file_<sha8>.json`.
**Commit:** `[L-08] hidden: keys, headers, filenames, metadata, base64 channels`

### L-09 · Privacy core (H6–10)
`privacy/pseudonym.py`, `privacy/dates.py` (detect format → shift → same format; support DD/MM/YYYY, MM/DD/YYYY (Arogya, via file-level format inference), YYYY-MM-DD, DD.MM.YYYY, DD-Mon-YYYY, datetime, Devanagari digits), `generalize.py` (age band, 90+, PIN prefix, village → tehsil using `resources/admin_areas_up.csv` or the record's own tehsil/district fields), `assign_identity`.
**Tests:** a 9-day stay is still 9 days; a different secret gives a different PSN and offset; the band contains the age; the offset is never 0.
**Commit:** `[L-09] privacy: HMAC pseudonyms, per-patient date shift, generalizers`

### L-10 · Rewrite engine (H8–11), **M1 integration**
`rewrite.render`: per slot, apply mentions right-to-left using the rules in `08_ARCHITECTURE.md §4`; whole-cell replacement when `column_type` is set; PSN placement (D-010); numeric JSON types preserved.
**M1 gate with Saransh:** 4/4 canaries, recall > 0.9 per script, CONTRACT OK.
**Commit:** `[L-10] rewrite: mention application and PSN placement`

### L-11 · Attack simulator (H10–14)
`tools/attack_sim.py`, following kit `docs/ATTACKS.md`: evidence extraction from the release, A2/A3 registry filtering + weights, A4 profile pooling by PSN, A5 known facts + global-shift recovery. Print risk for raw input vs our output. **Never imported by `wardguard/`.**
**Commit:** `[L-11] tools: attack simulator A2-A5`

### L-12 · k-anonymity + targeted coarsening (H13–16)
`privacy/kanon.py`: equivalence classes over (age band, gender, district, diagnosis/rare term); for classes < k: wider band (10/20 years), drop the village/tehsil, ICD → chapter or "[RARE CONDITION]" only for those units. Tune k and decide D-012 with attack_sim + check_dev utility.
**Commit:** `[L-12] privacy: targeted k-anonymity coarsening`

### L-13 · Performance and determinism (H15–18), **M3**
Profile (`python -X importtime`, `cProfile`); a ×10 bulk test; RSS < 512 MB; `check_submission.py --run` → READY TO SUBMIT.
**Commit:** `[L-13] perf: ...`

### L-14 · README + brief (H18–21)
Root `README.md` (see the template already there) + `docs/brief.pdf` (kit `brief/` template, 2 pages, measured numbers from CURRENT_STATUS + Saransh's tables).

### L-15 · Release (H21–23), **M4**
Every box in `12_RELEASE_CHECKLIST.md`, including the project-docs cleanup **last**.

---

## Your Gemini master prompt (copy everything between the lines)

```
────────────────────────────────────────────────────────────────────────
You are my senior Python pair-programmer for a 24-hour hackathon project called
WardGuard (Track 3 "Secret Wards", Yugaantar DevForge). I am LAKSHYA, the
Platform + Privacy lead. My teammate SARANSH owns detection + linkage.

The attached PDF "WardGuard_Context_Lakshya.pdf" is the COMPLETE source of truth:
PRD, product context, technical requirements, approved scope, user flows, data
models, API contracts, architecture, AI coding rules, field research, risk
register, release checklist, current status, task board, decisions, known
issues, and my personal task cards. Read all of it before answering.

HARD RULES (never break them):
1. Use ONLY facts, functions, dataclasses and fields defined in the PDF
   (06_DATA_MODELS, 07_API_CONTRACTS). If something is missing say
   "NOT IN DOCS" and propose a contract change; never invent APIs or rules.
2. Only create/modify MY files (listed in "Files you own" in my task cards).
   Never write Saransh's modules; if I need something from him, write the
   request for him instead.
3. The product must contain NO LLM / generative model / transformer >50M
   params, NO network calls, NO temp files, NO printing/logging of data values
   (counts only, via safety.log), NEVER write RAKSHA_SECRET, deterministic
   output (sorted iteration, no random/time/hash()), never hardcode practice
   data names/files/headers, never copy raw input to output.
4. Python 3.10+, type hints, small pure functions, stdlib first, no new
   dependency without a DECISIONS entry.
5. Every reply uses this format:
   TASK / REQS / PLAN / FILES / CODE (full file contents) / TESTS (pytest) /
   RUN (exact commands) / RISKS & ASSUMPTIONS / TRACKING UPDATE (lines for
   AI_TASK_STATES.md, BUILD_LOG.md, CHANGELOG.md, + DECISIONS/KNOWN_ISSUES).
6. If my request conflicts with the docs or scope, say so and stop.

Workspace facts: the repo root holds raksha.toml, main.py, wardguard/, tools/,
tests/, config/, resources/, project-docs/. The organizer kit is cloned at
../Secret-Wards-ToolKit (dev/input, validate_output.py, check_dev.py,
check_submission.py). Run: RAKSHA_SECRET=practice python main.py --input
../Secret-Wards-ToolKit/dev/input --output /tmp/o ; tools/eval.sh

Current task: <TASK-ID, e.g. L-05>
Current code of the relevant files (pasted below): <paste>
Latest eval/check_dev output (if any): <paste>

First, restate the task and its acceptance criteria from my task card in 3
lines, list any doubts, then produce the answer in the required format.
────────────────────────────────────────────────────────────────────────
```

**Follow-up prompts you'll reuse:**
- *Fix loop:* "Here is the failing test / check_dev output: <paste>. Diagnose using only the docs and the code I pasted, then fix with minimal changes, in the same format."
- *End of session:* "Summarize what we finished for <TASK-ID> as TRACKING UPDATE lines only, plus any new risk or known issue."
- *Context refresh* (long chats drift): "Re-read the PDF sections 06, 07, 09 and my task card for <TASK-ID>. List any place where your previous code violates them."
