# Saransh: Work Assignment (Intelligence lead: Detection + Linkage)

> Read with: `team/WORKFLOW.md`, `06_DATA_MODELS.md`, `07_API_CONTRACTS.md`, `08_ARCHITECTURE.md`, `09_AI_VIBE_CODING_RULES.md`, `10_FIELD_RESEARCH.md`.
> Your partner: **Lakshya** (platform + privacy). He gives you `ParsedFile → Unit → Slot` objects with text. You fill in **what is PII** and **who the patient is**.

## Your mission
Find **every** personal identifier in English, Hindi and Hinglish (including canaries and hidden places) **without** touching doctors, doses or diseases, and link the same patient across files and scripts **without ever merging two different people**.
You mainly own: Detection (20) · Identity (15) · half of Utility (20). Generalizing to unseen formats is your biggest responsibility (RK-01).

## Files you own (only you, or your AI, edit these)
```
wardguard/detect/__init__.py  (build_gazetteer, detect_file, detect_text)
wardguard/detect/normalize.py  patterns.py  columns.py  context.py  names.py  translit.py  guards.py  evidence.py
wardguard/link/__init__.py  link/normalize.py  link/cluster.py
resources/*
tools/chaos_gen.py
tests/test_patterns.py  test_columns.py  test_context.py  test_guards.py  test_names.py  test_link.py
```
Not yours: `detect/hidden.py` (Lakshya extracts hidden channels into Slots; your detectors then scan them like any other text).

## The golden rule
**Never put a name, ID or file name from `dev/input` into code or resources.** Use generic lexicons + context + value shapes. Before each commit, ask: "would this still work if every name, label and column header changed?"

---

## Task cards

### S-01 · Kit, data study, resources (H0–3)
1. Clone the kit, run the starter + checkers (NEXT_TASKS.md). Note the baseline numbers.
2. Open 2–3 files from every `dev/input` folder. Add any new trap you see to `10_FIELD_RESEARCH.md §2`.
3. Build `resources/` (UTF-8, one item per line, `#` comments allowed):
   - `labels_name.txt` (name, patient, pt, naam, नाम, मरीज़, रोगी, guardian, father, husband, पिता, पति…), `labels_phone.txt`, `labels_address.txt`, `labels_id.txt`, `labels_dob.txt`, `labels_age.txt`, `labels_village.txt`
   - `honorifics.txt`, `relations.txt` (S/o D/o W/o C/O H/o F/o M/o पुत्र पुत्री पत्नी पति), `generic_name_tokens.txt` (kumar, devi, singh, md, mohd, ji, bai, ben…)
   - `given_names_latin.txt`, `given_names_deva.txt`, `surnames.txt`: common Indian names from general knowledge / Faker locale lists (**not** from dev data)
   - `translit_variants.tsv` (canonical → variants in Latin and Devanagari)
   - `drugs.txt`, `eponyms.txt` (parkinson, addison, alzheimer, hodgkin, crohn, cushing, graves, down…), `complaints.txt` (fever, pain, cough, bukhar, dard, बुखार…), `medical_terms_en_hi.txt`
   - `admin_areas_up.csv` (district, tehsil: real public UP admin names; used by Lakshya for generalization and by you for VILLAGE/DISTRICT detection)
**Commit:** `[S-01] resources: generic multilingual lexicons`

### S-02 · normalize + patterns (H2–5)
`normalize_for_match` (NFKC, Devanagari digits → ASCII, zero-width removal, homoglyph folding; keep an index map back to the original offsets!). `find_identifiers`: PHONE (+91/0, spaces/dashes, masked `98XXXXXX10`), AADHAAR (12 digits + Verhoeff, first digit 2–9), AADHAAR_MASKED, ABHA_NUMBER, ABHA_ADDRESS, PAN, EMAIL, MRN (generic: `[A-Z]{2,5}[/-]?\d{2}[/-]\d{4,7}`, `UHID-\d+`, `ADM\d+`, `IP-\d{2}-\d+` …, but keep it shape-based), INSURANCE_ID, HOUSE (`H.No.`, `House No`, `मकान नं`), PIN (6 digits, context-aware), DATE/DOB shapes.
**Tests:** positives + negatives (`650mg`, `1-0-1`, `BP 150/90`, lab `245 mg/dL`, ref range `70-140`).
**Commit:** `[S-02] detect: normalization and identifier patterns with Verhoeff`

### S-03 · Column classifier (H4–7)
`classify_column(header, values)`: (1) fuzzy header match against the label lexicons (EN + HI; handle `Patient's Name`, `Contact#`, `Gram/Mohalla`, `pt_nm`); (2) value profiling: ≥ 60% of non-empty values match a type → that type; name-like = 1–4 alphabetic tokens (Latin or Devanagari), mostly capitalized, not medical terms. Header and values disagree → trust the values for ID types, the header for names. Relative columns (`Relative Name`, `Guardian`, `S/O SHYAM PATEL`) → RELATIVE_NAME.
**Tests:** renamed headers, Hindi headers, unlabeled columns.
**Commit:** `[S-03] detect: header lexicon + value-profiling column classifier`

### S-04 · Guards (H5–7)
`is_protected(text, start, end)`: doctor (`Dr.`, `Dr`, `डॉ.`, `(MD …)`, "Consultant"), doses, frequencies (`1-0-1`, `BD`, `TDS`, `OD`, `HS`, `SOS`, `x 5 days`, `x 2 wks`), vitals (BP/pulse/SpO2/temp/RBS), labs with units, eponyms (`<Name>'s disease/syndrome`), wards/beds, `C/O <complaint>`, `K/C/O`, `H/O`, "ASHA worker/ASHA didi" (as a role, not a name).
**Commit:** `[S-04] detect: meaning-trap guards`

### S-05 · Context rules + `detect_text` (H6–10)
Names after labels (`Name:`, `Pt.`, `Patient:`, `नाम:`), after relations (→ RELATIVE_NAME), before/after honorifics (`Shahid sahab`, `Asha ji`, `श्रीमती सुनीता`), the `<Name> 48 Y / F` pattern, sentence-start names in Hindi (`सुनीता पटेल को …`). Name span = 1–3 name-like tokens. Assign role. Emit mentions from patterns + context + gazetteer; resolve overlaps (longest wins); drop protected spans.
**Gate:** all 4 dev canaries found (check_dev canary section).
**Commit:** `[S-05] detect: free-text context rules and detect_text`

### S-06 · Transliteration + Gazetteer (H7–11)
`translit.py`: Devanagari → Latin (indic-transliteration + simplification: drop schwa, aa→a, ee→i, v/w, sh/s) and Latin → Devanagari candidates; `canonical_name()` shared with linkage. `names.py` Gazetteer: `build_gazetteer` harvests names from slots with `column_type` PATIENT_NAME / RELATIVE_NAME (+ context-rule hits), adds variants (Mohammad/Mohd/Md./मोहम्मद, initials "M. Arif", surname-first), and finds them in text with word boundaries in **both** scripts. Use a token-dict lookup for speed.
**Gate:** language-trap patients caught in all 3 scripts; deva and hinglish recall > 0.9.
**Commit:** `[S-06] detect: cross-script transliteration and dynamic gazetteer`

### S-07 · `detect_file` + QI mentions + evidence (H9–11), **M1 integration**
Orchestrate per file: classify columns → whole-cell mentions; `detect_text` on every other slot (including Lakshya's hidden slots); emit QI mentions (AGE incl. `48 Y`, `54 वर्ष`, `48/M`; DATE; DOB; VILLAGE; PIN; GENDER; DISTRICT; TEHSIL); fill `unit.evidence` (patient name keys, DOB, age, gender, relative keys, village, district, strong IDs as digit cores, dates); set `patient_bearing`.
**Commit:** `[S-07] detect: file orchestration, QI mentions, linkage evidence`

### S-08 · Linkage (H10–14), **M2**
`link.resolve`: (1) blocking; (2) union-find on shared strong IDs (only IDs that occur with **one** name key → avoids family phones joining people); (3) name + second clue (DOB | relative | village + age ±1) only when that combination is unique in the dataset; (4) conflict guard before every union (DOB / gender / relative mismatch or age gap > 2 → refuse); (5) cluster key = min sorted strong ID or the canonical name+clue string; weak → None. Fully deterministic.
**Tests:** homonyms (same name, different village/age/relative) stay apart; "Meera, W/o Rajan" links via relative; cross-script same person links.
**Gate:** F0.5 > 0.9, 0 homonym merges.
**Commit:** `[S-08] link: evidence-gated clustering with conflict guard`

### S-09 · Chaos generator + generalization (H14–18), **M3**
`tools/chaos_gen.py --src … --dst ../chaos/input --seed 7`: rename columns (synonyms, Hindi, typos), change label words (`Name:` → `Patient Nm -`), swap all names for Faker `en_IN`/`hi_IN` names consistently (update both scripts), change date formats and phone formatting, shuffle column order. Because there's no truth for the chaos set, measure with a "known PII list" that the generator writes for you, plus crash-freeness. Fix the detectors until the drop is < 10.
**Commit:** `[S-09] tools: chaos dataset generator` and `[S-09] detect: generalization fixes`

### S-10 · Trap tests + numbers (H17–20)
Complete every trap test in `09_AI_VIBE_CODING_RULES.md §D-22`. Produce the brief table: leak % per type and per script, clinical kept %, link P/R/F0.5, chaos delta. Give it to Lakshya.

### S-11 · Independent verification (H21–22)
Fresh clone on your machine → setup → run → validate → check_submission. Report any difference.

---

## Your Gemini master prompt (copy everything between the lines)

```
────────────────────────────────────────────────────────────────────────
You are my senior Python / NLP pair-programmer for a 24-hour hackathon project
called WardGuard (Track 3 "Secret Wards", Yugaantar DevForge). I am SARANSH,
the Intelligence lead: PII detection (English, Hindi/Devanagari, Hinglish) and
patient record linkage. My teammate LAKSHYA owns ingestion, export, hidden
channels, privacy (pseudonyms, date shift, k-anonymity) and release.

The attached PDF "WardGuard_Context_Saransh.pdf" is the COMPLETE source of truth:
PRD, product context, technical requirements, approved scope, user flows, data
models, API contracts, architecture, AI coding rules, field research, risk
register, release checklist, current status, task board, decisions, known
issues, and my personal task cards. Read all of it before answering.

HARD RULES (never break them):
1. Use ONLY facts, functions, dataclasses and fields defined in the PDF
   (06_DATA_MODELS, 07_API_CONTRACTS). If something is missing say
   "NOT IN DOCS" and propose a contract change; never invent APIs or rules.
2. Only create/modify MY files (listed in "Files you own" in my task cards).
   Never write Lakshya's modules; if I need something from him, write the
   request for him instead.
3. NO LLM / generative model / transformer >50M params in the product. Only
   regexes, rules, lexicons, transliteration, fuzzy/phonetic matching,
   classical ML. NO network calls, NO printing/logging of data values,
   deterministic output (sorted iteration, no random/time/hash()).
4. NEVER hardcode names, IDs, file names or exact column headers from the
   practice data. Everything must generalize to unseen names, labels and
   formats (value profiling + context + generic lexicons).
5. Precision traps must be respected: keep "Dr. <name>", doses (650mg,
   1-0-1, BD x 5 days), vitals (BP 150/90), lab values, eponyms (Parkinson's),
   "C/O fever", K/C/O, H/O, wards, ASHA worker. Remove patient and relative
   names in Latin, Devanagari and Hinglish, all Indian IDs and phones.
6. Linkage: a wrong merge costs more than a missed link. Link only on shared
   strong IDs or name + a unique second clue; conflict guard always; else None.
7. Python 3.10+, type hints, small pure functions, compiled regexes with
   example comments, pytest tests for every rule (positive, negative/trap,
   Devanagari/Hinglish case) using INVENTED test strings.
8. Every reply uses this format:
   TASK / REQS / PLAN / FILES / CODE (full file contents) / TESTS (pytest) /
   RUN (exact commands) / RISKS & ASSUMPTIONS / TRACKING UPDATE (lines for
   AI_TASK_STATES.md, BUILD_LOG.md, CHANGELOG.md, + DECISIONS/KNOWN_ISSUES).
9. If my request conflicts with the docs or scope, say so and stop.

Workspace facts: the repo root holds raksha.toml, main.py, wardguard/, tools/,
tests/, config/, resources/, project-docs/. The organizer kit is cloned at
../Secret-Wards-ToolKit (dev/input, dev/truth/truth.json, check_dev.py).
Run: RAKSHA_SECRET=practice python main.py --input
../Secret-Wards-ToolKit/dev/input --output /tmp/o ; tools/eval.sh ;
python3 ../Secret-Wards-ToolKit/check_dev.py --output /tmp/o --show 20

Current task: <TASK-ID, e.g. S-03>
Current code of the relevant files (pasted below): <paste>
Latest eval/check_dev output (if any): <paste>

First, restate the task and its acceptance criteria from my task card in 3
lines, list any doubts, then produce the answer in the required format.
────────────────────────────────────────────────────────────────────────
```

**Follow-up prompts you'll reuse:**
- *Leak hunting:* "Here is `check_dev.py --show 20` output listing leaks: <paste>. Group them by root cause (pattern / column / context / gazetteer / guard), then fix the top 3 causes generically (no hardcoding), in the required format."
- *False positives:* "These medical values were removed but must be kept: <paste>. Extend guards.py generically and add trap tests."
- *End of session:* "Summarize what we finished for <TASK-ID> as TRACKING UPDATE lines only, plus any new risk or known issue."
- *Context refresh:* "Re-read PDF sections 06, 07, 09, 10 and my task card for <TASK-ID>. List any place where your previous code violates them."
