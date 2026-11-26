# 03 · Technical Requirements

Every requirement has an ID. Code comments and commits reference these IDs. "AC" = acceptance criteria.

## 1. Runtime and platform (TR-RUN)

| ID | Requirement | AC |
|---|---|---|
| TR-RUN-1 | Python **3.10+**, Linux; also runs on macOS for development | `python3 --version` ≥ 3.10 in CI and locally |
| TR-RUN-2 | Entry point `python main.py --input {input} --output {output}` declared in root `raksha.toml` | check_submission.py passes |
| TR-RUN-3 | Secret only from env `RAKSHA_SECRET`; never printed, logged or written | check_submission "secret never written" passes |
| TR-RUN-4 | **No network** at run time. No lazy model downloads (NLTK/spaCy/HF) | grep: no `requests`, `urllib`, or socket use in `wardguard/` |
| TR-RUN-5 | **No LLM / generative / >50M-parameter model** | README "Models" section lists none (or our own small CRF) |
| TR-RUN-6 | Budget: 2 CPUs, 4 GB RSS (whole process tree), 15 min hard limit. Target < 60 s and < 512 MB on dev | report.json timing/resources |
| TR-RUN-7 | Dependencies pinned in `requirements.txt`; installed only by `setup` | fresh-venv install works |
| TR-RUN-8 | Single process by default (no multiprocessing unless measured to help; it doubles RSS) | — |

## 2. Ingestion (TR-ING): owner Lakshya

| ID | Requirement | AC |
|---|---|---|
| TR-ING-1 | Walk the input tree **sorted**; include hidden files and odd names; never write to the input | input hash unchanged after run |
| TR-ING-2 | Sniff format by **content**: JSON (incl. JSON behind `.csv`), XML, PDF `%PDF`, JPEG `FF D8 FF`, empty (0 bytes), binary | `misc/mislabeled_export.csv` handled as JSON |
| TR-ING-3 | Decode order: BOM (utf-8-sig / utf-16) → strict utf-8 → cp1252 → else quarantine `undecodable` | UTF-16 TSV and cp1252 CSV parse correctly |
| TR-ING-4 | CSV/TSV: detect delimiter, keep header, tolerate ragged rows and multi-line quoted cells | `arogya_legacy_export.csv` row count matches truth |
| TR-ING-5 | JSON: parse 1,500-deep nesting without crashing (iterative walk / raised recursion limit inside try) | `misc/deep_export.json` doesn't crash |
| TR-ING-6 | Truncated or invalid JSON → quarantine `malformed_json` | no raw copy |
| TR-ING-7 | FHIR = JSON with `resourceType: "Bundle"`; parsed as JSON, written back as valid R4 | FHIR validity part of the score |
| TR-ING-8 | Unsupported (PDF, JPG, XML, binary) → status `quarantined` with a **generic** reason (`unsupported_format`), never the file content | — |
| TR-ING-9 | Enumerate **units** (scoring records): CSV row → `row:N` (0-based after header); JSON list-of-objects element → JSON pointer (`/visits/3`); text, FHIR or single-object JSON → `doc` | locs match truth `units` keys |

## 3. Detection (TR-DET): owner Saransh (hidden channel extraction: Lakshya)

| ID | Requirement | AC |
|---|---|---|
| TR-DET-1 | Regexes: Indian phone (+91 / 0 prefix, spaces, dashes, Devanagari digits), Aadhaar 12-digit + **Verhoeff**, masked Aadhaar `XXXX XXXX 1234`, ABHA `NN-NNNN-NNNN-NNNN`, ABHA address `x@abdm`, PAN `[A-Z]{5}\d{4}[A-Z]`, email, MRN/UHID/IPD/ADM styles, insurance IDs, house `H.No.`, PIN 6 digits | unit tests per type |
| TR-DET-2 | Normalize before matching: NFKC, Devanagari digits → ASCII, zero-width removal, homoglyph folding | test with `९८७६…` |
| TR-DET-3 | Column classifier = header lexicon (EN + HI + fuzzy) **OR** value profile (≥ 60% of non-empty cells match a type) | renamed-column chaos test passes |
| TR-DET-4 | Context rules for names: labels (`Name:`, `Pt.`, `Patient:`, `नाम:`, `मरीज़`), relations (`S/o`, `D/o`, `W/o`, `C/O`, `पुत्र`, `पत्नी`, `पति`), honorifics (`ji`, `sahab`, `didi`, `behenji`, `Shri`, `Smt`, `श्री`, `श्रीमती`), `<Name> 48 Y/F` | the 4 dev canaries detected |
| TR-DET-5 | Dynamic gazetteer: harvest names from structured name columns, generate variants (transliteration + spelling rules), search all text with word boundaries | language-trap patients fully caught |
| TR-DET-6 | Guards (keep): `Dr./डॉ.` + name, doses (`\d+\s?(mg|ml|mcg|g|IU)`), `\d-\d-\d`, `BD/TDS/OD/HS/SOS x N days/wks`, vitals (`BP 117/82`, pulse, SpO2, temp), lab values with units, eponyms, wards/beds, `C/O <complaint>`, `K/C/O`, `H/O`, `ASHA` worker | contextual precision groups ≥ 0.9 on check_dev |
| TR-DET-7 | Roles: every name mention tagged `patient` / `relative` / `unknown`; doctors are never mentions | — |
| TR-DET-8 | Quasi-identifier mentions also emitted: AGE, DATE, DOB, VILLAGE, LOCALITY, PIN, GENDER, DISTRICT, TEHSIL | consumed by the privacy layer |
| TR-DET-9 | Hidden channels: JSON keys, CSV header cells, file name stem, metadata fields (`source_path`, `exported_by`…), FHIR `text.div`, base64 strings (decode → detect → re-encode), `\uXXXX` / HTML entities / %-encoding decoded before detection | channel leak = 0 on dev |
| TR-DET-10 | Detection must not depend on practice-data names or exact file names | code review + chaos test |

## 4. Linkage (TR-LNK): owner Saransh

| ID | Requirement | AC |
|---|---|---|
| TR-LNK-1 | Evidence per unit: canonical patient name keys (Latin, generic tokens removed), phonetic key, DOB, age, gender, relative keys, village/district, strong IDs (digit cores) | — |
| TR-LNK-2 | Union-find on shared strong IDs (UHID/IPD core, Aadhaar, ABHA, phone, email, PAN, insurance) | — |
| TR-LNK-3 | Name + second clue (DOB / relative / village + age ±1) only if that combination is **unique in the dataset** | — |
| TR-LNK-4 | **Conflict guard:** never merge clusters that disagree on DOB, gender, relative, or age (gap > 2) | 0 homonym merges |
| TR-LNK-5 | Blocking so cost is ~O(n log n) | standard dataset < 60 s overall |
| TR-LNK-6 | Cluster key = smallest sorted strong identifier (or canonical name+clue string); deterministic | determinism check |
| TR-LNK-7 | Weak evidence → `cluster = None` → `"patient": null` | — |

## 5. Privacy (TR-PRV): owner Lakshya

| ID | Requirement | AC |
|---|---|---|
| TR-PRV-1 | Pseudonym = `PSN-` + 6 Crockford-base32 chars of `HMAC-SHA256(secret, "psn|" + cluster_key)` | different secret → different PSN |
| TR-PRV-2 | PSN written **inside** the record: patient-name cell/field, or a `Patient: PSN-…` line in docs/FHIR. **No new CSV columns** | pseudonym consistency = 1.0 |
| TR-PRV-3 | Date offset per patient = HMAC(secret, `"shift|"+cluster_key`) mod ±180, never 0. Unlinked units use the unit uid as key | intervals preserved; A7 passes |
| TR-PRV-4 | Dates re-emitted in the **same format** as found (DD/MM/YYYY, MM/DD/YYYY, ISO, DD.MM.YYYY, Devanagari digits, datetime) | format validity |
| TR-PRV-5 | Age → band containing the true age (default 5 years, 90+ top-coded). JSON numbers stay numbers (band lower bound or decision D-012) | generalization score, no false bands |
| TR-PRV-6 | PIN → true 3-digit prefix `229***`; village/locality/house/landmark → removed or generalized to tehsil/district | — |
| TR-PRV-7 | k-anonymity over (age band, gender, district, diagnosis) with k = policy; classes < k get **targeted** coarsening | attack_sim A5 below reference |
| TR-PRV-8 | Replacement tokens for removed values: `[NAME]`, `[RELATIVE]`, `[PHONE]`, `[AADHAAR]`, `[ABHA]`, `[PAN]`, `[MRN]`, `[INSURANCE]`, `[EMAIL]`, `[ADDRESS]`. Numeric JSON fields → `0` | types preserved |

## 6. Export and safety (TR-EXP / TR-SEC): owner Lakshya

| ID | Requirement | AC |
|---|---|---|
| TR-EXP-1 | `sanitized/` mirrors input paths; UTF-8 output; same delimiter, header, row count, JSON structure and value types | validate_output CONTRACT OK |
| TR-EXP-2 | File names with PII renamed (e.g. `7148988804_report_0047.json` → `[PHONE]_report_0047.json` or `file_<n>.json`); mapping recorded in report | — |
| TR-EXP-3 | `report.json` per SPEC §5: every input by SHA-256, status, reason, honest counts, entities, timing, peak RSS | report quality |
| TR-EXP-4 | `records.jsonl` per SPEC §6: one line per patient-bearing unit, `loc` = input locator, PSN or null | — |
| TR-SEC-1 | No temp files. If ever needed: AES-GCM with HKDF(secret) key, deleted in `finally` | TMPDIR scan clean |
| TR-SEC-2 | Logger accepts **only counts and fixed event names**; exceptions logged as `type(e).__name__` | stdout/stderr scan clean |
| TR-SEC-3 | Top-level per-file try/except → quarantine; process continues; exit 0 only if report + all files are accounted for | no false-success penalty |
| TR-SEC-4 | Determinism: sorted iteration, no `set` iteration in output paths, no time or random in `sanitized/` or `records.jsonl` | two runs give identical bytes |

## 7. Tooling (TR-TOOL)

| ID | Requirement | Owner |
|---|---|---|
| TR-TOOL-1 | `tools/eval.sh`: run → validate → check_dev → append a one-line score summary to `tracking/BUILD_LOG.md` | Lakshya |
| TR-TOOL-2 | `tools/attack_sim.py`: A2/A3 record linkage, A4 profile, A5 targeted (with global-shift recovery), per ATTACKS.md | Lakshya |
| TR-TOOL-3 | `tools/chaos_gen.py`: copy dev input with renamed columns, new labels, Faker `hi_IN`/`en_IN` names, new date formats → `../chaos/input` | Saransh |
| TR-TOOL-4 | `tests/`: pytest unit tests for every trap and regex | both |
