# 08 · Architecture

## 1. High-level pipeline (three passes)

```
                 ┌──────────────────────────── WardGuard (python main.py) ────────────────────────────┐
 input/ (RO) ──► │ PASS 1  PER FILE                 PASS 2  GLOBAL              PASS 3  PER FILE       │ ──► output/
                 │ ingest.load_all (sniff/decode)   link.resolve (clusters)     rewrite.render         │     sanitized/
                 │ enumerate_units (slots)          privacy.assign_identity     export.write_file      │     report.json
                 │ hidden.extract_hidden_slots      (PSN + date offset)         export.write_records   │     records.jsonl
                 │ detect.build_gazetteer           privacy.kanon.plan          export.write_report    │
                 │ detect.detect_file               (rare-record coarsening)                           │
                 └───── in memory only · counts-only logging · deterministic order · per-file try/except ─┘
```

Why three passes: linking (the same patient across files) and k-anonymity (rarity across the release) need a **global view** before anything is written.

## 2. Repository layout and ownership

```
<repo root>/
├── raksha.toml                      L   how the grader runs us
├── requirements.txt                 L   pinned deps
├── README.md                        L   product README (KEEP in git)
├── main.py                          L   argparse → wardguard.pipeline.run()
├── config/policy.yaml               L   privacy knobs (06 §4)
├── wardguard/
│   ├── __init__.py
│   ├── model.py                     L+S (frozen at H2)
│   ├── pipeline.py                  L
│   ├── rewrite.py                   L
│   ├── ingest/  __init__.py  sniff.py  decode.py  readers.py  units.py        L
│   ├── detect/  __init__.py (build_gazetteer, detect_file, detect_text)      S
│   │            patterns.py  normalize.py  columns.py  context.py             S
│   │            names.py  translit.py  guards.py  evidence.py                 S
│   │            hidden.py                                                     L
│   ├── link/    __init__.py (resolve)  normalize.py  cluster.py               S
│   ├── privacy/ __init__.py  pseudonym.py  dates.py  generalize.py  kanon.py  L
│   ├── export/  __init__.py  writers.py  report.py  records.py                L
│   └── safety/  __init__.py  log.py                                           L
├── resources/                       S   generic lexicons (NO practice-data names)
│   ├── labels_name.txt  labels_phone.txt  labels_address.txt …   (EN + HI header/label words)
│   ├── honorifics.txt  relations.txt  generic_name_tokens.txt
│   ├── given_names_latin.txt  given_names_deva.txt  surnames.txt
│   ├── translit_variants.tsv  (Mohammad|Mohd|Md|मोहम्मद …)
│   ├── drugs.txt  eponyms.txt  medical_terms_en_hi.txt  complaints.txt
│   └── admin_areas_up.csv  (district,tehsil — real public names)
├── tools/  eval.sh (L)  attack_sim.py (L)  chaos_gen.py (S)
├── tests/  test_patterns.py test_columns.py test_context.py test_names.py test_link.py (S)
│           test_ingest.py test_dates.py test_privacy.py test_export.py test_e2e.py (L)
├── docs/brief.pdf                   L   2-page project brief (KEEP in git)
└── project-docs/                    both   these planning docs (git-ignored at the end)
```

Remove the old starter `src/` and `tests/test_main.py` hello-world in task L-01.

## 3. Module responsibilities

| Module | Responsibility | Key techniques |
|---|---|---|
| ingest | bytes → ParsedFile + Units + Slots | magic-byte sniffing, BOM/UTF-16/cp1252 decoding, csv.Sniffer, iterative JSON walk |
| detect.patterns | direct identifiers | compiled regexes, Verhoeff checksum, digit normalization |
| detect.columns | what a structured column holds | header lexicon (EN/HI, fuzzy) + value-profile voting |
| detect.context | names in free text | label / relation / honorific rules, `Name 48 Y/F` |
| detect.names + translit | cross-script names | dataset-harvested gazetteer, Devanagari ↔ Latin, spelling variants |
| detect.guards | precision | doctor, dose, frequency, vitals, lab, eponym, ward, complaint, ASHA protections |
| detect.hidden | hidden places | keys, headers, filenames, metadata, base64, escapes |
| detect.evidence | linkage clues | patient name keys, DOB, age, gender, relative, village, strong IDs |
| link | identity resolution | union-find, blocking, unique name+clue, conflict guard |
| privacy | pseudonyms and QIs | HMAC-SHA256, per-patient date offset, age bands, PIN prefix, tehsil/district, k-anonymity |
| rewrite / export | output | span replacement right-to-left, format-preserving writers, honest report |
| safety | hygiene | counts-only logger, generic exception reasons |

## 4. Rewrite rules (what happens to each mention)

| Mention type | Output |
|---|---|
| PATIENT_NAME | the unit's PSN if any, else `[NAME]` |
| RELATIVE_NAME, OTHER_PERSON | `[RELATIVE]` / `[NAME]` |
| PHONE, AADHAAR(_MASKED), ABHA_*, PAN, MRN, INSURANCE_ID, EMAIL | type token (numeric JSON → `0`) |
| HOUSE, LANDMARK, LOCALITY | `[ADDRESS]` |
| DATE | shifted by unit.date_offset, same format |
| DOB | year only or shifted (policy `dob_action`) |
| AGE | band (`45-49`); wider if `unit.coarsen` |
| PIN | `229***` |
| VILLAGE | tehsil (or district if coarsen) |
| GENDER, DISTRICT, TEHSIL | kept (district may be dropped if coarsen) |

PSN placement: CSV → the patient-name cell (or UHID cell if there is no name column). JSON → the patient name field (or UHID field). Text/FHIR → replace patient-name mentions; if there are none, prepend `Patient: PSN-XXXXXX` as the first line (text) or put it in `Patient.identifier` (FHIR).

## 5. Security design ("assume breach")

- **No intermediate data on disk.** Everything is in memory. TMPDIR and HOME stay empty.
- **Secret handling:** read once from env and kept as bytes in the pipeline. Only HMAC uses it. Never logged, printed or written.
- **Keyed pseudonyms:** HMAC-SHA256 with per-purpose prefixes (`psn|`, `shift|`) → no dictionary or hash inversion (A6), and they change per release (A7).
- **Logging:** fixed event names + integer counts only. Exceptions are reduced to `type(e).__name__`.
- **Quarantine:** unparseable files are never copied. They appear in the report by SHA-256 with a generic reason.
- **Input integrity:** files are opened `rb` only. Nothing is written under the input path.
- (For the brief) If persistence were ever needed: AES-256-GCM, key = HKDF(secret, "wardguard-at-rest"), key never stored next to the data.

## 6. Performance design

- Read each file once. Precompile regexes at import. Use the gazetteer as a single compiled alternation or an Aho-Corasick-style dict lookup over tokens.
- Linkage uses blocking (phonetic key / strong ID) → no O(n²).
- Stream-ish handling of the large bulk export; avoid copying big strings repeatedly.
- Targets: dev < 10 s, standard < 60 s, RSS < 512 MB.

## 7. Determinism checklist

Sorted `os.walk` / `sorted(Path.rglob)`; sorted dict/set iteration wherever output order depends on it; no `random`, `time`, `uuid`, or `hash()` of str (it's salted per process!) in output paths; JSON dumped with stable separators and `ensure_ascii=False`, preserving the original key order; cluster keys chosen by `min(sorted(...))`.
