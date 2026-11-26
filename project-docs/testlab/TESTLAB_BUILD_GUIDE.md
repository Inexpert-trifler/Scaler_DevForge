# WardGuard Proving Ground: Test Lab Build Guide

> **Audience:** the one Lab Builder (plus their AI assistant), and Lakshya and Saransh as the people who fix what the lab finds.
> **Goal:** build an isolated sandbox that attacks WardGuard with thousands of labelled test cases, finds every bug it can, and produces an honest capability report.
> **Status of this doc:** v1.0 · written 2026-11-26 against product commit `00fdde9` (branch `lakshya/wardguard-core-scaffold`).
> **Rule zero:** the lab measures the product; it never changes it. Product fixes go through the owners (Lakshya / Saransh) as normal commits.

---

## Contents

1. What we are building and why
2. Baseline: what the product does today (measured)
3. Bugs already found while writing this doc
4. Lab architecture
5. Repository layout for the lab
6. Component specs
   - 6.1 Sandbox runner (S)
   - 6.2 Forge: synthetic dataset generator with answer key (F)
   - 6.3 Chaos mutators (M)
   - 6.4 Oracles: scorers, invariants, leak scanner (O)
   - 6.5 Attack arena A1–A7 (A)
   - 6.6 Metamorphic tests (MR)
   - 6.7 Micro-case catalogue (TC)
   - 6.8 Fuzzing and property tests (Z)
   - 6.9 Performance and scale (P)
   - 6.10 Security and hygiene (SEC)
   - 6.11 Orchestrator, results store, dashboard (R)
   - 6.12 Minimizer and bug loop (B)
7. Test campaigns (smoke / regression / nightly / holdout)
8. Build plan: task cards T-00 … T-16 for the one builder
9. Bug handling: severity, routing, ledger, regression fixtures
10. Capability report template
11. Lab rules (anti-cheating, anti-overfitting, data hygiene)
12. Prompts (master prompt, task prompt, triage, fix, red-team, report, audit)
13. Appendix: truth schema, attacker files, kit commands, glossary

---

## 1. What we are building and why

The organizers score WardGuard on **hidden datasets**, and one of them is an **unseen-format (chaos) dataset**. On that dataset, the organizers' own reference solution drops from ~80–85 to ~48–50 points. The practice data (`Secret-Wards-ToolKit/dev`) has only 200 files and 48 patients. Tuning on it alone is exactly the memorization trap the hidden data punishes.

So the lab has three jobs:

| Job | What it means | Output |
|---|---|---|
| **Find bugs** | crashes, leaks, false merges, contract breaks, nondeterminism, penalties | `bugs/BUG-####.md` + minimized repro + regression fixture |
| **Measure true capability** | scores with confidence intervals across many unseen seeds, per category, per type/script/channel | `reports/capability-<date>.html` |
| **Prevent regressions** | every fix stays fixed; every commit is gated | smoke + regression campaigns, a trend chart |

**"Thousands of test cases"** comes from four multipliers:

| Source | Count (target) | Each case checks |
|---|---|---|
| Forge datasets (seeds × profiles × chaos on/off) | 300+ datasets, ~250k labelled entities | full score + all invariants + attacks |
| Micro cases (trap catalogue × formats × scripts × channels) | 2,000–5,000 tiny datasets | one behaviour, pass/fail |
| Metamorphic relations × datasets | 12 relations × 50 datasets = 600 | consistency under a transformation |
| Property/fuzz tests | 50k+ generated inputs per night | never crash, never leak, deterministic |

---

## 2. Baseline: what the product does today (measured)

Measured 2026-11-26 on the kit practice data (`dev/input`, 200 files) with `RAKSHA_SECRET=practice`, macOS Apple Silicon, product commit `00fdde9`. The pytest suite was **127 passed in 1.96 s**.

| Check | Result |
|---|---|
| `validate_output.py` | CONTRACT OK |
| Determinism (two runs, same secret) | byte-identical ✅ |
| Runtime / peak RSS | 11.9 s / 55 MB |
| Kit `check_submission.py` (no `--run`) | READY TO SUBMIT, but see BUG-0003 |
| `tools/chaos_gen.py` → run on 209 chaos files | exit 0, CONTRACT OK |

**`check_dev.py` (rough practice score):**

| Metric | Value | Target from PRD |
|---|---|---|
| Overall leak | **16.1%** (519 / 3230) | < 3% |
| Leak by script | latin 14.8% · deva 25.2% · hinglish **39.6%** | < 5% each |
| Leak by channel | content 13.9% · filename **87.5%** · metadata **100%** · header **50%** · key 8.3% · base64 0% | 0% side channels |
| Canaries found in output | **2 / 4** (−6 points officially) | 0 |
| Clinical values kept | 96.0% (4608 / 4799) | > 95% ✅ |
| Linking | precision 1.00 · recall **0.41** · F0.5 0.78 · false merges 0 | F0.5 > 0.9 |
| Raw copies | 0 ✅ | 0 |

**Worst leak types:** LOCALITY 59.2% · LANDMARK 57.8% · ABHA_NUMBER 32.6% · PIN 32.4% · HOUSE 30.1% · DOB 26.1% · VILLAGE 21.3% · PATIENT_NAME 15.0% (144 leaks, at −1 each, so this alone can hit the −25 cap) · PHONE 10.4% · RELATIVE_NAME 9.9% · MRN 7.2%. AADHAAR, PAN, INSURANCE_ID, EMAIL and AADHAAR_MASKED were at 0%.

**Interpretation:** structured IDs are strong. Address fields, side channels, Devanagari and Hinglish text, and linkage recall are where the points are. These numbers come from the **practice** data, so the unseen-format numbers will be worse. Measuring how much worse is the lab's first job.

---

## 3. Bugs already found while writing this doc

Seed the bug ledger with these. Lakshya owns all four (platform, tools and release).

| ID | Sev | Finding | Evidence | Fix direction |
|---|---|---|---|---|
| BUG-0001 | S2 | `tools/attack_sim.py` crashes on the kit attacker files: `KeyError: 'patient_id'` at `attack_sim.py:634` | The kit's `registry.csv` columns are `rid,name,relation,relative_name,gender,age,house_no,mohalla,village,tehsil,district,pin,phone,email,aadhaar_last4`; the key is `rid` | Read `rid`; add a test that loads the real kit attacker files |
| BUG-0002 | S1 (false-success risk) | `wardguard/pipeline.py` swallows failures of privacy steps: `plan()` (k-anonymity) and `apply_filename_renaming` sit in `except Exception: pass`, and `resolve` / `assign_identity` errors only log an event. The run still returns 0 and the report says success | `pipeline.py`, around the Pass-2 block | If a privacy step fails, fail closed for the affected units (generalize harder, or quarantine) and report the failure honestly. A wrong "success" costs −10 |
| BUG-0003 | S1 (submission) | Kit `check_submission.py` found **no `docs/brief.pdf`** and picked `project-docs/pdf/WardGuard_Context_Saransh.pdf` as the "Project Brief". Once `project-docs/` is untracked, there will be no brief at all | `check_submission.py` output: "Project Brief PDF found: project-docs/pdf/WardGuard_Context_Saransh.pdf" | Create the real 2-page `docs/brief.pdf` (release checklist step) |
| BUG-0004 | S3 | `tools/eval.sh` writes to fixed `/tmp/wardguard_eval_*` paths and prints a hard-coded `[H1.5] … [L-03]` build-log line | `tools/eval.sh` | Use `mktemp -d`; print a neutral log line |

---

## 4. Lab architecture

```
                         ┌─────────────────────────────── LAB HOST (your laptop / a Linux VM) ─────────────────────────────┐
                         │                                                                                                  │
  seeds ─► FORGE (F) ──► dataset/ input/  truth/truth.json  attacker/registry.csv,known_facts.jsonl                         │
             │                 │                                                                                            │
             └─► CHAOS (M) ────┤  (mutated copy + updated truth)                                                            │
                               ▼                                                                                            │
                     ┌──── SANDBOX (S): docker --network none, 2 CPU, 4 GB, 15 min, input read-only ───┐                    │
                     │   product repo (ro) ── python main.py --input /in --output /out/release        │                    │
                     │   runner.py: RSS watchdog, timeout, stdout/stderr capture, run.json            │                    │
                     └────────────────────────────────────────────────────────────────────────────────┘                    │
                               │ release/ (sanitized, report.json, records.jsonl) + run.json + logs + tmp/home scan        │
                               ▼                                                                                            │
   ORACLES (O): kit validate_output · kit check_dev (on forge truth) · full scorer · invariants I-01..I-24 · leak scanner   │
   ATTACKS (A): A1..A7 against release with forge attacker files                                                            │
   METAMORPHIC (MR): transform input → rerun → compare                                                                      │
                               │                                                                                            │
                               ▼                                                                                            │
   RESULTS (R): results/runs.sqlite + per-run folder ─► dashboard HTML ─► capability report                                │
                               │ failures                                                                                   │
                               ▼                                                                                            │
   MINIMIZER (B): ddmin files→rows→chars ─► bugs/BUG-####.md + fixture ─► owner fixes product ─► lab re-verifies            │
                         └──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Two execution lanes:**

| Lane | How the product runs | Used for | Speed |
|---|---|---|---|
| **Sandbox lane** | `docker run` of the real CLI, exactly like the grader | full datasets, performance, security, determinism, every campaign gate | ~12 s per 200 files + container start |
| **Fast lane** | In-process `wardguard.pipeline.run(...)` from a lab venv that has the product on `PYTHONPATH` (read-only) | thousands of micro cases, property tests, minimization loops | ~0.1–1 s per case |

Anything the fast lane finds **must be re-confirmed in the sandbox lane** before it is filed as a bug.

---

## 5. Repository layout for the lab

The lab lives in its **own repo, next to the product**, so the product repo stays clean and the product can never import the lab by accident.

```
~/Desktop/Scaler_DevForge/
├── Scaler_DevForge/            # product repo (WardGuard), mounted read-only into the sandbox
├── Secret-Wards-ToolKit/       # organizer kit (validate_output.py, check_dev.py, check_submission.py, dev/)
└── wardguard-testlab/          # THIS LAB (separate git repo, private)
    ├── lab.py                  # single CLI: forge | mutate | run | score | attack | mr | micro | fuzz | perf | campaign | minimize | report
    ├── pyproject.toml / requirements-lab.txt   # hypothesis, psutil, pyyaml, jinja2, (optional) reportlab or fpdf2 for PDF fixtures
    ├── config/
    │   ├── lab.yaml            # paths (product, kit), budgets, docker image name
    │   ├── seeds_dev.txt       # seeds the whole team may see
    │   └── seeds_holdout.txt   # seeds ONLY the builder sees (never shared, never committed to the product repo)
    ├── sandbox/
    │   ├── Dockerfile
    │   ├── runner.py           # runs inside the container: timeout, RSS watchdog, run.json
    │   └── run_sandbox.sh      # docker run wrapper (and a Linux `unshare` alternative)
    ├── forge/                  # synthetic generator
    │   ├── world.py            # districts, tehsils, villages, PINs, hospitals (invented)
    │   ├── people.py           # patients, relatives, doctors, homonyms, twins, canaries
    │   ├── ids.py              # Aadhaar (Verhoeff), ABHA, PAN, phone, MRN/UHID, insurance, email, ABHA address
    │   ├── lexicon/            # the lab's OWN names/labels (dev pool + holdout pool) — NOT copied from product resources/
    │   ├── clinical.py         # diagnoses, drugs, doses, vitals, labs, procedures (the "preserve" values)
    │   ├── render/             # csv.py tsv.py json.py fhir.py text.py xml.py pdf.py binary.py
    │   ├── channels.py         # filename, key, header, metadata, base64, \u-escape, FHIR narrative
    │   ├── traps.py            # meaning traps, fragmented identity, homonyms, re-id outliers
    │   ├── truth.py            # writes truth.json (raksha-truth/1 compatible)
    │   └── attacker.py         # writes registry.csv + known_facts.jsonl (+ decoys)
    ├── mutate/operators.py     # chaos catalogue C-01..C-45 (updates truth consistently)
    ├── oracles/
    │   ├── kit.py              # wraps validate_output.py / check_dev.py (subprocess, python -I)
    │   ├── score_full.py       # approximate official 100-pt score (weights from scoring.toml)
    │   ├── invariants.py       # I-01..I-24
    │   └── leakscan.py         # normalized leak search incl. base64, \u, NFKC, digit-only
    ├── attacks/                # a1_direct.py … a7_cross_release.py
    ├── metamorphic/relations.py  # MR-01..MR-12
    ├── micro/catalogue.py      # TC families → tiny datasets with truth
    ├── fuzz/                   # hypothesis strategies + byte mutators
    ├── minimize/ddmin.py
    ├── report/                 # templates/capability.html.j2, trend.py
    ├── campaigns/              # smoke.yaml regression.yaml nightly.yaml holdout.yaml perf.yaml security.yaml
    ├── bugs/                   # BUG-####.md + fixtures/BUG-####/ (minimized input + truth)
    ├── tests/                  # tests OF THE LAB (calibration anchors, truth self-tests)
    └── results/                # gitignored: runs.sqlite, run folders, reports
```

---

## 6. Component specs

### 6.1 Sandbox runner (S): mirror the grader

The grader (kit `docs/SANDBOX.md`) runs the submission with **no network**, a **read-only copy of the input**, an **empty output folder**, private `TMPDIR` and `HOME` that are **scanned for PII afterwards**, a **memory watchdog on the whole process tree**, a **hard wall-clock limit**, and stdout/stderr scanned for network-error strings. The lab copies all of that.

**Dockerfile (sketch):**
```dockerfile
FROM python:3.11-slim          # also build 3.10 and 3.12 variants (matrix)
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
RUN useradd -m sub
# product dependencies, installed at build time (the grader's "setup" step has network; "run" does not)
COPY requirements.txt /tmp/req.txt
RUN python -m venv /sub-venv && /sub-venv/bin/pip install -r /tmp/req.txt
# lab-only tools live in a separate venv so they cannot leak into the product environment
RUN python -m venv /lab-venv && /lab-venv/bin/pip install psutil
COPY sandbox/runner.py /lab/runner.py
USER sub
```
Rebuild the image whenever the product's `requirements.txt` changes (hash it into the image tag).

**Run command:**
```bash
docker run --rm --network none --cpus 2 --memory 4g --memory-swap 4g --pids-limit 512 \
  --ulimit core=0 --ulimit fsize=2147483648 \
  -v "$PRODUCT":/sub:ro -v "$DATASET/input":/in:ro -v "$RUN/out":/out \
  -v "$RUN/sbx_tmp":/sbx/tmp -v "$RUN/sbx_home":/sbx/home \
  -e TMPDIR=/sbx/tmp -e HOME=/sbx/home -e RAKSHA_SECRET="$SECRET" -w /sub \
  wardguard-sbx:py311-<reqhash> \
  /lab-venv/bin/python /lab/runner.py --timeout 900 --mem-limit-mb 4096 \
     --out /out --cmd /sub-venv/bin/python main.py --input /in --output /out/release
```

**`runner.py` must:**
1. Start the command, sample the RSS of the **whole process tree** every 50 ms (psutil), and kill it above `--mem-limit-mb` (status `memory_exceeded`).
2. Kill it at `--timeout` (status `timeout`).
3. Capture stdout/stderr to `/out/stdout.txt` and `/out/stderr.txt`.
4. Write `/out/run.json` with: `status`, `exit_code`, `wall_s`, `cpu_s`, `peak_rss_mb`, `python`, `image`, `isolation` ("docker-netnone" or "unshare-full"), `input_sha256` (a Merkle hash of the input tree computed before **and** after the run, which proves the input was not modified), `network_attempt_strings` (matches for `Temporary failure in name resolution`, `Network is unreachable`, `Max retries exceeded`, `Name or service not known`, `ConnectionRefused`), `tmp_leftovers` and `home_leftovers` (lists of files).

**Linux alternative (closest to the grader):** `unshare --user --net --mount --pid --fork --mount-proc` with the same runner. Use it in the nightly run if the builder has a Linux VM. On Ubuntu 24.04+, `sysctl kernel.apparmor_restrict_unprivileged_userns=0` may be needed.

**Budgets to enforce** (kit `scoring.toml`, `[performance.profiles]`):

| Profile | time good | time limit | memory good | memory limit |
|---|---|---|---|---|
| tiny | 10 s | 120 s | 512 MB | 4096 MB |
| small | 15 s | 300 s | 512 MB | 4096 MB |
| medium | 30 s | 450 s | 512 MB | 4096 MB |
| standard | 60 s | 900 s | 512 MB | 4096 MB |
| large | 180 s | 1800 s | 768 MB | 4096 MB |

> Apple-Silicon Docker CPUs are usually faster than a grader's slot. When the builder has a Linux VM, measure a calibration factor there (run the kit dev data on both machines) and apply it to every timing.

### 6.2 Forge: synthetic dataset generator with an answer key (F)

This is the heart of the lab. It produces datasets **in the same shape as the kit's**, so the kit's own `check_dev.py` can score them unchanged:

```
<dataset>/
  input/...                     # the messy dump
  truth/truth.json              # schema "raksha-truth/1" (see Appendix A)
  attacker/registry.csv         # population registry (patients + decoys)
  attacker/known_facts.jsonl    # visit dates, hospital, condition hints for some people
  dataset_manifest.json         # seed, profile, chaos flag, counts, generator version
```

**Determinism:** everything comes from one `random.Random(seed)` per sub-generator (seed derived as `sha256(seed + ":" + component)`). The same seed must give the same bytes. Lab test `tests/test_forge_determinism.py` enforces this.

**Profiles** (match the grader's names so the budgets line up):

| Profile | Files | Patients | Notes |
|---|---|---|---|
| tiny | ~40 | ~10 | micro-scale smoke |
| small | ~200 | ~50 | same scale as the practice data |
| medium | ~600 | ~150 | |
| standard | ~1,500 | ~400 | the main scoring scale |
| large | ~5,000 + one bulk CSV of 200k rows | ~2,000 | performance only |

**World model (invented, never real people):**
- Geography: 6–10 districts per dataset, each with tehsils, villages (including **tiny villages** with 1–2 patients for re-identification pressure) and 6-digit PINs in plausible UP/Bihar ranges.
- Hospitals: 3–5 per dataset, each with its own UHID/MRN pattern (e.g. `ABC-0076864`, `ABC/26/064098`, `26ABC00123`, and in holdout patterns never seen before).
- People: patients, relatives (father, husband, mother, guardian, C/O), doctors (who **share first names** with relatives), nurses, plus **canaries** (names and numbers that appear nowhere else and in no name list).

**Identifiers (`ids.py`), all synthetic:**

| Type | Generator rule | Surface variants to emit |
|---|---|---|
| AADHAAR | 12 digits, first digit 2–9, Verhoeff-valid | `1234 5678 9012`, `123456789012`, `1234-5678-9012`, Devanagari digits |
| AADHAAR_MASKED | `XXXX XXXX 1234`, `xxxx-xxxx-1234`, `********1234` | |
| ABHA_NUMBER | 14 digits `NN-NNNN-NNNN-NNNN` | with or without hyphens |
| ABHA_ADDRESS | `name.surname@abdm`, `name1987@sbx` | |
| PAN | `AAAAA9999A` (4th char P for person) | upper and lower case |
| PHONE | Indian mobile 6–9 start | `+91 98765 43210`, `+91-9876543210`, `09876543210`, `98765-43210`, `(+91)9876543210`, Devanagari digits |
| MRN / UHID | per-hospital pattern | in text, columns, keys, filenames |
| INSURANCE_ID | PMJAY-style alphanumerics, policy numbers | |
| EMAIL | name-based | |
| DOB | many formats | `12/04/1977`, `1977-04-12`, `12-Apr-77`, `12 अप्रैल 1977`, `१२/०४/१९७७` |
| PIN | 6 digits | `229073`, `229 073` |

**Names (`people.py` + `lexicon/`):**
- The lab keeps its **own** name lists, split into a **dev pool** and a **holdout pool**. Never copy the product's `resources/*.txt`: if the lab used the product's own lists, it would only measure memorization.
- Every name is produced in up to three scripts with a consistent identity: Latin (`Sunita Yadav`), Devanagari (`सुनीता यादव`), and Hinglish/romanized variants (`Suneeta Yaadav`, `sunita ydv`).
- Structures: given + surname, given only, initials (`R. K. Sharma`), honorific forms (Shri, Smt., Kumari, Late, श्री, श्रीमती, सुश्री), relation forms (`S/o`, `D/o`, `W/o`, `H/o`, `C/O`, `son of`, `पुत्र`, `पत्नी`, `पुत्री`, `द/o` mixed), generic parts that must **not** count alone (Devi, Kumar, Kumari, Md., ji, Bai).

**Clinical content (`clinical.py`), the values that must survive (`preserve`):** diagnoses (ICD-like text), drugs, doses (`1-0-1`, `BD x 5 days`, `500 mg`), vitals (`BP 130/85`, `SpO2 97%`, `Pulse 88`), labs (`Hb 11.2 g/dL`, `HbA1c 7.8%`), procedures, complaints, length of stay. **Phone-like and date-like clinical values must be included on purpose:** a 10-digit lab accession number, `Platelets 150000`, dose schedules, `since 3 days`.

**Renderers (`render/`)** produce each format with the encoding and channel mix of the kit, and more:

| Format | Must cover |
|---|---|
| CSV / TSV | header variants, quoted fields with commas/newlines, BOM, `;` delimiter, cp1252, UTF-16, wide (60 cols) and long (200k rows) |
| JSON | flat, nested (depth 1–50), arrays of visits, **PII in keys**, metadata blocks (`exported_by`, `source_file`), base64 attachments, `\u`-escaped Devanagari, NDJSON |
| FHIR R4 | Patient, Encounter, Observation, MedicationRequest, Bundle; `name`, `telecom`, `identifier`, `address`, and `text.div` narrative containing PII |
| Text notes | English, Hindi, Hinglish, mixed; discharge summaries, OPD slips, referral letters; wrapped lines that split a name |
| XML / HL7-like | expect `either` (quarantine is allowed) unless the product adds X-1 |
| PDF, JPG, binary | expect quarantine; **never copied raw** |
| Broken | truncated JSON, invalid UTF-8, empty file, JSON behind `.csv`, zero-byte, huge single line |

**Channels (`channels.py`):** every PII type can be placed into `content`, `filename` (`ward3_sunita_yadav_9876543210.csv`), `key` (`{"Sunita Yadav": {...}}`), `header` (`Patient: Sunita Yadav` as a CSV header row), `metadata` (`"exported_by": "…"`), `base64` (an attachment that decodes to a note), and `\u` escapes. The truth entity gets the right `channel`.

**Traps (`traps.py`), mirroring the kit's trap families (`language`, `fragmented`, `meaning`, `reidentification`, `homonym_pairs`):**

| Trap | Generation | Correct product behaviour |
|---|---|---|
| Homonym pair | two patients, same full name, different village/age/relative | two different PSNs (merging is a false merge) |
| Twins | same DOB, same address, same father, different given names | two PSNs |
| Fragmented identity | note says only `Sunita, W/o Ramesh` + date | link to the right patient through relative + date |
| Language split | same patient in Latin in one hospital, Devanagari in another | one PSN |
| Name change | married name in a later file + same Aadhaar/phone | one PSN |
| Doctor vs relative | `Dr. Ramesh Gupta` and relative `Ramesh` | doctor kept, relative removed |
| C/O complaint | `C/O fever x 3 days` vs `C/O Ramesh Yadav` | the complaint is kept and the name removed |
| Eponyms | Parkinson's, Down syndrome, Bell's palsy, Hashimoto | kept |
| Ward/bed numbers | `Ward 6`, `Bed 12` in clinical context vs `Ward 6` as LOCALITY in an address | context decides (truth tells which) |
| Re-id outliers | age 97, village with one patient, rare disease, exact admission dates | generalized or coarsened, but truthfully |
| Canaries | 2–6 per dataset, unique tokens, only findable through context (`Name: <canary>`) | 0 in the output, logs, report and temp files |

**Truth writer (`truth.py`):** see Appendix A. Every unit records `entities` (type, surface, person, role, script, channel, match, key or tokens, critical, optional weight), `preserve`, `dates`, `fields`, `exclude`, `patient`, `cid`, `link`, and `tags`.

**Attacker writer (`attacker.py`):** `registry.csv` with the kit's columns (`rid,name,relation,relative_name,gender,age,house_no,mohalla,village,tehsil,district,pin,phone,email,aadhaar_last4`), containing every patient **plus 5–10× decoys** from the same villages. `known_facts.jsonl` (`rid`, `visit_dates`, `hospital`, `condition_hint`) covers ~30% of patients plus some decoys.

**Lab self-tests for the Forge (critical, because a wrong answer key creates fake bugs):**
1. **Passthrough anchor:** copy `input/` to `release/sanitized/` with an empty `records.jsonl`. `check_dev` must report ~100% leaked and all canaries found.
2. **Redact-all anchor:** replace every alphanumeric token with `X`. It must report ~0% leaked and very low clinical utility.
3. **Oracle anchor:** a "perfect" release built from the truth (replace every entity surface by its token and the patient by an HMAC PSN). It must report ~0% leaked, ~100% utility and F0.5 ≈ 1.0.
4. **Kit starter / naive regex anchor:** the kit's `starter/` solution must score below WardGuard and above passthrough.
5. **Ordering assertion (like the organizers' calibration):** oracle > WardGuard > redact-all > naive > passthrough on every seed. If any ordering fails, **the lab is wrong. Fix the lab before filing a single product bug.**
6. **Truth consistency:** every entity surface actually occurs in its file (after decoding its channel), every `preserve` text occurs, and every `dates.true` corresponds to a surface in the file.

### 6.3 Chaos mutators (M): simulating the unseen-format round

The organizers seal the exact chaos catalogue, so the lab builds a broad one of its own. Each operator **updates the truth consistently** (new surfaces, new locators). The product team **never sees the operator code** for holdout operators (C-30 and up).

| ID | Operator | Example |
|---|---|---|
| C-01 | Header synonyms (English) | `Patient Name` → `Pt. Name`, `Name of Patient`, `PATIENT`, `full_name`, `nm` |
| C-02 | Header in Hindi / Hinglish | `नाम`, `मरीज़ का नाम`, `pita ka naam`, `मोबाइल नं.` |
| C-03 | Header style | camelCase, snake_case, UPPER, trailing spaces, BOM-glued first header |
| C-04 | Column order shuffle / split name columns | `First`, `Middle`, `Last` |
| C-05 | New hospital UHID patterns | `KGMU/2026/OPD/00123`, `R-77/1123` |
| C-06 | Date formats | `12-Apr-77`, `April 12, 1977`, `12.04.1977`, `20260412`, Hindi months, Devanagari digits |
| C-07 | Phone formats | `+91 98765 43210`, `098765-43210`, `98765 43210 (husband)` |
| C-08 | Aadhaar formats | dashed, dotted, split across two cells |
| C-09 | Label variants | `Naam:`, `नाम :`, `Pt:`, `Patient's Name -`, `NAME=` |
| C-10 | Relation markers | `s/o`, `S.O.`, `son of`, `पुत्र`, `w/o`, `पत्नी`, `h/o`, `C/o`, `care of` |
| C-11 | Honorifics | `Shri`, `Sh.`, `Smt.`, `Kum.`, `श्री`, `श्रीमती`, `Late` |
| C-12 | Transliteration noise | `Sunita` ↔ `Suneeta` ↔ `Sunitaa`, `Yadav` ↔ `Yaadav` ↔ `Jadav` |
| C-13 | Script swap of a whole note | Latin note → Devanagari note |
| C-14 | Code-mixing inside a sentence | `Patient Sunita ji ko 3 din se bukhaar hai, pati Ramesh ke saath aayi` |
| C-15 | OCR noise | `0`↔`O`, `1`↔`l`, broken spaces inside numbers |
| C-16 | Zero-width and homoglyph characters | ZWJ/ZWNJ in Devanagari, Cyrillic `а` in a Latin name |
| C-17 | Case and whitespace | `SUNITA   YADAV`, `sunita yadav`, tabs, NBSP |
| C-18 | Line wrapping | name split across a line break |
| C-19 | Encoding | UTF-16 LE/BE with BOM, cp1252, latin-1, mixed |
| C-20 | Delimiter | `;`, `|`, tab in a `.csv` file |
| C-21 | Format lies | JSON in `.csv`, CSV in `.txt`, no extension |
| C-22 | JSON shape | deeper nesting, arrays of arrays, NDJSON, keys that are names or UHIDs |
| C-23 | FHIR variants | contained resources, extensions, `text.div` with HTML entities |
| C-24 | Base64 variants | URL-safe base64, base64 with line breaks, data URIs |
| C-25 | Escapes | `सु…`, HTML entities `&#2360;`, percent-encoding |
| C-26 | Metadata variety | `prepared_by`, `operator`, `x-exported-for`, XML comments |
| C-27 | Filenames | names, phones and UHIDs in folder **and** file names; unicode and spaces |
| C-28 | Directory depth | nested 10–20 levels, hidden files (`.notes.txt`) |
| C-29 | Duplication | the same file twice under different names (`(1)` suffix) |
| C-30+ | **Holdout-only operators** | the builder invents these and never shows them to the product team (e.g. a brand-new state's geography, new ID families, new note templates) |

### 6.4 Oracles (O)

**O-1 Kit oracles (authoritative for the practice metrics):**
```bash
python3 -I ../Secret-Wards-ToolKit/validate_output.py --input <ds>/input --output <run>/release
python3 -I ../Secret-Wards-ToolKit/check_dev.py --output <run>/release --truth <ds>/truth/truth.json --show 50
```
`oracles/kit.py` parses the printed tables into JSON (leak by type/script/channel, canaries, utility, P/R/F0.5, false merges, raw copies). Run the kit scripts with `python3 -I` from a neutral working directory.

**O-2 Full scorer (`score_full.py`)**: an *approximation* of the official 100 points using the weights in the kit's `scoring.toml`:

| Category | Weight | Lab approximation |
|---|---|---|
| Privacy | 25 | `(1 − risk) × min(1, utility / 0.40)`; risk = weighted A1 0.20, record linkage (A2/A3) 0.20, profile (A4) 0.20, targeted (A5) 0.20, inversion (A6) 0.10, cross-release (A7) 0.10 |
| Detection | 20 | F-beta, β = 2; recall = 0.5 × macro over types (type weights from scoring.toml) + 0.5 × macro over scripts; precision from the over-redaction of `preserve` and `exclude` tokens |
| Utility | 20 | clinical probes 0.35 · temporal (intervals, LOS) 0.20 · truthful generalization 0.10 · statistics (diagnosis mix, LOS, lab means) 0.15 · token retention 0.10 · record retention 0.10 |
| Identity | 15 | B³ precision/recall → F0.5 over units with `link: required`; any homonym-pair merge is reported separately |
| Integrity | 10 | format validity 0.15 · schema preservation 0.20 · FHIR validity 0.15 · PSN consistency 0.10 · channel hygiene 0.15 · quarantine handling 0.15 · report quality 0.10 |
| Speed | 10 | linear between time good → limit and memory good → limit for the profile |
| Penalties | | −1 per leaked unique direct identifier or full patient name (cap −25) · −3 per canary (cap −15) · −5 per raw copy (cap −20) · −10 false success · −5 if the input was modified |

Always label this number **"lab estimate"**, never "score". Its purpose is trends and relative comparisons. The calibration anchors from 6.2 are used to sanity-check it.

**O-3 Invariants (`invariants.py`), checked on every sandbox run:**

| ID | Invariant | Severity if broken |
|---|---|---|
| I-01 | Exit code 0 and `CONTRACT OK` for any valid input dir | S0 |
| I-02 | `report.json` lists **every** input file by SHA-256, with status | S0 |
| I-03 | Input tree hash unchanged (before/after) | S0 (−5) |
| I-04 | No leftover files in `TMPDIR` / `HOME`; no file outside `--output` | S0 |
| I-05 | `RAKSHA_SECRET` (raw, hex, base64) not found in the output, stdout, stderr, report or temp files | S0 |
| I-06 | No `critical` truth surface in any output channel, stdout, stderr or report (normalized search, see O-4) | S1 |
| I-07 | No canary anywhere | S0 (−3 each) |
| I-08 | No quarantined or unsupported file copied byte-for-byte into `sanitized/` | S0 (−5 each) |
| I-09 | Determinism: 2 runs → identical bytes; also under `PYTHONHASHSEED=0/1/random`, `TZ=UTC/Asia/Kolkata`, `LANG=C/en_IN.UTF-8`, and a reversed file-copy order | S0 |
| I-10 | Different secret → every PSN differs **and** every date offset differs; structure identical | S0 |
| I-11 | Per patient: one offset, `0 < |offset| ≤ 180`, intervals between that patient's dates preserved exactly | S1 |
| I-12 | Age bands contain the true age, 5-year width, `90+` top-code; DOB generalization truthful | S2 |
| I-13 | PIN keeps exactly 3 digits (`229***`); village → tehsil | S2 |
| I-14 | Output formats parse: same CSV column count, valid JSON, FHIR `resourceType` kept, all UTF-8 | S1 |
| I-15 | `preserve` values present (per file, per unit) | S2 |
| I-16 | PSN regex `^PSN-[0-9A-HJKMNP-TV-Z]{6,}$` (Crockford); the same truth patient never gets two PSNs inside one file where linking is required | S2 |
| I-17 | No PSN shared by two different truth patients (false merge), especially homonym pairs and twins | S1 |
| I-18 | `records.jsonl` covers every unit locator in the truth; `loc` syntax valid (`row:N`, JSON pointer, `doc`) | S1 |
| I-19 | `report.json` counts are honest: detected entity counts are within the actual mentions; no "0 errors" when files were quarantined because of an exception | S1 (−10) |
| I-20 | No network-attempt strings in stdout/stderr | S0 |
| I-21 | Runtime and RSS within the profile limits (fail) and good thresholds (warn) | S1 / S3 |
| I-22 | Output file names contain no PII (filename channel) and keep the extension | S1 |
| I-23 | Logs (stdout/stderr) contain counts only: no token from any truth surface | S1 |
| I-24 | No product file was written inside the product repo during the run (repo mounted read-only; any write error is a finding) | S2 |

**O-4 Leak scanner (`leakscan.py`):** search for each truth surface in every output byte stream after normalizing both sides: NFKC, case-fold, collapse whitespace, strip zero-width characters, Devanagari↔ASCII digits, digit-only forms for numbers (`9876543210` matches `98765-43210`), decoding of base64 blobs (≥ 16 chars), `\u` escapes and HTML entities, and URL decoding. For multi-token names, also report **partial** leaks (surname + given name within 3 tokens). Report each hit with type, script, channel, file and the surrounding 40 characters, but **only inside the lab's results folder**.

### 6.5 Attack arena (A): A1–A7 as defined in kit `docs/ATTACKS.md`

Re-implement each attack generically (no knowledge of WardGuard internals), and run it against every release using the Forge's attacker files.

| Attack | Lab implementation | Metric |
|---|---|---|
| A1 Direct exposure | leak scanner over content and side channels | % of patients exposed |
| A2/A3 Record linkage | filter registry candidates by phone, email, last-4, masked phone, district, gender, age range (±1/+2), birth year, tehsil, village, PIN, PIN prefix, **skipping filters that would empty the set**; weight full name ×60, given ×8, surname ×3, relative ×8, house ×2; risk = probability on the true person | mean risk; % with risk ≥ 0.5 |
| A4 Profile aggregation | join records by shared PSN or shared reference values, pool evidence, re-attack; risk = max(record, profile) | % patients identified at ≥ 0.5 |
| A5 Targeted + shift recovery | match known facts (visit date, condition ×8 if ≤ 3 profiles share it, LOS); recover a global shift from ≥ 2 high-confidence re-ids; un-shift and re-attack; count decoy claims as membership false positives | % targets identified; recovered shift (should be "none") |
| A6 Pseudonym inversion | dictionary of originals × transforms (case, digits-only, MD5/SHA-1/SHA-256/SHA-512 full and prefixes ≥ 8, base64, reversal); PSN equal to or prefix of a transform, or embedding a UHID core or phone | count (must be 0) |
| A7 Cross-release | run again with a different secret; count patients with the same PSN or the same shifted dates | count (must be 0) |

**Reference levels to beat** (from the PRD; attack readings on a practice-style dataset): A3 27.7% · A4 16.7% · A5 40.1%. Also run the attacks on the **raw input** (the normalization baseline), so each result reads as "risk reduced from X to Y".

> The product already has `tools/attack_sim.py` (A2–A5). The lab's attacks are **independent re-implementations**, so the product's own simulator cannot hide a blind spot. When they disagree, investigate both.

### 6.6 Metamorphic relations (MR)

A metamorphic test transforms the input, reruns the product, and checks a relation between the two outputs. No answer key is needed, so these tests work on any data, including holdout.

| ID | Transform | Relation that must hold |
|---|---|---|
| MR-01 | Rename a file that contains no PII | sanitized content identical (only the path differs) |
| MR-02 | Shuffle CSV row order | the multiset of (sanitized row → PSN) is identical |
| MR-03 | Add an unrelated new patient file | the existing patients' sanitized rows and PSNs do not change (or the change is documented as intended) |
| MR-04 | Delete one file | no crash; the other files are unchanged unless they were linked through it |
| MR-05 | Change the secret | only PSNs and shifted dates change; every other byte is identical |
| MR-06 | Transliterate a patient's name Latin → Devanagari in one file | still removed; still linked to the same PSN |
| MR-07 | Re-encode a file (UTF-16, cp1252, BOM) | same detections; output is UTF-8 |
| MR-08 | Move a CSV row into an equivalent JSON record | same entity types removed; same PSN |
| MR-09 | Duplicate the whole input into a sub-folder | duplicated records get the same PSNs as the originals |
| MR-10 | Replace a header with a synonym (C-01/C-02) | same column classification (same cells removed) |
| MR-11 | Insert zero-width characters, NBSP or case changes into names | still removed |
| MR-12 | Run on a subset (first half of the files) vs the full set, same secret | the PSN of a patient present in both is the same (consistency) and the rows are identical except for linking-driven changes |

### 6.7 Micro-case catalogue (TC)

Micro cases are tiny generated datasets (1–3 files), each testing **one behaviour**, with a truth file. They run in the fast lane and are confirmed in the sandbox only when they fail. IDs are stable so failures can be tracked across versions.

| Family | Axes multiplied | Approx. cases |
|---|---|---|
| TC-ID | 11 ID types × ~8 surface formats × 6 channels × 3 scripts of the surrounding text | ~1,600 |
| TC-NAME | 4 name structures × 3 scripts × 8 contexts (label, relation, honorific, free text, column, key, filename, header) × 2 pools | ~400 |
| TC-REL | 10 relation markers × 3 scripts × 3 positions | ~90 |
| TC-ADDR | HOUSE / LOCALITY / LANDMARK / VILLAGE / PIN × 6 phrasings × 3 scripts × 3 formats | ~270 |
| TC-DATE | 15 date formats × DOB/clinical × 3 formats | ~90 |
| TC-TRAP | each meaning trap × 3 scripts × 4 formats (each case also asserts the clinical value is **kept**) | ~150 |
| TC-LINK | homonyms, twins, fragmented, language split, name change, typo, shared phone (family), shared address (joint family) × 4 formats | ~120 |
| TC-PRIV | age edges (0, 4, 5, 89, 90, 120), DOB-only, age-only, PIN edges, one-patient village, rare disease | ~80 |
| TC-ROBUST | every broken-file kind × 6 extensions | ~100 |
| TC-HIDDEN | every channel × every encoding (base64 variants, `\u`, entities) | ~100 |
| **Total** | | **~3,000** |

**Case naming:** `TC-ID-PHONE-plus91space-key-deva-0007`. Each case stores `input/`, `truth.json` and `expect.yaml` (for example `removed: [PHONE]`, `kept: ["BD x 5 days"]`, `psn_count: 2`).

### 6.8 Fuzzing and property tests (Z)

**Property tests (hypothesis, fast lane) on the product's pure functions**, using the signatures in `07_API_CONTRACTS.md`:

| Target | Properties |
|---|---|
| `ingest.decode.decode(raw)` | never raises; result is valid str or None; deterministic |
| `ingest.sniff.sniff(raw, rel)` | never raises; returns a known `Fmt` |
| readers (`load_all` on a temp dir with one fuzzed file) | never raises; the file is either parsed or quarantined with a reason |
| `detect.patterns.find_identifiers(text)` | spans inside the text bounds; non-overlapping after `resolve_overlaps`; a Verhoeff-valid 12-digit number inside any context is found; Verhoeff-invalid ones are not labelled AADHAAR |
| `detect.context.detect_text` | adding unrelated clinical words around a labelled name does not drop the name |
| `privacy.dates.shift_date_text(s, off)` | shifting by `+k` then `−k` returns the original for every supported format; output parses in the same format |
| `privacy.generalize.age_band(age)` | the band contains the age; width 5; `90+` above 90 |
| `privacy.pseudonym.pseudonym(key, secret)` | Crockford format; different secret → different value; no collisions in 1M random keys |
| `rewrite.set_json_pointer` | round-trip with RFC 6901 escaping (`~0`, `~1`) |

**File fuzzing (sandbox lane, nightly):** take real Forge files and apply byte mutations (bit flips, truncation, inserted NUL, duplicated chunks, random UTF-8 / invalid sequences, huge line, deep nesting injection). The properties are **I-01, I-02, I-03, I-08 and I-19**: never crash the whole run, always report, never raw-copy, stay honest. Optionally use `atheris` on Linux for `decode`/`sniff`/readers.

### 6.9 Performance and scale (P)

| Test | Input | Pass |
|---|---|---|
| P-01 Curve | tiny → small → medium → standard → large | time and RSS within each profile's limit; record good/limit position |
| P-02 Bulk CSV | one 200k-row CSV (~60 MB) | < 4 GB RSS, < 15 min; streaming behaviour visible (RSS not ∝ file size × 10) |
| P-03 Many small files | 20,000 files of 1 KB | file-count overhead |
| P-04 Deep JSON | depth 1,000 and 10,000 | no `RecursionError` crash of the whole run (quarantine is OK) |
| P-05 Long line | a single 50 MB line | no regex catastrophic backtracking (watch CPU time) |
| P-06 Regex ReDoS | adversarial strings for each pattern (long digit runs, repeated `S/o S/o S/o …`) | each file finishes in < 2 s |
| P-07 2-CPU realism | same as P-01 with `--cpus 2` vs `--cpus 1` | report the scaling |

Plot time vs input size and RSS vs input size in the report.

### 6.10 Security and hygiene (SEC)

| Test | Method | Pass |
|---|---|---|
| SEC-01 No network | `--network none`, plus a static scan of product imports (`socket`, `urllib`, `http`, `requests`, `ftplib`, `smtplib`) and dynamic: run with a fake `HTTP_PROXY` and see if anything tries | no attempts |
| SEC-02 Secret hygiene | I-05 with secrets that contain unicode, spaces, 1 char, 4 KB | never written |
| SEC-03 No temp files | I-04; also `strace -f -e trace=openat` (Linux) to list every file opened for writing | only under `--output` |
| SEC-04 Logs counts-only | I-23 | no data values |
| SEC-05 Exceptions sanitized | force failures (unreadable file via chmod 000, a symlink loop, a file that disappears) | stderr has exception **type names** only |
| SEC-06 Path traversal | file names like `..%2f..%2fx.csv`, `../x` inside JSON `source_file`, symlinks pointing outside input | output stays inside `--output`; symlinks are not followed outside |
| SEC-07 Dependency check | requirements: no LLM/transformer > 50M params, no hosted AI SDK; `pip-audit` optional | clean |
| SEC-08 Missing/empty secret, missing args, non-empty output dir, output inside input | CLI edge cases | clean error, exit code ≠ 0 only where the contract allows |

### 6.11 Orchestrator, results store, dashboard (R)

- `lab.py campaign <name>` reads `campaigns/<name>.yaml` (datasets, mutators, lanes, oracles, attacks, MRs, budgets), runs jobs in parallel (`--jobs N`, default = cores / 2 because each sandbox gets 2 CPUs), and writes:
  - `results/<run-id>/<job>/` with `run.json`, `stdout.txt`, `stderr.txt`, `release/`, `oracles.json`, `attacks.json`
  - one row per job in `results/runs.sqlite` (tables: `runs`, `metrics`, `failures`, `bugs`)
- `lab.py report --since <run-id>` produces `results/reports/capability-<date>.html`: scorecard with mean ± 95% t-interval across seeds (the organizers use the same statistic), leak heatmap (type × script × channel), linkage table, attack table vs raw baseline and reference levels, performance curves, invariant pass matrix, top-20 failures, trend vs previous report, and per-owner bug list.
- Every run is stamped with: product commit SHA, lab commit SHA, image tag, seed list hash, and kit `scoring.toml` SHA-256.

### 6.12 Minimizer and bug loop (B)

`lab.py minimize <job>` shrinks a failing dataset while the **same failure signature** still reproduces (for example `I-06:PHONE:key:deva`):

1. ddmin over files → 2. ddmin over rows/JSON array items/paragraphs → 3. ddmin over characters around the failing surface → 4. rebuild a consistent `truth.json` for what is left.

Output: `bugs/fixtures/BUG-####/{input/, truth.json, expect.yaml, repro.sh}` + a filled `bugs/BUG-####.md`. Fixtures are synthetic, so they can be copied into the product repo as regression tests (`tests/regression/test_bug_####.py`).

---

## 7. Test campaigns

| Campaign | When | Content | Wall time (8 cores) | Gate |
|---|---|---|---|---|
| **smoke** | every product commit / PR | kit dev data + 3 dev seeds (small, one with chaos) + invariants I-01..I-10 + MR-05 | ~5 min | no S0/S1 regressions |
| **regression** | every merge to `main` | 20 dev seeds (small/medium, half chaos) + all micro cases (fast lane) + all bug fixtures + MR-01..12 on 5 seeds + attacks | ~30–45 min | lab estimate not below the last tag − 1 point; all fixed bugs stay fixed |
| **nightly / torture** | daily | 100+ seeds incl. standard, chaos operators combined (2–4 per dataset), fuzz 1 h, perf P-01..P-07, security SEC-01..08, Python 3.10/3.11/3.12 matrix, determinism matrix | 3–6 h | report + new bugs filed |
| **holdout** | before each release tag, run **only by the builder** | holdout seeds + holdout lexicon + C-30+ operators | ~1 h | publish aggregate numbers only (no per-case details to the product team) |

---

## 8. Build plan: task cards for the one builder

The order is chosen so that **useful results arrive early**: after T-04 the lab already finds real bugs on the kit data, and every later card adds coverage.

Each card has **Goal / Steps / Done when / Commit**. Commit format in the lab repo: `[T-xx] area: message`.

#### T-00 · Setup (0.5 h)
- Goal: lab repo, kit, product checkout side by side; baseline recorded.
- Steps: `git init wardguard-testlab`; `config/lab.yaml` with paths; reproduce section 2's numbers with the kit scripts; write `results/baseline-00fdde9.json`.
- Done when: `lab.py doctor` prints the product SHA, kit path, Docker version, Python version and the baseline metrics.
- Commit: `[T-00] lab: scaffold, config, baseline`

#### T-01 · Sandbox runner (2 h)
- Goal: section 6.1, working on macOS Docker (and optionally Linux `unshare`).
- Steps: Dockerfile with a requirements-hash tag; `runner.py` (watchdog, timeout, run.json, input Merkle hash before/after, tmp/home leftovers, network strings); `run_sandbox.sh`.
- Done when: the kit dev data runs in the sandbox → `run.json` with `status: ok`, `peak_rss_mb`, `input_unchanged: true`; a test program that allocates 5 GB is killed as `memory_exceeded`; one that sleeps is killed as `timeout`; one that tries `socket.connect` produces a network-attempt string.
- Commit: `[T-01] sandbox: docker runner with watchdog and run.json`

#### T-02 · Kit oracle wrapper + invariants on kit data (2 h)
- Goal: O-1 and the invariants that need no Forge truth (I-01..I-05, I-08..I-10, I-14, I-16, I-18 partial, I-20..I-24).
- Done when: `lab.py run --dataset kit-dev` prints a pass/fail table; it reproduces BUG-0001..0004 or confirms them as fixed.
- Commit: `[T-02] oracles: kit wrapper and contract invariants`

#### T-03 · Results store + minimal report (1.5 h)
- Goal: sqlite store and a one-page HTML report (scorecard + invariant matrix + leaks table).
- Done when: two runs on different product commits show a delta column.
- Commit: `[T-03] report: sqlite store and first HTML report`

#### T-04 · Bug ledger and filing (1 h)
- Goal: `bugs/BUG-####.md` template (section 9), auto-numbering, owner routing by file path (section 9.2), and import of BUG-0001..0004.
- Done when: `lab.py bug new --from <job>` creates a filled file.
- Commit: `[T-04] bugs: ledger, template, routing`

#### T-05 · Forge v1 (6–8 h, the largest card)
- Goal: section 6.2 for CSV/TSV/JSON/FHIR/text in Latin + Devanagari + Hinglish, all channels, traps, canaries, truth, attacker files, profiles tiny/small/medium.
- Steps: world → people → ids → clinical → renderers → channels → traps → truth → attacker. Start with CSV + text and grow.
- Done when: the **Forge self-tests 1–6 pass** (passthrough, redact-all, oracle anchors, kit starter anchor, ordering, truth consistency) on 10 seeds, and `check_dev.py` runs unchanged on the Forge truth.
- Commit: `[T-05] forge: generator v1 with raksha-truth/1 answer key`

#### T-06 · Forge v2: robustness formats and the standard/large profiles (2 h)
- Goal: XML, PDF, JPG, binary, broken files, encodings, deep/large files; profiles standard and large.
- Done when: quarantine expectations (`expect: either|quarantine`) are in the truth and I-08 is checked.
- Commit: `[T-06] forge: robustness corpus and scale profiles`

#### T-07 · Full scorer (2 h)
- Goal: O-2 with the weights from the kit `scoring.toml` (read the file, never hard-code the numbers).
- Done when: the anchors are ordered correctly on 10 seeds, and the lab estimate for WardGuard on kit dev data is printed with a per-category breakdown.
- Commit: `[T-07] oracles: approximate official scorer`

#### T-08 · Leak scanner + remaining invariants (1.5 h)
- Goal: O-4 and I-06, I-07, I-11, I-12, I-13, I-15, I-17, I-19.
- Done when: a planted leak in each channel and encoding is caught by a lab self-test.
- Commit: `[T-08] oracles: normalized leak scanner and truth invariants`

#### T-09 · Attack arena (3 h)
- Goal: section 6.5, A1–A7, with the raw-input baseline.
- Done when: attacks on the **passthrough** anchor give very high risk, attacks on the **oracle** anchor give ~0, and A7 uses a second sandbox run with a different secret.
- Commit: `[T-09] attacks: A1-A7 arena`

#### T-10 · Chaos mutators (3 h)
- Goal: section 6.3, C-01..C-29 (dev) + at least 5 holdout operators kept private.
- Done when: every operator has a lab test proving that the truth stays consistent after mutation (self-test 6 passes on mutated datasets).
- Commit: `[T-10] mutate: chaos catalogue`

#### T-11 · Metamorphic relations (2 h)
- Goal: MR-01..MR-12.
- Done when: each relation runs on 5 seeds and reports pass/fail with a diff excerpt.
- Commit: `[T-11] mr: metamorphic relations`

#### T-12 · Micro-case catalogue + fast lane (3 h)
- Goal: section 6.7 with ~3,000 cases; fast-lane runner (in-process, parallel via `multiprocessing`); confirmation of failures in the sandbox.
- Done when: `lab.py micro --all` finishes in < 15 min on 8 cores and outputs a per-family pass-rate table.
- Commit: `[T-12] micro: case catalogue and fast lane`

#### T-13 · Fuzz + property tests (2 h)
- Goal: section 6.8.
- Done when: 1 h of fuzzing runs unattended; crashes are deduplicated by stack signature (type + top frame, **no values**).
- Commit: `[T-13] fuzz: hypothesis properties and file mutators`

#### T-14 · Performance + security suites (2 h)
- Goal: sections 6.9 and 6.10.
- Done when: the report has performance curves and a SEC pass matrix.
- Commit: `[T-14] perf/sec: scale curves and hygiene suite`

#### T-15 · Minimizer (2 h)
- Goal: section 6.12.
- Done when: a deliberately injected failure (e.g. a phone in a JSON key, in Devanagari digits) shrinks to ≤ 1 file and ≤ 3 lines with the same signature.
- Commit: `[T-15] minimize: ddmin with signature preservation`

#### T-16 · Campaigns + full capability report (2 h)
- Goal: the campaign YAMLs from section 7, the full report (section 10), and a trend chart across product commits.
- Done when: `lab.py campaign nightly` runs end-to-end unattended and produces the capability report.
- Commit: `[T-16] campaigns: smoke, regression, nightly, holdout + capability report`

**Total: ~37–40 builder hours.** MVP (T-00..T-04) ≈ 7 h. If time is short, the next-best order is T-05 → T-08 → T-10 → T-09 → T-12.

---

## 9. Bug handling

### 9.1 Severity (tied to score impact)

| Sev | Meaning | Examples | Fix SLA |
|---|---|---|---|
| **S0** | Direct penalty or disqualification risk | crash/exit ≠ 0, contract break, raw copy, canary leak, secret written, input modified, nondeterminism, network attempt, false success | stop everything, fix now |
| **S1** | Critical identifier leak or false merge | full patient name / Aadhaar / phone / ABHA / MRN surviving; homonym merged; report dishonest | same day |
| **S2** | Score loss | quasi-identifier leak, over-redaction of clinical values, linkage miss, weak generalization, slow | prioritize by points × frequency |
| **S3** | Minor | cosmetic, rare edge, tooling | backlog |

**Priority = expected points lost** = (frequency across seeds) × (points per occurrence, from the scorer). Always fix the highest-points family first, not single cases.

### 9.2 Routing (from `08_ARCHITECTURE.md` ownership)

| Failing area (path of the top frame, or the failing oracle) | Owner |
|---|---|
| `wardguard/ingest/*`, `export/*`, `safety/*`, `pipeline.py`, `rewrite.py`, `detect/hidden.py`, `privacy/*`, `tools/eval.sh`, `tools/attack_sim.py`, `tools/check_submission.py`, README/brief, performance | **Lakshya** |
| `wardguard/detect/*` (except `hidden.py`), `link/*`, `resources/*`, `tools/chaos_gen.py`, misses of type × script, homonym merges, linkage recall | **Saransh** |
| Shared `model.py` / contracts | both (proposal via `DECISIONS.md`) |

### 9.3 Bug record template (`bugs/BUG-####.md`)

```markdown
# BUG-#### <one-line title, no data values>
- Severity: S0|S1|S2|S3      - Owner: Lakshya|Saransh      - State: NEW|TRIAGED|FIXING|FIXED|VERIFIED|WONTFIX
- Signature: <oracle>:<type>:<channel>:<script>  (e.g. I-06:PHONE:key:deva)
- Found by: <campaign/job id>   - Product SHA: <sha>   - Lab SHA: <sha>
- Frequency: <n of m seeds> · Est. points lost: <x>
## Repro
bugs/fixtures/BUG-####/repro.sh   (sandbox lane)
## Expected vs actual
## Minimized input (synthetic)
## Suspected cause (module/function)
## Fix commit · Regression test path · Verified in campaign <id>
```

### 9.4 Loop

`NEW` (auto-filed) → `TRIAGED` (the builder confirms in the sandbox, dedups by signature, sets severity/owner) → `FIXING` (owner branch `fix/BUG-####-<slug>`, commit `[BUG-####] module: msg`, regression test added under `tests/regression/` in the product repo) → `FIXED` (merged) → `VERIFIED` (the regression campaign passes and the signature count in the nightly drops to 0). Mirror S0/S1 items into the product's `project-docs/tracking/KNOWN_ISSUES.md`.

---

## 10. Capability report template

```markdown
# WardGuard Capability Report: <date> · product <sha> · lab <sha>
Datasets: <n> (dev <a>, holdout <b>, chaos <c>) · profiles <…> · seeds hash <…> · scoring.toml sha <…>

## Headline (lab estimate, mean ± 95% CI across datasets)
| | Normal | Chaos | Holdout |
| Total / 100 | | | |
| Privacy / 25 · Detection / 20 · Utility / 20 · Identity / 15 · Integrity / 10 · Speed / 10 | | | |
| Penalties | | | |

## Detection
Leak % by type (rows) × script (cols); leak % by channel; canaries found; over-redaction (preserve kept %).

## Identity
B³ P/R/F0.5; false merges (homonyms, twins); trap success: fragmented, language split, name change.

## Privacy
A1..A7 risk (raw → release); recovered global shift (should be none); cross-release links (should be 0).

## Utility
Clinical probes kept; interval preservation; band truthfulness; statistics drift (diagnosis mix, LOS, lab means).

## Robustness and integrity
Invariant pass matrix (I-01..I-24); quarantine correctness; format validity; fuzz crash signatures.

## Performance
Time and RSS curves by profile; position vs good/limit thresholds; 1 vs 2 CPU.

## Bugs
Open by severity and owner; fixed since last report; top-10 by points lost.

## Honest limitations
What the product cannot do yet (feeds README "Known limitations" and the brief).
```

---

## 11. Lab rules

1. **Never tune on holdout.** Holdout seeds, the holdout lexicon and the C-30+ operators stay with the builder. The product team sees only aggregate holdout numbers. If a holdout case leaks into a fix, retire it and make new ones.
2. **The lab never edits the product.** All product changes go through Lakshya/Saransh commits. The product repo is mounted read-only.
3. **Never weaken an oracle to make the product pass.** A failing oracle is either a product bug or a **lab** bug with its own record (`LAB-####`). Lab bugs are fixed first.
4. **Fixes must be generic.** Reject product fixes that hard-code a lab name, header, file name or seed. A regression fixture for a bug must also pass when regenerated with a **different seed** of the same family.
5. **Synthetic only.** No real names, numbers or records ever. Generated Aadhaar numbers are Verhoeff-valid but random; never type in a real one.
6. **Determinism of the lab.** Same seed → same dataset bytes; same product + same dataset + same secret → same scores. Non-reproducible results are not filed.
7. **Data stays in the lab.** Leak excerpts and fixtures stay in `wardguard-testlab/` (private). Never paste them into public issues or the product README.
8. **Every finding carries provenance:** product SHA, lab SHA, seed, campaign, image tag.
9. **AI assistants:** the lab may use AI to write lab code and to brainstorm cases, but test data must be produced by the seeded Forge code (reproducible), not pasted from a chat.

---

## 12. Prompts

> How to use: build `WardGuard_TestLab_Builder.pdf` (`bash project-docs/build_pdfs.sh`), start a **new** Gemini chat, upload the PDF, paste **P-1**. Use the other prompts as needed. After a long session, paste **P-8** (audit).

### P-1 · Master prompt for the Lab Builder's AI session

```
You are my senior test engineer and Python pair-programmer. I am the single
LAB BUILDER for "WardGuard Proving Ground", a test lab that attacks WardGuard
(an offline, CPU-only, LLM-free privacy firewall for synthetic multilingual
English/Hindi/Hinglish Indian hospital records: Yugaantar DevForge Track 3
"Secret Wards").

The attached PDF is the COMPLETE source of truth: the Test Lab Build Guide
(sections 1-13: baseline numbers, known bugs, architecture, repo layout,
component specs S/F/M/O/A/MR/TC/Z/P/SEC/R/B, campaigns, task cards T-00..T-16,
bug handling, report template, lab rules, truth schema) plus the product's
context, data models, API contracts and architecture. Read it fully first.

NON-NEGOTIABLE RULES
1. Ground everything in the PDF or in code/output I paste. If something is not
   there (e.g. an exact field read by the kit's check_dev.py), say
   "NOT IN DOCS - please paste <file>" instead of guessing.
2. The lab lives in its own repo (wardguard-testlab/). Never propose edits to
   the product repo. Product bugs become BUG records routed to Lakshya or
   Saransh by the ownership table in section 9.2.
3. Never weaken an oracle, never tune on holdout, never hard-code product
   behaviour into the lab. Lab bugs (LAB-####) are fixed before product bugs
   are filed.
4. All test data is synthetic and generated by seeded, deterministic code
   (random.Random(derived_seed)); no real people or numbers; no hash() or
   set-iteration order in anything that affects output bytes.
5. Sandbox runs mirror the grader: --network none, 2 CPU, 4 GB, timeout,
   read-only input and product, private TMPDIR/HOME scanned afterwards.
6. The kit scripts (validate_output.py, check_dev.py, check_submission.py) are
   run unchanged with `python3 -I` from a neutral directory.
7. Python 3.10+, type hints, small pure functions, pytest tests for the lab
   itself (especially Forge self-tests 1-6 and calibration ordering).
8. Reply format, always:
   TASK / SPEC REFS (section numbers) / PLAN / FILES / CODE (full files) /
   LAB TESTS / RUN COMMANDS / EXPECTED OUTPUT / RISKS & ASSUMPTIONS /
   LEDGER UPDATE (task state, new BUG-/LAB- records if any)

Environment: macOS + Docker Desktop (optional Linux VM for unshare).
Paths: ../Scaler_DevForge (product, read-only), ../Secret-Wards-ToolKit (kit),
./ (lab repo).

Acknowledge by listing: (a) the 5 components that matter most for the next
task, (b) the next task card from section 8 that is not DONE, (c) the
invariants/oracles that task must satisfy, (d) anything NOT IN DOCS you need
me to paste. Then wait.
```

### P-2 · Start a task card

```
Task: T-<xx>. Current lab tree:
<paste `tree -L 3` of wardguard-testlab>
Relevant existing code:
<paste files>
Last run output (if any):
<paste>
Restate the goal and the "Done when" in 3 lines, list doubts, then deliver in
the required format. Include lab self-tests that prove the component is
correct BEFORE it is used to judge the product.
```

### P-3 · Kit truth-schema extraction (use before T-05)

```
Here is the kit's check_dev.py and the first 2 units of dev/truth/truth.json:
<paste check_dev.py>
<paste a truth excerpt>
List every truth field check_dev.py actually reads (path, type, how it is
used: leak scan, utility, linking, canaries, raw copies), and every field it
ignores. Then give the exact JSON schema my Forge must write so check_dev.py
scores Forge datasets unchanged. Mark anything uncertain as NOT IN DOCS.
```

### P-4 · Triage a failure

```
Failure from campaign <id>, job <job>:
run.json: <paste>
oracle/invariant output: <paste>
leak excerpts (synthetic): <paste>
1) Is this a product bug or a lab bug? Check the Forge truth for consistency
   first (self-test 6 logic).
2) Give the failure signature (<oracle>:<type>:<channel>:<script>).
3) Severity (S0-S3) with the points-lost estimate from section 9.1.
4) Owner from section 9.2, and the suspected module/function from the API
   contracts.
5) A filled BUG-#### (or LAB-####) record in the section 9.3 template.
Do not propose product code here.
```

### P-5 · Hand-off prompt for the product owner (Lakshya or Saransh pastes this into THEIR Gemini chat, which already has their own context PDF)

```
A test-lab bug is assigned to me:
<paste BUG-####.md>
Minimized synthetic repro:
<paste fixture files + repro.sh>
Current code of the suspected files:
<paste>
Find the root cause using only my docs and this code. Fix it GENERICALLY
(no hard-coded names, headers, files or seeds from the fixture; the fix must
also hold for a different seed of the same family). Add a regression test
under tests/regression/test_bug_####.py that rebuilds the case from invented
data. Respect file ownership and the AI coding rules. Same reply format as my
master prompt, plus: "Why this generalizes" (3 bullets).
```

### P-6 · Red-team brainstorm (new adversarial cases)

```
Current capability report summary:
<paste headline + leak heatmap + top failures>
Act as the organizers designing the sealed unseen-format dataset. Propose 15
NEW variations that are NOT already in chaos operators C-01..C-29 or the
micro families, each with: name, what changes, why a practice-tuned system
fails, which truth fields change, and the expected correct behaviour. Rank
them by expected points at risk. Output as a table, then as stubs for
mutate/operators.py (C-30+, holdout) or micro/catalogue.py.
```

### P-7 · Write the capability report narrative

```
Here are the report numbers (JSON):
<paste results summary>
Write the "Headline", "Honest limitations" and "Top risks before submission"
sections of the section 10 template. Use only these numbers; give CIs as
printed; label every score "lab estimate"; no marketing language.
Then give a 5-line summary for the team chat.
```

### P-8 · Anti-drift audit (every ~10 messages)

```
Re-read the Lab Build Guide sections 6, 9 and 11. Audit all the code you gave
me in this chat for: nondeterminism (hash(), set order, time, unseeded
random), oracles weakened or tuned to the product, holdout leakage, edits to
the product repo, kit scripts modified or run without -I, real-looking
personal data, missing lab self-tests, data values printed outside the
results folder. List violations, then give corrected code for those parts
only.
```

### P-9 · Release gate check (before every submission tag)

```
Here are: smoke + regression + holdout results, the open bug list, and the
kit check_submission.py --run output:
<paste>
Using section 7 gates and section 9.1 severities, answer GO / NO-GO with the
blocking items, then list the README "Known limitations" lines that the
numbers justify.
```

---

## 13. Appendix

### A. Truth schema (`raksha-truth/1`), observed in the kit's `dev/truth/truth.json`

```jsonc
{
  "schema": "raksha-truth/1",
  "generator_version": "1.0.0", "seed": "dev-seed-1", "profile": "small", "chaos": false,
  "ref_date": "2026-11-20",
  "files": {
    "<relative path>": {
      "path": "...", "format": "csv|tsv|json|fhir|text|xml|pdf|binary",
      "encoding": "utf-8|utf-8-sig|utf-16|cp1252", "delimiter": ","|null,
      "expect": "sanitize|either|quarantine", "category": "registration|hidden|malformed|…",
      "clean": false, "date_hint": "dmy|mdy|iso", "sha256": "...", "size": 5904,
      "generalizable": ["col:Age", "col:DOB", "col:PIN", "col:Village/Mohalla"],
      "units": {
        "row:0": {
          "loc": "row:0", "patient": "PT00004", "cid": "PT00004#0",
          "link": "required|none|ambiguous", "tags": [],
          "entities": [ { "type": "RELATIVE_NAME", "surface": "Naresh Chauhan", "person": "P00225",
                          "role": "patient|relative|…", "script": "latin|deva|hinglish",
                          "channel": "content|filename|metadata|key|base64|header",
                          "match": "name|text|dob|…", "tokens": ["naresh","chauhan"], "full": true,
                          "key": "<normalized form, for non-name types>", "critical": false,
                          "weight": 0.4 } ],
          "preserve": [ { "text": "Rae Bareli", "kind": "district", "weight": 0.3, "path": "col:District" } ],
          "dates":    [ { "true": "2025-06-30", "event": "registration:snj", "patient": "PT00004", "hint": "dmy", "path": "col:Reg Date" } ],
          "fields":   [ { "kind": "age|gender|dob|village|district|pin", "true": 48, "path": "col:Age", "patient": "PT00004" } ],
          "exclude":  ["48", "12/04/1977", "30/06/2025"]
        }
      }
    }
  },
  "patients": { "PT00000": { "rid": "UPV5851611", "pid": "P00072", "hospitals": ["jjh"],
                             "uhids": {"jjh": ["JJH-0076864"]}, "traps": ["homonym"] } },
  "traps": { "language": [...], "fragmented": [...], "meaning": [...], "reidentification": [...],
             "homonym_pairs": [["PT00000","PT00021"]] },
  "linkability": { "required_units": 771, "ambiguous_units": 2, "components": 49 },
  "canaries": ["CANARY-0", "CANARY-1", ...]
}
```
Practice-data reference counts: 200 files (192 sanitize, 8 either); 48 patients; 883 units (771 required, 110 none, 2 ambiguous); 3,230 PII entities; scripts latin 2,980 · deva 143 · hinglish 111; channels content 3,115 · filename 48 · metadata 40 · key 12 · base64 11 · header 8. Use these as the **minimum** mix for `small`, and push the deva/hinglish/side-channel shares much higher in chaos datasets, because that is where the product is weakest.

> Before writing `truth.py`, run **P-3** with the real `check_dev.py` to confirm exactly which fields it reads.

### B. Attacker files (kit format)
- `registry.csv`: `rid,name,relation,relative_name,gender,age,house_no,mohalla,village,tehsil,district,pin,phone,email,aadhaar_last4`
- `known_facts.jsonl`: `{"rid": "...", "visit_dates": ["YYYY-MM-DD"], "hospital": "...", "condition_hint": "..."}` (`condition_hint` is optional)

### C. Kit commands
```bash
KIT=../Secret-Wards-ToolKit
RAKSHA_SECRET=practice python main.py --input $KIT/dev/input --output /path/to/empty_out
python3 -I $KIT/validate_output.py --input $KIT/dev/input --output /path/to/empty_out
python3 -I $KIT/check_dev.py --output /path/to/empty_out [--truth <truth.json>] [--show 20]
python3 -I $KIT/check_submission.py --repo ../Scaler_DevForge [--run] [--input <dir>] [--timeout 900]
```

### D. Glossary
- **Unit / record:** the scoring unit: `row:N`, a JSON pointer, `doc`, or a file-level place (`@file`, `@header`, `@filename`).
- **Channel:** where PII hides: content, filename, key, header, metadata, base64.
- **PSN:** the keyed pseudonym `PSN-XXXXXX` (HMAC-SHA256 with `RAKSHA_SECRET`, Crockford base32).
- **Anchor:** a reference submission (passthrough, redact-all, oracle, naive, kit starter) used to prove the lab's scoring is sane.
- **Signature:** `<oracle>:<type>:<channel>:<script>`, used to deduplicate failures.
- **Fast lane / sandbox lane:** in-process vs Docker-isolated execution of the product.
- **Holdout:** seeds, lexicons and operators only the builder sees.
