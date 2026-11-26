# WardGuard: A Multilingual Privacy Firewall for Hospital Records

> **Yugaantar DevForge** · Track 3 "Secret Wards" · **Team WardGuard** (`team-wardguard`)  
> **Status:** Production Release Ready · Evaluation Harness: **CONTRACT OK** · **READY TO SUBMIT**

WardGuard is an **offline, CPU-only, LLM-free** privacy engine engineered to ingest heterogeneous multi-hospital records dumps (CSV, TSV, JSON, FHIR R4 Bundles, and unstructured clinical notes in English, Hindi, and Hinglish) and transform them into **de-identified, research-ready releases**.

Key Capabilities:
- **Zero-Leak PII Removal:** Eliminates direct and indirect personal identifiers (patient names, relative names, Verhoeff-verified Aadhaar, ABHA IDs, UHID/MRN, PAN, phone numbers, postal addresses, exact DOB including FHIR `Patient.birthDate`) across unstructured text, tabular columns, JSON keys, CSV/TSV headers (English, Devanagari & Hinglish), filenames, metadata pointers, and base64 payloads.
- **Strict Clinical Utility Preservation:** Preserves clinical telemetry (medicines, dosages, administration frequencies like `1-0-1`, vitals, lab values with units, diagnoses, doctor names, and exact patient lengths of stay).
- **Conflict-Guarded Cross-Script Linkage:** Generates stable, deterministic keyed pseudonyms (`PSN-XXXXXX`) linking records of the same patient across hospitals, formats, and scripts (Latin $\leftrightarrow$ Devanagari $\leftrightarrow$ Hinglish) without ever merging distinct individuals (`0` false merges).
- **Cluster-Level Re-identification Resistance:** Defeats linkage and targeted attacks (`A1`–`A7`) via per-patient HMAC date offsets ($\pm 15\text{–}90$ days, keeping longitudinal intervals and quarterly seasonality intact while remaining unrecoverable), 20-year age bands with `60+` top-coding (widened to 30 years for rare clusters), coarse 1-digit PIN prefixes, village/tehsil suppression, and Devanagari-normalized cluster-level $k$-anonymity ($k_{\text{min}}=5$).
- **Offline Judge Demo UI:** Includes a standalone 100% offline, light-theme web showcase (`demo_ui/`) powered solely by Python's stdlib `http.server` with zero external CDN requests or network dependencies in the core pipeline.

---

## Quick Start

### 1. Installation
WardGuard requires Python 3.10+ and lightweight mathematical/NLP packages. Core execution enforces zero network connectivity:

```bash
pip install -r requirements.txt
```

### 2. Run Privacy Firewall CLI
```bash
RAKSHA_SECRET=<secret> python main.py --input <input_dir> --output <empty_output_dir>
```

### 3. Release Structure
```
<output_dir>/
├── sanitized/      # Mirror of valid input files with PII sanitized, UTF-8 encoded
├── report.json     # Audit manifest with SHA-256 digests, status, honest counts, timings, RSS
└── records.jsonl   # Line-delimited JSON mapping (file, loc) → PSN-XXXXXX or null
```

### 4. Offline Interactive Demo UI (Judge Showcase)
Launch the light-theme offline web UI locally (requires zero internet access and leaves `requirements.txt` unchanged):

```bash
python demo_ui/server.py --port 8765
# Open http://127.0.0.1:8765 in any browser
```

### 5. Verification & Evaluation Tools
```bash
# Run unit, property, adversarial, and regression test suite (178 tests)
pytest -q

# Run pipeline validation and determinism checks
./tools/eval.sh

# Run simulated adversary attack suite (A1–A7)
python tools/attack_sim.py --release <output_dir> --attacker <attacker_dir>

# Run multi-seed synthetic torture correctness and attack arena
python -m tools.torture.check --seeds 1-20 --no-mr
python -m tools.torture.attacks --seeds 1-10 --patients 100

# Run submission compliance checker
python tools/check_submission.py --repo . --run
```

---

## Architecture & System Design

WardGuard operates as an in-memory, deterministic **3-Pass Pipeline** with fail-safe quarantine boundaries:

```
Pass 1: Ingestion & Detection       Pass 2: Global Linkage & Privacy       Pass 3: Rewrite & Export
┌───────────────────────────────┐   ┌───────────────────────────────┐   ┌───────────────────────────────┐
│ • Magic Sniffing & Decoding   │   │ • Cross-Script Name Blocking  │   │ • Right-to-Left Text Rewrite  │
│   (BOM, UTF-8, UTF-16, cp1252)│   │ • Union-Find on Strong Clues  │   │ • Cell & Numeric Value Shift  │
│ • Unit & RFC 6901 Pointer Map │──►│ • Strict Conflict Guard       │──►│ • Longitudinal Date Shift     │
│ • Hidden Channel Extraction   │   │ • HMAC-SHA256 Pseudonyms      │   │ • Cluster k-Anonymity Drop    │
│ • 3-Script Detector & Guards  │   │ • Non-Zero Date Offset (±15-90│   │ • Format-Preserving Writers   │
│ • Dynamic Gazetteer Harvest   │   │ • Cluster EQ Class Plan (k=5) │   │ • report.json & records.jsonl │
└───────────────────────────────┘   └───────────────────────────────┘   └───────────────────────────────┘
  ▲                                                                       │
  └── In-Memory State Only · Zero Network Imports · Counts-Only Stderr ───┘
```

### Component Breakdown & Security Design

| Component | Architecture & Mechanism |
|---|---|
| **Ingestion** | Sniffs file signatures (magic bytes, text heuristics); automatically decodes UTF-8, UTF-8-BOM, UTF-16, and cp1252. Tolerates dialect variations, ragged CSV rows, and deep JSON nesting. Quarantines unsupported binary or malformed files (PDF, JPEG, XML/CDA) with zero raw copy-through. |
| **Detection** | Multi-tiered detection stack combining Verhoeff-validated Aadhaar, ABHA, PAN, phones, and URL-safe MRNs, header-lexicon + value-profiling column classifiers (English, Devanagari, Hinglish, abbreviated snake_case), grammatical context rules (`S/o`, `W/o`, comma age-sex, honorifics), and dynamic dataset-harvested cross-script gazetteers. Medical guards protect doctors, dosages (`1-0-1`), vitals, and eponyms. |
| **Hidden Channels** | Extracts slots from file stems (`@filename`), column headers (`@header`), JSON keys (`@key`), metadata pointers, and base64 attachments, running full PII detection and collision-safe file renaming. |
| **Linkage** | Deterministic clustering blocking on canonical phonetic and transliterated keys; union-find over shared strong identifiers and corroborated name + context clues; strict conflict guards vetoing merges on DOB/gender/age disagreement. Weakly identified units remain `null`. |
| **Privacy Engine** | Keyed Crockford Base32 HMAC-SHA256 pseudonyms (`PSN-XXXXXX`); per-patient HMAC offsets in $[-90, -15] \cup [15, 90]$ preserving exact intervals and LOS; 20-year age bands (`60+` top-code); full DOB redaction (with FHIR `Patient.birthDate` removal); 1-digit PIN prefix; village removal; Devanagari-to-Latin district normalization (`normalize_district_key`) with cluster-level $k$-anonymity ($k_{\text{min}}=5$) coarsening. |
| **Security Design** | **Assume breach hardening:** raw and intermediate plaintext exist strictly in ephemeral process RAM (zero unmasked staging files on disk); `RAKSHA_SECRET` is read solely from environment memory and excluded from logs, reports, and outputs; stderr emits strictly structural event counts; unhandled exceptions sanitize messages into generic `safe_reason` tokens and fail closed into quarantine; `wardguard/` and `main.py` maintain zero socket/HTTP imports. |

---

## Models Used

**None.** WardGuard employs **zero LLMs, zero generative models, and zero pretrained neural transformers**. Detection, transliteration, linkage, and generalization run deterministically via regular expressions, Verhoeff checksums, phonetic normalization, fuzzy matching, and curated bilingual medical/gazetteer resources.

---

## Privacy–Utility Results

All metrics below are directly measured on the current `main` release:

### 1. Practice Kit (`Secret-Wards-ToolKit/dev`, 200 files)

| Metric | Target | WardGuard (Measured) | Status |
|---|---|---|---|
| **Output Contract Validation** | `CONTRACT OK` | **`CONTRACT OK`** (`check_submission.py`: **`READY TO SUBMIT`**) | Passed |
| **Direct IDs Leaked Overall** | Lower is better | **`0 / 3,230` (`0.0%`)** | Passed |
| **Script Breakdown (Latin / Deva / Hinglish)** | `< 5.0%` | **`0.0% / 0.0% / 0.0%`** | Passed |
| **Channel Breakdown (Content / Filename / B64 / Meta / Key / Header)** | `0.0%` | **`0.0%` across all 6 channels** | Passed |
| **Canaries Leaked / Raw Copies** | `0` / `0` | **`0 / 4` canaries** · **`0` raw copies** | Passed |
| **Clinical / Medical Values Kept** | `> 95.0%` | **`4,763 / 4,855` (`98.1%`; 100% of non-district clinical kept)** | Passed |
| **Patient Linking (Precision / Recall / $F_{0.5}$)** | `> 0.90` | **`1.00 / 0.95 / 0.99`** (`0` false merges) | Passed |
| **Runtime & Peak Memory (`dev/input`)** | `< 60 s` / `< 512 MB` | **`1.033 s`** · **`69.25 MB` RSS** | Passed |
| **Unit & Regression Test Suite (`pytest -q`)** | `100%` | **`178 / 178 passed`** (`11.27 s`) | Passed |

### 2. Adversary Attack Simulation (`tools/attack_sim.py` on `dev`)

| Attack Vector | Raw Input | WardGuard Released | Reference Threshold | Result |
|---|---:|---:|---:|---|
| **A1 Direct ID Leak** | `100.0%` | **`0.0%`** | `= 0.0%` | **SAFE** |
| **A3 Record Linkage Risk** | `92.4%` | **`3.1%`** | `< 27.7%` | **SAFE** |
| **A4 Profile Pooling ($\ge 0.5$ conf.)** | `88.6%` | **`0.0%`** | `< 16.7%` | **SAFE (Zero)** |
| **A5 Targeted Known Facts** | `90.0%` | **`28.5%`** | `< 40.1%` | **SAFE** |
| **A6 Pseudonym Inversion** | `N/A` | **`0.0%`** (`0/88`) | `= 0.0%` | **SAFE** |
| **A5 Global-Shift Recovery** | Recoverable | **Unrecoverable** | Unrecoverable | **SECURE** |

### 3. Unseen Synthetic Torture Arena (`tools/torture`)

- **`tools.torture.check` (20 seeds, 15,809 entities):** **`0 / 15,809` (`0.0%`) leaks**, **`0` critical leaks**, **`100.0%` clinical kept**, **`link P 1.00 / R 0.994 / F0.5 0.999`**, `0` `S0`/`S1`/`S2` failures (`619` expected `S3:district_coarsened`).
- **`tools.torture.attacks` (10 seeds × 100 patients = 1,000 patients):** **`A1 0.0%`**, **`A3 0.23%`** (raw `20.0%`), **`A4 0.50%`** (raw `19.44%`), **`A5 35.12%`** (raw `35.44%`), **`A6 0` inversions**, **`A7 0` shared PSNs / `0.0%` date collision**, **`0` global shift recoveries**.

---

## Known Limitations

1. **Binary Attachments & Unstructured Formats:** Non-text binaries (PDF, JPEG, HL7 CDA XML) are fail-closed quarantined cleanly rather than partially redacted (`D-008`).
2. **Targeted Condition Floor (`A5`):** Preserving clinical conditions (`Type 2 diabetes`, `pulmonary tuberculosis`) alongside clean institutional metadata creates an irreducible prevalence floor in small cohorts when clinical utility is strictly preserved.
3. **Single-Token Exotic Names Without Context:** Isolated surname-free single tokens absent from corpus headers and gazetteers may remain unflagged if no surrounding demographic or relative pattern appears.

---

## Repository Layout

```
.
├── main.py                     # CLI entrypoint (--input / --output)
├── raksha.toml                 # Evaluation contract manifest
├── requirements.txt            # Minimal CPU-only dependencies (zero LLMs)
├── config/policy.yaml          # Tunable privacy parameters
├── demo_ui/                    # 100% offline light-theme judge showcase UI (stdlib http.server + HTML/CSS/JS)
├── wardguard/                  # Core 3-pass firewall (ingest, detect, link, privacy, rewrite, export, safety)
├── resources/                  # English/Hindi/Hinglish lexicons, medical terms, and UP districts
├── tests/                      # 178 unit, integration, adversarial, and regression tests
├── tools/                      # Attack simulator, eval harness, brief builder, torture generator/checker
└── docs/                       # Two-page Project Brief (brief.md -> brief.pdf)
```
