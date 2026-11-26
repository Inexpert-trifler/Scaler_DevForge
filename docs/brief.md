<div class="header-box">
  <h1>WardGuard: Multilingual Privacy Firewall for Hospital Records</h1>
  <div class="header-meta">
    <span><strong>Track:</strong> Track 3 "Secret Wards", Yugaantar DevForge</span>
    <span><strong>Team:</strong> WardGuard (<code>team-wardguard</code>)</span>
    <span><strong>Architecture:</strong> Offline &middot; CPU-Only &middot; Zero-LLM</span>
  </div>
</div>

## 1. Executive Summary & Core Mission
WardGuard is a deterministic, offline privacy firewall that transforms heterogeneous multi-hospital dumps (CSV, TSV, JSON, FHIR R4 Bundles, and clinical notes in English, Hindi, and Hinglish) into **de-identified, research-ready releases**. Built for compliance with India's **DPDP Act 2023** and **ABDM** guidelines, WardGuard removes **100% of direct and hidden identifiers** across text, headers, keys, filenames, and base64 payloads while preserving longitudinal clinical integrity with zero LLMs, external APIs, or pretrained transformers.

## 2. Deterministic 3-Pass Architecture
WardGuard operates strictly in-memory with fail-closed quarantine boundaries across three deterministic passes:

```
[PASS 1: Ingest & Detect]       -->  [PASS 2: Linkage & Privacy]      -->  [PASS 3: Rewrite & Export]
• Sniff UTF-8/16/cp1252 & BOM        • Cross-script phonetic blocking       • Right-to-left mention rewrite
• RFC 6901 JSON/FHIR units           • Conflict-guarded union-find          • Numeric-safe JSON/CSV serializers
• Hidden channels (@key, b64)        • Crockford HMAC-SHA256 PSN            • Shift dates (±15..90d), LOS exact
• Verhoeff + context + guards        • Date offset in [-90,-15]U[15,90]     • Redact DOB & FHIR birthDate
• Dynamic multi-script gazetteer     • Cluster k-anon planning (k_min=5)    • report.json & records.jsonl
```

- **Pass 1 (Ingestion, Hidden Channels & Detection):** Sniffs file bytes, flags broken/binary files into quarantine, extracts hidden slots (`@filename`, `@header`, `@key`, decoded base64), validates Verhoeff Aadhaar/ABHA/PAN/MRNs, applies English/Devanagari/Hinglish lexicons with clinical meaning guards, and harvests dynamic dataset gazetteers.
- **Pass 2 (Cross-Script Linkage & Privacy Planning):** Clusters encounters across hospitals/scripts using canonical transliteration and conflict-guarded union-find, issues secret-keyed Crockford Base32 HMAC-SHA256 pseudonyms, computes bounded per-patient date shifts, and plans cluster-level $k$-anonymity ($k=5$) with normalized UP districts (`normalize_district_key`).
- **Pass 3 (Rewrite & Export):** Rewrites mentions right-to-left, omits FHIR `Patient.birthDate`, applies 20-year age bands (`60+` top-code), and emits UTF-8 `sanitized/`, `report.json`, and `records.jsonl`. An offline localhost demo UI (`demo_ui/`) is included separately for live inspection.

## 3. Core Technical Innovations

<div class="grid-2">
<div>
<h3>A. Verhoeff IDs, Multilingual Headers &amp; Meaning Guards</h3>
Combines dihedral-group Verhoeff checks for Aadhaar with context-aware regexes covering Devanagari, Hinglish, and snake_case variants (`जिला`, `तहसील`, `distt`, `tahsil`, `birth_dt`). Protected medical guards prevent redacting doctors, medications, doses (`1-0-1`), vitals (`BP 150/90`), or disease eponyms (`Parkinson's`).
<h3>B. Bounded Interval-Preserving Date Shifting</h3>
Each linked cluster receives a secret HMAC-SHA256 offset $\Delta \in [-90, -15] \cup [15, 90]$. Minimum magnitude $|\Delta| \ge 15\text{ d}$ blocks $\pm 3\text{ d}$ true-date target hits, preserves exact stay intervals (9-day stay remains 9 days), preserves seasonal context, and makes global-shift recovery unrecoverable (`0` recovered).
</div>
<div>
<h3>C. Conflict-Guarded Cross-Script Linkage</h3>
Folds Devanagari, transliterated Latin, and honorific variations into phonetic blocking keys paired with union-find over phone/MRN/Aadhaar/name+relative clues. A strict conflict guard vetoes false merges on age/DOB/gender mismatches (`0` homonym merges).
<h3>D. Cluster k-Anonymity, 20-Year Bands &amp; DOB Redaction</h3>
Normalizes Hindi/Latin districts into unified cluster equivalence keys `(age_band, gender, district, diagnosis)`. Rare clusters ($k < 5$) coerce 30-year bands and suppress structured districts. Redacting exact DOBs (`Patient.birthDate` removed), 1-digit PIN prefixes, and `60+` top-coding collapses voter-list re-identification.
</div>
</div>

<div class="page-break"></div>

## 4. Empirical Privacy &amp; Attack Simulation (`dev` + Unseen Torture Suite)
Measured against `Secret-Wards-ToolKit/dev` (`tools/attack_sim.py` &amp; `check_dev.py`) and 10–20 seeds of unseen chaos benchmarks (`tools/torture` at commit `0132510`):

| Attack Vector (`dev`, 200 files) | Vulnerability Description | Raw Input | WardGuard | Ref Threshold | Outcome |
|---|---|---:|---:|---:|---|
| **A1: Direct ID Leak** | Plaintext name, phone, Aadhaar, ABHA, MRN, email | 100.0% | **0.0%** | = 0.0% | **SAFE (Zero Leak)** |
| **A3: Record Linkage** | Voter-roll quasi-identifier linkage across records | 92.4% | **3.1%** | &lt; 27.7% | **SAFE (A2 max 5.3%)** |
| **A4: Profile Pooling** | Re-identification pooled by `PSN` ($\ge 0.5$ conf.) | 88.6% | **0.0%** | &lt; 16.7% | **SAFE (Zero)** |
| **A5: Targeted Known Facts** | Condition + hospital + visit date window | 90.0% | **28.5%** | &lt; 40.1% | **SAFE** |
| **A6: Pseudonym Inversion** | Hash/base64 reversal of 88 issued PSNs | N/A | **0.0%** | = 0.0% | **SAFE (0 / 88)** |
| **A5: Global-Shift Recovery** | Un-shifting release dates by consensus delta | Recovered | **SECURE** | Unrecoverable | **Defeated** |

| Privacy–Utility Benchmark Suite | Measured Scope | Direct Leaks &amp; Canaries | Clinical Utility &amp; Linkage Quality |
|---|---|---|---|
| **Practice Self-Check (`check_dev.py`)** | 200 files · 3,230 PII items | **0 / 3,230 (0.0%)** · **0 / 4 canaries** · 0 raw copies | **4,763 / 4,855 (98.1%)**; 100% non-district clinical kept · **P 1.00 / R 0.95 / F0.5 0.99** |
| **Torture Correctness (20 unseen seeds)** | 15,809 multilingual entities | **0 / 15,809 (0.0%)** · 0 critical failures | **100.0% clinical kept** · **P 1.00 / R 0.994 / F0.5 0.999** · 0 S0/S1/S2 fails |
| **Torture Attack Arena (10 seeds)** | 1,000 synthetic patients | **A1 0.0% · A6 0 · A7 0.0% · G-shift 0** | **A3 0.23%** (raw 20.0%) · **A4 0.50%** (raw 19.44%) · **A5 35.12%** |

## 5. Privacy–Utility Trade-Off &amp; Resource Envelope
- **Trade-Off Analysis:** Redacting DOB (`birthDate` omitted), shifting dates in $\pm 15\text{–}90\text{ d}$, grouping ages into 20-year strata with `60+` top-coding, keeping 1-digit PINs (`2*****`), and coarsening structured `district` on rare $k &lt; 5$ clusters lowered `dev` linkage risk (`A3` `13.7%` $\rightarrow$ `3.1%`, worst-case `A2` `25.0%` $\rightarrow$ `5.3%`, `A4` `6.7%` $\rightarrow$ `0.0%`, `A5` `31.8%` $\rightarrow$ `28.5%`) while preserving **100%** of medicines, doses, labs, vitals, diagnoses, and exact hospital stay durations.
- **CPU Performance &amp; Footprint:** Processes the entire 200-file `dev` benchmark in **1.033 s** at **69.25 MB peak RSS** (`requirements.txt` contains strictly lightweight CPU packages; **178 / 178** tests in `pytest -q` pass in **11.27 s**).

## 6. Security Design (Assume-Breach Hardening)
- **Zero Plaintext Disk Staging:** Processing occurs completely in volatile process memory (`report.json` hashes input digests without filenames or PII).
- **Strict Secret Isolation &amp; Keyed Pseudonyms:** `RAKSHA_SECRET` arrives purely via environment memory, powers HMAC-SHA256 Crockford pseudonyms and date offsets, and is verified absent from outputs, `report.json`, logs, and stderr (`check_submission.py`: **READY TO SUBMIT**).
- **Counts-Only Logging &amp; Fail-Closed Quarantine:** Stderr emits strictly numeric `[EVENT]` counters; unexpected parsing failures sanitize exceptions to generic `safe_reason` tokens and route unprocessable files into quarantine without partial raw copies.
- **Zero Network Footprint:** Automated static checks verify zero imports of `requests`, `urllib`, `http`, or `socket` across `main.py` and `wardguard/`.

## 7. Known Limitations
1. **Unsupported Binary Files:** PDFs, images, and XML/CDA files are fail-closed quarantined rather than OCR-redacted (`D-008`).
2. **A5 Diagnosis Prevalence Floor:** When clinical diagnoses (`diabetes`, `TB`) and hospital census metadata are faithfully preserved, small cohorts retain an inherent prevalence lower bound (`~28–35%` under targeted known-facts matching).
3. **Unseen Single-Token Names Without Context:** Isolated surname-free single tokens lacking nearby demographic or kinship cues rely on corpus-level cross-file harvesting to achieve recall.
