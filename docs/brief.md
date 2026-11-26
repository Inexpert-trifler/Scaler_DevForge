<div class="header-box">
  <h1>WardGuard: Multilingual Privacy Firewall for Hospital Records</h1>
  <div class="header-meta">
    <span><strong>Track:</strong> Track 3 "Secret Wards", Yugaantar DevForge</span>
    <span><strong>Team:</strong> WardGuard (Lakshya & Saransh)</span>
    <span><strong>Architecture:</strong> Offline · CPU-Only · Zero-LLM</span>
  </div>
</div>

## 1. Executive Summary & Core Mission
WardGuard is a deterministic, offline privacy firewall engineered to process heterogeneous, multilingual clinical data dumps (CSV, TSV, JSON, FHIR R4 Bundles, and unstructured notes in English, Hindi, and Hinglish) into **privacy-preserving, research-ready releases**. Built for compliance with India's **Digital Personal Data Protection (DPDP) Act 2023** and **Ayushman Bharat Digital Mission (ABDM)** standards, WardGuard eliminates 100% of direct and hidden personal identifiers while preserving complete longitudinal clinical utility without relying on external network calls, pretrained transformers, or generative LLMs.

## 2. Deterministic 3-Pass Architecture
WardGuard operates in-memory with strict stream-level fail-safe quarantine boundaries:

```
[PASS 1: Ingest & Detect]       ──►  [PASS 2: Linkage & Privacy]      ──►  [PASS 3: Rewrite & Export]
• Magic sniff (UTF-8,16,cp1252)       • Phonetic & script blocking          • Right-to-left mention rewrite
• RFC 6901 pointers, CSV units        • Conflict-guarded union-find         • Intact JSON types & CSV cells
• Hidden channels (b64, keys)         • Crockford HMAC-SHA256 PSN           • Interval-preserving date shift
• Multi-script patterns & guards      • Non-zero per-patient date offsets   • Format-preserving serializers
• Dynamic gazetteer harvesting        • Targeted k-anonymity planning       • report.json & records.jsonl
```

- **Pass 1 (Ingestion, Hidden Channels & Detection):** Heuristically sniffs encoding signatures and dialect variations. Extracts hidden channels from filenames (`@filename`), headers (`@header`), JSON object keys (`@key`), and base64 attachments. Scans content using Indian ID checksum patterns (Verhoeff), grammatical context rules, and dynamic cross-script gazetteer harvesting.
- **Pass 2 (Identity Linkage & Privacy Planning):** Solves patient identity across multi-hospital encounters using candidate blocking, transliteration, and union-find on strong identifiers gated by strict conflict guards. Computes keyed Crockford Base32 HMAC-SHA256 pseudonyms, non-zero longitudinal date offsets, and equivalence class coarsening.
- **Pass 3 (Rewrite & Format-Preserving Export):** Applies mentions right-to-left per slot to prevent offset drift; replaces whole cells in classified columns; preserves numeric types in JSON; executes interval-preserving date shifts; and emits sanitized mirrors alongside RFC-compliant `report.json` and `records.jsonl`.

## 3. Novel Technical Approaches

<div class="grid-2">
<div>
<h3>A. Verhoeff-Checked IDs & Meaning Guards</h3>
Employs exact mathematical Verhoeff dihedral group validation for 12-digit Aadhaar numbers, strict shape regexes for ABHA, PAN, phones, and MRNs. Protected medical context guards prevent false-positive scrubbing of medications, doses (e.g., <code>650mg</code>, <code>1-0-1</code>), vitals (<code>BP 150/90</code>), and medical eponyms (e.g., <em>Parkinson's</em>, <em>Crohn's</em>).

<h3>B. Dynamic Cross-Script Gazetteer</h3>
Two-stage harvesting extracts patient and relative names from structured column classifiers, generates Latin $\leftrightarrow$ Devanagari transliteration variants with spelling normalization, and applies high-speed token lookups to catch untagged names in unstructured Hindi and Hinglish doctor notes.
</div>
<div>
<h3>C. Interval-Preserving Date Shifting</h3>
Each patient receives a secret, non-zero HMAC-SHA256 date offset: $\Delta = (\text{HMAC}(K, \text{PSN}) \pmod{60}) - 30$. Offsets preserve longitudinal clinical intervals (e.g., a 9-day hospital stay remains exactly 9 days) while defeating attacker global-shift recovery attacks.

<h3>D. Targeted k-Anonymity Coarsening</h3>
Partitions patient records into equivalence classes over quasi-identifiers ($\text{age\_band}, \text{gender}, \text{district}, \text{diagnosis}$). For rare cohorts ($|E| < k_{\text{min}}=5$), targeted coarsening expands age bands to 10 years and suppresses village/tehsil/district, maximizing utility on common records.
</div>
</div>

<div class="page-break"></div>

## 4. Empirical Evaluation & Attack Simulation (TR-TOOL-2)
WardGuard's privacy guarantees were evaluated against the official adversary model (`docs/ATTACKS.md`) simulating a registry-assisted attacker with access to 4–5× population databases, leaked partial identifiers, and known facts:

| Attack Vector | Vulnerability Description | Raw Input | Sanitized Release | Reference Threshold | Adversary Outcome |
|---|---|---|---|---|---|
| **A1: Direct ID Leak** | Plaintext Aadhaar, ABHA, phone, email, PAN | 100.0% | **0.0%** | 0.0% (Zero leak) | **Neutralized** |
| **A3: Record Linkage** | Re-identification via quasi-identifiers (QI) | 92.4% | **4.3%** | < 27.7% | **Defeated** |
| **A4: Profile Pooling** | Longitudinal linkage exploiting pseudonym | 88.6% | **4.3%** | < 16.7% | **Defeated** |
| **A5: Targeted Known Facts** | Diagnosis + stay duration + visit window | 90.0% | **25.0%** | < 40.1% | **Defeated** |
| **A5: Global-Shift Recovery** | Attacker recovers date delta across records | Recovered (100%) | **FAILED (0.0%)** | Failed | **Defeated** |

*Outcome: All empirical re-identification risk metrics fall well below reference safety thresholds; global date recovery completely fails due to per-patient HMAC divergence.*

## 5. Core Privacy & Utility Verification

| Evaluation Dimension | Starter Baseline | Hackathon Target | WardGuard Measured | Status |
|---|---|---|---|---|
| **Contract Validation** | Pass | Pass | **CONTRACT OK** | Passed |
| **Direct Identifier Leak Rate** | 84.1% (2,718 / 3,230) | < 3.0% | **0.0% (0 / 3,230)** | Passed |
| **Script Leak (Latin / Deva / Hinglish)** | 82.8% / 100% / 100% | < 5.0% each | **0.0% / 0.0% / 0.0%** | Passed |
| **Canary Leakage (Hidden & Narrative)** | 4 / 4 Leaked | 0 / 4 | **0 / 4 (100% Caught)** | Passed |
| **Clinical Value Preservation** | 100.0% (4,855 / 4,855) | > 95.0% | **100.0% (4,855 / 4,855)** | Passed |
| **Linkage Precision / Recall / $F_{0.5}$** | 0.00 / 0.00 / 0.00 | > 0.90 | **1.00 / 0.94 / 0.98** | Passed |
| **Homonym Merges (Cross-Identity)** | 0 | 0 | **0 (Zero False Unions)** | Passed |
| **Adversarial Chaos Generalization ($\Delta$)** | N/A | < 10.0 | **< 2.5 Score Delta** | Passed |

## 6. Engineering Rigor, Resource Envelope & Safety
- **Zero Network Footprint (TR-SEC-1):** Zero calls to `requests`, `urllib`, `http`, or `socket`. Audited by automated static AST analysis.
- **High Throughput, Low Footprint (TR-RUN-6):** Process startup time is **0.102 s**; dev run executes in **0.021 s**; 10× bulk stress dataset (60 files, >1,000 records) completes in **1.81 s** with peak RSS of **35.4 MB** (against 512 MB ceiling).
- **Byte-Identical Determinism (TR-SEC-4):** Two consecutive executions with identical `RAKSHA_SECRET` yield 100% byte-identical release mirrors and `records.jsonl`. Executions with rotated secrets produce completely decoupled pseudonyms and date shifts.
- **Fail-Safe Quarantine Isolation:** Malformed, deeply nested, or unparseable inputs are intercepted by safe exception handlers and routed to generic quarantine manifests; stderr logs strictly event counts with zero patient data.

## 7. Compliance Framework & Limitations
- **DPDP Act 2023 & ABDM:** Establishes rigorous de-identification safeguards for research processing, eliminating personal data identifiers while maintaining auditing integrity.
- **Known Scope Limitations:** Unsupported non-text binaries (PDF, JPG, HL7 CDA XML) are isolated into quarantine per Architectural Decision **D-008**. $k$-anonymity guarantees apply specifically to the configured quasi-identifier set.
