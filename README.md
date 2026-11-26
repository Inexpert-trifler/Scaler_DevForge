# WardGuard: a multilingual privacy firewall for hospital records

> Yugaantar DevForge · Track 3 "Secret Wards" · Team: Lakshya & Saransh
> Status: 🚧 in development. Sections marked _TBD_ are filled in with measured numbers before submission.

WardGuard is an **offline, CPU-only, LLM-free** pipeline that turns a messy multi-hospital records dump (CSV, TSV, JSON, FHIR R4 and text notes in English, Hindi and Hinglish) into a **de-identified research release**. It:

- removes every personal identifier: names, relatives, Aadhaar, ABHA, UHID/MRN, PAN, phones, addresses, DOB, including those hidden in JSON keys, CSV headers, file names, metadata and base64 attachments;
- keeps every medical value exact: medicines, doses, frequencies, vitals, labs, diagnoses, and the length of stay;
- gives each real patient **one stable pseudonym** across files, scripts and hospitals, and never merges different people;
- resists **re-identification** with per-patient date shifting, truthful age bands, location generalization and targeted k-anonymity.

## Quick start

```bash
pip install -r requirements.txt
RAKSHA_SECRET=<secret> python main.py --input <input_dir> --output <empty_output_dir>
```

The output (`<output_dir>/`) contains:
```
sanitized/      cleaned mirror of the input (same paths and formats, UTF-8)
report.json     every input file by SHA-256, status, honest counts, timing, memory
records.jsonl   record → pseudonym (PSN-XXXXXX) or null
```

Run configuration for the evaluator is in `raksha.toml`. Privacy knobs are in `config/policy.yaml`.

## Architecture

```
PASS 1 per file            PASS 2 global                 PASS 3 per file
ingest → units/slots  ──►  link (identity clusters)  ──► rewrite (tokens, PSN, shifted dates,
hidden channels            pseudonyms + date offsets     bands, PIN prefix, tehsil)
detect (3 scripts)         k-anonymity plan              export sanitized/ + report + records
        all in memory · counts-only logging · deterministic · per-file fail-safe quarantine
```

| Component | How it works |
|---|---|
| Ingestion | Content-based format sniffing; UTF-8 / BOM / UTF-16 / cp1252 decoding; robust CSV/JSON/FHIR/text readers; unsupported or broken files quarantined, never copied |
| Detection | Indian ID patterns (Verhoeff-checked Aadhaar, ABHA, PAN, phones, MRNs); header-lexicon + value-profiling column classifier; context rules (labels, S/o-W/o-D/o-C/O, honorifics); dataset-harvested cross-script gazetteer with transliteration; medical guards for doctors, doses, vitals, eponyms |
| Linkage | Union-find on strong identifiers; name + unique second clue; conflict guard against homonym merges; unsure → `null` |
| Privacy | HMAC-SHA256 pseudonyms keyed by `RAKSHA_SECRET`; per-patient secret date offsets (intervals preserved); 5-year age bands; PIN → 3 digits; village → tehsil; coarsening of rare records only |
| Security | No intermediate data on disk; secret never written; logs contain counts only; exceptions reduced to type names; input opened read-only |

## Models used
None. WardGuard uses rules, lexicons, transliteration and fuzzy/phonetic matching only. No LLMs, generative models or pretrained transformers.

## Privacy–utility results
_TBD: measured leak rate (overall and per script), clinical values kept, linkage precision/recall/F0.5, re-identification risk from our attack simulator, runtime and memory._

## Known limitations
_TBD._ PDF, image and XML files are quarantined rather than sanitized.

## Repository layout
```
main.py · raksha.toml · requirements.txt · config/policy.yaml
wardguard/   ingest/ detect/ link/ privacy/ export/ safety/ pipeline.py rewrite.py model.py
resources/   generic multilingual lexicons (no real or practice-data personal data)
tools/       eval.sh, attack_sim.py, chaos_gen.py (development only)
tests/       unit and end-to-end tests
docs/        brief.pdf (2-page project brief)
```
