# 02 · Product Context

> Read this first if you (human or AI) are new to the project. It explains the world the product lives in.

## 1. The event

- **Hackathon:** Yugaantar DevForge (Scaler), 24 hours, 4 tracks. We chose **Track 3: "Secret Wards"**.
- **Submission:** a public GitHub repo (created during the hackathon) + a **2-page Project Brief PDF**. Only the last commit before the deadline counts.
- **Judging funnel:**
  1. **Stage 1:** automated scoring on 3 hidden datasets. The top 10 per track advance.
  2. **Stage 2:** desk review + live demo + technical questions. The top 2 advance.
  3. **Round 3:** finals in front of the judging panel.
- **Domain:** privacy engineering, multilingual information extraction, record linkage, data security.

## 2. The official sources (ground truth for every decision)

| Source | Where | Use it for |
|---|---|---|
| Problem statement PDF | `Yugaantar DevForge Tracks (2).pdf` (Track 3 section) | The official rules |
| Team Kit repo | https://github.com/Reinforce-SST/Secret-Wards-ToolKit, cloned **next to** our repo as `../Secret-Wards-ToolKit` | Data, checkers, docs |
| `START_HERE.md` | kit root | Plain-language overview |
| `docs/SPEC.md` | kit | **Exact output contract** (the most important doc) |
| `docs/SCORING.md` + `scoring.toml` | kit | Every formula and weight |
| `docs/ATTACKS.md` | kit | How the attacker works (A1–A7) |
| `docs/DATASET.md` | kit | Data layout, traps, linkability rule, canaries |
| `docs/SANDBOX.md`, `docs/FAQ.md` | kit | Runtime environment and quick answers |
| `dev/input/` | kit | 200 practice files (48 patients) |
| `dev/truth/truth.json` | kit | Practice answer key (**never** available on event day) |
| `dev/attacker/` | kit | `registry.csv`, `known_facts.jsonl` for our attack simulator |
| `validate_output.py`, `check_dev.py`, `check_submission.py` | kit | Our three gates |

If these docs and the kit ever disagree, **the kit and the PDF win**. Log the conflict in `tracking/DECISIONS.md`.

## 3. Hard constraints (breaking any = penalty or disqualification)

1. **No LLMs or generative models** (hosted, local or distilled). No pretrained transformer above 50M parameters. Declare any model in the README.
2. **Offline at run time.** Any network call during `run` is blocked and flagged, and can disqualify you. Install everything in `setup`.
3. **Hardware:** Linux, **2 CPUs, 4 GB RAM (whole process tree), 15-minute limit**, no GPU.
4. **Synthetic data only.** Never use real patient data.
5. **No hardcoding.** Hidden data has new patients, and at least one dataset has unseen names, labels and formats.
6. **Zero leaks.** Canary PII is planted; finding one anywhere (output, logs, temp files, errors, report) costs −3 each.
7. **Fail safe.** Never silently skip a file, never export a raw file as "cleaned", never exit 0 with missing outputs.
8. **Reproducible.** Same input + same `RAKSHA_SECRET` → byte-identical output. A different secret → different pseudonyms and date shifts.
9. **Original work.** The core pipeline, linkage and privacy layer are built during the event. The kit's `starter/` may be copied as a base.

## 4. Scoring at a glance (100 points + penalties)

| Category | Pts | Key formula detail |
|---|---:|---|
| Privacy vs attacks | 25 | `(1 − risk) × min(1, utility/0.40)`, so over-redaction also kills privacy points |
| PII detection | 20 | **F2** (recall-heavy); recall is macro-averaged **per type and per script** |
| Clinical utility | 20 | probes 35%, temporal 20%, generalization 10%, statistics 15%, token retention 10%, record retention 10% |
| Identity consistency | 15 | **F0.5** (precision-heavy) + B³ + language/fragmented/homonym traps |
| Output validity | 10 | format, schema, FHIR, pseudonym-in-record, side channels, quarantine, honest report |
| Speed and reliability | 10 | exit code, time (good < 60 s), memory (good < 512 MB), determinism, scaling |

**Penalties:**

| Event | Points |
|---|---:|
| Each direct ID or full name leaked | −1 (cap −25) |
| Each canary leaked | −3 (cap −15) |
| Each raw broken file copied | −5 (cap −20) |
| False success (exit 0 with missing report or dropped files) | −10 |
| Input modified | −5 |

**Calibration** (from the kit):

| Submission | Normal data | Unseen-format data |
|---|---:|---:|
| Reference | ~80–85 | ~48–50 |
| Redact-all | ~22 | ~22 |
| Naive regex | ~4 | ~4 |
| Passthrough | ~−19 | ~−19 |

## 5. What makes this hard (the six traps)

1. **Language trap:** one person written in Latin, Devanagari and Hinglish, sometimes with no ID.
2. **Meaning trap:** "C/O Ramesh" (care of) vs "C/O fever" (complaint of); "Dr. Ramesh" stays; "1-0-1" and "Dolo 650" are doses; "Parkinson's" is not a person.
3. **Fragmented identity:** a note that says only "Meera, W/o Rajan" plus a date.
4. **Re-identification:** a very old patient, a tiny village, a rare disease, exact dates.
5. **Clinical integrity:** a 9-day stay must stay 9 days; age bands must contain the true age.
6. **Hidden leakage:** JSON keys, CSV headers, file names, metadata, base64 attachments, `\u` escapes.

## 6. Our positioning (USP)

1. **Cross-script dynamic gazetteer.** Names are harvested from this dataset's own structured fields and transliterated, not taken from a fixed list. This is how we catch the same person in three scripts, and canaries through context.
2. **Value-profiling column classifier.** It survives renamed columns in the unseen-format round.
3. **Evidence-gated, conflict-guarded linkage.** We link only when the evidence is unique; homonyms are never merged.
4. **Risk-targeted privacy.** Only the rare records are coarsened, measured with our own attacker simulator.
5. **Assume-breach design.** Zero temp files, counts-only logs, PII-free exceptions, HMAC everywhere.

## 7. Team

| Person | Role |
|---|---|
| **Lakshya** | Platform + Privacy lead: ingestion, export, hidden channels, pseudonyms and dates, k-anonymity, attack simulator, safety, release, README/brief |
| **Saransh** | Intelligence lead: PII detection (patterns, columns, context, names, transliteration, guards), linkage, resources, chaos generator, trap tests |

Details: `team/WORKFLOW.md`, `team/LAKSHYA.md`, `team/SARANSH.md`.

## 8. Note on AI assistants

We use Gemini as a **coding assistant** (see `00_MASTER_PROMPT.md` and `09_AI_VIBE_CODING_RULES.md`). The "No LLMs" rule applies to the **submitted system at run time**. AI-assisted coding during the build is a separate question. If in doubt, confirm with the organizers and record the answer in `tracking/DECISIONS.md`.
