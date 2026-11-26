# 05 · User Flows

WardGuard has no GUI. Its "users" interact through the command line and the output folder.

## Flow 1: Evaluator runs a submission (the flow that is graded)

```
Organizer machine (Linux, 2 CPU, 4 GB, NO network)
 │
 ├─ 1. git clone <our public repo> at the deadline commit
 ├─ 2. setup:  pip install -r requirements.txt        (network allowed, 30 min)
 ├─ 3. run:    RAKSHA_SECRET=<s1> python main.py --input /data/ds1 --output /out/ds1
 │        └─ WardGuard: load → detect → link → privacy → rewrite → export → exit 0
 ├─ 4. run again with the same secret   → output must be byte-identical (determinism)
 ├─ 5. run again with a different secret → PSNs and date shifts must change (A7)
 ├─ 6. scan everything: sanitized/, report.json, records.jsonl, logs/, stdout/stderr, TMPDIR, HOME
 ├─ 7. score: detection, utility, linkage, validity, speed
 └─ 8. attacker A1–A7 on sanitized/ with the hidden registry + known facts → privacy score
     (repeated for 3 hidden datasets; one has unseen formats)
```

## Flow 2: Inside one run (system flow)

```
main.py
 ├─ read args + RAKSHA_SECRET + config/policy.yaml
 ├─ PASS 1  for each file (sorted):
 │     sniff → supported?  ── no ──► mark QUARANTINED (generic reason) ─┐
 │         │ yes                                                        │
 │     decode → parse → enumerate units → extract hidden slots          │
 │     parse error? ──────────────────────────► QUARANTINED ───────────┤
 ├─ build gazetteer (names from structured name columns + variants)     │
 ├─ detect every slot of every unit (mentions + evidence)               │
 ├─ PASS 2  link.resolve → clusters; privacy.assign → PSN + date offset │
 │          kanon.plan → coarsen flags for rare records                 │
 ├─ PASS 3  for each sanitizable file: render → write sanitized/ (UTF-8)│
 │          render error? ──────────────────► QUARANTINED ─────────────┤
 ├─ write records.jsonl (only for files actually written)               │
 ├─ write report.json (every input by SHA-256, honest counts) ◄─────────┘
 └─ exit 0  (non-zero only on fatal failure; never "false success")
```

## Flow 3: Per-file decision (what happens to a file)

| File situation | Action | report status |
|---|---|---|
| Valid CSV/TSV/JSON/FHIR/text | Sanitize, same path | `sanitized` |
| File name contains PII | Sanitize + rename, record new path | `sanitized` |
| JSON behind a `.csv` extension | Parse as JSON, keep `.csv` path | `sanitized` |
| Empty file (0 bytes) | Write an empty file or quarantine (decision D-011) | `sanitized` / `quarantined` |
| PDF / JPG / XML / binary | Don't copy | `quarantined` (`unsupported_format`) |
| Truncated JSON / invalid bytes | Don't copy | `quarantined` (`malformed`) |
| Crash while processing | Don't copy | `quarantined` (`processing_error`) |
| Clean doc (`clean/`), no PII | Pass through the detector; should come out ~unchanged | `sanitized` |

## Flow 4: Developer loop (Lakshya and Saransh, every change)

```
pick a task from tracking/AI_TASK_STATES.md (state → IN_PROGRESS)
   ↓
git pull --rebase origin main ; git checkout -b <name>/<TASK-ID>-short
   ↓
code (with Gemini + master prompt) in YOUR files only
   ↓
pytest -q                       (unit tests green)
tools/eval.sh                   (CONTRACT OK + check_dev numbers)
   ↓  numbers same or better?  ── no ──► fix or discuss
   ↓ yes
update tracking: AI_TASK_STATES, BUILD_LOG, CHANGELOG (+ DECISIONS / KNOWN_ISSUES if needed)
   ↓
git commit -m "[TASK-ID] module: what changed" ; push ; merge to main (see team/WORKFLOW.md)
   ↓
tell your partner in chat: "merged S-03, columns classifier, recall latin 0.93"
```

## Flow 5: Research consumer (why utility matters)

The researcher opens `sanitized/` and must still be able to:
- read every prescription (drug + dose + frequency) exactly;
- follow one patient (PSN) across registration → OPD → discharge → labs;
- compute length of stay, diagnosis distribution and lab medians;
- know the age band, gender and district, but never the name, village or exact dates.

## Flow 6: Attacker (what we defend against)

```
registry.csv (whole population) + leaked contacts + known_facts.jsonl
      ↓ read the release: ages, bands, district, village, PIN, names, phones, dates, rare diagnoses
A1 direct identifier left?  → found
A2/A3 filter registry by evidence → probability on the true person
A4 pool records with the same PSN / reference → attack again
A5 known visit date / rare disease / length of stay → match profile; recover a GLOBAL shift if any
A6 is the PSN a plain hash of the UHID/phone?  A7 is the PSN the same under another secret?
```
Defences: removal (A1), generalization + k-anonymity (A2–A4), per-patient shifts + rare-record coarsening (A5), HMAC with the per-release secret (A6, A7).
