# Team Workflow: Lakshya + Saransh

## 1. The split (why it works)

| | **Lakshya: Platform + Privacy** | **Saransh: Intelligence** |
|---|---|---|
| Question answered | "How does data get in and out safely, and how is it anonymized?" | "Where is the PII, and who is this patient?" |
| Modules | `main.py`, `pipeline.py`, `rewrite.py`, `ingest/`, `export/`, `safety/`, `privacy/`, `detect/hidden.py` | `detect/` (all except `hidden.py`), `link/`, `resources/` |
| Tools | `tools/eval.sh`, `tools/attack_sim.py` | `tools/chaos_gen.py` |
| Tests | ingest, dates, privacy, export, e2e | patterns, columns, context, names, guards, link |
| Docs | README, brief, release checklist | numbers tables for the brief, field research updates |
| Score categories mainly owned | Privacy 25 · Integrity 10 · Speed 10 · (Utility 20 shared) | Detection 20 · Identity 15 · (Utility 20 shared) |

**Shared:** `wardguard/model.py` (frozen at H2), `project-docs/tracking/*` (each edits their own rows or appends).

**The interface between you** is `model.py` + `07_API_CONTRACTS.md`:
- Lakshya produces `ParsedFile`/`Unit`/`Slot` objects (text to look at).
- Saransh fills `Slot.mentions`, `Slot.column_type`, `Unit.evidence` and `Unit.cluster`.
- Lakshya consumes those to anonymize and write.

## 2. Timeline side by side

```
Hour   0    2    4    6    8    10   12   14   16   18   20   22   24
L     [L01][L02/03][L04-L05 ingest][L06][L07 export][L09 privacy][L10 rewrite][L11 attack][L12 kanon][L13 perf][L14 docs][L15 rel]
S     [S01 resources ][S02 patterns][S03 cols][S04 guards][S05 context][S06 names][S07][S08 linkage   ][S09 chaos ][S10][S11]
Sync        ▲M0 (H2)            ▲M1 integration (H8)       ▲M2 (H14)       ▲M3 freeze (H18) ▲M4 (H22)
```

Until a module is real, its **stub** returns empty results (no mentions, no clusters), so `main.py` always runs end to end and `tools/eval.sh` always works.

## 3. Sync points (15 minutes each, both together)

| When | Agenda |
|---|---|
| **H2 (M0)** | Freeze `model.py` + contracts. Both run `tools/eval.sh` on the scaffold. |
| **H8 (M1)** | Merge everything; run eval; read `check_dev --show 20` together; update the risk register. |
| **H14 (M2)** | Linkage + privacy numbers; decide D-012 (DOB / age format); plan hardening. |
| **H18 (M3)** | Feature freeze; release checklist dry run; split README/brief writing. |
| **H22 (M4)** | Final verification on both machines; push; submit. |

Also send a short message after every merge: `merged S-03 columns · leak 12%→7% · deva recall 0.81`.

## 4. Git workflow

```bash
# start of every task
git checkout main && git pull --rebase origin main
git checkout -b lakshya/L-05-ingest          # or saransh/S-03-columns

# while working (small commits)
git add <your files only>
git commit -m "[L-05] ingest: decode utf-16 tsv and cp1252 csv"

# finish
pytest -q && tools/eval.sh                    # must be green and not worse
git checkout main && git pull --rebase origin main
git merge --no-ff lakshya/L-05-ingest
git push origin main
```

**Rules:**
1. **Commit message:** `[TASK-ID] module: what changed` (e.g. `[S-06] names: add Devanagari variant generation`).
2. **Only stage your own files** (`git add <paths>`, never `git add -A` blindly).
3. `main` must **always** pass CONTRACT OK. Never push a red main.
4. Merge at least every 2 hours, because small merges mean small conflicts.
5. Tracking files: edit **only your own rows/sections** or **append** at the bottom. If a conflict happens there, keep both sides.
6. `model.py` changes: a DECISIONS entry + a message to your partner **before** pushing.
7. Never commit: `.venv/`, outputs (`out*/`, `/tmp/...`), the kit folder, `__pycache__/`, secrets.
8. A shortcut when you're both online and the change is small: committing directly to main is fine **if** eval passes.

## 5. Working with Gemini (both)

1. Make your PDF context pack (see `project-docs/README.md`, "Build PDFs"): `WardGuard_Context_<Name>.pdf`.
2. Open a **new Gemini chat per task** (or per 2–3 small tasks). Upload the PDF, then paste the master prompt filled in for you (in your personal file `team/<NAME>.md`, section "Your Gemini master prompt").
3. Paste the current code of the files you're changing (Gemini can't see your repo).
4. Ask for one task at a time, by ID.
5. Review with the checklist in `09_AI_VIBE_CODING_RULES.md §F`, then run the tests and eval.
6. Paste Gemini's "TRACKING UPDATE" lines into the tracking files and commit them with the code.
7. When tracking files change a lot (every milestone), rebuild the PDF so the next chat has fresh status.

## 6. Definition of Done (every task)

- [ ] Code in your owned files only, following 09 rules
- [ ] Tests added, `pytest -q` green
- [ ] `tools/eval.sh` → CONTRACT OK, numbers not worse (or the regression explained in BUILD_LOG)
- [ ] `AI_TASK_STATES.md` row → DONE; `BUILD_LOG.md` line appended; `CHANGELOG.md` entry
- [ ] Merged to main and pushed; partner informed
