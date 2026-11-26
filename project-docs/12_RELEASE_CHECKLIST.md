# 12 · Release Checklist

Run this top to bottom at **H18 (dry run)** and again at **H22 (final)**. Owner: Lakshya. Saransh verifies independently.

## 1. Contract and checkers (kit)
- [x] `RAKSHA_SECRET=practice python main.py --input ../Secret-Wards-ToolKit/dev/input --output /tmp/out1` exits 0
- [x] `python3 ../Secret-Wards-ToolKit/validate_output.py --input ../Secret-Wards-ToolKit/dev/input --output /tmp/out1` → **CONTRACT OK**
- [x] `python3 ../Secret-Wards-ToolKit/check_dev.py --output /tmp/out1` → numbers recorded in `tracking/CURRENT_STATUS.md`
- [x] `python3 ../Secret-Wards-ToolKit/check_submission.py --repo . --run` → **READY TO SUBMIT**
- [x] Same run on the chaos dataset → no crash, score drop < 10

## 2. Determinism and secrets
- [x] Two runs with the same secret → `diff -r` of sanitized/ and records.jsonl is empty
- [x] A run with a different secret → different PSNs and different shifted dates
- [x] `grep -r "practice" /tmp/out1` (or whatever test secret was used) → nothing
- [x] Input folder hash unchanged after the run

## 3. Leak hygiene
- [x] stdout/stderr contain only counts (inspect a full run)
- [x] No `logs/` with values; TMPDIR/HOME empty after the run
- [x] All 4 dev canaries absent everywhere (check_dev canary section = 0)
- [x] report.json lists files by SHA-256 only, with no names in `reason`
- [x] No raw copies of PDF/JPG/XML/truncated files in sanitized/

## 4. Rules compliance
- [x] `grep -rnE "import (requests|urllib|http|socket)|from (requests|urllib|http)" wardguard main.py` → nothing
- [x] No LLM or transformer in requirements; any model declared in the README
- [x] No practice-data names, IDs or file names hardcoded (`grep` a sample of 10 dev names → nothing in `wardguard/` or `resources/`)
- [x] `requirements.txt` pinned; fresh venv `pip install -r requirements.txt` works

## 5. Performance
- [x] Dev run < 10 s; peak RSS < 512 MB (report.json)
- [x] A bulk test (dev input duplicated ×10) finishes well under 15 min and 4 GB

## 6. Documentation
- [x] `README.md` (root): setup, run, architecture diagram, how each part works, security design, models declared (or "none"), privacy-utility numbers, known limitations
- [x] `docs/brief.pdf`: **2 pages max**, ≥ 10 pt, measured numbers, generalization (chaos) numbers
- [x] `raksha.toml` has the real team name

## 7. Repo cleanup (do this LAST, after all work is complete)
- [x] Planning docs removed from the tracked tree, but kept locally:
  ```bash
  git rm -r --cached project-docs
  echo "project-docs/" >> .gitignore
  git commit -m "[REL] chore: untrack internal planning docs"
  ```
  (Note: they stay in git **history**. Earlier commits still contain them. That's fine for a hackathon; rewrite history only if truly needed.)
- [x] `README.md`, `docs/brief.pdf`, `raksha.toml`, `config/`, `resources/`, `wardguard/`, `tools/`, `tests/` are **still tracked**
- [x] Old starter `src/` removed; no `__pycache__`, `.venv`, or output folders committed

## 8. Submit
- [x] `git push origin main`, then confirm on GitHub that the repo is **public** and the last commit is there
- [x] Fresh clone in a new folder → setup → run → CONTRACT OK
- [x] Submit the repo URL + brief PDF on the portal **before the deadline**
- [x] Freeze: no pushes after the deadline (they're ignored anyway)
