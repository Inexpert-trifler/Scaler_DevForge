# 11 · Risk Register

Likelihood (L) and Impact (I): H / M / L. Review at every integration checkpoint (H8, H14, H18).

| ID | Risk | L | I | Mitigation | Owner | Status |
|---|---|:-:|:-:|---|---|---|
| RK-01 | Overfitting to practice data → big drop on the unseen-format dataset (the reference loses ~30 pts) | H | H | Value-profiling columns, context rules, generic lexicons, `chaos_gen.py` test set from H14; never hardcode | Saransh | Open |
| RK-02 | Canary or PII leaks via logs, tracebacks or stdout (−3 each) | M | H | Counts-only logger, `safe_reason()`, no prints, code-review checklist | Lakshya | Open |
| RK-03 | Over-redaction kills utility and therefore privacy credit (utility/0.40 coupling) | M | H | Guards module, `clean/` docs as a regression test, token-retention watched in check_dev | Saransh | Open |
| RK-04 | False merges (homonyms) → F0.5 crash | M | H | Conflict guard, uniqueness rule, `null` when unsure, homonym unit test | Saransh | Open |
| RK-05 | Non-determinism (set order, `hash()`, time) → loses determinism points | M | M | Determinism rules; eval.sh runs twice and diffs | Lakshya | Open |
| RK-06 | Crash on a weird file → exit≠0 or a missing report (−10 false success) | M | H | Per-file try/except → quarantine; report always written in `finally` | Lakshya | Open |
| RK-07 | A raw broken file copied to sanitized/ (−5 each) | L | H | Only `render()` output is ever written; unit test with PDF/JPG/truncated files | Lakshya | Open |
| RK-08 | Date shifting breaks the format or the length of stay | M | M | Format-preserving shifter, per-patient offset, interval test | Lakshya | Open |
| RK-09 | Schema break (added column, changed JSON type) → integrity points lost | M | M | PSN placed in an existing field; numbers stay numbers; validate_output in eval.sh | Lakshya | Open |
| RK-10 | Integration conflicts between the two of us (both editing the same file) | M | M | Strict file ownership, `model.py` frozen at H2, small frequent merges | Both | Open |
| RK-11 | AI assistant hallucinates APIs or rules → broken or forbidden code | H | M | Master prompt, contracts doc, review checklist, "NOT IN DOCS" rule | Both | Open |
| RK-12 | Time overrun / scope creep (UI, XML, CRF) | M | H | Approved scope, feature freeze at H18, stretch only after M3 | Both | Open |
| RK-13 | Slow run (gazetteer × text, linkage O(n²)) → speed points / timeout | L | M | Compiled alternations, blocking, profiling at H15 | Lakshya | Open |
| RK-14 | Network import or lazy download at run time → disqualification | L | H | No network libraries; grep check in the release checklist | Both | Open |
| RK-15 | Devanagari/Hinglish recall weak → per-script macro recall low | M | H | Dedicated Devanagari rules + transliteration from H7; per-script numbers tracked | Saransh | Open |
| RK-16 | Missing the deadline commit / last-minute breakage | L | H | Working build committed every 1–2 h; final freeze at H22 | Lakshya | Open |
| RK-17 | Planning docs (project-docs/) accidentally excluded/included wrongly at the end | L | L | Release checklist step: `git rm -r --cached project-docs` + .gitignore; README stays | Lakshya | Open |
| RK-18 | One teammate blocked by the other's unfinished module | M | M | Stubs that return empty results from H2, so the pipeline always runs end to end | Both | Open |
