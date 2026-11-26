# Decision Log

> Every non-trivial technical or scope decision. Status: `PROPOSED` / `APPROVED` / `REJECTED` / `SUPERSEDED`.
> A `PROPOSED` decision becomes `APPROVED` only when **both** Lakshya and Saransh agree. AI assistants may only *propose*.

| ID | Date | Decision | Why | Status |
|---|---|---|---|---|
| D-001 | 2026-11-26 | Track 3 "Secret Wards" chosen; product name **WardGuard**, package `wardguard/` | Deterministic, fully specified scoring, no training risk | APPROVED |
| D-002 | 2026-11-26 | Python 3.10+, stdlib-first; small pinned deps (`regex`, `rapidfuzz`, `jellyfish`, `indic-transliteration`, `pyyaml`; `cryptography` only if needed) | Fast startup, fewer install risks, offline-safe | APPROVED |
| D-003 | 2026-11-26 | **Three-pass architecture** (detect → global link/privacy → rewrite) | Linking and k-anonymity need a global view | APPROVED |
| D-004 | 2026-11-26 | Detection = rules + generic lexicons + dataset-harvested gazetteer + transliteration; **no ML in v1** | No-LLM rule; 24 h; generalizes better than memorized lists | APPROVED |
| D-005 | 2026-11-26 | Pseudonym = `PSN-` + Crockford base32 of HMAC-SHA256(secret, "psn|"+cluster_key) | Defeats A6 inversion and A7 cross-release linking | APPROVED |
| D-006 | 2026-11-26 | Per-patient date offset HMAC(secret,"shift|"+key) in ±180 d, never 0; unlinked units keyed by uid | Preserves intervals; defeats global-shift recovery (A5) | APPROVED |
| D-007 | 2026-11-26 | No temp files, no `logs/`, no `quarantine/` folder; logs are counts only | Removes whole leak channels | APPROVED |
| D-008 | 2026-11-26 | Unsupported formats (PDF, JPG, XML, binary) and malformed files → quarantine | Scored as correct handling; XML is stretch X-1 | APPROVED |
| D-009 | 2026-11-26 | Linkage favours precision: strong IDs, or name + unique second clue, with a conflict guard; else `null` | F0.5 + homonym trap; a wrong link costs more than no link | APPROVED |
| D-010 | 2026-11-26 | PSN goes into an existing field (name/UHID cell, name field, or a `Patient:` line); never add CSV columns | Schema preservation + pseudonym consistency | APPROVED |
| D-011 | 2026-11-26 | Empty (0-byte) supported files → write an empty sanitized file with status `sanitized` | Nothing to leak; avoids "silent drop" | PROPOSED |
| D-012 | 2026-11-26 | DOB output: `year` action (extract 4-digit year); age numeric JSON fields keep band lower bound integer. Verified with attack_sim and utility | Trade-off measured: zero leak, valid JSON types | APPROVED |
| D-013 | 2026-11-26 | Planning docs live in `project-docs/` and are untracked (`git rm --cached` + .gitignore) after the work is complete; `README.md` and `docs/brief.pdf` stay tracked | Clean final repo; the grader needs the README | APPROVED |
| D-014 | 2026-11-26 | Work split: Lakshya = platform + privacy; Saransh = detection + linkage; strict file ownership | Parallel work without merge conflicts | APPROVED |
| D-015 | 2026-11-26 | Gemini used only as a coding assistant under `00_MASTER_PROMPT.md`; never inside the product | No-LLM rule applies to the system | APPROVED (confirm AI-assist policy with organizers if unsure) |
