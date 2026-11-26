# Build Log

> Append-only. Newest at the **bottom**. One entry per merged change or eval run.
> Format: `- [YYYY-MM-DD HH:MM] [H<hour>] <Name> [<TASK-ID>] <what> | CONTRACT: ok/fail | leak <x>% (L/D/H <a>/<b>/<c>) | canary <n>/4 | clin <y>% | F0.5 <z> | <sec>s <mb>MB`
> `tools/eval.sh` prints this line for you.

- [2026-11-26] [pre] Lakshya [PLAN] Created project-docs (PRD, context, requirements, scope, flows, models, contracts, architecture, rules, research, risks, release, tracking, team files). No code yet.
- [2026-11-26 17:15] [H1] Lakshya [L-01] Scaffold WardGuard layout, models, stubs, ingest/export, tests green | CONTRACT: ok | tests: 9 passed | 0.05s 18MB
- [2026-11-26 17:40] [H1.5] Lakshya [L-02/L-03] Frozen model.py (M0) and created tools/eval.sh with determinism & keyed PSN checks | CONTRACT: ok | determinism: ok | 0.001s 25.06MB
- [2026-11-26 17:46] [H2] Lakshya [L-04] Safety layer: counts-only logging, safe_reason tokenization, fail-safe per-file quarantine | CONTRACT: ok | tests: 12 passed | 0.001s 25.11MB
- [2026-11-26 18:35] [H1] Saransh [S-STRESS] Tough stress test suite (12 tests) and hardening: zero-width/homoglyph evasion, Hinglish note parsing, dotted/slashed Aadhaar Verhoeff verification, canary detection, medical eponyms/clinical protection, 100% deterministic transliteration variants, and pair-age linkage guard | CONTRACT: ok | tests: 60/60 pass
