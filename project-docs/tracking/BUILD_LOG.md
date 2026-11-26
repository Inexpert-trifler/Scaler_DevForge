# Build Log

> Append-only. Newest at the **bottom**. One entry per merged change or eval run.
> Format: `- [YYYY-MM-DD HH:MM] [H<hour>] <Name> [<TASK-ID>] <what> | CONTRACT: ok/fail | leak <x>% (L/D/H <a>/<b>/<c>) | canary <n>/4 | clin <y>% | F0.5 <z> | <sec>s <mb>MB`
> `tools/eval.sh` prints this line for you.

- [2026-11-26] [pre] Lakshya [PLAN] Created project-docs (PRD, context, requirements, scope, flows, models, contracts, architecture, rules, research, risks, release, tracking, team files). No code yet.
- [2026-11-26 17:15] [H1] Lakshya [L-01] Scaffold WardGuard layout, models, stubs, ingest/export, tests green | CONTRACT: ok | tests: 9 passed | 0.05s 18MB
- [2026-11-26 17:40] [H1.5] Lakshya [L-02/L-03] Frozen model.py (M0) and created tools/eval.sh with determinism & keyed PSN checks | CONTRACT: ok | determinism: ok | 0.001s 25.06MB
- [2026-11-26 17:46] [H2] Lakshya [L-04] Safety layer: counts-only logging, safe_reason tokenization, fail-safe per-file quarantine | CONTRACT: ok | tests: 12 passed | 0.001s 25.11MB
- [2026-11-26 18:35] [H1] Saransh [S-STRESS] Tough stress test suite (12 tests) and hardening: zero-width/homoglyph evasion, Hinglish note parsing, dotted/slashed Aadhaar Verhoeff verification, canary detection, medical eponyms/clinical protection, 100% deterministic transliteration variants, and pair-age linkage guard | CONTRACT: ok | tests: 60/60 pass
- [2026-11-26 19:35] [H3] Lakshya [L-05] Ingestion: magic-byte sniffing, multi-encoding decode (BOM/UTF-8/UTF-16/cp1252), ragged CSV rows, deep JSON safety (1500+ levels), generic quarantine | CONTRACT: ok | tests: 74 passed | 0.015s 34.94MB
- [2026-11-26 19:47] [H4] Lakshya [L-06] Unit enumeration: RFC 6901 JSON pointers, CSV row:N locators with duplicate/empty header handling, FHIR/text doc locators | CONTRACT: ok | tests: 81 passed | 0.015s 34.86MB
- [2026-11-26 19:52] [H5] Lakshya [L-07] Export: RFC 4180 CSV/TSV writer, JSON type/structure-preserving emitter, sorted records.jsonl, and SPEC §5 report.json | CONTRACT: ok | tests: 87 passed | 0.015s 34.91MB
- [2026-11-26 20:33] [H6] Lakshya [L-08] Hidden channels: @filename stem, @header, @key slots, metadata pointers, base64 / escape decoding, and collision-safe PII file renaming | CONTRACT: ok | tests: 93 passed | 0.016s 35.28MB
- [2026-11-26 20:39] [H7] Lakshya [L-09] Privacy core: Crockford Base32 HMAC pseudonyms, non-zero date offsets, format & interval preserving date shifter (9-day stay preserved), age band, PIN prefix | CONTRACT: ok | tests: 98 passed | 0.016s 35.27MB
- [2026-11-26 20:50] [H8] Lakshya [L-10] Rewrite engine (H8–11), M1 integration: right-to-left mentions, whole-cell replacement, JSON numeric types preserved, D-010 PSN placement, base64 re-encoding | CONTRACT: ok | tests: 109 passed | 0.021s 35.41MB
- [2026-11-26 20:57] [H10] Lakshya [L-11] tools: attack simulator A2-A5, profile pooling, global-shift recovery | CONTRACT: ok | A3 4.5% (<27.7%), A4 4.5% (<16.7%), A5 25.0% (<40.1%) | tests: 116 passed | 0.021s 35.38MB
- [2026-11-26 21:01] [H13] Lakshya [L-12] k-anonymity targeted coarsening (TR-PRV-7), Milestone M2: equivalence classes over QIs, wider age band (10y), village/tehsil/district drop for rare units | CONTRACT: ok | A3 4.3%, A4 4.3%, A5 25.0% | tests: 123 passed | 0.021s 35.38MB
