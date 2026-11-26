# Changelog

> User-visible / score-relevant changes per version. Bump the minor version at each milestone (M1 → 0.2, M2 → 0.3 …).
> Format: `- [TASK-ID] (Name) description`

## [Unreleased]
- [L-05] (Lakshya) Ingestion engine: content-based format sniffing (magic bytes, XML/PDF/JPEG/binary rejection), multi-encoding decode (UTF-8, UTF-8-BOM, UTF-16, cp1252), dialect-aware CSV/TSV readers with ragged row tolerance, 1500-level deep-safe JSON parsing, FHIR R4 bundle classification, and generic quarantine tokens.
- [L-04] (Lakshya) Safety layer: strict counts-only stderr logging, safe exception reason reduction, per-file crash isolation with generic quarantine, and report generation in finally block.
- [L-02] (Lakshya) Freeze `wardguard/model.py` and confirm contracts with Saransh (Milestone M0).
- [L-03] (Lakshya) Add `tools/eval.sh` evaluation harness with determinism diff and keyed pseudonym test.
- [L-01] (Lakshya) Scaffold WardGuard package layout with modular stubs, data models, safety logging, raksha.toml, policy configuration, and test suites.

## [0.0.1] - 2026-11-26
### Added
- [PLAN] (Lakshya) Project planning docs in `project-docs/`: PRD, context, requirements, scope, flows, data models, API contracts, architecture, AI rules, field research, risk register, release checklist, tracking files, team work split, Gemini master prompt.
