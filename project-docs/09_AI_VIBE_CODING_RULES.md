# 09 · AI Vibe-Coding Rules

> These rules apply to **every AI assistant** (Gemini or anything else) that writes code for this project, and to the humans reviewing that code. Paste `00_MASTER_PROMPT.md` at the start of every AI chat; it points here.

## A. Grounding (anti-hallucination)

1. **The docs are the truth.** Use only facts from: the project-docs PDF/files, the kit docs (`SPEC.md`, `SCORING.md`, `ATTACKS.md`, `DATASET.md`), and code the human pastes. If a fact isn't there, say **"NOT IN DOCS"** and ask. Never guess.
2. **Never invent APIs.** Use only the functions, dataclasses and fields defined in `06_DATA_MODELS.md` and `07_API_CONTRACTS.md`. If something is missing, propose a contract change and stop. Don't silently add it.
3. **Never invent library functions.** Use only libraries in `requirements.txt` (or the stdlib). If you're unsure a function exists in a library version, say so and prefer the stdlib.
4. **Quote the task ID** (e.g. `S-03`) and the requirement IDs (e.g. `TR-DET-3`) you're implementing, at the top of every answer.
5. **Stay in your owner's files.** Lakshya's AI edits only L-owned files, and Saransh's AI only S-owned files (see `08_ARCHITECTURE.md §2`). `model.py` changes need a DECISIONS entry.

## B. Hard product rules (violating any = disqualification or penalty)

6. **No LLM, generative model, or transformer > 50M params in product code.** Rules, regexes, gazetteers, classical ML only.
7. **No network** in `wardguard/` or `main.py`: no `requests`, `urllib`, `http`, `socket`, and no model or data downloads at run time.
8. **Never print, log, or put into exception messages any data value.** Only fixed event names + integer counts. Use `safety.log.event()` and `safety.log.safe_reason()`.
9. **Never write `RAKSHA_SECRET`** anywhere, and never derive anything from it other than HMAC outputs.
10. **Never write temp files**, and never write anything inside the input folder.
11. **Never hardcode practice-data names, file names, IDs or exact column headers.** Use generic lexicons in `resources/` + value profiling. Ask yourself: "would this still work if every name and column label changed?"
12. **Never copy an input file to the output** unless it went through render. Failures → quarantine.
13. **Determinism:** no `random`, `time`, `uuid`, or `hash()` of strings in anything that affects output. Always iterate sorted.
14. **Preserve format:** CSV keeps its delimiter, header, row count and column count; JSON keeps its structure, key order and value types; all output is UTF-8.

## C. Code style

15. Python 3.10+, type hints everywhere, `from __future__ import annotations`.
16. Small pure functions; no global mutable state except precompiled regexes and constant tables.
17. Regexes are compiled once at module import, with a comment showing one positive and one negative example.
18. Docstring on every public function: what it does, inputs, outputs, edge cases.
19. No new dependency without a DECISIONS entry. Prefer the stdlib.
20. Performance matters (2 CPUs / 4 GB / < 60 s target): no O(n²) loops over all units; precompile; avoid repeated string copies.

## D. Testing

21. Every new detector or rule comes with pytest tests: **at least one positive, one negative (a trap), one Devanagari or Hinglish case** where relevant.
22. Trap cases that must always have tests: `Dr. Ramesh` kept · relative `Ramesh` removed · `C/O fever` kept · `C/O Ramesh Kumar` removed · `K/C/O addison's disease` kept · `Dolo 650 BD x 5 days` kept · `1-0-1` kept · `650mg` kept · `BP 150/90` kept · `Parkinson's disease` kept · `+91 72864 90658`, `072864-90658`, `९८७६५४३२१०` removed · `नाम: सुनीता पटेल` removed · `Shahid sahab ka BP` → name removed, BP kept.
23. Test data is **invented** in the test file, never copied from `dev/input`.
24. After a change, the human runs `pytest -q` and `tools/eval.sh`. The AI must tell them to.

## E. Answer format for the AI (every coding reply)

```
TASK: <ID> — <title>          REQS: <TR-…>
PLAN: 3–6 bullet steps
FILES: list of files created/changed (must be owned by the requester)
CODE: full content of each changed file (or a precise diff)
TESTS: new/updated tests
RUN: exact commands to verify (pytest -q ; tools/eval.sh)
RISKS / ASSUMPTIONS: anything not confirmed by the docs
TRACKING UPDATE: lines to paste into AI_TASK_STATES.md, BUILD_LOG.md, CHANGELOG.md
                 (+ DECISIONS.md / KNOWN_ISSUES.md if applicable)
```

## F. Human review checklist before committing AI code

- [ ] Does it only touch my files?
- [ ] Any `print(` with data, f-strings in exceptions, or logging of values? → remove
- [ ] Any network import, random, time-dependent output, or unsorted set iteration?
- [ ] Any practice-data name or exact header hardcoded?
- [ ] Do the tests pass, does `tools/eval.sh` show CONTRACT OK, and are the numbers not worse?
- [ ] Have the tracking files been updated?
