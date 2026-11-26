# project-docs: WardGuard internal planning docs

> Internal working docs for Lakshya + Saransh and their AI assistants.
> **Untrack at the end** (see `12_RELEASE_CHECKLIST.md §7`). The product README lives at the repo root.

## Reading order

| # | File | What it is | Who updates it |
|---|---|---|---|
| 00 | `00_MASTER_PROMPT.md` | Gemini prompts (session start, task, fix, anti-drift, end) | rarely |
| 01 | `01_PRD.md` | Product requirements, goals, metrics, milestones | rarely |
| 02 | `02_PRODUCT_CONTEXT.md` | Event, rules, scoring, traps, USP, team | rarely |
| 03 | `03_TECHNICAL_REQUIREMENTS.md` | Numbered requirements (TR-…) with acceptance criteria | when scope changes |
| 04 | `04_APPROVED_SCOPE.md` | In / stretch / out of scope | via DECISIONS only |
| 05 | `05_USER_FLOW.md` | Evaluator, system, file, developer, attacker flows | rarely |
| 06 | `06_DATA_MODELS.md` | Dataclasses, enums, slot paths, policy, output schemas | via DECISIONS only |
| 07 | `07_API_CONTRACTS.md` | External contract + internal function signatures | via DECISIONS only |
| 08 | `08_ARCHITECTURE.md` | Pipeline, repo layout + ownership, rewrite rules, security | rarely |
| 09 | `09_AI_VIBE_CODING_RULES.md` | Rules for AI-written code + review checklist | rarely |
| 10 | `10_FIELD_RESEARCH.md` | Dataset facts, Indian ID/name formats, privacy concepts, attacker | add findings |
| 11 | `11_RISK_REGISTER.md` | Risks, mitigations, owners | each checkpoint |
| 12 | `12_RELEASE_CHECKLIST.md` | Final verification + cleanup steps | at H18, H22 |
| – | `tracking/CURRENT_STATUS.md` | Where we are + latest numbers | every checkpoint |
| – | `tracking/NEXT_TASKS.md` | Top 3 next tasks per person | after each task |
| – | `tracking/AI_TASK_STATES.md` | Task board with states | every task change |
| – | `tracking/BUILD_LOG.md` | Append-only log of builds/evals | every merge |
| – | `tracking/DECISIONS.md` | Decision log | when deciding |
| – | `tracking/KNOWN_ISSUES.md` | Bugs + limitations | when found/fixed |
| – | `tracking/CHANGELOG.md` | Score-relevant changes per version | every merge |
| – | `team/WORKFLOW.md` | Work split, timeline, git workflow, Gemini usage, DoD | rarely |
| – | `team/LAKSHYA.md` | Lakshya's task cards + personal Gemini prompt | Lakshya |
| – | `team/SARANSH.md` | Saransh's task cards + personal Gemini prompt | Saransh |
| – | `testlab/TESTLAB_BUILD_GUIDE.md` | Test lab (sandbox) build guide: specs, task cards T-00..T-16, bug loop, prompts | Lab Builder |

## Build PDFs (context packs for Gemini)

```bash
bash project-docs/build_pdfs.sh
# → project-docs/pdf/WardGuard_Context_Lakshya.pdf
# → project-docs/pdf/WardGuard_Context_Saransh.pdf
# → project-docs/pdf/WardGuard_Full_Docs.pdf
# → project-docs/pdf/WardGuard_TestLab_Builder.pdf  (lab guide + product context, data models, API contracts, architecture, field research)
```
Each personal pack = master prompt + all shared docs + tracking + that person's task file.
It needs `pandoc` and Google Chrome (macOS paths; on Linux set `CHROME=` to your chromium binary).
Rebuild after every milestone so Gemini sees current status.
