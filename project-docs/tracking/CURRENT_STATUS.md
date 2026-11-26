# Current Status

> Update at every checkpoint (at least every 2 hours) and after every merge that changes scores.
> **Last updated:** 2026-11-26 · by Lakshya (planning) · Hackathon hour: pre-start

## Phase
**Planning complete → ready for H0.** The docs are written, and nothing has been built yet.

## Repo state
- Branch `main`, 1 commit (`a0826d3` initial: generic README, `src/main.py` hello-world, `tests/test_main.py`).
- `project-docs/` created (this folder): not yet committed.
- Kit (`Secret-Wards-ToolKit`) not yet cloned next to the repo on team machines.

## Milestones
| M0 | M1 | M2 | M3 | M4 |
|---|---|---|---|---|
| TODO | TODO | TODO | TODO | TODO |

## Latest measured numbers (from `tools/eval.sh` / check_dev.py)
| Metric | Starter baseline | Current | Target |
|---|---|---|---|
| CONTRACT OK | yes (starter) | – | yes |
| Leak % overall | high (starter ≈ 8/100 official) | – | < 3% |
| Leak % latin / deva / hinglish | – | – | < 5% each |
| Canaries leaked | – | – | 0 / 4 |
| Clinical values kept | – | – | > 95% |
| Link precision / recall / F0.5 | 0 (no links) | – | > 0.9 F0.5 |
| Homonym merges | 0 | – | 0 |
| attack_sim A3 / A4 / A5 | – | – | < 27.7% / 16.7% / 40.1% |
| Chaos-set score delta | – | – | < 10 |
| Runtime / peak RSS (dev) | – | – | < 10 s / < 512 MB |
| Deterministic | – | – | yes |

## Who is doing what right now
| Person | Task | State |
|---|---|---|
| Lakshya | L-01 Scaffold | TODO |
| Saransh | S-01 Kit setup + resources | TODO |

## Blockers
None.
