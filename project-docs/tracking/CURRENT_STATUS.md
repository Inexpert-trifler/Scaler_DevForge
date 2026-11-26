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
| CONTRACT OK | yes (starter) | yes | yes |
| Leak % overall | 84.1% (2718 / 3230) | 84.1% | < 3% |
| Leak % latin / deva / hinglish | latin 82.8%, deva 100%, hing 100% | – | < 5% each |
| Canaries leaked | 4 / 4 | 4 / 4 | 0 / 4 |
| Clinical values kept | 100.0% (4855 / 4855) | 100.0% | > 95% |
| Link precision / recall / F0.5 | 0.00 / 0.00 / 0.00 | 0.00 | > 0.9 F0.5 |
| Homonym merges | 0 | 0 | 0 |
| attack_sim A3 / A4 / A5 | – | – | < 27.7% / 16.7% / 40.1% |
| Chaos-set score delta | – | – | < 10 |
| Runtime / peak RSS (dev) | ~1.5 s / < 100 MB | – | < 10 s / < 512 MB |
| Deterministic | yes | yes | yes |

## Who is doing what right now
| Person | Task | State |
|---|---|---|
| Lakshya | L-01 Scaffold | TODO |
| Saransh | S-04 Meaning-trap guards | TODO |

## Blockers
None.
