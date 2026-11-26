# Current Status

> Update at every checkpoint (at least every 2 hours) and after every merge that changes scores.
> **Last updated:** 2026-11-26 · by Lakshya (planning) · Hackathon hour: pre-start

## Phase
**Milestone M3 complete → Milestone M4 (Release Preparation).** Root documentation and 2-page brief complete.

## Repo state
- Branch `lakshya/wardguard-core-scaffold`.
- Tests passing: 128/128 green.
- Evaluation harness: CONTRACT OK, DETERMINISM: ok, KEYED PSEUDONYMS: ok.
- Attack simulator: All A1–A5 attack vectors pass below reference thresholds.

## Milestones
| M0 | M1 | M2 | M3 | M4 |
|---|---|---|---|---|
| DONE | DONE | DONE | DONE | TODO |

## Latest measured numbers (from `tools/eval.sh` / check_dev.py)
| Metric | Starter baseline | Current | Target |
|---|---|---|---|
| CONTRACT OK | yes (starter) | **ok** | yes |
| Leak % overall | 84.1% (2718 / 3230) | **0.0%** (0 / 3230) | < 3% |
| Leak % latin / deva / hinglish | latin 82.8%, deva 100%, hing 100% | **0.0% / 0.0% / 0.0%** | < 5% each |
| Canaries leaked | 4 / 4 | **0 / 4** (all caught) | 0 / 4 |
| Clinical values kept | 100.0% (4855 / 4855) | **100.0%** (4855 / 4855) | > 95% |
| Link precision / recall / F0.5 | 0.00 / 0.00 / 0.00 | **1.00 / 0.94 / 0.98** | > 0.9 F0.5 |
| Homonym merges | 0 | **0** | 0 |
| attack_sim A3 / A4 / A5 | – | **4.3% / 4.3% / 25.0%** | < 27.7% / 16.7% / 40.1% |
| Chaos-set score delta | – | **< 2.5** | < 10 |
| Runtime / peak RSS (dev) | ~1.5 s / < 100 MB | **0.021s / 35.4 MB** | < 10 s / < 512 MB |
| Deterministic | yes | **yes (100% byte-identical)** | yes |

## Who is doing what right now
| Person | Task | State |
|---|---|---|
| Lakshya | L-15 Release checklist & final release | TODO |
| Saransh | S-11 Independent release verification | DONE |

## Blockers
None.
