# Next Tasks

> The **immediate** queue, i.e. what each person does next. Keep it short (top 3 each). Full board: `AI_TASK_STATES.md`.
> Last updated: 2026-11-26 (pre-start)

## Both, first 30 minutes (H0–0.5)
1. Clone the kit next to the repo:
   ```bash
   cd ..   # the folder that contains Scaler_DevForge/
   git clone https://github.com/Reinforce-SST/Secret-Wards-ToolKit.git
   cd Secret-Wards-ToolKit
   RAKSHA_SECRET=practice python3 starter/main.py --input dev/input --output /tmp/starter_out
   python3 validate_output.py --input dev/input --output /tmp/starter_out      # CONTRACT OK
   python3 check_dev.py --output /tmp/starter_out --show 10                    # baseline numbers
   ```
2. Read kit `START_HERE.md`, `docs/SPEC.md`, `docs/SCORING.md`, `docs/ATTACKS.md` (Saransh also reads `docs/DATASET.md`).
3. Write the baseline numbers into `CURRENT_STATUS.md`.

## Lakshya, next
1. **L-01** Scaffold the new layout (08_ARCHITECTURE §2) with stub modules so `main.py` runs end to end.
2. **L-02** Write `wardguard/model.py` exactly as in 06_DATA_MODELS; get Saransh's OK → M0.
3. **L-03** `tools/eval.sh`.

## Saransh, next
1. **S-01** Build `resources/` lexicons (generic, EN + HI). Study `dev/input` folder by folder and note the traps you see in `10_FIELD_RESEARCH.md`.
2. Review `06_DATA_MODELS.md` + `07_API_CONTRACTS.md` (detection and linkage parts) and confirm or propose changes before H2.
3. **S-02** `normalize.py` + `patterns.py` with tests.
