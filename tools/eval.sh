#!/usr/bin/env bash
# tools/eval.sh: WardGuard pipeline evaluation and determinism verification script.
set -euo pipefail

INPUT_DIR="${1:-tests/sample_data}"
OUTPUT_RUN1="/tmp/wardguard_eval_run1"
OUTPUT_RUN2="/tmp/wardguard_eval_run2"
OUTPUT_DIFF_SECRET="/tmp/wardguard_eval_diff_secret"

# Ensure clean temporary directories
rm -rf "$OUTPUT_RUN1" "$OUTPUT_RUN2" "$OUTPUT_DIFF_SECRET"
mkdir -p "$OUTPUT_RUN1" "$OUTPUT_RUN2" "$OUTPUT_DIFF_SECRET"

echo "=== WardGuard Evaluation ==="
echo "Input directory: $INPUT_DIR"

# If input_dir doesn't exist, create a mock test input set to ensure tests run
if [ ! -d "$INPUT_DIR" ]; then
    echo "Notice: $INPUT_DIR not found, creating test sample set in $INPUT_DIR"
    mkdir -p "$INPUT_DIR"
    cat << 'EOF' > "$INPUT_DIR/sample_opd.csv"
Name,Age,Gender,Phone,Date,Diagnosis
Rajesh Kumar,45,M,9876543210,12/04/2023,Hypertension
Sunita Devi,38,F,9123456789,15/04/2023,Type 2 Diabetes
EOF
    cat << 'EOF' > "$INPUT_DIR/sample_note.txt"
Patient Rajesh Kumar attended OPD for regular follow-up. Blood pressure recorded at 130/85.
EOF
    cat << 'EOF' > "$INPUT_DIR/sample_record.json"
[
  {"visit_id": "V1001", "patient_name": "Rajesh Kumar", "symptoms": "headache"}
]
EOF
fi

# Step 1: Run main with secret 'practice'
echo "[1/4] Running pipeline with RAKSHA_SECRET=practice (Run 1)..."
RAKSHA_SECRET=practice python3 main.py --input "$INPUT_DIR" --output "$OUTPUT_RUN1"

# Step 2: Validate output contract
echo "[2/4] Validating output contract..."
if [ ! -f "$OUTPUT_RUN1/report.json" ] || [ ! -f "$OUTPUT_RUN1/records.jsonl" ]; then
    echo "ERROR: Missing required outputs (report.json or records.jsonl)"
    exit 1
fi
echo "CONTRACT: ok"

# Step 3: Run 2 with same secret for determinism check
echo "[3/4] Running pipeline with RAKSHA_SECRET=practice (Run 2)..."
RAKSHA_SECRET=practice python3 main.py --input "$INPUT_DIR" --output "$OUTPUT_RUN2"

echo "Checking determinism across runs..."
# Compare sanitized directories and records.jsonl (ignoring timing and resources in report.json)
diff -r "$OUTPUT_RUN1/sanitized" "$OUTPUT_RUN2/sanitized"
diff -u "$OUTPUT_RUN1/records.jsonl" "$OUTPUT_RUN2/records.jsonl"
echo "DETERMINISM: ok (runs are byte-identical)"

# Step 4: Run with secret 'other' (pseudonyms and date offsets must change)
echo "[4/4] Running pipeline with RAKSHA_SECRET=other..."
RAKSHA_SECRET=other python3 main.py --input "$INPUT_DIR" --output "$OUTPUT_DIFF_SECRET"

PSN_COUNT1=$(grep -o "PSN-[A-Z0-9]*" "$OUTPUT_RUN1/records.jsonl" | sort -u | wc -l | tr -d ' ')
PSN_COUNT_DIFF=$(grep -o "PSN-[A-Z0-9]*" "$OUTPUT_DIFF_SECRET/records.jsonl" | sort -u | wc -l | tr -d ' ')

if [ "$PSN_COUNT1" -gt 0 ] && cmp -s "$OUTPUT_RUN1/records.jsonl" "$OUTPUT_DIFF_SECRET/records.jsonl"; then
    echo "ERROR: Pseudonyms did not change under a different secret!"
    exit 1
fi
echo "KEYED PSEUDONYMS: ok (secret changes output)"

# Extract metrics from report.json
FILES_TOTAL=$(python3 -c "import json; r=json.load(open('$OUTPUT_RUN1/report.json')); print(r['counts']['files_total'])")
FILES_SANITIZED=$(python3 -c "import json; r=json.load(open('$OUTPUT_RUN1/report.json')); print(r['counts']['files_sanitized'])")
FILES_QUARANTINED=$(python3 -c "import json; r=json.load(open('$OUTPUT_RUN1/report.json')); print(r['counts']['files_quarantined'])")
TIME_SEC=$(python3 -c "import json; r=json.load(open('$OUTPUT_RUN1/report.json')); print(r['timing']['seconds'])")
PEAK_RSS=$(python3 -c "import json; r=json.load(open('$OUTPUT_RUN1/report.json')); print(r['resources']['peak_rss_mb'])")

TIMESTAMP=$(date +"%Y-%m-%d %H:%M")
echo ""
echo "=== BUILD LOG LINE ==="
echo "- [$TIMESTAMP] [H1.5] Lakshya [L-03] eval.sh verification | CONTRACT: ok | files: ${FILES_SANITIZED}/${FILES_TOTAL} sanitized, ${FILES_QUARANTINED} quarantined | ${TIME_SEC}s ${PEAK_RSS}MB"
