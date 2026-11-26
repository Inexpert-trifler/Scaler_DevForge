#!/usr/bin/env bash
# Build Gemini context-pack PDFs from the project-docs markdown files.
# Usage: bash project-docs/build_pdfs.sh
# Needs: pandoc, and Google Chrome / Chromium (headless print-to-pdf).
set -euo pipefail

DOCS="$(cd "$(dirname "$0")" && pwd)"
OUT="$DOCS/pdf"
mkdir -p "$OUT"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
command -v pandoc >/dev/null || { echo "pandoc not found (brew install pandoc)"; exit 1; }
[ -x "$CHROME" ] || CHROME="$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)"
[ -n "$CHROME" ] || { echo "Chrome/Chromium not found; set CHROME=/path/to/chrome"; exit 1; }

SHARED=(
  00_MASTER_PROMPT.md 01_PRD.md 02_PRODUCT_CONTEXT.md 03_TECHNICAL_REQUIREMENTS.md
  04_APPROVED_SCOPE.md 05_USER_FLOW.md 06_DATA_MODELS.md 07_API_CONTRACTS.md
  08_ARCHITECTURE.md 09_AI_VIBE_CODING_RULES.md 10_FIELD_RESEARCH.md
  11_RISK_REGISTER.md 12_RELEASE_CHECKLIST.md
  tracking/CURRENT_STATUS.md tracking/NEXT_TASKS.md tracking/AI_TASK_STATES.md
  tracking/DECISIONS.md tracking/KNOWN_ISSUES.md tracking/CHANGELOG.md tracking/BUILD_LOG.md
  team/WORKFLOW.md
)

CSS="$OUT/.style.css"
cat > "$CSS" <<'EOF'
body{font-family:-apple-system,"Segoe UI","Noto Sans","Noto Sans Devanagari",Arial,sans-serif;font-size:10.5pt;line-height:1.45;max-width:100%;margin:0 8mm;color:#111}
h1{font-size:17pt;border-bottom:2px solid #333;padding-bottom:3px;margin-top:28px;page-break-before:always}
h1:first-of-type{page-break-before:avoid}
h2{font-size:13.5pt;margin-top:20px}h3{font-size:11.5pt}
table{border-collapse:collapse;width:100%;font-size:9pt;margin:8px 0}
th,td{border:1px solid #bbb;padding:3px 5px;vertical-align:top}th{background:#eee}
pre{background:#f5f5f5;border:1px solid #ddd;padding:6px;font-size:8.3pt;white-space:pre-wrap;word-break:break-word}
code{font-family:Menlo,Consolas,monospace;font-size:8.8pt}
blockquote{border-left:3px solid #999;margin:6px 0;padding-left:8px;color:#444}
EOF

build() { # $1 = output name, rest = md files
  local name="$1"; shift
  local tmp_md="$OUT/.$name.md" tmp_html="$OUT/.$name.html"
  : > "$tmp_md"
  for f in "$@"; do
    printf '\n\n<!-- %s -->\n\n' "$f" >> "$tmp_md"
    printf '> Source file: `project-docs/%s`\n\n' "$f" >> "$tmp_md"
    cat "$DOCS/$f" >> "$tmp_md"
  done
  pandoc "$tmp_md" -f gfm -t html5 -s --metadata title="$name" -c "$(basename "$CSS")" -o "$tmp_html"
  "$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
    --print-to-pdf="$OUT/$name.pdf" "file://$tmp_html" >/dev/null 2>&1
  rm -f "$tmp_md" "$tmp_html"
  echo "built $OUT/$name.pdf"
}

build "WardGuard_Context_Lakshya" team/LAKSHYA.md "${SHARED[@]}"
build "WardGuard_Context_Saransh" team/SARANSH.md "${SHARED[@]}"
build "WardGuard_Full_Docs" README.md "${SHARED[@]}" team/LAKSHYA.md team/SARANSH.md
rm -f "$CSS"
