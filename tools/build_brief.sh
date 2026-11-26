#!/usr/bin/env bash
# tools/build_brief.sh
# Compiles docs/brief.md into docs/brief.pdf using pandoc and headless Chrome
# and verifies that it is strictly <= 2 pages.

set -euo pipefail

DOCS_DIR="$(cd "$(dirname "$0")/../docs" && pwd)"
MD_FILE="$DOCS_DIR/brief.md"
CSS_FILE="$DOCS_DIR/.brief_style.css"
HTML_FILE="$DOCS_DIR/.brief.html"
PDF_FILE="$DOCS_DIR/brief.pdf"

command -v pandoc >/dev/null || { echo "[ERROR] pandoc not found"; exit 1; }

CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
[ -x "$CHROME" ] || CHROME="$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)"
[ -n "$CHROME" ] || { echo "[ERROR] Chrome/Chromium executable not found"; exit 1; }

echo "==> Converting docs/brief.md to HTML with pandoc..."
pandoc "$MD_FILE" -f gfm -t html5 -s --metadata title="WardGuard - Track 3 Technical Brief" -c "$(basename "$CSS_FILE")" -o "$HTML_FILE"

echo "==> Generating docs/brief.pdf with headless Chrome..."
"$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$PDF_FILE" "file://$HTML_FILE" >/dev/null 2>&1

rm -f "$HTML_FILE"

echo "==> Verifying page count of $PDF_FILE..."
python3 -c "
import sys, pypdf
reader = pypdf.PdfReader('$PDF_FILE')
num_pages = len(reader.pages)
print(f'Generated PDF: {num_pages} pages')
if num_pages > 2:
    print(f'[FAIL] Page count {num_pages} exceeds maximum of 2 pages!', file=sys.stderr)
    sys.exit(1)
elif num_pages < 1:
    print(f'[FAIL] Empty PDF generated!', file=sys.stderr)
    sys.exit(1)
print(f'[PASS] Brief strictly conforms to <= 2 pages constraint ({num_pages}/2 pages).')
"

echo "==> Successfully built $PDF_FILE"
