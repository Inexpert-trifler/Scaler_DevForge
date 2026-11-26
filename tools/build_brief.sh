#!/usr/bin/env bash
# tools/build_brief.sh
# Compiles docs/brief.md into docs/brief.pdf using pandoc (or stdlib Python fallback)
# plus headless Chrome and verifies that it is strictly <= 2 pages.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DOCS_DIR="$ROOT_DIR/docs"
MD_FILE="$DOCS_DIR/brief.md"
CSS_FILE="$DOCS_DIR/.brief_style.css"
HTML_FILE="$DOCS_DIR/.brief.html"
PDF_FILE="$DOCS_DIR/brief.pdf"

PY_BIN="${PYTHON:-python3}"
if [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PY_BIN="$ROOT_DIR/.venv/bin/python"
fi

CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
[ -x "$CHROME" ] || CHROME="$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)"
[ -n "$CHROME" ] || { echo "[ERROR] Chrome/Chromium executable not found"; exit 1; }

if command -v pandoc >/dev/null 2>&1; then
  echo "==> Converting docs/brief.md to HTML with pandoc..."
  pandoc "$MD_FILE" -f gfm -t html5 -s --metadata title="WardGuard - Track 3 Technical Brief" -c "$(basename "$CSS_FILE")" -o "$HTML_FILE"
else
  echo "==> pandoc not found; converting docs/brief.md with built-in Python GFM converter..."
  "$PY_BIN" - "$MD_FILE" "$CSS_FILE" "$HTML_FILE" <<'PYEOF'
import html, re, sys
from pathlib import Path

md_text = Path(sys.argv[1]).read_text(encoding="utf-8")
css_name = Path(sys.argv[2]).name
out_html = Path(sys.argv[3])

SYM_MAP = {
    r"\Delta": "&Delta;", r"\in": "&isin;", r"\cup": "&cup;",
    r"\pm": "&plusmn;", r"\text{–}": "&ndash;", r"\text{ d}": " d",
    r"\ge": "&ge;", r"\le": "&le;", r"\rightarrow": "&rarr;",
    r"\leftrightarrow": "&harr;",
}

def fmt_inline(s: str) -> str:
    # Inline math $...$
    def _math(m):
        expr = m.group(1)
        for k, v in SYM_MAP.items():
            expr = expr.replace(k, v)
        expr = re.sub(r"\\text\{([^}]*)\}", r"\1", expr)
        expr = re.sub(r"_\{([^}]*)\}", r"<sub>\1</sub>", expr)
        return f"<em>{expr}</em>"
    placeholders = []
    def _stash_code(m):
        placeholders.append(f"<code>{html.escape(m.group(1))}</code>")
        return f"\x00CODE{len(placeholders)-1}\x00"
    s = re.sub(r"`([^`]+)`", _stash_code, s)
    s = re.sub(r"\$([^$]+)\$", _math, s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", s)
    for idx, code_html in enumerate(placeholders):
        s = s.replace(f"\x00CODE{idx}\x00", code_html)
    return s

lines = md_text.splitlines()
body = []
i = 0
while i < len(lines):
    ln = lines[i]
    if ln.startswith("```"):
        code_lines = []
        i += 1
        while i < len(lines) and not lines[i].startswith("```"):
            code_lines.append(html.escape(lines[i]))
            i += 1
        body.append("<pre><code>" + "\n".join(code_lines) + "</code></pre>")
        i += 1
        continue
    if ln.lstrip().startswith("<div") or ln.lstrip().startswith("</div") or ln.lstrip().startswith("<h") or ln.lstrip().startswith("<span"):
        body.append(ln)
        i += 1
        continue
    if ln.startswith("## "):
        body.append(f"<h2>{fmt_inline(ln[3:])}</h2>")
        i += 1
        continue
    if ln.startswith("### "):
        body.append(f"<h3>{fmt_inline(ln[4:])}</h3>")
        i += 1
        continue
    if ln.startswith("|") and i + 1 < len(lines) and re.match(r"^\|\s*[-:| ]+\|$", lines[i + 1].strip()):
        hdrs = [c.strip() for c in ln.strip().strip("|").split("|")]
        i += 2
        rows = []
        while i < len(lines) and lines[i].startswith("|"):
            rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
            i += 1
        t = ["<table><thead><tr>" + "".join(f"<th>{fmt_inline(h)}</th>" for h in hdrs) + "</tr></thead><tbody>"]
        for r in rows:
            t.append("<tr>" + "".join(f"<td>{fmt_inline(c)}</td>" for c in r) + "</tr>")
        t.append("</tbody></table>")
        body.append("".join(t))
        continue
    if ln.startswith("- "):
        items = []
        while i < len(lines) and lines[i].startswith("- "):
            items.append(f"<li>{fmt_inline(lines[i][2:])}</li>")
            i += 1
        body.append("<ul>" + "".join(items) + "</ul>")
        continue
    if re.match(r"^\d+\.\s+", ln):
        items = []
        while i < len(lines) and re.match(r"^\d+\.\s+", lines[i]):
            item_txt = re.sub(r"^\d+\.\s+", "", lines[i])
            items.append(f"<li>{fmt_inline(item_txt)}</li>")
            i += 1
        body.append("<ol>" + "".join(items) + "</ol>")
        continue
    if not ln.strip():
        i += 1
        continue
    body.append(f"<p>{fmt_inline(ln)}</p>")
    i += 1

doc = (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
    "<title>WardGuard - Track 3 Technical Brief</title>"
    f"<link rel='stylesheet' href='{css_name}'></head><body>"
    + "\n".join(body)
    + "</body></html>"
)
out_html.write_text(doc, encoding="utf-8")
PYEOF
fi

echo "==> Generating docs/brief.pdf with headless Chrome..."
"$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$PDF_FILE" "file://$HTML_FILE" >/dev/null 2>&1

rm -f "$HTML_FILE"

echo "==> Verifying page count of $PDF_FILE..."
"$PY_BIN" -c "
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
