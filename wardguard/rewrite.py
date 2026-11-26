"""Rewrite engine for applying mentions and pseudonyms."""
import json
from wardguard.model import ParsedFile


def render(pf: ParsedFile, policy: dict) -> bytes:
    """Render sanitized bytes from ParsedFile and policy."""
    if pf.fmt in ("csv", "tsv"):
        delimiter = pf.delimiter or ("," if pf.fmt == "csv" else "\t")
        lines = []
        if pf.header is not None:
            lines.append(delimiter.join(pf.header))
        if pf.rows is not None:
            # Reconstruct from units if present, else original rows
            if pf.units:
                for u in pf.units:
                    row_vals = [s.text for s in u.slots]
                    lines.append(delimiter.join(row_vals))
            else:
                for row in pf.rows:
                    lines.append(delimiter.join(row))
        content = "\n".join(lines) + "\n" if lines else ""
        return content.encode("utf-8")

    elif pf.fmt in ("json", "fhir"):
        if pf.obj is not None:
            return json.dumps(pf.obj, indent=2, ensure_ascii=False).encode("utf-8")
        return b"{}\n"

    else:  # text
        if pf.text is not None:
            return pf.text.encode("utf-8")
        return b""
