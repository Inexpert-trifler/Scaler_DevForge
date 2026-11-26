"""Robust readers for CSV, TSV, JSON, FHIR and Text."""
import csv
import hashlib
import io
import json
from pathlib import Path
from typing import List

from wardguard.ingest.decode import decode
from wardguard.ingest.sniff import sniff
from wardguard.model import ParsedFile
from wardguard.safety.log import safe_reason


def load_all(input_dir: Path) -> List[ParsedFile]:
    """Read all files under input_dir recursively in deterministic sorted order."""
    results: List[ParsedFile] = []
    
    if not input_dir.exists():
        return results

    paths = sorted([p for p in input_dir.rglob("*") if p.is_file()])
    for p in paths:
        rel = p.relative_to(input_dir).as_posix()
        try:
            raw = p.read_bytes()
        except Exception as e:
            results.append(
                ParsedFile(
                    rel=rel,
                    sha256="",
                    size=0,
                    fmt="unsupported",
                    status="quarantined",
                    reason=safe_reason(e),
                )
            )
            continue

        sha256_hash = hashlib.sha256(raw).hexdigest()
        size = len(raw)
        fmt = sniff(raw, rel)

        if fmt == "unsupported":
            results.append(
                ParsedFile(
                    rel=rel,
                    sha256=sha256_hash,
                    size=size,
                    fmt=fmt,
                    status="quarantined",
                    reason="unsupported_format",
                )
            )
            continue

        decoded = decode(raw)
        if decoded is None:
            results.append(
                ParsedFile(
                    rel=rel,
                    sha256=sha256_hash,
                    size=size,
                    fmt=fmt,
                    status="quarantined",
                    reason="undecodable",
                )
            )
            continue

        text_content, encoding = decoded
        pf = ParsedFile(
            rel=rel,
            sha256=sha256_hash,
            size=size,
            fmt=fmt,
            encoding=encoding,
            status="pending",
        )

        try:
            if fmt in ("csv", "tsv"):
                delimiter = "\t" if fmt == "tsv" else ","
                # Try csv reader
                f = io.StringIO(text_content)
                reader = csv.reader(f, delimiter=delimiter)
                rows = list(reader)
                if rows:
                    pf.header = rows[0]
                    pf.rows = rows[1:]
                else:
                    pf.header = []
                    pf.rows = []
                pf.delimiter = delimiter
            elif fmt in ("json", "fhir"):
                pf.obj = json.loads(text_content)
            else:  # text
                pf.text = text_content
            results.append(pf)
        except Exception as e:
            pf.status = "quarantined"
            pf.reason = "malformed"
            results.append(pf)

    return results
