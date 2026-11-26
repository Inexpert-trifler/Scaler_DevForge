"""File writers for sanitized mirror."""
from pathlib import Path
from wardguard.model import ParsedFile
from wardguard.rewrite import render
from wardguard.safety.log import safe_reason


def write_file(pf: ParsedFile, output_dir: Path, policy: dict) -> None:
    """Render and write sanitized file to output_dir/sanitized/..."""
    if pf.status == "quarantined":
        return

    out_rel = pf.out_rel or f"sanitized/{pf.rel}"
    san_root = (output_dir / "sanitized").resolve()
    dest = (output_dir / out_rel).resolve()
    try:
        if not dest.is_relative_to(san_root):
            raise ValueError("path_escape")
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = render(pf, policy)
        dest.write_bytes(data)
        pf.status = "sanitized"
        pf.out_rel = out_rel
    except Exception as e:
        pf.status = "quarantined"
        pf.reason = safe_reason(e)
        pf.out_rel = None
