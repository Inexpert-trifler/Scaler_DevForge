"""Safety and logging module for WardGuard.

Rules:
- Fixed event names only.
- Counts only (integers). Never logs patient names, IDs, dates or file text.
- Exceptions reduced strictly to type name (e.g. 'UnicodeDecodeError', 'ValueError').
"""
import sys
from typing import Set

ALLOWED_EVENTS: Set[str] = {
    "pipeline_start",
    "pipeline_complete",
    "files_loaded",
    "file_quarantined",
    "record_count",
    "detection_complete",
    "linkage_complete",
    "privacy_complete",
    "export_complete",
    "link_error",
    "privacy_error",
    "kanon_error",
    "detection_error",
    "filename_rename_error",
    "export_error",
    "fatal_error",
}


def event(name: str, **counts: int) -> None:
    """Log a structured event to stderr with fixed event name and integer counts only."""
    event_name = name if name in ALLOWED_EVENTS else "generic_event"
    safe_counts = []
    for k, v in sorted(counts.items()):
        if isinstance(v, int):
            safe_counts.append(f"{k}={v}")

    line = f"[EVENT] {event_name}"
    if safe_counts:
        line += " " + " ".join(safe_counts)
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def safe_reason(exc: BaseException) -> str:
    """Safely reduce an exception to a generic reason token.
    
    Never exposes exception messages, file paths, or line contents.
    """
    exc_type = type(exc).__name__
    if exc_type in ("UnicodeDecodeError", "LookupError"):
        return "undecodable"
    if exc_type in ("JSONDecodeError", "csv.Error"):
        return "malformed"
    if exc_type in ("RecursionError", "MemoryError"):
        return "resource_limit"
    if exc_type in ("PermissionError", "FileNotFoundError", "IsADirectoryError"):
        return "io_error"
    return exc_type
