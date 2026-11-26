"""Safety and logging module for WardGuard.

Logs only fixed event names and integer counts.
Exceptions are safely reduced to type name only.
"""
import sys


def event(name: str, **counts: int) -> None:
    """Log an event to stderr using fixed names and integer counts only."""
    count_parts = [f"{k}={v}" for k, v in sorted(counts.items()) if isinstance(v, int)]
    line = f"[EVENT] {name} " + " ".join(count_parts) if count_parts else f"[EVENT] {name}"
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def safe_reason(exc: BaseException) -> str:
    """Reduce an exception to its type name to avoid any side-channel leakage."""
    return type(exc).__name__
