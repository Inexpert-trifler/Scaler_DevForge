"""Content-based format sniffing."""
from wardguard.model import Fmt


def sniff(raw: bytes, rel: str) -> Fmt:
    """Sniff format from raw bytes and relative path."""
    clean = raw.lstrip()
    if clean.startswith((b"{", b"[")):
        # Could be json or fhir
        if b'"resourceType"' in clean:
            return "fhir"
        return "json"
    
    # Check delimiters in first lines
    first_line = clean.split(b"\n", 1)[0]
    if b"\t" in first_line:
        return "tsv"
    if b"," in first_line:
        return "csv"
    
    lower_rel = rel.lower()
    if lower_rel.endswith(".json"):
        return "json"
    if lower_rel.endswith(".csv"):
        return "csv"
    if lower_rel.endswith(".tsv"):
        return "tsv"
    if lower_rel.endswith((".txt", ".text", ".note", ".md")):
        return "text"
    
    # Check if mostly valid text
    try:
        raw.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        pass
    
    return "unsupported"
