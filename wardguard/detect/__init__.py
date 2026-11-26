"""Detection package stubs (Saransh's domain)."""
from typing import List, Set, Tuple
from wardguard.model import Channel, EType, Mention, ParsedFile, Role


class Gazetteer:
    """Stub gazetteer for names and spelling variants."""
    def add(self, name: str, role: Role) -> None:
        pass

    def variants(self, name: str) -> Set[str]:
        return set()

    def find(self, text: str) -> List[Tuple[int, int, Role, str]]:
        return []


def build_gazetteer(files: List[ParsedFile], policy: dict) -> Gazetteer:
    """Stub: harvest names from slots."""
    return Gazetteer()


def detect_file(pf: ParsedFile, gaz: Gazetteer, policy: dict) -> None:
    """Stub: detection pass for a file."""
    pass


def detect_text(text: str, channel: Channel, gaz: Gazetteer, policy: dict) -> List[Mention]:
    """Stub: free-text detection."""
    return []


def classify_column(header: str, values: List[str]) -> EType | None:
    """Stub: column classification."""
    return None


def find_identifiers(text: str) -> List[Mention]:
    """Stub: regex pattern identifier finder."""
    return []


def is_protected(text: str, start: int, end: int) -> bool:
    """Stub: guard checking."""
    return False


def normalize_for_match(text: str) -> str:
    """Stub: normalization."""
    return text
