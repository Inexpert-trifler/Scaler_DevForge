"""Single source of truth data models for WardGuard.

Matches project-docs/06_DATA_MODELS.md exactly.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

Script = Literal["latin", "deva", "hinglish"]
Channel = Literal["content", "filename", "header", "key", "metadata", "base64"]
Role = Literal["patient", "relative", "unknown"]
Source = Literal["regex", "column", "context", "gazetteer", "hidden"]
Fmt = Literal["csv", "tsv", "json", "fhir", "text", "unsupported"]
Status = Literal["pending", "sanitized", "quarantined", "suppressed"]
ValueType = Literal["str", "int", "float", "bool", "null"]


class EType(str, Enum):
    # --- direct identifiers (REMOVED or replaced) — names match truth.json types
    PATIENT_NAME = "PATIENT_NAME"
    RELATIVE_NAME = "RELATIVE_NAME"
    MRN = "MRN"  # UHID / IPD / ADM / hospital IDs
    PHONE = "PHONE"
    AADHAAR = "AADHAAR"
    AADHAAR_MASKED = "AADHAAR_MASKED"
    ABHA_NUMBER = "ABHA_NUMBER"
    ABHA_ADDRESS = "ABHA_ADDRESS"
    PAN = "PAN"
    INSURANCE_ID = "INSURANCE_ID"
    EMAIL = "EMAIL"
    HOUSE = "HOUSE"
    LANDMARK = "LANDMARK"
    LOCALITY = "LOCALITY"  # mohalla / ward / street
    OTHER_PERSON = "OTHER_PERSON"  # person name, unknown role (still removed)
    # --- quasi-identifiers (GENERALIZED, not deleted)
    DOB = "DOB"
    AGE = "AGE"
    DATE = "DATE"  # clinical/event dates -> shifted
    VILLAGE = "VILLAGE"
    PIN = "PIN"
    TEHSIL = "TEHSIL"
    DISTRICT = "DISTRICT"
    GENDER = "GENDER"


DIRECT = {
    EType.PATIENT_NAME,
    EType.RELATIVE_NAME,
    EType.MRN,
    EType.PHONE,
    EType.AADHAAR,
    EType.AADHAAR_MASKED,
    EType.ABHA_NUMBER,
    EType.ABHA_ADDRESS,
    EType.PAN,
    EType.INSURANCE_ID,
    EType.EMAIL,
    EType.HOUSE,
    EType.LANDMARK,
    EType.LOCALITY,
    EType.OTHER_PERSON,
}

QUASI = {
    EType.DOB,
    EType.AGE,
    EType.DATE,
    EType.VILLAGE,
    EType.PIN,
    EType.TEHSIL,
    EType.DISTRICT,
    EType.GENDER,
}


@dataclass(slots=True)
class Mention:
    """One detected PII / quasi-identifier span inside a Slot's text."""
    etype: EType
    start: int  # char offset in Slot.text (inclusive)
    end: int  # char offset in Slot.text (exclusive)
    text: str  # == slot.text[start:end]
    script: Script
    channel: Channel
    role: Role = "unknown"
    source: Source = "regex"
    confidence: float = 1.0  # rewrite applies when >= policy.min_confidence


@dataclass(slots=True)
class Slot:
    """One string-bearing location of a record that can contain PII."""
    path: str  # e.g. "col:Name", "doc", etc.
    text: str  # decoded string form of the value
    channel: Channel
    value_type: ValueType = "str"  # original JSON type; CSV/text always "str"
    column_type: Optional[EType] = None  # set by detect.columns for structured cells
    mentions: list[Mention] = field(default_factory=list)


@dataclass(slots=True)
class Evidence:
    """Identity clues of the PATIENT of a unit (filled by detect, used by link)."""
    name_keys: tuple[str, ...] = ()  # canonical Latin full-name keys, sorted
    given_keys: tuple[str, ...] = ()
    surname_keys: tuple[str, ...] = ()
    relative_keys: tuple[str, ...] = ()
    dob: Optional[str] = None  # ISO yyyy-mm-dd (true, unshifted)
    age: Optional[int] = None
    gender: Optional[Literal["M", "F"]] = None
    village_key: Optional[str] = None
    district_key: Optional[str] = None
    strong_ids: tuple[tuple[str, str], ...] = ()  # (EType.value, normalized core), sorted
    dates: tuple[str, ...] = ()  # ISO dates seen in the unit (true)


@dataclass(slots=True)
class Unit:
    """A scoring record: CSV row, JSON-pointer record, or whole doc."""
    uid: str  # f"{file_rel}#{loc}" - unique, stable
    file_rel: str  # input-relative path, POSIX style
    loc: str  # "row:N" | "/visits/3" | "doc"
    slots: list[Slot] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)
    patient_bearing: bool = False  # True if any patient PII/evidence found
    cluster: Optional[str] = None  # canonical cluster key (link)
    psn: Optional[str] = None  # "PSN-XXXXXX" (privacy)
    date_offset: Optional[int] = None  # days (privacy)
    coarsen: bool = False  # k-anon rare record (privacy.kanon)


@dataclass(slots=True)
class ParsedFile:
    rel: str  # input-relative path
    sha256: str  # of raw input bytes
    size: int
    fmt: Fmt
    encoding: Optional[str] = None  # "utf-8" | "utf-8-sig" | "utf-16" | "cp1252"
    delimiter: Optional[str] = None
    header: Optional[list[str]] = None
    rows: Optional[list[list[str]]] = None  # csv/tsv data rows (no header)
    obj: Any = None  # parsed JSON / FHIR
    text: Optional[str] = None  # text docs
    units: list[Unit] = field(default_factory=list)
    file_slots: list[Slot] = field(default_factory=list)  # @filename, @header, file-level keys/metadata
    status: Status = "pending"
    reason: Optional[str] = None  # generic token only, e.g. "unsupported_format"
    out_rel: Optional[str] = None  # "sanitized/<path>" (may be renamed)


@dataclass(slots=True)
class RunStats:
    records_processed: int = 0
    identifiers_detected: int = 0
    records_linked: int = 0
    records_generalized: int = 0
    records_suppressed: int = 0
    records_quarantined: int = 0
    entities: dict[str, int] = field(default_factory=dict)  # EType.value -> count
