# 06 · Data Models

> **Single source of truth:** `wardguard/model.py`. This doc and that file must match.
> `model.py` is **jointly owned** and **frozen at M0 (H2)**. After that, any change needs a `tracking/DECISIONS.md` entry and a heads-up to your partner, because both halves of the code depend on it.

## 1. Enums and literals

```python
# wardguard/model.py
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

Script  = Literal["latin", "deva", "hinglish"]
Channel = Literal["content", "filename", "header", "key", "metadata", "base64"]
Role    = Literal["patient", "relative", "unknown"]
Source  = Literal["regex", "column", "context", "gazetteer", "hidden"]
Fmt     = Literal["csv", "tsv", "json", "fhir", "text", "unsupported"]
Status  = Literal["pending", "sanitized", "quarantined", "suppressed"]
ValueType = Literal["str", "int", "float", "bool", "null"]

class EType(str, Enum):
    # --- direct identifiers (REMOVED or replaced) — names match truth.json types
    PATIENT_NAME   = "PATIENT_NAME"
    RELATIVE_NAME  = "RELATIVE_NAME"
    MRN            = "MRN"            # UHID / IPD / ADM / hospital IDs
    PHONE          = "PHONE"
    AADHAAR        = "AADHAAR"
    AADHAAR_MASKED = "AADHAAR_MASKED"
    ABHA_NUMBER    = "ABHA_NUMBER"
    ABHA_ADDRESS   = "ABHA_ADDRESS"
    PAN            = "PAN"
    INSURANCE_ID   = "INSURANCE_ID"
    EMAIL          = "EMAIL"
    HOUSE          = "HOUSE"
    LANDMARK       = "LANDMARK"
    LOCALITY       = "LOCALITY"       # mohalla / ward / street
    OTHER_PERSON   = "OTHER_PERSON"   # person name, unknown role (still removed)
    # --- quasi-identifiers (GENERALIZED, not deleted)
    DOB      = "DOB"
    AGE      = "AGE"
    DATE     = "DATE"                 # clinical/event dates → shifted
    VILLAGE  = "VILLAGE"
    PIN      = "PIN"
    TEHSIL   = "TEHSIL"
    DISTRICT = "DISTRICT"
    GENDER   = "GENDER"

DIRECT = {EType.PATIENT_NAME, EType.RELATIVE_NAME, EType.MRN, EType.PHONE, EType.AADHAAR,
          EType.AADHAAR_MASKED, EType.ABHA_NUMBER, EType.ABHA_ADDRESS, EType.PAN,
          EType.INSURANCE_ID, EType.EMAIL, EType.HOUSE, EType.LANDMARK, EType.LOCALITY,
          EType.OTHER_PERSON}
QUASI  = {EType.DOB, EType.AGE, EType.DATE, EType.VILLAGE, EType.PIN, EType.TEHSIL,
          EType.DISTRICT, EType.GENDER}
```

## 2. Core dataclasses

```python
@dataclass(slots=True)
class Mention:
    """One detected PII / quasi-identifier span inside a Slot's text."""
    etype: EType
    start: int                 # char offset in Slot.text (inclusive)
    end: int                   # char offset in Slot.text (exclusive)
    text: str                  # == slot.text[start:end]
    script: Script
    channel: Channel
    role: Role = "unknown"
    source: Source = "regex"
    confidence: float = 1.0    # rewrite applies when >= policy.min_confidence

@dataclass(slots=True)
class Slot:
    """One string-bearing location of a record that can contain PII."""
    path: str                  # see §3 "Slot paths"
    text: str                  # decoded string form of the value
    channel: Channel
    value_type: ValueType = "str"      # original JSON type; CSV/text always "str"
    column_type: Optional[EType] = None  # set by detect.columns for structured cells
    mentions: list[Mention] = field(default_factory=list)

@dataclass(slots=True)
class Evidence:
    """Identity clues of the PATIENT of a unit (filled by detect, used by link)."""
    name_keys: tuple[str, ...] = ()       # canonical Latin full-name keys, sorted
    given_keys: tuple[str, ...] = ()
    surname_keys: tuple[str, ...] = ()
    relative_keys: tuple[str, ...] = ()
    dob: Optional[str] = None             # ISO yyyy-mm-dd (true, unshifted)
    age: Optional[int] = None
    gender: Optional[Literal["M", "F"]] = None
    village_key: Optional[str] = None
    district_key: Optional[str] = None
    strong_ids: tuple[tuple[str, str], ...] = ()   # (EType.value, normalized core), sorted
    dates: tuple[str, ...] = ()           # ISO dates seen in the unit (true)

@dataclass(slots=True)
class Unit:
    """A scoring record: CSV row, JSON-pointer record, or whole doc."""
    uid: str                   # f"{file_rel}#{loc}" — unique, stable
    file_rel: str              # input-relative path, POSIX style
    loc: str                   # "row:N" | "/visits/3" | "doc"
    slots: list[Slot] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)
    patient_bearing: bool = False      # True if any patient PII/evidence found
    cluster: Optional[str] = None      # canonical cluster key (link)
    psn: Optional[str] = None          # "PSN-XXXXXX" (privacy)
    date_offset: Optional[int] = None  # days (privacy)
    coarsen: bool = False              # k-anon rare record (privacy.kanon)

@dataclass(slots=True)
class ParsedFile:
    rel: str                   # input-relative path
    sha256: str                # of raw input bytes
    size: int
    fmt: Fmt
    encoding: Optional[str] = None     # "utf-8" | "utf-8-sig" | "utf-16" | "cp1252"
    delimiter: Optional[str] = None
    header: Optional[list[str]] = None
    rows: Optional[list[list[str]]] = None   # csv/tsv data rows (no header)
    obj: Any = None                    # parsed JSON / FHIR
    text: Optional[str] = None         # text docs
    units: list[Unit] = field(default_factory=list)
    file_slots: list[Slot] = field(default_factory=list)  # @filename, @header, file-level keys/metadata
    status: Status = "pending"
    reason: Optional[str] = None       # generic token only, e.g. "unsupported_format"
    out_rel: Optional[str] = None      # "sanitized/<path>" (may be renamed)

@dataclass(slots=True)
class RunStats:
    records_processed: int = 0
    identifiers_detected: int = 0
    records_linked: int = 0
    records_generalized: int = 0
    records_suppressed: int = 0
    records_quarantined: int = 0
    entities: dict[str, int] = field(default_factory=dict)   # EType.value -> count
```

## 3. Slot paths (naming convention, used everywhere)

| Where | `Slot.path` | channel |
|---|---|---|
| CSV/TSV cell | `col:<header name>` (or `col#<index>` if the header is empty or duplicated) | content |
| CSV header cell | `@header:<index>` (file_slots) | header |
| JSON string/number leaf | RFC 6901 pointer, e.g. `/visits/3/patient/name` | content |
| JSON key | `@key:<pointer of the parent>/<key>` | key |
| JSON metadata (export info, `source_path`, `meta.source`) | its pointer | metadata |
| base64 payload (decoded) | `<pointer>#b64` | base64 |
| Text document | `doc` | content |
| File name stem | `@filename` (file_slots) | filename |

## 4. Policy (`config/policy.yaml`)

```yaml
age_band_years: 5          # band width; band must contain the true age
age_top_code: 90           # ages >= 90 -> "90+"
date_shift_max_days: 180   # per-patient offset in [-180, 180] \ {0}
k_min: 5                   # k-anonymity threshold for targeted coarsening
min_confidence: 0.5        # mentions below are ignored
pin_keep_digits: 3         # 229073 -> 229***
village_action: tehsil     # tehsil | district | remove
dob_action: year           # year | shift   (see DECISIONS D-012)
link_age_tolerance: 1
link_conflict_age_gap: 2
psn_prefix: "PSN-"
tokens:                    # replacement tokens
  PATIENT_NAME: "[NAME]"   # replaced by the PSN when the unit has one
  RELATIVE_NAME: "[RELATIVE]"
  PHONE: "[PHONE]"
  AADHAAR: "[AADHAAR]"
  AADHAAR_MASKED: "[AADHAAR]"
  ABHA_NUMBER: "[ABHA]"
  ABHA_ADDRESS: "[ABHA]"
  PAN: "[PAN]"
  MRN: "[MRN]"
  INSURANCE_ID: "[INSURANCE]"
  EMAIL: "[EMAIL]"
  HOUSE: "[ADDRESS]"
  LANDMARK: "[ADDRESS]"
  LOCALITY: "[ADDRESS]"
  OTHER_PERSON: "[NAME]"
```

## 5. Output models (external, fixed by the kit SPEC)

```jsonc
// report.json  (schema "raksha-report/1")
{ "schema": "raksha-report/1",
  "files": [ {"input_sha256": "…", "output": "sanitized/x/y.csv" | null,
              "status": "sanitized|quarantined|suppressed", "reason": "unsupported_format"} ],
  "counts": {"files_total":0,"files_sanitized":0,"files_quarantined":0,"records_processed":0,
             "identifiers_detected":0,"records_linked":0,"records_generalized":0,
             "records_suppressed":0,"records_quarantined":0},
  "entities": {"PATIENT_NAME": 0, "PHONE": 0},
  "timing": {"seconds": 0.0}, "resources": {"peak_rss_mb": 0.0} }

// records.jsonl — one line per patient-bearing unit of a WRITTEN file, sorted by (file, loc)
{"file": "sanitized/opd/x.json", "loc": "/visits/3", "patient": "PSN-7Q2K9D"}
{"file": "sanitized/notes/n.txt", "loc": "doc", "patient": null}
```

## 6. Ground-truth model (practice only, read by tools, NEVER by `wardguard/`)

`dev/truth/truth.json` keys: `files{rel: {sha256, encoding, delimiter, format, expect, units{loc: {patient, cid, link, tags, entities[], preserve[], dates[], fields[], exclude}}}}`, `patients`, `traps`, `linkability`, `canaries`.
Entity keys: `type, surface, person, role, script, channel, match, key, critical`.
The product code must **never** read truth or attacker files. Only `tools/` may.
