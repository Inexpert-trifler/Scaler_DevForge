# 07 · API Contracts

There are two kinds of contract:
- **(A) External:** fixed by the organizers. We can't change it.
- **(B) Internal:** the module interfaces between Lakshya's and Saransh's code. Frozen at M0 (H2). Changing one needs a DECISIONS entry.

> Rule for AI assistants: **never invent a function that isn't listed here.** If you need one, propose an addition (in the session's tracking updates) instead of silently creating it in someone else's module.

---

## A. External contracts (from kit `docs/SPEC.md`)

### A1. `raksha.toml` (repo root)
```toml
[submission]
name  = "team-wardguard"                                   # change to the real team name
setup = "pip install -r requirements.txt"                  # network allowed, 30 min
run   = "python main.py --input {input} --output {output}" # NO network
```

### A2. CLI
```
python main.py --input <dir> --output <empty dir>
env: RAKSHA_SECRET (required), RAKSHA_INPUT, RAKSHA_OUTPUT, RAKSHA_CPUS (optional)
exit 0  = release complete (report.json present, every input accounted for)
exit !=0 = fatal (never exit 0 with missing outputs)
```

### A3. Output folder
```
{output}/sanitized/…        mirror of input (UTF-8), renamed only if the file name has PII
{output}/report.json        REQUIRED  (schema in 06_DATA_MODELS §5)
{output}/records.jsonl      REQUIRED for linkage credit
{output}/logs/              optional, scanned for PII → we don't create it
{output}/quarantine/        optional, not scanned → we don't use it (simpler and safer)
```

### A4. Locators
`row:N` (0-based, header excluded) · RFC 6901 pointer (`/visits/3`) · `doc`. The evaluator matches each truth record to the **longest** loc we report for that file.

---

## B. Internal contracts (Python signatures)

Owner: **L** = Lakshya, **S** = Saransh. "Pure" = no I/O, no globals mutated.

### B1. Pipeline (L): `wardguard/pipeline.py`
```python
def run(input_dir: Path, output_dir: Path, secret: bytes, policy: dict) -> int:
    """Whole run. Returns the exit code. Never raises (fatal errors → exit 2, report still written if possible)."""
```
Order of calls (fixed):
```
files = ingest.load_all(input_dir)                       # L
for pf in files: ingest.units.enumerate_units(pf)        # L
for pf in files: detect.hidden.extract_hidden_slots(pf)  # L
gaz   = detect.build_gazetteer(files, policy)            # S
for pf in files: detect.detect_file(pf, gaz, policy)     # S
units = [u for pf in files if pf.status=="pending" for u in pf.units]
link.resolve(units, policy)                              # S
privacy.assign_identity(units, secret, policy)           # L
privacy.kanon.plan(units, policy)                        # L
for pf in files: export.write_file(pf, output_dir, policy)   # L (calls rewrite.render)
export.write_records(files, output_dir)                  # L
export.write_report(files, stats, output_dir, t0)        # L
```

### B2. Ingestion (L): `wardguard/ingest/`
```python
def load_all(input_dir: Path) -> list[ParsedFile]:
    """Sorted by rel path. Never raises. Unsupported/broken → status='quarantined', reason=generic token.
    Reads bytes once; computes sha256; never writes to input_dir."""

def sniff(raw: bytes, rel: str) -> Fmt                       # content-based
def decode(raw: bytes) -> tuple[str, str] | None             # (text, encoding) or None
def enumerate_units(pf: ParsedFile) -> None                  # fills pf.units with Slots (content channel)
```

### B3. Hidden channels (L): `wardguard/detect/hidden.py`
```python
def extract_hidden_slots(pf: ParsedFile) -> None:
    """Adds Slots for: @filename, @header:i, @key:…, metadata pointers, base64 payloads (decoded),
    \\uXXXX / HTML-entity / %-encoded strings (decoded). Attaches them to the right unit or pf.file_slots."""
```

### B4. Detection (S): `wardguard/detect/`
```python
def build_gazetteer(files: list[ParsedFile], policy: dict) -> Gazetteer:
    """Harvest names from slots classified as name columns; add transliteration/spelling variants."""

class Gazetteer:
    def add(self, name: str, role: Role) -> None
    def variants(self, name: str) -> set[str]
    def find(self, text: str) -> list[tuple[int, int, Role, str]]   # (start, end, role, canonical_key), sorted

def detect_file(pf: ParsedFile, gaz: Gazetteer, policy: dict) -> None:
    """For every unit and file_slot: set slot.column_type (structured), slot.mentions,
    unit.evidence, unit.patient_bearing. Pure w.r.t. I/O. Deterministic."""

def detect_text(text: str, channel: Channel, gaz: Gazetteer, policy: dict) -> list[Mention]:
    """Free-text detector used for docs AND hidden channels. Non-overlapping, sorted by start."""

def classify_column(header: str, values: list[str]) -> EType | None     # columns.py
def find_identifiers(text: str) -> list[Mention]                       # patterns.py
def is_protected(text: str, start: int, end: int) -> bool              # guards.py (dose/Dr./eponym/…)
def normalize_for_match(text: str) -> str                              # NFKC, digits, zero-width, homoglyphs
```
Mention rules: spans are non-overlapping (the longer span wins; on a tie, the higher-priority type wins), offsets index into `slot.text`, and guards are applied before emitting.

### B5. Linkage (S): `wardguard/link/`
```python
def resolve(units: list[Unit], policy: dict) -> None:
    """Sets unit.cluster for linked units, None otherwise. Deterministic (sort inputs; never iterate sets
    unsorted). Implements TR-LNK-1..7. Must not read slots' raw text beyond unit.evidence."""

def canonical_name(name: str) -> str          # Latin, lowercase, generic tokens removed, variants unified
def phonetic_key(name: str) -> str
```

### B6. Privacy (L): `wardguard/privacy/`
```python
def pseudonym(cluster_key: str, secret: bytes, policy: dict) -> str          # PSN-XXXXXX
def date_offset(key: str, secret: bytes, policy: dict) -> int               # [-max,max]\{0}
def assign_identity(units: list[Unit], secret: bytes, policy: dict) -> None # psn + date_offset for all units
def shift_date_text(s: str, offset: int) -> str | None   # same format out; None if not a date
def age_band(age: int, policy: dict) -> str               # "45-49", "90+"
def generalize_pin(pin: str, policy: dict) -> str          # "229***"
def plan(units: list[Unit], policy: dict) -> None          # kanon.py: sets unit.coarsen
```

### B7. Rewrite and export (L): `wardguard/rewrite.py`, `wardguard/export/`
```python
def render(pf: ParsedFile, policy: dict) -> bytes:
    """Apply every mention (DIRECT → token / PSN; QUASI → shift/band/prefix/generalize) to every slot,
    put the PSN inside each patient-bearing unit, rebuild the file in its ORIGINAL format, UTF-8."""
def write_file(pf, output_dir, policy) -> None     # render → write; on any exception → quarantine
def write_records(files, output_dir) -> None
def write_report(files, stats, output_dir, t0) -> None
```

### B8. Safety (L): `wardguard/safety/log.py`
```python
def event(name: str, **counts: int) -> None    # name must be a fixed literal; values must be ints
def safe_reason(exc: BaseException) -> str     # → type(exc).__name__ only
```

### B9. Tools (outside the product; may read truth/attacker files)
```
tools/eval.sh  [input_dir]                     (L)  → prints and appends a score line
tools/attack_sim.py --release out --attacker ../Secret-Wards-ToolKit/dev/attacker   (L)
tools/chaos_gen.py --src ../Secret-Wards-ToolKit/dev/input --dst ../chaos/input --seed 7 (S)
```

## C. Contract change log
| Date | Change | Approved by |
|---|---|---|
| 2026-11-26 | v1.0 created and frozen at Milestone M0 | Lakshya, Saransh (Approved at M0) |
