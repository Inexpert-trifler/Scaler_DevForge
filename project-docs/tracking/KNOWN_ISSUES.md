# Known Issues and Limitations

> Bugs, gaps and honest limitations. Severity: `S1` (leak / crash / penalty) · `S2` (score loss) · `S3` (minor).
> Move fixed items to the bottom section and reference the commit. The "Limitations" section feeds the README and brief.

## Open

| ID | Sev | Issue | Found by | Owner | Notes |
|---|---|---|---|---|---|
| KI-001 | S2 | Nothing built yet; the repo still has the hello-world `src/` | planning | Lakshya | Fixed by L-01 |
| KI-002 | S2 | XML (HL7 CDA), PDF and JPG are quarantined, not sanitized, so any medical value in them is lost | design | – | Accepted limitation (D-008); X-1 stretch |
| KI-003 | S3 | Unseen-format dataset contents are unknown; only our chaos set approximates it | design | Saransh | RK-01 |

## Limitations to state in the brief (keep updated)
- Rule- and lexicon-based detection: very unusual name spellings with no context may be missed.
- Quarantined files (PDF/JPG/XML) are excluded from the release.
- k-anonymity is computed on our chosen quasi-identifier set; it isn't proof of anonymity against every attack.

## Fixed

| ID | Fixed in | Note |
|---|---|---|
| – | – | – |
