# 10 · Field Research

Domain knowledge + measured facts about the practice data. Verify any external fact before relying on it in the brief.

## 1. Practice dataset, measured (from `dev/truth/truth.json`, 2026-11-26)

| Fact | Value |
|---|---|
| Files | 200 (192 must be sanitized, 8 "either": fine to quarantine) |
| Formats | text 101 · json 60 · fhir 19 · csv 16 · tsv 1 · xml 1 · pdf 1 · binary 1 |
| Encodings | utf-8 196 · utf-8-sig 2 · utf-16 1 · cp1252 1 |
| Patients | 48 · scoring units (records) 883 → link `required` 771 · `none` 110 · `ambiguous` 2 |
| PII mentions by type | PATIENT_NAME 962 · MRN 850 · PHONE 308 · RELATIVE_NAME 232 · VILLAGE 150 · HOUSE 136 · PIN 136 · DOB 111 · LOCALITY 103 · AADHAAR 71 · LANDMARK 64 · ABHA_NUMBER 46 · PAN 22 · INSURANCE_ID 22 · AADHAAR_MASKED 16 · CANARY 4 · EMAIL 1 |
| By script | latin 2,980 · deva 143 · hinglish 111 |
| By hiding channel | content 3,115 · filename 48 · metadata 40 · key 12 · base64 11 · header 8 |
| Roles | patient 3,002 · relative 232 |
| Traps | 2 language · 2 fragmented · 2 meaning · 2 re-identification · 2 homonym pairs · 4 canaries |

**Implications:**
- Devanagari and Hinglish are only about 8% of mentions, but recall is **macro-averaged per script**, so they're worth about two-thirds of the script half of recall. Don't neglect them.
- MRN is the 2nd most common type. Get every hospital ID style right.
- 48 file names hold PII. Renaming files is mandatory.
- Hidden data is **larger** and has new patients and unseen formats.

## 2. Folder-by-folder notes (from the kit's START_HERE)

| Folder | What's tricky |
|---|---|
| registration/ | 4 systems: Sanjeevani CSV (UTF-8 BOM, day-first, plus a duplicate `(1).csv`), Jeevan Jyoti TSV (**UTF-16**, Hindi headers), Arogya legacy CSV (**cp1252**, **month-first** dates, split first/last name, ragged multi-line rows), District Hospital Hardoi JSON (Aadhaar as a **number** under a misspelled key) |
| opd/ | nested JSON; PII in metadata (`"source_path": "D:\\HIS\\exports\\opd\\Anita_Sharma_010565\\..."`) |
| prescriptions/ | Hindi: `नाम: सुनीता पटेल आयु: 54 वर्ष ग्राम: भीमपुर तारीख: 19.08.2026`; doses like `1-0-1 x 5 days` |
| discharge/ | admission/discharge dates: the stay length must be exact |
| notes/ | Hinglish: `Shahid sahab ka BP 117/82`, `Mohd. Shahid - K/C/O addison's disease`, `S/o Zubair` |
| lab/ | phone numbers in file names (`7148988804_report_0047.json`); WhatsApp forwards `Asha ji 48 Y / F` |
| fhir/ | IDs in `meta.source`, `identifier`, references; narrative `text.div`; base64 attachments |
| billing/ | insurance IDs, PAN, MRNs |
| misc/ | PDF, JPG, XML (HL7 CDA), corrupt bytes, empty CSV, truncated JSON, 1,500-deep JSON, base64 "scanned" form, helpdesk tickets, JSON mislabeled as `.csv` |
| clean/ | protocols, formulary, lab ranges: no PII; **must not be damaged** |

## 3. Indian identifier formats

| ID | Format | Detection notes |
|---|---|---|
| Mobile | 10 digits starting 6–9; prefixes `+91`, `91`, `0`; spaces or dashes (`+91 72864 90658`, `072864-90658`) | also masked `98XXXXXX10`; Devanagari digits |
| Aadhaar | 12 digits, first digit 2–9, last digit = **Verhoeff** checksum; often `XXXX XXXX XXXX` | the Verhoeff check cuts false positives from other 12-digit numbers; masked `XXXX XXXX 1234` |
| ABHA number | 14 digits, usually `NN-NNNN-NNNN-NNNN` (e.g. `91-7938-3729-8403`) | |
| ABHA address | `handle@abdm` (sandbox: `@sbx`) | email-like regex |
| PAN | `AAAAA9999A`; 4th letter = holder type (`P` = individual) | |
| PIN code | 6 digits, first digit 1–9; Uttar Pradesh PINs start with 20–28 | don't confuse with lab values; use context or column |
| UHID / MRN | hospital-specific: `SNJ/26/064127`, `UHID-010610`, `ADM000161`, `IP-26-00134` | learn shapes generically: letters + separators + 4–7 digits |
| Doses / frequencies | `650 mg`, `1-0-1`, `1-1-1 x 5 days`, `BD/TDS/OD/HS/SOS` | must **not** be read as phones/IDs |

## 4. Indian name structures

- **Order:** given + surname ("Mahesh Chauhan"); surname first in legacy exports ("Patel, Ashok"); split columns.
- **Generic tokens that don't identify anyone alone:** Kumar, Kumari, Devi, Singh (when alone), Md./Mohd., ji, Bai, Ben, Lal, Prasad (context-dependent). The scorer explicitly treats *Devi, Kumar, Md., ji* as non-identifying, so removing them is optional; the identifying tokens are what matter.
- **Honorifics:** ji, sahab/saheb, didi, behenji, bhaiya, amma, chacha, Shri/Sri/श्री, Smt./श्रीमती, Kumari/कुमारी, Mr/Mrs/Ms.
- **Relations:** S/o (son of), D/o (daughter of), W/o (wife of), H/o (husband of; careful, also "history of"), C/O (care of vs complaint of), F/o, M/o. Hindi: पुत्र, पुत्री, पत्नी, पति, पिता, माता, "पिता का नाम", "पति का नाम".
- **Transliteration variants:** Mohammad/Mohammed/Muhammad/Mohd/Md./मोहम्मद · Sunita/Suneeta/सुनीता · Laxmi/Lakshmi/लक्ष्मी · Shahid/Sahid/शाहिद · v/w, sh/s, aa/a, ee/i, oo/u, ph/f.
- **Hindi labels:** नाम (name), आयु / उम्र (age), वर्ष (years), ग्राम / गांव (village), पता (address), तारीख / दिनांक (date), मोबाइल / फोन (phone), लिंग (gender), पुरुष / महिला (male/female), जिला (district), तहसील (tehsil).
- **Hinglish clinical words** (keep): bukhar (fever), khansi (cough), dard (pain), ulti (vomiting), dast (diarrhoea), neend (sleep), diya (given), "BP ka", "sugar".

## 5. Privacy standards and concepts (for design and the brief)

- **k-anonymity** (Sweeney): every record is indistinguishable from ≥ k−1 others on its quasi-identifiers. Sweeney showed ZIP + gender + full DOB uniquely identifies about 87% of the US population, which is why exact DOB/PIN/village are dangerous.
- **l-diversity:** each k-group should have diverse sensitive values (a group where everyone has the rare disease still leaks).
- **HIPAA Safe Harbor:** 18 identifiers; remove all date elements except year; ages ≥ 90 aggregated to "90+"; ZIP reduced to 3 digits (if the area is populous). We mirror these ideas for India.
- **India DPDP Act 2023:** consent-based processing of digital personal data; de-identified research data reduces obligations. **ABDM** health-data guidelines govern ABHA. (Cite carefully in the brief; one line is enough.)
- **Date shifting:** a per-patient random offset preserves intervals. A single global offset is recoverable (the kit's attacker A5 does exactly this).
- **Keyed pseudonyms:** HMAC with a secret key, not plain hashing. Unkeyed hashes of known IDs are inverted by dictionary (attack A6).
- **Record linkage:** Fellegi–Sunter; blocking; avoid transitive over-merging (A~B, B~C ⇒ A~C can chain different people together).

## 6. The attacker, summarized (from kit `docs/ATTACKS.md`)

- Knows: the full-population registry (4–5× the patients) with names, relative, gender, age, house, mohalla, village, tehsil, district, PIN; leaked phone/email/Aadhaar-last-4 for 60% of people; known facts (visit date, hospital, rare condition, length of stay) for about 30% + every re-identification-trap patient, plus decoys.
- Filters candidates by phone → email → last-4 → masked phone → district → gender → age range → birth year → tehsil → village → PIN → PIN prefix. A filter that would empty the set is **skipped**.
- Weights: full name ×60, given name ×8, surname ×3, relative ×8, house ×2.
- Reference results: A3 27.7% · A4 16.7% · A5 40.1%. Rare diagnosis + exact band + district is the main remaining weakness, which is why we do **targeted** coarsening.

## 7. Library notes (verify versions when pinning)

| Need | Library | Note |
|---|---|---|
| Transliteration | `indic-transliteration` (sanscript) | Devanagari ↔ ITRANS/IAST/HK; we still need custom spelling-variant rules for names |
| Fuzzy / phonetic | `rapidfuzz`, `jellyfish` | jellyfish metaphone/soundex is English-centric; build our own Indian phonetic key |
| Phones | `phonenumbers` | may be slower than a regex; regex is enough for the IN format |
| Dates | stdlib `datetime` + our own format table | `dateparser` is slow and ambiguous; we must preserve the format anyway |
| Crypto | stdlib `hmac`, `hashlib`; `cryptography` only if AES-GCM is needed | |
| Synthetic test data | `Faker` (`en_IN`, `hi_IN`) | tools only, not the product |
| Risk measurement | own `attack_sim.py`; optional `pycanon` | |
