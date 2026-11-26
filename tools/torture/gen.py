"""Torture dataset generator for WardGuard (development tool, never imported by main.py).

Produces a messy multi-hospital dump plus an answer key:

  <out>/input/...            files to feed to main.py
  <out>/answer.json          what must be removed, what must be kept, who is who

Everything is synthetic and derived from one seed (same seed -> same bytes).
The name/village lists here are deliberately NOT copied from resources/, and they
include spellings and regions the product lexicons do not contain, so the run
measures generalization instead of memorization.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------------------
# Lexicons (lab-owned, synthetic)
# --------------------------------------------------------------------------------------
GIVEN_F = [
    ("Sunita", "सुनीता"), ("Kavita", "कविता"), ("Rekha", "रेखा"), ("Savitri", "सावित्री"),
    ("Rukhsana", "रुख़साना"), ("Shabnam", "शबनम"), ("Gurpreet", "गुरप्रीत"), ("Philomena", "फिलोमिना"),
    ("Debjani", "देबजानी"), ("Lalremruati", "ललरेमरुआती"), ("Thamizhselvi", "तमिलसेल्वी"), ("Oishee", "ओइशी"),
    ("Bhagwati", "भगवती"), ("Champa", "चंपा"), ("Phoolmati", "फूलमती"), ("Nirmala", "निर्मला"),
    ("Jasoda", "जसोदा"), ("Munni", "मुन्नी"), ("Tabassum", "तबस्सुम"), ("Kalavati", "कलावती"),
]
GIVEN_M = [
    ("Ramesh", "रमेश"), ("Shivnath", "शिवनाथ"), ("Jagdish", "जगदीश"), ("Imran", "इमरान"),
    ("Harjinder", "हरजिंदर"), ("Anthony", "एंथनी"), ("Subhendu", "शुभेंदु"), ("Lalthanzuala", "ललथनज़ुआला"),
    ("Kathiresan", "कतिरेसन"), ("Bhupendra", "भूपेंद्र"), ("Chhedi", "छेदी"), ("Ramkhilawan", "रामखिलावन"),
    ("Pheku", "फेकू"), ("Dukhiram", "दुखीराम"), ("Baijnath", "बैजनाथ"), ("Tejpal", "तेजपाल"),
    ("Mehboob", "महबूब"), ("Sarvesh", "सर्वेश"), ("Ganga Prasad", "गंगा प्रसाद"), ("Ram Lakhan", "राम लखन"),
]
SURNAMES = [
    ("Yadav", "यादव"), ("Chauhan", "चौहान"), ("Nishad", "निषाद"), ("Kushwaha", "कुशवाहा"), ("Pasi", "पासी"),
    ("Rajbhar", "राजभर"), ("Siddiqui", "सिद्दीकी"), ("Gill", "गिल"), ("D'Souza", "डिसूज़ा"),
    ("Mukherjee", "मुखर्जी"), ("Hmar", "हमार"), ("Murugan", "मुरुगन"), ("Lodhi", "लोधी"), ("Kurmi", "कुर्मी"),
    ("Maurya", "मौर्य"), ("Prajapati", "प्रजापति"), ("Bind", "बिंद"), ("Saroj", "सरोज"), ("Gautam", "गौतम"),
    ("Qureshi", "क़ुरैशी"),
]
DOCTORS = ["Dr. Ramesh Srivastava", "Dr. Anjali Mehrotra", "Dr. Imran Hashmi", "Dr. Kavita Bansal",
           "Dr. Jagdish Tandon", "Dr. S. K. Awasthi"]
KIN = ["Chachu", "Mama", "Papa", "Bhaiya", "Didi", "Mausi", "Fufa", "Jiju", "Bhabhi"]
GEO = [  # (tehsil, district, pin3, tehsil_deva, district_deva)
    ("Bikapur", "Ayodhya", "224", "बीकापुर", "अयोध्या"),
    ("Musafirkhana", "Amethi", "227", "मुसाफिरखाना", "अमेठी"),
    ("Mahrajganj", "Rae Bareli", "229", "महराजगंज", "रायबरेली"),
    ("Khaga", "Fatehpur", "212", "खागा", "फतेहपुर"),
    ("Mehnagar", "Azamgarh", "276", "मेहनगर", "आज़मगढ़"),
]
VILLAGES = [
    ("Saraiya Kalan", "सरैया कलां"), ("Bhitaura", "भिटौरा"), ("Kanchanpur Khas", "कंचनपुर खास"),
    ("Rampur Mathura", "रामपुर मथुरा"), ("Pipri Buzurg", "पिपरी बुज़ुर्ग"), ("Gaura Bazar", "गौरा बाज़ार"),
    ("Lohra Dih", "लोहरा डीह"), ("Chandauli Kalan", "चंदौली कलां"), ("Basantpur Ujjaini", "बसंतपुर उज्जैनी"),
    ("Tikri Khurd", "टिकरी खुर्द"), ("Narayanpur Dih", "नारायणपुर डीह"), ("Jamunipur", "जमुनीपुर"),
]
LOCALITIES = [("Mohalla Qazi Tola", "मोहल्ला काज़ी टोला"), ("Gandhi Nagar", "गांधी नगर"),
              ("Purani Basti", "पुरानी बस्ती"), ("Harijan Basti", "हरिजन बस्ती")]
LANDMARKS = [("near Shiv Mandir", "शिव मंदिर के पास"), ("opp. Primary School", "प्राथमिक विद्यालय के सामने"),
             ("behind Panchayat Bhawan", "पंचायत भवन के पीछे"), ("near Pakki Masjid", "पक्की मस्जिद के पास")]
DIAGNOSES = [
    ("Type 2 diabetes mellitus (E11.9)", "मधुमेह"), ("Essential hypertension (I10)", "उच्च रक्तचाप"),
    ("Pulmonary tuberculosis (A15.0)", "टीबी"), ("Typhoid fever (A01.0)", "टाइफाइड"),
    ("Parkinson's disease (G20)", "पार्किंसन रोग"), ("Bell's palsy (G51.0)", "बेल्स पाल्सी"),
    ("Iron deficiency anaemia (D50.9)", "खून की कमी"), ("Acute gastroenteritis (A09)", "दस्त"),
]
MEDS = [
    "Tab Metformin 500 mg 1-0-1 x 30 days", "Tab Amlodipine 5 mg 0-0-1 x 30 days",
    "Tab Paracetamol 650 mg 1-1-1 x 5 days", "Inj Ceftriaxone 1 g IV BD x 5 days",
    "Cap Omeprazole 20 mg 1-0-0 x 14 days", "Syp Ondansetron 5 ml SOS",
    "Tab Levodopa+Carbidopa 100/25 mg 1-1-1", "Tab Ferrous sulphate 200 mg 0-1-0 x 90 days",
]
LAB_LINES = ["Hb 10.4 g/dL", "Platelets 245000 /cumm", "TSH 4.52 mIU/L", "HbA1c 8.1 %",
             "Serum Creatinine 1.3 mg/dL", "RBS 212 mg/dL", "TLC 11200 /cumm"]
VITALS = ["BP 136/88 mmHg", "Pulse 92/min", "SpO2 96%", "Temp 99.2 F"]
CLINICAL_PHRASES = ["C/O fever for 3 days", "Review in OPD after 2 weeks", "Ward 4 (Medicine) / Bed 12",
                    "K/C/O DM2 x 6 yrs", "Advised low salt diet", "Follow up with reports"]
CANARY_NAMES = [("Vexhira", "Tolumbeki"), ("Quornel", "Dabrishtan"), ("Ylvarin", "Pothemaru")]

DEVA_DIGITS = str.maketrans("0123456789", "०१२३४५६७८९")
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# Verhoeff tables (Aadhaar check digit)
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]


def verhoeff_digit(num: str) -> int:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return _INV[c]


# --------------------------------------------------------------------------------------
# World model
# --------------------------------------------------------------------------------------
@dataclass
class Person:
    pid: str
    given: tuple[str, str]
    surname: tuple[str, str]
    gender: str
    age: int
    dob: tuple[int, int, int]           # y, m, d
    rel_marker: str                     # S/o, W/o, D/o
    rel_given: tuple[str, str]
    village: tuple[str, str]
    geo: tuple[str, str, str, str, str]
    pin: str
    house: int
    locality: tuple[str, str]
    landmark: tuple[str, str]
    phone: str
    aadhaar: str
    abha: str
    pan: str
    mrn: dict[str, str] = field(default_factory=dict)
    traps: list[str] = field(default_factory=list)

    @property
    def full(self) -> str:
        return f"{self.given[0]} {self.surname[0]}"

    @property
    def full_deva(self) -> str:
        return f"{self.given[1]} {self.surname[1]}"

    @property
    def rel_full(self) -> str:
        return f"{self.rel_given[0]} {self.surname[0]}"

    @property
    def rel_full_deva(self) -> str:
        return f"{self.rel_given[1]} {self.surname[1]}"


HOSPITALS = [  # code, display name, MRN pattern id
    ("SKH", "SANKALP KISAN HOSPITAL, AYODHYA", 0),
    ("MCH", "Matri Chhaya Hospital, Amethi", 1),
    ("PHC", "Prathmik Swasthya Kendra Khaga", 2),
]


def make_mrn(rng: random.Random, code: str, pattern: int) -> str:
    n = rng.randint(10000, 999999)
    return [f"{code}-{n:07d}", f"{code}/26/{n:06d}", f"UHID{n:08d}", f"{code}.OPD.{n:06d}"][pattern]


def phone_variant(rng: random.Random, phone: str) -> tuple[str, str]:
    """Return (surface, script) for a 10-digit phone."""
    forms = [
        (phone, "latin"), (f"+91 {phone[:5]} {phone[5:]}", "latin"), (f"+91-{phone}", "latin"),
        (f"0{phone[:5]}-{phone[5:]}", "latin"), (f"{phone[:3]}-{phone[3:6]}-{phone[6:]}", "latin"),
        (f"(+91) {phone}", "latin"), (f"91 {phone[:4]} {phone[4:7]} {phone[7:]}", "latin"),
        (phone.translate(DEVA_DIGITS), "deva"),
    ]
    return rng.choice(forms)


def aadhaar_variant(rng: random.Random, a: str) -> str:
    return rng.choice([f"{a[:4]} {a[4:8]} {a[8:]}", a, f"{a[:4]}-{a[4:8]}-{a[8:]}", f"{a[:4]}.{a[4:8]}.{a[8:]}"])


def date_fmt(rng: random.Random, y: int, m: int, d: int, allow_text: bool = True) -> str:
    forms = [f"{d:02d}/{m:02d}/{y}", f"{d:02d}-{m:02d}-{y}", f"{y}-{m:02d}-{d:02d}", f"{d:02d}.{m:02d}.{y}"]
    if allow_text:
        forms += [f"{d} {MONTHS[m-1]} {y}", f"{d:02d}-{MONTHS[m-1]}-{y}"]
    return rng.choice(forms)


class Answer:
    def __init__(self) -> None:
        self.remove: list[dict[str, Any]] = []
        self.keep: list[dict[str, Any]] = []
        self.records: list[dict[str, Any]] = []   # file, loc, patient (or None)
        self.files: dict[str, dict[str, Any]] = {}
        self.homonyms: list[list[str]] = []
        self.twins: list[list[str]] = []
        self.canaries: list[str] = []
        self.los: list[dict[str, Any]] = []      # file, loc, cols (admit, discharge), days

    def rm(self, file: str, surface: str, etype: str, script: str = "latin", channel: str = "content",
           critical: bool = False, person: str | None = None, loc: str | None = None) -> None:
        self.remove.append(dict(file=file, surface=surface, type=etype, script=script, channel=channel,
                                critical=critical, person=person, loc=loc))

    def kp(self, file: str, text: str, kind: str, loc: str | None = None) -> None:
        self.keep.append(dict(file=file, text=text, kind=kind, loc=loc))


# --------------------------------------------------------------------------------------
# Generator
# --------------------------------------------------------------------------------------
class Forge:
    def __init__(self, seed: int, n_patients: int = 14, hard: bool = True) -> None:
        self.hard = hard
        self.seed = seed
        self.rng = random.Random(f"wardguard-torture:{seed}")
        self.n = n_patients
        self.ans = Answer()
        self.files: dict[str, bytes] = {}
        self.people: list[Person] = []
        self.visit_facts: dict[str, list[dict[str, Any]]] = {}

    # ---- people -------------------------------------------------------------------
    def _new_person(self, i: int) -> Person:
        r = self.rng
        gender = r.choice("MF")
        given = r.choice(GIVEN_M if gender == "M" else GIVEN_F)
        surname = r.choice(SURNAMES)
        age = r.choice([r.randint(18, 75), r.randint(18, 75), r.randint(1, 12), r.randint(88, 99)])
        dob = (2026 - age, r.randint(1, 12), r.randint(1, 28))
        rel_marker = "S/o" if gender == "M" else r.choice(["W/o", "D/o"])
        rel_given = r.choice(GIVEN_M)
        geo = r.choice(GEO)
        a11 = str(r.randint(2, 9)) + "".join(str(r.randint(0, 9)) for _ in range(10))
        return Person(
            pid=f"T{self.seed:03d}P{i:03d}", given=given, surname=surname, gender=gender, age=age, dob=dob,
            rel_marker=rel_marker, rel_given=rel_given, village=r.choice(VILLAGES), geo=geo,
            pin=geo[2] + f"{r.randint(0, 999):03d}", house=r.randint(1, 999), locality=r.choice(LOCALITIES),
            landmark=r.choice(LANDMARKS), phone=str(r.randint(6, 9)) + "".join(str(r.randint(0, 9)) for _ in range(9)),
            aadhaar=a11 + str(verhoeff_digit(a11)),
            abha=str(r.randint(1, 9)) + "".join(str(r.randint(0, 9)) for _ in range(13)),
            pan="".join(r.choice("ABCDEFGHJKLMNPRSTUVWXYZ") for _ in range(3)) + "P" + surname[0][0].upper()
                + f"{r.randint(0, 9999):04d}" + r.choice("ABCDEFGHJKLMNPRSTUVWXYZ"),
        )

    def build_people(self) -> None:
        r = self.rng
        self.people = [self._new_person(i) for i in range(self.n)]
        # homonym pair: same full name, different everything else
        a, b = self.people[0], self.people[1]
        b.given, b.surname, b.gender = a.given, a.surname, a.gender
        b.rel_marker = a.rel_marker
        while b.village == a.village:
            b.village = r.choice(VILLAGES)
        b.age = a.age + 17 if a.age < 70 else a.age - 23
        b.dob = (2026 - b.age, b.dob[1], b.dob[2])
        a.traps.append("homonym"); b.traps.append("homonym")
        self.ans.homonyms.append([a.pid, b.pid])
        # twins: same surname, dob, father, village, house; different given names and phones
        c, d = self.people[2], self.people[3]
        d.surname, d.dob, d.age, d.rel_given, d.rel_marker = c.surname, c.dob, c.age, c.rel_given, "S/o"
        c.rel_marker = "S/o"; c.gender = d.gender = "M"
        c.given = GIVEN_M[(GIVEN_M.index(c.given) if c.given in GIVEN_M else 0)]
        d.given = GIVEN_M[(GIVEN_M.index(c.given) + 1) % len(GIVEN_M)]
        d.village, d.geo, d.pin, d.house, d.locality = c.village, c.geo, c.pin, c.house, c.locality
        c.traps.append("twin"); d.traps.append("twin")
        self.ans.twins.append([c.pid, d.pid])
        # relative given name equals a doctor's given name (doctor must be kept)
        self.people[4].rel_given = ("Ramesh", "रमेश")
        self.people[4].traps.append("doctor_relative_same_name")
        for p in self.people:
            for code, _, pat in HOSPITALS:
                p.mrn[code] = make_mrn(r, code, pat)

    # ---- helpers ------------------------------------------------------------------
    def put(self, rel: str, data: bytes, fmt: str, expect: str = "sanitize") -> None:
        self.files[rel] = data
        self.ans.files[rel] = {"format": fmt, "expect": expect}

    def _rm_person_core(self, f: str, p: Person, *, deva: bool = False, channel: str = "content") -> None:
        if deva:
            self.ans.rm(f, p.full_deva, "PATIENT_NAME", "deva", channel, True, p.pid)
        else:
            self.ans.rm(f, p.full, "PATIENT_NAME", "latin", channel, True, p.pid)

    # ---- tabular --------------------------------------------------------------------
    HEADER_STYLES = {
        "english": ["Patient Name", "Father/Husband Name", "Age", "Sex", "DOB", "Mobile No", "Aadhaar No",
                    "ABHA No", "Address", "Village", "Tehsil", "District", "PIN", "Admission Date",
                    "Discharge Date", "Diagnosis", "UHID"],
        "snake": ["patient_nm", "guardian_nm", "age_yrs", "gender", "birth_dt", "contact_no", "uid_no", "health_id",
                  "addr_line", "gram", "tahsil", "distt", "pincode", "admit_dt", "disch_dt", "dx", "hosp_no"],
        "hindi": ["मरीज़ का नाम", "पिता/पति का नाम", "आयु", "लिंग", "जन्म तिथि", "मोबाइल", "आधार", "आभा", "पता",
                  "ग्राम", "तहसील", "जिला", "पिन", "भर्ती तिथि", "छुट्टी तिथि", "निदान", "यूएचआईडी"],
        "hinglish": ["Marij Naam", "Pita Pati Naam", "Umar", "Ling", "Janm Tithi", "Phone", "Aadhar", "ABHA ID",
                     "Pata", "Gaon", "Tehsil", "Jila", "Pin Code", "Bharti Tithi", "Chhutti Tithi", "Bimari",
                     "Reg No"],
        "cryptic": ["PT", "REL", "A", "S", "D_O_B", "MOB", "UID", "HID", "ADDR", "VIL", "TEH", "DIST", "PC",
                    "IN_DT", "OUT_DT", "DX", "ID"],
    }

    def tabular(self, style: str, enc: str, delim: str, hosp: tuple[str, str, int], idx: int) -> None:
        r = self.rng
        code = hosp[0]
        ext = "tsv" if delim == "\t" else "csv"
        f = f"registration/{code.lower()}_{style}_{idx}.{ext}"
        deva = style == "hindi"
        header = self.HEADER_STYLES[style]
        rows = []
        members = r.sample(self.people, k=min(len(self.people), 9))
        for p in self.people[:4]:          # traps always present
            if p not in members:
                members.append(p)
        members.sort(key=lambda p: p.pid)
        for ri, p in enumerate(members):
            name = p.full_deva if deva else p.full
            rel = (p.rel_full_deva if deva else f"{p.rel_marker} {p.rel_full}") if r.random() < 0.8 else (p.rel_full_deva if deva else p.rel_full)
            dob = date_fmt(r, *p.dob, allow_text=False)
            ph, ph_script = phone_variant(r, p.phone)
            if enc == "cp1252" and ph_script == "deva":
                ph, ph_script = p.phone, "latin"
            aad = aadhaar_variant(r, p.aadhaar)
            abha = f"{p.abha[:2]}-{p.abha[2:6]}-{p.abha[6:10]}-{p.abha[10:]}"
            loc_txt = p.locality[1] if deva else p.locality[0]
            addr = f"House {p.house}, {loc_txt}" if not deva else f"मकान नं. {p.house}, {loc_txt}"
            vill = p.village[1] if deva else p.village[0]
            teh = p.geo[3] if deva else p.geo[0]
            dist = p.geo[4] if deva else p.geo[1]
            adm = (2026, r.randint(1, 10), r.randint(1, 19))
            stay = r.randint(1, 9)
            dis = (adm[0], adm[1], adm[2] + stay)
            adm_s = date_fmt(r, *adm, allow_text=False)
            fmt_choice = adm_s  # discharge uses same format as admission
            if "/" in fmt_choice:
                dis_s = f"{dis[2]:02d}/{dis[1]:02d}/{dis[0]}"
            elif "." in fmt_choice:
                dis_s = f"{dis[2]:02d}.{dis[1]:02d}.{dis[0]}"
            elif fmt_choice[4] == "-":
                dis_s = f"{dis[0]}-{dis[1]:02d}-{dis[2]:02d}"
            else:
                dis_s = f"{dis[2]:02d}-{dis[1]:02d}-{dis[0]}"
            dx = r.choice(DIAGNOSES)
            dx_s = dx[1] if deva else dx[0]
            mrn = p.mrn[code]
            gender = {"M": "पुरुष", "F": "महिला"}[p.gender] if deva else r.choice([p.gender, {"M": "Male", "F": "Female"}[p.gender]])
            row = [name, rel, str(p.age), gender, dob, ph, aad, abha, addr, vill, teh, dist, p.pin,
                   adm_s, dis_s, dx_s, mrn]
            rows.append(row)
            script = "deva" if deva else "latin"
            self.ans.rm(f, name, "PATIENT_NAME", script, critical=True, person=p.pid, loc=f"row:{ri}")
            self.ans.rm(f, p.rel_full_deva if deva else p.rel_full, "RELATIVE_NAME", script, person=p.pid, loc=f"row:{ri}")
            self.ans.rm(f, ph, "PHONE", ph_script, critical=True, person=p.pid, loc=f"row:{ri}")
            self.ans.rm(f, aad, "AADHAAR", critical=True, person=p.pid, loc=f"row:{ri}")
            self.ans.rm(f, abha, "ABHA_NUMBER", critical=True, person=p.pid, loc=f"row:{ri}")
            self.ans.rm(f, mrn, "MRN", critical=True, person=p.pid, loc=f"row:{ri}")
            self.ans.rm(f, dob, "DOB", person=p.pid, loc=f"row:{ri}")
            self.ans.rm(f, f"{p.house}, {loc_txt}", "HOUSE", script, person=p.pid, loc=f"row:{ri}")
            self.ans.rm(f, vill, "VILLAGE", script, person=p.pid, loc=f"row:{ri}")
            self.ans.rm(f, p.pin, "PIN", person=p.pid, loc=f"row:{ri}")
            self.ans.kp(f, dx_s, "diagnosis", loc=f"row:{ri}")
            self.ans.kp(f, dist, "district", loc=f"row:{ri}")
            self.ans.records.append(dict(file=f, loc=f"row:{ri}", patient=p.pid))
            self.ans.los.append(dict(file=f, loc=f"row:{ri}", col_in=13, col_out=14, days=stay, adm=adm_s, dis=dis_s))
            self.visit_facts.setdefault(p.pid, []).append({
                "date": f"{adm[0]}-{adm[1]:02d}-{adm[2]:02d}",
                "condition": dx[0],
                "los_days": stay,
                "hospital": hosp[1],
            })
        out_lines = []
        import csv
        import io
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=delim, lineterminator="\r\n" if r.random() < 0.3 else "\n")
        w.writerow(header)
        for row in rows:
            w.writerow(row)
        text = buf.getvalue()
        if enc == "utf-16":
            data = text.encode("utf-16")
        elif enc == "utf-8-sig":
            data = text.encode("utf-8-sig")
        elif enc == "cp1252":
            data = text.encode("cp1252", errors="strict")
        else:
            data = text.encode("utf-8")
        self.put(f, data, ext)
        _ = out_lines

    # ---- free text ----------------------------------------------------------------
    def discharge_en(self, p: Person, hosp: tuple[str, str, int], idx: int, pii_filename: bool) -> None:
        r = self.rng
        code, hname, _ = hosp
        mrn = p.mrn[code]
        if pii_filename:
            f = f"discharge/DS_{p.given[0].replace(' ', '_')}_{p.surname[0].replace(chr(39), '')}_{mrn.replace('/', '-')}.txt"
            self.ans.rm(f, f"{p.given[0].replace(' ', '_')}_{p.surname[0].replace(chr(39), '')}", "PATIENT_NAME",
                        channel="filename", critical=True, person=p.pid)
        else:
            f = f"discharge/{code.lower()}_ds_{idx:03d}.txt"
        label = r.choice(["Patient Name:", "Name of Patient -", "Pt:", "NAME =", "Patient's Name :"])
        ph, ph_script = phone_variant(r, p.phone)
        ph_label = r.choice(["Mobile:", "Ph.", "Contact No.", "Mob -", "Phone"])
        adm = (2026, r.randint(1, 10), r.randint(1, 18))
        stay = r.randint(1, 9)
        adm_s = f"{adm[2]:02d}/{adm[1]:02d}/{adm[0]}"
        dis_s = f"{adm[2] + stay:02d}/{adm[1]:02d}/{adm[0]}"
        dob_s = date_fmt(r, *p.dob)
        dx = r.choice(DIAGNOSES)[0]
        meds = r.sample(MEDS, 3)
        doc = r.choice(DOCTORS)
        if "doctor_relative_same_name" in p.traps:
            doc = "Dr. Ramesh Srivastava"
        aad = aadhaar_variant(r, p.aadhaar)
        abha = f"91-{p.abha[2:6]}-{p.abha[6:10]}-{p.abha[10:]}" if r.random() < 0.5 else p.abha
        rel_line = f"{p.rel_marker} {p.rel_full}"
        addr_parts = [f"House {p.house}", p.locality[0], p.landmark[0], p.village[0], f"Tehsil {p.geo[0]}",
                      f"Distt. {p.geo[1]} - {p.pin}"]
        lines = [
            hname, "DISCHARGE SUMMARY", "",
            f"{label} {p.full}        Age/Sex: {p.age} Yrs/{p.gender}",
            f"UHID: {mrn}        IPD No: IPD-2026-{r.randint(100, 999):05d}",
            rel_line,
            f"Address: {', '.join(addr_parts)}",
            f"{ph_label} {ph}",
            f"Aadhaar: {aad}" if r.random() < 0.6 else f"UID No. {aad}",
            f"ABHA: {abha}",
            f"Consultant: {doc} (MD Medicine)",
            f"Ward/Bed: Ward {r.randint(1, 9)} (Medicine) / Bed {r.randint(1, 30)}",
            f"Date of Admission: {adm_s}",
            f"Date of Discharge: {dis_s}",
            f"DOB: {dob_s}", "",
            f"Diagnosis: {dx}",
            f"Presenting complaints: C/O fever for 3 days, generalised weakness.",
            f"Course in hospital: {' '.join(r.sample(VITALS, 3))}. {' '.join(r.sample(LAB_LINES, 3))}. "
            f"{p.given[0]} {r.choice(['bhai', 'ji', 'didi'])} ki condition ab stable hai.", "",
            "Medications on discharge:",
            *[f" {i + 1}. {m}" for i, m in enumerate(meds)], "",
            f"Advice: Advised low salt diet. Review in OPD after 2 weeks with {doc}.",
            f"Attendant: {p.rel_full}, Mob. {p.phone}",
        ]
        text = "\n".join(lines) + "\n"
        if r.random() < 0.3:
            text = text.replace("\n", "\r\n")
        self.put(f, text.encode("utf-8"), "text")
        A = self.ans
        A.rm(f, p.full, "PATIENT_NAME", critical=True, person=p.pid)
        A.rm(f, p.rel_full, "RELATIVE_NAME", person=p.pid)
        A.rm(f, ph, "PHONE", ph_script, critical=True, person=p.pid)
        A.rm(f, p.phone, "PHONE", critical=True, person=p.pid)
        A.rm(f, mrn, "MRN", critical=True, person=p.pid)
        A.rm(f, aad, "AADHAAR", critical=True, person=p.pid)
        A.rm(f, abha, "ABHA_NUMBER", critical=True, person=p.pid)
        A.rm(f, dob_s, "DOB", person=p.pid)
        A.rm(f, f"House {p.house}", "HOUSE", person=p.pid)
        A.rm(f, p.locality[0], "LOCALITY", person=p.pid)
        A.rm(f, p.landmark[0], "LANDMARK", person=p.pid)
        A.rm(f, p.village[0], "VILLAGE", person=p.pid)
        A.rm(f, p.pin, "PIN", person=p.pid)
        A.rm(f, f"{p.age} Yrs/{p.gender}", "AGE90" if p.age >= 90 else "AGE", person=p.pid)
        for keep in [dx, *meds, doc, "Review in OPD after 2 weeks", "C/O fever for 3 days", "Advised low salt diet",
                     f"Tehsil {p.geo[0]}", p.geo[1]]:
            A.kp(f, keep, "clinical")
        A.records.append(dict(file=f, loc="doc", patient=p.pid))
        self.visit_facts.setdefault(p.pid, []).append({
            "date": f"{adm[0]}-{adm[1]:02d}-{adm[2]:02d}",
            "condition": dx,
            "los_days": stay,
            "hospital": hname,
        })

    def note_hindi(self, p: Person, idx: int) -> None:
        r = self.rng
        f = f"notes/hindi_note_{idx:03d}.txt"
        ph_dev = p.phone.translate(DEVA_DIGITS) if r.random() < 0.5 else p.phone
        rel_word = {"S/o": "पिता", "W/o": "पति", "D/o": "पिता"}[p.rel_marker]
        dx = r.choice(DIAGNOSES)[1]
        visit = (2026, r.randint(1, 11), r.randint(1, 28))
        visit_s = f"{visit[2]:02d}/{visit[1]:02d}/{visit[0]}"
        lines = [
            "ओपीडी पर्ची", f"नाम: {p.full_deva}", f"{rel_word}: {p.rel_full_deva}",
            f"आयु: {p.age} वर्ष   लिंग: {'पुरुष' if p.gender == 'M' else 'महिला'}",
            f"ग्राम: {p.village[1]}, तहसील {p.geo[3]}, जिला {p.geo[4]}",
            f"मोबाइल: {ph_dev}", f"दिनांक: {visit_s}",
            f"निदान: {dx}", "दवा: Tab Paracetamol 650 mg 1-0-1 x 5 days",
            f"{p.given[1]} को तीन दिन से बुखार है। BP 128/84 mmHg",
        ]
        self.put(f, ("\n".join(lines) + "\n").encode("utf-8"), "text")
        A = self.ans
        A.rm(f, p.full_deva, "PATIENT_NAME", "deva", critical=True, person=p.pid)
        A.rm(f, p.rel_full_deva, "RELATIVE_NAME", "deva", person=p.pid)
        A.rm(f, ph_dev, "PHONE", "deva" if ph_dev != p.phone else "latin", critical=True, person=p.pid)
        A.rm(f, p.village[1], "VILLAGE", "deva", person=p.pid)
        for keep in [dx, "Tab Paracetamol 650 mg 1-0-1 x 5 days", "BP 128/84 mmHg", p.geo[4]]:
            A.kp(f, keep, "clinical")
        A.records.append(dict(file=f, loc="doc", patient=p.pid))

    def whatsapp(self, p: Person, idx: int) -> None:
        r = self.rng
        kin = r.choice(KIN)
        sender = f"{p.rel_given[0]} {kin}"
        f = f"lab/chat_{p.phone}.txt" if r.random() < 0.4 else f"lab/whatsapp_{idx:03d}.txt"
        if f.startswith("lab/chat_"):
            self.ans.rm(f, p.phone, "PHONE", channel="filename", critical=True, person=p.pid)
        alt_phone = str(r.randint(6, 9)) + "".join(str(r.randint(0, 9)) for _ in range(9))
        lab = r.sample(LAB_LINES, 2)
        lines = [
            f"[{r.randint(1, 28):02d}/0{r.randint(1, 9)}/26, {r.randint(1, 12)}:{r.randint(10, 59)} pm] {sender}: <attachment: report.pdf>",
            "Forwarded", "*Lab Report*",
            f"Report of {p.given[0]} ji  {p.age} Y / {p.gender}",
            " | ".join(lab),
            f"{p.given[0]} ko 3 din se bukhaar hai, Dolo 650 BD x 5 days diya hai 🙏",
            f"Koi problem ho to call karo {alt_phone}",
        ]
        self.put(f, ("\n".join(lines) + "\n").encode("utf-8"), "text")
        A = self.ans
        A.rm(f, sender, "RELATIVE_NAME", "hinglish", person=p.pid)
        A.rm(f, f"{p.given[0]} ji", "PATIENT_NAME", "hinglish", person=p.pid)
        A.rm(f, f"{p.given[0]} ko", "PATIENT_NAME", "hinglish", person=p.pid)
        A.rm(f, alt_phone, "PHONE", critical=True, person=p.pid)
        for keep in [*lab, "Dolo 650 BD x 5 days"]:
            A.kp(f, keep, "clinical")

    def nursing(self, p: Person, hosp: tuple[str, str, int], idx: int) -> None:
        r = self.rng
        mrn = p.mrn[hosp[0]]
        f = f"notes/nursing_{idx:03d}.txt"
        ward = f"Ward {r.randint(1, 9)} (Surgery), Bed {r.randint(1, 20)}"
        lines = [
            f"NURSING NOTES - {ward} - {mrn}", "",
            f"{r.randint(1, 28):02d}/0{r.randint(1, 9)}/2026 22:00  Pt {p.given[0]} c/o pain abdomen. {r.choice(VITALS)}.",
            f"{r.randint(1, 28):02d}/0{r.randint(1, 9)}/2026 06:00  Relative {p.rel_full} informed about NPO status.",
            f"Inj Tramadol 50 mg IV SOS given. {r.choice(LAB_LINES)}.",
        ]
        self.put(f, ("\n".join(lines) + "\n").encode("utf-8"), "text")
        A = self.ans
        A.rm(f, mrn, "MRN", critical=True, person=p.pid)
        A.rm(f, f"Pt {p.given[0]}", "PATIENT_NAME", person=p.pid)
        A.rm(f, p.rel_full, "RELATIVE_NAME", person=p.pid)
        A.kp(f, ward, "ward")
        A.kp(f, "Inj Tramadol 50 mg IV SOS", "clinical")

    def referral(self, p: Person, idx: int) -> None:
        r = self.rng
        f = f"referrals/referral_{idx:03d}.txt"
        hon = "Mr." if p.gender == "M" else r.choice(["Mrs.", "Smt."])
        ph, ph_script = phone_variant(r, p.phone)
        lines = [
            "To,", "The Medical Superintendent,", "District Hospital", "",
            f"Respected Sir/Madam, I am referring {hon} {p.full}, aged {p.age} years, R/o {p.village[0]}, "
            f"Tehsil {p.geo[0]}, for further management of {r.choice(DIAGNOSES)[0]}.",
            f"Patient's contact: {ph}. Aadhaar ending {p.aadhaar[-4:]}.",
            f"Kindly do the needful. Regards, {r.choice(DOCTORS)}",
        ]
        self.put(f, ("\n".join(lines) + "\n").encode("utf-8"), "text")
        A = self.ans
        A.rm(f, p.full, "PATIENT_NAME", critical=True, person=p.pid)
        A.rm(f, ph, "PHONE", ph_script, critical=True, person=p.pid)
        A.rm(f, p.village[0], "VILLAGE", person=p.pid)
        A.records.append(dict(file=f, loc="doc", patient=p.pid))

    # ---- JSON / FHIR -----------------------------------------------------------------
    def opd_json(self, hosp: tuple[str, str, int], idx: int, escaped: bool) -> None:
        r = self.rng
        code = hosp[0]
        f = f"opd/{code.lower()}_opd_{idx}.json"
        members = sorted(r.sample(self.people, k=min(6, len(self.people))), key=lambda p: p.pid)
        visits = []
        A = self.ans
        by_name: dict[str, str] = {}
        for vi, p in enumerate(members):
            deva = escaped and r.random() < 0.6
            name = p.full_deva if deva else p.full
            ph, ph_script = phone_variant(r, p.phone)
            v = {
                "visit_id": f"V{r.randint(10000, 99999)}",
                "visit_date": date_fmt(r, 2026, r.randint(1, 11), r.randint(1, 28), allow_text=False),
                "patient": {"name": name, "age": p.age, "gender": p.gender, "phone": ph, "uhid": p.mrn[code]},
                "relative": {"relation": p.rel_marker, "name": p.rel_full},
                "vitals": {"bp": "130/86", "pulse": 88, "spo2": "97%"},
                "rx": [{"drug": "Tab Metformin", "dose": "500 mg", "freq": "1-0-1"}],
                "diagnosis": r.choice(DIAGNOSES)[0],
            }
            visits.append(v)
            by_name[name] = p.mrn[code]
            sc = "deva" if deva else "latin"
            A.rm(f, name, "PATIENT_NAME", sc, critical=True, person=p.pid)
            A.rm(f, name, "PATIENT_NAME", sc, channel="key", critical=True, person=p.pid)
            A.rm(f, ph, "PHONE", ph_script, critical=True, person=p.pid)
            A.rm(f, p.mrn[code], "MRN", critical=True, person=p.pid)
            A.rm(f, p.rel_full, "RELATIVE_NAME", person=p.pid)
            A.kp(f, v["diagnosis"], "diagnosis")
            A.records.append(dict(file=f, loc=f"/visits/{vi}", patient=p.pid))
        first = members[0]
        doc: dict[str, Any] = {
            "export_meta": {"system": "eHMS v2", "prepared_for": first.full, "generated": "2026-11-01"},
            "visits": visits,
            "index": {"by_name": by_name},
        }
        A.rm(f, first.full, "PATIENT_NAME", channel="metadata", critical=True, person=first.pid)
        # base64 attachment holding a note with PII
        att_p = members[-1]
        note = f"Referral note: {att_p.full}, phone {att_p.phone}, Aadhaar {att_p.aadhaar}."
        doc["attachments"] = [{"mime": "text/plain", "data": base64.b64encode(note.encode()).decode()}]
        A.rm(f, att_p.full, "PATIENT_NAME", channel="base64", critical=True, person=att_p.pid)
        A.rm(f, att_p.phone, "PHONE", channel="base64", critical=True, person=att_p.pid)
        A.rm(f, att_p.aadhaar, "AADHAAR", channel="base64", critical=True, person=att_p.pid)
        A.kp(f, "1-0-1", "dose")
        A.kp(f, "130/86", "vitals")
        text = json.dumps(doc, ensure_ascii=escaped, indent=2)
        self.put(f, text.encode("utf-8"), "json")

    def fhir(self, p: Person, idx: int) -> None:
        r = self.rng
        f = f"fhir/bundle_{idx:03d}.json"
        dx = r.choice(DIAGNOSES)[0]
        start = (2026, r.randint(1, 10), r.randint(1, 18))
        stay = r.randint(1, 6)
        bundle = {
            "resourceType": "Bundle", "type": "collection",
            "entry": [
                {"resource": {
                    "resourceType": "Patient", "id": "pat-1",
                    "text": {"status": "generated", "div": f"<div>{p.full}, {p.age} yrs, ph {p.phone}</div>"},
                    "identifier": [{"system": "https://uidai.gov.in", "value": p.aadhaar},
                                   {"system": "urn:mrn", "value": p.mrn["SKH"]}],
                    "name": [{"family": p.surname[0], "given": [p.given[0]], "text": p.full}],
                    "telecom": [{"system": "phone", "value": p.phone}],
                    "gender": "male" if p.gender == "M" else "female",
                    "birthDate": f"{p.dob[0]}-{p.dob[1]:02d}-{p.dob[2]:02d}",
                    "address": [{"line": [f"House {p.house}", p.locality[0]], "city": p.village[0],
                                 "district": p.geo[1], "postalCode": p.pin}],
                }},
                {"resource": {"resourceType": "Encounter", "id": "enc-1", "status": "finished",
                              "period": {"start": f"{start[0]}-{start[1]:02d}-{start[2]:02d}",
                                         "end": f"{start[0]}-{start[1]:02d}-{start[2] + stay:02d}"}}},
                {"resource": {"resourceType": "Condition", "id": "cond-1", "code": {"text": dx}}},
                {"resource": {"resourceType": "Practitioner", "id": "prac-1",
                              "name": [{"text": r.choice(DOCTORS)}]}},
            ],
        }
        self.put(f, json.dumps(bundle, indent=2).encode("utf-8"), "fhir")
        A = self.ans
        A.rm(f, p.full, "PATIENT_NAME", critical=True, person=p.pid)
        A.rm(f, p.aadhaar, "AADHAAR", critical=True, person=p.pid)
        A.rm(f, p.mrn["SKH"], "MRN", critical=True, person=p.pid)
        A.rm(f, p.phone, "PHONE", critical=True, person=p.pid)
        A.rm(f, p.village[0], "VILLAGE", person=p.pid)
        A.rm(f, p.pin, "PIN", person=p.pid)
        A.rm(f, f"{p.dob[0]}-{p.dob[1]:02d}-{p.dob[2]:02d}", "DOB", person=p.pid)
        A.kp(f, dx, "diagnosis")
        A.records.append(dict(file=f, loc="doc", patient=p.pid))

    # ---- canaries / broken / side channels --------------------------------------------
    def canary(self, idx: int) -> None:
        g, s = CANARY_NAMES[idx % len(CANARY_NAMES)]
        f = f"misc/walkin_{idx}.txt"
        ph = "9" + f"{(self.seed * 7919 + idx * 104729) % 10**9:09d}"
        text = (f"Walk-in registration\nPatient Name: {g} {s}\nMob: {ph}\n"
                f"C/O cough x 2 weeks. Advised sputum AFB.\n")
        self.put(f, text.encode("utf-8"), "text")
        self.ans.rm(f, f"{g} {s}", "CANARY", critical=True)
        self.ans.rm(f, ph, "PHONE", critical=True)
        self.ans.canaries += [f"{g} {s}", ph]
        self.ans.kp(f, "C/O cough x 2 weeks", "clinical")

    def broken(self) -> None:
        p = self.people[5]
        self.put("misc/truncated_export.json", f'{{"patient": {{"name": "{p.full}", "phone": "{p.phone}"'.encode(),
                 "json", "either")
        self.ans.rm("misc/truncated_export.json", p.full, "PATIENT_NAME", critical=True, person=p.pid)
        self.put("misc/empty.csv", b"", "csv", "either")
        self.put("misc/scan_0001.pdf", b"%PDF-1.4\n1 0 obj << /Title (" + p.full.encode() + b") >>\n%%EOF\n",
                 "pdf", "quarantine")
        self.ans.rm("misc/scan_0001.pdf", p.full, "PATIENT_NAME", critical=True, person=p.pid)
        self.put("misc/photo.jpg", b"\xff\xd8\xff\xe0" + bytes(range(256)) * 4, "binary", "quarantine")
        self.put("misc/hl7_message.xml", f"<ClinicalDocument><patient><name>{p.full}</name></patient></ClinicalDocument>".encode(),
                 "xml", "either")
        self.ans.rm("misc/hl7_message.xml", p.full, "PATIENT_NAME", critical=True, person=p.pid)
        self.put("misc/mislabeled.csv", json.dumps([{"name": p.full, "mobile": p.phone, "dx": "Asthma"}]).encode(),
                 "json")
        self.ans.rm("misc/mislabeled.csv", p.full, "PATIENT_NAME", critical=True, person=p.pid)
        self.ans.rm("misc/mislabeled.csv", p.phone, "PHONE", critical=True, person=p.pid)
        self.ans.kp("misc/mislabeled.csv", "Asthma", "diagnosis")
        q = self.people[6]
        latin1 = f"Patient Name: {q.full}\nPhone: {q.phone}\nDx: Typhoid fever\n".encode("utf-8") + b"\xff\xfe\x00bad\n"
        self.put("misc/corrupt_note.txt", latin1, "text", "either")
        self.ans.rm("misc/corrupt_note.txt", q.full, "PATIENT_NAME", critical=True, person=q.pid)
        self.ans.rm("misc/corrupt_note.txt", q.phone, "PHONE", critical=True, person=q.pid)
        deep: Any = {"name": q.full, "dx": "Asthma"}
        for _ in range(60):
            deep = {"child": deep}
        self.put("misc/deep.json", json.dumps(deep).encode(), "json", "either")
        self.ans.rm("misc/deep.json", q.full, "PATIENT_NAME", critical=True, person=q.pid)


    # ---- hard mode -----------------------------------------------------------------
    def hard_cases(self, p: Person, idx: int) -> None:
        """Rarer, nastier shapes: initials, CAPS, wrapped names, zero-width characters, spelling
        variants, extra ID types, ages to band, NDJSON, PII in folder names, fragments."""
        r = self.rng
        A = self.ans
        kind = idx % 6
        email = f"{p.given[0].lower().replace(' ', '')}.{p.surname[0].lower().replace(chr(39), '')}{r.randint(10, 99)}@gmail.com"
        pan = p.pan
        pmjay = f"PMJAY-{r.randint(10**9, 10**10 - 1)}"
        abha_addr = f"{p.given[0].lower().replace(' ', '')}{p.dob[0]}@abdm"
        masked = f"XXXX XXXX {p.aadhaar[-4:]}"
        if kind == 0:
            f = f"billing/claim_{idx:03d}.txt"
            initials = f"{p.given[0][0]}. {p.rel_given[0][0]}. {p.surname[0]}"
            text = (f"CLAIM FORM\nInsured: {p.full.upper()}\nAlso known as: {initials}\nPAN: {pan}\n"
                    f"Scheme ID: {pmjay}\nE-mail: {email}\nABHA address: {abha_addr}\nAadhaar (masked): {masked}\n"
                    f"Procedure: Laparoscopic cholecystectomy. Amount: Rs 45000. Hb 11.2 g/dL\n")
            self.put(f, text.encode("utf-8"), "text")
            A.rm(f, p.full.upper(), "PATIENT_NAME", critical=True, person=p.pid)
            A.rm(f, initials, "PATIENT_NAME", person=p.pid)
            A.rm(f, pan, "PAN", critical=True, person=p.pid)
            A.rm(f, pmjay, "INSURANCE_ID", critical=True, person=p.pid)
            A.rm(f, email, "EMAIL", critical=True, person=p.pid)
            A.rm(f, abha_addr, "ABHA_ADDRESS", critical=True, person=p.pid)
            A.rm(f, masked, "AADHAAR_MASKED", person=p.pid)
            for k in ["Laparoscopic cholecystectomy", "Rs 45000", "Hb 11.2 g/dL"]:
                A.kp(f, k, "clinical")
        elif kind == 1:
            f = f"notes/wrapped_{idx:03d}.txt"
            text = (f"Case discussed in morning rounds. Patient {p.given[0]}\n{p.surname[0]} admitted with "
                    f"Down syndrome features and Hodgkin lymphoma workup. GCS 15/15. Apgar not applicable.\n"
                    f"Plan: Tab Allopurinol 100 mg OD x 7 days.\n")
            self.put(f, text.encode("utf-8"), "text")
            A.rm(f, f"{p.given[0]}\n{p.surname[0]}", "PATIENT_NAME", critical=True, person=p.pid)
            for k in ["Down syndrome", "Hodgkin lymphoma", "GCS 15/15", "Tab Allopurinol 100 mg OD x 7 days"]:
                A.kp(f, k, "clinical")
        elif kind == 2:
            f = f"notes/zw_{idx:03d}.txt"
            zw_name = p.given[1][:2] + "‍" + p.given[1][2:] + " " + p.surname[1]
            nb_name = p.given[0] + " " + p.surname[0]
            text = (f"नाम: {zw_name}\nName (English): {nb_name}\nआयु: {p.age} वर्ष\n"
                    f"निदान: मधुमेह, Tab Glimepiride 1 mg 1-0-0\n")
            self.put(f, text.encode("utf-8"), "text")
            A.rm(f, p.full_deva, "PATIENT_NAME", "deva", critical=True, person=p.pid)
            A.rm(f, p.full, "PATIENT_NAME", critical=True, person=p.pid)
            A.kp(f, "Tab Glimepiride 1 mg 1-0-0", "clinical")
        elif kind == 3:
            f = f"exports/visits_{idx:03d}.jsonl"
            lines = []
            for j in range(3):
                lines.append(json.dumps({"seq": j, "pt_name": p.full, "mobile": p.phone, "dx": "Hypertension",
                                         "bp": "150/96"}, ensure_ascii=False))
            self.put(f, ("\n".join(lines) + "\n").encode("utf-8"), "json", "either")
            A.rm(f, p.full, "PATIENT_NAME", critical=True, person=p.pid)
            A.rm(f, p.phone, "PHONE", critical=True, person=p.pid)
        elif kind == 4:
            folder = f"{p.given[0].replace(' ', '_')}_{p.surname[0].replace(chr(39), '')}"
            f = f"scans/{folder}/visit_note.txt"
            text = f"Follow-up visit. BP 138/90 mmHg. Continue Tab Telmisartan 40 mg 0-0-1.\n"
            self.put(f, text.encode("utf-8"), "text")
            A.rm(f, folder, "PATIENT_NAME", channel="filename", critical=True, person=p.pid)
            A.kp(f, "Tab Telmisartan 40 mg 0-0-1", "clinical")
        else:
            f = f"registration/titled_{idx:03d}.csv"
            text = (f"Export for patient: {p.full} ({p.mrn['SKH']})\n"
                    f"Test,Value,Unit\nHaemoglobin,10.9,g/dL\nPlatelets,182000,/cumm\nTSH,3.1,mIU/L\n")
            self.put(f, text.encode("utf-8"), "csv", "either")
            A.rm(f, p.full, "PATIENT_NAME", channel="header", critical=True, person=p.pid)
            A.rm(f, p.mrn["SKH"], "MRN", channel="header", critical=True, person=p.pid)
            A.kp(f, "182000", "lab")
        # spelling-variant fragment that must link to the same person
        g2 = p.given[0].replace("i", "ee", 1) if "i" in p.given[0] else p.given[0] + "a"
        ff = f"notes/fragment_{idx:03d}.txt"
        frag = (f"{g2}, {p.rel_marker} {p.rel_full}, seen in OPD. Complains of joint pain. "
                f"Age {p.age} yrs. Mob {p.phone}.\n")
        self.put(ff, frag.encode("utf-8"), "text")
        A.rm(ff, g2, "PATIENT_NAME", "hinglish", person=p.pid)
        A.rm(ff, p.rel_full, "RELATIVE_NAME", person=p.pid)
        A.rm(ff, p.phone, "PHONE", critical=True, person=p.pid)
        A.records.append(dict(file=ff, loc="doc", patient=p.pid))
        if p.age >= 90:
            A.rm(ff, f"Age {p.age} yrs", "AGE90", person=p.pid)

    # ---- main ---------------------------------------------------------------------
    def build(self) -> None:
        r = self.rng
        self.build_people()
        styles = list(self.HEADER_STYLES)
        encs = [("utf-8", ","), ("utf-8-sig", ","), ("utf-16", ","), ("utf-8", ";"), ("utf-8", "\t"), ("cp1252", ",")]
        for i, hosp in enumerate(HOSPITALS):
            style = styles[(self.seed + i) % len(styles)]
            enc, delim = encs[(self.seed * 3 + i) % len(encs)]
            if style == "hindi" and enc == "cp1252":
                enc = "utf-8"
            self.tabular(style, enc, delim, hosp, i)
        for i, p in enumerate(self.people):
            hosp = HOSPITALS[i % len(HOSPITALS)]
            self.discharge_en(p, hosp, i, pii_filename=(i % 3 == 0))
            if i % 2 == 0:
                self.note_hindi(p, i)
            if i % 3 == 1:
                self.whatsapp(p, i)
            if i % 4 == 2:
                self.nursing(p, hosp, i)
            if i % 4 == 3:
                self.referral(p, i)
            if i % 2 == 1:
                self.fhir(p, i)
            if self.hard:
                self.hard_cases(p, i)
        self.opd_json(HOSPITALS[0], 0, escaped=False)
        self.opd_json(HOSPITALS[1], 1, escaped=True)
        self.canary(0)
        self.canary(1)
        self.broken()
        _ = r

    def _write_attacker(self, out: Path) -> None:
        """Generate attacker/registry.csv (real cohort + 4x decoys) and known_facts.jsonl from answer key."""
        import csv
        import io
        arng = random.Random(f"wardguard-attacker:{self.seed}")
        att_dir = out / "attacker"
        att_dir.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "rid", "name", "relation", "relative_name", "gender", "age", "birth_year",
            "dob", "house", "village", "tehsil", "district", "pin", "phone", "email", "aadhaar_last4",
        ]
        reg_rows: list[dict[str, str]] = []
        for p in self.people:
            reg_rows.append({
                "rid": p.pid,
                "name": p.full,
                "relation": p.rel_marker,
                "relative_name": p.rel_full,
                "gender": p.gender,
                "age": str(p.age),
                "birth_year": str(p.dob[0]),
                "dob": f"{p.dob[0]:04d}-{p.dob[1]:02d}-{p.dob[2]:02d}",
                "house": f"House {p.house}",
                "village": p.village[0],
                "tehsil": p.geo[0],
                "district": p.geo[1],
                "pin": p.pin,
                "phone": p.phone,
                "email": f"{p.given[0].lower().replace(' ', '')}.{p.surname[0].lower().replace(chr(39), '')}@example.com",
                "aadhaar_last4": p.aadhaar[-4:],
            })

        # Add 4x decoy background population across same geography & age bands
        n_decoys = max(40, len(self.people) * 4)
        for di in range(n_decoys):
            dec = self._new_person(self.n + di)
            # Reuse arng deterministically for decoy identifiers
            gender = arng.choice("MF")
            given = arng.choice(GIVEN_M if gender == "M" else GIVEN_F)
            surname = arng.choice(SURNAMES)
            age = arng.randint(1, 95)
            geo = arng.choice(GEO)
            reg_rows.append({
                "rid": f"D{self.seed:03d}P{di:03d}",
                "name": f"{given[0]} {surname[0]}",
                "relation": "S/o" if gender == "M" else arng.choice(["W/o", "D/o"]),
                "relative_name": f"{arng.choice(GIVEN_M)[0]} {surname[0]}",
                "gender": gender,
                "age": str(age),
                "birth_year": str(2026 - age),
                "dob": f"{2026 - age:04d}-{arng.randint(1, 12):02d}-{arng.randint(1, 28):02d}",
                "house": f"House {arng.randint(1, 999)}",
                "village": arng.choice(VILLAGES)[0],
                "tehsil": geo[0],
                "district": geo[1],
                "pin": geo[2] + f"{arng.randint(0, 999):03d}",
                "phone": str(arng.randint(6, 9)) + "".join(str(arng.randint(0, 9)) for _ in range(9)),
                "email": f"{given[0].lower()}.{surname[0].lower()}.{di}@decoy.org",
                "aadhaar_last4": f"{arng.randint(0, 9999):04d}",
            })
            _ = dec

        arng.shuffle(reg_rows)
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(reg_rows)
        (att_dir / "registry.csv").write_text(buf.getvalue(), encoding="utf-8")

        # Known facts for 50% of cohort (plus 2 decoys to catch false membership claims)
        fact_lines: list[str] = []
        for idx, p in enumerate(self.people):
            if idx % 2 != 0:
                continue
            vfs = self.visit_facts.get(p.pid, [])
            if not vfs:
                continue
            fact_lines.append(json.dumps({
                "rid": p.pid,
                "visit_dates": sorted({vf["date"] for vf in vfs}),
                "hospital": vfs[0]["hospital"],
                "condition_hint": vfs[0]["condition"],
                "los_days": vfs[0]["los_days"],
            }, ensure_ascii=False))
        (att_dir / "known_facts.jsonl").write_text("\n".join(fact_lines) + ("\n" if fact_lines else ""), encoding="utf-8")

    def _write_truth(self, out: Path) -> None:
        """Write kit-format truth/truth.json (schema 'raksha-truth/1') without perturbing self.rng."""
        A = self.ans
        word_re = re.compile(r"[A-Za-z0-9\u0900-\u097f]+")
        profile = (
            "tiny" if self.n <= 12 else
            "small" if self.n <= 60 else
            "medium" if self.n <= 200 else
            "standard" if self.n <= 500 else
            "large"
        )

        # Index records, removals, and preserved clinical items by (file, loc)
        rec_by_file: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        for rec in A.records:
            rec_by_file[rec["file"]][rec["loc"]] = rec

        rm_by_file_loc: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for item in A.remove:
            loc = item.get("loc") or ("@filename" if item["channel"] == "filename" else "doc")
            rm_by_file_loc[(item["file"], loc)].append(item)

        kp_by_file_loc: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for item in A.keep:
            loc = item.get("loc") or "doc"
            kp_by_file_loc[(item["file"], loc)].append(item)

        def _detect_format(rel: str, raw: bytes, meta: dict[str, Any]) -> tuple[str, str, str | None]:
            fmt = str(meta.get("fmt") or "")
            if not fmt:
                ext = Path(rel).suffix.lower()
                if ext == ".csv":
                    fmt = "csv"
                elif ext == ".tsv":
                    fmt = "tsv"
                elif ext == ".json":
                    fmt = "fhir" if rel.startswith("fhir/") else "json"
                elif ext == ".xml":
                    fmt = "xml"
                elif ext == ".pdf":
                    fmt = "pdf"
                elif ext in (".bin", ".jpg", ".png"):
                    fmt = "binary"
                else:
                    fmt = "text"
            enc = "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else (
                "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
            )
            delim = "," if fmt == "csv" else ("\t" if fmt == "tsv" else None)
            return fmt, enc, delim

        files_obj: dict[str, Any] = {}
        req_units = ambig_units = 0
        linked_pids: set[str] = set()

        for rel in sorted(A.files):
            meta = A.files[rel]
            raw = self.files[rel]
            fmt, enc, delim = _detect_format(rel, raw, meta)
            locs = sorted(
                set(rec_by_file.get(rel, {}).keys())
                | {loc for (f, loc) in rm_by_file_loc if f == rel}
                | {loc for (f, loc) in kp_by_file_loc if f == rel}
            ) or ["doc"]

            units_obj: dict[str, Any] = {}
            has_entities = False
            for loc in locs:
                rec = rec_by_file.get(rel, {}).get(loc)
                pid = rec.get("patient") if rec else None
                link_mode = "required" if pid else ("ambiguous" if rec and rec.get("ambiguous") else "none")
                if link_mode == "required" and pid:
                    req_units += 1
                    linked_pids.add(pid)
                elif link_mode == "ambiguous":
                    ambig_units += 1

                entities = []
                for it in rm_by_file_loc.get((rel, loc), []):
                    has_entities = True
                    etype = it["type"]
                    surf = it["surface"]
                    is_name = etype in ("PATIENT_NAME", "RELATIVE_NAME", "DOCTOR_NAME", "NAME")
                    toks = [t.lower() for t in word_re.findall(surf)] if is_name else []
                    key = "" if is_name else re.sub(r"[\s\-()/]+", "", surf).lower()
                    entities.append({
                        "type": etype,
                        "surface": surf,
                        "person": it.get("person") or pid,
                        "role": "relative" if etype == "RELATIVE_NAME" else "patient",
                        "script": it.get("script", "latin"),
                        "channel": it.get("channel", "content"),
                        "match": "name" if is_name else "text",
                        "tokens": toks,
                        "full": len(toks) >= 2 if is_name else True,
                        "key": key,
                        "critical": bool(it.get("critical", False)),
                        "weight": 1.0 if it.get("critical") else 0.4,
                    })

                preserve = [
                    {"text": k["text"], "kind": k["kind"], "weight": 0.5, "path": loc}
                    for k in kp_by_file_loc.get((rel, loc), [])
                ]

                units_obj[loc] = {
                    "loc": loc,
                    "patient": pid,
                    "cid": f"{pid}#0" if pid else None,
                    "link": link_mode,
                    "tags": list(rec.get("tags", [])) if rec else [],
                    "entities": entities,
                    "preserve": preserve,
                    "dates": [],
                    "fields": [],
                    "exclude": [],
                }

            files_obj[rel] = {
                "path": rel,
                "format": fmt,
                "encoding": enc,
                "delimiter": delim,
                "expect": meta["expect"],
                "category": meta.get("cat") or rel.split("/")[0],
                "clean": not has_entities,
                "date_hint": "dmy",
                "sha256": meta.get("sha256") or hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "generalizable": [],
                "units": units_obj,
            }

        patients_obj: dict[str, Any] = {}
        trap_buckets: dict[str, list[Any]] = {
            "language": [],
            "fragmented": [],
            "meaning": [],
            "reidentification": [],
            "homonym_pairs": list(A.homonyms),
        }
        for p in self.people:
            patients_obj[p.pid] = {
                "rid": p.pid,
                "pid": p.pid,
                "hospitals": sorted(p.mrn.keys()),
                "uhids": {h: [v] for h, v in sorted(p.mrn.items())},
                "traps": list(p.traps),
            }
            for tr in p.traps:
                if tr in trap_buckets:
                    trap_buckets[tr].append(p.pid)

        truth = {
            "schema": "raksha-truth/1",
            "generator_version": "1.0.0",
            "seed": str(self.seed),
            "profile": profile,
            "chaos": bool(self.hard),
            "ref_date": "2026-11-20",
            "files": files_obj,
            "patients": patients_obj,
            "traps": trap_buckets,
            "linkability": {
                "required_units": req_units,
                "ambiguous_units": ambig_units,
                "components": len(linked_pids),
            },
            "canaries": list(A.canaries),
        }
        tdir = out / "truth"
        tdir.mkdir(parents=True, exist_ok=True)
        (tdir / "truth.json").write_text(json.dumps(truth, ensure_ascii=False, indent=1), encoding="utf-8")

    def write(self, out: Path) -> None:
        inp = out / "input"
        for rel, data in sorted(self.files.items()):
            path = inp / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        A = self.ans
        for rel in A.files:
            A.files[rel]["sha256"] = hashlib.sha256(self.files[rel]).hexdigest()
        out.joinpath("answer.json").write_text(json.dumps({
            "seed": self.seed, "files": A.files, "remove": A.remove, "keep": A.keep, "records": A.records,
            "homonyms": A.homonyms, "twins": A.twins, "canaries": A.canaries, "los": A.los,
            "people": {p.pid: {
                "name": p.full, "name_deva": p.full_deva, "phone": p.phone,
                "aadhaar": p.aadhaar, "abha": p.abha, "pan": p.pan,
                "mrns": list(p.mrn.values()), "traps": p.traps,
            } for p in self.people},
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        self._write_truth(out)
        self._write_attacker(out)


def generate(seed: int, out: Path, n_patients: int = 14) -> Path:
    fg = Forge(seed, n_patients)
    fg.build()
    fg.write(out)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a torture dataset with an answer key")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--patients", type=int, default=14)
    a = ap.parse_args()
    generate(a.seed, a.out, a.patients)
    print(f"generated seed={a.seed} -> {a.out}")


if __name__ == "__main__":
    main()
