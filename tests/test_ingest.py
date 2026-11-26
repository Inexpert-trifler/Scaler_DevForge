"""Comprehensive tests for Ingestion (TR-ING-1..8)."""
from pathlib import Path
import tempfile
from wardguard.ingest.decode import decode
from wardguard.ingest.sniff import sniff
from wardguard.ingest.readers import load_all


def test_decode_all_encodings():
    # 1. UTF-8
    u8 = "नमस्ते, Patient Report".encode("utf-8")
    res_u8 = decode(u8)
    assert res_u8 is not None
    assert res_u8[1] == "utf-8"
    assert "नमस्ते" in res_u8[0]

    # 2. UTF-8 with BOM
    bom_u8 = b"\xef\xbb\xbfUHID,Name\n1234,Ramesh"
    res_bom = decode(bom_u8)
    assert res_bom is not None
    assert res_bom[1] == "utf-8-sig"
    assert "Ramesh" in res_bom[0]

    # 3. UTF-16 LE with BOM
    u16le = "Patient\tNote\nRajesh\tFever".encode("utf-16")
    res_u16 = decode(u16le)
    assert res_u16 is not None
    assert res_u16[1] == "utf-16"
    assert "Rajesh" in res_u16[0]

    # 4. CP1252 (Windows-1252 with smart quote / en-dash)
    cp1252_bytes = "Patient Name: Renée – Kumar".encode("cp1252")
    res_cp = decode(cp1252_bytes)
    assert res_cp is not None
    assert res_cp[1] == "cp1252"
    assert "Renée" in res_cp[0]

    # 5. Undecodable binary with random invalid bytes and null
    bad_bin = b"\x00\x81\x8d\x8f\x90\x9d\xff\xfe\x00\x00"
    res_bad = decode(bad_bin)
    assert res_bad is None


def test_sniff_unsupported_magic_bytes():
    # PDF
    assert sniff(b"%PDF-1.4\n%...\x00\x01", "report.pdf") == "unsupported"
    # JPEG
    assert sniff(b"\xff\xd8\xff\xe0\x00\x10JFIF", "scan.jpg") == "unsupported"
    # PNG
    assert sniff(b"\x89PNG\r\n\x1a\n\x00\x00", "xray.png") == "unsupported"
    # Empty
    assert sniff(b"", "empty.txt") == "unsupported"
    # XML
    assert sniff(b"<?xml version=\"1.0\"?>\n<ClinicalDocument>", "doc.xml") == "unsupported"
    assert sniff(b"<ClinicalDocument xmlns=\"urn:hl7-org:v3\">", "cda.xml") == "unsupported"
    # Raw binary null bytes
    assert sniff(b"hello\x00world\x01\x02", "data.bin") == "unsupported"


def test_sniff_content_based_formats():
    # JSON mislabeled as CSV (TR-ING-2)
    assert sniff(b'{"patients": [{"name": "Aarav"}]}', "mislabeled_export.csv") == "json"
    assert sniff(b'[{"uhid": "123"}]', "data.csv") == "json"

    # FHIR Bundle (TR-ING-7)
    assert sniff(b'{"resourceType": "Bundle", "entry": []}', "bundle.json") == "fhir"

    # TSV and CSV
    assert sniff(b"ID\tName\tAge\n1\tSunita\t45", "export.tsv") == "tsv"
    assert sniff(b"ID,Name,Age\n1,Sunita,45", "export.csv") == "csv"

    # Plain text
    assert sniff(b"Chief Complaint: Fever for 3 days.\nAdvised PCM.", "opd_note.txt") == "text"


def test_readers_ragged_csv():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        csv_path = p / "ragged.csv"
        # Row 1 has 3 cols, Row 2 has 2 cols (short), Row 3 has 3 cols
        csv_path.write_text("UHID,Name,Diagnosis\n101,Aarav\n102,Bhavna,Malaria\n", encoding="utf-8")

        files = load_all(p)
        assert len(files) == 1
        pf = files[0]
        assert pf.status == "pending"
        assert pf.fmt == "csv"
        assert pf.header == ["UHID", "Name", "Diagnosis"]
        assert len(pf.rows) == 2
        # Ragged row padded to 3 elements
        assert pf.rows[0] == ["101", "Aarav", ""]
        assert pf.rows[1] == ["102", "Bhavna", "Malaria"]


def test_readers_deep_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        # Create 1,500 level nested JSON (TR-ING-5)
        nest = "{\"a\": " * 1500 + "42" + "}" * 1500
        (p / "deep.json").write_text(nest, encoding="utf-8")

        files = load_all(p)
        assert len(files) == 1
        assert files[0].status == "pending"
        assert files[0].fmt == "json"
        assert isinstance(files[0].obj, dict)


def test_readers_malformed_json_quarantine():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "truncated.json").write_text("{\"name\": \"Incomplete\", ", encoding="utf-8")

        files = load_all(p)
        assert len(files) == 1
        assert files[0].status == "quarantined"
        assert files[0].reason == "malformed"


def test_readers_quarantine_reasons():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "scan.jpg").write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF")
        (p / "empty.txt").write_bytes(b"")
        (p / "corrupt.txt").write_bytes(b"Patient Name: \x81\x8d\x8f\x90\x9d")

        files = load_all(p)
        assert len(files) == 3
        statuses = {f.rel: (f.status, f.reason) for f in files}
        assert statuses["scan.jpg"] == ("quarantined", "unsupported_format")
        assert statuses["empty.txt"] == ("quarantined", "unsupported_format")
        assert statuses["corrupt.txt"] == ("quarantined", "undecodable")


def test_sniff_plain_text_robustness_bug_a():
    """Verify Bug A fixes: title commas, WhatsApp exports, Devanagari lines sniff as text."""
    # 1. Hospital title with comma in line 1 (.txt) -> text
    hosp = b"SANJEEVANI MULTISPECIALITY HOSPITAL, LUCKNOW\nPatient visited OPD.\nAdvised rest."
    assert sniff(hosp, "discharge_summary.txt") == "text"

    # 2. Nursing note title with comma
    nursing = b"NURSING NOTES - Ward 8 (Medicine), Bed 2 - Morning round\nBP 120/80\nPulse 72"
    assert sniff(nursing, "note.text") == "text"

    # 3. WhatsApp export starting with [dd/mm/yy...] -> text
    whatsapp = b"[23/06/26, 8:11 pm] Dr. Sharma: Patient vitals stable, discharge tomorrow."
    assert sniff(whatsapp, "chat_export.txt") == "text"

    # 4. Devanagari with comma in line 1
    deva_txt = "नमस्ते अस्पताल, लखनऊ\nमरीज़ को बुखार है।".encode("utf-8")
    assert sniff(deva_txt, "hindi_note.txt") == "text"

    # 5. Real CSV in .txt -> text because extension is .txt and content is not valid JSON
    fake_csv_txt = b"Col1,Col2\nVal1,Val2\nVal3,Val4"
    assert sniff(fake_csv_txt, "data.txt") == "text"

    # 6. JSON content in .csv -> json (content wins when it truly parses)
    valid_json_csv = b'{"patients": [{"id": 1, "name": "Rajesh"}]}'
    assert sniff(valid_json_csv, "export.csv") == "json"

    # 7. Truncated / malformed JSON in .json -> stays json so reader quarantines as malformed
    trunc_json = b'{"name": "Incomplete", '
    assert sniff(trunc_json, "record.json") == "json"

    # 8. Truncated JSON-like text in .txt -> text (does not parse as JSON)
    pseudo_json_txt = b'{"note": "This is a doctor note that ends abruptly...'
    assert sniff(pseudo_json_txt, "raw_note.txt") == "text"

    # 9. FHIR Bundle -> fhir
    fhir_bundle = b'{"resourceType": "Bundle", "type": "collection", "entry": []}'
    assert sniff(fhir_bundle, "bundle.json") == "fhir"

    # 10. UTF-16 CSV -> csv
    u16_csv = "Name,Age,Gender\nRajesh,45,M\nSunita,38,F".encode("utf-16")
    assert sniff(u16_csv, "records.csv") == "csv"

